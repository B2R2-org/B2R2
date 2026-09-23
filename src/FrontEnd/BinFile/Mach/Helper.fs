(*
  B2R2 - the Next-Generation Reversing Platform

  Copyright (c) SoftSec Lab. @ KAIST, since 2016

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*)

module internal B2R2.FrontEnd.BinFile.Mach.Helper

open System
open B2R2
open B2R2.Collections
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.FileHelper

/// Mach-specific virtual memory permission (for maxprot and initprot). Note
/// that these values are different than the B2R2.Permission type.
[<Flags>]
type internal MachVMProt =
  /// File is readable.
  | Readable = 1
  /// File is writable.
  | Writable = 2
  /// File is executable.
  | Executable = 4

let isMainCmd = function
  | Main _ -> true
  | _ -> false

let getMainOffset cmds =
  match cmds |> Array.tryFind isMainCmd with
  | Some(Main(_, _, m)) -> m.EntryOff
  | _ -> 0UL

let getTextSegOffset segs =
  match Segment.tryGetImageBase segs with
  | Some vmAddr -> vmAddr
  | None -> raise InvalidFileFormatException

let getThreadEntry cmds =
  cmds
  |> Array.tryPick (function
    | Thread(_, _, pc) -> pc
    | _ -> None)

/// Returns the entry point of the image. LC_MAIN names a file offset from the
/// Mach-O header, so it is taken from the image base, whereas the older thread
/// state commands spell out an unslid address that only the load slide moves.
let computeEntryPoint toolBox segs cmds =
  match getThreadEntry cmds with
  | Some pc ->
    Some(pc + toolBox.BaseAddress)
  | None ->
    let mainOffset = getMainOffset cmds
    if mainOffset = 0UL then None else Some(mainOffset + getTextSegOffset segs)

/// Returns a pointer to the given address, bounded by the segment that holds
/// it. An address a segment maps but the file does not reach, as the
/// zero-filled tail of one is, names no file offset and gives a virtual
/// pointer; an address no segment maps at all gives a null one.
let boundedPointerOf (segCmds: SegCmd[]) addr =
  let mutable found = false
  let mutable idx = 0
  let mutable maxAddr = 0UL
  let mutable offset = 0
  let mutable maxOffset = 0
  while not found && idx < segCmds.Length do
    let seg = segCmds[idx]
    if addr >= seg.VMAddr && addr < seg.VMAddr + seg.VMSize then
      found <- true
      maxOffset <- int seg.FileOff + int seg.FileSize - 1
      if addr < seg.VMAddr + seg.FileSize then
        offset <- int seg.FileOff + int (addr - seg.VMAddr)
        maxAddr <- seg.VMAddr + seg.FileSize - 1UL
      else
        offset <- maxOffset + 1
        maxAddr <- seg.VMAddr + seg.VMSize - 1UL
    else
      idx <- idx + 1
  if found then
    if offset > maxOffset then BinFilePointer.CreateVirtual(addr, maxAddr)
    else BinFilePointer.CreateFileBacked(addr, maxAddr, offset, maxOffset)
  else
    BinFilePointer.Null

let isNXEnabled hdr =
  not (hdr.Flags.HasFlag MachFlag.MH_ALLOW_STACK_EXECUTION)
  || hdr.Flags.HasFlag MachFlag.MH_NO_HEAP_EXECUTION

let private computeInvalidRanges toolBox segCmds getNextStartAddr =
  segCmds
  |> Array.filter (fun seg -> seg.SegCmdName <> "__PAGEZERO")
  |> Array.sortBy (fun seg -> seg.VMAddr)
  |> Array.fold (fun (set, saddr) seg ->
       let n = getNextStartAddr seg
       addInvalidRange set saddr seg.VMAddr, n) (IntervalSet.empty, 0UL)
  |> addLastInvalidRange toolBox.Header.Class

let invalidRangesByVM toolBox segCmds =
  computeInvalidRanges toolBox segCmds (fun seg -> seg.VMAddr + seg.VMSize)

let invalidRangesByFileBounds toolBox segCmds =
  computeInvalidRanges toolBox segCmds (fun seg -> seg.VMAddr + seg.FileSize)

/// Converts a Mach VM protection value (initprot/maxprot) to a B2R2 Permission.
/// The two use different bit layouts, so a direct cast would be wrong (e.g.,
/// Mach READ = 1 collides with B2R2 Permission.Executable = 1).
let machVMProtToPermission (prot: int) =
  let mp: MachVMProt = LanguagePrimitives.EnumOfValue prot
  (if mp.HasFlag MachVMProt.Readable then Permission.Readable else enum 0)
  ||| (if mp.HasFlag MachVMProt.Writable then Permission.Writable else enum 0)
  ||| (if mp.HasFlag MachVMProt.Executable then Permission.Executable
       else enum 0)

let executableRanges segCmds =
  segCmds
  |> Array.filter (fun seg ->
    let prot: MachVMProt = LanguagePrimitives.EnumOfValue seg.InitProt
    prot.HasFlag MachVMProt.Executable)
  |> Array.fold (fun set s ->
    IntervalSet.add (AddrRange.create s.VMAddr (s.VMAddr + s.VMSize - 1UL)) set
    ) IntervalSet.empty

/// Returns the given Mach protection bit where the permissions carry the
/// right it stands for, and no bit at all where they do not.
let private pick (perm: Permission) (has: Permission) (flag: MachVMProt) =
  if perm.HasFlag has then flag else enum 0

/// Returns the protections a segment carrying the given permissions is
/// mapped with, which is the inverse of machVMProtToPermission: the two spell
/// the same three rights out in bits of their own.
let permissionToMachVMProt (perm: Permission) =
  let r = pick perm Permission.Readable MachVMProt.Readable
  let w = pick perm Permission.Writable MachVMProt.Writable
  let x = pick perm Permission.Executable MachVMProt.Executable
  int (r ||| w ||| x)

/// Returns the segment that holds the given file offset, which is how an
/// offset a load command names is turned into the address it is mapped at.
/// __PAGEZERO and the like occupy no file bytes, so they hold nothing.
let private tryFindSegmentOfOffset segCmds offset =
  segCmds
  |> Array.tryFind (fun s ->
    offset >= s.FileOff && offset < s.FileOff + s.FileSize)

/// Returns the address range an encryption info command covers. The command
/// gives a file offset, so a range the segments do not map is one that names
/// no address at all.
let private toEncryptedRange segCmds cmd =
  let offset = uint64 cmd.CryptOffset
  match tryFindSegmentOfOffset segCmds offset with
  | Some seg ->
    let saddr = seg.VMAddr + offset - seg.FileOff
    Some(AddrRange.create saddr (saddr + uint64 cmd.CryptSize - 1UL))
  | None ->
    None

/// Returns the ranges of the image that ship encrypted, whose bytes decode to
/// nothing meaningful until a loader has decrypted them. A zero cryptid is
/// what a linker writes for a range that nobody has encrypted yet, so it
/// names no such range.
let encryptedRanges segCmds cmds =
  cmds
  |> Array.choose (function
    | EncryptionInfo(_, _, c) when c.CryptId <> 0u && c.CryptSize > 0u ->
      toEncryptedRange segCmds c
    | _ ->
      None)

/// Returns the images a fileset container holds, in the order it names them.
/// Every other kind of Mach-O file holds none.
let filesetEntries cmds =
  cmds
  |> Array.choose (function
    | FilesetEntry(_, _, e) -> Some e
    | _ -> None)

/// Returns the initialization routines LC_ROUTINES names, which a library
/// built before the pointer arrays took the job over carries in place of
/// one. No toolchain has emitted the command in a long while.
let initRoutines cmds =
  cmds
  |> Array.choose (function
    | Routines(_, _, addr) -> addr
    | _ -> None)

/// The section types holding an array of pointers to the functions an image
/// runs on its way up and down, which is where the constructors and the
/// destructors of a C++ translation unit are registered.
let private funcPointerTypes =
  [| SectionType.S_MOD_INIT_FUNC_POINTERS
     SectionType.S_MOD_TERM_FUNC_POINTERS |]

/// Returns how many pointers the given section holds, counting only the ones
/// the file has the bytes for, so a section naming more than the file
/// carries is read as far as it goes rather than past the end of it.
let private countFuncPointers (bytes: byte[]) sec entrySize =
  let avail = bytes.Length - int sec.SecOffset
  if avail <= 0 then 0 else min (int sec.SecSize) avail / entrySize

/// Returns the functions one array of pointers names. dyld, not the linker,
/// is what writes such a pointer in an image it fixes up: the slot holds a
/// chain entry there, or is left to a rebase opcode, so the fixup names the
/// function where the bytes on disk do not.
let private readFuncPointers toolBox resolve sec =
  let cls = toolBox.Header.Class
  let entrySize = selectByWordSize cls 4 8
  let count = countFuncPointers toolBox.Bytes sec entrySize
  let span = ReadOnlySpan(toolBox.Bytes, int sec.SecOffset, count * entrySize)
  let addrs = ResizeArray()
  for i = 0 to count - 1 do
    match resolve (sec.SecAddr + uint64 (i * entrySize)) with
    | Some target ->
      addrs.Add target
    | None ->
      let raw = readUIntByWordSize span toolBox.Reader cls (i * entrySize)
      if raw <> 0UL then addrs.Add(raw + toolBox.BaseAddress) else ()
  addrs.ToArray()

/// Returns the functions the initializer and terminator pointer arrays of an
/// image name, which is where every toolchain of the last twenty years puts
/// what LC_ROUTINES once named.
let funcPointerAddrs toolBox secs resolve =
  secs
  |> Array.filter (fun sec -> Array.contains sec.SecType funcPointerTypes)
  |> Array.collect (readFuncPointers toolBox resolve)

/// The linker option forms that join the library name to the flag itself, as
/// autolinking writes -lfoo.
let private joinedLibFlags = [| "-l"; "-weak-l"; "-needed-l"; "-hidden-l" |]

/// The linker option forms that leave the library name to the string that
/// comes after, as autolinking writes -framework Bar.
let private splitLibFlags =
  [| "-framework"; "-weak_framework"; "-needed_framework" |]

/// Returns the library the given option names when the name is joined to the
/// flag. A flag carrying nothing after it names none.
let private tryJoinedLibName (opt: string) =
  joinedLibFlags
  |> Array.tryPick (fun flag ->
    if opt.StartsWith flag && opt.Length > flag.Length then
      Some opt[flag.Length..]
    else
      None)

/// Returns the libraries the given run of linker option strings names, in the
/// order they appear. An option asking the linker for anything else, and a
/// framework flag with no name after it, names none.
let rec private collectLibNames opts acc =
  match opts with
  | [] ->
    List.rev acc
  | opt :: name :: rest when Array.contains opt splitLibFlags ->
    collectLibNames rest (name :: acc)
  | opt :: rest ->
    match tryJoinedLibName opt with
    | Some name -> collectLibNames rest (name :: acc)
    | None -> collectLibNames rest acc

/// Returns the libraries one linker option command names.
let private libNamesOf (opts: string[]) =
  collectLibNames (List.ofArray opts) [] |> List.toArray

/// Returns the options each LC_LINKER_OPTION command carries, in the order
/// the file names them. Only an object file carries any.
let linkerOptions cmds =
  cmds
  |> Array.choose (function
    | LinkerOption(_, _, opts) -> Some opts
    | _ -> None)

/// Returns the libraries an object file asks to be linked against, named the
/// way the linker flag names them rather than by the install path that only a
/// linked image knows. Autolinking repeats a directive for every translation
/// unit carrying it, so a library is named once however many commands name it.
let autolinkedLibraries cmds =
  linkerOptions cmds
  |> Array.collect libNamesOf
  |> Array.distinct

let getPLT symInfo =
  symInfo.Imports
  |> Array.sortBy (fun entry -> entry.TrampolineAddress)
