(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>
          Seung Il Jung <sijung@kaist.ac.kr>
          DongYeop Oh <oh51dy@kaist.ac.kr>

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

namespace B2R2.BinFile

open B2R2
open System.Runtime.InteropServices

/// FileInfo describes a binary file in a format-agnostic way.
[<AbstractClass>]
type FileInfo () =
  /// <summary>
  ///   The format of this file: ELF, PE, Mach-O, or etc.
  /// </summary>
  abstract FileFormat: FileFormat

  /// <summary>
  ///   What kind of binary is this?
  /// </summary>
  abstract FileType: FileType

  /// <summary>
  ///   The file path where this file is located.
  /// </summary>
  abstract FilePath: string

  /// <summary>
  ///   Is this binary stripped?
  /// </summary>
  abstract IsStripped: bool

  /// <summary>
  ///   Word size of the CPU that this binary can run on.
  /// </summary>
  abstract WordSize: WordSize

  /// <summary>
  ///   Is NX enabled for this binary?
  /// </summary>
  abstract NXEnabled: bool

  /// <summary>
  ///   The entry point of this binary (the start address that this binary runs
  ///   at). Note that some binaries (e.g., PE DLL files) do not have a specific
  ///   entry point, and EntryPoint will return zero in such a case.
  /// </summary>
  abstract EntryPoint: Addr

  /// <summary>
  ///   The beginning of the text section of this binary.
  /// </summary>
  abstract TextStartAddr: Addr

  /// <summary>
  ///   Translate a virtual address into a relative offset to this binary.
  /// </summary>
  /// <param name="addr">Virtual address.</param>
  /// <returns>
  ///   Returns an offset to this binary for a given virtual address.
  /// </returns>
  /// <exception cref="T:B2R2.BinFile.InvalidAddrReadException">
  ///   Thrown when the given address is out of a valid address range.
  /// </exception>
  abstract member TranslateAddress: addr: Addr -> int

  /// <summary>
  ///   Find the start address of the symbol chunk, which includes the given
  ///   address. We let a symbol chunk be a consecutive sequence of code/data
  ///   that corresponds to the same symbol.
  /// </summary>
  /// <returns>
  ///   Returns a start address of the symbol chunk if it exists. Otherwise, it
  ///   raises an exception.
  /// </returns>
  /// <exception cref="T:B2R2.BinFile.InvalidAddrReadException">
  ///   Thrown when the given address is out of a valid address range.
  /// </exception>
  abstract member FindSymbolChunkStartAddress: Addr -> Addr

  /// <summary>
  ///   Return a list of all the symbols from the binary.
  /// </summary>
  /// <returns>
  ///   A sequence of symbols.
  /// </returns>
  abstract member GetSymbols: unit -> seq<Symbol>

  /// <summary>
  ///   Return a list of all the static symbols from the binary.
  /// </summary>
  /// <returns>
  ///   A sequence of static symbols.
  /// </returns>
  abstract member GetStaticSymbols: unit -> seq<Symbol>

  /// <summary>
  ///   Return a list of all the dynamic symbols from the binary.
  /// </summary>
  /// <returns>
  ///   A sequence of dynamic symbols.
  /// </returns>
  abstract member GetDynamicSymbols: unit -> seq<Symbol>

  /// <summary>
  ///   Return a list of all the sections from the binary.
  /// </summary>
  /// <returns>
  ///   A sequence of sections.
  /// </returns>
  abstract member GetSections: unit -> seq<Section>

  /// <summary>
  ///   Return a section that contains the given address.
  /// </summary>
  /// <param name="addr">The address that belongs to a section.</param>
  /// <returns>
  ///   A sequence of sections. This function returns a singleton if there
  ///   exists a corresponding section. Otherwise, it returns an empty sequence.
  /// </returns>
  abstract member GetSections: addr: Addr -> seq<Section>

  /// <summary>
  ///   Return a section that has the specified name.
  /// </summary>
  /// <param name="name">The name of the section.</param>
  /// <returns>
  ///   A sequence of sections that have the specified name. This function
  ///   returns an empty sequence if there is no section of the given name.
  /// </returns>
  abstract member GetSectionsByName: name: string -> seq<Section>

  /// <summary>
  ///   Return a list of all the linkage table entries from the binary.
  /// </summary>
  /// <returns>
  ///   A sequence of linkage table entries, e.g., PLT entries for ELF files.
  /// </returns>
  abstract member GetLinkageTableEntries: unit -> seq<LinkageTableEntry>

  /// <summary> todo </summary>
  abstract member GetRelocationSymbols: unit -> seq<Symbol>

  /// <summary>
  ///   Return a list of all the segments from the binary.
  /// </summary>
  /// <returns>
  ///   A sequence of segments.
  /// </returns>
  abstract member GetSegments: unit -> seq<Segment>

  /// <summary>
  ///   Return a list of the segments from the binary, which contain the given
  ///   address.
  /// </summary>
  /// <param name="addr">The address that belongs to segments.</param>
  /// <returns>
  ///   A sequence of segments.
  /// </returns>
  member __.GetSegments (addr: Addr) =
    __.GetSegments ()
    |> Seq.filter (fun s -> (addr >= s.Address) && (addr < s.Address + s.Size))

  /// <summary>
  ///   For a given permission, return a list of segments that satisfy the
  ///   permission. For a given "READ-only" permission, this function may return
  ///   a segment whose permission is "READABLE and WRITABLE", as an instance.
  /// </summary>
  /// <returns>
  ///   A sequence of segments.
  /// </returns>
  member __.GetSegments (perm: Permission) =
    __.GetSegments ()
    |> Seq.filter (fun s -> (s.Permission &&& perm = perm) && s.Size > 0UL)

  /// <summary>
  ///   Find the symbol name for a given address.
  /// </summary>
  /// <returns>
  ///   Returns true if a symbol exists, otherwise returns false.
  /// </returns>
  abstract member TryFindFunctionSymbolName:
    Addr * [<Out>] name: byref<string>
    -> bool

  /// <summary>
  ///   Check if the given address is valid for this binary. We say a given
  ///   address is valid for the binary, if the address is within the range of
  ///   statically computable segment ranges.
  /// </summary>
  /// <returns>
  ///   Returns true if the address is within a valid range, false otherwise.
  /// </returns>
  abstract member IsValidAddr : Addr -> bool

  /// <summary>
  ///   Returns a sequence of local function addresses (excluding external
  ///   functions) from a given FileInfo.
  /// </summary>
  /// <returns>
  ///   A sequence of function addresses.
  /// </returns>
  member __.GetFunctionAddresses () =
    __.GetStaticSymbols ()
    |> Seq.filter (fun s -> s.Kind = SymbolKind.FunctionType)
    |> Seq.map (fun s -> s.Address)

  /// <summary>
  ///   Get a sequence of executable sections including linkage table code
  ///   sections such as PLT.
  /// </summary>
  /// <returns>
  ///   A sequence of executable sections.
  /// </returns>
  member __.GetExecutableSections () =
    __.GetSections ()
    |> Seq.filter (fun s -> (s.Kind = SectionKind.ExecutableSection)
                         || (s.Kind = SectionKind.LinkageTableSection))

  /// <summary>
  ///   Convert <see cref="T:B2R2.BinFile.FileType">FileType</see> to string.
  /// </summary>
  /// <param name="ty">A FileType to convert.</param>
  /// <returns>
  ///   A converted string.
  /// </returns>
  static member FileTypeToString (ty) =
    match ty with
    | FileType.ExecutableFile -> "Executable"
    | FileType.CoreFile -> "Core dump"
    | FileType.LibFile -> "Library"
    | FileType.ObjFile -> "Object"
    | _ -> "Unknown"

  /// <summary>
  ///   Convert from permission to string.
  /// </summary>
  /// <param name="perm">A permission to convert.</param>
  /// <returns>
  ///   A converted string.
  /// </returns>
  static member PermissionToString (p: Permission) =
    let r =
      if p &&& Permission.Readable = LanguagePrimitives.EnumOfValue 0 then ""
      else "R"
    let w =
      if p &&& Permission.Writable = LanguagePrimitives.EnumOfValue 0 then ""
      else "W"
    let x =
      if p &&& Permission.Executable = LanguagePrimitives.EnumOfValue 0 then ""
      else "X"
    r + w + x
