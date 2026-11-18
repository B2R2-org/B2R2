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

namespace B2R2.MiddleEnd.ControlFlowAnalysis.Strategies

open System.Collections.Generic
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Represents the function identification for m68k. It takes what the binary
/// tells, as FunctionIdentification does, and then finds the functions that
/// the data of the binary points to, as GCC emits no call frame information
/// for C code that would tell every function up front, and nothing calls a
/// function that only a pointer leads to, such as one in a table of
/// callbacks. A word of data may name code that starts no function, as a
/// number does that happens to look like a code address, so it starts one
/// only where the code shows a function starting, as M68KCode tells, which
/// the code alone tells, so that the recovery knows every such function
/// before it starts, as it bounds a table by the next function. The same goes
/// for an address that recovered code takes as a constant, as code does that
/// passes a callback or stores a function pointer, which the identification
/// finds in what the recovery builds.
type M68KFunctionIdentification(hdl: BinHandle, exnInfo: ExceptionInfo) =
  let metadata = FunctionIdentification(hdl, exnInfo) :> IFunctionIdentifiable

  let file = hdl.File

  /// Returns the values that the loader writes where it relocates the binary.
  let relocatedValues () =
    match file.Relocations with
    | Some relocs ->
      relocs.Relocations
      |> Seq.choose (fun reloc ->
        relocs.TryComputeRelocationValue reloc.Address |> Result.toOption)
    | None ->
      Seq.empty

  /// Tells whether the section holds code that a function may start in: it is
  /// executable, and it does not link the binary to others, as a PLT does,
  /// which serves imports.
  let isCodeSection (s: BinSection) =
    s.Permission.HasFlag Permission.Executable
    && s.Kind <> DynamicLinkageSection
    && s.Size > 0UL

  /// Lists the address ranges of the sections that hold code that a function
  /// may start in, or of the executable segments of a file without sections,
  /// such as a raw image.
  let codeRanges =
    let rangeOf (addr: Addr) size = AddrRange.create addr (addr + size - 1UL)
    let sections = BinFileOps.getSections file
    if sections.IsEmpty then
      BinFileOps.getSegments file
      |> Seq.filter (fun s -> s.Permission.HasFlag Permission.Executable)
      |> Seq.map (fun s -> rangeOf s.Address s.Size)
      |> Seq.toArray
    else
      sections
      |> Seq.filter isCodeSection
      |> Seq.map (fun s -> rangeOf s.Address s.Size)
      |> Seq.toArray

  /// Tells whether the value names code of this binary that a function may
  /// start at: an even address, as every instruction of m68k starts at one,
  /// in a section of such code, where no entry of the import table lies. The
  /// loader maps more than the sections, such as the headers of the file and
  /// read-only data, along with code, so a number that names an address there
  /// names no code.
  let isCodePointer (v: uint64) =
    v % 2UL = 0UL
    && codeRanges |> Array.exists (fun r -> r.IsIncluding v)
    && not (BinFileOps.isInImportTable file v)

  /// Names the sections that hold nothing but pointers.
  let pointerSectionNames =
    set [ ".fini_array"
          ".got"
          ".init_array"
          ".preinit_array" ]

  /// Names the sections that hold pointers among other data.
  let dataSectionNames =
    set [ ".data"
          ".data.rel.ro"
          ".rodata" ]

  /// Returns the words of the section that name code, each with where it
  /// lies, reading one at every halfword, as m68k aligns a pointer to two
  /// bytes.
  let readCodeWords (section: BinSection) =
    if section.Size < 4UL then
      [||]
    else
      [| section.Address .. 2UL .. section.Address + section.Size - 4UL |]
      |> Array.choose (fun addr ->
        match hdl.TryReadUInt(addr, 4) with
        | Ok v when isCodePointer v -> Some(addr, v)
        | _ -> None)

  /// The farthest that another word naming code lies from a pointer among
  /// other data, as pointers sit together, in tables and in structures.
  let [<Literal>] NeighborDistance = 32UL

  /// Tells whether another of the given slots, which are in order, lies near
  /// the one of the given index.
  let hasNeighbor (slots: Addr[]) idx =
    let slot = slots[idx]
    (idx > 0 && slot - slots[idx - 1] <= NeighborDistance)
    || (idx + 1 < slots.Length && slots[idx + 1] - slot <= NeighborDistance)

  /// Returns the code addresses that the words naming code hold: every one in
  /// a section of nothing but pointers, and in a section of other data only
  /// one that another word naming code lies near, as a number that happens to
  /// look like a code address sits among numbers.
  let keepPointers (words: (string * Addr * uint64)[]) =
    let slots = words |> Array.map (fun (_, slot, _) -> slot)
    words
    |> Array.indexed
    |> Array.choose (fun (idx, (name, _, v)) ->
      if pointerSectionNames.Contains name || hasNeighbor slots idx then Some v
      else None)

  /// Returns the code addresses that the data sections of the binary hold as
  /// they are.
  let storedValues () =
    BinFileOps.getSections file
    |> Seq.filter (fun s ->
      pointerSectionNames.Contains s.Name || dataSectionNames.Contains s.Name)
    |> Seq.collect (fun s ->
      readCodeWords s |> Array.map (fun (slot, v) -> s.Name, slot, v))
    |> Seq.sortBy (fun (_, slot, _) -> slot)
    |> Seq.toArray
    |> keepPointers

  /// Lists the code addresses that the data of the binary holds. A binary that
  /// the loader relocates has one wherever a relocation writes one, and
  /// nowhere else, while one that stays where it is linked has its pointers in
  /// its data sections as they are.
  let dataPointers () =
    if file.IsBaseRelative then
      relocatedValues ()
      |> Seq.map (fun v -> v &&& 0xFFFFFFFFUL)
      |> Seq.filter isCodePointer
      |> Seq.toArray
    else
      storedValues ()

  /// Where the executable sections start, which no code runs into from above.
  let sectionStarts =
    BinFileOps.getSections file
    |> Seq.filter (fun s -> s.Permission.HasFlag Permission.Executable)
    |> Seq.map (fun s -> s.Address)
    |> Set.ofSeq

  let lu = hdl.NewLiftingUnit()

  /// What the code at each address shows of a function starting there, as
  /// telling it takes decoding, while rounds of identification ask again.
  let entryEvidence = Dictionary<Addr, bool>()

  /// Tells whether the code at the address shows a function starting there.
  let showsEntry addr =
    match entryEvidence.TryGetValue addr with
    | true, shows ->
      shows
    | false, _ ->
      let shows = M68KCode.showsEntry lu (sectionStarts.Contains addr) addr
      entryEvidence[addr] <- shows
      shows

  /// Returns the code addresses in data at which the code shows a function
  /// starting.
  let findLikelyEntries () =
    dataPointers () |> Array.distinct |> Array.filter showsEntry

  /// Returns the addresses that the code that the recovery has built for the
  /// function takes as constants.
  let addressesTakenBy (fn: Function) =
    let isFixedBase = not file.IsBaseRelative
    fn.CFG.Vertices
    |> Array.filter (fun v -> not v.VData.Internals.IsAbstract)
    |> Array.collect (fun v -> v.VData.Internals.Instructions)
    |> Array.choose (fun ins ->
      M68KCode.tryTakenAddress isFixedBase (ins :?> M68K.Instruction))

  interface IIncrementalFunctionIdentifiable with
    member _.Identify() =
      Array.append (metadata.Identify()) (findLikelyEntries ())
      |> Array.distinct

    member _.IdentifyMore recovered =
      recovered
      |> Array.filter (fun fn -> not fn.IsExternal)
      |> Array.collect addressesTakenBy
      |> Array.distinct
      |> Array.filter (fun addr -> isCodePointer addr && showsEntry addr)
