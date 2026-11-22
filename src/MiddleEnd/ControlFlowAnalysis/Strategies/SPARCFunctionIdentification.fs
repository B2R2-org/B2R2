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
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.ControlFlowAnalysis.ExternalFunctionLoader
open B2R2.MiddleEnd.ControlFlowAnalysis.Strategies.FunctionIdentificationCommon

/// Represents the function identification for SPARC. It takes what the binary
/// tells, as FunctionIdentification does, and then finds the functions that
/// the data of the binary points to, as neither GCC nor clang emits call frame
/// information for SPARC code that would tell every function up front, and
/// nothing calls a function that only a pointer leads to, such as one in a
/// table of callbacks. A word of data may name code that starts no function,
/// so it starts one only where the code shows a function starting, as
/// SPARCCode tells, which the code alone tells, so that the recovery knows
/// every such function before it starts.
type SPARCFunctionIdentification(hdl: BinHandle, exnInfo: ExceptionInfo) =
  let metadata = FunctionIdentification(hdl, exnInfo) :> IFunctionIdentifiable

  let file = hdl.File

  /// The address ranges of the code that a function may start in.
  let codeRanges = findCodeRanges file

  /// Tells whether the value names code of this binary that a function may
  /// start at: a word-aligned address in a section of such code, where no
  /// entry of the import table lies. The loader maps more than the sections,
  /// such as the headers of the file and read-only data, along with code, so
  /// a number that names an address there names no code.
  let isCodePointer (v: uint64) =
    v % 4UL = 0UL
    && codeRanges |> Array.exists (fun r -> r.IsIncluding v)
    && not (BinFileOps.isInImportTable file v)

  /// Names the sections that hold nothing but pointers and variables, whose
  /// every word that names code is a pointer.
  let pointerSectionNames =
    set [ ".data"
          ".data.rel.ro"
          ".fini_array"
          ".got"
          ".init_array"
          ".preinit_array" ]

  /// The size of a pointer, to which SPARC aligns one.
  let pointerSize = WordSize.toByteWidth hdl.ISA.WordSize |> uint64

  /// Returns the words of the section that name code, each with where it
  /// lies, reading one at every aligned slot.
  let readCodeWords (section: BinSection) =
    let first = (section.Address + pointerSize - 1UL) / pointerSize
    let last = (section.Address + section.Size) / pointerSize
    [| first * pointerSize .. pointerSize .. last * pointerSize - pointerSize |]
    |> Array.choose (fun slot ->
      match hdl.TryReadUInt(slot, int pointerSize) with
      | Ok v when isCodePointer v -> Some(slot, v)
      | _ -> None)

  /// Where the executable sections start, which no code runs into from above.
  let sectionStarts = findSectionStarts file

  let lu = hdl.NewLiftingUnit()

  /// The stubs of the imports that never return, as their names tell for
  /// sure, such as _exit.
  let noReturnStubs =
    let cc = hdl.Conventions.Calling
    let isNoRet (entry: BinImport) =
      ELF.getNoReturnStatusFromKnownFunc cc entry.Name = NoRet
    match file.ImportTable with
    | Some tbl ->
      tbl.Imports
      |> Seq.filter isNoRet
      |> Seq.choose (fun entry -> entry.TrampolineAddress)
      |> HashSet
    | None ->
      HashSet()

  /// Tells whether the function at the given address never returns, as the
  /// stub of an import that its name tells never to return.
  let neverReturns callee = noReturnStubs.Contains callee

  /// What the code at each address shows of a function starting there, as
  /// telling it takes lifting.
  let entryEvidence = Dictionary<Addr, bool>()

  /// Tells whether the code at the address shows a function starting there.
  let showsEntry addr =
    match entryEvidence.TryGetValue addr with
    | true, shows ->
      shows
    | false, _ ->
      let isSectionStart = sectionStarts.Contains addr
      let shows = SPARCCode.showsEntry lu neverReturns isSectionStart addr
      entryEvidence[addr] <- shows
      shows

  /// Splits the given words, which are in order, into runs of words that lie
  /// next to each other.
  let splitIntoRuns (words: (Addr * Addr)[]) =
    let runs = List<List<Addr>>()
    let mutable lastSlot = None
    for slot, v in words do
      match lastSlot with
      | Some last when slot = last + pointerSize -> runs[runs.Count - 1].Add v
      | _ -> runs.Add(List [ v ])
      lastSlot <- Some slot
    runs

  /// Returns the code addresses that the runs of words naming code in the
  /// read-only data hold, keeping only the runs whose every word names code
  /// that shows a function starting, as a table of callbacks holds nothing
  /// else.
  let readTablesOfCallbacks (section: BinSection) =
    readCodeWords section
    |> splitIntoRuns
    |> Seq.filter (Seq.forall showsEntry)
    |> Seq.concat
    |> Seq.toArray

  /// Returns the code addresses that the data sections of the binary hold as
  /// they are, at which the code shows a function starting.
  let storedEntries () =
    BinFileOps.getSections file
    |> Seq.collect (fun s ->
      if pointerSectionNames.Contains s.Name then
        readCodeWords s |> Array.map snd |> Array.filter showsEntry
      elif s.Name = ".rodata" then
        readTablesOfCallbacks s
      else
        [||])
    |> Seq.toArray

  /// Returns the code addresses in data at which the code shows a function
  /// starting. A binary that the loader relocates has one wherever a
  /// relocation writes one, and nowhere else, while one that stays where it is
  /// linked has its pointers in its data sections as they are.
  let findLikelyEntries () =
    if file.IsBaseRelative then
      relocatedValues file
      |> Seq.filter isCodePointer
      |> Seq.distinct
      |> Seq.filter showsEntry
      |> Seq.toArray
    else
      storedEntries () |> Array.distinct

  interface IFunctionIdentifiable with
    member _.Identify() =
      Array.append (metadata.Identify()) (findLikelyEntries ())
      |> Array.distinct
