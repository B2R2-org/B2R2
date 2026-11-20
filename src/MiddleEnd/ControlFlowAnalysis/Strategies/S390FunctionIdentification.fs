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
open System.Runtime.CompilerServices
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.ControlFlowAnalysis.Strategies.FunctionIdentificationCommon

/// Represents the function identification for S390. It takes what the binary
/// tells, as FunctionIdentification does, and then finds the functions that
/// the data of the binary points to, as clang emits no call frame information
/// for C code that would tell every function up front, and nothing calls a
/// function that only a pointer leads to, such as one in a table of
/// callbacks. A word of data may name code that starts no function, as an
/// entry of a jump table does, so it starts one only where the code shows a
/// function starting, as S390Code tells, which the code alone tells, so that
/// the recovery knows every such function before it starts, as it bounds a
/// table by the next function. The same goes for an address that recovered
/// code takes as a constant, as code does that passes a callback or stores a
/// function pointer, and for where a recovered function jumps past the next
/// function or before its own entry, as it calls another as its tail, which
/// the identification finds in what the recovery builds, and for where code
/// resumes past a recovered function, past the nops and the templates of EXRL
/// that follow it, as nothing else leads to a function that nothing calls or
/// points to.
type S390FunctionIdentification(hdl: BinHandle, exnInfo: ExceptionInfo) =
  let metadata = FunctionIdentification(hdl, exnInfo) :> IFunctionIdentifiable

  let file = hdl.File

  /// The address ranges of the code that a function may start in.
  let codeRanges = findCodeRanges file

  /// The bits of an address, which leave out the leftmost bit of a word in
  /// the 31-bit mode.
  let addressMask =
    if hdl.ISA.WordSize = WordSize.Bit32 then 0x7FFFFFFFUL
    else System.UInt64.MaxValue

  /// What the call frame information gives functions past their entries,
  /// where no function starts.
  let framedBodies =
    BinFileOps.getExceptionFrames file
    |> Seq.filter (fun frame -> frame.FunctionStart < frame.FunctionEnd)
    |> Seq.map (fun frame ->
      AddrRange.create (frame.FunctionStart + 1UL) frame.FunctionEnd)
    |> Seq.toArray
    |> AddrRangeUnion.ofArray

  /// Tells whether the value names code of this binary that a function may
  /// start at: an even address, as every instruction of S390 starts at one,
  /// in a section of such code, where no entry of the import table lies, and
  /// past the entry of no function that the call frame information tells. The
  /// loader maps more than the sections, such as the headers of the file and
  /// read-only data, along with code, so a number that names an address there
  /// names no code, and a jump table of GCC, whose entries name code in the
  /// middle of a function, may hold nothing but the returns of its cases,
  /// which read nothing that code above left.
  let isCodePointer (v: uint64) =
    v % 2UL = 0UL
    && codeRanges |> Array.exists (fun r -> r.IsIncluding v)
    && not (BinFileOps.isInImportTable file v)
    && not (AddrRangeUnion.containsAddr v framedBodies)

  /// Names the sections that hold nothing but pointers and variables, whose
  /// every word that names code is a pointer.
  let pointerSectionNames =
    set [ ".data"
          ".data.rel.ro"
          ".fini_array"
          ".got"
          ".init_array"
          ".preinit_array" ]

  /// The size of a pointer, to which S390 aligns one.
  let pointerSize = WordSize.toByteWidth hdl.ISA.WordSize |> uint64

  /// Returns the words of the section that name code, each with where it
  /// lies, reading one at every aligned slot.
  let readCodeWords (section: BinSection) =
    let first = (section.Address + pointerSize - 1UL) / pointerSize
    let last = (section.Address + section.Size) / pointerSize
    [| first * pointerSize .. pointerSize .. last * pointerSize - pointerSize |]
    |> Array.choose (fun slot ->
      match hdl.TryReadUInt(slot, int pointerSize) with
      | Ok v when isCodePointer (v &&& addressMask) ->
        Some(slot, v &&& addressMask)
      | _ ->
        None)

  /// Where the executable sections start, which no code runs into from above.
  let sectionStarts = findSectionStarts file

  let lu = hdl.NewLiftingUnit()

  /// What the code at each address shows of a function starting there, as
  /// telling it takes lifting.
  let entryEvidence = Dictionary<Addr, bool>()

  /// Tells whether the code at the address shows a function starting there.
  let showsEntry addr =
    match entryEvidence.TryGetValue addr with
    | true, shows ->
      shows
    | false, _ ->
      let shows = S390Code.showsEntry lu (sectionStarts.Contains addr) addr
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
  /// that shows a function starting. Read-only data holds tables of
  /// callbacks along with jump tables, whose entries name code in the middle
  /// of a function, which reads what the code before the jump left, while a
  /// table of callbacks holds nothing else.
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
      |> Seq.map (fun v -> v &&& addressMask)
      |> Seq.filter isCodePointer
      |> Seq.distinct
      |> Seq.filter showsEntry
      |> Seq.toArray
    else
      storedEntries () |> Array.distinct

  /// Returns the addresses that the code that the recovery has built for the
  /// function takes as constants.
  let readTakenAddresses (fn: Function) =
    fn.CFG.Vertices
    |> Array.filter (fun v -> not v.VData.Internals.IsAbstract)
    |> Array.collect (fun v -> v.VData.Internals.Instructions)
    |> Array.choose (fun ins ->
      S390Code.tryTakenAddress (ins :?> S390.Instruction))
    |> Array.map (fun addr -> addr &&& addressMask)

  /// The addresses that the code of each recovered function takes as
  /// constants, by its CFG, with the counts of its vertices and edges, as
  /// reading them takes every instruction of the function, while most
  /// functions stay the same from round to round of identification.
  let takenByCFG = ConditionalWeakTable<LowUIRCFG, _>()

  /// Returns the addresses that the code that the recovery has built for the
  /// function takes as constants, reading them anew only once the function has
  /// changed.
  let addressesTakenBy fn = readOnce takenByCFG readTakenAddresses fn

  /// Returns what the blocks that the recovery has built for the function
  /// cover.
  let readBuiltCode (fn: Function) =
    fn.CFG.Vertices
    |> Array.filter (fun v -> not v.VData.Internals.IsAbstract)
    |> Array.map (fun v -> v.VData.Internals.Range)
    |> AddrRangeUnion.ofArray

  /// What the blocks of each recovered function cover, by its CFG, with the
  /// counts of its vertices and edges, as telling it takes every block of the
  /// function.
  let builtCodeByCFG = ConditionalWeakTable<LowUIRCFG, _>()

  /// Returns what the blocks that the recovery has built for the function
  /// cover, reading them anew only once the function has changed.
  let findBuiltCode fn = readOnce builtCodeByCFG readBuiltCode fn

  /// Returns where the given code that the recovery has built ends, past its
  /// last block, if it has built any.
  let tryFindCodeEnd (built: AddrRangeUnion) =
    Array.tryLast built.Ranges |> Option.map (fun range -> range.Max + 1UL)

  /// What the code at each address where code resumes past a recovered
  /// function shows of a function starting there.
  let resumeEvidence = Dictionary<Addr, bool>()

  /// Tells whether the code at the address, where code resumes past a
  /// recovered function, shows a function starting there.
  let showsEntryPastCode addr =
    match resumeEvidence.TryGetValue addr with
    | true, shows ->
      shows
    | false, _ ->
      let isSectionStart = sectionStarts.Contains addr
      let shows = S390Code.showsEntryPastCode lu isSectionStart addr
      resumeEvidence[addr] <- shows
      shows

  /// Whether the code of each recovered function jumps to where code resumes
  /// past it, by what the recovery has built of the function, along with
  /// where code resumes, as telling it takes reading the whole function.
  let jumpsByBuiltCode = ConditionalWeakTable<AddrRangeUnion, Addr * bool>()

  /// Tells whether the code of the function at the given entry, of which the
  /// recovery has built the given code, jumps to the given address where code
  /// resumes past it. The code that the recovery has yet to build is the
  /// function's own up to where it shows another function starting.
  let jumpsAhead entry built start =
    match jumpsByBuiltCode.TryGetValue built with
    | true, (startOfCache, jumps) when startOfCache = start ->
      jumps
    | _ ->
      let startsAnother addr =
        not (AddrRangeUnion.containsAddr addr built) && showsEntryPastCode addr
      let jumps = S390Code.jumpsAhead lu entry start startsAnother
      jumpsByBuiltCode.AddOrUpdate(built, (start, jumps))
      jumps

  /// Tells whether the given vertex of the CFG calls an external function that
  /// never returns, which its name tells for sure, such as abort, unlike what
  /// the recovery finds of a function of the binary, which it may yet find to
  /// return.
  let callsNoReturnExternal (cfg: LowUIRCFG) v =
    cfg.GetSuccs v
    |> Array.exists (fun w ->
      let bbl = w.VData.Internals
      bbl.IsAbstract
      && bbl.AbstractContent.IsExternal
      && bbl.AbstractContent.ReturningStatus = NoRet)

  /// Tells whether the code that the recovery has built for the function ends
  /// the flow where it ends, at the given address, as the last instruction of
  /// its last block returns or jumps, or calls an external function that never
  /// returns.
  let endsFlowAt (fn: Function) codeEnd =
    fn.CFG.Vertices
    |> Array.exists (fun v ->
      let bbl = v.VData.Internals
      not bbl.IsAbstract
      && bbl.Range.Max + 1UL = codeEnd
      && (S390Code.leaves bbl.LastInstruction
          || callsNoReturnExternal fn.CFG v))

  /// Tells whether the code where code resumes past the given function, at the
  /// given start past the end of its code, shows a function starting there,
  /// either by the code right above the start, or, past code of the function
  /// that ends the flow, by the code at the start alone.
  let showsEntryPast fn codeEnd start =
    showsEntryPastCode start
    || (endsFlowAt fn codeEnd && S390Code.showsEntryPastFlowEnd lu start)

  /// Returns where code resumes past each of the given functions: past the end
  /// of its code and the padding there, before the next entry, where no code
  /// of a function at or before it reaches, nor its code jumps to, as it does
  /// to a block of its own that the recovery has yet to build. Nothing else
  /// leads to a function that nothing calls or points to, such as one that
  /// only calls itself.
  let findNextStarts internals =
    withNextEntries internals
    |> Array.fold (fun (reach, starts) (fn: Function, next) ->
      let built = findBuiltCode fn
      match tryFindCodeEnd built with
      | Some codeEnd ->
        let reach = max reach codeEnd
        let start = S390Code.skipPadding lu codeEnd next
        if start < next && start >= reach then
          reach, (fn, built, codeEnd, start) :: starts
        else
          reach, starts
      | None ->
        reach, starts) (0UL, [])
    |> snd
    |> List.filter (fun (fn, built, codeEnd, start) ->
      isCodePointer start
      && showsEntryPast fn codeEnd start
      && not (jumpsAhead fn.EntryPoint built start))
    |> List.map (fun (_, _, _, start) -> start)
    |> List.toArray

  interface IIncrementalFunctionIdentifiable with
    member _.Identify() =
      Array.append (metadata.Identify()) (findLikelyEntries ())
      |> Array.distinct

    member _.IdentifyMore recovered =
      let internals = recovered |> Array.filter (fun fn -> not fn.IsExternal)
      Array.append
        (Array.collect addressesTakenBy internals)
        (findTailCallTargets internals)
      |> Array.filter (fun addr -> isCodePointer addr && showsEntry addr)
      |> Array.append (findNextStarts internals)
      |> Array.distinct
