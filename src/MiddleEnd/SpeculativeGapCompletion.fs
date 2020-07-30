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

namespace B2R2.MiddleEnd

open B2R2
open B2R2.FrontEnd
open B2R2.BinCorpus
open B2R2.BinGraph

module private SpeculativeGapCompletionHelper =
  /// XXX: Should be fixed
  let findGaps (corpus: BinCorpus) sAddr eAddr =
    corpus.InstrMap.Keys
    |> Seq.filter (fun addr -> addr >= sAddr && addr < eAddr)
    |> Seq.sort
    |> Seq.fold (fun (gaps, prevAddr) addr ->
      let nextAddr = addr + uint64 corpus.InstrMap.[addr].Instruction.Length
      if prevAddr >= addr then gaps, nextAddr
      else AddrRange (prevAddr, addr) :: gaps, nextAddr
      ) ([], sAddr)
    |> fun (gaps, nextAddr) ->
      if nextAddr >= eAddr then gaps
      else AddrRange (nextAddr, eAddr) :: gaps

  let rec shiftUntilValid hdl corpus entries (gap: AddrRange) =
    let entry = Set.singleton gap.Min
    match BinCorpus.initByEntries hdl DefaultGraph entry with
    | Ok _ -> AddrRange (gap.Min, gap.Max) :: entries
    | Error _ ->
      if gap.Min + 1UL = gap.Max then entries
      else
        let gap' = AddrRange (gap.Min + 1UL, gap.Max)
        shiftUntilValid hdl corpus entries gap'

  let shiftByOne entries (gap: AddrRange) =
    let nextAddr = gap.Min + 1UL
    if gap.Max <= nextAddr then entries
    else AddrRange (nextAddr, gap.Max) :: entries

  let shiftGaps fn gaps =
    gaps |> List.fold fn []

  let updateResults branchRecovery hdl corpus resultCorpus =
    match resultCorpus.SCFG.CalleeMap.Entries |> BinCorpus.addEntries hdl corpus None with
    | Ok corpus ->
      resultCorpus.SCFG.IndirectBranchMap
      |> BinCorpus.addIndirectBranchMap hdl corpus
      |> (branchRecovery: BranchRecovery).CalculateTable hdl
    | Error _ -> corpus

  let rec recoverGaps branchRecovery hdl corpus gaps =
    match shiftGaps (shiftUntilValid hdl corpus) gaps with
    | [] -> corpus
    | gaps ->
      let ents =
        gaps |> List.map (fun g -> g.Min) |> Set.ofList
      match BinCorpus.initByEntries hdl DefaultGraph ents with
      | Ok partialCorpus ->
        let isTarget addr =
          corpus.SCFG.IndirectBranchMap
          |> Map.exists (fun _ { HostFunctionAddr = entry } -> entry = addr)
          |> not
        let corpus =
          isTarget
          |> (branchRecovery: BranchRecovery).RunWith hdl partialCorpus
          |> updateResults branchRecovery hdl corpus
        gaps
        |> List.map (fun gap -> findGaps corpus gap.Min gap.Max)
        |> List.concat
        |> recoverGaps branchRecovery hdl corpus
      | Error _ ->
        recoverGaps branchRecovery hdl corpus (shiftGaps shiftByOne gaps)

  let run branchRecovery hdl corpus =
    hdl.FileInfo.GetTextSections ()
    |> Seq.map (fun sec ->
      let sAddr, eAddr = sec.Address, sec.Address + sec.Size
      findGaps corpus sAddr eAddr)
    |> List.concat
    |> recoverGaps branchRecovery hdl corpus

type SpeculativeGapCompletion (enableNoReturn) =
  let branchRecovery = BranchRecovery (enableNoReturn)

  interface IAnalysis with
    member __.Name = "Speculative Gap Completion"

    member __.Run hdl corpus =
      SpeculativeGapCompletionHelper.run branchRecovery hdl corpus
