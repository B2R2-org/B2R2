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

namespace B2R2.MiddleEnd.Reclaimer

open B2R2
open B2R2.MiddleEnd.BinEssence

module private SpeculativeGapCompletionHelper =
  /// XXX: Should be fixed
  let findGaps (ess: BinEssence) sAddr eAddr =
    ess.InstrMap.Keys
    |> Seq.filter (fun addr -> addr >= sAddr && addr < eAddr)
    |> Seq.sort
    |> Seq.fold (fun (gaps, prevAddr) addr ->
      let nextAddr =
        addr + uint64 ess.InstrMap.[addr].Instruction.Length
      if prevAddr >= addr then gaps, nextAddr
      else AddrRange (prevAddr, addr) :: gaps, nextAddr
      ) ([], sAddr)
    |> fun (gaps, nextAddr) ->
      if nextAddr >= eAddr then gaps
      else AddrRange (nextAddr, eAddr) :: gaps

  let rec shiftUntilValid ess entries (gap: AddrRange) =
    let entry = [ gap.Min, ess.BinHandle.Parser.OperationMode ]
    match BinEssence.initByEntries ess.BinHandle entry with
    | Ok _ -> AddrRange (gap.Min, gap.Max) :: entries
    | Error _ ->
      if gap.Min + 1UL = gap.Max then entries
      else
        let gap' = AddrRange (gap.Min + 1UL, gap.Max)
        shiftUntilValid ess entries gap'

  let shiftByOne entries (gap: AddrRange) =
    let nextAddr = gap.Min + 1UL
    if gap.Max <= nextAddr then entries
    else AddrRange (nextAddr, gap.Max) :: entries

  let shiftGaps fn gaps =
    gaps |> List.fold fn []

  let updateResults branchRecovery ess ess' =
    let mode = ess'.BinHandle.Parser.OperationMode
    let entries =
      ess'.CalleeMap.Entries |> Set.toList |> List.map (fun a -> a, mode)
    match BinEssence.addEntries ess entries with
    | Ok ess ->
      { ess with IndirectBranchMap = ess'.IndirectBranchMap }
      |> (branchRecovery: BranchRecovery).CalculateTable
    | Error _ -> ess

  let rec recoverGaps branchRecovery ess gaps =
    match shiftGaps (shiftUntilValid ess) gaps with
    | [] -> ess
    | gaps ->
      let mode = ess.BinHandle.Parser.OperationMode
      let ents = gaps |> List.map (fun g -> g.Min, mode)
      match BinEssence.initByEntries ess.BinHandle ents with
      | Ok partial ->
        let isTarget addr =
          ess.IndirectBranchMap
          |> Map.exists (fun _ { HostFunctionAddr = entry } -> entry = addr)
          |> not
        let ess =
          isTarget
          |> (branchRecovery: BranchRecovery).RunWith partial
          |> updateResults branchRecovery ess
        gaps
        |> List.map (fun gap -> findGaps ess gap.Min gap.Max)
        |> List.concat
        |> recoverGaps branchRecovery ess
      | Error _ ->
        recoverGaps branchRecovery ess (shiftGaps shiftByOne gaps)

  let run branchRecovery ess =
    ess.BinHandle.FileInfo.GetTextSections ()
    |> Seq.map (fun sec ->
      let sAddr, eAddr = sec.Address, sec.Address + sec.Size
      findGaps ess sAddr eAddr)
    |> List.concat
    |> recoverGaps branchRecovery ess

type SpeculativeGapCompletion (enableNoReturn) =
  let branchRecovery = BranchRecovery (enableNoReturn)

  interface IAnalysis with
    member __.Name = "Speculative Gap Completion"

    member __.Run ess hint =
      SpeculativeGapCompletionHelper.run branchRecovery ess, hint
