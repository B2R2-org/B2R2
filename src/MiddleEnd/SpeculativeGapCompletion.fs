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
  let findGaps app sAddr eAddr =
    app.InstrMap.Keys
    |> Seq.filter (fun addr -> addr >= sAddr && addr < eAddr)
    |> Seq.sort
    |> Seq.fold (fun (gaps, prevAddr) addr ->
      let nextAddr = addr + uint64 app.InstrMap.[addr].Instruction.Length
      if prevAddr >= addr then gaps, nextAddr
      else AddrRange (prevAddr, addr) :: gaps, nextAddr
      ) ([], sAddr)
    |> fun (gaps, nextAddr) ->
      if nextAddr >= eAddr then gaps
      else AddrRange (nextAddr, eAddr) :: gaps

  let rec shiftUntilValid hdl scfg entries (gap: AddrRange) =
    let app' =
      LeaderInfo.Init (hdl, gap.Min)
      |> Set.singleton
      |> Apparatus.initWithoutDefaultEntry hdl
    match SCFG.Init (hdl, app', false) with
    | Error _ ->
      if gap.Min + 1UL = gap.Max then entries
      else
        let gap' = AddrRange (gap.Min + 1UL, gap.Max)
        shiftUntilValid hdl scfg entries gap'
    | Ok _ -> AddrRange (gap.Min, gap.Max) :: entries

  let shiftByOne entries (gap: AddrRange) =
    let nextAddr = gap.Min + 1UL
    if gap.Max <= nextAddr then entries
    else AddrRange (nextAddr, gap.Max) :: entries

  let shiftGaps fn gaps =
    gaps |> List.fold fn []

  let updateResults hdl scfg app (_, resultApp) =
    let app =
      Apparatus.getFunctionAddrs resultApp
      |> Set.ofSeq
      |> Set.map (fun addr -> LeaderInfo.Init (hdl, addr))
      |> Apparatus.registerRecoveredEntries hdl app
    match SCFG.Init (hdl, app) with
    | Ok scfg -> scfg, app
    | Error _ -> scfg, app

  let rec recoverGaps (branchRecovery: IAnalysis) hdl (scfg: SCFG) app gaps =
    match shiftGaps (shiftUntilValid hdl scfg) gaps with
    | [] -> scfg, app
    | gaps ->
      let entries = gaps |> List.map (fun gap -> LeaderInfo.Init (hdl, gap.Min))
      let partialApp =
        Apparatus.initWithoutDefaultEntry hdl (Set.ofList entries)
      match SCFG.Init (hdl, partialApp, false) with
      | Ok partialCFG ->
        let scfg, app =
          branchRecovery.Run hdl partialCFG partialApp
          |> updateResults hdl scfg app
        gaps
        |> Seq.map (fun gap -> findGaps app gap.Min gap.Max)
        |> List.concat
        |> recoverGaps branchRecovery hdl scfg app
        // FIXME: check the remaining gaps and recurse if necessary
      | _ -> recoverGaps branchRecovery hdl scfg app (shiftGaps shiftByOne gaps)

  let run branchRecovery hdl (scfg: SCFG) app =
    hdl.FileInfo.GetTextSections ()
    |> Seq.map (fun sec ->
      let sAddr, eAddr = sec.Address, sec.Address + sec.Size
      findGaps app sAddr eAddr)
    |> List.concat
    |> recoverGaps branchRecovery hdl scfg app

type SpeculativeGapCompletion (enableNoReturn) =
  let branchRecovery = BranchRecovery (enableNoReturn) :> IAnalysis

  interface IAnalysis with
    member __.Name = "Speculative Gap Completion"

    member __.Run hdl scfg app =
      SpeculativeGapCompletionHelper.run branchRecovery hdl scfg app
