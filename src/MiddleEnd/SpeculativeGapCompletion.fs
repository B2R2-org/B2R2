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
    let entry = LeaderInfo.Init (hdl, gap.Min) |> Set.singleton
    let app' = Apparatus.initByEntries hdl entry (Some gap.Max)
    match SCFG.Init (hdl, app', IRCFG.initImperative, false) with
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

  let updateResults branchRecovery hdl scfg app (_, resultApp) =
    let app =
      Apparatus.getFunctionAddrs resultApp
      |> Set.ofSeq
      |> Set.map (fun addr -> LeaderInfo.Init (hdl, addr))
      |> Apparatus.addRecoveredEntries app
    let app =
      resultApp.IndirectBranchMap
      |> Apparatus.addIndirectBranchMap app
      |> (branchRecovery: BranchRecovery).CalculateTable hdl
      |> Apparatus.update hdl
    match SCFG.Init (hdl, app, IRCFG.initImperative) with
    | Ok scfg -> scfg, app
    | Error _ -> scfg, app

  let rec recoverGaps branchRecovery hdl (scfg: SCFG) app gaps =
    match shiftGaps (shiftUntilValid hdl scfg) gaps with
    | [] -> scfg, app
    | gaps ->
      let ents =
        gaps |> List.map (fun g -> LeaderInfo.Init (hdl, g.Min)) |> Set.ofList
      let partialApp = Apparatus.initByEntries hdl ents None
      match SCFG.Init (hdl, partialApp, IRCFG.initImperative, false) with
      | Ok partialCFG ->
        let isTarget addr =
          app.IndirectBranchMap
          |> Map.exists (fun _ { HostFunctionAddr = entry } -> entry = addr)
          |> not
        let scfg, app =
          isTarget
          |> (branchRecovery: BranchRecovery).RunWith hdl partialCFG partialApp
          |> updateResults branchRecovery hdl scfg app
        gaps
        |> List.map (fun gap -> findGaps app gap.Min gap.Max)
        |> List.concat
        |> recoverGaps branchRecovery hdl scfg app
      | _ ->
        recoverGaps branchRecovery hdl scfg app (shiftGaps shiftByOne gaps)

  let run branchRecovery hdl (scfg: SCFG) app =
    hdl.FileInfo.GetTextSections ()
    |> Seq.map (fun sec ->
      let sAddr, eAddr = sec.Address, sec.Address + sec.Size
      findGaps app sAddr eAddr)
    |> List.concat
    |> recoverGaps branchRecovery hdl scfg app

type SpeculativeGapCompletion (enableNoReturn) =
  let branchRecovery = BranchRecovery (enableNoReturn)

  interface IAnalysis with
    member __.Name = "Speculative Gap Completion"

    member __.Run hdl scfg app =
      SpeculativeGapCompletionHelper.run branchRecovery hdl scfg app
