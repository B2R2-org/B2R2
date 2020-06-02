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
    |> Seq.fold (fun (gaps, prevAddr, prevInstAddr) addr ->
      let nextAddr = addr + uint64 app.InstrMap.[addr].Instruction.Length
      if prevAddr >= addr then gaps, nextAddr, addr
      elif prevInstAddr = sAddr then
        AddrRange (prevAddr, addr) :: gaps, nextAddr, addr
      else
        let prevInstr = app.InstrMap.[prevInstAddr].Instruction
        if prevInstr.IsIndirectBranch () && not <| prevInstr.IsRET () then
          gaps, nextAddr, addr
        else AddrRange (prevAddr, addr) :: gaps, nextAddr, addr
      ) ([], sAddr, sAddr)
    |> fun (gaps, nextAddr, _) ->
      if nextAddr >= eAddr then gaps
      else AddrRange (nextAddr, eAddr) :: gaps

  let filterBBLs (irCFG: ControlFlowGraph<IRBasicBlock, _>) (gap: AddrRange) =
    irCFG.FoldVertex (fun (inner, outer, overwrap) v ->
      if v.VData.IsFakeBlock () then inner, outer, overwrap
      else
        let range = v.VData.Range
        if gap.Min <= range.Min && range.Max <= gap.Max then
          v :: inner, outer, overwrap
        elif range.Min <= gap.Max && gap.Max < range.Max then
          inner, outer, v :: overwrap
        else inner, v :: outer, overwrap) ([], [], [])

  let checkJumpsToExistingBBL (scfg: SCFG) inner (v: Vertex<IRBasicBlock>) =
    List.forall (fun succ ->
      if List.contains succ inner then true
      else
        scfg.FindVertex (v.VData.PPoint.Address) |> Option.isSome) v.Succs

  let refineGap (irCFG: ControlFlowGraph<IRBasicBlock, _>) (gap: AddrRange) =
    let boundary =
      irCFG.GetVertices ()
      |> Set.fold (fun acc v ->
        if v.VData.IsFakeBlock () then acc
        else v.VData.Range.Max :: acc) []
      |> List.max
    if boundary >= gap.Max then None
    else AddrRange (boundary, gap.Max) |> Some

  let rec tryResolveGaps hdl scfg entries (gap: AddrRange) =
    let app' =
      Set.singleton <| LeaderInfo.Init (hdl, gap.Min)
      |> Apparatus.initWithoutDefaultEntry hdl
    let scfg' = SCFG.Init (hdl, app')
    match scfg' with
    | Error _ ->
      if gap.Min + 1UL = gap.Max then entries
      else
        tryResolveGaps hdl scfg entries <| AddrRange (gap.Min + 1UL, gap.Max)
    | Ok scfg' ->
      let irCFG, _ = scfg'.GetFunctionCFG (gap.Min, false)
      let inner, outer, overwrap = filterBBLs irCFG gap
      if not <| List.isEmpty overwrap then entries
      elif not <| List.isEmpty outer then
        if List.forall (checkJumpsToExistingBBL scfg inner) inner then
          gap.Min :: entries
        else entries
      else
        match refineGap irCFG gap with
        | None -> gap.Min :: entries
        | Some gap' -> tryResolveGaps hdl scfg (gap.Min :: entries) gap'

  let rec run (branchRecovery: IAnalysis) hdl scfg app =
    let newEntries =
      hdl.FileInfo.GetTextSections ()
      |> Seq.map (fun sec ->
        let sAddr, eAddr = sec.Address, sec.Address + sec.Size
        findGaps app sAddr eAddr)
      |> Seq.fold (fun entries (rs: AddrRange list) ->
        rs |> List.fold (tryResolveGaps hdl scfg) entries) []
      |> List.map (fun a -> LeaderInfo.Init (hdl, a))
    if List.isEmpty newEntries then branchRecovery.Run hdl scfg app
    else
      let app =
        newEntries
        |> Set.ofList
        |> Apparatus.registerRecoveredLeaders app
      let app = Apparatus.update hdl app newEntries
      match SCFG.Init (hdl, app) with
      | Ok scfg -> run branchRecovery hdl scfg app
      | Error e -> failwithf "Failed to run speculative gap completion due to %A" e

type SpeculativeGapCompletion (enableNoReturn) =
  let branchRecovery = BranchRecovery (enableNoReturn) :> IAnalysis

  interface IAnalysis with
    member __.Name = "Speculative Gap Completion"

    member __.Run hdl scfg app =
      SpeculativeGapCompletionHelper.run branchRecovery hdl scfg app
