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
open B2R2.BinFile
open B2R2.FrontEnd
open B2R2.BinIR
open B2R2.BinIR.SSA
open B2R2.BinGraph
open B2R2.BinCorpus
open B2R2.DataFlow.ConstantPropagation
open System.Collections.Generic

module private SwitchHelper =
  let collectVerticesWithIndJump (cfg: ControlFlowGraph<SSABBlock, _>) =
    []
    |> cfg.FoldVertex (fun acc v ->
      if not <| v.VData.IsFakeBlock () && v.VData.HasIndirectBranch then
        let insInfos = v.VData.InsInfos
        if Array.isEmpty insInfos then acc
        else
          let instr = insInfos.[Array.length insInfos - 1].Instruction
          if not <| instr.IsCall () then v :: acc else acc
      else acc)

  let rec execExpr st = function
    | Num _ as e -> e
    | Var v as e ->
      match Map.tryFind v st with
      | Some e -> e
      | None -> e
    | Load _ as e -> e
    | UnOp (op, rt, e) ->
      let e = execExpr st e
      UnOp (op, rt, e)
    | BinOp (op, rt, e1, e2) ->
      let e1 = execExpr st e1
      let e2 = execExpr st e2
      BinOp (op, rt, e1, e2)
    | RelOp (op, rt, e1, e2) ->
      let e1 = execExpr st e1
      let e2 = execExpr st e2
      RelOp (op, rt, e1, e2)
    | Ite (e1, rt, e2, e3) ->
      let e1 = execExpr st e1
      let e2 = execExpr st e2
      let e3 = execExpr st e3
      Ite (e1, rt, e2, e3)
    | Cast (op, rt, e) ->
      let e = execExpr st e
      Cast (op, rt, e)
    | Extract (e, rt, pos) ->
      let e = execExpr st e
      Extract (e, rt, pos)
    | Undefined _ as e -> e
    | e -> e

  let execStmt st = function
    | Def (v, e) ->
      let e = execExpr st e
      Map.add v e st
    | _ -> st

  let extractJumpAddrExprs (v: Vertex<SSABBlock>) =
    match v.VData.GetLastStmt () with
    | Jmp (InterJmp (e)) -> [ e ]
    | Jmp (InterCJmp (_, e1, e2)) -> [ e1; e2 ]
    | _ -> []

  let findJumpTableAddr hdl bbl out st = function
    | Var v ->
      match Map.find v st with
      | BinOp (BinOpType.ADD, _, (Load _ as tableIdx),
                                  (Var _ as tableBase)) ->
        Some (tableBase, tableIdx)
      | BinOp (BinOpType.ADD, _, (Var _ as tableBase),
                                  (Load _ as tableIdx)) ->
        Some (tableBase, tableIdx)
      | BinOp (BinOpType.ADD, _, (Load (_, _, addr1) as e1),
                                (Load (_, _, addr2) as e2)) ->
        let addr1, _ = Transfer.evalExpr hdl bbl out addr1
        let addr2, _ = Transfer.evalExpr hdl bbl out addr2
        match addr1, addr2 with
        | Const _, NotAConst -> Some (e1, e2)
        | NotAConst, Const _ -> Some (e2, e1)
        | _ -> None
      | _ -> None
    | _ -> None

  let getTypeOfVar v =
    match v.Kind with
    | RegVar (rt, _, _)
    | TempVar (rt, _) -> rt
    | _ -> Utils.impossible ()

  let rec computeAddr out = function
    | Num bv -> Some bv
    | Var v ->
      match CPState.loadReg v out with
      | Const bv -> Some bv
      | _ -> Some (BitVector.zero <| getTypeOfVar v)
    | BinOp (BinOpType.ADD, _, e1, e2) ->
      let bv1 = computeAddr out e1
      let bv2 = computeAddr out e2
      match bv1, bv2 with
      | Some bv1, Some bv2 -> Some (bv1 + bv2)
      | _ -> None
    | BinOp (BinOpType.MUL, _, e1, e2) ->
      let bv1 = computeAddr out e1
      let bv2 = computeAddr out e2
      match bv1, bv2 with
      | Some bv1, Some bv2 -> Some (bv1 * bv2)
      | _ -> None
    | _ -> None

  let inferTableSize hdl funcSizes entry baseAddr startAddr =
    let wdSize = WordSize.toByteWidth hdl.ISA.WordSize
    let wdSize64 = uint64 wdSize
    let withinFunc addr =
      entry <= addr && addr < entry + Map.find entry funcSizes
    let rec inferSize cnt =
      let offset =
        BinHandler.ReadInt (hdl, startAddr + wdSize64 * uint64 cnt, wdSize)
      let target = baseAddr + uint64 offset
      if offset >= 0L then cnt
      elif not <| withinFunc target then cnt
      else inferSize (cnt + 1)
    inferSize 0

  let updateApp hdl (app: Apparatus) fromAddr baseAddr size =
    let wdSize = WordSize.toByteWidth hdl.ISA.WordSize
    let wdSize64 = wdSize |> uint64
    [ 0 .. size - 1 ]
    |> List.fold (fun app idx ->
      let offset =
        BinHandler.ReadInt (hdl, baseAddr + wdSize64 * uint64 idx, wdSize)
        |> uint64
      let toAddr = baseAddr + offset
      Apparatus.addIndirectBranchTarget app fromAddr toAddr) app

  /// Find switch tables and update app accordingly.
  let findSwitchTable hdl cfg funcSizes entry (outs: Dictionary<_, _>) app bbl =
    let ppoint = (bbl: Vertex<SSABBlock>).VData.PPoint
    if outs.ContainsKey <| bbl.GetID () then
      let out = outs.[bbl.GetID ()]
      let st =
        bbl.VData.Stmts
        |> Array.fold execStmt Map.empty
      extractJumpAddrExprs bbl
      |> List.fold (fun app e ->
        match findJumpTableAddr hdl bbl out st e with
        | Some (tableBase, Load (_, _, idxAddr)) ->
          let baseAddr, _ = Transfer.evalExpr hdl bbl out tableBase
          let startAddr = computeAddr out idxAddr
          match baseAddr, startAddr with
          | Const baseAddr, Some startAddr ->
            let baseAddr = BitVector.toUInt64 baseAddr
            let startAddr = BitVector.toUInt64 startAddr
            printfn "%A %A" ppoint <| inferTableSize hdl funcSizes entry baseAddr startAddr
            // updateApp hdl app ppoint.Address baseAddr size
            app
          | _ -> app
        | _ -> app) app
    else app

  let analyze hdl (scfg: SCFG) funcSizes app callee =
    match callee.Addr with
    | Some addr ->
      let irCFG, irRoot = scfg.GetFunctionCFG (addr, false)
      let lens = SSALens.Init hdl scfg
      let ssaCFG, ssaRoots = lens.Filter irCFG [irRoot] app
      match collectVerticesWithIndJump ssaCFG with
      | [] -> app
      | bbls ->
        let cp = ConstantPropagation (hdl, ssaCFG)
        let root =
          ssaCFG.FindVertexBy (fun v -> v.VData.PPoint = irRoot.VData.PPoint)
        let _, outs = cp.Compute root
        let entry = root.VData.PPoint.Address
        List.fold (findSwitchTable hdl ssaCFG funcSizes entry outs) app bbls
    | None -> app

  let extractIndirectTargets app =
    app.IndirectBranchMap
    |> Map.fold (fun acc _ addrs -> Set.union acc addrs) Set.empty

  let filterOutLinkageTables hdl callees =
    let tabAddrs =
      hdl.FileInfo.GetLinkageTableEntries ()
      |> Seq.map (fun ent -> ent.TrampolineAddress)
      |> Set.ofSeq
    callees
    |> Seq.filter (fun callee ->
      match callee.Addr with
      | Some addr -> not <| Set.contains addr tabAddrs
      | None -> false)

  let rec getFuncSize acc = function
    | [] -> acc
    | [ x ] -> Map.add x 0UL acc
    | addr :: next :: addrs ->
      let acc = Map.add addr (next - addr) acc
      getFuncSize acc (next :: addrs)

  let recoverSwitchTables hdl scfg app =
    let prevTargets = extractIndirectTargets app
    let funcSizes =
      app.CalleeMap.Callees
      |> filterOutLinkageTables hdl
      |> Seq.choose (fun callee -> callee.Addr)
      |> Seq.toList
      |> List.sort
      |> getFuncSize Map.empty
    app.CalleeMap.Callees
    |> filterOutLinkageTables hdl
    |> Seq.fold (analyze hdl scfg funcSizes) app
    |> fun app' ->
      let newTargets = extractIndirectTargets app'
      if prevTargets <> newTargets then
        Set.toSeq newTargets
        |> Seq.map (fun addr -> LeaderInfo.Init (hdl, addr))
        |> Apparatus.update hdl app' Seq.empty
      else app'

type SwitchRecovery () =
  interface IPostAnalysis with
    member __.Run hdl scfg app =
      scfg, SwitchHelper.recoverSwitchTables hdl scfg app
