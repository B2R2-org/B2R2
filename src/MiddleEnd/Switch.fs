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
open B2R2.DataFlow
open System.Collections.Generic

type SwitchTableInfo =
  {
    Entry      : Addr
    BBLLoc     : ProgramPoint
    JumpBase   : Addr
    TableRange : Addr * Addr
  }

module private SwitchHelper =

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

  let rec computeFunctionBoundary acc = function
    | [] -> acc
    | [ addr ] -> Map.add addr (addr, 0UL) acc
    | addr :: next :: addrs ->
      let acc = Map.add addr (addr, next) acc
      computeFunctionBoundary acc (next :: addrs)

  let getFunctionBoundary hdl app =
    app.CalleeMap.Callees
    |> filterOutLinkageTables hdl
    |> Seq.choose (fun callee -> callee.Addr)
    |> Seq.toList
    |> List.sort
    |> computeFunctionBoundary Map.empty

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

  /// Symbolically execute expression with ignoring memories
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

  /// Symbolically execute Def statement only
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
        let addr1, _ = CPTransfer.evalExpr hdl bbl out addr1
        let addr2, _ = CPTransfer.evalExpr hdl bbl out addr2
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

  /// Find switch tables and update app accordingly.
  let findBase hdl cfg entry (outs: Dictionary<_, _>) switchMap bbl =
    let ppoint = (bbl: Vertex<SSABBlock>).VData.PPoint
    if outs.ContainsKey <| bbl.GetID () then
      let out = outs.[bbl.GetID ()]
      let symbSt =
        bbl.VData.Stmts
        |> Array.fold execStmt Map.empty
      extractJumpAddrExprs bbl
      |> List.fold (fun switchMap e ->
        match findJumpTableAddr hdl bbl out symbSt e with
        | Some (tableBase, Load (_, _, idxAddr)) ->
          let baseAddr, _ = CPTransfer.evalExpr hdl bbl out tableBase
          let startAddr = computeAddr out idxAddr
          match baseAddr, startAddr with
          | Const baseAddr, Some startAddr ->
            let baseAddr = BitVector.toUInt64 baseAddr
            let startAddr = BitVector.toUInt64 startAddr
            let info =
              {
                Entry = entry ;
                BBLLoc = ppoint ;
                JumpBase = baseAddr ;
                TableRange = (startAddr, startAddr)
              }
            Map.add startAddr info switchMap
            // updateApp hdl app ppoint.Address baseAddr size
          | _ -> switchMap
        | _ -> switchMap) switchMap
    else switchMap

  let analyzeBase hdl (scfg: SCFG) app switchMap callee =
    match callee.Addr with
    | Some addr ->
      let irCFG, irRoot = scfg.GetFunctionCFG (addr, false)
      let lens = SSALens.Init hdl scfg
      let ssaCFG, ssaRoots = lens.Filter irCFG [irRoot] app
      match collectVerticesWithIndJump ssaCFG with
      | [] -> switchMap
      | bbls ->
        let cp = ConstantPropagation (hdl, ssaCFG)
        let root =
          ssaCFG.FindVertexBy (fun v -> v.VData.PPoint = irRoot.VData.PPoint)
        let _, outs = cp.Compute root
        let entry = root.VData.PPoint.Address
        bbls
        |> List.fold (findBase hdl ssaCFG entry outs) switchMap
    | None -> switchMap

  let findSwitchTableBase hdl scfg app switchMap =
    app.CalleeMap.Callees
    |> filterOutLinkageTables hdl
    |> Seq.fold (analyzeBase hdl scfg app) switchMap

  let inline switchTableHeuristic funcBdry info nextBase addr offset =
    let inline checkAddr offset =
      let target = info.JumpBase + uint64 offset
      match Map.find info.Entry funcBdry with
      | (sAddr, 0UL) -> sAddr <= target
      | (sAddr, eAddr) -> sAddr <= target && target < eAddr
    match nextBase with
    | Some next ->
      if addr = next then false
      else checkAddr offset
    | None -> checkAddr offset

  let rec inferUpperBound hdl funcBdry info nextBase addr =
    let wdSize = WordSize.toByteWidth hdl.ISA.WordSize |> uint64
    let offset = BinHandler.ReadInt (hdl, addr, int wdSize)
    if offset >= 0L then addr
    elif not (switchTableHeuristic funcBdry info nextBase addr offset) then addr
    else inferUpperBound hdl funcBdry info nextBase (addr + wdSize)

  let rec computeTableBoundary hdl funcBdry switchMap = function
    | [] -> switchMap
    | [ lb ] ->
      let info = Map.find lb switchMap
      let ub = inferUpperBound hdl funcBdry info None lb
      let info = { info with TableRange = (lb, ub) }
      Map.add lb info switchMap
    | lb :: next :: addrs ->
      let info = Map.find lb switchMap
      let ub = inferUpperBound hdl funcBdry info (Some next) lb
      let info = { info with TableRange = (lb, ub) }
      let switchMap = Map.add lb info switchMap
      computeTableBoundary hdl funcBdry switchMap (next :: addrs)

  let updateApp hdl (app: Apparatus) info =
    let wdSize = WordSize.toByteWidth hdl.ISA.WordSize |> uint64
    let lb, ub = info.TableRange
    [ lb .. wdSize .. ub - wdSize ]
    |> List.fold (fun app addr ->
      let offset = BinHandler.ReadUInt (hdl, addr, int wdSize)
      let target =
        if wdSize = 4UL then (info.JumpBase + offset) % 0x100000000UL
        else info.JumpBase + offset
      Apparatus.addIndirectBranchTarget app info.BBLLoc.Address target) app

  let refineTables hdl funcBdry app switchMap =
    let switchMap =
      switchMap
      |> Map.fold (fun acc baseAddr _ -> baseAddr :: acc) []
      |> List.sort
      |> computeTableBoundary hdl funcBdry switchMap
    let app = Map.fold (fun app _ info -> updateApp hdl app info) app switchMap
    Map.iter (fun _ info ->
      let lb, rb = info.TableRange
      printfn "%A => %A" info.BBLLoc (rb / 4UL - lb / 4UL)) switchMap
    app, switchMap

  let extractIndirectTargets app =
    app.IndirectBranchMap
    |> Map.fold (fun acc _ addrs -> Set.union acc addrs) Set.empty

  let rec recoverSwitchTables hdl scfg app funcBdry oldSwitchMap =
    let app, newSwitchMap =
      findSwitchTableBase hdl scfg app Map.empty
      |> refineTables hdl funcBdry app
    if oldSwitchMap = newSwitchMap then scfg, app
    else
      let targets = extractIndirectTargets app
      let app =
        Set.toSeq targets
        |> Seq.map (fun addr -> LeaderInfo.Init (hdl, addr))
        |> Apparatus.update hdl app Seq.empty
      let scfg = SCFG (hdl, app)
      recoverSwitchTables hdl scfg app funcBdry newSwitchMap

type SwitchRecovery () =
  interface IPostAnalysis with
    member __.Run hdl scfg app =
      let funcBdry = SwitchHelper.getFunctionBoundary hdl app
      SwitchHelper.recoverSwitchTables hdl scfg app funcBdry Map.empty
