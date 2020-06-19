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

type IndirectBranchPattern =
  | GOTIndexed of insAddr: Addr * baseAddr: Addr * indexAddr: Addr * rt: RegType
  | FixedTab of insAddr: Addr * indexAddr: Addr * rt: RegType
  | ConstAddr of insAddr: Addr * targetAddr: Addr
  | UnknownFormat

type BranchInfo =
  | ConstJmp of entry: Addr * insAddr: Addr * target: Addr
  | JmpTable of entry: Addr
              * insAddr: Addr
              * targets: Set<Addr>
              * table:AddrRange
              * rt:RegType

module private BranchRecoveryHelper =
  let filterOutLinkageTables hdl calleeAddrs =
    let tabAddrs =
      hdl.FileInfo.GetLinkageTableEntries ()
      |> Seq.map (fun ent -> ent.TrampolineAddress)
      |> Set.ofSeq
    calleeAddrs
    |> List.filter (fun addr -> not <| Set.contains addr tabAddrs)

  let rec computeFunctionBoundary acc = function
    | [] -> acc
    | [ addr ] -> Map.add addr (addr, 0UL) acc
    | addr :: next :: addrs ->
      let acc = Map.add addr (addr, next) acc
      computeFunctionBoundary acc (next :: addrs)

  let computeCalleeAddrs hdl app =
    app.CalleeMap.Callees
    |> Seq.choose (fun callee -> callee.Addr)
    |> Seq.toList
    |> filterOutLinkageTables hdl
    |> List.sort

  let hasIndirectBranch (cfg: ControlFlowGraph<IRBasicBlock, _>) =
    cfg.FoldVertex (fun acc v ->
      (not <| v.VData.IsFakeBlock () && v.VData.HasIndirectBranch)
      || acc) false

  let extractIndirectBranches (cfg: ControlFlowGraph<SSABBlock, _>) =
    cfg.FoldVertex (fun acc v ->
      let len = v.VData.InsInfos.Length
      if not <| v.VData.IsFakeBlock ()
        && v.VData.HasIndirectBranch
        && len > 0
      then
        let lastIns = v.VData.InsInfos.[len - 1].Instruction
        let lastAddr = lastIns.Address
        let isCall = lastIns.IsCall ()
        (lastAddr, v.VData.GetLastStmt (), isCall) :: acc
      else acc) []

  let rec simplifyBinOp = function
    | BinOp (BinOpType.ADD, _, Num v1, Num v2) -> Num (BitVector.add v1 v2)
    | BinOp (BinOpType.SUB, _, Num v1, Num v2) -> Num (BitVector.sub v1 v2)
    | BinOp (BinOpType.MUL, _, Num v1, Num v2) -> Num (BitVector.mul v1 v2)
    | BinOp (BinOpType.ADD, rt, Num v1, BinOp (BinOpType.ADD, _, Num v2, e))
    | BinOp (BinOpType.ADD, rt, Num v1, BinOp (BinOpType.ADD, _, e, Num v2))
    | BinOp (BinOpType.ADD, rt, BinOp (BinOpType.ADD, _, Num v2, e), Num v1)
    | BinOp (BinOpType.ADD, rt, BinOp (BinOpType.ADD, _, e, Num v2), Num v1) ->
      simplifyBinOp (BinOp (BinOpType.ADD, rt, Num (BitVector.add v1 v2), e))
    | e -> e

  let simplifyExtract = function
    | Extract (Cast (CastKind.ZeroExt, _, e'), rt, 0) as e ->
      if AST.typeOf e' = rt then e' else e
    | e -> e

  let rec extractExp cpstate expr =
    match expr with
    | Num _ -> expr
    | Var v ->
      match CPState.findReg cpstate v with
      | Const bv -> Num bv
      | PCThunk bv -> Num bv
      | GOT bv -> Num bv
      | _ ->
        match Map.tryFind v cpstate.SSAEdges.Defs with
        | Some (Def (_, e)) -> extractExp cpstate e
        | _ -> expr
    | Load (mem, rt, addr) ->
      match extractExp cpstate addr with
      | Num bv ->
        let addr = BitVector.toUInt64 bv
        match CPState.findMem cpstate mem rt addr with
        | Const bv -> Num bv
        | PCThunk bv -> Num bv
        | GOT bv -> Num bv
        | _ -> Load (mem, rt, Num bv)
      | expr -> Load (mem, rt, expr)
    | UnOp (op, rt, e) ->
      let e = extractExp cpstate e
      UnOp (op, rt, e)
    | BinOp (op, rt, e1, e2) ->
      let e1 = extractExp cpstate e1
      let e2 = extractExp cpstate e2
      simplifyBinOp (BinOp (op, rt, e1, e2))
    | RelOp (op, rt, e1, e2) ->
      let e1 = extractExp cpstate e1
      let e2 = extractExp cpstate e2
      RelOp (op, rt, e1, e2)
    | Ite (e1, rt, e2, e3) ->
      let e1 = extractExp cpstate e1
      let e2 = extractExp cpstate e2
      let e3 = extractExp cpstate e3
      Ite (e1, rt, e2, e3)
    | Cast (op, rt, e) ->
      let e = extractExp cpstate e
      Cast (op, rt, e)
    | Extract (e, rt, pos) ->
      let e = extractExp cpstate e
      simplifyExtract (Extract (e, rt, pos))
    | _ -> expr

  let computeIndexAddr = function
    | BinOp (BinOpType.ADD, _, Num idx, _)
    | BinOp (BinOpType.ADD, _, _, Num idx)
    | Num idx -> Some (BitVector.toUInt64 idx)
    | _ -> None

  let computeCallInfo insAddr = function
    | Num addr -> ConstAddr (insAddr, BitVector.toUInt64 addr)
    | _ -> UnknownFormat

  let computeJmpInfo insAddr = function
    | BinOp (BinOpType.ADD, _, Load (_, t, idxExpr), Num tbase)
    | BinOp (BinOpType.ADD, _, Num tbase, Load (_, t, idxExpr))
    | BinOp (BinOpType.ADD, _, Cast (_, _, Load (_, t, idxExpr)), Num tbase)
    | BinOp (BinOpType.ADD, _, Num tbase, Cast (_, _, Load (_, t, idxExpr))) ->
      match computeIndexAddr idxExpr with
      | Some tindex -> GOTIndexed (insAddr, BitVector.toUInt64 tbase, tindex, t)
      | None -> UnknownFormat
    | Load (_, t, (BinOp (BinOpType.ADD, _, Num i, _)))
    | Load (_, t, (BinOp (BinOpType.ADD, _, _, Num i))) ->
      FixedTab (insAddr, BitVector.toUInt64 i, t)
    | Num addr -> ConstAddr (insAddr, BitVector.toUInt64 addr)
    | _ -> UnknownFormat

  let computeIndBranchInfo cpstate insAddr isCall exp =
    let exp = extractExp cpstate exp
    // printfn "%x: %s" insAddr (Pp.expToString exp)
    if isCall then computeCallInfo insAddr exp
    else computeJmpInfo insAddr exp

  let partitionIndBranchInfo entry constBranches jmpTblInfo lst =
    lst
    |> List.fold (fun (constBranches, jmpTblInfo) info ->
      match info with
      | ConstAddr (i, t) ->
        if t <> 0UL then ConstJmp (entry, i, t) :: constBranches, jmpTblInfo
        else constBranches, jmpTblInfo
      | GOTIndexed (instr, bAddr, iAddr, rt) ->
        constBranches, (entry, instr, bAddr, iAddr, rt) :: jmpTblInfo
      | FixedTab (instr, iAddr, rt) ->
        constBranches, (entry, instr, 0UL, iAddr, rt) :: jmpTblInfo
      | _ -> constBranches, jmpTblInfo
    ) (constBranches, jmpTblInfo)

  /// Read jump targets from a jump table.
  let rec readTargets hdl fStart fEnd baseAddr maxAddr startAddr rt targets =
    match maxAddr with
    | Some maxAddr when startAddr >= maxAddr -> targets, startAddr
    | _ ->
      if hdl.FileInfo.IsValidAddr startAddr then
        let size = RegType.toByteWidth rt
        match BinHandler.TryReadInt (hdl, startAddr, size) with
        | None -> targets, startAddr
        | Some offset ->
          let target = baseAddr + uint64 offset
          if target >= fStart && target <= fEnd then
            let nextAddr = startAddr + uint64 size
            let targets = Set.add target targets
            readTargets hdl fStart fEnd baseAddr maxAddr nextAddr rt targets
          else targets, startAddr
      else targets, startAddr

  let getMaxAddr tableAddrs startAddr maxAddr =
    tableAddrs
    |> Set.partition (fun addr -> addr <= startAddr)
    |> snd
    |> fun s ->
      match Set.isEmpty s, maxAddr with
      | true, None -> None
      | false, None -> Set.minElement s |> Some
      | true, Some _ -> maxAddr
      | false, Some fromAnalysis ->
        let fromApp = Set.minElement s
        min fromAnalysis fromApp |> Some

  let computeTableAddrs recoveredInfo =
    recoveredInfo.IndirectBranchMap
    |> Map.fold (fun acc _ (_, info) ->
      match info with
      | None -> acc
      | Some (range, _) -> Set.add range.Min acc
      ) Set.empty

  let inline accJmpTableInfo acc targets lb iAddr sAddr eAddr t =
    if Set.isEmpty targets then acc
    else JmpTable (lb, iAddr, targets, AddrRange (sAddr, eAddr), t) :: acc

  let checkDefinedTable recoveredInfo iAddr sAddr =
    recoveredInfo.IndirectBranchMap
    |> Map.exists (fun addr (_, info) ->
      match info with
      | None -> false
      | Some (range, _) -> sAddr = range.Min && iAddr <> addr)

  let inferGOTIndexedBranchTargets hdl rInfo boundaries jmpTblInfo infos =
    let tableAddrs = computeTableAddrs rInfo
    let rec infer acc = function
      | [] -> acc
      | [ (entry, iAddr, bAddr, sAddr, t) ] ->
        if checkDefinedTable rInfo iAddr sAddr then acc
        else
          let lb, ub = Map.find entry boundaries (* function boundaries *)
          let max = getMaxAddr tableAddrs sAddr None
          let targets, eAddr = readTargets hdl lb ub bAddr max sAddr t Set.empty
          accJmpTableInfo acc targets lb iAddr sAddr eAddr t
      | (entry, iAddr, bAddr, s1, t) :: (((_, _, _, s2, _) :: _) as next) ->
        if checkDefinedTable rInfo iAddr s1 then infer acc next
        else
          let lb, ub = Map.find entry boundaries
          let max = getMaxAddr tableAddrs s1 (Some s2)
          let targets, eAddr = readTargets hdl lb ub bAddr max s1 t Set.empty
          infer (accJmpTableInfo acc targets lb iAddr s1 eAddr t) next
    jmpTblInfo
    |> List.sortBy (fun (_, _, _, i, _) -> i)
    |> infer infos

  let analyzeIndirectBranch ssaCFG cpstate entry constBranches jmpTblInfo =
    extractIndirectBranches ssaCFG
    |> List.map (fun (insAddr, stmt, isCall) ->
      match stmt with
      | Jmp (InterJmp exp) -> computeIndBranchInfo cpstate insAddr isCall exp
      | _ -> UnknownFormat)
    |> partitionIndBranchInfo entry constBranches jmpTblInfo

  let analyzeBranches hdl app (scfg: SCFG) (constBranches, jmpTblInfo) addr =
    let irCFG, irRoot = scfg.GetFunctionCFG (addr, false)
    if hasIndirectBranch irCFG then
      let lens = SSALens.Init hdl scfg
      let ssaCFG, ssaRoot = lens.Filter irCFG [irRoot] app
      let cp = ConstantPropagation (hdl, ssaCFG)
      let cpstate = cp.Compute (List.head ssaRoot)
      analyzeIndirectBranch ssaCFG cpstate addr constBranches jmpTblInfo
    else constBranches, jmpTblInfo

  let updateIndirectBranchMap indmap = function
    | ConstJmp (_, iAddr, target) ->
      Map.add iAddr (Set.singleton target, None) indmap
    | JmpTable (_, iAddr, targets, table, rt) ->
      Map.add iAddr (targets, Some (table, rt)) indmap

  let rec recover (noReturn: IAnalysis) hdl scfg app =
    let scfg, app = noReturn.Run hdl scfg app
    let callees = computeCalleeAddrs hdl app
    let boundaries = computeFunctionBoundary Map.empty callees
    let rInfo = app.RecoveredInfo
    let indmap = rInfo.IndirectBranchMap
    let branchInfo, jmpTblInfo =
      callees |> List.fold (analyzeBranches hdl app scfg) ([], [])
    let indmap' =
      inferGOTIndexedBranchTargets hdl rInfo boundaries jmpTblInfo branchInfo
      |> List.fold updateIndirectBranchMap indmap
    if indmap <> indmap' then
      let app = Apparatus.addIndirectBranchMap hdl app indmap'
      match SCFG.Init (hdl, app) with
      | Ok scfg ->
#if DEBUG
        printfn "[*] Go to the next phase ..."
#endif
        recover noReturn hdl scfg app
      | Error e -> failwithf "Failed to recover switch due to %A" e
    else scfg, app

type BranchRecovery (enableNoReturn) =
  let noReturn =
    if enableNoReturn then NoReturnAnalysis () :> IAnalysis
    else NoAnalysis () :> IAnalysis

  interface IAnalysis with
    member __.Name = "Indirect Branch Recovery"

    member __.Run hdl scfg app =
      BranchRecoveryHelper.recover noReturn hdl scfg app
