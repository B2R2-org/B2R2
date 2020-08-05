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
open B2R2.Lens
open B2R2.DataFlow

type IndirectBranchPattern =
  | GOTIndexed of insAddr: Addr * baseAddr: Addr * indexAddr: Addr * rt: RegType
  | FixedTab of insAddr: Addr * indexAddr: Addr * rt: RegType
  | ConstAddr of insAddr: Addr * targetAddr: Addr
  | UnknownFormat

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

  let computeCalleeAddrs hdl corpus =
    corpus.SCFG.CalleeMap.Callees
    |> Seq.choose (fun callee -> callee.Addr)
    |> Seq.toList
    |> filterOutLinkageTables hdl
    |> List.sort

  let hasIndirectBranch cfg =
    DiGraph.foldVertex cfg (fun acc (v: Vertex<IRBasicBlock>) ->
      (not <| v.VData.IsFakeBlock () && v.VData.HasIndirectBranch)
      || acc) false

  let extractIndirectBranches cfg =
    DiGraph.foldVertex cfg (fun acc (v: Vertex<SSABBlock>) ->
      let len = v.VData.InsInfos.Length
      if not <| v.VData.IsFakeBlock ()
        && v.VData.HasIndirectBranch
        && len > 0
      then
        let lastIns = v.VData.InsInfos.[len - 1].Instruction
        let isCall = lastIns.IsCall ()
        (lastIns.Address, v.VData.GetLastStmt (), isCall) :: acc
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
    //printfn "%x: %s %A" insAddr (Pp.expToString exp) isCall
    if isCall then computeCallInfo insAddr exp
    else computeJmpInfo insAddr exp

  let inline constIndBranchInfo host targets =
    { HostFunctionAddr = host; TargetAddresses = targets; JumpTableInfo = None }

  let inline tblIndBranchInfo host targets bAddr sAddr eAddr rt =
    let range = AddrRange (sAddr, eAddr)
    let tbl = Some <| JumpTableInfo.Init bAddr range rt
    { HostFunctionAddr = host; TargetAddresses = targets; JumpTableInfo = tbl }

  let partitionIndBranchInfo entry constBranches tblBranches needCPMap lst =
    lst
    |> List.fold (fun (constBranches, tblBranches) info ->
      match info with
      | ConstAddr (b, t) ->
        if t <> 0UL then
          let info = constIndBranchInfo entry (Set.singleton t)
          Map.add b info constBranches, tblBranches
        else constBranches, tblBranches
      | GOTIndexed (insAddr, bAddr, iAddr, rt) ->
        let info = tblIndBranchInfo entry Set.empty bAddr iAddr (iAddr + 1UL) rt
        constBranches, Map.add insAddr info tblBranches
      | FixedTab (insAddr, iAddr, rt) ->
        let info = tblIndBranchInfo entry Set.empty 0UL iAddr (iAddr + 1UL) rt
        constBranches, Map.add insAddr info tblBranches
      | _ -> constBranches, tblBranches
    ) (constBranches, tblBranches), needCPMap

  /// Read jump targets from a jump table.
  let rec readTargets hdl corpus fStart fEnd blockAddr baseAddr maxAddr startAddr rt targets =
    match maxAddr with
    | Some maxAddr when startAddr >= maxAddr -> targets, startAddr, corpus
    | _ ->
      if hdl.FileInfo.IsValidAddr startAddr then
        let size = RegType.toByteWidth rt
        match BinHandler.TryReadInt (hdl, startAddr, size) with
        | None -> targets, startAddr, corpus
        | Some offset ->
          let target = baseAddr + uint64 offset
          if target >= fStart && target <= fEnd then
            match BinCorpus.addEdge hdl corpus None blockAddr target IndirectJmpEdge with
            | Ok (corpus', hasNewIndirectJump) ->
              let targets = Set.add target targets
              let nextAddr = startAddr + uint64 size
              if not hasNewIndirectJump then
                readTargets hdl corpus' fStart fEnd blockAddr baseAddr maxAddr nextAddr rt targets
              else targets, nextAddr, corpus'
            | Error _ -> targets, startAddr, corpus
          else targets, startAddr, corpus
      else targets, startAddr, corpus

  let getMaxAddr tableAddrs corpus insAddr startAddr maxAddr =
    let scfg = corpus.SCFG
    match Map.tryFind insAddr scfg.IndirectBranchMap with
    | Some ({ JumpTableInfo = Some info }) ->
      tableAddrs |> Set.remove info.JTRange.Min
    | _ -> tableAddrs
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

  let getBlockAddr corpus insAddr =
    let v = corpus.SCFG.FindVertex insAddr |> Option.get
    v.VData.PPoint.Address

  let computeTableAddrs corpus =
    corpus.SCFG.IndirectBranchMap
    |> Map.fold (fun acc _ indInfo ->
      match indInfo.JumpTableInfo with
      | None -> acc
      | Some info -> Set.add info.JTRange.Min acc
      ) Set.empty

  let inline accJmpTableInfo acc targets entry insAddr bAddr sAddr eAddr t =
    if Set.isEmpty targets then acc
    else
      let info = tblIndBranchInfo entry targets bAddr sAddr eAddr t
      match Map.tryFind insAddr acc with
      | None -> Map.add insAddr info acc
      | Some info' -> if info = info' then acc else Map.add insAddr info acc

  let checkDefinedTable corpus insAddr sAddr =
    corpus.SCFG.IndirectBranchMap
    |> Map.exists (fun addr indInfo ->
      match indInfo.JumpTableInfo with
      | None -> false
      | Some info -> sAddr = info.JTRange.Min && insAddr <> addr)

  let inferGOTIndexedBranches hdl corpus boundaries oldTableBranches tableBranches constBranches needCPMap =
    let tableAddrs = computeTableAddrs corpus
    let rec infer corpus acc needCPMap = function
      | [ (insAddr, { HostFunctionAddr = entry ; JumpTableInfo = Some i }) ] ->
        let bAddr = i.JTBaseAddr
        let t = i.JTEntrySize
        if checkDefinedTable corpus insAddr i.JTRange.Min then corpus, acc, needCPMap
        else
          let sAddr = i.JTRange.Min
          let lb, ub = Map.find entry boundaries (* function boundaries *)
          let max = getMaxAddr tableAddrs corpus insAddr sAddr None
          let block = getBlockAddr corpus insAddr
          let targets, eAddr, corpus =
            readTargets hdl corpus lb ub block bAddr max sAddr t Set.empty
          let acc = accJmpTableInfo acc targets lb insAddr bAddr sAddr eAddr t
          let hasChanged =
            match Map.tryFind insAddr oldTableBranches, Map.tryFind insAddr acc with
            | None, None -> false
            | Some info, Some info' ->
              info <> info'
            | _ -> true
          let needCPMap =
            if hasChanged then Map.add entry true needCPMap else needCPMap
          corpus, acc, needCPMap
      | (insAddr, { HostFunctionAddr = entry ; JumpTableInfo = Some i1 }) ::
          (((_, { JumpTableInfo = Some i2 }) :: _) as next) ->
        let bAddr = i1.JTBaseAddr
        let t = i1.JTEntrySize
        if checkDefinedTable corpus insAddr i1.JTRange.Min then
          infer corpus acc needCPMap next
        else
          let s1 = i1.JTRange.Min
          let s2 = i2.JTRange.Min
          let lb, ub = Map.find entry boundaries
          let max = getMaxAddr tableAddrs corpus insAddr s1 (Some s2)
          let block = getBlockAddr corpus insAddr
          let targets, eAddr, corpus =
            readTargets hdl corpus lb ub block bAddr max s1 t Set.empty
          let acc = accJmpTableInfo acc targets lb insAddr bAddr s1 eAddr t
          let hasChanged =
            match Map.tryFind insAddr oldTableBranches, Map.tryFind insAddr acc with
            | None, None -> false
            | Some info, Some info' ->
              info <> info'
            | _ -> true
          let needCPMap =
            if hasChanged then Map.add entry true needCPMap else needCPMap
          infer corpus acc needCPMap next
      | _ -> corpus, acc, needCPMap
    tableBranches
    |> Map.fold (fun acc insAddr info -> (insAddr, info) :: acc) []
    |> List.sortBy (fun (_, ind) ->
      let info = Option.get ind.JumpTableInfo
      info.JTRange.Min)
    |> infer corpus constBranches needCPMap

  let analyzeIndirectBranch ssaCFG cpstate entry constBranches tblBranches needCPMap =
    extractIndirectBranches ssaCFG
    |> List.map (fun (insAddr, stmt, isCall) ->
      match stmt with
      | Jmp (InterJmp exp) -> computeIndBranchInfo cpstate insAddr isCall exp
      | _ -> UnknownFormat)
    |> partitionIndBranchInfo entry constBranches tblBranches needCPMap

  let analyzeBranches hdl corpus ((constBranches, tblBranches), needCPMap) addr =
    match Map.tryFind addr needCPMap with
    | None | Some true ->
      let needCPMap = Map.add addr false needCPMap
      let irCFG, irRoot = corpus.SCFG.GetFunctionCFG (addr, false)
      if hasIndirectBranch irCFG then
        let lens = SSALens.Init hdl corpus.SCFG
        let ssaCFG, ssaRoot = lens.Filter (irCFG, [irRoot], corpus)
        let cp = ConstantPropagation (hdl, ssaCFG)
        let cpstate = cp.Compute (List.head ssaRoot)
        analyzeIndirectBranch ssaCFG cpstate addr constBranches tblBranches needCPMap
      else (constBranches, tblBranches), needCPMap
    | _ -> (constBranches, tblBranches), needCPMap

  let toBranchInfo indMap =
    indMap
    |> Map.fold (fun (constBranches, tblBranches) iAddr indInfo ->
      match indInfo.JumpTableInfo with
      | Some _ -> constBranches, Map.add iAddr indInfo tblBranches
      | None ->
        Map.add iAddr indInfo constBranches, tblBranches) (Map.empty, Map.empty)

  let inferJumpTableRange hdl corpus callees oldTblBranches (constBranches, tblBranches) needCPMap =
    let boundaries = computeFunctionBoundary Map.empty callees
    inferGOTIndexedBranches hdl corpus boundaries oldTblBranches tblBranches constBranches needCPMap

  let calculateTable hdl corpus =
    let callees = computeCalleeAddrs hdl corpus
    let constBranches, tblBranches = toBranchInfo corpus.SCFG.IndirectBranchMap
    let corpus, indmap, _ =
      ((constBranches, tblBranches), Map.empty)
      ||> inferJumpTableRange hdl corpus callees tblBranches
    BinCorpus.addIndirectBranchMap hdl corpus indmap

  let filterCalleeAddrs isTarget addrs =
    match isTarget with
    | Some isTarget -> addrs |> List.filter isTarget
    | None -> addrs

  let rec recover (noReturn: IAnalysis) hdl corpus needCPMap isTarget =
    let corpus = noReturn.Run hdl corpus
    let callees = computeCalleeAddrs hdl corpus |> filterCalleeAddrs isTarget
    let indmap = corpus.SCFG.IndirectBranchMap
    let constBranches, tblBranches = toBranchInfo indmap
    let corpus, indmap', needCPMap =
      callees
      |> List.fold (analyzeBranches hdl corpus) ((constBranches, tblBranches), needCPMap)
      ||> inferJumpTableRange hdl corpus callees tblBranches
    let indmap' = Map.fold (fun acc k v -> Map.add k v acc) indmap indmap'
    if indmap <> indmap' then
      let corpus = BinCorpus.addIndirectBranchMap hdl corpus indmap'
#if DEBUG
      printfn "[*] Go to the next phase ..."
#endif
      recover noReturn hdl corpus needCPMap isTarget
    else corpus

type BranchRecovery (enableNoReturn) =
  let noReturn =
    if enableNoReturn then NoReturnAnalysis () :> IAnalysis
    else NoAnalysis () :> IAnalysis

  member __.CalculateTable hdl corpus =
    BranchRecoveryHelper.calculateTable hdl corpus

  member __.RunWith hdl corpus isTarget =
    BranchRecoveryHelper.recover noReturn hdl corpus Map.empty (Some isTarget)

  interface IAnalysis with
    member __.Name = "Indirect Branch Recovery"

    member __.Run hdl corpus =
      BranchRecoveryHelper.recover noReturn hdl corpus Map.empty None
