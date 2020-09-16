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
open B2R2.BinIR
open B2R2.BinIR.SSA
open B2R2.BinGraph
open B2R2.BinEssence
open B2R2.DataFlow
open B2R2.Lens
open System

/// We mainly consider two types of indirect branches: jump-table and const
/// address pattern.
type BranchPattern =
  /// This encodes an indirect jump with a jump table where baseAddr is the jump
  /// target's base address, tblAddr is the start address of a jump table, and
  /// rt is the size of each entry in the jump table.
  | JmpTablePattern of baseAddr: Addr * tblAddr: Addr * rt: RegType
  /// Jump to a constant target.
  | ConstPattern of targetAddr: Addr
  /// Unknown pattern.
  | UnknownPattern

/// Indirect branch whose target is a constant.
type ConstantIndirectBranch = {
  /// The address of the owner function of the indirect branch.
  HostFunctionAddr: Addr
  /// Constant branch target.
  TargetAddr: Addr
  /// Address of the indirect branch instruction.
  InsAddr: Addr
}

/// Current recovery status for a jump table.
type TableRecoveryStatus =
  /// Recovery is done for the jump table.
  | Done
  /// Recovery needs to be continued.
  | Continue

/// Indirect branch that uses a jump table.
type JmpTableIndirectBranch = {
  /// Start address of the function containing the indirect branch instruction.
  HostFunctionStart: Addr
  /// End address of the function containing the indirect branch instruction.
  HostFunctionEnd: Addr
  /// Address of the basic block containing the indirect branch instruction.
  BBLAddr: Addr
  /// Address of the indirect branch instruction.
  InsAddr: Addr
  /// The base address of the jump target.
  BranchBaseAddr: Addr
  /// Start address of the jump table.
  JTStartAddr: Addr
  /// Currently confirmed (fixed) end address of the jump table. As we analyze
  /// more branch targets, this can grow.
  JTFixedEnd: Addr
  /// Maximum end address of the jump table.
  JTMaxEnd: Addr
  /// Jump table entry size.
  JTEntrySize: RegType
  /// Jump targets of the indirect branch.
  TargetAddresses: Set<Addr>
  /// Recovery status.
  RecoveryStatus: TableRecoveryStatus
}
with
  static member Init (fnStart, fnEnd) block insAddr bAddr sAddr rt =
    { HostFunctionStart = fnStart
      HostFunctionEnd = fnEnd
      BBLAddr = block
      InsAddr = insAddr
      BranchBaseAddr = bAddr
      JTStartAddr = sAddr
      JTFixedEnd = sAddr
      JTMaxEnd = 0UL
      JTEntrySize = rt
      TargetAddresses = Set.empty
      RecoveryStatus = Continue }

/// Per-function jump table info, which maps an indirect jump instruction
/// address to its jump table info. This map exists per function.
type FunctionLevelJumpTableInfo = Map<Addr, JmpTableIndirectBranch>

module FunctionLevelJumpTableInfo =
  let private computeBoundaries hint (inf: FunctionLevelJumpTableInfo) map =
    let rec loop inf = function
      | (_, Some br) :: (((addr', _) :: _) as next) ->
        loop (Map.add br.InsAddr { br with JTMaxEnd = addr' } inf) next
      | (_, None) :: next -> loop inf next
      | [ (_, Some br) ] ->
        loop (Map.add br.InsAddr { br with JTMaxEnd = UInt64.MaxValue } inf) []
      | _ -> inf
    let map, lo, hi =
      map
      |> Map.fold (fun (acc, lo, hi) addr br ->
        Map.add addr (Some br) acc, min lo br.JTStartAddr, max hi br.JTMaxEnd
      ) (Map.empty, UInt64.MaxValue, 0UL)
    hint.PotentialTableIndBranches
    |> Set.fold (fun map (_, addr) ->
      if addr > lo && addr < hi then Map.add addr None map else map) map
    |> Map.toList
    |> loop inf

  let addBranch hint jtInfo br =
    let newTblAddr = br.JTStartAddr
    let tableInfos =
      jtInfo
      |> Map.fold (fun acc _ br -> Map.add br.JTStartAddr br acc) Map.empty
      |> Map.add newTblAddr { br with RecoveryStatus = Continue }
      |> computeBoundaries hint jtInfo
    let p = Set.add (br.InsAddr, br.JTStartAddr) hint.PotentialTableIndBranches
    let hint = { hint with PotentialTableIndBranches = p }
    hint, tableInfos

  let removeBranch hint jtInfo br =
    let tableInfos = Map.remove br.InsAddr jtInfo
    let p =
      hint.PotentialTableIndBranches
      |> Set.filter (fun (insAddr, tblAddr) ->
        insAddr <> br.InsAddr && tblAddr <> br.JTStartAddr)
    { hint with PotentialTableIndBranches = p }, tableInfos

  let updateBoundary hint jtInfo =
    jtInfo
    |> Map.fold (fun acc _ br -> Map.add br.JTStartAddr br acc) Map.empty
    |> computeBoundaries hint jtInfo

  let resetTableRanges jtInfo =
    jtInfo
    |> Map.map (fun _ br ->
      let s = br.JTStartAddr
      { br with JTStartAddr = s
                JTFixedEnd = s
                TargetAddresses = Set.empty
                RecoveryStatus = Continue })

/// Function-level indirect branch recovery state. This state exists for every
/// function that has a jump-table indirect branch.
type FunctionLevelJmpTableRecoveryState = {
  FunctionEntry: Addr
  /// The function boundary.
  FunctionBoundary: Addr * Addr
  /// Map from an indirect branch instruction address to its jump table.
  JumpTableInfo: FunctionLevelJumpTableInfo
  /// Constant propagation state and the current SSA graph.
  CPInfo: CPState * DiGraph<SSABBlock, CFGEdgeKind>
}

module BranchRecoveryHelper =
  let private filterOutLinkageTables hdl calleeAddrs =
    let tabAddrs =
      hdl.FileInfo.GetLinkageTableEntries ()
      |> Seq.map (fun ent -> ent.TrampolineAddress)
      |> Set.ofSeq
    calleeAddrs
    |> List.filter (fun addr -> not <| Set.contains addr tabAddrs)

  let private computeCalleeAddrs ess =
    ess.CalleeMap.Callees
    |> Seq.choose (fun callee -> callee.Addr)
    |> Seq.toList
    |> filterOutLinkageTables ess.BinHandler
    |> List.sort

  let rec private computeFunctionBoundaries acc = function
    | [] -> acc
    | [ addr ] -> (addr, 0UL) :: acc
    | addr :: ((next :: _) as addrs) ->
      computeFunctionBoundaries ((addr, next) :: acc) addrs

  let private hasIndirectBranch (ess: BinEssence) entry =
    let cfg, _ = ess.GetFunctionCFG (entry, false)
    DiGraph.foldVertex cfg (fun acc (v: Vertex<IRBasicBlock>) ->
      (not <| v.VData.IsFakeBlock () && v.VData.HasIndirectBranch)
      || acc) false

  let private filterFunctions ess (hint, acc) ((entry, _) as bnd) =
    if Set.contains entry hint.BranchRecoveryPerformed then hint, acc
    elif hasIndirectBranch ess entry then hint, bnd :: acc
    else AnalysisHint.markBranchRecovery entry hint, acc

  let private obtainTargetFunctionBoundaries ess hint =
    computeCalleeAddrs ess
    |> computeFunctionBoundaries []
    |> List.fold (filterFunctions ess) (hint, [])
    |> fun (hint, bnds) -> hint, List.rev bnds

  let private computeConstantPropagation ess entry =
    let irCFG, irRoot = (ess: BinEssence).GetFunctionCFG (entry, false)
    let lens = SSALens.Init ess
    let ssaCFG, ssaRoots = lens.Filter (irCFG, [irRoot], ess)
    let cp = ConstantPropagation (ess.BinHandler, ssaCFG)
    let ssaRoot = List.head ssaRoots
    cp.Compute (ssaRoot), ssaCFG

  let private extractIndirectBranches cfg =
    DiGraph.foldVertex cfg (fun acc (v: Vertex<SSABBlock>) ->
      let len = v.VData.InsInfos.Length
      if not <| v.VData.IsFakeBlock ()
        && v.VData.HasIndirectBranch
        && len > 0
      then
        let addr = v.VData.PPoint.Address
        let lastIns = v.VData.InsInfos.[len - 1].Instruction
        let isCall = lastIns.IsCall ()
        (addr, lastIns.Address, v.VData.GetLastStmt (), isCall) :: acc
      else acc) []

  let rec private simplifyBinOp = function
    | BinOp (BinOpType.ADD, _, Num v1, Num v2) -> Num (BitVector.add v1 v2)
    | BinOp (BinOpType.SUB, _, Num v1, Num v2) -> Num (BitVector.sub v1 v2)
    | BinOp (BinOpType.MUL, _, Num v1, Num v2) ->
      let v1 =
        if BitVector.toUInt64 v2 = 4UL && not <| BitVector.isZero v1 then
          BitVector.zero <| BitVector.getType v1
        else v1
      Num (BitVector.mul v1 v2)
    | BinOp (BinOpType.ADD, rt, Num v1, BinOp (BinOpType.ADD, _, Num v2, e))
    | BinOp (BinOpType.ADD, rt, Num v1, BinOp (BinOpType.ADD, _, e, Num v2))
    | BinOp (BinOpType.ADD, rt, BinOp (BinOpType.ADD, _, Num v2, e), Num v1)
    | BinOp (BinOpType.ADD, rt, BinOp (BinOpType.ADD, _, e, Num v2), Num v1) ->
      simplifyBinOp (BinOp (BinOpType.ADD, rt, Num (BitVector.add v1 v2), e))
    | e -> e

  let private simplifyExtract = function
    | Extract (Cast (CastKind.ZeroExt, _, e'), rt, 0) as e ->
      if AST.typeOf e' = rt then e' else e
    | e -> e

  let rec private extractExp cpstate expr =
    match expr with
    | Num _ -> expr
    | Var v ->
      match CPState.findReg cpstate v with
      | Const bv -> Num bv
      | Pointer bv -> Num bv
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
        | Pointer bv -> Num bv
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

  let private computeTableAddr = function
    | BinOp (BinOpType.ADD, _, Num addr, _)
    | BinOp (BinOpType.ADD, _, _, Num addr)
    | Num addr -> Some (BitVector.toUInt64 addr)
    | _ -> None

  let private computeBranchPattern isCall expr =
    match expr, isCall with
    | Num addr, _ -> ConstPattern (BitVector.toUInt64 addr)
    | _, true -> UnknownPattern
    | BinOp (BinOpType.ADD, _, Load (_, t, tbl), Num bBase), _
    | BinOp (BinOpType.ADD, _, Num bBase, Load (_, t, tbl)), _
    | BinOp (BinOpType.ADD, _, Cast (_, _, Load (_, t, tbl)), Num bBase), _
    | BinOp (BinOpType.ADD, _, Num bBase, Cast (_, _, Load (_, t, tbl))), _ ->
      match computeTableAddr tbl with
      | Some tAddr -> JmpTablePattern (BitVector.toUInt64 bBase, tAddr, t)
      | None -> UnknownPattern
    | _ -> UnknownPattern

  let private classifyBranch cpState isCall = function
    | Jmp (InterJmp exp)
    | Jmp (InterCJmp (_, exp, Num _))
    | Jmp (InterCJmp (_, Num _, exp)) ->
      extractExp cpState exp |> computeBranchPattern isCall
    | _ -> UnknownPattern

  let private findPotentialJmpTableIndBranches fnBnd (cpState, ssaCFG) =
    extractIndirectBranches ssaCFG
    |> List.fold (fun lst (block, insAddr, stmt, isCall) ->
      match classifyBranch cpState isCall stmt with
      | JmpTablePattern (bAddr, tAddr, rt) ->
        JmpTableIndirectBranch.Init fnBnd block insAddr bAddr tAddr rt :: lst
      | _ -> lst) []

  let private initializeIndirectBranchInfoPerFunc ess ((fnEntry, _) as fnBnd) =
    let cpInfo = computeConstantPropagation ess fnEntry
    match findPotentialJmpTableIndBranches fnBnd cpInfo with
    | [] -> None
    | brs ->
      let brs = List.sortBy (fun br -> br.JTStartAddr) brs
      let minTblAddr = (List.head brs).JTStartAddr
      Some (fnBnd, brs, minTblAddr, cpInfo)

  let private computeJumpTableInfo tblMax brs =
    let rec loop m = function
      | br :: ((br' :: _) as rest) ->
        let br =
          { br with JTMaxEnd = br'.JTStartAddr; RecoveryStatus = Continue }
        loop (Map.add br.InsAddr br m) rest
      | [ br ] ->
        Map.add br.InsAddr
          { br with JTMaxEnd = tblMax; RecoveryStatus = Continue } m
      | [] -> Utils.impossible ()
    loop Map.empty brs

  let private addPotentialTableIndBranches hint brs =
    let brs =
      brs |> List.fold (fun acc br ->
        Set.add (br.InsAddr, br.JTStartAddr) acc
      ) hint.PotentialTableIndBranches
    { hint with PotentialTableIndBranches = brs }

  let private createState hint fnBnd brs tblMax cpInfo =
    let hint = addPotentialTableIndBranches hint brs
    let jtInfo = computeJumpTableInfo tblMax brs
    let st =
      { FunctionEntry = fst fnBnd
        FunctionBoundary = fnBnd
        JumpTableInfo = jtInfo
        CPInfo = cpInfo }
    struct (hint, st)

  let rec private initializeFunctionLevelJmpTblStates hint acc = function
    | [] -> hint, acc
    | [ (fnBnd, brs, _, cpInfo) ] ->
      let struct (hint, st) = createState hint fnBnd brs UInt64.MaxValue cpInfo
      hint, List.rev (st :: acc)
    | (fnBnd, brs, _, cpInfo) :: (((_, _, minTbl, _) :: _) as rest) ->
      let struct (hint, st) = createState hint fnBnd brs minTbl cpInfo
      initializeFunctionLevelJmpTblStates hint (st :: acc) rest

  let private prepareJmpTableRecovery fnBnds ess hint =
    fnBnds
    |> List.choose (initializeIndirectBranchInfoPerFunc ess)
    |> List.sortBy (fun (_, _, minTblAddr, _) -> minTblAddr)
    |> initializeFunctionLevelJmpTblStates hint []

  let private collectIndirectJumps (ess: BinEssence) entry =
    let cfg, root = ess.GetFunctionCFG (entry, false)
    Traversal.foldPostorder cfg root (fun acc (v: Vertex<IRBasicBlock>) ->
      if not <| v.VData.IsFakeBlock () && v.VData.HasIndirectBranch then
        let addr = v.VData.PPoint.Address
        if v.VData.LastInstruction.IsCall () then acc
        else Set.add addr acc
      else acc) Set.empty

  let inline private withinCallee br addr =
    br.HostFunctionStart <= addr && addr < br.HostFunctionEnd

  let readTarget ess (br: JmpTableIndirectBranch) sAddr =
    let hdl = (ess: BinEssence).BinHandler
    if hdl.FileInfo.IsValidAddr sAddr then
      let size = RegType.toByteWidth br.JTEntrySize
      match BinHandler.TryReadInt (hdl, sAddr, size) with
      | Error _ -> Error ()
      | Ok offset ->
        let target = br.BranchBaseAddr + uint64 offset
        if withinCallee br target then
          let block = br.BBLAddr
          match BinEssence.addEdge ess block target IndirectJmpEdge with
          | Ok ess' ->
            let next = sAddr + uint64 size
            let br =
              { br with
                  JTStartAddr = br.JTStartAddr
                  JTFixedEnd = next
                  TargetAddresses = Set.add target br.TargetAddresses }
            Ok (ess', br)
          | Error _ -> Error ()
        else Error ()
    else Error ()

  let rec readTargets ess br sAddr max =
    if sAddr >= max then Error br
    else
      let oldJmps = collectIndirectJumps ess br.HostFunctionStart
      match readTarget ess br sAddr with
      | Ok (ess, br) ->
        let newJmps = collectIndirectJumps ess br.HostFunctionStart
        let diff = Set.difference newJmps oldJmps
        if Set.isEmpty diff then readTargets ess br br.JTFixedEnd max
        else Ok (ess, br)
      | Error _ -> Error br

  let rec readTargetsUntil ess br sAddr max =
    if sAddr >= max then ess, br
    else
      match readTarget ess br sAddr with
      | Ok (ess', br) -> readTargetsUntil ess' br br.JTFixedEnd max
      | Error _ -> ess, br

  let tryRecover noret ess hint st (discovered, recovered) br =
    let insAddr = br.InsAddr // XXX: no need to pass br here.
    let br = Map.find insAddr st.JumpTableInfo
    match br.RecoveryStatus with
    | Done -> discovered, recovered
    | Continue ->
      let ess, br = readTargetsUntil ess br br.JTStartAddr br.JTFixedEnd // XXX
      match readTargets ess br br.JTFixedEnd br.JTMaxEnd with
      | Ok (ess, br) ->
        let hint = AnalysisHint.unmarkNoReturn br.HostFunctionStart hint
        let ess, _ = (noret: IAnalysis).Run ess hint
        Map.add insAddr (ess, br) discovered, recovered
      | Error br -> discovered, Map.add insAddr br recovered

  let inline private isAlreadyFound jtInfo br =
    Map.containsKey br.InsAddr jtInfo

  let inline private hasDuplicatedBase jtInfo br =
    jtInfo |> Map.exists (fun _ br' -> br'.JTStartAddr = br.JTStartAddr)

  let discoverNewBranches hint st br cpInfo =
    let newBranches, hasDuplicated =
      findPotentialJmpTableIndBranches st.FunctionBoundary cpInfo
      |> List.fold (fun (acc, hasDuplicated) br ->
        if isAlreadyFound st.JumpTableInfo br then (acc, hasDuplicated)
        elif hasDuplicatedBase st.JumpTableInfo br then (acc, true)
        else br :: acc, hasDuplicated) ([], false)
    if List.isEmpty newBranches then
      if hasDuplicated then Error st
      else
        let insAddr = br.InsAddr
        let inf = { br with RecoveryStatus = Continue }
        { st with JumpTableInfo = Map.add insAddr inf st.JumpTableInfo }
        |> Error
    else
      newBranches
      |> List.fold (fun (hint, st) br ->
        let hint, jtInfo =
          FunctionLevelJumpTableInfo.addBranch hint st.JumpTableInfo br
        hint, { st with JumpTableInfo = jtInfo }) (hint, st)
      |> Ok

  let inline private checkOverlap jtInfo =
    jtInfo |> Map.exists (fun _ br -> br.JTFixedEnd > br.JTMaxEnd)

  let recoverTableUntilNewBranch (ess, st: FunctionLevelJmpTableRecoveryState) insAddr (_, br) =
    let ess, br = readTargetsUntil ess br br.JTStartAddr br.JTFixedEnd
    let info =
      if br.JTMaxEnd = br.JTFixedEnd then { br with RecoveryStatus = Done }
      else { br with RecoveryStatus = Continue }
    ess, { st with JumpTableInfo = Map.add insAddr info st.JumpTableInfo }

  let recoverTableUntilBoundary (ess, st: FunctionLevelJmpTableRecoveryState) insAddr br =
    if br.JTFixedEnd > br.JTMaxEnd then ess, st
    else
      let ess, br = readTargetsUntil ess br br.JTStartAddr br.JTFixedEnd
      ess, { st with JumpTableInfo = Map.add insAddr { br with RecoveryStatus = Done } st.JumpTableInfo }

  let updateBinEssenceWithKnowledge ess st discovered recovered =
    if not <| Map.isEmpty discovered then
      discovered |> Map.fold recoverTableUntilNewBranch (ess, st)
    elif not <| Map.isEmpty recovered then
      recovered |> Map.fold recoverTableUntilBoundary (ess, st)
    else ess, st

  let updateKnowledgeWithNewBinEssence st cpInfo =
    findPotentialJmpTableIndBranches st.FunctionBoundary cpInfo
    |> List.fold (fun st br ->
      let insAddr = br.InsAddr
      if not <| Map.containsKey insAddr st.JumpTableInfo then st
      else
        let br' = Map.find insAddr st.JumpTableInfo
        match br'.RecoveryStatus with
        | Done ->
          let info = { br' with BBLAddr = br.BBLAddr; RecoveryStatus = Done }
          { st with JumpTableInfo = Map.add insAddr info st.JumpTableInfo }
        | Continue ->
          let info = { br' with BBLAddr = br.BBLAddr
                                RecoveryStatus = Continue }
          { st with JumpTableInfo = Map.add insAddr info st.JumpTableInfo }) st

  let checkTableConflictAndUpdateKnowledge hint acc st br br' =
    if br.JTStartAddr < br'.JTStartAddr then
      let hint, jtInfo = FunctionLevelJumpTableInfo.removeBranch hint st.JumpTableInfo br'
      let hint, jtInfo = FunctionLevelJumpTableInfo.addBranch hint jtInfo br
      (hint, { st with JumpTableInfo = jtInfo }) |> Error
    else
      match acc with
      | Ok _ -> Ok (hint, st)
      | Error _ -> Error (hint, st)

  let recoverNewBranches hint st cpInfo =
    findPotentialJmpTableIndBranches st.FunctionBoundary cpInfo
    |> List.fold (fun acc br ->
      let hint, st =
        match acc with
        | Ok (hint, st) | Error (hint, st) -> hint, st
      let insAddr = br.InsAddr
      match Map.tryFind insAddr st.JumpTableInfo with
      | None ->
        match discoverNewBranches hint st br cpInfo with
        | Ok (hint, st) ->
          match acc with
          | Ok _ -> Ok (hint, st)
          | Error _ -> Error (hint, st)
        | Error st ->
          match acc with
          | Ok _ -> Ok (hint, st)
          | Error _ -> Error (hint, st)
      | Some br' ->
        checkTableConflictAndUpdateKnowledge hint acc st br br'
      ) (Ok (hint, st))

  let checkAllDone jtInfo =
    jtInfo
    |> Map.forall (fun _ br ->
      match br.RecoveryStatus with
      | Done -> true
      | _ -> false)

  let private tryRecoverOneLevel noret ess hint st =
    let discovered, recovered =
      findPotentialJmpTableIndBranches st.FunctionBoundary st.CPInfo
      |> List.fold (tryRecover noret ess hint st) (Map.empty, Map.empty)
    discovered
    |> Map.fold (fun (struct (hint, st, discovered, recovered)) insAddr (ess, br) ->
      let cpInfo = computeConstantPropagation ess st.FunctionEntry
      match discoverNewBranches hint st br cpInfo with
      | Ok (hint, st) ->
        struct (hint, st, Map.add insAddr (ess, br) discovered, recovered)
      | Error st ->
        struct (hint, st, discovered, recovered)) (struct (hint, st, Map.empty, recovered))

  let rec recoverLoop noret oldEss ess hint st =
    let struct (hint, st, discovered, recovered) = tryRecoverOneLevel noret ess hint st
    if checkOverlap st.JumpTableInfo then
      rollBackWithKnowledge noret oldEss hint st
    else
      let ess, st = updateBinEssenceWithKnowledge ess st discovered recovered
      if checkOverlap st.JumpTableInfo then
        rollBackWithKnowledge noret oldEss hint st
      else
        let candidates =
          computeConstantPropagation ess st.FunctionEntry
          |> findPotentialJmpTableIndBranches st.FunctionBoundary
          |> List.fold (fun acc br ->
            if Map.containsKey br.InsAddr st.JumpTableInfo then acc
            else Set.add (br.InsAddr, br.JTStartAddr) acc) Set.empty
        let hint = AnalysisHint.unmarkNoReturn st.FunctionEntry hint
        let ess, hint = (noret: IAnalysis).Run ess hint
        let cpInfo = computeConstantPropagation ess st.FunctionEntry
        let st = updateKnowledgeWithNewBinEssence st cpInfo
        match recoverNewBranches hint st cpInfo with
        | Ok (hint, st) ->
          let unreachables =
            Set.union candidates hint.PotentialTableIndBranches
          let unreachables =
            st.JumpTableInfo
            |> Map.fold (fun acc _ br ->
              Set.filter (fun (insAddr, addr) ->
                insAddr <> br.InsAddr && addr <> br.JTStartAddr) acc
            ) unreachables
          let hint = { hint with PotentialTableIndBranches = unreachables }
          if checkAllDone st.JumpTableInfo then ess, hint, st
          else
            let unreachables =
              Set.union candidates hint.PotentialTableIndBranches
            let unreachables =
              st.JumpTableInfo
              |> Map.fold (fun acc _ br ->
                Set.filter (fun (insAddr, addr) ->
                  insAddr <> br.InsAddr && addr <> br.JTStartAddr) acc
              ) unreachables
            let hint = { hint with PotentialTableIndBranches = unreachables }
            let jtInfo = FunctionLevelJumpTableInfo.updateBoundary hint st.JumpTableInfo
            recoverLoop noret oldEss ess hint
              { st with JumpTableInfo = jtInfo; CPInfo = cpInfo }
        | Error (hint, st) ->
          let unreachables =
            Set.union candidates hint.PotentialTableIndBranches
          let unreachables =
            st.JumpTableInfo
            |> Map.fold (fun acc _ br ->
              Set.filter (fun (insAddr, addr) ->
                insAddr <> br.InsAddr && addr <> br.JTStartAddr) acc
            ) unreachables
          let hint = { hint with PotentialTableIndBranches = unreachables }
          let st = { st with JumpTableInfo = FunctionLevelJumpTableInfo.updateBoundary hint st.JumpTableInfo }
          rollBackWithKnowledge noret oldEss hint st

  and rollBackWithKnowledge noret ess hint st =
    let cpInfo = computeConstantPropagation ess st.FunctionEntry
    let st = updateKnowledgeWithNewBinEssence st cpInfo
    let jtInfo = FunctionLevelJumpTableInfo.resetTableRanges st.JumpTableInfo
    recoverLoop noret ess ess hint
      { st with JumpTableInfo = jtInfo; CPInfo = cpInfo }

  let recoverJmpTablesForFunction noret (ess, hint) st =
    let ess, hint, st = recoverLoop noret ess ess hint st
    st.JumpTableInfo
    |> Map.fold (fun acc insAddr br ->
      match br.RecoveryStatus with
      | Done ->
        if Set.isEmpty br.TargetAddresses then acc
        else
          let range = AddrRange (br.JTStartAddr, br.JTFixedEnd)
          let jtInfo = JumpTableInfo.Init br.BranchBaseAddr range br.JTEntrySize
          let info =
            { HostFunctionAddr = br.HostFunctionStart
              TargetAddresses = br.TargetAddresses
              JumpTableInfo = Some jtInfo }
          Map.add insAddr info acc
      | _ -> acc) ess.IndirectBranchMap
    |> fun indMap -> { ess with IndirectBranchMap = indMap }, hint

  let private recoverTableJmps noret fnBnds ess hint =
    let hint, states = prepareJmpTableRecovery fnBnds ess hint
    List.fold (recoverJmpTablesForFunction noret) (ess, hint) states

  let findConstBranches ess entry =
    let cpState, ssaCFG = computeConstantPropagation ess entry
    extractIndirectBranches ssaCFG
    |> List.fold (fun acc (blockAddr, insAddr, stmt, isCall) ->
      match classifyBranch cpState isCall stmt with
      | ConstPattern target ->
        let br =
          { HostFunctionAddr = entry; TargetAddr = target; InsAddr = insAddr }
        (blockAddr, insAddr, br , isCall) :: acc
      | _ -> acc) []

  let addConstJmpEdge (ess: BinEssence) blockAddr target isCall =
    if ess.BinHandler.FileInfo.IsExecutableAddr target then
      if isCall then
        [ (target, (ess: BinEssence).BinHandler.DefaultParsingContext) ]
        |> BinEssence.addEntries ess
      else Ok ess
      |> Result.bind (fun ess ->
        if isCall then IndirectCallEdge else IndirectJmpEdge
        |> BinEssence.addEdge ess blockAddr target)
      |> (fun ess ->
        match ess with
        | Ok ess -> ess
        | _ -> Utils.impossible ())
    else ess

  let private recoverConstJmpsOfFunc noret (ess, hint) (entry, _) =
    match findConstBranches ess entry with
    | [] -> ess, hint
    | constBranches ->
      let ess =
        constBranches
        |> List.fold (fun ess (block, insAddr, br, isCall) ->
          let ess = addConstJmpEdge ess block br.TargetAddr isCall
          let info =
            { HostFunctionAddr = br.HostFunctionAddr
              TargetAddresses = Set.singleton br.TargetAddr
              JumpTableInfo = None }
          let indMap = Map.add insAddr info ess.IndirectBranchMap
          { ess with IndirectBranchMap = indMap }) ess
      let hint = AnalysisHint.unmarkNoReturn entry hint
      (noret: IAnalysis).Run ess hint

  let private recoverConstJmps noret fnBnds ess hint =
    fnBnds |> List.fold (recoverConstJmpsOfFunc noret) (ess, hint)

  let private markPerformed fnBnds hint =
    fnBnds
    |> List.fold (fun hint (entry, _) ->
      AnalysisHint.markBranchRecovery entry hint) hint

  let rec recover noret ess hint =
    let hint, fnBnds = obtainTargetFunctionBoundaries ess hint
    if List.isEmpty fnBnds then ess, hint
    else
      let ess, hint = recoverTableJmps noret fnBnds ess hint
      let ess, hint = recoverConstJmps noret fnBnds ess hint
      let hint = markPerformed fnBnds hint
#if DEBUG
      printfn "[*] Go to the next recovery phase..."
#endif
      recover noret ess hint

type BranchRecovery (enableNoReturn) =
  let noret =
    if enableNoReturn then NoReturnAnalysis () :> IAnalysis
    else NoAnalysis () :> IAnalysis

  member __.RunWith _ = Utils.futureFeature ()

  member __.CalculateTable _ = Utils.futureFeature ()

  interface IAnalysis with
    member __.Name = "Indirect Branch Recovery"

    member __.Run ess hint =
      BranchRecoveryHelper.recover noret ess hint
