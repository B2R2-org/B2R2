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
open B2R2.FrontEnd.BinInterface
open B2R2.BinIR
open B2R2.BinIR.SSA
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.BinEssence
open B2R2.MiddleEnd.Lens
open B2R2.MiddleEnd.DataFlow
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

/// Per-function jump tables, which map an indirect jump instruction address to
/// its jump table info. This map exists per function.
type FunctionLevelJmpTables = Map<Addr, JmpTableIndirectBranch>

/// Function-level jump table info. This exists for every function that has a
/// jump-table indirect branch.
type FunctionLevelJmpTableInfo = {
  /// The entry of the function.
  FunctionEntry: Addr
  /// The function boundary.
  FunctionBoundary: Addr * Addr
  /// Map from an indirect branch instruction address to its jump table.
  JumpTables: FunctionLevelJmpTables
  /// The maximum possible jump table entry address for this function.
  TableMax: Addr
  /// Constant propagation state and the current SSA graph.
  CPInfo: CPState<CopyValue> * DiGraph<SSABBlock, CFGEdgeKind>
}

module FunctionLevelJumpTableState =
  let private computeBoundaries hint info tblMax map =
    let rec loop info = function
      | (_, Some br) :: (((addr', _) :: _) as next) ->
        loop (Map.add br.InsAddr { br with JTMaxEnd = addr' } info) next
      | (_, None) :: next -> loop info next
      | [ (_, Some br) ] ->
        loop (Map.add br.InsAddr { br with JTMaxEnd = tblMax } info) []
      | _ -> info
    let map, lo =
      map
      |> Map.fold (fun (acc, lo) addr br ->
        Map.add addr (Some br) acc, min lo br.JTStartAddr
      ) (Map.empty, UInt64.MaxValue)
    hint.PotentialTableIndBranches
    |> Set.fold (fun map (_, addr) ->
      if addr >= lo || addr < tblMax then Map.add addr None map else map) map
    |> Map.toList
    |> loop info

  let addBranch hint info br =
    let p =
      hint.PotentialTableIndBranches
      |> Set.filter (fun (insAddr, tblAddr) ->
        insAddr <> br.InsAddr && tblAddr <> br.JTStartAddr)
    let hint = { hint with PotentialTableIndBranches = p }
    hint, { info with JumpTables = Map.add br.InsAddr br info.JumpTables }

  let updateBoundary hint info =
    let jtbls =
      info.JumpTables
      |> Map.fold (fun acc _ br -> Map.add br.JTStartAddr br acc) Map.empty
      |> computeBoundaries hint info.JumpTables info.TableMax
    { info with JumpTables = jtbls }

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
    |> filterOutLinkageTables ess.BinHandle
    |> List.sort

  let rec private computeFunctionBoundaries acc = function
    | [] -> acc
    | [ addr ] -> (addr, 0UL) :: acc
    | addr :: ((next :: _) as addrs) ->
      computeFunctionBoundaries ((addr, next) :: acc) addrs

  let private hasIndirectBranch (ess: BinEssence) entry =
    let cfg, _ = ess.GetFunctionCFG (entry, false) |> Result.get
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

  let private getNecessarySubGraph irCFG =
    let rev = DiGraph.reverse irCFG
    (* Collect vertices with indirect branches *)
    let indBranches =
      DiGraph.foldVertex irCFG (fun acc (v: Vertex<IRBasicBlock>) ->
        if (not <| v.VData.IsFakeBlock () && v.VData.HasIndirectBranch) then
          v :: acc
        else acc) []
      |> List.map (fun v -> DiGraph.findVertexByID rev <| v.GetID ())
    (* Use DFS to get necessary-to-analysis vertices *)
    let vertices =
      Set.empty
      |> Traversal.foldPostorder rev indBranches (fun acc v ->
        Set.add (DiGraph.findVertexByID irCFG <| v.GetID ()) acc)
    DiGraph.subGraph irCFG vertices

  let private computeConstantPropagation ess entry =
    let irCFG, irRoot =
      (ess: BinEssence).GetFunctionCFG (entry, false) |> Result.get
    let lens = SSALens.Init ess
    let irCFG = getNecessarySubGraph irCFG
    let ssaCFG, ssaRoots = lens.Filter (irCFG, [irRoot], ess)
    let ssaRoot = List.head ssaRoots
    let stackProp = StackPointerPropagation.Init ess.BinHandle ssaCFG
    let stackSt = stackProp.Compute (ssaRoot)
    let copyProp = ConstantCopyPropagation.Init ess.BinHandle ssaCFG stackSt
    let copySt = copyProp.Compute (ssaRoot)
    copySt, ssaCFG

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
      | CopyValue.Const bv -> Num bv
      | _ ->
        match Map.tryFind v cpstate.SSAEdges.Defs with
        | Some (Def (_, e)) -> extractExp cpstate e
        | _ -> expr
    | Load (mem, rt, addr) ->
      match extractExp cpstate addr with
      | Num bv ->
        let addr = BitVector.toUInt64 bv
        match CPState.findMem cpstate mem rt addr with
        | CopyValue.Const bv -> Num bv
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
    let jtbls = computeJumpTableInfo tblMax brs
    let potentials =
      jtbls
      |> Map.fold (fun p _ br ->
        Set.filter (fun (insAddr, tblAddr) ->
          insAddr <> br.InsAddr && tblAddr <> br.JTStartAddr) p
      ) hint.PotentialTableIndBranches
    let hint = { hint with PotentialTableIndBranches = potentials }
    let info = { FunctionEntry = fst fnBnd
                 FunctionBoundary = fnBnd
                 JumpTables = jtbls
                 TableMax = tblMax
                 CPInfo = cpInfo }
    struct (hint, info)

  let rec private initializeFunctionLevelJmpTblStates hint acc = function
    | [] -> hint, acc
    | [ (fnBnd, brs, _, cpInfo) ] ->
      let struct (hint, i) = createState hint fnBnd brs UInt64.MaxValue cpInfo
      hint, List.rev (i :: acc)
    | (fnBnd, brs, _, cpInfo) :: (((_, _, minTbl, _) :: _) as rest) ->
      let struct (hint, info) = createState hint fnBnd brs minTbl cpInfo
      initializeFunctionLevelJmpTblStates hint (info :: acc) rest

  let private prepareJmpTableRecovery fnBnds ess hint =
    fnBnds
    |> List.choose (initializeIndirectBranchInfoPerFunc ess)
    |> List.sortBy (fun (_, _, minTblAddr, _) -> minTblAddr)
    |> initializeFunctionLevelJmpTblStates hint []

  let private collectIndirectJumps (ess: BinEssence) entry =
    let cfg, _ = ess.GetFunctionCFG (entry, false) |> Result.get
    DiGraph.foldVertex cfg (fun acc (v: Vertex<IRBasicBlock>) ->
      if not <| v.VData.IsFakeBlock () && v.VData.HasIndirectBranch then
        let addr = v.VData.LastInstruction.Address
        if v.VData.LastInstruction.IsCall () then acc
        else Set.add addr acc
      else acc) Set.empty

  let private runNoReturn noret ess hint entry =
    let hint = AnalysisHint.unmarkNoReturn entry hint
    (noret: IAnalysis).Run ess hint

  let inline private hasDuplicatedBase jtbls br =
    jtbls |> Map.exists (fun _ br' -> br'.JTStartAddr = br.JTStartAddr)

  /// Check if there exist new valid indirect jumps after recovering one entry.
  let private checkNewlyFoundIndJump noret oldJmps ess hint info br =
    let newJmps = collectIndirectJumps ess br.HostFunctionStart
    let diff = Set.difference newJmps oldJmps
    (* First, check if there EXIST new indirect jumps in recovered cfg. *)
    if Set.isEmpty diff then Error (ess, hint)
    else
      let ess, hint = runNoReturn noret ess hint br.HostFunctionStart
      let newJmps = collectIndirectJumps ess br.HostFunctionStart
      let diff = Set.difference newJmps oldJmps
      (* Next, check if new indirect jumps still exist after noret-analysis. *)
      if Set.isEmpty diff then Error (ess, hint)
      else
        let cpInfo = computeConstantPropagation ess info.FunctionEntry
        let newJmps =
          findPotentialJmpTableIndBranches info.FunctionBoundary cpInfo
          |> List.fold (fun acc br ->
            if hasDuplicatedBase info.JumpTables br then acc
            else Set.add br.InsAddr acc) Set.empty
        let diff = Set.difference newJmps oldJmps
        (* Finally, check if new indirect jumps can be successfully analyzed. *)
        if Set.isEmpty diff then Error (ess, hint)
        else Ok ess

  let inline private isWithinHostFunction br addr =
    br.HostFunctionStart <= addr && addr < br.HostFunctionEnd

  let inline private addIndBranchTargetFromJmpTbl ess br sAddr size target =
    match BinEssence.addEdge ess br.BBLAddr target IndirectJmpEdge with
    | Ok ess ->
      let br =
        { br with JTFixedEnd = sAddr + uint64 size
                  TargetAddresses = Set.add target br.TargetAddresses }
      Ok (ess, br)
    | Error _ -> Error ()

  /// Recover one entry from the jump table of the indirect branch (br).
  let private recoverJmpTblEntry ess (br: JmpTableIndirectBranch) =
    let sAddr = br.JTFixedEnd
    let hdl = (ess: BinEssence).BinHandle
    if hdl.FileInfo.IsValidAddr sAddr then
      let size = RegType.toByteWidth br.JTEntrySize
      match BinHandle.TryReadInt (hdl, sAddr, size) with
      | Error _ -> Error ()
      | Ok offset ->
        let target = br.BranchBaseAddr + uint64 offset
        if isWithinHostFunction br target then
          addIndBranchTargetFromJmpTbl ess br sAddr size target
        else Error ()
    else Error ()

  let rec private findPromisingBranch noret ess hint info br max =
    if br.JTFixedEnd >= max then Error br
    else
      match recoverJmpTblEntry ess br with
      | Ok (ess', br) ->
        let oldJmps = collectIndirectJumps ess br.HostFunctionStart
        match checkNewlyFoundIndJump noret oldJmps ess' hint info br with
        | Ok ess' -> Ok (ess', br)
        | Error (ess', hint) -> findPromisingBranch noret ess' hint info br max
      | Error _ -> Error br

  let private foldPromisingIndBranch noret ess hint info promisingBrs _ br =
    match br.RecoveryStatus with
    | Done -> promisingBrs
    | Continue ->
      match findPromisingBranch noret ess hint info br br.JTMaxEnd with
      | Ok (ess, br) -> (ess, br) :: promisingBrs
      | Error _ -> promisingBrs

  /// Promising indirect branch here means a newly recovered indirect branch
  /// that we can potentially trust. If a newly found indirect branch of a valid
  /// address has a valid JTStartAddr, then we say it is a promising indirect
  /// branch. However, even a promising indirect branch may become invalid later
  /// on, in which case we may have to roll-back.
  let private findPromisingIndBranches noret ess hint info =
    let promisingBrs =
      info.JumpTables
      |> Map.fold (foldPromisingIndBranch noret ess hint info) []
    hint, info, promisingBrs

  /// Recover jump table entries until meeting the max address (maxAddr).
  let rec private recoverJmpTblEntries ess br maxAddr =
    if br.JTFixedEnd >= maxAddr then ess, br
    else
      match recoverJmpTblEntry ess br with
      | Ok (ess', br) -> recoverJmpTblEntries ess' br maxAddr
      | Error _ -> ess, br

  let private recoverPromisingBr (ess, info) (_, promising) =
    let br = Map.find promising.InsAddr info.JumpTables
    let ess, br = recoverJmpTblEntries ess br promising.JTFixedEnd
    let br =
      if br.JTMaxEnd = br.JTFixedEnd then { br with RecoveryStatus = Done }
      else { br with RecoveryStatus = Continue }
    ess, { info with JumpTables = Map.add br.InsAddr br info.JumpTables }

  let private seemsDuplicatedIndBranch jtbls br =
    jtbls
    |> Map.exists (fun _ br' ->
      br.InsAddr = br'.InsAddr || br.JTStartAddr = br'.JTStartAddr)

  let private addPotentialIndBranchesToHint ess (hint: AnalysisHint) info =
    let potentialTableBranches =
      computeConstantPropagation ess info.FunctionEntry
      |> findPotentialJmpTableIndBranches info.FunctionBoundary
      |> List.fold (fun acc br ->
        if seemsDuplicatedIndBranch info.JumpTables br then
          Set.remove (br.InsAddr, br.JTStartAddr) acc
        else Set.add (br.InsAddr, br.JTStartAddr) acc
        ) hint.PotentialTableIndBranches
    { hint with PotentialTableIndBranches = potentialTableBranches }

  let private restorePromisings noret ess hint info promisingBrs =
    let ess, info = List.fold recoverPromisingBr (ess, info) promisingBrs
    let hint = addPotentialIndBranchesToHint ess hint info
    let ess, hint = runNoReturn noret ess hint info.FunctionEntry
    ess, hint, info

  let inline private isAlreadyFound jtbls br =
    Map.containsKey br.InsAddr jtbls

  /// Update info.JumpTables since CFG is updated and new ind jumps are found.
  let private updateJmpTblInfo ess hint info =
    let cpInfo = computeConstantPropagation ess info.FunctionEntry
    findPotentialJmpTableIndBranches info.FunctionBoundary cpInfo
    |> List.fold (fun (hint, info) br ->
      if isAlreadyFound info.JumpTables br then hint, info
      elif hasDuplicatedBase info.JumpTables br then hint, info
      else FunctionLevelJumpTableState.addBranch hint info br) (hint, info)
    |> fun (hint, info) -> hint, { info with CPInfo = cpInfo }

  /// Once BinEssence is updated, basic blocks in the CFG can change due to the
  /// basic block splitting. So we sync JumpTables with new CFG.
  let private syncBBLAddr info =
    findPotentialJmpTableIndBranches info.FunctionBoundary info.CPInfo
    |> List.fold (fun info br ->
      let insAddr = br.InsAddr
      match Map.tryFind insAddr info.JumpTables with
      | Some br' ->
        let br' = { br' with BBLAddr = br.BBLAddr }
        { info with JumpTables = Map.add insAddr br' info.JumpTables }
      | None -> info) info

  let private restoreJmpTbl (ess, info) _ br =
    if br.JTFixedEnd > br.JTMaxEnd then Utils.impossible ()
    else
      let ess, br = recoverJmpTblEntries ess br br.JTMaxEnd
      let br = { br with RecoveryStatus = Done }
      ess, { info with JumpTables = Map.add br.InsAddr br info.JumpTables }

  let inline private finalizeRecovery noret ess hint info =
    let ess, info = Map.fold restoreJmpTbl (ess, info) info.JumpTables
    let ess, hint = runNoReturn noret ess hint info.FunctionEntry
    ess, hint, info

  let inline private checkOverlap jtbls =
    jtbls |> Map.exists (fun _ br -> br.JTFixedEnd > br.JTMaxEnd)

  let rec private recoverLoop noret oldEss ess hint info =
    let hint, info, promisingBrs = findPromisingIndBranches noret ess hint info
    if List.length promisingBrs > 0 then
      let ess, hint, info = restorePromisings noret ess hint info promisingBrs
      let hint, info = updateJmpTblInfo ess hint info
      let info = FunctionLevelJumpTableState.updateBoundary hint info
      if checkOverlap info.JumpTables then rollBack noret oldEss hint info
      else recoverLoop noret oldEss ess hint <| syncBBLAddr info
    else finalizeRecovery noret ess hint info

  and private rollBack noret ess hint info =
    (* Move currently recovered jumptable info into PotentialTableIndBranches *)
    let potentials =
      info.JumpTables
      |> Map.fold (fun p ins info ->
        Set.add (ins, info.JTStartAddr) p) hint.PotentialTableIndBranches
    let cpInfo = computeConstantPropagation ess info.FunctionEntry
    (* Take initial jumptable info *)
    let jtbls, potentials =
      cpInfo
      |> findPotentialJmpTableIndBranches info.FunctionBoundary
      |> List.fold (fun (acc, p) br ->
        Map.add br.InsAddr br acc, Set.remove (br.InsAddr, br.JTStartAddr) p
        ) (Map.empty, potentials)
    let hint = { hint with PotentialTableIndBranches = potentials }
    let info = { info with JumpTables = jtbls; CPInfo = cpInfo }
    let info = FunctionLevelJumpTableState.updateBoundary hint info
    recoverLoop noret ess ess hint info

  let private updateIndirectBranchMap ess info =
    info.JumpTables
    |> Map.fold (fun map insAddr br ->
      match br.RecoveryStatus with
      | Done when not (Set.isEmpty br.TargetAddresses) ->
        let range = AddrRange (br.JTStartAddr, br.JTFixedEnd)
        let jtInfo = JumpTableInfo.Init br.BranchBaseAddr range br.JTEntrySize
        let indBranchInfo =
          { HostFunctionAddr = br.HostFunctionStart
            TargetAddresses = br.TargetAddresses
            JumpTableInfo = Some jtInfo }
        Map.add insAddr indBranchInfo map
      | _ -> map) ess.IndirectBranchMap

  let private recoverJmpTablesForFunction noret (ess, hint) info =
    let ess, hint, info = recoverLoop noret ess ess hint info
    let indBrMap = updateIndirectBranchMap ess info
    { ess with IndirectBranchMap = indBrMap }, hint

  let private recoverTableJmps noret fnBnds ess hint =
    let hint, infos = prepareJmpTableRecovery fnBnds ess hint
    List.fold (recoverJmpTablesForFunction noret) (ess, hint) infos

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

  let isContainedInTextSection hdl addr =
    hdl.FileInfo.GetTextSections ()
    |> Seq.exists (fun sec ->
      sec.Address <= addr && addr < sec.Address + sec.Size)

  let addConstJmpEdge (ess: BinEssence) blockAddr target isCall =
    if isContainedInTextSection ess.BinHandle target then
      if isCall then
        [ (target, ess.BinHandle.DefaultParsingContext) ]
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
      runNoReturn noret ess hint entry

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
