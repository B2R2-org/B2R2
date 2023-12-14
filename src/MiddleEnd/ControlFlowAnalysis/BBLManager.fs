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

namespace B2R2.MiddleEnd.ControlFlowAnalysis

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

/// Temporary information obtained by parsing a block (bbl) of instructions,
/// such as IR-level leaders and auxiliary information about an
/// instruction-level basic block. This information is necessary to construct a
/// (IR-level) CFG. Normally, a single instruction-level bbl represents a single
/// IR-level basic block, but if there exist intra-instruction control flows, it
/// can have multiple intra blocks.
type TempInfo = {
  /// Helper for translating symbol to program point.
  LabelPPoints: Map<LabelIdentifier, ProgramPoint>
  /// All leaders in this block.
  Leaders: Set<ProgramPoint>
  /// Intra-Instruction edges in this block.
  IntraEdges: (ProgramPoint * ProgramPoint * CFGEdgeKind) list
  /// Inter-Instruction edges related to this block.
  InterEdges: (ProgramPoint * ProgramPoint * CFGEdgeKind) list
  /// Flag indicating that IEMark statement follows a terminatinig statment,
  /// such as SideEffect. Although our IR optimizer will remove such IEMarks in
  /// most cases, there is one exception, though. If there is a SideEffect
  /// statement immediately followed by an IEMark, our optmizer will not remove
  /// the IEMark because we cannot assume that the SideEffect statement will
  /// advance the PC. In fact, the SideEffect statement does not necessarily
  /// know the size of the corresponding machine instruction. Thus, it is not
  /// natural to remove such IEMarks.
  HasExplicitTerminator: bool
  /// Next events to consume. Since BBLManager parses only a single BBL, other
  /// events need to be consumed later.
  NextEvents: CFGEvents
}
with
  static member Init initialLeader evts =
    { LabelPPoints = Map.empty
      Leaders = Set.singleton initialLeader
      IntraEdges = []
      InterEdges = []
      HasExplicitTerminator = false
      NextEvents = evts }

  /// Find label symbol at the given program point (myPp).
  static member FindLabelSymbol tmpInfo myPp =
    Map.findKey (fun _ labelPp -> labelPp = myPp) tmpInfo.LabelPPoints
    |> snd

/// Since Symbol is only unique within an instruction, it is necessary to tag it
/// with the instruction address that holds the symbol.
and LabelIdentifier = Addr * Symbol

[<RequireQualifiedAccess>]
module BBLManager =
  /// Return the bitmask for the given BinHandle to correctly compute jump
  /// target addresses.
  let computeJumpTargetMask (hdl: BinHandle) =
    let rt = hdl.File.ISA.WordSize |> WordSize.toRegType
    (* It is reasonable enough to assume that jump target addresses will never
       overflow when rt is greater than 64<rt>. *)
    if rt > 64<rt> then 0xFFFFFFFFFFFFFFFFUL
    else BitVector.UnsignedMax rt |> BitVector.ToUInt64

  let private maskingAddr hdl addr =
    let mask = computeJumpTargetMask hdl
    addr &&& mask

  let private addLabel addr idx symb tmp =
    let leader = ProgramPoint (addr, idx)
    let labels = Map.add (addr, symb) leader tmp.LabelPPoints
    let leaders = Set.add leader tmp.Leaders
    { tmp with LabelPPoints = labels; Leaders = leaders }

  let private addAddrLeader addr tmp =
    { tmp with Leaders = Set.add (ProgramPoint (addr, 0)) tmp.Leaders }

  let inline private updateNextEvents tmp evts =
    { tmp with NextEvents = evts }

  /// Since there is an explicit edge to another bbl, we should add events to
  /// parse those new edges.
  let private addExplicitBranchEvents fm addr fn target e tmp =
    (* Do nothing when there is a recursion *)
    if (fm: FunctionMaintainer).Contains (addr=target) then
      CFGEvents.addTailCallEvt fn addr target tmp.NextEvents
      |> updateNextEvents tmp
    else
      let lastLeader = Set.maxElement tmp.Leaders
      CFGEvents.addEdgeEvt fn lastLeader target e tmp.NextEvents
      |> updateNextEvents tmp

  let private collectAux hdl fm addr fn idx tmp stmt isLast =
    match stmt.S with
    | LMark symb -> addLabel addr idx symb tmp
    (* This is the case of "JMP PC". This means, the instruction iterates
       itself. Therefore, the current instruction needs to be considered as a
       new leader. *)
    | InterJmp ({ E = PCVar _ }, InterJmpKind.Base) ->
      addAddrLeader addr tmp
    | InterJmp ({ E = BinOp (BinOpType.ADD, _, { E = PCVar (_) },
                                               { E = Num bv }) },
                InterJmpKind.Base) ->
      let target = (addr + BitVector.ToUInt64 bv) |> maskingAddr hdl
      (* If the ijmp statement is the last one of the corresponding basic block,
         then we know it is used to jump to another bbl. If otherwise, the ijmp
         statement should branch to the current instruction. In such a case, we
         simply consider the target address as a new (intra-bbl) leader. *)
      if isLast then addExplicitBranchEvents fm addr fn target InterJmpEdge tmp
      else addAddrLeader target tmp
    | InterJmp ({ E = Num bv }, InterJmpKind.Base) ->
      let target = BitVector.ToUInt64 bv |> maskingAddr hdl
      if isLast then addExplicitBranchEvents fm addr fn target InterJmpEdge tmp
      else addAddrLeader target tmp
    (* InterCJmp targets are leaders if they are not belonging to last
       instruction of a basic block, i.e. intra-instruction level branch *)
    | InterCJmp (_, { E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                                   { E = Num tBv }) },
                    { E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                                   { E = Num fBv }) }) ->
      let tTarget = (addr + BitVector.ToUInt64 tBv) |> maskingAddr hdl
      let fTarget = (addr + BitVector.ToUInt64 fBv) |> maskingAddr hdl
      if isLast then
        addExplicitBranchEvents fm addr fn tTarget InterCJmpTrueEdge tmp
        |> addExplicitBranchEvents fm addr fn fTarget InterCJmpFalseEdge
      else addAddrLeader tTarget tmp |> addAddrLeader fTarget
    | InterCJmp (_, { E = Num tBv }, { E = Num fBv }) ->
      let tTarget = BitVector.ToUInt64 tBv |> maskingAddr hdl
      let fTarget = BitVector.ToUInt64 fBv |> maskingAddr hdl
      if isLast then
        addExplicitBranchEvents fm addr fn tTarget InterCJmpTrueEdge tmp
        |> addExplicitBranchEvents fm addr fn fTarget InterCJmpFalseEdge
      else addAddrLeader tTarget tmp |> addAddrLeader fTarget
    | InterCJmp (_, { E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                                   { E = Num tBv }) },
                    _) ->
      let tTarget = (addr + BitVector.ToUInt64 tBv) |> maskingAddr hdl
      if isLast then
        addExplicitBranchEvents fm addr fn tTarget InterCJmpTrueEdge tmp
      else addAddrLeader tTarget tmp
    | InterCJmp (_, { E = Num tBv }, _) ->
      let tTarget = BitVector.ToUInt64 tBv |> maskingAddr hdl
      if isLast then
        addExplicitBranchEvents fm addr fn tTarget InterCJmpTrueEdge tmp
      else addAddrLeader tTarget tmp
    | InterCJmp (_, _,
                    { E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                                   { E = Num fBv }) }) ->
      let fTarget = (addr + BitVector.ToUInt64 fBv) |> maskingAddr hdl
      if isLast then
        addExplicitBranchEvents fm addr fn fTarget InterCJmpFalseEdge tmp
      else addAddrLeader fTarget tmp
    | InterCJmp (_, _, { E = Num fBv }) ->
      let fTarget = BitVector.ToUInt64 fBv |> maskingAddr hdl
      if isLast then
        addExplicitBranchEvents fm addr fn fTarget InterCJmpFalseEdge tmp
      else addAddrLeader fTarget tmp
    | _ -> tmp

  let rec private collectLeaders hdl fm addr fn idx isLastIns stmts tmp =
    if idx >= (stmts: Stmt []).Length then tmp
    else
      let isLastStmt = isLastIns && idx = stmts.Length - 1
      let tmp =
        collectAux hdl fm addr fn idx tmp stmts[idx] isLastStmt
      collectLeaders hdl fm addr fn (idx + 1) isLastIns stmts tmp

  let rec private prepareLeaders hdl fm instrs fn tmp =
    match instrs with
    | (insInfo: LiftedInstruction) :: tl ->
      let isLastIns = List.isEmpty tl
      let addr = insInfo.Instruction.Address
      let stmts = insInfo.Stmts
      prepareLeaders hdl fm tl fn
        (collectLeaders hdl fm addr fn 0 isLastIns stmts tmp)
    | [] -> tmp

  let private addIntraEdge src insAddr symb edge tmp =
    let dst = Map.find (insAddr, symb) tmp.LabelPPoints
    let intraEdges = (src, dst, edge) :: tmp.IntraEdges
    { tmp with IntraEdges = intraEdges }

  let private addInterEdge src dstAddr edge tmp =
    let dst = ProgramPoint (dstAddr, 0)
    { tmp with InterEdges = (src, dst, edge) :: tmp.InterEdges }

  let private addExceptionEdgeEvents callSite excTbl fn caller tmp =
    match (excTbl: ExceptionTable).TryFindExceptionTarget callSite with
    | Some target ->
      tmp.NextEvents
      |> CFGEvents.addEdgeEvt fn caller target ExceptionFallThroughEdge
    | None -> tmp.NextEvents

  let private addCallEdgeEvents callSite excTbl fn caller target tmp =
    addExceptionEdgeEvents callSite excTbl fn caller tmp
    |> CFGEvents.addCallEvt fn callSite target
    |> updateNextEvents tmp

  let private addIndirectCallEvents callSite excTbl fn caller tmp =
    addExceptionEdgeEvents callSite excTbl fn caller tmp
    |> CFGEvents.addIndCallEvt fn callSite
    |> updateNextEvents tmp

  /// Add intra-instruction edges.
  let private addEdgesAux hdl fm excTbl fn addr idx leader tmp insInfo isLast =
    let stmt = insInfo.Stmts[idx]
    match stmt.S with
    | LMark _ -> ProgramPoint (addr, idx), tmp
    | Jmp { E = Name symb } ->
      leader, addIntraEdge leader addr symb IntraJmpEdge tmp
    | CJmp (_, { E = Name tSymb }, { E = Name fSymb }) ->
      let tmp =
        addIntraEdge leader addr tSymb IntraCJmpTrueEdge tmp
        |> addIntraEdge leader addr fSymb IntraCJmpFalseEdge
      leader, tmp
    | CJmp (_, { E = Name tSymb }, { E = Undefined _ }) ->
      leader, addIntraEdge leader addr tSymb IntraCJmpTrueEdge tmp
    | CJmp (_, { E = Undefined _ }, { E = Name fSymb }) ->
      leader, addIntraEdge leader addr fSymb IntraCJmpFalseEdge tmp
    | InterJmp ({ E = PCVar _ }, InterJmpKind.Base) ->
      leader, addInterEdge leader addr InterJmpEdge tmp
    (* We have to add an extra inter-block edge only if the statement is placed
       at the middle of a block. *)
    | InterJmp ({ E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                               { E = Num bv }) },
                InterJmpKind.Base) ->
      if isLast then leader, tmp
      else
        let target = (addr + BitVector.ToUInt64 bv) |> maskingAddr hdl
        leader, addInterEdge leader target InterJmpEdge tmp
    | InterJmp ({ E = Num bv }, InterJmpKind.Base) ->
      if isLast then leader, tmp
      else
        let target = BitVector.ToUInt64 bv |> maskingAddr hdl
        leader, addInterEdge leader target InterJmpEdge tmp
    | InterJmp ({ E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                               { E = Num bv }) },
                InterJmpKind.IsCall) ->
      let target = (addr + BitVector.ToUInt64 bv) |> maskingAddr hdl
      let tmp = addCallEdgeEvents addr excTbl fn leader target tmp
      if isLast then leader, tmp
      else leader, addInterEdge leader target InterJmpEdge tmp
    | InterJmp ({ E = Num bv }, InterJmpKind.IsCall) ->
      let target = BitVector.ToUInt64 bv |> maskingAddr hdl
      let tmp = addCallEdgeEvents addr excTbl fn leader target tmp
      if isLast then leader, tmp
      else leader, addInterEdge leader target InterJmpEdge tmp
    | InterJmp ({ E = Var _ }, InterJmpKind.Base)
    | InterJmp ({ E = Load _ }, InterJmpKind.Base) ->
      (fn: RegularFunction).RegisterNewIndJump addr
      leader, tmp
    (* Indirect calls. *)
    | InterJmp (_, InterJmpKind.IsCall) ->
      leader, addIndirectCallEvents addr excTbl fn leader tmp
    (* We have to add an extra inter-block edge only if the statement is placed
       at the middle of a block. *)
    | InterCJmp (_, { E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                                   { E = Num tBv }) },
                    { E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                                   { E = Num fBv }) }) ->
      let tTarget = (addr + BitVector.ToUInt64 tBv) |> maskingAddr hdl
      let fTarget = (addr + BitVector.ToUInt64 fBv) |> maskingAddr hdl
      if isLast then leader, tmp
      else
        let tmp =
          addInterEdge leader tTarget InterCJmpTrueEdge tmp
          |> addInterEdge leader fTarget InterCJmpFalseEdge
        leader, tmp
    | InterCJmp (_, { E = Num tBv }, { E = Num fBv }) ->
      let tTarget = BitVector.ToUInt64 tBv |> maskingAddr hdl
      let fTarget = BitVector.ToUInt64 fBv |> maskingAddr hdl
      if isLast then leader, tmp
      else
        let tmp =
          addInterEdge leader tTarget InterCJmpTrueEdge tmp
          |> addInterEdge leader fTarget InterCJmpFalseEdge
        leader, tmp
    | InterCJmp (_, { E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                                   { E = Num tBv }) },
                    _) ->
      if isLast then leader, tmp
      else
        let tTarget = (addr + BitVector.ToUInt64 tBv) |> maskingAddr hdl
        leader, addInterEdge leader tTarget InterCJmpTrueEdge tmp
    | InterCJmp (_, { E = Num tBv }, _) ->
      if isLast then leader, tmp
      else
        let tTarget = BitVector.ToUInt64 tBv |> maskingAddr hdl
        leader, addInterEdge leader tTarget InterCJmpTrueEdge tmp
    | InterCJmp (_, _,
                    { E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                                   { E = Num fBv }) }) ->
      if isLast then leader, tmp
      else
        let fTarget = (addr + BitVector.ToUInt64 fBv) |> maskingAddr hdl
        leader, addInterEdge leader fTarget InterCJmpFalseEdge tmp
    | InterCJmp (_, _, { E = Num fBv }) ->
      if isLast then leader, tmp
      else
        let fTarget = (addr + BitVector.ToUInt64 fBv) |> maskingAddr hdl
        leader, addInterEdge leader fTarget InterCJmpFalseEdge tmp
    | InterJmp (_, InterJmpKind.IsRet) -> leader, tmp
    (* SideEffects *)
    | SideEffect SysCall ->
      fn.AddSysCallSite addr
      leader, { tmp with HasExplicitTerminator = true }
    | SideEffect _ when insInfo.Instruction.IsExit () ->
      leader, { tmp with HasExplicitTerminator = true }
    (* For EVM. *)
    | InterJmp ({ E = TempVar _ }, _)
    | InterCJmp (_, { E = TempVar _ }, { E = Num _ }) ->
      (fn: RegularFunction).RegisterNewIndJump addr
      leader, tmp
    | _ -> (* Fall-through cases. *)
      (* Inter-instruction fall-through. *)
      if isLast then
        let ftAddr = addr + uint64 insInfo.Instruction.Length
        let tmp =
          if (fm: FunctionMaintainer).Contains ftAddr
            || tmp.HasExplicitTerminator
          then tmp
          else
            tmp.NextEvents
            |> CFGEvents.addEdgeEvt fn leader ftAddr FallThroughEdge
            |> updateNextEvents tmp
        leader, tmp
      else
        let nextPp = ProgramPoint (addr, idx + 1)
        (* Intra-instruction fall-through. *)
        if Set.contains nextPp tmp.Leaders then
          let symb = TempInfo.FindLabelSymbol tmp nextPp
          leader, addIntraEdge leader addr symb FallThroughEdge tmp
        else leader, tmp

  let rec private addEdges hdl fm excTbl fn addr idx isLastIns ins leader t =
    let len = ins.Stmts.Length
    if idx >= len then t
    else
      let isLastStmt = isLastIns && idx = (len - 1)
      let leader, tmp =
        addEdgesAux hdl fm excTbl fn addr idx leader t ins isLastStmt
      addEdges hdl fm excTbl fn addr (idx + 1) isLastIns ins leader tmp

  let private isKnownEdge (src1: ProgramPoint) (dst1: ProgramPoint) tmp =
    tmp.InterEdges
    |> List.exists (fun (src2: ProgramPoint, dst2: ProgramPoint, _) ->
      src2.Address = src1.Address && dst2.Address = dst1.Address)

  let private addFallThrough src dst tmp =
    if Set.contains dst tmp.Leaders
      && not (isKnownEdge src dst tmp) then
      { tmp with
          InterEdges = (src, dst, FallThroughEdge) :: tmp.InterEdges }
    else tmp

  let rec private includeEdges hdl fm excTbl leader instrs fn tmp =
    match instrs with
    | (insInfo: LiftedInstruction) :: ((nextInsInfo :: _) as tl) ->
      let addr = insInfo.Instruction.Address
      let pp = ProgramPoint (addr, 0)
      let nextPp = ProgramPoint (nextInsInfo.Instruction.Address, 0)
      let leader = if Set.contains pp tmp.Leaders then pp else leader
      let tmp = addEdges hdl fm excTbl fn addr 0 false insInfo leader tmp
      let tmp = addFallThrough leader nextPp tmp
      includeEdges hdl fm excTbl leader tl fn tmp
    | [insInfo] ->
      let addr = insInfo.Instruction.Address
      let pp = ProgramPoint (addr, 0)
      let leader = if Set.contains pp tmp.Leaders then pp else leader
      addEdges hdl fm excTbl fn addr 0 true insInfo leader tmp
    | [] -> tmp

  /// Sequentially scan instructions at an IR-level, and find both intra-block
  /// and inter-block edges.
  let private scanBlock hdl fm excTbl instrs fn startAddr evts =
    let leader = ProgramPoint (startAddr, 0)
    let tmp = TempInfo.Init leader evts
    prepareLeaders hdl fm instrs fn tmp
    |> includeEdges hdl fm excTbl leader instrs fn

  let rec private findInsInfo (ppoint: ProgramPoint) instrs =
    match instrs with
    | (info: LiftedInstruction) :: tl ->
      if info.Instruction.Address = ppoint.Address then
        struct (info, instrs)
      else findInsInfo ppoint tl
    | [] -> Utils.impossible ()

  /// Extract ir-bbl part of LiftedInstruction from a single instruction from
  /// given ppoint.
  let private extractInsInfo i (ppoint: ProgramPoint) nextLeader =
    (* If addresses are different, we take everything from ppoint *)
    if ppoint.Address <> (nextLeader: ProgramPoint).Address then
      let nextInsAddr = i.Instruction.Address + uint64 i.Instruction.Length
      let nextPoint = ProgramPoint (nextInsAddr, 0)
      if ppoint.Position > 0 then
        let delta = i.Stmts.Length - ppoint.Position
        let i' = { i with Stmts = Array.sub i.Stmts ppoint.Position delta }
        i', nextPoint
      else i, nextPoint
    else (* Intra-instruction case. *)
      let delta = nextLeader.Position - ppoint.Position
      let i' = { i with Stmts = Array.sub i.Stmts ppoint.Position delta }
      i', nextLeader

  /// This function returns an array of LiftedInstruction for ir-level bbl
  let rec private gatherInsInfos acc instrs ppoint nextLeader =
    if ppoint < nextLeader then
      let struct (info, instrs) = findInsInfo ppoint instrs
      let info, nextPoint = extractInsInfo info ppoint nextLeader
      let acc = info :: acc
      if nextPoint = nextLeader then List.rev acc |> List.toArray
      else gatherInsInfos acc instrs nextPoint nextLeader
    elif ppoint = nextLeader then List.rev acc |> List.toArray
    (* Next point is beyond the next leader's point. This is possible when two
       control flows divide an instruction into two parts. This typically
       happens in obfuscated code. *)
    else Utils.futureFeature ()

  let private createIRBBL fn instrs nextAddr leaders idx leader =
    let nextLeader =
      if idx < (leaders: ProgramPoint []).Length - 1 then leaders[idx + 1]
      else ProgramPoint (nextAddr, 0)
    let instrs = gatherInsInfos [] instrs leader nextLeader
    if Array.isEmpty instrs then ()
    else (fn: RegularFunction).AddVertex (instrs, leader) |> ignore

  let private resetFunctionBoundary (fn: RegularFunction) endAddr =
    if endAddr > fn.MaxAddr then fn.SetBoundary fn.MinAddr endAddr
    else ()

  let private markNoReturn (fn: RegularFunction) instrs =
    let insInfo: LiftedInstruction = instrs |> List.last
    if insInfo.Instruction.IsRET () then fn.NoReturnProperty <- NotNoRet
    else ()

  let private buildVertices instrs nextAddr fn tmp =
    let leaders = Set.toArray tmp.Leaders
    leaders
    |> Array.iteri (createIRBBL fn instrs nextAddr leaders)
    resetFunctionBoundary fn (nextAddr - 1UL)
    markNoReturn fn instrs

  let private buildEdges (fn: RegularFunction) tmp =
    tmp.IntraEdges |> List.iter fn.AddEdge
    tmp.InterEdges |> List.iter fn.AddEdge

  /// Parse basic block info.
  let parseBBLInfo hdl instrs sAddr nextAddr fn fnMaintainer excTbl evts =
    let tmp = scanBlock hdl fnMaintainer excTbl instrs fn sAddr evts
    buildVertices instrs nextAddr fn tmp
    buildEdges fn tmp
    struct (
      { BlkRange = AddrRange (sAddr, nextAddr - 1UL)
        InstrAddrs =
          instrs |> List.map (fun i -> i.Instruction.Address) |> Set.ofList
        IRLeaders = tmp.Leaders
        FunctionEntry = fn.EntryPoint }, tmp.NextEvents
    )

  let initBBLInfo blkRange blkAddrs irLeaders funcEntry =
    { BlkRange = blkRange
      InstrAddrs = blkAddrs |> Set.ofList
      IRLeaders = irLeaders
      FunctionEntry = funcEntry }
