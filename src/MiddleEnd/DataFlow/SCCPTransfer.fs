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

module B2R2.MiddleEnd.DataFlow.SCCPTransfer

open B2R2
open B2R2.FrontEnd.BinInterface
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.Intel
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.ELF
open B2R2.BinIR
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.BinEssence
open B2R2.MiddleEnd.Lens
open B2R2.BinIR.SSA

let private isGetPCThunkCode = function
  | 0xc324048bUL | 0xc3241c8bUL | 0xc3240c8bUL | 0xc324148bUL
  | 0xc324348bUL | 0xc3243c8bUL | 0xc3242c8bUL -> true
  | _ -> false

/// This is a heuristic to discover __x86.get_pc_thunk- family functions.
/// 1. If a function name symbol exists and its name matches, then we know it is
/// __x86.get_pc_thunk- family
/// 2. But there are some cases we don't have symbols for them. In such cases,
/// we directly compare first 4 bytes of byte code. Because __x86.get_pc_thunk-
/// family only has 4 bytes for its function body and their values are fixed.
let private isGetPCThunk hdl addr =
  if addr = 0UL then false
  else
    match hdl.FileInfo.TryFindFunctionSymbolName addr with
    | Ok name -> name.StartsWith "__x86.get_pc_thunk"
    | Error _ -> BinHandle.ReadUInt (hdl, addr, 4) |> isGetPCThunkCode

let evalLoad st m rt addr =
  match addr with
  | Const addr -> BitVector.toUInt64 addr |> CPState.findMem st m rt
  | _ -> NotAConst

let evalUnOp op c =
  match op with
  | UnOpType.NEG -> SCCPValue.neg c
  | UnOpType.NOT -> SCCPValue.not c
  | _ -> NotAConst

let evalBinOp op c1 c2 =
  match op with
  | BinOpType.ADD -> SCCPValue.add c1 c2
  | BinOpType.SUB -> SCCPValue.sub c1 c2
  | BinOpType.MUL -> SCCPValue.mul c1 c2
  | BinOpType.DIV -> SCCPValue.div c1 c2
  | BinOpType.SDIV -> SCCPValue.sdiv c1 c2
  | BinOpType.MOD -> SCCPValue.``mod`` c1 c2
  | BinOpType.SMOD -> SCCPValue.smod c1 c2
  | BinOpType.SHL -> SCCPValue.shl c1 c2
  | BinOpType.SHR -> SCCPValue.shr c1 c2
  | BinOpType.SAR -> SCCPValue.sar c1 c2
  | BinOpType.AND -> SCCPValue.``and`` c1 c2
  | BinOpType.OR -> SCCPValue.``or`` c1 c2
  | BinOpType.XOR -> SCCPValue.xor c1 c2
  | BinOpType.CONCAT -> SCCPValue.concat c1 c2
  | _ -> NotAConst

let evalRelOp op c1 c2 =
  match op with
  | RelOpType.EQ -> SCCPValue.eq c1 c2
  | RelOpType.NEQ -> SCCPValue.neq c1 c2
  | RelOpType.GT -> SCCPValue.gt c1 c2
  | RelOpType.GE -> SCCPValue.ge c1 c2
  | RelOpType.SGT -> SCCPValue.sgt c1 c2
  | RelOpType.SGE -> SCCPValue.sge c1 c2
  | RelOpType.LT -> SCCPValue.lt c1 c2
  | RelOpType.LE -> SCCPValue.le c1 c2
  | RelOpType.SLT -> SCCPValue.slt c1 c2
  | RelOpType.SLE -> SCCPValue.sle c1 c2
  | _ -> NotAConst

let evalCast op rt c =
  match op with
  | CastKind.SignExt -> SCCPValue.signExt rt c
  | CastKind.ZeroExt -> SCCPValue.zeroExt rt c
  | _ -> NotAConst

let checkStackAdjustFromIns ess acc (ins: Instruction) =
  match ess.BinHandle.ISA.Arch with
  | Arch.IntelX86 ->
    let ins = ins :?> IntelInstruction
    if ins.IsRET () then
      match ins.Info.Opcode with
      | Opcode.RETNearImm ->
        match ins.Info.Operands with
        | OneOperand (OprImm n) -> uint64 n
        | _ -> acc
      | _ -> acc
    else acc
  | _ -> acc

let computeStackAdjustFromTargetFunction (ess: BinEssence) (entry: Addr) =
  if ess.CalleeMap.Contains entry then
    let ircfg, _ = ess.GetFunctionCFG (entry, false) |> Result.get
    DiGraph.getExits ircfg
    |> List.fold (fun acc v ->
      if v.VData.IsFakeBlock () then acc
      else
        let ins = v.VData.LastInstruction
        checkStackAdjustFromIns ess acc ins) 0UL
  else 0UL

let findStackOffset hdl tbl addr =
  match Map.tryFind addr tbl with
  | None -> None
  | Some entry ->
    match entry.CanonicalFrameAddress with
    | RegPlusOffset (rid, n) ->
      if hdl.RegisterBay.IsStackPointer rid then Some n
      else None
    | _ -> None

let computeStackAdjustFromUnwindingTable ess cfg (blk: Vertex<SSABBlock>) tbl c =
  let caller =
    DiGraph.getPreds cfg blk
    |> List.find (fun p ->
      let e = DiGraph.findEdgeData cfg p blk
      e = CallEdge || e = IndirectCallEdge)
  let ftAddr = caller.VData.Range.Max
  let hdl = ess.BinHandle
  match c, findStackOffset hdl tbl ftAddr with
  | NotAConst, _ -> 0UL
  | Const bv, Some n -> 0x80000000UL - uint64 n - BitVector.toUInt64 bv
  | _ -> 0UL

let isNoReturn ess cfg blk entry =
  match Map.tryFind entry ess.NoReturnInfo.NoReturnFuncs with
  | None -> false
  | Some UnconditionalNoRet -> true
  | Some (ConditionalNoRet _) -> DiGraph.getSuccs cfg blk |> List.length = 0

let computeStackAdjust (ess: BinEssence) cfg blk entry c =
  if isNoReturn ess cfg blk entry then 0UL
  else
    let fi = ess.BinHandle.FileInfo
    match fi.FileFormat with
    | FileFormat.ELFBinary ->
      let elf = (fi :?> ELFFileInfo).ELF
      if Map.isEmpty elf.UnwindingTbl then
        computeStackAdjustFromTargetFunction ess entry
      else computeStackAdjustFromUnwindingTable ess cfg blk elf.UnwindingTbl c
    | _ -> computeStackAdjustFromTargetFunction ess entry

let evalReturn ess cfg (st: CPState<SCCPValue>) blk addr ret v =
  match v.Kind with
  | RegVar (rt, rid, _) ->
    let hdl = st.BinHandle
    if hdl.RegisterBay.IsStackPointer rid then
      let c = CPState.findReg st v
      let wordByte = RegType.toByteWidth rt |> uint64
      let adjust = computeStackAdjust ess cfg blk addr c
      let wordSize = Const (BitVector.ofUInt64 (wordByte + adjust) rt)
      evalBinOp BinOpType.ADD c wordSize
    elif isGetPCThunk hdl addr then
      Pointer (BitVector.ofUInt64 ret rt)
    elif CallingConvention.isNonVolatile hdl rid then
      CPState.findReg st v
    else NotAConst
  | _ -> Utils.impossible ()

let rec evalExpr ess cfg st blk = function
  | Num bv -> Const bv
  | Var v -> CPState.findReg st v
  | Nil -> NotAConst
  | Load (m, rt, addr) -> evalExpr ess cfg st blk addr |> evalLoad st m rt
  | UnOp (op, _, e) -> evalExpr ess cfg st blk e |> evalUnOp op
  | FuncName _ -> NotAConst
  | BinOp (op, _, e1, e2) ->
    let c1 = evalExpr ess cfg st blk e1
    let c2 = evalExpr ess cfg st blk e2
    evalBinOp op c1 c2
  | RelOp (op, _, e1, e2) ->
    let c1 = evalExpr ess cfg st blk e1
    let c2 = evalExpr ess cfg st blk e2
    evalRelOp op c1 c2
  | Ite (e1, _, e2, e3) ->
    let c1 = evalExpr ess cfg st blk e1
    let c2 = evalExpr ess cfg st blk e2
    let c3 = evalExpr ess cfg st blk e3
    SCCPValue.ite c1 c2 c3
  | Cast (op, rt, e) ->
    let c = evalExpr ess cfg st blk e
    evalCast op rt c
  | Extract (e, rt, pos) ->
    let c = evalExpr ess cfg st blk e
    SCCPValue.extract c rt pos
  | Undefined _ -> NotAConst
  | ReturnVal (addr, ret, v) ->
    evalReturn ess cfg st blk addr ret v
  | _ -> Utils.impossible ()

let invalidateValuesWithFreshMemory st mDst =
  let dstid = mDst.Identifier
  let mem, updated = st.MemState.[dstid]
  let mem, needPush =
    mem
    |> Map.fold (fun (mem, needPush) addr v ->
      match v with
      | Pointer _ | NotAConst -> Map.add addr v mem, needPush
      | _ -> Map.add addr NotAConst mem, true) (mem, false)
  st.MemState.[dstid] <- (mem, updated)
  if needPush then st.SSAWorkList.Push mDst

let invalidateValuesWithDefinedMemory oldMem st mDst =
  let dstid = mDst.Identifier
  let mem, updated = st.MemState.[dstid]
  let mem, updated, needPush =
    mem
    |> Map.fold (fun (mem, updated, needPush) addr v ->
      match v, Map.tryFind addr oldMem with
      | Pointer p1, Some (Pointer p2) when p1 = p2 ->
        Map.add addr v mem, updated, needPush
      | Pointer _, Some (Pointer _) ->
        Map.add addr v mem, Set.add addr updated, true
      | Pointer _, None ->
        Map.add addr v mem, Set.add addr updated, true
      | NotAConst, Some NotAConst ->
        Map.add addr v mem, updated, needPush
      | NotAConst, None ->
        Map.add addr v mem, Set.add addr updated, true
      | _, Some NotAConst ->
        Map.add addr NotAConst mem, updated, needPush
      | _, _ ->
        Map.add addr NotAConst mem, Set.add addr updated, true
      ) (mem, updated, false)
  st.MemState.[dstid] <- (mem, updated)
  if needPush then st.SSAWorkList.Push mDst

let evalMemDef ess cfg st blk mDst e =
  let dstid = mDst.Identifier
  match e with
  | Store (mSrc, rt, addr, v) ->
    let c = evalExpr ess cfg st blk v
    let addr = evalExpr ess cfg st blk addr
    let oldMem = st.MemState.TryGetValue dstid |> Utils.tupleToOpt
    CPState.copyMem st dstid mSrc.Identifier
    match addr with
    | Const addr ->
      let addr = BitVector.toUInt64 addr
      match oldMem with
      | Some (oldMem, _) -> CPState.storeToDefinedMem oldMem st mDst rt addr c
      | None -> CPState.storeToFreshMem st mDst rt addr c
    | _ ->
      if st.MemState.[dstid] |> snd |> Set.isEmpty |> not then
        st.SSAWorkList.Push mDst
  | ReturnVal (_, _, mSrc) ->
    let oldMem = st.MemState.TryGetValue dstid |> Utils.tupleToOpt
    CPState.copyMem st dstid mSrc.Identifier
    match oldMem with
    | Some (oldMem, _) -> invalidateValuesWithDefinedMemory oldMem st mDst
    | None -> invalidateValuesWithFreshMemory st mDst
  | _ ->  Utils.impossible ()

let inline updateConst st r v =
  if not (st.RegState.ContainsKey r) then
    st.RegState.[r] <- v
    st.SSAWorkList.Push r
  elif st.RegState.[r] = v then ()
  elif st.GoingUp st.RegState.[r] v then ()
  else
    st.RegState.[r] <- st.Meet st.RegState.[r] v
    st.SSAWorkList.Push r

let loadPointerToReg hdl (blk: Vertex<SSABBlock>) addr =
  let info =
    blk.VData.InsInfos
    |> Array.find (fun (i: InstructionInfo) -> i.Instruction.Address = addr)
  let ins = info.Instruction
  match hdl.FileInfo.ISA.Arch with
  | Arch.IntelX64 ->
    match (ins :?> IntelInstruction).Info.Operands with
    | TwoOperands (_, OprMem (Some reg, None, Some _, _)) -> reg = Register.RIP
    | _ -> false
  | Arch.IntelX86 ->
    match (ins :?> IntelInstruction).Info.Operands with
    | TwoOperands (_, OprMem (None, None, Some _, _)) -> true
    | _ -> false
  | _ -> false

let evalDef ess cfg (st: CPState<SCCPValue>) blk (ppoint: ProgramPoint) v e =
  match v.Kind, e with
  | RegVar _, Num _ when loadPointerToReg st.BinHandle blk ppoint.Address ->
    match evalExpr ess cfg st blk e with
    | Const c -> Pointer c
    | c -> c
    |> updateConst st v
  | RegVar _, _ | TempVar _, _ -> evalExpr ess cfg st blk e |> updateConst st v
  | MemVar, _ -> evalMemDef ess cfg st blk v e
  | PCVar _, _ -> ()

let executableSources cfg st (blk: Vertex<_>) srcIDs =
  srcIDs
  |> Array.mapi (fun i srcID ->
    let p = DiGraph.getPreds cfg blk |> List.item i
    if not <| CPState.isExecuted st (p.GetID ()) (blk.GetID ()) then None
    else Some srcID)
  |> Array.choose id

let evalPhi cfg st blk dst srcIDs =
  match executableSources cfg st blk srcIDs with
  | [||] -> ()
  | executableSrcIDs ->
    match dst.Kind with
    | RegVar _ | TempVar _ ->
      executableSrcIDs
      |> Array.map (fun i ->
        { dst with Identifier = i } |> CPState.tryFindReg st)
      |> Array.choose id
      |> Array.reduce st.Meet
      |> fun merged -> updateConst st dst merged
    | MemVar ->
      let dstid = dst.Identifier
      let oldMem = st.MemState.TryGetValue dstid |> Utils.tupleToOpt
      CPState.mergeMemWithoutMergePoints st oldMem dst executableSrcIDs
    | PCVar _ -> ()

let markAllSuccessors cfg st (blk: Vertex<SSABBlock>) =
  let myid = blk.GetID ()
  DiGraph.getSuccs cfg blk
  |> List.iter (fun succ ->
    let succid = succ.GetID ()
    CPState.markExecutable st myid succid)

let markSuccessorsConditionally cfg st (blk: Vertex<SSABBlock>) cond =
  let myid = blk.GetID ()
  DiGraph.getSuccs cfg blk
  |> List.iter (fun succ ->
    if cond succ then
      let succid = succ.GetID ()
      CPState.markExecutable st myid succid
    else ())

let evalIntraCJmp cfg st blk cond trueLbl falseLbl =
  match cond with
  | Const bv ->
    (fun (succ: Vertex<SSABBlock>) ->
      let target = if BitVector.isTrue bv then trueLbl else falseLbl
      match succ.VData.SSAStmtInfos.[0] with
      | _, LMark lbl -> lbl = target
      | _ -> false)
    |> markSuccessorsConditionally cfg st blk
  | _ -> markAllSuccessors cfg st blk

let evalInterJmp cfg st blk = function
  | Num _ ->
    (fun (succ: Vertex<SSABBlock>) ->
      DiGraph.findEdgeData cfg blk succ <> CallFallThroughEdge)
    |> markSuccessorsConditionally cfg st blk
  | _ ->
    let insInfos = blk.VData.InsInfos
    if insInfos.[Array.length insInfos - 1].Instruction.IsCall () then
      (fun (succ: Vertex<SSABBlock>) ->
        succ.VData.PPoint |> ProgramPoint.IsFake)
      |> markSuccessorsConditionally cfg st blk
    else markAllSuccessors cfg st blk

let evalInterCJmp cfg st blk cond trueExpr falseExpr =
  match cond, trueExpr, falseExpr with
  | Const bv, Num trueAddr, Num falseAddr ->
    (fun (succ: Vertex<SSABBlock>) ->
      let target = if BitVector.isTrue bv then trueAddr else falseAddr
      succ.VData.PPoint.Address = BitVector.toUInt64 target)
    |> markSuccessorsConditionally cfg st blk
  | Const bv, Var _, Num falseAddr ->
    (fun (succ: Vertex<SSABBlock>) ->
      if BitVector.isTrue bv then
        succ.VData.PPoint.Address <> BitVector.toUInt64 falseAddr
      else succ.VData.PPoint.Address = BitVector.toUInt64 falseAddr)
    |> markSuccessorsConditionally cfg st blk
  | Const bv, Num trueAddr, Var _ ->
    (fun (succ: Vertex<SSABBlock>) ->
      if BitVector.isTrue bv then
        succ.VData.PPoint.Address = BitVector.toUInt64 trueAddr
      else succ.VData.PPoint.Address <> BitVector.toUInt64 trueAddr)
    |> markSuccessorsConditionally cfg st blk
  | _ -> markAllSuccessors cfg st blk

let evalJmp ess cfg st blk = function
  | IntraJmp _ -> markAllSuccessors cfg st blk
  | IntraCJmp (cond, trueLbl, falseLbl) ->
    let c = evalExpr ess cfg st blk cond
    evalIntraCJmp cfg st blk c trueLbl falseLbl
  | InterJmp expr -> evalInterJmp cfg st blk expr
  | InterCJmp (cond, trueExpr, falseExpr) ->
    let c = evalExpr ess cfg st blk cond
    evalInterCJmp cfg st blk c trueExpr falseExpr

let evalStmt ess cfg st blk ppoint = function
  | Def (v, e) -> evalDef ess cfg st blk ppoint v e
  | Phi (v, ns) -> evalPhi cfg st blk v ns
  | Jmp jmpTy -> evalJmp ess cfg st blk jmpTy
  | LMark _ | SideEffect _ -> ()
