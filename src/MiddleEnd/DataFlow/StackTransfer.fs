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

module B2R2.MiddleEnd.DataFlow.StackTransfer

open B2R2
open B2R2.BinIR
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.Intel
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.ELF
open B2R2.FrontEnd.BinInterface
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.BinEssence
open B2R2.MiddleEnd.Lens
open B2R2.BinIR.SSA

let evalBinOp op c1 c2 =
  match op with
  | BinOpType.ADD -> StackValue.add c1 c2
  | BinOpType.SUB -> StackValue.sub c1 c2
  | BinOpType.AND -> StackValue.``and`` c1 c2
  | _ -> NotAConst

let isStackRelatedRegister (st: CPState<StackValue>) regid =
  st.BinHandle.RegisterBay.IsStackPointer regid ||
    st.BinHandle.RegisterBay.IsFramePointer regid

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

let evalReturn ess cfg (st: CPState<StackValue>) blk addr v =
  match v.Kind with
  | RegVar (rt, rid, _) ->
    let hdl = st.BinHandle
    if isStackRelatedRegister st rid then
      let c = CPState.findReg st v
      let wordByte = RegType.toByteWidth rt |> uint64
      let adjust = computeStackAdjust ess cfg blk addr c
      let wordSize = Const (BitVector.ofUInt64 (wordByte + adjust) rt)
      if hdl.RegisterBay.IsStackPointer rid then
        evalBinOp BinOpType.ADD c wordSize
      else c
    else NotAConst
  | _ -> Utils.impossible ()

let rec evalExpr ess cfg st blk = function
  | Num bv -> Const bv
  | Var v -> CPState.findReg st v
  | Nil -> NotAConst
  | Load _ -> NotAConst
  | UnOp _ -> NotAConst
  | FuncName _ -> NotAConst
  | BinOp (op, _, e1, e2) ->
    let c1 = evalExpr ess cfg st blk e1
    let c2 = evalExpr ess cfg st blk e2
    evalBinOp op c1 c2
  | RelOp _ -> NotAConst
  | Ite _ -> NotAConst
  | Cast _ -> NotAConst
  | Extract _ -> NotAConst
  | Undefined _ -> NotAConst
  | ReturnVal (addr, _, v) -> evalReturn ess cfg st blk addr v
  | _ -> Utils.impossible ()

let inline updateConst st r v =
  if not (st.RegState.ContainsKey r) then
    st.RegState.[r] <- v
    st.SSAWorkList.Push r
  elif st.RegState.[r] = v then ()
  elif st.GoingUp st.RegState.[r] v then ()
  else
    st.RegState.[r] <- st.Meet st.RegState.[r] v
    st.SSAWorkList.Push r

let evalDef ess cfg (st: CPState<StackValue>) blk v e =
  match v.Kind with
  | RegVar (_, regid, _) when isStackRelatedRegister st regid ->
    evalExpr ess cfg st blk e |> updateConst st v
  | RegVar _ -> updateConst st v NotAConst
  | TempVar _ -> evalExpr ess cfg st blk e |> updateConst st v
  | MemVar -> ()
  | PCVar _ -> ()

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
    | MemVar -> ()
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

let evalInterJmp cfg st blk =
  (fun (succ: Vertex<SSABBlock>) ->
    DiGraph.findEdgeData cfg blk succ <> CallFallThroughEdge)
  |> markSuccessorsConditionally cfg st blk

let evalJmp cfg st blk = function
  | InterJmp _ -> evalInterJmp cfg st blk
  | _ -> markAllSuccessors cfg st blk

let evalStmt ess cfg st blk _ppoint = function
  | Def (v, e) -> evalDef ess cfg st blk v e
  | Phi (v, ns) -> evalPhi cfg st blk v ns
  | Jmp jmpTy -> evalJmp cfg st blk jmpTy
  | LMark _ | SideEffect _ -> ()
