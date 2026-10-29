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

namespace B2R2.MiddleEnd.ControlFlowAnalysis.Strategies

open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Represents a base class for summarizing a function in a lightweight manner.
/// One can extend this class to implement a more sophisticated function
/// summarizer.
type FunctionSummarizer<'FnCtx, 'GlCtx>() =
  let retrieveStackAdjustment (ins: IInstruction) =
    match ins.Immediate() with
    | true, v -> int v
    | false, _ -> 0

  let intReturnValueDef (hdl: BinHandle) =
    let retReg =
      hdl.Conventions.Calling.IntReturnRegister
      |> hdl.RegisterFactory.GetRegVar
    let rt = hdl.ISA.WordSize |> WordSize.toRegType
    let e = AST.undef rt "ret"
    [| (retReg, e) |]

  /// Collects the definitions that cover the given return value register. A
  /// concatenated register variable, such as ST0 or XMM0, cannot be a
  /// definition target, so we define each of the chunks it concatenates.
  let rec returnValueDefs acc e =
    match e with
    | BinOp(Op = BinOpType.CONCAT; Left = hi; Right = lo) ->
      returnValueDefs (returnValueDefs acc hi) lo
    | _ ->
      (e, AST.undef (Expr.typeOf e) "ret") :: acc

  let floatReturnValueDef (hdl: BinHandle) =
    hdl.Conventions.Calling.FloatReturnRegister
    |> hdl.RegisterFactory.GetRegVar
    |> returnValueDefs []
    |> List.toArray

  /// Makes the definitions that invalidate the given registers, which are the
  /// caller-saved registers that a callee may modify.
  let callerSavedValueDefs (hdl: BinHandle) (clobbered: Set<RegisterID>) =
    let regFactory = hdl.RegisterFactory
    [| for rid in clobbered do
        let regVar = regFactory.GetRegVar rid
        let rt = regFactory.GetRegType rid
        regVar, AST.undef rt "caller-saved" |]

  let stackPointerDef (hdl: BinHandle) unwindingAmount =
    match hdl.RegisterFactory.StackPointer with
    | Some sp ->
      let rt = hdl.RegisterFactory.GetRegType sp
      let sp = hdl.RegisterFactory.GetRegVar sp
      let retAddrSize = RegType.toByteWidth rt |> int64
      let adj = int64 unwindingAmount
      let shiftAmount = BitVector(retAddrSize + adj, rt)
      let e = AST.binop BinOpType.ADD sp (AST.num shiftAmount)
      [| (sp, e) |]
    | None ->
      [||]

  let toRegExpr (hdl: BinHandle) register =
    Intel.Register.toRegID register
    |> hdl.RegisterFactory.GetRegVar

  let tryFindLiveRegFromGetPCThunk (hdl: BinHandle) (addr: Addr) =
    match hdl.ReadUInt(addr, 4) with
    | 0xc324048bUL -> Some(toRegExpr hdl Intel.Register.EAX)
    | 0xc3241c8bUL -> Some(toRegExpr hdl Intel.Register.EBX)
    | 0xc3240c8bUL -> Some(toRegExpr hdl Intel.Register.ECX)
    | 0xc324148bUL -> Some(toRegExpr hdl Intel.Register.EDX)
    | 0xc324348bUL -> Some(toRegExpr hdl Intel.Register.ESI)
    | 0xc3243c8bUL -> Some(toRegExpr hdl Intel.Register.EDI)
    | 0xc3242c8bUL -> Some(toRegExpr hdl Intel.Register.EBP)
    | _ -> None

  let genFreshStackVarExpr hdl =
    let rt = (hdl: BinHandle).ISA.WordSize |> WordSize.toRegType
    let spId = hdl.RegisterFactory.StackPointer.Value
    let sp = hdl.RegisterFactory.GetRegVar spId
    AST.load Endian.Little rt sp (* [rsp] *)

  let initializeLiveVarMap hdl funcAddr =
    match (hdl: BinHandle).ISA with
    | X86 ->
      match tryFindLiveRegFromGetPCThunk hdl funcAddr with
      | Some var ->
        let e = genFreshStackVarExpr hdl
        [| (var, e) |]
      | None ->
        [||]
    | _ ->
      [||]

  let computeLiveDefs hdl callee calleeInfo =
    let unwindingAmount, clobbered = calleeInfo.Unwinding, calleeInfo.Clobbered
    if calleeInfo.IsExternal then
      [| yield! intReturnValueDef hdl
         yield! floatReturnValueDef hdl
         yield! callerSavedValueDefs hdl clobbered
         yield! stackPointerDef hdl unwindingAmount |]
    else
      let liveVarDefs = initializeLiveVarMap hdl callee
      [| if Array.isEmpty liveVarDefs then
           yield! intReturnValueDef hdl
           yield! floatReturnValueDef hdl
           yield! callerSavedValueDefs hdl clobbered
         else
           yield! liveVarDefs
         yield! stackPointerDef hdl unwindingAmount |]

  /// Computes how many bytes are unwound by this function.
  abstract ComputeUnwindingAmount:
    ctx: CFGBuildingContext<'FnCtx, 'GlCtx> -> int

  /// Summarizes the function at `callee` using LowUIR, which the function of
  /// the given context calls with the given instruction.
  abstract Summarize:
       ctx: CFGBuildingContext<'FnCtx, 'GlCtx>
     * callee: Addr
     * calleeInfo: CalleeInfo
     * IInstruction
    -> Rundown<LowUIR.Stmt>

  /// Computes how many bytes are unwound in a simplistic way, assuming that
  /// "ret NN" instructions are used.
  default _.ComputeUnwindingAmount ctx =
    let mutable amount = 0
    let exits = ctx.CFG.Exits
    let reachableExits =
      exits
      |> Seq.filter (fun v ->
        not <| ctx.GapAnalysisVertices.Contains v.VData.Internals.PPoint)
    for exitV in reachableExits do
      let vData = exitV.VData :> ILowUIRBasicBlock
      if vData.IsAbstract then
        ()
      else
        let ins = vData.LastInstruction
        if ins.IsRET then
          let newAmount = retrieveStackAdjustment ins
          assert (amount <= newAmount) (* bad case *)
          amount <- newAmount
        else
          ()
    amount

  /// Simply over-approximates the function semantics. Particularly, we are
  /// interested in several well-known "getpc" functions for x86.
  default _.Summarize(ctx, callee, calleeInfo, callInstruction) =
    let returnAddress = callInstruction.Address + uint64 callInstruction.Length
    let stmts = (* For abstraction, we check which var can be defined. *)
      computeLiveDefs ctx.BinHandle callee calleeInfo
      |> Array.map (fun (dst, src) -> AST.put dst src)
    let regType = ctx.BinHandle.ISA.WordSize |> WordSize.toRegType
    let fallThrough = AST.num <| BitVector(returnAddress, regType)
    let jmpToFallThrough = AST.interjmp fallThrough InterJmpKind.Base
    Array.append stmts [| jmpToFallThrough |]

  interface IFunctionSummarizable<'FnCtx, 'GlCtx> with
    member this.Summarize(ctx, callee, calleeInfo, ins) =
      FunctionSummary(callee,
                      calleeInfo.Unwinding,
                      this.Summarize(ctx, callee, calleeInfo, ins),
                      calleeInfo.IsExternal,
                      calleeInfo.Status)

    member _.MakeUnknownFunctionSummary(hdl, callIns, unwindingBytes) =
      let returnAddress = callIns.Address + uint64 callIns.Length
      let wordSize = hdl.ISA.WordSize
      let regType = wordSize |> WordSize.toRegType
      let fallThrough = AST.num <| BitVector(returnAddress, regType)
      let jmpToFallThrough = AST.interjmp fallThrough InterJmpKind.Base
      let stmts =
        stackPointerDef hdl unwindingBytes
        |> Array.map (fun (dst, src) -> AST.put dst src)
      let ssaRundown = [| yield! stmts; yield jmpToFallThrough |]
      FunctionSummary(0UL, unwindingBytes, ssaRundown, false, NotNoRet)

    member this.ComputeUnwindingAmount ctx = this.ComputeUnwindingAmount ctx
