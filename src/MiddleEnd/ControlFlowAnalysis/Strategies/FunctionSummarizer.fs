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

/// Base class for summarizing a function in a lightweight manner. One can
/// extend this class to implement a more sophisticated function summarizer.
type FunctionSummarizer<'FnCtx,
                        'GlCtx when 'FnCtx :> IResettable
                                and 'FnCtx: (new: unit -> 'FnCtx)
                                and 'GlCtx: (new: unit -> 'GlCtx)> () =
  let retrieveStackAdjustment (ins: Instruction) =
    match ins.Immediate () with
    | true, v -> int v
    | false, _ -> 0

  let stackPointerDef (hdl: BinHandle) unwindingAmount =
    match hdl.RegisterFactory.StackPointer with
    | Some sp ->
      let rt = hdl.RegisterFactory.RegIDToRegType sp
      let sp = hdl.RegisterFactory.RegIDToRegExpr sp
      let retAddrSize = RegType.toByteWidth rt |> int64
      let adj = int64 unwindingAmount
      let shiftAmount = BitVector.OfInt64 (retAddrSize + adj) rt
      let e = AST.binop BinOpType.ADD sp (AST.num shiftAmount)
      [| (sp, e) |]
    | None -> [||]

  let toRegExpr (hdl: BinHandle) register =
    Intel.Register.toRegID register
    |> hdl.RegisterFactory.RegIDToRegExpr

  let tryFindLiveRegFromGetPCThunk (hdl: BinHandle) (addr: Addr) =
    match hdl.ReadUInt (addr, 4) with
    | 0xc324048bUL -> Some (toRegExpr hdl Intel.Register.EAX)
    | 0xc3241c8bUL -> Some (toRegExpr hdl Intel.Register.EBX)
    | 0xc3240c8bUL -> Some (toRegExpr hdl Intel.Register.ECX)
    | 0xc324148bUL -> Some (toRegExpr hdl Intel.Register.EDX)
    | 0xc324348bUL -> Some (toRegExpr hdl Intel.Register.ESI)
    | 0xc3243c8bUL -> Some (toRegExpr hdl Intel.Register.EDI)
    | 0xc3242c8bUL -> Some (toRegExpr hdl Intel.Register.EBP)
    | _ -> None

  let genFreshStackVarExpr hdl =
    let rt = (hdl: BinHandle).File.ISA.WordSize |> WordSize.toRegType
    let spId = hdl.RegisterFactory.StackPointer.Value
    let sp = hdl.RegisterFactory.RegIDToRegExpr spId
    AST.load Endian.Little rt sp (* [rsp] *)

  let initializeLiveVarMap (ctx: CFGBuildingContext<_, _>) =
    match ctx.BinHandle.File.ISA.Arch with
    | Architecture.IntelX86 ->
      let hdl = ctx.BinHandle
      match tryFindLiveRegFromGetPCThunk hdl ctx.FunctionAddress with
      | Some var ->
        let e = genFreshStackVarExpr hdl
        [| (var, e) |]
      | None -> [||]
    | _ -> [||]

  let computeLiveVars (ctx: CFGBuildingContext<_, _>) unwindingAmount =
    let hdl = ctx.BinHandle
    if ctx.IsExternal then
      let retReg =
        CallingConvention.returnRegister hdl
        |> hdl.RegisterFactory.RegIDToRegExpr
      let rt = hdl.File.ISA.WordSize |> WordSize.toRegType
      let e = AST.undef rt "ret"
      [| (retReg, e)
         yield! stackPointerDef hdl unwindingAmount |]
    else
      [| yield! initializeLiveVarMap ctx
         yield! stackPointerDef hdl unwindingAmount |]

  /// Compute how many bytes are unwound by this function.
  abstract ComputeUnwindingAmount:
    ctx: CFGBuildingContext<'FnCtx, 'GlCtx> -> int option

  /// This is the simplistic way of counting the unwinding amount. Assuming that
  /// "ret NN" instructions are used, compute how many bytes are unwound.
  default _.ComputeUnwindingAmount ctx =
    ctx.CFG.Exits
    |> Array.fold (fun acc v ->
      let vData = v.VData :> ILowUIRBasicBlock
      if Option.isSome acc || vData.IsAbstract then acc
      else
        let ins = vData.LastInstruction
        if ins.IsRET () then retrieveStackAdjustment ins |> Some
        else acc
    ) None

  /// Summarize the function using LowUIR.
  abstract Summarize:
       ctx: CFGBuildingContext<'FnCtx, 'GlCtx>
     * Instruction
     * unwindingAmount: int
    -> Rundown<LowUIR.Stmt>

  /// Simply over-approximate the function semantics. Particularly, we are
  /// interested in several well-known "getpc" functions for x86.
  default _.Summarize (ctx, callInstruction, unwindingAmount) =
    let returnAddress = callInstruction.Address + uint64 callInstruction.Length
    let stmts = (* For abstraction, we check which var can be defined. *)
      computeLiveVars ctx unwindingAmount
      |> Array.map (fun (dst, src) -> AST.put dst src)
    let regType = ctx.BinHandle.File.ISA.WordSize |> WordSize.toRegType
    let fallThrough = AST.num <| BitVector.OfUInt64 returnAddress regType
    let jmpToFallThrough = AST.interjmp fallThrough InterJmpKind.Base
    Array.append stmts [| jmpToFallThrough |]

  interface IFunctionSummarizable<'FnCtx, 'GlCtx> with
    member __.Summarize (ctx: CFGBuildingContext<'FnCtx, 'GlCtx>, ins) =
      let unwindingBytes =
        if ctx.IsExternal then None else __.ComputeUnwindingAmount ctx
      let unwindingAmount = Option.defaultValue 0 unwindingBytes
      let ssaRundown = __.Summarize (ctx, ins, unwindingAmount)
      FunctionAbstraction (ctx.FunctionAddress,
                           unwindingBytes,
                           ssaRundown,
                           ctx.IsExternal,
                           ctx.NonReturningStatus)

    member __.SummarizeUnknown (ctx, callIns) =
      let returnAddress = callIns.Address + uint64 callIns.Length
      let wordSize = ctx.BinHandle.File.ISA.WordSize
      let regType = wordSize |> WordSize.toRegType
      let fallThrough = AST.num <| BitVector.OfUInt64 returnAddress regType
      let jmpToFallThrough = AST.interjmp fallThrough InterJmpKind.Base
      let stmts =
        stackPointerDef ctx.BinHandle 0
        |> Array.map (fun (dst, src) -> AST.put dst src)
      let ssaRundown = [| yield! stmts; yield jmpToFallThrough |]
      FunctionAbstraction (0UL, None, ssaRundown, false, NotNoRet)
