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
      let rt = hdl.RegisterFactory.GetRegType sp
      let sp = hdl.RegisterFactory.GetRegVar sp
      let retAddrSize = RegType.toByteWidth rt |> int64
      let adj = int64 unwindingAmount
      let shiftAmount = BitVector.OfInt64 (retAddrSize + adj) rt
      let e = AST.binop BinOpType.ADD sp (AST.num shiftAmount)
      [| (sp, e) |]
    | None -> [||]

  let toRegExpr (hdl: BinHandle) register =
    Intel.Register.toRegID register
    |> hdl.RegisterFactory.GetRegVar

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
    let sp = hdl.RegisterFactory.GetRegVar spId
    AST.load Endian.Little rt sp (* [rsp] *)

  let initializeLiveVarMap hdl funcAddr =
    match (hdl: BinHandle).File.ISA.Arch with
    | Architecture.IntelX86 ->
      match tryFindLiveRegFromGetPCThunk hdl funcAddr with
      | Some var ->
        let e = genFreshStackVarExpr hdl
        [| (var, e) |]
      | None -> [||]
    | _ -> [||]

  let computeLiveDefs ctx unwindingAmount =
    let hdl = ctx.BinHandle
    if ctx.IsExternal then
      let retReg =
        CallingConvention.returnRegister hdl
        |> hdl.RegisterFactory.GetRegVar
      let rt = hdl.File.ISA.WordSize |> WordSize.toRegType
      let e = AST.undef rt "ret"
      [| (retReg, e)
         yield! stackPointerDef hdl unwindingAmount |]
    else
      [| yield! initializeLiveVarMap hdl ctx.FunctionAddress
         yield! stackPointerDef hdl unwindingAmount |]

  /// Compute how many bytes are unwound by this function.
  abstract ComputeUnwindingAmount:
    ctx: CFGBuildingContext<'FnCtx, 'GlCtx> -> int

  /// This is the simplistic way of counting the unwinding amount. Assuming that
  /// "ret NN" instructions are used, compute how many bytes are unwound.
  default _.ComputeUnwindingAmount ctx =
    let mutable amount = 0
    for exitV in ctx.CFG.Exits do
      let vData = exitV.VData :> ILowUIRBasicBlock
      if vData.IsAbstract then ()
      else
        let ins = vData.LastInstruction
        if ins.IsRET () then
          let newAmount = retrieveStackAdjustment ins
          assert (amount <= newAmount) (* bad case *)
          amount <- newAmount
        else ()
    amount

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
      computeLiveDefs ctx unwindingAmount
      |> Array.map (fun (dst, src) -> AST.put dst src)
    let regType = ctx.BinHandle.File.ISA.WordSize |> WordSize.toRegType
    let fallThrough = AST.num <| BitVector.OfUInt64 returnAddress regType
    let jmpToFallThrough = AST.interjmp fallThrough InterJmpKind.Base
    Array.append stmts [| jmpToFallThrough |]

  interface IFunctionSummarizable<'FnCtx, 'GlCtx> with
    member this.Summarize (ctx, retStatus, unwindingBytes, ins) =
      FunctionAbstraction (ctx.FunctionAddress,
                           unwindingBytes,
                           this.Summarize (ctx, ins, unwindingBytes),
                           ctx.IsExternal,
                           retStatus)

    member _.MakeUnknownFunctionAbstraction (hdl, callIns) =
      let returnAddress = callIns.Address + uint64 callIns.Length
      let wordSize = hdl.File.ISA.WordSize
      let regType = wordSize |> WordSize.toRegType
      let fallThrough = AST.num <| BitVector.OfUInt64 returnAddress regType
      let jmpToFallThrough = AST.interjmp fallThrough InterJmpKind.Base
      let stmts =
        stackPointerDef hdl 0
        |> Array.map (fun (dst, src) -> AST.put dst src)
      let ssaRundown = [| yield! stmts; yield jmpToFallThrough |]
      FunctionAbstraction (0UL, 0, ssaRundown, false, NotNoRet)

    member this.ComputeUnwindingAmount ctx =
      this.ComputeUnwindingAmount ctx
