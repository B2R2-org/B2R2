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
open B2R2.BinIR.SSA
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Base class for summarizing a function in a lightweight manner. One can
/// extend this class to implement a more sophisticated function summarizer.
type FunctionSummarizer<'V,
                        'E,
                        'FnCtx,
                        'GlCtx when 'V :> IRBasicBlock
                                and 'V: equality
                                and 'E: equality
                                and 'FnCtx :> IResettable
                                and 'FnCtx: (new: unit -> 'FnCtx)
                                and 'GlCtx: (new: unit -> 'GlCtx)> () =
  let retrieveStackAdjustment (ins: Instruction) =
    match ins.Immediate () with
    | true, v -> int v
    | false, _ -> 0

  /// Translate the given expression into another one w.r.t caller's context.
  /// Its translation is done by replacing the stack variable with the
  /// corresponding load expression. Note that our current impl of SSA
  /// construction does not rename stack variables in abstract basic blocks
  /// for simplicity.
  let rec translateExprForCallerContext hdl = function
    | Var { Kind = StackVar (rt, off) } -> (* convert into Load(...) *)
      let memVar: Variable = { Kind = MemVar; Identifier = -1 }
      let spRid = (hdl: BinHandle).RegisterFactory.StackPointer |> Option.get
      let spRegStr = hdl.RegisterFactory.RegIDToString spRid
      let spVar: Variable =
        { Kind = RegVar (rt, spRid, spRegStr); Identifier = -1 }
      let sp = Var spVar
      let amount = Num <| BitVector.OfInt32 off rt
      let shiftedAddr = BinOp (BinOpType.SUB, rt, sp, amount)
      Load (memVar, rt, shiftedAddr)
    | Var var -> Var { var with Identifier = -1 }
    | BinOp (op, rt, e1, e2) ->
      let e1 = translateExprForCallerContext hdl e1
      let e2 = translateExprForCallerContext hdl e2
      BinOp (op, rt, e1, e2)
    | UnOp (op, rt, e) ->
      UnOp (op, rt, translateExprForCallerContext hdl e)
    | Load (v, rt, e) ->
      Load (v, rt, translateExprForCallerContext hdl e)
    | Cast (kind, rt, e) ->
      Cast (kind, rt, translateExprForCallerContext hdl e)
    | RelOp (op, rt, e1, e2) ->
      let e1 = translateExprForCallerContext hdl e1
      let e2 = translateExprForCallerContext hdl e2
      RelOp (op, rt, e1, e2)
    | Extract (e, rt, pos) ->
      Extract (translateExprForCallerContext hdl e, rt, pos)
    | e -> e

  let addOutVar hdl var e varMap =
    let e = translateExprForCallerContext hdl e
    Map.add var e varMap

  let buildRegVar (hdl: BinHandle) reg =
    let wordSize = hdl.File.ISA.WordSize |> WordSize.toRegType
    RegVar (wordSize, reg, hdl.RegisterFactory.RegIDToString reg)

  let addMemDef hdl defs =
    let e = Var { Kind = MemVar; Identifier = - 1 }
    addOutVar hdl MemVar e defs

  let addStackPointerDef (hdl: BinHandle) unwindingAmount defs =
    match hdl.RegisterFactory.StackPointer with
    | Some sp ->
      let rt = hdl.RegisterFactory.RegIDToRegType sp
      let var = buildRegVar hdl sp
      let retAddrSize = RegType.toByteWidth rt |> int64
      let adj = int64 unwindingAmount
      let shiftAmount = BitVector.OfInt64 (retAddrSize + adj) rt
      let v1 = Var { Kind = var; Identifier = -1 }
      let v2 = Num shiftAmount
      let e = BinOp (BinOpType.ADD, rt, v1, v2)
      addOutVar hdl var e defs
    | None -> defs

  let toID register =
    Intel.Register.toRegID register

  let tryFindLiveRegFromGetPCThunk (hdl: BinHandle) (addr: Addr) =
    match hdl.ReadUInt (addr, 4) with
    | 0xc324048bUL -> Some (RegVar (32<rt>, toID Intel.Register.EAX, "EAX"))
    | 0xc3241c8bUL -> Some (RegVar (32<rt>, toID Intel.Register.EBX, "EBX"))
    | 0xc3240c8bUL -> Some (RegVar (32<rt>, toID Intel.Register.ECX, "ECX"))
    | 0xc324148bUL -> Some (RegVar (32<rt>, toID Intel.Register.EDX, "EDX"))
    | 0xc324348bUL -> Some (RegVar (32<rt>, toID Intel.Register.ESI, "ESI"))
    | 0xc3243c8bUL -> Some (RegVar (32<rt>, toID Intel.Register.EDI, "EDI"))
    | 0xc3242c8bUL -> Some (RegVar (32<rt>, toID Intel.Register.EBP, "EBP"))
    | _ -> None

  let genFreshStackVarExpr hdl off =
    let rt = (hdl: BinHandle).File.ISA.WordSize |> WordSize.toRegType
    Var { Kind = StackVar (rt, off); Identifier = -1 }

  let initializeLiveVarMap (ctx: CFGBuildingContext<_, _, _, _>) =
    match ctx.BinHandle.File.ISA.Arch with
    | Architecture.IntelX86 ->
      let hdl = ctx.BinHandle
      match tryFindLiveRegFromGetPCThunk hdl ctx.FunctionAddress with
      | Some var ->
        let e = genFreshStackVarExpr hdl 0
        addOutVar hdl var e Map.empty
      | None -> Map.empty
    | _ -> Map.empty

  let computeLiveVars (ctx: CFGBuildingContext<_, _, _, _>) unwindingAmount =
    let hdl = ctx.BinHandle
    if ctx.IsExternal then
      let var = CallingConvention.returnRegister hdl |> buildRegVar hdl
      let rt = hdl.File.ISA.WordSize |> WordSize.toRegType
      let e = Undefined (rt, "ret")
      addOutVar hdl var e Map.empty
      |> addMemDef hdl
      |> addStackPointerDef hdl unwindingAmount
    else
      initializeLiveVarMap ctx
      |> addMemDef hdl
      |> addStackPointerDef hdl unwindingAmount

  /// Compute how many bytes are unwound by this function.
  abstract ComputeUnwindingAmount:
    ctx: CFGBuildingContext<'V, 'E, 'FnCtx, 'GlCtx> -> int option

  /// This is the simplistic way of counting the unwinding amount. Assuming that
  /// "ret NN" instructions are used, compute how many bytes are unwound.
  default _.ComputeUnwindingAmount ctx =
    ctx.CFG.Exits
    |> Array.fold (fun acc v ->
      if Option.isSome acc || v.VData.IsAbstract then acc
      else
        let ins = v.VData.LastInstruction
        if ins.IsRET () then retrieveStackAdjustment ins |> Some
        else acc
    ) None

  /// Summarize the function in SSA form.
  abstract SSASummarize:
       ctx: CFGBuildingContext<'V, 'E, 'FnCtx, 'GlCtx>
     * Instruction
     * unwindingAmount: int
    -> SSARundown

  /// Simply over-approximate the function semantics, except for several
  /// well-known "getpc" functions for x86.
  default _.SSASummarize (ctx, callInstruction, unwindingAmount) =
    let returnAddress = callInstruction.Address + uint64 callInstruction.Length
    let stmts = (* For abstraction, we check which var can be defined. *)
      computeLiveVars ctx unwindingAmount
      |> Seq.map (fun (KeyValue (kind, e)) ->
        let dst = { Kind = kind; Identifier = -1 }
        Def (dst, ReturnVal (ctx.FunctionAddress, returnAddress, e)))
      |> Seq.toArray
    let regType = ctx.BinHandle.File.ISA.WordSize |> WordSize.toRegType
    let fallThrough = BitVector.OfUInt64 returnAddress regType
    let jmpToFallThrough = Jmp (InterJmp (Num fallThrough))
    Array.append stmts [| jmpToFallThrough |]
    |> Array.map (fun s -> ProgramPoint.GetFake (), s)

  interface IFunctionSummarizable<'V, 'E, 'FnCtx, 'GlCtx> with
    member __.Summarize (ctx: CFGBuildingContext<'V, 'E, 'FnCtx, 'GlCtx>, ins) =
      let unwindingBytes =
        if ctx.IsExternal then None else __.ComputeUnwindingAmount ctx
      let unwindingAmount = Option.defaultValue 0 unwindingBytes
      let ssaRundown = __.SSASummarize (ctx, ins, unwindingAmount)
      FunctionAbstraction (ctx.FunctionAddress,
                           unwindingBytes,
                           ssaRundown,
                           ctx.IsExternal,
                           ctx.NonReturningStatus)

    member __.SummarizeUnknown (wordSize, callIns) =
      let returnAddress = callIns.Address + uint64 callIns.Length
      let regType = wordSize |> WordSize.toRegType
      let fallThrough = BitVector.OfUInt64 returnAddress regType
      let jmpToFallThrough = Jmp (InterJmp (Num fallThrough))
      let ssaRundown = [| (ProgramPoint.GetFake (), jmpToFallThrough) |]
      FunctionAbstraction (0UL, None, ssaRundown, false, NotNoRet)
