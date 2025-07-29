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

open System.Collections.Generic
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.DataFlow.LowUIRSensitiveDataFlow
open B2R2.MiddleEnd.BinGraph

/// Summarizes a function in the EVM context. Thanks to the powerful
/// expressiveness of B2R2's IR, we can easily express a function's
/// abstraction, including its unwinding behavior and return behavior.
type EVMFunctionSummarizer<'FnCtx,
                           'GlCtx when 'FnCtx :> EVMFuncUserContext
                                   and 'FnCtx: (new: unit -> 'FnCtx)
                                   and 'GlCtx: (new: unit -> 'GlCtx)> () =
  let makeRundownForReturn hdl unwindingAmount retStackOff =
    let spRegId = (hdl: BinHandle).RegisterFactory.StackPointer |> Option.get
    let spVar = hdl.RegisterFactory.GetRegVar spRegId
    let rt = hdl.RegisterFactory.GetRegType spRegId
    let jumpDstVar = AST.tmpvar rt 0
    let spUnwindingBv = BitVector.OfInt64(int64 unwindingAmount, rt)
    let retStackOffBv = BitVector.OfInt64(int64 retStackOff, rt)
    let retSp = AST.binop BinOpType.ADD spVar (AST.num retStackOffBv)
    let finalSp = AST.binop BinOpType.ADD spVar (AST.num spUnwindingBv)
    [| AST.put jumpDstVar (AST.load Endian.Little rt retSp)
       AST.put spVar finalSp
       AST.interjmp jumpDstVar InterJmpKind.Base |]

  let makeRundown hdl ret unwindingAmount retStackOff =
    match ret with
    | NoRet -> [| AST.sideEffect Terminate |]
    | NotNoRet -> makeRundownForReturn hdl unwindingAmount retStackOff
    | _ -> Terminator.impossible ()

  interface IFunctionSummarizable<'FnCtx, 'GlCtx> with
    member _.Summarize (ctx, ret, unwinding, _ins) =
      let entryPoint = ctx.FunctionAddress
      let returnTargetStackOff = ctx.UserContext.ReturnTargetStackOff
      let hdl = ctx.BinHandle
      let rundown = makeRundown hdl ret unwinding returnTargetStackOff
      let abs = FunctionAbstraction (entryPoint, unwinding, rundown, false, ret)
      abs

    member _.MakeUnknownFunctionAbstraction (_, _) = Terminator.impossible ()

    member _.ComputeUnwindingAmount _ = Terminator.impossible ()

/// User-defined context for EVM functions. EVMFunctionSummarizer uses this
/// information to summarize the function, especially the return target.
and EVMFuncUserContext () =
  let mutable cp: LowUIRSensitiveConstantPropagation<EVMExeCtx> = null

  /// Stack pointer difference from the entry point of the function to the
  /// return block.
  let mutable stackPointerDiff: Option<uint64> = None

  /// Stack offset of the return target that the function will return to.
  let mutable returnTargetStackOff: uint64 = 0UL

  let mutable isPublicFunction = false

  let mutable isSharedRegion = false

  let perVertexStackPointerDelta = Dictionary<IVertex<LowUIRBasicBlock>, int> ()

  /// Postponed vertices that are not yet processed because the data-flow
  /// analysis has not yet reached them due to incomplete CFG traversal.
  let verticesPostponed = HashSet<IVertex<LowUIRBasicBlock>> ()

  /// Vertices that are resumable, i.e., the data-flow analysis on these
  /// vertices is already completed, and we can resume their analysis on the
  /// CFG.
  let verticesResumable = HashSet<IVertex<LowUIRBasicBlock>> ()

  let getStackPointerId hdl =
    (hdl: BinHandle).RegisterFactory.StackPointer.Value

  let convertStackPointerToInt32 bv = BitVector.ToUInt64 bv |> toFrameOffset

  /// Assuming that the stack pointer is always computed only using the
  /// stack pointer register, we use a lightweight manner to compute the stack
  /// pointer delta for the given vertex. This enables us to keep our design
  /// where we compute stack pointers after reaching definition analysis.
  let rec computeStackPointerDelta (state: State<_, _>) v =
    let spId = getStackPointerId state.BinHandle
    let spRegType = state.BinHandle.RegisterFactory.GetRegType spId
    let stmtInfos = state.GetStmtInfos v
    let initialBV = BitVector.OfUInt64(Constants.InitialStackPointer, spRegType)
    stmtInfos
    |> Array.fold (fun offBV (stmt, _) ->
      match stmt with
      | Put (Var (_, regId, _, _), src, _)
        when regId = spId -> evalStackPointer spId offBV src
      | _ -> offBV) initialBV
    |> convertStackPointerToInt32

  and evalStackPointer spId offBV = function
    | BinOp (binOp, _, e1, e2, _) ->
      let v1 = evalStackPointer spId offBV e1
      let v2 = evalStackPointer spId offBV e2
      match binOp with
      | BinOpType.ADD -> v1 + v2
      | BinOpType.SUB -> v1 - v2
      | _ -> Terminator.impossible ()
    | Num (bv, _) -> bv
    | Var (_, regId, _, _) when regId = spId -> offBV
    | _ -> Terminator.impossible ()

  let getStackPointerDelta state v =
    match perVertexStackPointerDelta.TryGetValue v with
    | true, delta -> delta
    | false, _ ->
      let delta = computeStackPointerDelta state v
      perVertexStackPointerDelta[v] <- delta
      delta

  let onRemoveVertex v =
    verticesPostponed.Remove v |> ignore
    verticesResumable.Remove v |> ignore
    perVertexStackPointerDelta.Remove v |> ignore

  member _.StackPointerDiff with get () = stackPointerDiff

  member _.ReturnTargetStackOff with get () = returnTargetStackOff

  member _.IsPublicFunction with get () = isPublicFunction

  member _.IsSharedRegion with get () = isSharedRegion

  member _.SetStackPointerDiff diff = stackPointerDiff <- Some diff

  member _.SetReturnTargetStackOff off = returnTargetStackOff <- off

  member _.SetPublicFunction () = isPublicFunction <- true

  member _.SetSharedRegion () = isSharedRegion <- true

  member _.PostponedVertices with get () = verticesPostponed

  member _.ResumableVertices with get () = verticesResumable

  member _.PerVertexStackPointerDelta with get () = perVertexStackPointerDelta

  member _.GetStackPointerDelta state v = getStackPointerDelta state v

  member _.CP with get () = cp and set (v) = cp <- v

  interface IResettable with
    member _.Reset () =
      cp.Reset ()
      perVertexStackPointerDelta.Clear ()
      verticesPostponed.Clear ()
      verticesResumable.Clear ()
      stackPointerDiff <- None
      returnTargetStackOff <- 0UL

and EVMExeCtx = {
  /// The stack offset of the current vertex.
  StackOffset: int
  /// A mapping from a program point to a boolean value indicating whether the
  /// variable defined at that point has been evaluated to true or false.
  /// We do not use SensitiveProgramPoint here because we hate path explosion.
  Conditions: Map<ProgramPoint, bool>
}


