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
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis

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
    let spUnwindingBv = BitVector.OfInt64 (int64 unwindingAmount) rt
    let retStackOffBv = BitVector.OfInt64 (int64 retStackOff) rt
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
and EVMFuncUserContext public () =
  /// Stack pointer difference from the entry point of the function to the
  /// return block.
  let mutable stackPointerDiff: Option<uint64> = None

  /// Stack offset of the return target that the function will return to.
  let mutable returnTargetStackOff: uint64 = 0UL

  let mutable isPublicFunction = false

  let mutable isSharedRegion = false

  member _.StackPointerDiff with get () = stackPointerDiff

  member _.ReturnTargetStackOff with get () = returnTargetStackOff

  member _.IsPublicFunction with get () = isPublicFunction

  member _.IsSharedRegion with get () = isSharedRegion

  member _.SetStackPointerDiff diff = stackPointerDiff <- Some diff

  member _.SetReturnTargetStackOff off = returnTargetStackOff <- off

  member _.SetPublicFunction () = isPublicFunction <- true

  member _.SetSharedRegion () = isSharedRegion <- true

  interface IResettable with
    member _.Reset () =
      stackPointerDiff <- None
      returnTargetStackOff <- 0UL

