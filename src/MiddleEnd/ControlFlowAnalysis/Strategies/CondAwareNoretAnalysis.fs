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

open B2R2.FrontEnd
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis

/// This is a non-returning function identification strategy that can check
/// conditionally non-returning functions. We currently support only those
/// simple patterns that are handled by compilers, but we may have to extend
/// this as the compilers evolve.
type CondAwareNoretAnalysis () =
  let meet a b =
    match a, b with
    | NoRet, NoRet
    | UnknownNoRet, NoRet
    | NoRet, UnknownNoRet-> NoRet
    | _ -> NotNoRet

  /// Disregard return instructions and PLT entries because they should not
  /// decide the return status.
  let filterReturns (hdl: BinHandle) exitVertices =
    match (exitVertices: IVertex<IRBasicBlock>[]) with
    | [| v |] when not v.VData.IsAbstract ->
      if v.VData.LastInstruction.IsRET () ||
        hdl.File.IsLinkageTable v.VData.PPoint.Address then [||]
      else exitVertices
    | _ -> exitVertices

  interface IPostAnalysis<unit -> unit> with
    member _.Unwrap env =
      let ctx = env.Context
      fun () ->
        let mutable idx = 0
        let mutable returnStatus = UnknownNoRet
        let exits = ctx.CFG.Exits |> filterReturns ctx.BinHandle
        let numExits = Array.length exits
        while idx < numExits && returnStatus = UnknownNoRet do
          let v = exits[idx]
          if v.VData.IsAbstract then
            let calleeAddr = v.VData.PPoint.Address
            match ctx.ManagerChannel.GetNonReturningStatus calleeAddr with
            | NoRet | ConditionalNoRet _ ->
              (* Since this is an exit node, the abstract vertex has no
                fall-through edge. This means, that even if the callee is
                conditionally returning, we know that the argument to the callee
                is always constant, and it is confirmed to be non-returning. *)
              returnStatus <- meet returnStatus NoRet
            | _ -> ()
          else returnStatus <- meet returnStatus NoRet
          idx <- idx + 1
        match returnStatus with
        | UnknownNoRet -> ctx.NonReturningStatus <- NotNoRet
        | _ -> ctx.NonReturningStatus <- returnStatus
#if CFGDEBUG
        dbglog ctx.ThreadID (nameof CondAwareNoretAnalysis)
        <| $"{ctx.FunctionAddress:x}: {ctx.NonReturningStatus}"
#endif
