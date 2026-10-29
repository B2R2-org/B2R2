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
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis

[<RequireQualifiedAccess>]
module private CalleeClobberHelper =
  /// Represents how a function ends at an exit vertex.
  type ExitKind =
    | ReturningExit
    | UnknownExit
    | IgnoredExit

  let classify (ctx: CFGBuildingContext<_, _>) (v: IVertex<LowUIRBasicBlock>) =
    let vData = v.VData :> ILowUIRBasicBlock
    if ctx.GapAnalysisVertices.Contains vData.PPoint then
      IgnoredExit
    elif vData.IsAbstract then
      match vData.AbstractContent.ReturningStatus with
      | NoRet -> IgnoredExit
      | _ -> ReturningExit
    elif vData.LastInstruction.IsRET then
      ReturningExit
    elif vData.LastInstruction.IsIndirectBranch then
      UnknownExit
    else
      IgnoredExit

  /// Collects the vertices from which the given exit vertices are reachable.
  let collectVerticesToExits (cfg: LowUIRCFG)
                                     (exits: IVertex<LowUIRBasicBlock>[]) =
    let visited = HashSet<IVertex<LowUIRBasicBlock>>()
    let stack = Stack<IVertex<LowUIRBasicBlock>>(exits)
    while stack.Count > 0 do
      let v = stack.Pop()
      if visited.Add v then
        for pred in cfg.GetPreds v do stack.Push pred
        done
      else
        ()
    visited

  let collectWrittenRegs (written: HashSet<RegisterID>) stmts =
    for stmt in stmts do
      match stmt with
      | Put(Dst = Var(RegisterID = rid)) -> written.Add rid |> ignore
      | _ -> ()

  let collectRegsWrittenIn (vertices: HashSet<_>) =
    let written = HashSet<RegisterID>()
    for v in vertices do
      let internals = (v: IVertex<LowUIRBasicBlock>).VData.Internals
      if internals.IsAbstract then
        collectWrittenRegs written internals.AbstractContent.Rundown
      else
        for li in internals.LiftedInstructions do
          collectWrittenRegs written li.Stmts
    written

  /// Checks if a register is modified, i.e., if it or one of its aliases is
  /// written.
  let isModified (hdl: BinHandle) (written: HashSet<_>) rid =
    let aliases = hdl.RegisterFactory.GetRegisterIDAliases rid
    written.Contains rid || Array.exists written.Contains aliases

  /// Returns the caller-saved registers that the function may modify. When the
  /// function does not return, or when it ends in a way that we cannot follow,
  /// we conservatively return every register that the calling convention lets
  /// a callee modify.
  let compute (ctx: CFGBuildingContext<_, _>) =
    let hdl = ctx.BinHandle
    let all = ClobberedRegisters.ofCallingConvention hdl
    let kinds = ctx.CFG.Exits |> Array.map (fun v -> v, classify ctx v)
    let returning =
      kinds |> Array.filter (snd >> (=) ReturningExit) |> Array.map fst
    let isUnknown = Array.exists (snd >> (=) UnknownExit) kinds
    if Array.isEmpty returning || isUnknown then
      all
    else
      let vertices = collectVerticesToExits ctx.CFG returning
      let written = collectRegsWrittenIn vertices
      all |> Set.filter (isModified hdl written)

  /// Updates the registers of the context that the function may modify.
  let update (ctx: CFGBuildingContext<_, _>) =
    let modified = compute ctx
    ctx.ClobberedRegs.Clear()
    ctx.ClobberedRegs.UnionWith modified

/// Finds the caller-saved registers that a function may modify, by collecting
/// the registers that the function writes before it returns. The result is
/// kept in the building context so that a call to the function invalidates
/// only those registers. When this analysis does not run, the context keeps
/// the safe default, which is every register that the calling convention lets
/// a callee modify.
type CalleeClobberAnalysis() =
  interface ICFGAnalysis<unit -> unit> with
    member _.Unwrap env =
      fun () -> CalleeClobberHelper.update env.Context
