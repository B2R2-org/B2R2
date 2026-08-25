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

namespace B2R2.MiddleEnd.ControlFlowGraph

open B2R2.BinIR.SSA
open B2R2.MiddleEnd.BinGraph

/// Represents an SSA-based CFG, where each node contains an SSA-based basic
/// block. This is the graph interface itself, so that a CFG is a mutable graph
/// or a persistent one without a caller having to know which.
type SSACFG = IMutableDiGraph<SSABasicBlock, CFGEdgeKind>

/// Represents an SSACFG paired with the dominance of that very graph. Lifting
/// a CFG to SSA form computes the dominance on the way, and a reaching
/// definition is read off the dominator tree, so the two travel together
/// rather than a caller computing the dominance a second time.
and SSACFGWithDominance = SSACFG * IForwardDominance<SSABasicBlock>

/// <summary>
/// Provides ways to create an
/// <see cref="T:B2R2.MiddleEnd.ControlFlowGraph.SSACFG"/> and to read
/// definitions off its dominator tree.
/// </summary>
[<RequireQualifiedAccess>]
module SSACFG =
  /// Creates an empty CFG of the given implementation type.
  let create t: SSACFG = GraphFactory.create t

  /// Finds the definition of the given variable kind (targetVarKind) at the
  /// given node v, following the dominator tree of the given dominance until a
  /// definition is found. The dominance has to be that of the graph v belongs
  /// to, which is what makes the walk this reads off the right one.
  let rec findDef dom (v: IVertex<SSABasicBlock>) targetVarKind =
    let stmtInfo =
      v.VData.Internals.Statements
      |> Array.tryFindBack (fun (_, stmt) ->
        match stmt with
        | Def({ Kind = k }, _) when k = targetVarKind -> true
        | _ -> false)
    match stmtInfo with
    | Some stmtInfo ->
      Some(snd stmtInfo)
    | None ->
      match (dom: IForwardDominance<_>).ImmediateDominator v with
      | null -> None
      | idom -> findDef dom idom targetVarKind

  /// Finds the reaching definition of the given variable kind (targetVarKind)
  /// at the entry of node v, as `findDef` does from the dominator of v.
  let findReachingDef dom (v: IVertex<SSABasicBlock>) targetVarKind =
    match (dom: IForwardDominance<_>).ImmediateDominator v with
    | null -> None
    | idom -> findDef dom idom targetVarKind
