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

open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

/// Provides functions to find the guards of the edges of a CFG. A guard is the
/// condition of the conditional jump that takes an edge, paired with whether
/// the jump takes the edge when that holds. Each function takes
/// tryGetCondition, which gives the condition of the conditional jump that
/// ends a vertex in whatever form its caller reads, and calls it only for the
/// source of an edge that a conditional jump takes.
[<RequireQualifiedAccess>]
module internal Guard =
  /// Gets the guard of the given vertex as one of the two ways that a
  /// conditional jump within an instruction takes, if it is one.
  let tryGetOfWay tryGetCondition (g: IDiGraph<_, _>) way =
    match g.GetPreds way with
    | [| src |] ->
      match g.FindEdge(src, way).Label with
      | IntraCJmpTrueEdge ->
        tryGetCondition src |> Option.map (fun c -> c, true)
      | IntraCJmpFalseEdge ->
        tryGetCondition src |> Option.map (fun c -> c, false)
      | _ ->
        None
    | _ ->
      None

  /// Gets the guard on the edge from pred to v. Either a conditional jump ends
  /// pred, whether it jumps out of its instruction or within it, or pred is a
  /// way that a conditional jump within an instruction takes, out of which the
  /// instruction jumps to v, as ARM branches on a condition.
  let tryGet tryGetCondition (g: IDiGraph<_, _>) pred v =
    match g.FindEdge(pred, v).Label with
    | InterCJmpTrueEdge | IntraCJmpTrueEdge ->
      tryGetCondition pred |> Option.map (fun c -> c, true)
    | InterCJmpFalseEdge | IntraCJmpFalseEdge ->
      tryGetCondition pred |> Option.map (fun c -> c, false)
    | InterJmpEdge ->
      tryGetOfWay tryGetCondition g pred
    | _ ->
      None

  /// Collects the edges into the given vertex, each as its source paired with
  /// its guard, if it has one.
  let collect tryGetCondition (g: IDiGraph<_, _>) v =
    g.GetPreds v
    |> Seq.map (fun pred -> pred, tryGet tryGetCondition g pred v)
    |> Seq.toList

  /// Collects the guards that every path to the given vertex passes: those on
  /// the edge into the vertex or into one of its dominators, from the only
  /// predecessor that it has.
  let collectDominating tryGetCondition (g: IDiGraph<_, _>) dom v =
    let rec collect (v: IVertex<_>) acc =
      match (dom: IForwardDominance<_>).ImmediateDominator v with
      | null ->
        acc
      | idom ->
        match g.GetPreds v with
        | [| pred |] ->
          match tryGet tryGetCondition g pred v with
          | Some guard -> collect idom (guard :: acc)
          | None -> collect idom acc
        | _ ->
          collect idom acc
    collect v []
