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

/// Provides the entry point that builds a graph from the implementations named
/// by value, for a caller that picks its implementation at run time rather
/// than by reaching for one of the graph types beside it.
[<RequireQualifiedAccess>]
module B2R2.MiddleEnd.BinGraph.GraphFactory

/// <summary>
/// Creates an empty graph of the given implementation type. The result is
/// modified in place either way: a persistent graph comes back wrapped in a
/// MutablePersistentDiGraph, which replaces its snapshot on every
/// modification.
/// </summary>
/// <param name="t">The implementation type to create a graph of.</param>
[<CompiledName "Create">]
let create t =
  match t with
  | Mutable -> MutableDiGraph() :> IMutableDiGraph<_, _>
  | Persistent -> MutablePersistentDiGraph(PersistentDiGraph())
