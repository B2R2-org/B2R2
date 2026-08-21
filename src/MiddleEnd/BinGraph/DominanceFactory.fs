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

/// Provides the entry point that builds an IDominance from the algorithms
/// named by value, for a caller that picks its algorithm at run time rather
/// than by reaching for one of the modules of the Dominance namespace.
module B2R2.MiddleEnd.BinGraph.DominanceFactory

open B2R2.MiddleEnd.BinGraph.Dominance

/// <summary>
/// Computes the dominance of the given graph using the given algorithm and the
/// given dominance frontier provider. Prefer create, which names the provider
/// by value too; this overload is for a caller that brings an
/// IDominanceFrontierProvider of its own.
/// </summary>
/// <param name="g">The graph to compute the dominance of.</param>
/// <param name="algo">The algorithm to compute the dominance with.</param>
/// <param name="dfp">Provides the dominance frontier implementation.</param>
[<CompiledName "CreateWithProvider">]
let createWithProvider g algo dfp =
  match algo with
  | Static algo -> StaticDominance.create g dfp algo
  | DepthBasedSearch algo -> DepthBasedSearchDominance.create g dfp algo

/// <summary>
/// Computes the dominance of the given graph using the given algorithms.
/// </summary>
/// <param name="g">The graph to compute the dominance of.</param>
/// <param name="algo">The algorithm to compute the dominance with.</param>
/// <param name="dfAlgo">The algorithm to compute the dominance frontiers
/// with.</param>
[<CompiledName "Create">]
let create g algo dfAlgo =
  let dfp: IDominanceFrontierProvider<_, _> =
    match dfAlgo with
    | CytronFrontier -> CytronDominanceFrontier()
    | CooperFrontier -> CooperDominanceFrontier()
  createWithProvider g algo dfp
