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

namespace B2R2.RearEnd.Visualization

open System.Runtime.CompilerServices

[<assembly: InternalsVisibleTo("B2R2.RearEnd.Visualization.Tests")>]
do ()

/// <namespacedoc>
///   <summary>
///   Contains the layout algorithm that arranges a control flow graph for
///   drawing, along with the types that carry the arrangement. A graph goes
///   through the Sugiyama passes in turn: its cycles are broken, its vertices
///   are dealt out into layers, the layers are reordered to leave fewer edges
///   crossing, coordinates are assigned by the method of Brandes et al., and
///   the edges are last routed around what has been placed. What comes out is
///   a VisGraph, whose vertices and edges carry the geometry a drawing needs.
///   Visualizer is the way in, and JSONExport renders a laid-out graph for a
///   viewer to read.
///   </summary>
/// </namespacedoc>
///
/// <summary>
/// Represents the x-y position of a node, or of one point along an edge, in a
/// laid-out graph.
/// </summary>
type VisPosition =
  { /// The x position, growing to the right.
    mutable X: float
    /// The y position, growing downwards.
    mutable Y: float }
with
  /// Creates a position at the given x and y.
  static member Create(x, y) = { X = x; Y = y }