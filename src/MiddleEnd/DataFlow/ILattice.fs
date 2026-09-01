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

namespace B2R2.MiddleEnd.DataFlow

/// Represents an interface for a lattice used in abstract interpretation.
type ILattice<'AbsVal when 'AbsVal: equality> =
  /// Represents the initial abstract value, i.e. the bottom of the lattice.
  /// Our analysis starts with this value until it reaches a fixed point.
  abstract Bottom: 'AbsVal

  /// Joins two abstract values.
  abstract Join: 'AbsVal * 'AbsVal -> 'AbsVal

  /// Checks if the first abstract value subsumes the second, i.e., whether
  /// joining the second into the first would leave the first unchanged. The
  /// analysis stops propagating once it does. An implementation may
  /// under-approximate this and answer false where the order does hold, which
  /// only costs an extra round of propagation.
  abstract Subsume: 'AbsVal * 'AbsVal -> bool
