(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Minkyu Jung <hestati@kaist.ac.kr>

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

namespace B2R2

open B2R2

/// RegisterSet is an efficient representation for managing a set of registers.
[<RequireQualifiedAccess>]
[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module RegisterSet =

  /// Returns an empty RegisterSet.
  val empty : RegisterSet

  /// Make a union of two register sets.
  val inline union : RegisterSet -> RegisterSet -> RegisterSet

  /// Make an intersection of two register sets.
  val inline intersect : RegisterSet -> RegisterSet -> RegisterSet

  /// Remove a register from the register set.
  val inline remove : RegisterID -> RegisterSet -> RegisterSet

  /// Add a register from the register set.
  val inline add : RegisterID -> RegisterSet -> RegisterSet

  /// Check the existence of a register in the register set.
  val inline exist : RegisterID -> RegisterSet -> bool

  /// Is the register set empty?
  val inline isEmpty : RegisterSet -> bool

