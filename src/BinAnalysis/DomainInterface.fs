(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>
          Soomin Kim <soomink@kaist.ac.kr>

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

namespace B2R2.BinAnalysis

type IValueDomain<'aval> =
  /// Constants
  abstract Top : 'aval
  abstract Bot : 'aval
  /// Lattice operations
  abstract IsLe : 'aval -> 'aval -> bool
  abstract Lub : 'aval -> 'aval -> 'aval
  abstract Glb : 'aval -> 'aval -> 'aval
  abstract Widen : 'aval -> 'aval -> 'aval
  /// Unary operation
  abstract Neg : 'aval -> 'aval
  abstract Not : 'aval -> 'aval
  /// Binary operation
  abstract Add : 'aval -> 'aval -> 'aval
  abstract Sub : 'aval -> 'aval -> 'aval
  abstract Mul : 'aval -> 'aval -> 'aval
  abstract Div : 'aval -> 'aval -> 'aval
  abstract SDiv : 'aval -> 'aval -> 'aval
  abstract Mod : 'aval -> 'aval -> 'aval
  abstract SMod : 'aval -> 'aval -> 'aval
  abstract Shl : 'aval -> 'aval -> 'aval
  abstract Shr : 'aval -> 'aval -> 'aval
  abstract Sar : 'aval -> 'aval -> 'aval
  abstract And : 'aval -> 'aval -> 'aval
  abstract Or : 'aval -> 'aval -> 'aval
  abstract Xor : 'aval -> 'aval -> 'aval
  abstract Concat : 'aval -> 'aval -> 'aval
  /// Relative operation
  abstract Eq : 'aval -> 'aval -> 'aval
  abstract NEq : 'aval -> 'aval -> 'aval
  abstract Gt : 'aval -> 'aval -> 'aval
  abstract Ge : 'aval -> 'aval -> 'aval
  abstract SGt : 'aval -> 'aval -> 'aval
  abstract SGe : 'aval -> 'aval -> 'aval
  abstract Lt : 'aval -> 'aval -> 'aval
  abstract Le : 'aval -> 'aval -> 'aval
  abstract SLt : 'aval -> 'aval -> 'aval
  abstract SLe : 'aval -> 'aval -> 'aval
  /// Casting
  abstract Low : 'aval -> 'aval
  abstract High : 'aval -> 'aval
  abstract SExt : 'aval -> 'aval
  abstract ZExt : 'aval -> 'aval

type IStateDomain<'astate> =
  /// Constants
  /// TODO: Modify the element type of list to be registers
  abstract Top : string list -> 'astate
  /// Lattice operations
  abstract Join : 'astate -> 'astate -> 'astate
  abstract Widen : 'astate -> 'astate -> 'astate
  abstract IsLeq : 'astate -> 'astate -> bool
  /// Add environment
  abstract AddDom : string -> 'astate -> 'astate

