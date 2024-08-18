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

namespace B2R2.BinIR.SSA

open B2R2

/// SSA variables always have their own identifier.
type Variable = {
  Kind: VariableKind
  mutable Identifier: int
}
with
  static member ToString ({ Kind = k; Identifier = i }) =
    VariableKind.ToString k + "_" + i.ToString ()

  static member IsPC ({ Kind = k }) =
    match k with
    | PCVar (_) -> true
    | _ -> false

/// Type representing destination of an assignment.
and VariableKind =
  /// Register.
  | RegVar of RegType * RegisterID * string
  /// PC.
  | PCVar of RegType
  /// Temporary variables.
  | TempVar of RegType * int
  /// The whole memory as a var (an over-approximated instance). Whenever there
  /// is a memory store op, we update MemVar.
  | MemVar
  /// Stack variables. This variable is available only after the SSA promotion,
  /// which basically translates every memory load/store expression with a
  /// concrete address into either a StackVar or a GlobalVar.
  | StackVar of RegType * offset: int
  /// Global variables. This variable is available only after the SSA promotion.
  | GlobalVar of RegType * Addr
with
  static member ToString = function
    | RegVar (_, _, n) -> n
    | PCVar (_) -> "PC"
    | TempVar (_, n) -> "T_" + n.ToString()
    | MemVar -> "MEM"
    | StackVar (_, offset) -> "V_" + offset.ToString ()
    | GlobalVar (_, addr) -> "G_" + addr.ToString ()
