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

/// <summary>
/// Represents SSA variables that always have their own identifier.
/// </summary>
type Variable =
  { Kind: VariableKind
    mutable Identifier: int }
with
  override this.ToString() =
    this.Kind.ToString() + "_" + this.Identifier.ToString()

  static member IsPC({ Kind = k }) =
    match k with
    | PCVar(_) -> true
    | _ -> false

/// Provides utility functions for SSA variables.
[<RequireQualifiedAccess>]
module Variable =
  /// Converts an SSA variable to a string.
  [<CompiledName "ToString">]
  let toString (var: Variable) =
    var.ToString()

  /// Checks if an SSA variable represents a program counter.
  [<CompiledName "IsPC">]
  let isPC (var: Variable) =
    Variable.IsPC var