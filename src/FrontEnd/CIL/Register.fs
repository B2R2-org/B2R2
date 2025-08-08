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

namespace B2R2.FrontEnd.CIL

open B2R2

/// <namespacedoc>
///   <summary>
///   Contains types and functions for working with the CIL instructions.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Represents a CIL register.
/// </summary>
type Register =
  /// Program counter.
  | PC = 0x0
  /// Stack pointer.
  | SP = 0x1

/// Provides several useful functions for handling CIL registers.
[<RequireQualifiedAccess>]
module Register =
  let inline ofRegID (n: RegisterID): Register =
    int n |> LanguagePrimitives.EnumOfValue

  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue(reg) |> RegisterID.create

  let ofString (str: string) =
    match str.ToLowerInvariant() with
    | "pc" -> Register.PC
    | "sp" -> Register.SP
    | _ -> Terminator.impossible ()

  let toString = function
    | Register.PC -> "PC"
    | Register.SP -> "SP"
    | _ -> Terminator.impossible ()

  let toRegType = function
    | Register.PC -> 64<rt>
    | Register.SP -> 64<rt>
    | _ -> Terminator.impossible ()

/// Shortcut for Register type.
type internal R = Register
