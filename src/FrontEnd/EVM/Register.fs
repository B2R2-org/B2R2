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

namespace B2R2.FrontEnd.EVM

open B2R2
open System.Runtime.CompilerServices

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.EVM.Tests")>]
do ()

/// Represents an EVM register.
type Register =
  /// Program counter.
  | PC = 0x1
  /// Gas.
  | GAS = 0x2
  /// Stack pointer.
  | SP = 0x3

/// Shortcut for Register type.
type internal R = Register

/// Represents an Operation Size.
type OperationSize = int
module internal OperationSize =
  let regType = 256<rt>

/// Provides exposes several useful functions to handle EVM registers.
[<RequireQualifiedAccess>]
module Register =
  let inline ofRegID (n: RegisterID): Register =
    int n |> LanguagePrimitives.EnumOfValue

  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  let ofString (str: string) =
    match str.ToLowerInvariant () with
    | "PC" -> R.PC
    | "GAS" -> R.GAS
    | "SP" -> R.SP
    | _ -> Terminator.impossible ()

  let toString = function
    | R.PC -> "PC"
    | R.GAS -> "GAS"
    | R.SP -> "SP"
    | _ -> Terminator.impossible ()

  let toRegType = function
    | R.PC -> 256<rt>
    | R.GAS -> 64<rt>
    | R.SP -> 256<rt>
    | _ -> Terminator.impossible ()
