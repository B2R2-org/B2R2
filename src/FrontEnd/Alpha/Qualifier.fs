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

namespace B2R2.FrontEnd.Alpha

open B2R2

/// <summary>
/// Represents the qualifier an Alpha floating-point instruction hangs off its
/// name, which says how the instruction rounds and what it traps on.
///
/// The architecture spends the function code field on both what an instruction
/// computes and how it computes it, so what one word says over another of the
/// same instruction is exactly this. It is written glued to the mnemonic with a
/// slash, the way the architecture handbook writes it: ADDS/SUID is ADDS
/// carrying <see cref='F:B2R2.FrontEnd.Alpha.Qualifier.SUID'/>.
/// </summary>
type Qualifier =
  /// No qualifier at all, which is how the machine rounds
  /// and traps by default.
  | NoQualifier = 0
  /// Chopped rounding.
  | C = 1
  /// Rounding toward minus infinity.
  | M = 2
  /// Rounding the floating-point control register names.
  | D = 3
  /// Trapping on underflow.
  | U = 4
  /// Trapping on underflow, chopped rounding.
  | UC = 5
  /// Trapping on underflow, rounding toward minus infinity.
  | UM = 6
  /// Trapping on underflow, dynamic rounding.
  | UD = 7
  /// Software completion, trapping on underflow.
  | SU = 8
  /// Software completion, trapping on underflow, chopped
  /// rounding.
  | SUC = 9
  /// Software completion, trapping on underflow, rounding toward
  /// minus infinity.
  | SUM = 10
  /// Software completion, trapping on underflow, dynamic
  /// rounding.
  | SUD = 11
  /// Software completion, trapping on underflow and on an inexact
  /// result.
  | SUI = 12
  /// The same, chopped rounding.
  | SUIC = 13
  /// The same, rounding toward minus infinity.
  | SUIM = 14
  /// The same, dynamic rounding.
  | SUID = 15
  /// Software completion.
  | S = 16
  /// Software completion, chopped rounding.
  | SC = 17
  /// Trapping on integer overflow.
  | V = 18
  /// Trapping on integer overflow, chopped rounding.
  | VC = 19
  /// Trapping on integer overflow, rounding toward minus
  /// infinity.
  | VM = 20
  /// Trapping on integer overflow, dynamic rounding.
  | VD = 21
  /// Software completion, trapping on integer overflow.
  | SV = 22
  /// Software completion, trapping on integer overflow, chopped
  /// rounding.
  | SVC = 23
  /// Software completion, trapping on integer overflow, rounding
  /// toward minus infinity.
  | SVM = 24
  /// Software completion, trapping on integer overflow, dynamic
  /// rounding.
  | SVD = 25
  /// Software completion, trapping on integer overflow and on an
  /// inexact result.
  | SVI = 26
  /// The same, chopped rounding.
  | SVIC = 27
  /// The same, rounding toward minus infinity.
  | SVIM = 28
  /// The same, dynamic rounding.
  | SVID = 29

/// Provides functions to handle Alpha floating-point qualifiers.
module Qualifier =
  /// Returns the text an Alpha qualifier is written as, which is empty for the
  /// one that is written by writing nothing.
  [<CompiledName "ToString">]
  let toString qualifier =
    match qualifier with
    | Qualifier.NoQualifier -> ""
    | Qualifier.C -> "c"
    | Qualifier.M -> "m"
    | Qualifier.D -> "d"
    | Qualifier.U -> "u"
    | Qualifier.UC -> "uc"
    | Qualifier.UM -> "um"
    | Qualifier.UD -> "ud"
    | Qualifier.SU -> "su"
    | Qualifier.SUC -> "suc"
    | Qualifier.SUM -> "sum"
    | Qualifier.SUD -> "sud"
    | Qualifier.SUI -> "sui"
    | Qualifier.SUIC -> "suic"
    | Qualifier.SUIM -> "suim"
    | Qualifier.SUID -> "suid"
    | Qualifier.S -> "s"
    | Qualifier.SC -> "sc"
    | Qualifier.V -> "v"
    | Qualifier.VC -> "vc"
    | Qualifier.VM -> "vm"
    | Qualifier.VD -> "vd"
    | Qualifier.SV -> "sv"
    | Qualifier.SVC -> "svc"
    | Qualifier.SVM -> "svm"
    | Qualifier.SVD -> "svd"
    | Qualifier.SVI -> "svi"
    | Qualifier.SVIC -> "svic"
    | Qualifier.SVIM -> "svim"
    | Qualifier.SVID -> "svid"
    | _ -> Terminator.impossible ()

  /// Returns the Alpha qualifier the given text is written as, the empty
  /// string being the one that is written by writing nothing.
  [<CompiledName "OfString">]
  let ofString (str: string) =
    match str.ToLowerInvariant() with
    | "" -> Qualifier.NoQualifier
    | "c" -> Qualifier.C
    | "m" -> Qualifier.M
    | "d" -> Qualifier.D
    | "u" -> Qualifier.U
    | "uc" -> Qualifier.UC
    | "um" -> Qualifier.UM
    | "ud" -> Qualifier.UD
    | "su" -> Qualifier.SU
    | "suc" -> Qualifier.SUC
    | "sum" -> Qualifier.SUM
    | "sud" -> Qualifier.SUD
    | "sui" -> Qualifier.SUI
    | "suic" -> Qualifier.SUIC
    | "suim" -> Qualifier.SUIM
    | "suid" -> Qualifier.SUID
    | "s" -> Qualifier.S
    | "sc" -> Qualifier.SC
    | "v" -> Qualifier.V
    | "vc" -> Qualifier.VC
    | "vm" -> Qualifier.VM
    | "vd" -> Qualifier.VD
    | "sv" -> Qualifier.SV
    | "svc" -> Qualifier.SVC
    | "svm" -> Qualifier.SVM
    | "svd" -> Qualifier.SVD
    | "svi" -> Qualifier.SVI
    | "svic" -> Qualifier.SVIC
    | "svim" -> Qualifier.SVIM
    | "svid" -> Qualifier.SVID
    | _ -> Terminator.impossible ()

  /// <summary>
  /// Returns the mnemonic the given opcode carrying the given qualifier is
  /// written as, which is the opcode's own name where the qualifier is none and
  /// that name with the qualifier glued to it by a slash where it is not.
  ///
  /// Both ends of the round trip read this: the disassembler writes what it
  /// returns and the assembler builds the names it reads out of it, so what one
  /// writes cannot drift from what the other reads.
  /// </summary>
  [<CompiledName "MnemonicOf">]
  let mnemonicOf opcode qualifier =
    if qualifier = Qualifier.NoQualifier then Opcode.toString opcode
    else Opcode.toString opcode + "/" + toString qualifier

// vim: set tw=80 sts=2 sw=2:
