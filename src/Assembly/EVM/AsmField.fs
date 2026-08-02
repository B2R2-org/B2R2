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

/// <summary>
/// Turns what a source wrote into the bytes an EVM encoding is built from. What
/// does not fit is rejected rather than truncated, because a push holding fewer
/// bytes than its name says leaves every line after it at the wrong address,
/// and a program whose addresses moved is not the one the source asked for.
/// </summary>
module internal B2R2.Assembly.EVM.AsmField

open System.Numerics
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.EVM.ParserHelper

/// Reports a source this assembler cannot encode.
let fail msg = raise <| EncodingFailureException msg

/// Reports operands that do not belong to the given mnemonic.
let wrongOperands (ins: AsmInsInfo) =
  fail $"{ins.Mnemonic} does not take these operands"

/// How many numbers a field of the given width in bytes tells apart.
let private capacity width = BigInteger.Pow(2I, 8 * width)

/// <summary>
/// The number an operand comes to.
///
/// A label is as much a number as a written one is, once where it stands has
/// been worked out. One that has not been is a mistake made before ever
/// reaching here rather than something an encoding could have said.
/// </summary>
let private valueOf ins = function
  | AsmNum value -> value
  | AsmTarget addr -> BigInteger addr
  | AsmLabel lbl -> fail $"{ins.Mnemonic} still names the unplaced '{lbl}'"

/// <summary>
/// The bytes a push holds, in the order the machine reads them, which is the
/// most telling byte first.
///
/// The disassembler writes what a push holds as the number it is, which is
/// never below zero; a source of its own may write what that number stands for
/// where a program reads it as signed, which is. Both are read here, and a
/// number reaching past what the named width holds is refused rather than cut
/// down to it.
/// </summary>
let immediate width ins operand =
  let whole = capacity width
  let value = valueOf ins operand
  if value >= -(whole / 2I) && value < whole then
    let value = if value.Sign < 0 then value + whole else value
    [ for i in width - 1 .. -1 .. 0 -> byte ((value >>> (8 * i)) &&& 255I) ]
  else
    fail $"{ins.Mnemonic} cannot hold {value}"

// vim: set tw=80 sts=2 sw=2:
