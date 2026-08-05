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
/// Encodes the floating-point unit: the arithmetic at each of the three widths
/// a number is kept at, the conversions between those widths and the integers,
/// the comparisons, the moves that happen only where something holds, and the
/// instructions working on the two halves of a doubleword at once.
/// </summary>
module internal B2R2.Assembly.SPARC.AsmFloat

open B2R2.FrontEnd.SPARC
open B2R2.Assembly.SPARC.ParserHelper
open B2R2.Assembly.SPARC.AsmField
open B2R2.Assembly.SPARC.AsmOpcode

(* The three families the floating-point instructions are divided into: what
   computes, what compares or moves on a condition, and what the machine it
   runs on is left to say the meaning of, which is where the instructions
   working on two halves of a doubleword at once were put. *)
let [<Literal>] private OpCompute = 0x34u
let [<Literal>] private OpDecide = 0x35u
let [<Literal>] private OpWide = 0x36u

/// An instruction computing from one register into another.
let private unary opf source dest ins =
  match ins.Operands with
  | [ Rg s2; Rg d ] ->
    format3 2u OpCompute (dest d) 0u ((opf <<< 5) ||| source s2)
  | _ ->
    wrongOperands ins

/// <summary>
/// The instructions computing from one floating-point register into another:
/// the sign changes, the square roots, and the conversions.
///
/// Two of them name the registers they work on by the wrong width: the square
/// root of a double-precision number names both of its registers as if they
/// held single-precision ones, and so does the conversion of a quad-precision
/// number to an integer. Both are named here as the disassembler reads them,
/// because an assembler that read them otherwise could not read back what the
/// disassembler writes.
/// </summary>
let private unaryEncoders () =
  [ "fmovs", unary 0b000000001u single single
    "fmovd", unary 0b000000010u double double
    "fmovq", unary 0b000000011u quad quad
    "fnegs", unary 0b000000101u single single
    "fnegd", unary 0b000000110u double double
    "fnegq", unary 0b000000111u quad quad
    "fabss", unary 0b000001001u single single
    "fabsd", unary 0b000001010u double double
    "fabsq", unary 0b000001011u quad quad
    "fsqrts", unary 0b000101001u single single
    "fsqrtd", unary 0b000101010u single single
    "fsqrtq", unary 0b000101011u quad quad
    "fstox", unary 0b010000001u single double
    "fdtox", unary 0b010000010u double double
    "fqtox", unary 0b010000011u quad double
    "fxtos", unary 0b010000100u double single
    "fxtod", unary 0b010001000u double double
    "fxtoq", unary 0b010001100u double quad
    "fitos", unary 0b011000100u single single
    "fitod", unary 0b011001000u single double
    "fitoq", unary 0b011001100u single quad
    "fstod", unary 0b011001001u single double
    "fstoq", unary 0b011001101u single quad
    "fdtos", unary 0b011000110u double single
    "fdtoq", unary 0b011001110u double quad
    "fqtod", unary 0b011001011u quad double
    "fstoi", unary 0b011010001u single single
    "fdtoi", unary 0b011010010u double single
    "fqtoi", unary 0b011010011u single single ]

/// An instruction computing from two registers into a third.
let private binary op3 opf first second dest ins =
  match ins.Operands with
  | [ Rg s1; Rg s2; Rg d ] ->
    format3 2u op3 (dest d) (first s1) ((opf <<< 5) ||| second s2)
  | _ ->
    wrongOperands ins

/// The instructions computing from two floating-point registers into a third.
/// Two of them widen what they computed, so what they write is kept at twice
/// the width of what they read.
let private binaryEncoders () =
  [ "fadds", binary OpCompute 0b001000001u single single single
    "faddd", binary OpCompute 0b001000010u double double double
    "faddq", binary OpCompute 0b001000011u quad quad quad
    "fsubs", binary OpCompute 0b001000101u single single single
    "fsubd", binary OpCompute 0b001000110u double double double
    "fsubq", binary OpCompute 0b001000111u quad quad quad
    "fmuls", binary OpCompute 0b001001001u single single single
    "fmuld", binary OpCompute 0b001001010u double double double
    "fmulq", binary OpCompute 0b001001011u quad quad quad
    "fdivs", binary OpCompute 0b001001101u single single single
    "fdivd", binary OpCompute 0b001001110u double double double
    "fdivq", binary OpCompute 0b001001111u quad quad quad
    "fsmuld", binary OpCompute 0b001101001u single single double
    "fdmulq", binary OpCompute 0b001101110u double double quad ]

/// <summary>
/// A comparison, which writes nothing but leaves in the set of condition bits
/// it names how what the two registers hold compare.
///
/// Which set that is lands where every other instruction keeps the register it
/// writes to, because a comparison writes to none.
/// </summary>
let private compare opf kind ins =
  match ins.Operands with
  | [ Cc cc; Rg s1; Rg s2 ] ->
    format3 2u OpDecide (floatCC cc) (kind s1) ((opf <<< 5) ||| kind s2)
  | _ ->
    wrongOperands ins

/// The comparisons, at each of the three widths and in the two kinds that
/// differ in what they do where one of the two is not a number at all.
let private compareEncoders () =
  [ "fcmps", compare 0b001010001u single
    "fcmpd", compare 0b001010010u double
    "fcmpq", compare 0b001010011u quad
    "fcmpes", compare 0b001010101u single
    "fcmped", compare 0b001010110u double
    "fcmpeq", compare 0b001010111u quad ]

/// <summary>
/// A move that happens only where the named condition holds.
///
/// Which condition it tests is written into the name and which set of bits it
/// is read off is the first operand, exactly as for the move between general
/// registers; what differs is that the set of bits lies below the condition
/// rather than around it.
/// </summary>
let private moveOnCondition kind width name ins =
  match ins.Operands with
  | [ Cc cc; Rg s2; Rg d ] ->
    let low = (ccThree cc <<< 11) ||| (width <<< 5) ||| kind s2
    format3 2u OpDecide (kind d) (conditionOf name cc) low
  | _ ->
    wrongOperands ins

/// A move that happens only where what a general register holds compares as the
/// name says against zero.
let private moveOnRegister kind width rcond ins =
  match ins.Operands with
  | [ Rg s1; Rg s2; Rg d ] ->
    let low = (rcond <<< 10) ||| (width <<< 5) ||| kind s2
    format3 2u OpDecide (kind d) (gpr s1) low
  | _ ->
    wrongOperands ins

/// <summary>
/// The floating-point moves that happen only where something holds.
///
/// The one moving a double-precision number where what a comparison of integers
/// left says it is above zero is written under the name of the one moving a
/// single-precision number, so that name covers both and which of the two a
/// line names is settled by the registers it works on.
/// </summary>
let private conditionalMoveEncoders () =
  [ for name, _, _ in conditions do
      let onSingle = moveOnCondition single 1u name
      let onDouble = moveOnCondition double 2u name
      if name = "pos" then yield "fmovs" + name, orTry onSingle onDouble
      else yield "fmovs" + name, onSingle
      yield "fmovd" + name, onDouble
      yield "fmovq" + name, moveOnCondition quad 3u name
    for _, name, rcond in registerConditions do
      yield "fmovrs" + name, moveOnRegister single 5u rcond
      yield "fmovrd" + name, moveOnRegister double 6u rcond
      yield "fmovrq" + name, moveOnRegister quad 7u rcond ]

/// <summary>
/// The instructions working on the two halves of a doubleword at once.
///
/// They were put where the machine a program runs on is left to say what an
/// instruction means, so a word reaching none of them is that instruction and
/// nothing more; two of them work on the general registers rather than the
/// floating-point ones, because what they compute is an address.
/// </summary>
let private wideEncoders () =
  [ "fzerod", binary OpWide 0b001100000u double double double
    "foned", binary OpWide 0b001111110u double double double
    "fsrc1d", binary OpWide 0b001110100u double double double
    "fsrc2d", binary OpWide 0b001111000u double double double
    "fnot1d", binary OpWide 0b001101010u double double double
    "fnot2d", binary OpWide 0b001100110u double double double
    "ford", binary OpWide 0b001111100u double double double
    "fnord", binary OpWide 0b001100010u double double double
    "fandd", binary OpWide 0b001110000u double double double
    "fnandd", binary OpWide 0b001101110u double double double
    "fxord", binary OpWide 0b001101100u double double double
    "fxnord", binary OpWide 0b001110010u double double double
    "fornot1d", binary OpWide 0b001111010u double double double
    "fornot2d", binary OpWide 0b001110110u double double double
    "fandnot1d", binary OpWide 0b001101000u double double double
    "fandnot2d", binary OpWide 0b001100100u double double double
    "faligndata", binary OpWide 0b001001000u double double double
    "alignaddr", binary OpWide 0b000011000u gpr gpr gpr
    "alignaddrl", binary OpWide 0b000011010u gpr gpr gpr ]

/// Every floating-point instruction, paired with the encoder for it.
let floatEncoders () =
  [ unaryEncoders ()
    binaryEncoders ()
    compareEncoders ()
    conditionalMoveEncoders ()
    wideEncoders () ]
  |> List.concat

// vim: set tw=80 sts=2 sw=2:
