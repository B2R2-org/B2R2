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
/// Encodes one instruction of the floating-point unit into the word that means
/// it. What sets these apart from the instructions beside them is that the
/// format their operands are read in is written into the mnemonic, and where
/// that format sits in the encoding differs between the two spaces the unit
/// has.
/// </summary>
module internal B2R2.Assembly.MIPS.AsmFloat

open B2R2.FrontEnd.MIPS
open B2R2.Assembly.MIPS.ParserHelper
open B2R2.Assembly.MIPS.AsmField

/// <summary>
/// The five bits above the registers, which say the format the operands of an
/// instruction of the first space are read in.
///
/// Only the two kinds of floating-point number are named here: a fixed-point
/// one is something the unit converts to and from rather than works on, so
/// every instruction but a conversion leaves those two out.
/// </summary>
let private floatFormat ins =
  match ins.Fmt with
  | Some FPRFormat.S -> 0b10000u
  | Some FPRFormat.D -> 0b10001u
  | Some fmt -> fail $"{ins.Opcode} is not read in the {fmt} format"
  | None -> fail $"{ins.Opcode} is written with the format it reads"

/// The same field for a conversion, which reads a fixed-point number as well.
let private convertFormat ins =
  match ins.Fmt with
  | Some FPRFormat.W -> 0b10100u
  | Some FPRFormat.L -> 0b10101u
  | _ -> floatFormat ins

/// Encodes <fd>, <fs>, <ft>: the arithmetic on two floating-point numbers.
let private arith3 func ins =
  match ins.Operands with
  | ThreeOperands(Rg fd, Rg fs, Rg ft) ->
    word 0b010001u (floatFormat ins) (fpr ft) (fpr fs) (fpr fd) func
  | _ ->
    wrongOperands ins

/// Encodes <fd>, <fs>: the arithmetic on one of them, and the truncations
/// towards zero that turn one into a fixed-point number.
let private arith2 func ins =
  match ins.Operands with
  | TwoOperands(Rg fd, Rg fs) ->
    word 0b010001u (floatFormat ins) 0u (fpr fs) (fpr fd) func
  | _ ->
    wrongOperands ins

/// Encodes <fd>, <fs>: turning a number of one kind into a number of another.
/// The name says which kind it becomes and the suffix says which kind it was,
/// so the two cannot be the same.
let private convert into func ins =
  match ins.Operands with
  | TwoOperands(Rg fd, Rg fs) ->
    let fmt = convertFormat ins
    if fmt = into then fail $"{ins.Opcode} cannot read what it writes"
    else word 0b010001u fmt 0u (fpr fs) (fpr fd) func
  | _ ->
    wrongOperands ins

/// Encodes <fd>, <fs>, <cc>: a move that happens only where the condition the
/// source names holds, or only where it does not.
let private moveOnCondition tf ins =
  match ins.Operands with
  | ThreeOperands(Rg fd, Rg fs, Im cc) ->
    let rt = (unsigned 3 cc <<< 2) ||| tf
    word 0b010001u (floatFormat ins) rt (fpr fs) (fpr fd) 0b010001u
  | _ ->
    wrongOperands ins

/// Encodes <fd>, <fs>, <rt>: a move that happens only where a general register
/// holds zero, or only where it does not.
let private moveOnZero func ins =
  match ins.Operands with
  | ThreeOperands(Rg fd, Rg fs, Rg rt) ->
    word 0b010001u (floatFormat ins) (gpr rt) (fpr fs) (fpr fd) func
  | _ ->
    wrongOperands ins

/// Encodes <fs>, <ft> and <cc>, <fs>, <ft>: the compare, which writes what it
/// found into one of the eight places the unit keeps a condition in and names
/// that place only where it is not the first of them.
let private compare ins =
  let func =
    match ins.Condition with
    | Some cond -> 0b110000u ||| uint32 (int cond)
    | None -> fail $"{ins.Opcode} is written with the condition it tests"
  match ins.Operands with
  | TwoOperands(Rg fs, Rg ft) ->
    word 0b010001u (floatFormat ins) (fpr ft) (fpr fs) 0u func
  | ThreeOperands(Im cc, Rg fs, Rg ft) ->
    let sa = unsigned 3 cc <<< 2
    word 0b010001u (floatFormat ins) (fpr ft) (fpr fs) sa func
  | _ ->
    wrongOperands ins

/// Encodes <rt>, <fs>: the moves of a word between a general register and a
/// register of the unit, and the reads and the writes of the registers that say
/// how the unit is set up.
let private moveBetween rs ins =
  match ins.Operands with
  | TwoOperands(Rg rt, Rg fs) -> word 0b010001u rs (gpr rt) (fpr fs) 0u 0u
  | _ -> wrongOperands ins

/// Encodes <place> and <cc>, <place>: a branch on a condition the unit found
/// earlier, which names which of the eight places for one it reads only where
/// that is not the first of them.
let private branchOnFP tf ins =
  match ins.Operands with
  | OneOperand(Place distance) ->
    immWord 0b010001u 0b01000u tf (branchOffset distance)
  | TwoOperands(Im cc, Place distance) ->
    let rt = (unsigned 3 cc <<< 2) ||| tf
    immWord 0b010001u 0b01000u rt (branchOffset distance)
  | _ ->
    wrongOperands ins

(* The second space of the unit, which reaches memory at a distance a register
   holds and multiplies three numbers at once. Its instructions say the format
   they are read in at the bottom of the word rather than above the registers,
   because what sits above them there is a register of its own. *)
/// Encodes <fd>, <index>(<base>): the loads that name where to read in a
/// register rather than in the instruction.
let private loadIndexed func ins =
  match ins.Operands with
  | TwoOperands(Rg fd, MemIdx(baseReg, index)) ->
    word 0b010011u (gpr baseReg) (gpr index) 0u (fpr fd) func
  | _ ->
    wrongOperands ins

/// Encodes <fs>, <index>(<base>): the stores that name it the same way.
let private storeIndexed func ins =
  match ins.Operands with
  | TwoOperands(Rg fs, MemIdx(baseReg, index)) ->
    word 0b010011u (gpr baseReg) (gpr index) (fpr fs) 0u func
  | _ ->
    wrongOperands ins

/// <summary>
/// Encodes &lt;hint&gt;, &lt;index&gt;(&lt;base&gt;): the word that a place is
/// about to be read, which names it the same way.
///
/// What to do with the place and which register holds the distance to it are
/// one field, so a source naming two different things there asks for an
/// instruction there is no room to encode.
/// </summary>
let private prefetchIndexed ins =
  match ins.Operands with
  | TwoOperands(Im hint, MemIdx(baseReg, index)) ->
    let field = gpr index
    if unsigned 5 hint = field then
      word 0b010011u (gpr baseReg) field 0u 0u 0b001111u
    else
      fail "a prefetch says what to do and where to read in one field"
  | _ ->
    wrongOperands ins

/// The three bits at the bottom of the function field that say the format a
/// multiply of three numbers is read in, which is a pair of them as well as
/// the two kinds of single number.
let private wideFormat ins =
  match ins.Fmt with
  | Some FPRFormat.S -> 0b000u
  | Some FPRFormat.D -> 0b001u
  | Some FPRFormat.PS -> 0b110u
  | Some fmt -> fail $"{ins.Opcode} is not read in the {fmt} format"
  | None -> fail $"{ins.Opcode} is written with the format it reads"

/// Encodes <fd>, <fr>, <fs>, <ft>: a multiply whose product is added to a third
/// number before anything is rounded.
let private multiplyAdd func ins =
  match ins.Operands with
  | FourOperands(Rg fd, Rg fr, Rg fs, Rg ft) ->
    word 0b010011u (fpr fr) (fpr ft) (fpr fs) (fpr fd) (func ||| wideFormat ins)
  | _ ->
    wrongOperands ins

let floatEncoders () =
  [ Opcode.ADD, arith3 0b000000u
    Opcode.SUB, arith3 0b000001u
    Opcode.MUL, arith3 0b000010u
    Opcode.DIV, arith3 0b000011u
    Opcode.SQRT, arith2 0b000100u
    Opcode.ABS, arith2 0b000101u
    Opcode.MOV, arith2 0b000110u
    Opcode.NEG, arith2 0b000111u
    Opcode.TRUNCL, arith2 0b001001u
    Opcode.TRUNCW, arith2 0b001101u
    Opcode.RECIP, arith2 0b010101u
    Opcode.RSQRT, arith2 0b010110u
    Opcode.CVTS, convert 0b10000u 0b100000u
    Opcode.CVTD, convert 0b10001u 0b100001u
    Opcode.MOVF, moveOnCondition 0u
    Opcode.MOVT, moveOnCondition 1u
    Opcode.MOVZ, moveOnZero 0b010010u
    Opcode.MOVN, moveOnZero 0b010011u
    Opcode.C, compare
    Opcode.MFC1, moveBetween 0b00000u
    Opcode.DMFC1, moveBetween 0b00001u
    Opcode.CFC1, moveBetween 0b00010u
    Opcode.MFHC1, moveBetween 0b00011u
    Opcode.MTC1, moveBetween 0b00100u
    Opcode.DMTC1, moveBetween 0b00101u
    Opcode.CTC1, moveBetween 0b00110u
    Opcode.MTHC1, moveBetween 0b00111u
    Opcode.BC1F, branchOnFP 0u
    Opcode.BC1T, branchOnFP 1u
    Opcode.LWXC1, loadIndexed 0b000000u
    Opcode.LDXC1, loadIndexed 0b000001u
    Opcode.SWXC1, storeIndexed 0b001000u
    Opcode.SDXC1, storeIndexed 0b001001u
    Opcode.PREFX, prefetchIndexed
    Opcode.MADD, multiplyAdd 0b100000u
    Opcode.MSUB, multiplyAdd 0b101000u
    Opcode.NMADD, multiplyAdd 0b110000u ]
