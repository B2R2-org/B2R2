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

/// Provides the pieces every Alpha lifter shares: the values its operands
/// stand for, the address a memory operand names, and the byte masks the
/// instructions reaching inside a quadword are defined by.
module internal B2R2.FrontEnd.Alpha.LiftHelper

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils

/// A quadword constant, which is the width of every Alpha register.
let inline num64 (n: int) = numI32 n 64<rt>

/// The register that always reads as zero, which is R31 among the general
/// registers and F31 among the floating-point ones.
let private isZeroReg reg = reg = Register.R31 || reg = Register.F31

/// <summary>
/// Returns the value a register operand holds. R31 and F31 read as zero
/// however they are written to, so they are the constant rather than a
/// variable: folding them here is what turns the architecture's idioms into
/// the plain statements they mean, so that BIS R31, R31, Rc reads as a clear
/// rather than as a logical sum of two register reads.
/// </summary>
let regRead bld reg =
  if isZeroReg reg then AST.num0 64<rt> else regVar bld reg

/// <summary>
/// Returns the value an operand stands for, whether that is a register, the
/// number an Operate instruction holds where a second register would, or the
/// address a memory operand names.
///
/// A literal is written in the encoding as eight bits and is what the machine
/// widens to a whole word with zeros, so that is what it becomes here.
/// </summary>
let transOpr bld opr =
  match opr with
  | OprReg r -> regRead bld r
  | OprImm imm -> numU64 imm 64<rt>
  | OprMem(b, disp) -> regRead bld b .+ num64 disp
  | OprBase b -> regRead bld b
  | OprAddr _ -> raise InvalidOperandException

/// <summary>
/// Emits the write of a value to a register operand, which is nothing at all
/// where the register named is the one that always reads as zero.
///
/// Dropping the write is not an optimization but the architecture: a result
/// sent to R31 or F31 is discarded, and an instruction whose only effect is
/// that write is how Alpha spells a no-op.
/// </summary>
let regWrite bld reg v =
  if isZeroReg reg then () else append bld { regVar bld reg := v }

/// Returns the register a register operand names.
let getReg opr =
  match opr with
  | OprReg r -> r
  | _ -> raise InvalidOperandException

/// Returns the two operands of an instruction that has two.
let getTwoOprs (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(o1, o2) -> struct (o1, o2)
  | _ -> raise InvalidOperandException

/// Returns the three operands of an instruction that has three.
let getThreeOprs (ins: Instruction) =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) -> struct (o1, o2, o3)
  | _ -> raise InvalidOperandException

/// Returns the one operand of an instruction that has one.
let getOneOpr (ins: Instruction) =
  match ins.Operands with
  | OneOperand o -> o
  | _ -> raise InvalidOperandException

/// The address the instruction after this one sits at, which is where a branch
/// counts its displacement from and what a call keeps as its return address.
let nextAddr (ins: Instruction) = ins.Address + uint64 ins.Length

/// <summary>
/// Returns the address a branch names: its displacement counted from the
/// instruction after it.
///
/// The parser has already widened the field and scaled it to bytes, so what is
/// left is the addition the machine performs.
/// </summary>
let branchTarget (ins: Instruction) =
  match getTwoOprs ins with
  | struct (_, OprAddr disp) -> nextAddr ins + uint64 (int64 disp)
  | _ -> raise InvalidOperandException

/// The bytes a mask names, gathered as one expression over the mask itself.
let private expandMask (mask: Expr) =
  let zero = AST.num0 64<rt>
  let mutable acc = zero
  for i in 0 .. 7 do
    let bit = AST.xtlo 1<rt> (mask >> num64 i)
    let bytes = numU64 (0xffUL <<< (i * 8)) 64<rt>
    acc <- acc .| AST.ite bit bytes zero
  acc

/// <summary>
/// Expands an eight-bit byte mask into the quadword that keeps exactly the
/// bytes it names.
///
/// The instructions reaching inside a quadword are all defined in terms of
/// BYTE_ZAP, which is a mask over bytes rather than over bits, so every one of
/// them ends up here.
///
/// A mask the encoding states outright is expanded as one expression, which
/// folds to the single constant it is -- that is what turns the zapnot a
/// compiler emits to widen a longword into one masking instruction. A computed
/// one goes through a temporary instead, so that the eight bytes read the
/// shift once rather than each recomputing it.
/// </summary>
let byteMaskToBits bld (mask: Expr) =
  match mask with
  | Num _ ->
    expandMask mask
  | _ ->
    let m = tmpVar bld 64<rt>
    let acc = tmpVar bld 64<rt>
    append bld { m := mask }
    append bld { acc := expandMask m }
    acc

/// <summary>
/// The mask that keeps the low bytes of a quadword, of which there are as many
/// as the given size holds.
///
/// This is the byte_mask the extract, insert and mask instructions name in
/// their function code, before it is moved to where the shift amount puts it.
/// </summary>
let sizeMask (size: RegType) =
  match size with
  | 8<rt> -> 0x1UL
  | 16<rt> -> 0x3UL
  | 32<rt> -> 0xfUL
  | 64<rt> -> 0xffUL
  | _ -> raise InvalidOperandSizeException

/// <summary>
/// How far the low form of an extract, insert or mask shifts, which is the
/// byte the low three bits of its second operand name counted in bits.
/// </summary>
let lowShift src = (src .& num64 0x7) .* num64 8

/// <summary>
/// How far the high form shifts, which is what is left of a quadword above
/// that same byte.
///
/// The architecture writes the amount as sixty-four less the byte position and
/// then takes its low six bits, so a position of zero shifts by nothing rather
/// than by the whole word -- which is the case the plain subtraction gets
/// wrong, and the one an aligned access takes.
/// </summary>
let highShift src =
  (num64 64 .- ((src .& num64 0x7) .* num64 8)) .& num64 0x3f

/// <summary>
/// The number of bits set in a quadword, counted by folding the value through
/// the usual halving masks.
///
/// The three instructions counting bits all end up here: how many are set is
/// what CTPOP asks for outright, and the other two ask it of a value they have
/// reshaped first.
/// </summary>
let popCount bld src =
  let m1 = numU64 0x5555555555555555UL 64<rt>
  let m2 = numU64 0x3333333333333333UL 64<rt>
  let m4 = numU64 0x0f0f0f0f0f0f0f0fUL 64<rt>
  let m8 = numU64 0x0101010101010101UL 64<rt>
  let t = tmpVar bld 64<rt>
  append bld {
    t := src
    t := t .- ((t >> num64 1) .& m1)
    t := (t .& m2) .+ ((t >> num64 2) .& m2)
    t := (t .+ (t >> num64 4)) .& m4
    t := t .* m8
  }
  t >> num64 56

/// <summary>
/// Smears the highest set bit of a quadword down through every bit below it,
/// leaving as many bits set as there are from that bit down.
///
/// Counting the zeros above the highest set bit is then counting the bits this
/// leaves and taking that from sixty-four, which is how CTLZ is had without an
/// operator of its own.
/// </summary>
let smearHighBit bld src =
  let t = tmpVar bld 64<rt>
  append bld {
    t := src
    for step in [ 1; 2; 4; 8; 16; 32 ] do
      t := t .| (t >> num64 step)
  }
  t

// vim: set tw=80 sts=2 sw=2:
