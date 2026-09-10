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


/// Provides the pieces every eBPF lifter shares: the values its operands stand
/// for, the width the class an instruction belongs to computes in, and the
/// byte orders the instructions naming one convert between.
module internal B2R2.FrontEnd.BPF.LiftHelper

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils

/// A quadword constant, which is the width of every eBPF register.
let inline num64 (n: int) = numI32 n 64<rt>

/// Returns the one operand of an instruction that has one.
let getOneOpr (ins: Instruction) =
  match ins.Operands with
  | OneOperand o -> o
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

/// Returns the register a register operand names.
let getReg opr =
  match opr with
  | OprReg r -> r
  | _ -> raise InvalidOperandException

/// Returns the register variable a register operand names.
let regOf bld opr = regVar bld (getReg opr)

/// Returns the bits a number operand holds.
let getImm opr =
  match opr with
  | OprImm imm -> imm
  | _ -> raise InvalidOperandException

/// Narrows a quadword to the width a load, a store, or an atomic store
/// reaches, which is the whole of it where that width is a quadword.
let narrow size v = if size = 64<rt> then v else AST.xtlo size v

/// Widens what a load or an atomic store read to the quadword a register
/// holds, bringing in zeroes, which is nothing at all where the width read is
/// a quadword already.
let widen size v = if size = 64<rt> then v else AST.zext 64<rt> v

/// The address the instruction after this one sits at, which is where every
/// jump counts its distance from and what a call comes back to.
let nextAddr (ins: Instruction) = ins.Address + uint64 ins.Length

/// <summary>
/// Returns the address a jump names: the distance it holds, counted from the
/// instruction after it.
///
/// The parser has already widened the field and scaled it from the
/// instructions the encoding counts to the bytes an address counts, so what is
/// left here is the addition the machine performs.
/// </summary>
let jumpTarget (ins: Instruction) opr =
  match opr with
  | OprAddr rel -> nextAddr ins + uint64 rel
  | _ -> raise InvalidOperandException

/// <summary>
/// Returns the value a number written in an instruction stands for, widened to
/// a quadword.
///
/// The field is thirty-two bits and the machine widens what it holds as
/// signed, which is what makes `add %r0, -1` a subtraction of one rather than
/// of four thousand million. The parser keeps the bits rather than what they
/// stand for, so the widening happens here.
/// </summary>
let immSExt (imm: Imm) = numI64 (int64 (int32 (uint32 imm))) 64<rt>

/// <summary>
/// Returns the value an operand stands for, in the width the class the
/// instruction naming it belongs to computes in.
///
/// An instruction of the thirty-two bit class reads the lower half of a
/// register and the lower half of a number alike, so the two narrow together
/// and nothing downstream of this has to know which it was handed.
/// </summary>
let srcOf bld rt opr =
  match opr with
  | OprReg r when rt = 64<rt> -> regVar bld r
  | OprReg r -> AST.xtlo 32<rt> (regVar bld r)
  | OprImm imm when rt = 64<rt> -> immSExt imm
  | OprImm imm -> numU32 (uint32 imm) 32<rt>
  | _ -> raise InvalidOperandException

/// <summary>
/// Emits the write of a computed value to the register an instruction names.
///
/// An instruction of the thirty-two bit class clears the upper half of the
/// register it writes, so a lifter computes in the width its class names and
/// leaves the widening to this rather than repeating it in every one of them.
/// </summary>
let dstWrite bld rt opr v =
  let r = regVar bld (getReg opr)
  if rt = 64<rt> then
    append bld { r := v }
  else
    append bld { r := AST.zext 64<rt> v }

/// <summary>
/// Returns the address a memory operand names, computed into a temporary.
///
/// A temporary rather than the expression itself, so that an atomic store --
/// which reaches the same place to read it and to write it back -- names one
/// address computed once rather than two that only happen to agree.
/// </summary>
let effectiveAddr bld opr =
  match opr with
  | OprMem(b, disp) ->
    let t = tmpVar bld 64<rt>
    append bld { t := regVar bld b .+ num64 disp }
    t
  | _ ->
    raise InvalidOperandException

/// <summary>
/// Reverses the bytes of a value of the given width.
///
/// The bytes are gathered rather than shifted together, so that what an
/// instruction naming a byte order comes to is one concatenation of extracts;
/// that folds to a constant where the value it reverses is one.
/// </summary>
let swapBytes rt v =
  let n = RegType.toByteWidth rt
  AST.revConcat (Array.init n (fun i -> AST.extract v 8<rt> ((n - 1 - i) * 8)))

/// <summary>
/// Converts a value of the given width to the byte order named, which is a
/// reversal on a machine of the other order and nothing at all on one of the
/// same order.
///
/// These instructions are defined against the byte order of the machine
/// running the program, and eBPF is built for both, so which of the two ends
/// up a no-op is a property of the ISA being lifted rather than of the
/// instruction being lifted.
/// </summary>
let toOrder (bld: ILowUIRBuilder) order rt v =
  if bld.Endianness = order then v else swapBytes rt v

// vim: set tw=80 sts=2 sw=2:
