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
/// Lifts the instructions of Variable Length Encoding (VLE) that have no
/// instruction of the base encoding to be lifted as. The rest are lifted by
/// the lifter of the instruction they are another encoding of, which is the
/// Power ISA's own statement that they mean the same.
/// </summary>
module internal B2R2.FrontEnd.PPC.VLELifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC
open B2R2.FrontEnd.PPC.LiftingUtils

/// What an instruction made only to be lifted holds in place of the lifter of
/// instructions, which it is never asked for.
let private noLifter = Unchecked.defaultof<ILiftable>

/// <summary>
/// The instruction of the base encoding that a VLE instruction is another
/// encoding of, given the operands that instruction takes. The lifters of the
/// base encoding read only the address, the length and the operands of what
/// they lift, so what they lift here is the same operation with the same
/// statements, which is the Power ISA's own statement that the two mean the
/// same.
/// </summary>
let private asBase (ins: Instruction) operands =
  let size, ea = ins.OperationSize, ins.EffectiveAddress
  Instruction(ins.Address, ins.Length, ins.Opcode, operands, size, ea, noLifter)

/// RX = f(RX, RY), as the instruction of three registers that names RX twice
/// does.
let dyadic (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(rx, ry) -> asBase ins (ThreeOperands(rx, rx, ry))
  | _ -> raise InvalidOperandException

/// RX = f(RY, RX), which is what a subtraction of RY from RX asks of the
/// instruction that subtracts its first source from its second.
let reversed (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(rx, ry) -> asBase ins (ThreeOperands(rx, ry, rx))
  | _ -> raise InvalidOperandException

/// RX = f(RX), as the instruction of two registers that names RX twice does.
let monadic (ins: Instruction) =
  match ins.Operands with
  | OneOperand rx -> asBase ins (TwoOperands(rx, rx))
  | _ -> raise InvalidOperandException

/// RX = f(RX, RX), as the instruction of three registers that names RX three
/// times does, which is how the base encoding complements a register.
let repeated (ins: Instruction) =
  match ins.Operands with
  | OneOperand rx -> asBase ins (ThreeOperands(rx, rx, rx))
  | _ -> raise InvalidOperandException

/// RX with all but the bits from n to 31 of its low word cleared, as the
/// rotate by nothing that keeps those bits does.
let clearLeft (ins: Instruction) n =
  match ins.Operands with
  | OneOperand rx ->
    asBase ins (FiveOperands(rx, rx, OprImm 0UL, OprImm n, OprImm 31UL))
  | _ ->
    raise InvalidOperandException

/// RX = RX + a number.
let addImmediate (ins: Instruction) (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (dst, imm) = transTwoOprs ins bld
    dst := dst .+ imm
  }

/// RX = RX - a number, which records CR0 where the instruction says so.
let subtractImmediate (ins: Instruction) (bld: ILowUIRBuilder) record =
  lift bld ins {
    let struct (dst, imm) = transTwoOprs ins bld
    dst := dst .- imm
    if record then setCR0Reg bld dst else ()
  }

/// RX = RX & a number.
let andImmediate (ins: Instruction) (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (dst, imm) = transTwoOprs ins bld
    dst := dst .& imm
  }

/// se_illegal, which asks for an Illegal Instruction exception.
let illegal ins bld = sideEffects ins bld UndefinedInstruction

/// A branch to the address in a register, whose low bit is the only one it
/// clears: an instruction sits on a halfword, so the bit below that is not
/// masked as the base encoding masks it. A branch that links writes the
/// address of the instruction after it, which is two bytes on, only once it
/// has read where it goes.
let branchToRegister (ins: Instruction) (bld: ILowUIRBuilder) reg link =
  lift bld ins {
    let rt = bld.RegType
    let target = tmpVar bld rt
    target := regVar bld reg .& AST.not (AST.num1 rt)
    if link then
      regVar bld Register.LR := numU64 (ins.Address + uint64 ins.Length) rt
      AST.interjmp target InterJmpKind.IsCall
    elif reg = Register.LR then
      AST.interjmp target InterJmpKind.IsRet
    else
      AST.interjmp target InterJmpKind.Base
  }
