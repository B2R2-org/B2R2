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

module internal B2R2.FrontEnd.PPC.Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils

let transRegister bld = function
  | Register.CR0_0 -> AST.extract (regVar bld Register.CR0) 1<rt> 3
  | Register.CR0_1 -> AST.extract (regVar bld Register.CR0) 1<rt> 2
  | Register.CR0_2 -> AST.extract (regVar bld Register.CR0) 1<rt> 1
  | Register.CR0_3 -> AST.extract (regVar bld Register.CR0) 1<rt> 0
  | Register.CR1_0 -> AST.extract (regVar bld Register.CR1) 1<rt> 3
  | Register.CR1_1 -> AST.extract (regVar bld Register.CR1) 1<rt> 2
  | Register.CR1_2 -> AST.extract (regVar bld Register.CR1) 1<rt> 1
  | Register.CR1_3 -> AST.extract (regVar bld Register.CR1) 1<rt> 0
  | Register.CR2_0 -> AST.extract (regVar bld Register.CR2) 1<rt> 3
  | Register.CR2_1 -> AST.extract (regVar bld Register.CR2) 1<rt> 2
  | Register.CR2_2 -> AST.extract (regVar bld Register.CR2) 1<rt> 1
  | Register.CR2_3 -> AST.extract (regVar bld Register.CR2) 1<rt> 0
  | Register.CR3_0 -> AST.extract (regVar bld Register.CR3) 1<rt> 3
  | Register.CR3_1 -> AST.extract (regVar bld Register.CR3) 1<rt> 2
  | Register.CR3_2 -> AST.extract (regVar bld Register.CR3) 1<rt> 1
  | Register.CR3_3 -> AST.extract (regVar bld Register.CR3) 1<rt> 0
  | Register.CR4_0 -> AST.extract (regVar bld Register.CR4) 1<rt> 3
  | Register.CR4_1 -> AST.extract (regVar bld Register.CR4) 1<rt> 2
  | Register.CR4_2 -> AST.extract (regVar bld Register.CR4) 1<rt> 1
  | Register.CR4_3 -> AST.extract (regVar bld Register.CR4) 1<rt> 0
  | Register.CR5_0 -> AST.extract (regVar bld Register.CR5) 1<rt> 3
  | Register.CR5_1 -> AST.extract (regVar bld Register.CR5) 1<rt> 2
  | Register.CR5_2 -> AST.extract (regVar bld Register.CR5) 1<rt> 1
  | Register.CR5_3 -> AST.extract (regVar bld Register.CR5) 1<rt> 0
  | Register.CR6_0 -> AST.extract (regVar bld Register.CR6) 1<rt> 3
  | Register.CR6_1 -> AST.extract (regVar bld Register.CR6) 1<rt> 2
  | Register.CR6_2 -> AST.extract (regVar bld Register.CR6) 1<rt> 1
  | Register.CR6_3 -> AST.extract (regVar bld Register.CR6) 1<rt> 0
  | Register.CR7_0 -> AST.extract (regVar bld Register.CR7) 1<rt> 3
  | Register.CR7_1 -> AST.extract (regVar bld Register.CR7) 1<rt> 2
  | Register.CR7_2 -> AST.extract (regVar bld Register.CR7) 1<rt> 1
  | Register.CR7_3 -> AST.extract (regVar bld Register.CR7) 1<rt> 0
  | reg -> regVar bld reg

let transOperand bld = function
  | OprReg reg -> transRegister bld reg
  | OprImm imm -> numU64 imm bld.RegType
  | OprAddr addr -> numU64 addr 64<rt>
  | OprCY cy -> numU32 (cy |> uint32) 2<rt>
  | OprL l -> numU32 (l |> uint32) 2<rt>
  | _ -> Terminator.futureFeature ()

let transThreeOperands bld = function
  | ThreeOperands(opr1, opr2, opr3) ->
    transOperand bld opr1, transOperand bld opr2, transOperand bld opr3
  | _ -> raise InvalidOperandException

let add (ins: Instruction) insLen bld =
  let dst, src1, src2 = transThreeOperands bld ins.Operands
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := src1 .+ src2)
  bld --!> insLen

let translate (ins: Instruction) insLen bld =
  match ins.Opcode with
  | Op.ADD -> add ins insLen bld
  | o -> raise (NotImplementedIRException(Disasm.opCodeToString o))
