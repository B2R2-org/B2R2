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

module internal B2R2.Assembly.MIPS.ParserHelper

open System.Runtime.CompilerServices
open B2R2
open B2R2.FrontEnd.MIPS

[<assembly: InternalsVisibleTo("B2R2.Assembly.Tests")>]
do ()

type AsmInsInfo =
  { Address: Addr
    Length: uint32
    Opcode: Opcode
    Operands: Operands
    Condition: Condition option
    Fmt: FPRFormat option
    OperationSize: RegType }

let extractOperands = function
  | [] -> NoOperand
  | [ op1 ] -> OneOperand op1
  | [ op1; op2 ] -> TwoOperands(op1, op2)
  | [ op1; op2; op3 ] -> ThreeOperands(op1, op2, op3)
  | [ op1; op2; op3; op4 ] -> FourOperands(op1, op2, op3, op4)
  | _ -> failwith "Operand overload"

let getOperandsAsList operands =
  match operands with
  | NoOperand -> []
  | OneOperand(op1) -> [ op1 ]
  | TwoOperands(op1, op2) -> [ op1; op2 ]
  | ThreeOperands(op1, op2, op3) -> [ op1; op2; op3 ]
  | FourOperands(op1, op2, op3, op4) -> [ op1; op2; op3; op4 ]

let getOperationSize opcode wordSz =
  match opcode with
  | Opcode.SB -> 8<rt>
  | Opcode.SH -> 16<rt>
  | Opcode.SW -> 32<rt>
  | Opcode.SD -> 64<rt>
  | _ -> WordSize.toRegType wordSz

let getRealRegName = function
  | "zero" -> "R0"
  | "at" -> "R1"
  | "v0" -> "R2"
  | "v1" -> "R3"
  | "a0" -> "R4"
  | "a1" -> "R5"
  | "a2" -> "R6"
  | "a3" -> "R7"
  | "t0" -> "R8"
  | "t1" -> "R9"
  | "t2" -> "R10"
  | "t3" -> "R11"
  | "t4" -> "R12"
  | "t5" -> "R13"
  | "t6" -> "R14"
  | "t7" -> "R15"
  | "s0" -> "R16"
  | "s1" -> "R17"
  | "s2" -> "R18"
  | "s3" -> "R19"
  | "s4" -> "R20"
  | "s5" -> "R21"
  | "s6" -> "R22"
  | "s7" -> "R23"
  | "t8" -> "R24"
  | "t9" -> "R25"
  | "k0" -> "R26"
  | "k1" -> "R27"
  | "gp" -> "R28"
  | "sp" -> "R29"
  | "fp" -> "R30"
  | "ra" -> "R31"
  | other -> other.ToUpper()

let newAssemblyIns (isa: ISA) address opcode condition fmt operands =
  let oprSize = getOperationSize opcode isa.WordSize
  { Address = address
    Length = 4u
    Opcode = opcode
    Operands = operands
    Condition = condition
    Fmt = fmt
    OperationSize = oprSize }
