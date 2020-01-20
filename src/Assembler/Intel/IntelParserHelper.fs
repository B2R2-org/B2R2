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

module B2R2.Assembler.Intel.ParserHelper

open B2R2
open B2R2.FrontEnd.Intel

type AssemblyLine =
  | LabelDefLine
  | InstructionLine of InsInfo

let checkIfInstructionLine = function
  | InstructionLine ins -> Some ins
  | LabelDefLine -> None

let filterInstructionLines lst =
  List.choose checkIfInstructionLine lst

let extractOperands = function
  | [] -> NoOperand
  | [op1] -> OneOperand op1
  | [op1; op2] -> TwoOperands (op1, op2)
  | [op1; op2; op3] -> ThreeOperands (op1, op2, op3)
  | [op1; op2; op3; op4] -> FourOperands (op1, op2, op3, op4)
  | _ -> failwith "Operand overload"

let getOperandsAsList operands =
  match operands with
  | NoOperand -> []
  | OneOperand (op1) -> [op1]
  | TwoOperands (op1, op2) -> [op1; op2]
  | ThreeOperands (op1, op2, op3) -> [op1; op2; op3]
  | FourOperands (op1, op2, op3, op4) -> [op1; op2; op3; op4]

let isCallOrJmpOpcode = function
  | Opcode.CALLFar
  | Opcode.CALLNear
  | Opcode.JA
  | Opcode.JB
  | Opcode.JBE
  | Opcode.JCXZ
  | Opcode.JECXZ
  | Opcode.JG
  | Opcode.JL
  | Opcode.JLE
  | Opcode.JMPFar
  | Opcode.JMPNear
  | Opcode.JNB
  | Opcode.JNL
  | Opcode.JNO
  | Opcode.JNP
  | Opcode.JNS
  | Opcode.JNZ
  | Opcode.JO
  | Opcode.JP
  | Opcode.JRCXZ
  | Opcode.JS
  | Opcode.JZ -> true
  | _ -> false

let ptrStringToBitSize = function
  | "byte ptr" -> 1 * 8<rt>
  | "word ptr" -> 2 * 8<rt>
  | "word far ptr" | "dword ptr" -> 4 * 8<rt>
  | "dword far ptr" -> 6 * 8<rt>
  | "qword ptr" -> 8 * 8<rt>
  | "qword far ptr" | "tword ptr" -> 10 * 8<rt>
  | "xmmword ptr" -> 16 * 8<rt>
  | "ymmword ptr" -> 32 * 8<rt>
  | "zmmword ptr" -> 64 * 8<rt>
  | _ -> failwith "invalid pointer string"

let prefixFromRegString (str: string) =
  match str.ToLower () with
  | "cs" -> Prefix.PrxCS
  | "ds" -> Prefix.PrxCS
  | "es" -> Prefix.PrxCS
  | "fs" -> Prefix.PrxCS
  | "gs" -> Prefix.PrxCS
  | "ss" -> Prefix.PrxCS
  | _ -> failwith "invalid segment register string"

let dummyRegType = 0<rt>
let dummyMemorySize =
  { EffOprSize = dummyRegType
    EffAddrSize = dummyRegType
    EffRegSize = dummyRegType }
let dummyInsSize =
  { MemSize = dummyMemorySize
    RegSize = dummyRegType
    OperationSize = dummyRegType
    SizeCond = SizeCond.Sz64 }

let newInfo prfxs rexPrfx vexInfo opc operands size =
  { Prefixes = prfxs
    REXPrefix = rexPrfx
    VEXInfo = vexInfo
    Opcode = opc
    Operands = operands
    InsSize = size }
