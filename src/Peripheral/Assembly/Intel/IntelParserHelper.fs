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

module B2R2.Peripheral.Assembly.Intel.ParserHelper

open B2R2
open B2R2.FrontEnd.Intel

type AsmInsInfo = {
  Prefixes: Prefix
  REXPrefix: REXPrefix
  VEXInfo: VEXInfo option
  Opcode: Opcode
  Operands: Operands
}

/// AssemblyLine is either a label or an instruction.
type AssemblyLine =
  | LabelDefLine
  | InstructionLine of AsmInsInfo

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
  | _ -> Utils.impossible ()

let getOperandsAsList operands =
  match operands with
  | NoOperand -> []
  | OneOperand (op1) -> [op1]
  | TwoOperands (op1, op2) -> [op1; op2]
  | ThreeOperands (op1, op2, op3) -> [op1; op2; op3]
  | FourOperands (op1, op2, op3, op4) -> [op1; op2; op3; op4]

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
  | _ -> Utils.impossible ()

let prefixFromRegString (str: string) =
  match str.ToLowerInvariant () with
  | "cs" -> Prefix.PrxCS
  | "ds" -> Prefix.PrxDS
  | "es" -> Prefix.PrxES
  | "fs" -> Prefix.PrxFS
  | "gs" -> Prefix.PrxGS
  | "ss" -> Prefix.PrxSS
  | _ -> Utils.impossible ()

let newInfo prfxs rexPrfx vexInfo opc operands =
  { Prefixes = prfxs
    REXPrefix = rexPrfx
    VEXInfo = vexInfo
    Opcode = opc
    Operands = operands }
