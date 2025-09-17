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

module internal B2R2.FrontEnd.PPC.ParsingMain

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.ParsingUtils

let getRegister (n: uint32) =
  match n with
  | 0u -> Register.R0
  | 1u -> Register.R1
  | 2u -> Register.R2
  | 3u -> Register.R3
  | 4u -> Register.R4
  | 5u -> Register.R5
  | 6u -> Register.R6
  | 7u -> Register.R7
  | 8u -> Register.R8
  | 9u -> Register.R9
  | 10u -> Register.R10
  | 11u -> Register.R11
  | 12u -> Register.R12
  | 13u -> Register.R13
  | 14u -> Register.R14
  | 15u -> Register.R15
  | 16u -> Register.R16
  | 17u -> Register.R17
  | 18u -> Register.R18
  | 19u -> Register.R19
  | 20u -> Register.R20
  | 21u -> Register.R21
  | 22u -> Register.R22
  | 23u -> Register.R23
  | 24u -> Register.R24
  | 25u -> Register.R25
  | 26u -> Register.R26
  | 27u -> Register.R27
  | 28u -> Register.R28
  | 29u -> Register.R29
  | 30u -> Register.R30
  | 31u -> Register.R31
  | _ -> Terminator.futureFeature ()

let parseField (bin: uint32) (form: Form) (field: Field) =
  match field, form with
  | Field.RA, Form.D -> Bits.extract bin 20u 16u
  | Field.RT, Form.D -> Bits.extract bin 25u 21u
  | Field.SI, Form.D -> Bits.extract bin 15u 0u
  | _ -> Terminator.futureFeature ()

let parseExpr (bin: uint32) (form: Form) (expr: OprExpr) =
  match expr with
  | RegFrom field -> parseField bin form field |> getRegister |> OprReg
  | ImmFrom field -> parseField bin form field |> uint64 |> OprImm

let parseThreeOperands (bin: uint32) form e1 e2 e3 =
  ThreeOperands(parseExpr bin form e1,
                parseExpr bin form e2,
                parseExpr bin form e3)

let parseInstruction (bin: uint32) (addr: Addr) =
  match Bits.extract bin 31u 26u with
  | 0b001110u ->
    let e1, e2, e3 =
      RegFrom Field.RT, RegFrom Field.RA, ImmFrom Field.SI
    struct (Op.ADDI, parseThreeOperands bin Form.D e1 e2 e3)
  | _ -> Terminator.futureFeature ()

let parse lifter (span: ByteSpan) (reader: IBinReader) (addr: Addr) =
  let bin = reader.ReadUInt32(span, 0)
  let struct (opcode, operands) = parseInstruction bin addr
  Instruction(addr, 4u, opcode, operands, 64<rt>, 0UL, lifter)
