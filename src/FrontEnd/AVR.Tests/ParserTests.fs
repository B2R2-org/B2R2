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

namespace B2R2.FrontEnd.AVR.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.AVR
open type Opcode
open type Register

/// Shortcut for creating operands.
[<AutoOpen>]
module private Shortcut =
  type O =
    static member Reg(r) = OprReg r

    static member Imm(v) = OprImm v

    static member Addr(v) = OprAddr v

    static member AbsAddr(v) = OprAbsAddr v

    static member MemDisp(r, v) = OprMemory(DispMode(r, v))

    static member MemPostIdx(r) = OprMemory(PostIdxMode r)

[<TestClass>]
type ParserTests() =
  let test (bytes: byte[]) (opcode, oprs: Operands) =
    let reader = BinReader.Init Endian.Little
    let parser = AVRParser(reader) :> IInstructionParsable
    let span = System.ReadOnlySpan bytes
    let ins = parser.Parse(span, 0UL) :?> Instruction
    Assert.AreEqual<Opcode>(opcode, ins.Opcode)
    Assert.AreEqual<Operands>(oprs, ins.Operands)

  let operandsFromArray oprList =
    let oprs = Array.ofList oprList
    match oprs.Length with
    | 0 -> NoOperand
    | 1 -> OneOperand oprs[0]
    | 2 -> TwoOperands(oprs[0], oprs[1])
    | _ -> Terminator.impossible ()

  let ( ** ) opcode oprList = opcode, operandsFromArray oprList

  let ( ++ ) byteString pair = ByteArray.ofHexString byteString, pair

  [<TestMethod>]
  member _.``[AVR] No Operand Insturctions Parse Test (1)``() =
    "0895"
    ++ RET ** [] ||> test

  [<TestMethod>]
  member _.``[AVR] One Operand Insturctions Parse Test (1)``() =
    "81f1"
    ++ BREQ ** [ O.Addr 96 ] ||> test

  [<TestMethod>]
  member _.``[AVR] One Operand Insturctions Parse Test (2)``() =
    "b4f4"
    ++ BRGE ** [ O.Addr 44 ] ||> test

  [<TestMethod>]
  member _.``[AVR] Two Register Operands Insturctions Parse Test (1)``() =
    "c90e"
    ++ ADD ** [ O.Reg R12; O.Reg R25 ] ||> test

  [<TestMethod>]
  member _.``[AVR] Two Register Operands Insturctions Parse Test (2)``() =
    "e12c"
    ++ MOV ** [ O.Reg R14; O.Reg R1 ] ||> test

  [<TestMethod>]
  member _.``[AVR] Memory Operands Insturctions Parse Test (1)``() =
    "1d92"
    ++ ST ** [ O.MemPostIdx X; OprReg R1 ] ||> test

  [<TestMethod>]
  member _.``[AVR] Memory Operands Insturctions Parse Test (2)``() =
    "6980"
    ++ LDD ** [ O.Reg R6; O.MemDisp(Y, 1) ] ||> test

  [<TestMethod>]
  member _.``[AVR] Immediate Operand Insturction Parse Test (1)``() =
    "8fef"
    ++ LDI ** [ O.Reg R24; O.Imm 0xff ] ||> test

  /// A signed multiplication reaches only the upper half of the register file,
  /// where the four bits naming each of its registers are counted from r16.
  [<TestMethod>]
  member _.``[AVR] Signed Multiplication Parse Test``() =
    "0102"
    ++ MULS ** [ O.Reg R16; O.Reg R17 ] ||> test

  /// Where a long call or jump goes is a word address written out in full, not
  /// a distance counted from anywhere.
  [<TestMethod>]
  member _.``[AVR] Long Jump Parse Test``() =
    "0c943412"
    ++ JMP ** [ O.AbsAddr 0x2468 ] ||> test

  /// <summary>
  /// The highest bit of that address sits in the word naming the instruction
  /// rather than in the word below it.
  ///
  /// Reading that word as one word wide leaves the address behind and the whole
  /// instruction is then something else, or nothing at all.
  /// </summary>
  [<TestMethod>]
  member _.``[AVR] Long Call Parse Test``() =
    "0f943412"
    ++ CALL ** [ O.AbsAddr 0x22468 ] ||> test

  /// Nor is the byte a direct load or store reaches a distance from anywhere.
  [<TestMethod>]
  member _.``[AVR] Direct Load Parse Test``() =
    "00903412"
    ++ LDS ** [ O.Reg R0; O.AbsAddr 0x1234 ] ||> test

  /// A subtraction with a written byte whose lowest bits happen to be spelt the
  /// way a long call is, which is one word wide all the same.
  [<TestMethod>]
  member _.``[AVR] Immediate Subtraction Parse Test``() =
    "074a"
    ++ SBCI ** [ O.Reg R16; O.Imm 0xa7 ] ||> test

  /// Every register an instruction names is read back under the name it is
  /// written by, so that what reads a name cannot drift from what writes one.
  [<TestMethod>]
  member _.``[AVR] Register Name Round Trip Test``() =
    let named =
      [ for i in 0 .. 31 -> enum<Register>(int Register.R0 + i) ]
      @ [ Register.X; Register.Y; Register.Z ]
    for reg in named do
      Assert.AreEqual<Register>(reg, Register.ofString (Register.toString reg))
