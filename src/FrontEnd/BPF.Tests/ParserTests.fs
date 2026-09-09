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

namespace B2R2.FrontEnd.BinLifter.Tests

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BPF
open Microsoft.VisualStudio.TestTools.UnitTesting
open type Opcode
open type Register

[<TestClass>]
type ParserTests() =
  static let parseWith endian hex =
    let bytes = ByteArray.ofHexString hex
    let parser = BPFParser(BinReader.Init endian)
    (parser :> IInstructionParsable).Parse(ReadOnlySpan bytes, 0UL)
    :?> Instruction

  static let parse hex = parseWith Endian.Little hex

  static let assertIns opcode (oprs: Operands) length hex =
    let ins = parse hex
    Assert.AreEqual<Opcode>(opcode, ins.Opcode)
    Assert.AreEqual<Operands>(oprs, ins.Operands)
    Assert.AreEqual<uint32>(length, ins.Length)

  /// The instruction every one but the one carrying a quadword is as long as.
  static let assertWord opcode oprs hex = assertIns opcode oprs 8u hex

  /// Two registers, which is what an instruction computing from one names.
  static let two a b = TwoOperands(OprReg a, OprReg b)

  /// A register and a number written in place of a second register.
  static let counted a value = TwoOperands(OprReg a, OprImm value)

  /// A register, the memory an instruction reaches, and the other way round.
  static let loads a b disp = TwoOperands(OprReg a, OprMem(b, disp))

  static let assertFails hex =
    Assert.ThrowsExactly<ParsingFailureException>(fun () ->
      parse hex |> ignore)
    |> ignore

  [<TestMethod>]
  member _.``[BPF] an instruction computing names two operands test``() =
    assertWord ADD (two R1 R2) "0f21000000000000"
    assertWord MOV (counted R0 1UL) "b700000001000000"
    assertWord ADD32 (two R1 R2) "0c21000000000000"
    assertWord MOV32 (counted R1 0xffffffffUL) "b4010000ffffffff"

  (* The halfword where a distance would sit is what tells a division reading
     both sides as signed from one reading them as unsigned. *)
  [<TestMethod>]
  member _.``[BPF] a division may read both sides as signed test``() =
    assertWord DIV (two R1 R2) "3f21000000000000"
    assertWord SDIV (two R1 R2) "3f21010000000000"
    assertWord SMOD32 (two R1 R2) "9c21010000000000"

  (* A negation names the one register it works on and nothing else. *)
  [<TestMethod>]
  member _.``[BPF] a negation names one register test``() =
    assertWord NEG (OneOperand(OprReg R1)) "8701000000000000"
    assertWord NEG32 (OneOperand(OprReg R1)) "8401000000000000"

  (* A widening move says how much of its source it reads where every other
     instruction holds a distance, and it reads a register alone. *)
  [<TestMethod>]
  member _.``[BPF] a move may widen what it reads test``() =
    assertWord MOVSX (ThreeOperands(OprReg R1, OprReg R2, OprImm 8UL))
                     "bf21080000000000"
    assertWord MOVSX32 (ThreeOperands(OprReg R1, OprReg R2, OprImm 16UL))
                       "bc21100000000000"
    assertFails "bc21200000000000"

  (* How much of a register to reverse is part of the name, the encoding
     holding it where a number would sit. *)
  [<TestMethod>]
  member _.``[BPF] a byte-reversing instruction names its width test``() =
    assertWord LE16 (OneOperand(OprReg R1)) "d401000010000000"
    assertWord BE32 (OneOperand(OprReg R1)) "dc01000020000000"
    assertWord BSWAP64 (OneOperand(OprReg R1)) "d701000040000000"
    assertFails "d401000008000000"

  (* A jump counts how far away the place it goes to is in instructions, and
     what is written here is that distance in the bytes an address counts. *)
  [<TestMethod>]
  member _.``[BPF] a jump counts its distance in bytes test``() =
    assertWord JEQ (ThreeOperands(OprReg R1, OprImm 2UL, OprAddr 24L))
                   "1501030002000000"
    assertWord JA (OneOperand(OprAddr -8L)) "0500ffff00000000"
    assertWord GOTOL (OneOperand(OprAddr 16L)) "0600000002000000"

  (* A call names a helper by number, a function of this same program by how far
     away it is, and a kernel function by the number the kernel knows it as. *)
  [<TestMethod>]
  member _.``[BPF] a call says what kind of thing it calls test``() =
    assertWord CALL (OneOperand(OprImm 12UL)) "850000000c000000"
    assertWord CALL_LOCAL (OneOperand(OprAddr 16L)) "8510000002000000"
    assertWord CALL_KFUNC (OneOperand(OprImm 5UL)) "8520000005000000"
    assertWord EXIT NoOperand "9500000000000000"

  [<TestMethod>]
  member _.``[BPF] a load names the memory it reaches test``() =
    assertWord LDXW (loads R1 R2 8) "6121080000000000"
    assertWord LDXDW (loads R1 R2 -8) "7921f8ff00000000"
    assertWord LDXSW (loads R1 R2 4) "8121040000000000"

  [<TestMethod>]
  member _.``[BPF] a store names the memory it reaches first test``() =
    assertWord STXDW (TwoOperands(OprMem(R1, 16), OprReg R2))
                     "7b21100000000000"
    assertWord STW (TwoOperands(OprMem(R1, 0), OprImm 5UL))
                   "6201000005000000"

  (* Which operation an atomic store performs is held where a number would sit,
     and the ones reading what was there hold the bit below it as well. *)
  [<TestMethod>]
  member _.``[BPF] an atomic store names its operation test``() =
    assertWord ATOMIC_ADD_DW (TwoOperands(OprMem(R1, 0), OprReg R2))
                             "db21000000000000"
    assertWord ATOMIC_FADD_DW (TwoOperands(OprMem(R1, 0), OprReg R2))
                              "db21000001000000"
    assertWord ATOMIC_CMPXCHG_W (TwoOperands(OprMem(R1, 0), OprReg R2))
                                "c3210000f1000000"
    assertFails "db21000002000000"

  (* The one instruction two words wide carries the upper half of what it loads
     in the word after it, every other field of which holds zero. *)
  [<TestMethod>]
  member _.``[BPF] the instruction carrying a quadword is two words``() =
    let quadword = TwoOperands(OprReg R1, OprImm 0x1122334455667788UL)
    let descriptor = TwoOperands(OprReg R1, OprImm 3UL)
    assertIns LDDW quadword 16u "18010000887766550000000044332211"
    assertIns LDDW_MAPFD descriptor 16u "18110000030000000000000000000000"
    assertFails "18010000887766550100000044332211"
    assertFails "1801000088776655"

  (* The reads of a packet leave what they read in the first register, which
     they therefore do not name. *)
  [<TestMethod>]
  member _.``[BPF] a read of a packet names no destination test``() =
    assertWord LDABSW (OneOperand(OprImm 16UL)) "2000000010000000"
    assertWord LDINDH (TwoOperands(OprReg R1, OprImm 4UL)) "4810000004000000"

  (* The machine keeps eleven registers, so a field naming anything above them
     names no register, and every field an instruction does not use is required
     to hold zero. *)
  [<TestMethod>]
  member _.``[BPF] a word naming nothing is no instruction test``() =
    assertFails "0f2b000000000000"
    assertFails "0f21000001000000"
    assertFails "b721000001000000"
    assertFails "9521000000000000"

  (* Which nibble of the second byte names which register follows the order the
     bytes are stored in, the two being one field of a structure the machine's
     own header declares as bitfields. *)
  [<TestMethod>]
  member _.``[BPF] the register nibbles follow the byte order test``() =
    let little = parseWith Endian.Little "6121080000000000"
    let big = parseWith Endian.Big "6112000800000000"
    Assert.AreEqual<Operands>(little.Operands, big.Operands)
    Assert.AreEqual<Operands>(loads R1 R2 8, big.Operands)

// vim: set tw=80 sts=2 sw=2:
