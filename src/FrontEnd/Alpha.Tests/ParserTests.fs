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
open B2R2.FrontEnd.Alpha
open Microsoft.VisualStudio.TestTools.UnitTesting
open type Opcode
open type Register

[<TestClass>]
type ParserTests() =
  static let isa = ISA Architecture.Alpha

  static let parse hex =
    let bytes = ByteArray.ofHexString hex
    let parser = AlphaParser(BinReader.Init isa.Endian)
    (parser :> IInstructionParsable).Parse(ReadOnlySpan bytes, 0UL)
    :?> Instruction

  static let assertIns opcode qualifier (oprs: Operands) hex =
    let ins = parse hex
    Assert.AreEqual<Opcode>(opcode, ins.Opcode)
    Assert.AreEqual<Qualifier>(qualifier, ins.Qualifier)
    Assert.AreEqual<Operands>(oprs, ins.Operands)
    Assert.AreEqual<uint32>(4u, ins.Length)

  static let assertPlain opcode oprs hex =
    assertIns opcode Qualifier.NoQualifier oprs hex

  /// Three registers, which is what most instructions name.
  static let three a b c = ThreeOperands(OprReg a, OprReg b, OprReg c)

  /// Two registers, which is what an instruction reading one thing names.
  static let two a b = TwoOperands(OprReg a, OprReg b)

  /// A register, a number standing where the second register would, and the
  /// register written to.
  static let counted a value c = ThreeOperands(OprReg a, OprImm value, OprReg c)

  /// A register, the register holding where to go, and the hint a branch to a
  /// computed address carries.
  static let jump a b h = ThreeOperands(OprReg a, OprBase b, OprImm h)

  static let assertFails hex =
    Assert.ThrowsExactly<ParsingFailureException>(fun () ->
      parse hex |> ignore)
    |> ignore

  [<TestMethod>]
  member _.``[Alpha] an operate instruction reads three operands test``() =
    assertPlain ADDQ (three R1 R2 R3) "03042240"
    assertPlain CMPLE (three R1 R2 R3) "A30D2240"

  (* Bit 12 says a number stands where a second register would, and the number
     is the eight bits above it rather than the five a register field holds. *)
  [<TestMethod>]
  member _.``[Alpha] a number may stand for the second register test``() =
    assertPlain SLL (counted R1 5UL R3) "23B72048"
    assertPlain ADDQ (counted R1 255UL R3) "03F43F40"

  (* The instructions reading one thing only leave the first register field
     unused, so what they name is the second one and the one written to. *)
  [<TestMethod>]
  member _.``[Alpha] the instructions reading one thing test``() =
    assertPlain AMASK (two R2 R3) "230CE247"
    assertPlain SEXTB (two R2 R3) "0300E273"
    assertPlain IMPLVER (OneOperand(OprReg R3)) "833DE047"

  (* A displacement is signed and sixteen bits wide, so one below zero has to
     widen rather than read as the large number its bits would otherwise be. *)
  [<TestMethod>]
  member _.``[Alpha] a displacement is signed test``() =
    assertPlain LDA (TwoOperands(OprReg R1, OprMem(R30, 16))) "10003E20"
    assertPlain STQ (TwoOperands(OprReg R1, OprMem(R30, -8))) "F8FF3EB4"

  (* A load or a store of a floating-point register names one where the general
     ones are named, because the field is the same field. *)
  [<TestMethod>]
  member _.``[Alpha] a floating-point load names a float register test``() =
    assertPlain LDT (TwoOperands(OprReg F1, OprMem(R16, 32))) "2000308C"

  (* A load whose result goes to the register that always reads as zero is a
     prefetch, which the architecture spends no opcode of its own on. *)
  [<TestMethod>]
  member _.``[Alpha] a load into the zero register is a prefetch test``() =
    assertPlain PREFETCH (OneOperand(OprMem(R16, 64))) "4000F0A3"
    assertPlain PREFETCH_EN (OneOperand(OprMem(R16, 64))) "4000F0A7"
    assertPlain PREFETCH_M (OneOperand(OprMem(R16, 64))) "4000F08B"
    assertPlain PREFETCH_MEN (OneOperand(OprMem(R16, 64))) "4000F08F"
    assertPlain LDL (TwoOperands(OprReg R1, OprMem(R16, 64))) "400030A0"

  (* The instructions ordering memory spend the whole displacement field on
     saying which of them a word is, so what is left to name is a register at
     most. *)
  [<TestMethod>]
  member _.``[Alpha] a function code may fill the displacement test``() =
    assertPlain MB NoOperand "0040FF63"
    assertPlain WMB NoOperand "0044FF63"
    assertPlain FETCH (OneOperand(OprBase R16)) "0080F063"
    assertPlain RPCC (OneOperand(OprReg R1)) "00C03F60"

  (* Which of the four branches to a computed address a word is comes from the
     two bits at the top of that same field; the rest of it is a hint. *)
  [<TestMethod>]
  member _.``[Alpha] a computed branch reads a hint test``() =
    assertPlain JMP (jump R26 R27 0UL) "00005B6B"
    assertPlain JSR (jump R26 R27 0UL) "00405B6B"
    assertPlain RET (jump R31 R26 1UL) "0180FA6B"

  (* A branch counts in words and what is kept is that distance in bytes, from
     the instruction after the branch rather than from the branch itself. *)
  [<TestMethod>]
  member _.``[Alpha] a branch counts a distance in bytes test``() =
    assertPlain BR (TwoOperands(OprReg R31, OprAddr 8)) "0200E0C3"
    assertPlain BEQ (TwoOperands(OprReg R1, OprAddr -8)) "FEFF3FE4"
    assertPlain FBEQ (TwoOperands(OprReg F1, OprAddr 0)) "000020C4"

  (* A floating-point function code says what an instruction computes and how
     it rounds and traps at once, and the qualifier is the second half of that.
     *)
  [<TestMethod>]
  member _.``[Alpha] a qualifier comes out of the function code test``() =
    assertPlain ADDS (three F1 F2 F3) "03102258"
    assertIns ADDS Qualifier.SUID (three F1 F2 F3) "03F82258"
    assertIns CVTTQ Qualifier.SVC (two F2 F3) "E3A5E25B"
    assertIns ADDG Qualifier.SC (three F1 F2 F3) "03842254"

  (* The conversion to the wider format and the conversion to the narrower one
     share the six bits naming them, and are told apart by what each traps on.
     *)
  [<TestMethod>]
  member _.``[Alpha] two conversions share the bits naming them test``() =
    assertPlain CVTTS (two F2 F3) "8315E25B"
    assertPlain CVTST (two F2 F3) "8355E25B"
    assertIns CVTST Qualifier.S (two F2 F3) "83D5E25B"

  (* A move between the two register files names one of each, so which field
     holds which kind is what says the direction. *)
  [<TestMethod>]
  member _.``[Alpha] a move between register files test``() =
    assertPlain ITOFS (two R1 F3) "83003F50"
    assertPlain FTOIS (two F1 R3) "030F3F70"
    assertPlain MT_FPCR (OneOperand(OprReg F1)) "8104215C"

  [<TestMethod>]
  member _.``[Alpha] a trap to palcode reads the whole word test``() =
    assertPlain CALL_PAL (OneOperand(OprImm 0x83UL)) "83000000"
    assertPlain CALL_PAL (OneOperand(OprImm 0x3FFFFFFUL)) "FFFFFF03"

  (* The architecture keeps several of the six-bit values for itself, and a
     function code naming nothing is likewise no instruction. *)
  [<TestMethod>]
  member _.``[Alpha] an encoding naming nothing is a failure test``() =
    assertFails "00002204"
    assertFails "00002264"
    assertFails "E30F2240"
    assertFails "A3182258"
    assertFails "0100FF63"

  [<TestMethod>]
  member _.``[Alpha] a span too short for a word is a failure test``() =
    assertFails ""
    assertFails "0304"

// vim: set tw=80 sts=2 sw=2:
