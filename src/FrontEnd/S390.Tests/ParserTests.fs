(*
  B2R2 - the Next-Generation Reversing Platform

  Copyright (c) SoftSec Lab. @ KAIST, since 2016

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*)

namespace B2R2.FrontEnd.BinLifter.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.S390
open B2R2.FrontEnd.BinLifter
open type Opcode
open type Register

type O =
  static member Reg r = OpReg r

  static member Imm v = OpImm v

  static member Mask m = OpMask m

  static member Store v = OpStore v

  static member StoreLen v = OpStoreLen v

[<TestClass>]
type ParserTests() =
  let parseWith (isa: ISA) (bytes: byte[]) =
    let reader = BinReader.Init isa.Endian
    let parser = S390Parser(isa, reader) :> IInstructionParsable
    parser.Parse(System.ReadOnlySpan bytes, 0UL) :?> Instruction

  let assertIns opcode (oprs: Operands) (ins: Instruction) =
    Assert.AreEqual<Opcode>(ins.Opcode, opcode)
    Assert.AreEqual<Operands>(ins.Operands, oprs)

  let test endian opcode (oprs: Operands) (bytes: byte[]) =
    parseWith (ISA(Architecture.S390, endian = endian)) bytes
    |> assertIns opcode oprs

  let test32 (bytes: byte[]) (opcode, operands) =
    test Endian.Big opcode operands bytes

  /// A 32-bit S390 target, which runs ESA/390 rather than z/Architecture.
  let esa390 = ISA(Architecture.S390, Endian.Big, WordSize.Bit32)

  let testEsa390 (bytes: byte[]) (opcode, oprs) =
    parseWith esa390 bytes |> assertIns opcode oprs

  let testNotEsa390 (bytes: byte[]) =
    Assert.ThrowsExactly<ParsingFailureException>(fun () ->
      parseWith esa390 bytes |> ignore)
    |> ignore

  let operandsFromArray oprList =
    let oprArray = Array.ofList oprList
    match oprArray.Length with
    | 0 -> NoOperand
    | 1 -> OneOperand oprArray[0]
    | 2 -> TwoOperands(oprArray[0], oprArray[1])
    | 3 -> ThreeOperands(oprArray[0], oprArray[1], oprArray[2])
    | 4 -> FourOperands(oprArray[0], oprArray[1], oprArray[2], oprArray[3])
    | 5 ->
      FiveOperands(oprArray[0], oprArray[1], oprArray[2], oprArray[3],
        oprArray[4])
    | 6 ->
      SixOperands(oprArray[0], oprArray[1], oprArray[2], oprArray[3],
        oprArray[4], oprArray[5])
    | _ -> Terminator.impossible ()

  let ( ** ) opcode oprList = opcode, operandsFromArray oprList
  let ( ++ ) byteString pair = ByteArray.ofHexString byteString, pair

  [<TestMethod>]
  member _.``[S390] Fmt.E instructions Parse Test (1)``() =
    "0101"
    ++ PR ** []
    ||> test32

  [<TestMethod>]
  member _.``[S390] Fmt.RR instruction Parse Test (1)``() =
    "1612"
    ++ OR **
    [ O.Reg R1; O.Reg R2 ]
    ||> test32

  [<TestMethod>]
  member _.``[S390] Fmt.RX instructions Parse Test (1)``() =
    "47CBA050"
    ++ BC **
    [ O.Mask(uint16 12); O.Store(Some R11, R10, DispU 0x50u) ]
    ||> test32 // 4

  [<TestMethod>]
  member _.``[S390] Fmt.RX instructions Parse Test (2)``() =
    "5EABABAB"
    ++ AL **
    [ O.Reg R10; O.Store(Some R11, R10, DispU 0xBABu) ]
    ||> test32

  [<TestMethod>]
  member _.``[S390] Fmt.RX instructions Parse Test (3)``() =
    "5DABABAB"
    ++ D **
    [ O.Reg R10; O.Store(Some R11, R10, DispU 0xBABu) ]
    ||> test32

  [<TestMethod>]
  member _.``[S390] Fmt.RX instructions Parse Test (4)``() =
    "5CABABAB"
    ++ M **
    [ O.Reg R10; O.Store(Some R11, R10, DispU 0xBABu) ]
    ||> test32

  [<TestMethod>]
  member _.``[S390] Fmt.RX instructions Parse Test (5)``() =
    "60000000"
    ++ STD **
    [ O.Reg FPR0; OpStore(Some R0, R0, DispU 0u) ]
    ||> test32

  [<TestMethod>]
  member _.``[S390] Fmt.RX instruction Parse Test (6)``() =
    "4A5DC6B0"
    ++ AH **
    [ O.Reg R5; O.Store(Some R13, R12, DispU 0x6B0u) ]
    ||> test32

  [<TestMethod>]
  member _.``[S390] Fmt.RS instruction Parse Test (1)``() =
    "8F2F001F"
    ++ SLDA **
    [ O.Reg R2; O.Store(None, R0, DispU 31u) ]
    ||> test32

  [<TestMethod>]
  member _.``[S390] Fmt.SI instruction Parse Test (1)``() =
    "94FE8001"
    ++ NI **
    [ O.Store(None, R8, DispU 1u); O.Imm(ImmU8 0xFEuy) ]
    ||> test32

  [<TestMethod>]
  member _.``[S390] Fmt.MII instruction Parse Test (1)``() =
    "C50ABCDEFFFF"
    ++ BPRP **
    [ O.Mask 0us
      O.Imm(ImmS12(BitVector(0xABC, 12<rt>)))
      O.Imm(ImmS24(BitVector(0xDEFFFF, 24<rt>))) ]
    ||> test32

  [<TestMethod>]
  member _.``[S390] Fmt.SS instruction Parse Test (1)``() =
    "DD141001F000"
    ++ TRT **
    [ O.StoreLen(0x15us, R1, DispU 1u); O.Store(None, R15, DispU 0u) ]
    ||> test32

  [<TestMethod>]
  member _.``[S390] Fmt.SS instruction Parse Test (2)``() =
    "F05040010003"
    ++ SRP **
    [ O.StoreLen(6us, R4, DispU 1u)
      O.Store(None, R0, DispU 3u)
      O.Imm(ImmU4(BitVector(0x00u, 4<rt>))) ]
    ||> test32

  [<TestMethod>]
  member _.``[S390] Fmt.VRI instruction Parse Test (1)``() =
    "E73500024840"
    ++ VLEIB **
    [ O.Reg VR19; O.Imm(ImmU16 2us); O.Mask 4us ]
    ||> test32

  [<TestMethod>]
  member _.``[S390] Fmt.VRR instruction Parse Test (1)``() =
    "E71FA04327EB"
    ++ VFCH **
    [ O.Reg VR1; O.Reg VR31; O.Reg VR26; O.Mask 2us; O.Mask 3us; O.Mask 4us ]
    ||> test32

  [<TestMethod>]
  member _.``[S390] Fmt.VRS instruction Parse Test (1)``() =
    "E7312004083F"
    ++ VSTL **
    [ O.Reg VR19; O.Store(None, R2, DispU 4u); O.Reg R1 ]
    ||> test32

  [<TestMethod>]
  member _.``[S390] Fmt.VRV instruction Parse Test (1)``() =
    "E73210114F1A"
    ++ VSCEG **
    [ O.Reg VR19; O.Store(Some VR18, R1, DispU 0x11u); O.Mask 4us ]
    ||> test32

  (* A 32-bit S390 target runs ESA/390, so only the part of the instruction set
     that predates z/Architecture may decode there. Appendix B of the
     z/Architecture Principles of Operation is what says which part that is:
     SAM31 carries the N3 mark and so was added back to ESA/390, while SAM64
     carries a plain N and never existed outside z/Architecture. *)
  [<TestMethod>]
  member _.``[S390] an ESA/390 instruction parses in 32-bit mode test``() =
    "010D" ++ SAM31 ** [] ||> testEsa390

  [<TestMethod>]
  member _.``[S390] a 32-bit RR instruction parses in 32-bit mode test``() =
    "1A12" ++ AR ** [ O.Reg R1; O.Reg R2 ] ||> testEsa390

  (* BRASL came with the immediate-and-relative-instruction facility, which
     ESA/390 gained before z/Architecture existed, so its N3 mark keeps it
     available to a 32-bit target even though it is a 6-byte RIL instruction. *)
  [<TestMethod>]
  member _.``[S390] an N3 relative branch parses in 32-bit mode test``() =
    "C01500000002"
    ++ BRASL **
    [ O.Reg R1; OpRImm(ImmS32 2) ]
    ||> testEsa390

  [<TestMethod>]
  member _.``[S390] SAM64 is rejected in 32-bit mode test``() =
    testNotEsa390 (ByteArray.ofHexString "010E")

  [<TestMethod>]
  member _.``[S390] a 64-bit RRE instruction is rejected in 32-bit test``() =
    testNotEsa390 (ByteArray.ofHexString "B9040012")

  [<TestMethod>]
  member _.``[S390] a 64-bit RXY load is rejected in 32-bit mode test``() =
    testNotEsa390 (ByteArray.ofHexString "E31020000004")

  [<TestMethod>]
  member _.``[S390] a vector instruction is rejected in 32-bit mode test``() =
    testNotEsa390 (ByteArray.ofHexString "E7312004083F")

  [<TestMethod>]
  member _.``[S390] SAM64 parses in 64-bit mode test``() =
    "010E" ++ SAM64 ** [] ||> test32

  [<TestMethod>]
  member _.``[S390] a 64-bit RRE instruction parses in 64-bit mode test``() =
    "B9040012" ++ LGR ** [ O.Reg R1; O.Reg R2 ] ||> test32

  [<TestMethod>]
  member _.``[S390] a 64-bit RXY load parses in 64-bit mode test``() =
    "E31020000004"
    ++ LG **
    [ O.Reg R1; O.Store(Some R0, R2, DispS 0) ]
    ||> test32

  [<TestMethod>]
  member _.``[S390] Fmt.VRX instruction Parse Test (1)``() =
    "E6523FFF2105"
    ++ VLBRREP **
    [ O.Reg VR5; O.Store(Some R2, R3, DispU 0xfffu); O.Mask 2us ]
    ||> test32

  [<TestMethod>]
  member _.``[S390] Fmt.VSI instruction Parse Test (1)``() =
    "E63E0100313C"
    ++ VUPKZ **
    [ O.Reg VR19; O.Store(None, R0, DispU 0x100u); O.Imm(ImmU8 0x3Euy) ]
    ||> test32

  [<TestMethod>]
  member _.``[S390] Fmt.IE instruction Parse Test (1)``() =
    "B2FA002F"
    ++ NIAI **
    [ O.Imm(ImmU4(BitVector(0x2u, 4<rt>)))
      O.Imm(ImmU4(BitVector(0xfu, 4<rt>))) ]
    ||> test32