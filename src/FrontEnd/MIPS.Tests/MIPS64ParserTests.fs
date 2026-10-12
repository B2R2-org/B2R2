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

namespace B2R2.FrontEnd.MIPS.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.MIPS
open type Opcode
open type Register

/// Shortcut for creating operands.
[<AutoOpen>]
module private MIPS64Shortcut =
  type O =
    static member Reg(r) = OpReg r

    static member Imm(v) = OpImm v

    static member Mem(r, o: int64, rt) = OpMem(r, Imm o, rt)

    static member Mem(r, o, rt) = OpMem(r, Reg o, rt)

    static member Addr(t) = OpAddr t

    static member Shift(s) = OpShiftAmount s

[<TestClass>]
type MIPS64ParserTests() =
  let test wordSize endian opcode (oprs: Operands) (bytes: byte[]) =
    let isa = ISA(Architecture.MIPS, endian, wordSize)
    let reader = BinReader.Init endian
    let parser = Parser(isa, reader) :> IInstructionParsable
    let span = System.ReadOnlySpan bytes
    let ins = parser.Parse(span, 0UL) :?> Instruction
    let opcode' = ins.Opcode
    let oprs' = ins.Operands
    Assert.AreEqual<Opcode>(opcode, opcode')
    Assert.AreEqual<Operands>(oprs, oprs')

  let test64R2 (bytes: byte[]) (opcode, operands) =
    test WordSize.Bit64 Endian.Big opcode operands bytes

  let operandsFromArray oprList =
    let oprArray = Array.ofList oprList
    match oprArray.Length with
    | 0 -> NoOperand
    | 1 -> OneOperand oprArray[0]
    | 2 -> TwoOperands(oprArray[0], oprArray[1])
    | 3 -> ThreeOperands(oprArray[0], oprArray[1], oprArray[2])
    | 4 -> FourOperands(oprArray[0], oprArray[1], oprArray[2], oprArray[3])
    | _ -> Terminator.impossible ()

  let ( ** ) opcode oprList = opcode, operandsFromArray oprList

  let ( ++ ) byteString pair = ByteArray.ofHexString byteString, pair

  /// <summary>
  /// The privileged encodings, which the parser refused wholesale until the
  /// COP0 major opcode was decoded.
  ///
  /// What this pins is the field splits a round-trip cannot see. ERET and
  /// ERETNC share a function field and differ in bit 6 alone; DI and EI share
  /// theirs and differ in bit 5; the two of those and DVP and EVP are one
  /// encoding told apart by the rd field as well. An encoder and a decoder
  /// that made the same mistake about any of them would still round-trip.
  /// </summary>
  [<TestMethod>]
  member _.``[MIPS64] The privileged encodings parse``() =
    let words =
      [ "40086000", MFC0
        "40286000", DMFC0
        "40486000", MFHC0
        "40886000", MTC0
        "40a86000", DMTC0
        "40c86000", MTHC0
        "41494000", RDPGPR
        "41c94000", WRPGPR
        "41686000", DI
        "41686020", EI
        "42000018", ERET
        "42000058", ERETNC
        "4200001f", DERET
        "42000020", WAIT
        "42000001", TLBR
        "42000002", TLBWI
        "42000003", TLBINV
        "42000004", TLBINVF
        "42000006", TLBWR
        "42000008", TLBP
        "bcb00004", CACHE
        "7ca8022c", LBE
        "7ca8021f", SWE ]
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64)
    let parser = Parser(isa, BinReader.Init Endian.Big)
    let parser = parser :> IInstructionParsable
    for hex, opcode in words do
      let bytes = ByteArray.ofHexString hex
      let ins = parser.Parse(System.ReadOnlySpan bytes, 0UL) :?> Instruction
      Assert.AreEqual<Opcode>(opcode, ins.Opcode, hex)

  /// <summary>
  /// The nine-bit offset a SPECIAL3 load or store holds is SIGNED, and
  /// widening it from the wrong place reads every negative offset as a large
  /// positive one. 0x1fc is -4 in nine bits and 508 in nine unsigned ones.
  /// </summary>
  [<TestMethod>]
  member _.``[MIPS64] A nine-bit SPECIAL3 offset is signed``() =
    "7ca8fe2c"
    ++ LBE ** [ O.Reg R8; O.Mem(R5, -4L, 8<rt>) ]
    ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Arithmetic operations Parse Test (1)``() =
    "02bd782d"
    ++ DADDU ** [ O.Reg R15; O.Reg R21; O.Reg R29 ]
    ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Arithmetic operations Parse Test (2)``() =
    "64cdccd5"
      ++ DADDIU ** [ O.Reg R13; O.Reg R6; O.Imm 0xffffffffffffccd5UL ]
      ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Arithmetic operations Parse Test (3)``() =
    "0229d02f"
    ++ DSUBU ** [ O.Reg R26; O.Reg R17; O.Reg R9 ]
    ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Shift And Rotate operations Parse Test (1)``() =
    "002df6ba"
    ++ DROTR ** [ O.Reg R30; O.Reg R13; O.Shift 0x1aUL ]
    ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Shift And Rotate operations Parse Test (2)``() =
    "000eeef8"
    ++ DSLL ** [ O.Reg R29; O.Reg R14; O.Shift 0x1bUL ]
    ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Shift And Rotate operations Parse Test (3)``() =
    "0011e57c"
    ++ DSLL32 ** [ O.Reg R28; O.Reg R17; O.Shift 0x15UL ]
    ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Shift And Rotate operations Parse Test (4)``() =
    "02baf014"
    ++ DSLLV ** [ O.Reg R30; O.Reg R26; O.Reg R21 ]
    ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Shift And Rotate operations Parse Test (5)``() =
    "000ef7fb"
    ++ DSRA ** [ O.Reg R30; O.Reg R14; O.Shift 0x1fUL ]
    ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Shift And Rotate operations Parse Test (6)``() =
    "000fd1ff"
    ++ DSRA32 ** [ O.Reg R26; O.Reg R15; O.Shift 0x7UL ]
    ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Logical and Bit-Field operations Parse Test (1)``() =
    "7d5d6883"
    ++ DEXT ** [ O.Reg R29; O.Reg R10; O.Imm 0x2UL; O.Imm 0xeUL ]
    ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Logical and Bit-Field operations Parse Test (2)``() =
    "7df5ca47"
    ++ DINS ** [ O.Reg R21; O.Reg R15; O.Imm 0x9UL; O.Imm 0x11UL ]
    ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Multiply and Divide operations Parse Test (1)``() =
    "03c3001f"
      ++ DDIVU ** [ O.Reg R30; O.Reg R3 ]
      ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Multiply and Divide operations Parse Test (2)``() =
    "030e001c"
      ++ DMULT ** [ O.Reg R24; O.Reg R14 ]
      ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Multiply and Divide operations Parse Test (3)``() =
    "0232001d"
      ++ DMULTU ** [ O.Reg R17; O.Reg R18 ]
      ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Load and Store operations Parse Test (1)``() =
    "df5d2afd"
    ++ LD ** [ O.Reg R29; O.Mem(R26, 0x2afdL, 64<rt>) ]
    ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Load and Store operations Parse Test (2)``() =
    "9f11ad01"
      ++ LWU ** [ O.Reg R17; O.Mem(R24, -0x52ffL, 32<rt>) ]
      ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Load and Store operations Parse Test (3)``() =
    "fe25380a"
      ++ SD ** [ O.Reg R5; O.Mem(R.R17, 0x380aL, 64<rt>) ]
      ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Load and Store operations Parse Test (4)``() =
    "b34c3f02"
      ++ SDL ** [ O.Reg R12; O.Mem(R26, 0x3f02L, 64<rt>) ]
      ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Load and Store operations Parse Test (5)``() =
    "b4cb8715"
      ++ SDR ** [ O.Reg R11; O.Mem(R6, -0x78ebL, 64<rt>) ]
      ||> test64R2

  /// <summary>
  /// The CRC family, whose encoding is checked against binutils: it encodes
  /// <c>crc32b $10, $9, $10</c> as 0x7D2A000F, and the rows walk the two
  /// fields from there -- the element size at 7..6 and the polynomial at
  /// 10..8.
  ///
  /// The third operand is the first one again: the running value is an input
  /// as well as the destination, which is how the manual writes them.
  /// </summary>
  [<TestMethod>]
  member _.``[MIPS64] The CRC family parses``() =
    let words =
      [ "7d2a000f", CRC32B
        "7d2a004f", CRC32H
        "7d2a008f", CRC32W
        "7d2a00cf", CRC32D
        "7d2a010f", CRC32CB
        "7d2a014f", CRC32CH
        "7d2a018f", CRC32CW
        "7d2a01cf", CRC32CD ]
    let isa =
      ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64, int MIPSRelease.R6)
    let parser = Parser(isa, BinReader.Init Endian.Big)
                 :> IInstructionParsable
    let expected = ThreeOperands(OpReg R10, OpReg R9, OpReg R10)
    for hex, opcode in words do
      let bytes = ByteArray.ofHexString hex
      let ins = parser.Parse(System.ReadOnlySpan bytes, 0UL) :?> Instruction
      Assert.AreEqual<Opcode>(opcode, ins.Opcode, hex)
      Assert.AreEqual<Operands>(expected, ins.Operands, hex)

  /// <summary>
  /// Release 6 puts CMP.cond.fmt in the rows of the W and L formats, with its
  /// condition in function bits 4 to 0 and bit 5 clear. CVT.S and CVT.D from
  /// a word or a long stay in the same rows, at 32 and 33, and were read as
  /// CMP.AF and CMP.UN.
  /// </summary>
  [<TestMethod>]
  member _.``[MIPS64R6] CVT from a word or a long is not a CMP``() =
    let words =
      [ "46801020", CVTS, Fmt.W
        "46801021", CVTD, Fmt.W
        "46a01020", CVTS, Fmt.L
        "46a01021", CVTD, Fmt.L ]
    let isa =
      ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64, int MIPSRelease.R6)
    let parser = Parser(isa, BinReader.Init Endian.Big)
                 :> IInstructionParsable
    for hex, opcode, fmt in words do
      let bytes = ByteArray.ofHexString hex
      let ins = parser.Parse(System.ReadOnlySpan bytes, 0UL) :?> Instruction
      Assert.AreEqual<Opcode>(opcode, ins.Opcode, hex)
      Assert.AreEqual<Fmt option>(Some fmt, ins.Fmt, hex)

  /// <summary>
  /// Release 6 defines six comparisons above the sixteen C.cond.fmt has: OR,
  /// UNE and NE at 17 to 19, the negations of UN, EQ and UEQ, and their
  /// signalling forms at 25 to 27. They were refused as undefined.
  /// </summary>
  [<TestMethod>]
  member _.``[MIPS64R6] CMP.cond.fmt reads the negated conditions``() =
    let words =
      [ "46841011", Condition.OR
        "46841012", Condition.UNE
        "46841013", Condition.NE
        "46841019", Condition.SOR
        "4684101a", Condition.SUNE
        "4684101b", Condition.SNE ]
    let isa =
      ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64, int MIPSRelease.R6)
    let parser = Parser(isa, BinReader.Init Endian.Big)
                 :> IInstructionParsable
    for hex, condition in words do
      let bytes = ByteArray.ofHexString hex
      let ins = parser.Parse(System.ReadOnlySpan bytes, 0UL) :?> Instruction
      Assert.AreEqual<Opcode>(CMP, ins.Opcode, hex)
      Assert.AreEqual<Condition option>(Some condition, ins.Condition, hex)

  /// <summary>
  /// A bitfield whose fields run past the register, or end before they
  /// begin, is UNPREDICTABLE (MD00087 EXT, INS, DEXTM, DEXTU, DINS and
  /// DINSU), and the reference takes it as a Reserved Instruction: the
  /// decoder refuses it, and reads the widest field that fits.
  /// </summary>
  [<TestMethod>]
  member _.``[MIPS64] Bitfields past the register are refused``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64)
    let parser = Parser(isa, BinReader.Init Endian.Big) :> IInstructionParsable
    let parse hex =
      parser.Parse(System.ReadOnlySpan(ByteArray.ofHexString hex), 0UL)
    for hex in [ "7c623780" (* ext, 30 + 7 *)
                 "7c62f7c4" (* ins, lsb 31 > msb 30 *)
                 "7c620047" (* dins, lsb 1 > msb 0 *)
                 "7c620046" (* dinsu, lsb 33 > msb 32 *)
                 "7c62f841" (* dextm, 1 + 64 *)
                 "7c62f842" (* dextu, 33 + 32 *) ] do
      Assert.ThrowsExactly<ParsingFailureException>(fun () ->
        parse hex |> ignore) |> ignore
    for hex in [ "7c62f040" (* ext, 1 + 31 *)
                 "7c62f804" (* ins, 0 to 31 *)
                 "7c62f001" (* dextm, 0 + 63 *)
                 "7c62f002" (* dextu, 32 + 31 *) ] do
      parse hex |> ignore

  /// <summary>
  /// What Release 6 removed is not an instruction there: the likely branches
  /// BEQL and BNEL, the unaligned and the sixteen-bit-offset LL, SC and PREF
  /// families, COP1X, SPECIAL2, the condition-code moves and branches and the
  /// C.cond comparisons, HI and LO, BLTZAL and BGEZAL on a register, and the
  /// EVA unaligned forms (MD00087, each one's Format line); and DAUI on r0
  /// and SIGRIE with a register are Reserved Instructions. SDBBP moved into
  /// SPECIAL, and NAL stayed.
  /// </summary>
  [<TestMethod>]
  member _.``[MIPS64] Release 6 refuses what it removed``() =
    let isa =
      ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64, int MIPSRelease.R6)
    let parser = Parser(isa, BinReader.Init Endian.Big) :> IInstructionParsable
    let parse hex =
      parser.Parse(System.ReadOnlySpan(ByteArray.ofHexString hex), 0UL)
    let removed =
      [ "50000e40" (* beql *)
        "5400fb80" (* bnel *)
        "6800e600" (* ldl *)
        "6c008a40" (* ldr *)
        "8800b2c0" (* lwl *)
        "9800aa40" (* lwr *)
        "a8001880" (* swl *)
        "b00007c0" (* sdl *)
        "b400b200" (* sdr *)
        "b800eec0" (* swr *)
        "c0005240" (* ll *)
        "cc006800" (* pref *)
        "d000ad40" (* lld *)
        "e0003a80" (* sc *)
        "f0003e40" (* scd *)
        "4ffcc721" (* madd.d *)
        "70a41002" (* mul, SPECIAL2 *)
        "70a01020" (* clz, SPECIAL2 *)
        "4500a2c0" (* bc1f *)
        "46213a92" (* movz.d *)
        "463c3c11" (* movf.d *)
        "46201032" (* c.eq.d *)
        "0014180b" (* movn *)
        "00000801" (* movf *)
        "00001010" (* mfhi *)
        "04308180" (* bltzal *)
        "0431da00" (* bgezal *)
        "7c0026d9" (* lwle *)
        "7400f080" (* daui on r0 *)
        "04379800" (* sigrie with a register *) ]
    for hex in removed do
      Assert.ThrowsExactly<ParsingFailureException>((fun () ->
        parse hex |> ignore), hex) |> ignore
    let kept = [ "0000000e", SDBBP; "04100003", NAL ]
    for hex, opcode in kept do
      Assert.AreEqual<Opcode>(opcode, (parse hex :?> Instruction).Opcode, hex)

  /// <summary>
  /// Coprocessor 2 decodes at both releases.
  ///
  /// What a coprocessor 2 register, control word or condition is, is the
  /// implementation's -- "The interpretation of the Impl field is left
  /// entirely to the Coprocessor 2 implementation" (MD00087 MFC2) -- so each
  /// is read as the number the word holds. Release 6 replaced the branches on
  /// a condition code with two on a condition register, and moved the loads
  /// and stores into COP2, with an eleven-bit offset, from the major opcodes
  /// it gave its compact branches.
  /// </summary>
  [<TestMethod>]
  member _.``[MIPS64] Coprocessor 2 decodes at both releases``() =
    let parse release hex =
      let isa =
        ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64, int release)
      let parser =
        Parser(isa, BinReader.Init Endian.Big) :> IInstructionParsable
      let bytes = ByteArray.ofHexString hex
      let ins = parser.Parse(System.ReadOnlySpan bytes, 0UL) :?> Instruction
      ins.Opcode, ins.Operands
    let pre, r6 = MIPSRelease.PreR6, MIPSRelease.R6
    let cases =
      [ pre, "48021805", (MFC2, [ O.Reg R2; O.Imm 0x1805UL ])
        r6, "48021805", (MFC2, [ O.Reg R2; O.Imm 0x1805UL ])
        pre, "48420800", (CFC2, [ O.Reg R2; O.Imm 0x800UL ])
        pre, "48a20000", (DMTC2, [ O.Reg R2; O.Imm 0UL ])
        pre, "48e20007", (MTHC2, [ O.Reg R2; O.Imm 7UL ])
        pre, "49010003", (BC2T, [ O.Addr(Relative 16L) ])
        pre, "4a123456", (COP2, [ O.Imm 0x123456UL ])
        pre, "c8820010", (LWC2, [ O.Imm 2UL; O.Mem(R4, 16L, 32<rt>) ])
        pre, "f8820010", (SDC2, [ O.Imm 2UL; O.Mem(R4, 16L, 64<rt>) ])
        r6, "49250003", (BC2EQZ, [ O.Imm 5UL; O.Addr(Relative 16L) ])
        r6, "494227f0", (LWC2, [ O.Imm 2UL; O.Mem(R4, -16L, 32<rt>) ]) ]
    for release, hex, (opcode, oprs) in cases do
      let opcode', oprs' = parse release hex
      Assert.AreEqual<Opcode>(opcode, opcode', hex)
      Assert.AreEqual<Operands>(operandsFromArray oprs, oprs', hex)

  /// Release 6's own encodings are not instructions before it: AUI, the
  /// nine-bit LL, SC, LLD, SCD and PREF in SPECIAL3, ALIGN and DALIGN, and
  /// the three-register DIVU and CLZ and CLO in SPECIAL (MD00087).
  [<TestMethod>]
  member _.``[MIPS64] Release 2 refuses Release 6 encodings``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64)
    let parser = Parser(isa, BinReader.Init Endian.Big) :> IInstructionParsable
    let parse hex =
      parser.Parse(System.ReadOnlySpan(ByteArray.ofHexString hex), 0UL)
    let r6Only =
      [ "3c202b80" (* aui *)
        "7c003526" (* sc *)
        "7c00de35" (* pref *)
        "7c0002b7" (* lld *)
        "7c02b736" (* ll *)
        "7c017927" (* scd *)
        "7c0bca60" (* align *)
        "7c10cba4" (* dalign *)
        "0012b09b" (* divu, three registers *)
        "00a01050" (* clz, SPECIAL *)
        "00a01051" (* clo, SPECIAL *) ]
    for hex in r6Only do
      Assert.ThrowsExactly<ParsingFailureException>((fun () ->
        parse hex |> ignore), hex) |> ignore
    let kept =
      [ "00001010", MFHI
        "0005180a", MOVZ
        "70a41002", MUL
        "50a40001", BEQL ]
    for hex, opcode in kept do
      Assert.AreEqual<Opcode>(opcode, (parse hex :?> Instruction).Opcode, hex)

  /// <summary>
  /// The I64 pool EXTENDED (MD00077 EXT-I64 and EXT-RI64): each of the eight
  /// takes the sixteen bits the prefix widens, sign-extended and not scaled.
  /// They had been read as their short forms, the prefix's bits dropped and
  /// the halfword's own five scaled. The PC-relative two sit at 0x1006, so
  /// LD's base clears three bits (0x1000) and DADDIU's two (0x1004).
  /// </summary>
  [<TestMethod>]
  member _.``[MIPS16e] The extended I64 forms take sixteen bits``() =
    let isa = ISA "mips16-64el"
    let parser =
      Parser(isa, BinReader.Init Endian.Little) :> IInstructionParsable
    let parse hex addr =
      let bytes = ByteArray.ofHexString hex
      parser.Parse(System.ReadOnlySpan bytes, addr) :?> Instruction
    let sp (o: int64) = O.Mem(R29, o, 64<rt>)
    let neg (v: int64) = O.Imm(uint64 v)
    let rel (v: int64) = O.Addr(Relative v)
    let cases =
      [ "fff758f8", LD, TwoOperands(O.Reg R2, sp -8L)
        "22f294f9", SD, TwoOperands(O.Reg R4, sp 0x1234L)
        "fff710fa", SD, TwoOperands(O.Reg R31, sp -16L)
        "d9f707fb", DADDIU, ThreeOperands(O.Reg R29, O.Reg R29, neg -12345L)
        "00f160fc", LD, TwoOperands(O.Reg R3, rel 0xfaL)
        "eff71ffd", DADDIU, ThreeOperands(O.Reg R16, O.Reg R16, O.Imm 0x7fffUL)
        "9ff7bcfe", DADDIUPC, TwoOperands(O.Reg R5, rel -0x66L)
        "fff77fff", DADDIU, ThreeOperands(O.Reg R3, O.Reg R29, neg -1L) ]
    for hex, opcode, operands in cases do
      let ins = parse hex 0x1006UL
      Assert.AreEqual<Opcode>(opcode, ins.Opcode, hex)
      Assert.AreEqual<Operands>(operands, ins.Operands, hex)
