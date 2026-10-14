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

  let isa64R2 =
    ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64)

  let disasm64R2 (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let parser =
      Parser(isa64R2, BinReader.Init isa64R2.Endian)
      :> IInstructionParsable
    let ins = parser.Parse(bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  let isa64R6 =
    ISA(Architecture.MIPS,
        Endian.Big,
        WordSize.Bit64,
        int MIPSRelease.R6)

  let disasm64R6 (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let parser =
      Parser(isa64R6, BinReader.Init isa64R6.Endian)
      :> IInstructionParsable
    let ins = parser.Parse(bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

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

  /// A 64-bit processor's registers go by the n64 names whatever the width
  /// an instruction accesses: register 8 is a4 for a store of a byte as much
  /// as for a load of a doubleword, where the o32 name would be t0.
  [<TestMethod>]
  member _.``[MIPS64] A store names its registers as a load does``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64)
    let parser = Parser(isa, BinReader.Init Endian.Big) :> IInstructionParsable
    let text hex =
      let bytes = ByteArray.ofHexString hex
      parser.Parse(System.ReadOnlySpan bytes, 0UL).Disasm()
    Assert.AreEqual<string>("sb a4, 1(a5)", text "a1280001")
    Assert.AreEqual<string>("sh a4, 1(a5)", text "a5280001")
    Assert.AreEqual<string>("sw a4, 1(a5)", text "ad280001")
    Assert.AreEqual<string>("lw a4, 1(a5)", text "8d280001")

  (* One test for each MIPS64 instruction MD00087 describes, in the order of its
     sections. Each reads words of the instruction and checks the text, and each
     word is one binutils' objdump reads as the same instruction with the same
     operands, so what is asserted is a reading two decoders agree on. Read
     before Release 6. *)
  [<TestMethod>]
  member _.``MD00087 ABS.fmt``() =
    disasm64R2 "46000005" "abs.s f0, f0"
    disasm64R2 "46200005" "abs.d f0, f0"
    disasm64R2 "46c00005" "abs.ps f0, f0"
    disasm64R2 "46001805" "abs.s f0, f3"

  [<TestMethod>]
  member _.``MD00087 ADD``() =
    disasm64R2 "00000020" "add r0, r0, r0"
    disasm64R2 "00200020" "add r0, at, r0"
    disasm64R2 "00010020" "add r0, r0, at"
    disasm64R2 "00000820" "add at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 ADD.fmt``() =
    disasm64R2 "46000000" "add.s f0, f0, f0"
    disasm64R2 "46200000" "add.d f0, f0, f0"
    disasm64R2 "46c00000" "add.ps f0, f0, f0"
    disasm64R2 "46021900" "add.s f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 ADDI``() =
    disasm64R2 "20000000" "addi r0, r0, 0x0"
    disasm64R2 "20200000" "addi r0, at, 0x0"
    disasm64R2 "20010000" "addi at, r0, 0x0"
    disasm64R2 "20400000" "addi r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 ADDIU``() =
    disasm64R2 "24000000" "addiu r0, r0, 0x0"
    disasm64R2 "24200000" "addiu r0, at, 0x0"
    disasm64R2 "24010000" "addiu at, r0, 0x0"
    disasm64R2 "24400000" "addiu r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 ADDU``() =
    disasm64R2 "00000021" "addu r0, r0, r0"
    disasm64R2 "00200021" "addu r0, at, r0"
    disasm64R2 "00010021" "addu r0, r0, at"
    disasm64R2 "00000821" "addu at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 ALNV.PS``() =
    disasm64R2 "4c00001e" "alnv.ps f0, f0, f0, r0"
    disasm64R2 "4c20001e" "alnv.ps f0, f0, f0, at"
    disasm64R2 "4c01001e" "alnv.ps f0, f0, f1, r0"
    disasm64R2 "4c00081e" "alnv.ps f0, f1, f0, r0"

  [<TestMethod>]
  member _.``MD00087 AND``() =
    disasm64R2 "00000024" "and r0, r0, r0"
    disasm64R2 "00200024" "and r0, at, r0"
    disasm64R2 "00010024" "and r0, r0, at"
    disasm64R2 "00000824" "and at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 ANDI``() =
    disasm64R2 "30000000" "andi r0, r0, 0x0"
    disasm64R2 "30200000" "andi r0, at, 0x0"
    disasm64R2 "30010000" "andi at, r0, 0x0"
    disasm64R2 "30400000" "andi r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 B``() =
    disasm64R2 "10000000" "b 0x4"

  [<TestMethod>]
  member _.``MD00087 BAL``() =
    disasm64R2 "04110000" "bal 0x4"
    disasm64R2 "04110001" "bal 0x8"
    disasm64R2 "04110002" "bal 0xc"
    disasm64R2 "04110003" "bal 0x10"

  [<TestMethod>]
  member _.``MD00087 BC1F``() =
    disasm64R2 "45000000" "bc1f 0x4"
    disasm64R2 "45000001" "bc1f 0x8"
    disasm64R2 "45000002" "bc1f 0xc"
    disasm64R2 "45000003" "bc1f 0x10"

  [<TestMethod>]
  member _.``MD00087 BC1FL``() =
    disasm64R2 "45021900" "bc1fl 0x6404"
    disasm64R2 "45021901" "bc1fl 0x6408"
    disasm64R2 "45021902" "bc1fl 0x640c"
    disasm64R2 "45021903" "bc1fl 0x6410"

  [<TestMethod>]
  member _.``MD00087 BC1T``() =
    disasm64R2 "45011800" "bc1t 0x6004"
    disasm64R2 "45011801" "bc1t 0x6008"
    disasm64R2 "45011802" "bc1t 0x600c"
    disasm64R2 "45011803" "bc1t 0x6010"

  [<TestMethod>]
  member _.``MD00087 BC1TL``() =
    disasm64R2 "45031800" "bc1tl 0x6004"
    disasm64R2 "45031801" "bc1tl 0x6008"
    disasm64R2 "45031802" "bc1tl 0x600c"
    disasm64R2 "45031803" "bc1tl 0x6010"

  [<TestMethod>]
  member _.``MD00087 BC2F``() =
    disasm64R2 "49000000" "bc2f 0x4"
    disasm64R2 "49000001" "bc2f 0x8"
    disasm64R2 "49000002" "bc2f 0xc"
    disasm64R2 "49000003" "bc2f 0x10"

  [<TestMethod>]
  member _.``MD00087 BC2FL``() =
    disasm64R2 "49021900" "bc2fl 0x6404"
    disasm64R2 "49021901" "bc2fl 0x6408"
    disasm64R2 "49021902" "bc2fl 0x640c"
    disasm64R2 "49021903" "bc2fl 0x6410"

  [<TestMethod>]
  member _.``MD00087 BC2T``() =
    disasm64R2 "49010003" "bc2t 0x10"

  [<TestMethod>]
  member _.``MD00087 BC2TL``() =
    disasm64R2 "49030001" "bc2tl 0x8"

  [<TestMethod>]
  member _.``MD00087 BEQ``() =
    disasm64R2 "10200000" "beq at, r0, 0x4"
    disasm64R2 "10010000" "beq r0, at, 0x4"
    disasm64R2 "10400000" "beq v0, r0, 0x4"
    disasm64R2 "10020000" "beq r0, v0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BEQL``() =
    disasm64R2 "50000000" "beql r0, r0, 0x4"
    disasm64R2 "50200000" "beql at, r0, 0x4"
    disasm64R2 "50010000" "beql r0, at, 0x4"
    disasm64R2 "50400000" "beql v0, r0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BGEZ``() =
    disasm64R2 "04010000" "bgez r0, 0x4"
    disasm64R2 "04010001" "bgez r0, 0x8"
    disasm64R2 "04010002" "bgez r0, 0xc"
    disasm64R2 "04010003" "bgez r0, 0x10"

  [<TestMethod>]
  member _.``MD00087 BGEZAL``() =
    disasm64R2 "04311900" "bgezal at, 0x6404"
    disasm64R2 "04311901" "bgezal at, 0x6408"
    disasm64R2 "04311902" "bgezal at, 0x640c"
    disasm64R2 "04311903" "bgezal at, 0x6410"

  [<TestMethod>]
  member _.``MD00087 BGEZALL``() =
    disasm64R2 "04130000" "bgezall r0, 0x4"
    disasm64R2 "04130001" "bgezall r0, 0x8"
    disasm64R2 "04130002" "bgezall r0, 0xc"
    disasm64R2 "04130003" "bgezall r0, 0x10"

  [<TestMethod>]
  member _.``MD00087 BGEZL``() =
    disasm64R2 "04030000" "bgezl r0, 0x4"
    disasm64R2 "04030001" "bgezl r0, 0x8"
    disasm64R2 "04030002" "bgezl r0, 0xc"
    disasm64R2 "04030003" "bgezl r0, 0x10"

  [<TestMethod>]
  member _.``MD00087 BGTZ``() =
    disasm64R2 "1c000000" "bgtz r0, 0x4"
    disasm64R2 "1c200000" "bgtz at, 0x4"
    disasm64R2 "1c400000" "bgtz v0, 0x4"
    disasm64R2 "1c600000" "bgtz v1, 0x4"

  [<TestMethod>]
  member _.``MD00087 BGTZL``() =
    disasm64R2 "5c000000" "bgtzl r0, 0x4"
    disasm64R2 "5c200000" "bgtzl at, 0x4"
    disasm64R2 "5c400000" "bgtzl v0, 0x4"
    disasm64R2 "5c600000" "bgtzl v1, 0x4"

  [<TestMethod>]
  member _.``MD00087 BLEZ``() =
    disasm64R2 "18000000" "blez r0, 0x4"
    disasm64R2 "18200000" "blez at, 0x4"
    disasm64R2 "18400000" "blez v0, 0x4"
    disasm64R2 "18600000" "blez v1, 0x4"

  [<TestMethod>]
  member _.``MD00087 BLEZL``() =
    disasm64R2 "58000000" "blezl r0, 0x4"
    disasm64R2 "58200000" "blezl at, 0x4"
    disasm64R2 "58400000" "blezl v0, 0x4"
    disasm64R2 "58600000" "blezl v1, 0x4"

  [<TestMethod>]
  member _.``MD00087 BLTZ``() =
    disasm64R2 "04000000" "bltz r0, 0x4"
    disasm64R2 "04200000" "bltz at, 0x4"
    disasm64R2 "04400000" "bltz v0, 0x4"
    disasm64R2 "04600000" "bltz v1, 0x4"

  [<TestMethod>]
  member _.``MD00087 BLTZAL``() =
    disasm64R2 "04301900" "bltzal at, 0x6404"
    disasm64R2 "04301901" "bltzal at, 0x6408"
    disasm64R2 "04301902" "bltzal at, 0x640c"
    disasm64R2 "04301903" "bltzal at, 0x6410"

  [<TestMethod>]
  member _.``MD00087 BLTZALL``() =
    disasm64R2 "04120000" "bltzall r0, 0x4"
    disasm64R2 "04120001" "bltzall r0, 0x8"
    disasm64R2 "04120002" "bltzall r0, 0xc"
    disasm64R2 "04120003" "bltzall r0, 0x10"

  [<TestMethod>]
  member _.``MD00087 BLTZL``() =
    disasm64R2 "04020000" "bltzl r0, 0x4"
    disasm64R2 "04020001" "bltzl r0, 0x8"
    disasm64R2 "04020002" "bltzl r0, 0xc"
    disasm64R2 "04020003" "bltzl r0, 0x10"

  [<TestMethod>]
  member _.``MD00087 BNE``() =
    disasm64R2 "14000000" "bne r0, r0, 0x4"
    disasm64R2 "14200000" "bne at, r0, 0x4"
    disasm64R2 "14010000" "bne r0, at, 0x4"
    disasm64R2 "14400000" "bne v0, r0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BNEL``() =
    disasm64R2 "54000000" "bnel r0, r0, 0x4"
    disasm64R2 "54200000" "bnel at, r0, 0x4"
    disasm64R2 "54010000" "bnel r0, at, 0x4"
    disasm64R2 "54400000" "bnel v0, r0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BREAK``() =
    disasm64R2 "0000000d" "break"

  [<TestMethod>]
  member _.``MD00087 C.cond.fmt``() =
    disasm64R2 "46000030" "c.f.s f0, f0"
    disasm64R2 "46200030" "c.f.d f0, f0"
    disasm64R2 "46c00030" "c.f.ps f0, f0"
    disasm64R2 "46000031" "c.un.s f0, f0"

  [<TestMethod>]
  member _.``MD00087 CACHE``() =
    disasm64R2 "bc000000" "cache 0x0, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 CACHEE``() =
    disasm64R2 "7c00001b" "cachee 0x0, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 CEIL.L.fmt``() =
    disasm64R2 "4600000a" "ceil.l.s f0, f0"
    disasm64R2 "4620000a" "ceil.l.d f0, f0"
    disasm64R2 "4600180a" "ceil.l.s f0, f3"
    disasm64R2 "4620180a" "ceil.l.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 CEIL.W.fmt``() =
    disasm64R2 "4600000e" "ceil.w.s f0, f0"
    disasm64R2 "4620000e" "ceil.w.d f0, f0"
    disasm64R2 "4600180e" "ceil.w.s f0, f3"
    disasm64R2 "4620180e" "ceil.w.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 CFC1``() =
    disasm64R2 "44400000" "cfc1 r0, f0"
    disasm64R2 "44401800" "cfc1 r0, f3"
    disasm64R2 "44411800" "cfc1 at, f3"
    disasm64R2 "44421800" "cfc1 v0, f3"

  [<TestMethod>]
  member _.``MD00087 CFC2``() =
    disasm64R2 "48400000" "cfc2 r0, 0x0"

  [<TestMethod>]
  member _.``MD00087 CLO``() =
    disasm64R2 "70000021" "clo r0, r0"
    disasm64R2 "70200021" "clo r0, at"
    disasm64R2 "70000821" "clo at, r0"
    disasm64R2 "70400021" "clo r0, v0"

  [<TestMethod>]
  member _.``MD00087 CLZ``() =
    disasm64R2 "70000020" "clz r0, r0"
    disasm64R2 "70200020" "clz r0, at"
    disasm64R2 "70000820" "clz at, r0"
    disasm64R2 "70400020" "clz r0, v0"

  [<TestMethod>]
  member _.``MD00087 COP2``() =
    disasm64R2 "4a000000" "cop2 0x0"
    disasm64R2 "4a200000" "cop2 0x200000"
    disasm64R2 "4a400000" "cop2 0x400000"
    disasm64R2 "4a600000" "cop2 0x600000"

  [<TestMethod>]
  member _.``MD00087 CTC1``() =
    disasm64R2 "44c00000" "ctc1 r0, f0"
    disasm64R2 "44c01800" "ctc1 r0, f3"
    disasm64R2 "44c11800" "ctc1 at, f3"
    disasm64R2 "44c21800" "ctc1 v0, f3"

  [<TestMethod>]
  member _.``MD00087 CTC2``() =
    disasm64R2 "48c00000" "ctc2 r0, 0x0"

  [<TestMethod>]
  member _.``MD00087 CVT.D.fmt``() =
    disasm64R2 "46000021" "cvt.d.s f0, f0"
    disasm64R2 "46800021" "cvt.d.w f0, f0"
    disasm64R2 "46a00021" "cvt.d.l f0, f0"
    disasm64R2 "46001821" "cvt.d.s f0, f3"

  [<TestMethod>]
  member _.``MD00087 CVT.L.fmt``() =
    disasm64R2 "46000025" "cvt.l.s f0, f0"
    disasm64R2 "46200025" "cvt.l.d f0, f0"
    disasm64R2 "46001825" "cvt.l.s f0, f3"
    disasm64R2 "46201825" "cvt.l.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 CVT.PS.S``() =
    disasm64R2 "46000026" "cvt.ps.s f0, f0, f0"
    disasm64R2 "46021926" "cvt.ps.s f4, f3, f2"
    disasm64R2 "461eef26" "cvt.ps.s f28, f29, f30"
    disasm64R2 "46001826" "cvt.ps.s f0, f3, f0"

  [<TestMethod>]
  member _.``MD00087 CVT.S.PL``() =
    disasm64R2 "46c00028" "cvt.s.pl f0, f0"
    disasm64R2 "46c01828" "cvt.s.pl f0, f3"

  [<TestMethod>]
  member _.``MD00087 CVT.S.PU``() =
    disasm64R2 "46c00020" "cvt.s.pu f0, f0"
    disasm64R2 "46c01820" "cvt.s.pu f0, f3"

  [<TestMethod>]
  member _.``MD00087 CVT.S.fmt``() =
    disasm64R2 "46200020" "cvt.s.d f0, f0"
    disasm64R2 "46800020" "cvt.s.w f0, f0"
    disasm64R2 "46a00020" "cvt.s.l f0, f0"
    disasm64R2 "46201820" "cvt.s.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 CVT.W.fmt``() =
    disasm64R2 "46000024" "cvt.w.s f0, f0"
    disasm64R2 "46200024" "cvt.w.d f0, f0"
    disasm64R2 "46001824" "cvt.w.s f0, f3"
    disasm64R2 "46201824" "cvt.w.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 DADD``() =
    disasm64R2 "0000002c" "dadd r0, r0, r0"
    disasm64R2 "0020002c" "dadd r0, at, r0"
    disasm64R2 "0001002c" "dadd r0, r0, at"
    disasm64R2 "0000082c" "dadd at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 DADDI``() =
    disasm64R2 "60000000" "daddi r0, r0, 0x0"
    disasm64R2 "60200000" "daddi r0, at, 0x0"
    disasm64R2 "60010000" "daddi at, r0, 0x0"
    disasm64R2 "60400000" "daddi r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DADDIU``() =
    disasm64R2 "64000000" "daddiu r0, r0, 0x0"
    disasm64R2 "64200000" "daddiu r0, at, 0x0"
    disasm64R2 "64010000" "daddiu at, r0, 0x0"
    disasm64R2 "64400000" "daddiu r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DADDU``() =
    disasm64R2 "0001002d" "daddu r0, r0, at"
    disasm64R2 "0002002d" "daddu r0, r0, v0"
    disasm64R2 "0003002d" "daddu r0, r0, v1"
    disasm64R2 "0004002d" "daddu r0, r0, a0"

  [<TestMethod>]
  member _.``MD00087 DCLO``() =
    disasm64R2 "70000025" "dclo r0, r0"
    disasm64R2 "70200025" "dclo r0, at"
    disasm64R2 "70000825" "dclo at, r0"
    disasm64R2 "70400025" "dclo r0, v0"

  [<TestMethod>]
  member _.``MD00087 DCLZ``() =
    disasm64R2 "70000024" "dclz r0, r0"
    disasm64R2 "70200024" "dclz r0, at"
    disasm64R2 "70000824" "dclz at, r0"
    disasm64R2 "70400024" "dclz r0, v0"

  [<TestMethod>]
  member _.``MD00087 DDIV``() =
    disasm64R2 "0000001e" "ddiv r0, r0"
    disasm64R2 "0020001e" "ddiv at, r0"
    disasm64R2 "0001001e" "ddiv r0, at"
    disasm64R2 "0040001e" "ddiv v0, r0"

  [<TestMethod>]
  member _.``MD00087 DDIVU``() =
    disasm64R2 "0000001f" "ddivu r0, r0"
    disasm64R2 "0020001f" "ddivu at, r0"
    disasm64R2 "0001001f" "ddivu r0, at"
    disasm64R2 "0040001f" "ddivu v0, r0"

  [<TestMethod>]
  member _.``MD00087 DERET``() =
    disasm64R2 "4200001f" "deret"

  [<TestMethod>]
  member _.``MD00087 DEXT``() =
    disasm64R2 "7c000003" "dext r0, r0, 0x0, 0x1"
    disasm64R2 "7c200003" "dext r0, at, 0x0, 0x1"
    disasm64R2 "7c010003" "dext at, r0, 0x0, 0x1"
    disasm64R2 "7c400003" "dext r0, v0, 0x0, 0x1"

  [<TestMethod>]
  member _.``MD00087 DEXTM``() =
    disasm64R2 "7c000001" "dextm r0, r0, 0x0, 0x21"
    disasm64R2 "7c200001" "dextm r0, at, 0x0, 0x21"
    disasm64R2 "7c010001" "dextm at, r0, 0x0, 0x21"
    disasm64R2 "7c400001" "dextm r0, v0, 0x0, 0x21"

  [<TestMethod>]
  member _.``MD00087 DEXTU``() =
    disasm64R2 "7c000002" "dextu r0, r0, 0x20, 0x1"
    disasm64R2 "7c200002" "dextu r0, at, 0x20, 0x1"
    disasm64R2 "7c010002" "dextu at, r0, 0x20, 0x1"
    disasm64R2 "7c400002" "dextu r0, v0, 0x20, 0x1"

  [<TestMethod>]
  member _.``MD00087 DI``() =
    disasm64R2 "41626000" "di v0"

  [<TestMethod>]
  member _.``MD00087 DINS``() =
    disasm64R2 "7c000007" "dins r0, r0, 0x0, 0x1"
    disasm64R2 "7c200007" "dins r0, at, 0x0, 0x1"
    disasm64R2 "7c010007" "dins at, r0, 0x0, 0x1"
    disasm64R2 "7c400007" "dins r0, v0, 0x0, 0x1"

  [<TestMethod>]
  member _.``MD00087 DINSM``() =
    disasm64R2 "7c000005" "dinsm r0, r0, 0x0, 0x21"
    disasm64R2 "7c200005" "dinsm r0, at, 0x0, 0x21"
    disasm64R2 "7c010005" "dinsm at, r0, 0x0, 0x21"
    disasm64R2 "7c400005" "dinsm r0, v0, 0x0, 0x21"

  [<TestMethod>]
  member _.``MD00087 DINSU``() =
    disasm64R2 "7c000006" "dinsu r0, r0, 0x20, 0x1"
    disasm64R2 "7c200006" "dinsu r0, at, 0x20, 0x1"
    disasm64R2 "7c010006" "dinsu at, r0, 0x20, 0x1"
    disasm64R2 "7c400006" "dinsu r0, v0, 0x20, 0x1"

  [<TestMethod>]
  member _.``MD00087 DIV``() =
    disasm64R2 "0000001a" "div r0, r0"
    disasm64R2 "0020001a" "div at, r0"
    disasm64R2 "0001001a" "div r0, at"
    disasm64R2 "0040001a" "div v0, r0"

  [<TestMethod>]
  member _.``MD00087 DIV.fmt``() =
    disasm64R2 "46000003" "div.s f0, f0, f0"
    disasm64R2 "46200003" "div.d f0, f0, f0"
    disasm64R2 "46021903" "div.s f4, f3, f2"
    disasm64R2 "46221903" "div.d f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 DIVU``() =
    disasm64R2 "0000001b" "divu r0, r0"
    disasm64R2 "0020001b" "divu at, r0"
    disasm64R2 "0001001b" "divu r0, at"
    disasm64R2 "0040001b" "divu v0, r0"

  [<TestMethod>]
  member _.``MD00087 DMFC0``() =
    disasm64R2 "40200001" "dmfc0 r0, 0x0, 0x1"
    disasm64R2 "40200002" "dmfc0 r0, 0x0, 0x2"
    disasm64R2 "40200003" "dmfc0 r0, 0x0, 0x3"
    disasm64R2 "40221801" "dmfc0 v0, 0x3, 0x1"

  [<TestMethod>]
  member _.``MD00087 DMFC1``() =
    disasm64R2 "44200000" "dmfc1 r0, f0"
    disasm64R2 "44221800" "dmfc1 v0, f3"
    disasm64R2 "44201800" "dmfc1 r0, f3"
    disasm64R2 "44211800" "dmfc1 at, f3"

  [<TestMethod>]
  member _.``MD00087 DMFC2``() =
    disasm64R2 "48200000" "dmfc2 r0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DMTC0``() =
    disasm64R2 "40a00001" "dmtc0 r0, 0x0, 0x1"
    disasm64R2 "40a00002" "dmtc0 r0, 0x0, 0x2"
    disasm64R2 "40a00003" "dmtc0 r0, 0x0, 0x3"

  [<TestMethod>]
  member _.``MD00087 DMTC1``() =
    disasm64R2 "44a00000" "dmtc1 r0, f0"
    disasm64R2 "44a01800" "dmtc1 r0, f3"
    disasm64R2 "44a11800" "dmtc1 at, f3"
    disasm64R2 "44a21800" "dmtc1 v0, f3"

  [<TestMethod>]
  member _.``MD00087 DMTC2``() =
    disasm64R2 "48a00000" "dmtc2 r0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DMULT``() =
    disasm64R2 "0000001c" "dmult r0, r0"
    disasm64R2 "0020001c" "dmult at, r0"
    disasm64R2 "0001001c" "dmult r0, at"
    disasm64R2 "0040001c" "dmult v0, r0"

  [<TestMethod>]
  member _.``MD00087 DMULTU``() =
    disasm64R2 "0000001d" "dmultu r0, r0"
    disasm64R2 "0020001d" "dmultu at, r0"
    disasm64R2 "0001001d" "dmultu r0, at"
    disasm64R2 "0040001d" "dmultu v0, r0"

  [<TestMethod>]
  member _.``MD00087 DROTR``() =
    disasm64R2 "0020003a" "drotr r0, r0, 0x0"
    disasm64R2 "0020193a" "drotr v1, r0, 0x4"
    disasm64R2 "0022013a" "drotr r0, v0, 0x4"
    disasm64R2 "0022183a" "drotr v1, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DROTR32``() =
    disasm64R2 "0020003e" "drotr32  r0, r0, 0x0"
    disasm64R2 "0020193e" "drotr32  v1, r0, 0x4"
    disasm64R2 "0022013e" "drotr32  r0, v0, 0x4"
    disasm64R2 "0022183e" "drotr32  v1, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DROTRV``() =
    disasm64R2 "00000056" "drotrv r0, r0, r0"
    disasm64R2 "00221856" "drotrv v1, v0, at"
    disasm64R2 "03fee856" "drotrv sp, s8, ra"

  [<TestMethod>]
  member _.``MD00087 DSBH``() =
    disasm64R2 "7c0000a4" "dsbh r0, r0"

  [<TestMethod>]
  member _.``MD00087 DSHD``() =
    disasm64R2 "7c000164" "dshd r0, r0"

  [<TestMethod>]
  member _.``MD00087 DSLL``() =
    disasm64R2 "00000038" "dsll r0, r0, 0x0"
    disasm64R2 "00010038" "dsll r0, at, 0x0"
    disasm64R2 "00000838" "dsll at, r0, 0x0"
    disasm64R2 "00020038" "dsll r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DSLL32``() =
    disasm64R2 "0000003c" "dsll32 r0, r0, 0x0"
    disasm64R2 "0001003c" "dsll32 r0, at, 0x0"
    disasm64R2 "0000083c" "dsll32 at, r0, 0x0"
    disasm64R2 "0002003c" "dsll32 r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DSLLV``() =
    disasm64R2 "00000014" "dsllv r0, r0, r0"
    disasm64R2 "00200014" "dsllv r0, r0, at"
    disasm64R2 "00010014" "dsllv r0, at, r0"
    disasm64R2 "00000814" "dsllv at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 DSRA``() =
    disasm64R2 "0000003b" "dsra r0, r0, 0x0"
    disasm64R2 "0001003b" "dsra r0, at, 0x0"
    disasm64R2 "0000083b" "dsra at, r0, 0x0"
    disasm64R2 "0002003b" "dsra r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DSRA32``() =
    disasm64R2 "0000003f" "dsra32 r0, r0, 0x0"
    disasm64R2 "0001003f" "dsra32 r0, at, 0x0"
    disasm64R2 "0000083f" "dsra32 at, r0, 0x0"
    disasm64R2 "0002003f" "dsra32 r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DSRAV``() =
    disasm64R2 "00000017" "dsrav r0, r0, r0"
    disasm64R2 "00200017" "dsrav r0, r0, at"
    disasm64R2 "00010017" "dsrav r0, at, r0"
    disasm64R2 "00000817" "dsrav at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 DSRL``() =
    disasm64R2 "0000003a" "dsrl r0, r0, 0x0"
    disasm64R2 "0001003a" "dsrl r0, at, 0x0"
    disasm64R2 "0000083a" "dsrl at, r0, 0x0"
    disasm64R2 "0002003a" "dsrl r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DSRL32``() =
    disasm64R2 "0000003e" "dsrl32 r0, r0, 0x0"
    disasm64R2 "0001003e" "dsrl32 r0, at, 0x0"
    disasm64R2 "0000083e" "dsrl32 at, r0, 0x0"
    disasm64R2 "0002003e" "dsrl32 r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DSRLV``() =
    disasm64R2 "00000016" "dsrlv r0, r0, r0"
    disasm64R2 "00200016" "dsrlv r0, r0, at"
    disasm64R2 "00010016" "dsrlv r0, at, r0"
    disasm64R2 "00000816" "dsrlv at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 DSUB``() =
    disasm64R2 "0020002e" "dsub r0, at, r0"
    disasm64R2 "0040002e" "dsub r0, v0, r0"
    disasm64R2 "0060002e" "dsub r0, v1, r0"
    disasm64R2 "0080002e" "dsub r0, a0, r0"

  [<TestMethod>]
  member _.``MD00087 DSUBU``() =
    disasm64R2 "0020002f" "dsubu r0, at, r0"
    disasm64R2 "0040002f" "dsubu r0, v0, r0"
    disasm64R2 "0060002f" "dsubu r0, v1, r0"
    disasm64R2 "0080002f" "dsubu r0, a0, r0"

  [<TestMethod>]
  member _.``MD00087 EHB``() =
    disasm64R2 "000000c0" "ehb"

  [<TestMethod>]
  member _.``MD00087 EI``() =
    disasm64R2 "41636020" "ei v1"

  [<TestMethod>]
  member _.``MD00087 ERET``() =
    disasm64R2 "42000018" "eret"

  [<TestMethod>]
  member _.``MD00087 EXT``() =
    disasm64R2 "7c000000" "ext r0, r0, 0x0, 0x1"
    disasm64R2 "7c200000" "ext r0, at, 0x0, 0x1"
    disasm64R2 "7c010000" "ext at, r0, 0x0, 0x1"
    disasm64R2 "7c400000" "ext r0, v0, 0x0, 0x1"

  [<TestMethod>]
  member _.``MD00087 FLOOR.L.fmt``() =
    disasm64R2 "4600000b" "floor.l.s f0, f0"
    disasm64R2 "4620000b" "floor.l.d f0, f0"
    disasm64R2 "4600180b" "floor.l.s f0, f3"
    disasm64R2 "4620180b" "floor.l.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 FLOOR.W.fmt``() =
    disasm64R2 "4600000f" "floor.w.s f0, f0"
    disasm64R2 "4620000f" "floor.w.d f0, f0"
    disasm64R2 "4600180f" "floor.w.s f0, f3"
    disasm64R2 "4620180f" "floor.w.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 INS``() =
    disasm64R2 "7c000004" "ins r0, r0, 0x0, 0x1"
    disasm64R2 "7c200004" "ins r0, at, 0x0, 0x1"
    disasm64R2 "7c010004" "ins at, r0, 0x0, 0x1"
    disasm64R2 "7c400004" "ins r0, v0, 0x0, 0x1"

  [<TestMethod>]
  member _.``MD00087 J``() =
    disasm64R2 "08000000" "j 0x0"

  [<TestMethod>]
  member _.``MD00087 JAL``() =
    disasm64R2 "0c000000" "jal 0x0"

  [<TestMethod>]
  member _.``MD00087 JALR``() =
    disasm64R2 "00000809" "jalr at, r0"
    disasm64R2 "00001009" "jalr v0, r0"
    disasm64R2 "00001809" "jalr v1, r0"
    disasm64R2 "00002009" "jalr a0, r0"

  [<TestMethod>]
  member _.``MD00087 JALR.HB``() =
    disasm64R2 "00000409" "jalr.hb r0, r0"

  [<TestMethod>]
  member _.``MD00087 JALX``() =
    disasm64R2 "74000000" "jalx 0x0"

  [<TestMethod>]
  member _.``MD00087 JR``() =
    disasm64R2 "00000008" "jr r0"
    disasm64R2 "00200008" "jr at"
    disasm64R2 "00400008" "jr v0"
    disasm64R2 "00600008" "jr v1"

  [<TestMethod>]
  member _.``MD00087 JR.HB``() =
    disasm64R2 "00000408" "jr.hb r0"
    disasm64R2 "00000409" "jalr.hb r0, r0"

  [<TestMethod>]
  member _.``MD00087 LB``() =
    disasm64R2 "80000000" "lb r0, 0(r0)"
    disasm64R2 "80010000" "lb at, 0(r0)"
    disasm64R2 "80020000" "lb v0, 0(r0)"
    disasm64R2 "80030000" "lb v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LBE``() =
    disasm64R2 "7c00002c" "lbe r0, 0(r0)"
    disasm64R2 "7c01002c" "lbe at, 0(r0)"
    disasm64R2 "7c02002c" "lbe v0, 0(r0)"
    disasm64R2 "7c03002c" "lbe v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LBU``() =
    disasm64R2 "90000000" "lbu r0, 0(r0)"
    disasm64R2 "90010000" "lbu at, 0(r0)"
    disasm64R2 "90020000" "lbu v0, 0(r0)"
    disasm64R2 "90030000" "lbu v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LBUE``() =
    disasm64R2 "7c000028" "lbue r0, 0(r0)"
    disasm64R2 "7c010028" "lbue at, 0(r0)"
    disasm64R2 "7c020028" "lbue v0, 0(r0)"
    disasm64R2 "7c030028" "lbue v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LD``() =
    disasm64R2 "dc000000" "ld r0, 0(r0)"
    disasm64R2 "dc010000" "ld at, 0(r0)"
    disasm64R2 "dc020000" "ld v0, 0(r0)"
    disasm64R2 "dc030000" "ld v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LDC1``() =
    disasm64R2 "d4000000" "ldc1 f0, 0(r0)"
    disasm64R2 "d4010000" "ldc1 f1, 0(r0)"
    disasm64R2 "d4020000" "ldc1 f2, 0(r0)"
    disasm64R2 "d4030000" "ldc1 f3, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LDC2``() =
    disasm64R2 "d8000000" "ldc2 0x0, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LDL``() =
    disasm64R2 "68000000" "ldl r0, 0(r0)"
    disasm64R2 "68010000" "ldl at, 0(r0)"
    disasm64R2 "68020000" "ldl v0, 0(r0)"
    disasm64R2 "68030000" "ldl v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LDR``() =
    disasm64R2 "6c000000" "ldr r0, 0(r0)"
    disasm64R2 "6c010000" "ldr at, 0(r0)"
    disasm64R2 "6c020000" "ldr v0, 0(r0)"
    disasm64R2 "6c030000" "ldr v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LDXC1``() =
    disasm64R2 "4c000001" "ldxc1 f0, r0(r0)"
    disasm64R2 "4c200001" "ldxc1 f0, r0(at)"
    disasm64R2 "4c010001" "ldxc1 f0, at(r0)"
    disasm64R2 "4c000041" "ldxc1 f1, r0(r0)"

  [<TestMethod>]
  member _.``MD00087 LH``() =
    disasm64R2 "84000000" "lh r0, 0(r0)"
    disasm64R2 "84010000" "lh at, 0(r0)"
    disasm64R2 "84020000" "lh v0, 0(r0)"
    disasm64R2 "84030000" "lh v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LHE``() =
    disasm64R2 "7c00002d" "lhe r0, 0(r0)"
    disasm64R2 "7c01002d" "lhe at, 0(r0)"
    disasm64R2 "7c02002d" "lhe v0, 0(r0)"
    disasm64R2 "7c03002d" "lhe v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LHU``() =
    disasm64R2 "94000000" "lhu r0, 0(r0)"
    disasm64R2 "94010000" "lhu at, 0(r0)"
    disasm64R2 "94020000" "lhu v0, 0(r0)"
    disasm64R2 "94030000" "lhu v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LHUE``() =
    disasm64R2 "7c000029" "lhue r0, 0(r0)"
    disasm64R2 "7c010029" "lhue at, 0(r0)"
    disasm64R2 "7c020029" "lhue v0, 0(r0)"
    disasm64R2 "7c030029" "lhue v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LL``() =
    disasm64R2 "c0000000" "ll r0, 0(r0)"
    disasm64R2 "c0010000" "ll at, 0(r0)"
    disasm64R2 "c0020000" "ll v0, 0(r0)"
    disasm64R2 "c0030000" "ll v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LLD``() =
    disasm64R2 "d0000000" "lld r0, 0(r0)"
    disasm64R2 "d0010000" "lld at, 0(r0)"
    disasm64R2 "d0020000" "lld v0, 0(r0)"
    disasm64R2 "d0030000" "lld v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LLE``() =
    disasm64R2 "7c00002e" "lle r0, 0(r0)"
    disasm64R2 "7c01002e" "lle at, 0(r0)"
    disasm64R2 "7c02002e" "lle v0, 0(r0)"
    disasm64R2 "7c03002e" "lle v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LUI``() =
    disasm64R2 "3c000000" "lui r0, 0x0"
    disasm64R2 "3c010000" "lui at, 0x0"
    disasm64R2 "3c020000" "lui v0, 0x0"
    disasm64R2 "3c030000" "lui v1, 0x0"

  [<TestMethod>]
  member _.``MD00087 LUXC1``() =
    disasm64R2 "4c000005" "luxc1 f0, r0(r0)"
    disasm64R2 "4c200005" "luxc1 f0, r0(at)"
    disasm64R2 "4c010005" "luxc1 f0, at(r0)"
    disasm64R2 "4c000045" "luxc1 f1, r0(r0)"

  [<TestMethod>]
  member _.``MD00087 LW``() =
    disasm64R2 "8c000000" "lw r0, 0(r0)"
    disasm64R2 "8c010000" "lw at, 0(r0)"
    disasm64R2 "8c020000" "lw v0, 0(r0)"
    disasm64R2 "8c030000" "lw v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LWC1``() =
    disasm64R2 "c4000000" "lwc1 f0, 0(r0)"
    disasm64R2 "c4010000" "lwc1 f1, 0(r0)"
    disasm64R2 "c4020000" "lwc1 f2, 0(r0)"
    disasm64R2 "c4030000" "lwc1 f3, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LWC2``() =
    disasm64R2 "c8000000" "lwc2 0x0, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LWE``() =
    disasm64R2 "7c00002f" "lwe r0, 0(r0)"
    disasm64R2 "7c01002f" "lwe at, 0(r0)"
    disasm64R2 "7c02002f" "lwe v0, 0(r0)"
    disasm64R2 "7c03002f" "lwe v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LWL``() =
    disasm64R2 "88000000" "lwl r0, 0(r0)"
    disasm64R2 "88010000" "lwl at, 0(r0)"
    disasm64R2 "88020000" "lwl v0, 0(r0)"
    disasm64R2 "88030000" "lwl v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LWLE``() =
    disasm64R2 "7c000019" "lwle r0, 0(r0)"
    disasm64R2 "7c010019" "lwle at, 0(r0)"
    disasm64R2 "7c020019" "lwle v0, 0(r0)"
    disasm64R2 "7c030019" "lwle v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LWR``() =
    disasm64R2 "98000000" "lwr r0, 0(r0)"
    disasm64R2 "98010000" "lwr at, 0(r0)"
    disasm64R2 "98020000" "lwr v0, 0(r0)"
    disasm64R2 "98030000" "lwr v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LWRE``() =
    disasm64R2 "7c00001a" "lwre r0, 0(r0)"
    disasm64R2 "7c01001a" "lwre at, 0(r0)"
    disasm64R2 "7c02001a" "lwre v0, 0(r0)"
    disasm64R2 "7c03001a" "lwre v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LWU``() =
    disasm64R2 "9c000000" "lwu r0, 0(r0)"
    disasm64R2 "9c010000" "lwu at, 0(r0)"
    disasm64R2 "9c020000" "lwu v0, 0(r0)"
    disasm64R2 "9c030000" "lwu v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LWXC1``() =
    disasm64R2 "4c000000" "lwxc1 f0, r0(r0)"
    disasm64R2 "4c200000" "lwxc1 f0, r0(at)"
    disasm64R2 "4c010000" "lwxc1 f0, at(r0)"
    disasm64R2 "4c000040" "lwxc1 f1, r0(r0)"

  [<TestMethod>]
  member _.``MD00087 MADD``() =
    disasm64R2 "70000000" "madd r0, r0"
    disasm64R2 "70200000" "madd at, r0"
    disasm64R2 "70010000" "madd r0, at"
    disasm64R2 "70400000" "madd v0, r0"

  [<TestMethod>]
  member _.``MD00087 MADD.fmt``() =
    disasm64R2 "4c000020" "madd.s f0, f0, f0, f0"
    disasm64R2 "4c200020" "madd.s f0, f1, f0, f0"
    disasm64R2 "4c010020" "madd.s f0, f0, f0, f1"
    disasm64R2 "4c000820" "madd.s f0, f0, f1, f0"

  [<TestMethod>]
  member _.``MD00087 MADDU``() =
    disasm64R2 "70000001" "maddu r0, r0"
    disasm64R2 "70200001" "maddu at, r0"
    disasm64R2 "70010001" "maddu r0, at"
    disasm64R2 "70400001" "maddu v0, r0"

  [<TestMethod>]
  member _.``MD00087 MFC0``() =
    disasm64R2 "40000000" "mfc0 r0, 0x0, 0x0"
    disasm64R2 "40010000" "mfc0 at, 0x0, 0x0"
    disasm64R2 "40020000" "mfc0 v0, 0x0, 0x0"
    disasm64R2 "40030000" "mfc0 v1, 0x0, 0x0"

  [<TestMethod>]
  member _.``MD00087 MFC1``() =
    disasm64R2 "44000000" "mfc1 r0, f0"
    disasm64R2 "44010000" "mfc1 at, f0"
    disasm64R2 "44000800" "mfc1 r0, f1"
    disasm64R2 "44020000" "mfc1 v0, f0"

  [<TestMethod>]
  member _.``MD00087 MFC2``() =
    disasm64R2 "48000000" "mfc2 r0, 0x0"
    disasm64R2 "48010000" "mfc2 at, 0x0"
    disasm64R2 "48020000" "mfc2 v0, 0x0"
    disasm64R2 "48030000" "mfc2 v1, 0x0"

  [<TestMethod>]
  member _.``MD00087 MFHC0``() =
    disasm64R2 "40400000" "mfhc0 r0, 0x0, 0x0"
    disasm64R2 "40400001" "mfhc0 r0, 0x0, 0x1"
    disasm64R2 "40400002" "mfhc0 r0, 0x0, 0x2"
    disasm64R2 "40400003" "mfhc0 r0, 0x0, 0x3"

  [<TestMethod>]
  member _.``MD00087 MFHC1``() =
    disasm64R2 "44600000" "mfhc1 r0, f0"
    disasm64R2 "44601800" "mfhc1 r0, f3"
    disasm64R2 "44611800" "mfhc1 at, f3"
    disasm64R2 "44621800" "mfhc1 v0, f3"

  [<TestMethod>]
  member _.``MD00087 MFHC2``() =
    disasm64R2 "48600000" "mfhc2 r0, 0x0"
    disasm64R2 "48621900" "mfhc2 v0, 0x1900"
    disasm64R2 "48621901" "mfhc2 v0, 0x1901"
    disasm64R2 "48621902" "mfhc2 v0, 0x1902"

  [<TestMethod>]
  member _.``MD00087 MFHI``() =
    disasm64R2 "00000010" "mfhi r0"
    disasm64R2 "00000810" "mfhi at"
    disasm64R2 "00001010" "mfhi v0"
    disasm64R2 "00001810" "mfhi v1"

  [<TestMethod>]
  member _.``MD00087 MFLO``() =
    disasm64R2 "00000012" "mflo r0"
    disasm64R2 "00000812" "mflo at"
    disasm64R2 "00001012" "mflo v0"
    disasm64R2 "00001812" "mflo v1"

  [<TestMethod>]
  member _.``MD00087 MOV.fmt``() =
    disasm64R2 "46000006" "mov.s f0, f0"
    disasm64R2 "46200006" "mov.d f0, f0"
    disasm64R2 "46c00006" "mov.ps f0, f0"
    disasm64R2 "46001806" "mov.s f0, f3"

  [<TestMethod>]
  member _.``MD00087 MOVF``() =
    disasm64R2 "00000001" "movf r0, r0, 0x0"
    disasm64R2 "00200001" "movf r0, at, 0x0"
    disasm64R2 "00000801" "movf at, r0, 0x0"
    disasm64R2 "00400001" "movf r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 MOVF.fmt``() =
    disasm64R2 "46000011" "movf.s f0, f0, 0x0"
    disasm64R2 "46200011" "movf.d f0, f0, 0x0"
    disasm64R2 "46c00011" "movf.ps f0, f0, 0x0"
    disasm64R2 "46001811" "movf.s f0, f3, 0x0"

  [<TestMethod>]
  member _.``MD00087 MOVN``() =
    disasm64R2 "0000000b" "movn r0, r0, r0"
    disasm64R2 "0020000b" "movn r0, at, r0"
    disasm64R2 "0001000b" "movn r0, r0, at"
    disasm64R2 "0000080b" "movn at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 MOVN.fmt``() =
    disasm64R2 "46000013" "movn.s f0, f0, r0"
    disasm64R2 "46200013" "movn.d f0, f0, r0"
    disasm64R2 "46c00013" "movn.ps f0, f0, r0"
    disasm64R2 "46021913" "movn.s f4, f3, v0"

  [<TestMethod>]
  member _.``MD00087 MOVT``() =
    disasm64R2 "00010001" "movt r0, r0, 0x0"
    disasm64R2 "00050001" "movt r0, r0, 0x1"
    disasm64R2 "00090001" "movt r0, r0, 0x2"
    disasm64R2 "000d0001" "movt r0, r0, 0x3"

  [<TestMethod>]
  member _.``MD00087 MOVT.fmt``() =
    disasm64R2 "46011811" "movt.s f0, f3, 0x0"
    disasm64R2 "46051811" "movt.s f0, f3, 0x1"
    disasm64R2 "46091811" "movt.s f0, f3, 0x2"
    disasm64R2 "460d1811" "movt.s f0, f3, 0x3"

  [<TestMethod>]
  member _.``MD00087 MOVZ``() =
    disasm64R2 "0000000a" "movz r0, r0, r0"
    disasm64R2 "0020000a" "movz r0, at, r0"
    disasm64R2 "0001000a" "movz r0, r0, at"
    disasm64R2 "0000080a" "movz at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 MOVZ.fmt``() =
    disasm64R2 "46000012" "movz.s f0, f0, r0"
    disasm64R2 "46200012" "movz.d f0, f0, r0"
    disasm64R2 "46c00012" "movz.ps f0, f0, r0"
    disasm64R2 "46021912" "movz.s f4, f3, v0"

  [<TestMethod>]
  member _.``MD00087 MSUB``() =
    disasm64R2 "70000004" "msub r0, r0"
    disasm64R2 "70200004" "msub at, r0"
    disasm64R2 "70010004" "msub r0, at"
    disasm64R2 "70400004" "msub v0, r0"

  [<TestMethod>]
  member _.``MD00087 MSUB.fmt``() =
    disasm64R2 "4c000028" "msub.s f0, f0, f0, f0"
    disasm64R2 "4c200028" "msub.s f0, f1, f0, f0"
    disasm64R2 "4c010028" "msub.s f0, f0, f0, f1"
    disasm64R2 "4c000828" "msub.s f0, f0, f1, f0"

  [<TestMethod>]
  member _.``MD00087 MSUBU``() =
    disasm64R2 "70000005" "msubu r0, r0"
    disasm64R2 "70200005" "msubu at, r0"
    disasm64R2 "70010005" "msubu r0, at"
    disasm64R2 "70400005" "msubu v0, r0"

  [<TestMethod>]
  member _.``MD00087 MTC0``() =
    disasm64R2 "40800000" "mtc0 r0, 0x0, 0x0"
    disasm64R2 "40800001" "mtc0 r0, 0x0, 0x1"
    disasm64R2 "40800002" "mtc0 r0, 0x0, 0x2"
    disasm64R2 "40800003" "mtc0 r0, 0x0, 0x3"

  [<TestMethod>]
  member _.``MD00087 MTC1``() =
    disasm64R2 "44800000" "mtc1 r0, f0"
    disasm64R2 "44801800" "mtc1 r0, f3"
    disasm64R2 "44811800" "mtc1 at, f3"
    disasm64R2 "44821800" "mtc1 v0, f3"

  [<TestMethod>]
  member _.``MD00087 MTC2``() =
    disasm64R2 "48800000" "mtc2 r0, 0x0"

  [<TestMethod>]
  member _.``MD00087 MTHC0``() =
    disasm64R2 "40c00000" "mthc0 r0, 0x0, 0x0"
    disasm64R2 "40c00001" "mthc0 r0, 0x0, 0x1"
    disasm64R2 "40c00002" "mthc0 r0, 0x0, 0x2"
    disasm64R2 "40c00003" "mthc0 r0, 0x0, 0x3"

  [<TestMethod>]
  member _.``MD00087 MTHC1``() =
    disasm64R2 "44e00000" "mthc1 r0, f0"
    disasm64R2 "44e01800" "mthc1 r0, f3"
    disasm64R2 "44e11800" "mthc1 at, f3"
    disasm64R2 "44e21800" "mthc1 v0, f3"

  [<TestMethod>]
  member _.``MD00087 MTHC2``() =
    disasm64R2 "48e00000" "mthc2 r0, 0x0"
    disasm64R2 "48e21900" "mthc2 v0, 0x1900"
    disasm64R2 "48e21901" "mthc2 v0, 0x1901"
    disasm64R2 "48e21902" "mthc2 v0, 0x1902"

  [<TestMethod>]
  member _.``MD00087 MTHI``() =
    disasm64R2 "00000011" "mthi r0"
    disasm64R2 "00200011" "mthi at"
    disasm64R2 "00400011" "mthi v0"
    disasm64R2 "00600011" "mthi v1"

  [<TestMethod>]
  member _.``MD00087 MTLO``() =
    disasm64R2 "00000013" "mtlo r0"
    disasm64R2 "00200013" "mtlo at"
    disasm64R2 "00400013" "mtlo v0"
    disasm64R2 "00600013" "mtlo v1"

  [<TestMethod>]
  member _.``MD00087 MUL``() =
    disasm64R2 "70000002" "mul r0, r0, r0"
    disasm64R2 "70200002" "mul r0, at, r0"
    disasm64R2 "70010002" "mul r0, r0, at"
    disasm64R2 "70000802" "mul at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 MUL.fmt``() =
    disasm64R2 "46000002" "mul.s f0, f0, f0"
    disasm64R2 "46200002" "mul.d f0, f0, f0"
    disasm64R2 "46c00002" "mul.ps f0, f0, f0"
    disasm64R2 "46021902" "mul.s f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 MULT``() =
    disasm64R2 "00000018" "mult r0, r0"
    disasm64R2 "00200018" "mult at, r0"
    disasm64R2 "00010018" "mult r0, at"
    disasm64R2 "00400018" "mult v0, r0"

  [<TestMethod>]
  member _.``MD00087 MULTU``() =
    disasm64R2 "00000019" "multu r0, r0"
    disasm64R2 "00200019" "multu at, r0"
    disasm64R2 "00010019" "multu r0, at"
    disasm64R2 "00400019" "multu v0, r0"

  [<TestMethod>]
  member _.``MD00087 NAL``() =
    disasm64R2 "04100000" "nal 0x4"
    disasm64R2 "04100001" "nal 0x8"
    disasm64R2 "04100002" "nal 0xc"
    disasm64R2 "04100003" "nal 0x10"

  [<TestMethod>]
  member _.``MD00087 NEG.fmt``() =
    disasm64R2 "46000007" "neg.s f0, f0"
    disasm64R2 "46200007" "neg.d f0, f0"
    disasm64R2 "46c00007" "neg.ps f0, f0"
    disasm64R2 "46001807" "neg.s f0, f3"

  [<TestMethod>]
  member _.``MD00087 NMADD.fmt``() =
    disasm64R2 "4c000030" "nmadd.s f0, f0, f0, f0"
    disasm64R2 "4c200030" "nmadd.s f0, f1, f0, f0"
    disasm64R2 "4c010030" "nmadd.s f0, f0, f0, f1"
    disasm64R2 "4c000830" "nmadd.s f0, f0, f1, f0"

  [<TestMethod>]
  member _.``MD00087 NMSUB.fmt``() =
    disasm64R2 "4c000038" "nmsub.s f0, f0, f0, f0"
    disasm64R2 "4c200038" "nmsub.s f0, f1, f0, f0"
    disasm64R2 "4c010038" "nmsub.s f0, f0, f0, f1"
    disasm64R2 "4c000838" "nmsub.s f0, f0, f1, f0"

  [<TestMethod>]
  member _.``MD00087 NOP``() =
    disasm64R2 "00000000" "nop"

  [<TestMethod>]
  member _.``MD00087 NOR``() =
    disasm64R2 "00000027" "nor r0, r0, r0"
    disasm64R2 "00200027" "nor r0, at, r0"
    disasm64R2 "00010027" "nor r0, r0, at"
    disasm64R2 "00000827" "nor at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 OR``() =
    disasm64R2 "00000025" "or r0, r0, r0"
    disasm64R2 "00200025" "or r0, at, r0"
    disasm64R2 "00010025" "or r0, r0, at"
    disasm64R2 "00000825" "or at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 ORI``() =
    disasm64R2 "34200000" "ori r0, at, 0x0"
    disasm64R2 "34400000" "ori r0, v0, 0x0"
    disasm64R2 "34600000" "ori r0, v1, 0x0"
    disasm64R2 "34800000" "ori r0, a0, 0x0"

  [<TestMethod>]
  member _.``MD00087 PAUSE``() =
    disasm64R2 "00000140" "pause"

  [<TestMethod>]
  member _.``MD00087 PLL.PS``() =
    disasm64R2 "46c0002c" "pll.ps f0, f0, f0"
    disasm64R2 "46c2192c" "pll.ps f4, f3, f2"
    disasm64R2 "46deef2c" "pll.ps f28, f29, f30"
    disasm64R2 "46c0182c" "pll.ps f0, f3, f0"

  [<TestMethod>]
  member _.``MD00087 PLU.PS``() =
    disasm64R2 "46c0002d" "plu.ps f0, f0, f0"
    disasm64R2 "46c2192d" "plu.ps f4, f3, f2"
    disasm64R2 "46deef2d" "plu.ps f28, f29, f30"
    disasm64R2 "46c0182d" "plu.ps f0, f3, f0"

  [<TestMethod>]
  member _.``MD00087 PREF``() =
    disasm64R2 "cc000000" "pref 0x0, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 PREFE``() =
    disasm64R2 "7c000023" "prefe 0x0, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 PREFX``() =
    disasm64R2 "4c00000f" "prefx 0x0, r0(r0)"
    disasm64R2 "4c20000f" "prefx 0x0, r0(at)"
    disasm64R2 "4c40000f" "prefx 0x0, r0(v0)"
    disasm64R2 "4c60000f" "prefx 0x0, r0(v1)"

  [<TestMethod>]
  member _.``MD00087 PUL.PS``() =
    disasm64R2 "46c0002e" "pul.ps f0, f0, f0"
    disasm64R2 "46c2192e" "pul.ps f4, f3, f2"
    disasm64R2 "46deef2e" "pul.ps f28, f29, f30"
    disasm64R2 "46c0182e" "pul.ps f0, f3, f0"

  [<TestMethod>]
  member _.``MD00087 PUU.PS``() =
    disasm64R2 "46c0002f" "puu.ps f0, f0, f0"
    disasm64R2 "46c2192f" "puu.ps f4, f3, f2"
    disasm64R2 "46deef2f" "puu.ps f28, f29, f30"
    disasm64R2 "46c0182f" "puu.ps f0, f3, f0"

  [<TestMethod>]
  member _.``MD00087 RDPGPR``() =
    disasm64R2 "41400000" "rdpgpr r0, r0"

  [<TestMethod>]
  member _.``MD00087 RECIP.fmt``() =
    disasm64R2 "46000015" "recip.s f0, f0"
    disasm64R2 "46200015" "recip.d f0, f0"
    disasm64R2 "46001815" "recip.s f0, f3"
    disasm64R2 "46201815" "recip.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 ROTR``() =
    disasm64R2 "00200002" "rotr r0, r0, 0x0"
    disasm64R2 "00201902" "rotr v1, r0, 0x4"
    disasm64R2 "00220102" "rotr r0, v0, 0x4"
    disasm64R2 "00221802" "rotr v1, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 ROTRV``() =
    disasm64R2 "00000046" "rotrv r0, r0, r0"
    disasm64R2 "00221846" "rotrv v1, v0, at"
    disasm64R2 "03fee846" "rotrv sp, s8, ra"

  [<TestMethod>]
  member _.``MD00087 ROUND.L.fmt``() =
    disasm64R2 "46000008" "round.l.s f0, f0"
    disasm64R2 "46200008" "round.l.d f0, f0"
    disasm64R2 "46001808" "round.l.s f0, f3"
    disasm64R2 "46201808" "round.l.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 ROUND.W.fmt``() =
    disasm64R2 "4600000c" "round.w.s f0, f0"
    disasm64R2 "4620000c" "round.w.d f0, f0"
    disasm64R2 "4600180c" "round.w.s f0, f3"
    disasm64R2 "4620180c" "round.w.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 RSQRT.fmt``() =
    disasm64R2 "46000016" "rsqrt.s f0, f0"
    disasm64R2 "46200016" "rsqrt.d f0, f0"
    disasm64R2 "46001816" "rsqrt.s f0, f3"
    disasm64R2 "46201816" "rsqrt.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 SB``() =
    disasm64R2 "a0000000" "sb r0, 0(r0)"
    disasm64R2 "a0010000" "sb at, 0(r0)"
    disasm64R2 "a0020000" "sb v0, 0(r0)"
    disasm64R2 "a0030000" "sb v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SBE``() =
    disasm64R2 "7c00001c" "sbe r0, 0(r0)"
    disasm64R2 "7c01001c" "sbe at, 0(r0)"
    disasm64R2 "7c02001c" "sbe v0, 0(r0)"
    disasm64R2 "7c03001c" "sbe v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SC``() =
    disasm64R2 "e0000000" "sc r0, 0(r0)"
    disasm64R2 "e0010000" "sc at, 0(r0)"
    disasm64R2 "e0020000" "sc v0, 0(r0)"
    disasm64R2 "e0030000" "sc v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SCD``() =
    disasm64R2 "f0000000" "scd r0, 0(r0)"
    disasm64R2 "f0010000" "scd at, 0(r0)"
    disasm64R2 "f0020000" "scd v0, 0(r0)"
    disasm64R2 "f0030000" "scd v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SCE``() =
    disasm64R2 "7c00001e" "sce r0, 0(r0)"
    disasm64R2 "7c01001e" "sce at, 0(r0)"
    disasm64R2 "7c02001e" "sce v0, 0(r0)"
    disasm64R2 "7c03001e" "sce v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SD``() =
    disasm64R2 "fc000000" "sd r0, 0(r0)"
    disasm64R2 "fc010000" "sd at, 0(r0)"
    disasm64R2 "fc020000" "sd v0, 0(r0)"
    disasm64R2 "fc030000" "sd v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SDBBP``() =
    disasm64R2 "7000003f" "sdbbp 0x0"

  [<TestMethod>]
  member _.``MD00087 SDC1``() =
    disasm64R2 "f4000000" "sdc1 f0, 0(r0)"
    disasm64R2 "f4010000" "sdc1 f1, 0(r0)"
    disasm64R2 "f4020000" "sdc1 f2, 0(r0)"
    disasm64R2 "f4030000" "sdc1 f3, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SDC2``() =
    disasm64R2 "f8000000" "sdc2 0x0, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SDL``() =
    disasm64R2 "b0000000" "sdl r0, 0(r0)"
    disasm64R2 "b0010000" "sdl at, 0(r0)"
    disasm64R2 "b0020000" "sdl v0, 0(r0)"
    disasm64R2 "b0030000" "sdl v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SDR``() =
    disasm64R2 "b4000000" "sdr r0, 0(r0)"
    disasm64R2 "b4010000" "sdr at, 0(r0)"
    disasm64R2 "b4020000" "sdr v0, 0(r0)"
    disasm64R2 "b4030000" "sdr v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SDXC1``() =
    disasm64R2 "4c000009" "sdxc1 f0, r0(r0)"
    disasm64R2 "4c200009" "sdxc1 f0, r0(at)"
    disasm64R2 "4c010009" "sdxc1 f0, at(r0)"
    disasm64R2 "4c000809" "sdxc1 f1, r0(r0)"

  [<TestMethod>]
  member _.``MD00087 SEB``() =
    disasm64R2 "7c000420" "seb r0, r0"

  [<TestMethod>]
  member _.``MD00087 SEH``() =
    disasm64R2 "7c000620" "seh r0, r0"

  [<TestMethod>]
  member _.``MD00087 SH``() =
    disasm64R2 "a4000000" "sh r0, 0(r0)"
    disasm64R2 "a4010000" "sh at, 0(r0)"
    disasm64R2 "a4020000" "sh v0, 0(r0)"
    disasm64R2 "a4030000" "sh v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SHE``() =
    disasm64R2 "7c00001d" "she r0, 0(r0)"
    disasm64R2 "7c01001d" "she at, 0(r0)"
    disasm64R2 "7c02001d" "she v0, 0(r0)"
    disasm64R2 "7c03001d" "she v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SLL``() =
    disasm64R2 "00010000" "sll r0, at, 0x0"
    disasm64R2 "00000800" "sll at, r0, 0x0"
    disasm64R2 "00020000" "sll r0, v0, 0x0"
    disasm64R2 "00001000" "sll v0, r0, 0x0"

  [<TestMethod>]
  member _.``MD00087 SLLV``() =
    disasm64R2 "00000004" "sllv r0, r0, r0"
    disasm64R2 "00200004" "sllv r0, r0, at"
    disasm64R2 "00010004" "sllv r0, at, r0"
    disasm64R2 "00000804" "sllv at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 SLT``() =
    disasm64R2 "0000002a" "slt r0, r0, r0"
    disasm64R2 "0020002a" "slt r0, at, r0"
    disasm64R2 "0001002a" "slt r0, r0, at"
    disasm64R2 "0000082a" "slt at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 SLTI``() =
    disasm64R2 "28000000" "slti r0, r0, 0x0"
    disasm64R2 "28200000" "slti r0, at, 0x0"
    disasm64R2 "28010000" "slti at, r0, 0x0"
    disasm64R2 "28400000" "slti r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 SLTIU``() =
    disasm64R2 "2c000000" "sltiu r0, r0, 0x0"
    disasm64R2 "2c200000" "sltiu r0, at, 0x0"
    disasm64R2 "2c010000" "sltiu at, r0, 0x0"
    disasm64R2 "2c400000" "sltiu r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 SLTU``() =
    disasm64R2 "0000002b" "sltu r0, r0, r0"
    disasm64R2 "0020002b" "sltu r0, at, r0"
    disasm64R2 "0001002b" "sltu r0, r0, at"
    disasm64R2 "0000082b" "sltu at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 SQRT.fmt``() =
    disasm64R2 "46000004" "sqrt.s f0, f0"
    disasm64R2 "46200004" "sqrt.d f0, f0"
    disasm64R2 "46001804" "sqrt.s f0, f3"
    disasm64R2 "46201804" "sqrt.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 SRA``() =
    disasm64R2 "00000003" "sra r0, r0, 0x0"
    disasm64R2 "00010003" "sra r0, at, 0x0"
    disasm64R2 "00000803" "sra at, r0, 0x0"
    disasm64R2 "00020003" "sra r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 SRAV``() =
    disasm64R2 "00000007" "srav r0, r0, r0"
    disasm64R2 "00200007" "srav r0, r0, at"
    disasm64R2 "00010007" "srav r0, at, r0"
    disasm64R2 "00000807" "srav at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 SRL``() =
    disasm64R2 "00000002" "srl r0, r0, 0x0"
    disasm64R2 "00010002" "srl r0, at, 0x0"
    disasm64R2 "00000802" "srl at, r0, 0x0"
    disasm64R2 "00020002" "srl r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 SRLV``() =
    disasm64R2 "00000006" "srlv r0, r0, r0"
    disasm64R2 "00200006" "srlv r0, r0, at"
    disasm64R2 "00010006" "srlv r0, at, r0"
    disasm64R2 "00000806" "srlv at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 SSNOP``() =
    disasm64R2 "00000040" "ssnop"

  [<TestMethod>]
  member _.``MD00087 SUB``() =
    disasm64R2 "00200022" "sub r0, at, r0"
    disasm64R2 "00400022" "sub r0, v0, r0"
    disasm64R2 "00600022" "sub r0, v1, r0"
    disasm64R2 "00800022" "sub r0, a0, r0"

  [<TestMethod>]
  member _.``MD00087 SUB.fmt``() =
    disasm64R2 "46000001" "sub.s f0, f0, f0"
    disasm64R2 "46200001" "sub.d f0, f0, f0"
    disasm64R2 "46c00001" "sub.ps f0, f0, f0"
    disasm64R2 "46021901" "sub.s f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 SUBU``() =
    disasm64R2 "00200023" "subu r0, at, r0"
    disasm64R2 "00400023" "subu r0, v0, r0"
    disasm64R2 "00600023" "subu r0, v1, r0"
    disasm64R2 "00800023" "subu r0, a0, r0"

  [<TestMethod>]
  member _.``MD00087 SUXC1``() =
    disasm64R2 "4c00000d" "suxc1 f0, r0(r0)"
    disasm64R2 "4c20000d" "suxc1 f0, r0(at)"
    disasm64R2 "4c01000d" "suxc1 f0, at(r0)"
    disasm64R2 "4c00080d" "suxc1 f1, r0(r0)"

  [<TestMethod>]
  member _.``MD00087 SW``() =
    disasm64R2 "ac000000" "sw r0, 0(r0)"
    disasm64R2 "ac010000" "sw at, 0(r0)"
    disasm64R2 "ac020000" "sw v0, 0(r0)"
    disasm64R2 "ac030000" "sw v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SWC1``() =
    disasm64R2 "e4000000" "swc1 f0, 0(r0)"
    disasm64R2 "e4010000" "swc1 f1, 0(r0)"
    disasm64R2 "e4020000" "swc1 f2, 0(r0)"
    disasm64R2 "e4030000" "swc1 f3, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SWC2``() =
    disasm64R2 "e8000000" "swc2 0x0, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SWE``() =
    disasm64R2 "7c00001f" "swe r0, 0(r0)"
    disasm64R2 "7c01001f" "swe at, 0(r0)"
    disasm64R2 "7c02001f" "swe v0, 0(r0)"
    disasm64R2 "7c03001f" "swe v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SWL``() =
    disasm64R2 "a8000000" "swl r0, 0(r0)"
    disasm64R2 "a8010000" "swl at, 0(r0)"
    disasm64R2 "a8020000" "swl v0, 0(r0)"
    disasm64R2 "a8030000" "swl v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SWLE``() =
    disasm64R2 "7c000021" "swle r0, 0(r0)"
    disasm64R2 "7c010021" "swle at, 0(r0)"
    disasm64R2 "7c020021" "swle v0, 0(r0)"
    disasm64R2 "7c030021" "swle v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SWR``() =
    disasm64R2 "b8000000" "swr r0, 0(r0)"
    disasm64R2 "b8010000" "swr at, 0(r0)"
    disasm64R2 "b8020000" "swr v0, 0(r0)"
    disasm64R2 "b8030000" "swr v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SWRE``() =
    disasm64R2 "7c000022" "swre r0, 0(r0)"
    disasm64R2 "7c010022" "swre at, 0(r0)"
    disasm64R2 "7c020022" "swre v0, 0(r0)"
    disasm64R2 "7c030022" "swre v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SWXC1``() =
    disasm64R2 "4c000008" "swxc1 f0, r0(r0)"
    disasm64R2 "4c200008" "swxc1 f0, r0(at)"
    disasm64R2 "4c010008" "swxc1 f0, at(r0)"
    disasm64R2 "4c000808" "swxc1 f1, r0(r0)"

  [<TestMethod>]
  member _.``MD00087 SYNC``() =
    disasm64R2 "0000000f" "sync 0x0"

  [<TestMethod>]
  member _.``MD00087 SYNCI``() =
    disasm64R2 "041f0000" "synci 0(r0)"
    disasm64R2 "041f0001" "synci 1(r0)"
    disasm64R2 "041f0002" "synci 2(r0)"
    disasm64R2 "041f0003" "synci 3(r0)"

  [<TestMethod>]
  member _.``MD00087 SYSCALL``() =
    disasm64R2 "0000000c" "syscall"

  [<TestMethod>]
  member _.``MD00087 TEQ``() =
    disasm64R2 "00000034" "teq r0, r0"
    disasm64R2 "00200034" "teq at, r0"
    disasm64R2 "00010034" "teq r0, at"
    disasm64R2 "00400034" "teq v0, r0"

  [<TestMethod>]
  member _.``MD00087 TEQI``() =
    disasm64R2 "040c0000" "teqi r0, 0x0"
    disasm64R2 "040c0001" "teqi r0, 0x1"
    disasm64R2 "040c0002" "teqi r0, 0x2"
    disasm64R2 "040c0003" "teqi r0, 0x3"

  [<TestMethod>]
  member _.``MD00087 TGE``() =
    disasm64R2 "00000030" "tge r0, r0"
    disasm64R2 "00200030" "tge at, r0"
    disasm64R2 "00010030" "tge r0, at"
    disasm64R2 "00400030" "tge v0, r0"

  [<TestMethod>]
  member _.``MD00087 TGEI``() =
    disasm64R2 "04080000" "tgei r0, 0x0"
    disasm64R2 "04080001" "tgei r0, 0x1"
    disasm64R2 "04080002" "tgei r0, 0x2"
    disasm64R2 "04080003" "tgei r0, 0x3"

  [<TestMethod>]
  member _.``MD00087 TGEIU``() =
    disasm64R2 "04090000" "tgeiu r0, 0x0"
    disasm64R2 "04090001" "tgeiu r0, 0x1"
    disasm64R2 "04090002" "tgeiu r0, 0x2"
    disasm64R2 "04090003" "tgeiu r0, 0x3"

  [<TestMethod>]
  member _.``MD00087 TGEU``() =
    disasm64R2 "00000031" "tgeu r0, r0"
    disasm64R2 "00200031" "tgeu at, r0"
    disasm64R2 "00010031" "tgeu r0, at"
    disasm64R2 "00400031" "tgeu v0, r0"

  [<TestMethod>]
  member _.``MD00087 TLBINV``() =
    disasm64R2 "42000003" "tlbinv"

  [<TestMethod>]
  member _.``MD00087 TLBINVF``() =
    disasm64R2 "42000004" "tlbinvf"

  [<TestMethod>]
  member _.``MD00087 TLBP``() =
    disasm64R2 "42000008" "tlbp"

  [<TestMethod>]
  member _.``MD00087 TLBR``() =
    disasm64R2 "42000001" "tlbr"

  [<TestMethod>]
  member _.``MD00087 TLBWI``() =
    disasm64R2 "42000002" "tlbwi"

  [<TestMethod>]
  member _.``MD00087 TLBWR``() =
    disasm64R2 "42000006" "tlbwr"

  [<TestMethod>]
  member _.``MD00087 TLT``() =
    disasm64R2 "00000032" "tlt r0, r0"
    disasm64R2 "00200032" "tlt at, r0"
    disasm64R2 "00010032" "tlt r0, at"
    disasm64R2 "00400032" "tlt v0, r0"

  [<TestMethod>]
  member _.``MD00087 TLTI``() =
    disasm64R2 "040a0000" "tlti r0, 0x0"
    disasm64R2 "040a0001" "tlti r0, 0x1"
    disasm64R2 "040a0002" "tlti r0, 0x2"
    disasm64R2 "040a0003" "tlti r0, 0x3"

  [<TestMethod>]
  member _.``MD00087 TLTIU``() =
    disasm64R2 "040b0000" "tltiu r0, 0x0"
    disasm64R2 "040b0001" "tltiu r0, 0x1"
    disasm64R2 "040b0002" "tltiu r0, 0x2"
    disasm64R2 "040b0003" "tltiu r0, 0x3"

  [<TestMethod>]
  member _.``MD00087 TLTU``() =
    disasm64R2 "00000033" "tltu r0, r0"
    disasm64R2 "00200033" "tltu at, r0"
    disasm64R2 "00010033" "tltu r0, at"
    disasm64R2 "00400033" "tltu v0, r0"

  [<TestMethod>]
  member _.``MD00087 TNE``() =
    disasm64R2 "00000036" "tne r0, r0"
    disasm64R2 "00200036" "tne at, r0"
    disasm64R2 "00010036" "tne r0, at"
    disasm64R2 "00400036" "tne v0, r0"

  [<TestMethod>]
  member _.``MD00087 TNEI``() =
    disasm64R2 "040e0000" "tnei r0, 0x0"
    disasm64R2 "040e0001" "tnei r0, 0x1"
    disasm64R2 "040e0002" "tnei r0, 0x2"
    disasm64R2 "040e0003" "tnei r0, 0x3"

  [<TestMethod>]
  member _.``MD00087 TRUNC.L.fmt``() =
    disasm64R2 "46000009" "trunc.l.s f0, f0"
    disasm64R2 "46200009" "trunc.l.d f0, f0"
    disasm64R2 "46001809" "trunc.l.s f0, f3"
    disasm64R2 "46201809" "trunc.l.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 TRUNC.W.fmt``() =
    disasm64R2 "4600000d" "trunc.w.s f0, f0"
    disasm64R2 "4620000d" "trunc.w.d f0, f0"
    disasm64R2 "4600180d" "trunc.w.s f0, f3"
    disasm64R2 "4620180d" "trunc.w.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 WAIT``() =
    disasm64R2 "42000020" "wait"

  [<TestMethod>]
  member _.``MD00087 WRPGPR``() =
    disasm64R2 "41c00000" "wrpgpr r0, r0"

  [<TestMethod>]
  member _.``MD00087 WSBH``() =
    disasm64R2 "7c0000a0" "wsbh r0, r0"

  [<TestMethod>]
  member _.``MD00087 XOR``() =
    disasm64R2 "00000026" "xor r0, r0, r0"
    disasm64R2 "00200026" "xor r0, at, r0"
    disasm64R2 "00010026" "xor r0, r0, at"
    disasm64R2 "00000826" "xor at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 XORI``() =
    disasm64R2 "38000000" "xori r0, r0, 0x0"
    disasm64R2 "38200000" "xori r0, at, 0x0"
    disasm64R2 "38010000" "xori at, r0, 0x0"
    disasm64R2 "38400000" "xori r0, v0, 0x0"

  (* One test for each MIPS64 instruction MD00087 describes, in the order of its
     sections. Each reads words of the instruction and checks the text, and each
     word is one binutils' objdump reads as the same instruction with the same
     operands, so what is asserted is a reading two decoders agree on. Read as
     Release 6. *)
  [<TestMethod>]
  member _.``MD00087 ABS.fmt (Release 6)``() =
    disasm64R6 "46000005" "abs.s f0, f0"
    disasm64R6 "46200005" "abs.d f0, f0"
    disasm64R6 "46001805" "abs.s f0, f3"
    disasm64R6 "46201805" "abs.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 ADD (Release 6)``() =
    disasm64R6 "00000020" "add r0, r0, r0"
    disasm64R6 "00200020" "add r0, at, r0"
    disasm64R6 "00010020" "add r0, r0, at"
    disasm64R6 "00000820" "add at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 ADD.fmt (Release 6)``() =
    disasm64R6 "46000000" "add.s f0, f0, f0"
    disasm64R6 "46200000" "add.d f0, f0, f0"
    disasm64R6 "46021900" "add.s f4, f3, f2"
    disasm64R6 "46221900" "add.d f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 ADDIU (Release 6)``() =
    disasm64R6 "24000000" "addiu r0, r0, 0x0"
    disasm64R6 "24200000" "addiu r0, at, 0x0"
    disasm64R6 "24010000" "addiu at, r0, 0x0"
    disasm64R6 "24400000" "addiu r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 ADDIUPC (Release 6)``() =
    disasm64R6 "ec000000" "addiupc r0, 0x0"
    disasm64R6 "ec200000" "addiupc at, 0x0"
    disasm64R6 "ec400000" "addiupc v0, 0x0"
    disasm64R6 "ec600000" "addiupc v1, 0x0"

  [<TestMethod>]
  member _.``MD00087 ADDU (Release 6)``() =
    disasm64R6 "00000021" "addu r0, r0, r0"
    disasm64R6 "00200021" "addu r0, at, r0"
    disasm64R6 "00010021" "addu r0, r0, at"
    disasm64R6 "00000821" "addu at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 ALIGN (Release 6)``() =
    disasm64R6 "7c000220" "align r0, r0, r0, 0x0"
    disasm64R6 "7c000260" "align r0, r0, r0, 0x1"
    disasm64R6 "7c0002a0" "align r0, r0, r0, 0x2"
    disasm64R6 "7c0002e0" "align r0, r0, r0, 0x3"

  [<TestMethod>]
  member _.``MD00087 ALUIPC (Release 6)``() =
    disasm64R6 "ec1f0000" "aluipc r0, 0x0"
    disasm64R6 "ec1f0001" "aluipc r0, 0x1"
    disasm64R6 "ec1f0002" "aluipc r0, 0x2"
    disasm64R6 "ec1f0003" "aluipc r0, 0x3"

  [<TestMethod>]
  member _.``MD00087 AND (Release 6)``() =
    disasm64R6 "00000024" "and r0, r0, r0"
    disasm64R6 "00200024" "and r0, at, r0"
    disasm64R6 "00010024" "and r0, r0, at"
    disasm64R6 "00000824" "and at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 ANDI (Release 6)``() =
    disasm64R6 "30000000" "andi r0, r0, 0x0"
    disasm64R6 "30200000" "andi r0, at, 0x0"
    disasm64R6 "30010000" "andi at, r0, 0x0"
    disasm64R6 "30400000" "andi r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 AUI (Release 6)``() =
    disasm64R6 "3c200000" "aui r0, at, 0x0"
    disasm64R6 "3c400000" "aui r0, v0, 0x0"
    disasm64R6 "3c600000" "aui r0, v1, 0x0"
    disasm64R6 "3c800000" "aui r0, a0, 0x0"

  [<TestMethod>]
  member _.``MD00087 AUIPC (Release 6)``() =
    disasm64R6 "ec1e0000" "auipc r0, 0x0"
    disasm64R6 "ec1e0001" "auipc r0, 0x1"
    disasm64R6 "ec1e0002" "auipc r0, 0x2"
    disasm64R6 "ec1e0003" "auipc r0, 0x3"

  [<TestMethod>]
  member _.``MD00087 B (Release 6)``() =
    disasm64R6 "10000000" "b 0x4"

  [<TestMethod>]
  member _.``MD00087 BAL (Release 6)``() =
    disasm64R6 "04110000" "bal 0x4"
    disasm64R6 "04110001" "bal 0x8"
    disasm64R6 "04110002" "bal 0xc"
    disasm64R6 "04110003" "bal 0x10"

  [<TestMethod>]
  member _.``MD00087 BALC (Release 6)``() =
    disasm64R6 "e8000000" "balc 0x4"

  [<TestMethod>]
  member _.``MD00087 BC (Release 6)``() =
    disasm64R6 "c8000000" "bc 0x4"

  [<TestMethod>]
  member _.``MD00087 BC1EQZ (Release 6)``() =
    disasm64R6 "45200000" "bc1eqz f0, 0x4"
    disasm64R6 "45200001" "bc1eqz f0, 0x8"
    disasm64R6 "45200002" "bc1eqz f0, 0xc"
    disasm64R6 "45200003" "bc1eqz f0, 0x10"

  [<TestMethod>]
  member _.``MD00087 BC1NEZ (Release 6)``() =
    disasm64R6 "45a00000" "bc1nez f0, 0x4"
    disasm64R6 "45a00001" "bc1nez f0, 0x8"
    disasm64R6 "45a00002" "bc1nez f0, 0xc"
    disasm64R6 "45a00003" "bc1nez f0, 0x10"

  [<TestMethod>]
  member _.``MD00087 BC2EQZ (Release 6)``() =
    disasm64R6 "49200000" "bc2eqz 0x0, 0x4"
    disasm64R6 "49200001" "bc2eqz 0x0, 0x8"
    disasm64R6 "49200002" "bc2eqz 0x0, 0xc"
    disasm64R6 "49200003" "bc2eqz 0x0, 0x10"

  [<TestMethod>]
  member _.``MD00087 BC2NEZ (Release 6)``() =
    disasm64R6 "49a00000" "bc2nez 0x0, 0x4"
    disasm64R6 "49a00001" "bc2nez 0x0, 0x8"
    disasm64R6 "49a00002" "bc2nez 0x0, 0xc"
    disasm64R6 "49a00003" "bc2nez 0x0, 0x10"

  [<TestMethod>]
  member _.``MD00087 BEQ (Release 6)``() =
    disasm64R6 "10200000" "beq at, r0, 0x4"
    disasm64R6 "10010000" "beq r0, at, 0x4"
    disasm64R6 "10400000" "beq v0, r0, 0x4"
    disasm64R6 "10020000" "beq r0, v0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BEQC (Release 6)``() =
    disasm64R6 "20220100" "beqc at, v0, 0x404"
    disasm64R6 "20221800" "beqc at, v0, 0x6004"
    disasm64R6 "20221900" "beqc at, v0, 0x6404"
    disasm64R6 "20220900" "beqc at, v0, 0x2404"

  [<TestMethod>]
  member _.``MD00087 BEQZALC (Release 6)``() =
    disasm64R6 "20010000" "beqzalc at, 0x4"
    disasm64R6 "20020000" "beqzalc v0, 0x4"
    disasm64R6 "20030000" "beqzalc v1, 0x4"
    disasm64R6 "20040000" "beqzalc a0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BEQZC (Release 6)``() =
    disasm64R6 "d8200000" "beqzc at, 0x4"
    disasm64R6 "d8400000" "beqzc v0, 0x4"
    disasm64R6 "d8600000" "beqzc v1, 0x4"
    disasm64R6 "d8800000" "beqzc a0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BGEC (Release 6)``() =
    disasm64R6 "58220100" "bgec at, v0, 0x404"
    disasm64R6 "58221800" "bgec at, v0, 0x6004"
    disasm64R6 "58221900" "bgec at, v0, 0x6404"
    disasm64R6 "58220900" "bgec at, v0, 0x2404"

  [<TestMethod>]
  member _.``MD00087 BGEUC (Release 6)``() =
    disasm64R6 "18220100" "bgeuc at, v0, 0x404"
    disasm64R6 "18221800" "bgeuc at, v0, 0x6004"
    disasm64R6 "18221900" "bgeuc at, v0, 0x6404"
    disasm64R6 "18220900" "bgeuc at, v0, 0x2404"

  [<TestMethod>]
  member _.``MD00087 BGEZ (Release 6)``() =
    disasm64R6 "04010000" "bgez r0, 0x4"
    disasm64R6 "04010001" "bgez r0, 0x8"
    disasm64R6 "04010002" "bgez r0, 0xc"
    disasm64R6 "04010003" "bgez r0, 0x10"

  [<TestMethod>]
  member _.``MD00087 BGEZALC (Release 6)``() =
    disasm64R6 "18211900" "bgezalc at, 0x6404"
    disasm64R6 "18421900" "bgezalc v0, 0x6404"
    disasm64R6 "18211901" "bgezalc at, 0x6408"
    disasm64R6 "18421901" "bgezalc v0, 0x6408"

  [<TestMethod>]
  member _.``MD00087 BGEZC (Release 6)``() =
    disasm64R6 "58211900" "bgezc at, 0x6404"
    disasm64R6 "58421900" "bgezc v0, 0x6404"
    disasm64R6 "58211901" "bgezc at, 0x6408"
    disasm64R6 "58421901" "bgezc v0, 0x6408"

  [<TestMethod>]
  member _.``MD00087 BGTZ (Release 6)``() =
    disasm64R6 "1c000000" "bgtz r0, 0x4"
    disasm64R6 "1c200000" "bgtz at, 0x4"
    disasm64R6 "1c400000" "bgtz v0, 0x4"
    disasm64R6 "1c600000" "bgtz v1, 0x4"

  [<TestMethod>]
  member _.``MD00087 BGTZALC (Release 6)``() =
    disasm64R6 "1c010000" "bgtzalc at, 0x4"
    disasm64R6 "1c020000" "bgtzalc v0, 0x4"
    disasm64R6 "1c030000" "bgtzalc v1, 0x4"
    disasm64R6 "1c040000" "bgtzalc a0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BGTZC (Release 6)``() =
    disasm64R6 "5c010000" "bgtzc at, 0x4"
    disasm64R6 "5c020000" "bgtzc v0, 0x4"
    disasm64R6 "5c030000" "bgtzc v1, 0x4"
    disasm64R6 "5c040000" "bgtzc a0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BITSWAP (Release 6)``() =
    disasm64R6 "7c000020" "bitswap r0, r0"
    disasm64R6 "7c010020" "bitswap r0, at"
    disasm64R6 "7c000820" "bitswap at, r0"
    disasm64R6 "7c020020" "bitswap r0, v0"

  [<TestMethod>]
  member _.``MD00087 BLEZ (Release 6)``() =
    disasm64R6 "18000000" "blez r0, 0x4"
    disasm64R6 "18200000" "blez at, 0x4"
    disasm64R6 "18400000" "blez v0, 0x4"
    disasm64R6 "18600000" "blez v1, 0x4"

  [<TestMethod>]
  member _.``MD00087 BLEZALC (Release 6)``() =
    disasm64R6 "18010000" "blezalc at, 0x4"
    disasm64R6 "18020000" "blezalc v0, 0x4"
    disasm64R6 "18030000" "blezalc v1, 0x4"
    disasm64R6 "18040000" "blezalc a0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BLEZC (Release 6)``() =
    disasm64R6 "58010000" "blezc at, 0x4"
    disasm64R6 "58020000" "blezc v0, 0x4"
    disasm64R6 "58030000" "blezc v1, 0x4"
    disasm64R6 "58040000" "blezc a0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BLTC (Release 6)``() =
    disasm64R6 "5c220100" "bltc at, v0, 0x404"
    disasm64R6 "5c221800" "bltc at, v0, 0x6004"
    disasm64R6 "5c221900" "bltc at, v0, 0x6404"
    disasm64R6 "5c220900" "bltc at, v0, 0x2404"

  [<TestMethod>]
  member _.``MD00087 BLTUC (Release 6)``() =
    disasm64R6 "1c220100" "bltuc at, v0, 0x404"
    disasm64R6 "1c221800" "bltuc at, v0, 0x6004"
    disasm64R6 "1c221900" "bltuc at, v0, 0x6404"
    disasm64R6 "1c220900" "bltuc at, v0, 0x2404"

  [<TestMethod>]
  member _.``MD00087 BLTZ (Release 6)``() =
    disasm64R6 "04000000" "bltz r0, 0x4"
    disasm64R6 "04200000" "bltz at, 0x4"
    disasm64R6 "04400000" "bltz v0, 0x4"
    disasm64R6 "04600000" "bltz v1, 0x4"

  [<TestMethod>]
  member _.``MD00087 BLTZALC (Release 6)``() =
    disasm64R6 "1c211900" "bltzalc at, 0x6404"
    disasm64R6 "1c421900" "bltzalc v0, 0x6404"
    disasm64R6 "1c211901" "bltzalc at, 0x6408"
    disasm64R6 "1c421901" "bltzalc v0, 0x6408"

  [<TestMethod>]
  member _.``MD00087 BLTZC (Release 6)``() =
    disasm64R6 "5c211900" "bltzc at, 0x6404"
    disasm64R6 "5c421900" "bltzc v0, 0x6404"
    disasm64R6 "5c211901" "bltzc at, 0x6408"
    disasm64R6 "5c421901" "bltzc v0, 0x6408"

  [<TestMethod>]
  member _.``MD00087 BNE (Release 6)``() =
    disasm64R6 "14000000" "bne r0, r0, 0x4"
    disasm64R6 "14200000" "bne at, r0, 0x4"
    disasm64R6 "14010000" "bne r0, at, 0x4"
    disasm64R6 "14400000" "bne v0, r0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BNEC (Release 6)``() =
    disasm64R6 "60220100" "bnec at, v0, 0x404"
    disasm64R6 "60221800" "bnec at, v0, 0x6004"
    disasm64R6 "60221900" "bnec at, v0, 0x6404"
    disasm64R6 "60220900" "bnec at, v0, 0x2404"

  [<TestMethod>]
  member _.``MD00087 BNEZALC (Release 6)``() =
    disasm64R6 "60010000" "bnezalc at, 0x4"
    disasm64R6 "60020000" "bnezalc v0, 0x4"
    disasm64R6 "60030000" "bnezalc v1, 0x4"
    disasm64R6 "60040000" "bnezalc a0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BNEZC (Release 6)``() =
    disasm64R6 "f8200000" "bnezc at, 0x4"
    disasm64R6 "f8400000" "bnezc v0, 0x4"
    disasm64R6 "f8600000" "bnezc v1, 0x4"
    disasm64R6 "f8800000" "bnezc a0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BNVC (Release 6)``() =
    disasm64R6 "60000000" "bnvc r0, r0, 0x4"
    disasm64R6 "60200000" "bnvc at, r0, 0x4"
    disasm64R6 "60400000" "bnvc v0, r0, 0x4"
    disasm64R6 "60600000" "bnvc v1, r0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BOVC (Release 6)``() =
    disasm64R6 "20000000" "bovc r0, r0, 0x4"
    disasm64R6 "20200000" "bovc at, r0, 0x4"
    disasm64R6 "20400000" "bovc v0, r0, 0x4"
    disasm64R6 "20600000" "bovc v1, r0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BREAK (Release 6)``() =
    disasm64R6 "0000000d" "break"

  [<TestMethod>]
  member _.``MD00087 CACHE (Release 6)``() =
    disasm64R6 "7c000025" "cache 0x0, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 CACHEE (Release 6)``() =
    disasm64R6 "7c00001b" "cachee 0x0, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 CEIL.L.fmt (Release 6)``() =
    disasm64R6 "4600000a" "ceil.l.s f0, f0"
    disasm64R6 "4620000a" "ceil.l.d f0, f0"
    disasm64R6 "4600180a" "ceil.l.s f0, f3"
    disasm64R6 "4620180a" "ceil.l.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 CEIL.W.fmt (Release 6)``() =
    disasm64R6 "4600000e" "ceil.w.s f0, f0"
    disasm64R6 "4620000e" "ceil.w.d f0, f0"
    disasm64R6 "4600180e" "ceil.w.s f0, f3"
    disasm64R6 "4620180e" "ceil.w.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 CFC1 (Release 6)``() =
    disasm64R6 "44400000" "cfc1 r0, f0"
    disasm64R6 "44401800" "cfc1 r0, f3"
    disasm64R6 "44411800" "cfc1 at, f3"
    disasm64R6 "44421800" "cfc1 v0, f3"

  [<TestMethod>]
  member _.``MD00087 CFC2 (Release 6)``() =
    disasm64R6 "48400000" "cfc2 r0, 0x0"

  [<TestMethod>]
  member _.``MD00087 CLASS.fmt (Release 6)``() =
    disasm64R6 "4600001b" "class.s f0, f0"
    disasm64R6 "4620001b" "class.d f0, f0"
    disasm64R6 "4600181b" "class.s f0, f3"
    disasm64R6 "4620181b" "class.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 CLO (Release 6)``() =
    disasm64R6 "00000051" "clo r0, r0"

  [<TestMethod>]
  member _.``MD00087 CLZ (Release 6)``() =
    disasm64R6 "00000050" "clz r0, r0"

  [<TestMethod>]
  member _.``MD00087 CMP.condn.fmt (Release 6)``() =
    disasm64R6 "46800000" "cmp.af.s f0, f0, f0"
    disasm64R6 "46a00000" "cmp.af.d f0, f0, f0"
    disasm64R6 "46800001" "cmp.un.s f0, f0, f0"
    disasm64R6 "46a00001" "cmp.un.d f0, f0, f0"

  [<TestMethod>]
  member _.``MD00087 COP2 (Release 6)``() =
    disasm64R6 "4a000000" "cop2 0x0"
    disasm64R6 "4a200000" "cop2 0x200000"
    disasm64R6 "4a400000" "cop2 0x400000"
    disasm64R6 "4a600000" "cop2 0x600000"

  [<TestMethod>]
  member _.``MD00087 CRC32B (Release 6)``() =
    disasm64R6 "7c00000f" "crc32b r0, r0, r0"
    disasm64R6 "7c20000f" "crc32b r0, at, r0"
    disasm64R6 "7c01000f" "crc32b at, r0, at"
    disasm64R6 "7c40000f" "crc32b r0, v0, r0"

  [<TestMethod>]
  member _.``MD00087 CRC32CB (Release 6)``() =
    disasm64R6 "7c00010f" "crc32cb r0, r0, r0"
    disasm64R6 "7c22010f" "crc32cb v0, at, v0"

  [<TestMethod>]
  member _.``MD00087 CRC32CD (Release 6)``() =
    disasm64R6 "7c0001cf" "crc32cd r0, r0, r0"

  [<TestMethod>]
  member _.``MD00087 CRC32CH (Release 6)``() =
    disasm64R6 "7c00014f" "crc32ch r0, r0, r0"

  [<TestMethod>]
  member _.``MD00087 CRC32CW (Release 6)``() =
    disasm64R6 "7c00018f" "crc32cw r0, r0, r0"

  [<TestMethod>]
  member _.``MD00087 CRC32D (Release 6)``() =
    disasm64R6 "7c0000cf" "crc32d r0, r0, r0"

  [<TestMethod>]
  member _.``MD00087 CRC32H (Release 6)``() =
    disasm64R6 "7c00004f" "crc32h r0, r0, r0"

  [<TestMethod>]
  member _.``MD00087 CRC32W (Release 6)``() =
    disasm64R6 "7c00008f" "crc32w r0, r0, r0"

  [<TestMethod>]
  member _.``MD00087 CTC1 (Release 6)``() =
    disasm64R6 "44c00000" "ctc1 r0, f0"
    disasm64R6 "44c01800" "ctc1 r0, f3"
    disasm64R6 "44c11800" "ctc1 at, f3"
    disasm64R6 "44c21800" "ctc1 v0, f3"

  [<TestMethod>]
  member _.``MD00087 CTC2 (Release 6)``() =
    disasm64R6 "48c00000" "ctc2 r0, 0x0"

  [<TestMethod>]
  member _.``MD00087 CVT.D.fmt (Release 6)``() =
    disasm64R6 "46000021" "cvt.d.s f0, f0"
    disasm64R6 "46800021" "cvt.d.w f0, f0"
    disasm64R6 "46a00021" "cvt.d.l f0, f0"
    disasm64R6 "46001821" "cvt.d.s f0, f3"

  [<TestMethod>]
  member _.``MD00087 CVT.L.fmt (Release 6)``() =
    disasm64R6 "46000025" "cvt.l.s f0, f0"
    disasm64R6 "46200025" "cvt.l.d f0, f0"
    disasm64R6 "46001825" "cvt.l.s f0, f3"
    disasm64R6 "46201825" "cvt.l.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 CVT.S.fmt (Release 6)``() =
    disasm64R6 "46200020" "cvt.s.d f0, f0"
    disasm64R6 "46800020" "cvt.s.w f0, f0"
    disasm64R6 "46a00020" "cvt.s.l f0, f0"
    disasm64R6 "46201820" "cvt.s.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 CVT.W.fmt (Release 6)``() =
    disasm64R6 "46000024" "cvt.w.s f0, f0"
    disasm64R6 "46200024" "cvt.w.d f0, f0"
    disasm64R6 "46001824" "cvt.w.s f0, f3"
    disasm64R6 "46201824" "cvt.w.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 DADD (Release 6)``() =
    disasm64R6 "0000002c" "dadd r0, r0, r0"
    disasm64R6 "0020002c" "dadd r0, at, r0"
    disasm64R6 "0001002c" "dadd r0, r0, at"
    disasm64R6 "0000082c" "dadd at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 DADDIU (Release 6)``() =
    disasm64R6 "64000000" "daddiu r0, r0, 0x0"
    disasm64R6 "64200000" "daddiu r0, at, 0x0"
    disasm64R6 "64010000" "daddiu at, r0, 0x0"
    disasm64R6 "64400000" "daddiu r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DADDU (Release 6)``() =
    disasm64R6 "0001002d" "daddu r0, r0, at"
    disasm64R6 "0002002d" "daddu r0, r0, v0"
    disasm64R6 "0003002d" "daddu r0, r0, v1"
    disasm64R6 "0004002d" "daddu r0, r0, a0"

  [<TestMethod>]
  member _.``MD00087 DAHI (Release 6)``() =
    disasm64R6 "04060000" "dahi r0, 0x0"
    disasm64R6 "04060001" "dahi r0, 0x1"
    disasm64R6 "04060002" "dahi r0, 0x2"
    disasm64R6 "04060003" "dahi r0, 0x3"

  [<TestMethod>]
  member _.``MD00087 DALIGN (Release 6)``() =
    disasm64R6 "7c000224" "dalign r0, r0, r0, 0x0"
    disasm64R6 "7c000264" "dalign r0, r0, r0, 0x1"
    disasm64R6 "7c0002a4" "dalign r0, r0, r0, 0x2"
    disasm64R6 "7c0002e4" "dalign r0, r0, r0, 0x3"

  [<TestMethod>]
  member _.``MD00087 DATI (Release 6)``() =
    disasm64R6 "041e0000" "dati r0, 0x0"
    disasm64R6 "041e0001" "dati r0, 0x1"
    disasm64R6 "041e0002" "dati r0, 0x2"
    disasm64R6 "041e0003" "dati r0, 0x3"

  [<TestMethod>]
  member _.``MD00087 DAUI (Release 6)``() =
    disasm64R6 "74200000" "daui r0, at, 0x0"
    disasm64R6 "74400000" "daui r0, v0, 0x0"
    disasm64R6 "74600000" "daui r0, v1, 0x0"
    disasm64R6 "74800000" "daui r0, a0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DBITSWAP (Release 6)``() =
    disasm64R6 "7c000024" "dbitswap r0, r0"
    disasm64R6 "7c010024" "dbitswap r0, at"
    disasm64R6 "7c000824" "dbitswap at, r0"
    disasm64R6 "7c020024" "dbitswap r0, v0"

  [<TestMethod>]
  member _.``MD00087 DCLO (Release 6)``() =
    disasm64R6 "00000053" "dclo r0, r0"

  [<TestMethod>]
  member _.``MD00087 DCLZ (Release 6)``() =
    disasm64R6 "00000052" "dclz r0, r0"

  [<TestMethod>]
  member _.``MD00087 DDIV (Release 6)``() =
    disasm64R6 "0000009e" "ddiv r0, r0, r0"
    disasm64R6 "0022189e" "ddiv v1, at, v0"
    disasm64R6 "03fee89e" "ddiv sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 DDIVU (Release 6)``() =
    disasm64R6 "0000009f" "ddivu r0, r0, r0"
    disasm64R6 "0022189f" "ddivu v1, at, v0"
    disasm64R6 "03fee89f" "ddivu sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 DERET (Release 6)``() =
    disasm64R6 "4200001f" "deret"

  [<TestMethod>]
  member _.``MD00087 DEXT (Release 6)``() =
    disasm64R6 "7c000003" "dext r0, r0, 0x0, 0x1"
    disasm64R6 "7c200003" "dext r0, at, 0x0, 0x1"
    disasm64R6 "7c010003" "dext at, r0, 0x0, 0x1"
    disasm64R6 "7c400003" "dext r0, v0, 0x0, 0x1"

  [<TestMethod>]
  member _.``MD00087 DEXTM (Release 6)``() =
    disasm64R6 "7c000001" "dextm r0, r0, 0x0, 0x21"
    disasm64R6 "7c200001" "dextm r0, at, 0x0, 0x21"
    disasm64R6 "7c010001" "dextm at, r0, 0x0, 0x21"
    disasm64R6 "7c400001" "dextm r0, v0, 0x0, 0x21"

  [<TestMethod>]
  member _.``MD00087 DEXTU (Release 6)``() =
    disasm64R6 "7c000002" "dextu r0, r0, 0x20, 0x1"
    disasm64R6 "7c200002" "dextu r0, at, 0x20, 0x1"
    disasm64R6 "7c010002" "dextu at, r0, 0x20, 0x1"
    disasm64R6 "7c400002" "dextu r0, v0, 0x20, 0x1"

  [<TestMethod>]
  member _.``MD00087 DI (Release 6)``() =
    disasm64R6 "41626000" "di v0"

  [<TestMethod>]
  member _.``MD00087 DINS (Release 6)``() =
    disasm64R6 "7c000007" "dins r0, r0, 0x0, 0x1"
    disasm64R6 "7c200007" "dins r0, at, 0x0, 0x1"
    disasm64R6 "7c010007" "dins at, r0, 0x0, 0x1"
    disasm64R6 "7c400007" "dins r0, v0, 0x0, 0x1"

  [<TestMethod>]
  member _.``MD00087 DINSM (Release 6)``() =
    disasm64R6 "7c000005" "dinsm r0, r0, 0x0, 0x21"
    disasm64R6 "7c200005" "dinsm r0, at, 0x0, 0x21"
    disasm64R6 "7c010005" "dinsm at, r0, 0x0, 0x21"
    disasm64R6 "7c400005" "dinsm r0, v0, 0x0, 0x21"

  [<TestMethod>]
  member _.``MD00087 DINSU (Release 6)``() =
    disasm64R6 "7c000006" "dinsu r0, r0, 0x20, 0x1"
    disasm64R6 "7c200006" "dinsu r0, at, 0x20, 0x1"
    disasm64R6 "7c010006" "dinsu at, r0, 0x20, 0x1"
    disasm64R6 "7c400006" "dinsu r0, v0, 0x20, 0x1"

  [<TestMethod>]
  member _.``MD00087 DIV (Release 6)``() =
    disasm64R6 "0000009a" "div r0, r0, r0"
    disasm64R6 "0022189a" "div v1, at, v0"
    disasm64R6 "03fee89a" "div sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 DIV.fmt (Release 6)``() =
    disasm64R6 "46000003" "div.s f0, f0, f0"
    disasm64R6 "46200003" "div.d f0, f0, f0"
    disasm64R6 "46021903" "div.s f4, f3, f2"
    disasm64R6 "46221903" "div.d f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 DIVU (Release 6)``() =
    disasm64R6 "0000009b" "divu r0, r0, r0"
    disasm64R6 "0022189b" "divu v1, at, v0"
    disasm64R6 "03fee89b" "divu sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 DLSA (Release 6)``() =
    disasm64R6 "00000015" "dlsa r0, r0, r0, 0x0"
    disasm64R6 "00200015" "dlsa r0, at, r0, 0x0"
    disasm64R6 "00010015" "dlsa r0, r0, at, 0x0"
    disasm64R6 "00000815" "dlsa at, r0, r0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DMFC0 (Release 6)``() =
    disasm64R6 "40200001" "dmfc0 r0, 0x0, 0x1"
    disasm64R6 "40200002" "dmfc0 r0, 0x0, 0x2"
    disasm64R6 "40200003" "dmfc0 r0, 0x0, 0x3"
    disasm64R6 "40221801" "dmfc0 v0, 0x3, 0x1"

  [<TestMethod>]
  member _.``MD00087 DMFC1 (Release 6)``() =
    disasm64R6 "44200000" "dmfc1 r0, f0"
    disasm64R6 "44221800" "dmfc1 v0, f3"
    disasm64R6 "44201800" "dmfc1 r0, f3"
    disasm64R6 "44211800" "dmfc1 at, f3"

  [<TestMethod>]
  member _.``MD00087 DMFC2 (Release 6)``() =
    disasm64R6 "48200000" "dmfc2 r0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DMOD (Release 6)``() =
    disasm64R6 "000000de" "dmod r0, r0, r0"
    disasm64R6 "002218de" "dmod v1, at, v0"
    disasm64R6 "03fee8de" "dmod sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 DMODU (Release 6)``() =
    disasm64R6 "000000df" "dmodu r0, r0, r0"
    disasm64R6 "002218df" "dmodu v1, at, v0"
    disasm64R6 "03fee8df" "dmodu sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 DMTC0 (Release 6)``() =
    disasm64R6 "40a00001" "dmtc0 r0, 0x0, 0x1"
    disasm64R6 "40a00002" "dmtc0 r0, 0x0, 0x2"
    disasm64R6 "40a00003" "dmtc0 r0, 0x0, 0x3"

  [<TestMethod>]
  member _.``MD00087 DMTC1 (Release 6)``() =
    disasm64R6 "44a00000" "dmtc1 r0, f0"
    disasm64R6 "44a01800" "dmtc1 r0, f3"
    disasm64R6 "44a11800" "dmtc1 at, f3"
    disasm64R6 "44a21800" "dmtc1 v0, f3"

  [<TestMethod>]
  member _.``MD00087 DMTC2 (Release 6)``() =
    disasm64R6 "48a00000" "dmtc2 r0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DMUH (Release 6)``() =
    disasm64R6 "000000dc" "dmuh r0, r0, r0"
    disasm64R6 "002218dc" "dmuh v1, at, v0"
    disasm64R6 "03fee8dc" "dmuh sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 DMUHU (Release 6)``() =
    disasm64R6 "000000dd" "dmuhu r0, r0, r0"
    disasm64R6 "002218dd" "dmuhu v1, at, v0"
    disasm64R6 "03fee8dd" "dmuhu sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 DMUL (Release 6)``() =
    disasm64R6 "0000009c" "dmul r0, r0, r0"
    disasm64R6 "0022189c" "dmul v1, at, v0"
    disasm64R6 "03fee89c" "dmul sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 DMULU (Release 6)``() =
    disasm64R6 "0000009d" "dmulu r0, r0, r0"
    disasm64R6 "0022189d" "dmulu v1, at, v0"
    disasm64R6 "03fee89d" "dmulu sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 DROTR (Release 6)``() =
    disasm64R6 "0020003a" "drotr r0, r0, 0x0"
    disasm64R6 "0020193a" "drotr v1, r0, 0x4"
    disasm64R6 "0022013a" "drotr r0, v0, 0x4"
    disasm64R6 "0022183a" "drotr v1, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DROTR32 (Release 6)``() =
    disasm64R6 "0020003e" "drotr32  r0, r0, 0x0"
    disasm64R6 "0020193e" "drotr32  v1, r0, 0x4"
    disasm64R6 "0022013e" "drotr32  r0, v0, 0x4"
    disasm64R6 "0022183e" "drotr32  v1, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DROTRV (Release 6)``() =
    disasm64R6 "00000056" "drotrv r0, r0, r0"
    disasm64R6 "00221856" "drotrv v1, v0, at"
    disasm64R6 "03fee856" "drotrv sp, s8, ra"

  [<TestMethod>]
  member _.``MD00087 DSBH (Release 6)``() =
    disasm64R6 "7c0000a4" "dsbh r0, r0"

  [<TestMethod>]
  member _.``MD00087 DSHD (Release 6)``() =
    disasm64R6 "7c000164" "dshd r0, r0"

  [<TestMethod>]
  member _.``MD00087 DSLL (Release 6)``() =
    disasm64R6 "00000038" "dsll r0, r0, 0x0"
    disasm64R6 "00010038" "dsll r0, at, 0x0"
    disasm64R6 "00000838" "dsll at, r0, 0x0"
    disasm64R6 "00020038" "dsll r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DSLL32 (Release 6)``() =
    disasm64R6 "0000003c" "dsll32 r0, r0, 0x0"
    disasm64R6 "0001003c" "dsll32 r0, at, 0x0"
    disasm64R6 "0000083c" "dsll32 at, r0, 0x0"
    disasm64R6 "0002003c" "dsll32 r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DSLLV (Release 6)``() =
    disasm64R6 "00000014" "dsllv r0, r0, r0"
    disasm64R6 "00200014" "dsllv r0, r0, at"
    disasm64R6 "00010014" "dsllv r0, at, r0"
    disasm64R6 "00000814" "dsllv at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 DSRA (Release 6)``() =
    disasm64R6 "0000003b" "dsra r0, r0, 0x0"
    disasm64R6 "0001003b" "dsra r0, at, 0x0"
    disasm64R6 "0000083b" "dsra at, r0, 0x0"
    disasm64R6 "0002003b" "dsra r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DSRA32 (Release 6)``() =
    disasm64R6 "0000003f" "dsra32 r0, r0, 0x0"
    disasm64R6 "0001003f" "dsra32 r0, at, 0x0"
    disasm64R6 "0000083f" "dsra32 at, r0, 0x0"
    disasm64R6 "0002003f" "dsra32 r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DSRAV (Release 6)``() =
    disasm64R6 "00000017" "dsrav r0, r0, r0"
    disasm64R6 "00200017" "dsrav r0, r0, at"
    disasm64R6 "00010017" "dsrav r0, at, r0"
    disasm64R6 "00000817" "dsrav at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 DSRL (Release 6)``() =
    disasm64R6 "0000003a" "dsrl r0, r0, 0x0"
    disasm64R6 "0001003a" "dsrl r0, at, 0x0"
    disasm64R6 "0000083a" "dsrl at, r0, 0x0"
    disasm64R6 "0002003a" "dsrl r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DSRL32 (Release 6)``() =
    disasm64R6 "0000003e" "dsrl32 r0, r0, 0x0"
    disasm64R6 "0001003e" "dsrl32 r0, at, 0x0"
    disasm64R6 "0000083e" "dsrl32 at, r0, 0x0"
    disasm64R6 "0002003e" "dsrl32 r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DSRLV (Release 6)``() =
    disasm64R6 "00000016" "dsrlv r0, r0, r0"
    disasm64R6 "00200016" "dsrlv r0, r0, at"
    disasm64R6 "00010016" "dsrlv r0, at, r0"
    disasm64R6 "00000816" "dsrlv at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 DSUB (Release 6)``() =
    disasm64R6 "0020002e" "dsub r0, at, r0"
    disasm64R6 "0040002e" "dsub r0, v0, r0"
    disasm64R6 "0060002e" "dsub r0, v1, r0"
    disasm64R6 "0080002e" "dsub r0, a0, r0"

  [<TestMethod>]
  member _.``MD00087 DSUBU (Release 6)``() =
    disasm64R6 "0020002f" "dsubu r0, at, r0"
    disasm64R6 "0040002f" "dsubu r0, v0, r0"
    disasm64R6 "0060002f" "dsubu r0, v1, r0"
    disasm64R6 "0080002f" "dsubu r0, a0, r0"

  [<TestMethod>]
  member _.``MD00087 DVP (Release 6)``() =
    disasm64R6 "41600024" "dvp r0"

  [<TestMethod>]
  member _.``MD00087 EHB (Release 6)``() =
    disasm64R6 "000000c0" "ehb"

  [<TestMethod>]
  member _.``MD00087 EI (Release 6)``() =
    disasm64R6 "41636020" "ei v1"

  [<TestMethod>]
  member _.``MD00087 ERET (Release 6)``() =
    disasm64R6 "42000018" "eret"

  [<TestMethod>]
  member _.``MD00087 ERETNC (Release 6)``() =
    disasm64R6 "42000058" "eretnc"

  [<TestMethod>]
  member _.``MD00087 EVP (Release 6)``() =
    disasm64R6 "41600004" "evp r0"

  [<TestMethod>]
  member _.``MD00087 EXT (Release 6)``() =
    disasm64R6 "7c000000" "ext r0, r0, 0x0, 0x1"
    disasm64R6 "7c200000" "ext r0, at, 0x0, 0x1"
    disasm64R6 "7c010000" "ext at, r0, 0x0, 0x1"
    disasm64R6 "7c400000" "ext r0, v0, 0x0, 0x1"

  [<TestMethod>]
  member _.``MD00087 FLOOR.L.fmt (Release 6)``() =
    disasm64R6 "4600000b" "floor.l.s f0, f0"
    disasm64R6 "4620000b" "floor.l.d f0, f0"
    disasm64R6 "4600180b" "floor.l.s f0, f3"
    disasm64R6 "4620180b" "floor.l.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 FLOOR.W.fmt (Release 6)``() =
    disasm64R6 "4600000f" "floor.w.s f0, f0"
    disasm64R6 "4620000f" "floor.w.d f0, f0"
    disasm64R6 "4600180f" "floor.w.s f0, f3"
    disasm64R6 "4620180f" "floor.w.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 GINVI (Release 6)``() =
    disasm64R6 "7c00003d" "ginvi r0"
    disasm64R6 "7c20003d" "ginvi at"
    disasm64R6 "7c40003d" "ginvi v0"
    disasm64R6 "7c60003d" "ginvi v1"

  [<TestMethod>]
  member _.``MD00087 GINVT (Release 6)``() =
    disasm64R6 "7c0000bd" "ginvt r0, 0x0"
    disasm64R6 "7c0001bd" "ginvt r0, 0x1"
    disasm64R6 "7c0002bd" "ginvt r0, 0x2"
    disasm64R6 "7c0003bd" "ginvt r0, 0x3"

  [<TestMethod>]
  member _.``MD00087 INS (Release 6)``() =
    disasm64R6 "7c000004" "ins r0, r0, 0x0, 0x1"
    disasm64R6 "7c200004" "ins r0, at, 0x0, 0x1"
    disasm64R6 "7c010004" "ins at, r0, 0x0, 0x1"
    disasm64R6 "7c400004" "ins r0, v0, 0x0, 0x1"

  [<TestMethod>]
  member _.``MD00087 J (Release 6)``() =
    disasm64R6 "08000000" "j 0x0"

  [<TestMethod>]
  member _.``MD00087 JAL (Release 6)``() =
    disasm64R6 "0c000000" "jal 0x0"

  [<TestMethod>]
  member _.``MD00087 JALR (Release 6)``() =
    disasm64R6 "00000809" "jalr at, r0"
    disasm64R6 "00001009" "jalr v0, r0"
    disasm64R6 "00001809" "jalr v1, r0"
    disasm64R6 "00002009" "jalr a0, r0"

  [<TestMethod>]
  member _.``MD00087 JALR.HB (Release 6)``() =
    disasm64R6 "00000409" "jalr.hb r0, r0"

  [<TestMethod>]
  member _.``MD00087 JIALC (Release 6)``() =
    disasm64R6 "f8010001" "jialc at, 0x1"
    disasm64R6 "f8020001" "jialc v0, 0x1"
    disasm64R6 "f8030001" "jialc v1, 0x1"
    disasm64R6 "f8040001" "jialc a0, 0x1"

  [<TestMethod>]
  member _.``MD00087 JIC (Release 6)``() =
    disasm64R6 "d8010001" "jic at, 0x1"
    disasm64R6 "d8020001" "jic v0, 0x1"
    disasm64R6 "d8030001" "jic v1, 0x1"
    disasm64R6 "d8040001" "jic a0, 0x1"

  [<TestMethod>]
  member _.``MD00087 JR (Release 6)``() =
    disasm64R6 "00200009" "jr at"
    disasm64R6 "00400009" "jr v0"
    disasm64R6 "00600009" "jr v1"
    disasm64R6 "00800009" "jr a0"

  [<TestMethod>]
  member _.``MD00087 JR.HB (Release 6)``() =
    disasm64R6 "00000409" "jalr.hb r0, r0"

  [<TestMethod>]
  member _.``MD00087 LB (Release 6)``() =
    disasm64R6 "80000000" "lb r0, 0(r0)"
    disasm64R6 "80010000" "lb at, 0(r0)"
    disasm64R6 "80020000" "lb v0, 0(r0)"
    disasm64R6 "80030000" "lb v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LBE (Release 6)``() =
    disasm64R6 "7c00002c" "lbe r0, 0(r0)"
    disasm64R6 "7c01002c" "lbe at, 0(r0)"
    disasm64R6 "7c02002c" "lbe v0, 0(r0)"
    disasm64R6 "7c03002c" "lbe v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LBU (Release 6)``() =
    disasm64R6 "90000000" "lbu r0, 0(r0)"
    disasm64R6 "90010000" "lbu at, 0(r0)"
    disasm64R6 "90020000" "lbu v0, 0(r0)"
    disasm64R6 "90030000" "lbu v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LBUE (Release 6)``() =
    disasm64R6 "7c000028" "lbue r0, 0(r0)"
    disasm64R6 "7c010028" "lbue at, 0(r0)"
    disasm64R6 "7c020028" "lbue v0, 0(r0)"
    disasm64R6 "7c030028" "lbue v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LD (Release 6)``() =
    disasm64R6 "dc000000" "ld r0, 0(r0)"
    disasm64R6 "dc010000" "ld at, 0(r0)"
    disasm64R6 "dc020000" "ld v0, 0(r0)"
    disasm64R6 "dc030000" "ld v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LDC1 (Release 6)``() =
    disasm64R6 "d4000000" "ldc1 f0, 0(r0)"
    disasm64R6 "d4010000" "ldc1 f1, 0(r0)"
    disasm64R6 "d4020000" "ldc1 f2, 0(r0)"
    disasm64R6 "d4030000" "ldc1 f3, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LDC2 (Release 6)``() =
    disasm64R6 "49c00000" "ldc2 0x0, 0(r0)"
    disasm64R6 "49c00001" "ldc2 0x0, 1(r0)"
    disasm64R6 "49c00002" "ldc2 0x0, 2(r0)"
    disasm64R6 "49c00003" "ldc2 0x0, 3(r0)"

  [<TestMethod>]
  member _.``MD00087 LDPC (Release 6)``() =
    disasm64R6 "ec391900" "ldpc at, 0x8c800"
    disasm64R6 "ec3b1900" "ldpc at, 0xfffffffffff8c800"
    disasm64R6 "eff8ef00" "ldpc ra, 0x77800"
    disasm64R6 "eff9ef00" "ldpc ra, 0xf7800"

  [<TestMethod>]
  member _.``MD00087 LH (Release 6)``() =
    disasm64R6 "84000000" "lh r0, 0(r0)"
    disasm64R6 "84010000" "lh at, 0(r0)"
    disasm64R6 "84020000" "lh v0, 0(r0)"
    disasm64R6 "84030000" "lh v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LHE (Release 6)``() =
    disasm64R6 "7c00002d" "lhe r0, 0(r0)"
    disasm64R6 "7c01002d" "lhe at, 0(r0)"
    disasm64R6 "7c02002d" "lhe v0, 0(r0)"
    disasm64R6 "7c03002d" "lhe v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LHU (Release 6)``() =
    disasm64R6 "94000000" "lhu r0, 0(r0)"
    disasm64R6 "94010000" "lhu at, 0(r0)"
    disasm64R6 "94020000" "lhu v0, 0(r0)"
    disasm64R6 "94030000" "lhu v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LHUE (Release 6)``() =
    disasm64R6 "7c000029" "lhue r0, 0(r0)"
    disasm64R6 "7c010029" "lhue at, 0(r0)"
    disasm64R6 "7c020029" "lhue v0, 0(r0)"
    disasm64R6 "7c030029" "lhue v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LL (Release 6)``() =
    disasm64R6 "7c000036" "ll r0, 0(r0)"
    disasm64R6 "7c010036" "ll at, 0(r0)"
    disasm64R6 "7c020036" "ll v0, 0(r0)"
    disasm64R6 "7c030036" "ll v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LLD (Release 6)``() =
    disasm64R6 "7c000037" "lld r0, 0(r0)"
    disasm64R6 "7c010037" "lld at, 0(r0)"
    disasm64R6 "7c020037" "lld v0, 0(r0)"
    disasm64R6 "7c030037" "lld v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LLDP (Release 6)``() =
    disasm64R6 "7c000077" "lldp r0, r0, 0(r0)"
    disasm64R6 "7c221877" "lldp v0, v1, 0(at)"
    disasm64R6 "7ffee877" "lldp s8, sp, 0(ra)"

  [<TestMethod>]
  member _.``MD00087 LLE (Release 6)``() =
    disasm64R6 "7c00002e" "lle r0, 0(r0)"
    disasm64R6 "7c01002e" "lle at, 0(r0)"
    disasm64R6 "7c02002e" "lle v0, 0(r0)"
    disasm64R6 "7c03002e" "lle v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LLWP (Release 6)``() =
    disasm64R6 "7c000076" "llwp r0, r0, 0(r0)"
    disasm64R6 "7c221876" "llwp v0, v1, 0(at)"
    disasm64R6 "7ffee876" "llwp s8, sp, 0(ra)"

  [<TestMethod>]
  member _.``MD00087 LLWPE (Release 6)``() =
    disasm64R6 "7c00006e" "llwpe r0, r0, 0(r0)"
    disasm64R6 "7c22186e" "llwpe v0, v1, 0(at)"
    disasm64R6 "7ffee86e" "llwpe s8, sp, 0(ra)"

  [<TestMethod>]
  member _.``MD00087 LSA (Release 6)``() =
    disasm64R6 "00000005" "lsa r0, r0, r0, 0x0"
    disasm64R6 "00200005" "lsa r0, at, r0, 0x0"
    disasm64R6 "00010005" "lsa r0, r0, at, 0x0"
    disasm64R6 "00000805" "lsa at, r0, r0, 0x0"

  [<TestMethod>]
  member _.``MD00087 LUI (Release 6)``() =
    disasm64R6 "3c000000" "lui r0, 0x0"
    disasm64R6 "3c010000" "lui at, 0x0"
    disasm64R6 "3c020000" "lui v0, 0x0"
    disasm64R6 "3c030000" "lui v1, 0x0"

  [<TestMethod>]
  member _.``MD00087 LW (Release 6)``() =
    disasm64R6 "8c000000" "lw r0, 0(r0)"
    disasm64R6 "8c010000" "lw at, 0(r0)"
    disasm64R6 "8c020000" "lw v0, 0(r0)"
    disasm64R6 "8c030000" "lw v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LWC1 (Release 6)``() =
    disasm64R6 "c4000000" "lwc1 f0, 0(r0)"
    disasm64R6 "c4010000" "lwc1 f1, 0(r0)"
    disasm64R6 "c4020000" "lwc1 f2, 0(r0)"
    disasm64R6 "c4030000" "lwc1 f3, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LWC2 (Release 6)``() =
    disasm64R6 "49400000" "lwc2 0x0, 0(r0)"
    disasm64R6 "49400001" "lwc2 0x0, 1(r0)"
    disasm64R6 "49400002" "lwc2 0x0, 2(r0)"
    disasm64R6 "49400003" "lwc2 0x0, 3(r0)"

  [<TestMethod>]
  member _.``MD00087 LWE (Release 6)``() =
    disasm64R6 "7c00002f" "lwe r0, 0(r0)"
    disasm64R6 "7c01002f" "lwe at, 0(r0)"
    disasm64R6 "7c02002f" "lwe v0, 0(r0)"
    disasm64R6 "7c03002f" "lwe v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LWPC (Release 6)``() =
    disasm64R6 "ec080000" "lwpc r0, 0x0"
    disasm64R6 "ec090000" "lwpc r0, 0x40000"
    disasm64R6 "ec0a0000" "lwpc r0, 0x80000"
    disasm64R6 "ec0b0000" "lwpc r0, 0xc0000"

  [<TestMethod>]
  member _.``MD00087 LWU (Release 6)``() =
    disasm64R6 "9c000000" "lwu r0, 0(r0)"
    disasm64R6 "9c010000" "lwu at, 0(r0)"
    disasm64R6 "9c020000" "lwu v0, 0(r0)"
    disasm64R6 "9c030000" "lwu v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LWUPC (Release 6)``() =
    disasm64R6 "ec100000" "lwupc r0, 0x0"
    disasm64R6 "ec110000" "lwupc r0, 0x40000"
    disasm64R6 "ec120000" "lwupc r0, 0x80000"
    disasm64R6 "ec130000" "lwupc r0, 0xc0000"

  [<TestMethod>]
  member _.``MD00087 MADDF.fmt (Release 6)``() =
    disasm64R6 "46000018" "maddf.s f0, f0, f0"
    disasm64R6 "46200018" "maddf.d f0, f0, f0"
    disasm64R6 "46021918" "maddf.s f4, f3, f2"
    disasm64R6 "46221918" "maddf.d f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 MAX.fmt (Release 6)``() =
    disasm64R6 "4600001e" "max.s f0, f0, f0"
    disasm64R6 "4620001e" "max.d f0, f0, f0"
    disasm64R6 "4602191e" "max.s f4, f3, f2"
    disasm64R6 "4622191e" "max.d f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 MAXA.fmt (Release 6)``() =
    disasm64R6 "4600001f" "maxa.s f0, f0, f0"
    disasm64R6 "4620001f" "maxa.d f0, f0, f0"
    disasm64R6 "4602191f" "maxa.s f4, f3, f2"
    disasm64R6 "4622191f" "maxa.d f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 MFC0 (Release 6)``() =
    disasm64R6 "40000000" "mfc0 r0, 0x0, 0x0"
    disasm64R6 "40010000" "mfc0 at, 0x0, 0x0"
    disasm64R6 "40020000" "mfc0 v0, 0x0, 0x0"
    disasm64R6 "40030000" "mfc0 v1, 0x0, 0x0"

  [<TestMethod>]
  member _.``MD00087 MFC1 (Release 6)``() =
    disasm64R6 "44000000" "mfc1 r0, f0"
    disasm64R6 "44010000" "mfc1 at, f0"
    disasm64R6 "44000800" "mfc1 r0, f1"
    disasm64R6 "44020000" "mfc1 v0, f0"

  [<TestMethod>]
  member _.``MD00087 MFC2 (Release 6)``() =
    disasm64R6 "48000000" "mfc2 r0, 0x0"
    disasm64R6 "48010000" "mfc2 at, 0x0"
    disasm64R6 "48020000" "mfc2 v0, 0x0"
    disasm64R6 "48030000" "mfc2 v1, 0x0"

  [<TestMethod>]
  member _.``MD00087 MFHC0 (Release 6)``() =
    disasm64R6 "40400000" "mfhc0 r0, 0x0, 0x0"
    disasm64R6 "40400001" "mfhc0 r0, 0x0, 0x1"
    disasm64R6 "40400002" "mfhc0 r0, 0x0, 0x2"
    disasm64R6 "40400003" "mfhc0 r0, 0x0, 0x3"

  [<TestMethod>]
  member _.``MD00087 MFHC1 (Release 6)``() =
    disasm64R6 "44600000" "mfhc1 r0, f0"
    disasm64R6 "44601800" "mfhc1 r0, f3"
    disasm64R6 "44611800" "mfhc1 at, f3"
    disasm64R6 "44621800" "mfhc1 v0, f3"

  [<TestMethod>]
  member _.``MD00087 MFHC2 (Release 6)``() =
    disasm64R6 "48600000" "mfhc2 r0, 0x0"
    disasm64R6 "48621900" "mfhc2 v0, 0x1900"
    disasm64R6 "48621901" "mfhc2 v0, 0x1901"
    disasm64R6 "48621902" "mfhc2 v0, 0x1902"

  [<TestMethod>]
  member _.``MD00087 MIN.fmt (Release 6)``() =
    disasm64R6 "4600001c" "min.s f0, f0, f0"
    disasm64R6 "4620001c" "min.d f0, f0, f0"
    disasm64R6 "4602191c" "min.s f4, f3, f2"
    disasm64R6 "4622191c" "min.d f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 MINA.fmt (Release 6)``() =
    disasm64R6 "4600001d" "mina.s f0, f0, f0"
    disasm64R6 "4620001d" "mina.d f0, f0, f0"
    disasm64R6 "4602191d" "mina.s f4, f3, f2"
    disasm64R6 "4622191d" "mina.d f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 MOD (Release 6)``() =
    disasm64R6 "000000da" "mod r0, r0, r0"
    disasm64R6 "002218da" "mod v1, at, v0"
    disasm64R6 "03fee8da" "mod sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 MODU (Release 6)``() =
    disasm64R6 "000000db" "modu r0, r0, r0"
    disasm64R6 "002218db" "modu v1, at, v0"
    disasm64R6 "03fee8db" "modu sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 MOV.fmt (Release 6)``() =
    disasm64R6 "46000006" "mov.s f0, f0"
    disasm64R6 "46200006" "mov.d f0, f0"
    disasm64R6 "46001806" "mov.s f0, f3"
    disasm64R6 "46201806" "mov.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 MSUBF.fmt (Release 6)``() =
    disasm64R6 "46000019" "msubf.s f0, f0, f0"
    disasm64R6 "46200019" "msubf.d f0, f0, f0"
    disasm64R6 "46021919" "msubf.s f4, f3, f2"
    disasm64R6 "46221919" "msubf.d f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 MTC0 (Release 6)``() =
    disasm64R6 "40800000" "mtc0 r0, 0x0, 0x0"
    disasm64R6 "40800001" "mtc0 r0, 0x0, 0x1"
    disasm64R6 "40800002" "mtc0 r0, 0x0, 0x2"
    disasm64R6 "40800003" "mtc0 r0, 0x0, 0x3"

  [<TestMethod>]
  member _.``MD00087 MTC1 (Release 6)``() =
    disasm64R6 "44800000" "mtc1 r0, f0"
    disasm64R6 "44801800" "mtc1 r0, f3"
    disasm64R6 "44811800" "mtc1 at, f3"
    disasm64R6 "44821800" "mtc1 v0, f3"

  [<TestMethod>]
  member _.``MD00087 MTC2 (Release 6)``() =
    disasm64R6 "48800000" "mtc2 r0, 0x0"

  [<TestMethod>]
  member _.``MD00087 MTHC0 (Release 6)``() =
    disasm64R6 "40c00000" "mthc0 r0, 0x0, 0x0"
    disasm64R6 "40c00001" "mthc0 r0, 0x0, 0x1"
    disasm64R6 "40c00002" "mthc0 r0, 0x0, 0x2"
    disasm64R6 "40c00003" "mthc0 r0, 0x0, 0x3"

  [<TestMethod>]
  member _.``MD00087 MTHC1 (Release 6)``() =
    disasm64R6 "44e00000" "mthc1 r0, f0"
    disasm64R6 "44e01800" "mthc1 r0, f3"
    disasm64R6 "44e11800" "mthc1 at, f3"
    disasm64R6 "44e21800" "mthc1 v0, f3"

  [<TestMethod>]
  member _.``MD00087 MTHC2 (Release 6)``() =
    disasm64R6 "48e00000" "mthc2 r0, 0x0"
    disasm64R6 "48e21900" "mthc2 v0, 0x1900"
    disasm64R6 "48e21901" "mthc2 v0, 0x1901"
    disasm64R6 "48e21902" "mthc2 v0, 0x1902"

  [<TestMethod>]
  member _.``MD00087 MUH (Release 6)``() =
    disasm64R6 "000000d8" "muh r0, r0, r0"
    disasm64R6 "002218d8" "muh v1, at, v0"
    disasm64R6 "03fee8d8" "muh sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 MUHU (Release 6)``() =
    disasm64R6 "000000d9" "muhu r0, r0, r0"
    disasm64R6 "002218d9" "muhu v1, at, v0"
    disasm64R6 "03fee8d9" "muhu sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 MUL (Release 6)``() =
    disasm64R6 "00000098" "mul r0, r0, r0"
    disasm64R6 "00221898" "mul v1, at, v0"
    disasm64R6 "03fee898" "mul sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 MUL.fmt (Release 6)``() =
    disasm64R6 "46000002" "mul.s f0, f0, f0"
    disasm64R6 "46200002" "mul.d f0, f0, f0"
    disasm64R6 "46021902" "mul.s f4, f3, f2"
    disasm64R6 "46221902" "mul.d f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 MULU (Release 6)``() =
    disasm64R6 "00000099" "mulu r0, r0, r0"
    disasm64R6 "00221899" "mulu v1, at, v0"
    disasm64R6 "03fee899" "mulu sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 NAL (Release 6)``() =
    disasm64R6 "04100000" "nal 0x4"

  [<TestMethod>]
  member _.``MD00087 NEG.fmt (Release 6)``() =
    disasm64R6 "46000007" "neg.s f0, f0"
    disasm64R6 "46200007" "neg.d f0, f0"
    disasm64R6 "46001807" "neg.s f0, f3"
    disasm64R6 "46201807" "neg.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 NOP (Release 6)``() =
    disasm64R6 "00000000" "nop"

  [<TestMethod>]
  member _.``MD00087 NOR (Release 6)``() =
    disasm64R6 "00000027" "nor r0, r0, r0"
    disasm64R6 "00200027" "nor r0, at, r0"
    disasm64R6 "00010027" "nor r0, r0, at"
    disasm64R6 "00000827" "nor at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 OR (Release 6)``() =
    disasm64R6 "00000025" "or r0, r0, r0"
    disasm64R6 "00200025" "or r0, at, r0"
    disasm64R6 "00010025" "or r0, r0, at"
    disasm64R6 "00000825" "or at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 ORI (Release 6)``() =
    disasm64R6 "34200000" "ori r0, at, 0x0"
    disasm64R6 "34400000" "ori r0, v0, 0x0"
    disasm64R6 "34600000" "ori r0, v1, 0x0"
    disasm64R6 "34800000" "ori r0, a0, 0x0"

  [<TestMethod>]
  member _.``MD00087 PAUSE (Release 6)``() =
    disasm64R6 "00000140" "pause"

  [<TestMethod>]
  member _.``MD00087 PREF (Release 6)``() =
    disasm64R6 "7c000035" "pref 0x0, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 PREFE (Release 6)``() =
    disasm64R6 "7c000023" "prefe 0x0, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 RDHWR (Release 6)``() =
    disasm64R6 "7c02193b" "rdhwr v0, v1, 0x4"

  [<TestMethod>]
  member _.``MD00087 RDPGPR (Release 6)``() =
    disasm64R6 "41400000" "rdpgpr r0, r0"

  [<TestMethod>]
  member _.``MD00087 RECIP.fmt (Release 6)``() =
    disasm64R6 "46000015" "recip.s f0, f0"
    disasm64R6 "46200015" "recip.d f0, f0"
    disasm64R6 "46001815" "recip.s f0, f3"
    disasm64R6 "46201815" "recip.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 RINT.fmt (Release 6)``() =
    disasm64R6 "4600001a" "rint.s f0, f0"
    disasm64R6 "4620001a" "rint.d f0, f0"
    disasm64R6 "4600181a" "rint.s f0, f3"
    disasm64R6 "4620181a" "rint.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 ROTR (Release 6)``() =
    disasm64R6 "00200002" "rotr r0, r0, 0x0"
    disasm64R6 "00201902" "rotr v1, r0, 0x4"
    disasm64R6 "00220102" "rotr r0, v0, 0x4"
    disasm64R6 "00221802" "rotr v1, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 ROTRV (Release 6)``() =
    disasm64R6 "00000046" "rotrv r0, r0, r0"
    disasm64R6 "00221846" "rotrv v1, v0, at"
    disasm64R6 "03fee846" "rotrv sp, s8, ra"

  [<TestMethod>]
  member _.``MD00087 ROUND.L.fmt (Release 6)``() =
    disasm64R6 "46000008" "round.l.s f0, f0"
    disasm64R6 "46200008" "round.l.d f0, f0"
    disasm64R6 "46001808" "round.l.s f0, f3"
    disasm64R6 "46201808" "round.l.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 ROUND.W.fmt (Release 6)``() =
    disasm64R6 "4600000c" "round.w.s f0, f0"
    disasm64R6 "4620000c" "round.w.d f0, f0"
    disasm64R6 "4600180c" "round.w.s f0, f3"
    disasm64R6 "4620180c" "round.w.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 RSQRT.fmt (Release 6)``() =
    disasm64R6 "46000016" "rsqrt.s f0, f0"
    disasm64R6 "46200016" "rsqrt.d f0, f0"
    disasm64R6 "46001816" "rsqrt.s f0, f3"
    disasm64R6 "46201816" "rsqrt.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 SB (Release 6)``() =
    disasm64R6 "a0000000" "sb r0, 0(r0)"
    disasm64R6 "a0010000" "sb at, 0(r0)"
    disasm64R6 "a0020000" "sb v0, 0(r0)"
    disasm64R6 "a0030000" "sb v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SBE (Release 6)``() =
    disasm64R6 "7c00001c" "sbe r0, 0(r0)"
    disasm64R6 "7c01001c" "sbe at, 0(r0)"
    disasm64R6 "7c02001c" "sbe v0, 0(r0)"
    disasm64R6 "7c03001c" "sbe v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SC (Release 6)``() =
    disasm64R6 "7c000026" "sc r0, 0(r0)"
    disasm64R6 "7c010026" "sc at, 0(r0)"
    disasm64R6 "7c020026" "sc v0, 0(r0)"
    disasm64R6 "7c030026" "sc v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SCD (Release 6)``() =
    disasm64R6 "7c000027" "scd r0, 0(r0)"
    disasm64R6 "7c010027" "scd at, 0(r0)"
    disasm64R6 "7c020027" "scd v0, 0(r0)"
    disasm64R6 "7c030027" "scd v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SCDP (Release 6)``() =
    disasm64R6 "7c000067" "scdp r0, r0, 0(r0)"
    disasm64R6 "7c221867" "scdp v0, v1, 0(at)"
    disasm64R6 "7ffee867" "scdp s8, sp, 0(ra)"

  [<TestMethod>]
  member _.``MD00087 SCE (Release 6)``() =
    disasm64R6 "7c00001e" "sce r0, 0(r0)"
    disasm64R6 "7c01001e" "sce at, 0(r0)"
    disasm64R6 "7c02001e" "sce v0, 0(r0)"
    disasm64R6 "7c03001e" "sce v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SCWP (Release 6)``() =
    disasm64R6 "7c000066" "scwp r0, r0, 0(r0)"
    disasm64R6 "7c221866" "scwp v0, v1, 0(at)"
    disasm64R6 "7ffee866" "scwp s8, sp, 0(ra)"

  [<TestMethod>]
  member _.``MD00087 SCWPE (Release 6)``() =
    disasm64R6 "7c00005e" "scwpe r0, r0, 0(r0)"
    disasm64R6 "7c22185e" "scwpe v0, v1, 0(at)"
    disasm64R6 "7ffee85e" "scwpe s8, sp, 0(ra)"

  [<TestMethod>]
  member _.``MD00087 SD (Release 6)``() =
    disasm64R6 "fc000000" "sd r0, 0(r0)"
    disasm64R6 "fc010000" "sd at, 0(r0)"
    disasm64R6 "fc020000" "sd v0, 0(r0)"
    disasm64R6 "fc030000" "sd v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SDBBP (Release 6)``() =
    disasm64R6 "0000000e" "sdbbp 0x0"

  [<TestMethod>]
  member _.``MD00087 SDC1 (Release 6)``() =
    disasm64R6 "f4000000" "sdc1 f0, 0(r0)"
    disasm64R6 "f4010000" "sdc1 f1, 0(r0)"
    disasm64R6 "f4020000" "sdc1 f2, 0(r0)"
    disasm64R6 "f4030000" "sdc1 f3, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SDC2 (Release 6)``() =
    disasm64R6 "49e00000" "sdc2 0x0, 0(r0)"
    disasm64R6 "49e00001" "sdc2 0x0, 1(r0)"
    disasm64R6 "49e00002" "sdc2 0x0, 2(r0)"
    disasm64R6 "49e00003" "sdc2 0x0, 3(r0)"

  [<TestMethod>]
  member _.``MD00087 SEB (Release 6)``() =
    disasm64R6 "7c000420" "seb r0, r0"

  [<TestMethod>]
  member _.``MD00087 SEH (Release 6)``() =
    disasm64R6 "7c000620" "seh r0, r0"

  [<TestMethod>]
  member _.``MD00087 SEL.fmt (Release 6)``() =
    disasm64R6 "46000010" "sel.s f0, f0, f0"
    disasm64R6 "46200010" "sel.d f0, f0, f0"
    disasm64R6 "46021910" "sel.s f4, f3, f2"
    disasm64R6 "46221910" "sel.d f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 SELEQZ (Release 6)``() =
    disasm64R6 "00000035" "seleqz r0, r0, r0"
    disasm64R6 "00200035" "seleqz r0, at, r0"
    disasm64R6 "00010035" "seleqz r0, r0, at"
    disasm64R6 "00000835" "seleqz at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 SELEQZ.fmt (Release 6)``() =
    disasm64R6 "46000014" "seleqz.s f0, f0, f0"
    disasm64R6 "46200014" "seleqz.d f0, f0, f0"
    disasm64R6 "46021914" "seleqz.s f4, f3, f2"
    disasm64R6 "46221914" "seleqz.d f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 SELNEQZ.fmt (Release 6)``() =
    disasm64R6 "46000017" "selneqz.s f0, f0, f0"
    disasm64R6 "46200017" "selneqz.d f0, f0, f0"
    disasm64R6 "46021917" "selneqz.s f4, f3, f2"
    disasm64R6 "46221917" "selneqz.d f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 SELNEZ (Release 6)``() =
    disasm64R6 "00000037" "selnez r0, r0, r0"
    disasm64R6 "00200037" "selnez r0, at, r0"
    disasm64R6 "00010037" "selnez r0, r0, at"
    disasm64R6 "00000837" "selnez at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 SH (Release 6)``() =
    disasm64R6 "a4000000" "sh r0, 0(r0)"
    disasm64R6 "a4010000" "sh at, 0(r0)"
    disasm64R6 "a4020000" "sh v0, 0(r0)"
    disasm64R6 "a4030000" "sh v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SHE (Release 6)``() =
    disasm64R6 "7c00001d" "she r0, 0(r0)"
    disasm64R6 "7c01001d" "she at, 0(r0)"
    disasm64R6 "7c02001d" "she v0, 0(r0)"
    disasm64R6 "7c03001d" "she v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SIGRIE (Release 6)``() =
    disasm64R6 "04170000" "sigrie 0x0"
    disasm64R6 "04170001" "sigrie 0x1"
    disasm64R6 "04170002" "sigrie 0x2"
    disasm64R6 "04170003" "sigrie 0x3"

  [<TestMethod>]
  member _.``MD00087 SLL (Release 6)``() =
    disasm64R6 "00010000" "sll r0, at, 0x0"
    disasm64R6 "00000800" "sll at, r0, 0x0"
    disasm64R6 "00020000" "sll r0, v0, 0x0"
    disasm64R6 "00001000" "sll v0, r0, 0x0"

  [<TestMethod>]
  member _.``MD00087 SLLV (Release 6)``() =
    disasm64R6 "00000004" "sllv r0, r0, r0"
    disasm64R6 "00200004" "sllv r0, r0, at"
    disasm64R6 "00010004" "sllv r0, at, r0"
    disasm64R6 "00000804" "sllv at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 SLT (Release 6)``() =
    disasm64R6 "0000002a" "slt r0, r0, r0"
    disasm64R6 "0020002a" "slt r0, at, r0"
    disasm64R6 "0001002a" "slt r0, r0, at"
    disasm64R6 "0000082a" "slt at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 SLTI (Release 6)``() =
    disasm64R6 "28000000" "slti r0, r0, 0x0"
    disasm64R6 "28200000" "slti r0, at, 0x0"
    disasm64R6 "28010000" "slti at, r0, 0x0"
    disasm64R6 "28400000" "slti r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 SLTIU (Release 6)``() =
    disasm64R6 "2c000000" "sltiu r0, r0, 0x0"
    disasm64R6 "2c200000" "sltiu r0, at, 0x0"
    disasm64R6 "2c010000" "sltiu at, r0, 0x0"
    disasm64R6 "2c400000" "sltiu r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 SLTU (Release 6)``() =
    disasm64R6 "0000002b" "sltu r0, r0, r0"
    disasm64R6 "0020002b" "sltu r0, at, r0"
    disasm64R6 "0001002b" "sltu r0, r0, at"
    disasm64R6 "0000082b" "sltu at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 SQRT.fmt (Release 6)``() =
    disasm64R6 "46000004" "sqrt.s f0, f0"
    disasm64R6 "46200004" "sqrt.d f0, f0"
    disasm64R6 "46001804" "sqrt.s f0, f3"
    disasm64R6 "46201804" "sqrt.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 SRA (Release 6)``() =
    disasm64R6 "00000003" "sra r0, r0, 0x0"
    disasm64R6 "00010003" "sra r0, at, 0x0"
    disasm64R6 "00000803" "sra at, r0, 0x0"
    disasm64R6 "00020003" "sra r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 SRAV (Release 6)``() =
    disasm64R6 "00000007" "srav r0, r0, r0"
    disasm64R6 "00200007" "srav r0, r0, at"
    disasm64R6 "00010007" "srav r0, at, r0"
    disasm64R6 "00000807" "srav at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 SRL (Release 6)``() =
    disasm64R6 "00000002" "srl r0, r0, 0x0"
    disasm64R6 "00010002" "srl r0, at, 0x0"
    disasm64R6 "00000802" "srl at, r0, 0x0"
    disasm64R6 "00020002" "srl r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 SRLV (Release 6)``() =
    disasm64R6 "00000006" "srlv r0, r0, r0"
    disasm64R6 "00200006" "srlv r0, r0, at"
    disasm64R6 "00010006" "srlv r0, at, r0"
    disasm64R6 "00000806" "srlv at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 SSNOP (Release 6)``() =
    disasm64R6 "00000040" "ssnop"

  [<TestMethod>]
  member _.``MD00087 SUB (Release 6)``() =
    disasm64R6 "00200022" "sub r0, at, r0"
    disasm64R6 "00400022" "sub r0, v0, r0"
    disasm64R6 "00600022" "sub r0, v1, r0"
    disasm64R6 "00800022" "sub r0, a0, r0"

  [<TestMethod>]
  member _.``MD00087 SUB.fmt (Release 6)``() =
    disasm64R6 "46000001" "sub.s f0, f0, f0"
    disasm64R6 "46200001" "sub.d f0, f0, f0"
    disasm64R6 "46021901" "sub.s f4, f3, f2"
    disasm64R6 "46221901" "sub.d f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 SUBU (Release 6)``() =
    disasm64R6 "00200023" "subu r0, at, r0"
    disasm64R6 "00400023" "subu r0, v0, r0"
    disasm64R6 "00600023" "subu r0, v1, r0"
    disasm64R6 "00800023" "subu r0, a0, r0"

  [<TestMethod>]
  member _.``MD00087 SW (Release 6)``() =
    disasm64R6 "ac000000" "sw r0, 0(r0)"
    disasm64R6 "ac010000" "sw at, 0(r0)"
    disasm64R6 "ac020000" "sw v0, 0(r0)"
    disasm64R6 "ac030000" "sw v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SWC1 (Release 6)``() =
    disasm64R6 "e4000000" "swc1 f0, 0(r0)"
    disasm64R6 "e4010000" "swc1 f1, 0(r0)"
    disasm64R6 "e4020000" "swc1 f2, 0(r0)"
    disasm64R6 "e4030000" "swc1 f3, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SWC2 (Release 6)``() =
    disasm64R6 "49600000" "swc2 0x0, 0(r0)"
    disasm64R6 "49600001" "swc2 0x0, 1(r0)"
    disasm64R6 "49600002" "swc2 0x0, 2(r0)"
    disasm64R6 "49600003" "swc2 0x0, 3(r0)"

  [<TestMethod>]
  member _.``MD00087 SWE (Release 6)``() =
    disasm64R6 "7c00001f" "swe r0, 0(r0)"
    disasm64R6 "7c01001f" "swe at, 0(r0)"
    disasm64R6 "7c02001f" "swe v0, 0(r0)"
    disasm64R6 "7c03001f" "swe v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SYNC (Release 6)``() =
    disasm64R6 "0000000f" "sync 0x0"

  [<TestMethod>]
  member _.``MD00087 SYNCI (Release 6)``() =
    disasm64R6 "041f0000" "synci 0(r0)"
    disasm64R6 "041f0001" "synci 1(r0)"
    disasm64R6 "041f0002" "synci 2(r0)"
    disasm64R6 "041f0003" "synci 3(r0)"

  [<TestMethod>]
  member _.``MD00087 SYSCALL (Release 6)``() =
    disasm64R6 "0000000c" "syscall"

  [<TestMethod>]
  member _.``MD00087 TEQ (Release 6)``() =
    disasm64R6 "00000034" "teq r0, r0"
    disasm64R6 "00200034" "teq at, r0"
    disasm64R6 "00010034" "teq r0, at"
    disasm64R6 "00400034" "teq v0, r0"

  [<TestMethod>]
  member _.``MD00087 TGE (Release 6)``() =
    disasm64R6 "00000030" "tge r0, r0"
    disasm64R6 "00200030" "tge at, r0"
    disasm64R6 "00010030" "tge r0, at"
    disasm64R6 "00400030" "tge v0, r0"

  [<TestMethod>]
  member _.``MD00087 TGEU (Release 6)``() =
    disasm64R6 "00000031" "tgeu r0, r0"
    disasm64R6 "00200031" "tgeu at, r0"
    disasm64R6 "00010031" "tgeu r0, at"
    disasm64R6 "00400031" "tgeu v0, r0"

  [<TestMethod>]
  member _.``MD00087 TLBINV (Release 6)``() =
    disasm64R6 "42000003" "tlbinv"

  [<TestMethod>]
  member _.``MD00087 TLBINVF (Release 6)``() =
    disasm64R6 "42000004" "tlbinvf"

  [<TestMethod>]
  member _.``MD00087 TLBP (Release 6)``() =
    disasm64R6 "42000008" "tlbp"

  [<TestMethod>]
  member _.``MD00087 TLBR (Release 6)``() =
    disasm64R6 "42000001" "tlbr"

  [<TestMethod>]
  member _.``MD00087 TLBWI (Release 6)``() =
    disasm64R6 "42000002" "tlbwi"

  [<TestMethod>]
  member _.``MD00087 TLBWR (Release 6)``() =
    disasm64R6 "42000006" "tlbwr"

  [<TestMethod>]
  member _.``MD00087 TLT (Release 6)``() =
    disasm64R6 "00000032" "tlt r0, r0"
    disasm64R6 "00200032" "tlt at, r0"
    disasm64R6 "00010032" "tlt r0, at"
    disasm64R6 "00400032" "tlt v0, r0"

  [<TestMethod>]
  member _.``MD00087 TLTU (Release 6)``() =
    disasm64R6 "00000033" "tltu r0, r0"
    disasm64R6 "00200033" "tltu at, r0"
    disasm64R6 "00010033" "tltu r0, at"
    disasm64R6 "00400033" "tltu v0, r0"

  [<TestMethod>]
  member _.``MD00087 TNE (Release 6)``() =
    disasm64R6 "00000036" "tne r0, r0"
    disasm64R6 "00200036" "tne at, r0"
    disasm64R6 "00010036" "tne r0, at"
    disasm64R6 "00400036" "tne v0, r0"

  [<TestMethod>]
  member _.``MD00087 TRUNC.L.fmt (Release 6)``() =
    disasm64R6 "46000009" "trunc.l.s f0, f0"
    disasm64R6 "46200009" "trunc.l.d f0, f0"
    disasm64R6 "46001809" "trunc.l.s f0, f3"
    disasm64R6 "46201809" "trunc.l.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 TRUNC.W.fmt (Release 6)``() =
    disasm64R6 "4600000d" "trunc.w.s f0, f0"
    disasm64R6 "4620000d" "trunc.w.d f0, f0"
    disasm64R6 "4600180d" "trunc.w.s f0, f3"
    disasm64R6 "4620180d" "trunc.w.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 WAIT (Release 6)``() =
    disasm64R6 "42000020" "wait"

  [<TestMethod>]
  member _.``MD00087 WRPGPR (Release 6)``() =
    disasm64R6 "41c00000" "wrpgpr r0, r0"

  [<TestMethod>]
  member _.``MD00087 WSBH (Release 6)``() =
    disasm64R6 "7c0000a0" "wsbh r0, r0"

  [<TestMethod>]
  member _.``MD00087 XOR (Release 6)``() =
    disasm64R6 "00000026" "xor r0, r0, r0"
    disasm64R6 "00200026" "xor r0, at, r0"
    disasm64R6 "00010026" "xor r0, r0, at"
    disasm64R6 "00000826" "xor at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 XORI (Release 6)``() =
    disasm64R6 "38000000" "xori r0, r0, 0x0"
    disasm64R6 "38200000" "xori r0, at, 0x0"
    disasm64R6 "38010000" "xori at, r0, 0x0"
    disasm64R6 "38400000" "xori r0, v0, 0x0"
