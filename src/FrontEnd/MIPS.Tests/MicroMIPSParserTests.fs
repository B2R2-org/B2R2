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

namespace B2R2.FrontEnd.MIPS.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.MIPS
open type Opcode
open type Register

/// Shortcut for creating operands.
[<AutoOpen>]
module private MicroMIPSShortcut =
  type O =
    static member Reg(r) = OpReg r

    static member Imm(v) = OpImm v

    static member Mem(r, o: int64, rt) = OpMem(r, Imm o, rt)

    static member Addr(t) = OpAddr t

    static member Shift(s) = OpShiftAmount s

    static member List(rs) = OpRegList rs

/// <summary>
/// The 16-bit microMIPS encodings.
///
/// Every case here was assembled rather than read off a page: the manual's
/// field boxes do not survive being turned into text, and more than one of
/// them comes out with the labels over the wrong bits. What settles each
/// field is what an assembler emits for an instruction whose operands say
/// where the field has to be.
/// </summary>
[<TestClass>]
type MicroMIPSParserTests() =
  let isa =
    ISA(Architecture.MIPS,
        Endian.Little,
        WordSize.Bit64,
        int MIPSISAMode.MicroMIPS)

  let parser =
    Parser(isa, BinReader.Init Endian.Little) :> IInstructionParsable

  let operandsFromArray oprList =
    let oprArray = Array.ofList oprList
    match oprArray.Length with
    | 0 -> NoOperand
    | 1 -> OneOperand oprArray[0]
    | 2 -> TwoOperands(oprArray[0], oprArray[1])
    | 3 -> ThreeOperands(oprArray[0], oprArray[1], oprArray[2])
    | 4 -> FourOperands(oprArray[0], oprArray[1], oprArray[2], oprArray[3])
    | _ -> Terminator.impossible ()

  let test (cases: (string * (Opcode * Operand list)) list) =
    for hex, (opcode, oprs) in cases do
      let bytes = ByteArray.ofHexString hex
      let ins = parser.Parse(System.ReadOnlySpan bytes, 0UL) :?> Instruction
      Assert.AreEqual<Opcode>(opcode, ins.Opcode, hex)
      Assert.AreEqual<Operands>(operandsFromArray oprs, ins.Operands, hex)

  /// One instruction at a release and a word size, read from big-endian
  /// bytes so that the hex is the word as the manuals draw it: the halfword
  /// holding the major opcode first.
  let parseAt release wordSize (hex: string) =
    let flags = int MIPSISAMode.MicroMIPS ||| int release
    let isa = ISA(Architecture.MIPS, Endian.Big, wordSize, flags)
    let p = Parser(isa, BinReader.Init Endian.Big) :> IInstructionParsable
    let bytes = ByteArray.ofHexString hex
    p.Parse(System.ReadOnlySpan bytes, 0UL) :?> Instruction

  let testR6 wordSize (cases: (string * (Opcode * Operand list)) list) =
    for hex, (opcode, oprs) in cases do
      let ins = parseAt MIPSRelease.R6 wordSize hex
      Assert.AreEqual<Opcode>(opcode, ins.Opcode, hex)
      Assert.AreEqual<Operands>(operandsFromArray oprs, ins.Operands, hex)

  let refusesAt release wordSize hex =
    Assert.ThrowsExactly<ParsingFailureException>((fun () ->
      parseAt release wordSize hex |> ignore), hex) |> ignore

  let isaMicro64 =
    ISA(Architecture.MIPS,
        Endian.Big,
        WordSize.Bit64,
        int MIPSISAMode.MicroMIPS)

  let disasmMicro64 (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let parser =
      Parser(isaMicro64, BinReader.Init isaMicro64.Endian)
      :> IInstructionParsable
    let ins = parser.Parse(bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  /// <summary>
  /// POOL16A and POOL16B, whose destination field is the TOPMOST of the
  /// three rather than the last.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] The register pools decode``() =
    test [ "4705", (SUBU, [ O.Reg R2; O.Reg R3; O.Reg R4 ])
           "4605", (ADDU, [ O.Reg R2; O.Reg R3; O.Reg R4 ])
           "3a25", (SLL, [ O.Reg R2; O.Reg R3; O.Shift 5UL ])
           "3b25", (SRL, [ O.Reg R2; O.Reg R3; O.Shift 5UL ]) ]

  /// <summary>
  /// The forms that stand for an instruction MIPS64 writes another way.
  ///
  /// MOVE16 is an OR against the zero register and LI16 an ADDIU from it,
  /// which is what the older encoding has always written, so that is the
  /// instruction rather than a name for one.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] The moves decode as what they are``() =
    test [ "090d", (OR, [ O.Reg R8; O.Reg R9; O.Reg R0 ])
           "07ed", (ADDIU, [ O.Reg R2; O.Reg R0; O.Imm 7UL ])
           "7fed", (ADDIU, [ O.Reg R2; O.Reg R0; O.Imm 0xFFFFFFFFFFFFFFFFUL ]) ]

  /// <summary>
  /// The loads and stores, whose offset is scaled by the width of the access
  /// and whose store register field reaches the zero register where the load
  /// one reaches $16.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] The memory forms decode``() =
    test [ "3369", (LW, [ O.Reg R2; O.Mem(R3, 12L, 32<rt>) ])
           "33e9", (SW, [ O.Reg R2; O.Mem(R3, 12L, 32<rt>) ])
           "3309", (LBU, [ O.Reg R2; O.Mem(R3, 3L, 8<rt>) ])
           "3389", (SB, [ O.Reg R2; O.Mem(R3, 3L, 8<rt>) ])
           "3188", (SB, [ O.Reg R0; O.Mem(R3, 1L, 8<rt>) ])
           "3329", (LHU, [ O.Reg R2; O.Mem(R3, 6L, 16<rt>) ])
           "33a9", (SH, [ O.Reg R2; O.Mem(R3, 6L, 16<rt>) ])
           "4448", (LW, [ O.Reg R2; O.Mem(R29, 16L, 32<rt>) ])
           "44c8", (SW, [ O.Reg R2; O.Mem(R29, 16L, 32<rt>) ])
           "0265", (LW, [ O.Reg R2; O.Mem(R28, 8L, 32<rt>) ]) ]

  /// <summary>
  /// The immediate forms, none of whose fields is the number it stands for.
  ///
  /// ADDIUSP's is a rotation, so 508 means -4 rather than 508 or -4 read as
  /// nine bits; ADDIUR2's selects one of eight values, seven of them small
  /// multiples of four and the last minus one; ANDI16's selects one of the
  /// sixteen masks a compiler actually emits.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] The immediate forms decode``() =
    test [ "342d", (ANDI, [ O.Reg R2; O.Reg R3; O.Imm 4UL ])
           "f94f", (ADDIU, [ O.Reg R29
                             O.Reg R29
                             O.Imm 0xFFFFFFFFFFFFFFF0UL ])
           "464c", (ADDIU, [ O.Reg R2; O.Reg R2; O.Imm 3UL ])
           "326d", (ADDIU, [ O.Reg R2; O.Reg R3; O.Imm 4UL ])
           "056d", (ADDIU, [ O.Reg R2; O.Reg R29; O.Imm 8UL ]) ]

  /// <summary>
  /// The 16-bit branches, whose offset counts halfwords from the instruction
  /// that follows rather than words.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] The branches decode``() =
    test [ "00cc", (B, [ O.Addr(Relative 2L) ])
           "008d", (BEQ, [ O.Reg R2; O.Reg R0; O.Addr(Relative 2L) ])
           "00ad", (BNE, [ O.Reg R2; O.Reg R0; O.Addr(Relative 2L) ]) ]

  /// <summary>
  /// POOL16C, whose minor opcode is the top of what the major leaves and
  /// grows downwards as the instruction needs fewer operand bits.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] POOL16C decodes``() =
    test [ "1344", (NOR, [ O.Reg R2; O.Reg R3; O.Reg R0 ])
           "5344", (XOR, [ O.Reg R2; O.Reg R2; O.Reg R3 ])
           "9344", (AND, [ O.Reg R2; O.Reg R2; O.Reg R3 ])
           "d344", (OR, [ O.Reg R2; O.Reg R2; O.Reg R3 ])
           "8545", (JR, [ O.Reg R5 ])
           "a545", (JRC, [ O.Reg R5 ])
           "c545", (JALR, [ O.Reg R5 ])
           "e545", (JALRS, [ O.Reg R5 ])
           "0546", (MFHI, [ O.Reg R5 ])
           "4546", (MFLO, [ O.Reg R5 ])
           "8046", (BREAK, [ O.Imm 0UL ])
           "8546", (BREAK, [ O.Imm 5UL ])
           "c746", (SDBBP, [ O.Imm 7UL ])
           "0447", (JRADDIUSP, [ O.Imm 16UL ])
           "1f47", (JRADDIUSP, [ O.Imm 124UL ]) ]

  /// <summary>
  /// The load and store multiples, whose two-bit field says how many of the
  /// callee-saved registers the set holds. The return address is always the
  /// last of them, and the offset counts words from the stack pointer.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] The multiples decode``() =
    let sp off = O.Mem(R29, off, 32<rt>)
    test [ "0145", (LWM, [ O.List [ R16; R31 ]; sp 4L ])
           "1045", (LWM, [ O.List [ R16; R17; R31 ]; sp 0L ])
           "2245", (LWM, [ O.List [ R16; R17; R18; R31 ]; sp 8L ])
           "3345", (LWM, [ O.List [ R16; R17; R18; R19; R31 ]; sp 12L ])
           "5045", (SWM, [ O.List [ R16; R17; R31 ]; sp 0L ]) ]

  /// <summary>
  /// The last row of the 32-bit forms' register list, which is the one that
  /// does not continue the run.
  ///
  /// MD00594 gives 01001 as "GPR[16] ... GPR[23], GPR[30]". The count reaches
  /// eight and then the FRAME POINTER joins it, $24 not being callee-saved --
  /// so a decoder that reads the field as a count alone stops one short and
  /// refuses the prologue of every function that keeps a frame pointer.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] The longest register list decodes``() =
    let saved = [ R16; R17; R18; R19; R20; R21; R22; R23 ]
    test [ "3d214050", (LWM, [ O.List(saved @ [ R30 ])
                               O.Mem(R29, 64L, 32<rt>) ])
           "3d234050", (LWM, [ O.List(saved @ [ R30; R31 ])
                               O.Mem(R29, 64L, 32<rt>) ])
           "3d2340d0", (SWM, [ O.List(saved @ [ R30; R31 ])
                               O.Mem(R29, 64L, 32<rt>) ]) ]

  /// <summary>
  /// MOVEP, whose three fields are three different register sets: one of
  /// eight destination PAIRS, and two sources out of a set that reaches the
  /// zero register where the ordinary three-bit set reaches $4 to $7.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] MOVEP decodes``() =
    test [ "3484", (MOVEP, [ O.Reg R5; O.Reg R6; O.Reg R2; O.Reg R3 ])
           "b484", (MOVEP, [ O.Reg R5; O.Reg R7; O.Reg R2; O.Reg R3 ])
           "3485", (MOVEP, [ O.Reg R6; O.Reg R7; O.Reg R2; O.Reg R3 ])
           "b487", (MOVEP, [ O.Reg R4; O.Reg R7; O.Reg R2; O.Reg R3 ])
           "3084", (MOVEP, [ O.Reg R5; O.Reg R6; O.Reg R0; O.Reg R3 ])
           "3884", (MOVEP, [ O.Reg R5; O.Reg R6; O.Reg R16; O.Reg R3 ])
           "0484", (MOVEP, [ O.Reg R5; O.Reg R6; O.Reg R2; O.Reg R0 ]) ]

  /// <summary>
  /// The 32-bit encodings, every one of them assembled rather than read off
  /// a page.
  ///
  /// What a row pins is the whole chain a word goes through: the major
  /// opcode, the pool it names, and inside the pool a minor opcode that may
  /// be read in as many as three steps. The floating-point format is checked
  /// with the opcode because it is not one field -- it sits in a different
  /// place depending on which member is being read -- so an arm that got it
  /// from the wrong bits would still name the right instruction.
  ///
  /// The coprocessor 2 encodings are absent on purpose: this front end does
  /// not decode them in the older encoding either.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] The 32-bit encodings decode``() =
    let cases =
      [ "4b010018", SLL, None
        "4b014018", SRL, None
        "4b018018", SRA, None
        "4b01c018", ROTR, None
        "6c011050", SLLV, None
        "6c015050", SRLV, None
        "6c019050", SRAV, None
        "6c01d050", ROTRV, None
        "8b011850", MOVN, None
        "8b015850", MOVZ, None
        "8b011051", ADD, None
        "8b015051", ADDU, None
        "8b019051", SUB, None
        "8b01d051", SUBU, None
        "8b011052", MUL, None
        "8b015052", AND, None
        "8b019052", OR, None
        "8b01d052", NOR, None
        "8b011053", XOR, None
        "8b015053", SLT, None
        "8b019053", SLTU, None
        "6c011851", LWXS, None
        "4b01cc30", INS, None
        "4b01ec18", EXT, None
        "6a013c00", TEQ, None
        "6a013c02", TGE, None
        "6a013c04", TGEU, None
        "6a013c08", TLT, None
        "6a013c0a", TLTU, None
        "6a013c0c", TNE, None
        "4b01fc00", MFC0, None
        "4b01fc02", MTC0, None
        "4b013c0f", JALR, None
        "4b013c1f", JALRHB, None
        "4b013c2b", SEB, None
        "4b013c3b", SEH, None
        "4b013c4b", CLO, None
        "4b013c5b", CLZ, None
        "4b013c6b", RDHWR, None
        "4b013c7b", WSBH, None
        "6a013c8b", MULT, None
        "6a013c9b", MULTU, None
        "6a013cab", DIV, None
        "6a013cbb", DIVU, None
        "6a013ccb", MADD, None
        "6a013cdb", MADDU, None
        "6a013ceb", MSUB, None
        "6a013cfb", MSUBU, None
        "00007c03", TLBP, None
        "00007c13", TLBR, None
        "00007c23", TLBWI, None
        "00007c33", TLBWR, None
        "0a007c2d", MTHI, None
        "0a007c3d", MTLO, None
        "0a007c47", DI, None
        "0a007c57", EI, None
        "03007c6b", SYNC, None
        "07007c8b", SYSCALL, None
        "00007c93", WAIT, None
        "00007ce3", DERET, None
        "00007cf3", ERET, None
        "4b017ce1", RDPGPR, None
        "4b017cf1", WRPGPR, None
        "4b210810", LWP, None
        "4b210840", LDP, None
        "4b220850", LWM, None
        "6b200860", CACHE, None
        "4b220870", LDM, None
        "4b210890", SWP, None
        "4b2108c0", SDP, None
        "4b2208d0", SWM, None
        "4b2208f0", SDM, None
        "4b610800", LWL, None
        "4b610810", LWR, None
        "6b600820", PREF, None
        "4b610830", LL, None
        "4b610840", LDL, None
        "4b610850", LDR, None
        "4b610870", LLD, None
        "4b610880", SWL, None
        "4b610890", SWR, None
        "4b6108b0", SC, None
        "4b6108c0", SDL, None
        "4b6108d0", SDR, None
        "4b6108e0", LWU, None
        "4b6108f0", SCD, None
        "4b610860", LBUE, None
        "4b610862", LHUE, None
        "4b610864", LWLE, None
        "4b610866", LWRE, None
        "4b610868", LBE, None
        "4b61086a", LHE, None
        "4b61086c", LLE, None
        "4b61086e", LWE, None
        "4b6108a0", SWLE, None
        "4b6108a2", SWRE, None
        "6b6008a4", PREFE, None
        "6b6008a6", CACHEE, None
        "4b6108a8", SBE, None
        "4b6108aa", SHE, None
        "4b6108ac", SCE, None
        "4b6108ae", SWE, None
        "0a400000", BLTZ, None
        "2a400000", BLTZAL, None
        "4a400000", BGEZ, None
        "6a400000", BGEZAL, None
        "8a400000", BLEZ, None
        "aa400000", BNEZC, None
        "ca400000", BGTZ, None
        "ea400000", BEQZC, None
        "0a412301", TLTI, None
        "2a412301", TGEI, None
        "4a412301", TLTIU, None
        "6a412301", TGEIU, None
        "8a412301", TNEI, None
        "aa412301", LUI, None
        "ca412301", TEQI, None
        "0a420800", SYNCI, None
        "2a420000", BLTZALS, None
        "6a420000", BGEZALS, None
        "88430000", BC1F, None
        "a8430000", BC1T, None
        "4b590018", DSLL, None
        "4b590818", DSLL32, None
        "4b594018", DSRL, None
        "4b594818", DSRL32, None
        "4b598018", DSRA, None
        "4b598818", DSRA32, None
        "4b59c018", DROTR, None
        "4b59c818", DROTR32, None
        "6c591050", DSLLV, None
        "6c595050", DSRLV, None
        "6c599050", DSRAV, None
        "6c59d050", DROTRV, None
        "8b591051", DADD, None
        "8b595051", DADDU, None
        "8b599051", DSUB, None
        "8b59d051", DSUBU, None
        "4b593c4b", DCLO, None
        "4b593c5b", DCLZ, None
        "6a593c8b", DMULT, None
        "6a593c9b", DMULTU, None
        "6a593cab", DDIV, None
        "6a593cbb", DDIVU, None
        "4b59fc00", DMFC0, None
        "4b59fc02", DMTC0, None
        "4b593c7b", DSBH, None
        "4b593cfb", DSHD, None
        "4b59ec18", DEXT, None
        "4b59cc30", DINS, None
        "06553020", ADD, Some Fmt.S
        "06553021", ADD, Some Fmt.D
        "06557020", SUB, Some Fmt.S
        "0655b020", MUL, Some Fmt.S
        "0655f020", DIV, Some Fmt.S
        "86547b03", ABS, Some Fmt.S
        "86547b0b", NEG, Some Fmt.S
        "86543b0a", SQRT, Some Fmt.S
        "86547b00", MOV, Some Fmt.S
        "86547b13", CVTD, Some Fmt.S
        "86547b1b", CVTS, Some Fmt.D
        "86543b09", CVTW, Some Fmt.S
        "86547b3b", CVTS, Some Fmt.W
        "86543b01", CVTL, Some Fmt.S
        "86547b53", CVTD, Some Fmt.L
        "86543b2b", TRUNCW, Some Fmt.S
        "86543b23", TRUNCL, Some Fmt.S
        "86543b1b", CEILW, Some Fmt.S
        "86543b0b", FLOORW, Some Fmt.S
        "86543b3b", ROUNDW, Some Fmt.S
        "c454bc40", C, Some Fmt.S
        "c4543c47", C, Some Fmt.D
        "44553b20", MFC1, None
        "44553b28", MTC1, None
        "44553b24", DMFC1, None
        "44553b2c", DMTC1, None
        "44553b30", MFHC1, None
        "44553b38", MTHC1, None
        "44553b10", CFC1, None
        "44553b18", CTC1, None
        "4b557b41", MOVF, None
        "4b557b49", MOVT, None
        "46553820", MOVN, Some Fmt.S
        "46557820", MOVZ, Some Fmt.S
        "86542040", MOVF, Some Fmt.S
        "48558121", MADD, Some Fmt.S
        "4855a121", MSUB, Some Fmt.S
        "48558221", NMADD, Some Fmt.S
        "4855a221", NMSUB, Some Fmt.S
        "4b554820", LWXC1, None
        "4b558820", SWXC1, None
        "4b55c820", LDXC1, None
        "4b550821", SDXC1, None
        "86543b12", RECIP, Some Fmt.S
        "86543b02", RSQRT, Some Fmt.S
        "06553022", ADD, Some Fmt.PS
        "06557022", SUB, Some Fmt.PS
        "0655b022", MUL, Some Fmt.PS
        "06557021", SUB, Some Fmt.D
        "0655b021", MUL, Some Fmt.D
        "0655f021", DIV, Some Fmt.D
        "46553821", MOVN, Some Fmt.D
        "46557821", MOVZ, Some Fmt.D
        "46553822", MOVN, Some Fmt.PS
        "86546040", MOVT, Some Fmt.S
        "86542042", MOVF, Some Fmt.D
        "86546042", MOVT, Some Fmt.D
        "86547b23", ABS, Some Fmt.D
        "86547b2b", NEG, Some Fmt.D
        "86543b4a", SQRT, Some Fmt.D
        "86547b20", MOV, Some Fmt.D
        "86547b43", ABS, Some Fmt.PS
        "86547b40", MOV, Some Fmt.PS
        "86547b4b", NEG, Some Fmt.PS
        "86543b52", RECIP, Some Fmt.D
        "86543b42", RSQRT, Some Fmt.D
        "86543b49", CVTW, Some Fmt.D
        "86543b41", CVTL, Some Fmt.D
        "86547b5b", CVTS, Some Fmt.L
        "86547b33", CVTD, Some Fmt.W
        "86543b6b", TRUNCW, Some Fmt.D
        "86543b63", TRUNCL, Some Fmt.D
        "86543b5b", CEILW, Some Fmt.D
        "86543b13", CEILL, Some Fmt.S
        "86543b53", CEILL, Some Fmt.D
        "86543b4b", FLOORW, Some Fmt.D
        "86543b03", FLOORL, Some Fmt.S
        "86543b43", FLOORL, Some Fmt.D
        "86543b7b", ROUNDW, Some Fmt.D
        "86543b33", ROUNDL, Some Fmt.S
        "86543b73", ROUNDL, Some Fmt.D
        "c454bc48", C, Some Fmt.PS
        (* These eight carry the format in the NAME rather than in a
           suffix, so the format they decode to is none: a disassembler
           that answered PS here would write pll.ps.ps. *)
        "06558020", PLLPS, None
        "0655c020", PLUPS, None
        "06550021", PULPS, None
        "06554021", PUUPS, None
        "06558021", CVTPSS, None
        "86543b29", CVTSPU, None
        "86543b21", CVTSPL, None
        "06559922", ALNVPS, None
        "4b554821", LUXC1, None
        "4b558821", SUXC1, None
        "48558921", MADD, Some Fmt.D
        "48559121", MADD, Some Fmt.PS
        "4b55a019", PREFX, None
        "6a950000", BEQ, None
        "6ab50000", BNE, None
        "007a8d04", ADDIUPC, None ]
    for hex, opcode, fmt in cases do
      let bytes = ByteArray.ofHexString hex
      let ins = parser.Parse(System.ReadOnlySpan bytes, 0UL) :?> Instruction
      Assert.AreEqual<Opcode>(opcode, ins.Opcode, hex)
      Assert.AreEqual<FPRFormat option>(fmt, ins.Fmt, hex)
      Assert.AreEqual<uint32>(4u, ins.Length, hex)

  /// <summary>
  /// Where the operands of a 32-bit form are.
  ///
  /// The three wide register fields run rt, rs, rd from the top, which is
  /// the reverse of the older encoding, so every three-register instruction
  /// would name its operands in the wrong order if they were read from the
  /// older places. The rest of these are fields with no counterpart there at
  /// all: a register list, a pair whose second member the encoding does not
  /// name, and a jump index counting halfwords.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] The 32-bit operands decode``() =
    test [ "8b011051", (ADD, [ O.Reg R10; O.Reg R11; O.Reg R12 ])
           "4b010018", (SLL, [ O.Reg R10; O.Reg R11; O.Shift 3UL ])
           "6c011851", (LWXS, [ O.Reg R10; OpMem(R12, Reg R11, 32<rt>) ])
           "4b220850", (LWM, [ O.List [ R16; R17; R31 ]
                               O.Mem(R11, 8L, 32<rt>) ])
           "4b210810", (LWP, [ O.Reg R10
                               O.Reg R11
                               O.Mem(R11, 8L, 32<rt>) ])
           "4b01ec18", (EXT, [ O.Reg R10; O.Reg R11; O.Imm 3UL; O.Imm 4UL ])
           "4b01cc30", (INS, [ O.Reg R10; O.Reg R11; O.Imm 3UL; O.Imm 4UL ])
           "4b59e438", (DEXTM, [ O.Reg R10
                                 O.Reg R11
                                 O.Imm 3UL
                                 O.Imm 40UL ])
           "4b59f430", (DINSU, [ O.Reg R10
                                 O.Reg R11
                                 O.Imm 35UL
                                 O.Imm 4UL ])
           "4b01fc00", (MFC0, [ O.Reg R10; O.Imm 11UL; O.Imm 0UL ])
           "6a950000", (BEQ, [ O.Reg R10; O.Reg R11; O.Addr(Relative 4L) ])
           "0a400000", (BLTZ, [ O.Reg R10; O.Addr(Relative 4L) ])
           "a8430000", (BC1T, [ O.Imm 2UL; O.Addr(Relative 4L) ])
           "09d42c1a", (J, [ O.Addr(Region 0x123458UL) ])
           "04f0168d", (JALX, [ O.Addr(Region 0x123458UL) ])
           "007a8d04", (ADDIUPC, [ O.Reg R4; O.Addr(Relative 0x1234L) ])
           "07007c8b", (SYSCALL, [ O.Imm 7UL ])
           "03007c6b", (SYNC, [ O.Imm 3UL ])
           "0a007c47", (DI, [ O.Reg R10 ])
           "4b610860", (LBUE, [ O.Reg R10; O.Mem(R11, 8L, 8<rt>) ])
           "4b6108ae", (SWE, [ O.Reg R10; O.Mem(R11, 8L, 32<rt>) ])
           "6b200860", (CACHE, [ O.Imm 3UL; O.Mem(R11, 8L, 32<rt>) ])
           "06553021", (ADD, [ O.Reg F4; O.Reg F6; O.Reg F8 ])
           "48558121", (MADD, [ O.Reg F4
                                O.Reg F6
                                O.Reg F8
                                O.Reg F10 ]) ]

  /// <summary>
  /// A floating-point comparison, whose result goes to one of eight
  /// condition codes rather than to a register.
  ///
  /// Which comparison it is lives in four bits of the word rather than in
  /// the opcode, which is why it is checked apart from the operands.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] A comparison names its condition``() =
    let bytes = ByteArray.ofHexString "c4543c47"
    let ins = parser.Parse(System.ReadOnlySpan bytes, 0UL) :?> Instruction
    Assert.AreEqual<Opcode>(C, ins.Opcode)
    Assert.AreEqual<Condition option>(Some Condition.LT, ins.Condition)
    Assert.AreEqual<FPRFormat option>(Some FPRFormat.D, ins.Fmt)
    let oprs = ThreeOperands(O.Imm 2UL, O.Reg F4, O.Reg F6)
    Assert.AreEqual<Operands>(oprs, ins.Operands)

  /// <summary>
  /// The major opcodes Release 6 reassigned.
  ///
  /// Seven of them changed hands outright -- ADDI32 became AUI, JALX32 DAUI,
  /// BEQ32 and BNE32 the two unconditional compact branches, and the three
  /// jumps the compact compare families -- so the same word is two different
  /// instructions in the two releases and a decoder that is not told which
  /// cannot be right for both. Four majors that held nothing before hold a
  /// compact family now.
  ///
  /// None of these can be assembled: binutils refuses microMIPS together
  /// with Release 6, so every word here is built from the field boxes of
  /// revision 6.01 and the rule its own pages give for telling the members
  /// of one compact family apart.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] Release 6 reassigned the majors``() =
    let r6 =
      ISA(Architecture.MIPS,
          Endian.Little,
          WordSize.Bit64,
          int MIPSISAMode.MicroMIPS ||| int MIPSRelease.R6)
    let parser =
      Parser(r6, BinReader.Init Endian.Little) :> IInstructionParsable
    let here = O.Addr(Relative 36L)
    let cases =
      [ "80103412", (LUI, [ O.Reg R4; O.Imm 0x1234UL ])
        "85103412", (AUI, [ O.Reg R4; O.Reg R5; O.Imm 0x1234UL ])
        "85f03412", (DAUI, [ O.Reg R4; O.Reg R5; O.Imm 0x1234UL ])
        "00941000", (BC, [ here ])
        "00b41000", (BALC, [ here ])
        "80c01000", (BLEZALC, [ O.Reg R4; here ])
        "84c01000", (BGEZALC, [ O.Reg R4; here ])
        "85c01000", (BGEUC, [ O.Reg R5; O.Reg R4; here ])
        "80e01000", (BGTZALC, [ O.Reg R4; here ])
        "84e01000", (BLTZALC, [ O.Reg R4; here ])
        "85e01000", (BLTUC, [ O.Reg R5; O.Reg R4; here ])
        "85741000", (BOVC, [ O.Reg R5; O.Reg R4; here ])
        "80741000", (BEQZALC, [ O.Reg R4; here ])
        "83741000", (BEQC, [ O.Reg R3; O.Reg R4; here ])
        "857c1000", (BNVC, [ O.Reg R5; O.Reg R4; here ])
        "807c1000", (BNEZALC, [ O.Reg R4; here ])
        "837c1000", (BNEC, [ O.Reg R3; O.Reg R4; here ])
        "80d41000", (BGTZC, [ O.Reg R4; here ])
        "84d41000", (BLTZC, [ O.Reg R4; here ])
        "85d41000", (BLTC, [ O.Reg R5; O.Reg R4; here ])
        "80f41000", (BLEZC, [ O.Reg R4; here ])
        "84f41000", (BGEZC, [ O.Reg R4; here ])
        "85f41000", (BGEC, [ O.Reg R5; O.Reg R4; here ])
        "80782301", (ADDIUPC, [ O.Reg R4; O.Addr(Relative 0x48CL) ])
        "88782301", (LWPC, [ O.Reg R4; O.Addr(Relative 0x48CL) ])
        "9e783412", (AUIPC, [ O.Reg R4; O.Imm 0x1234UL ])
        "8b010f52", (LSA, [ O.Reg R10
                            O.Reg R11
                            O.Reg R12
                            O.Imm 1UL ]) ]
    for hex, (opcode, oprs) in cases do
      let bytes = ByteArray.ofHexString hex
      let ins = parser.Parse(System.ReadOnlySpan bytes, 0UL) :?> Instruction
      Assert.AreEqual<Opcode>(opcode, ins.Opcode, hex)
      Assert.AreEqual<Operands>(operandsFromArray oprs, ins.Operands, hex)

  /// <summary>
  /// Coprocessor 2, the moves of the upper half of a coprocessor 0 register,
  /// ERETNC, DADDI, and the four shifts of the zero register that are
  /// instructions of their own.
  ///
  /// Every word before Release 6 is the one binutils writes for the source in
  /// it. Two of the microMIPS64 pages give a field the wrong value -- DMTC2's
  /// pool as 000011 and SDC2's major as 110110 -- where the opcode tables and
  /// binutils agree on POOL32Axf (111100) and POOL32B (001000). Release 6
  /// keeps bit 11 of a coprocessor 2 load or store clear, with eleven bits of
  /// offset below it, and moves the branches on a coprocessor 2 condition to
  /// two compact ones on a condition register (MD00594, POOL32I).
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] Coprocessor 2 and the Release 5 additions decode``() =
    let here = O.Addr(Relative 4L)
    test
      [ "43003c4d", (MFC2, [ O.Reg R2; O.Imm 3UL ])
        "43003c7d", (DMTC2, [ O.Reg R2; O.Imm 3UL ])
        "44201000", (LWC2, [ O.Imm 2UL; O.Mem(R4, 16L, 32<rt>) ])
        "4420f08f", (SWC2, [ O.Imm 2UL; O.Mem(R4, -16L, 32<rt>) ])
        "442010a0", (SDC2, [ O.Imm 2UL; O.Mem(R4, 16L, 64<rt>) ])
        "80420000", (BC2F, [ O.Imm 0UL; here ])
        "a8420000", (BC2T, [ O.Imm 2UL; here ])
        "00001a09", (COP2, [ O.Imm 0x123UL ])
        "4300f428", (MFHC0, [ O.Reg R2; O.Imm 3UL; O.Imm 5UL ])
        "4300f42a", (MTHC0, [ O.Reg R2; O.Imm 3UL; O.Imm 5UL ])
        "01007cf3", (ERETNC, [])
        "4358dcfe", (DADDI, [ O.Reg R2; O.Reg R3; O.Imm 0xfffffffffffffffbUL ])
        "00000000", (NOP, [])
        "00000008", (SSNOP, [])
        "00000018", (EHB, [])
        "00000028", (PAUSE, []) ]
    let r6 =
      ISA(Architecture.MIPS,
          Endian.Little,
          WordSize.Bit64,
          int MIPSISAMode.MicroMIPS ||| int MIPSRelease.R6)
    let r6Parser =
      Parser(r6, BinReader.Init Endian.Little) :> IInstructionParsable
    let parseR6 hex =
      let bytes = ByteArray.ofHexString hex
      r6Parser.Parse(System.ReadOnlySpan bytes, 0UL) :?> Instruction
    let lwc2 = parseR6 "4420f007"
    let lwc2Oprs = TwoOperands(O.Imm 2UL, O.Mem(R4, -16L, 32<rt>))
    Assert.AreEqual<Opcode>(LWC2, lwc2.Opcode)
    Assert.AreEqual<Operands>(lwc2Oprs, lwc2.Operands)
    let bc2eqzc = parseR6 "45410300"
    let bc2eqzcOprs = TwoOperands(O.Imm 5UL, O.Addr(Relative 10L))
    Assert.AreEqual<Opcode>(BC2EQZC, bc2eqzc.Opcode)
    Assert.AreEqual<Operands>(bc2eqzcOprs, bc2eqzc.Operands)
    for hex in [ "4420f00f"; "80420000"; "4358dcfe" ] do
      Assert.ThrowsExactly<ParsingFailureException>((fun () ->
        parseR6 hex |> ignore), hex) |> ignore

  /// An INS whose field ends before it begins is refused as it is in the
  /// older encoding (MD00087 INS: UNPREDICTABLE, which the reference takes as
  /// a Reserved Instruction). The decoder read its size as a negative number
  /// widened to sixty-four bits, which the check on where the field ends
  /// wrapped back under thirty-two, and the lifter then failed on it.
  [<TestMethod>]
  member _.``[microMIPS] An INS that ends before it begins is refused``() =
    (* INS zero, zero, with lsb 2 and msb 0 *)
    let bytes = ByteArray.ofHexString "00008c00"
    Assert.ThrowsExactly<ParsingFailureException>(fun () ->
      parser.Parse(System.ReadOnlySpan bytes, 0UL) |> ignore) |> ignore

  /// <summary>
  /// Release 6 decodes what its book adds, and LSA and DLSA where the book
  /// puts them.
  ///
  /// Every word below is assembled from MD00582 (microMIPS32, revision 6.04)
  /// and, for the doubleword forms, MD00594 (microMIPS64, revision 6.01) --
  /// no assembler or emulator reads microMIPS Release 6, so the books are
  /// the only witness. LSA is POOL32A's 001111 with its shift in bits 10..9
  /// and DLSA POOL32S's grid at row 100, where this decoder had read both as
  /// the older encoding's SPECIAL forms. Where the two books disagree the
  /// newer revision is followed: LLWP and SCWP where 6.01 has LLX and SCX,
  /// and RDHWR's select form in POOL32A beside the older place, which 6.01
  /// keeps and which is still read. POOL32C at Release 6 has no unaligned
  /// loads and stores, and its LL, SC and PREF take nine bits of offset.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] Release 6 decodes what its book adds``() =
    let parserAt release =
      let flags = int MIPSISAMode.MicroMIPS ||| int release
      let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64, flags)
      Parser(isa, BinReader.Init Endian.Big) :> IInstructionParsable
    let r6, pre = parserAt MIPSRelease.R6, parserAt MIPSRelease.PreR6
    let parse (p: IInstructionParsable) hex =
      let bytes = ByteArray.ofHexString hex
      p.Parse(System.ReadOnlySpan bytes, 0UL) :?> Instruction
    let place = O.Addr(Relative 10L)
    let pair = [ O.Reg R2; O.Reg R3; O.Mem(R4, 0L, 32<rt>) ]
    let cases =
      [ "0083120f", (LSA, None, [ O.Reg R2; O.Reg R3; O.Reg R4; O.Imm 1UL ])
        "58831300", (DLSA, None, [ O.Reg R2; O.Reg R3; O.Reg R4; O.Imm 1UL ])
        "0083141f", (ALIGN, None, [ O.Reg R2; O.Reg R3; O.Reg R4; O.Imm 2UL ])
        "5883151c", (DALIGN, None, [ O.Reg R2; O.Reg R3; O.Reg R4; O.Imm 5UL ])
        "00048d3f", (SIGRIE, None, [ O.Imm 0x1234UL ])
        "00831140", (SELEQZ, None, [ O.Reg R2; O.Reg R3; O.Reg R4 ])
        "00831180", (SELNEZ, None, [ O.Reg R2; O.Reg R3; O.Reg R4 ])
        "005d19c0", (RDHWR, None, [ O.Reg R2; O.Reg R29; O.Imm 3UL ])
        "00620b3c", (BITSWAP, None, [ O.Reg R2; O.Reg R3 ])
        "58620b3c", (DBITSWAP, None, [ O.Reg R2; O.Reg R3 ])
        "0002197c", (DVP, None, [ O.Reg R2 ])
        "0002397c", (EVP, None, [ O.Reg R2 ])
        "0000437c", (TLBINV, None, [])
        "0000537c", (TLBINVF, None, [])
        "41020003", (BC1EQZC, None, [ O.Reg F2; place ])
        "41220003", (BC1NEZC, None, [ O.Reg F2; place ])
        "54620220", (RINT, Some Fmt.D, [ O.Reg F2; O.Reg F3 ])
        "54620060", (CLASS, Some Fmt.S, [ O.Reg F2; O.Reg F3 ])
        "548312b8", (SEL, Some Fmt.D, [ O.Reg F2; O.Reg F3; O.Reg F4 ])
        "54831038", (SELEQZ, Some Fmt.S, [ O.Reg F2; O.Reg F3; O.Reg F4 ])
        "54831078", (SELNEQZ, Some Fmt.S, [ O.Reg F2; O.Reg F3; O.Reg F4 ])
        "548311b8", (MADDF, Some Fmt.S, [ O.Reg F2; O.Reg F3; O.Reg F4 ])
        "548313f8", (MSUBF, Some Fmt.D, [ O.Reg F2; O.Reg F3; O.Reg F4 ])
        "54831003", (MIN, Some Fmt.S, [ O.Reg F2; O.Reg F3; O.Reg F4 ])
        "5483120b", (MAX, Some Fmt.D, [ O.Reg F2; O.Reg F3; O.Reg F4 ])
        "54831023", (MINA, Some Fmt.S, [ O.Reg F2; O.Reg F3; O.Reg F4 ])
        "5483122b", (MAXA, Some Fmt.D, [ O.Reg F2; O.Reg F3; O.Reg F4 ])
        "54831085", (CMP, Some Fmt.S, [ O.Reg F2; O.Reg F3; O.Reg F4 ])
        "604431f8", (LL, None, [ O.Reg R2; O.Mem(R4, -8L, 32<rt>) ])
        "6044b008", (SC, None, [ O.Reg R2; O.Mem(R4, 8L, 32<rt>) ])
        "60242008", (PREF, None, [ O.Imm 1UL; O.Mem(R4, 8L, 32<rt>) ])
        "60447008", (LLD, None, [ O.Reg R2; O.Mem(R4, 8L, 64<rt>) ])
        "6044f008", (SCD, None, [ O.Reg R2; O.Mem(R4, 8L, 64<rt>) ])
        "60441030", (LLWP, None, pair)
        "60449030", (SCWP, None, pair)
        "60446430", (LLWPE, None, pair)
        "6044a030", (SCWPE, None, pair) ]
    for hex, (opcode, fmt, oprs) in cases do
      let ins = parse r6 hex
      Assert.AreEqual<Opcode>(opcode, ins.Opcode, hex)
      Assert.AreEqual<Fmt option>(fmt, ins.Fmt, hex)
      Assert.AreEqual<Operands>(operandsFromArray oprs, ins.Operands, hex)
    let cmp = parse r6 "54831115"
    Assert.AreEqual<Condition option>(Some Condition.OLT, cmp.Condition)
    Assert.AreEqual<Fmt option>(Some Fmt.D, cmp.Fmt)
    let removed =
      [ "60440000" (* LWL *)
        "60444000" (* LDL *)
        "60449008" (* SCWP with its low bits set *)
        "60446600" (* LWRE *)
        "6044a200" (* SWRE *)
        "60443200" (* LL with a bit of its zero field set *) ]
    for hex in removed do
      Assert.ThrowsExactly<ParsingFailureException>((fun () ->
        parse r6 hex |> ignore), hex) |> ignore
    (* and what Release 6 added is not an instruction before it *)
    for hex in [ "0083120f"; "00048d3f"; "54831085" ] do
      Assert.ThrowsExactly<ParsingFailureException>((fun () ->
        parse pre hex |> ignore), hex) |> ignore
    Assert.AreEqual<Opcode>(LWL, (parse pre "60440000").Opcode)

  /// <summary>
  /// MUL, MUH, MULU and MUHU, which write one register where the older
  /// multiplies write HI and LO (MD00582 revision 6.04, p.256): POOL32A's
  /// column 011, rows 0000 to 0011. The older MUL's place, row 1000 of
  /// column 010, is reserved at Release 6 (Table 7.4).
  ///
  /// binutils refuses microMIPS at Release 6 and QEMU runs none of it, so
  /// what each word here and below is checked against is the manual and
  /// nothing else: the encodings match the manual.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] R6 MUL MUH MULU MUHU decode (32r6 p.256)``() =
    let oprs = [ O.Reg R2; O.Reg R3; O.Reg R4 ]
    testR6 WordSize.Bit32
      [ "00831018", (MUL, oprs)
        "00831058", (MUH, oprs)
        "00831098", (MULU, oprs)
        "008310d8", (MUHU, oprs) ]
    refusesAt MIPSRelease.R6 WordSize.Bit32 "00831210"
    let older = parseAt MIPSRelease.PreR6 WordSize.Bit32 "00831210"
    Assert.AreEqual<Opcode>(MUL, older.Opcode)

  /// <summary>
  /// DIV, MOD, DIVU and MODU (MD00582 revision 6.04, p.182): rows 0100 to
  /// 0111 of the same column. Row 0100 is where LWXS sits before Release 6,
  /// and neither Release 6 book has LWXS, so the word is DIV at Release 6
  /// and LWXS only before it. The encodings match the manual.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] R6 DIV MOD DIVU MODU decode (32r6 p.182)``() =
    let oprs = [ O.Reg R2; O.Reg R3; O.Reg R4 ]
    testR6 WordSize.Bit32
      [ "00831118", (DIV, oprs)
        "00831158", (MOD, oprs)
        "00831198", (DIVU, oprs)
        "008311d8", (MODU, oprs) ]
    let older = parseAt MIPSRelease.PreR6 WordSize.Bit32 "00831118"
    Assert.AreEqual<Opcode>(LWXS, older.Opcode)

  /// <summary>
  /// JALRC and JALRC.HB (MD00582 revision 6.04, pp.202 and 204), which take
  /// the places POOL32Axf gives JALR and JALR.HB before Release 6. They are
  /// not the older jumps under new names: a compact jump has no delay slot
  /// and links the address right after itself. The encodings match the
  /// manual.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] R6 JALRC and JALRC.HB decode (32r6 pp.202 204)``() =
    let oprs = [ O.Reg R31; O.Reg R5 ]
    testR6 WordSize.Bit32
      [ "03e50f3c", (JALRC, oprs)
        "03e51f3c", (JALRCHB, oprs) ]
    let older = parseAt MIPSRelease.PreR6 WordSize.Bit32 "03e51f3c"
    Assert.AreEqual<Opcode>(JALRHB, older.Opcode)

  /// <summary>
  /// DAHI and DATI (MD00594 revision 6.01, p.134), POOL32I's minors 10001
  /// and 10000, with the sixteen-bit immediate unsigned as the older
  /// encoding's DAHI and DATI hold it. 10000 is where SYNCI sits before
  /// Release 6. Both are microMIPS64 instructions, so a 32-bit decoder
  /// refuses them; the microMIPS32 book leaves both minors reserved (Table
  /// 7.13). The encodings match the manual.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] R6 DAHI and DATI decode (64r6 p.134)``() =
    testR6 WordSize.Bit64
      [ "4223f234", (DAHI, [ O.Reg R3; O.Imm 0xf234UL ])
        "4203f234", (DATI, [ O.Reg R3; O.Imm 0xf234UL ]) ]
    for hex in [ "4223f234"; "4203f234" ] do
      refusesAt MIPSRelease.R6 WordSize.Bit32 hex

  /// <summary>
  /// DDIV, DMOD, DDIVU and DMODU (MD00594 revision 6.01, p.210): POOL32S's
  /// column 011, rows 0100 to 0111, where DIV and its family sit in POOL32A.
  /// The page labels the three register fields of these four rd, rs, rt from
  /// the top, against rt, rs, rd for DIV on the same page and for DMUL on
  /// p.312; rd is bits 15..11 here as everywhere else in the pool. A 32-bit
  /// decoder refuses them. The encodings match the manual.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] R6 DDIV DMOD DDIVU DMODU decode (64r6 p.210)``() =
    let oprs = [ O.Reg R2; O.Reg R3; O.Reg R4 ]
    let cases =
      [ "58831118", (DDIV, oprs)
        "58831158", (DMOD, oprs)
        "58831198", (DDIVU, oprs)
        "588311d8", (DMODU, oprs) ]
    testR6 WordSize.Bit64 cases
    for hex, _ in cases do
      refusesAt MIPSRelease.R6 WordSize.Bit32 hex

  /// <summary>
  /// DMUL, DMUH, DMULU and DMUHU (MD00594 revision 6.01, p.312): POOL32S's
  /// column 011, rows 0000 to 0011. A 32-bit decoder refuses them. The
  /// encodings match the manual.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] R6 DMUL DMUH DMULU DMUHU decode (64r6 p.312)``() =
    let oprs = [ O.Reg R2; O.Reg R3; O.Reg R4 ]
    let cases =
      [ "58831018", (DMUL, oprs)
        "58831058", (DMUH, oprs)
        "58831098", (DMULU, oprs)
        "588310d8", (DMUHU, oprs) ]
    testR6 WordSize.Bit64 cases
    for hex, _ in cases do
      refusesAt MIPSRelease.R6 WordSize.Bit32 hex

  /// <summary>
  /// SYNCI at Release 6 is POOL32I's minor 01100 (MD00582 revision 6.04,
  /// p.338; MD00594 revision 6.01, p.404), at both word sizes. Its older
  /// place, 10000, is reserved in the microMIPS32 book and DATI in the
  /// microMIPS64 one, so it is SYNCI at neither. The encodings match the
  /// manual.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] R6 SYNCI moved to 01100 (32r6 p.338 64r6 p.404)``() =
    let synci = [ O.Mem(R4, 8L, 32<rt>) ]
    testR6 WordSize.Bit32 [ "41840008", (SYNCI, synci) ]
    testR6 WordSize.Bit64 [ "41840008", (SYNCI, synci) ]
    refusesAt MIPSRelease.R6 WordSize.Bit32 "42040008"
    testR6 WordSize.Bit64 [ "42040008", (DATI, [ O.Reg R4; O.Imm 8UL ]) ]
    let older = parseAt MIPSRelease.PreR6 WordSize.Bit32 "42040008"
    Assert.AreEqual<Opcode>(SYNCI, older.Opcode)

  /// <summary>
  /// ADDU16 and SUBU16 at Release 6 (MD00582 revision 6.04, pp.71 and 105;
  /// MD00594 revision 6.01, pp.72 and 113). Both books draw rs in bits 9..7,
  /// rt in 6..4 and rd in 3..1, and say that each "has been recoded for
  /// Release 6". Before it the destination is the topmost field, as binutils
  /// writes it, so the same halfword names different registers in the two
  /// releases. The encodings match the manual.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] R6 ADDU16 SUBU16 put rd last (32r6 p.71 p.105)``() =
    let oprs = [ O.Reg R2; O.Reg R3; O.Reg R4 ]
    for wordSize in [ WordSize.Bit32; WordSize.Bit64 ] do
      testR6 wordSize [ "05c4", (ADDU, oprs); "05c5", (SUBU, oprs) ]
    let older = parseAt MIPSRelease.PreR6 WordSize.Bit32 "05c5"
    let olderOprs = ThreeOperands(O.Reg R3, O.Reg R2, O.Reg R4)
    Assert.AreEqual<Operands>(olderOprs, older.Operands)

  /// <summary>
  /// CACHE at Release 6 (MD00582 revision 6.04, p.144) keeps nine bits of
  /// offset below three clear ones -- "The 9-bit offset is sign-extended" --
  /// where the releases before it keep twelve. The decoder read twelve at
  /// Release 6 as well, so an offset with its sign bit set came out as a
  /// large positive one. The encodings match the manual.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] R6 CACHE takes a nine-bit offset (32r6 p.144)``() =
    let oprs = [ O.Imm 0x15UL; O.Mem(R5, -16L, 32<rt>) ]
    testR6 WordSize.Bit64 [ "22a561f0", (CACHE, oprs) ]
    refusesAt MIPSRelease.R6 WordSize.Bit64 "22a563f0"
    let older = parseAt MIPSRelease.PreR6 WordSize.Bit64 "22a561f0"
    let olderOprs = TwoOperands(O.Imm 0x15UL, O.Mem(R5, 496L, 32<rt>))
    Assert.AreEqual<Operands>(olderOprs, older.Operands)

  /// <summary>
  /// DAUI's rs "cannot be r0, the zero register. The encoding may be used
  /// for other instructions or must signal a Reserved Instruction Exception"
  /// (MD00594 revision 6.01, p.135), and no other instruction is given it, so
  /// the word is refused. The decoder read it as DAUI adding to the zero
  /// register. The encodings match the manual.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] R6 DAUI refuses a zero rs (64r6 p.135)``() =
    let oprs = [ O.Reg R6; O.Reg R15; O.Imm 0x8002UL ]
    testR6 WordSize.Bit64 [ "f0cf8002", (DAUI, oprs) ]
    refusesAt MIPSRelease.R6 WordSize.Bit64 "f0c08002"

  /// LDP, LDM, SDP and SDM move doublewords, and microMIPS64 alone has them
  /// (microMIPS64 Release 5, POOL32B): a 32-bit decoder refuses them, as it
  /// refuses LD.
  [<TestMethod>]
  member _.``[microMIPS] The doubleword pairs and lists are 64-bit only``() =
    let parserOf wordSize =
      let isa =
        ISA(Architecture.MIPS, Endian.Big, wordSize, int MIPSISAMode.MicroMIPS)
      Parser(isa, BinReader.Init Endian.Big) :> IInstructionParsable
    let p32, p64 = parserOf WordSize.Bit32, parserOf WordSize.Bit64
    let words =
      [ "200f4aaf", LDP
        "20387c1c", LDM
        "2009c48e", SDP
        "203af536", SDM ]
    for hex, opcode in words do
      let bytes = ByteArray.ofHexString hex
      let ins = p64.Parse(System.ReadOnlySpan bytes, 0UL) :?> Instruction
      Assert.AreEqual<Opcode>(opcode, ins.Opcode, hex)
      Assert.ThrowsExactly<ParsingFailureException>(fun () ->
        p32.Parse(System.ReadOnlySpan bytes, 0UL) |> ignore
      ) |> ignore

  /// <summary>
  /// A word that belongs to one release alone is refused by the other.
  ///
  /// Release 6 removed HI and LO and everything that reads or writes them,
  /// the short-delay-slot calls, the traps that take a written number, and
  /// the floating-point comparisons that answer into a condition code. It
  /// added the scaled address. A decoder that read any of them under the
  /// wrong release would name an instruction the processor does not have.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] A word belonging to one release is refused``() =
    let r6 =
      ISA(Architecture.MIPS,
          Endian.Little,
          WordSize.Bit64,
          int MIPSISAMode.MicroMIPS ||| int MIPSRelease.R6)
    let r6Parser =
      Parser(r6, BinReader.Init Endian.Little) :> IInstructionParsable
    let refuses (p: IInstructionParsable) hex =
      let bytes = ByteArray.ofHexString hex
      Assert.ThrowsExactly<ParsingFailureException>(fun () ->
        p.Parse(System.ReadOnlySpan bytes, 0UL) |> ignore
      ) |> ignore
    for hex in [ "6a013c8b"   (* mult *)
                 "4b013c4f"   (* jalrs *)
                 "ca411c23"   (* teqi *)
                 "c4543c47"   (* c.lt.d *)
                 "4b554820" ] (* lwxc1 *) do
      refuses r6Parser hex
    (* LSA is the other way round: Release 6 brought it in. *)
    refuses parser "8b010f52"

  /// <summary>
  /// POP40 and POP50, which the two manuals had to be read together to
  /// settle.
  ///
  /// Revision 6.01 of the microMIPS64 book gives these two majors on its
  /// JIC and JIALC pages as POP50 = 101000 and POP51 = 101001, and 101001
  /// cannot be a 32-bit major at all -- that row of the opcode map is the
  /// 16-bit one. Revision 6.04 of the microMIPS32 book names them POP40 =
  /// 100000 and POP50 = 101000, which is what both books' own Table 7.2
  /// says, so the numbering on those two pages is what is wrong.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] The indexed jumps share a major with a branch``() =
    let r6 =
      ISA(Architecture.MIPS,
          Endian.Little,
          WordSize.Bit64,
          int MIPSISAMode.MicroMIPS ||| int MIPSRelease.R6)
    let parser =
      Parser(r6, BinReader.Init Endian.Little) :> IInstructionParsable
    let cases =
      [ "04800800", (JIC, [ O.Reg R4; O.Imm 8UL ])
        "80801000", (BEQZC, [ O.Reg R4; O.Addr(Relative 36L) ])
        "04a00800", (JIALC, [ O.Reg R4; O.Imm 8UL ])
        "80a01000", (BNEZC, [ O.Reg R4; O.Addr(Relative 36L) ]) ]
    for hex, (opcode, oprs) in cases do
      let bytes = ByteArray.ofHexString hex
      let ins = parser.Parse(System.ReadOnlySpan bytes, 0UL) :?> Instruction
      Assert.AreEqual<Opcode>(opcode, ins.Opcode, hex)
      Assert.AreEqual<Operands>(operandsFromArray oprs, ins.Operands, hex)

  /// <summary>
  /// JALX says in the jump which encoding it crosses into.
  ///
  /// The processor holds the encoding it is reading in a bit no register
  /// names, so a decoder that followed the target address alone would go on
  /// reading the encoding it was already in. Which way the call crosses is
  /// settled by the side it starts on, and the two sides are two different
  /// parsers, so the same opcode lifts to two different jumps.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] JALX carries the encoding it crosses into``() =
    let kindOf (isa: ISA) (jump: string) (slot: string) =
      let bld = LowUIRBuilder(isa, RegisterFactory isa, LowUIRStream())
      let p = Parser(isa, BinReader.Init isa.Endian)
      let p = p :> IInstructionParsable
      (p.Parse(ByteArray.ofHexString jump, 0UL)).Translate bld |> ignore
      (p.Parse(ByteArray.ofHexString slot, 4UL)).Translate bld
      |> Array.pick (function
        | InterJmp(Kind = kind) -> Some kind
        | _ -> None)
    let word = ISA(Architecture.MIPS, Endian.Little, WordSize.Bit64)
    (* JALX 0x123458 with a NOP after it, in each of the two encodings. The
       two NOPs differ: the older one is a word of zeros and the microMIPS
       one a halfword moving the zero register onto itself. *)
    let fromWord = kindOf word "168d0474" "00000000"
    let fromMicro = kindOf isa "04f0168d" "000c"
    let call = InterJmpKind.IsCall
    Assert.AreEqual<InterJmpKind>(call ||| InterJmpKind.SwitchToMicroMIPS,
                                  fromWord)
    Assert.AreEqual<InterJmpKind>(call ||| InterJmpKind.SwitchToMIPS,
                                  fromMicro)

  /// <summary>
  /// Every halfword either decodes or is refused, and nothing it decodes to
  /// fails to disassemble or to lift.
  ///
  /// What this checks is that the decoder is TOTAL, which the round-trip
  /// sweep beside it does not: a word the decoder cannot read has to say so
  /// with the one exception a caller is promised, not with an index that ran
  /// off the end of a table, and a word it can read has to produce an
  /// instruction the rest of the front end will accept. The sweep starts
  /// from what the decoder decoded and so never sees the words it refused.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] The 16-bit space decodes or is refused``() =
    let builder = LowUIRBuilder(isa, RegisterFactory isa, LowUIRStream())
    let disasm = StringDisasmBuilder(false, null, WordSize.Bit64)
    let mutable decoded = 0
    for h in 0 .. 0xFFFF do
      let bytes = [| byte h; byte (h >>> 8) |]
      let ins =
        try Some(parser.Parse(System.ReadOnlySpan bytes, 0UL))
        with :? ParsingFailureException -> None
      match ins with
      | Some ins when ins.Length = 2u ->
        decoded <- decoded + 1
        ins.Disasm(disasm) |> ignore
        ins.Translate builder |> ignore
      | _ ->
        ()
    (* Three of the eight rows of the major opcode table are the 16-bit
       ones, so 24576 halfwords can be 16-bit at all and the rest are the
       first half of a longer instruction. Most of those three rows is
       occupied; a count far below this would mean an arm had stopped being
       reached rather than that the space had changed. *)
    if decoded <= 20000 then Assert.Fail(string decoded) else ()

  /// <summary>
  /// The same for the 32-bit pools, whose tables are the deepest: a word
  /// there is read in as many as four steps.
  ///
  /// The whole low half is walked for each pool, which covers every minor
  /// opcode and every operand field below bit 16 that any of them reads.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] The 32-bit pools decode or are refused``() =
    let disasm = StringDisasmBuilder(false, null, WordSize.Bit64)
    let majors =
      [ 0b000000u
        0b001000u
        0b010000u
        0b011000u
        0b010101u
        0b010110u ]
    let mutable decoded = 0
    for major in majors do
      let hi = (major <<< 10) ||| (4u <<< 5) ||| 5u
      for lo in 0 .. 0xFFFF do
        let bytes =
          [| byte hi; byte (hi >>> 8); byte lo; byte (lo >>> 8) |]
        let ins =
          try Some(parser.Parse(System.ReadOnlySpan bytes, 0UL))
          with :? ParsingFailureException -> None
        match ins with
        | Some ins ->
          decoded <- decoded + 1
          ins.Disasm(disasm) |> ignore
        | None ->
          ()
    if decoded <= 1000 then Assert.Fail(string decoded) else ()

  /// <summary>
  /// Release 6 recoded POOL16C with the minor opcode at the BOTTOM of the
  /// halfword, the way the 32-bit encodings already had it, so the same
  /// halfword means different instructions in the two releases.
  ///
  /// These cannot be assembled: binutils refuses microMIPS together with
  /// Release 6. They come from the field boxes on the instruction pages of
  /// revision 6.01, which agree with its own Table 7.17 once that table is
  /// read by the minor opcode its columns really hold.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS] Release 6 moved POOL16C's minor opcode``() =
    let isa =
      ISA(Architecture.MIPS,
          Endian.Little,
          WordSize.Bit64,
          int MIPSISAMode.MicroMIPS ||| int MIPSRelease.R6)
    let parser =
      Parser(isa, BinReader.Init Endian.Little) :> IInstructionParsable
    let cases =
      [ "3045", (NOR, [ O.Reg R2; O.Reg R3; O.Reg R0 ])
        "3145", (AND, [ O.Reg R2; O.Reg R2; O.Reg R3 ])
        "3845", (XOR, [ O.Reg R2; O.Reg R2; O.Reg R3 ])
        "3945", (OR, [ O.Reg R2; O.Reg R2; O.Reg R3 ])
        "a344", (JRC, [ O.Reg R5 ])
        "ab44", (JALRC, [ O.Reg R5 ])
        "b344", (JRCADDIUSP, [ O.Imm 20UL ])
        "5b45", (BREAK, [ O.Imm 5UL ])
        "7b45", (SDBBP, [ O.Imm 5UL ])
        "1244", (LWM, [ O.List [ R16; R31 ]; O.Mem(R29, 4L, 32<rt>) ])
        "1a44", (SWM, [ O.List [ R16; R31 ]; O.Mem(R29, 4L, 32<rt>) ])
        "3644", (MOVEP, [ O.Reg R5; O.Reg R6; O.Reg R2; O.Reg R3 ]) ]
    for hex, (opcode, oprs) in cases do
      let bytes = ByteArray.ofHexString hex
      let ins = parser.Parse(System.ReadOnlySpan bytes, 0UL) :?> Instruction
      Assert.AreEqual<Opcode>(opcode, ins.Opcode, hex)
      Assert.AreEqual<Operands>(operandsFromArray oprs, ins.Operands, hex)

  (* One test for each microMIPS instruction microMIPS64 5.04 describes, in the
     order of its sections. Each reads words of the instruction and checks the
     text, and each word is one binutils' objdump reads as the same instruction
     with the same operands, so what is asserted is a reading two decoders agree
     on. BC1F, BC1T, BC2F and BC2T, which binutils reads otherwise, are checked
     against the manual's encodings. *)
  /// microMIPS64 5.04 pp.194, 196, 198 and 200.
  [<TestMethod>]
  member _.``microMIPS64 5.04 BC1F BC1T BC2F BC2T``() =
    disasmMicro64 "43880008" "bc1f 0x2, 0x14"
    disasmMicro64 "43a80008" "bc1t 0x2, 0x14"
    disasmMicro64 "42880008" "bc2f 0x2, 0x14"
    disasmMicro64 "42a80008" "bc2t 0x2, 0x14"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ABS.fmt``() =
    disasmMicro64 "5400037b" "abs.s f0, f0"
    disasmMicro64 "5400237b" "abs.d f0, f0"
    disasmMicro64 "5400437b" "abs.ps f0, f0"
    disasmMicro64 "5422037b" "abs.s f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ADD``() =
    disasmMicro64 "00000110" "add r0, r0, r0"
    disasmMicro64 "00000910" "add at, r0, r0"
    disasmMicro64 "00001110" "add v0, r0, r0"
    disasmMicro64 "00001910" "add v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ADD.fmt``() =
    disasmMicro64 "54000030" "add.s f0, f0, f0"
    disasmMicro64 "54000130" "add.d f0, f0, f0"
    disasmMicro64 "54000230" "add.ps f0, f0, f0"
    disasmMicro64 "54000830" "add.s f1, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDI``() =
    disasmMicro64 "10030000" "addi r0, v1, 0x0"
    disasmMicro64 "10600000" "addi v1, r0, 0x0"
    disasmMicro64 "10030001" "addi r0, v1, 0x1"
    disasmMicro64 "10600001" "addi v1, r0, 0x1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDIU``() =
    disasmMicro64 "4c000c00" "addiu r0, r0, 0x0"
    disasmMicro64 "4c010c00" "addiu sp, sp, 0x400"
    disasmMicro64 "4c020c00" "addiu r0, r0, 0x1"
    disasmMicro64 "4c030c00" "addiu sp, sp, 0x404"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDIUPC``() =
    disasmMicro64 "78030000" "addiupc s0, 0xc0000"
    disasmMicro64 "78030001" "addiupc s0, 0xc0004"
    disasmMicro64 "78830000" "addiupc s1, 0xc0000"
    disasmMicro64 "78830001" "addiupc s1, 0xc0004"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDIUR1SP``() =
    disasmMicro64 "4c000c00" "addiu r0, r0, 0x0"
    disasmMicro64 "4c010c00" "addiu sp, sp, 0x400"
    disasmMicro64 "4c020c00" "addiu r0, r0, 0x1"
    disasmMicro64 "4c030c00" "addiu sp, sp, 0x404"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDIUR2``() =
    disasmMicro64 "4c000c00" "addiu r0, r0, 0x0"
    disasmMicro64 "4c010c00" "addiu sp, sp, 0x400"
    disasmMicro64 "4c020c00" "addiu r0, r0, 0x1"
    disasmMicro64 "4c030c00" "addiu sp, sp, 0x404"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDIUS5``() =
    disasmMicro64 "4c000c00" "addiu r0, r0, 0x0"
    disasmMicro64 "4c010c00" "addiu sp, sp, 0x400"
    disasmMicro64 "4c020c00" "addiu r0, r0, 0x1"
    disasmMicro64 "4c030c00" "addiu sp, sp, 0x404"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDIUSP``() =
    disasmMicro64 "4c000c00" "addiu r0, r0, 0x0"
    disasmMicro64 "4c010c00" "addiu sp, sp, 0x400"
    disasmMicro64 "4c020c00" "addiu r0, r0, 0x1"
    disasmMicro64 "4c030c00" "addiu sp, sp, 0x404"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDU``() =
    disasmMicro64 "04000c00" "addu s0, s0, s0"
    disasmMicro64 "04020c00" "addu s0, s1, s0"
    disasmMicro64 "04040c00" "addu s0, v0, s0"
    disasmMicro64 "04060c00" "addu s0, v1, s0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDU16``() =
    disasmMicro64 "04000c00" "addu s0, s0, s0"
    disasmMicro64 "04020c00" "addu s0, s1, s0"
    disasmMicro64 "04040c00" "addu s0, v0, s0"
    disasmMicro64 "04060c00" "addu s0, v1, s0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ALNV.PS``() =
    disasmMicro64 "54000019" "alnv.ps f0, f0, f0, r0"
    disasmMicro64 "54000059" "alnv.ps f0, f0, f0, at"
    disasmMicro64 "54000099" "alnv.ps f0, f0, f0, v0"
    disasmMicro64 "540000d9" "alnv.ps f0, f0, f0, v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 AND``() =
    disasmMicro64 "44800c00" "and s0, s0, s0"
    disasmMicro64 "44810c00" "and s0, s0, s1"
    disasmMicro64 "44820c00" "and s0, s0, v0"
    disasmMicro64 "44830c00" "and s0, s0, v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 AND16``() =
    disasmMicro64 "44800c00" "and s0, s0, s0"
    disasmMicro64 "44810c00" "and s0, s0, s1"
    disasmMicro64 "44820c00" "and s0, s0, v0"
    disasmMicro64 "44830c00" "and s0, s0, v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ANDI``() =
    disasmMicro64 "2c000c00" "andi s0, s0, 0x80"
    disasmMicro64 "2c010c00" "andi s0, s0, 0x1"
    disasmMicro64 "2c020c00" "andi s0, s0, 0x2"
    disasmMicro64 "2c030c00" "andi s0, s0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ANDI16``() =
    disasmMicro64 "2c000c00" "andi s0, s0, 0x80"
    disasmMicro64 "2c010c00" "andi s0, s0, 0x1"
    disasmMicro64 "2c020c00" "andi s0, s0, 0x2"
    disasmMicro64 "2c030c00" "andi s0, s0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 B``() =
    disasmMicro64 "cc000c00" "b 0x2"
    disasmMicro64 "cc010c00" "b 0x4"
    disasmMicro64 "cc020c00" "b 0x6"
    disasmMicro64 "cc030c00" "b 0x8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 B16``() =
    disasmMicro64 "cc000c00" "b 0x2"
    disasmMicro64 "cc010c00" "b 0x4"
    disasmMicro64 "cc020c00" "b 0x6"
    disasmMicro64 "cc030c00" "b 0x8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BAL``() =
    disasmMicro64 "40600000" "bgezal r0, 0x4"
    disasmMicro64 "40600001" "bgezal r0, 0x6"
    disasmMicro64 "40607fff" "bgezal r0, 0x10002"
    disasmMicro64 "40608000" "bgezal r0, 0xffffffffffff0004"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BEQ``() =
    disasmMicro64 "8d000c00" "beq v0, r0, 0x2"
    disasmMicro64 "8c000c00" "beq s0, r0, 0x2"
    disasmMicro64 "8c010c00" "beq s0, r0, 0x4"
    disasmMicro64 "8c020c00" "beq s0, r0, 0x6"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BEQZ16``() =
    disasmMicro64 "8d000c00" "beq v0, r0, 0x2"
    disasmMicro64 "8c000c00" "beq s0, r0, 0x2"
    disasmMicro64 "8c010c00" "beq s0, r0, 0x4"
    disasmMicro64 "8c020c00" "beq s0, r0, 0x6"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BEQZC``() =
    disasmMicro64 "40e30000" "beqzc v1, 0x4"
    disasmMicro64 "40e30001" "beqzc v1, 0x6"
    disasmMicro64 "40e37fff" "beqzc v1, 0x10002"
    disasmMicro64 "40e38000" "beqzc v1, 0xffffffffffff0004"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BGEZ``() =
    disasmMicro64 "40430000" "bgez v1, 0x4"
    disasmMicro64 "40430001" "bgez v1, 0x6"
    disasmMicro64 "40437fff" "bgez v1, 0x10002"
    disasmMicro64 "40438000" "bgez v1, 0xffffffffffff0004"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BGEZAL``() =
    disasmMicro64 "40600000" "bgezal r0, 0x4"
    disasmMicro64 "40600001" "bgezal r0, 0x6"
    disasmMicro64 "40607fff" "bgezal r0, 0x10002"
    disasmMicro64 "40608000" "bgezal r0, 0xffffffffffff0004"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BGEZALS``() =
    disasmMicro64 "42630000" "bgezals v1, 0x4"
    disasmMicro64 "42630001" "bgezals v1, 0x6"
    disasmMicro64 "42637fff" "bgezals v1, 0x10002"
    disasmMicro64 "42638000" "bgezals v1, 0xffffffffffff0004"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BGTZ``() =
    disasmMicro64 "40c30000" "bgtz v1, 0x4"
    disasmMicro64 "40c30001" "bgtz v1, 0x6"
    disasmMicro64 "40c37fff" "bgtz v1, 0x10002"
    disasmMicro64 "40c38000" "bgtz v1, 0xffffffffffff0004"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BLEZ``() =
    disasmMicro64 "40830000" "blez v1, 0x4"
    disasmMicro64 "40830001" "blez v1, 0x6"
    disasmMicro64 "40837fff" "blez v1, 0x10002"
    disasmMicro64 "40838000" "blez v1, 0xffffffffffff0004"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BLTZ``() =
    disasmMicro64 "40000000" "bltz r0, 0x4"
    disasmMicro64 "40000001" "bltz r0, 0x6"
    disasmMicro64 "40000002" "bltz r0, 0x8"
    disasmMicro64 "40000003" "bltz r0, 0xa"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BLTZAL``() =
    disasmMicro64 "40220000" "bltzal v0, 0x4"
    disasmMicro64 "40220001" "bltzal v0, 0x6"
    disasmMicro64 "40220002" "bltzal v0, 0x8"
    disasmMicro64 "40220003" "bltzal v0, 0xa"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BLTZALS``() =
    disasmMicro64 "42230000" "bltzals v1, 0x4"
    disasmMicro64 "42230001" "bltzals v1, 0x6"
    disasmMicro64 "42237fff" "bltzals v1, 0x10002"
    disasmMicro64 "42238000" "bltzals v1, 0xffffffffffff0004"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BNE``() =
    disasmMicro64 "ad000c00" "bne v0, r0, 0x2"
    disasmMicro64 "ac000c00" "bne s0, r0, 0x2"
    disasmMicro64 "ac010c00" "bne s0, r0, 0x4"
    disasmMicro64 "ac020c00" "bne s0, r0, 0x6"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BNEZ16``() =
    disasmMicro64 "ad000c00" "bne v0, r0, 0x2"
    disasmMicro64 "ac000c00" "bne s0, r0, 0x2"
    disasmMicro64 "ac010c00" "bne s0, r0, 0x4"
    disasmMicro64 "ac020c00" "bne s0, r0, 0x6"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BNEZC``() =
    disasmMicro64 "40a30000" "bnezc v1, 0x4"
    disasmMicro64 "40a30001" "bnezc v1, 0x6"
    disasmMicro64 "40a37fff" "bnezc v1, 0x10002"
    disasmMicro64 "40a38000" "bnezc v1, 0xffffffffffff0004"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BREAK``() =
    disasmMicro64 "46800c00" "break 0x0"
    disasmMicro64 "46810c00" "break 0x1"
    disasmMicro64 "46820c00" "break 0x2"
    disasmMicro64 "46830c00" "break 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BREAK16``() =
    disasmMicro64 "46800c00" "break 0x0"
    disasmMicro64 "46810c00" "break 0x1"
    disasmMicro64 "46820c00" "break 0x2"
    disasmMicro64 "46830c00" "break 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 C.cond.fmt``() =
    disasmMicro64 "5400203c" "c.f.s 0x1, f0, f0"
    disasmMicro64 "5400207c" "c.un.s 0x1, f0, f0"
    disasmMicro64 "540020bc" "c.eq.s 0x1, f0, f0"
    disasmMicro64 "540020fc" "c.ueq.s 0x1, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CACHE``() =
    disasmMicro64 "20006000" "cache 0x0, 0(r0)"
    disasmMicro64 "20006001" "cache 0x0, 1(r0)"
    disasmMicro64 "20006002" "cache 0x0, 2(r0)"
    disasmMicro64 "20006003" "cache 0x0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CACHEE``() =
    disasmMicro64 "6000a600" "cachee 0x0, 0(r0)"
    disasmMicro64 "6000a601" "cachee 0x0, 1(r0)"
    disasmMicro64 "6000a602" "cachee 0x0, 2(r0)"
    disasmMicro64 "6000a603" "cachee 0x0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CEIL.L.fmt``() =
    disasmMicro64 "5400133b" "ceil.l.s f0, f0"
    disasmMicro64 "5400533b" "ceil.l.d f0, f0"
    disasmMicro64 "5422133b" "ceil.l.s f1, f2"
    disasmMicro64 "5422533b" "ceil.l.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CEIL.W.fmt``() =
    disasmMicro64 "54001b3b" "ceil.w.s f0, f0"
    disasmMicro64 "54005b3b" "ceil.w.d f0, f0"
    disasmMicro64 "54221b3b" "ceil.w.s f1, f2"
    disasmMicro64 "54225b3b" "ceil.w.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CFC1``() =
    disasmMicro64 "5400103b" "cfc1 r0, f0"
    disasmMicro64 "5422103b" "cfc1 at, f2"
    disasmMicro64 "57fe103b" "cfc1 ra, f30"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CFC2``() =
    disasmMicro64 "0000cd3c" "cfc2 r0, 0x0"
    disasmMicro64 "0022cd3c" "cfc2 at, 0x2"
    disasmMicro64 "03fecd3c" "cfc2 ra, 0x1e"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CLO``() =
    disasmMicro64 "00004b3c" "clo r0, r0"
    disasmMicro64 "00224b3c" "clo at, v0"
    disasmMicro64 "03fe4b3c" "clo ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CLZ``() =
    disasmMicro64 "00005b3c" "clz r0, r0"
    disasmMicro64 "00225b3c" "clz at, v0"
    disasmMicro64 "03fe5b3c" "clz ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 COP2``() =
    disasmMicro64 "00000002" "cop2 0x0"
    disasmMicro64 "0000000a" "cop2 0x1"
    disasmMicro64 "00000012" "cop2 0x2"
    disasmMicro64 "0000001a" "cop2 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CTC1``() =
    disasmMicro64 "5400183b" "ctc1 r0, f0"
    disasmMicro64 "5422183b" "ctc1 at, f2"
    disasmMicro64 "57fe183b" "ctc1 ra, f30"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CTC2``() =
    disasmMicro64 "0000dd3c" "ctc2 r0, 0x0"
    disasmMicro64 "0022dd3c" "ctc2 at, 0x2"
    disasmMicro64 "03fedd3c" "ctc2 ra, 0x1e"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CVT.D.fmt``() =
    disasmMicro64 "5400137b" "cvt.d.s f0, f0"
    disasmMicro64 "5400337b" "cvt.d.w f0, f0"
    disasmMicro64 "5400537b" "cvt.d.l f0, f0"
    disasmMicro64 "5422137b" "cvt.d.s f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CVT.L.fmt``() =
    disasmMicro64 "5400013b" "cvt.l.s f0, f0"
    disasmMicro64 "5400413b" "cvt.l.d f0, f0"
    disasmMicro64 "5422013b" "cvt.l.s f1, f2"
    disasmMicro64 "5422413b" "cvt.l.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CVT.PS.S``() =
    disasmMicro64 "54000180" "cvt.ps.s f0, f0, f0"
    disasmMicro64 "54000980" "cvt.ps.s f1, f0, f0"
    disasmMicro64 "54001180" "cvt.ps.s f2, f0, f0"
    disasmMicro64 "54001980" "cvt.ps.s f3, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CVT.S.PL``() =
    disasmMicro64 "5400213b" "cvt.s.pl f0, f0"
    disasmMicro64 "5422213b" "cvt.s.pl f1, f2"
    disasmMicro64 "57fe213b" "cvt.s.pl f31, f30"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CVT.S.PU``() =
    disasmMicro64 "5400293b" "cvt.s.pu f0, f0"
    disasmMicro64 "5422293b" "cvt.s.pu f1, f2"
    disasmMicro64 "57fe293b" "cvt.s.pu f31, f30"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CVT.S.fmt``() =
    disasmMicro64 "54001b7b" "cvt.s.d f0, f0"
    disasmMicro64 "54003b7b" "cvt.s.w f0, f0"
    disasmMicro64 "54005b7b" "cvt.s.l f0, f0"
    disasmMicro64 "54221b7b" "cvt.s.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CVT.W.fmt``() =
    disasmMicro64 "5400093b" "cvt.w.s f0, f0"
    disasmMicro64 "5400493b" "cvt.w.d f0, f0"
    disasmMicro64 "5422093b" "cvt.w.s f1, f2"
    disasmMicro64 "5422493b" "cvt.w.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DADD``() =
    disasmMicro64 "58000110" "dadd r0, r0, r0"
    disasmMicro64 "58000910" "dadd at, r0, r0"
    disasmMicro64 "58001110" "dadd v0, r0, r0"
    disasmMicro64 "58001910" "dadd v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DADDI``() =
    disasmMicro64 "5800001c" "daddi r0, r0, 0x0"
    disasmMicro64 "5800005c" "daddi r0, r0, 0x1"
    disasmMicro64 "5800009c" "daddi r0, r0, 0x2"
    disasmMicro64 "580000dc" "daddi r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DADDIU``() =
    disasmMicro64 "5c030000" "daddiu r0, v1, 0x0"
    disasmMicro64 "5c600000" "daddiu v1, r0, 0x0"
    disasmMicro64 "5c030001" "daddiu r0, v1, 0x1"
    disasmMicro64 "5c600001" "daddiu v1, r0, 0x1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DADDU``() =
    disasmMicro64 "58220150" "daddu r0, v0, at"
    disasmMicro64 "58220950" "daddu at, v0, at"
    disasmMicro64 "58221150" "daddu v0, v0, at"
    disasmMicro64 "58221950" "daddu v1, v0, at"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DCLO``() =
    disasmMicro64 "58004b3c" "dclo r0, r0"
    disasmMicro64 "58224b3c" "dclo at, v0"
    disasmMicro64 "5bfe4b3c" "dclo ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DCLZ``() =
    disasmMicro64 "58005b3c" "dclz r0, r0"
    disasmMicro64 "58225b3c" "dclz at, v0"
    disasmMicro64 "5bfe5b3c" "dclz ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DDIV``() =
    disasmMicro64 "5800ab3c" "ddiv r0, r0"
    disasmMicro64 "5822ab3c" "ddiv v0, at"
    disasmMicro64 "5bfeab3c" "ddiv s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DDIVU``() =
    disasmMicro64 "5800bb3c" "ddivu r0, r0"
    disasmMicro64 "5822bb3c" "ddivu v0, at"
    disasmMicro64 "5bfebb3c" "ddivu s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DERET``() =
    disasmMicro64 "0000e37c" "deret"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DEXT``() =
    disasmMicro64 "5800002c" "dext r0, r0, 0x0, 0x1"
    disasmMicro64 "5800006c" "dext r0, r0, 0x1, 0x1"
    disasmMicro64 "580000ac" "dext r0, r0, 0x2, 0x1"
    disasmMicro64 "580000ec" "dext r0, r0, 0x3, 0x1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DEXTM``() =
    disasmMicro64 "58000024" "dextm r0, r0, 0x0, 0x21"
    disasmMicro64 "58000064" "dextm r0, r0, 0x1, 0x21"
    disasmMicro64 "580000a4" "dextm r0, r0, 0x2, 0x21"
    disasmMicro64 "580000e4" "dextm r0, r0, 0x3, 0x21"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DEXTU``() =
    disasmMicro64 "58000014" "dextu r0, r0, 0x20, 0x1"
    disasmMicro64 "58000054" "dextu r0, r0, 0x21, 0x1"
    disasmMicro64 "58000094" "dextu r0, r0, 0x22, 0x1"
    disasmMicro64 "580000d4" "dextu r0, r0, 0x23, 0x1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DI``() =
    disasmMicro64 "0000477c" "di r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DINS``() =
    disasmMicro64 "5800000c" "dins r0, r0, 0x0, 0x1"
    disasmMicro64 "5800080c" "dins r0, r0, 0x0, 0x2"
    disasmMicro64 "5800084c" "dins r0, r0, 0x1, 0x1"
    disasmMicro64 "5800100c" "dins r0, r0, 0x0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DINSM``() =
    disasmMicro64 "58000004" "dinsm r0, r0, 0x0, 0x21"
    disasmMicro64 "58000044" "dinsm r0, r0, 0x1, 0x20"
    disasmMicro64 "58000084" "dinsm r0, r0, 0x2, 0x1f"
    disasmMicro64 "580000c4" "dinsm r0, r0, 0x3, 0x1e"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DINSU``() =
    disasmMicro64 "58000034" "dinsu r0, r0, 0x20, 0x1"
    disasmMicro64 "58000834" "dinsu r0, r0, 0x20, 0x2"
    disasmMicro64 "58000874" "dinsu r0, r0, 0x21, 0x1"
    disasmMicro64 "58001034" "dinsu r0, r0, 0x20, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DIV``() =
    disasmMicro64 "0000ab3c" "div r0, r0"
    disasmMicro64 "0022ab3c" "div v0, at"
    disasmMicro64 "03feab3c" "div s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DIV.fmt``() =
    disasmMicro64 "540000f0" "div.s f0, f0, f0"
    disasmMicro64 "540001f0" "div.d f0, f0, f0"
    disasmMicro64 "540008f0" "div.s f1, f0, f0"
    disasmMicro64 "540009f0" "div.d f1, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DIVU``() =
    disasmMicro64 "0000bb3c" "divu r0, r0"
    disasmMicro64 "0022bb3c" "divu v0, at"
    disasmMicro64 "03febb3c" "divu s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DMFC0``() =
    disasmMicro64 "580008fc" "dmfc0 r0, 0x0, 0x1"
    disasmMicro64 "580010fc" "dmfc0 r0, 0x0, 0x2"
    disasmMicro64 "580018fc" "dmfc0 r0, 0x0, 0x3"
    disasmMicro64 "582208fc" "dmfc0 at, 0x2, 0x1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DMFC1``() =
    disasmMicro64 "5400243b" "dmfc1 r0, f0"
    disasmMicro64 "5422243b" "dmfc1 at, f2"
    disasmMicro64 "57fe243b" "dmfc1 ra, f30"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DMFC2``() =
    disasmMicro64 "00006d3c" "dmfc2 r0, 0x0"
    disasmMicro64 "00226d3c" "dmfc2 at, 0x2"
    disasmMicro64 "03fe6d3c" "dmfc2 ra, 0x1e"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DMTC0``() =
    disasmMicro64 "58000afc" "dmtc0 r0, 0x0, 0x1"
    disasmMicro64 "580012fc" "dmtc0 r0, 0x0, 0x2"
    disasmMicro64 "58001afc" "dmtc0 r0, 0x0, 0x3"
    disasmMicro64 "58220afc" "dmtc0 at, 0x2, 0x1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DMTC1``() =
    disasmMicro64 "54002c3b" "dmtc1 r0, f0"
    disasmMicro64 "54222c3b" "dmtc1 at, f2"
    disasmMicro64 "57fe2c3b" "dmtc1 ra, f30"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DMTC2``() =
    disasmMicro64 "00007d3c" "dmtc2 r0, 0x0"
    disasmMicro64 "00227d3c" "dmtc2 at, 0x2"
    disasmMicro64 "03fe7d3c" "dmtc2 ra, 0x1e"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DMULT``() =
    disasmMicro64 "58008b3c" "dmult r0, r0"
    disasmMicro64 "58228b3c" "dmult v0, at"
    disasmMicro64 "5bfe8b3c" "dmult s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DMULTU``() =
    disasmMicro64 "58009b3c" "dmultu r0, r0"
    disasmMicro64 "58229b3c" "dmultu v0, at"
    disasmMicro64 "5bfe9b3c" "dmultu s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DROTR``() =
    disasmMicro64 "580000c0" "drotr r0, r0, 0x0"
    disasmMicro64 "580008c0" "drotr r0, r0, 0x1"
    disasmMicro64 "580010c0" "drotr r0, r0, 0x2"
    disasmMicro64 "580018c0" "drotr r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DROTR32``() =
    disasmMicro64 "580000c8" "drotr32  r0, r0, 0x0"
    disasmMicro64 "580008c8" "drotr32  r0, r0, 0x1"
    disasmMicro64 "580010c8" "drotr32  r0, r0, 0x2"
    disasmMicro64 "580018c8" "drotr32  r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DROTRV``() =
    disasmMicro64 "580000d0" "drotrv r0, r0, r0"
    disasmMicro64 "580008d0" "drotrv at, r0, r0"
    disasmMicro64 "580010d0" "drotrv v0, r0, r0"
    disasmMicro64 "580018d0" "drotrv v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DSBH``() =
    disasmMicro64 "58007b3c" "dsbh r0, r0"
    disasmMicro64 "58227b3c" "dsbh at, v0"
    disasmMicro64 "5bfe7b3c" "dsbh ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DSHD``() =
    disasmMicro64 "5800fb3c" "dshd r0, r0"
    disasmMicro64 "5822fb3c" "dshd at, v0"
    disasmMicro64 "5bfefb3c" "dshd ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DSLL``() =
    disasmMicro64 "58000000" "dsll r0, r0, 0x0"
    disasmMicro64 "58000800" "dsll r0, r0, 0x1"
    disasmMicro64 "58001000" "dsll r0, r0, 0x2"
    disasmMicro64 "58001800" "dsll r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DSLL32``() =
    disasmMicro64 "58000008" "dsll32 r0, r0, 0x0"
    disasmMicro64 "58000808" "dsll32 r0, r0, 0x1"
    disasmMicro64 "58001008" "dsll32 r0, r0, 0x2"
    disasmMicro64 "58001808" "dsll32 r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DSLLV``() =
    disasmMicro64 "58000010" "dsllv r0, r0, r0"
    disasmMicro64 "58000810" "dsllv at, r0, r0"
    disasmMicro64 "58001010" "dsllv v0, r0, r0"
    disasmMicro64 "58001810" "dsllv v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DSRA``() =
    disasmMicro64 "58000080" "dsra r0, r0, 0x0"
    disasmMicro64 "58000880" "dsra r0, r0, 0x1"
    disasmMicro64 "58001080" "dsra r0, r0, 0x2"
    disasmMicro64 "58001880" "dsra r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DSRA32``() =
    disasmMicro64 "58000088" "dsra32 r0, r0, 0x0"
    disasmMicro64 "58000888" "dsra32 r0, r0, 0x1"
    disasmMicro64 "58001088" "dsra32 r0, r0, 0x2"
    disasmMicro64 "58001888" "dsra32 r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DSRAV``() =
    disasmMicro64 "58000090" "dsrav r0, r0, r0"
    disasmMicro64 "58000890" "dsrav at, r0, r0"
    disasmMicro64 "58001090" "dsrav v0, r0, r0"
    disasmMicro64 "58001890" "dsrav v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DSRL``() =
    disasmMicro64 "58000040" "dsrl r0, r0, 0x0"
    disasmMicro64 "58000840" "dsrl r0, r0, 0x1"
    disasmMicro64 "58001040" "dsrl r0, r0, 0x2"
    disasmMicro64 "58001840" "dsrl r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DSRL32``() =
    disasmMicro64 "58000048" "dsrl32 r0, r0, 0x0"
    disasmMicro64 "58000848" "dsrl32 r0, r0, 0x1"
    disasmMicro64 "58001048" "dsrl32 r0, r0, 0x2"
    disasmMicro64 "58001848" "dsrl32 r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DSRLV``() =
    disasmMicro64 "58000050" "dsrlv r0, r0, r0"
    disasmMicro64 "58000850" "dsrlv at, r0, r0"
    disasmMicro64 "58001050" "dsrlv v0, r0, r0"
    disasmMicro64 "58001850" "dsrlv v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DSUB``() =
    disasmMicro64 "58220190" "dsub r0, v0, at"
    disasmMicro64 "58220990" "dsub at, v0, at"
    disasmMicro64 "58221190" "dsub v0, v0, at"
    disasmMicro64 "58221990" "dsub v1, v0, at"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DSUBU``() =
    disasmMicro64 "582201d0" "dsubu r0, v0, at"
    disasmMicro64 "582209d0" "dsubu at, v0, at"
    disasmMicro64 "582211d0" "dsubu v0, v0, at"
    disasmMicro64 "582219d0" "dsubu v1, v0, at"

  [<TestMethod>]
  member _.``microMIPS64 5.04 EHB``() =
    disasmMicro64 "00001800" "ehb"

  [<TestMethod>]
  member _.``microMIPS64 5.04 EI``() =
    disasmMicro64 "0000577c" "ei r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ERET``() =
    disasmMicro64 "0000f37c" "eret"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ERETNC``() =
    disasmMicro64 "0001f37c" "eretnc"

  [<TestMethod>]
  member _.``microMIPS64 5.04 EXT``() =
    disasmMicro64 "0000002c" "ext r0, r0, 0x0, 0x1"
    disasmMicro64 "0000006c" "ext r0, r0, 0x1, 0x1"
    disasmMicro64 "000000ac" "ext r0, r0, 0x2, 0x1"
    disasmMicro64 "000000ec" "ext r0, r0, 0x3, 0x1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 FLOOR.L.fmt``() =
    disasmMicro64 "5400033b" "floor.l.s f0, f0"
    disasmMicro64 "5400433b" "floor.l.d f0, f0"
    disasmMicro64 "5422033b" "floor.l.s f1, f2"
    disasmMicro64 "5422433b" "floor.l.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 FLOOR.W.fmt``() =
    disasmMicro64 "54000b3b" "floor.w.s f0, f0"
    disasmMicro64 "54004b3b" "floor.w.d f0, f0"
    disasmMicro64 "54220b3b" "floor.w.s f1, f2"
    disasmMicro64 "54224b3b" "floor.w.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 INS``() =
    disasmMicro64 "0000000c" "ins r0, r0, 0x0, 0x1"
    disasmMicro64 "0000080c" "ins r0, r0, 0x0, 0x2"
    disasmMicro64 "0000084c" "ins r0, r0, 0x1, 0x1"
    disasmMicro64 "0000100c" "ins r0, r0, 0x0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 J``() =
    disasmMicro64 "d4030000" "j 0x60000"
    disasmMicro64 "d4600000" "j 0xc00000"
    disasmMicro64 "d4030001" "j 0x60002"
    disasmMicro64 "d4600001" "j 0xc00002"

  [<TestMethod>]
  member _.``microMIPS64 5.04 JAL``() =
    disasmMicro64 "f4030000" "jal 0x60000"
    disasmMicro64 "f4600000" "jal 0xc00000"
    disasmMicro64 "f4030001" "jal 0x60002"
    disasmMicro64 "f4600001" "jal 0xc00002"

  [<TestMethod>]
  member _.``microMIPS64 5.04 JALR``() =
    disasmMicro64 "45c00c00" "jalr r0"
    disasmMicro64 "45c10c00" "jalr at"
    disasmMicro64 "45c20c00" "jalr v0"
    disasmMicro64 "45c30c00" "jalr v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 JALR.HB``() =
    disasmMicro64 "00051f3c" "jalr.hb r0, a1"
    disasmMicro64 "00001f3c" "jalr.hb r0, r0"
    disasmMicro64 "00221f3c" "jalr.hb at, v0"
    disasmMicro64 "03fe1f3c" "jalr.hb ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 JALR16``() =
    disasmMicro64 "45c00c00" "jalr r0"
    disasmMicro64 "45c10c00" "jalr at"
    disasmMicro64 "45c20c00" "jalr v0"
    disasmMicro64 "45c30c00" "jalr v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 JALRS``() =
    disasmMicro64 "45e00c00" "jalrs r0"
    disasmMicro64 "45e10c00" "jalrs at"
    disasmMicro64 "45e20c00" "jalrs v0"
    disasmMicro64 "45e30c00" "jalrs v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 JALRS.HB``() =
    disasmMicro64 "00225f3c" "jalrs.hb at, v0"
    disasmMicro64 "03fe5f3c" "jalrs.hb ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 JALRS16``() =
    disasmMicro64 "45e00c00" "jalrs r0"
    disasmMicro64 "45e10c00" "jalrs at"
    disasmMicro64 "45e20c00" "jalrs v0"
    disasmMicro64 "45e30c00" "jalrs v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 JALS``() =
    disasmMicro64 "74030000" "jals 0x60000"
    disasmMicro64 "74600000" "jals 0xc00000"
    disasmMicro64 "74030001" "jals 0x60002"
    disasmMicro64 "74600001" "jals 0xc00002"

  [<TestMethod>]
  member _.``microMIPS64 5.04 JALX``() =
    disasmMicro64 "f0030000" "jalx 0xc0000"
    disasmMicro64 "f0600000" "jalx 0x1800000"
    disasmMicro64 "f0030001" "jalx 0xc0004"
    disasmMicro64 "f0600001" "jalx 0x1800004"

  [<TestMethod>]
  member _.``microMIPS64 5.04 JR``() =
    disasmMicro64 "45800c00" "jr r0"
    disasmMicro64 "45810c00" "jr at"
    disasmMicro64 "45820c00" "jr v0"
    disasmMicro64 "45830c00" "jr v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 JR.HB``() =
    disasmMicro64 "00051f3c" "jalr.hb r0, a1"
    disasmMicro64 "00001f3c" "jalr.hb r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 JR16``() =
    disasmMicro64 "45800c00" "jr r0"
    disasmMicro64 "45810c00" "jr at"
    disasmMicro64 "45820c00" "jr v0"
    disasmMicro64 "45830c00" "jr v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 JRADDIUSP``() =
    disasmMicro64 "47000c00" "jraddiusp 0x0"
    disasmMicro64 "47010c00" "jraddiusp 0x4"
    disasmMicro64 "47020c00" "jraddiusp 0x8"
    disasmMicro64 "47030c00" "jraddiusp 0xc"

  [<TestMethod>]
  member _.``microMIPS64 5.04 JRC``() =
    disasmMicro64 "45a00c00" "jrc r0"
    disasmMicro64 "45a10c00" "jrc at"
    disasmMicro64 "45a20c00" "jrc v0"
    disasmMicro64 "45a30c00" "jrc v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LB``() =
    disasmMicro64 "1c030000" "lb r0, 0(v1)"
    disasmMicro64 "1c600000" "lb v1, 0(r0)"
    disasmMicro64 "1c030001" "lb r0, 1(v1)"
    disasmMicro64 "1c600001" "lb v1, 1(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LBE``() =
    disasmMicro64 "60006800" "lbe r0, 0(r0)"
    disasmMicro64 "60006801" "lbe r0, 1(r0)"
    disasmMicro64 "60006802" "lbe r0, 2(r0)"
    disasmMicro64 "60006803" "lbe r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LBU``() =
    disasmMicro64 "08000c00" "lbu s0, 0(s0)"
    disasmMicro64 "08010c00" "lbu s0, 1(s0)"
    disasmMicro64 "08020c00" "lbu s0, 2(s0)"
    disasmMicro64 "08030c00" "lbu s0, 3(s0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LBU16``() =
    disasmMicro64 "08000c00" "lbu s0, 0(s0)"
    disasmMicro64 "08010c00" "lbu s0, 1(s0)"
    disasmMicro64 "08020c00" "lbu s0, 2(s0)"
    disasmMicro64 "08030c00" "lbu s0, 3(s0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LBUE``() =
    disasmMicro64 "60006000" "lbue r0, 0(r0)"
    disasmMicro64 "60006001" "lbue r0, 1(r0)"
    disasmMicro64 "60006002" "lbue r0, 2(r0)"
    disasmMicro64 "60006003" "lbue r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LD``() =
    disasmMicro64 "dc030000" "ld r0, 0(v1)"
    disasmMicro64 "dc600000" "ld v1, 0(r0)"
    disasmMicro64 "dc030001" "ld r0, 1(v1)"
    disasmMicro64 "dc600001" "ld v1, 1(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LDC1``() =
    disasmMicro64 "bc030000" "ldc1 f0, 0(v1)"
    disasmMicro64 "bc600000" "ldc1 f3, 0(r0)"
    disasmMicro64 "bc030001" "ldc1 f0, 1(v1)"
    disasmMicro64 "bc600001" "ldc1 f3, 1(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LDC2``() =
    disasmMicro64 "20002000" "ldc2 0x0, 0(r0)"
    disasmMicro64 "20002001" "ldc2 0x0, 1(r0)"
    disasmMicro64 "20002002" "ldc2 0x0, 2(r0)"
    disasmMicro64 "20002003" "ldc2 0x0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LDL``() =
    disasmMicro64 "60004000" "ldl r0, 0(r0)"
    disasmMicro64 "60004001" "ldl r0, 1(r0)"
    disasmMicro64 "60004002" "ldl r0, 2(r0)"
    disasmMicro64 "60004003" "ldl r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LDM``() =
    disasmMicro64 "20227000" "ldm s0, 0(v0)"
    disasmMicro64 "20227001" "ldm s0, 1(v0)"
    disasmMicro64 "20227002" "ldm s0, 2(v0)"
    disasmMicro64 "20227003" "ldm s0, 3(v0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LDP``() =
    disasmMicro64 "20004000" "ldp r0, at, 0(r0)"
    disasmMicro64 "20004001" "ldp r0, at, 1(r0)"
    disasmMicro64 "20004002" "ldp r0, at, 2(r0)"
    disasmMicro64 "20004003" "ldp r0, at, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LDR``() =
    disasmMicro64 "60005000" "ldr r0, 0(r0)"
    disasmMicro64 "60005001" "ldr r0, 1(r0)"
    disasmMicro64 "60005002" "ldr r0, 2(r0)"
    disasmMicro64 "60005003" "ldr r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LDXC1``() =
    disasmMicro64 "540000c8" "ldxc1 f0, r0(r0)"
    disasmMicro64 "540008c8" "ldxc1 f1, r0(r0)"
    disasmMicro64 "540010c8" "ldxc1 f2, r0(r0)"
    disasmMicro64 "540018c8" "ldxc1 f3, r0(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LH``() =
    disasmMicro64 "3c030000" "lh r0, 0(v1)"
    disasmMicro64 "3c600000" "lh v1, 0(r0)"
    disasmMicro64 "3c030001" "lh r0, 1(v1)"
    disasmMicro64 "3c600001" "lh v1, 1(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LHE``() =
    disasmMicro64 "60006a00" "lhe r0, 0(r0)"
    disasmMicro64 "60006a01" "lhe r0, 1(r0)"
    disasmMicro64 "60006a02" "lhe r0, 2(r0)"
    disasmMicro64 "60006a03" "lhe r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LHU``() =
    disasmMicro64 "28000c00" "lhu s0, 0(s0)"
    disasmMicro64 "28010c00" "lhu s0, 2(s0)"
    disasmMicro64 "28020c00" "lhu s0, 4(s0)"
    disasmMicro64 "28030c00" "lhu s0, 6(s0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LHU16``() =
    disasmMicro64 "28000c00" "lhu s0, 0(s0)"
    disasmMicro64 "28010c00" "lhu s0, 2(s0)"
    disasmMicro64 "28020c00" "lhu s0, 4(s0)"
    disasmMicro64 "28030c00" "lhu s0, 6(s0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LHUE``() =
    disasmMicro64 "60006200" "lhue r0, 0(r0)"
    disasmMicro64 "60006201" "lhue r0, 1(r0)"
    disasmMicro64 "60006202" "lhue r0, 2(r0)"
    disasmMicro64 "60006203" "lhue r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LI16``() =
    disasmMicro64 "4c000c00" "addiu r0, r0, 0x0"
    disasmMicro64 "4c010c00" "addiu sp, sp, 0x400"
    disasmMicro64 "4c020c00" "addiu r0, r0, 0x1"
    disasmMicro64 "4c030c00" "addiu sp, sp, 0x404"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LL``() =
    disasmMicro64 "60003000" "ll r0, 0(r0)"
    disasmMicro64 "60003001" "ll r0, 1(r0)"
    disasmMicro64 "60003002" "ll r0, 2(r0)"
    disasmMicro64 "60003003" "ll r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LLD``() =
    disasmMicro64 "60007000" "lld r0, 0(r0)"
    disasmMicro64 "60007001" "lld r0, 1(r0)"
    disasmMicro64 "60007002" "lld r0, 2(r0)"
    disasmMicro64 "60007003" "lld r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LLE``() =
    disasmMicro64 "60006c00" "lle r0, 0(r0)"
    disasmMicro64 "60006c01" "lle r0, 1(r0)"
    disasmMicro64 "60006c02" "lle r0, 2(r0)"
    disasmMicro64 "60006c03" "lle r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LUI``() =
    disasmMicro64 "41a30000" "lui v1, 0x0"
    disasmMicro64 "41a30001" "lui v1, 0x1"
    disasmMicro64 "41a37fff" "lui v1, 0x7fff"
    disasmMicro64 "41a38000" "lui v1, 0x8000"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LUXC1``() =
    disasmMicro64 "54000148" "luxc1 f0, r0(r0)"
    disasmMicro64 "54000948" "luxc1 f1, r0(r0)"
    disasmMicro64 "54001148" "luxc1 f2, r0(r0)"
    disasmMicro64 "54001948" "luxc1 f3, r0(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LW``() =
    disasmMicro64 "48000c00" "lw r0, 0(sp)"
    disasmMicro64 "48010c00" "lw r0, 4(sp)"
    disasmMicro64 "48020c00" "lw r0, 8(sp)"
    disasmMicro64 "48030c00" "lw r0, 12(sp)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LW16``() =
    disasmMicro64 "48000c00" "lw r0, 0(sp)"
    disasmMicro64 "48010c00" "lw r0, 4(sp)"
    disasmMicro64 "48020c00" "lw r0, 8(sp)"
    disasmMicro64 "48030c00" "lw r0, 12(sp)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LWC1``() =
    disasmMicro64 "9c030000" "lwc1 f0, 0(v1)"
    disasmMicro64 "9c600000" "lwc1 f3, 0(r0)"
    disasmMicro64 "9c030001" "lwc1 f0, 1(v1)"
    disasmMicro64 "9c600001" "lwc1 f3, 1(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LWC2``() =
    disasmMicro64 "20000000" "lwc2 0x0, 0(r0)"
    disasmMicro64 "20000001" "lwc2 0x0, 1(r0)"
    disasmMicro64 "20000002" "lwc2 0x0, 2(r0)"
    disasmMicro64 "20000003" "lwc2 0x0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LWE``() =
    disasmMicro64 "60006e00" "lwe r0, 0(r0)"
    disasmMicro64 "60006e01" "lwe r0, 1(r0)"
    disasmMicro64 "60006e02" "lwe r0, 2(r0)"
    disasmMicro64 "60006e03" "lwe r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LWGP``() =
    disasmMicro64 "48000c00" "lw r0, 0(sp)"
    disasmMicro64 "48010c00" "lw r0, 4(sp)"
    disasmMicro64 "48020c00" "lw r0, 8(sp)"
    disasmMicro64 "48030c00" "lw r0, 12(sp)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LWL``() =
    disasmMicro64 "60000000" "lwl r0, 0(r0)"
    disasmMicro64 "60000001" "lwl r0, 1(r0)"
    disasmMicro64 "60000002" "lwl r0, 2(r0)"
    disasmMicro64 "60000003" "lwl r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LWLE``() =
    disasmMicro64 "60006400" "lwle r0, 0(r0)"
    disasmMicro64 "60006401" "lwle r0, 1(r0)"
    disasmMicro64 "60006402" "lwle r0, 2(r0)"
    disasmMicro64 "60006403" "lwle r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LWM16``() =
    disasmMicro64 "45300c00" "lwm s0, s1, s2, s3, ra, 0(sp)"
    disasmMicro64 "45000c00" "lwm s0, ra, 0(sp)"
    disasmMicro64 "45010c00" "lwm s0, ra, 4(sp)"
    disasmMicro64 "45020c00" "lwm s0, ra, 8(sp)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LWM32``() =
    disasmMicro64 "20225000" "lwm s0, 0(v0)"
    disasmMicro64 "20225001" "lwm s0, 1(v0)"
    disasmMicro64 "20225002" "lwm s0, 2(v0)"
    disasmMicro64 "20225003" "lwm s0, 3(v0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LWP``() =
    disasmMicro64 "20001000" "lwp r0, at, 0(r0)"
    disasmMicro64 "20001001" "lwp r0, at, 1(r0)"
    disasmMicro64 "20001002" "lwp r0, at, 2(r0)"
    disasmMicro64 "20001003" "lwp r0, at, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LWR``() =
    disasmMicro64 "60001000" "lwr r0, 0(r0)"
    disasmMicro64 "60001001" "lwr r0, 1(r0)"
    disasmMicro64 "60001002" "lwr r0, 2(r0)"
    disasmMicro64 "60001003" "lwr r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LWRE``() =
    disasmMicro64 "60006600" "lwre r0, 0(r0)"
    disasmMicro64 "60006601" "lwre r0, 1(r0)"
    disasmMicro64 "60006602" "lwre r0, 2(r0)"
    disasmMicro64 "60006603" "lwre r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LWSP``() =
    disasmMicro64 "48000c00" "lw r0, 0(sp)"
    disasmMicro64 "48010c00" "lw r0, 4(sp)"
    disasmMicro64 "48020c00" "lw r0, 8(sp)"
    disasmMicro64 "48030c00" "lw r0, 12(sp)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LWU``() =
    disasmMicro64 "6000e000" "lwu r0, 0(r0)"
    disasmMicro64 "6000e001" "lwu r0, 1(r0)"
    disasmMicro64 "6000e002" "lwu r0, 2(r0)"
    disasmMicro64 "6000e003" "lwu r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LWXC1``() =
    disasmMicro64 "54000048" "lwxc1 f0, r0(r0)"
    disasmMicro64 "54000848" "lwxc1 f1, r0(r0)"
    disasmMicro64 "54001048" "lwxc1 f2, r0(r0)"
    disasmMicro64 "54001848" "lwxc1 f3, r0(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LWXS``() =
    disasmMicro64 "00000118" "lwxs r0, r0(r0)"
    disasmMicro64 "00000918" "lwxs at, r0(r0)"
    disasmMicro64 "00001118" "lwxs v0, r0(r0)"
    disasmMicro64 "00001918" "lwxs v1, r0(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MADD``() =
    disasmMicro64 "0000cb3c" "madd r0, r0"
    disasmMicro64 "0022cb3c" "madd v0, at"
    disasmMicro64 "03fecb3c" "madd s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MADD.fmt``() =
    disasmMicro64 "54000001" "madd.s f0, f0, f0, f0"
    disasmMicro64 "54000009" "madd.d f0, f0, f0, f0"
    disasmMicro64 "54000011" "madd.ps f0, f0, f0, f0"
    disasmMicro64 "54000041" "madd.s f0, f1, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MADDU``() =
    disasmMicro64 "0000db3c" "maddu r0, r0"
    disasmMicro64 "0022db3c" "maddu v0, at"
    disasmMicro64 "03fedb3c" "maddu s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MFC0``() =
    disasmMicro64 "000000fc" "mfc0 r0, 0x0, 0x0"
    disasmMicro64 "000008fc" "mfc0 r0, 0x0, 0x1"
    disasmMicro64 "000010fc" "mfc0 r0, 0x0, 0x2"
    disasmMicro64 "000018fc" "mfc0 r0, 0x0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MFC1``() =
    disasmMicro64 "5400203b" "mfc1 r0, f0"
    disasmMicro64 "5422203b" "mfc1 at, f2"
    disasmMicro64 "57fe203b" "mfc1 ra, f30"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MFC2``() =
    disasmMicro64 "00004d3c" "mfc2 r0, 0x0"
    disasmMicro64 "00224d3c" "mfc2 at, 0x2"
    disasmMicro64 "03fe4d3c" "mfc2 ra, 0x1e"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MFHC0``() =
    disasmMicro64 "000000f4" "mfhc0 r0, 0x0, 0x0"
    disasmMicro64 "000008f4" "mfhc0 r0, 0x0, 0x1"
    disasmMicro64 "000010f4" "mfhc0 r0, 0x0, 0x2"
    disasmMicro64 "000018f4" "mfhc0 r0, 0x0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MFHC1``() =
    disasmMicro64 "5400303b" "mfhc1 r0, f0"
    disasmMicro64 "5422303b" "mfhc1 at, f2"
    disasmMicro64 "57fe303b" "mfhc1 ra, f30"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MFHC2``() =
    disasmMicro64 "00008d3c" "mfhc2 r0, 0x0"
    disasmMicro64 "00228d3c" "mfhc2 at, 0x2"
    disasmMicro64 "03fe8d3c" "mfhc2 ra, 0x1e"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MFHI``() =
    disasmMicro64 "46000c00" "mfhi r0"
    disasmMicro64 "46010c00" "mfhi at"
    disasmMicro64 "46020c00" "mfhi v0"
    disasmMicro64 "46030c00" "mfhi v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MFHI16``() =
    disasmMicro64 "46000c00" "mfhi r0"
    disasmMicro64 "46010c00" "mfhi at"
    disasmMicro64 "46020c00" "mfhi v0"
    disasmMicro64 "46030c00" "mfhi v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MFLO``() =
    disasmMicro64 "46400c00" "mflo r0"
    disasmMicro64 "46410c00" "mflo at"
    disasmMicro64 "46420c00" "mflo v0"
    disasmMicro64 "46430c00" "mflo v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MFLO16``() =
    disasmMicro64 "46400c00" "mflo r0"
    disasmMicro64 "46410c00" "mflo at"
    disasmMicro64 "46420c00" "mflo v0"
    disasmMicro64 "46430c00" "mflo v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MOV.fmt``() =
    disasmMicro64 "5400007b" "mov.s f0, f0"
    disasmMicro64 "5400207b" "mov.d f0, f0"
    disasmMicro64 "5400407b" "mov.ps f0, f0"
    disasmMicro64 "5422007b" "mov.s f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVE16``() =
    disasmMicro64 "04000c00" "addu s0, s0, s0"
    disasmMicro64 "04020c00" "addu s0, s1, s0"
    disasmMicro64 "04040c00" "addu s0, v0, s0"
    disasmMicro64 "04060c00" "addu s0, v1, s0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVEP``() =
    disasmMicro64 "84000c00" "movep a1, a2, r0, r0"
    disasmMicro64 "84020c00" "movep a1, a2, s1, r0"
    disasmMicro64 "84040c00" "movep a1, a2, v0, r0"
    disasmMicro64 "84060c00" "movep a1, a2, v1, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVF``() =
    disasmMicro64 "5400017b" "movf r0, r0, 0x0"
    disasmMicro64 "5400217b" "movf r0, r0, 0x1"
    disasmMicro64 "5400417b" "movf r0, r0, 0x2"
    disasmMicro64 "5400617b" "movf r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVF.fmt``() =
    disasmMicro64 "54000020" "movf.s f0, f0, 0x0"
    disasmMicro64 "54000220" "movf.d f0, f0, 0x0"
    disasmMicro64 "54000420" "movf.ps f0, f0, 0x0"
    disasmMicro64 "54220020" "movf.s f1, f2, 0x0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVN``() =
    disasmMicro64 "00000018" "movn r0, r0, r0"
    disasmMicro64 "00000818" "movn at, r0, r0"
    disasmMicro64 "00001018" "movn v0, r0, r0"
    disasmMicro64 "00001818" "movn v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVN.fmt``() =
    disasmMicro64 "54000038" "movn.s f0, f0, r0"
    disasmMicro64 "54000138" "movn.d f0, f0, r0"
    disasmMicro64 "54000238" "movn.ps f0, f0, r0"
    disasmMicro64 "54000838" "movn.s f1, f0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVT``() =
    disasmMicro64 "5400097b" "movt r0, r0, 0x0"
    disasmMicro64 "5400297b" "movt r0, r0, 0x1"
    disasmMicro64 "5400497b" "movt r0, r0, 0x2"
    disasmMicro64 "5400697b" "movt r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVT.fmt``() =
    disasmMicro64 "54000060" "movt.s f0, f0, 0x0"
    disasmMicro64 "54000260" "movt.d f0, f0, 0x0"
    disasmMicro64 "54000460" "movt.ps f0, f0, 0x0"
    disasmMicro64 "54220060" "movt.s f1, f2, 0x0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVZ``() =
    disasmMicro64 "00000058" "movz r0, r0, r0"
    disasmMicro64 "00000858" "movz at, r0, r0"
    disasmMicro64 "00001058" "movz v0, r0, r0"
    disasmMicro64 "00001858" "movz v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVZ.fmt``() =
    disasmMicro64 "54000078" "movz.s f0, f0, r0"
    disasmMicro64 "54000178" "movz.d f0, f0, r0"
    disasmMicro64 "54000278" "movz.ps f0, f0, r0"
    disasmMicro64 "54000878" "movz.s f1, f0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MSUB``() =
    disasmMicro64 "0000eb3c" "msub r0, r0"
    disasmMicro64 "0022eb3c" "msub v0, at"
    disasmMicro64 "03feeb3c" "msub s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MSUB.fmt``() =
    disasmMicro64 "54000021" "msub.s f0, f0, f0, f0"
    disasmMicro64 "54000029" "msub.d f0, f0, f0, f0"
    disasmMicro64 "54000031" "msub.ps f0, f0, f0, f0"
    disasmMicro64 "54000061" "msub.s f0, f1, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MSUBU``() =
    disasmMicro64 "0000fb3c" "msubu r0, r0"
    disasmMicro64 "0022fb3c" "msubu v0, at"
    disasmMicro64 "03fefb3c" "msubu s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MTC0``() =
    disasmMicro64 "000002fc" "mtc0 r0, 0x0, 0x0"
    disasmMicro64 "00000afc" "mtc0 r0, 0x0, 0x1"
    disasmMicro64 "000012fc" "mtc0 r0, 0x0, 0x2"
    disasmMicro64 "00001afc" "mtc0 r0, 0x0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MTC1``() =
    disasmMicro64 "5400283b" "mtc1 r0, f0"
    disasmMicro64 "5422283b" "mtc1 at, f2"
    disasmMicro64 "57fe283b" "mtc1 ra, f30"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MTC2``() =
    disasmMicro64 "00005d3c" "mtc2 r0, 0x0"
    disasmMicro64 "00225d3c" "mtc2 at, 0x2"
    disasmMicro64 "03fe5d3c" "mtc2 ra, 0x1e"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MTHC0``() =
    disasmMicro64 "000002f4" "mthc0 r0, 0x0, 0x0"
    disasmMicro64 "00000af4" "mthc0 r0, 0x0, 0x1"
    disasmMicro64 "000012f4" "mthc0 r0, 0x0, 0x2"
    disasmMicro64 "00001af4" "mthc0 r0, 0x0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MTHC1``() =
    disasmMicro64 "5400383b" "mthc1 r0, f0"
    disasmMicro64 "5422383b" "mthc1 at, f2"
    disasmMicro64 "57fe383b" "mthc1 ra, f30"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MTHC2``() =
    disasmMicro64 "00009d3c" "mthc2 r0, 0x0"
    disasmMicro64 "00229d3c" "mthc2 at, 0x2"
    disasmMicro64 "03fe9d3c" "mthc2 ra, 0x1e"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MTHI``() =
    disasmMicro64 "00002d7c" "mthi r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MTLO``() =
    disasmMicro64 "00003d7c" "mtlo r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MUL``() =
    disasmMicro64 "00000210" "mul r0, r0, r0"
    disasmMicro64 "00000a10" "mul at, r0, r0"
    disasmMicro64 "00001210" "mul v0, r0, r0"
    disasmMicro64 "00001a10" "mul v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MUL.fmt``() =
    disasmMicro64 "540000b0" "mul.s f0, f0, f0"
    disasmMicro64 "540001b0" "mul.d f0, f0, f0"
    disasmMicro64 "540002b0" "mul.ps f0, f0, f0"
    disasmMicro64 "540008b0" "mul.s f1, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MULT``() =
    disasmMicro64 "00008b3c" "mult r0, r0"
    disasmMicro64 "00228b3c" "mult v0, at"
    disasmMicro64 "03fe8b3c" "mult s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MULTU``() =
    disasmMicro64 "00009b3c" "multu r0, r0"
    disasmMicro64 "00229b3c" "multu v0, at"
    disasmMicro64 "03fe9b3c" "multu s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 NEG.fmt``() =
    disasmMicro64 "54000b7b" "neg.s f0, f0"
    disasmMicro64 "54002b7b" "neg.d f0, f0"
    disasmMicro64 "54004b7b" "neg.ps f0, f0"
    disasmMicro64 "54220b7b" "neg.s f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 NMADD.fmt``() =
    disasmMicro64 "54000002" "nmadd.s f0, f0, f0, f0"
    disasmMicro64 "5400000a" "nmadd.d f0, f0, f0, f0"
    disasmMicro64 "54000012" "nmadd.ps f0, f0, f0, f0"
    disasmMicro64 "54000042" "nmadd.s f0, f1, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 NMSUB.fmt``() =
    disasmMicro64 "54000022" "nmsub.s f0, f0, f0, f0"
    disasmMicro64 "5400002a" "nmsub.d f0, f0, f0, f0"
    disasmMicro64 "54000032" "nmsub.ps f0, f0, f0, f0"
    disasmMicro64 "54000062" "nmsub.s f0, f1, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 NOP``() =
    disasmMicro64 "00000000" "nop"

  [<TestMethod>]
  member _.``microMIPS64 5.04 NOR``() =
    disasmMicro64 "44130c00" "nor v0, v1, r0"
    disasmMicro64 "44000c00" "nor s0, s0, r0"
    disasmMicro64 "44010c00" "nor s0, s1, r0"
    disasmMicro64 "44020c00" "nor s0, v0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 NOT16``() =
    disasmMicro64 "44130c00" "nor v0, v1, r0"
    disasmMicro64 "44000c00" "nor s0, s0, r0"
    disasmMicro64 "44010c00" "nor s0, s1, r0"
    disasmMicro64 "44020c00" "nor s0, v0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 OR``() =
    disasmMicro64 "0c010c00" "or r0, at, r0"
    disasmMicro64 "0c020c00" "or r0, v0, r0"
    disasmMicro64 "0c030c00" "or r0, v1, r0"
    disasmMicro64 "0c040c00" "or r0, a0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 OR16``() =
    disasmMicro64 "0c010c00" "or r0, at, r0"
    disasmMicro64 "0c020c00" "or r0, v0, r0"
    disasmMicro64 "0c030c00" "or r0, v1, r0"
    disasmMicro64 "0c040c00" "or r0, a0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ORI``() =
    disasmMicro64 "50030000" "ori r0, v1, 0x0"
    disasmMicro64 "50030001" "ori r0, v1, 0x1"
    disasmMicro64 "50037fff" "ori r0, v1, 0x7fff"
    disasmMicro64 "50038000" "ori r0, v1, 0x8000"

  [<TestMethod>]
  member _.``microMIPS64 5.04 PAUSE``() =
    disasmMicro64 "00002800" "pause"

  [<TestMethod>]
  member _.``microMIPS64 5.04 PLL.PS``() =
    disasmMicro64 "54000080" "pll.ps f0, f0, f0"
    disasmMicro64 "54000880" "pll.ps f1, f0, f0"
    disasmMicro64 "54001080" "pll.ps f2, f0, f0"
    disasmMicro64 "54001880" "pll.ps f3, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 PLU.PS``() =
    disasmMicro64 "540000c0" "plu.ps f0, f0, f0"
    disasmMicro64 "540008c0" "plu.ps f1, f0, f0"
    disasmMicro64 "540010c0" "plu.ps f2, f0, f0"
    disasmMicro64 "540018c0" "plu.ps f3, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 PREF``() =
    disasmMicro64 "60002000" "pref 0x0, 0(r0)"
    disasmMicro64 "60002001" "pref 0x0, 1(r0)"
    disasmMicro64 "60002002" "pref 0x0, 2(r0)"
    disasmMicro64 "60002003" "pref 0x0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 PREFE``() =
    disasmMicro64 "6000a400" "prefe 0x0, 0(r0)"
    disasmMicro64 "6000a401" "prefe 0x0, 1(r0)"
    disasmMicro64 "6000a402" "prefe 0x0, 2(r0)"
    disasmMicro64 "6000a403" "prefe 0x0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 PREFX``() =
    disasmMicro64 "540001a0" "prefx 0x0, r0(r0)"
    disasmMicro64 "542201a0" "prefx 0x0, at(v0)"
    disasmMicro64 "57fe01a0" "prefx 0x0, ra(s8)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 PUL.PS``() =
    disasmMicro64 "54000100" "pul.ps f0, f0, f0"
    disasmMicro64 "54000900" "pul.ps f1, f0, f0"
    disasmMicro64 "54001100" "pul.ps f2, f0, f0"
    disasmMicro64 "54001900" "pul.ps f3, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 PUU.PS``() =
    disasmMicro64 "54000140" "puu.ps f0, f0, f0"
    disasmMicro64 "54000940" "puu.ps f1, f0, f0"
    disasmMicro64 "54001140" "puu.ps f2, f0, f0"
    disasmMicro64 "54001940" "puu.ps f3, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 RDHWR``() =
    disasmMicro64 "00006b3c" "rdhwr r0, r0"
    disasmMicro64 "00226b3c" "rdhwr at, v0"
    disasmMicro64 "03fe6b3c" "rdhwr ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 RDPGPR``() =
    disasmMicro64 "0000e17c" "rdpgpr r0, r0"
    disasmMicro64 "0022e17c" "rdpgpr at, v0"
    disasmMicro64 "03fee17c" "rdpgpr ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 RECIP.fmt``() =
    disasmMicro64 "5400123b" "recip.s f0, f0"
    disasmMicro64 "5400523b" "recip.d f0, f0"
    disasmMicro64 "5422123b" "recip.s f1, f2"
    disasmMicro64 "5422523b" "recip.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ROTR``() =
    disasmMicro64 "000000c0" "rotr r0, r0, 0x0"
    disasmMicro64 "000008c0" "rotr r0, r0, 0x1"
    disasmMicro64 "000010c0" "rotr r0, r0, 0x2"
    disasmMicro64 "000018c0" "rotr r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ROTRV``() =
    disasmMicro64 "000000d0" "rotrv r0, r0, r0"
    disasmMicro64 "000008d0" "rotrv at, r0, r0"
    disasmMicro64 "000010d0" "rotrv v0, r0, r0"
    disasmMicro64 "000018d0" "rotrv v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ROUND.L.fmt``() =
    disasmMicro64 "5400333b" "round.l.s f0, f0"
    disasmMicro64 "5400733b" "round.l.d f0, f0"
    disasmMicro64 "5422333b" "round.l.s f1, f2"
    disasmMicro64 "5422733b" "round.l.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ROUND.W.fmt``() =
    disasmMicro64 "54003b3b" "round.w.s f0, f0"
    disasmMicro64 "54007b3b" "round.w.d f0, f0"
    disasmMicro64 "54223b3b" "round.w.s f1, f2"
    disasmMicro64 "54227b3b" "round.w.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 RSQRT.fmt``() =
    disasmMicro64 "5400023b" "rsqrt.s f0, f0"
    disasmMicro64 "5400423b" "rsqrt.d f0, f0"
    disasmMicro64 "5422023b" "rsqrt.s f1, f2"
    disasmMicro64 "5422423b" "rsqrt.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SB``() =
    disasmMicro64 "88000c00" "sb r0, 0(s0)"
    disasmMicro64 "88010c00" "sb r0, 1(s0)"
    disasmMicro64 "88020c00" "sb r0, 2(s0)"
    disasmMicro64 "88030c00" "sb r0, 3(s0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SB16``() =
    disasmMicro64 "88000c00" "sb r0, 0(s0)"
    disasmMicro64 "88010c00" "sb r0, 1(s0)"
    disasmMicro64 "88020c00" "sb r0, 2(s0)"
    disasmMicro64 "88030c00" "sb r0, 3(s0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SBE``() =
    disasmMicro64 "6000a800" "sbe r0, 0(r0)"
    disasmMicro64 "6000a801" "sbe r0, 1(r0)"
    disasmMicro64 "6000a802" "sbe r0, 2(r0)"
    disasmMicro64 "6000a803" "sbe r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SC``() =
    disasmMicro64 "6000b000" "sc r0, 0(r0)"
    disasmMicro64 "6000b001" "sc r0, 1(r0)"
    disasmMicro64 "6000b002" "sc r0, 2(r0)"
    disasmMicro64 "6000b003" "sc r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SCD``() =
    disasmMicro64 "6000f000" "scd r0, 0(r0)"
    disasmMicro64 "6000f001" "scd r0, 1(r0)"
    disasmMicro64 "6000f002" "scd r0, 2(r0)"
    disasmMicro64 "6000f003" "scd r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SCE``() =
    disasmMicro64 "6000ac00" "sce r0, 0(r0)"
    disasmMicro64 "6000ac01" "sce r0, 1(r0)"
    disasmMicro64 "6000ac02" "sce r0, 2(r0)"
    disasmMicro64 "6000ac03" "sce r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SD``() =
    disasmMicro64 "d8030000" "sd r0, 0(v1)"
    disasmMicro64 "d8600000" "sd v1, 0(r0)"
    disasmMicro64 "d8030001" "sd r0, 1(v1)"
    disasmMicro64 "d8600001" "sd v1, 1(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SDBBP``() =
    disasmMicro64 "46c00c00" "sdbbp 0x0"
    disasmMicro64 "46c10c00" "sdbbp 0x1"
    disasmMicro64 "46c20c00" "sdbbp 0x2"
    disasmMicro64 "46c30c00" "sdbbp 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SDBBP16``() =
    disasmMicro64 "46c00c00" "sdbbp 0x0"
    disasmMicro64 "46c10c00" "sdbbp 0x1"
    disasmMicro64 "46c20c00" "sdbbp 0x2"
    disasmMicro64 "46c30c00" "sdbbp 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SDC1``() =
    disasmMicro64 "b8030000" "sdc1 f0, 0(v1)"
    disasmMicro64 "b8600000" "sdc1 f3, 0(r0)"
    disasmMicro64 "b8030001" "sdc1 f0, 1(v1)"
    disasmMicro64 "b8600001" "sdc1 f3, 1(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SDC2``() =
    disasmMicro64 "2000a000" "sdc2 0x0, 0(r0)"
    disasmMicro64 "2000a001" "sdc2 0x0, 1(r0)"
    disasmMicro64 "2000a002" "sdc2 0x0, 2(r0)"
    disasmMicro64 "2000a003" "sdc2 0x0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SDL``() =
    disasmMicro64 "6000c000" "sdl r0, 0(r0)"
    disasmMicro64 "6000c001" "sdl r0, 1(r0)"
    disasmMicro64 "6000c002" "sdl r0, 2(r0)"
    disasmMicro64 "6000c003" "sdl r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SDM``() =
    disasmMicro64 "2022f000" "sdm s0, 0(v0)"
    disasmMicro64 "2022f001" "sdm s0, 1(v0)"
    disasmMicro64 "2022f002" "sdm s0, 2(v0)"
    disasmMicro64 "2022f003" "sdm s0, 3(v0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SDP``() =
    disasmMicro64 "2000c000" "sdp r0, at, 0(r0)"
    disasmMicro64 "2000c001" "sdp r0, at, 1(r0)"
    disasmMicro64 "2000c002" "sdp r0, at, 2(r0)"
    disasmMicro64 "2000c003" "sdp r0, at, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SDR``() =
    disasmMicro64 "6000d000" "sdr r0, 0(r0)"
    disasmMicro64 "6000d001" "sdr r0, 1(r0)"
    disasmMicro64 "6000d002" "sdr r0, 2(r0)"
    disasmMicro64 "6000d003" "sdr r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SDXC1``() =
    disasmMicro64 "54000108" "sdxc1 f0, r0(r0)"
    disasmMicro64 "54000908" "sdxc1 f1, r0(r0)"
    disasmMicro64 "54001108" "sdxc1 f2, r0(r0)"
    disasmMicro64 "54001908" "sdxc1 f3, r0(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SEB``() =
    disasmMicro64 "00002b3c" "seb r0, r0"
    disasmMicro64 "00222b3c" "seb at, v0"
    disasmMicro64 "03fe2b3c" "seb ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SEH``() =
    disasmMicro64 "00003b3c" "seh r0, r0"
    disasmMicro64 "00223b3c" "seh at, v0"
    disasmMicro64 "03fe3b3c" "seh ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SH``() =
    disasmMicro64 "a8000c00" "sh r0, 0(s0)"
    disasmMicro64 "a8010c00" "sh r0, 2(s0)"
    disasmMicro64 "a8020c00" "sh r0, 4(s0)"
    disasmMicro64 "a8030c00" "sh r0, 6(s0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SH16``() =
    disasmMicro64 "a8000c00" "sh r0, 0(s0)"
    disasmMicro64 "a8010c00" "sh r0, 2(s0)"
    disasmMicro64 "a8020c00" "sh r0, 4(s0)"
    disasmMicro64 "a8030c00" "sh r0, 6(s0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SHE``() =
    disasmMicro64 "6000aa00" "she r0, 0(r0)"
    disasmMicro64 "6000aa01" "she r0, 1(r0)"
    disasmMicro64 "6000aa02" "she r0, 2(r0)"
    disasmMicro64 "6000aa03" "she r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SLL``() =
    disasmMicro64 "24000c00" "sll s0, s0, 0x8"
    disasmMicro64 "24020c00" "sll s0, s0, 0x1"
    disasmMicro64 "24040c00" "sll s0, s0, 0x2"
    disasmMicro64 "24060c00" "sll s0, s0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SLL16``() =
    disasmMicro64 "24000c00" "sll s0, s0, 0x8"
    disasmMicro64 "24020c00" "sll s0, s0, 0x1"
    disasmMicro64 "24040c00" "sll s0, s0, 0x2"
    disasmMicro64 "24060c00" "sll s0, s0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SLLV``() =
    disasmMicro64 "00000010" "sllv r0, r0, r0"
    disasmMicro64 "00000810" "sllv at, r0, r0"
    disasmMicro64 "00001010" "sllv v0, r0, r0"
    disasmMicro64 "00001810" "sllv v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SLT``() =
    disasmMicro64 "00000350" "slt r0, r0, r0"
    disasmMicro64 "00000b50" "slt at, r0, r0"
    disasmMicro64 "00001350" "slt v0, r0, r0"
    disasmMicro64 "00001b50" "slt v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SLTI``() =
    disasmMicro64 "90030000" "slti r0, v1, 0x0"
    disasmMicro64 "90600000" "slti v1, r0, 0x0"
    disasmMicro64 "90030001" "slti r0, v1, 0x1"
    disasmMicro64 "90600001" "slti v1, r0, 0x1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SLTIU``() =
    disasmMicro64 "b0030000" "sltiu r0, v1, 0x0"
    disasmMicro64 "b0600000" "sltiu v1, r0, 0x0"
    disasmMicro64 "b0030001" "sltiu r0, v1, 0x1"
    disasmMicro64 "b0600001" "sltiu v1, r0, 0x1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SLTU``() =
    disasmMicro64 "00000390" "sltu r0, r0, r0"
    disasmMicro64 "00000b90" "sltu at, r0, r0"
    disasmMicro64 "00001390" "sltu v0, r0, r0"
    disasmMicro64 "00001b90" "sltu v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SQRT.fmt``() =
    disasmMicro64 "54000a3b" "sqrt.s f0, f0"
    disasmMicro64 "54004a3b" "sqrt.d f0, f0"
    disasmMicro64 "54220a3b" "sqrt.s f1, f2"
    disasmMicro64 "54224a3b" "sqrt.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SRA``() =
    disasmMicro64 "00000080" "sra r0, r0, 0x0"
    disasmMicro64 "00000880" "sra r0, r0, 0x1"
    disasmMicro64 "00001080" "sra r0, r0, 0x2"
    disasmMicro64 "00001880" "sra r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SRAV``() =
    disasmMicro64 "00000090" "srav r0, r0, r0"
    disasmMicro64 "00000890" "srav at, r0, r0"
    disasmMicro64 "00001090" "srav v0, r0, r0"
    disasmMicro64 "00001890" "srav v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SRL``() =
    disasmMicro64 "24010c00" "srl s0, s0, 0x8"
    disasmMicro64 "24030c00" "srl s0, s0, 0x1"
    disasmMicro64 "24050c00" "srl s0, s0, 0x2"
    disasmMicro64 "24070c00" "srl s0, s0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SRL16``() =
    disasmMicro64 "24010c00" "srl s0, s0, 0x8"
    disasmMicro64 "24030c00" "srl s0, s0, 0x1"
    disasmMicro64 "24050c00" "srl s0, s0, 0x2"
    disasmMicro64 "24070c00" "srl s0, s0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SRLV``() =
    disasmMicro64 "00000050" "srlv r0, r0, r0"
    disasmMicro64 "00000850" "srlv at, r0, r0"
    disasmMicro64 "00001050" "srlv v0, r0, r0"
    disasmMicro64 "00001850" "srlv v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SSNOP``() =
    disasmMicro64 "00000800" "ssnop"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SUB``() =
    disasmMicro64 "00220190" "sub r0, v0, at"
    disasmMicro64 "00220990" "sub at, v0, at"
    disasmMicro64 "00221190" "sub v0, v0, at"
    disasmMicro64 "00221990" "sub v1, v0, at"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SUB.fmt``() =
    disasmMicro64 "54000070" "sub.s f0, f0, f0"
    disasmMicro64 "54000170" "sub.d f0, f0, f0"
    disasmMicro64 "54000270" "sub.ps f0, f0, f0"
    disasmMicro64 "54000870" "sub.s f1, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SUBU``() =
    disasmMicro64 "04010c00" "subu s0, s0, s0"
    disasmMicro64 "04030c00" "subu s0, s1, s0"
    disasmMicro64 "04050c00" "subu s0, v0, s0"
    disasmMicro64 "04070c00" "subu s0, v1, s0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SUBU16``() =
    disasmMicro64 "04010c00" "subu s0, s0, s0"
    disasmMicro64 "04030c00" "subu s0, s1, s0"
    disasmMicro64 "04050c00" "subu s0, v0, s0"
    disasmMicro64 "04070c00" "subu s0, v1, s0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SUXC1``() =
    disasmMicro64 "54000188" "suxc1 f0, r0(r0)"
    disasmMicro64 "54000988" "suxc1 f1, r0(r0)"
    disasmMicro64 "54001188" "suxc1 f2, r0(r0)"
    disasmMicro64 "54001988" "suxc1 f3, r0(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SW``() =
    disasmMicro64 "c8000c00" "sw r0, 0(sp)"
    disasmMicro64 "c8010c00" "sw r0, 4(sp)"
    disasmMicro64 "c8020c00" "sw r0, 8(sp)"
    disasmMicro64 "c8030c00" "sw r0, 12(sp)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SW16``() =
    disasmMicro64 "c8000c00" "sw r0, 0(sp)"
    disasmMicro64 "c8010c00" "sw r0, 4(sp)"
    disasmMicro64 "c8020c00" "sw r0, 8(sp)"
    disasmMicro64 "c8030c00" "sw r0, 12(sp)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SWC1``() =
    disasmMicro64 "98030000" "swc1 f0, 0(v1)"
    disasmMicro64 "98600000" "swc1 f3, 0(r0)"
    disasmMicro64 "98030001" "swc1 f0, 1(v1)"
    disasmMicro64 "98600001" "swc1 f3, 1(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SWC2``() =
    disasmMicro64 "20008000" "swc2 0x0, 0(r0)"
    disasmMicro64 "20008001" "swc2 0x0, 1(r0)"
    disasmMicro64 "20008002" "swc2 0x0, 2(r0)"
    disasmMicro64 "20008003" "swc2 0x0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SWE``() =
    disasmMicro64 "6000ae00" "swe r0, 0(r0)"
    disasmMicro64 "6000ae01" "swe r0, 1(r0)"
    disasmMicro64 "6000ae02" "swe r0, 2(r0)"
    disasmMicro64 "6000ae03" "swe r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SWL``() =
    disasmMicro64 "60008000" "swl r0, 0(r0)"
    disasmMicro64 "60008001" "swl r0, 1(r0)"
    disasmMicro64 "60008002" "swl r0, 2(r0)"
    disasmMicro64 "60008003" "swl r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SWLE``() =
    disasmMicro64 "6000a000" "swle r0, 0(r0)"
    disasmMicro64 "6000a001" "swle r0, 1(r0)"
    disasmMicro64 "6000a002" "swle r0, 2(r0)"
    disasmMicro64 "6000a003" "swle r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SWM16``() =
    disasmMicro64 "45400c00" "swm s0, ra, 0(sp)"
    disasmMicro64 "45410c00" "swm s0, ra, 4(sp)"
    disasmMicro64 "45420c00" "swm s0, ra, 8(sp)"
    disasmMicro64 "45430c00" "swm s0, ra, 12(sp)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SWM32``() =
    disasmMicro64 "2022d000" "swm s0, 0(v0)"
    disasmMicro64 "2022d001" "swm s0, 1(v0)"
    disasmMicro64 "2022d002" "swm s0, 2(v0)"
    disasmMicro64 "2022d003" "swm s0, 3(v0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SWP``() =
    disasmMicro64 "20009000" "swp r0, at, 0(r0)"
    disasmMicro64 "20009001" "swp r0, at, 1(r0)"
    disasmMicro64 "20009002" "swp r0, at, 2(r0)"
    disasmMicro64 "20009003" "swp r0, at, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SWR``() =
    disasmMicro64 "60009000" "swr r0, 0(r0)"
    disasmMicro64 "60009001" "swr r0, 1(r0)"
    disasmMicro64 "60009002" "swr r0, 2(r0)"
    disasmMicro64 "60009003" "swr r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SWRE``() =
    disasmMicro64 "6000a200" "swre r0, 0(r0)"
    disasmMicro64 "6000a201" "swre r0, 1(r0)"
    disasmMicro64 "6000a202" "swre r0, 2(r0)"
    disasmMicro64 "6000a203" "swre r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SWSP``() =
    disasmMicro64 "c8000c00" "sw r0, 0(sp)"
    disasmMicro64 "c8010c00" "sw r0, 4(sp)"
    disasmMicro64 "c8020c00" "sw r0, 8(sp)"
    disasmMicro64 "c8030c00" "sw r0, 12(sp)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SWXC1``() =
    disasmMicro64 "54000088" "swxc1 f0, r0(r0)"
    disasmMicro64 "54000888" "swxc1 f1, r0(r0)"
    disasmMicro64 "54001088" "swxc1 f2, r0(r0)"
    disasmMicro64 "54001888" "swxc1 f3, r0(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SYNC``() =
    disasmMicro64 "00006b7c" "sync 0x0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SYNCI``() =
    disasmMicro64 "42030000" "synci 0(v1)"
    disasmMicro64 "42030001" "synci 1(v1)"
    disasmMicro64 "42037fff" "synci 32767(v1)"
    disasmMicro64 "42038000" "synci -32768(v1)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SYSCALL``() =
    disasmMicro64 "00008b7c" "syscall 0x0"
    disasmMicro64 "00228b7c" "syscall 0x22"
    disasmMicro64 "03fe8b7c" "syscall 0x3fe"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TEQ``() =
    disasmMicro64 "0000003c" "teq r0, r0"
    disasmMicro64 "0022003c" "teq v0, at"
    disasmMicro64 "03fe003c" "teq s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TEQI``() =
    disasmMicro64 "41c30000" "teqi v1, 0x0"
    disasmMicro64 "41c30001" "teqi v1, 0x1"
    disasmMicro64 "41c37fff" "teqi v1, 0x7fff"
    disasmMicro64 "41c38000" "teqi v1, 0xffffffffffff8000"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TGE``() =
    disasmMicro64 "0000023c" "tge r0, r0"
    disasmMicro64 "0022023c" "tge v0, at"
    disasmMicro64 "03fe023c" "tge s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TGEI``() =
    disasmMicro64 "41230000" "tgei v1, 0x0"
    disasmMicro64 "41230001" "tgei v1, 0x1"
    disasmMicro64 "41237fff" "tgei v1, 0x7fff"
    disasmMicro64 "41238000" "tgei v1, 0xffffffffffff8000"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TGEIU``() =
    disasmMicro64 "41630000" "tgeiu v1, 0x0"
    disasmMicro64 "41630001" "tgeiu v1, 0x1"
    disasmMicro64 "41637fff" "tgeiu v1, 0x7fff"
    disasmMicro64 "41638000" "tgeiu v1, 0xffffffffffff8000"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TGEU``() =
    disasmMicro64 "0000043c" "tgeu r0, r0"
    disasmMicro64 "0022043c" "tgeu v0, at"
    disasmMicro64 "03fe043c" "tgeu s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TLBP``() =
    disasmMicro64 "0000037c" "tlbp"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TLBR``() =
    disasmMicro64 "0000137c" "tlbr"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TLBWI``() =
    disasmMicro64 "0000237c" "tlbwi"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TLBWR``() =
    disasmMicro64 "0000337c" "tlbwr"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TLT``() =
    disasmMicro64 "0000083c" "tlt r0, r0"
    disasmMicro64 "0022083c" "tlt v0, at"
    disasmMicro64 "03fe083c" "tlt s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TLTI``() =
    disasmMicro64 "41030000" "tlti v1, 0x0"
    disasmMicro64 "41030001" "tlti v1, 0x1"
    disasmMicro64 "41037fff" "tlti v1, 0x7fff"
    disasmMicro64 "41038000" "tlti v1, 0xffffffffffff8000"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TLTIU``() =
    disasmMicro64 "41430000" "tltiu v1, 0x0"
    disasmMicro64 "41430001" "tltiu v1, 0x1"
    disasmMicro64 "41437fff" "tltiu v1, 0x7fff"
    disasmMicro64 "41438000" "tltiu v1, 0xffffffffffff8000"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TLTU``() =
    disasmMicro64 "00000a3c" "tltu r0, r0"
    disasmMicro64 "00220a3c" "tltu v0, at"
    disasmMicro64 "03fe0a3c" "tltu s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TNE``() =
    disasmMicro64 "00000c3c" "tne r0, r0"
    disasmMicro64 "00220c3c" "tne v0, at"
    disasmMicro64 "03fe0c3c" "tne s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TNEI``() =
    disasmMicro64 "41830000" "tnei v1, 0x0"
    disasmMicro64 "41830001" "tnei v1, 0x1"
    disasmMicro64 "41837fff" "tnei v1, 0x7fff"
    disasmMicro64 "41838000" "tnei v1, 0xffffffffffff8000"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TRUNC.L.fmt``() =
    disasmMicro64 "5400233b" "trunc.l.s f0, f0"
    disasmMicro64 "5400633b" "trunc.l.d f0, f0"
    disasmMicro64 "5422233b" "trunc.l.s f1, f2"
    disasmMicro64 "5422633b" "trunc.l.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TRUNC.W.fmt``() =
    disasmMicro64 "54002b3b" "trunc.w.s f0, f0"
    disasmMicro64 "54006b3b" "trunc.w.d f0, f0"
    disasmMicro64 "54222b3b" "trunc.w.s f1, f2"
    disasmMicro64 "54226b3b" "trunc.w.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 WAIT``() =
    disasmMicro64 "0000937c" "wait 0x0"
    disasmMicro64 "0022937c" "wait 0x22"
    disasmMicro64 "03fe937c" "wait 0x3fe"

  [<TestMethod>]
  member _.``microMIPS64 5.04 WRPGPR``() =
    disasmMicro64 "0000f17c" "wrpgpr r0, r0"
    disasmMicro64 "0022f17c" "wrpgpr at, v0"
    disasmMicro64 "03fef17c" "wrpgpr ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 WSBH``() =
    disasmMicro64 "00007b3c" "wsbh r0, r0"
    disasmMicro64 "00227b3c" "wsbh at, v0"
    disasmMicro64 "03fe7b3c" "wsbh ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 XOR``() =
    disasmMicro64 "44400c00" "xor s0, s0, s0"
    disasmMicro64 "44410c00" "xor s0, s0, s1"
    disasmMicro64 "44420c00" "xor s0, s0, v0"
    disasmMicro64 "44430c00" "xor s0, s0, v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 XOR16``() =
    disasmMicro64 "44400c00" "xor s0, s0, s0"
    disasmMicro64 "44410c00" "xor s0, s0, s1"
    disasmMicro64 "44420c00" "xor s0, s0, v0"
    disasmMicro64 "44430c00" "xor s0, s0, v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 XORI``() =
    disasmMicro64 "70030000" "xori r0, v1, 0x0"
    disasmMicro64 "70600000" "xori v1, r0, 0x0"
    disasmMicro64 "70030001" "xori r0, v1, 0x1"
    disasmMicro64 "70600001" "xori v1, r0, 0x1"
