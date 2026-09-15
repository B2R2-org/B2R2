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
    MIPSParser(isa, BinReader.Init Endian.Little) :> IInstructionParsable

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
        "06558020", PLLPS, Some Fmt.PS
        "0655c020", PLUPS, Some Fmt.PS
        "06550021", PULPS, Some Fmt.PS
        "06554021", PUUPS, Some Fmt.PS
        "06558021", CVTPSS, Some Fmt.S
        "86543b29", CVTSPU, Some Fmt.PS
        "86543b21", CVTSPL, Some Fmt.PS
        "06559922", ALNVPS, Some Fmt.PS
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
      MIPSParser(r6, BinReader.Init Endian.Little) :> IInstructionParsable
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
        "8b016050", (LSA, [ O.Reg R10
                            O.Reg R11
                            O.Reg R12
                            O.Imm 1UL ]) ]
    for hex, (opcode, oprs) in cases do
      let bytes = ByteArray.ofHexString hex
      let ins = parser.Parse(System.ReadOnlySpan bytes, 0UL) :?> Instruction
      Assert.AreEqual<Opcode>(opcode, ins.Opcode, hex)
      Assert.AreEqual<Operands>(operandsFromArray oprs, ins.Operands, hex)

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
      MIPSParser(r6, BinReader.Init Endian.Little) :> IInstructionParsable
    let refuses (p: IInstructionParsable) hex =
      let bytes = ByteArray.ofHexString hex
      Assert.ThrowsExactly<ParsingFailureException>(fun () ->
        p.Parse(System.ReadOnlySpan bytes, 0UL) |> ignore
      ) |> ignore
    for hex in [ "6a013c8b"   (* mult *)
                 "4b013c4f"   (* jalrs *)
                 "0a411c23"   (* teqi *)
                 "c4543c47"   (* c.lt.d *)
                 "4b554820" ] (* lwxc1 *) do
      refuses r6Parser hex
    (* LSA is the other way round: Release 6 brought it in. *)
    refuses parser "8b016050"

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
      MIPSParser(r6, BinReader.Init Endian.Little) :> IInstructionParsable
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
      let p = MIPSParser(isa, BinReader.Init isa.Endian)
      let p = p :> IInstructionParsable
      (p.Parse(ByteArray.ofHexString jump, 0UL)).Translate bld |> ignore
      (p.Parse(ByteArray.ofHexString slot, 4UL)).Translate bld
      |> Array.pick (function
        | InterJmp(_, kind) -> Some kind
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
  /// This is what stands in for the round-trip sweep the other encodings
  /// get. There is no microMIPS assembler to sweep against, so what is
  /// checked instead is that the decoder is total: a word it cannot read has
  /// to say so with the one exception a caller is promised, not with an
  /// index that ran off the end of a table, and a word it can read has to
  /// produce an instruction the rest of the front end will accept.
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
      MIPSParser(isa, BinReader.Init Endian.Little) :> IInstructionParsable
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
