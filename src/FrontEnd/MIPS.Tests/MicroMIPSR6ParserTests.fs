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
open B2R2.FrontEnd.MIPS

/// <summary>
/// Release 6 microMIPS, read one manual page at a time.
///
/// Nothing but the manuals reads microMIPS at Release 6 -- binutils refuses
/// the combination and QEMU runs none of it -- so what each method claims is
/// that the encodings match the manual. Every word is built from the field
/// boxes of the page named, with no two registers the same and an immediate's
/// sign bit set where it has one, and the text is what the page's Format line
/// gives, written the way this disassembler writes everything: the opcode the
/// encoding stands for, hexadecimal immediates, registers by their n64 names
/// at word size 64, and a place as the address it names from 0, where each
/// word is read. MD00582 is the microMIPS32 book at revision 6.04 and MD00594
/// the microMIPS64 one at revision 6.01; where they disagree the newer is
/// followed.
/// </summary>
[<TestClass>]
type MicroMIPSR6ParserTests() =
  /// One instruction at a release and a word size, read from big-endian
  /// bytes so that the hex is the word as the manuals draw it.
  let parseAt release wordSize (hex: string) =
    let flags = int MIPSISAMode.MicroMIPS ||| int release
    let isa = ISA(Architecture.MIPS, Endian.Big, wordSize, flags)
    let p = Parser(isa, BinReader.Init Endian.Big) :> IInstructionParsable
    let bytes = ByteArray.ofHexString hex
    p.Parse(System.ReadOnlySpan bytes, 0UL)

  /// What each word reads as in microMIPS64 at Release 6.
  let test (cases: (string * string) list) =
    for hex, text in cases do
      let ins = parseAt MIPSRelease.R6 WordSize.Bit64 hex
      Assert.AreEqual<string>(text, ins.Disasm(), hex)

  let refusesAt wordSize hex =
    Assert.ThrowsExactly<ParsingFailureException>((fun () ->
      parseAt MIPSRelease.R6 wordSize hex |> ignore), hex) |> ignore

  let isa =
    ISA(Architecture.MIPS,
        Endian.Big,
        WordSize.Bit64,
        int MIPSISAMode.MicroMIPS ||| int MIPSRelease.R6)

  let testDisasm (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let parser = Parser(isa, BinReader.Init isa.Endian) :> IInstructionParsable
    let ins = parser.Parse(bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  /// AND16 (MD00582 revision 6.04, p.72): POOL16C, rt in 9..7, rs in 6..4
  /// and the minor 0001 at the bottom. The three-bit fields name $16, $17
  /// and $2 to $7 (Table 5.4), and the instruction is the AND it stands for.
  /// The encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] AND16 decodes (32r6 p.72)``() =
    test [ "44e1", "and s1, s1, a2" ]

  /// BC16 (MD00582 revision 6.04, p.74): ten bits of offset counted in
  /// halfwords from the instruction after this one, "PC &lt;- PC + 2 +
  /// target_offset". 1000000101 is -1014 bytes, so -1012 from here. The
  /// encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] BC16 decodes (32r6 p.74)``() =
    test [ "ce05", "bc 0xfffffffffffffc0c" ]

  /// <summary>
  /// BEQZC16 (MD00582 revision 6.04, p.75): rs in 9..7 and seven bits of
  /// offset. The page's Operation writes "PC &lt;- PC + target_offset", but
  /// its Description adds the offset "to the address of the instruction
  /// following the branch", as BC16's operation does since revision 6.03
  /// (p.392); the place is read that way. 1000011 is -122 bytes, -120 from
  /// here. The encodings match the manual.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS R6] BEQZC16 decodes (32r6 p.75)``() =
    test [ "8fc3", "beqzc a3, 0xffffffffffffff88" ]

  /// BNEZC16 (MD00582 revision 6.04, p.76), BEQZC16's twin: 1010101 is -86
  /// bytes past the next instruction, -84 from here. The encodings match the
  /// manual.
  [<TestMethod>]
  member _.``[microMIPS R6] BNEZC16 decodes (32r6 p.76)``() =
    test [ "acd5", "bnezc s1, 0xffffffffffffffac" ]

  /// BREAK16 (MD00582 revision 6.04, p.77): the code in 9..6 above the minor
  /// 011011. The Format line names no operand; the code field is written as
  /// BREAK's. The encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] BREAK16 decodes (32r6 p.77)``() =
    test [ "469b", "break 0xa" ]

  /// JALRC16 (MD00582 revision 6.04, p.78): rs in 9..5 above the minor
  /// 01011. The encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] JALRC16 decodes (32r6 p.78)``() =
    test [ "462b", "jalrc s1" ]

  /// JRCADDIUSP (MD00582 revision 6.04, p.80): five bits of immediate above
  /// the minor 10011, written as the decoded immediate, the field shifted
  /// left by two: 10110 is 0x58. The encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] JRCADDIUSP decodes (32r6 p.80)``() =
    test [ "46d3", "jrcaddiusp 0x58" ]

  /// JRC16 (MD00582 revision 6.04, p.82): rs in 9..5 above the minor 00011.
  /// The encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] JRC16 decodes (32r6 p.82)``() =
    test [ "4723", "jrc t9" ]

  /// LWM16 (MD00582 revision 6.04, p.91): the list in 9..8, a word count of
  /// offset in 7..4 and the minor 0010. List 10 is $16, $17, $18 and $31,
  /// and offset 1011 is 44 bytes from sp. The encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] LWM16 decodes (32r6 p.91)``() =
    test [ "46b2", "lwm s0, s1, s2, ra, 44(sp)" ]

  /// <summary>
  /// MOVEP (MD00582 revision 6.04, p.96): enc_dest in 9..7, enc_rt in 6..4,
  /// and enc_rs split around the 1 in bit 2, its top bit in bit 3 and its
  /// low two in 1..0. Table 5.14's heading still names the older place,
  /// "Instr3..1"; the field boxes and the revision 6.01 note "MOVEP: in
  /// encoding, changed bit 2 to 1" (p.391) settle it. enc_dest 3 is a0 and
  /// s5, enc_rt 6 is s3 and enc_rs 101 is s2. The encodings match the manual.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS R6] MOVEP decodes (32r6 p.96)``() =
    test [ "45ed", "movep a0, s5, s2, s3" ]

  /// NOT16 (MD00582 revision 6.04, p.98): rt in 9..7, rs in 6..4 and the
  /// minor 0000, written as the NOR against the zero register that it is.
  /// The encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] NOT16 decodes (32r6 p.98)``() =
    test [ "4710", "nor a2, s1, r0" ]

  /// OR16 (MD00582 revision 6.04, p.99): rt, rs and the minor 1001. The
  /// encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] OR16 decodes (32r6 p.99)``() =
    test [ "4789", "or a3, a3, s0" ]

  /// SDBBP16 (MD00582 revision 6.04, p.101): the code in 9..6 above the
  /// minor 111011. The encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] SDBBP16 decodes (32r6 p.101)``() =
    test [ "457b", "sdbbp 0x5" ]

  /// SWM16 (MD00582 revision 6.04, p.108): LWM16's fields with the minor
  /// 1010. List 01 is $16, $17 and $31, and offset 0110 is 24 bytes. The
  /// encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] SWM16 decodes (32r6 p.108)``() =
    test [ "456a", "swm s0, s1, ra, 24(sp)" ]

  /// XOR16 (MD00582 revision 6.04, p.113): rt, rs and the minor 1000. The
  /// encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] XOR16 decodes (32r6 p.113)``() =
    test [ "45d8", "xor v1, v1, a1" ]

  /// <summary>
  /// ADDIUPC (MD00582 revision 6.04, p.119): PCREL, rt in 25..21, the
  /// selector 00 and nineteen bits of word offset, counted from "PC &amp;
  /// ~0x3". 0x40005 is -0xfffec bytes. Before Release 6 the same major held
  /// a three-bit register and twenty-three bits of offset, so only this page
  /// vouches for the word. The encodings match the manual.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS R6] ADDIUPC decodes (32r6 p.119)``() =
    test [ "7ae40005", "addiupc s7, 0xfffffffffff00014" ]

  /// <summary>
  /// ALIGN (MD00582 revision 6.04, p.121): rt in 25..21, rs in 20..16, rd,
  /// and a two-bit bp in 10..9 above 000 and the minor 011111. Revision 6.01
  /// of the microMIPS64 book draws rs above rt for ALIGN and DALIGN alike
  /// (MD00594, p.129); the newer page is followed, and with it the order
  /// every other POOL32A page gives the two. The encodings match the manual.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS R6] ALIGN decodes (32r6 p.121)``() =
    test [ "02666e1f", "align t1, a2, s3, 0x3" ]

  /// DALIGN (MD00594 revision 6.01, p.129): POOL32S, ALIGN's registers, a
  /// three-bit bp in 10..8 above 00 and the minor 011100, rt above rs as in
  /// ALIGN (see ALIGN). microMIPS64 alone has it. The encodings match the
  /// manual.
  [<TestMethod>]
  member _.``[microMIPS R6] DALIGN decodes (64r6 p.129)``() =
    test [ "5a666d1c", "dalign t1, a2, s3, 0x5" ]
    refusesAt WordSize.Bit32 "5a666d1c"

  /// ALUIPC (MD00582 revision 6.04, p.123): PCREL, rt, the selector 11111
  /// and a sixteen-bit immediate. The encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] ALUIPC decodes (32r6 p.123)``() =
    test [ "7adf8004", "aluipc s6, 0x8004" ]

  /// AUI (MD00582 revision 6.04, p.126): the major 000100, rt in 25..21, rs
  /// in 20..16 and a sixteen-bit immediate. ADDI32 had the major before
  /// Release 6. The encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] AUI decodes (32r6 p.126)``() =
    test [ "10f08001", "aui a3, s0, 0x8001" ]

  /// <summary>
  /// DAUI (MD00594 revision 6.01, p.134): the major 111100, rt, rs and a
  /// sixteen-bit immediate. The page's Format block names AUI twice and DAUI
  /// not at all; the field boxes and the Description, "GPR[rt] &lt;- GPR[rs]
  /// + sign_extend(immediate &lt;&lt; 16)", give it. Its rs may not be the
  /// zero register (p.135), and microMIPS64 alone has it. The encodings
  /// match the manual.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS R6] DAUI decodes (64r6 p.134)``() =
    test [ "f0cf8002", "daui a2, t3, 0x8002" ]
    refusesAt WordSize.Bit64 "f0c08002"
    refusesAt WordSize.Bit32 "f0cf8002"

  /// AUIPC (MD00582 revision 6.04, p.127): PCREL, rt, the selector 11110
  /// and a sixteen-bit immediate. The encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] AUIPC decodes (32r6 p.127)``() =
    test [ "7abe8003", "auipc s5, 0x8003" ]

  /// BALC (MD00582 revision 6.04, p.128): the major 101101 and twenty-six
  /// bits of halfword offset from the next instruction. 0x2000003 is
  /// -0x3fffffa bytes. BNE32 had the major before Release 6. The encodings
  /// match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] BALC decodes (32r6 p.128)``() =
    test [ "b6000003", "balc 0xfffffffffc00000a" ]

  /// <summary>
  /// BC1EQZC and BC1NEZC (MD00582 revision 6.04, p.129): POOL32I, the minors
  /// 01000 and 01001 in 25..21, ft and sixteen bits of halfword offset. The
  /// boxes print POOL32I as 010001, which is no pool at all; Table 7.2
  /// (p.372) and every other POOL32I page, SYNCI's among them, put it at
  /// 010000. The encodings match the manual.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS R6] BC1EQZC BC1NEZC decode (32r6 p.129)``() =
    test [ "41078005", "bc1eqzc f7, 0xffffffffffff000e"
           "412c0010", "bc1nezc f12, 0x24" ]

  /// BC2EQZC and BC2NEZC (MD00582 revision 6.04, p.131): POOL32I, the minors
  /// 01010 and 01011, a five-bit condition number ct and sixteen bits of
  /// offset. The encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] BC2EQZC BC2NEZC decode (32r6 p.131)``() =
    test [ "41498006", "bc2eqzc 0x9, 0xffffffffffff0010"
           "417e0021", "bc2nezc 0x1e, 0x46" ]

  /// <summary>
  /// The compact zero-compare branch-and-links (MD00582 revision 6.04,
  /// p.133). POP60 holds BLEZALC (rs zero) and BGEZALC (rs equal to rt),
  /// POP70 BGTZALC and BLTZALC the same way, and POP35 and POP37 BEQZALC and
  /// BNEZALC (rs zero), rt being bits 25..21 and rs 20..16. The boxes label
  /// the last two "rs &lt; rt", which they hold since rs is zero. The
  /// encodings match the manual.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS R6] The ZALC branches decode (32r6 p.133)``() =
    test [ "c0c08007", "blezalc a2, 0xffffffffffff0012"
           "c2520030", "bgezalc s2, 0x64"
           "e180ffff", "bgtzalc t0, 0x2"
           "e3de0001", "bltzalc s8, 0x6"
           "75208000", "beqzalc a5, 0xffffffffffff0004"
           "7f801234", "bnezalc gp, 0x246c" ]

  /// <summary>
  /// The compact compare branches (MD00582 revision 6.04, p.135), told apart
  /// by their two register fields: zero in rs (20..16) for the compare with
  /// zero, rs equal to rt for the other compare with zero, and two different
  /// registers for the register-register form, which on POP35 and POP37 must
  /// have rs below rt. BEQZC and BNEZC are POP40 and POP50 with rs in
  /// 25..21 and twenty-one bits of offset. The Format Details write "BEQZC
  /// rt, rs, offset" for a branch on GPR[rs] alone; it takes one register.
  /// The encodings match the manual.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS R6] The compact branches decode (32r6 p.135)``() =
    test [ "f4e08008", "blezc a3, 0xffffffffffff0014"
           "f6310002", "bgezc s1, 0x8"
           "f48d8009", "bgec t1, a0, 0xffffffffffff0016"
           "d4600003", "bgtzc v1, 0xa"
           "d6d6800a", "bltzc s6, 0xffffffffffff0018"
           "d4570004", "bltc s7, v0, 0xc"
           "c0b8800b", "bgeuc t8, a1, 0xffffffffffff001a"
           "e2140005", "bltuc s4, s0, 0xe"
           "75c6800c", "beqc a2, t2, 0xffffffffffff001c"
           "7feb0006", "bnec a7, ra, 0x10"
           "82700007", "beqzc s3, 0xffffffffffe00012"
           "a1000040", "bnezc a4, 0x84" ]

  /// BC (MD00582 revision 6.04, p.138): the major 100101 and twenty-six bits
  /// of halfword offset. BEQ32 had the major before Release 6. The encodings
  /// match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] BC decodes (32r6 p.138)``() =
    test [ "96000101", "bc 0xfffffffffc000206" ]

  /// BREAK (MD00582 revision 6.04, p.139): POOL32A, twenty bits of code and
  /// the minor 000111. The encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] BREAK decodes (32r6 p.139)``() =
    test [ "026af347", "break 0x9abcd" ]

  /// BITSWAP (MD00582 revision 6.04, p.140): POOL32A, rt in 25..21, rd in
  /// 20..16, 0000, the minor 101100 and POOL32Axf. The encodings match the
  /// manual.
  [<TestMethod>]
  member _.``[microMIPS R6] BITSWAP decodes (32r6 p.140)``() =
    test [ "01f10b3c", "bitswap s1, t3" ]

  /// DBITSWAP (MD00594 revision 6.01, p.152): BITSWAP's fields in POOL32S.
  /// microMIPS64 alone has it. The encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] DBITSWAP decodes (64r6 p.152)``() =
    test [ "59560b3c", "dbitswap s6, a6" ]
    refusesAt WordSize.Bit32 "59560b3c"

  /// <summary>
  /// BOVC and BNVC (MD00582 revision 6.04, p.142): POP35 and POP37 with rs,
  /// bits 20..16, no lower than rt, bits 25..21, and BNVC may name the zero
  /// register as rt. The Format line writes "BOVC rt,rs, offset", the first
  /// field first; the text keeps rs first, as BEQC and BNEC on the same two
  /// majors write it and as the microMIPS64 page's own note, "BOVC
  /// rs,r0,offset" (MD00594 revision 6.01, p.154), does. The sum is the same
  /// either way round. The encodings match the manual.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS R6] BOVC BNVC decode (32r6 p.142)``() =
    test [ "7489800d", "bovc a5, a0, 0xffffffffffff001e"
           "7c150007", "bnvc s5, r0, 0x12" ]

  /// CACHE (MD00582 revision 6.04, p.144): POOL32B, op in 25..21, base, the
  /// minor 0110, 000 and nine bits of offset, sign-extended. The encodings
  /// match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] CACHE decodes (32r6 p.144)``() =
    test [ "22a561f0", "cache 0x15, -16(a1)" ]

  /// CLASS.fmt (MD00582 revision 6.04, p.161): POOL32F, fs in 25..21, fd in
  /// 20..16, 00000, fmt in 10..9 (01 is D) and the minor 001100000. The
  /// encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] CLASS.fmt decodes (32r6 p.161)``() =
    test [ "553a0260", "class.d f26, f9" ]

  /// <summary>
  /// CMP.condn.fmt (MD00582 revision 6.04, p.165): POOL32F, ft, fs, fd, the
  /// five-bit condn and 000101 for S or 010101 for D. Table 5.23 (pp.167-168)
  /// names the conditions: 01101 is SULT, signalling unordered or less than,
  /// and 10011 is NE, the negation of quiet unordered or equal. The
  /// encodings match the manual.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS R6] CMP.condn.fmt decodes (32r6 p.165)``() =
    test [ "55658b45", "cmp.sult.s f17, f5, f11"
           "543e44d5", "cmp.ne.d f8, f30, f1" ]

  /// DVP (MD00582 revision 6.04, p.185): POOL32A, 00000, rs, the minor
  /// 0001100101 and POOL32Axf. The encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] DVP decodes (32r6 p.185)``() =
    test [ "000c197c", "dvp t0" ]

  /// EVP (MD00582 revision 6.04, p.196): DVP's fields with the minor
  /// 0011100101. The encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] EVP decodes (32r6 p.196)``() =
    test [ "001a397c", "evp k0" ]

  /// JIALC (MD00582 revision 6.04, p.207): POP50, 00000 in 25..21, rt in
  /// 20..16 and a sixteen-bit offset added unshifted. The encodings match
  /// the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] JIALC decodes (32r6 p.207)``() =
    test [ "a0198011", "jialc t9, 0xffffffffffff8011" ]

  /// JIC (MD00582 revision 6.04, p.209): POP40 with JIALC's fields. The
  /// encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] JIC decodes (32r6 p.209)``() =
    test [ "8007fff1", "jic a3, 0xfffffffffffffff1" ]

  /// LL (MD00582 revision 6.04, p.221): POOL32C, rt, base, the minor 0011,
  /// 000 and nine bits of offset, sign-extended. The encodings match the
  /// manual.
  [<TestMethod>]
  member _.``[microMIPS R6] LL decodes (32r6 p.221)``() =
    test [ "624c31a5", "ll s2, -91(t0)" ]

  /// <summary>
  /// LLWP (MD00582 revision 6.04, p.226): POOL32C, rt, base, the minor 0001,
  /// 000, rd in 8..4 and 0000, and no offset; the Format line's "(base)" is
  /// written as an offset of 0. The encodings match the manual.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS R6] LLWP decodes (32r6 p.226)``() =
    test [ "607010e0", "llwp v1, t2, 0(s0)" ]

  /// <summary>
  /// The slot LLWP took from the extended family.
  ///
  /// Revision 6.01 of the microMIPS64 book gives POOL32C's minor 0001 over
  /// 000 to LLX and 0101 over 000 to LLDX (MD00594, p.273), where the newer
  /// microMIPS32 book gives 0001 to LLWP (MD00582 revision 6.04, p.226). That
  /// book's history says why: revision 6.04 "Removed the LLX, LLXE, SCX, and
  /// SCXE instructions" and, for microMIPS64, "Removed the LLDX and SCDX
  /// instructions" in favour of the paired ones (p.392). So 0001 is LLWP at
  /// both word sizes, and 0101 is refused: the 6.04 book marks it as an
  /// encoding of a higher ISA level (Table 7.10, p.377), and no book after
  /// 6.01 says what microMIPS64 reads there. Table 7.10 also marks row 001
  /// reserved, against LLWP's own page; the page is followed.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS R6] LLWP holds LLX's slot, not LLDX's (64r6 p.273)``() =
    test [ "607010e0", "llwp v1, t2, 0(s0)" ]
    let narrow = parseAt MIPSRelease.R6 WordSize.Bit32 "607010e0"
    Assert.AreEqual<string>("llwp v1, t6, 0(s0)", narrow.Disasm())
    for wordSize in [ WordSize.Bit32; WordSize.Bit64 ] do
      refusesAt wordSize "60705010"

  /// <summary>
  /// The rest of the extended family revision 6.01 drew and 6.04 removed
  /// (MD00594, pp.273 and 353; MD00582, p.392). LLXE's slot, LD-EVA 0110 over
  /// 010, is LLWPE's, and SCXE's, ST-EVA 1010 over 000, is SCWPE's. The SCX
  /// page gives SCX and SCDX the codes of LLX and LLDX, 0001 and 0101, which
  /// a store cannot share with a load; the store conditional's own slot,
  /// 1001, holds SCWP, and 0101 is refused at both word sizes (above).
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS R6] LLXE, SCX, SCXE and SCDX slots (64r6 p.353)``() =
    test [ "630764d0", "llwpe t8, t1, 0(a3)"
           "617d9020", "scwp a7, v0, 0(sp)"
           "6264a1e0", "scwpe s3, s8, 0(a0)" ]
    for wordSize in [ WordSize.Bit32; WordSize.Bit64 ] do
      refusesAt wordSize "60705010"

  /// LLWPE (MD00582 revision 6.04, p.228): POOL32C, rt, base, LD-EVA 0110,
  /// the minor 010, rd and 0000. The encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] LLWPE decodes (32r6 p.228)``() =
    test [ "630764d0", "llwpe t8, t1, 0(a3)" ]

  /// <summary>
  /// LSA (MD00582 revision 6.04, p.230): POOL32A, rt in 25..21, rs in
  /// 20..16, rd, the two-bit sa in 10..9, 000 and the minor 001111; the
  /// shift is sa + 1. The Format line writes "LSA rt, rs, rd, sa", in the
  /// order of the fields; the text keeps the destination first, as the
  /// Description, "GPR[rd] &lt;- sign_extend.32((GPR[rs] &lt;&lt; (sa+1)) +
  /// GPR[rt])", and the 32-bit encoding's LSA write it. The encodings match
  /// the manual.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS R6] LSA decodes (32r6 p.230)``() =
    test [ "02854c0f", "lsa a5, a1, s4, 0x2" ]

  /// LUI (MD00582 revision 6.04, p.231): AUI with rs zero, which Release 6
  /// writes as LUI. The encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] LUI decodes (32r6 p.231)``() =
    test [ "13008765", "lui t8, 0x8765" ]

  /// LWC2 (MD00582 revision 6.04, p.234): POOL32B, rt, base, the minor 0000,
  /// a clear bit 11 and eleven bits of offset, sign-extended: 0x404 is
  /// -1020. The encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] LWC2 decodes (32r6 p.234)``() =
    test [ "21a30404", "lwc2 0xd, -1020(v1)" ]

  /// LWPC (MD00582 revision 6.04, p.236): PCREL, rt, the selector 01 and
  /// nineteen bits of word offset from "PC &amp; ~0x3": 0x40003 is
  /// -0xffff4. The encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] LWPC decodes (32r6 p.236)``() =
    test [ "78ac0003", "lwpc a1, 0xfffffffffff0000c" ]

  /// LDPC (MD00594 revision 6.01, p.262): PCREL, rt, the selector 110 and
  /// eighteen bits of doubleword offset: 0x20009 is -0xfffb8. microMIPS64
  /// alone has it. The encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] LDPC decodes (64r6 p.262)``() =
    test [ "7a9a0009", "ldpc s4, 0xfffffffffff00048" ]
    refusesAt WordSize.Bit32 "7a9a0009"

  /// LWUPC (MD00594 revision 6.01, p.291): PCREL, rt, the selector 10 and
  /// nineteen bits of word offset: 0x40007 is -0xfffe4. microMIPS64 alone
  /// has it. The encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] LWUPC decodes (64r6 p.291)``() =
    test [ "79d40007", "lwupc t2, 0xfffffffffff0001c" ]
    refusesAt WordSize.Bit32 "79d40007"

  /// MADDF.fmt and MSUBF.fmt (MD00582 revision 6.04, p.237): POOL32F, ft,
  /// fs, fd, fmt in 10..9 and the minors 110111000 and 111111000. The
  /// encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] MADDF MSUBF decode (32r6 p.237)``() =
    test [ "548231b8", "maddf.s f6, f2, f4"
           "554e93f8", "msubf.d f18, f14, f10" ]

  /// MAX.fmt, MAXA.fmt, MIN.fmt and MINA.fmt (MD00582 revision 6.04,
  /// p.239): POOL32F's ternary fields with the minors 000001011, 000101011,
  /// 000000011 and 000100011. The encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] MAX MAXA MIN MINA decode (32r6 p.239)``() =
    test [ "54670a0b", "max.d f1, f7, f3"
           "55a9282b", "maxa.s f5, f9, f13"
           "5690c003", "min.s f24, f16, f20"
           "57fdda23", "mina.d f27, f29, f31" ]

  /// PREF (MD00582 revision 6.04, p.266): POOL32C, hint, base, the minor
  /// 0010, 000 and nine bits of offset, sign-extended. The encodings match
  /// the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] PREF decodes (32r6 p.266)``() =
    test [ "63d121fc", "pref 0x1e, -4(s1)" ]

  /// <summary>
  /// RDHWR (MD00582 revision 6.04, p.274): POOL32A, rt, rs, 00, the
  /// three-bit sel in 13..11, a clear bit 10 and the minor 0111000000. The
  /// hardware register is written by its number's general register name,
  /// $29 as sp. The encodings match the manual.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS R6] RDHWR decodes (32r6 p.274)``() =
    test [ "011d29c0", "rdhwr a4, sp, 0x5" ]

  /// RINT.fmt (MD00582 revision 6.04, p.279): POOL32F, fs in 25..21, fd in
  /// 20..16, 00000, fmt and the minor 000100000. The encodings match the
  /// manual.
  [<TestMethod>]
  member _.``[microMIPS R6] RINT.fmt decodes (32r6 p.279)``() =
    test [ "55870220", "rint.d f7, f12" ]

  /// SC (MD00582 revision 6.04, p.288): LL's fields with the minor 1011. The
  /// encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] SC decodes (32r6 p.288)``() =
    test [ "6155b101", "sc a6, -255(s5)" ]

  /// SCWP (MD00582 revision 6.04, p.294): LLWP's fields with the minor 1001.
  /// The encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] SCWP decodes (32r6 p.294)``() =
    test [ "617d9020", "scwp a7, v0, 0(sp)" ]

  /// SCWPE (MD00582 revision 6.04, p.298): ST-EVA 1010 and the minor 000
  /// with LLWPE's fields. The encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] SCWPE decodes (32r6 p.298)``() =
    test [ "6264a1e0", "scwpe s3, s8, 0(a0)" ]

  /// SDBBP (MD00582 revision 6.04, p.301): POOL32A, ten bits of code in
  /// 25..16, the minor 1101101101 and POOL32Axf. The encodings match the
  /// manual.
  [<TestMethod>]
  member _.``[microMIPS R6] SDBBP decodes (32r6 p.301)``() =
    test [ "02c5db7c", "sdbbp 0x2c5" ]

  /// SEL.fmt (MD00582 revision 6.04, p.306): POOL32F's ternary fields with
  /// the minor 010111000. The Format line's "SEL fd, fs, ft, fmt" is written
  /// with the format on the mnemonic. The encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] SEL.fmt decodes (32r6 p.306)``() =
    test [ "54c852b8", "sel.d f10, f8, f6" ]

  /// SELEQZ and SELNEZ (MD00582 revision 6.04, p.307): POOL32A, rt, rs, rd,
  /// a clear bit 10 and the minors 0101000000 and 0110000000. The encodings
  /// match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] SELEQZ SELNEZ decode (32r6 p.307)``() =
    test [ "02e44940", "seleqz a5, a0, s7"
           "005f7980", "selnez t3, ra, v0" ]

  /// <summary>
  /// SELEQZ.fmt and SELNEQZ.fmt (MD00582 revision 6.04, p.309): POOL32F's
  /// ternary fields with the minors 000111000 and 001111000. The page's
  /// heading names the second SELNEQZ.fmt and its Format lines SELNEZ.S and
  /// SELNEZ.D; the heading's name is kept, which keeps it apart from the
  /// integer SELNEZ. The encodings match the manual.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS R6] SELEQZ.fmt SELNEQZ.fmt decode (32r6 p.309)``() =
    test [ "55e3a838", "seleqz.s f21, f3, f15"
           "57335a78", "selneqz.d f11, f19, f25" ]

  /// SIGRIE (MD00582 revision 6.04, p.313): POOL32A, 0000, sixteen bits of
  /// code in 21..6 and the minor 111111. The encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] SIGRIE decodes (32r6 p.313)``() =
    test [ "002fbbff", "sigrie 0xbeef" ]

  /// SWC2 (MD00582 revision 6.04, p.332): LWC2's fields with the minor 1000:
  /// 0x7ff is -1. The encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] SWC2 decodes (32r6 p.332)``() =
    test [ "236887ff", "swc2 0x1b, -1(a4)" ]

  /// TLBINV (MD00582 revision 6.04, p.346): POOL32A, ten clear bits, the
  /// minor 0100001101 and POOL32Axf. The encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] TLBINV decodes (32r6 p.346)``() =
    test [ "0000437c", "tlbinv" ]

  /// TLBINVF (MD00582 revision 6.04, p.349): TLBINV's fields with the minor
  /// 0101001101. The encodings match the manual.
  [<TestMethod>]
  member _.``[microMIPS R6] TLBINVF decodes (32r6 p.349)``() =
    test [ "0000537c", "tlbinvf" ]

  (* One test for each Release 6 microMIPS instruction microMIPS64 6.01 and
     microMIPS32 6.04 describes, in the order of its sections. Each reads words
     of the instruction and checks the text, and each word is one binutils'
     objdump reads as the same instruction with the same operands, so what is
     asserted is a reading two decoders agree on. Where the page keeps the
     encoding Release 6 inherited, binutils' pre-Release-6 reading is the second
     decoder. *)
  [<TestMethod>]
  member _.``microMIPS64 6.01 ABS.fmt``() =
    testDisasm "5400037b" "abs.s f0, f0"
    testDisasm "5400237b" "abs.d f0, f0"
    testDisasm "5400437b" "abs.ps f0, f0"
    testDisasm "5422037b" "abs.s f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 6.01 ADD``() =
    testDisasm "00000110" "add r0, r0, r0"
    testDisasm "00000910" "add at, r0, r0"
    testDisasm "00001110" "add v0, r0, r0"
    testDisasm "00001910" "add v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 ADD.fmt``() =
    testDisasm "54000030" "add.s f0, f0, f0"
    testDisasm "54000130" "add.d f0, f0, f0"
    testDisasm "54000230" "add.ps f0, f0, f0"
    testDisasm "54000830" "add.s f1, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 ADDIU``() =
    testDisasm "4c000c00" "addiu r0, r0, 0x0"
    testDisasm "4c010c00" "addiu sp, sp, 0x400"
    testDisasm "4c020c00" "addiu r0, r0, 0x1"
    testDisasm "4c030c00" "addiu sp, sp, 0x404"

  [<TestMethod>]
  member _.``microMIPS64 6.01 ADDIUR1SP``() =
    testDisasm "4c000c00" "addiu r0, r0, 0x0"
    testDisasm "4c010c00" "addiu sp, sp, 0x400"
    testDisasm "4c020c00" "addiu r0, r0, 0x1"
    testDisasm "4c030c00" "addiu sp, sp, 0x404"

  [<TestMethod>]
  member _.``microMIPS64 6.01 ADDIUR2``() =
    testDisasm "4c000c00" "addiu r0, r0, 0x0"
    testDisasm "4c010c00" "addiu sp, sp, 0x400"
    testDisasm "4c020c00" "addiu r0, r0, 0x1"
    testDisasm "4c030c00" "addiu sp, sp, 0x404"

  [<TestMethod>]
  member _.``microMIPS64 6.01 ADDIUS5``() =
    testDisasm "4c000c00" "addiu r0, r0, 0x0"
    testDisasm "4c010c00" "addiu sp, sp, 0x400"
    testDisasm "4c020c00" "addiu r0, r0, 0x1"
    testDisasm "4c030c00" "addiu sp, sp, 0x404"

  [<TestMethod>]
  member _.``microMIPS64 6.01 ADDIUSP``() =
    testDisasm "4c000c00" "addiu r0, r0, 0x0"
    testDisasm "4c010c00" "addiu sp, sp, 0x400"
    testDisasm "4c020c00" "addiu r0, r0, 0x1"
    testDisasm "4c030c00" "addiu sp, sp, 0x404"

  [<TestMethod>]
  member _.``microMIPS64 6.01 ADDU``() =
    testDisasm "04000c00" "addu s0, s0, s0"
    testDisasm "04100c00" "addu s0, s0, s1"
    testDisasm "04200c00" "addu s0, s0, v0"
    testDisasm "04300c00" "addu s0, s0, v1"

  [<TestMethod>]
  member _.``microMIPS64 6.01 AND``() =
    testDisasm "00000250" "and r0, r0, r0"
    testDisasm "00000a50" "and at, r0, r0"
    testDisasm "00001250" "and v0, r0, r0"
    testDisasm "00001a50" "and v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 ANDI``() =
    testDisasm "2c000c00" "andi s0, s0, 0x80"
    testDisasm "2c010c00" "andi s0, s0, 0x1"
    testDisasm "2c020c00" "andi s0, s0, 0x2"
    testDisasm "2c030c00" "andi s0, s0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 6.01 ANDI16``() =
    testDisasm "2c000c00" "andi s0, s0, 0x80"
    testDisasm "2c010c00" "andi s0, s0, 0x1"
    testDisasm "2c020c00" "andi s0, s0, 0x2"
    testDisasm "2c030c00" "andi s0, s0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 6.01 CACHE``() =
    testDisasm "20006000" "cache 0x0, 0(r0)"
    testDisasm "20006001" "cache 0x0, 1(r0)"
    testDisasm "20006002" "cache 0x0, 2(r0)"
    testDisasm "20006003" "cache 0x0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 CACHEE``() =
    testDisasm "6000a600" "cachee 0x0, 0(r0)"
    testDisasm "6000a601" "cachee 0x0, 1(r0)"
    testDisasm "6000a602" "cachee 0x0, 2(r0)"
    testDisasm "6000a603" "cachee 0x0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 CEIL.L.fmt``() =
    testDisasm "5400133b" "ceil.l.s f0, f0"
    testDisasm "5400533b" "ceil.l.d f0, f0"
    testDisasm "5422133b" "ceil.l.s f1, f2"
    testDisasm "5422533b" "ceil.l.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 6.01 CEIL.W.fmt``() =
    testDisasm "54001b3b" "ceil.w.s f0, f0"
    testDisasm "54005b3b" "ceil.w.d f0, f0"
    testDisasm "54221b3b" "ceil.w.s f1, f2"
    testDisasm "54225b3b" "ceil.w.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 6.01 CFC1``() =
    testDisasm "5400103b" "cfc1 r0, f0"
    testDisasm "5422103b" "cfc1 at, f2"
    testDisasm "57fe103b" "cfc1 ra, f30"

  [<TestMethod>]
  member _.``microMIPS64 6.01 CFC2``() =
    testDisasm "0000cd3c" "cfc2 r0, 0x0"
    testDisasm "0022cd3c" "cfc2 at, 0x2"
    testDisasm "03fecd3c" "cfc2 ra, 0x1e"

  [<TestMethod>]
  member _.``microMIPS64 6.01 CLO``() =
    testDisasm "00004b3c" "clo r0, r0"
    testDisasm "00224b3c" "clo at, v0"
    testDisasm "03fe4b3c" "clo ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 6.01 CLZ``() =
    testDisasm "00005b3c" "clz r0, r0"
    testDisasm "00225b3c" "clz at, v0"
    testDisasm "03fe5b3c" "clz ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 6.01 COP2``() =
    testDisasm "00000002" "cop2 0x0"
    testDisasm "0000000a" "cop2 0x1"
    testDisasm "00000012" "cop2 0x2"
    testDisasm "0000001a" "cop2 0x3"

  [<TestMethod>]
  member _.``microMIPS64 6.01 CTC1``() =
    testDisasm "5400183b" "ctc1 r0, f0"
    testDisasm "5422183b" "ctc1 at, f2"
    testDisasm "57fe183b" "ctc1 ra, f30"

  [<TestMethod>]
  member _.``microMIPS64 6.01 CTC2``() =
    testDisasm "0000dd3c" "ctc2 r0, 0x0"
    testDisasm "0022dd3c" "ctc2 at, 0x2"
    testDisasm "03fedd3c" "ctc2 ra, 0x1e"

  [<TestMethod>]
  member _.``microMIPS64 6.01 CVT.D.fmt``() =
    testDisasm "5400137b" "cvt.d.s f0, f0"
    testDisasm "5400337b" "cvt.d.w f0, f0"
    testDisasm "5400537b" "cvt.d.l f0, f0"
    testDisasm "5422137b" "cvt.d.s f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 6.01 CVT.L.fmt``() =
    testDisasm "5400013b" "cvt.l.s f0, f0"
    testDisasm "5400413b" "cvt.l.d f0, f0"
    testDisasm "5422013b" "cvt.l.s f1, f2"
    testDisasm "5422413b" "cvt.l.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 6.01 CVT.S.fmt``() =
    testDisasm "54001b7b" "cvt.s.d f0, f0"
    testDisasm "54003b7b" "cvt.s.w f0, f0"
    testDisasm "54005b7b" "cvt.s.l f0, f0"
    testDisasm "54221b7b" "cvt.s.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 6.01 CVT.W.fmt``() =
    testDisasm "5400093b" "cvt.w.s f0, f0"
    testDisasm "5400493b" "cvt.w.d f0, f0"
    testDisasm "5422093b" "cvt.w.s f1, f2"
    testDisasm "5422493b" "cvt.w.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DADD``() =
    testDisasm "58000110" "dadd r0, r0, r0"
    testDisasm "58000910" "dadd at, r0, r0"
    testDisasm "58001110" "dadd v0, r0, r0"
    testDisasm "58001910" "dadd v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DADDIU``() =
    testDisasm "5c030000" "daddiu r0, v1, 0x0"
    testDisasm "5c600000" "daddiu v1, r0, 0x0"
    testDisasm "5c030001" "daddiu r0, v1, 0x1"
    testDisasm "5c600001" "daddiu v1, r0, 0x1"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DADDU``() =
    testDisasm "58220150" "daddu r0, v0, at"
    testDisasm "58220950" "daddu at, v0, at"
    testDisasm "58221150" "daddu v0, v0, at"
    testDisasm "58221950" "daddu v1, v0, at"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DCLO``() =
    testDisasm "58004b3c" "dclo r0, r0"
    testDisasm "58224b3c" "dclo at, v0"
    testDisasm "5bfe4b3c" "dclo ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DCLZ``() =
    testDisasm "58005b3c" "dclz r0, r0"
    testDisasm "58225b3c" "dclz at, v0"
    testDisasm "5bfe5b3c" "dclz ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DERET``() =
    testDisasm "0000e37c" "deret"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DEXT``() =
    testDisasm "5800002c" "dext r0, r0, 0x0, 0x1"
    testDisasm "5800006c" "dext r0, r0, 0x1, 0x1"
    testDisasm "580000ac" "dext r0, r0, 0x2, 0x1"
    testDisasm "580000ec" "dext r0, r0, 0x3, 0x1"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DEXTM``() =
    testDisasm "58000024" "dextm r0, r0, 0x0, 0x21"
    testDisasm "58000064" "dextm r0, r0, 0x1, 0x21"
    testDisasm "580000a4" "dextm r0, r0, 0x2, 0x21"
    testDisasm "580000e4" "dextm r0, r0, 0x3, 0x21"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DEXTU``() =
    testDisasm "58000014" "dextu r0, r0, 0x20, 0x1"
    testDisasm "58000054" "dextu r0, r0, 0x21, 0x1"
    testDisasm "58000094" "dextu r0, r0, 0x22, 0x1"
    testDisasm "580000d4" "dextu r0, r0, 0x23, 0x1"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DI``() =
    testDisasm "0000477c" "di r0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DINS``() =
    testDisasm "5800000c" "dins r0, r0, 0x0, 0x1"
    testDisasm "5800080c" "dins r0, r0, 0x0, 0x2"
    testDisasm "5800084c" "dins r0, r0, 0x1, 0x1"
    testDisasm "5800100c" "dins r0, r0, 0x0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DINSM``() =
    testDisasm "58000004" "dinsm r0, r0, 0x0, 0x21"
    testDisasm "58000044" "dinsm r0, r0, 0x1, 0x20"
    testDisasm "58000084" "dinsm r0, r0, 0x2, 0x1f"
    testDisasm "580000c4" "dinsm r0, r0, 0x3, 0x1e"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DINSU``() =
    testDisasm "58000034" "dinsu r0, r0, 0x20, 0x1"
    testDisasm "58000834" "dinsu r0, r0, 0x20, 0x2"
    testDisasm "58000874" "dinsu r0, r0, 0x21, 0x1"
    testDisasm "58001034" "dinsu r0, r0, 0x20, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DIV.fmt``() =
    testDisasm "540000f0" "div.s f0, f0, f0"
    testDisasm "540001f0" "div.d f0, f0, f0"
    testDisasm "540008f0" "div.s f1, f0, f0"
    testDisasm "540009f0" "div.d f1, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DMFC0``() =
    testDisasm "580008fc" "dmfc0 r0, 0x0, 0x1"
    testDisasm "580010fc" "dmfc0 r0, 0x0, 0x2"
    testDisasm "580018fc" "dmfc0 r0, 0x0, 0x3"
    testDisasm "582208fc" "dmfc0 at, 0x2, 0x1"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DMFC1``() =
    testDisasm "5400243b" "dmfc1 r0, f0"
    testDisasm "5422243b" "dmfc1 at, f2"
    testDisasm "57fe243b" "dmfc1 ra, f30"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DMFC2``() =
    testDisasm "00006d3c" "dmfc2 r0, 0x0"
    testDisasm "00226d3c" "dmfc2 at, 0x2"
    testDisasm "03fe6d3c" "dmfc2 ra, 0x1e"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DMTC0``() =
    testDisasm "58000afc" "dmtc0 r0, 0x0, 0x1"
    testDisasm "580012fc" "dmtc0 r0, 0x0, 0x2"
    testDisasm "58001afc" "dmtc0 r0, 0x0, 0x3"
    testDisasm "58220afc" "dmtc0 at, 0x2, 0x1"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DMTC1``() =
    testDisasm "54002c3b" "dmtc1 r0, f0"
    testDisasm "54222c3b" "dmtc1 at, f2"
    testDisasm "57fe2c3b" "dmtc1 ra, f30"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DMTC2``() =
    testDisasm "00007d3c" "dmtc2 r0, 0x0"
    testDisasm "00227d3c" "dmtc2 at, 0x2"
    testDisasm "03fe7d3c" "dmtc2 ra, 0x1e"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DROTR``() =
    testDisasm "580000c0" "drotr r0, r0, 0x0"
    testDisasm "580008c0" "drotr r0, r0, 0x1"
    testDisasm "580010c0" "drotr r0, r0, 0x2"
    testDisasm "580018c0" "drotr r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DROTR32``() =
    testDisasm "580000c8" "drotr32  r0, r0, 0x0"
    testDisasm "580008c8" "drotr32  r0, r0, 0x1"
    testDisasm "580010c8" "drotr32  r0, r0, 0x2"
    testDisasm "580018c8" "drotr32  r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DROTRV``() =
    testDisasm "580000d0" "drotrv r0, r0, r0"
    testDisasm "580008d0" "drotrv at, r0, r0"
    testDisasm "580010d0" "drotrv v0, r0, r0"
    testDisasm "580018d0" "drotrv v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DSBH``() =
    testDisasm "58007b3c" "dsbh r0, r0"
    testDisasm "58227b3c" "dsbh at, v0"
    testDisasm "5bfe7b3c" "dsbh ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DSHD``() =
    testDisasm "5800fb3c" "dshd r0, r0"
    testDisasm "5822fb3c" "dshd at, v0"
    testDisasm "5bfefb3c" "dshd ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DSLL``() =
    testDisasm "58000000" "dsll r0, r0, 0x0"
    testDisasm "58000800" "dsll r0, r0, 0x1"
    testDisasm "58001000" "dsll r0, r0, 0x2"
    testDisasm "58001800" "dsll r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DSLL32``() =
    testDisasm "58000008" "dsll32 r0, r0, 0x0"
    testDisasm "58000808" "dsll32 r0, r0, 0x1"
    testDisasm "58001008" "dsll32 r0, r0, 0x2"
    testDisasm "58001808" "dsll32 r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DSLLV``() =
    testDisasm "58000010" "dsllv r0, r0, r0"
    testDisasm "58000810" "dsllv at, r0, r0"
    testDisasm "58001010" "dsllv v0, r0, r0"
    testDisasm "58001810" "dsllv v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DSRA``() =
    testDisasm "58000080" "dsra r0, r0, 0x0"
    testDisasm "58000880" "dsra r0, r0, 0x1"
    testDisasm "58001080" "dsra r0, r0, 0x2"
    testDisasm "58001880" "dsra r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DSRA32``() =
    testDisasm "58000088" "dsra32 r0, r0, 0x0"
    testDisasm "58000888" "dsra32 r0, r0, 0x1"
    testDisasm "58001088" "dsra32 r0, r0, 0x2"
    testDisasm "58001888" "dsra32 r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DSRAV``() =
    testDisasm "58000090" "dsrav r0, r0, r0"
    testDisasm "58000890" "dsrav at, r0, r0"
    testDisasm "58001090" "dsrav v0, r0, r0"
    testDisasm "58001890" "dsrav v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DSRL``() =
    testDisasm "58000040" "dsrl r0, r0, 0x0"
    testDisasm "58000840" "dsrl r0, r0, 0x1"
    testDisasm "58001040" "dsrl r0, r0, 0x2"
    testDisasm "58001840" "dsrl r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DSRL32``() =
    testDisasm "58000048" "dsrl32 r0, r0, 0x0"
    testDisasm "58000848" "dsrl32 r0, r0, 0x1"
    testDisasm "58001048" "dsrl32 r0, r0, 0x2"
    testDisasm "58001848" "dsrl32 r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DSRLV``() =
    testDisasm "58000050" "dsrlv r0, r0, r0"
    testDisasm "58000850" "dsrlv at, r0, r0"
    testDisasm "58001050" "dsrlv v0, r0, r0"
    testDisasm "58001850" "dsrlv v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DSUB``() =
    testDisasm "58220190" "dsub r0, v0, at"
    testDisasm "58220990" "dsub at, v0, at"
    testDisasm "58221190" "dsub v0, v0, at"
    testDisasm "58221990" "dsub v1, v0, at"

  [<TestMethod>]
  member _.``microMIPS64 6.01 DSUBU``() =
    testDisasm "582201d0" "dsubu r0, v0, at"
    testDisasm "582209d0" "dsubu at, v0, at"
    testDisasm "582211d0" "dsubu v0, v0, at"
    testDisasm "582219d0" "dsubu v1, v0, at"

  [<TestMethod>]
  member _.``microMIPS64 6.01 EHB``() =
    testDisasm "00001800" "ehb"

  [<TestMethod>]
  member _.``microMIPS64 6.01 EI``() =
    testDisasm "0000577c" "ei r0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 ERET``() =
    testDisasm "0000f37c" "eret"

  [<TestMethod>]
  member _.``microMIPS64 6.01 ERETNC``() =
    testDisasm "0001f37c" "eretnc"

  [<TestMethod>]
  member _.``microMIPS64 6.01 EXT``() =
    testDisasm "0000002c" "ext r0, r0, 0x0, 0x1"
    testDisasm "0000006c" "ext r0, r0, 0x1, 0x1"
    testDisasm "000000ac" "ext r0, r0, 0x2, 0x1"
    testDisasm "000000ec" "ext r0, r0, 0x3, 0x1"

  [<TestMethod>]
  member _.``microMIPS64 6.01 FLOOR.L.fmt``() =
    testDisasm "5400033b" "floor.l.s f0, f0"
    testDisasm "5400433b" "floor.l.d f0, f0"
    testDisasm "5422033b" "floor.l.s f1, f2"
    testDisasm "5422433b" "floor.l.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 6.01 FLOOR.W.fmt``() =
    testDisasm "54000b3b" "floor.w.s f0, f0"
    testDisasm "54004b3b" "floor.w.d f0, f0"
    testDisasm "54220b3b" "floor.w.s f1, f2"
    testDisasm "54224b3b" "floor.w.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 6.01 INS``() =
    testDisasm "0000000c" "ins r0, r0, 0x0, 0x1"
    testDisasm "0000080c" "ins r0, r0, 0x0, 0x2"
    testDisasm "0000084c" "ins r0, r0, 0x1, 0x1"
    testDisasm "0000100c" "ins r0, r0, 0x0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 6.01 LB``() =
    testDisasm "1c030000" "lb r0, 0(v1)"
    testDisasm "1c600000" "lb v1, 0(r0)"
    testDisasm "1c030001" "lb r0, 1(v1)"
    testDisasm "1c600001" "lb v1, 1(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 LBE``() =
    testDisasm "60006800" "lbe r0, 0(r0)"
    testDisasm "60006801" "lbe r0, 1(r0)"
    testDisasm "60006802" "lbe r0, 2(r0)"
    testDisasm "60006803" "lbe r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 LBU``() =
    testDisasm "08000c00" "lbu s0, 0(s0)"
    testDisasm "08010c00" "lbu s0, 1(s0)"
    testDisasm "08020c00" "lbu s0, 2(s0)"
    testDisasm "08030c00" "lbu s0, 3(s0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 LBU16``() =
    testDisasm "08000c00" "lbu s0, 0(s0)"
    testDisasm "08010c00" "lbu s0, 1(s0)"
    testDisasm "08020c00" "lbu s0, 2(s0)"
    testDisasm "08030c00" "lbu s0, 3(s0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 LBUE``() =
    testDisasm "60006000" "lbue r0, 0(r0)"
    testDisasm "60006001" "lbue r0, 1(r0)"
    testDisasm "60006002" "lbue r0, 2(r0)"
    testDisasm "60006003" "lbue r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 LD``() =
    testDisasm "dc030000" "ld r0, 0(v1)"
    testDisasm "dc600000" "ld v1, 0(r0)"
    testDisasm "dc030001" "ld r0, 1(v1)"
    testDisasm "dc600001" "ld v1, 1(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 LDC1``() =
    testDisasm "bc030000" "ldc1 f0, 0(v1)"
    testDisasm "bc600000" "ldc1 f3, 0(r0)"
    testDisasm "bc030001" "ldc1 f0, 1(v1)"
    testDisasm "bc600001" "ldc1 f3, 1(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 LDC2``() =
    testDisasm "20002000" "ldc2 0x0, 0(r0)"
    testDisasm "20002001" "ldc2 0x0, 1(r0)"
    testDisasm "20002002" "ldc2 0x0, 2(r0)"
    testDisasm "20002003" "ldc2 0x0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 LDM``() =
    testDisasm "20227000" "ldm s0, 0(v0)"
    testDisasm "20227001" "ldm s0, 1(v0)"
    testDisasm "20227002" "ldm s0, 2(v0)"
    testDisasm "20227003" "ldm s0, 3(v0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 LDP``() =
    testDisasm "20004000" "ldp r0, at, 0(r0)"
    testDisasm "20004001" "ldp r0, at, 1(r0)"
    testDisasm "20004002" "ldp r0, at, 2(r0)"
    testDisasm "20004003" "ldp r0, at, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 LH``() =
    testDisasm "3c030000" "lh r0, 0(v1)"
    testDisasm "3c600000" "lh v1, 0(r0)"
    testDisasm "3c030001" "lh r0, 1(v1)"
    testDisasm "3c600001" "lh v1, 1(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 LHE``() =
    testDisasm "60006a00" "lhe r0, 0(r0)"
    testDisasm "60006a01" "lhe r0, 1(r0)"
    testDisasm "60006a02" "lhe r0, 2(r0)"
    testDisasm "60006a03" "lhe r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 LHU``() =
    testDisasm "28000c00" "lhu s0, 0(s0)"
    testDisasm "28010c00" "lhu s0, 2(s0)"
    testDisasm "28020c00" "lhu s0, 4(s0)"
    testDisasm "28030c00" "lhu s0, 6(s0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 LHU16``() =
    testDisasm "28000c00" "lhu s0, 0(s0)"
    testDisasm "28010c00" "lhu s0, 2(s0)"
    testDisasm "28020c00" "lhu s0, 4(s0)"
    testDisasm "28030c00" "lhu s0, 6(s0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 LHUE``() =
    testDisasm "60006200" "lhue r0, 0(r0)"
    testDisasm "60006201" "lhue r0, 1(r0)"
    testDisasm "60006202" "lhue r0, 2(r0)"
    testDisasm "60006203" "lhue r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 LI16``() =
    testDisasm "4c000c00" "addiu r0, r0, 0x0"
    testDisasm "4c010c00" "addiu sp, sp, 0x400"
    testDisasm "4c020c00" "addiu r0, r0, 0x1"
    testDisasm "4c030c00" "addiu sp, sp, 0x404"

  [<TestMethod>]
  member _.``microMIPS64 6.01 LL``() =
    testDisasm "60003000" "ll r0, 0(r0)"
    testDisasm "60003001" "ll r0, 1(r0)"
    testDisasm "60003002" "ll r0, 2(r0)"
    testDisasm "60003003" "ll r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 LLD``() =
    testDisasm "60007000" "lld r0, 0(r0)"
    testDisasm "60007001" "lld r0, 1(r0)"
    testDisasm "60007002" "lld r0, 2(r0)"
    testDisasm "60007003" "lld r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 LLE``() =
    testDisasm "60006c00" "lle r0, 0(r0)"
    testDisasm "60006c01" "lle r0, 1(r0)"
    testDisasm "60006c02" "lle r0, 2(r0)"
    testDisasm "60006c03" "lle r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 LW``() =
    testDisasm "48000c00" "lw r0, 0(sp)"
    testDisasm "48010c00" "lw r0, 4(sp)"
    testDisasm "48020c00" "lw r0, 8(sp)"
    testDisasm "48030c00" "lw r0, 12(sp)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 LW16``() =
    testDisasm "48000c00" "lw r0, 0(sp)"
    testDisasm "48010c00" "lw r0, 4(sp)"
    testDisasm "48020c00" "lw r0, 8(sp)"
    testDisasm "48030c00" "lw r0, 12(sp)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 LWC1``() =
    testDisasm "9c030000" "lwc1 f0, 0(v1)"
    testDisasm "9c600000" "lwc1 f3, 0(r0)"
    testDisasm "9c030001" "lwc1 f0, 1(v1)"
    testDisasm "9c600001" "lwc1 f3, 1(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 LWC2``() =
    testDisasm "20000000" "lwc2 0x0, 0(r0)"
    testDisasm "20000001" "lwc2 0x0, 1(r0)"
    testDisasm "20000002" "lwc2 0x0, 2(r0)"
    testDisasm "20000003" "lwc2 0x0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 LWE``() =
    testDisasm "60006e00" "lwe r0, 0(r0)"
    testDisasm "60006e01" "lwe r0, 1(r0)"
    testDisasm "60006e02" "lwe r0, 2(r0)"
    testDisasm "60006e03" "lwe r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 LWGP``() =
    testDisasm "48000c00" "lw r0, 0(sp)"
    testDisasm "48010c00" "lw r0, 4(sp)"
    testDisasm "48020c00" "lw r0, 8(sp)"
    testDisasm "48030c00" "lw r0, 12(sp)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 LWM32``() =
    testDisasm "20225000" "lwm s0, 0(v0)"
    testDisasm "20225001" "lwm s0, 1(v0)"
    testDisasm "20225002" "lwm s0, 2(v0)"
    testDisasm "20225003" "lwm s0, 3(v0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 LWP``() =
    testDisasm "20001000" "lwp r0, at, 0(r0)"
    testDisasm "20001001" "lwp r0, at, 1(r0)"
    testDisasm "20001002" "lwp r0, at, 2(r0)"
    testDisasm "20001003" "lwp r0, at, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 LWSP``() =
    testDisasm "48000c00" "lw r0, 0(sp)"
    testDisasm "48010c00" "lw r0, 4(sp)"
    testDisasm "48020c00" "lw r0, 8(sp)"
    testDisasm "48030c00" "lw r0, 12(sp)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 LWU``() =
    testDisasm "6000e000" "lwu r0, 0(r0)"
    testDisasm "6000e001" "lwu r0, 1(r0)"
    testDisasm "6000e002" "lwu r0, 2(r0)"
    testDisasm "6000e003" "lwu r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 MFC0``() =
    testDisasm "000000fc" "mfc0 r0, 0x0, 0x0"
    testDisasm "000008fc" "mfc0 r0, 0x0, 0x1"
    testDisasm "000010fc" "mfc0 r0, 0x0, 0x2"
    testDisasm "000018fc" "mfc0 r0, 0x0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 6.01 MFC1``() =
    testDisasm "5400203b" "mfc1 r0, f0"
    testDisasm "5422203b" "mfc1 at, f2"
    testDisasm "57fe203b" "mfc1 ra, f30"

  [<TestMethod>]
  member _.``microMIPS64 6.01 MFC2``() =
    testDisasm "00004d3c" "mfc2 r0, 0x0"
    testDisasm "00224d3c" "mfc2 at, 0x2"
    testDisasm "03fe4d3c" "mfc2 ra, 0x1e"

  [<TestMethod>]
  member _.``microMIPS64 6.01 MFHC0``() =
    testDisasm "000000f4" "mfhc0 r0, 0x0, 0x0"
    testDisasm "000008f4" "mfhc0 r0, 0x0, 0x1"
    testDisasm "000010f4" "mfhc0 r0, 0x0, 0x2"
    testDisasm "000018f4" "mfhc0 r0, 0x0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 6.01 MFHC1``() =
    testDisasm "5400303b" "mfhc1 r0, f0"
    testDisasm "5422303b" "mfhc1 at, f2"
    testDisasm "57fe303b" "mfhc1 ra, f30"

  [<TestMethod>]
  member _.``microMIPS64 6.01 MFHC2``() =
    testDisasm "00008d3c" "mfhc2 r0, 0x0"
    testDisasm "00228d3c" "mfhc2 at, 0x2"
    testDisasm "03fe8d3c" "mfhc2 ra, 0x1e"

  [<TestMethod>]
  member _.``microMIPS64 6.01 MOV.fmt``() =
    testDisasm "5400007b" "mov.s f0, f0"
    testDisasm "5400207b" "mov.d f0, f0"
    testDisasm "5400407b" "mov.ps f0, f0"
    testDisasm "5422007b" "mov.s f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 6.01 MOVE16``() =
    testDisasm "04000c00" "addu s0, s0, s0"
    testDisasm "04100c00" "addu s0, s0, s1"
    testDisasm "04200c00" "addu s0, s0, v0"
    testDisasm "04300c00" "addu s0, s0, v1"

  [<TestMethod>]
  member _.``microMIPS64 6.01 MTC0``() =
    testDisasm "000002fc" "mtc0 r0, 0x0, 0x0"
    testDisasm "00000afc" "mtc0 r0, 0x0, 0x1"
    testDisasm "000012fc" "mtc0 r0, 0x0, 0x2"
    testDisasm "00001afc" "mtc0 r0, 0x0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 6.01 MTC1``() =
    testDisasm "5400283b" "mtc1 r0, f0"
    testDisasm "5422283b" "mtc1 at, f2"
    testDisasm "57fe283b" "mtc1 ra, f30"

  [<TestMethod>]
  member _.``microMIPS64 6.01 MTC2``() =
    testDisasm "00005d3c" "mtc2 r0, 0x0"
    testDisasm "00225d3c" "mtc2 at, 0x2"
    testDisasm "03fe5d3c" "mtc2 ra, 0x1e"

  [<TestMethod>]
  member _.``microMIPS64 6.01 MTHC0``() =
    testDisasm "000002f4" "mthc0 r0, 0x0, 0x0"
    testDisasm "00000af4" "mthc0 r0, 0x0, 0x1"
    testDisasm "000012f4" "mthc0 r0, 0x0, 0x2"
    testDisasm "00001af4" "mthc0 r0, 0x0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 6.01 MTHC1``() =
    testDisasm "5400383b" "mthc1 r0, f0"
    testDisasm "5422383b" "mthc1 at, f2"
    testDisasm "57fe383b" "mthc1 ra, f30"

  [<TestMethod>]
  member _.``microMIPS64 6.01 MTHC2``() =
    testDisasm "00009d3c" "mthc2 r0, 0x0"
    testDisasm "00229d3c" "mthc2 at, 0x2"
    testDisasm "03fe9d3c" "mthc2 ra, 0x1e"

  [<TestMethod>]
  member _.``microMIPS64 6.01 MUL.fmt``() =
    testDisasm "540000b0" "mul.s f0, f0, f0"
    testDisasm "540001b0" "mul.d f0, f0, f0"
    testDisasm "540002b0" "mul.ps f0, f0, f0"
    testDisasm "540008b0" "mul.s f1, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 NEG.fmt``() =
    testDisasm "54000b7b" "neg.s f0, f0"
    testDisasm "54002b7b" "neg.d f0, f0"
    testDisasm "54004b7b" "neg.ps f0, f0"
    testDisasm "54220b7b" "neg.s f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 6.01 NOP``() =
    testDisasm "00000000" "nop"

  [<TestMethod>]
  member _.``microMIPS64 6.01 NOR``() =
    testDisasm "44000c00" "nor s0, s0, r0"
    testDisasm "000002d0" "nor r0, r0, r0"
    testDisasm "00000ad0" "nor at, r0, r0"
    testDisasm "000012d0" "nor v0, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 NOT16``() =
    testDisasm "44000c00" "nor s0, s0, r0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 OR``() =
    testDisasm "0c010c00" "or r0, at, r0"
    testDisasm "0c020c00" "or r0, v0, r0"
    testDisasm "0c030c00" "or r0, v1, r0"
    testDisasm "0c040c00" "or r0, a0, r0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 ORI``() =
    testDisasm "50030000" "ori r0, v1, 0x0"
    testDisasm "50030001" "ori r0, v1, 0x1"
    testDisasm "50037fff" "ori r0, v1, 0x7fff"
    testDisasm "50038000" "ori r0, v1, 0x8000"

  [<TestMethod>]
  member _.``microMIPS64 6.01 PAUSE``() =
    testDisasm "00002800" "pause"

  [<TestMethod>]
  member _.``microMIPS64 6.01 PREF``() =
    testDisasm "60002000" "pref 0x0, 0(r0)"
    testDisasm "60002001" "pref 0x0, 1(r0)"
    testDisasm "60002002" "pref 0x0, 2(r0)"
    testDisasm "60002003" "pref 0x0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 PREFE``() =
    testDisasm "6000a400" "prefe 0x0, 0(r0)"
    testDisasm "6000a401" "prefe 0x0, 1(r0)"
    testDisasm "6000a402" "prefe 0x0, 2(r0)"
    testDisasm "6000a403" "prefe 0x0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 RDHWR``() =
    testDisasm "00006b3c" "rdhwr r0, r0"
    testDisasm "00226b3c" "rdhwr at, v0"
    testDisasm "03fe6b3c" "rdhwr ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 6.01 RDPGPR``() =
    testDisasm "0000e17c" "rdpgpr r0, r0"
    testDisasm "0022e17c" "rdpgpr at, v0"
    testDisasm "03fee17c" "rdpgpr ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 6.01 RECIP.fmt``() =
    testDisasm "5400123b" "recip.s f0, f0"
    testDisasm "5400523b" "recip.d f0, f0"
    testDisasm "5422123b" "recip.s f1, f2"
    testDisasm "5422523b" "recip.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 6.01 ROTR``() =
    testDisasm "000000c0" "rotr r0, r0, 0x0"
    testDisasm "000008c0" "rotr r0, r0, 0x1"
    testDisasm "000010c0" "rotr r0, r0, 0x2"
    testDisasm "000018c0" "rotr r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 6.01 ROTRV``() =
    testDisasm "000000d0" "rotrv r0, r0, r0"
    testDisasm "000008d0" "rotrv at, r0, r0"
    testDisasm "000010d0" "rotrv v0, r0, r0"
    testDisasm "000018d0" "rotrv v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 ROUND.L.fmt``() =
    testDisasm "5400333b" "round.l.s f0, f0"
    testDisasm "5400733b" "round.l.d f0, f0"
    testDisasm "5422333b" "round.l.s f1, f2"
    testDisasm "5422733b" "round.l.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 6.01 ROUND.W.fmt``() =
    testDisasm "54003b3b" "round.w.s f0, f0"
    testDisasm "54007b3b" "round.w.d f0, f0"
    testDisasm "54223b3b" "round.w.s f1, f2"
    testDisasm "54227b3b" "round.w.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 6.01 RSQRT.fmt``() =
    testDisasm "5400023b" "rsqrt.s f0, f0"
    testDisasm "5400423b" "rsqrt.d f0, f0"
    testDisasm "5422023b" "rsqrt.s f1, f2"
    testDisasm "5422423b" "rsqrt.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SB``() =
    testDisasm "88000c00" "sb r0, 0(s0)"
    testDisasm "88010c00" "sb r0, 1(s0)"
    testDisasm "88020c00" "sb r0, 2(s0)"
    testDisasm "88030c00" "sb r0, 3(s0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SB16``() =
    testDisasm "88000c00" "sb r0, 0(s0)"
    testDisasm "88010c00" "sb r0, 1(s0)"
    testDisasm "88020c00" "sb r0, 2(s0)"
    testDisasm "88030c00" "sb r0, 3(s0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SBE``() =
    testDisasm "6000a800" "sbe r0, 0(r0)"
    testDisasm "6000a801" "sbe r0, 1(r0)"
    testDisasm "6000a802" "sbe r0, 2(r0)"
    testDisasm "6000a803" "sbe r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SC``() =
    testDisasm "6000b000" "sc r0, 0(r0)"
    testDisasm "6000b001" "sc r0, 1(r0)"
    testDisasm "6000b002" "sc r0, 2(r0)"
    testDisasm "6000b003" "sc r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SCD``() =
    testDisasm "6000f000" "scd r0, 0(r0)"
    testDisasm "6000f001" "scd r0, 1(r0)"
    testDisasm "6000f002" "scd r0, 2(r0)"
    testDisasm "6000f003" "scd r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SCE``() =
    testDisasm "6000ac00" "sce r0, 0(r0)"
    testDisasm "6000ac01" "sce r0, 1(r0)"
    testDisasm "6000ac02" "sce r0, 2(r0)"
    testDisasm "6000ac03" "sce r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SD``() =
    testDisasm "d8030000" "sd r0, 0(v1)"
    testDisasm "d8600000" "sd v1, 0(r0)"
    testDisasm "d8030001" "sd r0, 1(v1)"
    testDisasm "d8600001" "sd v1, 1(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SDC1``() =
    testDisasm "b8030000" "sdc1 f0, 0(v1)"
    testDisasm "b8600000" "sdc1 f3, 0(r0)"
    testDisasm "b8030001" "sdc1 f0, 1(v1)"
    testDisasm "b8600001" "sdc1 f3, 1(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SDC2``() =
    testDisasm "2000a000" "sdc2 0x0, 0(r0)"
    testDisasm "2000a001" "sdc2 0x0, 1(r0)"
    testDisasm "2000a002" "sdc2 0x0, 2(r0)"
    testDisasm "2000a003" "sdc2 0x0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SDM``() =
    testDisasm "2022f000" "sdm s0, 0(v0)"
    testDisasm "2022f001" "sdm s0, 1(v0)"
    testDisasm "2022f002" "sdm s0, 2(v0)"
    testDisasm "2022f003" "sdm s0, 3(v0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SDP``() =
    testDisasm "2000c000" "sdp r0, at, 0(r0)"
    testDisasm "2000c001" "sdp r0, at, 1(r0)"
    testDisasm "2000c002" "sdp r0, at, 2(r0)"
    testDisasm "2000c003" "sdp r0, at, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SEB``() =
    testDisasm "00002b3c" "seb r0, r0"
    testDisasm "00222b3c" "seb at, v0"
    testDisasm "03fe2b3c" "seb ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SEH``() =
    testDisasm "00003b3c" "seh r0, r0"
    testDisasm "00223b3c" "seh at, v0"
    testDisasm "03fe3b3c" "seh ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SH``() =
    testDisasm "a8000c00" "sh r0, 0(s0)"
    testDisasm "a8010c00" "sh r0, 2(s0)"
    testDisasm "a8020c00" "sh r0, 4(s0)"
    testDisasm "a8030c00" "sh r0, 6(s0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SH16``() =
    testDisasm "a8000c00" "sh r0, 0(s0)"
    testDisasm "a8010c00" "sh r0, 2(s0)"
    testDisasm "a8020c00" "sh r0, 4(s0)"
    testDisasm "a8030c00" "sh r0, 6(s0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SHE``() =
    testDisasm "6000aa00" "she r0, 0(r0)"
    testDisasm "6000aa01" "she r0, 1(r0)"
    testDisasm "6000aa02" "she r0, 2(r0)"
    testDisasm "6000aa03" "she r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SLL``() =
    testDisasm "24000c00" "sll s0, s0, 0x8"
    testDisasm "24020c00" "sll s0, s0, 0x1"
    testDisasm "24040c00" "sll s0, s0, 0x2"
    testDisasm "24060c00" "sll s0, s0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SLL16``() =
    testDisasm "24000c00" "sll s0, s0, 0x8"
    testDisasm "24020c00" "sll s0, s0, 0x1"
    testDisasm "24040c00" "sll s0, s0, 0x2"
    testDisasm "24060c00" "sll s0, s0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SLLV``() =
    testDisasm "00000010" "sllv r0, r0, r0"
    testDisasm "00000810" "sllv at, r0, r0"
    testDisasm "00001010" "sllv v0, r0, r0"
    testDisasm "00001810" "sllv v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SLT``() =
    testDisasm "00000350" "slt r0, r0, r0"
    testDisasm "00000b50" "slt at, r0, r0"
    testDisasm "00001350" "slt v0, r0, r0"
    testDisasm "00001b50" "slt v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SLTI``() =
    testDisasm "90030000" "slti r0, v1, 0x0"
    testDisasm "90600000" "slti v1, r0, 0x0"
    testDisasm "90030001" "slti r0, v1, 0x1"
    testDisasm "90600001" "slti v1, r0, 0x1"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SLTIU``() =
    testDisasm "b0030000" "sltiu r0, v1, 0x0"
    testDisasm "b0600000" "sltiu v1, r0, 0x0"
    testDisasm "b0030001" "sltiu r0, v1, 0x1"
    testDisasm "b0600001" "sltiu v1, r0, 0x1"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SLTU``() =
    testDisasm "00000390" "sltu r0, r0, r0"
    testDisasm "00000b90" "sltu at, r0, r0"
    testDisasm "00001390" "sltu v0, r0, r0"
    testDisasm "00001b90" "sltu v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SQRT.fmt``() =
    testDisasm "54000a3b" "sqrt.s f0, f0"
    testDisasm "54004a3b" "sqrt.d f0, f0"
    testDisasm "54220a3b" "sqrt.s f1, f2"
    testDisasm "54224a3b" "sqrt.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SRA``() =
    testDisasm "00000080" "sra r0, r0, 0x0"
    testDisasm "00000880" "sra r0, r0, 0x1"
    testDisasm "00001080" "sra r0, r0, 0x2"
    testDisasm "00001880" "sra r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SRAV``() =
    testDisasm "00000090" "srav r0, r0, r0"
    testDisasm "00000890" "srav at, r0, r0"
    testDisasm "00001090" "srav v0, r0, r0"
    testDisasm "00001890" "srav v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SRL``() =
    testDisasm "24010c00" "srl s0, s0, 0x8"
    testDisasm "24030c00" "srl s0, s0, 0x1"
    testDisasm "24050c00" "srl s0, s0, 0x2"
    testDisasm "24070c00" "srl s0, s0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SRL16``() =
    testDisasm "24010c00" "srl s0, s0, 0x8"
    testDisasm "24030c00" "srl s0, s0, 0x1"
    testDisasm "24050c00" "srl s0, s0, 0x2"
    testDisasm "24070c00" "srl s0, s0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SRLV``() =
    testDisasm "00000050" "srlv r0, r0, r0"
    testDisasm "00000850" "srlv at, r0, r0"
    testDisasm "00001050" "srlv v0, r0, r0"
    testDisasm "00001850" "srlv v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SSNOP``() =
    testDisasm "00000800" "ssnop"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SUB``() =
    testDisasm "00220190" "sub r0, v0, at"
    testDisasm "00220990" "sub at, v0, at"
    testDisasm "00221190" "sub v0, v0, at"
    testDisasm "00221990" "sub v1, v0, at"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SUB.fmt``() =
    testDisasm "54000070" "sub.s f0, f0, f0"
    testDisasm "54000170" "sub.d f0, f0, f0"
    testDisasm "54000270" "sub.ps f0, f0, f0"
    testDisasm "54000870" "sub.s f1, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SUBU``() =
    testDisasm "04010c00" "subu s0, s0, s0"
    testDisasm "04110c00" "subu s0, s0, s1"
    testDisasm "04210c00" "subu s0, s0, v0"
    testDisasm "04310c00" "subu s0, s0, v1"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SW``() =
    testDisasm "c8000c00" "sw r0, 0(sp)"
    testDisasm "c8010c00" "sw r0, 4(sp)"
    testDisasm "c8020c00" "sw r0, 8(sp)"
    testDisasm "c8030c00" "sw r0, 12(sp)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SW16``() =
    testDisasm "c8000c00" "sw r0, 0(sp)"
    testDisasm "c8010c00" "sw r0, 4(sp)"
    testDisasm "c8020c00" "sw r0, 8(sp)"
    testDisasm "c8030c00" "sw r0, 12(sp)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SWC1``() =
    testDisasm "98030000" "swc1 f0, 0(v1)"
    testDisasm "98600000" "swc1 f3, 0(r0)"
    testDisasm "98030001" "swc1 f0, 1(v1)"
    testDisasm "98600001" "swc1 f3, 1(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SWC2``() =
    testDisasm "20008000" "swc2 0x0, 0(r0)"
    testDisasm "20008001" "swc2 0x0, 1(r0)"
    testDisasm "20008002" "swc2 0x0, 2(r0)"
    testDisasm "20008003" "swc2 0x0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SWE``() =
    testDisasm "6000ae00" "swe r0, 0(r0)"
    testDisasm "6000ae01" "swe r0, 1(r0)"
    testDisasm "6000ae02" "swe r0, 2(r0)"
    testDisasm "6000ae03" "swe r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SWM32``() =
    testDisasm "2022d000" "swm s0, 0(v0)"
    testDisasm "2022d001" "swm s0, 1(v0)"
    testDisasm "2022d002" "swm s0, 2(v0)"
    testDisasm "2022d003" "swm s0, 3(v0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SWP``() =
    testDisasm "20009000" "swp r0, at, 0(r0)"
    testDisasm "20009001" "swp r0, at, 1(r0)"
    testDisasm "20009002" "swp r0, at, 2(r0)"
    testDisasm "20009003" "swp r0, at, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SWSP``() =
    testDisasm "c8000c00" "sw r0, 0(sp)"
    testDisasm "c8010c00" "sw r0, 4(sp)"
    testDisasm "c8020c00" "sw r0, 8(sp)"
    testDisasm "c8030c00" "sw r0, 12(sp)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SYNC``() =
    testDisasm "00006b7c" "sync 0x0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SYSCALL``() =
    testDisasm "00008b7c" "syscall 0x0"
    testDisasm "00228b7c" "syscall 0x22"
    testDisasm "03fe8b7c" "syscall 0x3fe"

  [<TestMethod>]
  member _.``microMIPS64 6.01 TEQ``() =
    testDisasm "0000003c" "teq r0, r0"
    testDisasm "0022003c" "teq v0, at"
    testDisasm "03fe003c" "teq s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 6.01 TGE``() =
    testDisasm "0000023c" "tge r0, r0"
    testDisasm "0022023c" "tge v0, at"
    testDisasm "03fe023c" "tge s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 6.01 TGEU``() =
    testDisasm "0000043c" "tgeu r0, r0"
    testDisasm "0022043c" "tgeu v0, at"
    testDisasm "03fe043c" "tgeu s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 6.01 TLBP``() =
    testDisasm "0000037c" "tlbp"

  [<TestMethod>]
  member _.``microMIPS64 6.01 TLBR``() =
    testDisasm "0000137c" "tlbr"

  [<TestMethod>]
  member _.``microMIPS64 6.01 TLBWI``() =
    testDisasm "0000237c" "tlbwi"

  [<TestMethod>]
  member _.``microMIPS64 6.01 TLBWR``() =
    testDisasm "0000337c" "tlbwr"

  [<TestMethod>]
  member _.``microMIPS64 6.01 TLT``() =
    testDisasm "0000083c" "tlt r0, r0"
    testDisasm "0022083c" "tlt v0, at"
    testDisasm "03fe083c" "tlt s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 6.01 TLTU``() =
    testDisasm "00000a3c" "tltu r0, r0"
    testDisasm "00220a3c" "tltu v0, at"
    testDisasm "03fe0a3c" "tltu s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 6.01 TNE``() =
    testDisasm "00000c3c" "tne r0, r0"
    testDisasm "00220c3c" "tne v0, at"
    testDisasm "03fe0c3c" "tne s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 6.01 TRUNC.L.fmt``() =
    testDisasm "5400233b" "trunc.l.s f0, f0"
    testDisasm "5400633b" "trunc.l.d f0, f0"
    testDisasm "5422233b" "trunc.l.s f1, f2"
    testDisasm "5422633b" "trunc.l.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 6.01 TRUNC.W.fmt``() =
    testDisasm "54002b3b" "trunc.w.s f0, f0"
    testDisasm "54006b3b" "trunc.w.d f0, f0"
    testDisasm "54222b3b" "trunc.w.s f1, f2"
    testDisasm "54226b3b" "trunc.w.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 6.01 WAIT``() =
    testDisasm "0000937c" "wait 0x0"
    testDisasm "0022937c" "wait 0x22"
    testDisasm "03fe937c" "wait 0x3fe"

  [<TestMethod>]
  member _.``microMIPS64 6.01 WRPGPR``() =
    testDisasm "0000f17c" "wrpgpr r0, r0"
    testDisasm "0022f17c" "wrpgpr at, v0"
    testDisasm "03fef17c" "wrpgpr ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 6.01 WSBH``() =
    testDisasm "00007b3c" "wsbh r0, r0"
    testDisasm "00227b3c" "wsbh at, v0"
    testDisasm "03fe7b3c" "wsbh ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 6.01 XOR``() =
    testDisasm "00000310" "xor r0, r0, r0"
    testDisasm "00000b10" "xor at, r0, r0"
    testDisasm "00001310" "xor v0, r0, r0"
    testDisasm "00001b10" "xor v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 XORI``() =
    testDisasm "70030000" "xori r0, v1, 0x0"
    testDisasm "70600000" "xori v1, r0, 0x0"
    testDisasm "70030001" "xori r0, v1, 0x1"
    testDisasm "70600001" "xori v1, r0, 0x1"
