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
