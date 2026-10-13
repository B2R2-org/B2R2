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
/// One test for each instruction microMIPS64 6.01 describes, ABS.fmt to OR.
/// Each reads words of the instruction and checks the text, and each word is
/// one binutils' objdump reads as the same instruction with the same operands,
/// so what is asserted is a reading two decoders agree on.
/// </summary>
[<TestClass>]
type ManualMicroMIPSR6ParserTests1() =
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
