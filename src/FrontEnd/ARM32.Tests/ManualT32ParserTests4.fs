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

namespace B2R2.FrontEnd.ARM32.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.ARM32

/// <summary>
/// One test for each T32 instruction DDI0406C and DDI0487F.c's AArch32
/// chapters describe, SMLADX to VJCVT in the order of their sections. Each
/// reads T32 words of the instruction and checks the text, and each word's
/// text is one binutils' objdump reads the word as too, so what is asserted
/// is a reading two decoders agree on.
/// </summary>
[<TestClass>]
type ManualT32ParserTests4() =
  let testDisasm (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let isa = ISA(Architecture.ARMv7, Endian.Big)
    let parser = Parser(isa, true, BinReader.Init Endian.Big)
    let ins = (parser :> IInstructionParsable).Parse(bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  /// F5.1.194 SMLAD, SMLADX
  [<TestMethod>]
  member _.``F5.1.194 SMLADX``() =
    testDisasm "fb213012" "smladx r0, r1, r2, r3"
    testDisasm "fb210910" "smladx sb, r1, r0, r0"
    testDisasm "fb210a10" "smladx sl, r1, r0, r0"
    testDisasm "fb210b10" "smladx fp, r1, r0, r0"

  /// F5.1.197 SMLALD, SMLALDX
  [<TestMethod>]
  member _.``F5.1.197 SMLALDX``() =
    testDisasm "fbc101d2" "smlaldx r0, r1, r1, r2"
    testDisasm "fbc109d1" "smlaldx r0, sb, r1, r1"
    testDisasm "fbc10ad1" "smlaldx r0, sl, r1, r1"
    testDisasm "fbc10bd1" "smlaldx r0, fp, r1, r1"

  /// F5.1.199 SMLSD, SMLSDX
  [<TestMethod>]
  member _.``F5.1.199 SMLSDX``() =
    testDisasm "fb413012" "smlsdx r0, r1, r2, r3"
    testDisasm "fb410910" "smlsdx sb, r1, r0, r0"
    testDisasm "fb410a10" "smlsdx sl, r1, r0, r0"
    testDisasm "fb410b10" "smlsdx fp, r1, r0, r0"

  /// F5.1.200 SMLSLD, SMLSLDX
  [<TestMethod>]
  member _.``F5.1.200 SMLSLDX``() =
    testDisasm "fbd101d2" "smlsldx r0, r1, r1, r2"
    testDisasm "fbd109d1" "smlsldx r0, sb, r1, r1"
    testDisasm "fbd10ad1" "smlsldx r0, sl, r1, r1"
    testDisasm "fbd10bd1" "smlsldx r0, fp, r1, r1"

  /// F5.1.201 SMMLA, SMMLAR
  [<TestMethod>]
  member _.``F5.1.201 SMMLAR``() =
    testDisasm "fb513012" "smmlar r0, r1, r2, r3"
    testDisasm "fb510910" "smmlar sb, r1, r0, r0"
    testDisasm "fb510a10" "smmlar sl, r1, r0, r0"
    testDisasm "fb510b10" "smmlar fp, r1, r0, r0"

  /// F5.1.202 SMMLS, SMMLSR
  [<TestMethod>]
  member _.``F5.1.202 SMMLSR``() =
    testDisasm "fb613012" "smmlsr r0, r1, r2, r3"
    testDisasm "fb610910" "smmlsr sb, r1, r0, r0"
    testDisasm "fb610a10" "smmlsr sl, r1, r0, r0"
    testDisasm "fb610b10" "smmlsr fp, r1, r0, r0"

  /// F5.1.203 SMMUL, SMMULR
  [<TestMethod>]
  member _.``F5.1.203 SMMULR``() =
    testDisasm "fb51f012" "smmulr r0, r1, r2"
    testDisasm "fb51f910" "smmulr sb, r1, r0"
    testDisasm "fb51fa10" "smmulr sl, r1, r0"
    testDisasm "fb51fb10" "smmulr fp, r1, r0"

  /// F5.1.204 SMUAD, SMUADX
  [<TestMethod>]
  member _.``F5.1.204 SMUADX``() =
    testDisasm "fb21f012" "smuadx r0, r1, r2"
    testDisasm "fb21f910" "smuadx sb, r1, r0"
    testDisasm "fb21fa10" "smuadx sl, r1, r0"
    testDisasm "fb21fb10" "smuadx fp, r1, r0"

  /// F5.1.208 SMUSD, SMUSDX
  [<TestMethod>]
  member _.``F5.1.208 SMUSDX``() =
    testDisasm "fb41f012" "smusdx r0, r1, r2"
    testDisasm "fb41f910" "smusdx sb, r1, r0"
    testDisasm "fb41fa10" "smusdx sl, r1, r0"
    testDisasm "fb41fb10" "smusdx fp, r1, r0"

  /// F5.1.209 SRS, SRSDA, SRSDB, SRSIA, SRSIB
  [<TestMethod>]
  member _.``F5.1.209 SRSDB``() =
    testDisasm "e80dc013" "srsdb sp, #0x13"

  /// F5.1.209 SRS, SRSDA, SRSDB, SRSIA, SRSIB
  [<TestMethod>]
  member _.``F5.1.209 SRSIA``() =
    testDisasm "e9adc013" "srsia sp!, #0x13"

  /// F5.1.21 BIC, BICS (immediate)
  [<TestMethod>]
  member _.``F5.1.21 BICS``() =
    testDisasm "f031407f" "bics r0, r1, #0xff000000"
    testDisasm "ea310002" "bics r0, r1, r2"
    testDisasm "ea310034" "bics r0, r1, r4, rrx"
    testDisasm "ea310010" "bics r0, r1, r0, lsr #0x20"

  /// F5.1.213 SSBB
  [<TestMethod>]
  member _.``F5.1.213 SSBB``() =
    testDisasm "f3bf8f40" "ssbb"

  /// F5.1.217 STL
  [<TestMethod>]
  member _.``F5.1.217 STL``() =
    testDisasm "e8c10faf" "stl r0, [r1]"

  /// F5.1.218 STLB
  [<TestMethod>]
  member _.``F5.1.218 STLB``() =
    testDisasm "e8c10f8f" "stlb r0, [r1]"

  /// F5.1.219 STLEX
  [<TestMethod>]
  member _.``F5.1.219 STLEX``() =
    testDisasm "e8c12fe0" "stlex r0, r2, [r1]"

  /// F5.1.220 STLEXB
  [<TestMethod>]
  member _.``F5.1.220 STLEXB``() =
    testDisasm "e8c12fc0" "stlexb r0, r2, [r1]"

  /// F5.1.221 STLEXD
  [<TestMethod>]
  member _.``F5.1.221 STLEXD``() =
    testDisasm "e8c123f0" "stlexd r0, r2, r3, [r1]"
    testDisasm "e8c109f3" "stlexd r3, r0, sb, [r1]"
    testDisasm "e8c10af3" "stlexd r3, r0, sl, [r1]"
    testDisasm "e8c10bf3" "stlexd r3, r0, fp, [r1]"

  /// F5.1.222 STLEXH
  [<TestMethod>]
  member _.``F5.1.222 STLEXH``() =
    testDisasm "e8c12fd0" "stlexh r0, r2, [r1]"

  /// F5.1.223 STLH
  [<TestMethod>]
  member _.``F5.1.223 STLH``() =
    testDisasm "e8c10f9f" "stlh r0, [r1]"

  /// F5.1.224 STM, STMIA, STMEA
  [<TestMethod>]
  member _.``F5.1.224 STMEA``() =
    testDisasm "e881000c" "stm.w r1, {r2, r3}"
    testDisasm "c10cbf00" "stm r1!, {r2, r3}"
    testDisasm "c001bf00" "stm r0!, {r0}"
    testDisasm "c007bf00" "stm r0!, {r0, r1, r2}"

  /// F5.1.224 STM, STMIA, STMEA
  [<TestMethod>]
  member _.``F5.1.224 STMIA``() =
    testDisasm "e881000c" "stm.w r1, {r2, r3}"
    testDisasm "c10cbf00" "stm r1!, {r2, r3}"
    testDisasm "c001bf00" "stm r0!, {r0}"
    testDisasm "c007bf00" "stm r0!, {r0, r1, r2}"

  /// F5.1.227 STMDB, STMFD
  [<TestMethod>]
  member _.``F5.1.227 STMFD``() =
    testDisasm "e901000c" "stmdb r1, {r2, r3}"
    testDisasm "b40cbf00" "push {r2, r3}"
    testDisasm "e921000c" "stmdb r1!, {r2, r3}"
    testDisasm "b401bf00" "push {r0}"

  /// F5.1.38 CPS, CPSID, CPSIE
  [<TestMethod>]
  member _.``F5.1.38 CPSID``() =
    testDisasm "b673bf00" "cpsid if"
    testDisasm "b671bf00" "cpsid f"
    testDisasm "b672bf00" "cpsid i"
    testDisasm "b674bf00" "cpsid a"

  /// F5.1.38 CPS, CPSID, CPSIE
  [<TestMethod>]
  member _.``F5.1.38 CPSIE``() =
    testDisasm "b662bf00" "cpsie i"
    testDisasm "b661bf00" "cpsie f"
    testDisasm "b663bf00" "cpsie if"
    testDisasm "b664bf00" "cpsie a"

  /// F5.1.39 CRC32
  [<TestMethod>]
  member _.``F5.1.39 CRC32``() =
    testDisasm "fac2f083" "crc32b r0, r2, r3"
    testDisasm "fac1f092" "crc32h r0, r1, r2"

  /// F5.1.4 ADD, ADDS (immediate)
  [<TestMethod>]
  member _.``F5.1.4 ADDS``() =
    testDisasm "f111417f" "adds.w r1, r1, #0xff000000"
    testDisasm "1889bf00" "adds r1, r1, r2"
    testDisasm "eb110002" "adds.w r0, r1, r2"
    testDisasm "1c00bf00" "adds r0, r0, #0x0"

  /// F5.1.40 CRC32C
  [<TestMethod>]
  member _.``F5.1.40 CRC32C``() =
    testDisasm "fad2f0a3" "crc32cw r0, r2, r3"

  /// F5.1.43 DCPS1
  [<TestMethod>]
  member _.``F5.1.43 DCPS1``() =
    testDisasm "f78f8001" "dcps1"

  /// F5.1.44 DCPS2
  [<TestMethod>]
  member _.``F5.1.44 DCPS2``() =
    testDisasm "f78f8002" "dcps2"

  /// F5.1.45 DCPS3
  [<TestMethod>]
  member _.``F5.1.45 DCPS3``() =
    testDisasm "f78f8003" "dcps3"

  /// F5.1.48 EOR, EORS (immediate)
  [<TestMethod>]
  member _.``F5.1.48 EORS``() =
    testDisasm "ea910002" "eors.w r0, r1, r2"
    testDisasm "4051bf00" "eors r1, r1, r2"
    testDisasm "ea910034" "eors r0, r1, r4, rrx"
    testDisasm "ea910010" "eors.w r0, r1, r0, lsr #0x20"

  /// F5.1.52 ESB
  [<TestMethod>]
  member _.``F5.1.52 ESB``() =
    testDisasm "f3af8010" "esb"

  /// F5.1.53 HLT
  [<TestMethod>]
  member _.``F5.1.53 HLT``() =
    testDisasm "ba80bf00" "hlt #0x0"

  /// F5.1.57 LDA
  [<TestMethod>]
  member _.``F5.1.57 LDA``() =
    testDisasm "e8d10faf" "lda r0, [r1]"

  /// F5.1.58 LDAB
  [<TestMethod>]
  member _.``F5.1.58 LDAB``() =
    testDisasm "e8d10f8f" "ldab r0, [r1]"

  /// F5.1.59 LDAEX
  [<TestMethod>]
  member _.``F5.1.59 LDAEX``() =
    testDisasm "e8d10fef" "ldaex r0, [r1]"

  /// F5.1.60 LDAEXB
  [<TestMethod>]
  member _.``F5.1.60 LDAEXB``() =
    testDisasm "e8d10fcf" "ldaexb r0, [r1]"

  /// F5.1.61 LDAEXD
  [<TestMethod>]
  member _.``F5.1.61 LDAEXD``() =
    testDisasm "e8d123ff" "ldaexd r2, r3, [r1]"
    testDisasm "e8d109ff" "ldaexd r0, sb, [r1]"
    testDisasm "e8d10aff" "ldaexd r0, sl, [r1]"
    testDisasm "e8d10bff" "ldaexd r0, fp, [r1]"

  /// F5.1.62 LDAEXH
  [<TestMethod>]
  member _.``F5.1.62 LDAEXH``() =
    testDisasm "e8d10fdf" "ldaexh r0, [r1]"

  /// F5.1.63 LDAH
  [<TestMethod>]
  member _.``F5.1.63 LDAH``() =
    testDisasm "e8d10f9f" "ldah r0, [r1]"

  /// F6.1.1 AESD
  [<TestMethod>]
  member _.``F6.1.1 AESD``() =
    testDisasm "ffb00342" "aesd.8 q0, q1"

  /// F6.1.10 SHA1P
  [<TestMethod>]
  member _.``F6.1.10 SHA1P``() =
    testDisasm "ef120c44" "sha1p.32 q0, q1, q2"

  /// F6.1.11 SHA1SU0
  [<TestMethod>]
  member _.``F6.1.11 SHA1SU0``() =
    testDisasm "ef320c44" "sha1su0.32 q0, q1, q2"

  /// F6.1.112 VLDM, VLDMDB, VLDMIA
  [<TestMethod>]
  member _.``F6.1.112 VLDMDB``() =
    testDisasm "ed310a01" "vldmdb r1!, {s0}"
    ("vldmdb r1!, {s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, "
     + "s13, s14, s15}")
    |> testDisasm "ed310a10"
    ("vldmdb r1!, {s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, "
     + "s13, s14, s15, s16, s17}")
    |> testDisasm "ed310a12"
    ("vldmdb r1!, {s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, "
     + "s13, s14, s15, s16, s17, s18, s19}")
    |> testDisasm "ed310a14"

  /// F6.1.112 VLDM, VLDMDB, VLDMIA
  [<TestMethod>]
  member _.``F6.1.112 VLDMIA``() =
    testDisasm "ec910b04" "vldmia r1, {d0, d1}"
    testDisasm "ecbd0b04" "vldmia sp!, {d0, d1}"
    testDisasm "ecb10b08" "vldmia r1!, {d0, d1, d2, d3}"
    testDisasm "ec910a01" "vldmia r1, {s0}"

  /// F6.1.117 VMAXNM
  [<TestMethod>]
  member _.``F6.1.117 VMAXNM``() =
    testDisasm "fe800981" "vmaxnm.f16 s0, s1, s2"
    testDisasm "ff120f54" "vmaxnm.f16 q0, q1, q2"
    testDisasm "fe810b00" "vmaxnm.f64 d0, d1, d0"

  /// F6.1.12 SHA1SU1
  [<TestMethod>]
  member _.``F6.1.12 SHA1SU1``() =
    testDisasm "ffba0382" "sha1su1.32 q0, q1"

  /// F6.1.120 VMINNM
  [<TestMethod>]
  member _.``F6.1.120 VMINNM``() =
    testDisasm "fe8009c1" "vminnm.f16 s0, s1, s2"
    testDisasm "ff320f54" "vminnm.f16 q0, q1, q2"
    testDisasm "fe810b4f" "vminnm.f64 d0, d1, d15"

  /// F6.1.13 SHA256H
  [<TestMethod>]
  member _.``F6.1.13 SHA256H``() =
    testDisasm "ff020c44" "sha256h.32 q0, q1, q2"

  /// F6.1.14 SHA256H2
  [<TestMethod>]
  member _.``F6.1.14 SHA256H2``() =
    testDisasm "ff120c44" "sha256h2.32 q0, q1, q2"

  /// F6.1.143 VMOVX
  [<TestMethod>]
  member _.``F6.1.143 VMOVX``() =
    testDisasm "feb00a60" "vmovx.f16 s0, s1"

  /// F6.1.15 SHA256SU0
  [<TestMethod>]
  member _.``F6.1.15 SHA256SU0``() =
    testDisasm "ffba03c2" "sha256su0.32 q0, q1"

  /// F6.1.16 SHA256SU1
  [<TestMethod>]
  member _.``F6.1.16 SHA256SU1``() =
    testDisasm "ff220c44" "sha256su1.32 q0, q1, q2"

  /// F6.1.179 VQRDMLAH
  [<TestMethod>]
  member _.``F6.1.179 VQRDMLAH``() =
    testDisasm "ff110b12" "vqrdmlah.s16 d0, d1, d2"
    testDisasm "ef910e4f" "vqrdmlah.s16 d0, d1, d7[1]"
    testDisasm "ff100b70" "vqrdmlah.s16 q0, q0, q8"
    testDisasm "ff900e4f" "vqrdmlah.s16 q0, q0, d7[1]"

  /// F6.1.180 VQRDMLSH
  [<TestMethod>]
  member _.``F6.1.180 VQRDMLSH``() =
    testDisasm "ff220c54" "vqrdmlsh.s32 q0, q1, q2"
    testDisasm "ef910f4f" "vqrdmlsh.s16 d0, d1, d7[1]"
    testDisasm "ff110c34" "vqrdmlsh.s16 d0, d1, d20"
    testDisasm "ff900f4f" "vqrdmlsh.s16 q0, q0, d7[1]"

  /// F6.1.199 VRINTA (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.199 VRINTA``() =
    testDisasm "feb80960" "vrinta.f16 s0, s1"
    testDisasm "ffb60542" "vrinta.f16 q0, q1"

  /// F6.1.2 AESE
  [<TestMethod>]
  member _.``F6.1.2 AESE``() =
    testDisasm "ffb00302" "aese.8 q0, q1"

  /// F6.1.201 VRINTM (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.201 VRINTM``() =
    testDisasm "febb0960" "vrintm.f16 s0, s1"
    testDisasm "ffb606c2" "vrintm.f16 q0, q1"
    testDisasm "febb0b41" "vrintm.f64 d0, d1"

  /// F6.1.203 VRINTN (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.203 VRINTN``() =
    testDisasm "feb90960" "vrintn.f16 s0, s1"
    testDisasm "ffb60442" "vrintn.f16 q0, q1"
    testDisasm "feb90b4f" "vrintn.f64 d0, d15"

  /// F6.1.205 VRINTP (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.205 VRINTP``() =
    testDisasm "feba0960" "vrintp.f16 s0, s1"
    testDisasm "ffb607c2" "vrintp.f16 q0, q1"
    testDisasm "ffba0781" "vrintp.f32 d0, d1"

  /// F6.1.207 VRINTR
  [<TestMethod>]
  member _.``F6.1.207 VRINTR``() =
    testDisasm "eeb60960" "vrintr.f16 s0, s1"

  /// F6.1.208 VRINTX (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.208 VRINTX``() =
    testDisasm "eeb70960" "vrintx.f16 s0, s1"
    testDisasm "ffb604c2" "vrintx.f16 q0, q1"
    testDisasm "eeb70b41" "vrintx.f64 d0, d1"

  /// F6.1.210 VRINTZ (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.210 VRINTZ``() =
    testDisasm "eeb609e0" "vrintz.f16 s0, s1"
    testDisasm "ffb605c2" "vrintz.f16 q0, q1"

  /// F6.1.221 VSDOT (by element)
  [<TestMethod>]
  member _.``F6.1.221 VSDOT``() =
    testDisasm "fc210d02" "vsdot.s8 d0, d1, d2"
    testDisasm "fe210d00" "vsdot.s8 d0, d1, d0[0]"
    testDisasm "fe200d4f" "vsdot.s8 q0, q0, d15[0]"

  /// F6.1.223 VSELEQ, VSELGE, VSELGT, VSELVS
  [<TestMethod>]
  member _.``F6.1.223 VSELEQ``() =
    testDisasm "fe000981" "vseleq.f16 s0, s1, s2"
    testDisasm "fe010b00" "vseleq.f64 d0, d1, d0"

  /// F6.1.223 VSELEQ, VSELGE, VSELGT, VSELVS
  [<TestMethod>]
  member _.``F6.1.223 VSELGE``() =
    testDisasm "fe200981" "vselge.f16 s0, s1, s2"
    testDisasm "fe210b02" "vselge.f64 d0, d1, d2"

  /// F6.1.223 VSELEQ, VSELGE, VSELGT, VSELVS
  [<TestMethod>]
  member _.``F6.1.223 VSELGT``() =
    testDisasm "fe300981" "vselgt.f16 s0, s1, s2"
    testDisasm "fe310b00" "vselgt.f64 d0, d1, d0"

  /// F6.1.223 VSELEQ, VSELGE, VSELGT, VSELVS
  [<TestMethod>]
  member _.``F6.1.223 VSELVS``() =
    testDisasm "fe100981" "vselvs.f16 s0, s1, s2"
    testDisasm "fe110b02" "vselvs.f64 d0, d1, d2"

  /// F6.1.244 VSTM, VSTMDB, VSTMIA
  [<TestMethod>]
  member _.``F6.1.244 VSTMDB``() =
    testDisasm "ed2d0b04" "vstmdb sp!, {d0, d1}"
    testDisasm "ed2d0a04" "vstmdb sp!, {s0, s1, s2, s3}"
    testDisasm "ed210a01" "vstmdb r1!, {s0}"
    ("vstmdb r1!, {s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, "
     + "s13, s14, s15}")
    |> testDisasm "ed210a10"

  /// F6.1.244 VSTM, VSTMDB, VSTMIA
  [<TestMethod>]
  member _.``F6.1.244 VSTMIA``() =
    testDisasm "ec810b04" "vstmia r1, {d0, d1}"
    testDisasm "ec810a04" "vstmia r1, {s0, s1, s2, s3}"
    testDisasm "ec810a01" "vstmia r1, {s0}"
    ("vstmia r1, {s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, "
     + "s13, s14, s15}")
    |> testDisasm "ec810a10"

  /// F6.1.251 VSUDOT (by element)
  [<TestMethod>]
  member _.``F6.1.251 VSUDOT``() =
    testDisasm "fe810d34" "vsudot.u8 d0, d1, d4[1]"
    testDisasm "fe800d5f" "vsudot.u8 q0, q0, d15[0]"

  /// F6.1.256 VUDOT (by element)
  [<TestMethod>]
  member _.``F6.1.256 VUDOT``() =
    testDisasm "fe220d74" "vudot.u8 q0, q1, d4[1]"
    testDisasm "fc210d34" "vudot.u8 d0, d1, d20"
    testDisasm "fc200d70" "vudot.u8 q0, q0, q8"
    testDisasm "fe210d34" "vudot.u8 d0, d1, d4[1]"

  /// F6.1.258 VUMMLA
  [<TestMethod>]
  member _.``F6.1.258 VUMMLA``() =
    testDisasm "fc200c70" "vummla.u8 q0, q0, q8"

  /// F6.1.259 VUSDOT (by element)
  [<TestMethod>]
  member _.``F6.1.259 VUSDOT``() =
    testDisasm "fca10d00" "vusdot.s8 d0, d1, d0"
    testDisasm "fe810d00" "vusdot.s8 d0, d1, d0[0]"
    testDisasm "fe800d4f" "vusdot.s8 q0, q0, d15[0]"

  /// F6.1.3 AESIMC
  [<TestMethod>]
  member _.``F6.1.3 AESIMC``() =
    testDisasm "ffb003c2" "aesimc.8 q0, q1"

  /// F6.1.39 VCADD
  [<TestMethod>]
  member _.``F6.1.39 VCADD``() =
    testDisasm "fc910802" "vcadd.f32 d0, d1, d2, #0x5a"

  /// F6.1.4 AESMC
  [<TestMethod>]
  member _.``F6.1.4 AESMC``() =
    testDisasm "ffb00382" "aesmc.8 q0, q1"

  /// F6.1.52 VCMLA
  [<TestMethod>]
  member _.``F6.1.52 VCMLA``() =
    testDisasm "fc310802" "vcmla.f32 d0, d1, d2, #0x0"
    testDisasm "fe010800" "vcmla.f16 d0, d1, d0[0], #0x0"
    testDisasm "fe00084f" "vcmla.f16 q0, q0, d15[0], #0x0"

  /// F6.1.6 FSTMDBX, FSTMIAX
  [<TestMethod>]
  member _.``F6.1.6 FSTMDBX``() =
    testDisasm "ed210b11" "fstmdbx r1!, {d0, d1, d2, d3, d4, d5, d6, d7}"
    testDisasm "ed290b11" "fstmdbx sb!, {d0, d1, d2, d3, d4, d5, d6, d7}"
    testDisasm "ed2d0b11" "fstmdbx sp!, {d0, d1, d2, d3, d4, d5, d6, d7}"

  /// F6.1.6 FSTMDBX, FSTMIAX
  [<TestMethod>]
  member _.``F6.1.6 FSTMIAX``() =
    testDisasm "ec810b11" "fstmiax r1, {d0, d1, d2, d3, d4, d5, d6, d7}"
    testDisasm "ec890b11" "fstmiax sb, {d0, d1, d2, d3, d4, d5, d6, d7}"
    testDisasm "ec8d0b11" "fstmiax sp, {d0, d1, d2, d3, d4, d5, d6, d7}"
    testDisasm "ec8f0b11" "fstmiax pc, {d0, d1, d2, d3, d4, d5, d6, d7}"

  /// F6.1.65 VCVTA (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.65 VCVTA``() =
    testDisasm "febc09e0" "vcvta.s32.f16 s0, s1"
    testDisasm "ffb70042" "vcvta.s16.f16 q0, q1"

  /// F6.1.69 VCVTM (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.69 VCVTM``() =
    testDisasm "febf09e0" "vcvtm.s32.f16 s0, s1"
    testDisasm "ffb70342" "vcvtm.s16.f16 q0, q1"
    testDisasm "febf0b41" "vcvtm.u32.f64 s0, d1"
    testDisasm "febf094f" "vcvtm.u32.f16 s0, s30"

  /// F6.1.7 SHA1C
  [<TestMethod>]
  member _.``F6.1.7 SHA1C``() =
    testDisasm "ef020c44" "sha1c.32 q0, q1, q2"

  /// F6.1.71 VCVTN (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.71 VCVTN``() =
    testDisasm "febd09e0" "vcvtn.s32.f16 s0, s1"
    testDisasm "ffb70142" "vcvtn.s16.f16 q0, q1"
    testDisasm "ffbb0101" "vcvtn.s32.f32 d0, d1"
    testDisasm "febd094f" "vcvtn.u32.f16 s0, s30"

  /// F6.1.73 VCVTP (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.73 VCVTP``() =
    testDisasm "febe09e0" "vcvtp.s32.f16 s0, s1"
    testDisasm "ffb70242" "vcvtp.s16.f16 q0, q1"
    testDisasm "ffbb02c2" "vcvtp.u32.f32 q0, q1"

  /// F6.1.79 VDOT (vector)
  [<TestMethod>]
  member _.``F6.1.79 VDOT``() =
    testDisasm "fc010d00" "vdot.bf16 d0, d1, d0"
    testDisasm "fe010d00" "vdot.bf16 d0, d1, d0[0]"
    testDisasm "fe000d4f" "vdot.bf16 q0, q0, d15[0]"

  /// F6.1.8 SHA1H
  [<TestMethod>]
  member _.``F6.1.8 SHA1H``() =
    testDisasm "ffb902c2" "sha1h.32 q0, q1"

  /// F6.1.87 VFMAB, VFMAT (BFloat16, vector)
  [<TestMethod>]
  member _.``F6.1.87 VFMAB``() =
    testDisasm "fc300834" "vfmab.bf16 q0, q0, q10"
    testDisasm "fe300834" "vfmab.bf16 q0, q0, d4[2]"

  /// F6.1.87 VFMAB, VFMAT (BFloat16, vector)
  [<TestMethod>]
  member _.``F6.1.87 VFMAT``() =
    testDisasm "fc300870" "vfmat.bf16 q0, q0, q8"
    testDisasm "fe30085f" "vfmat.bf16 q0, q0, d7[1]"

  /// F6.1.89 VFMAL (vector)
  [<TestMethod>]
  member _.``F6.1.89 VFMAL``() =
    testDisasm "fc210831" "vfmal.f16 d0, s2, s3"
    testDisasm "fc21085f" "vfmal.f16 q0, d1, d15"
    testDisasm "fe010834" "vfmal.f16 d0, s2, s9[0]"
    testDisasm "fe01085f" "vfmal.f16 q0, d1, d7[1]"

  /// F6.1.9 SHA1M
  [<TestMethod>]
  member _.``F6.1.9 SHA1M``() =
    testDisasm "ef220c44" "sha1m.32 q0, q1, q2"

  /// F6.1.92 VFMSL (vector)
  [<TestMethod>]
  member _.``F6.1.92 VFMSL``() =
    testDisasm "fe12085b" "vfmsl.f16 q0, d2, d3[1]"
    testDisasm "fca10834" "vfmsl.f16 d0, s2, s9"
    testDisasm "fca1085f" "vfmsl.f16 q0, d1, d15"
    testDisasm "fe110834" "vfmsl.f16 d0, s2, s9[0]"

  /// F6.1.98 VINS
  [<TestMethod>]
  member _.``F6.1.98 VINS``() =
    testDisasm "feb00ae0" "vins.f16 s0, s1"

  /// F6.1.99 VJCVT
  [<TestMethod>]
  member _.``F6.1.99 VJCVT``() =
    testDisasm "eeb90bc1" "vjcvt.s32.f64 s0, d1"
