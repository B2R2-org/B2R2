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
/// chapters describe, TBH to VPMIN in the order of their sections. Each
/// reads T32 words of the instruction and checks the text, and each word's
/// text is one binutils' objdump reads the word as too, so what is asserted
/// is a reading two decoders agree on.
/// </summary>
[<TestClass>]
type ManualT32ParserTests2() =
  let testDisasm (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let isa = ISA(Architecture.ARMv7, Endian.Big)
    let parser = Parser(isa, true, BinReader.Init Endian.Big)
    let ins = (parser :> IInstructionParsable).Parse(bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  /// A8.8.237 TBB, TBH
  [<TestMethod>]
  member _.``A8.8.237 TBH``() =
    testDisasm "e8dff012" "tbh [pc, r2, lsl #0x1]"

  /// A8.8.238 TEQ (immediate)
  [<TestMethod>]
  member _.``A8.8.238 TEQ``() =
    testDisasm "f0914f7f" "teq r1, #0xff000000"
    testDisasm "ea910f02" "teq r1, r2"
    testDisasm "ea910f42" "teq r1, r2, lsl #0x1"
    testDisasm "ea910fd2" "teq r1, r2, lsr #0x3"

  /// A8.8.24 BKPT
  [<TestMethod>]
  member _.``A8.8.24 BKPT``() =
    testDisasm "be03bf00" "bkpt #0x3"

  /// A8.8.241 TST (immediate)
  [<TestMethod>]
  member _.``A8.8.241 TST``() =
    testDisasm "4211bf00" "tst r1, r2"
    testDisasm "ea110f42" "tst r1, r2, lsl #0x1"
    testDisasm "ea110fd2" "tst r1, r2, lsr #0x3"
    testDisasm "ea111f62" "tst r1, r2, asr #0x5"

  /// A8.8.244 UADD16
  [<TestMethod>]
  member _.``A8.8.244 UADD16``() =
    testDisasm "fa91f042" "uadd16 r0, r1, r2"

  /// A8.8.245 UADD8
  [<TestMethod>]
  member _.``A8.8.245 UADD8``() =
    testDisasm "fa81f042" "uadd8 r0, r1, r2"

  /// A8.8.246 UASX
  [<TestMethod>]
  member _.``A8.8.246 UASX``() =
    testDisasm "faa1f042" "uasx r0, r1, r2"

  /// A8.8.247 UBFX
  [<TestMethod>]
  member _.``A8.8.247 UBFX``() =
    testDisasm "f3c100c4" "ubfx r0, r1, #0x3, #0x5"
    testDisasm "f3c10900" "ubfx sb, r1, #0x0, #0x1"
    testDisasm "f3c10a00" "ubfx sl, r1, #0x0, #0x1"
    testDisasm "f3c10b00" "ubfx fp, r1, #0x0, #0x1"

  /// A8.8.248 UDF
  [<TestMethod>]
  member _.``A8.8.248 UDF``() =
    testDisasm "de00bf00" "udf #0x0"
    testDisasm "f7f1a034" "udf.w #0x1034"

  /// A8.8.249 UDIV
  [<TestMethod>]
  member _.``A8.8.249 UDIV``() =
    testDisasm "fbb1f0f2" "udiv r0, r1, r2"
    testDisasm "fbb1f9f1" "udiv sb, r1, r1"
    testDisasm "fbb1faf1" "udiv sl, r1, r1"
    testDisasm "fbb1fbf1" "udiv fp, r1, r1"

  /// A8.8.25 BL, BLX (immediate)
  [<TestMethod>]
  member _.``A8.8.25 BL``() =
    testDisasm "f000f800" "bl 0x4 ; "
    testDisasm "d900bf00" "bls 0x4 ; "
    testDisasm "f2418034" "bls.w 0x106c ; "

  /// A8.8.25 BL, BLX (immediate)
  [<TestMethod>]
  member _.``A8.8.25 BLX``() =
    testDisasm "f000e802" "blx 0x8 ; "
    testDisasm "4780bf00" "blx r0"
    testDisasm "47c8bf00" "blx sb"
    testDisasm "47d0bf00" "blx sl"

  /// A8.8.250 UHADD16
  [<TestMethod>]
  member _.``A8.8.250 UHADD16``() =
    testDisasm "fa91f062" "uhadd16 r0, r1, r2"

  /// A8.8.251 UHADD8
  [<TestMethod>]
  member _.``A8.8.251 UHADD8``() =
    testDisasm "fa81f062" "uhadd8 r0, r1, r2"

  /// A8.8.252 UHASX
  [<TestMethod>]
  member _.``A8.8.252 UHASX``() =
    testDisasm "faa1f062" "uhasx r0, r1, r2"

  /// A8.8.253 UHSAX
  [<TestMethod>]
  member _.``A8.8.253 UHSAX``() =
    testDisasm "fae1f062" "uhsax r0, r1, r2"

  /// A8.8.254 UHSUB16
  [<TestMethod>]
  member _.``A8.8.254 UHSUB16``() =
    testDisasm "fad1f062" "uhsub16 r0, r1, r2"

  /// A8.8.255 UHSUB8
  [<TestMethod>]
  member _.``A8.8.255 UHSUB8``() =
    testDisasm "fac1f062" "uhsub8 r0, r1, r2"

  /// A8.8.256 UMAAL
  [<TestMethod>]
  member _.``A8.8.256 UMAAL``() =
    testDisasm "fbe20163" "umaal r0, r1, r2, r3"

  /// A8.8.257 UMLAL
  [<TestMethod>]
  member _.``A8.8.257 UMLAL``() =
    testDisasm "fbe20103" "umlal r0, r1, r2, r3"
    testDisasm "fbe10900" "umlal r0, sb, r1, r0"
    testDisasm "fbe10a00" "umlal r0, sl, r1, r0"
    testDisasm "fbe10b00" "umlal r0, fp, r1, r0"

  /// A8.8.258 UMULL
  [<TestMethod>]
  member _.``A8.8.258 UMULL``() =
    testDisasm "fba20103" "umull r0, r1, r2, r3"
    testDisasm "fba10900" "umull r0, sb, r1, r0"
    testDisasm "fba10a00" "umull r0, sl, r1, r0"
    testDisasm "fba10b00" "umull r0, fp, r1, r0"

  /// A8.8.259 UQADD16
  [<TestMethod>]
  member _.``A8.8.259 UQADD16``() =
    testDisasm "fa91f052" "uqadd16 r0, r1, r2"

  /// A8.8.260 UQADD8
  [<TestMethod>]
  member _.``A8.8.260 UQADD8``() =
    testDisasm "fa81f052" "uqadd8 r0, r1, r2"

  /// A8.8.261 UQASX
  [<TestMethod>]
  member _.``A8.8.261 UQASX``() =
    testDisasm "faa1f052" "uqasx r0, r1, r2"

  /// A8.8.262 UQSAX
  [<TestMethod>]
  member _.``A8.8.262 UQSAX``() =
    testDisasm "fae1f052" "uqsax r0, r1, r2"

  /// A8.8.263 UQSUB16
  [<TestMethod>]
  member _.``A8.8.263 UQSUB16``() =
    testDisasm "fad1f052" "uqsub16 r0, r1, r2"

  /// A8.8.264 UQSUB8
  [<TestMethod>]
  member _.``A8.8.264 UQSUB8``() =
    testDisasm "fac1f052" "uqsub8 r0, r1, r2"

  /// A8.8.265 USAD8
  [<TestMethod>]
  member _.``A8.8.265 USAD8``() =
    testDisasm "fb71f002" "usad8 r0, r1, r2"
    testDisasm "fb71f900" "usad8 sb, r1, r0"
    testDisasm "fb71fa00" "usad8 sl, r1, r0"
    testDisasm "fb71fb00" "usad8 fp, r1, r0"

  /// A8.8.266 USADA8
  [<TestMethod>]
  member _.``A8.8.266 USADA8``() =
    testDisasm "fb713002" "usada8 r0, r1, r2, r3"
    testDisasm "fb710900" "usada8 sb, r1, r0, r0"
    testDisasm "fb710a00" "usada8 sl, r1, r0, r0"
    testDisasm "fb710b00" "usada8 fp, r1, r0, r0"

  /// A8.8.267 USAT
  [<TestMethod>]
  member _.``A8.8.267 USAT``() =
    testDisasm "f3810003" "usat r0, #0x3, r1"
    testDisasm "f3810043" "usat r0, #0x3, r1, lsl #0x1"
    testDisasm "f3a11043" "usat r0, #0x3, r1, asr #0x5"
    testDisasm "f3810900" "usat sb, #0x0, r1"

  /// A8.8.268 USAT16
  [<TestMethod>]
  member _.``A8.8.268 USAT16``() =
    testDisasm "f3a10003" "usat16 r0, #0x3, r1"
    testDisasm "f3a10900" "usat16 sb, #0x0, r1"
    testDisasm "f3a10a00" "usat16 sl, #0x0, r1"
    testDisasm "f3a10b00" "usat16 fp, #0x0, r1"

  /// A8.8.269 USAX
  [<TestMethod>]
  member _.``A8.8.269 USAX``() =
    testDisasm "fae1f042" "usax r0, r1, r2"

  /// A8.8.27 BX
  [<TestMethod>]
  member _.``A8.8.27 BX``() =
    testDisasm "4700bf00" "bx r0"
    testDisasm "4748bf00" "bx sb"
    testDisasm "4750bf00" "bx sl"
    testDisasm "4758bf00" "bx fp"

  /// A8.8.270 USUB16
  [<TestMethod>]
  member _.``A8.8.270 USUB16``() =
    testDisasm "fad1f042" "usub16 r0, r1, r2"

  /// A8.8.271 USUB8
  [<TestMethod>]
  member _.``A8.8.271 USUB8``() =
    testDisasm "fac1f042" "usub8 r0, r1, r2"

  /// A8.8.272 UXTAB
  [<TestMethod>]
  member _.``A8.8.272 UXTAB``() =
    testDisasm "fa51f082" "uxtab r0, r1, r2"

  /// A8.8.273 UXTAB16
  [<TestMethod>]
  member _.``A8.8.273 UXTAB16``() =
    testDisasm "fa31f082" "uxtab16 r0, r1, r2"

  /// A8.8.274 UXTAH
  [<TestMethod>]
  member _.``A8.8.274 UXTAH``() =
    testDisasm "fa11f082" "uxtah r0, r1, r2"

  /// A8.8.275 UXTB
  [<TestMethod>]
  member _.``A8.8.275 UXTB``() =
    testDisasm "b2c8bf00" "uxtb r0, r1"
    testDisasm "fa5ff082" "uxtb.w r0, r2"

  /// A8.8.276 UXTB16
  [<TestMethod>]
  member _.``A8.8.276 UXTB16``() =
    testDisasm "fa3ff081" "uxtb16 r0, r1"

  /// A8.8.277 UXTH
  [<TestMethod>]
  member _.``A8.8.277 UXTH``() =
    testDisasm "b288bf00" "uxth r0, r1"
    testDisasm "fa1ff082" "uxth.w r0, r2"

  /// A8.8.278 VABA, VABAL
  [<TestMethod>]
  member _.``A8.8.278 VABA``() =
    testDisasm "ef120754" "vaba.s16 q0, q1, q2"
    testDisasm "ff020754" "vaba.u8 q0, q1, q2"
    testDisasm "ef010712" "vaba.s8 d0, d1, d2"
    testDisasm "ff010712" "vaba.u8 d0, d1, d2"

  /// A8.8.278 VABA, VABAL
  [<TestMethod>]
  member _.``A8.8.278 VABAL``() =
    testDisasm "ef810502" "vabal.s8 q0, d1, d2"
    testDisasm "ff810500" "vabal.u8 q0, d1, d0"

  /// A8.8.279 VABD, VABDL (integer)
  [<TestMethod>]
  member _.``A8.8.279 VABD``() =
    testDisasm "ff320d44" "vabd.f16 q0, q1, q2"
    testDisasm "ef120744" "vabd.s16 q0, q1, q2"
    testDisasm "ff020744" "vabd.u8 q0, q1, q2"
    testDisasm "ef010702" "vabd.s8 d0, d1, d2"

  /// A8.8.279 VABD, VABDL (integer)
  [<TestMethod>]
  member _.``A8.8.279 VABDL``() =
    testDisasm "ef810702" "vabdl.s8 q0, d1, d2"
    testDisasm "ff810700" "vabdl.u8 q0, d1, d0"

  /// A8.8.28 BXJ
  [<TestMethod>]
  member _.``A8.8.28 BXJ``() =
    testDisasm "f3c18f00" "bxj r1"

  /// A8.8.281 VABS
  [<TestMethod>]
  member _.``A8.8.281 VABS``() =
    testDisasm "eeb009e0" "vabs.f16 s0, s1"
    testDisasm "ffb50742" "vabs.f16 q0, q1"
    testDisasm "ffb10344" "vabs.s8 q0, q2"
    testDisasm "ffb10302" "vabs.s8 d0, d2"

  /// A8.8.282 VACGE, VACGT, VACLE, VACLT
  [<TestMethod>]
  member _.``A8.8.282 VACGE``() =
    testDisasm "ff120e54" "vacge.f16 q0, q1, q2"
    testDisasm "ff020e11" "vacge.f32 d0, d2, d1"

  /// A8.8.282 VACGE, VACGT, VACLE, VACLT
  [<TestMethod>]
  member _.``A8.8.282 VACGT``() =
    testDisasm "ff320e54" "vacgt.f16 q0, q1, q2"
    testDisasm "ff210e34" "vacgt.f32 d0, d1, d20"

  /// A8.8.282 VACGE, VACGT, VACLE, VACLT
  [<TestMethod>]
  member _.``A8.8.282 VACLE``() =
    testDisasm "ff120e54" "vacge.f16 q0, q1, q2"
    testDisasm "ff020e11" "vacge.f32 d0, d2, d1"

  /// A8.8.282 VACGE, VACGT, VACLE, VACLT
  [<TestMethod>]
  member _.``A8.8.282 VACLT``() =
    testDisasm "ff320e54" "vacgt.f16 q0, q1, q2"
    testDisasm "ff210e34" "vacgt.f32 d0, d1, d20"

  /// A8.8.283 VADD (integer)
  [<TestMethod>]
  member _.``A8.8.283 VADD``() =
    testDisasm "ee300981" "vadd.f16 s0, s1, s2"
    testDisasm "ef120d44" "vadd.f16 q0, q1, q2"
    testDisasm "ef120844" "vadd.i16 q0, q1, q2"
    testDisasm "ef010802" "vadd.i8 d0, d1, d2"

  /// A8.8.285 VADDHN
  [<TestMethod>]
  member _.``A8.8.285 VADDHN``() =
    testDisasm "ef920404" "vaddhn.i32 d0, q1, q2"

  /// A8.8.286 VADDL, VADDW
  [<TestMethod>]
  member _.``A8.8.286 VADDL``() =
    testDisasm "ef910002" "vaddl.s16 q0, d1, d2"
    testDisasm "ff810002" "vaddl.u8 q0, d1, d2"

  /// A8.8.286 VADDL, VADDW
  [<TestMethod>]
  member _.``A8.8.286 VADDW``() =
    testDisasm "ef800101" "vaddw.s8 q0, q0, d1"
    testDisasm "ff800100" "vaddw.u8 q0, q0, d0"

  /// A8.8.287 VAND (immediate)
  [<TestMethod>]
  member _.``A8.8.287 VAND``() =
    testDisasm "ef020154" "vand q0, q1, q2"
    testDisasm "ef011112" "vand d1, d1, d2"

  /// A8.8.289 VBIC (immediate)
  [<TestMethod>]
  member _.``A8.8.289 VBIC``() =
    testDisasm "ef120154" "vbic q0, q1, q2"
    testDisasm "ef810970" "vbic.i16 q0, #0x10"
    testDisasm "ef810930" "vbic.i16 d0, #0x10"
    testDisasm "ef111112" "vbic d1, d1, d2"

  /// A8.8.29 CBNZ, CBZ
  [<TestMethod>]
  member _.``A8.8.29 CBNZ``() =
    testDisasm "b900bf00" "cbnz r0, 0x4 ; "

  /// A8.8.29 CBNZ, CBZ
  [<TestMethod>]
  member _.``A8.8.29 CBZ``() =
    testDisasm "b100bf00" "cbz r0, 0x4 ; "

  /// A8.8.291 VBIF, VBIT, VBSL
  [<TestMethod>]
  member _.``A8.8.291 VBIF``() =
    testDisasm "ff320154" "vbif q0, q1, q2"
    testDisasm "ff310134" "vbif d0, d1, d20"

  /// A8.8.291 VBIF, VBIT, VBSL
  [<TestMethod>]
  member _.``A8.8.291 VBIT``() =
    testDisasm "ff220154" "vbit q0, q1, q2"
    testDisasm "ff210134" "vbit d0, d1, d20"

  /// A8.8.291 VBIF, VBIT, VBSL
  [<TestMethod>]
  member _.``A8.8.291 VBSL``() =
    testDisasm "ff120154" "vbsl q0, q1, q2"
    testDisasm "ff110134" "vbsl d0, d1, d20"

  /// A8.8.292 VCEQ (register)
  [<TestMethod>]
  member _.``A8.8.292 VCEQ``() =
    testDisasm "ef120e44" "vceq.f16 q0, q1, q2"
    testDisasm "ffb50542" "vceq.f16 q0, q1, #0x0"
    testDisasm "ff010812" "vceq.i8 d0, d1, d2"
    testDisasm "ef010e02" "vceq.f32 d0, d1, d2"

  /// A8.8.294 VCGE (register)
  [<TestMethod>]
  member _.``A8.8.294 VCGE``() =
    testDisasm "ff120e44" "vcge.f16 q0, q1, q2"
    testDisasm "ffb504c2" "vcge.f16 q0, q1, #0x0"
    testDisasm "ef010312" "vcge.s8 d0, d1, d2"
    testDisasm "ff010312" "vcge.u8 d0, d1, d2"

  /// A8.8.296 VCGT (register)
  [<TestMethod>]
  member _.``A8.8.296 VCGT``() =
    testDisasm "ff320e44" "vcgt.f16 q0, q1, q2"
    testDisasm "ffb50442" "vcgt.f16 q0, q1, #0x0"
    testDisasm "ef010302" "vcgt.s8 d0, d1, d2"
    testDisasm "ff010302" "vcgt.u8 d0, d1, d2"

  /// A8.8.298 VCLE (register)
  [<TestMethod>]
  member _.``A8.8.298 VCLE``() =
    testDisasm "ffb505c2" "vcle.f16 q0, q1, #0x0"
    testDisasm "ffb101c4" "vcle.s8 q0, q2, #0x0"
    testDisasm "ffb10182" "vcle.s8 d0, d2, #0x0"
    testDisasm "ffb90582" "vcle.f32 d0, d2, #0x0"

  /// A8.8.300 VCLS
  [<TestMethod>]
  member _.``A8.8.300 VCLS``() =
    testDisasm "ffb00444" "vcls.s8 q0, q2"
    testDisasm "ffb00402" "vcls.s8 d0, d2"

  /// A8.8.301 VCLT (register)
  [<TestMethod>]
  member _.``A8.8.301 VCLT``() =
    testDisasm "ffb50642" "vclt.f16 q0, q1, #0x0"
    testDisasm "ffb10244" "vclt.s8 q0, q2, #0x0"
    testDisasm "ffb10202" "vclt.s8 d0, d2, #0x0"
    testDisasm "ffb90602" "vclt.f32 d0, d2, #0x0"

  /// A8.8.303 VCLZ
  [<TestMethod>]
  member _.``A8.8.303 VCLZ``() =
    testDisasm "ffb004c4" "vclz.i8 q0, q2"
    testDisasm "ffb00482" "vclz.i8 d0, d2"

  /// A8.8.304 VCMP, VCMPE
  [<TestMethod>]
  member _.``A8.8.304 VCMP``() =
    testDisasm "eeb40960" "vcmp.f16 s0, s1"
    testDisasm "eeb40b42" "vcmp.f64 d0, d2"

  /// A8.8.304 VCMP, VCMPE
  [<TestMethod>]
  member _.``A8.8.304 VCMPE``() =
    testDisasm "eeb409e0" "vcmpe.f16 s0, s1"
    testDisasm "eeb40bc2" "vcmpe.f64 d0, d2"

  /// A8.8.305 VCNT
  [<TestMethod>]
  member _.``A8.8.305 VCNT``() =
    testDisasm "ffb00544" "vcnt.8 q0, q2"
    testDisasm "ffb00502" "vcnt.8 d0, d2"

  /// A8.8.306 VCVT (between floating-point and integer, Advanced SIMD)
  [<TestMethod>]
  member _.``A8.8.306 VCVT``() =
    testDisasm "eebd09e0" "vcvt.s32.f16 s0, s1"
    testDisasm "eebc09e0" "vcvt.u32.f16 s0, s1"
    testDisasm "eeb809e0" "vcvt.f16.s32 s0, s1"
    testDisasm "eeb80960" "vcvt.f16.u32 s0, s1"

  /// A8.8.307 VCVT, VCVTR (between floating-point and integer, Floating-point)
  [<TestMethod>]
  member _.``A8.8.307 VCVTR``() =
    testDisasm "eebd0960" "vcvtr.s32.f16 s0, s1"
    testDisasm "eebd0b42" "vcvtr.s32.f64 s0, d2"
    testDisasm "eebc0b42" "vcvtr.u32.f64 s0, d2"
    testDisasm "eebc0a41" "vcvtr.u32.f32 s0, s2"

  /// A8.8.312 VCVTB, VCVTT
  [<TestMethod>]
  member _.``A8.8.312 VCVTB``() =
    testDisasm "eeb20a60" "vcvtb.f32.f16 s0, s1"

  /// A8.8.312 VCVTB, VCVTT
  [<TestMethod>]
  member _.``A8.8.312 VCVTT``() =
    testDisasm "eeb20ae0" "vcvtt.f32.f16 s0, s1"

  /// A8.8.313 VDIV
  [<TestMethod>]
  member _.``A8.8.313 VDIV``() =
    testDisasm "ee800981" "vdiv.f16 s0, s1, s2"
    testDisasm "ee810b02" "vdiv.f64 d0, d1, d2"

  /// A8.8.314 VDUP (scalar)
  [<TestMethod>]
  member _.``A8.8.314 VDUP``() =
    testDisasm "eec01b10" "vdup.8 d0, r1"
    testDisasm "ee819b10" "vdup.32 d1, sb"
    testDisasm "ee81ab10" "vdup.32 d1, sl"
    testDisasm "ee81bb10" "vdup.32 d1, fp"

  /// A8.8.316 VEOR
  [<TestMethod>]
  member _.``A8.8.316 VEOR``() =
    testDisasm "ff020154" "veor q0, q1, q2"
    testDisasm "ff011112" "veor d1, d1, d2"

  /// A8.8.317 VEXT
  [<TestMethod>]
  member _.``A8.8.317 VEXT``() =
    testDisasm "efb00142" "vext.8 q0, q0, q1, #0x1"
    testDisasm "efb10000" "vext.8 d0, d1, d0, #0x0"

  /// A8.8.318 VFMA, VFMS
  [<TestMethod>]
  member _.``A8.8.318 VFMA``() =
    testDisasm "eea00981" "vfma.f16 s0, s1, s2"
    testDisasm "ef120c54" "vfma.f16 q0, q1, q2"
    testDisasm "eea10b00" "vfma.f64 d0, d1, d0"

  /// A8.8.318 VFMA, VFMS
  [<TestMethod>]
  member _.``A8.8.318 VFMS``() =
    testDisasm "eea009c1" "vfms.f16 s0, s1, s2"
    testDisasm "ef320c54" "vfms.f16 q0, q1, q2"
    testDisasm "eea10b4f" "vfms.f64 d0, d1, d15"

  /// A8.8.319 VFNMA, VFNMS
  [<TestMethod>]
  member _.``A8.8.319 VFNMA``() =
    testDisasm "ee9009c1" "vfnma.f16 s0, s1, s2"
    testDisasm "ee910b4f" "vfnma.f64 d0, d1, d15"

  /// A8.8.319 VFNMA, VFNMS
  [<TestMethod>]
  member _.``A8.8.319 VFNMS``() =
    testDisasm "ee900981" "vfnms.f16 s0, s1, s2"
    testDisasm "ee910b00" "vfnms.f64 d0, d1, d0"

  /// A8.8.32 CLREX
  [<TestMethod>]
  member _.``A8.8.32 CLREX``() =
    testDisasm "f3bf8f2f" "clrex"

  /// A8.8.320 VHADD, VHSUB
  [<TestMethod>]
  member _.``A8.8.320 VHADD``() =
    testDisasm "ef020044" "vhadd.s8 q0, q1, q2"
    testDisasm "ef010000" "vhadd.s8 d0, d1, d0"
    testDisasm "ff010000" "vhadd.u8 d0, d1, d0"

  /// A8.8.320 VHADD, VHSUB
  [<TestMethod>]
  member _.``A8.8.320 VHSUB``() =
    testDisasm "ef020244" "vhsub.s8 q0, q1, q2"
    testDisasm "ef010200" "vhsub.s8 d0, d1, d0"
    testDisasm "ff010200" "vhsub.u8 d0, d1, d0"

  /// A8.8.321 VLD1 (multiple single elements)
  [<TestMethod>]
  member _.``A8.8.321 VLD1``() =
    testDisasm "f921070f" "vld1.8 {d0}, [r1]"
    testDisasm "f9210234" "vld1.8 {d0, d1, d2, d3}, [r1:256], r4"
    testDisasm "f9210200" "vld1.8 {d0, d1, d2, d3}, [r1], r0"
    testDisasm "f921024f" "vld1.16 {d0, d1, d2, d3}, [r1]"

  /// A8.8.324 VLD2 (multiple 2-element structures)
  [<TestMethod>]
  member _.``A8.8.324 VLD2``() =
    testDisasm "f921080f" "vld2.8 {d0, d1}, [r1]"
    testDisasm "f9210334" "vld2.8 {d0, d1, d2, d3}, [r1:256], r4"
    testDisasm "f9210300" "vld2.8 {d0, d1, d2, d3}, [r1], r0"
    testDisasm "f921034f" "vld2.16 {d0, d1, d2, d3}, [r1]"

  /// A8.8.327 VLD3 (multiple 3-element structures)
  [<TestMethod>]
  member _.``A8.8.327 VLD3``() =
    testDisasm "f921040f" "vld3.8 {d0, d1, d2}, [r1]"
    testDisasm "f9210400" "vld3.8 {d0, d1, d2}, [r1], r0"
    testDisasm "f9210410" "vld3.8 {d0, d1, d2}, [r1:64], r0"
    testDisasm "f921045f" "vld3.16 {d0, d1, d2}, [r1:64]"

  /// A8.8.33 CLZ
  [<TestMethod>]
  member _.``A8.8.33 CLZ``() =
    testDisasm "fab1f081" "clz r0, r1"

  /// A8.8.330 VLD4 (multiple 4-element structures)
  [<TestMethod>]
  member _.``A8.8.330 VLD4``() =
    testDisasm "f921000f" "vld4.8 {d0, d1, d2, d3}, [r1]"
    testDisasm "f9210034" "vld4.8 {d0, d1, d2, d3}, [r1:256], r4"
    testDisasm "f9210000" "vld4.8 {d0, d1, d2, d3}, [r1], r0"
    testDisasm "f921005f" "vld4.16 {d0, d1, d2, d3}, [r1:64]"

  /// A8.8.333 VLDM
  [<TestMethod>]
  member _.``A8.8.333 VLDM``() =
    testDisasm "ec910b04" "vldmia r1, {d0, d1}"
    testDisasm "ecbd0b04" "vldmia sp!, {d0, d1}"
    testDisasm "ecb10b08" "vldmia r1!, {d0, d1, d2, d3}"
    testDisasm "ec910a01" "vldmia r1, {s0}"

  /// A8.8.334 VLDR
  [<TestMethod>]
  member _.``A8.8.334 VLDR``() =
    testDisasm "ed910900" "vldr.16 s0, [r1]"
    testDisasm "ed9f0b00" "vldr.64 d0, [pc]"
    testDisasm "ed910a00" "vldr s0, [r1]"
    testDisasm "ed9f0a00" "vldr.32 s0, [pc]"

  /// A8.8.335 VMAX, VMIN (integer)
  [<TestMethod>]
  member _.``A8.8.335 VMAX``() =
    testDisasm "ef120f44" "vmax.f16 q0, q1, q2"
    testDisasm "ef020644" "vmax.s8 q0, q1, q2"
    testDisasm "ef010600" "vmax.s8 d0, d1, d0"
    testDisasm "ef010f00" "vmax.f32 d0, d1, d0"

  /// A8.8.335 VMAX, VMIN (integer)
  [<TestMethod>]
  member _.``A8.8.335 VMIN``() =
    testDisasm "ef320f44" "vmin.f16 q0, q1, q2"
    testDisasm "ef020654" "vmin.s8 q0, q1, q2"
    testDisasm "ef010634" "vmin.s8 d0, d1, d20"
    testDisasm "ef210f00" "vmin.f32 d0, d1, d0"

  /// A8.8.337 VMLA, VMLAL, VMLS, VMLSL (integer)
  [<TestMethod>]
  member _.``A8.8.337 VMLA``() =
    testDisasm "ee000981" "vmla.f16 s0, s1, s2"
    testDisasm "ef120d54" "vmla.f16 q0, q1, q2"
    testDisasm "ff92016c" "vmla.f16 q0, q1, d4[3]"
    testDisasm "ef020944" "vmla.i8 q0, q1, q2"

  /// A8.8.337 VMLA, VMLAL, VMLS, VMLSL (integer)
  [<TestMethod>]
  member _.``A8.8.337 VMLAL``() =
    testDisasm "ef810802" "vmlal.s8 q0, d1, d2"
    testDisasm "ef91024f" "vmlal.s16 q0, d1, d7[1]"
    testDisasm "ff810800" "vmlal.u8 q0, d1, d0"
    testDisasm "ff91024f" "vmlal.u16 q0, d1, d7[1]"

  /// A8.8.337 VMLA, VMLAL, VMLS, VMLSL (integer)
  [<TestMethod>]
  member _.``A8.8.337 VMLS``() =
    testDisasm "ee0009c1" "vmls.f16 s0, s1, s2"
    testDisasm "ef320d54" "vmls.f16 q0, q1, q2"
    testDisasm "ff92056c" "vmls.f16 q0, q1, d4[3]"
    testDisasm "ff020944" "vmls.i8 q0, q1, q2"

  /// A8.8.337 VMLA, VMLAL, VMLS, VMLSL (integer)
  [<TestMethod>]
  member _.``A8.8.337 VMLSL``() =
    testDisasm "ef810a02" "vmlsl.s8 q0, d1, d2"
    testDisasm "ef91064f" "vmlsl.s16 q0, d1, d7[1]"
    testDisasm "ff810a00" "vmlsl.u8 q0, d1, d0"
    testDisasm "ff91064f" "vmlsl.u16 q0, d1, d7[1]"

  /// A8.8.34 CMN (immediate)
  [<TestMethod>]
  member _.``A8.8.34 CMN``() =
    testDisasm "f1114f7f" "cmn r1, #0xff000000"
    testDisasm "42d1bf00" "cmn r1, r2"
    testDisasm "eb110f42" "cmn r1, r2, lsl #0x1"
    testDisasm "eb110fd2" "cmn r1, r2, lsr #0x3"

  /// A8.8.340 VMOV (immediate)
  [<TestMethod>]
  member _.``A8.8.340 VMOV``() =
    testDisasm "ee000910" "vmov.f16 s0, r0"
    testDisasm "ee100990" "vmov.f16 r0, s1"
    testDisasm "ef810e50" "vmov.i8 q0, #0x10"
    testDisasm "ef810e10" "vmov.i8 d0, #0x10"

  /// A8.8.347 VMOVL
  [<TestMethod>]
  member _.``A8.8.347 VMOVL``() =
    testDisasm "ef880a12" "vmovl.s8 q0, d2"
    testDisasm "ff880a12" "vmovl.u8 q0, d2"

  /// A8.8.348 VMOVN
  [<TestMethod>]
  member _.``A8.8.348 VMOVN``() =
    testDisasm "ffb20204" "vmovn.i16 d0, q2"

  /// A8.8.349 VMRS
  [<TestMethod>]
  member _.``A8.8.349 VMRS``() =
    testDisasm "eef10a10" "vmrs r0, fpscr"
    testDisasm "eef19a10" "vmrs sb, fpscr"
    testDisasm "eef1aa10" "vmrs sl, fpscr"
    testDisasm "eef1ba10" "vmrs fp, fpscr"

  /// A8.8.350 VMSR
  [<TestMethod>]
  member _.``A8.8.350 VMSR``() =
    testDisasm "eee10a10" "vmsr fpscr, r0"
    testDisasm "eee19a10" "vmsr fpscr, sb"
    testDisasm "eee1aa10" "vmsr fpscr, sl"
    testDisasm "eee1ba10" "vmsr fpscr, fp"

  /// A8.8.351 VMUL, VMULL (integer and polynomial)
  [<TestMethod>]
  member _.``A8.8.351 VMUL``() =
    testDisasm "ee200981" "vmul.f16 s0, s1, s2"
    testDisasm "ff120d54" "vmul.f16 q0, q1, q2"
    testDisasm "ff92096c" "vmul.f16 q0, q1, d4[3]"
    testDisasm "ef120954" "vmul.i16 q0, q1, q2"

  /// A8.8.351 VMUL, VMULL (integer and polynomial)
  [<TestMethod>]
  member _.``A8.8.351 VMULL``() =
    testDisasm "ef810c02" "vmull.s8 q0, d1, d2"
    testDisasm "efa20e03" "vmull.p64 q0, d2, d3"
    testDisasm "ef910a4f" "vmull.s16 q0, d1, d7[1]"
    testDisasm "ff810c00" "vmull.u8 q0, d1, d0"

  /// A8.8.354 VMVN (immediate)
  [<TestMethod>]
  member _.``A8.8.354 VMVN``() =
    testDisasm "ffb005c2" "vmvn q0, q1"
    testDisasm "ef810870" "vmvn.i16 q0, #0x10"
    testDisasm "ef810830" "vmvn.i16 d0, #0x10"
    testDisasm "ffb00582" "vmvn d0, d2"

  /// A8.8.356 VNEG
  [<TestMethod>]
  member _.``A8.8.356 VNEG``() =
    testDisasm "eeb10960" "vneg.f16 s0, s1"
    testDisasm "ffb507c2" "vneg.f16 q0, q1"
    testDisasm "ffb103c4" "vneg.s8 q0, q2"
    testDisasm "ffb10382" "vneg.s8 d0, d2"

  /// A8.8.357 VNMLA, VNMLS, VNMUL
  [<TestMethod>]
  member _.``A8.8.357 VNMLA``() =
    testDisasm "ee1009c1" "vnmla.f16 s0, s1, s2"
    testDisasm "ee110b42" "vnmla.f64 d0, d1, d2"

  /// A8.8.357 VNMLA, VNMLS, VNMUL
  [<TestMethod>]
  member _.``A8.8.357 VNMLS``() =
    testDisasm "ee100981" "vnmls.f16 s0, s1, s2"
    testDisasm "ee110b00" "vnmls.f64 d0, d1, d0"

  /// A8.8.357 VNMLA, VNMLS, VNMUL
  [<TestMethod>]
  member _.``A8.8.357 VNMUL``() =
    testDisasm "ee2009c1" "vnmul.f16 s0, s1, s2"
    testDisasm "ee210b4f" "vnmul.f64 d0, d1, d15"

  /// A8.8.358 VORN (immediate)
  [<TestMethod>]
  member _.``A8.8.358 VORN``() =
    testDisasm "ef320154" "vorn q0, q1, q2"
    testDisasm "ef311112" "vorn d1, d1, d2"

  /// A8.8.360 VORR (immediate)
  [<TestMethod>]
  member _.``A8.8.360 VORR``() =
    testDisasm "ef220154" "vorr q0, q1, q2"
    testDisasm "ef810950" "vorr.i16 q0, #0x10"
    testDisasm "ef810910" "vorr.i16 d0, #0x10"
    testDisasm "ef211112" "vorr d1, d1, d2"

  /// A8.8.362 VPADAL
  [<TestMethod>]
  member _.``A8.8.362 VPADAL``() =
    testDisasm "ffb00644" "vpadal.s8 q0, q2"
    testDisasm "ffb006c4" "vpadal.u8 q0, q2"
    testDisasm "ffb00602" "vpadal.s8 d0, d2"
    testDisasm "ffb00682" "vpadal.u8 d0, d2"

  /// A8.8.363 VPADD (integer)
  [<TestMethod>]
  member _.``A8.8.363 VPADD``() =
    testDisasm "ff110d02" "vpadd.f16 d0, d1, d2"
    testDisasm "ef110b12" "vpadd.i16 d0, d1, d2"

  /// A8.8.365 VPADDL
  [<TestMethod>]
  member _.``A8.8.365 VPADDL``() =
    testDisasm "ffb00244" "vpaddl.s8 q0, q2"
    testDisasm "ffb002c4" "vpaddl.u8 q0, q2"
    testDisasm "ffb00202" "vpaddl.s8 d0, d2"
    testDisasm "ffb00282" "vpaddl.u8 d0, d2"

  /// A8.8.366 VPMAX, VPMIN (integer)
  [<TestMethod>]
  member _.``A8.8.366 VPMAX``() =
    testDisasm "ff110f02" "vpmax.f16 d0, d1, d2"
    testDisasm "ef010a02" "vpmax.s8 d0, d1, d2"
    testDisasm "ff010a00" "vpmax.u8 d0, d1, d0"

  /// A8.8.366 VPMAX, VPMIN (integer)
  [<TestMethod>]
  member _.``A8.8.366 VPMIN``() =
    testDisasm "ff310f02" "vpmin.f16 d0, d1, d2"
    testDisasm "ef010a12" "vpmin.s8 d0, d1, d2"
    testDisasm "ff010a34" "vpmin.u8 d0, d1, d20"
