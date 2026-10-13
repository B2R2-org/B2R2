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
/// One test for each A32 instruction DDI0406C and DDI0487F.c's AArch32
/// chapters describe, SXTAH to VPADDL in the order of their sections. Each
/// reads A32 words of the instruction and checks the text, and each word's
/// text is one binutils' objdump reads the word as too, so what is asserted
/// is a reading two decoders agree on.
/// </summary>
[<TestClass>]
type ManualA32ParserTests2() =
  let testDisasm (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let isa = ISA(Architecture.ARMv7, Endian.Big)
    let parser = Parser(isa, false, BinReader.Init Endian.Big)
    let ins = (parser :> IInstructionParsable).Parse(bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  /// A8.8.233 SXTAH
  [<TestMethod>]
  member _.``A8.8.233 SXTAH``() =
    testDisasm "e6b10072" "sxtah r0, r1, r2"
    testDisasm "e6b12474" "sxtah r2, r1, r4, ror #0x8"
    testDisasm "e6b1d074" "sxtah sp, r1, r4"
    testDisasm "e6b1d474" "sxtah sp, r1, r4, ror #0x8"

  /// A8.8.234 SXTB
  [<TestMethod>]
  member _.``A8.8.234 SXTB``() =
    testDisasm "e6af0071" "sxtb r0, r1"
    testDisasm "e6af2474" "sxtb r2, r4, ror #0x8"
    testDisasm "e6afd074" "sxtb sp, r4"
    testDisasm "e6afd474" "sxtb sp, r4, ror #0x8"

  /// A8.8.235 SXTB16
  [<TestMethod>]
  member _.``A8.8.235 SXTB16``() =
    testDisasm "e68f0071" "sxtb16 r0, r1"
    testDisasm "e68f2474" "sxtb16 r2, r4, ror #0x8"
    testDisasm "e68fd074" "sxtb16 sp, r4"
    testDisasm "e68fd474" "sxtb16 sp, r4, ror #0x8"

  /// A8.8.236 SXTH
  [<TestMethod>]
  member _.``A8.8.236 SXTH``() =
    testDisasm "e6bf0071" "sxth r0, r1"
    testDisasm "e6bf2474" "sxth r2, r4, ror #0x8"
    testDisasm "e6bfd074" "sxth sp, r4"
    testDisasm "e6bfd474" "sxth sp, r4, ror #0x8"

  /// A8.8.238 TEQ (immediate)
  [<TestMethod>]
  member _.``A8.8.238 TEQ``() =
    testDisasm "e1310002" "teq r1, r2"
    testDisasm "e1310082" "teq r1, r2, lsl #0x1"
    testDisasm "e13101a2" "teq r1, r2, lsr #0x3"
    testDisasm "e13102c2" "teq r1, r2, asr #0x5"

  /// A8.8.24 BKPT
  [<TestMethod>]
  member _.``A8.8.24 BKPT``() =
    testDisasm "e1200073" "bkpt #0x3"

  /// A8.8.241 TST (immediate)
  [<TestMethod>]
  member _.``A8.8.241 TST``() =
    testDisasm "e1110002" "tst r1, r2"
    testDisasm "e1110082" "tst r1, r2, lsl #0x1"
    testDisasm "e11101a2" "tst r1, r2, lsr #0x3"
    testDisasm "e11102c2" "tst r1, r2, asr #0x5"

  /// A8.8.244 UADD16
  [<TestMethod>]
  member _.``A8.8.244 UADD16``() =
    testDisasm "e6510f12" "uadd16 r0, r1, r2"

  /// A8.8.245 UADD8
  [<TestMethod>]
  member _.``A8.8.245 UADD8``() =
    testDisasm "e6510f92" "uadd8 r0, r1, r2"

  /// A8.8.246 UASX
  [<TestMethod>]
  member _.``A8.8.246 UASX``() =
    testDisasm "e6510f32" "uasx r0, r1, r2"

  /// A8.8.247 UBFX
  [<TestMethod>]
  member _.``A8.8.247 UBFX``() =
    testDisasm "e7e401d1" "ubfx r0, r1, #0x3, #0x5"
    testDisasm "e7e1d054" "ubfx sp, r4, #0x0, #0x2"
    testDisasm "17e12054" "ubfxne r2, r4, #0x0, #0x2"
    testDisasm "17e1d054" "ubfxne sp, r4, #0x0, #0x2"

  /// A8.8.248 UDF
  [<TestMethod>]
  member _.``A8.8.248 UDF``() =
    testDisasm "e7f120f4" "udf #0x1204"

  /// A8.8.249 UDIV
  [<TestMethod>]
  member _.``A8.8.249 UDIV``() =
    testDisasm "e730f211" "udiv r0, r1, r2"
    testDisasm "e731f914" "udiv r1, r4, sb"
    testDisasm "e731fa14" "udiv r1, r4, sl"
    testDisasm "e731fb14" "udiv r1, r4, fp"

  /// A8.8.25 BL, BLX (immediate)
  [<TestMethod>]
  member _.``A8.8.25 BL``() =
    testDisasm "ebffffff" "bl 0x4 ; "
    testDisasm "1b012004" "blne 0x48018 ; "

  /// A8.8.25 BL, BLX (immediate)
  [<TestMethod>]
  member _.``A8.8.25 BLX``() =
    testDisasm "faffffff" "blx 0x4 ; "

  /// A8.8.250 UHADD16
  [<TestMethod>]
  member _.``A8.8.250 UHADD16``() =
    testDisasm "e6710f12" "uhadd16 r0, r1, r2"

  /// A8.8.251 UHADD8
  [<TestMethod>]
  member _.``A8.8.251 UHADD8``() =
    testDisasm "e6710f92" "uhadd8 r0, r1, r2"

  /// A8.8.252 UHASX
  [<TestMethod>]
  member _.``A8.8.252 UHASX``() =
    testDisasm "e6710f32" "uhasx r0, r1, r2"

  /// A8.8.253 UHSAX
  [<TestMethod>]
  member _.``A8.8.253 UHSAX``() =
    testDisasm "e6710f52" "uhsax r0, r1, r2"

  /// A8.8.254 UHSUB16
  [<TestMethod>]
  member _.``A8.8.254 UHSUB16``() =
    testDisasm "e6710f72" "uhsub16 r0, r1, r2"

  /// A8.8.255 UHSUB8
  [<TestMethod>]
  member _.``A8.8.255 UHSUB8``() =
    testDisasm "e6710ff2" "uhsub8 r0, r1, r2"

  /// A8.8.256 UMAAL
  [<TestMethod>]
  member _.``A8.8.256 UMAAL``() =
    testDisasm "e0410392" "umaal r0, r1, r2, r3"
    testDisasm "e0412994" "umaal r2, r1, r4, sb"
    testDisasm "e0412a94" "umaal r2, r1, r4, sl"
    testDisasm "e0412b94" "umaal r2, r1, r4, fp"

  /// A8.8.257 UMLAL
  [<TestMethod>]
  member _.``A8.8.257 UMLAL``() =
    testDisasm "e0a10392" "umlal r0, r1, r2, r3"
    testDisasm "e0b10291" "umlals r0, r1, r1, r2"
    testDisasm "e0a12994" "umlal r2, r1, r4, sb"
    testDisasm "e0a12a94" "umlal r2, r1, r4, sl"

  /// A8.8.258 UMULL
  [<TestMethod>]
  member _.``A8.8.258 UMULL``() =
    testDisasm "e0810392" "umull r0, r1, r2, r3"
    testDisasm "e0910291" "umulls r0, r1, r1, r2"
    testDisasm "e0812994" "umull r2, r1, r4, sb"
    testDisasm "e0812a94" "umull r2, r1, r4, sl"

  /// A8.8.259 UQADD16
  [<TestMethod>]
  member _.``A8.8.259 UQADD16``() =
    testDisasm "e6610f12" "uqadd16 r0, r1, r2"

  /// A8.8.260 UQADD8
  [<TestMethod>]
  member _.``A8.8.260 UQADD8``() =
    testDisasm "e6610f92" "uqadd8 r0, r1, r2"

  /// A8.8.261 UQASX
  [<TestMethod>]
  member _.``A8.8.261 UQASX``() =
    testDisasm "e6610f32" "uqasx r0, r1, r2"

  /// A8.8.262 UQSAX
  [<TestMethod>]
  member _.``A8.8.262 UQSAX``() =
    testDisasm "e6610f52" "uqsax r0, r1, r2"

  /// A8.8.263 UQSUB16
  [<TestMethod>]
  member _.``A8.8.263 UQSUB16``() =
    testDisasm "e6610f72" "uqsub16 r0, r1, r2"

  /// A8.8.264 UQSUB8
  [<TestMethod>]
  member _.``A8.8.264 UQSUB8``() =
    testDisasm "e6610ff2" "uqsub8 r0, r1, r2"

  /// A8.8.265 USAD8
  [<TestMethod>]
  member _.``A8.8.265 USAD8``() =
    testDisasm "e780f211" "usad8 r0, r1, r2"
    testDisasm "e781f914" "usad8 r1, r4, sb"
    testDisasm "e781fa14" "usad8 r1, r4, sl"
    testDisasm "e781fb14" "usad8 r1, r4, fp"

  /// A8.8.266 USADA8
  [<TestMethod>]
  member _.``A8.8.266 USADA8``() =
    testDisasm "e7803211" "usada8 r0, r1, r2, r3"
    testDisasm "e7812914" "usada8 r1, r4, sb, r2"
    testDisasm "e7812a14" "usada8 r1, r4, sl, r2"
    testDisasm "e7812b14" "usada8 r1, r4, fp, r2"

  /// A8.8.267 USAT
  [<TestMethod>]
  member _.``A8.8.267 USAT``() =
    testDisasm "e6e30011" "usat r0, #0x3, r1"
    testDisasm "e6e30091" "usat r0, #0x3, r1, lsl #0x1"
    testDisasm "e6e302d1" "usat r0, #0x3, r1, asr #0x5"
    testDisasm "e6e1d014" "usat sp, #0x1, r4"

  /// A8.8.268 USAT16
  [<TestMethod>]
  member _.``A8.8.268 USAT16``() =
    testDisasm "e6e30f31" "usat16 r0, #0x3, r1"

  /// A8.8.269 USAX
  [<TestMethod>]
  member _.``A8.8.269 USAX``() =
    testDisasm "e6510f52" "usax r0, r1, r2"

  /// A8.8.270 USUB16
  [<TestMethod>]
  member _.``A8.8.270 USUB16``() =
    testDisasm "e6510f72" "usub16 r0, r1, r2"

  /// A8.8.271 USUB8
  [<TestMethod>]
  member _.``A8.8.271 USUB8``() =
    testDisasm "e6510ff2" "usub8 r0, r1, r2"

  /// A8.8.272 UXTAB
  [<TestMethod>]
  member _.``A8.8.272 UXTAB``() =
    testDisasm "e6e10072" "uxtab r0, r1, r2"
    testDisasm "e6e12474" "uxtab r2, r1, r4, ror #0x8"
    testDisasm "e6e1d074" "uxtab sp, r1, r4"
    testDisasm "e6e1d474" "uxtab sp, r1, r4, ror #0x8"

  /// A8.8.273 UXTAB16
  [<TestMethod>]
  member _.``A8.8.273 UXTAB16``() =
    testDisasm "e6c10072" "uxtab16 r0, r1, r2"
    testDisasm "e6c12474" "uxtab16 r2, r1, r4, ror #0x8"
    testDisasm "e6c1d074" "uxtab16 sp, r1, r4"
    testDisasm "e6c1d474" "uxtab16 sp, r1, r4, ror #0x8"

  /// A8.8.274 UXTAH
  [<TestMethod>]
  member _.``A8.8.274 UXTAH``() =
    testDisasm "e6f10072" "uxtah r0, r1, r2"
    testDisasm "e6f12474" "uxtah r2, r1, r4, ror #0x8"
    testDisasm "e6f1d074" "uxtah sp, r1, r4"
    testDisasm "e6f1d474" "uxtah sp, r1, r4, ror #0x8"

  /// A8.8.275 UXTB
  [<TestMethod>]
  member _.``A8.8.275 UXTB``() =
    testDisasm "e6ef0071" "uxtb r0, r1"
    testDisasm "e6ef2474" "uxtb r2, r4, ror #0x8"
    testDisasm "e6efd074" "uxtb sp, r4"
    testDisasm "e6efd474" "uxtb sp, r4, ror #0x8"

  /// A8.8.276 UXTB16
  [<TestMethod>]
  member _.``A8.8.276 UXTB16``() =
    testDisasm "e6cf0071" "uxtb16 r0, r1"
    testDisasm "e6cf2474" "uxtb16 r2, r4, ror #0x8"
    testDisasm "e6cfd074" "uxtb16 sp, r4"
    testDisasm "e6cfd474" "uxtb16 sp, r4, ror #0x8"

  /// A8.8.277 UXTH
  [<TestMethod>]
  member _.``A8.8.277 UXTH``() =
    testDisasm "e6ff0071" "uxth r0, r1"

  /// A8.8.278 VABA, VABAL
  [<TestMethod>]
  member _.``A8.8.278 VABA``() =
    testDisasm "f2120754" "vaba.s16 q0, q1, q2"
    testDisasm "f3020754" "vaba.u8 q0, q1, q2"
    testDisasm "f2010712" "vaba.s8 d0, d1, d2"
    testDisasm "f3010712" "vaba.u8 d0, d1, d2"

  /// A8.8.278 VABA, VABAL
  [<TestMethod>]
  member _.``A8.8.278 VABAL``() =
    testDisasm "f2810502" "vabal.s8 q0, d1, d2"
    testDisasm "f3812504" "vabal.u8 q1, d1, d4"

  /// A8.8.279 VABD, VABDL (integer)
  [<TestMethod>]
  member _.``A8.8.279 VABD``() =
    testDisasm "f3320d44" "vabd.f16 q0, q1, q2"
    testDisasm "f2120744" "vabd.s16 q0, q1, q2"
    testDisasm "f3020744" "vabd.u8 q0, q1, q2"
    testDisasm "f2010702" "vabd.s8 d0, d1, d2"

  /// A8.8.279 VABD, VABDL (integer)
  [<TestMethod>]
  member _.``A8.8.279 VABDL``() =
    testDisasm "f2810702" "vabdl.s8 q0, d1, d2"
    testDisasm "f3812704" "vabdl.u8 q1, d1, d4"

  /// A8.8.28 BXJ
  [<TestMethod>]
  member _.``A8.8.28 BXJ``() =
    testDisasm "e12fff21" "bxj r1"

  /// A8.8.281 VABS
  [<TestMethod>]
  member _.``A8.8.281 VABS``() =
    testDisasm "eeb009e0" "vabs.f16 s0, s1"
    testDisasm "f3b50742" "vabs.f16 q0, q1"
    testDisasm "f3b10344" "vabs.s8 q0, q2"
    testDisasm "f3b10302" "vabs.s8 d0, d2"

  /// A8.8.282 VACGE, VACGT, VACLE, VACLT
  [<TestMethod>]
  member _.``A8.8.282 VACGE``() =
    testDisasm "f3120e54" "vacge.f16 q0, q1, q2"
    testDisasm "f3020e11" "vacge.f32 d0, d2, d1"

  /// A8.8.282 VACGE, VACGT, VACLE, VACLT
  [<TestMethod>]
  member _.``A8.8.282 VACGT``() =
    testDisasm "f3320e54" "vacgt.f16 q0, q1, q2"
    testDisasm "f3220e11" "vacgt.f32 d0, d2, d1"

  /// A8.8.282 VACGE, VACGT, VACLE, VACLT
  [<TestMethod>]
  member _.``A8.8.282 VACLE``() =
    testDisasm "f3120e54" "vacge.f16 q0, q1, q2"
    testDisasm "f3020e11" "vacge.f32 d0, d2, d1"

  /// A8.8.282 VACGE, VACGT, VACLE, VACLT
  [<TestMethod>]
  member _.``A8.8.282 VACLT``() =
    testDisasm "f3320e54" "vacgt.f16 q0, q1, q2"
    testDisasm "f3220e11" "vacgt.f32 d0, d2, d1"

  /// A8.8.283 VADD (integer)
  [<TestMethod>]
  member _.``A8.8.283 VADD``() =
    testDisasm "ee300981" "vadd.f16 s0, s1, s2"
    testDisasm "f2120d44" "vadd.f16 q0, q1, q2"
    testDisasm "f2120844" "vadd.i16 q0, q1, q2"
    testDisasm "f2010802" "vadd.i8 d0, d1, d2"

  /// A8.8.285 VADDHN
  [<TestMethod>]
  member _.``A8.8.285 VADDHN``() =
    testDisasm "f2920404" "vaddhn.i32 d0, q1, q2"

  /// A8.8.286 VADDL, VADDW
  [<TestMethod>]
  member _.``A8.8.286 VADDL``() =
    testDisasm "f2910002" "vaddl.s16 q0, d1, d2"
    testDisasm "f3810002" "vaddl.u8 q0, d1, d2"

  /// A8.8.286 VADDL, VADDW
  [<TestMethod>]
  member _.``A8.8.286 VADDW``() =
    testDisasm "f2800101" "vaddw.s8 q0, q0, d1"
    testDisasm "f3802104" "vaddw.u8 q1, q0, d4"

  /// A8.8.287 VAND (immediate)
  [<TestMethod>]
  member _.``A8.8.287 VAND``() =
    testDisasm "f2020154" "vand q0, q1, q2"
    testDisasm "f2011112" "vand d1, d1, d2"

  /// A8.8.289 VBIC (immediate)
  [<TestMethod>]
  member _.``A8.8.289 VBIC``() =
    testDisasm "f2120154" "vbic q0, q1, q2"
    testDisasm "f2810970" "vbic.i16 q0, #0x10"
    testDisasm "f2810930" "vbic.i16 d0, #0x10"
    testDisasm "f2111112" "vbic d1, d1, d2"

  /// A8.8.291 VBIF, VBIT, VBSL
  [<TestMethod>]
  member _.``A8.8.291 VBIF``() =
    testDisasm "f3320154" "vbif q0, q1, q2"
    testDisasm "f3312114" "vbif d2, d1, d4"

  /// A8.8.291 VBIF, VBIT, VBSL
  [<TestMethod>]
  member _.``A8.8.291 VBIT``() =
    testDisasm "f3220154" "vbit q0, q1, q2"
    testDisasm "f3212114" "vbit d2, d1, d4"

  /// A8.8.291 VBIF, VBIT, VBSL
  [<TestMethod>]
  member _.``A8.8.291 VBSL``() =
    testDisasm "f3120154" "vbsl q0, q1, q2"
    testDisasm "f3112114" "vbsl d2, d1, d4"

  /// A8.8.292 VCEQ (register)
  [<TestMethod>]
  member _.``A8.8.292 VCEQ``() =
    testDisasm "f2120e44" "vceq.f16 q0, q1, q2"
    testDisasm "f3b50542" "vceq.f16 q0, q1, #0x0"
    testDisasm "f3010812" "vceq.i8 d0, d1, d2"
    testDisasm "f2010e02" "vceq.f32 d0, d1, d2"

  /// A8.8.294 VCGE (register)
  [<TestMethod>]
  member _.``A8.8.294 VCGE``() =
    testDisasm "f3120e44" "vcge.f16 q0, q1, q2"
    testDisasm "f3b504c2" "vcge.f16 q0, q1, #0x0"
    testDisasm "f2010312" "vcge.s8 d0, d1, d2"
    testDisasm "f3010312" "vcge.u8 d0, d1, d2"

  /// A8.8.296 VCGT (register)
  [<TestMethod>]
  member _.``A8.8.296 VCGT``() =
    testDisasm "f3320e44" "vcgt.f16 q0, q1, q2"
    testDisasm "f3b50442" "vcgt.f16 q0, q1, #0x0"
    testDisasm "f2010302" "vcgt.s8 d0, d1, d2"
    testDisasm "f3010302" "vcgt.u8 d0, d1, d2"

  /// A8.8.298 VCLE (register)
  [<TestMethod>]
  member _.``A8.8.298 VCLE``() =
    testDisasm "f3b505c2" "vcle.f16 q0, q1, #0x0"
    testDisasm "f3b101c4" "vcle.s8 q0, q2, #0x0"
    testDisasm "f3b10182" "vcle.s8 d0, d2, #0x0"
    testDisasm "f3b90582" "vcle.f32 d0, d2, #0x0"

  /// A8.8.30 CDP, CDP2
  [<TestMethod>]
  member _.``A8.8.30 CDP``() =
    testDisasm "ee1323a4" "cdp p3, #0x1, c2, c3, c4, #0x5"

  /// A8.8.30 CDP, CDP2
  [<TestMethod>]
  member _.``A8.8.30 CDP2``() =
    testDisasm "fe1323a4" "cdp2 p3, #0x1, c2, c3, c4, #0x5"

  /// A8.8.300 VCLS
  [<TestMethod>]
  member _.``A8.8.300 VCLS``() =
    testDisasm "f3b00444" "vcls.s8 q0, q2"
    testDisasm "f3b00402" "vcls.s8 d0, d2"

  /// A8.8.301 VCLT (register)
  [<TestMethod>]
  member _.``A8.8.301 VCLT``() =
    testDisasm "f3b50642" "vclt.f16 q0, q1, #0x0"
    testDisasm "f3b10244" "vclt.s8 q0, q2, #0x0"
    testDisasm "f3b10202" "vclt.s8 d0, d2, #0x0"
    testDisasm "f3b90602" "vclt.f32 d0, d2, #0x0"

  /// A8.8.303 VCLZ
  [<TestMethod>]
  member _.``A8.8.303 VCLZ``() =
    testDisasm "f3b004c4" "vclz.i8 q0, q2"
    testDisasm "f3b00482" "vclz.i8 d0, d2"

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
    testDisasm "f3b00544" "vcnt.8 q0, q2"
    testDisasm "f3b00502" "vcnt.8 d0, d2"

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
    testDisasm "1e812a04" "vdivne.f32 s4, s2, s8"
    testDisasm "1e812b04" "vdivne.f64 d2, d1, d4"

  /// A8.8.314 VDUP (scalar)
  [<TestMethod>]
  member _.``A8.8.314 VDUP``() =
    testDisasm "eec01b10" "vdup.8 d0, r1"
    testDisasm "ee81db14" "vdup.32 d1, sp"
    testDisasm "eea02b14" "vdup.32 q0, r2"
    testDisasm "eea0db14" "vdup.32 q0, sp"

  /// A8.8.316 VEOR
  [<TestMethod>]
  member _.``A8.8.316 VEOR``() =
    testDisasm "f3020154" "veor q0, q1, q2"
    testDisasm "f3011112" "veor d1, d1, d2"

  /// A8.8.317 VEXT
  [<TestMethod>]
  member _.``A8.8.317 VEXT``() =
    testDisasm "f2b00142" "vext.8 q0, q0, q1, #0x1"
    testDisasm "f2b12004" "vext.8 d2, d1, d4, #0x0"

  /// A8.8.318 VFMA, VFMS
  [<TestMethod>]
  member _.``A8.8.318 VFMA``() =
    testDisasm "eea00981" "vfma.f16 s0, s1, s2"
    testDisasm "f2120c54" "vfma.f16 q0, q1, q2"
    testDisasm "eea12b04" "vfma.f64 d2, d1, d4"
    testDisasm "1ea12a04" "vfmane.f32 s4, s2, s8"

  /// A8.8.318 VFMA, VFMS
  [<TestMethod>]
  member _.``A8.8.318 VFMS``() =
    testDisasm "eea009c1" "vfms.f16 s0, s1, s2"
    testDisasm "f2320c54" "vfms.f16 q0, q1, q2"
    testDisasm "eea12b44" "vfms.f64 d2, d1, d4"
    testDisasm "1ea12a44" "vfmsne.f32 s4, s2, s8"

  /// A8.8.319 VFNMA, VFNMS
  [<TestMethod>]
  member _.``A8.8.319 VFNMA``() =
    testDisasm "ee9009c1" "vfnma.f16 s0, s1, s2"
    testDisasm "ee912b44" "vfnma.f64 d2, d1, d4"
    testDisasm "1e912a44" "vfnmane.f32 s4, s2, s8"
    testDisasm "1e912b44" "vfnmane.f64 d2, d1, d4"

  /// A8.8.319 VFNMA, VFNMS
  [<TestMethod>]
  member _.``A8.8.319 VFNMS``() =
    testDisasm "ee900981" "vfnms.f16 s0, s1, s2"
    testDisasm "ee912b04" "vfnms.f64 d2, d1, d4"
    testDisasm "1e912a04" "vfnmsne.f32 s4, s2, s8"
    testDisasm "1e912b04" "vfnmsne.f64 d2, d1, d4"

  /// A8.8.32 CLREX
  [<TestMethod>]
  member _.``A8.8.32 CLREX``() =
    testDisasm "f57ff01f" "clrex"

  /// A8.8.320 VHADD, VHSUB
  [<TestMethod>]
  member _.``A8.8.320 VHADD``() =
    testDisasm "f2020044" "vhadd.s8 q0, q1, q2"
    testDisasm "f2012004" "vhadd.s8 d2, d1, d4"
    testDisasm "f3012004" "vhadd.u8 d2, d1, d4"
    testDisasm "f3002044" "vhadd.u8 q1, q0, q2"

  /// A8.8.320 VHADD, VHSUB
  [<TestMethod>]
  member _.``A8.8.320 VHSUB``() =
    testDisasm "f2020244" "vhsub.s8 q0, q1, q2"
    testDisasm "f2012204" "vhsub.s8 d2, d1, d4"
    testDisasm "f3012204" "vhsub.u8 d2, d1, d4"
    testDisasm "f3002244" "vhsub.u8 q1, q0, q2"

  /// A8.8.321 VLD1 (multiple single elements)
  [<TestMethod>]
  member _.``A8.8.321 VLD1``() =
    testDisasm "f421070f" "vld1.8 {d0}, [r1]"
    testDisasm "f4212204" "vld1.8 {d2, d3, d4, d5}, [r1], r4"
    testDisasm "f421220f" "vld1.8 {d2, d3, d4, d5}, [r1]"
    testDisasm "f4212604" "vld1.8 {d2, d3, d4}, [r1], r4"

  /// A8.8.324 VLD2 (multiple 2-element structures)
  [<TestMethod>]
  member _.``A8.8.324 VLD2``() =
    testDisasm "f421080f" "vld2.8 {d0, d1}, [r1]"
    testDisasm "f4212304" "vld2.8 {d2, d3, d4, d5}, [r1], r4"
    testDisasm "f421230f" "vld2.8 {d2, d3, d4, d5}, [r1]"
    testDisasm "f4212804" "vld2.8 {d2, d3}, [r1], r4"

  /// A8.8.327 VLD3 (multiple 3-element structures)
  [<TestMethod>]
  member _.``A8.8.327 VLD3``() =
    testDisasm "f421040f" "vld3.8 {d0, d1, d2}, [r1]"
    testDisasm "f4212404" "vld3.8 {d2, d3, d4}, [r1], r4"
    testDisasm "f4292404" "vld3.8 {d2, d3, d4}, [sb], r4"
    testDisasm "f429240f" "vld3.8 {d2, d3, d4}, [sb]"

  /// A8.8.33 CLZ
  [<TestMethod>]
  member _.``A8.8.33 CLZ``() =
    testDisasm "e16f0f11" "clz r0, r1"

  /// A8.8.330 VLD4 (multiple 4-element structures)
  [<TestMethod>]
  member _.``A8.8.330 VLD4``() =
    testDisasm "f421000f" "vld4.8 {d0, d1, d2, d3}, [r1]"
    testDisasm "f4212004" "vld4.8 {d2, d3, d4, d5}, [r1], r4"
    testDisasm "f4292004" "vld4.8 {d2, d3, d4, d5}, [sb], r4"
    testDisasm "f429200f" "vld4.8 {d2, d3, d4, d5}, [sb]"

  /// A8.8.333 VLDM
  [<TestMethod>]
  member _.``A8.8.333 VLDM``() =
    testDisasm "ec910b04" "vldmia r1, {d0, d1}"
    testDisasm "ecbd0b04" "vldmia sp!, {d0, d1}"
    testDisasm "ecb10b08" "vldmia r1!, {d0, d1, d2, d3}"
    testDisasm "ec912a04" "vldmia r1, {s4, s5, s6, s7}"

  /// A8.8.334 VLDR
  [<TestMethod>]
  member _.``A8.8.334 VLDR``() =
    testDisasm "ed910900" "vldr.16 s0, [r1]"
    testDisasm "ed1f0b01" "vldr d0, [pc, #-0x4]"
    testDisasm "ed1f0b00" "vldr d0, [pc]"
    testDisasm "ed910a00" "vldr s0, [r1]"

  /// A8.8.335 VMAX, VMIN (integer)
  [<TestMethod>]
  member _.``A8.8.335 VMAX``() =
    testDisasm "f2120f44" "vmax.f16 q0, q1, q2"
    testDisasm "f2020644" "vmax.s8 q0, q1, q2"
    testDisasm "f2012604" "vmax.s8 d2, d1, d4"
    testDisasm "f2012f04" "vmax.f32 d2, d1, d4"

  /// A8.8.335 VMAX, VMIN (integer)
  [<TestMethod>]
  member _.``A8.8.335 VMIN``() =
    testDisasm "f2320f44" "vmin.f16 q0, q1, q2"
    testDisasm "f2020654" "vmin.s8 q0, q1, q2"
    testDisasm "f2012614" "vmin.s8 d2, d1, d4"
    testDisasm "f2212f04" "vmin.f32 d2, d1, d4"

  /// A8.8.337 VMLA, VMLAL, VMLS, VMLSL (integer)
  [<TestMethod>]
  member _.``A8.8.337 VMLA``() =
    testDisasm "ee000981" "vmla.f16 s0, s1, s2"
    testDisasm "f2120d54" "vmla.f16 q0, q1, q2"
    testDisasm "f392016c" "vmla.f16 q0, q1, d4[3]"
    testDisasm "f2020944" "vmla.i8 q0, q1, q2"

  /// A8.8.337 VMLA, VMLAL, VMLS, VMLSL (integer)
  [<TestMethod>]
  member _.``A8.8.337 VMLAL``() =
    testDisasm "f2810802" "vmlal.s8 q0, d1, d2"
    testDisasm "f2912244" "vmlal.s16 q1, d1, d4[0]"
    testDisasm "f3812804" "vmlal.u8 q1, d1, d4"
    testDisasm "f3912244" "vmlal.u16 q1, d1, d4[0]"

  /// A8.8.337 VMLA, VMLAL, VMLS, VMLSL (integer)
  [<TestMethod>]
  member _.``A8.8.337 VMLS``() =
    testDisasm "ee0009c1" "vmls.f16 s0, s1, s2"
    testDisasm "f2320d54" "vmls.f16 q0, q1, q2"
    testDisasm "f392056c" "vmls.f16 q0, q1, d4[3]"
    testDisasm "f3020944" "vmls.i8 q0, q1, q2"

  /// A8.8.337 VMLA, VMLAL, VMLS, VMLSL (integer)
  [<TestMethod>]
  member _.``A8.8.337 VMLSL``() =
    testDisasm "f2810a02" "vmlsl.s8 q0, d1, d2"
    testDisasm "f2912644" "vmlsl.s16 q1, d1, d4[0]"
    testDisasm "f3812a04" "vmlsl.u8 q1, d1, d4"
    testDisasm "f3912644" "vmlsl.u16 q1, d1, d4[0]"

  /// A8.8.34 CMN (immediate)
  [<TestMethod>]
  member _.``A8.8.34 CMN``() =
    testDisasm "e1710002" "cmn r1, r2"
    testDisasm "e1710082" "cmn r1, r2, lsl #0x1"
    testDisasm "e17101a2" "cmn r1, r2, lsr #0x3"
    testDisasm "e17102c2" "cmn r1, r2, asr #0x5"

  /// A8.8.340 VMOV (immediate)
  [<TestMethod>]
  member _.``A8.8.340 VMOV``() =
    testDisasm "ee000910" "vmov.f16 s0, r0"
    testDisasm "ee100990" "vmov.f16 r0, s1"
    testDisasm "f2810e50" "vmov.i8 q0, #0x10"
    testDisasm "f2810e10" "vmov.i8 d0, #0x10"

  /// A8.8.347 VMOVL
  [<TestMethod>]
  member _.``A8.8.347 VMOVL``() =
    testDisasm "f2880a12" "vmovl.s8 q0, d2"
    testDisasm "f3880a12" "vmovl.u8 q0, d2"

  /// A8.8.348 VMOVN
  [<TestMethod>]
  member _.``A8.8.348 VMOVN``() =
    testDisasm "f3b20204" "vmovn.i16 d0, q2"

  /// A8.8.349 VMRS
  [<TestMethod>]
  member _.``A8.8.349 VMRS``() =
    testDisasm "eef10a10" "vmrs r0, fpscr"
    testDisasm "eef1da10" "vmrs sp, fpscr"
    testDisasm "eef02a10" "vmrs r2, fpsid"
    testDisasm "eef0da10" "vmrs sp, fpsid"

  /// A8.8.350 VMSR
  [<TestMethod>]
  member _.``A8.8.350 VMSR``() =
    testDisasm "eee10a10" "vmsr fpscr, r0"
    testDisasm "eee1da10" "vmsr fpscr, sp"
    testDisasm "eee02a10" "vmsr fpsid, r2"
    testDisasm "eee0da10" "vmsr fpsid, sp"

  /// A8.8.351 VMUL, VMULL (integer and polynomial)
  [<TestMethod>]
  member _.``A8.8.351 VMUL``() =
    testDisasm "ee200981" "vmul.f16 s0, s1, s2"
    testDisasm "f3120d54" "vmul.f16 q0, q1, q2"
    testDisasm "f392096c" "vmul.f16 q0, q1, d4[3]"
    testDisasm "f2120954" "vmul.i16 q0, q1, q2"

  /// A8.8.351 VMUL, VMULL (integer and polynomial)
  [<TestMethod>]
  member _.``A8.8.351 VMULL``() =
    testDisasm "f2810c02" "vmull.s8 q0, d1, d2"
    testDisasm "f2a20e03" "vmull.p64 q0, d2, d3"
    testDisasm "f2912a44" "vmull.s16 q1, d1, d4[0]"
    testDisasm "f3812c04" "vmull.u8 q1, d1, d4"

  /// A8.8.354 VMVN (immediate)
  [<TestMethod>]
  member _.``A8.8.354 VMVN``() =
    testDisasm "f3b005c2" "vmvn q0, q1"
    testDisasm "f2810870" "vmvn.i16 q0, #0x10"
    testDisasm "f2810830" "vmvn.i16 d0, #0x10"
    testDisasm "f3b00582" "vmvn d0, d2"

  /// A8.8.356 VNEG
  [<TestMethod>]
  member _.``A8.8.356 VNEG``() =
    testDisasm "eeb10960" "vneg.f16 s0, s1"
    testDisasm "f3b507c2" "vneg.f16 q0, q1"
    testDisasm "f3b103c4" "vneg.s8 q0, q2"
    testDisasm "f3b10382" "vneg.s8 d0, d2"

  /// A8.8.357 VNMLA, VNMLS, VNMUL
  [<TestMethod>]
  member _.``A8.8.357 VNMLA``() =
    testDisasm "ee1009c1" "vnmla.f16 s0, s1, s2"
    testDisasm "ee110b42" "vnmla.f64 d0, d1, d2"
    testDisasm "1e112a44" "vnmlane.f32 s4, s2, s8"
    testDisasm "1e112b44" "vnmlane.f64 d2, d1, d4"

  /// A8.8.357 VNMLA, VNMLS, VNMUL
  [<TestMethod>]
  member _.``A8.8.357 VNMLS``() =
    testDisasm "ee100981" "vnmls.f16 s0, s1, s2"
    testDisasm "ee112b04" "vnmls.f64 d2, d1, d4"
    testDisasm "1e112a04" "vnmlsne.f32 s4, s2, s8"
    testDisasm "1e112b04" "vnmlsne.f64 d2, d1, d4"

  /// A8.8.357 VNMLA, VNMLS, VNMUL
  [<TestMethod>]
  member _.``A8.8.357 VNMUL``() =
    testDisasm "ee2009c1" "vnmul.f16 s0, s1, s2"
    testDisasm "ee212b44" "vnmul.f64 d2, d1, d4"
    testDisasm "1e212a44" "vnmulne.f32 s4, s2, s8"
    testDisasm "1e212b44" "vnmulne.f64 d2, d1, d4"

  /// A8.8.358 VORN (immediate)
  [<TestMethod>]
  member _.``A8.8.358 VORN``() =
    testDisasm "f2320154" "vorn q0, q1, q2"
    testDisasm "f2311112" "vorn d1, d1, d2"

  /// A8.8.360 VORR (immediate)
  [<TestMethod>]
  member _.``A8.8.360 VORR``() =
    testDisasm "f2220154" "vorr q0, q1, q2"
    testDisasm "f2810950" "vorr.i16 q0, #0x10"
    testDisasm "f2810910" "vorr.i16 d0, #0x10"
    testDisasm "f2211112" "vorr d1, d1, d2"

  /// A8.8.362 VPADAL
  [<TestMethod>]
  member _.``A8.8.362 VPADAL``() =
    testDisasm "f3b00644" "vpadal.s8 q0, q2"
    testDisasm "f3b006c4" "vpadal.u8 q0, q2"
    testDisasm "f3b00602" "vpadal.s8 d0, d2"
    testDisasm "f3b00682" "vpadal.u8 d0, d2"

  /// A8.8.363 VPADD (integer)
  [<TestMethod>]
  member _.``A8.8.363 VPADD``() =
    testDisasm "f3110d02" "vpadd.f16 d0, d1, d2"
    testDisasm "f2110b12" "vpadd.i16 d0, d1, d2"

  /// A8.8.365 VPADDL
  [<TestMethod>]
  member _.``A8.8.365 VPADDL``() =
    testDisasm "f3b00244" "vpaddl.s8 q0, q2"
    testDisasm "f3b002c4" "vpaddl.u8 q0, q2"
    testDisasm "f3b00202" "vpaddl.s8 d0, d2"
    testDisasm "f3b00282" "vpaddl.u8 d0, d2"
