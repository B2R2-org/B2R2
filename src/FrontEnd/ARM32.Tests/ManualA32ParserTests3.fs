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
/// chapters describe, VPMAX to RFEIA in the order of their sections. Each
/// reads A32 words of the instruction and checks the text, and each word's
/// text is one binutils' objdump reads the word as too, so what is asserted
/// is a reading two decoders agree on.
/// </summary>
[<TestClass>]
type ManualA32ParserTests3() =
  let testDisasm (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let isa = ISA(Architecture.ARMv7, Endian.Big)
    let parser = Parser(isa, false, BinReader.Init Endian.Big)
    let ins = (parser :> IInstructionParsable).Parse(bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  /// A8.8.366 VPMAX, VPMIN (integer)
  [<TestMethod>]
  member _.``A8.8.366 VPMAX``() =
    testDisasm "f3110f02" "vpmax.f16 d0, d1, d2"
    testDisasm "f2010a02" "vpmax.s8 d0, d1, d2"
    testDisasm "f3012a04" "vpmax.u8 d2, d1, d4"

  /// A8.8.366 VPMAX, VPMIN (integer)
  [<TestMethod>]
  member _.``A8.8.366 VPMIN``() =
    testDisasm "f3310f02" "vpmin.f16 d0, d1, d2"
    testDisasm "f2010a12" "vpmin.s8 d0, d1, d2"
    testDisasm "f3012a14" "vpmin.u8 d2, d1, d4"

  /// A8.8.368 VPOP
  [<TestMethod>]
  member _.``A8.8.368 VPOP``() =
    testDisasm "ecbd0b04" "vldmia sp!, {d0, d1}"
    testDisasm "ecbd2a04" "vldmia sp!, {s4, s5, s6, s7}"
    testDisasm "ecbd2a01" "vldmia sp!, {s4}"
    ("vldmia sp!, {s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, "
     + "s16, s17, s18}")
    |> testDisasm "ecbd2a0f"

  /// A8.8.369 VPUSH
  [<TestMethod>]
  member _.``A8.8.369 VPUSH``() =
    testDisasm "ed2d0b04" "vstmdb sp!, {d0, d1}"
    testDisasm "ed2d0a04" "vstmdb sp!, {s0, s1, s2, s3}"
    testDisasm "ed2d2a01" "vstmdb sp!, {s4}"
    ("vstmdb sp!, {s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, "
     + "s16, s17, s18}")
    |> testDisasm "ed2d2a0f"

  /// A8.8.37 CMP (immediate)
  [<TestMethod>]
  member _.``A8.8.37 CMP``() =
    testDisasm "e3510003" "cmp r1, #0x3"
    testDisasm "e1510002" "cmp r1, r2"
    testDisasm "e1510082" "cmp r1, r2, lsl #0x1"
    testDisasm "e15101a2" "cmp r1, r2, lsr #0x3"

  /// A8.8.370 VQABS
  [<TestMethod>]
  member _.``A8.8.370 VQABS``() =
    testDisasm "f3b00744" "vqabs.s8 q0, q2"
    testDisasm "f3b00702" "vqabs.s8 d0, d2"

  /// A8.8.371 VQADD
  [<TestMethod>]
  member _.``A8.8.371 VQADD``() =
    testDisasm "f2120054" "vqadd.s16 q0, q1, q2"
    testDisasm "f3020054" "vqadd.u8 q0, q1, q2"
    testDisasm "f2010012" "vqadd.s8 d0, d1, d2"
    testDisasm "f3010012" "vqadd.u8 d0, d1, d2"

  /// A8.8.372 VQDMLAL, VQDMLSL
  [<TestMethod>]
  member _.``A8.8.372 VQDMLAL``() =
    testDisasm "f2910902" "vqdmlal.s16 q0, d1, d2"
    testDisasm "f2912344" "vqdmlal.s16 q1, d1, d4[0]"

  /// A8.8.372 VQDMLAL, VQDMLSL
  [<TestMethod>]
  member _.``A8.8.372 VQDMLSL``() =
    testDisasm "f2910b02" "vqdmlsl.s16 q0, d1, d2"
    testDisasm "f2912744" "vqdmlsl.s16 q1, d1, d4[0]"

  /// A8.8.373 VQDMULH
  [<TestMethod>]
  member _.``A8.8.373 VQDMULH``() =
    testDisasm "f2220b44" "vqdmulh.s32 q0, q1, q2"
    testDisasm "f2110b02" "vqdmulh.s16 d0, d1, d2"
    testDisasm "f3920c42" "vqdmulh.s16 q0, q1, d2[0]"
    testDisasm "f2910c42" "vqdmulh.s16 d0, d1, d2[0]"

  /// A8.8.374 VQDMULL
  [<TestMethod>]
  member _.``A8.8.374 VQDMULL``() =
    testDisasm "f2a10d02" "vqdmull.s32 q0, d1, d2"
    testDisasm "f2910b42" "vqdmull.s16 q0, d1, d2[0]"

  /// A8.8.375 VQMOVN, VQMOVUN
  [<TestMethod>]
  member _.``A8.8.375 VQMOVN``() =
    testDisasm "f3b20282" "vqmovn.s16 d0, q1"

  /// A8.8.375 VQMOVN, VQMOVUN
  [<TestMethod>]
  member _.``A8.8.375 VQMOVUN``() =
    testDisasm "f3b20242" "vqmovun.s16 d0, q1"

  /// A8.8.376 VQNEG
  [<TestMethod>]
  member _.``A8.8.376 VQNEG``() =
    testDisasm "f3b007c4" "vqneg.s8 q0, q2"
    testDisasm "f3b00782" "vqneg.s8 d0, d2"

  /// A8.8.377 VQRDMULH
  [<TestMethod>]
  member _.``A8.8.377 VQRDMULH``() =
    testDisasm "f3220b44" "vqrdmulh.s32 q0, q1, q2"
    testDisasm "f3110b02" "vqrdmulh.s16 d0, d1, d2"
    testDisasm "f3920d42" "vqrdmulh.s16 q0, q1, d2[0]"
    testDisasm "f2910d42" "vqrdmulh.s16 d0, d1, d2[0]"

  /// A8.8.378 VQRSHL
  [<TestMethod>]
  member _.``A8.8.378 VQRSHL``() =
    testDisasm "f2040552" "vqrshl.s8 q0, q1, q2"
    testDisasm "f2012514" "vqrshl.s8 d2, d4, d1"
    testDisasm "f3012514" "vqrshl.u8 d2, d4, d1"
    testDisasm "f3002554" "vqrshl.u8 q1, q2, q0"

  /// A8.8.379 VQRSHRN, VQRSHRUN
  [<TestMethod>]
  member _.``A8.8.379 VQRSHRN``() =
    testDisasm "f28f0952" "vqrshrn.s16 d0, q1, #0x1"
    testDisasm "f3892954" "vqrshrn.u16 d2, q2, #0x7"

  /// A8.8.379 VQRSHRN, VQRSHRUN
  [<TestMethod>]
  member _.``A8.8.379 VQRSHRUN``() =
    testDisasm "f38f0852" "vqrshrun.s16 d0, q1, #0x1"

  /// A8.8.380 VQSHL (register)
  [<TestMethod>]
  member _.``A8.8.380 VQSHL``() =
    testDisasm "f2040452" "vqshl.s8 q0, q1, q2"
    testDisasm "f2012414" "vqshl.s8 d2, d4, d1"
    testDisasm "f2892714" "vqshl.s8 d2, d4, #0x1"
    testDisasm "f2892754" "vqshl.s8 q1, q2, #0x1"

  /// A8.8.381 VQSHL, VQSHLU (immediate)
  [<TestMethod>]
  member _.``A8.8.381 VQSHLU``() =
    testDisasm "f3890652" "vqshlu.s8 q0, q1, #0x1"
    testDisasm "f3892614" "vqshlu.s8 d2, d4, #0x1"

  /// A8.8.382 VQSHRN, VQSHRUN
  [<TestMethod>]
  member _.``A8.8.382 VQSHRN``() =
    testDisasm "f28f0912" "vqshrn.s16 d0, q1, #0x1"
    testDisasm "f3892914" "vqshrn.u16 d2, q2, #0x7"

  /// A8.8.382 VQSHRN, VQSHRUN
  [<TestMethod>]
  member _.``A8.8.382 VQSHRUN``() =
    testDisasm "f38f0812" "vqshrun.s16 d0, q1, #0x1"

  /// A8.8.383 VQSUB
  [<TestMethod>]
  member _.``A8.8.383 VQSUB``() =
    testDisasm "f2020254" "vqsub.s8 q0, q1, q2"
    testDisasm "f2012214" "vqsub.s8 d2, d1, d4"
    testDisasm "f3012214" "vqsub.u8 d2, d1, d4"
    testDisasm "f3002254" "vqsub.u8 q1, q0, q2"

  /// A8.8.384 VRADDHN
  [<TestMethod>]
  member _.``A8.8.384 VRADDHN``() =
    testDisasm "f3920404" "vraddhn.i32 d0, q1, q2"

  /// A8.8.385 VRECPE
  [<TestMethod>]
  member _.``A8.8.385 VRECPE``() =
    testDisasm "f3b70542" "vrecpe.f16 q0, q1"
    testDisasm "f3bb0444" "vrecpe.u32 q0, q2"
    testDisasm "f3bb0402" "vrecpe.u32 d0, d2"
    testDisasm "f3bb0502" "vrecpe.f32 d0, d2"

  /// A8.8.386 VRECPS
  [<TestMethod>]
  member _.``A8.8.386 VRECPS``() =
    testDisasm "f2120f54" "vrecps.f16 q0, q1, q2"
    testDisasm "f2010f12" "vrecps.f32 d0, d1, d2"

  /// A8.8.387 VREV16, VREV32, VREV64
  [<TestMethod>]
  member _.``A8.8.387 VREV16``() =
    testDisasm "f3b00142" "vrev16.8 q0, q1"
    testDisasm "f3b02104" "vrev16.8 d2, d4"

  /// A8.8.387 VREV16, VREV32, VREV64
  [<TestMethod>]
  member _.``A8.8.387 VREV32``() =
    testDisasm "f3b000c2" "vrev32.8 q0, q1"
    testDisasm "f3b02084" "vrev32.8 d2, d4"

  /// A8.8.387 VREV16, VREV32, VREV64
  [<TestMethod>]
  member _.``A8.8.387 VREV64``() =
    testDisasm "f3b00042" "vrev64.8 q0, q1"
    testDisasm "f3b02004" "vrev64.8 d2, d4"

  /// A8.8.388 VRHADD
  [<TestMethod>]
  member _.``A8.8.388 VRHADD``() =
    testDisasm "f3020144" "vrhadd.u8 q0, q1, q2"
    testDisasm "f2022144" "vrhadd.s8 q1, q1, q2"
    testDisasm "f2011102" "vrhadd.s8 d1, d1, d2"
    testDisasm "f3011102" "vrhadd.u8 d1, d1, d2"

  /// A8.8.389 VRSHL
  [<TestMethod>]
  member _.``A8.8.389 VRSHL``() =
    testDisasm "f2040542" "vrshl.s8 q0, q1, q2"
    testDisasm "f2012504" "vrshl.s8 d2, d4, d1"
    testDisasm "f3012504" "vrshl.u8 d2, d4, d1"
    testDisasm "f3002544" "vrshl.u8 q1, q2, q0"

  /// A8.8.390 VRSHR
  [<TestMethod>]
  member _.``A8.8.390 VRSHR``() =
    testDisasm "f2892214" "vrshr.s8 d2, d4, #0x7"
    testDisasm "f2892254" "vrshr.s8 q1, q2, #0x7"
    testDisasm "f3892214" "vrshr.u8 d2, d4, #0x7"
    testDisasm "f3892254" "vrshr.u8 q1, q2, #0x7"

  /// A8.8.391 VRSHRN
  [<TestMethod>]
  member _.``A8.8.391 VRSHRN``() =
    testDisasm "f28f0852" "vrshrn.i16 d0, q1, #0x1"

  /// A8.8.392 VRSQRTE
  [<TestMethod>]
  member _.``A8.8.392 VRSQRTE``() =
    testDisasm "f3b705c2" "vrsqrte.f16 q0, q1"
    testDisasm "f3bb04c4" "vrsqrte.u32 q0, q2"
    testDisasm "f3bb0482" "vrsqrte.u32 d0, d2"
    testDisasm "f3bb0582" "vrsqrte.f32 d0, d2"

  /// A8.8.393 VRSQRTS
  [<TestMethod>]
  member _.``A8.8.393 VRSQRTS``() =
    testDisasm "f2320f54" "vrsqrts.f16 q0, q1, q2"
    testDisasm "f2210f12" "vrsqrts.f32 d0, d1, d2"

  /// A8.8.394 VRSRA
  [<TestMethod>]
  member _.``A8.8.394 VRSRA``() =
    testDisasm "f28f0352" "vrsra.s8 q0, q1, #0x1"
    testDisasm "f2892314" "vrsra.s8 d2, d4, #0x7"
    testDisasm "f3892314" "vrsra.u8 d2, d4, #0x7"
    testDisasm "f3892354" "vrsra.u8 q1, q2, #0x7"

  /// A8.8.395 VRSUBHN
  [<TestMethod>]
  member _.``A8.8.395 VRSUBHN``() =
    testDisasm "f3920604" "vrsubhn.i32 d0, q1, q2"

  /// A8.8.396 VSHL (immediate)
  [<TestMethod>]
  member _.``A8.8.396 VSHL``() =
    testDisasm "f2890552" "vshl.i8 q0, q1, #0x1"
    testDisasm "f2012404" "vshl.s8 d2, d4, d1"
    testDisasm "f2002444" "vshl.s8 q1, q2, q0"
    testDisasm "f2892514" "vshl.i8 d2, d4, #0x1"

  /// A8.8.398 VSHLL
  [<TestMethod>]
  member _.``A8.8.398 VSHLL``() =
    testDisasm "f2890a11" "vshll.s8 q0, d1, #0x1"
    testDisasm "f3892a14" "vshll.u8 q1, d4, #0x1"

  /// A8.8.399 VSHR
  [<TestMethod>]
  member _.``A8.8.399 VSHR``() =
    testDisasm "f2892014" "vshr.s8 d2, d4, #0x7"
    testDisasm "f2892054" "vshr.s8 q1, q2, #0x7"
    testDisasm "f3892014" "vshr.u8 d2, d4, #0x7"
    testDisasm "f3892054" "vshr.u8 q1, q2, #0x7"

  /// A8.8.4 ADD (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.4 ADD``() =
    testDisasm "e28dd008" "add sp, sp, #0x8"
    testDisasm "e2800003" "add r0, r0, #0x3"
    testDisasm "e0810002" "add r0, r1, r2"
    testDisasm "e0911002" "adds r1, r1, r2"

  /// A8.8.40 CPS
  [<TestMethod>]
  member _.``A8.8.40 CPS``() =
    testDisasm "f1020013" "cps #0x13"

  /// A8.8.400 VSHRN
  [<TestMethod>]
  member _.``A8.8.400 VSHRN``() =
    testDisasm "f28f0812" "vshrn.i16 d0, q1, #0x1"

  /// A8.8.401 VSLI
  [<TestMethod>]
  member _.``A8.8.401 VSLI``() =
    testDisasm "f3890552" "vsli.8 q0, q1, #0x1"
    testDisasm "f3892514" "vsli.8 d2, d4, #0x1"

  /// A8.8.402 VSQRT
  [<TestMethod>]
  member _.``A8.8.402 VSQRT``() =
    testDisasm "eeb109e0" "vsqrt.f16 s0, s1"
    testDisasm "eeb10bc2" "vsqrt.f64 d0, d2"
    testDisasm "1eb12ac4" "vsqrtne.f32 s4, s8"
    testDisasm "1eb12bc4" "vsqrtne.f64 d2, d4"

  /// A8.8.403 VSRA
  [<TestMethod>]
  member _.``A8.8.403 VSRA``() =
    testDisasm "f28f0152" "vsra.s8 q0, q1, #0x1"
    testDisasm "f2892114" "vsra.s8 d2, d4, #0x7"
    testDisasm "f3892114" "vsra.u8 d2, d4, #0x7"
    testDisasm "f3892154" "vsra.u8 q1, q2, #0x7"

  /// A8.8.404 VSRI
  [<TestMethod>]
  member _.``A8.8.404 VSRI``() =
    testDisasm "f38f0452" "vsri.8 q0, q1, #0x1"
    testDisasm "f3892414" "vsri.8 d2, d4, #0x7"

  /// A8.8.405 VST1 (multiple single elements)
  [<TestMethod>]
  member _.``A8.8.405 VST1``() =
    testDisasm "f401070f" "vst1.8 {d0}, [r1]"
    testDisasm "f4012204" "vst1.8 {d2, d3, d4, d5}, [r1], r4"
    testDisasm "f401220f" "vst1.8 {d2, d3, d4, d5}, [r1]"
    testDisasm "f4012604" "vst1.8 {d2, d3, d4}, [r1], r4"

  /// A8.8.407 VST2 (multiple 2-element structures)
  [<TestMethod>]
  member _.``A8.8.407 VST2``() =
    testDisasm "f401080f" "vst2.8 {d0, d1}, [r1]"
    testDisasm "f4012304" "vst2.8 {d2, d3, d4, d5}, [r1], r4"
    testDisasm "f401230f" "vst2.8 {d2, d3, d4, d5}, [r1]"
    testDisasm "f4012804" "vst2.8 {d2, d3}, [r1], r4"

  /// A8.8.409 VST3 (multiple 3-element structures)
  [<TestMethod>]
  member _.``A8.8.409 VST3``() =
    testDisasm "f401040f" "vst3.8 {d0, d1, d2}, [r1]"
    testDisasm "f4012404" "vst3.8 {d2, d3, d4}, [r1], r4"
    testDisasm "f4092404" "vst3.8 {d2, d3, d4}, [sb], r4"
    testDisasm "f409240f" "vst3.8 {d2, d3, d4}, [sb]"

  /// A8.8.41 CPY
  [<TestMethod>]
  member _.``A8.8.41 CPY``() =
    testDisasm "e1a00002" "mov r0, r2"
    testDisasm "e1b00002" "movs r0, r2"
    testDisasm "11a02004" "movne r2, r4"
    testDisasm "11b02004" "movsne r2, r4"

  /// A8.8.411 VST4 (multiple 4-element structures)
  [<TestMethod>]
  member _.``A8.8.411 VST4``() =
    testDisasm "f401000f" "vst4.8 {d0, d1, d2, d3}, [r1]"
    testDisasm "f4012004" "vst4.8 {d2, d3, d4, d5}, [r1], r4"
    testDisasm "f4092004" "vst4.8 {d2, d3, d4, d5}, [sb], r4"
    testDisasm "f409200f" "vst4.8 {d2, d3, d4, d5}, [sb]"

  /// A8.8.413 VSTM
  [<TestMethod>]
  member _.``A8.8.413 VSTM``() =
    testDisasm "ec810b04" "vstmia r1, {d0, d1}"
    testDisasm "ed2d0b04" "vstmdb sp!, {d0, d1}"
    testDisasm "ec810a04" "vstmia r1, {s0, s1, s2, s3}"
    testDisasm "ed2d0a04" "vstmdb sp!, {s0, s1, s2, s3}"

  /// A8.8.414 VSTR
  [<TestMethod>]
  member _.``A8.8.414 VSTR``() =
    testDisasm "ed810900" "vstr.16 s0, [r1]"
    testDisasm "ed810b00" "vstr.64 d0, [r1]"
    testDisasm "ed012904" "vstr.16 s4, [r1, #-0x8]"
    testDisasm "ed012b04" "vstr.64 d2, [r1, #-0x10]"

  /// A8.8.415 VSUB (integer)
  [<TestMethod>]
  member _.``A8.8.415 VSUB``() =
    testDisasm "ee3009c1" "vsub.f16 s0, s1, s2"
    testDisasm "f2320d44" "vsub.f16 q0, q1, q2"
    testDisasm "f3120844" "vsub.i16 q0, q1, q2"
    testDisasm "f3010802" "vsub.i8 d0, d1, d2"

  /// A8.8.417 VSUBHN
  [<TestMethod>]
  member _.``A8.8.417 VSUBHN``() =
    testDisasm "f2920604" "vsubhn.i32 d0, q1, q2"

  /// A8.8.418 VSUBL, VSUBW
  [<TestMethod>]
  member _.``A8.8.418 VSUBL``() =
    testDisasm "f2910202" "vsubl.s16 q0, d1, d2"
    testDisasm "f3810202" "vsubl.u8 q0, d1, d2"

  /// A8.8.418 VSUBL, VSUBW
  [<TestMethod>]
  member _.``A8.8.418 VSUBW``() =
    testDisasm "f2800301" "vsubw.s8 q0, q0, d1"
    testDisasm "f3802304" "vsubw.u8 q1, q0, d4"

  /// A8.8.419 VSWP
  [<TestMethod>]
  member _.``A8.8.419 VSWP``() =
    testDisasm "f3b20042" "vswp q0, q1"
    testDisasm "f3b20002" "vswp d0, d2"

  /// A8.8.42 CSDB
  [<TestMethod>]
  member _.``A8.8.42 CSDB``() =
    testDisasm "e320f014" "csdb"

  /// A8.8.420 VTBL, VTBX
  [<TestMethod>]
  member _.``A8.8.420 VTBL``() =
    testDisasm "f3b10802" "vtbl.8 d0, {d1}, d2"
    testDisasm "f3b12904" "vtbl.8 d2, {d1, d2}, d4"
    testDisasm "f3b12a04" "vtbl.8 d2, {d1, d2, d3}, d4"
    testDisasm "f3b12b04" "vtbl.8 d2, {d1, d2, d3, d4}, d4"

  /// A8.8.420 VTBL, VTBX
  [<TestMethod>]
  member _.``A8.8.420 VTBX``() =
    testDisasm "f3b10842" "vtbx.8 d0, {d1}, d2"
    testDisasm "f3b12944" "vtbx.8 d2, {d1, d2}, d4"
    testDisasm "f3b12a44" "vtbx.8 d2, {d1, d2, d3}, d4"
    testDisasm "f3b12b44" "vtbx.8 d2, {d1, d2, d3, d4}, d4"

  /// A8.8.421 VTRN
  [<TestMethod>]
  member _.``A8.8.421 VTRN``() =
    testDisasm "f3b200c2" "vtrn.8 q0, q1"
    testDisasm "f3b20081" "vtrn.8 d0, d1"

  /// A8.8.422 VTST
  [<TestMethod>]
  member _.``A8.8.422 VTST``() =
    testDisasm "f2020854" "vtst.8 q0, q1, q2"
    testDisasm "f2012814" "vtst.8 d2, d1, d4"

  /// A8.8.423 VUZP
  [<TestMethod>]
  member _.``A8.8.423 VUZP``() =
    testDisasm "f3b20142" "vuzp.8 q0, q1"
    testDisasm "f3b20101" "vuzp.8 d0, d1"

  /// A8.8.424 VZIP
  [<TestMethod>]
  member _.``A8.8.424 VZIP``() =
    testDisasm "f3b201c2" "vzip.8 q0, q1"
    testDisasm "f3b20181" "vzip.8 d0, d1"

  /// A8.8.425 WFE
  [<TestMethod>]
  member _.``A8.8.425 WFE``() =
    testDisasm "e320f002" "wfe"

  /// A8.8.426 WFI
  [<TestMethod>]
  member _.``A8.8.426 WFI``() =
    testDisasm "e320f003" "wfi"

  /// A8.8.427 YIELD
  [<TestMethod>]
  member _.``A8.8.427 YIELD``() =
    testDisasm "e320f001" "yield"
    testDisasm "1320f001" "yieldne"

  /// A8.8.43 DBG
  [<TestMethod>]
  member _.``A8.8.43 DBG``() =
    testDisasm "e320f0f4" "dbg #0x4"
    testDisasm "1320f0f4" "dbgne #0x4"

  /// A8.8.44 DMB
  [<TestMethod>]
  member _.``A8.8.44 DMB``() =
    testDisasm "f57ff05f" "dmb sy"
    testDisasm "f57ff05b" "dmb ish"

  /// A8.8.45 DSB
  [<TestMethod>]
  member _.``A8.8.45 DSB``() =
    testDisasm "f57ff04f" "dsb sy"

  /// A8.8.47 EOR (immediate)
  [<TestMethod>]
  member _.``A8.8.47 EOR``() =
    testDisasm "e0200002" "eor r0, r0, r2"
    testDisasm "e0310002" "eors r0, r1, r2"
    testDisasm "e0210082" "eor r0, r1, r2, lsl #0x1"
    testDisasm "e02101a2" "eor r0, r1, r2, lsr #0x3"

  /// A8.8.50 ERET
  [<TestMethod>]
  member _.``A8.8.50 ERET``() =
    testDisasm "e160006e" "eret"

  /// A8.8.53 HVC
  [<TestMethod>]
  member _.``A8.8.53 HVC``() =
    testDisasm "e1412074" "hvc #0x1204"

  /// A8.8.54 ISB
  [<TestMethod>]
  member _.``A8.8.54 ISB``() =
    testDisasm "f57ff06f" "isb sy"

  /// A8.8.56 LDC, LDC2 (immediate)
  [<TestMethod>]
  member _.``A8.8.56 LDC2``() =
    testDisasm "fd915302" "ldc2 p3, c5, [r1, #0x8]"

  /// A8.8.58 LDM/LDMIA/LDMFD (Thumb)
  [<TestMethod>]
  member _.``A8.8.58 LDM``() =
    testDisasm "e891000c" "ldm r1, {r2, r3}"
    testDisasm "e8b1000c" "ldm r1!, {r2, r3}"
    testDisasm "e8912004" "ldm r1, {r2, sp}"
    testDisasm "e8912000" "ldm r1, {sp}"

  /// A8.8.58 LDM/LDMIA/LDMFD (Thumb)
  [<TestMethod>]
  member _.``A8.8.58 LDMFD``() =
    testDisasm "e891000c" "ldm r1, {r2, r3}"
    testDisasm "e8bd000c" "pop {r2, r3}"
    testDisasm "e8b1000c" "ldm r1!, {r2, r3}"
    testDisasm "e49d2004" "pop {r2}"

  /// A8.8.58 LDM/LDMIA/LDMFD (Thumb)
  [<TestMethod>]
  member _.``A8.8.58 LDMIA``() =
    testDisasm "e891000c" "ldm r1, {r2, r3}"
    testDisasm "e8bd000c" "pop {r2, r3}"
    testDisasm "e8b1000c" "ldm r1!, {r2, r3}"
    testDisasm "e49d2004" "pop {r2}"

  /// A8.8.60 LDMDA/LDMFA
  [<TestMethod>]
  member _.``A8.8.60 LDMDA``() =
    testDisasm "e811000c" "ldmda r1, {r2, r3}"
    testDisasm "e8112004" "ldmda r1, {r2, sp}"
    testDisasm "e8112000" "ldmda r1, {sp}"
    testDisasm "e811200f" "ldmda r1, {r0, r1, r2, r3, sp}"

  /// A8.8.60 LDMDA/LDMFA
  [<TestMethod>]
  member _.``A8.8.60 LDMFA``() =
    testDisasm "e811000c" "ldmda r1, {r2, r3}"
    testDisasm "e8112004" "ldmda r1, {r2, sp}"
    testDisasm "e8112000" "ldmda r1, {sp}"
    testDisasm "e811200f" "ldmda r1, {r0, r1, r2, r3, sp}"

  /// A8.8.61 LDMDB/LDMEA
  [<TestMethod>]
  member _.``A8.8.61 LDMDB``() =
    testDisasm "e911000c" "ldmdb r1, {r2, r3}"
    testDisasm "e931000c" "ldmdb r1!, {r2, r3}"
    testDisasm "e9112004" "ldmdb r1, {r2, sp}"
    testDisasm "e9112000" "ldmdb r1, {sp}"

  /// A8.8.61 LDMDB/LDMEA
  [<TestMethod>]
  member _.``A8.8.61 LDMEA``() =
    testDisasm "e911000c" "ldmdb r1, {r2, r3}"
    testDisasm "e931000c" "ldmdb r1!, {r2, r3}"
    testDisasm "e9112004" "ldmdb r1, {r2, sp}"
    testDisasm "e9112000" "ldmdb r1, {sp}"

  /// A8.8.62 LDMIB/LDMED
  [<TestMethod>]
  member _.``A8.8.62 LDMED``() =
    testDisasm "e991000c" "ldmib r1, {r2, r3}"
    testDisasm "e9912004" "ldmib r1, {r2, sp}"
    testDisasm "e9912000" "ldmib r1, {sp}"
    testDisasm "e991200f" "ldmib r1, {r0, r1, r2, r3, sp}"

  /// A8.8.62 LDMIB/LDMED
  [<TestMethod>]
  member _.``A8.8.62 LDMIB``() =
    testDisasm "e991000c" "ldmib r1, {r2, r3}"
    testDisasm "e9912004" "ldmib r1, {r2, sp}"
    testDisasm "e9912000" "ldmib r1, {sp}"
    testDisasm "e991200f" "ldmib r1, {r0, r1, r2, r3, sp}"

  /// A8.8.63 LDR (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.63 LDR``() =
    testDisasm "e5910010" "ldr r0, [r1, #0x10]"
    testDisasm "e51f0004" "ldr r0, [0x4]"
    testDisasm "e7910002" "ldr r0, [r1, r2]"
    testDisasm "e7910082" "ldr r0, [r1, r2, lsl #0x1]"

  /// A8.8.68 LDRB (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.68 LDRB``() =
    testDisasm "e5d10003" "ldrb r0, [r1, #0x3]"
    testDisasm "e55f0004" "ldrb r0, [0x4]"
    testDisasm "e7d10002" "ldrb r0, [r1, r2]"
    testDisasm "e5d10000" "ldrb r0, [r1]"

  /// A8.8.72 LDRBT
  [<TestMethod>]
  member _.``A8.8.72 LDRBT``() =
    testDisasm "e4f10000" "ldrbt r0, [r1], #0x0"
    testDisasm "e471d004" "ldrbt sp, [r1], #-0x4"
    testDisasm "e4792004" "ldrbt r2, [sb], #-0x4"
    testDisasm "e479d004" "ldrbt sp, [sb], #-0x4"

  /// A8.8.73 LDRD (immediate)
  [<TestMethod>]
  member _.``A8.8.73 LDRD``() =
    testDisasm "e14f00d4" "ldrd r0, r1, [0x4]"
    testDisasm "e1c100d0" "ldrd r0, r1, [r1]"
    testDisasm "e00120d4" "ldrd r2, r3, [r1], -r4"
    testDisasm "e00920d4" "ldrd r2, r3, [sb], -r4"

  /// A8.8.76 LDREX
  [<TestMethod>]
  member _.``A8.8.76 LDREX``() =
    testDisasm "e1910f9f" "ldrex r0, [r1]"

  /// A8.8.77 LDREXB
  [<TestMethod>]
  member _.``A8.8.77 LDREXB``() =
    testDisasm "e1d10f9f" "ldrexb r0, [r1]"

  /// A8.8.78 LDREXD
  [<TestMethod>]
  member _.``A8.8.78 LDREXD``() =
    testDisasm "e1b10f9f" "ldrexd r0, r1, [r1]"

  /// A8.8.79 LDREXH
  [<TestMethod>]
  member _.``A8.8.79 LDREXH``() =
    testDisasm "e1f10f9f" "ldrexh r0, [r1]"

  /// A8.8.80 LDRH (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.80 LDRH``() =
    testDisasm "e1d101b0" "ldrh r0, [r1, #0x10]"
    testDisasm "e15f00b4" "ldrh r0, [0x4]"
    testDisasm "e19100b2" "ldrh r0, [r1, r2]"
    testDisasm "e1d100b0" "ldrh r0, [r1]"

  /// A8.8.84 LDRHT
  [<TestMethod>]
  member _.``A8.8.84 LDRHT``() =
    testDisasm "e0f100b0" "ldrht r0, [r1], #0x0"
    testDisasm "e03120b4" "ldrht r2, [r1], -r4"
    testDisasm "e031d0b4" "ldrht sp, [r1], -r4"
    testDisasm "e03920b4" "ldrht r2, [sb], -r4"

  /// A8.8.85 LDRSB (immediate)
  [<TestMethod>]
  member _.``A8.8.85 LDRSB``() =
    testDisasm "e1d100d7" "ldrsb r0, [r1, #0x7]"
    testDisasm "e15f00d4" "ldrsb r0, [0x4]"
    testDisasm "e19100d2" "ldrsb r0, [r1, r2]"
    testDisasm "e1d100d0" "ldrsb r0, [r1]"

  /// A8.8.88 LDRSBT
  [<TestMethod>]
  member _.``A8.8.88 LDRSBT``() =
    testDisasm "e0f100d0" "ldrsbt r0, [r1], #0x0"
    testDisasm "e03120d4" "ldrsbt r2, [r1], -r4"
    testDisasm "e031d0d4" "ldrsbt sp, [r1], -r4"
    testDisasm "e03920d4" "ldrsbt r2, [sb], -r4"

  /// A8.8.89 LDRSH (immediate)
  [<TestMethod>]
  member _.``A8.8.89 LDRSH``() =
    testDisasm "e1d100f7" "ldrsh r0, [r1, #0x7]"
    testDisasm "e15f00f4" "ldrsh r0, [0x4]"
    testDisasm "e19100f2" "ldrsh r0, [r1, r2]"
    testDisasm "e1d100f0" "ldrsh r0, [r1]"

  /// A8.8.92 LDRSHT
  [<TestMethod>]
  member _.``A8.8.92 LDRSHT``() =
    testDisasm "e0f100f0" "ldrsht r0, [r1], #0x0"
    testDisasm "e03120f4" "ldrsht r2, [r1], -r4"
    testDisasm "e031d0f4" "ldrsht sp, [r1], -r4"
    testDisasm "e03920f4" "ldrsht r2, [sb], -r4"

  /// A8.8.93 LDRT
  [<TestMethod>]
  member _.``A8.8.93 LDRT``() =
    testDisasm "e4b10000" "ldrt r0, [r1], #0x0"
    testDisasm "e431d004" "ldrt sp, [r1], #-0x4"
    testDisasm "e4392004" "ldrt r2, [sb], #-0x4"
    testDisasm "e439d004" "ldrt sp, [sb], #-0x4"

  /// A8.8.95 LSL (immediate)
  [<TestMethod>]
  member _.``A8.8.95 LSL``() =
    testDisasm "e1a00210" "lsl r0, r0, r2"
    testDisasm "e1b00211" "lsls r0, r1, r2"
    testDisasm "e1a02914" "lsl r2, r4, sb"
    testDisasm "e1a02a14" "lsl r2, r4, sl"

  /// A8.8.97 LSR (immediate)
  [<TestMethod>]
  member _.``A8.8.97 LSR``() =
    testDisasm "e1a00822" "lsr r0, r2, #0x10"
    testDisasm "e1b00822" "lsrs r0, r2, #0x10"
    testDisasm "e1a00230" "lsr r0, r0, r2"
    testDisasm "e1b00231" "lsrs r0, r1, r2"

  /// A8.8.99 MCR, MCR2
  [<TestMethod>]
  member _.``A8.8.99 MCR``() =
    testDisasm "ee012e14" "mcr p14, #0x0, r2, c1, c4, #0x0"
    testDisasm "ee01de14" "mcr p14, #0x0, sp, c1, c4, #0x0"
    testDisasm "1e012e14" "mcrne p14, #0x0, r2, c1, c4, #0x0"
    testDisasm "1e01de14" "mcrne p14, #0x0, sp, c1, c4, #0x0"

  /// A8.8.99 MCR, MCR2
  [<TestMethod>]
  member _.``A8.8.99 MCR2``() =
    testDisasm "fe2323b4" "mcr2 p3, #0x1, r2, c3, c4, #0x5"

  /// F5.1.1 ADC, ADCS (immediate)
  [<TestMethod>]
  member _.``F5.1.1 ADCS``() =
    testDisasm "e0b10002" "adcs r0, r1, r2"
    testDisasm "e0b10312" "adcs r0, r1, r2, lsl r3"
    testDisasm "e0b10332" "adcs r0, r1, r2, lsr r3"
    testDisasm "e0b10352" "adcs r0, r1, r2, asr r3"

  /// F5.1.101 LSLS (immediate)
  [<TestMethod>]
  member _.``F5.1.101 LSLS``() =
    testDisasm "e1b00211" "lsls r0, r1, r2"
    testDisasm "e1b02914" "lsls r2, r4, sb"
    testDisasm "e1b02a14" "lsls r2, r4, sl"
    testDisasm "e1b02b14" "lsls r2, r4, fp"

  /// F5.1.105 LSRS (immediate)
  [<TestMethod>]
  member _.``F5.1.105 LSRS``() =
    testDisasm "e1b00822" "lsrs r0, r2, #0x10"
    testDisasm "e1b00231" "lsrs r0, r1, r2"
    testDisasm "e1b02934" "lsrs r2, r4, sb"
    testDisasm "e1b02a34" "lsrs r2, r4, sl"

  /// F5.1.109 MLA, MLAS
  [<TestMethod>]
  member _.``F5.1.109 MLAS``() =
    testDisasm "e0303291" "mlas r0, r1, r2, r3"
    testDisasm "e0312994" "mlas r1, r4, sb, r2"
    testDisasm "e0312a94" "mlas r1, r4, sl, r2"
    testDisasm "e0312b94" "mlas r1, r4, fp, r2"

  /// F5.1.11 AND, ANDS (immediate)
  [<TestMethod>]
  member _.``F5.1.11 ANDS``() =
    testDisasm "e0110002" "ands r0, r1, r2"
    testDisasm "e0110312" "ands r0, r1, r2, lsl r3"
    testDisasm "e0110332" "ands r0, r1, r2, lsr r3"
    testDisasm "e0110352" "ands r0, r1, r2, asr r3"

  /// F5.1.111 MOV, MOVS (immediate)
  [<TestMethod>]
  member _.``F5.1.111 MOVS``() =
    testDisasm "e1b00002" "movs r0, r2"
    testDisasm "e1b0200f" "movs r2, pc"
    testDisasm "e1b0d004" "movs sp, r4"
    testDisasm "e1b0d00f" "movs sp, pc"

  /// F5.1.122 MUL, MULS
  [<TestMethod>]
  member _.``F5.1.122 MULS``() =
    testDisasm "e0100091" "muls r0, r1, r0"
    testDisasm "e0112994" "muls r1, r4, sb"
    testDisasm "e0112a94" "muls r1, r4, sl"
    testDisasm "e0112b94" "muls r1, r4, fp"

  /// F5.1.123 MVN, MVNS (immediate)
  [<TestMethod>]
  member _.``F5.1.123 MVNS``() =
    testDisasm "e1f00002" "mvns r0, r2"
    testDisasm "e1f00312" "mvns r0, r2, lsl r3"
    testDisasm "e1f00332" "mvns r0, r2, lsr r3"
    testDisasm "e1f00352" "mvns r0, r2, asr r3"

  /// F5.1.129 ORR, ORRS (immediate)
  [<TestMethod>]
  member _.``F5.1.129 ORRS``() =
    testDisasm "e1910002" "orrs r0, r1, r2"
    testDisasm "e1910312" "orrs r0, r1, r2, lsl r3"
    testDisasm "e1910332" "orrs r0, r1, r2, lsr r3"
    testDisasm "e1910352" "orrs r0, r1, r2, asr r3"

  /// F5.1.132 PKHBT, PKHTB
  [<TestMethod>]
  member _.``F5.1.132 PKHBT``() =
    testDisasm "e6810212" "pkhbt r0, r1, r2, lsl #0x4"
    testDisasm "e6810012" "pkhbt r0, r1, r2"
    testDisasm "e681d014" "pkhbt sp, r1, r4"
    testDisasm "e681d114" "pkhbt sp, r1, r4, lsl #0x2"

  /// F5.1.132 PKHBT, PKHTB
  [<TestMethod>]
  member _.``F5.1.132 PKHTB``() =
    testDisasm "e6810252" "pkhtb r0, r1, r2, asr #0x4"
    testDisasm "e681d054" "pkhtb sp, r1, r4, asr #0x20"
    testDisasm "e6892054" "pkhtb r2, sb, r4, asr #0x20"
    testDisasm "e689d054" "pkhtb sp, sb, r4, asr #0x20"

  /// F5.1.141 PSSBB
  [<TestMethod>]
  member _.``F5.1.141 PSSBB``() =
    testDisasm "f57ff044" "pssbb"

  /// F5.1.159 RFE, RFEDA, RFEDB, RFEIA, RFEIB
  [<TestMethod>]
  member _.``F5.1.159 RFEDA``() =
    testDisasm "f8310a00" "rfeda r1!"

  /// F5.1.159 RFE, RFEDA, RFEDB, RFEIA, RFEIB
  [<TestMethod>]
  member _.``F5.1.159 RFEDB``() =
    testDisasm "f9110a00" "rfedb r1"

  /// F5.1.159 RFE, RFEDA, RFEDB, RFEIA, RFEIB
  [<TestMethod>]
  member _.``F5.1.159 RFEIA``() =
    testDisasm "f8910a00" "rfeia r1"
