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
/// chapters describe, VPOP to SEVL in the order of their sections. Each
/// reads T32 words of the instruction and checks the text, and each word's
/// text is one binutils' objdump reads the word as too, so what is asserted
/// is a reading two decoders agree on.
/// </summary>
[<TestClass>]
type ManualT32ParserTests3() =
  let testDisasm (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let isa = ISA(Architecture.ARMv7, Endian.Big)
    let parser = Parser(isa, true, BinReader.Init Endian.Big)
    let ins = (parser :> IInstructionParsable).Parse(bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  /// A8.8.368 VPOP
  [<TestMethod>]
  member _.``A8.8.368 VPOP``() =
    testDisasm "ecbd0b04" "vldmia sp!, {d0, d1}"
    testDisasm "ecbd0a01" "vldmia sp!, {s0}"
    ("vldmia sp!, {s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, "
     + "s13, s14, s15}")
    |> testDisasm "ecbd0a10"
    ("vldmia sp!, {s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, "
     + "s13, s14, s15, s16, s17}")
    |> testDisasm "ecbd0a12"

  /// A8.8.369 VPUSH
  [<TestMethod>]
  member _.``A8.8.369 VPUSH``() =
    testDisasm "ed2d0b04" "vstmdb sp!, {d0, d1}"
    testDisasm "ed2d0a04" "vstmdb sp!, {s0, s1, s2, s3}"
    testDisasm "ed2d0a01" "vstmdb sp!, {s0}"
    ("vstmdb sp!, {s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, "
     + "s13, s14, s15}")
    |> testDisasm "ed2d0a10"

  /// A8.8.37 CMP (immediate)
  [<TestMethod>]
  member _.``A8.8.37 CMP``() =
    testDisasm "2903bf00" "cmp r1, #0x3"
    testDisasm "4291bf00" "cmp r1, r2"
    testDisasm "ebb10f42" "cmp r1, r2, lsl #0x1"
    testDisasm "ebb10fd2" "cmp r1, r2, lsr #0x3"

  /// A8.8.370 VQABS
  [<TestMethod>]
  member _.``A8.8.370 VQABS``() =
    testDisasm "ffb00744" "vqabs.s8 q0, q2"
    testDisasm "ffb00702" "vqabs.s8 d0, d2"

  /// A8.8.371 VQADD
  [<TestMethod>]
  member _.``A8.8.371 VQADD``() =
    testDisasm "ef120054" "vqadd.s16 q0, q1, q2"
    testDisasm "ff020054" "vqadd.u8 q0, q1, q2"
    testDisasm "ef010012" "vqadd.s8 d0, d1, d2"
    testDisasm "ff010012" "vqadd.u8 d0, d1, d2"

  /// A8.8.372 VQDMLAL, VQDMLSL
  [<TestMethod>]
  member _.``A8.8.372 VQDMLAL``() =
    testDisasm "ef910902" "vqdmlal.s16 q0, d1, d2"
    testDisasm "ef91034f" "vqdmlal.s16 q0, d1, d7[1]"

  /// A8.8.372 VQDMLAL, VQDMLSL
  [<TestMethod>]
  member _.``A8.8.372 VQDMLSL``() =
    testDisasm "ef910b02" "vqdmlsl.s16 q0, d1, d2"
    testDisasm "ef91074f" "vqdmlsl.s16 q0, d1, d7[1]"

  /// A8.8.373 VQDMULH
  [<TestMethod>]
  member _.``A8.8.373 VQDMULH``() =
    testDisasm "ef220b44" "vqdmulh.s32 q0, q1, q2"
    testDisasm "ef110b02" "vqdmulh.s16 d0, d1, d2"
    testDisasm "ff920c42" "vqdmulh.s16 q0, q1, d2[0]"
    testDisasm "ef910c42" "vqdmulh.s16 d0, d1, d2[0]"

  /// A8.8.374 VQDMULL
  [<TestMethod>]
  member _.``A8.8.374 VQDMULL``() =
    testDisasm "efa10d02" "vqdmull.s32 q0, d1, d2"
    testDisasm "ef910b42" "vqdmull.s16 q0, d1, d2[0]"

  /// A8.8.375 VQMOVN, VQMOVUN
  [<TestMethod>]
  member _.``A8.8.375 VQMOVN``() =
    testDisasm "ffb20282" "vqmovn.s16 d0, q1"

  /// A8.8.375 VQMOVN, VQMOVUN
  [<TestMethod>]
  member _.``A8.8.375 VQMOVUN``() =
    testDisasm "ffb20242" "vqmovun.s16 d0, q1"

  /// A8.8.376 VQNEG
  [<TestMethod>]
  member _.``A8.8.376 VQNEG``() =
    testDisasm "ffb007c4" "vqneg.s8 q0, q2"
    testDisasm "ffb00782" "vqneg.s8 d0, d2"

  /// A8.8.377 VQRDMULH
  [<TestMethod>]
  member _.``A8.8.377 VQRDMULH``() =
    testDisasm "ff220b44" "vqrdmulh.s32 q0, q1, q2"
    testDisasm "ff110b02" "vqrdmulh.s16 d0, d1, d2"
    testDisasm "ff920d42" "vqrdmulh.s16 q0, q1, d2[0]"
    testDisasm "ef910d42" "vqrdmulh.s16 d0, d1, d2[0]"

  /// A8.8.378 VQRSHL
  [<TestMethod>]
  member _.``A8.8.378 VQRSHL``() =
    testDisasm "ef040552" "vqrshl.s8 q0, q1, q2"
    testDisasm "ef010534" "vqrshl.s8 d0, d20, d1"
    testDisasm "ff010534" "vqrshl.u8 d0, d20, d1"
    testDisasm "ff000570" "vqrshl.u8 q0, q8, q0"

  /// A8.8.379 VQRSHRN, VQRSHRUN
  [<TestMethod>]
  member _.``A8.8.379 VQRSHRN``() =
    testDisasm "ef8f0952" "vqrshrn.s16 d0, q1, #0x1"
    testDisasm "ff890970" "vqrshrn.u16 d0, q8, #0x7"

  /// A8.8.379 VQRSHRN, VQRSHRUN
  [<TestMethod>]
  member _.``A8.8.379 VQRSHRUN``() =
    testDisasm "ff8f0852" "vqrshrun.s16 d0, q1, #0x1"

  /// A8.8.380 VQSHL (register)
  [<TestMethod>]
  member _.``A8.8.380 VQSHL``() =
    testDisasm "ef040452" "vqshl.s8 q0, q1, q2"
    testDisasm "ef010434" "vqshl.s8 d0, d20, d1"
    testDisasm "ef890734" "vqshl.s8 d0, d20, #0x1"
    testDisasm "ef890770" "vqshl.s8 q0, q8, #0x1"

  /// A8.8.381 VQSHL, VQSHLU (immediate)
  [<TestMethod>]
  member _.``A8.8.381 VQSHLU``() =
    testDisasm "ff890652" "vqshlu.s8 q0, q1, #0x1"
    testDisasm "ff890634" "vqshlu.s8 d0, d20, #0x1"

  /// A8.8.382 VQSHRN, VQSHRUN
  [<TestMethod>]
  member _.``A8.8.382 VQSHRN``() =
    testDisasm "ef8f0912" "vqshrn.s16 d0, q1, #0x1"
    testDisasm "ff890934" "vqshrn.u16 d0, q10, #0x7"

  /// A8.8.382 VQSHRN, VQSHRUN
  [<TestMethod>]
  member _.``A8.8.382 VQSHRUN``() =
    testDisasm "ff8f0812" "vqshrun.s16 d0, q1, #0x1"

  /// A8.8.383 VQSUB
  [<TestMethod>]
  member _.``A8.8.383 VQSUB``() =
    testDisasm "ef020254" "vqsub.s8 q0, q1, q2"
    testDisasm "ef010234" "vqsub.s8 d0, d1, d20"
    testDisasm "ff010234" "vqsub.u8 d0, d1, d20"
    testDisasm "ff000270" "vqsub.u8 q0, q0, q8"

  /// A8.8.384 VRADDHN
  [<TestMethod>]
  member _.``A8.8.384 VRADDHN``() =
    testDisasm "ff920404" "vraddhn.i32 d0, q1, q2"

  /// A8.8.385 VRECPE
  [<TestMethod>]
  member _.``A8.8.385 VRECPE``() =
    testDisasm "ffb70542" "vrecpe.f16 q0, q1"
    testDisasm "ffbb0444" "vrecpe.u32 q0, q2"
    testDisasm "ffbb0402" "vrecpe.u32 d0, d2"
    testDisasm "ffbb0502" "vrecpe.f32 d0, d2"

  /// A8.8.386 VRECPS
  [<TestMethod>]
  member _.``A8.8.386 VRECPS``() =
    testDisasm "ef120f54" "vrecps.f16 q0, q1, q2"
    testDisasm "ef010f12" "vrecps.f32 d0, d1, d2"

  /// A8.8.387 VREV16, VREV32, VREV64
  [<TestMethod>]
  member _.``A8.8.387 VREV16``() =
    testDisasm "ffb00142" "vrev16.8 q0, q1"
    testDisasm "ffb00100" "vrev16.8 d0, d0"

  /// A8.8.387 VREV16, VREV32, VREV64
  [<TestMethod>]
  member _.``A8.8.387 VREV32``() =
    testDisasm "ffb000c2" "vrev32.8 q0, q1"

  /// A8.8.387 VREV16, VREV32, VREV64
  [<TestMethod>]
  member _.``A8.8.387 VREV64``() =
    testDisasm "ffb00042" "vrev64.8 q0, q1"
    testDisasm "ffb00000" "vrev64.8 d0, d0"

  /// A8.8.388 VRHADD
  [<TestMethod>]
  member _.``A8.8.388 VRHADD``() =
    testDisasm "ff020144" "vrhadd.u8 q0, q1, q2"
    testDisasm "ef022144" "vrhadd.s8 q1, q1, q2"
    testDisasm "ef011102" "vrhadd.s8 d1, d1, d2"
    testDisasm "ff011102" "vrhadd.u8 d1, d1, d2"

  /// A8.8.389 VRSHL
  [<TestMethod>]
  member _.``A8.8.389 VRSHL``() =
    testDisasm "ef040542" "vrshl.s8 q0, q1, q2"
    testDisasm "ef010500" "vrshl.s8 d0, d0, d1"
    testDisasm "ff010500" "vrshl.u8 d0, d0, d1"

  /// A8.8.390 VRSHR
  [<TestMethod>]
  member _.``A8.8.390 VRSHR``() =
    testDisasm "ef890234" "vrshr.s8 d0, d20, #0x7"
    testDisasm "ef890270" "vrshr.s8 q0, q8, #0x7"
    testDisasm "ff890234" "vrshr.u8 d0, d20, #0x7"
    testDisasm "ff890270" "vrshr.u8 q0, q8, #0x7"

  /// A8.8.391 VRSHRN
  [<TestMethod>]
  member _.``A8.8.391 VRSHRN``() =
    testDisasm "ef8f0852" "vrshrn.i16 d0, q1, #0x1"

  /// A8.8.392 VRSQRTE
  [<TestMethod>]
  member _.``A8.8.392 VRSQRTE``() =
    testDisasm "ffb705c2" "vrsqrte.f16 q0, q1"
    testDisasm "ffbb04c4" "vrsqrte.u32 q0, q2"
    testDisasm "ffbb0482" "vrsqrte.u32 d0, d2"
    testDisasm "ffbb0582" "vrsqrte.f32 d0, d2"

  /// A8.8.393 VRSQRTS
  [<TestMethod>]
  member _.``A8.8.393 VRSQRTS``() =
    testDisasm "ef320f54" "vrsqrts.f16 q0, q1, q2"
    testDisasm "ef210f12" "vrsqrts.f32 d0, d1, d2"

  /// A8.8.394 VRSRA
  [<TestMethod>]
  member _.``A8.8.394 VRSRA``() =
    testDisasm "ef8f0352" "vrsra.s8 q0, q1, #0x1"
    testDisasm "ef890334" "vrsra.s8 d0, d20, #0x7"
    testDisasm "ff890334" "vrsra.u8 d0, d20, #0x7"
    testDisasm "ff890370" "vrsra.u8 q0, q8, #0x7"

  /// A8.8.395 VRSUBHN
  [<TestMethod>]
  member _.``A8.8.395 VRSUBHN``() =
    testDisasm "ff920604" "vrsubhn.i32 d0, q1, q2"

  /// A8.8.396 VSHL (immediate)
  [<TestMethod>]
  member _.``A8.8.396 VSHL``() =
    testDisasm "ef890552" "vshl.i8 q0, q1, #0x1"
    testDisasm "ef010400" "vshl.s8 d0, d0, d1"
    testDisasm "ef890534" "vshl.i8 d0, d20, #0x1"
    testDisasm "ff010400" "vshl.u8 d0, d0, d1"

  /// A8.8.398 VSHLL
  [<TestMethod>]
  member _.``A8.8.398 VSHLL``() =
    testDisasm "ef890a11" "vshll.s8 q0, d1, #0x1"
    testDisasm "ff890a34" "vshll.u8 q0, d20, #0x1"

  /// A8.8.399 VSHR
  [<TestMethod>]
  member _.``A8.8.399 VSHR``() =
    testDisasm "ef890034" "vshr.s8 d0, d20, #0x7"
    testDisasm "ef890070" "vshr.s8 q0, q8, #0x7"
    testDisasm "ff890034" "vshr.u8 d0, d20, #0x7"
    testDisasm "ff890070" "vshr.u8 q0, q8, #0x7"

  /// A8.8.4 ADD (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.4 ADD``() =
    testDisasm "b002bf00" "add sp, sp, #0x8"
    testDisasm "f1000003" "add r0, r0, #0x3"
    testDisasm "f111417f" "adds.w r1, r1, #0xff000000"
    testDisasm "eb010002" "add r0, r1, r2"

  /// A8.8.40 CPS
  [<TestMethod>]
  member _.``A8.8.40 CPS``() =
    testDisasm "f3af8113" "cps #0x13"

  /// A8.8.400 VSHRN
  [<TestMethod>]
  member _.``A8.8.400 VSHRN``() =
    testDisasm "ef8f0812" "vshrn.i16 d0, q1, #0x1"

  /// A8.8.401 VSLI
  [<TestMethod>]
  member _.``A8.8.401 VSLI``() =
    testDisasm "ff890552" "vsli.8 q0, q1, #0x1"
    testDisasm "ff890534" "vsli.8 d0, d20, #0x1"

  /// A8.8.402 VSQRT
  [<TestMethod>]
  member _.``A8.8.402 VSQRT``() =
    testDisasm "eeb109e0" "vsqrt.f16 s0, s1"
    testDisasm "eeb10bc2" "vsqrt.f64 d0, d2"

  /// A8.8.403 VSRA
  [<TestMethod>]
  member _.``A8.8.403 VSRA``() =
    testDisasm "ef8f0152" "vsra.s8 q0, q1, #0x1"
    testDisasm "ef890134" "vsra.s8 d0, d20, #0x7"
    testDisasm "ff890134" "vsra.u8 d0, d20, #0x7"
    testDisasm "ff890170" "vsra.u8 q0, q8, #0x7"

  /// A8.8.404 VSRI
  [<TestMethod>]
  member _.``A8.8.404 VSRI``() =
    testDisasm "ff8f0452" "vsri.8 q0, q1, #0x1"
    testDisasm "ff890434" "vsri.8 d0, d20, #0x7"

  /// A8.8.405 VST1 (multiple single elements)
  [<TestMethod>]
  member _.``A8.8.405 VST1``() =
    testDisasm "f901070f" "vst1.8 {d0}, [r1]"
    testDisasm "f9010234" "vst1.8 {d0, d1, d2, d3}, [r1:256], r4"
    testDisasm "f9010200" "vst1.8 {d0, d1, d2, d3}, [r1], r0"
    testDisasm "f901024f" "vst1.16 {d0, d1, d2, d3}, [r1]"

  /// A8.8.407 VST2 (multiple 2-element structures)
  [<TestMethod>]
  member _.``A8.8.407 VST2``() =
    testDisasm "f901080f" "vst2.8 {d0, d1}, [r1]"
    testDisasm "f9010334" "vst2.8 {d0, d1, d2, d3}, [r1:256], r4"
    testDisasm "f9010300" "vst2.8 {d0, d1, d2, d3}, [r1], r0"
    testDisasm "f901034f" "vst2.16 {d0, d1, d2, d3}, [r1]"

  /// A8.8.409 VST3 (multiple 3-element structures)
  [<TestMethod>]
  member _.``A8.8.409 VST3``() =
    testDisasm "f901040f" "vst3.8 {d0, d1, d2}, [r1]"
    testDisasm "f9010400" "vst3.8 {d0, d1, d2}, [r1], r0"
    testDisasm "f9010410" "vst3.8 {d0, d1, d2}, [r1:64], r0"
    testDisasm "f901045f" "vst3.16 {d0, d1, d2}, [r1:64]"

  /// A8.8.41 CPY
  [<TestMethod>]
  member _.``A8.8.41 CPY``() =
    testDisasm "4610bf00" "mov r0, r2"
    testDisasm "0010bf00" "movs r0, r2"

  /// A8.8.411 VST4 (multiple 4-element structures)
  [<TestMethod>]
  member _.``A8.8.411 VST4``() =
    testDisasm "f901000f" "vst4.8 {d0, d1, d2, d3}, [r1]"
    testDisasm "f9010034" "vst4.8 {d0, d1, d2, d3}, [r1:256], r4"
    testDisasm "f9010000" "vst4.8 {d0, d1, d2, d3}, [r1], r0"
    testDisasm "f901005f" "vst4.16 {d0, d1, d2, d3}, [r1:64]"

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
    testDisasm "ed810a00" "vstr s0, [r1]"
    testDisasm "ed810b00" "vstr d0, [r1]"
    testDisasm "ed010934" "vstr.16 s0, [r1, #-0x68]"

  /// A8.8.415 VSUB (integer)
  [<TestMethod>]
  member _.``A8.8.415 VSUB``() =
    testDisasm "ee3009c1" "vsub.f16 s0, s1, s2"
    testDisasm "ef320d44" "vsub.f16 q0, q1, q2"
    testDisasm "ff120844" "vsub.i16 q0, q1, q2"
    testDisasm "ff010802" "vsub.i8 d0, d1, d2"

  /// A8.8.417 VSUBHN
  [<TestMethod>]
  member _.``A8.8.417 VSUBHN``() =
    testDisasm "ef920604" "vsubhn.i32 d0, q1, q2"

  /// A8.8.418 VSUBL, VSUBW
  [<TestMethod>]
  member _.``A8.8.418 VSUBL``() =
    testDisasm "ef910202" "vsubl.s16 q0, d1, d2"
    testDisasm "ff810202" "vsubl.u8 q0, d1, d2"

  /// A8.8.418 VSUBL, VSUBW
  [<TestMethod>]
  member _.``A8.8.418 VSUBW``() =
    testDisasm "ef800301" "vsubw.s8 q0, q0, d1"
    testDisasm "ff800300" "vsubw.u8 q0, q0, d0"

  /// A8.8.419 VSWP
  [<TestMethod>]
  member _.``A8.8.419 VSWP``() =
    testDisasm "ffb20042" "vswp q0, q1"
    testDisasm "ffb20002" "vswp d0, d2"

  /// A8.8.42 CSDB
  [<TestMethod>]
  member _.``A8.8.42 CSDB``() =
    testDisasm "f3af8014" "csdb"

  /// A8.8.420 VTBL, VTBX
  [<TestMethod>]
  member _.``A8.8.420 VTBL``() =
    testDisasm "ffb10802" "vtbl.8 d0, {d1}, d2"
    testDisasm "ffb10900" "vtbl.8 d0, {d1, d2}, d0"
    testDisasm "ffb10a00" "vtbl.8 d0, {d1, d2, d3}, d0"
    testDisasm "ffb10b00" "vtbl.8 d0, {d1, d2, d3, d4}, d0"

  /// A8.8.420 VTBL, VTBX
  [<TestMethod>]
  member _.``A8.8.420 VTBX``() =
    testDisasm "ffb10842" "vtbx.8 d0, {d1}, d2"
    testDisasm "ffb1094f" "vtbx.8 d0, {d1, d2}, d15"
    testDisasm "ffb10a4f" "vtbx.8 d0, {d1, d2, d3}, d15"
    testDisasm "ffb10b4f" "vtbx.8 d0, {d1, d2, d3, d4}, d15"

  /// A8.8.421 VTRN
  [<TestMethod>]
  member _.``A8.8.421 VTRN``() =
    testDisasm "ffb200c2" "vtrn.8 q0, q1"

  /// A8.8.422 VTST
  [<TestMethod>]
  member _.``A8.8.422 VTST``() =
    testDisasm "ef020854" "vtst.8 q0, q1, q2"
    testDisasm "ef010834" "vtst.8 d0, d1, d20"

  /// A8.8.423 VUZP
  [<TestMethod>]
  member _.``A8.8.423 VUZP``() =
    testDisasm "ffb20142" "vuzp.8 q0, q1"

  /// A8.8.424 VZIP
  [<TestMethod>]
  member _.``A8.8.424 VZIP``() =
    testDisasm "ffb201c2" "vzip.8 q0, q1"

  /// A8.8.425 WFE
  [<TestMethod>]
  member _.``A8.8.425 WFE``() =
    testDisasm "bf20bf00" "wfe"
    testDisasm "f3af8002" "wfe.w"

  /// A8.8.426 WFI
  [<TestMethod>]
  member _.``A8.8.426 WFI``() =
    testDisasm "bf30bf00" "wfi"

  /// A8.8.427 YIELD
  [<TestMethod>]
  member _.``A8.8.427 YIELD``() =
    testDisasm "bf10bf00" "yield"

  /// A8.8.44 DMB
  [<TestMethod>]
  member _.``A8.8.44 DMB``() =
    testDisasm "f3bf8f5f" "dmb sy"

  /// A8.8.45 DSB
  [<TestMethod>]
  member _.``A8.8.45 DSB``() =
    testDisasm "f3bf8f4f" "dsb sy"

  /// A8.8.47 EOR (immediate)
  [<TestMethod>]
  member _.``A8.8.47 EOR``() =
    testDisasm "ea800002" "eor r0, r0, r2"
    testDisasm "ea910002" "eors.w r0, r1, r2"
    testDisasm "ea810042" "eor r0, r1, r2, lsl #0x1"
    testDisasm "ea8100d2" "eor r0, r1, r2, lsr #0x3"

  /// A8.8.50 ERET
  [<TestMethod>]
  member _.``A8.8.50 ERET``() =
    testDisasm "f3de8f00" "eret"

  /// A8.8.53 HVC
  [<TestMethod>]
  member _.``A8.8.53 HVC``() =
    testDisasm "f7e18034" "hvc #0x1034"

  /// A8.8.54 ISB
  [<TestMethod>]
  member _.``A8.8.54 ISB``() =
    testDisasm "f3bf8f6f" "isb sy"

  /// A8.8.55 IT
  [<TestMethod>]
  member _.``A8.8.55 IT``() =
    testDisasm "bf08bf00" "it eq"
    testDisasm "bf18bf00" "it ne"
    testDisasm "bf28bf00" "it cs"
    testDisasm "bf38bf00" "it cc"

  /// A8.8.56 LDC, LDC2 (immediate)
  [<TestMethod>]
  member _.``A8.8.56 LDC``() =
    testDisasm "ec315e34" "ldc p14, c5, [r1], #-0xd0"
    testDisasm "ec395e34" "ldc p14, c5, [sb], #-0xd0"
    testDisasm "ec3d5e34" "ldc p14, c5, [sp], #-0xd0"
    testDisasm "ed115e34" "ldc p14, c5, [r1, #-0xd0]"

  /// A8.8.58 LDM/LDMIA/LDMFD (Thumb)
  [<TestMethod>]
  member _.``A8.8.58 LDM``() =
    testDisasm "e891000c" "ldm.w r1, {r2, r3}"
    testDisasm "c90cbf00" "ldm r1!, {r2, r3}"
    testDisasm "c801bf00" "ldm r0, {r0}"
    testDisasm "c802bf00" "ldm r0!, {r1}"

  /// A8.8.58 LDM/LDMIA/LDMFD (Thumb)
  [<TestMethod>]
  member _.``A8.8.58 LDMFD``() =
    testDisasm "e891000c" "ldm.w r1, {r2, r3}"
    testDisasm "bc0cbf00" "pop {r2, r3}"
    testDisasm "c90cbf00" "ldm r1!, {r2, r3}"
    testDisasm "bc01bf00" "pop {r0}"

  /// A8.8.58 LDM/LDMIA/LDMFD (Thumb)
  [<TestMethod>]
  member _.``A8.8.58 LDMIA``() =
    testDisasm "e891000c" "ldm.w r1, {r2, r3}"
    testDisasm "bc0cbf00" "pop {r2, r3}"
    testDisasm "c90cbf00" "ldm r1!, {r2, r3}"
    testDisasm "bc01bf00" "pop {r0}"

  /// A8.8.61 LDMDB/LDMEA
  [<TestMethod>]
  member _.``A8.8.61 LDMDB``() =
    testDisasm "e911000c" "ldmdb r1, {r2, r3}"
    testDisasm "e9110034" "ldmdb r1, {r2, r4, r5}"
    testDisasm "e911004f" "ldmdb r1, {r0, r1, r2, r3, r6}"
    testDisasm "e911005f" "ldmdb r1, {r0, r1, r2, r3, r4, r6}"

  /// A8.8.61 LDMDB/LDMEA
  [<TestMethod>]
  member _.``A8.8.61 LDMEA``() =
    testDisasm "e911000c" "ldmdb r1, {r2, r3}"
    testDisasm "e9110034" "ldmdb r1, {r2, r4, r5}"
    testDisasm "e911004f" "ldmdb r1, {r0, r1, r2, r3, r6}"
    testDisasm "e911005f" "ldmdb r1, {r0, r1, r2, r3, r4, r6}"

  /// A8.8.63 LDR (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.63 LDR``() =
    testDisasm "6908bf00" "ldr r0, [r1, #0x10]"
    testDisasm "4800bf00" "ldr r0, [0x4]"
    testDisasm "f8df0000" "ldr.w r0, [0x4]"
    testDisasm "5888bf00" "ldr r0, [r1, r2]"

  /// A8.8.68 LDRB (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.68 LDRB``() =
    testDisasm "78c8bf00" "ldrb r0, [r1, #0x3]"
    testDisasm "f89f0002" "ldrb r0, [0x6]"
    testDisasm "5c88bf00" "ldrb r0, [r1, r2]"
    testDisasm "7808bf00" "ldrb r0, [r1]"

  /// A8.8.72 LDRBT
  [<TestMethod>]
  member _.``A8.8.72 LDRBT``() =
    testDisasm "f8110e00" "ldrbt r0, [r1]"
    testDisasm "f8110e03" "ldrbt r0, [r1, #0x3]"
    testDisasm "f8119e34" "ldrbt sb, [r1, #0x34]"
    testDisasm "f8119e00" "ldrbt sb, [r1]"

  /// A8.8.73 LDRD (immediate)
  [<TestMethod>]
  member _.``A8.8.73 LDRD``() =
    testDisasm "e9df0100" "ldrd r0, r1, [0x4]"
    testDisasm "e9d10100" "ldrd r0, r1, [r1]"
    testDisasm "e8710234" "ldrd r0, r2, [r1], #-0xd0"
    testDisasm "e8710934" "ldrd r0, sb, [r1], #-0xd0"

  /// A8.8.76 LDREX
  [<TestMethod>]
  member _.``A8.8.76 LDREX``() =
    testDisasm "e8510f00" "ldrex r0, [r1]"
    testDisasm "e8510f04" "ldrex r0, [r1, #0x10]"

  /// A8.8.77 LDREXB
  [<TestMethod>]
  member _.``A8.8.77 LDREXB``() =
    testDisasm "e8d10f4f" "ldrexb r0, [r1]"

  /// A8.8.78 LDREXD
  [<TestMethod>]
  member _.``A8.8.78 LDREXD``() =
    testDisasm "e8d1017f" "ldrexd r0, r1, [r1]"

  /// A8.8.79 LDREXH
  [<TestMethod>]
  member _.``A8.8.79 LDREXH``() =
    testDisasm "e8d10f5f" "ldrexh r0, [r1]"

  /// A8.8.80 LDRH (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.80 LDRH``() =
    testDisasm "8a08bf00" "ldrh r0, [r1, #0x10]"
    testDisasm "f8bf0002" "ldrh r0, [0x6]"
    testDisasm "5a88bf00" "ldrh r0, [r1, r2]"
    testDisasm "8808bf00" "ldrh r0, [r1]"

  /// A8.8.84 LDRHT
  [<TestMethod>]
  member _.``A8.8.84 LDRHT``() =
    testDisasm "f8310e00" "ldrht r0, [r1]"
    testDisasm "f8310e03" "ldrht r0, [r1, #0x3]"
    testDisasm "f8319e34" "ldrht sb, [r1, #0x34]"
    testDisasm "f8319e00" "ldrht sb, [r1]"

  /// A8.8.85 LDRSB (immediate)
  [<TestMethod>]
  member _.``A8.8.85 LDRSB``() =
    testDisasm "f9910007" "ldrsb r0, [r1, #0x7]"
    testDisasm "f99f0000" "ldrsb r0, [0x4]"
    testDisasm "5688bf00" "ldrsb r0, [r1, r2]"
    testDisasm "f9910000" "ldrsb r0, [r1]"

  /// A8.8.88 LDRSBT
  [<TestMethod>]
  member _.``A8.8.88 LDRSBT``() =
    testDisasm "f9110e00" "ldrsbt r0, [r1]"
    testDisasm "f9110e03" "ldrsbt r0, [r1, #0x3]"
    testDisasm "f9119e34" "ldrsbt sb, [r1, #0x34]"
    testDisasm "f9119e00" "ldrsbt sb, [r1]"

  /// A8.8.89 LDRSH (immediate)
  [<TestMethod>]
  member _.``A8.8.89 LDRSH``() =
    testDisasm "f9b10007" "ldrsh r0, [r1, #0x7]"
    testDisasm "f9bf0002" "ldrsh r0, [0x6]"
    testDisasm "5e88bf00" "ldrsh r0, [r1, r2]"
    testDisasm "f9b10000" "ldrsh r0, [r1]"

  /// A8.8.92 LDRSHT
  [<TestMethod>]
  member _.``A8.8.92 LDRSHT``() =
    testDisasm "f9310e00" "ldrsht r0, [r1]"
    testDisasm "f9310e03" "ldrsht r0, [r1, #0x3]"
    testDisasm "f9319e34" "ldrsht sb, [r1, #0x34]"
    testDisasm "f9319e00" "ldrsht sb, [r1]"

  /// A8.8.93 LDRT
  [<TestMethod>]
  member _.``A8.8.93 LDRT``() =
    testDisasm "f8510e00" "ldrt r0, [r1]"
    testDisasm "f8510e03" "ldrt r0, [r1, #0x3]"
    testDisasm "f8519e34" "ldrt sb, [r1, #0x34]"
    testDisasm "f8519e00" "ldrt sb, [r1]"

  /// A8.8.95 LSL (immediate)
  [<TestMethod>]
  member _.``A8.8.95 LSL``() =
    testDisasm "fa00f002" "lsl r0, r0, r2"
    testDisasm "fa11f002" "lsls.w r0, r1, r2"
    testDisasm "4091bf00" "lsls r1, r2"
    testDisasm "01bf00" "lsls r7, r7, #0x6"

  /// A8.8.97 LSR (immediate)
  [<TestMethod>]
  member _.``A8.8.97 LSR``() =
    testDisasm "0c10bf00" "lsrs r0, r2, #0x10"
    testDisasm "fa20f002" "lsr r0, r0, r2"
    testDisasm "fa31f002" "lsrs.w r0, r1, r2"
    testDisasm "40d1bf00" "lsrs r1, r2"

  /// A8.8.99 MCR, MCR2
  [<TestMethod>]
  member _.``A8.8.99 MCR``() =
    testDisasm "ee010e34" "mcr p14, #0x0, r0, c1, c4, #0x1"
    testDisasm "ee019e34" "mcr p14, #0x0, sb, c1, c4, #0x1"
    testDisasm "ee01ae34" "mcr p14, #0x0, sl, c1, c4, #0x1"
    testDisasm "ee01be34" "mcr p14, #0x0, fp, c1, c4, #0x1"

  /// F5.1.1 ADC, ADCS (immediate)
  [<TestMethod>]
  member _.``F5.1.1 ADCS``() =
    testDisasm "eb510002" "adcs.w r0, r1, r2"
    testDisasm "4151bf00" "adcs r1, r1, r2"
    testDisasm "eb510034" "adcs r0, r1, r4, rrx"
    testDisasm "eb510010" "adcs.w r0, r1, r0, lsr #0x20"

  /// F5.1.101 LSLS (immediate)
  [<TestMethod>]
  member _.``F5.1.101 LSLS``() =
    testDisasm "fa11f002" "lsls.w r0, r1, r2"
    testDisasm "4091bf00" "lsls r1, r2"
    testDisasm "01bf00" "lsls r7, r7, #0x6"
    testDisasm "fa11f900" "lsls.w sb, r1, r0"

  /// F5.1.105 LSRS (immediate)
  [<TestMethod>]
  member _.``F5.1.105 LSRS``() =
    testDisasm "0c10bf00" "lsrs r0, r2, #0x10"
    testDisasm "fa31f002" "lsrs.w r0, r1, r2"
    testDisasm "40d1bf00" "lsrs r1, r2"
    testDisasm "fa31f900" "lsrs.w sb, r1, r0"

  /// F5.1.11 AND, ANDS (immediate)
  [<TestMethod>]
  member _.``F5.1.11 ANDS``() =
    testDisasm "f011407f" "ands r0, r1, #0xff000000"
    testDisasm "ea110002" "ands.w r0, r1, r2"
    testDisasm "4011bf00" "ands r1, r1, r2"
    testDisasm "ea110034" "ands r0, r1, r4, rrx"

  /// F5.1.111 MOV, MOVS (immediate)
  [<TestMethod>]
  member _.``F5.1.111 MOVS``() =
    testDisasm "f05f407f" "movs r0, #0xff000000"
    testDisasm "0010bf00" "movs r0, r2"
    testDisasm "ea5f0002" "movs.w r0, r2"
    testDisasm "ea5f0900" "movs.w sb, r0"

  /// F5.1.122 MUL, MULS
  [<TestMethod>]
  member _.``F5.1.122 MULS``() =
    testDisasm "4340bf00" "muls r0, r0, r0"

  /// F5.1.123 MVN, MVNS (immediate)
  [<TestMethod>]
  member _.``F5.1.123 MVNS``() =
    testDisasm "f07f407f" "mvns r0, #0xff000000"
    testDisasm "43d0bf00" "mvns r0, r2"
    testDisasm "ea7f0002" "mvns.w r0, r2"
    testDisasm "ea7f0034" "mvns r0, r4, rrx"

  /// F5.1.127 ORN, ORNS (immediate)
  [<TestMethod>]
  member _.``F5.1.127 ORNS``() =
    testDisasm "f071407f" "orns r0, r1, #0xff000000"
    testDisasm "ea710002" "orns r0, r1, r2"
    testDisasm "ea710034" "orns r0, r1, r4, rrx"
    testDisasm "ea710010" "orns r0, r1, r0, lsr #0x20"

  /// F5.1.129 ORR, ORRS (immediate)
  [<TestMethod>]
  member _.``F5.1.129 ORRS``() =
    testDisasm "f051407f" "orrs r0, r1, #0xff000000"
    testDisasm "ea510002" "orrs.w r0, r1, r2"
    testDisasm "4311bf00" "orrs r1, r1, r2"
    testDisasm "ea510034" "orrs r0, r1, r4, rrx"

  /// F5.1.132 PKHBT, PKHTB
  [<TestMethod>]
  member _.``F5.1.132 PKHBT``() =
    testDisasm "eac11002" "pkhbt r0, r1, r2, lsl #0x4"
    testDisasm "eac10000" "pkhbt r0, r1, r0"
    testDisasm "eac10900" "pkhbt sb, r1, r0"
    testDisasm "eac109c1" "pkhbt sb, r1, r1, lsl #0x3"

  /// F5.1.132 PKHBT, PKHTB
  [<TestMethod>]
  member _.``F5.1.132 PKHTB``() =
    testDisasm "eac11022" "pkhtb r0, r1, r2, asr #0x4"
    testDisasm "eac109e1" "pkhtb sb, r1, r1, asr #0x3"
    testDisasm "eac10ae1" "pkhtb sl, r1, r1, asr #0x3"
    testDisasm "eac10be1" "pkhtb fp, r1, r1, asr #0x3"

  /// F5.1.141 PSSBB
  [<TestMethod>]
  member _.``F5.1.141 PSSBB``() =
    testDisasm "f3bf8f44" "pssbb"

  /// F5.1.159 RFE, RFEDA, RFEDB, RFEIA, RFEIB
  [<TestMethod>]
  member _.``F5.1.159 RFEDB``() =
    testDisasm "e831c000" "rfedb r1!"

  /// F5.1.159 RFE, RFEDA, RFEDB, RFEIA, RFEIB
  [<TestMethod>]
  member _.``F5.1.159 RFEIA``() =
    testDisasm "e991c000" "rfeia r1"

  /// F5.1.16 ASRS (immediate)
  [<TestMethod>]
  member _.``F5.1.16 ASRS``() =
    testDisasm "1410bf00" "asrs r0, r2, #0x10"
    testDisasm "fa51f002" "asrs.w r0, r1, r2"
    testDisasm "4111bf00" "asrs r1, r2"
    testDisasm "fa51f900" "asrs.w sb, r1, r0"

  /// F5.1.162 RORS (immediate)
  [<TestMethod>]
  member _.``F5.1.162 RORS``() =
    testDisasm "fa71f002" "rors.w r0, r1, r2"
    testDisasm "41d1bf00" "rors r1, r2"
    testDisasm "fa71f900" "rors.w sb, r1, r0"
    testDisasm "fa71fa00" "rors.w sl, r1, r0"

  /// F5.1.165 RRXS
  [<TestMethod>]
  member _.``F5.1.165 RRXS``() =
    testDisasm "ea5f0032" "rrxs r0, r2"
    testDisasm "ea5f0034" "rrxs r0, r4"
    testDisasm "ea5f0031" "rrxs r0, r1"
    testDisasm "ea5f0134" "rrxs r1, r4"

  /// F5.1.166 RSB, RSBS (immediate)
  [<TestMethod>]
  member _.``F5.1.166 RSBS``() =
    testDisasm "f1d1407f" "rsbs r0, r1, #0xff000000"
    testDisasm "ebd10002" "rsbs r0, r1, r2"
    testDisasm "ebd10034" "rsbs r0, r1, r4, rrx"
    testDisasm "ebd10010" "rsbs r0, r1, r0, lsr #0x20"

  /// F5.1.175 SB
  [<TestMethod>]
  member _.``F5.1.175 SB``() =
    testDisasm "f171407f" "sbcs r0, r1, #0xff000000"
    testDisasm "eb710002" "sbcs.w r0, r1, r2"
    testDisasm "4191bf00" "sbcs r1, r1, r2"
    testDisasm "eb710034" "sbcs r0, r1, r4, rrx"

  /// F5.1.176 SBC, SBCS (immediate)
  [<TestMethod>]
  member _.``F5.1.176 SBCS``() =
    testDisasm "f171407f" "sbcs r0, r1, #0xff000000"
    testDisasm "eb710002" "sbcs.w r0, r1, r2"
    testDisasm "4191bf00" "sbcs r1, r1, r2"
    testDisasm "eb710034" "sbcs r0, r1, r4, rrx"

  /// F5.1.183 SETPAN
  [<TestMethod>]
  member _.``F5.1.183 SETPAN``() =
    testDisasm "b610bf00" "setpan #0x0"

  /// F5.1.185 SEVL
  [<TestMethod>]
  member _.``F5.1.185 SEVL``() =
    testDisasm "bf50bf00" "sevl"
