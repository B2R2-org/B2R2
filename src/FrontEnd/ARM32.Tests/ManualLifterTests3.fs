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
open B2R2.BinIR
open B2R2.FrontEnd.ARM32
open B2R2.FrontEnd.ARM32.Tests.ManualLifting

/// <summary>
/// One test for each instruction DDI0406C and DDI0487F.c describe, A8.8.304
/// VCMP to F5.1.52 ESB in the order of their sections. A value test runs a
/// word's lifting with IRRunner over inputs QEMU ran the word on (qemu-arm -cpu
/// max) and asserts what QEMU left. A structural test is for a word a user-mode
/// run cannot execute alone; its doc comment says what it checks, and its
/// expectation is the manual's.
/// </summary>
[<TestClass>]
type ManualLifterTests3() =
  /// <summary>
  /// A8.8.304 VCMP: vcmp.f32 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.304 VCMP``() =
    let inputs =
      [ [ D(0, 0xc0d000003fc00000UL); FPSCR 0x00000000u ]
        [ D(0, 0x40000000c0d00000UL); FPSCR 0x60000000u ]
        [ D(0, 0x3f0000007f800000UL); FPSCR 0x00000000u ] ]
    let outputs =
      [ [ FPSCR 0x20000000u ]
        [ FPSCR 0x80000000u ]
        [ FPSCR 0x20000000u ] ]
    check false "eeb40a60" inputs outputs

  /// <summary>
  /// A8.8.304 VCMPE: vcmpe.f32 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.304 VCMPE``() =
    let inputs =
      [ [ D(0, 0x414000003e000000UL); FPSCR 0x00000000u ]
        [ D(0, 0x40c0000040000000UL); FPSCR 0x60000000u ]
        [ D(0, 0x7f80000080000000UL); FPSCR 0x00000000u ] ]
    let outputs =
      [ [ FPSCR 0x80000000u ]
        [ FPSCR 0x80000000u ]
        [ FPSCR 0x80000000u ] ]
    check false "eeb40ae0" inputs outputs

  /// <summary>
  /// A8.8.305 VCNT: vcnt.8 q0, q1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.305 VCNT``() =
    let inputs =
      [ [ D(0, 0x08ba6cf3031fb354UL)
          D(1, 0xf8193ccb3569f65dUL)
          D(2, 0xf9c243798e1a6eabUL)
          D(3, 0xe71d3f623c3ca742UL) ]
        [ D(0, 0xb1a7e452c6c3ed3eUL)
          D(1, 0x90447b8b8d4af6b1UL)
          D(2, 0x42932e290c7cbe7cUL)
          D(3, 0x5b7a554cc015d8feUL) ]
        [ D(0, 0x00ff00ff00ff00ffUL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0x0102030405060708UL)
          D(3, 0xffffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x0603030504030505UL); D(1, 0x0604060304040502UL) ]
        [ D(0, 0x0204040302050605UL); D(1, 0x0505040302030407UL) ]
        [ D(0, 0x0101020102020301UL); D(1, 0x0808080808080808UL) ] ]
    check false "f3b00542" inputs outputs

  /// <summary>
  /// A8.8.306 VCVT: vcvt.f32.f64 s0, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.306 VCVT``() =
    let inputs =
      [ [ D(0, 0x4008000000000000UL)
          D(2, 0x4059200000000000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0xc002000000000000UL)
          D(2, 0xbff0000000000000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x8000000000000000UL)
          D(2, 0x3ff8000000000000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x4008000042c90000UL); FPSCR 0x00000000u ]
        [ D(0, 0xc0020000bf800000UL); FPSCR 0x60000000u ]
        [ D(0, 0x800000003fc00000UL); FPSCR 0x00000000u ] ]
    check false "eeb70bc2" inputs outputs

  /// <summary>
  /// A8.8.307 VCVTR: vcvtr.s32.f32 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.307 VCVTR``() =
    let inputs =
      [ [ D(0, 0x3d80000040e80000UL); FPSCR 0x00000000u ]
        [ D(0, 0xbf800000c0600000UL); FPSCR 0x60000000u ]
        [ D(0, 0x404000003f000000UL); FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x3d80000000000000UL); FPSCR 0x00000010u ]
        [ D(0, 0xbf800000ffffffffUL); FPSCR 0x60000000u ]
        [ D(0, 0x4040000000000003UL); FPSCR 0x00000000u ] ]
    check false "eebd0a60" inputs outputs

  /// <summary>
  /// A8.8.312 VCVTB: vcvtb.f32.f16 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.312 VCVTB``() =
    let inputs =
      [ [ D(0, 0x3a003a003e004400UL); FPSCR 0x00000000u ]
        [ D(0, 0x4a004600b600c200UL); FPSCR 0x60000000u ]
        [ D(0, 0x000042008000c080UL); FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x3a003a003f400000UL); FPSCR 0x00000000u ]
        [ D(0, 0x4a00460040c00000UL); FPSCR 0x60000000u ]
        [ D(0, 0x0000420040400000UL); FPSCR 0x00000000u ] ]
    check false "eeb20a60" inputs outputs

  /// <summary>
  /// A8.8.312 VCVTT: vcvtt.f32.f16 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.312 VCVTT``() =
    let inputs =
      [ [ D(0, 0x4a004740d2004600UL); FPSCR 0x00000000u ]
        [ D(0, 0x40004a00c3003e00UL); FPSCR 0x60000000u ]
        [ D(0, 0xfc003e00c0803e00UL); FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x4a00474041400000UL); FPSCR 0x00000000u ]
        [ D(0, 0x40004a0040000000UL); FPSCR 0x60000000u ]
        [ D(0, 0xfc003e00ff800000UL); FPSCR 0x00000000u ] ]
    check false "eeb20ae0" inputs outputs

  /// <summary>
  /// A8.8.313 VDIV: vdiv.f32 s0, s1, s2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.313 VDIV``() =
    let inputs =
      [ [ D(0, 0x3e0000003d800000UL)
          D(1, 0xc240000042c90000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0xbf80000040200000UL)
          D(1, 0xbf800000c0600000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x404000003f000000UL)
          D(1, 0x3fc0000000000000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x3e0000003aa3065eUL); FPSCR 0x00000010u ]
        [ D(0, 0xbf8000003e924925UL); FPSCR 0x60000010u ]
        [ D(0, 0x404000007f800000UL); FPSCR 0x00000002u ] ]
    check false "ee800a81" inputs outputs

  /// <summary>
  /// A8.8.314 VDUP: vdup.8 d0, r1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.314 VDUP``() =
    let inputs =
      [ [ Gpr(1, 0x2447aff9u); D(0, 0x06865995f3c3933bUL) ]
        [ Gpr(1, 0x834cb9e5u); D(0, 0xc9bb5f2c7cdedb74UL) ]
        [ Gpr(1, 0x00008000u); D(0, 0x8001800180018001UL) ] ]
    let outputs =
      [ [ D(0, 0xf9f9f9f9f9f9f9f9UL) ]
        [ D(0, 0xe5e5e5e5e5e5e5e5UL) ]
        [ D(0, 0x0000000000000000UL) ] ]
    check false "eec01b10" inputs outputs

  /// <summary>
  /// A8.8.316 VEOR: veor q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.316 VEOR``() =
    let inputs =
      [ [ D(0, 0x0267842d78c38535UL)
          D(1, 0xca321d5129e0208bUL)
          D(2, 0xaf44bffa1de8a818UL)
          D(3, 0x491f525966285a1fUL)
          D(4, 0xab577f3bad25a837UL)
          D(5, 0xaed3c74a515ba094UL) ]
        [ D(0, 0x31ee508c7090436eUL)
          D(1, 0xe1963a3ea98e88ceUL)
          D(2, 0x10882e5951e36f10UL)
          D(3, 0xb1e83987cd76c196UL)
          D(4, 0x8b5f3900d4946de2UL)
          D(5, 0x6492b8c8aafb7658UL) ]
        [ D(0, 0x0000000000000001UL)
          D(1, 0x0000000000000001UL)
          D(2, 0x7fffffffffffffffUL)
          D(3, 0x0102030405060708UL)
          D(4, 0x8000000000000000UL)
          D(5, 0xffffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x0413c0c1b0cd002fUL); D(1, 0xe7cc95133773fa8bUL) ]
        [ D(0, 0x9bd71759857702f2UL); D(1, 0xd57a814f678db7ceUL) ]
        [ D(0, 0xffffffffffffffffUL); D(1, 0xfefdfcfbfaf9f8f7UL) ] ]
    check false "f3020154" inputs outputs

  /// <summary>
  /// A8.8.317 VEXT: vext.8 q0, q0, q1, #0x1. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.317 VEXT``() =
    let inputs =
      [ [ D(0, 0x51da26db469e0ccbUL)
          D(1, 0x69e12900a46377eeUL)
          D(2, 0x944bb4acf895ac8cUL)
          D(3, 0x6df64de0db4c0d71UL) ]
        [ D(0, 0xe31c5dea357cdd5eUL)
          D(1, 0xcec45037fc797bb0UL)
          D(2, 0x2e7c7c60275dc8d1UL)
          D(3, 0xfd0e7eff8ba0e880UL) ]
        [ D(0, 0x8000000000000000UL)
          D(1, 0x0102030405060708UL)
          D(2, 0x0000000000000001UL)
          D(3, 0x7fffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0xee51da26db469e0cUL); D(1, 0x8c69e12900a46377UL) ]
        [ D(0, 0xb0e31c5dea357cddUL); D(1, 0xd1cec45037fc797bUL) ]
        [ D(0, 0x0880000000000000UL); D(1, 0x0101020304050607UL) ] ]
    check false "f2b00142" inputs outputs

  /// <summary>
  /// A8.8.318 VFMA: vfma.f32 s0, s1, s2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.318 VFMA``() =
    let inputs =
      [ [ D(0, 0xbec000003d800000UL)
          D(1, 0x41400000bf000000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x414000003fe00000UL)
          D(1, 0x3fe0000041200000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x7f80000080000000UL)
          D(1, 0xc01000003f000000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xbec000003e800000UL); FPSCR 0x00000000u ]
        [ D(0, 0x4140000042f38000UL); FPSCR 0x60000000u ]
        [ D(0, 0x7f8000007f800000UL); FPSCR 0x00000000u ] ]
    check false "eea00a81" inputs outputs

  /// <summary>
  /// A8.8.318 VFMS: vfms.f32 s0, s1, s2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.318 VFMS``() =
    let inputs =
      [ [ D(0, 0xc0600000c2400000UL)
          D(1, 0x3fc0000044800000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x40c00000c0400000UL)
          D(1, 0xbec0000042c90000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x3f00000080000000UL)
          D(1, 0x4040000000000000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xc0600000455d0000UL); FPSCR 0x00000000u ]
        [ D(0, 0x40c00000c4178000UL); FPSCR 0x60000000u ]
        [ D(0, 0x3f00000080000000UL); FPSCR 0x00000000u ] ]
    check false "eea00ac1" inputs outputs

  /// <summary>
  /// A8.8.319 VFNMA: vfnma.f32 s0, s1, s2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.319 VFNMA``() =
    let inputs =
      [ [ D(0, 0xc060000040200000UL)
          D(1, 0x412000003fc00000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x3fc00000bf800000UL)
          D(1, 0xc06000003e800000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x7f800000c0100000UL)
          D(1, 0x40400000c0100000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xc060000040300000UL); FPSCR 0x00000000u ]
        [ D(0, 0x3fc000003f200000UL); FPSCR 0x60000000u ]
        [ D(0, 0x7f8000007f800000UL); FPSCR 0x00000000u ] ]
    check false "ee900ac1" inputs outputs

  /// <summary>
  /// A8.8.319 VFNMS: vfnms.f32 s0, s1, s2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.319 VFNMS``() =
    let inputs =
      [ [ D(0, 0x3d800000c0100000UL)
          D(1, 0xc040000040800000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x44800000c0600000UL)
          D(1, 0x412000003f400000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0xc0100000ff800000UL)
          D(1, 0x3fc0000080000000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x3d80000040200000UL); FPSCR 0x00000000u ]
        [ D(0, 0x448000004440e000UL); FPSCR 0x60000000u ]
        [ D(0, 0xc01000007f800000UL); FPSCR 0x00000000u ] ]
    check false "ee900a81" inputs outputs

  /// <summary>
  /// A8.8.320 VHADD: vhadd.s8 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.320 VHADD``() =
    let inputs =
      [ [ D(0, 0xf3ff4fa143e2db51UL)
          D(1, 0xf2b07aea1bf4407eUL)
          D(2, 0xa4ddaec7fee0d4a0UL)
          D(3, 0x380cdef7584cc00cUL)
          D(4, 0x7f0a6471411284b9UL)
          D(5, 0xfac0a4fdf01203b5UL) ]
        [ D(0, 0xe201276e926fe205UL)
          D(1, 0xdc1049e3465edd74UL)
          D(2, 0x48cf306d367c3e6cUL)
          D(3, 0x9c65a4142ace0c5fUL)
          D(4, 0x843ed809c89aa457UL)
          D(5, 0xe6f0c44b5d7cbb5aUL) ]
        [ D(0, 0xffffffffffffffffUL)
          D(1, 0x7fffffffffffffffUL)
          D(2, 0x8001800180018001UL)
          D(3, 0x8000000000000000UL)
          D(4, 0x8000000000000000UL)
          D(5, 0x7fffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x11f3091c1ff9acacUL); D(1, 0x19e6c1fa242fe1e0UL) ]
        [ D(0, 0xe606043bff0bf161UL); D(1, 0xc12ab42f4325e35cUL) ]
        [ D(0, 0x8000c000c000c000UL); D(1, 0xffffffffffffffffUL) ] ]
    check false "f2020044" inputs outputs

  /// <summary>
  /// A8.8.320 VHSUB: vhsub.s8 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.320 VHSUB``() =
    let inputs =
      [ [ D(0, 0xc11ca04a92f75cc9UL)
          D(1, 0xcf55930657711301UL)
          D(2, 0xe461c2da322208d3UL)
          D(3, 0x4c189f5161cf3f18UL)
          D(4, 0x8307e27b4ba95d38UL)
          D(5, 0xd3628b5a2b5ce1f3UL) ]
        [ D(0, 0x6401ca788da8a261UL)
          D(1, 0x37b01f7fcf4d02beUL)
          D(2, 0xf57b7774a9fdfdedUL)
          D(3, 0xadb9412872bf3201UL)
          D(4, 0x31ef53bd1188a703UL)
          D(5, 0xbdfbaaa3ce926878UL) ]
        [ D(0, 0x0102030405060708UL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0x8001800180018001UL)
          D(3, 0x8000000000000000UL)
          D(4, 0x8001800180018001UL)
          D(5, 0x0000000000000001UL) ] ]
    let outputs =
      [ [ D(0, 0x302df0aff33cd5cdUL); D(1, 0x3cdb0afb1bb92f12UL) ]
        [ D(0, 0xe246125bcc3a2bf5UL); D(1, 0xf8df4b425216e5c4UL) ]
        [ D(0, 0x0000000000000000UL); D(1, 0xc0000000000000ffUL) ] ]
    check false "f2020244" inputs outputs

  /// <summary>
  /// A8.8.321 VLD1: vld1.8 {d0}, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.321 VLD1``() =
    let inputs =
      [ [ Gpr(1, 0x20000810u)
          D(0, 0xf29182db8de23a75UL)
          M(0, 0x287e27533cfb21d3UL)
          M(8, 0x15647879dfaacfcbUL)
          M(16, 0x75275800b6ee1375UL)
          M(24, 0x7102829825835242UL)
          M(32, 0x332e01d7a68bf8d8UL)
          M(40, 0x5703018c9463b557UL)
          M(48, 0x4226bd0d5cd3a6ceUL)
          M(56, 0x491c46055ee775b3UL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x74dd1bd73ee81118UL)
          M(0, 0x748e93cdbf765745UL)
          M(8, 0x316b0ee34490d886UL)
          M(16, 0x8f014e9a7568cce0UL)
          M(24, 0xfa6265a8447446efUL)
          M(32, 0x659ff9061663ff78UL)
          M(40, 0x83fed3264b30ec2dUL)
          M(48, 0x129d5799b498c290UL)
          M(56, 0x3a7e8b4a8aa7144aUL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x8000000000000000UL)
          M(0, 0x6c4a40ce047a8155UL)
          M(8, 0x633d12919f8789aaUL)
          M(16, 0xa6e75709701b7af4UL)
          M(24, 0x8cb707efa4c06271UL)
          M(32, 0x909107d037254f03UL)
          M(40, 0x197f5f7a6eb2f13cUL)
          M(48, 0xf284c1981234953dUL)
          M(56, 0x49132993f11bf5baUL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000810u); D(0, 0x75275800b6ee1375UL) ]
        [ Gpr(1, 0x20000810u); D(0, 0x8f014e9a7568cce0UL) ]
        [ Gpr(1, 0x20000810u); D(0, 0xa6e75709701b7af4UL) ] ]
    check false "f421070f" inputs outputs

  /// <summary>
  /// A8.8.324 VLD2: vld2.8 {d0, d1}, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.324 VLD2``() =
    let inputs =
      [ [ Gpr(1, 0x20000810u)
          D(0, 0x952db694e26a5165UL)
          D(1, 0xa3d5d12d7ee59ac3UL)
          M(0, 0x05192f28f65b12c6UL)
          M(8, 0x5febb41a6b4d06aaUL)
          M(16, 0x65c27fe6030fd3c4UL)
          M(24, 0x0c1b283a45fe3007UL)
          M(32, 0xc264f0b3dc0714dbUL)
          M(40, 0xfa879bff62a6d542UL)
          M(48, 0x78b164e6fe1a371dUL)
          M(56, 0xd4d3421effbb56e0UL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0xaf870fb0fdd5dd6aUL)
          D(1, 0x297f07ffcef032e7UL)
          M(0, 0x11b0a1f290c7fb46UL)
          M(8, 0x701bf861270e3f66UL)
          M(16, 0xb979a1d118e6fa0bUL)
          M(24, 0xb84aa6e9514c7141UL)
          M(32, 0x3072c14cb5935e37UL)
          M(40, 0x97701b04a2c29196UL)
          M(48, 0xbd4dbd01778bc8daUL)
          M(56, 0x9b40a6d9a55b689dUL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x7f80ff00807fffffUL)
          D(1, 0xffffffffffffffffUL)
          M(0, 0xd4bdeb894bd54b81UL)
          M(8, 0x6e1b95962a4515d8UL)
          M(16, 0x9184f3ef56e26de5UL)
          M(24, 0x2a71a26b6b95b543UL)
          M(32, 0x01d7bb187684d85aUL)
          M(40, 0x488604ebe20acabbUL)
          M(48, 0x173be1bffa6dd90cUL)
          M(56, 0x6d887ca5cdc79ed5UL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000810u)
          D(0, 0x1b3afe07c2e60fc4UL)
          D(1, 0x0c284530657f03d3UL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x4ae94c4179d1e60bUL)
          D(1, 0xb8a65171b9a118faUL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x716b954384efe2e5UL)
          D(1, 0x2aa26bb591f3566dUL) ] ]
    check false "f421080f" inputs outputs

  /// <summary>
  /// A8.8.327 VLD3: vld3.8 {d0, d1, d2}, [r1]. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.327 VLD3``() =
    let inputs =
      [ [ Gpr(1, 0x20000810u)
          D(0, 0xe48a21e57b7ca134UL)
          D(1, 0x6f4785549973c2a5UL)
          D(2, 0x0458bc630ebb3b1aUL)
          M(0, 0x97b46f597a4c0176UL)
          M(8, 0x9e123d89cb7fcf55UL)
          M(16, 0x1d018e07b3d22a6fUL)
          M(24, 0x18c515226a2e8bbeUL)
          M(32, 0xdf863ae95250a8f7UL)
          M(40, 0x055d7ee2cda592e8UL)
          M(48, 0x31097f037a35ac9dUL)
          M(56, 0x4c86295b7ceb0a9bUL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0xf977f4b4491eee49UL)
          D(1, 0x512f6c88e0e55c6bUL)
          D(2, 0xbeb79ceb6c0eff5dUL)
          M(0, 0x0edd1b22c73e37c1UL)
          M(8, 0x6547cd9c962e7a08UL)
          M(16, 0x25c4de06b887831eUL)
          M(24, 0x0fb8a6131a81687aUL)
          M(32, 0x74a934174bf589c4UL)
          M(40, 0xf8411446996bbd37UL)
          M(48, 0xe5ce1a9887723857UL)
          M(56, 0x4529878a20af333fUL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x7f80ff00807fffffUL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0x7fffffffffffffffUL)
          M(0, 0xe3f7accfeb5cb856UL)
          M(8, 0x0dffa6d8606140feUL)
          M(16, 0xe6c51e21e9d2f0e6UL)
          M(24, 0xf8ea3574c6412e4aUL)
          M(32, 0xbd075e03924ae669UL)
          M(40, 0x79c40b52efb925d3UL)
          M(48, 0xad87285baf6ff53cUL)
          M(56, 0x516d10e7df8e4b4cUL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000810u)
          D(0, 0x3a5018228b01b36fUL)
          D(1, 0x8652f7152e1d072aUL)
          D(2, 0xdfe9a8c56abe8ed2UL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x34f50f1368c4b81eUL)
          D(1, 0xa94bc4a681250683UL)
          D(2, 0x741789b81a7ade87UL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x5e4af8742ec5e9e6UL)
          D(1, 0x0792693541e621f0UL)
          D(2, 0xbd03e6eac64a1ed2UL) ] ]
    check false "f421040f" inputs outputs

  /// <summary>
  /// A8.8.330 VLD4: vld4.8 {d0, d1, d2, d3}, [r1]. The outputs are what QEMU
  /// left after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.330 VLD4``() =
    let inputs =
      [ [ Gpr(1, 0x20000810u)
          D(0, 0xb2b817bd8f13d6e0UL)
          D(1, 0x0aa47df515a31af1UL)
          D(2, 0xcffe8ecbc79695e3UL)
          D(3, 0x16293101021a95cfUL)
          M(0, 0xfa7b4eed5507ed86UL)
          M(8, 0x4ef45c6714f7467dUL)
          M(16, 0x79927526a51bfe9cUL)
          M(24, 0x052b72007a62f07cUL)
          M(32, 0xe4779354b7d8bd1bUL)
          M(40, 0xf505b56436903c79UL)
          M(48, 0x1017111ba0e6208eUL)
          M(56, 0x5db928ac4f10ef3bUL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0xc0e5d3ba63048995UL)
          D(1, 0x30b993f964e79ee2UL)
          D(2, 0x35f251a2e4799f69UL)
          D(3, 0x2491db2680ffb839UL)
          M(0, 0x2e3547eb4c3c3cebUL)
          M(8, 0xa38d567510eaf326UL)
          M(16, 0x31f4e64a934c3719UL)
          M(24, 0xee3d5d0dff7afec5UL)
          M(32, 0x8b1008b0a8975582UL)
          M(40, 0xf122a28d88fb8cccUL)
          M(48, 0xbfaba2279982a1a8UL)
          M(56, 0x772268d787edb7f9UL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x0102030405060708UL)
          D(1, 0x7f80ff00807fffffUL)
          D(2, 0x8001800180018001UL)
          D(3, 0xffffffffffffffffUL)
          M(0, 0x2c99d169b47a3b98UL)
          M(8, 0x0d1a3b654b48e285UL)
          M(16, 0x3145ab8cf1b78c60UL)
          M(24, 0xe4174f2ef5d42ab2UL)
          M(32, 0x208dcfbdf855dd8bUL)
          M(40, 0x6fbf127e6a90db01UL)
          M(48, 0x79f444dbd791f8f7UL)
          M(56, 0x95bd2f7c19aaf8b0UL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000810u)
          D(0, 0x6479541b007c269cUL)
          D(1, 0xb53c93bd72f075feUL)
          D(2, 0x059077d82b62921bUL)
          D(3, 0xf536e4b7057a79a5UL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x8dccb0820dc54a19UL)
          D(1, 0xa28c08555dfee637UL)
          D(2, 0x22fb10973d7af44cUL)
          D(3, 0xf1888ba8eeff3193UL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x7e01bd8b2eb28c60UL)
          D(1, 0x12dbcfdd4f2aab8cUL)
          D(2, 0xbf908d5517d445b7UL)
          D(3, 0x6f6a20f8e4f531f1UL) ] ]
    check false "f421000f" inputs outputs

  /// <summary>
  /// A8.8.333 VLDM: vldmia r1, {d0, d1}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.333 VLDM``() =
    let inputs =
      [ [ Gpr(1, 0x20000818u)
          D(0, 0xcb6813eccef19e3fUL)
          D(1, 0xf4799afdc500e8ddUL)
          M(0, 0x7c815fc83f89d5dcUL)
          M(8, 0x0110c7a8a7d99f07UL)
          M(16, 0x25c3222beb6d7955UL)
          M(24, 0x24c64c73663798f7UL)
          M(32, 0x76ffced30bee1d2fUL)
          M(40, 0x3c517fe412a3f00fUL)
          M(48, 0xb054517e2aa4ecb1UL)
          M(56, 0x7bb3f7851fb04c5eUL) ]
        [ Gpr(1, 0x20000818u)
          D(0, 0x869fc8e6be15bc20UL)
          D(1, 0x57ecfd69040ae787UL)
          M(0, 0xf3ed8cce4dbb2bd7UL)
          M(8, 0x8dd22a0f084c3bf7UL)
          M(16, 0x2363912313d3f71bUL)
          M(24, 0xb355571a5324e0e5UL)
          M(32, 0x30f060f96e23b741UL)
          M(40, 0xca63b345a85b054aUL)
          M(48, 0x50cb2ffa403b5973UL)
          M(56, 0xcbb6a3718caa3192UL) ]
        [ Gpr(1, 0x20000818u)
          D(0, 0x00ff00ff00ff00ffUL)
          D(1, 0x7f80ff00807fffffUL)
          M(0, 0x3ccd22263bec8b59UL)
          M(8, 0xc8219001957b1a62UL)
          M(16, 0x80b07120c0d57240UL)
          M(24, 0x8db75f07e88ca8ccUL)
          M(32, 0x7f60c45d622fb81aUL)
          M(40, 0x52a5bcff73a10a21UL)
          M(48, 0x9c0889207d71c5d5UL)
          M(56, 0x5e0ce031502774fdUL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000818u)
          D(0, 0x24c64c73663798f7UL)
          D(1, 0x76ffced30bee1d2fUL) ]
        [ Gpr(1, 0x20000818u)
          D(0, 0xb355571a5324e0e5UL)
          D(1, 0x30f060f96e23b741UL) ]
        [ Gpr(1, 0x20000818u)
          D(0, 0x8db75f07e88ca8ccUL)
          D(1, 0x7f60c45d622fb81aUL) ] ]
    check false "ec910b04" inputs outputs

  /// <summary>
  /// A8.8.334 VLDR: vldr d0, [r1, #8]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.334 VLDR``() =
    let inputs =
      [ [ Gpr(1, 0x20000808u)
          D(0, 0x563e3b5bab720799UL)
          M(0, 0x129580f1379442daUL)
          M(8, 0xb85b7c4e449e0859UL)
          M(16, 0xbd4b871713d1da02UL)
          M(24, 0x103a7bac6591bf45UL)
          M(32, 0xc8288fe15ad4e857UL)
          M(40, 0x78954fae9f193240UL)
          M(48, 0x1ffecb2582629c64UL)
          M(56, 0x16d36e92b3d618afUL) ]
        [ Gpr(1, 0x20000808u)
          D(0, 0x77a137e4ff24eb4dUL)
          M(0, 0xdf925e443ee0b1c4UL)
          M(8, 0x90b6824aed8944b7UL)
          M(16, 0x3ef17a15840e842bUL)
          M(24, 0xeeb1c1fc73391cf0UL)
          M(32, 0xe583f8ff8777fcc1UL)
          M(40, 0xb6751a9d80fd5c68UL)
          M(48, 0x9597663ec49d3f8bUL)
          M(56, 0x2b6d451e202dc484UL) ]
        [ Gpr(1, 0x20000808u)
          D(0, 0xffffffffffffffffUL)
          M(0, 0xbad319c1dac0cb36UL)
          M(8, 0x8fab233b6e74554fUL)
          M(16, 0xa31a9ffdd70f0797UL)
          M(24, 0x9015ef2cb8d0c28aUL)
          M(32, 0xbb72b1d984c1ab21UL)
          M(40, 0x39ab3a636bd884c1UL)
          M(48, 0x1850a45f66628a22UL)
          M(56, 0x9623ba05be6142caUL) ] ]
    let outputs =
      [ [ D(0, 0xbd4b871713d1da02UL) ]
        [ D(0, 0x3ef17a15840e842bUL) ]
        [ D(0, 0xa31a9ffdd70f0797UL) ] ]
    check false "ed910b02" inputs outputs

  /// <summary>
  /// A8.8.335 VMAX: vmax.s8 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.335 VMAX``() =
    let inputs =
      [ [ D(0, 0x7bf3e3e4d04d2188UL)
          D(1, 0x72d5e856fe2d8d60UL)
          D(2, 0x8be3e07fa6edada0UL)
          D(3, 0x35d5b94b0f20b77fUL)
          D(4, 0xc1720a57472fe211UL)
          D(5, 0x1a03e6078cd9384fUL) ]
        [ D(0, 0xfc72af1a424c0afaUL)
          D(1, 0x53c793b1ea89a32aUL)
          D(2, 0x09ae625293d7dfa6UL)
          D(3, 0xf1b12801175dfc4aUL)
          D(4, 0x80343ed870a93fdbUL)
          D(5, 0x9cbdc760b01568d0UL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0x7f80ff00807fffffUL)
          D(2, 0x8001800180018001UL)
          D(3, 0x0102030405060708UL)
          D(4, 0x8000000000000000UL)
          D(5, 0x8001800180018001UL) ] ]
    let outputs =
      [ [ D(0, 0xc1720a7f472fe211UL); D(1, 0x3503e64b0f20387fUL) ]
        [ D(0, 0x0934625270d73fdbUL); D(1, 0xf1bd2860175d684aUL) ]
        [ D(0, 0x8001000100010001UL); D(1, 0x0102030405060708UL) ] ]
    check false "f2020644" inputs outputs

  /// <summary>
  /// A8.8.335 VMIN: vmin.s8 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.335 VMIN``() =
    let inputs =
      [ [ D(0, 0xc34eb6d5f9da95aeUL)
          D(1, 0xc4d3eb1094b8ffc0UL)
          D(2, 0x7c2e571ddc860403UL)
          D(3, 0x8dbb253af49df2bfUL)
          D(4, 0x0840ad52f4f2cca6UL)
          D(5, 0x6ced8a34490a1f03UL) ]
        [ D(0, 0x37a3d63f7953eb7dUL)
          D(1, 0x0e1a4675c924957eUL)
          D(2, 0x6cd7dedd299abe6dUL)
          D(3, 0xdeecf967c244bf11UL)
          D(4, 0x494f7be115cba6b7UL)
          D(5, 0x72881482b976e31dUL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0x7f80ff00807fffffUL)
          D(2, 0x0102030405060708UL)
          D(3, 0xffffffffffffffffUL)
          D(4, 0x0102030405060708UL)
          D(5, 0xffffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x082ead1ddc86cca6UL); D(1, 0x8dbb8a34f49df2bfUL) ]
        [ D(0, 0x49d7dedd159aa6b7UL); D(1, 0xde88f982b944bf11UL) ]
        [ D(0, 0x0102030405060708UL); D(1, 0xffffffffffffffffUL) ] ]
    check false "f2020654" inputs outputs

  /// <summary>
  /// A8.8.337 VMLA: vmla.i8 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.337 VMLA``() =
    let inputs =
      [ [ D(0, 0xfadbdf52cfc5f391UL)
          D(1, 0x4f2f74e8f212d007UL)
          D(2, 0xc49c0aa4dd9605b4UL)
          D(3, 0xd672dcbf7cb4903bUL)
          D(4, 0x5767c1c8e9e48919UL)
          D(5, 0x65c5f9c9d0fd68afUL) ]
        [ D(0, 0xe935792274ac3fc7UL)
          D(1, 0x468b0d5a3e1b68e1UL)
          D(2, 0x951d095ae5d77841UL)
          D(3, 0x1347ee9129ec1a37UL)
          D(4, 0x20e95f2e84905213UL)
          D(5, 0xf9311c995bec5607UL) ]
        [ D(0, 0x0000000000000001UL)
          D(1, 0x7f80ff00807fffffUL)
          D(2, 0x7f80ff00807fffffUL)
          D(3, 0xffffffffffffffffUL)
          D(4, 0x0102030405060708UL)
          D(5, 0x0000000000000001UL) ] ]
    let outputs =
      [ [ D(0, 0x969f6972f45da025UL); D(1, 0xbde970dfb2f6505cUL) ]
        [ D(0, 0x899ad04e889caf9aUL); D(1, 0xc1221503d1ab2462UL) ]
        [ D(0, 0x7f00fd0080faf9f9UL); D(1, 0x7f80ff00807ffffeUL) ] ]
    check false "f2020944" inputs outputs

  /// <summary>
  /// A8.8.337 VMLAL: vmlal.s8 q0, d1, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.337 VMLAL``() =
    let inputs =
      [ [ D(0, 0xe594ea681f98275cUL)
          D(1, 0x3b51dc5b5b5b46caUL)
          D(2, 0xaffee423d5faa848UL) ]
        [ D(0, 0x61e6902866715754UL)
          D(1, 0xdd70f203fcc73b14UL)
          D(2, 0x62b0233ec6d27762UL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0x7fffffffffffffffUL)
          D(2, 0x00ff00ff00ff00ffUL) ] ]
    let outputs =
      [ [ D(0, 0xd64be8460788182cUL); D(1, 0x28a6dbb95f4b533bUL) ]
        [ D(0, 0x62ce9a6681de5efcUL); D(1, 0xd00acf03fadd3bceUL) ]
        [ D(0, 0x7f80ff01807f0000UL); D(1, 0x7fff0000ffff0000UL) ] ]
    check false "f2810802" inputs outputs

  /// <summary>
  /// A8.8.337 VMLS: vmls.i8 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.337 VMLS``() =
    let inputs =
      [ [ D(0, 0x99871de95292b276UL)
          D(1, 0xd1fc565256f60395UL)
          D(2, 0x183cd0710c9c20b0UL)
          D(3, 0x9326b74bcc267d43UL)
          D(4, 0x01b55d0cd2b37f48UL)
          D(5, 0x5be6b4798c48e6b7UL) ]
        [ D(0, 0x2817050a589c0adfUL)
          D(1, 0x0b9e5c582f273111UL)
          D(2, 0x13cc4d6c9baedc44UL)
          D(3, 0xbeb70b05f73762bdUL)
          D(4, 0xa74f9d97a2ae38e6UL)
          D(5, 0x2946681ef01f75b5UL) ]
        [ D(0, 0x8001800180018001UL)
          D(1, 0x00ff00ff00ff00ffUL)
          D(2, 0x8000000000000000UL)
          D(3, 0x0000000000000001UL)
          D(4, 0x7fffffffffffffffUL)
          D(5, 0x7fffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x811b8d9d7a7ed2f6UL); D(1, 0x90d8aadfc646b5b0UL) ]
        [ D(0, 0xc323cc564258eac7UL); D(1, 0x9d94e4c29f7e6770UL) ]
        [ D(0, 0x0001800180018001UL); D(1, 0x00ff00ff00ff0000UL) ] ]
    check false "f3020944" inputs outputs

  /// <summary>
  /// A8.8.337 VMLSL: vmlsl.s8 q0, d1, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.337 VMLSL``() =
    let inputs =
      [ [ D(0, 0xcb9d29275ba80ebdUL)
          D(1, 0xee88c1e1317c3dafUL)
          D(2, 0x0f0c152f7f8de425UL) ]
        [ D(0, 0xb1174050404f9210UL)
          D(1, 0x54112b5393249f70UL)
          D(2, 0x5bd43c9348eb1638UL) ]
        [ D(0, 0x8000000000000000UL)
          D(1, 0x0102030405060708UL)
          D(2, 0x7f80ff00807fffffUL) ] ]
    let outputs =
      [ [ D(0, 0xb34e60db62541a72UL); D(1, 0xef96c78136a74360UL) ]
        [ D(0, 0xcfbf434448a57990UL); D(1, 0x36352e3f8910c2c7UL) ]
        [ D(0, 0x8280fd0600070008UL); D(1, 0x0083040405090708UL) ] ]
    check false "f2810a02" inputs outputs

  /// <summary>
  /// A8.8.340 VMOV: vmov d0, r2, r3. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.340 VMOV``() =
    let inputs =
      [ [ Gpr(2, 0x26344926u); Gpr(3, 0xe8154720u); D(0, 0x789b450ddb5a3ee3UL) ]
        [ Gpr(2, 0xca5f649bu); Gpr(3, 0xd45b0fe9u); D(0, 0x40b74d74fb4e32dbUL) ]
        [ Gpr(2, 0x7fff8000u)
          Gpr(3, 0x00000000u)
          D(0, 0x8001800180018001UL) ] ]
    let outputs =
      [ [ D(0, 0xe815472026344926UL) ]
        [ D(0, 0xd45b0fe9ca5f649bUL) ]
        [ D(0, 0x000000007fff8000UL) ] ]
    check false "ec432b10" inputs outputs

  /// <summary>
  /// A8.8.347 VMOVL: vmovl.s32 q0, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.347 VMOVL``() =
    let inputs =
      [ [ D(0, 0x6b45e1cc0e9e4ba2UL)
          D(1, 0x414af6fb10ec1d86UL)
          D(2, 0x6407e173d41c1499UL) ]
        [ D(0, 0x2639b1fcae558314UL)
          D(1, 0xaeaba144258a1fbaUL)
          D(2, 0x2f2992c7de6fe87eUL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0x8001800180018001UL)
          D(2, 0x0102030405060708UL) ] ]
    let outputs =
      [ [ D(0, 0xffffffffd41c1499UL); D(1, 0x000000006407e173UL) ]
        [ D(0, 0xffffffffde6fe87eUL); D(1, 0x000000002f2992c7UL) ]
        [ D(0, 0x0000000005060708UL); D(1, 0x0000000001020304UL) ] ]
    check false "f2a00a12" inputs outputs

  /// <summary>
  /// A8.8.348 VMOVN: vmovn.i32 d0, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.348 VMOVN``() =
    let inputs =
      [ [ D(0, 0x673c8e3af726ace0UL)
          D(4, 0xe9b46dc666435f83UL)
          D(5, 0xabc30a907d005660UL) ]
        [ D(0, 0xd7c11a3243d857adUL)
          D(4, 0x9b64b8b1b41db136UL)
          D(5, 0x5cbe4245e0cf9a9bUL) ]
        [ D(0, 0x0000000000000001UL)
          D(4, 0x7fffffffffffffffUL)
          D(5, 0x7fffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x0a9056606dc65f83UL) ]
        [ D(0, 0x42459a9bb8b1b136UL) ]
        [ D(0, 0xffffffffffffffffUL) ] ]
    check false "f3b60204" inputs outputs

  /// <summary>
  /// A8.8.349 VMRS: vmrs r0, fpscr. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.349 VMRS``() =
    let inputs =
      [ [ Gpr(0, 0xa5c75178u); FPSCR 0x00000000u ]
        [ Gpr(0, 0x9f8c8148u); FPSCR 0x60000000u ]
        [ Gpr(0, 0x0000ffffu); FPSCR 0x00000000u ] ]
    let outputs =
      [ [ Gpr(0, 0x00000000u) ]
        [ Gpr(0, 0x60000000u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "eef10a10" inputs outputs

  /// <summary>
  /// A8.8.350 VMSR: vmsr fpscr, r0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.350 VMSR``() =
    let inputs =
      [ [ Gpr(0, 0x33ee013eu); FPSCR 0x00000000u ]
        [ Gpr(0, 0xd8b255adu); FPSCR 0x60000000u ]
        [ Gpr(0, 0x0000ffffu); FPSCR 0x00000000u ] ]
    let outputs =
      [ [ FPSCR 0x33ee001eu ]
        [ FPSCR 0xd8b2008du ]
        [ FPSCR 0x0000009fu ] ]
    check false "eee10a10" inputs outputs

  /// <summary>
  /// A8.8.351 VMUL: vmul.f32 s0, s1, s2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.351 VMUL``() =
    let inputs =
      [ [ D(0, 0xbec000003f400000UL)
          D(1, 0x40e8000040800000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0xc2400000c0600000UL)
          D(1, 0x3fc0000040800000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x3f0000003f000000UL)
          D(1, 0x404000003f000000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xbec00000bfc00000UL); FPSCR 0x00000000u ]
        [ D(0, 0xc2400000c3400000UL); FPSCR 0x60000000u ]
        [ D(0, 0x3f0000003e800000UL); FPSCR 0x00000000u ] ]
    check false "ee200a81" inputs outputs

  /// <summary>
  /// A8.8.351 VMULL: vmull.s8 q0, d1, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.351 VMULL``() =
    let inputs =
      [ [ D(0, 0xb670d5a902b493a4UL)
          D(1, 0xa73b80bb07e27609UL)
          D(2, 0x3429b17ecfd77564UL) ]
        [ D(0, 0xb7e8ea6f1f1ab9cdUL)
          D(1, 0x104099c4d7035d81UL)
          D(2, 0xd0c7ba57a83ddddeUL) ]
        [ D(0, 0x00ff00ff00ff00ffUL)
          D(1, 0x7f80ff00807fffffUL)
          D(2, 0x8001800180018001UL) ] ]
    let outputs =
      [ [ D(0, 0xfea904ce35ee0384UL); D(1, 0xedec09732780de0aUL) ]
        [ D(0, 0x0e1800b7f34910deUL); D(1, 0xfd00f1c01c2aeb9cUL) ]
        [ D(0, 0x4000007f0080ffffUL); D(1, 0xc080ff8000800000UL) ] ]
    check false "f2810c02" inputs outputs

  /// <summary>
  /// A8.8.354 VMVN: vmvn.i32 q0, #0x10. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.354 VMVN``() =
    let inputs =
      [ [ D(0, 0x41905544972ed968UL); D(1, 0xb580e69d93c70529UL) ]
        [ D(0, 0x09a2f32164ac1617UL); D(1, 0x5e8cfcc4d4b77a6cUL) ]
        [ D(0, 0x7f80ff00807fffffUL); D(1, 0x8001800180018001UL) ] ]
    let outputs =
      [ [ D(0, 0xffffffefffffffefUL); D(1, 0xffffffefffffffefUL) ]
        [ D(0, 0xffffffefffffffefUL); D(1, 0xffffffefffffffefUL) ]
        [ D(0, 0xffffffefffffffefUL); D(1, 0xffffffefffffffefUL) ] ]
    check false "f2810070" inputs outputs

  /// <summary>
  /// A8.8.356 VNEG: vneg.f32 s0, s2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.356 VNEG``() =
    let inputs =
      [ [ D(0, 0x4000000044800000UL); D(1, 0xbec0000044800000UL) ]
        [ D(0, 0x3d800000c0100000UL); D(1, 0x40e80000c0100000UL) ]
        [ D(0, 0x4040000040400000UL); D(1, 0xc01000003f000000UL) ] ]
    let outputs =
      [ [ D(0, 0x40000000c4800000UL) ]
        [ D(0, 0x3d80000040100000UL) ]
        [ D(0, 0x40400000bf000000UL) ] ]
    check false "eeb10a41" inputs outputs

  /// <summary>
  /// A8.8.357 VNMLA: vnmla.f32 s0, s1, s2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.357 VNMLA``() =
    let inputs =
      [ [ D(0, 0x3e80000040200000UL)
          D(1, 0x40000000bec00000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0xc06000003e000000UL)
          D(1, 0x3f40000040800000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x000000003f000000UL)
          D(1, 0x404000003fc00000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x3e800000c01a0000UL); FPSCR 0x00000000u ]
        [ D(0, 0xc0600000415e0000UL); FPSCR 0x60000000u ]
        [ D(0, 0x00000000bf000000UL); FPSCR 0x00000000u ] ]
    check false "ee100ac1" inputs outputs

  /// <summary>
  /// A8.8.357 VNMLS: vnmls.f32 s0, s1, s2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.357 VNMLS``() =
    let inputs =
      [ [ D(0, 0x42c9000041200000UL)
          D(1, 0x42c9000040000000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0xbec0000041400000UL)
          D(1, 0xbec0000041400000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x3f000000c0100000UL)
          D(1, 0x7f80000000000000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x42c90000433f0000UL); FPSCR 0x00000000u ]
        [ D(0, 0xbec00000c1840000UL); FPSCR 0x60000000u ]
        [ D(0, 0x3f00000040100000UL); FPSCR 0x00000000u ] ]
    check false "ee100a81" inputs outputs

  /// <summary>
  /// A8.8.357 VNMUL: vnmul.f32 s0, s1, s2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.357 VNMUL``() =
    let inputs =
      [ [ D(0, 0x4120000040800000UL)
          D(1, 0x404000003e800000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x3fc0000041400000UL)
          D(1, 0xc040000040200000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x800000003fc00000UL)
          D(1, 0x7f80000040400000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x41200000c0200000UL); FPSCR 0x00000000u ]
        [ D(0, 0x3fc00000c0700000UL); FPSCR 0x60000000u ]
        [ D(0, 0x8000000000000000UL); FPSCR 0x00000000u ] ]
    check false "ee200ac1" inputs outputs

  /// <summary>
  /// A8.8.358 VORN: vorn q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.358 VORN``() =
    let inputs =
      [ [ D(0, 0xfa08115855022c56UL)
          D(1, 0xcc6a78d43467d5a8UL)
          D(2, 0x5d77bf4b8d6a4718UL)
          D(3, 0x6bb16728c1bc3359UL)
          D(4, 0x285abc441d6c52f5UL)
          D(5, 0x886282ed80e362baUL) ]
        [ D(0, 0xed348accc4272f8aUL)
          D(1, 0x8a8c6365d6ff07eeUL)
          D(2, 0x1fea4cb17f8f9e67UL)
          D(3, 0x0982680e4b41201aUL)
          D(4, 0xc9c582ab1deb6e13UL)
          D(5, 0x641f0002da68ffa1UL) ]
        [ D(0, 0x8001800180018001UL)
          D(1, 0x7fffffffffffffffUL)
          D(2, 0x00ff00ff00ff00ffUL)
          D(3, 0x8001800180018001UL)
          D(4, 0x00ff00ff00ff00ffUL)
          D(5, 0x0102030405060708UL) ] ]
    let outputs =
      [ [ D(0, 0xdff7fffbeffbef1aUL); D(1, 0x7fbd7f3affbcbf5dUL) ]
        [ D(0, 0x3ffa7df5ff9f9fefUL); D(1, 0x9be2ffff6fd7205eUL) ]
        [ D(0, 0xffffffffffffffffUL); D(1, 0xfefdfcfbfaf9f8f7UL) ] ]
    check false "f2320154" inputs outputs

  /// <summary>
  /// A8.8.360 VORR: vorr.i32 q0, #0x10. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.360 VORR``() =
    let inputs =
      [ [ D(0, 0x2a68a8df16d5a64eUL); D(1, 0x1f093bd8790807f3UL) ]
        [ D(0, 0xb13e2170ebced17dUL); D(1, 0xd98cad61b263409fUL) ]
        [ D(0, 0x7fffffffffffffffUL); D(1, 0x0102030405060708UL) ] ]
    let outputs =
      [ [ D(0, 0x2a68a8df16d5a65eUL); D(1, 0x1f093bd8790807f3UL) ]
        [ D(0, 0xb13e2170ebced17dUL); D(1, 0xd98cad71b263409fUL) ]
        [ D(0, 0x7fffffffffffffffUL); D(1, 0x0102031405060718UL) ] ]
    check false "f2810150" inputs outputs

  /// <summary>
  /// A8.8.362 VPADAL: vpadal.s32 q0, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.362 VPADAL``() =
    let inputs =
      [ [ D(0, 0x532641a9d0c0504dUL)
          D(1, 0x5ebb46ec3069b759UL)
          D(4, 0x78fe6a56bdf007a9UL)
          D(5, 0x69770d34950b4593UL) ]
        [ D(0, 0x77bc3e7d93cd2365UL)
          D(1, 0x59656e1ae6ddf107UL)
          D(4, 0x9f57232460c17462UL)
          D(5, 0xec812e9730fa7f88UL) ]
        [ D(0, 0x8000000000000000UL)
          D(1, 0xffffffffffffffffUL)
          D(4, 0x8001800180018001UL)
          D(5, 0x0102030405060708UL) ] ]
    let outputs =
      [ [ D(0, 0x532641aa07aec24cUL); D(1, 0x5ebb46ec2eec0a20UL) ]
        [ D(0, 0x77bc3e7d93e5baebUL); D(1, 0x59656e1b04599f26UL) ]
        [ D(0, 0x7fffffff00030002UL); D(1, 0x0000000006080a0bUL) ] ]
    check false "f3b80644" inputs outputs

  /// <summary>
  /// A8.8.363 VPADD: vpadd.f32 d0, d1, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.363 VPADD``() =
    let inputs =
      [ [ D(0, 0xc0d000003fe00000UL)
          D(1, 0x4000000040400000UL)
          D(2, 0xbec000003d800000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x3e00000044800000UL)
          D(1, 0xc0400000bf800000UL)
          D(2, 0x3e80000044800000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x3f000000ff800000UL)
          D(1, 0x3f00000080000000UL)
          D(2, 0x000000007f800000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xbea0000040a00000UL); FPSCR 0x00000000u ]
        [ D(0, 0x44800800c0800000UL); FPSCR 0x60000000u ]
        [ D(0, 0x7f8000003f000000UL); FPSCR 0x00000000u ] ]
    check false "f3010d02" inputs outputs

  /// <summary>
  /// A8.8.363 VPADD, the integer forms: vpadd.i16 d0, d1, d2. The pairs of Dn
  /// fill the low half of Dd and the pairs of Dm the high half; the outputs are
  /// computed from the manual's Operation, over lanes at each extreme of their
  /// type.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.363 VPADD (integer)``() =
    let inputs =
      [ [ D(0, 0x5555555555555555UL)
          D(1, 0x80017ffe05fa7f80UL)
          D(2, 0x00ff01028081fe7fUL) ] ]
    check false "f2110b12" inputs [ [ D(0, 0x02017f00ffff857aUL) ] ]

  /// <summary>
  /// A8.8.365 VPADDL: vpaddl.s32 q0, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.365 VPADDL``() =
    let inputs =
      [ [ D(0, 0xdb04cc13dbc42314UL)
          D(1, 0xa9d6347d76f14cf4UL)
          D(4, 0x3dd1fd6135b81945UL)
          D(5, 0x6d183ef90909cf50UL) ]
        [ D(0, 0xf7aa3ce13b632526UL)
          D(1, 0xac339420a670a220UL)
          D(4, 0x330d81ff4ad4fc4dUL)
          D(5, 0x07f2ceb5e84175f3UL) ]
        [ D(0, 0x00ff00ff00ff00ffUL)
          D(1, 0x7f80ff00807fffffUL)
          D(4, 0x8000000000000000UL)
          D(5, 0x8000000000000000UL) ] ]
    let outputs =
      [ [ D(0, 0x00000000738a16a6UL); D(1, 0x0000000076220e49UL) ]
        [ D(0, 0x000000007de27e4cUL); D(1, 0xfffffffff03444a8UL) ]
        [ D(0, 0xffffffff80000000UL); D(1, 0xffffffff80000000UL) ] ]
    check false "f3b80244" inputs outputs

  /// <summary>
  /// A8.8.366 VPMAX: vpmax.f32 d0, d1, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.366 VPMAX``() =
    let inputs =
      [ [ D(0, 0xbf0000003fe00000UL)
          D(1, 0xc0100000bec00000UL)
          D(2, 0xc24000003d800000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x4000000042c90000UL)
          D(1, 0xc2400000c0600000UL)
          D(2, 0x40c0000040c00000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x0000000040400000UL)
          D(1, 0x0000000080000000UL)
          D(2, 0x3fc00000ff800000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x3d800000bec00000UL); FPSCR 0x00000000u ]
        [ D(0, 0x40c00000c0600000UL); FPSCR 0x60000000u ]
        [ D(0, 0x3fc0000000000000UL); FPSCR 0x00000000u ] ]
    check false "f3010f02" inputs outputs

  /// <summary>
  /// A8.8.366 VPMAX, the integer forms: vpmax.s8 d0, d1, d2; vpmax.s16 d0, d1,
  /// d2. The pairs of Dn fill the low half of Dd and the pairs of Dm the high
  /// half; the outputs are computed from the manual's Operation, over lanes at
  /// each extreme of their type.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.366 VPMAX (integer)``() =
    let inputs =
      [ [ D(0, 0x5555555555555555UL)
          D(1, 0x80017ffe05fa7f80UL)
          D(2, 0x00ff01028081fe7fUL) ] ]
    check false "f2010a02" inputs [ [ D(0, 0x0002817f017f057fUL) ] ]
    check false "f2110a02" inputs [ [ D(0, 0x0102fe7f7ffe7f80UL) ] ]

  /// <summary>
  /// A8.8.366 VPMIN: vpmin.f32 d0, d1, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.366 VPMIN``() =
    let inputs =
      [ [ D(0, 0x3fc000003e800000UL)
          D(1, 0xc0d000003fe00000UL)
          D(2, 0x3e000000bf800000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0xc0100000c0d00000UL)
          D(1, 0x4080000040e80000UL)
          D(2, 0xc0600000c0600000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x7f8000003fc00000UL)
          D(1, 0x8000000080000000UL)
          D(2, 0xc010000000000000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xbf800000c0d00000UL); FPSCR 0x00000000u ]
        [ D(0, 0xc060000040800000UL); FPSCR 0x60000000u ]
        [ D(0, 0xc010000080000000UL); FPSCR 0x00000000u ] ]
    check false "f3210f02" inputs outputs

  /// <summary>
  /// A8.8.366 VPMIN, the integer forms: vpmin.s8 d0, d1, d2; vpmin.u32 d0, d1,
  /// d2. The pairs of Dn fill the low half of Dd and the pairs of Dm the high
  /// half; the outputs are computed from the manual's Operation, over lanes at
  /// each extreme of their type.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.366 VPMIN (integer)``() =
    let inputs =
      [ [ D(0, 0x5555555555555555UL)
          D(1, 0x80017ffe05fa7f80UL)
          D(2, 0x00ff01028081fe7fUL) ] ]
    check false "f2010a12" inputs [ [ D(0, 0xff0180fe80fefa80UL) ] ]
    check false "f3210a12" inputs [ [ D(0, 0x00ff010205fa7f80UL) ] ]

  /// <summary>
  /// A8.8.368 VPOP: vldmia sp!, {d0, d1}. This checks that it loads D0 and D1
  /// from SP and moves SP up by sixteen. It is not a value test because it
  /// moves SP, which the run itself stands on.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.368 VPOP``() =
    let w = uint32 Window
    let d0, d1 = 0x1111111100000000UL, 0x3333333322222222UL
    let cells = [ M(16, d0); M(24, d1) ]
    let run = runWith false "ecbd0b04" cells [ Register.SP, w + 16u ]
    Assert.AreEqual(D(0, d0), run.After(D(0, 0UL)))
    Assert.AreEqual(D(1, d1), run.After(D(1, 0UL)))
    Assert.AreEqual(w + 32u, run.Reg Register.SP)

  /// <summary>
  /// A8.8.369 VPUSH: vstmdb sp!, {s0, s1, s2, s3}. This checks that it stores
  /// S0 to S3 below SP, in order, and moves SP down by sixteen. It is not a
  /// value test because it moves SP, which the run itself stands on.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.369 VPUSH``() =
    let w = uint32 Window
    let d0, d1 = 0x1111111100000000UL, 0x3333333322222222UL
    let cells = [ D(0, d0); D(1, d1); M(16, 0UL); M(24, 0UL) ]
    let run = runWith false "ed2d0a04" cells [ Register.SP, w + 32u ]
    Assert.AreEqual(M(16, d0), run.After(M(16, 0UL)))
    Assert.AreEqual(M(24, d1), run.After(M(24, 0UL)))
    Assert.AreEqual(w + 16u, run.Reg Register.SP)

  /// <summary>
  /// A8.8.370 VQABS: vqabs.s32 q0, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.370 VQABS``() =
    let inputs =
      [ [ D(0, 0x59daa02e49344175UL)
          D(1, 0x83612ebb30c256cfUL)
          D(4, 0x422b8ae4b88bcd56UL)
          D(5, 0x20e78bdfb64d369eUL)
          FPSCR 0x00000000u ]
        [ D(0, 0xbf594f116a28e30dUL)
          D(1, 0xeed0f7959c320b38UL)
          D(4, 0x6cc5e622542060e5UL)
          D(5, 0xf4e6d5380b6e0657UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x7fffffffffffffffUL)
          D(1, 0x0102030405060708UL)
          D(4, 0x7f80ff00807fffffUL)
          D(5, 0x00ff00ff00ff00ffUL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x422b8ae4477432aaUL)
          D(1, 0x20e78bdf49b2c962UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x6cc5e622542060e5UL)
          D(1, 0x0b192ac80b6e0657UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x7f80ff007f800001UL)
          D(1, 0x00ff00ff00ff00ffUL)
          FPSCR 0x00000000u ] ]
    check false "f3b80744" inputs outputs

  /// <summary>
  /// A8.8.371 VQADD: vqadd.s32 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.371 VQADD``() =
    let inputs =
      [ [ D(0, 0xe8a6f33abc6915f3UL)
          D(1, 0xa3110ddee7334becUL)
          D(2, 0xf5cba359b577378dUL)
          D(3, 0x23a8fe33d30921fdUL)
          D(4, 0x7f54ed34bebcab51UL)
          D(5, 0x39945b1699dddbc5UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x15b95ad1738a0301UL)
          D(1, 0xd5c9ec76f48a7f6dUL)
          D(2, 0x535bae450945a539UL)
          D(3, 0x7d5dd7058606a03dUL)
          D(4, 0xac731efa03d6ef09UL)
          D(5, 0x1a156a1b5380ee6aUL)
          FPSCR 0x60000000u ]
        [ D(0, 0x8000000000000000UL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0x0000000000000001UL)
          D(3, 0x7fffffffffffffffUL)
          D(4, 0x00ff00ff00ff00ffUL)
          D(5, 0xffffffffffffffffUL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x7520908d80000000UL)
          D(1, 0x5d3d594980000000UL)
          FPSCR 0x08000000u ]
        [ D(0, 0xffcecd3f0d1c9442UL)
          D(1, 0x7fffffffd9878ea7UL)
          FPSCR 0x68000000u ]
        [ D(0, 0x00ff00ff00ff0100UL)
          D(1, 0x7ffffffefffffffeUL)
          FPSCR 0x00000000u ] ]
    check false "f2220054" inputs outputs

  /// <summary>
  /// A8.8.372 VQDMLAL: vqdmlal.s16 q0, d1, d2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.372 VQDMLAL``() =
    let inputs =
      [ [ D(0, 0x98773d68edab7b2fUL)
          D(1, 0x71a573da64c6b3bcUL)
          D(2, 0x2a0170f40c60295aUL)
          FPSCR 0x00000000u ]
        [ D(0, 0xd85a68ac6021cbbcUL)
          D(1, 0xb666382a7e889fd6UL)
          D(2, 0x3d92476beb95f8f6UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0xffffffffffffffffUL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xa23561e8d508135fUL)
          D(1, 0x7fffffff7fffffffUL)
          FPSCR 0x08000000u ]
        [ D(0, 0xc42b62fc656b9b04UL)
          D(1, 0x92fee0827fffffffUL)
          FPSCR 0x68000000u ]
        [ D(0, 0x7f80ff0280800001UL)
          D(1, 0x0000000100000001UL)
          FPSCR 0x00000000u ] ]
    check false "f2910902" inputs outputs

  /// <summary>
  /// A8.8.372 VQDMLSL: vqdmlsl.s16 q0, d1, d2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.372 VQDMLSL``() =
    let inputs =
      [ [ D(0, 0xc9595dc3281d5cffUL)
          D(1, 0x97b539ec250ad876UL)
          D(2, 0x36b7868a6de5f0ffUL)
          FPSCR 0x00000000u ]
        [ D(0, 0x2a550e0baf852f13UL)
          D(1, 0x4b3841206c884a3aUL)
          D(2, 0x1b93843d7ba0b8d6UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0x7f80ff00807fffffUL)
          D(2, 0x7f80ff00807fffffUL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xa98c95df237ae1ebUL)
          D(1, 0xc449f9265c015606UL)
          FPSCR 0x00000000u ]
        [ D(0, 0xc182b40bd8c9b61bUL)
          D(1, 0x3b040ed07fffffffUL)
          FPSCR 0x68000000u ]
        [ D(0, 0x007e80fe807ffffdUL)
          D(1, 0x00807f00807dffffUL)
          FPSCR 0x00000000u ] ]
    check false "f2910b02" inputs outputs

  /// <summary>
  /// A8.8.373 VQDMULH: vqdmulh.s32 q0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.373 VQDMULH``() =
    let inputs =
      [ [ D(0, 0x3afe8916228e6a8dUL)
          D(1, 0x04a69c18c8f74e07UL)
          D(2, 0x8906d23f87a43584UL)
          D(3, 0xf3ad24c7b4821937UL)
          D(4, 0xa0e1aa7a35043cc3UL)
          D(5, 0x073173fce1e56c6eUL)
          FPSCR 0x00000000u ]
        [ D(0, 0xffc11bebf137c3d7UL)
          D(1, 0x22b3907a98bfbbf7UL)
          D(2, 0x1a00115cf06e75bcUL)
          D(3, 0x490128d8dddfba9dUL)
          D(4, 0x221793171098095dUL)
          D(5, 0xf9ae12ead05fd393UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x00ff00ff00ff00ffUL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0x0000000000000001UL)
          D(3, 0x8000000000000000UL)
          D(4, 0x8000000000000000UL)
          D(5, 0x0000000000000001UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x586921d9ce260227UL)
          D(1, 0xff4eb52011c12eb2UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x06ecce80fdfb50bfUL)
          D(1, 0xfc6538210cb28da9UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x0000000000000000UL)
          D(1, 0x0000000000000000UL)
          FPSCR 0x00000000u ] ]
    check false "f2220b44" inputs outputs

  /// <summary>
  /// A8.8.374 VQDMULL: vqdmull.s32 q0, d1, d2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.374 VQDMULL``() =
    let inputs =
      [ [ D(0, 0x3bc6e64e4d679eeaUL)
          D(1, 0xd9d8cd7c01410d16UL)
          D(2, 0xfe0de0b203503b44UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x65b551cc326fafe3UL)
          D(1, 0xf23e3b988b21275cUL)
          D(2, 0x9a3c5f43ffbf5841UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x8001800180018001UL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0x7f80ff00807fffffUL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x00084f8b585717b0UL)
          D(1, 0x009479d547aec070UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x003b0895752d3cb8UL)
          D(1, 0x0aefeb71cc0e0190UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x00000000ff000002UL)
          D(1, 0xffffffff00fe0200UL)
          FPSCR 0x00000000u ] ]
    check false "f2a10d02" inputs outputs

  /// <summary>
  /// A8.8.375 VQMOVN: vqmovn.s16 d0, q1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.375 VQMOVN``() =
    let inputs =
      [ [ D(0, 0x23d808ce18157c75UL)
          D(2, 0x55c9b2c8e8059596UL)
          D(3, 0xeb30af4c3705b91bUL)
          FPSCR 0x00000000u ]
        [ D(0, 0x8ca58b8ed7c4886dUL)
          D(2, 0x97ba240e233fc97aUL)
          D(3, 0x3fddc01e84491c5eUL)
          FPSCR 0x60000000u ]
        [ D(0, 0x7fffffffffffffffUL)
          D(2, 0x0000000000000001UL)
          D(3, 0x00ff00ff00ff00ffUL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x80807f807f808080UL); FPSCR 0x08000000u ]
        [ D(0, 0x7f80807f807f7f80UL); FPSCR 0x68000000u ]
        [ D(0, 0x7f7f7f7f00000001UL); FPSCR 0x08000000u ] ]
    check false "f3b20282" inputs outputs

  /// <summary>
  /// A8.8.375 VQMOVUN: vqmovun.s16 d0, q1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.375 VQMOVUN``() =
    let inputs =
      [ [ D(0, 0x70459ef4909004aaUL)
          D(2, 0x73ce40f9257ec817UL)
          D(3, 0x3f418505cd01d469UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x643e9c2cd44deee9UL)
          D(2, 0xa9b180ec3e9a1064UL)
          D(3, 0x9ae201291cdb2594UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x0000000000000001UL)
          D(2, 0x0102030405060708UL)
          D(3, 0x0000000000000001UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xff000000ffffff00UL); FPSCR 0x08000000u ]
        [ D(0, 0x00ffffff0000ffffUL); FPSCR 0x68000000u ]
        [ D(0, 0x00000001ffffffffUL); FPSCR 0x08000000u ] ]
    check false "f3b20242" inputs outputs

  /// <summary>
  /// A8.8.376 VQNEG: vqneg.s32 q0, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.376 VQNEG``() =
    let inputs =
      [ [ D(0, 0xc3f057737ea51493UL)
          D(1, 0xd476dda43a34bd4aUL)
          D(4, 0x2c16e94dc4376c72UL)
          D(5, 0xcbf0fdbb3135bce5UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x2a35d5c74d79e6c2UL)
          D(1, 0x496b87030b39aea4UL)
          D(4, 0xd7366acbc78a3896UL)
          D(5, 0x40c3cc0e8c7ab06fUL)
          FPSCR 0x60000000u ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0x8001800180018001UL)
          D(4, 0x8000000000000000UL)
          D(5, 0x0102030405060708UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xd3e916b33bc8938eUL)
          D(1, 0x340f0245ceca431bUL)
          FPSCR 0x00000000u ]
        [ D(0, 0x28c995353875c76aUL)
          D(1, 0xbf3c33f273854f91UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x7fffffff00000000UL)
          D(1, 0xfefdfcfcfaf9f8f8UL)
          FPSCR 0x08000000u ] ]
    check false "f3b807c4" inputs outputs

  /// <summary>
  /// A8.8.377 VQRDMULH: vqrdmulh.s32 q0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.377 VQRDMULH``() =
    let inputs =
      [ [ D(0, 0x709b9e841ac9f4ccUL)
          D(1, 0xc5ea7bbc3d1df061UL)
          D(2, 0x98d4fdcc17fa3680UL)
          D(3, 0xf08c856fc1508ecfUL)
          D(4, 0xe2d14397cff74810UL)
          D(5, 0xb8939c0355e09c36UL)
          FPSCR 0x00000000u ]
        [ D(0, 0xd255bd82153c53cdUL)
          D(1, 0x08f5257160a1a2e2UL)
          D(2, 0x01d982a78af386a9UL)
          D(3, 0xb65bddd6f53168e2UL)
          D(4, 0x8c5eab7368032b8fUL)
          D(5, 0x6c6e69b5bb57a58bUL)
          FPSCR 0x60000000u ]
        [ D(0, 0x8001800180018001UL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0x8000000000000000UL)
          D(3, 0x8000000000000000UL)
          D(4, 0x8001800180018001UL)
          D(5, 0x00ff00ff00ff00ffUL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x178569d0f7008978UL)
          D(1, 0x089f237ed5f17f4fUL)
          FPSCR 0x00000000u ]
        [ D(0, 0xfe543fcfa0e2f74aUL)
          D(1, 0xc19dfd4e05cbf711UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x7ffe7fff00000000UL)
          D(1, 0xff00ff0100000000UL)
          FPSCR 0x00000000u ] ]
    check false "f3220b44" inputs outputs

  /// <summary>
  /// A8.8.378 VQRSHL: vqrshl.s8 q0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.378 VQRSHL``() =
    let inputs =
      [ [ D(0, 0xefaae4a5e8845254UL)
          D(1, 0xe3f0550038c80cd5UL)
          D(2, 0x3650e10728b8c899UL)
          D(3, 0xa41eb82cb8987e6fUL)
          D(4, 0xb6e316f1fa9e23adUL)
          D(5, 0xe94ac28cdc699f4fUL)
          FPSCR 0x00000000u ]
        [ D(0, 0x9347cbe0fb8c16d7UL)
          D(1, 0x3f704887d7016521UL)
          D(2, 0xa316a7427f296428UL)
          D(3, 0x0b74276f716133f1UL)
          D(4, 0x99a53766f9230be4UL)
          D(5, 0x2597c507f8edf5e5UL)
          FPSCR 0x60000000u ]
        [ D(0, 0xffffffffffffffffUL)
          D(1, 0x00ff00ff00ff00ffUL)
          D(2, 0x00ff00ff00ff00ffUL)
          D(3, 0x00ff00ff00ff00ffUL)
          D(4, 0x0000000000000001UL)
          D(5, 0x7fffffffffffffffUL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x0000800001008000UL)
          D(1, 0x007f00000080007fUL)
          FPSCR 0x08000000u ]
        [ D(0, 0x0000807f017f7f00UL)
          D(1, 0x7f00007f00000000UL)
          FPSCR 0x68000000u ]
        [ D(0, 0x00ff00ff00ff00feUL)
          D(1, 0x0000000000000000UL)
          FPSCR 0x00000000u ] ]
    check false "f2040552" inputs outputs

  /// <summary>
  /// A8.8.379 VQRSHRN: vqrshrn.s16 d0, q1, #0x1. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.379 VQRSHRN``() =
    let inputs =
      [ [ D(0, 0x2c7dfcca2e70d125UL)
          D(2, 0x4597463793294016UL)
          D(3, 0xa2422b5be9f38b6eUL)
          FPSCR 0x00000000u ]
        [ D(0, 0xa5643895b4f56516UL)
          D(2, 0x46ec049da3a437b9UL)
          D(3, 0xc28e4e8e8215d708UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x7fffffffffffffffUL)
          D(2, 0xffffffffffffffffUL)
          D(3, 0x8000000000000000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x807f80807f7f807fUL); FPSCR 0x08000000u ]
        [ D(0, 0x807f80807f7f807fUL); FPSCR 0x68000000u ]
        [ D(0, 0x8000000000000000UL); FPSCR 0x08000000u ] ]
    check false "f28f0952" inputs outputs

  /// <summary>
  /// A8.8.379 VQRSHRUN: vqrshrun.s16 d0, q1, #0x1. The outputs are what QEMU
  /// left after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.379 VQRSHRUN``() =
    let inputs =
      [ [ D(0, 0xb851b15478c29ac2UL)
          D(2, 0xf737437f5263266fUL)
          D(3, 0xefe957cdb57fedccUL)
          FPSCR 0x00000000u ]
        [ D(0, 0xf8e327fba026ab02UL)
          D(2, 0x0be717fb4654392eUL)
          D(3, 0x920650e52d30a309UL)
          FPSCR 0x60000000u ]
        [ D(0, 0xffffffffffffffffUL)
          D(2, 0x8001800180018001UL)
          D(3, 0x8001800180018001UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x00ff000000ffffffUL); FPSCR 0x08000000u ]
        [ D(0, 0x00ffff00ffffffffUL); FPSCR 0x68000000u ]
        [ D(0, 0x0000000000000000UL); FPSCR 0x08000000u ] ]
    check false "f38f0852" inputs outputs

  /// <summary>
  /// A8.8.380 VQSHL: vqshl.s8 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.380 VQSHL``() =
    let inputs =
      [ [ D(0, 0x86b6f75634a39e0cUL)
          D(1, 0x7b7770373c99c845UL)
          D(2, 0xd6fe785a9c7eff78UL)
          D(3, 0x64508ef01df5a093UL)
          D(4, 0xdc746519d3681b29UL)
          D(5, 0xbb16f5ff30fff92eUL)
          FPSCR 0x00000000u ]
        [ D(0, 0x979e9b36e44431f3UL)
          D(1, 0xc5eaa121cd1ff37eUL)
          D(2, 0xb8acfe50b41e9566UL)
          D(3, 0x183f7dda3f5fd8ecUL)
          D(4, 0xebb2ffa1dc35305bUL)
          D(5, 0x78f254dd6f320d76UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x00ff00ff00ff00ffUL)
          D(1, 0x0000000000000001UL)
          D(2, 0x8001800180018001UL)
          D(3, 0x8001800180018001UL)
          D(4, 0x7fffffffffffffffUL)
          D(5, 0x8000000000000000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xff807f7fff7f807fUL)
          D(1, 0x007ffff87ffaff80UL)
          FPSCR 0x08000000u ]
        [ D(0, 0xffffff00ff7f807fUL)
          D(1, 0x7f007fff7f7f8080UL)
          FPSCR 0x68000000u ]
        [ D(0, 0x8000c000c000c000UL)
          D(1, 0xff01800180018001UL)
          FPSCR 0x08000000u ] ]
    check false "f2040452" inputs outputs

  /// <summary>
  /// A8.8.381 VQSHLU: vqshlu.s8 q0, q1, #0x1. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.381 VQSHLU``() =
    let inputs =
      [ [ D(0, 0x76ea85eddbd63d9eUL)
          D(1, 0xa5eef923e2661208UL)
          D(2, 0x8ef345fea89f90e1UL)
          D(3, 0x1ed13f77a08dafd5UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x0e0cc69e51810b80UL)
          D(1, 0xb43d5f10e9910958UL)
          D(2, 0x08cb5e256d3bc7fdUL)
          D(3, 0x9b525514d874118cUL)
          FPSCR 0x60000000u ]
        [ D(0, 0x8000000000000000UL)
          D(1, 0x7f80ff00807fffffUL)
          D(2, 0x00ff00ff00ff00ffUL)
          D(3, 0x0102030405060708UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x00008a0000000000UL)
          D(1, 0x3c007eee00000000UL)
          FPSCR 0x08000000u ]
        [ D(0, 0x1000bc4ada760000UL)
          D(1, 0x00a4aa2800e82200UL)
          FPSCR 0x68000000u ]
        [ D(0, 0x0000000000000000UL)
          D(1, 0x020406080a0c0e10UL)
          FPSCR 0x08000000u ] ]
    check false "f3890652" inputs outputs

  /// <summary>
  /// A8.8.382 VQSHRN: vqshrn.s16 d0, q1, #0x1. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.382 VQSHRN``() =
    let inputs =
      [ [ D(0, 0x4800e080127dfa94UL)
          D(2, 0x5dd0d9a650e8983cUL)
          D(3, 0x3d5ba258e379623dUL)
          FPSCR 0x00000000u ]
        [ D(0, 0xa16d785d9b94596fUL)
          D(2, 0xa27b6cc6de11e4caUL)
          D(3, 0xa275ab9eec13c55eUL)
          FPSCR 0x60000000u ]
        [ D(0, 0x8001800180018001UL)
          D(2, 0x0102030405060708UL)
          D(3, 0x0000000000000001UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x7f80807f7f807f80UL); FPSCR 0x08000000u ]
        [ D(0, 0x80808080807f8080UL); FPSCR 0x68000000u ]
        [ D(0, 0x000000007f7f7f7fUL); FPSCR 0x08000000u ] ]
    check false "f28f0912" inputs outputs

  /// <summary>
  /// A8.8.382 VQSHRUN: vqshrun.s16 d0, q1, #0x1. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.382 VQSHRUN``() =
    let inputs =
      [ [ D(0, 0xdc34f8bc85fe22b3UL)
          D(2, 0x898899b96987e18fUL)
          D(3, 0x3fb177144373c427UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x6c4325a0e0456407UL)
          D(2, 0xd39dda21b99c9b28UL)
          D(3, 0xea6ada94effce543UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(2, 0xffffffffffffffffUL)
          D(3, 0x7fffffffffffffffUL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xffffff000000ff00UL); FPSCR 0x08000000u ]
        [ D(0, 0x0000000000000000UL); FPSCR 0x68000000u ]
        [ D(0, 0xff00000000000000UL); FPSCR 0x08000000u ] ]
    check false "f38f0812" inputs outputs

  /// <summary>
  /// A8.8.383 VQSUB: vqsub.s8 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.383 VQSUB``() =
    let inputs =
      [ [ D(0, 0xc721548bc972f6e6UL)
          D(1, 0x9e879585d4ef8a6dUL)
          D(2, 0x6eaa9a2441bee20cUL)
          D(3, 0x06d1aa97181360a7UL)
          D(4, 0xd456d963909e2b37UL)
          D(5, 0x3fb296097a4ba266UL)
          FPSCR 0x00000000u ]
        [ D(0, 0xf3c66f8e207d6577UL)
          D(1, 0x7a723ee55c1cb3a9UL)
          D(2, 0xd32dfea99749867dUL)
          D(3, 0x947538cfb0292c08UL)
          D(4, 0x6fa241e6c0178cfbUL)
          D(5, 0x9c401dbcd53dff64UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0x8000000000000000UL)
          D(2, 0x7fffffffffffffffUL)
          D(3, 0x0102030405060708UL)
          D(4, 0x0000000000000001UL)
          D(5, 0x8001800180018001UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x7f80c1c17f20b7d5UL)
          D(1, 0xc71f148e9ec87f80UL)
          FPSCR 0x08000000u ]
        [ D(0, 0x807fbdc3d732fa7fUL)
          D(1, 0xf8351b13dbec2da4UL)
          FPSCR 0x68000000u ]
        [ D(0, 0x7ffffffffffffffeUL)
          D(1, 0x7f017f037f057f07UL)
          FPSCR 0x08000000u ] ]
    check false "f2020254" inputs outputs

  /// <summary>
  /// A8.8.384 VRADDHN: vraddhn.i32 d0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.384 VRADDHN``() =
    let inputs =
      [ [ D(0, 0x2db2251cb9939f86UL)
          D(2, 0xc8a18ba54f395538UL)
          D(3, 0xe00dee9c3020bccfUL)
          D(4, 0x06922c7d61513aa8UL)
          D(5, 0x69fdaa7c69ab1c65UL) ]
        [ D(0, 0xc4a581c0f4e2af61UL)
          D(2, 0x235303bc44dd8a1dUL)
          D(3, 0x609e429c153d624fUL)
          D(4, 0xbc48fc28eb84a2c2UL)
          D(5, 0x759c5cd2605946e7UL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(2, 0x7fffffffffffffffUL)
          D(3, 0x8000000000000000UL)
          D(4, 0x7f80ff00807fffffUL)
          D(5, 0x7f80ff00807fffffUL) ] ]
    let outputs =
      [ [ D(0, 0x4a0c99cccf34b08bUL) ]
        [ D(0, 0xd63b7597df9c3062UL) ]
        [ D(0, 0xff818080ff818080UL) ] ]
    check false "f3920404" inputs outputs

  /// <summary>
  /// A8.8.385 VRECPE: vrecpe.f32 d0, d1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.385 VRECPE``() =
    let inputs =
      [ [ D(0, 0x40e8000041400000UL)
          D(1, 0x40e800003e000000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0xbf80000041200000UL)
          D(1, 0x40e8000040400000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x7f800000c0100000UL)
          D(1, 0x3f00000000000000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x3e0d000040ff8000UL); FPSCR 0x00000000u ]
        [ D(0, 0x3e0d00003eaa8000UL); FPSCR 0x60000000u ]
        [ D(0, 0x3fff80007f800000UL); FPSCR 0x00000002u ] ]
    check false "f3bb0501" inputs outputs

  /// <summary>
  /// A8.8.386 VRECPS: vrecps.f32 d0, d1, d2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.386 VRECPS``() =
    let inputs =
      [ [ D(0, 0x40e80000c0400000UL)
          D(1, 0x42c9000040200000UL)
          D(2, 0x3e0000003e800000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x3e800000bf000000UL)
          D(1, 0xc060000041200000UL)
          D(2, 0x44800000bf800000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x80000000c0100000UL)
          D(1, 0xc010000000000000UL)
          D(2, 0xc0100000c0100000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xc12900003fb00000UL); FPSCR 0x00000000u ]
        [ D(0, 0x4560200041400000UL); FPSCR 0x60000000u ]
        [ D(0, 0xc044000040000000UL); FPSCR 0x00000000u ] ]
    check false "f2010f12" inputs outputs

  /// <summary>
  /// A8.8.387 VREV16: vrev16.8 q0, q1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.387 VREV16``() =
    let inputs =
      [ [ D(0, 0x42aa91d83192ce99UL)
          D(1, 0x063a38bfe0e3251eUL)
          D(2, 0xa6fa64fe717d25c3UL)
          D(3, 0xfa32b8f3c55ae158UL) ]
        [ D(0, 0x8d7cb441f3305ee0UL)
          D(1, 0xccac40b5bfbba3f8UL)
          D(2, 0xf56ad0bde369ee2cUL)
          D(3, 0x1cb0cc576891aa91UL) ]
        [ D(0, 0x0000000000000001UL)
          D(1, 0x8001800180018001UL)
          D(2, 0x0102030405060708UL)
          D(3, 0xffffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0xfaa6fe647d71c325UL); D(1, 0x32faf3b85ac558e1UL) ]
        [ D(0, 0x6af5bdd069e32ceeUL); D(1, 0xb01c57cc916891aaUL) ]
        [ D(0, 0x0201040306050807UL); D(1, 0xffffffffffffffffUL) ] ]
    check false "f3b00142" inputs outputs

  /// <summary>
  /// A8.8.387 VREV32: vrev32.8 q0, q1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.387 VREV32``() =
    let inputs =
      [ [ D(0, 0xc933685e40707a4bUL)
          D(1, 0x54f70a10818e5766UL)
          D(2, 0x2c40ce84c05abb09UL)
          D(3, 0x2b7da4193d230f6bUL) ]
        [ D(0, 0xa45993cf42c27856UL)
          D(1, 0xa114190b59aa1cc5UL)
          D(2, 0xfe595ee2f13b9c43UL)
          D(3, 0x850e33dde63f1425UL) ]
        [ D(0, 0x0000000000000001UL)
          D(1, 0x0102030405060708UL)
          D(2, 0x8001800180018001UL)
          D(3, 0x7fffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x84ce402c09bb5ac0UL); D(1, 0x19a47d2b6b0f233dUL) ]
        [ D(0, 0xe25e59fe439c3bf1UL); D(1, 0xdd330e8525143fe6UL) ]
        [ D(0, 0x0180018001800180UL); D(1, 0xffffff7fffffffffUL) ] ]
    check false "f3b000c2" inputs outputs

  /// <summary>
  /// A8.8.387 VREV64: vrev64.8 q0, q1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.387 VREV64``() =
    let inputs =
      [ [ D(0, 0x92f57b571bf6b4bdUL)
          D(1, 0x69e9a3652707ee22UL)
          D(2, 0x887d07ccaf2e4e47UL)
          D(3, 0x4fce5332adc80b79UL) ]
        [ D(0, 0x73f459ad874f1d83UL)
          D(1, 0xbc7ee98b6f0d4d4eUL)
          D(2, 0xf90d30abc5348f6cUL)
          D(3, 0x221a8c3551204782UL) ]
        [ D(0, 0x8000000000000000UL)
          D(1, 0x0000000000000001UL)
          D(2, 0x7f80ff00807fffffUL)
          D(3, 0x00ff00ff00ff00ffUL) ] ]
    let outputs =
      [ [ D(0, 0x474e2eafcc077d88UL); D(1, 0x790bc8ad3253ce4fUL) ]
        [ D(0, 0x6c8f34c5ab300df9UL); D(1, 0x82472051358c1a22UL) ]
        [ D(0, 0xffff7f8000ff807fUL); D(1, 0xff00ff00ff00ff00UL) ] ]
    check false "f3b00042" inputs outputs

  /// <summary>
  /// A8.8.388 VRHADD: vrhadd.s32 q1, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.388 VRHADD``() =
    let inputs =
      [ [ D(2, 0x0818dd52a8e548a6UL)
          D(3, 0x4ed3d98050826c73UL)
          D(4, 0x9227f1de836a6c39UL)
          D(5, 0x56c2ca59a074ea14UL) ]
        [ D(2, 0x400e3e90bb2f6a77UL)
          D(3, 0x7620210a0ea8547fUL)
          D(4, 0xac3d61e625c797faUL)
          D(5, 0xd0beeb2b8554f67aUL) ]
        [ D(2, 0x7fffffffffffffffUL)
          D(3, 0x00ff00ff00ff00ffUL)
          D(4, 0x7f80ff00807fffffUL)
          D(5, 0x8001800180018001UL) ] ]
    let outputs =
      [ [ D(2, 0xcd2067989627da70UL); D(3, 0x52cb51edf87bab44UL) ]
        [ D(2, 0xf625d03bf07b8139UL); D(3, 0x236f861bc9fea57dUL) ]
        [ D(2, 0x7fc07f80c03fffffUL); D(3, 0xc0804080c0804080UL) ] ]
    check false "f2222144" inputs outputs

  /// <summary>
  /// A8.8.389 VRSHL: vrshl.s8 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.389 VRSHL``() =
    let inputs =
      [ [ D(0, 0x014ca156c3993f4cUL)
          D(1, 0x65b510f31788a883UL)
          D(2, 0x02f508ff54bc6979UL)
          D(3, 0xa2466fb96156441eUL)
          D(4, 0x0f1d6e324acb8db2UL)
          D(5, 0x611598e438a7b98bUL) ]
        [ D(0, 0x199db6d8eeaea754UL)
          D(1, 0x632c96f550ccab4dUL)
          D(2, 0x38d27dd622d0a500UL)
          D(3, 0x18eb9b1d13e9789aUL)
          D(4, 0x9f7ba29c36c18728UL)
          D(5, 0x5d4310f200823d8eUL) ]
        [ D(0, 0x8000000000000000UL)
          D(1, 0x8000000000000000UL)
          D(2, 0x8000000000000000UL)
          D(3, 0x0000000000000001UL)
          D(4, 0x0000000000000001UL)
          D(5, 0x0000000000000001UL) ] ]
    let outputs =
      [ [ D(0, 0x0000000000000000UL); D(1, 0x0000000000000000UL) ]
        [ D(0, 0x0000000000000000UL); D(1, 0x0000000013000000UL) ]
        [ D(0, 0x8000000000000000UL); D(1, 0x0000000000000002UL) ] ]
    check false "f2040542" inputs outputs

  /// <summary>
  /// A8.8.390 VRSHR: vrshr.s32 d2, d4, #0x1f. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.390 VRSHR``() =
    let inputs =
      [ [ D(2, 0x0f6e6c643f22c542UL); D(4, 0x257a6c0b45c5d05fUL) ]
        [ D(2, 0xb88099fca8f747e3UL); D(4, 0xe09801d4685e1905UL) ]
        [ D(2, 0x00ff00ff00ff00ffUL); D(4, 0x7fffffffffffffffUL) ] ]
    let outputs =
      [ [ D(2, 0x0000000000000001UL) ]
        [ D(2, 0x0000000000000001UL) ]
        [ D(2, 0x0000000100000000UL) ] ]
    check false "f2a12214" inputs outputs

  /// <summary>
  /// A8.8.391 VRSHRN: vrshrn.i16 d0, q1, #0x1. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.391 VRSHRN``() =
    let inputs =
      [ [ D(0, 0xb95ec055d2621f9aUL)
          D(2, 0xf737f32884bfe382UL)
          D(3, 0xa8e4a58d88de30d0UL) ]
        [ D(0, 0x0de266da0cef0d62UL)
          D(2, 0x01c16e2048abc096UL)
          D(3, 0x922d83f28eca0990UL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(2, 0x0102030405060708UL)
          D(3, 0x7fffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x72c76f689c9460c1UL) ]
        [ D(0, 0x17f965c8e110564bUL) ]
        [ D(0, 0x0000000081828384UL) ] ]
    check false "f28f0852" inputs outputs

  /// <summary>
  /// A8.8.392 VRSQRTE: vrsqrte.f32 d0, d1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.392 VRSQRTE``() =
    let inputs =
      [ [ D(0, 0x3e8000003e800000UL)
          D(1, 0x3e80000044800000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0xc0100000c0100000UL)
          D(1, 0x3f400000c2400000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x3fc0000000000000UL)
          D(1, 0xc0100000ff800000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x3fff80003cff8000UL); FPSCR 0x00000000u ]
        [ D(0, 0x3f9380007fc00000UL); FPSCR 0x60000001u ]
        [ D(0, 0x7fc000007fc00000UL); FPSCR 0x00000001u ] ]
    check false "f3bb0581" inputs outputs

  /// <summary>
  /// A8.8.393 VRSQRTS: vrsqrts.f32 d0, d1, d2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.393 VRSQRTS``() =
    let inputs =
      [ [ D(0, 0x3e00000042c90000UL)
          D(1, 0xc010000040000000UL)
          D(2, 0x414000003fc00000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x41200000bf800000UL)
          D(1, 0xc010000040800000UL)
          D(2, 0x40200000bec00000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x7f8000007f800000UL)
          D(1, 0x000000003fc00000UL)
          D(2, 0x4040000000000000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x4170000000000000UL); FPSCR 0x00000000u ]
        [ D(0, 0x408a000040100000UL); FPSCR 0x60000000u ]
        [ D(0, 0x3fc000003fc00000UL); FPSCR 0x00000000u ] ]
    check false "f2210f12" inputs outputs

  /// <summary>
  /// A8.8.394 VRSRA: vrsra.s8 q0, q1, #0x1. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.394 VRSRA``() =
    let inputs =
      [ [ D(0, 0x29185ffec19a3b7eUL)
          D(1, 0xe62b6b7e2071aa26UL)
          D(2, 0x023dffc8b4ce551fUL)
          D(3, 0x779a08ab87f2f70bUL) ]
        [ D(0, 0xa202ddb9f8bee9b6UL)
          D(1, 0xca80ae6c388ff48eUL)
          D(2, 0x4ad51ad37017f97dUL)
          D(3, 0x42a3ae14b75bfe64UL) ]
        [ D(0, 0x8000000000000000UL)
          D(1, 0x0102030405060708UL)
          D(2, 0x7f80ff00807fffffUL)
          D(3, 0xffffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x2a375fe29b81668eUL); D(1, 0x22f86f54e46aa62cUL) ]
        [ D(0, 0xc7edeaa330cae6f5UL); D(1, 0xeb52857614bdf3c0UL) ]
        [ D(0, 0xc0c00000c0400000UL); D(1, 0x0102030405060708UL) ] ]
    check false "f28f0352" inputs outputs

  /// <summary>
  /// A8.8.395 VRSUBHN: vrsubhn.i32 d0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.395 VRSUBHN``() =
    let inputs =
      [ [ D(0, 0x978954b3bc0d99d4UL)
          D(2, 0x768d2c4c63eea13fUL)
          D(3, 0x6f3f987aa8de3a14UL)
          D(4, 0xd3d502e2923734f2UL)
          D(5, 0x8ab3a1d28d62b8acUL) ]
        [ D(0, 0x7130b39bde9a8f4aUL)
          D(2, 0x7f969cb8bf369d57UL)
          D(3, 0x6ce08a9537311a67UL)
          D(4, 0x82484dddff6b2becUL)
          D(5, 0xb85146ea30719c99UL) ]
        [ D(0, 0x8001800180018001UL)
          D(2, 0x0000000000000001UL)
          D(3, 0x7fffffffffffffffUL)
          D(4, 0x7f80ff00807fffffUL)
          D(5, 0x0000000000000001UL) ] ]
    let outputs =
      [ [ D(0, 0xe48c1b7ca2b8d1b7UL) ]
        [ D(0, 0xb48f06bffd4ebfcbUL) ]
        [ D(0, 0x80000000807f7f80UL) ] ]
    check false "f3920604" inputs outputs

  /// <summary>
  /// A8.8.396 VSHL: vshl.i8 q0, q1, #0x1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.396 VSHL``() =
    let inputs =
      [ [ D(0, 0x894e1e0c79ec5b12UL)
          D(1, 0xe64701cd0534a80cUL)
          D(2, 0x373cf1a699a13691UL)
          D(3, 0x0119a510a07f6f94UL) ]
        [ D(0, 0x62995182874c3d76UL)
          D(1, 0xd09fde520d4b9ab9UL)
          D(2, 0x408c08abe8198688UL)
          D(3, 0x517b95f470f9f9b1UL) ]
        [ D(0, 0x8000000000000000UL)
          D(1, 0x00ff00ff00ff00ffUL)
          D(2, 0x8001800180018001UL)
          D(3, 0x00ff00ff00ff00ffUL) ] ]
    let outputs =
      [ [ D(0, 0x6e78e24c32426c22UL); D(1, 0x02324a2040fede28UL) ]
        [ D(0, 0x80181056d0320c10UL); D(1, 0xa2f62ae8e0f2f262UL) ]
        [ D(0, 0x0002000200020002UL); D(1, 0x00fe00fe00fe00feUL) ] ]
    check false "f2890552" inputs outputs

  /// <summary>
  /// A8.8.398 VSHLL: vshll.s8 q0, d1, #0x1. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.398 VSHLL``() =
    let inputs =
      [ [ D(0, 0x520479750d09d4a9UL); D(1, 0x1117c560c8e29096UL) ]
        [ D(0, 0xd30e551b11cf5a1eUL); D(1, 0x0a650a87a8d6b543UL) ]
        [ D(0, 0x7fffffffffffffffUL); D(1, 0x7f80ff00807fffffUL) ] ]
    let outputs =
      [ [ D(0, 0xff90ffc4ff20ff2cUL); D(1, 0x0022002eff8a00c0UL) ]
        [ D(0, 0xff50ffacff6a0086UL); D(1, 0x001400ca0014ff0eUL) ]
        [ D(0, 0xff0000fefffefffeUL); D(1, 0x00feff00fffe0000UL) ] ]
    check false "f2890a11" inputs outputs

  /// <summary>
  /// A8.8.399 VSHR: vshr.s32 d2, d4, #0x1f. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.399 VSHR``() =
    let inputs =
      [ [ D(2, 0xd8d3f2c7d7c2424cUL); D(4, 0xbc60268149375531UL) ]
        [ D(2, 0x85e42eaecb70f1b1UL); D(4, 0x9cacc906804942a6UL) ]
        [ D(2, 0x0102030405060708UL); D(4, 0x0102030405060708UL) ] ]
    let outputs =
      [ [ D(2, 0xffffffff00000000UL) ]
        [ D(2, 0xffffffffffffffffUL) ]
        [ D(2, 0x0000000000000000UL) ] ]
    check false "f2a12014" inputs outputs

  /// <summary>
  /// A8.8.400 VSHRN: vshrn.i16 d0, q1, #0x1. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.400 VSHRN``() =
    let inputs =
      [ [ D(0, 0xef13993844e55501UL)
          D(2, 0x07afb87443cb5b8dUL)
          D(3, 0xd0c8442e3b8440bcUL) ]
        [ D(0, 0xdd8cf630550df5e8UL)
          D(2, 0x610cd525c22618efUL)
          D(3, 0x1c807737967c3f25UL) ]
        [ D(0, 0x8000000000000000UL)
          D(2, 0x7f80ff00807fffffUL)
          D(3, 0x7fffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x6417c25ed73ae5c6UL) ]
        [ D(0, 0x409b3e9286921377UL) ]
        [ D(0, 0xffffffffc0803fffUL) ] ]
    check false "f28f0812" inputs outputs

  /// <summary>
  /// A8.8.401 VSLI: vsli.8 q0, q1, #0x1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.401 VSLI``() =
    let inputs =
      [ [ D(0, 0x59129c1e3f15898dUL)
          D(1, 0x244e12fa64e0493eUL)
          D(2, 0x715550123432c166UL)
          D(3, 0x3cf5266c43a93989UL) ]
        [ D(0, 0x183368a4a74408d1UL)
          D(1, 0x938e64f076f89f78UL)
          D(2, 0x2a48abd8a1df2d36UL)
          D(3, 0x812c27c6438c6a3cUL) ]
        [ D(0, 0x0000000000000001UL)
          D(1, 0x0102030405060708UL)
          D(2, 0x0000000000000001UL)
          D(3, 0xffffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0xe3aaa024696583cdUL); D(1, 0x78ea4cd886527312UL) ]
        [ D(0, 0x549156b043be5a6dUL); D(1, 0x03584e8c8618d578UL) ]
        [ D(0, 0x0000000000000003UL); D(1, 0xfffefffefffefffeUL) ] ]
    check false "f3890552" inputs outputs

  /// <summary>
  /// A8.8.402 VSQRT: vsqrt.f32 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.402 VSQRT``() =
    let inputs =
      [ [ D(0, 0xc240000040c00000UL); FPSCR 0x00000000u ]
        [ D(0, 0x4140000044800000UL); FPSCR 0x60000000u ]
        [ D(0, 0x8000000080000000UL); FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xc24000007fc00000UL); FPSCR 0x00000001u ]
        [ D(0, 0x41400000405db3d7UL); FPSCR 0x60000010u ]
        [ D(0, 0x8000000080000000UL); FPSCR 0x00000000u ] ]
    check false "eeb10ae0" inputs outputs

  /// <summary>
  /// A8.8.403 VSRA: vsra.s8 q0, q1, #0x1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.403 VSRA``() =
    let inputs =
      [ [ D(0, 0x7e2e30565dbc8febUL)
          D(1, 0x087603bc220715ebUL)
          D(2, 0x97b069ff1448a2f4UL)
          D(3, 0x4db7158e29dce822UL) ]
        [ D(0, 0x42c538b6a44d8181UL)
          D(1, 0x747634d5c04c9376UL)
          D(2, 0x25f38d572d2b9570UL)
          D(3, 0xde5163dc7940ab24UL) ]
        [ D(0, 0xffffffffffffffffUL)
          D(1, 0x7fffffffffffffffUL)
          D(2, 0x7fffffffffffffffUL)
          D(3, 0x00ff00ff00ff00ffUL) ] ]
    let outputs =
      [ [ D(0, 0x4906645567e060e5UL); D(1, 0x2e510d8336f509fcUL) ]
        [ D(0, 0x54befee1ba624bb9UL); D(1, 0x639e65c3fc6c6888UL) ]
        [ D(0, 0x3efefefefefefefeUL); D(1, 0x7ffefffefffefffeUL) ] ]
    check false "f28f0152" inputs outputs

  /// <summary>
  /// A8.8.404 VSRI: vsri.8 q0, q1, #0x1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.404 VSRI``() =
    let inputs =
      [ [ D(0, 0x443a15fe77524705UL)
          D(1, 0x2d5565b2d89936ecUL)
          D(2, 0xec078401ec5cd015UL)
          D(3, 0x8795dc548c922f3dUL) ]
        [ D(0, 0xec9c4d40f36bc973UL)
          D(1, 0x7b7fd3761fe52a44UL)
          D(2, 0x27b28ac8e4a31955UL)
          D(3, 0x8a40a2548220fe63UL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0x7fffffffffffffffUL)
          D(2, 0x8001800180018001UL)
          D(3, 0x00ff00ff00ff00ffUL) ] ]
    let outputs =
      [ [ D(0, 0x76034280762e680aUL); D(1, 0x434a6eaac6c9179eUL) ]
        [ D(0, 0x93d94564f2518c2aUL); D(1, 0x4520d12a41907f31UL) ]
        [ D(0, 0x4080c000c000c080UL); D(1, 0x00ff80ff80ff80ffUL) ] ]
    check false "f38f0452" inputs outputs

  /// <summary>
  /// A8.8.405 VST1: vst1.8 {d0}, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.405 VST1``() =
    let inputs =
      [ [ Gpr(1, 0x20000810u)
          D(0, 0xc81687b8189b7ad3UL)
          M(0, 0xb873a7e1387dc8bfUL)
          M(8, 0xe8a2d3e73f42f85eUL)
          M(16, 0xb49990bfceef2c68UL)
          M(24, 0xb5bfaf05ae4f98d5UL)
          M(32, 0x508a3c2f7d90484dUL)
          M(40, 0x61f2a972562591a6UL)
          M(48, 0x100cec07294e5b99UL)
          M(56, 0xcc817018887719d6UL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x87abb58e698f2200UL)
          M(0, 0xbf3c0952ec371973UL)
          M(8, 0x5d24e3bda58c4073UL)
          M(16, 0x8c51ec73221c9fa8UL)
          M(24, 0xd02f3444782da932UL)
          M(32, 0xba42870de28152dcUL)
          M(40, 0xf2f30edff8af6d38UL)
          M(48, 0x25d7998a0eec1d76UL)
          M(56, 0x776a80a1626ed7b9UL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x7f80ff00807fffffUL)
          M(0, 0xd6a0fd4a8d47dafdUL)
          M(8, 0xca8c9e4f52f3d4dbUL)
          M(16, 0x744010f080154440UL)
          M(24, 0x2133474bd8e58ab9UL)
          M(32, 0x1366e0e9c363f5d3UL)
          M(40, 0xbed8291ad38bc3b5UL)
          M(48, 0xcb3c3eb830019600UL)
          M(56, 0xfa156b41080d8ebbUL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000810u); M(16, 0xc81687b8189b7ad3UL) ]
        [ Gpr(1, 0x20000810u); M(16, 0x87abb58e698f2200UL) ]
        [ Gpr(1, 0x20000810u); M(16, 0x7f80ff00807fffffUL) ] ]
    check false "f401070f" inputs outputs

  /// <summary>
  /// A8.8.407 VST2: vst2.8 {d0, d1}, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.407 VST2``() =
    let inputs =
      [ [ Gpr(1, 0x20000810u)
          D(0, 0x9fed5ee8bc843367UL)
          D(1, 0x9e27b8e2ed94763aUL)
          M(0, 0x6ee5f018ff523b09UL)
          M(8, 0x7fb5223b74757476UL)
          M(16, 0x65317b04c57369c1UL)
          M(24, 0x7d879e1994bc4127UL)
          M(32, 0x20cf00b2ed586e38UL)
          M(40, 0x1224671e692494fcUL)
          M(48, 0xa68b2b22707ec6aeUL)
          M(56, 0x5ff8c61887aacb3fUL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x7f02832685081303UL)
          D(1, 0xde9dbe04d0c8b3d9UL)
          M(0, 0x5c8841e46c4550ceUL)
          M(8, 0x7ab131d0f9ab6e2dUL)
          M(16, 0x0a6fa99cf30f2be4UL)
          M(24, 0x681347e6b0bbb990UL)
          M(32, 0x9ad7c3fd0842cffbUL)
          M(40, 0x55c8094bc7abb431UL)
          M(48, 0x322c078f2f3ed6ddUL)
          M(56, 0x5418568dbf3e544cUL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x00ff00ff00ff00ffUL)
          D(1, 0x0102030405060708UL)
          M(0, 0x3eea7321833b8f00UL)
          M(8, 0x3e98d429a98c9e65UL)
          M(16, 0x695b760a87c2797dUL)
          M(24, 0xbf56ad3d7900b8e1UL)
          M(32, 0x76bd10b77dd07971UL)
          M(40, 0xdc8c4291f3e9c15bUL)
          M(48, 0xa5a768d4c9b34825UL)
          M(56, 0xdf33186d621d1b78UL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000810u)
          M(16, 0xedbc948476333a67UL)
          M(24, 0x9e9f27edb85ee2e8UL) ]
        [ Gpr(1, 0x20000810u)
          M(16, 0xd085c808b313d903UL)
          M(24, 0xde7f9d02be830426UL) ]
        [ Gpr(1, 0x20000810u)
          M(16, 0x050006ff070008ffUL)
          M(24, 0x010002ff030004ffUL) ] ]
    check false "f401080f" inputs outputs

  /// <summary>
  /// A8.8.409 VST3: vst3.8 {d0, d1, d2}, [r1]. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.409 VST3``() =
    let inputs =
      [ [ Gpr(1, 0x20000810u)
          D(0, 0x1cb019db55ed5c6cUL)
          D(1, 0x81f7ee669fbcd9b3UL)
          D(2, 0xcaf0d332082dbf42UL)
          M(0, 0x76d538f5581a1086UL)
          M(8, 0xe774ffe0d6091917UL)
          M(16, 0xd88c72b788ed69e2UL)
          M(24, 0xe8886096b628c7a0UL)
          M(32, 0xd278d96bece7f1b4UL)
          M(40, 0x00997e5d67a7db32UL)
          M(48, 0xd62c1ff9b8d7aa67UL)
          M(56, 0x9ab93960e510baf3UL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0xa92055884fa12055UL)
          D(1, 0x238f384cafe3d884UL)
          D(2, 0xd8aaf2a140848849UL)
          M(0, 0xa19a286d83ad4ccaUL)
          M(8, 0x044296510848e074UL)
          M(16, 0xfdc9b77d5d5b0d72UL)
          M(24, 0x47ea9e0b04467ac9UL)
          M(32, 0xd12c4e5f797fb8f8UL)
          M(40, 0x7fb0b0189137570aUL)
          M(48, 0xe6bda5f8d20b1f9bUL)
          M(56, 0xb3254558b8a6eb64UL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0xffffffffffffffffUL)
          D(1, 0x00ff00ff00ff00ffUL)
          D(2, 0x8000000000000000UL)
          M(0, 0x32a67d82b2bd9ee1UL)
          M(8, 0xda9628fe09e93714UL)
          M(16, 0x231fa93f9cdaf054UL)
          M(24, 0x9b8235c1c660450fUL)
          M(32, 0xc595a42d79bff805UL)
          M(40, 0xa39a866b9ef816f1UL)
          M(48, 0x032e0eb1f668a93dUL)
          M(56, 0xdaf524ce4d8e0db0UL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000810u)
          M(16, 0xbcedbfd95c42b36cUL)
          M(24, 0x193266db089f552dUL)
          M(32, 0xca811cf0f7b0d3eeUL) ]
        [ Gpr(1, 0x20000810u)
          M(16, 0xe3a188d820498455UL)
          M(24, 0x55a14c8840af4f84UL)
          M(32, 0xd823a9aa8f20f238UL) ]
        [ Gpr(1, 0x20000810u)
          M(16, 0xffff0000ff00ffffUL)
          M(24, 0xff00ffff0000ff00UL)
          M(32, 0x8000ff00ffff0000UL) ] ]
    check false "f401040f" inputs outputs

  /// <summary>
  /// A8.8.411 VST4: vst4.8 {d0, d1, d2, d3}, [r1]. The outputs are what QEMU
  /// left after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.411 VST4``() =
    let inputs =
      [ [ Gpr(1, 0x20000810u)
          D(0, 0xd9ebf535901f2dabUL)
          D(1, 0x00cf39102482b417UL)
          D(2, 0x684028d018bd7a70UL)
          D(3, 0x98ed5f42d6491acdUL)
          M(0, 0xac8bfbbf0026870dUL)
          M(8, 0x7748f8edfcfa242aUL)
          M(16, 0x2c4a922b584dd61dUL)
          M(24, 0x2fed19877ac1151cUL)
          M(32, 0xa037a9a66f2d350aUL)
          M(40, 0xc1ed81c820a3c9eeUL)
          M(48, 0x9add4b529b498ef9UL)
          M(56, 0xe603c48503cfe133UL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x1d85611341ef2e2bUL)
          D(1, 0xdda2010715a18cd3UL)
          D(2, 0xe9db2a132e06ef29UL)
          D(3, 0x6dfb482502895ffaUL)
          M(0, 0xace39f6efd19c849UL)
          M(8, 0x7eeba68b2d344bc6UL)
          M(16, 0x547f6fc40c512caaUL)
          M(24, 0xc194fc70be800f0aUL)
          M(32, 0x9c91f2f8c13be28dUL)
          M(40, 0x9a245c77befcbe8dUL)
          M(48, 0xfd33fb734b8c324eUL)
          M(56, 0x97ac8d5f670640daUL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x0000000000000001UL)
          D(1, 0x7f80ff00807fffffUL)
          D(2, 0x8000000000000000UL)
          D(3, 0x7f80ff00807fffffUL)
          M(0, 0x6a873d9c5bc02fa4UL)
          M(8, 0x3506d1bc52c29ed7UL)
          M(16, 0x0365d0d8d5210488UL)
          M(24, 0x331ba257f021aff6UL)
          M(32, 0x40aad3653407aedaUL)
          M(40, 0x233c0e72514cfd4fUL)
          M(48, 0xb9681cbb0b288d6fUL)
          M(56, 0xb9538c6127ebfb52UL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000810u)
          M(16, 0x1a7ab42dcd7017abUL)
          M(24, 0xd618249049bd821fUL)
          M(32, 0x5f2839f542d01035UL)
          M(40, 0x986800d9ed40cfebUL) ]
        [ Gpr(1, 0x20000810u)
          M(16, 0x5fef8c2efa29d32bUL)
          M(24, 0x022e15418906a1efUL)
          M(32, 0x482a016125130713UL)
          M(40, 0x6de9dd1dfbdba285UL) ]
        [ Gpr(1, 0x20000810u)
          M(16, 0xff00ff00ff00ff01UL)
          M(24, 0x800080007f007f00UL)
          M(32, 0xff00ff0000000000UL)
          M(40, 0x7f807f0080008000UL) ] ]
    check false "f401000f" inputs outputs

  /// <summary>
  /// A8.8.413 VSTM: vstmia r1, {s0, s1, s2, s3}. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.413 VSTM``() =
    let inputs =
      [ [ Gpr(1, 0x20000818u)
          D(0, 0x44c67f3d988f1ba9UL)
          D(1, 0x31c1bc0b21f12996UL)
          M(0, 0x8e4f33ef81461b7eUL)
          M(8, 0x8b498304512f8278UL)
          M(16, 0xba037898f678082dUL)
          M(24, 0x20f441b93b0046e0UL)
          M(32, 0x0b4654c56e02a738UL)
          M(40, 0xa2a7cf02fb38b269UL)
          M(48, 0x173b0aae318abfbfUL)
          M(56, 0x6d41d20044b6cb54UL) ]
        [ Gpr(1, 0x20000818u)
          D(0, 0x3f23f4d623cb4199UL)
          D(1, 0x4d742de38bbc5f9cUL)
          M(0, 0xd7bde531c6dedfbaUL)
          M(8, 0xb2c578f1efac86f1UL)
          M(16, 0x81b8e8c7465b8144UL)
          M(24, 0x07d055de8258003bUL)
          M(32, 0x875eefa48d110953UL)
          M(40, 0x004fb7d00079e71cUL)
          M(48, 0x1579020c5e2d6bedUL)
          M(56, 0x55d1c12f78bc623eUL) ]
        [ Gpr(1, 0x20000818u)
          D(0, 0x7fffffffffffffffUL)
          D(1, 0x8000000000000000UL)
          M(0, 0x060a73194f8b13e9UL)
          M(8, 0xe5174cc528babdf8UL)
          M(16, 0x8524eff3847b1e82UL)
          M(24, 0x260f9a68edd6ba04UL)
          M(32, 0xe00fdb5fcce06decUL)
          M(40, 0x2d6fcdbd69cf2db2UL)
          M(48, 0xe78002e91b31e629UL)
          M(56, 0x66554dd27dec02abUL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000818u)
          M(24, 0x44c67f3d988f1ba9UL)
          M(32, 0x31c1bc0b21f12996UL) ]
        [ Gpr(1, 0x20000818u)
          M(24, 0x3f23f4d623cb4199UL)
          M(32, 0x4d742de38bbc5f9cUL) ]
        [ Gpr(1, 0x20000818u)
          M(24, 0x7fffffffffffffffUL)
          M(32, 0x8000000000000000UL) ] ]
    check false "ec810a04" inputs outputs

  /// <summary>
  /// A8.8.414 VSTR: vstr d0, [r1, #8]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.414 VSTR``() =
    let inputs =
      [ [ Gpr(1, 0x20000808u)
          D(0, 0x34843c9c99df8264UL)
          M(0, 0x7071a01abae6c42dUL)
          M(8, 0x090fb1beeb4ac693UL)
          M(16, 0x8188f04a41ab4dacUL)
          M(24, 0xeb166cb14337278bUL)
          M(32, 0x901ffa70498d771eUL)
          M(40, 0x22e081fe4a09531bUL)
          M(48, 0xa5e73423d086ac91UL)
          M(56, 0xfb3af1068d4f8638UL) ]
        [ Gpr(1, 0x20000808u)
          D(0, 0x6b29df7c41995380UL)
          M(0, 0x157e9f22902648e6UL)
          M(8, 0xd2eb850ed6a64c0aUL)
          M(16, 0x5e5aecf52ef40cf8UL)
          M(24, 0x3958ca1fde7663f6UL)
          M(32, 0x8171b116e37a9725UL)
          M(40, 0xf8a2b00f240ef833UL)
          M(48, 0x28970ed86daf36e0UL)
          M(56, 0x5229e30dada912acUL) ]
        [ Gpr(1, 0x20000808u)
          D(0, 0x8000000000000000UL)
          M(0, 0xd926077cac41e30eUL)
          M(8, 0x8f8d3b27ad88e9deUL)
          M(16, 0x95db823b059fad8cUL)
          M(24, 0xc726cba552f075ceUL)
          M(32, 0xa77f8b6176f7f42eUL)
          M(40, 0x82b863f23c4a0cd5UL)
          M(48, 0x7eb5c841ab8a40bcUL)
          M(56, 0xf8cb4ed1ac7e2cecUL) ] ]
    let outputs =
      [ [ M(16, 0x34843c9c99df8264UL) ]
        [ M(16, 0x6b29df7c41995380UL) ]
        [ M(16, 0x8000000000000000UL) ] ]
    check false "ed810b02" inputs outputs

  /// <summary>
  /// A8.8.415 VSUB: vsub.f32 s0, s1, s2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.415 VSUB``() =
    let inputs =
      [ [ D(0, 0x3fe00000c0100000UL)
          D(1, 0xbf800000c2400000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0xc06000003d800000UL)
          D(1, 0x4480000044800000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x3f0000003f000000UL)
          D(1, 0x3f00000000000000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x3fe0000042470000UL); FPSCR 0x00000000u ]
        [ D(0, 0xc0600000c4807000UL); FPSCR 0x60000000u ]
        [ D(0, 0x3f0000003f000000UL); FPSCR 0x00000000u ] ]
    check false "ee300ac1" inputs outputs

  /// <summary>
  /// A8.8.417 VSUBHN: vsubhn.i32 d0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.417 VSUBHN``() =
    let inputs =
      [ [ D(0, 0xcf3849858be1b545UL)
          D(2, 0x9bd6eb47e16dfa0fUL)
          D(3, 0x5e8ec89c85de1317UL)
          D(4, 0x46c2e71b3d32b430UL)
          D(5, 0xdc1d6985c46fbc94UL) ]
        [ D(0, 0x4d57c944130a0065UL)
          D(2, 0x4a8fdfe817b8a629UL)
          D(3, 0x32fc2059f7a5716fUL)
          D(4, 0x581a8f70097287bfUL)
          D(5, 0x467b90551cc42308UL) ]
        [ D(0, 0x7fffffffffffffffUL)
          D(2, 0x0000000000000001UL)
          D(3, 0x00ff00ff00ff00ffUL)
          D(4, 0x7fffffffffffffffUL)
          D(5, 0x7f80ff00807fffffUL) ] ]
    let outputs =
      [ [ D(0, 0x8271c16e5514a43bUL) ]
        [ D(0, 0xec80dae1f2750e46UL) ]
        [ D(0, 0x817e807f80000000UL) ] ]
    check false "f2920604" inputs outputs

  /// <summary>
  /// A8.8.418 VSUBL: vsubl.s32 q0, d1, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.418 VSUBL``() =
    let inputs =
      [ [ D(0, 0x25e4b1369ac3d5c5UL)
          D(1, 0x4f14d1835777e3a5UL)
          D(2, 0x6fe1604d791ec2c6UL) ]
        [ D(0, 0x93e387c3aeba78f7UL)
          D(1, 0xa204957b0201ad25UL)
          D(2, 0xf9678778a3b87192UL) ]
        [ D(0, 0x0102030405060708UL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0x00ff00ff00ff00ffUL) ] ]
    let outputs =
      [ [ D(0, 0xffffffffde5920dfUL); D(1, 0xffffffffdf337136UL) ]
        [ D(0, 0x000000005e493b93UL); D(1, 0xffffffffa89d0e03UL) ]
        [ D(0, 0xffffffffff00ff00UL); D(1, 0xffffffffff00ff00UL) ] ]
    check false "f2a10202" inputs outputs

  /// <summary>
  /// A8.8.418 VSUBW: vsubw.s8 q0, q0, d1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.418 VSUBW``() =
    let inputs =
      [ [ D(0, 0x70304e839f2165b5UL); D(1, 0xadc0885b609fe3d2UL) ]
        [ D(0, 0x85a1b096505509e0UL); D(1, 0x82c7e011bf4365cfUL) ]
        [ D(0, 0x8001800180018001UL); D(1, 0x0000000000000001UL) ] ]
    let outputs =
      [ [ D(0, 0x6fd04ee49f3e65e3UL); D(1, 0xae13889b6117e377UL) ]
        [ D(0, 0x85e2b0534ff00a11UL); D(1, 0x8345e04abf6365beUL) ]
        [ D(0, 0x8001800180018000UL); D(1, 0x0000000000000001UL) ] ]
    check false "f2800301" inputs outputs

  /// <summary>
  /// A8.8.419 VSWP: vswp q0, q1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.419 VSWP``() =
    let inputs =
      [ [ D(0, 0xbfcd0832405e4f85UL)
          D(1, 0x4c75673b5c776c3bUL)
          D(2, 0xebec652c4493095aUL)
          D(3, 0xc91dded8e26d5e2fUL) ]
        [ D(0, 0x310cb2039720ca99UL)
          D(1, 0x5d528fb24368ac83UL)
          D(2, 0x2381d9bad8b2eb84UL)
          D(3, 0xe36a4de5c2e79c74UL) ]
        [ D(0, 0x00ff00ff00ff00ffUL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0x7fffffffffffffffUL)
          D(3, 0x8000000000000000UL) ] ]
    let outputs =
      [ [ D(0, 0xebec652c4493095aUL)
          D(1, 0xc91dded8e26d5e2fUL)
          D(2, 0xbfcd0832405e4f85UL)
          D(3, 0x4c75673b5c776c3bUL) ]
        [ D(0, 0x2381d9bad8b2eb84UL)
          D(1, 0xe36a4de5c2e79c74UL)
          D(2, 0x310cb2039720ca99UL)
          D(3, 0x5d528fb24368ac83UL) ]
        [ D(0, 0x7fffffffffffffffUL)
          D(1, 0x8000000000000000UL)
          D(2, 0x00ff00ff00ff00ffUL)
          D(3, 0xffffffffffffffffUL) ] ]
    check false "f3b20042" inputs outputs

  /// <summary>
  /// A8.8.420 VTBL: vtbl.8 d0, {d1}, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.420 VTBL``() =
    let inputs =
      [ [ D(0, 0x2899e80e3892b370UL)
          D(1, 0x2e80bc9dd6830b41UL)
          D(2, 0xbe9283ddb0a3f202UL) ]
        [ D(0, 0x998ad0c761a44e0fUL)
          D(1, 0x4bfab8b1a069d893UL)
          D(2, 0x1855b0e51cc06ab1UL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0x8000000000000000UL)
          D(2, 0x7fffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x0000000000000083UL) ]
        [ D(0, 0x0000000000000000UL) ]
        [ D(0, 0x0000000000000000UL) ] ]
    check false "f3b10802" inputs outputs

  /// <summary>
  /// A8.8.420 VTBX: vtbx.8 d0, {d1}, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.420 VTBX``() =
    let inputs =
      [ [ D(0, 0xad9e4ece8c5764d4UL)
          D(1, 0x7a5b626d65fc8b89UL)
          D(2, 0x0f36c6f2ad64d125UL) ]
        [ D(0, 0x44c8bde09518b949UL)
          D(1, 0xe03c5f92f92f8b51UL)
          D(2, 0x45ee01d4a3cb913cUL) ]
        [ D(0, 0x0102030405060708UL)
          D(1, 0x0000000000000001UL)
          D(2, 0x7f80ff00807fffffUL) ] ]
    let outputs =
      [ [ D(0, 0xad9e4ece8c5764d4UL) ]
        [ D(0, 0x44c88be09518b949UL) ]
        [ D(0, 0x0102030105060708UL) ] ]
    check false "f3b10842" inputs outputs

  /// <summary>
  /// A8.8.421 VTRN: vtrn.8 q0, q1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.421 VTRN``() =
    let inputs =
      [ [ D(0, 0x1bf6050411880d32UL)
          D(1, 0x4e528acb75efb270UL)
          D(2, 0xeed669703032a77fUL)
          D(3, 0x071894c53ba7cef8UL) ]
        [ D(0, 0x9bef6c3f77db5349UL)
          D(1, 0xee5f0faa1a5f81e4UL)
          D(2, 0x95ea20efb15010d8UL)
          D(3, 0xd920eea139287a10UL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0x7f80ff00807fffffUL)
          D(2, 0x8000000000000000UL)
          D(3, 0xffffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0xd6f6700432887f32UL)
          D(1, 0x1852c5cba7eff870UL)
          D(2, 0xee1b69053011a70dUL)
          D(3, 0x074e948a3b75ceb2UL) ]
        [ D(0, 0xeaefef3f50dbd849UL)
          D(1, 0x205fa1aa285f10e4UL)
          D(2, 0x959b206cb1771053UL)
          D(3, 0xd9eeee0f391a7a81UL) ]
        [ D(0, 0x00800000007f00ffUL)
          D(1, 0xff80ff00ff7fffffUL)
          D(2, 0x807f00ff008000ffUL)
          D(3, 0xff7fffffff80ffffUL) ] ]
    check false "f3b200c2" inputs outputs

  /// <summary>
  /// A8.8.422 VTST: vtst.8 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.422 VTST``() =
    let inputs =
      [ [ D(0, 0xa5537c0b2dbe226fUL)
          D(1, 0xb0764bef9cc7bedbUL)
          D(2, 0xe94af54229b61773UL)
          D(3, 0x34cf6e882aff9237UL)
          D(4, 0xeae0f30dfab48431UL)
          D(5, 0x8eb83348375b67d8UL) ]
        [ D(0, 0xb69aee3698100f59UL)
          D(1, 0x58a8f083e2671e41UL)
          D(2, 0xa367000990e72d88UL)
          D(3, 0xa715c5dbea71b4e1UL)
          D(4, 0xa0a8dc88263bab17UL)
          D(5, 0x6b76a377c34bee2cUL) ]
        [ D(0, 0x7fffffffffffffffUL)
          D(1, 0x00ff00ff00ff00ffUL)
          D(2, 0x8000000000000000UL)
          D(3, 0x0102030405060708UL)
          D(4, 0x8000000000000000UL)
          D(5, 0x0102030405060708UL) ] ]
    let outputs =
      [ [ D(0, 0xffffff00ffffffffUL); D(1, 0xffffffffffffffffUL) ]
        [ D(0, 0xffff00ff00ffff00UL); D(1, 0xffffffffffffffffUL) ]
        [ D(0, 0xff00000000000000UL); D(1, 0xffffffffffffffffUL) ] ]
    check false "f2020854" inputs outputs

  /// <summary>
  /// A8.8.423 VUZP: vuzp.8 q0, q1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.423 VUZP``() =
    let inputs =
      [ [ D(0, 0x76f4f51a271863e0UL)
          D(1, 0x2049f4b9874a1c91UL)
          D(2, 0xfe7717a75c0f3255UL)
          D(3, 0xd4d6b69265c0cd60UL) ]
        [ D(0, 0xe949263359af6b33UL)
          D(1, 0x793d85175ec92f58UL)
          D(2, 0x4b53aa4cddd1224eUL)
          D(3, 0xad69319f5793df67UL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0x7f80ff00807fffffUL)
          D(2, 0x8000000000000000UL)
          D(3, 0xffffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x49b94a91f41a18e0UL)
          D(1, 0xd692c06077a70f55UL)
          D(2, 0x20f4871c76f52763UL)
          D(3, 0xd4b665cdfe175c32UL) ]
        [ D(0, 0x3d17c9584933af33UL)
          D(1, 0x699f9367534cd14eUL)
          D(2, 0x79855e2fe926596bUL)
          D(3, 0xad3157df4baadd22UL) ]
        [ D(0, 0x80007fff80007fffUL)
          D(1, 0xffffffff00000000UL)
          D(2, 0x7fff80ff7fff80ffUL)
          D(3, 0xffffffff80000000UL) ] ]
    check false "f3b20142" inputs outputs

  /// <summary>
  /// A8.8.424 VZIP: vzip.8 q0, q1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.424 VZIP``() =
    let inputs =
      [ [ D(0, 0xcb0e77fbcbe6b2dfUL)
          D(1, 0x86e452c04f4e266fUL)
          D(2, 0x9b7c7be1a03e78c0UL)
          D(3, 0x31addc63a6400c50UL) ]
        [ D(0, 0x2d404a79c380f090UL)
          D(1, 0x778bb773e945f5e0UL)
          D(2, 0x12ed3f1cfe9e9fe8UL)
          D(3, 0xf9fac96fab62c931UL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0x8000000000000000UL)
          D(2, 0x7fffffffffffffffUL)
          D(3, 0x8000000000000000UL) ] ]
    let outputs =
      [ [ D(0, 0xa0cb3ee678b2c0dfUL)
          D(1, 0x9bcb7c0e7b77e1fbUL)
          D(2, 0xa64f404e0c26506fUL)
          D(3, 0x3186ade4dc5263c0UL) ]
        [ D(0, 0xfec39e809ff0e890UL)
          D(1, 0x122ded403f4a1c79UL)
          D(2, 0xabe96245c9f531e0UL)
          D(3, 0xf977fa8bc9b76f73UL) ]
        [ D(0, 0xff80ff7fffffffffUL)
          D(1, 0x7f7fff80ffffff00UL)
          D(2, 0x0000000000000000UL)
          D(3, 0x8080000000000000UL) ] ]
    check false "f3b201c2" inputs outputs

  /// <summary>
  /// A8.8.425 WFE: wfe. It lifts to no statements: what it does is a hint or an
  /// ordering of memory accesses that one run cannot observe, and QEMU's runs
  /// of it changed no register and no byte, so a value test would assert
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.425 WFE``() =
    Assert.AreEqual(0, (lift false "e320f002").Length)

  /// <summary>
  /// A8.8.426 WFI: wfi. It lifts to no statements: what it does is a hint or an
  /// ordering of memory accesses that one run cannot observe, and QEMU's runs
  /// of it changed no register and no byte, so a value test would assert
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.426 WFI``() =
    Assert.AreEqual(0, (lift false "e320f003").Length)

  /// <summary>
  /// A8.8.427 YIELD: yield. It lifts to no statements: what it does is a hint
  /// or an ordering of memory accesses that one run cannot observe, and QEMU's
  /// runs of it changed no register and no byte, so a value test would assert
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.427 YIELD``() =
    Assert.AreEqual(0, (lift false "e320f001").Length)

  /// <summary>
  /// F5.1.1 ADCS: adcs r0, r1, r2. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.1 ADCS``() =
    let inputs =
      [ [ Gpr(0, 0x4128e91fu)
          Gpr(1, 0xa6fa4bf0u)
          Gpr(2, 0xa14662f0u)
          CPSR 0x20000010u ]
        [ Gpr(0, 0x192afffcu)
          Gpr(1, 0x6e4d9f8cu)
          Gpr(2, 0xf50b5b6fu)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x4840aee1u); CPSR 0x30000010u ]
        [ Gpr(0, 0x6358fafbu); CPSR 0x200a0010u ]
        [ Gpr(0, 0x80000000u); CPSR 0x98050010u ] ]
    check false "e0b10002" inputs outputs

  /// <summary>
  /// F5.1.4 ADDS: adds r1, r1, r2. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.4 ADDS``() =
    let inputs =
      [ [ Gpr(1, 0x228453e0u); Gpr(2, 0x77f62eddu); CPSR 0x20000010u ]
        [ Gpr(1, 0x9509b2a4u); Gpr(2, 0x13e2a296u); CPSR 0x900a0010u ]
        [ Gpr(1, 0x00008000u); Gpr(2, 0x7fff8000u); CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(1, 0x9a7a82bdu); CPSR 0x90000010u ]
        [ Gpr(1, 0xa8ec553au); CPSR 0x800a0010u ]
        [ Gpr(1, 0x80000000u); CPSR 0x98050010u ] ]
    check false "e0911002" inputs outputs

  /// <summary>
  /// F5.1.11 ANDS: ands r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.11 ANDS``() =
    let inputs =
      [ [ Gpr(0, 0x7aa3a745u)
          Gpr(1, 0xab00eb4au)
          Gpr(2, 0xd5214273u)
          CPSR 0x20000010u ]
        [ Gpr(0, 0xa8bc3ab5u)
          Gpr(1, 0x96fecd6fu)
          Gpr(2, 0x9b7c0c31u)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x81004242u); CPSR 0xa0000010u ]
        [ Gpr(0, 0x927c0c21u); CPSR 0x900a0010u ]
        [ Gpr(0, 0x00008000u); CPSR 0x08050010u ] ]
    check false "e0110002" inputs outputs

  /// <summary>
  /// F5.1.16 ASRS: asrs r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.16 ASRS``() =
    let inputs =
      [ [ Gpr(0, 0x80ca8f87u)
          Gpr(1, 0x99254a54u)
          Gpr(2, 0x91229f4cu)
          CPSR 0x20000010u ]
        [ Gpr(0, 0x708ba151u)
          Gpr(1, 0xbf021a22u)
          Gpr(2, 0xa5644eefu)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xffffffffu); CPSR 0xa0000010u ]
        [ Gpr(0, 0xffffffffu); CPSR 0xb00a0010u ]
        [ Gpr(0, 0x00008000u); CPSR 0x08050010u ] ]
    check false "e1b00251" inputs outputs

  /// <summary>
  /// F5.1.21 BICS: bics r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.21 BICS``() =
    let inputs =
      [ [ Gpr(0, 0x341eb3ceu)
          Gpr(1, 0x28661f69u)
          Gpr(2, 0x8a18f21cu)
          CPSR 0x20000010u ]
        [ Gpr(0, 0xf8474a15u)
          Gpr(1, 0xa65e9ae4u)
          Gpr(2, 0x5b8f94dfu)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x20660d61u); CPSR 0x20000010u ]
        [ Gpr(0, 0xa4500a20u); CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000000u); CPSR 0x48050010u ] ]
    check false "e1d10002" inputs outputs

  /// <summary>
  /// F5.1.38 CPSID: cpsid if, #0x13. This checks that from System mode it masks
  /// IRQ and FIQ and enters Supervisor mode, and that in User mode it changes
  /// nothing. It is not a value test because it needs a privileged mode, which
  /// a user-mode run does not have.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.38 CPSID``() =
    let user = runWith false "f10e00d3" [ CPSR 0x10u ] []
    let system = runWith false "f10e00d3" [ CPSR 0x1fu ] []
    Assert.AreEqual(CPSR 0x10u, user.After(CPSR 0u))
    Assert.AreEqual(CPSR 0xd3u, system.After(CPSR 0u))

  /// <summary>
  /// F5.1.38 CPSIE: cpsie i. This checks that it unmasks IRQ in Supervisor mode
  /// and that in User mode it changes nothing. It is not a value test because
  /// it needs a privileged mode, which a user-mode run does not have.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.38 CPSIE``() =
    let user = runWith false "f1080080" [ CPSR 0x90u ] []
    let svc = runWith false "f1080080" [ CPSR 0x93u ] []
    Assert.AreEqual(CPSR 0x90u, user.After(CPSR 0u))
    Assert.AreEqual(CPSR 0x13u, svc.After(CPSR 0u))

  /// <summary>
  /// F5.1.39 CRC32: crc32w r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.39 CRC32``() =
    let inputs =
      [ [ Gpr(0, 0xb0a0ae68u); Gpr(1, 0xb30c1f4au); Gpr(2, 0xddcd7798u) ]
        [ Gpr(0, 0xcbb3a351u); Gpr(1, 0x4ccfdd3au); Gpr(2, 0x3d44fd43u) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0xb27241dau) ]
        [ Gpr(0, 0xd10fa9dcu) ]
        [ Gpr(0, 0xb2ab8a5fu) ] ]
    check false "e1410042" inputs outputs

  /// <summary>
  /// F5.1.40 CRC32C: crc32cw r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.40 CRC32C``() =
    let inputs =
      [ [ Gpr(0, 0xacb3c881u); Gpr(1, 0x12dcf8f6u); Gpr(2, 0xdb37da7eu) ]
        [ Gpr(0, 0xf1bf7f82u); Gpr(1, 0xb49a5096u); Gpr(2, 0xe69c5d2fu) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x635c4a16u) ]
        [ Gpr(0, 0x9dff5660u) ]
        [ Gpr(0, 0xb0d78fd1u) ] ]
    check false "e1410242" inputs outputs

  /// <summary>
  /// F5.1.43 DCPS1: dcps1. This checks that it takes the Undefined Instruction
  /// exception. It is not a value test because it takes an exception, which a
  /// user-mode run cannot return from.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.43 DCPS1``() =
    let run = runWith true "f78f8001" [ CPSR 0x10u ] []
    Assert.AreEqual(Some SideEffect.UndefinedInstruction, run.Effect)

  /// <summary>
  /// F5.1.44 DCPS2: dcps2. This checks that it takes the Undefined Instruction
  /// exception. It is not a value test because it takes an exception, which a
  /// user-mode run cannot return from.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.44 DCPS2``() =
    let run = runWith true "f78f8002" [ CPSR 0x10u ] []
    Assert.AreEqual(Some SideEffect.UndefinedInstruction, run.Effect)

  /// <summary>
  /// F5.1.45 DCPS3: dcps3. This checks that it takes the Undefined Instruction
  /// exception. It is not a value test because it takes an exception, which a
  /// user-mode run cannot return from.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.45 DCPS3``() =
    let run = runWith true "f78f8003" [ CPSR 0x10u ] []
    Assert.AreEqual(Some SideEffect.UndefinedInstruction, run.Effect)

  /// <summary>
  /// F5.1.48 EORS: eors r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.48 EORS``() =
    let inputs =
      [ [ Gpr(0, 0x6edfdb79u)
          Gpr(1, 0x90073113u)
          Gpr(2, 0xbf5d8ea2u)
          CPSR 0x20000010u ]
        [ Gpr(0, 0xadefba22u)
          Gpr(1, 0x62ec6571u)
          Gpr(2, 0xa8355e59u)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x2f5abfb1u); CPSR 0x20000010u ]
        [ Gpr(0, 0xcad93b28u); CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff0000u); CPSR 0x08050010u ] ]
    check false "e0310002" inputs outputs

  /// <summary>
  /// F5.1.52 ESB: esb. It lifts to no statements: what it does is a hint or an
  /// ordering of memory accesses that one run cannot observe, and QEMU's runs
  /// of it changed no register and no byte, so a value test would assert
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.52 ESB``() =
    Assert.AreEqual(0, (lift false "e320f010").Length)
