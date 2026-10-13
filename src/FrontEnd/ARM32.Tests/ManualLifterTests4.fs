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
/// One test for each instruction DDI0406C and DDI0487F.c describe, F5.1.53 HLT
/// to F6.1.261 VUSMMLA in the order of their sections. A value test runs a
/// word's lifting with IRRunner over inputs QEMU ran the word on (qemu-arm -cpu
/// max) and asserts what QEMU left. A structural test is for a word a user-mode
/// run cannot execute alone; its doc comment says what it checks, and its
/// expectation is the manual's.
/// </summary>
[<TestClass>]
type ManualLifterTests4() =
  /// <summary>
  /// F5.1.53 HLT: hlt #0x0. This checks that it takes the Undefined Instruction
  /// exception. It is not a value test because it takes an exception, which a
  /// user-mode run cannot return from.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.53 HLT``() =
    let run = runWith false "e1000070" [ CPSR 0x10u ] []
    Assert.AreEqual(Some SideEffect.UndefinedInstruction, run.Effect)

  /// <summary>
  /// F5.1.57 LDA: lda r0, [r1]. The outputs are what QEMU left after running it
  /// on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.57 LDA``() =
    let inputs =
      [ [ Gpr(0, 0xac6cb53du)
          Gpr(1, 0x20000810u)
          M(0, 0x8b004b9390ed7761UL)
          M(8, 0x73e211b4d2088986UL)
          M(16, 0xfde76fb794cff7dfUL)
          M(24, 0x89d8239bebb545b4UL)
          M(32, 0x2bc961bdf65d4ac8UL)
          M(40, 0x5c790a60c63d6fdeUL)
          M(48, 0x088bf20b40c36ee9UL)
          M(56, 0x3a79cb1c02750585UL) ]
        [ Gpr(0, 0x2acb53dfu)
          Gpr(1, 0x20000810u)
          M(0, 0x0658e84db3859909UL)
          M(8, 0xf81b4fa599b662d8UL)
          M(16, 0xbf99212096a4a177UL)
          M(24, 0x7bffa19440a565b3UL)
          M(32, 0x7c11e5fa7024b9adUL)
          M(40, 0x17255f79bd570095UL)
          M(48, 0x7b68256322228c01UL)
          M(56, 0x26d047893b217db9UL) ]
        [ Gpr(0, 0x00000001u)
          Gpr(1, 0x20000810u)
          M(0, 0x0b02e0432c23d769UL)
          M(8, 0x293b766744d4abf8UL)
          M(16, 0xc136fdf86ae278d1UL)
          M(24, 0x32608776ad3bef6dUL)
          M(32, 0x256c7aba676beb9aUL)
          M(40, 0x1c5634c07fdbb03dUL)
          M(48, 0xcff3c2b88069f8beUL)
          M(56, 0x128be0f8c2609ae3UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x94cff7dfu) ]
        [ Gpr(0, 0x96a4a177u) ]
        [ Gpr(0, 0x6ae278d1u) ] ]
    check false "e1910c9f" inputs outputs

  /// <summary>
  /// F5.1.58 LDAB: ldab r0, [r1]. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.58 LDAB``() =
    let inputs =
      [ [ Gpr(0, 0xd4453508u)
          Gpr(1, 0x20000810u)
          M(0, 0x7378d890ce4d9715UL)
          M(8, 0xf9a005bf1f5981a4UL)
          M(16, 0x3b737a94a2f78917UL)
          M(24, 0x616d8ae46d8a0fe2UL)
          M(32, 0xd587238f2b555a65UL)
          M(40, 0x3ef49ff00d456e70UL)
          M(48, 0xe24a231841cc1c60UL)
          M(56, 0xdfa7f1737a67b5bdUL) ]
        [ Gpr(0, 0x15c34f02u)
          Gpr(1, 0x20000810u)
          M(0, 0x2d8bf49635d52bb1UL)
          M(8, 0x76399fac73960f98UL)
          M(16, 0xf00cde1cbc5639efUL)
          M(24, 0x1721be047c9c4b1dUL)
          M(32, 0x475ddd175ca85595UL)
          M(40, 0xaf5f079cd6d295efUL)
          M(48, 0x453573308350180aUL)
          M(56, 0x5590a9a6a66b9859UL) ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x20000810u)
          M(0, 0xcead6442205674f2UL)
          M(8, 0xd73fa58bd7df408eUL)
          M(16, 0xb85aeb4480a00b12UL)
          M(24, 0x43d46f220d9ace7aUL)
          M(32, 0xf0c3a80f665ab849UL)
          M(40, 0x565831cdd08f7f1cUL)
          M(48, 0xd2f5120af3769c17UL)
          M(56, 0x0f2362c1a0bbe142UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000017u) ]
        [ Gpr(0, 0x000000efu) ]
        [ Gpr(0, 0x00000012u) ] ]
    check false "e1d10c9f" inputs outputs

  /// <summary>
  /// F5.1.59 LDAEX: ldaex r0, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.59 LDAEX``() =
    let inputs =
      [ [ Gpr(0, 0x4747fd80u)
          Gpr(1, 0x20000810u)
          M(0, 0x431387fb287f6869UL)
          M(8, 0x4d62f208f767c9e5UL)
          M(16, 0x83f16a5144a3ddd2UL)
          M(24, 0xdbbf81ea265b1416UL)
          M(32, 0x8aca65872249effeUL)
          M(40, 0xd93dc6ba6e8d6971UL)
          M(48, 0x169cb7a7f32fb07cUL)
          M(56, 0x66512233f0c55e37UL) ]
        [ Gpr(0, 0x762104d5u)
          Gpr(1, 0x20000810u)
          M(0, 0xf426adb8c2abf523UL)
          M(8, 0x3a34996ff8362d25UL)
          M(16, 0xec83763e5d34ae15UL)
          M(24, 0xb7db87e072096a20UL)
          M(32, 0x9e589d07dcb902cdUL)
          M(40, 0xdc30d339f68b860eUL)
          M(48, 0xe3ead63899e97a46UL)
          M(56, 0x70f94e665d5bc2acUL) ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x20000810u)
          M(0, 0xc067f0dab4cce439UL)
          M(8, 0x473c4831e7f0dcd7UL)
          M(16, 0x1bd7c27730747de6UL)
          M(24, 0xefd142a78af3605bUL)
          M(32, 0xee778cf1f654ef95UL)
          M(40, 0x04db71d60049bbe6UL)
          M(48, 0x2caa2c2409a181e1UL)
          M(56, 0xd926085cacaf7892UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x44a3ddd2u) ]
        [ Gpr(0, 0x5d34ae15u) ]
        [ Gpr(0, 0x30747de6u) ] ]
    check false "e1910e9f" inputs outputs

  /// <summary>
  /// F5.1.60 LDAEXB: ldaexb r0, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.60 LDAEXB``() =
    let inputs =
      [ [ Gpr(0, 0xfc23ed22u)
          Gpr(1, 0x20000810u)
          M(0, 0xea20288267de4569UL)
          M(8, 0xb6e974e9192f7a6aUL)
          M(16, 0xd7ca8ba94bb46d6bUL)
          M(24, 0xd1bb8d23b716a13eUL)
          M(32, 0x297e83bd5dde45b8UL)
          M(40, 0x002e4d5ffc10eb4eUL)
          M(48, 0x19e1e4e1f3fc14acUL)
          M(56, 0xad2eb0a1a69f2e3dUL) ]
        [ Gpr(0, 0x5ddd5ea5u)
          Gpr(1, 0x20000810u)
          M(0, 0xd37c4f3a8a5090d0UL)
          M(8, 0xf31960aa1cf09387UL)
          M(16, 0xc260218a80e355f4UL)
          M(24, 0xca8841804d380ca7UL)
          M(32, 0xf1e26b24ad746135UL)
          M(40, 0xaf421dd75d10be04UL)
          M(48, 0xe226442ae2cae371UL)
          M(56, 0x204ccd33917b3857UL) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x20000810u)
          M(0, 0x72fbd22c8415078bUL)
          M(8, 0x665f65541768fb9eUL)
          M(16, 0x95a6918b359530daUL)
          M(24, 0xb3ffd885ab0b0b3fUL)
          M(32, 0x6e4d3eea8f9db82dUL)
          M(40, 0xdaa54e99aceb1a37UL)
          M(48, 0xaa88968987aa0085UL)
          M(56, 0x0d515394805d8e06UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x0000006bu) ]
        [ Gpr(0, 0x000000f4u) ]
        [ Gpr(0, 0x000000dau) ] ]
    check false "e1d10e9f" inputs outputs

  /// <summary>
  /// F5.1.61 LDAEXD: ldaexd r2, r3, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.61 LDAEXD``() =
    let inputs =
      [ [ Gpr(1, 0x20000810u)
          Gpr(2, 0xb8347b47u)
          Gpr(3, 0xf295b6a7u)
          M(0, 0xb6643a8edd40d07dUL)
          M(8, 0xf46aeaae9278b9beUL)
          M(16, 0xfd1347ab353732d6UL)
          M(24, 0x470e6e7f5f14dbd9UL)
          M(32, 0xbca2c1c9ef5f2330UL)
          M(40, 0xa74ef2477aa2499fUL)
          M(48, 0x0b49ee4bc90f3385UL)
          M(56, 0x21e70c227ab40f52UL) ]
        [ Gpr(1, 0x20000810u)
          Gpr(2, 0x18d1edbau)
          Gpr(3, 0xbdc3b9cau)
          M(0, 0xdb5b8cd70f3a2964UL)
          M(8, 0x131cacbcfdbb87d7UL)
          M(16, 0x7ae3918085605be4UL)
          M(24, 0x06455c73d567a4baUL)
          M(32, 0xd42e35c421839d81UL)
          M(40, 0x107343da379a542aUL)
          M(48, 0x9130c37d47b8894bUL)
          M(56, 0x254f2e61293a556fUL) ]
        [ Gpr(1, 0x20000810u)
          Gpr(2, 0x80007fffu)
          Gpr(3, 0x00000003u)
          M(0, 0x7fe72312bc23d034UL)
          M(8, 0xa03c6720b8ce486cUL)
          M(16, 0x3cbac98f8ffc9792UL)
          M(24, 0x6dd3012892418cd0UL)
          M(32, 0xa55fbb213a774460UL)
          M(40, 0xd071f118442f7085UL)
          M(48, 0x3f930a3689efb2eeUL)
          M(56, 0x24842035e61ff0eaUL) ] ]
    let outputs =
      [ [ Gpr(2, 0x353732d6u); Gpr(3, 0xfd1347abu) ]
        [ Gpr(2, 0x85605be4u); Gpr(3, 0x7ae39180u) ]
        [ Gpr(2, 0x8ffc9792u); Gpr(3, 0x3cbac98fu) ] ]
    check false "e1b12e9f" inputs outputs

  /// <summary>
  /// F5.1.62 LDAEXH: ldaexh r0, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.62 LDAEXH``() =
    let inputs =
      [ [ Gpr(0, 0x47b9cb5cu)
          Gpr(1, 0x20000810u)
          M(0, 0x88345a8fd4705317UL)
          M(8, 0x07ade15b2df0e021UL)
          M(16, 0x4dac23be7981296aUL)
          M(24, 0xde3d66891ce1f9e1UL)
          M(32, 0x5352f1f061e4d06aUL)
          M(40, 0xc3809b9ee895799eUL)
          M(48, 0x78cc97a9a4b4a798UL)
          M(56, 0x29efcc8610dc7bd9UL) ]
        [ Gpr(0, 0xa6cfdd75u)
          Gpr(1, 0x20000810u)
          M(0, 0x338fdf2c32b2e7a2UL)
          M(8, 0x3692663cff2b22e3UL)
          M(16, 0x6649400a1dfa480cUL)
          M(24, 0x80635b671a9d2730UL)
          M(32, 0x3086f73d21a2ec00UL)
          M(40, 0x12bb8de606f3cffeUL)
          M(48, 0x843458580782ce77UL)
          M(56, 0xe7ec411335fd8457UL) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x20000810u)
          M(0, 0xcbc52b25a5d11ce6UL)
          M(8, 0xa4ed7c1de58e0c2dUL)
          M(16, 0xebed2e4f45a3a5c9UL)
          M(24, 0x7c219b388e9e9692UL)
          M(32, 0x6d7182e1f5d1e62eUL)
          M(40, 0x7be9ead5b558c480UL)
          M(48, 0xbbb16cbad272831bUL)
          M(56, 0xe16c82658f89091fUL) ] ]
    let outputs =
      [ [ Gpr(0, 0x0000296au) ]
        [ Gpr(0, 0x0000480cu) ]
        [ Gpr(0, 0x0000a5c9u) ] ]
    check false "e1f10e9f" inputs outputs

  /// <summary>
  /// F5.1.63 LDAH: ldah r0, [r1]. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.63 LDAH``() =
    let inputs =
      [ [ Gpr(0, 0x0854d596u)
          Gpr(1, 0x20000810u)
          M(0, 0xd7541156748800ddUL)
          M(8, 0x9bb5f1e8772363b5UL)
          M(16, 0xf29ad30572e180deUL)
          M(24, 0xab9c5edad865463fUL)
          M(32, 0x7b7cc69fe967595bUL)
          M(40, 0xb7e60b36d10c49dfUL)
          M(48, 0x2c58eff058679d1aUL)
          M(56, 0xedbce3d295fa9d52UL) ]
        [ Gpr(0, 0x2fae49cdu)
          Gpr(1, 0x20000810u)
          M(0, 0x1b4c20db47480c99UL)
          M(8, 0x09dbd2206d8117edUL)
          M(16, 0x0c847734c7155c52UL)
          M(24, 0xa920d05af68707bdUL)
          M(32, 0x32a8f7fa26ee538aUL)
          M(40, 0x03febb036d1b3483UL)
          M(48, 0xfaf8aefa121645abUL)
          M(56, 0x627ae52e0e22e083UL) ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x20000810u)
          M(0, 0x8d97cb016e10d645UL)
          M(8, 0x396c81ac075d2345UL)
          M(16, 0xe91c96880b9b3609UL)
          M(24, 0x1127c71c67ee6d65UL)
          M(32, 0x629574c5c75093d7UL)
          M(40, 0x59bc8ebeac7bfbb7UL)
          M(48, 0x59a542dae6bac8e2UL)
          M(56, 0x7c170edf3358e96bUL) ] ]
    let outputs =
      [ [ Gpr(0, 0x000080deu) ]
        [ Gpr(0, 0x00005c52u) ]
        [ Gpr(0, 0x00003609u) ] ]
    check false "e1f10c9f" inputs outputs

  /// <summary>
  /// F5.1.101 LSLS: lsls r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.101 LSLS``() =
    let inputs =
      [ [ Gpr(0, 0x127f9ab7u)
          Gpr(1, 0x72fd49bau)
          Gpr(2, 0xdf57764eu)
          CPSR 0x20000010u ]
        [ Gpr(0, 0x3b7e7eabu)
          Gpr(1, 0x17ae87abu)
          Gpr(2, 0xb04dfda2u)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x00000000u); CPSR 0x40000010u ]
        [ Gpr(0, 0x00000000u); CPSR 0x500a0010u ]
        [ Gpr(0, 0x00008000u); CPSR 0x08050010u ] ]
    check false "e1b00211" inputs outputs

  /// <summary>
  /// F5.1.105 LSRS: lsrs r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.105 LSRS``() =
    let inputs =
      [ [ Gpr(0, 0xe9158f30u)
          Gpr(1, 0xf193ce01u)
          Gpr(2, 0xc4dc0d77u)
          CPSR 0x20000010u ]
        [ Gpr(0, 0xab431617u)
          Gpr(1, 0x0f098ce6u)
          Gpr(2, 0x8081724du)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x00000000u); CPSR 0x40000010u ]
        [ Gpr(0, 0x00000000u); CPSR 0x500a0010u ]
        [ Gpr(0, 0x00008000u); CPSR 0x08050010u ] ]
    check false "e1b00231" inputs outputs

  /// <summary>
  /// F5.1.109 MLAS: mlas r0, r1, r2, r3. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.109 MLAS``() =
    let inputs =
      [ [ Gpr(0, 0xeab26a87u)
          Gpr(1, 0xf491cc6fu)
          Gpr(2, 0x605eb262u)
          Gpr(3, 0x27c4ed70u)
          CPSR 0x20000010u ]
        [ Gpr(0, 0xed5fcc86u)
          Gpr(1, 0xe493c995u)
          Gpr(2, 0xc7c36a96u)
          Gpr(3, 0x8a3f9853u)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          Gpr(3, 0x00000000u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xd87c5deeu); CPSR 0xa0000010u ]
        [ Gpr(0, 0x09ce67a1u); CPSR 0x100a0010u ]
        [ Gpr(0, 0xc0000000u); CPSR 0x88050010u ] ]
    check false "e0303291" inputs outputs

  /// <summary>
  /// F5.1.111 MOVS: movs r0, r2. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.111 MOVS``() =
    let inputs =
      [ [ Gpr(0, 0xa307d6edu); Gpr(2, 0x98895201u); CPSR 0x20000010u ]
        [ Gpr(0, 0x73cacb81u); Gpr(2, 0x94ff1792u); CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu); Gpr(2, 0x7fff8000u); CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x98895201u); CPSR 0xa0000010u ]
        [ Gpr(0, 0x94ff1792u); CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u); CPSR 0x08050010u ] ]
    check false "e1b00002" inputs outputs

  /// <summary>
  /// F5.1.122 MULS: muls r0, r1, r0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.122 MULS``() =
    let inputs =
      [ [ Gpr(0, 0x16ee9265u); Gpr(1, 0x7ead47a3u); CPSR 0x20000010u ]
        [ Gpr(0, 0x160d463bu); Gpr(1, 0xbef02b60u); CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u); CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x68c2394fu); CPSR 0x20000010u ]
        [ Gpr(0, 0x21163f20u); CPSR 0x100a0010u ]
        [ Gpr(0, 0x7fff8000u); CPSR 0x08050010u ] ]
    check false "e0100091" inputs outputs

  /// <summary>
  /// F5.1.123 MVNS: mvns r0, r2. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.123 MVNS``() =
    let inputs =
      [ [ Gpr(0, 0xc4521089u); Gpr(2, 0x39ccc950u); CPSR 0x20000010u ]
        [ Gpr(0, 0x7ba83cc8u); Gpr(2, 0xe9c40ac5u); CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu); Gpr(2, 0x7fff8000u); CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xc63336afu); CPSR 0xa0000010u ]
        [ Gpr(0, 0x163bf53au); CPSR 0x100a0010u ]
        [ Gpr(0, 0x80007fffu); CPSR 0x88050010u ] ]
    check false "e1f00002" inputs outputs

  /// <summary>
  /// F5.1.127 ORNS: orns r0, r1, #0xff000000. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.127 ORNS``() =
    let inputs =
      [ [ Gpr(0, 0x2e5f1036u); Gpr(1, 0x368dfffbu); CPSR 0x20000010u ]
        [ Gpr(0, 0xcda2aedeu); Gpr(1, 0x4f1c5636u); CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u); CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x36ffffffu); CPSR 0x20000010u ]
        [ Gpr(0, 0x4fffffffu); CPSR 0x300a0010u ]
        [ Gpr(0, 0x00ffffffu); CPSR 0x28050010u ] ]
    check true "f071407f" inputs outputs

  /// <summary>
  /// F5.1.129 ORRS: orrs r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.129 ORRS``() =
    let inputs =
      [ [ Gpr(0, 0x95db05a9u)
          Gpr(1, 0x32ff4ff2u)
          Gpr(2, 0x2b0c52e8u)
          CPSR 0x20000010u ]
        [ Gpr(0, 0x7afdbde2u)
          Gpr(1, 0xfa992fa7u)
          Gpr(2, 0x32d88184u)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x3bff5ffau); CPSR 0x20000010u ]
        [ Gpr(0, 0xfad9afa7u); CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u); CPSR 0x08050010u ] ]
    check false "e1910002" inputs outputs

  /// <summary>
  /// F5.1.132 PKHBT: pkhbt r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.132 PKHBT``() =
    let inputs =
      [ [ Gpr(0, 0x651f4ec7u); Gpr(1, 0xf1f5128bu); Gpr(2, 0x819d5405u) ]
        [ Gpr(0, 0x33bd8588u); Gpr(1, 0x1d29c8c5u); Gpr(2, 0xa95372deu) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x819d128bu) ]
        [ Gpr(0, 0xa953c8c5u) ]
        [ Gpr(0, 0x00008000u) ] ]
    check false "e6810012" inputs outputs

  /// <summary>
  /// F5.1.132 PKHTB: pkhtb r0, r1, r2, asr #0x4. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.132 PKHTB``() =
    let inputs =
      [ [ Gpr(0, 0xb5c7e303u); Gpr(1, 0xde1d9837u); Gpr(2, 0x4d9d59f6u) ]
        [ Gpr(0, 0x0f03b4dfu); Gpr(1, 0xee868f08u); Gpr(2, 0x40f9e1f6u) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0xde1dd59fu) ]
        [ Gpr(0, 0xee869e1fu) ]
        [ Gpr(0, 0x7fff0000u) ] ]
    check false "e6810252" inputs outputs

  /// <summary>
  /// F5.1.141 PSSBB: pssbb. It lifts to no statements: what it does is a hint
  /// or an ordering of memory accesses that one run cannot observe, and QEMU's
  /// runs of it changed no register and no byte, so a value test would assert
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.141 PSSBB``() =
    Assert.AreEqual(0, (lift false "f57ff044").Length)

  /// <summary>
  /// F5.1.159 RFEDA: rfeda r1!. This checks, in Supervisor mode with Rn
  /// pointing at a return address of 0x30003000 and a saved CPSR of 0x20000010,
  /// that it returns there with that CPSR and writes Rn back, and that User and
  /// Hyp mode refuse it. It is not a value test because it needs a privileged
  /// mode, which a user-mode run does not have.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.159 RFEDA``() =
    let w = uint32 Window
    let cells = [ Gpr(1, w + 20u); M(16, 0x2000001030003000UL) ]
    let run = runWith false "f8310a00" (CPSR 0x13u :: cells) []
    let refused = refusedModes false "f8310a00" cells []
    CollectionAssert.AreEqual([| 0x10u; 0x1au |], refused)
    Assert.AreEqual(Some 0x30003000UL, run.Target)
    Assert.AreEqual(CPSR 0x20000010u, run.After(CPSR 0u))
    Assert.AreEqual(Gpr(1, w + 12u), run.After(Gpr(1, 0u)))

  /// <summary>
  /// F5.1.159 RFEDB: rfedb r1. This checks, in Supervisor mode with Rn pointing
  /// at a return address of 0x30003000 and a saved CPSR of 0x20000010, that it
  /// returns there with that CPSR and leaves Rn, and that User and Hyp mode
  /// refuse it. It is not a value test because it needs a privileged mode,
  /// which a user-mode run does not have.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.159 RFEDB``() =
    let w = uint32 Window
    let cells = [ Gpr(1, w + 24u); M(16, 0x2000001030003000UL) ]
    let run = runWith false "f9110a00" (CPSR 0x13u :: cells) []
    let refused = refusedModes false "f9110a00" cells []
    CollectionAssert.AreEqual([| 0x10u; 0x1au |], refused)
    Assert.AreEqual(Some 0x30003000UL, run.Target)
    Assert.AreEqual(CPSR 0x20000010u, run.After(CPSR 0u))
    Assert.AreEqual(Gpr(1, w + 24u), run.After(Gpr(1, 0u)))

  /// <summary>
  /// F5.1.159 RFEIA: rfeia r1. This checks, in Supervisor mode with Rn pointing
  /// at a return address of 0x30003000 and a saved CPSR of 0x20000010, that it
  /// returns there with that CPSR and leaves Rn, and that User and Hyp mode
  /// refuse it. It is not a value test because it needs a privileged mode,
  /// which a user-mode run does not have.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.159 RFEIA``() =
    let w = uint32 Window
    let cells = [ Gpr(1, w + 16u); M(16, 0x2000001030003000UL) ]
    let run = runWith false "f8910a00" (CPSR 0x13u :: cells) []
    let refused = refusedModes false "f8910a00" cells []
    CollectionAssert.AreEqual([| 0x10u; 0x1au |], refused)
    Assert.AreEqual(Some 0x30003000UL, run.Target)
    Assert.AreEqual(CPSR 0x20000010u, run.After(CPSR 0u))
    Assert.AreEqual(Gpr(1, w + 16u), run.After(Gpr(1, 0u)))

  /// <summary>
  /// F5.1.159 RFEIB: rfeib r1!. This checks, in Supervisor mode with Rn
  /// pointing at a return address of 0x30003000 and a saved CPSR of 0x20000010,
  /// that it returns there with that CPSR and writes Rn back, and that User and
  /// Hyp mode refuse it. It is not a value test because it needs a privileged
  /// mode, which a user-mode run does not have.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.159 RFEIB``() =
    let w = uint32 Window
    let cells = [ Gpr(1, w + 12u); M(16, 0x2000001030003000UL) ]
    let run = runWith false "f9b10a00" (CPSR 0x13u :: cells) []
    let refused = refusedModes false "f9b10a00" cells []
    CollectionAssert.AreEqual([| 0x10u; 0x1au |], refused)
    Assert.AreEqual(Some 0x30003000UL, run.Target)
    Assert.AreEqual(CPSR 0x20000010u, run.After(CPSR 0u))
    Assert.AreEqual(Gpr(1, w + 20u), run.After(Gpr(1, 0u)))

  /// <summary>
  /// F5.1.162 RORS: rors r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.162 RORS``() =
    let inputs =
      [ [ Gpr(0, 0xd3b7a8c8u)
          Gpr(1, 0x3a2e2979u)
          Gpr(2, 0xc84ed0cbu)
          CPSR 0x20000010u ]
        [ Gpr(0, 0x5cf14666u)
          Gpr(1, 0xa39709eau)
          Gpr(2, 0x14978227u)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x2f2745c5u); CPSR 0x00000010u ]
        [ Gpr(0, 0xd5472e13u); CPSR 0xb00a0010u ]
        [ Gpr(0, 0x00008000u); CPSR 0x08050010u ] ]
    check false "e1b00271" inputs outputs

  /// <summary>
  /// F5.1.165 RRXS: rrxs r0, r2. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.165 RRXS``() =
    let inputs =
      [ [ Gpr(0, 0x0e0b7e93u); Gpr(2, 0x3d4894afu); CPSR 0x20000010u ]
        [ Gpr(0, 0x2ce1528fu); Gpr(2, 0x2ad2fafbu); CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu); Gpr(2, 0x7fff8000u); CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x9ea44a57u); CPSR 0xa0000010u ]
        [ Gpr(0, 0x15697d7du); CPSR 0x300a0010u ]
        [ Gpr(0, 0x3fffc000u); CPSR 0x08050010u ] ]
    check false "e1b00062" inputs outputs

  /// <summary>
  /// F5.1.166 RSBS: rsbs r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.166 RSBS``() =
    let inputs =
      [ [ Gpr(0, 0xa060791eu)
          Gpr(1, 0xdb5d00feu)
          Gpr(2, 0x42a62fbeu)
          CPSR 0x20000010u ]
        [ Gpr(0, 0xad30a34fu)
          Gpr(1, 0xff4681e0u)
          Gpr(2, 0x277ab335u)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x67492ec0u); CPSR 0x00000010u ]
        [ Gpr(0, 0x28343155u); CPSR 0x000a0010u ]
        [ Gpr(0, 0x7fff0000u); CPSR 0x28050010u ] ]
    check false "e0710002" inputs outputs

  /// <summary>
  /// F5.1.169 RSCS: rscs r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.169 RSCS``() =
    let inputs =
      [ [ Gpr(0, 0x497d7e21u)
          Gpr(1, 0x3ef13624u)
          Gpr(2, 0xaea1de77u)
          CPSR 0x20000010u ]
        [ Gpr(0, 0xb6abc075u)
          Gpr(1, 0x93a7c607u)
          Gpr(2, 0x4666882au)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x6fb0a853u); CPSR 0x30000010u ]
        [ Gpr(0, 0xb2bec222u); CPSR 0x900a0010u ]
        [ Gpr(0, 0x7ffeffffu); CPSR 0x28050010u ] ]
    check false "e0f10002" inputs outputs

  /// <summary>
  /// F5.1.175 SB: sb. It lifts to no statements: what it does is a hint or an
  /// ordering of memory accesses that one run cannot observe, and QEMU's runs
  /// of it changed no register and no byte, so a value test would assert
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.175 SB``() =
    Assert.AreEqual(0, (lift false "f57ff070").Length)

  /// <summary>
  /// F5.1.176 SBCS: sbcs r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.176 SBCS``() =
    let inputs =
      [ [ Gpr(0, 0xaac4e759u)
          Gpr(1, 0x3205efc7u)
          Gpr(2, 0x35d6269bu)
          CPSR 0x20000010u ]
        [ Gpr(0, 0x442bd01eu)
          Gpr(1, 0x81d4761cu)
          Gpr(2, 0x2927232fu)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xfc2fc92cu); CPSR 0x80000010u ]
        [ Gpr(0, 0x58ad52ecu); CPSR 0x300a0010u ]
        [ Gpr(0, 0x8000ffffu); CPSR 0x88050010u ] ]
    check false "e0d10002" inputs outputs

  /// <summary>
  /// F5.1.183 SETPAN: setpan #0x0. This checks that it clears PAN, CPSR bit 22,
  /// in Supervisor mode and changes nothing in User mode. It is not a value
  /// test because it needs a privileged mode, which a user-mode run does not
  /// have.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.183 SETPAN``() =
    let svc = runWith false "f1100000" [ CPSR 0x00400013u ] []
    let user = runWith false "f1100000" [ CPSR 0x00400010u ] []
    Assert.AreEqual(CPSR 0x13u, svc.After(CPSR 0u))
    Assert.AreEqual(CPSR 0x00400010u, user.After(CPSR 0u))

  /// <summary>
  /// F5.1.185 SEVL: sevl. It lifts to no statements: what it does is a hint or
  /// an ordering of memory accesses that one run cannot observe, and QEMU's
  /// runs of it changed no register and no byte, so a value test would assert
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.185 SEVL``() =
    Assert.AreEqual(0, (lift false "e320f005").Length)

  /// <summary>
  /// F5.1.194 SMLADX: smladx r0, r1, r2, r3. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.194 SMLADX``() =
    let inputs =
      [ [ Gpr(0, 0xb24614aeu)
          Gpr(1, 0x42f23ad5u)
          Gpr(2, 0xdf0e10f9u)
          Gpr(3, 0x0b494391u)
          CPSR 0x20000010u ]
        [ Gpr(0, 0x4781606fu)
          Gpr(1, 0x1e6de73du)
          Gpr(2, 0x5cec20c1u)
          Gpr(3, 0xf6e7ba9au)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Gpr(3, 0x00000003u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x08274399u); CPSR 0x20000010u ]
        [ Gpr(0, 0xf1cf6303u); CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000003u); CPSR 0x48050010u ] ]
    check false "e7003231" inputs outputs

  /// <summary>
  /// F5.1.195 SMLALS: smlals r0, r1, r1, r2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.195 SMLALS``() =
    let inputs =
      [ [ Gpr(0, 0x92c7c486u)
          Gpr(1, 0x6bff063bu)
          Gpr(2, 0x4e27cf92u)
          CPSR 0x20000010u ]
        [ Gpr(0, 0x052b10d5u)
          Gpr(1, 0xd71eccaau)
          Gpr(2, 0x7deadc49u)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x4d40072cu); Gpr(1, 0x8cf7858cu); CPSR 0xa0000010u ]
        [ Gpr(0, 0xea39854fu); Gpr(1, 0xc3035592u); CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); CPSR 0x08050010u ] ]
    check false "e0f10291" inputs outputs

  /// <summary>
  /// F5.1.197 SMLALDX: smlaldx r0, r1, r1, r2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.197 SMLALDX``() =
    let inputs =
      [ [ Gpr(0, 0x44c55ba1u); Gpr(1, 0x873ea598u); Gpr(2, 0xb39bfc44u) ]
        [ Gpr(0, 0xfb93980eu); Gpr(1, 0x2e4310d6u); Gpr(2, 0xf5bff92bu) ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x80007fffu); Gpr(2, 0x00000003u) ] ]
    let outputs =
      [ [ Gpr(0, 0x6182db21u); Gpr(1, 0x873ea598u) ]
        [ Gpr(0, 0xf9aae5f9u); Gpr(1, 0x2e4310d6u) ]
        [ Gpr(0, 0xfffe8000u); Gpr(1, 0x80007ffeu) ] ]
    check false "e7410231" inputs outputs

  /// <summary>
  /// F5.1.199 SMLSDX: smlsdx r0, r1, r2, r3. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.199 SMLSDX``() =
    let inputs =
      [ [ Gpr(0, 0x0e9fa437u)
          Gpr(1, 0x2f9693b6u)
          Gpr(2, 0x1f244528u)
          Gpr(3, 0xcbeb9180u)
          CPSR 0x20000010u ]
        [ Gpr(0, 0x6969af05u)
          Gpr(1, 0xa6ce18fdu)
          Gpr(2, 0x9fc2f862u)
          Gpr(3, 0xfb3af588u)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Gpr(3, 0x00000003u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xb1e483a8u); CPSR 0x20000010u ]
        [ Gpr(0, 0xef2e9d66u); CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000003u); CPSR 0x48050010u ] ]
    check false "e7003271" inputs outputs

  /// <summary>
  /// F5.1.200 SMLSLDX: smlsldx r0, r1, r1, r2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.200 SMLSLDX``() =
    let inputs =
      [ [ Gpr(0, 0x2e98da76u); Gpr(1, 0x1d7f8941u); Gpr(2, 0x3a3dd73bu) ]
        [ Gpr(0, 0xe6504e09u); Gpr(1, 0x5ecbe29bu); Gpr(2, 0xe465b5b6u) ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x80007fffu); Gpr(2, 0x00000003u) ] ]
    let outputs =
      [ [ Gpr(0, 0x1847d3aeu); Gpr(1, 0x1d7f8941u) ]
        [ Gpr(0, 0x04fdd5deu); Gpr(1, 0x5ecbe29cu) ]
        [ Gpr(0, 0x00018000u); Gpr(1, 0x80007fffu) ] ]
    check false "e7410271" inputs outputs

  /// <summary>
  /// F5.1.201 SMMLAR: smmlar r0, r1, r2, r3. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.201 SMMLAR``() =
    let inputs =
      [ [ Gpr(0, 0xdc7fb691u)
          Gpr(1, 0x6d29f3c7u)
          Gpr(2, 0xec478b80u)
          Gpr(3, 0x7e71af99u) ]
        [ Gpr(0, 0xa9852b83u)
          Gpr(1, 0xad5b0a77u)
          Gpr(2, 0x2704fdbeu)
          Gpr(3, 0xc5506a53u) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Gpr(3, 0x00000003u) ] ]
    let outputs =
      [ [ Gpr(0, 0x7608eaacu) ]
        [ Gpr(0, 0xb8b7ac6du) ]
        [ Gpr(0, 0x00000003u) ] ]
    check false "e7503231" inputs outputs

  /// <summary>
  /// F5.1.202 SMMLSR: smmlsr r0, r1, r2, r3. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.202 SMMLSR``() =
    let inputs =
      [ [ Gpr(0, 0x74aec40cu)
          Gpr(1, 0xf314f8a5u)
          Gpr(2, 0x8af4a257u)
          Gpr(3, 0xc5b98782u) ]
        [ Gpr(0, 0xa754d049u)
          Gpr(1, 0x056429a4u)
          Gpr(2, 0x1f0557eau)
          Gpr(3, 0x0b761c79u) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Gpr(3, 0x00000003u) ] ]
    let outputs =
      [ [ Gpr(0, 0xbfd18a52u) ]
        [ Gpr(0, 0x0acede9fu) ]
        [ Gpr(0, 0x00000003u) ] ]
    check false "e75032f1" inputs outputs

  /// <summary>
  /// F5.1.203 SMMULR: smmulr r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.203 SMMULR``() =
    let inputs =
      [ [ Gpr(0, 0xe4647335u); Gpr(1, 0x6ef30c77u); Gpr(2, 0xbc8c763bu) ]
        [ Gpr(0, 0x28885e34u); Gpr(1, 0x0ac65edeu); Gpr(2, 0x263ce5cau) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0xe2c450d9u) ]
        [ Gpr(0, 0x019c023fu) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e750f231" inputs outputs

  /// <summary>
  /// F5.1.204 SMUADX: smuadx r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.204 SMUADX``() =
    let inputs =
      [ [ Gpr(0, 0x27aef3d8u)
          Gpr(1, 0x9bc0f2d1u)
          Gpr(2, 0xfb978b4bu)
          CPSR 0x20000010u ]
        [ Gpr(0, 0x8ee3583bu)
          Gpr(1, 0x67ffee36u)
          Gpr(2, 0x8772f330u)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x2dee0587u); CPSR 0x20000010u ]
        [ Gpr(0, 0x032c1adcu); CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000000u); CPSR 0x48050010u ] ]
    check false "e700f231" inputs outputs

  /// <summary>
  /// F5.1.206 SMULLS: smulls r0, r1, r1, r2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.206 SMULLS``() =
    let inputs =
      [ [ Gpr(0, 0xbfd54adeu)
          Gpr(1, 0x58a0b338u)
          Gpr(2, 0x45363553u)
          CPSR 0x20000010u ]
        [ Gpr(0, 0x843eddaeu)
          Gpr(1, 0xffd1f2a1u)
          Gpr(2, 0x7b3ab53bu)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xe704b328u); Gpr(1, 0x17f614a9u); CPSR 0x20000010u ]
        [ Gpr(0, 0xb968c01bu); Gpr(1, 0xffe9d503u); CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x00000000u); CPSR 0x48050010u ] ]
    check false "e0d10291" inputs outputs

  /// <summary>
  /// F5.1.208 SMUSDX: smusdx r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.208 SMUSDX``() =
    let inputs =
      [ [ Gpr(0, 0xddaee962u); Gpr(1, 0xbe98fd38u); Gpr(2, 0x0d92d24fu) ]
        [ Gpr(0, 0x695fc06au); Gpr(1, 0xafd92535u); Gpr(2, 0x7f6dfa38u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0xf42dc108u) ]
        [ Gpr(0, 0x10b5c119u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e700f271" inputs outputs

  /// <summary>
  /// F5.1.209 SRSDA: srsda sp, #0x13. This checks, from IRQ mode with SP_svc
  /// pointing into memory, that it stores LR then SPSR on Supervisor mode's
  /// stack and leaves SP_svc, and that User, Hyp and System mode refuse it. It
  /// is not a value test because it needs a privileged mode, which a user-mode
  /// run does not have.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.209 SRSDA``() =
    let w = uint32 Window
    let others =
      [ Register.LR, 0x11112222u
        Register.SPSR, 0x600001d3u
        Register.SP, w + 20u
        Register.SPsvc, w + 20u ]
    let cells = [ M(16, 0UL) ]
    let run = runWith false "f84d0513" (CPSR 0x12u :: cells) others
    let refused = refusedModes false "f84d0513" cells others
    CollectionAssert.AreEqual([| 0x10u; 0x1au; 0x1fu |], refused)
    Assert.AreEqual(M(16, 0x600001d311112222UL), run.After(M(16, 0UL)))
    Assert.AreEqual(w + 20u, run.Reg Register.SPsvc)

  /// <summary>
  /// F5.1.209 SRSDB: srsdb sp!, #0x13. This checks, from IRQ mode with SP_svc
  /// pointing into memory, that it stores LR then SPSR on Supervisor mode's
  /// stack and writes SP_svc back, and that User, Hyp and System mode refuse
  /// it. It is not a value test because it needs a privileged mode, which a
  /// user-mode run does not have.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.209 SRSDB``() =
    let w = uint32 Window
    let others =
      [ Register.LR, 0x11112222u
        Register.SPSR, 0x600001d3u
        Register.SP, w + 24u
        Register.SPsvc, w + 24u ]
    let cells = [ M(16, 0UL) ]
    let run = runWith false "f96d0513" (CPSR 0x12u :: cells) others
    let refused = refusedModes false "f96d0513" cells others
    CollectionAssert.AreEqual([| 0x10u; 0x1au; 0x1fu |], refused)
    Assert.AreEqual(M(16, 0x600001d311112222UL), run.After(M(16, 0UL)))
    Assert.AreEqual(w + 16u, run.Reg Register.SPsvc)

  /// <summary>
  /// F5.1.209 SRSIA: srsia sp, #0x13. This checks, from IRQ mode with SP_svc
  /// pointing into memory, that it stores LR then SPSR on Supervisor mode's
  /// stack and leaves SP_svc, and that User, Hyp and System mode refuse it. It
  /// is not a value test because it needs a privileged mode, which a user-mode
  /// run does not have.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.209 SRSIA``() =
    let w = uint32 Window
    let others =
      [ Register.LR, 0x11112222u
        Register.SPSR, 0x600001d3u
        Register.SP, w + 16u
        Register.SPsvc, w + 16u ]
    let cells = [ M(16, 0UL) ]
    let run = runWith false "f8cd0513" (CPSR 0x12u :: cells) others
    let refused = refusedModes false "f8cd0513" cells others
    CollectionAssert.AreEqual([| 0x10u; 0x1au; 0x1fu |], refused)
    Assert.AreEqual(M(16, 0x600001d311112222UL), run.After(M(16, 0UL)))
    Assert.AreEqual(w + 16u, run.Reg Register.SPsvc)

  /// <summary>
  /// F5.1.209 SRSIB: srsib sp, #0x13. This checks, from IRQ mode with SP_svc
  /// pointing into memory, that it stores LR then SPSR on Supervisor mode's
  /// stack and leaves SP_svc, and that User, Hyp and System mode refuse it. It
  /// is not a value test because it needs a privileged mode, which a user-mode
  /// run does not have.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.209 SRSIB``() =
    let w = uint32 Window
    let others =
      [ Register.LR, 0x11112222u
        Register.SPSR, 0x600001d3u
        Register.SP, w + 12u
        Register.SPsvc, w + 12u ]
    let cells = [ M(16, 0UL) ]
    let run = runWith false "f9cd0513" (CPSR 0x12u :: cells) others
    let refused = refusedModes false "f9cd0513" cells others
    CollectionAssert.AreEqual([| 0x10u; 0x1au; 0x1fu |], refused)
    Assert.AreEqual(M(16, 0x600001d311112222UL), run.After(M(16, 0UL)))
    Assert.AreEqual(w + 12u, run.Reg Register.SPsvc)

  /// <summary>
  /// F5.1.213 SSBB: ssbb. It lifts to no statements: what it does is a hint or
  /// an ordering of memory accesses that one run cannot observe, and QEMU's
  /// runs of it changed no register and no byte, so a value test would assert
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.213 SSBB``() =
    Assert.AreEqual(0, (lift false "f57ff040").Length)

  /// <summary>
  /// F5.1.217 STL: stl r0, [r1]. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.217 STL``() =
    let inputs =
      [ [ Gpr(0, 0xb16e845eu)
          Gpr(1, 0x20000810u)
          M(0, 0xfe6688f69779bd87UL)
          M(8, 0x33db71dcab0ae78fUL)
          M(16, 0xd4cf0579966da04cUL)
          M(24, 0xa38f6464d7d92ea5UL)
          M(32, 0x93e0bc8c114941f2UL)
          M(40, 0xfd70ca8e7f203df2UL)
          M(48, 0x5393379bc11bcf0eUL)
          M(56, 0xe39a6f072aae7f0eUL) ]
        [ Gpr(0, 0x92ad2fc8u)
          Gpr(1, 0x20000810u)
          M(0, 0xe05432408c31c718UL)
          M(8, 0x242c5bf7c2e66635UL)
          M(16, 0xa61bd1a46650160aUL)
          M(24, 0x6f56c86510ff34baUL)
          M(32, 0x7f8149ff131cc7acUL)
          M(40, 0x2352be9bbfc0e43aUL)
          M(48, 0xdcd1d849bf6b6c85UL)
          M(56, 0x057a508ad9ed8267UL) ]
        [ Gpr(0, 0x00000001u)
          Gpr(1, 0x20000810u)
          M(0, 0x7caf10d6c160e4edUL)
          M(8, 0x6b808d20ed70c160UL)
          M(16, 0x1c5c1ff3ade8c8beUL)
          M(24, 0xe3dfe91d25393b33UL)
          M(32, 0xe394485c09877eedUL)
          M(40, 0xbe5d1c76242a96ddUL)
          M(48, 0x1b5c0f75fd201b37UL)
          M(56, 0xf74f18f9f78c4699UL) ] ]
    let outputs =
      [ [ M(16, 0xd4cf0579b16e845eUL) ]
        [ M(16, 0xa61bd1a492ad2fc8UL) ]
        [ M(16, 0x1c5c1ff300000001UL) ] ]
    check false "e181fc90" inputs outputs

  /// <summary>
  /// F5.1.218 STLB: stlb r0, [r1]. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.218 STLB``() =
    let inputs =
      [ [ Gpr(0, 0xf7c90586u)
          Gpr(1, 0x20000810u)
          M(0, 0x71fd41def1ae4630UL)
          M(8, 0xb1a9f11d2dc0875dUL)
          M(16, 0xd81568ab90102f31UL)
          M(24, 0x361a36c285a5b175UL)
          M(32, 0x36d8e26f1f768a23UL)
          M(40, 0x33d001a8dcb7c433UL)
          M(48, 0xb6d89d041f7d72e5UL)
          M(56, 0xaf252058d808f896UL) ]
        [ Gpr(0, 0x5dfef18au)
          Gpr(1, 0x20000810u)
          M(0, 0xbb0121c01dc0aafdUL)
          M(8, 0xa95bea36c2e109daUL)
          M(16, 0xdf281a1963b718fdUL)
          M(24, 0x320d4b558ee45e22UL)
          M(32, 0xa36d4e766bcb6d8dUL)
          M(40, 0x92131415a75a097fUL)
          M(48, 0x7eec4a204caf8c95UL)
          M(56, 0x0f55efacff8f4facUL) ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x20000810u)
          M(0, 0x4ddd8867a896069aUL)
          M(8, 0x41ad83e9c5a5bc40UL)
          M(16, 0xc3aa6eed623456a7UL)
          M(24, 0x52485cbbffbd3cb1UL)
          M(32, 0x3c8bea1c0a31e180UL)
          M(40, 0x473fa570e4851bf4UL)
          M(48, 0xfbb278b6ff8abff6UL)
          M(56, 0xf5723fea4bf6ec82UL) ] ]
    let outputs =
      [ [ M(16, 0xd81568ab90102f86UL) ]
        [ M(16, 0xdf281a1963b7188aUL) ]
        [ M(16, 0xc3aa6eed623456ffUL) ] ]
    check false "e1c1fc90" inputs outputs

  /// <summary>
  /// F5.1.219 STLEX: stlex r0, r2, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.219 STLEX``() =
    let inputs =
      [ [ Gpr(0, 0xb3118b01u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x439f1908u)
          M(0, 0x5fbd4d4ad42597efUL)
          M(8, 0xcca41c34f221813fUL)
          M(16, 0xc08de2320de5b108UL)
          M(24, 0x5bdc6a483e703775UL)
          M(32, 0x4b626328ed2f7c0cUL)
          M(40, 0x33f10616dc0542c8UL)
          M(48, 0xe8e5aa5860454751UL)
          M(56, 0xc1ab5e7bbd28118bUL) ]
        [ Gpr(0, 0x36bd4c69u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0xb4fd8628u)
          M(0, 0x0984d1dd5e0ff932UL)
          M(8, 0x0d6ea7dd30900eabUL)
          M(16, 0x952c0312db394bdcUL)
          M(24, 0xec646a6b232777dbUL)
          M(32, 0x131bd90a9e88c8c3UL)
          M(40, 0xc0fd403a3faf74d2UL)
          M(48, 0xeef727d4a3b42710UL)
          M(56, 0x9239c24f939f4e28UL) ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x00000000u)
          M(0, 0x9c180b0926efddd2UL)
          M(8, 0x4fe1cfa5762bb325UL)
          M(16, 0x3fba4bfb79557e47UL)
          M(24, 0x962e7598148ff9cdUL)
          M(32, 0xa4595cb90ecd5445UL)
          M(40, 0xd85b5b4d6c73ab8aUL)
          M(48, 0x06df580e7b885460UL)
          M(56, 0xbbeb3f9b5ad2d9f5UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ] ]
    check false "e1810e92" inputs outputs

  /// <summary>
  /// F5.1.220 STLEXB: stlexb r0, r2, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.220 STLEXB``() =
    let inputs =
      [ [ Gpr(0, 0x0dba23c5u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x18267b81u)
          M(0, 0xb4f0a3da823f960cUL)
          M(8, 0x8346e459dff076e1UL)
          M(16, 0xa8f03889ce26f840UL)
          M(24, 0xb391f99d070ca7ccUL)
          M(32, 0xa991d7ca9c3ab1f7UL)
          M(40, 0x89e1c36a3e9eff2eUL)
          M(48, 0x9b2af612f4c3ffe6UL)
          M(56, 0x491a762f05dad95bUL) ]
        [ Gpr(0, 0xa609bde0u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0xcd2f4fdau)
          M(0, 0xe11772ce7e79c6c7UL)
          M(8, 0x6b24f405738f64c0UL)
          M(16, 0x804253af5df91064UL)
          M(24, 0xa2cf63a7e8bfb7deUL)
          M(32, 0x1274eb0ac4640318UL)
          M(40, 0x54b213db93757292UL)
          M(48, 0x253c3dc44021e65eUL)
          M(56, 0x6b0c2f865a7f06eaUL) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x80007fffu)
          M(0, 0x38831e4db06589e9UL)
          M(8, 0x13749afc60df6f7dUL)
          M(16, 0xb82a48120fe091aeUL)
          M(24, 0x146a9b458362e82aUL)
          M(32, 0x7b54f55a75b6ed13UL)
          M(40, 0xaa39e76989e29aceUL)
          M(48, 0x360921c07a900b23UL)
          M(56, 0xa7c728b672f85deeUL) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ] ]
    check false "e1c10e92" inputs outputs

  /// <summary>
  /// F5.1.221 STLEXD: stlexd r0, r2, r3, [r1]. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.221 STLEXD``() =
    let inputs =
      [ [ Gpr(0, 0x069163b7u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x3e733873u)
          Gpr(3, 0xb28eabd9u)
          M(0, 0x85e126dbf3718c73UL)
          M(8, 0xfbc3331d71cc3073UL)
          M(16, 0x2ee8f2f857266de3UL)
          M(24, 0xc8310433c94af8f5UL)
          M(32, 0xb604f41ed70fff53UL)
          M(40, 0x6c1cc30cd1570975UL)
          M(48, 0x93b1d1da02e5e3b1UL)
          M(56, 0xfc2be4e308d81dc5UL) ]
        [ Gpr(0, 0x4fb5fa7cu)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x264b6064u)
          Gpr(3, 0x80765e58u)
          M(0, 0x8527f9707abf44edUL)
          M(8, 0x0749646b58f2d5abUL)
          M(16, 0xf7ec9fb7d1ed46bbUL)
          M(24, 0xb5a37aade6cbbcf7UL)
          M(32, 0x214078c274d99a50UL)
          M(40, 0x7f280c4b5493464aUL)
          M(48, 0xbedd195698cc27f8UL)
          M(56, 0xd9166ca0bfe6a842UL) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x80007fffu)
          Gpr(3, 0x00000003u)
          M(0, 0xace0d592c4874616UL)
          M(8, 0xf3f47556b0a77aaeUL)
          M(16, 0xb3f5b891616e81e8UL)
          M(24, 0x715642651d01c4b8UL)
          M(32, 0x4d6685914ddbc9c5UL)
          M(40, 0xef782f6da2a85b2cUL)
          M(48, 0x8c6a3d27a523bb6eUL)
          M(56, 0xaf969a7e02cb28adUL) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ] ]
    check false "e1a10e92" inputs outputs

  /// <summary>
  /// F5.1.222 STLEXH: stlexh r0, r2, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.222 STLEXH``() =
    let inputs =
      [ [ Gpr(0, 0x60d587b4u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x7568d897u)
          M(0, 0xae696f46a5057b8eUL)
          M(8, 0xcada14d335fe4110UL)
          M(16, 0x300551ce9a795c20UL)
          M(24, 0x2411fb24fe41c368UL)
          M(32, 0x6736e6ed4980324fUL)
          M(40, 0x8abb45c1613bb3acUL)
          M(48, 0xe9184ed9c3ddb06fUL)
          M(56, 0x06442701df30f5d7UL) ]
        [ Gpr(0, 0x8443b0aau)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x99eeec80u)
          M(0, 0x14d830eaf8a1e0a8UL)
          M(8, 0x17fea1aae6d94d1cUL)
          M(16, 0x8ece25ecb3f2e3feUL)
          M(24, 0xf8c46e5af74eaf01UL)
          M(32, 0x6460133659e5d3d5UL)
          M(40, 0x9a914915a8976825UL)
          M(48, 0x02e7b2f1af49fbc4UL)
          M(56, 0x38ce1ed2732774c1UL) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x80007fffu)
          M(0, 0x1aa66938e82bfcf9UL)
          M(8, 0x5541503ae0d3a7dcUL)
          M(16, 0x53363a84c2fc3178UL)
          M(24, 0xb7cd02d4a1522308UL)
          M(32, 0x18b37063aff209c1UL)
          M(40, 0x24659970a7669a3bUL)
          M(48, 0x334ab408ac40b7a9UL)
          M(56, 0xd12c0390712883b4UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ] ]
    check false "e1e10e92" inputs outputs

  /// <summary>
  /// F5.1.223 STLH: stlh r0, [r1]. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.223 STLH``() =
    let inputs =
      [ [ Gpr(0, 0xac4afc49u)
          Gpr(1, 0x20000810u)
          M(0, 0xbe1ce781233afe42UL)
          M(8, 0xede251eb0665f515UL)
          M(16, 0x21ca763142d0a8a8UL)
          M(24, 0x52961bb0c2d525c1UL)
          M(32, 0xea7a2093d542d9d9UL)
          M(40, 0xdbf57bb392139af7UL)
          M(48, 0x39db2449f42aba66UL)
          M(56, 0x50e7f10eb9294378UL) ]
        [ Gpr(0, 0x59d0a7a1u)
          Gpr(1, 0x20000810u)
          M(0, 0x4c6ea9ae378edf59UL)
          M(8, 0x989db3c69277341dUL)
          M(16, 0xe7592cb69fba78ddUL)
          M(24, 0x8c24c67b179f7bc3UL)
          M(32, 0x4a0a8ec31412ac5aUL)
          M(40, 0xb24c3f48ba083ecbUL)
          M(48, 0xdbf9c2ed547f4c84UL)
          M(56, 0x2711af5c7eba5a52UL) ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x20000810u)
          M(0, 0xaf7f86c8b960dbd7UL)
          M(8, 0xc0de58539ea6b709UL)
          M(16, 0x8e3b2f52daa1e40fUL)
          M(24, 0xca1bc0764daa6a7aUL)
          M(32, 0xefdfc8e8d9d9af95UL)
          M(40, 0x6220c680be0883c5UL)
          M(48, 0xeef8cb43e1272f73UL)
          M(56, 0x0f29b85cf19ffa47UL) ] ]
    let outputs =
      [ [ M(16, 0x21ca763142d0fc49UL) ]
        [ M(16, 0xe7592cb69fbaa7a1UL) ]
        [ M(16, 0x8e3b2f52daa1ffffUL) ] ]
    check false "e1e1fc90" inputs outputs

  /// <summary>
  /// F5.1.224 STMEA: stm r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.224 STMEA``() =
    let inputs =
      [ [ Gpr(1, 0x20000818u)
          Gpr(2, 0xd073be5au)
          Gpr(3, 0x0e83b49au)
          M(0, 0x6692796ebe1b4370UL)
          M(8, 0x3523b80e250f6dd4UL)
          M(16, 0x3afa8ed75e09f9acUL)
          M(24, 0x1d89e659c0d105fcUL)
          M(32, 0x8aba5dd9552508dfUL)
          M(40, 0xeae90c90b0431a94UL)
          M(48, 0x512869cba0877619UL)
          M(56, 0x85b4292bc5cdbac5UL) ]
        [ Gpr(1, 0x20000818u)
          Gpr(2, 0x0dcb12c0u)
          Gpr(3, 0x693ae6c9u)
          M(0, 0xe4625d43508d5309UL)
          M(8, 0xc171509754e5e104UL)
          M(16, 0xa7d54b4f2306c121UL)
          M(24, 0xdca67d22596fe5aaUL)
          M(32, 0x7acf6b188a95b50dUL)
          M(40, 0xb8157b42932f8145UL)
          M(48, 0x7cf3017dad96544aUL)
          M(56, 0x8d67826111a935e8UL) ]
        [ Gpr(1, 0x20000818u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0xf91fe05d6098d811UL)
          M(8, 0x6ad643a47f5e765eUL)
          M(16, 0x9d4040e5effe6f1dUL)
          M(24, 0xd2b4ade04110d455UL)
          M(32, 0xe63d3a5f9f79350eUL)
          M(40, 0x64ba3ec30b6f8241UL)
          M(48, 0x09e073e067a9b70bUL)
          M(56, 0xede33f90270936a9UL) ] ]
    let outputs =
      [ [ M(24, 0x0e83b49ad073be5aUL) ]
        [ M(24, 0x693ae6c90dcb12c0UL) ]
        [ M(24, 0x80007fff00000000UL) ] ]
    check false "e881000c" inputs outputs

  /// <summary>
  /// F5.1.224 STMIA: stm r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.224 STMIA``() =
    let inputs =
      [ [ Gpr(1, 0x20000818u)
          Gpr(2, 0x48fa5639u)
          Gpr(3, 0xba49a316u)
          M(0, 0x882fa8f4baedb37bUL)
          M(8, 0x576f5bba80f046e2UL)
          M(16, 0x3a1b28ac86703beeUL)
          M(24, 0x13f24db1ee17a46cUL)
          M(32, 0x6728970a3b709f5dUL)
          M(40, 0x467ad221cedc293dUL)
          M(48, 0x4fbf0a99c191976eUL)
          M(56, 0x59293458b827f895UL) ]
        [ Gpr(1, 0x20000818u)
          Gpr(2, 0x7f3f42adu)
          Gpr(3, 0x4c0a4409u)
          M(0, 0x6faee5ffceb6e80dUL)
          M(8, 0x9c88a916122297f8UL)
          M(16, 0x7bf5d52165a0fb07UL)
          M(24, 0xa1d6d8fe6e40818fUL)
          M(32, 0xf098c91195d06e9fUL)
          M(40, 0x2b974fc2018f4256UL)
          M(48, 0x3724f35be18366e7UL)
          M(56, 0xf57030be58928556UL) ]
        [ Gpr(1, 0x20000818u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0x9e4dc9319a2d169bUL)
          M(8, 0x98da028315a74ed4UL)
          M(16, 0x495da23e41ab3ffeUL)
          M(24, 0x9d328dfd1095b96bUL)
          M(32, 0xf1b249b7b8289b7dUL)
          M(40, 0x2d172991af646576UL)
          M(48, 0xf81eb5e9e8e87504UL)
          M(56, 0xf6660dc7ae03e88fUL) ] ]
    let outputs =
      [ [ M(24, 0xba49a31648fa5639UL) ]
        [ M(24, 0x4c0a44097f3f42adUL) ]
        [ M(24, 0x80007fff00000000UL) ] ]
    check false "e881000c" inputs outputs

  /// <summary>
  /// F5.1.226 STMED: stmda r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.226 STMED``() =
    let inputs =
      [ [ Gpr(1, 0x2000081cu)
          Gpr(2, 0xe8c880f6u)
          Gpr(3, 0xdb303358u)
          M(0, 0x643e0c79e077727fUL)
          M(8, 0x1e2fca56361a8cacUL)
          M(16, 0x3d30fd3a50eed790UL)
          M(24, 0xc5d8dd7225a70490UL)
          M(32, 0xfecbc18dbbcdd0b5UL)
          M(40, 0x86254803f693fc4dUL)
          M(48, 0xbddffb6904901faaUL)
          M(56, 0x7febd21fc784b792UL) ]
        [ Gpr(1, 0x2000081cu)
          Gpr(2, 0x09206433u)
          Gpr(3, 0x26ac2e90u)
          M(0, 0x3a23e25aec3a005dUL)
          M(8, 0x0a9a1d298295bebbUL)
          M(16, 0x5110e2f9d1a559bdUL)
          M(24, 0xc917b8b3f314129bUL)
          M(32, 0x067eebed3b6c1592UL)
          M(40, 0x9a1a7b696663cf35UL)
          M(48, 0x7d58576ee3ba480aUL)
          M(56, 0x1de6185c467868e3UL) ]
        [ Gpr(1, 0x2000081cu)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0xd2c2f43fe66bd3bcUL)
          M(8, 0xc34bd9ddc0ba6676UL)
          M(16, 0x38a4f0630601c92fUL)
          M(24, 0xda1f4828ae27faf2UL)
          M(32, 0x7d209bfff9c2347bUL)
          M(40, 0x40701db16bb9f2d5UL)
          M(48, 0x7d04c513eb26a17eUL)
          M(56, 0xdba8bbeb4541c48aUL) ] ]
    let outputs =
      [ [ M(24, 0xdb303358e8c880f6UL) ]
        [ M(24, 0x26ac2e9009206433UL) ]
        [ M(24, 0x80007fff00000000UL) ] ]
    check false "e801000c" inputs outputs

  /// <summary>
  /// F5.1.227 STMFD: stmdb r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.227 STMFD``() =
    let inputs =
      [ [ Gpr(1, 0x20000820u)
          Gpr(2, 0xa9a87542u)
          Gpr(3, 0x4bc9ee2du)
          M(0, 0x1814b8d285f9d5f3UL)
          M(8, 0x3a5423f0a430ff3dUL)
          M(16, 0x87c30b9f37ee3cfeUL)
          M(24, 0xe3f06bf432d0a237UL)
          M(32, 0x96a39e4cf827f983UL)
          M(40, 0xe8f68e073d3d9310UL)
          M(48, 0x30b3cc9b5908a896UL)
          M(56, 0x2d6f7043a3da3084UL) ]
        [ Gpr(1, 0x20000820u)
          Gpr(2, 0x08161032u)
          Gpr(3, 0xa4f83bd9u)
          M(0, 0xe55e32476bfc0665UL)
          M(8, 0x4807589e02f6f900UL)
          M(16, 0xd1c84156799e08feUL)
          M(24, 0x04c8014745dc4e82UL)
          M(32, 0x62a24ca6bdd0664cUL)
          M(40, 0xc5cb885601136627UL)
          M(48, 0x1e94eaae015e7a20UL)
          M(56, 0xd840ce27b43a94c6UL) ]
        [ Gpr(1, 0x20000820u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0x1a5aa52e140e7c31UL)
          M(8, 0xe83d58e620f79a78UL)
          M(16, 0x652c08828506597bUL)
          M(24, 0xc8c53083d195f0b1UL)
          M(32, 0xce1fac865932c8c4UL)
          M(40, 0x9c94b3a412783b30UL)
          M(48, 0xf82ea165ef65256aUL)
          M(56, 0x7677d3379abc3f7fUL) ] ]
    let outputs =
      [ [ M(24, 0x4bc9ee2da9a87542UL) ]
        [ M(24, 0xa4f83bd908161032UL) ]
        [ M(24, 0x80007fff00000000UL) ] ]
    check false "e901000c" inputs outputs

  /// <summary>
  /// F5.1.228 STMFA: stmib r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.228 STMFA``() =
    let inputs =
      [ [ Gpr(1, 0x20000814u)
          Gpr(2, 0xc954f080u)
          Gpr(3, 0xa7bf4009u)
          M(0, 0x658c013148284121UL)
          M(8, 0x580a568b44a38b6eUL)
          M(16, 0xcf6335f16b735540UL)
          M(24, 0x82a0d9fa4ff902d7UL)
          M(32, 0x679965ed7505293fUL)
          M(40, 0x5fc902d87ab4b307UL)
          M(48, 0xa8fb6e52b0edf7d1UL)
          M(56, 0x75fef4115d8a2968UL) ]
        [ Gpr(1, 0x20000814u)
          Gpr(2, 0x5cb3f1efu)
          Gpr(3, 0x1af80a95u)
          M(0, 0xcb0442cbec2c1acbUL)
          M(8, 0x5036eaad6c49ea13UL)
          M(16, 0xf27857c998810012UL)
          M(24, 0x9983aaee267ae1d8UL)
          M(32, 0x8e8bf4587bbec069UL)
          M(40, 0x04d9c4d58abfa8d2UL)
          M(48, 0x22f6ee20dd592513UL)
          M(56, 0xab56dc7050f50d03UL) ]
        [ Gpr(1, 0x20000814u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0xd25ca76385850890UL)
          M(8, 0xaa6d5341c9db55ecUL)
          M(16, 0x8998b7db1050de28UL)
          M(24, 0x597c1949cb7b642fUL)
          M(32, 0x4474127d570f8684UL)
          M(40, 0x638610a6b9cdceacUL)
          M(48, 0xee752c0fc2c4f039UL)
          M(56, 0x5fbe4d66c0e900e1UL) ] ]
    let outputs =
      [ [ M(24, 0xa7bf4009c954f080UL) ]
        [ M(24, 0x1af80a955cb3f1efUL) ]
        [ M(24, 0x80007fff00000000UL) ] ]
    check false "e981000c" inputs outputs

  /// <summary>
  /// F5.1.261 TSB: .inst 0xe320f012. It lifts to no statements: what it does is
  /// a hint or an ordering of memory accesses that one run cannot observe, and
  /// QEMU's runs of it changed no register and no byte, so a value test would
  /// assert nothing.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.261 TSB``() =
    Assert.AreEqual(0, (lift false "e320f012").Length)

  /// <summary>
  /// F5.1.278 UMLALS: umlals r0, r1, r1, r2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.278 UMLALS``() =
    let inputs =
      [ [ Gpr(0, 0xb00ca214u)
          Gpr(1, 0x64c4b0adu)
          Gpr(2, 0x4efd9dceu)
          CPSR 0x20000010u ]
        [ Gpr(0, 0xfab4c9e9u)
          Gpr(1, 0x95a5da71u)
          Gpr(2, 0x31fca8dbu)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xb7a5e64au); Gpr(1, 0x83dc7302u); CPSR 0xa0000010u ]
        [ Gpr(0, 0x7f2cd094u); Gpr(1, 0xb2de4b39u); CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); CPSR 0x08050010u ] ]
    check false "e0b10291" inputs outputs

  /// <summary>
  /// F5.1.279 UMULLS: umulls r0, r1, r1, r2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.279 UMULLS``() =
    let inputs =
      [ [ Gpr(0, 0x01417434u)
          Gpr(1, 0x76dfa7efu)
          Gpr(2, 0xadd2add9u)
          CPSR 0x20000010u ]
        [ Gpr(0, 0xae095c18u)
          Gpr(1, 0x54ae56afu)
          Gpr(2, 0xbf6b11beu)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x2d1fdc97u); Gpr(1, 0x50b6f8aeu); CPSR 0x20000010u ]
        [ Gpr(0, 0x394af4e2u); Gpr(1, 0x3f517d69u); CPSR 0x100a0010u ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x00000000u); CPSR 0x48050010u ] ]
    check false "e0910291" inputs outputs

  /// <summary>
  /// F6.1.1 AESD: aesd.8 q0, q1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.1 AESD``() =
    let inputs =
      [ [ D(0, 0x0d2fb2c6294a7c6dUL)
          D(1, 0x124da8e9fea19c09UL)
          D(2, 0xf6ba7f27c90af1b7UL)
          D(3, 0xc980c34d74e2f06dUL) ]
        [ D(0, 0x27824ec557c30863UL)
          D(1, 0xd79e2f9f44385e16UL)
          D(2, 0x61ed714bb939598cUL)
          D(3, 0x408a2650e145a28eUL) ]
        [ D(0, 0x0000000000000001UL)
          D(1, 0x0102030405060708UL)
          D(2, 0x7fffffffffffffffUL)
          D(3, 0x0000000000000001UL) ] ]
    let outputs =
      [ [ D(0, 0xcf80b4e06364057aUL); D(1, 0xa0adb81d9f72808cUL) ]
        [ D(0, 0x299b70e698134061UL); D(1, 0x9906555f851425e2UL) ]
        [ D(0, 0x366a7d7d6ba5d50cUL); D(1, 0x7d7d3830097d7d40UL) ] ]
    check false "f3b00342" inputs outputs

  /// <summary>
  /// F6.1.2 AESE: aese.8 q0, q1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.2 AESE``() =
    let inputs =
      [ [ D(0, 0x863efd8194eab4b5UL)
          D(1, 0x05ced7976ae06b3fUL)
          D(2, 0x87adfc988316e1c1UL)
          D(3, 0x875525b0d4fccb3eUL) ]
        [ D(0, 0x6b9a370d21d87e48UL)
          D(1, 0x773539b049685686UL)
          D(2, 0xf5c74438767b1000UL)
          D(3, 0xa9ceae3ead9b42ddUL) ]
        [ D(0, 0x7fffffffffffffffUL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0x0000000000000001UL)
          D(3, 0xffffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0xf014e0d4139c7c92UL); D(1, 0xaedcfccc7cb0897cUL) ]
        [ D(0, 0x5b0ffa961d0d8f52UL); D(1, 0x694c9f190b0a8839UL) ]
        [ D(0, 0x16636316636316bbUL); D(1, 0x63161663d2166363UL) ] ]
    check false "f3b00302" inputs outputs

  /// <summary>
  /// F6.1.3 AESIMC: aesimc.8 q0, q1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.3 AESIMC``() =
    let inputs =
      [ [ D(0, 0x4fb39d10cb4edab9UL)
          D(1, 0x875fc5b16bce3e66UL)
          D(2, 0x170fb37390da23e2UL)
          D(3, 0x7b3d9b4006a44469UL) ]
        [ D(0, 0x948329af7de9ea07UL)
          D(1, 0x75bb8d1c7a69f62bUL)
          D(2, 0x14a910db08ea0a3bUL)
          D(3, 0x5b6e5646f077b496UL) ]
        [ D(0, 0x8000000000000000UL)
          D(1, 0x0000000000000001UL)
          D(2, 0x7fffffffffffffffUL)
          D(3, 0x00ff00ff00ff00ffUL) ] ]
    let outputs =
      [ [ D(0, 0x3b96344131118f24UL); D(1, 0xb947781b507917b1UL) ]
        [ D(0, 0x6af0826e774dc821UL); D(1, 0x43b204d0cd31d881UL) ]
        [ D(0, 0xbe082513ffffffffUL); D(1, 0xe51ae51ae51ae51aUL) ] ]
    check false "f3b003c2" inputs outputs

  /// <summary>
  /// F6.1.4 AESMC: aesmc.8 q0, q1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.4 AESMC``() =
    let inputs =
      [ [ D(0, 0x7fcd0b4941102020UL)
          D(1, 0xa01f8fe98ff6d767UL)
          D(2, 0x507f833dd9f7e1f0UL)
          D(3, 0xa8397c95def534c4UL) ]
        [ D(0, 0xb12a3de6682d6b9cUL)
          D(1, 0x8abb26474d42e037UL)
          D(2, 0x9e01b09c969842c3UL)
          D(3, 0x6124588d3a55c822UL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0x00ff00ff00ff00ffUL)
          D(3, 0x00ff00ff00ff00ffUL) ] ]
    let outputs =
      [ [ D(0, 0x1bb0f1cbb494f2edUL); D(1, 0xaa788e24317876e4UL) ]
        [ D(0, 0x29977a77b30b6255UL); D(1, 0x323e30ac8f0e6c68UL) ]
        [ D(0, 0xe51ae51ae51ae51aUL); D(1, 0xe51ae51ae51ae51aUL) ] ]
    check false "f3b00382" inputs outputs

  /// <summary>
  /// F6.1.6 FSTMDBX: fstmdbx r1!, {d0, d1, d2, d3, d4, d5, d6}. The outputs are
  /// what QEMU left after running it on the inputs, three runs paired by
  /// position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.6 FSTMDBX``() =
    let inputs =
      [ [ Gpr(1, 0x2000083cu)
          D(0, 0x07678a5e54e5bf78UL)
          D(1, 0x168e732e08e28ca8UL)
          D(2, 0x2eb4d674806f4dc3UL)
          D(3, 0xfb1c1916a79bfdf4UL)
          D(4, 0xb8a8407de29a3ef7UL)
          D(5, 0x55a8faa5b5acb48dUL)
          D(6, 0x61fac22701b513b3UL)
          M(0, 0x94d82ebe1ff745eeUL)
          M(8, 0xfa9e3a80b313de19UL)
          M(16, 0x376631d16d48f896UL)
          M(24, 0x1b4da5e5f9c57e85UL)
          M(32, 0x06eb4f026f55d4c2UL)
          M(40, 0x4eae48178df441aaUL)
          M(48, 0xe37cbeee04287c07UL)
          M(56, 0x1147eccca00cf0a2UL) ]
        [ Gpr(1, 0x2000083cu)
          D(0, 0x6c15746abb58fcecUL)
          D(1, 0x5f0ce07c6c973280UL)
          D(2, 0xd9dcb0d277b2225fUL)
          D(3, 0x8e820a4e73d02cefUL)
          D(4, 0x3fd5cedf51756795UL)
          D(5, 0xa3b103841a20522eUL)
          D(6, 0xc37627b8e2345991UL)
          M(0, 0xfd01d1dfe88e1e72UL)
          M(8, 0xcec248de80aea7fcUL)
          M(16, 0x15b161c508b31657UL)
          M(24, 0x71ff4e712be09b9dUL)
          M(32, 0x9423d09f64492cfeUL)
          M(40, 0x87836d937be2f0f9UL)
          M(48, 0x899a8a2a8cf636f4UL)
          M(56, 0x8281eec6a17cfeb7UL) ]
        [ Gpr(1, 0x2000083cu)
          D(0, 0x8001800180018001UL)
          D(1, 0x8001800180018001UL)
          D(2, 0x8000000000000000UL)
          D(3, 0x8000000000000000UL)
          D(4, 0x8000000000000000UL)
          D(5, 0x00ff00ff00ff00ffUL)
          D(6, 0x00ff00ff00ff00ffUL)
          M(0, 0x731db2a32964bd10UL)
          M(8, 0x3d443a743cf9b8cbUL)
          M(16, 0xbeddfbc2ea1782e4UL)
          M(24, 0x65cf65f40fe9b894UL)
          M(32, 0xb0ae5a2ff17b37e1UL)
          M(40, 0x69d7f1df93d4c45aUL)
          M(48, 0x1bbba2d2fd342612UL)
          M(56, 0x52143ffd921b85d0UL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000800u)
          M(0, 0x07678a5e54e5bf78UL)
          M(8, 0x168e732e08e28ca8UL)
          M(16, 0x2eb4d674806f4dc3UL)
          M(24, 0xfb1c1916a79bfdf4UL)
          M(32, 0xb8a8407de29a3ef7UL)
          M(40, 0x55a8faa5b5acb48dUL)
          M(48, 0x61fac22701b513b3UL) ]
        [ Gpr(1, 0x20000800u)
          M(0, 0x6c15746abb58fcecUL)
          M(8, 0x5f0ce07c6c973280UL)
          M(16, 0xd9dcb0d277b2225fUL)
          M(24, 0x8e820a4e73d02cefUL)
          M(32, 0x3fd5cedf51756795UL)
          M(40, 0xa3b103841a20522eUL)
          M(48, 0xc37627b8e2345991UL) ]
        [ Gpr(1, 0x20000800u)
          M(0, 0x8001800180018001UL)
          M(8, 0x8001800180018001UL)
          M(16, 0x8000000000000000UL)
          M(24, 0x8000000000000000UL)
          M(32, 0x8000000000000000UL)
          M(40, 0x00ff00ff00ff00ffUL)
          M(48, 0x00ff00ff00ff00ffUL) ] ]
    check false "ed210b0f" inputs outputs

  /// <summary>
  /// F6.1.6 FSTMIAX: fstmiax r1, {d0, d1, d2, d3, d4, d5, d6}. The outputs are
  /// what QEMU left after running it on the inputs, three runs paired by
  /// position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.6 FSTMIAX``() =
    let inputs =
      [ [ Gpr(1, 0x20000800u)
          D(0, 0xafa4f4613ec15eafUL)
          D(1, 0x6145421f2526df51UL)
          D(2, 0x7541fba90c9eb858UL)
          D(3, 0x90978029fd29c4c4UL)
          D(4, 0x0550c3cd4a6f4ea5UL)
          D(5, 0x101743a64db46dabUL)
          D(6, 0x3ff47d018aff3a32UL)
          M(0, 0x345f8e0bf40196e6UL)
          M(8, 0xc2b122bf8211195fUL)
          M(16, 0xace23c982701298dUL)
          M(24, 0xc74707ba0adb54aeUL)
          M(32, 0xa361f85bb292f487UL)
          M(40, 0x7a3539ca0e706e0fUL)
          M(48, 0xba8e75021c575c47UL)
          M(56, 0x67955acb54207455UL) ]
        [ Gpr(1, 0x20000800u)
          D(0, 0xb81bcccc11dfbf1dUL)
          D(1, 0x9964a950ecd72f0dUL)
          D(2, 0xaa93aa3759d4af2dUL)
          D(3, 0x7a15cd33ad79517eUL)
          D(4, 0x8027f2d36a4d294fUL)
          D(5, 0xe7a64594885bdf75UL)
          D(6, 0xaec544821e8702e9UL)
          M(0, 0xbda385fc977a7dc0UL)
          M(8, 0xba45c6571976ca7aUL)
          M(16, 0x46c211483fadcb77UL)
          M(24, 0x702e2f39e1792fddUL)
          M(32, 0x1913fb27149265f8UL)
          M(40, 0xfc8e45c55d228909UL)
          M(48, 0x0d43d9b8e7de162eUL)
          M(56, 0x2a03ea6ea500e404UL) ]
        [ Gpr(1, 0x20000800u)
          D(0, 0x8001800180018001UL)
          D(1, 0x7fffffffffffffffUL)
          D(2, 0x0000000000000001UL)
          D(3, 0x7f80ff00807fffffUL)
          D(4, 0xffffffffffffffffUL)
          D(5, 0x0102030405060708UL)
          D(6, 0x8000000000000000UL)
          M(0, 0xb639c176cfa41db5UL)
          M(8, 0xe7b98e4edb5b746eUL)
          M(16, 0x0b167af0857d8720UL)
          M(24, 0x655250ba868da109UL)
          M(32, 0x1e70a7887c82eb83UL)
          M(40, 0x537bb1abf60d971fUL)
          M(48, 0x3c2fb52001effde8UL)
          M(56, 0xbf000079f94401e6UL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000800u)
          M(0, 0xafa4f4613ec15eafUL)
          M(8, 0x6145421f2526df51UL)
          M(16, 0x7541fba90c9eb858UL)
          M(24, 0x90978029fd29c4c4UL)
          M(32, 0x0550c3cd4a6f4ea5UL)
          M(40, 0x101743a64db46dabUL)
          M(48, 0x3ff47d018aff3a32UL) ]
        [ Gpr(1, 0x20000800u)
          M(0, 0xb81bcccc11dfbf1dUL)
          M(8, 0x9964a950ecd72f0dUL)
          M(16, 0xaa93aa3759d4af2dUL)
          M(24, 0x7a15cd33ad79517eUL)
          M(32, 0x8027f2d36a4d294fUL)
          M(40, 0xe7a64594885bdf75UL)
          M(48, 0xaec544821e8702e9UL) ]
        [ Gpr(1, 0x20000800u)
          M(0, 0x8001800180018001UL)
          M(8, 0x7fffffffffffffffUL)
          M(16, 0x0000000000000001UL)
          M(24, 0x7f80ff00807fffffUL)
          M(32, 0xffffffffffffffffUL)
          M(40, 0x0102030405060708UL)
          M(48, 0x8000000000000000UL) ] ]
    check false "ec810b0f" inputs outputs

  /// <summary>
  /// F6.1.7 SHA1C: sha1c.32 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.7 SHA1C``() =
    let inputs =
      [ [ D(0, 0xe93f2cfd4b93682dUL)
          D(1, 0xced11a9385e8a1a3UL)
          D(2, 0xb02b7d32adee6002UL)
          D(4, 0xe7465ac62fed7affUL)
          D(5, 0xf3ef6baa0a8283cfUL) ]
        [ D(0, 0xc44dd3f05fab4424UL)
          D(1, 0xaf920199de2e1ba7UL)
          D(2, 0x006aeee402678076UL)
          D(4, 0x544f9400ac5a8cf6UL)
          D(5, 0xddadcd2a75188ca7UL) ]
        [ D(0, 0xffffffffffffffffUL)
          D(1, 0x8001800180018001UL)
          D(2, 0x8000000000000000UL)
          D(4, 0x00ff00ff00ff00ffUL)
          D(5, 0x8001800180018001UL) ] ]
    let outputs =
      [ [ D(0, 0x578f181eb2668d7eUL); D(1, 0x760c44d3e2a96a30UL) ]
        [ D(0, 0x46d7a3eb00a838d7UL); D(1, 0x24f22968837f6a54UL) ]
        [ D(0, 0x22171df5c1d4bde3UL); D(1, 0xe040203fe844283bUL) ] ]
    check false "f2020c44" inputs outputs

  /// <summary>
  /// F6.1.8 SHA1H: sha1h.32 q0, q1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.8 SHA1H``() =
    let inputs =
      [ [ D(0, 0x86d72e878ffb46dfUL)
          D(1, 0xf6ecdebb7c976279UL)
          D(2, 0xbcf55d18d3c8751cUL) ]
        [ D(0, 0x505ced72e6be8d8eUL)
          D(1, 0xd56d73ca718639dfUL)
          D(2, 0xe4b2f433fdef2861UL) ]
        [ D(0, 0x00ff00ff00ff00ffUL)
          D(1, 0x7fffffffffffffffUL)
          D(2, 0x8001800180018001UL) ] ]
    let outputs =
      [ [ D(0, 0x0000000034f21d47UL); D(1, 0x0000000000000000UL) ]
        [ D(0, 0x000000007f7bca18UL); D(1, 0x0000000000000000UL) ]
        [ D(0, 0x0000000060006000UL); D(1, 0x0000000000000000UL) ] ]
    check false "f3b902c2" inputs outputs

  /// <summary>
  /// F6.1.9 SHA1M: sha1m.32 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.9 SHA1M``() =
    let inputs =
      [ [ D(0, 0x09bf03a604f02544UL)
          D(1, 0xa7fcf07ef80589f6UL)
          D(2, 0x28096f58376211bfUL)
          D(4, 0x7f8682faacebe61aUL)
          D(5, 0x5ef3d89b1d7273caUL) ]
        [ D(0, 0x9481efa4ec8bda1fUL)
          D(1, 0x69d9776f5adab2afUL)
          D(2, 0x614c96e297a634c4UL)
          D(4, 0xf66816836e4c5652UL)
          D(5, 0x542590be270bc553UL) ]
        [ D(0, 0x7fffffffffffffffUL)
          D(1, 0x00ff00ff00ff00ffUL)
          D(2, 0x8000000000000000UL)
          D(4, 0x8000000000000000UL)
          D(5, 0x7fffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x535be62e560c689fUL); D(1, 0xcb0408934a7b4fd0UL) ]
        [ D(0, 0x2bb58ebfecf9d543UL); D(1, 0xbc11f1b0f571583fUL) ]
        [ D(0, 0xfce318cd7d62fa7cUL); D(1, 0x803fc03fa037c82fUL) ] ]
    check false "f2220c44" inputs outputs

  /// <summary>
  /// F6.1.10 SHA1P: sha1p.32 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.10 SHA1P``() =
    let inputs =
      [ [ D(0, 0x816fe4f937d13928UL)
          D(1, 0x9c1f75638f19714eUL)
          D(2, 0x25f5b5d67d1e34c3UL)
          D(4, 0x86e61de628f0db42UL)
          D(5, 0x14a7f250f9a3ef9dUL) ]
        [ D(0, 0x0f44f831212e6805UL)
          D(1, 0xf201ece1df35d4dfUL)
          D(2, 0x6e81548072e7ddfcUL)
          D(4, 0x2d8fbead2360911eUL)
          D(5, 0x42fffe0c4d30fb5bUL) ]
        [ D(0, 0x0000000000000001UL)
          D(1, 0x0000000000000001UL)
          D(2, 0x00ff00ff00ff00ffUL)
          D(4, 0x0102030405060708UL)
          D(5, 0xffffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0xdb4d147f6d66c743UL); D(1, 0xcca80577d3e70021UL) ]
        [ D(0, 0xc5c85fefd1a573fdUL); D(1, 0x77a18bf3eb888a07UL) ]
        [ D(0, 0x7a6608c0cce3621cUL); D(1, 0x0181420a3068c201UL) ] ]
    check false "f2120c44" inputs outputs

  /// <summary>
  /// F6.1.11 SHA1SU0: sha1su0.32 q0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.11 SHA1SU0``() =
    let inputs =
      [ [ D(0, 0xd62b650c0dae0da9UL)
          D(1, 0xd449f2b35622c769UL)
          D(2, 0x3d50e51dd6498250UL)
          D(4, 0x0858c8f2229444f3UL)
          D(5, 0xc9b513958e9d8760UL) ]
        [ D(0, 0x09e0011228968052UL)
          D(1, 0xe51ca4ce4d1b78cfUL)
          D(2, 0x26a7825dffbf2d2bUL)
          D(4, 0xd60a47b8d4047b4bUL)
          D(5, 0x38668cdd0644d1d2UL) ]
        [ D(0, 0x8000000000000000UL)
          D(1, 0x8000000000000000UL)
          D(2, 0x7fffffffffffffffUL)
          D(4, 0x00ff00ff00ff00ffUL)
          D(5, 0x8001800180018001UL) ] ]
    let outputs =
      [ [ D(0, 0x0a3a5f4d79188e33UL); D(1, 0x20ac043b0ef6c259UL) ]
        [ D(0, 0x3af6e264b18983d6UL); D(1, 0xfbddaa4eb4e08436UL) ]
        [ D(0, 0x00ff00ff00ff00ffUL); D(1, 0x7ffe7ffe7ffe7ffeUL) ] ]
    check false "f2320c44" inputs outputs

  /// <summary>
  /// F6.1.12 SHA1SU1: sha1su1.32 q0, q1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.12 SHA1SU1``() =
    let inputs =
      [ [ D(0, 0x5403ba2e401f2711UL)
          D(1, 0x49972c90ec965a7aUL)
          D(2, 0x3b375cb456cf4eecUL)
          D(3, 0xd38efd271ff7ef0dUL) ]
        [ D(0, 0xf34851f2e6e073ffUL)
          D(1, 0x207b3a434d977c36UL)
          D(2, 0xc34bcf7f4010609dUL)
          D(3, 0x1fcd597fa85af76fUL) ]
        [ D(0, 0x8001800180018001UL)
          D(1, 0x7f80ff00807fffffUL)
          D(2, 0x0102030405060708UL)
          D(3, 0x00ff00ff00ff00ffUL) ] ]
    let outputs =
      [ [ D(0, 0x97e8aa46f650f74aUL); D(1, 0x7f8fb7b57e314ebaUL) ]
        [ D(0, 0xb6254d3a4b577900UL); D(1, 0xd6588686a4b44a92UL) ]
        [ D(0, 0x01fd01fd0207060bUL); D(1, 0xfb0ff2160101fe01UL) ] ]
    check false "f3ba0382" inputs outputs

  /// <summary>
  /// F6.1.13 SHA256H: sha256h.32 q0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.13 SHA256H``() =
    let inputs =
      [ [ D(0, 0xe3b52a0dea123d84UL)
          D(1, 0x38f73a9368629ac0UL)
          D(2, 0xd8d6aed4cb0aec5dUL)
          D(3, 0x4f296536de4ecd50UL)
          D(4, 0xd938ac856e28c4e8UL)
          D(5, 0x929b3a64ba048fc8UL) ]
        [ D(0, 0x6ead86c6f3a2b647UL)
          D(1, 0x3031a0fe81923173UL)
          D(2, 0x3dae586568dc3afeUL)
          D(3, 0x3ba1f4e72f90c5bbUL)
          D(4, 0x863a3cc5e4e3457cUL)
          D(5, 0x06d2e7ba30a277dfUL) ]
        [ D(0, 0x00ff00ff00ff00ffUL)
          D(1, 0x8001800180018001UL)
          D(2, 0x0000000000000001UL)
          D(3, 0xffffffffffffffffUL)
          D(4, 0x00ff00ff00ff00ffUL)
          D(5, 0x0000000000000001UL) ] ]
    let outputs =
      [ [ D(0, 0xa49aada01c9d65d4UL); D(1, 0x9c044257201a840dUL) ]
        [ D(0, 0xc6256529c60e49ffUL); D(1, 0xc03611b1bd60376bUL) ]
        [ D(0, 0xe3be941c1bdca998UL); D(1, 0x41e23e3ff55d186eUL) ] ]
    check false "f3020c44" inputs outputs

  /// <summary>
  /// F6.1.14 SHA256H2: sha256h2.32 q0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.14 SHA256H2``() =
    let inputs =
      [ [ D(0, 0x3a084fd7c892a87eUL)
          D(1, 0x748df4b6c021f5efUL)
          D(2, 0x8086b688674f78eaUL)
          D(3, 0x5a3a3848a4eebefaUL)
          D(4, 0x9e007c317497259eUL)
          D(5, 0xea190394c0a959dbUL) ]
        [ D(0, 0xa2b563f23bfc686bUL)
          D(1, 0xca65ffae4fd23f97UL)
          D(2, 0x63de66ebbae4da35UL)
          D(3, 0x89465a4469f9b213UL)
          D(4, 0x29b7c5617f3983ecUL)
          D(5, 0xad66236ad380bb62UL) ]
        [ D(0, 0x8001800180018001UL)
          D(1, 0x8000000000000000UL)
          D(2, 0x00ff00ff00ff00ffUL)
          D(3, 0x8001800180018001UL)
          D(4, 0x8000000000000000UL)
          D(5, 0x8001800180018001UL) ] ]
    let outputs =
      [ [ D(0, 0x80f4708be8b7180bUL); D(1, 0x09301803d17368d7UL) ]
        [ D(0, 0x06aea1a80071d280UL); D(1, 0x99591185a9dea726UL) ]
        [ D(0, 0xef248ceb8f5c0e90UL); D(1, 0x86f306f2edcb6b3aUL) ] ]
    check false "f3120c44" inputs outputs

  /// <summary>
  /// F6.1.15 SHA256SU0: sha256su0.32 q0, q1. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.15 SHA256SU0``() =
    let inputs =
      [ [ D(0, 0x841dc5a4a9a0c7d0UL)
          D(1, 0x8656d23f9edf3d59UL)
          D(2, 0x0a6cbcf39af1267fUL) ]
        [ D(0, 0x407ac9e86d6cd460UL)
          D(1, 0x35229fe622c9c983UL)
          D(2, 0x435b69d4b30bec68UL) ]
        [ D(0, 0x7fffffffffffffffUL)
          D(1, 0x8001800180018001UL)
          D(2, 0x0102030405060708UL) ] ]
    let outputs =
      [ [ D(0, 0xf3ce040ad2836a08UL); D(1, 0x2c4af27e7a28d3cfUL) ]
        [ D(0, 0xb0f72bf9d8629110UL); D(1, 0x713fe67d9001650eUL) ]
        [ D(0, 0xf30052ff0effdffeUL); D(1, 0x116a4daff301d301UL) ] ]
    check false "f3ba03c2" inputs outputs

  /// <summary>
  /// F6.1.16 SHA256SU1: sha256su1.32 q0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.16 SHA256SU1``() =
    let inputs =
      [ [ D(0, 0x56a83a557eac6b3aUL)
          D(1, 0xcbaa53b899bd44c7UL)
          D(2, 0x580b418c8647a02bUL)
          D(3, 0x816ee81fa6b12fcdUL)
          D(4, 0x4e336c6f437ebd62UL)
          D(5, 0x38bcc3a26f2033afUL) ]
        [ D(0, 0xfc2634ec09c107c1UL)
          D(1, 0xe6bc65820749c014UL)
          D(2, 0x1c2896e0bf129fa5UL)
          D(3, 0x66341ed054cad6edUL)
          D(4, 0x0b6897b89c9dccb2UL)
          D(5, 0x6e8cf7313bbd756dUL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0x00ff00ff00ff00ffUL)
          D(2, 0x7fffffffffffffffUL)
          D(3, 0x8000000000000000UL)
          D(4, 0x8000000000000000UL)
          D(5, 0x8001800180018001UL) ] ]
    let outputs =
      [ [ D(0, 0xf704de9bf6713f3eUL); D(1, 0x03cc556fd371669fUL) ]
        [ D(0, 0x3656458339ff7495UL); D(1, 0x6dd69aa4c2542301UL) ]
        [ D(0, 0x6fa1ef60f0a0f05eUL); D(1, 0xcb46d35ee7178f77UL) ] ]
    check false "f3220c44" inputs outputs

  /// <summary>
  /// F6.1.39 VCADD: vcadd.f32 d0, d1, d2, #0x5a. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.39 VCADD``() =
    let inputs =
      [ [ D(0, 0x40c0000041400000UL)
          D(1, 0x40000000bec00000UL)
          D(2, 0xbf8000003d800000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x4140000041200000UL)
          D(1, 0x3f400000bf000000UL)
          D(2, 0x3e800000c0d00000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x800000007f800000UL)
          D(1, 0x7f80000040400000UL)
          D(2, 0x8000000000000000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x400400003f200000UL); FPSCR 0x00000000u ]
        [ D(0, 0xc0b80000bf400000UL); FPSCR 0x60000000u ]
        [ D(0, 0x7f80000040400000UL); FPSCR 0x00000000u ] ]
    check false "fc910802" inputs outputs

  /// <summary>
  /// F6.1.52 VCMLA: vcmla.f32 d0, d1, d2, #0x0. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.52 VCMLA``() =
    let inputs =
      [ [ D(0, 0xbec0000040200000UL)
          D(1, 0x3fe0000041400000UL)
          D(2, 0xbf8000003e800000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0xc240000040000000UL)
          D(1, 0xbf800000c0d00000UL)
          D(2, 0xc0d00000bec00000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x800000003f000000UL)
          D(1, 0xc010000040400000UL)
          D(2, 0xff80000040400000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xc146000040b00000UL); FPSCR 0x00000000u ]
        [ D(0, 0xc0b80000408e0000UL); FPSCR 0x60000000u ]
        [ D(0, 0xff80000041180000UL); FPSCR 0x00000000u ] ]
    check false "fc310802" inputs outputs

  /// <summary>
  /// F6.1.65 VCVTA: vcvta.s32.f32 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.65 VCVTA``() =
    let inputs =
      [ [ D(0, 0xbec00000c0600000UL); FPSCR 0x00000000u ]
        [ D(0, 0xc0d00000bec00000UL); FPSCR 0x60000000u ]
        [ D(0, 0x40400000ff800000UL); FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xbec0000000000000UL); FPSCR 0x00000010u ]
        [ D(0, 0xc0d00000fffffff9UL); FPSCR 0x60000010u ]
        [ D(0, 0x4040000000000003UL); FPSCR 0x00000000u ] ]
    check false "febc0ae0" inputs outputs

  /// <summary>
  /// F6.1.69 VCVTM: vcvtm.s32.f32 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.69 VCVTM``() =
    let inputs =
      [ [ D(0, 0xbec0000040000000UL); FPSCR 0x00000000u ]
        [ D(0, 0x40400000bf800000UL); FPSCR 0x60000000u ]
        [ D(0, 0x7f8000003fc00000UL); FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xbec00000ffffffffUL); FPSCR 0x00000010u ]
        [ D(0, 0x4040000000000003UL); FPSCR 0x60000000u ]
        [ D(0, 0x7f8000007fffffffUL); FPSCR 0x00000001u ] ]
    check false "febf0ae0" inputs outputs

  /// <summary>
  /// F6.1.71 VCVTN: vcvtn.s32.f32 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.71 VCVTN``() =
    let inputs =
      [ [ D(0, 0x40400000bec00000UL); FPSCR 0x00000000u ]
        [ D(0, 0x41200000bec00000UL); FPSCR 0x60000000u ]
        [ D(0, 0xff8000003f000000UL); FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x4040000000000003UL); FPSCR 0x00000000u ]
        [ D(0, 0x412000000000000aUL); FPSCR 0x60000000u ]
        [ D(0, 0xff80000080000000UL); FPSCR 0x00000001u ] ]
    check false "febd0ae0" inputs outputs

  /// <summary>
  /// F6.1.73 VCVTP: vcvtp.s32.f32 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.73 VCVTP``() =
    let inputs =
      [ [ D(0, 0xc060000040000000UL); FPSCR 0x00000000u ]
        [ D(0, 0x42c9000042c90000UL); FPSCR 0x60000000u ]
        [ D(0, 0x3f00000000000000UL); FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xc0600000fffffffdUL); FPSCR 0x00000010u ]
        [ D(0, 0x42c9000000000065UL); FPSCR 0x60000010u ]
        [ D(0, 0x3f00000000000001UL); FPSCR 0x00000010u ] ]
    check false "febe0ae0" inputs outputs

  /// <summary>
  /// F6.1.79 VDOT: vdot.bf16 d0, d1, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.79 VDOT``() =
    let inputs =
      [ [ D(0, 0xbf003f40c0103fc0UL)
          D(1, 0xbf003e00bf004020UL)
          D(2, 0x3fc04140c010c0d0UL) ]
        [ D(0, 0x3e00c060c240bf80UL)
          D(1, 0x40e84480c0404080UL)
          D(2, 0x448040803e004040UL) ]
        [ D(0, 0x40400000c0104040UL)
          D(1, 0xc0100000c0104040UL)
          D(2, 0xc0103fc03fc07f80UL) ] ]
    let outputs =
      [ [ D(0, 0x3e7f0300c18b07f8UL) ]
        [ D(0, 0x46340081c2123f80UL) ]
        [ D(0, 0x410100007f800000UL) ] ]
    check false "fc010d02" inputs outputs

  /// <summary>
  /// F6.1.87 VFMAB: vfmab.bf16 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.87 VFMAB``() =
    let inputs =
      [ [ D(0, 0x3d804040c2404040UL)
          D(1, 0x3d803fe0c06042c9UL)
          D(2, 0x4120c2404140bf00UL)
          D(3, 0xc0403fe0408040c0UL)
          D(4, 0x40203fc0c240c0d0UL)
          D(5, 0xbec0c04040c04020UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x40c03d80c0604040UL)
          D(1, 0xbf80c010bf80c010UL)
          D(2, 0x3d8040804080bf80UL)
          D(3, 0x40c042c9c040c0d0UL)
          D(4, 0xc0404000c240c060UL)
          D(5, 0x3fe03fe03e00bf00UL)
          FPSCR 0x60000000u ]
        [ D(0, 0xff803f003f003fc0UL)
          D(1, 0x3f003fc080000000UL)
          D(2, 0xc01000000000c010UL)
          D(3, 0xc010ff807f80c010UL)
          D(4, 0x800080004040ff80UL)
          D(5, 0x3fc080003fc07f80UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xc28fdff0c2334040UL)
          D(1, 0xc0a5ff004137ef4eUL)
          FPSCR 0x00000010u ]
        [ D(0, 0x41601ec0bb808000UL)
          D(1, 0x432ede80400f9ff8UL)
          FPSCR 0x60000010u ]
        [ D(0, 0x7fc000007f800000UL)
          D(1, 0x7fc00000ff800000UL)
          FPSCR 0x00000001u ] ]
    check false "fc320814" inputs outputs

  /// <summary>
  /// F6.1.87 VFMAT: vfmat.bf16 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.87 VFMAT``() =
    let inputs =
      [ [ D(0, 0x3e80c0403f403e80UL)
          D(1, 0xc010bf003d8040c0UL)
          D(2, 0x412042c944803e00UL)
          D(3, 0xbf804140c0604140UL)
          D(4, 0xbf803f404000bf00UL)
          D(5, 0xc24040e8c0d03d80UL)
          FPSCR 0x00000000u ]
        [ D(0, 0xc0403f40c0104040UL)
          D(1, 0xc0403e003e00bf00UL)
          D(2, 0xc0d0402040203d80UL)
          D(3, 0x3d803e003d8040e8UL)
          D(4, 0x42c9c0604020c240UL)
          D(5, 0x3f4042c93fc0c0d0UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x3fc0c0103f00ff80UL)
          D(1, 0x80003f007f803f00UL)
          D(2, 0x800040403f004040UL)
          D(3, 0xff807f803f000000UL)
          D(4, 0x3fc00000c0104040UL)
          D(5, 0x7f80c0103f000000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xc11bf9fe45000c04UL)
          D(1, 0x4236f41041b68041UL)
          FPSCR 0x00000010u ]
        [ D(0, 0xc424103f407fbfc0UL)
          D(1, 0xc03d3e003e60bf00UL)
          FPSCR 0x60000010u ]
        [ D(0, 0x3fc0c010bf1f0080UL)
          D(1, 0xff8000007fc00000UL)
          FPSCR 0x00000081u ] ]
    check false "fc320854" inputs outputs

  /// <summary>
  /// F6.1.89 VFMAL: vfmal.f16 d0, s2, s3. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.89 VFMAL``() =
    let inputs =
      [ [ D(0, 0x2c003a003f00bc00UL)
          D(1, 0x56484a00c2003a00UL)
          FPSCR 0x00000000u ]
        [ D(0, 0xb600c0804a00c200UL)
          D(1, 0x3a00440056484740UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x3e00fc0042003800UL)
          D(1, 0xfc0000003e008000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xc396c00041180bc0UL); FPSCR 0x00000010u ]
        [ D(0, 0x4296c0004a00c274UL); FPSCR 0x60000010u ]
        [ D(0, 0xff80000042003800UL); FPSCR 0x00000000u ] ]
    check false "fc210831" inputs outputs

  /// <summary>
  /// F6.1.92 VFMSL: vfmsl.f16 q0, d2, d3[1]. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.92 VFMSL``() =
    let inputs =
      [ [ D(0, 0x47406400c300d200UL)
          D(1, 0xc3003e0034004100UL)
          D(2, 0x2c00410046006400UL)
          D(3, 0xb8004a00c2004400UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x5648d2004100d200UL)
          D(1, 0x4600d200b800c680UL)
          D(2, 0x3a00c68056482c00UL)
          D(3, 0xc2003000c080d200UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x4200420038003800UL)
          D(1, 0x0000fc000000fc00UL)
          D(2, 0xc080fc003e008000UL)
          D(3, 0x3800c0803e00c080UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x474076004537f2e0UL)
          D(1, 0xc3000e0040f00000UL)
          FPSCR 0x00000010u ]
        [ D(0, 0x5648d20041031200UL)
          D(1, 0x4600d8c0c16a0020UL)
          FPSCR 0x60000010u ]
        [ D(0, 0x41ee840038003800UL)
          D(1, 0x405800007f800000UL)
          FPSCR 0x00000080u ] ]
    check false "fe12085b" inputs outputs

  /// <summary>
  /// F6.1.98 VINS: vins.f16 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.98 VINS``() =
    let inputs =
      [ [ D(0, 0xd2003a00bc00c680UL) ]
        [ D(0, 0xb800c0806400d200UL) ]
        [ D(0, 0xfc00c080fc008000UL) ] ]
    let outputs =
      [ [ D(0, 0xd2003a003a00c680UL) ]
        [ D(0, 0xb800c080c080d200UL) ]
        [ D(0, 0xfc00c080c0808000UL) ] ]
    check false "feb00ae0" inputs outputs

  /// <summary>
  /// F6.1.99 VJCVT: vjcvt.s32.f64 s0, d1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.99 VJCVT``() =
    let inputs =
      [ [ D(0, 0x4028000000000000UL)
          D(1, 0xc008000000000000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x3ff8000000000000UL)
          D(1, 0xbff0000000000000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x0000000000000000UL)
          D(1, 0xfff0000000000000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x40280000fffffffdUL); FPSCR 0x40000000u ]
        [ D(0, 0x3ff80000ffffffffUL); FPSCR 0x40000000u ]
        [ D(0, 0x0000000000000000UL); FPSCR 0x00000001u ] ]
    check false "eeb90bc1" inputs outputs

  /// <summary>
  /// F6.1.112 VLDMDB: vldmdb r1!, {d0-d1}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.112 VLDMDB``() =
    let inputs =
      [ [ Gpr(1, 0x20000828u)
          D(0, 0x2780e0bd8044664dUL)
          D(1, 0x8ca7a6b62a7c01ebUL)
          M(0, 0x45ebf4f3be85ecb7UL)
          M(8, 0xc060fc165b638c40UL)
          M(16, 0x0ee19469b936ca63UL)
          M(24, 0xbedd48a0a282ec8fUL)
          M(32, 0x4c4c704b09f830e6UL)
          M(40, 0x32655a75d9d444c8UL)
          M(48, 0x7aa09596654bbf72UL)
          M(56, 0xd0ba5b2e9c29a13bUL) ]
        [ Gpr(1, 0x20000828u)
          D(0, 0xe33d5766aff6fe63UL)
          D(1, 0x7f92834a7baade4bUL)
          M(0, 0x4a216e96b3ab1207UL)
          M(8, 0x22f7d5df91690663UL)
          M(16, 0xee92c4825621f97aUL)
          M(24, 0x1fdd3de8770e5e5fUL)
          M(32, 0xb1430aed643a9193UL)
          M(40, 0x24e5453b071996ecUL)
          M(48, 0xd8772e517431be16UL)
          M(56, 0x9ff44e9b5ffb09b4UL) ]
        [ Gpr(1, 0x20000828u)
          D(0, 0x0000000000000001UL)
          D(1, 0x0102030405060708UL)
          M(0, 0x11e9fa9cc5e0a99eUL)
          M(8, 0x10b07445280196d7UL)
          M(16, 0xf953a203c304a408UL)
          M(24, 0xe07588bd26c83012UL)
          M(32, 0x74b91fb568ec2b0dUL)
          M(40, 0xfa4c2ea51755137eUL)
          M(48, 0xe0f3f6baf421557dUL)
          M(56, 0xf0ac4335048da08fUL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000818u)
          D(0, 0xbedd48a0a282ec8fUL)
          D(1, 0x4c4c704b09f830e6UL) ]
        [ Gpr(1, 0x20000818u)
          D(0, 0x1fdd3de8770e5e5fUL)
          D(1, 0xb1430aed643a9193UL) ]
        [ Gpr(1, 0x20000818u)
          D(0, 0xe07588bd26c83012UL)
          D(1, 0x74b91fb568ec2b0dUL) ] ]
    check false "ed310b04" inputs outputs

  /// <summary>
  /// F6.1.112 VLDMIA: vldmia r1, {d0, d1}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.112 VLDMIA``() =
    let inputs =
      [ [ Gpr(1, 0x20000818u)
          D(0, 0x83bc6c9b190eb214UL)
          D(1, 0xe97484b45bebf069UL)
          M(0, 0x3d211825d75102fcUL)
          M(8, 0x343dd935186b4f68UL)
          M(16, 0xbc73709a9a16a801UL)
          M(24, 0xdb4436cb3b2123e8UL)
          M(32, 0xc498789f0fa4bdfcUL)
          M(40, 0x4da392d37b35befdUL)
          M(48, 0xe1b763bbdabb9bd5UL)
          M(56, 0xaaefe924a58386ffUL) ]
        [ Gpr(1, 0x20000818u)
          D(0, 0x6f1aef6dea093f37UL)
          D(1, 0xcaee11044270bdf3UL)
          M(0, 0x2805316dbfafabfbUL)
          M(8, 0x8a425ce994812938UL)
          M(16, 0x26ec7a5bb6b0ea1dUL)
          M(24, 0x18159b77ab924b67UL)
          M(32, 0xecd08420edc71f7dUL)
          M(40, 0xaf87ada7b4e6ab88UL)
          M(48, 0x2c738aa547eaf026UL)
          M(56, 0x6086cf98f417d6c7UL) ]
        [ Gpr(1, 0x20000818u)
          D(0, 0xffffffffffffffffUL)
          D(1, 0x0102030405060708UL)
          M(0, 0x055416a862f9201bUL)
          M(8, 0xa60fe3b358a7c151UL)
          M(16, 0x658df459229e42bfUL)
          M(24, 0x7c4f3b41cd6a06efUL)
          M(32, 0x0e7c34d8f43e788dUL)
          M(40, 0xb6201d84b2efed12UL)
          M(48, 0x8b8cd8cd44165d53UL)
          M(56, 0x57b5207be3e1d941UL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000818u)
          D(0, 0xdb4436cb3b2123e8UL)
          D(1, 0xc498789f0fa4bdfcUL) ]
        [ Gpr(1, 0x20000818u)
          D(0, 0x18159b77ab924b67UL)
          D(1, 0xecd08420edc71f7dUL) ]
        [ Gpr(1, 0x20000818u)
          D(0, 0x7c4f3b41cd6a06efUL)
          D(1, 0x0e7c34d8f43e788dUL) ] ]
    check false "ec910b04" inputs outputs

  /// <summary>
  /// F6.1.117 VMAXNM: vmaxnm.f32 s0, s1, s2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.117 VMAXNM``() =
    let inputs =
      [ [ D(0, 0x3e000000bf800000UL)
          D(1, 0x44800000c0400000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0xc010000040400000UL)
          D(1, 0xc0d000003e800000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x3fc000003fc00000UL)
          D(1, 0x0000000080000000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x3e0000003e000000UL); FPSCR 0x00000000u ]
        [ D(0, 0xc01000003e800000UL); FPSCR 0x60000000u ]
        [ D(0, 0x3fc000003fc00000UL); FPSCR 0x00000000u ] ]
    check false "fe800a81" inputs outputs

  /// <summary>
  /// F6.1.120 VMINNM: vminnm.f32 s0, s1, s2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.120 VMINNM``() =
    let inputs =
      [ [ D(0, 0xc010000041400000UL)
          D(1, 0x3d800000c0400000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x4480000044800000UL)
          D(1, 0xbec000003d800000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x3f000000c0100000UL)
          D(1, 0xc01000003fc00000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xc0100000c0400000UL); FPSCR 0x00000000u ]
        [ D(0, 0x448000003d800000UL); FPSCR 0x60000000u ]
        [ D(0, 0x3f0000003f000000UL); FPSCR 0x00000000u ] ]
    check false "fe800ac1" inputs outputs

  /// <summary>
  /// F6.1.131 VMMLA: vmmla.bf16 q0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.131 VMMLA``() =
    let inputs =
      [ [ D(0, 0x3d80c0d0c06040c0UL)
          D(1, 0xc0104020bf0040c0UL)
          D(2, 0xc0d0c0d03e00c010UL)
          D(3, 0x4040c010bec042c9UL)
          D(4, 0xbf80bec040e84120UL)
          D(5, 0xc060c04040e83fc0UL) ]
        [ D(0, 0xbf803fc040203fe0UL)
          D(1, 0xbf0040c0bf00bf00UL)
          D(2, 0xc240404040c03d80UL)
          D(3, 0x40204480c0103d80UL)
          D(4, 0xc0403fe03e804020UL)
          D(5, 0x41203fc03fc04020UL) ]
        [ D(0, 0xff8040407f807f80UL)
          D(1, 0x80003fc03fc0ff80UL)
          D(2, 0xff8000003fc03f00UL)
          D(3, 0xff80c0107f808000UL)
          D(4, 0x3f003fc00000ff80UL)
          D(5, 0x40403f003fc03f00UL) ] ]
    let outputs =
      [ [ D(0, 0x421f6061c1814818UL); D(1, 0x430e06ff4479e7efUL) ]
        [ D(0, 0xc3e9ac3f431968ffUL); D(1, 0x44c2a8f744def2e9UL) ]
        [ D(0, 0x7fc000007fc00000UL); D(1, 0x7fc000007fc00000UL) ] ]
    check false "fc020c44" inputs outputs

  /// <summary>
  /// F6.1.143 VMOVX: vmovx.f16 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.143 VMOVX``() =
    let inputs =
      [ [ D(0, 0xb8003e00c200d200UL) ]
        [ D(0, 0xb600340042004900UL) ]
        [ D(0, 0x8000c0804200c080UL) ] ]
    let outputs =
      [ [ D(0, 0xb8003e000000b800UL) ]
        [ D(0, 0xb60034000000b600UL) ]
        [ D(0, 0x8000c08000008000UL) ] ]
    check false "feb00a60" inputs outputs

  /// <summary>
  /// F6.1.179 VQRDMLAH: vqrdmlah.s16 d0, d1, d2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.179 VQRDMLAH``() =
    let inputs =
      [ [ D(0, 0x50f799b1b81fe00dUL)
          D(1, 0x5fb1b16843acebfcUL)
          D(2, 0x7a8374fc5e04963cUL)
          FPSCR 0x00000000u ]
        [ D(0, 0x6dc514eacb5475b7UL)
          D(1, 0x4351107805653974UL)
          D(2, 0x706fb28f54e2201bUL)
          FPSCR 0x60000000u ]
        [ D(0, 0xffffffffffffffffUL)
          D(1, 0x8000000000000000UL)
          D(2, 0x7fffffffffffffffUL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x7fff8000e9d3f097UL); FPSCR 0x08000000u ]
        [ D(0, 0x7fff0af3cee87fffUL); FPSCR 0x68000000u ]
        [ D(0, 0x8000ffffffffffffUL); FPSCR 0x00000000u ] ]
    check false "f3110b12" inputs outputs

  /// <summary>
  /// F6.1.180 VQRDMLSH: vqrdmlsh.s32 q0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.180 VQRDMLSH``() =
    let inputs =
      [ [ D(0, 0x7012a9bd0701855eUL)
          D(1, 0xdf70e97c7b4b1eb0UL)
          D(2, 0x3ed9b2a494c1c0e6UL)
          D(3, 0x9609e4a2cb306429UL)
          D(4, 0x183bc4c7bf28c51fUL)
          D(5, 0x6920a02b6db1307dUL)
          FPSCR 0x00000000u ]
        [ D(0, 0xc21a0cf10e60d174UL)
          D(1, 0x08f603c74d3ddedcUL)
          D(2, 0x69ca6c67b7da2282UL)
          D(3, 0x73165db5c67d1a93UL)
          D(4, 0x38df555544e46549UL)
          D(5, 0x9b73fbe4d72ad0b7UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x7fffffffffffffffUL)
          D(1, 0x7fffffffffffffffUL)
          D(2, 0x7fffffffffffffffUL)
          D(3, 0x0000000000000001UL)
          D(4, 0x00ff00ff00ff00ffUL)
          D(5, 0xffffffffffffffffUL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x642c7f47d0ae11eeUL)
          D(1, 0x3677ce0d7fffffffUL)
          FPSCR 0x08000000u ]
        [ D(0, 0x9318e8543535aba8UL)
          D(1, 0x635d61253ae52e19UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x7f00ff00ffffffffUL)
          D(1, 0x7fffffffffffffffUL)
          FPSCR 0x00000000u ] ]
    check false "f3220c54" inputs outputs

  /// <summary>
  /// F6.1.199 VRINTA: vrinta.f32 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.199 VRINTA``() =
    let inputs =
      [ [ D(0, 0x42c9000041200000UL); FPSCR 0x00000000u ]
        [ D(0, 0x40c000003d800000UL); FPSCR 0x60000000u ]
        [ D(0, 0x000000007f800000UL); FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x42c9000042ca0000UL); FPSCR 0x00000000u ]
        [ D(0, 0x40c0000040c00000UL); FPSCR 0x60000000u ]
        [ D(0, 0x0000000000000000UL); FPSCR 0x00000000u ] ]
    check false "feb80a60" inputs outputs

  /// <summary>
  /// F6.1.201 VRINTM: vrintm.f32 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.201 VRINTM``() =
    let inputs =
      [ [ D(0, 0x41400000c2400000UL); FPSCR 0x00000000u ]
        [ D(0, 0x4020000040800000UL); FPSCR 0x60000000u ]
        [ D(0, 0xff800000ff800000UL); FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x4140000041400000UL); FPSCR 0x00000000u ]
        [ D(0, 0x4020000040000000UL); FPSCR 0x60000000u ]
        [ D(0, 0xff800000ff800000UL); FPSCR 0x00000000u ] ]
    check false "febb0a60" inputs outputs

  /// <summary>
  /// F6.1.203 VRINTN: vrintn.f32 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.203 VRINTN``() =
    let inputs =
      [ [ D(0, 0x40800000bec00000UL); FPSCR 0x00000000u ]
        [ D(0, 0x3fc00000c0d00000UL); FPSCR 0x60000000u ]
        [ D(0, 0x4040000040400000UL); FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x4080000040800000UL); FPSCR 0x00000000u ]
        [ D(0, 0x3fc0000040000000UL); FPSCR 0x60000000u ]
        [ D(0, 0x4040000040400000UL); FPSCR 0x00000000u ] ]
    check false "feb90a60" inputs outputs

  /// <summary>
  /// F6.1.205 VRINTP: vrintp.f32 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.205 VRINTP``() =
    let inputs =
      [ [ D(0, 0x42c90000c0400000UL); FPSCR 0x00000000u ]
        [ D(0, 0x4080000040c00000UL); FPSCR 0x60000000u ]
        [ D(0, 0x000000003f000000UL); FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x42c9000042ca0000UL); FPSCR 0x00000000u ]
        [ D(0, 0x4080000040800000UL); FPSCR 0x60000000u ]
        [ D(0, 0x0000000000000000UL); FPSCR 0x00000000u ] ]
    check false "feba0a60" inputs outputs

  /// <summary>
  /// F6.1.207 VRINTR: vrintr.f32 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.207 VRINTR``() =
    let inputs =
      [ [ D(0, 0xc04000003f400000UL); FPSCR 0x00000000u ]
        [ D(0, 0x4140000041200000UL); FPSCR 0x60000000u ]
        [ D(0, 0x4040000000000000UL); FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xc0400000c0400000UL); FPSCR 0x00000000u ]
        [ D(0, 0x4140000041400000UL); FPSCR 0x60000000u ]
        [ D(0, 0x4040000040400000UL); FPSCR 0x00000000u ] ]
    check false "eeb60a60" inputs outputs

  /// <summary>
  /// F6.1.208 VRINTX: vrintx.f32 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.208 VRINTX``() =
    let inputs =
      [ [ D(0, 0x3e80000044800000UL); FPSCR 0x00000000u ]
        [ D(0, 0x3d8000003fe00000UL); FPSCR 0x60000000u ]
        [ D(0, 0x404000003f000000UL); FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x3e80000000000000UL); FPSCR 0x00000010u ]
        [ D(0, 0x3d80000000000000UL); FPSCR 0x60000010u ]
        [ D(0, 0x4040000040400000UL); FPSCR 0x00000000u ] ]
    check false "eeb70a60" inputs outputs

  /// <summary>
  /// F6.1.210 VRINTZ: vrintz.f32 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.210 VRINTZ``() =
    let inputs =
      [ [ D(0, 0xbec0000040e80000UL); FPSCR 0x00000000u ]
        [ D(0, 0x40e8000040e80000UL); FPSCR 0x60000000u ]
        [ D(0, 0x80000000ff800000UL); FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xbec0000080000000UL); FPSCR 0x00000000u ]
        [ D(0, 0x40e8000040e00000UL); FPSCR 0x60000000u ]
        [ D(0, 0x8000000080000000UL); FPSCR 0x00000000u ] ]
    check false "eeb60ae0" inputs outputs

  /// <summary>
  /// F6.1.221 VSDOT: vsdot.s8 d0, d1, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.221 VSDOT``() =
    let inputs =
      [ [ D(0, 0x0c619891e00d53bcUL)
          D(1, 0xb8973d27234cc900UL)
          D(2, 0x9442102ac516a58bUL) ]
        [ D(0, 0xd9f0f00225b7a387UL)
          D(1, 0x45774dc44a542ef6UL)
          D(2, 0x5d680b55f06f0698UL) ]
        [ D(0, 0x8000000000000000UL)
          D(1, 0x0000000000000001UL)
          D(2, 0x0000000000000001UL) ] ]
    let outputs =
      [ [ D(0, 0x0c61a615e00d65c0UL) ]
        [ D(0, 0xd9f128ce25b7c877UL) ]
        [ D(0, 0x8000000000000001UL) ] ]
    check false "fc210d02" inputs outputs

  /// <summary>
  /// F6.1.223 VSELEQ: vseleq.f32 s0, s1, s2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.223 VSELEQ``() =
    let inputs =
      [ [ D(0, 0x4480000042c90000UL)
          D(1, 0xc240000040e80000UL)
          CPSR 0x20000010u ]
        [ D(0, 0x3e8000003fe00000UL)
          D(1, 0x400000003f400000UL)
          CPSR 0x900a0010u ]
        [ D(0, 0xff8000003fc00000UL)
          D(1, 0x40400000c0100000UL)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ D(0, 0x4480000040e80000UL) ]
        [ D(0, 0x3e8000003f400000UL) ]
        [ D(0, 0xff800000ff800000UL) ] ]
    check false "fe000a81" inputs outputs

  /// <summary>
  /// F6.1.223 VSELGE: vselge.f64 d0, d1, d2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.223 VSELGE``() =
    let inputs =
      [ [ D(0, 0x4090000000000000UL)
          D(1, 0x4010000000000000UL)
          D(2, 0xc048000000000000UL)
          CPSR 0x20000010u ]
        [ D(0, 0xbfd8000000000000UL)
          D(1, 0x4000000000000000UL)
          D(2, 0x3fd0000000000000UL)
          CPSR 0x900a0010u ]
        [ D(0, 0x0000000000000000UL)
          D(1, 0xfff0000000000000UL)
          D(2, 0x3fe0000000000000UL)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ D(0, 0x4010000000000000UL) ]
        [ D(0, 0x4000000000000000UL) ]
        [ D(0, 0xfff0000000000000UL) ] ]
    check false "fe210b02" inputs outputs

  /// <summary>
  /// F6.1.223 VSELGT: vselgt.f32 s0, s1, s2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.223 VSELGT``() =
    let inputs =
      [ [ D(0, 0x3fc0000041400000UL)
          D(1, 0xbec00000c0d00000UL)
          CPSR 0x20000010u ]
        [ D(0, 0x414000003fc00000UL)
          D(1, 0x3d80000044800000UL)
          CPSR 0x900a0010u ]
        [ D(0, 0x4040000040400000UL)
          D(1, 0x7f800000ff800000UL)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ D(0, 0x3fc000003fc00000UL) ]
        [ D(0, 0x4140000041400000UL) ]
        [ D(0, 0x40400000ff800000UL) ] ]
    check false "fe300a81" inputs outputs

  /// <summary>
  /// F6.1.223 VSELVS: vselvs.f64 d0, d1, d2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.223 VSELVS``() =
    let inputs =
      [ [ D(0, 0x3fe8000000000000UL)
          D(1, 0xc008000000000000UL)
          D(2, 0xc048000000000000UL)
          CPSR 0x20000010u ]
        [ D(0, 0x4004000000000000UL)
          D(1, 0x4024000000000000UL)
          D(2, 0x3fd0000000000000UL)
          CPSR 0x900a0010u ]
        [ D(0, 0x0000000000000000UL)
          D(1, 0xc002000000000000UL)
          D(2, 0x4008000000000000UL)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ D(0, 0xc048000000000000UL) ]
        [ D(0, 0x4024000000000000UL) ]
        [ D(0, 0x4008000000000000UL) ] ]
    check false "fe110b02" inputs outputs

  /// <summary>
  /// F6.1.232 VSMMLA: vsmmla.s8 q0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.232 VSMMLA``() =
    let inputs =
      [ [ D(0, 0x08399930871cbc07UL)
          D(1, 0x4f36615dfa865b68UL)
          D(2, 0xbfa70c43df244d8fUL)
          D(3, 0x84460a27ca3f86b2UL)
          D(4, 0x773a4b94405be9e1UL)
          D(5, 0xd19018754fb0d73bUL) ]
        [ D(0, 0xec6c7b66f75a19f4UL)
          D(1, 0x61c51785cc970faaUL)
          D(2, 0x441d47efe3850154UL)
          D(3, 0x54f12d44b88b0f99UL)
          D(4, 0x48ae8a03b49716d4UL)
          D(5, 0xef683d0f01dc35e5UL) ]
        [ D(0, 0x0102030405060708UL)
          D(1, 0x0102030405060708UL)
          D(2, 0x00ff00ff00ff00ffUL)
          D(3, 0x7fffffffffffffffUL)
          D(4, 0x7f80ff00807fffffUL)
          D(5, 0x7f80ff00807fffffUL) ] ]
    let outputs =
      [ [ D(0, 0x0839afff871c7c36UL); D(1, 0x4f36497afa864167UL) ]
        [ D(0, 0xec6c9b1ef75a2f92UL); D(1, 0x61c538b2cc977081UL) ]
        [ D(0, 0x010203060506070aUL); D(1, 0x010242890506468dUL) ] ]
    check false "fc220c44" inputs outputs

  /// <summary>
  /// F6.1.244 VSTMDB: vstmdb r1!, {d0-d1}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.244 VSTMDB``() =
    let inputs =
      [ [ Gpr(1, 0x20000828u)
          D(0, 0x26e8748cb0889d8fUL)
          D(1, 0x945775ec06ac32a1UL)
          M(0, 0xe0e84594267c6e69UL)
          M(8, 0x706b77a67a00b853UL)
          M(16, 0x6836529ae674b9dfUL)
          M(24, 0x1e54c23af339a164UL)
          M(32, 0xed0a778b0b67c408UL)
          M(40, 0x25510bb00cdf7d54UL)
          M(48, 0xf949fc310988e293UL)
          M(56, 0x2a9894cc9f514790UL) ]
        [ Gpr(1, 0x20000828u)
          D(0, 0x8f6626099b06519bUL)
          D(1, 0x5ee04464810c34f0UL)
          M(0, 0x432793250d5e3b56UL)
          M(8, 0x91ac432fa435c69dUL)
          M(16, 0x457b537d8bb87a25UL)
          M(24, 0x64eafb033ca03dc0UL)
          M(32, 0x829b823f4cf0b740UL)
          M(40, 0xd5ee5cb7dd418228UL)
          M(48, 0xaddce65c0bf22febUL)
          M(56, 0x2b0c694e7eea1944UL) ]
        [ Gpr(1, 0x20000828u)
          D(0, 0x7f80ff00807fffffUL)
          D(1, 0x8000000000000000UL)
          M(0, 0x86bf248cb41ca10bUL)
          M(8, 0xfca38d81ec8e0f71UL)
          M(16, 0xa71e55045384cd5eUL)
          M(24, 0x246572c05c8462beUL)
          M(32, 0x6d6fc2b77e7b9beaUL)
          M(40, 0x17b65421800526c2UL)
          M(48, 0xa7ea9c3041cd5b85UL)
          M(56, 0x9b41d474edd7c35eUL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000818u)
          M(24, 0x26e8748cb0889d8fUL)
          M(32, 0x945775ec06ac32a1UL) ]
        [ Gpr(1, 0x20000818u)
          M(24, 0x8f6626099b06519bUL)
          M(32, 0x5ee04464810c34f0UL) ]
        [ Gpr(1, 0x20000818u)
          M(24, 0x7f80ff00807fffffUL)
          M(32, 0x8000000000000000UL) ] ]
    check false "ed210b04" inputs outputs

  /// <summary>
  /// F6.1.244 VSTMIA: vstmia r1, {s0, s1, s2, s3}. The outputs are what QEMU
  /// left after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.244 VSTMIA``() =
    let inputs =
      [ [ Gpr(1, 0x20000818u)
          D(0, 0x468a458beb0aaef3UL)
          D(1, 0x4ebfa1a84e07ac00UL)
          M(0, 0x8dcece674f57e441UL)
          M(8, 0x0dd9029501f981ddUL)
          M(16, 0xee5ee7e3b6dd1ac4UL)
          M(24, 0xcabcf9ee3bc888c6UL)
          M(32, 0x8838ca20293ed542UL)
          M(40, 0x92cde554d05a8016UL)
          M(48, 0xc277b3a305b559bbUL)
          M(56, 0xdbcacc1f71186025UL) ]
        [ Gpr(1, 0x20000818u)
          D(0, 0x32c54e39b0634b39UL)
          D(1, 0x387cf220b608a297UL)
          M(0, 0x870d9c1e783f3318UL)
          M(8, 0xe5f6e72ec4ce3cb0UL)
          M(16, 0x234c0a9114c6c8d7UL)
          M(24, 0x78280141ccf82a63UL)
          M(32, 0x5d4d2344897a2902UL)
          M(40, 0xae6656b7b482e035UL)
          M(48, 0x63a1367a2a109ce9UL)
          M(56, 0xf13f5a60960524d3UL) ]
        [ Gpr(1, 0x20000818u)
          D(0, 0x7f80ff00807fffffUL)
          D(1, 0x8000000000000000UL)
          M(0, 0x58869a2eee607bb7UL)
          M(8, 0xcff7354011277acdUL)
          M(16, 0x03a43e4cb9971e4aUL)
          M(24, 0x4be748f7e16b8145UL)
          M(32, 0x25f4d7db109ce623UL)
          M(40, 0xa345518439f4cea6UL)
          M(48, 0x02fcb34e0bf5a313UL)
          M(56, 0xeb242b565cf13000UL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000818u)
          M(24, 0x468a458beb0aaef3UL)
          M(32, 0x4ebfa1a84e07ac00UL) ]
        [ Gpr(1, 0x20000818u)
          M(24, 0x32c54e39b0634b39UL)
          M(32, 0x387cf220b608a297UL) ]
        [ Gpr(1, 0x20000818u)
          M(24, 0x7f80ff00807fffffUL)
          M(32, 0x8000000000000000UL) ] ]
    check false "ec810a04" inputs outputs

  /// <summary>
  /// F6.1.251 VSUDOT: vsudot.u8 d0, d1, d2[0]. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.251 VSUDOT``() =
    let inputs =
      [ [ D(0, 0xd5ac8e0692ef7939UL)
          D(1, 0x4708a54034aa2e74UL)
          D(2, 0x1c3130f010c02f4eUL) ]
        [ D(0, 0xa019bc888a601079UL)
          D(1, 0x105fd11bdf2b0861UL)
          D(2, 0xa6ac426bf2f3e89eUL) ]
        [ D(0, 0x8001800180018001UL)
          D(1, 0x8001800180018001UL)
          D(2, 0x8001800180018001UL) ] ]
    let outputs =
      [ [ D(0, 0xd5ac9b4192ef67c3UL) ]
        [ D(0, 0xa01a0be78a605d36UL) ]
        [ D(0, 0x8001000380010003UL) ] ]
    check false "fe810d12" inputs outputs

  /// <summary>
  /// F6.1.256 VUDOT: vudot.u8 q0, q1, d4[1]. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.256 VUDOT``() =
    let inputs =
      [ [ D(0, 0xe10ec4b37cf8ddbcUL)
          D(1, 0x8440e59538196048UL)
          D(2, 0xcebe06c36bdc9f04UL)
          D(3, 0xf841311a4113b45bUL)
          D(4, 0x7433791bb15f69e7UL) ]
        [ D(0, 0xb56cdb80d6ee8c63UL)
          D(1, 0x4586b77ad6247258UL)
          D(2, 0xf0b82758a8fa83f6UL)
          D(3, 0x92d4835e52ca5940UL)
          D(4, 0xd98b9e130a615352UL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0x8001800180018001UL)
          D(3, 0x0102030405060708UL)
          D(4, 0x0000000000000001UL) ] ]
    let outputs =
      [ [ D(0, 0xe10f5f4c7cf9859fUL); D(1, 0x84417ccf3819e032UL) ]
        [ D(0, 0xb56e2972d6f005a5UL); D(1, 0x4587fe2cd6256136UL) ]
        [ D(0, 0x7f80ff00807fffffUL); D(1, 0xffffffffffffffffUL) ] ]
    check false "fe220d74" inputs outputs

  /// <summary>
  /// F6.1.258 VUMMLA: vummla.u8 q0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.258 VUMMLA``() =
    let inputs =
      [ [ D(0, 0x6aec4215af3c3d3eUL)
          D(1, 0x3b6491ddd14b07e8UL)
          D(2, 0xefcb79960b6cb6deUL)
          D(3, 0x2e54bb29aba08b60UL)
          D(4, 0xa567d3c4e67df49eUL)
          D(5, 0x9594e4f3d90bc9cbUL) ]
        [ D(0, 0xfe08260c54758a58UL)
          D(1, 0x34e3768cc262cd24UL)
          D(2, 0x9bb5a5f274e8fe7dUL)
          D(3, 0x67a468c6124e5127UL)
          D(4, 0x9c317c2cbd6f7b30UL)
          D(5, 0x3c3360f5264d1400UL) ]
        [ D(0, 0x8000000000000000UL)
          D(1, 0x8001800180018001UL)
          D(2, 0x8000000000000000UL)
          D(3, 0x00ff00ff00ff00ffUL)
          D(4, 0x8000000000000000UL)
          D(5, 0x7fffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x6aef8999af3f74a3UL); D(1, 0x3b66fbc0d14da85dUL) ]
        [ D(0, 0xfe09fec15477d0abUL); D(1, 0x34e4b450c263dd0bUL) ]
        [ D(0, 0x80003f8000004000UL); D(1, 0x8005780580018001UL) ] ]
    check false "fc220c54" inputs outputs

  /// <summary>
  /// F6.1.259 VUSDOT: vusdot.s8 d0, d1, d2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.259 VUSDOT``() =
    let inputs =
      [ [ D(0, 0xfbdc73102f5858d8UL)
          D(1, 0xb588656eb1d3c0a8UL)
          D(2, 0x12ef1e1e4f1e496dUL) ]
        [ D(0, 0xc59c049b80bba252UL)
          D(1, 0x2a29edf0e5c31cabUL)
          D(2, 0xf1b7e945586b1f82UL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0x8001800180018001UL)
          D(2, 0x7fffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0xfbdc8f7c2f592679UL) ]
        [ D(0, 0xc59c21d980bbf1c5UL) ]
        [ D(0, 0x7f813dfe807ffefdUL) ] ]
    check false "fca10d02" inputs outputs

  /// <summary>
  /// F6.1.261 VUSMMLA: vusmmla.s8 q0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.261 VUSMMLA``() =
    let inputs =
      [ [ D(0, 0x0a81120d5fce0f03UL)
          D(1, 0x27fc0e1f6d217189UL)
          D(2, 0x6d9b7f6ca7c16af0UL)
          D(3, 0x77c2f12dfdf1f1fcUL)
          D(4, 0x239836063980421fUL)
          D(5, 0xb931960bdf79f78aUL) ]
        [ D(0, 0xe6a33643cc201b27UL)
          D(1, 0x67202d3fe5fe3a33UL)
          D(2, 0x669b3a9a1158309cUL)
          D(3, 0xf1c2418981dc04dbUL)
          D(4, 0xe41de9f5e52ae9ccUL)
          D(5, 0x834873f83652442aUL) ]
        [ D(0, 0x7fffffffffffffffUL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0x8000000000000000UL)
          D(3, 0x8001800180018001UL)
          D(4, 0x8001800180018001UL)
          D(5, 0x8001800180018001UL) ] ]
    let outputs =
      [ [ D(0, 0x0a80b4e35fcdf957UL); D(1, 0x27fb85106d21835dUL) ]
        [ D(0, 0xe6a38b69cc1ffe5fUL); D(1, 0x67208db9e5fe13bcUL) ]
        [ D(0, 0x7fffbfffffffbfffUL); D(1, 0xffff0003ffff0003UL) ] ]
    check false "fca20c44" inputs outputs
