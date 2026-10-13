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
/// One test for each instruction DDI0406C and DDI0487F.c describe, A8.8.177
/// SMLABB to A8.8.303 VCLZ in the order of their sections. A value test runs a
/// word's lifting with IRRunner over inputs QEMU ran the word on (qemu-arm -cpu
/// max) and asserts what QEMU left. A structural test is for a word a user-mode
/// run cannot execute alone; its doc comment says what it checks, and its
/// expectation is the manual's.
/// </summary>
[<TestClass>]
type ManualLifterTests2() =
  /// <summary>
  /// A8.8.177 SMLABB: smlabb r0, r1, r2, r3. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.177 SMLABB``() =
    let inputs =
      [ [ Gpr(0, 0xb42b3feau)
          Gpr(1, 0x1d294439u)
          Gpr(2, 0x40ba6fedu)
          Gpr(3, 0x8f2c9f26u)
          CPSR 0x20000010u ]
        [ Gpr(0, 0x98e4d05eu)
          Gpr(1, 0xcc3e059du)
          Gpr(2, 0x51d79b3cu)
          Gpr(3, 0xf6f84595u)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Gpr(3, 0x00000003u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xad007eebu); CPSR 0x20000010u ]
        [ Gpr(0, 0xf4c2a561u); CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000003u); CPSR 0x48050010u ] ]
    check false "e1003281" inputs outputs

  /// <summary>
  /// A8.8.177 SMLABT: smlabt r0, r1, r2, r3. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.177 SMLABT``() =
    let inputs =
      [ [ Gpr(0, 0x34c26e19u)
          Gpr(1, 0x3e14b576u)
          Gpr(2, 0xe1ac481du)
          Gpr(3, 0x100e3090u)
          CPSR 0x20000010u ]
        [ Gpr(0, 0xeb2356e0u)
          Gpr(1, 0x6d22209fu)
          Gpr(2, 0x7e1bbf23u)
          Gpr(3, 0xb20c5b9bu)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Gpr(3, 0x00000003u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x18e2d1d8u); CPSR 0x20000010u ]
        [ Gpr(0, 0xc21e0e60u); CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000003u); CPSR 0x48050010u ] ]
    check false "e10032c1" inputs outputs

  /// <summary>
  /// A8.8.177 SMLATB: smlatb r0, r1, r2, r3. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.177 SMLATB``() =
    let inputs =
      [ [ Gpr(0, 0x4f8f23c2u)
          Gpr(1, 0x12ede41bu)
          Gpr(2, 0xd204fd6cu)
          Gpr(3, 0xa3589811u)
          CPSR 0x20000010u ]
        [ Gpr(0, 0x1e4ba1d0u)
          Gpr(1, 0x745d9ec4u)
          Gpr(2, 0xd0dd84a4u)
          Gpr(3, 0xc5ccb9d7u)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Gpr(3, 0x00000003u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xa327cd0du); CPSR 0x20000010u ]
        [ Gpr(0, 0x8dba396bu); CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000003u); CPSR 0x48050010u ] ]
    check false "e10032a1" inputs outputs

  /// <summary>
  /// A8.8.177 SMLATT: smlatt r0, r1, r2, r3. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.177 SMLATT``() =
    let inputs =
      [ [ Gpr(0, 0x071393d1u)
          Gpr(1, 0x4ace3d91u)
          Gpr(2, 0x82f50bedu)
          Gpr(3, 0x84fe217fu)
          CPSR 0x20000010u ]
        [ Gpr(0, 0x5a35e897u)
          Gpr(1, 0xfe887406u)
          Gpr(2, 0x7279efd1u)
          Gpr(3, 0xeb0d8981u)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Gpr(3, 0x00000003u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x607454a5u); CPSR 0x28000010u ]
        [ Gpr(0, 0xea6567c9u); CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000003u); CPSR 0x48050010u ] ]
    check false "e10032e1" inputs outputs

  /// <summary>
  /// A8.8.178 SMLAD: smlad r0, r1, r2, r3. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.178 SMLAD``() =
    let inputs =
      [ [ Gpr(0, 0xebb26d6bu)
          Gpr(1, 0x1eecdf9bu)
          Gpr(2, 0x707a2135u)
          Gpr(3, 0x5aa89feau)
          CPSR 0x20000010u ]
        [ Gpr(0, 0x9909d3a9u)
          Gpr(1, 0x8b415745u)
          Gpr(2, 0xa05294abu)
          Gpr(3, 0xd05d79bcu)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x7fff8000u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x640ae279u); CPSR 0x20000010u ]
        [ Gpr(0, 0xd768e3a5u); CPSR 0x900a0010u ]
        [ Gpr(0, 0x80007fffu); CPSR 0x48050010u ] ]
    check false "e7003211" inputs outputs

  /// <summary>
  /// A8.8.179 SMLAL: smlal r0, r1, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.179 SMLAL``() =
    let inputs =
      [ [ Gpr(0, 0xe4322896u); Gpr(1, 0x42dfea09u); Gpr(2, 0xa39680d3u) ]
        [ Gpr(0, 0x674d7b6au); Gpr(1, 0xe5542e81u); Gpr(2, 0x8f10c123u) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0xd40a8e01u); Gpr(1, 0x2abbe2deu) ]
        [ Gpr(0, 0x2fef180du); Gpr(1, 0xf118471eu) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u) ] ]
    check false "e0e10291" inputs outputs

  /// <summary>
  /// A8.8.180 SMLALBB: smlalbb r0, r1, r2, r3. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.180 SMLALBB``() =
    let inputs =
      [ [ Gpr(0, 0x237756d0u)
          Gpr(1, 0xe2041f82u)
          Gpr(2, 0xeb98a5b7u)
          Gpr(3, 0x07c714c4u) ]
        [ Gpr(0, 0x053ebd69u)
          Gpr(1, 0xf0defea6u)
          Gpr(2, 0x092d5367u)
          Gpr(3, 0x6ec996a6u) ]
        [ Gpr(0, 0x00000000u)
          Gpr(1, 0x80007fffu)
          Gpr(2, 0x00000003u)
          Gpr(3, 0xfffffffeu) ] ]
    let outputs =
      [ [ Gpr(0, 0x1c2482ecu); Gpr(1, 0xe2041f82u) ]
        [ Gpr(0, 0xe2ec2c33u); Gpr(1, 0xf0defea5u) ]
        [ Gpr(0, 0xfffffffau); Gpr(1, 0x80007ffeu) ] ]
    check false "e1410382" inputs outputs

  /// <summary>
  /// A8.8.180 SMLALBT: smlalbt r0, r1, r2, r3. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.180 SMLALBT``() =
    let inputs =
      [ [ Gpr(0, 0x32d5e91au)
          Gpr(1, 0x40a3741au)
          Gpr(2, 0x13ece276u)
          Gpr(3, 0x512b0238u) ]
        [ Gpr(0, 0x230233d0u)
          Gpr(1, 0x77c62879u)
          Gpr(2, 0x263256b7u)
          Gpr(3, 0x593e2acdu) ]
        [ Gpr(0, 0x00000000u)
          Gpr(1, 0x80007fffu)
          Gpr(2, 0x00000003u)
          Gpr(3, 0xfffffffeu) ] ]
    let outputs =
      [ [ Gpr(0, 0x297848ecu); Gpr(1, 0x40a3741au) ]
        [ Gpr(0, 0x413cd322u); Gpr(1, 0x77c62879u) ]
        [ Gpr(0, 0xfffffffdu); Gpr(1, 0x80007ffeu) ] ]
    check false "e14103c2" inputs outputs

  /// <summary>
  /// A8.8.180 SMLALTB: smlaltb r0, r1, r2, r3. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.180 SMLALTB``() =
    let inputs =
      [ [ Gpr(0, 0x7a45fae9u)
          Gpr(1, 0xe90b2a03u)
          Gpr(2, 0x82a317e7u)
          Gpr(3, 0x109a5539u) ]
        [ Gpr(0, 0x7e5f734eu)
          Gpr(1, 0xc1d7a288u)
          Gpr(2, 0x47e1c87bu)
          Gpr(3, 0x6db0b338u) ]
        [ Gpr(0, 0x00000000u)
          Gpr(1, 0x80007fffu)
          Gpr(2, 0x00000003u)
          Gpr(3, 0xfffffffeu) ] ]
    let outputs =
      [ [ Gpr(0, 0x508a3034u); Gpr(1, 0xe90b2a03u) ]
        [ Gpr(0, 0x68d07f86u); Gpr(1, 0xc1d7a288u) ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x80007fffu) ] ]
    check false "e14103a2" inputs outputs

  /// <summary>
  /// A8.8.180 SMLALTT: smlaltt r0, r1, r2, r3. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.180 SMLALTT``() =
    let inputs =
      [ [ Gpr(0, 0x57073d05u)
          Gpr(1, 0xf9862a25u)
          Gpr(2, 0x37d7852bu)
          Gpr(3, 0x3ec2d0e4u) ]
        [ Gpr(0, 0x69ad168bu)
          Gpr(1, 0xded2b966u)
          Gpr(2, 0x84c80323u)
          Gpr(3, 0x4a8f0854u) ]
        [ Gpr(0, 0x00000000u)
          Gpr(1, 0x80007fffu)
          Gpr(2, 0x00000003u)
          Gpr(3, 0xfffffffeu) ] ]
    let outputs =
      [ [ Gpr(0, 0x64b79ff3u); Gpr(1, 0xf9862a25u) ]
        [ Gpr(0, 0x45ca1243u); Gpr(1, 0xded2b966u) ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x80007fffu) ] ]
    check false "e14103e2" inputs outputs

  /// <summary>
  /// A8.8.181 SMLALD: smlald r0, r1, r1, r2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.181 SMLALD``() =
    let inputs =
      [ [ Gpr(0, 0x46c23d9fu); Gpr(1, 0x83a19dc8u); Gpr(2, 0x66b4a365u) ]
        [ Gpr(0, 0x752ec863u); Gpr(1, 0x48f6b25cu); Gpr(2, 0x8e914375u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x386488bbu); Gpr(1, 0x83a19dc8u) ]
        [ Gpr(0, 0x406527c5u); Gpr(1, 0x48f6b25cu) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u) ] ]
    check false "e7410211" inputs outputs

  /// <summary>
  /// A8.8.182 SMLAWB: smlawb r0, r1, r2, r3. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.182 SMLAWB``() =
    let inputs =
      [ [ Gpr(0, 0xef79185eu)
          Gpr(1, 0x86a6dd5au)
          Gpr(2, 0x174acf61u)
          Gpr(3, 0x5e22ba38u)
          CPSR 0x20000010u ]
        [ Gpr(0, 0x152e780au)
          Gpr(1, 0x3801570bu)
          Gpr(2, 0x201ba6d1u)
          Gpr(3, 0x527c1c48u)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Gpr(3, 0x00000003u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x752ecf13u); CPSR 0x20000010u ]
        [ Gpr(0, 0x3ef95cc6u); CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000003u); CPSR 0x48050010u ] ]
    check false "e1203281" inputs outputs

  /// <summary>
  /// A8.8.182 SMLAWT: smlawt r0, r1, r2, r3. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.182 SMLAWT``() =
    let inputs =
      [ [ Gpr(0, 0xfc02e268u)
          Gpr(1, 0xc2212160u)
          Gpr(2, 0xe437a02au)
          Gpr(3, 0xc13af77au)
          CPSR 0x20000010u ]
        [ Gpr(0, 0xae45a41au)
          Gpr(1, 0xdf96d7e3u)
          Gpr(2, 0xff6d0240u)
          Gpr(3, 0x8286e763u)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Gpr(3, 0x00000003u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xc7f20cf1u); CPSR 0x20000010u ]
        [ Gpr(0, 0x829983c5u); CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000003u); CPSR 0x48050010u ] ]
    check false "e12032c1" inputs outputs

  /// <summary>
  /// A8.8.183 SMLSD: smlsd r0, r1, r2, r3. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.183 SMLSD``() =
    let inputs =
      [ [ Gpr(0, 0x9126d238u)
          Gpr(1, 0x47a9e6b2u)
          Gpr(2, 0x6b15b150u)
          Gpr(3, 0xdfad2bcfu)
          CPSR 0x20000010u ]
        [ Gpr(0, 0x888fb61cu)
          Gpr(1, 0x7df39321u)
          Gpr(2, 0x91ec0156u)
          Gpr(3, 0x4eb7062cu)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x7fff8000u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xc97ad192u); CPSR 0x20000010u ]
        [ Gpr(0, 0x844dd53eu); CPSR 0x980a0010u ]
        [ Gpr(0, 0x80007fffu); CPSR 0x48050010u ] ]
    check false "e7003251" inputs outputs

  /// <summary>
  /// A8.8.184 SMLSLD: smlsld r0, r1, r1, r2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.184 SMLSLD``() =
    let inputs =
      [ [ Gpr(0, 0x392855b7u); Gpr(1, 0xa675ba2bu); Gpr(2, 0x4ca0f399u) ]
        [ Gpr(0, 0xab4aed93u); Gpr(1, 0x59c53329u); Gpr(2, 0x45e7e999u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x5757a54au); Gpr(1, 0xa675ba2bu) ]
        [ Gpr(0, 0x8e4db851u); Gpr(1, 0x59c53329u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u) ] ]
    check false "e7410251" inputs outputs

  /// <summary>
  /// A8.8.185 SMMLA: smmla r0, r1, r2, r3. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.185 SMMLA``() =
    let inputs =
      [ [ Gpr(0, 0x502ba0c2u)
          Gpr(1, 0xdb50fa01u)
          Gpr(2, 0x58735cb2u)
          Gpr(3, 0x805e3b32u) ]
        [ Gpr(0, 0x246b34bau)
          Gpr(1, 0xd9a6da60u)
          Gpr(2, 0x0bc49ac7u)
          Gpr(3, 0x382fc7beu) ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x7fff8000u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x73b1893au) ]
        [ Gpr(0, 0x366c7fafu) ]
        [ Gpr(0, 0x80007fffu) ] ]
    check false "e7503211" inputs outputs

  /// <summary>
  /// A8.8.186 SMMLS: smmls r0, r1, r2, r3. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.186 SMMLS``() =
    let inputs =
      [ [ Gpr(0, 0x3002ae5au)
          Gpr(1, 0x45897846u)
          Gpr(2, 0x80260911u)
          Gpr(3, 0xde17a13du) ]
        [ Gpr(0, 0x3926299bu)
          Gpr(1, 0xbe348583u)
          Gpr(2, 0x48dc8ebfu)
          Gpr(3, 0x00647f8eu) ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x7fff8000u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x00d20881u) ]
        [ Gpr(0, 0x131e698eu) ]
        [ Gpr(0, 0x80007fffu) ] ]
    check false "e75032d1" inputs outputs

  /// <summary>
  /// A8.8.187 SMMUL: smmul r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.187 SMMUL``() =
    let inputs =
      [ [ Gpr(0, 0x985d0884u); Gpr(1, 0x4004d9acu); Gpr(2, 0x4b0ae800u) ]
        [ Gpr(0, 0x9069b7d8u); Gpr(1, 0x62357becu); Gpr(2, 0x8f6afe46u) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x12c425fau) ]
        [ Gpr(0, 0xd4cf6ffeu) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e750f211" inputs outputs

  /// <summary>
  /// A8.8.188 SMUAD: smuad r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.188 SMUAD``() =
    let inputs =
      [ [ Gpr(0, 0xcf4d369au)
          Gpr(1, 0xd578ea79u)
          Gpr(2, 0x52160ae5u)
          CPSR 0x20000010u ]
        [ Gpr(0, 0xfcd85d11u)
          Gpr(1, 0x7af0e7b7u)
          Gpr(2, 0x5c512903u)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x7fff8000u)
          Gpr(2, 0x00000000u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xf172408du); CPSR 0x20000010u ]
        [ Gpr(0, 0x28712c15u); CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000000u); CPSR 0x48050010u ] ]
    check false "e700f211" inputs outputs

  /// <summary>
  /// A8.8.189 SMULBB: smulbb r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.189 SMULBB``() =
    let inputs =
      [ [ Gpr(0, 0x9020a6e0u); Gpr(1, 0x376039fcu); Gpr(2, 0xbbde03a3u) ]
        [ Gpr(0, 0xd6e1ab29u); Gpr(1, 0x33e2c228u); Gpr(2, 0x0ccac701u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x00d2df74u) ]
        [ Gpr(0, 0x0dc4da28u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e1600281" inputs outputs

  /// <summary>
  /// A8.8.189 SMULBT: smulbt r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.189 SMULBT``() =
    let inputs =
      [ [ Gpr(0, 0x75c719ccu); Gpr(1, 0xe8e15c7fu); Gpr(2, 0x890a1ba4u) ]
        [ Gpr(0, 0x359e9a3du); Gpr(1, 0x747cb694u); Gpr(2, 0x1d281a92u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0xd50493f6u) ]
        [ Gpr(0, 0xf7a34b20u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e16002c1" inputs outputs

  /// <summary>
  /// A8.8.189 SMULTB: smultb r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.189 SMULTB``() =
    let inputs =
      [ [ Gpr(0, 0x4cc64deeu); Gpr(1, 0x2ac62fcau); Gpr(2, 0x0f0155c7u) ]
        [ Gpr(0, 0xe126c41bu); Gpr(1, 0x68eb3a10u); Gpr(2, 0xc0c70632u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x0e54fdeau) ]
        [ Gpr(0, 0x0289ffe6u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e16002a1" inputs outputs

  /// <summary>
  /// A8.8.189 SMULTT: smultt r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.189 SMULTT``() =
    let inputs =
      [ [ Gpr(0, 0xf84cc9b5u); Gpr(1, 0x98cd2d66u); Gpr(2, 0xcb8d1c21u) ]
        [ Gpr(0, 0x574a0e03u); Gpr(1, 0x6f02130fu); Gpr(2, 0xbfb8f1a9u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x1524b7e9u) ]
        [ Gpr(0, 0xe4204770u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e16002e1" inputs outputs

  /// <summary>
  /// A8.8.190 SMULL: smull r0, r1, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.190 SMULL``() =
    let inputs =
      [ [ Gpr(0, 0x97785c93u); Gpr(1, 0x270df5cbu); Gpr(2, 0x1193ba79u) ]
        [ Gpr(0, 0xca8d68c1u); Gpr(1, 0x38e297d0u); Gpr(2, 0x7f437946u) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x38bfaaf3u); Gpr(1, 0x02ae76c9u) ]
        [ Gpr(0, 0x9326d2e0u); Gpr(1, 0x1c476790u) ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x00000000u) ] ]
    check false "e0c10291" inputs outputs

  /// <summary>
  /// A8.8.191 SMULWB: smulwb r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.191 SMULWB``() =
    let inputs =
      [ [ Gpr(0, 0x2a8b37abu); Gpr(1, 0x4784f655u); Gpr(2, 0x758f2c51u) ]
        [ Gpr(0, 0xff65d9a7u); Gpr(1, 0xee2073cfu); Gpr(2, 0xef899a57u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x0c617b68u) ]
        [ Gpr(0, 0x0718fee2u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e12002a1" inputs outputs

  /// <summary>
  /// A8.8.191 SMULWT: smulwt r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.191 SMULWT``() =
    let inputs =
      [ [ Gpr(0, 0x677d6fafu); Gpr(1, 0x91b30a20u); Gpr(2, 0x9db5c86bu) ]
        [ Gpr(0, 0x7bb0e4c1u); Gpr(1, 0x339dc936u); Gpr(2, 0x896c20d8u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x2a59c6abu) ]
        [ Gpr(0, 0xe8176e08u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e12002e1" inputs outputs

  /// <summary>
  /// A8.8.192 SMUSD: smusd r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.192 SMUSD``() =
    let inputs =
      [ [ Gpr(0, 0xce89da6bu); Gpr(1, 0x7a78e1dfu); Gpr(2, 0xd420d93eu) ]
        [ Gpr(0, 0x47538b08u); Gpr(1, 0xc09d9a49u); Gpr(2, 0x78bcb88eu) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x198d0c02u) ]
        [ Gpr(0, 0x3a480132u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e700f251" inputs outputs

  /// <summary>
  /// A8.8.193 SRS: srsia sp, #0x13. This checks, from IRQ mode with SP_svc
  /// pointing into memory, that it stores LR then SPSR on Supervisor mode's
  /// stack and leaves SP_svc, and that User, Hyp and System mode refuse it. It
  /// is not a value test because it needs a privileged mode, which a user-mode
  /// run does not have.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.193 SRS``() =
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
  /// A8.8.194 SSAT: ssat r0, #0x8, r1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.194 SSAT``() =
    let inputs =
      [ [ Gpr(0, 0x737cb173u); Gpr(1, 0xba8dbda8u); CPSR 0x20000010u ]
        [ Gpr(0, 0x233427beu); Gpr(1, 0x4e7dfa6cu); CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u); CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xffffff80u); CPSR 0x28000010u ]
        [ Gpr(0, 0x0000007fu); CPSR 0x980a0010u ]
        [ Gpr(0, 0x0000007fu); CPSR 0x48050010u ] ]
    check false "e6a70011" inputs outputs

  /// <summary>
  /// A8.8.195 SSAT16: ssat16 r0, #0x8, r1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.195 SSAT16``() =
    let inputs =
      [ [ Gpr(0, 0xfcd49780u); Gpr(1, 0x02632342u); CPSR 0x20000010u ]
        [ Gpr(0, 0x83f80af0u); Gpr(1, 0x6d4bcf68u); CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x007f007fu); CPSR 0x28000010u ]
        [ Gpr(0, 0x007fff80u); CPSR 0x980a0010u ]
        [ Gpr(0, 0x00000000u); CPSR 0x48050010u ] ]
    check false "e6a70f31" inputs outputs

  /// <summary>
  /// A8.8.196 SSAX: ssax r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.196 SSAX``() =
    let inputs =
      [ [ Gpr(0, 0xcd0cfc36u)
          Gpr(1, 0x28adae44u)
          Gpr(2, 0xae1fb76cu)
          CPSR 0x20000010u ]
        [ Gpr(0, 0xe45693f2u)
          Gpr(1, 0xa68784f5u)
          Gpr(2, 0xd8960805u)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x71415c63u); CPSR 0x200c0010u ]
        [ Gpr(0, 0x9e825d8bu); CPSR 0x90000010u ]
        [ Gpr(0, 0x8000ffffu); CPSR 0x480c0010u ] ]
    check false "e6110f52" inputs outputs

  /// <summary>
  /// A8.8.197 SSUB16: ssub16 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.197 SSUB16``() =
    let inputs =
      [ [ Gpr(0, 0x3605a797u)
          Gpr(1, 0xfe18c72eu)
          Gpr(2, 0x437a0074u)
          CPSR 0x20000010u ]
        [ Gpr(0, 0xa1fce275u)
          Gpr(1, 0x89842624u)
          Gpr(2, 0xea2034d7u)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xba9ec6bau); CPSR 0x20000010u ]
        [ Gpr(0, 0x9f64f14du); CPSR 0x90000010u ]
        [ Gpr(0, 0x80008001u); CPSR 0x480c0010u ] ]
    check false "e6110f72" inputs outputs

  /// <summary>
  /// A8.8.198 SSUB8: ssub8 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.198 SSUB8``() =
    let inputs =
      [ [ Gpr(0, 0x4d96c04au)
          Gpr(1, 0x254d2237u)
          Gpr(2, 0x9dd2e951u)
          CPSR 0x20000010u ]
        [ Gpr(0, 0x8d0559fau)
          Gpr(1, 0xd7acdda7u)
          Gpr(2, 0x03fc2b88u)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x7fff8000u)
          Gpr(2, 0x00000000u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x887b39e6u); CPSR 0x200e0010u ]
        [ Gpr(0, 0xd4b0b21fu); CPSR 0x90010010u ]
        [ Gpr(0, 0x7fff8000u); CPSR 0x48090010u ] ]
    check false "e6110ff2" inputs outputs

  /// <summary>
  /// A8.8.199 STC: stc 7, cr1, [r1, #8]. This checks that the lift says the
  /// instruction is unsupported: coprocessor 7 is none this front end models.
  /// It is not a value test because it reaches a coprocessor, which a user-mode
  /// run cannot.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.199 STC``() =
    let run = runWith false "ed811702" [ CPSR 0x13u ] []
    Assert.AreEqual(Some SideEffect.UnsupportedInstruction, run.Effect)

  /// <summary>
  /// A8.8.199 STC2: stc2 7, cr1, [r1, #8]. This checks that the lift says the
  /// instruction is unsupported: coprocessor 7 is none this front end models.
  /// It is not a value test because it reaches a coprocessor, which a user-mode
  /// run cannot.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.199 STC2``() =
    let run = runWith false "fd811702" [ CPSR 0x13u ] []
    Assert.AreEqual(Some SideEffect.UnsupportedInstruction, run.Effect)

  /// <summary>
  /// A8.8.200 STM: stm r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.200 STM``() =
    let inputs =
      [ [ Gpr(1, 0x20000818u)
          Gpr(2, 0x54d35318u)
          Gpr(3, 0xc5d88dc4u)
          M(0, 0xe0eac52665eb627dUL)
          M(8, 0x8e0cb381fbdebc1eUL)
          M(16, 0x5c251b935100c407UL)
          M(24, 0xb0fac97f24b14f8eUL)
          M(32, 0xa5d2db291c927115UL)
          M(40, 0xfcfb62a08d1fb51dUL)
          M(48, 0xd0ea678bce3bbcecUL)
          M(56, 0x0bbcd38d74b1d3fcUL) ]
        [ Gpr(1, 0x20000818u)
          Gpr(2, 0xe155b86fu)
          Gpr(3, 0x8cdaccc0u)
          M(0, 0xef4ec48a0f75a804UL)
          M(8, 0x3423e81072a7f607UL)
          M(16, 0x1b501efb5fed418aUL)
          M(24, 0xb86a0f24a827bfa6UL)
          M(32, 0xbe87527f8adf8825UL)
          M(40, 0x3fb8939f6236a1dfUL)
          M(48, 0xeb80d76534230fe1UL)
          M(56, 0x103c4005f83ba18cUL) ]
        [ Gpr(1, 0x20000818u)
          Gpr(2, 0x00008000u)
          Gpr(3, 0x7fff8000u)
          M(0, 0x789e9e4f7330fb04UL)
          M(8, 0x9a317e8afe0568fcUL)
          M(16, 0xf578c5c33237935aUL)
          M(24, 0x88fadf1161868303UL)
          M(32, 0x3721f6e1a5b525fcUL)
          M(40, 0x6a2650987a01155eUL)
          M(48, 0x3f485aa365d5a6feUL)
          M(56, 0x54880859a1bd5adeUL) ] ]
    let outputs =
      [ [ M(24, 0xc5d88dc454d35318UL) ]
        [ M(24, 0x8cdaccc0e155b86fUL) ]
        [ M(24, 0x7fff800000008000UL) ] ]
    check false "e881000c" inputs outputs

  /// <summary>
  /// A8.8.201 STMDA: stmda r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.201 STMDA``() =
    let inputs =
      [ [ Gpr(1, 0x2000081cu)
          Gpr(2, 0x390b745eu)
          Gpr(3, 0x4b6cb3cfu)
          M(0, 0x495152a12765be07UL)
          M(8, 0x2dfa37cdfa218b78UL)
          M(16, 0x4e9865a63bbe8507UL)
          M(24, 0x0d58a8142915c89bUL)
          M(32, 0x21c30d8334593979UL)
          M(40, 0x2a26a65c271e9eb7UL)
          M(48, 0xd23e8c51416e9633UL)
          M(56, 0x796b5a9fcd7fda2aUL) ]
        [ Gpr(1, 0x2000081cu)
          Gpr(2, 0x5b74c126u)
          Gpr(3, 0x67c4bdc4u)
          M(0, 0x386f88c1642d4293UL)
          M(8, 0x8c3d151ca7e2631aUL)
          M(16, 0x6f89a80316f3205eUL)
          M(24, 0xc4a537bd78ea6a23UL)
          M(32, 0x6e9445b1e56e0480UL)
          M(40, 0x3ce46b5b2d18b131UL)
          M(48, 0xad413fe4c9281da6UL)
          M(56, 0x5d941c11c16b964cUL) ]
        [ Gpr(1, 0x2000081cu)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0xcd414b85d7fe611eUL)
          M(8, 0x4928995332a1a3d7UL)
          M(16, 0x474178a7b8748d15UL)
          M(24, 0xca8b42212a4ca712UL)
          M(32, 0xaebdada55c158030UL)
          M(40, 0x664fdcdbce30c9e2UL)
          M(48, 0xb9855c69e42be12fUL)
          M(56, 0x43643d5cbbd7c8f8UL) ] ]
    let outputs =
      [ [ M(24, 0x4b6cb3cf390b745eUL) ]
        [ M(24, 0x67c4bdc45b74c126UL) ]
        [ M(24, 0x80007fff00000000UL) ] ]
    check false "e801000c" inputs outputs

  /// <summary>
  /// A8.8.202 STMDB: stmdb r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.202 STMDB``() =
    let inputs =
      [ [ Gpr(1, 0x20000820u)
          Gpr(2, 0x89467f26u)
          Gpr(3, 0xcb19a67bu)
          M(0, 0xae8e25a01519ed3eUL)
          M(8, 0x29286e1e81437e59UL)
          M(16, 0xba5d8741330b0711UL)
          M(24, 0x036d34bd2e436a70UL)
          M(32, 0x8edebc0aa8eafa7eUL)
          M(40, 0xd1536459ec39e541UL)
          M(48, 0xc43ddcf55edc3f47UL)
          M(56, 0x06009d2365902a0cUL) ]
        [ Gpr(1, 0x20000820u)
          Gpr(2, 0x8bdbf9ccu)
          Gpr(3, 0x6f82dd6au)
          M(0, 0x9da2b0f055dd0631UL)
          M(8, 0x2f266da05fc88563UL)
          M(16, 0xbfcbb0b0cab9bff6UL)
          M(24, 0xcedc4ebbfcab2de4UL)
          M(32, 0x82aa65d9c4183d67UL)
          M(40, 0xaae1d513a2a46d2cUL)
          M(48, 0x852aace2e6d9e5b8UL)
          M(56, 0xe2304e208644a565UL) ]
        [ Gpr(1, 0x20000820u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0x49b17ad0dd5e43acUL)
          M(8, 0x0da5055d2dcce084UL)
          M(16, 0x645a0ad4e08ca6d1UL)
          M(24, 0x434025f88cc61b24UL)
          M(32, 0xf4e3fd18a26d501dUL)
          M(40, 0xfe077fb67e9c9497UL)
          M(48, 0xf387808db38835e3UL)
          M(56, 0xe4c291d9bdecd77fUL) ] ]
    let outputs =
      [ [ M(24, 0xcb19a67b89467f26UL) ]
        [ M(24, 0x6f82dd6a8bdbf9ccUL) ]
        [ M(24, 0x80007fff00000000UL) ] ]
    check false "e901000c" inputs outputs

  /// <summary>
  /// A8.8.203 STMIB: stmib r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.203 STMIB``() =
    let inputs =
      [ [ Gpr(1, 0x20000814u)
          Gpr(2, 0x5572a46cu)
          Gpr(3, 0xf532e49fu)
          M(0, 0x1906a1d5044f85dfUL)
          M(8, 0xf4f1b603e4aa2563UL)
          M(16, 0x6c60a7830edecad3UL)
          M(24, 0xa4bc52f03062d836UL)
          M(32, 0xefa4f2312d228169UL)
          M(40, 0x8a238d4a7f7bc1fdUL)
          M(48, 0x2cac180bab4e64b1UL)
          M(56, 0x90d43a7db8ac8ef8UL) ]
        [ Gpr(1, 0x20000814u)
          Gpr(2, 0x9c8b5a1cu)
          Gpr(3, 0x47e80981u)
          M(0, 0xb7ac97daca95454eUL)
          M(8, 0xfe576c566dbd496aUL)
          M(16, 0x722671d72bde66fbUL)
          M(24, 0xeb6564684683afddUL)
          M(32, 0x1961af94da51ff6eUL)
          M(40, 0xf8dfd11eefba9590UL)
          M(48, 0xd847aff29dd51bb4UL)
          M(56, 0xc32031f2ec81de92UL) ]
        [ Gpr(1, 0x20000814u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0x3ce72a121f5e3669UL)
          M(8, 0x3a8b96344d7bb8e4UL)
          M(16, 0xe49efacbe9a168daUL)
          M(24, 0x354d4f37d3725a26UL)
          M(32, 0x1856c4ef774a945aUL)
          M(40, 0xf3a548268dde11d0UL)
          M(48, 0x4b43fd068610aff9UL)
          M(56, 0xe3343ae4ee85438bUL) ] ]
    let outputs =
      [ [ M(24, 0xf532e49f5572a46cUL) ]
        [ M(24, 0x47e809819c8b5a1cUL) ]
        [ M(24, 0x80007fff00000000UL) ] ]
    check false "e981000c" inputs outputs

  /// <summary>
  /// A8.8.204 STR: str r0, [r1]. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.204 STR``() =
    let inputs =
      [ [ Gpr(0, 0xa5a39373u)
          Gpr(1, 0x20000810u)
          M(0, 0x596b3fdf6fac6b4dUL)
          M(8, 0x3232352e1e649024UL)
          M(16, 0x4903074abaaa8070UL)
          M(24, 0x396cb3c0d285dcfdUL)
          M(32, 0x0408f4be184db736UL)
          M(40, 0x73e1e37b19b6429eUL)
          M(48, 0x5d8d0fc56c0d4eabUL)
          M(56, 0x0245ab00118d812eUL) ]
        [ Gpr(0, 0x693c3bc3u)
          Gpr(1, 0x20000810u)
          M(0, 0xbb48230a620415aaUL)
          M(8, 0x1c74a683c95cccb0UL)
          M(16, 0x68f58ba8fbbdb2b2UL)
          M(24, 0xd444df27b03c94cdUL)
          M(32, 0xfd38843581b0e36bUL)
          M(40, 0xd7f33713ebb73184UL)
          M(48, 0xbcc11aebd1c4ce9cUL)
          M(56, 0xe2720eb384986a07UL) ]
        [ Gpr(0, 0x00000001u)
          Gpr(1, 0x20000810u)
          M(0, 0x09b49c52c4e649d8UL)
          M(8, 0x34fd4d07d1e6675aUL)
          M(16, 0x6f8b3e0f8043321aUL)
          M(24, 0x7ca675d4618bc5b9UL)
          M(32, 0x2eee9405bc8ad949UL)
          M(40, 0x26c7d9a6fbd20d46UL)
          M(48, 0xa027f3431bf9b8bdUL)
          M(56, 0x7a2d9e4e4382628fUL) ] ]
    let outputs =
      [ [ M(16, 0x4903074aa5a39373UL) ]
        [ M(16, 0x68f58ba8693c3bc3UL) ]
        [ M(16, 0x6f8b3e0f00000001UL) ] ]
    check false "e5810000" inputs outputs

  /// <summary>
  /// A8.8.207 STRB: strb r0, [r1]. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.207 STRB``() =
    let inputs =
      [ [ Gpr(0, 0x2905ba39u)
          Gpr(1, 0x20000810u)
          M(0, 0x3327c003e4626732UL)
          M(8, 0xc3b4ff84c957e374UL)
          M(16, 0x4a5662615458d9f6UL)
          M(24, 0xf2d269e95190ed5dUL)
          M(32, 0xbf9d4310a592ea7cUL)
          M(40, 0x0cbd3213f1c18f7cUL)
          M(48, 0x1f5b1c1fa8d2816aUL)
          M(56, 0x0104088472587c7eUL) ]
        [ Gpr(0, 0xfd7cda94u)
          Gpr(1, 0x20000810u)
          M(0, 0x49b8c53f0cb29e0bUL)
          M(8, 0x7b0ee1b4f99cd667UL)
          M(16, 0xea85a2022fb822b1UL)
          M(24, 0x6787f5e6070424a8UL)
          M(32, 0x9043df65823c0665UL)
          M(40, 0x0586d6790adcf704UL)
          M(48, 0x31c5df381e3f49a1UL)
          M(56, 0xc17616edefc2eaebUL) ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x20000810u)
          M(0, 0x9071293676c7767bUL)
          M(8, 0xe658a24ba02cab3aUL)
          M(16, 0x7ce76c5663557f2aUL)
          M(24, 0xa56e4c3f01e6f59eUL)
          M(32, 0x97a0c2ded840dcc0UL)
          M(40, 0xc5ee2375130bfdcbUL)
          M(48, 0x5190fc2113eefaafUL)
          M(56, 0x0901da1adf33f837UL) ] ]
    let outputs =
      [ [ M(16, 0x4a5662615458d939UL) ]
        [ M(16, 0xea85a2022fb82294UL) ]
        [ M(16, 0x7ce76c5663557fffUL) ] ]
    check false "e5c10000" inputs outputs

  /// <summary>
  /// A8.8.210 STRBT: strbt r0, [r1], #0x0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.210 STRBT``() =
    let inputs =
      [ [ Gpr(0, 0xc7bc4775u)
          Gpr(1, 0x20000810u)
          M(0, 0xaa9c7d4f5ea1b0ffUL)
          M(8, 0xf2334cf6c549ffadUL)
          M(16, 0xd93465b1abb2a7d5UL)
          M(24, 0xfb50a9e2e2b1c24fUL)
          M(32, 0x002d4b324a840b8cUL)
          M(40, 0x633e108fcf215f47UL)
          M(48, 0x27df4dedaeffce6aUL)
          M(56, 0x0127a069462df4e0UL) ]
        [ Gpr(0, 0xb8b3c37bu)
          Gpr(1, 0x20000810u)
          M(0, 0xa6921f738b9ed8a7UL)
          M(8, 0xb2a5428737016ca5UL)
          M(16, 0x4d433a5ec6e4ccd5UL)
          M(24, 0xe1294d2c235a250dUL)
          M(32, 0xa8189bd91e1a121aUL)
          M(40, 0xd9e2764c9339d837UL)
          M(48, 0x68fad320e9212c54UL)
          M(56, 0x9572af45933f3c87UL) ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x20000810u)
          M(0, 0x23ff3fcffc93cbe9UL)
          M(8, 0x353b838ae79d198eUL)
          M(16, 0xf0db7e41a061913cUL)
          M(24, 0x9524d33d8db86c13UL)
          M(32, 0xe635650e9bc18375UL)
          M(40, 0xfa329c999a37ef2dUL)
          M(48, 0x61d13fa570b1ef7fUL)
          M(56, 0xc3f21390aeb44669UL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000810u); M(16, 0xd93465b1abb2a775UL) ]
        [ Gpr(1, 0x20000810u); M(16, 0x4d433a5ec6e4cc7bUL) ]
        [ Gpr(1, 0x20000810u); M(16, 0xf0db7e41a0619100UL) ] ]
    check false "e4e10000" inputs outputs

  /// <summary>
  /// A8.8.211 STRD: strd r2, [r1, #8]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.211 STRD``() =
    let inputs =
      [ [ Gpr(1, 0x20000808u)
          Gpr(2, 0xc870fe96u)
          Gpr(3, 0x7a5a74b6u)
          M(0, 0x52364cf42eb668abUL)
          M(8, 0x56dd44db7d8c8cc3UL)
          M(16, 0x720c4925505e5977UL)
          M(24, 0x1fd681733efb5663UL)
          M(32, 0xf8f00931fe7054f4UL)
          M(40, 0x9ccbefe23e78a353UL)
          M(48, 0x5058294359ef2ab4UL)
          M(56, 0x974832f1681fe69fUL) ]
        [ Gpr(1, 0x20000808u)
          Gpr(2, 0x7ebc889bu)
          Gpr(3, 0xcf6119b8u)
          M(0, 0x24cccfbc71874e6cUL)
          M(8, 0x327e08d1d81a4c0aUL)
          M(16, 0xe025256b99801bd3UL)
          M(24, 0xbcbc76cf0422c04cUL)
          M(32, 0x1af538e3de1234fbUL)
          M(40, 0x9c0935a69bbe69e7UL)
          M(48, 0xd5d41fa8f51916aaUL)
          M(56, 0xbb43f6c842dea9bbUL) ]
        [ Gpr(1, 0x20000808u)
          Gpr(2, 0x7fff8000u)
          Gpr(3, 0x00000000u)
          M(0, 0xe1de7b5403cbde0bUL)
          M(8, 0x0898a1e3d9b3c3e3UL)
          M(16, 0xf45938a950fa74f1UL)
          M(24, 0xf3434f5f31d8386dUL)
          M(32, 0x97e395b69e395abfUL)
          M(40, 0x76997aea24e33d4eUL)
          M(48, 0x0783a1d9e49e7366UL)
          M(56, 0xb7909cc0e908af6fUL) ] ]
    let outputs =
      [ [ M(16, 0x7a5a74b6c870fe96UL) ]
        [ M(16, 0xcf6119b87ebc889bUL) ]
        [ M(16, 0x000000007fff8000UL) ] ]
    check false "e1c120f8" inputs outputs

  /// <summary>
  /// A8.8.213 STREX: strex r0, r2, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.213 STREX``() =
    let inputs =
      [ [ Gpr(0, 0x7474c3f4u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x8bd01c1bu)
          M(0, 0x93b2bf27fa513e78UL)
          M(8, 0xfcbdf736ebb61dbbUL)
          M(16, 0xc596abfad9608d45UL)
          M(24, 0x6cb4e8317bd3bd16UL)
          M(32, 0x02ef899a70057a7eUL)
          M(40, 0xdba6611c690713c8UL)
          M(48, 0xfc6749f9449402e8UL)
          M(56, 0xb4093a3f3165faddUL) ]
        [ Gpr(0, 0x5220b0edu)
          Gpr(1, 0x20000810u)
          Gpr(2, 0xfc73400fu)
          M(0, 0x6da4458adfeb75c7UL)
          M(8, 0xbd6e069a3f871412UL)
          M(16, 0x0acd2aa75b3fa3b0UL)
          M(24, 0x84d8ac95e2e47becUL)
          M(32, 0xaa180cac70d5de78UL)
          M(40, 0x261eecfc3e65dec7UL)
          M(48, 0xfaa71c0dc0928e67UL)
          M(56, 0x46c0c422dbbfc474UL) ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x00000000u)
          M(0, 0x490f9590cc09b2daUL)
          M(8, 0x275f6a166315b2f7UL)
          M(16, 0x5ceac70580dc43a3UL)
          M(24, 0xb06bdba3a0b03a9dUL)
          M(32, 0xa43c4ee423070e2dUL)
          M(40, 0xba50d51541b45db0UL)
          M(48, 0x54eac34c4f950d44UL)
          M(56, 0x5f1edb9f2d24e053UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ] ]
    check false "e1810f92" inputs outputs

  /// <summary>
  /// A8.8.214 STREXB: strexb r0, r2, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.214 STREXB``() =
    let inputs =
      [ [ Gpr(0, 0x20c6e37fu)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x58eda946u)
          M(0, 0x6c800c4442ce59c9UL)
          M(8, 0xdeda1fcb5b28a339UL)
          M(16, 0xa256b110bf01391cUL)
          M(24, 0x5d4c3d697d462818UL)
          M(32, 0x610ce6f0f9f1a471UL)
          M(40, 0x470ca9f25b578facUL)
          M(48, 0x141b6be6317acd0dUL)
          M(56, 0x8187283acf4750aeUL) ]
        [ Gpr(0, 0x83d35f9bu)
          Gpr(1, 0x20000810u)
          Gpr(2, 0xb3e81174u)
          M(0, 0xca13cc955a555de2UL)
          M(8, 0x4ffb68810d8a02d2UL)
          M(16, 0x40c93de1c506561dUL)
          M(24, 0xdb2184a10f72822eUL)
          M(32, 0x43c942abbc9e7191UL)
          M(40, 0x303784907f3be8b9UL)
          M(48, 0x795f69e3b7bf8d43UL)
          M(56, 0x46663dcbc2d0003fUL) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x80007fffu)
          M(0, 0x89e98c40be0f24c1UL)
          M(8, 0x0765dd78135fb7fcUL)
          M(16, 0x86c7030bc7538399UL)
          M(24, 0xce072ccba10d6f92UL)
          M(32, 0x391127f5e707d175UL)
          M(40, 0x077311b7a12ccf3fUL)
          M(48, 0xc8fefc9dac4b4215UL)
          M(56, 0x1c05352b1e95778eUL) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ] ]
    check false "e1c10f92" inputs outputs

  /// <summary>
  /// A8.8.215 STREXD: strexd r0, r2, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.215 STREXD``() =
    let inputs =
      [ [ Gpr(0, 0x31785c3fu)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x4f63f99bu)
          Gpr(3, 0x7267883cu)
          M(0, 0xda51882b0fecae33UL)
          M(8, 0x12792f061b009b76UL)
          M(16, 0x8934ca36aa0cf1d8UL)
          M(24, 0xef169991c896376cUL)
          M(32, 0xc6ca4bfaae79f744UL)
          M(40, 0xcd56b4612bb879a7UL)
          M(48, 0x6976c50f8649ff7fUL)
          M(56, 0x3acd3b75d89d82e4UL) ]
        [ Gpr(0, 0xc74b91ffu)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x42027c81u)
          Gpr(3, 0xd78752c4u)
          M(0, 0x47664dbb1982fd4cUL)
          M(8, 0xdf5ee4744a6f2fb6UL)
          M(16, 0x7088202de4c21e1aUL)
          M(24, 0xfd98a1a82b0ba89dUL)
          M(32, 0xf91c4f229efb02b6UL)
          M(40, 0x717b1ec75d53e43bUL)
          M(48, 0x803917b99c5f48afUL)
          M(56, 0xe2b8a9e623102a9bUL) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x80007fffu)
          Gpr(3, 0x00000003u)
          M(0, 0x019c1f6087441951UL)
          M(8, 0xd91325d86c174030UL)
          M(16, 0x03f4b9d3e4afd593UL)
          M(24, 0x887a4da7a1032bfbUL)
          M(32, 0xcd92397f6fd048d4UL)
          M(40, 0x28f519ebf222751cUL)
          M(48, 0x95d083b4b353ee6eUL)
          M(56, 0x914e2ca8655faa17UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ] ]
    check false "e1a10f92" inputs outputs

  /// <summary>
  /// A8.8.216 STREXH: strexh r0, r2, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.216 STREXH``() =
    let inputs =
      [ [ Gpr(0, 0xbc42704cu)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x92b2a905u)
          M(0, 0x55e0248400b71411UL)
          M(8, 0xbec365b3e0091887UL)
          M(16, 0xcf7e66db8e542701UL)
          M(24, 0xbb59ac93ee67424bUL)
          M(32, 0x4285b72b4ce8ad9fUL)
          M(40, 0xf2d5b8c363110c3bUL)
          M(48, 0x7468b0925266ec4dUL)
          M(56, 0xdc57d281a59b83d5UL) ]
        [ Gpr(0, 0xe8b60f12u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x923378bau)
          M(0, 0x495d3a05b613b00dUL)
          M(8, 0x1829600eac9fc905UL)
          M(16, 0x51ba8d1ee9b27f63UL)
          M(24, 0x373542fc279aae3dUL)
          M(32, 0xe510ec83bb34e823UL)
          M(40, 0x80d11cb8afef0015UL)
          M(48, 0x2d0cbadc5686ca41UL)
          M(56, 0xeedf419cb9169c77UL) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x80007fffu)
          M(0, 0xef7f19a846a29c32UL)
          M(8, 0x1af89f4c2d0fcb7fUL)
          M(16, 0x3ca35c3ad57c6fe7UL)
          M(24, 0xc2a828892e992d18UL)
          M(32, 0x66f9fde1a52ce3a5UL)
          M(40, 0x706286ac3d7f5c31UL)
          M(48, 0x499c5c305e171390UL)
          M(56, 0x5cfd516e45911719UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ] ]
    check false "e1e10f92" inputs outputs

  /// <summary>
  /// A8.8.217 STRH: strh r0, [r1]. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.217 STRH``() =
    let inputs =
      [ [ Gpr(0, 0x8703e21au)
          Gpr(1, 0x20000810u)
          M(0, 0xbcb68aca41cd6e8aUL)
          M(8, 0x1ce0df4ebc1d2894UL)
          M(16, 0xb8e0076a016723a8UL)
          M(24, 0x379dd998a8b055c4UL)
          M(32, 0x0cc7ed822b791282UL)
          M(40, 0xb9982b513eb18d19UL)
          M(48, 0xd3d8953c24b5a005UL)
          M(56, 0x4aa65177c33238c7UL) ]
        [ Gpr(0, 0x52534fe4u)
          Gpr(1, 0x20000810u)
          M(0, 0x07fe643cb723c38aUL)
          M(8, 0x2d97dab3899424a5UL)
          M(16, 0xbfd5434febe0784bUL)
          M(24, 0x5af6d9c143def620UL)
          M(32, 0xcb4a28cb4031359bUL)
          M(40, 0x935755aa7caea7ccUL)
          M(48, 0x628c1d83458a1e87UL)
          M(56, 0x08221937c78f523eUL) ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x20000810u)
          M(0, 0x4be63d3442ef5305UL)
          M(8, 0x0d1ee70e1430c87cUL)
          M(16, 0x71aafb5d3a03c455UL)
          M(24, 0xf988804f455192d1UL)
          M(32, 0x244341bce9199b09UL)
          M(40, 0x5ae6284c15326ec4UL)
          M(48, 0xd3a06dbff4cddb16UL)
          M(56, 0xa38de1d0d8abc023UL) ] ]
    let outputs =
      [ [ M(16, 0xb8e0076a0167e21aUL) ]
        [ M(16, 0xbfd5434febe04fe4UL) ]
        [ M(16, 0x71aafb5d3a03ffffUL) ] ]
    check false "e1c100b0" inputs outputs

  /// <summary>
  /// A8.8.220 STRHT: strht r0, [r1], #0x0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.220 STRHT``() =
    let inputs =
      [ [ Gpr(0, 0x9463c311u)
          Gpr(1, 0x20000810u)
          M(0, 0xa5bb907747280ee9UL)
          M(8, 0x1ee6ebaaa9ff0eeaUL)
          M(16, 0xc7279c5c3c39070dUL)
          M(24, 0x428b9eec92c136d5UL)
          M(32, 0xf56277411494942eUL)
          M(40, 0x151e407a4991ad84UL)
          M(48, 0x401886686f54af01UL)
          M(56, 0x7d3499c394c5cfafUL) ]
        [ Gpr(0, 0x4e9e5105u)
          Gpr(1, 0x20000810u)
          M(0, 0x42e73779373142daUL)
          M(8, 0x16ade9b22ed300e6UL)
          M(16, 0x482ea4da10c6f007UL)
          M(24, 0x2aec4e00daab4351UL)
          M(32, 0x1e6b48cf4f80b2d9UL)
          M(40, 0x23fd8e5512f89d56UL)
          M(48, 0x12b0f1c3f42ce96dUL)
          M(56, 0x32a91d7cf0047852UL) ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x20000810u)
          M(0, 0xc78a04f22a082e2dUL)
          M(8, 0x085345ea0726b6a5UL)
          M(16, 0x6bb22cc0543fdc84UL)
          M(24, 0x36ae58625a460a76UL)
          M(32, 0xbc4e3b2efdf07dd2UL)
          M(40, 0x37e05ff83b3de911UL)
          M(48, 0x9ff53706edf04071UL)
          M(56, 0x6c828b64cf5ee5f6UL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000810u); M(16, 0xc7279c5c3c39c311UL) ]
        [ Gpr(1, 0x20000810u); M(16, 0x482ea4da10c65105UL) ]
        [ Gpr(1, 0x20000810u); M(16, 0x6bb22cc0543f8000UL) ] ]
    check false "e0e100b0" inputs outputs

  /// <summary>
  /// A8.8.221 STRT: strt r0, [r1], #0x0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.221 STRT``() =
    let inputs =
      [ [ Gpr(0, 0xcf4d1abcu)
          Gpr(1, 0x20000810u)
          M(0, 0xadb8ead0ea0113cfUL)
          M(8, 0x3049a18e6f6eb763UL)
          M(16, 0x5592b7e14a7c94b2UL)
          M(24, 0xa0cf2887478e9a03UL)
          M(32, 0x813ce67cf043898fUL)
          M(40, 0xdf3ec0952e5575aaUL)
          M(48, 0x2bbfe04e7c4b8b17UL)
          M(56, 0xe01466782dbf3d6cUL) ]
        [ Gpr(0, 0x94d4b92eu)
          Gpr(1, 0x20000810u)
          M(0, 0x9dc64013a602bf5fUL)
          M(8, 0x039e5d610e7cde7fUL)
          M(16, 0xe320da4bc57ef02dUL)
          M(24, 0xac09afa3ebf621b9UL)
          M(32, 0x0f7f0e86123d2b80UL)
          M(40, 0xe2604d1707484952UL)
          M(48, 0x21a52fe78b846222UL)
          M(56, 0x917fb018c1b45164UL) ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x20000810u)
          M(0, 0x611fca9db8dc67a7UL)
          M(8, 0xc3fe370d077ea48aUL)
          M(16, 0x476ff4799bbc3547UL)
          M(24, 0xa6ca4544de092bc1UL)
          M(32, 0xd4499e3912eee099UL)
          M(40, 0x171666b12c697bafUL)
          M(48, 0xdb9c4a141f0dca74UL)
          M(56, 0x553c9dca4deebf8eUL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000810u); M(16, 0x5592b7e1cf4d1abcUL) ]
        [ Gpr(1, 0x20000810u); M(16, 0xe320da4b94d4b92eUL) ]
        [ Gpr(1, 0x20000810u); M(16, 0x476ff4790000ffffUL) ] ]
    check false "e4a10000" inputs outputs

  /// <summary>
  /// A8.8.222 SUB: sub r0, r1, r2. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.222 SUB``() =
    let inputs =
      [ [ Gpr(0, 0xf2ff0243u); Gpr(1, 0xfc45a56fu); Gpr(2, 0x9e56b737u) ]
        [ Gpr(0, 0x63f0e3deu); Gpr(1, 0x323e4537u); Gpr(2, 0xbc767841u) ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu); Gpr(2, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x5deeee38u) ]
        [ Gpr(0, 0x75c7ccf6u) ]
        [ Gpr(0, 0x00007fffu) ] ]
    check false "e0410002" inputs outputs

  /// <summary>
  /// A8.8.228 SUBS: subs r0, r1, #0x3f0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.228 SUBS``() =
    let inputs =
      [ [ Gpr(0, 0x69e9fe84u); Gpr(1, 0xa37d472du); CPSR 0x20000010u ]
        [ Gpr(0, 0xee7f0296u); Gpr(1, 0xe4afc26eu); CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u); CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xa37d433du); CPSR 0xa0000010u ]
        [ Gpr(0, 0xe4afbe7eu); CPSR 0xa00a0010u ]
        [ Gpr(0, 0x00007c10u); CPSR 0x28050010u ] ]
    check false "e2510e3f" inputs outputs

  /// <summary>
  /// A8.8.229 SVC: svc #0x12004. This checks that it calls the supervisor with
  /// its immediate. It is not a value test because it takes an exception, which
  /// a user-mode run cannot return from.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.229 SVC``() =
    let run = runWith false "ef012004" [ CPSR 0x10u ] []
    Assert.AreEqual(Some(SideEffect.Interrupt 0x12004), run.Effect)

  /// <summary>
  /// A8.8.230 SWP: swp r0, r1, [r2]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.230 SWP``() =
    let inputs =
      [ [ Gpr(0, 0x02e6b309u)
          Gpr(1, 0x09b8ec33u)
          Gpr(2, 0x20000810u)
          M(0, 0xb2303c58084f8573UL)
          M(8, 0x85e2748352dd8ce5UL)
          M(16, 0x3860d2f5aca3ca63UL)
          M(24, 0xe03bfc4e57a7a898UL)
          M(32, 0xde0c578d9d5a20dfUL)
          M(40, 0x35ebed9e835feb49UL)
          M(48, 0x6d36782a15c2dab4UL)
          M(56, 0x94c406456bb2fa64UL) ]
        [ Gpr(0, 0x5a143f54u)
          Gpr(1, 0x245b7007u)
          Gpr(2, 0x20000810u)
          M(0, 0xcfc8291efe384860UL)
          M(8, 0x9c3fad25aab52049UL)
          M(16, 0xd0ec9bbcdd226365UL)
          M(24, 0xad9056661a19d1f2UL)
          M(32, 0xbd920abd369dc6e4UL)
          M(40, 0x94c0d4169d8cf640UL)
          M(48, 0xda690b68769de80fUL)
          M(56, 0x37ea93bd5950c7efUL) ]
        [ Gpr(0, 0x00000001u)
          Gpr(1, 0x0000ffffu)
          Gpr(2, 0x20000810u)
          M(0, 0x76feef21be05f9b8UL)
          M(8, 0xd1e410845e18f9dcUL)
          M(16, 0xe4de3c399466d533UL)
          M(24, 0x20d7f5e90ff375ebUL)
          M(32, 0x140a959b2551a3cdUL)
          M(40, 0xa49ad91cd1e23f75UL)
          M(48, 0x7a67979d79fd106eUL)
          M(56, 0xad5a16505a10f75dUL) ] ]
    let outputs =
      [ [ Gpr(0, 0xaca3ca63u); M(16, 0x3860d2f509b8ec33UL) ]
        [ Gpr(0, 0xdd226365u); M(16, 0xd0ec9bbc245b7007UL) ]
        [ Gpr(0, 0x9466d533u); M(16, 0xe4de3c390000ffffUL) ] ]
    check false "e1020091" inputs outputs

  /// <summary>
  /// A8.8.230 SWPB: swpb r0, r1, [r2]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.230 SWPB``() =
    let inputs =
      [ [ Gpr(0, 0x63a86bf4u)
          Gpr(1, 0xe545e4e5u)
          Gpr(2, 0x20000810u)
          M(0, 0xfa217c750309031bUL)
          M(8, 0x26484fed15a3c03fUL)
          M(16, 0xa444812a9dff56aaUL)
          M(24, 0x2028bc53ca8961f2UL)
          M(32, 0xdeb21255aef2c408UL)
          M(40, 0xd3187f8e16222c53UL)
          M(48, 0x550aca19b8e9c5c0UL)
          M(56, 0x77b5e2ea19095d25UL) ]
        [ Gpr(0, 0x63b61ce4u)
          Gpr(1, 0x78df086eu)
          Gpr(2, 0x20000810u)
          M(0, 0x76e1e4a573521895UL)
          M(8, 0x7c8c2fdcd327a127UL)
          M(16, 0x6d9424cd86942455UL)
          M(24, 0xd123248f9abd78bfUL)
          M(32, 0x02a3e776240d484eUL)
          M(40, 0xed94ad677dc923cbUL)
          M(48, 0x122cf149d4e3a889UL)
          M(56, 0x4b14e7b39fa3e1fdUL) ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x20000810u)
          M(0, 0xebc0f46d2223605cUL)
          M(8, 0x940cef9b5673bd2bUL)
          M(16, 0x4c65afc71ffdd90aUL)
          M(24, 0x164a8a587396fa89UL)
          M(32, 0x06ee63852e9041f6UL)
          M(40, 0x61b5d21f46656bbeUL)
          M(48, 0xd0785727234b364cUL)
          M(56, 0xdaabcf320eb8f337UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x000000aau); M(16, 0xa444812a9dff56e5UL) ]
        [ Gpr(0, 0x00000055u); M(16, 0x6d9424cd8694246eUL) ]
        [ Gpr(0, 0x0000000au); M(16, 0x4c65afc71ffdd900UL) ] ]
    check false "e1420091" inputs outputs

  /// <summary>
  /// A8.8.231 SXTAB: sxtab r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.231 SXTAB``() =
    let inputs =
      [ [ Gpr(0, 0x3cd0e642u); Gpr(1, 0x51573fd1u); Gpr(2, 0x945c229cu) ]
        [ Gpr(0, 0x88aa534du); Gpr(1, 0xc8cc1122u); Gpr(2, 0xbb39a395u) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x51573f6du) ]
        [ Gpr(0, 0xc8cc10b7u) ]
        [ Gpr(0, 0x7fff8000u) ] ]
    check false "e6a10072" inputs outputs

  /// <summary>
  /// A8.8.232 SXTAB16: sxtab16 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.232 SXTAB16``() =
    let inputs =
      [ [ Gpr(0, 0x226310fbu); Gpr(1, 0x2e3284b0u); Gpr(2, 0xfcd71e2fu) ]
        [ Gpr(0, 0x4f4b89a4u); Gpr(1, 0x22e1c60eu); Gpr(2, 0x66066e24u) ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x80007fffu); Gpr(2, 0x00000003u) ] ]
    let outputs =
      [ [ Gpr(0, 0x2e0984dfu) ]
        [ Gpr(0, 0x22e7c632u) ]
        [ Gpr(0, 0x80008002u) ] ]
    check false "e6810072" inputs outputs

  /// <summary>
  /// A8.8.233 SXTAH: sxtah r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.233 SXTAH``() =
    let inputs =
      [ [ Gpr(0, 0x883f85a0u); Gpr(1, 0xdc70d6aau); Gpr(2, 0xfbf4bebeu) ]
        [ Gpr(0, 0xf0ddfd6cu); Gpr(1, 0xc21d8e79u); Gpr(2, 0x26c8c4d0u) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0xdc709568u) ]
        [ Gpr(0, 0xc21d5349u) ]
        [ Gpr(0, 0x7fff8000u) ] ]
    check false "e6b10072" inputs outputs

  /// <summary>
  /// A8.8.234 SXTB: sxtb r0, r1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.234 SXTB``() =
    let inputs =
      [ [ Gpr(0, 0x59c35db0u); Gpr(1, 0xd3fa08cdu) ]
        [ Gpr(0, 0xcc25ec2du); Gpr(1, 0x1323282au) ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0xffffffcdu) ]
        [ Gpr(0, 0x0000002au) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e6af0071" inputs outputs

  /// <summary>
  /// A8.8.235 SXTB16: sxtb16 r0, r1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.235 SXTB16``() =
    let inputs =
      [ [ Gpr(0, 0xc297f29au); Gpr(1, 0xcbaa2d71u) ]
        [ Gpr(0, 0x028ac0ccu); Gpr(1, 0xa4c096f8u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0xffaa0071u) ]
        [ Gpr(0, 0xffc0fff8u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e68f0071" inputs outputs

  /// <summary>
  /// A8.8.236 SXTH: sxth r0, r1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.236 SXTH``() =
    let inputs =
      [ [ Gpr(0, 0x1983dae6u); Gpr(1, 0x482904f1u) ]
        [ Gpr(0, 0x5f29e24eu); Gpr(1, 0x8ad378e4u) ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x000004f1u) ]
        [ Gpr(0, 0x000078e4u) ]
        [ Gpr(0, 0xffff8000u) ] ]
    check false "e6bf0071" inputs outputs

  /// <summary>
  /// A8.8.237 TBB: tbb [r1, r2]. This checks that it goes to PC plus twice the
  /// byte at Rn + Rm, here 0x10. It is not a value test because it branches,
  /// and a run inside one instruction cannot follow it to what QEMU would show.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.237 TBB``() =
    let w = uint32 Window
    let cells = [ Gpr(1, w + 8u); Gpr(2, 3u); M(8, 0x10000000UL) ]
    let run = runWith true "e8d1f002" cells []
    Assert.AreEqual(Some(CodeAddr + 0x24UL), run.Target)

  /// <summary>
  /// A8.8.237 TBH: tbh [r1, r2, lsl #1]. This checks that it goes to PC plus
  /// twice the halfword at Rn + Rm * 2, here 0x30. It is not a value test
  /// because it branches, and a run inside one instruction cannot follow it to
  /// what QEMU would show.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.237 TBH``() =
    let w = uint32 Window
    let cells = [ Gpr(1, w + 8u); Gpr(2, 1u); M(8, 0x300000UL) ]
    let run = runWith true "e8d1f012" cells []
    Assert.AreEqual(Some(CodeAddr + 0x64UL), run.Target)

  /// <summary>
  /// A8.8.238 TEQ: teq r1, #0x0. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.238 TEQ``() =
    let inputs =
      [ [ Gpr(1, 0xa3484b20u); CPSR 0x20000010u ]
        [ Gpr(1, 0x55812e8bu); CPSR 0x900a0010u ]
        [ Gpr(1, 0x0000ffffu); CPSR 0x48050010u ] ]
    let outputs =
      [ [ CPSR 0xa0000010u ]
        [ CPSR 0x100a0010u ]
        [ CPSR 0x08050010u ] ]
    check false "e3310000" inputs outputs

  /// <summary>
  /// A8.8.241 TST: tst r1, r2. The outputs are what QEMU left after running it
  /// on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.241 TST``() =
    let inputs =
      [ [ Gpr(1, 0x5309626eu); Gpr(2, 0xa7fc9211u); CPSR 0x20000010u ]
        [ Gpr(1, 0x93b9198fu); Gpr(2, 0x11096717u); CPSR 0x900a0010u ]
        [ Gpr(1, 0x0000ffffu); Gpr(2, 0x00008000u); CPSR 0x48050010u ] ]
    let outputs =
      [ [ CPSR 0x20000010u ]
        [ CPSR 0x100a0010u ]
        [ CPSR 0x08050010u ] ]
    check false "e1110002" inputs outputs

  /// <summary>
  /// A8.8.244 UADD16: uadd16 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.244 UADD16``() =
    let inputs =
      [ [ Gpr(0, 0x57a7c716u)
          Gpr(1, 0x94dddf74u)
          Gpr(2, 0xc8850e87u)
          CPSR 0x20000010u ]
        [ Gpr(0, 0x5b170891u)
          Gpr(1, 0x49d1b136u)
          Gpr(2, 0x1512ae13u)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x5d62edfbu); CPSR 0x200c0010u ]
        [ Gpr(0, 0x5ee35f49u); CPSR 0x90030010u ]
        [ Gpr(0, 0x80007fffu); CPSR 0x48000010u ] ]
    check false "e6510f12" inputs outputs

  /// <summary>
  /// A8.8.245 UADD8: uadd8 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.245 UADD8``() =
    let inputs =
      [ [ Gpr(0, 0x546c144du)
          Gpr(1, 0x599ebbf0u)
          Gpr(2, 0x90c3de1fu)
          CPSR 0x20000010u ]
        [ Gpr(0, 0x0b7701a8u)
          Gpr(1, 0x0fe518b6u)
          Gpr(2, 0xdf7d791du)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x7fff8000u)
          Gpr(2, 0x00000000u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xe961990fu); CPSR 0x20070010u ]
        [ Gpr(0, 0xee6291d3u); CPSR 0x90040010u ]
        [ Gpr(0, 0x7fff8000u); CPSR 0x48000010u ] ]
    check false "e6510f92" inputs outputs

  /// <summary>
  /// A8.8.246 UASX: uasx r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.246 UASX``() =
    let inputs =
      [ [ Gpr(0, 0x88d061f7u)
          Gpr(1, 0x8260ac82u)
          Gpr(2, 0xca0265ceu)
          CPSR 0x20000010u ]
        [ Gpr(0, 0x0f90fccfu)
          Gpr(1, 0x030d0eebu)
          Gpr(2, 0x676a6f9au)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xe82ee280u); CPSR 0x20000010u ]
        [ Gpr(0, 0x72a7a781u); CPSR 0x90000010u ]
        [ Gpr(0, 0x80000001u); CPSR 0x48030010u ] ]
    check false "e6510f32" inputs outputs

  /// <summary>
  /// A8.8.247 UBFX: ubfx r0, r1, #0x3, #0x5. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.247 UBFX``() =
    let inputs =
      [ [ Gpr(0, 0xdd557924u); Gpr(1, 0x38f5c451u) ]
        [ Gpr(0, 0x0cb7961cu); Gpr(1, 0x76c43496u) ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x0000000au) ]
        [ Gpr(0, 0x00000012u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e7e401d1" inputs outputs

  /// <summary>
  /// A8.8.248 UDF: udf #0x1204. This checks that it takes the Undefined
  /// Instruction exception. It is not a value test because it takes an
  /// exception, which a user-mode run cannot return from.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.248 UDF``() =
    let run = runWith false "e7f120f4" [ CPSR 0x10u ] []
    Assert.AreEqual(Some SideEffect.UndefinedInstruction, run.Effect)

  /// <summary>
  /// A8.8.249 UDIV: udiv r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.249 UDIV``() =
    let inputs =
      [ [ Gpr(0, 0x55b70c20u); Gpr(1, 0xf2b03f3cu); Gpr(2, 0xd89c261bu) ]
        [ Gpr(0, 0xe8d8e115u); Gpr(1, 0x7a734270u); Gpr(2, 0x4fae4587u) ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u); Gpr(2, 0x7fff8000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e730f211" inputs outputs

  /// <summary>
  /// A8.8.250 UHADD16: uhadd16 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.250 UHADD16``() =
    let inputs =
      [ [ Gpr(0, 0x4814e457u); Gpr(1, 0x469f3b16u); Gpr(2, 0x578f38d2u) ]
        [ Gpr(0, 0x526c61c7u); Gpr(1, 0x6bd760c8u); Gpr(2, 0xb246317du) ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x80007fffu); Gpr(2, 0x00000003u) ] ]
    let outputs =
      [ [ Gpr(0, 0x4f1739f4u) ]
        [ Gpr(0, 0x8f0e4922u) ]
        [ Gpr(0, 0x40004001u) ] ]
    check false "e6710f12" inputs outputs

  /// <summary>
  /// A8.8.251 UHADD8: uhadd8 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.251 UHADD8``() =
    let inputs =
      [ [ Gpr(0, 0x19b4313du); Gpr(1, 0x6a46c515u); Gpr(2, 0x6969a2bfu) ]
        [ Gpr(0, 0xdb8d64f1u); Gpr(1, 0x1d3e2768u); Gpr(2, 0xf48bc355u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x6957b36au) ]
        [ Gpr(0, 0x8864755eu) ]
        [ Gpr(0, 0x40003f7fu) ] ]
    check false "e6710f92" inputs outputs

  /// <summary>
  /// A8.8.252 UHASX: uhasx r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.252 UHASX``() =
    let inputs =
      [ [ Gpr(0, 0xf2dbd45au); Gpr(1, 0xda407e57u); Gpr(2, 0x360850b5u) ]
        [ Gpr(0, 0x7d070062u); Gpr(1, 0x947e603bu); Gpr(2, 0x09239876u) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x957a2427u) ]
        [ Gpr(0, 0x967a2b8cu) ]
        [ Gpr(0, 0x3fff4000u) ] ]
    check false "e6710f32" inputs outputs

  /// <summary>
  /// A8.8.253 UHSAX: uhsax r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.253 UHSAX``() =
    let inputs =
      [ [ Gpr(0, 0x2de2ae3eu); Gpr(1, 0xa40a6b75u); Gpr(2, 0xc3231718u) ]
        [ Gpr(0, 0x63b4d0edu); Gpr(1, 0x291640f8u); Gpr(2, 0x47fe356au) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x4679974cu) ]
        [ Gpr(0, 0xf9d6447bu) ]
        [ Gpr(0, 0x3fff4000u) ] ]
    check false "e6710f52" inputs outputs

  /// <summary>
  /// A8.8.254 UHSUB16: uhsub16 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.254 UHSUB16``() =
    let inputs =
      [ [ Gpr(0, 0xf4b5c734u); Gpr(1, 0x83401106u); Gpr(2, 0x90024214u) ]
        [ Gpr(0, 0x095496cfu); Gpr(1, 0x4a7bca4fu); Gpr(2, 0x8753b553u) ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x80007fffu); Gpr(2, 0x00000003u) ] ]
    let outputs =
      [ [ Gpr(0, 0xf99fe779u) ]
        [ Gpr(0, 0xe1940a7eu) ]
        [ Gpr(0, 0x40003ffeu) ] ]
    check false "e6710f72" inputs outputs

  /// <summary>
  /// A8.8.255 UHSUB8: uhsub8 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.255 UHSUB8``() =
    let inputs =
      [ [ Gpr(0, 0x17a456eeu); Gpr(1, 0x8b3dadd8u); Gpr(2, 0x2d748789u) ]
        [ Gpr(0, 0x9fa3c6dau); Gpr(1, 0x80f8d3c4u); Gpr(2, 0x0aa7c88eu) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x2fe41327u) ]
        [ Gpr(0, 0x3b28051bu) ]
        [ Gpr(0, 0xc000c080u) ] ]
    check false "e6710ff2" inputs outputs

  /// <summary>
  /// A8.8.256 UMAAL: umaal r0, r1, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.256 UMAAL``() =
    let inputs =
      [ [ Gpr(0, 0x6acb38a0u); Gpr(1, 0xd0f98a2eu); Gpr(2, 0xf9a0a853u) ]
        [ Gpr(0, 0xe96aa7c8u); Gpr(1, 0x4460ebcbu); Gpr(2, 0x3223904du) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0xda1abfb8u); Gpr(1, 0xcbc5dcc5u) ]
        [ Gpr(0, 0x2655afa2u); Gpr(1, 0x0d646ddau) ]
        [ Gpr(0, 0x80000000u); Gpr(1, 0x00000000u) ] ]
    check false "e0410291" inputs outputs

  /// <summary>
  /// A8.8.257 UMLAL: umlal r0, r1, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.257 UMLAL``() =
    let inputs =
      [ [ Gpr(0, 0x49d5921au); Gpr(1, 0x214caf5fu); Gpr(2, 0x447ae81du) ]
        [ Gpr(0, 0xb7301873u); Gpr(1, 0x1ff67ea1u); Gpr(2, 0x2cba3d69u) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x5db987ddu); Gpr(1, 0x2a350ab1u) ]
        [ Gpr(0, 0x3c70657cu); Gpr(1, 0x258c1d28u) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u) ] ]
    check false "e0a10291" inputs outputs

  /// <summary>
  /// A8.8.258 UMULL: umull r0, r1, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.258 UMULL``() =
    let inputs =
      [ [ Gpr(0, 0x7179f9a0u); Gpr(1, 0x582d39ccu); Gpr(2, 0x78b13401u) ]
        [ Gpr(0, 0x369efe58u); Gpr(1, 0xca6fcc0du); Gpr(2, 0x139880fau) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x1df6a9ccu); Gpr(1, 0x29923c46u) ]
        [ Gpr(0, 0xb5ebc4b2u); Gpr(1, 0x0f7ee483u) ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x00000000u) ] ]
    check false "e0810291" inputs outputs

  /// <summary>
  /// A8.8.259 UQADD16: uqadd16 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.259 UQADD16``() =
    let inputs =
      [ [ Gpr(0, 0x86536460u); Gpr(1, 0x1ab4c76cu); Gpr(2, 0x226b0bc1u) ]
        [ Gpr(0, 0x4b6bfde0u); Gpr(1, 0x3448c38au); Gpr(2, 0xed22f60du) ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x80007fffu); Gpr(2, 0x00000003u) ] ]
    let outputs =
      [ [ Gpr(0, 0x3d1fd32du) ]
        [ Gpr(0, 0xffffffffu) ]
        [ Gpr(0, 0x80008002u) ] ]
    check false "e6610f12" inputs outputs

  /// <summary>
  /// A8.8.260 UQADD8: uqadd8 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.260 UQADD8``() =
    let inputs =
      [ [ Gpr(0, 0xc0379efeu); Gpr(1, 0x5d43f187u); Gpr(2, 0x8b0f297eu) ]
        [ Gpr(0, 0x8f7719ffu); Gpr(1, 0xd3809f0cu); Gpr(2, 0xd2da2177u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0xe852ffffu) ]
        [ Gpr(0, 0xffffc083u) ]
        [ Gpr(0, 0x80007fffu) ] ]
    check false "e6610f92" inputs outputs

  /// <summary>
  /// A8.8.261 UQASX: uqasx r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.261 UQASX``() =
    let inputs =
      [ [ Gpr(0, 0x8880e1e1u); Gpr(1, 0x93341aebu); Gpr(2, 0x5e480292u) ]
        [ Gpr(0, 0x0b57b39fu); Gpr(1, 0xd5288c8fu); Gpr(2, 0x1cf2a7dbu) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x95c60000u) ]
        [ Gpr(0, 0xffff6f9du) ]
        [ Gpr(0, 0x7fff8000u) ] ]
    check false "e6610f32" inputs outputs

  /// <summary>
  /// A8.8.262 UQSAX: uqsax r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.262 UQSAX``() =
    let inputs =
      [ [ Gpr(0, 0x8d8c6e05u); Gpr(1, 0xcaf6211fu); Gpr(2, 0xdfaaa154u) ]
        [ Gpr(0, 0x6ade2150u); Gpr(1, 0xd3d55345u); Gpr(2, 0xf312b434u) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x29a2ffffu) ]
        [ Gpr(0, 0x1fa1ffffu) ]
        [ Gpr(0, 0x7fff8000u) ] ]
    check false "e6610f52" inputs outputs

  /// <summary>
  /// A8.8.263 UQSUB16: uqsub16 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.263 UQSUB16``() =
    let inputs =
      [ [ Gpr(0, 0x5d375db1u); Gpr(1, 0x9a852d14u); Gpr(2, 0xfc791db2u) ]
        [ Gpr(0, 0x094e41c2u); Gpr(1, 0xd6f1e6fdu); Gpr(2, 0xe6cde1a6u) ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x80007fffu); Gpr(2, 0x00000003u) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000f62u) ]
        [ Gpr(0, 0x00000557u) ]
        [ Gpr(0, 0x80007ffcu) ] ]
    check false "e6610f72" inputs outputs

  /// <summary>
  /// A8.8.264 UQSUB8: uqsub8 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.264 UQSUB8``() =
    let inputs =
      [ [ Gpr(0, 0xe99e5253u); Gpr(1, 0x0fc81c85u); Gpr(2, 0xdb3e3308u) ]
        [ Gpr(0, 0x1abd43b8u); Gpr(1, 0x52768212u); Gpr(2, 0xa0a4479au) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x008a007du) ]
        [ Gpr(0, 0x00003b00u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e6610ff2" inputs outputs

  /// <summary>
  /// A8.8.265 USAD8: usad8 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.265 USAD8``() =
    let inputs =
      [ [ Gpr(0, 0x4dbfa8b0u); Gpr(1, 0xae101b0fu); Gpr(2, 0xf9b12514u) ]
        [ Gpr(0, 0x280118dcu); Gpr(1, 0xa4eeaa5au); Gpr(2, 0xe53946a0u) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x000000fbu) ]
        [ Gpr(0, 0x000001a0u) ]
        [ Gpr(0, 0x000001feu) ] ]
    check false "e780f211" inputs outputs

  /// <summary>
  /// A8.8.266 USADA8: usada8 r0, r1, r2, r3. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.266 USADA8``() =
    let inputs =
      [ [ Gpr(0, 0xb88f9b1du)
          Gpr(1, 0x8a08dea2u)
          Gpr(2, 0xdb56130au)
          Gpr(3, 0x065716c5u) ]
        [ Gpr(0, 0xaf3396aau)
          Gpr(1, 0x4d87dd37u)
          Gpr(2, 0x7b4be4ddu)
          Gpr(3, 0xf9ce750du) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Gpr(3, 0x00000003u) ] ]
    let outputs =
      [ [ Gpr(0, 0x065718c7u) ]
        [ Gpr(0, 0xf9ce7624u) ]
        [ Gpr(0, 0x00000201u) ] ]
    check false "e7803211" inputs outputs

  /// <summary>
  /// A8.8.267 USAT: usat r0, #0x3, r1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.267 USAT``() =
    let inputs =
      [ [ Gpr(0, 0xff225d82u); Gpr(1, 0x2e71154cu); CPSR 0x20000010u ]
        [ Gpr(0, 0xbad24a42u); Gpr(1, 0x55b5136cu); CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u); CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x00000007u); CPSR 0x28000010u ]
        [ Gpr(0, 0x00000007u); CPSR 0x980a0010u ]
        [ Gpr(0, 0x00000007u); CPSR 0x48050010u ] ]
    check false "e6e30011" inputs outputs

  /// <summary>
  /// A8.8.268 USAT16: usat16 r0, #0x3, r1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.268 USAT16``() =
    let inputs =
      [ [ Gpr(0, 0xd6912eb0u); Gpr(1, 0x57e1de5au); CPSR 0x20000010u ]
        [ Gpr(0, 0x26641ae8u); Gpr(1, 0x1792315eu); CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x00070000u); CPSR 0x28000010u ]
        [ Gpr(0, 0x00070007u); CPSR 0x980a0010u ]
        [ Gpr(0, 0x00000000u); CPSR 0x48050010u ] ]
    check false "e6e30f31" inputs outputs

  /// <summary>
  /// A8.8.269 USAX: usax r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.269 USAX``() =
    let inputs =
      [ [ Gpr(0, 0xd5d26d44u)
          Gpr(1, 0x7990403au)
          Gpr(2, 0x254053a3u)
          CPSR 0x20000010u ]
        [ Gpr(0, 0x49b4885cu)
          Gpr(1, 0xa65fae60u)
          Gpr(2, 0x71067a8au)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x25ed657au); CPSR 0x200c0010u ]
        [ Gpr(0, 0x2bd51f66u); CPSR 0x900f0010u ]
        [ Gpr(0, 0x8000ffffu); CPSR 0x48000010u ] ]
    check false "e6510f52" inputs outputs

  /// <summary>
  /// A8.8.270 USUB16: usub16 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.270 USUB16``() =
    let inputs =
      [ [ Gpr(0, 0x59ba4996u)
          Gpr(1, 0x5d094aa4u)
          Gpr(2, 0x72ea34d8u)
          CPSR 0x20000010u ]
        [ Gpr(0, 0x072827dbu)
          Gpr(1, 0xafffcb8bu)
          Gpr(2, 0x0c3f37b0u)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xea1f15ccu); CPSR 0x20030010u ]
        [ Gpr(0, 0xa3c093dbu); CPSR 0x900f0010u ]
        [ Gpr(0, 0x80008001u); CPSR 0x48000010u ] ]
    check false "e6510f72" inputs outputs

  /// <summary>
  /// A8.8.271 USUB8: usub8 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.271 USUB8``() =
    let inputs =
      [ [ Gpr(0, 0x3403ed21u)
          Gpr(1, 0xef6f22e1u)
          Gpr(2, 0x1910fb96u)
          CPSR 0x20000010u ]
        [ Gpr(0, 0xda568efau)
          Gpr(1, 0x6f7a3ea2u)
          Gpr(2, 0xb03ede03u)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x7fff8000u)
          Gpr(2, 0x00000000u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xd65f274bu); CPSR 0x200d0010u ]
        [ Gpr(0, 0xbf3c609fu); CPSR 0x90050010u ]
        [ Gpr(0, 0x7fff8000u); CPSR 0x480f0010u ] ]
    check false "e6510ff2" inputs outputs

  /// <summary>
  /// A8.8.272 UXTAB: uxtab r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.272 UXTAB``() =
    let inputs =
      [ [ Gpr(0, 0x13341b72u); Gpr(1, 0xfc77a1f0u); Gpr(2, 0x602664dbu) ]
        [ Gpr(0, 0x00a7a90au); Gpr(1, 0x53cca7a7u); Gpr(2, 0x9d862cadu) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0xfc77a2cbu) ]
        [ Gpr(0, 0x53cca854u) ]
        [ Gpr(0, 0x7fff8000u) ] ]
    check false "e6e10072" inputs outputs

  /// <summary>
  /// A8.8.273 UXTAB16: uxtab16 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.273 UXTAB16``() =
    let inputs =
      [ [ Gpr(0, 0x9cb1d82fu); Gpr(1, 0x946a83dbu); Gpr(2, 0x28594f20u) ]
        [ Gpr(0, 0xd6c717e0u); Gpr(1, 0x44f1197du); Gpr(2, 0x3fa3b295u) ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x80007fffu); Gpr(2, 0x00000003u) ] ]
    let outputs =
      [ [ Gpr(0, 0x94c383fbu) ]
        [ Gpr(0, 0x45941a12u) ]
        [ Gpr(0, 0x80008002u) ] ]
    check false "e6c10072" inputs outputs

  /// <summary>
  /// A8.8.274 UXTAH: uxtah r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.274 UXTAH``() =
    let inputs =
      [ [ Gpr(0, 0x44a54a97u); Gpr(1, 0x86b10abau); Gpr(2, 0x1b81a0a5u) ]
        [ Gpr(0, 0x5309c972u); Gpr(1, 0xc44157ddu); Gpr(2, 0x27674f64u) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x86b1ab5fu) ]
        [ Gpr(0, 0xc441a741u) ]
        [ Gpr(0, 0x7fff8000u) ] ]
    check false "e6f10072" inputs outputs

  /// <summary>
  /// A8.8.275 UXTB: uxtb r0, r1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.275 UXTB``() =
    let inputs =
      [ [ Gpr(0, 0x799fe8bau); Gpr(1, 0x270a2230u) ]
        [ Gpr(0, 0x02492aa5u); Gpr(1, 0x9d410817u) ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000030u) ]
        [ Gpr(0, 0x00000017u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e6ef0071" inputs outputs

  /// <summary>
  /// A8.8.276 UXTB16: uxtb16 r0, r1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.276 UXTB16``() =
    let inputs =
      [ [ Gpr(0, 0x9961713cu); Gpr(1, 0xcc5c0dd2u) ]
        [ Gpr(0, 0xc341aac9u); Gpr(1, 0xda697c90u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x005c00d2u) ]
        [ Gpr(0, 0x00690090u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e6cf0071" inputs outputs

  /// <summary>
  /// A8.8.277 UXTH: uxth r0, r1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.277 UXTH``() =
    let inputs =
      [ [ Gpr(0, 0xc6d59ab8u); Gpr(1, 0x3e999ac8u) ]
        [ Gpr(0, 0x5071f0ffu); Gpr(1, 0x072ccf15u) ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x00009ac8u) ]
        [ Gpr(0, 0x0000cf15u) ]
        [ Gpr(0, 0x00008000u) ] ]
    check false "e6ff0071" inputs outputs

  /// <summary>
  /// A8.8.278 VABA: vaba.s32 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.278 VABA``() =
    let inputs =
      [ [ D(0, 0xf7287e15921ac7e9UL)
          D(1, 0x7e8070ebe13f7785UL)
          D(2, 0x333b9560c8011f90UL)
          D(3, 0x87db9401e034b5c5UL)
          D(4, 0xf003dd3a70840f79UL)
          D(5, 0xed5171538e3f0a17UL) ]
        [ D(0, 0xc803a0935d406519UL)
          D(1, 0x7d7d773af1fff0a6UL)
          D(2, 0x356a85abd3fcb6ecUL)
          D(3, 0x53fd1b9bf3f6a157UL)
          D(4, 0xe99afb5a18167ed6UL)
          D(5, 0xee29fbbb2cf87789UL) ]
        [ D(0, 0x8001800180018001UL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0xffffffffffffffffUL)
          D(3, 0x7f80ff00807fffffUL)
          D(4, 0x7f80ff00807fffffUL)
          D(5, 0x7fffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x3a60363b3a9db7d2UL); D(1, 0xe3f64e3d33352333UL) ]
        [ D(0, 0x13d32ae4a15a2d03UL); D(1, 0xe350971a2b01c6d8UL) ]
        [ D(0, 0xff827f02ff818001UL); D(1, 0x007f00fe7f7fffffUL) ] ]
    check false "f2220754" inputs outputs

  /// <summary>
  /// A8.8.278 VABAL: vabal.s8 q0, d1, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.278 VABAL``() =
    let inputs =
      [ [ D(0, 0xc301a6c80452798dUL)
          D(1, 0xbb89ba4ba96fc071UL)
          D(2, 0x28149c1e0137ef2bUL) ]
        [ D(0, 0x25253408a08cd0c6UL)
          D(1, 0x13733fb15755bb69UL)
          D(2, 0xc7e12afe06412a7eUL) ]
        [ D(0, 0x00ff00ff00ff00ffUL)
          D(1, 0x8000000000000000UL)
          D(2, 0x00ff00ff00ff00ffUL) ] ]
    let outputs =
      [ [ D(0, 0xc359a700048179d3UL); D(1, 0xbbf6bad6a98dc09eUL) ]
        [ D(0, 0x2576341ca0fbd0dbUL); D(1, 0x13bf4043576abbb6UL) ]
        [ D(0, 0x00ff010000ff0100UL); D(1, 0x8080000100000001UL) ] ]
    check false "f2810502" inputs outputs

  /// <summary>
  /// A8.8.279 VABD: vabd.f32 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.279 VABD``() =
    let inputs =
      [ [ D(0, 0xc040000040200000UL)
          D(1, 0x3fe00000c0600000UL)
          D(2, 0x4140000040800000UL)
          D(3, 0xc010000040200000UL)
          D(4, 0x3fc0000044800000UL)
          D(5, 0xc0100000c0400000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x3e00000040c00000UL)
          D(1, 0xc0d0000040200000UL)
          D(2, 0xc01000003e800000UL)
          D(3, 0x40400000c0d00000UL)
          D(4, 0x448000003fc00000UL)
          D(5, 0x3d800000bf800000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x40400000ff800000UL)
          D(1, 0x3fc000007f800000UL)
          D(2, 0xc01000007f800000UL)
          D(3, 0x80000000c0100000UL)
          D(4, 0x404000003f000000UL)
          D(5, 0x3f0000007f800000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x41280000447f0000UL)
          D(1, 0x0000000040b00000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x448048003fa00000UL)
          D(1, 0x403c000040b00000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x40a800007f800000UL)
          D(1, 0x3f0000007f800000UL)
          FPSCR 0x00000000u ] ]
    check false "f3220d44" inputs outputs

  /// <summary>
  /// A8.8.279 VABDL: vabdl.s8 q0, d1, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.279 VABDL``() =
    let inputs =
      [ [ D(0, 0xf48fecfee65c4e60UL)
          D(1, 0x5fb8e46daa7dca43UL)
          D(2, 0xfc55079899f5661aUL) ]
        [ D(0, 0x58b36b12059477c4UL)
          D(1, 0x2363cd68fde2e6b2UL)
          D(2, 0x5108450000f15402UL) ]
        [ D(0, 0x0102030405060708UL)
          D(1, 0x8000000000000000UL)
          D(2, 0x0102030405060708UL) ] ]
    let outputs =
      [ [ D(0, 0x00110088009c0029UL); D(1, 0x0063009d002300d5UL) ]
        [ D(0, 0x0003000f006e0050UL); D(1, 0x002e005b00780068UL) ]
        [ D(0, 0x0005000600070008UL); D(1, 0x0081000200030004UL) ] ]
    check false "f2810702" inputs outputs

  /// <summary>
  /// A8.8.281 VABS: vabs.f32 s0, s2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.281 VABS``() =
    let inputs =
      [ [ D(0, 0xbf00000042c90000UL); D(1, 0x40c0000040800000UL) ]
        [ D(0, 0xc0d00000bec00000UL); D(1, 0xc240000041400000UL) ]
        [ D(0, 0xc0100000c0100000UL); D(1, 0x7f8000007f800000UL) ] ]
    let outputs =
      [ [ D(0, 0xbf00000040800000UL) ]
        [ D(0, 0xc0d0000041400000UL) ]
        [ D(0, 0xc01000007f800000UL) ] ]
    check false "eeb00ac1" inputs outputs

  /// <summary>
  /// A8.8.282 VACGE: vacge.f32 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.282 VACGE``() =
    let inputs =
      [ [ D(0, 0x4120000040c00000UL)
          D(1, 0xbf000000bf800000UL)
          D(2, 0xbf00000040200000UL)
          D(3, 0x40e80000c0d00000UL)
          D(4, 0xbf000000bf800000UL)
          D(5, 0x40000000bf000000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0xc2400000c2400000UL)
          D(1, 0x408000003fe00000UL)
          D(2, 0xc0d00000c0600000UL)
          D(3, 0xc06000003fe00000UL)
          D(4, 0x40400000c0100000UL)
          D(5, 0x40400000bf800000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x3f00000080000000UL)
          D(1, 0x3f000000c0100000UL)
          D(2, 0x7f80000040400000UL)
          D(3, 0xff800000ff800000UL)
          D(4, 0xff80000080000000UL)
          D(5, 0xc0100000c0100000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xffffffffffffffffUL)
          D(1, 0xffffffffffffffffUL)
          FPSCR 0x00000000u ]
        [ D(0, 0xffffffffffffffffUL)
          D(1, 0xffffffffffffffffUL)
          FPSCR 0x60000000u ]
        [ D(0, 0xffffffffffffffffUL)
          D(1, 0xffffffffffffffffUL)
          FPSCR 0x00000000u ] ]
    check false "f3020e54" inputs outputs

  /// <summary>
  /// A8.8.282 VACGT: vacgt.f32 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.282 VACGT``() =
    let inputs =
      [ [ D(0, 0xc0d000003e000000UL)
          D(1, 0xc040000040800000UL)
          D(2, 0xc010000040c00000UL)
          D(3, 0x41200000c0100000UL)
          D(4, 0xbf800000bf800000UL)
          D(5, 0xbf8000003e000000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x3fe00000bec00000UL)
          D(1, 0x41200000c0d00000UL)
          D(2, 0xc060000040800000UL)
          D(3, 0xc040000044800000UL)
          D(4, 0x40c00000bf800000UL)
          D(5, 0xc0400000c2400000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x80000000ff800000UL)
          D(1, 0x7f80000040400000UL)
          D(2, 0x7f80000040400000UL)
          D(3, 0x80000000ff800000UL)
          D(4, 0x3fc000007f800000UL)
          D(5, 0xff80000000000000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xffffffffffffffffUL)
          D(1, 0xffffffffffffffffUL)
          FPSCR 0x00000000u ]
        [ D(0, 0x00000000ffffffffUL)
          D(1, 0x00000000ffffffffUL)
          FPSCR 0x60000000u ]
        [ D(0, 0xffffffff00000000UL)
          D(1, 0x00000000ffffffffUL)
          FPSCR 0x00000000u ] ]
    check false "f3220e54" inputs outputs

  /// <summary>
  /// A8.8.282 VACLE: vacge.f32 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.282 VACLE``() =
    let inputs =
      [ [ D(0, 0x3d800000bec00000UL)
          D(1, 0x3d8000003f400000UL)
          D(2, 0x4000000040800000UL)
          D(3, 0x3fc0000040e80000UL)
          D(4, 0xc06000003e800000UL)
          D(5, 0x40c000003e800000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0xc06000003e000000UL)
          D(1, 0x3fc00000c0d00000UL)
          D(2, 0x3e800000bf000000UL)
          D(3, 0x3f400000bf800000UL)
          D(4, 0xc040000040e80000UL)
          D(5, 0x4120000041400000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x3f00000040400000UL)
          D(1, 0xc010000000000000UL)
          D(2, 0x3f0000003fc00000UL)
          D(3, 0x8000000040400000UL)
          D(4, 0x3f000000ff800000UL)
          D(5, 0x7f80000040400000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x00000000ffffffffUL)
          D(1, 0x00000000ffffffffUL)
          FPSCR 0x00000000u ]
        [ D(0, 0x0000000000000000UL)
          D(1, 0x0000000000000000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0xffffffff00000000UL)
          D(1, 0x00000000ffffffffUL)
          FPSCR 0x00000000u ] ]
    check false "f3020e54" inputs outputs

  /// <summary>
  /// A8.8.282 VACLT: vacgt.f32 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.282 VACLT``() =
    let inputs =
      [ [ D(0, 0x3fe0000041200000UL)
          D(1, 0x4080000042c90000UL)
          D(2, 0x3fc0000041200000UL)
          D(3, 0x40e8000041200000UL)
          D(4, 0x3d800000c0600000UL)
          D(5, 0xc010000040e80000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x402000003d800000UL)
          D(1, 0x40800000c0600000UL)
          D(2, 0xbf00000040200000UL)
          D(3, 0xc0400000c0100000UL)
          D(4, 0x3e00000041400000UL)
          D(5, 0x400000003d800000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0xc01000007f800000UL)
          D(1, 0x3fc0000040400000UL)
          D(2, 0x000000003fc00000UL)
          D(3, 0x4040000040400000UL)
          D(4, 0x7f80000040400000UL)
          D(5, 0x7f80000080000000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xffffffffffffffffUL)
          D(1, 0xffffffffffffffffUL)
          FPSCR 0x00000000u ]
        [ D(0, 0xffffffff00000000UL)
          D(1, 0xffffffffffffffffUL)
          FPSCR 0x60000000u ]
        [ D(0, 0x0000000000000000UL)
          D(1, 0x00000000ffffffffUL)
          FPSCR 0x00000000u ] ]
    check false "f3220e54" inputs outputs

  /// <summary>
  /// A8.8.283 VADD: vadd.f32 s0, s1, s2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.283 VADD``() =
    let inputs =
      [ [ D(0, 0x4480000041200000UL)
          D(1, 0x4080000041200000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x40c0000041200000UL)
          D(1, 0x4080000040200000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x40400000c0100000UL)
          D(1, 0xff8000007f800000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x4480000044814000UL); FPSCR 0x00000000u ]
        [ D(0, 0x40c0000041080000UL); FPSCR 0x60000000u ]
        [ D(0, 0x404000007f800000UL); FPSCR 0x00000000u ] ]
    check false "ee300a81" inputs outputs

  /// <summary>
  /// A8.8.285 VADDHN: vaddhn.i32 d0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.285 VADDHN``() =
    let inputs =
      [ [ D(0, 0x8fa5a98a00cca5f2UL)
          D(2, 0x09476fffbadd635fUL)
          D(3, 0xd7b37d35df6c535cUL)
          D(4, 0x6e455ca26a910a03UL)
          D(5, 0xb5e0523400db875cUL) ]
        [ D(0, 0xeed8ca8725835d7eUL)
          D(2, 0xf386217080c4c352UL)
          D(3, 0x929e54d8f82b3d2eUL)
          D(4, 0x01c5085cdb750b00UL)
          D(5, 0x0d1715a26274fd15UL) ]
        [ D(0, 0x00ff00ff00ff00ffUL)
          D(2, 0x0102030405060708UL)
          D(3, 0x7f80ff00807fffffUL)
          D(4, 0x7f80ff00807fffffUL)
          D(5, 0x00ff00ff00ff00ffUL) ] ]
    let outputs =
      [ [ D(0, 0x8d93e047778c256eUL) ]
        [ D(0, 0x9fb55aa0f54b5c39UL) ]
        [ D(0, 0x807f817f80838586UL) ] ]
    check false "f2920404" inputs outputs

  /// <summary>
  /// A8.8.286 VADDL: vaddl.s32 q0, d1, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.286 VADDL``() =
    let inputs =
      [ [ D(0, 0x5e12011b0bc61bd1UL)
          D(1, 0xbfce12dc52a43b82UL)
          D(2, 0x013057ae7594e638UL) ]
        [ D(0, 0x0c70a9b18fd96809UL)
          D(1, 0x58db655d8ab7f14fUL)
          D(2, 0xf8b0bf69e1110b56UL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0x00ff00ff00ff00ffUL)
          D(2, 0x7fffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x00000000c83921baUL); D(1, 0xffffffffc0fe6a8aUL) ]
        [ D(0, 0xffffffff6bc8fca5UL); D(1, 0x00000000518c24c6UL) ]
        [ D(0, 0x0000000000ff00feUL); D(1, 0x0000000080ff00feUL) ] ]
    check false "f2a10002" inputs outputs

  /// <summary>
  /// A8.8.286 VADDW: vaddw.s8 q0, q0, d1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.286 VADDW``() =
    let inputs =
      [ [ D(0, 0x5edef6a08932c0e5UL); D(1, 0x00dbde28de5ea4a9UL) ]
        [ D(0, 0xf02caedb331a92a4UL); D(1, 0x9d6d550586cfcabcUL) ]
        [ D(0, 0x00ff00ff00ff00ffUL); D(1, 0x00ff00ff00ff00ffUL) ] ]
    let outputs =
      [ [ D(0, 0x5ebcf6fe88d6c08eUL); D(1, 0x00dbde03de3ca4d1UL) ]
        [ D(0, 0xefb2aeaa32e49260UL); D(1, 0x9d0a55728724cac1UL) ]
        [ D(0, 0x00ff00fe00ff00feUL); D(1, 0x00ff00fe00ff00feUL) ] ]
    check false "f2800101" inputs outputs

  /// <summary>
  /// A8.8.287 VAND: vand q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.287 VAND``() =
    let inputs =
      [ [ D(0, 0x67b35580692dc62cUL)
          D(1, 0x149ef507ef2e2c93UL)
          D(2, 0xa5710873507213e7UL)
          D(3, 0xe1c20eacda4ad417UL)
          D(4, 0xfc709659ec661f57UL)
          D(5, 0x6382526b242b11c3UL) ]
        [ D(0, 0xc24ff5ee3726cc36UL)
          D(1, 0x5eca19cd149279c1UL)
          D(2, 0xc55bfdb249a8eb0eUL)
          D(3, 0x143701d21cee9474UL)
          D(4, 0x9e2d49ea374a2ad9UL)
          D(5, 0x90fc95eb23d2d85eUL) ]
        [ D(0, 0xffffffffffffffffUL)
          D(1, 0x7fffffffffffffffUL)
          D(2, 0x0102030405060708UL)
          D(3, 0x7f80ff00807fffffUL)
          D(4, 0x7fffffffffffffffUL)
          D(5, 0x00ff00ff00ff00ffUL) ] ]
    let outputs =
      [ [ D(0, 0xa470005140621347UL); D(1, 0x61820228000a1003UL) ]
        [ D(0, 0x840949a201082a08UL); D(1, 0x103401c200c29054UL) ]
        [ D(0, 0x0102030405060708UL); D(1, 0x00800000007f00ffUL) ] ]
    check false "f2020154" inputs outputs

  /// <summary>
  /// A8.8.289 VBIC: vbic.i32 q0, #0x10. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.289 VBIC``() =
    let inputs =
      [ [ D(0, 0x6a79494a496a4921UL); D(1, 0x5ca0049476afc743UL) ]
        [ D(0, 0x982307198df69294UL); D(1, 0x9fcd8087ab29652dUL) ]
        [ D(0, 0x8000000000000000UL); D(1, 0x7fffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x6a79494a496a4921UL); D(1, 0x5ca0048476afc743UL) ]
        [ D(0, 0x982307098df69284UL); D(1, 0x9fcd8087ab29652dUL) ]
        [ D(0, 0x8000000000000000UL); D(1, 0x7fffffefffffffefUL) ] ]
    check false "f2810170" inputs outputs

  /// <summary>
  /// A8.8.291 VBIF: vbif q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.291 VBIF``() =
    let inputs =
      [ [ D(0, 0xd33c3f9168c310a4UL)
          D(1, 0x7567f58548138a12UL)
          D(2, 0x093a5f5dff6580fdUL)
          D(3, 0x70e6f50e69edc0ecUL)
          D(4, 0x0520ab3c7dc91528UL)
          D(5, 0x7663ad3a08e96d79UL) ]
        [ D(0, 0xd05120fbf86280dbUL)
          D(1, 0x776193105776c905UL)
          D(2, 0x72e18a6c5682c2d7UL)
          D(3, 0x5bed1bba2acac8b0UL)
          D(4, 0x15409f8b5d2beab3UL)
          D(5, 0xdf42d5ec1184ede5UL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0x8000000000000000UL)
          D(3, 0x00ff00ff00ff00ffUL)
          D(4, 0x8001800180018001UL)
          D(5, 0x0000000000000001UL) ] ]
    let outputs =
      [ [ D(0, 0x093a7f51eae590f5UL); D(1, 0x74e7f50469058894UL) ]
        [ D(0, 0x72e100ef5aa280d7UL); D(1, 0x57ed9b123b4ec915UL) ]
        [ D(0, 0x0000800080018001UL); D(1, 0x00ff00ff00ff00ffUL) ] ]
    check false "f3320154" inputs outputs

  /// <summary>
  /// A8.8.291 VBIT: vbit q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.291 VBIT``() =
    let inputs =
      [ [ D(0, 0x1640bc5a0551b073UL)
          D(1, 0x00f2033d83f15a79UL)
          D(2, 0xdfb3bc436311bacbUL)
          D(3, 0x88dbadda17fecf6eUL)
          D(4, 0x908713f483331574UL)
          D(5, 0x4e0090f8664e8e43UL) ]
        [ D(0, 0xaa2e3119f48f8c1dUL)
          D(1, 0xbaf63939937d2fd0UL)
          D(2, 0x6e71e2d1ecb87225UL)
          D(3, 0x8bfd06b4030751bbUL)
          D(4, 0xcafacf4a629fdebdUL)
          D(5, 0xea70f12427fd67b6UL) ]
        [ D(0, 0x8001800180018001UL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0x00ff00ff00ff00ffUL)
          D(3, 0x0102030405060708UL)
          D(4, 0x7f80ff00807fffffUL)
          D(5, 0x7f80ff00807fffffUL) ] ]
    let outputs =
      [ [ D(0, 0x96c3bc4a0751b043UL); D(1, 0x08f283dd87ffde7aUL) ]
        [ D(0, 0x6a74f251f4985225UL); D(1, 0x9af6083d930549f2UL) ]
        [ D(0, 0x80810001007f00ffUL); D(1, 0x817f03ff7f860708UL) ] ]
    check false "f3220154" inputs outputs

  /// <summary>
  /// A8.8.291 VBSL: vbsl q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.291 VBSL``() =
    let inputs =
      [ [ D(0, 0x7980a23c9fa97998UL)
          D(1, 0x34285f19f2140a79UL)
          D(2, 0x306d8207f3c79a21UL)
          D(3, 0xb7bf89b070effcfaUL)
          D(4, 0x2e3e6e51944e2469UL)
          D(5, 0x45761623a27377faUL) ]
        [ D(0, 0xcca5fbdee34d371bUL)
          D(1, 0x230458c6e0c8aefbUL)
          D(2, 0xa3382ec15ca5d491UL)
          D(3, 0xb6b1ed9488063842UL)
          D(4, 0x3389d4872f5447e3UL)
          D(5, 0x8cb97f6a354ff27cUL) ]
        [ D(0, 0xffffffffffffffffUL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0xffffffffffffffffUL)
          D(3, 0x8000000000000000UL)
          D(4, 0x0102030405060708UL)
          D(5, 0x0102030405060708UL) ] ]
    let outputs =
      [ [ D(0, 0x363ece4593c71c61UL); D(1, 0x757e093270677dfaUL) ]
        [ D(0, 0xb3282ec14c1554f1UL); D(1, 0xaeb96fac95077846UL) ]
        [ D(0, 0xffffffffffffffffUL); D(1, 0x8000000000000000UL) ] ]
    check false "f3120154" inputs outputs

  /// <summary>
  /// A8.8.292 VCEQ: vceq.f32 d0, d1, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.292 VCEQ``() =
    let inputs =
      [ [ D(0, 0xbec000003d800000UL)
          D(1, 0x3f40000042c90000UL)
          D(2, 0x3f40000041400000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0xc040000044800000UL)
          D(1, 0x4080000042c90000UL)
          D(2, 0x3d8000003f400000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x3fc00000ff800000UL)
          D(1, 0x3fc000007f800000UL)
          D(2, 0x7f80000040400000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xffffffff00000000UL); FPSCR 0x00000000u ]
        [ D(0, 0x0000000000000000UL); FPSCR 0x60000000u ]
        [ D(0, 0x0000000000000000UL); FPSCR 0x00000000u ] ]
    check false "f2010e02" inputs outputs

  /// <summary>
  /// A8.8.294 VCGE: vcge.f32 d0, d1, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.294 VCGE``() =
    let inputs =
      [ [ D(0, 0x41400000c0d00000UL)
          D(1, 0xbf00000042c90000UL)
          D(2, 0xc040000040400000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0xc24000003fe00000UL)
          D(1, 0x3e800000bf000000UL)
          D(2, 0x40e8000040000000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x3f0000003f000000UL)
          D(1, 0x404000007f800000UL)
          D(2, 0x00000000c0100000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xffffffffffffffffUL); FPSCR 0x00000000u ]
        [ D(0, 0x0000000000000000UL); FPSCR 0x60000000u ]
        [ D(0, 0xffffffffffffffffUL); FPSCR 0x00000000u ] ]
    check false "f3010e02" inputs outputs

  /// <summary>
  /// A8.8.296 VCGT: vcgt.f32 d0, d1, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.296 VCGT``() =
    let inputs =
      [ [ D(0, 0xc0100000c0100000UL)
          D(1, 0x40e800003e000000UL)
          D(2, 0x3e8000003f400000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0xbf00000040e80000UL)
          D(1, 0x44800000c2400000UL)
          D(2, 0x4480000040800000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0xc01000007f800000UL)
          D(1, 0xff80000000000000UL)
          D(2, 0xff8000007f800000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xffffffff00000000UL); FPSCR 0x00000000u ]
        [ D(0, 0x0000000000000000UL); FPSCR 0x60000000u ]
        [ D(0, 0x0000000000000000UL); FPSCR 0x00000000u ] ]
    check false "f3210e02" inputs outputs

  /// <summary>
  /// A8.8.298 VCLE: vcle.f32 q0, q2, #0x0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.298 VCLE``() =
    let inputs =
      [ [ D(0, 0xc0400000c0600000UL)
          D(1, 0x4000000042c90000UL)
          D(4, 0x42c900003fc00000UL)
          D(5, 0x4140000041400000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x4040000041400000UL)
          D(1, 0x44800000c0100000UL)
          D(4, 0x3d800000c0400000UL)
          D(5, 0xc0600000c0d00000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x80000000c0100000UL)
          D(1, 0xc0100000c0100000UL)
          D(4, 0x00000000c0100000UL)
          D(5, 0x8000000040400000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x0000000000000000UL)
          D(1, 0x0000000000000000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x00000000ffffffffUL)
          D(1, 0xffffffffffffffffUL)
          FPSCR 0x60000000u ]
        [ D(0, 0xffffffffffffffffUL)
          D(1, 0xffffffff00000000UL)
          FPSCR 0x00000000u ] ]
    check false "f3b905c4" inputs outputs

  /// <summary>
  /// A8.8.300 VCLS: vcls.s32 q0, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.300 VCLS``() =
    let inputs =
      [ [ D(0, 0x61518dd9d0bddc5dUL)
          D(1, 0x546dcf189b0f90fbUL)
          D(4, 0x8a5155387b6b587bUL)
          D(5, 0x784de809cf17fca2UL) ]
        [ D(0, 0x4d18d56390dd4a05UL)
          D(1, 0x7dcfaba365499c09UL)
          D(4, 0xc19e18e20aa1f286UL)
          D(5, 0xf1ee666648267de5UL) ]
        [ D(0, 0x0000000000000001UL)
          D(1, 0x8001800180018001UL)
          D(4, 0x8001800180018001UL)
          D(5, 0x0102030405060708UL) ] ]
    let outputs =
      [ [ D(0, 0x0000000000000000UL); D(1, 0x0000000000000001UL) ]
        [ D(0, 0x0000000100000003UL); D(1, 0x0000000300000000UL) ]
        [ D(0, 0x0000000000000000UL); D(1, 0x0000000600000004UL) ] ]
    check false "f3b80444" inputs outputs

  /// <summary>
  /// A8.8.301 VCLT: vclt.f32 q0, q2, #0x0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.301 VCLT``() =
    let inputs =
      [ [ D(0, 0x42c90000bec00000UL)
          D(1, 0xbf8000003fc00000UL)
          D(4, 0x3fe0000041400000UL)
          D(5, 0x3fe000003fc00000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x4000000040e80000UL)
          D(1, 0x404000003e000000UL)
          D(4, 0x4140000040000000UL)
          D(5, 0xbf0000003fc00000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0x000000007f800000UL)
          D(1, 0xff8000003f000000UL)
          D(4, 0xff8000007f800000UL)
          D(5, 0x3fc0000040400000UL)
          FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x0000000000000000UL)
          D(1, 0x0000000000000000UL)
          FPSCR 0x00000000u ]
        [ D(0, 0x0000000000000000UL)
          D(1, 0xffffffff00000000UL)
          FPSCR 0x60000000u ]
        [ D(0, 0xffffffff00000000UL)
          D(1, 0x0000000000000000UL)
          FPSCR 0x00000000u ] ]
    check false "f3b90644" inputs outputs

  /// <summary>
  /// A8.8.303 VCLZ: vclz.i32 q0, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.303 VCLZ``() =
    let inputs =
      [ [ D(0, 0x57c2e10c114fb5dbUL)
          D(1, 0x31f971a8d627aefcUL)
          D(4, 0x2c512e68aacf7a8eUL)
          D(5, 0x5f8da5338bbd9897UL) ]
        [ D(0, 0xef81da491f17bb65UL)
          D(1, 0x6b79a3ad3a412244UL)
          D(4, 0x786404bc6217c084UL)
          D(5, 0x667f7842800509c4UL) ]
        [ D(0, 0x7fffffffffffffffUL)
          D(1, 0x7fffffffffffffffUL)
          D(4, 0x0102030405060708UL)
          D(5, 0x8001800180018001UL) ] ]
    let outputs =
      [ [ D(0, 0x0000000200000000UL); D(1, 0x0000000100000000UL) ]
        [ D(0, 0x0000000100000001UL); D(1, 0x0000000100000000UL) ]
        [ D(0, 0x0000000700000005UL); D(1, 0x0000000000000000UL) ] ]
    check false "f3b804c4" inputs outputs
