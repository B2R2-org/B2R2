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

namespace B2R2.ABI.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.ABI

[<TestClass>]
type WindowsSyscallTests() =

  let x64 = ISA(Architecture.Intel, WordSize.Bit64)

  let x86 = ISA(Architecture.Intel, WordSize.Bit32)

  let ssn64 build sc = WindowsSyscall.toNumber build x64 sc

  let ssn86 build sc = WindowsSyscall.toNumber build x86 sc

  [<TestMethod>]
  member _.``Common x64 SSNs on Win10 2004 match j00ru's table``() =
    Assert.AreEqual<int>(
      0x55, ssn64 WindowsBuild.Win10_2004 WindowsSyscall.NtCreateFile
    )
    Assert.AreEqual<int>(
      0x0f, ssn64 WindowsBuild.Win10_2004 WindowsSyscall.NtClose
    )
    Assert.AreEqual<int>(
      0x06, ssn64 WindowsBuild.Win10_2004 WindowsSyscall.NtReadFile
    )

  [<TestMethod>]
  member _.``Common x64 SSNs on Win11 22H2 match j00ru's table``() =
    Assert.AreEqual<int>(
      0x55, ssn64 WindowsBuild.Win11_22H2 WindowsSyscall.NtCreateFile
    )
    Assert.AreEqual<int>(
      0x26, ssn64 WindowsBuild.Win11_22H2 WindowsSyscall.NtOpenProcess
    )

  [<TestMethod>]
  member _.``x86 SSNs differ from x64 and match j00ru's table``() =
    Assert.AreEqual<int>(
      0x0178, ssn86 WindowsBuild.Win10_2004 WindowsSyscall.NtCreateFile
    )
    Assert.AreEqual<int>(
      0x0019, ssn86 WindowsBuild.WinXP_SP1 WindowsSyscall.NtClose
    )

  [<TestMethod>]
  member _.``NtAcceptConnectPort SSN differs across builds``() =
    Assert.AreEqual<int>(
      0x60, ssn64 WindowsBuild.WinXP_SP1 WindowsSyscall.NtAcceptConnectPort
    )
    Assert.AreEqual<int>(
      0x02, ssn64 WindowsBuild.Win10_2004 WindowsSyscall.NtAcceptConnectPort
    )

  [<TestMethod>]
  member _.``Syscall absent on a build raises``() =
    Assert.ThrowsExactly<UnhandledSyscallException>(fun () ->
      ssn64 WindowsBuild.WinXP_SP1 WindowsSyscall.NtAcquireCrossVmMutant
      |> ignore)
    |> ignore

  [<TestMethod>]
  member _.``Win11 has no x86 table so x86 lookup raises``() =
    Assert.ThrowsExactly<UnhandledSyscallException>(fun () ->
      ssn86 WindowsBuild.Win11_22H2 WindowsSyscall.NtCreateFile |> ignore)
    |> ignore

  [<TestMethod>]
  member _.``ISA other than x86 or x64 raises``() =
    let arm = ISA Architecture.ARMv8
    let f = WindowsSyscall.NtCreateFile
    Assert.ThrowsExactly<UnhandledSyscallException>(fun () ->
      WindowsSyscall.toNumber WindowsBuild.Win10_2004 arm f |> ignore)
    |> ignore
