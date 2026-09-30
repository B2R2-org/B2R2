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

[<TestClass>]
type WindowsBuildTests() =

  let x64 = ISA(Architecture.Intel, WordSize.Bit64)

  [<TestMethod>]
  member _.``A version names the build it belongs to``() =
    Assert.AreEqual<WindowsBuild option>(
      Some WindowsBuild.Win11_24H2, WindowsBuild.ofVersion 10 0 26100
    )
    Assert.AreEqual<WindowsBuild option>(
      Some WindowsBuild.Win10_2004, WindowsBuild.ofVersion 10 0 19041
    )

  (* The numbers a real 24H2 ntdll carries, read out of its own stubs. They
     are what ties this mapping to a machine rather than to a table. *)
  [<TestMethod>]
  member _.``The build a 24H2 version names numbers calls as 24H2 does``() =
    match WindowsBuild.ofVersion 10 0 26100 with
    | None ->
      Assert.Fail "10.0.26100 names a build"
    | Some build ->
      let ssn sc = WindowsSyscall.toNumber build x64 sc
      Assert.AreEqual<int>(0x06, ssn WindowsSyscall.NtReadFile)
      Assert.AreEqual<int>(0x0f, ssn WindowsSyscall.NtClose)
      Assert.AreEqual<int>(0x55, ssn WindowsSyscall.NtCreateFile)
      Assert.AreEqual<int>(0xd1, ssn WindowsSyscall.NtCreateUserProcess)

  (* Before Windows 10 a build number names several releases that disagree
     about system-call numbers -- NT 4.0 is 1381 under all six of its service
     packs -- so there is no answer to give. *)
  [<TestMethod>]
  member _.``A version older than Windows 10 names no build``() =
    Assert.AreEqual<WindowsBuild option>(None, WindowsBuild.ofVersion 4 0 1381)
    Assert.AreEqual<WindowsBuild option>(None, WindowsBuild.ofVersion 6 1 7601)
    Assert.AreEqual<WindowsBuild option>(None, WindowsBuild.ofVersion 10 0 1)

  (* A build this names has to be one the tables know, or the mapping sends a
     caller somewhere there is nothing to read. *)
  [<TestMethod>]
  member _.``Every build a version names has a table``() =
    for b in 10000 .. 27000 do
      match WindowsBuild.ofVersion 10 0 b with
      | None ->
        ()
      | Some build ->
        WindowsSyscall.toNumber build x64 WindowsSyscall.NtClose |> ignore

