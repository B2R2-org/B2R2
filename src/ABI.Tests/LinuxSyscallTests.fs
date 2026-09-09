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
type LinuxSyscallTests() =

  let alpha = ISA Architecture.Alpha

  (* Alpha's numbering is Digital's rather than Linux's in its low range, so
     reading it through any other port's table mistakes one call for another:
     71 is mmap where i386 has it at 90, and 45 is open where i386 has 5. *)
  [<TestMethod>]
  member _.``Alpha numbers its early calls the OSF/1 way``() =
    Assert.AreEqual<int>(1, LinuxSyscall.toNumber alpha LinuxSyscall.Exit)
    Assert.AreEqual<int>(4, LinuxSyscall.toNumber alpha LinuxSyscall.Write)
    Assert.AreEqual<int>(45, LinuxSyscall.toNumber alpha LinuxSyscall.Open)
    Assert.AreEqual<int>(71, LinuxSyscall.toNumber alpha LinuxSyscall.Mmap)
    Assert.AreEqual<int>(33, LinuxSyscall.toNumber alpha LinuxSyscall.Access)

  (* The calls Linux added of its own begin at 300, and the OSF/1 forms were
     kept beside them: gettimeofday is osf_gettimeofday at 116 as well, and it
     is the modern number that a C library asks for. *)
  [<TestMethod>]
  member _.``Alpha names the modern form of a doubled call``() =
    let n = LinuxSyscall.toNumber alpha LinuxSyscall.Gettimeofday
    Assert.AreEqual<int>(359, n)
    Assert.AreEqual<int>(377,
                         LinuxSyscall.toNumber alpha LinuxSyscall.Getdents64)

  (* These two have no counterpart on any other port: they are how a program on
     Alpha reaches the floating-point control word. *)
  [<TestMethod>]
  member _.``Alpha keeps the two calls reaching its control word``() =
    let get = LinuxSyscall.toNumber alpha LinuxSyscall.OsfGetSysinfo
    let set = LinuxSyscall.toNumber alpha LinuxSyscall.OsfSetSysinfo
    Assert.AreEqual<int>(256, get)
    Assert.AreEqual<int>(257, set)

  [<TestMethod>]
  member _.``ofNumber inverts toNumber on Alpha``() =
    for syscall in [ LinuxSyscall.Exit
                     LinuxSyscall.Write
                     LinuxSyscall.Mmap
                     LinuxSyscall.Getdents64
                     LinuxSyscall.OsfSetSysinfo
                     LinuxSyscall.ClockGettime
                     LinuxSyscall.RtSigprocmask ] do
      let num = LinuxSyscall.toNumber alpha syscall
      Assert.AreEqual<LinuxSyscall>(syscall, LinuxSyscall.ofNumber alpha num)

  [<TestMethod>]
  member _.``toString and ofString round-trip``() =
    let name = LinuxSyscall.toString LinuxSyscall.OsfSetSysinfo
    Assert.AreEqual<string>("osf_setsysinfo", name)
    Assert.AreEqual<LinuxSyscall>(LinuxSyscall.OsfSetSysinfo,
                                  LinuxSyscall.ofString name)

// vim: set tw=80 sts=2 sw=2:
