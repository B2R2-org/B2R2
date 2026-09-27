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
type MachTrapTests() =

  let x64 = ISA(Architecture.Intel, WordSize.Bit64)

  let arm64 = ISA(Architecture.ARMv8, WordSize.Bit64)

  let all =
    System.Enum.GetValues typeof<MachTrap> :?> MachTrap[]

  [<TestMethod>]
  member _.``trap numbers match the XNU table``() =
    let n t = -(MachTrap.toNumber arm64 t)
    Assert.AreEqual<int>(26, n MachTrap.MachReplyPort)
    Assert.AreEqual<int>(27, n MachTrap.ThreadSelfTrap)
    Assert.AreEqual<int>(28, n MachTrap.TaskSelfTrap)
    Assert.AreEqual<int>(29, n MachTrap.HostSelfTrap)
    Assert.AreEqual<int>(31, n MachTrap.MachMsgTrap)
    Assert.AreEqual<int>(10, n MachTrap.KernelrpcMachVmAllocateTrap)
    Assert.AreEqual<int>(96, n MachTrap.DebugControlPortForPid)

  [<TestMethod>]
  member _.``x86_64 encodes the Mach syscall class in the high bits``() =
    Assert.AreEqual<int>(0x100001c, MachTrap.toNumber x64 MachTrap.TaskSelfTrap)

  (* arm64 has no class byte: it tells a Mach trap from a BSD call by the
     number being negative. *)
  [<TestMethod>]
  member _.``arm64 passes the trap number negated``() =
    Assert.AreEqual<int>(-28, MachTrap.toNumber arm64 MachTrap.TaskSelfTrap)

  [<TestMethod>]
  member _.``ofNumber inverts toNumber for every trap on both ISAs``() =
    for t in all do
      let onX64 = MachTrap.ofNumber x64 (MachTrap.toNumber x64 t)
      let onArm = MachTrap.ofNumber arm64 (MachTrap.toNumber arm64 t)
      Assert.AreEqual<MachTrap>(t, onX64)
      Assert.AreEqual<MachTrap>(t, onArm)

  [<TestMethod>]
  member _.``every trap has a name``() =
    for t in all do
      Assert.AreNotEqual<string>("", MachTrap.toString t)

  [<TestMethod>]
  member _.``toString gives the kernel's own spelling``() =
    Assert.AreEqual<string>(
      "task_self_trap", MachTrap.toString MachTrap.TaskSelfTrap
    )
    Assert.AreEqual<string>(
      "_kernelrpc_mach_vm_allocate_trap",
      MachTrap.toString MachTrap.KernelrpcMachVmAllocateTrap
    )

  (* The two classes are separate namespaces, which is the whole reason a
     Darwin dispatcher has to split the class off before it looks anything
     up: trap 28 is task_self_trap, while BSD call 28 is something else. *)
  [<TestMethod>]
  member _.``a trap number and a BSD number of the same value differ``() =
    let trap = MachTrap.toNumber x64 MachTrap.TaskSelfTrap
    let bsd = MacosSyscall.toNumber x64 (MacosSyscall.ofNumber x64 0x200001c)
    Assert.AreNotEqual<int>(trap, bsd)
    Assert.AreEqual<int>(0x100001c, trap)
    Assert.AreEqual<int>(0x200001c, bsd)

  [<TestMethod>]
  member _.``an unsupported ISA raises UnhandledSyscallException``() =
    let x86 = ISA(Architecture.Intel, WordSize.Bit32)
    Assert.ThrowsExactly<UnhandledSyscallException>(fun () ->
      MachTrap.toNumber x86 MachTrap.TaskSelfTrap |> ignore)
    |> ignore
