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

namespace B2R2.MiddleEnd.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.ControlFlowAnalysis.Strategies
open B2R2.MiddleEnd.ControlFlowGraph

/// Tests the recovery of 32-bit ARM binaries, whose functions each start in
/// one of two instruction sets.
[<TestClass>]
type ARMBinaryBrewTests() =
  /// GCC links the Thumb start-up code of glibc in front of a program it
  /// builds in ARM, so this binary holds functions of both instruction sets.
  static let mixedFunctions =
    let hdl = BinHandle.LoadFileBytes(readZippedBinary "elf_arm32", ISA "armv7")
    BinaryBrew(hdl).Functions

  /// Recovers the functions of the binary as if it were stripped: the
  /// identification for ARM knows only the entry point up front and finds the
  /// rest in what the recovery builds.
  static let recoverStripped (hdl: BinHandle) =
    let arm32 =
      ARM32FunctionIdentification(hdl, ExceptionInfo hdl)
      :> IIncrementalFunctionIdentifiable
    let identification =
      { new IIncrementalFunctionIdentifiable with
          member _.Identify() = [| Option.get hdl.File.EntryPoint |]
          member _.IdentifyMore recovered = arm32.IdentifyMore recovered }
    BinaryBrew(hdl, identification, CFGRecovery()).Functions

  /// Returns which instruction sets the instructions of the function are in,
  /// telling Thumb by true.
  static let instructionSetsOf (fn: Function) =
    fn.CFG.Vertices
    |> Array.filter (fun v -> not v.VData.Internals.IsAbstract)
    |> Array.collect (fun v -> v.VData.Internals.Instructions)
    |> Array.map (fun ins -> (ins :?> ARM32.Instruction).IsThumb)
    |> Array.distinct

  [<TestMethod>]
  member _.``An ARM function is read in ARM``() =
    let main = mixedFunctions[0x10330UL]
    CollectionAssert.AreEqual([| false |], instructionSetsOf main)

  (* The file says _start is in Thumb by setting the lowest bit of the address
     it gives, while the function itself starts at the even address below. *)
  [<TestMethod>]
  member _.``A Thumb function is read in Thumb at its even address``() =
    let start = mixedFunctions[0x10354UL]
    CollectionAssert.AreEqual([| true |], instructionSetsOf start)

  (* The symbol of a Thumb function sets the lowest bit of its value, while the
     function starts at the even address below, where $t marks the encoding
     and names nothing. *)
  [<TestMethod>]
  member _.``A Thumb function takes the name of its symbol``() =
    Assert.AreEqual<string>("_start", mixedFunctions[0x10354UL].Name)

  (* A BLX with an immediate always switches instruction sets, so the function
     it calls starts in the other one: here an ARM function calls a Thumb one
     that only returns. *)
  [<TestMethod>]
  member _.``A BLX makes its callee start in the other instruction set``() =
    let code =
      [ "10402de9" (* push {r4, lr} *)
        "010000fa" (* blx 0x10 *)
        "1080bde8" (* pop {r4, pc} *)
        "00f020e3" (* nop *)
        "7047" (* bx lr, in Thumb *) ]
      |> String.concat ""
      |> ByteArray.ofHexString
    let fns = BinaryBrew(BinHandle.LoadRawImage(code, ISA "armv7")).Functions
    CollectionAssert.AreEqual([| false |], instructionSetsOf fns[0x0UL])
    CollectionAssert.AreEqual([| true |], instructionSetsOf fns[0x10UL])

  (* A BLX through a register goes to the instruction set that the lowest bit
     of the register names, so it ends in a call for each of the two. Both are
     the one call, which returns to the instruction after the BLX. *)
  [<TestMethod>]
  member _.``Both ways of a BLX through a register make one call``() =
    let code =
      [ "10402de9" (* push {r4, lr} *)
        "33ff2fe1" (* blx r3 *)
        "1080bde8" (* pop {r4, pc} *) ]
      |> String.concat ""
      |> ByteArray.ofHexString
    let fns = BinaryBrew(BinHandle.LoadRawImage(code, ISA "armv7")).Functions
    let cfg = fns[0x0UL].CFG
    let callee = cfg.FindVertexBy(fun v -> v.VData.Internals.IsAbstract)
    let addrOfCall (v: IVertex<LowUIRBasicBlock>) =
      v.VData.Internals.LastInstruction.Address
    let addrOfBlock (v: IVertex<LowUIRBasicBlock>) =
      v.VData.Internals.BlockAddress
    let callers = cfg.GetPreds callee |> Array.map addrOfCall
    let returns = cfg.GetSuccs callee |> Array.map addrOfBlock
    CollectionAssert.AreEqual([| 0x4UL; 0x4UL |], callers)
    CollectionAssert.AreEqual([| 0x8UL |], returns)

  (* An ADD to the PC in ARM may switch to Thumb by the lowest bit of the sum,
     so it ends in a jump for each instruction set. A switch only ever jumps
     within its function, which stays in ARM, and the jump that does is the
     one to read the table from. Clang lays the table of offsets right after
     the jump. A raw image has no sections to tell where a table may lie, but
     one whose first target falls before the next function holds labels of
     its own function, so the function calls another one placed after it. *)
  [<TestMethod>]
  member _.``A jump table is read through the jump that stays in ARM``() =
    let code =
      [ "0c0000eb" (* bl 0x38 *)
        "030050e3" (* cmp r0, #3 *)
        "0800008a" (* bhi 0x30 *)
        "04108fe2" (* add r1, pc, #4 *)
        "000191e7" (* ldr r0, [r1, r0, lsl #2] *)
        "00f081e0" (* add pc, r1, r0 *)
        "10000000" (* .word 0x10 *)
        "14000000" (* .word 0x14 *)
        "18000000" (* .word 0x18 *)
        "1c000000" (* .word 0x1c *)
        "0000a0e3" (* mov r0, #0 *)
        "0100a0e3" (* mov r0, #1 *)
        "0200a0e3" (* mov r0, #2 *)
        "1eff2fe1" (* bx lr *)
        "1eff2fe1" (* bx lr *) ]
      |> String.concat ""
      |> ByteArray.ofHexString
    let fns = BinaryBrew(BinHandle.LoadRawImage(code, ISA "armv7")).Functions
    let cfg = fns[0x0UL].CFG
    let targets =
      cfg.Edges
      |> Array.filter (fun e -> e.Label = IndirectJmpEdge)
      |> Array.map (fun e -> e.Second.VData.Internals.BlockAddress)
      |> Array.sort
    CollectionAssert.AreEqual([| 0x28UL; 0x2cUL; 0x30UL; 0x34UL |], targets)

  (* Only a pointer leads to the second function, so the identification finds
     it in what the recovery has built rather than up front. It keeps naming
     the function once it is built, which must not keep the recovery going. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A function found in what the recovery built is recovered``() =
    let code =
      [ "0000a0e3" (* mov r0, #0 *)
        "1eff2fe1" (* bx lr *)
        "0100a0e3" (* mov r0, #1 *)
        "1eff2fe1" (* bx lr *) ]
      |> String.concat ""
      |> ByteArray.ofHexString
    let hdl = BinHandle.LoadRawImage(code, ISA "armv7")
    let identification =
      { new IIncrementalFunctionIdentifiable with
          member _.Identify() = [| 0x0UL |]
          member _.IdentifyMore _ = [| 0x8UL |] }
    let fns = BinaryBrew(hdl, identification, CFGRecovery()).Functions
    CollectionAssert.AreEqual([| 0x0UL; 0x8UL |], Seq.toArray fns.Addresses)

  (* The identification gives a Thumb function by its odd address, as the
     binary does, also when it finds the function after the recovery. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A Thumb function found after the recovery starts in Thumb``() =
    let hdl = BinHandle.LoadFileBytes(readZippedBinary "elf_arm32", ISA "armv7")
    let identification =
      { new IIncrementalFunctionIdentifiable with
          member _.Identify() = [| 0x10330UL |]
          member _.IdentifyMore _ = [| 0x10355UL |] }
    let fns = BinaryBrew(hdl, identification, CFGRecovery()).Functions
    CollectionAssert.AreEqual([| true |], instructionSetsOf fns[0x10354UL])

  (* Only the pointer that the call loads leads to the function at 0x14, and
     the call proves that a function starts there. *)
  [<TestMethod>]
  member _.``An indirect call proves its constant target a function``() =
    let code =
      [ "10402de9" (* push {r4, lr} *)
        "04309fe5" (* ldr r3, [pc, #4] *)
        "33ff2fe1" (* blx r3 *)
        "1080bde8" (* pop {r4, pc} *)
        "14000000" (* .word 0x14 *)
        "0100a0e3" (* mov r0, #1 *)
        "1eff2fe1" (* bx lr *) ]
      |> String.concat ""
      |> ByteArray.ofHexString
    let fns = BinaryBrew(BinHandle.LoadRawImage(code, ISA "armv7")).Functions
    CollectionAssert.AreEqual([| 0x0UL; 0x14UL |], Seq.toArray fns.Addresses)

  (* A call through the link register writes the return address there as it
     jumps, so what the call proves is what the register held before, not the
     address after the call. *)
  [<TestMethod>]
  member _.``A call through LR proves what LR held before the call``() =
    let code =
      [ "10402de9" (* push {r4, lr} *)
        "04e09fe5" (* ldr lr, [pc, #4] *)
        "3eff2fe1" (* blx lr *)
        "1080bde8" (* pop {r4, pc} *)
        "14000000" (* .word 0x14 *)
        "0100a0e3" (* mov r0, #1 *)
        "1eff2fe1" (* bx lr *) ]
      |> String.concat ""
      |> ByteArray.ofHexString
    let fns = BinaryBrew(BinHandle.LoadRawImage(code, ISA "armv7")).Functions
    CollectionAssert.AreEqual([| 0x0UL; 0x14UL |], Seq.toArray fns.Addresses)

  (* GNU C lets a program take the address of a label, which this code stores
     but never calls, so nothing proves that a function starts at 0xc. *)
  [<TestMethod>]
  member _.``A code address stored but never called proves nothing``() =
    let code =
      [ "04308fe2" (* add r3, pc, #4 *)
        "003080e5" (* str r3, [r0] *)
        "1eff2fe1" (* bx lr *)
        "0100a0e3" (* mov r0, #1 *)
        "1eff2fe1" (* bx lr *) ]
      |> String.concat ""
      |> ByteArray.ofHexString
    let fns = BinaryBrew(BinHandle.LoadRawImage(code, ISA "armv7")).Functions
    CollectionAssert.AreEqual([| 0x0UL |], Seq.toArray fns.Addresses)

  (* _start passes main to __libc_start_main, which calls it, while only a GOT
     slot refers to main otherwise. *)
  [<TestMethod>]
  member _.``__libc_start_main proves main a function``() =
    let hdl = BinHandle.LoadFileBytes(readZippedBinary "elf_arm32", ISA "armv7")
    let onlyStart =
      { new IFunctionIdentifiable with
          member _.Identify() = [| 0x10355UL |] }
    let recovered =
      BinaryBrew(hdl, onlyStart, CFGRecovery()).Functions.Sequence
      |> Seq.toArray
    let identification =
      ARM32FunctionIdentification(hdl, ExceptionInfo hdl)
      :> IIncrementalFunctionIdentifiable
    let found = identification.IdentifyMore recovered
    CollectionAssert.Contains(found, 0x10330UL)

  (* GNU ld starts the ARM PLT entry of qsort with a Thumb stub, which
     sort_tail tail-calls, and main calls 0x48c past the stub with a blx. The
     call is to the import all the same, not to a function at 0x48c. *)
  [<TestMethod>]
  member _.``A call past a Thumb PLT stub calls the import``() =
    let bytes = readZippedBinary "elf_thumb_pltstub"
    let fns = BinaryBrew(BinHandle.LoadFileBytes(bytes, ISA "armv7")).Functions
    CollectionAssert.DoesNotContain(Seq.toArray fns.Addresses, 0x48cUL)
    let callee = fns[0x4a4UL].Callees[LeafCallSite 0x4ccUL]
    Assert.AreEqual<CalleeKind>(RegularCallee 0x488UL, callee)

  (* main passes cmp to qsort by the call that skips the stub, which proves
     cmp a function as much as a call to the stub would. *)
  [<TestMethod>]
  member _.``A call past a Thumb PLT stub proves its callback``() =
    let bytes = readZippedBinary "elf_thumb_pltstub"
    let hdl = BinHandle.LoadFileBytes(bytes, ISA "armv7")
    let onlyMain =
      { new IFunctionIdentifiable with
          member _.Identify() = [| 0x4a5UL |] }
    let recovered =
      BinaryBrew(hdl, onlyMain, CFGRecovery()).Functions.Sequence
      |> Seq.toArray
    let identification =
      ARM32FunctionIdentification(hdl, ExceptionInfo hdl)
      :> IIncrementalFunctionIdentifiable
    CollectionAssert.Contains(identification.IdentifyMore recovered, 0x609UL)

  (* Only .fini_array leads to __do_global_dtors_aux, by a pointer that the
     loader relocates, and the function saves the link register first. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A relocated pointer to code saving registers is a function``() =
    let bytes = readZippedBinary "elf_arm32_exidx"
    let fns = recoverStripped (BinHandle.LoadFileBytes(bytes, ISA "armv7"))
    CollectionAssert.Contains(Seq.toArray fns.Addresses, 0x6ccUL)

  (* frame_dummy only jumps to register_tm_clones, saving nothing, but it lies
     right below the literal pool of __do_global_dtors_aux, which a function
     ends with and a label does not. The pool is known once the recovery has
     built that function. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A relocated pointer to code below a literal is a function``() =
    let bytes = readZippedBinary "elf_arm32_exidx"
    let fns = recoverStripped (BinHandle.LoadFileBytes(bytes, ISA "armv7"))
    CollectionAssert.Contains(Seq.toArray fns.Addresses, 0x70cUL)

  (* A binary that the loader leaves where it is linked relocates nothing, and
     .fini_array holds the address of __do_global_dtors_aux as it is. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A pointer that fixed-base data holds can name a function``() =
    let bytes = readZippedBinary "elf_arm32"
    let fns = recoverStripped (BinHandle.LoadFileBytes(bytes, ISA "armv7"))
    CollectionAssert.Contains(Seq.toArray fns.Addresses, 0x103fcUL)

  (* With .fini_array pointing at 0x685 instead, the pointer names the bx lr
     that follows a bx r3 in deregister_tm_clones, as Clang lays out a label
     that returns right after the dispatch of the one above it. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A pointer to code right after a dispatch is no function``() =
    let bytes = readZippedBinary "elf_arm32_exidx"
    System.BitConverter.GetBytes(0x685u).CopyTo(bytes, 0xea4)
    let fns = recoverStripped (BinHandle.LoadFileBytes(bytes, ISA "armv7"))
    CollectionAssert.DoesNotContain(Seq.toArray fns.Addresses, 0x684UL)

  (* Until the loader binds an import, its GOT slot holds the address of the
     code that binds it, which starts the PLT and is no function: the slots of
     this binary that hold 0x102ec. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``The code that binds imports is no function``() =
    let bytes = readZippedBinary "elf_arm32"
    let fns = recoverStripped (BinHandle.LoadFileBytes(bytes, ISA "armv7"))
    CollectionAssert.DoesNotContain(Seq.toArray fns.Addresses, 0x102ecUL)

  (* With .fini_array cleared, only .rodata holds the address of
     __do_global_dtors_aux, among small numbers rather than other addresses, as
     a number that happens to look like a code address sits. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A lone code address among fixed-base numbers is no pointer``() =
    let bytes = readZippedBinary "elf_arm32"
    System.BitConverter.GetBytes(0u).CopyTo(bytes, 0xf14)
    System.BitConverter.GetBytes(0x103fdu).CopyTo(bytes, 0x4b0)
    let fns = recoverStripped (BinHandle.LoadFileBytes(bytes, ISA "armv7"))
    CollectionAssert.DoesNotContain(Seq.toArray fns.Addresses, 0x103fcUL)

  (* The address of __do_global_dtors_aux sits next to that of a string this
     time, as a structure holds a function with its name. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A code address next to another address is a pointer``() =
    let bytes = readZippedBinary "elf_arm32"
    System.BitConverter.GetBytes(0u).CopyTo(bytes, 0xf14)
    System.BitConverter.GetBytes(0x103fdu).CopyTo(bytes, 0x4b0)
    System.BitConverter.GetBytes(0x104bcu).CopyTo(bytes, 0x4b4)
    let fns = recoverStripped (BinHandle.LoadFileBytes(bytes, ISA "armv7"))
    CollectionAssert.Contains(Seq.toArray fns.Addresses, 0x103fcUL)
