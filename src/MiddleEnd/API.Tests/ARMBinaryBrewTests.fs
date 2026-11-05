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
open B2R2.ABI
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

  /// Returns where the indirect jumps of the function go, in order.
  static let indirectJumpTargetsOf (fn: Function) =
    fn.CFG.Edges
    |> Array.filter (fun e -> e.Label = IndirectJmpEdge)
    |> Array.map (fun e -> e.Second.VData.Internals.BlockAddress)
    |> Array.sort

  /// Returns how many entries each jump table of main has, once main becomes
  /// the given code and .rodata starts with the given bytes.
  static let countEntriesInPatchedMain code rodata =
    let bytes = readZippedBinary "elf_arm32"
    let patch (offset: int) (hex: string) =
      (ByteArray.ofHexString hex).CopyTo(bytes, offset)
    patch 0x330 (String.concat "" code)
    patch 0x428 rodata
    let hdl = BinHandle.LoadFileBytes(bytes, ISA "armv7")
    BinaryBrew(hdl).Functions[0x10330UL].JumpTables
    |> Array.map _.NumEntries

  /// Recovers the functions of the given code of 32-bit ARM, which starts at
  /// address zero with the entry of the binary.
  static let recoverCode (code: string list) =
    let bytes = code |> String.concat "" |> ByteArray.ofHexString
    BinaryBrew(BinHandle.LoadRawImage(bytes, ISA "armv7")).Functions

  /// Returns the kinds of the edges that leave the block of the function that
  /// ends at the given address.
  static let edgeKindsFrom (fn: Function) insAddr =
    let v =
      fn.CFG.FindVertexBy(fun v ->
        not v.VData.Internals.IsAbstract
        && v.VData.Internals.LastInstruction.Address = insAddr)
    fn.CFG.GetSuccEdges v |> Array.map _.Label

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

  (* libbfd calls the fatal callback of the linker through a pointer, and GCC
     lays the literal pool that the code reads the message from right after
     the call, as the callback never returns. A compiler puts no pool where
     control comes, so the call does not return to the word it loads. *)
  [<TestMethod>]
  member _.``A BLX right before a literal it loads never returns``() =
    let code =
      [ "10402de9" (* push {r4, lr} *)
        "00009fe5" (* ldr r0, [pc, #0] *)
        "33ff2fe1" (* blx r3 *)
        "98890500" (* .word 0x58998, a muleq to decode *)
        "0100a0e3" (* mov r0, #1 *)
        "1eff2fe1" (* bx lr *) ]
      |> String.concat ""
      |> ByteArray.ofHexString
    let fns = BinaryBrew(BinHandle.LoadRawImage(code, ISA "armv7")).Functions
    let cfg = fns[0x0UL].CFG
    let callee = cfg.FindVertexBy(fun v -> v.VData.Internals.IsAbstract)
    CollectionAssert.AreEqual([||], cfg.GetSuccs callee)

  (* Clang keeps one pool for a whole function, so the literal right after a
     call may be one that another block loads, which the recovery may build
     only after it has connected the call. *)
  [<TestMethod>]
  member _.``A BLX right before a literal loaded elsewhere never returns``() =
    let code =
      [ "10402de9" (* push {r4, lr} *)
        "000050e3" (* cmp r0, #0 *)
        "0100000a" (* beq 0x14 *)
        "0c009fe5" (* ldr r0, [pc, #12] *)
        "1080bde8" (* pop {r4, pc} *)
        "08009fe5" (* ldr r0, [pc, #8] *)
        "003091e5" (* ldr r3, [r1] *)
        "33ff2fe1" (* blx r3 *)
        "98890500" (* .word 0x58998, loaded at 0xc *)
        "34120000" (* .word 0x1234, loaded at 0x14 *)
        "0100a0e3" (* mov r0, #1 *)
        "1eff2fe1" (* bx lr *) ]
      |> String.concat ""
      |> ByteArray.ofHexString
    let fns = BinaryBrew(BinHandle.LoadRawImage(code, ISA "armv7")).Functions
    let cfg = fns[0x0UL].CFG
    let callee = cfg.FindVertexBy(fun v -> v.VData.Internals.IsAbstract)
    CollectionAssert.AreEqual([||], cfg.GetSuccs callee)

  (* The error of gnulib returns only when its status is zero, and exits
     otherwise. ARM pops the PC on that condition within the instruction
     rather than branching around the pop, and compares the status with zero
     by adding the complement of zero and one. *)
  [<TestMethod>]
  member _.``A pop of the PC on a zero argument returns conditionally``() =
    let code =
      [ "10402de9" (* push {r4, lr} *)
        "0040a0e1" (* mov r4, r0 *)
        "000054e3" (* cmp r4, #0 *)
        "1080bd08" (* popeq {r4, pc} *)
        "000000eb" (* bl 0x18 *)
        "00000000" (* .word 0, which no path reaches *)
        "feffffea" (* b 0x18 *) ]
      |> String.concat ""
      |> ByteArray.ofHexString
    let fns = BinaryBrew(BinHandle.LoadRawImage(code, ISA "armv7")).Functions
    let r0 = ARM32.Register.toRegID ARM32.Register.R0
    let expected = ConditionalNoRet(ArgLocation.Reg r0)
    Assert.AreEqual<NonReturningStatus>(expected, fns[0x0UL].NoRet)

  (* f jumps to x before anything tells that x is a function, so its building
     follows the jump within f. Only once f returns does main call g, which
     calls x and so makes it a function, after which f is built again to call
     x as its tail rather than keep a copy of it. *)
  [<TestMethod>]
  member _.``A jump to code that a later call proves calls it as a tail``() =
    let fns =
      recoverCode
        [ "10402de9" (* main: push {r4, lr} *)
          "010000eb" (* bl f *)
          "020000eb" (* bl g *)
          "1080bde8" (* pop {r4, pc} *)
          "0100a0e3" (* f: mov r0, #1 *)
          "020000ea" (* b x *)
          "10402de9" (* g: push {r4, lr} *)
          "000000eb" (* bl x *)
          "1080bde8" (* pop {r4, pc} *)
          "010080e2" (* x: add r0, r0, #1 *)
          "1eff2fe1" (* bx lr *) ]
    let kinds = edgeKindsFrom fns[0x10UL] 0x14UL
    CollectionAssert.AreEqual([| TailCallEdge |], kinds)

  (* Only f calls x, by jumping to it as its tail. x lies below the entry of
     f, and code of 32-bit ARM keeps each function in one piece, so the jump
     leaves f for another function, which x shows starting by saving the
     registers that its caller keeps. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A jump below its function proves the function it enters``() =
    let fns =
      recoverCode
        [ "10402de9" (* main: push {r4, lr} *)
          "030000eb" (* bl f *)
          "1080bde8" (* pop {r4, pc} *)
          "10402de9" (* x: push {r4, lr} *)
          "0200a0e3" (* mov r0, #2 *)
          "1080bde8" (* pop {r4, pc} *)
          "0100a0e3" (* f: mov r0, #1 *)
          "faffffea" (* b x *) ]
    let entries = Seq.toArray fns.Addresses
    let kinds = edgeKindsFrom fns[0x18UL] 0x1cUL
    CollectionAssert.AreEqual([| 0x0UL; 0xcUL; 0x18UL |], entries)
    CollectionAssert.AreEqual([| TailCallEdge |], kinds)

  (* The recovery reads a literal pool as code when the call before it is taken
     to return, as a Thumb call of error may be, and a literal may then decode
     as a jump out of its function. f runs into the literal that it loads, a
     word that reads as a jump to x. A literal that code loads is data, so the
     jump proves nothing, however x starts. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A jump that decodes from a loaded literal proves nothing``() =
    let fns =
      recoverCode
        [ "10402de9" (* main: push {r4, lr} *)
          "030000eb" (* bl f *)
          "1080bde8" (* pop {r4, pc} *)
          "10402de9" (* x: push {r4, lr} *)
          "0200a0e3" (* mov r0, #2 *)
          "1080bde8" (* pop {r4, pc} *)
          "00109fe5" (* f: ldr r1, [pc, #0] *)
          "0100a0e3" (* mov r0, #1 *)
          "f9ffffea" (* .word 0xeafffff9, loaded at 0x18, as b x *) ]
    let entries = Seq.toArray fns.Addresses
    CollectionAssert.AreEqual([| 0x0UL; 0x18UL |], entries)

  (* Only code that the recovery never builds loads the words at x, yet they
     are literals all the same, as in a pool amid a large switch whose cases
     the recovery has yet to reach, which jump back to where the cases meet.
     A literal is data whatever it decodes as, so the jump to it proves
     nothing, though the words read as a push and a pop. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A jump to a literal that unbuilt code loads proves nothing``() =
    let fns =
      recoverCode
        [ "10402de9" (* main: push {r4, lr} *)
          "050000eb" (* bl f *)
          "1080bde8" (* pop {r4, pc} *)
          "04009fe5" (* ldr r0, [pc, #4], which nothing reaches *)
          "04109fe5" (* ldr r1, [pc, #4] *)
          "fbffffea" (* b 0x8 *)
          "10402de9" (* x: .word 0xe92d4010, loaded at 0xc *)
          "1080bde8" (* .word 0xe8bd8010, loaded at 0x10 *)
          "0100a0e3" (* f: mov r0, #1 *)
          "fbffffea" (* b x *) ]
    let entries = Seq.toArray fns.Addresses
    CollectionAssert.AreEqual([| 0x0UL; 0x20UL |], entries)

  (* The floating-point code of libgcc jumps from one function into the middle
     of another, as __floatsidf does into __adddf3, which nothing may call. The
     code above the target falls through to it without saving any register on
     the way, so the target starts no function, while g, which returns right
     past main, does. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A jump into the middle of code proves nothing``() =
    let fns =
      recoverCode
        [ "10402de9" (* main: push {r4, lr} *)
          "030000eb" (* bl f *)
          "1080bde8" (* pop {r4, pc} *)
          "010080e0" (* g: add r0, r0, r1 *)
          "010080e2" (* l: add r0, r0, #1 *)
          "1eff2fe1" (* bx lr *)
          "0100a0e3" (* f: mov r0, #1 *)
          "fbffffea" (* b l *) ]
    let entries = Seq.toArray fns.Addresses
    let kinds = edgeKindsFrom fns[0x18UL] 0x1cUL
    CollectionAssert.AreEqual([| 0x0UL; 0xcUL; 0x18UL |], entries)
    CollectionAssert.AreEqual([| InterJmpEdge |], kinds)

  (* A Cortex-A8 erratum makes GNU ld redirect a branch of Thumb code across
     a page to a veneer past the code, which branches back into the function.
     The jump to v leaves f past the next function, g, and v lies right below
     a literal that g loads, the way a function may start; yet v only
     branches on, and so starts no function. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A jump to a veneer that only branches on proves nothing``() =
    let fns =
      recoverCode
        [ "10402de9" (* main: push {r4, lr} *)
          "010000eb" (* bl f *)
          "040000eb" (* bl g *)
          "1080bde8" (* pop {r4, pc} *)
          "000050e3" (* f: cmp r0, #0 *)
          "040000ea" (* b v *)
          "0100a0e3" (* mov r0, #1 *)
          "1eff2fe1" (* bx lr *)
          "00009fe5" (* g: ldr r0, [pc, #0] *)
          "1eff2fe1" (* bx lr *)
          "34120000" (* .word 0x1234 *)
          "f9ffffea" (* v: b 0x18 *) ]
    let entries = Seq.toArray fns.Addresses
    CollectionAssert.AreEqual([| 0x0UL; 0x10UL; 0x20UL |], entries)

  (* Nothing calls g or takes its address, as with dead code that a linker
     keeps. Code of 32-bit ARM keeps each function in one piece, followed by
     the literals that it loads, so g follows the literal of f, and it saves
     the registers that its caller keeps first thing, as no code in the middle
     of a function does. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A function past the literals of another one is found``() =
    let fns =
      recoverCode
        [ "10402de9" (* main: push {r4, lr} *)
          "000000eb" (* bl f *)
          "1080bde8" (* pop {r4, pc} *)
          "00009fe5" (* f: ldr r0, [pc, #0] *)
          "1eff2fe1" (* bx lr *)
          "34120000" (* .word 0x1234 *)
          "10402de9" (* g: push {r4, lr} *)
          "0200a0e3" (* mov r0, #2 *)
          "1080bde8" (* pop {r4, pc} *) ]
    let entries = Seq.toArray fns.Addresses
    CollectionAssert.AreEqual([| 0x0UL; 0xcUL; 0x18UL |], entries)

  (* g tests its argument before it saves the registers that its caller keeps,
     returning at once on zero, as a compiler lays out a function that needs
     its frame only on some paths. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A function that saves registers after a test is found``() =
    let fns =
      recoverCode
        [ "10402de9" (* main: push {r4, lr} *)
          "000000eb" (* bl f *)
          "1080bde8" (* pop {r4, pc} *)
          "0100a0e3" (* f: mov r0, #1 *)
          "1eff2fe1" (* bx lr *)
          "000050e3" (* g: cmp r0, #0 *)
          "1eff2f01" (* bxeq lr *)
          "10402de9" (* push {r4, lr} *)
          "0200a0e3" (* mov r0, #2 *)
          "1080bde8" (* pop {r4, pc} *) ]
    let entries = Seq.toArray fns.Addresses
    CollectionAssert.AreEqual([| 0x0UL; 0xcUL; 0x14UL |], entries)

  (* g saves no register, as a function that calls none need not. f ends in a
     return, and the recovery knows where every jump of f goes, so no code of
     f lies past it, and g returns before anything else. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A function that returns past a whole function is found``() =
    let fns =
      recoverCode
        [ "10402de9" (* main: push {r4, lr} *)
          "000000eb" (* bl f *)
          "1080bde8" (* pop {r4, pc} *)
          "0100a0e3" (* f: mov r0, #1 *)
          "1eff2fe1" (* bx lr *)
          "010080e2" (* g: add r0, r0, #1 *)
          "1eff2fe1" (* bx lr *) ]
    let entries = Seq.toArray fns.Addresses
    CollectionAssert.AreEqual([| 0x0UL; 0xcUL; 0x14UL |], entries)

  (* g only sets an argument and jumps to f as its tail, saving nothing, the
     way a wrapper does. It follows the literal of f. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A function that calls its tail past literals is found``() =
    let fns =
      recoverCode
        [ "10402de9" (* main: push {r4, lr} *)
          "000000eb" (* bl f *)
          "1080bde8" (* pop {r4, pc} *)
          "00009fe5" (* f: ldr r0, [pc, #0] *)
          "1eff2fe1" (* bx lr *)
          "34120000" (* .word 0x1234 *)
          "0010a0e3" (* g: mov r1, #0 *)
          "faffffea" (* b f *) ]
    let entries = Seq.toArray fns.Addresses
    CollectionAssert.AreEqual([| 0x0UL; 0xcUL; 0x18UL |], entries)

  (* f jumps through a register that the recovery cannot follow, as Clang
     does for a computed goto with a BX, so the code past its literal may be a
     label of f, which saves no register and returns like a function does. It
     starts none. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``Code past a function with an unknown jump starts none``() =
    let fns =
      recoverCode
        [ "10402de9" (* main: push {r4, lr} *)
          "000000eb" (* bl f *)
          "1080bde8" (* pop {r4, pc} *)
          "00109fe5" (* f: ldr r1, [pc, #0] *)
          "10ff2fe1" (* bx r0 *)
          "34120000" (* .word 0x1234 *)
          "0200a0e3" (* mov r0, #2 *)
          "1eff2fe1" (* bx lr *) ]
    let entries = Seq.toArray fns.Addresses
    CollectionAssert.AreEqual([| 0x0UL; 0xcUL |], entries)

  (* GCC puts a mov r0, r0 for a nop in ARMv5 code, here between f and the
     literal that it loads, and the word of the literal decodes as an andeq.
     Read on through them, the code at 0x14 would save registers with the
     push of g, but a literal is data, so 0x14 starts no function. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``Code that runs into a literal starts no function``() =
    let fns =
      recoverCode
        [ "10402de9" (* main: push {r4, lr} *)
          "000000eb" (* bl f *)
          "1080bde8" (* pop {r4, pc} *)
          "04009fe5" (* f: ldr r0, [pc, #4] *)
          "1eff2fe1" (* bx lr *)
          "0000a0e1" (* mov r0, r0 *)
          "34120000" (* .word 0x1234, loaded at 0xc *)
          "10402de9" (* g: push {r4, lr} *)
          "0200a0e3" (* mov r0, #2 *)
          "1080bde8" (* pop {r4, pc} *) ]
    let entries = Seq.toArray fns.Addresses
    CollectionAssert.DoesNotContain(entries, 0x14UL)

  (* No code that the recovery knows loads the word past f, so it may be a
     literal of code that the recovery has not built. It decodes as an
     instruction that runs on a condition, which no function starts with, so
     the push right after it does not make it a start either. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A word that no load reads before a push starts no function``() =
    let fns =
      recoverCode
        [ "10402de9" (* main: push {r4, lr} *)
          "000000eb" (* bl f *)
          "1080bde8" (* pop {r4, pc} *)
          "0100a0e3" (* f: mov r0, #1 *)
          "1eff2fe1" (* bx lr *)
          "34120000" (* .word 0x1234, as andeq r1, r0, r4, lsr r2 *)
          "10402de9" (* push {r4, lr} *)
          "0200a0e3" (* mov r0, #2 *)
          "1080bde8" (* pop {r4, pc} *) ]
    let entries = Seq.toArray fns.Addresses
    CollectionAssert.AreEqual([| 0x0UL; 0xcUL |], entries)

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
    let targets = indirectJumpTargetsOf fns[0x0UL]
    CollectionAssert.AreEqual([| 0x28UL; 0x2cUL; 0x30UL; 0x34UL |], targets)

  (* Clang fills the entries of the cases that never come with the end of the
     function, which in 32-bit ARM is where its literal pool starts. The
     function loads the first literal of the pool, so no code lies there, and
     the entry is a hole that the table reads past. *)
  [<TestMethod>]
  member _.``A table entry to a literal that its function loads is a hole``() =
    let fns =
      recoverCode
        [ "28309fe5" (* ldr r3, [pc, #0x28] *)
          "0a0000eb" (* bl g *)
          "04108fe2" (* add r1, pc, #4 *)
          "000191e7" (* ldr r0, [r1, r0, lsl #2] *)
          "00f081e0" (* add pc, r1, r0 *)
          "0c000000" (* .word 0xc *)
          "1c000000" (* .word 0x1c, a hole *)
          "14000000" (* .word 0x14 *)
          "0000a0e3" (* mov r0, #0 *)
          "1eff2fe1" (* bx lr *)
          "0200a0e3" (* mov r0, #2 *)
          "1eff2fe1" (* bx lr *)
          "34120000" (* .word 0x1234, loaded at 0x0 *)
          "1eff2fe1" (* g: bx lr *) ]
    let entries = fns[0x0UL].JumpTables |> Array.map _.NumEntries
    let targets = indirectJumpTargetsOf fns[0x0UL]
    CollectionAssert.AreEqual([| 3 |], entries)
    CollectionAssert.AreEqual([| 0x20UL; 0x28UL |], targets)

  (* Only a case that the table reaches through an entry after the hole may
     load the literal, as in the regex code of gnulib, so the hole has to be
     told before the recovery builds that case. *)
  [<TestMethod>]
  member _.``A table entry to a literal that a later case loads is a hole``() =
    let fns =
      recoverCode
        [ "0a0000eb" (* bl g *)
          "04108fe2" (* add r1, pc, #4 *)
          "000191e7" (* ldr r0, [r1, r0, lsl #2] *)
          "00f081e0" (* add pc, r1, r0 *)
          "0c000000" (* .word 0xc *)
          "1c000000" (* .word 0x1c, a hole *)
          "14000000" (* .word 0x14 *)
          "0000a0e3" (* mov r0, #0 *)
          "1eff2fe1" (* bx lr *)
          "00009fe5" (* ldr r0, [pc, #0] *)
          "1eff2fe1" (* bx lr *)
          "34120000" (* .word 0x1234, loaded at 0x24 *)
          "1eff2fe1" (* g: bx lr *) ]
    let entries = fns[0x0UL].JumpTables |> Array.map _.NumEntries
    let targets = indirectJumpTargetsOf fns[0x0UL]
    CollectionAssert.AreEqual([| 3 |], entries)
    CollectionAssert.AreEqual([| 0x1cUL; 0x24UL |], targets)

  (* GCC copies `goto *tbl[i]` into the end of each label, so the code that an
     entry leads to dispatches through the same table again. That is the table
     itself rather than one starting inside it, so no entry is to blame, and
     both dispatches share the table. *)
  [<TestMethod>]
  member _.``Labels that dispatch through their own table share it``() =
    let fns =
      recoverCode
        [ "10402de9" (* push {r4, lr} *)
          "0b0000eb" (* bl g *)
          "0120d0e4" (* ldrb r2, [r0], #1 *)
          "20309fe5" (* ldr r3, [pc, #0x20] *)
          "022193e7" (* ldr r2, [r3, r2, lsl #2] *)
          "02f0a0e1" (* mov pc, r2 *)
          "011081e2" (* l0: add r1, r1, #1 *)
          "0120d0e4" (* ldrb r2, [r0], #1 *)
          "0c309fe5" (* ldr r3, [pc, #0xc] *)
          "022193e7" (* ldr r2, [r3, r2, lsl #2] *)
          "02f0a0e1" (* mov pc, r2 *)
          "0100a0e1" (* l1: mov r0, r1 *)
          "1080bde8" (* pop {r4, pc} *)
          "3c000000" (* .word 0x3c, the table *)
          "1eff2fe1" (* g: bx lr *)
          "18000000" (* .word l0 *)
          "2c000000" (* .word l1 *) ]
    let entries = fns[0x0UL].JumpTables |> Array.map _.NumEntries
    let targets = indirectJumpTargetsOf fns[0x0UL]
    CollectionAssert.AreEqual([| 2 |], entries)
    CollectionAssert.AreEqual([| 0x18UL; 0x18UL; 0x2cUL; 0x2cUL |], targets)

  (* GCC keeps the table away from the code and reads where it lies out of the
     literal pool of the function. The ADD to the PC that jumps scales each
     entry by four, so a byte counts the words from the instruction after the
     next one, and the index needs no scaling of its own. *)
  [<TestMethod>]
  member _.``A GCC table of bytes is scaled by the add to the PC``() =
    let code =
      [ "0e0000eb" (* bl 0x40 *)
        "2c309fe5" (* ldr r3, [pc, #0x2c] *)
        "03308fe0" (* add r3, pc, r3 *)
        "030050e3" (* cmp r0, #3 *)
        "0700008a" (* bhi 0x34 *)
        "0000d3e7" (* ldrb r0, [r3, r0] *)
        "00f18fe0" (* add pc, pc, r0, lsl #2 *)
        "00f020e3" (* nop *)
        "0000a0e3" (* mov r0, #0 *)
        "1eff2fe1" (* bx lr *)
        "0100a0e3" (* mov r0, #1 *)
        "1eff2fe1" (* bx lr *)
        "0200a0e3" (* mov r0, #2 *)
        "1eff2fe1" (* bx lr *)
        "2c000000" (* .word 0x2c, from the PC of the add to the table *)
        "00020405" (* .byte 0, 2, 4, 5 *)
        "1eff2fe1" (* bx lr *) ]
      |> String.concat ""
      |> ByteArray.ofHexString
    let fns = BinaryBrew(BinHandle.LoadRawImage(code, ISA "armv7")).Functions
    let targets = indirectJumpTargetsOf fns[0x0UL]
    CollectionAssert.AreEqual([| 0x20UL; 0x28UL; 0x30UL; 0x34UL |], targets)

  (* A load of a halfword in ARM cannot scale its index, so GCC doubles the
     index with an ADD first. Here two cases lie before the jump, and their
     entries are negative, which ldrsh reads as such. *)
  [<TestMethod>]
  member _.``A GCC table of halfwords reads a doubled index``() =
    let code =
      [ "110000eb" (* bl 0x4c *)
        "030000ea" (* b 0x18 *)
        "0000a0e3" (* mov r0, #0 *)
        "1eff2fe1" (* bx lr *)
        "0100a0e3" (* mov r0, #1 *)
        "1eff2fe1" (* bx lr *)
        "20309fe5" (* ldr r3, [pc, #0x20] *)
        "03308fe0" (* add r3, pc, r3 *)
        "030050e3" (* cmp r0, #3 *)
        "0400008a" (* bhi 0x3c *)
        "000080e0" (* add r0, r0, r0 *)
        "f00093e1" (* ldrsh r0, [r3, r0] *)
        "00f18fe0" (* add pc, pc, r0, lsl #2 *)
        "00f020e3" (* nop *)
        "0200a0e3" (* mov r0, #2 *)
        "1eff2fe1" (* bx lr *)
        "20000000" (* .word 0x20, from the PC of the add to the table *)
        "f4fff6ff" (* .short -12, -10 *)
        "00000100" (* .short 0, 1 *)
        "1eff2fe1" (* bx lr *) ]
      |> String.concat ""
      |> ByteArray.ofHexString
    let fns = BinaryBrew(BinHandle.LoadRawImage(code, ISA "armv7")).Functions
    let targets = indirectJumpTargetsOf fns[0x0UL]
    CollectionAssert.AreEqual([| 0x8UL; 0x10UL; 0x38UL; 0x3cUL |], targets)

  (* GCC may also add the index to the table first and then load the halfword
     at the index past that, which doubles the index all the same. *)
  [<TestMethod>]
  member _.``A GCC table of halfwords reads an index added twice``() =
    let code =
      [ "110000eb" (* bl 0x4c *)
        "030000ea" (* b 0x18 *)
        "0000a0e3" (* mov r0, #0 *)
        "1eff2fe1" (* bx lr *)
        "0100a0e3" (* mov r0, #1 *)
        "1eff2fe1" (* bx lr *)
        "20309fe5" (* ldr r3, [pc, #0x20] *)
        "03308fe0" (* add r3, pc, r3 *)
        "030050e3" (* cmp r0, #3 *)
        "0400008a" (* bhi 0x3c *)
        "003083e0" (* add r3, r3, r0 *)
        "f00093e1" (* ldrsh r0, [r3, r0] *)
        "00f18fe0" (* add pc, pc, r0, lsl #2 *)
        "00f020e3" (* nop *)
        "0200a0e3" (* mov r0, #2 *)
        "1eff2fe1" (* bx lr *)
        "20000000" (* .word 0x20, from the PC of the add to the table *)
        "f4fff6ff" (* .short -12, -10 *)
        "00000100" (* .short 0, 1 *)
        "1eff2fe1" (* bx lr *) ]
      |> String.concat ""
      |> ByteArray.ofHexString
    let fns = BinaryBrew(BinHandle.LoadRawImage(code, ISA "armv7")).Functions
    let targets = indirectJumpTargetsOf fns[0x0UL]
    CollectionAssert.AreEqual([| 0x8UL; 0x10UL; 0x38UL; 0x3cUL |], targets)

  (* Each entry of a GCC table counts words from the jump, so the bytes after
     the table in .rodata send the jump into its function as well, and only
     the range check ends the table. ARM branches on a condition within one
     instruction, and jumps out of one of its two ways, which the check then
     guards. Here main becomes a switch, and the start of .rodata its table,
     followed by four bytes that could be entries. *)
  [<TestMethod>]
  member _.``A range check ends the table of a GCC switch in ARM``() =
    let code =
      [ "10309fe5" (* ldr r3, [pc, #0x10] *)
        "03308fe0" (* add r3, pc, r3 *)
        "030050e3" (* cmp r0, #3 *)
        "0300008a" (* bhi 0x10350 *)
        "0000d3e7" (* ldrb r0, [r3, r0] *)
        "00f18fe0" (* add pc, pc, r0, lsl #2 *)
        "ec000000" (* .word 0xec, from the PC of the add to the table *)
        "1eff2fe1" (* bx lr *)
        "1eff2fe1" (* bx lr *) ]
    let rodata = "0001010001000100" (* .byte 0, 1, 1, 0, then 1, 0, 1, 0 *)
    let actual = countEntriesInPatchedMain code rodata
    CollectionAssert.AreEqual([| 4 |], actual)

  (* GCC may switch on a byte that a callee has written into a structure on
     the stack, a slot that the function itself never writes. The data flow
     knows neither what such a slot holds nor how wide it is, so the range
     check has to bound the index as the load extends the byte. Here main
     switches on a byte that its caller left on the stack. *)
  [<TestMethod>]
  member _.``A GCC switch on a stack byte ends at its range check``() =
    let code =
      [ "10309fe5" (* ldr r3, [pc, #0x10] *)
        "0400dde5" (* ldrb r0, [sp, #4] *)
        "030050e3" (* cmp r0, #3 *)
        "0300008a" (* bhi 0x10350 *)
        "0000d3e7" (* ldrb r0, [r3, r0] *)
        "00f18fe0" (* add pc, pc, r0, lsl #2 *)
        "28040100" (* .word 0x10428, the table *)
        "1eff2fe1" (* bx lr *)
        "1eff2fe1" (* bx lr *) ]
    let rodata = "0001010001000100" (* .byte 0, 1, 1, 0, then 1, 0, 1, 0 *)
    let actual = countEntriesInPatchedMain code rodata
    CollectionAssert.AreEqual([| 4 |], actual)

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
     but never calls, so nothing proves that a function starts at 0xc, where
     the label dispatches on through a register. *)
  [<TestMethod>]
  member _.``A code address stored but never called proves nothing``() =
    let code =
      [ "04308fe2" (* add r3, pc, #4 *)
        "003080e5" (* str r3, [r0] *)
        "1eff2fe1" (* bx lr *)
        "010080e2" (* add r0, r0, #1 *)
        "01f0a0e1" (* mov pc, r1 *) ]
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

  (* With main saving r4, r5, fp and lr instead, its push reads in Thumb as a
     load of a literal at __do_global_dtors_aux, as one halfword in 32 of any
     data or code does, so no such reading tells that the function that the
     pointer of .fini_array names is a literal. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A Thumb function that ARM code seems to load is found``() =
    let bytes = readZippedBinary "elf_arm32"
    System.BitConverter.GetBytes(0xe92d4830u).CopyTo(bytes, 0x338)
    System.BitConverter.GetBytes(0xe8bd8830u).CopyTo(bytes, 0x34c)
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
