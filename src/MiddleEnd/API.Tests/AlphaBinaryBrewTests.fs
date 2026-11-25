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
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Tests the recovery of Alpha binaries.
[<TestClass>]
type AlphaBinaryBrewTests() =
  /// Recovers the functions of the given Alpha code, which starts at address
  /// zero with the entry of the binary.
  static let recoverCode (code: string list) =
    let bytes = code |> String.concat "" |> ByteArray.ofHexString
    BinaryBrew(BinHandle.LoadRawImage(bytes, ISA "alpha")).Functions

  /// Recovers the functions of elf_alpha_so with get, at 0x600, made the given
  /// code from 0x608 on, past the two words that compute gp, which has room
  /// for 27 words before .text ends.
  static let recoverPatchedGet (code: string list) =
    let bytes = readZippedBinary "elf_alpha_so"
    (ByteArray.ofHexString(String.concat "" code)).CopyTo(bytes, 0x608)
    BinaryBrew(BinHandle.LoadFileBytes(bytes, ISA "alpha")).Functions

  /// Returns the entries of the given functions, in order.
  static let entriesOf (fns: FunctionCollection) =
    fns.Sequence |> Seq.map _.EntryPoint |> Seq.sort |> Seq.toArray

  (* A jump clears the low two bits of its target, which the address of code
     has clear anyway, so a table is read through the jump as if it did not.
     A raw image has no section to hold a table, so the table is one of
     labels, which point into its function, before the next one: the code
     starts by calling a function that lies past its table. *)
  [<TestMethod>]
  member _.``A table is read through the mask of its jump``() =
    let code =
      [ "0e0040d3" (* 0x00: bsr ra,0x3c *)
        "a1370042" (* cmpule a0,1,t0 *)
        "0b0020e4" (* beq t0,0x38 *)
        "20005f20" (* lda t1,0x20 *)
        "50040242" (* s4addq a0,t1,a0 *)
        "000030a0" (* ldl t0,0(a0) *)
        "01044140" (* addq t1,t0,t0 *)
        "0000e16b" (* jmp (t0) *)
        "08000000" (* 0x20: .long 0x28 - 0x20 *)
        "10000000" (* .long 0x30 - 0x20 *)
        "00001f20" (* 0x28: lda v0,0 *)
        "0080fa6b" (* ret *)
        "01001f20" (* 0x30: lda v0,1 *)
        "0080fa6b" (* ret *)
        "0080fa6b" (* 0x38: ret *)
        "0080fa6b" (* 0x3c: ret *) ]
    let fns = recoverCode code
    let entries = fns[0UL].JumpTables |> Array.map _.NumEntries
    CollectionAssert.AreEqual([| 2 |], entries)

  (* The caller of a function puts its address in t12, from which the function
     computes gp, which the code reads its tables through. The function at 0x8
     makes gp the address of its table, at 0x2c. *)
  [<TestMethod>]
  member _.``A function finds gp from t12``() =
    let code =
      [ "010040d3" (* 0x00: bsr ra,0x8 *)
        "0080fa6b" (* ret *)
        "0000bb27" (* 0x08: ldah gp,0(t12) *)
        "2400bd23" (* lda gp,0x24(gp) *)
        "0d0040d3" (* bsr ra,0x48 *)
        "a1370042" (* cmpule a0,1,t0 *)
        "0a0020e4" (* beq t0,0x44 *)
        "50041d42" (* s4addq a0,gp,a0 *)
        "000030a0" (* ldl t0,0(a0) *)
        "0104a143" (* addq gp,t0,t0 *)
        "0000e16b" (* jmp (t0) *)
        "08000000" (* 0x2c: .long 0x34 - 0x2c *)
        "10000000" (* .long 0x3c - 0x2c *)
        "00001f20" (* 0x34: lda v0,0 *)
        "0080fa6b" (* ret *)
        "01001f20" (* 0x3c: lda v0,1 *)
        "0080fa6b" (* ret *)
        "0080fa6b" (* 0x44: ret *)
        "0080fa6b" (* 0x48: ret *) ]
    let fns = recoverCode code
    let entries = fns[0x8UL].JumpTables |> Array.map _.NumEntries
    CollectionAssert.AreEqual([| 2 |], entries)

  (* A caller that shares gp with its callee calls it past the two words that
     compute gp from t12, where the callee starts all the same. *)
  [<TestMethod>]
  member _.``A call past the gp prologue enters its function``() =
    let code =
      [ "030040d3" (* 0x00: bsr ra,0x10 *)
        "0080fa6b" (* ret *)
        "0000bb27" (* 0x08: ldah gp,0(t12) *)
        "2400bd23" (* lda gp,0x24(gp) *)
        "0d0040d3" (* 0x10: bsr ra,0x48 *)
        "a1370042" (* cmpule a0,1,t0 *)
        "0a0020e4" (* beq t0,0x44 *)
        "50041d42" (* s4addq a0,gp,a0 *)
        "000030a0" (* ldl t0,0(a0) *)
        "0104a143" (* addq gp,t0,t0 *)
        "0000e16b" (* jmp (t0) *)
        "08000000" (* 0x2c: .long 0x34 - 0x2c *)
        "10000000" (* .long 0x3c - 0x2c *)
        "00001f20" (* 0x34: lda v0,0 *)
        "0080fa6b" (* ret *)
        "01001f20" (* 0x3c: lda v0,1 *)
        "0080fa6b" (* ret *)
        "0080fa6b" (* 0x44: ret *)
        "0080fa6b" (* 0x48: ret *) ]
    let fns = recoverCode code
    let entries = fns[0x8UL].JumpTables |> Array.map _.NumEntries
    CollectionAssert.AreEqual([| 0x0UL; 0x8UL; 0x48UL |], entriesOf fns)
    CollectionAssert.AreEqual([| 2 |], entries)

  (* A callee returns through ra, so ra holds the address past the call once
     the call returns, from which the code computes gp again, whatever else of
     ra the callee writes on its way. The function at 0x8 makes gp the address
     of its table, at 0x34, past a call to one that calls in turn. *)
  [<TestMethod>]
  member _.``A call leaves the return address in ra``() =
    let code =
      [ "010040d3" (* 0x00: bsr ra,0x8 *)
        "0080fa6b" (* ret *)
        "f0ffde23" (* 0x08: lda sp,-16(sp) *)
        "00005eb7" (* stq ra,0(sp) *)
        "100040d3" (* bsr ra,0x54 *)
        "0000ba27" (* 0x14: ldah gp,0(ra) *)
        "2000bd23" (* lda gp,0x20(gp) *)
        "a1372041" (* cmpule s0,1,t0 *)
        "090020e4" (* beq t0,0x48 *)
        "49043d41" (* s4addq s0,gp,s0 *)
        "000029a0" (* ldl t0,0(s0) *)
        "0104a143" (* addq gp,t0,t0 *)
        "0000e16b" (* jmp (t0) *)
        "08000000" (* 0x34: .long 0x3c - 0x34 *)
        "10000000" (* .long 0x44 - 0x34 *)
        "00001f20" (* 0x3c: lda v0,0 *)
        "0100e0c3" (* br 0x48 *)
        "01001f20" (* 0x44: lda v0,1 *)
        "00005ea7" (* 0x48: ldq ra,0(sp) *)
        "1000de23" (* lda sp,16(sp) *)
        "0080fa6b" (* ret *)
        "f0ffde23" (* 0x54: lda sp,-16(sp) *)
        "00005eb7" (* stq ra,0(sp) *)
        "030040d3" (* bsr ra,0x6c *)
        "00005ea7" (* ldq ra,0(sp) *)
        "1000de23" (* lda sp,16(sp) *)
        "0080fa6b" (* ret *)
        "0080fa6b" (* 0x6c: ret *) ]
    let fns = recoverCode code
    let entries = fns[0x8UL].JumpTables |> Array.map _.NumEntries
    CollectionAssert.AreEqual([| 2 |], entries)

  (* get, at 0x600 in elf_alpha_so, calls ext through its slot of the GOT,
     0x20010, which it reads through gp, as the slot holds the PLT entry of
     ext, 0x4b4, until the loader binds it. *)
  [<TestMethod>]
  member _.``A call through the GOT reaches the PLT entry of its import``() =
    let bytes = readZippedBinary "elf_alpha_so"
    let fns = BinaryBrew(BinHandle.LoadFileBytes(bytes, ISA "alpha")).Functions
    let callee = fns[0x600UL].Callees[LeafCallSite 0x640UL]
    Assert.AreEqual<CalleeKind>(RegularCallee 0x4b4UL, callee)

  (* The FDE of get says that the frame goes 32 bytes deep past its first
     instruction past gp, so the stack pointer lies 32 bytes below where it
     lies on entry, although the code computes it from t8, which the data flow
     cannot tell, as GCC does past a loop that probes a big frame page by page.
     The code keeps the address of its table in the frame and reads it back. *)
  [<TestMethod>]
  member _.``A frame slot is read where the FDE tells the stack pointer``() =
    let code =
      [ "e0ffd623" (* 0x608: lda sp,-32(t8) *)
        "feff3d24" (* ldah t0,-2(gp) *)
        "24862120" (* lda t0,-31196(t0) *)
        "10003eb4" (* stq t0,16(sp) *)
        "a2370042" (* cmpule a0,1,t1 *)
        "0a0040e4" (* beq t1,0x648 *)
        "10003ea4" (* ldq t0,16(sp) *)
        "41040142" (* s4addq a0,t0,t0 *)
        "000021a0" (* ldl t0,0(t0) *)
        "0104a143" (* addq gp,t0,t0 *)
        "0000e16b" (* jmp (t0) *)
        "2c86fdff" (* 0x634: .long 0x63c - gp *)
        "3486fdff" (* .long 0x644 - gp *)
        "00001f20" (* 0x63c: lda v0,0 *)
        "0100e0c3" (* br 0x648 *)
        "01001f20" (* 0x644: lda v0,1 *)
        "2000de23" (* 0x648: lda sp,32(sp) *)
        "0080fa6b" (* ret *) ]
    let fns = recoverPatchedGet code
    let entries = fns[0x600UL].JumpTables |> Array.map _.NumEntries
    CollectionAssert.AreEqual([| 2 |], entries)
