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

namespace B2R2.FrontEnd.Intel.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.Intel

#if !EMULATION
[<TestClass>]
type LifterTests() =
  let test builder wordSize (expectedStmts: string[]) (bytes: byte[]) =
    let reader = BinReader.Init Endian.Little
    let parser = Parser(wordSize, reader) :> IInstructionParsable
    let ins = parser.Parse(bytes, 0UL)
    let actual = ins.Translate builder |> Array.map PrettyPrinter.ToString
    CollectionAssert.AreEqual(expectedStmts, actual)

  let testX86 (hex: string) expectedStmts =
    let isa = ISA(Architecture.Intel, WordSize.Bit32)
    let regFactory = RegisterFactory isa
    let stream = LowUIRStream()
    let builder = ILowUIRBuilder.Default(isa, regFactory, stream)
    ByteArray.ofHexString hex
    |> test builder WordSize.Bit32 expectedStmts

  let testX64 (hex: string) expectedStmts =
    let isa = ISA(Architecture.Intel, WordSize.Bit64)
    let regFactory = RegisterFactory isa
    let stream = LowUIRStream()
    let builder = ILowUIRBuilder.Default(isa, regFactory, stream)
    ByteArray.ofHexString hex
    |> test builder WordSize.Bit64 expectedStmts

  [<TestMethod>]
  member _.``[X86] ADD instruction lift Test (1)``() =
    testX86 "0500000100"
    <| [| "(5) {"
          "T_1:I32 := EAX"
          "T_2:I32 := (T_1:I32 + 0x10000:I32)"
          "EAX := T_2:I32"
          "T_3:I1 := (T_1:I32[31:31])"
          "T_4:I1 := (T_2:I32[31:31])"
          "CF := (T_2:I32 < T_1:I32)"
          "OF := ((T_3:I1 = 0x0:I1) & (T_3:I1 ^ T_4:I1))"
          "AF := ((((T_2:I32 ^ T_1:I32) ^ 0x10000:I32) & 0x10:I32) = 0x10:I32)"
          "SF := T_4:I1"
          "ZF := (T_2:I32 = 0x0:I32)"
          "T_5:I32 := (T_2:I32 ^ (T_2:I32 >> 0x4:I32))"
          "T_6:I32 := (T_5:I32 ^ (T_5:I32 >> 0x2:I32))"
          "PF := (~ ((T_6:I32 ^ (T_6:I32 >> 0x1:I32))[0:0]))"
          "} // 5" |]

  [<TestMethod>]
  member _.``[X64] ADD instruction lift Test (1)``() =
    testX64 "0500000100"
    <| [| "(5) {"
          "T_1:I32 := (RAX[31:0])"
          "T_2:I32 := (T_1:I32 + 0x10000:I32)"
          "RAX := zext:I64(T_2:I32)"
          "T_3:I1 := (T_1:I32[31:31])"
          "T_4:I1 := (T_2:I32[31:31])"
          "CF := (T_2:I32 < T_1:I32)"
          "OF := ((T_3:I1 = 0x0:I1) & (T_3:I1 ^ T_4:I1))"
          "AF := ((((T_2:I32 ^ T_1:I32) ^ 0x10000:I32) & 0x10:I32) = 0x10:I32)"
          "SF := T_4:I1"
          "ZF := (T_2:I32 = 0x0:I32)"
          "T_5:I32 := (T_2:I32 ^ (T_2:I32 >> 0x4:I32))"
          "T_6:I32 := (T_5:I32 ^ (T_5:I32 >> 0x2:I32))"
          "PF := (~ ((T_6:I32 ^ (T_6:I32 >> 0x1:I32))[0:0]))"
          "} // 5" |]

  [<TestMethod>]
  member _.``[X86] MOV instruction lift Test (1)``() =
    testX86 "C6456400"
    <| [| "(4) {"
          "[(EBP + 0x64:I32)] := 0x0:I8"
          "} // 4" |]

  [<TestMethod>]
  member _.``[X86] CMPSB instruction lift Test (1)``() =
    testX86 "A6"
    <| [| "(1) {"
          "T_1:I8 := [ESI]:I8"
          "T_2:I8 := [EDI]:I8"
          "T_3:I8 := (T_1:I8 - T_2:I8)"
          "ESI := ((DF) ? ((ESI - 0x1:I32)) : ((ESI + 0x1:I32)))"
          "EDI := ((DF) ? ((EDI - 0x1:I32)) : ((EDI + 0x1:I32)))"
          "CF := (T_1:I8 < T_2:I8)"
          "OF := (((T_1:I8 ^ T_2:I8) & (T_1:I8 ^ T_3:I8))[7:7])"
          "AF := ((((T_3:I8 ^ T_1:I8) ^ T_2:I8) & 0x10:I8) = 0x10:I8)"
          "SF := (T_3:I8[7:7])"
          "ZF := (T_3:I8 = 0x0:I8)"
          "T_4:I8 := (T_3:I8 ^ (T_3:I8 >> 0x4:I8))"
          "T_5:I8 := (T_4:I8 ^ (T_4:I8 >> 0x2:I8))"
          "PF := (~ ((T_5:I8 ^ (T_5:I8 >> 0x1:I8))[0:0]))"
          "} // 1" |]

  [<TestMethod>]
  member _.``[X64] MOV instruction lift Test (1)``() =
    testX64 "488EC1"
    <| [| "(3) {"
          "ES := (RCX[15:0])"
          "} // 3" |]

  [<TestMethod>]
  member _.``[X64] PUSH instruction lift Test (1)``() =
    testX64 "664850"
    <| [| "(3) {"
          "RSP := (RSP - 0x8:I64)"
          "[RSP] := RAX"
          "} // 3" |]

  [<TestMethod>]
  member _.``[X64] RET instruction lift Test (1)``() =
    testX64 "CB"
    <| [| "(1) {"
          "!!UnsupportedInstruction"
          "} // 1" |]

  (* Intel reserves four encodings so that they always fault, and what they
     mean is the fault: an emulator has to raise it, and an analysis reading
     one has reached code that never runs. Only UD2 used to say so; the other
     three fell through to the catch-all and came back as an instruction
     merely awaiting implementation. *)
  [<TestMethod>]
  member _.``[X64] UD1 instruction lift Test (1)``() =
    testX64 "0FB9C0"
    <| [| "(3) {"
          "!!UndefinedInstruction"
          "} // 3" |]

  [<TestMethod>]
  member _.``[X64] UD2 instruction lift Test (1)``() =
    testX64 "0F0B"
    <| [| "(2) {"
          "!!UndefinedInstruction"
          "} // 2" |]

  (* AMD TBM: the source joined to its increment, CF set by the carry out of
     that increment alone, which only a source of all ones makes. *)
  [<TestMethod>]
  member _.``[X64] BLCFILL instruction lift Test (1)``() =
    testX64 "8fe96801cb" (* blcfill edx, ebx *)
    <| [| "(5) {"
          "T_1:I32 := (RBX[31:0])"
          "T_2:I32 := (T_1:I32 & (T_1:I32 + 0x1:I32))"
          "SF := (T_2:I32[31:31])"
          "ZF := (T_2:I32 = 0x0:I32)"
          "CF := (T_1:I32 = 0xffffffff:I32)"
          "RDX := zext:I64(T_2:I32)"
          "OF := 0x0:I1"
          "AF := ?? (AF is undefined.)"
          "PF := ?? (PF is undefined.)"
          "} // 5" |]

  (* A decrement borrows only from zero, and a source in memory is loaded
     once however many times the operation reads it. *)
  [<TestMethod>]
  member _.``[X64] TZMSK instruction lift Test (1)``() =
    testX64 "8fe9f80123" (* tzmsk rax, qword ptr [rbx] *)
    <| [| "(5) {"
          "T_1:I64 := [RBX]:I64"
          "T_2:I64 := ((~ T_1:I64) & (T_1:I64 - 0x1:I64))"
          "SF := (T_2:I64[63:63])"
          "ZF := (T_2:I64 = 0x0:I64)"
          "CF := (T_1:I64 = 0x0:I64)"
          "RAX := T_2:I64"
          "OF := 0x0:I1"
          "AF := ?? (AF is undefined.)"
          "PF := ?? (PF is undefined.)"
          "} // 5" |]

  (* The immediate form of BEXTR goes through the same lifter as the VEX one,
     the control word now a constant. *)
  [<TestMethod>]
  member _.``[X64] BEXTR immediate form lift Test (1)``() =
    testX64 "8fea7810cb04080000" (* bextr ecx, ebx, 0x804 *)
    <| [| "(9) {"
          "T_3:I32 := 0x4:I32"
          "T_4:I32 := 0x8:I32"
          "T_2:I32 := (0xffffffff:I32 << T_4:I32)"
          "T_1:I32 := (RBX[31:0])"
          "T_1:I32 := ((T_1:I32 >> T_3:I32) & (~ T_2:I32))"
          "RCX := zext:I64(T_1:I32)"
          "ZF := ((RCX[31:0]) = 0x0:I32)"
          "CF := 0x0:I1"
          "OF := 0x0:I1"
          "AF := ?? (AF is undefined.)"
          "SF := ?? (SF is undefined.)"
          "PF := ?? (PF is undefined.)"
          "} // 9" |]

  (* Intel APX. A new data destination takes the whole register whatever the
     operand size, and EVEX.NF leaves every status flag as it was. Intel APX
     spec 355828, 3.1.2.3 and 3.1.2.4. *)
  [<TestMethod>]
  member _.``[X64] APX ADD with NF writes no flag (1)``() =
    testX64 "62f4741c01d3" (* {nf} add ecx, ebx, edx *)
    <| [| "(6) {"
          "T_1:I32 := (RBX[31:0])"
          "T_2:I32 := (RDX[31:0])"
          "T_3:I32 := T_1:I32"
          "T_4:I32 := T_2:I32"
          "T_5:I32 := (T_3:I32 + T_4:I32)"
          "T_1:I32 := T_5:I32"
          "RCX := zext:I64(T_1:I32)"
          "} // 6" |]

  [<TestMethod>]
  member _.``[X64] APX INC zeroes above a byte destination (1)``() =
    testX64 "62f47c1cfec3" (* {nf} inc al, bl *)
    <| [| "(6) {"
          "T_1:I8 := (RBX[7:0])"
          "T_2:I8 := T_1:I8"
          "T_3:I8 := 0x1:I8"
          "T_4:I8 := (T_2:I8 + T_3:I8)"
          "T_1:I8 := T_4:I8"
          "RAX := zext:I64(T_1:I8)"
          "} // 6" |]

  (* Where the source condition fails, the flags take the default value:
     here OF alone set, PF following CF, and AF clear. *)
  [<TestMethod>]
  member _.``[X64] APX CCMPB falls back to its default flags (1)``() =
    testX64 "62f4440239c8" (* ccmpb {dfv=of} eax, ecx *)
    <| [| "(6) {"
          "T_1:I32 := (RAX[31:0])"
          "T_2:I32 := (RCX[31:0])"
          "if CF then jmp Compare else jmp NotCompare"
          ":Compare"
          "T_3:I32 := T_1:I32"
          "T_4:I32 := T_2:I32"
          "T_5:I32 := (T_3:I32 - T_4:I32)"
          "CF := (T_3:I32 < T_4:I32)"
          "OF := (((T_3:I32 ^ T_4:I32) & (T_3:I32 ^ T_5:I32))[31:31])"
          "AF := ((((T_5:I32 ^ T_3:I32) ^ T_4:I32) & 0x10:I32) = 0x10:I32)"
          "SF := (T_5:I32[31:31])"
          "ZF := (T_5:I32 = 0x0:I32)"
          "T_6:I32 := (T_5:I32 ^ (T_5:I32 >> 0x4:I32))"
          "T_7:I32 := (T_6:I32 ^ (T_6:I32 >> 0x2:I32))"
          "PF := (~ ((T_7:I32 ^ (T_7:I32 >> 0x1:I32))[0:0]))"
          "jmp CompareEnd"
          ":NotCompare"
          "OF := 0x1:I1"
          "SF := 0x0:I1"
          "ZF := 0x0:I1"
          "CF := 0x0:I1"
          "PF := 0x0:I1"
          "AF := 0x0:I1"
          ":CompareEnd"
          "} // 6" |]

  (* CFCMOVcc touches its memory operand only where the condition holds, so
     a fault the access would raise is suppressed otherwise. *)
  [<TestMethod>]
  member _.``[X64] APX CFCMOVB loads only when it moves (1)``() =
    testX64 "62f47c084203" (* cfcmovb eax, dword ptr [rbx] *)
    <| [| "(6) {"
          "T_1:I32 := 0x0:I32"
          "if CF then jmp Move else jmp MoveEnd"
          ":Move"
          "T_1:I32 := [RBX]:I32"
          ":MoveEnd"
          "RAX := zext:I64(T_1:I32)"
          "} // 6" |]

  [<TestMethod>]
  member _.``[X64] APX CFCMOVB stores only when it moves (1)``() =
    testX64 "62f47c0c4203" (* cfcmovb dword ptr [rbx], eax *)
    <| [| "(6) {"
          "if CF then jmp Store else jmp StoreEnd"
          ":Store"
          "[RBX] := (RAX[31:0])"
          ":StoreEnd"
          "} // 6" |]

  [<TestMethod>]
  member _.``[X64] APX CFCMOVB keeps its first source otherwise (1)``() =
    testX64 "62f46c1c42c1" (* cfcmovb edx, eax, ecx *)
    <| [| "(6) {"
          "T_1:I32 := (RAX[31:0])"
          "if CF then jmp Move else jmp MoveEnd"
          ":Move"
          "T_1:I32 := (RCX[31:0])"
          ":MoveEnd"
          "RDX := zext:I64(T_1:I32)"
          "} // 6" |]

  [<TestMethod>]
  member _.``[X64] APX CMOVB picks between its two sources (1)``() =
    testX64 "62f4741842c3" (* cmovb ecx, eax, ebx *)
    <| [| "(6) {"
          "RCX := zext:I64(((CF) ? ((RBX[31:0])) : ((RAX[31:0]))))"
          "} // 6" |]

  [<TestMethod>]
  member _.``[X64] APX SETZUB writes the whole register (1)``() =
    testX64 "62f47f1842c0" (* setzub al *)
    <| [| "(6) {"
          "RAX := zext:I64(CF)"
          "} // 6" |]

  [<TestMethod>]
  member _.``[X64] APX IMULZU zeroes above a word destination (1)``() =
    testX64 "62f47d186bc105" (* imulzu ax, cx, 0x5 *)
    <| [| "(7) {"
          "T_1:I32 := (sext:I32((RCX[15:0])) * 0x5:I32)"
          "RAX := zext:I64((T_1:I32[15:0]))"
          "CF := (sext:I32((RAX[15:0])) != T_1:I32)"
          "OF := (sext:I32((RAX[15:0])) != T_1:I32)"
          "SF := ?? (SF is undefined.)"
          "ZF := ?? (ZF is undefined.)"
          "AF := ?? (AF is undefined.)"
          "PF := ?? (PF is undefined.)"
          "} // 7" |]

  [<TestMethod>]
  member _.``[X64] APX POP2 pops its first operand first (1)``() =
    testX64 "62fc7c108fc1" (* pop2 r16, r17 *)
    <| [| "(6) {"
          "R16 := [RSP]:I64"
          "RSP := (RSP + 0x8:I64)"
          "R17 := [RSP]:I64"
          "RSP := (RSP + 0x8:I64)"
          "} // 6" |]

  [<TestMethod>]
  member _.``[X64] APX PUSH2P pushes its first operand first (1)``() =
    testX64 "62f4fc18fff3" (* push2p rax, rbx *)
    <| [| "(6) {"
          "RSP := (RSP - 0x8:I64)"
          "[RSP] := RAX"
          "RSP := (RSP - 0x8:I64)"
          "[RSP] := RBX"
          "} // 6" |]

  [<TestMethod>]
  member _.``[X64] APX JMPABS jumps to its immediate (1)``() =
    testX64 "d500a18877665544332211" (* jmpabs 0x1122334455667788 *)
    <| [| "(11) {"
          "ijmp 0x1122334455667788:I64" |]

  [<TestMethod>]
  member _.``[X64] APX AADD adds atomically and sets no flag (1)``() =
    testX64 "62f47c08fc03" (* aadd dword ptr [rbx], eax *)
    <| [| "(6) {"
          "T_1:I32 := (RAX[31:0])"
          "!!AtomicBegin"
          "[RBX] := ([RBX]:I32 + T_1:I32)"
          "!!AtomicEnd"
          "} // 6" |]

#endif

/// The lifter reads the EVEX decorations off the instruction rather than off
/// the operands, so these check what the operand list cannot say. They are
/// outside the guard above because nothing on this path is conditional on the
/// emulation build: no flag is written, and no operand is RIP-relative.
[<TestClass>]
type EVEXDecorationLifterTests() =
  let testX64 (hex: string) (expectedStmts: string[]) =
    let isa = ISA(Architecture.Intel, WordSize.Bit64)
    let regFactory = RegisterFactory isa
    let builder = LowUIRBuilder(isa, regFactory, LowUIRStream())
    let reader = BinReader.Init Endian.Little
    let parser = Parser(WordSize.Bit64, reader) :> IInstructionParsable
    let ins = parser.Parse(ByteArray.ofHexString hex, 0UL)
    let actual = ins.Translate builder |> Array.map PrettyPrinter.ToString
    CollectionAssert.AreEqual(expectedStmts, actual)

  (* One element read once and repeated, not a vector read and thrown away:
     the hardware reads four bytes here, and a lifter that read sixteen would
     fault on a broadcast from the last element of a page. *)
  [<TestMethod>]
  member _.``[X64] EVEX embedded broadcast reads one element (1)``() =
    testX64 "62f16d18fe08" (* vpaddd xmm1, xmm2, dword bcst [rax] *)
    <| [| "(6) {"
          "T_1:I32 := [RAX]:I32"
          "T_2:I32 := ((ZMM2A[31:0]) + T_1:I32)"
          "T_3:I32 := ((ZMM2A[63:32]) + T_1:I32)"
          "T_4:I32 := ((ZMM2B[31:0]) + T_1:I32)"
          "T_5:I32 := ((ZMM2B[63:32]) + T_1:I32)"
          "ZMM1A := (T_3:I32 ++ T_2:I32)"
          "ZMM1B := (T_5:I32 ++ T_4:I32)"
          "ZMM1C := 0x0:I64"
          "ZMM1D := 0x0:I64"
          "ZMM1E := 0x0:I64"
          "ZMM1F := 0x0:I64"
          "ZMM1G := 0x0:I64"
          "ZMM1H := 0x0:I64"
          "} // 6" |]

  [<TestMethod>]
  member _.``[X64] EVEX opmask with zeroing gates every lane (1)``() =
    testX64 "62f16d99fe08" (* vpaddd xmm1{k1}{z}, xmm2, dword bcst [rax] *)
    <| [| "(6) {"
          "T_1:I32 := [RAX]:I32"
          "T_2:I32 := (((K1[0:0])) ? (((ZMM2A[31:0]) + T_1:I32)) : (0x0:I32))"
          "T_3:I32 := (((K1[1:1])) ? (((ZMM2A[63:32]) + T_1:I32)) : (0x0:I32))"
          "T_4:I32 := (((K1[2:2])) ? (((ZMM2B[31:0]) + T_1:I32)) : (0x0:I32))"
          "T_5:I32 := (((K1[3:3])) ? (((ZMM2B[63:32]) + T_1:I32)) : (0x0:I32))"
          "ZMM1A := (T_3:I32 ++ T_2:I32)"
          "ZMM1B := (T_5:I32 ++ T_4:I32)"
          "ZMM1C := 0x0:I64"
          "ZMM1D := 0x0:I64"
          "ZMM1E := 0x0:I64"
          "ZMM1F := 0x0:I64"
          "ZMM1G := 0x0:I64"
          "ZMM1H := 0x0:I64"
          "} // 6" |]

  (* Without an opmask no lane is gated. EVEX.aaa of zero is not the register
     K0, so nothing here reads it to compare against a constant true. *)
  [<TestMethod>]
  member _.``[X64] EVEX without an opmask gates nothing (1)``() =
    testX64 "62f16d08fe08" (* vpaddd xmm1, xmm2, xmmword [rax] *)
    <| [| "(6) {"
          "T_2:I64 := [RAX]:I64"
          "T_1:I64 := [(RAX + 0x8:I64)]:I64"
          "T_3:I32 := ((ZMM2A[31:0]) + (T_2:I64[31:0]))"
          "T_4:I32 := ((ZMM2A[63:32]) + (T_2:I64[63:32]))"
          "T_5:I32 := ((ZMM2B[31:0]) + (T_1:I64[31:0]))"
          "T_6:I32 := ((ZMM2B[63:32]) + (T_1:I64[63:32]))"
          "ZMM1A := (T_4:I32 ++ T_3:I32)"
          "ZMM1B := (T_6:I32 ++ T_5:I32)"
          "ZMM1C := 0x0:I64"
          "ZMM1D := 0x0:I64"
          "ZMM1E := 0x0:I64"
          "ZMM1F := 0x0:I64"
          "ZMM1G := 0x0:I64"
          "ZMM1H := 0x0:I64"
          "} // 6" |]

/// The AVX-512 opmask instructions. Each writes only its own width and clears
/// the rest of the 64-bit mask register, which is what the zext in almost
/// every expectation below is; the Q forms have nothing to clear and so have
/// no zext at all.
[<TestClass>]
type OpMaskLifterTests() =
  let test (hex: string) (expectedStmts: string[]) =
    let isa = ISA(Architecture.Intel, WordSize.Bit64)
    let regFactory = RegisterFactory isa
    let builder = LowUIRBuilder(isa, regFactory, LowUIRStream())
    let reader = BinReader.Init Endian.Little
    let parser = Parser(WordSize.Bit64, reader) :> IInstructionParsable
    let ins = parser.Parse(ByteArray.ofHexString hex, 0UL)
    let actual =
      ins.Translate builder
      |> Array.map PrettyPrinter.ToString
      |> Array.filter (fun l -> not (l.StartsWith "(" || l.StartsWith "}"))
    CollectionAssert.AreEqual(expectedStmts, actual)

  [<TestMethod>]
  member _.``[X64] KADDB adds the low byte and clears the rest (1)``() =
    test "c5ed4acb" (* kaddb k1, k2, k3 *)
    <| [| "K1 := zext:I64(((K2[7:0]) + (K3[7:0])))" |]

  (* The Q form fills the register, so nothing is cleared above it. *)
  [<TestMethod>]
  member _.``[X64] KADDQ writes the whole mask register (1)``() =
    test "c4e1ec4acb" (* kaddq k1, k2, k3 *)
    <| [| "K1 := (K2 + K3)" |]

  (* KANDN complements the operand VEX.vvvv names, which is the second one
     written, not the third. *)
  [<TestMethod>]
  member _.``[X64] KANDNW complements its first source (1)``() =
    test "c5ec42cb" (* kandnw k1, k2, k3 *)
    <| [| "K1 := zext:I64(((~ (K2[15:0])) & (K3[15:0])))" |]

  [<TestMethod>]
  member _.``[X64] KANDW ands the low word (1)``() =
    test "c5ec41cb" (* kandw k1, k2, k3 *)
    <| [| "K1 := zext:I64(((K2[15:0]) & (K3[15:0])))" |]

  [<TestMethod>]
  member _.``[X64] KORW ors the low word (1)``() =
    test "c5ec45cb" (* korw k1, k2, k3 *)
    <| [| "K1 := zext:I64(((K2[15:0]) | (K3[15:0])))" |]

  [<TestMethod>]
  member _.``[X64] KXORW xors the low word (1)``() =
    test "c5ec47cb" (* kxorw k1, k2, k3 *)
    <| [| "K1 := zext:I64(((K2[15:0]) ^ (K3[15:0])))" |]

  [<TestMethod>]
  member _.``[X64] KXNORW complements the xor (1)``() =
    test "c5ec46cb" (* kxnorw k1, k2, k3 *)
    <| [| "K1 := zext:I64((~ ((K2[15:0]) ^ (K3[15:0]))))" |]

  [<TestMethod>]
  member _.``[X64] KNOTW complements the low word (1)``() =
    test "c5f844ca" (* knotw k1, k2 *)
    <| [| "K1 := zext:I64((~ (K2[15:0])))" |]

  (* The low half of the result comes from the last operand and the high half
     from the one before it -- the opposite order to the way they are read. *)
  [<TestMethod>]
  member _.``[X64] KUNPCKBW takes its low half from the last source (1)``() =
    test "c5ed4bcb" (* kunpckbw k1, k2, k3 *)
    <| [| "K1 := zext:I64(((K2[7:0]) ++ (K3[7:0])))" |]

  [<TestMethod>]
  member _.``[X64] KMOVW between mask registers (1)``() =
    test "c5f890ca" (* kmovw k1, k2 *)
    <| [| "K1 := zext:I64((K2[15:0]))" |]

  (* A memory source is read at the mask's width and nothing wider: the parser
     sized the operand, and reading a whole quadword for a KMOVW would fault
     where the hardware does not. *)
  [<TestMethod>]
  member _.``[X64] KMOVW loads exactly a word (1)``() =
    test "c5f89008" (* kmovw k1, word ptr [rax] *)
    <| [| "K1 := zext:I64([RAX]:I16)" |]

  [<TestMethod>]
  member _.``[X64] KMOVW stores exactly a word (1)``() =
    test "c5f89108" (* kmovw word ptr [rax], k1 *)
    <| [| "[RAX] := (K1[15:0])" |]

  [<TestMethod>]
  member _.``[X64] KMOVW reads a general-purpose register (1)``() =
    test "c5f892cb" (* kmovw k1, ebx *)
    <| [| "K1 := zext:I64((RBX[15:0]))" |]

  (* Every KMOV but the Q form writes 32 bits of a general-purpose
     destination, which in 64-bit mode clears the upper half of the register. *)
  [<TestMethod>]
  member _.``[X64] KMOVW writes 32 bits of a GPR (1)``() =
    test "c5f893d9" (* kmovw ebx, k1 *)
    <| [| "RBX := zext:I64(zext:I32((K1[15:0])))" |]

  [<TestMethod>]
  member _.``[X64] KMOVQ writes a whole 64-bit GPR (1)``() =
    test "c4e1fb93d9" (* kmovq rbx, k1 *)
    <| [| "RBX := K1" |]

  [<TestMethod>]
  member _.``[X64] KSHIFTLB shifts by its immediate (1)``() =
    test "c4e37932ca05" (* kshiftlb k1, k2, 5 *)
    <| [| "K1 := zext:I64(((K2[7:0]) << 0x5:I8))" |]

  [<TestMethod>]
  member _.``[X64] KSHIFTRW shifts right, filling with zeros (1)``() =
    test "c4e3f930ca05" (* kshiftrw k1, k2, 5 *)
    <| [| "K1 := zext:I64(((K2[15:0]) >> 0x5:I16))" |]

  (* A count at or past the mask's width clears the destination outright. The
     count is an immediate, so that is settled while lifting rather than left
     to a comparison in the IR. *)
  [<TestMethod>]
  member _.``[X64] KSHIFTLB by the mask's width clears it (1)``() =
    test "c4e37932ca08" (* kshiftlb k1, k2, 8 *)
    <| [| "K1 := 0x0:I64" |]

  [<TestMethod>]
  member _.``[X64] KSHIFTRW by 255 clears it (1)``() =
    test "c4e3f930caff" (* kshiftrw k1, k2, 255 *)
    <| [| "K1 := 0x0:I64" |]

  (* KORTEST sets CF when every bit of the mask's own width is set, so the
     constant it compares against is as wide as the mask and no wider. *)
  [<TestMethod>]
  member _.``[X64] KORTESTW sets ZF and CF from the OR (1)``() =
    test "c5f898ca" (* kortestw k1, k2 *)
    <| [| "T_1:I16 := ((K1[15:0]) | (K2[15:0]))"
          "ZF := (T_1:I16 = 0x0:I16)"
          "CF := (T_1:I16 = 0xffff:I16)"
          "OF := 0x0:I1"
          "AF := 0x0:I1"
          "PF := 0x0:I1"
          "SF := 0x0:I1" |]

  [<TestMethod>]
  member _.``[X64] KTESTW sets ZF and CF from both tests (1)``() =
    test "c5f899ca" (* ktestw k1, k2 *)
    <| [| "ZF := (((K2[15:0]) & (K1[15:0])) = 0x0:I16)"
          "CF := (((K2[15:0]) & (~ (K1[15:0]))) = 0x0:I16)"
          "OF := 0x0:I1"
          "AF := 0x0:I1"
          "PF := 0x0:I1"
          "SF := 0x0:I1" |]

/// AMD's XOP instructions. Every one of them writes a 128-bit or a 256-bit
/// result and clears the register above it, which is the run of zeros that
/// closes each expectation; XOP.W only swaps which source ModRM names, and the
/// parser has already put the operands in the order the operation reads them.
[<TestClass>]
type XOPLifterTests() =
  let lift (hex: string) =
    let isa = ISA(Architecture.Intel, WordSize.Bit64)
    let regFactory = RegisterFactory isa
    let builder = LowUIRBuilder(isa, regFactory, LowUIRStream())
    let reader = BinReader.Init Endian.Little
    let parser = Parser(WordSize.Bit64, reader) :> IInstructionParsable
    let ins = parser.Parse(ByteArray.ofHexString hex, 0UL)
    ins.Translate builder
    |> Array.map PrettyPrinter.ToString
    |> Array.filter (fun l -> not (l.StartsWith "(" || l.StartsWith "}"))

  let test hex (expectedStmts: string[]) =
    CollectionAssert.AreEqual(expectedStmts, lift hex)

  let zeroAbove128 =
    [| "ZMM1C := 0x0:I64"
       "ZMM1D := 0x0:I64"
       "ZMM1E := 0x0:I64"
       "ZMM1F := 0x0:I64"
       "ZMM1G := 0x0:I64"
       "ZMM1H := 0x0:I64" |]

  let zeroAbove256 =
    [| "ZMM1E := 0x0:I64"
       "ZMM1F := 0x0:I64"
       "ZMM1G := 0x0:I64"
       "ZMM1H := 0x0:I64" |]

  [<TestMethod>]
  member _.``[X64] VPCMOV selects bitwise (1)``() =
    test "8fe868a20b40" (* vpcmov xmm1, xmm2, xmmword ptr [rbx], xmm4 *)
    <| Array.append
      [| "T_2:I64 := [RBX]:I64"
         "T_1:I64 := [(RBX + 0x8:I64)]:I64"
         "ZMM1A := (((ZMM2A[63:0]) & (ZMM4A[63:0]))"
         + " | ((T_2:I64[63:0]) & (~ (ZMM4A[63:0]))))"
         "ZMM1B := (((ZMM2B[63:0]) & (ZMM4B[63:0]))"
         + " | ((T_1:I64[63:0]) & (~ (ZMM4B[63:0]))))" |] zeroAbove128

  (* Only the low three bits of the immediate name the test: 0xfd is 5, NEQ. *)
  [<TestMethod>]
  member _.``[X64] VPCOMQ reads three bits of its immediate (1)``() =
    test "8fe868cfcbfd" (* vpcomq xmm1, xmm2, xmm3, 0xfd *)
    <| Array.append
      [| "ZMM1A := ((((ZMM2A[63:0]) != (ZMM3A[63:0])))"
         + " ? (0xffffffffffffffff:I64) : (0x0:I64))"
         "ZMM1B := ((((ZMM2B[63:0]) != (ZMM3B[63:0])))"
         + " ? (0xffffffffffffffff:I64) : (0x0:I64))" |] zeroAbove128

  [<TestMethod>]
  member _.``[X64] VPHADDWQ sums four sign-extended words (1)``() =
    test "8fe978c7ca" (* vphaddwq xmm1, xmm2 *)
    <| Array.append
      [| "ZMM1A := (((sext:I64((ZMM2A[15:0])) + sext:I64((ZMM2A[31:16])))"
         + " + sext:I64((ZMM2A[47:32]))) + sext:I64((ZMM2A[63:48])))"
         "ZMM1B := (((sext:I64((ZMM2B[15:0])) + sext:I64((ZMM2B[31:16])))"
         + " + sext:I64((ZMM2B[47:32]))) + sext:I64((ZMM2B[63:48])))" |]
      zeroAbove128

  (* The upper element of each pair is taken from the lower one. *)
  [<TestMethod>]
  member _.``[X64] VPHSUBDQ subtracts the upper element (1)``() =
    test "8fe978e3ca" (* vphsubdq xmm1, xmm2 *)
    <| Array.append
      [| "ZMM1A := (sext:I64((ZMM2A[31:0])) - sext:I64((ZMM2A[63:32])))"
         "ZMM1B := (sext:I64((ZMM2B[31:0])) - sext:I64((ZMM2B[63:32])))" |]
      zeroAbove128

  (* The H form multiplies the odd doublewords, and wraps. *)
  [<TestMethod>]
  member _.``[X64] VPMACSDQH accumulates the odd doublewords (1)``() =
    test "8fe8689fcb40" (* vpmacsdqh xmm1, xmm2, xmm3, xmm4 *)
    <| Array.append
      [| "ZMM1A := ((sext:I128((ZMM4A[63:0]))"
         + " + (sext:I128((ZMM2A[63:32])) * sext:I128((ZMM3A[63:32]))))"
         + "[63:0])"
         "ZMM1B := ((sext:I128((ZMM4B[63:0]))"
         + " + (sext:I128((ZMM2B[63:32])) * sext:I128((ZMM3B[63:32]))))"
         + "[63:0])" |] zeroAbove128

  (* The saturating form keeps the sum at twice the width and clamps it. *)
  [<TestMethod>]
  member _.``[X64] VPMACSSDQH saturates the sum (1)``() =
    test "8fe8688fcb40" (* vpmacssdqh xmm1, xmm2, xmm3, xmm4 *)
    <| Array.append
      [| "T_1:I128 := (sext:I128((ZMM4A[63:0]))"
         + " + (sext:I128((ZMM2A[63:32])) * sext:I128((ZMM3A[63:32]))))"
         "T_2:I128 := (sext:I128((ZMM4B[63:0]))"
         + " + (sext:I128((ZMM2B[63:32])) * sext:I128((ZMM3B[63:32]))))"
         "ZMM1A := (((sext:I128((T_1:I128[63:0])) = T_1:I128))"
         + " ? ((T_1:I128[63:0])) : ((((T_1:I128[127:127]))"
         + " ? (0x8000000000000000:I64) : (0x7fffffffffffffff:I64))))"
         "ZMM1B := (((sext:I128((T_2:I128[63:0])) = T_2:I128))"
         + " ? ((T_2:I128[63:0])) : ((((T_2:I128[127:127]))"
         + " ? (0x8000000000000000:I64) : (0x7fffffffffffffff:I64))))" |]
      zeroAbove128

  (* The selector's low five bits index the 32 bytes of the two sources, the
     first source's sixteen first. *)
  [<TestMethod>]
  member _.``[X64] VPPERM picks from both sources (1)``() =
    let stmts = lift "8fe868a3cb40" (* vpperm xmm1, xmm2, xmm3, xmm4 *)
    let expected =
      [| "T_1:I256 := (((ZMM3B[63:0]) ++ (ZMM3A[63:0]))"
         + " ++ ((ZMM2B[63:0]) ++ (ZMM2A[63:0])))"
         "T_2:I8 := ((T_1:I256 >> (zext:I256(((ZMM4A[7:0]) & 0x1f:I8))"
         + " << 0x3:I256))[7:0])"
         "T_17:I8 := ((T_1:I256 >> (zext:I256(((ZMM4B[63:56]) & 0x1f:I8))"
         + " << 0x3:I256))[7:0])" |]
      |> Array.append zeroAbove128
    Assert.AreEqual<int>(25, stmts.Length)
    CollectionAssert.IsSubsetOf(expected, stmts)

  [<TestMethod>]
  member _.``[X64] VPROTQ rotates by its immediate (1)``() =
    test "8fe878c3ca07" (* vprotq xmm1, xmm2, 7 *)
    <| Array.append
      [| "ZMM1A := (((ZMM2A[63:0]) << 0x7:I64)"
         + " | ((ZMM2A[63:0]) >> 0x39:I64))"
         "ZMM1B := (((ZMM2B[63:0]) << 0x7:I64)"
         + " | ((ZMM2B[63:0]) >> 0x39:I64))" |] zeroAbove128

  (* XOP.W set: the count is what ModRM names, and a negative one rotates
     right, which is a left rotate by the count modulo the width. *)
  [<TestMethod>]
  member _.``[X64] VPROTQ rotates by a signed count (1)``() =
    test "8fe9e893cb" (* vprotq xmm1, xmm2, xmm3 *)
    <| Array.append
      [| "ZMM1A := (((ZMM2A[63:0]) << zext:I64(((ZMM3A[7:0]) & 0x3f:I8)))"
         + " | ((ZMM2A[63:0]) >> zext:I64(((- (ZMM3A[7:0])) & 0x3f:I8))))"
         "ZMM1B := (((ZMM2B[63:0]) << zext:I64(((ZMM3B[7:0]) & 0x3f:I8)))"
         + " | ((ZMM2B[63:0]) >> zext:I64(((- (ZMM3B[7:0])) & 0x3f:I8))))" |]
      zeroAbove128

  (* A negative count shifts right, arithmetically for VPSHA. *)
  [<TestMethod>]
  member _.``[X64] VPSHAQ shifts by a signed count (1)``() =
    test "8fe9e89b0b" (* vpshaq xmm1, xmm2, xmmword ptr [rbx] *)
    <| Array.append
      [| "T_2:I64 := [RBX]:I64"
         "T_1:I64 := [(RBX + 0x8:I64)]:I64"
         "ZMM1A := (((T_2:I64[7:7]))"
         + " ? (((ZMM2A[63:0]) ?>> zext:I64(((- (T_2:I64[7:0])) & 0x3f:I8))))"
         + " : (((ZMM2A[63:0]) << zext:I64(((T_2:I64[7:0]) & 0x3f:I8)))))"
         "ZMM1B := (((T_1:I64[7:7]))"
         + " ? (((ZMM2B[63:0]) ?>> zext:I64(((- (T_1:I64[7:0])) & 0x3f:I8))))"
         + " : (((ZMM2B[63:0]) << zext:I64(((T_1:I64[7:0]) & 0x3f:I8)))))" |]
      zeroAbove128

  [<TestMethod>]
  member _.``[X64] VPSHLQ shifts logically (1)``() =
    test "8fe9e897cb" (* vpshlq xmm1, xmm2, xmm3 *)
    <| Array.append
      [| "ZMM1A := (((ZMM3A[7:7]))"
         + " ? (((ZMM2A[63:0]) >> zext:I64(((- (ZMM3A[7:0])) & 0x3f:I8))))"
         + " : (((ZMM2A[63:0]) << zext:I64(((ZMM3A[7:0]) & 0x3f:I8)))))"
         "ZMM1B := (((ZMM3B[7:7]))"
         + " ? (((ZMM2B[63:0]) >> zext:I64(((- (ZMM3B[7:0])) & 0x3f:I8))))"
         + " : (((ZMM2B[63:0]) << zext:I64(((ZMM3B[7:0]) & 0x3f:I8)))))" |]
      zeroAbove128

  [<TestMethod>]
  member _.``[X64] VFRCZPD takes away the truncated part (1)``() =
    test "8fe97c81ca" (* vfrczpd ymm1, ymm2 *)
    <| Array.append
      [| "ZMM1A := ((ZMM2A[63:0]) -. rnd(0x3:I8, rint:I64((ZMM2A[63:0]))))"
         "ZMM1B := ((ZMM2B[63:0]) -. rnd(0x3:I8, rint:I64((ZMM2B[63:0]))))"
         "ZMM1C := ((ZMM2C[63:0]) -. rnd(0x3:I8, rint:I64((ZMM2C[63:0]))))"
         "ZMM1D := ((ZMM2D[63:0]) -. rnd(0x3:I8, rint:I64((ZMM2D[63:0]))))" |]
      zeroAbove256

  (* The scalar form clears the rest of the low 128 bits too, and reads its
     memory operand once. *)
  [<TestMethod>]
  member _.``[X64] VFRCZSS clears the upper elements (1)``() =
    test "8fe978820b" (* vfrczss xmm1, dword ptr [rbx] *)
    <| Array.append
      [| "T_1:I32 := [RBX]:I32"
         "ZMM1A := zext:I64((T_1:I32 -. rnd(0x3:I8, rint:I32(T_1:I32))))"
         "ZMM1B := 0x0:I64" |] zeroAbove128

  (* LWP keeps its state in a facility this lifter does not model. *)
  [<TestMethod>]
  member _.``[X64] LWPVAL is unsupported (1)``() =
    test "8feae812cb78563412" (* lwpval rdx, ebx, 0x12345678 *)
    <| [| "!!UnsupportedInstruction" |]

/// Intel AMX. The tile state lives in TILECFG and the eight TMM registers;
/// what an instruction does with it depends on the shapes TILECFG holds at run
/// time, so these check the instructions whose IR does not loop over them.
[<TestClass>]
type AMXLifterTests() =
  let lift (hex: string) =
    let isa = ISA(Architecture.Intel, WordSize.Bit64)
    let regFactory = RegisterFactory isa
    let builder = LowUIRBuilder(isa, regFactory, LowUIRStream())
    let reader = BinReader.Init Endian.Little
    let parser = Parser(WordSize.Bit64, reader) :> IInstructionParsable
    let ins = parser.Parse(ByteArray.ofHexString hex, 0UL)
    ins.Translate builder
    |> Array.map PrettyPrinter.ToString
    |> Array.filter (fun l -> not (l.StartsWith "(" || l.StartsWith "}"))

  let test hex (expectedStmts: string[]) =
    CollectionAssert.AreEqual(expectedStmts, lift hex)

  [<TestMethod>]
  member _.``[X64] TILERELEASE clears the configuration and every tile (1)``() =
    test "c4e27849c0" (* tilerelease *)
    <| [| "TILECFG := 0x0:I512"
          "TMM0 := 0x0:I8192"
          "TMM1 := 0x0:I8192"
          "TMM2 := 0x0:I8192"
          "TMM3 := 0x0:I8192"
          "TMM4 := 0x0:I8192"
          "TMM5 := 0x0:I8192"
          "TMM6 := 0x0:I8192"
          "TMM7 := 0x0:I8192" |]

  [<TestMethod>]
  member _.``[X64] STTILECFG stores the configuration (1)``() =
    test "c4e2794900" (* sttilecfg [rax] *)
    <| [| "[RAX] := TILECFG" |]

  (* TILEZERO faults on a tile the configuration leaves unused: palette 0, or
     no rows, or no bytes per row (TMM1's are bytes 49 and 18-19). *)
  [<TestMethod>]
  member _.``[X64] TILEZERO faults on an unused tile (1)``() =
    let check =
      "if (((TILECFG[7:0]) = 0x0:I8) | ((zext:I32((TILECFG[399:392])) = "
      + "0x0:I32) | (zext:I32((TILECFG[159:144])) = 0x0:I32))) then jmp "
      + "BadTile else jmp BadTileEnd"
    let mask = "0x" + String.replicate 124 "f" + "00ff:I512"
    test "c4e27b49c8" (* tilezero tmm1 *)
    <| [| check
          ":BadTile"
          "!!UndefinedInstruction"
          ":BadTileEnd"
          "TMM1 := 0x0:I8192"
          "TILECFG := (TILECFG & " + mask + ")" |]
