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

#if !EMULATION && !HASHCONS
[<TestClass>]
type LifterTests() =
  let test builder wordSize (expectedStmts: string[]) (bytes: byte[]) =
    let reader = BinReader.Init Endian.Little
    let parser = IntelParser(wordSize, reader) :> IInstructionParsable
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

#endif

/// The lifter reads the EVEX decorations off the instruction rather than off
/// the operands, so these check what the operand list cannot say. They are
/// outside the guard above because nothing on this path is conditional on the
/// emulation build: no flag is written, and no operand is RIP-relative.
#if !HASHCONS
[<TestClass>]
type EVEXDecorationLifterTests() =
  let testX64 (hex: string) (expectedStmts: string[]) =
    let isa = ISA(Architecture.Intel, WordSize.Bit64)
    let regFactory = RegisterFactory isa
    let stream = LowUIRStream()
    let builder = ILowUIRBuilder.Default(isa, regFactory, stream)
    let reader = BinReader.Init Endian.Little
    let parser = IntelParser(WordSize.Bit64, reader) :> IInstructionParsable
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
#endif
