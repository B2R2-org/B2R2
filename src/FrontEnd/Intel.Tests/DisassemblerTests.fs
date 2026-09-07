(*
  B2R2 - the Next-Generation Reversing Platform

  Copyright (c) SoftSec Lab. @ KAIST, since 2016

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*)

namespace B2R2.FrontEnd.Intel.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.Intel
open type Opcode

[<TestClass>]
type DisassemblerTests() =
  let test wordSize (bytes: byte[]) (instruction: string[]) =
    let reader = BinReader.Init Endian.Little
    let parser = IntelParser(wordSize, reader) :> IInstructionParsable
    let actualInstruction (syntax: DisasmSyntax) =
      (parser :?> IntelParser).SetDisassemblySyntax syntax
      parser.Parse(bytes, 0UL)
      |> fun instruction -> (instruction.Disasm()).ToLowerInvariant()
    Assert.AreEqual<string>(instruction[0], actualInstruction DefaultSyntax)
    Assert.AreEqual<string>(instruction[1], actualInstruction ATTSyntax)

  let testX86 (bytes: byte[], instruction) =
    test WordSize.Bit32 bytes instruction

  let testX64 (bytes: byte[], instruction) =
    test WordSize.Bit64 bytes instruction

  let ( ++ ) byteString pair = ByteArray.ofHexString byteString, pair

  [<TestMethod>]
  member _.``X86 ADD instruction test (1)``() =
    "0500000100" ++ [| "add eax, 0x10000"; "add $0x10000, %eax" |]
    |> testX86

  [<TestMethod>]
  member _.``X86 ADD instruction test (2)``() =
    "83000a" ++ [| "add dword ptr [eax], 0xa"; "addl $0xa, (%eax)" |]
    |> testX86

  [<TestMethod>]
  // gcc isn't contain '+'
  member _.``X86 ADD instruction test (3)``() =
    "8340100a"
    ++ [| "add dword ptr [eax+0x10], 0xa"; "addl $0xa, +0x10(%eax)" |]
    |> testX86

  [<TestMethod>]
  member _.``X86 ADD instruction test (4)``() =
    "8304580a"
    ++ [| "add dword ptr [eax+ebx*2], 0xa"; "addl $0xa, (%eax, %ebx, 2)" |]
    |> testX86

  [<TestMethod>]
  // gcc isn't contain '+'
  member _.``X86 ADD instruction test (5)``() =
    "838458000100000a"
    ++ [| "add dword ptr [eax+ebx*2+0x100], 0xa"
          "addl $0xa, +0x100(%eax, %ebx, 2)" |]
    |> testX86

  [<TestMethod>]
  member _.``X64 ADD instruction test (6)``() =
    "480500000100" ++ [| "add rax, 0x10000"; "add $0x10000, %rax" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 ADD instruction test (7)``() =
    "4883000a" ++ [| "add qword ptr [rax], 0xa"; "addq $0xa, (%rax)" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 ADD instruction test (8)``() =
    "678340100a"
    ++ [| "add dword ptr [eax+0x10], 0xa"; "addl $0xa, +0x10(%eax)" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 ADD instruction test (9)``() =
    "678304580a"
    ++ [| "add dword ptr [eax+ebx*2], 0xa"; "addl $0xa, (%eax, %ebx, 2)" |]
    |> testX64

  [<TestMethod>]
  // gcc isn't contain '+'
  member _.``X64 ADD instruction test (10)``() =
    "67838458000100000a"
    ++ [| "add dword ptr [eax+ebx*2+0x100], 0xa"
          "addl $0xa, +0x100(%eax, %ebx, 2)" |]
    |> testX64

  (* A Key Locker handle is 48 bytes wide and Intel syntax names no directive
     that wide, so the operand prints bare. *)
  [<TestMethod>]
  member _.``X64 AESENC128KL instruction test``() =
    "f30f38dc00"
    ++ [| "aesenc128kl xmm0, [rax]"; "aesenc128kl (%rax), %xmm0" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 AESENCWIDE128KL instruction test``() =
    "f30f38d800"
    ++ [| "aesencwide128kl [rax]"; "aesencwide128kl (%rax)" |]
    |> testX64

  (* The x87 state areas are the same case, and used to print a stray space
     where the directive would have gone. *)
  [<TestMethod>]
  member _.``X64 FLDENV instruction test``() =
    "d920" ++ [| "fldenv [rax]"; "fldenv (%rax)" |]
    |> testX64

  (* LEA computes an address and reads no memory, so there is no access width
     to name. Vol 2A tables 3-57 and 3-58 give it an operand size and an
     address size, and the destination and base registers already show both. *)
  [<TestMethod>]
  member _.``X64 LEA instruction test``() =
    "488d4508" ++ [| "lea rax, [rbp+0x8]"; "leaq +0x8(%rbp), %rax" |]
    |> testX64

  (* With 67h the address narrows to 32 bits while the destination stays 64,
     so a directive naming the destination would read as the address width. *)
  [<TestMethod>]
  member _.``X64 LEA instruction test (address-size prefix)``() =
    "67488d4508" ++ [| "lea rax, [ebp+0x8]"; "leaq +0x8(%ebp), %rax" |]
    |> testX64

  [<TestMethod>]
  member _.``X86 LEA instruction test``() =
    "8d4508" ++ [| "lea eax, [ebp+0x8]"; "leal +0x8(%ebp), %eax" |]
    |> testX86

  (* NOP at 90h is, in the manual's own words, an alias mnemonic for the
     XCHG (E)AX, (E)AX instruction. REX.B moves the second register to r8, so
     the bytes exchange rather than do nothing, which the hardware confirms. *)
  [<TestMethod>]
  member _.``X64 XCHG instruction test (REX.B on 90h)``() =
    "4190" ++ [| "xchg eax, r8d"; "xchg %r8d, %eax" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 NOP instruction test``() =
    "90" ++ [| "nop"; "nop" |]
    |> testX64

  (* PAUSE shares the byte but is a separate instruction the F3 prefix names,
     so REX.B rides along inert there. *)
  [<TestMethod>]
  member _.``X64 PAUSE instruction test (REX.B on F3 90h)``() =
    "f34190" ++ [| "pause"; "pause" |]
    |> testX64

  (* The multi-byte NOP does take a ModRM byte, where REX.B extends the r/m
     register as it does anywhere else. *)
  [<TestMethod>]
  member _.``X64 NOP instruction test (multi-byte with REX.B)``() =
    "410f1f00" ++ [| "nop dword ptr [r8]"; "nopl (%r8)" |]
    |> testX64

  (* An EVEX decoration belongs to a position, not to a shape. These are the
     positions that used to be missed: a mask on a RIP-relative destination, a
     broadcast on anything but the last operand, and a static rounding at all
     in AT&T syntax. *)
  [<TestMethod>]
  member _.``X64 EVEX masked RIP-relative load test (1)``() =
    "62f17e496f0d00010000"
    ++ [| "vmovdqu32 zmm1{k1}, zmmword ptr [rip+0x100] ; 0x10a"
          "vmovdqu32 +0x100(%rip), %zmm1{%k1}" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 EVEX masked zeroing register test (1)``() =
    "62f16dc9fecb"
    ++ [| "vpaddd zmm1{k1}{z}, zmm2, zmm3"
          "vpaddd %zmm3, %zmm2, %zmm1{%k1}{z}" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 EVEX masked store test (1)``() =
    "62f17e497f08"
    ++ [| "vmovdqu32 zmmword ptr [rax]{k1}, zmm1"
          "vmovdqu32 %zmm1, (%rax){%k1}" |]
    |> testX64

  (* The broadcast sits on the second of three operands here, which the old
     shape-matched printer had no arm for. *)
  [<TestMethod>]
  member _.``X64 EVEX broadcast on a middle operand test (1)``() =
    "62f37d59661003"
    ++ [| "vfpclassps k2{k1}, dword ptr [rax]{1to16}, 0x3"
          "vfpclasspsl $0x3, (%rax){1to16}, %k2{%k1}" |]
    |> testX64

  (* {sae} without embedded rounding. EVEX.b spends L'L here as it does for
     {er}, so the operands are 512 bits wide however L'L reads -- and the
     decoration is SAE alone, with no rounding mode to name. *)
  [<TestMethod>]
  member _.``X64 EVEX suppress-all-exceptions test (1)``() =
    "62f16c995fcb"
    ++ [| "vmaxps zmm1{k1}{z}, zmm2, zmm3{sae}"
          "vmaxps {sae}, %zmm3, %zmm2, %zmm1{%k1}{z}" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 EVEX embedded rounding test (1)``() =
    "62f16c3858cb"
    ++ [| "vaddps zmm1, zmm2, zmm3{rd-sae}"
          "vaddps {rd-sae}, %zmm3, %zmm2, %zmm1" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 EVEX broadcast with a trailing immediate test (1)``() =
    "62f16c5ac20801"
    ++ [| "vcmpps k1{k2}, zmm2, dword ptr [rax]{1to16}, 0x1"
          "vcmppsl $0x1, (%rax){1to16}, %zmm2, %k1{%k2}" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 EVEX RIP-relative broadcast test (1)``() =
    "62f16c59580d40000000"
    ++ [| "vaddps zmm1{k1}, zmm2, dword ptr [rip+0x40]{1to16} ; 0x4a"
          "vaddpsl +0x40(%rip){1to16}, %zmm2, %zmm1{%k1}" |]
    |> testX64
