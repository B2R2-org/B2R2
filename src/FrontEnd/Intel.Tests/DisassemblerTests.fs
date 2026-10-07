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
    let parser = Parser(wordSize, reader) :> IInstructionParsable
    let actualInstruction (syntax: DisasmSyntax) =
      (parser :?> Parser).SetDisassemblySyntax syntax
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

  (* AMX. A tile prints as its own name in either syntax, and sibmem prints
     bare: it names no width, because how many rows a tile load or store
     moves and how wide each of them is are configured at run time rather
     than encoded. SDM Vol. 2B, TILELOADD 4-710. *)
  [<TestMethod>]
  member _.``X64 AMX tile configuration test (1)``() =
    "c4e2784900"
    ++ [| "ldtilecfg zmmword ptr [rax]"; "ldtilecfg (%rax)" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 AMX tile configuration test (2)``() =
    "c4e27849c0"
    ++ [| "tilerelease"; "tilerelease" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 AMX tile zeroing test (1)``() =
    "c4e27b49c8"
    ++ [| "tilezero tmm1"; "tilezero %tmm1" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 AMX tile load test (1)``() =
    "c4e27b4b0c18"
    ++ [| "tileloadd tmm1, [rax+rbx]"; "tileloadd (%rax, %rbx), %tmm1" |]
    |> testX64

  (* AMX-MOVRS: the VEX forms, beside the EVEX ones of Intel APX. *)
  [<TestMethod>]
  member _.``X64 AMX read-shared tile load test (1)``() =
    "c4e27b4a0418"
    ++ [| "tileloaddrs tmm0, [rax+rbx]"; "tileloaddrs (%rax, %rbx), %tmm0" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 AMX read-shared tile load test (2)``() =
    "c4e2794a0418"
    ++ [| "tileloaddrst1 tmm0, [rax+rbx]"
          "tileloaddrst1 (%rax, %rbx), %tmm0" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 AMX tile load test (2)``() =
    "c4e27b4b4c9820"
    ++ [| "tileloadd tmm1, [rax+rbx*4+0x20]"
          "tileloadd +0x20(%rax, %rbx, 4), %tmm1" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 AMX tile store test (1)``() =
    "c4e27a4b0c18"
    ++ [| "tilestored [rax+rbx], tmm1"; "tilestored %tmm1, (%rax, %rbx)" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 AMX dot product test (1)``() =
    "c4e2635eca"
    ++ [| "tdpbssd tmm1, tmm2, tmm3"; "tdpbssd %tmm3, %tmm2, %tmm1" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 AMX dot product test (2)``() =
    "c4e2635cca"
    ++ [| "tdpfp16ps tmm1, tmm2, tmm3"; "tdpfp16ps %tmm3, %tmm2, %tmm1" |]
    |> testX64

  (* Intel APX. The extended GPRs print as r16 to r31 with the usual width
     suffixes; a suppressed flags update prints as the {nf} marker ahead of
     the mnemonic, and a conditional compare's default flags value after it,
     as XED and LLVM print them. Intel APX spec 355828-007. *)
  [<TestMethod>]
  member _.``X64 APX REX2 test (1)``() =
    "d55901cf"
    ++ [| "add r31, r17"; "add %r17, %r31" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 APX REX2 test (2)``() =
    "d53a8b0478"
    ++ [| "mov rax, qword ptr [r16+r31*2]"; "movq (%r16, %r31, 2), %rax" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 APX REX2 test (3)``() =
    "d55000ec"
    ++ [| "add r20b, r21b"; "add %r21b, %r20b" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 APX JMPABS test (1)``() =
    "d500a18877665544332211"
    ++ [| "jmpabs 0x1122334455667788"; "jmpabs $0x1122334455667788" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 APX PUSHP test (1)``() =
    "d51857"
    ++ [| "pushp r23"; "pushp %r23" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 APX new data destination test (1)``() =
    "62f4741801d3"
    ++ [| "add ecx, ebx, edx"; "add %edx, %ebx, %ecx" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 APX new data destination test (2)``() =
    "62f46c18000b"
    ++ [| "add dl, byte ptr [rbx], cl"; "addb %cl, (%rbx), %dl" |]
    |> testX64

  (* EVEX stands in for REX, so a byte-sized vvvv of 4 to 7 names SPL, BPL,
     SIL or DIL, never AH, CH, DH or BH. *)
  [<TestMethod>]
  member _.``X64 APX new data destination test (3)``() =
    "62cc5018101e"
    ++ [| "adc bpl, byte ptr [r30], r19b"; "adcb %r19b, (%r30), %bpl" |]
    |> testX64

  (* The same holds of ModRM's fields: an EVEX prefix in map 4 is a REX one
     too, whether or not any of its R, X and B bits is set. *)
  [<TestMethod>]
  member _.``X64 APX byte register test (1)``() =
    "62f47c0800e6"
    ++ [| "add sil, spl"; "add %spl, %sil" |]
    |> testX64

  (* A SIB index of 100 means no index only while X4 is clear as well: with
     it set, the field names R20. *)
  [<TestMethod>]
  member _.``X64 APX SIB index test (1)``() =
    "62ec4014091c61"
    ++ [| "{nf} or r23d, dword ptr [r17+r20*2], r19d"
          "{nf} orl %r19d, (%r17, %r20, 2), %r23d" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 APX no-flags test (1)``() =
    "62f4741c01d3"
    ++ [| "{nf} add ecx, ebx, edx"; "{nf} add %edx, %ebx, %ecx" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 APX conditional compare test (1)``() =
    "62f4440239c8"
    ++ [| "ccmpb {dfv=of} eax, ecx"; "ccmpb {dfv=of} %ecx, %eax" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 APX conditional compare test (2)``() =
    "62f41c04f7c078563412"
    ++ [| "ctestz {dfv=zf,cf} eax, 0x12345678"
          "ctestz {dfv=zf,cf} $0x12345678, %eax" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 APX conditional move test (1)``() =
    "62f46c1c42c1"
    ++ [| "cfcmovb edx, eax, ecx"; "cfcmovb %ecx, %eax, %edx" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 APX zero-upper test (1)``() =
    "62f47f1842c0"
    ++ [| "setzub al"; "setzub %al" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 APX PUSH2 test (1)``() =
    "62f4fc18fff3"
    ++ [| "push2p rax, rbx"; "push2p %rbx, %rax" |]
    |> testX64

  (* AMD SSE4a. The Intel manual does not cover these, so their rows are the
     ones Intel.json carries with a note rather than ones read from the SDM;
     pinning every encoding here keeps a regeneration from dropping them
     without a word. AMD64 APM Vol. 4. *)
  [<TestMethod>]
  member _.``X64 SSE4a non-temporal store test (1)``() =
    "f30f2b08"
    ++ [| "movntss dword ptr [rax], xmm1"; "movntssl %xmm1, (%rax)" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 SSE4a non-temporal store test (2)``() =
    "f20f2b08"
    ++ [| "movntsd qword ptr [rax], xmm1"; "movntsdq %xmm1, (%rax)" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 SSE4a field extract test (1)``() =
    "660f78c10408"
    ++ [| "extrq xmm1, 0x4, 0x8"; "extrq $0x8, $0x4, %xmm1" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 SSE4a field extract test (2)``() =
    "660f79ca"
    ++ [| "extrq xmm1, xmm2"; "extrq %xmm2, %xmm1" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 SSE4a field insert test (1)``() =
    "f20f78ca0408"
    ++ [| "insertq xmm1, xmm2, 0x4, 0x8"; "insertq $0x8, $0x4, %xmm2, %xmm1" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 SSE4a field insert test (2)``() =
    "f20f79ca"
    ++ [| "insertq xmm1, xmm2"; "insertq %xmm2, %xmm1" |]
    |> testX64

  (* AMD XOP, TBM and LWP. The Intel manual does not cover these either; the
     encodings are AMD64 APM Vol. 3's and Vol. 4's. *)
  [<TestMethod>]
  member _.``X64 XOP four-operand test (1)``() =
    "8fe86885cb40"
    ++ [| "vpmacssww xmm1, xmm2, xmm3, xmm4"
          "vpmacssww %xmm4, %xmm3, %xmm2, %xmm1" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 XOP four-operand test (2)``() =
    "8fe8eca20b40"
    ++ [| "vpcmov ymm1, ymm2, ymm4, ymmword ptr [rbx]"
          "vpcmov (%rbx), %ymm4, %ymm2, %ymm1" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 XOP immediate test (1)``() =
    "8fe878c0ca07"
    ++ [| "vprotb xmm1, xmm2, 0x7"; "vprotb $0x7, %xmm2, %xmm1" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 XOP immediate test (2)``() =
    "8fe868eecb03"
    ++ [| "vpcomud xmm1, xmm2, xmm3, 0x3"
          "vpcomud $0x3, %xmm3, %xmm2, %xmm1" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 XOP shift test (1)``() =
    "8fe9e89b0b"
    ++ [| "vpshaq xmm1, xmm2, xmmword ptr [rbx]"
          "vpshaq (%rbx), %xmm2, %xmm1" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 XOP scalar test (1)``() =
    "8fe978820b"
    ++ [| "vfrczss xmm1, dword ptr [rbx]"; "vfrczssl (%rbx), %xmm1" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 TBM test (1)``() =
    "8fe9e801cb"
    ++ [| "blcfill rdx, rbx"; "blcfill %rbx, %rdx" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 TBM test (2)``() =
    "8fe978013b"
    ++ [| "t1mskc eax, dword ptr [rbx]"; "t1mskcl (%rbx), %eax" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 TBM test (3)``() =
    "8feaf810cb78563412"
    ++ [| "bextr rcx, rbx, 0x12345678"; "bextr $0x12345678, %rbx, %rcx" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 LWP test (1)``() =
    "8fe97812c3"
    ++ [| "llwpcb ebx"; "llwpcb %ebx" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 LWP test (2)``() =
    "8feae812cb78563412"
    ++ [| "lwpval rdx, ebx, 0x12345678"; "lwpval $0x12345678, %ebx, %rdx" |]
    |> testX64
