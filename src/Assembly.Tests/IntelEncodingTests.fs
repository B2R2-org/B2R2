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

namespace B2R2.Assembly.Tests

open System
open System.IO
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.Intel

/// <summary>
/// Golden encoding vectors written by hand, covering the assembly syntax that
/// canonical disassembly cannot express and that IntelRoundTripTests therefore
/// cannot reach: unsized memory operands, labels, mnemonic aliases, letter
/// case, and instruction prefixes.
///
/// Every expected byte string here was validated by disassembling it with
/// B2R2.FrontEnd.Intel and confirming it means what the source text says.
/// </summary>
[<TestClass>]
type IntelEncodingTests() =

  /// Source text paired with the encoding it must produce. Multi-line sources
  /// are compared instruction by instruction, joined by a space.
  let vectors =
    [ WordSize.Bit32, "mov dword ptr [eax], ebx", "8918"
      WordSize.Bit32, "mov ebx, dword ptr [eax]", "8b18"
      (* An unsized memory operand must not flip the operand order. *)
      WordSize.Bit32, "mov [eax], ebx", "8918"
      WordSize.Bit32, "mov [eax], bl", "8818"
      WordSize.Bit64, "mov [rax], rbx", "488918"
      (* Segment prefixes must survive encoding. *)
      WordSize.Bit32, "mov eax, dword ptr [gs:0x10]", "658b0510000000"
      WordSize.Bit32, "call dword ptr [gs:0x10]", "65ff1510000000"
      (* The ModRM.reg digit distinguishes SUB from SBB. *)
      WordSize.Bit64, "sub qword ptr [rax], 0x1000", "48812800100000"
      WordSize.Bit64, "sub dword ptr [rax], 0x1000", "812800100000"
      WordSize.Bit64, "sbb qword ptr [rax], 0x1000", "48811800100000"
      (* An extended index register needs REX.X, not REX.R. *)
      WordSize.Bit64, "add qword ptr [rax+r8*2], 0x1", "4a83044001"
      WordSize.Bit64, "add qword ptr [rax+rcx*2], 0x1", "4883044801"
      (* ORPD takes a 128-bit memory operand, like ANDPD. *)
      WordSize.Bit32, "orpd xmm0, xmmword ptr [eax]", "660f5600"
      WordSize.Bit32, "andpd xmm0, xmmword ptr [eax]", "660f5400"
      (* Every classic ALU opcode accepts a label operand. *)
      WordSize.Bit32, "add eax, L\nL:\nret", "030506000000 c3"
      WordSize.Bit32, "sub eax, L\nL:\nret", "2b0506000000 c3"
      WordSize.Bit32, "xor eax, L\nL:\nret", "330506000000 c3"
      (* Letter case and tabs are not part of the syntax. *)
      WordSize.Bit32, "MOV eax, ebx", "8bc3"
      WordSize.Bit32, "mov\teax, ebx", "8bc3"
      (* LOCK reaches the read-modify-write instructions. *)
      WordSize.Bit32, "lock add dword ptr [eax], ebx", "f00118"
      WordSize.Bit32, "lock inc dword ptr [eax]", "f0ff00"
      WordSize.Bit32, "lock not dword ptr [eax]", "f0f710"
      WordSize.Bit32, "lock cmpxchg dword ptr [eax], ebx", "f00fb118"
      (* A repeat prefix survives on a string instruction. MOVSD is both a
         string move and a scalar double move, told apart by its operands. *)
      WordSize.Bit32, "repz scasb", "f3ae"
      WordSize.Bit32, "repnz scasb", "f2ae"
      WordSize.Bit32, "movsd", "a5"
      WordSize.Bit32, "repz movsd", "f3a5"
      WordSize.Bit32, "movsd xmm0, xmm1", "f20f10c1"
      (* RET's operand is a count of bytes to pop, not a displacement, so it
         must not have the instruction length subtracted from it. *)
      WordSize.Bit32, "ret", "c3"
      WordSize.Bit32, "ret 0x8", "c20800"
      WordSize.Bit32, "ret 0x1111", "c21111"
      (* A segment register answers to isReg16, so without its own case a
         segment destination is encoded as the general register sharing its
         number: mov es, cx came out as mov ax, cx. *)
      WordSize.Bit32, "mov es, cx", "8ec1"
      WordSize.Bit32, "mov ds, dx", "8eda"
      WordSize.Bit32, "mov es, word ptr [ecx]", "8e01"
      WordSize.Bit32, "mov cx, es", "668cc1"
      WordSize.Bit32, "mov word ptr [ecx], es", "668c01"
      (* SHLD puts its destination in ModRM.rm and its source in ModRM.reg,
         the opposite way round from most instructions. *)
      WordSize.Bit32, "shld cx, ax, 0x5", "660fa4c105"
      WordSize.Bit32, "shld cx, ax, cl", "660fa5c1"
      WordSize.Bit32, "shld ecx, eax, 0x5", "0fa4c105"
      WordSize.Bit32, "shld ecx, eax, cl", "0fa5c1"
      WordSize.Bit64, "shld rcx, rax, 0x5", "480fa4c105"
      WordSize.Bit32, "shld dword ptr [ecx], eax, cl", "0fa501" ]

  /// Sources that must be refused rather than encoded. Before these were
  /// checked, an instruction whose encoder emits raw opcode bytes dropped a
  /// prefix it could not carry instead of reporting it.
  let rejected =
    [ WordSize.Bit32, "lock ret"
      WordSize.Bit32, "repz ret"
      WordSize.Bit32, "lock hlt"
      WordSize.Bit32, "repz nop"
      WordSize.Bit32, "lock syscall"
      WordSize.Bit32, "lock fld1"
      (* LOCK needs a memory destination and a lockable opcode. *)
      WordSize.Bit32, "lock add eax, ebx"
      WordSize.Bit32, "lock mov dword ptr [eax], ebx"
      (* A repeat prefix belongs only to the string instructions. *)
      WordSize.Bit32, "repz add eax, ebx"
      WordSize.Bit32, "repz movsd xmm0, xmm1"
      (* A register with no general-purpose width used to escape as a register
         exception rather than a refusal. *)
      WordSize.Bit32, "mov ecx, cr0"
      WordSize.Bit32, "mov cr0, ecx"
      WordSize.Bit32, "mov ecx, dr0"
      (* 16-bit addressing needs a ModRM layout this assembler does not emit,
         and used to be encoded as though the registers were 32-bit. *)
      WordSize.Bit32, "adc dword ptr [bx+di], edx"
      WordSize.Bit32, "rcl dword ptr [bx+di], 0x11" ]

  /// Runs the given action with stderr muted; see IntelRoundTripTests.
  let mutingStderr action =
    let saved = Console.Error
    Console.SetError TextWriter.Null
    try action () finally Console.SetError saved

  let encode (wordSize: WordSize) source =
    let asm = Assembler(ISA(Architecture.Intel, wordSize), 0UL) :> ILowerable
    try
      match asm.Lower source with
      | Ok encoded ->
        encoded
        |> List.map (Array.map (sprintf "%02x") >> String.concat "")
        |> String.concat " "
      | Error _ -> "<cannot parse>"
    with
    | :? EncodingFailureException -> "<unsupported>"
    | :? NotImplementedException -> "<unsupported>"
    | :? InvalidOperationException -> "<invalid>"
    | :? Collections.Generic.KeyNotFoundException -> "<missing label>"

  [<TestMethod>]
  member _.``An unusable prefix is refused rather than dropped``() =
    let accepted =
      mutingStderr (fun () ->
        rejected
        |> List.choose (fun (wordSize, source) ->
          match encode wordSize source with
          | "<unsupported>" -> None
          | encoded -> Some $"{source} encoded as {encoded}"))
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" accepted,
      "These carry a prefix the instruction cannot take.")

  [<TestMethod>]
  member _.``Golden vectors encode exactly as specified``() =
    let defects =
      mutingStderr (fun () ->
        vectors
        |> List.choose (fun (wordSize, source, expected) ->
          let actual = encode wordSize source
          if actual = expected then None else Some $"{source} => {actual}"))
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" defects,
      "These vectors no longer encode as specified.")
