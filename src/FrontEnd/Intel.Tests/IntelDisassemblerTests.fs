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
open B2R2.FrontEnd.Intel.Disasm
open type Opcode

[<TestClass>]
type IntelDisassemblerTests () =
  let test wordSize (bytes: byte[]) (instruction: string[]) =
    let reader = BinReader.Init Endian.Little
    let parser = IntelParser (wordSize, reader) :> IInstructionParsable
    let actualInstruction (syntax: DisasmSyntax) =
      setDisassemblyFlavor syntax
      parser.Parse (bytes, 0UL) :?> IntelInstruction
      |> fun instruction -> (instruction.Disasm ()).ToLowerInvariant ()
    Assert.AreEqual<string> (instruction[0], actualInstruction DefaultSyntax)
    Assert.AreEqual<string> (instruction[1], actualInstruction ATTSyntax)

  let testX86 (bytes: byte[], instruction) =
    test WordSize.Bit32 bytes instruction

  let testX64 (bytes: byte[], instruction) =
    test WordSize.Bit64 bytes instruction

  let ( ++ ) byteString pair = (ByteArray.ofHexString byteString, pair)

  [<TestMethod>]
  member _.``X86 ADD instruction test (1)`` () =
    "0500000100" ++ [| "add eax, 0x10000"; "add $0x10000, %eax" |]
    |> testX86

  [<TestMethod>]
  member _.``X86 ADD instruction test (2)`` () =
    "83000a" ++ [| "add dword ptr [eax], 0xa"; "addl $0xa, (%eax)" |]
    |> testX86

  [<TestMethod>]
  // gcc isn't contain '+'
  member _.``X86 ADD instruction test (3)`` () =
    "8340100a"
    ++ [| "add dword ptr [eax+0x10], 0xa"; "addl $0xa, +0x10(%eax)" |]
    |> testX86

  [<TestMethod>]
  member _.``X86 ADD instruction test (4)`` () =
    "8304580a"
    ++ [| "add dword ptr [eax+ebx*2], 0xa"; "addl $0xa, (%eax, %ebx, 2)" |]
    |> testX86

  [<TestMethod>]
  // gcc isn't contain '+'
  member _.``X86 ADD instruction test (5)`` () =
    "838458000100000a"
    ++ [| "add dword ptr [eax+ebx*2+0x100], 0xa"
          "addl $0xa, +0x100(%eax, %ebx, 2)" |]
    |> testX86

  [<TestMethod>]
  member _.``X64 ADD instruction test (6)`` () =
    "480500000100" ++ [| "add rax, 0x10000"; "add $0x10000, %rax" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 ADD instruction test (7)`` () =
    "4883000a" ++ [| "add qword ptr [rax], 0xa"; "addq $0xa, (%rax)" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 ADD instruction test (8)`` () =
    "678340100a"
    ++ [| "add dword ptr [eax+0x10], 0xa"; "addl $0xa, +0x10(%eax)" |]
    |> testX64

  [<TestMethod>]
  member _.``X64 ADD instruction test (9)`` () =
    "678304580a"
    ++ [| "add dword ptr [eax+ebx*2], 0xa"; "addl $0xa, (%eax, %ebx, 2)" |]
    |> testX64

  [<TestMethod>]
  // gcc isn't contain '+'
  member _.``X64 ADD instruction test (10)`` () =
    "67838458000100000a"
    ++ [| "add dword ptr [eax+ebx*2+0x100], 0xa"
          "addl $0xa, +0x100(%eax, %ebx, 2)" |]
    |> testX64
