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

namespace B2R2.Assembler.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.Assembler.Intel

[<TestClass>]
type X86Tests () =
  let isa = ISA.Init Arch.IntelX86 Endian.Little
  let asm = AsmParser (isa, 0UL)

  [<TestMethod>]
  member __.``Basic Test``() =
    let str = """
  cmp ecx, ecx
  jne cond
  add edx, ecx
  jmp done
cond:
  mov eax, done
  inc ebx
done:
  ret
"""
    let result = asm.Run str
    let expectation =
      [ [| 0x3buy; 0xc9uy |]
        [| 0x75uy; 0x04uy |]
        [| 0x03uy; 0xd1uy |]
        [| 0xebuy; 0x07uy |]
        [| 0x8buy; 0x05uy; 0x0fuy; 0x00uy; 0x00uy; 0x00uy |]
        [| 0x43uy |]
        [| 0xc3uy |] ]
    List.forall2 (fun a b -> a = b) result expectation
    |> Assert.IsTrue
