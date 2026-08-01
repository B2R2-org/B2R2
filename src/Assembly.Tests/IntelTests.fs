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

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.Intel

[<TestClass>]
type IntelTests() =
  let isa = ISA(Architecture.Intel, WordSize.Bit32)
  let asm = Assembler(isa, 0UL) :> ILowerable

  [<TestMethod>]
  member _.``Basic Test``() =
    let str =
      """
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
    let result =
      match asm.Lower str with
      | Ok v -> List.map snd v
      | Error _ -> failwith "Bad value"
    let expectation =
      [ [| 0x3buy; 0xc9uy |]
        [| 0x75uy; 0x04uy |]
        [| 0x03uy; 0xd1uy |]
        [| 0xebuy; 0x07uy |]
        [| 0x8buy; 0x05uy; 0x0fuy; 0x00uy; 0x00uy; 0x00uy |]
        [| 0x43uy |]
        [| 0xc3uy |] ]
    Assert.AreEqual(true, List.forall2 (=) result expectation)

  /// An assembler is meant to be reused across sources. Until the parser state
  /// was cleared at the start of every call, a source that failed to parse left
  /// its segment prefix or far-pointer flag behind, and the next instruction
  /// came out as a far jump, or carried a prefix it never asked for.
  [<TestMethod>]
  member _.``A source that fails to parse leaves nothing behind``() =
    let hex (bytes: byte[]) =
      bytes |> Array.map (sprintf "%02x") |> String.concat ""
    for bad in [ "jmp fword ptr [ecx"; "mov eax, dword ptr [gs:"; "lock " ] do
      (try asm.Lower bad |> ignore with _ -> ())
      match (try asm.Lower "jmp dword ptr [ecx]" with _ -> Error "raised") with
      | Ok((_, bytes) :: _) ->
        Assert.AreEqual<string>("ff21", hex bytes, $"after '{bad}'")
      | Ok [] | Error _ -> Assert.Fail $"'{bad}' left the assembler unusable"
