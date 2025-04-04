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

namespace B2R2.FrontEnd.API.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.Intel

#if !EMULATION
[<TestClass>]
type IntelLifterTests () =
  let test ctxt wordSize (expectedStmts: string[]) (bytes: byte[]) =
    let parser = IntelParser (wordSize) :> IInstructionParsable
    let ins = parser.Parse (bytes, 0UL) :?> IntelInternalInstruction
    let actual = ins.Translate ctxt |> Array.map Pp.stmtToString
    printfn "%A" actual
    CollectionAssert.AreEqual (expectedStmts, actual)

  let testX86 (hex: string) expectedStmts =
    let isa = ISA.Init Architecture.IntelX86 Endian.Little
    let ctxt = IntelTranslationContext isa
    ByteArray.ofHexString hex
    |> test ctxt WordSize.Bit32 expectedStmts

  let testX64 (hex: string) expectedStmts =
    let isa = ISA.Init Architecture.IntelX64 Endian.Little
    let ctxt = IntelTranslationContext isa
    ByteArray.ofHexString hex
    |> test ctxt WordSize.Bit64 expectedStmts

  [<TestMethod>]
  member __.``[X86] ADD instruction lift Test (1)`` () =
    testX86 "0500000100"
    <| [| "(5) {"
          "T_1:I32 := EAX"
          "T_2:I32 := (T_1:I32 + 0x10000:I32)"
          "EAX := T_2:I32"
          "T_3:I1 := (T_1:I32[31:31])"
          "T_4:I1 := (T_2:I32[31:31])"
          "CF := (T_2:I32 < T_1:I32)"
          "OF := ((T_3:I1 = 0x0:I1) & (T_4:I1 ^ T_3:I1))"
          "AF := (((0x10000:I32 ^ (T_1:I32 ^ T_2:I32)) & 0x10:I32) = 0x10:I32)"
          "SF := T_4:I1"
          "ZF := (T_2:I32 = 0x0:I32)"
          "T_5:I32 := ((T_2:I32 >> 0x4:I32) ^ T_2:I32)"
          "T_6:I32 := ((T_5:I32 >> 0x2:I32) ^ T_5:I32)"
          "PF := (~ (((T_6:I32 >> 0x1:I32) ^ T_6:I32)[0:0]))"
          "} // 5" |]

  [<TestMethod>]
  member __.``[X64] ADD instruction lift Test (1)`` () =
    testX64 "0500000100"
    <| [| "(5) {"
          "T_1:I32 := (RAX[31:0])"
          "T_2:I32 := (T_1:I32 + 0x10000:I32)"
          "RAX := zext:I64(T_2:I32)"
          "T_3:I1 := (T_1:I32[31:31])"
          "T_4:I1 := (T_2:I32[31:31])"
          "CF := (T_2:I32 < T_1:I32)"
          "OF := ((T_3:I1 = 0x0:I1) & (T_4:I1 ^ T_3:I1))"
          "AF := (((0x10000:I32 ^ (T_1:I32 ^ T_2:I32)) & 0x10:I32) = 0x10:I32)"
          "SF := T_4:I1"
          "ZF := (T_2:I32 = 0x0:I32)"
          "T_5:I32 := ((T_2:I32 >> 0x4:I32) ^ T_2:I32)"
          "T_6:I32 := ((T_5:I32 >> 0x2:I32) ^ T_5:I32)"
          "PF := (~ (((T_6:I32 >> 0x1:I32) ^ T_6:I32)[0:0]))"
          "} // 5" |]
#endif
