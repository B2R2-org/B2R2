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

namespace B2R2.FrontEnd.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinInterface

module EVM =
  open B2R2.FrontEnd.BinLifter.EVM

  let private test opcode (bytes: byte[]) =
    let reader = BinReader.binReaderLE
    let span = System.ReadOnlySpan bytes
    let ins = Parser.parse span reader 0UL WordSize.Bit64 0UL
    let opcode' = ins.Info.Opcode
    Assert.AreEqual (opcode', opcode)

  /// 60s & 70s: Push Operations
  [<TestClass>]
  type PUSHClass () =
    [<TestMethod>]
    member __.``[EVM] Push Parse Test`` () =
      test
        (Opcode.PUSH10 <| (BitVector.OfBInt 316059037807746189465I 80<rt>))
        [| 0x69uy
           0x00uy
           0x11uy
           0x22uy
           0x33uy
           0x44uy
           0x55uy
           0x66uy
           0x77uy
           0x88uy
           0x99uy |]