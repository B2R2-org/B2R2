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

namespace B2R2.FrontEnd.WASM.Tests

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.WASM
open Microsoft.VisualStudio.TestTools.UnitTesting
open type Opcode

/// Pins the decoding of the immediates WASM encodes with LEB128, whose length
/// the decoder has to derive from the bytes themselves. Every case here is one
/// wabt's own decoder read differently, and each stands for a class the
/// encoding space repeats: a signed immediate read as unsigned, an operand the
/// decoder skipped, and a length that drifted from what the instruction spans.
/// A length that is short by one is the damaging shape, because the sweep that
/// follows resumes inside the instruction it just read.
[<TestClass>]
type ParserTests() =
  static let parser =
    WASMParser(BinReader.Init Endian.Little) :> IInstructionParsable

  let test hex (opcode, oprs: Operands, len: uint32) =
    let bytes = ByteArray.ofHexString hex
    let ins = parser.Parse(ReadOnlySpan bytes, 0UL) :?> Instruction
    Assert.AreEqual<Opcode>(opcode, ins.Opcode)
    Assert.AreEqual<Operands>(oprs, ins.Operands)
    Assert.AreEqual<uint32>(len, ins.Length)

  [<TestMethod>]
  member _.``[WASM] Signed LEB128 Immediate Parse Test``() =
    test "417b" (I32Const, OneOperand(I32 -5), 2u)
    test "42ff7e" (I64Const, OneOperand(I64 -129L), 3u)

  [<TestMethod>]
  member _.``[WASM] Vector Immediate Parse Test``() =
    (* br_table carries a default label after its vector; select carries
       nothing after its own. *)
    test "0e02010203" (BrTable, Operands [ Index 1u; Index 2u; Index 3u ], 5u)
    test "1c017f" (SelectT, Operands [ Type -1 ], 3u)

  [<TestMethod>]
  member _.``[WASM] Omitted Immediate Parse Test``() =
    test "fc0d00" (ElemDrop, OneOperand(Index 0u), 3u)
    test "d06f" (RefNull, OneOperand(RefType -17), 2u)

  [<TestMethod>]
  member _.``[WASM] Splat Reads No Memarg Parse Test``() =
    (* The lane-splat instructions take their input off the stack; only the
       load-and-splat ones next to them in the table carry a memarg. *)
    test "fd0f" (I8X16Splat, NoOperand, 2u)
    test "fd0a0004" (V128Load64Splat, TwoOperands(Alignment 0u, Address 4u), 4u)

  [<TestMethod>]
  member _.``[WASM] Memarg Carries A Memory Index Parse Test``() =
    (* Bit 6 of the alignment field says an explicit memory index follows, so
       the same instruction spans three fields instead of two. *)
    test "280205" (I32Load, TwoOperands(Alignment 2u, Address 5u), 3u)
    test "28420005"
      (I32Load, ThreeOperands(Alignment 2u, Index 0u, Address 5u), 4u)

  [<TestMethod>]
  member _.``[WASM] SIMD Opcode Is LEB128 Parse Test``() =
    test "fd8001" (I16X8Abs, NoOperand, 3u)
    test "fd8002" (I8X16RelaxedSwizzle, NoOperand, 3u)

  [<TestMethod>]
  member _.``[WASM] Atomic RMW Opcode Parse Test``() =
    test "fe260000" (I64AtomicRmwSub, TwoOperands(Alignment 0u, Address 0u), 4u)
