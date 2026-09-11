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

namespace B2R2.FrontEnd.CIL.Tests

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.CIL
open Microsoft.VisualStudio.TestTools.UnitTesting
open type Opcode

/// Pins what the decoder makes of each shape of operand ECMA-335 gives an
/// instruction: how wide it is, whether it is signed, and, for a branch, that
/// the address it names is counted from the instruction after the branch. A
/// length short by one is the damaging mistake, because a sweep resumes inside
/// the instruction it just read.
[<TestClass>]
type ParserTests() =
  static let parser =
    CILParser(BinReader.Init Endian.Little) :> IInstructionParsable

  let parseAt addr hex =
    let bytes = ByteArray.ofHexString hex
    parser.Parse(ReadOnlySpan bytes, addr) :?> Instruction

  let testAt addr hex (opcode, oprs: Operands, len: uint32) =
    let ins = parseAt addr hex
    Assert.AreEqual<Opcode>(opcode, ins.Opcode)
    Assert.AreEqual<Operands>(oprs, ins.Operands)
    Assert.AreEqual<uint32>(len, ins.Length)

  let test hex expected = testAt 0UL hex expected

  [<TestMethod>]
  member _.``[CIL] Bare Opcode Parse Test``() =
    test "00" (Nop, NoOperand, 1u)
    test "02" (Ldarg_0, NoOperand, 1u)
    test "15" (Ldc_I4_M1, NoOperand, 1u)
    test "8b" (Conv_Ovf_U_Un, NoOperand, 1u)
    test "e0" (Conv_U, NoOperand, 1u)

  [<TestMethod>]
  member _.``[CIL] Two Byte Opcode Parse Test``() =
    test "fe00" (Arglist, NoOperand, 2u)
    test "fe01" (Ceq, NoOperand, 2u)
    test "fe13" (Volatile, NoOperand, 2u)
    test "fe1e" (Readonly, NoOperand, 2u)

  (* The short form carries one byte of index and the long form two, and
     neither is signed. *)
  [<TestMethod>]
  member _.``[CIL] Variable Index Parse Test``() =
    test "0e05" (Ldarg_S, OneOperand(OprVar 5us), 2u)
    test "13ff" (Stloc_S, OneOperand(OprVar 255us), 2u)
    test "fe090001" (Ldarg, OneOperand(OprVar 256us), 4u)
    test "fe0effff" (Stloc, OneOperand(OprVar 65535us), 4u)

  (* The one byte of ldc.i4.s is signed, and is widened to the 32 bits the
     instruction pushes. *)
  [<TestMethod>]
  member _.``[CIL] Integer Constant Parse Test``() =
    test "1fff" (Ldc_I4_S, OneOperand(OprI4 -1), 2u)
    test "1f7f" (Ldc_I4_S, OneOperand(OprI4 127), 2u)
    test "2078563412" (Ldc_I4, OneOperand(OprI4 0x12345678), 5u)
    test "20ffffffff" (Ldc_I4, OneOperand(OprI4 -1), 5u)
    test "21ffffffffffffffff" (Ldc_I8, OneOperand(OprI8 -1L), 9u)
    test "210100000000000080"
      (Ldc_I8, OneOperand(OprI8 0x8000000000000001L), 9u)

  [<TestMethod>]
  member _.``[CIL] Floating Point Constant Parse Test``() =
    test "220000c03f" (Ldc_R4, OneOperand(OprR4 1.5f), 5u)
    test "23000000000000f03f" (Ldc_R8, OneOperand(OprR8 1.0), 9u)

  (* A branch counts its distance from the instruction after it, and the
     distance is signed in both of its widths. *)
  [<TestMethod>]
  member _.``[CIL] Branch Target Parse Test``() =
    testAt 0x1000UL "2b05" (Br_S, OneOperand(OprTarget 0x1007UL), 2u)
    testAt 0x1000UL "2bfe" (Br_S, OneOperand(OprTarget 0x1000UL), 2u)
    testAt 0x1000UL "2d80" (Brtrue_S, OneOperand(OprTarget 0xf82UL), 2u)
    testAt 0x1000UL "3800010000" (Br, OneOperand(OprTarget 0x1105UL), 5u)
    testAt 0x1000UL "38fbffffff" (Br, OneOperand(OprTarget 0x1000UL), 5u)
    testAt 0x1000UL "44ffffffff" (Blt_Un, OneOperand(OprTarget 0x1004UL), 5u)
    testAt 0x1000UL "dd00000000" (Leave, OneOperand(OprTarget 0x1005UL), 5u)
    testAt 0x1000UL "de00" (Leave_S, OneOperand(OprTarget 0x1002UL), 2u)

  (* Every entry of a switch table is counted from the instruction after the
     whole table, not from the entry itself. *)
  [<TestMethod>]
  member _.``[CIL] Switch Parse Test``() =
    testAt 0x1000UL "4500000000" (Switch, OneOperand(OprTargets []), 5u)
    testAt 0x1000UL "450200000002000000fcffffff"
      (Switch, OneOperand(OprTargets [ 0x100fUL; 0x1009UL ]), 13u)

  [<TestMethod>]
  member _.``[CIL] Token Parse Test``() =
    test "2801000006" (Call, OneOperand(OprToken 0x06000001u), 5u)
    test "6f0100000a" (Callvirt, OneOperand(OprToken 0x0a000001u), 5u)
    test "7201000070" (Ldstr, OneOperand(OprToken 0x70000001u), 5u)
    test "d001000002" (Ldtoken, OneOperand(OprToken 0x02000001u), 5u)
    test "fe0601000006" (Ldftn, OneOperand(OprToken 0x06000001u), 6u)
    test "fe1601000002" (Constrained, OneOperand(OprToken 0x02000001u), 6u)
    test "fe1c01000002" (Sizeof, OneOperand(OprToken 0x02000001u), 6u)

  [<TestMethod>]
  member _.``[CIL] Prefix Byte Parse Test``() =
    test "fe1204" (Unaligned, OneOperand(OprByte 4uy), 3u)
    test "fe1901" (No, OneOperand(OprByte 1uy), 3u)

  (* A parser is handed whatever follows the instruction as well, and reads
     none of it. *)
  [<TestMethod>]
  member _.``[CIL] Trailing Bytes Are Not Read Test``() =
    test "00ffffffff" (Nop, NoOperand, 1u)
    test "0e05ffffff" (Ldarg_S, OneOperand(OprVar 5us), 2u)
    test "fe01ffff" (Ceq, NoOperand, 2u)

// vim: set tw=80 sts=2 sw=2:
