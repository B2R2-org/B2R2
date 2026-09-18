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

namespace B2R2.FrontEnd.BinFile.Tests

open System
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile.DWARF
open B2R2.FrontEnd.BinFile.ELF
open Microsoft.VisualStudio.TestTools.UnitTesting

/// Represents the exception raised by the DWARF expression parser when the
/// given bytes are not a valid instruction sequence.
type private InvalidDWExpr = DWExpression.InvalidDWInstructionExpException

/// Tests for reading DW_FORM_exprloc values, which are parsed in place from
/// the debug section bytes.
[<TestClass>]
type DWARFTests() =
  static let isa = ISA(Architecture.Intel, Endian.Little, WordSize.Bit64)

  static let regFactory =
    B2R2.FrontEnd.Intel.RegisterFactory isa :> IRegisterFactory

  /// Reads an expression the way a DW_FORM_exprloc attribute value is read,
  /// i.e., out of the bytes of a debug section.
  static let readExpr (bytes: byte[]) len offset =
    DebugInformation.readExpr (ReadOnlySpan bytes) regFactory len offset

  (* DW_OP_breg6 pushes DWARF register 6 (RBP on x64) plus a ULEB128 offset,
     so it is the shortest expression that carries an operand. *)
  let [<Literal>] DWOpBreg6 = 0x76uy

  let [<Literal>] DWOpBreg7 = 0x77uy

  /// Asserts that the given expression is the DWARF register `reg` plus `n`.
  static let assertRegPlusNum reg n (expr: Expr) =
    match expr with
    | BinOp(BinOpType.ADD, _, Var(_, rid, _), Num bv) ->
      Assert.AreEqual(DWRegister.toRegID isa reg, rid)
      Assert.AreEqual<uint64>(n, bv.ToUInt64())
    | _ ->
      Assert.Fail $"Unexpected expression: {PrettyPrinter.ToString expr}"

  [<TestMethod>]
  member _.``[DWARF] expression is read at a non-zero offset``() =
    let bytes = [| 0xaauy; DWOpBreg6; 0x10uy; 0xbbuy |]
    let value, next = readExpr bytes 2 1
    Assert.AreEqual<int>(3, next)
    match value with
    | DWExprLoc expr -> assertRegPlusNum 6uy 0x10UL expr
    | _ -> Assert.Fail $"Unexpected value: {value}"

  [<TestMethod>]
  member _.``[DWARF] consecutive expressions are read independently``() =
    let bytes = [| DWOpBreg6; 0x10uy; DWOpBreg7; 0x08uy |]
    let first, next = readExpr bytes 2 0
    let second, last = readExpr bytes 2 next
    Assert.AreEqual<int>(2, next)
    Assert.AreEqual<int>(4, last)
    match first, second with
    | DWExprLoc e1, DWExprLoc e2 ->
      assertRegPlusNum 6uy 0x10UL e1
      assertRegPlusNum 7uy 0x08UL e2
    | _ ->
      Assert.Fail $"Unexpected values: {first}, {second}"

  [<TestMethod>]
  member _.``[DWARF] expression may end at the end of the input``() =
    let bytes = [| DWOpBreg6; 0x10uy |]
    let value, next = readExpr bytes 2 0
    Assert.AreEqual<int>(2, next)
    match value with
    | DWExprLoc expr -> assertRegPlusNum 6uy 0x10UL expr
    | _ -> Assert.Fail $"Unexpected value: {value}"

  [<TestMethod>]
  member _.``[DWARF] operand does not run past the expression``() =
    (* The ULEB128 operand is cut in the middle, and the byte that follows,
       which belongs to whatever comes next, must not complete it. *)
    let bytes = [| DWOpBreg6; 0x80uy; 0x7fuy |]
    Assert.ThrowsExactly<LEB128.DecodeException>(fun () ->
      readExpr bytes 2 0 |> ignore) |> ignore

  [<TestMethod>]
  member _.``[DWARF] empty expression fails``() =
    let bytes = [| DWOpBreg6; 0x10uy |]
    Assert.ThrowsExactly<InvalidDWExpr>(fun () ->
      readExpr bytes 0 0 |> ignore) |> ignore

  [<TestMethod>]
  member _.``[DWARF] length past the end of the input fails``() =
    let bytes = [| DWOpBreg6; 0x10uy |]
    Assert.ThrowsExactly<ArgumentOutOfRangeException>(fun () ->
      readExpr bytes 3 0 |> ignore) |> ignore
