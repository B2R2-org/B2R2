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

/// Tests for reading DWARF data in place from section bytes: DW_FORM_exprloc
/// values, and the call frame instructions of an FDE.
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
    | BinOp(Op = BinOpType.ADD
            Left = Var(RegisterID = rid)
            Right = Num(Value = bv)) ->
      Assert.AreEqual(DWRegister.toRegID isa reg, rid)
      Assert.AreEqual<uint64>(n, bv.ToUInt64())
    | _ ->
      Assert.Fail $"Unexpected expression: {PrettyPrinter.ToString expr}"

  static let rsp = DWRegister.toRegID isa 7uy

  /// Represents the CIE an x64 FDE starts from: the CFA is rsp+8 with the
  /// return address (DWARF register 16) at CFA-8, and offsets are factored by
  /// -8.
  static let x64CIE =
    { Version = 1uy
      AugmentationString = "zR"
      CodeAlignmentFactor = 1UL
      DataAlignmentFactor = -8L
      ReturnAddressRegister = 16uy
      InitialUnwinding =
        lazy
          { Rule = Map.ofList [ ReturnAddress, Offset -8L ]
            CFARegister = 7uy
            CFA = RegPlusOffset(rsp, 8) }
      Augmentations = [] }

  /// Interprets the given call frame instructions as those of an x64 FDE, and
  /// returns the last row they produce.
  static let unwind (bytes: byte[]) =
    let instrs = ReadOnlyMemory bytes
    (FDE.parseCallFrameInstrs x64CIE isa regFactory instrs 0UL).Value
    |> List.last

  /// Asserts that the CFA of the given row is rsp plus n.
  static let assertCFA n (row: UnwindingEntry) =
    let expected = RegPlusOffset(rsp, n)
    Assert.AreEqual<CanonicalFrameAddress>(expected, row.CanonicalFrameAddress)

  let [<Literal>] DWCFAOffsetExtended = 0x05uy

  let [<Literal>] DWCFAUndefined = 0x07uy

  let [<Literal>] DWCFADefCFAOffset = 0x0euy

  let [<Literal>] DWCFAExpression = 0x10uy

  let [<Literal>] DWCFAValExpression = 0x16uy

  [<TestMethod>]
  member _.``[DWARF] string value ends past its terminator``() =
    (* "ab\0cd\0", i.e., an inline string followed by another attribute. *)
    let bytes = [| 0x61uy; 0x62uy; 0x00uy; 0x63uy; 0x64uy; 0x00uy |]
    let first, next = DebugInformation.readCStringValue (ReadOnlySpan bytes) 0
    let span = ReadOnlySpan bytes
    let second, last = DebugInformation.readCStringValue span next
    Assert.AreEqual(DWString "ab", first)
    Assert.AreEqual<int>(3, next)
    Assert.AreEqual(DWString "cd", second)
    Assert.AreEqual<int>(6, last)

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

  [<TestMethod>]
  member _.``[DWARF] undefined register leaves the CFA register``() =
    (* rip, the return address, becomes undefined; the CFA then moves to 16
       bytes past its register, which must still be rsp. *)
    [| DWCFAUndefined; 0x10uy; DWCFADefCFAOffset; 0x10uy |]
    |> unwind
    |> assertCFA 16

  [<TestMethod>]
  member _.``[DWARF] register expression leaves the CFA register``() =
    (* rbx is saved at the address rsp+8 evaluates to. *)
    let saveRbx = [| DWCFAExpression; 0x03uy; 0x02uy; DWOpBreg7; 0x08uy |]
    Array.append saveRbx [| DWCFADefCFAOffset; 0x10uy |]
    |> unwind
    |> assertCFA 16

  [<TestMethod>]
  member _.``[DWARF] value expression leaves the CFA register``() =
    (* rbx is the value rsp+8 evaluates to. *)
    let setRbx = [| DWCFAValExpression; 0x03uy; 0x02uy; DWOpBreg7; 0x08uy |]
    Array.append setRbx [| DWCFADefCFAOffset; 0x10uy |]
    |> unwind
    |> assertCFA 16

  [<TestMethod>]
  member _.``[DWARF] extended offset is factored by the data alignment``() =
    (* rbx is saved two slots below the CFA, a slot being -8 bytes. *)
    let row = unwind [| DWCFAOffsetExtended; 0x03uy; 0x02uy |]
    let rbx = NormalReg(DWRegister.toRegID isa 3uy)
    let saved = Map.tryFind rbx row.Rule
    Assert.AreEqual<UnwindingAction option>(Some(Offset -16L), saved)
