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

namespace B2R2.FrontEnd.BinFile.ELF

open B2R2
open B2R2.BinIR

/// Represents an entry (a row) of the call frame information table (i.e.,
/// unwinding table).
type UnwindingEntry =
  { /// Instruction location.
    Location: Addr
    /// CFA.
    CanonicalFrameAddress: CanonicalFrameAddress
    /// Unwinding rule.
    Rule: UnwindingRule }

/// Represents a rule describing how a register or return address is saved on
/// the stack frame. We can use the rule to find the value for the register in
/// the previous frame.
and UnwindingRule = Map<UnwindingTarget, UnwindingAction>

/// Represents a unwinding target, which can be either a return address or a
/// normal register.
and UnwindingTarget =
  | ReturnAddress
  | NormalReg of RegisterID

/// Represents unwinding action that can be performed to restore a register
/// value during stack unwinding. This is referred to as "register rules" in
/// the DWARF specification.
and UnwindingAction =
  /// Has no recoverable value in the previous frame.
  | Undefined
  /// The register has not been modified from the previous frame.
  | SameValue
  /// The previous value of this register is saved at the address CFA+N where
  /// CFA is the current CFA value and N is a signed offset.
  | Offset of int64
  /// The previous value of this register is the value CFA+N where CFA is the
  /// current CFA value and N is a signed offset.
  | ValOffset of int
  /// The previous value of this register is stored in another register numbered
  /// R.
  | Register of RegisterID
  /// The previous value is located at the address produced by evaluating the
  /// expression.
  | ActionExpr of LowUIR.Expr
  /// The previous value is represented as the value produced by evaluating the
  /// expression.
  | ActionValExpr of LowUIR.Expr
with
  /// Returns a string representation of the unwinding action.
  static member ToString act =
    match act with
    | Undefined -> "undef"
    | SameValue -> "sv"
    | Offset o -> "c" + (o.ToString("+0;-#"))
    | ValOffset o -> "v" + (o.ToString("+0;-#"))
    | Register rid -> "r(" + rid.ToString() + ")"
    | ActionExpr e -> "exp:" + LowUIR.Pp.expToString e
    | ActionValExpr e -> "val_exp:" + LowUIR.Pp.expToString e
