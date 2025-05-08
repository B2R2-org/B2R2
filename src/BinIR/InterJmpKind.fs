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

namespace B2R2.BinIR

/// Represents the kind of an InterJmp (inter-instruction jump) statement, such
/// as a call, return, etc. A jump statement can have a combination of these
/// kinds.
[<System.Flags>]
type InterJmpKind =
  /// The base case, i.e., a simple jump instruction.
  | Base = 0
  /// A call to a function.
  | IsCall = 1
  /// A return from a function.
  | IsRet = 2
  /// An exit, which will terminate the process.
  | IsExit = 4
  /// A branch instruction that modifies the operation mode from Thumb to ARM.
  | SwitchToARM = 8
  /// A branch instruction that modifies the operation mode from ARM to Thumb.
  | SwitchToThumb = 16
  /// This is not a jump instruction. This is only useful in special cases such
  /// as when representing a delay slot of MIPS, and should never be used in
  /// other cases.
  | NotAJmp = -1
