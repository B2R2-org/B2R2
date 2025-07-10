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

namespace B2R2.FrontEnd.Intel

open System.Runtime.CompilerServices
open B2R2

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.Intel.Tests")>]
[<assembly: InternalsVisibleTo("B2R2.Peripheral.Assembly.Intel")>]
do ()

/// Information about Intel vector extension.
type VEXInfo = {
  VVVV: byte
  VectorLength: RegType
  VEXType: VEXType
  VPrefixes: Prefix
  EVEXPrx: EVEXPrefix option
}

/// Types of VEX (Vector Extension).
and VEXType =
  /// Original VEX that refers to two-byte opcode map.
  | VEXTwoByteOp = 0x1
  /// Original VEX that refers to three-byte opcode map #1.
  | VEXThreeByteOpOne = 0x2
  /// Original VEX that refers to three-byte opcode map #2.
  | VEXThreeByteOpTwo = 0x4
  /// EVEX Mask
  | EVEX = 0x10

/// Vector destination merging/zeroing: P[23] encodes the destination result
/// behavior which either zeroes the masked elements or leave masked element
/// unchanged.
and ZeroingOrMerging =
  | Zeroing
  | Merging

/// Static Rounding Mode and SAE control can be enabled in the encoding of the
/// instruction by setting the EVEX.b bit to 1 in a register-register vector
/// instruction.
and StaticRoundingMode =
  | RN (* Round to nearest (even) + SAE *)
  | RD (* Round down (toward -inf) + SAE *)
  | RU (* Round up (toward +inf) + SAE *)
  | RZ (* Round toward zero (Truncate) + SAE *)

and EVEXPrefix = {
  /// Embedded opmask register specifier, P[18:16].
  AAA: uint8
  /// Zeroing/Merging, P[23].
  Z: ZeroingOrMerging
  /// Broadcast/RC/SAE Context, P[20].
  B: uint8
  /// Reg-reg, FP Instructions w/ rounding semantic or SAE, P2[6:5].
  RC: StaticRoundingMode
}
