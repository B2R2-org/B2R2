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

open B2R2

/// Represents the VEX prefix used in Intel instructions.
type VEXInfo =
  { VVVV: byte
    VectorLength: RegType
    VEXType: VEXType
    VPrefixes: Prefix
    EVEXPrx: EVEXPrefix option }

/// Represents the original VEX prefix type (Vector Extension).
and VEXType =
  /// Original VEX that refers to two-byte opcode map.
  | TwoByteOp = 0x1
  /// Original VEX that refers to three-byte opcode map #1.
  | ThreeByteOpOne = 0x2
  /// Original VEX that refers to three-byte opcode map #2.
  | ThreeByteOpTwo = 0x4
  /// EVEX Mask
  | EVEX = 0x10

/// Represents the zeroing or merging behavior of the destination result
/// (P[23] in EVEX encoding).
and ZeroingOrMerging =
  | Zeroing
  | Merging

/// Represents static rounding modes with Suppress All Exceptions (SAE) control,
/// enabled via EVEX.b = 1 in register-register vector instructions.
and StaticRoundingMode =
  | RN (* Round to nearest (even) + SAE *)
  | RD (* Round down (toward -inf) + SAE *)
  | RU (* Round up (toward +inf) + SAE *)
  | RZ (* Round toward zero (Truncate) + SAE *)

/// Represents the EVEX prefix used in Intel instructions.
and EVEXPrefix =
  { /// Embedded opmask register specifier, P[18:16].
    AAA: uint8
    /// Zeroing/Merging, P[23].
    Z: ZeroingOrMerging
    /// Broadcast/RC/SAE Context, P[20].
    B: uint8
    /// Reg-reg, FP Instructions w/ rounding semantic or SAE, P2[6:5].
    RC: StaticRoundingMode }
