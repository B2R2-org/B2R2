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
  /// EVEX that refers to map 5, the AVX512-FP16 counterpart of the two-byte
  /// map.
  | Map5 = 0x8
  /// EVEX Mask
  | EVEX = 0x10
  /// EVEX that refers to map 6, the AVX512-FP16 counterpart of the 0F38 map.
  | Map6 = 0x20
  /// EVEX map 4, where Intel APX puts the legacy instructions it promotes.
  | Map4 = 0x40
  /// EVEX map 7, the immediate forms of the MSR instructions.
  | Map7 = 0x80
  /// AMD's XOP prefix (8Fh) selecting its map 8, the vector forms that carry
  /// an immediate byte or an /is4 register beside their operands.
  | XOPMap8 = 0x100
  /// XOP map 9: the remaining vector forms, TBM, and the LWP control block
  /// instructions.
  | XOPMap9 = 0x200
  /// XOP map 0Ah: BEXTR with an immediate, LWPINS and LWPVAL.
  | XOPMap10 = 0x400

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

/// Represents what EVEX.b means on a register form: the bit is shared, and
/// only the instruction it sits on separates the two readings. Either one
/// spends EVEX.L'L, which is why a form carrying one is always 512 bits wide
/// however L'L reads.
and RoundingDecor =
  /// EVEX.b names no rounding here: it is clear, or the operand it applies to
  /// is in memory, where it means an embedded broadcast instead.
  | NoRounding
  /// The instruction takes a rounding mode, which L'L holds, and suppresses
  /// exceptions with it.
  | StaticRounding
  /// The instruction suppresses exceptions but takes no rounding mode; L'L
  /// holds nothing.
  | SuppressAllExceptions

/// Represents the EVEX prefix used in Intel instructions.
and EVEXPrefix =
  { /// Embedded opmask register specifier, P[18:16].
    AAA: uint8
    /// Zeroing/Merging, P[23].
    Z: ZeroingOrMerging
    /// Broadcast/RC/SAE Context, P[20].
    B: uint8
    /// Reg-reg, FP Instructions w/ rounding semantic or SAE, P2[6:5].
    RC: StaticRoundingMode
    /// The width of the one element an embedded broadcast reads, or 0<rt> when
    /// no operand of this encoding declared a broadcast form. Unlike the fields
    /// above this one does not come from the prefix bytes: the operand declares
    /// it, and B alone cannot stand in for it. An FP16 element is 16 bits wide
    /// with either setting of REX.W, and a converting instruction reads an
    /// element narrower than the lane it fills.
    BcstElemSize: RegType
    /// Which reading of B applies here, which likewise only the matched
    /// instruction settles. NoRounding whenever B is clear.
    RCDecor: RoundingDecor
    /// EVEX.ND of an Intel APX instruction: a new data destination in vvvv,
    /// or zero-upper where the instruction has no destination to add. False
    /// where the prefix is not APX's.
    ND: bool
    /// EVEX.NF of an Intel APX instruction: the status flags are left as
    /// they were. False where the bit picks a form instead (CFCMOVcc) and
    /// where the prefix is not APX's.
    NF: bool
    /// The source condition code of CCMPscc and CTESTscc, P2[3:0]; zero on
    /// every other instruction.
    SCC: uint8
    /// The default flags value of CCMPscc and CTESTscc, EVEX.[OF,SF,ZF,CF]
    /// in P1[6:3]; zero on every other instruction.
    DFV: uint8 }
