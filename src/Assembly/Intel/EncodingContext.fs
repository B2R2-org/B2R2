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

namespace B2R2.Assembly.Intel

open B2R2
open B2R2.FrontEnd.Intel

/// Represents an assembly encoding context.
type internal EncodingContext(wordSize: WordSize) =
  member _.WordSize with get() = wordSize

  member _.PrefNormal with get() = EncPrefix(Prefix.None, false, false, true)

  member _.PrefREP with get() = EncPrefix(Prefix.None, false, true, true)

  member _.PrefREP66 with get() = EncPrefix(Prefix.OPSIZE, false, true, true)

  member _.PrefF3 with get() = EncPrefix(Prefix.REPZ, false, false, true)

  member _.PrefF2 with get() = EncPrefix(Prefix.REPNZ, false, false, true)

  member _.Pref66 with get() = EncPrefix(Prefix.OPSIZE, false, false, true)

  member _.RexNormal with get() = EncREXPrefix(false, false)

  member _.RexW with get() = EncREXPrefix(true, false)

  member _.RexMR with get() = EncREXPrefix(false, true)

  member _.RexWAndMR with get() = EncREXPrefix(true, true)

  member _.VEX128n0F with get() =
    EncVEXPrefix(VEXType.TwoByteOp, REXPrefix.NOREX, 128<rt>, Prefix.None)

  member _.VEX256n0F with get() =
    EncVEXPrefix(VEXType.TwoByteOp, REXPrefix.NOREX, 256<rt>, Prefix.None)

  member _.VEX128nF3n0F with get() =
    EncVEXPrefix(VEXType.TwoByteOp, REXPrefix.NOREX, 128<rt>, Prefix.REPZ)

  member _.VEX128nF2n0F with get() =
    EncVEXPrefix(VEXType.TwoByteOp, REXPrefix.NOREX, 128<rt>, Prefix.REPNZ)

  member _.VEX128n66n0F with get() =
    EncVEXPrefix(VEXType.TwoByteOp, REXPrefix.NOREX, 128<rt>, Prefix.OPSIZE)

  member _.VEX256n66n0F with get() =
    EncVEXPrefix(VEXType.TwoByteOp, REXPrefix.NOREX, 256<rt>, Prefix.OPSIZE)

  member _.VEX128n66nWn0F with get() =
    EncVEXPrefix(VEXType.TwoByteOp, REXPrefix.REXW, 128<rt>, Prefix.OPSIZE)

  member _.VEX128n66n0F3A with get() =
    EncVEXPrefix(VEXType.ThreeByteOpTwo, REXPrefix.NOREX, 128<rt>,
      Prefix.OPSIZE)

  member _.VEX256n66n0F3A with get() =
    EncVEXPrefix(VEXType.ThreeByteOpTwo, REXPrefix.NOREX, 256<rt>,
      Prefix.OPSIZE)

and internal EncPrefix =
  struct
    val MandPrefix: Prefix (* Mandatory prefix (66H, F2H, or F3H) *)
    val CanLock: bool
    val CanRep: bool
    val CanSeg: bool
    new(m, l, r, s) =
      { MandPrefix = m
        CanLock = l
        CanRep = r
        CanSeg = s }
  end

and internal EncREXPrefix =
  struct
    val RexW: bool
    val IsMemReg: bool
    new(w, mr) =
      { RexW = w
        IsMemReg = mr }
  end

and internal EncVEXPrefix =
  struct
    val LeadingOpcode: VEXType
    val RexW: REXPrefix
    val VecLen: RegType
    val PP: Prefix
    new(vt, w, l, p) =
      { LeadingOpcode = vt
        RexW = w
        VecLen = l
        PP = p }
  end
