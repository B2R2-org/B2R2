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

namespace B2R2.Peripheral.Assembly.Intel

open B2R2
open B2R2.FrontEnd.BinLifter.Intel

exception NotEncodableException

/// Basic components for assembling binaries.
type AsmComponent =
  | Normal of byte
  | IncompLabel of RegType
  | IncompleteOp of Opcode * Operands
  | CompOp of Opcode * Operands * byte [] * byte [] option

type EncodedByteCode = {
  Prefix        : AsmComponent []
  REXPrefix     : AsmComponent []
  Opcode        : AsmComponent []
  ModRM         : AsmComponent []
  SIB           : AsmComponent []
  Displacement  : AsmComponent []
  Immediate     : AsmComponent []
}

type EncPrefix =
  struct
    val MandPrefix: Prefix (* Mandatory prefix (66H, F2H, or F3H) *)
    val CanLock: bool
    val CanRep: bool
    val CanSeg: bool
    new (m, l, r, s) =
      { MandPrefix = m
        CanLock = l
        CanRep = r
        CanSeg = s }
  end

type EncREXPrefix =
  struct
    val RexW: bool
    val IsMemReg: bool
    new (w, mr) =
      { RexW = w
        IsMemReg = mr }
  end

type EncVEXPrefix =
  struct
    val LeadingOpcode: VEXType
    val RexW: REXPrefix
    val VecLen: RegType
    val PP: Prefix
    new (vt, w, l, p) =
      { LeadingOpcode = vt
        RexW = w
        VecLen = l
        PP = p }
  end

type EncContext (arch: Architecture) =
  member val Arch = arch
  member val PrefNormal = EncPrefix (Prefix.PrxNone, false, false, true)
  member val PrefREP = EncPrefix (Prefix.PrxNone, false, true, true)
  member val PrefREP66 = EncPrefix (Prefix.PrxOPSIZE, false, true, true)
  member val PrefF3 = EncPrefix (Prefix.PrxREPZ, false, false, true)
  member val PrefF2 = EncPrefix (Prefix.PrxREPNZ, false, false, true)
  member val Pref66 = EncPrefix (Prefix.PrxOPSIZE, false, false, true)

  member val RexNormal = EncREXPrefix (false, false)
  member val RexW = EncREXPrefix (true, false)
  member val RexMR = EncREXPrefix (false, true)
  member val RexWAndMR = EncREXPrefix (true, true)

  member val VEX128n0F =
    EncVEXPrefix (VEXType.VEXTwoByteOp, REXPrefix.NOREX, 128<rt>,
                  Prefix.PrxNone)
  member val VEX256n0F =
    EncVEXPrefix (VEXType.VEXTwoByteOp, REXPrefix.NOREX, 256<rt>,
                  Prefix.PrxNone)
  member val VEX128nF3n0F =
    EncVEXPrefix (VEXType.VEXTwoByteOp, REXPrefix.NOREX, 128<rt>,
                  Prefix.PrxREPZ)
  member val VEX128nF2n0F =
    EncVEXPrefix (VEXType.VEXTwoByteOp, REXPrefix.NOREX, 128<rt>,
                  Prefix.PrxREPNZ)
  member val VEX128n66n0F =
    EncVEXPrefix (VEXType.VEXTwoByteOp, REXPrefix.NOREX, 128<rt>,
                  Prefix.PrxOPSIZE)
  member val VEX256n66n0F =
    EncVEXPrefix (VEXType.VEXTwoByteOp, REXPrefix.NOREX, 256<rt>,
                  Prefix.PrxOPSIZE)
  member val VEX128n66nWn0F =
    EncVEXPrefix (VEXType.VEXTwoByteOp, REXPrefix.REXW, 128<rt>,
                  Prefix.PrxOPSIZE)
  member val VEX128n66n0F3A =
    EncVEXPrefix (VEXType.VEXThreeByteOpTwo, REXPrefix.NOREX, 128<rt>,
                  Prefix.PrxOPSIZE)
  member val VEX256n66n0F3A =
    EncVEXPrefix (VEXType.VEXThreeByteOpTwo, REXPrefix.NOREX, 256<rt>,
                  Prefix.PrxOPSIZE)

// vim: set tw=80 sts=2 sw=2:
