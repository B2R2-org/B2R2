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

module B2R2.FrontEnd.ARM32.IRHelper

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp

let getRegVar (ctxt: TranslationContext) reg =
  Register.toRegID reg |> ctxt.GetRegVar

/// Returns TRUE if the implementation includes the Security Extensions,
/// on page B1-1157. function : HaveSecurityExt()
let haveSecurityExt () = AST.b0

/// Returns TRUE if the implementation includes the Virtualization Extensions,
/// on page AppxP-2660. function : HaveVirtExt()
let haveVirtExt () = AST.b0

/// Gets the mask bits for fetching the condition flag bits from the PSR.
/// PSR bit[31:28]
let maskPSRForCondbits = AST.num <| BitVector.OfBInt 4026531840I 32<rt>

/// Gets the mask bits for fetching the N condition flag from the PSR.
/// PSR bit[31]
let maskPSRForNbit = AST.num <| BitVector.OfBInt 2147483648I 32<rt>

/// Gets the mask bits for fetching the Z condition flag from the PSR.
/// PSR bits[30]
let maskPSRForZbit = AST.num <| BitVector.OfBInt 1073741824I 32<rt>

/// Gets the mask bits for fetching the C condition flag from the PSR.
/// PSR bit[29]
let maskPSRForCbit = AST.num <| BitVector.OfBInt 536870912I 32<rt>

/// Gets the mask bits for fetching the V condition flag from the PSR.
/// PSR bit[28]
let maskPSRForVbit = AST.num <| BitVector.OfBInt 268435456I 32<rt>

/// Gets the mask bits for fetching the Q bit from the PSR.
/// PSR bit[27]
let maskPSRForQbit = AST.num <| BitVector.OfBInt 134217728I 32<rt>

/// Gets the mask bits for fetching the IT[1:0] bits from the PSR.
/// PSR bits[26:25]
let maskPSRForIT10bits = AST.num <| BitVector.OfBInt 100663296I 32<rt>

/// Gets the mask bits for fetching the J bit from the PSR.
/// PSR bit[24]
let maskPSRForJbit = AST.num <| BitVector.OfBInt 16777216I 32<rt>

/// Gets the mask bits for fetching the GE[3:0] bits from the PSR.
/// PSR bits[19:16]
let maskPSRForGEbits = AST.num <| BitVector.OfBInt 983040I 32<rt>

/// Gets the mask bits for fetching the IT[7:2] bits from the PSR.
/// PSR bits[15:10]
let maskPSRForIT72bits = AST.num <| BitVector.OfBInt 64512I 32<rt>

/// Gets the mask bits for fetching the E bit from the PSR.
/// PSR bit[9]
let maskPSRForEbit = AST.num <| BitVector.OfBInt 512I 32<rt>

/// Gets the mask bits for fetching the A bit from the PSR.
/// PSR bit[8]
let maskPSRForAbit = AST.num <| BitVector.OfBInt 256I 32<rt>

/// Gets the mask bits for fetching the I bit from the PSR.
/// PSR bit[7]
let maskPSRForIbit = AST.num <| BitVector.OfBInt 128I 32<rt>

/// Gets the mask bits for fetching the F bit from the PSR.
/// PSR bit[6]
let maskPSRForFbit = AST.num <| BitVector.OfBInt 64I 32<rt>

/// Gets the mask bits for fetching the T bit from the PSR.
/// PSR bit[5]
let maskPSRForTbit = AST.num <| BitVector.OfBInt 32I 32<rt>

/// Gets the mask bits for fetching the M[4:0] bits from the PSR.
/// PSR bits[4:0]
let maskPSRForMbits = AST.num <| BitVector.OfBInt 31I 32<rt>

/// Get PSR bits without shifting it.
let internal getPSR ctxt reg psrType =
  let psr = getRegVar ctxt reg
  match psrType with
  | PSR.Cond -> psr .& maskPSRForCondbits
  | PSR.N -> psr .& maskPSRForNbit
  | PSR.Z -> psr .& maskPSRForZbit
  | PSR.C -> psr .& maskPSRForCbit
  | PSR.V -> psr .& maskPSRForVbit
  | PSR.Q -> psr .& maskPSRForQbit
  | PSR.IT10 -> psr .& maskPSRForIT10bits
  | PSR.J -> psr .& maskPSRForJbit
  | PSR.GE -> psr .& maskPSRForGEbits
  | PSR.IT72 -> psr .& maskPSRForIT72bits
  | PSR.E -> psr .& maskPSRForEbit
  | PSR.A -> psr .& maskPSRForAbit
  | PSR.I -> psr .& maskPSRForIbit
  | PSR.F -> psr .& maskPSRForFbit
  | PSR.T -> psr .& maskPSRForTbit
  | PSR.M -> psr .& maskPSRForMbits
  | _ -> Terminator.impossible ()

let isSetCPSRn ctxt = getPSR ctxt R.CPSR PSR.N == maskPSRForNbit
let isSetCPSRz ctxt = getPSR ctxt R.CPSR PSR.Z == maskPSRForZbit
let isSetCPSRc ctxt = getPSR ctxt R.CPSR PSR.C == maskPSRForCbit
let isSetCPSRv ctxt = getPSR ctxt R.CPSR PSR.V == maskPSRForVbit
let isSetCPSRj ctxt = getPSR ctxt R.CPSR PSR.J == maskPSRForJbit
let isSetCPSRt ctxt = getPSR ctxt R.CPSR PSR.T == maskPSRForTbit
let isSetCPSRm ctxt = getPSR ctxt R.CPSR PSR.M == maskPSRForMbits

/// Test whether mode number is valid, on page B1-1142.
/// function : BadMode()
let isBadMode modeM =
  let cond1 = modeM == (numI32 0b10000 32<rt>)
  let cond2 = modeM == (numI32 0b10001 32<rt>)
  let cond3 = modeM == (numI32 0b10010 32<rt>)
  let cond4 = modeM == (numI32 0b10011 32<rt>)
  let cond5 = modeM == (numI32 0b10110 32<rt>)
  let cond6 = modeM == (numI32 0b10111 32<rt>)
  let cond7 = modeM == (numI32 0b11010 32<rt>)
  let cond8 = modeM == (numI32 0b11011 32<rt>)
  let cond9 = modeM == (numI32 0b11111 32<rt>)
  let ite1 = AST.ite cond9 AST.b0 AST.b1
  let ite2 = AST.ite cond8 AST.b0 ite1
  let ite3 = AST.ite cond7 (haveVirtExt () |> AST.not) ite2
  let ite4 = AST.ite cond6 AST.b0 ite3
  let ite5 = AST.ite cond5 (haveSecurityExt () |> AST.not) ite4
  let ite6 = AST.ite cond4 AST.b0 ite5
  let ite7 = AST.ite cond3 AST.b0 ite6
  let ite8 = AST.ite cond2 AST.b0 ite7
  AST.ite cond1 AST.b0 ite8

/// Returns TRUE if current mode is User or System mode, on page B1-1142.
/// function : CurrentModeIsUserOrSystem()
let currentModeIsUserOrSystem ctxt =
  let modeM = getPSR ctxt R.CPSR PSR.M
  let modeCond = isBadMode modeM
  let ite1 = modeM == (numI32 0b11111 32<rt>)
  let ite2 = AST.ite (modeM == (numI32 0b10000 32<rt>)) AST.b1 ite1
  AST.ite modeCond (AST.undef 1<rt> "UNPREDICTABLE") ite2

/// Returns TRUE if current mode is Hyp mode, on page B1-1142.
/// function : CurrentModeIsHyp()
let currentModeIsHyp ctxt =
  let modeM = getPSR ctxt R.CPSR PSR.M
  let modeCond = isBadMode modeM
  let ite1 = modeM == (numI32 0b11010 32<rt>)
  AST.ite modeCond (AST.undef 1<rt> "UNPREDICTABLE") ite1

/// Is this ARM instruction set, on page A2-51.
let isInstrSetARM ctxt =
  AST.not (isSetCPSRj ctxt) .& AST.not (isSetCPSRt ctxt)

/// Is this Thumb instruction set, on page A2-51.
let isInstrSetThumb ctxt = AST.not (isSetCPSRj ctxt) .& (isSetCPSRt ctxt)

/// Is this ThumbEE instruction set, on page A2-51.
let isInstrSetThumbEE ctxt = (isSetCPSRj ctxt) .& (isSetCPSRt ctxt)

