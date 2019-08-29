(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Seung Il Jung <sijung@kaist.ac.kr>

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
open B2R2.FrontEnd
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST

let getRegVar (ctxt: TranslationContext) name =
  Register.toRegID name |> ctxt.GetRegVar

/// Returns TRUE if the implementation includes the Security Extensions,
/// on page B1-1157. function : HaveSecurityExt()
let haveSecurityExt () = b0

/// Returns TRUE if the implementation includes the Virtualization Extensions,
/// on page AppxP-2660. function : HaveVirtExt()
let haveVirtExt () = b0

/// Gets the mask bits for fetching the condition flag bits from the PSR.
/// PSR bit[31:28]
let maskPSRForCondbits = num <| BitVector.ofUBInt 4026531840I 32<rt>

/// Gets the mask bits for fetching the N condition flag from the PSR.
/// PSR bit[31]
let maskPSRForNbit = num <| BitVector.ofUBInt 2147483648I 32<rt>

/// Gets the mask bits for fetching the Z condition flag from the PSR.
/// PSR bits[30]
let maskPSRForZbit = num <| BitVector.ofUBInt 1073741824I 32<rt>

/// Gets the mask bits for fetching the C condition flag from the PSR.
/// PSR bit[29]
let maskPSRForCbit = num <| BitVector.ofUBInt 536870912I 32<rt>

/// Gets the mask bits for fetching the V condition flag from the PSR.
/// PSR bit[28]
let maskPSRForVbit = num <| BitVector.ofUBInt 268435456I 32<rt>

/// Gets the mask bits for fetching the Q bit from the PSR.
/// PSR bit[27]
let maskPSRForQbit = num <| BitVector.ofUBInt 134217728I 32<rt>

/// Gets the mask bits for fetching the IT[1:0] bits from the PSR.
/// PSR bits[26:25]
let maskPSRForIT10bits = num <| BitVector.ofUBInt 100663296I 32<rt>

/// Gets the mask bits for fetching the J bit from the PSR.
/// PSR bit[24]
let maskPSRForJbit = num <| BitVector.ofUBInt 16777216I 32<rt>

/// Gets the mask bits for fetching the GE[3:0] bits from the PSR.
/// PSR bits[19:16]
let maskPSRForGEbits = num <| BitVector.ofUBInt 983040I 32<rt>

/// Gets the mask bits for fetching the IT[7:2] bits from the PSR.
/// PSR bits[15:10]
let maskPSRForIT72bits = num <| BitVector.ofUBInt 64512I 32<rt>

/// Gets the mask bits for fetching the E bit from the PSR.
/// PSR bit[9]
let maskPSRForEbit = num <| BitVector.ofUBInt 512I 32<rt>

/// Gets the mask bits for fetching the A bit from the PSR.
/// PSR bit[8]
let maskPSRForAbit = num <| BitVector.ofUBInt 256I 32<rt>

/// Gets the mask bits for fetching the I bit from the PSR.
/// PSR bit[7]
let maskPSRForIbit = num <| BitVector.ofUBInt 128I 32<rt>

/// Gets the mask bits for fetching the F bit from the PSR.
/// PSR bit[6]
let maskPSRForFbit = num <| BitVector.ofUBInt 64I 32<rt>

/// Gets the mask bits for fetching the T bit from the PSR.
/// PSR bit[5]
let maskPSRForTbit = num <| BitVector.ofUBInt 32I 32<rt>

/// Gets the mask bits for fetching the M[4:0] bits from the PSR.
/// PSR bits[4:0]
let maskPSRForMbits = num <| BitVector.ofUBInt 31I 32<rt>

/// Get PSR bits without shifting it.
let internal getPSR ctxt reg psrType =
  let psr = getRegVar ctxt reg
  match psrType with
  | PSR_Cond -> psr .& maskPSRForCondbits
  | PSR_N -> psr .& maskPSRForNbit
  | PSR_Z -> psr .& maskPSRForZbit
  | PSR_C -> psr .& maskPSRForCbit
  | PSR_V -> psr .& maskPSRForVbit
  | PSR_Q -> psr .& maskPSRForQbit
  | PSR_IT10 -> psr .& maskPSRForIT10bits
  | PSR_J -> psr .& maskPSRForJbit
  | PSR_GE -> psr .& maskPSRForGEbits
  | PSR_IT72 -> psr .& maskPSRForIT72bits
  | PSR_E -> psr .& maskPSRForEbit
  | PSR_A -> psr .& maskPSRForAbit
  | PSR_I -> psr .& maskPSRForIbit
  | PSR_F -> psr .& maskPSRForFbit
  | PSR_T -> psr .& maskPSRForTbit
  | PSR_M -> psr .& maskPSRForMbits

let isSetCPSR_N ctxt = getPSR ctxt R.CPSR PSR_N == maskPSRForNbit
let isSetCPSR_Z ctxt = getPSR ctxt R.CPSR PSR_Z == maskPSRForZbit
let isSetCPSR_C ctxt = getPSR ctxt R.CPSR PSR_C == maskPSRForCbit
let isSetCPSR_V ctxt = getPSR ctxt R.CPSR PSR_V == maskPSRForVbit
let isSetCPSR_J ctxt = getPSR ctxt R.CPSR PSR_J == maskPSRForJbit
let isSetCPSR_T ctxt = getPSR ctxt R.CPSR PSR_T == maskPSRForTbit
let isSetCPSR_M ctxt = getPSR ctxt R.CPSR PSR_M == maskPSRForMbits

/// Test whether mode number is valid, on page B1-1142.
/// function : BadMode()
let isBadMode modeM =
  let cond1 = modeM == (num <| BitVector.ofInt32 0b10000 32<rt>)
  let cond2 = modeM == (num <| BitVector.ofInt32 0b10001 32<rt>)
  let cond3 = modeM == (num <| BitVector.ofInt32 0b10010 32<rt>)
  let cond4 = modeM == (num <| BitVector.ofInt32 0b10011 32<rt>)
  let cond5 = modeM == (num <| BitVector.ofInt32 0b10110 32<rt>)
  let cond6 = modeM == (num <| BitVector.ofInt32 0b10111 32<rt>)
  let cond7 = modeM == (num <| BitVector.ofInt32 0b11010 32<rt>)
  let cond8 = modeM == (num <| BitVector.ofInt32 0b11011 32<rt>)
  let cond9 = modeM == (num <| BitVector.ofInt32 0b11111 32<rt>)
  let ite1 = ite cond9 b0 b1
  let ite2 = ite cond8 b0 ite1
  let ite3 = ite cond7 (haveVirtExt () |> not) ite2
  let ite4 = ite cond6 b0 ite3
  let ite5 = ite cond5 (haveSecurityExt () |> not) ite4
  let ite6 = ite cond4 b0 ite5
  let ite7 = ite cond3 b0 ite6
  let ite8 = ite cond2 b0 ite7
  ite cond1 b0 ite8

/// Returns TRUE if current mode is User or System mode, on page B1-1142.
/// function : CurrentModeIsUserOrSystem()
let currentModeIsUserOrSystem ctxt =
  let modeM = getPSR ctxt R.CPSR PSR_M
  let modeCond = isBadMode modeM
  let ite1 = modeM == (num <| BitVector.ofInt32 0b11111 32<rt>)
  let ite2 = ite (modeM == (num <| BitVector.ofInt32 0b10000 32<rt>)) b1 ite1
  ite modeCond (Expr.Undefined (1<rt>, "UNPREDICTABLE")) ite2

/// Returns TRUE if current mode is Hyp mode, on page B1-1142.
/// function : CurrentModeIsHyp()
let currentModeIsHyp ctxt =
  let modeM = getPSR ctxt R.CPSR PSR_M
  let modeCond = isBadMode modeM
  let ite1 = modeM == (num <| BitVector.ofInt32 0b11010 32<rt>)
  ite modeCond (Expr.Undefined (1<rt>, "UNPREDICTABLE")) ite1

/// Is this ARM instruction set, on page A2-51.
let isInstrSetARM ctxt = not (isSetCPSR_J ctxt) .& not (isSetCPSR_T ctxt)

/// Is this Thumb instruction set, on page A2-51.
let isInstrSetThumb ctxt = not (isSetCPSR_J ctxt) .& (isSetCPSR_T ctxt)

/// Is this ThumbEE instruction set, on page A2-51.
let isInstrSetThumbEE ctxt = (isSetCPSR_J ctxt) .& (isSetCPSR_T ctxt)

