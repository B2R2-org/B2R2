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

module internal B2R2.FrontEnd.Intel.ParsingFunctions

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.Intel
open LanguagePrimitives

let inline getVVVV b = ~~~(b >>> 3) &&& 0b01111uy

let getVPrefs b =
  match b &&& 0b00000011uy with
  | 0b01uy -> Prefix.OPSIZE
  | 0b10uy -> Prefix.REPZ
  | 0b11uy -> Prefix.REPNZ
  | _ -> Prefix.None

let getTwoVEXInfo (span: ByteSpan) (rex: byref<REXPrefix>) pos =
  let b = span[pos]
  rex <- rex ||| if (b >>> 7) = 0uy then REXPrefix.REXR else REXPrefix.NOREX
  let vLen = if ((b >>> 2) &&& 0b000001uy) = 0uy then 128<rt> else 256<rt>
  { VVVV = getVVVV b
    VectorLength = vLen
    VEXType = VEXType.TwoByteOp
    VPrefixes = getVPrefs b
    EVEXPrx = None }

/// EVEX widened the map selector to the three bits P0[2:0]; a two-byte VEX
/// only ever uses the low two of them.
let pickVEXType b1 =
  match b1 &&& 0b00111uy with
  | 0b001uy -> VEXType.TwoByteOp
  | 0b010uy -> VEXType.ThreeByteOpOne
  | 0b011uy -> VEXType.ThreeByteOpTwo
  | 0b101uy -> VEXType.Map5
  | 0b110uy -> VEXType.Map6
  | _ -> raise ParsingFailureException

let getVREXPref (b1: byte) b2 =
  let w = (b2 &&& 0b10000000uy) >>> 4
  let rxb = (~~~b1) >>> 5
  let rex = w ||| rxb ||| 0b1000000uy
  if rex &&& 0b1111uy = 0uy then REXPrefix.NOREX
  else EnumOfValue<int, REXPrefix>(int rex)

let getThreeVEXInfo (span: ByteSpan) (rex: byref<REXPrefix>) pos =
  let b1 = span[pos]
  let b2 = span[pos + 1]
  let vLen = if ((b2 >>> 2) &&& 0b000001uy) = 0uy then 128<rt> else 256<rt>
  rex <- rex ||| getVREXPref b1 b2
  { VVVV = getVVVV b2
    VectorLength = vLen
    VEXType = pickVEXType b1
    VPrefixes = getVPrefs b2
    EVEXPrx = None }

let getVLen = function
  | 0b00uy -> 128<rt>
  | 0b01uy -> 256<rt>
  | 0b10uy -> 512<rt>
  | 0b11uy -> 0<rt> (* For EVEX Rounding Control *)
  | _ -> raise ParsingFailureException

let getRC = function
  | 0b00uy -> RN
  | 0b01uy -> RD
  | 0b10uy -> RU
  | 0b11uy -> RZ
  | _ -> raise ParsingFailureException

let getEVEXInfo (span: ByteSpan) (rex: byref<REXPrefix>) pos =
  let b1 = span[pos]
  (* P0[3] is the only reserved bit left; P0[2] belongs to the map selector. *)
  if ((b1 >>> 3) &&& 0b1uy) <> 0uy then raise ParsingFailureException
  else ()
  let b2 = span[pos + 1]
  if ((b2 >>> 2) &&& 0b1uy) <> 1uy then raise ParsingFailureException
  else ()
  let l'l = span[pos + 2] >>> 5 &&& 0b011uy
  let vLen = getVLen l'l
  let rc = getRC l'l
  let aaa = span[pos + 2] &&& 0b111uy
  let z = if (span[pos + 2] >>> 7 &&& 0b1uy) = 1uy then Zeroing else Merging
  let b = (span[pos + 2] >>> 4) &&& 0b1uy
  let e = Some { AAA = aaa; Z = z; B = b; RC = rc }
  (* R' (P0[4]) and V' (P2[3]) are stored inverted, like R, X and B. They
     carry the fifth bit of ModRM.reg and of vvvv / the VSIB index. *)
  let r' =
    if ((b1 >>> 4) &&& 0b1uy) = 0uy then REXPrefix.EVEXR
    else REXPrefix.NOREX
  let v' =
    if ((span[pos + 2] >>> 3) &&& 0b1uy) = 0uy then REXPrefix.EVEXV
    else REXPrefix.NOREX
  rex <- rex ||| getVREXPref b1 b2 ||| r' ||| v'
  { VVVV = getVVVV b2
    VectorLength = vLen
    VEXType = pickVEXType b1 ||| VEXType.EVEX
    VPrefixes = getVPrefs b2
    EVEXPrx = e }

let inline newInstruction (phlp: ParsingHelper) opcode oprs =
  Instruction(phlp.InsAddr,
              uint32 (phlp.ParsedLen()),
              phlp.WordSize,
              phlp.Prefixes,
              phlp.REXPrefix,
              phlp.VEXInfo,
              opcode,
              oprs,
              phlp.OperationSize,
              phlp.MemEffAddrSize,
              phlp.IsFar,
              phlp.Lifter)

/// Some instructions use 66/F2/F3 prefix as a mandatory prefix. When both
/// VEX.pp and old-style prefix are used, the VEX.pp is used to select the
/// opcodes. But if VEX.pp does not exist, then we have to use the old-style
/// prefix, and we have to filter out the prefixes because they are not going
/// to be used as a normal prefixes. They will only be used as a mandatory
/// prefix to decide the opcode.
let inline filterPrefs (prefix: Prefix) = prefix &&& Prefix.ClearVEXPrefMask
