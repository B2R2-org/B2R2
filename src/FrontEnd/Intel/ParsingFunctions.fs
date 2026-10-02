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
  | 0b100uy -> VEXType.Map4
  | 0b101uy -> VEXType.Map5
  | 0b110uy -> VEXType.Map6
  | 0b111uy -> VEXType.Map7
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

/// The map an XOP payload selects, P0[4:0]: AMD defined 08h, 09h and 0Ah
/// and reserved the rest, which are #UD.
let pickXOPMap b1 =
  match b1 &&& 0b11111uy with
  | 0x08uy -> VEXType.XOPMap8
  | 0x09uy -> VEXType.XOPMap9
  | 0x0Auy -> VEXType.XOPMap10
  | _ -> raise ParsingFailureException

/// Reads the two payload bytes of AMD's XOP prefix (8Fh), which are laid out
/// as the three-byte VEX's: R, X and B inverted above the map selector in
/// the first, and W, vvvv, L and pp in the second. No XOP instruction takes
/// an implied 66h, F3h or F2h, so pp has to be zero. Outside 64-bit mode
/// there are eight registers of each kind, so R, X, B and the top bit of
/// vvvv are ignored there; W still picks the form. AMD64 APM Vol. 3, "VEX
/// and XOP Prefixes".
let getXOPInfo (span: ByteSpan) (rex: byref<REXPrefix>) is64 pos =
  let b1 = if is64 then span[pos] else span[pos] ||| 0b11100000uy
  let b2 = span[pos + 1]
  if b2 &&& 0b11uy <> 0uy then raise ParsingFailureException else ()
  let vLen = if ((b2 >>> 2) &&& 0b000001uy) = 0uy then 128<rt> else 256<rt>
  rex <- rex ||| getVREXPref b1 b2
  { VVVV = if is64 then getVVVV b2 else getVVVV b2 &&& 0b0111uy
    VectorLength = vLen
    VEXType = pickXOPMap b1
    VPrefixes = Prefix.None
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

/// The maps Intel APX added: 4, where the promoted legacy instructions sit,
/// and 7.
let inline private isAPXMap vt = vt = VEXType.Map4 || vt = VEXType.Map7

/// The register bits Intel APX added to the EVEX prefix. P0[3], which was
/// reserved, is B4, the fifth bit of the B register identifier; P1[2], which
/// was fixed at one, is X4 inverted, the fifth bit of the SIB index, where
/// ModRM names memory, and stays one on a register form. Both are 64-bit
/// mode's alone: outside it the old reservations hold. Intel APX spec
/// 355828-007, 3.1.2.3.
let private evexHighRegBits (span: ByteSpan) is64 pos =
  let b4 = (span[pos] >>> 3) &&& 0b1uy <> 0uy
  let x4 = (span[pos + 1] >>> 2) &&& 0b1uy = 0uy
  let isRegForm = span[pos + 4] >= 0xC0uy
  if (b4 || x4) && not is64 then raise ParsingFailureException
  elif x4 && isRegForm then raise ParsingFailureException
  else ()
  (if b4 then REXPrefix.REXB4 else REXPrefix.NOREX)
  ||| (if x4 then REXPrefix.REXX4 else REXPrefix.NOREX)

/// In the APX maps the third payload byte is mostly reserved: its top three
/// bits, the vector instructions' z and L'L, have to be clear, and no REX
/// may sit ahead of the prefix. The bits below them are ND, V4, NF and the
/// low two bits of a source condition code, which the rows read.
let private checkAPXPayload (span: ByteSpan) (rex: REXPrefix) pos =
  if span[pos + 2] &&& 0b11100000uy <> 0uy || rex <> REXPrefix.NOREX then
    raise ParsingFailureException
  else
    ()

/// The third payload byte as the vector instructions read it: the vector
/// length or rounding mode in L'L, the opmask in aaa, and the zeroing and
/// broadcast bits. The APX fields of the prefix are filled in by the row
/// that reads them (see OpcodeMapHelper.finishA).
let private getEVEXPrefix (span: ByteSpan) pos =
  let b3 = span[pos + 2]
  let l'l = b3 >>> 5 &&& 0b011uy
  let aaa = b3 &&& 0b111uy
  let z = if (b3 >>> 7 &&& 0b1uy) = 1uy then Zeroing else Merging
  (* Zeroing with no mask to zero under. The manual gives this as one of the
     #UD conditions of the opmask encoding fields (Vol. 2A, Table 2-42), and it
     holds of every instruction, so it is settled here beside the reserved bits
     rather than asked of a row. *)
  if z = Zeroing && aaa = 0uy then raise ParsingFailureException else ()
  (* The broadcast width is the operand's, so it is filled in once the operands
     have been parsed; see Parser.recordBroadcastWidth. *)
  { AAA = aaa
    Z = z
    B = (b3 >>> 4) &&& 0b1uy
    RC = getRC l'l
    BcstElemSize = 0<rt>
    RCDecor = NoRounding
    ND = false
    NF = false
    SCC = 0uy
    DFV = 0uy }

let getEVEXInfo (span: ByteSpan) (rex: byref<REXPrefix>) is64 pos =
  let b1 = span[pos]
  let b2 = span[pos + 1]
  let vt = pickVEXType b1
  if isAPXMap vt then checkAPXPayload span rex pos else ()
  let highBits = evexHighRegBits span is64 pos
  let e = getEVEXPrefix span pos
  (* R' (P0[4]) and V' (P2[3]) are stored inverted, like R, X and B. They
     carry the fifth bit of ModRM.reg and of vvvv / the VSIB index. *)
  let r' =
    if ((b1 >>> 4) &&& 0b1uy) = 0uy then REXPrefix.EVEXR
    else REXPrefix.NOREX
  let v' =
    if ((span[pos + 2] >>> 3) &&& 0b1uy) = 0uy then REXPrefix.EVEXV
    else REXPrefix.NOREX
  rex <- rex ||| getVREXPref b1 b2 ||| r' ||| v' ||| highBits
  { VVVV = getVVVV b2
    VectorLength = getVLen (span[pos + 2] >>> 5 &&& 0b011uy)
    VEXType = vt ||| VEXType.EVEX
    VPrefixes = getVPrefs b2
    EVEXPrx = Some e }

/// Reads the payload byte of a REX2 prefix (D5h) into the REX and returns
/// the legacy map its M0 bit selects: 0 for the one-byte map, 1 for the 0Fh
/// map. The low four bits are REX's W, R, X and B; above them sit the fifth
/// register bits B4, X4 and R4, which read as the EVEX ones do. Intel APX
/// spec 355828-007, 3.1.2.1.
let getREX2Info (span: ByteSpan) (rex: byref<REXPrefix>) pos =
  let b = span[pos]
  let low = EnumOfValue<int, REXPrefix>(int b &&& 0b1111)
  let none = REXPrefix.NOREX
  let b4 = if b &&& 0b00010000uy <> 0uy then REXPrefix.REXB4 else none
  let x4 = if b &&& 0b00100000uy <> 0uy then REXPrefix.REXX4 else none
  let r4 = if b &&& 0b01000000uy <> 0uy then REXPrefix.EVEXR else none
  rex <- REXPrefix.REX ||| REXPrefix.REX2 ||| low ||| b4 ||| x4 ||| r4
  int (b >>> 7)

// vim: set tw=80 sts=2 sw=2:
