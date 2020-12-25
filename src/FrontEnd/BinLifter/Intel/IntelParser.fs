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

module B2R2.FrontEnd.BinLifter.Intel.Parser

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.Intel
open B2R2.FrontEnd.BinLifter.Intel.RegGroup
open B2R2.FrontEnd.BinLifter.Intel.Helper
open LanguagePrimitives

#if !EMULATION
let inline ensure32 (t: TemporaryInfo) =
  if WordSize.is64 t.TWordSize then raise ParsingFailureException else ()

let inline ensure64 (t: TemporaryInfo) =
  if WordSize.is32 t.TWordSize then raise ParsingFailureException else ()

let inline ensureVEX128 (t: TemporaryInfo) =
  match t.TVEXInfo with
  | Some { VectorLength = 256<rt> } -> raise ParsingFailureException
  | _ -> ()
#endif

let rec prefixLoop (reader: BinReader) pos acc =
  let nextPos = pos + 1
  match reader.PeekByte pos with
  | 0xF0uy ->
    prefixLoop reader nextPos (Prefix.PrxLOCK ||| (clearGrp1PrefMask &&& acc))
  | 0xF2uy ->
    prefixLoop reader nextPos (Prefix.PrxREPNZ ||| (clearGrp1PrefMask &&& acc))
  | 0xF3uy ->
    prefixLoop reader nextPos (Prefix.PrxREPZ ||| (clearGrp1PrefMask &&& acc))
  | 0x2Euy ->
    prefixLoop reader nextPos (Prefix.PrxCS ||| (clearSegMask &&& acc))
  | 0x36uy ->
    prefixLoop reader nextPos (Prefix.PrxSS ||| (clearSegMask &&& acc))
  | 0x3Euy ->
    prefixLoop reader nextPos (Prefix.PrxDS ||| (clearSegMask &&& acc))
  | 0x26uy ->
    prefixLoop reader nextPos (Prefix.PrxES ||| (clearSegMask &&& acc))
  | 0x64uy ->
    prefixLoop reader nextPos (Prefix.PrxFS ||| (clearSegMask &&& acc))
  | 0x65uy ->
    prefixLoop reader nextPos (Prefix.PrxGS ||| (clearSegMask &&& acc))
  | 0x66uy ->
    prefixLoop reader nextPos (Prefix.PrxOPSIZE ||| acc)
  | 0x67uy ->
    prefixLoop reader nextPos (Prefix.PrxADDRSIZE ||| acc)
  | _opcode -> struct (acc, pos)

let inline parsePrefix reader pos =
  prefixLoop reader pos Prefix.PrxNone

let inline parseREX wordSize (reader: BinReader) pos =
  if wordSize = WordSize.Bit32 then struct (REXPrefix.NOREX, pos)
  else
    let rb = reader.PeekByte pos |> int
    if rb &&& 0b11110000 = 0b01000000 then struct (EnumOfValue rb, pos + 1)
    else struct (REXPrefix.NOREX, pos)

let inline getVVVV b = (b >>> 3) &&& 0b01111uy

let getVPrefs b =
  match b &&& 0b00000011uy with
  | 0b01uy -> Prefix.PrxOPSIZE
  | 0b10uy -> Prefix.PrxREPZ
  | 0b11uy -> Prefix.PrxREPNZ
  | _ -> Prefix.PrxNone

let getTwoVEXInfo (reader: BinReader) pos =
  let b = reader.PeekByte pos
  let rexPref = if (b >>> 7) = 0uy then REXPrefix.REXR else REXPrefix.NOREX
  let vLen = if ((b >>> 2) &&& 0b000001uy) = 0uy then 128<rt> else 256<rt>
  { VVVV = getVVVV b
    VectorLength = vLen
    VEXType = VEXType.VEXTwoByteOp
    VPrefixes = getVPrefs b
    VREXPrefix = rexPref
    EVEXPrx = None }

let pickVEXType b1 =
  match b1 &&& 0b00011uy with
  | 0b01uy -> VEXType.VEXTwoByteOp
  | 0b10uy -> VEXType.VEXThreeByteOpOne
  | 0b11uy -> VEXType.VEXThreeByteOpTwo
  | _ -> raise ParsingFailureException

let getVREXPref (b1: byte) b2 =
  let w = (b2 &&& 0b10000000uy) >>> 4
  let rxb = (~~~ b1) >>> 5
  let rex = w ||| rxb ||| 0b1000000uy
  if rex &&& 0b1111uy = 0uy then REXPrefix.NOREX
  else EnumOfValue (int rex)

let getThreeVEXInfo (reader: BinReader) pos =
  let b1 = reader.PeekByte pos
  let b2 = reader.PeekByte (pos + 1)
  let vLen = if ((b2 >>> 2) &&& 0b000001uy) = 0uy then 128<rt> else 256<rt>
  { VVVV = getVVVV b2
    VectorLength = vLen
    VEXType = pickVEXType b1
    VPrefixes = getVPrefs b2
    VREXPrefix = getVREXPref b1 b2
    EVEXPrx = None }

let getVLen = function
  | 0b00uy -> 128<rt>
  | 0b01uy -> 256<rt>
  | 0b10uy -> 512<rt>
  | 0b11uy -> raise ParsingFailureException
  | _ -> raise ParsingFailureException

let getEVEXInfo (reader: BinReader) pos =
  let b1 = reader.PeekByte pos
  let b2 = reader.PeekByte (pos + 1)
  let l'l = reader.PeekByte (pos + 2) >>> 5 &&& 0b011uy
  let vLen = getVLen l'l
  let aaa = reader.PeekByte (pos + 2) &&& 0b111uy
  let z = if (reader.PeekByte (pos + 2) >>> 7 &&& 0b1uy) = 0uy then Zeroing
          else Merging
  let b = (reader.PeekByte (pos + 2) >>> 4) &&& 0b1uy
  let e = Some { AAA = aaa; Z = z; B = b }
  { VVVV = getVVVV b2
    VectorLength = vLen
    VEXType = pickVEXType b1 ||| VEXType.EVEX
    VPrefixes = getVPrefs b2
    VREXPrefix = getVREXPref b1 b2
    EVEXPrx = e }

let inline isVEX (reader: BinReader) wordSize pos =
  (wordSize = WordSize.Bit64) || (reader.PeekByte pos >= 0xC0uy)

/// Parse the VEX prefix (VEXInfo).
let inline parseVEXInfo wordSize (reader: BinReader) pos =
  let nextPos = pos + 1
  match reader.PeekByte pos with
  | 0xC5uy when isVEX reader wordSize nextPos ->
    struct (Some <| getTwoVEXInfo reader nextPos, nextPos + 1)
  | 0xC4uy when isVEX reader wordSize nextPos ->
    struct (Some <| getThreeVEXInfo reader nextPos, nextPos + 2)
  | 0x62uy when isVEX reader wordSize nextPos ->
    struct (Some <| getEVEXInfo reader nextPos, nextPos + 3)
  | _ -> struct (None, pos)

let getOprSize size sizeCond =
  if sizeCond = SzCond.F64 ||
    (size = 32<rt> && sizeCond = SzCond.D64) then 64<rt>
  else size

let getSize32 prefs =
  if hasOprSz prefs then
    if hasAddrSz prefs then struct (16<rt>, 16<rt>)
    else struct (16<rt>, 32<rt>)
  else
    if hasAddrSz prefs then struct (32<rt>, 16<rt>)
    else struct (32<rt>, 32<rt>)

let getSize64 prefs rexPref sizeCond =
  if hasREXW rexPref then
    if hasAddrSz prefs then struct (64<rt>, 32<rt>)
    else struct (64<rt>, 64<rt>)
  else
    if hasOprSz prefs then
      if hasAddrSz prefs then struct (getOprSize 16<rt> sizeCond, 32<rt>)
      else struct (getOprSize 16<rt> sizeCond, 64<rt>)
    else
      if hasAddrSz prefs then
        struct (getOprSize 32<rt> sizeCond, 32<rt>)
      else struct (getOprSize 32<rt> sizeCond, 64<rt>)

let inline selectREX t =
  match t.TVEXInfo with
  | None -> t.TREXPrefix
  | Some v -> v.VREXPrefix

let inline getSize t sizeCond =
  if t.TWordSize = WordSize.Bit32 then getSize32 t.TPrefixes
  else getSize64 t.TPrefixes (selectREX t) sizeCond

let exceptionalOperationSize opcode insSize =
  match opcode with
  | Opcode.PUSH | Opcode.POP ->
    { insSize with OperationSize = insSize.MemEffOprSize }
  | Opcode.MOVSB | Opcode.INSB
  | Opcode.STOSB | Opcode.LODSB
  | Opcode.OUTSB | Opcode.SCASB -> { insSize with OperationSize = 8<rt> }
  | Opcode.OUTSW -> { insSize with OperationSize = 16<rt> }
  | Opcode.OUTSD -> { insSize with OperationSize = 32<rt> }
  | _ -> insSize

let newInsInfo t (rhlp: ReadHelper) opcode oprs insSize =
  let ins =
    { Prefixes = t.TPrefixes
      REXPrefix = t.TREXPrefix
      VEXInfo = t.TVEXInfo
      Opcode = opcode
      Operands = oprs
      InsSize = insSize }
  IntelInstruction (rhlp.InsAddr, uint32 (rhlp.ParsedLen ()), ins, t.TWordSize)

let render t (rhlp: ReadHelper) opcode szCond fnOperand fnSize =
  let struct (effOprSize, effAddrSize) = getSize t szCond
  let insSize = fnSize t effOprSize effAddrSize
  let insSize = exceptionalOperationSize opcode insSize
  let struct (oprs, insSize) = fnOperand t rhlp insSize
  newInsInfo t rhlp opcode oprs insSize

(* Table A-7/15 of Volume 2
   (D8/DC Opcode Map When ModR/M Byte is within 00H to BFH) *)
let getD8OpWithin00toBF b =
  match getReg b with
  | 0b000 -> Opcode.FADD
  | 0b001 -> Opcode.FMUL
  | 0b010 -> Opcode.FCOM
  | 0b011 -> Opcode.FCOMP
  | 0b100 -> Opcode.FSUB
  | 0b101 -> Opcode.FSUBR
  | 0b110 -> Opcode.FDIV
  | 0b111 -> Opcode.FDIVR
  | _ -> raise ParsingFailureException

let getDCOpWithin00toBF b = getD8OpWithin00toBF b

(* Table A-8 of Volume 2
   (D8 Opcode Map When ModR/M Byte is Outside 00H to BFH) *)
let getD8OpcodeOutside00toBF = function
  | b when b >= 0xC0uy && b <= 0xC7uy -> Opcode.FADD
  | b when b >= 0xC8uy && b <= 0xCFuy -> Opcode.FMUL
  | b when b >= 0xD0uy && b <= 0xD7uy -> Opcode.FCOM
  | b when b >= 0xD8uy && b <= 0xDFuy -> Opcode.FCOMP
  | b when b >= 0xE0uy && b <= 0xE7uy -> Opcode.FSUB
  | b when b >= 0xE8uy && b <= 0xEFuy -> Opcode.FSUBR
  | b when b >= 0xF0uy && b <= 0xF7uy -> Opcode.FDIV
  | b when b >= 0xF8uy && b <= 0xFFuy -> Opcode.FDIVR
  | _ -> raise ParsingFailureException

(* Table A-9 of Volume 2
   (D9 Opcode Map When ModR/M Byte is Within 00H to BFH) *)
let getD9OpWithin00toBF b =
  match getReg b with
  | 0b000 -> Opcode.FLD
  | 0b010 -> Opcode.FST
  | 0b011 -> Opcode.FSTP
  | 0b100 -> Opcode.FLDENV
  | 0b101 -> Opcode.FLDCW
  | 0b110 -> Opcode.FSTENV
  | 0b111 -> Opcode.FNSTCW
  | _ -> raise ParsingFailureException

(* Table A-10 of Volume 2
   (D9 Opcode Map When ModR/M Byte is Outside 00H to BFH) *)
let getD9OpcodeOutside00toBF = function
  | b when b >= 0xC0uy && b <= 0xC7uy -> Opcode.FLD
  | b when b >= 0xC8uy && b <= 0xCFuy -> Opcode.FXCH
  | 0xD0uy -> Opcode.FNOP
  | 0xE0uy -> Opcode.FCHS
  | 0xE1uy -> Opcode.FABS
  | 0xE5uy -> Opcode.FXAM
  | 0xE8uy -> Opcode.FLD1
  | 0xE9uy -> Opcode.FLDL2T
  | 0xEAuy -> Opcode.FLDL2E
  | 0xEBuy -> Opcode.FLDPI
  | 0xECuy -> Opcode.FLDLG2
  | 0xEDuy -> Opcode.FLDLN2
  | 0xEEuy -> Opcode.FLDZ
  | 0xF0uy -> Opcode.F2XM1
  | 0xF1uy -> Opcode.FYL2X
  | 0xF2uy -> Opcode.FPTAN
  | 0xF3uy -> Opcode.FPATAN
  | 0xF4uy -> Opcode.FXTRACT
  | 0xF5uy -> Opcode.FPREM1
  | 0xF6uy -> Opcode.FDECSTP
  | 0xF7uy -> Opcode.FINCSTP
  | 0xF8uy -> Opcode.FPREM
  | 0xF9uy -> Opcode.FYL2XP1
  | 0xFAuy -> Opcode.FSQRT
  | 0xFBuy -> Opcode.FSINCOS
  | 0xFCuy -> Opcode.FRNDINT
  | 0xFDuy -> Opcode.FSCALE
  | 0xFEuy -> Opcode.FSIN
  | 0xFFuy -> Opcode.FCOS
  | _ -> raise ParsingFailureException

(* Table A-11/19 of Volume 2
   (DA/DE Opcode Map When ModR/M Byte is Within 00H to BFH) *)
let getDAOpWithin00toBF b =
  match getReg b with
  | 0b000 -> Opcode.FIADD
  | 0b001 -> Opcode.FIMUL
  | 0b010 -> Opcode.FICOM
  | 0b011 -> Opcode.FICOMP
  | 0b100 -> Opcode.FISUB
  | 0b101 -> Opcode.FISUBR
  | 0b110 -> Opcode.FIDIV
  | 0b111 -> Opcode.FIDIVR
  | _ -> raise ParsingFailureException

let getDEOpWithin00toBF b = getDAOpWithin00toBF b

(* Table A-12 of Volume 2
   (DA Opcode Map When ModR/M Byte is Outside 00H to BFH) *)
let getDAOpcodeOutside00toBF = function
  | b when b >= 0xC0uy && b <= 0xC7uy -> Opcode.FCMOVB
  | b when b >= 0xC8uy && b <= 0xCFuy -> Opcode.FCMOVE
  | b when b >= 0xD0uy && b <= 0xD7uy -> Opcode.FCMOVBE
  | b when b >= 0xD8uy && b <= 0xDFuy -> Opcode.FCMOVU
  | 0xE9uy -> Opcode.FUCOMPP
  | _ -> raise ParsingFailureException

(* Table A-13 of Volume 2
   (DB Opcode Map When ModR/M Byte is Within 00H to BFH) *)
let getDBOpWithin00toBF b =
  match getReg b with
  | 0b000 -> Opcode.FILD
  | 0b001 -> Opcode.FISTTP
  | 0b010 -> Opcode.FIST
  | 0b011 -> Opcode.FISTP
  | 0b101 -> Opcode.FLD
  | 0b111 -> Opcode.FSTP
  | _ -> raise ParsingFailureException

(* Table A-14 of Volume 2
   (DB Opcode Map When ModR/M Byte is Outside 00H to BFH) *)
let getDBOpcodeOutside00toBF = function
  | b when b >= 0xC0uy && b <= 0xC7uy -> Opcode.FCMOVNB
  | b when b >= 0xC8uy && b <= 0xCFuy -> Opcode.FCMOVNE
  | b when b >= 0xD0uy && b <= 0xD7uy -> Opcode.FCMOVNBE
  | b when b >= 0xD8uy && b <= 0xDFuy -> Opcode.FCMOVNU
  | b when b >= 0xE8uy && b <= 0xEFuy -> Opcode.FUCOMI
  | b when b >= 0xF0uy && b <= 0xF7uy -> Opcode.FCOMI
  | 0xE2uy -> Opcode.FCLEX
  | 0xE3uy -> Opcode.FINIT
  | _ -> raise ParsingFailureException

(* Table A-16 of Volume 2
   (DC Opcode Map When ModR/M Byte is Outside 00H to BFH) *)
let getDCOpcodeOutside00toBF = function
  | b when b >= 0xC0uy && b <= 0xC7uy -> Opcode.FADD
  | b when b >= 0xC8uy && b <= 0xCFuy -> Opcode.FMUL
  | b when b >= 0xE0uy && b <= 0xE7uy -> Opcode.FSUBR
  | b when b >= 0xE8uy && b <= 0xEFuy -> Opcode.FSUB
  | b when b >= 0xF0uy && b <= 0xF7uy -> Opcode.FDIVR
  | b when b >= 0xF8uy && b <= 0xFFuy -> Opcode.FDIV
  | _ -> raise ParsingFailureException

(* Table A-17 of Volume 2
   (DD Opcode Map When ModR/M Byte is Within 00H to BFH) *)
let getDDOpWithin00toBF b =
  match getReg b with
  | 0b000 -> Opcode.FLD
  | 0b001 -> Opcode.FISTTP
  | 0b010 -> Opcode.FST
  | 0b011 -> Opcode.FSTP
  | 0b100 -> Opcode.FRSTOR
  | 0b110 -> Opcode.FSAVE
  | 0b111 -> Opcode.FNSTSW
  | _ -> raise ParsingFailureException

(* Table A-18 of Volume 2
   (DD Opcode Map When ModR/M Byte is Outside 00H to BFH) *)
let getDDOpcodeOutside00toBF b =
  match b with
  | b when b >= 0xC0uy && b <= 0xC7uy -> Opcode.FFREE
  | b when b >= 0xD0uy && b <= 0xD7uy -> Opcode.FST
  | b when b >= 0xD8uy && b <= 0xDFuy -> Opcode.FSTP
  | b when b >= 0xE0uy && b <= 0xE7uy -> Opcode.FUCOM
  | b when b >= 0xE8uy && b <= 0xEFuy -> Opcode.FUCOMP
  | _ -> raise ParsingFailureException

(* Table A-20 of Volume 2
   (DE Opcode Map When ModR/M Byte is Outside 00H to BFH) *)
let getDEOpcodeOutside00toBF = function
  | b when b >= 0xC0uy && b <= 0xC7uy -> Opcode.FADDP
  | b when b >= 0xC8uy && b <= 0xCFuy -> Opcode.FMULP
  | 0xD9uy -> Opcode.FCOMPP
  | b when b >= 0xE0uy && b <= 0xE7uy -> Opcode.FSUBRP
  | b when b >= 0xE8uy && b <= 0xEFuy -> Opcode.FSUBP
  | b when b >= 0xF0uy && b <= 0xF7uy -> Opcode.FDIVRP
  | b when b >= 0xF8uy && b <= 0xFFuy -> Opcode.FDIVP
  | _ -> raise ParsingFailureException

(* Table A-21 of Volume 2
   (DF Opcode Map When ModR/M Byte is Within 00H to BFH) *)
let getDFOpWithin00toBF b =
  match getReg b with
  | 0b000 -> Opcode.FILD
  | 0b001 -> Opcode.FISTTP
  | 0b010 -> Opcode.FIST
  | 0b011 -> Opcode.FISTP
  | 0b100 -> Opcode.FBLD
  | 0b101 -> Opcode.FILD
  | 0b110 -> Opcode.FBSTP
  | 0b111 -> Opcode.FISTP
  | _ -> raise ParsingFailureException

(* Table A-22 of Volume 2
   (DF Opcode Map When ModR/M Byte is Outside 00H to BFH) *)
let getDFOpcodeOutside00toBF = function
  | 0xE0uy -> Opcode.FNSTSW
  | b when b >= 0xE8uy && b <= 0xEFuy -> Opcode.FUCOMIP
  | b when b >= 0xF0uy && b <= 0xF7uy -> Opcode.FCOMIP
  | _ -> raise ParsingFailureException

let getD8OverBF b =
  getD8OpcodeOutside00toBF b, TwoOperands (OprReg R.ST0, getRM b |> getSTReg)

let getD9OverBF b =
  getD9OpcodeOutside00toBF b,
  if b < 0xC0uy || b >= 0xD0uy then NoOperand
  else OneOperand (getRM b |> getSTReg)

let getDAOverBF b =
  getDAOpcodeOutside00toBF b,
  if b = 0xE9uy then NoOperand
  else TwoOperands (OprReg R.ST0, getRM b |> getSTReg)

let getDBOverBF b =
  getDBOpcodeOutside00toBF b,
  if b = 0xE2uy || b = 0xE3uy then NoOperand
  else TwoOperands (OprReg R.ST0, getRM b |> getSTReg)

let getDCOverBF b =
  getDCOpcodeOutside00toBF b, TwoOperands (getRM b |> getSTReg, OprReg R.ST0)

let getDDOverBF b =
  getDDOpcodeOutside00toBF b,
  if b < 0xE0uy || b >= 0xE8uy then getRM b |> getSTReg |> OneOperand
  else TwoOperands (getRM b |> getSTReg, OprReg R.ST0)

let getDEOverBF b =
  getDEOpcodeOutside00toBF b,
  if b = 0xD9uy then NoOperand
  else TwoOperands (getRM b |> getSTReg, OprReg R.ST0)

let getDFOverBF b =
  getDFOpcodeOutside00toBF b,
  if b = 0xE0uy then OprReg R.AX |> OneOperand
  else TwoOperands (OprReg R.ST0, getRM b |> getSTReg)

let getD9EscEffOprSizeByModRM = function
 | 0b000 | 0b010 | 0b011 -> 32<rt> (* single-real *)
 | 0b100 | 0b110 -> 224<rt> (* 14/28 bytes (Vol.1 8-11 8.1.10) *)
 | 0b101 | 0b111 -> 16<rt> (* 2 bytes *)
 | _ -> raise ParsingFailureException

let getDBEscEffOprSizeByModRM = function
 | 0b101 | 0b111 -> 80<rt> (* extended-real *)
 | 0b000 | 0b001 | 0b010 | 0b011 -> 32<rt> (* dword-integer *)
 | _ -> raise ParsingFailureException

let getDDEscEffOprSizeByModRM = function
 | 0b000 | 0b010 | 0b011 -> 64<rt> (* double-real *)
 | 0b001 -> 64<rt> (* integer64 *)
 | 0b100 | 0b110 -> 864<rt> (* 94/108 bytes *)
 | 0b111 -> 16<rt> (* 2 bytes *)
 | _ -> raise ParsingFailureException

let getDFEscEffOprSizeByModRM = function
 | 0b000 | 0b001 | 0b010 | 0b011 -> 16<rt> (* word-integer *)
 | 0b100 | 0b110 -> 80<rt> (* packed-BCD *)
 | 0b101 | 0b111 -> 64<rt> (* qword-integer *)
 | _ -> raise ParsingFailureException

let getEscEffOprSizeByESCOp = function
  | 0xD8uy -> 32<rt> (* single-real *)
  | 0xDAuy -> 32<rt> (* dword-integer *)
  | 0xDCuy -> 64<rt> (* double-real *)
  | 0xDEuy -> 16<rt> (* word-integer *)
  | _ -> raise ParsingFailureException

let selectPrefix t =
  match t.TVEXInfo with
  | None -> t.TPrefixes
  | Some v -> v.VPrefixes

let [<Literal>] rexb =
  RGrpAttr.ARegInOpREX
  ||| RGrpAttr.ABaseRM
  ||| RGrpAttr.AMod11
  ||| RGrpAttr.ASIBBase

let [<Literal>] rexxb =
  RGrpAttr.ARegInOpREX
  ||| RGrpAttr.ABaseRM
  ||| RGrpAttr.AMod11
  ||| RGrpAttr.ASIBIdx
  ||| RGrpAttr.ASIBBase

let [<Literal>] rexrb =
  RGrpAttr.ARegInOpREX
  ||| RGrpAttr.ABaseRM
  ||| RGrpAttr.AMod11
  ||| RGrpAttr.ARegBits
  ||| RGrpAttr.ASIBBase

let [<Literal>] rexrx = RGrpAttr.ARegBits ||| RGrpAttr.ASIBIdx

let [<Literal>] rexrxb =
  RGrpAttr.ARegInOpREX
  ||| RGrpAttr.ABaseRM
  ||| RGrpAttr.AMod11
  ||| RGrpAttr.ARegBits
  ||| RGrpAttr.ASIBIdx
  ||| RGrpAttr.ASIBBase

let returnRegIdxFromSize sz =
  match sz with
  | 64<rt> -> 3
  | 32<rt> -> 2
  | 16<rt> -> 1
  | 8<rt> -> 0
  | 128<rt> -> 4
  | 256<rt> -> 5
  | 512<rt> -> 6
  | _ -> raise ParsingFailureException

let noRexGrp grpnum sz =
  let idx = returnRegIdxFromSize sz
  match grpnum with
  | 0 -> grpEAX idx
  | 1 -> grpECX idx
  | 2 -> grpEDX idx
  | 3 -> grpEBX idx
  | 4 -> grpAH idx
  | 5 -> grpCH idx
  | 6 -> grpDH idx
  | 7 -> grpBH idx
  | _ -> raise ParsingFailureException

let rexGrp1 grpnum sz =
  let idx = returnRegIdxFromSize sz
  match grpnum with
  | 0 -> grpR8 idx
  | 1 -> grpR9 idx
  | 2 -> grpR10 idx
  | 3 -> grpR11 idx
  | 4 -> grpR12 idx
  | 5 -> grpR13 idx
  | 6 -> grpR14 idx
  | 7 -> grpR15 idx
  | _ -> raise ParsingFailureException

let rexGrp2 grpnum sz =
  let idx = returnRegIdxFromSize sz
  match grpnum with
  | 0 -> grpEAX idx
  | 1 -> grpECX idx
  | 2 -> grpEDX idx
  | 3 -> grpEBX idx
  | 4 -> grpESP idx
  | 5 -> grpEBP idx
  | 6 -> grpESI idx
  | 7 -> grpEDI idx
  | _ -> raise ParsingFailureException

/// Find an appropriate register symbol from the given RegType, RGrpAttribute,
/// REXPrefix, and RegGrp (int).
let findReg sz attr rex (grpnum: int) =
  if rex = REXPrefix.NOREX then noRexGrp grpnum sz
  else
    match rex with
    | REXPrefix.REX -> rexGrp2 grpnum sz
    | REXPrefix.REXB | REXPrefix.REXWB ->
      if (rexb &&& attr) <> RGrpAttr.ANone then rexGrp1 grpnum sz
      else rexGrp2 grpnum sz
    | REXPrefix.REXX | REXPrefix.REXWX ->
      if RGrpAttr.ASIBIdx = attr then rexGrp1 grpnum sz
      else rexGrp2 grpnum sz
    | REXPrefix.REXXB | REXPrefix.REXWXB ->
      if (rexxb &&& attr) <> RGrpAttr.ANone then rexGrp1 grpnum sz
      else rexGrp2 grpnum sz
    | REXPrefix.REXR | REXPrefix.REXWR ->
      if RGrpAttr.ARegBits = attr then rexGrp1 grpnum sz
      else rexGrp2 grpnum sz
    | REXPrefix.REXRB | REXPrefix.REXWRB ->
      if (rexrb &&& attr) <> RGrpAttr.ANone then rexGrp1 grpnum sz
      else rexGrp2 grpnum sz
    | REXPrefix.REXRX | REXPrefix.REXWRX ->
      if (rexrx &&& attr) <> RGrpAttr.ANone then rexGrp1 grpnum sz
      else rexGrp2 grpnum sz
    | REXPrefix.REXRXB | REXPrefix.REXWRXB ->
      if (rexrxb &&& attr) <> RGrpAttr.ANone then rexGrp1 grpnum sz
      else rexGrp2 grpnum sz
    | REXPrefix.REXW -> rexGrp2 grpnum sz
    | _ -> raise ParsingFailureException

let getOpCode0F0D (rhlp: ReadHelper) =
  let b = rhlp.PeekByte ()
  match modIsMemory b, getReg b with
  | true, 0b001 -> Opcode.PREFETCHW
  | true, 0b010 -> Opcode.PREFETCHWT1
  | _ -> raise ParsingFailureException

let ignOpSz t = { t with TPrefixes = t.TPrefixes &&& EnumOfValue 0xFDFF }

let getOprFromRegGrp rgrp attr t insSize =
  findReg insSize.RegSize attr t.TREXPrefix rgrp |> OprReg

let parseSignedImm (rhlp: ReadHelper) = function
  | 1 -> rhlp.ReadInt8 () |> int64
  | 2 -> rhlp.ReadInt16 () |> int64
  | 4 -> rhlp.ReadInt32 () |> int64
  | 8 -> rhlp.ReadInt64 ()
  | _ -> raise ParsingFailureException

let parseUnsignedImm (rhlp: ReadHelper) = function
  | 1 -> rhlp.ReadUInt8 () |> uint64
  | 2 -> rhlp.ReadUInt16 () |> uint64
  | 4 -> rhlp.ReadUInt32 () |> uint64
  | 8 -> rhlp.ReadUInt64 ()
  | _ -> raise ParsingFailureException

/// EVEX uses compressed displacement. See the manual Chap. 15 of Vol. 1.
let compressDisp vInfo disp =
  match vInfo with
  | Some { VectorLength = 128<rt>; VEXType = t }
    when t &&& VEXType.EVEX = VEXType.EVEX -> disp * 16L
  | Some { VectorLength = 256<rt>; VEXType = t }
      when t &&& VEXType.EVEX = VEXType.EVEX -> disp * 32L
  | Some { VectorLength = 512<rt>; VEXType = t }
      when t &&& VEXType.EVEX = VEXType.EVEX -> disp * 64L
  | _ -> disp

let parseOprMem insSize t rhlp b s disp =
  let memSz = insSize.MemEffOprSize
  match disp with
  | None -> OprMem (b, s, None, memSz)
  | Some dispSz ->
    let disp = parseSignedImm rhlp dispSz
    let disp = compressDisp t.TVEXInfo disp
    OprMem (b, s, Some disp, memSz)

let parseOprImm rhlp immSize =
  let immSize = RegType.toByteWidth immSize
  let imm = parseUnsignedImm rhlp immSize
  OprImm (int64 imm)

let parseOprSImm rhlp immSize =
  let immSize = RegType.toByteWidth immSize
  let imm = parseSignedImm rhlp immSize
  OprImm imm

/// The first 24 rows of Table 2-1. of the manual Vol. 2A.
/// The index of this tbl is a number that is a concatenation of (mod) and
/// (r/m) field of the ModR/M byte. Each element is a tuple of base register,
/// scaled index register, and the size of the displacement.
let tbl16bitMem = function
  (* Mod 00b *)
  | 0 -> struct (Some R.BX, Some (R.SI, Scale.X1), None)
  | 1 -> struct (Some R.BX, Some (R.DI, Scale.X1), None)
  | 2 -> struct (Some R.BP, Some (R.SI, Scale.X1), None)
  | 3 -> struct (Some R.BP, Some (R.DI, Scale.X1), None)
  | 4 -> struct (Some R.SI, None, None)
  | 5 -> struct (Some R.DI, None, None)
  | 6 -> struct (None, None, Some 2)
  | 7 -> struct (Some R.BX, None, None)
  (* Mod 01b *)
  | 8 -> struct (Some R.BX, Some (R.SI, Scale.X1), Some 1)
  | 9 -> struct (Some R.BX, Some (R.DI, Scale.X1), Some 1)
  | 10 -> struct (Some R.BP, Some (R.SI, Scale.X1), Some 1)
  | 11 -> struct (Some R.BP, Some (R.DI, Scale.X1), Some 1)
  | 12 -> struct (Some R.SI, None, Some 1)
  | 13 -> struct (Some R.DI, None, Some 1)
  | 14 -> struct (Some R.BP, None, Some 1)
  | 15 -> struct (Some R.BX, None, Some 1)
  (* Mod 10b *)
  | 16 -> struct (Some R.BX, Some (R.SI, Scale.X1), Some 2)
  | 17 -> struct (Some R.BX, Some (R.DI, Scale.X1), Some 2)
  | 18 -> struct (Some R.BP, Some (R.SI, Scale.X1), Some 2)
  | 19 -> struct (Some R.BP, Some (R.DI, Scale.X1), Some 2)
  | 20 -> struct (Some R.SI, None, Some 2)
  | 21 -> struct (Some R.DI, None, Some 2)
  | 22 -> struct (Some R.BP, None, Some 2)
  | 23 -> struct (Some R.BX, None, Some 2)
  | _ -> raise ParsingFailureException

/// The first 24 rows of Table 2-2. of the manual Vol. 2A.
/// The index of this tbl is a number that is a concatenation of (mod) and
/// (r/m) field of the ModR/M byte. Each element is a tuple of (MemLookupType,
/// and the size of the displacement). If the first value of the tuple (register
/// group) is None, it means we need to look up the SIB tbl (Table 2-3). If
/// not, then it represents the reg group of the base reigster.
let tbl32bitMem = function
  (* Mod 00b *)
  | 0 -> struct (NOSIB (Some RegGrp.RG0), None)
  | 1 -> struct (NOSIB (Some RegGrp.RG1), None)
  | 2 -> struct (NOSIB (Some RegGrp.RG2), None)
  | 3 -> struct (NOSIB (Some RegGrp.RG3), None)
  | 4 -> struct (SIB,                     None)
  | 5 -> struct (NOSIB (None),            Some 4)
  | 6 -> struct (NOSIB (Some RegGrp.RG6), None)
  | 7 -> struct (NOSIB (Some RegGrp.RG7), None)
  (* Mod 01b *)
  | 8 -> struct (NOSIB (Some RegGrp.RG0), Some 1)
  | 9 -> struct (NOSIB (Some RegGrp.RG1), Some 1)
  | 10 -> struct (NOSIB (Some RegGrp.RG2), Some 1)
  | 11 -> struct (NOSIB (Some RegGrp.RG3), Some 1)
  | 12 -> struct (SIB,                     Some 1)
  | 13 -> struct (NOSIB (Some RegGrp.RG5), Some 1)
  | 14 -> struct (NOSIB (Some RegGrp.RG6), Some 1)
  | 15 -> struct (NOSIB (Some RegGrp.RG7), Some 1)
  (* Mod 10b *)
  | 16 -> struct (NOSIB (Some RegGrp.RG0), Some 4)
  | 17 -> struct (NOSIB (Some RegGrp.RG1), Some 4)
  | 18 -> struct (NOSIB (Some RegGrp.RG2), Some 4)
  | 19 -> struct (NOSIB (Some RegGrp.RG3), Some 4)
  | 20 -> struct (SIB,                     Some 4)
  | 21 -> struct (NOSIB (Some RegGrp.RG5), Some 4)
  | 22 -> struct (NOSIB (Some RegGrp.RG6), Some 4)
  | 23 -> struct (NOSIB (Some RegGrp.RG7), Some 4)
  | _ -> raise ParsingFailureException

/// Table for scales (of SIB). This tbl is indexbed by the scale value of SIB.
let tblScale = function
  | 0 -> Scale.X1
  | 1 -> Scale.X2
  | 2 -> Scale.X4
  | 3 -> Scale.X8
  | _ -> raise ParsingFailureException

let parseMEM16 insSize t rhlp modRM =
  let m = getMod modRM
  let rm = getRM modRM
  let mrm = (m <<< 3) ||| rm (* Concatenation of mod and rm bit *)
  match tbl16bitMem mrm with
  | struct (b, si, disp) -> parseOprMem insSize t rhlp b si disp

let inline hasREXX rexPref = rexPref &&& REXPrefix.REXX = REXPrefix.REXX

let getScaledIndex s i insSize rexPref =
  if i = 0b100 && (not <| hasREXX rexPref) then None
  else let r = findReg insSize.MemEffAddrSize RGrpAttr.ASIBIdx rexPref i
       Some (r, tblScale s)

/// See Notes 1 of Table 2-3 of the manual Vol. 2A
let getBaseReg b insSize modValue rexPref =
  if b = int RegGrp.RG5 && modValue = 0b00 then None
  else Some (findReg insSize.MemEffAddrSize RGrpAttr.ASIBBase rexPref b)

let getSIB b =
  struct ((b >>> 6) &&& 0b11, (b >>> 3) &&& 0b111, b &&& 0b111)

let parseSIB insSize t (rhlp: ReadHelper) modValue =
  let struct (s, i, b) = rhlp.ReadByte () |> int |> getSIB
  let rexPref = selectREX t
  let si = getScaledIndex s i insSize rexPref
  let baseReg = getBaseReg b insSize modValue rexPref
  struct (si, baseReg, b)

let getSIBDisplacement disp bgrp modValue =
  match disp with
  | Some dispSz -> dispSz
  | None when modValue = 0 && bgrp = int RegGrp.RG5 -> 4
  | None when modValue = 1 && bgrp = int RegGrp.RG5 -> 1
  | None when modValue = 2 && bgrp = int RegGrp.RG5 -> 4
  | _ -> 0

let parseOprMemWithSIB insSize t rhlp oprSz modVal disp =
  let struct (si, b, bgrp) = parseSIB insSize t rhlp modVal
  match getSIBDisplacement disp bgrp modVal with
  | 0 -> OprMem (b, si, None, oprSz)
  | dispSz ->
    let vInfo = t.TVEXInfo
    let disp = parseSignedImm rhlp dispSz
    let disp = compressDisp vInfo disp
    OprMem (b, si, Some disp, oprSz)

/// RIP-relative addressing (see Section 2.2.1.6. of Vol. 2A).
let parseOprRIPRelativeMem insSize t rhlp disp =
  if t.TWordSize = WordSize.Bit64 then
    if hasAddrSz t.TPrefixes then
      parseOprMem insSize t rhlp (Some R.EIP) None disp
    else parseOprMem insSize t rhlp (Some R.RIP) None disp
  else parseOprMem insSize t rhlp None None disp

let getBaseRMReg insSize t regGrp =
  let rexPref = selectREX t
  let regSz = insSize.MemEffAddrSize
  findReg regSz RGrpAttr.ABaseRM rexPref (int regGrp) |> Some

let parseMEM32 insSize t rhlp oprSize modRM =
  let m = getMod modRM
  let rm = getRM modRM
  let mrm = (m <<< 3) ||| rm (* Concatenation of mod and rm bit *)
  match tbl32bitMem mrm with
  | struct (NOSIB (None), disp) ->
    parseOprRIPRelativeMem insSize t rhlp disp
  | struct (NOSIB (Some b), disp) ->
    parseOprMem insSize t rhlp (getBaseRMReg insSize t b) None disp
  | struct (SIB, disp) -> parseOprMemWithSIB insSize t rhlp oprSize m disp

let parseMemory modRM insSize t rhlp =
  let addrSize = insSize.MemEffAddrSize
  if addrSize = 16<rt> then parseMEM16 insSize t rhlp modRM
  else parseMEM32 insSize t rhlp insSize.MemEffOprSize modRM

let parseReg rGrp sz attr t =
  findReg sz attr (selectREX t) rGrp |> OprReg

let parseMemOrReg modRM insSize t rhlp =
  if getMod modRM = 0b11 then
    let regSize = insSize.MemEffRegSize
    parseReg (getRM modRM) regSize RGrpAttr.AMod11 t
  else parseMemory modRM insSize t rhlp

let parseVVVVReg t =
  match t.TVEXInfo with
  | None -> raise ParsingFailureException
  | Some vInfo when vInfo.VectorLength = 512<rt> ->
    Register.make (int vInfo.VVVV) Register.Kind.ZMM |> OprReg
  | Some vInfo when vInfo.VectorLength = 256<rt> ->
    Register.make (int vInfo.VVVV) Register.Kind.YMM |> OprReg
  | Some vInfo -> Register.make (int vInfo.VVVV) Register.Kind.XMM |> OprReg

let parseVEXtoGPR t insSize =
  match t.TVEXInfo with
  | None -> raise ParsingFailureException
  | Some vInfo ->
    let grp = ~~~(int vInfo.VVVV) &&& 0b111
    noRexGrp grp insSize.RegSize |> OprReg

let parseMMXReg n = Register.make n Register.Kind.MMX |> OprReg

let parseSegReg n = Register.make n Register.Kind.Segment |> OprReg

let parseBoundRegister n = Register.make n Register.Kind.Bound |> OprReg

let parseControlReg n = Register.make n Register.Kind.Control |> OprReg

let parseDebugReg n = Register.make n Register.Kind.Debug |> OprReg

let parseOprOnlyDisp t rhlp insSize =
  let dispSz = RegType.toByteWidth insSize.MemEffAddrSize
  parseOprMem insSize t rhlp None None (Some dispSz)

let getImmZ insSize =
  if insSize.MemEffOprSize = 64<rt>
    || insSize.MemEffOprSize = 32<rt> then 32<rt>
  else insSize.MemEffOprSize

let opRmGpr t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr1 = parseMemOrReg modRM insSize t rhlp
  let opr2 = parseReg (getReg modRM) insSize.RegSize RGrpAttr.ARegBits t
  struct (TwoOperands (opr1, opr2), insSize)

let opRmSeg t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr1 = parseMemOrReg modRM insSize t rhlp
  let opr2 = parseSegReg (getReg modRM)
  struct (TwoOperands (opr1, opr2), insSize)

let opRmCtrl t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr1 = parseMemOrReg modRM insSize t rhlp
  let opr2 = parseControlReg (getReg modRM)
  struct (TwoOperands (opr1, opr2), insSize)

let opRmDbg t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr1 = parseMemOrReg modRM insSize t rhlp
  let opr2 = parseDebugReg (getReg modRM)
  struct (TwoOperands (opr1, opr2), insSize)

let opRMMmx t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr1 = parseMemOrReg modRM insSize t rhlp
  let opr2 = parseMMXReg (getReg modRM)
  struct (TwoOperands (opr1, opr2), insSize)

let opMmMmx t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr1 =
    if modIsReg modRM then parseMMXReg (getRM modRM)
    else parseMemory modRM insSize t rhlp
  let opr2 = parseMMXReg (getReg modRM)
  struct (TwoOperands (opr1, opr2), insSize)

let opBmBnd t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr1 =
    if modIsReg modRM then parseBoundRegister (getRM modRM)
    else parseMemory modRM insSize t rhlp
  let opr2 = parseBoundRegister (getReg modRM)
  struct (TwoOperands (opr1, opr2), insSize)

let opRmBnd t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr1 = parseMemOrReg modRM insSize t rhlp
  let opr2 = parseBoundRegister (getReg modRM)
  struct (TwoOperands (opr1, opr2), insSize)

let opGprRm t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr1 = parseReg (getReg modRM) insSize.RegSize RGrpAttr.ARegBits t
  let opr2 = parseMemOrReg modRM insSize t rhlp
  struct (TwoOperands (opr1, opr2), insSize)

let opGprM t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  if modIsMemory modRM then
    let opr1 = parseReg (getReg modRM) insSize.RegSize RGrpAttr.ARegBits t
    let opr2 = parseMemory modRM insSize t rhlp
    struct (TwoOperands (opr1, opr2), insSize)
  else raise ParsingFailureException

let opSegRm t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr1 = parseSegReg (getReg modRM)
  let opr2 = parseMemOrReg modRM insSize t rhlp
  struct (TwoOperands (opr1, opr2), insSize)

let opBndBm t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr1 = parseBoundRegister (getReg modRM)
  let opr2 =
    if modIsReg modRM then parseBoundRegister (getRM modRM)
    else parseMemory modRM insSize t rhlp
  struct (TwoOperands (opr1, opr2), insSize)

let opBndRm t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr1 = parseBoundRegister (getReg modRM)
  let opr2 = parseMemOrReg modRM insSize t rhlp
  struct (TwoOperands (opr1, opr2), insSize)

let opCtrlRm t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr1 = parseControlReg (getReg modRM)
  let opr2 = parseMemOrReg modRM insSize t rhlp
  struct (TwoOperands (opr1, opr2), insSize)

let opDbgRm t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr1 = parseDebugReg (getReg modRM)
  let opr2 = parseMemOrReg modRM insSize t rhlp
  struct (TwoOperands (opr1, opr2), insSize)

let opMmxRm t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr1 = parseMMXReg (getReg modRM)
  let opr2 =
    if modIsReg modRM then parseMMXReg (getRM modRM)
    else parseMemory modRM insSize t rhlp
  struct (TwoOperands (opr1, opr2), insSize)

let opMmxMm t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr1 = parseMMXReg (getReg modRM)
  let opr2 = parseMemOrReg modRM insSize t rhlp
  struct (TwoOperands (opr1, opr2), insSize)

let opGprRMm t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr1 = parseReg (getReg modRM) insSize.RegSize RGrpAttr.ARegBits t
  let opr2 =
    if modIsReg modRM then parseMMXReg (getRM modRM)
    else parseMemOrReg modRM insSize t rhlp
  struct (TwoOperands (opr1, opr2), insSize)

let opRegImm8 t rhlp insSize =
  let opr1 = getOprFromRegGrp (int RegGrp.RG0) RGrpAttr.ARegInOpNoREX t insSize
  let opr2 = parseOprImm rhlp 8<rt>
  struct (TwoOperands (opr1, opr2), insSize)

let opImm8Reg t rhlp insSize =
  let opr1 = parseOprImm rhlp 8<rt>
  let opr2 = getOprFromRegGrp (int RegGrp.RG0) RGrpAttr.ARegInOpNoREX t insSize
  struct (TwoOperands (opr1, opr2), insSize)

let opImm8 _ rhlp insSize =
  let opr = parseOprImm rhlp 8<rt>
  struct (OneOperand opr, insSize)

let opImm16 _ rhlp insSize =
  let opr = parseOprImm rhlp 16<rt>
  struct (OneOperand opr, insSize)

let opRegImm t rhlp insSize =
  let opr1 = getOprFromRegGrp (int RegGrp.RG0) RGrpAttr.ARegInOpNoREX t insSize
  let opr2 = parseOprSImm rhlp (getImmZ insSize)
  struct (TwoOperands (opr1, opr2), insSize)

let opSImm8 _ rhlp insSize =
  let opr = parseOprSImm rhlp 8<rt>
  struct (OneOperand opr, insSize)

let opImm _ rhlp insSize =
  let opr = parseOprSImm rhlp (getImmZ insSize)
  struct (OneOperand opr, insSize)

let opEs _ _ insSize = struct (OneOperand (OprReg R.ES), insSize)

let opCs _ _ insSize = struct (OneOperand (OprReg R.CS), insSize)

let opSs _ _ insSize = struct (OneOperand (OprReg R.SS), insSize)

let opDs _ _ insSize = struct (OneOperand (OprReg R.DS), insSize)

let opFs _ _ insSize = struct (OneOperand (OprReg R.FS), insSize)

let opGs _ _ insSize = struct (OneOperand (OprReg R.GS), insSize)

let opALDx _ _ insSz = struct (TwoOperands (OprReg R.AL, OprReg R.DX), insSz)

let opEaxDx t _ insSize =
  let reg = if hasOprSz t.TPrefixes then R.AX else R.EAX
  struct (TwoOperands (OprReg reg, OprReg R.DX), insSize)

let opDxEax t _ insSize =
  let reg = if hasOprSz t.TPrefixes then R.AX else R.EAX
  struct (TwoOperands (OprReg R.DX, OprReg reg), insSize)

let opDxAL _ _ insSize =
  struct (TwoOperands (OprReg R.DX, OprReg R.AL), insSize)

let opNo _ _ insSize = struct (NoOperand, insSize)

let opEax t _ insSize =
  let opr = getOprFromRegGrp (int RegGrp.RG0) RGrpAttr.ARegInOpNoREX t insSize
  struct (OneOperand opr, insSize)

let opEcx t _ insSize =
  let opr = getOprFromRegGrp (int RegGrp.RG1) RGrpAttr.ARegInOpNoREX t insSize
  struct (OneOperand opr, insSize)

let opEdx t _ insSize =
  let opr = getOprFromRegGrp (int RegGrp.RG2) RGrpAttr.ARegInOpNoREX t insSize
  struct (OneOperand opr, insSize)

let opEbx t _ insSize =
  let opr = getOprFromRegGrp (int RegGrp.RG3) RGrpAttr.ARegInOpNoREX t insSize
  struct (OneOperand opr, insSize)

let opEsp t _ insSize =
  let opr = getOprFromRegGrp (int RegGrp.RG4) RGrpAttr.ARegInOpNoREX t insSize
  struct (OneOperand opr, insSize)

let opEbp t _ insSize =
  let opr = getOprFromRegGrp (int RegGrp.RG5) RGrpAttr.ARegInOpNoREX t insSize
  struct (OneOperand opr, insSize)

let opEsi t _ insSize =
  let opr = getOprFromRegGrp (int RegGrp.RG6) RGrpAttr.ARegInOpNoREX t insSize
  struct (OneOperand opr, insSize)

let opEdi t _ insSize =
  let opr = getOprFromRegGrp (int RegGrp.RG7) RGrpAttr.ARegInOpNoREX t insSize
  struct (OneOperand opr, insSize)

let opRax t _ insSize =
  let opr = getOprFromRegGrp (int RegGrp.RG0) RGrpAttr.ARegInOpREX t insSize
  struct (OneOperand opr, insSize)

let opRcx t _ insSize =
  let opr = getOprFromRegGrp (int RegGrp.RG1) RGrpAttr.ARegInOpREX t insSize
  struct (OneOperand opr, insSize)

let opRdx t _ insSize =
  let opr = getOprFromRegGrp (int RegGrp.RG2) RGrpAttr.ARegInOpREX t insSize
  struct (OneOperand opr, insSize)

let opRbx t _ insSize =
  let opr = getOprFromRegGrp (int RegGrp.RG3) RGrpAttr.ARegInOpREX t insSize
  struct (OneOperand opr, insSize)

let opRsp t _ insSize =
  let opr = getOprFromRegGrp (int RegGrp.RG4) RGrpAttr.ARegInOpREX t insSize
  struct (OneOperand opr, insSize)

let opRbp t _ insSize =
  let opr = getOprFromRegGrp (int RegGrp.RG5) RGrpAttr.ARegInOpREX t insSize
  struct (OneOperand opr, insSize)

let opRsi t _ insSize =
  let opr = getOprFromRegGrp (int RegGrp.RG6) RGrpAttr.ARegInOpREX t insSize
  struct (OneOperand opr, insSize)

let opRdi t _ insSize =
  let opr = getOprFromRegGrp (int RegGrp.RG7) RGrpAttr.ARegInOpREX t insSize
  struct (OneOperand opr, insSize)

let opRaxRax t _ insSize =
  let opr1 = getOprFromRegGrp (int RegGrp.RG0) RGrpAttr.ARegInOpNoREX t insSize
  let opr2 = getOprFromRegGrp (int RegGrp.RG0) RGrpAttr.ARegInOpREX t insSize
  struct (TwoOperands (opr1, opr2), insSize)

let opRaxRcx t _ insSize =
  let opr1 = getOprFromRegGrp (int RegGrp.RG0) RGrpAttr.ARegInOpNoREX t insSize
  let opr2 = getOprFromRegGrp (int RegGrp.RG1) RGrpAttr.ARegInOpREX t insSize
  struct (TwoOperands (opr1, opr2), insSize)

let opRaxRdx t _ insSize =
  let opr1 = getOprFromRegGrp (int RegGrp.RG0) RGrpAttr.ARegInOpNoREX t insSize
  let opr2 = getOprFromRegGrp (int RegGrp.RG2) RGrpAttr.ARegInOpREX t insSize
  struct (TwoOperands (opr1, opr2), insSize)

let opRaxRbx t _ insSize =
  let opr1 = getOprFromRegGrp (int RegGrp.RG0) RGrpAttr.ARegInOpNoREX t insSize
  let opr2 = getOprFromRegGrp (int RegGrp.RG3) RGrpAttr.ARegInOpREX t insSize
  struct (TwoOperands (opr1, opr2), insSize)

let opRaxRsp t _ insSize =
  let opr1 = getOprFromRegGrp (int RegGrp.RG0) RGrpAttr.ARegInOpNoREX t insSize
  let opr2 = getOprFromRegGrp (int RegGrp.RG4) RGrpAttr.ARegInOpREX t insSize
  struct (TwoOperands (opr1, opr2), insSize)

let opRaxRbp t _ insSize =
  let opr1 = getOprFromRegGrp (int RegGrp.RG0) RGrpAttr.ARegInOpNoREX t insSize
  let opr2 = getOprFromRegGrp (int RegGrp.RG5) RGrpAttr.ARegInOpREX t insSize
  struct (TwoOperands (opr1, opr2), insSize)

let opRaxRsi t _ insSize =
  let opr1 = getOprFromRegGrp (int RegGrp.RG0) RGrpAttr.ARegInOpNoREX t insSize
  let opr2 = getOprFromRegGrp (int RegGrp.RG6) RGrpAttr.ARegInOpREX t insSize
  struct (TwoOperands (opr1, opr2), insSize)

let opRaxRdi t _ insSize =
  let opr1 = getOprFromRegGrp (int RegGrp.RG0) RGrpAttr.ARegInOpNoREX t insSize
  let opr2 = getOprFromRegGrp (int RegGrp.RG7) RGrpAttr.ARegInOpREX t insSize
  struct (TwoOperands (opr1, opr2), insSize)

let opGprRmImm8 t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr1 = parseReg (getReg modRM) insSize.RegSize RGrpAttr.ARegBits t
  let opr2 = parseMemOrReg modRM insSize t rhlp
  let opr3 = parseOprSImm rhlp 8<rt>
  struct (ThreeOperands (opr1, opr2, opr3), insSize)

let opGprRmImm t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr1 = parseReg (getReg modRM) insSize.RegSize RGrpAttr.ARegBits t
  let opr2 = parseMemOrReg modRM insSize t rhlp
  let opr3 = parseOprSImm rhlp (getImmZ insSize)
  struct (ThreeOperands (opr1, opr2, opr3), insSize)

let parseOprForRelJmp rhlp immSz =
  let immSz = RegType.toByteWidth immSz
  let offset = parseSignedImm rhlp immSz
  let relOffset = offset + int64 (rhlp.ParsedLen ())
  OprDirAddr (Relative (relOffset))

let opRel8 _ rhlp insSize =
  let opr = parseOprForRelJmp rhlp 8<rt>
  struct (OneOperand opr, insSize)

let opRel _ rhlp insSize =
  let opr = parseOprForRelJmp rhlp (getImmZ insSize)
  struct (OneOperand opr, insSize)

let opDir _ rhlp insSize =
  let addrSz = RegType.toByteWidth insSize.MemEffAddrSize
  let addrValue = parseUnsignedImm rhlp addrSz
  let selector = rhlp.ReadInt16 ()
  let absAddr = Absolute (selector, addrValue, RegType.fromByteWidth addrSz)
  let opr = OprDirAddr absAddr
  struct (OneOperand opr, insSize)

let opRaxFar t rhlp insSize =
  let opr1 = getOprFromRegGrp (int RegGrp.RG0) RGrpAttr.ARegInOpNoREX t insSize
  let opr2 = parseOprOnlyDisp t rhlp insSize
  struct (TwoOperands (opr1, opr2), insSize)

let opFarRax t rhlp insSize =
  let opr1 = parseOprOnlyDisp t rhlp insSize
  let opr2 = getOprFromRegGrp (int RegGrp.RG0) RGrpAttr.ARegInOpNoREX t insSize
  struct (TwoOperands (opr1, opr2), insSize)

let opALImm8 t rhlp insSize =
  let opr1 = getOprFromRegGrp (int RegGrp.RG0) RGrpAttr.ARegInOpREX t insSize
  let opr2 = parseOprImm rhlp 8<rt>
  struct (TwoOperands (opr1, opr2), insSize)

let opCLImm8 t rhlp insSize =
  let opr1 = getOprFromRegGrp (int RegGrp.RG1) RGrpAttr.ARegInOpREX t insSize
  let opr2 = parseOprImm rhlp 8<rt>
  struct (TwoOperands (opr1, opr2), insSize)

let opDLImm8 t rhlp insSize =
  let opr1 = getOprFromRegGrp (int RegGrp.RG2) RGrpAttr.ARegInOpREX t insSize
  let opr2 = parseOprImm rhlp 8<rt>
  struct (TwoOperands (opr1, opr2), insSize)

let opBLImm8 t rhlp insSize =
  let opr1 = getOprFromRegGrp (int RegGrp.RG3) RGrpAttr.ARegInOpREX t insSize
  let opr2 = parseOprImm rhlp 8<rt>
  struct (TwoOperands (opr1, opr2), insSize)

let opAhImm8 t rhlp insSize =
  let opr1 = getOprFromRegGrp (int RegGrp.RG4) RGrpAttr.ARegInOpREX t insSize
  let opr2 = parseOprImm rhlp 8<rt>
  struct (TwoOperands (opr1, opr2), insSize)

let opChImm8 t rhlp insSize =
  let opr1 = getOprFromRegGrp (int RegGrp.RG5) RGrpAttr.ARegInOpREX t insSize
  let opr2 = parseOprImm rhlp 8<rt>
  struct (TwoOperands (opr1, opr2), insSize)

let opDhImm8 t rhlp insSize =
  let opr1 = getOprFromRegGrp (int RegGrp.RG6) RGrpAttr.ARegInOpREX t insSize
  let opr2 = parseOprImm rhlp 8<rt>
  struct (TwoOperands (opr1, opr2), insSize)

let opBhImm8 t rhlp insSize =
  let opr1 = getOprFromRegGrp (int RegGrp.RG7) RGrpAttr.ARegInOpREX t insSize
  let opr2 = parseOprImm rhlp 8<rt>
  struct (TwoOperands (opr1, opr2), insSize)

let opGprImm t rhlp insSize regGrp =
  let opr1 = getOprFromRegGrp (int regGrp) RGrpAttr.ARegInOpREX t insSize
  let opr2 = parseOprSImm rhlp insSize.MemEffOprSize
  struct (TwoOperands (opr1, opr2), insSize)

let opRaxImm t rhlp insSize = opGprImm t rhlp insSize RegGrp.RG0

let opRcxImm t rhlp insSize = opGprImm t rhlp insSize RegGrp.RG1

let opRdxImm t rhlp insSize = opGprImm t rhlp insSize RegGrp.RG2

let opRbxImm t rhlp insSize = opGprImm t rhlp insSize RegGrp.RG3

let opRspImm t rhlp insSize = opGprImm t rhlp insSize RegGrp.RG4

let opRbpImm t rhlp insSize = opGprImm t rhlp insSize RegGrp.RG5

let opRsiImm t rhlp insSize = opGprImm t rhlp insSize RegGrp.RG6

let opRdiImm t rhlp insSize = opGprImm t rhlp insSize RegGrp.RG7

let opImmImm _ rhlp insSize =
  let opr1 = parseOprImm rhlp 16<rt>
  let opr2 = parseOprImm rhlp 8<rt>
  struct (TwoOperands (opr1, opr2), insSize)

let opRmImm t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr1 = parseMemOrReg modRM insSize t rhlp
  let opr2 = parseOprSImm rhlp (getImmZ insSize)
  struct (TwoOperands (opr1, opr2), insSize)

let opRmImm8 t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr1 = parseMemOrReg modRM insSize t rhlp
  let opr2 = parseOprSImm rhlp 8<rt>
  struct (TwoOperands (opr1, opr2), insSize)

let opMmxImm8 t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr1 =
    if modIsReg modRM then parseMMXReg (getRM modRM)
    else parseMemory modRM insSize t rhlp
  let opr2 = parseOprSImm rhlp 8<rt>
  struct (TwoOperands (opr1, opr2), insSize)

let opMem t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr = parseMemOrReg modRM insSize t rhlp
  struct (OneOperand opr, insSize)

let opM1 t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr = parseMemOrReg modRM insSize t rhlp
  struct (TwoOperands (opr, OprImm 1L), insSize)

let opRmCL t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr = parseMemOrReg modRM insSize t rhlp
  struct (TwoOperands (opr, OprReg R.CL), insSize)

let opXmmVvXm t (rhlp: ReadHelper) (insSize: InstrSize) =
  let modRM = rhlp.ReadByte ()
  let opr1 = parseReg (getReg modRM) insSize.RegSize RGrpAttr.ARegBits t
  let opr3 = parseMemOrReg modRM insSize t rhlp
  let oprs = ThreeOperands (opr1, parseVVVVReg t, opr3)
  struct (oprs, insSize)

let opGprVvRm t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr1 = parseReg (getReg modRM) insSize.RegSize RGrpAttr.ARegBits t
  let opr2 = parseVEXtoGPR t insSize
  let opr3 = parseMemOrReg modRM insSize t rhlp
  struct (ThreeOperands (opr1, opr2, opr3), insSize)

let opXmVvXmm t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr1 = parseMemOrReg modRM insSize t rhlp
  let opr3 = parseReg (getReg modRM) insSize.RegSize RGrpAttr.ARegBits t
  let oprs = ThreeOperands (opr1, parseVVVVReg t, opr3)
  struct (oprs, insSize)

let opGpr t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr = parseReg (getRM modRM) insSize.RegSize RGrpAttr.AMod11 t
  struct (OneOperand opr, insSize)

let opXmmRmImm8 t (rhlp: ReadHelper) (insSize: InstrSize) =
  let modRM = rhlp.ReadByte ()
  let opr1 = parseReg (getReg modRM) insSize.RegSize RGrpAttr.ARegBits t
  let opr2 = parseMemOrReg modRM insSize t rhlp
  let opr3 = parseOprImm rhlp 8<rt>
  struct (ThreeOperands (opr1, opr2, opr3), insSize)

let opMmxMmImm8 t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr1 = parseMMXReg (getReg modRM)
  let opr2 =
    if modIsReg modRM then parseMMXReg (getRM modRM)
    else parseMemory modRM insSize t rhlp
  let opr3 = parseOprImm rhlp 8<rt>
  struct (ThreeOperands (opr1, opr2, opr3), insSize)

let opMmxRmImm8 t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr1 = parseMMXReg (getReg modRM)
  let opr2 = parseMemOrReg modRM insSize t rhlp
  let opr3 = parseOprImm rhlp 8<rt>
  struct (ThreeOperands (opr1, opr2, opr3), insSize)

let opGprMmxImm8 t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr1 =
    parseReg (getReg modRM) insSize.RegSize RGrpAttr.ARegBits t
  let opr2 =
    if modIsReg modRM then parseMMXReg (getRM modRM)
    else parseMemory modRM insSize t rhlp
  let opr3 = parseOprImm rhlp 8<rt>
  struct (ThreeOperands (opr1, opr2, opr3), insSize)

let opXmmVvXmImm8 t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr1 = parseReg (getReg modRM) insSize.RegSize RGrpAttr.ARegBits t
  let opr2 = parseVVVVReg t
  let opr3 = parseMemOrReg modRM insSize t rhlp
  let opr4 = parseOprImm rhlp 8<rt>
  struct (FourOperands (opr1, opr2, opr3, opr4), insSize)

let opXmRegImm8 t (rhlp: ReadHelper) insSize =
  let modRM = rhlp.ReadByte ()
  let opr1 = parseMemOrReg modRM insSize t rhlp
  let opr2 = parseReg (getReg modRM) insSize.RegSize RGrpAttr.ARegBits t
  let opr3 = parseOprImm rhlp 8<rt>
  struct (ThreeOperands (opr1, opr2, opr3), insSize)

let opGprRmVv t (rhlp: ReadHelper) (insSize: InstrSize) =
  let modRM = rhlp.ReadByte ()
  let opr1 = parseReg (getReg modRM) insSize.RegSize RGrpAttr.ARegBits t
  let opr2 = parseMemOrReg modRM insSize t rhlp
  let opr3 = parseVEXtoGPR t insSize
  struct (ThreeOperands (opr1, opr2, opr3), insSize)

let opVvRmImm8 t (rhlp: ReadHelper) (insSize: InstrSize) =
  let modRM = rhlp.ReadByte ()
  let opr2 = parseMemOrReg modRM insSize t rhlp
  let opr3 = parseOprImm rhlp 8<rt>
  let oprs = ThreeOperands (parseVVVVReg t, opr2, opr3)
  struct (oprs, insSize)

let opRmGprCL t (rhlp: ReadHelper) (insSize: InstrSize) =
  let modRM = rhlp.ReadByte ()
  let opr1 = parseMemOrReg modRM insSize t rhlp
  let opr2 = parseReg (getReg modRM) insSize.RegSize RGrpAttr.ARegBits t
  let opr3 = Register.CL |> OprReg
  struct (ThreeOperands (opr1, opr2, opr3), insSize)

/// Not Encodable
let notEn _ = raise ParsingFailureException

let nor0F10 = function
  | MPref.MPrxNP -> struct (Opcode.MOVUPS, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrx66 -> struct (Opcode.MOVUPD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3 -> struct (Opcode.MOVSS, opGprRm, szDqdDq) (* VdqWdqd *)
  | MPref.MPrxF2 -> struct (Opcode.MOVSD, opGprRm, szDqqDq) (* VdqWdqq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F10Mem = function
  | MPref.MPrxNP -> struct (Opcode.VMOVUPS, opGprRm, szVecDef) (* VpsWps *)
  | MPref.MPrx66 -> struct (Opcode.VMOVUPD, opGprRm, szVecDef) (* VpdWpd *)
  | MPref.MPrxF3 -> struct (Opcode.VMOVSS, opGprRm, szDqdDq) (* VdqMd *)
  | MPref.MPrxF2 -> struct (Opcode.VMOVSD, opGprRm, szDqqDq) (* VdqMq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F10Reg = function
  | MPref.MPrxNP -> struct (Opcode.VMOVUPS, opGprRm, szVecDef) (* VpsWps *)
  | MPref.MPrx66 -> struct (Opcode.VMOVUPD, opGprRm, szVecDef) (* VpdWpd *)
  | MPref.MPrxF3 -> struct (Opcode.VMOVSS, opXmmVvXm, szVecDef) (* VxHxWss *)
  | MPref.MPrxF2 -> struct (Opcode.VMOVSD, opXmmVvXm, szVecDef) (* VxHxWsd *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F11 = function
  | MPref.MPrxNP -> struct (Opcode.MOVUPS, opRmGpr, szDqDq) (* WdqVdq *)
  | MPref.MPrx66 -> struct (Opcode.MOVUPD, opRmGpr, szDqDq) (* WdqVdq *)
  | MPref.MPrxF3 -> struct (Opcode.MOVSS, opRmGpr, szDqdDqMR) (* WdqdVdq *)
  | MPref.MPrxF2 -> struct (Opcode.MOVSD, opRmGpr, szDqqDq) (* WdqqVdq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F11Mem = function
  | MPref.MPrxNP -> struct (Opcode.VMOVUPS, opRmGpr, szVecDef) (* WpsVps *)
  | MPref.MPrx66 -> struct (Opcode.VMOVUPD, opRmGpr, szVecDef) (* WpdVpd *)
  | MPref.MPrxF3 -> struct (Opcode.VMOVSS, opRmGpr, szDqdDqMR) (* MdVdq *)
  | MPref.MPrxF2 -> struct (Opcode.VMOVSD, opRmGpr, szDqqDq) (* MqVdq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F11Reg = function
  | MPref.MPrxNP -> struct (Opcode.VMOVUPS, opRmGpr, szVecDef) (* WpsVps *)
  | MPref.MPrx66 -> struct (Opcode.VMOVUPD, opRmGpr, szVecDef) (* WpdVpd *)
  | MPref.MPrxF3 -> struct (Opcode.VMOVSS, opXmVvXmm, szVecDef) (* WssHxVss *)
  | MPref.MPrxF2 -> struct (Opcode.VMOVSD, opXmVvXmm, szVecDef) (* WsdHxVsd *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F12Mem = function
  | MPref.MPrxNP -> struct (Opcode.MOVLPS, opGprRm, szDqqDq) (* VdqWdqq *)
  | MPref.MPrx66 -> struct (Opcode.MOVLPD, opGprRm, szDqqDq) (* VdqMq *)
  | MPref.MPrxF3 -> struct (Opcode.MOVSLDUP, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF2 -> struct (Opcode.MOVDDUP, opGprRm, szDqqDq) (* VdqWdqq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F12Reg = function
  | MPref.MPrxNP -> struct (Opcode.MOVHLPS, opGprRm, szDqqDq) (* VdqWdqq *)
  | MPref.MPrx66 -> struct (Opcode.MOVLPD, opGprRm, szDqqDq) (* VdqMq *)
  | MPref.MPrxF3 -> struct (Opcode.MOVSLDUP, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF2 -> struct (Opcode.MOVDDUP, opGprRm, szDqqDq) (* VdqWdqq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F12Mem = function
  | MPref.MPrxNP ->
    struct (Opcode.VMOVLPS, opXmmVvXm, szDqqDq) (* VdqHdqWdqq *)
  | MPref.MPrx66 -> struct (Opcode.VMOVLPD, opXmmVvXm, szDqqDq) (* VdqHdqMq *)
  | MPref.MPrxF3 -> struct (Opcode.VMOVSLDUP, opGprRm, szVecDef) (* VxWx *)
  | MPref.MPrxF2 -> struct (Opcode.VMOVDDUP, opGprRm, szXqX) (* VxWxq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F12Reg = function
  | MPref.MPrxNP ->
    struct (Opcode.VMOVHLPS, opXmmVvXm, szDqqDq) (* VdqHdqWdqq *)
  | MPref.MPrx66 -> struct (Opcode.VMOVLPD, opXmmVvXm, szDqqDq) (* VdqHdqMq *)
  | MPref.MPrxF3 -> struct (Opcode.VMOVSLDUP, opGprRm, szVecDef) (* VxWx *)
  | MPref.MPrxF2 -> struct (Opcode.VMOVDDUP, opGprRm, szXqX) (* VxWxq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F13 = function
  | MPref.MPrxNP -> struct (Opcode.MOVLPS, opRmGpr, szDqqDq) (* MqVdq *)
  | MPref.MPrx66 -> struct (Opcode.MOVLPD, opRmGpr, szDqqDq) (* MqVdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F13 = function
  | MPref.MPrxNP -> struct (Opcode.VMOVLPS, opRmGpr, szDqqDq) (* MqVdq *)
  | MPref.MPrx66 -> struct (Opcode.VMOVLPD, opRmGpr, szDqqDq) (* MqVdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F14 = function
  | MPref.MPrxNP -> struct (Opcode.UNPCKLPS, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrx66 -> struct (Opcode.UNPCKLPD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F14 = function
  | MPref.MPrxNP ->
    struct (Opcode.VUNPCKLPS, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrx66 ->
    struct (Opcode.VUNPCKLPD, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F15 = function
  | MPref.MPrxNP -> struct (Opcode.UNPCKHPS, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrx66 -> struct (Opcode.UNPCKHPD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F15 = function
  | MPref.MPrxNP ->
    struct (Opcode.VUNPCKHPS, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrx66 ->
    struct (Opcode.VUNPCKHPD, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F16Mem = function
  | MPref.MPrxNP -> struct (Opcode.MOVHPS, opGprRm, szDqqDq) (* VdqMq *)
  | MPref.MPrx66 -> struct (Opcode.MOVHPD, opGprRm, szDqqDq) (* VdqMq *)
  | MPref.MPrxF3 -> struct (Opcode.MOVSHDUP, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F16Reg = function
  | MPref.MPrxNP -> struct (Opcode.MOVLHPS, opXmmVvXm, szDqDq) (* VdqUdq *)
  | MPref.MPrx66 -> struct (Opcode.MOVHPD, opGprRm, szDqqDq) (* VdqMq *)
  | MPref.MPrxF3 -> struct (Opcode.MOVSHDUP, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F16Mem = function
  | MPref.MPrxNP -> struct (Opcode.VMOVHPS, opXmmVvXm, szDqqDq) (* VdqHdqMq *)
  | MPref.MPrx66 -> struct (Opcode.VMOVHPD, opXmmVvXm, szDqqDq) (* VdqHdqMq *)
  | MPref.MPrxF3 -> struct (Opcode.VMOVSHDUP, opGprRm, szVecDef) (* VxWx *)
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F16Reg = function
  | MPref.MPrxNP ->
    struct (Opcode.VMOVLHPS, opXmmVvXm, szDqDq) (* VdqHdqUdq *)
  | MPref.MPrx66 ->
    struct (Opcode.VMOVHPD, opXmmVvXm, szDqqDq) (* VdqHdqMq *)
  | MPref.MPrxF3 -> struct (Opcode.VMOVSHDUP, opGprRm, szVecDef) (* VxWx *)
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F17 = function
  | MPref.MPrxNP -> struct (Opcode.MOVHPS, opRmGpr, szDqqDq) (* MqVdq *)
  | MPref.MPrx66 -> struct (Opcode.MOVHPD, opRmGpr, szDqqDq) (* MqVdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F17 = function
  | MPref.MPrxNP -> struct (Opcode.VMOVHPS, opRmGpr, szDqqDq) (* MqVdq *)
  | MPref.MPrx66 -> struct (Opcode.VMOVHPD, opRmGpr, szDqqDq) (* MqVdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F1A = function
  | MPref.MPrxNP -> struct (Opcode.BNDLDX, opBndRm, szVyDq) (* BNMib *)
  | MPref.MPrx66 -> struct (Opcode.BNDMOV, opBndBm, szDqqDqWS) (* BNBNdqq *)
  | MPref.MPrxF3 -> struct (Opcode.BNDCL, opBndRm, szVyDq) (* BNEv *)
  | MPref.MPrxF2 -> struct (Opcode.BNDCU, opBndRm, szVyDq) (* BNEv *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F1B = function
  | MPref.MPrxNP -> struct (Opcode.BNDSTX, opRmBnd, szVyDqMR) (* MibBN *)
  | MPref.MPrx66 -> struct (Opcode.BNDMOV, opBmBnd, szDqqDqWS) (* BNdqqBN *)
  | MPref.MPrxF3 -> struct (Opcode.BNDMK, opBndRm, szVyDq) (* BNMv *)
  | MPref.MPrxF2 -> struct (Opcode.BNDCN, opBndRm, szVyDq) (* BNEv *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F28 = function
  | MPref.MPrxNP -> struct (Opcode.MOVAPS, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrx66 -> struct (Opcode.MOVAPD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F28 = function
  | MPref.MPrxNP -> struct (Opcode.VMOVAPS, opRmGpr, szVecDef) (* VpsWps *)
  | MPref.MPrx66 -> struct (Opcode.VMOVAPD, opGprRm, szVecDef) (* VpdWpd *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F29 = function
  | MPref.MPrxNP -> struct (Opcode.MOVAPS, opRmGpr, szDqDq) (* WdqVdq *)
  | MPref.MPrx66 -> struct (Opcode.MOVAPD, opRmGpr, szDqDq) (* WdqVdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F29 = function
  | MPref.MPrxNP -> struct (Opcode.VMOVAPS, opRmGpr, szVecDef) (* WpsVps *)
  | MPref.MPrx66 -> struct (Opcode.VMOVAPD, opRmGpr, szVecDef) (* WpdVpd *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F2A = function
  | MPref.MPrxNP -> struct (Opcode.CVTPI2PS, opGprRMm, szQDq) (* VdqQpi *)
  | MPref.MPrx66 -> struct (Opcode.CVTPI2PD, opGprRMm, szQDq) (* VdqQpi *)
  | MPref.MPrxF3 -> struct (Opcode.CVTSI2SS, opGprRm, szVyDq) (* VdqEy *)
  | MPref.MPrxF2 -> struct (Opcode.CVTSI2SD, opGprRm, szVyDq) (* VdqEy *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F2A = function
  | MPref.MPrxNP
  | MPref.MPrx66 -> raise ParsingFailureException
  | MPref.MPrxF3 ->
    struct (Opcode.VCVTSI2SS, opXmmVvXm, szVyDq) (* VssHssEy *)
  | MPref.MPrxF2 ->
    struct (Opcode.VCVTSI2SD, opXmmVvXm, szVyDq) (* VsdHsdEy *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F2B = function
  | MPref.MPrxNP -> struct (Opcode.MOVNTPS, opRmGpr, szDqDq) (* MdqVdq *)
  | MPref.MPrx66 -> struct (Opcode.MOVNTPD, opRmGpr, szDqDq) (* MdqVdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F2B = function
  | MPref.MPrxNP -> struct (Opcode.VMOVNTPS, opRmGpr, szVecDef) (* MpsVps *)
  | MPref.MPrx66 -> struct (Opcode.VMOVNTPD, opRmGpr, szVecDef) (* MpdVpd *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F2C = function
  | MPref.MPrxNP ->
    struct (Opcode.CVTTPS2PI, opMmxMm, szDqqQ) (* PpiWdqq *)
  | MPref.MPrx66 -> struct (Opcode.CVTTPD2PI, opMmxMm, szDqQ) (* PpiWdq *)
  | MPref.MPrxF3 -> struct (Opcode.CVTTSS2SI, opGprRm, szDqdY) (* GyWdqd *)
  | MPref.MPrxF2 -> struct (Opcode.CVTTSD2SI, opGprRm, szDqqY) (* GyWdqq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F2C = function
  | MPref.MPrxNP
  | MPref.MPrx66 -> raise ParsingFailureException
  | MPref.MPrxF3 -> struct (Opcode.VCVTTSS2SI, opGprRm, szDqdY) (* GyWdqd *)
  | MPref.MPrxF2 -> struct (Opcode.VCVTTSD2SI, opGprRm, szDqqY) (* GyWdqq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F2D = function
  | MPref.MPrxNP -> struct (Opcode.CVTPS2PI, opMmxMm, szDqqQ) (* PpiWdqq *)
  | MPref.MPrx66 -> struct (Opcode.CVTPD2PI, opMmxMm, szDqQ) (* PpiWdq *)
  | MPref.MPrxF3 -> struct (Opcode.CVTSS2SI, opGprRm, szDqdY) (* GyWdqd *)
  | MPref.MPrxF2 -> struct (Opcode.CVTSD2SI, opGprRm, szDqqY) (* GyWdqq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F2D = function
  | MPref.MPrxNP
  | MPref.MPrx66 -> raise ParsingFailureException
  | MPref.MPrxF3 -> struct (Opcode.VCVTSS2SI, opGprRm, szDqdY) (* GyWdqd *)
  | MPref.MPrxF2 -> struct (Opcode.VCVTSD2SI, opGprRm, szDqqY) (* GyWdqq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F2E = function
  | MPref.MPrxNP -> struct (Opcode.UCOMISS, opGprRm, szDqdDq) (* VdqWdqd *)
  | MPref.MPrx66 -> struct (Opcode.UCOMISD, opGprRm, szDqqDq) (* VdqWdqq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F2E = function
  | MPref.MPrxNP -> struct (Opcode.VUCOMISS, opGprRm, szDqdDq) (* VdqWdqd *)
  | MPref.MPrx66 -> struct (Opcode.VUCOMISD, opGprRm, szDqqDq) (* VdqWdqq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F2F = function
  | MPref.MPrxNP -> struct (Opcode.COMISS, opGprRm, szDqdDq) (* VdqWdqd *)
  | MPref.MPrx66 -> struct (Opcode.COMISD, opGprRm, szDqqDq) (* VdqWdqq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F2F = function
  | MPref.MPrxNP -> struct (Opcode.VCOMISS, opGprRm, szDqdDq) (* VdqWdqd *)
  | MPref.MPrx66 -> struct (Opcode.VCOMISD, opGprRm, szDqqDq) (* VdqWdqq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F50 = function
  | MPref.MPrxNP -> struct (Opcode.MOVMSKPS, opGprRm, szDqY) (* GyUdq *)
  | MPref.MPrx66 -> struct (Opcode.MOVMSKPD, opGprRm, szDqY) (* GyUdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F50 = function
  | MPref.MPrxNP -> struct (Opcode.VMOVMSKPS, opGprRm, szDqY) (* GyUdq *)
  | MPref.MPrx66 -> struct (Opcode.VMOVMSKPD, opGprRm, szDqY) (* GyUdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F51 = function
  | MPref.MPrxNP -> struct (Opcode.SQRTPS, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrx66 -> struct (Opcode.SQRTPD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3 -> struct (Opcode.SQRTSS, opGprRm, szDqdDq) (* VdqWdqd *)
  | MPref.MPrxF2 -> struct (Opcode.SQRTSD, opGprRm, szDqqDq) (* VdqWdqq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F51 = function
  | MPref.MPrxNP -> struct (Opcode.VSQRTPS, opGprRm, szVecDef) (* VpsWps *)
  | MPref.MPrx66 -> struct (Opcode.VSQRTPD, opGprRm, szVecDef) (* VpdWpd *)
  | MPref.MPrxF3 ->
    struct (Opcode.VSQRTSS, opXmmVvXm, szDqdDq) (* VdqHdqWdqd *)
  | MPref.MPrxF2 ->
    struct (Opcode.VSQRTSD, opXmmVvXm, szDqqDq) (* VdqHdqWdqq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F52 = function
  | MPref.MPrxNP -> struct (Opcode.RSQRTPS, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrx66 -> raise ParsingFailureException
  | MPref.MPrxF3 -> struct (Opcode.RSQRTSS, opGprRm, szDqdDq) (* VdqWdqd *)
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F52 = function
  | MPref.MPrxNP
  | MPref.MPrx66
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F53 = function
  | MPref.MPrxNP -> struct (Opcode.RCPPS, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrx66 -> raise ParsingFailureException
  | MPref.MPrxF3 -> struct (Opcode.RCPSS, opGprRm, szDqdDq) (* VdqWdqd *)
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F53 = function
  | MPref.MPrxNP
  | MPref.MPrx66
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F54 = function
  | MPref.MPrxNP -> struct (Opcode.ANDPS, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrx66 -> struct (Opcode.ANDPD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F54 = function
  | MPref.MPrxNP ->
    struct (Opcode.VANDPS, opXmmVvXm, szVecDef) (* VpsHpsWps *)
  | MPref.MPrx66 ->
    struct (Opcode.VANDPD, opXmmVvXm, szVecDef) (* VpdHpdWpd *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F55 = function
  | MPref.MPrxNP -> struct (Opcode.ANDNPS, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrx66 -> struct (Opcode.ANDNPD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F55 = function
  | MPref.MPrxNP ->
    struct (Opcode.VANDNPS, opXmmVvXm, szVecDef) (* VpsHpsWps *)
  | MPref.MPrx66 ->
    struct (Opcode.VANDNPD, opXmmVvXm, szVecDef) (* VpdHpdWpd *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F56 = function
  | MPref.MPrxNP -> struct (Opcode.ORPS, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrx66 -> struct (Opcode.ORPD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F56 = function
  | MPref.MPrxNP -> struct (Opcode.VORPS, opXmmVvXm, szVecDef) (* VpsHpsWps *)
  | MPref.MPrx66 -> struct (Opcode.VORPD, opXmmVvXm, szVecDef) (* VpdHpdWpd *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F57 = function
  | MPref.MPrxNP -> struct (Opcode.XORPS, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrx66 -> struct (Opcode.XORPD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F57 = function
  | MPref.MPrxNP ->
    struct (Opcode.VXORPS, opXmmVvXm, szVecDef) (* VpsHpsWps *)
  | MPref.MPrx66 ->
    struct (Opcode.VXORPD, opXmmVvXm, szVecDef) (* VpdHpdWpd *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F58 = function
  | MPref.MPrxNP -> struct (Opcode.ADDPS, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrx66 -> struct (Opcode.ADDPD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3 -> struct (Opcode.ADDSS, opGprRm, szDqdDq) (* VdqWdqd *)
  | MPref.MPrxF2 -> struct (Opcode.ADDSD, opGprRm, szDqqDq) (* VdqWdqq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F58 = function
  | MPref.MPrxNP ->
    struct (Opcode.VADDPS, opXmmVvXm, szVecDef) (* VpsHpsWps *)
  | MPref.MPrx66 ->
    struct (Opcode.VADDPD, opXmmVvXm, szVecDef) (* VpdHpdWpd *)
  | MPref.MPrxF3 ->
    struct (Opcode.VADDSS, opXmmVvXm, szDqdDq) (* VdqHdqWdqd *)
  | MPref.MPrxF2 ->
    struct (Opcode.VADDSD, opXmmVvXm, szDqqDq) (* VdqHdqWdqq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F59 = function
  | MPref.MPrxNP -> struct (Opcode.MULPS, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrx66 -> struct (Opcode.MULPD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3 -> struct (Opcode.MULSS, opGprRm, szDqdDq) (* VdqWdqd *)
  | MPref.MPrxF2 -> struct (Opcode.MULSD, opGprRm, szDqqDq) (* VdqWdqq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F59 = function
  | MPref.MPrxNP ->
    struct (Opcode.VMULPS, opXmmVvXm, szVecDef) (* VpsHpsWps *)
  | MPref.MPrx66 ->
    struct (Opcode.VMULPD, opXmmVvXm, szVecDef) (* VpdHpdWpd *)
  | MPref.MPrxF3 ->
    struct (Opcode.VMULSS, opXmmVvXm, szDqdDq) (* VdqHdqWdqd *)
  | MPref.MPrxF2 ->
    struct (Opcode.VMULSD, opXmmVvXm, szDqqDq) (* VdqHdqWdqq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F5A = function
  | MPref.MPrxNP -> struct (Opcode.CVTPS2PD, opGprRm, szDqqDq) (* VdqWdqq *)
  | MPref.MPrx66 -> struct (Opcode.CVTPD2PS, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3 -> struct (Opcode.CVTSS2SD, opGprRm, szDqdDq) (* VdqWdqd *)
  | MPref.MPrxF2 -> struct (Opcode.CVTSD2SS, opGprRm, szDqqDq) (* VdqWdqq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F5A = function
  | MPref.MPrxNP
  | MPref.MPrx66 -> raise ParsingFailureException
  | MPref.MPrxF3 ->
    struct (Opcode.VCVTSS2SD, opXmmVvXm, szDqdDq) (* VdqHdqWdqd *)
  | MPref.MPrxF2 ->
    struct (Opcode.VCVTSD2SS, opXmmVvXm, szDqqDq) (* VdqHdqWdqq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F5AW0 = function
  | MPref.MPrxNP -> struct (Opcode.VCVTPS2PD, opGprRm, szXqXz) (* VZxzWxq *)
  | MPref.MPrx66
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F5AW1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VCVTPD2PS, opGprRm, szXzX) (* VxWZxz *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F5B = function
  | MPref.MPrxNP -> struct (Opcode.CVTDQ2PS, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrx66 -> struct (Opcode.CVTPS2DQ, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3 -> struct (Opcode.CVTTPS2DQ, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F5B = function
  | MPref.MPrxNP
  | MPref.MPrx66
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F5C = function
  | MPref.MPrxNP -> struct (Opcode.SUBPS, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrx66 -> struct (Opcode.SUBPD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3 -> struct (Opcode.SUBSS, opGprRm, szDqdDq) (* VdqWdqd *)
  | MPref.MPrxF2 -> struct (Opcode.SUBSD, opGprRm, szDqqDq) (* VdqWdqq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F5C = function
  | MPref.MPrxNP ->
    struct (Opcode.VSUBPS, opXmmVvXm, szVecDef) (* VpsHpsWps *)
  | MPref.MPrx66 ->
    struct (Opcode.VSUBPD, opXmmVvXm, szVecDef) (* VpdHpdWpd *)
  | MPref.MPrxF3 ->
    struct (Opcode.VSUBSS, opXmmVvXm, szDqdDq) (* VdqHdqWdqd *)
  | MPref.MPrxF2 ->
    struct (Opcode.VSUBSD, opXmmVvXm, szDqqDq) (* VdqHdqWdqq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F5D = function
  | MPref.MPrxNP -> struct (Opcode.MINPS, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrx66 -> struct (Opcode.MINPD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3 -> struct (Opcode.MINSS, opGprRm, szDqdDq) (* VdqWdqd *)
  | MPref.MPrxF2 -> struct (Opcode.MINSD, opGprRm, szDqqDq) (* VdqWdqq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F5D = function
  | MPref.MPrxNP ->
    struct (Opcode.InvalOP, opXmmVvXm, szVecDef) (* VpsHpsWps *)
  | MPref.MPrx66 ->
    struct (Opcode.InvalOP, opXmmVvXm, szVecDef) (* VpdHpdWpd *)
  | MPref.MPrxF3 ->
    struct (Opcode.VMINSS, opXmmVvXm, szDqdDq) (* VdqHdqWdqd *)
  | MPref.MPrxF2 ->
    struct (Opcode.InvalOP, opXmmVvXm, szDqqDq) (* VdqHdqWdqq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F5DW0 = function
  | MPref.MPrxNP
  | MPref.MPrx66 -> raise ParsingFailureException
  | MPref.MPrxF3 ->
    struct (Opcode.VMINSS, opXmmVvXm, szDqdDq) (* VdqHdqWdqd *)
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F5E = function
  | MPref.MPrxNP -> struct (Opcode.DIVPS, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrx66 -> struct (Opcode.DIVPD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3 -> struct (Opcode.DIVSS, opGprRm, szDqdDq) (* VdqWdqd *)
  | MPref.MPrxF2 -> struct (Opcode.DIVSD, opGprRm, szDqqDq) (* VdqWdqq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F5E = function
  | MPref.MPrxNP ->
    struct (Opcode.VDIVPS, opXmmVvXm, szVecDef) (* VpsHpsWps *)
  | MPref.MPrx66 ->
    struct (Opcode.VDIVPD, opXmmVvXm, szVecDef) (* VpdHpdWpd *)
  | MPref.MPrxF3 ->
    struct (Opcode.VDIVSS, opXmmVvXm, szDqdDq) (* VdqHdqWdqd *)
  | MPref.MPrxF2 ->
    struct (Opcode.VDIVSD, opXmmVvXm, szDqqDq) (* VdqHdqWdqq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F5F = function
  | MPref.MPrxNP -> struct (Opcode.MAXPS, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrx66 -> struct (Opcode.MAXPD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3 -> struct (Opcode.MAXSS, opGprRm, szDqdDq) (* VdqWdqd *)
  | MPref.MPrxF2 -> struct (Opcode.MAXSD, opGprRm, szDqqDq) (* VdqWdqq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F5F = function
  | MPref.MPrxNP ->
    struct (Opcode.VMAXPS, opXmmVvXm, szVecDef) (* VpsHpsWps *)
  | MPref.MPrx66 ->
    struct (Opcode.InvalOP, opXmmVvXm, szVecDef) (* VpdHpdWpd *)
  | MPref.MPrxF3 ->
    struct (Opcode.VMAXSS, opXmmVvXm, szDqdDq) (* VdqHdqWdqd *)
  | MPref.MPrxF2 ->
    struct (Opcode.VMAXSD, opXmmVvXm, szDqqDq) (* VdqHdqWdqq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F5FW0 = function
  | MPref.MPrxNP -> struct (Opcode.VMAXPS, opXmmVvXm, szXzXz) (* VZxzHxWZxz *)
  | MPref.MPrx66 -> raise ParsingFailureException
  | MPref.MPrxF3 ->
    struct (Opcode.VMAXSS, opXmmVvXm, szDqdDq) (* VdqHdqWdqd *)
  | MPref.MPrxF2 ->
    struct (Opcode.InvalOP, opXmmVvXm, szDqqDq) (* VdqHdqWdqq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F5FW1 = function
  | MPref.MPrxNP
  | MPref.MPrx66
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2 ->
    struct (Opcode.VMAXSD, opXmmVvXm, szDqqDq) (* VdqHdqWdqq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F60 = function
  | MPref.MPrxNP -> struct (Opcode.PUNPCKLBW, opMmxRm, szDQ) (* PqQd *)
  | MPref.MPrx66 -> struct (Opcode.PUNPCKLBW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F60 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPUNPCKLBW, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F61 = function
  | MPref.MPrxNP -> struct (Opcode.PUNPCKLWD, opMmxRm, szDQ) (* PqQd *)
  | MPref.MPrx66 -> struct (Opcode.PUNPCKLWD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F61 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPUNPCKLWD, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F62 = function
  | MPref.MPrxNP -> struct (Opcode.PUNPCKLDQ, opMmxRm, szDQ) (* PqQd *)
  | MPref.MPrx66 -> struct (Opcode.PUNPCKLDQ, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F62 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPUNPCKLDQ, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F63 = function
  | MPref.MPrxNP -> struct (Opcode.PACKSSWB, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PACKSSWB, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F63 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPACKSSWB, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F64 = function
  | MPref.MPrxNP -> struct (Opcode.PCMPGTB, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PCMPGTB, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F64 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPCMPGTB, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F65 = function
  | MPref.MPrxNP -> struct (Opcode.PCMPGTW, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PCMPGTW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F65 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPCMPGTW, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F66 = function
  | MPref.MPrxNP -> struct (Opcode.PCMPGTD, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PCMPGTD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F66 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPCMPGTD, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F67 = function
  | MPref.MPrxNP -> struct (Opcode.PACKUSWB, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PACKUSWB, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F67 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPACKUSWB, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F68 = function
  | MPref.MPrxNP -> struct (Opcode.PUNPCKHBW, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PUNPCKHBW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F68 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPUNPCKHBW, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F69 = function
  | MPref.MPrxNP -> struct (Opcode.PUNPCKHWD, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PUNPCKHWD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F69 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPUNPCKHWD, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F6A = function
  | MPref.MPrxNP -> struct (Opcode.PUNPCKHDQ, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PUNPCKHDQ, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F6A = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPUNPCKHDQ, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F6B = function
  | MPref.MPrxNP -> struct (Opcode.PACKSSDW, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PACKSSDW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F6B = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPACKSSDW, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F6C = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PUNPCKLQDQ, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F6C = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPUNPCKLQDQ, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F6D = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PUNPCKHQDQ, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F6D = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPUNPCKHQDQ, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F6EW1 = function
  | MPref.MPrxNP -> struct (Opcode.MOVQ, opMmxMm, szYQRM) (* PqEy *)
  | MPref.MPrx66 -> struct (Opcode.MOVQ, opGprRm, szVyDq) (* VdqEy *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F6EW0 = function
  | MPref.MPrxNP -> struct (Opcode.MOVD, opMmxMm, szYQRM) (* PqEy *)
  | MPref.MPrx66 -> struct (Opcode.MOVD, opGprRm, szVyDq) (* VdqEy *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F6EW1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VMOVQ, opGprRm, szVyDq) (* VdqEy *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F6EW0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VMOVD, opGprRm, szVyDq) (* VdqEy *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F6F = function
  | MPref.MPrxNP -> struct (Opcode.MOVQ, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.MOVDQA, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3 -> struct (Opcode.MOVDQU, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F6F = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VMOVDQA, opGprRm, szVecDef) (* VxWx *)
  | MPref.MPrxF3 -> struct (Opcode.VMOVDQU, opGprRm, szVecDef) (* VxWx *)
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F6FW1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VMOVDQA64, opGprRm, szVecDef) (* VZxzWZxz *)
  | MPref.MPrxF3 ->
    struct (Opcode.VMOVDQU64, opGprRm, szVecDef) (* VZxzWZxz *)
  | MPref.MPrxF2 ->
    struct (Opcode.VMOVDQU16, opGprRm, szVecDef) (* VZxzWZxz *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F6FW0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VMOVDQA32, opGprRm, szVecDef) (* VZxzWZxz *)
  | MPref.MPrxF3 ->
    struct (Opcode.VMOVDQU32, opGprRm, szVecDef) (* VZxzWZxz *)
  | MPref.MPrxF2 -> struct (Opcode.VMOVDQU8, opGprRm, szVecDef) (* VZxzWZxz *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F70 = function
  | MPref.MPrxNP -> struct (Opcode.PSHUFW, opMmxMmImm8, szQQ) (* PqQqIb *)
  | MPref.MPrx66 -> struct (Opcode.PSHUFD, opXmmRmImm8, szDqDq) (* VdqWdqIb *)
  | MPref.MPrxF3 ->
    struct (Opcode.PSHUFHW, opXmmRmImm8, szDqDq) (* VdqWdqIb *)
  | MPref.MPrxF2 ->
    struct (Opcode.PSHUFLW, opXmmRmImm8, szDqDq) (* VdqWdqIb *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F70 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPSHUFD, opXmmRmImm8, szVecDef) (* VxWxIb *)
  | MPref.MPrxF3 ->
    struct (Opcode.VPSHUFHW, opXmmRmImm8, szVecDef) (* VxWxIb *)
  | MPref.MPrxF2 ->
    struct (Opcode.VPSHUFLW, opXmmRmImm8, szVecDef) (* VxWxIb *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F74 = function
  | MPref.MPrxNP -> struct (Opcode.PCMPEQB, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PCMPEQB, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F74 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPCMPEQB, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F75 = function
  | MPref.MPrxNP -> struct (Opcode.PCMPEQW, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PCMPEQW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F75 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPCMPEQW, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F76 = function
  | MPref.MPrxNP -> struct (Opcode.PCMPEQD, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PCMPEQD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F76 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPCMPEQD, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F77 = function
  | MPref.MPrxNP -> struct (Opcode.EMMS, opNo, szDef) (* NoOpr *)
  | MPref.MPrx66
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F77 = function
  | MPref.MPrxNP -> struct (Opcode.VZEROUPPER, opNo, szDef) (* NoOpr *)
  | MPref.MPrx66
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F7EW1 = function
  | MPref.MPrxNP -> struct (Opcode.MOVQ, opRMMmx, szYQ) (* EyPq *)
  | MPref.MPrx66 -> struct (Opcode.MOVQ, opRmGpr, szVyDqMR) (* EyVdq *)
  | MPref.MPrxF3 -> struct (Opcode.MOVQ, opGprRm, szDqqDq) (* VdqWdqq *)
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F7EW0 = function
  | MPref.MPrxNP -> struct (Opcode.MOVD, opRMMmx, szYQ) (* EyPq *)
  | MPref.MPrx66 -> struct (Opcode.MOVD, opRmGpr, szVyDqMR) (* EyVdq *)
  | MPref.MPrxF3 -> struct (Opcode.MOVQ, opGprRm, szDqqDq) (* VdqWdqq *)
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F7EW1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VMOVQ, opRmGpr, szVyDqMR) (* EyVdq *)
  | MPref.MPrxF3 -> struct (Opcode.VMOVQ, opGprRm, szDqqDq) (* VdqWdqq *)
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F7EW0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VMOVD, opRmGpr, szVyDqMR) (* EyVdq *)
  | MPref.MPrxF3 -> struct (Opcode.VMOVQ, opGprRm, szDqqDq) (* VdqWdqq *)
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F7F = function
  | MPref.MPrxNP -> struct (Opcode.MOVQ, opMmMmx, szQQ) (* QqPq *)
  | MPref.MPrx66 -> struct (Opcode.MOVDQA, opRmGpr, szDqDq) (* WdqVdq *)
  | MPref.MPrxF3 -> struct (Opcode.MOVDQU, opRmGpr, szDqDq) (* WdqVdq *)
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F7F = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VMOVDQA, opRmGpr, szVecDef) (* WxVx *)
  | MPref.MPrxF3 -> struct (Opcode.VMOVDQU, opRmGpr, szVecDef) (* WxVx *)
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F7FW1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VMOVDQA64, opRmGpr, szVecDef) (* WZxzVZxz *)
  | MPref.MPrxF3 ->
    struct (Opcode.VMOVDQU64, opRmGpr, szVecDef) (* WZxzVZxz *)
  | MPref.MPrxF2 ->
    struct (Opcode.VMOVDQU16, opRmGpr, szVecDef) (* WZxzVZxz *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F7FW0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VMOVDQA32, opRmGpr, szVecDef) (* WZxzVZxz *)
  | MPref.MPrxF3 ->
    struct (Opcode.VMOVDQU32, opRmGpr, szVecDef) (* WZxzVZxz *)
  | MPref.MPrxF2 -> struct (Opcode.VMOVDQU8, opRmGpr, szVecDef) (* WZxzVZxz *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FC2 = function
  | MPref.MPrxNP -> struct (Opcode.CMPPS, opXmmRmImm8, szDqDq) (* VdqWdqIb *)
  | MPref.MPrx66 -> struct (Opcode.CMPPD, opXmmRmImm8, szDqDq) (* VdqWdqIb *)
  | MPref.MPrxF3 ->
    struct (Opcode.CMPSS, opXmmRmImm8, szDqdDq) (* VdqWdqdIb *)
  | MPref.MPrxF2 ->
    struct (Opcode.CMPSD, opXmmRmImm8, szDqqDq) (* VdqWdqqIb *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FC2 = function
  | MPref.MPrxNP ->
    struct (Opcode.InvalOP, opXmmVvXmImm8, szVecDef) (* VpsHpsWpsIb *)
  | MPref.MPrx66 ->
    struct (Opcode.InvalOP, opXmmVvXmImm8, szVecDef) (* VpdHpdWpdIb *)
  | MPref.MPrxF3 ->
    struct (Opcode.InvalOP, opXmmVvXmImm8, szVecDef) (* VssHssWssIb *)
  | MPref.MPrxF2 ->
    struct (Opcode.InvalOP, opXmmVvXmImm8, szVecDef) (* VsdHsdWsdIb *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0FC2W0 = function
  | MPref.MPrxNP ->
    struct (Opcode.VCMPPS, opXmmVvXmImm8, szXzXz) (* VZxzHxWZxzIb *)
  | MPref.MPrx66
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0FC2W1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VCMPPD, opXmmVvXmImm8, szXzXz) (* VZxzHxWZxzIb *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FC4 = function
  | MPref.MPrxNP -> struct (Opcode.PINSRW, opMmxRmImm8, szDwQ) (* PqEdwIb *)
  | MPref.MPrx66 -> struct (Opcode.PINSRW, opXmmRmImm8, szDwDq) (* VdqEdwIb *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FC4 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPINSRW, opXmmVvXmImm8, szDwDq) (* VdqHdqEdwIb *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FC5 = function
  | MPref.MPrxNP -> struct (Opcode.PEXTRW, opGprMmxImm8, szQD) (* GdNqIb *)
  | MPref.MPrx66 -> struct (Opcode.PEXTRW, opXmmRmImm8, szDqd) (* GdUdqIb *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FC5 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPEXTRW, opXmmRmImm8, szDqd) (* GdUdqIb *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FC6 = function
  | MPref.MPrxNP -> struct (Opcode.SHUFPS, opXmmRmImm8, szDqDq) (* VdqWdqIb *)
  | MPref.MPrx66 -> struct (Opcode.SHUFPD, opXmmRmImm8, szDqDq) (* VdqWdqIb *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FC6 = function
  | MPref.MPrxNP ->
    struct (Opcode.VSHUFPS, opXmmVvXmImm8, szVecDef) (* VpsHpsWpsIb *)
  | MPref.MPrx66 ->
    struct (Opcode.VSHUFPD, opXmmVvXmImm8, szVecDef) (* VpdHpdWpdIb *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FD1 = function
  | MPref.MPrxNP -> struct (Opcode.PSRLW, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PSRLW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FD1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPSRLW, opXmmVvXm, szDqX) (* VxHxWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FD2 = function
  | MPref.MPrxNP -> struct (Opcode.PSRLD, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PSRLD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FD2 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPSRLD, opXmmVvXm, szDqX) (* VxHxWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FD3 = function
  | MPref.MPrxNP -> struct (Opcode.PSRLQ, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PSRLQ, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FD3 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPSRLQ, opXmmVvXm, szDqX) (* VxHxWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FD4 = function
  | MPref.MPrxNP -> struct (Opcode.PADDQ, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PADDQ, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FD4 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPADDQ, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FD5 = function
  | MPref.MPrxNP -> struct (Opcode.PMULLW, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PMULLW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FD5 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPMULLW, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FD6 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.MOVQ, opRmGpr, szDqqDq) (* WdqqVdq *)
  | MPref.MPrxF3 -> struct (Opcode.MOVQ2DQ, opGprRMm, szQDq) (* VdqNq *)
  | MPref.MPrxF2 -> struct (Opcode.MOVDQ2Q, opMmxMm, szDqQ) (* PqUdq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FD6 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VMOVQ, opRmGpr, szDqqDq) (* WdqqVdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FD7 = function
  | MPref.MPrxNP -> struct (Opcode.PMOVMSKB, opGprRMm, szQD) (* GdNq *)
  | MPref.MPrx66 -> struct (Opcode.PMOVMSKB, opGprRm, szDqd) (* GdUdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FD7 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPMOVMSKB, opGprRm, szXD) (* GdUx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FD8 = function
  | MPref.MPrxNP -> struct (Opcode.PSUBUSB, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PSUBUSB, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FD8 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPSUBUSB, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FD9 = function
  | MPref.MPrxNP -> struct (Opcode.PSUBUSW, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PSUBUSW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FD9 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPSUBUSW, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FDA = function
  | MPref.MPrxNP -> struct (Opcode.PMINUB, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PMINUB, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FDA = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPMINUB, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FDB = function
  | MPref.MPrxNP -> struct (Opcode.PAND, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PAND, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FDB = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPAND, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FDC = function
  | MPref.MPrxNP -> struct (Opcode.PADDUSB, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PADDUSB, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FDC = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPADDUSB, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FDD = function
  | MPref.MPrxNP -> struct (Opcode.PADDUSW, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PADDUSW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FDD = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPADDUSW, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FDE = function
  | MPref.MPrxNP -> struct (Opcode.PMAXUB, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PMAXUB, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FDE = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPMAXUB, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FDF = function
  | MPref.MPrxNP -> struct (Opcode.PANDN, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PANDN, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FDF = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPANDN, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FE0 = function
  | MPref.MPrxNP -> struct (Opcode.PAVGB, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PAVGB, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FE0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPAVGB, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FE1 = function
  | MPref.MPrxNP -> struct (Opcode.PSRAW, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PSRAW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FE1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPSRAW, opXmmVvXm, szDqX) (* VxHxWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FE2 = function
  | MPref.MPrxNP -> struct (Opcode.PSRAD, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PSRAD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FE2 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPSRAD, opXmmVvXm, szDqX) (* VxHxWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FE3 = function
  | MPref.MPrxNP -> struct (Opcode.PAVGW, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PAVGW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FE3 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPAVGW, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FE4 = function
  | MPref.MPrxNP -> struct (Opcode.PMULHUW, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PMULHUW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FE4 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPMULHUW, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FE5 = function
  | MPref.MPrxNP -> struct (Opcode.PMULHW, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PMULHW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FE5 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPMULHW, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FE6 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.CVTTPD2DQ, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3 -> struct (Opcode.CVTDQ2PD, opGprRm, szDqqDq) (* VdqWdqq *)
  | MPref.MPrxF2 -> struct (Opcode.CVTPD2DQ, opGprRm, szDqDq) (* VdqWdq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FE6 = function
  | MPref.MPrxNP
  | MPref.MPrx66 -> raise ParsingFailureException
  | MPref.MPrxF3 ->
    struct (Opcode.VCVTDQ2PD, opGprRm, szDqqdqX) (* VxWdqqdq *)
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0FE6W0 = function
  | MPref.MPrxNP
  | MPref.MPrx66 -> raise ParsingFailureException
  | MPref.MPrxF3 -> struct (Opcode.VCVTDQ2PD, opGprRm, szXXz) (* VZxzWx *)
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FE7 = function
  | MPref.MPrxNP -> struct (Opcode.MOVNTQ, opRMMmx, szQQ) (* MqPq *)
  | MPref.MPrx66 -> struct (Opcode.MOVNTDQ, opRmGpr, szDqDq) (* MdqVdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FE7 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VMOVNTDQ, opRmGpr, szVecDef) (* MxVx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0FE7W1 = function
  | MPref.MPrxNP
  | MPref.MPrx66
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0FE7W0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VMOVNTDQ, opRmGpr, szVecDef) (* MZxzVZxz *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FE8 = function
  | MPref.MPrxNP -> struct (Opcode.PSUBSB, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PSUBSB, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FE8 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPSUBSB, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FE9 = function
  | MPref.MPrxNP -> struct (Opcode.PSUBSW, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PSUBSW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FE9 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPSUBSW, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FEA = function
  | MPref.MPrxNP -> struct (Opcode.PMINSW, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PMINSW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FEA = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPMINSW, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FEB = function
  | MPref.MPrxNP -> struct (Opcode.POR, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.POR, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FEB = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPOR, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FEC = function
  | MPref.MPrxNP -> struct (Opcode.PADDSB, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PADDSB, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FEC = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPADDSB, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FED = function
  | MPref.MPrxNP -> struct (Opcode.PADDSW, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PADDSW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FED = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPADDSW, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FEE = function
  | MPref.MPrxNP -> struct (Opcode.PMAXSW, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PMAXSW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FEE = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPMAXSW, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FEF = function
  | MPref.MPrxNP -> struct (Opcode.PXOR, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PXOR, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FEF = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPXOR, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0FEFW0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPXORD, opXmmVvXm, szXzXz) (* VZxzHxWZxz *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0FEFW1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPXORQ, opXmmVvXm, szXzXz) (* VZxzHxWZxz *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FF0 = function
  | MPref.MPrxNP
  | MPref.MPrx66
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2 -> struct (Opcode.LDDQU, opGprRm, szDqDq) (* VdqMdq *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FF0 = function
  | MPref.MPrxNP
  | MPref.MPrx66
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2 -> struct (Opcode.VLDDQU, opGprRm, szVecDef) (* VxMx *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FF1 = function
  | MPref.MPrxNP -> struct (Opcode.PSLLW, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PSLLW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FF1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPSLLW, opXmmVvXm, szDqX) (* VxHxWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FF2 = function
  | MPref.MPrxNP -> struct (Opcode.PSLLD, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PSLLD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FF2 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPSLLD, opXmmVvXm, szDqX) (* VxHxWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FF3 = function
  | MPref.MPrxNP -> struct (Opcode.PSLLQ, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PSLLQ, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FF3 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPSLLQ, opXmmVvXm, szDqX) (* VxHxWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FF4 = function
  | MPref.MPrxNP -> struct (Opcode.PMULUDQ, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PMULUDQ, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FF4 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPMULUDQ, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FF5 = function
  | MPref.MPrxNP -> struct (Opcode.PMADDWD, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PMADDWD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FF5 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPMADDWD, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FF6 = function
  | MPref.MPrxNP -> struct (Opcode.PSADBW, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PSADBW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FF6 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPSADBW, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FF8 = function
  | MPref.MPrxNP -> struct (Opcode.PSUBB, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PSUBB, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FF8 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPSUBB, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FF9 = function
  | MPref.MPrxNP -> struct (Opcode.PSUBW, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PSUBW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FF9 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPSUBW, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FFA = function
  | MPref.MPrxNP -> struct (Opcode.PSUBD, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PSUBD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FFA = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPSUBD, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FFB = function
  | MPref.MPrxNP -> struct (Opcode.PSUBQ, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PSUBQ, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FFB = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPSUBQ, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FFC = function
  | MPref.MPrxNP -> struct (Opcode.PADDB, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PADDB, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FFC = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPADDB, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FFD = function
  | MPref.MPrxNP -> struct (Opcode.PADDW, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PADDW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FFD = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPADDW, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0FFE = function
  | MPref.MPrxNP -> struct (Opcode.PADDD, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PADDD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0FFE = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPADDD, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3800 = function
  | MPref.MPrxNP -> struct (Opcode.PSHUFB, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PSHUFB, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3800 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPSHUFB, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3801 = function
  | MPref.MPrxNP -> struct (Opcode.PHADDW, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PHADDW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3801 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPHADDW, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3802 = function
  | MPref.MPrxNP -> struct (Opcode.PHADDD, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PHADDD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3802 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPHADDD, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3803 = function
  | MPref.MPrxNP -> struct (Opcode.PHADDSW, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PHADDSW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3803 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPHADDSW, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3805 = function
  | MPref.MPrxNP -> struct (Opcode.PHSUBW, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PHSUBW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3805 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPHSUBW, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3806 = function
  | MPref.MPrxNP -> struct (Opcode.PHSUBD, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PHSUBD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3806 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPHSUBD, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3807 = function
  | MPref.MPrxNP -> struct (Opcode.PHSUBSW, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PHSUBSW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3807 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPHSUBSW, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3808 = function
  | MPref.MPrxNP -> struct (Opcode.PSIGNB, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PSIGNB, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3808 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPSIGNB, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3809 = function
  | MPref.MPrxNP -> struct (Opcode.PSIGNW, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PSIGNW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3809 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPSIGNW, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F380A = function
  | MPref.MPrxNP -> struct (Opcode.PSIGND, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PSIGND, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F380A = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPSIGND, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F380B = function
  | MPref.MPrxNP -> struct (Opcode.PMULHRSW, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PMULHRSW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F380B = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPMULHRSW, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3817 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PTEST, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3817 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPTEST, opGprRm, szVecDef) (* VxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3818W0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VBROADCASTSS, opGprRm, szDX) (* VxMd *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F3818W0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VBROADCASTSS, opGprRm, szDqdXz) (* VZxzWdqd *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3819W0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VBROADCASTSD, opGprRm, szDqqQq) (* VqqWdqq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F3819W1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VBROADCASTSD, opGprRm, szDqqXz) (* VZxzWdqq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F381C = function
  | MPref.MPrxNP -> struct (Opcode.PABSB, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PABSB, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F381C = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPABSB, opGprRm, szVecDef) (* VxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F381D = function
  | MPref.MPrxNP -> struct (Opcode.PABSW, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PABSW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F381D = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPABSW, opGprRm, szVecDef) (* VxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F381E = function
  | MPref.MPrxNP -> struct (Opcode.PABSD, opMmxRm, szQQ) (* PqQq *)
  | MPref.MPrx66 -> struct (Opcode.PABSD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F381E = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPABSD, opGprRm, szVecDef) (* VxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3820 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PMOVSXBW, opGprRm, szDqqDq) (* VdqWdqq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3820 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPMOVSXBW, opGprRm, szDqqdqX) (* VxWdqqdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3821 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PMOVSXBD, opGprRm, szDqdDq) (* VdqWdqd *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3821 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPMOVSXBD, opGprRm, szDqddqX) (* VxWdqdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3822 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PMOVSXBQ, opGprRm, szDqwDq) (* VdqWdqw *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3822 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPMOVSXBQ, opGprRm, szDqwX) (* VxWdqwd *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3823 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PMOVSXWD, opGprRm, szDqqDq) (* VdqWdqq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3823 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPMOVSXWD, opGprRm, szDqqdqX) (* VxWdqqdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3824 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PMOVSXWQ, opGprRm, szDqdDq) (* VdqWdqd *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3824 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPMOVSXWQ, opGprRm, szDqddqX) (* VxWdqdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3825 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PMOVSXDQ, opGprRm, szDqqDq) (* VdqWdqq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3825 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPMOVSXDQ, opGprRm, szDqqdqX) (* VxWdqqdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3828 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PMULDQ, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3828 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPMULDQ, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3829 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PCMPEQQ, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3829 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPCMPEQQ, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F382B = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PACKUSDW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F382B = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPACKUSDW, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3830 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PMOVZXBW, opGprRm, szDqqDq) (* VdqWdqq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3830 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPMOVZXBW, opGprRm, szDqqdqX) (* VxWdqqdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F3830 = function
  | MPref.MPrxNP
  | MPref.MPrx66 -> raise ParsingFailureException
  | MPref.MPrxF3 -> struct (Opcode.VPMOVWB, opRmGpr, szQqXz) (* WqqVZxz *)
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3831 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PMOVZXBD, opGprRm, szDqdDq) (* VdqWdqd *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3831 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPMOVZXBD, opGprRm, szDqddqX) (* VxWdqdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3832 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PMOVZXBQ, opGprRm, szDqwDq) (* VdqWdqw *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3832 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPMOVZXBQ, opGprRm, szDqwX) (* VxWdqwd *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3833 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PMOVZXWD, opGprRm, szDqqDq) (* VdqWdqq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3833 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPMOVZXWD, opGprRm, szDqqdqX) (* VxWdqqdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F3833 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPMOVZXWD, opGprRm, szXqXz) (* VZxzWxq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3834 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PMOVZXWQ, opGprRm, szDqdDq) (* VdqWdqd *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3834 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPMOVZXWQ, opGprRm, szDqddqX) (* VxWdqdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3835 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PMOVZXDQ, opGprRm, szDqqDq) (* VdqWdqq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3835 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPMOVZXDQ, opGprRm, szDqqdqX) (* VxWdqqdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3837 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PCMPGTQ, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3837 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPCMPGTQ, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3838 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PMINSB, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3838 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPMINSB, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3839 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PMINSD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3839 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPMINSD, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F383A = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PMINUW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F383A = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPMINUW, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F383B = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PMINUD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F383B = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPMINUD, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F383C = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PMAXSB, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F383C = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPMAXSB, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F383D = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PMAXSD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F383D = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPMAXSD, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F383E = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PMAXUW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F383E = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPMAXUW, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F383F = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PMAXUD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F383F = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPMAXUD, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3840 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PMULLD, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3840 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPMULLD, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3841 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PHMINPOSUW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3841 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPHMINPOSUW, opGprRm, szDqDq) (* VdqWdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3858W0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPBROADCASTD, opGprRm, szDqdX) (* VxWdqd *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F3858W0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPBROADCASTD, opGprRm, szDqdXz) (* VZxzWdqd *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F385A = function
  | MPref.MPrxNP
  | MPref.MPrx66
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F385A = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VBROADCASTI128, opGprRm, szDqQqq) (* VqqMdq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F3875W1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPERMI2W, opXmmVvXm, szXzXz) (* VZxzHxWZxz *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F3876W0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPERMI2D, opXmmVvXm, szXzXz) (* VZxzHxWZxz *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F3877W1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPERMI2PD, opXmmVvXm, szXzXz) (* VZxzHxWZxz *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3878 = function
  | MPref.MPrxNP
  | MPref.MPrx66
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3878 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPBROADCASTB, opGprRm, szDqbX) (* VxWdqb *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F387AW0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPBROADCASTB, opGprRm, szDXz) (* VZxzRd *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F387CW0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPBROADCASTD, opGprRm, szDXz) (* VZxzRd *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F387CW1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.VPBROADCASTQ, opGprRm, szQXz) (* VZxzRq *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3890W0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPGATHERDD, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F3890W0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPGATHERDD, opGprRm, szVecDef) (* VZxzWZxz *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3892W0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VGATHERDPS, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F3892W0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VGATHERDPS, opGprRm, szVecDef) (* VZxzWZxz *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3898W1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VFMADD132PD, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F3898W1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VFMADD132PD, opXmmVvXm, szXzXz) (* VZxzHxWZxz *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3899W0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VFMADD132SS, opXmmVvXm, szDqdXz) (* VxHxWdqd *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3899W1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VFMADD132SD, opXmmVvXm, szDqqX) (* VxHxWdqq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F389BW0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VFMSUB132SS, opXmmVvXm, szDqdDq) (* VdqHdqWdqd *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F389BW0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VFMSUB132SS, opXmmVvXm, szDqdDq) (* VdqHdqWdqd *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F389CW1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VFNMADD132PD, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F389CW1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VFNMADD132PD, opXmmVvXm, szXzXz) (* VZxzHxWZxz *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F389DW1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VFNMADD132SD, opXmmVvXm, szDqqDq) (* VdqHdqWdqq *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F389DW1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VFNMADD132SD, opXmmVvXm, szDqqDq) (* VdqHdqWdqq *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F38A8W0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VFMADD213PS, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F38A8W0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VFMADD213PS, opXmmVvXm, szXzXz) (* VZxzHxWZxz *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F38A9W0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VFMADD213SS, opXmmVvXm, szDqdXz) (* VxHxWdqd *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F38A9W1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VFMADD213SD, opXmmVvXm, szDqqX) (* VxHxWdqq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F38ADW1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VFNMADD213SD, opXmmVvXm, szDqqDq) (* VdqHdqWdqq *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F38ADW1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VFNMADD213SD, opXmmVvXm, szDqqDq) (* VdqHdqWdqq *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F38B8W1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VFMADD231PD, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F38B8W1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VFMADD231PD, opXmmVvXm, szXzXz) (* VZxzHxWZxz *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F38B9W0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VFMADD231SS, opXmmVvXm, szDqdXz) (* VxHxWdqd *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F38B9W1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VFMADD231SD, opXmmVvXm, szDqqX) (* VxHxWdqq *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F38BBW1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VFMSUB231SD, opXmmVvXm, szDqqDq) (* VdqHdqWdqq *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F38BBW1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VFMSUB231SD, opXmmVvXm, szDqqDq) (* VdqHdqWdqq *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F38BCW1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VFNMADD231PD, opXmmVvXm, szVecDef) (* VxHxWx *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F38BCW1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VFNMADD231PD, opXmmVvXm, szXzXz) (* VZxzHxWZxz *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F38BDW1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VFNMADD231SD, opXmmVvXm, szDqqDq) (* VdqHdqWdqq *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F38BDW1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VFNMADD231SD, opXmmVvXm, szDqqDq) (* VdqHdqWdqq *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F38F0 = function
  | MPref.MPrxNP -> struct (Opcode.MOVBE, opGprRm, szDef) (* GyMy *)
  | MPref.MPrx66 -> struct (Opcode.MOVBE, opGprRm, szWord) (* GwMw *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2 -> struct (Opcode.CRC32, opGprRm, szBV) (* GvEb *)
  | MPref.MPrx66F2 -> struct (Opcode.CRC32, opGprRm, szBV) (* GvEb *)
  | _ -> raise ParsingFailureException

let nor0F38F1 = function
  | MPref.MPrxNP -> struct (Opcode.MOVBE, opRmGpr, szDef) (* MyGy *)
  | MPref.MPrx66 -> struct (Opcode.MOVBE, opRmGpr, szWord) (* MwGw *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2 -> struct (Opcode.CRC32, opGprRm, szDef) (* GvEy *)
  | MPref.MPrx66F2 -> struct (Opcode.CRC32, opGprRm, szWV) (* GvEw *)
  | _ -> raise ParsingFailureException

let vex0F38F2 = function
  | MPref.MPrxNP -> struct (Opcode.ANDN, opGprVvRm, szDef) (* GyByEy *)
  | MPref.MPrx66
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F38F5W0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.WRUSSD, opRmGpr, szDef) (* EyGy *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F38F5W1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.WRUSSQ, opRmGpr, szDef) (* EyGy *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F38F5W0 = function
  | MPref.MPrxNP -> struct (Opcode.BZHI, opGprRmVv, szDef) (* GyEyBy *)
  | MPref.MPrx66 -> raise ParsingFailureException
  | MPref.MPrxF3 -> struct (Opcode.PEXT, opGprVvRm, szDef) (* GyByEy *)
  | MPref.MPrxF2 -> struct (Opcode.PDEP, opGprVvRm, szDef) (* GyByEy *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F38F5W1 = function
  | MPref.MPrxNP -> struct (Opcode.BZHI, opGprRmVv, szDef) (* GyEyBy *)
  | MPref.MPrx66 -> raise ParsingFailureException
  | MPref.MPrxF3 -> struct (Opcode.PEXT, opGprVvRm, szDef) (* GyByEy *)
  | MPref.MPrxF2 -> struct (Opcode.PDEP, opGprVvRm, szDef) (* GyByEy *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F38F6W0 = function
  | MPref.MPrxNP -> struct (Opcode.WRSSD, opGprRm, szDef) (* GyEy *)
  | MPref.MPrx66
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F38F6W1 = function
  | MPref.MPrxNP -> struct (Opcode.WRSSQ, opGprRm, szDef) (* GyEy *)
  | MPref.MPrx66
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F38F6W0 = function
  | MPref.MPrxNP
  | MPref.MPrx66
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2 -> struct (Opcode.MULX, opGprVvRm, szDef) (* GyByEy *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F38F6W1 = function
  | MPref.MPrxNP
  | MPref.MPrx66
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2 -> struct (Opcode.MULX, opGprVvRm, szDef) (* GyByEy *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F38F7 = function
  | MPref.MPrxNP
  | MPref.MPrx66
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F38F7 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.SHLX, opGprRmVv, szDef) (* GyEyBy *)
  | MPref.MPrxF3 -> struct (Opcode.SARX, opGprRmVv, szDef) (* GyEyBy *)
  | MPref.MPrxF2 -> struct (Opcode.SHRX, opGprRmVv, szDef) (* GyEyBy *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3A0B = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.ROUNDSD, opXmmRmImm8, szDqqDq) (* VdqWdqqIb *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3A0B = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.InvalOP, opXmmVvXmImm8, szDqDq) (* VdqHdqWdqIb *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3A0F = function
  | MPref.MPrxNP -> struct (Opcode.PALIGNR, opMmxMmImm8, szQQ) (* PqQqIb *)
  | MPref.MPrx66 ->
    struct (Opcode.PALIGNR, opXmmRmImm8, szDqDq) (* VdqWdqIb *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3A0F = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPALIGNR, opXmmVvXmImm8, szVecDef) (* VxHxWxIb *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3A15 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PEXTRW, opXmRegImm8, szDwDq) (* EdwVdqIb *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3A15 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPEXTRW, opXmRegImm8, szDwDq) (* EdwVdqIb *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3A18W0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VINSERTF128, opXmmVvXmImm8, szDqQqq) (* VqqHqqWdqIb *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3A19W0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.InvalOP, opXmRegImm8, szDqQq) (* WdqVqqIb *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F3A19W0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VEXTRACTF32X4, opXmRegImm8, szDqXz) (* WdqVZxzIb *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F3A19W1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VEXTRACTF64X2, opXmRegImm8, szDqXz) (* WdqVZxzIb *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F3A1AW1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VINSERTF64X4, opXmmVvXmImm8, szQqXzRM) (* VZxzHxWqqIb *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F3A1BW0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VEXTRACTF32X8, opXmRegImm8, szQqXz) (* WZqqVZxzIb *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F3A1BW1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VEXTRACTF64X4, opXmRegImm8, szQqXz) (* WZqqVZxzIb *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3A20 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 -> struct (Opcode.PINSRB, opXmmRmImm8, szDbDq) (* VdqEdbIb *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3A20 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPINSRB, opXmmVvXmImm8, szDbDq) (* VdqHdqEdbIb *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3A22W0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPINSRD, opXmmVvXmImm8, szYDq) (* VdqHdqEyIb *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3A22W1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPINSRQ, opXmmVvXmImm8, szYDq) (* VdqHdqEyIb *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F3A22W0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPINSRD, opXmmVvXmImm8, szYDq) (* VdqHdqEyIb *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F3A22W1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPINSRQ, opXmmVvXmImm8, szYDq) (* VdqHdqEyIb *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F3A25W0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPTERNLOGD, opXmmVvXmImm8, szXzXz) (* VZxzHxWZxzIb *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3A38 = function
  | MPref.MPrxNP
  | MPref.MPrx66
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3A38 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VINSERTI128, opXmmVvXmImm8, szDqQqq) (* VqqHqqWdqIb *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F3A3AW0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VINSERTI32X8, opXmmVvXmImm8, szQqXzRM) (* VZxzHxWqqIb *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F3A3AW1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VINSERTI64X4, opXmmVvXmImm8, szQqXzRM) (* VZxzHxWqqIb *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F3A3BW0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VEXTRACTI32X8, opXmRegImm8, szQqXz) (* WqqVZxzIb *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F3A3BW1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VEXTRACTI64X4, opXmRegImm8, szQqXz) (* WqqVZxzIb *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F3A43W0 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VSHUFI32X4, opXmmVvXmImm8, szXzXz) (* VZxzHxWZxzIb *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let evex0F3A43W1 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VSHUFI64X2, opXmmVvXmImm8, szXzXz) (* VZxzHxWZxzIb *)
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3A60 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.PCMPESTRM, opXmmRmImm8, szDqDq) (* VdqWdqIb *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3A60 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPCMPESTRM, opXmmRmImm8, szDqDq) (* VdqWdqIb *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3A61 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.PCMPESTRI, opXmmRmImm8, szDqDq) (* VdqWdqIb *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3A61 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPCMPESTRI, opXmmRmImm8, szDqDq) (* VdqWdqIb *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3A62 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.PCMPISTRM, opXmmRmImm8, szDqDq) (* VdqWdqIb *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3A62 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPCMPISTRM, opXmmRmImm8, szDqDq) (* VdqWdqIb *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3A63 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.PCMPISTRI, opXmmRmImm8, szDqDq) (* VdqWdqIb *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3A63 = function
  | MPref.MPrxNP -> raise ParsingFailureException
  | MPref.MPrx66 ->
    struct (Opcode.VPCMPISTRI, opXmmRmImm8, szDqDq) (* VdqWdqIb *)
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let nor0F3AF0 = function
  | MPref.MPrxNP
  | MPref.MPrx66
  | MPref.MPrxF3
  | MPref.MPrxF2
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let vex0F3AF0 = function
  | MPref.MPrxNP
  | MPref.MPrx66
  | MPref.MPrxF3 -> raise ParsingFailureException
  | MPref.MPrxF2 -> struct (Opcode.RORX, opXmmRmImm8, szDef) (* GyEyIb *)
  | _ (* MPrx66F2 *) -> raise ParsingFailureException

let grp1Op = function
  | 0 -> Opcode.ADD
  | 1 -> Opcode.OR
  | 2 -> Opcode.ADC
  | 3 -> Opcode.SBB
  | 4 -> Opcode.AND
  | 5 -> Opcode.SUB
  | 6 -> Opcode.XOR
  | 7 -> Opcode.CMP
  | _ -> raise ParsingFailureException

let grp2Op = function
  | 0 -> Opcode.ROL
  | 1 -> Opcode.ROR
  | 2 -> Opcode.RCL
  | 3 -> Opcode.RCR
  | 4 -> Opcode.SHL
  | 5 -> Opcode.SHR
  | 6 -> Opcode.InvalOP
  | 7 -> Opcode.SAR
  | _ -> raise ParsingFailureException

let grp4Op = function
  | 0 -> Opcode.INC
  | 1 -> Opcode.DEC
  | _ -> raise ParsingFailureException

let grp5 = function
  | 0 -> struct (Opcode.INC, opMem, szDef, SzCond.Nor)
  | 1 -> struct (Opcode.DEC, opMem, szDef, SzCond.Nor)
  | 2 -> struct (Opcode.CALLNear, opMem, szDef, SzCond.F64)
  | 3 -> struct (Opcode.CALLFar, opMem, szP, SzCond.Nor)
  | 4 -> struct (Opcode.JMPNear, opMem, szDef, SzCond.F64)
  | 5 -> struct (Opcode.JMPFar, opDir, szP, SzCond.Nor)
  | 6 -> struct (Opcode.PUSH, opMem, szDef, SzCond.D64)
  | _ -> raise ParsingFailureException

let grp7 = function
  | 0 -> struct (Opcode.SGDT, opMem, szS, SzCond.Nor)
  | 1 -> struct (Opcode.SIDT, opMem, szS, SzCond.Nor)
  | 2 -> struct (Opcode.LGDT, opMem, szS, SzCond.Nor)
  | 3 -> struct (Opcode.LIDT, opMem, szS, SzCond.Nor)
  | 4 -> struct (Opcode.SMSW, opMem, szMemW, SzCond.Nor)
  | 5 -> struct (Opcode.RSTORSSP, opMem, szQ, SzCond.Nor)
  | 6 -> struct (Opcode.LMSW, opMem, szMemW, SzCond.Nor)
  | 7 -> struct (Opcode.INVLPG, opMem, szMemW, SzCond.Nor)
  | _ -> raise ParsingFailureException

let grp8Op = function
  | 0 -> Opcode.InvalOP
  | 1 -> Opcode.InvalOP
  | 2 -> Opcode.InvalOP
  | 3 -> Opcode.InvalOP
  | 4 -> Opcode.BT
  | 5 -> Opcode.BTS
  | 6 -> Opcode.BTR
  | 7 -> Opcode.BTC
  | _ -> raise ParsingFailureException

let grp16Op = function
  | 0 -> Opcode.PREFETCHNTA
  | 1 -> Opcode.PREFETCHT0
  | 2 -> Opcode.PREFETCHT1
  | 3 -> Opcode.PREFETCHT2
  | _ -> raise ParsingFailureException

let getGrp3OpKind fnOpr fnSize oprGrp regBits =
  match regBits with
  | 0b000 when oprGrp = OpGroup.G3A ->
    struct (Opcode.TEST, opRmImm8, szByte, SzCond.Nor)
  | 0b000 when oprGrp = OpGroup.G3B ->
    struct (Opcode.TEST, opRmImm, szDef, SzCond.Nor)
  | 0b010 -> struct (Opcode.NOT, fnOpr, fnSize, SzCond.Nor)
  | 0b011 -> struct (Opcode.NEG, fnOpr, fnSize, SzCond.Nor)
  | 0b100 -> struct (Opcode.MUL, fnOpr, fnSize, SzCond.Nor)
  | 0b101 -> struct (Opcode.IMUL, fnOpr, fnSize, SzCond.Nor)
  | 0b110 -> struct (Opcode.DIV, fnOpr, fnSize, SzCond.Nor)
  | 0b111 -> struct (Opcode.IDIV, fnOpr, fnSize, SzCond.Nor)
  | _ -> raise ParsingFailureException

let getGrp6OpKind b regBits =
  match modIsMemory b, regBits with
  | true, 0b000 -> struct (Opcode.SLDT, opMem, szMemW, SzCond.Nor)
  | false, 0b000 -> struct (Opcode.SLDT, opMem, szDef, SzCond.Nor)
  | true, 0b001 -> struct (Opcode.STR, opMem, szMemW, SzCond.Nor)
  | false, 0b001 -> struct (Opcode.STR, opMem, szDef, SzCond.Nor)
  | _, 0b010 -> struct (Opcode.LLDT, opMem, szMemW, SzCond.Nor)
  | _, 0b011 -> struct (Opcode.LTR, opMem, szMemW, SzCond.Nor)
  | _, 0b100 -> struct (Opcode.VERR, opMem, szMemW, SzCond.Nor)
  | _, 0b101 -> struct (Opcode.VERW, opMem, szMemW, SzCond.Nor)
  | _ -> raise ParsingFailureException

let parseGrp7OpKind t (rhlp: ReadHelper) b regBits =
  if modIsMemory b then grp7 regBits
  else
    match regBits, getRM b with
    | 0b000, 0b001 ->
      rhlp.IncPos (); struct (Opcode.VMCALL, opNo, szDef, SzCond.Nor)
    | 0b000, 0b010 ->
      rhlp.IncPos (); struct (Opcode.VMLAUNCH, opNo, szDef, SzCond.Nor)
    | 0b000, 0b011 ->
      rhlp.IncPos (); struct (Opcode.VMRESUME, opNo, szDef, SzCond.Nor)
    | 0b000, 0b100 ->
      rhlp.IncPos (); struct (Opcode.VMXOFF, opNo, szDef, SzCond.Nor)
    | 0b001, 0b000 ->
      rhlp.IncPos (); struct (Opcode.MONITOR, opNo, szDef, SzCond.Nor)
    | 0b001, 0b001 ->
      rhlp.IncPos (); struct (Opcode.MWAIT, opNo, szDef, SzCond.Nor)
    | 0b001, 0b010 ->
      rhlp.IncPos (); struct (Opcode.CLAC, opNo, szDef, SzCond.Nor)
    | 0b001, 0b011 ->
      rhlp.IncPos (); struct (Opcode.STAC, opNo, szDef, SzCond.Nor)
    | 0b010, 0b000 ->
      rhlp.IncPos (); struct (Opcode.XGETBV, opNo, szDef, SzCond.Nor)
    | 0b010, 0b001 ->
      rhlp.IncPos (); struct (Opcode.XSETBV, opNo, szDef, SzCond.Nor)
    | 0b010, 0b100 ->
      rhlp.IncPos (); struct (Opcode.VMFUNC, opNo, szDef, SzCond.Nor)
    | 0b010, 0b101 ->
      rhlp.IncPos (); struct (Opcode.XEND, opNo, szDef, SzCond.Nor)
    | 0b010, 0b110 ->
      rhlp.IncPos (); struct (Opcode.XTEST, opNo, szDef, SzCond.Nor)
    | 0b100, _     -> struct (Opcode.SMSW, opMem, szDef, SzCond.Nor)
    | 0b101, 0b000 ->
      rhlp.IncPos (); struct (Opcode.SETSSBSY, opNo, szDef, SzCond.Nor)
    | 0b101, 0b010 ->
      rhlp.IncPos (); struct (Opcode.SAVEPREVSSP, opNo, szDef, SzCond.Nor)
    | 0b101, 0b110 ->
      rhlp.IncPos (); struct (Opcode.RDPKRU, opNo, szDef, SzCond.Nor)
    | 0b101, 0b111 ->
      rhlp.IncPos (); struct (Opcode.WRPKRU, opNo, szDef, SzCond.Nor)
    | 0b110, _     -> struct (Opcode.LMSW, opMem, szMemW, SzCond.Nor)
    | 0b111, 0b000 ->
#if !EMULATION
      ensure32 t
#endif
      rhlp.IncPos (); struct (Opcode.SWAPGS, opNo, szDef, SzCond.Nor)
    | 0b111, 0b001 ->
      rhlp.IncPos (); struct (Opcode.RDTSCP, opNo, szDef, SzCond.Nor)
    | _ -> raise ParsingFailureException

let getGrp9OpKind t b regBits =
  let hasOprSzPref = hasOprSz t.TPrefixes
  let hasREPZPref = hasREPZ t.TPrefixes
  let hasREXWPref = hasREXW t.TREXPrefix
  match modIsMemory b, regBits, hasOprSzPref, hasREPZPref, hasREXWPref with
  | true,  0b001, false, false, false ->
    struct (Opcode.CMPXCHG8B, opMem, szQ, SzCond.Nor)
  | true,  0b001, false, false, true  ->
    struct (Opcode.CMPXCHG16B, opMem, szDq, SzCond.Nor)
  | true,  0b011, false, false, false ->
    struct (Opcode.XRSTORS, opMem, szQ, SzCond.Nor)
  | true,  0b011, false, false, true  ->
    struct (Opcode.XRSTORS64, opMem, szQ, SzCond.Nor)
  | true,  0b100, false, false, false ->
    struct (Opcode.XSAVEC, opMem, szQ, SzCond.Nor)
  | true,  0b100, false, false, true  ->
    struct (Opcode.XSAVEC64, opMem, szQ, SzCond.Nor)
  | true,  0b101, false, false, false ->
    struct (Opcode.XSAVES, opMem, szQ, SzCond.Nor)
  | true,  0b101, false, false, true  ->
    struct (Opcode.XSAVES64, opMem, szQ, SzCond.Nor)
  | true,  0b110, false, false, _     ->
    struct (Opcode.VMPTRLD, opMem, szQ, SzCond.Nor)
  | true,  0b111, false, false, _     ->
    struct (Opcode.VMPTRST, opMem, szQ, SzCond.Nor)
  | true,  0b110, true,  false, _     ->
    struct (Opcode.VMCLEAR, opMem, szQ, SzCond.Nor)
  | true,  0b110, false, true,  _     ->
    struct (Opcode.VMXON, opMem, szQ, SzCond.Nor)
  | true,  0b111, false, true,  _     ->
    struct (Opcode.VMPTRST, opMem, szQ, SzCond.Nor)
  | false, 0b110, false, false, _     ->
    struct (Opcode.RDRAND, opMem, szDef, SzCond.Nor)
  | false, 0b111, false, false, _     ->
    struct (Opcode.RDSEED, opMem, szDef, SzCond.Nor)
  | _ -> raise ParsingFailureException

let getGrp11OpKind rhlp op fnOpr1 sz1 b reg fnOpr2 sz2 =
  match reg with
  | 0b000 -> struct (Opcode.MOV, fnOpr2, sz2, SzCond.Nor)
  | 0b111 when modIsMemory b -> raise ParsingFailureException
  | 0b111 ->
    if (rhlp: ReadHelper).ReadByte () = 0xF8uy then
      struct (op, fnOpr1, sz1, SzCond.Nor)
    else raise ParsingFailureException
  | _ -> raise ParsingFailureException

let getGrp12OpKind t b regBits =
  match modIsMemory b, regBits, hasOprSz (selectPrefix t) with
  | false, 0b010, false -> struct (Opcode.PSRLW, opMmxImm8, szQ, SzCond.Nor)
  | false, 0b010, true  ->
    if t.TVEXInfo = None then
      struct (Opcode.PSRLW, opRmImm8, szDq, SzCond.Nor)
    else struct (Opcode.VPSRLW, opVvRmImm8, szVecDef, SzCond.Nor)
  | false, 0b100, false -> struct (Opcode.PSRAW, opMmxImm8, szQ, SzCond.Nor)
  | false, 0b100, true  ->
    if t.TVEXInfo = None then
      struct (Opcode.PSRAW, opRmImm8, szDq, SzCond.Nor)
    else struct (Opcode.VPSRAW, opVvRmImm8, szVecDef, SzCond.Nor)
  | false, 0b110, false -> struct (Opcode.PSLLW, opMmxImm8, szQ, SzCond.Nor)
  | false, 0b110, true  ->
    if t.TVEXInfo = None then
      struct (Opcode.PSLLW, opRmImm8, szDq, SzCond.Nor)
    else struct (Opcode.VPSLLW, opVvRmImm8, szVecDef, SzCond.Nor)
  | _ -> raise ParsingFailureException

let getGrp13OpKind t b regBits =
  match modIsMemory b, regBits, hasOprSz (selectPrefix t) with
  | false, 0b010, false -> struct (Opcode.PSRLD, opMmxImm8, szQ, SzCond.Nor)
  | false, 0b010, true  ->
    if t.TVEXInfo = None then
      struct (Opcode.PSRLD, opRmImm8, szDq, SzCond.Nor)
    else struct (Opcode.VPSRLD, opVvRmImm8, szVecDef, SzCond.Nor)
  | false, 0b100, false -> struct (Opcode.PSRAD, opMmxImm8, szQ, SzCond.Nor)
  | false, 0b100, true  ->
    if t.TVEXInfo = None then
      struct (Opcode.PSRAD, opRmImm8, szDq, SzCond.Nor)
    else struct (Opcode.VPSRAD, opVvRmImm8, szVecDef, SzCond.Nor)
  | false, 0b110, false -> struct (Opcode.PSLLD, opMmxImm8, szQ, SzCond.Nor)
  | false, 0b110, true  ->
    if t.TVEXInfo = None then
      struct (Opcode.PSLLD, opRmImm8, szDq, SzCond.Nor)
    else struct (Opcode.VPSLLD, opVvRmImm8, szVecDef, SzCond.Nor)
  | _ -> raise ParsingFailureException

let getGrp14OpKind t b regBits =
  match modIsMemory b, regBits, hasOprSz (selectPrefix t) with
  | false, 0b010, false ->
    struct (Opcode.PSRLQ, opMmxImm8, szQ, SzCond.Nor)
  | false, 0b010, true  ->
    if t.TVEXInfo = None then
      struct (Opcode.PSRLQ, opRmImm8, szDq, SzCond.Nor)
    else struct (Opcode.VPSRLQ, opVvRmImm8, szVecDef, SzCond.Nor)
  | false, 0b011, true  ->
    if t.TVEXInfo = None then
      struct (Opcode.PSRLDQ, opRmImm8, szDq, SzCond.Nor)
    else struct (Opcode.VPSRLDQ, opVvRmImm8, szVecDef, SzCond.Nor)
  | false, 0b110, false -> struct (Opcode.PSLLQ, opMmxImm8, szQ, SzCond.Nor)
  | false, 0b110, true  ->
    if t.TVEXInfo = None then
      struct (Opcode.PSLLQ, opRmImm8, szDq, SzCond.Nor)
    else struct (Opcode.VPSLLQ, opVvRmImm8, szVecDef, SzCond.Nor)
  | false, 0b111, true  ->
    if t.TVEXInfo = None then
      struct (Opcode.PSLLDQ, opRmImm8, szDq, SzCond.Nor)
    else struct (Opcode.VPSLLDQ, opVvRmImm8, szVecDef, SzCond.Nor)
  | _ -> raise ParsingFailureException

let parseGrp15OpKind (rhlp: ReadHelper) t b regBits =
  match modIsMemory b, regBits, hasREPZ t.TPrefixes with
  | true,  0b110, true -> struct (Opcode.CLRSSBSY, opMem, szQ, SzCond.Nor)
  | true,  0b000, false ->
    let op = if hasREXW t.TREXPrefix then Opcode.FXSAVE64 else Opcode.FXSAVE
    struct (op, opMem, szDef, SzCond.Nor)
  | true,  0b001, false ->
    let op = if hasREXW t.TREXPrefix then Opcode.FXRSTOR64 else Opcode.FXRSTOR
    struct (op, opMem, szDef, SzCond.Nor)
  | true,  0b010, false -> struct (Opcode.LDMXCSR, opMem, szD, SzCond.Nor)
  | true,  0b011, false -> struct (Opcode.STMXCSR, opMem, szD, SzCond.Nor)
  | true,  0b100, false -> struct (Opcode.XSAVE, opMem, szDef, SzCond.Nor)
  | true,  0b101, false -> struct (Opcode.XRSTOR, opMem, szDef, SzCond.Nor)
  | true,  0b110, false -> struct (Opcode.XSAVEOPT, opMem, szDef, SzCond.Nor)
  | true,  0b111, false -> struct (Opcode.CLFLUSH, opMem, szBV, SzCond.Nor)
  | false, 0b101, false ->
    rhlp.IncPos (); struct (Opcode.LFENCE, opNo, szDef, SzCond.Nor)
  | false, 0b110, false ->
    rhlp.IncPos (); struct (Opcode.MFENCE, opNo, szDef, SzCond.Nor)
  | false, 0b111, false ->
    rhlp.IncPos (); struct (Opcode.SFENCE, opNo, szDef, SzCond.Nor)
  | false, 0b000, true -> struct (Opcode.RDFSBASE, opGpr, szDef, SzCond.Nor)
  | false, 0b001, true -> struct (Opcode.RDGSBASE, opGpr, szDef, SzCond.Nor)
  | false, 0b010, true -> struct (Opcode.WRFSBASE, opGpr, szDef, SzCond.Nor)
  | false, 0b011, true -> struct (Opcode.WRGSBASE, opGpr, szDef, SzCond.Nor)
  | false, 0b101, true ->
    let op = if hasREXW t.TREXPrefix then Opcode.INCSSPQ else Opcode.INCSSPD
    struct (op, opGpr, szDef, SzCond.Nor)
  | _ -> raise ParsingFailureException

let parseGrpOpKind t (rhlp: ReadHelper) fnOpr fnSize oprGrp =
  let b = rhlp.PeekByte ()
  let r = getReg b
  match oprGrp with
  | OpGroup.G1 -> struct (grp1Op r, fnOpr, fnSize, SzCond.Nor)
  | OpGroup.G1Inv64 ->
#if !EMULATION
    ensure32 t
#endif
    struct (grp1Op r, fnOpr, fnSize, SzCond.Nor)
  | OpGroup.G1A -> struct (Opcode.POP, fnOpr, fnSize, SzCond.D64)
  | OpGroup.G2 when r = 0b110 -> raise ParsingFailureException
  | OpGroup.G2 -> struct (grp2Op r, fnOpr, fnSize, SzCond.Nor)
  | OpGroup.G3A | OpGroup.G3B -> getGrp3OpKind fnOpr fnSize oprGrp r
  | OpGroup.G4 -> struct (grp4Op r, opMem, szByte, SzCond.Nor)
  | OpGroup.G5 -> grp5 r
  | OpGroup.G6 -> getGrp6OpKind b r
  | OpGroup.G7 -> parseGrp7OpKind t rhlp b r
  | OpGroup.G8 -> struct (grp8Op r, fnOpr, fnSize, SzCond.Nor)
  | OpGroup.G9 -> getGrp9OpKind t b r
  | OpGroup.G11A ->
    getGrp11OpKind rhlp Opcode.XABORT opImm8 szDef b r fnOpr fnSize
  | OpGroup.G11B ->
    getGrp11OpKind rhlp Opcode.XBEGIN opRel szD64 b r fnOpr fnSize
  | OpGroup.G12 -> getGrp12OpKind t b r
  | OpGroup.G13 -> getGrp13OpKind t b r
  | OpGroup.G14 -> getGrp14OpKind t b r
  | OpGroup.G15 -> parseGrp15OpKind rhlp t b r
  | OpGroup.G16 -> struct (grp16Op r, fnOpr, fnSize, SzCond.Nor)
  | OpGroup.G10 | OpGroup.G17
  | _ ->
    raise ParsingFailureException (* Not implemented yet *)

/// Add BND prefix (Intel MPX extension).
let addBND t =
  if hasREPNZ t.TPrefixes then
    { t with TPrefixes = Prefix.PrxBND ||| (clearGrp1PrefMask &&& t.TPrefixes) }
  else t

/// Parse group Opcodes: Vol.2C A-19 Table A-6. Opcode Extensions for One- and
/// Two-byte Opcodes by Group Number.
let parseGrpOp t rhlp grp fnOpr sz =
  let struct (op, fnOpr, sz, szCond) = parseGrpOpKind t rhlp fnOpr sz grp
  let t =
    if isBranch op then addBND t
    elif isCETInstr op then
      { t with TPrefixes = clearGrp1PrefMask &&& t.TPrefixes }
    else t
  render t rhlp op szCond fnOpr sz

let inline getMandPrx (prefix: Prefix) =
  match int prefix &&& 0x40a with
  | 0x402 -> MPref.MPrx66F2
  | 0x2 -> MPref.MPrxF2
  | 0x400 -> MPref.MPrx66
  | 0x8 -> MPref.MPrxF3
  | 0x0 -> MPref.MPrxNP
  | _ -> raise ParsingFailureException

/// Some instructions use 66/F2/F3 prefix as a mandatory prefix. When both
/// VEX.pp and old-style prefix are used, the VEX.pp is used to select the
/// opcodes. But if VEX.pp does not exist, then we have to use the old-style
/// prefix, and we have to filter out the prefixes because they are not going to
/// be used as a normal prefixes. They will only be used as a mandatory prefix
/// to decide the opcode.
let inline filterPrefs (prefix: Prefix) = prefix &&& clearVEXPrefMask

let getInstr prefix fnInstr = fnInstr (getMandPrx prefix)

/// Normal/VEX
let parseVEX t rhlp fnNor fnVex =
  match t.TVEXInfo with
  | None ->
    let struct (op, fnOpr, fnSize) = fnNor (getMandPrx t.TPrefixes)
    let t = { t with TPrefixes = filterPrefs t.TPrefixes }
    render t rhlp op SzCond.Nor fnOpr fnSize
  | Some v ->
    let struct (op, fnOpr, fnSize) = fnVex (getMandPrx v.VPrefixes)
    render t rhlp op SzCond.Nor fnOpr fnSize

let selectVEXW t fnNorW0 fnNorW1 fnVexW0 fnVexW1 =
  match t.TVEXInfo with
  | None ->
    let fnNor = if hasREXW t.TREXPrefix then fnNorW1 else fnNorW0
    getInstr t.TPrefixes fnNor,
    { t with TPrefixes = filterPrefs t.TPrefixes }
  | Some v ->
    let fnVex = if hasREXW v.VREXPrefix then fnVexW1 else fnVexW0
    getInstr v.VPrefixes fnVex, t

/// Normal/VEX (Both REX.W)
let parseVEXW t rhlp fnNorW0 fnNorW1 fnVexW0 fnVexW1 =
  let (struct (op, fnOpr, fnSize)), t =
    selectVEXW t fnNorW0 fnNorW1 fnVexW0 fnVexW1
  render t rhlp op SzCond.Nor fnOpr fnSize

/// Normal(REX.W), VEX(REX.W)
/// Normal, VEX, EVEX(REX.W)
let selectEVEX t fnNor fnVex fnEVexW0 fnEVexW1 =
  match t.TVEXInfo with
  | None ->
    getInstr t.TPrefixes fnNor, { t with TPrefixes = filterPrefs t.TPrefixes }
  | Some v ->
    if v.VEXType &&& VEXType.EVEX = VEXType.EVEX then
      let fnEVex = if hasREXW v.VREXPrefix then fnEVexW1 else fnEVexW0
      getInstr v.VPrefixes fnEVex, t
    else getInstr v.VPrefixes fnVex, t

/// Normal/VEX/EVEX (EVEX REX.W)
let parseEVEX t rhlp fnNor fnVex fnEVexW0 fnEVexW1 =
  let (struct (op, fnOpr, fnSize)), t =
    selectEVEX t fnNor fnVex fnEVexW0 fnEVexW1
  render t rhlp op SzCond.Nor fnOpr fnSize

/// VEX(REX.W), EVEX(REX.W)
let selectEVEXW t fnVexW0 fnVexW1 fnEVexW0 fnEVexW1 =
  match t.TVEXInfo with
  | None -> raise ParsingFailureException
  | Some v ->
    if v.VEXType &&& VEXType.EVEX = VEXType.EVEX then
      let fnEVex = if hasREXW v.VREXPrefix then fnEVexW1 else fnEVexW0
      getInstr v.VPrefixes fnEVex, t
    else
      let fnVex = if hasREXW v.VREXPrefix then fnVexW1 else fnVexW0
      getInstr v.VPrefixes fnVex, t

/// VEX/EVEX (Both REX.W)
let parseEVEXW t rhlp fnVexW0 fnVexW1 fnEVexW0 fnEVexW1 =
  let (struct (op, fnOpr, fnSize)), t =
    selectEVEXW t fnVexW0 fnVexW1 fnEVexW0 fnEVexW1
  render t rhlp op SzCond.Nor fnOpr fnSize

/// Parse non-VEX instructions.
let parseNonVEX t rhlp fnNor =
  let struct (op, fnOpr, fnSize) = getInstr t.TPrefixes fnNor
  let t = { t with TPrefixes = filterPrefs t.TPrefixes }
  render t rhlp op SzCond.Nor fnOpr fnSize

/// Parse non-VEX instructions.
let pVEXByMem t (rhlp: ReadHelper) fnNorM fnNorR fnVexM fnVexR =
  let struct (fnNor, fnVex) =
    if rhlp.PeekByte () |> modIsMemory then struct (fnNorM, fnVexM)
    else struct (fnNorR, fnVexR)
  parseVEX t rhlp fnNor fnVex

/// Parse BND-related instructions.
let parseBND t rhlp szCond fnBND =
  let struct (op, fnOpr, fnSize) = getInstr t.TPrefixes fnBND
  let t = { t with TPrefixes = filterPrefs t.TPrefixes }
  render t rhlp op szCond fnOpr fnSize

let parseCETInstr t (rhlp: ReadHelper) =
  let struct (op, fnOpr, fnSize) =
    match rhlp.PeekByte () with
    | 0xFAuy -> rhlp.IncPos (); struct (Opcode.ENDBR64, opNo, szDef)
    | 0xFBuy -> rhlp.IncPos (); struct (Opcode.ENDBR32, opNo, szDef)
    | b when getReg b = 0b001 && getMod b = 0b11 ->
      let op = if hasREXW t.TREXPrefix then Opcode.RDSSPQ else Opcode.RDSSPD
      struct (op, opGpr, szDef)
    | _ -> raise InvalidOpcodeException
  let t = { t with TPrefixes = clearGrp1PrefMask &&& t.TPrefixes }
  render t rhlp op SzCond.Nor fnOpr fnSize

let parseESCOp t (rhlp: ReadHelper) escFlag getOpIn getOpOut =
  let modRM = rhlp.ReadByte ()
  let struct (effOprSize, effAddrSize) = getSize t SzCond.Nor
  let insSize = szDef t effOprSize effAddrSize
  if modRM <= 0xBFuy then
    let op = getOpIn modRM
    let effOprSize =
      match escFlag with
      | 0xD9uy -> getReg modRM |> getD9EscEffOprSizeByModRM
      | 0xDBuy -> getReg modRM |> getDBEscEffOprSizeByModRM
      | 0xDDuy -> getReg modRM |> getDDEscEffOprSizeByModRM
      | 0xDFuy -> getReg modRM |> getDFEscEffOprSizeByModRM
      | _ -> escFlag |> getEscEffOprSizeByESCOp
    let insSize =
      { insSize with MemEffOprSize = effOprSize; MemEffRegSize = effOprSize }
    let o = parseMemory modRM insSize t rhlp
    newInsInfo t rhlp op (OneOperand o) insSize
  else
    let opcode, oprs = getOpOut modRM
    newInsInfo t rhlp opcode oprs insSize

/// When the first two bytes are 0F38.
/// Table A-4 of Volume 2 (Three-byte Opcode Map : First Two Bytes are 0F 38H)
let parseThreeByteOp1 t (rhlp: ReadHelper) =
  match rhlp.ReadByte () with
  | 0x00uy -> parseVEX t rhlp nor0F3800 vex0F3800
  | 0x01uy -> parseVEX t rhlp nor0F3801 vex0F3801
  | 0x02uy -> parseVEX t rhlp nor0F3802 vex0F3802
  | 0x03uy -> parseVEX t rhlp nor0F3803 vex0F3803
  | 0x05uy -> parseVEX t rhlp nor0F3805 vex0F3805
  | 0x06uy -> parseVEX t rhlp nor0F3806 vex0F3806
  | 0x07uy -> parseVEX t rhlp nor0F3807 vex0F3807
  | 0x08uy -> parseVEX t rhlp nor0F3808 vex0F3808
  | 0x09uy -> parseVEX t rhlp nor0F3809 vex0F3809
  | 0x0auy -> parseVEX t rhlp nor0F380A vex0F380A
  | 0x0buy -> parseVEX t rhlp nor0F380B vex0F380B
  | 0x17uy -> parseVEX t rhlp nor0F3817 vex0F3817
  | 0x18uy -> parseEVEXW t rhlp vex0F3818W0 notEn evex0F3818W0 notEn
  | 0x19uy -> parseEVEXW t rhlp vex0F3819W0 notEn notEn evex0F3819W1
  | 0x1cuy -> parseVEX t rhlp nor0F381C vex0F381C
  | 0x1duy -> parseVEX t rhlp nor0F381D vex0F381D
  | 0x1euy -> parseVEX t rhlp nor0F381E vex0F381E
  | 0x20uy -> parseVEX t rhlp nor0F3820 vex0F3820
  | 0x21uy -> parseVEX t rhlp nor0F3821 vex0F3821
  | 0x22uy -> parseVEX t rhlp nor0F3822 vex0F3822
  | 0x23uy -> parseVEX t rhlp nor0F3823 vex0F3823
  | 0x24uy -> parseVEX t rhlp nor0F3824 vex0F3824
  | 0x25uy -> parseVEX t rhlp nor0F3825 vex0F3825
  | 0x28uy -> parseVEX t rhlp nor0F3828 vex0F3828
  | 0x29uy -> parseVEX t rhlp nor0F3829 vex0F3829
  | 0x2buy -> parseVEX t rhlp nor0F382B vex0F382B
  | 0x30uy -> parseEVEX t rhlp nor0F3830 vex0F3830 evex0F3830 evex0F3830
  | 0x31uy -> parseVEX t rhlp nor0F3831 vex0F3831
  | 0x32uy -> parseVEX t rhlp nor0F3832 vex0F3832
  | 0x33uy -> parseEVEX t rhlp nor0F3833 vex0F3833 evex0F3833 evex0F3833
  | 0x34uy -> parseVEX t rhlp nor0F3834 vex0F3834
  | 0x35uy -> parseVEX t rhlp nor0F3835 vex0F3835
  | 0x37uy -> parseVEX t rhlp nor0F3837 vex0F3837
  | 0x38uy -> parseVEX t rhlp nor0F3838 vex0F3838
  | 0x39uy -> parseVEX t rhlp nor0F3839 vex0F3839
  | 0x3auy -> parseVEX t rhlp nor0F383A vex0F383A
  | 0x3buy -> parseVEX t rhlp nor0F383B vex0F383B
  | 0x3cuy -> parseVEX t rhlp nor0F383C vex0F383C
  | 0x3duy -> parseVEX t rhlp nor0F383D vex0F383D
  | 0x3euy -> parseVEX t rhlp nor0F383E vex0F383E
  | 0x3fuy -> parseVEX t rhlp nor0F383F vex0F383F
  | 0x40uy -> parseVEX t rhlp nor0F3840 vex0F3840
  | 0x41uy -> parseVEX t rhlp nor0F3841 vex0F3841
  | 0x58uy -> parseEVEXW t rhlp vex0F3858W0 notEn evex0F3858W0 notEn
  | 0x5Auy -> parseVEX t rhlp nor0F385A vex0F385A
  | 0x75uy -> parseEVEXW t rhlp notEn notEn notEn evex0F3875W1
  | 0x76uy -> parseEVEXW t rhlp notEn notEn evex0F3876W0 notEn
  | 0x77uy -> parseEVEXW t rhlp notEn notEn notEn evex0F3877W1
  | 0x78uy -> parseVEX t rhlp nor0F3878 vex0F3878
  | 0x7Auy -> parseEVEXW t rhlp notEn notEn evex0F387AW0 notEn
  | 0x7Cuy -> parseEVEXW t rhlp notEn notEn evex0F387CW0 evex0F387CW1
  | 0x90uy -> parseEVEXW t rhlp vex0F3890W0 notEn evex0F3890W0 notEn
  | 0x92uy -> parseEVEXW t rhlp vex0F3892W0 notEn evex0F3892W0 notEn
  | 0x98uy -> parseEVEXW t rhlp notEn vex0F3898W1 notEn evex0F3898W1
  | 0x99uy -> parseVEXW t rhlp notEn notEn vex0F3899W0 vex0F3899W1
  | 0x9Buy -> parseEVEXW t rhlp vex0F389BW0 notEn evex0F389BW0 notEn
  | 0x9Cuy -> parseEVEXW t rhlp notEn vex0F389CW1 notEn evex0F389CW1
  | 0x9Duy -> parseEVEXW t rhlp notEn vex0F389DW1 notEn evex0F389DW1
  | 0xA8uy -> parseEVEXW t rhlp vex0F38A8W0 notEn evex0F38A8W0 notEn
  | 0xA9uy -> parseVEXW t rhlp notEn notEn vex0F38A9W0 vex0F38A9W1
  | 0xADuy -> parseEVEXW t rhlp notEn vex0F38ADW1 notEn evex0F38ADW1
  | 0xB8uy -> parseEVEXW t rhlp notEn vex0F38B8W1 notEn evex0F38B8W1
  | 0xB9uy -> parseVEXW t rhlp notEn notEn vex0F38B9W0 vex0F38B9W1
  | 0xBBuy -> parseEVEXW t rhlp notEn vex0F38BBW1 notEn evex0F38BBW1
  | 0xBCuy -> parseEVEXW t rhlp notEn vex0F38BCW1 notEn evex0F38BCW1
  | 0xBDuy -> parseEVEXW t rhlp notEn vex0F38BDW1 notEn evex0F38BDW1
  | 0xF0uy -> parseNonVEX t rhlp nor0F38F0
  | 0xF1uy -> parseNonVEX t rhlp nor0F38F1
  | 0xF2uy -> parseVEX t rhlp notEn vex0F38F2
  | 0xF5uy -> parseVEXW t rhlp nor0F38F5W0 nor0F38F5W1 vex0F38F5W0 vex0F38F5W1
  | 0xF6uy -> parseVEXW t rhlp nor0F38F6W0 nor0F38F6W1 vex0F38F6W0 vex0F38F6W1
  | 0xF7uy -> parseVEX t rhlp nor0F38F7 vex0F38F7
  | _ -> raise ParsingFailureException

/// When the first two bytes are 0F3A.
/// Table A-5 of Volume 2 (Three-byte Opcode Map : First Two Bytes are 0F 3AH)
let parseThreeByteOp2 t (rhlp: ReadHelper) =
  match rhlp.ReadByte () with
  | 0x0Fuy -> parseVEX t rhlp nor0F3A0F vex0F3A0F
  | 0x15uy -> parseVEX t rhlp nor0F3A15 vex0F3A15
  | 0x18uy -> parseEVEXW t rhlp vex0F3A18W0 notEn notEn notEn
  | 0x19uy -> parseEVEXW t rhlp notEn vex0F3A19W0 evex0F3A19W0 evex0F3A19W1
  | 0x1Auy -> parseEVEXW t rhlp notEn notEn notEn evex0F3A1AW1
  | 0x1Buy -> parseEVEXW t rhlp notEn notEn evex0F3A1BW0 evex0F3A1BW1
  | 0x20uy -> parseVEX t rhlp nor0F3A20 vex0F3A20
  | 0x22uy ->
    parseEVEXW t rhlp vex0F3A22W0 vex0F3A22W1 evex0F3A22W0 evex0F3A22W1
  | 0x25uy -> parseEVEXW t rhlp notEn notEn evex0F3A25W0 notEn
  | 0x38uy -> parseVEX t rhlp nor0F3A38 vex0F3A38
  | 0x3Auy -> parseEVEXW t rhlp notEn notEn evex0F3A3AW0 evex0F3A3AW1
  | 0x3Buy -> parseEVEXW t rhlp notEn notEn evex0F3A3BW0 evex0F3A3BW1
  | 0x43uy -> parseEVEXW t rhlp notEn notEn evex0F3A43W0 evex0F3A43W1
  | 0x60uy -> parseVEX t rhlp nor0F3A60 vex0F3A60
  | 0x61uy -> parseVEX t rhlp nor0F3A61 vex0F3A61
  | 0x62uy -> parseVEX t rhlp nor0F3A62 vex0F3A62
  | 0x63uy -> parseVEX t rhlp nor0F3A63 vex0F3A63
  | 0x0Buy -> parseVEX t rhlp nor0F3A0B vex0F3A0B
  | 0xF0uy -> parseVEX t rhlp nor0F3AF0 vex0F3AF0
  | _ -> raise ParsingFailureException

let pTwoByteOp t (rhlp: ReadHelper) byte =
  match byte with
  | 0x02uy -> render t rhlp Opcode.LAR SzCond.Nor opGprRm szWV
  | 0x03uy -> render t rhlp Opcode.LSL SzCond.Nor opGprRm szWV
  | 0x05uy ->
#if !EMULATION
    ensure64 t
#endif
    render t rhlp Opcode.SYSCALL SzCond.Nor opNo szDef
  | 0x06uy -> render t rhlp Opcode.CLTS SzCond.Nor opNo szDef
  | 0x07uy ->
#if !EMULATION
    ensure64 t
#endif
    render t rhlp Opcode.SYSRET SzCond.Nor opNo szDef
  | 0x08uy -> render t rhlp Opcode.INVD SzCond.Nor opNo szDef
  | 0x09uy -> render t rhlp Opcode.WBINVD SzCond.Nor opNo szDef
  | 0x0Buy -> render t rhlp Opcode.UD2 SzCond.Nor opNo szDef
  | 0x0Duy -> render t rhlp (getOpCode0F0D rhlp) SzCond.Nor opMem szDef
  | 0x10uy -> pVEXByMem t rhlp nor0F10 nor0F10 vex0F10Mem vex0F10Reg
  | 0x11uy -> pVEXByMem t rhlp nor0F11 nor0F11 vex0F11Mem vex0F11Reg
  | 0x12uy -> pVEXByMem t rhlp nor0F12Mem nor0F12Reg vex0F12Mem vex0F12Reg
  | 0x13uy -> parseVEX t rhlp nor0F13 vex0F13
  | 0x14uy -> parseVEX t rhlp nor0F14 vex0F14
  | 0x15uy -> parseVEX t rhlp nor0F15 vex0F15
  | 0x16uy -> pVEXByMem t rhlp nor0F16Mem nor0F16Reg vex0F16Mem vex0F16Reg
  | 0x17uy -> parseVEX t rhlp nor0F17 vex0F17
  | 0x1Auy -> parseBND t rhlp SzCond.Nor nor0F1A
  | 0x1Buy -> parseBND t rhlp SzCond.Nor nor0F1B
  | 0x1Euy -> if hasREPZ t.TPrefixes then parseCETInstr t rhlp
              else raise InvalidOpcodeException
  | 0x1Fuy -> render t rhlp Opcode.NOP SzCond.Nor opMem szDef (* NOP /0 Ev *)
  | 0x20uy -> render t rhlp Opcode.MOV SzCond.F64 opRmCtrl szDY
  | 0x21uy -> render t rhlp Opcode.MOV SzCond.Nor opRmDbg szDY
  | 0x22uy -> render t rhlp Opcode.MOV SzCond.Nor opCtrlRm szDY
  | 0x23uy -> render t rhlp Opcode.MOV SzCond.Nor opDbgRm szDY
  | 0x28uy -> parseVEX t rhlp nor0F28 vex0F28
  | 0x29uy -> parseVEX t rhlp nor0F29 vex0F29
  | 0x2Auy -> parseVEX t rhlp nor0F2A vex0F2A
  | 0x2Buy -> parseVEX t rhlp nor0F2B vex0F2B
  | 0x2Cuy -> parseVEX t rhlp nor0F2C vex0F2C
  | 0x2Duy -> parseVEX t rhlp nor0F2D vex0F2D
  | 0x2Euy -> parseVEX t rhlp nor0F2E vex0F2E
  | 0x2Fuy -> parseVEX t rhlp nor0F2F vex0F2F
  | 0x30uy -> render t rhlp Opcode.WRMSR SzCond.Nor opNo szDef
  | 0x31uy -> render t rhlp Opcode.RDTSC SzCond.Nor opNo szDef
  | 0x32uy -> render t rhlp Opcode.RDMSR SzCond.Nor opNo szDef
  | 0x33uy -> render t rhlp Opcode.RDPMC SzCond.Nor opNo szDef
  | 0x34uy -> render t rhlp Opcode.SYSENTER SzCond.Nor opNo szDef
  | 0x35uy -> render t rhlp Opcode.SYSEXIT SzCond.Nor opNo szDef
  | 0x37uy -> render t rhlp Opcode.GETSEC SzCond.Nor opNo szDef
  | 0x40uy -> render t rhlp Opcode.CMOVO SzCond.Nor opGprRm szDef
  | 0x41uy -> render t rhlp Opcode.CMOVNO SzCond.Nor opGprRm szDef
  | 0x42uy -> render t rhlp Opcode.CMOVB SzCond.Nor opGprRm szDef
  | 0x43uy -> render t rhlp Opcode.CMOVAE SzCond.Nor opGprRm szDef
  | 0x44uy -> render t rhlp Opcode.CMOVZ SzCond.Nor opGprRm szDef
  | 0x45uy -> render t rhlp Opcode.CMOVNZ SzCond.Nor opGprRm szDef
  | 0x46uy -> render t rhlp Opcode.CMOVBE SzCond.Nor opGprRm szDef
  | 0x47uy -> render t rhlp Opcode.CMOVA SzCond.Nor opGprRm szDef
  | 0x48uy -> render t rhlp Opcode.CMOVS SzCond.Nor opGprRm szDef
  | 0x49uy -> render t rhlp Opcode.CMOVNS SzCond.Nor opGprRm szDef
  | 0x4Auy -> render t rhlp Opcode.CMOVP SzCond.Nor opGprRm szDef
  | 0x4Buy -> render t rhlp Opcode.CMOVNP SzCond.Nor opGprRm szDef
  | 0x4Cuy -> render t rhlp Opcode.CMOVL SzCond.Nor opGprRm szDef
  | 0x4Duy -> render t rhlp Opcode.CMOVGE SzCond.Nor opGprRm szDef
  | 0x4Euy -> render t rhlp Opcode.CMOVLE SzCond.Nor opGprRm szDef
  | 0x4Fuy -> render t rhlp Opcode.CMOVG SzCond.Nor opGprRm szDef
  | 0x50uy -> parseVEX t rhlp nor0F50 vex0F50
  | 0x51uy -> parseVEX t rhlp nor0F51 vex0F51
  | 0x52uy -> parseVEX t rhlp nor0F52 vex0F52
  | 0x53uy -> parseVEX t rhlp nor0F53 vex0F53
  | 0x54uy -> parseVEX t rhlp nor0F54 vex0F54
  | 0x55uy -> parseVEX t rhlp nor0F55 vex0F55
  | 0x56uy -> parseVEX t rhlp nor0F56 vex0F56
  | 0x57uy -> parseVEX t rhlp nor0F57 vex0F57
  | 0x58uy -> parseVEX t rhlp nor0F58 vex0F58
  | 0x59uy -> parseVEX t rhlp nor0F59 vex0F59
  | 0x5Auy -> parseEVEX t rhlp nor0F5A vex0F5A evex0F5AW0 evex0F5AW1
  | 0x5Buy -> parseVEX t rhlp nor0F5B vex0F5B
  | 0x5Cuy -> parseVEX t rhlp nor0F5C vex0F5C
  | 0x5Duy -> parseVEXW t rhlp nor0F5D vex0F5D evex0F5DW0 notEn
  | 0x5Euy -> parseVEX t rhlp nor0F5E vex0F5E
  | 0x5Fuy -> parseEVEX t rhlp nor0F5F vex0F5F evex0F5FW0 evex0F5FW1
  | 0x60uy -> parseVEX t rhlp nor0F60 vex0F60
  | 0x61uy -> parseVEX t rhlp nor0F61 vex0F61
  | 0x62uy -> parseVEX t rhlp nor0F62 vex0F62
  | 0x63uy -> parseVEX t rhlp nor0F63 vex0F63
  | 0x64uy -> parseVEX t rhlp nor0F64 vex0F64
  | 0x65uy -> parseVEX t rhlp nor0F65 vex0F65
  | 0x66uy -> parseVEX t rhlp nor0F66 vex0F66
  | 0x67uy -> parseVEX t rhlp nor0F67 vex0F67
  | 0x68uy -> parseVEX t rhlp nor0F68 vex0F68
  | 0x69uy -> parseVEX t rhlp nor0F69 vex0F69
  | 0x6Auy -> parseVEX t rhlp nor0F6A vex0F6A
  | 0x6Buy -> parseVEX t rhlp nor0F6B vex0F6B
  | 0x6Cuy -> parseVEX t rhlp nor0F6C vex0F6C
  | 0x6Duy -> parseVEX t rhlp nor0F6D vex0F6D
  | 0x6Euy -> parseVEXW t rhlp nor0F6EW0 nor0F6EW1 vex0F6EW0 vex0F6EW1
  | 0x6Fuy -> parseEVEX t rhlp nor0F6F vex0F6F evex0F6FW0 evex0F6FW1
  | 0x70uy -> parseVEX t rhlp nor0F70 vex0F70
  | 0x74uy -> parseVEX t rhlp nor0F74 vex0F74
  | 0x75uy -> parseVEX t rhlp nor0F75 vex0F75
  | 0x76uy -> parseVEX t rhlp nor0F76 vex0F76
  | 0x77uy -> parseVEX t rhlp nor0F77 vex0F77
  | 0x7Euy -> parseVEXW t rhlp nor0F7EW0 nor0F7EW1 vex0F7EW0 vex0F7EW1
  | 0x7Fuy -> parseEVEX t rhlp nor0F7F vex0F7F evex0F7FW0 evex0F7FW1
  | 0x80uy -> render (addBND t) rhlp Opcode.JO SzCond.F64 opRel szD64
  | 0x81uy -> render (addBND t) rhlp Opcode.JNO SzCond.F64 opRel szD64
  | 0x82uy -> render (addBND t) rhlp Opcode.JB SzCond.F64 opRel szD64
  | 0x83uy -> render (addBND t) rhlp Opcode.JNB SzCond.F64 opRel szD64
  | 0x84uy -> render (addBND t) rhlp Opcode.JZ SzCond.F64 opRel szD64
  | 0x85uy -> render (addBND t) rhlp Opcode.JNZ SzCond.F64 opRel szD64
  | 0x86uy -> render (addBND t) rhlp Opcode.JBE SzCond.F64 opRel szD64
  | 0x87uy -> render (addBND t) rhlp Opcode.JA SzCond.F64 opRel szD64
  | 0x88uy -> render (addBND t) rhlp Opcode.JS SzCond.F64 opRel szD64
  | 0x89uy -> render (addBND t) rhlp Opcode.JNS SzCond.F64 opRel szD64
  | 0x8Auy -> render (addBND t) rhlp Opcode.JP SzCond.F64 opRel szD64
  | 0x8Buy -> render (addBND t) rhlp Opcode.JNP SzCond.F64 opRel szD64
  | 0x8Cuy -> render (addBND t) rhlp Opcode.JL SzCond.F64 opRel szD64
  | 0x8Duy -> render (addBND t) rhlp Opcode.JNL SzCond.F64 opRel szD64
  | 0x8Euy -> render (addBND t) rhlp Opcode.JLE SzCond.F64 opRel szD64
  | 0x8Fuy -> render (addBND t) rhlp Opcode.JG SzCond.F64 opRel szD64
  | 0x90uy -> render t rhlp Opcode.SETO SzCond.Nor opMem szByte
  | 0x91uy -> render t rhlp Opcode.SETNO SzCond.Nor opMem szByte
  | 0x92uy -> render t rhlp Opcode.SETB SzCond.Nor opMem szByte
  | 0x93uy -> render t rhlp Opcode.SETNB SzCond.Nor opMem szByte
  | 0x94uy -> render t rhlp Opcode.SETZ SzCond.Nor opMem szByte
  | 0x95uy -> render t rhlp Opcode.SETNZ SzCond.Nor opMem szByte
  | 0x96uy -> render t rhlp Opcode.SETBE SzCond.Nor opMem szByte
  | 0x97uy -> render t rhlp Opcode.SETA SzCond.Nor opMem szByte
  | 0x98uy -> render t rhlp Opcode.SETS SzCond.Nor opMem szByte
  | 0x99uy -> render t rhlp Opcode.SETNS SzCond.Nor opMem szByte
  | 0x9Auy -> render t rhlp Opcode.SETP SzCond.Nor opMem szByte
  | 0x9Buy -> render t rhlp Opcode.SETNP SzCond.Nor opMem szByte
  | 0x9Cuy -> render t rhlp Opcode.SETL SzCond.Nor opMem szByte
  | 0x9Duy -> render t rhlp Opcode.SETNL SzCond.Nor opMem szByte
  | 0x9Euy -> render t rhlp Opcode.SETLE SzCond.Nor opMem szByte
  | 0x9Fuy -> render t rhlp Opcode.SETG SzCond.Nor opMem szByte
  | 0xA0uy -> render t rhlp Opcode.PUSH SzCond.D64 opFs szRegW
  | 0xA1uy -> render t rhlp Opcode.POP SzCond.D64 opFs szRegW
  | 0xA2uy -> render t rhlp Opcode.CPUID SzCond.Nor opNo szDef
  | 0xA3uy -> render t rhlp Opcode.BT SzCond.Nor opRmGpr szDef
  | 0xA4uy -> render t rhlp Opcode.SHLD SzCond.Nor opXmRegImm8 szDef
  | 0xA5uy -> render t rhlp Opcode.SHLD SzCond.Nor opRmGprCL szDef
  | 0xA8uy -> render t rhlp Opcode.PUSH SzCond.D64 opGs szRegW
  | 0xA9uy -> render t rhlp Opcode.POP SzCond.D64 opGs szRegW
  | 0xAAuy -> render t rhlp Opcode.RSM SzCond.Nor opNo szDef
  | 0xABuy -> render t rhlp Opcode.BTS SzCond.Nor opRmGpr szDef
  | 0xACuy -> render t rhlp Opcode.SHRD SzCond.Nor opXmRegImm8 szDef
  | 0xADuy -> render t rhlp Opcode.SHRD SzCond.Nor opRmGprCL szDef
  | 0xAFuy -> render t rhlp Opcode.IMUL SzCond.Nor opGprRm szDef
  | 0xB0uy -> render t rhlp Opcode.CMPXCHG SzCond.Nor opRmGpr szByte
  | 0xB1uy -> render t rhlp Opcode.CMPXCHG SzCond.Nor opRmGpr szDef
  | 0xB2uy -> render t rhlp Opcode.LSS SzCond.Nor opGprM szPRM
  | 0xB3uy -> render t rhlp Opcode.BTR SzCond.Nor opRmGpr szDef
  | 0xB4uy -> render t rhlp Opcode.LFS SzCond.Nor opGprM szPRM
  | 0xB5uy -> render t rhlp Opcode.LGS SzCond.Nor opGprM szPRM
  | 0xB6uy -> render t rhlp Opcode.MOVZX SzCond.Nor opGprRm szBV
  | 0xB7uy -> render t rhlp Opcode.MOVZX SzCond.Nor opGprRm szWV
  | 0xB8uy when not <| hasREPZ t.TPrefixes -> raise ParsingFailureException
  | 0xB8uy -> render t rhlp Opcode.POPCNT SzCond.Nor opGprRm szDef
  | 0xBBuy when hasREPZ t.TPrefixes -> raise ParsingFailureException
  | 0xBBuy -> render t rhlp Opcode.BTC SzCond.Nor opRmGpr szDef
  | 0xBCuy when hasREPZ t.TPrefixes ->
    render t rhlp Opcode.TZCNT SzCond.Nor opGprRm szDef
  | 0xBCuy -> render t rhlp Opcode.BSF SzCond.Nor opGprRm szDef
  | 0xBDuy when hasREPZ t.TPrefixes ->
    render t rhlp Opcode.LZCNT SzCond.Nor opGprRm szDef
  | 0xBDuy -> render t rhlp Opcode.BSR SzCond.Nor opGprRm szDef
  | 0xBEuy -> render t rhlp Opcode.MOVSX SzCond.Nor opGprRm szBV
  | 0xBFuy -> render t rhlp Opcode.MOVSX SzCond.Nor opGprRm szWV
  | 0xC0uy -> render t rhlp Opcode.XADD SzCond.Nor opRmGpr szByte
  | 0xC1uy -> render t rhlp Opcode.XADD SzCond.Nor opRmGpr szDef
  | 0xC2uy -> parseEVEX t rhlp nor0FC2 vex0FC2 evex0FC2W0 evex0FC2W1
  | 0xC3uy -> render t rhlp Opcode.MOVNTI SzCond.Nor opRmGpr szDef
  | 0xC4uy -> parseVEX t rhlp nor0FC4 vex0FC4
  | 0xC5uy -> parseVEX t rhlp nor0FC5 vex0FC5
  | 0xC6uy -> parseVEX t rhlp nor0FC6 vex0FC6
  | 0xC8uy -> render (ignOpSz t) rhlp Opcode.BSWAP SzCond.Nor opRax szDef
  | 0xC9uy -> render (ignOpSz t) rhlp Opcode.BSWAP SzCond.Nor opRcx szDef
  | 0xCAuy -> render (ignOpSz t) rhlp Opcode.BSWAP SzCond.Nor opRdx szDef
  | 0xCBuy -> render (ignOpSz t) rhlp Opcode.BSWAP SzCond.Nor opRbx szDef
  | 0xCCuy -> render (ignOpSz t) rhlp Opcode.BSWAP SzCond.Nor opRsp szDef
  | 0xCDuy -> render (ignOpSz t) rhlp Opcode.BSWAP SzCond.Nor opRbp szDef
  | 0xCEuy -> render (ignOpSz t) rhlp Opcode.BSWAP SzCond.Nor opRsi szDef
  | 0xCFuy -> render (ignOpSz t) rhlp Opcode.BSWAP SzCond.Nor opRdi szDef
  | 0xD1uy -> parseVEX t rhlp nor0FD1 vex0FD1
  | 0xD2uy -> parseVEX t rhlp nor0FD2 vex0FD2
  | 0xD3uy -> parseVEX t rhlp nor0FD3 vex0FD3
  | 0xD4uy -> parseVEX t rhlp nor0FD4 vex0FD4
  | 0xD5uy -> parseVEX t rhlp nor0FD5 vex0FD5
  | 0xD6uy ->
#if !EMULATION
    ensureVEX128 t
#endif
    parseVEX t rhlp nor0FD6 vex0FD6
  | 0xD7uy -> parseVEX t rhlp nor0FD7 vex0FD7
  | 0xD8uy -> parseVEX t rhlp nor0FD8 vex0FD8
  | 0xD9uy -> parseVEX t rhlp nor0FD9 vex0FD9
  | 0xDAuy -> parseVEX t rhlp nor0FDA vex0FDA
  | 0xDBuy -> parseVEX t rhlp nor0FDB vex0FDB
  | 0xDCuy -> parseVEX t rhlp nor0FDC vex0FDC
  | 0xDDuy -> parseVEX t rhlp nor0FDD vex0FDD
  | 0xDEuy -> parseVEX t rhlp nor0FDE vex0FDE
  | 0xDFuy -> parseVEX t rhlp nor0FDF vex0FDF
  | 0xE0uy -> parseVEX t rhlp nor0FE0 vex0FE0
  | 0xE1uy -> parseVEX t rhlp nor0FE1 vex0FE1
  | 0xE2uy -> parseVEX t rhlp nor0FE2 vex0FE2
  | 0xE3uy -> parseVEX t rhlp nor0FE3 vex0FE3
  | 0xE4uy -> parseVEX t rhlp nor0FE4 vex0FE4
  | 0xE5uy -> parseVEX t rhlp nor0FE5 vex0FE5
  | 0xE6uy -> parseEVEX t rhlp nor0FE6 vex0FE6 evex0FE6W0 notEn
  | 0xE7uy -> parseEVEX t rhlp nor0FE7 vex0FE7 evex0FE7W0 evex0FE7W1
  | 0xE8uy -> parseVEX t rhlp nor0FE8 vex0FE8
  | 0xE9uy -> parseVEX t rhlp nor0FE9 vex0FE9
  | 0xEAuy -> parseVEX t rhlp nor0FEA vex0FEA
  | 0xEBuy -> parseVEX t rhlp nor0FEB vex0FEB
  | 0xECuy -> parseVEX t rhlp nor0FEC vex0FEC
  | 0xEDuy -> parseVEX t rhlp nor0FED vex0FED
  | 0xEFuy -> parseEVEX t rhlp nor0FEF vex0FEF evex0FEFW0 evex0FEFW1
  | 0xEFuy -> parseVEX t rhlp nor0FEF vex0FEF
  | 0xF0uy -> parseVEX t rhlp nor0FF0 vex0FF0
  | 0xF1uy -> parseVEX t rhlp nor0FF1 vex0FF1
  | 0xF2uy -> parseVEX t rhlp nor0FF2 vex0FF2
  | 0xF3uy -> parseVEX t rhlp nor0FF3 vex0FF3
  | 0xF4uy -> parseVEX t rhlp nor0FF4 vex0FF4
  | 0xF5uy -> parseVEX t rhlp nor0FF5 vex0FF5
  | 0xF6uy -> parseVEX t rhlp nor0FF6 vex0FF6
  | 0xF8uy -> parseVEX t rhlp nor0FF8 vex0FF8
  | 0xF9uy -> parseVEX t rhlp nor0FF9 vex0FF9
  | 0xFAuy -> parseVEX t rhlp nor0FFA vex0FFA
  | 0xFBuy -> parseVEX t rhlp nor0FFB vex0FFB
  | 0xFCuy -> parseVEX t rhlp nor0FFC vex0FFC
  | 0xFDuy -> parseVEX t rhlp nor0FFD vex0FFD
  | 0xFEuy -> parseVEX t rhlp nor0FFE vex0FFE
  | 0x00uy -> parseGrpOp t rhlp OpGroup.G6 opNo szDef
  | 0x01uy -> parseGrpOp t rhlp OpGroup.G7 opNo szDef
  | 0xBAuy -> parseGrpOp t rhlp OpGroup.G8 opRmImm8 szDef
  | 0xC7uy -> parseGrpOp t rhlp OpGroup.G9 opNo szDef
  | 0x71uy -> parseGrpOp t rhlp OpGroup.G12 opNo szDef
  | 0x72uy -> parseGrpOp t rhlp OpGroup.G13 opNo szDef
  | 0x73uy -> parseGrpOp t rhlp OpGroup.G14 opNo szDef
  | 0xAEuy -> parseGrpOp t rhlp OpGroup.G15 opNo szDef
  | 0x18uy -> parseGrpOp t rhlp OpGroup.G16 opMem szDef
  | 0x38uy -> parseThreeByteOp1 t rhlp
  | 0x3Auy -> parseThreeByteOp2 t rhlp
  | _ -> raise ParsingFailureException

(* Table A-3 of Volume 2 (Two-byte Opcode Map) *)
let parseTwoByteOpcode t (rhlp: ReadHelper) =
  rhlp.ReadByte () |> pTwoByteOp t rhlp

let pOneByteOpcode t rhlp byte =
  match byte with
  | 0x00uy -> render t rhlp Opcode.ADD SzCond.Nor opRmGpr szByte
  | 0x01uy -> render t rhlp Opcode.ADD SzCond.Nor opRmGpr szDef
  | 0x02uy -> render t rhlp Opcode.ADD SzCond.Nor opGprRm szByte
  | 0x03uy -> render t rhlp Opcode.ADD SzCond.Nor opGprRm szDef
  | 0x04uy -> render t rhlp Opcode.ADD SzCond.Nor opRegImm8 szByte
  | 0x05uy -> render t rhlp Opcode.ADD SzCond.Nor opRegImm szDef
  | 0x06uy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.PUSH SzCond.Nor opEs szRegW
  | 0x07uy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.POP SzCond.Nor opEs szRegW
  | 0x08uy -> render t rhlp Opcode.OR SzCond.Nor opRmGpr szByte
  | 0x09uy -> render t rhlp Opcode.OR SzCond.Nor opRmGpr szDef
  | 0x0Auy -> render t rhlp Opcode.OR SzCond.Nor opGprRm szByte
  | 0x0Buy -> render t rhlp Opcode.OR SzCond.Nor opGprRm szDef
  | 0x0Cuy -> render t rhlp Opcode.OR SzCond.Nor opRegImm8 szByte
  | 0x0Duy -> render t rhlp Opcode.OR SzCond.Nor opRegImm szDef
  | 0x0Euy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.PUSH SzCond.Nor opCs szRegW
  | 0x10uy -> render t rhlp Opcode.ADC SzCond.Nor opRmGpr szByte
  | 0x11uy -> render t rhlp Opcode.ADC SzCond.Nor opRmGpr szDef
  | 0x12uy -> render t rhlp Opcode.ADC SzCond.Nor opGprRm szByte
  | 0x13uy -> render t rhlp Opcode.ADC SzCond.Nor opGprRm szDef
  | 0x14uy -> render t rhlp Opcode.ADC SzCond.Nor opRegImm8 szByte
  | 0x15uy -> render t rhlp Opcode.ADC SzCond.Nor opRegImm szDef
  | 0x16uy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.PUSH SzCond.Nor opSs szRegW
  | 0x17uy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.POP SzCond.Nor opSs szRegW
  | 0x18uy -> render t rhlp Opcode.SBB SzCond.Nor opRmGpr szByte
  | 0x19uy -> render t rhlp Opcode.SBB SzCond.Nor opRmGpr szDef
  | 0x1Auy -> render t rhlp Opcode.SBB SzCond.Nor opGprRm szByte
  | 0x1Buy -> render t rhlp Opcode.SBB SzCond.Nor opGprRm szDef
  | 0x1Cuy -> render t rhlp Opcode.SBB SzCond.Nor opRegImm8 szByte
  | 0x1Duy -> render t rhlp Opcode.SBB SzCond.Nor opRegImm szDef
  | 0x1Euy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.PUSH SzCond.Nor opDs szRegW
  | 0x1Fuy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.POP SzCond.Nor opDs szRegW
  | 0x20uy -> render t rhlp Opcode.AND SzCond.Nor opRmGpr szByte
  | 0x21uy -> render t rhlp Opcode.AND SzCond.Nor opRmGpr szDef
  | 0x22uy -> render t rhlp Opcode.AND SzCond.Nor opGprRm szByte
  | 0x23uy -> render t rhlp Opcode.AND SzCond.Nor opGprRm szDef
  | 0x24uy -> render t rhlp Opcode.AND SzCond.Nor opRegImm8 szByte
  | 0x25uy -> render t rhlp Opcode.AND SzCond.Nor opRegImm szDef
  | 0x27uy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.DAA SzCond.Nor opNo szDef
  | 0x28uy -> render t rhlp Opcode.SUB SzCond.Nor opRmGpr szByte
  | 0x29uy -> render t rhlp Opcode.SUB SzCond.Nor opRmGpr szDef
  | 0x2Auy -> render t rhlp Opcode.SUB SzCond.Nor opGprRm szByte
  | 0x2Buy -> render t rhlp Opcode.SUB SzCond.Nor opGprRm szDef
  | 0x2Cuy -> render t rhlp Opcode.SUB SzCond.Nor opRegImm8 szByte
  | 0x2Duy -> render t rhlp Opcode.SUB SzCond.Nor opRegImm szDef
  | 0x2Fuy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.DAS SzCond.Nor opNo szDef
  | 0x30uy -> render t rhlp Opcode.XOR SzCond.Nor opRmGpr szByte
  | 0x31uy -> render t rhlp Opcode.XOR SzCond.Nor opRmGpr szDef
  | 0x32uy -> render t rhlp Opcode.XOR SzCond.Nor opGprRm szByte
  | 0x33uy -> render t rhlp Opcode.XOR SzCond.Nor opGprRm szDef
  | 0x34uy -> render t rhlp Opcode.XOR SzCond.Nor opRegImm8 szByte
  | 0x35uy -> render t rhlp Opcode.XOR SzCond.Nor opRegImm szDef
  | 0x37uy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.AAA SzCond.Nor opNo szDef
  | 0x38uy -> render t rhlp Opcode.CMP SzCond.Nor opRmGpr szByte
  | 0x39uy -> render t rhlp Opcode.CMP SzCond.Nor opRmGpr szDef
  | 0x3Auy -> render t rhlp Opcode.CMP SzCond.Nor opGprRm szByte
  | 0x3Buy -> render t rhlp Opcode.CMP SzCond.Nor opGprRm szDef
  | 0x3Cuy -> render t rhlp Opcode.CMP SzCond.Nor opRegImm8 szByte
  | 0x3Duy -> render t rhlp Opcode.CMP SzCond.Nor opRegImm szDef
  | 0x3Fuy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.AAS SzCond.Nor opNo szDef
  | 0x40uy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.INC SzCond.Nor opEax szDef
  | 0x41uy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.INC SzCond.Nor opEcx szDef
  | 0x42uy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.INC SzCond.Nor opEdx szDef
  | 0x43uy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.INC SzCond.Nor opEbx szDef
  | 0x44uy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.INC SzCond.Nor opEsp szDef
  | 0x45uy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.INC SzCond.Nor opEbp szDef
  | 0x46uy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.INC SzCond.Nor opEsi szDef
  | 0x47uy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.INC SzCond.Nor opEdi szDef
  | 0x48uy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.DEC SzCond.Nor opEax szDef
  | 0x49uy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.DEC SzCond.Nor opEcx szDef
  | 0x4Auy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.DEC SzCond.Nor opEdx szDef
  | 0x4Buy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.DEC SzCond.Nor opEbx szDef
  | 0x4Cuy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.DEC SzCond.Nor opEsp szDef
  | 0x4Duy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.DEC SzCond.Nor opEbp szDef
  | 0x4Euy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.DEC SzCond.Nor opEsi szDef
  | 0x4Fuy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.DEC SzCond.Nor opEdi szDef
  | 0x50uy -> render t rhlp Opcode.PUSH SzCond.D64 opRax szD64
  | 0x51uy -> render t rhlp Opcode.PUSH SzCond.D64 opRcx szD64
  | 0x52uy -> render t rhlp Opcode.PUSH SzCond.D64 opRdx szD64
  | 0x53uy -> render t rhlp Opcode.PUSH SzCond.D64 opRbx szD64
  | 0x54uy -> render t rhlp Opcode.PUSH SzCond.D64 opRsp szD64
  | 0x55uy -> render t rhlp Opcode.PUSH SzCond.D64 opRbp szD64
  | 0x56uy -> render t rhlp Opcode.PUSH SzCond.D64 opRsi szD64
  | 0x57uy -> render t rhlp Opcode.PUSH SzCond.D64 opRdi szD64
  | 0x58uy -> render t rhlp Opcode.POP SzCond.D64 opRax szD64
  | 0x59uy -> render t rhlp Opcode.POP SzCond.D64 opRcx szD64
  | 0x5Auy -> render t rhlp Opcode.POP SzCond.D64 opRdx szD64
  | 0x5Buy -> render t rhlp Opcode.POP SzCond.D64 opRbx szD64
  | 0x5Cuy -> render t rhlp Opcode.POP SzCond.D64 opRsp szD64
  | 0x5Duy -> render t rhlp Opcode.POP SzCond.D64 opRbp szD64
  | 0x5Euy -> render t rhlp Opcode.POP SzCond.D64 opRsi szD64
  | 0x5Fuy -> render t rhlp Opcode.POP SzCond.D64 opRdi szD64
  | 0x60uy ->
#if !EMULATION
    ensure32 t
#endif
    if hasOprSz t.TPrefixes then
      render t rhlp Opcode.PUSHA SzCond.Nor opNo szDef
    else render t rhlp Opcode.PUSHAD SzCond.Nor opNo szDef
  | 0x61uy ->
#if !EMULATION
    ensure32 t
#endif
    if hasOprSz t.TPrefixes then
      render t rhlp Opcode.POPA SzCond.Nor opNo szDef
    else render t rhlp Opcode.POPAD SzCond.Nor opNo szDef
  | 0x62uy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.BOUND SzCond.Nor opGprM szDef
  | 0x63uy ->
    if is64bit t then
      if not (hasREXW t.TREXPrefix) then raise ParsingFailureException
      else render t rhlp Opcode.MOVSXD SzCond.Nor opGprRm szDV
    else render t rhlp Opcode.ARPL SzCond.Nor opRmGpr szWord
  | 0x68uy -> render t rhlp Opcode.PUSH SzCond.D64 opImm szDef
  | 0x69uy -> render t rhlp Opcode.IMUL SzCond.Nor opGprRmImm szDef
  | 0x6Auy -> render t rhlp Opcode.PUSH SzCond.D64 opSImm8 szDef
  | 0x6Buy -> render t rhlp Opcode.IMUL SzCond.Nor opGprRmImm8 szDef
  | 0x6Cuy -> render t rhlp Opcode.INSB SzCond.Nor opNo szDef
  | 0x6Duy ->
    if hasOprSz t.TPrefixes then
      render t rhlp Opcode.INSW SzCond.Nor opNo szDef
    else render t rhlp Opcode.INSD SzCond.Nor opNo szDef
  | 0x6Euy -> render t rhlp Opcode.OUTSB SzCond.Nor opNo szDef
  | 0x6Fuy ->
    if hasOprSz t.TPrefixes then
      render t rhlp Opcode.OUTSW SzCond.Nor opNo szDef
    else render t rhlp Opcode.OUTSD SzCond.Nor opNo szDef
  | 0x70uy -> render (addBND t) rhlp Opcode.JO SzCond.F64 opRel8 szByte
  | 0x71uy -> render (addBND t) rhlp Opcode.JNO SzCond.F64 opRel8 szByte
  | 0x72uy -> render (addBND t) rhlp Opcode.JB SzCond.F64 opRel8 szByte
  | 0x73uy -> render (addBND t) rhlp Opcode.JNB SzCond.F64 opRel8 szByte
  | 0x74uy -> render (addBND t) rhlp Opcode.JZ SzCond.F64 opRel8 szByte
  | 0x75uy -> render (addBND t) rhlp Opcode.JNZ SzCond.F64 opRel8 szByte
  | 0x76uy -> render (addBND t) rhlp Opcode.JBE SzCond.F64 opRel8 szByte
  | 0x77uy -> render (addBND t) rhlp Opcode.JA SzCond.F64 opRel8 szByte
  | 0x78uy -> render (addBND t) rhlp Opcode.JS SzCond.F64 opRel8 szByte
  | 0x79uy -> render (addBND t) rhlp Opcode.JNS SzCond.F64 opRel8 szByte
  | 0x7Auy -> render (addBND t) rhlp Opcode.JP SzCond.F64 opRel8 szByte
  | 0x7Buy -> render (addBND t) rhlp Opcode.JNP SzCond.F64 opRel8 szByte
  | 0x7Cuy -> render (addBND t) rhlp Opcode.JL SzCond.F64 opRel8 szByte
  | 0x7Duy -> render (addBND t) rhlp Opcode.JNL SzCond.F64 opRel8 szByte
  | 0x7Euy -> render (addBND t) rhlp Opcode.JLE SzCond.F64 opRel8 szByte
  | 0x7Fuy -> render (addBND t) rhlp Opcode.JG SzCond.F64 opRel8 szByte
  | 0x84uy -> render t rhlp Opcode.TEST SzCond.Nor opRmGpr szByte
  | 0x85uy -> render t rhlp Opcode.TEST SzCond.Nor opRmGpr szDef
  | 0x86uy -> render t rhlp Opcode.XCHG SzCond.Nor opRmGpr szByte
  | 0x87uy -> render t rhlp Opcode.XCHG SzCond.Nor opRmGpr szDef
  | 0x88uy -> render t rhlp Opcode.MOV SzCond.Nor opRmGpr szByte
  | 0x89uy -> render t rhlp Opcode.MOV SzCond.Nor opRmGpr szDef
  | 0x8Auy -> render t rhlp Opcode.MOV SzCond.Nor opGprRm szByte
  | 0x8Buy -> render t rhlp Opcode.MOV SzCond.Nor opGprRm szDef
  | 0x8Cuy -> render t rhlp Opcode.MOV SzCond.Nor opRmSeg szWord
  | 0x8Duy -> render t rhlp Opcode.LEA SzCond.Nor opGprM szDef
  | 0x8Euy -> render t rhlp Opcode.MOV SzCond.Nor opSegRm szWord
  | 0x90uy ->
    if hasNoPref t && hasNoREX t then
      render t rhlp Opcode.NOP SzCond.Nor opNo szDef
    elif hasREPZ t.TPrefixes then
      render t rhlp Opcode.PAUSE SzCond.Nor opNo szDef
    else render t rhlp Opcode.XCHG SzCond.Nor opRaxRax szDef
  | 0x91uy -> render t rhlp Opcode.XCHG SzCond.Nor opRaxRcx szDef
  | 0x92uy -> render t rhlp Opcode.XCHG SzCond.Nor opRaxRdx szDef
  | 0x93uy -> render t rhlp Opcode.XCHG SzCond.Nor opRaxRbx szDef
  | 0x94uy -> render t rhlp Opcode.XCHG SzCond.Nor opRaxRsp szDef
  | 0x95uy -> render t rhlp Opcode.XCHG SzCond.Nor opRaxRbp szDef
  | 0x96uy -> render t rhlp Opcode.XCHG SzCond.Nor opRaxRsi szDef
  | 0x97uy -> render t rhlp Opcode.XCHG SzCond.Nor opRaxRdi szDef
  | 0x98uy ->
    if hasOprSz t.TPrefixes then
      render t rhlp Opcode.CBW SzCond.Nor opNo szDef
    elif hasREXW t.TREXPrefix then
      render t rhlp Opcode.CDQE SzCond.Nor opNo szDef
    else render t rhlp Opcode.CWDE SzCond.Nor opNo szDef
  | 0x99uy ->
    if hasOprSz t.TPrefixes then
      render t rhlp Opcode.CWD SzCond.Nor opNo szDef
    elif hasREXW t.TREXPrefix then
      render t rhlp Opcode.CQO SzCond.Nor opNo szDef
    else render t rhlp Opcode.CDQ SzCond.Nor opNo szDef
  | 0x9Auy ->
#if !EMULATION
    ensure32 t
#endif
    render (addBND t) rhlp Opcode.CALLFar SzCond.Nor opDir szP
  | 0x9Buy -> render t rhlp Opcode.WAIT SzCond.Nor opNo szDef
  | 0x9Cuy ->
    if hasOprSz t.TPrefixes then
      let szcond = if is64bit t then SzCond.D64 else SzCond.Nor
      render t rhlp Opcode.PUSHF szcond opNo szDef
    elif is64bit t then render t rhlp Opcode.PUSHFQ SzCond.D64 opNo szDef
    else render t rhlp Opcode.PUSHFD SzCond.Nor opNo szDef
  | 0x9Duy ->
    if hasOprSz t.TPrefixes then
      let szcond = if is64bit t then SzCond.D64 else SzCond.Nor
      render t rhlp Opcode.POPF szcond opNo szDef
    elif is64bit t then render t rhlp Opcode.POPFQ SzCond.D64 opNo szDef
    else render t rhlp Opcode.POPFD SzCond.Nor opNo szDef
  | 0x9Euy -> render t rhlp Opcode.SAHF SzCond.Nor opNo szDef
  | 0x9Fuy -> render t rhlp Opcode.LAHF SzCond.Nor opNo szDef
  | 0xA0uy -> render t rhlp Opcode.MOV SzCond.Nor opRaxFar szByte
  | 0xA1uy -> render t rhlp Opcode.MOV SzCond.Nor opRaxFar szDef
  | 0xA2uy -> render t rhlp Opcode.MOV SzCond.Nor opFarRax szByte
  | 0xA3uy -> render t rhlp Opcode.MOV SzCond.Nor opFarRax szDef
  | 0xA4uy -> render t rhlp Opcode.MOVSB SzCond.Nor opNo szDef
  | 0xA5uy ->
    if hasOprSz t.TPrefixes then
      render t rhlp Opcode.MOVSW SzCond.Nor opNo szDef
    elif hasREXW t.TREXPrefix then
      render t rhlp Opcode.MOVSQ SzCond.Nor opNo szDef
    else render t rhlp Opcode.MOVSD SzCond.Nor opNo szDef
  | 0xA6uy -> render t rhlp Opcode.CMPSB SzCond.Nor opNo szByte
  | 0xA7uy ->
    if hasOprSz t.TPrefixes then
      render t rhlp Opcode.CMPSW SzCond.Nor opNo szDef
    elif hasREXW t.TREXPrefix then
      render t rhlp Opcode.CMPSQ SzCond.Nor opNo szDef
    else render t rhlp Opcode.CMPSD SzCond.Nor opNo szDef
  | 0xA8uy -> render t rhlp Opcode.TEST SzCond.Nor opRegImm8 szByte
  | 0xA9uy -> render t rhlp Opcode.TEST SzCond.Nor opRegImm szDef
  | 0xAAuy -> render t rhlp Opcode.STOSB SzCond.Nor opNo szDef
  | 0xABuy ->
    if hasOprSz t.TPrefixes then
      render t rhlp Opcode.STOSW SzCond.Nor opNo szDef
    elif hasREXW t.TREXPrefix then
      render t rhlp Opcode.STOSQ SzCond.Nor opNo szDef
    else render t rhlp Opcode.STOSD SzCond.Nor opNo szDef
  | 0xACuy -> render t rhlp Opcode.LODSB SzCond.Nor opNo szDef
  | 0xADuy ->
    if hasOprSz t.TPrefixes then
      render t rhlp Opcode.LODSW SzCond.Nor opNo szDef
    elif hasREXW t.TREXPrefix then
      render t rhlp Opcode.LODSQ SzCond.Nor opNo szDef
    else render t rhlp Opcode.LODSD SzCond.Nor opNo szDef
  | 0xAEuy -> render t rhlp Opcode.SCASB SzCond.Nor opNo szDef
  | 0xAFuy ->
    if hasOprSz t.TPrefixes then
      render t rhlp Opcode.SCASW SzCond.Nor opNo szDef
    elif hasREXW t.TREXPrefix then
      render t rhlp Opcode.SCASQ SzCond.Nor opNo szDef
    else render t rhlp Opcode.SCASD SzCond.Nor opNo szDef
  | 0xB0uy -> render t rhlp Opcode.MOV SzCond.Nor opALImm8 szByte
  | 0xB1uy -> render t rhlp Opcode.MOV SzCond.Nor opCLImm8 szByte
  | 0xB2uy -> render t rhlp Opcode.MOV SzCond.Nor opDLImm8 szByte
  | 0xB3uy -> render t rhlp Opcode.MOV SzCond.Nor opBLImm8 szByte
  | 0xB4uy -> render t rhlp Opcode.MOV SzCond.Nor opAhImm8 szByte
  | 0xB5uy -> render t rhlp Opcode.MOV SzCond.Nor opChImm8 szByte
  | 0xB6uy -> render t rhlp Opcode.MOV SzCond.Nor opDhImm8 szByte
  | 0xB7uy -> render t rhlp Opcode.MOV SzCond.Nor opBhImm8 szByte
  | 0xB8uy -> render t rhlp Opcode.MOV SzCond.Nor opRaxImm szDef
  | 0xB9uy -> render t rhlp Opcode.MOV SzCond.Nor opRcxImm szDef
  | 0xBAuy -> render t rhlp Opcode.MOV SzCond.Nor opRdxImm szDef
  | 0xBBuy -> render t rhlp Opcode.MOV SzCond.Nor opRbxImm szDef
  | 0xBCuy -> render t rhlp Opcode.MOV SzCond.Nor opRspImm szDef
  | 0xBDuy -> render t rhlp Opcode.MOV SzCond.Nor opRbpImm szDef
  | 0xBEuy -> render t rhlp Opcode.MOV SzCond.Nor opRsiImm szDef
  | 0xBFuy -> render t rhlp Opcode.MOV SzCond.Nor opRdiImm szDef
  | 0xC2uy ->
    render (addBND t) rhlp Opcode.RETNearImm SzCond.F64 opImm16 szDef
  | 0xC3uy -> render (addBND t) rhlp Opcode.RETNear SzCond.F64 opNo szDef
  | 0xC4uy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.LES SzCond.Nor opGprM szPZ
  | 0xC5uy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.LDS SzCond.Nor opGprM szPZ
  | 0xC8uy -> render t rhlp Opcode.ENTER SzCond.Nor opImmImm szDef
  | 0xC9uy -> render t rhlp Opcode.LEAVE SzCond.D64 opNo szDef
  | 0xCAuy -> render (addBND t) rhlp Opcode.RETFarImm SzCond.Nor opImm16 szDef
  | 0xCBuy -> render (addBND t) rhlp Opcode.RETFar SzCond.Nor opNo szDef
  | 0xCCuy -> render t rhlp Opcode.INT3 SzCond.Nor opNo szDef
  | 0xCDuy -> render t rhlp Opcode.INT SzCond.Nor opImm8 szDef
  | 0xCEuy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.INTO SzCond.Nor opNo szDef
  | 0xCFuy ->
    if hasOprSz t.TPrefixes then
      render t rhlp Opcode.IRETW SzCond.Nor opNo szDef
    elif hasREXW t.TREXPrefix then
      render t rhlp Opcode.IRETQ SzCond.Nor opNo szDef
    else render t rhlp Opcode.IRETD SzCond.Nor opNo szDef
  | 0xD4uy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.AAM SzCond.Nor opImm8 szDef
  | 0xD5uy ->
#if !EMULATION
    ensure32 t
#endif
    render t rhlp Opcode.AAD SzCond.Nor opImm8 szDef
  | 0xD7uy -> render t rhlp Opcode.XLATB SzCond.Nor opNo szDef
  | 0xD8uy -> parseESCOp t rhlp 0xD8uy getD8OpWithin00toBF getD8OverBF
  | 0xD9uy -> parseESCOp t rhlp 0xD9uy getD9OpWithin00toBF getD9OverBF
  | 0xDAuy -> parseESCOp t rhlp 0xDAuy getDAOpWithin00toBF getDAOverBF
  | 0xDBuy -> parseESCOp t rhlp 0xDBuy getDBOpWithin00toBF getDBOverBF
  | 0xDCuy -> parseESCOp t rhlp 0xDCuy getDCOpWithin00toBF getDCOverBF
  | 0xDDuy -> parseESCOp t rhlp 0xDDuy getDDOpWithin00toBF getDDOverBF
  | 0xDEuy -> parseESCOp t rhlp 0xDEuy getDEOpWithin00toBF getDEOverBF
  | 0xDFuy -> parseESCOp t rhlp 0xDFuy getDFOpWithin00toBF getDFOverBF
  | 0xE0uy -> render t rhlp Opcode.LOOPNE SzCond.F64 opRel8 szByte
  | 0xE1uy -> render t rhlp Opcode.LOOPE SzCond.F64 opRel8 szByte
  | 0xE2uy -> render t rhlp Opcode.LOOP SzCond.F64 opRel8 szByte
  | 0xE3uy ->
    if hasAddrSz t.TPrefixes then
      let opcode = if is64bit t then Opcode.JECXZ else Opcode.JCXZ
      render t rhlp opcode SzCond.F64 opRel8 szByte
    elif is64bit t then render t rhlp Opcode.JRCXZ SzCond.F64 opRel8 szByte
    else render t rhlp Opcode.JECXZ SzCond.F64 opRel8 szByte
  | 0xE4uy -> render t rhlp Opcode.IN SzCond.Nor opRegImm8 szByte
  | 0xE5uy -> render t rhlp Opcode.IN SzCond.Nor opRegImm8 szDef
  | 0xE6uy -> render t rhlp Opcode.OUT SzCond.Nor opImm8Reg szByte
  | 0xE7uy -> render t rhlp Opcode.OUT SzCond.Nor opImm8Reg szDef
  | 0xE8uy -> render (addBND t) rhlp Opcode.CALLNear SzCond.F64 opRel szD64
  | 0xE9uy -> render (addBND t) rhlp Opcode.JMPNear SzCond.F64 opRel szD64
  | 0xEAuy ->
#if !EMULATION
    ensure32 t
#endif
    render (addBND t) rhlp Opcode.JMPFar SzCond.Nor opDir szP
  | 0xEBuy -> render (addBND t) rhlp Opcode.JMPNear SzCond.F64 opRel8 szByte
  | 0xECuy -> render t rhlp Opcode.IN SzCond.Nor opALDx szDef
  | 0xEDuy -> render t rhlp Opcode.IN SzCond.Nor opEaxDx szDef
  | 0xEEuy -> render t rhlp Opcode.OUT SzCond.Nor opDxAL szDef
  | 0xEFuy -> render t rhlp Opcode.OUT SzCond.Nor opDxEax szDef
  | 0xF4uy -> render t rhlp Opcode.HLT SzCond.F64 opNo szDef
  | 0xF5uy -> render t rhlp Opcode.CMC SzCond.F64 opNo szDef
  | 0xF8uy -> render t rhlp Opcode.CLC SzCond.F64 opNo szDef
  | 0xF9uy -> render t rhlp Opcode.STC SzCond.F64 opNo szDef
  | 0xFAuy -> render t rhlp Opcode.CLI SzCond.F64 opNo szDef
  | 0xFBuy -> render t rhlp Opcode.STI SzCond.F64 opNo szDef
  | 0xFCuy -> render t rhlp Opcode.CLD SzCond.F64 opNo szDef
  | 0xFDuy -> render t rhlp Opcode.STD SzCond.F64 opNo szDef
  | 0x80uy -> parseGrpOp t rhlp OpGroup.G1 opRmImm8 szByte
  | 0x81uy -> parseGrpOp t rhlp OpGroup.G1 opRmImm szDef
  | 0x82uy -> parseGrpOp t rhlp OpGroup.G1Inv64 opRmImm8 szByte
  | 0x83uy -> parseGrpOp t rhlp OpGroup.G1 opRmImm8 szDef
  | 0x8Fuy -> parseGrpOp t rhlp OpGroup.G1A opMem szDef
  | 0xC0uy -> parseGrpOp t rhlp OpGroup.G2 opRmImm8 szByte
  | 0xC1uy -> parseGrpOp t rhlp OpGroup.G2 opRmImm8 szDef
  | 0xD0uy -> parseGrpOp t rhlp OpGroup.G2 opM1 szByte
  | 0xD1uy -> parseGrpOp t rhlp OpGroup.G2 opM1 szDef
  | 0xD2uy -> parseGrpOp t rhlp OpGroup.G2 opRmCL szByte
  | 0xD3uy -> parseGrpOp t rhlp OpGroup.G2 opRmCL szDef
  | 0xF6uy -> parseGrpOp t rhlp OpGroup.G3A opMem szByte
  | 0xF7uy -> parseGrpOp t rhlp OpGroup.G3B opMem szDef
  | 0xFEuy -> parseGrpOp t rhlp OpGroup.G4 opNo szDef
  | 0xFFuy -> parseGrpOp t rhlp OpGroup.G5 opNo szDef
  | 0xC6uy -> parseGrpOp t rhlp OpGroup.G11A opRmImm8 szByte
  | 0xC7uy -> parseGrpOp t rhlp OpGroup.G11B opRmImm szDef
  | 0x0Fuy -> parseTwoByteOpcode t rhlp
  | _ -> raise ParsingFailureException

let parseRegularOpcode t (rhlp: ReadHelper) =
  rhlp.ReadByte () |> pOneByteOpcode t rhlp

let parseMain t rhlp =
  match t.TVEXInfo with
  | Some { VEXType = vt } ->
    if vt &&& VEXType.VEXTwoByteOp = VEXType.VEXTwoByteOp then
      parseTwoByteOpcode t rhlp
    elif vt &&& VEXType.VEXThreeByteOpOne = VEXType.VEXThreeByteOpOne then
      parseThreeByteOp1 t rhlp
    elif vt &&& VEXType.VEXThreeByteOpTwo = VEXType.VEXThreeByteOpTwo then
      parseThreeByteOp2 t rhlp
    else raise ParsingFailureException
  | None -> parseRegularOpcode t rhlp

let parse (reader: BinReader) wordSz addr pos =
  let struct (prefs, nextPos) = parsePrefix reader pos
  let struct (rexPref, nextPos) = parseREX wordSz reader nextPos
  let struct (vInfo, nextPos) = parseVEXInfo wordSz reader nextPos
  let t = newTemporaryInfo prefs rexPref vInfo wordSz
  let rhlp = ReadHelper (reader, addr, pos, nextPos)
  parseMain t rhlp

// vim: set tw=80 sts=2 sw=2:
