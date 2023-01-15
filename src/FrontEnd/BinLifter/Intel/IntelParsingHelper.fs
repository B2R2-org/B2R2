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

namespace B2R2.FrontEnd.BinLifter.Intel

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.Intel
open B2R2.FrontEnd.BinLifter.Intel.Helper
open LanguagePrimitives
open type Opcode

type OD = OprDesc
type internal SZ = SizeKind

module internal ParsingHelper = begin
#if !EMULATION
  let inline ensure32 (rhlp: ReadHelper) =
    if WordSize.is64 rhlp.WordSize then raise ParsingFailureException else ()

  let inline ensure64 (rhlp: ReadHelper) =
    if WordSize.is32 rhlp.WordSize then raise ParsingFailureException else ()

  let inline ensureVEX128 (rhlp: ReadHelper) =
    match rhlp.VEXInfo with
    | Some { VectorLength = 256<rt> } -> raise ParsingFailureException
    | _ -> ()
#endif

  let inline getVVVV b = ~~~ (b >>> 3) &&& 0b01111uy

  let getVPrefs b =
    match b &&& 0b00000011uy with
    | 0b01uy -> Prefix.PrxOPSIZE
    | 0b10uy -> Prefix.PrxREPZ
    | 0b11uy -> Prefix.PrxREPNZ
    | _ -> Prefix.PrxNone

  let getTwoVEXInfo (span: ByteSpan) (rex: byref<REXPrefix>) pos =
    let b = span[pos]
    rex <- rex ||| if (b >>> 7) = 0uy then REXPrefix.REXR else REXPrefix.NOREX
    let vLen = if ((b >>> 2) &&& 0b000001uy) = 0uy then 128<rt> else 256<rt>
    { VVVV = getVVVV b
      VectorLength = vLen
      VEXType = VEXType.VEXTwoByteOp
      VPrefixes = getVPrefs b
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
    else EnumOfValue<int, REXPrefix> (int rex)

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
    | 0b11uy -> raise ParsingFailureException
    | _ -> raise ParsingFailureException

  let getEVEXInfo (span: ByteSpan) (rex: byref<REXPrefix>) pos =
    let b1 = span[pos]
    let b2 = span[pos + 1]
    let l'l = span[pos + 2] >>> 5 &&& 0b011uy
    let vLen = getVLen l'l
    let aaa = span[pos + 2] &&& 0b111uy
    let z =
      if (span[pos + 2] >>> 7 &&& 0b1uy) = 0uy then Zeroing
      else Merging
    let b = (span[pos + 2] >>> 4) &&& 0b1uy
    let e = Some { AAA = aaa; Z = z; B = b }
    rex <- rex ||| getVREXPref b1 b2
    { VVVV = getVVVV b2
      VectorLength = vLen
      VEXType = pickVEXType b1 ||| VEXType.EVEX
      VPrefixes = getVPrefs b2
      EVEXPrx = e }

  let exceptionalOperationSize opcode (rhlp: ReadHelper) =
    match opcode with
    | Opcode.PUSH | Opcode.POP -> rhlp.OperationSize <- rhlp.MemEffOprSize
    | Opcode.MOVSB | Opcode.INSB
    | Opcode.STOSB | Opcode.LODSB
    | Opcode.OUTSB | Opcode.SCASB -> rhlp.OperationSize <- 8<rt>
    | Opcode.OUTSW -> rhlp.OperationSize <- 16<rt>
    | Opcode.OUTSD -> rhlp.OperationSize <- 32<rt>
    | _ -> ()

  let inline newInsInfo (rhlp: ReadHelper) opcode oprs =
    IntelInstruction (rhlp.InsAddr,
                      uint32 (rhlp.ParsedLen ()),
                      rhlp.WordSize,
                      rhlp.Prefixes,
                      rhlp.REXPrefix,
                      rhlp.VEXInfo,
                      opcode,
                      oprs,
                      rhlp.OperationSize,
                      rhlp.MemEffAddrSize
                      (* rhlp.GetInsID () *))

  (* Table A-7/15 of Volume 2
     (D8/DC Opcode Map When ModR/M Byte is within 00H to BFH) *)
  let getD8OpWithin00toBF b =
    match getReg b with
    | 0b000 -> FADD
    | 0b001 -> FMUL
    | 0b010 -> FCOM
    | 0b011 -> FCOMP
    | 0b100 -> FSUB
    | 0b101 -> FSUBR
    | 0b110 -> FDIV
    | 0b111 -> FDIVR
    | _ -> raise ParsingFailureException

  let getDCOpWithin00toBF b = getD8OpWithin00toBF b

  (* Table A-8 of Volume 2
     (D8 Opcode Map When ModR/M Byte is Outside 00H to BFH) *)
  let getD8OpcodeOutside00toBF = function
    | b when b >= 0xC0uy && b <= 0xC7uy -> FADD
    | b when b >= 0xC8uy && b <= 0xCFuy -> FMUL
    | b when b >= 0xD0uy && b <= 0xD7uy -> FCOM
    | b when b >= 0xD8uy && b <= 0xDFuy -> FCOMP
    | b when b >= 0xE0uy && b <= 0xE7uy -> FSUB
    | b when b >= 0xE8uy && b <= 0xEFuy -> FSUBR
    | b when b >= 0xF0uy && b <= 0xF7uy -> FDIV
    | b when b >= 0xF8uy && b <= 0xFFuy -> FDIVR
    | _ -> raise ParsingFailureException

  (* Table A-9 of Volume 2
     (D9 Opcode Map When ModR/M Byte is Within 00H to BFH) *)
  let getD9OpWithin00toBF b =
    match getReg b with
    | 0b000 -> FLD
    | 0b010 -> FST
    | 0b011 -> FSTP
    | 0b100 -> FLDENV
    | 0b101 -> FLDCW
    | 0b110 -> FNSTENV
    | 0b111 -> FNSTCW
    | _ -> raise ParsingFailureException

  (* Table A-10 of Volume 2
     (D9 Opcode Map When ModR/M Byte is Outside 00H to BFH) *)
  let getD9OpcodeOutside00toBF = function
    | b when b >= 0xC0uy && b <= 0xC7uy -> FLD
    | b when b >= 0xC8uy && b <= 0xCFuy -> FXCH
    | 0xD0uy -> FNOP
    | 0xE0uy -> FCHS
    | 0xE1uy -> FABS
    | 0xE4uy -> FTST
    | 0xE5uy -> FXAM
    | 0xE8uy -> FLD1
    | 0xE9uy -> FLDL2T
    | 0xEAuy -> FLDL2E
    | 0xEBuy -> FLDPI
    | 0xECuy -> FLDLG2
    | 0xEDuy -> FLDLN2
    | 0xEEuy -> FLDZ
    | 0xF0uy -> F2XM1
    | 0xF1uy -> FYL2X
    | 0xF2uy -> FPTAN
    | 0xF3uy -> FPATAN
    | 0xF4uy -> FXTRACT
    | 0xF5uy -> FPREM1
    | 0xF6uy -> FDECSTP
    | 0xF7uy -> FINCSTP
    | 0xF8uy -> FPREM
    | 0xF9uy -> FYL2XP1
    | 0xFAuy -> FSQRT
    | 0xFBuy -> FSINCOS
    | 0xFCuy -> FRNDINT
    | 0xFDuy -> FSCALE
    | 0xFEuy -> FSIN
    | 0xFFuy -> FCOS
    | _ -> raise ParsingFailureException

  (* Table A-11/19 of Volume 2
     (DA/DE Opcode Map When ModR/M Byte is Within 00H to BFH) *)
  let getDAOpWithin00toBF b =
    match getReg b with
    | 0b000 -> FIADD
    | 0b001 -> FIMUL
    | 0b010 -> FICOM
    | 0b011 -> FICOMP
    | 0b100 -> FISUB
    | 0b101 -> FISUBR
    | 0b110 -> FIDIV
    | 0b111 -> FIDIVR
    | _ -> raise ParsingFailureException

  let getDEOpWithin00toBF b = getDAOpWithin00toBF b

  (* Table A-12 of Volume 2
     (DA Opcode Map When ModR/M Byte is Outside 00H to BFH) *)
  let getDAOpcodeOutside00toBF = function
    | b when b >= 0xC0uy && b <= 0xC7uy -> FCMOVB
    | b when b >= 0xC8uy && b <= 0xCFuy -> FCMOVE
    | b when b >= 0xD0uy && b <= 0xD7uy -> FCMOVBE
    | b when b >= 0xD8uy && b <= 0xDFuy -> FCMOVU
    | 0xE9uy -> FUCOMPP
    | _ -> raise ParsingFailureException

  (* Table A-13 of Volume 2
     (DB Opcode Map When ModR/M Byte is Within 00H to BFH) *)
  let getDBOpWithin00toBF b =
    match getReg b with
    | 0b000 -> FILD
    | 0b001 -> FISTTP
    | 0b010 -> FIST
    | 0b011 -> FISTP
    | 0b101 -> FLD
    | 0b111 -> FSTP
    | _ -> raise ParsingFailureException

  (* Table A-14 of Volume 2
     (DB Opcode Map When ModR/M Byte is Outside 00H to BFH) *)
  let getDBOpcodeOutside00toBF = function
    | b when b >= 0xC0uy && b <= 0xC7uy -> FCMOVNB
    | b when b >= 0xC8uy && b <= 0xCFuy -> FCMOVNE
    | b when b >= 0xD0uy && b <= 0xD7uy -> FCMOVNBE
    | b when b >= 0xD8uy && b <= 0xDFuy -> FCMOVNU
    | b when b >= 0xE8uy && b <= 0xEFuy -> FUCOMI
    | b when b >= 0xF0uy && b <= 0xF7uy -> FCOMI
    | 0xE2uy -> FCLEX
    | 0xE3uy -> FINIT
    | _ -> raise ParsingFailureException

  (* Table A-16 of Volume 2
     (DC Opcode Map When ModR/M Byte is Outside 00H to BFH) *)
  let getDCOpcodeOutside00toBF = function
    | b when b >= 0xC0uy && b <= 0xC7uy -> FADD
    | b when b >= 0xC8uy && b <= 0xCFuy -> FMUL
    | b when b >= 0xE0uy && b <= 0xE7uy -> FSUBR
    | b when b >= 0xE8uy && b <= 0xEFuy -> FSUB
    | b when b >= 0xF0uy && b <= 0xF7uy -> FDIVR
    | b when b >= 0xF8uy && b <= 0xFFuy -> FDIV
    | _ -> raise ParsingFailureException

  (* Table A-17 of Volume 2
     (DD Opcode Map When ModR/M Byte is Within 00H to BFH) *)
  let getDDOpWithin00toBF b =
    match getReg b with
    | 0b000 -> FLD
    | 0b001 -> FISTTP
    | 0b010 -> FST
    | 0b011 -> FSTP
    | 0b100 -> FRSTOR
    | 0b110 -> FNSAVE
    | 0b111 -> FNSTSW
    | _ -> raise ParsingFailureException

  (* Table A-18 of Volume 2
     (DD Opcode Map When ModR/M Byte is Outside 00H to BFH) *)
  let getDDOpcodeOutside00toBF b =
    match b with
    | b when b >= 0xC0uy && b <= 0xC7uy -> FFREE
    | b when b >= 0xD0uy && b <= 0xD7uy -> FST
    | b when b >= 0xD8uy && b <= 0xDFuy -> FSTP
    | b when b >= 0xE0uy && b <= 0xE7uy -> FUCOM
    | b when b >= 0xE8uy && b <= 0xEFuy -> FUCOMP
    | _ -> raise ParsingFailureException

  (* Table A-20 of Volume 2
     (DE Opcode Map When ModR/M Byte is Outside 00H to BFH) *)
  let getDEOpcodeOutside00toBF = function
    | b when b >= 0xC0uy && b <= 0xC7uy -> FADDP
    | b when b >= 0xC8uy && b <= 0xCFuy -> FMULP
    | 0xD9uy -> FCOMPP
    | b when b >= 0xE0uy && b <= 0xE7uy -> FSUBRP
    | b when b >= 0xE8uy && b <= 0xEFuy -> FSUBP
    | b when b >= 0xF0uy && b <= 0xF7uy -> FDIVRP
    | b when b >= 0xF8uy && b <= 0xFFuy -> FDIVP
    | _ -> raise ParsingFailureException

  (* Table A-21 of Volume 2
     (DF Opcode Map When ModR/M Byte is Within 00H to BFH) *)
  let getDFOpWithin00toBF b =
    match getReg b with
    | 0b000 -> FILD
    | 0b001 -> FISTTP
    | 0b010 -> FIST
    | 0b011 -> FISTP
    | 0b100 -> FBLD
    | 0b101 -> FILD
    | 0b110 -> FBSTP
    | 0b111 -> FISTP
    | _ -> raise ParsingFailureException

  (* Table A-22 of Volume 2
     (DF Opcode Map When ModR/M Byte is Outside 00H to BFH) *)
  let getDFOpcodeOutside00toBF = function
    | b when b >= 0xC0uy && b <= 0xC7uy ->
      FFREEP (* FIXME: Undocumented x87 instructions *)
    | 0xE0uy -> FNSTSW
    | b when b >= 0xE8uy && b <= 0xEFuy -> FUCOMIP
    | b when b >= 0xF0uy && b <= 0xF7uy -> FCOMIP
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
    let op = getDFOpcodeOutside00toBF b
    if b = 0xE0uy then op, OprReg R.AX |> OneOperand
    elif b >= 0xC0uy && b <= 0xC7uy then op, OneOperand (getRM b |> getSTReg)
    else op, TwoOperands (OprReg R.ST0, getRM b |> getSTReg)

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

  let selectPrefix (rhlp: ReadHelper) =
    match rhlp.VEXInfo with
    | None -> rhlp.Prefixes
    | Some v -> v.VPrefixes

  /// Not Encodable
  let notEn _ = raise ParsingFailureException

  let nor0F10 = function
    | MPref.MPrxNP -> struct (MOVUPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (MOVUPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> struct (MOVSS, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrxF2 -> struct (MOVSD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F10Mem = function
    | MPref.MPrxNP -> struct (VMOVUPS, OD.GprRm, SZ.VecDef) (* VpsWps *)
    | MPref.MPrx66 -> struct (VMOVUPD, OD.GprRm, SZ.VecDef) (* VpdWpd *)
    | MPref.MPrxF3 -> struct (VMOVSS, OD.GprRm, SZ.DqdDq) (* VdqMd *)
    | MPref.MPrxF2 -> struct (VMOVSD, OD.GprRm, SZ.DqqDq) (* VdqMq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F10Reg = function
    | MPref.MPrxNP -> struct (VMOVUPS, OD.GprRm, SZ.VecDef) (* VpsWps *)
    | MPref.MPrx66 -> struct (VMOVUPD, OD.GprRm, SZ.VecDef) (* VpdWpd *)
    | MPref.MPrxF3 -> struct (VMOVSS, OD.XmmVvXm, SZ.VecDef) (* VxHxWss *)
    | MPref.MPrxF2 -> struct (VMOVSD, OD.XmmVvXm, SZ.VecDef) (* VxHxWsd *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F11 = function
    | MPref.MPrxNP -> struct (MOVUPS, OD.RmGpr, SZ.DqDq) (* WdqVdq *)
    | MPref.MPrx66 -> struct (MOVUPD, OD.RmGpr, SZ.DqDq) (* WdqVdq *)
    | MPref.MPrxF3 -> struct (MOVSS, OD.RmGpr, SZ.DqdDqMR) (* WdqdVdq *)
    | MPref.MPrxF2 -> struct (MOVSD, OD.RmGpr, SZ.DqqDq) (* WdqqVdq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F11Mem = function
    | MPref.MPrxNP -> struct (VMOVUPS, OD.RmGpr, SZ.VecDef) (* WpsVps *)
    | MPref.MPrx66 -> struct (VMOVUPD, OD.RmGpr, SZ.VecDef) (* WpdVpd *)
    | MPref.MPrxF3 -> struct (VMOVSS, OD.RmGpr, SZ.DqdDqMR) (* MdVdq *)
    | MPref.MPrxF2 -> struct (VMOVSD, OD.RmGpr, SZ.DqqDq) (* MqVdq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F11Reg = function
    | MPref.MPrxNP -> struct (VMOVUPS, OD.RmGpr, SZ.VecDef) (* WpsVps *)
    | MPref.MPrx66 -> struct (VMOVUPD, OD.RmGpr, SZ.VecDef) (* WpdVpd *)
    | MPref.MPrxF3 -> struct (VMOVSS, OD.XmVvXmm, SZ.VecDef) (* WssHxVss *)
    | MPref.MPrxF2 -> struct (VMOVSD, OD.XmVvXmm, SZ.VecDef) (* WsdHxVsd *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F12Mem = function
    | MPref.MPrxNP -> struct (MOVLPS, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrx66 -> struct (MOVLPD, OD.GprRm, SZ.DqqDq) (* VdqMq *)
    | MPref.MPrxF3 -> struct (MOVSLDUP, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF2 -> struct (MOVDDUP, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F12Reg = function
    | MPref.MPrxNP -> struct (MOVHLPS, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrx66 -> struct (MOVLPD, OD.GprRm, SZ.DqqDq) (* VdqMq *)
    | MPref.MPrxF3 -> struct (MOVSLDUP, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF2 -> struct (MOVDDUP, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F12Mem = function
    | MPref.MPrxNP ->
      struct (VMOVLPS, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrx66 -> struct (VMOVLPD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqMq *)
    | MPref.MPrxF3 -> struct (VMOVSLDUP, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF2 -> struct (VMOVDDUP, OD.GprRm, SZ.XqX) (* VxWxq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F12Reg = function
    | MPref.MPrxNP ->
      struct (VMOVHLPS, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrx66 -> struct (VMOVLPD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqMq *)
    | MPref.MPrxF3 -> struct (VMOVSLDUP, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF2 -> struct (VMOVDDUP, OD.GprRm, SZ.XqX) (* VxWxq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F13 = function
    | MPref.MPrxNP -> struct (MOVLPS, OD.RmGpr, SZ.DqqDq) (* MqVdq *)
    | MPref.MPrx66 -> struct (MOVLPD, OD.RmGpr, SZ.DqqDq) (* MqVdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F13 = function
    | MPref.MPrxNP -> struct (VMOVLPS, OD.RmGpr, SZ.DqqDq) (* MqVdq *)
    | MPref.MPrx66 -> struct (VMOVLPD, OD.RmGpr, SZ.DqqDq) (* MqVdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F14 = function
    | MPref.MPrxNP -> struct (UNPCKLPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (UNPCKLPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F14 = function
    | MPref.MPrxNP ->
      struct (VUNPCKLPS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrx66 ->
      struct (VUNPCKLPD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F15 = function
    | MPref.MPrxNP -> struct (UNPCKHPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (UNPCKHPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F15 = function
    | MPref.MPrxNP ->
      struct (VUNPCKHPS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrx66 ->
      struct (VUNPCKHPD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F16Mem = function
    | MPref.MPrxNP -> struct (MOVHPS, OD.GprRm, SZ.DqqDq) (* VdqMq *)
    | MPref.MPrx66 -> struct (MOVHPD, OD.GprRm, SZ.DqqDq) (* VdqMq *)
    | MPref.MPrxF3 -> struct (MOVSHDUP, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F16Reg = function
    | MPref.MPrxNP -> struct (MOVLHPS, OD.GprRm, SZ.DqDq) (* VdqUdq *)
    | MPref.MPrx66 -> struct (MOVHPD, OD.GprRm, SZ.DqqDq) (* VdqMq *)
    | MPref.MPrxF3 -> struct (MOVSHDUP, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F16Mem = function
    | MPref.MPrxNP -> struct (VMOVHPS, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqMq *)
    | MPref.MPrx66 -> struct (VMOVHPD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqMq *)
    | MPref.MPrxF3 -> struct (VMOVSHDUP, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F16Reg = function
    | MPref.MPrxNP ->
      struct (VMOVLHPS, OD.XmmVvXm, SZ.DqDq) (* VdqHdqUdq *)
    | MPref.MPrx66 ->
      struct (VMOVHPD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqMq *)
    | MPref.MPrxF3 -> struct (VMOVSHDUP, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F17 = function
    | MPref.MPrxNP -> struct (MOVHPS, OD.RmGpr, SZ.DqqDq) (* MqVdq *)
    | MPref.MPrx66 -> struct (MOVHPD, OD.RmGpr, SZ.DqqDq) (* MqVdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F17 = function
    | MPref.MPrxNP -> struct (VMOVHPS, OD.RmGpr, SZ.DqqDq) (* MqVdq *)
    | MPref.MPrx66 -> struct (VMOVHPD, OD.RmGpr, SZ.DqqDq) (* MqVdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F1A = function
    | MPref.MPrxNP -> struct (BNDLDX, OD.BndRm, SZ.VyDq) (* BNMib *)
    | MPref.MPrx66 -> struct (BNDMOV, OD.BndBm, SZ.DqqDqWS) (* BNBNdqq *)
    | MPref.MPrxF3 -> struct (BNDCL, OD.BndRm, SZ.VyDq) (* BNEv *)
    | MPref.MPrxF2 -> struct (BNDCU, OD.BndRm, SZ.VyDq) (* BNEv *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F1B = function
    | MPref.MPrxNP -> struct (BNDSTX, OD.RmBnd, SZ.VyDqMR) (* MibBN *)
    | MPref.MPrx66 -> struct (BNDMOV, OD.BmBnd, SZ.DqqDqWS) (* BNdqqBN *)
    | MPref.MPrxF3 -> struct (BNDMK, OD.BndRm, SZ.VyDq) (* BNMv *)
    | MPref.MPrxF2 -> struct (BNDCN, OD.BndRm, SZ.VyDq) (* BNEv *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F28 = function
    | MPref.MPrxNP -> struct (MOVAPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (MOVAPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F28 = function
    | MPref.MPrxNP -> struct (VMOVAPS, OD.GprRm, SZ.VecDef) (* VpsWps *)
    | MPref.MPrx66 -> struct (VMOVAPD, OD.GprRm, SZ.VecDef) (* VpdWpd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F29 = function
    | MPref.MPrxNP -> struct (MOVAPS, OD.RmGpr, SZ.DqDq) (* WdqVdq *)
    | MPref.MPrx66 -> struct (MOVAPD, OD.RmGpr, SZ.DqDq) (* WdqVdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F29 = function
    | MPref.MPrxNP -> struct (VMOVAPS, OD.RmGpr, SZ.VecDef) (* WpsVps *)
    | MPref.MPrx66 -> struct (VMOVAPD, OD.RmGpr, SZ.VecDef) (* WpdVpd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F2A = function
    | MPref.MPrxNP -> struct (CVTPI2PS, OD.GprRMm, SZ.QDq) (* VdqQpi *)
    | MPref.MPrx66 -> struct (CVTPI2PD, OD.GprRMm, SZ.QDq) (* VdqQpi *)
    | MPref.MPrxF3 -> struct (CVTSI2SS, OD.GprRm, SZ.VyDq) (* VdqEy *)
    | MPref.MPrxF2 -> struct (CVTSI2SD, OD.GprRm, SZ.VyDq) (* VdqEy *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F2A = function
    | MPref.MPrxNP
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 ->
      struct (VCVTSI2SS, OD.XmmVvXm, SZ.VyDq) (* VssHssEy *)
    | MPref.MPrxF2 ->
      struct (VCVTSI2SD, OD.XmmVvXm, SZ.VyDq) (* VsdHsdEy *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F2B = function
    | MPref.MPrxNP -> struct (MOVNTPS, OD.RmGpr, SZ.DqDq) (* MdqVdq *)
    | MPref.MPrx66 -> struct (MOVNTPD, OD.RmGpr, SZ.DqDq) (* MdqVdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F2B = function
    | MPref.MPrxNP -> struct (VMOVNTPS, OD.RmGpr, SZ.VecDef) (* MpsVps *)
    | MPref.MPrx66 -> struct (VMOVNTPD, OD.RmGpr, SZ.VecDef) (* MpdVpd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F2C = function
    | MPref.MPrxNP ->
      struct (CVTTPS2PI, OD.MmxMm, SZ.DqqQ) (* PpiWdqq *)
    | MPref.MPrx66 -> struct (CVTTPD2PI, OD.MmxMm, SZ.DqQ) (* PpiWdq *)
    | MPref.MPrxF3 -> struct (CVTTSS2SI, OD.GprRm, SZ.DqdY) (* GyWdqd *)
    | MPref.MPrxF2 -> struct (CVTTSD2SI, OD.GprRm, SZ.DqqY) (* GyWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F2C = function
    | MPref.MPrxNP
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 -> struct (VCVTTSS2SI, OD.GprRm, SZ.DqdY) (* GyWdqd *)
    | MPref.MPrxF2 -> struct (VCVTTSD2SI, OD.GprRm, SZ.DqqY) (* GyWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F2D = function
    | MPref.MPrxNP -> struct (CVTPS2PI, OD.MmxMm, SZ.DqqQ) (* PpiWdqq *)
    | MPref.MPrx66 -> struct (CVTPD2PI, OD.MmxMm, SZ.DqQ) (* PpiWdq *)
    | MPref.MPrxF3 -> struct (CVTSS2SI, OD.GprRm, SZ.DqdY) (* GyWdqd *)
    | MPref.MPrxF2 -> struct (CVTSD2SI, OD.GprRm, SZ.DqqY) (* GyWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F2D = function
    | MPref.MPrxNP
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 -> struct (VCVTSS2SI, OD.GprRm, SZ.DqdY) (* GyWdqd *)
    | MPref.MPrxF2 -> struct (VCVTSD2SI, OD.GprRm, SZ.DqqY) (* GyWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F2E = function
    | MPref.MPrxNP -> struct (UCOMISS, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrx66 -> struct (UCOMISD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F2E = function
    | MPref.MPrxNP -> struct (VUCOMISS, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrx66 -> struct (VUCOMISD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F2F = function
    | MPref.MPrxNP -> struct (COMISS, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrx66 -> struct (COMISD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F2F = function
    | MPref.MPrxNP -> struct (VCOMISS, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrx66 -> struct (VCOMISD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F50 = function
    | MPref.MPrxNP -> struct (MOVMSKPS, OD.GprRm, SZ.DqY) (* GyUdq *)
    | MPref.MPrx66 -> struct (MOVMSKPD, OD.GprRm, SZ.DqY) (* GyUdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F50 = function
    | MPref.MPrxNP -> struct (VMOVMSKPS, OD.GprRm, SZ.DqY) (* GyUdq *)
    | MPref.MPrx66 -> struct (VMOVMSKPD, OD.GprRm, SZ.DqY) (* GyUdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F51 = function
    | MPref.MPrxNP -> struct (SQRTPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (SQRTPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> struct (SQRTSS, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrxF2 -> struct (SQRTSD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F51 = function
    | MPref.MPrxNP -> struct (VSQRTPS, OD.GprRm, SZ.VecDef) (* VpsWps *)
    | MPref.MPrx66 -> struct (VSQRTPD, OD.GprRm, SZ.VecDef) (* VpdWpd *)
    | MPref.MPrxF3 ->
      struct (VSQRTSS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF2 ->
      struct (VSQRTSD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F52 = function
    | MPref.MPrxNP -> struct (RSQRTPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 -> struct (RSQRTSS, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F52 = function
    | MPref.MPrxNP -> struct (VRSQRTPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 ->
      struct (VRSQRTSS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd*)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F53 = function
    | MPref.MPrxNP -> struct (RCPPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 -> struct (RCPSS, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F53 = function
    | MPref.MPrxNP -> struct (VRCPPS, OD.GprRm, SZ.VecDef) (* VxHx *)
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 ->
      struct (VRCPSS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F54 = function
    | MPref.MPrxNP -> struct (ANDPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (ANDPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F54 = function
    | MPref.MPrxNP ->
      struct (VANDPS, OD.XmmVvXm, SZ.VecDef) (* VpsHpsWps *)
    | MPref.MPrx66 ->
      struct (VANDPD, OD.XmmVvXm, SZ.VecDef) (* VpdHpdWpd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F55 = function
    | MPref.MPrxNP -> struct (ANDNPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (ANDNPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F55 = function
    | MPref.MPrxNP ->
      struct (VANDNPS, OD.XmmVvXm, SZ.VecDef) (* VpsHpsWps *)
    | MPref.MPrx66 ->
      struct (VANDNPD, OD.XmmVvXm, SZ.VecDef) (* VpdHpdWpd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F56 = function
    | MPref.MPrxNP -> struct (ORPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (ORPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F56 = function
    | MPref.MPrxNP -> struct (VORPS, OD.XmmVvXm, SZ.VecDef) (* VpsHpsWps *)
    | MPref.MPrx66 -> struct (VORPD, OD.XmmVvXm, SZ.VecDef) (* VpdHpdWpd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F57 = function
    | MPref.MPrxNP -> struct (XORPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (XORPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F57 = function
    | MPref.MPrxNP ->
      struct (VXORPS, OD.XmmVvXm, SZ.VecDef) (* VpsHpsWps *)
    | MPref.MPrx66 ->
      struct (VXORPD, OD.XmmVvXm, SZ.VecDef) (* VpdHpdWpd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F58 = function
    | MPref.MPrxNP -> struct (ADDPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (ADDPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> struct (ADDSS, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrxF2 -> struct (ADDSD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F58 = function
    | MPref.MPrxNP ->
      struct (VADDPS, OD.XmmVvXm, SZ.VecDef) (* VpsHpsWps *)
    | MPref.MPrx66 ->
      struct (VADDPD, OD.XmmVvXm, SZ.VecDef) (* VpdHpdWpd *)
    | MPref.MPrxF3 ->
      struct (VADDSS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF2 ->
      struct (VADDSD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F59 = function
    | MPref.MPrxNP -> struct (MULPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (MULPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> struct (MULSS, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrxF2 -> struct (MULSD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F59 = function
    | MPref.MPrxNP ->
      struct (VMULPS, OD.XmmVvXm, SZ.VecDef) (* VpsHpsWps *)
    | MPref.MPrx66 ->
      struct (VMULPD, OD.XmmVvXm, SZ.VecDef) (* VpdHpdWpd *)
    | MPref.MPrxF3 ->
      struct (VMULSS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF2 ->
      struct (VMULSD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F5A = function
    | MPref.MPrxNP -> struct (CVTPS2PD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrx66 -> struct (CVTPD2PS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> struct (CVTSS2SD, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrxF2 -> struct (CVTSD2SS, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F5A = function
    | MPref.MPrxNP ->
      struct (VCVTPS2PD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrx66 -> struct (VCVTPD2PS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 ->
      struct (VCVTSS2SD, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF2 ->
      struct (VCVTSD2SS, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F5AW0 = function
    | MPref.MPrxNP -> struct (VCVTPS2PD, OD.GprRm, SZ.XqXz) (* VZxzWxq *)
    | MPref.MPrx66
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F5AW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VCVTPD2PS, OD.GprRm, SZ.XzX) (* VxWZxz *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F5B = function
    | MPref.MPrxNP -> struct (CVTDQ2PS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (CVTPS2DQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> struct (CVTTPS2DQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F5B = function
    | MPref.MPrxNP -> struct (VCVTDQ2PS, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 -> struct (VCVTTPS2DQ, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F5C = function
    | MPref.MPrxNP -> struct (SUBPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (SUBPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> struct (SUBSS, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrxF2 -> struct (SUBSD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F5C = function
    | MPref.MPrxNP ->
      struct (VSUBPS, OD.XmmVvXm, SZ.VecDef) (* VpsHpsWps *)
    | MPref.MPrx66 ->
      struct (VSUBPD, OD.XmmVvXm, SZ.VecDef) (* VpdHpdWpd *)
    | MPref.MPrxF3 ->
      struct (VSUBSS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF2 ->
      struct (VSUBSD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F5D = function
    | MPref.MPrxNP -> struct (MINPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (MINPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> struct (MINSS, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrxF2 -> struct (MINSD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F5D = function
    | MPref.MPrxNP ->
      struct (VMINPS, OD.XmmVvXm, SZ.VecDef) (* VpsHpsWps *)
    | MPref.MPrx66 ->
      struct (VMINPD, OD.XmmVvXm, SZ.VecDef) (* VpdHpdWpd *)
    | MPref.MPrxF3 ->
      struct (VMINSS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF2 ->
      struct (VMINSD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F5DW0 = function
    | MPref.MPrxNP
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 ->
      struct (VMINSS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F5E = function
    | MPref.MPrxNP -> struct (DIVPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (DIVPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> struct (DIVSS, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrxF2 -> struct (DIVSD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F5E = function
    | MPref.MPrxNP ->
      struct (VDIVPS, OD.XmmVvXm, SZ.VecDef) (* VpsHpsWps *)
    | MPref.MPrx66 ->
      struct (VDIVPD, OD.XmmVvXm, SZ.VecDef) (* VpdHpdWpd *)
    | MPref.MPrxF3 ->
      struct (VDIVSS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF2 ->
      struct (VDIVSD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F5F = function
    | MPref.MPrxNP -> struct (MAXPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (MAXPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> struct (MAXSS, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrxF2 -> struct (MAXSD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F5F = function
    | MPref.MPrxNP ->
      struct (VMAXPS, OD.XmmVvXm, SZ.VecDef) (* VpsHpsWps *)
    | MPref.MPrx66 ->
      struct (VMAXPD, OD.XmmVvXm, SZ.VecDef) (* VpdHpdWpd *)
    | MPref.MPrxF3 ->
      struct (VMAXSS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF2 ->
      struct (VMAXSD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F5FW0 = function
    | MPref.MPrxNP -> struct (VMAXPS, OD.XmmVvXm, SZ.XzXz) (* VZxzHxWZxz *)
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 ->
      struct (VMAXSS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F5FW1 = function
    | MPref.MPrxNP
    | MPref.MPrx66
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 ->
      struct (VMAXSD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F60 = function
    | MPref.MPrxNP -> struct (PUNPCKLBW, OD.MmxRm, SZ.DQ) (* PqQd *)
    | MPref.MPrx66 -> struct (PUNPCKLBW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F60 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPUNPCKLBW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F61 = function
    | MPref.MPrxNP -> struct (PUNPCKLWD, OD.MmxRm, SZ.DQ) (* PqQd *)
    | MPref.MPrx66 -> struct (PUNPCKLWD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F61 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPUNPCKLWD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F62 = function
    | MPref.MPrxNP -> struct (PUNPCKLDQ, OD.MmxRm, SZ.DQ) (* PqQd *)
    | MPref.MPrx66 -> struct (PUNPCKLDQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F62 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPUNPCKLDQ, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F63 = function
    | MPref.MPrxNP -> struct (PACKSSWB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PACKSSWB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F63 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPACKSSWB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F64 = function
    | MPref.MPrxNP -> struct (PCMPGTB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PCMPGTB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F64 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPCMPGTB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F65 = function
    | MPref.MPrxNP -> struct (PCMPGTW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PCMPGTW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F65 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPCMPGTW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F66 = function
    | MPref.MPrxNP -> struct (PCMPGTD, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PCMPGTD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F66 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPCMPGTD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F67 = function
    | MPref.MPrxNP -> struct (PACKUSWB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PACKUSWB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F67 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPACKUSWB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F68 = function
    | MPref.MPrxNP -> struct (PUNPCKHBW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PUNPCKHBW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F68 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPUNPCKHBW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F69 = function
    | MPref.MPrxNP -> struct (PUNPCKHWD, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PUNPCKHWD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F69 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPUNPCKHWD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F6A = function
    | MPref.MPrxNP -> struct (PUNPCKHDQ, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PUNPCKHDQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F6A = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPUNPCKHDQ, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F6B = function
    | MPref.MPrxNP -> struct (PACKSSDW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PACKSSDW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F6B = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPACKSSDW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F6C = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PUNPCKLQDQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F6C = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPUNPCKLQDQ, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F6D = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PUNPCKHQDQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F6D = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPUNPCKHQDQ, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F6EW1 = function
    | MPref.MPrxNP -> struct (MOVQ, OD.MmxMm, SZ.YQRM) (* PqEy *)
    | MPref.MPrx66 -> struct (MOVQ, OD.GprRm, SZ.VyDq) (* VdqEy *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F6EW0 = function
    | MPref.MPrxNP -> struct (MOVD, OD.MmxMm, SZ.YQRM) (* PqEy *)
    | MPref.MPrx66 -> struct (MOVD, OD.GprRm, SZ.VyDq) (* VdqEy *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F6EW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VMOVQ, OD.GprRm, SZ.VyDq) (* VdqEy *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F6EW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VMOVD, OD.GprRm, SZ.VyDq) (* VdqEy *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F6F = function
    | MPref.MPrxNP -> struct (MOVQ, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (MOVDQA, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> struct (MOVDQU, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F6F = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VMOVDQA, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF3 -> struct (VMOVDQU, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F6FW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VMOVDQA64, OD.GprRm, SZ.VecDef) (* VZxzWZxz *)
    | MPref.MPrxF3 ->
      struct (VMOVDQU64, OD.GprRm, SZ.VecDef) (* VZxzWZxz *)
    | MPref.MPrxF2 ->
      struct (VMOVDQU16, OD.GprRm, SZ.VecDef) (* VZxzWZxz *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F6FW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VMOVDQA32, OD.GprRm, SZ.VecDef) (* VZxzWZxz *)
    | MPref.MPrxF3 ->
      struct (VMOVDQU32, OD.GprRm, SZ.VecDef) (* VZxzWZxz *)
    | MPref.MPrxF2 -> struct (VMOVDQU8, OD.GprRm, SZ.VecDef) (* VZxzWZxz *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F70 = function
    | MPref.MPrxNP -> struct (PSHUFW, OD.MmxMmImm8, SZ.QQ) (* PqQqIb *)
    | MPref.MPrx66 -> struct (PSHUFD, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF3 ->
      struct (PSHUFHW, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF2 ->
      struct (PSHUFLW, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F70 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPSHUFD, OD.XmmRmImm8, SZ.VecDef) (* VxWxIb *)
    | MPref.MPrxF3 ->
      struct (VPSHUFHW, OD.XmmRmImm8, SZ.VecDef) (* VxWxIb *)
    | MPref.MPrxF2 ->
      struct (VPSHUFLW, OD.XmmRmImm8, SZ.VecDef) (* VxWxIb *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F74 = function
    | MPref.MPrxNP -> struct (PCMPEQB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PCMPEQB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F74 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPCMPEQB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F75 = function
    | MPref.MPrxNP -> struct (PCMPEQW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PCMPEQW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F75 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPCMPEQW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F76 = function
    | MPref.MPrxNP -> struct (PCMPEQD, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PCMPEQD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F76 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPCMPEQD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F77 = function
    | MPref.MPrxNP -> struct (EMMS, OD.No, SZ.Def) (* NoOpr *)
    | MPref.MPrx66
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F77 = function
    | MPref.MPrxNP -> struct (VZEROUPPER, OD.No, SZ.Def) (* NoOpr *)
    | MPref.MPrx66
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F78 = function
    | MPref.MPrxNP -> struct (VMREAD, OD.RmGpr, SZ.Y) (* EyGy *)
    | MPref.MPrx66 -> (* FIXME: Undocumented instruction *)
      struct (EXTRQ, OD.RmImm8Imm8, SZ.Dq) (* VdqUdqIbIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 -> (* FIXME: Undocumented instruction *)
      struct (INSERTQ, OD.GprRmImm8Imm8, SZ.Dq) (* VdqUdqIbIb *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F78W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VCVTTPS2UQQ, OD.GprRm, SZ.XqXz) (* VZxzWxq *)
    | MPref.MPrxF3 -> struct (VCVTTSS2USI, OD.GprRm, SZ.DqdY) (* VdWdqq *)
    | MPref.MPrxF2 -> struct (VCVTTSD2USI, OD.GprRm, SZ.DqqY) (* VqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F78W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VCVTTPD2UQQ, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF3 -> struct (VCVTTSS2USI, OD.GprRm, SZ.DqdY) (* VdWdqq *)
    | MPref.MPrxF2 -> struct (VCVTTSD2USI, OD.GprRm, SZ.DqqY) (* VqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F7AW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VCVTTPS2QQ, OD.GprRm, SZ.XqX) (* VxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2 -> raise ParsingFailureException
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F7AW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VCVTTPD2QQ, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF3 -> struct (VCVTUQQ2PD, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF2 -> raise ParsingFailureException
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F7BW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 ->
      struct (VCVTUSI2SS, OD.XmmVvXm, SZ.DDq) (* VdqHdqWd *)
    | MPref.MPrxF2 ->
      struct (VCVTUSI2SD, OD.XmmVvXm, SZ.DDq) (* VdqHdqWd *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F7BW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 ->
      struct (VCVTUSI2SS, OD.XmmVvXm, SZ.QDq) (* VdqHdqWq *)
    | MPref.MPrxF2 ->
      struct (VCVTUSI2SD, OD.XmmVvXm, SZ.QDq) (* VdqHdqWq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F7C = function
    | MPref.MPrxNP  -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (HADDPD, OD.GprRm, SZ.Dq)
    | MPref.MPrxF3
    | MPref.MPrxF2 -> struct (HADDPS, OD.GprRm, SZ.Dq)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F7C = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VHADDPD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 ->
      struct (VHADDPS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F7D = function
    | MPref.MPrxNP  -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (HSUBPD, OD.GprRm, SZ.Dq)
    | MPref.MPrxF3
    | MPref.MPrxF2 -> struct (HSUBPS, OD.GprRm, SZ.Dq)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F7D = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VHSUBPD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 ->
      struct (VHSUBPS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F7EW1 = function
    | MPref.MPrxNP -> struct (MOVQ, OD.RMMmx, SZ.YQ) (* EyPq *)
    | MPref.MPrx66 -> struct (MOVQ, OD.RmGpr, SZ.VyDqMR) (* EyVdq *)
    | MPref.MPrxF3 -> struct (MOVQ, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F7EW0 = function
    | MPref.MPrxNP -> struct (MOVD, OD.RMMmx, SZ.YQ) (* EyPq *)
    | MPref.MPrx66 -> struct (MOVD, OD.RmGpr, SZ.VyDqMR) (* EyVdq *)
    | MPref.MPrxF3 -> struct (MOVQ, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F7EW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VMOVQ, OD.RmGpr, SZ.VyDqMR) (* EyVdq *)
    | MPref.MPrxF3 -> struct (VMOVQ, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F7EW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VMOVD, OD.RmGpr, SZ.VyDqMR) (* EyVdq *)
    | MPref.MPrxF3 -> struct (VMOVQ, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F7F = function
    | MPref.MPrxNP -> struct (MOVQ, OD.MmMmx, SZ.QQ) (* QqPq *)
    | MPref.MPrx66 -> struct (MOVDQA, OD.RmGpr, SZ.DqDq) (* WdqVdq *)
    | MPref.MPrxF3 -> struct (MOVDQU, OD.RmGpr, SZ.DqDq) (* WdqVdq *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F7F = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VMOVDQA, OD.RmGpr, SZ.VecDef) (* WxVx *)
    | MPref.MPrxF3 -> struct (VMOVDQU, OD.RmGpr, SZ.VecDef) (* WxVx *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F7FW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VMOVDQA64, OD.RmGpr, SZ.VecDef) (* WZxzVZxz *)
    | MPref.MPrxF3 ->
      struct (VMOVDQU64, OD.RmGpr, SZ.VecDef) (* WZxzVZxz *)
    | MPref.MPrxF2 ->
      struct (VMOVDQU16, OD.RmGpr, SZ.VecDef) (* WZxzVZxz *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F7FW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VMOVDQA32, OD.RmGpr, SZ.VecDef) (* WZxzVZxz *)
    | MPref.MPrxF3 ->
      struct (VMOVDQU32, OD.RmGpr, SZ.VecDef) (* WZxzVZxz *)
    | MPref.MPrxF2 ->
      struct (VMOVDQU8, OD.RmGpr, SZ.VecDef) (* WZxzVZxz *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FC2 = function
    | MPref.MPrxNP ->
      struct (CMPPS, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrx66 ->
      struct (CMPPD, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF3 ->
      struct (CMPSS, OD.XmmRmImm8, SZ.DqdDq) (* VdqWdqdIb *)
    | MPref.MPrxF2 ->
      struct (CMPSD, OD.XmmRmImm8, SZ.DqqDq) (* VdqWdqqIb *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FC2 = function
    | MPref.MPrxNP ->
      struct (VCMPPS, OD.XmmVvXmImm8, SZ.VecDef) (* VpsHpsWpsIb *)
    | MPref.MPrx66 ->
      struct (VCMPPD, OD.XmmVvXmImm8, SZ.VecDef) (* VpdHpdWpdIb *)
    | MPref.MPrxF3 ->
      struct (VCMPSS, OD.XmmVvXmImm8, SZ.VecDef) (* VssHssWssIb *)
    | MPref.MPrxF2 ->
      struct (VCMPSD, OD.XmmVvXmImm8, SZ.VecDef) (* VsdHsdWsdIb *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0FC2W0 = function
    | MPref.MPrxNP ->
      struct (VCMPPS, OD.KnVvXmImm8, SZ.XzXz) (* KnHxWxIb *)
    | MPref.MPrx66
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0FC2W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VCMPPD, OD.KnVvXmImm8, SZ.XzXz) (* KnHxWxIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FC4 = function
    | MPref.MPrxNP -> struct (PINSRW, OD.MmxRmImm8, SZ.DwQ) (* PqEdwIb *)
    | MPref.MPrx66 ->
      struct (PINSRW, OD.XmmRmImm8, SZ.DwDq) (* VdqEdwIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FC4 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPINSRW, OD.XmmVvXmImm8, SZ.DwDq) (* VdqHdqEdwIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FC5 = function
    | MPref.MPrxNP -> struct (PEXTRW, OD.GprMmxImm8, SZ.QD) (* GdNqIb *)
    | MPref.MPrx66 -> struct (PEXTRW, OD.XmmRmImm8, SZ.Dqd) (* GdUdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FC5 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPEXTRW, OD.XmmRmImm8, SZ.Dqd) (* GdUdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FC6 = function
    | MPref.MPrxNP -> struct (SHUFPS, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrx66 -> struct (SHUFPD, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FC6 = function
    | MPref.MPrxNP ->
      struct (VSHUFPS, OD.XmmVvXmImm8, SZ.VecDef) (* VpsHpsWpsIb *)
    | MPref.MPrx66 ->
      struct (VSHUFPD, OD.XmmVvXmImm8, SZ.VecDef) (* VpdHpdWpdIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FD0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (ADDSUBPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 -> struct (ADDSUBPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FD0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VADDSUBPD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 ->
      struct (VADDSUBPS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FD1 = function
    | MPref.MPrxNP -> struct (PSRLW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PSRLW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FD1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSRLW, OD.XmmVvXm, SZ.DqX) (* VxHxWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FD2 = function
    | MPref.MPrxNP -> struct (PSRLD, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PSRLD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FD2 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSRLD, OD.XmmVvXm, SZ.DqX) (* VxHxWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FD3 = function
    | MPref.MPrxNP -> struct (PSRLQ, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PSRLQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FD3 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSRLQ, OD.XmmVvXm, SZ.DqX) (* VxHxWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FD4 = function
    | MPref.MPrxNP -> struct (PADDQ, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PADDQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FD4 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPADDQ, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FD5 = function
    | MPref.MPrxNP -> struct (PMULLW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PMULLW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FD5 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPMULLW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FD6 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (MOVQ, OD.RmGpr, SZ.DqqDq) (* WdqqVdq *)
    | MPref.MPrxF3 -> struct (MOVQ2DQ, OD.GprRMm, SZ.QDq) (* VdqNq *)
    | MPref.MPrxF2 -> struct (MOVDQ2Q, OD.MmxMm, SZ.DqQ) (* PqUdq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FD6 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VMOVQ, OD.RmGpr, SZ.DqqDq) (* WdqqVdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FD7 = function
    | MPref.MPrxNP -> struct (PMOVMSKB, OD.GprRMm, SZ.QD) (* GdNq *)
    | MPref.MPrx66 -> struct (PMOVMSKB, OD.GprRm, SZ.Dqd) (* GdUdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FD7 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPMOVMSKB, OD.GprRm, SZ.XD) (* GdUx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FD8 = function
    | MPref.MPrxNP -> struct (PSUBUSB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PSUBUSB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FD8 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSUBUSB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FD9 = function
    | MPref.MPrxNP -> struct (PSUBUSW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PSUBUSW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FD9 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSUBUSW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FDA = function
    | MPref.MPrxNP -> struct (PMINUB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PMINUB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FDA = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPMINUB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FDB = function
    | MPref.MPrxNP -> struct (PAND, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PAND, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FDB = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPAND, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FDC = function
    | MPref.MPrxNP -> struct (PADDUSB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PADDUSB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FDC = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPADDUSB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FDD = function
    | MPref.MPrxNP -> struct (PADDUSW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PADDUSW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FDD = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPADDUSW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FDE = function
    | MPref.MPrxNP -> struct (PMAXUB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PMAXUB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FDE = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPMAXUB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FDF = function
    | MPref.MPrxNP -> struct (PANDN, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PANDN, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FDF = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPANDN, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FE0 = function
    | MPref.MPrxNP -> struct (PAVGB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PAVGB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FE0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPAVGB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FE1 = function
    | MPref.MPrxNP -> struct (PSRAW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PSRAW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FE1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSRAW, OD.XmmVvXm, SZ.DqX) (* VxHxWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FE2 = function
    | MPref.MPrxNP -> struct (PSRAD, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PSRAD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FE2 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSRAD, OD.XmmVvXm, SZ.DqX) (* VxHxWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FE3 = function
    | MPref.MPrxNP -> struct (PAVGW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PAVGW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FE3 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPAVGW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FE4 = function
    | MPref.MPrxNP -> struct (PMULHUW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PMULHUW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FE4 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPMULHUW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FE5 = function
    | MPref.MPrxNP -> struct (PMULHW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PMULHW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FE5 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPMULHW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FE6 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (CVTTPD2DQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> struct (CVTDQ2PD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrxF2 -> struct (CVTPD2DQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FE6 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VCVTTPD2DQ, OD.GprRm, SZ.DqX) (* VdqWx *)
    | MPref.MPrxF3 -> struct (VCVTDQ2PD, OD.GprRm, SZ.DqqdqX) (* VxWdqqdq *)
    | MPref.MPrxF2 -> struct (VCVTPD2DQ, OD.GprRm, SZ.DqX) (* VdqWpd *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0FE6W0 = function
    | MPref.MPrxNP
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 -> struct (VCVTDQ2PD, OD.GprRm, SZ.XXz) (* VZxzWx *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0FE6W1 = function
    | MPref.MPrxNP
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 -> struct (VCVTQQ2PD, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FE7 = function
    | MPref.MPrxNP -> struct (MOVNTQ, OD.RMMmx, SZ.QQ) (* MqPq *)
    | MPref.MPrx66 -> struct (MOVNTDQ, OD.RmGpr, SZ.DqDq) (* MdqVdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FE7 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VMOVNTDQ, OD.RmGpr, SZ.VecDef) (* MxVx *)
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
    | MPref.MPrx66 -> struct (VMOVNTDQ, OD.RmGpr, SZ.VecDef) (* MZxzVZxz *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FE8 = function
    | MPref.MPrxNP -> struct (PSUBSB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PSUBSB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FE8 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSUBSB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FE9 = function
    | MPref.MPrxNP -> struct (PSUBSW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PSUBSW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FE9 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSUBSW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FEA = function
    | MPref.MPrxNP -> struct (PMINSW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PMINSW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FEA = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPMINSW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FEB = function
    | MPref.MPrxNP -> struct (POR, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (POR, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FEB = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPOR, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FEC = function
    | MPref.MPrxNP -> struct (PADDSB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PADDSB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FEC = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPADDSB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FED = function
    | MPref.MPrxNP -> struct (PADDSW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PADDSW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FED = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPADDSW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FEE = function
    | MPref.MPrxNP -> struct (PMAXSW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PMAXSW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FEE = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPMAXSW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FEF = function
    | MPref.MPrxNP -> struct (PXOR, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PXOR, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FEF = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPXOR, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0FEFW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPXORD, OD.XmmVvXm, SZ.XzXz) (* VZxzHxWZxz *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0FEFW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPXORQ, OD.XmmVvXm, SZ.XzXz) (* VZxzHxWZxz *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FF0 = function
    | MPref.MPrxNP
    | MPref.MPrx66
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 -> struct (LDDQU, OD.GprRm, SZ.DqDq) (* VdqMdq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FF0 = function
    | MPref.MPrxNP
    | MPref.MPrx66
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 -> struct (VLDDQU, OD.GprRm, SZ.VecDef) (* VxMx *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FF1 = function
    | MPref.MPrxNP -> struct (PSLLW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PSLLW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FF1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSLLW, OD.XmmVvXm, SZ.DqX) (* VxHxWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FF2 = function
    | MPref.MPrxNP -> struct (PSLLD, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PSLLD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FF2 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSLLD, OD.XmmVvXm, SZ.DqX) (* VxHxWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FF3 = function
    | MPref.MPrxNP -> struct (PSLLQ, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PSLLQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FF3 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSLLQ, OD.XmmVvXm, SZ.DqX) (* VxHxWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FF4 = function
    | MPref.MPrxNP -> struct (PMULUDQ, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PMULUDQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FF4 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPMULUDQ, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FF5 = function
    | MPref.MPrxNP -> struct (PMADDWD, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PMADDWD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FF5 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPMADDWD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FF6 = function
    | MPref.MPrxNP -> struct (PSADBW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PSADBW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FF6 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSADBW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FF8 = function
    | MPref.MPrxNP -> struct (PSUBB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PSUBB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FF8 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSUBB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FF9 = function
    | MPref.MPrxNP -> struct (PSUBW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PSUBW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FF9 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSUBW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FFA = function
    | MPref.MPrxNP -> struct (PSUBD, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PSUBD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FFA = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSUBD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FFB = function
    | MPref.MPrxNP -> struct (PSUBQ, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PSUBQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FFB = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSUBQ, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FFC = function
    | MPref.MPrxNP -> struct (PADDB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PADDB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FFC = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPADDB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FFD = function
    | MPref.MPrxNP -> struct (PADDW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PADDW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FFD = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPADDW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FFE = function
    | MPref.MPrxNP -> struct (PADDD, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PADDD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FFE = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPADDD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3800 = function
    | MPref.MPrxNP -> struct (PSHUFB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PSHUFB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3800 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSHUFB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3801 = function
    | MPref.MPrxNP -> struct (PHADDW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PHADDW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3801 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPHADDW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3802 = function
    | MPref.MPrxNP -> struct (PHADDD, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PHADDD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3802 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPHADDD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3803 = function
    | MPref.MPrxNP -> struct (PHADDSW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PHADDSW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3804 = function
    | MPref.MPrxNP -> struct (PMADDUBSW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PMADDUBSW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3803 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPHADDSW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3805 = function
    | MPref.MPrxNP -> struct (PHSUBW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PHSUBW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3805 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPHSUBW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3806 = function
    | MPref.MPrxNP -> struct (PHSUBD, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PHSUBD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3806 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPHSUBD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3807 = function
    | MPref.MPrxNP -> struct (PHSUBSW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PHSUBSW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3807 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPHSUBSW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3808 = function
    | MPref.MPrxNP -> struct (PSIGNB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PSIGNB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3808 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSIGNB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3809 = function
    | MPref.MPrxNP -> struct (PSIGNW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PSIGNW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3809 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSIGNW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F380A = function
    | MPref.MPrxNP -> struct (PSIGND, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PSIGND, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F380A = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSIGND, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F380B = function
    | MPref.MPrxNP -> struct (PMULHRSW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PMULHRSW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F380B = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPMULHRSW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F380CW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPERMILPS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3810 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PBLENDVB, OD.XmmXmXmm0, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3814 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (BLENDVPS, OD.XmmXmXmm0, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3814W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPRORVD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3814W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPRORVQ, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3815 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (BLENDVPD, OD.XmmXmXmm0, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3816W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPERMPS, OD.XmmVvXm, SZ.Qq) (* VqqHqqWqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3817 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PTEST, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3817 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPTEST, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3818W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VBROADCASTSS, OD.GprRm, SZ.DX) (* VxMd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3818W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VBROADCASTSS, OD.GprRm, SZ.DqdXz) (* VZxzWdqd *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3819W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VBROADCASTSD, OD.GprRm, SZ.DqqQq) (* VqqWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3819W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VBROADCASTSD, OD.GprRm, SZ.DqqXz) (* VZxzWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F381C = function
    | MPref.MPrxNP -> struct (PABSB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PABSB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F381AW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VBROADCASTF128, OD.GprRm, SZ.DqQq) (* VqqMdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F381C = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPABSB, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F381D = function
    | MPref.MPrxNP -> struct (PABSW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PABSW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F381D = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPABSW, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F381E = function
    | MPref.MPrxNP -> struct (PABSD, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (PABSD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F381E = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPABSD, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F381FW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPABSQ, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3820 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PMOVSXBW, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3820 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPMOVSXBW, OD.GprRm, SZ.DqqdqX) (* VxWdqqdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3821 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PMOVSXBD, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3821 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPMOVSXBD, OD.GprRm, SZ.DqddqX) (* VxWdqdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3822 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PMOVSXBQ, OD.GprRm, SZ.DqwDq) (* VdqWdqw *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3822 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPMOVSXBQ, OD.GprRm, SZ.DqwdX) (* VxWdqwd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3823 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PMOVSXWD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3823 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPMOVSXWD, OD.GprRm, SZ.DqqdqX) (* VxWdqqdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3824 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PMOVSXWQ, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3824 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPMOVSXWQ, OD.GprRm, SZ.DqddqX) (* VxWdqdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3825 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PMOVSXDQ, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3825 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPMOVSXDQ, OD.GprRm, SZ.DqqdqX) (* VxWdqqdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3828 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PMULDQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3828 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPMULDQ, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3829 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PCMPEQQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3829 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPCMPEQQ, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F382AW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 -> struct (VPBROADCASTMB2Q, OD.GprKn, SZ.VecDef) (* VxKn *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F382B = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PACKUSDW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F382B = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPACKUSDW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F382CW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VMASKMOVPS, OD.XmmVvXm, SZ.VecDef) (* VxHxMx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F382CW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VSCALEFPS, OD.XmmVvXm, SZ.VecDef) (* VxHxMx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F382CW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VSCALEFPD, OD.XmmVvXm, SZ.VecDef) (* VxHxMx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F382DW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VMASKMOVPD, OD.XmmVvXm, SZ.VecDef) (* VxHxMx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F382DW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VSCALEFSS, OD.XmmVvXm, SZ.DqdDqMR) (* VdqHdqMd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F382DW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VSCALEFSD, OD.XmmVvXm, SZ.DqqDqMR) (* VdqHdqMq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F382EW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VMASKMOVPS, OD.XmVvXmm, SZ.VecDef) (* MxHxVx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F382FW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VMASKMOVPD, OD.XmVvXmm, SZ.VecDef) (* MxHxVx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3830 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PMOVZXBW, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3830 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPMOVZXBW, OD.GprRm, SZ.DqqdqX) (* VxWdqqdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3830 = function
    | MPref.MPrxNP
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 -> struct (VPMOVWB, OD.RmGpr, SZ.QqXz) (* WqqVZxz *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3831 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PMOVZXBD, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3831 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPMOVZXBD, OD.GprRm, SZ.DqddqX) (* VxWdqdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3832 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PMOVZXBQ, OD.GprRm, SZ.DqwDq) (* VdqWdqw *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3832 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPMOVZXBQ, OD.GprRm, SZ.DqwdX) (* VxWdqwd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3833 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PMOVZXWD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3833 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPMOVZXWD, OD.GprRm, SZ.DqqdqX) (* VxWdqqdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3833 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPMOVZXWD, OD.GprRm, SZ.XqXz) (* VZxzWxq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3834 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PMOVZXWQ, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3834 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPMOVZXWQ, OD.GprRm, SZ.DqddqX) (* VxWdqdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3835 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PMOVZXDQ, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3835 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPMOVZXDQ, OD.GprRm, SZ.DqqdqX) (* VxWdqqdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3836W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPERMD, OD.XmmVvXm, SZ.Qq) (* VqqHqqWqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3837 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PCMPGTQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3837 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPCMPGTQ, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3838 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PMINSB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3838 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPMINSB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3839 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PMINSD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3839 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPMINSD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3839W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 -> struct (VPMOVD2M, OD.KnGpr, SZ.VecDef) (* KnWx *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F383A = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PMINUW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F383A = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPMINUW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F383AW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 -> struct (VPBROADCASTMW2D, OD.GprKn, SZ.VecDef) (* VxKn *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F383B = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PMINUD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F383B = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPMINUD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F383C = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PMAXSB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F383C = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPMAXSB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F383D = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PMAXSD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F383D = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPMAXSD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F383E = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PMAXUW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F383E = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPMAXUW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F383F = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PMAXUD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F383F = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPMAXUD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3840 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PMULLD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3840 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPMULLD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3841 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PHMINPOSUW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3841 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPHMINPOSUW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3843W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VGETEXPSD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3845W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPSRLVD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3845W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPSRLVQ, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3846W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPSRAVD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3847W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPSLLVD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3847W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPSLLVQ, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F384DW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VRCP14SD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3850W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPDPBUSD, OD.XmmVvXm, SZ.VecDef) (* VxHxWdx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3850W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPDPBUSD, OD.XmmVvXm, SZ.VecDef) (* VxHxWdx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3851W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPDPBUSDS, OD.XmmVvXm, SZ.VecDef) (* VxHxWdx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3851W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPDPBUSDS, OD.XmmVvXm, SZ.VecDef) (* VxHxWdx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3852W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPDPWSSD, OD.XmmVvXm, SZ.VecDef) (* VxHxWdx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3852W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPDPWSSD, OD.XmmVvXm, SZ.VecDef) (* VxHxWdx *)
    | MPref.MPrxF3 -> struct (VDPBF16PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF2 -> struct (VP4DPWSSD, OD.XmmVvXm, SZ.XDq) (* VzHzMdq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3853W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPDPWSSDS, OD.XmmVvXm, SZ.VecDef) (* VxHxWdx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3853W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPDPWSSDS, OD.XmmVvXm, SZ.VecDef) (* VxHxWdx *)
    | MPref.MPrxF3
    | MPref.MPrxF2 -> struct (VP4DPWSSDS, OD.XmmVvXm, SZ.XDq) (* VzHzMdq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3854W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPOPCNTB, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3854W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPOPCNTW, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3855W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPOPCNTD, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3855W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPOPCNTQ, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3858W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPBROADCASTD, OD.GprRm, SZ.DqdX) (* VxWdqd *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3858W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPBROADCASTD, OD.GprRm, SZ.DqdXz) (* VZxzWdqd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3859W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPBROADCASTQ, OD.GprRm, SZ.DqqX) (* VxWdqd *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3859W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VBROADCASTI32X2, OD.GprRm, SZ.DqqX) (* VxWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3859W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPBROADCASTQ, OD.GprRm, SZ.DqqXz) (* VZxzWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F385AW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VBROADCASTI128, OD.GprRm, SZ.DqQqq) (* VqqMdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F385AW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VBROADCASTI32X4, OD.GprM, SZ.XDq) (* VxMdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F385AW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VBROADCASTI64X2, OD.GprM, SZ.XDq) (* VxMdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F385BW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VBROADCASTI32X8, OD.GprM, SZ.QqXzRM) (* VdqqMqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F385BW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VBROADCASTI64X4, OD.GprM, SZ.QqXzRM) (* VdqqMqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3862W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPEXPANDB, OD.GprRm, SZ.VecDef) (* VxHx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 -> raise ParsingFailureException
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3862W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPEXPANDW, OD.GprRm, SZ.VecDef) (* VxHx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 -> raise ParsingFailureException
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3863W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPCOMPRESSB, OD.RmGpr, SZ.VecDef) (* VxHx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 -> raise ParsingFailureException
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3863W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPCOMPRESSW, OD.RmGpr, SZ.VecDef) (* VxHx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 -> raise ParsingFailureException
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3868W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 -> struct (VP2INTERSECTD, OD.KnVvXm, SZ.VecDef) (* KnHxWx *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3868W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 -> struct (VP2INTERSECTQ, OD.KnVvXm, SZ.VecDef) (* KnHxWx *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3870W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSHLDVW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3871W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSHLDVD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3871W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSHLDVQ, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3872W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 ->
      struct (VCVTNEPS2BF16, OD.GprRm, SZ.XzX) (* VxWx *)
    | MPref.MPrxF2 ->
      struct (VCVTNE2PS2BF16, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3872W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSHRDVW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3873W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSHRDVD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3873W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSHRDVQ, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3875W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPERMI2W, OD.XmmVvXm, SZ.XzXz) (* VZxzHxWZxz *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3876W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPERMI2D, OD.XmmVvXm, SZ.XzXz) (* VZxzHxWZxz *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3877W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPERMI2PD, OD.XmmVvXm, SZ.XzXz) (* VZxzHxWZxz *)
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
    | MPref.MPrx66 ->
      struct (VPBROADCASTB, OD.GprRm, SZ.DqbX) (* VxWdqb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3879W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPBROADCASTW, OD.GprRm, SZ.DqwX) (* VxWdqw *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F387AW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPBROADCASTB, OD.GprRm, SZ.DXz) (* VZxzRd *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F387BW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPBROADCASTW, OD.GprRm, SZ.DXz) (* VZxzRd *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F387CW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPBROADCASTD, OD.GprRm, SZ.DXz) (* VZxzRd *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F387CW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPBROADCASTQ, OD.GprRm, SZ.QXz) (* VZxzRq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F387DW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPERMT2B, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F387DW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPERMT2W, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3883W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPMULTISHIFTQB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F388CW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPMASKMOVD, OD.XmmVvXm, SZ.VecDef) (* VxHxMx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F388CW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPMASKMOVQ, OD.XmmVvXm, SZ.VecDef) (* VxHxMx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F388DW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPERMB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F388EW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPMASKMOVD, OD.XmVvXmm, SZ.VecDef) (* MxVxHx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F388EW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPMASKMOVQ, OD.XmVvXmm, SZ.VecDef) (* MxVxHx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F388FW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSHUFBITQMB, OD.KnVvXm, SZ.VecDef) (* KnHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3890W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPGATHERDD, OD.XmmXmVv, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3890W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPGATHERDQ, OD.XmmXmVv, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3890W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPGATHERDD, OD.GprRm, SZ.VecDef) (* VZxzWZxz *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3891W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPGATHERQD, OD.XmmVvXm, SZ.Dq) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3891W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPGATHERQQ, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3892W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VGATHERDPS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3892W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VGATHERDPD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3892W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VGATHERDPS, OD.GprRm, SZ.VecDef) (* VZxzWZxz *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3893W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VGATHERQPS, OD.XmmXmVv, SZ.Dq) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3893W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VGATHERQPD, OD.XmmXmVv, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3896W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMADDSUB132PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3896W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMADDSUB132PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3896W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMADDSUB132PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3896W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMADDSUB132PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3897W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMSUBADD132PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3897W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMSUBADD132PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3897W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMSUBADD132PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3897W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMSUBADD132PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3898W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMADD132PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3898W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMADD132PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3898W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMADD132PD, OD.XmmVvXm, SZ.XzXz) (* VZxzHxWZxz *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3899W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMADD132SS, OD.XmmVvXm, SZ.DqdXz) (* VxHxWdqd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3899W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMADD132SD, OD.XmmVvXm, SZ.DqqX) (* VxHxWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F389AW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMSUB132PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F389AW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMSUB132PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F389AW0 = function
    | MPref.MPrxNP
    | MPref.MPrx66
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 -> struct (V4FMADDPS, OD.XmmVvXm, SZ.XDq) (* VzHzMdq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F389BW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMSUB132SS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F389BW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMSUB132SD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F389BW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMSUB132SS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 -> struct (V4FMADDSS, OD.XmmVvXm, SZ.Dq) (* VdqHdqMdq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F389CW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VFNMADD132PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F389CW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VFNMADD132PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F389CW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFNMADD132PD, OD.XmmVvXm, SZ.XzXz) (* VZxzHxWZxz *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F389DW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFNMADD132SS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F389DW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFNMADD132SD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F389DW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFNMADD132SD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F389EW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFNMSUB132PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F389EW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFNMSUB132PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F389FW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFNMSUB132SS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F389FW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFNMSUB132SD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38A2W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VSCATTERDPS, OD.RmGpr, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38A2W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VSCATTERDPD, OD.RmGpr, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38A3W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VSCATTERQPS, OD.RmGpr, SZ.XzX) (* VxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38A3W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VSCATTERQPD, OD.RmGpr, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38A6W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMADDSUB213PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38A6W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMADDSUB213PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38A7W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMSUBADD213PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38A7W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMSUBADD213PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38A8W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMADD213PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38A8W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMADD213PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38A8W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMADD213PS, OD.XmmVvXm, SZ.XzXz) (* VZxzHxWZxz *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38A9W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMADD213SS, OD.XmmVvXm, SZ.DqdXz) (* VxHxWdqd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38A9W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMADD213SD, OD.XmmVvXm, SZ.DqqX) (* VxHxWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38AAW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VFMSUB213PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38AAW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VFMSUB213PD, OD.XmmVvXm, SZ.DqqX) (* VxHxWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38AAW0 = function
    | MPref.MPrxNP
    | MPref.MPrx66
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 -> struct (V4FNMADDPS, OD.XmmVvXm, SZ.DqXz) (* VzHzMdq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38ABW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VFMSUB213SS, OD.XmmVvXm, SZ.DqdX) (* VxHxWdqd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38ABW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VFMSUB213SD, OD.XmmVvXm, SZ.DqqX) (* VxHxWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38ABW0 = function
    | MPref.MPrxNP
    | MPref.MPrx66
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 -> struct (V4FNMADDSS, OD.XmmVvXm, SZ.Dq) (* VdqHdqMdq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38ACW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFNMADD213PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38ACW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFNMADD213PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38ADW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFNMADD213SS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38ADW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFNMADD213SD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38ADW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFNMADD213SD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38AEW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFNMSUB213PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38AEW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFNMSUB213PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38AFW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFNMSUB213SS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38AFW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFNMSUB213SD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38B4W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPMADD52LUQ, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38B5W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPMADD52HUQ, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38B6W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMADDSUB231PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38B6W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMADDSUB231PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38B7W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMSUBADD231PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38B7W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMSUBADD231PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38B8W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMADD231PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38B8W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMADD231PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38B8W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMADD231PD, OD.XmmVvXm, SZ.XzXz) (* VZxzHxWZxz *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38B9W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMADD231SS, OD.XmmVvXm, SZ.DqdXz) (* VxHxWdqd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38B9W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMADD231SD, OD.XmmVvXm, SZ.DqqX) (* VxHxWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38BAW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMSUB231PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38BAW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMSUB231PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38BBW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMSUB231SS, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38BBW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMSUB231SD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38BBW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMSUB231SD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38BCW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFNMADD231PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38BCW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFNMADD231PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38BCW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFNMADD231PD, OD.XmmVvXm, SZ.XzXz) (* VZxzHxWZxz *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38BDW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFNMADD231SS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38BDW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFNMADD231SD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38BDW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFNMADD231SD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38BEW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFNMSUB231PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38BEW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFNMSUB231PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38BFW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFNMSUB231SS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38BFW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFNMSUB231SD, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38C61W0 = function (* C6 /1 *)
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VGATHERPF0DPS, OD.Mem, SZ.VecDef) (* Wdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38C61W1 = function (* C6 /1 *)
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VGATHERPF0DPD, OD.Mem, SZ.Qq) (* Wqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38C62W0 = function (* C6 /2 *)
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VGATHERPF1DPS, OD.Mem, SZ.VecDef) (* Wdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38C62W1 = function (* C6 /2 *)
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VGATHERPF1DPD, OD.Mem, SZ.Qq) (* Wqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38C65W0 = function (* C6 /5 *)
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VSCATTERPF0DPS, OD.Mem, SZ.VecDef) (* Wdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38C65W1 = function (* C6 /5 *)
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VSCATTERPF0DPD, OD.Mem, SZ.Qq) (* Wqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38C66W0 = function (* C6 /6 *)
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VSCATTERPF1DPS, OD.Mem, SZ.VecDef) (* Wdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38C66W1 = function (* C6 /6 *)
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VSCATTERPF1DPD, OD.Mem, SZ.Qq) (* Wqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38C71W0 = function (* C7 /1 *)
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VGATHERPF0QPS, OD.Mem, SZ.VecDef) (* Wdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38C71W1 = function (* C7 /1 *)
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VGATHERPF0QPD, OD.Mem, SZ.VecDef) (* Wdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38C72W0 = function (* C7 /2 *)
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VGATHERPF1QPS, OD.Mem, SZ.VecDef) (* Wdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38C72W1 = function (* C7 /2 *)
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VGATHERPF1QPD, OD.Mem, SZ.VecDef) (* Wdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38C75W0 = function (* C7 /5 *)
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VSCATTERPF0QPS, OD.Mem, SZ.VecDef) (* Wdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38C75W1 = function (* C7 /5 *)
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VSCATTERPF0QPD, OD.Mem, SZ.VecDef) (* Wdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38C76W0 = function (* C7 /6 *)
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VSCATTERPF1QPS, OD.Mem, SZ.VecDef) (* Wdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38C76W1 = function (* C7 /6 *)
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VSCATTERPF1QPD, OD.Mem, SZ.VecDef) (* Wdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38CBW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VRCP28SD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38CDW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VRSQRT28SD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38CFW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VGF2P8MULB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38CFW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VGF2P8MULB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F38DB = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (AESIMC, OD.GprRm, SZ.Dq) (* VxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F38DC = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (AESENC, OD.GprRm, SZ.Dq) (* VxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38DC = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VAESENC, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38DC = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VAESENC, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F38DD = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (AESENCLAST, OD.GprRm, SZ.Dq) (* VxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38DD = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VAESENCLAST, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38DD = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VAESENCLAST, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F38DE = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (AESDEC, OD.GprRm, SZ.Dq) (* VxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38DE = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VAESDEC, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38DE = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VAESDEC, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F38DF = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (AESDECLAST, OD.GprRm, SZ.Dq) (* VdqWdq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38DF = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VAESDECLAST, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38DF = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VAESDECLAST, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F38F0 = function
    | MPref.MPrxNP -> struct (MOVBE, OD.GprRm, SZ.Def) (* GyMy *)
    | MPref.MPrx66 -> struct (MOVBE, OD.GprRm, SZ.Word) (* GwMw *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 -> struct (CRC32, OD.GprRm, SZ.BV) (* GvEb *)
    | MPref.MPrx66F2 -> struct (CRC32, OD.GprRm, SZ.BV) (* GvEb *)
    | _ -> raise ParsingFailureException

  let nor0F38F1 = function
    | MPref.MPrxNP -> struct (MOVBE, OD.RmGpr, SZ.Def) (* MyGy *)
    | MPref.MPrx66 -> struct (MOVBE, OD.RmGpr, SZ.Word) (* MwGw *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 -> struct (CRC32, OD.GprRm, SZ.Def) (* GvEy *)
    | MPref.MPrx66F2 -> struct (CRC32, OD.GprRm, SZ.WV) (* GvEw *)
    | _ -> raise ParsingFailureException

  let vex0F38F2 = function
    | MPref.MPrxNP -> struct (ANDN, OD.GprVvRm, SZ.Def) (* GyByEy *)
    | MPref.MPrx66
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F38F5W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (WRUSSD, OD.MGpr, SZ.Def) (* EyGy *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F38F5W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (WRUSSQ, OD.RmGpr, SZ.Def) (* EyGy *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38F5W0 = function
    | MPref.MPrxNP -> struct (BZHI, OD.GprRmVv, SZ.Def) (* GyEyBy *)
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 -> struct (PEXT, OD.GprVvRm, SZ.Def) (* GyByEy *)
    | MPref.MPrxF2 -> struct (PDEP, OD.GprVvRm, SZ.Def) (* GyByEy *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38F5W1 = function
    | MPref.MPrxNP -> struct (BZHI, OD.GprRmVv, SZ.Def) (* GyEyBy *)
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 -> struct (PEXT, OD.GprVvRm, SZ.Def) (* GyByEy *)
    | MPref.MPrxF2 -> struct (PDEP, OD.GprVvRm, SZ.Def) (* GyByEy *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F38F6W0 = function
    | MPref.MPrxNP -> struct (WRSSD, OD.GprRm, SZ.Def) (* GyEy *)
    | MPref.MPrx66 -> struct (ADCX, OD.GprRm, SZ.Def) (* GyEy *)
    | MPref.MPrxF3 -> struct (ADOX, OD.GprRm, SZ.Def) (* GyEy *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F38F6W1 = function
    | MPref.MPrxNP -> struct (WRSSQ, OD.GprRm, SZ.Def) (* GyEy *)
    | MPref.MPrx66 -> struct (ADCX, OD.GprRm, SZ.Def) (* GyEy *)
    | MPref.MPrxF3 -> struct (ADOX, OD.GprRm, SZ.Def) (* GyEy *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38F6W0 = function
    | MPref.MPrxNP
    | MPref.MPrx66
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 -> struct (MULX, OD.GprVvRm, SZ.Def) (* GyByEy *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38F6W1 = function
    | MPref.MPrxNP
    | MPref.MPrx66
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 -> struct (MULX, OD.GprVvRm, SZ.Def) (* GyByEy *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F38F7 = function
    | MPref.MPrxNP
    | MPref.MPrx66
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38F7 = function
    | MPref.MPrxNP -> struct (BEXTR, OD.GprRmVv, SZ.Def) (* GyEyBy *)
    | MPref.MPrx66 -> struct (SHLX, OD.GprRmVv, SZ.Def) (* GyEyBy *)
    | MPref.MPrxF3 -> struct (SARX, OD.GprRmVv, SZ.Def) (* GyEyBy *)
    | MPref.MPrxF2 -> struct (SHRX, OD.GprRmVv, SZ.Def) (* GyEyBy *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A00W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPERMQ, OD.XmmRmImm8, SZ.Qq) (* VqqWqqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A01W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPERMPD, OD.XmmRmImm8, SZ.Qq) (* VqqWqqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A02W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPBLENDD, OD.XmmVvXmImm8, SZ.VecDef) (* VxVxWxIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A04W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPERMILPS, OD.XmmRmImm8, SZ.VecDef) (* VxWxIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A05W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPERMILPD, OD.XmmRmImm8, SZ.VecDef) (* VxWxIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A06W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPERM2F128, OD.XmmVvXmImm8, SZ.Qq) (* VqqHqqWqqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A08 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (ROUNDPS, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A08 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VROUNDPS, OD.XmmRmImm8, SZ.VecDef) (* VxWxIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A09 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (ROUNDPD, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A09 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VROUNDPD, OD.XmmVvXmImm8, SZ.VecDef) (* VxHxWxIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A0A = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (ROUNDSS, OD.GprRmImm8, SZ.DqdDq) (* VdqWdqdIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A0A = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VROUNDSS, OD.XmmVvXmImm8, SZ.DqdDq) (* VdqHdqWdqdIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A0B = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (ROUNDSD, OD.XmmRmImm8, SZ.DqqDq) (* VdqWdqqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A0B = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VROUNDSD, OD.XmmVvXmImm8, SZ.DqqDq) (* VdqHdqWdqqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A0BW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VRNDSCALESD, OD.XmmVvXmImm8, SZ.DqqDq) (* VdqHdqWdqqIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A0C = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (BLENDPS, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A0D = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (BLENDPD, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A0C = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VBLENDPS, OD.XmmVvXmImm8, SZ.VecDef) (* VxHxWxIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A0D = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VBLENDPD, OD.XmmVvXmImm8, SZ.VecDef) (* VxHxWxIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A0E = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PBLENDW, OD.GprRmImm8, SZ.Dq) (* VxWxIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A0E = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPBLENDW, OD.XmmVvXmImm8, SZ.VecDef) (* VxHxWxIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A0F = function
    | MPref.MPrxNP -> struct (PALIGNR, OD.MmxMmImm8, SZ.QQ) (* PqQqIb *)
    | MPref.MPrx66 ->
      struct (PALIGNR, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A0F = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPALIGNR, OD.XmmVvXmImm8, SZ.VecDef) (* VxHxWxIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A14 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (PEXTRB, OD.XmRegImm8, SZ.DbDq) (* EbVdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A14W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPEXTRB, OD.XmRegImm8, SZ.DbDq) (* EdbVdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A15 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (PEXTRW, OD.XmRegImm8, SZ.DwDq) (* EdwVdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A15 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPEXTRW, OD.XmRegImm8, SZ.DwDq) (* EdwVdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A16W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (PEXTRD, OD.XmRegImm8, SZ.VyDqMR)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A16W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (PEXTRQ, OD.XmRegImm8, SZ.VyDqMR)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A16W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPEXTRD, OD.XmRegImm8, SZ.VyDqMR)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A16W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPEXTRD, OD.XmRegImm8, SZ.VyDqMR)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A17 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (EXTRACTPS, OD.RmXmmImm8, SZ.DDq) (* EdVdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A17 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VEXTRACTPS, OD.RmXmmImm8, SZ.DDq) (* EdVdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A18W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VINSERTF128, OD.XmmVvXmImm8, SZ.DqQqq) (* VqqHqqWdqIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A19W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VEXTRACTF128, OD.XmRegImm8, SZ.DqQq) (* WdqVqqIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A19W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VEXTRACTF32X4, OD.XmRegImm8, SZ.DqXz) (* WdqVZxzIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A19W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VEXTRACTF64X2, OD.XmRegImm8, SZ.DqXz) (* WdqVZxzIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A1AW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VINSERTF64X4, OD.XmmVvXmImm8, SZ.QqXzRM) (* VZxzHxWqqIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A1BW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VEXTRACTF32X8, OD.XmRegImm8, SZ.QqXz) (* WZqqVZxzIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A1BW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VEXTRACTF64X4, OD.XmRegImm8, SZ.QqXz) (* WZqqVZxzIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A1EW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPCMPUD, OD.KnVvXmImm8, SZ.VecDef) (* KnHxWxIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A1EW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPCMPUQ, OD.KnVvXmImm8, SZ.VecDef) (* KnHxWxIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A20 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PINSRB, OD.XmmRmImm8, SZ.DbDq) (* VdqEdbIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A20 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPINSRB, OD.XmmVvXmImm8, SZ.DbDq) (* VdqHdqEdbIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A21 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (INSERTPS, OD.GprRmImm8, SZ.DqdDq) (* VdqUdqdIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A21 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VINSERTPS, OD.XmmVvXmImm8, SZ.DqdDq) (* VdqHdqUdqdIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A22W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (PINSRD, OD.GprRmImm8, SZ.DDq) (* VdqEdIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A22W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (PINSRQ, OD.GprRmImm8, SZ.QDq) (* VdqEqIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A22W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPINSRD, OD.XmmVvXmImm8, SZ.YDq) (* VdqHdqEyIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A22W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPINSRQ, OD.XmmVvXmImm8, SZ.YDq) (* VdqHdqEyIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A22W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPINSRD, OD.XmmVvXmImm8, SZ.YDq) (* VdqHdqEyIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A22W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPINSRQ, OD.XmmVvXmImm8, SZ.YDq) (* VdqHdqEyIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A25W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPTERNLOGD, OD.XmmVvXmImm8, SZ.XzXz) (* VZxzHxWZxzIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A25W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPTERNLOGQ, OD.XmmVvXmImm8, SZ.VecDef) (* VxHxWxIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A27W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VGETMANTSD, OD.XmmVvXmImm8, SZ.DqqDq) (* VdqHdqWdqqIb *)
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
      struct (VINSERTI128, OD.XmmVvXmImm8, SZ.DqQqq) (* VqqHqqWdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A39W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VEXTRACTI128, OD.XmRegImm8, SZ.DqQq) (* WdqVqqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A3AW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VINSERTI32X8, OD.XmmVvXmImm8, SZ.QqXzRM) (* VZxzHxWqqIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A3AW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VINSERTI64X4, OD.XmmVvXmImm8, SZ.QqXzRM) (* VZxzHxWqqIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A3BW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VEXTRACTI32X8, OD.XmRegImm8, SZ.QqXz) (* WqqVZxzIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A3BW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VEXTRACTI64X4, OD.XmRegImm8, SZ.QqXz) (* WqqVZxzIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A3EW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPCMPUB, OD.KnVvXmImm8, SZ.VecDef) (* KnHxWxIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A3EW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPCMPUW, OD.KnVvXmImm8, SZ.VecDef) (* KnHxWxIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A40 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (DPPD, OD.GprRmImm8, SZ.Dq) (* VdqWdqIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A41 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (DPPD, OD.GprRmImm8, SZ.Dq) (* VdqWdqIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A42 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (MPSADBW, OD.GprRmImm8, SZ.Dq) (* VdqWdqIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A43W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VSHUFI32X4, OD.XmmVvXmImm8, SZ.XzXz) (* VZxzHxWZxzIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A43W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VSHUFI64X2, OD.XmmVvXmImm8, SZ.XzXz) (* VZxzHxWZxzIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A44 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (PCLMULQDQ, OD.GprRmImm8, SZ.Dq) (* VdqWdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A44 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPCLMULQDQ, OD.XmmVvXmImm8, SZ.VecDef) (* VxHxWxIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A44 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPCLMULQDQ, OD.XmmVvXmImm8, SZ.VecDef) (* VxHxWxIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException


  let vex0F3A46W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPERM2I128, OD.XmmVvXmImm8, SZ.Qq) (* VqqHqqWqqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A4AW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VBLENDVPS, OD.XmmVvXmXmm, SZ.VecDef) (* VxHxWxLx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A4BW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VBLENDVPD, OD.XmmVvXmXmm, SZ.VecDef) (* VxHxWxLx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A4CW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPBLENDVB, OD.XmmVvXmXmm, SZ.VecDef) (* VxHxWxLx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A57W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VREDUCESD, OD.XmmVvXmImm8, SZ.DqqDq) (* VdqHdqWdqqIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A60 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (PCMPESTRM, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A60 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPCMPESTRM, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A61 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (PCMPESTRI, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A61 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPCMPESTRI, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A62 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (PCMPISTRM, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A62 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPCMPISTRM, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A63 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (PCMPISTRI, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A63 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VPCMPISTRI, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A68W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VFMADDPS, OD.XmmVvXmXmm, SZ.VecDef) (* VxHxWxLx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A68W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VFMADDPS, OD.XmmVvXmmXm, SZ.VecDef) (* VxHxLxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A69W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VFMADDPD, OD.XmmVvXmXmm, SZ.VecDef) (* VxHxWxLx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A69W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VFMADDPD, OD.XmmVvXmmXm, SZ.VecDef) (* VxHxLxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A6AW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMADDSS, OD.XmmVvXmXmm, SZ.DqdDq) (* VdqHdqWdqdLdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A6AW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMADDSS, OD.XmmVvXmmXm, SZ.DqdDq) (* VdqHdqLdqWdqd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A6BW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMADDSD, OD.XmmVvXmXmm, SZ.DqqDq) (* VdqHdqWdqqLdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A6BW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VFMADDSD, OD.XmmVvXmmXm, SZ.DqqDq) (* VdqHdqLdqWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A70W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSHLDW, OD.XmmVvXmImm8, SZ.VecDef) (* VxHxWxIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A71W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSHLDD, OD.XmmVvXmImm8, SZ.VecDef) (* VxHxWxIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A71W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSHLDQ, OD.XmmVvXmImm8, SZ.VecDef) (* VxHxWxIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A72W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSHRDW, OD.XmmVvXmImm8, SZ.VecDef) (* VxHxWxIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A73W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSHRDD, OD.XmmVvXmImm8, SZ.VecDef) (* VxHxWxIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A73W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (VPSHRDQ, OD.XmmVvXmImm8, SZ.VecDef) (* VxHxWxIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3ACEW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VGF2P8AFFINEQB, OD.XmmVvXmImm8, SZ.VecDef) (* VxHxWxIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3ACEW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> (* FIXME *)
      struct (VGF2P8AFFINEQB, OD.XmmVvXmImm8, SZ.VecDef) (* VxHxWxIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3ACFW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (VGF2P8AFFINEINVQB, OD.XmmVvXmImm8, SZ.VecDef) (* VxHxWxIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3ACFW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> (* FIXME*)
      struct (VGF2P8AFFINEINVQB, OD.XmmVvXmImm8, SZ.VecDef) (* VxHxWxIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3ADF = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (AESKEYGENASSIST,OD.XmmRmImm8, SZ.DqDq)
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
    | MPref.MPrxF2 -> struct (RORX, OD.XmmRmImm8, SZ.Def) (* GyEyIb *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let grp1Op = function
    | 0 -> ADD
    | 1 -> OR
    | 2 -> ADC
    | 3 -> SBB
    | 4 -> AND
    | 5 -> SUB
    | 6 -> XOR
    | 7 -> CMP
    | _ -> raise ParsingFailureException

  let grp2Op = function
    | 0 -> ROL
    | 1 -> ROR
    | 2 -> RCL
    | 3 -> RCR
    | 4 -> SHL
    | 5 -> SHR
    | 6 -> InvalOP
    | 7 -> SAR
    | _ -> raise ParsingFailureException

  let grp4Op = function
    | 0 -> INC
    | 1 -> DEC
    | _ -> raise ParsingFailureException

  let grp5 = function
    | 0 -> struct (INC, OD.Mem, SZ.Def, SzCond.Nor)
    | 1 -> struct (DEC, OD.Mem, SZ.Def, SzCond.Nor)
    | 2 -> struct (CALLNear, OD.Mem, SZ.Def, SzCond.F64)
    | 3 -> struct (CALLFar, OD.Mem, SZ.P, SzCond.Nor)
    | 4 -> struct (JMPNear, OD.Mem, SZ.Def, SzCond.F64)
    | 5 -> struct (JMPFar, OD.Dir, SZ.P, SzCond.Nor)
    | 6 -> struct (PUSH, OD.Mem, SZ.Def, SzCond.D64)
    | _ -> raise ParsingFailureException

  let grp7 = function
    | 0 -> struct (SGDT, OD.Mem, SZ.S, SzCond.Nor)
    | 1 -> struct (SIDT, OD.Mem, SZ.S, SzCond.Nor)
    | 2 -> struct (LGDT, OD.Mem, SZ.S, SzCond.Nor)
    | 3 -> struct (LIDT, OD.Mem, SZ.S, SzCond.Nor)
    | 4 -> struct (SMSW, OD.Mem, SZ.MemW, SzCond.Nor)
    | 5 -> struct (RSTORSSP, OD.Mem, SZ.Q, SzCond.Nor)
    | 6 -> struct (LMSW, OD.Mem, SZ.MemW, SzCond.Nor)
    | 7 -> struct (INVLPG, OD.Mem, SZ.MemW, SzCond.Nor)
    | _ -> raise ParsingFailureException

  let grp8Op = function
    | 0 -> InvalOP
    | 1 -> InvalOP
    | 2 -> InvalOP
    | 3 -> InvalOP
    | 4 -> BT
    | 5 -> BTS
    | 6 -> BTR
    | 7 -> BTC
    | _ -> raise ParsingFailureException

  let grp16Op = function
    | 0 -> PREFETCHNTA
    | 1 -> PREFETCHT0
    | 2 -> PREFETCHT1
    | 3 -> PREFETCHT2
    | _ -> raise ParsingFailureException

  let grp17Op = function
    | 1 -> BLSR
    | 2 -> BLSMSK
    | 3 -> BLSI
    | _ -> raise ParsingFailureException

  let getGrp3OpKind oidx sidx oprGrp regBits =
    match regBits with
    | 0b000 when oprGrp = OpGroup.G3A ->
      struct (TEST, OD.RmImm8, SZ.Byte, SzCond.Nor)
    | 0b000 when oprGrp = OpGroup.G3B ->
      struct (TEST, OD.RmImm, SZ.Def, SzCond.Nor)
    | 0b010 -> struct (NOT, oidx, sidx, SzCond.Nor)
    | 0b011 -> struct (NEG, oidx, sidx, SzCond.Nor)
    | 0b100 -> struct (MUL, oidx, sidx, SzCond.Nor)
    | 0b101 -> struct (IMUL, oidx, sidx, SzCond.Nor)
    | 0b110 -> struct (DIV, oidx, sidx, SzCond.Nor)
    | 0b111 -> struct (IDIV, oidx, sidx, SzCond.Nor)
    | _ -> raise ParsingFailureException

  let getGrp6OpKind b regBits =
    match modIsMemory b, regBits with
    | true, 0b000 -> struct (SLDT, OD.Mem, SZ.MemW, SzCond.Nor)
    | false, 0b000 -> struct (SLDT, OD.Mem, SZ.Def, SzCond.Nor)
    | true, 0b001 -> struct (STR, OD.Mem, SZ.MemW, SzCond.Nor)
    | false, 0b001 -> struct (STR, OD.Mem, SZ.Def, SzCond.Nor)
    | _, 0b010 -> struct (LLDT, OD.Mem, SZ.MemW, SzCond.Nor)
    | _, 0b011 -> struct (LTR, OD.Mem, SZ.MemW, SzCond.Nor)
    | _, 0b100 -> struct (VERR, OD.Mem, SZ.MemW, SzCond.Nor)
    | _, 0b101 -> struct (VERW, OD.Mem, SZ.MemW, SzCond.Nor)
    | _ -> raise ParsingFailureException

  let parseGrp7OpKind (rhlp: ReadHelper) b regBits =
    if modIsMemory b then grp7 regBits
    else
      match regBits, getRM b with
      | 0b000, 0b001 ->
        rhlp.IncPos (); struct (VMCALL, OD.No, SZ.Def, SzCond.Nor)
      | 0b000, 0b010 ->
        rhlp.IncPos (); struct (VMLAUNCH, OD.No, SZ.Def, SzCond.Nor)
      | 0b000, 0b011 ->
        rhlp.IncPos (); struct (VMRESUME, OD.No, SZ.Def, SzCond.Nor)
      | 0b000, 0b100 ->
        rhlp.IncPos (); struct (VMXOFF, OD.No, SZ.Def, SzCond.Nor)
      | 0b001, 0b000 ->
        rhlp.IncPos (); struct (MONITOR, OD.No, SZ.Def, SzCond.Nor)
      | 0b001, 0b001 ->
        rhlp.IncPos (); struct (MWAIT, OD.No, SZ.Def, SzCond.Nor)
      | 0b001, 0b010 ->
        rhlp.IncPos (); struct (CLAC, OD.No, SZ.Def, SzCond.Nor)
      | 0b001, 0b011 ->
        rhlp.IncPos (); struct (STAC, OD.No, SZ.Def, SzCond.Nor)
      | 0b010, 0b000 ->
        rhlp.IncPos (); struct (XGETBV, OD.No, SZ.Def, SzCond.Nor)
      | 0b010, 0b001 ->
        rhlp.IncPos (); struct (XSETBV, OD.No, SZ.Def, SzCond.Nor)
      | 0b010, 0b100 ->
        rhlp.IncPos (); struct (VMFUNC, OD.No, SZ.Def, SzCond.Nor)
      | 0b010, 0b101 ->
        rhlp.IncPos (); struct (XEND, OD.No, SZ.Def, SzCond.Nor)
      | 0b010, 0b110 ->
        rhlp.IncPos (); struct (XTEST, OD.No, SZ.Def, SzCond.Nor)
      | 0b100, _     -> struct (SMSW, OD.Mem, SZ.Def, SzCond.Nor)
      | 0b101, 0b000 ->
        rhlp.IncPos (); struct (SETSSBSY, OD.No, SZ.Def, SzCond.Nor)
      | 0b101, 0b010 ->
        rhlp.IncPos (); struct (SAVEPREVSSP, OD.No, SZ.Def, SzCond.Nor)
      | 0b101, 0b110 ->
        rhlp.IncPos (); struct (RDPKRU, OD.No, SZ.Def, SzCond.Nor)
      | 0b101, 0b111 ->
        rhlp.IncPos (); struct (WRPKRU, OD.No, SZ.Def, SzCond.Nor)
      | 0b110, _     -> struct (LMSW, OD.Mem, SZ.MemW, SzCond.Nor)
      | 0b111, 0b000 ->
#if !EMULATION
        ensure32 rhlp
#endif
        rhlp.IncPos (); struct (SWAPGS, OD.No, SZ.Def, SzCond.Nor)
      | 0b111, 0b001 ->
        rhlp.IncPos (); struct (RDTSCP, OD.No, SZ.Def, SzCond.Nor)
      | _ -> raise ParsingFailureException

  let getGrp9OpKind (rhlp: ReadHelper) b regBits =
    let hasOprSzPref = hasOprSz rhlp.Prefixes
    let hasREPZPref = hasREPZ rhlp.Prefixes
    let hasREXWPref = hasREXW rhlp.REXPrefix
    match modIsMemory b, regBits, hasOprSzPref, hasREPZPref, hasREXWPref with
    | true,  0b001, false, false, false ->
      struct (CMPXCHG8B, OD.Mem, SZ.Q, SzCond.Nor)
    | true,  0b001, false, false, true  ->
      struct (CMPXCHG16B, OD.Mem, SZ.Dq, SzCond.Nor)
    | true,  0b011, false, false, false ->
      struct (XRSTORS, OD.Mem, SZ.Q, SzCond.Nor)
    | true,  0b011, false, false, true  ->
      struct (XRSTORS64, OD.Mem, SZ.Q, SzCond.Nor)
    | true,  0b100, false, false, false ->
      struct (XSAVEC, OD.Mem, SZ.Q, SzCond.Nor)
    | true,  0b100, false, false, true  ->
      struct (XSAVEC64, OD.Mem, SZ.Q, SzCond.Nor)
    | true,  0b101, false, false, false ->
      struct (XSAVES, OD.Mem, SZ.Q, SzCond.Nor)
    | true,  0b101, false, false, true  ->
      struct (XSAVES64, OD.Mem, SZ.Q, SzCond.Nor)
    | true,  0b110, false, false, _     ->
      struct (VMPTRLD, OD.Mem, SZ.Q, SzCond.Nor)
    | true,  0b111, false, false, _     ->
      struct (VMPTRST, OD.Mem, SZ.Q, SzCond.Nor)
    | true,  0b110, true,  false, _     ->
      struct (VMCLEAR, OD.Mem, SZ.Q, SzCond.Nor)
    | true,  0b110, false, true,  _     ->
      struct (VMXON, OD.Mem, SZ.Q, SzCond.Nor)
    | true,  0b111, false, true,  _     ->
      struct (VMPTRST, OD.Mem, SZ.Q, SzCond.Nor)
    | false, 0b110, false, false, _     ->
      struct (RDRAND, OD.Mem, SZ.Def, SzCond.Nor)
    | false, 0b111, false, false, _     ->
      struct (RDSEED, OD.Mem, SZ.Def, SzCond.Nor)
    | _ -> raise ParsingFailureException

  let getGrp11OpKind span rhlp op oidx1 sz1 b reg oidx2 sz2 =
    match reg with
    | 0b000 -> struct (MOV, oidx2, sz2, SzCond.Nor)
    | 0b111 when modIsMemory b -> raise ParsingFailureException
    | 0b111 ->
      if (rhlp: ReadHelper).ReadByte span = 0xF8uy then
        struct (op, oidx1, sz1, SzCond.Nor)
      else raise ParsingFailureException
    | _ -> raise ParsingFailureException

  let getGrp12OpKind rhlp b regBits =
    match modIsMemory b, regBits, hasOprSz (selectPrefix rhlp) with
    | false, 0b010, false -> struct (PSRLW, OD.MmxImm8, SZ.Q, SzCond.Nor)
    | false, 0b010, true  ->
      if rhlp.VEXInfo = None then
        struct (PSRLW, OD.RmImm8, SZ.Dq, SzCond.Nor)
      else struct (VPSRLW, OD.VvRmImm8, SZ.VecDef, SzCond.Nor)
    | false, 0b100, false -> struct (PSRAW, OD.MmxImm8, SZ.Q, SzCond.Nor)
    | false, 0b100, true  ->
      if rhlp.VEXInfo = None then
        struct (PSRAW, OD.RmImm8, SZ.Dq, SzCond.Nor)
      else struct (VPSRAW, OD.VvRmImm8, SZ.VecDef, SzCond.Nor)
    | false, 0b110, false -> struct (PSLLW, OD.MmxImm8, SZ.Q, SzCond.Nor)
    | false, 0b110, true  ->
      if rhlp.VEXInfo = None then
        struct (PSLLW, OD.RmImm8, SZ.Dq, SzCond.Nor)
      else struct (VPSLLW, OD.VvRmImm8, SZ.VecDef, SzCond.Nor)
    | _ -> raise ParsingFailureException

  let getGrp13OpKind rhlp b regBits =
    match modIsMemory b, regBits, hasOprSz (selectPrefix rhlp) with
    | false, 0b010, false -> struct (PSRLD, OD.MmxImm8, SZ.Q, SzCond.Nor)
    | false, 0b010, true  ->
      if rhlp.VEXInfo = None then
        struct (PSRLD, OD.RmImm8, SZ.Dq, SzCond.Nor)
      else struct (VPSRLD, OD.VvRmImm8, SZ.VecDef, SzCond.Nor)
    | false, 0b100, false -> struct (PSRAD, OD.MmxImm8, SZ.Q, SzCond.Nor)
    | false, 0b100, true  ->
      if rhlp.VEXInfo = None then
        struct (PSRAD, OD.RmImm8, SZ.Dq, SzCond.Nor)
      else struct (VPSRAD, OD.VvRmImm8, SZ.VecDef, SzCond.Nor)
    | false, 0b110, false -> struct (PSLLD, OD.MmxImm8, SZ.Q, SzCond.Nor)
    | false, 0b110, true  ->
      if rhlp.VEXInfo = None then
        struct (PSLLD, OD.RmImm8, SZ.Dq, SzCond.Nor)
      else struct (VPSLLD, OD.VvRmImm8, SZ.VecDef, SzCond.Nor)
    | _ -> raise ParsingFailureException

  let getGrp14OpKind rhlp b regBits =
    match modIsMemory b, regBits, hasOprSz (selectPrefix rhlp) with
    | false, 0b010, false ->
      struct (PSRLQ, OD.MmxImm8, SZ.Q, SzCond.Nor)
    | false, 0b010, true  ->
      if rhlp.VEXInfo = None then
        struct (PSRLQ, OD.RmImm8, SZ.Dq, SzCond.Nor)
      else struct (VPSRLQ, OD.VvRmImm8, SZ.VecDef, SzCond.Nor)
    | false, 0b011, true  ->
      if rhlp.VEXInfo = None then
        struct (PSRLDQ, OD.RmImm8, SZ.Dq, SzCond.Nor)
      else struct (VPSRLDQ, OD.VvRmImm8, SZ.VecDef, SzCond.Nor)
    | false, 0b110, false -> struct (PSLLQ, OD.MmxImm8, SZ.Q, SzCond.Nor)
    | false, 0b110, true  ->
      if rhlp.VEXInfo = None then
        struct (PSLLQ, OD.RmImm8, SZ.Dq, SzCond.Nor)
      else struct (VPSLLQ, OD.VvRmImm8, SZ.VecDef, SzCond.Nor)
    | false, 0b111, true  ->
      if rhlp.VEXInfo = None then
        struct (PSLLDQ, OD.RmImm8, SZ.Dq, SzCond.Nor)
      else struct (VPSLLDQ, OD.VvRmImm8, SZ.VecDef, SzCond.Nor)
    | _ -> raise ParsingFailureException

  let parseGrp15OpKind (rhlp: ReadHelper) b regBits =
    match modIsMemory b, regBits, rhlp.Prefixes with
    | true, 0b000, Prefix.PrxNone ->
      let op = if hasREXW rhlp.REXPrefix then FXSAVE64 else FXSAVE
      struct (op, OD.Mem, SZ.Def, SzCond.Nor)
    | true, 0b001, Prefix.PrxNone ->
      let op =
        if hasREXW rhlp.REXPrefix then FXRSTOR64 else FXRSTOR
      struct (op, OD.Mem, SZ.Def, SzCond.Nor)
    | true, 0b010, Prefix.PrxNone -> struct (LDMXCSR, OD.Mem, SZ.D, SzCond.Nor)
    | true, 0b011, Prefix.PrxNone -> struct (STMXCSR, OD.Mem, SZ.D, SzCond.Nor)
    | true, 0b100, Prefix.PrxNone -> struct (XSAVE, OD.Mem, SZ.Def, SzCond.Nor)
    | true, 0b101, Prefix.PrxNone -> struct (XRSTOR, OD.Mem, SZ.Def, SzCond.Nor)
    | true, 0b110, Prefix.PrxNone ->
      struct (XSAVEOPT, OD.Mem, SZ.Def, SzCond.Nor)
    | true, 0b110, Prefix.PrxOPSIZE ->
      struct (CLWB, OD.Mem, SZ.Byte, SzCond.Nor)
    | true, 0b110, Prefix.PrxREPZ -> struct (CLRSSBSY, OD.Mem, SZ.Q, SzCond.Nor)
    | true, 0b111, Prefix.PrxNone -> struct (CLFLUSH, OD.Mem, SZ.BV, SzCond.Nor)
    | true, 0b111, Prefix.PrxOPSIZE ->
      struct (CLFLUSHOPT, OD.Mem, SZ.BV, SzCond.Nor)
    | false, 0b101, Prefix.PrxNone ->
      rhlp.IncPos (); struct (LFENCE, OD.No, SZ.Def, SzCond.Nor)
    | false, 0b110, Prefix.PrxNone ->
      rhlp.IncPos (); struct (MFENCE, OD.No, SZ.Def, SzCond.Nor)
    | false, 0b111, Prefix.PrxNone ->
      rhlp.IncPos (); struct (SFENCE, OD.No, SZ.Def, SzCond.Nor)
    | false, 0b000, Prefix.PrxREPZ ->
      struct (RDFSBASE, OD.Gpr, SZ.Def, SzCond.Nor)
    | false, 0b001, Prefix.PrxREPZ ->
      struct (RDGSBASE, OD.Gpr, SZ.Def, SzCond.Nor)
    | false, 0b010, Prefix.PrxREPZ ->
      struct (WRFSBASE, OD.Gpr, SZ.Def, SzCond.Nor)
    | false, 0b011, Prefix.PrxREPZ ->
      struct (WRGSBASE, OD.Gpr, SZ.Def, SzCond.Nor)
    | false, 0b101, Prefix.PrxREPZ ->
      let op = if hasREXW rhlp.REXPrefix then INCSSPQ else INCSSPD
      struct (op, OD.Gpr, SZ.Def, SzCond.Nor)
    | _ -> raise ParsingFailureException

  let parseGrpOpKind span (rhlp: ReadHelper) oidx sidx oprGrp =
    let b = rhlp.PeekByte span
    let r = getReg b
    match oprGrp with
    | OpGroup.G1 -> struct (grp1Op r, oidx, sidx, SzCond.Nor)
    | OpGroup.G1Inv64 ->
#if !EMULATION
      ensure32 rhlp
#endif
      struct (grp1Op r, oidx, sidx, SzCond.Nor)
    | OpGroup.G1A -> struct (POP, oidx, sidx, SzCond.D64)
    | OpGroup.G2 when r = 0b110 -> raise ParsingFailureException
    | OpGroup.G2 -> struct (grp2Op r, oidx, sidx, SzCond.Nor)
    | OpGroup.G3A | OpGroup.G3B -> getGrp3OpKind oidx sidx oprGrp r
    | OpGroup.G4 -> struct (grp4Op r, OD.Mem, SZ.Byte, SzCond.Nor)
    | OpGroup.G5 -> grp5 r
    | OpGroup.G6 -> getGrp6OpKind b r
    | OpGroup.G7 -> parseGrp7OpKind rhlp b r
    | OpGroup.G8 -> struct (grp8Op r, oidx, sidx, SzCond.Nor)
    | OpGroup.G9 -> getGrp9OpKind rhlp b r
    | OpGroup.G11A ->
      getGrp11OpKind span rhlp XABORT OD.Imm8 SZ.Def b r oidx sidx
    | OpGroup.G11B ->
      getGrp11OpKind span rhlp XBEGIN OD.Rel SZ.D64 b r oidx sidx
    | OpGroup.G12 -> getGrp12OpKind rhlp b r
    | OpGroup.G13 -> getGrp13OpKind rhlp b r
    | OpGroup.G14 -> getGrp14OpKind rhlp b r
    | OpGroup.G15 -> parseGrp15OpKind rhlp b r
    | OpGroup.G16 -> struct (grp16Op r, oidx, sidx, SzCond.Nor)
    | OpGroup.G17 -> struct (grp17Op r, oidx, sidx, SzCond.Nor)
    | OpGroup.G10
    | _ ->
      raise ParsingFailureException (* Not implemented yet *)

  /// Add BND prefix (Intel MPX extension).
  let addBND (rhlp: ReadHelper) =
    if hasREPNZ rhlp.Prefixes then
      rhlp.Prefixes <- Prefix.PrxBND ||| (ClearGrp1PrefMask &&& rhlp.Prefixes)
    else ()

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
  /// prefix, and we have to filter out the prefixes because they are not going
  /// to be used as a normal prefixes. They will only be used as a mandatory
  /// prefix to decide the opcode.
  let inline filterPrefs (prefix: Prefix) = prefix &&& ClearVEXPrefMask

  let getInstr prefix fnInstr = fnInstr (getMandPrx prefix)

  /// The main instruction rendering function.
  let render span rhlp opcode szCond (oidx: OprDesc) (sidx: SizeKind) =
    (rhlp: ReadHelper).SzComputers[int sidx].Render rhlp szCond
    exceptionalOperationSize opcode rhlp
    let oprs = rhlp.OprParsers[int oidx].Render (span, rhlp)
    newInsInfo rhlp opcode oprs

  /// Parse group Opcodes: Vol.2C A-19 Table A-6. Opcode Extensions for One- and
  /// Two-byte Opcodes by Group Number.
  let parseGrpOp span rhlp grp oidx sidx =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span rhlp oidx sidx grp
    if isBranch op then addBND rhlp |> ignore
    elif isCETInstr op then rhlp.Prefixes <- ClearGrp1PrefMask &&& rhlp.Prefixes
    else ()
    render span rhlp op szCond oidx szidx

  /// Normal/VEX
  let parseVEX span (rhlp: ReadHelper) fnNor fnVex =
    match rhlp.VEXInfo with
    | None ->
      let struct (op, oidx, sidx) = fnNor (getMandPrx rhlp.Prefixes)
      rhlp.Prefixes <- filterPrefs rhlp.Prefixes
      render span rhlp op SzCond.Nor oidx sidx
    | Some v ->
      let struct (op, oidx, sidx) = fnVex (getMandPrx v.VPrefixes)
      render span rhlp op SzCond.Nor oidx sidx

  /// Select Normal(REX.W), VEX(REX.W)
  let selectVEXW (span: ByteSpan) rhlp fnNorW0 fnNorW1 fnVexW0 fnVexW1 =
    match (rhlp: ReadHelper).VEXInfo with
    | None ->
      let fnNor = if hasREXW rhlp.REXPrefix then fnNorW1 else fnNorW0
      let ins = getInstr rhlp.Prefixes fnNor
      rhlp.Prefixes <- filterPrefs rhlp.Prefixes
      ins
    | Some v ->
      let fnVex = if hasREXW rhlp.REXPrefix then fnVexW1 else fnVexW0
      getInstr v.VPrefixes fnVex

  /// Normal(REX.W)/VEX(REX.W)
  let parseVEXW span rhlp fnNorW0 fnNorW1 fnVexW0 fnVexW1 =
    let struct (op, oidx, sidx) =
      selectVEXW span rhlp fnNorW0 fnNorW1 fnVexW0 fnVexW1
    render span rhlp op SzCond.Nor oidx sidx

  /// Select Normal, VEX, EVEX(REX.W)
  let selectEVEX (rhlp: ReadHelper) fnNor fnVex fnEVexW0 fnEVexW1 =
    match rhlp.VEXInfo with
    | None ->
      let ins = getInstr rhlp.Prefixes fnNor
      rhlp.Prefixes <- filterPrefs rhlp.Prefixes
      ins
    | Some v ->
      if v.VEXType &&& VEXType.EVEX = VEXType.EVEX then
        let fnEVex = if hasREXW rhlp.REXPrefix then fnEVexW1 else fnEVexW0
        getInstr v.VPrefixes fnEVex
      else getInstr v.VPrefixes fnVex

  /// Normal/VEX/EVEX(REX.W)
  let parseEVEX span rhlp fnNor fnVex fnEVexW0 fnEVexW1 =
    let struct (op, oidx, sidx) = selectEVEX rhlp fnNor fnVex fnEVexW0 fnEVexW1
    render span rhlp op SzCond.Nor oidx sidx

  /// Select VEX(REX.W), EVEX(REX.W)
  let selectEVEXW (rhlp: ReadHelper) fnVexW0 fnVexW1 fnEVexW0 fnEVexW1 =
    match rhlp.VEXInfo with
    | None -> raise ParsingFailureException
    | Some v ->
      if v.VEXType &&& VEXType.EVEX = VEXType.EVEX then
        let fnEVex = if hasREXW rhlp.REXPrefix then fnEVexW1 else fnEVexW0
        getInstr v.VPrefixes fnEVex
      else
        let fnVex = if hasREXW rhlp.REXPrefix then fnVexW1 else fnVexW0
        getInstr v.VPrefixes fnVex

  /// VEX(REX.W)/EVEX(REX.W)
  let parseEVEXW span rhlp fnVexW0 fnVexW1 fnEVexW0 fnEVexW1 =
    let struct (op, oidx, sidx) =
      selectEVEXW rhlp fnVexW0 fnVexW1 fnEVexW0 fnEVexW1
    render span rhlp op SzCond.Nor oidx sidx

  /// Select Normal(REX.W), VEX(REX.W), EVEX(REX.W)
  let selectEVEXAll (rhlp: ReadHelper) fnNorW0 fnNorW1 fnVexW0 fnVexW1 fnEVexW0
                    fnEVexW1 =
    match (rhlp: ReadHelper).VEXInfo with
    | None ->
      let fnNor = if hasREXW rhlp.REXPrefix then fnNorW1 else fnNorW0
      let ins = getInstr rhlp.Prefixes fnNor
      rhlp.Prefixes <- filterPrefs rhlp.Prefixes
      ins
    | Some v ->
      if v.VEXType &&& VEXType.EVEX = VEXType.EVEX then
        let fnEVex = if hasREXW rhlp.REXPrefix then fnEVexW1 else fnEVexW0
        getInstr v.VPrefixes fnEVex
      else
        let fnVex = if hasREXW rhlp.REXPrefix then fnVexW1 else fnVexW0
        getInstr v.VPrefixes fnVex

  /// Normal(REX.W)/VEX(REX.W)/EVEX(REX.W)
  let parseEVEXAll span rhlp fnNorW0 fnNorW1 fnVexW0 fnVexW1 fnEVexW0 fnEVexW1 =
    let struct (op, oidx, sidx) =
      selectEVEXAll rhlp fnNorW0 fnNorW1 fnVexW0 fnVexW1 fnEVexW0 fnEVexW1
    render span rhlp op SzCond.Nor oidx sidx

  /// Parse non-VEX instructions.
  let parseNonVEX span (rhlp: ReadHelper) fnNor =
    let struct (op, oidx, sidx) = getInstr rhlp.Prefixes fnNor
    rhlp.Prefixes <- filterPrefs rhlp.Prefixes
    render span rhlp op SzCond.Nor oidx sidx

  /// Parse non-VEX instructions.
  let pVEXByMem span (rhlp: ReadHelper) fnNorM fnNorR fnVexM fnVexR =
    let struct (fnNor, fnVex) =
      if rhlp.PeekByte span |> modIsMemory then struct (fnNorM, fnVexM)
      else struct (fnNorR, fnVexR)
    parseVEX span rhlp fnNor fnVex

  /// Parse BND-related instructions.
  let parseBND span (rhlp: ReadHelper) szCond fnBND =
    let struct (op, oidx, sidx) = getInstr rhlp.Prefixes fnBND
    rhlp.Prefixes <- filterPrefs rhlp.Prefixes
    render span rhlp op szCond oidx sidx

  let parseCETInstr span (rhlp: ReadHelper) =
    let struct (op, oidx, sidx) =
      match rhlp.PeekByte span with
      | 0xFAuy -> rhlp.IncPos (); struct (ENDBR64, OD.No, SZ.Def)
      | 0xFBuy -> rhlp.IncPos (); struct (ENDBR32, OD.No, SZ.Def)
      | b when getReg b = 0b001 && getMod b = 0b11 ->
        let op = if hasREXW rhlp.REXPrefix then RDSSPQ else RDSSPD
        struct (op, OD.Gpr, SZ.Def)
      | _ -> raise InvalidOpcodeException
    rhlp.Prefixes <- ClearGrp1PrefMask &&& rhlp.Prefixes
    render span rhlp op SzCond.Nor oidx sidx

  let parseESCOp span (rhlp: ReadHelper) escFlag getOpIn getOpOut =
    let modRM = rhlp.ReadByte span
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Nor
    if modRM <= 0xBFuy then
      let op = getOpIn modRM
      let effOprSize =
        match escFlag with
        | 0xD9uy -> getReg modRM |> getD9EscEffOprSizeByModRM
        | 0xDBuy -> getReg modRM |> getDBEscEffOprSizeByModRM
        | 0xDDuy -> getReg modRM |> getDDEscEffOprSizeByModRM
        | 0xDFuy -> getReg modRM |> getDFEscEffOprSizeByModRM
        | _ -> escFlag |> getEscEffOprSizeByESCOp
      rhlp.MemEffOprSize <- effOprSize
      rhlp.MemEffRegSize <- effOprSize
      let o = OperandParsingHelper.parseMemory modRM span rhlp
      newInsInfo rhlp op (OneOperand o)
    else
      let opcode, oprs = getOpOut modRM
      newInsInfo rhlp opcode oprs

  /// When the first two bytes are 0F38.
  /// Table A-4 of Volume 2 (Three-byte Opcode Map : First Two Bytes are 0F 38H)
  let parseThreeByteOp1 span (rhlp: ReadHelper) =
    match rhlp.ReadByte span with
    | 0x00uy -> parseVEX span rhlp nor0F3800 vex0F3800
    | 0x01uy -> parseVEX span rhlp nor0F3801 vex0F3801
    | 0x02uy -> parseVEX span rhlp nor0F3802 vex0F3802
    | 0x03uy -> parseVEX span rhlp nor0F3803 vex0F3803
    | 0x04uy -> parseEVEX span rhlp nor0F3804 notEn notEn notEn
    | 0x05uy -> parseVEX span rhlp nor0F3805 vex0F3805
    | 0x06uy -> parseVEX span rhlp nor0F3806 vex0F3806
    | 0x07uy -> parseVEX span rhlp nor0F3807 vex0F3807
    | 0x08uy -> parseVEX span rhlp nor0F3808 vex0F3808
    | 0x09uy -> parseVEX span rhlp nor0F3809 vex0F3809
    | 0x0auy -> parseVEX span rhlp nor0F380A vex0F380A
    | 0x0buy -> parseVEX span rhlp nor0F380B vex0F380B
    | 0x0cuy -> parseEVEXW span rhlp vex0F380CW0 notEn notEn notEn
    | 0x10uy -> parseVEX span rhlp nor0F3810 notEn
    | 0x14uy -> parseEVEX span rhlp nor0F3814 notEn evex0F3814W0 evex0F3814W1
    | 0x15uy -> parseVEX span rhlp nor0F3815 notEn
    | 0x16uy -> parseVEXW span rhlp notEn notEn vex0F3816W0 notEn
    | 0x17uy -> parseVEX span rhlp nor0F3817 vex0F3817
    | 0x18uy -> parseEVEXW span rhlp vex0F3818W0 notEn evex0F3818W0 notEn
    | 0x19uy -> parseEVEXW span rhlp vex0F3819W0 notEn notEn evex0F3819W1
    | 0x1auy -> parseVEXW span rhlp notEn notEn vex0F381AW0 notEn
    | 0x1cuy -> parseVEX span rhlp nor0F381C vex0F381C
    | 0x1duy -> parseVEX span rhlp nor0F381D vex0F381D
    | 0x1euy -> parseVEX span rhlp nor0F381E vex0F381E
    | 0x1fuy -> parseEVEXW span rhlp notEn notEn notEn evex0F381FW1
    | 0x20uy -> parseVEX span rhlp nor0F3820 vex0F3820
    | 0x21uy -> parseVEX span rhlp nor0F3821 vex0F3821
    | 0x22uy -> parseVEX span rhlp nor0F3822 vex0F3822
    | 0x23uy -> parseVEX span rhlp nor0F3823 vex0F3823
    | 0x24uy -> parseVEX span rhlp nor0F3824 vex0F3824
    | 0x25uy -> parseVEX span rhlp nor0F3825 vex0F3825
    | 0x28uy -> parseVEX span rhlp nor0F3828 vex0F3828
    | 0x29uy -> parseVEX span rhlp nor0F3829 vex0F3829
    | 0X2auy -> parseEVEXW span rhlp notEn notEn notEn evex0F382AW1
    | 0x2buy -> parseVEX span rhlp nor0F382B vex0F382B
    | 0x2cuy -> parseEVEXW span rhlp vex0F382CW0 notEn evex0F382CW0 evex0F382CW1
    | 0x2duy -> parseEVEXW span rhlp vex0F382DW0 notEn evex0F382DW0 evex0F382DW1
    | 0x2euy -> parseVEXW span rhlp notEn notEn vex0F382EW0 notEn
    | 0x2fuy -> parseVEXW span rhlp notEn notEn vex0F382FW0 notEn
    | 0x30uy -> parseEVEX span rhlp nor0F3830 vex0F3830 evex0F3830 evex0F3830
    | 0x31uy -> parseVEX span rhlp nor0F3831 vex0F3831
    | 0x32uy -> parseVEX span rhlp nor0F3832 vex0F3832
    | 0x33uy -> parseEVEX span rhlp nor0F3833 vex0F3833 evex0F3833 evex0F3833
    | 0x34uy -> parseVEX span rhlp nor0F3834 vex0F3834
    | 0x35uy -> parseVEX span rhlp nor0F3835 vex0F3835
    | 0x36uy -> parseEVEXW span rhlp vex0F3836W0 notEn notEn notEn
    | 0x37uy -> parseVEX span rhlp nor0F3837 vex0F3837
    | 0x38uy -> parseVEX span rhlp nor0F3838 vex0F3838
    | 0x39uy -> parseEVEX span rhlp nor0F3839 vex0F3839 evex0F3839W0 notEn
    | 0x3auy -> parseEVEX span rhlp nor0F383A vex0F383A evex0F383AW0 notEn
    | 0x3buy -> parseVEX span rhlp nor0F383B vex0F383B
    | 0x3cuy -> parseVEX span rhlp nor0F383C vex0F383C
    | 0x3duy -> parseVEX span rhlp nor0F383D vex0F383D
    | 0x3euy -> parseVEX span rhlp nor0F383E vex0F383E
    | 0x3fuy -> parseVEX span rhlp nor0F383F vex0F383F
    | 0x40uy -> parseVEX span rhlp nor0F3840 vex0F3840
    | 0x41uy -> parseVEX span rhlp nor0F3841 vex0F3841
    | 0x43uy -> parseEVEXW span rhlp notEn notEn notEn evex0F3843W1
    | 0x45uy -> parseEVEXW span rhlp vex0F3845W0 vex0F3845W1 notEn notEn
    | 0x46uy -> parseEVEXW span rhlp vex0F3846W0 notEn notEn notEn
    | 0x47uy -> parseEVEXW span rhlp vex0F3847W0 vex0F3847W1 notEn notEn
    | 0x4Duy -> parseEVEXW span rhlp notEn notEn notEn evex0F384DW1
    | 0x50uy -> parseEVEXW span rhlp vex0F3850W0 notEn evex0F3850W0 notEn
    | 0x51uy -> parseEVEXW span rhlp vex0F3851W0 notEn evex0F3851W0 notEn
    | 0x52uy -> parseEVEXW span rhlp vex0F3852W0 notEn evex0F3852W0 notEn
    | 0x53uy -> parseEVEXW span rhlp vex0F3853W0 notEn evex0F3853W0 notEn
    | 0x54uy -> parseEVEXW span rhlp notEn notEn evex0F3854W0 evex0F3854W1
    | 0x55uy -> parseEVEXW span rhlp notEn notEn evex0F3855W0 evex0F3855W1
    | 0x58uy -> parseEVEXW span rhlp vex0F3858W0 notEn evex0F3858W0 notEn
    | 0x59uy -> parseEVEXW span rhlp vex0F3859W0 notEn evex0F3859W0 evex0F3859W1
    | 0x5Auy -> parseEVEXW span rhlp vex0F385AW0 notEn evex0F385AW0 evex0F385AW1
    | 0x5Buy -> parseEVEXW span rhlp notEn notEn evex0F385BW0 evex0F385BW1
    | 0x62uy -> parseEVEXW span rhlp notEn notEn evex0F3862W0 evex0F3862W1
    | 0x63uy -> parseEVEXW span rhlp notEn notEn evex0F3863W0 evex0F3863W1
    | 0x68uy -> parseEVEXW span rhlp notEn notEn evex0F3868W0 evex0F3868W1
    | 0x70uy -> parseEVEXW span rhlp notEn notEn notEn evex0F3870W1
    | 0x71uy -> parseEVEXW span rhlp notEn notEn evex0F3871W0 evex0F3871W1
    | 0x72uy -> parseEVEXW span rhlp notEn notEn evex0F3872W0 evex0F3872W1
    | 0x73uy -> parseEVEXW span rhlp notEn notEn evex0F3873W0 evex0F3873W1
    | 0x75uy -> parseEVEXW span rhlp notEn notEn notEn evex0F3875W1
    | 0x76uy -> parseEVEXW span rhlp notEn notEn evex0F3876W0 notEn
    | 0x77uy -> parseEVEXW span rhlp notEn notEn notEn evex0F3877W1
    | 0x78uy -> parseVEX span rhlp nor0F3878 vex0F3878
    | 0x79uy -> parseEVEXW span rhlp vex0F3879W0 notEn notEn notEn
    | 0x7Auy -> parseEVEXW span rhlp notEn notEn evex0F387AW0 notEn
    | 0x7Buy -> parseEVEXW span rhlp notEn notEn evex0F387BW0 notEn
    | 0x7Cuy -> parseEVEXW span rhlp notEn notEn evex0F387CW0 evex0F387CW1
    | 0x7Duy -> parseEVEXW span rhlp notEn notEn evex0F387DW0 evex0F387DW1
    | 0x83uy -> parseEVEXW span rhlp notEn notEn notEn evex0F3883W1
    | 0x8Cuy -> parseVEXW span rhlp notEn notEn vex0F388CW0 vex0F388CW1
    | 0x8Duy -> parseEVEXW span rhlp notEn notEn evex0F388DW0 notEn
    | 0x8Euy -> parseVEXW span rhlp notEn notEn vex0F388EW0 vex0F388EW1
    | 0x8Fuy -> parseEVEXW span rhlp notEn notEn evex0F388FW0 notEn
    | 0x90uy -> parseEVEXW span rhlp vex0F3890W0 vex0F3890W1 evex0F3890W0 notEn
    | 0x91uy -> parseEVEXW span rhlp vex0F3891W0 vex0F3891W1 notEn notEn
    | 0x92uy -> parseEVEXW span rhlp vex0F3892W0 vex0F3892W1 evex0F3892W0 notEn
    | 0x93uy -> parseEVEXW span rhlp vex0F3893W0 vex0F3893W1 notEn notEn
    | 0x96uy ->
      parseEVEXW span rhlp vex0F3896W0 vex0F3896W1 evex0F3896W0 evex0F3896W1
    | 0x97uy ->
      parseEVEXW span rhlp vex0F3897W0 vex0F3897W1 evex0F3897W0 evex0F3897W1
    | 0x98uy -> parseEVEXW span rhlp vex0F3898W0 vex0F3898W1 notEn evex0F3898W1
    | 0x99uy -> parseVEXW span rhlp notEn notEn vex0F3899W0 vex0F3899W1
    | 0x9Auy -> parseEVEXW span rhlp vex0F389AW0 vex0F389AW1 evex0F389AW0 notEn
    | 0x9Buy -> parseEVEXW span rhlp vex0F389BW0 vex0F389BW1 evex0F389BW0 notEn
    | 0x9Cuy -> parseEVEXW span rhlp vex0F389CW0 vex0F389CW1 notEn evex0F389CW1
    | 0x9Duy -> parseEVEXW span rhlp vex0F389DW0 vex0F389DW1 notEn evex0F389DW1
    | 0x9Euy -> parseEVEXW span rhlp vex0F389EW0 vex0F389EW1 notEn notEn
    | 0x9Fuy -> parseEVEXW span rhlp vex0F389FW0 vex0F389FW1 notEn notEn
    | 0xA2uy -> parseEVEXW span rhlp notEn notEn evex0F38A2W0 evex0F38A2W1
    | 0xA3uy -> parseEVEXW span rhlp notEn notEn evex0F38A3W0 evex0F38A3W1
    | 0xA6uy -> parseEVEXW span rhlp vex0F38A6W0 vex0F38A6W1 notEn notEn
    | 0xA7uy -> parseEVEXW span rhlp vex0F38A7W0 vex0F38A7W1 notEn notEn
    | 0xA8uy -> parseEVEXW span rhlp vex0F38A8W0 vex0F38A8W1 evex0F38A8W0 notEn
    | 0xA9uy -> parseVEXW span rhlp notEn notEn vex0F38A9W0 vex0F38A9W1
    | 0xAAuy -> parseEVEXW span rhlp vex0F38AAW0 vex0F38AAW1 evex0F38AAW0 notEn
    | 0xABuy -> parseEVEXW span rhlp vex0F38ABW0 vex0F38ABW1 evex0F38ABW0 notEn
    | 0xACuy -> parseEVEXW span rhlp vex0F38ACW0 vex0F38ACW1 notEn notEn
    | 0xADuy -> parseEVEXW span rhlp vex0F38ADW0 vex0F38ADW1 notEn evex0F38ADW1
    | 0xAEuy -> parseEVEXW span rhlp vex0F38AEW0 vex0F38AEW1 notEn notEn
    | 0xAFuy -> parseEVEXW span rhlp vex0F38AFW0 vex0F38AFW1 notEn notEn
    | 0xB4uy -> parseEVEXW span rhlp notEn notEn notEn evex0F38B4W1
    | 0xB5uy -> parseEVEXW span rhlp notEn notEn notEn evex0F38B5W1
    | 0xB6uy -> parseEVEXW span rhlp vex0F38B6W0 vex0F38B6W1 notEn evex0F38B8W1
    | 0xB7uy -> parseEVEXW span rhlp vex0F38B7W0 vex0F38B7W1 notEn evex0F38B8W1
    | 0xB8uy -> parseEVEXW span rhlp vex0F38B8W0 vex0F38B8W1 notEn evex0F38B8W1
    | 0xB9uy -> parseVEXW span rhlp notEn notEn vex0F38B9W0 vex0F38B9W1
    | 0xBAuy -> parseEVEXW span rhlp vex0F38BAW0 vex0F38BAW1 notEn notEn
    | 0xBBuy -> parseEVEXW span rhlp vex0F38BBW0 vex0F38BBW1 notEn evex0F38BBW1
    | 0xBCuy -> parseEVEXW span rhlp vex0F38BCW0 vex0F38BCW1 notEn evex0F38BCW1
    | 0xBDuy -> parseEVEXW span rhlp vex0F38BDW0 vex0F38BDW1 notEn evex0F38BDW1
    | 0xBEuy -> parseEVEXW span rhlp vex0F38BEW0 vex0F38BEW1 notEn notEn
    | 0xBFuy -> parseEVEXW span rhlp vex0F38BFW0 vex0F38BFW1 notEn notEn
    | 0xC6uy when isReg001 span rhlp ->
      parseEVEXW span rhlp notEn notEn evex0F38C61W0 evex0F38C61W1
    | 0xC6uy when isReg010 span rhlp ->
      parseEVEXW span rhlp notEn notEn evex0F38C62W0 evex0F38C62W1
    | 0xC6uy when isReg101 span rhlp ->
      parseEVEXW span rhlp notEn notEn evex0F38C65W0 evex0F38C65W1
    | 0xC6uy when isReg110 span rhlp ->
      parseEVEXW span rhlp notEn notEn evex0F38C66W0 evex0F38C66W1
    | 0xC7uy when isReg001 span rhlp ->
      parseEVEXW span rhlp notEn notEn evex0F38C71W0 evex0F38C71W1
    | 0xC7uy when isReg010 span rhlp ->
      parseEVEXW span rhlp notEn notEn evex0F38C72W0 evex0F38C72W1
    | 0xC7uy when isReg101 span rhlp ->
      parseEVEXW span rhlp notEn notEn evex0F38C75W0 evex0F38C75W1
    | 0xC7uy when isReg110 span rhlp ->
      parseEVEXW span rhlp notEn notEn evex0F38C76W0 evex0F38C76W1
    | 0xCBuy -> parseEVEXW span rhlp notEn notEn notEn evex0F38CBW1
    | 0xCDuy -> parseEVEXW span rhlp notEn notEn notEn evex0F38CDW1
    | 0xCFuy -> parseEVEXW span rhlp evex0F38CFW0 notEn evex0F38CFW0 notEn
    | 0xDBuy -> parseVEX span rhlp nor0F38DB notEn
    | 0xDCuy -> parseEVEX span rhlp nor0F38DC vex0F38DC evex0F38DC evex0F38DC
    | 0xDDuy -> parseEVEX span rhlp nor0F38DD vex0F38DD evex0F38DD evex0F38DD
    | 0xDEuy -> parseEVEX span rhlp nor0F38DE vex0F38DE evex0F38DE evex0F38DE
    | 0xDFuy -> parseEVEX span rhlp nor0F38DF vex0F38DF evex0F38DF evex0F38DF
    | 0xF0uy -> parseNonVEX span rhlp nor0F38F0
    | 0xF1uy -> parseNonVEX span rhlp nor0F38F1
    | 0xF2uy -> parseVEX span rhlp notEn vex0F38F2
    | 0xF3uy ->
      if Option.isNone rhlp.VEXInfo then raise ParsingFailureException
      else parseGrpOp span rhlp OpGroup.G17 OD.VvRm SZ.Def
    | 0xF5uy ->
      parseVEXW span rhlp nor0F38F5W0 nor0F38F5W1 vex0F38F5W0 vex0F38F5W1
    | 0xF6uy ->
      parseVEXW span rhlp nor0F38F6W0 nor0F38F6W1 vex0F38F6W0 vex0F38F6W1
    | 0xF7uy -> parseVEX span rhlp nor0F38F7 vex0F38F7
    | _ -> raise ParsingFailureException

  /// When the first two bytes are 0F3A.
  /// Table A-5 of Volume 2 (Three-byte Opcode Map : First Two Bytes are 0F 3AH)
  let parseThreeByteOp2 span (rhlp: ReadHelper) =
    match rhlp.ReadByte span with
    | 0x00uy -> parseEVEXW span rhlp notEn vex0F3A00W1 notEn notEn
    | 0x01uy -> parseEVEXW span rhlp notEn vex0F3A01W1 notEn notEn
    | 0x02uy -> parseEVEXW span rhlp vex0F3A02W0 notEn notEn notEn
    | 0x04uy -> parseEVEXW span rhlp vex0F3A04W0 notEn notEn notEn
    | 0x05uy -> parseEVEXW span rhlp vex0F3A05W0 notEn notEn notEn
    | 0x06uy -> parseVEXW span rhlp notEn notEn vex0F3A06W0 notEn
    | 0x08uy -> parseVEX span rhlp nor0F3A08 vex0F3A08
    | 0x09uy -> parseVEX span rhlp nor0F3A09 vex0F3A09
    | 0x0Auy -> parseVEX span rhlp nor0F3A0A vex0F3A0A
    | 0x0Buy -> parseEVEX span rhlp nor0F3A0B vex0F3A0B notEn evex0F3A0BW1
    | 0x0Cuy -> parseVEX span rhlp nor0F3A0C vex0F3A0C
    | 0x0Duy -> parseVEX span rhlp nor0F3A0D vex0F3A0D
    | 0x0Euy -> parseVEX span rhlp nor0F3A0E vex0F3A0E
    | 0x0Fuy -> parseVEX span rhlp nor0F3A0F vex0F3A0F
    | 0x14uy -> parseVEXW span rhlp nor0F3A14 nor0F3A14 vex0F3A14W0 notEn
    | 0x15uy -> parseVEX span rhlp nor0F3A15 vex0F3A15
    | 0x16uy ->
      parseEVEXAll span rhlp nor0F3A16W0 nor0F3A16W1 vex0F3A16W0 notEn
        evex0F3A16W0 notEn
    | 0x17uy -> parseEVEX span rhlp nor0F3A17 vex0F3A17 notEn notEn
    | 0x18uy -> parseEVEXW span rhlp vex0F3A18W0 notEn notEn notEn
    | 0x19uy -> parseEVEXW span rhlp vex0F3A19W0 notEn evex0F3A19W0 evex0F3A19W1
    | 0x1Auy -> parseEVEXW span rhlp notEn notEn notEn evex0F3A1AW1
    | 0x1Buy -> parseEVEXW span rhlp notEn notEn evex0F3A1BW0 evex0F3A1BW1
    | 0x1Euy -> parseEVEXW span rhlp notEn notEn evex0F3A1EW0 evex0F3A1EW1
    | 0x20uy -> parseVEX span rhlp nor0F3A20 vex0F3A20
    | 0x21uy -> parseVEX span rhlp nor0F3A21 vex0F3A21
    | 0x22uy ->
      parseEVEXAll span rhlp nor0F3A22W0 nor0F3A22W1 vex0F3A22W0 vex0F3A22W1
        evex0F3A22W0 evex0F3A22W1
    | 0x25uy -> parseEVEXW span rhlp notEn notEn evex0F3A25W0 evex0F3A25W1
    | 0x27uy -> parseEVEXW span rhlp notEn notEn notEn evex0F3A27W1
    | 0x38uy -> parseVEX span rhlp nor0F3A38 vex0F3A38
    | 0x39uy -> parseEVEXW span rhlp vex0F3A39W0 notEn notEn notEn
    | 0x3Auy -> parseEVEXW span rhlp notEn notEn evex0F3A3AW0 evex0F3A3AW1
    | 0x3Buy -> parseEVEXW span rhlp notEn notEn evex0F3A3BW0 evex0F3A3BW1
    | 0x3Euy -> parseEVEXW span rhlp notEn notEn evex0F3A3EW0 evex0F3A3EW1
    | 0x40uy -> parseVEX span rhlp nor0F3A40 notEn
    | 0x41uy -> parseVEX span rhlp nor0F3A41 notEn
    | 0x42uy -> parseVEX span rhlp nor0F3A42 notEn
    | 0x43uy -> parseEVEXW span rhlp notEn notEn evex0F3A43W0 evex0F3A43W1
    | 0x44uy -> parseEVEX span rhlp nor0F3A44 vex0F3A44 evex0F3A44 evex0F3A44
    | 0x46uy -> parseEVEXW span rhlp vex0F3A46W0 notEn notEn notEn
    | 0x4Auy -> parseVEXW span rhlp notEn notEn vex0F3A4AW0 notEn
    | 0x4Buy -> parseVEXW span rhlp notEn notEn vex0F3A4BW0 notEn
    | 0x4Cuy -> parseVEXW span rhlp notEn notEn vex0F3A4CW0 notEn
    | 0x57uy -> parseEVEXW span rhlp notEn notEn notEn evex0F3A57W1
    | 0x60uy -> parseVEX span rhlp nor0F3A60 vex0F3A60
    | 0x61uy -> parseVEX span rhlp nor0F3A61 vex0F3A61
    | 0x62uy -> parseVEX span rhlp nor0F3A62 vex0F3A62
    | 0x63uy -> parseVEX span rhlp nor0F3A63 vex0F3A63
    | 0x68uy -> parseVEXW span rhlp notEn notEn vex0F3A68W0 vex0F3A68W1
    | 0x69uy -> parseVEXW span rhlp notEn notEn vex0F3A69W0 vex0F3A69W1
    | 0x6Auy -> parseVEXW span rhlp notEn notEn vex0F3A6AW0 vex0F3A6AW1
    | 0x6Buy -> parseVEXW span rhlp notEn notEn vex0F3A6BW0 vex0F3A6BW1
    | 0x70uy -> parseEVEXW span rhlp notEn notEn notEn evex0F3A70W1
    | 0x71uy -> parseEVEXW span rhlp notEn notEn evex0F3A71W0 evex0F3A71W1
    | 0x72uy -> parseEVEXW span rhlp notEn notEn notEn evex0F3A72W1
    | 0x73uy -> parseEVEXW span rhlp notEn notEn evex0F3A73W0 evex0F3A73W1
    | 0xCEuy -> parseEVEXW span rhlp notEn vex0F3ACEW1 notEn evex0F3ACEW1
    | 0xCFuy -> parseEVEXW span rhlp notEn vex0F3ACFW1 notEn evex0F3ACFW1
    | 0xDFuy -> parseVEX span rhlp nor0F3ADF notEn
    | 0xF0uy -> parseVEX span rhlp nor0F3AF0 vex0F3AF0
    | _ -> raise ParsingFailureException

  let getOpCode0F0D span (rhlp: ReadHelper) =
    let b = rhlp.PeekByte span
    match modIsMemory b, getReg b with
    | true, 0b001 -> PREFETCHW
    | true, 0b010 -> PREFETCHWT1
    | _ -> raise ParsingFailureException

  let ignOpSz (rhlp: ReadHelper) =
    rhlp.Prefixes <- rhlp.Prefixes &&& EnumOfValue 0xFDFF
    rhlp

  let pTwoByteOp span (rhlp: ReadHelper) byte =
    match byte with
    | 0x02uy -> render span rhlp LAR SzCond.Nor OD.GprRm SZ.WV
    | 0x03uy -> render span rhlp LSL SzCond.Nor OD.GprRm SZ.WV
    | 0x05uy ->
#if !EMULATION
      ensure64 rhlp
#endif
      render span rhlp SYSCALL SzCond.Nor OD.No SZ.Def
    | 0x06uy -> render span rhlp CLTS SzCond.Nor OD.No SZ.Def
    | 0x07uy ->
#if !EMULATION
      ensure64 rhlp
#endif
      render span rhlp SYSRET SzCond.Nor OD.No SZ.Def
    | 0x08uy -> render span rhlp INVD SzCond.Nor OD.No SZ.Def
    | 0x09uy -> render span rhlp WBINVD SzCond.Nor OD.No SZ.Def
    | 0x0Buy -> render span rhlp UD2 SzCond.Nor OD.No SZ.Def
    | 0x0Duy ->
      render span rhlp (getOpCode0F0D span rhlp) SzCond.Nor OD.Mem SZ.Def
    | 0x10uy -> pVEXByMem span rhlp nor0F10 nor0F10 vex0F10Mem vex0F10Reg
    | 0x11uy -> pVEXByMem span rhlp nor0F11 nor0F11 vex0F11Mem vex0F11Reg
    | 0x12uy -> pVEXByMem span rhlp nor0F12Mem nor0F12Reg vex0F12Mem vex0F12Reg
    | 0x13uy -> parseVEX span rhlp nor0F13 vex0F13
    | 0x14uy -> parseVEX span rhlp nor0F14 vex0F14
    | 0x15uy -> parseVEX span rhlp nor0F15 vex0F15
    | 0x16uy -> pVEXByMem span rhlp nor0F16Mem nor0F16Reg vex0F16Mem vex0F16Reg
    | 0x17uy -> parseVEX span rhlp nor0F17 vex0F17
    | 0x1Auy -> parseBND span rhlp SzCond.Nor nor0F1A
    | 0x1Buy -> parseBND span rhlp SzCond.Nor nor0F1B
    | 0x1Euy ->
      if hasREPZ rhlp.Prefixes then parseCETInstr span rhlp
      else raise InvalidOpcodeException
    | 0x1Fuy -> render span rhlp NOP SzCond.Nor OD.Mem SZ.Def (* NOP /0 Ev *)
    | 0x20uy -> render span rhlp MOV SzCond.F64 OD.GprCtrl SZ.DY
    | 0x21uy -> render span rhlp MOV SzCond.Nor OD.GprDbg SZ.DY
    | 0x22uy -> render span rhlp MOV SzCond.Nor OD.CtrlGpr SZ.DY
    | 0x23uy -> render span rhlp MOV SzCond.Nor OD.DbgGpr SZ.DY
    | 0x28uy -> parseVEX span rhlp nor0F28 vex0F28
    | 0x29uy -> parseVEX span rhlp nor0F29 vex0F29
    | 0x2Auy -> parseVEX span rhlp nor0F2A vex0F2A
    | 0x2Buy -> parseVEX span rhlp nor0F2B vex0F2B
    | 0x2Cuy -> parseVEX span rhlp nor0F2C vex0F2C
    | 0x2Duy -> parseVEX span rhlp nor0F2D vex0F2D
    | 0x2Euy -> parseVEX span rhlp nor0F2E vex0F2E
    | 0x2Fuy -> parseVEX span rhlp nor0F2F vex0F2F
    | 0x30uy -> render span rhlp WRMSR SzCond.Nor OD.No SZ.Def
    | 0x31uy -> render span rhlp RDTSC SzCond.Nor OD.No SZ.Def
    | 0x32uy -> render span rhlp RDMSR SzCond.Nor OD.No SZ.Def
    | 0x33uy -> render span rhlp RDPMC SzCond.Nor OD.No SZ.Def
    | 0x34uy -> render span rhlp SYSENTER SzCond.Nor OD.No SZ.Def
    | 0x35uy -> render span rhlp SYSEXIT SzCond.Nor OD.No SZ.Def
    | 0x37uy -> render span rhlp GETSEC SzCond.Nor OD.No SZ.Def
    | 0x40uy -> render span rhlp CMOVO SzCond.Nor OD.GprRm SZ.Def
    | 0x41uy -> render span rhlp CMOVNO SzCond.Nor OD.GprRm SZ.Def
    | 0x42uy -> render span rhlp CMOVB SzCond.Nor OD.GprRm SZ.Def
    | 0x43uy -> render span rhlp CMOVAE SzCond.Nor OD.GprRm SZ.Def
    | 0x44uy -> render span rhlp CMOVZ SzCond.Nor OD.GprRm SZ.Def
    | 0x45uy -> render span rhlp CMOVNZ SzCond.Nor OD.GprRm SZ.Def
    | 0x46uy -> render span rhlp CMOVBE SzCond.Nor OD.GprRm SZ.Def
    | 0x47uy -> render span rhlp CMOVA SzCond.Nor OD.GprRm SZ.Def
    | 0x48uy -> render span rhlp CMOVS SzCond.Nor OD.GprRm SZ.Def
    | 0x49uy -> render span rhlp CMOVNS SzCond.Nor OD.GprRm SZ.Def
    | 0x4Auy -> render span rhlp CMOVP SzCond.Nor OD.GprRm SZ.Def
    | 0x4Buy -> render span rhlp CMOVNP SzCond.Nor OD.GprRm SZ.Def
    | 0x4Cuy -> render span rhlp CMOVL SzCond.Nor OD.GprRm SZ.Def
    | 0x4Duy -> render span rhlp CMOVGE SzCond.Nor OD.GprRm SZ.Def
    | 0x4Euy -> render span rhlp CMOVLE SzCond.Nor OD.GprRm SZ.Def
    | 0x4Fuy -> render span rhlp CMOVG SzCond.Nor OD.GprRm SZ.Def
    | 0x50uy -> parseVEX span rhlp nor0F50 vex0F50
    | 0x51uy -> parseVEX span rhlp nor0F51 vex0F51
    | 0x52uy -> parseVEX span rhlp nor0F52 vex0F52
    | 0x53uy -> parseVEX span rhlp nor0F53 vex0F53
    | 0x54uy -> parseVEX span rhlp nor0F54 vex0F54
    | 0x55uy -> parseVEX span rhlp nor0F55 vex0F55
    | 0x56uy -> parseVEX span rhlp nor0F56 vex0F56
    | 0x57uy -> parseVEX span rhlp nor0F57 vex0F57
    | 0x58uy -> parseVEX span rhlp nor0F58 vex0F58
    | 0x59uy -> parseVEX span rhlp nor0F59 vex0F59
    | 0x5Auy -> parseEVEX span rhlp nor0F5A vex0F5A evex0F5AW0 evex0F5AW1
    | 0x5Buy -> parseVEX span rhlp nor0F5B vex0F5B
    | 0x5Cuy -> parseVEX span rhlp nor0F5C vex0F5C
    | 0x5Duy -> parseEVEX span rhlp nor0F5D vex0F5D evex0F5DW0 notEn
    | 0x5Euy -> parseVEX span rhlp nor0F5E vex0F5E
    | 0x5Fuy -> parseEVEX span rhlp nor0F5F vex0F5F evex0F5FW0 evex0F5FW1
    | 0x60uy -> parseVEX span rhlp nor0F60 vex0F60
    | 0x61uy -> parseVEX span rhlp nor0F61 vex0F61
    | 0x62uy -> parseVEX span rhlp nor0F62 vex0F62
    | 0x63uy -> parseVEX span rhlp nor0F63 vex0F63
    | 0x64uy -> parseVEX span rhlp nor0F64 vex0F64
    | 0x65uy -> parseVEX span rhlp nor0F65 vex0F65
    | 0x66uy -> parseVEX span rhlp nor0F66 vex0F66
    | 0x67uy -> parseVEX span rhlp nor0F67 vex0F67
    | 0x68uy -> parseVEX span rhlp nor0F68 vex0F68
    | 0x69uy -> parseVEX span rhlp nor0F69 vex0F69
    | 0x6Auy -> parseVEX span rhlp nor0F6A vex0F6A
    | 0x6Buy -> parseVEX span rhlp nor0F6B vex0F6B
    | 0x6Cuy -> parseVEX span rhlp nor0F6C vex0F6C
    | 0x6Duy -> parseVEX span rhlp nor0F6D vex0F6D
    | 0x6Euy -> parseVEXW span rhlp nor0F6EW0 nor0F6EW1 vex0F6EW0 vex0F6EW1
    | 0x6Fuy -> parseEVEX span rhlp nor0F6F vex0F6F evex0F6FW0 evex0F6FW1
    | 0x70uy -> parseVEX span rhlp nor0F70 vex0F70
    | 0x74uy -> parseVEX span rhlp nor0F74 vex0F74
    | 0x75uy -> parseVEX span rhlp nor0F75 vex0F75
    | 0x76uy -> parseVEX span rhlp nor0F76 vex0F76
    | 0x77uy -> parseVEX span rhlp nor0F77 vex0F77
    | 0x78uy -> parseEVEX span rhlp nor0F78 notEn evex0F78W0 evex0F78W1
    | 0x7Auy -> parseEVEX span rhlp notEn notEn evex0F7AW0 evex0F7AW1
    | 0x7Buy -> parseEVEXW span rhlp notEn notEn evex0F7BW0 evex0F7BW1
    | 0x7Cuy -> parseVEX span rhlp nor0F7C vex0F7C
    | 0x7Duy -> parseVEX span rhlp nor0F7D vex0F7D
    | 0x7Euy -> parseVEXW span rhlp nor0F7EW0 nor0F7EW1 vex0F7EW0 vex0F7EW1
    | 0x7Fuy -> parseEVEX span rhlp nor0F7F vex0F7F evex0F7FW0 evex0F7FW1
    | 0x80uy -> addBND rhlp; render span rhlp JO SzCond.F64 OD.Rel SZ.D64
    | 0x81uy -> addBND rhlp; render span rhlp JNO SzCond.F64 OD.Rel SZ.D64
    | 0x82uy -> addBND rhlp; render span rhlp JB SzCond.F64 OD.Rel SZ.D64
    | 0x83uy -> addBND rhlp; render span rhlp JNB SzCond.F64 OD.Rel SZ.D64
    | 0x84uy -> addBND rhlp; render span rhlp JZ SzCond.F64 OD.Rel SZ.D64
    | 0x85uy -> addBND rhlp; render span rhlp JNZ SzCond.F64 OD.Rel SZ.D64
    | 0x86uy -> addBND rhlp; render span rhlp JBE SzCond.F64 OD.Rel SZ.D64
    | 0x87uy -> addBND rhlp; render span rhlp JA SzCond.F64 OD.Rel SZ.D64
    | 0x88uy -> addBND rhlp; render span rhlp JS SzCond.F64 OD.Rel SZ.D64
    | 0x89uy -> addBND rhlp; render span rhlp JNS SzCond.F64 OD.Rel SZ.D64
    | 0x8Auy -> addBND rhlp; render span rhlp JP SzCond.F64 OD.Rel SZ.D64
    | 0x8Buy -> addBND rhlp; render span rhlp JNP SzCond.F64 OD.Rel SZ.D64
    | 0x8Cuy -> addBND rhlp; render span rhlp JL SzCond.F64 OD.Rel SZ.D64
    | 0x8Duy -> addBND rhlp; render span rhlp JNL SzCond.F64 OD.Rel SZ.D64
    | 0x8Euy -> addBND rhlp; render span rhlp JLE SzCond.F64 OD.Rel SZ.D64
    | 0x8Fuy -> addBND rhlp; render span rhlp JG SzCond.F64 OD.Rel SZ.D64
    | 0x90uy -> render span rhlp SETO SzCond.Nor OD.Mem SZ.Byte
    | 0x91uy -> render span rhlp SETNO SzCond.Nor OD.Mem SZ.Byte
    | 0x92uy -> render span rhlp SETB SzCond.Nor OD.Mem SZ.Byte
    | 0x93uy -> render span rhlp SETNB SzCond.Nor OD.Mem SZ.Byte
    | 0x94uy -> render span rhlp SETZ SzCond.Nor OD.Mem SZ.Byte
    | 0x95uy -> render span rhlp SETNZ SzCond.Nor OD.Mem SZ.Byte
    | 0x96uy -> render span rhlp SETBE SzCond.Nor OD.Mem SZ.Byte
    | 0x97uy -> render span rhlp SETA SzCond.Nor OD.Mem SZ.Byte
    | 0x98uy -> render span rhlp SETS SzCond.Nor OD.Mem SZ.Byte
    | 0x99uy -> render span rhlp SETNS SzCond.Nor OD.Mem SZ.Byte
    | 0x9Auy -> render span rhlp SETP SzCond.Nor OD.Mem SZ.Byte
    | 0x9Buy -> render span rhlp SETNP SzCond.Nor OD.Mem SZ.Byte
    | 0x9Cuy -> render span rhlp SETL SzCond.Nor OD.Mem SZ.Byte
    | 0x9Duy -> render span rhlp SETNL SzCond.Nor OD.Mem SZ.Byte
    | 0x9Euy -> render span rhlp SETLE SzCond.Nor OD.Mem SZ.Byte
    | 0x9Fuy -> render span rhlp SETG SzCond.Nor OD.Mem SZ.Byte
    | 0xA0uy -> render span rhlp PUSH SzCond.D64 OD.Fs SZ.RegW
    | 0xA1uy -> render span rhlp POP SzCond.D64 OD.Fs SZ.RegW
    | 0xA2uy -> render span rhlp CPUID SzCond.Nor OD.No SZ.Def
    | 0xA3uy -> render span rhlp BT SzCond.Nor OD.RmGpr SZ.Def
    | 0xA4uy -> render span rhlp SHLD SzCond.Nor OD.XmRegImm8 SZ.Def
    | 0xA5uy -> render span rhlp SHLD SzCond.Nor OD.RmGprCL SZ.Def
    | 0xA8uy -> render span rhlp PUSH SzCond.D64 OD.Gs SZ.RegW
    | 0xA9uy -> render span rhlp POP SzCond.D64 OD.Gs SZ.RegW
    | 0xAAuy -> render span rhlp RSM SzCond.Nor OD.No SZ.Def
    | 0xABuy -> render span rhlp BTS SzCond.Nor OD.RmGpr SZ.Def
    | 0xACuy -> render span rhlp SHRD SzCond.Nor OD.XmRegImm8 SZ.Def
    | 0xADuy -> render span rhlp SHRD SzCond.Nor OD.RmGprCL SZ.Def
    | 0xAFuy -> render span rhlp IMUL SzCond.Nor OD.GprRm SZ.Def
    | 0xB0uy -> render span rhlp CMPXCHG SzCond.Nor OD.RmGpr SZ.Byte
    | 0xB1uy -> render span rhlp CMPXCHG SzCond.Nor OD.RmGpr SZ.Def
    | 0xB2uy -> render span rhlp LSS SzCond.Nor OD.GprM SZ.PRM
    | 0xB3uy -> render span rhlp BTR SzCond.Nor OD.RmGpr SZ.Def
    | 0xB4uy -> render span rhlp LFS SzCond.Nor OD.GprM SZ.PRM
    | 0xB5uy -> render span rhlp LGS SzCond.Nor OD.GprM SZ.PRM
    | 0xB6uy -> render span rhlp MOVZX SzCond.Nor OD.GprRm SZ.BV
    | 0xB7uy -> render span rhlp MOVZX SzCond.Nor OD.GprRm SZ.WV
    | 0xB8uy when not <| hasREPZ rhlp.Prefixes -> raise ParsingFailureException
    | 0xB8uy ->
      rhlp.Prefixes <- filterPrefs rhlp.Prefixes
      render span rhlp POPCNT SzCond.Nor OD.GprRm SZ.Def
    | 0xBBuy when hasREPZ rhlp.Prefixes -> raise ParsingFailureException
    | 0xBBuy -> render span rhlp BTC SzCond.Nor OD.RmGpr SZ.Def
    | 0xBCuy when hasREPZ rhlp.Prefixes ->
      rhlp.Prefixes <- filterPrefs rhlp.Prefixes
      render span rhlp TZCNT SzCond.Nor OD.GprRm SZ.Def
    | 0xBCuy -> render span rhlp BSF SzCond.Nor OD.GprRm SZ.Def
    | 0xBDuy when hasREPZ rhlp.Prefixes ->
      rhlp.Prefixes <- filterPrefs rhlp.Prefixes
      render span rhlp LZCNT SzCond.Nor OD.GprRm SZ.Def
    | 0xBDuy -> render span rhlp BSR SzCond.Nor OD.GprRm SZ.Def
    | 0xBEuy -> render span rhlp MOVSX SzCond.Nor OD.GprRm SZ.BV
    | 0xBFuy -> render span rhlp MOVSX SzCond.Nor OD.GprRm SZ.WV
    | 0xC0uy -> render span rhlp XADD SzCond.Nor OD.RmGpr SZ.Byte
    | 0xC1uy -> render span rhlp XADD SzCond.Nor OD.RmGpr SZ.Def
    | 0xC2uy -> parseEVEX span rhlp nor0FC2 vex0FC2 evex0FC2W0 evex0FC2W1
    | 0xC3uy -> render span rhlp MOVNTI SzCond.Nor OD.RmGpr SZ.Def
    | 0xC4uy -> parseVEX span rhlp nor0FC4 vex0FC4
    | 0xC5uy -> parseVEX span rhlp nor0FC5 vex0FC5
    | 0xC6uy -> parseVEX span rhlp nor0FC6 vex0FC6
    | 0xC8uy -> render span (ignOpSz rhlp) BSWAP SzCond.Nor OD.Rax SZ.Def
    | 0xC9uy -> render span (ignOpSz rhlp) BSWAP SzCond.Nor OD.Rcx SZ.Def
    | 0xCAuy -> render span (ignOpSz rhlp) BSWAP SzCond.Nor OD.Rdx SZ.Def
    | 0xCBuy -> render span (ignOpSz rhlp) BSWAP SzCond.Nor OD.Rbx SZ.Def
    | 0xCCuy -> render span (ignOpSz rhlp) BSWAP SzCond.Nor OD.Rsp SZ.Def
    | 0xCDuy -> render span (ignOpSz rhlp) BSWAP SzCond.Nor OD.Rbp SZ.Def
    | 0xCEuy -> render span (ignOpSz rhlp) BSWAP SzCond.Nor OD.Rsi SZ.Def
    | 0xCFuy -> render span (ignOpSz rhlp) BSWAP SzCond.Nor OD.Rdi SZ.Def
    | 0xD0uy -> parseVEX span rhlp nor0FD0 vex0FD0
    | 0xD1uy -> parseVEX span rhlp nor0FD1 vex0FD1
    | 0xD2uy -> parseVEX span rhlp nor0FD2 vex0FD2
    | 0xD3uy -> parseVEX span rhlp nor0FD3 vex0FD3
    | 0xD4uy -> parseVEX span rhlp nor0FD4 vex0FD4
    | 0xD5uy -> parseVEX span rhlp nor0FD5 vex0FD5
    | 0xD6uy ->
#if !EMULATION
      ensureVEX128 rhlp
#endif
      parseVEX span rhlp nor0FD6 vex0FD6
    | 0xD7uy -> parseVEX span rhlp nor0FD7 vex0FD7
    | 0xD8uy -> parseVEX span rhlp nor0FD8 vex0FD8
    | 0xD9uy -> parseVEX span rhlp nor0FD9 vex0FD9
    | 0xDAuy -> parseVEX span rhlp nor0FDA vex0FDA
    | 0xDBuy -> parseVEX span rhlp nor0FDB vex0FDB
    | 0xDCuy -> parseVEX span rhlp nor0FDC vex0FDC
    | 0xDDuy -> parseVEX span rhlp nor0FDD vex0FDD
    | 0xDEuy -> parseVEX span rhlp nor0FDE vex0FDE
    | 0xDFuy -> parseVEX span rhlp nor0FDF vex0FDF
    | 0xE0uy -> parseVEX span rhlp nor0FE0 vex0FE0
    | 0xE1uy -> parseVEX span rhlp nor0FE1 vex0FE1
    | 0xE2uy -> parseVEX span rhlp nor0FE2 vex0FE2
    | 0xE3uy -> parseVEX span rhlp nor0FE3 vex0FE3
    | 0xE4uy -> parseVEX span rhlp nor0FE4 vex0FE4
    | 0xE5uy -> parseVEX span rhlp nor0FE5 vex0FE5
    | 0xE6uy -> parseEVEX span rhlp nor0FE6 vex0FE6 evex0FE6W0 evex0FE6W1
    | 0xE7uy -> parseEVEX span rhlp nor0FE7 vex0FE7 evex0FE7W0 evex0FE7W1
    | 0xE8uy -> parseVEX span rhlp nor0FE8 vex0FE8
    | 0xE9uy -> parseVEX span rhlp nor0FE9 vex0FE9
    | 0xEAuy -> parseVEX span rhlp nor0FEA vex0FEA
    | 0xEBuy -> parseVEX span rhlp nor0FEB vex0FEB
    | 0xECuy -> parseVEX span rhlp nor0FEC vex0FEC
    | 0xEDuy -> parseVEX span rhlp nor0FED vex0FED
    | 0xEEuy -> parseVEX span rhlp nor0FEE vex0FEE
    | 0xEFuy -> parseEVEX span rhlp nor0FEF vex0FEF evex0FEFW0 evex0FEFW1
    | 0xF0uy -> parseVEX span rhlp nor0FF0 vex0FF0
    | 0xF1uy -> parseVEX span rhlp nor0FF1 vex0FF1
    | 0xF2uy -> parseVEX span rhlp nor0FF2 vex0FF2
    | 0xF3uy -> parseVEX span rhlp nor0FF3 vex0FF3
    | 0xF4uy -> parseVEX span rhlp nor0FF4 vex0FF4
    | 0xF5uy -> parseVEX span rhlp nor0FF5 vex0FF5
    | 0xF6uy -> parseVEX span rhlp nor0FF6 vex0FF6
    | 0xF8uy -> parseVEX span rhlp nor0FF8 vex0FF8
    | 0xF9uy -> parseVEX span rhlp nor0FF9 vex0FF9
    | 0xFAuy -> parseVEX span rhlp nor0FFA vex0FFA
    | 0xFBuy -> parseVEX span rhlp nor0FFB vex0FFB
    | 0xFCuy -> parseVEX span rhlp nor0FFC vex0FFC
    | 0xFDuy -> parseVEX span rhlp nor0FFD vex0FFD
    | 0xFEuy -> parseVEX span rhlp nor0FFE vex0FFE
    | 0x00uy -> parseGrpOp span rhlp OpGroup.G6 OD.No SZ.Def
    | 0x01uy -> parseGrpOp span rhlp OpGroup.G7 OD.No SZ.Def
    | 0xBAuy -> parseGrpOp span rhlp OpGroup.G8 OD.RmImm8 SZ.Def
    | 0xC7uy -> parseGrpOp span rhlp OpGroup.G9 OD.No SZ.Def
    | 0x71uy -> parseGrpOp span rhlp OpGroup.G12 OD.No SZ.Def
    | 0x72uy -> parseGrpOp span rhlp OpGroup.G13 OD.No SZ.Def
    | 0x73uy -> parseGrpOp span rhlp OpGroup.G14 OD.No SZ.Def
    | 0xAEuy -> parseGrpOp span rhlp OpGroup.G15 OD.No SZ.Def
    | 0x18uy -> parseGrpOp span rhlp OpGroup.G16 OD.Mem SZ.Def
    | 0x38uy -> parseThreeByteOp1 span rhlp
    | 0x3Auy -> parseThreeByteOp2 span rhlp
    | _ -> raise ParsingFailureException

  (* Table A-3 of Volume 2 (Two-byte Opcode Map) *)
  let parseTwoByteOpcode span (rhlp: ReadHelper) =
    pTwoByteOp span rhlp (rhlp.ReadByte span)

end
