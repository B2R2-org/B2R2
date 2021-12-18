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

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.Intel
open B2R2.FrontEnd.BinLifter.Intel.Helper
open LanguagePrimitives

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

  let getTwoVEXInfo (reader: BinReader) (rex: byref<REXPrefix>) pos =
    let b = reader.PeekByte pos
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

  let getThreeVEXInfo (reader: BinReader) (rex: byref<REXPrefix>) pos =
    let b1 = reader.PeekByte pos
    let b2 = reader.PeekByte (pos + 1)
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

  let getEVEXInfo (reader: BinReader) (rex: byref<REXPrefix>) pos =
    let b1 = reader.PeekByte pos
    let b2 = reader.PeekByte (pos + 1)
    let l'l = reader.PeekByte (pos + 2) >>> 5 &&& 0b011uy
    let vLen = getVLen l'l
    let aaa = reader.PeekByte (pos + 2) &&& 0b111uy
    let z = if (reader.PeekByte (pos + 2) >>> 7 &&& 0b1uy) = 0uy then Zeroing
            else Merging
    let b = (reader.PeekByte (pos + 2) >>> 4) &&& 0b1uy
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
    | b when b >= 0xC0uy && b <= 0xC7uy ->
      Opcode.FFREEP (* FIXME: Undocumented x87 instructions *)
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
    | MPref.MPrxNP -> struct (Opcode.MOVUPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (Opcode.MOVUPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> struct (Opcode.MOVSS, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrxF2 -> struct (Opcode.MOVSD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F10Mem = function
    | MPref.MPrxNP -> struct (Opcode.VMOVUPS, OD.GprRm, SZ.VecDef) (* VpsWps *)
    | MPref.MPrx66 -> struct (Opcode.VMOVUPD, OD.GprRm, SZ.VecDef) (* VpdWpd *)
    | MPref.MPrxF3 -> struct (Opcode.VMOVSS, OD.GprRm, SZ.DqdDq) (* VdqMd *)
    | MPref.MPrxF2 -> struct (Opcode.VMOVSD, OD.GprRm, SZ.DqqDq) (* VdqMq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F10Reg = function
    | MPref.MPrxNP -> struct (Opcode.VMOVUPS, OD.GprRm, SZ.VecDef) (* VpsWps *)
    | MPref.MPrx66 -> struct (Opcode.VMOVUPD, OD.GprRm, SZ.VecDef) (* VpdWpd *)
    | MPref.MPrxF3 -> struct (Opcode.VMOVSS, OD.XmmVvXm, SZ.VecDef) (* VxHxWss *)
    | MPref.MPrxF2 -> struct (Opcode.VMOVSD, OD.XmmVvXm, SZ.VecDef) (* VxHxWsd *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F11 = function
    | MPref.MPrxNP -> struct (Opcode.MOVUPS, OD.RmGpr, SZ.DqDq) (* WdqVdq *)
    | MPref.MPrx66 -> struct (Opcode.MOVUPD, OD.RmGpr, SZ.DqDq) (* WdqVdq *)
    | MPref.MPrxF3 -> struct (Opcode.MOVSS, OD.RmGpr, SZ.DqdDqMR) (* WdqdVdq *)
    | MPref.MPrxF2 -> struct (Opcode.MOVSD, OD.RmGpr, SZ.DqqDq) (* WdqqVdq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F11Mem = function
    | MPref.MPrxNP -> struct (Opcode.VMOVUPS, OD.RmGpr, SZ.VecDef) (* WpsVps *)
    | MPref.MPrx66 -> struct (Opcode.VMOVUPD, OD.RmGpr, SZ.VecDef) (* WpdVpd *)
    | MPref.MPrxF3 -> struct (Opcode.VMOVSS, OD.RmGpr, SZ.DqdDqMR) (* MdVdq *)
    | MPref.MPrxF2 -> struct (Opcode.VMOVSD, OD.RmGpr, SZ.DqqDq) (* MqVdq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F11Reg = function
    | MPref.MPrxNP -> struct (Opcode.VMOVUPS, OD.RmGpr, SZ.VecDef) (* WpsVps *)
    | MPref.MPrx66 -> struct (Opcode.VMOVUPD, OD.RmGpr, SZ.VecDef) (* WpdVpd *)
    | MPref.MPrxF3 -> struct (Opcode.VMOVSS, OD.XmVvXmm, SZ.VecDef) (* WssHxVss *)
    | MPref.MPrxF2 -> struct (Opcode.VMOVSD, OD.XmVvXmm, SZ.VecDef) (* WsdHxVsd *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F12Mem = function
    | MPref.MPrxNP -> struct (Opcode.MOVLPS, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrx66 -> struct (Opcode.MOVLPD, OD.GprRm, SZ.DqqDq) (* VdqMq *)
    | MPref.MPrxF3 -> struct (Opcode.MOVSLDUP, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF2 -> struct (Opcode.MOVDDUP, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F12Reg = function
    | MPref.MPrxNP -> struct (Opcode.MOVHLPS, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrx66 -> struct (Opcode.MOVLPD, OD.GprRm, SZ.DqqDq) (* VdqMq *)
    | MPref.MPrxF3 -> struct (Opcode.MOVSLDUP, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF2 -> struct (Opcode.MOVDDUP, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F12Mem = function
    | MPref.MPrxNP ->
      struct (Opcode.VMOVLPS, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrx66 -> struct (Opcode.VMOVLPD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqMq *)
    | MPref.MPrxF3 -> struct (Opcode.VMOVSLDUP, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF2 -> struct (Opcode.VMOVDDUP, OD.GprRm, SZ.XqX) (* VxWxq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F12Reg = function
    | MPref.MPrxNP ->
      struct (Opcode.VMOVHLPS, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrx66 -> struct (Opcode.VMOVLPD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqMq *)
    | MPref.MPrxF3 -> struct (Opcode.VMOVSLDUP, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF2 -> struct (Opcode.VMOVDDUP, OD.GprRm, SZ.XqX) (* VxWxq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F13 = function
    | MPref.MPrxNP -> struct (Opcode.MOVLPS, OD.RmGpr, SZ.DqqDq) (* MqVdq *)
    | MPref.MPrx66 -> struct (Opcode.MOVLPD, OD.RmGpr, SZ.DqqDq) (* MqVdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F13 = function
    | MPref.MPrxNP -> struct (Opcode.VMOVLPS, OD.RmGpr, SZ.DqqDq) (* MqVdq *)
    | MPref.MPrx66 -> struct (Opcode.VMOVLPD, OD.RmGpr, SZ.DqqDq) (* MqVdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F14 = function
    | MPref.MPrxNP -> struct (Opcode.UNPCKLPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (Opcode.UNPCKLPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F14 = function
    | MPref.MPrxNP ->
      struct (Opcode.VUNPCKLPS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrx66 ->
      struct (Opcode.VUNPCKLPD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F15 = function
    | MPref.MPrxNP -> struct (Opcode.UNPCKHPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (Opcode.UNPCKHPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F15 = function
    | MPref.MPrxNP ->
      struct (Opcode.VUNPCKHPS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrx66 ->
      struct (Opcode.VUNPCKHPD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F16Mem = function
    | MPref.MPrxNP -> struct (Opcode.MOVHPS, OD.GprRm, SZ.DqqDq) (* VdqMq *)
    | MPref.MPrx66 -> struct (Opcode.MOVHPD, OD.GprRm, SZ.DqqDq) (* VdqMq *)
    | MPref.MPrxF3 -> struct (Opcode.MOVSHDUP, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F16Reg = function
    | MPref.MPrxNP -> struct (Opcode.MOVLHPS, OD.GprRm, SZ.DqDq) (* VdqUdq *)
    | MPref.MPrx66 -> struct (Opcode.MOVHPD, OD.GprRm, SZ.DqqDq) (* VdqMq *)
    | MPref.MPrxF3 -> struct (Opcode.MOVSHDUP, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F16Mem = function
    | MPref.MPrxNP -> struct (Opcode.VMOVHPS, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqMq *)
    | MPref.MPrx66 -> struct (Opcode.VMOVHPD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqMq *)
    | MPref.MPrxF3 -> struct (Opcode.VMOVSHDUP, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F16Reg = function
    | MPref.MPrxNP ->
      struct (Opcode.VMOVLHPS, OD.XmmVvXm, SZ.DqDq) (* VdqHdqUdq *)
    | MPref.MPrx66 ->
      struct (Opcode.VMOVHPD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqMq *)
    | MPref.MPrxF3 -> struct (Opcode.VMOVSHDUP, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F17 = function
    | MPref.MPrxNP -> struct (Opcode.MOVHPS, OD.RmGpr, SZ.DqqDq) (* MqVdq *)
    | MPref.MPrx66 -> struct (Opcode.MOVHPD, OD.RmGpr, SZ.DqqDq) (* MqVdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F17 = function
    | MPref.MPrxNP -> struct (Opcode.VMOVHPS, OD.RmGpr, SZ.DqqDq) (* MqVdq *)
    | MPref.MPrx66 -> struct (Opcode.VMOVHPD, OD.RmGpr, SZ.DqqDq) (* MqVdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F1A = function
    | MPref.MPrxNP -> struct (Opcode.BNDLDX, OD.BndRm, SZ.VyDq) (* BNMib *)
    | MPref.MPrx66 -> struct (Opcode.BNDMOV, OD.BndBm, SZ.DqqDqWS) (* BNBNdqq *)
    | MPref.MPrxF3 -> struct (Opcode.BNDCL, OD.BndRm, SZ.VyDq) (* BNEv *)
    | MPref.MPrxF2 -> struct (Opcode.BNDCU, OD.BndRm, SZ.VyDq) (* BNEv *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F1B = function
    | MPref.MPrxNP -> struct (Opcode.BNDSTX, OD.RmBnd, SZ.VyDqMR) (* MibBN *)
    | MPref.MPrx66 -> struct (Opcode.BNDMOV, OD.BmBnd, SZ.DqqDqWS) (* BNdqqBN *)
    | MPref.MPrxF3 -> struct (Opcode.BNDMK, OD.BndRm, SZ.VyDq) (* BNMv *)
    | MPref.MPrxF2 -> struct (Opcode.BNDCN, OD.BndRm, SZ.VyDq) (* BNEv *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F28 = function
    | MPref.MPrxNP -> struct (Opcode.MOVAPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (Opcode.MOVAPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F28 = function
    | MPref.MPrxNP -> struct (Opcode.VMOVAPS, OD.GprRm, SZ.VecDef) (* VpsWps *)
    | MPref.MPrx66 -> struct (Opcode.VMOVAPD, OD.GprRm, SZ.VecDef) (* VpdWpd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F29 = function
    | MPref.MPrxNP -> struct (Opcode.MOVAPS, OD.RmGpr, SZ.DqDq) (* WdqVdq *)
    | MPref.MPrx66 -> struct (Opcode.MOVAPD, OD.RmGpr, SZ.DqDq) (* WdqVdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F29 = function
    | MPref.MPrxNP -> struct (Opcode.VMOVAPS, OD.RmGpr, SZ.VecDef) (* WpsVps *)
    | MPref.MPrx66 -> struct (Opcode.VMOVAPD, OD.RmGpr, SZ.VecDef) (* WpdVpd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F2A = function
    | MPref.MPrxNP -> struct (Opcode.CVTPI2PS, OD.GprRMm, SZ.QDq) (* VdqQpi *)
    | MPref.MPrx66 -> struct (Opcode.CVTPI2PD, OD.GprRMm, SZ.QDq) (* VdqQpi *)
    | MPref.MPrxF3 -> struct (Opcode.CVTSI2SS, OD.GprRm, SZ.VyDq) (* VdqEy *)
    | MPref.MPrxF2 -> struct (Opcode.CVTSI2SD, OD.GprRm, SZ.VyDq) (* VdqEy *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F2A = function
    | MPref.MPrxNP
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 ->
      struct (Opcode.VCVTSI2SS, OD.XmmVvXm, SZ.VyDq) (* VssHssEy *)
    | MPref.MPrxF2 ->
      struct (Opcode.VCVTSI2SD, OD.XmmVvXm, SZ.VyDq) (* VsdHsdEy *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F2B = function
    | MPref.MPrxNP -> struct (Opcode.MOVNTPS, OD.RmGpr, SZ.DqDq) (* MdqVdq *)
    | MPref.MPrx66 -> struct (Opcode.MOVNTPD, OD.RmGpr, SZ.DqDq) (* MdqVdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F2B = function
    | MPref.MPrxNP -> struct (Opcode.VMOVNTPS, OD.RmGpr, SZ.VecDef) (* MpsVps *)
    | MPref.MPrx66 -> struct (Opcode.VMOVNTPD, OD.RmGpr, SZ.VecDef) (* MpdVpd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F2C = function
    | MPref.MPrxNP ->
      struct (Opcode.CVTTPS2PI, OD.MmxMm, SZ.DqqQ) (* PpiWdqq *)
    | MPref.MPrx66 -> struct (Opcode.CVTTPD2PI, OD.MmxMm, SZ.DqQ) (* PpiWdq *)
    | MPref.MPrxF3 -> struct (Opcode.CVTTSS2SI, OD.GprRm, SZ.DqdY) (* GyWdqd *)
    | MPref.MPrxF2 -> struct (Opcode.CVTTSD2SI, OD.GprRm, SZ.DqqY) (* GyWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F2C = function
    | MPref.MPrxNP
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 -> struct (Opcode.VCVTTSS2SI, OD.GprRm, SZ.DqdY) (* GyWdqd *)
    | MPref.MPrxF2 -> struct (Opcode.VCVTTSD2SI, OD.GprRm, SZ.DqqY) (* GyWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F2D = function
    | MPref.MPrxNP -> struct (Opcode.CVTPS2PI, OD.MmxMm, SZ.DqqQ) (* PpiWdqq *)
    | MPref.MPrx66 -> struct (Opcode.CVTPD2PI, OD.MmxMm, SZ.DqQ) (* PpiWdq *)
    | MPref.MPrxF3 -> struct (Opcode.CVTSS2SI, OD.GprRm, SZ.DqdY) (* GyWdqd *)
    | MPref.MPrxF2 -> struct (Opcode.CVTSD2SI, OD.GprRm, SZ.DqqY) (* GyWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F2D = function
    | MPref.MPrxNP
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 -> struct (Opcode.VCVTSS2SI, OD.GprRm, SZ.DqdY) (* GyWdqd *)
    | MPref.MPrxF2 -> struct (Opcode.VCVTSD2SI, OD.GprRm, SZ.DqqY) (* GyWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F2E = function
    | MPref.MPrxNP -> struct (Opcode.UCOMISS, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrx66 -> struct (Opcode.UCOMISD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F2E = function
    | MPref.MPrxNP -> struct (Opcode.VUCOMISS, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrx66 -> struct (Opcode.VUCOMISD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F2F = function
    | MPref.MPrxNP -> struct (Opcode.COMISS, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrx66 -> struct (Opcode.COMISD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F2F = function
    | MPref.MPrxNP -> struct (Opcode.VCOMISS, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrx66 -> struct (Opcode.VCOMISD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F50 = function
    | MPref.MPrxNP -> struct (Opcode.MOVMSKPS, OD.GprRm, SZ.DqY) (* GyUdq *)
    | MPref.MPrx66 -> struct (Opcode.MOVMSKPD, OD.GprRm, SZ.DqY) (* GyUdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F50 = function
    | MPref.MPrxNP -> struct (Opcode.VMOVMSKPS, OD.GprRm, SZ.DqY) (* GyUdq *)
    | MPref.MPrx66 -> struct (Opcode.VMOVMSKPD, OD.GprRm, SZ.DqY) (* GyUdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F51 = function
    | MPref.MPrxNP -> struct (Opcode.SQRTPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (Opcode.SQRTPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> struct (Opcode.SQRTSS, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrxF2 -> struct (Opcode.SQRTSD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F51 = function
    | MPref.MPrxNP -> struct (Opcode.VSQRTPS, OD.GprRm, SZ.VecDef) (* VpsWps *)
    | MPref.MPrx66 -> struct (Opcode.VSQRTPD, OD.GprRm, SZ.VecDef) (* VpdWpd *)
    | MPref.MPrxF3 ->
      struct (Opcode.VSQRTSS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF2 ->
      struct (Opcode.VSQRTSD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F52 = function
    | MPref.MPrxNP -> struct (Opcode.RSQRTPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 -> struct (Opcode.RSQRTSS, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F52 = function
    | MPref.MPrxNP -> struct (Opcode.VRSQRTPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 ->
      struct (Opcode.VRSQRTSS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd*)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F53 = function
    | MPref.MPrxNP -> struct (Opcode.RCPPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 -> struct (Opcode.RCPSS, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F53 = function
    | MPref.MPrxNP -> struct (Opcode.VRCPPS, OD.GprRm, SZ.VecDef) (* VxHx *)
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 ->
      struct (Opcode.VRCPSS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F54 = function
    | MPref.MPrxNP -> struct (Opcode.ANDPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (Opcode.ANDPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F54 = function
    | MPref.MPrxNP ->
      struct (Opcode.VANDPS, OD.XmmVvXm, SZ.VecDef) (* VpsHpsWps *)
    | MPref.MPrx66 ->
      struct (Opcode.VANDPD, OD.XmmVvXm, SZ.VecDef) (* VpdHpdWpd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F55 = function
    | MPref.MPrxNP -> struct (Opcode.ANDNPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (Opcode.ANDNPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F55 = function
    | MPref.MPrxNP ->
      struct (Opcode.VANDNPS, OD.XmmVvXm, SZ.VecDef) (* VpsHpsWps *)
    | MPref.MPrx66 ->
      struct (Opcode.VANDNPD, OD.XmmVvXm, SZ.VecDef) (* VpdHpdWpd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F56 = function
    | MPref.MPrxNP -> struct (Opcode.ORPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (Opcode.ORPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F56 = function
    | MPref.MPrxNP -> struct (Opcode.VORPS, OD.XmmVvXm, SZ.VecDef) (* VpsHpsWps *)
    | MPref.MPrx66 -> struct (Opcode.VORPD, OD.XmmVvXm, SZ.VecDef) (* VpdHpdWpd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F57 = function
    | MPref.MPrxNP -> struct (Opcode.XORPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (Opcode.XORPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F57 = function
    | MPref.MPrxNP ->
      struct (Opcode.VXORPS, OD.XmmVvXm, SZ.VecDef) (* VpsHpsWps *)
    | MPref.MPrx66 ->
      struct (Opcode.VXORPD, OD.XmmVvXm, SZ.VecDef) (* VpdHpdWpd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F58 = function
    | MPref.MPrxNP -> struct (Opcode.ADDPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (Opcode.ADDPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> struct (Opcode.ADDSS, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrxF2 -> struct (Opcode.ADDSD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F58 = function
    | MPref.MPrxNP ->
      struct (Opcode.VADDPS, OD.XmmVvXm, SZ.VecDef) (* VpsHpsWps *)
    | MPref.MPrx66 ->
      struct (Opcode.VADDPD, OD.XmmVvXm, SZ.VecDef) (* VpdHpdWpd *)
    | MPref.MPrxF3 ->
      struct (Opcode.VADDSS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF2 ->
      struct (Opcode.VADDSD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F59 = function
    | MPref.MPrxNP -> struct (Opcode.MULPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (Opcode.MULPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> struct (Opcode.MULSS, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrxF2 -> struct (Opcode.MULSD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F59 = function
    | MPref.MPrxNP ->
      struct (Opcode.VMULPS, OD.XmmVvXm, SZ.VecDef) (* VpsHpsWps *)
    | MPref.MPrx66 ->
      struct (Opcode.VMULPD, OD.XmmVvXm, SZ.VecDef) (* VpdHpdWpd *)
    | MPref.MPrxF3 ->
      struct (Opcode.VMULSS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF2 ->
      struct (Opcode.VMULSD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F5A = function
    | MPref.MPrxNP -> struct (Opcode.CVTPS2PD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrx66 -> struct (Opcode.CVTPD2PS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> struct (Opcode.CVTSS2SD, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrxF2 -> struct (Opcode.CVTSD2SS, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F5A = function
    | MPref.MPrxNP ->
      struct (Opcode.VCVTPS2PD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrx66 -> struct (Opcode.VCVTPD2PS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 ->
      struct (Opcode.VCVTSS2SD, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF2 ->
      struct (Opcode.VCVTSD2SS, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F5AW0 = function
    | MPref.MPrxNP -> struct (Opcode.VCVTPS2PD, OD.GprRm, SZ.XqXz) (* VZxzWxq *)
    | MPref.MPrx66
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F5AW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VCVTPD2PS, OD.GprRm, SZ.XzX) (* VxWZxz *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F5B = function
    | MPref.MPrxNP -> struct (Opcode.CVTDQ2PS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (Opcode.CVTPS2DQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> struct (Opcode.CVTTPS2DQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F5B = function
    | MPref.MPrxNP -> struct (Opcode.VCVTDQ2PS, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 -> struct (Opcode.VCVTTPS2DQ, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F5C = function
    | MPref.MPrxNP -> struct (Opcode.SUBPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (Opcode.SUBPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> struct (Opcode.SUBSS, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrxF2 -> struct (Opcode.SUBSD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F5C = function
    | MPref.MPrxNP ->
      struct (Opcode.VSUBPS, OD.XmmVvXm, SZ.VecDef) (* VpsHpsWps *)
    | MPref.MPrx66 ->
      struct (Opcode.VSUBPD, OD.XmmVvXm, SZ.VecDef) (* VpdHpdWpd *)
    | MPref.MPrxF3 ->
      struct (Opcode.VSUBSS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF2 ->
      struct (Opcode.VSUBSD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F5D = function
    | MPref.MPrxNP -> struct (Opcode.MINPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (Opcode.MINPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> struct (Opcode.MINSS, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrxF2 -> struct (Opcode.MINSD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F5D = function
    | MPref.MPrxNP ->
      struct (Opcode.VMINPS, OD.XmmVvXm, SZ.VecDef) (* VpsHpsWps *)
    | MPref.MPrx66 ->
      struct (Opcode.VMINPD, OD.XmmVvXm, SZ.VecDef) (* VpdHpdWpd *)
    | MPref.MPrxF3 ->
      struct (Opcode.VMINSS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF2 ->
      struct (Opcode.VMINSD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F5DW0 = function
    | MPref.MPrxNP
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 ->
      struct (Opcode.VMINSS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F5E = function
    | MPref.MPrxNP -> struct (Opcode.DIVPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (Opcode.DIVPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> struct (Opcode.DIVSS, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrxF2 -> struct (Opcode.DIVSD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F5E = function
    | MPref.MPrxNP ->
      struct (Opcode.VDIVPS, OD.XmmVvXm, SZ.VecDef) (* VpsHpsWps *)
    | MPref.MPrx66 ->
      struct (Opcode.VDIVPD, OD.XmmVvXm, SZ.VecDef) (* VpdHpdWpd *)
    | MPref.MPrxF3 ->
      struct (Opcode.VDIVSS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF2 ->
      struct (Opcode.VDIVSD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F5F = function
    | MPref.MPrxNP -> struct (Opcode.MAXPS, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrx66 -> struct (Opcode.MAXPD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> struct (Opcode.MAXSS, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrxF2 -> struct (Opcode.MAXSD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F5F = function
    | MPref.MPrxNP ->
      struct (Opcode.VMAXPS, OD.XmmVvXm, SZ.VecDef) (* VpsHpsWps *)
    | MPref.MPrx66 ->
      struct (Opcode.VMAXPD, OD.XmmVvXm, SZ.VecDef) (* VpdHpdWpd *)
    | MPref.MPrxF3 ->
      struct (Opcode.VMAXSS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF2 ->
      struct (Opcode.VMAXSD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F5FW0 = function
    | MPref.MPrxNP -> struct (Opcode.VMAXPS, OD.XmmVvXm, SZ.XzXz) (* VZxzHxWZxz *)
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 ->
      struct (Opcode.VMAXSS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F5FW1 = function
    | MPref.MPrxNP
    | MPref.MPrx66
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 ->
      struct (Opcode.VMAXSD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F60 = function
    | MPref.MPrxNP -> struct (Opcode.PUNPCKLBW, OD.MmxRm, SZ.DQ) (* PqQd *)
    | MPref.MPrx66 -> struct (Opcode.PUNPCKLBW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F60 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPUNPCKLBW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F61 = function
    | MPref.MPrxNP -> struct (Opcode.PUNPCKLWD, OD.MmxRm, SZ.DQ) (* PqQd *)
    | MPref.MPrx66 -> struct (Opcode.PUNPCKLWD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F61 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPUNPCKLWD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F62 = function
    | MPref.MPrxNP -> struct (Opcode.PUNPCKLDQ, OD.MmxRm, SZ.DQ) (* PqQd *)
    | MPref.MPrx66 -> struct (Opcode.PUNPCKLDQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F62 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPUNPCKLDQ, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F63 = function
    | MPref.MPrxNP -> struct (Opcode.PACKSSWB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PACKSSWB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F63 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPACKSSWB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F64 = function
    | MPref.MPrxNP -> struct (Opcode.PCMPGTB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PCMPGTB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F64 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPCMPGTB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F65 = function
    | MPref.MPrxNP -> struct (Opcode.PCMPGTW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PCMPGTW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F65 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPCMPGTW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F66 = function
    | MPref.MPrxNP -> struct (Opcode.PCMPGTD, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PCMPGTD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F66 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPCMPGTD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F67 = function
    | MPref.MPrxNP -> struct (Opcode.PACKUSWB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PACKUSWB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F67 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPACKUSWB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F68 = function
    | MPref.MPrxNP -> struct (Opcode.PUNPCKHBW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PUNPCKHBW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F68 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPUNPCKHBW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F69 = function
    | MPref.MPrxNP -> struct (Opcode.PUNPCKHWD, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PUNPCKHWD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F69 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPUNPCKHWD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F6A = function
    | MPref.MPrxNP -> struct (Opcode.PUNPCKHDQ, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PUNPCKHDQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F6A = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPUNPCKHDQ, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F6B = function
    | MPref.MPrxNP -> struct (Opcode.PACKSSDW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PACKSSDW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F6B = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPACKSSDW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F6C = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.PUNPCKLQDQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F6C = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPUNPCKLQDQ, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F6D = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.PUNPCKHQDQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F6D = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPUNPCKHQDQ, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F6EW1 = function
    | MPref.MPrxNP -> struct (Opcode.MOVQ, OD.MmxMm, SZ.YQRM) (* PqEy *)
    | MPref.MPrx66 -> struct (Opcode.MOVQ, OD.GprRm, SZ.VyDq) (* VdqEy *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F6EW0 = function
    | MPref.MPrxNP -> struct (Opcode.MOVD, OD.MmxMm, SZ.YQRM) (* PqEy *)
    | MPref.MPrx66 -> struct (Opcode.MOVD, OD.GprRm, SZ.VyDq) (* VdqEy *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F6EW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VMOVQ, OD.GprRm, SZ.VyDq) (* VdqEy *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F6EW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VMOVD, OD.GprRm, SZ.VyDq) (* VdqEy *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F6F = function
    | MPref.MPrxNP -> struct (Opcode.MOVQ, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.MOVDQA, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> struct (Opcode.MOVDQU, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F6F = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VMOVDQA, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF3 -> struct (Opcode.VMOVDQU, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F6FW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VMOVDQA64, OD.GprRm, SZ.VecDef) (* VZxzWZxz *)
    | MPref.MPrxF3 ->
      struct (Opcode.VMOVDQU64, OD.GprRm, SZ.VecDef) (* VZxzWZxz *)
    | MPref.MPrxF2 ->
      struct (Opcode.VMOVDQU16, OD.GprRm, SZ.VecDef) (* VZxzWZxz *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F6FW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VMOVDQA32, OD.GprRm, SZ.VecDef) (* VZxzWZxz *)
    | MPref.MPrxF3 ->
      struct (Opcode.VMOVDQU32, OD.GprRm, SZ.VecDef) (* VZxzWZxz *)
    | MPref.MPrxF2 -> struct (Opcode.VMOVDQU8, OD.GprRm, SZ.VecDef) (* VZxzWZxz *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F70 = function
    | MPref.MPrxNP -> struct (Opcode.PSHUFW, OD.MmxMmImm8, SZ.QQ) (* PqQqIb *)
    | MPref.MPrx66 -> struct (Opcode.PSHUFD, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF3 ->
      struct (Opcode.PSHUFHW, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF2 ->
      struct (Opcode.PSHUFLW, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F70 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPSHUFD, OD.XmmRmImm8, SZ.VecDef) (* VxWxIb *)
    | MPref.MPrxF3 ->
      struct (Opcode.VPSHUFHW, OD.XmmRmImm8, SZ.VecDef) (* VxWxIb *)
    | MPref.MPrxF2 ->
      struct (Opcode.VPSHUFLW, OD.XmmRmImm8, SZ.VecDef) (* VxWxIb *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F74 = function
    | MPref.MPrxNP -> struct (Opcode.PCMPEQB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PCMPEQB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F74 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPCMPEQB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F75 = function
    | MPref.MPrxNP -> struct (Opcode.PCMPEQW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PCMPEQW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F75 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPCMPEQW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F76 = function
    | MPref.MPrxNP -> struct (Opcode.PCMPEQD, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PCMPEQD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F76 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPCMPEQD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F77 = function
    | MPref.MPrxNP -> struct (Opcode.EMMS, OD.No, SZ.Def) (* NoOpr *)
    | MPref.MPrx66
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F77 = function
    | MPref.MPrxNP -> struct (Opcode.VZEROUPPER, OD.No, SZ.Def) (* NoOpr *)
    | MPref.MPrx66
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F78 = function
    | MPref.MPrxNP -> struct (Opcode.VMREAD, OD.RmGpr, SZ.Def) (* EyGy *)
    | MPref.MPrx66 -> (* FIXME: Undocumented instruction *)
      struct (Opcode.EXTRQ, OD.RmImm8Imm8, SZ.Dq) (* VdqUdqIbIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 -> (* FIXME: Undocumented instruction *)
      struct (Opcode.INSERTQ, OD.GprRmImm8Imm8, SZ.Dq) (* VdqUdqIbIb *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F7C = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VHADDPD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 ->
      struct (Opcode.VHADDPS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F7D = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VHSUBPD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 ->
      struct (Opcode.VHSUBPS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F7EW1 = function
    | MPref.MPrxNP -> struct (Opcode.MOVQ, OD.RMMmx, SZ.YQ) (* EyPq *)
    | MPref.MPrx66 -> struct (Opcode.MOVQ, OD.RmGpr, SZ.VyDqMR) (* EyVdq *)
    | MPref.MPrxF3 -> struct (Opcode.MOVQ, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F7EW0 = function
    | MPref.MPrxNP -> struct (Opcode.MOVD, OD.RMMmx, SZ.YQ) (* EyPq *)
    | MPref.MPrx66 -> struct (Opcode.MOVD, OD.RmGpr, SZ.VyDqMR) (* EyVdq *)
    | MPref.MPrxF3 -> struct (Opcode.MOVQ, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F7EW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VMOVQ, OD.RmGpr, SZ.VyDqMR) (* EyVdq *)
    | MPref.MPrxF3 -> struct (Opcode.VMOVQ, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F7EW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VMOVD, OD.RmGpr, SZ.VyDqMR) (* EyVdq *)
    | MPref.MPrxF3 -> struct (Opcode.VMOVQ, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F7F = function
    | MPref.MPrxNP -> struct (Opcode.MOVQ, OD.MmMmx, SZ.QQ) (* QqPq *)
    | MPref.MPrx66 -> struct (Opcode.MOVDQA, OD.RmGpr, SZ.DqDq) (* WdqVdq *)
    | MPref.MPrxF3 -> struct (Opcode.MOVDQU, OD.RmGpr, SZ.DqDq) (* WdqVdq *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F7F = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VMOVDQA, OD.RmGpr, SZ.VecDef) (* WxVx *)
    | MPref.MPrxF3 -> struct (Opcode.VMOVDQU, OD.RmGpr, SZ.VecDef) (* WxVx *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F7FW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VMOVDQA64, OD.RmGpr, SZ.VecDef) (* WZxzVZxz *)
    | MPref.MPrxF3 ->
      struct (Opcode.VMOVDQU64, OD.RmGpr, SZ.VecDef) (* WZxzVZxz *)
    | MPref.MPrxF2 ->
      struct (Opcode.VMOVDQU16, OD.RmGpr, SZ.VecDef) (* WZxzVZxz *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F7FW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VMOVDQA32, OD.RmGpr, SZ.VecDef) (* WZxzVZxz *)
    | MPref.MPrxF3 ->
      struct (Opcode.VMOVDQU32, OD.RmGpr, SZ.VecDef) (* WZxzVZxz *)
    | MPref.MPrxF2 ->
      struct (Opcode.VMOVDQU8, OD.RmGpr, SZ.VecDef) (* WZxzVZxz *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FC2 = function
    | MPref.MPrxNP ->
      struct (Opcode.CMPPS, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrx66 ->
      struct (Opcode.CMPPD, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF3 ->
      struct (Opcode.CMPSS, OD.XmmRmImm8, SZ.DqdDq) (* VdqWdqdIb *)
    | MPref.MPrxF2 ->
      struct (Opcode.CMPSD, OD.XmmRmImm8, SZ.DqqDq) (* VdqWdqqIb *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FC2 = function
    | MPref.MPrxNP ->
      struct (Opcode.VCMPPS, OD.XmmVvXmImm8, SZ.VecDef) (* VpsHpsWpsIb *)
    | MPref.MPrx66 ->
      struct (Opcode.VCMPPD, OD.XmmVvXmImm8, SZ.VecDef) (* VpdHpdWpdIb *)
    | MPref.MPrxF3 ->
      struct (Opcode.VCMPSS, OD.XmmVvXmImm8, SZ.VecDef) (* VssHssWssIb *)
    | MPref.MPrxF2 ->
      struct (Opcode.VCMPSD, OD.XmmVvXmImm8, SZ.VecDef) (* VsdHsdWsdIb *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0FC2W0 = function
    | MPref.MPrxNP ->
      struct (Opcode.VCMPPS, OD.XmmVvXmImm8, SZ.XzXz) (* VZxzHxWZxzIb *)
    | MPref.MPrx66
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0FC2W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VCMPPD, OD.XmmVvXmImm8, SZ.XzXz) (* VZxzHxWZxzIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FC4 = function
    | MPref.MPrxNP -> struct (Opcode.PINSRW, OD.MmxRmImm8, SZ.DwQ) (* PqEdwIb *)
    | MPref.MPrx66 ->
      struct (Opcode.PINSRW, OD.XmmRmImm8, SZ.DwDq) (* VdqEdwIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FC4 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPINSRW, OD.XmmVvXmImm8, SZ.DwDq) (* VdqHdqEdwIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FC5 = function
    | MPref.MPrxNP -> struct (Opcode.PEXTRW, OD.GprMmxImm8, SZ.QD) (* GdNqIb *)
    | MPref.MPrx66 -> struct (Opcode.PEXTRW, OD.XmmRmImm8, SZ.Dqd) (* GdUdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FC5 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPEXTRW, OD.XmmRmImm8, SZ.Dqd) (* GdUdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FC6 = function
    | MPref.MPrxNP -> struct (Opcode.SHUFPS, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrx66 -> struct (Opcode.SHUFPD, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FC6 = function
    | MPref.MPrxNP ->
      struct (Opcode.VSHUFPS, OD.XmmVvXmImm8, SZ.VecDef) (* VpsHpsWpsIb *)
    | MPref.MPrx66 ->
      struct (Opcode.VSHUFPD, OD.XmmVvXmImm8, SZ.VecDef) (* VpdHpdWpdIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FD0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VADDSUBPD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 ->
      struct (Opcode.VADDSUBPS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FD1 = function
    | MPref.MPrxNP -> struct (Opcode.PSRLW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PSRLW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FD1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPSRLW, OD.XmmVvXm, SZ.DqX) (* VxHxWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FD2 = function
    | MPref.MPrxNP -> struct (Opcode.PSRLD, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PSRLD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FD2 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPSRLD, OD.XmmVvXm, SZ.DqX) (* VxHxWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FD3 = function
    | MPref.MPrxNP -> struct (Opcode.PSRLQ, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PSRLQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FD3 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPSRLQ, OD.XmmVvXm, SZ.DqX) (* VxHxWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FD4 = function
    | MPref.MPrxNP -> struct (Opcode.PADDQ, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PADDQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FD4 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPADDQ, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FD5 = function
    | MPref.MPrxNP -> struct (Opcode.PMULLW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PMULLW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FD5 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPMULLW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FD6 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.MOVQ, OD.RmGpr, SZ.DqqDq) (* WdqqVdq *)
    | MPref.MPrxF3 -> struct (Opcode.MOVQ2DQ, OD.GprRMm, SZ.QDq) (* VdqNq *)
    | MPref.MPrxF2 -> struct (Opcode.MOVDQ2Q, OD.MmxMm, SZ.DqQ) (* PqUdq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FD6 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VMOVQ, OD.RmGpr, SZ.DqqDq) (* WdqqVdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FD7 = function
    | MPref.MPrxNP -> struct (Opcode.PMOVMSKB, OD.GprRMm, SZ.QD) (* GdNq *)
    | MPref.MPrx66 -> struct (Opcode.PMOVMSKB, OD.GprRm, SZ.Dqd) (* GdUdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FD7 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPMOVMSKB, OD.GprRm, SZ.XD) (* GdUx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FD8 = function
    | MPref.MPrxNP -> struct (Opcode.PSUBUSB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PSUBUSB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FD8 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPSUBUSB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FD9 = function
    | MPref.MPrxNP -> struct (Opcode.PSUBUSW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PSUBUSW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FD9 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPSUBUSW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FDA = function
    | MPref.MPrxNP -> struct (Opcode.PMINUB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PMINUB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FDA = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPMINUB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FDB = function
    | MPref.MPrxNP -> struct (Opcode.PAND, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PAND, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FDB = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPAND, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FDC = function
    | MPref.MPrxNP -> struct (Opcode.PADDUSB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PADDUSB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FDC = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPADDUSB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FDD = function
    | MPref.MPrxNP -> struct (Opcode.PADDUSW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PADDUSW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FDD = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPADDUSW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FDE = function
    | MPref.MPrxNP -> struct (Opcode.PMAXUB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PMAXUB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FDE = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPMAXUB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FDF = function
    | MPref.MPrxNP -> struct (Opcode.PANDN, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PANDN, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FDF = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPANDN, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FE0 = function
    | MPref.MPrxNP -> struct (Opcode.PAVGB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PAVGB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FE0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPAVGB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FE1 = function
    | MPref.MPrxNP -> struct (Opcode.PSRAW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PSRAW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FE1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPSRAW, OD.XmmVvXm, SZ.DqX) (* VxHxWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FE2 = function
    | MPref.MPrxNP -> struct (Opcode.PSRAD, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PSRAD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FE2 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPSRAD, OD.XmmVvXm, SZ.DqX) (* VxHxWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FE3 = function
    | MPref.MPrxNP -> struct (Opcode.PAVGW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PAVGW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FE3 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPAVGW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FE4 = function
    | MPref.MPrxNP -> struct (Opcode.PMULHUW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PMULHUW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FE4 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPMULHUW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FE5 = function
    | MPref.MPrxNP -> struct (Opcode.PMULHW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PMULHW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FE5 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPMULHW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FE6 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.CVTTPD2DQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> struct (Opcode.CVTDQ2PD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrxF2 -> struct (Opcode.CVTPD2DQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FE6 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VCVTTPD2DQ, OD.GprRm, SZ.DqX) (* VdqWx *)
    | MPref.MPrxF3 ->
      struct (Opcode.VCVTDQ2PD, OD.GprRm, SZ.DqqdqX) (* VxWdqqdq *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0FE6W0 = function
    | MPref.MPrxNP
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 -> struct (Opcode.VCVTDQ2PD, OD.GprRm, SZ.XXz) (* VZxzWx *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FE7 = function
    | MPref.MPrxNP -> struct (Opcode.MOVNTQ, OD.RMMmx, SZ.QQ) (* MqPq *)
    | MPref.MPrx66 -> struct (Opcode.MOVNTDQ, OD.RmGpr, SZ.DqDq) (* MdqVdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FE7 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VMOVNTDQ, OD.RmGpr, SZ.VecDef) (* MxVx *)
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
    | MPref.MPrx66 -> struct (Opcode.VMOVNTDQ, OD.RmGpr, SZ.VecDef) (* MZxzVZxz *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FE8 = function
    | MPref.MPrxNP -> struct (Opcode.PSUBSB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PSUBSB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FE8 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPSUBSB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FE9 = function
    | MPref.MPrxNP -> struct (Opcode.PSUBSW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PSUBSW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FE9 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPSUBSW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FEA = function
    | MPref.MPrxNP -> struct (Opcode.PMINSW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PMINSW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FEA = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPMINSW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FEB = function
    | MPref.MPrxNP -> struct (Opcode.POR, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.POR, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FEB = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPOR, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FEC = function
    | MPref.MPrxNP -> struct (Opcode.PADDSB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PADDSB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FEC = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPADDSB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FED = function
    | MPref.MPrxNP -> struct (Opcode.PADDSW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PADDSW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FED = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPADDSW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FEE = function
    | MPref.MPrxNP -> struct (Opcode.PMAXSW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PMAXSW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FEE = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPMAXSW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FEF = function
    | MPref.MPrxNP -> struct (Opcode.PXOR, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PXOR, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FEF = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPXOR, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0FEFW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPXORD, OD.XmmVvXm, SZ.XzXz) (* VZxzHxWZxz *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0FEFW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPXORQ, OD.XmmVvXm, SZ.XzXz) (* VZxzHxWZxz *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FF0 = function
    | MPref.MPrxNP
    | MPref.MPrx66
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 -> struct (Opcode.LDDQU, OD.GprRm, SZ.DqDq) (* VdqMdq *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FF0 = function
    | MPref.MPrxNP
    | MPref.MPrx66
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 -> struct (Opcode.VLDDQU, OD.GprRm, SZ.VecDef) (* VxMx *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FF1 = function
    | MPref.MPrxNP -> struct (Opcode.PSLLW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PSLLW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FF1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPSLLW, OD.XmmVvXm, SZ.DqX) (* VxHxWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FF2 = function
    | MPref.MPrxNP -> struct (Opcode.PSLLD, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PSLLD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FF2 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPSLLD, OD.XmmVvXm, SZ.DqX) (* VxHxWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FF3 = function
    | MPref.MPrxNP -> struct (Opcode.PSLLQ, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PSLLQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FF3 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPSLLQ, OD.XmmVvXm, SZ.DqX) (* VxHxWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FF4 = function
    | MPref.MPrxNP -> struct (Opcode.PMULUDQ, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PMULUDQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FF4 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPMULUDQ, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FF5 = function
    | MPref.MPrxNP -> struct (Opcode.PMADDWD, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PMADDWD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FF5 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPMADDWD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FF6 = function
    | MPref.MPrxNP -> struct (Opcode.PSADBW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PSADBW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FF6 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPSADBW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FF8 = function
    | MPref.MPrxNP -> struct (Opcode.PSUBB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PSUBB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FF8 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPSUBB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FF9 = function
    | MPref.MPrxNP -> struct (Opcode.PSUBW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PSUBW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FF9 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPSUBW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FFA = function
    | MPref.MPrxNP -> struct (Opcode.PSUBD, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PSUBD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FFA = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPSUBD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FFB = function
    | MPref.MPrxNP -> struct (Opcode.PSUBQ, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PSUBQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FFB = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPSUBQ, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FFC = function
    | MPref.MPrxNP -> struct (Opcode.PADDB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PADDB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FFC = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPADDB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FFD = function
    | MPref.MPrxNP -> struct (Opcode.PADDW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PADDW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FFD = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPADDW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0FFE = function
    | MPref.MPrxNP -> struct (Opcode.PADDD, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PADDD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0FFE = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPADDD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3800 = function
    | MPref.MPrxNP -> struct (Opcode.PSHUFB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PSHUFB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3800 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPSHUFB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3801 = function
    | MPref.MPrxNP -> struct (Opcode.PHADDW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PHADDW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3801 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPHADDW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3802 = function
    | MPref.MPrxNP -> struct (Opcode.PHADDD, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PHADDD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3802 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPHADDD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3803 = function
    | MPref.MPrxNP -> struct (Opcode.PHADDSW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PHADDSW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3803 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPHADDSW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3805 = function
    | MPref.MPrxNP -> struct (Opcode.PHSUBW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PHSUBW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3805 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPHSUBW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3806 = function
    | MPref.MPrxNP -> struct (Opcode.PHSUBD, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PHSUBD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3806 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPHSUBD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3807 = function
    | MPref.MPrxNP -> struct (Opcode.PHSUBSW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PHSUBSW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3807 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPHSUBSW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3808 = function
    | MPref.MPrxNP -> struct (Opcode.PSIGNB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PSIGNB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3808 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPSIGNB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3809 = function
    | MPref.MPrxNP -> struct (Opcode.PSIGNW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PSIGNW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3809 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPSIGNW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F380A = function
    | MPref.MPrxNP -> struct (Opcode.PSIGND, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PSIGND, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F380A = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPSIGND, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F380B = function
    | MPref.MPrxNP -> struct (Opcode.PMULHRSW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PMULHRSW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F380B = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPMULHRSW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F380CW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPERMILPS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3815 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.BLENDVPD, OD.XmmXmXmm0, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3816W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPERMPS, OD.XmmVvXm, SZ.Qq) (* VqqHqqWqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3817 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.PTEST, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3817 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPTEST, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3818W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VBROADCASTSS, OD.GprRm, SZ.DX) (* VxMd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3818W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VBROADCASTSS, OD.GprRm, SZ.DqdXz) (* VZxzWdqd *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3819W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VBROADCASTSD, OD.GprRm, SZ.DqqQq) (* VqqWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3819W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VBROADCASTSD, OD.GprRm, SZ.DqqXz) (* VZxzWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F381C = function
    | MPref.MPrxNP -> struct (Opcode.PABSB, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PABSB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F381AW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VBROADCASTF128, OD.GprRm, SZ.DqQq) (* VqqMdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F381C = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPABSB, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F381D = function
    | MPref.MPrxNP -> struct (Opcode.PABSW, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PABSW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F381D = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPABSW, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F381E = function
    | MPref.MPrxNP -> struct (Opcode.PABSD, OD.MmxRm, SZ.QQ) (* PqQq *)
    | MPref.MPrx66 -> struct (Opcode.PABSD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F381E = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPABSD, OD.GprRm, SZ.VecDef) (* VxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3820 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.PMOVSXBW, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3820 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPMOVSXBW, OD.GprRm, SZ.DqqdqX) (* VxWdqqdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3821 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.PMOVSXBD, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3821 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPMOVSXBD, OD.GprRm, SZ.DqddqX) (* VxWdqdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3822 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.PMOVSXBQ, OD.GprRm, SZ.DqwDq) (* VdqWdqw *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3822 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPMOVSXBQ, OD.GprRm, SZ.DqwdX) (* VxWdqwd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3823 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.PMOVSXWD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3823 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPMOVSXWD, OD.GprRm, SZ.DqqdqX) (* VxWdqqdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3824 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.PMOVSXWQ, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3824 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPMOVSXWQ, OD.GprRm, SZ.DqddqX) (* VxWdqdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3825 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.PMOVSXDQ, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3825 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPMOVSXDQ, OD.GprRm, SZ.DqqdqX) (* VxWdqqdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3828 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.PMULDQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3828 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPMULDQ, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3829 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.PCMPEQQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3829 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPCMPEQQ, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F382B = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.PACKUSDW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F382B = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPACKUSDW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F382CW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VMASKMOVPS, OD.XmmVvXm, SZ.VecDef) (* VxHxMx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F382DW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VMASKMOVPD, OD.XmmVvXm, SZ.VecDef) (* VxHxMx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F382EW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VMASKMOVPS, OD.XmVvXmm, SZ.VecDef) (* MxHxVx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F382FW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VMASKMOVPD, OD.XmVvXmm, SZ.VecDef) (* MxHxVx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3830 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.PMOVZXBW, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3830 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPMOVZXBW, OD.GprRm, SZ.DqqdqX) (* VxWdqqdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3830 = function
    | MPref.MPrxNP
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 -> struct (Opcode.VPMOVWB, OD.RmGpr, SZ.QqXz) (* WqqVZxz *)
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3831 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.PMOVZXBD, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3831 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPMOVZXBD, OD.GprRm, SZ.DqddqX) (* VxWdqdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3832 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.PMOVZXBQ, OD.GprRm, SZ.DqwDq) (* VdqWdqw *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3832 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPMOVZXBQ, OD.GprRm, SZ.DqwdX) (* VxWdqwd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3833 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.PMOVZXWD, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3833 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPMOVZXWD, OD.GprRm, SZ.DqqdqX) (* VxWdqqdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3833 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPMOVZXWD, OD.GprRm, SZ.XqXz) (* VZxzWxq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3834 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.PMOVZXWQ, OD.GprRm, SZ.DqdDq) (* VdqWdqd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3834 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPMOVZXWQ, OD.GprRm, SZ.DqddqX) (* VxWdqdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3835 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.PMOVZXDQ, OD.GprRm, SZ.DqqDq) (* VdqWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3835 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPMOVZXDQ, OD.GprRm, SZ.DqqdqX) (* VxWdqqdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3836W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPERMD, OD.XmmVvXm, SZ.Qq) (* VqqHqqWqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3837 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.PCMPGTQ, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3837 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPCMPGTQ, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3838 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.PMINSB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3838 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPMINSB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3839 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.PMINSD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3839 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPMINSD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F383A = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.PMINUW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F383A = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPMINUW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F383B = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.PMINUD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F383B = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPMINUD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F383C = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.PMAXSB, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F383C = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPMAXSB, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F383D = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.PMAXSD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F383D = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPMAXSD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F383E = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.PMAXUW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F383E = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.VPMAXUW, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F383F = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.PMAXUD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F383F = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPMAXUD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3840 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.PMULLD, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3840 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPMULLD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3841 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.PHMINPOSUW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3841 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPHMINPOSUW, OD.GprRm, SZ.DqDq) (* VdqWdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3843W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VGETEXPSD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3845W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPSRLVD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3845W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPSRLVQ, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3846W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPSRAVD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3847W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPSLLVD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3847W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPSLLVQ, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F384DW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VRCP14SD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3858W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPBROADCASTD, OD.GprRm, SZ.DqdX) (* VxWdqd *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3858W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPBROADCASTD, OD.GprRm, SZ.DqdXz) (* VZxzWdqd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3859W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPBROADCASTQ, OD.GprRm, SZ.DqqX) (* VxWdqd *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3859W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPBROADCASTQ, OD.GprRm, SZ.DqqXz) (* VZxzWdqq *)
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
      struct (Opcode.VBROADCASTI128, OD.GprRm, SZ.DqQqq) (* VqqMdq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3875W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPERMI2W, OD.XmmVvXm, SZ.XzXz) (* VZxzHxWZxz *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3876W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPERMI2D, OD.XmmVvXm, SZ.XzXz) (* VZxzHxWZxz *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3877W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPERMI2PD, OD.XmmVvXm, SZ.XzXz) (* VZxzHxWZxz *)
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
      struct (Opcode.VPBROADCASTB, OD.GprRm, SZ.DqbX) (* VxWdqb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3879W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPBROADCASTW, OD.GprRm, SZ.DqwX) (* VxWdqw *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F387AW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPBROADCASTB, OD.GprRm, SZ.DXz) (* VZxzRd *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F387BW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPBROADCASTW, OD.GprRm, SZ.DXz) (* VZxzRd *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F387CW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPBROADCASTD, OD.GprRm, SZ.DXz) (* VZxzRd *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F387CW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPBROADCASTQ, OD.GprRm, SZ.QXz) (* VZxzRq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F388CW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPMASKMOVD, OD.XmmVvXm, SZ.VecDef) (* VxHxMx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F388CW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPMASKMOVQ, OD.XmmVvXm, SZ.VecDef) (* VxHxMx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F388EW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPMASKMOVD, OD.XmVvXmm, SZ.VecDef) (* MxVxHx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F388EW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPMASKMOVQ, OD.XmVvXmm, SZ.VecDef) (* MxVxHx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3890W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPGATHERDD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3890W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPGATHERDD, OD.GprRm, SZ.VecDef) (* VZxzWZxz *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3892W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VGATHERDPS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3892W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VGATHERDPS, OD.GprRm, SZ.VecDef) (* VZxzWZxz *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3893W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VGATHERQPD, OD.XmmXmVv, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3898W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMADD132PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3898W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMADD132PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3898W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMADD132PD, OD.XmmVvXm, SZ.XzXz) (* VZxzHxWZxz *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3899W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMADD132SS, OD.XmmVvXm, SZ.DqdXz) (* VxHxWdqd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3899W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMADD132SD, OD.XmmVvXm, SZ.DqqX) (* VxHxWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F389AW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMSUB132PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F389AW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMSUB132PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F389BW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMSUB132SS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F389BW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMSUB132SD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F389BW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMSUB132SS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F389CW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFNMADD132PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F389CW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFNMADD132PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F389CW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFNMADD132PD, OD.XmmVvXm, SZ.XzXz) (* VZxzHxWZxz *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F389DW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFNMADD132SS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F389DW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFNMADD132SD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F389DW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFNMADD132SD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F389EW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFNMSUB132PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F389EW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFNMSUB132PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F389FW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFNMSUB132SS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F389FW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFNMSUB132SD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38A6W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMADDSUB213PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38A6W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMADDSUB213PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38A7W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMSUBADD213PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38A7W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMSUBADD213PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38A8W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMADD213PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38A8W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMADD213PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38A8W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMADD213PS, OD.XmmVvXm, SZ.XzXz) (* VZxzHxWZxz *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38A9W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMADD213SS, OD.XmmVvXm, SZ.DqdXz) (* VxHxWdqd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38A9W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMADD213SD, OD.XmmVvXm, SZ.DqqX) (* VxHxWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38AAW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMSUB213PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38AAW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMSUB213PD, OD.XmmVvXm, SZ.DqqX) (* VxHxWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38ABW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMSUB213SS, OD.XmmVvXm, SZ.DqdX) (* VxHxWdqd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38ABW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMSUB213SD, OD.XmmVvXm, SZ.DqqX) (* VxHxWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38ACW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFNMADD213PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38ACW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFNMADD213PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38ADW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFNMADD213SS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38ADW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFNMADD213SD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38ADW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFNMADD213SD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38AEW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFNMSUB213PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38AEW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFNMSUB213PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38AFW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFNMSUB213SS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38AFW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFNMSUB213SD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38B6W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMADDSUB231PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38B6W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMADDSUB231PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38B7W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMSUBADD231PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38B7W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMSUBADD231PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38B8W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMADD231PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38B8W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMADD231PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38B8W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMADD231PD, OD.XmmVvXm, SZ.XzXz) (* VZxzHxWZxz *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38B9W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMADD231SS, OD.XmmVvXm, SZ.DqdXz) (* VxHxWdqd *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38B9W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMADD231SD, OD.XmmVvXm, SZ.DqqX) (* VxHxWdqq *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38BAW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMSUB231PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38BAW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMSUB231PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38BBW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMSUB231SS, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38BBW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMSUB231SD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38BBW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFMSUB231SD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38BCW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFNMADD231PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38BCW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFNMADD231PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38BCW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFNMADD231PD, OD.XmmVvXm, SZ.XzXz) (* VZxzHxWZxz *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38BDW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFNMADD231SS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38BDW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFNMADD231SD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38BDW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFNMADD231SD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38BEW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFNMSUB231PS, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38BEW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFNMSUB231PD, OD.XmmVvXm, SZ.VecDef) (* VxHxWx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38BFW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFNMSUB231SS, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38BFW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VFNMSUB231SD, OD.XmmVvXm, SZ.DqdDq) (* VdqHdqWdqd *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38CBW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VRCP28SD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F38CDW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VRSQRT28SD, OD.XmmVvXm, SZ.DqqDq) (* VdqHdqWdqq *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F38F0 = function
    | MPref.MPrxNP -> struct (Opcode.MOVBE, OD.GprRm, SZ.Def) (* GyMy *)
    | MPref.MPrx66 -> struct (Opcode.MOVBE, OD.GprRm, SZ.Word) (* GwMw *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 -> struct (Opcode.CRC32, OD.GprRm, SZ.BV) (* GvEb *)
    | MPref.MPrx66F2 -> struct (Opcode.CRC32, OD.GprRm, SZ.BV) (* GvEb *)
    | _ -> raise ParsingFailureException

  let nor0F38F1 = function
    | MPref.MPrxNP -> struct (Opcode.MOVBE, OD.RmGpr, SZ.Def) (* MyGy *)
    | MPref.MPrx66 -> struct (Opcode.MOVBE, OD.RmGpr, SZ.Word) (* MwGw *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 -> struct (Opcode.CRC32, OD.GprRm, SZ.Def) (* GvEy *)
    | MPref.MPrx66F2 -> struct (Opcode.CRC32, OD.GprRm, SZ.WV) (* GvEw *)
    | _ -> raise ParsingFailureException

  let vex0F38F2 = function
    | MPref.MPrxNP -> struct (Opcode.ANDN, OD.GprVvRm, SZ.Def) (* GyByEy *)
    | MPref.MPrx66
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F38F5W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.WRUSSD, OD.RmGpr, SZ.Def) (* EyGy *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F38F5W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.WRUSSQ, OD.RmGpr, SZ.Def) (* EyGy *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38F5W0 = function
    | MPref.MPrxNP -> struct (Opcode.BZHI, OD.GprRmVv, SZ.Def) (* GyEyBy *)
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 -> struct (Opcode.PEXT, OD.GprVvRm, SZ.Def) (* GyByEy *)
    | MPref.MPrxF2 -> struct (Opcode.PDEP, OD.GprVvRm, SZ.Def) (* GyByEy *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38F5W1 = function
    | MPref.MPrxNP -> struct (Opcode.BZHI, OD.GprRmVv, SZ.Def) (* GyEyBy *)
    | MPref.MPrx66 -> raise ParsingFailureException
    | MPref.MPrxF3 -> struct (Opcode.PEXT, OD.GprVvRm, SZ.Def) (* GyByEy *)
    | MPref.MPrxF2 -> struct (Opcode.PDEP, OD.GprVvRm, SZ.Def) (* GyByEy *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F38F6W0 = function
    | MPref.MPrxNP -> struct (Opcode.WRSSD, OD.GprRm, SZ.Def) (* GyEy *)
    | MPref.MPrx66
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F38F6W1 = function
    | MPref.MPrxNP -> struct (Opcode.WRSSQ, OD.GprRm, SZ.Def) (* GyEy *)
    | MPref.MPrx66
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38F6W0 = function
    | MPref.MPrxNP
    | MPref.MPrx66
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 -> struct (Opcode.MULX, OD.GprVvRm, SZ.Def) (* GyByEy *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38F6W1 = function
    | MPref.MPrxNP
    | MPref.MPrx66
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2 -> struct (Opcode.MULX, OD.GprVvRm, SZ.Def) (* GyByEy *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F38F7 = function
    | MPref.MPrxNP
    | MPref.MPrx66
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F38F7 = function
    | MPref.MPrxNP -> struct (Opcode.BEXTR, OD.GprRmVv, SZ.Def) (* GyEyBy *)
    | MPref.MPrx66 -> struct (Opcode.SHLX, OD.GprRmVv, SZ.Def) (* GyEyBy *)
    | MPref.MPrxF3 -> struct (Opcode.SARX, OD.GprRmVv, SZ.Def) (* GyEyBy *)
    | MPref.MPrxF2 -> struct (Opcode.SHRX, OD.GprRmVv, SZ.Def) (* GyEyBy *)
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A00W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPERMQ, OD.XmmRmImm8, SZ.Qq) (* VqqWqqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A01W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPERMPD, OD.XmmRmImm8, SZ.Qq) (* VqqWqqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A02W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPBLENDD, OD.XmmVvXmImm8, SZ.VecDef) (* VxVxWxIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A04W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPERMILPS, OD.XmmRmImm8, SZ.VecDef) (* VxWxIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A05W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPERMILPD, OD.XmmRmImm8, SZ.VecDef) (* VxWxIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A06W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPERM2F128, OD.XmmVvXmImm8, SZ.Qq) (* VqqHqqWqqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A08 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.ROUNDPS, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A08 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VROUNDPS, OD.XmmRmImm8, SZ.VecDef) (* VxWxIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A09 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.ROUNDPD, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A09 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VROUNDPD, OD.XmmVvXmImm8, SZ.VecDef) (* VxHxWxIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A0A = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VROUNDSS, OD.XmmVvXmImm8, SZ.DqdDq) (* VdqHdqWdqdIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A0B = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.ROUNDSD, OD.XmmRmImm8, SZ.DqqDq) (* VdqWdqqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A0B = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VROUNDSD, OD.XmmVvXmImm8, SZ.DqqDq) (* VdqHdqWdqqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A0BW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VRNDSCALESD, OD.XmmVvXmImm8, SZ.DqqDq) (* VdqHdqWdqqIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A0C = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.BLENDPS, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A0C = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VBLENDPS, OD.XmmVvXmImm8, SZ.VecDef) (* VxHxWxIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A0D = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VBLENDPD, OD.XmmVvXmImm8, SZ.VecDef) (* VxHxWxIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A0E = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPBLENDW, OD.XmmVvXmImm8, SZ.VecDef) (* VxHxWxIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A0F = function
    | MPref.MPrxNP -> struct (Opcode.PALIGNR, OD.MmxMmImm8, SZ.QQ) (* PqQqIb *)
    | MPref.MPrx66 ->
      struct (Opcode.PALIGNR, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A0F = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPALIGNR, OD.XmmVvXmImm8, SZ.VecDef) (* VxHxWxIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A15 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.PEXTRW, OD.XmRegImm8, SZ.DwDq) (* EdwVdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A14W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPEXTRB, OD.XmRegImm8, SZ.DbDq) (* EdbVdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A15 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPEXTRW, OD.XmRegImm8, SZ.DwDq) (* EdwVdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A16 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.PEXTRD, OD.XmRegImm8, SZ.DwDq) (* EdwVdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A16 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPEXTRD, OD.XmRegImm8, SZ.DwDq) (* EdwVdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A17 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.EXTRACTPS, OD.RmXmmImm8, SZ.DDq) (* EdVdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A17 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VEXTRACTPS, OD.RmXmmImm8, SZ.DDq) (* EdVdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A18W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VINSERTF128, OD.XmmVvXmImm8, SZ.DqQqq) (* VqqHqqWdqIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A19W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VEXTRACTF128, OD.XmRegImm8, SZ.DqQq) (* WdqVqqIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A19W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VEXTRACTF32X4, OD.XmRegImm8, SZ.DqXz) (* WdqVZxzIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A19W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VEXTRACTF64X2, OD.XmRegImm8, SZ.DqXz) (* WdqVZxzIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A1AW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VINSERTF64X4, OD.XmmVvXmImm8, SZ.QqXzRM) (* VZxzHxWqqIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A1BW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VEXTRACTF32X8, OD.XmRegImm8, SZ.QqXz) (* WZqqVZxzIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A1BW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VEXTRACTF64X4, OD.XmRegImm8, SZ.QqXz) (* WZqqVZxzIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A20 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 -> struct (Opcode.PINSRB, OD.XmmRmImm8, SZ.DbDq) (* VdqEdbIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A20 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPINSRB, OD.XmmVvXmImm8, SZ.DbDq) (* VdqHdqEdbIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A21 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VINSERTPS, OD.XmmVvXmImm8, SZ.DqdDq) (* VdqHdqUdqdIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A22W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPINSRD, OD.XmmVvXmImm8, SZ.YDq) (* VdqHdqEyIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A22W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPINSRQ, OD.XmmVvXmImm8, SZ.YDq) (* VdqHdqEyIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A22W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPINSRD, OD.XmmVvXmImm8, SZ.YDq) (* VdqHdqEyIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A22W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPINSRQ, OD.XmmVvXmImm8, SZ.YDq) (* VdqHdqEyIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A25W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPTERNLOGD, OD.XmmVvXmImm8, SZ.XzXz) (* VZxzHxWZxzIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A27W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VGETMANTSD, OD.XmmVvXmImm8, SZ.DqqDq) (* VdqHdqWdqqIb *)
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
      struct (Opcode.VINSERTI128, OD.XmmVvXmImm8, SZ.DqQqq) (* VqqHqqWdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A39W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VEXTRACTI128, OD.XmRegImm8, SZ.DqQq) (* WdqVqqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A3AW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VINSERTI32X8, OD.XmmVvXmImm8, SZ.QqXzRM) (* VZxzHxWqqIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A3AW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VINSERTI64X4, OD.XmmVvXmImm8, SZ.QqXzRM) (* VZxzHxWqqIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A3BW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VEXTRACTI32X8, OD.XmRegImm8, SZ.QqXz) (* WqqVZxzIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A3BW1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VEXTRACTI64X4, OD.XmRegImm8, SZ.QqXz) (* WqqVZxzIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A43W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VSHUFI32X4, OD.XmmVvXmImm8, SZ.XzXz) (* VZxzHxWZxzIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A43W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VSHUFI64X2, OD.XmmVvXmImm8, SZ.XzXz) (* VZxzHxWZxzIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A46W0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPERM2I128, OD.XmmVvXmImm8, SZ.Qq) (* VqqHqqWqqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A4AW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VBLENDVPS, OD.XmmVvXmXmm, SZ.VecDef) (* VxHxWxLx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A4BW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VBLENDVPD, OD.XmmVvXmXmm, SZ.VecDef) (* VxHxWxLx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A4CW0 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPBLENDVB, OD.XmmVvXmXmm, SZ.VecDef) (* VxHxWxLx *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let evex0F3A57W1 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VREDUCESD, OD.XmmVvXmImm8, SZ.DqqDq) (* VdqHdqWdqqIb *)
    | MPref.MPrxF3 -> raise ParsingFailureException
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A60 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.PCMPESTRM, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A60 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPCMPESTRM, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A61 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.PCMPESTRI, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A61 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPCMPESTRI, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A62 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.PCMPISTRM, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A62 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPCMPISTRM, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let nor0F3A63 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.PCMPISTRI, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
    | MPref.MPrxF3
    | MPref.MPrxF2
    | _ (* MPrx66F2 *) -> raise ParsingFailureException

  let vex0F3A63 = function
    | MPref.MPrxNP -> raise ParsingFailureException
    | MPref.MPrx66 ->
      struct (Opcode.VPCMPISTRI, OD.XmmRmImm8, SZ.DqDq) (* VdqWdqIb *)
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
    | MPref.MPrxF2 -> struct (Opcode.RORX, OD.XmmRmImm8, SZ.Def) (* GyEyIb *)
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
    | 0 -> struct (Opcode.INC, OD.Mem, SZ.Def, SzCond.Nor)
    | 1 -> struct (Opcode.DEC, OD.Mem, SZ.Def, SzCond.Nor)
    | 2 -> struct (Opcode.CALLNear, OD.Mem, SZ.Def, SzCond.F64)
    | 3 -> struct (Opcode.CALLFar, OD.Mem, SZ.P, SzCond.Nor)
    | 4 -> struct (Opcode.JMPNear, OD.Mem, SZ.Def, SzCond.F64)
    | 5 -> struct (Opcode.JMPFar, OD.Dir, SZ.P, SzCond.Nor)
    | 6 -> struct (Opcode.PUSH, OD.Mem, SZ.Def, SzCond.D64)
    | _ -> raise ParsingFailureException

  let grp7 = function
    | 0 -> struct (Opcode.SGDT, OD.Mem, SZ.S, SzCond.Nor)
    | 1 -> struct (Opcode.SIDT, OD.Mem, SZ.S, SzCond.Nor)
    | 2 -> struct (Opcode.LGDT, OD.Mem, SZ.S, SzCond.Nor)
    | 3 -> struct (Opcode.LIDT, OD.Mem, SZ.S, SzCond.Nor)
    | 4 -> struct (Opcode.SMSW, OD.Mem, SZ.MemW, SzCond.Nor)
    | 5 -> struct (Opcode.RSTORSSP, OD.Mem, SZ.Q, SzCond.Nor)
    | 6 -> struct (Opcode.LMSW, OD.Mem, SZ.MemW, SzCond.Nor)
    | 7 -> struct (Opcode.INVLPG, OD.Mem, SZ.MemW, SzCond.Nor)
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

  let grp17Op = function
    | 1 -> Opcode.BLSR
    | 2 -> Opcode.BLSMSK
    | 3 -> Opcode.BLSI
    | _ -> raise ParsingFailureException

  let getGrp3OpKind oidx sidx oprGrp regBits =
    match regBits with
    | 0b000 when oprGrp = OpGroup.G3A ->
      struct (Opcode.TEST, OD.RmImm8, SZ.Byte, SzCond.Nor)
    | 0b000 when oprGrp = OpGroup.G3B ->
      struct (Opcode.TEST, OD.RmImm, SZ.Def, SzCond.Nor)
    | 0b010 -> struct (Opcode.NOT, oidx, sidx, SzCond.Nor)
    | 0b011 -> struct (Opcode.NEG, oidx, sidx, SzCond.Nor)
    | 0b100 -> struct (Opcode.MUL, oidx, sidx, SzCond.Nor)
    | 0b101 -> struct (Opcode.IMUL, oidx, sidx, SzCond.Nor)
    | 0b110 -> struct (Opcode.DIV, oidx, sidx, SzCond.Nor)
    | 0b111 -> struct (Opcode.IDIV, oidx, sidx, SzCond.Nor)
    | _ -> raise ParsingFailureException

  let getGrp6OpKind b regBits =
    match modIsMemory b, regBits with
    | true, 0b000 -> struct (Opcode.SLDT, OD.Mem, SZ.MemW, SzCond.Nor)
    | false, 0b000 -> struct (Opcode.SLDT, OD.Mem, SZ.Def, SzCond.Nor)
    | true, 0b001 -> struct (Opcode.STR, OD.Mem, SZ.MemW, SzCond.Nor)
    | false, 0b001 -> struct (Opcode.STR, OD.Mem, SZ.Def, SzCond.Nor)
    | _, 0b010 -> struct (Opcode.LLDT, OD.Mem, SZ.MemW, SzCond.Nor)
    | _, 0b011 -> struct (Opcode.LTR, OD.Mem, SZ.MemW, SzCond.Nor)
    | _, 0b100 -> struct (Opcode.VERR, OD.Mem, SZ.MemW, SzCond.Nor)
    | _, 0b101 -> struct (Opcode.VERW, OD.Mem, SZ.MemW, SzCond.Nor)
    | _ -> raise ParsingFailureException

  let parseGrp7OpKind (rhlp: ReadHelper) b regBits =
    if modIsMemory b then grp7 regBits
    else
      match regBits, getRM b with
      | 0b000, 0b001 ->
        rhlp.IncPos (); struct (Opcode.VMCALL, OD.No, SZ.Def, SzCond.Nor)
      | 0b000, 0b010 ->
        rhlp.IncPos (); struct (Opcode.VMLAUNCH, OD.No, SZ.Def, SzCond.Nor)
      | 0b000, 0b011 ->
        rhlp.IncPos (); struct (Opcode.VMRESUME, OD.No, SZ.Def, SzCond.Nor)
      | 0b000, 0b100 ->
        rhlp.IncPos (); struct (Opcode.VMXOFF, OD.No, SZ.Def, SzCond.Nor)
      | 0b001, 0b000 ->
        rhlp.IncPos (); struct (Opcode.MONITOR, OD.No, SZ.Def, SzCond.Nor)
      | 0b001, 0b001 ->
        rhlp.IncPos (); struct (Opcode.MWAIT, OD.No, SZ.Def, SzCond.Nor)
      | 0b001, 0b010 ->
        rhlp.IncPos (); struct (Opcode.CLAC, OD.No, SZ.Def, SzCond.Nor)
      | 0b001, 0b011 ->
        rhlp.IncPos (); struct (Opcode.STAC, OD.No, SZ.Def, SzCond.Nor)
      | 0b010, 0b000 ->
        rhlp.IncPos (); struct (Opcode.XGETBV, OD.No, SZ.Def, SzCond.Nor)
      | 0b010, 0b001 ->
        rhlp.IncPos (); struct (Opcode.XSETBV, OD.No, SZ.Def, SzCond.Nor)
      | 0b010, 0b100 ->
        rhlp.IncPos (); struct (Opcode.VMFUNC, OD.No, SZ.Def, SzCond.Nor)
      | 0b010, 0b101 ->
        rhlp.IncPos (); struct (Opcode.XEND, OD.No, SZ.Def, SzCond.Nor)
      | 0b010, 0b110 ->
        rhlp.IncPos (); struct (Opcode.XTEST, OD.No, SZ.Def, SzCond.Nor)
      | 0b100, _     -> struct (Opcode.SMSW, OD.Mem, SZ.Def, SzCond.Nor)
      | 0b101, 0b000 ->
        rhlp.IncPos (); struct (Opcode.SETSSBSY, OD.No, SZ.Def, SzCond.Nor)
      | 0b101, 0b010 ->
        rhlp.IncPos (); struct (Opcode.SAVEPREVSSP, OD.No, SZ.Def, SzCond.Nor)
      | 0b101, 0b110 ->
        rhlp.IncPos (); struct (Opcode.RDPKRU, OD.No, SZ.Def, SzCond.Nor)
      | 0b101, 0b111 ->
        rhlp.IncPos (); struct (Opcode.WRPKRU, OD.No, SZ.Def, SzCond.Nor)
      | 0b110, _     -> struct (Opcode.LMSW, OD.Mem, SZ.MemW, SzCond.Nor)
      | 0b111, 0b000 ->
#if !EMULATION
        ensure32 rhlp
#endif
        rhlp.IncPos (); struct (Opcode.SWAPGS, OD.No, SZ.Def, SzCond.Nor)
      | 0b111, 0b001 ->
        rhlp.IncPos (); struct (Opcode.RDTSCP, OD.No, SZ.Def, SzCond.Nor)
      | _ -> raise ParsingFailureException

  let getGrp9OpKind (rhlp: ReadHelper) b regBits =
    let hasOprSzPref = hasOprSz rhlp.Prefixes
    let hasREPZPref = hasREPZ rhlp.Prefixes
    let hasREXWPref = hasREXW rhlp.REXPrefix
    match modIsMemory b, regBits, hasOprSzPref, hasREPZPref, hasREXWPref with
    | true,  0b001, false, false, false ->
      struct (Opcode.CMPXCHG8B, OD.Mem, SZ.Q, SzCond.Nor)
    | true,  0b001, false, false, true  ->
      struct (Opcode.CMPXCHG16B, OD.Mem, SZ.Dq, SzCond.Nor)
    | true,  0b011, false, false, false ->
      struct (Opcode.XRSTORS, OD.Mem, SZ.Q, SzCond.Nor)
    | true,  0b011, false, false, true  ->
      struct (Opcode.XRSTORS64, OD.Mem, SZ.Q, SzCond.Nor)
    | true,  0b100, false, false, false ->
      struct (Opcode.XSAVEC, OD.Mem, SZ.Q, SzCond.Nor)
    | true,  0b100, false, false, true  ->
      struct (Opcode.XSAVEC64, OD.Mem, SZ.Q, SzCond.Nor)
    | true,  0b101, false, false, false ->
      struct (Opcode.XSAVES, OD.Mem, SZ.Q, SzCond.Nor)
    | true,  0b101, false, false, true  ->
      struct (Opcode.XSAVES64, OD.Mem, SZ.Q, SzCond.Nor)
    | true,  0b110, false, false, _     ->
      struct (Opcode.VMPTRLD, OD.Mem, SZ.Q, SzCond.Nor)
    | true,  0b111, false, false, _     ->
      struct (Opcode.VMPTRST, OD.Mem, SZ.Q, SzCond.Nor)
    | true,  0b110, true,  false, _     ->
      struct (Opcode.VMCLEAR, OD.Mem, SZ.Q, SzCond.Nor)
    | true,  0b110, false, true,  _     ->
      struct (Opcode.VMXON, OD.Mem, SZ.Q, SzCond.Nor)
    | true,  0b111, false, true,  _     ->
      struct (Opcode.VMPTRST, OD.Mem, SZ.Q, SzCond.Nor)
    | false, 0b110, false, false, _     ->
      struct (Opcode.RDRAND, OD.Mem, SZ.Def, SzCond.Nor)
    | false, 0b111, false, false, _     ->
      struct (Opcode.RDSEED, OD.Mem, SZ.Def, SzCond.Nor)
    | _ -> raise ParsingFailureException

  let getGrp11OpKind rhlp op oidx1 sz1 b reg oidx2 sz2 =
    match reg with
    | 0b000 -> struct (Opcode.MOV, oidx2, sz2, SzCond.Nor)
    | 0b111 when modIsMemory b -> raise ParsingFailureException
    | 0b111 ->
      if (rhlp: ReadHelper).ReadByte () = 0xF8uy then
        struct (op, oidx1, sz1, SzCond.Nor)
      else raise ParsingFailureException
    | _ -> raise ParsingFailureException

  let getGrp12OpKind rhlp b regBits =
    match modIsMemory b, regBits, hasOprSz (selectPrefix rhlp) with
    | false, 0b010, false -> struct (Opcode.PSRLW, OD.MmxImm8, SZ.Q, SzCond.Nor)
    | false, 0b010, true  ->
      if rhlp.VEXInfo = None then
        struct (Opcode.PSRLW, OD.RmImm8, SZ.Dq, SzCond.Nor)
      else struct (Opcode.VPSRLW, OD.VvRmImm8, SZ.VecDef, SzCond.Nor)
    | false, 0b100, false -> struct (Opcode.PSRAW, OD.MmxImm8, SZ.Q, SzCond.Nor)
    | false, 0b100, true  ->
      if rhlp.VEXInfo = None then
        struct (Opcode.PSRAW, OD.RmImm8, SZ.Dq, SzCond.Nor)
      else struct (Opcode.VPSRAW, OD.VvRmImm8, SZ.VecDef, SzCond.Nor)
    | false, 0b110, false -> struct (Opcode.PSLLW, OD.MmxImm8, SZ.Q, SzCond.Nor)
    | false, 0b110, true  ->
      if rhlp.VEXInfo = None then
        struct (Opcode.PSLLW, OD.RmImm8, SZ.Dq, SzCond.Nor)
      else struct (Opcode.VPSLLW, OD.VvRmImm8, SZ.VecDef, SzCond.Nor)
    | _ -> raise ParsingFailureException

  let getGrp13OpKind rhlp b regBits =
    match modIsMemory b, regBits, hasOprSz (selectPrefix rhlp) with
    | false, 0b010, false -> struct (Opcode.PSRLD, OD.MmxImm8, SZ.Q, SzCond.Nor)
    | false, 0b010, true  ->
      if rhlp.VEXInfo = None then
        struct (Opcode.PSRLD, OD.RmImm8, SZ.Dq, SzCond.Nor)
      else struct (Opcode.VPSRLD, OD.VvRmImm8, SZ.VecDef, SzCond.Nor)
    | false, 0b100, false -> struct (Opcode.PSRAD, OD.MmxImm8, SZ.Q, SzCond.Nor)
    | false, 0b100, true  ->
      if rhlp.VEXInfo = None then
        struct (Opcode.PSRAD, OD.RmImm8, SZ.Dq, SzCond.Nor)
      else struct (Opcode.VPSRAD, OD.VvRmImm8, SZ.VecDef, SzCond.Nor)
    | false, 0b110, false -> struct (Opcode.PSLLD, OD.MmxImm8, SZ.Q, SzCond.Nor)
    | false, 0b110, true  ->
      if rhlp.VEXInfo = None then
        struct (Opcode.PSLLD, OD.RmImm8, SZ.Dq, SzCond.Nor)
      else struct (Opcode.VPSLLD, OD.VvRmImm8, SZ.VecDef, SzCond.Nor)
    | _ -> raise ParsingFailureException

  let getGrp14OpKind rhlp b regBits =
    match modIsMemory b, regBits, hasOprSz (selectPrefix rhlp) with
    | false, 0b010, false ->
      struct (Opcode.PSRLQ, OD.MmxImm8, SZ.Q, SzCond.Nor)
    | false, 0b010, true  ->
      if rhlp.VEXInfo = None then
        struct (Opcode.PSRLQ, OD.RmImm8, SZ.Dq, SzCond.Nor)
      else struct (Opcode.VPSRLQ, OD.VvRmImm8, SZ.VecDef, SzCond.Nor)
    | false, 0b011, true  ->
      if rhlp.VEXInfo = None then
        struct (Opcode.PSRLDQ, OD.RmImm8, SZ.Dq, SzCond.Nor)
      else struct (Opcode.VPSRLDQ, OD.VvRmImm8, SZ.VecDef, SzCond.Nor)
    | false, 0b110, false -> struct (Opcode.PSLLQ, OD.MmxImm8, SZ.Q, SzCond.Nor)
    | false, 0b110, true  ->
      if rhlp.VEXInfo = None then
        struct (Opcode.PSLLQ, OD.RmImm8, SZ.Dq, SzCond.Nor)
      else struct (Opcode.VPSLLQ, OD.VvRmImm8, SZ.VecDef, SzCond.Nor)
    | false, 0b111, true  ->
      if rhlp.VEXInfo = None then
        struct (Opcode.PSLLDQ, OD.RmImm8, SZ.Dq, SzCond.Nor)
      else struct (Opcode.VPSLLDQ, OD.VvRmImm8, SZ.VecDef, SzCond.Nor)
    | _ -> raise ParsingFailureException

  let parseGrp15OpKind (rhlp: ReadHelper) b regBits =
    match modIsMemory b, regBits, hasREPZ rhlp.Prefixes with
    | true,  0b110, true -> struct (Opcode.CLRSSBSY, OD.Mem, SZ.Q, SzCond.Nor)
    | true,  0b000, false ->
      let op = if hasREXW rhlp.REXPrefix then Opcode.FXSAVE64 else Opcode.FXSAVE
      struct (op, OD.Mem, SZ.Def, SzCond.Nor)
    | true,  0b001, false ->
      let op =
        if hasREXW rhlp.REXPrefix then Opcode.FXRSTOR64 else Opcode.FXRSTOR
      struct (op, OD.Mem, SZ.Def, SzCond.Nor)
    | true,  0b010, false -> struct (Opcode.LDMXCSR, OD.Mem, SZ.D, SzCond.Nor)
    | true,  0b011, false -> struct (Opcode.STMXCSR, OD.Mem, SZ.D, SzCond.Nor)
    | true,  0b100, false -> struct (Opcode.XSAVE, OD.Mem, SZ.Def, SzCond.Nor)
    | true,  0b101, false -> struct (Opcode.XRSTOR, OD.Mem, SZ.Def, SzCond.Nor)
    | true,  0b110, false -> struct (Opcode.XSAVEOPT, OD.Mem, SZ.Def, SzCond.Nor)
    | true,  0b111, false -> struct (Opcode.CLFLUSH, OD.Mem, SZ.BV, SzCond.Nor)
    | false, 0b101, false ->
      rhlp.IncPos (); struct (Opcode.LFENCE, OD.No, SZ.Def, SzCond.Nor)
    | false, 0b110, false ->
      rhlp.IncPos (); struct (Opcode.MFENCE, OD.No, SZ.Def, SzCond.Nor)
    | false, 0b111, false ->
      rhlp.IncPos (); struct (Opcode.SFENCE, OD.No, SZ.Def, SzCond.Nor)
    | false, 0b000, true -> struct (Opcode.RDFSBASE, OD.Gpr, SZ.Def, SzCond.Nor)
    | false, 0b001, true -> struct (Opcode.RDGSBASE, OD.Gpr, SZ.Def, SzCond.Nor)
    | false, 0b010, true -> struct (Opcode.WRFSBASE, OD.Gpr, SZ.Def, SzCond.Nor)
    | false, 0b011, true -> struct (Opcode.WRGSBASE, OD.Gpr, SZ.Def, SzCond.Nor)
    | false, 0b101, true ->
      let op = if hasREXW rhlp.REXPrefix then Opcode.INCSSPQ else Opcode.INCSSPD
      struct (op, OD.Gpr, SZ.Def, SzCond.Nor)
    | _ -> raise ParsingFailureException

  let parseGrpOpKind (rhlp: ReadHelper) oidx sidx oprGrp =
    let b = rhlp.PeekByte ()
    let r = getReg b
    match oprGrp with
    | OpGroup.G1 -> struct (grp1Op r, oidx, sidx, SzCond.Nor)
    | OpGroup.G1Inv64 ->
#if !EMULATION
      ensure32 rhlp
#endif
      struct (grp1Op r, oidx, sidx, SzCond.Nor)
    | OpGroup.G1A -> struct (Opcode.POP, oidx, sidx, SzCond.D64)
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
      getGrp11OpKind rhlp Opcode.XABORT OD.Imm8 SZ.Def b r oidx sidx
    | OpGroup.G11B ->
      getGrp11OpKind rhlp Opcode.XBEGIN OD.Rel SZ.D64 b r oidx sidx
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
      rhlp.Prefixes <- Prefix.PrxBND ||| (clearGrp1PrefMask &&& rhlp.Prefixes)
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
  let inline filterPrefs (prefix: Prefix) = prefix &&& clearVEXPrefMask

  let getInstr prefix fnInstr = fnInstr (getMandPrx prefix)

  /// The main instruction rendering function.
  let render (rhlp: ReadHelper) opcode szCond (oidx: OprDesc) (sidx: SizeKind) =
    rhlp.SzComputers[int sidx].Render rhlp szCond
    exceptionalOperationSize opcode rhlp
    let oprs = rhlp.OprParsers[int oidx].Render rhlp
    newInsInfo rhlp opcode oprs

  /// Parse group Opcodes: Vol.2C A-19 Table A-6. Opcode Extensions for One- and
  /// Two-byte Opcodes by Group Number.
  let parseGrpOp rhlp grp oidx sidx =
    let struct (op, oidx, szidx, szCond) = parseGrpOpKind rhlp oidx sidx grp
    if isBranch op then addBND rhlp |> ignore
    elif isCETInstr op then rhlp.Prefixes <- clearGrp1PrefMask &&& rhlp.Prefixes
    else ()
    render rhlp op szCond oidx szidx

  /// Normal/VEX
  let parseVEX (rhlp: ReadHelper) fnNor fnVex =
    match rhlp.VEXInfo with
    | None ->
      let struct (op, oidx, sidx) = fnNor (getMandPrx rhlp.Prefixes)
      rhlp.Prefixes <- filterPrefs rhlp.Prefixes
      render rhlp op SzCond.Nor oidx sidx
    | Some v ->
      let struct (op, oidx, sidx) = fnVex (getMandPrx v.VPrefixes)
      render rhlp op SzCond.Nor oidx sidx

  /// Normal(REX.W), VEX(REX.W)
  let selectVEXW (rhlp: ReadHelper) fnNorW0 fnNorW1 fnVexW0 fnVexW1 =
    match rhlp.VEXInfo with
    | None ->
      let fnNor = if hasREXW rhlp.REXPrefix then fnNorW1 else fnNorW0
      let ins = getInstr rhlp.Prefixes fnNor
      rhlp.Prefixes <- filterPrefs rhlp.Prefixes
      ins
    | Some v ->
      let fnVex = if hasREXW rhlp.REXPrefix then fnVexW1 else fnVexW0
      getInstr v.VPrefixes fnVex

  /// Normal/VEX (Both REX.W)
  let parseVEXW rhlp fnNorW0 fnNorW1 fnVexW0 fnVexW1 =
    let struct (op, oidx, sidx) =
      selectVEXW rhlp fnNorW0 fnNorW1 fnVexW0 fnVexW1
    render rhlp op SzCond.Nor oidx sidx

  /// Normal(REX.W), VEX(REX.W)
  /// Normal, VEX, EVEX(REX.W)
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

  /// Normal/VEX/EVEX (EVEX REX.W)
  let parseEVEX rhlp fnNor fnVex fnEVexW0 fnEVexW1 =
    let struct (op, oidx, sidx) =
      selectEVEX rhlp fnNor fnVex fnEVexW0 fnEVexW1
    render rhlp op SzCond.Nor oidx sidx

  /// VEX(REX.W), EVEX(REX.W)
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

  /// VEX/EVEX (Both REX.W)
  let parseEVEXW rhlp fnVexW0 fnVexW1 fnEVexW0 fnEVexW1 =
    let struct (op, oidx, sidx) =
      selectEVEXW rhlp fnVexW0 fnVexW1 fnEVexW0 fnEVexW1
    render rhlp op SzCond.Nor oidx sidx

  /// Parse non-VEX instructions.
  let parseNonVEX (rhlp: ReadHelper) fnNor =
    let struct (op, oidx, sidx) = getInstr rhlp.Prefixes fnNor
    rhlp.Prefixes <- filterPrefs rhlp.Prefixes
    render rhlp op SzCond.Nor oidx sidx

  /// Parse non-VEX instructions.
  let pVEXByMem (rhlp: ReadHelper) fnNorM fnNorR fnVexM fnVexR =
    let struct (fnNor, fnVex) =
      if rhlp.PeekByte () |> modIsMemory then struct (fnNorM, fnVexM)
      else struct (fnNorR, fnVexR)
    parseVEX rhlp fnNor fnVex

  /// Parse BND-related instructions.
  let parseBND (rhlp: ReadHelper) szCond fnBND =
    let struct (op, oidx, sidx) = getInstr rhlp.Prefixes fnBND
    rhlp.Prefixes <- filterPrefs rhlp.Prefixes
    render rhlp op szCond oidx sidx

  let parseCETInstr (rhlp: ReadHelper) =
    let struct (op, oidx, sidx) =
      match rhlp.PeekByte () with
      | 0xFAuy -> rhlp.IncPos (); struct (Opcode.ENDBR64, OD.No, SZ.Def)
      | 0xFBuy -> rhlp.IncPos (); struct (Opcode.ENDBR32, OD.No, SZ.Def)
      | b when getReg b = 0b001 && getMod b = 0b11 ->
        let op = if hasREXW rhlp.REXPrefix then Opcode.RDSSPQ else Opcode.RDSSPD
        struct (op, OD.Gpr, SZ.Def)
      | _ -> raise InvalidOpcodeException
    rhlp.Prefixes <- clearGrp1PrefMask &&& rhlp.Prefixes
    render rhlp op SzCond.Nor oidx sidx

  let parseESCOp (rhlp: ReadHelper) escFlag getOpIn getOpOut =
    let modRM = rhlp.ReadByte ()
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
      let o = OperandParsingHelper.parseMemory modRM rhlp
      newInsInfo rhlp op (OneOperand o)
    else
      let opcode, oprs = getOpOut modRM
      newInsInfo rhlp opcode oprs

  /// When the first two bytes are 0F38.
  /// Table A-4 of Volume 2 (Three-byte Opcode Map : First Two Bytes are 0F 38H)
  let parseThreeByteOp1 (rhlp: ReadHelper) =
    match rhlp.ReadByte () with
    | 0x00uy -> parseVEX rhlp nor0F3800 vex0F3800
    | 0x01uy -> parseVEX rhlp nor0F3801 vex0F3801
    | 0x02uy -> parseVEX rhlp nor0F3802 vex0F3802
    | 0x03uy -> parseVEX rhlp nor0F3803 vex0F3803
    | 0x05uy -> parseVEX rhlp nor0F3805 vex0F3805
    | 0x06uy -> parseVEX rhlp nor0F3806 vex0F3806
    | 0x07uy -> parseVEX rhlp nor0F3807 vex0F3807
    | 0x08uy -> parseVEX rhlp nor0F3808 vex0F3808
    | 0x09uy -> parseVEX rhlp nor0F3809 vex0F3809
    | 0x0auy -> parseVEX rhlp nor0F380A vex0F380A
    | 0x0buy -> parseVEX rhlp nor0F380B vex0F380B
    | 0x0cuy -> parseEVEXW rhlp vex0F380CW0 notEn notEn notEn
    | 0x15uy -> parseVEX rhlp nor0F3815 notEn
    | 0x16uy -> parseVEXW rhlp notEn notEn vex0F3816W0 notEn
    | 0x17uy -> parseVEX rhlp nor0F3817 vex0F3817
    | 0x18uy -> parseEVEXW rhlp vex0F3818W0 notEn evex0F3818W0 notEn
    | 0x19uy -> parseEVEXW rhlp vex0F3819W0 notEn notEn evex0F3819W1
    | 0x1auy -> parseVEXW rhlp notEn notEn vex0F381AW0 notEn
    | 0x1cuy -> parseVEX rhlp nor0F381C vex0F381C
    | 0x1duy -> parseVEX rhlp nor0F381D vex0F381D
    | 0x1euy -> parseVEX rhlp nor0F381E vex0F381E
    | 0x20uy -> parseVEX rhlp nor0F3820 vex0F3820
    | 0x21uy -> parseVEX rhlp nor0F3821 vex0F3821
    | 0x22uy -> parseVEX rhlp nor0F3822 vex0F3822
    | 0x23uy -> parseVEX rhlp nor0F3823 vex0F3823
    | 0x24uy -> parseVEX rhlp nor0F3824 vex0F3824
    | 0x25uy -> parseVEX rhlp nor0F3825 vex0F3825
    | 0x28uy -> parseVEX rhlp nor0F3828 vex0F3828
    | 0x29uy -> parseVEX rhlp nor0F3829 vex0F3829
    | 0x2buy -> parseVEX rhlp nor0F382B vex0F382B
    | 0x2cuy -> parseVEXW rhlp notEn notEn vex0F382CW0 notEn
    | 0x2duy -> parseVEXW rhlp notEn notEn vex0F382DW0 notEn
    | 0x2euy -> parseVEXW rhlp notEn notEn vex0F382EW0 notEn
    | 0x2fuy -> parseVEXW rhlp notEn notEn vex0F382FW0 notEn
    | 0x30uy -> parseEVEX rhlp nor0F3830 vex0F3830 evex0F3830 evex0F3830
    | 0x31uy -> parseVEX rhlp nor0F3831 vex0F3831
    | 0x32uy -> parseVEX rhlp nor0F3832 vex0F3832
    | 0x33uy -> parseEVEX rhlp nor0F3833 vex0F3833 evex0F3833 evex0F3833
    | 0x34uy -> parseVEX rhlp nor0F3834 vex0F3834
    | 0x35uy -> parseVEX rhlp nor0F3835 vex0F3835
    | 0x36uy -> parseEVEXW rhlp vex0F3836W0 notEn notEn notEn
    | 0x37uy -> parseVEX rhlp nor0F3837 vex0F3837
    | 0x38uy -> parseVEX rhlp nor0F3838 vex0F3838
    | 0x39uy -> parseVEX rhlp nor0F3839 vex0F3839
    | 0x3auy -> parseVEX rhlp nor0F383A vex0F383A
    | 0x3buy -> parseVEX rhlp nor0F383B vex0F383B
    | 0x3cuy -> parseVEX rhlp nor0F383C vex0F383C
    | 0x3duy -> parseVEX rhlp nor0F383D vex0F383D
    | 0x3euy -> parseVEX rhlp nor0F383E vex0F383E
    | 0x3fuy -> parseVEX rhlp nor0F383F vex0F383F
    | 0x40uy -> parseVEX rhlp nor0F3840 vex0F3840
    | 0x41uy -> parseVEX rhlp nor0F3841 vex0F3841
    | 0x43uy -> parseEVEXW rhlp notEn notEn notEn evex0F3843W1
    | 0x45uy -> parseEVEXW rhlp vex0F3845W0 vex0F3845W1 notEn notEn
    | 0x46uy -> parseEVEXW rhlp vex0F3846W0 notEn notEn notEn
    | 0x47uy -> parseEVEXW rhlp vex0F3847W0 vex0F3847W1 notEn notEn
    | 0x4Duy -> parseEVEXW rhlp notEn notEn notEn evex0F384DW1
    | 0x58uy -> parseEVEXW rhlp vex0F3858W0 notEn evex0F3858W0 notEn
    | 0x59uy -> parseEVEXW rhlp vex0F3859W0 notEn notEn evex0F3859W1
    | 0x5Auy -> parseVEX rhlp nor0F385A vex0F385A
    | 0x75uy -> parseEVEXW rhlp notEn notEn notEn evex0F3875W1
    | 0x76uy -> parseEVEXW rhlp notEn notEn evex0F3876W0 notEn
    | 0x77uy -> parseEVEXW rhlp notEn notEn notEn evex0F3877W1
    | 0x78uy -> parseVEX rhlp nor0F3878 vex0F3878
    | 0x79uy -> parseEVEXW rhlp vex0F3879W0 notEn notEn notEn
    | 0x7Auy -> parseEVEXW rhlp notEn notEn evex0F387AW0 notEn
    | 0x7Buy -> parseEVEXW rhlp notEn notEn evex0F387BW0 notEn
    | 0x7Cuy -> parseEVEXW rhlp notEn notEn evex0F387CW0 evex0F387CW1
    | 0x8Cuy -> parseVEXW rhlp notEn notEn vex0F388CW0 vex0F388CW1
    | 0x8Euy -> parseVEXW rhlp notEn notEn vex0F388EW0 vex0F388EW1
    | 0x90uy -> parseEVEXW rhlp vex0F3890W0 notEn evex0F3890W0 notEn
    | 0x92uy -> parseEVEXW rhlp vex0F3892W0 notEn evex0F3892W0 notEn
    | 0x93uy -> parseEVEXW rhlp notEn vex0F3893W1 notEn notEn
    | 0x98uy -> parseEVEXW rhlp vex0F3898W0 vex0F3898W1 notEn evex0F3898W1
    | 0x99uy -> parseVEXW rhlp notEn notEn vex0F3899W0 vex0F3899W1
    | 0x9Auy -> parseEVEXW rhlp vex0F389AW0 vex0F389AW1 notEn notEn
    | 0x9Buy -> parseEVEXW rhlp vex0F389BW0 vex0F389BW1 evex0F389BW0 notEn
    | 0x9Cuy -> parseEVEXW rhlp vex0F389CW0 vex0F389CW1 notEn evex0F389CW1
    | 0x9Duy -> parseEVEXW rhlp vex0F389DW0 vex0F389DW1 notEn evex0F389DW1
    | 0x9Euy -> parseEVEXW rhlp vex0F389EW0 vex0F389EW1 notEn notEn
    | 0x9Fuy -> parseEVEXW rhlp vex0F389FW0 vex0F389FW1 notEn notEn
    | 0xA6uy -> parseEVEXW rhlp vex0F38A6W0 vex0F38A6W1 notEn notEn
    | 0xA7uy -> parseEVEXW rhlp vex0F38A7W0 vex0F38A7W1 notEn notEn
    | 0xA8uy -> parseEVEXW rhlp vex0F38A8W0 vex0F38A8W1 evex0F38A8W0 notEn
    | 0xA9uy -> parseVEXW rhlp notEn notEn vex0F38A9W0 vex0F38A9W1
    | 0xAAuy -> parseEVEXW rhlp vex0F38AAW0 vex0F38AAW1 notEn notEn
    | 0xABuy -> parseEVEXW rhlp vex0F38ABW0 vex0F38ABW1 notEn notEn
    | 0xACuy -> parseEVEXW rhlp vex0F38ACW0 vex0F38ACW1 notEn notEn
    | 0xADuy -> parseEVEXW rhlp vex0F38ADW0 vex0F38ADW1 notEn evex0F38ADW1
    | 0xAEuy -> parseEVEXW rhlp vex0F38AEW0 vex0F38AEW1 notEn notEn
    | 0xAFuy -> parseEVEXW rhlp vex0F38AFW0 vex0F38AFW1 notEn notEn
    | 0xB6uy -> parseEVEXW rhlp vex0F38B6W0 vex0F38B6W1 notEn evex0F38B8W1
    | 0xB7uy -> parseEVEXW rhlp vex0F38B7W0 vex0F38B7W1 notEn evex0F38B8W1
    | 0xB8uy -> parseEVEXW rhlp vex0F38B8W0 vex0F38B8W1 notEn evex0F38B8W1
    | 0xB9uy -> parseVEXW rhlp notEn notEn vex0F38B9W0 vex0F38B9W1
    | 0xBAuy -> parseEVEXW rhlp vex0F38BAW0 vex0F38BAW1 notEn notEn
    | 0xBBuy -> parseEVEXW rhlp vex0F38BBW0 vex0F38BBW1 notEn evex0F38BBW1
    | 0xBCuy -> parseEVEXW rhlp vex0F38BCW0 vex0F38BCW1 notEn evex0F38BCW1
    | 0xBDuy -> parseEVEXW rhlp vex0F38BDW0 vex0F38BDW1 notEn evex0F38BDW1
    | 0xBEuy -> parseEVEXW rhlp vex0F38BEW0 vex0F38BEW1 notEn notEn
    | 0xBFuy -> parseEVEXW rhlp vex0F38BFW0 vex0F38BFW1 notEn notEn
    | 0xCBuy -> parseEVEXW rhlp notEn notEn notEn evex0F38CBW1
    | 0xCDuy -> parseEVEXW rhlp notEn notEn notEn evex0F38CDW1
    | 0xF0uy -> parseNonVEX rhlp nor0F38F0
    | 0xF1uy -> parseNonVEX rhlp nor0F38F1
    | 0xF2uy -> parseVEX rhlp notEn vex0F38F2
    | 0xF3uy ->
      if Option.isNone rhlp.VEXInfo then raise ParsingFailureException
      else parseGrpOp rhlp OpGroup.G17 OD.VvRm SZ.Def
    | 0xF5uy -> parseVEXW rhlp nor0F38F5W0 nor0F38F5W1 vex0F38F5W0 vex0F38F5W1
    | 0xF6uy -> parseVEXW rhlp nor0F38F6W0 nor0F38F6W1 vex0F38F6W0 vex0F38F6W1
    | 0xF7uy -> parseVEX rhlp nor0F38F7 vex0F38F7
    | _ -> raise ParsingFailureException

  /// When the first two bytes are 0F3A.
  /// Table A-5 of Volume 2 (Three-byte Opcode Map : First Two Bytes are 0F 3AH)
  let parseThreeByteOp2 (rhlp: ReadHelper) =
    match rhlp.ReadByte () with
    | 0x00uy -> parseEVEXW rhlp notEn vex0F3A00W1 notEn notEn
    | 0x01uy -> parseEVEXW rhlp notEn vex0F3A01W1 notEn notEn
    | 0x02uy -> parseEVEXW rhlp vex0F3A02W0 notEn notEn notEn
    | 0x04uy -> parseEVEXW rhlp vex0F3A04W0 notEn notEn notEn
    | 0x05uy -> parseEVEXW rhlp vex0F3A05W0 notEn notEn notEn
    | 0x06uy -> parseVEXW rhlp notEn notEn vex0F3A06W0 notEn
    | 0x08uy -> parseVEX rhlp nor0F3A08 vex0F3A08
    | 0x09uy -> parseVEX rhlp nor0F3A09 vex0F3A09
    | 0x0Auy -> parseVEX rhlp notEn vex0F3A0A
    | 0x0Buy -> parseEVEX rhlp nor0F3A0B vex0F3A0B notEn evex0F3A0BW1
    | 0x0Cuy -> parseVEX rhlp nor0F3A0C vex0F3A0C
    | 0x0Duy -> parseVEX rhlp notEn vex0F3A0D
    | 0x0Euy -> parseVEX rhlp notEn vex0F3A0E
    | 0x0Fuy -> parseVEX rhlp nor0F3A0F vex0F3A0F
    | 0x14uy -> parseVEXW rhlp notEn notEn vex0F3A14W0 notEn
    | 0x15uy -> parseVEX rhlp nor0F3A15 vex0F3A15
    | 0x16uy -> parseVEX rhlp nor0F3A16 vex0F3A16
    | 0x17uy -> parseEVEX rhlp nor0F3A17 vex0F3A17 notEn notEn
    | 0x18uy -> parseEVEXW rhlp vex0F3A18W0 notEn notEn notEn
    | 0x19uy -> parseEVEXW rhlp vex0F3A19W0 notEn evex0F3A19W0 evex0F3A19W1
    | 0x1Auy -> parseEVEXW rhlp notEn notEn notEn evex0F3A1AW1
    | 0x1Buy -> parseEVEXW rhlp notEn notEn evex0F3A1BW0 evex0F3A1BW1
    | 0x20uy -> parseVEX rhlp nor0F3A20 vex0F3A20
    | 0x21uy -> parseVEX rhlp notEn vex0F3A21
    | 0x22uy ->
      parseEVEXW rhlp vex0F3A22W0 vex0F3A22W1 evex0F3A22W0 evex0F3A22W1
    | 0x25uy -> parseEVEXW rhlp notEn notEn evex0F3A25W0 notEn
    | 0x27uy -> parseEVEXW rhlp notEn notEn notEn evex0F3A27W1
    | 0x38uy -> parseVEX rhlp nor0F3A38 vex0F3A38
    | 0x39uy -> parseEVEXW rhlp vex0F3A39W0 notEn notEn notEn
    | 0x3Auy -> parseEVEXW rhlp notEn notEn evex0F3A3AW0 evex0F3A3AW1
    | 0x3Buy -> parseEVEXW rhlp notEn notEn evex0F3A3BW0 evex0F3A3BW1
    | 0x43uy -> parseEVEXW rhlp notEn notEn evex0F3A43W0 evex0F3A43W1
    | 0x46uy -> parseEVEXW rhlp vex0F3A46W0 notEn notEn notEn
    | 0x4Auy -> parseVEXW rhlp notEn notEn vex0F3A4AW0 notEn
    | 0x4Buy -> parseVEXW rhlp notEn notEn vex0F3A4BW0 notEn
    | 0x4Cuy -> parseVEXW rhlp notEn notEn vex0F3A4CW0 notEn
    | 0x57uy -> parseEVEXW rhlp notEn notEn notEn evex0F3A57W1
    | 0x60uy -> parseVEX rhlp nor0F3A60 vex0F3A60
    | 0x61uy -> parseVEX rhlp nor0F3A61 vex0F3A61
    | 0x62uy -> parseVEX rhlp nor0F3A62 vex0F3A62
    | 0x63uy -> parseVEX rhlp nor0F3A63 vex0F3A63
    | 0xF0uy -> parseVEX rhlp nor0F3AF0 vex0F3AF0
    | _ -> raise ParsingFailureException

  let getOpCode0F0D (rhlp: ReadHelper) =
    let b = rhlp.PeekByte ()
    match modIsMemory b, getReg b with
    | true, 0b001 -> Opcode.PREFETCHW
    | true, 0b010 -> Opcode.PREFETCHWT1
    | _ -> raise ParsingFailureException

  let ignOpSz (rhlp: ReadHelper) =
    rhlp.Prefixes <- rhlp.Prefixes &&& EnumOfValue 0xFDFF
    rhlp

  let pTwoByteOp (rhlp: ReadHelper) byte =
    match byte with
    | 0x02uy -> render rhlp Opcode.LAR SzCond.Nor OD.GprRm SZ.WV
    | 0x03uy -> render rhlp Opcode.LSL SzCond.Nor OD.GprRm SZ.WV
    | 0x05uy ->
#if !EMULATION
      ensure64 rhlp
#endif
      render rhlp Opcode.SYSCALL SzCond.Nor OD.No SZ.Def
    | 0x06uy -> render rhlp Opcode.CLTS SzCond.Nor OD.No SZ.Def
    | 0x07uy ->
#if !EMULATION
      ensure64 rhlp
#endif
      render rhlp Opcode.SYSRET SzCond.Nor OD.No SZ.Def
    | 0x08uy -> render rhlp Opcode.INVD SzCond.Nor OD.No SZ.Def
    | 0x09uy -> render rhlp Opcode.WBINVD SzCond.Nor OD.No SZ.Def
    | 0x0Buy -> render rhlp Opcode.UD2 SzCond.Nor OD.No SZ.Def
    | 0x0Duy -> render rhlp (getOpCode0F0D rhlp) SzCond.Nor OD.Mem SZ.Def
    | 0x10uy -> pVEXByMem rhlp nor0F10 nor0F10 vex0F10Mem vex0F10Reg
    | 0x11uy -> pVEXByMem rhlp nor0F11 nor0F11 vex0F11Mem vex0F11Reg
    | 0x12uy -> pVEXByMem rhlp nor0F12Mem nor0F12Reg vex0F12Mem vex0F12Reg
    | 0x13uy -> parseVEX rhlp nor0F13 vex0F13
    | 0x14uy -> parseVEX rhlp nor0F14 vex0F14
    | 0x15uy -> parseVEX rhlp nor0F15 vex0F15
    | 0x16uy -> pVEXByMem rhlp nor0F16Mem nor0F16Reg vex0F16Mem vex0F16Reg
    | 0x17uy -> parseVEX rhlp nor0F17 vex0F17
    | 0x1Auy -> parseBND rhlp SzCond.Nor nor0F1A
    | 0x1Buy -> parseBND rhlp SzCond.Nor nor0F1B
    | 0x1Euy ->
      if hasREPZ rhlp.Prefixes then parseCETInstr rhlp
      else raise InvalidOpcodeException
    | 0x1Fuy -> render rhlp Opcode.NOP SzCond.Nor OD.Mem SZ.Def (* NOP /0 Ev *)
    | 0x20uy -> render rhlp Opcode.MOV SzCond.F64 OD.RmCtrl SZ.DY
    | 0x21uy -> render rhlp Opcode.MOV SzCond.Nor OD.RmDbg SZ.DY
    | 0x22uy -> render rhlp Opcode.MOV SzCond.Nor OD.CtrlRm SZ.DY
    | 0x23uy -> render rhlp Opcode.MOV SzCond.Nor OD.DbgRm SZ.DY
    | 0x28uy -> parseVEX rhlp nor0F28 vex0F28
    | 0x29uy -> parseVEX rhlp nor0F29 vex0F29
    | 0x2Auy -> parseVEX rhlp nor0F2A vex0F2A
    | 0x2Buy -> parseVEX rhlp nor0F2B vex0F2B
    | 0x2Cuy -> parseVEX rhlp nor0F2C vex0F2C
    | 0x2Duy -> parseVEX rhlp nor0F2D vex0F2D
    | 0x2Euy -> parseVEX rhlp nor0F2E vex0F2E
    | 0x2Fuy -> parseVEX rhlp nor0F2F vex0F2F
    | 0x30uy -> render rhlp Opcode.WRMSR SzCond.Nor OD.No SZ.Def
    | 0x31uy -> render rhlp Opcode.RDTSC SzCond.Nor OD.No SZ.Def
    | 0x32uy -> render rhlp Opcode.RDMSR SzCond.Nor OD.No SZ.Def
    | 0x33uy -> render rhlp Opcode.RDPMC SzCond.Nor OD.No SZ.Def
    | 0x34uy -> render rhlp Opcode.SYSENTER SzCond.Nor OD.No SZ.Def
    | 0x35uy -> render rhlp Opcode.SYSEXIT SzCond.Nor OD.No SZ.Def
    | 0x37uy -> render rhlp Opcode.GETSEC SzCond.Nor OD.No SZ.Def
    | 0x40uy -> render rhlp Opcode.CMOVO SzCond.Nor OD.GprRm SZ.Def
    | 0x41uy -> render rhlp Opcode.CMOVNO SzCond.Nor OD.GprRm SZ.Def
    | 0x42uy -> render rhlp Opcode.CMOVB SzCond.Nor OD.GprRm SZ.Def
    | 0x43uy -> render rhlp Opcode.CMOVAE SzCond.Nor OD.GprRm SZ.Def
    | 0x44uy -> render rhlp Opcode.CMOVZ SzCond.Nor OD.GprRm SZ.Def
    | 0x45uy -> render rhlp Opcode.CMOVNZ SzCond.Nor OD.GprRm SZ.Def
    | 0x46uy -> render rhlp Opcode.CMOVBE SzCond.Nor OD.GprRm SZ.Def
    | 0x47uy -> render rhlp Opcode.CMOVA SzCond.Nor OD.GprRm SZ.Def
    | 0x48uy -> render rhlp Opcode.CMOVS SzCond.Nor OD.GprRm SZ.Def
    | 0x49uy -> render rhlp Opcode.CMOVNS SzCond.Nor OD.GprRm SZ.Def
    | 0x4Auy -> render rhlp Opcode.CMOVP SzCond.Nor OD.GprRm SZ.Def
    | 0x4Buy -> render rhlp Opcode.CMOVNP SzCond.Nor OD.GprRm SZ.Def
    | 0x4Cuy -> render rhlp Opcode.CMOVL SzCond.Nor OD.GprRm SZ.Def
    | 0x4Duy -> render rhlp Opcode.CMOVGE SzCond.Nor OD.GprRm SZ.Def
    | 0x4Euy -> render rhlp Opcode.CMOVLE SzCond.Nor OD.GprRm SZ.Def
    | 0x4Fuy -> render rhlp Opcode.CMOVG SzCond.Nor OD.GprRm SZ.Def
    | 0x50uy -> parseVEX rhlp nor0F50 vex0F50
    | 0x51uy -> parseVEX rhlp nor0F51 vex0F51
    | 0x52uy -> parseVEX rhlp nor0F52 vex0F52
    | 0x53uy -> parseVEX rhlp nor0F53 vex0F53
    | 0x54uy -> parseVEX rhlp nor0F54 vex0F54
    | 0x55uy -> parseVEX rhlp nor0F55 vex0F55
    | 0x56uy -> parseVEX rhlp nor0F56 vex0F56
    | 0x57uy -> parseVEX rhlp nor0F57 vex0F57
    | 0x58uy -> parseVEX rhlp nor0F58 vex0F58
    | 0x59uy -> parseVEX rhlp nor0F59 vex0F59
    | 0x5Auy -> parseEVEX rhlp nor0F5A vex0F5A evex0F5AW0 evex0F5AW1
    | 0x5Buy -> parseVEX rhlp nor0F5B vex0F5B
    | 0x5Cuy -> parseVEX rhlp nor0F5C vex0F5C
    | 0x5Duy -> parseEVEX rhlp nor0F5D vex0F5D evex0F5DW0 notEn
    | 0x5Euy -> parseVEX rhlp nor0F5E vex0F5E
    | 0x5Fuy -> parseEVEX rhlp nor0F5F vex0F5F evex0F5FW0 evex0F5FW1
    | 0x60uy -> parseVEX rhlp nor0F60 vex0F60
    | 0x61uy -> parseVEX rhlp nor0F61 vex0F61
    | 0x62uy -> parseVEX rhlp nor0F62 vex0F62
    | 0x63uy -> parseVEX rhlp nor0F63 vex0F63
    | 0x64uy -> parseVEX rhlp nor0F64 vex0F64
    | 0x65uy -> parseVEX rhlp nor0F65 vex0F65
    | 0x66uy -> parseVEX rhlp nor0F66 vex0F66
    | 0x67uy -> parseVEX rhlp nor0F67 vex0F67
    | 0x68uy -> parseVEX rhlp nor0F68 vex0F68
    | 0x69uy -> parseVEX rhlp nor0F69 vex0F69
    | 0x6Auy -> parseVEX rhlp nor0F6A vex0F6A
    | 0x6Buy -> parseVEX rhlp nor0F6B vex0F6B
    | 0x6Cuy -> parseVEX rhlp nor0F6C vex0F6C
    | 0x6Duy -> parseVEX rhlp nor0F6D vex0F6D
    | 0x6Euy -> parseVEXW rhlp nor0F6EW0 nor0F6EW1 vex0F6EW0 vex0F6EW1
    | 0x6Fuy -> parseEVEX rhlp nor0F6F vex0F6F evex0F6FW0 evex0F6FW1
    | 0x70uy -> parseVEX rhlp nor0F70 vex0F70
    | 0x74uy -> parseVEX rhlp nor0F74 vex0F74
    | 0x75uy -> parseVEX rhlp nor0F75 vex0F75
    | 0x76uy -> parseVEX rhlp nor0F76 vex0F76
    | 0x77uy -> parseVEX rhlp nor0F77 vex0F77
    | 0x78uy -> parseVEX rhlp nor0F78 notEn
    | 0x7Cuy -> parseVEX rhlp notEn vex0F7C
    | 0x7Duy -> parseVEX rhlp notEn vex0F7D
    | 0x7Euy -> parseVEXW rhlp nor0F7EW0 nor0F7EW1 vex0F7EW0 vex0F7EW1
    | 0x7Fuy -> parseEVEX rhlp nor0F7F vex0F7F evex0F7FW0 evex0F7FW1
    | 0x80uy -> addBND rhlp; render rhlp Opcode.JO SzCond.F64 OD.Rel SZ.D64
    | 0x81uy -> addBND rhlp; render rhlp Opcode.JNO SzCond.F64 OD.Rel SZ.D64
    | 0x82uy -> addBND rhlp; render rhlp Opcode.JB SzCond.F64 OD.Rel SZ.D64
    | 0x83uy -> addBND rhlp; render rhlp Opcode.JNB SzCond.F64 OD.Rel SZ.D64
    | 0x84uy -> addBND rhlp; render rhlp Opcode.JZ SzCond.F64 OD.Rel SZ.D64
    | 0x85uy -> addBND rhlp; render rhlp Opcode.JNZ SzCond.F64 OD.Rel SZ.D64
    | 0x86uy -> addBND rhlp; render rhlp Opcode.JBE SzCond.F64 OD.Rel SZ.D64
    | 0x87uy -> addBND rhlp; render rhlp Opcode.JA SzCond.F64 OD.Rel SZ.D64
    | 0x88uy -> addBND rhlp; render rhlp Opcode.JS SzCond.F64 OD.Rel SZ.D64
    | 0x89uy -> addBND rhlp; render rhlp Opcode.JNS SzCond.F64 OD.Rel SZ.D64
    | 0x8Auy -> addBND rhlp; render rhlp Opcode.JP SzCond.F64 OD.Rel SZ.D64
    | 0x8Buy -> addBND rhlp; render rhlp Opcode.JNP SzCond.F64 OD.Rel SZ.D64
    | 0x8Cuy -> addBND rhlp; render rhlp Opcode.JL SzCond.F64 OD.Rel SZ.D64
    | 0x8Duy -> addBND rhlp; render rhlp Opcode.JNL SzCond.F64 OD.Rel SZ.D64
    | 0x8Euy -> addBND rhlp; render rhlp Opcode.JLE SzCond.F64 OD.Rel SZ.D64
    | 0x8Fuy -> addBND rhlp; render rhlp Opcode.JG SzCond.F64 OD.Rel SZ.D64
    | 0x90uy -> render rhlp Opcode.SETO SzCond.Nor OD.Mem SZ.Byte
    | 0x91uy -> render rhlp Opcode.SETNO SzCond.Nor OD.Mem SZ.Byte
    | 0x92uy -> render rhlp Opcode.SETB SzCond.Nor OD.Mem SZ.Byte
    | 0x93uy -> render rhlp Opcode.SETNB SzCond.Nor OD.Mem SZ.Byte
    | 0x94uy -> render rhlp Opcode.SETZ SzCond.Nor OD.Mem SZ.Byte
    | 0x95uy -> render rhlp Opcode.SETNZ SzCond.Nor OD.Mem SZ.Byte
    | 0x96uy -> render rhlp Opcode.SETBE SzCond.Nor OD.Mem SZ.Byte
    | 0x97uy -> render rhlp Opcode.SETA SzCond.Nor OD.Mem SZ.Byte
    | 0x98uy -> render rhlp Opcode.SETS SzCond.Nor OD.Mem SZ.Byte
    | 0x99uy -> render rhlp Opcode.SETNS SzCond.Nor OD.Mem SZ.Byte
    | 0x9Auy -> render rhlp Opcode.SETP SzCond.Nor OD.Mem SZ.Byte
    | 0x9Buy -> render rhlp Opcode.SETNP SzCond.Nor OD.Mem SZ.Byte
    | 0x9Cuy -> render rhlp Opcode.SETL SzCond.Nor OD.Mem SZ.Byte
    | 0x9Duy -> render rhlp Opcode.SETNL SzCond.Nor OD.Mem SZ.Byte
    | 0x9Euy -> render rhlp Opcode.SETLE SzCond.Nor OD.Mem SZ.Byte
    | 0x9Fuy -> render rhlp Opcode.SETG SzCond.Nor OD.Mem SZ.Byte
    | 0xA0uy -> render rhlp Opcode.PUSH SzCond.D64 OD.Fs SZ.RegW
    | 0xA1uy -> render rhlp Opcode.POP SzCond.D64 OD.Fs SZ.RegW
    | 0xA2uy -> render rhlp Opcode.CPUID SzCond.Nor OD.No SZ.Def
    | 0xA3uy -> render rhlp Opcode.BT SzCond.Nor OD.RmGpr SZ.Def
    | 0xA4uy -> render rhlp Opcode.SHLD SzCond.Nor OD.XmRegImm8 SZ.Def
    | 0xA5uy -> render rhlp Opcode.SHLD SzCond.Nor OD.RmGprCL SZ.Def
    | 0xA8uy -> render rhlp Opcode.PUSH SzCond.D64 OD.Gs SZ.RegW
    | 0xA9uy -> render rhlp Opcode.POP SzCond.D64 OD.Gs SZ.RegW
    | 0xAAuy -> render rhlp Opcode.RSM SzCond.Nor OD.No SZ.Def
    | 0xABuy -> render rhlp Opcode.BTS SzCond.Nor OD.RmGpr SZ.Def
    | 0xACuy -> render rhlp Opcode.SHRD SzCond.Nor OD.XmRegImm8 SZ.Def
    | 0xADuy -> render rhlp Opcode.SHRD SzCond.Nor OD.RmGprCL SZ.Def
    | 0xAFuy -> render rhlp Opcode.IMUL SzCond.Nor OD.GprRm SZ.Def
    | 0xB0uy -> render rhlp Opcode.CMPXCHG SzCond.Nor OD.RmGpr SZ.Byte
    | 0xB1uy -> render rhlp Opcode.CMPXCHG SzCond.Nor OD.RmGpr SZ.Def
    | 0xB2uy -> render rhlp Opcode.LSS SzCond.Nor OD.GprM SZ.PRM
    | 0xB3uy -> render rhlp Opcode.BTR SzCond.Nor OD.RmGpr SZ.Def
    | 0xB4uy -> render rhlp Opcode.LFS SzCond.Nor OD.GprM SZ.PRM
    | 0xB5uy -> render rhlp Opcode.LGS SzCond.Nor OD.GprM SZ.PRM
    | 0xB6uy -> render rhlp Opcode.MOVZX SzCond.Nor OD.GprRm SZ.BV
    | 0xB7uy -> render rhlp Opcode.MOVZX SzCond.Nor OD.GprRm SZ.WV
    | 0xB8uy when not <| hasREPZ rhlp.Prefixes -> raise ParsingFailureException
    | 0xB8uy ->
      rhlp.Prefixes <- filterPrefs rhlp.Prefixes
      render rhlp Opcode.POPCNT SzCond.Nor OD.GprRm SZ.Def
    | 0xBBuy when hasREPZ rhlp.Prefixes -> raise ParsingFailureException
    | 0xBBuy -> render rhlp Opcode.BTC SzCond.Nor OD.RmGpr SZ.Def
    | 0xBCuy when hasREPZ rhlp.Prefixes ->
      rhlp.Prefixes <- filterPrefs rhlp.Prefixes
      render rhlp Opcode.TZCNT SzCond.Nor OD.GprRm SZ.Def
    | 0xBCuy -> render rhlp Opcode.BSF SzCond.Nor OD.GprRm SZ.Def
    | 0xBDuy when hasREPZ rhlp.Prefixes ->
      rhlp.Prefixes <- filterPrefs rhlp.Prefixes
      render rhlp Opcode.LZCNT SzCond.Nor OD.GprRm SZ.Def
    | 0xBDuy -> render rhlp Opcode.BSR SzCond.Nor OD.GprRm SZ.Def
    | 0xBEuy -> render rhlp Opcode.MOVSX SzCond.Nor OD.GprRm SZ.BV
    | 0xBFuy -> render rhlp Opcode.MOVSX SzCond.Nor OD.GprRm SZ.WV
    | 0xC0uy -> render rhlp Opcode.XADD SzCond.Nor OD.RmGpr SZ.Byte
    | 0xC1uy -> render rhlp Opcode.XADD SzCond.Nor OD.RmGpr SZ.Def
    | 0xC2uy -> parseEVEX rhlp nor0FC2 vex0FC2 evex0FC2W0 evex0FC2W1
    | 0xC3uy -> render rhlp Opcode.MOVNTI SzCond.Nor OD.RmGpr SZ.Def
    | 0xC4uy -> parseVEX rhlp nor0FC4 vex0FC4
    | 0xC5uy -> parseVEX rhlp nor0FC5 vex0FC5
    | 0xC6uy -> parseVEX rhlp nor0FC6 vex0FC6
    | 0xC8uy -> render (ignOpSz rhlp) Opcode.BSWAP SzCond.Nor OD.Rax SZ.Def
    | 0xC9uy -> render (ignOpSz rhlp) Opcode.BSWAP SzCond.Nor OD.Rcx SZ.Def
    | 0xCAuy -> render (ignOpSz rhlp) Opcode.BSWAP SzCond.Nor OD.Rdx SZ.Def
    | 0xCBuy -> render (ignOpSz rhlp) Opcode.BSWAP SzCond.Nor OD.Rbx SZ.Def
    | 0xCCuy -> render (ignOpSz rhlp) Opcode.BSWAP SzCond.Nor OD.Rsp SZ.Def
    | 0xCDuy -> render (ignOpSz rhlp) Opcode.BSWAP SzCond.Nor OD.Rbp SZ.Def
    | 0xCEuy -> render (ignOpSz rhlp) Opcode.BSWAP SzCond.Nor OD.Rsi SZ.Def
    | 0xCFuy -> render (ignOpSz rhlp) Opcode.BSWAP SzCond.Nor OD.Rdi SZ.Def
    | 0xD0uy -> parseVEX rhlp notEn vex0FD0
    | 0xD1uy -> parseVEX rhlp nor0FD1 vex0FD1
    | 0xD2uy -> parseVEX rhlp nor0FD2 vex0FD2
    | 0xD3uy -> parseVEX rhlp nor0FD3 vex0FD3
    | 0xD4uy -> parseVEX rhlp nor0FD4 vex0FD4
    | 0xD5uy -> parseVEX rhlp nor0FD5 vex0FD5
    | 0xD6uy ->
#if !EMULATION
      ensureVEX128 rhlp
#endif
      parseVEX rhlp nor0FD6 vex0FD6
    | 0xD7uy -> parseVEX rhlp nor0FD7 vex0FD7
    | 0xD8uy -> parseVEX rhlp nor0FD8 vex0FD8
    | 0xD9uy -> parseVEX rhlp nor0FD9 vex0FD9
    | 0xDAuy -> parseVEX rhlp nor0FDA vex0FDA
    | 0xDBuy -> parseVEX rhlp nor0FDB vex0FDB
    | 0xDCuy -> parseVEX rhlp nor0FDC vex0FDC
    | 0xDDuy -> parseVEX rhlp nor0FDD vex0FDD
    | 0xDEuy -> parseVEX rhlp nor0FDE vex0FDE
    | 0xDFuy -> parseVEX rhlp nor0FDF vex0FDF
    | 0xE0uy -> parseVEX rhlp nor0FE0 vex0FE0
    | 0xE1uy -> parseVEX rhlp nor0FE1 vex0FE1
    | 0xE2uy -> parseVEX rhlp nor0FE2 vex0FE2
    | 0xE3uy -> parseVEX rhlp nor0FE3 vex0FE3
    | 0xE4uy -> parseVEX rhlp nor0FE4 vex0FE4
    | 0xE5uy -> parseVEX rhlp nor0FE5 vex0FE5
    | 0xE6uy -> parseEVEX rhlp nor0FE6 vex0FE6 evex0FE6W0 notEn
    | 0xE7uy -> parseEVEX rhlp nor0FE7 vex0FE7 evex0FE7W0 evex0FE7W1
    | 0xE8uy -> parseVEX rhlp nor0FE8 vex0FE8
    | 0xE9uy -> parseVEX rhlp nor0FE9 vex0FE9
    | 0xEAuy -> parseVEX rhlp nor0FEA vex0FEA
    | 0xEBuy -> parseVEX rhlp nor0FEB vex0FEB
    | 0xECuy -> parseVEX rhlp nor0FEC vex0FEC
    | 0xEDuy -> parseVEX rhlp nor0FED vex0FED
    | 0xEEuy -> parseVEX rhlp nor0FEE vex0FEE
    | 0xEFuy -> parseEVEX rhlp nor0FEF vex0FEF evex0FEFW0 evex0FEFW1
    | 0xEFuy -> parseVEX rhlp nor0FEF vex0FEF
    | 0xF0uy -> parseVEX rhlp nor0FF0 vex0FF0
    | 0xF1uy -> parseVEX rhlp nor0FF1 vex0FF1
    | 0xF2uy -> parseVEX rhlp nor0FF2 vex0FF2
    | 0xF3uy -> parseVEX rhlp nor0FF3 vex0FF3
    | 0xF4uy -> parseVEX rhlp nor0FF4 vex0FF4
    | 0xF5uy -> parseVEX rhlp nor0FF5 vex0FF5
    | 0xF6uy -> parseVEX rhlp nor0FF6 vex0FF6
    | 0xF8uy -> parseVEX rhlp nor0FF8 vex0FF8
    | 0xF9uy -> parseVEX rhlp nor0FF9 vex0FF9
    | 0xFAuy -> parseVEX rhlp nor0FFA vex0FFA
    | 0xFBuy -> parseVEX rhlp nor0FFB vex0FFB
    | 0xFCuy -> parseVEX rhlp nor0FFC vex0FFC
    | 0xFDuy -> parseVEX rhlp nor0FFD vex0FFD
    | 0xFEuy -> parseVEX rhlp nor0FFE vex0FFE
    | 0x00uy -> parseGrpOp rhlp OpGroup.G6 OD.No SZ.Def
    | 0x01uy -> parseGrpOp rhlp OpGroup.G7 OD.No SZ.Def
    | 0xBAuy -> parseGrpOp rhlp OpGroup.G8 OD.RmImm8 SZ.Def
    | 0xC7uy -> parseGrpOp rhlp OpGroup.G9 OD.No SZ.Def
    | 0x71uy -> parseGrpOp rhlp OpGroup.G12 OD.No SZ.Def
    | 0x72uy -> parseGrpOp rhlp OpGroup.G13 OD.No SZ.Def
    | 0x73uy -> parseGrpOp rhlp OpGroup.G14 OD.No SZ.Def
    | 0xAEuy -> parseGrpOp rhlp OpGroup.G15 OD.No SZ.Def
    | 0x18uy -> parseGrpOp rhlp OpGroup.G16 OD.Mem SZ.Def
    | 0x38uy -> parseThreeByteOp1 rhlp
    | 0x3Auy -> parseThreeByteOp2 rhlp
    | _ -> raise ParsingFailureException

  (* Table A-3 of Volume 2 (Two-byte Opcode Map) *)
  let parseTwoByteOpcode (rhlp: ReadHelper) =
    rhlp.ReadByte () |> pTwoByteOp rhlp

end
