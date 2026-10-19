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

/// <summary>
/// The Decimal Floating-Point facility (Power ISA v3.1 Book I chapter 5).
/// LowUIR has no decimal arithmetic, so every instruction is a named call
/// for its result -- the value its target receives -- and one, DFPEXC, for
/// the FPSCR status it produces; this module merges that status into the
/// FPSCR, keeps the target where an enabled exception suppresses the result,
/// and records CR1 or CR field BF. optest-powerpc/lanes/F.md specifies every
/// name: its arguments, its result, and the status word's bits.
/// </summary>
module internal B2R2.FrontEnd.PPC.DFPLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC
open B2R2.FrontEnd.PPC.LiftingUtils
open B2R2.FrontEnd.PPC.OperandHelper

/// The FPSCR fields a DFP instruction replaces from the status word: FPRF
/// with FR and FI, FR and FI alone (FPRF undefined), FPCC alone (a compare or
/// a test), or none (an instruction that alters no FPSCR bit).
type private Fields =
  | ResultFields = 0x7f000u
  | RoundingFields = 0x60000u
  | ConditionFields = 0xf000u
  | NoFields = 0u

/// One DFP instruction as the lifting below takes it.
type private DFPOp =
  { /// The result call, if the instruction delivers a result.
    Name: string option
    /// The width of the result: 64 for one FPR, 128 for a pair or a VR.
    Width: RegType
    /// The arguments of the result call, and of the status call, before the
    /// control byte.
    Args: Expr list
    /// Whether the result call takes the control byte.
    TakesControl: bool
    /// The status call's code, if the instruction alters the FPSCR.
    Code: uint64 option
    /// The fields the status word replaces.
    Fields: Fields
    /// The rounding mode in the DRN encoding, as an 8-bit expression.
    Mode: Expr }

/// FPSCR[DRN], the decimal rounding mode: the low three bits of the FPSCR's
/// high word.
let private drn bld =
  AST.xtlo 8<rt> (regVar bld Register.FPSCRH) .& numU32 7u 8<rt>

/// The control byte every rounding call takes: the rounding mode in bits 2:0
/// and VE, OE, UE, ZE, XE (FPSCR bits 56:60) above it, where FPSCR keeps
/// them.
let private control bld mode =
  let fpscr = AST.xtlo 8<rt> (regVar bld Register.FPSCR)
  (fpscr .& numU32 0xf8u 8<rt>) .| mode

/// The status call: DFPEXC with the operation's code, its arguments and the
/// control byte, answering the FPSCR bits the operation produces.
let private statusOf (o: DFPOp) code ctl =
  AST.app "DFPEXC" ((numU64 code 8<rt> :: o.Args) @ [ ctl ]) 32<rt>

/// The result call.
let private resultOf (o: DFPOp) name ctl =
  let args = if o.TakesControl then o.Args @ [ ctl ] else o.Args
  AST.app name args o.Width

/// The status word's exception bits: OX, UX, ZX, XX, VXSNAN to VXVC, VXCVI.
let private exceptionMask = numU32 0x1ff80100u 32<rt>

/// The invalid-operation causes among them, which VE enables.
let private invalidMask = numU32 0x01f80100u 32<rt>

/// Whether the result is suppressed: an enabled invalid operation, or an
/// enabled zero divide, keeps the target as it was.
let private suppression old exc =
  (AST.extract old 1<rt> 7 .& ((exc .& invalidMask) != AST.num0 32<rt>))
  .| (AST.extract old 1<rt> 4 .& AST.extract exc 1<rt> 26)

/// <summary>
/// The FPSCR after a DFP instruction: the exception bits of the status word
/// OR-ed in, the fields the instruction replaces taken from the status word
/// (FPRF kept where the result was suppressed), FX set where an exception
/// bit turned on, and FEX and VX recomputed.
/// </summary>
let private recordStatus bld st (fields: Fields) suppressed =
  let fpscr = regVar bld Register.FPSCR
  let struct (old, exc) = tmpVars2 bld 32<rt>
  let m = uint32 fields
  let kept = numU32 (m &&& 0x1f000u) 32<rt>
  let taken = numU32 (m &&& 0x60000u) 32<rt>
  let replaced = (st .& taken) .| (old .& kept)
  let replaced = AST.ite suppressed replaced (st .& numU32 m 32<rt>)
  let turnedOn = (exc .& AST.not old) != AST.num0 32<rt>
  append bld {
    old := fpscr
    exc := st .& exceptionMask
    suppressed := suppression old exc
    fpscr :=
      ((old .| exc) .& numU32 ~~~m 32<rt>) .| replaced
      .| (AST.zext 32<rt> turnedOn << numI32 31 32<rt>)
  }
  FPLifter.updateSummaries bld

/// <summary>
/// A DFP instruction: the status first, from the operands as they were (a
/// target may be one of them), then the result, which `write` puts into the
/// target given the result, the status word and whether the result is
/// suppressed; then CR1 for a record form.
/// </summary>
let private liftDFP ins bld (o: DFPOp) write updateCond =
  lift bld ins {
    let ctl = tmpVar bld 8<rt>
    let st = tmpVar bld 32<rt>
    let res = tmpVar bld o.Width
    let suppressed = tmpVar bld 1<rt>
    ctl := control bld o.Mode
    suppressed := AST.b0
    match o.Code with
    | Some code -> st := statusOf o code ctl
    | None -> st := AST.num0 32<rt>
    if o.Code.IsSome then recordStatus bld st o.Fields suppressed else ()
    match o.Name with
    | Some name -> res := resultOf o name ctl
    | None -> ()
    write res st suppressed
    if updateCond then setCR1Reg bld else ()
  }

/// The odd register of the pair an operand names by its even one.
let private oddOf (bld: ILowUIRBuilder) = function
  | OprReg r ->
    let odd: Register = LanguagePrimitives.EnumOfValue(int r + 1)
    regVar bld odd
  | _ ->
    raise InvalidOperandException

/// A DFP operand of a long form (decimal64, one FPR) or of a quad form
/// (decimal128, the even register of the pair over the odd one).
let private operand quad bld opr =
  if quad then AST.concat (transOpr bld opr) (oddOf bld opr)
  else transOpr bld opr

/// A 64-bit operand whatever the form: an FPR holding an integer, an
/// exponent or a significance.
let private single bld opr = transOpr bld opr

/// An immediate field as the byte a call takes.
let private imm8 opr = numU64 (uint64 (getImmValue opr) &&& 0xffUL) 8<rt>

/// Writes a 64-bit result into one FPR unless it is suppressed.
let private intoOne bld opr (res: Expr) _ suppressed =
  let dst = transOpr bld opr
  append bld {
    dst := AST.ite suppressed dst res
  }

/// Writes a 128-bit result into the even-odd pair an operand names.
let private intoPair bld opr (res: Expr) _ suppressed =
  let even = transOpr bld opr
  let odd = oddOf bld opr
  append bld {
    even := AST.ite suppressed even (AST.xthi 64<rt> res)
    odd := AST.ite suppressed odd (AST.xtlo 64<rt> res)
  }

/// Writes a 128-bit result into a vector register, its high half first.
let private intoVector bld opr (res: Expr) _ suppressed =
  let hi = transOpr bld opr
  let lo =
    match opr with
    | OprReg r -> regVar bld (getLowHalf r)
    | _ -> raise InvalidOperandException
  append bld {
    hi := AST.ite suppressed hi (AST.xthi 64<rt> res)
    lo := AST.ite suppressed lo (AST.xtlo 64<rt> res)
  }

/// Writes the four bits 15:12 of the status word, FPCC, into CR field BF.
let private intoField bld opr _ (st: Expr) _ =
  let struct (c0, c1, c2, c3) =
    match opr with
    | OprReg r ->
      let a, b, c, d = transCRxToExpr bld r
      struct (a, b, c, d)
    | _ ->
      raise InvalidOperandException
  append bld {
    c0 := AST.extract st 1<rt> 15
    c1 := AST.extract st 1<rt> 14
    c2 := AST.extract st 1<rt> 13
    c3 := AST.extract st 1<rt> 12
  }

/// How a quad form's or a long form's result is written: into a pair or
/// into one FPR, and its width.
let private targetOf quad bld opr =
  if quad then struct (128<rt>, intoPair bld opr)
  else struct (64<rt>, intoOne bld opr)

/// The name of the quad form of a call and its status code, the long form's
/// code + 1.
let private formOf quad (name: string) code =
  if quad then struct (name + "Q", code + 1UL) else struct (name, code)

/// A DFPOp rounding in DRN, replacing FPRF, FR and FI.
let private rounding bld name width args code =
  { Name = Some name
    Width = width
    Args = args
    TakesControl = true
    Code = Some code
    Fields = Fields.ResultFields
    Mode = drn bld }

/// dadd, dsub, dmul and ddiv, "FRT, FRA, FRB", and their quad forms.
let arith ins quad name code updateCond bld =
  let struct (t, a, b) = getThreeOprs ins
  let struct (width, write) = targetOf quad bld t
  let struct (name, code) = formOf quad name code
  let args = [ operand quad bld a; operand quad bld b ]
  liftDFP ins bld (rounding bld name width args code) write updateCond

/// A compare or a test into CR field BF, which the status word's FPCC is.
let private test ins bld bf args code =
  let o =
    { rounding bld "" 64<rt> args code with
        Name = None
        Fields = Fields.ConditionFields }
  liftDFP ins bld o (intoField bld bf) false

/// dcmpu, dcmpo and dtstex, "BF, FRA, FRB", and their quad forms.
let compare ins quad code bld =
  let struct (bf, a, b) = getThreeOprs ins
  let code = if quad then code + 1UL else code
  test ins bld bf [ operand quad bld a; operand quad bld b ] code

/// dtstsf, "BF, FRA, FRB", whose FRA is a significance, not a DFP operand.
let tstsf ins quad bld =
  let struct (bf, a, b) = getThreeOprs ins
  let code = if quad then 20UL else 19UL
  test ins bld bf [ single bld a; operand quad bld b ] code

/// dtstsfi, "BF, UIM, FRB".
let tstsfi ins quad bld =
  let struct (bf, uim, b) = getThreeOprs ins
  let code = if quad then 22UL else 21UL
  test ins bld bf [ imm8 uim; operand quad bld b ] code

/// dtstdc and dtstdg, "BF, FRA, DCM" and "BF, FRA, DGM".
let tstData ins quad code bld =
  let struct (bf, a, mask) = getThreeOprs ins
  let code = if quad then code + 1UL else code
  test ins bld bf [ operand quad bld a; imm8 mask ] code

/// The rounding mode an RMC field names (Figures 72 and 73): the primary
/// encoding, whose 3 defers to DRN, or the secondary one.
let private rmcMode bld secondary rmc =
  let rmc = int (getImmValue rmc)
  let table = if secondary then [| 2u; 3u; 6u; 5u |] else [| 0u; 1u; 4u; 0u |]
  if not secondary && rmc = 3 then drn bld
  else numU32 table[rmc] 8<rt>

/// dqua "FRT, FRA, FRB, RMC" (FRA a DFP operand) and drrnd (FRA a
/// significance), and their quad forms, rounding as RMC says.
let quantize ins quad name code dfpA updateCond bld =
  let struct (t, a, b, rmc) = getFourOprs ins
  let struct (width, write) = targetOf quad bld t
  let struct (name, code) = formOf quad name code
  let a = if dfpA then operand quad bld a else single bld a
  let o = rounding bld name width [ a; operand quad bld b ] code
  let o = { o with Mode = rmcMode bld false rmc }
  liftDFP ins bld o write updateCond

/// dquai "TE, FRT, FRB, RMC", and its quad form.
let quantizeImm ins quad updateCond bld =
  let struct (te, t, b, rmc) = getFourOprs ins
  let struct (width, write) = targetOf quad bld t
  let struct (name, code) = formOf quad "DQUAI" 23UL
  let o = rounding bld name width [ imm8 te; operand quad bld b ] code
  let o = { o with Mode = rmcMode bld false rmc }
  liftDFP ins bld o write updateCond

/// drintx and drintn "R, FRT, FRB, RMC", and their quad forms: R picks the
/// encoding RMC is read in.
let roundToInt ins quad name code updateCond bld =
  let struct (r, t, b, rmc) = getFourOprs ins
  let struct (width, write) = targetOf quad bld t
  let struct (name, code) = formOf quad name code
  let o = rounding bld name width [ operand quad bld b ] code
  let o = { o with Mode = rmcMode bld (getImmValue r = 1u) rmc }
  liftDFP ins bld o write updateCond

/// The 128 bits of a vector register, its high half over its low one.
let private vectorOf bld opr =
  match opr with
  | OprReg r -> AST.concat (transOpr bld opr) (regVar bld (getLowHalf r))
  | _ -> raise InvalidOperandException

/// What a conversion reads: a DFP Short in the low word of an FPR, one FPR,
/// a pair, or a VR.
type private ConvertFrom =
  | FromShort
  | FromOne
  | FromPair
  | FromVector

/// What a conversion writes: one FPR, a pair, or a VR.
type private ConvertTo =
  | ToOne
  | ToPair
  | ToVector

/// The operand a conversion reads.
let private convertArg bld b = function
  | FromShort -> AST.xtlo 32<rt> (transOpr bld b)
  | FromOne -> transOpr bld b
  | FromPair -> operand true bld b
  | FromVector -> vectorOf bld b

/// The width of a conversion's result and how it is written.
let private convertTarget bld t = function
  | ToOne -> struct (64<rt>, intoOne bld t)
  | ToPair -> struct (128<rt>, intoPair bld t)
  | ToVector -> struct (128<rt>, intoVector bld t)

/// <summary>
/// The conversions and the roundings between the formats, "FRT, FRB":
/// dctdp, dctqpq, drsp, drdpq, dcffix[q][q] and dctfix[q][q], each with its
/// call, its status code, what it reads and writes, and the FPSCR fields it
/// replaces (FR and FI alone for a conversion to fixed, whose FPRF the
/// manual leaves undefined).
/// </summary>
let private convert ins name code (fromKind, toKind) fields updateCond bld =
  let struct (t, b) = getTwoOprs ins
  let struct (width, write) = convertTarget bld t toKind
  let o = rounding bld name width [ convertArg bld b fromKind ] code
  liftDFP ins bld { o with Fields = fields } write updateCond

/// dctdp: a DFP Short widened to a DFP Long.
let ctdp ins u bld =
  convert ins "DCTDP" 33UL (FromShort, ToOne) Fields.ResultFields u bld

/// dctqpq: a DFP Long widened to a DFP Extended.
let ctqpq ins u bld =
  convert ins "DCTQPQ" 34UL (FromOne, ToPair) Fields.ResultFields u bld

/// drsp: a DFP Long rounded to a DFP Short.
let rsp ins u bld =
  convert ins "DRSP" 35UL (FromOne, ToOne) Fields.ResultFields u bld

/// drdpq: a DFP Extended rounded to a DFP Long.
let rdpq ins u bld =
  convert ins "DRDPQ" 36UL (FromPair, ToPair) Fields.ResultFields u bld

/// dcffix: a signed doubleword converted to a DFP Long.
let cffix ins u bld =
  convert ins "DCFFIX" 37UL (FromOne, ToOne) Fields.ResultFields u bld

/// dcffixq: a signed doubleword converted to a DFP Extended.
let cffixq ins u bld =
  convert ins "DCFFIXQ" 38UL (FromOne, ToPair) Fields.ResultFields u bld

/// dcffixqq: a signed quadword in a VR converted to a DFP Extended.
let cffixqq ins bld =
  convert ins "DCFFIXQQ" 39UL (FromVector, ToPair) Fields.ResultFields false bld

/// dctfix: a DFP Long converted to a signed doubleword.
let ctfix ins u bld =
  convert ins "DCTFIX" 40UL (FromOne, ToOne) Fields.RoundingFields u bld

/// dctfixq: a DFP Extended converted to a signed doubleword.
let ctfixq ins u bld =
  convert ins "DCTFIXQ" 41UL (FromPair, ToOne) Fields.RoundingFields u bld

/// dctfixqq: a DFP Extended converted to a signed quadword in a VR.
let ctfixqq ins bld =
  let kinds = FromPair, ToVector
  convert ins "DCTFIXQQ" 42UL kinds Fields.RoundingFields false bld

/// denbcd "S, FRT, FRB" and its quad form, which encode BCD as DPD.
let enbcd ins quad updateCond bld =
  let struct (s, t, b) = getThreeOprs ins
  let struct (width, write) = targetOf quad bld t
  let struct (name, code) = formOf quad "DENBCD" 43UL
  let o = rounding bld name width [ imm8 s; operand quad bld b ] code
  liftDFP ins bld o write updateCond

/// An instruction that alters no FPSCR bit and rounds nothing: only its
/// result call, without the control byte.
let private plain bld name width args =
  { Name = Some name
    Width = width
    Args = args
    TakesControl = false
    Code = None
    Fields = Fields.NoFields
    Mode = drn bld }

/// ddedpd "SP, FRT, FRB" and its quad form, which decode DPD as BCD.
let dedpd ins quad updateCond bld =
  let struct (sp, t, b) = getThreeOprs ins
  let struct (width, write) = targetOf quad bld t
  let name = if quad then "DDEDPDQ" else "DDEDPD"
  let o = plain bld name width [ imm8 sp; operand quad bld b ]
  liftDFP ins bld o write updateCond

/// dxex "FRT, FRB" and its quad form, whose result is one FPR either way.
let xex ins quad updateCond bld =
  let struct (t, b) = getTwoOprs ins
  let name = if quad then "DXEXQ" else "DXEX"
  let o = plain bld name 64<rt> [ operand quad bld b ]
  liftDFP ins bld o (intoOne bld t) updateCond

/// diex "FRT, FRA, FRB" and its quad form, whose FRA is an exponent.
let iex ins quad updateCond bld =
  let struct (t, a, b) = getThreeOprs ins
  let struct (width, write) = targetOf quad bld t
  let name = if quad then "DIEXQ" else "DIEX"
  let o = plain bld name width [ single bld a; operand quad bld b ]
  liftDFP ins bld o write updateCond

/// dscli and dscri "FRT, FRA, SH" and their quad forms.
let shift ins quad (name: string) updateCond bld =
  let struct (t, a, sh) = getThreeOprs ins
  let struct (width, write) = targetOf quad bld t
  let name = if quad then name + "Q" else name
  let o = plain bld name width [ operand quad bld a; imm8 sh ]
  liftDFP ins bld o write updateCond
