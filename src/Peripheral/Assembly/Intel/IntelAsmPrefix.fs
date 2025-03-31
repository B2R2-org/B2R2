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

module internal B2R2.Peripheral.Assembly.Intel.AsmPrefix

open B2R2
open B2R2.FrontEnd.Register
open B2R2.FrontEnd.BinLifter.Intel
open B2R2.Peripheral.Assembly.Intel.ParserHelper

let isReg8 (ctx: EncContext) reg = Register.toRegType ctx.WordSize reg = 8<rt>
let isReg16 (ctx: EncContext) reg = Register.toRegType ctx.WordSize reg = 16<rt>
let isReg32 (ctx: EncContext) reg = Register.toRegType ctx.WordSize reg = 32<rt>
let isReg64 (ctx: EncContext) reg = Register.toRegType ctx.WordSize reg = 64<rt>
let isMMXReg reg = Register.Kind.MMX = Register.getKind reg
let isXMMReg reg = Register.Kind.XMM = Register.getKind reg
let isYMMReg reg = Register.Kind.YMM = Register.getKind reg
let isSegReg reg = Register.Kind.Segment = Register.getKind reg
let isFPUReg reg = Register.Kind.FPU = Register.getKind reg

let private isHalfSplit (ctx: EncContext) reg =
  match ctx.Arch, Register.toRegType ctx.WordSize reg with
  | Architecture.IntelX64, 32<rt> -> true
  | Architecture.IntelX86, 16<rt> -> true
  | _ -> false

let private isAddrSize ctx = function
  | OneOperand (OprMem (Some bReg, _, _, _))
  | TwoOperands (_, OprMem (Some bReg, _, _, _))
  | TwoOperands (OprMem (Some bReg, _, _, _), _) -> isHalfSplit ctx bReg
  | _ -> false

let getPrefByte = function
  | 0x1 -> 0xF0uy (* Prefix.PrxLOCK *)
  | 0x2 -> 0xF2uy (* Prefix.PrxREPNZ *)
  | 0x4 -> 0xF3uy (* Prefix.PrxREPZ *)
  | 0x8 -> 0x2Euy (* Prefix.PrxCS *)
  | 0x10 -> 0x36uy (* Prefix.PrxSS *)
  | 0x20 -> 0x3Euy (* Prefix.PrxDS *)
  | 0x40 -> 0x26uy (* Prefix.PrxES *)
  | 0x80 -> 0x64uy (* Prefix.PrxFS *)
  | 0x100 -> 0x65uy (* Prefix.PrxGS *)
  | 0x0 -> 0x0uy
  | _ -> failwith "Invalid prefix"

let getGrp1Pref prefs = prefs &&& 0x7 |> getPrefByte
let getGrp2Pref prefs = prefs &&& 0x1F8 |> getPrefByte

let encodePrefix ins ctx (pref: EncPrefix) =
  let prefs = LanguagePrimitives.EnumToValue ins.Prefixes
  (* Prefix group1 and group2 *)
  let prxGrp1 =
    let pGrp1 = getGrp1Pref prefs
    if pGrp1 = 0uy then [||]
    else if ((pGrp1 = 0xF0uy) && pref.CanLock) ||
            ((pGrp1 = 0xF2uy || pGrp1 = 0xF3uy) && pref.CanRep)
         then [| pGrp1 |> Normal |]
         else failwith "Invalid prefix (Lock)"
  let prxGrp2 =
    let pGrp2 = getGrp2Pref prefs
    if pGrp2 = 0uy then [||]
    else if pref.CanSeg then [| pGrp2 |> Normal |]
         else printfn "%A" ins; failwith "Invalid prefix (Segment)"
  (* Prefix group3: Operand-size override control with mandatory prefix *)
  let mandPrx =
    match pref.MandPrefix with
    | Prefix.PrxREPZ -> [| Normal 0xF3uy |]
    | Prefix.PrxREPNZ -> [| Normal 0xF2uy |]
    | Prefix.PrxOPSIZE -> [| Normal 0x66uy |]
    | _ -> [||]
  (* Prefix group4: Address-size override *)
  let prxGrp4 =
    if isAddrSize ctx ins.Operands then [| Normal 0x67uy |] else [||]
  [| yield! prxGrp1; yield! prxGrp2; yield! mandPrx; yield! prxGrp4 |]

let encodeRex = function
  | Intel.SPL | Intel.BPL | Intel.SIL | Intel.DIL -> 0x40uy
  | _ -> 0x0uy

let isExtendReg = function
  | Intel.R8B | Intel.R8W | Intel.R8D | Intel.R8
  | Intel.R9B | Intel.R9W | Intel.R9D | Intel.R9
  | Intel.R10B | Intel.R10W | Intel.R10D | Intel.R10
  | Intel.R11B | Intel.R11W | Intel.R11D | Intel.R11
  | Intel.R12B | Intel.R12W | Intel.R12D | Intel.R12
  | Intel.R13B | Intel.R13W | Intel.R13D | Intel.R13
  | Intel.R14B | Intel.R14W | Intel.R14D | Intel.R14
  | Intel.R15B | Intel.R15W | Intel.R15D | Intel.R15
  | Intel.XMM8 | Intel.XMM9 | Intel.XMM10 | Intel.XMM11
  | Intel.XMM12 | Intel.XMM13 | Intel.XMM14 | Intel.XMM15 -> true
  | _ -> false

let encodeRexR reg = if isExtendReg reg then 0x44uy else 0x0uy
let encodeRexX reg = if isExtendReg reg then 0x42uy else 0x0uy
let encodeRexB reg = if isExtendReg reg then 0x41uy else 0x0uy

let convVEXRexByte rexByte = (~~~ rexByte) &&& 0b111uy

let encodeVEXRexRB arch r1 r2 =
  if arch = Architecture.IntelX86 then 0b101uy
  else convVEXRexByte (encodeRexR r1 ||| encodeRexB r2)

let encodeVEXRexRXB arch reg rmOrSBase sIdx =
  if arch = Architecture.IntelX86 then 0b111uy
  else
    match rmOrSBase, sIdx with
    | Some r1, Some (r2, _) ->
      convVEXRexByte (encodeRexR reg ||| encodeRexX r2 ||| encodeRexB r1)
    | Some r1, None ->
      convVEXRexByte (encodeRexR reg ||| encodeRexB r1)
    | None, Some (r2, _) ->
      convVEXRexByte (encodeRexR reg ||| encodeRexX r2)
    | None, None -> convVEXRexByte (encodeRexR reg)

let encodeRexRR ctx isMR r1 r2 =
  if ((isReg8 ctx r1 || isReg32 ctx r1 || isReg64 ctx r1) && isReg8 ctx r2) then
    if isMR
    then encodeRex r1 ||| encodeRex r2 ||| encodeRexR r2 ||| encodeRexB r1
    else encodeRex r1 ||| encodeRex r2 ||| encodeRexR r1 ||| encodeRexB r2
  elif isMR then encodeRexR r2 ||| encodeRexB r1
  else encodeRexR r1 ||| encodeRexB r2

let encodeRexRM ctx r b s =
  let rex = if isReg8 ctx r then encodeRex r else 0uy
  match b, s with
  | Some b, Some (s, _) ->
    rex ||| encodeRexR r ||| encodeRexX s ||| encodeRexB b
  | Some b, None -> rex ||| encodeRexR r ||| encodeRexB b
  | None, Some (s, _) -> rex ||| encodeRexR r ||| encodeRexX s
  | None, None -> rex ||| encodeRexR r

let encodeRexRXB ctx isMR = function
  | NoOperand
  | OneOperand (Label _) | OneOperand (OprDirAddr _)
  | OneOperand (OprImm _)
  | TwoOperands (OprMem (None, None, Some _, _), OprImm _)
  | TwoOperands (Label _, OprImm _) -> 0uy
  | OneOperand (OprReg r) ->
    if isReg8 ctx r then encodeRex r ||| encodeRexB r else encodeRexB r
  | OneOperand (OprMem (Some bReg, Some (s, _), _, _)) ->
    encodeRexX s ||| encodeRexB bReg
  | OneOperand (OprMem (Some bReg, None, _, _)) -> encodeRexB bReg
  | OneOperand (OprMem (None, Some (s, _), _, _)) -> encodeRexX s
  | TwoOperands (OprReg r1, OprReg r2) -> encodeRexRR ctx isMR r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, _, _))
  | TwoOperands (OprMem (b, s, _, _), OprReg r) -> encodeRexRM ctx r b s
  | TwoOperands (OprReg r, OprImm _) ->
    if isReg8 ctx r then encodeRex r ||| encodeRexB r else encodeRexB r
  | TwoOperands (OprMem (Some bReg, None, _, _), OprImm _) -> encodeRexB bReg
  | TwoOperands (OprMem (Some bReg, Some (s, _), _, _), OprImm _) ->
    encodeRexR s ||| encodeRexB bReg
  | TwoOperands (OprReg r, Label _) | TwoOperands (Label _, OprReg r) ->
    encodeRexR r
  | ThreeOperands (OprReg r1, OprReg r2, OprImm _) ->
    encodeRexR r1 ||| encodeRexB r2
  | ThreeOperands (OprReg r, OprMem (Some bReg, Some (s, _), _, _), OprImm _) ->
    encodeRexR r ||| encodeRexX s ||| encodeRexB bReg
  | ThreeOperands (OprReg r, OprMem (Some bReg, None, _, _), OprImm _) ->
    encodeRexR r ||| encodeRexB bReg
  | ThreeOperands (OprReg r, OprMem (None, None, _, _), OprImm _) ->
    encodeRexR r
  | ThreeOperands (OprReg r, Label _, OprImm _) -> encodeRexR r
  | o -> printfn "Inavlid Operand (%A)" o; Utils.futureFeature ()

let encodeREXPref ins (ctx: EncContext) (rexPrx: EncREXPrefix) =
  if ctx.Arch = Architecture.IntelX86 then [||]
  else (* Arch.IntelX64 *)
    let rexW = if rexPrx.RexW then 0x48uy else 0uy
    let rxb = encodeRexRXB ctx rexPrx.IsMemReg ins.Operands
    if rxb = 0uy && rexW = 0uy then [||] else [| Normal (rexW ||| rxb) |]

let private getLeadingOpcodeByte = function (* m-mmmm *)
  | VEXType.VEXTwoByteOp -> 0b00001uy
  | VEXType.VEXThreeByteOpOne -> 0b00010uy
  | VEXType.VEXThreeByteOpTwo -> 0b00011uy
  | _ -> Utils.impossible ()

let private getVVVVByte = function
  | Some Intel.XMM0 | Some Intel.YMM0
  | Some Intel.EAX | Some Intel.RAX -> 0b1111uy
  | Some Intel.XMM1 | Some Intel.YMM1
  | Some Intel.ECX | Some Intel.RCX -> 0b1110uy
  | Some Intel.XMM2 | Some Intel.YMM2
  | Some Intel.EDX | Some Intel.RDX -> 0b1101uy
  | Some Intel.XMM3 | Some Intel.YMM3
  | Some Intel.EBX | Some Intel.RBX -> 0b1100uy
  | Some Intel.XMM4 | Some Intel.YMM4
  | Some Intel.ESP | Some Intel.RSP -> 0b1011uy
  | Some Intel.XMM5 | Some Intel.YMM5
  | Some Intel.EBP | Some Intel.RBP -> 0b1010uy
  | Some Intel.XMM6 | Some Intel.YMM6
  | Some Intel.ESI | Some Intel.RSI -> 0b1001uy
  | Some Intel.XMM7 | Some Intel.YMM7
  | Some Intel.EDI | Some Intel.RDI -> 0b1000uy
  | Some Intel.XMM8 | Some Intel.YMM8 -> 0b0111uy
  | Some Intel.XMM9 | Some Intel.YMM9 -> 0b0110uy
  | Some Intel.XMM10 | Some Intel.YMM10 -> 0b0101uy
  | Some Intel.XMM11 | Some Intel.YMM11 -> 0b0100uy
  | Some Intel.XMM12 | Some Intel.YMM12 -> 0b0011uy
  | Some Intel.XMM13 | Some Intel.YMM13 -> 0b0010uy
  | Some Intel.XMM14 | Some Intel.YMM14 -> 0b0001uy
  | Some Intel.XMM15 | Some Intel.YMM15 -> 0b0000uy
  | None -> 0b1111uy
  | _ -> Utils.impossible ()

let private getVLen = function
  | 128<rt> -> 0b0uy
  | 256<rt> -> 0b1uy
  | 32<rt> | 64<rt> -> 0b0uy // Scalar
  | _ -> Utils.impossible ()

let private getSIMDPref = function
  | Prefix.PrxNone -> 0b00uy
  | Prefix.PrxOPSIZE (* 0x66 *) -> 0b01uy
  | Prefix.PrxREPZ   (* 0xF3 *) -> 0b10uy
  | Prefix.PrxREPNZ  (* 0xF2 *) -> 0b11uy
  | _ -> Utils.impossible ()

let encodeTwoVEXPref rexR vvvv (vex: EncVEXPrefix) =
  let vvvv = getVVVVByte vvvv
  let vectorLen = getVLen vex.VecLen
  let pp = getSIMDPref vex.PP
  let sndVByte = (rexR <<< 7) + (vvvv <<< 3) + (vectorLen <<< 2) + pp
  [| Normal 0xC5uy; Normal sndVByte |]

let encodeThreeVEXPref rexRXB vvvv (vex: EncVEXPrefix) =
  let mmmmm = getLeadingOpcodeByte vex.LeadingOpcode
  let rexW = if vex.RexW = REXPrefix.REXW then 0b1uy else 0b0uy
  let vvvv = getVVVVByte vvvv
  let vectorLen = getVLen vex.VecLen
  let pp = getSIMDPref vex.PP
  let sndVByte = (rexRXB <<< 5) + mmmmm
  let trdVByte = (rexW <<< 7) + (vvvv <<< 3) + (vectorLen <<< 2) + pp
  [| Normal 0xC4uy; Normal sndVByte; Normal trdVByte |]

let isTwoByteVEX rexRXB (vex: EncVEXPrefix) =
  (rexRXB = 0b111uy || rexRXB = 0b011uy) &&
  vex.LeadingOpcode = VEXType.VEXTwoByteOp &&
  vex.RexW = REXPrefix.NOREX && vex.PP = Prefix.PrxOPSIZE

let encodeVEXPref rexRXB vvvv (vex: EncVEXPrefix) =
  if isTwoByteVEX rexRXB vex
  then encodeTwoVEXPref ((rexRXB >>> 2) &&& 0b1uy) vvvv vex
  else encodeThreeVEXPref rexRXB vvvv vex

// vim: set tw=80 sts=2 sw=2:
