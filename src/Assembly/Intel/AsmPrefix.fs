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

module internal B2R2.Assembly.Intel.AsmPrefix

open B2R2
open B2R2.FrontEnd.Intel
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.Intel.ParserHelper

type EncREXPrefix =
  struct
    val RexW: bool
    val IsMemReg: bool
    new(w, mr) =
      { RexW = w
        IsMemReg = mr }
  end

and EncVEXPrefix =
  struct
    val LeadingOpcode: VEXType
    val RexW: REXPrefix
    val VecLen: RegType
    val PP: Prefix
    new(vt, w, l, p) =
      { LeadingOpcode = vt
        RexW = w
        VecLen = l
        PP = p }
  end

(* The mandatory prefix, REX and VEX combinations the encoders choose between.
   None of them depends on the word size, so they are constants rather than
   members of an encoding context object. *)

let prefNormal = Prefix.None

let prefF3 = Prefix.REPZ

let prefF2 = Prefix.REPNZ

let pref66 = Prefix.OPSIZE

let rexNormal = EncREXPrefix(false, false)

let rexW = EncREXPrefix(true, false)

let rexMR = EncREXPrefix(false, true)

let rexWAndMR = EncREXPrefix(true, true)

let vex128n0F =
  EncVEXPrefix(VEXType.TwoByteOp, REXPrefix.NOREX, 128<rt>, Prefix.None)

let vex256n0F =
  EncVEXPrefix(VEXType.TwoByteOp, REXPrefix.NOREX, 256<rt>, Prefix.None)

let vex128nF3n0F =
  EncVEXPrefix(VEXType.TwoByteOp, REXPrefix.NOREX, 128<rt>, Prefix.REPZ)

let vex128nF2n0F =
  EncVEXPrefix(VEXType.TwoByteOp, REXPrefix.NOREX, 128<rt>, Prefix.REPNZ)

let vex128n66n0F =
  EncVEXPrefix(VEXType.TwoByteOp, REXPrefix.NOREX, 128<rt>, Prefix.OPSIZE)

let vex256n66n0F =
  EncVEXPrefix(VEXType.TwoByteOp, REXPrefix.NOREX, 256<rt>, Prefix.OPSIZE)

let vex128n66n0F3A =
  EncVEXPrefix(VEXType.ThreeByteOpTwo, REXPrefix.NOREX, 128<rt>,
    Prefix.OPSIZE)

let vex256n66n0F3A =
  EncVEXPrefix(VEXType.ThreeByteOpTwo, REXPrefix.NOREX, 256<rt>,
    Prefix.OPSIZE)

/// Whether the register is a general-purpose one of the given width. Anything
/// with no general-purpose width -- a control, debug or segment register --
/// answers false rather than raising, so that an operand no encoder can use
/// reaches the "unsupported operand" case instead of letting a register
/// exception escape the assembler.
let private isGPRegOf (wordSz: WordSize) width reg =
  RegisterHelper.getKind reg = RegisterHelper.Kind.GP
  && RegisterHelper.toRegType wordSz reg = width

let isReg8 wordSz reg = isGPRegOf wordSz 8<rt> reg

let isReg16 wordSz reg = isGPRegOf wordSz 16<rt> reg

let isReg32 wordSz reg = isGPRegOf wordSz 32<rt> reg

let isReg64 wordSz reg = isGPRegOf wordSz 64<rt> reg

let isMMXReg reg = RegisterHelper.Kind.MMX = RegisterHelper.getKind reg

let isXMMReg reg = RegisterHelper.Kind.XMM = RegisterHelper.getKind reg

let isYMMReg reg = RegisterHelper.Kind.YMM = RegisterHelper.getKind reg

let isSegReg reg = RegisterHelper.Kind.Segment = RegisterHelper.getKind reg

let isFPUReg reg = RegisterHelper.Kind.FPU = RegisterHelper.getKind reg

let private isHalfSplit (wordSz: WordSize) reg =
  match wordSz, RegisterHelper.toRegType wordSz reg with
  | WordSize.Bit64, 32<rt> -> true
  | WordSize.Bit32, 16<rt> -> true
  | _ -> false

let private isAddrSize wordSz = function
  | OneOperand(OprMem(Some bReg, _, _, _))
  | TwoOperands(_, OprMem(Some bReg, _, _, _))
  | TwoOperands(OprMem(Some bReg, _, _, _), _) -> isHalfSplit wordSz bReg
  | _ -> false

(* Matching on Prefix rather than on its numeric value is deliberate: these
   tables used to hardcode the underlying integers, and silently encoded the
   wrong prefix once a new member shifted the enum. *)
/// Group 1 prefixes, i.e. LOCK and the repeat prefixes.
let private group1Prefixes = Prefix.LOCK ||| Prefix.REPNZ ||| Prefix.REPZ

/// Group 2 prefixes, i.e. the segment overrides.
let private group2Prefixes =
  Prefix.CS ||| Prefix.SS ||| Prefix.DS ||| Prefix.ES ||| Prefix.FS
  ||| Prefix.GS

let private grp1PrefixByte = function
  | Prefix.LOCK -> 0xF0uy
  | Prefix.REPNZ -> 0xF2uy
  | Prefix.REPZ -> 0xF3uy
  | p -> raise <| EncodingFailureException $"Invalid group 1 prefix: {p}"

let private segPrefixByte = function
  | Prefix.CS -> 0x2Euy
  | Prefix.SS -> 0x36uy
  | Prefix.DS -> 0x3Euy
  | Prefix.ES -> 0x26uy
  | Prefix.FS -> 0x64uy
  | Prefix.GS -> 0x65uy
  | p -> raise <| EncodingFailureException $"Invalid segment prefix: {p}"

/// The read-modify-write instructions that may carry a LOCK prefix.
let private isLockableOpcode = function
  | Opcode.ADC | Opcode.ADD | Opcode.AND | Opcode.BTC | Opcode.BTR
  | Opcode.BTS | Opcode.CMPXCHG | Opcode.CMPXCHG8B | Opcode.CMPXCHG16B
  | Opcode.DEC | Opcode.INC | Opcode.NEG | Opcode.NOT | Opcode.OR
  | Opcode.SBB | Opcode.SUB | Opcode.XADD | Opcode.XCHG | Opcode.XOR -> true
  | _ -> false

/// LOCK is only meaningful when the destination is in memory. XCHG is the
/// exception, locking whichever of its two operands is the memory one.
let private hasMemoryDestination ins =
  match ins.Operands with
  | OneOperand(OprMem _ | Label _)
  | TwoOperands((OprMem _ | Label _), _) -> true
  | TwoOperands(_, OprMem _) -> ins.Opcode = Opcode.XCHG
  | _ -> false

/// The string instructions, the only ones a repeat prefix applies to. They
/// take no operands here, which is also what tells MOVSD the string move apart
/// from MOVSD the scalar double move.
let private isStringOpcode = function
  | Opcode.CMPS | Opcode.CMPSB | Opcode.CMPSW | Opcode.CMPSD | Opcode.CMPSQ
  | Opcode.INS | Opcode.INSB | Opcode.INSW | Opcode.INSD
  | Opcode.LODS | Opcode.LODSB | Opcode.LODSW | Opcode.LODSD | Opcode.LODSQ
  | Opcode.MOVS | Opcode.MOVSB | Opcode.MOVSW | Opcode.MOVSD | Opcode.MOVSQ
  | Opcode.OUTS | Opcode.OUTSB | Opcode.OUTSW | Opcode.OUTSD
  | Opcode.SCAS | Opcode.SCASB | Opcode.SCASW | Opcode.SCASD | Opcode.SCASQ
  | Opcode.STOS | Opcode.STOSB | Opcode.STOSW | Opcode.STOSD
  | Opcode.STOSQ -> true
  | _ -> false

let private isRepeatable ins =
  match ins.Operands with
  | NoOperand -> isStringOpcode ins.Opcode
  | _ -> false

/// Whether the instruction being encoded accepts the given group 1 prefix.
let private canTakeGrp1 ins = function
  | Prefix.LOCK -> isLockableOpcode ins.Opcode && hasMemoryDestination ins
  | _ -> isRepeatable ins

/// Rejects a group 1 prefix the instruction cannot carry. Encoding happens
/// below, but the check has to sit apart from it: an encoder that emits raw
/// opcode bytes never reaches encodePrefix, and used to drop a bogus prefix
/// without a word rather than refuse it.
let checkGroup1Prefix ins =
  let grp1 = ins.Prefixes &&& group1Prefixes
  if grp1 = Prefix.None || canTakeGrp1 ins grp1 then ()
  else raise <| EncodingFailureException $"{ins.Opcode} cannot take {grp1}"

let encodePrefix ins wordSz mandPrefix =
  let grp1 = ins.Prefixes &&& group1Prefixes
  let grp2 = ins.Prefixes &&& group2Prefixes
  (* Prefix group1 and group2 *)
  let prxGrp1 =
    if grp1 = Prefix.None then [||] else [| grp1PrefixByte grp1 |]
  let prxGrp2 =
    if grp2 = Prefix.None then [||] else [| segPrefixByte grp2 |]
  (* Prefix group3: Operand-size override control with mandatory prefix *)
  let mandPrx =
    match mandPrefix with
    | Prefix.REPZ -> [| 0xF3uy |]
    | Prefix.REPNZ -> [| 0xF2uy |]
    | Prefix.OPSIZE -> [| 0x66uy |]
    | _ -> [||]
  (* Prefix group4: Address-size override *)
  let prxGrp4 =
    if isAddrSize wordSz ins.Operands then [| 0x67uy |] else [||]
  [| yield! prxGrp1; yield! prxGrp2; yield! mandPrx; yield! prxGrp4 |]

let encodeRex = function
  | Register.SPL | Register.BPL | Register.SIL | Register.DIL -> 0x40uy
  | _ -> 0x0uy

let isExtendReg = function
  | Register.R8B | Register.R8W | Register.R8D | Register.R8
  | Register.R9B | Register.R9W | Register.R9D | Register.R9
  | Register.R10B | Register.R10W | Register.R10D | Register.R10
  | Register.R11B | Register.R11W | Register.R11D | Register.R11
  | Register.R12B | Register.R12W | Register.R12D | Register.R12
  | Register.R13B | Register.R13W | Register.R13D | Register.R13
  | Register.R14B | Register.R14W | Register.R14D | Register.R14
  | Register.R15B | Register.R15W | Register.R15D | Register.R15
  | Register.XMM8 | Register.XMM9 | Register.XMM10 | Register.XMM11
  | Register.XMM12 | Register.XMM13 | Register.XMM14 | Register.XMM15 -> true
  | _ -> false

let encodeRexR reg = if isExtendReg reg then 0x44uy else 0x0uy

let encodeRexX reg = if isExtendReg reg then 0x42uy else 0x0uy

let encodeRexB reg = if isExtendReg reg then 0x41uy else 0x0uy

let convVEXRexByte rexByte = (~~~rexByte) &&& 0b111uy

let encodeVEXRexRB wordSz r1 r2 =
  if wordSz = WordSize.Bit32 then 0b101uy
  else convVEXRexByte (encodeRexR r1 ||| encodeRexB r2)

let encodeVEXRexRXB wordSz reg rmOrSBase sIdx =
  if wordSz = WordSize.Bit32 then 0b111uy
  else
    match rmOrSBase, sIdx with
    | Some r1, Some(r2, _) ->
      convVEXRexByte (encodeRexR reg ||| encodeRexX r2 ||| encodeRexB r1)
    | Some r1, None ->
      convVEXRexByte (encodeRexR reg ||| encodeRexB r1)
    | None, Some(r2, _) ->
      convVEXRexByte (encodeRexR reg ||| encodeRexX r2)
    | None, None -> convVEXRexByte (encodeRexR reg)

let encodeRexRR wordSz isMR r1 r2 =
  let hasByteReg =
    (isReg8 wordSz r1 || isReg32 wordSz r1 || isReg64 wordSz r1)
    && isReg8 wordSz r2
  let rex = if hasByteReg then encodeRex r1 ||| encodeRex r2 else 0uy
  if isMR then rex ||| encodeRexR r2 ||| encodeRexB r1
  else rex ||| encodeRexR r1 ||| encodeRexB r2

let encodeRexRM wordSz r b s =
  let rex = if isReg8 wordSz r then encodeRex r else 0uy
  match b, s with
  | Some b, Some(s, _) ->
    rex ||| encodeRexR r ||| encodeRexX s ||| encodeRexB b
  | Some b, None -> rex ||| encodeRexR r ||| encodeRexB b
  | None, Some(s, _) -> rex ||| encodeRexR r ||| encodeRexX s
  | None, None -> rex ||| encodeRexR r

let encodeRexRXB wordSz isMR = function
  | NoOperand
  | OneOperand(Label _) | OneOperand(OprDirAddr _)
  | OneOperand(OprImm _)
  | TwoOperands(OprMem(None, None, Some _, _), OprImm _)
  | TwoOperands(Label _, OprImm _) -> 0uy
  | OneOperand(OprReg r) ->
    if isReg8 wordSz r then encodeRex r ||| encodeRexB r else encodeRexB r
  | OneOperand(OprMem(Some bReg, Some(s, _), _, _)) ->
    encodeRexX s ||| encodeRexB bReg
  | OneOperand(OprMem(Some bReg, None, _, _)) -> encodeRexB bReg
  | OneOperand(OprMem(None, Some(s, _), _, _)) -> encodeRexX s
  | TwoOperands(OprReg r1, OprReg r2) -> encodeRexRR wordSz isMR r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, _, _))
  | TwoOperands(OprMem(b, s, _, _), OprReg r) -> encodeRexRM wordSz r b s
  | TwoOperands(OprReg r, OprImm _) ->
    if isReg8 wordSz r then encodeRex r ||| encodeRexB r else encodeRexB r
  | TwoOperands(OprMem(Some bReg, None, _, _), OprImm _) -> encodeRexB bReg
  | TwoOperands(OprMem(Some bReg, Some(s, _), _, _), OprImm _) ->
    encodeRexX s ||| encodeRexB bReg
  | TwoOperands(OprReg r, Label _) | TwoOperands(Label _, OprReg r) ->
    encodeRexR r
  | ThreeOperands(OprReg r1, OprReg r2, OprImm _) ->
    if isMR then encodeRexR r2 ||| encodeRexB r1
    else encodeRexR r1 ||| encodeRexB r2
  | ThreeOperands(OprReg r, OprMem(Some bReg, Some(s, _), _, _), OprImm _) ->
    encodeRexR r ||| encodeRexX s ||| encodeRexB bReg
  | ThreeOperands(OprReg r, OprMem(Some bReg, None, _, _), OprImm _) ->
    encodeRexR r ||| encodeRexB bReg
  | ThreeOperands(OprReg r, OprMem(None, None, _, _), OprImm _) ->
    encodeRexR r
  | ThreeOperands(OprReg r, Label _, OprImm _) -> encodeRexR r
  | o -> raise <| EncodingFailureException $"Cannot encode REX for {o}"

let encodeREXPref ins (wordSz: WordSize) (rexPrx: EncREXPrefix) =
  if wordSz = WordSize.Bit32 then [||]
  else (* IntelX64 *)
    let rexW = if rexPrx.RexW then 0x48uy else 0uy
    let rxb = encodeRexRXB wordSz rexPrx.IsMemReg ins.Operands
    if rxb = 0uy && rexW = 0uy then [||] else [| rexW ||| rxb |]

let private getLeadingOpcodeByte = function (* m-mmmm *)
  | VEXType.TwoByteOp -> 0b00001uy
  | VEXType.ThreeByteOpOne -> 0b00010uy
  | VEXType.ThreeByteOpTwo -> 0b00011uy
  | _ -> Terminator.impossible ()

let private getVVVVByte = function
  | Some Register.XMM0 | Some Register.YMM0
  | Some Register.EAX | Some Register.RAX -> 0b1111uy
  | Some Register.XMM1 | Some Register.YMM1
  | Some Register.ECX | Some Register.RCX -> 0b1110uy
  | Some Register.XMM2 | Some Register.YMM2
  | Some Register.EDX | Some Register.RDX -> 0b1101uy
  | Some Register.XMM3 | Some Register.YMM3
  | Some Register.EBX | Some Register.RBX -> 0b1100uy
  | Some Register.XMM4 | Some Register.YMM4
  | Some Register.ESP | Some Register.RSP -> 0b1011uy
  | Some Register.XMM5 | Some Register.YMM5
  | Some Register.EBP | Some Register.RBP -> 0b1010uy
  | Some Register.XMM6 | Some Register.YMM6
  | Some Register.ESI | Some Register.RSI -> 0b1001uy
  | Some Register.XMM7 | Some Register.YMM7
  | Some Register.EDI | Some Register.RDI -> 0b1000uy
  | Some Register.XMM8 | Some Register.YMM8 -> 0b0111uy
  | Some Register.XMM9 | Some Register.YMM9 -> 0b0110uy
  | Some Register.XMM10 | Some Register.YMM10 -> 0b0101uy
  | Some Register.XMM11 | Some Register.YMM11 -> 0b0100uy
  | Some Register.XMM12 | Some Register.YMM12 -> 0b0011uy
  | Some Register.XMM13 | Some Register.YMM13 -> 0b0010uy
  | Some Register.XMM14 | Some Register.YMM14 -> 0b0001uy
  | Some Register.XMM15 | Some Register.YMM15 -> 0b0000uy
  | None -> 0b1111uy
  | _ -> Terminator.impossible ()

let private getVLen = function
  | 128<rt> -> 0b0uy
  | 256<rt> -> 0b1uy
  | 32<rt> | 64<rt> -> 0b0uy // Scalar
  | _ -> Terminator.impossible ()

let private getSIMDPref = function
  | Prefix.None -> 0b00uy
  | Prefix.OPSIZE (* 0x66 *) -> 0b01uy
  | Prefix.REPZ (* 0xF3 *) -> 0b10uy
  | Prefix.REPNZ (* 0xF2 *) -> 0b11uy
  | _ -> Terminator.impossible ()

let encodeTwoVEXPref rexR vvvv (vex: EncVEXPrefix) =
  let vvvv = getVVVVByte vvvv
  let vectorLen = getVLen vex.VecLen
  let pp = getSIMDPref vex.PP
  let sndVByte = (rexR <<< 7) + (vvvv <<< 3) + (vectorLen <<< 2) + pp
  [| 0xC5uy; sndVByte |]

let encodeThreeVEXPref rexRXB vvvv (vex: EncVEXPrefix) =
  let mmmmm = getLeadingOpcodeByte vex.LeadingOpcode
  let rexW = if vex.RexW = REXPrefix.REXW then 0b1uy else 0b0uy
  let vvvv = getVVVVByte vvvv
  let vectorLen = getVLen vex.VecLen
  let pp = getSIMDPref vex.PP
  let sndVByte = (rexRXB <<< 5) + mmmmm
  let trdVByte = (rexW <<< 7) + (vvvv <<< 3) + (vectorLen <<< 2) + pp
  [| 0xC4uy; sndVByte; trdVByte |]

let isTwoByteVEX rexRXB (vex: EncVEXPrefix) =
  (rexRXB = 0b111uy || rexRXB = 0b011uy) &&
  vex.LeadingOpcode = VEXType.TwoByteOp &&
  vex.RexW = REXPrefix.NOREX && vex.PP = Prefix.OPSIZE

let encodeVEXPref rexRXB vvvv (vex: EncVEXPrefix) =
  if isTwoByteVEX rexRXB vex
  then encodeTwoVEXPref ((rexRXB >>> 2) &&& 0b1uy) vvvv vex
  else encodeThreeVEXPref rexRXB vvvv vex

// vim: set tw=80 sts=2 sw=2:
