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

module internal B2R2.Assembly.Intel.AsmOpcode

open B2R2
open B2R2.FrontEnd.Intel
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.Intel.ParserHelper
open B2R2.Assembly.Intel.AsmPrefix
open B2R2.Assembly.Intel.AsmOperands

let no32Arch wordSz =
  if wordSz = WordSize.Bit32 then raise InvalidISAException else ()

let no64Arch wordSz =
  if wordSz = WordSize.Bit64 then raise InvalidISAException else ()

let isInt8 i = 0xFFFFFFFFFFFFFF80L <= i && i <= 0x7FL

let isInt16 i = 0xFFFFFFFFFFFF8000L <= i && i <= 0x7FFFL

let isInt32 i = 0xFFFFFFFF80000000L <= i && i <= 0x7FFFFFFFL

let isUInt8 (i: int64) = uint64 i <= 0xFFUL

let isUInt16 (i: int64) = uint64 i <= 0xFFFFUL

let isUInt32 (i: int64) = uint64 i <= 0xFFFFFFFFUL

let isClassicGPReg = function
  | Register.RAX | Register.EAX | Register.AX
  | Register.RCX | Register.ECX | Register.CX
  | Register.RDX | Register.EDX | Register.DX
  | Register.RBX | Register.EBX | Register.BX
  | Register.RSP | Register.ESP | Register.SP
  | Register.RBP | Register.EBP | Register.BP
  | Register.RSI | Register.ESI | Register.SI
  | Register.RDI | Register.EDI | Register.DI -> true
  | _ -> false

let inline prxRexOp ins wordSz pref rex op =
  [| yield! encodePrefix ins wordSz pref
     yield! encodeREXPref ins wordSz rex
     yield! op |]

let inline encLbl ins lbl = PendingBranch(ins.Opcode, lbl)

let inline encImm ins wordSz pref rex op i immSz =
  Resolved [| yield! prxRexOp ins wordSz pref rex op
              yield! immediate i immSz |]

let inline encR ins wordSz pref rex op r c =
  Resolved [| yield! prxRexOp ins wordSz pref rex op
              modrmR r c |]

let inline encClassicR opSizePref opValue diff =
  let opSize = if opSizePref then [| 0x66uy |] else [||]
  Resolved [| yield! opSize; yield opValue + diff |]

let inline encD ins wordSz pref rex op rel sz =
  let prxRexOp = prxRexOp ins wordSz pref rex op
  Resolved [| yield! prxRexOp
              yield! modrmRel (Array.length prxRexOp) rel sz |]

let inline encM ins wordSz pref rex op b s d c =
  Resolved [| yield! prxRexOp ins wordSz pref rex op
              modrmM b s d c
              yield! mem b s d |]

let inline encRR ins wordSz pref rex op r1 r2 =
  Resolved [| yield! prxRexOp ins wordSz pref rex op
              modrmRR r1 r2 |]

let getCtxtByOprSz (wordSz: WordSize) op8Byte opByte = function
  | 8<rt> -> prefNormal, rexNormal, op8Byte
  | 16<rt> -> pref66, rexNormal, opByte
  | 32<rt> -> prefNormal, rexNormal, opByte
  | 64<rt> -> prefNormal, rexW, opByte
  | _ -> Terminator.impossible ()

(* The three encoders below take the label they refer to rather than digging it
   back out of the operands later, so that adding a new label-bearing operand
   shape needs no matching change where the fixup is applied. *)
let inline encRL (wordSz: WordSize) ins r lbl op8Byte opByte =
  let pref, rex, opByte =
    getCtxtByOprSz wordSz op8Byte opByte (RegisterHelper.toRegType wordSz r)
  let head =
    [| yield! prxRexOp ins wordSz pref rex opByte
       modrmRL r |]
  PendingFixup { Head = head
                 Width = 32<rt>
                 Tail = [||]
                 Label = lbl
                 IsBranch = false }

let inline encLI (wordSz: WordSize) ins lbl regConstr i immSz op8Byte opByte =
  let pref, rex, opByte = getCtxtByOprSz wordSz op8Byte opByte 32<rt>
  let head =
    [| yield! prxRexOp ins wordSz pref rex opByte
       modrmLI regConstr |]
  PendingFixup { Head = head
                 Width = 32<rt>
                 Tail = immediate i immSz
                 Label = lbl
                 IsBranch = false }

let inline encRLI (wordSz: WordSize) ins r lbl op i immSz =
  let pref, rex, opByte =
    getCtxtByOprSz wordSz [||] op (RegisterHelper.toRegType wordSz r)
  let head =
    [| yield! prxRexOp ins wordSz pref rex opByte
       modrmRL r |]
  PendingFixup { Head = head
                 Width = 32<rt>
                 Tail = immediate i immSz
                 Label = lbl
                 IsBranch = false }

let inline encFR (op: byte[]) r =
  Resolved [| op[0]; op[1] + (regTo3Bit r) |]

let inline encO ins wordSz pref rex op r =
  let op = [| op + (regTo3Bit r) |]
  Resolved(prxRexOp ins wordSz pref rex op)

let inline encRI ins wordSz pref rex op r c i immSz =
  Resolved [| yield! prxRexOp ins wordSz pref rex op
              modrmRI r c
              yield! immediate i immSz |]

let inline encOI ins wordSz pref rex op r i immSz =
  let op = [| op + (regTo3Bit r) |]
  Resolved [| yield! prxRexOp ins wordSz pref rex op
              yield! immediate i immSz |]

let inline encRM ins wordSz pref rex op r b s d =
  Resolved [| yield! prxRexOp ins wordSz pref rex op
              modrmRM r b s d
              yield! mem b s d |]

let inline encMR ins wordSz pref rex op b s d r =
  Resolved [| yield! prxRexOp ins wordSz pref rex op
              modrmMR b s d r
              yield! mem b s d |]

let inline encMI ins wordSz pref rex op b s d c i immSz =
  Resolved [| yield! prxRexOp ins wordSz pref rex op
              modrmMI b s d c
              yield! mem b s d
              yield! immediate i immSz |]

let inline encRC ins wordSz pref rex op r c =
  Resolved [| yield! prxRexOp ins wordSz pref rex op
              modrmRC r c |]

let inline encMC ins wordSz pref rex op b s d c =
  Resolved [| yield! prxRexOp ins wordSz pref rex op
              modrmMC b s d c |]

let inline encNP ins wordSz pref rex op =
  Resolved(prxRexOp ins wordSz pref rex op)

let inline encRRI ins wordSz pref rex op r1 r2 i immSz =
  Resolved [| yield! prxRexOp ins wordSz pref rex op
              modrmRR r1 r2
              yield! immediate i immSz |]

let inline encRMI ins wordSz pref rex op r b s d i immSz =
  Resolved [| yield! prxRexOp ins wordSz pref rex op
              modrmRM r b s d
              yield! mem b s d
              yield! immediate i immSz |]

let inline encMRI ins wordSz pref rex op b s d r i immSz =
  Resolved [| yield! prxRexOp ins wordSz pref rex op
              modrmMR b s d r
              yield! mem b s d
              yield! immediate i immSz |]

let inline encVexRRR wordSz vvvv vex op r1 r3 =
  let rexRXB = encodeVEXRexRB wordSz r1 r3
  Resolved [| yield! encodeVEXPref rexRXB vvvv vex
              yield! op
              modrmRR r1 r3 |]

let inline encVexRRM wordSz vvvv vex op r b s d =
  let rexRXB = encodeVEXRexRXB wordSz r b s
  Resolved [| yield! encodeVEXPref rexRXB vvvv vex
              yield! op
              modrmRM r b s d
              yield! mem b s d |]

let inline encVexRRRI wordSz vvvv vex op r1 r3 i immSz =
  let rexRXB = encodeVEXRexRB wordSz r1 r3
  Resolved [| yield! encodeVEXPref rexRXB vvvv vex
              yield! op
              modrmRR r1 r3
              yield! immediate i immSz |]

let inline encVexRRMI wordSz vvvv vex op r b s d i immSz =
  let rexRXB = encodeVEXRexRXB wordSz r b s
  Resolved [| yield! encodeVEXPref rexRXB vvvv vex
              yield! op
              modrmRM r b s d
              yield! mem b s d
              yield! immediate i immSz |]

(* Special case: fills in an omitted memory operand size from the register
   operand. The operand order must be preserved, since it is what decides
   whether the instruction loads or stores. *)
let private resolveMemSizeFromReg ins (wordSz: WordSize) =
  let operands =
    match ins.Operands with
    | TwoOperands(OprMem(b, s, d, 0<rt>), OprReg r) ->
      let mOSz = RegisterHelper.toRegType wordSz r
      TwoOperands(OprMem(b, s, d, mOSz), OprReg r)
    | TwoOperands(OprReg r, OprMem(b, s, d, 0<rt>)) ->
      let mOSz = RegisterHelper.toRegType wordSz r
      TwoOperands(OprReg r, OprMem(b, s, d, mOSz))
    | _ ->
      ins.Operands
  { ins with Operands = operands }

let aaa (wordSz: WordSize) = function
  | NoOperand -> no64Arch wordSz; Resolved [| 0x37uy |]
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let aad (wordSz: WordSize) = function
  | NoOperand ->
    no64Arch wordSz; Resolved [| 0xD5uy; 0x0Auy |]
  | OneOperand(OprImm(imm, _)) ->
    no64Arch wordSz; Resolved [| 0xD5uy; yield! immediate imm 8<rt> |]
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let aam (wordSz: WordSize) = function
  | NoOperand ->
    no64Arch wordSz; Resolved [| 0xD4uy; 0x0Auy |]
  | OneOperand(OprImm(imm, _)) ->
    no64Arch wordSz; Resolved [| 0xD4uy; yield! immediate imm 8<rt> |]
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let aas (wordSz: WordSize) = function
  | NoOperand -> no64Arch wordSz; Resolved [| 0x3Fuy |]
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

/// Encodes one of the classic ALU instructions: ADD, OR, ADC, SBB, AND, SUB,
/// XOR and CMP. The eight share a single encoding layout, and differ only in
/// where their block of six consecutive opcodes starts and in the ModRM.reg
/// digit that selects the operation for the immediate forms.
let arithmetic (wordSz: WordSize) ins baseOp regConstr =
  let opMR8 = [| baseOp |] (* r/m8, r8 *)
  let opMR = [| baseOp + 1uy |] (* r/m, r *)
  let opRM8 = [| baseOp + 2uy |] (* r8, r/m8 *)
  let opRM = [| baseOp + 3uy |] (* r, r/m *)
  let opAcc8 = [| baseOp + 4uy |] (* AL, imm8 *)
  let opAcc = [| baseOp + 5uy |] (* eAX, imm *)
  let opSExt = [| 0x83uy |] (* r/m, imm8 sign-extended *)
  let opImm8 = [| 0x80uy |] (* r/m8, imm8 *)
  let opImm = [| 0x81uy |] (* r/m, imm *)
  match ins.Operands with
  (* Reg (fixed) - Imm (Priority 1) *)
  | TwoOperands(OprReg Register.AL, OprImm(imm, _)) ->
    encImm ins wordSz prefNormal rexNormal opAcc8 imm 8<rt>
  | TwoOperands(OprReg Register.AX, OprImm(imm, _)) ->
    encImm ins wordSz pref66 rexNormal opAcc imm 16<rt>
  | TwoOperands(OprReg Register.EAX, OprImm(imm, _)) ->
    encImm ins wordSz prefNormal rexNormal opAcc imm 32<rt>
  | TwoOperands(OprReg Register.RAX, OprImm(imm, _)) ->
    no32Arch wordSz
    encImm ins wordSz prefNormal rexW opAcc imm 32<rt>
  (* Reg - Imm (Priority 0) *)
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg16 wordSz r && isInt8 imm ->
    encRI ins wordSz pref66 rexNormal opSExt r regConstr imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg32 wordSz r && isInt8 imm ->
    encRI ins wordSz prefNormal rexNormal opSExt r regConstr imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg64 wordSz r && isInt8 imm ->
    no32Arch wordSz
    encRI ins wordSz prefNormal rexW opSExt r regConstr imm 8<rt>
  (* Mem - Imm (Priority 0) *)
  | TwoOperands(Label(lbl, _), OprImm(imm, _)) when isInt8 imm ->
    encLI wordSz ins lbl regConstr imm 8<rt> [||] opSExt
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprImm(imm, _)) when isInt8 imm ->
    encMI ins wordSz pref66 rexNormal opSExt b s d regConstr imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprImm(imm, _)) when isInt8 imm ->
    encMI ins wordSz prefNormal rexNormal opSExt b s d regConstr imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprImm(imm, _)) when isInt8 imm ->
    no32Arch wordSz
    encMI ins wordSz prefNormal rexW opSExt b s d regConstr imm 8<rt>
  (* Reg - Imm (Priority 1) *)
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg8 wordSz r ->
    encRI ins wordSz prefNormal rexNormal opImm8 r regConstr imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg16 wordSz r ->
    encRI ins wordSz pref66 rexNormal opImm r regConstr imm 16<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg32 wordSz r ->
    encRI ins wordSz prefNormal rexNormal opImm r regConstr imm 32<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg64 wordSz r ->
    no32Arch wordSz
    encRI ins wordSz prefNormal rexW opImm r regConstr imm 32<rt>
  (* Mem - Imm (Priority 1) *)
  | TwoOperands(Label(lbl, _), OprImm(imm, _)) ->
    encLI wordSz ins lbl regConstr imm 32<rt> opImm8 opImm
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprImm(imm, _)) ->
    encMI ins wordSz prefNormal rexNormal opImm8 b s d regConstr imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprImm(imm, _)) ->
    encMI ins wordSz pref66 rexNormal opImm b s d regConstr imm 16<rt>
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprImm(imm, _)) ->
    encMI ins wordSz prefNormal rexNormal opImm b s d regConstr imm 32<rt>
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprImm(imm, _)) ->
    no32Arch wordSz
    encMI ins wordSz prefNormal rexW opImm b s d regConstr imm 32<rt>
  (* Mem - Reg *)
  | TwoOperands(Label(lbl, _), OprReg r) ->
    encRL wordSz ins r lbl opMR8 opMR
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprReg r) when isReg8 wordSz r ->
    encMR ins wordSz prefNormal rexNormal opMR8 b s d r
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprReg r) when isReg16 wordSz r ->
    encMR ins wordSz pref66 rexNormal opMR b s d r
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprReg r) when isReg32 wordSz r ->
    encMR ins wordSz prefNormal rexNormal opMR b s d r
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprReg r) when isReg64 wordSz r ->
    no32Arch wordSz
    encMR ins wordSz prefNormal rexW opMR b s d r
  (* Reg - Reg *)
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg8 wordSz r1 && isReg8 wordSz r2 ->
    encRR ins wordSz prefNormal rexNormal opRM8 r1 r2
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg16 wordSz r1 && isReg16 wordSz r2 ->
    encRR ins wordSz pref66 rexNormal opRM r1 r2
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg32 wordSz r1 && isReg32 wordSz r2 ->
    encRR ins wordSz prefNormal rexNormal opRM r1 r2
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg64 wordSz r1 && isReg64 wordSz r2 ->
    no32Arch wordSz
    encRR ins wordSz prefNormal rexW opRM r1 r2
  (* Reg - Mem *)
  | TwoOperands(OprReg r, Label(lbl, _)) ->
    encRL wordSz ins r lbl opRM8 opRM
  | TwoOperands(OprReg r, OprMem(b, s, d, 8<rt>)) when isReg8 wordSz r ->
    encRM ins wordSz prefNormal rexNormal opRM8 r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg16 wordSz r ->
    encRM ins wordSz pref66 rexNormal opRM r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg32 wordSz r ->
    encRM ins wordSz prefNormal rexNormal opRM r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isReg64 wordSz r ->
    no32Arch wordSz
    encRM ins wordSz prefNormal rexW opRM r b s d
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let adc wordSz ins = arithmetic wordSz ins 0x10uy 0b010uy

let add wordSz ins = arithmetic wordSz ins 0x00uy 0b000uy

/// Encodes an SSE instruction taking an XMM destination and an XMM or memory
/// source, the shape shared by most of the packed and scalar arithmetic. Only
/// the mandatory prefix, the opcode and the memory operand size differ.
let sseRegRM (wordSz: WordSize) ins pref op memSz =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins wordSz pref rexNormal op r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, sz)) when isXMMReg r && sz = memSz ->
    encRM ins wordSz pref rexNormal op r b s d
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let addpd wordSz ins = sseRegRM wordSz ins pref66 [| 0x0Fuy; 0x58uy |] 128<rt>

let addps wordSz ins =
  sseRegRM wordSz ins prefNormal [| 0x0Fuy; 0x58uy |] 128<rt>

let addsd wordSz ins = sseRegRM wordSz ins prefF2 [| 0x0Fuy; 0x58uy |] 64<rt>

let addss wordSz ins = sseRegRM wordSz ins prefF3 [| 0x0Fuy; 0x58uy |] 32<rt>

let logAnd wordSz ins = arithmetic wordSz ins 0x20uy 0b100uy

let andpd wordSz ins = sseRegRM wordSz ins pref66 [| 0x0Fuy; 0x54uy |] 128<rt>

let andps wordSz ins =
  sseRegRM wordSz ins prefNormal [| 0x0Fuy; 0x54uy |] 128<rt>

let bsr (wordSz: WordSize) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg16 wordSz r1 && isReg16 wordSz r2 ->
    encRR ins wordSz pref66 rexNormal [| 0x0Fuy; 0xBDuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg16 wordSz r ->
    encRM ins wordSz pref66 rexNormal [| 0x0Fuy; 0xBDuy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg32 wordSz r1 && isReg32 wordSz r2 ->
    encRR ins wordSz prefNormal rexNormal [| 0x0Fuy; 0xBDuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg32 wordSz r ->
    encRM ins wordSz prefNormal rexNormal [| 0x0Fuy; 0xBDuy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg64 wordSz r1 && isReg64 wordSz r2 ->
    no32Arch wordSz
    encRR ins wordSz prefNormal rexW [| 0x0Fuy; 0xBDuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isReg64 wordSz r ->
    no32Arch wordSz
    encRM ins wordSz prefNormal rexW [| 0x0Fuy; 0xBDuy |] r b s d
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let bt (wordSz: WordSize) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg16 wordSz r1 && isReg16 wordSz r2 ->
    encRR ins wordSz pref66 rexMR [| 0x0Fuy; 0xA3uy |] r2 r1
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg32 wordSz r1 && isReg32 wordSz r2 ->
    encRR ins wordSz prefNormal rexMR [| 0x0Fuy; 0xA3uy |] r2 r1
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg64 wordSz r1 && isReg64 wordSz r2 ->
    no32Arch wordSz
    encRR ins wordSz prefNormal rexWAndMR [| 0x0Fuy; 0xA3uy |] r2 r1
  | TwoOperands(Label(lbl, _), OprReg r) ->
    encRL wordSz ins r lbl [||] [| 0x0Fuy; 0xA3uy |]
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprReg r) when isReg16 wordSz r ->
    encMR ins wordSz pref66 rexMR [| 0x0Fuy; 0xA3uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprReg r) when isReg32 wordSz r ->
    encMR ins wordSz prefNormal rexMR [| 0x0Fuy; 0xA3uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprReg r) when isReg64 wordSz r ->
    no32Arch wordSz
    encMR ins wordSz prefNormal rexWAndMR [| 0x0Fuy; 0xA3uy |] b s d r
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg16 wordSz r ->
    encRI ins wordSz pref66 rexNormal [| 0x0Fuy; 0xBAuy |] r 0b100uy imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg32 wordSz r ->
    encRI ins wordSz prefNormal rexNormal
      [| 0x0Fuy; 0xBAuy |] r 0b100uy imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg64 wordSz r ->
    no32Arch wordSz
    encRI ins wordSz prefNormal rexW [| 0x0Fuy; 0xBAuy |] r 0b100uy imm 8<rt>
  | TwoOperands(Label(lbl, _), OprImm(imm, _)) ->
    encLI wordSz ins lbl 0b100uy imm 32<rt> [||] [| 0x0Fuy; 0xBAuy |]
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprImm(imm, _)) ->
    encMI ins wordSz pref66 rexNormal
      [| 0x0Fuy; 0xBAuy |] b s d 0b100uy imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprImm(i, _)) ->
    encMI ins wordSz
      prefNormal rexNormal [| 0x0Fuy; 0xBAuy |] b s d 0b100uy i 8<rt>
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprImm(imm, _)) ->
    no32Arch wordSz
    encMI ins wordSz prefNormal rexW
      [| 0x0Fuy; 0xBAuy |] b s d 0b100uy imm 8<rt>
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// Describes how a branch with a relative target is encoded: its short (rel8)
/// form, its near form, and the longest encoding it can produce. An empty form
/// means the instruction has no encoding of that width.
type internal RelBranch =
  { ShortForm: byte[]
    NearForm: byte[]
    MaxLength: int }

let private condJump short near =
  { ShortForm = [| short |]; NearForm = [| 0x0Fuy; near |]; MaxLength = 6 }

let private uncondJump short near =
  { ShortForm = [| short |]; NearForm = [| near |]; MaxLength = 5 }

let private nearOnly near =
  { ShortForm = [||]; NearForm = [| near |]; MaxLength = 5 }

/// For a branch this assembler cannot encode yet, but whose length the first
/// pass still has to bound.
let private lengthOnly len =
  { ShortForm = [||]; NearForm = [||]; MaxLength = len }

/// The one table of relative branch encodings. Both the direct encoders below
/// and the label fixup in AsmMain read it, so the two cannot disagree about an
/// opcode. Aliases such as JNE and JE share an enum value with JNZ and JZ and
/// so need no case of their own.
let relBranch = function
  | Opcode.JA -> condJump 0x77uy 0x87uy
  | Opcode.JB -> condJump 0x72uy 0x82uy
  | Opcode.JBE -> condJump 0x76uy 0x86uy
  | Opcode.JG -> condJump 0x7Fuy 0x8Fuy
  | Opcode.JL -> condJump 0x7Cuy 0x8Cuy
  | Opcode.JLE -> condJump 0x7Euy 0x8Euy
  | Opcode.JNB -> condJump 0x73uy 0x83uy
  | Opcode.JNL -> condJump 0x7Duy 0x8Duy
  | Opcode.JNO -> condJump 0x71uy 0x81uy
  | Opcode.JNP -> condJump 0x7Buy 0x8Buy
  | Opcode.JNS -> condJump 0x79uy 0x89uy
  | Opcode.JNZ -> condJump 0x75uy 0x85uy
  | Opcode.JO -> condJump 0x70uy 0x80uy
  | Opcode.JP -> condJump 0x7Auy 0x8Auy
  | Opcode.JS -> condJump 0x78uy 0x88uy
  | Opcode.JZ -> condJump 0x74uy 0x84uy
  | Opcode.JMP -> uncondJump 0xEBuy 0xE9uy
  | Opcode.CALL -> nearOnly 0xE8uy
  | Opcode.LOOP | Opcode.LOOPE | Opcode.LOOPNE -> lengthOnly 2
  | Opcode.XBEGIN -> lengthOnly 6
  | op -> raise <| EncodingFailureException $"{op} is not a relative branch"

/// Encodes a far CALL or JMP, whose operand is a selector and an offset held
/// in memory. The three widths are 16:16, 16:32 and 16:64, told apart by the
/// operand size just as a near branch tells its widths apart.
let farBranch (wordSz: WordSize) ins digit =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins wordSz pref66 rexNormal [| 0xFFuy |] b s d digit
  | OneOperand(OprMem(b, s, d, 48<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xFFuy |] b s d digit
  | OneOperand(OprMem(b, s, d, 80<rt>)) ->
    no32Arch wordSz
    encM ins wordSz prefNormal rexW [| 0xFFuy |] b s d digit
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let nearCall (wordSz: WordSize) ins =
  let branch = relBranch Opcode.CALL
  match ins.Operands with
  | OneOperand(OprDirAddr(Relative rel))
    when isInt16 rel && wordSz = WordSize.Bit32 ->
    encD ins wordSz pref66 rexNormal branch.NearForm rel 16<rt>
  | OneOperand(OprDirAddr(Relative rel)) when isInt32 rel ->
    encD ins wordSz prefNormal rexNormal branch.NearForm rel 32<rt>
  | OneOperand(Label(lbl, _)) ->
    encLbl ins lbl
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    no64Arch wordSz
    encM ins wordSz pref66 rexNormal [| 0xFFuy |] b s d 0b010uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    no64Arch wordSz
    encM ins wordSz prefNormal rexNormal [| 0xFFuy |] b s d 0b010uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    no32Arch wordSz
    encM ins wordSz prefNormal rexNormal [| 0xFFuy |] b s d 0b010uy
  | OneOperand(OprReg r) when isReg16 wordSz r ->
    no64Arch wordSz
    encR ins wordSz pref66 rexNormal [| 0xFFuy |] r 0b010uy
  | OneOperand(OprReg r) when isReg32 wordSz r ->
    no64Arch wordSz
    encR ins wordSz prefNormal rexNormal [| 0xFFuy |] r 0b010uy
  | OneOperand(OprReg r) when isReg64 wordSz r ->
    no32Arch wordSz
    encR ins wordSz prefNormal rexNormal [| 0xFFuy |] r 0b010uy
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// Builds an encoder for a far branch to an absolute target, whose operand is a
/// selector and an offset written straight into the instruction.
let private farAbsolute op wordSz ins =
  match ins.Operands with
  | OneOperand(OprDirAddr(Absolute(sel, addr, _))) ->
    Resolved [| yield! prxRexOp ins wordSz prefNormal rexNormal [| op |]
                yield! immediate (int64 addr) 32<rt>
                yield! immediate (int64 sel) 16<rt> |]
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let call wordSz ins =
  match ins.Operands with
  | OneOperand(OprDirAddr(Absolute _)) -> farAbsolute 0x9Auy wordSz ins
  | _ when ins.IsFar -> farBranch wordSz ins 0b011uy
  | _ -> nearCall wordSz ins

let cbw _wordSize = function
  | NoOperand -> Resolved [| 0x66uy; 0x98uy |]
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let cdq _wordSize = function
  | NoOperand -> Resolved [| 0x99uy |]
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let cdqe (wordSz: WordSize) = function
  | NoOperand -> no32Arch wordSz; Resolved [| 0x48uy; 0x98uy |]
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let cmovcc (wordSz: WordSize) ins opcode =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg16 wordSz r1 && isReg16 wordSz r2 ->
    encRR ins wordSz pref66 rexNormal opcode r1 r2
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg32 wordSz r1 && isReg32 wordSz r2 ->
    encRR ins wordSz prefNormal rexNormal opcode r1 r2
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg64 wordSz r1 && isReg64 wordSz r2 ->
    no32Arch wordSz
    encRR ins wordSz prefNormal rexW opcode r1 r2
  | TwoOperands(Label(lbl, _), OprReg r) ->
    encRL wordSz ins r lbl [||] opcode
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg16 wordSz r ->
    encMR ins wordSz pref66 rexNormal opcode b s d r
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg32 wordSz r ->
    encMR ins wordSz prefNormal rexNormal opcode b s d r
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isReg64 wordSz r ->
    no32Arch wordSz
    encMR ins wordSz prefNormal rexW opcode b s d r
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let cmova wordSz ins = cmovcc wordSz ins [| 0x0Fuy; 0x47uy |]

let cmovae wordSz ins = cmovcc wordSz ins [| 0x0Fuy; 0x43uy |]

let cmovb wordSz ins = cmovcc wordSz ins [| 0x0Fuy; 0x42uy |]

let cmovbe wordSz ins = cmovcc wordSz ins [| 0x0Fuy; 0x46uy |]

let cmovg wordSz ins = cmovcc wordSz ins [| 0x0Fuy; 0x4Fuy |]

let cmovge wordSz ins = cmovcc wordSz ins [| 0x0Fuy; 0x4Duy |]

let cmovl wordSz ins = cmovcc wordSz ins [| 0x0Fuy; 0x4Cuy |]

let cmovle wordSz ins = cmovcc wordSz ins [| 0x0Fuy; 0x4Euy |]

let cmovno wordSz ins = cmovcc wordSz ins [| 0x0Fuy; 0x41uy |]

let cmovnp wordSz ins = cmovcc wordSz ins [| 0x0Fuy; 0x4Buy |]

let cmovns wordSz ins = cmovcc wordSz ins [| 0x0Fuy; 0x49uy |]

let cmovnz wordSz ins = cmovcc wordSz ins [| 0x0Fuy; 0x45uy |]

let cmovo wordSz ins = cmovcc wordSz ins [| 0x0Fuy; 0x40uy |]

let cmovp wordSz ins = cmovcc wordSz ins [| 0x0Fuy; 0x4Auy |]

let cmovs wordSz ins = cmovcc wordSz ins [| 0x0Fuy; 0x48uy |]

let cmovz wordSz ins = cmovcc wordSz ins [| 0x0Fuy; 0x44uy |]

let cmp wordSz ins = arithmetic wordSz ins 0x38uy 0b111uy

/// Encodes a string instruction. These take no operands, and carry their
/// operand size in the opcode and in the mandatory prefix.
let stringOp (wordSz: WordSize) ins pref rex op =
  match ins.Operands with
  | NoOperand -> encNP ins wordSz pref rex [| op |]
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let cmpsb wordSz ins = stringOp wordSz ins prefNormal rexNormal 0xA6uy

let cmpxchg (wordSz: WordSize) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg8 wordSz r1 && isReg8 wordSz r2 ->
    encRR ins wordSz prefNormal rexMR [| 0x0Fuy; 0xB0uy |] r2 r1
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg16 wordSz r1 && isReg16 wordSz r2 ->
    encRR ins wordSz pref66 rexMR [| 0x0Fuy; 0xB1uy |] r2 r1
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg32 wordSz r1 && isReg32 wordSz r2 ->
    encRR ins wordSz prefNormal rexMR [| 0x0Fuy; 0xB1uy |] r2 r1
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg64 wordSz r1 && isReg64 wordSz r2 ->
    no32Arch wordSz
    encRR ins wordSz prefNormal rexWAndMR [| 0x0Fuy; 0xB1uy |] r2 r1
  | TwoOperands(Label(lbl, _), OprReg r) ->
    encRL wordSz ins r lbl [| 0x0Fuy; 0xB0uy |] [| 0x0Fuy; 0xB1uy |]
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprReg r) when isReg8 wordSz r ->
    encMR ins wordSz prefNormal rexNormal [| 0x0Fuy; 0xB0uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprReg r) when isReg16 wordSz r ->
    encMR ins wordSz pref66 rexNormal [| 0x0Fuy; 0xB1uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprReg r) when isReg32 wordSz r ->
    encMR ins wordSz prefNormal rexNormal [| 0x0Fuy; 0xB1uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprReg r) when isReg64 wordSz r ->
    no32Arch wordSz
    encMR ins wordSz prefNormal rexW [| 0x0Fuy; 0xB1uy |] b s d r
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let cmpxchg8b (wordSz: WordSize) ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0x0Fuy; 0xC7uy |] b s d 0b001uy
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let cmpxchg16b (wordSz: WordSize) ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 128<rt>)) ->
    no32Arch wordSz
    encM ins wordSz prefNormal rexW [| 0x0Fuy; 0xC7uy |] b s d 0b001uy
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let cvtsd2ss wordSz ins = sseRegRM wordSz ins prefF2 [| 0x0Fuy; 0x5Auy |] 64<rt>

let cvtsi2sd (wordSz: WordSize) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isReg32 wordSz r2 ->
    encRR ins wordSz prefF2 rexNormal [| 0x0Fuy; 0x2Auy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isXMMReg r ->
    encRM ins wordSz prefF2 rexNormal [| 0x0Fuy; 0x2Auy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isReg64 wordSz r2 ->
    encRR ins wordSz prefF2 rexW [| 0x0Fuy; 0x2Auy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isXMMReg r ->
    encRM ins wordSz prefF2 rexW [| 0x0Fuy; 0x2Auy |] r b s d
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let cvtsi2ss (wordSz: WordSize) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isReg32 wordSz r2 ->
    encRR ins wordSz prefF3 rexNormal [| 0x0Fuy; 0x2Auy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isXMMReg r ->
    encRM ins wordSz prefF3 rexNormal [| 0x0Fuy; 0x2Auy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isReg64 wordSz r2 ->
    encRR ins wordSz prefF3 rexW [| 0x0Fuy; 0x2Auy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isXMMReg r ->
    encRM ins wordSz prefF3 rexW [| 0x0Fuy; 0x2Auy |] r b s d
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let cvtss2si (wordSz: WordSize) ins =
   match ins.Operands with
   | TwoOperands(OprReg r1, OprReg r2) when isReg32 wordSz r1 && isXMMReg r2 ->
     encRR ins wordSz prefF3 rexNormal [| 0x0Fuy; 0x2Duy |] r1 r2
   | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg32 wordSz r ->
     encRM ins wordSz prefF3 rexNormal [| 0x0Fuy; 0x2Duy |] r b s d
   | TwoOperands(OprReg r1, OprReg r2) when isReg64 wordSz r1 && isXMMReg r2 ->
     encRR ins wordSz prefF3 rexW [| 0x0Fuy; 0x2Duy |] r1 r2
   | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg64 wordSz r ->
     encRM ins wordSz prefF3 rexW [| 0x0Fuy; 0x2Duy |] r b s d
   | _ ->
     raise <| EncodingFailureException "Unsupported operand type"

let cvttss2si (wordSz: WordSize) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isReg32 wordSz r1 && isXMMReg r2 ->
    encRR ins wordSz prefF3 rexNormal [| 0x0Fuy; 0x2Cuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg32 wordSz r ->
    encRM ins wordSz prefF3 rexNormal [| 0x0Fuy; 0x2Cuy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2) when isReg64 wordSz r1 && isXMMReg r2 ->
    encRR ins wordSz prefF3 rexW [| 0x0Fuy; 0x2Cuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg64 wordSz r ->
    encRM ins wordSz prefF3 rexW [| 0x0Fuy; 0x2Cuy |] r b s d
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let cwde _wordSize = function
  | NoOperand -> Resolved [| 0x98uy |]
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let dec (wordSz: WordSize) ins =
  match ins.Operands with
  | OneOperand(OprReg r) when isReg8 wordSz r ->
    encR ins wordSz prefNormal rexNormal [| 0xFEuy |] r 1uy
  | OneOperand(OprMem(b, s, d, 8<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xFEuy |] b s d 1uy
  | OneOperand(OprReg r) when isReg16 wordSz r ->
    if isClassicGPReg r && wordSz = WordSize.Bit32 then
      encClassicR true 0x48uy (regTo3Bit r)
    else
      encR ins wordSz pref66 rexNormal [| 0xFFuy |] r 1uy
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins wordSz pref66 rexNormal [| 0xFFuy |] b s d 1uy
  | OneOperand(OprReg r) when isReg32 wordSz r ->
    if isClassicGPReg r && wordSz = WordSize.Bit32 then
      encClassicR false 0x48uy (regTo3Bit r)
    else
      encR ins wordSz prefNormal rexNormal [| 0xFFuy |] r 1uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xFFuy |] b s d 1uy
  | OneOperand(OprReg r) when isReg64 wordSz r ->
    no32Arch wordSz
    encR ins wordSz prefNormal rexW [| 0xFFuy |] r 1uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    no32Arch wordSz
    encM ins wordSz prefNormal rexW [| 0xFFuy |] b s d 1uy
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// Encodes one of the unary group 3 instructions in its single-operand form:
/// NOT, NEG, MUL, DIV and IDIV. They share one encoding layout and differ only
/// in the ModRM.reg digit. IMUL, which is group 3 digit 5, has extra two- and
/// three-operand forms and so is encoded separately.
let unaryGrp3 (wordSz: WordSize) ins regConstr =
  let op8 = [| 0xF6uy |]
  let op = [| 0xF7uy |]
  match ins.Operands with
  | OneOperand(OprReg r) when isReg8 wordSz r ->
    encR ins wordSz prefNormal rexNormal op8 r regConstr
  | OneOperand(OprMem(b, s, d, 8<rt>)) ->
    encM ins wordSz prefNormal rexNormal op8 b s d regConstr
  | OneOperand(OprReg r) when isReg16 wordSz r ->
    encR ins wordSz pref66 rexNormal op r regConstr
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins wordSz pref66 rexNormal op b s d regConstr
  | OneOperand(OprReg r) when isReg32 wordSz r ->
    encR ins wordSz prefNormal rexNormal op r regConstr
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins wordSz prefNormal rexNormal op b s d regConstr
  | OneOperand(OprReg r) when isReg64 wordSz r ->
    no32Arch wordSz
    encR ins wordSz prefNormal rexW op r regConstr
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    no32Arch wordSz
    encM ins wordSz prefNormal rexW op b s d regConstr
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let div wordSz ins = unaryGrp3 wordSz ins 0b110uy

let divsd wordSz ins = sseRegRM wordSz ins prefF2 [| 0x0Fuy; 0x5Euy |] 64<rt>

let divss wordSz ins = sseRegRM wordSz ins prefF3 [| 0x0Fuy; 0x5Euy |] 32<rt>

/// Encodes an x87 arithmetic instruction that operates on a memory operand or
/// on ST(0) and another stack register. The ModRM.reg digit selects the
/// operation for the memory forms, while the register forms use their own
/// opcode base. Note that the two register bases are passed separately rather
/// than derived: for the subtract and divide pairs the DC form takes what
/// looks like the reversed operation's slot, which is how x87 encodes them.
let x87Arith (wordSz: WordSize) ins regConstr toSt0 fromSt0 =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xD8uy |] b s d regConstr
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xDCuy |] b s d regConstr
  | TwoOperands(OprReg Register.ST0, OprReg r) when isFPUReg r ->
    encFR [| 0xD8uy; toSt0 |] r
  | TwoOperands(OprReg r, OprReg Register.ST0) when isFPUReg r ->
    encFR [| 0xDCuy; fromSt0 |] r
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let fadd wordSz ins = x87Arith wordSz ins 0b000uy 0xC0uy 0xC0uy

let fcmovb _wordSize ins =
  match ins.Operands with
  | TwoOperands(OprReg Register.ST0, OprReg r) when isFPUReg r ->
    encFR [| 0xDAuy; 0xC0uy |] r
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let fdiv wordSz ins = x87Arith wordSz ins 0b110uy 0xF0uy 0xF8uy

let fdivp _wordSize = function
  | NoOperand ->
    Resolved [| 0xDEuy; 0xF9uy |]
  | TwoOperands(OprReg r, OprReg Register.ST0) when isFPUReg r ->
    encFR [| 0xDEuy; 0xF8uy |] r
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let fdivrp _wordSize = function
  | NoOperand ->
    Resolved [| 0xDEuy; 0xF1uy |]
  | TwoOperands(OprReg r, OprReg Register.ST0) when isFPUReg r ->
    encFR [| 0xDEuy; 0xF0uy |] r
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let fild (wordSz: WordSize) ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xDFuy |] b s d 0b000uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xDBuy |] b s d 0b000uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xDFuy |] b s d 0b101uy
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let fistp (wordSz: WordSize) ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xDFuy |] b s d 0b011uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xDBuy |] b s d 0b011uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xDFuy |] b s d 0b111uy
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let fld (wordSz: WordSize) ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xD9uy |] b s d 0b000uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xDDuy |] b s d 0b000uy
  | OneOperand(OprMem(b, s, d, 80<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xDBuy |] b s d 0b101uy
  | OneOperand(OprReg r) when isFPUReg r ->
    encFR [| 0xD9uy; 0xC0uy |] r
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let fld1 _wordSize = function
  | NoOperand -> Resolved [| 0xD9uy; 0xE8uy |]
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let fldcw (wordSz: WordSize) ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xD9uy |] b s d 0b101uy
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let fldz _wordSize = function
  | NoOperand -> Resolved [| 0xD9uy; 0xEEuy |]
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let fmul wordSz ins = x87Arith wordSz ins 0b001uy 0xC8uy 0xC8uy

let fmulp _wordSize = function
  | NoOperand ->
    Resolved [| 0xDEuy; 0xC9uy |]
  | TwoOperands(OprReg r, OprReg Register.ST0) when isFPUReg r ->
    encFR [| 0xDEuy; 0xC8uy |] r
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let fnstcw (wordSz: WordSize) ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xD9uy |] b s d 0b111uy
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let fstp (wordSz: WordSize) ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xD9uy |] b s d 0b011uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xDDuy |] b s d 0b011uy
  | OneOperand(OprMem(b, s, d, 80<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xDBuy |] b s d 0b111uy
  | OneOperand(OprReg r) when isFPUReg r ->
    encFR [| 0xDDuy; 0xD8uy |] r
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let fsub wordSz ins = x87Arith wordSz ins 0b100uy 0xE0uy 0xE8uy

let fsubr wordSz ins = x87Arith wordSz ins 0b101uy 0xE8uy 0xE0uy

let fucomi _wordSize = function
  | TwoOperands(OprReg Register.ST0, OprReg r) when isFPUReg r ->
    encFR [| 0xDBuy; 0xE8uy |] r
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let fucomip _wordSize = function
  | TwoOperands(OprReg Register.ST0, OprReg r) when isFPUReg r ->
    encFR [| 0xDFuy; 0xE8uy |] r
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let fxch _wordSize = function
  | NoOperand -> Resolved [| 0xD9uy; 0xC9uy |]
  | OneOperand(OprReg r) when isFPUReg r -> encFR [| 0xD9uy; 0xC8uy |] r
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let hlt _wordSize = function
  | NoOperand -> Resolved [| 0xF4uy |]
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let idiv wordSz ins = unaryGrp3 wordSz ins 0b111uy

let imul (wordSz: WordSize) ins =
  match ins.Operands with
  | OneOperand(OprReg r) when isReg8 wordSz r ->
    encR ins wordSz prefNormal rexNormal [| 0xF6uy |] r 0b101uy
  | OneOperand(OprMem(b, s, d, 8<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xF6uy |] b s d 0b101uy
  | OneOperand(OprReg r) when isReg16 wordSz r ->
    encR ins wordSz pref66 rexNormal [| 0xF7uy |] r 0b101uy
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins wordSz pref66 rexNormal [| 0xF7uy |] b s d 0b101uy
  | OneOperand(OprReg r) when isReg32 wordSz r ->
    encR ins wordSz prefNormal rexNormal [| 0xF7uy |] r 0b101uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xF7uy |] b s d 0b101uy
  | OneOperand(OprReg r) when isReg64 wordSz r ->
    no32Arch wordSz
    encR ins wordSz prefNormal rexW [| 0xF7uy |] r 0b101uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    no32Arch wordSz
    encM ins wordSz prefNormal rexW [| 0xF7uy |] b s d 0b101uy
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg16 wordSz r1 && isReg16 wordSz r2 ->
    encRR ins wordSz pref66 rexNormal [| 0x0Fuy; 0xAFuy |] r1 r2
  | TwoOperands(OprReg r, Label(lbl, _)) ->
    encRL wordSz ins r lbl [||] [| 0x0Fuy; 0xAFuy |]
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg16 wordSz r ->
    encRM ins wordSz pref66 rexNormal [| 0x0Fuy; 0xAFuy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg32 wordSz r1 && isReg32 wordSz r2 ->
    encRR ins wordSz prefNormal rexNormal [| 0x0Fuy; 0xAFuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg32 wordSz r ->
    encRM ins wordSz prefNormal rexNormal [| 0x0Fuy; 0xAFuy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg64 wordSz r1 && isReg64 wordSz r2 ->
    encRR ins wordSz prefNormal rexW [| 0x0Fuy; 0xAFuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isReg64 wordSz r ->
    encRM ins wordSz prefNormal rexW [| 0x0Fuy; 0xAFuy |] r b s d
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _))
    when isReg16 wordSz r1 && isReg16 wordSz r2 && isInt8 imm ->
    encRRI ins wordSz pref66 rexNormal [| 0x6Buy |] r1 r2 imm 8<rt>
  | ThreeOperands(OprReg r, Label(lbl, _), OprImm(imm, _)) when isInt8 imm ->
    encRLI wordSz ins r lbl [| 0x6Buy |] imm 8<rt>
  | ThreeOperands(OprReg r, OprMem(b, s, d, 16<rt>), OprImm(imm, _))
    when isReg16 wordSz r && isInt8 imm ->
    encRMI ins wordSz pref66 rexNormal [| 0x6Buy |] r b s d imm 8<rt>
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _))
    when isReg32 wordSz r1 && isReg32 wordSz r2 && isInt8 imm ->
    encRRI ins wordSz prefNormal rexNormal [| 0x6Buy |] r1 r2 imm 8<rt>
  | ThreeOperands(OprReg r, OprMem(b, s, d, 32<rt>), OprImm(imm, _))
    when isReg32 wordSz r && isInt8 imm ->
    encRMI ins wordSz prefNormal rexNormal [| 0x6Buy |] r b s d imm 8<rt>
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _))
    when isReg64 wordSz r1 && isReg64 wordSz r2 && isInt8 imm ->
    no32Arch wordSz
    encRRI ins wordSz prefNormal rexW [| 0x6Buy |] r1 r2 imm 8<rt>
  | ThreeOperands(OprReg r, OprMem(b, s, d, 64<rt>), OprImm(imm, _))
    when isReg64 wordSz r && isInt8 imm ->
    no32Arch wordSz
    encRMI ins wordSz prefNormal rexW [| 0x6Buy |] r b s d imm 8<rt>
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _))
    when isReg16 wordSz r1 && isReg16 wordSz r2 ->
    encRRI ins wordSz pref66 rexNormal [| 0x69uy |] r1 r2 imm 16<rt>
  | ThreeOperands(OprReg r, Label(lbl, _), OprImm(imm, _)) ->
    encRLI wordSz ins r lbl [| 0x69uy |] imm 32<rt>
  | ThreeOperands(OprReg r, OprMem(b, s, d, 16<rt>), OprImm(imm, _))
    when isReg16 wordSz r ->
    encRMI ins wordSz pref66 rexNormal [| 0x69uy |] r b s d imm 16<rt>
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _))
    when isReg32 wordSz r1 && isReg32 wordSz r2 ->
    encRRI ins wordSz prefNormal rexNormal [| 0x69uy |] r1 r2 imm 32<rt>
  | ThreeOperands(OprReg r, OprMem(b, s, d, 32<rt>), OprImm(imm, _))
    when isReg32 wordSz r ->
    encRMI ins wordSz prefNormal rexNormal [| 0x69uy |] r b s d imm 32<rt>
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _))
    when isReg64 wordSz r1 && isReg64 wordSz r2 ->
    no32Arch wordSz
    encRRI ins wordSz prefNormal rexW [| 0x69uy |] r1 r2 imm 32<rt>
  | ThreeOperands(OprReg r, OprMem(b, s, d, 64<rt>), OprImm(imm, _))
    when isReg64 wordSz r ->
    no32Arch wordSz
    encRMI ins wordSz prefNormal rexW [| 0x69uy |] r b s d imm 32<rt>
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let inc (wordSz: WordSize) ins =
  match ins.Operands with
  | OneOperand(OprReg r) when isReg8 wordSz r ->
    encR ins wordSz prefNormal rexNormal [| 0xFEuy |] r 0uy
  | OneOperand(OprMem(b, s, d, 8<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xFEuy |] b s d 0uy
  | OneOperand(OprReg r) when isReg16 wordSz r ->
    if isClassicGPReg r && wordSz = WordSize.Bit32 then
      encClassicR true 0x40uy (regTo3Bit r)
    else
      encR ins wordSz pref66 rexNormal [| 0xFFuy |] r 0uy
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins wordSz pref66 rexNormal [| 0xFFuy |] b s d 0uy
  | OneOperand(OprReg r) when isReg32 wordSz r ->
    if isClassicGPReg r && wordSz = WordSize.Bit32 then
      encClassicR false 0x40uy (regTo3Bit r)
    else
      encR ins wordSz prefNormal rexNormal [| 0xFFuy |] r 0uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xFFuy |] b s d 0uy
  | OneOperand(OprReg r) when isReg64 wordSz r ->
    no32Arch wordSz
    encR ins wordSz prefNormal rexW [| 0xFFuy |] r 0uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    no32Arch wordSz
    encM ins wordSz prefNormal rexW [| 0xFFuy |] b s d 0uy
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let interrupt ins =
  match ins.Operands with
  | OneOperand(OprImm(n, _)) when isUInt8 n -> Resolved [| 0xcduy; byte n |]
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let interrupt3 () = Resolved [| 0xccuy |]

let jcc (wordSz: WordSize) ins =
  let branch = relBranch ins.Opcode
  match ins.Operands with
  | OneOperand(Label(lbl, _)) ->
    encLbl ins lbl
  | OneOperand(OprDirAddr(Relative rel)) when isInt8 rel ->
    encD ins wordSz prefNormal rexNormal branch.ShortForm rel 8<rt>
  | OneOperand(OprDirAddr(Relative rel))
    when isInt16 rel && wordSz = WordSize.Bit32 ->
    encD ins wordSz pref66 rexNormal branch.NearForm rel 16<rt>
  | OneOperand(OprDirAddr(Relative rel)) when isInt32 rel ->
    encD ins wordSz prefNormal rexNormal branch.NearForm rel 32<rt>
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let nearJmp (wordSz: WordSize) ins =
  let branch = relBranch Opcode.JMP
  match ins.Operands with
  | OneOperand(Label(lbl, _)) ->
    encLbl ins lbl
  | OneOperand(OprDirAddr(Relative rel)) when isInt8 rel ->
    encD ins wordSz prefNormal rexNormal branch.ShortForm rel 8<rt>
  | OneOperand(OprDirAddr(Relative rel)) when isInt32 rel ->
    encD ins wordSz prefNormal rexNormal branch.NearForm rel 32<rt>
  | OneOperand(OprReg r) when isReg16 wordSz r ->
    no64Arch wordSz (* N.S. *)
    encR ins wordSz pref66 rexNormal [| 0xFFuy |] r 0b100uy
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    no64Arch wordSz (* N.S. *)
    encM ins wordSz pref66 rexNormal [| 0xFFuy |] b s d 0b100uy
  | OneOperand(OprReg r) when isReg32 wordSz r ->
    no64Arch wordSz (* N.S. *)
    encR ins wordSz prefNormal rexNormal [| 0xFFuy |] r 0b100uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    no64Arch wordSz (* N.S. *)
    encM ins wordSz prefNormal rexNormal [| 0xFFuy |] b s d 0b100uy
  | OneOperand(OprReg r) when isReg64 wordSz r ->
    no32Arch wordSz
    encR ins wordSz prefNormal rexNormal [| 0xFFuy |] r 0b100uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    no32Arch wordSz
    encM ins wordSz prefNormal rexNormal [| 0xFFuy |] b s d 0b100uy
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let jmp wordSz ins =
  match ins.Operands with
  | OneOperand(OprDirAddr(Absolute _)) -> farAbsolute 0xEAuy wordSz ins
  | _ when ins.IsFar -> farBranch wordSz ins 0b101uy
  | _ -> nearJmp wordSz ins

let lahf = function
  | NoOperand -> Resolved [| 0x9Fuy |]
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let lea (wordSz: WordSize) ins =
  match ins.Operands with
  | TwoOperands(OprReg r, Label(lbl, _)) ->
    encRL wordSz ins r lbl [||] [| 0x8Duy |]
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg16 wordSz r ->
    encRM ins wordSz pref66 rexNormal [| 0x8Duy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg32 wordSz r ->
    encRM ins wordSz prefNormal rexNormal [| 0x8Duy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isReg64 wordSz r ->
    no32Arch wordSz
    encRM ins wordSz prefNormal rexW [| 0x8Duy |] r b s d
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let leave = function
  | NoOperand -> Resolved [| 0xC9uy |]
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

/// Whether the register is the general one a control or debug register move can
/// name: the mode alone fixes that width, which is why these forms carry
/// neither an operand-size prefix nor REX.W.
let private isSysMovReg wordSz r =
  if wordSz = WordSize.Bit64 then isReg64 wordSz r else isReg32 wordSz r

/// CR8 is told from CR0 by REX.R alone, and legacy mode has no REX to emit, so
/// naming CR8 there cannot be encoded.
let private noCR8In32Bit wordSz r =
  if r = Register.CR8 then no32Arch wordSz else ()

let mov wordSz ins =
  let ins = resolveMemSizeFromReg ins wordSz
  match ins.Operands with
  (* Reg - Ctrl/Dbg and the other way round. A control or debug register has no
     general-purpose width, so these cases cannot be reached by the general
     ones below, but they do have to precede them to keep the reading order the
     operand pairs are tried in. *)
  | TwoOperands(OprReg r1, OprReg r2)
    when isCtrlReg r2 && isSysMovReg wordSz r1 ->
    noCR8In32Bit wordSz r2
    encRR ins wordSz prefNormal rexMR [| 0x0Fuy; 0x20uy |] r2 r1
  | TwoOperands(OprReg r1, OprReg r2)
    when isDbgReg r2 && isSysMovReg wordSz r1 ->
    encRR ins wordSz prefNormal rexMR [| 0x0Fuy; 0x21uy |] r2 r1
  | TwoOperands(OprReg r1, OprReg r2)
    when isCtrlReg r1 && isSysMovReg wordSz r2 ->
    noCR8In32Bit wordSz r1
    encRR ins wordSz prefNormal rexNormal [| 0x0Fuy; 0x22uy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2)
    when isDbgReg r1 && isSysMovReg wordSz r2 ->
    encRR ins wordSz prefNormal rexNormal [| 0x0Fuy; 0x23uy |] r1 r2
  (* Reg - Sreg *)
  | TwoOperands(OprReg r1, OprReg r2) when isReg16 wordSz r1 && isSegReg r2 ->
    encRR ins wordSz pref66 rexMR [| 0x8Cuy |] r2 r1
  | TwoOperands(OprReg r1, OprReg r2) when isReg64 wordSz r1 && isSegReg r2 ->
    encRR ins wordSz prefNormal rexWAndMR [| 0x8Cuy |] r2 r1
  (* Mem - Sreg *)
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprReg r) when isSegReg r ->
    encMR ins wordSz pref66 rexNormal [| 0x8Cuy |] b s d r
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprReg r) when isSegReg r ->
    encMR ins wordSz prefNormal rexWAndMR [| 0x8Cuy |] b s d r
  (* Sreg - Reg/Mem. These have to precede the general-purpose cases below,
     because a segment register answers to isReg16 and would otherwise be
     encoded as whichever general register shares its number. *)
  | TwoOperands(OprReg r1, OprReg r2)
    when isSegReg r1 && not (isSegReg r2) && isReg16 wordSz r2 ->
    encRR ins wordSz prefNormal rexNormal [| 0x8Euy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isSegReg r ->
    encRM ins wordSz prefNormal rexNormal [| 0x8Euy |] r b s d
  (* Mem - Reg *)
  | TwoOperands(Label(lbl, _), OprReg r) ->
    encRL wordSz ins r lbl [| 0x88uy |] [| 0x89uy |]
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprReg r) when isReg8 wordSz r ->
    encMR ins wordSz prefNormal rexNormal [| 0x88uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprReg r) when isReg16 wordSz r ->
    encMR ins wordSz pref66 rexNormal [| 0x89uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprReg r) when isReg32 wordSz r ->
    encMR ins wordSz prefNormal rexNormal [| 0x89uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprReg r) when isReg64 wordSz r ->
    no32Arch wordSz
    encMR ins wordSz prefNormal rexW [| 0x89uy |] b s d r
  (* Reg - Reg *)
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg8 wordSz r1 && isReg8 wordSz r2 ->
    encRR ins wordSz prefNormal rexNormal [| 0x8Auy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg16 wordSz r1 && isReg16 wordSz r2 ->
    encRR ins wordSz pref66 rexNormal [| 0x8Buy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg32 wordSz r1 && isReg32 wordSz r2 ->
    encRR ins wordSz prefNormal rexNormal [| 0x8Buy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg64 wordSz r1 && isReg64 wordSz r2 ->
    no32Arch wordSz
    encRR ins wordSz prefNormal rexW [| 0x8Buy |] r1 r2
  (* Reg - Mem *)
  | TwoOperands(OprReg r, Label(lbl, _)) ->
    encRL wordSz ins r lbl [| 0x8Auy |] [| 0x8Buy |]
  | TwoOperands(OprReg r, OprMem(b, s, d, 8<rt>)) when isReg8 wordSz r ->
    encRM ins wordSz prefNormal rexNormal [| 0x8Auy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg16 wordSz r ->
    encRM ins wordSz pref66 rexNormal [| 0x8Buy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg32 wordSz r ->
    encRM ins wordSz prefNormal rexNormal [| 0x8Buy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isReg64 wordSz r ->
    no32Arch wordSz
    encRM ins wordSz prefNormal rexW [| 0x8Buy |] r b s d
  (* Reg - Imm (Opcode reg field) *)
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg8 wordSz r ->
    encOI ins wordSz prefNormal rexNormal 0xB0uy r imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg16 wordSz r ->
    encOI ins wordSz pref66 rexNormal 0xB8uy r imm 16<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg32 wordSz r ->
    encOI ins wordSz prefNormal rexNormal 0xB8uy r imm 32<rt>
  | TwoOperands(OprReg r, OprImm(imm, _))
    when isReg64 wordSz r && isInt32 imm ->
    no32Arch wordSz
    encRI ins wordSz prefNormal rexW [| 0xC7uy |] r 0b000uy imm 32<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg64 wordSz r ->
    no32Arch wordSz
    encOI ins wordSz prefNormal rexW 0xB8uy r imm 64<rt>
  (* Mem - Imm *)
  | TwoOperands(Label(lbl, _), OprImm(imm, _)) ->
    encLI wordSz ins lbl 0b000uy imm 32<rt> [| 0xC6uy |] [| 0xC7uy |]
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprImm(imm, _)) ->
    encMI ins wordSz prefNormal rexNormal [| 0xC6uy |] b s d 0b000uy imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprImm(imm, _)) ->
    encMI ins wordSz pref66 rexNormal [| 0xC7uy |] b s d 0b000uy imm 16<rt>
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprImm(imm, _)) ->
    encMI ins wordSz prefNormal rexNormal [| 0xC7uy |] b s d 0b000uy imm 32<rt>
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprImm(imm, _)) ->
    no32Arch wordSz;
    encMI ins wordSz prefNormal rexW [| 0xC7uy |] b s d 0b000uy imm 32<rt>
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// Encodes an SSE move, which unlike the arithmetic above can also store to
/// memory. The store opcode always follows the load opcode in the encoding
/// tables, but is passed explicitly rather than derived.
let sseMov (wordSz: WordSize) ins pref loadOp storeOp memSz =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins wordSz pref rexNormal loadOp r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, sz)) when isXMMReg r && sz = memSz ->
    encRM ins wordSz pref rexNormal loadOp r b s d
  | TwoOperands(OprMem(b, s, d, sz), OprReg r) when isXMMReg r && sz = memSz ->
    encMR ins wordSz pref rexNormal storeOp b s d r
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let movaps wordSz ins =
  sseMov wordSz ins prefNormal [| 0x0Fuy; 0x28uy |] [| 0x0Fuy; 0x29uy |] 128<rt>

let movd (wordSz: WordSize) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isMMXReg r1 && isReg32 wordSz r2 ->
    encRR ins wordSz prefNormal rexNormal [| 0x0Fuy; 0x6Euy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isMMXReg r ->
    encRM ins wordSz prefNormal rexNormal [| 0x0Fuy; 0x6Euy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2) when isReg32 wordSz r1 && isMMXReg r2 ->
    encRR ins wordSz prefNormal rexMR [| 0x0Fuy; 0x7Euy |] r2 r1
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprReg r) when isMMXReg r ->
    encMR ins wordSz prefNormal rexNormal [| 0x0Fuy; 0x7Euy |] b s d r
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isReg32 wordSz r2 ->
    encRR ins wordSz pref66 rexNormal [| 0x0Fuy; 0x6Euy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isXMMReg r ->
    encRM ins wordSz pref66 rexNormal [| 0x0Fuy; 0x6Euy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2) when isReg32 wordSz r1 && isXMMReg r2 ->
    encRR ins wordSz pref66 rexMR [| 0x0Fuy; 0x7Euy |] r2 r1
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprReg r) when isXMMReg r ->
    encMR ins wordSz pref66 rexNormal [| 0x0Fuy; 0x7Euy |] b s d r
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let movdqa wordSz ins =
  sseMov wordSz ins pref66 [| 0x0Fuy; 0x6Fuy |] [| 0x0Fuy; 0x7Fuy |] 128<rt>

let movdqu wordSz ins =
  sseMov wordSz ins prefF3 [| 0x0Fuy; 0x6Fuy |] [| 0x0Fuy; 0x7Fuy |] 128<rt>

let movsd (wordSz: WordSize) ins =
  match ins.Operands with
  | NoOperand ->
    stringOp wordSz ins prefNormal rexNormal 0xA5uy
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins wordSz prefF2 rexNormal [| 0x0Fuy; 0x10uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isXMMReg r ->
    encRM ins wordSz prefF2 rexNormal [| 0x0Fuy; 0x10uy |] r b s d
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprReg r) when isXMMReg r ->
    encMR ins wordSz prefF2 rexNormal [| 0x0Fuy; 0x11uy |] b s d r
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let movss wordSz ins =
  sseMov wordSz ins prefF3 [| 0x0Fuy; 0x10uy |] [| 0x0Fuy; 0x11uy |] 32<rt>

let movsx (wordSz: WordSize) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg16 wordSz r1 && isReg8 wordSz r2 ->
    encRR ins wordSz pref66 rexNormal [| 0x0Fuy; 0xBEuy |] r1 r2
  | TwoOperands(OprReg r, Label(lbl, _)) ->
    encRL wordSz ins r lbl [||] [| 0x0Fuy; 0xBEuy |]
  | TwoOperands(OprReg r, OprMem(b, s, d, 8<rt>)) when isReg16 wordSz r ->
    encRM ins wordSz pref66 rexNormal [| 0x0Fuy; 0xBEuy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg32 wordSz r1 && isReg8 wordSz r2 ->
    encRR ins wordSz prefNormal rexNormal [| 0x0Fuy; 0xBEuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 8<rt>)) when isReg32 wordSz r ->
    encRM ins wordSz prefNormal rexNormal [| 0x0Fuy; 0xBEuy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg64 wordSz r1 && isReg8 wordSz r2 ->
    no32Arch wordSz
    encRR ins wordSz prefNormal rexW [| 0x0Fuy; 0xBEuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 8<rt>)) when isReg64 wordSz r ->
    no32Arch wordSz
    encRM ins wordSz prefNormal rexW [| 0x0Fuy; 0xBEuy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg16 wordSz r1 && isReg16 wordSz r2 ->
    encRR ins wordSz pref66 rexNormal [| 0x0Fuy; 0xBFuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg16 wordSz r ->
    encRM ins wordSz pref66 rexNormal [| 0x0Fuy; 0xBFuy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg32 wordSz r1 && isReg16 wordSz r2 ->
    encRR ins wordSz prefNormal rexNormal [| 0x0Fuy; 0xBFuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg32 wordSz r ->
    encRM ins wordSz prefNormal rexNormal [| 0x0Fuy; 0xBFuy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg64 wordSz r1 && isReg16 wordSz r2 ->
    no32Arch wordSz
    encRR ins wordSz prefNormal rexW [| 0x0Fuy; 0xBFuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg64 wordSz r ->
    no32Arch wordSz
    encRM ins wordSz prefNormal rexW [| 0x0Fuy; 0xBFuy |] r b s d
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let movsxd (wordSz: WordSize) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg16 wordSz r1 && isReg32 wordSz r2 ->
    no32Arch wordSz
    encRR ins wordSz pref66 rexNormal [| 0x63uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg16 wordSz r ->
    no32Arch wordSz
    encRM ins wordSz pref66 rexNormal [| 0x63uy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg32 wordSz r1 && isReg32 wordSz r2 ->
    no32Arch wordSz
    encRR ins wordSz prefNormal rexNormal [| 0x63uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg32 wordSz r ->
    no32Arch wordSz
    encRM ins wordSz prefNormal rexNormal [| 0x63uy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg64 wordSz r1 && isReg32 wordSz r2 ->
    no32Arch wordSz
    encRR ins wordSz prefNormal rexW [| 0x63uy |] r1 r2
  | TwoOperands(OprReg r, Label(lbl, _)) ->
    encRL wordSz ins r lbl [||] [| 0x63uy |]
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg64 wordSz r ->
    no32Arch wordSz
    encRM ins wordSz prefNormal rexW [| 0x63uy |] r b s d
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let movups wordSz ins =
  sseMov wordSz ins prefNormal [| 0x0Fuy; 0x10uy |] [| 0x0Fuy; 0x11uy |] 128<rt>

let movzx (wordSz: WordSize) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg16 wordSz r1 && isReg8 wordSz r2 ->
    encRR ins wordSz pref66 rexNormal [| 0x0Fuy; 0xB6uy |] r1 r2
  | TwoOperands(OprReg r, Label(lbl, _)) ->
    encRL wordSz ins r lbl [||] [| 0x0Fuy; 0xB6uy |]
  | TwoOperands(OprReg r, OprMem(b, s, d, 8<rt>)) when isReg16 wordSz r ->
    encRM ins wordSz pref66 rexNormal [| 0x0Fuy; 0xB6uy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg32 wordSz r1 && isReg8 wordSz r2 ->
    encRR ins wordSz prefNormal rexNormal [| 0x0Fuy; 0xB6uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 8<rt>)) when isReg32 wordSz r ->
    encRM ins wordSz prefNormal rexNormal [| 0x0Fuy; 0xB6uy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg64 wordSz r1 && isReg8 wordSz r2 ->
    no32Arch wordSz
    encRR ins wordSz prefNormal rexW [| 0x0Fuy; 0xB6uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 8<rt>)) when isReg64 wordSz r ->
    no32Arch wordSz
    encRM ins wordSz prefNormal rexW [| 0x0Fuy; 0xB6uy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg16 wordSz r1 && isReg16 wordSz r2 ->
    encRR ins wordSz pref66 rexNormal [| 0x0Fuy; 0xB7uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg16 wordSz r ->
    encRM ins wordSz pref66 rexNormal [| 0x0Fuy; 0xB7uy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg32 wordSz r1 && isReg16 wordSz r2 ->
    encRR ins wordSz prefNormal rexNormal [| 0x0Fuy; 0xB7uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg32 wordSz r ->
    encRM ins wordSz prefNormal rexNormal [| 0x0Fuy; 0xB7uy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg64 wordSz r1 && isReg16 wordSz r2 ->
    no32Arch wordSz
    encRR ins wordSz prefNormal rexW [| 0x0Fuy; 0xB7uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg64 wordSz r ->
    no32Arch wordSz
    encRM ins wordSz prefNormal rexW [| 0x0Fuy; 0xB7uy |] r b s d
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let mul wordSz ins = unaryGrp3 wordSz ins 0b100uy

let mulsd wordSz ins = sseRegRM wordSz ins prefF2 [| 0x0Fuy; 0x59uy |] 64<rt>

let mulss wordSz ins = sseRegRM wordSz ins prefF3 [| 0x0Fuy; 0x59uy |] 32<rt>

let neg wordSz ins = unaryGrp3 wordSz ins 0b011uy

let nop (wordSz: WordSize) ins =
  match ins.Operands with
  | NoOperand ->
    Resolved [| 0x90uy |]
  | OneOperand(OprReg r) when isReg16 wordSz r ->
    encR ins wordSz pref66 rexNormal [| 0x0Fuy; 0x1Fuy |] r 0b000uy
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins wordSz pref66 rexNormal [| 0x0Fuy; 0x1Fuy |] b s d 0b000uy
  | OneOperand(OprReg r) when isReg32 wordSz r ->
    encR ins wordSz prefNormal rexNormal [| 0x0Fuy; 0x1Fuy |] r 0b000uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0x0Fuy; 0x1Fuy |] b s d 0b000uy
  | OneOperand(OprReg r) when isReg64 wordSz r ->
    no32Arch wordSz
    encR ins wordSz prefNormal rexW [| 0x0Fuy; 0x1Fuy |] r 0b000uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    no32Arch wordSz
    encM ins wordSz prefNormal rexW [| 0x0Fuy; 0x1Fuy |] b s d 0b000uy
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let not wordSz ins = unaryGrp3 wordSz ins 0b010uy

let logOr wordSz ins = arithmetic wordSz ins 0x08uy 0b001uy

let orpd wordSz ins = sseRegRM wordSz ins pref66 [| 0x0Fuy; 0x56uy |] 128<rt>

/// The packed integer instructions come in an MMX form and an SSE form that
/// share an opcode byte, told apart by which register file the operands name.
/// In the encoding it is the 66 prefix that distinguishes them, so the SSE form
/// falls through to sseRegRM and only the MMX form is spelled out here.
let mmxOrSseRegRM (wordSz: WordSize) ins op mmxMemSz =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isMMXReg r1 && isMMXReg r2 ->
    encRR ins wordSz prefNormal rexNormal op r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, sz))
    when isMMXReg r && sz = mmxMemSz ->
    encRM ins wordSz prefNormal rexNormal op r b s d
  | _ ->
    sseRegRM wordSz ins pref66 op 128<rt>

let paddd wordSz ins =
  mmxOrSseRegRM wordSz ins [| 0x0Fuy; 0xFEuy |] 64<rt>

let palignr (wordSz: WordSize) ins =
  match ins.Operands with
  (* Reg - Reg - Imm8 *)
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _))
    when isMMXReg r1 && isMMXReg r2 ->
    encRRI ins wordSz prefNormal rexNormal [| 0x0Fuy; 0x3Auy; 0x0Fuy |]
      r1 r2 imm 8<rt>
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _))
    when isXMMReg r1 && isXMMReg r2 ->
    encRRI ins wordSz pref66 rexNormal
      [| 0x0Fuy; 0x3Auy; 0x0Fuy |] r1 r2 imm 8<rt>
  (* Reg - Mem - Imm8 *)
  | ThreeOperands(OprReg r, OprMem(b, s, d, 64<rt>), OprImm(imm, _))
    when isMMXReg r ->
    encRMI ins wordSz prefNormal rexNormal [| 0x0Fuy; 0x3Auy; 0x0Fuy |]
      r b s d imm 8<rt>
  | ThreeOperands(OprReg r, OprMem(b, s, d, 128<rt>), OprImm(imm, _))
    when isXMMReg r ->
    encRMI ins wordSz
      pref66 rexNormal [| 0x0Fuy; 0x3Auy; 0x0Fuy |] r b s d imm 8<rt>
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let pop (wordSz: WordSize) ins =
  match ins.Operands with
  | OneOperand(OprReg Register.DS) ->
    no64Arch wordSz; Resolved [| 0x1Fuy |]
  | OneOperand(OprReg Register.ES) ->
    no64Arch wordSz; Resolved [| 0x07uy |]
  | OneOperand(OprReg Register.SS) ->
    no64Arch wordSz; Resolved [| 0x17uy |]
  | OneOperand(OprReg Register.FS) ->
    Resolved [| 0x0Fuy; 0xA1uy |]
  | OneOperand(OprReg Register.GS) ->
    Resolved [| 0x0Fuy; 0xA9uy |]
  | OneOperand(OprReg r) when isReg16 wordSz r ->
    if isClassicGPReg r then encClassicR true 0x58uy (regTo3Bit r)
    else encR ins wordSz pref66 rexNormal [| 0x8Fuy |] r 0uy
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins wordSz pref66 rexNormal [| 0x8Fuy |] b s d 0uy
  | OneOperand(OprReg r) when isReg32 wordSz r ->
    no64Arch wordSz
    if isClassicGPReg r then encClassicR false 0x58uy (regTo3Bit r)
    else encR ins wordSz prefNormal rexNormal [| 0x8Fuy |] r 0uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    no64Arch wordSz
    encM ins wordSz prefNormal rexNormal [| 0x8Fuy |] b s d 0uy
  | OneOperand(OprReg r) when isReg64 wordSz r ->
    no32Arch wordSz
    if isClassicGPReg r then encClassicR false 0x58uy (regTo3Bit r)
    else encR ins wordSz prefNormal rexW [| 0x8Fuy |] r 0uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    no32Arch wordSz
    encM ins wordSz prefNormal rexW [| 0x8Fuy |] b s d 0uy
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let pshufd (wordSz: WordSize) ins =
  match ins.Operands with
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _))
    when isXMMReg r1 && isXMMReg r2 ->
    encRRI ins wordSz pref66 rexNormal [| 0x0Fuy; 0x70uy |] r1 r2 imm 8<rt>
  | ThreeOperands(OprReg r, OprMem(b, s, d, 128<rt>), OprImm(imm, _))
    when isXMMReg r ->
    encRMI ins wordSz pref66 rexNormal [| 0x0Fuy; 0x70uy |] r b s d imm 8<rt>
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let punpckldq (wordSz: WordSize) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isMMXReg r1 && isMMXReg r2 ->
    encRR ins wordSz prefNormal rexNormal [| 0x0Fuy; 0x62uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isMMXReg r ->
    encRM ins wordSz prefNormal rexNormal [| 0x0Fuy; 0x62uy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins wordSz pref66 rexNormal [| 0x0Fuy; 0x62uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 128<rt>)) when isXMMReg r ->
    encRM ins wordSz pref66 rexNormal [| 0x0Fuy; 0x62uy |] r b s d
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let push (wordSz: WordSize) ins =
  match ins.Operands with
  | OneOperand(OprReg Register.CS) ->
    no64Arch wordSz; Resolved [| 0x0Euy |]
  | OneOperand(OprReg Register.SS) ->
    no64Arch wordSz; Resolved [| 0x16uy |]
  | OneOperand(OprReg Register.DS) ->
    no64Arch wordSz; Resolved [| 0x1Euy |]
  | OneOperand(OprReg Register.ES) ->
    no64Arch wordSz; Resolved [| 0x06uy |]
  | OneOperand(OprReg Register.FS) ->
    Resolved [| 0x0Fuy; 0xA0uy |]
  | OneOperand(OprReg Register.GS) ->
    Resolved [| 0x0Fuy; 0xA8uy |]
  | OneOperand(OprReg r) when isReg16 wordSz r ->
    if isClassicGPReg r then encClassicR true 0x50uy (regTo3Bit r)
    else encR ins wordSz pref66 rexNormal [| 0xFFuy |] r 0b110uy
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins wordSz pref66 rexNormal [| 0xFFuy |] b s d 0b110uy
  | OneOperand(OprReg r) when isReg32 wordSz r ->
    no64Arch wordSz
    if isClassicGPReg r then encClassicR false 0x50uy (regTo3Bit r)
    else encR ins wordSz prefNormal rexNormal [| 0xFFuy |] r 0b110uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    no64Arch wordSz
    encM ins wordSz prefNormal rexNormal [| 0xFFuy |] b s d 0b110uy
  | OneOperand(OprReg r) when isReg64 wordSz r ->
    no32Arch wordSz
    if isClassicGPReg r then encClassicR false 0x50uy (regTo3Bit r)
    else encR ins wordSz prefNormal rexNormal [| 0xFFuy |] r 0b110uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    no32Arch wordSz
    encM ins wordSz prefNormal rexNormal [| 0xFFuy |] b s d 0b110uy
  | OneOperand(OprImm(imm, _)) when isInt8 imm ->
    encImm ins wordSz prefNormal rexNormal [| 0x6Auy |] imm 8<rt>
  | OneOperand(OprImm(imm, _)) when isInt16 imm ->
    encImm ins wordSz pref66 rexNormal [| 0x68uy |] imm 16<rt>
  | OneOperand(OprImm(imm, _)) when isUInt32 imm ->
    encImm ins wordSz prefNormal rexNormal [| 0x68uy |] imm 32<rt>
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let pxor (wordSz: WordSize) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isMMXReg r1 && isMMXReg r2 ->
    encRR ins wordSz prefNormal rexNormal [| 0x0Fuy; 0xEFuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isMMXReg r ->
    encRM ins wordSz prefNormal rexNormal [| 0x0Fuy; 0xEFuy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins wordSz pref66 rexNormal [| 0x0Fuy; 0xEFuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 128<rt>)) when isXMMReg r ->
    encRM ins wordSz pref66 rexNormal [| 0x0Fuy; 0xEFuy |] r b s d
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let rotateOrShift (wordSz: WordSize) ins regConstr =
  match ins.Operands with
  | TwoOperands(OprReg r, OprImm(1L as imm, _)) when isReg8 wordSz r ->
    encRI ins wordSz prefNormal rexNormal [| 0xD0uy |] r regConstr imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprImm(1L as imm, _)) ->
    encMI ins wordSz prefNormal rexNormal [| 0xD0uy |] b s d regConstr imm 8<rt>
  | TwoOperands(OprReg r, OprReg Register.CL) when isReg8 wordSz r ->
    encRC ins wordSz prefNormal rexMR [| 0xD2uy |] r regConstr
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprReg Register.CL) ->
    encMC ins wordSz prefNormal rexNormal [| 0xD2uy |] b s d regConstr
  | TwoOperands(OprReg r, OprImm(imm, _))  when isReg8 wordSz r ->
    encRI ins wordSz prefNormal rexNormal [| 0xC0uy |] r regConstr imm 8<rt>
  | TwoOperands(Label(lbl, _), OprImm(imm, _)) ->
    encLI wordSz ins lbl regConstr imm 8<rt> [| 0xC0uy |] [| 0xC1uy |]
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprImm(imm, _)) ->
    encMI ins wordSz prefNormal rexNormal [| 0xC0uy |] b s d regConstr imm 8<rt>
  | TwoOperands(OprReg r, OprImm(1L as imm, _)) when isReg16 wordSz r ->
    encRI ins wordSz pref66 rexNormal [| 0xD1uy |] r regConstr imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprImm(1L as imm, _)) ->
    encMI ins wordSz pref66 rexNormal [| 0xD1uy |] b s d regConstr imm 8<rt>
  | TwoOperands(OprReg r, OprReg Register.CL) when isReg16 wordSz r ->
    encRC ins wordSz pref66 rexMR [| 0xD3uy |] r regConstr
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprReg Register.CL) ->
    encMC ins wordSz pref66 rexNormal [| 0xD3uy |] b s d regConstr
  | TwoOperands(OprReg r, OprImm(imm, _))  when isReg16 wordSz r ->
    encRI ins wordSz pref66 rexNormal [| 0xC1uy |] r regConstr imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprImm(imm, _)) ->
    encMI ins wordSz pref66 rexNormal [| 0xC1uy |] b s d regConstr imm 8<rt>
  | TwoOperands(OprReg r, OprImm(1L as imm, _)) when isReg32 wordSz r ->
    encRI ins wordSz prefNormal rexNormal [| 0xD1uy |] r regConstr imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprImm(1L as imm, _)) ->
    encMI ins wordSz prefNormal rexNormal [| 0xD1uy |] b s d regConstr imm 8<rt>
  | TwoOperands(OprReg r, OprReg Register.CL) when isReg32 wordSz r ->
    encRC ins wordSz prefNormal rexMR [| 0xD3uy |] r regConstr
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprReg Register.CL) ->
    encMC ins wordSz prefNormal rexNormal [| 0xD3uy |] b s d regConstr
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg32 wordSz r ->
    encRI ins wordSz prefNormal rexNormal [| 0xC1uy |] r regConstr imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprImm(imm, _)) ->
    encMI ins wordSz prefNormal rexNormal [| 0xC1uy |] b s d regConstr imm 8<rt>
  | TwoOperands(OprReg r, OprImm(1L as imm, _)) when isReg64 wordSz r ->
    no32Arch wordSz
    encRI ins wordSz prefNormal rexW [| 0xD1uy |] r regConstr imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprImm(1L as imm, _)) ->
    no32Arch wordSz
    encMI ins wordSz prefNormal rexW [| 0xD1uy |] b s d regConstr imm 8<rt>
  | TwoOperands(OprReg r, OprReg Register.CL) when isReg64 wordSz r ->
    no32Arch wordSz
    encRC ins wordSz prefNormal rexWAndMR [| 0xD3uy |] r regConstr
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprReg Register.CL) ->
    no32Arch wordSz
    encMC ins wordSz prefNormal rexW [| 0xD3uy |] b s d regConstr
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg64 wordSz r ->
    no32Arch wordSz
    encRI ins wordSz prefNormal rexW [| 0xC1uy |] r regConstr imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprImm(imm, _)) ->
    no32Arch wordSz
    encMI ins wordSz prefNormal rexW [| 0xC1uy |] b s d regConstr imm 8<rt>
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let rcl wordSz ins = rotateOrShift wordSz ins 0b010uy

let rcr wordSz ins = rotateOrShift wordSz ins 0b011uy

let rol wordSz ins = rotateOrShift wordSz ins 0b000uy

let ror wordSz ins = rotateOrShift wordSz ins 0b001uy

let ret (wordSz: WordSize) ins =
  match ins.Operands with
  | NoOperand ->
    Resolved [| 0xC3uy |]
  (* The parser offers a jump target to every branch opcode, RET included, but
     RET's operand is a count of bytes to pop rather than a displacement, so it
     is encoded as the immediate it is and not relative to anything. *)
  | OneOperand(OprDirAddr(Relative imm))
  | OneOperand(OprImm(imm, _)) ->
    encImm ins wordSz prefNormal rexNormal [| 0xC2uy |] imm 16<rt>
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let sar wordSz ins = rotateOrShift wordSz ins 0b111uy

let shl wordSz ins = rotateOrShift wordSz ins 0b100uy

let shr wordSz ins = rotateOrShift wordSz ins 0b101uy

let sahf = function
  | NoOperand -> Resolved [| 0x9Euy |]
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let sbb wordSz ins = arithmetic wordSz ins 0x18uy 0b011uy

let scasb wordSz ins = stringOp wordSz ins prefNormal rexNormal 0xAEuy

let scasd wordSz ins = stringOp wordSz ins prefNormal rexNormal 0xAFuy

let scasq (wordSz: WordSize) ins =
  no32Arch wordSz
  stringOp wordSz ins prefNormal rexW 0xAFuy

let scasw wordSz ins = stringOp wordSz ins pref66 rexNormal 0xAFuy

let setcc (wordSz: WordSize) ins op =
  match ins.Operands with
  | OneOperand(OprReg r) when isReg8 wordSz r ->
    encR ins wordSz prefNormal rexNormal [| 0x0Fuy; op |] r 0b000uy
  | OneOperand(OprMem(b, s, d, 8<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0x0Fuy; op |] b s d 0b000uy
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let seta wordSz ins = setcc wordSz ins 0x97uy

let setb wordSz ins = setcc wordSz ins 0x92uy

let setbe wordSz ins = setcc wordSz ins 0x96uy

let setg wordSz ins = setcc wordSz ins 0x9Fuy

let setl wordSz ins = setcc wordSz ins 0x9Cuy

let setle wordSz ins = setcc wordSz ins 0x9Euy

let setnb wordSz ins = setcc wordSz ins 0x93uy

let setnl wordSz ins = setcc wordSz ins 0x9Duy

let setno wordSz ins = setcc wordSz ins 0x91uy

let setnp wordSz ins = setcc wordSz ins 0x9Buy

let setns wordSz ins = setcc wordSz ins 0x99uy

let setnz wordSz ins = setcc wordSz ins 0x95uy

let seto wordSz ins = setcc wordSz ins 0x90uy

let setp wordSz ins = setcc wordSz ins 0x9Auy

let sets wordSz ins = setcc wordSz ins 0x98uy

let setz wordSz ins = setcc wordSz ins 0x94uy

let shld (wordSz: WordSize) ins =
  match ins.Operands with
  (* The destination goes in ModRM.rm and the source in ModRM.reg, which is
     the opposite of the order modrmRR reads its arguments in, so every
     register form below passes them the other way round. *)
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _))
    when isReg16 wordSz r1 && isReg16 wordSz r2 ->
    encRRI ins wordSz pref66 rexMR [| 0x0Fuy; 0xA4uy |] r2 r1 imm 8<rt>
  | ThreeOperands(OprMem(b, s, d, 16<rt>), OprReg r, OprImm(imm, _))
    when isReg16 wordSz r ->
    encMRI ins wordSz pref66 rexNormal [| 0x0Fuy; 0xA4uy |] b s d r imm 8<rt>
  | ThreeOperands(OprReg r1, OprReg r2, OprReg Register.CL)
    when isReg16 wordSz r1 && isReg16 wordSz r2 ->
    encRR ins wordSz pref66 rexMR [| 0x0Fuy; 0xA5uy |] r2 r1
  | ThreeOperands(OprMem(b, s, d, 16<rt>), OprReg r, OprReg Register.CL)
    when isReg16 wordSz r ->
    encMR ins wordSz pref66 rexNormal [| 0x0Fuy; 0xA5uy |] b s d r
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _))
    when isReg32 wordSz r1 && isReg32 wordSz r2 ->
    encRRI ins wordSz prefNormal rexMR [| 0x0Fuy; 0xA4uy |] r2 r1 imm 8<rt>
  | ThreeOperands(OprMem(b, s, d, 32<rt>), OprReg r, OprImm(imm, _))
    when isReg32 wordSz r ->
    encMRI ins wordSz prefNormal rexNormal
      [| 0x0Fuy; 0xA4uy |] b s d r imm 8<rt>
  | ThreeOperands(OprReg r1, OprReg r2, OprReg Register.CL)
    when isReg32 wordSz r1 && isReg32 wordSz r2 ->
    encRR ins wordSz prefNormal rexMR [| 0x0Fuy; 0xA5uy |] r2 r1
  | ThreeOperands(OprMem(b, s, d, 32<rt>), OprReg r, OprReg Register.CL)
    when isReg32 wordSz r ->
    encMR ins wordSz prefNormal rexNormal [| 0x0Fuy; 0xA5uy |] b s d r
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _))
    when isReg64 wordSz r1 && isReg64 wordSz r2 ->
    no32Arch wordSz
    encRRI ins wordSz prefNormal rexWAndMR [| 0x0Fuy; 0xA4uy |] r2 r1 imm 8<rt>
  | ThreeOperands(OprMem(b, s, d, 64<rt>), OprReg r, OprImm(imm, _))
    when isReg64 wordSz r ->
    no32Arch wordSz
    encMRI ins wordSz prefNormal rexW [| 0x0Fuy; 0xA4uy |] b s d r imm 8<rt>
  | ThreeOperands(OprReg r1, OprReg r2, OprReg Register.CL)
    when isReg64 wordSz r1 && isReg64 wordSz r2 ->
    no32Arch wordSz
    encRR ins wordSz prefNormal rexWAndMR [| 0x0Fuy; 0xA5uy |] r2 r1
  | ThreeOperands(OprMem(b, s, d, 64<rt>), OprReg r, OprReg Register.CL)
    when isReg64 wordSz r ->
    no32Arch wordSz
    encMR ins wordSz prefNormal rexW [| 0x0Fuy; 0xA5uy |] b s d r
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let stosb wordSz ins = stringOp wordSz ins prefNormal rexNormal 0xAAuy

let stosd wordSz ins = stringOp wordSz ins prefNormal rexNormal 0xABuy

let stosq (wordSz: WordSize) ins =
  no32Arch wordSz
  stringOp wordSz ins prefNormal rexW 0xABuy

let stosw wordSz ins = stringOp wordSz ins pref66 rexNormal 0xABuy

let sub wordSz ins = arithmetic wordSz ins 0x28uy 0b101uy

let subsd wordSz ins = sseRegRM wordSz ins prefF2 [| 0x0Fuy; 0x5Cuy |] 64<rt>

let subss wordSz ins = sseRegRM wordSz ins prefF3 [| 0x0Fuy; 0x5Cuy |] 32<rt>

let test (wordSz: WordSize) ins =
  match ins.Operands with
  (* Reg (fixed) - Imm *)
  | TwoOperands(OprReg Register.AL, OprImm(imm, _)) ->
    encImm ins wordSz prefNormal rexNormal [| 0xA8uy |] imm 8<rt>
  | TwoOperands(OprReg Register.AX, OprImm(imm, _)) ->
    encImm ins wordSz pref66 rexNormal [| 0xA9uy |] imm 16<rt>
  | TwoOperands(OprReg Register.EAX, OprImm(imm, _)) ->
    encImm ins wordSz prefNormal rexNormal [| 0xA9uy |] imm 32<rt>
  | TwoOperands(OprReg Register.RAX, OprImm(imm, _)) ->
    no32Arch wordSz
    encImm ins wordSz prefNormal rexW [| 0xA9uy |] imm 32<rt>
  (* Reg - Imm *)
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg8 wordSz r ->
    encRI ins wordSz prefNormal rexNormal [| 0xF6uy |] r 0b000uy imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg16 wordSz r ->
    encRI ins wordSz pref66 rexNormal [| 0xF7uy |] r 0b000uy imm 16<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg32 wordSz r ->
    encRI ins wordSz prefNormal rexNormal [| 0xF7uy |] r 0b000uy imm 32<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg64 wordSz r ->
    no32Arch wordSz
    encRI ins wordSz prefNormal rexW [| 0xF7uy |] r 0b000uy imm 32<rt>
  (* Mem - Imm *)
  | TwoOperands(Label(lbl, _), OprImm(imm, _)) ->
    encLI wordSz ins lbl 0b000uy imm 32<rt> [| 0xF6uy |] [| 0xF7uy |]
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprImm(imm, _)) ->
    encMI ins wordSz prefNormal rexNormal [| 0xF6uy |] b s d 0b000uy imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprImm(imm, _)) ->
    encMI ins wordSz pref66 rexNormal [| 0xF7uy |] b s d 0b000uy imm 16<rt>
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprImm(imm, _)) ->
    encMI ins wordSz prefNormal rexNormal [| 0xF7uy |] b s d 0b000uy imm 32<rt>
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprImm(imm, _)) ->
    no32Arch wordSz;
    encMI ins wordSz prefNormal rexW [| 0xF7uy |] b s d 0b000uy imm 32<rt>
  (* Reg - Reg *)
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg8 wordSz r1 && isReg8 wordSz r2 ->
    encRR ins wordSz prefNormal rexMR [| 0x84uy |] r2 r1
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg16 wordSz r1 && isReg16 wordSz r2 ->
    encRR ins wordSz pref66 rexMR [| 0x85uy |] r2 r1
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg32 wordSz r1 && isReg32 wordSz r2 ->
    encRR ins wordSz prefNormal rexMR [| 0x85uy |] r2 r1
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg64 wordSz r1 && isReg64 wordSz r2 ->
    no32Arch wordSz
    encRR ins wordSz prefNormal rexWAndMR [| 0x85uy |] r2 r1
  (* Mem - Reg *)
  | TwoOperands(OprReg r, Label(lbl, _)) ->
    encRL wordSz ins r lbl [| 0x84uy |] [| 0x85uy |]
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprReg r) when isReg8 wordSz r ->
    encMR ins wordSz prefNormal rexNormal [| 0x84uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprReg r) when isReg16 wordSz r ->
    encMR ins wordSz pref66 rexNormal [| 0x85uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprReg r) when isReg32 wordSz r ->
    encMR ins wordSz prefNormal rexNormal [| 0x85uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprReg r) when isReg64 wordSz r ->
    no32Arch wordSz
    encMR ins wordSz prefNormal rexW [| 0x85uy |] b s d r
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let ucomiss wordSz ins =
  sseRegRM wordSz ins prefNormal [| 0x0Fuy; 0x2Euy |] 32<rt>

let vaddpd (wordSz: WordSize) ins =
  match ins.Operands with
  | ThreeOperands(OprReg r1, OprReg r2, OprReg r3)
    when isXMMReg r1 && isXMMReg r2 && isXMMReg r3 ->
    encVexRRR wordSz (Some r2) vex128n66n0F [| 0x58uy |] r1 r3
  | ThreeOperands(OprReg r1, OprReg r2, OprReg r3)
    when isYMMReg r1 && isYMMReg r2 && isYMMReg r3 ->
    encVexRRR wordSz (Some r2) vex256n66n0F [| 0x58uy |] r1 r3
  | ThreeOperands(OprReg r1, OprReg r2, OprMem(b, s, d, 128<rt>))
    when isXMMReg r1 && isXMMReg r2 ->
    encVexRRM wordSz (Some r2) vex128n66n0F [| 0x58uy |] r1 b s d
  | ThreeOperands(OprReg r1, OprReg r2, OprMem(b, s, d, 256<rt>))
    when isYMMReg r1 && isYMMReg r2 ->
    encVexRRM wordSz (Some r2) vex256n66n0F [| 0x58uy |] r1 b s d
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let vaddps (wordSz: WordSize) ins =
  match ins.Operands with
  | ThreeOperands(OprReg r1, OprReg r2, OprReg r3)
    when isXMMReg r1 && isXMMReg r2 && isXMMReg r3 ->
    encVexRRR wordSz (Some r2) vex128n0F [| 0x58uy |] r1 r3
  | ThreeOperands(OprReg r1, OprReg r2, OprReg r3)
    when isYMMReg r1 && isYMMReg r2 && isYMMReg r3 ->
    encVexRRR wordSz (Some r2) vex256n0F [| 0x58uy |] r1 r3
  | ThreeOperands(OprReg r1, OprReg r2, OprMem(b, s, d, 128<rt>))
    when isXMMReg r1 && isXMMReg r2 ->
    encVexRRM wordSz (Some r2) vex128n0F [| 0x58uy |] r1 b s d
  | ThreeOperands(OprReg r1, OprReg r2, OprMem(b, s, d, 256<rt>))
    when isYMMReg r1 && isYMMReg r2 ->
    encVexRRM wordSz (Some r2) vex256n0F [| 0x58uy |] r1 b s d
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let vaddsd (wordSz: WordSize) ins =
  match ins.Operands with
  | ThreeOperands(OprReg r1, OprReg r2, OprReg r3)
    when isXMMReg r1 && isXMMReg r2 && isXMMReg r3 ->
    encVexRRR wordSz (Some r2) vex128nF2n0F [| 0x58uy |] r1 r3
  | ThreeOperands(OprReg r1, OprReg r2, OprMem(b, s, d, 64<rt>))
    when isXMMReg r1 && isXMMReg r2 ->
    encVexRRM wordSz (Some r2) vex128nF2n0F [| 0x58uy |] r1 b s d
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let vaddss (wordSz: WordSize) ins =
  match ins.Operands with
  | ThreeOperands(OprReg r1, OprReg r2, OprReg r3)
    when isXMMReg r1 && isXMMReg r2 && isXMMReg r3 ->
    encVexRRR wordSz (Some r2) vex128nF3n0F [| 0x58uy |] r1 r3
  | ThreeOperands(OprReg r1, OprReg r2, OprMem(b, s, d, 32<rt>))
    when isXMMReg r1 && isXMMReg r2 ->
    encVexRRM wordSz (Some r2) vex128nF3n0F [| 0x58uy |] r1 b s d
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let vpalignr (wordSz: WordSize) ins =
  match ins.Operands with
  (* Reg - Reg - Reg - Imm8 *)
  | FourOperands(OprReg r1, OprReg r2, OprReg r3, OprImm(imm, _))
    when isXMMReg r1 && isXMMReg r2 && isXMMReg r3 ->
    encVexRRRI wordSz
      (Some r2) vex128n66n0F3A [| 0x0Fuy |] r1 r3 imm 8<rt>
  | FourOperands(OprReg r1, OprReg r2, OprReg r3, OprImm(imm, _))
    when isYMMReg r1 && isYMMReg r2 && isYMMReg r3 ->
    encVexRRRI wordSz
      (Some r2) vex256n66n0F3A [| 0x0Fuy |] r1 r3 imm 8<rt>
  (* Reg - Reg - Mem - Imm8 *)
  | FourOperands(OprReg r1, OprReg r2, OprMem(b, s, d, 128<rt>), OprImm(imm, _))
    when isXMMReg r1 && isXMMReg r2 ->
    encVexRRMI wordSz
      (Some r2) vex128n66n0F3A [| 0x0Fuy |] r1 b s d imm 8<rt>
  | FourOperands(OprReg r1, OprReg r2, OprMem(b, s, d, 256<rt>), OprImm(imm, _))
    when isYMMReg r1 && isYMMReg r2 ->
    encVexRRMI wordSz
      (Some r2) vex256n66n0F3A [| 0x0Fuy |] r1 b s d imm 8<rt>
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let xchg (wordSz: WordSize) ins =
  match ins.Operands with
  | TwoOperands(OprReg Register.AX, OprReg r)
  | TwoOperands(OprReg r, OprReg Register.AX) when isReg16 wordSz r ->
    encO ins wordSz pref66 rexNormal 0x90uy r
  | TwoOperands(OprReg Register.EAX, OprReg r)
  | TwoOperands(OprReg r, OprReg Register.EAX) when isReg32 wordSz r ->
    encO ins wordSz prefNormal rexNormal 0x90uy r
  | TwoOperands(OprReg Register.RAX, OprReg r)
  | TwoOperands(OprReg r, OprReg Register.RAX) when isReg64 wordSz r ->
    no32Arch wordSz
    encO ins wordSz prefNormal rexW 0x90uy r
  (* Every other pair takes the ModRM form. The first operand goes in ModRM.rm
     and the second in ModRM.reg, which is the other way round from how encRR
     reads its arguments. *)
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg8 wordSz r1 && isReg8 wordSz r2 ->
    encRR ins wordSz prefNormal rexMR [| 0x86uy |] r2 r1
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg16 wordSz r1 && isReg16 wordSz r2 ->
    encRR ins wordSz pref66 rexMR [| 0x87uy |] r2 r1
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg32 wordSz r1 && isReg32 wordSz r2 ->
    encRR ins wordSz prefNormal rexMR [| 0x87uy |] r2 r1
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg64 wordSz r1 && isReg64 wordSz r2 ->
    no32Arch wordSz
    encRR ins wordSz prefNormal rexWAndMR [| 0x87uy |] r2 r1
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprReg r)
  | TwoOperands(OprReg r, OprMem(b, s, d, 8<rt>)) when isReg8 wordSz r ->
    encMR ins wordSz prefNormal rexNormal [| 0x86uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprReg r)
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg16 wordSz r ->
    encMR ins wordSz pref66 rexNormal [| 0x87uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprReg r)
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg32 wordSz r ->
    encMR ins wordSz prefNormal rexNormal [| 0x87uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprReg r)
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isReg64 wordSz r ->
    no32Arch wordSz
    encMR ins wordSz prefNormal rexW [| 0x87uy |] b s d r
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let xor wordSz ins = arithmetic wordSz ins 0x30uy 0b110uy

let xorps wordSz ins =
  sseRegRM wordSz ins prefNormal [| 0x0Fuy; 0x57uy |] 128<rt>

/// Builds an encoder for a packed instruction that comes in both an MMX and an
/// SSE form, from the third byte of its 0F 38 opcode.
let private mmxSse38 op wordSz ins =
  mmxOrSseRegRM wordSz ins [| 0x0Fuy; 0x38uy; op |] 64<rt>

/// Builds an encoder for an SSE-only 0F 38 instruction, given the mandatory
/// prefix it carries and the width of its memory operand.
let private sse38 pref memSz op wordSz ins =
  sseRegRM wordSz ins pref [| 0x0Fuy; 0x38uy; op |] memSz

/// Builds an encoder for a variable-blend instruction. These name XMM0 as a
/// third operand, which the encoding leaves implicit: it selects nothing in the
/// ModRM byte and only has to be accepted and dropped.
let private blend38 op wordSz ins =
  match ins.Operands with
  | ThreeOperands(o1, o2, OprReg Register.XMM0) ->
    let ins = { ins with Operands = TwoOperands(o1, o2) }
    sseRegRM wordSz ins pref66 [| 0x0Fuy; 0x38uy; op |] 128<rt>
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// The SSSE3, SSE4, SHA and AES instructions in the 0F 38 opcode map.
/// Every one of them encodes through a shared register-or-memory path,
/// so the whole map is a table of which path and which opcode byte
/// rather than one function apiece.
let threeByte38Encoders () =
  [ Opcode.PSHUFB, mmxSse38 0x00uy
    Opcode.PHADDW, mmxSse38 0x01uy
    Opcode.PHADDD, mmxSse38 0x02uy
    Opcode.PHADDSW, mmxSse38 0x03uy
    Opcode.PMADDUBSW, mmxSse38 0x04uy
    Opcode.PHSUBW, mmxSse38 0x05uy
    Opcode.PHSUBD, mmxSse38 0x06uy
    Opcode.PHSUBSW, mmxSse38 0x07uy
    Opcode.PSIGNB, mmxSse38 0x08uy
    Opcode.PSIGNW, mmxSse38 0x09uy
    Opcode.PSIGND, mmxSse38 0x0Auy
    Opcode.PMULHRSW, mmxSse38 0x0Buy
    Opcode.PBLENDVB, blend38 0x10uy
    Opcode.BLENDVPS, blend38 0x14uy
    Opcode.BLENDVPD, blend38 0x15uy
    Opcode.PTEST, sse38 pref66 128<rt> 0x17uy
    Opcode.PABSB, mmxSse38 0x1Cuy
    Opcode.PABSW, mmxSse38 0x1Duy
    Opcode.PABSD, mmxSse38 0x1Euy
    Opcode.PMOVSXBW, sse38 pref66 64<rt> 0x20uy
    Opcode.PMOVSXBD, sse38 pref66 32<rt> 0x21uy
    Opcode.PMOVSXBQ, sse38 pref66 16<rt> 0x22uy
    Opcode.PMOVSXWD, sse38 pref66 64<rt> 0x23uy
    Opcode.PMOVSXWQ, sse38 pref66 32<rt> 0x24uy
    Opcode.PMOVSXDQ, sse38 pref66 64<rt> 0x25uy
    Opcode.PMULDQ, sse38 pref66 128<rt> 0x28uy
    Opcode.PCMPEQQ, sse38 pref66 128<rt> 0x29uy
    Opcode.MOVNTDQA, sse38 pref66 128<rt> 0x2Auy
    Opcode.PACKUSDW, sse38 pref66 128<rt> 0x2Buy
    Opcode.PMOVZXBW, sse38 pref66 64<rt> 0x30uy
    Opcode.PMOVZXBD, sse38 pref66 32<rt> 0x31uy
    Opcode.PMOVZXBQ, sse38 pref66 16<rt> 0x32uy
    Opcode.PMOVZXWD, sse38 pref66 64<rt> 0x33uy
    Opcode.PMOVZXWQ, sse38 pref66 32<rt> 0x34uy
    Opcode.PMOVZXDQ, sse38 pref66 64<rt> 0x35uy
    Opcode.PCMPGTQ, sse38 pref66 128<rt> 0x37uy
    Opcode.PMINSB, sse38 pref66 128<rt> 0x38uy
    Opcode.PMINSD, sse38 pref66 128<rt> 0x39uy
    Opcode.PMINUW, sse38 pref66 128<rt> 0x3Auy
    Opcode.PMINUD, sse38 pref66 128<rt> 0x3Buy
    Opcode.PMAXSB, sse38 pref66 128<rt> 0x3Cuy
    Opcode.PMAXSD, sse38 pref66 128<rt> 0x3Duy
    Opcode.PMAXUW, sse38 pref66 128<rt> 0x3Euy
    Opcode.PMAXUD, sse38 pref66 128<rt> 0x3Fuy
    Opcode.PMULLD, sse38 pref66 128<rt> 0x40uy
    Opcode.PHMINPOSUW, sse38 pref66 128<rt> 0x41uy
    Opcode.SHA1NEXTE, sse38 prefNormal 128<rt> 0xC8uy
    Opcode.SHA1MSG1, sse38 prefNormal 128<rt> 0xC9uy
    Opcode.SHA1MSG2, sse38 prefNormal 128<rt> 0xCAuy
    Opcode.SHA256RNDS2, sse38 prefNormal 128<rt> 0xCBuy
    Opcode.SHA256MSG1, sse38 prefNormal 128<rt> 0xCCuy
    Opcode.SHA256MSG2, sse38 prefNormal 128<rt> 0xCDuy
    Opcode.AESIMC, sse38 pref66 128<rt> 0xDBuy
    Opcode.AESENC, sse38 pref66 128<rt> 0xDCuy
    Opcode.AESENCLAST, sse38 pref66 128<rt> 0xDDuy
    Opcode.AESDEC, sse38 pref66 128<rt> 0xDEuy
    Opcode.AESDECLAST, sse38 pref66 128<rt> 0xDFuy ]

/// Builds an encoder for a 0F 3A instruction whose last operand is an
/// immediate and whose destination is an XMM register. The source is either a
/// register - XMM for most of them, a general register for the inserts - or
/// memory of the given width.
let private sse3A rex memSz op wordSz ins =
  match ins.Operands with
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _)) when isXMMReg r1 ->
    encRRI ins wordSz pref66 rex [| 0x0Fuy; 0x3Auy; op |] r1 r2 imm 8<rt>
  | ThreeOperands(OprReg r, OprMem(b, s, d, sz), OprImm(imm, _))
    when isXMMReg r && sz = memSz ->
    encRMI ins wordSz pref66 rex [| 0x0Fuy; 0x3Auy; op |] r b s d imm 8<rt>
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// Builds an encoder for one of the extract instructions. These name their
/// destination first even though it goes in ModRM.rm, so the register pair
/// reaches encRRI the other way round. The quad forms share their opcode byte
/// with the double forms and are told apart by REX.W alone.
let private extract3A quad memSz op wordSz ins =
  let rexRR = if quad then rexWAndMR else rexMR
  let rexRM = if quad then rexW else rexNormal
  match ins.Operands with
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _)) when isXMMReg r2 ->
    encRRI ins wordSz pref66 rexRR [| 0x0Fuy; 0x3Auy; op |] r2 r1 imm 8<rt>
  | ThreeOperands(OprMem(b, s, d, sz), OprReg r, OprImm(imm, _))
    when isXMMReg r && sz = memSz ->
    encMRI ins wordSz pref66 rexRM [| 0x0Fuy; 0x3Auy; op |] b s d r imm 8<rt>
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// SHA1RNDS4 is the one instruction in the 0F 3A map with no mandatory prefix.
let private sha1rnds4 wordSz ins =
  match ins.Operands with
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _)) ->
    encRRI ins wordSz prefNormal rexNormal
      [| 0x0Fuy; 0x3Auy; 0xCCuy |] r1 r2 imm 8<rt>
  | ThreeOperands(OprReg r, OprMem(b, s, d, 128<rt>), OprImm(imm, _)) ->
    encRMI ins wordSz prefNormal rexNormal
      [| 0x0Fuy; 0x3Auy; 0xCCuy |] r b s d imm 8<rt>
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// The SSE4 and crypto instructions in the 0F 3A opcode map, which all take an
/// immediate as their last operand.
let threeByte3AEncoders () =
  [ Opcode.ROUNDPS, sse3A rexNormal 128<rt> 0x08uy
    Opcode.ROUNDPD, sse3A rexNormal 128<rt> 0x09uy
    Opcode.ROUNDSS, sse3A rexNormal 32<rt> 0x0Auy
    Opcode.ROUNDSD, sse3A rexNormal 64<rt> 0x0Buy
    Opcode.BLENDPS, sse3A rexNormal 128<rt> 0x0Cuy
    Opcode.BLENDPD, sse3A rexNormal 128<rt> 0x0Duy
    Opcode.PBLENDW, sse3A rexNormal 128<rt> 0x0Euy
    Opcode.PEXTRB, extract3A false 8<rt> 0x14uy
    Opcode.PEXTRD, extract3A false 32<rt> 0x16uy
    Opcode.PEXTRQ, extract3A true 64<rt> 0x16uy
    Opcode.EXTRACTPS, extract3A false 32<rt> 0x17uy
    Opcode.PINSRB, sse3A rexNormal 8<rt> 0x20uy
    Opcode.INSERTPS, sse3A rexNormal 32<rt> 0x21uy
    Opcode.PINSRD, sse3A rexNormal 32<rt> 0x22uy
    Opcode.PINSRQ, sse3A rexW 64<rt> 0x22uy
    Opcode.DPPS, sse3A rexNormal 128<rt> 0x40uy
    Opcode.DPPD, sse3A rexNormal 128<rt> 0x41uy
    Opcode.MPSADBW, sse3A rexNormal 128<rt> 0x42uy
    Opcode.PCLMULQDQ, sse3A rexNormal 128<rt> 0x44uy
    Opcode.PCMPESTRM, sse3A rexNormal 128<rt> 0x60uy
    Opcode.PCMPESTRI, sse3A rexNormal 128<rt> 0x61uy
    Opcode.PCMPISTRM, sse3A rexNormal 128<rt> 0x62uy
    Opcode.PCMPISTRI, sse3A rexNormal 128<rt> 0x63uy
    Opcode.SHA1RNDS4, sha1rnds4
    Opcode.AESKEYGENASSIST, sse3A rexNormal 128<rt> 0xDFuy ]

/// Builds an encoder for a packed instruction in the 0F map that comes in both
/// an MMX and an SSE form, from the width of the MMX memory operand and the
/// second byte of the opcode.
let private mmxSse mmxMemSz op wordSz ins =
  mmxOrSseRegRM wordSz ins [| 0x0Fuy; op |] mmxMemSz

/// Builds an encoder for an SSE-only instruction in the 0F map, given the
/// mandatory prefix it carries and the width of its memory operand.
let private sse2 pref memSz op wordSz ins =
  sseRegRM wordSz ins pref [| 0x0Fuy; op |] memSz

/// Builds an encoder for a packed shift, which counts either by an immediate or
/// by a value held in a register or memory. The two forms sit at different
/// opcode bytes, and the immediate one names which shift it is in the ModRM.reg
/// digit rather than in the opcode byte.
let private packedShift immOp digit rmOp wordSz ins =
  match ins.Operands with
  | TwoOperands(OprReg r, OprImm(imm, _)) when isMMXReg r ->
    encRI ins wordSz prefNormal rexNormal [| 0x0Fuy; immOp |] r digit imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isXMMReg r ->
    encRI ins wordSz pref66 rexNormal [| 0x0Fuy; immOp |] r digit imm 8<rt>
  | _ ->
    mmxOrSseRegRM wordSz ins [| 0x0Fuy; rmOp |] 64<rt>

  /// The MMX and SSE packed integer instructions of the 0F map. Each has
/// an MMX form with no mandatory prefix and an SSE form under 66, which
/// is what mmxSse encodes; they differ only in the opcode byte and in
/// how wide the MMX memory operand is.
let packedIntegerEncoders () =
  [ Opcode.PUNPCKLBW, mmxSse 32<rt> 0x60uy
    Opcode.PUNPCKLWD, mmxSse 32<rt> 0x61uy
    Opcode.PACKSSWB, mmxSse 64<rt> 0x63uy
    Opcode.PCMPGTB, mmxSse 64<rt> 0x64uy
    Opcode.PCMPGTW, mmxSse 64<rt> 0x65uy
    Opcode.PCMPGTD, mmxSse 64<rt> 0x66uy
    Opcode.PACKUSWB, mmxSse 64<rt> 0x67uy
    Opcode.PUNPCKHBW, mmxSse 64<rt> 0x68uy
    Opcode.PUNPCKHWD, mmxSse 64<rt> 0x69uy
    Opcode.PUNPCKHDQ, mmxSse 64<rt> 0x6Auy
    Opcode.PACKSSDW, mmxSse 64<rt> 0x6Buy
    Opcode.PCMPEQB, mmxSse 64<rt> 0x74uy
    Opcode.PCMPEQW, mmxSse 64<rt> 0x75uy
    Opcode.PCMPEQD, mmxSse 64<rt> 0x76uy
    Opcode.PADDQ, mmxSse 64<rt> 0xD4uy
    Opcode.PMULLW, mmxSse 64<rt> 0xD5uy
    Opcode.PSUBUSB, mmxSse 64<rt> 0xD8uy
    Opcode.PSUBUSW, mmxSse 64<rt> 0xD9uy
    Opcode.PMINUB, mmxSse 64<rt> 0xDAuy
    Opcode.PAND, mmxSse 64<rt> 0xDBuy
    Opcode.PADDUSB, mmxSse 64<rt> 0xDCuy
    Opcode.PADDUSW, mmxSse 64<rt> 0xDDuy
    Opcode.PMAXUB, mmxSse 64<rt> 0xDEuy
    Opcode.PANDN, mmxSse 64<rt> 0xDFuy
    Opcode.PAVGB, mmxSse 64<rt> 0xE0uy
    Opcode.PAVGW, mmxSse 64<rt> 0xE3uy
    Opcode.PMULHUW, mmxSse 64<rt> 0xE4uy
    Opcode.PMULHW, mmxSse 64<rt> 0xE5uy
    Opcode.PSUBSB, mmxSse 64<rt> 0xE8uy
    Opcode.PSUBSW, mmxSse 64<rt> 0xE9uy
    Opcode.PMINSW, mmxSse 64<rt> 0xEAuy
    Opcode.POR, mmxSse 64<rt> 0xEBuy
    Opcode.PADDSB, mmxSse 64<rt> 0xECuy
    Opcode.PADDSW, mmxSse 64<rt> 0xEDuy
    Opcode.PMAXSW, mmxSse 64<rt> 0xEEuy
    Opcode.PMULUDQ, mmxSse 64<rt> 0xF4uy
    Opcode.PMADDWD, mmxSse 64<rt> 0xF5uy
    Opcode.PSADBW, mmxSse 64<rt> 0xF6uy
    Opcode.PSUBB, mmxSse 64<rt> 0xF8uy
    Opcode.PSUBW, mmxSse 64<rt> 0xF9uy
    Opcode.PSUBD, mmxSse 64<rt> 0xFAuy
    Opcode.PSUBQ, mmxSse 64<rt> 0xFBuy
    Opcode.PADDB, mmxSse 64<rt> 0xFCuy
    Opcode.PADDW, mmxSse 64<rt> 0xFDuy ]

  /// The SSE instructions of the 0F map that take one register-or-memory
/// source. The mandatory prefix is what picks the mnemonic out of the
/// four sharing each opcode byte.
let sseArithmeticEncoders () =
  [ Opcode.MOVDDUP, sse2 prefF2 64<rt> 0x12uy
    Opcode.MOVSLDUP, sse2 prefF3 128<rt> 0x12uy
    Opcode.UNPCKLPD, sse2 pref66 128<rt> 0x14uy
    Opcode.UNPCKLPS, sse2 prefNormal 128<rt> 0x14uy
    Opcode.UNPCKHPD, sse2 pref66 128<rt> 0x15uy
    Opcode.UNPCKHPS, sse2 prefNormal 128<rt> 0x15uy
    Opcode.MOVSHDUP, sse2 prefF3 128<rt> 0x16uy
    Opcode.UCOMISD, sse2 pref66 64<rt> 0x2Euy
    Opcode.COMISD, sse2 pref66 64<rt> 0x2Fuy
    Opcode.COMISS, sse2 prefNormal 32<rt> 0x2Fuy
    Opcode.SQRTPD, sse2 pref66 128<rt> 0x51uy
    Opcode.SQRTPS, sse2 prefNormal 128<rt> 0x51uy
    Opcode.SQRTSD, sse2 prefF2 64<rt> 0x51uy
    Opcode.SQRTSS, sse2 prefF3 32<rt> 0x51uy
    Opcode.RSQRTPS, sse2 prefNormal 128<rt> 0x52uy
    Opcode.RSQRTSS, sse2 prefF3 32<rt> 0x52uy
    Opcode.RCPPS, sse2 prefNormal 128<rt> 0x53uy
    Opcode.RCPSS, sse2 prefF3 32<rt> 0x53uy
    Opcode.ANDNPD, sse2 pref66 128<rt> 0x55uy
    Opcode.ANDNPS, sse2 prefNormal 128<rt> 0x55uy
    Opcode.ORPS, sse2 prefNormal 128<rt> 0x56uy
    Opcode.XORPD, sse2 pref66 128<rt> 0x57uy
    Opcode.MULPD, sse2 pref66 128<rt> 0x59uy
    Opcode.MULPS, sse2 prefNormal 128<rt> 0x59uy
    Opcode.CVTPD2PS, sse2 pref66 128<rt> 0x5Auy
    Opcode.CVTPS2PD, sse2 prefNormal 64<rt> 0x5Auy
    Opcode.CVTSS2SD, sse2 prefF3 32<rt> 0x5Auy
    Opcode.CVTDQ2PS, sse2 prefNormal 128<rt> 0x5Buy
    Opcode.CVTPS2DQ, sse2 pref66 128<rt> 0x5Buy
    Opcode.CVTTPS2DQ, sse2 prefF3 128<rt> 0x5Buy
    Opcode.SUBPD, sse2 pref66 128<rt> 0x5Cuy
    Opcode.SUBPS, sse2 prefNormal 128<rt> 0x5Cuy
    Opcode.MINPD, sse2 pref66 128<rt> 0x5Duy
    Opcode.MINPS, sse2 prefNormal 128<rt> 0x5Duy
    Opcode.MINSD, sse2 prefF2 64<rt> 0x5Duy
    Opcode.MINSS, sse2 prefF3 32<rt> 0x5Duy
    Opcode.DIVPD, sse2 pref66 128<rt> 0x5Euy
    Opcode.DIVPS, sse2 prefNormal 128<rt> 0x5Euy
    Opcode.MAXPD, sse2 pref66 128<rt> 0x5Fuy
    Opcode.MAXPS, sse2 prefNormal 128<rt> 0x5Fuy
    Opcode.MAXSD, sse2 prefF2 64<rt> 0x5Fuy
    Opcode.MAXSS, sse2 prefF3 32<rt> 0x5Fuy
    Opcode.PUNPCKLQDQ, sse2 pref66 128<rt> 0x6Cuy
    Opcode.PUNPCKHQDQ, sse2 pref66 128<rt> 0x6Duy
    Opcode.HADDPD, sse2 pref66 128<rt> 0x7Cuy
    Opcode.HADDPS, sse2 prefF2 128<rt> 0x7Cuy
    Opcode.HSUBPD, sse2 pref66 128<rt> 0x7Duy
    Opcode.HSUBPS, sse2 prefF2 128<rt> 0x7Duy
    Opcode.ADDSUBPD, sse2 pref66 128<rt> 0xD0uy
    Opcode.ADDSUBPS, sse2 prefF2 128<rt> 0xD0uy
    Opcode.CVTDQ2PD, sse2 prefF3 64<rt> 0xE6uy
    Opcode.CVTPD2DQ, sse2 prefF2 128<rt> 0xE6uy
    Opcode.CVTTPD2DQ, sse2 pref66 128<rt> 0xE6uy
    Opcode.LDDQU, sse2 prefF2 128<rt> 0xF0uy
    Opcode.MASKMOVDQU, sse2 pref66 128<rt> 0xF7uy ]

  /// The packed shifts, each of which spans two opcode bytes.
let packedShiftEncoders () =
  [ Opcode.PSLLD, packedShift 0x72uy 0b110uy 0xF2uy
    Opcode.PSLLQ, packedShift 0x73uy 0b110uy 0xF3uy
    Opcode.PSLLW, packedShift 0x71uy 0b110uy 0xF1uy
    Opcode.PSRAD, packedShift 0x72uy 0b100uy 0xE2uy
    Opcode.PSRAW, packedShift 0x71uy 0b100uy 0xE1uy
    Opcode.PSRLD, packedShift 0x72uy 0b010uy 0xD2uy
    Opcode.PSRLQ, packedShift 0x73uy 0b010uy 0xD3uy
    Opcode.PSRLW, packedShift 0x71uy 0b010uy 0xD1uy ]

/// Builds an encoder for one of the SSE moves whose only defined operand form
/// names memory. Their register form is a different instruction - MOVHLPS and
/// MOVLHPS share these opcode bytes - so it must not be accepted here.
let private sseMovMem pref loadOp storeOp memSz wordSz ins =
  match ins.Operands with
  | TwoOperands(OprReg r, OprMem(b, s, d, sz)) when isXMMReg r && sz = memSz ->
    encRM ins wordSz pref rexNormal [| 0x0Fuy; loadOp |] r b s d
  | TwoOperands(OprMem(b, s, d, sz), OprReg r) when isXMMReg r && sz = memSz ->
    encMR ins wordSz pref rexNormal [| 0x0Fuy; storeOp |] b s d r
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// Builds an encoder for an SSE move that only ever names two registers, which
/// is how the ModRM byte tells it apart from the memory form sharing its
/// opcode byte.
let private sseRegOnly op wordSz ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins wordSz prefNormal rexNormal [| 0x0Fuy; op |] r1 r2
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// PSLLDQ and PSRLDQ shift a whole XMM register by a count of bytes. They have
/// no register-counted form, so unlike the other packed shifts they live at one
/// opcode byte and are told apart by the ModRM.reg digit alone.
let private xmmShiftImm digit wordSz ins =
  match ins.Operands with
  | TwoOperands(OprReg r, OprImm(imm, _)) when isXMMReg r ->
    encRI ins wordSz pref66 rexNormal [| 0x0Fuy; 0x73uy |] r digit imm 8<rt>
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// MASKMOVQ names two MMX registers, its SSE counterpart MASKMOVDQU two XMM
/// ones, and they share an opcode byte.
let private maskmovq wordSz ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isMMXReg r1 && isMMXReg r2 ->
    encRR ins wordSz prefNormal rexNormal [| 0x0Fuy; 0xF7uy |] r1 r2
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// The SSE moves that need a shape of their own rather than a table row,
/// because a register operand means a different instruction at the same opcode
/// byte instead of a different addressing mode.
let sseMoveEncoders () =
  [ Opcode.MOVLPS, sseMovMem prefNormal 0x12uy 0x13uy 64<rt>
    Opcode.MOVHPS, sseMovMem prefNormal 0x16uy 0x17uy 64<rt>
    Opcode.MOVLPD, sseMovMem pref66 0x12uy 0x13uy 64<rt>
    Opcode.MOVHPD, sseMovMem pref66 0x16uy 0x17uy 64<rt>
    Opcode.MOVHLPS, sseRegOnly 0x12uy
    Opcode.MOVLHPS, sseRegOnly 0x16uy
    Opcode.PSLLDQ, xmmShiftImm 0b111uy
    Opcode.PSRLDQ, xmmShiftImm 0b011uy
    Opcode.MASKMOVQ, maskmovq ]

/// A single-precision operand puts an x87 instruction at D8 and a double
/// puts it at DC; the integer instructions read a word at DE and a doubleword
/// at DA, which is the reverse of the order one might expect.
let private fCompareForms = [ 32<rt>, 0xD8uy; 64<rt>, 0xDCuy ]

let private fStoreForms = [ 32<rt>, 0xD9uy; 64<rt>, 0xDDuy ]

let private fIntegerForms = [ 16<rt>, 0xDEuy; 32<rt>, 0xDAuy ]

let private fIntegerStoreForms =
  [ 16<rt>, 0xDFuy; 32<rt>, 0xDBuy; 64<rt>, 0xDDuy ]

/// Builds an encoder for an x87 instruction that takes no operand and so is
/// two fixed bytes.
let private x87Fixed b1 b2 _wordSz ins =
  match ins.Operands with
  | NoOperand -> Resolved [| b1; b2 |]
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

/// Builds an encoder for an x87 instruction naming ST0 as its destination and
/// another stack register as its source, which the opcode byte's low three bits
/// carry.
let private x87ToSt0 b1 b2 _wordSz ins =
  match ins.Operands with
  | TwoOperands(OprReg Register.ST0, OprReg r) when isFPUReg r ->
    encFR [| b1; b2 |] r
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// Builds an encoder for an x87 instruction naming ST0 as its source, the other
/// way round from x87ToSt0.
let private x87FromSt0 b1 b2 _wordSz ins =
  match ins.Operands with
  | TwoOperands(OprReg r, OprReg Register.ST0) when isFPUReg r ->
    encFR [| b1; b2 |] r
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// Builds an encoder for an x87 instruction naming one stack register.
let private x87OneSt b1 b2 _wordSz ins =
  match ins.Operands with
  | OneOperand(OprReg r) when isFPUReg r -> encFR [| b1; b2 |] r
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

/// Builds an encoder for an x87 instruction that reads or writes memory. Which
/// opcode byte it uses is decided by how wide the operand is, so the forms are
/// given as pairs of the two. A width of zero stands for the state-saving
/// instructions, whose operand has no width to write down.
let private x87Mem forms digit wordSz ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, sz)) ->
    match List.tryFind (fun (w, _) -> w = sz) forms with
    | Some(_, op) -> encM ins wordSz prefNormal rexNormal [| op |] b s d digit
    | None -> raise <| EncodingFailureException "Unsupported operand type"
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// Builds an encoder for an x87 instruction that names either memory or one
/// stack register, the two forms sharing nothing but the mnemonic.
let private x87MemOrSt forms digit b1 b2 wordSz ins =
  match ins.Operands with
  | OneOperand(OprReg r) when isFPUReg r -> encFR [| b1; b2 |] r
  | _ -> x87Mem forms digit wordSz ins

/// FDIVR divides the other way round from FDIV, which swaps the two register
/// forms but leaves everything else in place.
let private fdivr wordSz ins = x87Arith wordSz ins 0b111uy 0xF8uy 0xF0uy

/// FNSTSW is the one x87 store that can name a general register instead of
/// memory, and then it is a fixed encoding.
let private fnstsw wordSz ins =
  match ins.Operands with
  | OneOperand(OprReg Register.AX) -> Resolved [| 0xDFuy; 0xE0uy |]
  | _ -> x87Mem [ 16<rt>, 0xDDuy ] 0b111uy wordSz ins

/// The x87 instructions beyond the five arithmetic ones, which between them use
/// every shape the stack offers: no operand at all, one or two stack registers,
/// and memory in widths from a word to the whole FPU state.
let x87Encoders () =
  [ Opcode.FABS, x87Fixed 0xD9uy 0xE1uy
    Opcode.FCOMPP, x87Fixed 0xDEuy 0xD9uy
    Opcode.FUCOMPP, x87Fixed 0xDAuy 0xE9uy
    Opcode.FLDL2T, x87Fixed 0xD9uy 0xE9uy
    Opcode.FYL2X, x87Fixed 0xD9uy 0xF1uy
    Opcode.FYL2XP1, x87Fixed 0xD9uy 0xF9uy
    Opcode.FADDP, x87FromSt0 0xDEuy 0xC0uy
    Opcode.FSUBP, x87FromSt0 0xDEuy 0xE8uy
    Opcode.FSUBRP, x87FromSt0 0xDEuy 0xE0uy
    Opcode.FCMOVE, x87ToSt0 0xDAuy 0xC8uy
    Opcode.FCMOVBE, x87ToSt0 0xDAuy 0xD0uy
    Opcode.FCMOVU, x87ToSt0 0xDAuy 0xD8uy
    Opcode.FCMOVNB, x87ToSt0 0xDBuy 0xC0uy
    Opcode.FCMOVNE, x87ToSt0 0xDBuy 0xC8uy
    Opcode.FCMOVNBE, x87ToSt0 0xDBuy 0xD0uy
    Opcode.FCMOVNU, x87ToSt0 0xDBuy 0xD8uy
    Opcode.FCOMI, x87ToSt0 0xDBuy 0xF0uy
    Opcode.FCOMIP, x87ToSt0 0xDFuy 0xF0uy
    Opcode.FFREE, x87OneSt 0xDDuy 0xC0uy
    Opcode.FFREEP, x87OneSt 0xDFuy 0xC0uy
    Opcode.FUCOM, x87OneSt 0xDDuy 0xE0uy
    Opcode.FUCOMP, x87OneSt 0xDDuy 0xE8uy
    Opcode.FCOM, x87MemOrSt fCompareForms 0b010uy 0xD8uy 0xD0uy
    Opcode.FCOMP, x87MemOrSt fCompareForms 0b011uy 0xD8uy 0xD8uy
    Opcode.FST, x87MemOrSt fStoreForms 0b010uy 0xDDuy 0xD0uy
    Opcode.FIADD, x87Mem fIntegerForms 0b000uy
    Opcode.FIMUL, x87Mem fIntegerForms 0b001uy
    Opcode.FICOM, x87Mem fIntegerForms 0b010uy
    Opcode.FICOMP, x87Mem fIntegerForms 0b011uy
    Opcode.FISUB, x87Mem fIntegerForms 0b100uy
    Opcode.FISUBR, x87Mem fIntegerForms 0b101uy
    Opcode.FIDIV, x87Mem fIntegerForms 0b110uy
    Opcode.FIDIVR, x87Mem fIntegerForms 0b111uy
    Opcode.FIST, x87Mem [ 16<rt>, 0xDFuy; 32<rt>, 0xDBuy ] 0b010uy
    Opcode.FISTTP, x87Mem fIntegerStoreForms 0b001uy
    Opcode.FBLD, x87Mem [ 80<rt>, 0xDFuy ] 0b100uy
    Opcode.FBSTP, x87Mem [ 80<rt>, 0xDFuy ] 0b110uy
    Opcode.FLDENV, x87Mem [ 0<rt>, 0xD9uy ] 0b100uy
    Opcode.FNSTENV, x87Mem [ 0<rt>, 0xD9uy ] 0b110uy
    Opcode.FRSTOR, x87Mem [ 0<rt>, 0xDDuy ] 0b100uy
    Opcode.FNSAVE, x87Mem [ 0<rt>, 0xDDuy ] 0b110uy
    Opcode.FDIVR, fdivr
    Opcode.FNSTSW, fnstsw ]

/// Builds an encoder for an instruction whose entire encoding is fixed: it
/// takes no operand, so there is no ModRM byte and nothing to compute.
let private fixedBytes bytes (_: WordSize) ins =
  match ins.Operands with
  | NoOperand -> Resolved bytes
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

/// Every instruction whose whole encoding is fixed, which is most of the
/// legacy flag, cache and string operations.
let noOperandEncoders () =
  [ Opcode.CLC, fixedBytes [| 0xF8uy |]
    Opcode.CLD, fixedBytes [| 0xFCuy |]
    Opcode.CLI, fixedBytes [| 0xFAuy |]
    Opcode.CLTS, fixedBytes [| 0x0Fuy; 0x06uy |]
    Opcode.CMC, fixedBytes [| 0xF5uy |]
    Opcode.CMPSQ, fixedBytes [| 0x48uy; 0xA7uy |]
    Opcode.CMPSW, fixedBytes [| 0x66uy; 0xA7uy |]
    Opcode.CPUID, fixedBytes [| 0x0Fuy; 0xA2uy |]
    Opcode.CQO, fixedBytes [| 0x48uy; 0x99uy |]
    Opcode.CWD, fixedBytes [| 0x66uy; 0x99uy |]
    Opcode.DAA, fixedBytes [| 0x27uy |]
    Opcode.DAS, fixedBytes [| 0x2Fuy |]
    Opcode.EMMS, fixedBytes [| 0x0Fuy; 0x77uy |]
    Opcode.GETSEC, fixedBytes [| 0x0Fuy; 0x37uy |]
    Opcode.INSB, fixedBytes [| 0x6Cuy |]
    Opcode.INSD, fixedBytes [| 0x6Duy |]
    Opcode.INSW, fixedBytes [| 0x66uy; 0x6Duy |]
    Opcode.INT1, fixedBytes [| 0xF1uy |]
    Opcode.INTO, fixedBytes [| 0xCEuy |]
    Opcode.INVD, fixedBytes [| 0x0Fuy; 0x08uy |]
    Opcode.IRETD, fixedBytes [| 0xCFuy |]
    Opcode.IRETQ, fixedBytes [| 0x48uy; 0xCFuy |]
    Opcode.IRETW, fixedBytes [| 0x66uy; 0xCFuy |]
    Opcode.LFENCE, fixedBytes [| 0x0Fuy; 0xAEuy; 0xE8uy |]
    Opcode.LODSB, fixedBytes [| 0xACuy |]
    Opcode.LODSD, fixedBytes [| 0xADuy |]
    Opcode.LODSQ, fixedBytes [| 0x48uy; 0xADuy |]
    Opcode.LODSW, fixedBytes [| 0x66uy; 0xADuy |]
    Opcode.MFENCE, fixedBytes [| 0x0Fuy; 0xAEuy; 0xF0uy |]
    Opcode.MOVSB, fixedBytes [| 0xA4uy |]
    Opcode.MOVSQ, fixedBytes [| 0x48uy; 0xA5uy |]
    Opcode.MOVSW, fixedBytes [| 0x66uy; 0xA5uy |]
    Opcode.MWAIT, fixedBytes [| 0x0Fuy; 0x01uy; 0xC9uy |]
    Opcode.OUTSB, fixedBytes [| 0x6Euy |]
    Opcode.OUTSD, fixedBytes [| 0x6Fuy |]
    Opcode.OUTSW, fixedBytes [| 0x66uy; 0x6Fuy |]
    Opcode.POPA, fixedBytes [| 0x66uy; 0x61uy |]
    Opcode.POPAD, fixedBytes [| 0x61uy |]
    Opcode.POPF, fixedBytes [| 0x66uy; 0x9Duy |]
    Opcode.POPFD, fixedBytes [| 0x9Duy |]
    Opcode.POPFQ, fixedBytes [| 0x9Duy |]
    Opcode.PUSHA, fixedBytes [| 0x66uy; 0x60uy |]
    Opcode.PUSHAD, fixedBytes [| 0x60uy |]
    Opcode.PUSHF, fixedBytes [| 0x66uy; 0x9Cuy |]
    Opcode.PUSHFD, fixedBytes [| 0x9Cuy |]
    Opcode.PUSHFQ, fixedBytes [| 0x9Cuy |]
    Opcode.RDMSR, fixedBytes [| 0x0Fuy; 0x32uy |]
    Opcode.RDPMC, fixedBytes [| 0x0Fuy; 0x33uy |]
    Opcode.RDTSC, fixedBytes [| 0x0Fuy; 0x31uy |]
    Opcode.RDTSCP, fixedBytes [| 0x0Fuy; 0x01uy; 0xF9uy |]
    Opcode.RSM, fixedBytes [| 0x0Fuy; 0xAAuy |]
    Opcode.SFENCE, fixedBytes [| 0x0Fuy; 0xAEuy; 0xF8uy |]
    Opcode.STC, fixedBytes [| 0xF9uy |]
    Opcode.STD, fixedBytes [| 0xFDuy |]
    Opcode.STI, fixedBytes [| 0xFBuy |]
    Opcode.SYSENTER, fixedBytes [| 0x0Fuy; 0x34uy |]
    Opcode.SYSEXIT, fixedBytes [| 0x0Fuy; 0x35uy |]
    Opcode.SYSRET, fixedBytes [| 0x0Fuy; 0x07uy |]
    Opcode.UD2, fixedBytes [| 0x0Fuy; 0x0Buy |]
    Opcode.VMCALL, fixedBytes [| 0x0Fuy; 0x01uy; 0xC1uy |]
    Opcode.WAIT, fixedBytes [| 0x9Buy |]
    Opcode.WBINVD, fixedBytes [| 0x0Fuy; 0x09uy |]
    Opcode.WRMSR, fixedBytes [| 0x0Fuy; 0x30uy |]
    Opcode.XLATB, fixedBytes [| 0xD7uy |]
    Opcode.XSETBV, fixedBytes [| 0x0Fuy; 0x01uy; 0xD1uy |] ]

/// The prefix and REX a memory operand of the given general-purpose width
/// needs, for the instructions whose other operand is an immediate and so says
/// nothing about the width.
let private gprMemForm wordSz sz =
  if sz = 16<rt> then
    Some(pref66, rexNormal)
  elif sz = 32<rt> then
    Some(prefNormal, rexNormal)
  elif sz = 64<rt> then
    no32Arch wordSz
    Some(prefNormal, rexW)
  else
    None

/// What a general-purpose operand of a given width needs: the width itself, the
/// operand-size prefix, and the REX for each of the two argument orders. A
/// register with no general-purpose width - control, debug or segment - has no
/// form at all, which is how it reaches the "unsupported operand" case.
let private gprForm wordSz r =
  if isReg16 wordSz r then
    Some(16<rt>, pref66, rexNormal, rexMR)
  elif isReg32 wordSz r then
    Some(32<rt>, prefNormal, rexNormal, rexMR)
  elif isReg64 wordSz r then
    (* Without this, a 64-bit register named in 32-bit mode would take the
       64-bit path and then lose its REX byte, which encodeREXPref does not
       emit there: the instruction would come out as the 32-bit one. *)
    no32Arch wordSz
    Some(64<rt>, prefNormal, rexW, rexWAndMR)
  else
    None

/// Builds an encoder for a two-operand instruction reading a general register
/// or memory into a general register. The widths differ in nothing but the
/// operand-size prefix and REX.W.
let private gprRegRM op wordSz ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) ->
    match gprForm wordSz r1 with
    | Some(_, pref, rex, _) -> encRR ins wordSz pref rex op r1 r2
    | None -> raise <| EncodingFailureException "Unsupported operand type"
  | TwoOperands(OprReg r, OprMem(b, s, d, sz)) ->
    match gprForm wordSz r with
    | Some(w, pref, rex, _) when w = sz -> encRM ins wordSz pref rex op r b s d
    | _ -> raise <| EncodingFailureException "Unsupported operand type"
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// Builds an encoder for the bit-counting instructions, which carry F3 as a
/// mandatory prefix and so have no 16-bit form to encode: the operand-size
/// prefix would have to sit alongside a prefix that already means something.
let private gprRegRMRep op wordSz ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isReg32 wordSz r1 ->
    encRR ins wordSz prefF3 rexNormal op r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isReg64 wordSz r1 ->
    no32Arch wordSz
    encRR ins wordSz prefF3 rexW op r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg32 wordSz r ->
    encRM ins wordSz prefF3 rexNormal op r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isReg64 wordSz r ->
    no32Arch wordSz
    encRM ins wordSz prefF3 rexW op r b s d
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// Builds an encoder for a two-operand instruction written the other way round,
/// with its destination in ModRM.rm and the register it reads in ModRM.reg.
let private gprRMReg op wordSz ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) ->
    match gprForm wordSz r1 with
    | Some(_, pref, _, rex) -> encRR ins wordSz pref rex op r2 r1
    | None -> raise <| EncodingFailureException "Unsupported operand type"
  | TwoOperands(OprMem(b, s, d, sz), OprReg r) ->
    match gprForm wordSz r with
    | Some(w, pref, rex, _) when w = sz -> encMR ins wordSz pref rex op b s d r
    | _ -> raise <| EncodingFailureException "Unsupported operand type"
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// Builds an encoder for a two-operand instruction naming a general register or
/// memory and an immediate byte, picked out of a group by the ModRM.reg digit.
let private gprRMImm op digit wordSz ins =
  match ins.Operands with
  | TwoOperands(OprReg r, OprImm(imm, _)) ->
    match gprForm wordSz r with
    | Some(_, pref, rex, _) -> encRI ins wordSz pref rex op r digit imm 8<rt>
    | None -> raise <| EncodingFailureException "Unsupported operand type"
  | TwoOperands(OprMem(b, s, d, sz), OprImm(imm, _)) ->
    match gprMemForm wordSz sz with
    | Some(pref, rex) -> encMI ins wordSz pref rex op b s d digit imm 8<rt>
    | None -> raise <| EncodingFailureException "Unsupported operand type"
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// Builds an encoder for one of the bit-test instructions. Naming the bit in a
/// register gives each of them an opcode byte of its own; naming it as an
/// immediate puts all four at 0F BA, told apart by the ModRM.reg digit.
let private bitTest regOp digit wordSz ins =
  match ins.Operands with
  | TwoOperands(_, OprImm _) -> gprRMImm [| 0x0Fuy; 0xBAuy |] digit wordSz ins
  | _ -> gprRMReg [| 0x0Fuy; regOp |] wordSz ins

/// XADD's byte-wide form has an opcode byte of its own, one below the byte the
/// other widths share, as the arithmetic instructions do.
let private xadd wordSz ins =
  match ins.Operands with
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprReg r) when isReg8 wordSz r ->
    encMR ins wordSz prefNormal rexNormal [| 0x0Fuy; 0xC0uy |] b s d r
  | TwoOperands(OprReg r1, OprReg r2) when isReg8 wordSz r1 ->
    encRR ins wordSz prefNormal rexMR [| 0x0Fuy; 0xC0uy |] r2 r1
  | _ ->
    gprRMReg [| 0x0Fuy; 0xC1uy |] wordSz ins

/// BSWAP carries its register in the low three bits of the second opcode byte
/// rather than in a ModRM byte.
let private bswap wordSz ins =
  match ins.Operands with
  | OneOperand(OprReg r) ->
    match gprForm wordSz r with
    | Some(_, pref, rex, _) ->
      let op = [| 0x0Fuy; 0xC8uy + regTo3Bit r |]
      Resolved(prxRexOp ins wordSz pref rex op)
    | None ->
      raise <| EncodingFailureException "Unsupported operand type"
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// MOVNTI only ever stores, so unlike the rest of this family it has no
/// register destination to encode.
let private movnti wordSz ins =
  match ins.Operands with
  | TwoOperands(OprMem(b, s, d, sz), OprReg r) when sz <> 16<rt> ->
    gprRMReg [| 0x0Fuy; 0xC3uy |] wordSz ins
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// Builds an encoder for a double shift, which names a destination, a source
/// and a count. The destination goes in ModRM.rm and the source in ModRM.reg,
/// the other way round from how encRR reads its arguments, and the count being
/// an immediate rather than CL changes the opcode byte.
let private doubleShift immOp clOp wordSz ins =
  match ins.Operands with
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _)) ->
    match gprForm wordSz r1 with
    | Some(_, pref, _, rex) ->
      encRRI ins wordSz pref rex [| 0x0Fuy; immOp |] r2 r1 imm 8<rt>
    | None ->
      raise <| EncodingFailureException "Unsupported operand type"
  | ThreeOperands(OprMem(b, s, d, sz), OprReg r, OprImm(imm, _)) ->
    match gprForm wordSz r with
    | Some(w, pref, rex, _) when w = sz ->
      encMRI ins wordSz pref rex [| 0x0Fuy; immOp |] b s d r imm 8<rt>
    | _ ->
      raise <| EncodingFailureException "Unsupported operand type"
  | ThreeOperands(OprReg r1, OprReg r2, OprReg Register.CL) ->
    match gprForm wordSz r1 with
    | Some(_, pref, _, rex) ->
      encRR ins wordSz pref rex [| 0x0Fuy; clOp |] r2 r1
    | None ->
      raise <| EncodingFailureException "Unsupported operand type"
  | ThreeOperands(OprMem(b, s, d, sz), OprReg r, OprReg Register.CL) ->
    match gprForm wordSz r with
    | Some(w, pref, rex, _) when w = sz ->
      encMR ins wordSz pref rex [| 0x0Fuy; clOp |] b s d r
    | _ ->
      raise <| EncodingFailureException "Unsupported operand type"
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// The general-purpose bit and count instructions, which between them use every
/// order the ModRM byte offers but differ in nothing else.
let bitwiseEncoders () =
  [ Opcode.BSF, gprRegRM [| 0x0Fuy; 0xBCuy |]
    Opcode.UD0, gprRegRM [| 0x0Fuy; 0xFFuy |]
    Opcode.UD1, gprRegRM [| 0x0Fuy; 0xB9uy |]
    Opcode.POPCNT, gprRegRMRep [| 0x0Fuy; 0xB8uy |]
    Opcode.TZCNT, gprRegRMRep [| 0x0Fuy; 0xBCuy |]
    Opcode.LZCNT, gprRegRMRep [| 0x0Fuy; 0xBDuy |]
    Opcode.BTS, bitTest 0xABuy 0b101uy
    Opcode.BTR, bitTest 0xB3uy 0b110uy
    Opcode.BTC, bitTest 0xBBuy 0b111uy
    Opcode.XADD, xadd
    Opcode.BSWAP, bswap
    Opcode.MOVNTI, movnti
    Opcode.SHRD, doubleShift 0xACuy 0xADuy
    Opcode.RCR, fun wordSz ins -> rotateOrShift wordSz ins 0b011uy ]

/// Builds an encoder for an SSE instruction in the 0F map whose last operand is
/// an immediate byte, given the mandatory prefix it carries and how wide its
/// memory operand is.
let private sseImm pref memSz op wordSz ins =
  match ins.Operands with
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _)) when isXMMReg r1 ->
    encRRI ins wordSz pref rexNormal [| 0x0Fuy; op |] r1 r2 imm 8<rt>
  | ThreeOperands(OprReg r, OprMem(b, s, d, sz), OprImm(imm, _))
    when isXMMReg r && sz = memSz ->
    encRMI ins wordSz pref rexNormal [| 0x0Fuy; op |] r b s d imm 8<rt>
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// PSHUFW is the MMX member of the shuffle family, and the only one at its
/// opcode byte with no mandatory prefix.
let private pshufw wordSz ins =
  match ins.Operands with
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _)) when isMMXReg r1 ->
    encRRI ins wordSz prefNormal rexNormal [| 0x0Fuy; 0x70uy |] r1 r2 imm 8<rt>
  | ThreeOperands(OprReg r, OprMem(b, s, d, 64<rt>), OprImm(imm, _))
    when isMMXReg r ->
    encRMI ins wordSz prefNormal rexNormal
      [| 0x0Fuy; 0x70uy |] r b s d imm 8<rt>
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// PINSRW reads a word from a general register or memory into one lane of an
/// MMX or XMM register, the register file deciding the mandatory prefix.
let private pinsrw wordSz ins =
  let prefOf r = if isMMXReg r then prefNormal else pref66
  match ins.Operands with
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _)) ->
    encRRI ins wordSz (prefOf r1) rexNormal
      [| 0x0Fuy; 0xC4uy |] r1 r2 imm 8<rt>
  | ThreeOperands(OprReg r, OprMem(b, s, d, 16<rt>), OprImm(imm, _)) ->
    encRMI ins wordSz (prefOf r) rexNormal
      [| 0x0Fuy; 0xC4uy |] r b s d imm 8<rt>
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// PEXTRW reads one lane out into a general register or, in the SSE4 form, into
/// memory. The two live in different opcode maps, so one encoder has to cover
/// both: 0F C5 takes a register source and leaves a memory ModRM byte reserved,
/// which is why the sweep still leaves that byte alone, while 0F 3A 15 is the
/// form that reaches memory.
let private pextrw wordSz ins =
  match ins.Operands with
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _)) when isMMXReg r2 ->
    encRRI ins wordSz prefNormal rexNormal
      [| 0x0Fuy; 0xC5uy |] r1 r2 imm 8<rt>
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _)) when isXMMReg r2 ->
    encRRI ins wordSz pref66 rexNormal [| 0x0Fuy; 0xC5uy |] r1 r2 imm 8<rt>
  | _ ->
    extract3A false 16<rt> 0x15uy wordSz ins

/// CMPSD names both the string compare, which takes no operand, and the scalar
/// double compare, told apart by whether anything was written down.
let private cmpsd wordSz ins =
  match ins.Operands with
  | NoOperand -> stringOp wordSz ins prefNormal rexNormal 0xA7uy
  | _ -> sseImm prefF2 64<rt> 0xC2uy wordSz ins

/// The SSE instructions of the 0F map that take an immediate byte last. The
/// mandatory prefix is again what picks the mnemonic out of the four sharing an
/// opcode byte.
let sseImmediateEncoders () =
  [ Opcode.CMPPS, sseImm prefNormal 128<rt> 0xC2uy
    Opcode.CMPPD, sseImm pref66 128<rt> 0xC2uy
    Opcode.CMPSS, sseImm prefF3 32<rt> 0xC2uy
    Opcode.CMPSD, cmpsd
    Opcode.SHUFPS, sseImm prefNormal 128<rt> 0xC6uy
    Opcode.SHUFPD, sseImm pref66 128<rt> 0xC6uy
    Opcode.PSHUFHW, sseImm prefF3 128<rt> 0x70uy
    Opcode.PSHUFLW, sseImm prefF2 128<rt> 0x70uy
    Opcode.PSHUFW, pshufw
    Opcode.PINSRW, pinsrw
    Opcode.PEXTRW, pextrw ]

/// Builds an encoder for a group instruction that only names memory, given its
/// opcode bytes, the mandatory prefix and REX.W that pick it out of the group,
/// the ModRM.reg digit that names it, and the widths its operand may have.
let private grpMem op pref rex digit widths wordSz ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, sz)) when List.contains sz widths ->
    encM ins wordSz pref rex op b s d digit
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// Builds an encoder for a group instruction whose memory operand comes in more
/// than one width. The width is not part of the encoding, so what has to match
/// is the operand-size prefix and REX.W that the decoder reads it back from.
let private grpMemSized op digit widths wordSz ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, sz)) when List.contains sz widths ->
    match gprMemForm wordSz sz with
    | Some(pref, rex) -> encM ins wordSz pref rex op b s d digit
    | None -> raise <| EncodingFailureException "Unsupported operand type"
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// Builds an encoder for a group instruction naming a general register, whose
/// width decides the operand-size prefix and REX.W. A mandatory prefix, where
/// there is one, sits alongside: no instruction here needs both, so the two
/// never have to share.
let private grpReg op pref digit widths wordSz ins =
  match ins.Operands with
  | OneOperand(OprReg r) ->
    match gprForm wordSz r with
    | Some(w, wpref, rex, _) when List.contains w widths ->
      encR ins wordSz (pref ||| wpref) rex op r digit
    | _ ->
      raise <| EncodingFailureException "Unsupported operand type"
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// Builds an encoder for a group instruction that names either a register or
/// memory, the two differing in which widths they accept.
let private grpRegMem op digit regWidths memWidths wordSz ins =
  match ins.Operands with
  | OneOperand(OprReg _) -> grpReg op prefNormal digit regWidths wordSz ins
  | _ -> grpMemSized op digit memWidths wordSz ins

/// The widths a descriptor-table or segment-limit operand comes in: a far
/// pointer is 16:32 in 32-bit mode and 16:64 in 64-bit mode, which the
/// disassembler spells "fword ptr" and "tbyte ptr".
let private descriptorWidths = [ 48<rt>; 80<rt> ]

/// The widths the extended-state instructions accept. Their operand is a region
/// whose real size depends on which features are enabled, so the width says
/// nothing about the encoding and any of these is the same instruction.
let private stateWidths = [ 32<rt>; 64<rt> ]

/// The widths a status or descriptor-table register is read into. A word is all
/// it holds, but the wider destinations encode too.
let private statusWidths = [ 16<rt>; 32<rt>; 64<rt> ]

/// The prefetch hints take memory of any width, and the decoder renders a
/// register operand for them too even though the manual has none.
let private prefetchWidths = [ 16<rt>; 32<rt>; 64<rt> ]

let private ae = [| 0x0Fuy; 0xAEuy |]

let private c7 = [| 0x0Fuy; 0xC7uy |]

let private zeroOne = [| 0x0Fuy; 0x01uy |]

let private zeroZero = [| 0x0Fuy; 0x00uy |]

let private zeroD = [| 0x0Fuy; 0x0Duy |]

let private one8 = [| 0x0Fuy; 0x18uy |]

/// The instructions encoded as a ModRM.reg digit under one opcode byte: the
/// descriptor tables, the extended-state saves, the cache and shadow-stack
/// operations, and the prefetch hints.
let digitGroupEncoders () =
  [ Opcode.FXSAVE, grpMem ae prefNormal rexNormal 0b000uy [ 32<rt> ]
    Opcode.FXSAVE64, grpMem ae prefNormal rexW 0b000uy [ 64<rt> ]
    Opcode.FXRSTOR, grpMem ae prefNormal rexNormal 0b001uy [ 32<rt> ]
    Opcode.FXRSTOR64, grpMem ae prefNormal rexW 0b001uy [ 64<rt> ]
    Opcode.LDMXCSR, grpMem ae prefNormal rexNormal 0b010uy [ 32<rt> ]
    Opcode.STMXCSR, grpMem ae prefNormal rexNormal 0b011uy [ 32<rt> ]
    Opcode.XSAVE, grpMemSized ae 0b100uy stateWidths
    Opcode.XRSTOR, grpMemSized ae 0b101uy stateWidths
    Opcode.XSAVEOPT, grpMemSized ae 0b110uy stateWidths
    Opcode.CLFLUSH, grpMem ae prefNormal rexNormal 0b111uy [ 8<rt> ]
    Opcode.CLFLUSHOPT, grpMem ae pref66 rexNormal 0b111uy [ 8<rt> ]
    Opcode.CLWB, grpMem ae pref66 rexNormal 0b110uy [ 8<rt> ]
    Opcode.CLRSSBSY, grpMem ae prefF3 rexNormal 0b110uy [ 64<rt> ]
    Opcode.INCSSPD, grpReg ae prefF3 0b101uy [ 32<rt> ]
    Opcode.INCSSPQ, grpReg ae prefF3 0b101uy [ 64<rt> ]
    Opcode.RDSSPD, grpReg [| 0x0Fuy; 0x1Euy |] prefF3 0b001uy [ 32<rt> ]
    Opcode.RDSSPQ, grpReg [| 0x0Fuy; 0x1Euy |] prefF3 0b001uy [ 64<rt> ]
    Opcode.XRSTORS, grpMem c7 prefNormal rexNormal 0b011uy [ 64<rt> ]
    Opcode.XRSTORS64, grpMem c7 prefNormal rexW 0b011uy [ 64<rt> ]
    Opcode.XSAVEC, grpMem c7 prefNormal rexNormal 0b100uy [ 64<rt> ]
    Opcode.XSAVEC64, grpMem c7 prefNormal rexW 0b100uy [ 64<rt> ]
    Opcode.XSAVES, grpMem c7 prefNormal rexNormal 0b101uy [ 64<rt> ]
    Opcode.XSAVES64, grpMem c7 prefNormal rexW 0b101uy [ 64<rt> ]
    Opcode.VMPTRLD, grpMem c7 prefNormal rexNormal 0b110uy [ 64<rt> ]
    Opcode.VMCLEAR, grpMem c7 pref66 rexNormal 0b110uy [ 64<rt> ]
    Opcode.RDRAND, grpReg c7 prefNormal 0b110uy stateWidths
    Opcode.RDSEED, grpReg c7 prefNormal 0b111uy prefetchWidths
    Opcode.SGDT, grpMem zeroOne prefNormal rexNormal 0b000uy descriptorWidths
    Opcode.SIDT, grpMem zeroOne prefNormal rexNormal 0b001uy descriptorWidths
    Opcode.LGDT, grpMem zeroOne prefNormal rexNormal 0b010uy descriptorWidths
    Opcode.LIDT, grpMem zeroOne prefNormal rexNormal 0b011uy descriptorWidths
    Opcode.RSTORSSP, grpMem zeroOne prefF3 rexNormal 0b101uy [ 64<rt> ]
    Opcode.INVLPG, grpMem zeroOne prefNormal rexNormal 0b111uy [ 16<rt> ]
    Opcode.SMSW, grpRegMem zeroOne 0b100uy statusWidths [ 16<rt> ]
    Opcode.LMSW, grpRegMem zeroOne 0b110uy [ 16<rt> ] [ 16<rt> ]
    Opcode.SLDT, grpRegMem zeroZero 0b000uy statusWidths [ 16<rt> ]
    Opcode.STR, grpRegMem zeroZero 0b001uy statusWidths [ 16<rt> ]
    Opcode.LLDT, grpRegMem zeroZero 0b010uy [ 16<rt> ] [ 16<rt> ]
    Opcode.LTR, grpRegMem zeroZero 0b011uy [ 16<rt> ] [ 16<rt> ]
    Opcode.VERR, grpRegMem zeroZero 0b100uy [ 16<rt> ] [ 16<rt> ]
    Opcode.VERW, grpRegMem zeroZero 0b101uy [ 16<rt> ] [ 16<rt> ]
    Opcode.PREFETCHW, grpMemSized zeroD 0b001uy prefetchWidths
    Opcode.PREFETCHWT1, grpMemSized zeroD 0b010uy prefetchWidths
    Opcode.PREFETCHNTA, grpRegMem one8 0b000uy prefetchWidths prefetchWidths
    Opcode.PREFETCHT0, grpRegMem one8 0b001uy prefetchWidths prefetchWidths
    Opcode.PREFETCHT1, grpRegMem one8 0b010uy prefetchWidths prefetchWidths
    Opcode.PREFETCHT2, grpRegMem one8 0b011uy prefetchWidths prefetchWidths ]

/// Builds an encoder for a conversion between register files. The register
/// kinds say nothing about which encoding it is - the mandatory prefix does -
/// so all this has to decide is whether a 64-bit general register calls for
/// REX.W.
let private convertRegRM pref memSz op wordSz ins =
  let rexOf r = if isReg64 wordSz r then rexW else rexNormal
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) ->
    encRR ins wordSz pref (rexOf r1) op r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, sz)) when sz = memSz ->
    encRM ins wordSz pref (rexOf r) op r b s d
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// Builds an encoder for LAR and LSL, which read a descriptor through a word of
/// memory whatever width their destination has.
let private accessRights op wordSz ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) ->
    match gprForm wordSz r1 with
    | Some(_, pref, rex, _) -> encRR ins wordSz pref rex op r1 r2
    | None -> raise <| EncodingFailureException "Unsupported operand type"
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) ->
    match gprForm wordSz r with
    | Some(_, pref, rex, _) -> encRM ins wordSz pref rex op r b s d
    | None -> raise <| EncodingFailureException "Unsupported operand type"
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// Builds an encoder for one of the far-pointer loads. Their memory operand is
/// a selector and an offset, so it is one word wider than the register it
/// fills: 16:16 into a word, 16:32 into a doubleword, 16:64 into a quadword.
let private loadFarPointer op wordSz ins =
  match ins.Operands with
  | TwoOperands(OprReg r, OprMem(b, s, d, sz)) ->
    match gprForm wordSz r with
    | Some(w, pref, rex, _) when int sz = int w + 16 ->
      encRM ins wordSz pref rex op r b s d
    | _ ->
      raise <| EncodingFailureException "Unsupported operand type"
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// Builds an encoder for an instruction reading a general register or memory
/// into a general register under a mandatory prefix, which is what keeps this
/// apart from gprRegRM.
let private gprRegRMPref pref op wordSz ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) ->
    match gprForm wordSz r1 with
    | Some(_, _, rex, _) -> encRR ins wordSz pref rex op r1 r2
    | None -> raise <| EncodingFailureException "Unsupported operand type"
  | TwoOperands(OprReg r, OprMem(b, s, d, sz)) ->
    match gprForm wordSz r with
    | Some(w, _, rex, _) when w = sz -> encRM ins wordSz pref rex op r b s d
    | _ -> raise <| EncodingFailureException "Unsupported operand type"
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// Builds an encoder for the same shape written the other way round, with the
/// destination in ModRM.rm.
let private gprRMRegPref pref op wordSz ins =
  match ins.Operands with
  | TwoOperands(OprMem(b, s, d, sz), OprReg r) ->
    match gprForm wordSz r with
    | Some(w, _, rex, _) when w = sz -> encMR ins wordSz pref rex op b s d r
    | _ -> raise <| EncodingFailureException "Unsupported operand type"
  | TwoOperands(OprReg r1, OprReg r2) ->
    match gprForm wordSz r1 with
    | Some(_, _, _, rex) -> encRR ins wordSz pref rex op r2 r1
    | None -> raise <| EncodingFailureException "Unsupported operand type"
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// CRC32 folds a byte, word, doubleword or quadword into a running checksum.
/// The byte-wide source has an opcode byte of its own, and the destination is
/// always a general register whose width decides REX.W.
let private crc32 wordSz ins =
  let rexOf r = if isReg64 wordSz r then rexW else rexNormal
  match ins.Operands with
  | TwoOperands(OprReg r, OprMem(b, s, d, 8<rt>)) ->
    encRM ins wordSz prefF2 (rexOf r) [| 0x0Fuy; 0x38uy; 0xF0uy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2) when isReg8 wordSz r2 ->
    encRR ins wordSz prefF2 (rexOf r1) [| 0x0Fuy; 0x38uy; 0xF0uy |] r1 r2
  | _ ->
    gprRegRMPref prefF2 [| 0x0Fuy; 0x38uy; 0xF1uy |] wordSz ins

/// MOVBE swaps a value's byte order as it crosses between a register and
/// memory, and which of the two it writes decides the opcode byte.
let private movbe wordSz ins =
  match ins.Operands with
  | TwoOperands(OprMem _, OprReg _) ->
    gprRMReg [| 0x0Fuy; 0x38uy; 0xF1uy |] wordSz ins
  | _ ->
    gprRegRM [| 0x0Fuy; 0x38uy; 0xF0uy |] wordSz ins

/// IN and OUT move a byte, word or doubleword through AL, AX or EAX, and the
/// accumulator's width is what the operand-size prefix has to say. A quadword
/// accumulator does not exist for these.
let private portPrefix wordSz r =
  if isReg16 wordSz r then pref66 else prefNormal

/// IN and OUT name a port either as an immediate byte or in DX. Reading uses
/// E4, writing the two bytes above it, and the byte-wide form of each sits one
/// below the wider one. One encoder covers both because the operand order is
/// what tells them apart.
let private portIO wordSz ins =
  let op b r = [| b + (if isReg8 wordSz r then 0uy else 1uy) |]
  match ins.Operands with
  | TwoOperands(OprReg r, OprImm(imm, _)) ->
    encImm ins wordSz (portPrefix wordSz r) rexNormal (op 0xE4uy r) imm 8<rt>
  | TwoOperands(OprImm(imm, _), OprReg r) ->
    encImm ins wordSz (portPrefix wordSz r) rexNormal (op 0xE6uy r) imm 8<rt>
  | TwoOperands(OprReg r, OprReg Register.DX) ->
    Resolved(prxRexOp ins wordSz (portPrefix wordSz r) rexNormal (op 0xECuy r))
  | TwoOperands(OprReg Register.DX, OprReg r) ->
    Resolved(prxRexOp ins wordSz (portPrefix wordSz r) rexNormal (op 0xEEuy r))
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// ENTER sets up a stack frame, taking the frame size as a word and the nesting
/// level as a byte.
let private enter wordSz ins =
  match ins.Operands with
  | TwoOperands(OprImm(size, _), OprImm(level, _)) ->
    Resolved [| yield! prxRexOp ins wordSz prefNormal rexNormal [| 0xC8uy |]
                yield! immediate size 16<rt>
                yield! immediate level 8<rt> |]
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// MOVNTPS and MOVNTPD only ever store. The register form the decoder renders
/// at their opcode byte does not exist, so the sweep leaves 0F 2B alone.
let private sseStore pref op wordSz ins =
  match ins.Operands with
  | TwoOperands(OprMem(b, s, d, 128<rt>), OprReg r) when isXMMReg r ->
    encMR ins wordSz pref rexNormal op b s d r
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// Builds an encoder for an SSE move from its prefix, its two opcode bytes and
/// its width, taking them in the order a table row wants rather than the order
/// sseMov itself does.
let private sseMovOf pref loadOp storeOp memSz wordSz ins =
  sseMov wordSz ins pref loadOp storeOp memSz

/// The instructions left over once every family with a shared encoding path has
/// been dealt with: the conversions between register files, the descriptor and
/// far-pointer loads, the byte-swapping and checksum pairs of the 0F 38 map,
/// and the legacy port and frame instructions.
let miscellaneousEncoders () =
  [ Opcode.CVTPI2PS, convertRegRM prefNormal 64<rt> [| 0x0Fuy; 0x2Auy |]
    Opcode.CVTPI2PD, convertRegRM pref66 64<rt> [| 0x0Fuy; 0x2Auy |]
    Opcode.CVTPS2PI, convertRegRM prefNormal 64<rt> [| 0x0Fuy; 0x2Duy |]
    Opcode.CVTPD2PI, convertRegRM pref66 128<rt> [| 0x0Fuy; 0x2Duy |]
    Opcode.CVTTPS2PI, convertRegRM prefNormal 64<rt> [| 0x0Fuy; 0x2Cuy |]
    Opcode.CVTTPD2PI, convertRegRM pref66 128<rt> [| 0x0Fuy; 0x2Cuy |]
    Opcode.CVTSD2SI, convertRegRM prefF2 64<rt> [| 0x0Fuy; 0x2Duy |]
    Opcode.CVTTSD2SI, convertRegRM prefF2 64<rt> [| 0x0Fuy; 0x2Cuy |]
    Opcode.LAR, accessRights [| 0x0Fuy; 0x02uy |]
    Opcode.LSL, accessRights [| 0x0Fuy; 0x03uy |]
    Opcode.LSS, loadFarPointer [| 0x0Fuy; 0xB2uy |]
    Opcode.LFS, loadFarPointer [| 0x0Fuy; 0xB4uy |]
    Opcode.LGS, loadFarPointer [| 0x0Fuy; 0xB5uy |]
    Opcode.LES, loadFarPointer [| 0xC4uy |]
    Opcode.LDS, loadFarPointer [| 0xC5uy |]
    Opcode.BOUND, gprRegRM [| 0x62uy |]
    Opcode.ARPL, gprRMReg [| 0x63uy |]
    Opcode.MOVAPD,
      sseMovOf pref66 [| 0x0Fuy; 0x28uy |] [| 0x0Fuy; 0x29uy |] 128<rt>
    Opcode.MOVUPD,
      sseMovOf pref66 [| 0x0Fuy; 0x10uy |] [| 0x0Fuy; 0x11uy |] 128<rt>
    Opcode.CRC32, crc32
    Opcode.MOVBE, movbe
    Opcode.ADCX, gprRegRMPref pref66 [| 0x0Fuy; 0x38uy; 0xF6uy |]
    Opcode.ADOX, gprRegRMPref prefF3 [| 0x0Fuy; 0x38uy; 0xF6uy |]
    Opcode.WRSSD, gprRegRMPref prefNormal [| 0x0Fuy; 0x38uy; 0xF6uy |]
    Opcode.WRSSQ, gprRegRMPref prefNormal [| 0x0Fuy; 0x38uy; 0xF6uy |]
    Opcode.WRUSSD, gprRMRegPref pref66 [| 0x0Fuy; 0x38uy; 0xF5uy |]
    Opcode.WRUSSQ, gprRMRegPref pref66 [| 0x0Fuy; 0x38uy; 0xF5uy |]
    Opcode.INVPCID, convertRegRM pref66 128<rt> [| 0x0Fuy; 0x38uy; 0x82uy |]
    Opcode.VMREAD, gprRMRegPref prefNormal [| 0x0Fuy; 0x78uy |]
    Opcode.IN, portIO
    Opcode.OUT, portIO
    Opcode.ENTER, enter
    Opcode.MOVNTPS, sseStore prefNormal [| 0x0Fuy; 0x2Buy |]
    Opcode.MOVNTPD, sseStore pref66 [| 0x0Fuy; 0x2Buy |] ]

/// Builds an encoder for a mask extraction, which reads a lane mask out of an
/// MMX or XMM register into a general register. The manual leaves a memory
/// ModRM byte reserved, which is why the sweep leaves these bytes alone.
let private maskExtract mmxPref ssePref op wordSz ins =
  let rexOf r = if isReg64 wordSz r then rexW else rexNormal
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isMMXReg r2 ->
    encRR ins wordSz mmxPref (rexOf r1) op r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r2 ->
    encRR ins wordSz ssePref (rexOf r1) op r1 r2
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// Builds an encoder for a move between the MMX and XMM files, which likewise
/// has no memory form however the decoder renders one.
let private crossFileMove pref op wordSz ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) ->
    encRR ins wordSz pref rexNormal op r1 r2
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// Builds an encoder for a non-temporal store of a whole register.
let private nonTemporalStore pref memSz op wordSz ins =
  match ins.Operands with
  | TwoOperands(OprMem(b, s, d, sz), OprReg r) when sz = memSz ->
    encMR ins wordSz pref rexNormal op b s d r
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// MOVQ moves a quadword between every pair of files there is, and each pair
/// has an opcode byte and prefix of its own: 0F 6E and 0F 7E carry it to and
/// from a
/// general register, 0F 6F and 0F 7F between MMX registers and memory, F3 0F 7E
/// and 66 0F D6 between XMM registers and memory.
let private movq wordSz ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isMMXReg r1 && isMMXReg r2 ->
    encRR ins wordSz prefNormal rexNormal [| 0x0Fuy; 0x6Fuy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isMMXReg r1 ->
    encRR ins wordSz prefNormal rexW [| 0x0Fuy; 0x6Euy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins wordSz prefF3 rexNormal [| 0x0Fuy; 0x7Euy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 ->
    encRR ins wordSz pref66 rexW [| 0x0Fuy; 0x6Euy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isMMXReg r2 ->
    encRR ins wordSz prefNormal rexW [| 0x0Fuy; 0x7Euy |] r2 r1
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r2 ->
    encRR ins wordSz pref66 rexW [| 0x0Fuy; 0x7Euy |] r2 r1
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isMMXReg r ->
    encRM ins wordSz prefNormal rexNormal [| 0x0Fuy; 0x6Fuy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isXMMReg r ->
    encRM ins wordSz prefF3 rexNormal [| 0x0Fuy; 0x7Euy |] r b s d
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprReg r) when isMMXReg r ->
    encMR ins wordSz prefNormal rexNormal [| 0x0Fuy; 0x7Fuy |] b s d r
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprReg r) when isXMMReg r ->
    encMR ins wordSz pref66 rexNormal [| 0x0Fuy; 0xD6uy |] b s d r
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// EXTRQ and INSERTQ take their field position and length as two immediate
/// bytes, which is the only place four operands appear outside AVX.
let private extrq wordSz ins =
  match ins.Operands with
  | ThreeOperands(OprReg r, OprImm(i1, _), OprImm(i2, _)) ->
    Resolved [| yield! prxRexOp ins wordSz pref66 rexNormal
                          [| 0x0Fuy; 0x78uy |]
                modrmRI r 0b000uy
                yield! immediate i1 8<rt>
                yield! immediate i2 8<rt> |]
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

let private insertq wordSz ins =
  match ins.Operands with
  | FourOperands(OprReg r1, OprReg r2, OprImm(i1, _), OprImm(i2, _)) ->
    Resolved [| yield! prxRexOp ins wordSz prefF2 rexNormal
                          [| 0x0Fuy; 0x78uy |]
                modrmRR r1 r2
                yield! immediate i1 8<rt>
                yield! immediate i2 8<rt> |]
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// Builds an encoder for one of the bounds checks, whose first operand is a
/// bounds register and whose second is an address held in a general register or
/// memory. REX.W is what says the address is 64 bits wide.
let private bndCheck pref op wordSz ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) ->
    let rex = if isReg64 wordSz r2 then rexW else rexNormal
    encRR ins wordSz pref rex op r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, sz)) ->
    match gprMemForm wordSz sz with
    | Some(_, rex) -> encRM ins wordSz pref rex op r b s d
    | None -> raise <| EncodingFailureException "Unsupported operand type"
  | TwoOperands(OprMem(b, s, d, sz), OprReg r) ->
    match gprMemForm wordSz sz with
    | Some(_, rex) -> encMR ins wordSz pref rex op b s d r
    | None -> raise <| EncodingFailureException "Unsupported operand type"
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// BNDSTX writes the bounds it names second through the address it names first,
/// so unlike the checks its bounds register goes in ModRM.reg.
let private bndstx wordSz ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) ->
    let rex = if isReg64 wordSz r1 then rexWAndMR else rexMR
    encRR ins wordSz prefNormal rex [| 0x0Fuy; 0x1Buy |] r2 r1
  | _ ->
    bndCheck prefNormal [| 0x0Fuy; 0x1Buy |] wordSz ins

/// BNDMOV moves a whole bounds pair, so its memory operand is as wide as the
/// pair rather than as wide as an address, and REX.W says nothing here. Which
/// of its two opcode bytes it takes depends on which operand is the memory one.
let private bndmov wordSz ins =
  match ins.Operands with
  | TwoOperands(OprMem(b, s, d, _), OprReg r) ->
    encMR ins wordSz pref66 rexNormal [| 0x0Fuy; 0x1Buy |] b s d r
  | TwoOperands(OprReg r, OprMem(b, s, d, _)) ->
    encRM ins wordSz pref66 rexNormal [| 0x0Fuy; 0x1Auy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2) ->
    encRR ins wordSz pref66 rexNormal [| 0x0Fuy; 0x1Auy |] r1 r2
  | _ ->
    raise <| EncodingFailureException "Unsupported operand type"

/// The instructions whose encoding is a shape of its own: the mask extracts and
/// cross-file moves that have no memory form, the quadword moves that span six
/// opcode bytes between them, the bounds registers, and the far branches to an
/// absolute target.
let oneOffEncoders () =
  [ Opcode.MOVMSKPS, maskExtract prefNormal prefNormal [| 0x0Fuy; 0x50uy |]
    Opcode.MOVMSKPD, maskExtract pref66 pref66 [| 0x0Fuy; 0x50uy |]
    Opcode.PMOVMSKB, maskExtract prefNormal pref66 [| 0x0Fuy; 0xD7uy |]
    Opcode.MOVDQ2Q, crossFileMove prefF2 [| 0x0Fuy; 0xD6uy |]
    Opcode.MOVQ2DQ, crossFileMove prefF3 [| 0x0Fuy; 0xD6uy |]
    Opcode.MOVNTQ, nonTemporalStore prefNormal 64<rt> [| 0x0Fuy; 0xE7uy |]
    Opcode.MOVNTDQ, nonTemporalStore pref66 128<rt> [| 0x0Fuy; 0xE7uy |]
    Opcode.MOVQ, movq
    Opcode.EXTRQ, extrq
    Opcode.INSERTQ, insertq
    Opcode.BNDCL, bndCheck prefF3 [| 0x0Fuy; 0x1Auy |]
    Opcode.BNDCU, bndCheck prefF2 [| 0x0Fuy; 0x1Auy |]
    Opcode.BNDLDX, bndCheck prefNormal [| 0x0Fuy; 0x1Auy |]
    Opcode.BNDCN, bndCheck prefF2 [| 0x0Fuy; 0x1Buy |]
    Opcode.BNDMK, bndCheck prefF3 [| 0x0Fuy; 0x1Buy |]
    Opcode.BNDSTX, bndstx
    Opcode.BNDMOV, bndmov ]

let syscall () = Resolved [| 0x0Fuy; 0x05uy |]

// vim: set tw=80 sts=2 sw=2:
