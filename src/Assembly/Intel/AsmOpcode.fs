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
    | _ -> ins.Operands
  { ins with Operands = operands }

let aaa (wordSz: WordSize) = function
  | NoOperand -> no64Arch wordSz; Resolved [| 0x37uy |]
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let aad (wordSz: WordSize) = function
  | NoOperand -> no64Arch wordSz; Resolved [| 0xD5uy; 0x0Auy |]
  | OneOperand(OprImm(imm, _)) ->
    no64Arch wordSz; Resolved [| 0xD5uy; yield! immediate imm 8<rt> |]
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let aam (wordSz: WordSize) = function
  | NoOperand -> no64Arch wordSz; Resolved [| 0xD4uy; 0x0Auy |]
  | OneOperand(OprImm(imm, _)) ->
    no64Arch wordSz; Resolved [| 0xD4uy; yield! immediate imm 8<rt> |]
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

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
  | TwoOperands(Label(lbl, _), OprReg r) -> encRL wordSz ins r lbl opMR8 opMR
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
  | TwoOperands(OprReg r, Label(lbl, _)) -> encRL wordSz ins r lbl opRM8 opRM
  | TwoOperands(OprReg r, OprMem(b, s, d, 8<rt>)) when isReg8 wordSz r ->
    encRM ins wordSz prefNormal rexNormal opRM8 r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg16 wordSz r ->
    encRM ins wordSz pref66 rexNormal opRM r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg32 wordSz r ->
    encRM ins wordSz prefNormal rexNormal opRM r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isReg64 wordSz r ->
    no32Arch wordSz
    encRM ins wordSz prefNormal rexW opRM r b s d
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

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
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

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
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

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
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

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

let call (wordSz: WordSize) ins =
  let branch = relBranch Opcode.CALL
  match ins.Operands with
  | OneOperand(OprDirAddr(Relative rel))
    when isInt16 rel && wordSz = WordSize.Bit32 ->
    encD ins wordSz pref66 rexNormal branch.NearForm rel 16<rt>
  | OneOperand(OprDirAddr(Relative rel)) when isInt32 rel ->
    encD ins wordSz prefNormal rexNormal branch.NearForm rel 32<rt>
  | OneOperand(Label(lbl, _)) -> encLbl ins lbl
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
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

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
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

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
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let cmpxchg8b (wordSz: WordSize) ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0x0Fuy; 0xC7uy |] b s d 0b001uy
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let cmpxchg16b (wordSz: WordSize) ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 128<rt>)) ->
    no32Arch wordSz
    encM ins wordSz prefNormal rexW [| 0x0Fuy; 0xC7uy |] b s d 0b001uy
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

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
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

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
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

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
   | _ -> raise <| EncodingFailureException "Unsupported operand type"

let cvttss2si (wordSz: WordSize) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isReg32 wordSz r1 && isXMMReg r2 ->
    encRR ins wordSz prefF3 rexNormal [| 0x0Fuy; 0x2Cuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg32 wordSz r ->
    encRM ins wordSz prefF3 rexNormal [| 0x0Fuy; 0x2Cuy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2) when isReg64 wordSz r1 && isXMMReg r2 ->
    encRR ins wordSz prefF3 rexW [| 0x0Fuy; 0x2Cuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isReg64 wordSz r ->
    encRM ins wordSz prefF3 rexW [| 0x0Fuy; 0x2Cuy |] r b s d
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

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
    else encR ins wordSz pref66 rexNormal [| 0xFFuy |] r 1uy
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins wordSz pref66 rexNormal [| 0xFFuy |] b s d 1uy
  | OneOperand(OprReg r) when isReg32 wordSz r ->
    if isClassicGPReg r && wordSz = WordSize.Bit32 then
      encClassicR false 0x48uy (regTo3Bit r)
    else encR ins wordSz prefNormal rexNormal [| 0xFFuy |] r 1uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xFFuy |] b s d 1uy
  | OneOperand(OprReg r) when isReg64 wordSz r ->
    no32Arch wordSz
    encR ins wordSz prefNormal rexW [| 0xFFuy |] r 1uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    no32Arch wordSz
    encM ins wordSz prefNormal rexW [| 0xFFuy |] b s d 1uy
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

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
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

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
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let fadd wordSz ins = x87Arith wordSz ins 0b000uy 0xC0uy 0xC0uy

let fcmovb _wordSize ins =
  match ins.Operands with
  | TwoOperands(OprReg Register.ST0, OprReg r) when isFPUReg r ->
    encFR [| 0xDAuy; 0xC0uy |] r
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let fdiv wordSz ins = x87Arith wordSz ins 0b110uy 0xF0uy 0xF8uy

let fdivp _wordSize = function
  | NoOperand -> Resolved [| 0xDEuy; 0xF9uy |]
  | TwoOperands(OprReg r, OprReg Register.ST0) when isFPUReg r ->
    encFR [| 0xDEuy; 0xF8uy |] r
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let fdivrp _wordSize = function
  | NoOperand -> Resolved [| 0xDEuy; 0xF1uy |]
  | TwoOperands(OprReg r, OprReg Register.ST0) when isFPUReg r ->
    encFR [| 0xDEuy; 0xF0uy |] r
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let fild (wordSz: WordSize) ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xDFuy |] b s d 0b000uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xDBuy |] b s d 0b000uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xDFuy |] b s d 0b101uy
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let fistp (wordSz: WordSize) ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xDFuy |] b s d 0b011uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xDBuy |] b s d 0b011uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xDFuy |] b s d 0b111uy
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let fld (wordSz: WordSize) ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xD9uy |] b s d 0b000uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xDDuy |] b s d 0b000uy
  | OneOperand(OprMem(b, s, d, 80<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xDBuy |] b s d 0b101uy
  | OneOperand(OprReg r) when isFPUReg r -> encFR [| 0xD9uy; 0xC0uy |] r
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let fld1 _wordSize = function
  | NoOperand -> Resolved [| 0xD9uy; 0xE8uy |]
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let fldcw (wordSz: WordSize) ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xD9uy |] b s d 0b101uy
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let fldz _wordSize = function
  | NoOperand -> Resolved [| 0xD9uy; 0xEEuy |]
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let fmul wordSz ins = x87Arith wordSz ins 0b001uy 0xC8uy 0xC8uy

let fmulp _wordSize = function
  | NoOperand -> Resolved [| 0xDEuy; 0xC9uy |]
  | TwoOperands(OprReg r, OprReg Register.ST0) when isFPUReg r ->
    encFR [| 0xDEuy; 0xC8uy |] r
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let fnstcw (wordSz: WordSize) ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xD9uy |] b s d 0b111uy
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let fstp (wordSz: WordSize) ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xD9uy |] b s d 0b011uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xDDuy |] b s d 0b011uy
  | OneOperand(OprMem(b, s, d, 80<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xDBuy |] b s d 0b111uy
  | OneOperand(OprReg r) when isFPUReg r -> encFR [| 0xDDuy; 0xD8uy |] r
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let fsub wordSz ins = x87Arith wordSz ins 0b100uy 0xE0uy 0xE8uy

let fsubr wordSz ins = x87Arith wordSz ins 0b101uy 0xE8uy 0xE0uy

let fucomi _wordSize = function
  | TwoOperands(OprReg Register.ST0, OprReg r) when isFPUReg r ->
    encFR [| 0xDBuy; 0xE8uy |] r
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let fucomip _wordSize = function
  | TwoOperands(OprReg Register.ST0, OprReg r) when isFPUReg r ->
    encFR [| 0xDFuy; 0xE8uy |] r
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

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
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let inc (wordSz: WordSize) ins =
  match ins.Operands with
  | OneOperand(OprReg r) when isReg8 wordSz r ->
    encR ins wordSz prefNormal rexNormal [| 0xFEuy |] r 0uy
  | OneOperand(OprMem(b, s, d, 8<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xFEuy |] b s d 0uy
  | OneOperand(OprReg r) when isReg16 wordSz r ->
    if isClassicGPReg r && wordSz = WordSize.Bit32 then
      encClassicR true 0x40uy (regTo3Bit r)
    else encR ins wordSz pref66 rexNormal [| 0xFFuy |] r 0uy
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins wordSz pref66 rexNormal [| 0xFFuy |] b s d 0uy
  | OneOperand(OprReg r) when isReg32 wordSz r ->
    if isClassicGPReg r && wordSz = WordSize.Bit32 then
      encClassicR false 0x40uy (regTo3Bit r)
    else encR ins wordSz prefNormal rexNormal [| 0xFFuy |] r 0uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0xFFuy |] b s d 0uy
  | OneOperand(OprReg r) when isReg64 wordSz r ->
    no32Arch wordSz
    encR ins wordSz prefNormal rexW [| 0xFFuy |] r 0uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    no32Arch wordSz
    encM ins wordSz prefNormal rexW [| 0xFFuy |] b s d 0uy
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let interrupt ins =
  match ins.Operands with
  | OneOperand(OprImm(n, _)) when isUInt8 n ->
    Resolved [| 0xcduy; byte n |]
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let interrupt3 () = Resolved [| 0xccuy |]

let jcc (wordSz: WordSize) ins =
  let branch = relBranch ins.Opcode
  match ins.Operands with
  | OneOperand(Label(lbl, _)) -> encLbl ins lbl
  | OneOperand(OprDirAddr(Relative rel)) when isInt8 rel ->
    encD ins wordSz prefNormal rexNormal branch.ShortForm rel 8<rt>
  | OneOperand(OprDirAddr(Relative rel))
    when isInt16 rel && wordSz = WordSize.Bit32 ->
    encD ins wordSz pref66 rexNormal branch.NearForm rel 16<rt>
  | OneOperand(OprDirAddr(Relative rel)) when isInt32 rel ->
    encD ins wordSz prefNormal rexNormal branch.NearForm rel 32<rt>
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let jmp (wordSz: WordSize) ins =
  let branch = relBranch Opcode.JMP
  match ins.Operands with
  | OneOperand(Label(lbl, _)) -> encLbl ins lbl
  | OneOperand(OprDirAddr(Relative rel)) when isInt8 rel ->
    encD ins wordSz prefNormal rexNormal branch.ShortForm rel 8<rt>
  | OneOperand(OprDirAddr(Relative rel)) when isInt32 rel ->
    encD ins wordSz prefNormal rexNormal branch.NearForm rel 32<rt>
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
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let lahf (wordSz: WordSize) = function
  | NoOperand -> no64Arch wordSz; Resolved [| 0x9Fuy |]
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
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let leave (wordSz: WordSize) = function
  | NoOperand -> no64Arch wordSz; Resolved [| 0xC9uy |]
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let mov wordSz ins =
  let ins = resolveMemSizeFromReg ins wordSz
  match ins.Operands with
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
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

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
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

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
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let movdqa wordSz ins =
  sseMov wordSz ins pref66 [| 0x0Fuy; 0x6Fuy |] [| 0x0Fuy; 0x7Fuy |] 128<rt>

let movdqu wordSz ins =
  sseMov wordSz ins prefF3 [| 0x0Fuy; 0x6Fuy |] [| 0x0Fuy; 0x7Fuy |] 128<rt>

let movsd (wordSz: WordSize) ins =
  match ins.Operands with
  | NoOperand -> stringOp wordSz ins prefNormal rexNormal 0xA5uy
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins wordSz prefF2 rexNormal [| 0x0Fuy; 0x10uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isXMMReg r ->
    encRM ins wordSz prefF2 rexNormal [| 0x0Fuy; 0x10uy |] r b s d
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprReg r) when isXMMReg r ->
    encMR ins wordSz prefF2 rexNormal [| 0x0Fuy; 0x11uy |] b s d r
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let movss wordSz ins = sseRegRM wordSz ins prefF3 [| 0x0Fuy; 0x10uy |] 32<rt>

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
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let movsxd (wordSz: WordSize) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2)
    when isReg64 wordSz r1 && isReg32 wordSz r2 ->
    no32Arch wordSz
    encRR ins wordSz prefNormal rexW [| 0x63uy |] r1 r2
  | TwoOperands(OprReg r, Label(lbl, _)) ->
    encRL wordSz ins r lbl [||] [| 0x63uy |]
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg64 wordSz r ->
    no32Arch wordSz
    encRM ins wordSz prefNormal rexW [| 0x63uy |] r b s d
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

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
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let mul wordSz ins = unaryGrp3 wordSz ins 0b100uy

let mulsd wordSz ins = sseRegRM wordSz ins prefF2 [| 0x0Fuy; 0x59uy |] 64<rt>

let mulss wordSz ins = sseRegRM wordSz ins prefF3 [| 0x0Fuy; 0x59uy |] 32<rt>

let neg wordSz ins = unaryGrp3 wordSz ins 0b011uy

let nop (wordSz: WordSize) ins =
  match ins.Operands with
  | NoOperand -> Resolved [| 0x90uy |]
  | OneOperand(OprReg r) when isReg16 wordSz r ->
    encR ins wordSz pref66 rexNormal [| 0x0Fuy; 0x1Fuy |] r 0b000uy
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins wordSz pref66 rexNormal [| 0x0Fuy; 0x1Fuy |] b s d 0b000uy
  | OneOperand(OprReg r) when isReg32 wordSz r ->
    encR ins wordSz prefNormal rexNormal [| 0x0Fuy; 0x1Fuy |] r 0b000uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins wordSz prefNormal rexNormal [| 0x0Fuy; 0x1Fuy |] b s d 0b000uy
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let not wordSz ins = unaryGrp3 wordSz ins 0b010uy

let logOr wordSz ins = arithmetic wordSz ins 0x08uy 0b001uy

let orpd wordSz ins = sseRegRM wordSz ins pref66 [| 0x0Fuy; 0x56uy |] 128<rt>

let paddd wordSz ins = sseRegRM wordSz ins pref66 [| 0x0Fuy; 0xFEuy |] 128<rt>

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
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let pop (wordSz: WordSize) ins =
  match ins.Operands with
  | OneOperand(OprReg Register.DS) ->
    no64Arch wordSz; Resolved [| 0x1Fuy |]
  | OneOperand(OprReg Register.ES) ->
    no64Arch wordSz; Resolved [| 0x07uy |]
  | OneOperand(OprReg Register.SS) ->
    no64Arch wordSz; Resolved [| 0x17uy |]
  | OneOperand(OprReg Register.FS) -> Resolved [| 0x0Fuy; 0xA1uy |]
  | OneOperand(OprReg Register.GS) -> Resolved [| 0x0Fuy; 0xA9uy |]
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
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let pshufd (wordSz: WordSize) ins =
  match ins.Operands with
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _))
    when isXMMReg r1 && isXMMReg r2 ->
    encRRI ins wordSz pref66 rexNormal [| 0x0Fuy; 0x70uy |] r1 r2 imm 8<rt>
  | ThreeOperands(OprReg r, OprMem(b, s, d, 128<rt>), OprImm(imm, _))
    when isXMMReg r ->
    encRMI ins wordSz pref66 rexNormal [| 0x0Fuy; 0x70uy |] r b s d imm 8<rt>
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

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
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

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
  | OneOperand(OprReg Register.FS) -> Resolved [| 0x0Fuy; 0xA0uy |]
  | OneOperand(OprReg Register.GS) -> Resolved [| 0x0Fuy; 0xA8uy |]
  | OneOperand(OprReg r) when isReg16 wordSz r ->
    if isClassicGPReg r then encClassicR true 0x50uy (regTo3Bit r)
    else encR ins wordSz pref66 rexNormal [| 0xFFuy |] r 0b110uy
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins wordSz pref66 rexNormal [| 0xFFuy |] b s d 0b110uy
  | OneOperand(OprReg r) when isReg32 wordSz r ->
    no64Arch wordSz
    if isClassicGPReg r then encClassicR false 0x50uy (regTo3Bit r)
    else
      encR ins wordSz prefNormal rexNormal [| 0xFFuy |] r 0b110uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    no64Arch wordSz
    encM ins wordSz prefNormal rexNormal [| 0xFFuy |] b s d 0b110uy
  | OneOperand(OprReg r) when isReg64 wordSz r ->
    no32Arch wordSz
    if isClassicGPReg r then encClassicR false 0x50uy (regTo3Bit r)
    else
      encR ins wordSz prefNormal rexNormal [| 0xFFuy |] r 0b110uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    no32Arch wordSz
    encM ins wordSz prefNormal rexNormal [| 0xFFuy |] b s d 0b110uy
  | OneOperand(OprImm(imm, _)) when isInt8 imm ->
    encImm ins wordSz prefNormal rexNormal [| 0x6Auy |] imm 8<rt>
  | OneOperand(OprImm(imm, _)) when isInt16 imm ->
    encImm ins wordSz pref66 rexNormal [| 0x68uy |] imm 16<rt>
  | OneOperand(OprImm(imm, _)) when isUInt32 imm ->
    encImm ins wordSz prefNormal rexNormal [| 0x68uy |] imm 32<rt>
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

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
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

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
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let rcl wordSz ins = rotateOrShift wordSz ins 0b010uy

let rcr wordSz ins = rotateOrShift wordSz ins 0b011uy

let rol wordSz ins = rotateOrShift wordSz ins 0b000uy

let ror wordSz ins = rotateOrShift wordSz ins 0b001uy

let ret (wordSz: WordSize) ins =
  match ins.Operands with
  | NoOperand -> Resolved [| 0xC3uy |]
  (* The parser offers a jump target to every branch opcode, RET included, but
     RET's operand is a count of bytes to pop rather than a displacement, so it
     is encoded as the immediate it is and not relative to anything. *)
  | OneOperand(OprDirAddr(Relative imm))
  | OneOperand(OprImm(imm, _)) ->
    encImm ins wordSz prefNormal rexNormal [| 0xC2uy |] imm 16<rt>
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let sar wordSz ins = rotateOrShift wordSz ins 0b111uy

let shl wordSz ins = rotateOrShift wordSz ins 0b100uy

let shr wordSz ins = rotateOrShift wordSz ins 0b101uy

let sahf (wordSz: WordSize) = function
  | NoOperand -> no64Arch wordSz; Resolved [| 0x9Euy |]
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
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

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
    encRR ins wordSz prefNormal rexW [| 0x0Fuy; 0xA5uy |] r1 r2
  | ThreeOperands(OprMem(b, s, d, 64<rt>), OprReg r, OprReg Register.CL)
    when isReg64 wordSz r ->
    no32Arch wordSz
    encMR ins wordSz prefNormal rexW [| 0x0Fuy; 0xA5uy |] b s d r
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

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
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

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
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

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
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let vaddsd (wordSz: WordSize) ins =
  match ins.Operands with
  | ThreeOperands(OprReg r1, OprReg r2, OprReg r3)
    when isXMMReg r1 && isXMMReg r2 && isXMMReg r3 ->
    encVexRRR wordSz (Some r2) vex128nF2n0F [| 0x58uy |] r1 r3
  | ThreeOperands(OprReg r1, OprReg r2, OprMem(b, s, d, 64<rt>))
    when isXMMReg r1 && isXMMReg r2 ->
    encVexRRM wordSz (Some r2) vex128nF2n0F [| 0x58uy |] r1 b s d
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let vaddss (wordSz: WordSize) ins =
  match ins.Operands with
  | ThreeOperands(OprReg r1, OprReg r2, OprReg r3)
    when isXMMReg r1 && isXMMReg r2 && isXMMReg r3 ->
    encVexRRR wordSz (Some r2) vex128nF3n0F [| 0x58uy |] r1 r3
  | ThreeOperands(OprReg r1, OprReg r2, OprMem(b, s, d, 32<rt>))
    when isXMMReg r1 && isXMMReg r2 ->
    encVexRRM wordSz (Some r2) vex128nF3n0F [| 0x58uy |] r1 b s d
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

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
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

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
  | _ -> raise <| EncodingFailureException "Unsupported operand type"

let xor wordSz ins = arithmetic wordSz ins 0x30uy 0b110uy

let xorps wordSz ins =
  sseRegRM wordSz ins prefNormal [| 0x0Fuy; 0x57uy |] 128<rt>

let syscall () = Resolved [| 0x0Fuy; 0x05uy |]

// vim: set tw=80 sts=2 sw=2:
