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

module internal B2R2.Assembler.Intel.AsmPrefix

open B2R2
open B2R2.FrontEnd.Intel

let isReg8 reg = Register.toRegType reg = 8<rt>
let isReg16 reg = Register.toRegType reg = 16<rt>
let isReg32 reg = Register.toRegType reg = 32<rt>
let isReg64 reg = Register.toRegType reg = 64<rt>
let isSegReg reg = Register.Kind.Segment = Register.getKind reg

let private exceptOprSzPrefOp encType op =
  match encType, op with
  | _ -> false

let private isOprReg16 = function
  | _ -> false

let private isAddrSz arch reg =
  match arch, Register.toRegType reg with
  | Arch.IntelX64, 32<rt> -> true
  | Arch.IntelX86, 16<rt> -> true
  | _ -> false

let private isAddrSize isa = function
  | OneOperand (OprMem (Some bReg, _, _, _))
  | TwoOperands (_, OprMem (Some bReg, _, _, _))
  | TwoOperands (OprMem (Some bReg, _, _, _), _) -> isAddrSz isa bReg
  | _ -> false

let getPrefByte = function
  | 0x1 -> 0xF0uy   (* Prefix.PrxLOCK *)
  | 0x2 -> 0xF2uy   (* Prefix.PrxREPNZ *)
  | 0x4 -> 0xF3uy   (* Prefix.PrxREPZ *)
  | 0x8 -> 0x2Euy   (* Prefix.PrxCS *)
  | 0x10 -> 0x36uy  (* Prefix.PrxSS *)
  | 0x20 -> 0x3Euy  (* Prefix.PrxDS *)
  | 0x40 -> 0x26uy  (* Prefix.PrxES *)
  | 0x80 -> 0x64uy  (* Prefix.PrxFS *)
  | 0x100 -> 0x65uy (* Prefix.PrxGS *)
  | 0x0 -> 0x0uy
  | _ -> failwith "Invalid prefix"

let getGrp1Pref prefs = prefs &&& 0x7 |> getPrefByte

let getGrp2Pref prefs = prefs &&& 0x1F8 |> getPrefByte

let encodePrefix arch ins oSzPref canLock canRepz canSeg =
  // 64-bit mode : register -> 16bit => 66
  //               memory base register -> 32bit => 67
  // 32-bit mode : register -> 16bit => 66
  //               memory base register -> 16bit => 67
  let prefs = LanguagePrimitives.EnumToValue ins.Prefixes

  // Prefix group1 and group2
  let prxGrp1 =
    let pGrp1 = getGrp1Pref prefs
    if pGrp1 = 0uy then [||]
    else if ((pGrp1 = 0xF0uy) && canLock) ||
            ((pGrp1 = 0xF2uy || pGrp1 = 0xF3uy) && canRepz)
         then [| pGrp1 |> Normal |]
         else failwith "Invalid prefix (Lock)"

  let prxGrp2 =
    if prefs = 0 then [||]
    else if canSeg then [| getGrp2Pref prefs |> Normal |]
         else failwith "Invalid prefix (Segment)"

  // Prefix group3: Operand-size override
  let prxGrp3 =
    match oSzPref with
    | Some pref -> [| Normal pref |]
    | _ -> [||]

  // Prefix group4: Address-size override
  let prxGrp4 =
    if isAddrSize arch ins.Operands then [| Normal 0x67uy |] else [||]

  [| yield! prxGrp1; yield! prxGrp2; yield! prxGrp3; yield! prxGrp4 |]

let private exceptREXPrefOp = function
  | Opcode.CRC32 | Opcode.CMPXCHG8B -> true
  | _ -> false

let encodeRex = function
  | Register.SPL | Register.BPL | Register.SIL | Register.DIL -> 0x40uy
  | _ -> 0x0uy

let encodeRexR = function
  | Register.R8L | Register.R8W | Register.R8D | Register.R8
  | Register.R9L | Register.R9W | Register.R9D | Register.R9
  | Register.R10L | Register.R10W | Register.R10D | Register.R10
  | Register.R11L | Register.R11W | Register.R11D | Register.R11
  | Register.R12L | Register.R12W | Register.R12D | Register.R12
  | Register.R13L | Register.R13W | Register.R13D | Register.R13
  | Register.R14L | Register.R14W | Register.R14D | Register.R14
  | Register.R15L | Register.R15W | Register.R15D | Register.R15 -> 0x44uy
  | _ -> 0x0uy

let encodeRexX = function
  | Register.R8L | Register.R8W | Register.R8D | Register.R8
  | Register.R9L | Register.R9W | Register.R9D | Register.R9
  | Register.R10L | Register.R10W | Register.R10D | Register.R10
  | Register.R11L | Register.R11W | Register.R11D | Register.R11
  | Register.R12L | Register.R12W | Register.R12D | Register.R12
  | Register.R13L | Register.R13W | Register.R13D | Register.R13
  | Register.R14L | Register.R14W | Register.R14D | Register.R14
  | Register.R15L | Register.R15W | Register.R15D | Register.R15 -> 0x42uy
  | _ -> 0x0uy

let encodeRexB = function
  | Register.R8L | Register.R8W | Register.R8D | Register.R8
  | Register.R9L | Register.R9W | Register.R9D | Register.R9
  | Register.R10L | Register.R10W | Register.R10D | Register.R10
  | Register.R11L | Register.R11W | Register.R11D | Register.R11
  | Register.R12L | Register.R12W | Register.R12D | Register.R12
  | Register.R13L | Register.R13W | Register.R13D | Register.R13
  | Register.R14L | Register.R14W | Register.R14D | Register.R14
  | Register.R15L | Register.R15W | Register.R15D | Register.R15 -> 0x41uy
  | _ -> 0x0uy

let encodeRexRXB isMR isOpRegFld = function
  | TwoOperands (OprReg r1, OprReg r2) when isReg8 r1 && isReg8 r2 ->
    encodeRex r1 ||| encodeRex r2
  | TwoOperands (OprReg r1, OprReg r2) when isMR ->
    encodeRexR r2 ||| encodeRexB r1
  | TwoOperands (OprReg r1, OprReg r2) -> encodeRexR r1 ||| encodeRexB r2
  | TwoOperands (OprReg r, OprMem (Some bReg, Some (s, _), _, _))
  | TwoOperands (OprMem (Some bReg, Some (s, _), _, _), OprReg r) ->
    encodeRexR r ||| encodeRexX s ||| encodeRexB bReg
  | TwoOperands (OprReg r, OprMem (Some bReg, None, _, _))
  | TwoOperands (OprMem (Some bReg, None, _, _), OprReg r) ->
    encodeRexR r ||| encodeRexB bReg
  | TwoOperands (OprReg r, OprMem (None, None, _, _))
  | TwoOperands (OprMem (None, None, _, _), OprReg r) -> encodeRexR r
  | TwoOperands (OprReg r, OprImm _) when isReg8 r -> encodeRex r
  | TwoOperands (OprReg r, OprImm _) when isOpRegFld -> encodeRexB r
  | TwoOperands (OprReg r, OprImm _) -> encodeRexR r
  | TwoOperands (OprMem (Some bReg, None, _, _), OprImm _) -> encodeRexB bReg
  | TwoOperands (OprMem (Some bReg, Some (s, _), _, _), OprImm _) ->
    encodeRexX s ||| encodeRexB bReg
  | o -> printfn "Inavlid Operand (%A)" o; Utils.futureFeature ()

let encodeREXPref arch (ins: InsInfo) rexW isMR isOpRegFld =
  if arch = Arch.IntelX86 then [||]
  else (* Arch.IntelX64 *)
    let rexW =
      match rexW with
      | Some rexW -> rexW
      | None -> 0uy
    let rxb = encodeRexRXB isMR isOpRegFld ins.Operands
    if rxb = 0uy && rexW = 0uy then [||] else [| Normal (rexW ||| rxb) |]

let private getRexRXB = function
  | REXPrefix.REXR -> 0b011uy
  | REXPrefix.REXX -> 0b101uy
  | REXPrefix.REXB -> 0b110uy
  | REXPrefix.REXRX -> 0b001uy
  | REXPrefix.REXRB -> 0b010uy
  | REXPrefix.REXXB -> 0b100uy
  | REXPrefix.REXRXB -> 0b000uy
  | REXPrefix.NOREX -> 0b111uy
  | _ -> Utils.impossible ()

let private getLeadingOpcodeByte = function (* m-mmmm *)
  | VEXType.VEXTwoByteOp -> 0b00001uy
  | VEXType.VEXThreeByteOpOne -> 0b00010uy
  | VEXType.VEXThreeByteOpTwo -> 0b00011uy
  | _ -> Utils.impossible ()

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

let getTwoByteVEX rexPref vvvv len pp op =
  let  rexR = if rexPref = REXPrefix.REXR then 0b0uy else 0b1uy
  let  vvvv = getVVVVByte vvvv
  let  vectorLen = getVLen len
  let  pp = getSIMDPref pp
  let  sndVByte = (rexR <<< 7) + (vvvv <<< 3) + (vectorLen <<< 2) + pp
  [| Normal 0b11000101uy; Normal sndVByte; Normal op |]

let getThreeByteVEX rexPref mmmmm rexW vvvv len pp op =
  let rexRXB = getRexRXB rexPref
  let mmmmm = getLeadingOpcodeByte mmmmm
  let rexW = if rexW = REXPrefix.REXW then 0b1uy else 0b0uy
  let vvvv = getVVVVByte vvvv
  let vectorLen = getVLen len
  let pp = getSIMDPref pp
  let sndVByte = (rexRXB <<< 5) + mmmmm
  let trdVByte = (rexW <<< 7) + (vvvv <<< 3) + (vectorLen <<< 2) + pp
  [| Normal 0b11000100uy; Normal sndVByte; Normal trdVByte; Normal op |]

// vim: set tw=80 sts=2 sw=2:
