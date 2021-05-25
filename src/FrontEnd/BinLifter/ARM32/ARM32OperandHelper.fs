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

module internal B2R2.FrontEnd.BinLifter.ARM32.OperandHelper

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.ARM32.ParseUtils

(* Offset *)
let memOffsetImm offset = OprMemory (OffsetMode (ImmOffset offset))

let memOffsetReg offset = OprMemory (OffsetMode (RegOffset offset))

let memOffsetAlign offset = OprMemory (OffsetMode (AlignOffset offset))

(* Pre-Indexed [<Rn>, #+/-<imm>]! *)
let memPreIdxImm offset = OprMemory (PreIdxMode (ImmOffset offset))

let memPreIdxReg offset = OprMemory (PreIdxMode (RegOffset offset))

let memPreIdxAlign offset = OprMemory (PreIdxMode (AlignOffset offset))

(* Post-Indexed *)
let memPostIdxImm offset = OprMemory (PostIdxMode (ImmOffset offset))

let memPostIdxReg offset = OprMemory (PostIdxMode (RegOffset offset))

let memPostIdxAlign offset = OprMemory (PostIdxMode (AlignOffset offset))

(* Label *)
let memLabel lbl = OprMemory (LiteralMode lbl)

(* Unindexed *)
let memUnIdxImm offset = OprMemory (UnIdxMode offset)

(* SIMD Operand *)
let toSVReg vReg = vReg |> Vector |> SFReg |> OprSIMD

let toSSReg scalar = scalar |> Scalar |> SFReg |> OprSIMD

let getCoprocCRegister = function
  | 0x00uy -> R.C0
  | 0x01uy -> R.C1
  | 0x02uy -> R.C2
  | 0x03uy -> R.C3
  | 0x04uy -> R.C4
  | 0x05uy -> R.C5
  | 0x06uy -> R.C6
  | 0x07uy -> R.C7
  | 0x08uy -> R.C8
  | 0x09uy -> R.C9
  | 0x0Auy -> R.C10
  | 0x0Buy -> R.C11
  | 0x0Cuy -> R.C12
  | 0x0Duy -> R.C13
  | 0x0Euy -> R.C14
  | 0x0Fuy -> R.C15
  | _ -> raise InvalidRegisterException

let checkUnpred cond = if cond then raise UnpredictableException else ()

let checkUndef cond = if cond then raise UndefinedException else ()

let isValidOpcode cond = if cond then raise InvalidOpcodeException else ()

let getRegister = function
  | 0x0uy -> R.R0
  | 0x1uy -> R.R1
  | 0x2uy -> R.R2
  | 0x3uy -> R.R3
  | 0x4uy -> R.R4
  | 0x5uy -> R.R5
  | 0x6uy -> R.R6
  | 0x7uy -> R.R7
  | 0x8uy -> R.R8
  | 0x9uy -> R.SB
  | 0xAuy -> R.SL
  | 0xBuy -> R.FP
  | 0xCuy -> R.IP
  | 0xDuy -> R.SP
  | 0xEuy -> R.LR
  | 0xFuy -> R.PC
  | _ -> raise InvalidRegisterException

let getVFPSRegister = function
  | 0x00uy -> R.S0
  | 0x01uy -> R.S1
  | 0x02uy -> R.S2
  | 0x03uy -> R.S3
  | 0x04uy -> R.S4
  | 0x05uy -> R.S5
  | 0x06uy -> R.S6
  | 0x07uy -> R.S7
  | 0x08uy -> R.S8
  | 0x09uy -> R.S9
  | 0x0Auy -> R.S10
  | 0x0Buy -> R.S11
  | 0x0Cuy -> R.S12
  | 0x0Duy -> R.S13
  | 0x0Euy -> R.S14
  | 0x0Fuy -> R.S15
  | 0x10uy -> R.S16
  | 0x11uy -> R.S17
  | 0x12uy -> R.S18
  | 0x13uy -> R.S19
  | 0x14uy -> R.S20
  | 0x15uy -> R.S21
  | 0x16uy -> R.S22
  | 0x17uy -> R.S23
  | 0x18uy -> R.S24
  | 0x19uy -> R.S25
  | 0x1Auy -> R.S26
  | 0x1Buy -> R.S27
  | 0x1Cuy -> R.S28
  | 0x1Duy -> R.S29
  | 0x1Euy -> R.S30
  | 0x1Fuy -> R.S31
  | _ -> raise InvalidRegisterException

let getVFPDRegister = function
  | 0x00uy -> R.D0
  | 0x01uy -> R.D1
  | 0x02uy -> R.D2
  | 0x03uy -> R.D3
  | 0x04uy -> R.D4
  | 0x05uy -> R.D5
  | 0x06uy -> R.D6
  | 0x07uy -> R.D7
  | 0x08uy -> R.D8
  | 0x09uy -> R.D9
  | 0x0Auy -> R.D10
  | 0x0Buy -> R.D11
  | 0x0Cuy -> R.D12
  | 0x0Duy -> R.D13
  | 0x0Euy -> R.D14
  | 0x0Fuy -> R.D15
  | 0x10uy -> R.D16
  | 0x11uy -> R.D17
  | 0x12uy -> R.D18
  | 0x13uy -> R.D19
  | 0x14uy -> R.D20
  | 0x15uy -> R.D21
  | 0x16uy -> R.D22
  | 0x17uy -> R.D23
  | 0x18uy -> R.D24
  | 0x19uy -> R.D25
  | 0x1Auy -> R.D26
  | 0x1Buy -> R.D27
  | 0x1Cuy -> R.D28
  | 0x1Duy -> R.D29
  | 0x1Euy -> R.D30
  | 0x1Fuy -> R.D31
  | 0x20uy -> R.FPINST2 (* VTBL, VTBX only *)
  | 0x21uy -> R.MVFR0
  | 0x22uy -> R.MVFR1
  | _ -> raise InvalidRegisterException

let getVFPQRegister = function
  | 0x00uy -> R.Q0
  | 0x01uy -> R.Q1
  | 0x02uy -> R.Q2
  | 0x03uy -> R.Q3
  | 0x04uy -> R.Q4
  | 0x05uy -> R.Q5
  | 0x06uy -> R.Q6
  | 0x07uy -> R.Q7
  | 0x08uy -> R.Q8
  | 0x09uy -> R.Q9
  | 0x0Auy -> R.Q10
  | 0x0Buy -> R.Q11
  | 0x0Cuy -> R.Q12
  | 0x0Duy -> R.Q13
  | 0x0Euy -> R.Q14
  | 0x0Fuy -> R.Q15
  | _ -> raise InvalidRegisterException

let getVFPRegister byte = function
  | 32 -> getVFPSRegister byte
  | 64 -> getVFPDRegister byte
  | 128 -> getVFPQRegister byte
  | _ -> raise InvalidOperandSizeException

let getCoprocPRegister = function
  | 0x00uy -> R.P0
  | 0x01uy -> R.P1
  | 0x02uy -> R.P2
  | 0x03uy -> R.P3
  | 0x04uy -> R.P4
  | 0x05uy -> R.P5
  | 0x06uy -> R.P6
  | 0x07uy -> R.P7
  | 0x08uy -> R.P8
  | 0x09uy -> R.P9
  | 0x0Auy -> R.P10
  | 0x0Buy -> R.P11
  | 0x0Cuy -> R.P12
  | 0x0Duy -> R.P13
  | 0x0Euy -> R.P14
  | 0x0Fuy -> R.P15
  | _ -> raise InvalidRegisterException

let getAPSR = function
  | 0b00uy -> R.APSR, None
  | 0b01uy -> R.APSR, Some PSRg
  | 0b10uy -> R.APSR, Some PSRnzcvq
  | 0b11uy -> R.APSR, Some PSRnzcvqg
  | _ -> raise InvalidRegisterException

let getCPSR = function
  | 0x0uy -> R.CPSR, None
  | 0x1uy -> R.CPSR, Some PSRc
  | 0x2uy -> R.CPSR, Some PSRx
  | 0x3uy -> R.CPSR, Some PSRxc
  | 0x4uy -> R.CPSR, Some PSRs
  | 0x5uy -> R.CPSR, Some PSRsc
  | 0x6uy -> R.CPSR, Some PSRsx
  | 0x7uy -> R.CPSR, Some PSRsxc
  | 0x8uy -> R.CPSR, Some PSRf
  | 0x9uy -> R.CPSR, Some PSRfc
  | 0xAuy -> R.CPSR, Some PSRfx
  | 0xBuy -> R.CPSR, Some PSRfxc
  | 0xCuy -> R.CPSR, Some PSRfs
  | 0xDuy -> R.CPSR, Some PSRfsc
  | 0xEuy -> R.CPSR, Some PSRfsx
  | 0xFuy -> R.CPSR, Some PSRfsxc
  | _ -> raise InvalidRegisterException

let getSPSR = function
  | 0x0uy -> R.SPSR, None
  | 0x1uy -> R.SPSR, Some PSRc
  | 0x2uy -> R.SPSR, Some PSRx
  | 0x3uy -> R.SPSR, Some PSRxc
  | 0x4uy -> R.SPSR, Some PSRs
  | 0x5uy -> R.SPSR, Some PSRsc
  | 0x6uy -> R.SPSR, Some PSRsx
  | 0x7uy -> R.SPSR, Some PSRsxc
  | 0x8uy -> R.SPSR, Some PSRf
  | 0x9uy -> R.SPSR, Some PSRfc
  | 0xAuy -> R.SPSR, Some PSRfx
  | 0xBuy -> R.SPSR, Some PSRfxc
  | 0xCuy -> R.SPSR, Some PSRfs
  | 0xDuy -> R.SPSR, Some PSRfsc
  | 0xEuy -> R.SPSR, Some PSRfsx
  | 0xFuy -> R.SPSR, Some PSRfsxc
  | _ -> raise InvalidRegisterException

let getBankedRegs r sysM =
  match r, sysM with
  | 0b0u, 0b00000u -> R.R8usr
  | 0b0u, 0b00001u -> R.R9usr
  | 0b0u, 0b00010u -> R.R10usr
  | 0b0u, 0b00011u -> R.R11usr
  | 0b0u, 0b00100u -> R.R12usr
  | 0b0u, 0b00101u -> R.SPusr
  | 0b0u, 0b00110u -> R.LRusr
  | 0b0u, 0b01000u -> R.R8fiq
  | 0b0u, 0b01001u -> R.R9fiq
  | 0b0u, 0b01010u -> R.R10fiq
  | 0b0u, 0b01011u -> R.R11fiq
  | 0b0u, 0b01100u -> R.R12fiq
  | 0b0u, 0b01101u -> R.SPfiq
  | 0b0u, 0b01110u -> R.LRfiq
  | 0b0u, 0b10000u -> R.LRirq
  | 0b0u, 0b10001u -> R.SPirq
  | 0b0u, 0b10010u -> R.LRsvc
  | 0b0u, 0b10011u -> R.SPsvc
  | 0b0u, 0b10100u -> R.LRabt
  | 0b0u, 0b10101u -> R.SPabt
  | 0b0u, 0b10110u -> R.LRund
  | 0b0u, 0b10111u -> R.SPund
  | 0b0u, 0b11100u -> R.LRmon
  | 0b0u, 0b11101u -> R.SPmon
  | 0b0u, 0b11110u -> R.ELRhyp
  | 0b0u, 0b11111u -> R.SPhyp
  | 0b1u, 0b01110u -> R.SPSRfiq
  | 0b1u, 0b10000u -> R.SPSRirq
  | 0b1u, 0b10010u -> R.SPSRsvc
  | 0b1u, 0b10100u -> R.SPSRabt
  | 0b1u, 0b10110u -> R.SPSRund
  | 0b1u, 0b11100u -> R.SPSRmon
  | 0b1u, 0b11110u -> R.SPSRhyp
  | _ -> raise UnpredictableException

let getOption = function
  | 0b0010uy -> Option.OSHST
  | 0b0011uy -> Option.OSH
  | 0b0110uy -> Option.NSHST
  | 0b0111uy -> Option.NSH
  | 0b1010uy -> Option.ISHST
  | 0b1011uy -> Option.ISH
  | 0b1110uy -> Option.ST
  | 0b1111uy -> Option.SY
  | _ -> raise ParsingFailureException

let getIflag = function
  | 0b100uy -> A
  | 0b010uy -> I
  | 0b001uy -> F
  | 0b110uy -> AI
  | 0b101uy -> AF
  | 0b011uy -> IF
  | 0b111uy -> AIF
  | _ -> raise ParsingFailureException

let getEndian = function
  | 0b0uy -> Endian.Little
  | _ (* 1 *) -> Endian.Big

let getFloatSizeBySz = function
  | 0b0u -> SIMDTypF32
  | _ (* 1 *) -> SIMDTypF64

let getSignednessSize32ByOp = function
  | 0b0u -> SIMDTypU32
  | 0b1u -> SIMDTypS32
  | _ -> raise ParsingFailureException

let getSignednessSizeBySizeNU size u =
  match size, u with
  | 0b00u, 0b0u -> SIMDTypS8
  | 0b01u, 0b0u -> SIMDTypS16
  | 0b10u, 0b0u -> SIMDTypS32
  | 0b11u, 0b0u -> SIMDTypS64
  | 0b00u, 0b1u -> SIMDTypU8
  | 0b01u, 0b1u -> SIMDTypU16
  | 0b10u, 0b1u -> SIMDTypU32
  | 0b11u, 0b1u -> SIMDTypU64
  | _ -> raise ParsingFailureException

let getIntegerSizeBySize = function
  | 0b00u -> SIMDTypI8
  | 0b01u -> SIMDTypI16
  | 0b10u -> SIMDTypI32
  | 0b11u -> SIMDTypI64
  | _ -> raise ParsingFailureException

let getIntegerSizeBySize2 = function
  | 0b00u -> SIMDTypI16
  | 0b01u -> SIMDTypI32
  | 0b10u -> SIMDTypI64
  | _ -> raise ParsingFailureException

let getSignedSizeBySize = function
  | 0b00u -> SIMDTypS8
  | 0b01u -> SIMDTypS16
  | 0b10u -> SIMDTypS32
  | 0b11u -> SIMDTypS64
  | _ -> raise ParsingFailureException

let getSizeBySize = function
  | 0b00u -> SIMDTyp8
  | 0b01u -> SIMDTyp16
  | 0b10u -> SIMDTyp32
  | 0b11u -> SIMDTyp64
  | _ -> raise ParsingFailureException

let getIntSizeBySizeNF size f =
  match size, f with
  | 0b00u, 0b0u -> SIMDTypI8
  | 0b01u, 0b0u -> SIMDTypI16
  | 0b10u, 0b0u -> SIMDTypI32
  | 0b01u, 0b1u -> SIMDTypF16
  | 0b10u, 0b1u -> SIMDTypF32
  | _ -> raise ParsingFailureException

let getSizeBySizeForVLD4 = function
  | 0b00u -> SIMDTyp8
  | 0b01u -> SIMDTyp16
  | 0b10u -> SIMDTyp32
  | 0b11u -> SIMDTyp32
  | _ -> raise ParsingFailureException

let getSignednessSizeByUNSx u sx =
  match u, sx with
  | 0u, 0u -> SIMDTypS16
  | 1u, 0u -> SIMDTypU16
  | 0u, 1u -> SIMDTypS32
  | 1u, 1u -> SIMDTypU32
  | _ -> raise ParsingFailureException

let getVFPBits bit vbits = function
  | 32 -> concat vbits bit 1
  | 64 -> concat bit vbits 4
  | 128 -> concat bit (vbits >>> 1) 3
  | _ -> raise InvalidOperandSizeException

let getVRegWithOffset e1 e2 offset regSize =
  getVFPRegister (getVFPBits e1 e2 regSize + offset |> byte) regSize

let getVReg e1 e2 regSize =
  getVFPRegister (getVFPBits e1 e2 regSize |> byte) regSize

let getRegList b =
  let rec loop acc = function
    | n when n > 15 -> acc
    | n when ((b >>> n) &&& 1u) <> 0u ->
      loop (getRegister (byte n) :: acc) (n + 1)
    | n -> loop acc (n + 1)
  loop [] 0 |> List.rev

let getSIMDVFPOprRegList d vd rs sz =
  let rec aux acc i rs =
    if rs > 0u then
      aux ((getVRegWithOffset d vd i sz) :: acc) (i + 1u) (rs - 1u)
    else acc |> List.rev
  aux [] 0u rs

(* SIMD vector register list *)
let getSIMDVector rLst =
  match rLst with
  | [ vt ] -> OneReg (Vector vt)
  | [ vt; vt2 ] -> TwoRegs (Vector vt, Vector vt2)
  | [ vt; vt2; vt3 ] -> ThreeRegs (Vector vt, Vector vt2, Vector vt3)
  | [ vt; vt2; vt3; vt4 ] ->
    FourRegs (Vector vt, Vector vt2, Vector vt3, Vector vt4)
  | _ -> raise ParsingFailureException
  |> OprSIMD

(* SIMD scalar list *)
let getSIMDScalar idx rLst =
  let s v = Scalar (v, idx)
  match rLst with
  | [ vt ] -> OneReg (s vt)
  | [ vt; vt2 ] -> TwoRegs (s vt, s vt2)
  | [ vt; vt2; vt3 ] -> ThreeRegs (s vt, s vt2, s vt3)
  | [ vt; vt2; vt3; vt4 ] -> FourRegs (s vt, s vt2, s vt3, s vt4)
  | _ -> raise ParsingFailureException
  |> OprSIMD

let getShiftOprByRotate = function
  | 0b00u -> OprShift (SRTypeROR, Imm 0u) // omitted when it is disassembled
  | 0b01u -> OprShift (SRTypeROR, Imm 8u)
  | 0b10u -> OprShift (SRTypeROR, Imm 16u)
  | 0b11u -> OprShift (SRTypeROR, Imm 24u)
  | _ -> raise ParsingFailureException

let getIdxForVStoreLoad1 ia = function
  | 0b00u when pickBit ia 0 = 0b0u -> Some (extract ia 3 1 |> uint8)
  | 0b01u when extract ia 1 0 = 0b00u -> Some (extract ia 3 2 |> uint8)
  | 0b01u when extract ia 1 0 = 0b01u -> Some (extract ia 3 2 |> uint8)
  | 0b10u when extract ia 2 0 = 0b000u -> Some (pickBit ia 3 |> uint8)
  | 0b10u when extract ia 2 0 = 0b011u -> Some (pickBit ia 3 |> uint8)
  | _ -> raise ParsingFailureException

let getIdxForVStoreLoad2 ia = function
  | 0b00u -> Some (extract ia 3 1 |> uint8)
  | 0b01u -> Some (extract ia 3 2 |> uint8)
  | 0b10u when extract ia 2 0 = 0b000u -> Some (pickBit ia 3 |> uint8)
  | 0b10u when extract ia 2 0 = 0b001u -> Some (pickBit ia 3 |> uint8)
  | 0b10u when extract ia 2 0 = 0b100u -> Some (pickBit ia 3 |> uint8)
  | 0b10u when extract ia 2 0 = 0b101u -> Some (pickBit ia 3 |> uint8)
  | _ -> raise ParsingFailureException

let getSpaceForVStoreLoad2 ia = function
  | 0b00u -> Single
  | 0b01u when extract ia 1 0 = 0b00u -> Single
  | 0b01u when extract ia 1 0 = 0b01u -> Single
  | 0b01u when extract ia 1 0 = 0b10u -> Double
  | 0b01u when extract ia 1 0 = 0b11u -> Double
  | 0b10u when extract ia 2 0 = 0b000u -> Single
  | 0b10u when extract ia 2 0 = 0b001u -> Single
  | 0b10u when extract ia 2 0 = 0b100u -> Double
  | 0b10u when extract ia 2 0 = 0b101u -> Double
  | _ -> raise ParsingFailureException

let getIdxForVStoreLoad3 ia = function
  | 0b00u when pickBit ia 0 = 0b0u -> Some (extract ia 3 1 |> uint8)
  | 0b01u when extract ia 1 0 = 0b00u -> Some (extract ia 3 2 |> uint8)
  | 0b01u when extract ia 1 0 = 0b10u -> Some (extract ia 3 2 |> uint8)
  | 0b10u when extract ia 2 0 = 0b000u -> Some (pickBit ia 3 |> uint8)
  | 0b10u when extract ia 2 0 = 0b100u -> Some (pickBit ia 3 |> uint8)
  | _ -> raise ParsingFailureException

let getSpaceForVStoreLoad3 ia = function
  | 0b00u when pickBit ia 0 = 0b0u -> Single
  | 0b01u when extract ia 1 0 = 0b00u -> Single
  | 0b01u when extract ia 1 0 = 0b10u -> Double
  | 0b10u when extract ia 2 0 = 0b000u -> Single
  | 0b10u when extract ia 2 0 = 0b100u -> Double
  | _ -> raise ParsingFailureException

let getIdxForVStoreLoad4 ia = function
  | 0b00u -> Some (extract ia 3 1 |> uint8)
  | 0b01u -> Some (extract ia 3 2 |> uint8)
  | 0b10u when extract ia 2 0 = 0b000u -> Some (pickBit ia 3 |> uint8)
  | 0b10u when extract ia 2 0 = 0b001u -> Some (pickBit ia 3 |> uint8)
  | 0b10u when extract ia 2 0 = 0b010u -> Some (pickBit ia 3 |> uint8)
  | 0b10u when extract ia 2 0 = 0b100u -> Some (pickBit ia 3 |> uint8)
  | 0b10u when extract ia 2 0 = 0b101u -> Some (pickBit ia 3 |> uint8)
  | 0b10u when extract ia 2 0 = 0b110u -> Some (pickBit ia 3 |> uint8)
  | _ -> raise ParsingFailureException

let getSpaceForVStoreLoad4 ia = function
  | 0b00u -> Single
  | 0b01u when extract ia 1 0 = 0b00u -> Single
  | 0b01u when extract ia 1 0 = 0b01u -> Single
  | 0b01u when extract ia 1 0 = 0b10u -> Double
  | 0b01u when extract ia 1 0 = 0b11u -> Double
  | 0b10u when extract ia 2 0 = 0b000u -> Single
  | 0b10u when extract ia 2 0 = 0b001u -> Single
  | 0b10u when extract ia 2 0 = 0b010u -> Single
  | 0b10u when extract ia 2 0 = 0b100u -> Double
  | 0b10u when extract ia 2 0 = 0b101u -> Double
  | 0b10u when extract ia 2 0 = 0b110u -> Double
  | _ -> raise ParsingFailureException

let getImm11110 opcode i =
  isValidOpcode (opcode <> Op.VMOV)
  let getImm n = pickBit i n |> int64
  0xf0000000L * getImm 7 + 0x0f000000L * getImm 6 + 0x00f00000L * getImm 5 +
  0x000f0000L * getImm 4 + 0x0000f000L * getImm 3 + 0x00000f00L * getImm 2 +
  0x000000f0L * getImm 1 + 0x0000000fL * getImm 0

let getImm01111 opcode i = // FIXME : immediate encoding
  isValidOpcode (opcode <> Op.VMOV)
  let a = pickBit (i |> uint32) 7 |> int64
  let b = pickBit (i |> uint32) 6 |> int64
  let b5 = b + (b <<< 1) + (b <<< 2) + (b <<< 3) + (b <<< 4)
  let cdefg = extract (i |> uint32) 5 0 |> int64
  (a <<< 63) + ((b ^^^ 1L) <<< 62) + (b5 <<< 57) + (cdefg <<< 51) +
  (a <<< 31) + ((b ^^^ 1L) <<< 30) + (b5 <<< 25) + (cdefg <<< 19)

let getFloatingPointImm64 i = // FIXME : immediate encoding
  let a = pickBit (i |> uint32) 7 |> int64
  let b = pickBit (i |> uint32) 6 |> int64
  let b8 = b + (b <<< 1) + (b <<< 2) + (b <<< 3) + (b <<< 4) +
           (b <<< 5) + (b <<< 6) + (b <<< 7)
  let cdefg = extract (i |> uint32) 5 0 |> int64
  (a <<< 63) + ((b ^^^ 1L) <<< 62) + (b8 <<< 54) + (cdefg <<< 48)

let getFloatingPointImm32 i = // FIXME : immediate encoding
  let a = pickBit (i |> uint32) 7 |> int64
  let b = pickBit (i |> uint32) 6 |> int64
  let b5 = b + (b <<< 1) + (b <<< 2) + (b <<< 3) + (b <<< 4)
  let cdefg = extract (i |> uint32) 5 0 |> int64
  (a <<< 31) + ((b ^^^ 1L) <<< 30) + (b5 <<< 25) + (cdefg <<< 19)

let getReg b s e = getRegister (extract b s e |> byte)

let getSign s = if s = 1u then Plus else Minus

let parseOneOpr b checkfn opr = checkfn b opr; OneOperand (opr b)

let parseTwoOprs b checkfn ((op1, op2) as oprs) =
  checkfn b oprs; TwoOperands (op1 b, op2 b)

let parseThreeOprs b checkfn ((op1, op2, op3) as oprs) =
  checkfn b oprs; ThreeOperands (op1 b, op2 b, op3 b)

let parseFourOprs b checkfn ((op1, op2, op3, op4) as oprs) =
  checkfn b oprs; FourOperands (op1 b, op2 b, op3 b, op4 b)

let parseFiveOprs b checkfn ((op1, op2, op3, op4, op5) as oprs) =
  checkfn b oprs; FiveOperands (op1 b, op2 b, op3 b, op4 b, op5 b)

let parseSixOprs b checkfn ((op1, op2, op3, op4, op5, op6) as oprs) =
  checkfn b oprs; SixOperands (op1 b, op2 b, op3 b, op4 b, op5 b, op6 b)

let inline p1Opr b = parseOneOpr b
let inline p2Oprs b = parseTwoOprs b
let inline p3Oprs b = parseThreeOprs b
let inline p4Oprs b = parseFourOprs b
let inline p5Oprs b = parseFiveOprs b
let inline p6Oprs b = parseSixOprs b

let getRegA b = getReg b 3 0 |> OprReg
let getRegB b = getReg b 11 8 |> OprReg
let getRegC b = getReg b 19 16 |> OprReg
let getRegD b = getReg b 15 12 |> OprReg
let getRegE _ = OprReg R.APSR
let getRegF b = getRegister (extract b 3 0 + 1u |> byte) |> OprReg
let getRegG b = getReg b 8 6 |> OprReg
let getRegH b = getReg b 5 3 |> OprReg
let getRegI b = getReg b 2 0 |> OprReg
let getRegJ b = getReg b 10 8 |> OprReg
let getRegK b =
  let mask = extract b 19 16
  if pickBit b 22 = 0b0u then getCPSR (mask |> byte) |> OprSpecReg
  else getSPSR (mask |> byte) |> OprSpecReg
let getRegL b = getRegister (extract b 15 12 + 1u |> byte) |> OprReg
let getRegM b = OprReg R.SP
let getRegN b = OprReg (getReg b 19 16)
let getRegO b = concat (pickBit b 7) (extract b 2 0) 3 |> byte
                |> getRegister |> OprReg
let getRegP b = getReg b 6 3 |> OprReg
let getRegQ b =
  let mask = extract b 19 16
  if pickBit b 22 = 0u then getCPSR (byte mask) |> OprSpecReg
  else getSPSR (byte mask) |> OprSpecReg
let getRegR q b =
  let regSize = if q = 0u then 64 else 128
  getVReg (pickBit b 22) (extract b 15 12) regSize |> toSVReg
let getRegS q b =
  let regSize = if q = 0u then 64 else 128
  getVReg (pickBit b 7) (extract b 19 16) regSize |> toSVReg
let getRegT q b =
  let regSize = if q = 0u then 64 else 128
  getVReg (pickBit b 5) (extract b 3 0) regSize |> toSVReg
let getRegU b = concat (pickBit b 7) (extract b 19 16 >>> 1) 3 |> byte
                |> getVFPQRegister |> toSVReg
let getRegV b = concat (pickBit b 7) (extract b 19 16) 4 |> byte
                |> getVFPDRegister |> toSVReg
let getRegX b =
  let regSize = if pickBit b 6 = 0u then 64 else 128
  getVReg (pickBit b 22) (extract b 15 12) regSize |> toSVReg
let getRegY b =
  let regSize = if pickBit b 6 = 0u then 64 else 128
  getVReg (pickBit b 7) (extract b 19 16) regSize |> toSVReg
let getRegZ b =
  let regSize = if pickBit b 6 = 0u then 64 else 128
  getVReg (pickBit b 5) (extract b 3 0) regSize |> toSVReg
let getRegAA b = OprReg (getReg b 19 16)
let getRegAB b =
  let regSize = if pickBit b 21 = 0u then 64 else 128
  getVReg (pickBit b 7) (extract b 19 16) regSize |> toSVReg
let getRegAC b = concat (pickBit b 22) (extract b 15 12) 4 |> byte
                 |> getVFPDRegister |> toSVReg
let getRegAD b = concat (pickBit b 5) (extract b 3 0 >>> 1) 3 |> byte
                 |> getVFPQRegister |> toSVReg
let getRegAE b = concat (pickBit b 22) (extract b 15 12 >>> 1) 3 |> byte
                 |> getVFPQRegister |> toSVReg
let getRegAF b = concat (pickBit b 5) (extract b 3 0) 4 |> byte
                 |> getVFPDRegister |> toSVReg
let getRegAG b =
  let regSize = if pickBit b 8 = 0u then 64 else 128
  getVReg (pickBit b 7) (extract b 19 16) regSize |> toSVReg
let getRegAH b =
  let regSize = if pickBit b 8 = 0u then 64 else 128
  getVReg (pickBit b 5) (extract b 3 0) regSize |> toSVReg
let getRegAI b =
  let regSize = if pickBit b 8 = 0u then 64 else 128
  getVReg (pickBit b 22) (extract b 15 12) regSize |> toSVReg
let getRegAJ b = concat (extract b 3 0) (pickBit b 5) 1 |> byte
                 |> getVFPSRegister |> toSVReg
let getRegAK b = (concat (extract b 15 12) (pickBit b 22) 1) + 1u |> byte
                 |> getVFPSRegister |> toSVReg
let getRegAL b =
  let regSize = if pickBit b 8 = 0u then 32 else 64
  getVReg (pickBit b 22) (extract b 15 12) regSize |> toSVReg
let getRegAL' b =
  let regSize = if pickBit b 8 = 0u then 64 else 32
  getVReg (pickBit b 22) (extract b 15 12) regSize |> toSVReg
let getRegAM b =
  let regSize = if pickBit b 8 = 0u then 32 else 64
  getVReg (pickBit b 7) (extract b 19 16) regSize |> toSVReg
let getRegAN b =
  let regSize = if pickBit b 8 = 0u then 32 else 64
  getVReg (pickBit b 5) (extract b 3 0) regSize |> toSVReg
let getRegAO b = concat (extract b 15 12) (pickBit b 22) 1 |> byte
                 |> getVFPSRegister |> toSVReg
let getRegAP b =
  let regSize =
    match extract b 18 16, pickBit b 8 with
    | 0b000u, 0b1u -> 64
    | 0b101u, _ | 0b100u, _ | 0b000u, 0b0u -> 32
    | _ -> raise ParsingFailureException
  getVReg (pickBit b 22) (extract b 15 12) regSize |> toSVReg

let getRegAQ b =
  let regSize =
    match extract b 18 16, pickBit b 8 with
    | 0b101u, 0b1u | 0b100u, 0b1u -> 64
    | 0b101u, 0b0u | 0b100u, 0b0u | 0b000u, _ -> 32
    | _ -> raise ParsingFailureException
  getVReg (pickBit b 5) (extract b 3 0) regSize |> toSVReg

let getRegAR b =
  match extract b 18 16, pickBit b 8 with
  | 0b101u, _ | 0b100u, _ ->
      concat (extract b 15 12) (pickBit b 22) 1 |> byte
      |> getVFPSRegister |> toSVReg
  | _ -> raise ParsingFailureException

let getRegAS b =
  let regSize =
    match extract b 18 16, pickBit b 8 with
    | 0b101u, 0b1u | 0b100u, 0b1u -> 64
    | 0b101u, 0b0u | 0b100u, 0b0u -> 32
    | _ -> raise ParsingFailureException
  getVReg (pickBit b 5) (extract b 3 0) regSize |> toSVReg

let getRegAT b = let regSize = if pickBit b 8  = 1u then 64 else 32
                 getVReg (pickBit b 22) (extract b 15 12) regSize |> toSVReg

let getRegAU b = concat (extract b 19 16) (pickBit b 7) 1 |> byte
                 |> getVFPSRegister |> toSVReg

let getRegAV (_, b2) = extract b2 11 8 |> byte |> getRegister |> OprReg
let getRegAW (_, b2) = extract b2 15 12 |> byte |> getRegister |> OprReg
let getRegAX (_, b2) = extract b2 3 0 |> byte |> getRegister |> OprReg
let getRegAY (b1, _) = extract b1 3 0 |> byte |> getRegister |> OprReg
let getRegAZ b = let reg = getReg b 15 12
                 if reg = R.PC then OprSpecReg (R.APSR, Some PSRnzcv)
                 else OprReg reg

let getRegSP _ = OprReg R.SP
let getRegPC _ = OprReg R.PC
let getRegLR _ = OprReg R.LR
let getAPSRxA b = let mask = extract b 19 18
                  checkUnpred (mask = 00u)
                  mask |> byte |> getAPSR |> OprSpecReg
let getAPSRxB b = extract b 19 18 |> byte |> getAPSR |> OprSpecReg
let getAPSRxC (_, b2) = extract b2 11 10 |> byte |> getAPSR |> OprSpecReg
let getxPSRxA (b1, b2) =
  let mask = extract b2 11 8
  if pickBit b1 4 = 0u then getCPSR (mask |> byte) |> OprSpecReg
  else getSPSR (mask |> byte) |> OprSpecReg
let getxPSRxB (b1, _) =
  if pickBit b1 4 = 0b0u then R.APSR |> OprReg else R.SPSR |> OprReg
let getRegFPSCR _ = OprReg R.FPSCR
let getBankedRegA bin =
  let sysM = concat (pickBit bin 8) (extract bin 19 16) 4
  getBankedRegs (pickBit bin 22) sysM |> OprReg
let getBankedRegB (_, b2) =
  let sysM = concat (pickBit b2 4) (extract b2 11 8) 4
  getBankedRegs 0b1u sysM |> OprReg
let getBankedRegC (b1, b2) =
  let sysM = concat (pickBit b2 4) (extract b1 3 0) 4
  getBankedRegs (pickBit b1 4) sysM |> OprReg
let getRegisterWA b = getRegister (extract b 19 16 |> byte) |> OprReg
let getRegisterWB (b1, _) = getRegister (extract b1 3 0 |> byte) |> OprReg
let getRegisterWC b = OprReg (getRegister (extract b 10 8 |> byte))
let getRegisterWD b =
  let rn = getRegister (extract b 10 8 |> byte)
  let rl = extract b 7 0 |> getRegList
  if List.exists (fun e -> e = rn) rl then OprReg rn
  else OprReg rn
let getCRegA b = extract b 15 12 |> byte |> getCoprocCRegister |> OprReg
let getCRegB b = extract b 3 0 |> byte |> getCoprocCRegister |> OprReg
let getCRegC b = extract b 19 16 |> byte |> getCoprocCRegister |> OprReg
let getPRegA b = extract b 11 8 |> byte |> getCoprocPRegister |> OprReg

let getRegListA b =
  let d = concat (pickBit b 7) (extract b 19 16) 4
  match extract b 9 8 with
  | 0b00u -> getSIMDVector [ getVFPDRegister (d |> byte) ]
  | 0b01u -> getSIMDVector [ getVFPDRegister (d |> byte);
                             getVFPDRegister (d + 1u |> byte) ]
  | 0b10u -> getSIMDVector [ getVFPDRegister (d |> byte);
                             getVFPDRegister (d + 1u |> byte);
                             getVFPDRegister (d + 2u |> byte) ]
  | 0b11u -> getSIMDVector [ getVFPDRegister (d |> byte);
                             getVFPDRegister (d + 1u |> byte);
                             getVFPDRegister (d + 2u |> byte);
                             getVFPDRegister (d + 3u |> byte) ]
  | _ -> raise ParsingFailureException

let getRegListB b =
  let d = concat (pickBit b 22) (extract b 15 12) 4
  match extract b 11 8 with
  | 0b0111u -> getSIMDVector [ getVFPDRegister (d |> byte) ]
  | 0b1010u
  | 0b1000u -> getSIMDVector [ getVFPDRegister (d |> byte);
                               getVFPDRegister (d + 1u |> byte); ]
  | 0b1001u -> getSIMDVector [ getVFPDRegister (d |> byte);
                               getVFPDRegister (d + 2u |> byte); ]
  | 0b0110u
  | 0b0100u -> getSIMDVector [ getVFPDRegister (d |> byte);
                               getVFPDRegister (d + 1u |> byte);
                               getVFPDRegister (d + 2u |> byte) ]
  | 0b0101u -> getSIMDVector [ getVFPDRegister (d |> byte);
                               getVFPDRegister (d + 2u |> byte);
                               getVFPDRegister (d + 4u |> byte) ]
  | 0b0010u | 0b0011u
  | 0b0000u -> getSIMDVector [ getVFPDRegister (d |> byte);
                               getVFPDRegister (d + 1u |> byte);
                               getVFPDRegister (d + 2u |> byte);
                               getVFPDRegister (d + 3u |> byte) ]
  | 0b0001u -> getSIMDVector [ getVFPDRegister (d |> byte);
                               getVFPDRegister (d + 2u |> byte);
                               getVFPDRegister (d + 4u |> byte);
                               getVFPDRegister (d + 6u |> byte) ]
  | _ -> raise ParsingFailureException

let getRegListC b =
  let d = concat (pickBit b 22) (extract b 15 12) 4
  let i = getIdxForVStoreLoad1 (extract b 7 4) (extract b 11 10)
  getSIMDScalar i [ getVFPDRegister (d |> byte) ]

let getRegListD b =
  let d = concat (pickBit b 22) (extract b 15 12) 4
  let ia = extract b 7 4
  let sz = extract b 11 10
  let i = getIdxForVStoreLoad2 ia sz
  match getSpaceForVStoreLoad2 ia sz with
  | Single -> getSIMDScalar i [ getVFPDRegister (d |> byte);
                                getVFPDRegister (d + 1u |> byte); ]
  | Double -> getSIMDScalar i [ getVFPDRegister (d |> byte);
                                getVFPDRegister (d + 2u |> byte); ]

let getRegListE b =
  let d = concat (pickBit b 22) (extract b 15 12) 4
  let ia = extract b 7 4
  let sz = extract b 11 10
  let i = getIdxForVStoreLoad3 ia sz
  match getSpaceForVStoreLoad3 ia sz with
  | Single -> getSIMDScalar i [ getVFPDRegister (d |> byte);
                                getVFPDRegister (d + 1u |> byte);
                                getVFPDRegister (d + 2u |> byte); ]
  | Double -> getSIMDScalar i [ getVFPDRegister (d |> byte);
                                getVFPDRegister (d + 2u |> byte);
                                getVFPDRegister (d + 4u |> byte); ]

let getRegListF b =
  let d = concat (pickBit b 22) (extract b 15 12) 4
  let ia = extract b 7 4
  let sz = extract b 11 10
  let i = getIdxForVStoreLoad4 ia sz
  match getSpaceForVStoreLoad4 ia sz with
  | Single -> getSIMDScalar i [ getVFPDRegister (d |> byte);
                                getVFPDRegister (d + 1u |> byte);
                                getVFPDRegister (d + 2u |> byte);
                                getVFPDRegister (d + 3u |> byte) ]
  | Double -> getSIMDScalar i [ getVFPDRegister (d |> byte);
                                getVFPDRegister (d + 2u |> byte);
                                getVFPDRegister (d + 4u |> byte);
                                getVFPDRegister (d + 6u |> byte) ]

let getRegListG b =
  let d = concat (pickBit b 22) (extract b 15 12) 4
  if pickBit b 5 = 0b0u then
    getSIMDScalar None [ getVFPDRegister (d |> byte) ]
  else getSIMDScalar None [ getVFPDRegister (d |> byte);
                            getVFPDRegister (d + 1u |> byte) ]

let getRegListH b =
  let d = concat (pickBit b 22) (extract b 15 12) 4
  if pickBit b 5 = 0b0u then
    getSIMDScalar None [ getVFPDRegister (d |> byte);
                         getVFPDRegister (d + 1u |> byte) ]
  else getSIMDScalar None [ getVFPDRegister (d |> byte);
                            getVFPDRegister (d + 2u |> byte) ]

let getRegListI b =
  let d = concat (pickBit b 22) (extract b 15 12) 4
  if pickBit b 5 = 0b0u then
    getSIMDScalar None [ getVFPDRegister (d |> byte);
                         getVFPDRegister (d + 1u |> byte);
                         getVFPDRegister (d + 2u |> byte) ]
  else getSIMDScalar None [ getVFPDRegister (d |> byte);
                            getVFPDRegister (d + 2u |> byte);
                            getVFPDRegister (d + 4u |> byte) ]

let getRegListJ b =
  let d = concat (pickBit b 22) (extract b 15 12) 4
  if pickBit b 5 = 0b0u then
    getSIMDScalar None [ getVFPDRegister (d |> byte);
                         getVFPDRegister (d + 1u |> byte);
                         getVFPDRegister (d + 2u |> byte);
                         getVFPDRegister (d + 3u |> byte) ]
  else getSIMDScalar None [ getVFPDRegister (d |> byte);
                            getVFPDRegister (d + 2u |> byte);
                            getVFPDRegister (d + 4u |> byte);
                            getVFPDRegister (d + 6u |> byte) ]

let getRegListK b = extract b 15 0 |> getRegList |> OprRegList
let getRegListL b =
  getSIMDVFPOprRegList (pickBit b 22)
                       (extract b 15 12)
                       ((extract b 7 0) / 2u) 64
  |> OprRegList
let getRegListM b =
  getSIMDVFPOprRegList (pickBit b 22) (extract b 15 12) (extract b 7 0) 32
  |> OprRegList
let getRegListN b =
  ((pickBit b 8) <<< 14) + (extract b 7 0) |> getRegList |> OprRegList
let getRegListO b =
  ((pickBit b 8) <<< 15) + (extract b 7 0) |> getRegList |> OprRegList
let getRegListP (_, b2) =
  concat ((pickBit b2 14) <<< 1) (extract b2 12 0) 13 |> getRegList
  |> OprRegList
let getRegListQ (_, b2) =
  concat ((extract b2 15 14) <<< 1) (extract b2 12 0) 13 |> getRegList
  |> OprRegList
let getRegListR b = extract b 7 0 |> getRegList |> OprRegList

let getShiftImm5A b = concat (extract b 14 12) (extract b 7 6) 2
let getShift typ imm =
  let struct (shift, imm) = decodeImmShift typ imm in OprShift (shift, Imm imm)
let getShiftA b =
  OprRegShift (decodeRegShift (extract b 6 5), getReg b 11 8)
let getShiftB b = getShift (extract b 6 5) (extract b 11 7)
let getShiftC b = extract b 11 10 |> getShiftOprByRotate
let getShiftD b = getShift (pickBit b 6 <<< 1) (extract b 11 7)
let getShiftF (_, b2) = getShift (extract b2 5 4) (getShiftImm5A b2)
let getShiftI (b1, b2) = getShift (pickBit b1 5 <<< 1) (getShiftImm5A b2)
let getShiftJ (_, b2) = extract b2 5 4 |> getShiftOprByRotate

let getImm0 _ = OprImm 0L

let replicate value width n =
  let rec loop acc idx =
    if idx = 0 then acc else loop (acc ||| (acc <<< (width * idx))) (idx - 1)
  loop (int64 value) (n - 1)

let getImmA opcode i b =
  let chk1 i = checkUnpred (i = 0u)
  let chk2 i = isValidOpcode (opcode <> Op.VMOV || opcode <> Op.VMVN); chk1 i
  let i = concat (concat i (extract b 18 16) 3) (extract b 3 0) 4
  match concat (pickBit b 5) (extract b 11 8) 4 with
  | r when r &&& 0b00110u = 0b00000u -> i |> int64 |> OprImm
  | r when r &&& 0b01110u = 0b00010u -> chk1 i; i <<< 8 |> int64 |> OprImm
  | r when r &&& 0b01110u = 0b00100u -> chk1 i; i <<< 16 |> int64 |> OprImm
  | r when r &&& 0b01110u = 0b00110u -> chk1 i; i <<< 24 |> int64 |> OprImm
  | r when r &&& 0b01110u = 0b01010u -> chk1 i; i <<< 8 |> int64 |> OprImm
  | r when r &&& 0b01111u = 0b01100u ->
    chk2 i; 0xffu + (i <<< 8) |> int64 |> OprImm
  | r when r &&& 0b01111u = 0b01101u ->
    chk2 i; 0xffu + (0xffu <<< 8) + (i <<< 16) |> int64 |> OprImm
  | 0b01110u -> isValidOpcode (opcode <> Op.VMOV); replicate i 8 8 |> OprImm
  | 0b11110u -> getImm11110 opcode i |> OprImm
  | 0b01111u -> getImm01111 opcode i |> OprImm
  | _ -> raise UndefinedException

let getImmB b =
  match concat (pickBit b 7) (extract b 21 16) 6 with
  | i when i &&& 0b1111000u = 0b1000u -> 8L - (extract b 18 16 |> int64)
  | i when i &&& 0b1110000u = 0b10000u -> 16L - (extract b 19 16 |> int64)
  | i when i &&& 0b1100000u = 0b100000u -> 32L - (extract b 20 16 |> int64)
  | i when i &&& 0b1000000u > 0u -> 64L - (extract b 21 16 |> int64)
  | _ -> raise ParsingFailureException
  |> OprImm

let getImmC b =
  match concat (pickBit b 7) (extract b 21 19) 3 with
  | 1u -> extract b 18 16 |> int64 |> OprImm
  | i when i &&& 0b1110u = 0b0010u -> extract b 19 16 |> int64 |> OprImm
  | i when i &&& 0b1100u = 0b0100u -> extract b 20 16 |> int64 |> OprImm
  | i when i &&& 0b1000u = 0b1000u -> extract b 21 16 |> int64 |> OprImm
  | _ -> raise ParsingFailureException

let getImmD b =
  match extract b 21 19 with
  | 1u -> 8L - (extract b 18 16 |> int64)
  | i when i &&& 0b110u = 0b010u -> 16L - (extract b 19 16 |> int64)
  | i when i &&& 0b100u = 0b100u -> 32L - (extract b 20 16 |> int64)
  | _ -> raise ParsingFailureException
  |> OprImm
let getImmE b =
  match extract b 21 19 with
  | i when i &&& 0b111u = 0b001u -> 8L - (extract b 18 16 |> int64)
  | i when i &&& 0b110u = 0b010u -> 16L - (extract b 19 16 |> int64)
  | i when i &&& 0b100u = 0b100u -> 32L - (extract b 20 16 |> int64)
  | _ -> raise ParsingFailureException
  |> OprImm
let getImmF b =
  match extract b 21 19  with
  | i when i &&& 0b111u = 0b001u -> extract b 18 16 |> int64 |> OprImm
  | i when i &&& 0b110u = 0b010u -> extract b 19 16 |> int64 |> OprImm
  | i when i &&& 0b100u = 0b100u -> extract b 20 16 |> int64 |> OprImm
  | _ -> raise ParsingFailureException
let getImmG b = 64L - (extract b 21 16 |> int64) |> OprImm
let getImmH b =
  let imm = concat (extract b 19 16) (extract b 3 0) 4 |> int64
  match pickBit b 8 with
  | 0b0u -> getFloatingPointImm32 imm |> OprImm
  | 0b1u -> getFloatingPointImm64 imm |> OprImm
  | _ -> raise ParsingFailureException
let getImmI b =
  let size = if pickBit b 7 = 0b0u then 16L else 32L
  let imm = concat (extract b 3 0) (pickBit b 5) 1 |> int64
  size - imm |> OprImm
let getImmJ (b1, b2) =
  let i = pickBit b1 10
  let i3 = extract b2 14 12
  let tp = concat i i3 3
  let rot = concat tp (pickBit b2 7) 1 |> int
  let imm = extract b2 7 0 |> int
  match rot with
  | 0b00000 | 0b00001 -> imm |> int64 |> OprImm
  | 0b00010 | 0b00011 -> ((imm <<< 16) + imm) |> int64 |> OprImm
  | 0b00100 | 0b00101 -> ((imm <<< 24) + (imm <<< 8)) |> int64 |> OprImm
  | 0b00110 | 0b00111
      -> ((imm <<< 24) + (imm <<< 16) + (imm <<< 8) + imm) |> int64 |> OprImm
  | rot ->
      let unrotated = (0b10000000 ||| imm)
      ((unrotated <<< (32 - rot)) ||| (unrotated >>> rot)) |> int64 |> OprImm

let getImmK (_, b2) =
  (extract b2 4 0) - (concat (extract b2 14 12) (extract b2 7 6) 2) + 1u
  |> int64 |> OprImm

let getImm3A b = extract b 8 6 |> int64 |> OprImm
let getImm3B b = extract b 7 5 |> int64 |> OprImm
let getImm3C b = extract b 23 21 |> int64 |> OprImm
let getImm4A b = extract b 3 0 |> int64 |> OprImm
let getImm4B b = (extract b 19 16 |> int64) + 1L |> OprImm
let getImm4C b = extract b 11 8 |> int64 |> OprImm
let getImm4D b = extract b 7 4 |> int64 |> OprImm
let getImm4E b = extract b 23 20 |> int64 |> OprImm
let getImm4F (_, b2) = extract b2 4 0 + 1u |> int64 |> OprImm
let getImm5A b = extract b 11 7 |> int64 |> OprImm
let getImm5B b = extract b 4 0 |> int64 |> OprImm
let getImm5C b = (extract b 20 16 |> int64) + 1L |> OprImm
let getImm5D b = extract b 10 6 |> int64 |> OprImm
let getImm5E b =
  let i5 = extract b 10 6 |> int64
  if i5 = 0L then 32L |> OprImm else i5 |> OprImm
let getImm5F b =
  (extract b 20 16) - (extract b 11 7) + 1u |> int64 |> OprImm
let getImm5G (_, b2) =
  concat (extract b2 14 12) (extract b2 7 6) 2 |> int64 |> OprImm
let getImm5H (_, b2) = extract b2 4 0 |> int64 |> OprImm

let getImm7A b = extract b 6 0 <<< 2 |> int64 |> OprImm
let getImm8A b = extract b 7 0 |> int64 |> OprImm
let getImm8B b = (extract b 7 0 |> int64) <<< 2 |> OprImm
let getImm12A b =
  let rot = extract b 11 8 |> int
  let imm = extract b 7 0 |> int
  if rot = 0 then imm |> int64 |> OprImm
  else (imm <<< ((32 - rot) * 2)) + (imm >>> rot * 2) |> int64 |> OprImm
  //imm |> int64 |> OprImm
let getImm12B b =
  (extract b 19 16 |> int64 <<< 12) + (extract b 11 0 |> int64) |> OprImm
let getImm12C b = extract b 11 0 |> int64 |> OprImm
let getImm12D b =
  ((extract b 19 8 |> int64) <<< 4) + (extract b 3 0 |> int64) |> OprImm
let getImm12E b = extract b 11 0 |> int64 |> OprImm
let getImm12F (b1, b2) =
  concat (concat (pickBit b1 10) (extract b2 14 12) 3) (extract b2 7 0) 8
  |> int64 |> OprImm
let getImm16A (b1, b2) =
  let i1 = concat (extract b1 3 0) (pickBit b1 10) 1
  let i2 = concat (extract b2 14 12) (extract b2 7 0) 8
  concat i1 i2 11 |> int64 |> OprImm
let getImm16B (b1, b2) =
  concat (extract b1 3 0) (extract b2 11 0) 12 |> int64 |> OprImm
let getImm24A b = extract b 23 0 |> int64 |> OprImm

let getLblA b = extract b 23 0 <<< 2 |> uint64 |> signExtend 26 32
                |> System.Convert.ToInt64 |> memLabel

let getLbl7A b = concat (pickBit b 9) (extract b 7 3) 5 <<< 1 |> uint64
                 |> System.Convert.ToInt64 |> memLabel

let getLbl8A b = extract b 7 0 <<< 2 |> uint64
                 |> System.Convert.ToInt64 |> memLabel

let getLbl9A b = extract b 7 0 <<< 1 |> uint64 |> signExtend 9 32
                 |> System.Convert.ToInt64 |> memLabel

let getLbl12A b = extract b 10 0 <<< 1 |> uint64 |> signExtend 12 32
                  |> System.Convert.ToInt64 |> memLabel

let getLbl24B b = extract b 23 0 <<< 2 |> uint64 |> signExtend 24 32
                  |> System.Convert.ToInt64 |> memLabel

let getLbl21A (b1, b2) =
  let i1 = concat (pickBit b1 10) (pickBit b2 11) 1
  let i2 = concat (pickBit b2 13) (extract b1 5 0) 6
  let label = concat (concat i1 i2 7) ((extract b2 10 0) <<< 1) 12 |> uint64
  signExtend 21 32 label |> System.Convert.ToInt64 |> memLabel

let getLbl25A (b1, b2) =
  let s = pickBit b1 10
  let i1 = concat s (~~~ ((pickBit b2 13) ^^^ s) &&& 0b1u) 1
  let i2 = concat (~~~ ((pickBit b2 11) ^^^ s) &&& 0b1u) (extract b1 9 0) 10
  let i = concat (concat i1 i2 11) ((extract b2 10 0) <<< 1) 12 |> uint64
  signExtend 25 32 i |> System.Convert.ToInt64 |> memLabel

let getLbl25B (b1 , b2) =
  let s = pickBit b1 10
  let i1 = concat s (~~~ ((pickBit b2 13) ^^^ s) &&& 0b1u) 1
  let i2 = concat (~~~ ((pickBit b2 11) ^^^ s) &&& 0b1u) (extract b1 9 0) 10
  let i = concat (concat i1 i2 11) ((extract b2 10 1) <<< 2) 12 |> uint64
  signExtend 25 32 i |> System.Convert.ToInt64 |> memLabel

let getLbl25C (b1 , b2) =
  let s = pickBit b1 10
  let i1 = concat s (~~~ ((pickBit b2 13) ^^^ s) &&& 0b1u) 1
  let i2 = concat (~~~ ((pickBit b2 11) ^^^ s) &&& 0b1u) (extract b1 9 0) 10
  let i = concat (concat i1 i2 11) ((extract b2 10 0) <<< 1) 12 |> uint64
  signExtend 25 32 i |> System.Convert.ToInt64 |> memLabel

let getLbl26A b =
  let hImm = concat (extract b 23 0) (pickBit b 24) 1 |> uint64
  signExtend 26 32 (hImm <<< 1) |> System.Convert.ToInt64 |> memLabel

let getMemA b = memOffsetImm (getReg b 19 16, None, None)

let getMemC b = memOffsetImm (R.SP, Some Plus,
                              Some (extract b 7 0 <<< 2 |> int64))
let getMemD b = memOffsetReg (getReg b 5 3, None, getReg b 8 6, None)
let getMemE b =
  memOffsetImm (getReg b 5 3, Some Plus,
                Some (extract b 10 6 |> int64 <<< 2))
let getMemF b =
  memOffsetImm (getReg b 5 3, Some Plus,
                Some (extract b 10 6 |> int64))
let getMemG b =
  memOffsetImm (getReg b 5 3, Some Plus,
                Some (extract b 10 6 |> int64 <<< 1))
let getMemH b =
  let u = pickBit b 23
  let i4h = extract b 11 8 |> int64
  let i4l = extract b 3 0 |> int64
  memLabel (if u = 0b0u then ((i4h <<< 4) + i4l) * -1L else (i4h <<< 4) + i4l)
let getMemI b =
  let rn = getReg b 19 16
  let rm = getReg b 3 0
  let sign = getSign (pickBit b 23) |> Some
  memPostIdxReg (rn, sign, rm, None)
let getMemJ b =
  let i4h = extract b 11 8 |> int64
  let i4l = extract b 3 0 |> int64
  let imm = (i4h <<< 4) + i4l
  memPostIdxImm (getReg b 19 16, pickBit b 23 |> getSign |> Some, Some imm)
let getMemK b =
  let rn = getReg b 19 16
  let imm12 = extract b 11 0 |> int64
  memPostIdxImm (rn, pickBit b 23 |> getSign |> Some, Some imm12)
let getMemL b =
  let imm12 = extract b 11 0 |> int64
  let rn = getReg b 19 16
  let sign = pickBit b 23 |> getSign |> Some
  match pickBit b 24, pickBit b 21 with
  | 0b0u, _ -> memPostIdxImm (rn, sign, Some imm12)
  | 0b1u, 0b0u -> memOffsetImm (rn, sign, Some imm12)
  | 0b1u, 0b1u -> memPreIdxImm  (rn, sign, Some imm12)
  | _ -> raise ParsingFailureException
let getMemM b =
  let imm12 = extract b 11 0 |> int64
  match pickBit b 23 with
  | 0b0u -> imm12 * -1L |> memLabel
  | 0b1u -> imm12 |> memLabel
  | _ -> raise ParsingFailureException
let getMemN b =
  let rn = getReg b 19 16
  let rm = getReg b 3 0
  let sign = pickBit b 23 |> getSign |> Some
  match pickBit b 24, pickBit b 21 with
  | 0b0u, _ -> memPostIdxReg (rn, sign, rm, None)
  | 0b1u, 0b0u -> memOffsetReg (rn, sign, rm, None)
  | 0b1u, 0b1u -> memPreIdxReg (rn, sign, rm, None)
  | _ -> raise ParsingFailureException
let getMemO b =
  let i4h = extract b 11 8 |> int64
  let i4l = extract b 3 0 |> int64
  let i8 = ((i4h <<< 4) + i4l)
  let rn = getReg b 19 16
  let sign = pickBit b 23 |> getSign |> Some
  match pickBit b 24, pickBit b 21 with
  | 0b0u, _ -> memPostIdxImm (rn, sign, Some i8)
  | 0b1u, 0b0u -> memOffsetImm (rn, sign, Some i8)
  | 0b1u, 0b1u -> memPreIdxImm (rn, sign, Some i8)
  | _ -> raise ParsingFailureException
let getMemP (b1, b2) =
  let i = extract b2 5 4
  memOffsetReg (getReg b1 3 0, None, getReg b2 3 0, Some (SRTypeLSL, Imm i))
let getMemQ b =
  let rn = getReg b 19 16
  let rm = getReg b 3 0
  let imm5 = extract b 11 7
  let struct (shift, imm) = decodeImmShift (extract b 6 5) imm5
  let typ = shift, Imm imm
  let sign = pickBit b 23 |> getSign |> Some
  memPostIdxReg (rn, sign, rm, Some typ)
let getMemR b =
  let rn = getReg b 19 16
  let rm = getReg b 3 0
  let struct (shift, imm) = decodeImmShift (extract b 6 5) (extract b 11 7)
  let shiftOffset = Some (shift, Imm imm)
  let sign = pickBit b 23 |> getSign |> Some
  match pickBit b 24, pickBit b 21 with
  | 0b0u, _ -> memPostIdxReg (rn, sign, rm, shiftOffset)
  | 0b1u, 0b0u -> memOffsetReg (rn, sign, rm, shiftOffset)
  | 0b1u, 0b1u -> memPreIdxReg (rn, sign, rm, shiftOffset)
  | _ -> raise ParsingFailureException
let getMemS b =
  let rn = getReg b 19 16
  let align =
    match extract b 5 4 with
    | 0b01u -> Some 64L
    | 0b10u -> Some 128L
    | 0b11u -> Some 256L
    | _ -> None
  let rm = getReg b 3 0
  match rm with
  | R.PC -> memOffsetAlign (rn, align, None)
  | R.SP -> memPreIdxAlign (rn, align, None)
  | _ -> memPostIdxAlign (rn, align, Some rm)
let getMemT b =
  let rn = getReg b 19 16
  let rm = getReg b 3 0
  let ia = extract b 7 4
  let align =
    match extract b 11 10 with
    | 0b00u when pickBit ia 0 = 0b0u -> None
    | 0b01u when extract ia 1 0 = 0b00u -> None
    | 0b01u when extract ia 1 0 = 0b01u -> Some 16L
    | 0b10u when extract ia 2 0 = 0b000u -> None
    | 0b10u when extract ia 2 0 = 0b011u -> Some 32L
    | _ -> raise ParsingFailureException
  match rm with
  | R.PC -> memOffsetAlign (rn, align, None)
  | R.SP -> memPreIdxAlign (rn, align, None)
  | _ -> memPostIdxAlign (rn, align, Some rm)
let getMemU b =
  let rn = getReg b 19 16
  let align =
    match extract b 11 10, pickBit b 5, pickBit b 4 with
    | 0b00u, _, _ | 0b01u, _, 0b0u | 0b10u, 0b0u, 0b0u -> None
    | 0b01u, _, 0b1u -> Some 32L
    | 0b10u, 0b0u, 0b1u -> Some 64L
    | _ -> raise ParsingFailureException
  let rm = getReg b 3 0
  match rm with
  | R.PC -> memOffsetAlign (rn, align, None)
  | R.SP -> memPreIdxAlign (rn, align, None)
  | _ -> memPostIdxAlign (rn, align, Some rm)
let getMemV b =
  let rn = getReg b 19 16
  let align =
    match extract b 11 10, pickBit b 5, pickBit b 4 with
    | 0b00u, _, 0b0u | 0b01u, _, 0b0u | 0b10u, 0b0u, 0b0u -> None
    | _ -> raise ParsingFailureException
  let rm = getReg b 3 0
  match rm with
  | R.PC -> memOffsetAlign (rn, align, None)
  | R.SP -> memPreIdxAlign (rn, align, None)
  | _ -> memPostIdxAlign (rn, align, Some rm)
let getMemW b =
  let rn = getReg b 19 16
  let align =
    match extract b 11 10, pickBit b 6, pickBit b 5, pickBit b 4 with
    | 0b00u, _, _, 0b0u | 0b01u, _, _, 0b0u | 0b10u, _, 0b0u, 0b0u -> None
    | 0b01u, _, _, 0b1u | 0b10u, _, 0b0u, 0b1u -> Some 64L
    | 0b10u, _, 0b1u, 0b0u -> Some 128L
    | 0b00u, _, _, 0b1u -> Some 32L
    | _ -> raise ParsingFailureException
  let rm = getReg b 3 0
  match rm with
  | R.PC -> memOffsetAlign (rn, align, None)
  | R.SP -> memPreIdxAlign (rn, align, None)
  | _ -> memPostIdxAlign (rn, align, Some rm)
let getAlignForVLD1 s a =
  match s, a with
  | _, 0b0u -> None
  | 0b01u, 0b1u -> Some 16L
  | 0b10u, 0b1u -> Some 32L
  | _ -> raise ParsingFailureException
let getMemX b =
  let rn = getReg b 19 16
  let align =
    match extract b 7 6, pickBit b 4 with
    | _, 0b0u -> None
    | 0b01u, 0b1u -> Some 16L
    | 0b10u, 0b1u -> Some 32L
    | _ -> raise ParsingFailureException
  let rm = getReg b 3 0
  match rm with
  | R.PC -> memOffsetAlign (rn, align, None)
  | R.SP -> memPreIdxAlign (rn, align, None)
  | _ -> memPostIdxAlign (rn, align, Some rm)
let getMemY b =
  let rn = getReg b 19 16
  let align =
    match extract b 7 6, pickBit b 4 with
    | _, 0b0u -> None
    | 0b00u, 0b1u -> Some 16L
    | 0b01u, 0b1u -> Some 32L
    | 0b10u, 0b1u -> Some 64L
    | _ -> raise ParsingFailureException
  let rm = getReg b 3 0
  match rm with
  | R.PC -> memOffsetAlign (rn, align, None)
  | R.SP -> memPreIdxAlign (rn, align, None)
  | _ -> memPostIdxAlign (rn, align, Some rm)
let getMemZ b =
  let rn = getReg b 19 16
  let rm = getReg b 3 0
  match rm with
  | R.PC -> memOffsetAlign (rn, None, None)
  | R.SP -> memPreIdxAlign (rn, None, None)
  | _ -> memPostIdxAlign (rn, None, Some rm)
let getMemAA b =
  let rn = getReg b 19 16
  let align =
    match extract b 7 6, pickBit b 4 with
    | _, 0b0u -> None
    | 0b00u, 0b1u -> Some 32L
    | 0b01u, 0b1u | 0b10u, 0b1u -> Some 64L
    | 0b11u, 0b1u -> Some 128L
    | _ -> raise ParsingFailureException
  let rm = getReg b 3 0
  match rm with
  | R.PC -> memOffsetAlign (rn, align, None)
  | R.SP -> memPreIdxAlign (rn, align, None)
  | _ -> memPostIdxAlign (rn, align, Some rm)
let getMemAB b =
  let rn = getRegister (extract b 19 16 |> byte)
  let i = extract b 11 0 |> int64
  memOffsetImm (rn, pickBit b 23 |> getSign |> Some, Some i)
let getMemAC b =
  let rn = getRegister (extract b 19 16 |> byte)
  let imm5 = extract b 11 7
  let struct (shift, imm) = decodeImmShift (extract b 6 5) imm5
  let typ = shift, Imm imm
  let rm = getRegister (extract b 3 0 |> byte)
  memOffsetReg (rn, pickBit b 23 |> getSign |> Some, rm, Some typ)
let getMemAD b =
  let i8 = extract b 7 0 |> int64
  match pickBit b 24, pickBit b 21, pickBit b 23 with
  | 1u, 0u, 0u -> memLabel (i8 * -4L)
  | 1u, 0u, 1u -> memLabel (i8 * 4L)
  | 0u, 0u, 1u -> memUnIdxImm (R.PC, i8 * 4L)
  | _ -> raise ParsingFailureException
let getMemAE b =
  let rn = getRegister (extract b 19 16 |> byte)
  let i8 = extract b 7 0 |> int64
  let sign = pickBit b 23 |> getSign |> Some
  match pickBit b 24, pickBit b 21 with
  | 0u, 0u when sign = Some Plus -> memUnIdxImm (rn, i8)
  | 0u, 1u -> memPostIdxImm (rn, sign, Some (i8 * 4L))
  | 1u, 0u -> memOffsetImm (rn, sign, Some (i8 * 4L))
  | 1u, 1u -> memPreIdxImm (rn, sign, Some (i8 * 4L))
  | _ -> raise ParsingFailureException
let getMemAF (b1, b2) =
  memOffsetImm (getRegister (extract b1 3 0 |> byte), None,
              extract b2 7 0 <<< 2 |> int64 |> Some)
let getMemAG (b1, b2) =
  memOffsetImm (getRegister (extract b1 3 0 |> byte), None,
              extract b2 7 0 |> int64 |> Some)
let getMemAH (b1, b2) =
  let rn = getRegister (extract b1 3 0 |> byte)
  let i8 = extract b2 7 0 <<< 2 |> int64
  let sign = pickBit b1 7 |> getSign |> Some
  match pickBit b1 8, pickBit b1 5 with
  | 0b0u, _ -> memPostIdxImm (rn, sign, Some i8)
  | 0b1u, 0b0u -> memOffsetImm (rn, sign, Some i8)
  | 0b1u, 0b1u -> memPreIdxImm  (rn, sign, Some i8)
  | _ -> raise ParsingFailureException
let getMemAI (b1, b2) =
  let i8 = extract b2 7 0 <<< 2 |> int64
  if pickBit b1 7 = 0b0u then memLabel (i8 * -1L) else memLabel i8
let getMemAJ (b1, _) =
  memOffsetImm (getRegister (extract b1 3 0 |> byte), None, None)
let getMemAK (b1, b2) =
  memOffsetReg (getRegister (extract b1 3 0 |> byte), None,
              getRegister (extract b2 3 0 |> byte), None)
let getMemAL (b1, b2) =
  memOffsetReg (getRegister (extract b1 3 0 |> byte), None,
              getRegister (extract b2 3 0 |> byte),
              Some (SRTypeLSL, Imm 1u))
let getMemAM (b1, b2) =
  let rn = getRegister (extract b1 3 0 |> byte)
  let i8 = extract b2 7 0 |> int64
  let sign = pickBit b2 9 |> getSign |> Some
  match pickBit b2 10, pickBit b2 8 with
  | 0b0u, 0b0u -> raise UndefinedException
  | 0b0u, 0b1u -> memPostIdxImm (rn, sign, Some i8)
  | 0b1u, 0b0u -> memOffsetImm (rn, sign, Some i8)
  | 0b1u, 0b1u -> memPreIdxImm  (rn, sign, Some i8)
  | _ -> raise ParsingFailureException
let getMemAN (b1, b2) =
  let rn = getRegister (extract b1 3 0 |> byte)
  let i12 = extract b2 11 0 |> int64 |> Some
  memOffsetImm (rn, Some Plus, i12)
let getMemAO (b1, b2) =
  let rn = getRegister (extract b1 3 0 |> byte)
  let rm = getRegister (extract b2 3 0 |> byte)
  let typ = SRTypeLSL, Imm (extract b2 5 4)
  memOffsetReg (rn,  Some Plus, rm, Some typ)
let getMemAP (b1, b2) =
  let rn = getRegister (extract b1 3 0 |> byte)
  let i8 = extract b2 7 0 |> int64
  memOffsetImm (rn, Some Minus, Some i8)
let getMemAQ (b1, b2) =
  let i12 = extract b2 11 0 |> int64
  if pickBit b1 7 = 0b1u then memLabel i12 else memLabel (i12 * -1L)

let getMemAR b =
  let rn = getRegister (extract b 19 16 |> byte)
  let i = extract b 7 0 <<< 2 |> int64
  let sign = (pickBit b 23) |> getSign |> Some
  memOffsetImm (rn, sign, Some i)

let getFlagA b = extract b 8 6 |> byte |> getIflag |> OprIflag
let getFlagB b = extract b 2 0 |> byte |> getIflag |> OprIflag
let getFlagC (_, b2) = extract b2 7 5 |> byte |> getIflag |> OprIflag
let getEndianA b = pickBit b 9 |> byte |> getEndian |> OprEndian
let getEndianB b = pickBit b 3 |> byte |> getEndian |> OprEndian
let getOptA b = extract b 3 0 |> byte |> getOption |> OprOption
let getFirstCond b = extract b 7 4 |> byte |> parseCond |> OprCond
let getScalarA b =
  let m = pickBit b 5
  let vm = extract b 3 0
  match extract b 21 20 with
  | 0b01u -> (getVFPDRegister (extract vm 2 0 |> byte),
              Some (concat m (pickBit vm 3) 1 |> uint8)) |> toSSReg
  | 0b10u -> (getVFPDRegister (vm |> byte), Some (m |> uint8)) |> toSSReg
  | _ -> raise ParsingFailureException
let getScalarB b =
  let reg = concat (pickBit b 5) (extract b 3 0) 4 |> byte |> getVFPDRegister
  match extract b 19 16 with
  | i4 when i4 &&& 0b0001u = 0b0001u -> reg, Some (extract i4 3 1 |> uint8)
  | i4 when i4 &&& 0b0011u = 0b0010u -> reg, Some (extract i4 3 2 |> uint8)
  | i4 when i4 &&& 0b0111u = 0b0100u -> reg, Some (pickBit i4 3 |> uint8)
  | _ -> raise ParsingFailureException
  |> toSSReg

let getScalarC b =
  let dd = concat (pickBit b 7) (extract b 19 16) 4 |> byte
           |> getVFPDRegister
  let x =
    match concat (extract b 22 21) (extract b 6 5) 2 with
    | opc when opc &&& 0b1000u = 0b1000u ->
      uint8 (concat (pickBit b 21) (extract b 6 5) 2)
    | opc when opc &&& 0b1001u = 0b0001u ->
      uint8 (concat (pickBit b 21) (pickBit b 6) 1)
    | opc when opc &&& 0b1011u = 0b0000u -> uint8 (pickBit b 21)
    | opc when opc &&& 0b1011u = 0b0010u -> raise UndefinedException
    | _ -> raise ParsingFailureException
  (dd, Some x) |> toSSReg

let getScalarD b =
  let dd = concat (pickBit b 7) (extract b 19 16) 4 |> byte
           |> getVFPDRegister
  let opc = concat (extract b 22 21) (extract b 6 5) 2
  let x =
    match concat (pickBit b 23) opc 4 with
    | uOpc when uOpc &&& 0b11000u = 0b01000u ->
      concat (pickBit b 21) (extract b 6 5) 2 |> uint8
    | uOpc when uOpc &&& 0b11000u = 0b11000u ->
      concat (pickBit b 21) (extract b 6 5) 2 |> uint8
    | uOpc when uOpc &&& 0b11001u = 0b00001u ->
      concat (pickBit b 21) (pickBit b 6) 1 |> uint8
    | uOpc when uOpc &&& 0b11001u = 0b10001u ->
      concat (pickBit b 21) (pickBit b 6) 1 |> uint8
    | uOpc when uOpc &&& 0b11011u = 0b00000u -> pickBit b 21 |> uint8
    | uOpc when uOpc &&& 0b11011u = 0b10000u -> raise UndefinedException
    | uOpc when uOpc &&& 0b01011u = 0b00010u -> raise UndefinedException
    | _ -> raise ParsingFailureException
  (dd, Some x) |> toSSReg

let dummyChk _ _ = ()

let checkStoreEx1 b (op1, op2, _) =
  let rn = getRegC b
  checkUnpred (op1 b = OprReg R.PC || op2 b = OprReg R.PC ||
               rn = OprReg R.PC || op1 b = rn || op1 b = op2 b)
let checkStoreEx2 b (op1, op2, op3, _) =
  let rn = getRegC b
  checkUnpred (op1 b = OprReg R.PC || pickBit b 0 = 0b1u ||
               op2 b = OprReg R.LR || rn = OprReg R.PC || op1 b = rn ||
               op1 b = op2 b || op1 b = op3 b)

let chkUnpreInAndNotLastItBlock itstate =
  inITBlock itstate && lastInITBlock itstate |> not

let chkUnpreA b (op1, op2, op3) =
  checkUnpred (op1 b = OprReg R.PC || op2 b = OprReg R.PC ||
               op3 b = OprReg R.PC)
let chkUnpreB b (op1, op2, op3, op4) =
  checkUnpred (op1 b = OprReg R.PC || op2 b = OprReg R.PC ||
               op3 b = OprReg R.PC || op4 b = OprReg R.PC)
let chkUnpreC b (op1, op2, op3, _) =
  checkUnpred (op1 b = OprReg R.PC || op2 b = OprReg R.PC ||
               op3 b = OprReg R.PC)
let chkUnpreD b op = checkUnpred (op b = OprReg R.PC)
let chkUnpreE b (op1, op2) =
  checkUnpred (op1 b = OprReg R.PC || op2 b = OprReg R.PC)
let chkUnpreF b (_, op2) = checkUnpred (op2 b = OprReg R.PC)
let chkUnpreG b (op1, _) = checkUnpred (op1 b = OprReg R.PC)
let chkUnpreH b (_, op2) =
  checkUnpred (extract b 19 16 = 0b0u || op2 b = OprReg R.PC)
let chkUnpreI b (op1, op2, op3, op4) =
  checkUnpred (op1 b = OprReg R.PC || op2 b = OprReg R.PC ||
               op3 b = OprReg R.PC || op4 b = OprReg R.PC ||
               op1 b = op2 b)
let chkUnpreJ b (op1, op2, _) =
  let rn = getRegC b
  checkUnpred (op1 b = OprReg R.PC || op2 b = OprReg R.PC ||
               rn = OprReg R.PC || rn = op1 b || rn = op2 b)
let chkUnpreK b (op1, _) =
  let rn = getRegC b
  checkUnpred (rn = OprReg R.PC || op1 b = OprReg R.PC)
let chkUnpreL b (op1, _, _) =
  checkUnpred (pickBit b 12 = 0b1u || op1 b = OprReg R.LR ||
               getRegC b = OprReg R.PC)
let chkUnpreM b (op1, _, op3) =
  checkUnpred (op1 b = OprReg R.PC || op3 b = OprReg R.PC)
let chkUnpreN b _ = checkUnpred (getRegC b = OprReg R.PC)
let chkUnpreO b (op1, _, op3, _) =
  checkUnpred (op1 b = OprReg R.PC || op3 b = OprReg R.PC)
let chkUnpreP b (op1, op2, _) =
  checkUnpred (op1 b = OprReg R.PC || op2 b = OprReg R.PC)
let chkUnpreQ b (op1, op2, _, _) =
  checkUnpred (op1 b = OprReg R.PC || op2 b = OprReg R.PC)
let chkUnpreR itstate b _ =
  let d = concat (pickBit b 7) (extract b 2 0) 3
  checkUnpred ((extract b 6 3 = 15u && d = 15u) &&
               d = 15u && inITBlock itstate && lastInITBlock itstate |> not)
let chkUnpreS b _ =
  let rnd = concat (pickBit b 7) (extract b 2 0) 3
  let rm = extract b 6 3
  checkUnpred (rnd = 15u || rm = 15u)
  checkUnpred (rnd < 8u && rm < 8u)

let chkUnpreX b _ = checkUnpred (extract b 19 16 = 0b0u)
let chkUnpreY b op = checkUnpred (op b = OprReg R.SP)
let chkUnpreZ b (op1, _) =
  let rn = getRegC b
  checkUnpred (rn = OprReg R.PC || rn = op1 b)
let chkUnpreAA b (op1, _) =
  let rn = getRegC b
  checkUnpred ((pickBit b 24 = 0u || pickBit b 21 = 1u) &&
               (rn = OprReg R.PC || rn = op1 b))
let chkUnpreAB b (op1, _) =
  let rn = getRegC b
  checkUnpred (op1 b = OprReg R.PC ||
               ((rn = op1 b) && (pickBit b 24 = 0u || pickBit b 21 = 1u)))
let chkUnpreAC b (op1, _) =
  let rn = getRegC b
  checkUnpred (op1 b = OprReg R.PC ||
                   ((rn = OprReg R.PC || rn = op1 b) &&
                    (pickBit b 24 = 0u || pickBit b 21 = 1u)))
let chkUnpreAD b (op1, _) =
  let rn = getRegC b
  checkUnpred (op1 b = OprReg R.PC || getRegA b = OprReg R.PC ||
               ((pickBit b 24 = 0b0u || pickBit b 21 = 0b1u) &&
                (rn = OprReg R.PC || rn = op1 b)))

let chkUnpreAE b (op1, op2, _) =
  let rn = getRegC b
  let rm = getRegA b
  checkUnpred ((pickBit b 24 = 0u && pickBit b 21 = 1u) ||
               op2 b = OprReg R.PC || rm = OprReg R.PC || rm = op1 b ||
               rm = op2 b || (pickBit b 24 = 0u || pickBit b 21 = 1u) &&
               (rn = OprReg R.PC || rn = op1 b || rn = op2 b))

let chkUnpreAF b (op1, op2, _) =
  let rn = getRegC b
  let rm = getRegA b
  let p = pickBit b 24
  let w = pickBit b 21
  checkUnpred ((p = 0u && w = 1u) || op2 b = OprReg R.PC ||
               rm = OprReg R.PC || pickBit b 12 = 1u ||
               ((p = 0u || w = 1u) &&
                (rn = OprReg R.PC || rn = op1 b || rn = op2 b)))
let chkUnpreAG b (op1, _) =
  let rn = getRegC b
  checkUnpred (op1 b = OprReg R.PC ||
               ((rn = OprReg R.PC || rn = op1 b) &&
                (pickBit b 24 = 0b0u || pickBit b 21 = 0b1u)))
let chkUnpreAH b (op1, _) =
  checkUnpred (op1 b = OprReg R.PC ||
               ((pickBit b 24 = 0b0u || pickBit b 21 = 0b1u) &&
                (getRegC b = op1 b)))

let chkUnpreAI b (op1, op2, _) =
  let p = pickBit b 24
  let w = pickBit b 21
  let rn = getRegC b
  checkUnpred (((p = 0b0u || w = 0b1u) && (rn = op1 b || rn = op2 b)) ||
               p = 0b0u && w = 0b1u)

let chkUnpreAJ b (op1, op2, _) =
  let p = pickBit b 24
  let w = pickBit b 21
  let rn = getRegC b
  checkUnpred ((p = 0u && w = 1u) || op2 b = OprReg R.PC
               || ((p = 0u || w = 1u) &&
                   (rn = OprReg R.PC || rn = op1 b || rn = op2 b)))

let chkUnpreAK (_, b2) _ =
  let rm = getRegA b2
  checkUnpred (rm = OprReg R.SP || rm = OprReg R.PC)

let chkUnpreAL b (op1, _) =
  let rn = getRegC b
  checkUnpred (getRegA b = OprReg R.PC || rn = OprReg R.PC || rn = op1 b)

let chkUnpreAM b (op1, _) =
  let rn = getRegC b
  checkUnpred (getRegA b = OprReg R.PC
              || ((pickBit b 24 = 0u || pickBit b 21 = 1u)
                  && (rn = OprReg R.PC || rn = op1 b)))

let chkUnpreAN b (op1, _) =
  checkUnpred (op1 b = OprReg R.PC); chkUnpreAM b (op1, ())
let chkUnpreAO b _ =
  checkUnpred (concat (pickBit b 22) (pickBit b 5) 1 = 0b11u)
let chkUnpreAP b (op1, _, _) =
  let msb = extract b 20 16 |> int64
  let lsb = extract b 11 7 |> int64
  checkUnpred (op1 b = OprReg R.PC || msb < lsb)
let chkUnpreAQ b (op1, _, _, _) =
  let msb = extract b 20 16 |> int64
  let lsb = extract b 11 7 |> int64
  checkUnpred (op1 b = OprReg R.PC || msb < lsb)
let chkUnpreAR b _ =
  checkUnpred (getReg b 19 16 = R.PC ||
               List.length (extract b 15 0 |> getRegList) < 1)
let chkUnpreAS b _ =
  let rn = getReg b 19 16
  let rl = extract b 15 0 |> getRegList
  checkUnpred (rn = R.PC || List.length rl < 1 ||
               (pickBit b 21 = 1u && List.exists (fun e -> e = rn) rl))

let chkUnpreAT b _ = checkUnpred (pickBit b 13 = 0b1u)

let chkUnpreAU b (_, _, op3, op4, _) =
  checkUnpred (op3 b = OprReg R.PC || op4 b = OprReg R.PC)

let chkUnpreAV b (_, _, op3, op4, _) =
  checkUnpred (op3 b = OprReg R.PC ||
               op4 b = OprReg R.PC || op3 b = op4 b)

let chkUnpreAW b (op1, _, op3, op4) =
  checkUnpred (op3 b = OprReg R.PC || op4 b = OprReg R.PC ||
               op1 b = OprReg R.S31)

let chkUnpreAX b (op1, op2, op3, _) =
  checkUnpred (op1 b = OprReg R.PC || op2 b = OprReg R.PC ||
               op3 b = OprReg R.S31 || op1 b = op2 b)

let chkUnpreAY b (op1, op2, _) =
  checkUnpred (op1 b = OprReg R.PC ||
               op2 b = OprReg R.PC || op1 b = op2 b)

let chkUnpreAZ b _ =
  let regs = (extract b 7 0) / 2u
  checkUnpred (regs = 0u || regs > 16u ||
                   (concat (pickBit b 22) (extract b 15 12) 4) + regs > 32u)

let chkUnpreBA b _ =
  let imm8 = extract b 7 0
  checkUnpred (imm8 = 0u ||
               (concat (extract b 15 12) (pickBit b 22) 1) + imm8 > 32u)

let chkUnpreBB b (_, _, op3, _, _, _) = checkUnpred (op3 b = OprReg R.PC)

let chkUnpreBC b _ =
  let rL = ((pickBit b 8) <<< 14) + (extract b 7 0) |> getRegList
  checkUnpred (List.length rL < 1)

let chkUnpreBD opcode itstate b op1 =
  let isITOpcode = function
    | Op.ITE | Op.ITET | Op.ITTE | Op.ITEE | Op.ITETT | Op.ITTET | Op.ITEET
    | Op.ITTTE | Op.ITETE | Op.ITTEE | Op.ITEEE -> true
    | _ -> false
  checkUnpred (inITBlock itstate || op1 b = OprCond Condition.UN ||
               (op1 b = OprCond Condition.AL && isITOpcode opcode))

let chkUnpreBE itstate b _ =
  checkUndef (extract b 11 8 = 14u)
  checkUnpred (inITBlock itstate)

let chkUnpreBF (b1, b2) _ =
  let n = extract b1 3 0 |> int
  let rL = concat ((pickBit b2 14) <<< 1) (extract b2 12 0) 13 |> getRegList
  checkUnpred ((n = 15 || List.length rL < 2) ||
               (pickBit b1 5 = 0b1u && pickBit b2 n = 0b1u))

let chkUnpreBG itstate (_, b2) _ =
  let pm = (extract b2 15 14)
  let rL = concat (pm <<< 1) (extract b2 12 0) 13 |> getRegList
  checkUnpred (List.length rL < 2 || pm = 0b11u ||
               (pickBit b2 15 = 1u && chkUnpreInAndNotLastItBlock itstate))

let chkUnpreBH itstate (b1, b2) _ =
  let n = extract b1 3 0 |> int
  let w =  pickBit b1 5
  let pm = extract b2 15 14
  let rl = getRegList (concat (pm <<< 1) (extract b2 12 0) 13)
  checkUnpred (n = 15 || List.length rl < 2 || pm = 0b11u)
  checkUnpred (pickBit b2 15 = 1u && chkUnpreInAndNotLastItBlock itstate)
  checkUnpred (w = 1u && pickBit b2 n = 1u)

let chkUnpreBI (_, b2) _ =
  let m = pickBit b2 14
  let rl = getRegList (concat (m <<< 1) (extract b2 12 0) 13)
  checkUnpred (List.length rl < 2 || pickBit b2 15 = 0b1u
               || pickBit b2 13 = 0b1u)

let chkUnpreBJ (b1, b2) (op1, op2, _) =
  let rn = getRegister (extract b1 3 0 |> byte)
  let opr1 = op1 (b1, b2)
  let opr2 = op2 (b1, b2)
  checkUnpred (opr1 = OprReg R.SP || opr1 = OprReg R.PC ||
               opr2 = OprReg R.SP || opr2 = OprReg R.PC ||
               rn = R.PC || op1 (b1, b2) = OprReg rn ||
               op1 (b1, b2) = op2 (b1, b2))

let chkUnpreBK (b1, b2) (op1, _) =
  checkUnpred (op1 (b1, b2) = OprReg R.SP ||
               op1 (b1, b2) = OprReg R.PC ||
               getRegister (extract b1 3 0 |> byte) = R.PC)

let chkUnpreBL (b1, b2) (op1, _) =
  checkUnpred (op1 (b1, b2) = OprReg R.SP ||
               op1 (b1, b2) = OprReg R.PC)

let chkUnpreBM (b1, b2) (op1, op2, _) =
  let rn = getRegister (extract b1 3 0 |> byte)
  checkUnpred (((OprReg rn = op1 (b1, b2) || OprReg rn = op2 (b1, b2))
               && pickBit b1 5 = 0b1u) || rn = R.PC ||
               op1 (b1, b2) = OprReg R.SP ||
               op1 (b1, b2) = OprReg R.PC ||
               op2 (b1, b2) = OprReg R.SP ||
               op2 (b1, b2) = OprReg R.PC)

let chkUnpreBN (b1, b2) (op1, op2, _) =
  let rn = getRegister (extract b1 3 0 |> byte)
  checkUnpred (((OprReg rn = op1 (b1, b2) || OprReg rn = op2 (b1, b2))
               && pickBit b1 5 = 0b1u) || op1 (b1, b2) = op2 (b1, b2) ||
               op1 (b1, b2) = OprReg R.SP ||
               op1 (b1, b2) = OprReg R.PC ||
               op2 (b1, b2) = OprReg R.SP ||
               op2 (b1, b2) = OprReg R.PC)

let chkUnpreBO (b1, b2) (op1, op2, _) =
  checkUnpred (op1 (b1, b2) = OprReg R.SP ||
               op1 (b1, b2) = OprReg R.PC ||
               op2 (b1, b2) = OprReg R.SP ||
               op2 (b1, b2) = OprReg R.PC ||
               op1 (b1, b2) = op2 (b1, b2))

let chkUnpreBP (b1, b2) (op1, op2, _) =
  let rn = getRegister (extract b1 3 0 |> byte)
  checkUnpred (op1 (b1, b2) = OprReg R.SP ||
               op1 (b1, b2) = OprReg R.PC ||
               op2 (b1, b2) = OprReg R.SP ||
               op2 (b1, b2) = OprReg R.PC ||
               rn = R.PC || op1 (b1, b2) = op2 (b1, b2))

let chkUnpreBQ (b1, b2) (op1, op2, op3, _) =
  let rn = getRegister (extract b1 3 0 |> byte)
  let opr1 = op1 (b1, b2)
  let opr2 = op2 (b1, b2)
  let opr3 = op3 (b1, b2)
  checkUnpred (opr1 = OprReg R.SP || opr1 = OprReg R.PC ||
               opr2 = OprReg R.SP || opr2 = OprReg R.PC ||
               opr3 = OprReg R.SP || opr3 = OprReg R.PC ||
               rn = R.PC || op1 (b1, b2) = OprReg rn ||
               op1 (b1, b2) = op2 (b1, b2))

let chkUnpreBR itstate (b1, b2) _ =
  let rn = getRegister (extract b1 3 0 |> byte)
  let rm = getRegister (extract b2 3 0 |> byte)
  checkUnpred (rn = R.SP || rm = R.SP || rm = R.PC)
  checkUnpred (chkUnpreInAndNotLastItBlock itstate)

let chkUnpreBS (b1, b2) (op1, _) =
  let rn = getRegister (extract b1 3 0 |> byte)
  let opr1 = op1 (b1, b2)
  checkUnpred (opr1 = OprReg R.SP || opr1 = OprReg R.PC || rn = R.PC)

let chkUnpreBT (b1, b2) (op1, op2) =
  let opr1 = op1 (b1, b2)
  let opr2 = op2 (b1, b2)
  checkUnpred (opr1 = OprReg R.PC || opr2 = OprReg R.PC ||
               (opr1 = OprReg R.SP && opr2 = OprReg R.SP))

let chkUnpreBU (b1, b2) (op1, op2) =
  let opr1 = op1 (b1, b2)
  let opr2 = op2 (b1, b2)
  checkUnpred (opr1 = OprReg R.SP || opr1 = OprReg R.PC ||
               opr2 = OprReg R.SP || opr2 = OprReg R.PC)

let chkUnpreBV (b1, b2) (op1, op2, _) =
  let opr1 = op1 (b1, b2)
  let opr2 = op2 (b1, b2)
  checkUnpred (opr1 = OprReg R.SP || opr1 = OprReg R.PC ||
               opr2 = OprReg R.SP || opr2 = OprReg R.PC)

let chkUnpreBW (b1, b2) (op1, op2, _) =
  let opr2 = op2 (b1, b2)
  checkUnpred (op1 (b1, b2) = OprReg R.PC || opr2 = OprReg R.SP ||
               opr2 = OprReg R.PC)

let chkUnpreBX (b1, b2) (op1, op2, op3, _) =
  let rd = op1 (b1, b2)
  let rn = op2 (b1, b2)
  let rm = op3 (b1, b2)
  checkUnpred (rd = OprReg R.SP || rd = OprReg R.PC
               || rn = OprReg R.SP || rn = OprReg R.PC
               || rm = OprReg R.SP || rm = OprReg R.PC)

let chkUnpreBY (b1, b2) (op1, op2, op3, _) =
  let rd = op1 (b1, b2)
  let rn = op2 (b1, b2)
  let rm = op3 (b1, b2)
  checkUnpred (rd = OprReg R.SP
               || rn = OprReg R.SP || rn = OprReg R.PC
               || rm = OprReg R.SP || rm = OprReg R.PC)

let chkUnpreBZ (b1, b2) (op1, op2, op3, _) =
  let opr1 = op1 (b1, b2)
  let opr3 = op3 (b1, b2)
  checkUnpred (opr1 = OprReg R.SP || opr1 = OprReg R.PC ||
               op2 (b1, b2) = OprReg R.SP || opr3 = OprReg R.SP ||
               opr3 = OprReg R.PC)

let chkUnpreCA (b1, b2) (op1, op2, op3, _) =
  let rd = op1 (b1, b2)
  let rn = op2 (b1, b2)
  let rm = op3 (b1, b2)
  checkUnpred (rn <> OprReg R.SP
               && (rd = OprReg R.SP || rd = OprReg R.PC
                   || rn = OprReg R.PC
                   || rm = OprReg R.SP || rm = OprReg R.PC))

let chkUnpreCB (b1, b2) (op1, op2, op3, _) =
  let rd = op1 (b1, b2)
  let rn = op2 (b1, b2)
  let rm = op3 (b1, b2)
  checkUnpred (rd = OprReg R.SP || rn = OprReg R.PC
               || rm = OprReg R.SP || rm = OprReg R.PC)

let chkUnpreCC (b1, b2) (op1, _) =
  checkUnpred (op1 (b1, b2) = OprReg R.PC)

let chkUnpreCD (b1, b2) (op1, op2, _) =
  let opr2 = op2 (b1, b2)
  checkUnpred (op1 (b1, b2) = OprReg R.SP || opr2 = OprReg R.SP ||
               opr2 = OprReg R.PC)

let chkUnpreCE (b1, b2) (op1, op2, _) =
  let opr1 = op1 (b1, b2)
  checkUnpred (opr1 = OprReg R.SP || opr1 = OprReg R.PC ||
               op2 (b1, b2) = OprReg R.SP)

let chkUnpreCF (b1, b2) (op1, op2, _) =
  let rd = op1 (b1, b2)
  let rn = op2 (b1, b2)
  checkUnpred (rn <> OprReg R.SP
               && (rd = OprReg R.SP
                   || (rd = OprReg R.PC && pickBit b1 4 = 0b0u)
                   || rn = OprReg R.PC))

let chkUnpreCG (b1, b2) (op1, op2, _) =
  checkUnpred (op1 (b1, b2) = OprReg R.SP || op2 (b1, b2) = OprReg R.PC)

let chkUnpreCH (b1, b2) (op1, op2, op3) =
  let rd = op1 (b1, b2)
  let rn = op2 (b1, b2)
  let rm = op3 (b1, b2)
  checkUnpred (rn <> OprReg R.SP
               && (rd = OprReg R.SP
                   || (rd = OprReg R.PC && pickBit b1 4 = 0b0u)
                   || rn = OprReg R.PC
                   || rm = OprReg R.SP || rm = OprReg R.PC))

let chkUnpreCI (b1, b2) (op1, _, op3, _) =
  let opr1 = op1 (b1, b2)
  let opr3 = op3 (b1, b2)
  checkUnpred (opr1 = OprReg R.SP || opr1 = OprReg R.PC ||
               opr3 = OprReg R.SP || opr3 = OprReg R.PC)

let chkUnpreCJ (b1, b2) (op1, _, op3) =
  let opr1 = op1 (b1, b2)
  let opr3 = op3 (b1, b2)
  checkUnpred (opr1 = OprReg R.SP || opr1 = OprReg R.PC ||
               opr3 = OprReg R.SP || opr3 = OprReg R.PC)

let chkUnpreCK (b1, b2) (op1, op2, _ , _) =
  let opr1 = op1 (b1, b2)
  let opr2 = op2 (b1, b2)
  checkUnpred (opr1 = OprReg R.SP || opr1 = OprReg R.PC ||
               opr2 = OprReg R.SP || opr2 = OprReg R.PC)

let chkUnpreCL (b1, b2) (op1, op2, _ , _) =
  let msb = extract b2 4 0
  let lsb = concat (extract b2 14 12) (extract b2 7 6) 2
  let opr1 = op1 (b1, b2)
  checkUnpred (opr1 = OprReg R.SP || opr1 = OprReg R.PC ||
               op2 (b1, b2) = OprReg R.SP || msb < lsb)

let chkUnpreCM (b1, b2) (op1, _, _) =
  let msb = extract b2 4 0
  let lsb = concat (extract b2 14 12) (extract b2 7 6) 2
  let opr1 = op1 (b1, b2)
  checkUnpred (opr1 = OprReg R.SP || opr1 = OprReg R.PC || msb < lsb)

let chkUnpreCN (b1, b2) (_, op2) =
  let opr2 = op2 (b1, b2)
  checkUnpred (opr2 = OprReg R.SP || opr2 = OprReg R.PC)

let chkUnpreCO (_, b2) _ =
  checkUnpred (getAPSR (extract b2 11 10 |> byte) = (R.APSR, None))

let chkUnpreCP (b1, b2) (_, op2) =
  checkUnpred (extract b2 11 8 = 0b0000u || op2 (b1, b2) = OprReg R.PC)

let chkUnpreCQ (b1, b2) op1 =
  let opr1 = op1 (b1, b2)
  checkUnpred (opr1 = OprReg R.SP || opr1 = OprReg R.PC)

let chkUnpreCR (_, b2) _ =
  checkUnpred (pickBit b2 0 = 0b1u)

let chkUnpreCS itstate (_, b2) _ =
  checkUnpred ((extract b2 4 0 <> 0b0u && pickBit b2 8 = 0b0u) ||
               (pickBit b2 10 = 0b1u && extract b2 7 5 = 0b0u) ||
               (pickBit b2 10 = 0b0u && extract b2 7 5 <> 0b0u))
  checkUnpred (extract b2 10 9 = 1u || inITBlock itstate)

let chkUnpreCT (b1, b2) (op1, _) =
  let rn = getRegister (extract b1 3 0 |> byte)
  let w = pickBit b2 8
  let opr1 = op1 (b1, b2)
  checkUnpred (opr1 = OprReg R.SP || (opr1 = OprReg R.PC && w = 1u) ||
               (w = 1u && OprReg rn = op1 (b1, b2)))

let chkUnpreCU itstate (b1, b2) _ =
  let n = extract b1 3 0
  let t = extract b2 15 12
  checkUnpred ((pickBit b2 8 = 1u && n = t) ||
               (t = 15u && chkUnpreInAndNotLastItBlock itstate))

let chkUnpreCV (b1, b2) (op1, _) = checkUnpred (op1 (b1, b2) = OprReg R.SP)
let chkUnpreCW (b1, b2) (op1, _) =
  let rm = getRegister (extract b2 3 0 |> byte)
  checkUnpred (op1 (b1, b2) = OprReg R.SP || rm = R.SP || rm = R.PC)

let chkUnpreCX it (_, b2) _ =
  let rm = getRegister (extract b2 3 0 |> byte)
  let t = extract b2 15 12
  checkUnpred (rm = R.SP || rm = R.PC ||
                   (t = 15u && chkUnpreInAndNotLastItBlock it))

let chkUnpreCY (b1, b2) (op1, op2, op3) =
  let opr1 = op1 (b1, b2)
  let opr2 = op2 (b1, b2)
  let opr3 = op3 (b1, b2)
  checkUnpred (opr1 = OprReg R.SP || opr1 = OprReg R.PC ||
               opr2 = OprReg R.SP || opr2 = OprReg R.PC ||
               opr3 = OprReg R.SP || opr3 = OprReg R.PC)

let chkUnpreCZ (b1, b2) (op1, op2) =
  let opr1 = op1 (b1, b2)
  let opr2 = op2 (b1, b2)
  checkUnpred (opr1 = OprReg R.SP || opr1 = OprReg R.PC ||
               opr2 = OprReg R.SP || opr2 = OprReg R.PC ||
               OprReg (getRegister (extract b1 3 0 |> byte)) <> opr2 )

let chkUnpreDA (b1, b2) (op1, op2, op3, op4) =
  let opr1 = op1 (b1, b2)
  let opr2 = op2 (b1, b2)
  let opr3 = op3 (b1, b2)
  checkUnpred (opr1 = OprReg R.SP || opr1 = OprReg R.PC ||
               opr2 = OprReg R.SP || opr2 = OprReg R.PC ||
               opr3 = OprReg R.SP || opr3 = OprReg R.PC ||
               op4 (b1, b2) = OprReg R.SP)

let chkUnpreDB (b1, b2) (op1, op2, op3, op4) =
  let opr1 = op1 (b1, b2)
  let opr2 = op2 (b1, b2)
  let opr3 = op3 (b1, b2)
  let opr4 = op4 (b1, b2)
  checkUnpred (opr1 = OprReg R.SP || opr1 = OprReg R.PC ||
               opr2 = OprReg R.SP || opr2 = OprReg R.PC ||
               opr3 = OprReg R.SP || opr3 = OprReg R.PC ||
               opr4 = OprReg R.SP || opr4 = OprReg R.PC)

let chkUnpreDC (b1, b2) (op1, op2, op3, op4) =
  let opr1 = op1 (b1, b2)
  let opr2 = op2 (b1, b2)
  let opr3 = op3 (b1, b2)
  let opr4 = op4 (b1, b2)
  checkUnpred (opr1 = OprReg R.SP || opr1 = OprReg R.PC ||
               opr2 = OprReg R.SP || opr2 = OprReg R.PC ||
               opr3 = OprReg R.SP || opr3 = OprReg R.PC ||
               opr4 = OprReg R.SP || opr4 = OprReg R.PC ||
               opr1 = opr2)

let chkUnpreDD b _ =
  checkUnpred (List.length (getRegList (extract b 7 0)) < 1)

let chkUnpreDE itstate _ _ = checkUnpred (inITBlock itstate)

let chkUnpreDF itstate b _ =
    let d = concat (pickBit b 7) (extract b 2 0) 3
    checkUnpred (d = 15u && chkUnpreInAndNotLastItBlock itstate)

let chkUnpreDG itstate _ _ =
    checkUnpred (chkUnpreInAndNotLastItBlock itstate)

let chkUnpreDH itstate b op =
  checkUnpred (op b = OprReg R.PC || chkUnpreInAndNotLastItBlock itstate)

let chkUnpreDI itstate b _ =
  checkUnpred (extract b 19 16 = 15u ||
               chkUnpreInAndNotLastItBlock itstate)

let chkUnpreDJ it (b1, b2) op1 =
  checkUnpred (op1 (b1, b2) = OprReg R.SP ||
               (op1 (b1, b2) = OprReg R.PC && chkUnpreInAndNotLastItBlock it))

let chkUnpreDK itstate b (op, _) =
  checkUnpred (op b = OprReg R.PC && chkUnpreInAndNotLastItBlock itstate)

let chkUnpreDL mode b (op1, _) =
  checkUnpred (op1 b = OprReg R.SP && mode <> ArchOperationMode.ARMMode)

let chkUnpreDM (b1, b2) (op1, op2, op3) =
  let rd = op1 (b1, b2)
  checkUnpred (rd = OprReg R.SP || rd = OprReg R.PC)

let chkUndefA q b _ =
  let size = extract b 21 20
  checkUndef (size = 0u || size = 3u ||
               (q = 1u && (pickBit b 16 = 1u || pickBit b 12 = 1u)))

let chkUndefB q b _ =
  let size = extract b 21 20
  checkUndef (size = 0u || (pickBit b 8 = 1u && size = 1u) ||
               q = 1u && (pickBit b 12 = 1u || pickBit b 16 = 1u))

let chkUndefC b _ = checkUndef (extract b 21 20 = 0u || pickBit b 12 = 1u)

let chkUndefD b  _ =
  let pick = pickBit b
  checkUndef (pick 6 = 1u && (pick 12 = 1u || pick 16 = 1u || pick 0 = 1u))

let chkUndefE b _ = checkUndef (extract b 21 20 = 3u)

let chkUndefF b _ = chkUndefD b (); chkUndefE b ()

let chkUndefG b _ =
  checkUndef (pickBit b 6 = 0b0u && pickBit b 10 = 0b1u); chkUndefD b ()

let chkUndefH b _ =
  checkUndef (pickBit b 6 = 1u && (pickBit b 12 = 1u || pickBit b 0 = 1u))

let chkUndefJ b _ =
  checkUndef (extract b 21 20 = 3u || pickBit b 6 = 1u)

let chkUndefK b _ =
  let size = extract b 21 20
  checkUndef (size = 0u || size = 3u); chkUndefD b ()

let chkUndefL b _ = checkUndef (pickBit b 20 = 1u); chkUndefD b ()

let chkUndefM b _ = checkUndef (pickBit b 20 = 1u || pickBit b 6 = 1u)

let chkUndefN b _ = checkUndef (pickBit b 6 = 0b1u && pickBit b 12 = 0b1u)

let chkUndefO b _ = checkUndef (extract b 3 0 % 2u = 0b1u)

let chkUndefP b _ = checkUndef (pickBit b 21 = 0b0u); chkUndefH b ()

let chkUndefQ b _ =
  checkUndef (pickBit b 12 = 1u || (pickBit b 8 = 1u && pickBit b 16 = 1u))

let chkUndefR b _ = checkUndef (pickBit b 16 = 1u || pickBit b 0 = 1u)

let chkUndefS b _ = checkUndef (pickBit b 12 = 0b1u)

let chkUndefT b _ = checkUndef (extract b 21 20 = 0u || pickBit b 12 = 1u)

let chkUndefU b _ =
  chkUndefH b ()
  checkUndef (pickBit b 6 = 0u &&
               ((extract b 8 7) + (extract b 19 18)) >= 3u)

let chkUndefV b _ = chkUndefH b (); checkUndef (extract b 19 18 = 0b11u)

let chkUndefW b _ = chkUndefH b (); checkUndef (extract b 19 18 <> 0b10u)

let chkUndefX b _ =
  chkUndefH b (); checkUndef (pickBit b 6 = 0u && extract b 19 18 = 0b11u)

let chkUndefY b _ =
  chkUndefH b (); checkUndef (pickBit b 6 = 0u && extract b 19 18 <> 0b00u)

let chkUndefZ b _ =
  chkUndefH b (); checkUndef (extract b 19 18 <> 0b00u)

let chkUndefAA b _ =
  chkUndefH b (); checkUndef (extract b 19 18 = 0b11u)

let chkUndefAB b _ =
  chkUndefH b ()
  checkUndef (extract b 19 18 = 0b11u ||
               pickBit b 6 = 0u && extract b 19 18 = 0b10u)

let chkUndefAC b _ =
  let s = extract b 19 18
  chkUndefH b (); checkUndef (s = 0b11u || (pickBit b 10 = 1u && s <> 0b10u))
let chkUndefAD b _ = checkUndef (extract b 19 18 = 3u || pickBit b 0 = 1u)
let chkUndefAE b _ =
  let op = pickBit b 8
  checkUndef (extract b 19 18 <> 01u || (op = 1u && pickBit b 12 = 1u) ||
               (op = 0u && pickBit b 0 = 1u))
let chkUndefAF b _ =
  chkUndefH b (); checkUndef (extract b 19 18 <> 0b10u)
let chkUndefAG b _ =
  let q = pickBit b 6
  let i = extract b 19 16
  checkUndef ((q = 0u && (i = 0u || i = 8u)) || (q = 1u && pickBit b 12 = 1u))
let chkUndefAH b _ =
  let typ = extract b 11 8
  let align = extract b 5 4
  checkUndef (typ = 0b0111u && pickBit align 1 = 0b1u ||
               (typ = 0b1010u && align = 0b11u) ||
               (typ = 0b0110u && pickBit align 1 = 0b1u))
let chkUndefAI b _ =
  let typ = extract b 11 8
  let align = extract b 5 4
  checkUndef (extract b 7 6 = 0b11u || (typ = 0b1000u && align = 0b11u) ||
               (typ = 0b1001u && align = 0b11u))
let chkUndefAJ b _ = checkUndef (extract b 7 6 = 3u || pickBit b 5 = 1u)
let chkUndefAK b _ = checkUndef (extract b 7 6 = 0b11u)
let chkUndefAL b _ =
  let size = extract b 11 10
  let ia = extract b 7 4
  checkUndef ((size = 0b00u && pickBit ia 0 <> 0b0u) ||
               (size = 0b01u && pickBit ia 1 <> 0b0u) ||
               (size = 0b10u && pickBit ia 2 <> 0b0u) ||
               (size = 0b10u && extract ia 1 0 = 0b01u) ||
               (size = 0b10u && extract ia 1 0 = 0b10u))
let chkUndefAM b _ =
  checkUndef (extract b 11 10 = 0b10u && pickBit b 5 <> 0b0u)
let chkUndefAN b _ =
  let size = extract b 11 10
  let ia = extract b 7 4
  checkUndef ((size = 0b00u && pickBit ia 0 <> 0b0u) ||
               (size = 0b01u && pickBit ia 0 <> 0b0u) ||
               (size = 0b10u && extract ia 1 0 <> 0b00u))
let chkUndefAO b _ =
  checkUndef (extract b 11 10 = 0b10u && extract b 5 4 = 0b11u)
let chkUndefAP b _ =
  let size = extract b 7 6
  checkUndef (size = 0b11u || (size = 0b00u && pickBit b 4 = 0b1u))
let chkUndefAQ b _ = checkUndef (extract b 7 6 = 0b11u)
let chkUndefAR b _ = checkUndef (extract b 7 6 = 3u || pickBit b 4 = 1u)
let chkUndefAS b _ = checkUndef (extract b 7 6 = 3u && pickBit b 4 = 0u)
let chkUndefAT b _ =
  checkUndef (pickBit b 12 = 1u || pickBit b 0 = 1u ||
               extract b 19 18 <> 0u)
let chkUndefAU b _ =
  checkUndef (pickBit b 12 = 1u || pickBit b 0 = 1u ||
               extract b 19 18 <> 2u)

let chkBothA (b1, b2) (op1, op2) =
  checkUndef (getRegister (extract b1 3 0 |> byte) = R.PC)
  chkUnpreBL (b1, b2) (op1, op2)
let chkBothB (b1, b2) (op1, op2, op3, op4) =
  chkUnpreBX (b1, b2) (op1, op2, op3, op4)
  checkUndef (pickBit b1 4 = 0b1u || pickBit b2 4 = 0b1u)
let chkBothC (b1, b2) (op1 ,_) =
  let rn = getRegister (extract b1 3 0 |> byte)
  let opr1 = op1 (b1, b2)
  checkUndef (rn = R.PC)
  checkUnpred (opr1 = OprReg R.SP || opr1 = OprReg R.PC ||
               (pickBit b2 8 = 1u && OprReg rn = opr1))
let chkBothD (b1, b2) (op1, _) =
  let rn = getRegister (extract b1 3 0 |> byte)
  checkUndef (rn = R.PC)
  checkUnpred (op1 (b1, b2) = OprReg R.PC ||
               (pickBit b2 8 = 0b1u && OprReg rn = op1 (b1, b2)))
let chkBothE (b1, b2) (op1, op2) =
  checkUndef (getRegister (extract b1 3 0 |> byte) = R.PC)
  chkUnpreBL (b1, b2) (op1, op2)
let chkBothF (b1, b2) (op1, _) =
  checkUndef (getRegister (extract b1 3 0 |> byte) = R.PC)
  checkUnpred (op1 (b1, b2) = OprReg R.PC)
let chkBothG (b1, b2) (op1, _) =
  let rm = getRegister (extract b2 3 0 |> byte)
  let opr1 = op1 (b1, b2)
  checkUndef (getRegister (extract b1 3 0 |> byte) = R.PC)
  checkUnpred (opr1 = OprReg R.SP || opr1 = OprReg R.PC ||
               rm = R.SP || rm = R.PC)
let chkBothH (b1, b2) (op1, _) =
  let rm = getRegister (extract b2 3 0 |> byte)
  checkUndef (getRegister (extract b1 3 0 |> byte) = R.PC)
  checkUnpred (op1 (b1, b2) = OprReg R.PC || rm = R.SP || rm = R.PC)

let oneDt dt = Some (OneDT dt)
let twoDt (dt1, dt2) = Some (TwoDT (dt1, dt2))

let getOneDtA b = extract b 21 20 |> getSignedSizeBySize |> oneDt
let getOneDtB b =
  getIntSizeBySizeNF (extract b 21 20) (pickBit b 8) |> oneDt
let getOneDtC b =
  getSignednessSizeBySizeNU (extract b 19 18) (pickBit b 7) |> oneDt
let getOneDtD u b = getSignednessSizeBySizeNU (extract b 21 20) u |> oneDt
let getOneDtE () = oneDt SIMDTyp8
let getOneDtF b = extract b 21 20 |> getIntegerSizeBySize |> oneDt
let getOneDtG b = pickBit b 20 |> getFloatSizeBySz |> oneDt
let getOneDtH b =
  match concat (pickBit b 5) (extract b 11 9) 3 with
  | r when r &&& 0b0100u = 0b0000u -> SIMDTypI32
  | r when r &&& 0b0111u = 0b0110u -> SIMDTypI32
  | r when r &&& 0b0110u = 0b0100u -> SIMDTypI16
  | 0b1111u when pickBit b 8 = 0u -> SIMDTypI64
  | 0b0111u when pickBit b 8 = 0u -> SIMDTypI8
  | 0b0111u when pickBit b 8 = 1u -> SIMDTypF32
  | _ -> raise UndefinedException
  |> oneDt
let getOneDtI b =
  match concat (pickBit b 22) (pickBit b 5) 1 with
  | 0b00u -> SIMDTyp32
  | 0b01u -> SIMDTyp16
  | 0b10u -> SIMDTyp8
  | _ -> raise ParsingFailureException
  |> oneDt
let getOneDtJ u b =
  match u, concat (pickBit b 7) (extract b 21 19) 3 with
  | 0u, 1u -> SIMDTypS8
  | 1u, 1u -> SIMDTypU8
  | 0u, i when i &&& 0b1110u = 0b0010u -> SIMDTypS16
  | 1u, i when i &&& 0b1110u = 0b0010u -> SIMDTypU16
  | 0u, i when i &&& 0b1100u = 0b0100u -> SIMDTypS32
  | 1u, i when i &&& 0b1100u = 0b0100u -> SIMDTypU32
  | 0u, i when i &&& 0b1000u = 0b1000u -> SIMDTypS64
  | 1u, i when i &&& 0b1000u = 0b1000u -> SIMDTypU64
  | _ -> raise ParsingFailureException
  |> oneDt

let getOneDtK b =
  match concat (pickBit b 7) (extract b 21 19) 3 with
  | 1u -> SIMDTyp8
  | i when i &&& 0b1110u = 0b0010u -> SIMDTyp16
  | i when i &&& 0b1100u = 0b0100u -> SIMDTyp32
  | i when i &&& 0b1000u = 0b1000u -> SIMDTyp64
  | _ -> raise ParsingFailureException
  |> oneDt

let getOneDtL b =
  match concat (pickBit b 7) (extract b 21 19) 3 with
  | i when i &&& 0b1111u = 0b0001u -> SIMDTypI8
  | i when i &&& 0b1110u = 0b0010u -> SIMDTypI16
  | i when i &&& 0b1100u = 0b0100u -> SIMDTypI32
  | i when i &&& 0b1000u = 0b1000u -> SIMDTypI64
  | _ -> raise ParsingFailureException
  |> oneDt

let getOneDtM b =
  match extract b 21 19 with
  | 1u -> SIMDTypI16
  | i when i &&& 0b110u = 0b010u -> SIMDTypI32
  | i when i &&& 0b100u = 0b100u -> SIMDTypI64
  | _ -> raise ParsingFailureException
  |> oneDt

let getOneDtN b =
  match extract b 21 19 with
  | 1u -> SIMDTypS16
  | i when i &&& 0b110u = 0b010u -> SIMDTypS32
  | i when i &&& 0b100u = 0b100u -> SIMDTypS64
  | _ -> raise ParsingFailureException
  |> oneDt

let getOneDtO u b =
  match u, extract b 21 19 with
  | 0u, i when i &&& 0b111u = 0b001u -> SIMDTypS16
  | 1u, i when i &&& 0b111u = 0b001u -> SIMDTypU16
  | 0u, i when i &&& 0b110u = 0b010u -> SIMDTypS32
  | 1u, i when i &&& 0b110u = 0b010u -> SIMDTypU32
  | 0u, i when i &&& 0b100u = 0b100u -> SIMDTypS64
  | 1u, i when i &&& 0b100u = 0b100u -> SIMDTypU64
  | _ -> raise ParsingFailureException
  |> oneDt

let getOneDtP u b =
  match u, extract b 21 19 with
  | 0u, i when i &&& 0b111u = 0b001u -> SIMDTypS8
  | 1u, i when i &&& 0b111u = 0b001u -> SIMDTypU8
  | 0u, i when i &&& 0b110u = 0b010u -> SIMDTypS16
  | 1u, i when i &&& 0b110u = 0b010u -> SIMDTypU16
  | 0u, i when i &&& 0b100u = 0b100u -> SIMDTypS32
  | 1u, i when i &&& 0b100u = 0b100u -> SIMDTypU32
  | _ -> raise ParsingFailureException
  |> oneDt

let getOneDtQ b =
  extract b 21 20 |> getIntegerSizeBySize2 |> oneDt
let getOneDtR u b =
  match pickBit b 9, u, extract b 21 20 with
  | 0b0u, 0b0u, 0b00u -> SIMDTypS8
  | 0b0u, 0b0u, 0b01u -> SIMDTypS16
  | 0b0u, 0b0u, 0b10u -> SIMDTypS32
  | 0b0u, 0b1u, 0b00u -> SIMDTypU8
  | 0b0u, 0b1u, 0b01u -> SIMDTypU16
  | 0b0u, 0b1u, 0b10u -> SIMDTypU32
  | 0b1u, 0b0u, 0b00u -> SIMDTypP8
  | _ -> raise ParsingFailureException
  |> oneDt
let getOneDtS b = extract b 19 18 |> getSizeBySize |> oneDt
let getOneDtT b = extract b 19 18 |> getSignedSizeBySize |> oneDt
let getOneDtU b = extract b 19 18 |> getIntegerSizeBySize |> oneDt
let getOneDtV b =
  match extract b 19 18, pickBit b 10 with
  | 0b00u, 0b0u -> SIMDTypS8
  | 0b01u, 0b0u -> SIMDTypS16
  | 0b10u, 0b0u -> SIMDTypS32
  | 0b10u, 0b1u -> SIMDTypF32
  | _ -> raise ParsingFailureException
  |> oneDt
let getOneDtW b =
  getIntSizeBySizeNF (extract b 19 18) (pickBit b 10) |> oneDt
let getOneDtX b = extract b 19 18 |> getIntegerSizeBySize2 |> oneDt
let getOneDtY b =
  match extract b 7 6, extract b 19 18 with
  | 0b01u, 0b00u -> SIMDTypS16
  | 0b01u, 0b01u -> SIMDTypS32
  | 0b01u, 0b10u -> SIMDTypS64
  | 0b11u, 0b00u -> SIMDTypU16
  | 0b11u, 0b01u -> SIMDTypU32
  | 0b11u, 0b10u -> SIMDTypU64
  | _ -> raise ParsingFailureException
  |> oneDt
let getOneDtZ b =
  match extract b 19 18, pickBit b 8 with
  | 0b10u, 0u -> SIMDTypU32
  | 0b10u, 1u -> SIMDTypF32
  | _ -> raise ParsingFailureException
  |> oneDt
let getOneDtAA () = SIMDTypF32 |> oneDt
let getOneDtAB b =
  match extract b 19 16 with
  | i4 when i4 &&& 0b0001u = 0b0001u -> SIMDTyp8
  | i4 when i4 &&& 0b0011u = 0b0010u -> SIMDTyp16
  | i4 when i4 &&& 0b0111u = 0b0100u -> SIMDTyp32
  | _ -> raise ParsingFailureException
  |> oneDt
let getOneDtAC b = extract b 7 6 |> getSizeBySize |> oneDt
let getOneDtAD b = extract b 11 10 |> getSizeBySize |> oneDt
let getOneDtAE b = extract b 7 6 |> getSizeBySizeForVLD4 |> oneDt
let getOneDtAF b = pickBit b 8 |> getFloatSizeBySz |> oneDt
let getOneDtAG b =
  match concat (extract b 22 21) (extract b 6 5) 2 with
  | opc when opc &&& 0b1000u = 0b1000u -> SIMDTyp8
  | opc when opc &&& 0b1001u = 0b0001u -> SIMDTyp16
  | opc when opc &&& 0b1011u = 0b0000u -> SIMDTyp32
  | opc when opc &&& 0b1011u = 0b0010u -> raise UndefinedException
  | _ -> raise ParsingFailureException
  |> oneDt
let getOneDtAH b =
  let opc = concat (extract b 22 21) (extract b 6 5) 2
  match concat (pickBit b 23) opc 4 with
  | o when o &&& 0b11000u = 0b01000u -> SIMDTypS8
  | o when o &&& 0b11000u = 0b11000u -> SIMDTypU8
  | o when o &&& 0b11001u = 0b00001u -> SIMDTypS16
  | o when o &&& 0b11001u = 0b10001u -> SIMDTypU16
  | o when o &&& 0b11011u = 0b00000u -> SIMDTyp32
  | o when o &&& 0b11011u = 0b10000u -> raise UndefinedException
  | o when o &&& 0b01011u = 0b00010u -> raise UndefinedException
  | _ -> raise ParsingFailureException
  |> oneDt
let getOneDtAI () = SIMDTyp32 |> oneDt
let getQfW () = Some W
let getQfN () = Some N
let getTwoDtA u b =
  match u, pickBit b 8 with
  | 0b0u, 0b1u -> SIMDTypS32, SIMDTypF32
  | 0b1u, 0b1u -> SIMDTypU32, SIMDTypF32
  | 0b0u, 0b0u -> SIMDTypF32, SIMDTypS32
  | 0b1u, 0b0u -> SIMDTypF32, SIMDTypU32
  | _ -> raise ParsingFailureException
  |> twoDt
let getTwoDtB b =
  match extract b 8 7, extract b 19 18 with
  | 0b10u, 0b10u -> SIMDTypS32, SIMDTypF32
  | 0b11u, 0b10u -> SIMDTypU32, SIMDTypF32
  | 0b00u, 0b10u -> SIMDTypF32, SIMDTypS32
  | 0b01u, 0b10u -> SIMDTypF32, SIMDTypU32
  | _ -> raise ParsingFailureException
  |> twoDt
let getTwoDtC b =
  match pickBit b 8 with
  | 0b0u -> SIMDTypF16, SIMDTypF32
  | 0b1u -> SIMDTypF32, SIMDTypF16
  | _ -> raise ParsingFailureException
  |> twoDt
let getTwoDtD b =
  match pickBit b 8 with
  | 0b0u -> SIMDTypF64, SIMDTypF32
  | 0b1u -> SIMDTypF32, SIMDTypF64
  | _ -> raise ParsingFailureException
  |> twoDt
let getTwoDtE b =
  match pickBit b 16 with
  | 0b0u -> SIMDTypF32, SIMDTypF16
  | 0b1u -> SIMDTypF16, SIMDTypF32
  | _ -> raise ParsingFailureException
  |> twoDt
let getTwoDtF b =
  match extract b 18 16, pickBit b 8 with
  | 0b101u, 1u -> SIMDTypS32, SIMDTypF64
  | 0b101u, 0u -> SIMDTypS32, SIMDTypF32
  | 0b100u, 1u -> SIMDTypU32, SIMDTypF64
  | 0b100u, 0u -> SIMDTypU32, SIMDTypF32
  | 0b000u, 1u -> SIMDTypF64, (getSignednessSize32ByOp (pickBit b 7))
  | 0b000u, 0u -> SIMDTypF32, (getSignednessSize32ByOp (pickBit b 7))
  | _ -> raise ParsingFailureException
  |> twoDt
let getTwoDtG b =
  match extract b 18 16, pickBit b 8 with
  | 0b101u, 1u -> SIMDTypS32, SIMDTypF64
  | 0b101u, 0u -> SIMDTypS32, SIMDTypF32
  | 0b100u, 1u -> SIMDTypU32, SIMDTypF64
  | 0b100u, 0u -> SIMDTypU32, SIMDTypF32
  | _ -> raise ParsingFailureException
  |> twoDt
let getTwoDtH b =
  let u = pickBit b 16
  let sx = pickBit b 7
  match pickBit b 18, pickBit b 8 with
  | 0b1u, 1u -> (getSignednessSizeByUNSx u sx), SIMDTypF64
  | 0b1u, 0u -> (getSignednessSizeByUNSx u sx), SIMDTypF32
  | 0b0u, 1u -> SIMDTypF64, (getSignednessSizeByUNSx u sx)
  | 0b0u, 0u -> SIMDTypF32, (getSignednessSizeByUNSx u sx)
  | _ -> raise ParsingFailureException
  |> twoDt

let getRrRsSCa q = getRegR q, getRegS q, getScalarA

let getRxIa opcode i = getRegX, getImmA opcode i

/// Multiply and multiply-accumulate, page A5-202 in ARMv7-A , DDI0406C.b
/// Multiply and Accumulate, page F4.2.2 in ARMv8-A ARM DDI 0487A.k
let parseMulNMulAcc bin =
  match extract bin 23 20 with
  | 0b0000u -> Op.MUL, None,
               parseThreeOprs bin chkUnpreA (getRegC, getRegA, getRegB)
  | 0b0001u -> Op.MULS, None,
               parseThreeOprs bin chkUnpreA (getRegC, getRegA, getRegB)
  | 0b0010u -> Op.MLA, None,
               parseFourOprs bin chkUnpreB (getRegC, getRegA, getRegB, getRegD)
  | 0b0011u -> Op.MLAS, None,
               parseFourOprs bin chkUnpreB (getRegC, getRegA, getRegB, getRegD)
  | 0b0100u -> Op.UMAAL, None,
               parseFourOprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
  | 0b0101u -> raise UndefinedException
  | 0b0110u -> Op.MLS, None,
               parseFourOprs bin chkUnpreB (getRegC, getRegA, getRegB, getRegD)
  | 0b0111u -> raise UndefinedException
  | 0b1000u -> Op.UMULL, None,
               parseFourOprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
  | 0b1001u -> Op.UMULLS, None,
               parseFourOprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
  | 0b1010u -> Op.UMLAL, None,
               parseFourOprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
  | 0b1011u -> Op.UMLALS, None,
               parseFourOprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
  | 0b1100u -> Op.SMULL, None,
               parseFourOprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
  | 0b1101u -> Op.SMULLS, None,
               parseFourOprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
  | 0b1110u -> Op.SMLAL, None,
               parseFourOprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
  | 0b1111u -> Op.SMLALS, None,
               parseFourOprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
  | _ -> raise ParsingFailureException

/// Halfword multiply and multi..., page A5-203 in ARMv7-A , DDI0406C.b
/// Halfword Multiply and Accumulate on page F4-2510  in ARMv8-A ARM DDI 0487A.k
let parseHalfMulNMulAcc bin =
  match concat (extract bin 22 21) (extract bin 6 5) 2 with
  | 0b0000u -> Op.SMLABB, None,
               parseFourOprs bin chkUnpreB (getRegC, getRegA, getRegB, getRegD)
  | 0b0001u -> Op.SMLATB, None,
               parseFourOprs bin chkUnpreB (getRegC, getRegA, getRegB, getRegD)
  | 0b0010u -> Op.SMLABT, None,
               parseFourOprs bin chkUnpreB (getRegC, getRegA, getRegB, getRegD)
  | 0b0011u -> Op.SMLATT, None,
               parseFourOprs bin chkUnpreB (getRegC, getRegA, getRegB, getRegD)
  | 0b0100u -> Op.SMLAWB, None,
               parseFourOprs bin chkUnpreB (getRegC, getRegA, getRegB, getRegD)
  | 0b0110u -> Op.SMLAWT, None,
               parseFourOprs bin chkUnpreB (getRegC, getRegA, getRegB, getRegD)
  | 0b0101u -> Op.SMULWB, None,
               parseThreeOprs bin dummyChk (getRegD, getRegA, getRegB)
  | 0b0111u -> Op.SMULWT, None,
               parseThreeOprs bin chkUnpreA (getRegC, getRegA, getRegB)
  | 0b1000u -> Op.SMLALBB, None,
               parseFourOprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
  | 0b1001u -> Op.SMLALTB, None,
               parseFourOprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
  | 0b1010u -> Op.SMLALBT, None,
               parseFourOprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
  | 0b1011u -> Op.SMLALTT, None,
               parseFourOprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
  | 0b1100u -> Op.SMULBB, None,
               parseThreeOprs bin chkUnpreA (getRegC, getRegA, getRegB)
  | 0b1101u -> Op.SMULTB, None,
               parseThreeOprs bin chkUnpreA (getRegC, getRegA, getRegB)
  | 0b1110u -> Op.SMULBT, None,
               parseThreeOprs bin chkUnpreA (getRegC, getRegA, getRegB)
  | 0b1111u -> Op.SMULTT, None,
               parseThreeOprs bin chkUnpreA (getRegC, getRegA, getRegB)
  | _ -> raise ParsingFailureException

/// OprMemory hints, Adv SIMD instrs, and miscellaneous instrs, page A5-217
/// CPS, CPSID, CPSIE on page F4-2645 in ARMv8-A ARM DDI 0487A.k
let getCPS bin =
  match extract bin 19 18, pickBit bin 17 with
  | 0u, 0u -> raise UnpredictableException
  | 0u, 1u -> Op.CPS, parseOneOpr bin dummyChk getImm5B
  | 1u, _ -> raise UnpredictableException
  | 2u, 0u -> Op.CPSIE, parseOneOpr bin dummyChk getFlagA
  | 2u, 1u -> Op.CPSIE, parseTwoOprs bin dummyChk (getFlagA, getImm5B)
  | 3u, 0u -> Op.CPSID, parseOneOpr bin dummyChk getFlagA
  | 3u, 1u -> Op.CPSID, parseTwoOprs bin dummyChk (getFlagA, getImm5B)
  | _ -> raise ParsingFailureException

// vim: set tw=80 sts=2 sw=2:
