(*
    B2R2 - the Next-Generation Reversing Platform

    Author: Seung Il Jung <sijung@kaist.ac.kr>
                    DongYeop Oh <oh51dy@kaist.ac.kr>

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

module internal B2R2.FrontEnd.ARM32.OperandHelper

open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.ARM32.ParseUtils

(* Offset *)
let memOffsetImm offset = Memory (OffsetMode (ImmOffset offset))
let memOffsetReg offset = Memory (OffsetMode (RegOffset offset))
let memOffsetAlign offset = Memory (OffsetMode (AlignOffset offset))
(* Pre-Indexed [<Rn>, #+/-<imm>]! *)
let memPreIdxImm offset = Memory (PreIdxMode (ImmOffset offset))
let memPreIdxReg offset = Memory (PreIdxMode (RegOffset offset))
let memPreIdxAlign offset = Memory (PreIdxMode (AlignOffset offset))
(* Post-Indexed *)
let memPostIdxImm offset = Memory (PostIdxMode (ImmOffset offset))
let memPostIdxReg offset = Memory (PostIdxMode (RegOffset offset))
let memPostIdxAlign offset = Memory (PostIdxMode (AlignOffset offset))
(* Label *)
let memLabel lbl = Memory (LiteralMode lbl)
(* Unindexed *)
let memUnIdxImm offset = Memory (UnIdxMode offset)
(* SIMD Operand *)
let sVReg vReg = vReg |> Vector |> SFReg |> SIMDOpr
let sSReg scalar = scalar |> Scalar |> SFReg |> SIMDOpr

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

let isUnpredictable cond = if cond then raise UnpredictableException else ()
let isUndefined cond = if cond then raise UndefinedException else ()
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

let getRegisterW (reg: Register) bool =
    let b = if bool then 0x01000000 else 0
    enum<Register> (0x10000000 ||| int reg ||| b)

let getOption = function
    | 0b0010uy -> OSHST
    | 0b0011uy -> OSH
    | 0b0110uy -> NSHST
    | 0b0111uy -> NSH
    | 0b1010uy -> ISHST
    | 0b1011uy -> ISH
    | 0b1110uy -> ST
    | 0b1111uy -> SY
    | _ -> raise InvalidOptionException

let getIflag = function
    | 0b100uy -> A
    | 0b010uy -> I
    | 0b001uy -> F
    | 0b110uy -> AI
    | 0b101uy -> AF
    | 0b011uy -> IF
    | 0b111uy -> AIF
    | _ -> raise InvalidIFlagException

let getEndian = function
    | 0b0uy -> Endian.Little
    | 0b1uy -> Endian.Big
    | _ -> raise InvalidEndianException

let getFloatSizeBySz = function
    | 0b0u -> SIMDTypF32
    | 0b1u -> SIMDTypF64
    | _ -> raise InvalidSizeException

let getSignednessSize32ByOp = function
    | 0b0u -> SIMDTypU32
    | 0b1u -> SIMDTypS32
    | _ -> raise InvalidSizeException

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
    | _ -> raise InvalidSizeException

let getIntegerSizeBySize = function
    | 0b00u -> SIMDTypI8
    | 0b01u -> SIMDTypI16
    | 0b10u -> SIMDTypI32
    | 0b11u -> SIMDTypI64
    | _ -> raise InvalidSizeException

let getIntegerSizeBySize2 = function
    | 0b00u -> SIMDTypI16
    | 0b01u -> SIMDTypI32
    | 0b10u -> SIMDTypI64
    | _ -> raise InvalidSizeException

let getSignedSizeBySize = function
    | 0b00u -> SIMDTypS8
    | 0b01u -> SIMDTypS16
    | 0b10u -> SIMDTypS32
    | 0b11u -> SIMDTypS64
    | _ -> raise InvalidSizeException

let getSizeBySize = function
    | 0b00u -> SIMDTyp8
    | 0b01u -> SIMDTyp16
    | 0b10u -> SIMDTyp32
    | 0b11u -> SIMDTyp64
    | _ -> raise InvalidSizeException

let getIntSizeBySizeNF size f =
    match size, f with
    | 0b00u, 0b0u -> SIMDTypI8
    | 0b01u, 0b0u -> SIMDTypI16
    | 0b10u, 0b0u -> SIMDTypI32
    | 0b01u, 0b1u -> SIMDTypF16
    | 0b10u, 0b1u -> SIMDTypF32
    | _ -> raise InvalidSizeException

let getSizeBySizeForVLD4 = function
    | 0b00u -> SIMDTyp8
    | 0b01u -> SIMDTyp16
    | 0b10u -> SIMDTyp32
    | 0b11u -> SIMDTyp32
    | _ -> raise InvalidSizeException

let getSignednessSizeByUNSx u sx =
    match u, sx with
    | 0u, 0u -> SIMDTypS16
    | 1u, 0u -> SIMDTypU16
    | 0u, 1u -> SIMDTypS32
    | 1u, 1u -> SIMDTypU32
    | _ -> failwith "Wrong data type encoding."

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

let getSIMDVFPRegList d vd rs sz =
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
    | _ -> failwith "Invalid SIMD operand"
    |> SIMDOpr

(* SIMD scalar list *)
let getSIMDScalar idx rLst =
    let s v = Scalar (v, idx)
    match rLst with
    | [ vt ] -> OneReg (s vt)
    | [ vt; vt2 ] -> TwoRegs (s vt, s vt2)
    | [ vt; vt2; vt3 ] -> ThreeRegs (s vt, s vt2, s vt3)
    | [ vt; vt2; vt3; vt4 ] -> FourRegs (s vt, s vt2, s vt3, s vt4)
    | _ -> failwith "Invalid SIMD operand"
    |> SIMDOpr

let getShiftOprByRotate = function
    | 0b00u -> Shift (SRTypeROR, Imm 0u) // omitted when it is disassembled
    | 0b01u -> Shift (SRTypeROR, Imm 8u)
    | 0b10u -> Shift (SRTypeROR, Imm 16u)
    | 0b11u -> Shift (SRTypeROR, Imm 24u)
    | _ -> failwith "Wrong operand encoding."

let getIdxForVStoreLoad1 ia = function
    | 0b00u when pickBit ia 0u = 0b0u -> Some (extract ia 3u 1u |> uint8)
    | 0b01u when extract ia 1u 0u = 0b00u -> Some (extract ia 3u 2u |> uint8)
    | 0b01u when extract ia 1u 0u = 0b01u -> Some (extract ia 3u 2u |> uint8)
    | 0b10u when extract ia 2u 0u = 0b000u -> Some (pickBit ia 3u |> uint8)
    | 0b10u when extract ia 2u 0u = 0b011u -> Some (pickBit ia 3u |> uint8)
    | _ -> failwith "Wrong index for VST1."

let getIdxForVStoreLoad2 ia = function
    | 0b00u -> Some (extract ia 3u 1u |> uint8)
    | 0b01u -> Some (extract ia 3u 2u |> uint8)
    | 0b10u when extract ia 2u 0u = 0b000u -> Some (pickBit ia 3u |> uint8)
    | 0b10u when extract ia 2u 0u = 0b001u -> Some (pickBit ia 3u |> uint8)
    | 0b10u when extract ia 2u 0u = 0b100u -> Some (pickBit ia 3u |> uint8)
    | 0b10u when extract ia 2u 0u = 0b101u -> Some (pickBit ia 3u |> uint8)
    | _ -> failwith "Wrong index spcaing align for VST2."

let getSpaceForVStoreLoad2 ia = function
    | 0b00u -> Single
    | 0b01u when extract ia 1u 0u = 0b00u -> Single
    | 0b01u when extract ia 1u 0u = 0b01u -> Single
    | 0b01u when extract ia 1u 0u = 0b10u -> Double
    | 0b01u when extract ia 1u 0u = 0b11u -> Double
    | 0b10u when extract ia 2u 0u = 0b000u -> Single
    | 0b10u when extract ia 2u 0u = 0b001u -> Single
    | 0b10u when extract ia 2u 0u = 0b100u -> Double
    | 0b10u when extract ia 2u 0u = 0b101u -> Double
    | _ -> failwith "Wrong index spcaing align for VST2."

let getIdxForVStoreLoad3 ia = function
    | 0b00u when pickBit ia 0u = 0b0u -> Some (extract ia 3u 1u |> uint8)
    | 0b01u when extract ia 1u 0u = 0b00u -> Some (extract ia 3u 2u |> uint8)
    | 0b01u when extract ia 1u 0u = 0b10u -> Some (extract ia 3u 2u |> uint8)
    | 0b10u when extract ia 2u 0u = 0b000u -> Some (pickBit ia 3u |> uint8)
    | 0b10u when extract ia 2u 0u = 0b100u -> Some (pickBit ia 3u |> uint8)
    | _ -> failwith "Wrong index spcaing align for VST3."

let getSpaceForVStoreLoad3 ia = function
    | 0b00u when pickBit ia 0u = 0b0u -> Single
    | 0b01u when extract ia 1u 0u = 0b00u -> Single
    | 0b01u when extract ia 1u 0u = 0b10u -> Double
    | 0b10u when extract ia 2u 0u = 0b000u -> Single
    | 0b10u when extract ia 2u 0u = 0b100u -> Double
    | _ -> failwith "Wrong index spcaing align for VST3."

let getIdxForVStoreLoad4 ia = function
    | 0b00u -> Some (extract ia 3u 1u |> uint8)
    | 0b01u -> Some (extract ia 3u 2u |> uint8)
    | 0b10u when extract ia 2u 0u = 0b000u -> Some (pickBit ia 3u |> uint8)
    | 0b10u when extract ia 2u 0u = 0b001u -> Some (pickBit ia 3u |> uint8)
    | 0b10u when extract ia 2u 0u = 0b010u -> Some (pickBit ia 3u |> uint8)
    | 0b10u when extract ia 2u 0u = 0b100u -> Some (pickBit ia 3u |> uint8)
    | 0b10u when extract ia 2u 0u = 0b101u -> Some (pickBit ia 3u |> uint8)
    | 0b10u when extract ia 2u 0u = 0b110u -> Some (pickBit ia 3u |> uint8)
    | _ -> failwith "Wrong index spcaing align for VST4."

let getSpaceForVStoreLoad4 ia = function
    | 0b00u -> Single
    | 0b01u when extract ia 1u 0u = 0b00u -> Single
    | 0b01u when extract ia 1u 0u = 0b01u -> Single
    | 0b01u when extract ia 1u 0u = 0b10u -> Double
    | 0b01u when extract ia 1u 0u = 0b11u -> Double
    | 0b10u when extract ia 2u 0u = 0b000u -> Single
    | 0b10u when extract ia 2u 0u = 0b001u -> Single
    | 0b10u when extract ia 2u 0u = 0b010u -> Single
    | 0b10u when extract ia 2u 0u = 0b100u -> Double
    | 0b10u when extract ia 2u 0u = 0b101u -> Double
    | 0b10u when extract ia 2u 0u = 0b110u -> Double
    | _ -> failwith "Wrong index spcaing align for VST4."

let getImm11110 opcode i =
    isValidOpcode (opcode <> Op.VMOV)
    let getImm n = pickBit i n |> int64
    0xf0000000L * getImm 7u + 0x0f000000L * getImm 6u + 0x00f00000L * getImm 5u +
    0x000f0000L * getImm 4u + 0x0000f000L * getImm 3u + 0x00000f00L * getImm 2u +
    0x000000f0L * getImm 1u + 0x0000000fL * getImm 0u

let getImm01111 opcode i = // FIXME : immediate encoding
    isValidOpcode (opcode <> Op.VMOV)
    let a = pickBit (i |> uint32) 7u |> int64
    let b = pickBit (i |> uint32) 6u |> int64
    let b5 = b + (b <<< 1) + (b <<< 2) + (b <<< 3) + (b <<< 4)
    let cdefg = extract (i |> uint32) 5u 0u |> int64
    (a <<< 63) + ((b ^^^ 1L) <<< 62) + (b5 <<< 57) + (cdefg <<< 51) +
    (a <<< 31) + ((b ^^^ 1L) <<< 30) + (b5 <<< 25) + (cdefg <<< 19)

let getFloatingPointImm64 i = // FIXME : immediate encoding
    let a = pickBit (i |> uint32) 7u |> int64
    let b = pickBit (i |> uint32) 6u |> int64
    let b8 = b + (b <<< 1) + (b <<< 2) + (b <<< 3) + (b <<< 4) +
                      (b <<< 5) + (b <<< 6) + (b <<< 7)
    let cdefg = extract (i |> uint32) 5u 0u |> int64
    (a <<< 63) + ((b ^^^ 1L) <<< 62) + (b8 <<< 54) + (cdefg <<< 48)

let getFloatingPointImm32 i = // FIXME : immediate encoding
    let a = pickBit (i |> uint32) 7u |> int64
    let b = pickBit (i |> uint32) 6u |> int64
    let b5 = b + (b <<< 1) + (b <<< 2) + (b <<< 3) + (b <<< 4)
    let cdefg = extract (i |> uint32) 5u 0u |> int64
    (a <<< 31) + ((b ^^^ 1L) <<< 30) + (b5 <<< 25) + (cdefg <<< 19)

let getReg b s e = getRegister (extract b s e |> byte)

let getSign s = if s = 1u then Plus else Minus

let retSndIfNotTheSame a b = isUnpredictable (a = b); b
let checkSize size v = isUnpredictable (size = v)

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

let getRegA b = getReg b 3u 0u |> Register
let getRegB b = getReg b 11u 8u |> Register
let getRegC b = getReg b 19u 16u |> Register
let getRegD b = getReg b 15u 12u |> Register
let getRegE _ = Register R.APSR
let getRegF b = getRegister (extract b 3u 0u + 1u |> byte) |> Register
let getRegG b = getReg b 8u 6u |> Register
let getRegH b = getReg b 5u 3u |> Register
let getRegI b = getReg b 2u 0u |> Register
let getRegJ b = getReg b 10u 8u |> Register
let getRegK b =
    let mask = extract b 19u 16u
    if pickBit b 22u = 0b0u then getCPSR (mask |> byte) |> SpecReg
    else getSPSR (mask |> byte) |> SpecReg
let getRegL b = getRegister (extract b 15u 12u + 1u |> byte) |> Register
let getRegM b = Register (getRegisterW R.SP (pickBit b 21u <> 0b0u))
let getRegN b = Register (getRegisterW (getReg b 19u 16u)
                                                                              (pickBit b 21u <> 0b0u))
let getRegO b = concat (pickBit b 7u) (extract b 2u 0u) 3 |> byte
                                |> getRegister |> Register
let getRegP b = getReg b 6u 3u |> Register
let getRegQ b =
    let mask = extract b 19u 16u
    if pickBit b 22u = 0u then getCPSR (byte mask) |> SpecReg
    else getSPSR (byte mask) |> SpecReg
let getRegR q b =
    let regSize = if q = 0u then 64 else 128
    getVReg (pickBit b 22u) (extract b 15u 12u) regSize |> sVReg
let getRegS q b =
    let regSize = if q = 0u then 64 else 128
    getVReg (pickBit b 7u) (extract b 19u 16u) regSize |> sVReg
let getRegT q b =
    let regSize = if q = 0u then 64 else 128
    getVReg (pickBit b 5u) (extract b 3u 0u) regSize |> sVReg
let getRegU b = concat (pickBit b 7u) (extract b 19u 16u >>> 1) 3 |> byte
                                |> getVFPQRegister |> sVReg
let getRegV b = concat (pickBit b 7u) (extract b 19u 16u) 4 |> byte
                                |> getVFPDRegister |> sVReg
let getRegX b =
    let regSize = if pickBit b 6u = 0u then 64 else 128
    getVReg (pickBit b 22u) (extract b 15u 12u) regSize |> sVReg
let getRegY b =
    let regSize = if pickBit b 6u = 0u then 64 else 128
    getVReg (pickBit b 7u) (extract b 19u 16u) regSize |> sVReg
let getRegZ b =
    let regSize = if pickBit b 6u = 0u then 64 else 128
    getVReg (pickBit b 5u) (extract b 3u 0u) regSize |> sVReg
let getRegAA b = Register (getRegisterW (getReg b 19u 16u)
                                                                                (pickBit b 21u <> 0b0u))
let getRegAB b =
    let regSize = if pickBit b 21u = 0u then 64 else 128
    getVReg (pickBit b 7u) (extract b 19u 16u) regSize |> sVReg
let getRegAC b = concat (pickBit b 22u) (extract b 15u 12u) 4 |> byte
                                  |> getVFPDRegister |> sVReg
let getRegAD b = concat (pickBit b 5u) (extract b 3u 0u >>> 1) 3 |> byte
                                  |> getVFPQRegister |> sVReg
let getRegAE b = concat (pickBit b 22u) (extract b 15u 12u >>> 1) 3 |> byte
                                  |> getVFPQRegister |> sVReg
let getRegAF b = concat (pickBit b 5u) (extract b 3u 0u) 4 |> byte
                                  |> getVFPDRegister |> sVReg
let getRegAG b =
    let regSize = if pickBit b 8u = 0u then 64 else 128
    getVReg (pickBit b 7u) (extract b 19u 16u) regSize |> sVReg
let getRegAH b =
    let regSize = if pickBit b 8u = 0u then 64 else 128
    getVReg (pickBit b 5u) (extract b 3u 0u) regSize |> sVReg
let getRegAI b =
    let regSize = if pickBit b 8u = 0u then 64 else 128
    getVReg (pickBit b 22u) (extract b 15u 12u) regSize |> sVReg
let getRegAJ b = concat (extract b 3u 0u) (pickBit b 5u) 1 |> byte
                                  |> getVFPSRegister |> sVReg
let getRegAK b = (concat (extract b 15u 12u) (pickBit b 22u) 1) + 1u |> byte
                                  |> getVFPSRegister |> sVReg
let getRegAL b =
    let regSize = if pickBit b 8u = 0u then 32 else 64
    getVReg (pickBit b 22u) (extract b 15u 12u) regSize |> sVReg
let getRegAM b =
    let regSize = if pickBit b 8u = 0u then 32 else 64
    getVReg (pickBit b 7u) (extract b 19u 16u) regSize |> sVReg
let getRegAN b =
    let regSize = if pickBit b 8u = 0u then 32 else 64
    getVReg (pickBit b 5u) (extract b 3u 0u) regSize |> sVReg
let getRegAO b = concat (extract b 15u 12u) (pickBit b 22u) 1 |> byte
                                  |> getVFPSRegister |> sVReg
let getRegAP b =
    let regSize =
        match extract b 18u 16u, pickBit b 8u with
        | 0b000u, 0b1u -> 64
        | 0b101u, _ | 0b100u, _ | 0b000u, 0b0u -> 32
        | _ -> failwith "Wrong regAP encoding."
    getVReg (pickBit b 22u) (extract b 15u 12u) regSize |> sVReg

let getRegAQ b =
    let regSize =
        match extract b 18u 16u, pickBit b 8u with
        | 0b101u, 0b1u | 0b100u, 0b1u -> 64
        | 0b101u, 0b0u | 0b100u, 0b0u | 0b000u, _ -> 32
        | _ -> failwith "Wrong regAQ encoding."
    getVReg (pickBit b 5u) (extract b 3u 0u) regSize |> sVReg

let getRegAR b =
    match extract b 18u 16u, pickBit b 8u with
    | 0b101u, _ | 0b100u, _ ->
            concat (extract b 15u 12u) (pickBit b 22u) 1 |> byte
            |> getVFPSRegister |> sVReg
    | _ -> failwith "Wrong regAR encoding."

let getRegAS b =
    let regSize =
        match extract b 18u 16u, pickBit b 8u with
        | 0b101u, 0b1u | 0b100u, 0b1u -> 64
        | 0b101u, 0b0u | 0b100u, 0b0u -> 32
        | _ -> failwith "Wrong regAS encoding."
    getVReg (pickBit b 5u) (extract b 3u 0u) regSize |> sVReg

let getRegAT b = 
    let regSize = if pickBit b 8u  = 1u then 64 else 32
    getVReg (pickBit b 22u) (extract b 15u 12u) regSize |> sVReg

let getRegAU b = concat (extract b 19u 16u) (pickBit b 7u) 1 |> byte
                                  |> getVFPSRegister |> sVReg

let getRegAV (_, b2) = extract b2 11u 8u |> byte |> getRegister |> Register
let getRegAW (_, b2) = extract b2 15u 12u |> byte |> getRegister |> Register
let getRegAX (_, b2) = extract b2 3u 0u |> byte |> getRegister |> Register
let getRegAY (b1, _) = extract b1 3u 0u |> byte |> getRegister |> Register
let getRegAZ b = 
    let reg = getReg b 15u 12u
    if reg = R.PC then SpecReg (R.APSR, Some PSRnzcv)
    else Register reg

let getRegSP _ = Register R.SP
let getRegPC _ = Register R.PC
let getRegLR _ = Register R.LR
let getAPSRxA b = 
    let mask = extract b 19u 18u
    isUnpredictable (mask = 00u)
    mask |> byte |> getAPSR |> SpecReg
let getAPSRxB b = extract b 19u 18u |> byte |> getAPSR |> SpecReg
let getAPSRxC (_, b2) = extract b2 11u 10u |> byte |> getAPSR |> SpecReg
let getxPSRxA (b1, b2) =
    let mask = extract b2 11u 8u
    if pickBit b1 4u = 0u then getCPSR (mask |> byte) |> SpecReg
    else getSPSR (mask |> byte) |> SpecReg
let getxPSRxB (b1, _) =
    if pickBit b1 4u = 0b0u then R.APSR |> Register else R.SPSR |> Register
let getRegFPSCR _ = Register R.FPSCR
let getBankedRegA bin =
    let sysM = concat (pickBit bin 8u) (extract bin 19u 16u) 4
    getBankedRegs (pickBit bin 22u) sysM |> Register
let getBankedRegB (_, b2) =
    let sysM = concat (pickBit b2 4u) (extract b2 11u 8u) 4
    getBankedRegs 0b1u sysM |> Register
let getBankedRegC (b1, b2) =
    let sysM = concat (pickBit b2 4u) (extract b1 3u 0u) 4
    getBankedRegs (pickBit b1 4u) sysM |> Register
let getRegisterWA b =
    getRegisterW (getRegister (extract b 19u 16u |> byte)) (pickBit b 21u <> 0b0u)
    |> Register
let getRegisterWB (b1, _) =
    getRegisterW (getRegister (extract b1 3u 0u |> byte)) (pickBit b1 5u <> 0b0u)
    |> Register
let getRegisterWC b =
    Register (getRegisterW (getRegister (extract b 10u 8u |> byte)) true)
let getRegisterWD b =
    let rn = getRegister (extract b 10u 8u |> byte)
    let rl = extract b 7u 0u |> getRegList
    if List.exists (fun e -> e = rn) rl then Register (getRegisterW rn false)
    else Register (getRegisterW rn true)
let getCRegA b = extract b 15u 12u |> byte |> getCoprocCRegister |> Register
let getCRegB b = extract b 3u 0u |> byte |> getCoprocCRegister |> Register
let getCRegC b = extract b 19u 16u |> byte |> getCoprocCRegister |> Register
let getPRegA b = extract b 11u 8u |> byte |> getCoprocPRegister |> Register

let getRegListA b =
    let d = concat (pickBit b 7u) (extract b 19u 16u) 4
    match extract b 9u 8u with
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
    | _ -> failwith "Wrong DRegListByDn encoding."

let getRegListB b =
    let d = concat (pickBit b 22u) (extract b 15u 12u) 4
    match extract b 11u 8u with
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
    | _ -> failwith "Wrong DRegListByDd encoding."

let getRegListC b =
    let d = concat (pickBit b 22u) (extract b 15u 12u) 4
    let i = getIdxForVStoreLoad1 (extract b 7u 4u) (extract b 11u 10u)
    getSIMDScalar i [ getVFPDRegister (d |> byte) ]

let getRegListD b =
    let d = concat (pickBit b 22u) (extract b 15u 12u) 4
    let ia = extract b 7u 4u
    let sz = extract b 11u 10u
    let i = getIdxForVStoreLoad2 ia sz
    match getSpaceForVStoreLoad2 ia sz with
    | Single -> getSIMDScalar i [ getVFPDRegister (d |> byte);
                                                                getVFPDRegister (d + 1u |> byte); ]
    | Double -> getSIMDScalar i [ getVFPDRegister (d |> byte);
                                                                getVFPDRegister (d + 2u |> byte); ]

let getRegListE b =
    let d = concat (pickBit b 22u) (extract b 15u 12u) 4
    let ia = extract b 7u 4u
    let sz = extract b 11u 10u
    let i = getIdxForVStoreLoad3 ia sz
    match getSpaceForVStoreLoad3 ia sz with
    | Single -> getSIMDScalar i [ getVFPDRegister (d |> byte);
                                                                getVFPDRegister (d + 1u |> byte);
                                                                getVFPDRegister (d + 2u |> byte); ]
    | Double -> getSIMDScalar i [ getVFPDRegister (d |> byte);
                                                                getVFPDRegister (d + 2u |> byte);
                                                                getVFPDRegister (d + 4u |> byte); ]

let getRegListF b =
    let d = concat (pickBit b 22u) (extract b 15u 12u) 4
    let ia = extract b 7u 4u
    let sz = extract b 11u 10u
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
    let d = concat (pickBit b 22u) (extract b 15u 12u) 4
    if pickBit b 5u = 0b0u then
        getSIMDScalar None [ getVFPDRegister (d |> byte) ]
    else getSIMDScalar None [ getVFPDRegister (d |> byte);
                                                        getVFPDRegister (d + 1u |> byte) ]

let getRegListH b =
    let d = concat (pickBit b 22u) (extract b 15u 12u) 4
    if pickBit b 5u = 0b0u then
        getSIMDScalar None [ getVFPDRegister (d |> byte);
                                                  getVFPDRegister (d + 1u |> byte) ]
    else getSIMDScalar None [ getVFPDRegister (d |> byte);
                                                        getVFPDRegister (d + 2u |> byte) ]

let getRegListI b =
    let d = concat (pickBit b 22u) (extract b 15u 12u) 4
    if pickBit b 5u = 0b0u then
        getSIMDScalar None [ getVFPDRegister (d |> byte);
                                                  getVFPDRegister (d + 1u |> byte);
                                                  getVFPDRegister (d + 2u |> byte) ]
    else getSIMDScalar None [ getVFPDRegister (d |> byte);
                                                        getVFPDRegister (d + 2u |> byte);
                                                        getVFPDRegister (d + 4u |> byte) ]

let getRegListJ b =
    let d = concat (pickBit b 22u) (extract b 15u 12u) 4
    if pickBit b 5u = 0b0u then
        getSIMDScalar None [ getVFPDRegister (d |> byte);
                                                  getVFPDRegister (d + 1u |> byte);
                                                  getVFPDRegister (d + 2u |> byte);
                                                  getVFPDRegister (d + 3u |> byte) ]
    else getSIMDScalar None [ getVFPDRegister (d |> byte);
                                                        getVFPDRegister (d + 2u |> byte);
                                                        getVFPDRegister (d + 4u |> byte);
                                                        getVFPDRegister (d + 6u |> byte) ]

let getRegListK b = extract b 15u 0u |> getRegList |> RegList
let getRegListL b = getSIMDVFPRegList (pickBit b 22u) (extract b 15u 12u)
                                            ((extract b 7u 0u) / 2u) 64 |> RegList
let getRegListM b = getSIMDVFPRegList (pickBit b 22u) (extract b 15u 12u)
                                            (extract b 7u 0u) 32 |> RegList
let getRegListN b =
    ((pickBit b 8u) <<< 14) + (extract b 7u 0u) |> getRegList |> RegList
let getRegListO b =
    ((pickBit b 8u) <<< 15) + (extract b 7u 0u) |> getRegList |> RegList
let getRegListP (_, b2) =
    concat ((pickBit b2 14u) <<< 1) (extract b2 12u 0u) 13 |> getRegList
    |> RegList
let getRegListQ (_, b2) =
    concat ((extract b2 15u 14u) <<< 1) (extract b2 12u 0u) 13 |> getRegList
    |> RegList
let getRegListR b = extract b 7u 0u |> getRegList |> RegList

let getShiftImm5A b = concat (extract b 14u 12u) (extract b 7u 6u) 2
let getShift typ imm =
    let shift, imm = decodeImmShift typ imm in Shift (shift, Imm imm)
let getShiftA b = RegShift (decodeRegShift (extract b 6u 5u), getReg b 11u 8u)
let getShiftB b = getShift (extract b 6u 5u) (extract b 11u 7u)
let getShiftC b = extract b 11u 10u |> getShiftOprByRotate
let getShiftD b = getShift (pickBit b 6u <<< 1) (extract b 11u 7u)
let getShiftF (_, b2) = getShift (extract b2 5u 4u) (getShiftImm5A b2)
let getShiftI (b1, b2) = getShift (pickBit b1 5u <<< 1) (getShiftImm5A b2)
let getShiftJ (_, b2) = extract b2 5u 4u |> getShiftOprByRotate

let getImm0 _ = Immediate 0L
let getImmA opcode i b =
    let chk1 i = isUnpredictable (i = 0u)
    let chk2 i = isValidOpcode (opcode <> Op.VMOV || opcode <> Op.VMVN); chk1 i
    let i = concat (concat i (extract b 18u 16u) 3) (extract b 3u 0u) 4
    match concat (pickBit b 5u) (extract b 11u 8u) 4 with
    | r when r &&& 0b00110u = 0b00000u -> i |> int64 |> Immediate
    | r when r &&& 0b01110u = 0b00010u -> chk1 i; i <<< 8 |> int64 |> Immediate
    | r when r &&& 0b01110u = 0b00100u -> chk1 i; i <<< 16 |> int64 |> Immediate
    | r when r &&& 0b01110u = 0b00110u -> chk1 i; i <<< 24 |> int64 |> Immediate
    | r when r &&& 0b01110u = 0b01010u -> chk1 i; i <<< 8 |> int64 |> Immediate
    | r when r &&& 0b01111u = 0b01100u ->
        chk2 i; 0xffu + (i <<< 8) |> int64 |> Immediate
    | r when r &&& 0b01111u = 0b01101u ->
        chk2 i; 0xffu + (0xffu <<< 8) + (i <<< 16) |> int64 |> Immediate
    | 0b01110u -> isValidOpcode (opcode <> Op.VMOV); i |> int64 |>Immediate
    | 0b11110u -> getImm11110 opcode i |> Immediate
    | 0b01111u -> getImm01111 opcode i |> Immediate
    | _ -> raise UndefinedException
let getImmB b =
    match concat (pickBit b 7u) (extract b 21u 16u) 6 with
    | 1u -> 8L - (extract b 18u 16u |> int64)
    | i when i &&& 0b1110u = 0b0010u -> 16L - (extract b 19u 16u |> int64)
    | i when i &&& 0b1100u = 0b0100u -> 32L - (extract b 20u 16u |> int64)
    | i when i &&& 0b1000u = 0b1000u -> 64L - (extract b 21u 16u |> int64)
    | _ -> failwith "Wrong encoding in getImmB"
    |> Immediate
let getImmC b =
    match concat (pickBit b 7u) (extract b 21u 19u) 3 with
    | 1u -> extract b 18u 16u |> int64 |> Immediate
    | i when i &&& 0b1110u = 0b0010u -> extract b 19u 16u |> int64 |> Immediate
    | i when i &&& 0b1100u = 0b0100u -> extract b 20u 16u |> int64 |> Immediate
    | i when i &&& 0b1000u = 0b1000u -> extract b 21u 16u |> int64 |> Immediate
    | _ -> failwith "Wrong encoding in getImmC"
let getImmD b =
    match extract b 21u 19u with
    | 1u -> 8L - (extract b 18u 16u |> int64)
    | i when i &&& 0b110u = 0b010u -> 16L - (extract b 19u 16u |> int64)
    | i when i &&& 0b100u = 0b100u -> 32L - (extract b 20u 16u |> int64)
    | _ -> failwith "Wrong encoding in getImmD"
    |> Immediate
let getImmE b =
    match extract b 21u 19u with
    | i when i &&& 0b111u = 0b001u -> 8L - (extract b 18u 16u |> int64)
    | i when i &&& 0b110u = 0b010u -> 16L - (extract b 19u 16u |> int64)
    | i when i &&& 0b100u = 0b100u -> 32L - (extract b 20u 16u |> int64)
    | _ -> failwith "Wrong encoding in getImmE"
    |> Immediate
let getImmF b =
    match extract b 21u 19u  with
    | i when i &&& 0b111u = 0b001u -> extract b 18u 16u |> int64 |> Immediate
    | i when i &&& 0b110u = 0b010u -> extract b 19u 16u |> int64 |> Immediate
    | i when i &&& 0b100u = 0b100u -> extract b 20u 16u |> int64 |> Immediate
    | _ -> failwith "Wrong encoding in getImmF"
let getImmG b = 64L - (extract b 21u 16u |> int64) |> Immediate
let getImmH b =
    let imm = concat (extract b 19u 16u) (extract b 3u 0u) 4 |> int64
    match pickBit b 8u with
    | 0b0u -> getFloatingPointImm32 imm |> Immediate
    | 0b1u -> getFloatingPointImm64 imm |> Immediate
    | _ -> failwith "Wrong floating point modified imm encoding."
let getImmI b =
    let size = if pickBit b 7u = 0b0u then 16L else 32L
    let imm = concat (extract b 3u 0u) (pickBit b 5u) 1 |> int64
    size - imm |> Immediate
let getImmJ (b1, b2) =
    let i = pickBit b1 10u
    let i3 = extract b2 14u 12u
    let rot = concat (concat i i3 3) (pickBit b2 7u) 1 |> int
    let imm = extract b2 7u 0u |> int
    match rot with
    | 0b00000 | 0b00001 -> imm |> int64 |> Immediate
    | 0b00010 | 0b00011 -> imm <<< 16 + imm |> int64 |> Immediate
    | 0b00100 | 0b00101 -> imm <<< 24 + imm <<< 8 |> int64 |> Immediate
    | 0b00110
    | 0b00111 -> imm <<< 24 + imm <<< 16 + imm <<< 8 + imm |> int64 |> Immediate
    | rot -> (0b10000000 ||| imm) <<< (32 - rot) |> int64 |> Immediate
let getImmK (_, b2) =
    (extract b2 4u 0u) - (concat (extract b2 14u 12u) (extract b2 7u 6u) 2) + 1u
    |> int64 |> Immediate

let getImm3A b = extract b 8u 6u |> int64 |> Immediate
let getImm3B b = extract b 7u 5u |> int64 |> Immediate
let getImm3C b = extract b 23u 21u |> int64 |> Immediate
let getImm4A b = extract b 3u 0u |> int64 |> Immediate
let getImm4B b = (extract b 19u 16u |> int64) + 1L |> Immediate
let getImm4C b = extract b 11u 8u |> int64 |> Immediate
let getImm4D b = extract b 7u 4u |> int64 |> Immediate
let getImm4E b = extract b 23u 20u |> int64 |> Immediate
let getImm4F (_, b2) = extract b2 4u 0u + 1u |> int64 |> Immediate
let getImm5A b = extract b 11u 7u |> int64 |> Immediate
let getImm5B b = extract b 4u 0u |> int64 |> Immediate
let getImm5C b = (extract b 20u 16u |> int64) + 1L |> Immediate
let getImm5D b = extract b 10u 6u |> int64 |> Immediate
let getImm5E b =
    let i5 = extract b 10u 6u |> int64
    if i5 = 0L then 32L |> Immediate else i5 |> Immediate
let getImm5F b =
    (extract b 20u 16u) - (extract b 11u 7u) + 1u |> int64 |> Immediate
let getImm5G (_, b2) =
    concat (extract b2 14u 12u) (extract b2 7u 6u) 2 |> int64 |> Immediate
let getImm5H (_, b2) = extract b2 4u 0u |> int64 |> Immediate

let getImm7A b = extract b 6u 0u <<< 2 |> int64 |> Immediate
let getImm8A b = extract b 7u 0u |> int64 |> Immediate
let getImm8B b = (extract b 7u 0u |> int64) <<< 2 |> Immediate
let getImm12A b =
    let rot = extract b 11u 8u |> int
    let imm = extract b 7u 0u |> int
    if rot = 0 then imm |> int64 |> Immediate
    else (imm <<< ((32 - rot) * 2)) + (imm >>> rot * 2) |> int64 |> Immediate
let getImm12B b =
    (extract b 19u 16u |> int64 <<< 12) + (extract b 11u 0u |> int64) |> Immediate
let getImm12C b = extract b 11u 0u |> int64 |> Immediate
let getImm12D b =
    ((extract b 19u 8u |> int64) <<< 4) + (extract b 3u 0u |> int64) |> Immediate
let getImm12E b = extract b 11u 0u |> int64 |> Immediate
let getImm12F (b1, b2) =
    concat (concat (pickBit b1 10u) (extract b2 14u 12u) 3) (extract b2 7u 0u) 8
    |> int64 |> Immediate
let getImm16A (b1, b2) =
    let i1 = concat (extract b1 3u 0u) (pickBit b1 10u) 1
    let i2 = concat (extract b2 14u 12u) (extract b2 7u 0u) 8
    concat i1 i2 11 |> int64 |> Immediate
let getImm16B (b1, b2) =
    concat (extract b1 3u 0u) (extract b2 11u 0u) 12 |> int64 |> Immediate
let getImm24A b = extract b 23u 0u |> int64 |> Immediate

let getLblA b = extract b 23u 0u <<< 2 |> uint64 |> signExtend 26 32
                                |> System.Convert.ToInt64 |> memLabel

let getLbl7A b = concat (pickBit b 9u) (extract b 7u 3u) 5 <<< 1 |> uint64
                                  |> System.Convert.ToInt64 |> memLabel

let getLbl8A b = extract b 7u 0u <<< 2 |> uint64
                                  |> System.Convert.ToInt64 |> memLabel

let getLbl9A b = extract b 7u 0u <<< 1 |> uint64 |> signExtend 9 32
                                  |> System.Convert.ToInt64 |> memLabel

let getLbl12A b = extract b 10u 0u <<< 1 |> uint64 |> signExtend 12 32
                                    |> System.Convert.ToInt64 |> memLabel

let getLbl24B b = extract b 23u 0u <<< 2 |> uint64 |> signExtend 24 32
                                    |> System.Convert.ToInt64 |> memLabel

let getLbl21A (b1, b2) =
    let i1 = concat (pickBit b1 10u) (pickBit b2 11u) 1
    let i2 = concat (pickBit b2 13u) (extract b1 5u 0u) 6
    let label = concat (concat i1 i2 7) ((extract b2 10u 0u) <<< 1) 12 |> uint64
    signExtend 21 32 label |> System.Convert.ToInt64 |> memLabel

let getLbl25A (b1, b2) =
    let s = pickBit b1 10u
    let i1 = concat s (~~~ ((pickBit b2 13u) ^^^ s) &&& 0b1u) 1
    let i2 = concat (~~~ ((pickBit b2 11u) ^^^ s) &&& 0b1u) (extract b1 9u 0u) 10
    let i = concat (concat i1 i2 11) ((extract b2 10u 0u) <<< 1) 12 |> uint64
    signExtend 25 32 i |> System.Convert.ToInt64 |> memLabel

let getLbl25B (b1 , b2) =
    let s = pickBit b1 10u
    let i1 = concat s (~~~ ((pickBit b2 13u) ^^^ s) &&& 0b1u) 1
    let i2 = concat (~~~ ((pickBit b2 11u) ^^^ s) &&& 0b1u) (extract b1 9u 0u) 10
    let i = concat (concat i1 i2 11) ((extract b2 10u 1u) <<< 2) 12 |> uint64
    signExtend 25 32 i |> System.Convert.ToInt64 |> memLabel

let getLbl25C (b1 , b2) =
    let s = pickBit b1 10u
    let i1 = concat s (~~~ ((pickBit b2 13u) ^^^ s) &&& 0b1u) 1
    let i2 = concat (~~~ ((pickBit b2 11u) ^^^ s) &&& 0b1u) (extract b1 9u 0u) 10
    let i = concat (concat i1 i2 11) ((extract b2 10u 0u) <<< 1) 12 |> uint64
    signExtend 25 32 i |> System.Convert.ToInt64 |> memLabel

let getLbl26A b =
    let hImm = concat (extract b 23u 0u) (pickBit b 24u) 1 |> uint64
    signExtend 26 32 (hImm <<< 1) |> System.Convert.ToInt64 |> memLabel

let getMemA b = memOffsetImm (getReg b 19u 16u, None, None)

let getMemC b = memOffsetImm (R.SP, Some Plus,
                                                            Some (extract b 7u 0u <<< 2 |> int64))
let getMemD b = memOffsetReg (getReg b 5u 3u, None, getReg b 8u 6u, None)
let getMemE b =
    memOffsetImm (getReg b 5u 3u, Some Plus,
                                Some (extract b 10u 6u |> int64 <<< 2))
let getMemF b =
    memOffsetImm (getReg b 5u 3u, Some Plus,
                                Some (extract b 10u 6u |> int64))
let getMemG b =
    memOffsetImm (getReg b 5u 3u, Some Plus,
                                Some (extract b 10u 6u |> int64 <<< 1))
let getMemH b =
    let u = pickBit b 23u
    let i4h = extract b 11u 8u |> int64
    let i4l = extract b 3u 0u |> int64
    memLabel (if u = 0b0u then ((i4h <<< 4) + i4l) * -1L else (i4h <<< 4) + i4l)
let getMemI b =
    let rn = getReg b 19u 16u
    let rm = getReg b 3u 0u
    let sign = getSign (pickBit b 23u) |> Some
    memPostIdxReg (rn, sign, rm, None)
let getMemJ b =
    let i4h = extract b 11u 8u |> int64
    let i4l = extract b 3u 0u |> int64
    let imm = (i4h <<< 4) + i4l
    memPostIdxImm (getReg b 19u 16u, pickBit b 23u |> getSign |> Some, Some imm)
let getMemK b =
    let rn = getReg b 19u 16u
    let imm12 = extract b 11u 0u |> int64
    memPostIdxImm (rn, pickBit b 23u |> getSign |> Some, Some imm12)
let getMemL b =
    let imm12 = extract b 11u 0u |> int64
    let rn = getReg b 19u 16u
    let sign = pickBit b 23u |> getSign |> Some
    match pickBit b 24u, pickBit b 21u with
    | 0b0u, _ -> memPostIdxImm (rn, sign, Some imm12)
    | 0b1u, 0b0u -> memOffsetImm (rn, sign, Some imm12)
    | 0b1u, 0b1u -> memPreIdxImm  (rn, sign, Some imm12)
    | _ -> failwith "Wrong U_RnRtI12 encoding."
let getMemM b =
    let imm12 = extract b 11u 0u |> int64
    match pickBit b 23u with
    | 0b0u -> imm12 * -1L |> memLabel
    | 0b1u -> imm12 |> memLabel
    | _ -> failwith "Wrong U_RtI12 encoding."
let getMemN b =
    let rn = getReg b 19u 16u
    let rm = getReg b 3u 0u
    let sign = pickBit b 23u |> getSign |> Some
    match pickBit b 24u, pickBit b 21u with
    | 0b0u, _ -> memPostIdxReg (rn, sign, rm, None)
    | 0b1u, 0b0u -> memOffsetReg (rn, sign, rm, None)
    | 0b1u, 0b1u -> memPreIdxReg (rn, sign, rm, None)
    | _ -> failwith "Wrong MemN encoding."
let getMemO b =
    let i4h = extract b 11u 8u |> int64
    let i4l = extract b 3u 0u |> int64
    let i8 = ((i4h <<< 4) + i4l)
    let rn = getReg b 19u 16u
    let sign = pickBit b 23u |> getSign |> Some
    match pickBit b 24u, pickBit b 21u with
    | 0b0u, _ -> memPostIdxImm (rn, sign, Some i8)
    | 0b1u, 0b0u -> memOffsetImm (rn, sign, Some i8)
    | 0b1u, 0b1u -> memPreIdxImm (rn, sign, Some i8)
    | _ -> failwith "Wrong MemO encoding."
let getMemP (b1, b2) =
    let i = extract b2 5u 4u
    memOffsetReg (getReg b1 3u 0u, None, getReg b2 3u 0u, Some (SRTypeLSL, Imm i))
let getMemQ b =
    let rn = getReg b 19u 16u
    let rm = getReg b 3u 0u
    let imm5 = extract b 11u 7u
    let shift, imm = decodeImmShift (extract b 6u 5u) imm5
    let typ = shift, Imm imm
    let sign = pickBit b 23u |> getSign |> Some
    memPostIdxReg (rn, sign, rm, Some typ)
let getMemR b =
    let rn = getReg b 19u 16u
    let rm = getReg b 3u 0u
    let shift, imm = decodeImmShift (extract b 6u 5u) (extract b 11u 7u)
    let shiftOffset = Some (shift, Imm imm)
    let sign = pickBit b 23u |> getSign |> Some
    match pickBit b 24u, pickBit b 21u with
    | 0b0u, _ -> memPostIdxReg (rn, sign, rm, shiftOffset)
    | 0b1u, 0b0u -> memOffsetReg (rn, sign, rm, shiftOffset)
    | 0b1u, 0b1u -> memPreIdxReg (rn, sign, rm, shiftOffset)
    | _ -> failwith "Wrong PU_W_RnRtI5Ty_Rm encoding."
let getMemS b =
    let rn = getReg b 19u 16u
    let align =
        match extract b 5u 4u with
        | 0b01u -> Some 64L
        | 0b10u -> Some 128L
        | 0b11u -> Some 256L
        | _ -> None
    let rm = getReg b 3u 0u
    match rm with
    | R.PC -> memOffsetAlign (rn, align, None)
    | R.SP -> memPreIdxAlign (rn, align, None)
    | _ -> memPostIdxAlign (rn, align, Some rm)
let getMemT b =
    let rn = getReg b 19u 16u
    let rm = getReg b 3u 0u
    let ia = extract b 7u 4u
    let align =
        match extract b 11u 10u with
        | 0b00u when pickBit ia 0u = 0b0u -> None
        | 0b01u when extract ia 1u 0u = 0b00u -> None
        | 0b01u when extract ia 1u 0u = 0b01u -> Some 16L
        | 0b10u when extract ia 2u 0u = 0b000u -> None
        | 0b10u when extract ia 2u 0u = 0b011u -> Some 32L
        | _ -> failwith "Wrong index align for VST1."
    match rm with
    | R.PC -> memOffsetAlign (rn, align, None)
    | R.SP -> memPreIdxAlign (rn, align, None)
    | _ -> memPostIdxAlign (rn, align, Some rm)
let getMemU b =
    let rn = getReg b 19u 16u
    let align =
        match extract b 11u 10u, pickBit b 5u, pickBit b 4u with
        | 0b00u, _, _ | 0b01u, _, 0b0u | 0b10u, 0b0u, 0b0u -> None
        | 0b01u, _, 0b1u -> Some 32L
        | 0b10u, 0b0u, 0b1u -> Some 64L
        | _ -> failwith "Wrong index spcaing align for VST2."
    let rm = getReg b 3u 0u
    match rm with
    | R.PC -> memOffsetAlign (rn, align, None)
    | R.SP -> memPreIdxAlign (rn, align, None)
    | _ -> memPostIdxAlign (rn, align, Some rm)
let getMemV b =
    let rn = getReg b 19u 16u
    let align =
        match extract b 11u 10u, pickBit b 5u, pickBit b 4u with
        | 0b00u, _, 0b0u | 0b01u, _, 0b0u | 0b10u, 0b0u, 0b0u -> None
        | _ -> failwith "Wrong index spcaing align for VST3."
    let rm = getReg b 3u 0u
    match rm with
    | R.PC -> memOffsetAlign (rn, align, None)
    | R.SP -> memPreIdxAlign (rn, align, None)
    | _ -> memPostIdxAlign (rn, align, Some rm)
let getMemW b =
    let rn = getReg b 19u 16u
    let align =
        match extract b 11u 10u, pickBit b 6u, pickBit b 5u, pickBit b 4u with
        | 0b00u, _, _, 0b0u | 0b01u, _, _, 0b0u | 0b10u, _, 0b0u, 0b0u -> None
        | 0b01u, _, _, 0b1u | 0b10u, _, 0b0u, 0b1u -> Some 64L
        | 0b10u, _, 0b1u, 0b0u -> Some 128L
        | 0b00u, _, _, 0b1u -> Some 32L
        | _ -> failwith "Wrong index spcaing align for VST4."
    let rm = getReg b 3u 0u
    match rm with
    | R.PC -> memOffsetAlign (rn, align, None)
    | R.SP -> memPreIdxAlign (rn, align, None)
    | _ -> memPostIdxAlign (rn, align, Some rm)
let getAlignForVLD1 s a =
    match s, a with
    | _, 0b0u -> None
    | 0b01u, 0b1u -> Some 16L
    | 0b10u, 0b1u -> Some 32L
    | _ -> failwith "Wrong align for VLD1."
let getMemX b =
    let rn = getReg b 19u 16u
    let align =
        match extract b 7u 6u, pickBit b 4u with
        | _, 0b0u -> None
        | 0b01u, 0b1u -> Some 16L
        | 0b10u, 0b1u -> Some 32L
        | _ -> failwith "Wrong align for VLD1."
    let rm = getReg b 3u 0u
    match rm with
    | R.PC -> memOffsetAlign (rn, align, None)
    | R.SP -> memPreIdxAlign (rn, align, None)
    | _ -> memPostIdxAlign (rn, align, Some rm)
let getMemY b =
    let rn = getReg b 19u 16u
    let align =
        match extract b 7u 6u, pickBit b 4u with
        | _, 0b0u -> None
        | 0b00u, 0b1u -> Some 16L
        | 0b01u, 0b1u -> Some 32L
        | 0b10u, 0b1u -> Some 64L
        | _ -> failwith "Wrong align for VLD2."
    let rm = getReg b 3u 0u
    match rm with
    | R.PC -> memOffsetAlign (rn, align, None)
    | R.SP -> memPreIdxAlign (rn, align, None)
    | _ -> memPostIdxAlign (rn, align, Some rm)
let getMemZ b =
    let rn = getReg b 19u 16u
    let rm = getReg b 3u 0u
    match rm with
    | R.PC -> memOffsetAlign (rn, None, None)
    | R.SP -> memPreIdxAlign (rn, None, None)
    | _ -> memPostIdxAlign (rn, None, Some rm)
let getMemAA b =
    let rn = getReg b 19u 16u
    let align =
        match extract b 7u 6u, pickBit b 4u with
        | _, 0b0u -> None
        | 0b00u, 0b1u -> Some 32L
        | 0b01u, 0b1u | 0b10u, 0b1u -> Some 64L
        | 0b11u, 0b1u -> Some 128L
        | _ -> failwith "Wrong align for VLD4."
    let rm = getReg b 3u 0u
    match rm with
    | R.PC -> memOffsetAlign (rn, align, None)
    | R.SP -> memPreIdxAlign (rn, align, None)
    | _ -> memPostIdxAlign (rn, align, Some rm)
let getMemAB b =
    let rn = getRegister (extract b 19u 16u |> byte)
    let i = extract b 11u 0u |> int64
    memOffsetImm (rn, pickBit b 23u |> getSign |> Some, Some i)
let getMemAC b =
    let rn = getRegister (extract b 19u 16u |> byte)
    let imm5 = extract b 11u 7u
    let shift, imm = decodeImmShift (extract b 6u 5u) imm5
    let typ = shift, Imm imm
    let rm = getRegister (extract b 3u 0u |> byte)
    memOffsetReg (rn, pickBit b 23u |> getSign |> Some, rm, Some typ)
let getMemAD b =
    let i8 = extract b 7u 0u |> int64
    match pickBit b 24u, pickBit b 21u, pickBit b 23u with
    | 1u, 0u, 0u -> memLabel (i8 * -4L)
    | 1u, 0u, 1u -> memLabel (i8 * 4L)
    | 0u, 0u, 1u -> memUnIdxImm (R.PC, i8 * 4L)
    | _ -> failwith "Wrong PUW_CdCPI8 encoding."
let getMemAE b =
    let rn = getRegister (extract b 19u 16u |> byte)
    let i8 = extract b 7u 0u |> int64
    let sign = pickBit b 23u |> getSign |> Some
    match pickBit b 24u, pickBit b 21u with
    | 0u, 0u when sign = Some Plus -> memUnIdxImm (rn, i8)
    | 0u, 1u -> memPostIdxImm (rn, sign, Some (i8 * 4L))
    | 1u, 0u -> memOffsetImm (rn, sign, Some (i8 * 4L))
    | 1u, 1u -> memPreIdxImm (rn, sign, Some (i8 * 4L))
    | _ -> failwith "Wrong PUW_RnCdCPI8 encoding."
let getMemAF (b1, b2) =
    memOffsetImm (getRegister (extract b1 3u 0u |> byte), None,
                            extract b2 7u 0u <<< 2 |> int64 |> Some)
let getMemAG (b1, b2) =
    memOffsetImm (getRegister (extract b1 3u 0u |> byte), None,
                            extract b2 7u 0u |> int64 |> Some)
let getMemAH (b1, b2) =
    let rn = getRegister (extract b1 3u 0u |> byte)
    let i8 = extract b2 7u 0u <<< 2 |> int64
    let sign = pickBit b1 7u |> getSign |> Some
    match pickBit b1 8u, pickBit b1 5u with
    | 0b0u, _ -> memPostIdxImm (rn, sign, Some i8)
    | 0b1u, 0b0u -> memOffsetImm (rn, sign, Some i8)
    | 0b1u, 0b1u -> memPreIdxImm  (rn, sign, Some i8)
    | _ -> failwith "Wrong U_RnRtI12 encoding."
let getMemAI (b1, b2) =
    let i8 = extract b2 7u 0u <<< 2 |> int64
    if pickBit b1 7u = 0b0u then memLabel (i8 * -1L) else memLabel i8
let getMemAJ (b1, _) =
    memOffsetImm (getRegister (extract b1 3u 0u |> byte), None, None)
let getMemAK (b1, b2) =
    memOffsetReg (getRegister (extract b1 3u 0u |> byte), None,
                            getRegister (extract b2 3u 0u |> byte), None)
let getMemAL (b1, b2) =
    memOffsetReg (getRegister (extract b1 3u 0u |> byte), None,
                            getRegister (extract b2 3u 0u |> byte),
                            Some (SRTypeLSL, Imm 1u))
let getMemAM (b1, b2) =
    let rn = getRegister (extract b1 3u 0u |> byte)
    let i8 = extract b2 7u 0u |> int64
    let sign = pickBit b2 9u |> getSign |> Some
    match pickBit b2 10u, pickBit b2 8u with
    | 0b0u, 0b0u -> raise UndefinedException
    | 0b0u, 0b1u -> memPostIdxImm (rn, sign, Some i8)
    | 0b1u, 0b0u -> memOffsetImm (rn, sign, Some i8)
    | 0b1u, 0b1u -> memPreIdxImm  (rn, sign, Some i8)
    | _ -> failwith "Wrong U_RnRtI12 encoding."
let getMemAN (b1, b2) =
    let rn = getRegister (extract b1 3u 0u |> byte)
    let i12 = extract b2 11u 0u |> int64 |> Some
    memOffsetImm (rn, Some Plus, i12)
let getMemAO (b1, b2) =
    let rn = getRegister (extract b1 3u 0u |> byte)
    let rm = getRegister (extract b2 3u 0u |> byte)
    let typ = SRTypeLSL, Imm (extract b2 5u 4u)
    memOffsetReg (rn,  Some Plus, rm, Some typ)
let getMemAP (b1, b2) =
    let rn = getRegister (extract b1 3u 0u |> byte)
    let i8 = extract b2 7u 0u |> int64
    memOffsetImm (rn, Some Minus, Some i8)
let getMemAQ (b1, b2) =
    let i12 = extract b2 11u 0u |> int64
    if pickBit b1 7u = 0b1u then memLabel i12 else memLabel (i12 * -1L)

let getMemAR b =
    let rn = getRegister (extract b 19u 16u |> byte)
    let i = extract b 7u 0u <<< 2 |> int64
    let sign = (pickBit b 23u) |> getSign |> Some
    memOffsetImm (rn, sign, Some i)

let getFlagA b = extract b 8u 6u |> byte |> getIflag |> Iflag
let getFlagB b = extract b 2u 0u |> byte |> getIflag |> Iflag
let getFlagC (_, b2) = extract b2 7u 5u |> byte |> getIflag |> Iflag
let getEndianA b = pickBit b 9u |> byte |> getEndian |> Operand.Endian
let getEndianB b = pickBit b 3u |> byte |> getEndian |> Operand.Endian
let getOptA b = extract b 3u 0u |> byte |> getOption |> Option
let getFirstCond b = extract b 7u 4u |> byte |> parseCond |> Cond
let getScalarA b =
    let m = pickBit b 5u
    let vm = extract b 3u 0u
    match extract b 21u 20u with
    | 0b01u -> (getVFPDRegister (extract vm 2u 0u |> byte),
                            Some (concat m (pickBit vm 3u) 1 |> uint8)) |> sSReg
    | 0b10u -> (getVFPDRegister (vm |> byte), Some (m |> uint8)) |> sSReg
    | _ -> failwith "Wrong scalar encoding."
let getScalarB b =
    let reg = concat (pickBit b 5u) (extract b 3u 0u) 4 |> byte |> getVFPDRegister
    match extract b 19u 16u with
    | i4 when i4 &&& 0b0001u = 0b0001u -> reg, Some (extract i4 3u 1u |> uint8)
    | i4 when i4 &&& 0b0011u = 0b0010u -> reg, Some (extract i4 3u 2u |> uint8)
    | i4 when i4 &&& 0b0111u = 0b0100u -> reg, Some (pickBit i4 3u |> uint8)
    | _ -> failwith "Wrong scalar encoding."
    |> sSReg

let getScalarC b =
    let dd = concat (pickBit b 7u) (extract b 19u 16u) 4 |> byte
                      |> getVFPDRegister
    let x =
        match concat (extract b 22u 21u) (extract b 6u 5u) 2 with
        | opc when opc &&& 0b1000u = 0b1000u ->
            uint8 (concat (pickBit b 21u) (extract b 6u 5u) 2)
        | opc when opc &&& 0b1001u = 0b0001u ->
            uint8 (concat (pickBit b 21u) (pickBit b 6u) 1)
        | opc when opc &&& 0b1011u = 0b0000u -> uint8 (pickBit b 21u)
        | opc when opc &&& 0b1011u = 0b0010u -> raise UndefinedException
        | _ -> failwith "Wrong scalarC encoding."
    (dd, Some x) |> sSReg
let getScalarD b =
    let dd = concat (pickBit b 7u) (extract b 19u 16u) 4 |> byte
                      |> getVFPDRegister
    let opc = concat (extract b 22u 21u) (extract b 6u 5u) 2
    let x =
        match concat (pickBit b 23u) opc 4 with
        | uOpc when uOpc &&& 0b11000u = 0b01000u ->
            concat (pickBit b 21u) (extract b 6u 5u) 2 |> uint8
        | uOpc when uOpc &&& 0b11000u = 0b11000u ->
            concat (pickBit b 21u) (extract b 6u 5u) 2 |> uint8
        | uOpc when uOpc &&& 0b11001u = 0b00001u ->
            concat (pickBit b 21u) (pickBit b 6u) 1 |> uint8
        | uOpc when uOpc &&& 0b11001u = 0b10001u ->
            concat (pickBit b 21u) (pickBit b 6u) 1 |> uint8
        | uOpc when uOpc &&& 0b11011u = 0b00000u -> pickBit b 21u |> uint8
        | uOpc when uOpc &&& 0b11011u = 0b10000u -> raise UndefinedException
        | uOpc when uOpc &&& 0b01011u = 0b00010u -> raise UndefinedException
        | _ -> failwith "Wrong operand encoding."
    (dd, Some x) |> sSReg

let dummyChk _ _ = ()
let checkStoreEx1 b (op1, op2, _) =
    let rn = getRegC b
    isUnpredictable (op1 b = Register R.PC || op2 b = Register R.PC ||
                                      rn = Register R.PC || op1 b = rn || op1 b = op2 b)
let checkStoreEx2 b (op1, op2, op3, _) =
    let rn = getRegC b
    isUnpredictable (op1 b = Register R.PC || pickBit b 0u = 0b1u ||
                                      op2 b = Register R.LR || rn = Register R.PC || op1 b = rn ||
                                      op1 b = op2 b || op1 b = op3 b)

let chkUnpreInAndNotLastItBlock itState =
    inITBlock itState && lastInITBlock itState |> not

let chkUnpreA b (op1, op2, op3) =
    isUnpredictable (op1 b = Register R.PC || op2 b = Register R.PC ||
                                      op3 b = Register R.PC)
let chkUnpreB b (op1, op2, op3, op4) =
    isUnpredictable (op1 b = Register R.PC || op2 b = Register R.PC ||
                                      op3 b = Register R.PC || op4 b = Register R.PC)
let chkUnpreC b (op1, op2, op3, _) =
    isUnpredictable (op1 b = Register R.PC || op2 b = Register R.PC ||
                                      op3 b = Register R.PC)
let chkUnpreD b op = isUnpredictable (op b = Register R.PC)
let chkUnpreE b (op1, op2) =
    isUnpredictable (op1 b = Register R.PC || op2 b = Register R.PC)
let chkUnpreF b (_, op2) = isUnpredictable (op2 b = Register R.PC)
let chkUnpreG b (op1, _) = isUnpredictable (op1 b = Register R.PC)
let chkUnpreH b (_, op2) =
    isUnpredictable (extract b 19u 16u = 0b0u || op2 b = Register R.PC)
let chkUnpreI b (op1, op2, op3, op4) =
    isUnpredictable (op1 b = Register R.PC || op2 b = Register R.PC ||
                                      op3 b = Register R.PC || op4 b = Register R.PC ||
                                      op1 b = op2 b)
let chkUnpreJ b (op1, op2, _) =
    let rn = getRegC b
    isUnpredictable (op1 b = Register R.PC || op2 b = Register R.PC ||
                                      rn = Register R.PC || rn = op1 b || rn = op2 b)
let chkUnpreK b (op1, _) =
    let rn = getRegC b
    isUnpredictable (rn = Register R.PC || op1 b = Register R.PC)
let chkUnpreL b (op1, _, _) =
    isUnpredictable (pickBit b 12u = 0b1u || op1 b = Register R.LR ||
                                      getRegC b = Register R.PC)
let chkUnpreM b (op1, _, op3) =
    isUnpredictable (op1 b = Register R.PC || op3 b = Register R.PC)
let chkUnpreN b _ = isUnpredictable (getRegC b = Register R.PC)
let chkUnpreO b (op1, _, op3, _) =
    isUnpredictable (op1 b = Register R.PC || op3 b = Register R.PC)
let chkUnpreP b (op1, op2, _) =
    isUnpredictable (op1 b = Register R.PC || op2 b = Register R.PC)
let chkUnpreQ b (op1, op2, _, _) =
    isUnpredictable (op1 b = Register R.PC || op2 b = Register R.PC)
let chkUnpreR itState b _ =
    let d = concat (pickBit b 7u) (extract b 2u 0u) 3
    isUnpredictable ((extract b 6u 3u = 15u && d = 15u) &&
                                      d = 15u && inITBlock itState && lastInITBlock itState |> not)
let chkUnpreS b _ =
    let rnd = concat (pickBit b 7u) (extract b 2u 0u) 3
    let rm = extract b 6u 3u
    isUnpredictable (rnd = 15u || rm = 15u)
    isUnpredictable (rnd < 8u && rm < 8u)
let chkUnpreT b (op1, _) =
    isUnpredictable (op1 b = Register R.PC || pickBit b 24u = pickBit b 21u)
let chkUnpreU b (_, op2, _) = isUnpredictable (op2 b = Register R.PC)
let chkUnpreV b (op1, _) =
    let rn = getRegC b
    isUnpredictable (op1 b = Register R.PC || rn = Register R.PC || rn = op1 b ||
                                      getRegA b = Register R.PC)
let chkUnpreW b (op1, _) =
    let rn = getRegC b
    isUnpredictable (op1 b = Register R.PC || rn = Register R.PC || rn = op1 b)

let chkUnpreX b _ = isUnpredictable (extract b 19u 16u = 0b0u)
let chkUnpreY b op = isUnpredictable (op b = Register R.SP)
let chkUnpreZ b (op1, _) =
    let rn = getRegC b
    isUnpredictable (rn = Register R.PC || rn = op1 b)
let chkUnpreAA b (op1, _) =
    let rn = getRegC b
    isUnpredictable ((pickBit b 24u = 0u || pickBit b 21u = 1u) &&
                                      (rn = Register R.PC || rn = op1 b))
let chkUnpreAB b (op1, _) =
    let rn = getRegC b
    isUnpredictable (op1 b = Register R.PC ||
                                      ((rn = op1 b) && (pickBit b 24u = 0u || pickBit b 21u = 1u)))
let chkUnpreAC b (op1, _) =
    let rn = getRegC b
    isUnpredictable (op1 b = Register R.PC ||
                                      ((rn = Register R.PC || rn = op1 b) &&
                                        (pickBit b 24u = 0u || pickBit b 21u = 1u)))
let chkUnpreAD b (op1, _) =
    let rn = getRegC b
    isUnpredictable (op1 b = Register R.PC || getRegA b = Register R.PC ||
                                      ((pickBit b 24u = 0b0u || pickBit b 21u = 0b1u) &&
                                        (rn = Register R.PC || rn = op1 b)))

let chkUnpreAE b (op1, op2, _) =
    let rn = getRegC b
    let rm = getRegA b
    isUnpredictable ((pickBit b 24u = 0u && pickBit b 21u = 1u) ||
                                      op2 b = Register R.PC || rm = Register R.PC || rm = op1 b ||
                                      rm = op2 b || (pickBit b 24u = 0u || pickBit b 21u = 1u) &&
                                      (rn = Register R.PC || rn = op1 b || rn = op2 b))

let chkUnpreAF b (op1, op2, _) =
    let rn = getRegC b
    let rm = getRegA b
    let p = pickBit b 24u
    let w = pickBit b 21u
    isUnpredictable ((p = 0u && w = 1u) || op2 b = Register R.PC ||
                                      rm = Register R.PC || pickBit b 12u = 1u ||
                                      ((p = 0u || w = 1u) &&
                                        (rn = Register R.PC || rn = op1 b || rn = op2 b)))
let chkUnpreAG b (op1, _) =
    let rn = getRegC b
    isUnpredictable (op1 b = Register R.PC ||
                                      ((rn = Register R.PC || rn = op1 b) &&
                                        (pickBit b 24u = 0b0u || pickBit b 21u = 0b1u)))
let chkUnpreAH b (op1, _) =
    isUnpredictable (op1 b = Register R.PC ||
                                      ((pickBit b 24u = 0b0u || pickBit b 21u = 0b1u) &&
                                        (getRegC b = op1 b)))

let chkUnpreAI b (op1, op2, _) =
    let p = pickBit b 24u
    let w = pickBit b 21u
    let rn = getRegC b
    isUnpredictable (((p = 0b0u || w = 0b1u) && (rn = op1 b || rn = op2 b)) ||
                                      p = 0b0u && w = 0b1u)

let chkUnpreAJ b (op1, op2, _) =
    let p = pickBit b 24u
    let w = pickBit b 21u
    let rn = getRegC b
    isUnpredictable ((p = 0u && w = 1u) || op2 b = Register R.PC ||
                                      ((p = 0u || w = 1u) &&
                                        (rn = Register R.PC || rn = op1 b || rn = op2 b)))
let chkUnpreAK (_, b2) _ =
    let rm = getRegA b2
    isUnpredictable (rm = Register R.SP || rm = Register R.PC)

let chkUnpreAL b (op1, _) =
    let rn = getRegC b
    isUnpredictable (getRegA b = Register R.PC ||
                                      rn = Register R.PC || rn = op1 b)

let chkUnpreAM b (op1, _) =
    let rn = getRegC b
    isUnpredictable (getRegA b = Register R.PC ||
                                      ((pickBit b 24u = 0u || pickBit b 21u = 1u) &&
                                        (rn = Register R.PC || rn = op1 b)))

let chkUnpreAN b (op1, _) =
    isUnpredictable (op1 b = Register R.PC); chkUnpreAM b (op1, ())
let chkUnpreAO b _ =
    isUnpredictable (concat (pickBit b 22u) (pickBit b 5u) 1 = 0b11u)
let chkUnpreAP b (op1, _, _) =
    let msb = extract b 20u 16u |> int64
    let lsb = extract b 11u 7u |> int64
    isUnpredictable (op1 b = Register R.PC || msb < lsb)
let chkUnpreAQ b (op1, _, _, _) =
    let msb = extract b 20u 16u |> int64
    let lsb = extract b 11u 7u |> int64
    isUnpredictable (op1 b = Register R.PC || msb < lsb)
let chkUnpreAR b _ =
    isUnpredictable (getReg b 19u 16u = R.PC ||
                                      List.length (extract b 15u 0u |> getRegList) < 1)
let chkUnpreAS b _ =
    let rn = getReg b 19u 16u
    let rl = extract b 15u 0u |> getRegList
    isUnpredictable (rn = R.PC || List.length rl < 1 ||
                                      (pickBit b 21u = 1u && List.exists (fun e -> e = rn) rl))

let chkUnpreAT b _ = isUnpredictable (pickBit b 13u = 0b1u)
let chkUnpreAU b (_, _, op3, op4, _) =
    isUnpredictable (op3 b = Register R.PC || op4 b = Register R.PC)
let chkUnpreAV b (_, _, op3, op4, _) =
    isUnpredictable (op3 b = Register R.PC ||
                                      op4 b = Register R.PC || op3 b = op4 b)
let chkUnpreAW b (op1, _, op3, op4) =
    isUnpredictable (op3 b = Register R.PC || op4 b = Register R.PC ||
                                      op1 b = Register R.S31)
let chkUnpreAX b (op1, op2, op3, _) =
    isUnpredictable (op1 b = Register R.PC || op2 b = Register R.PC ||
                                      op3 b = Register R.S31 || op1 b = op2 b)
let chkUnpreAY b (op1, op2, _) =
    isUnpredictable (op1 b = Register R.PC ||
                                      op2 b = Register R.PC || op1 b = op2 b)
let chkUnpreAZ b _ =
    let regs = (extract b 7u 0u) / 2u
    isUnpredictable (regs = 0u || regs > 16u ||
                                      (concat (pickBit b 22u) (extract b 15u 12u) 4) + regs > 32u)

let chkUnpreBA b _ =
    let imm8 = extract b 7u 0u
    isUnpredictable (imm8 = 0u ||
                                      (concat (extract b 15u 12u) (pickBit b 22u) 1) + imm8 > 32u)
let chkUnpreBB b (_, _, op3, _, _, _) = isUnpredictable (op3 b = Register R.PC)
let chkUnpreBC b _ =
    let rL = ((pickBit b 8u) <<< 14) + (extract b 7u 0u) |> getRegList
    isUnpredictable (List.length rL < 1)
let chkUnpreBD opcode itState b op1 =
    let isITOpcode = function
        | Op.ITE | Op.ITET | Op.ITTE | Op.ITEE | Op.ITETT | Op.ITTET | Op.ITEET
        | Op.ITTTE | Op.ITETE | Op.ITTEE | Op.ITEEE -> true
        | _ -> false
    isUnpredictable (inITBlock itState || op1 b = Cond Condition.UN ||
                                      (op1 b = Cond Condition.AL && isITOpcode opcode))

let chkUnpreBE itState b _ =
    isUndefined (extract b 11u 8u = 14u)
    isUnpredictable (inITBlock itState)

let chkUnpreBF (b1, b2) _ =
    let n = extract b1 3u 0u
    let rL = concat ((pickBit b2 14u) <<< 1) (extract b2 12u 0u) 13 |> getRegList
    isUnpredictable (n = 15u || List.length rL < 2 ||
                                      pickBit b2 5u = 0b1u || pickBit b2 n = 0b1u)

let chkUnpreBG itState (_, b2) _ =
    let pm = (extract b2 15u 14u)
    let rL = concat (pm <<< 1) (extract b2 12u 0u) 13 |> getRegList
    isUnpredictable (List.length rL < 2 || pm = 0b11u ||
                                      (pickBit b2 15u = 1u && chkUnpreInAndNotLastItBlock itState))

let chkUnpreBH itState (b1, b2) _ =
    let n = extract b1 3u 0u
    let w =  pickBit b1 5u
    let pm = extract b2 15u 14u
    let rl = getRegList (concat (pm <<< 1) (extract b2 12u 0u) 13)
    isUnpredictable (n = 15u || List.length rl < 2 || pm = 0b11u)
    isUnpredictable (pickBit b2 15u = 1u && chkUnpreInAndNotLastItBlock itState)
    isUnpredictable (w = 1u && pickBit b2 n = 1u)

let chkUnpreBI (_, b2) _ =
    let m = pickBit b2 14u
    let rl = getRegList (concat (m <<< 1) (extract b2 12u 0u) 13)
    isUnpredictable (List.length rl < 2 || pickBit b2 15u = 0b1u
                                      || pickBit b2 13u = 0b1u)

let chkUnpreBJ (b1, b2) (op1, op2, _) =
    let rn = getRegister (extract b1 3u 0u |> byte)
    let opr1 = op1 (b1, b2)
    let opr2 = op2 (b1, b2)
    isUnpredictable (opr1 = Register R.SP || opr1 = Register R.PC ||
                                      opr2 = Register R.SP || opr2 = Register R.PC ||
                                      rn = R.PC || op1 (b1, b2) = Register rn ||
                                      op1 (b1, b2) = op2 (b1, b2))

let chkUnpreBK (b1, b2) (op1, _) =
    isUnpredictable (op1 (b1, b2) = Register R.SP ||
                                      op1 (b1, b2) = Register R.PC ||
                                      getRegister (extract b1 3u 0u |> byte) = R.PC)

let chkUnpreBL (b1, b2) (op1, _) =
    isUnpredictable (op1 (b1, b2) = Register R.SP ||
                                      op1 (b1, b2) = Register R.PC)

let chkUnpreBM (b1, b2) (op1, op2, _) =
    let rn = getRegister (extract b1 3u 0u |> byte)
    isUnpredictable (((Register rn = op1 (b1, b2) || Register rn = op2 (b1, b2))
                                        && pickBit b1 5u = 0b1u) || rn = R.PC ||
                                      op1 (b1, b2) = Register R.SP ||
                                      op1 (b1, b2) = Register R.PC ||
                                      op2 (b1, b2) = Register R.SP ||
                                      op2 (b1, b2) = Register R.PC)

let chkUnpreBN (b1, b2) (op1, op2, _) =
    let rn = getRegister (extract b1 3u 0u |> byte)
    isUnpredictable (((Register rn = op1 (b1, b2) || Register rn = op2 (b1, b2))
                                        && pickBit b1 5u = 0b1u) || op1 (b1, b2) = op2 (b1, b2) ||
                                      op1 (b1, b2) = Register R.SP ||
                                      op1 (b1, b2) = Register R.PC ||
                                      op2 (b1, b2) = Register R.SP ||
                                      op2 (b1, b2) = Register R.PC)

let chkUnpreBO (b1, b2) (op1, op2, _) =
    isUnpredictable (op1 (b1, b2) = Register R.SP ||
                                      op1 (b1, b2) = Register R.PC ||
                                      op2 (b1, b2) = Register R.SP ||
                                      op2 (b1, b2) = Register R.PC ||
                                      op1 (b1, b2) = op2 (b1, b2))

let chkUnpreBP (b1, b2) (op1, op2, _) =
    let rn = getRegister (extract b1 3u 0u |> byte)
    isUnpredictable (op1 (b1, b2) = Register R.SP ||
                                      op1 (b1, b2) = Register R.PC ||
                                      op2 (b1, b2) = Register R.SP ||
                                      op2 (b1, b2) = Register R.PC ||
                                      rn = R.PC || op1 (b1, b2) = op2 (b1, b2))

let chkUnpreBQ (b1, b2) (op1, op2, op3, _) =
    let rn = getRegister (extract b1 3u 0u |> byte)
    let opr1 = op1 (b1, b2)
    let opr2 = op2 (b1, b2)
    let opr3 = op3 (b1, b2)
    isUnpredictable (opr1 = Register R.SP || opr1 = Register R.PC ||
                                      opr2 = Register R.SP || opr2 = Register R.PC ||
                                      opr3 = Register R.SP || opr3 = Register R.PC ||
                                      rn = R.PC || op1 (b1, b2) = Register rn ||
                                      op1 (b1, b2) = op2 (b1, b2))

let chkUnpreBR itState (b1, b2) _ =
    let rn = getRegister (extract b1 3u 0u |> byte)
    let rm = getRegister (extract b2 3u 0u |> byte)
    isUnpredictable (rn = R.SP || rm = R.SP || rm = R.PC)
    isUnpredictable (chkUnpreInAndNotLastItBlock itState)

let chkUnpreBS (b1, b2) (op1, _) =
    let rn = getRegister (extract b1 3u 0u |> byte)
    let opr1 = op1 (b1, b2)
    isUnpredictable (opr1 = Register R.SP || opr1 = Register R.PC || rn = R.PC)

let chkUnpreBT (b1, b2) (op1, op2) =
    let opr1 = op1 (b1, b2)
    let opr2 = op2 (b1, b2)
    isUnpredictable (opr1 = Register R.PC || opr2 = Register R.PC ||
                                      (opr1 = Register R.SP && opr2 = Register R.SP))

let chkUnpreBU (b1, b2) (op1, op2) =
    let opr1 = op1 (b1, b2)
    let opr2 = op2 (b1, b2)
    isUnpredictable (opr1 = Register R.SP || opr1 = Register R.PC ||
                                      opr2 = Register R.SP || opr2 = Register R.PC)

let chkUnpreBV (b1, b2) (op1, op2, _) =
    let opr1 = op1 (b1, b2)
    let opr2 = op2 (b1, b2)
    isUnpredictable (opr1 = Register R.SP || opr1 = Register R.PC ||
                                      opr2 = Register R.SP || opr2 = Register R.PC)

let chkUnpreBW (b1, b2) (op1, op2, _) =
    let opr2 = op2 (b1, b2)
    isUnpredictable (op1 (b1, b2) = Register R.PC || opr2 = Register R.SP ||
                                      opr2 = Register R.PC)

let chkUnpreBX (b1, b2) (op1, op2, op3, _) =
    let opr1 = op1 (b1, b2)
    let opr2 = op2 (b1, b2)
    let opr3 = op3 (b1, b2)
    isUnpredictable (opr1 = Register R.SP || opr1 = Register R.PC ||
                                      opr2 = Register R.SP || opr2 = Register R.PC ||
                                      opr3 = Register R.SP || opr3 = Register R.PC)

let chkUnpreBY (b1, b2) (op1, op2, op3, _) =
    let opr2 = op2 (b1, b2)
    let opr3 = op3 (b1, b2)
    isUnpredictable (op1 (b1, b2) = Register R.SP || opr2 = Register R.SP ||
                                      opr2 = Register R.PC || opr3 = Register R.SP ||
                                      opr3 = Register R.PC)

let chkUnpreBZ (b1, b2) (op1, op2, op3, _) =
    let opr1 = op1 (b1, b2)
    let opr3 = op3 (b1, b2)
    isUnpredictable (opr1 = Register R.SP || opr1 = Register R.PC ||
                                      op2 (b1, b2) = Register R.SP || opr3 = Register R.SP ||
                                      opr3 = Register R.PC)

let chkUnpreCA (b1, b2) (op1, op2, op3, _) =
    let opr1 = op1 (b1, b2)
    let opr3 = op3 (b1, b2)
    isUnpredictable (opr1 = Register R.SP || opr1 = Register R.PC ||
                                      op2 (b1, b2) = Register R.PC || opr3 = Register R.SP ||
                                      opr3 = Register R.PC)

let chkUnpreCB (b1, b2) (op1, op2, op3, _) =
    let opr3 = op3 (b1, b2)
    isUnpredictable (op1 (b1, b2) = Register R.SP ||
                                      op2 (b1, b2) = Register R.PC ||
                                      opr3 = Register R.SP || opr3 = Register R.PC)

let chkUnpreCC (b1, b2) (op1, _) =
    isUnpredictable (op1 (b1, b2) = Register R.PC)

let chkUnpreCD (b1, b2) (op1, op2, _) =
    let opr2 = op2 (b1, b2)
    isUnpredictable (op1 (b1, b2) = Register R.SP || opr2 = Register R.SP ||
                                      opr2 = Register R.PC)

let chkUnpreCE (b1, b2) (op1, op2, _) =
    let opr1 = op1 (b1, b2)
    isUnpredictable (opr1 = Register R.SP || opr1 = Register R.PC ||
                                      op2 (b1, b2) = Register R.SP)

let chkUnpreCF (b1, b2) (op1, op2, _) =
    let opr1 = op1 (b1, b2)
    isUnpredictable (opr1 = Register R.SP || opr1 = Register R.PC ||
                                      op2 (b1, b2) = Register R.PC)

let chkUnpreCG (b1, b2) (op1, op2, _) =
    isUnpredictable (op1 (b1, b2) = Register R.SP || op2 (b1, b2) = Register R.PC)

let chkUnpreCH (b1, b2) (op1, _, _) =
    let opr1 = op1 (b1, b2)
    isUnpredictable (opr1 = Register R.SP || opr1 = Register R.PC)

let chkUnpreCI (b1, b2) (op1, _, op3, _) =
    let opr1 = op1 (b1, b2)
    let opr3 = op3 (b1, b2)
    isUnpredictable (opr1 = Register R.SP || opr1 = Register R.PC ||
                                      opr3 = Register R.SP || opr3 = Register R.PC)

let chkUnpreCJ (b1, b2) (op1, _, op3) =
    let opr1 = op1 (b1, b2)
    let opr3 = op3 (b1, b2)
    isUnpredictable (opr1 = Register R.SP || opr1 = Register R.PC ||
                                      opr3 = Register R.SP || opr3 = Register R.PC)

let chkUnpreCK (b1, b2) (op1, op2, _ , _) =
    let opr1 = op1 (b1, b2)
    let opr2 = op2 (b1, b2)
    isUnpredictable (opr1 = Register R.SP || opr1 = Register R.PC ||
                                      opr2 = Register R.SP || opr2 = Register R.PC)

let chkUnpreCL (b1, b2) (op1, op2, _ , _) =
    let msb = extract b2 4u 0u
    let lsb = concat (extract b2 14u 12u) (extract b2 7u 6u) 2
    let opr1 = op1 (b1, b2)
    isUnpredictable (opr1 = Register R.SP || opr1 = Register R.PC ||
                                      op2 (b1, b2) = Register R.SP || msb < lsb)

let chkUnpreCM (b1, b2) (op1, _, _) =
    let msb = extract b2 4u 0u
    let lsb = concat (extract b2 14u 12u) (extract b2 7u 6u) 2
    let opr1 = op1 (b1, b2)
    isUnpredictable (opr1 = Register R.SP || opr1 = Register R.PC || msb < lsb)

let chkUnpreCN (b1, b2) (_, op2) =
    let opr2 = op2 (b1, b2)
    isUnpredictable (opr2 = Register R.SP || opr2 = Register R.PC)

let chkUnpreCO (_, b2) _ =
    isUnpredictable (getAPSR (extract b2 11u 10u |> byte) = (R.APSR, None))

let chkUnpreCP (b1, b2) (_, op2) =
    isUnpredictable (extract b2 11u 8u = 0b0000u || op2 (b1, b2) = Register R.PC)

let chkUnpreCQ (b1, b2) op1 =
    let opr1 = op1 (b1, b2)
    isUnpredictable (opr1 = Register R.SP || opr1 = Register R.PC)

let chkUnpreCR (_, b2) _ =
    isUnpredictable (pickBit b2 0u = 0b1u)

let chkUnpreCS itState (_, b2) _ =
    isUnpredictable ((extract b2 4u 0u <> 0b0u && pickBit b2 8u = 0b0u) ||
                                      (pickBit b2 10u = 0b1u && extract b2 7u 5u = 0b0u) ||
                                      (pickBit b2 10u = 0b0u && extract b2 7u 5u <> 0b0u))
    isUnpredictable (extract b2 10u 9u = 1u || inITBlock itState)

let chkUnpreCT (b1, b2) (op1, _) =
    let rn = getRegister (extract b1 3u 0u |> byte)
    let w = pickBit b2 8u
    let opr1 = op1 (b1, b2)
    isUnpredictable (opr1 = Register R.SP || (opr1 = Register R.PC && w = 1u) ||
                                      (w = 1u && Register rn = op1 (b1, b2)))

let chkUnpreCU itState (b1, b2) _ =
    let n = extract b1 3u 0u
    let t = extract b2 15u 12u
    isUnpredictable ((pickBit b2 8u = 1u && n = t) ||
                                      (t = 15u && chkUnpreInAndNotLastItBlock itState))

let chkUnpreCV (b1, b2) (op1, _) = isUnpredictable (op1 (b1, b2) = Register R.SP)
let chkUnpreCW (b1, b2) (op1, _) =
    let rm = getRegister (extract b2 3u 0u |> byte)
    isUnpredictable (op1 (b1, b2) = Register R.SP || rm = R.SP || rm = R.PC)

let chkUnpreCX it (_, b2) _ =
    let rm = getRegister (extract b2 3u 0u |> byte)
    let t = extract b2 15u 12u
    isUnpredictable (rm = R.SP || rm = R.PC ||
                                      (t = 15u && chkUnpreInAndNotLastItBlock it))

let chkUnpreCY (b1, b2) (op1, op2, op3) =
    let opr1 = op1 (b1, b2)
    let opr2 = op2 (b1, b2)
    let opr3 = op3 (b1, b2)
    isUnpredictable (opr1 = Register R.SP || opr1 = Register R.PC ||
                                      opr2 = Register R.SP || opr2 = Register R.PC ||
                                      opr3 = Register R.SP || opr3 = Register R.PC)

let chkUnpreCZ (b1, b2) (op1, op2) =
    let opr1 = op1 (b1, b2)
    let opr2 = op2 (b1, b2)
    isUnpredictable (opr1 = Register R.SP || opr1 = Register R.PC ||
                                      opr2 = Register R.SP || opr2 = Register R.PC ||
                                      Register (getRegister (extract b1 3u 0u |> byte)) <> opr2 )

let chkUnpreDA (b1, b2) (op1, op2, op3, op4) =
    let opr1 = op1 (b1, b2)
    let opr2 = op2 (b1, b2)
    let opr3 = op3 (b1, b2)
    isUnpredictable (opr1 = Register R.SP || opr1 = Register R.PC ||
                                      opr2 = Register R.SP || opr2 = Register R.PC ||
                                      opr3 = Register R.SP || opr3 = Register R.PC ||
                                      op4 (b1, b2) = Register R.SP)

let chkUnpreDB (b1, b2) (op1, op2, op3, op4) =
    let opr1 = op1 (b1, b2)
    let opr2 = op2 (b1, b2)
    let opr3 = op3 (b1, b2)
    let opr4 = op4 (b1, b2)
    isUnpredictable (opr1 = Register R.SP || opr1 = Register R.PC ||
                                      opr2 = Register R.SP || opr2 = Register R.PC ||
                                      opr3 = Register R.SP || opr3 = Register R.PC ||
                                      opr4 = Register R.SP || opr4 = Register R.PC)

let chkUnpreDC (b1, b2) (op1, op2, op3, op4) =
    let opr1 = op1 (b1, b2)
    let opr2 = op2 (b1, b2)
    let opr3 = op3 (b1, b2)
    let opr4 = op4 (b1, b2)
    isUnpredictable (opr1 = Register R.SP || opr1 = Register R.PC ||
                                      opr2 = Register R.SP || opr2 = Register R.PC ||
                                      opr3 = Register R.SP || opr3 = Register R.PC ||
                                      opr4 = Register R.SP || opr4 = Register R.PC ||
                                      opr1 = opr2)
let chkUnpreDD b _ =
    isUnpredictable (List.length (getRegList (extract b 7u 0u)) < 1)
let chkUnpreDE itState _ _ = isUnpredictable (inITBlock itState)
let chkUnpreDF itState b _ =
        let d = concat (pickBit b 7u) (extract b 2u 0u) 3
        isUnpredictable (d = 15u && chkUnpreInAndNotLastItBlock itState)
let chkUnpreDG itState _ _ =
        isUnpredictable (chkUnpreInAndNotLastItBlock itState)
let chkUnpreDH itState b op =
    isUnpredictable (op b = Register R.PC || chkUnpreInAndNotLastItBlock itState)
let chkUnpreDI itState b _ =
    isUnpredictable (extract b 19u 16u = 15u ||
                                      chkUnpreInAndNotLastItBlock itState)
let chkUnpreDJ it (b1, b2) op1 =
    isUnpredictable (op1 (b1, b2) = Register R.SP ||
                                        (op1 (b1, b2) = Register R.PC &&
                                          chkUnpreInAndNotLastItBlock it))
let chkUnpreDK itState b (op, _) =
    isUnpredictable (op b = Register R.PC && chkUnpreInAndNotLastItBlock itState)

let chkUnpreDL mode b (op1, _) =
    isUnpredictable (op1 b = Register R.SP && mode <> ArchOperationMode.ARMMode)

let chkUndefA q b _ =
    let size = extract b 21u 20u
    isUndefined (size = 0u || size = 3u ||
                              (q = 1u && (pickBit b 16u = 1u || pickBit b 12u = 1u)))
let chkUndefB q b _ =
    let size = extract b 21u 20u
    isUndefined (size = 0u || (pickBit b 8u = 1u && size = 1u) ||
                              q = 1u && (pickBit b 12u = 1u || pickBit b 16u = 1u))
let chkUndefC b _ = isUndefined (extract b 21u 20u = 0u || pickBit b 12u = 1u)
let chkUndefD b  _ =
    let pick = pickBit b
    isUndefined (pick 6u = 1u && (pick 12u = 1u || pick 16u = 1u || pick 0u = 1u))
let chkUndefE b _ = isUndefined (extract b 21u 20u = 3u)
let chkUndefF b _ = chkUndefD b (); chkUndefE b ()
let chkUndefG b _ =
    isUndefined (pickBit b 6u = 0b0u && pickBit b 10u = 0b1u); chkUndefD b ()
let chkUndefH b _ =
    isUndefined (pickBit b 6u = 1u && (pickBit b 12u = 1u || pickBit b 0u = 1u))
let chkUndefJ b _ = isUndefined (extract b 21u 20u = 3u); chkUndefD b ()
let chkUndefK b _ =
    let size = extract b 21u 20u
    isUndefined (size = 0u || size = 3u); chkUndefD b ()
let chkUndefL b _ = isUndefined (pickBit b 20u = 1u); chkUndefD b ()
let chkUndefM b _ = isUndefined (pickBit b 20u = 1u || pickBit b 6u = 1u)
let chkUndefN b _ = isUndefined (pickBit b 6u = 0b1u && pickBit b 12u = 0b1u)
let chkUndefO b _ = isUndefined (extract b 3u 0u % 2u = 0b1u)
let chkUndefP b _ = isUndefined (pickBit b 21u = 0b0u); chkUndefH b ()
let chkUndefQ b _ =
    isUndefined (pickBit b 12u = 1u || (pickBit b 8u = 1u && pickBit b 16u = 1u))
let chkUndefR b _ = isUndefined (pickBit b 16u = 1u || pickBit b 0u = 1u)
let chkUndefS b _ = isUndefined (pickBit b 12u = 0b1u)
let chkUndefT b _ = isUndefined (extract b 21u 20u = 0u || pickBit b 12u = 1u)
let chkUndefU b _ =
    chkUndefH b ()
    isUndefined (pickBit b 6u = 0u &&
                              ((extract b 8u 7u) + (extract b 19u 18u)) >= 3u)
let chkUndefV b _ = chkUndefH b (); isUndefined (extract b 19u 18u = 0b11u)
let chkUndefW b _ = chkUndefH b (); isUndefined (extract b 19u 18u <> 0b10u)
let chkUndefX b _ =
    chkUndefH b (); isUndefined (pickBit b 6u = 0u && extract b 19u 18u = 0b11u)
let chkUndefY b _ =
    chkUndefH b (); isUndefined (pickBit b 6u = 0u && extract b 19u 18u <> 0b00u)
let chkUndefZ b _ =
    chkUndefH b (); isUndefined (extract b 19u 18u <> 0b00u)
let chkUndefAA b _ =
    chkUndefH b (); isUndefined (extract b 19u 18u = 0b11u)
let chkUndefAB b _ =
    chkUndefH b ()
    isUndefined (extract b 19u 18u = 0b11u ||
                              pickBit b 6u = 0u && extract b 19u 18u = 0b10u)
let chkUndefAC b _ =
    let s = extract b 19u 18u
    chkUndefH b (); isUndefined (s = 0b11u || (pickBit b 10u = 1u && s <> 0b10u))
let chkUndefAD b _ = isUndefined (extract b 19u 18u = 3u || pickBit b 0u = 1u)
let chkUndefAE b _ =
    let op = pickBit b 8u
    isUndefined (extract b 19u 18u <> 01u || (op = 1u && pickBit b 12u = 1u) ||
                              (op = 0u && pickBit b 0u = 1u))
let chkUndefAF b _ =
    chkUndefH b (); isUndefined (extract b 19u 18u <> 0b10u)
let chkUndefAG b _ =
    let q = pickBit b 6u
    let i = extract b 19u 16u
    isUndefined ((q = 0u && (i = 0u || i = 8u)) || (q = 1u && pickBit b 12u = 1u))
let chkUndefAH b _ =
    let typ = extract b 11u 8u
    let align = extract b 5u 4u
    isUndefined (typ = 0b0111u && pickBit align 1u = 0b1u ||
                              (typ = 0b1010u && align = 0b11u) ||
                              (typ = 0b0110u && pickBit align 1u = 0b1u))
let chkUndefAI b _ =
    let typ = extract b 11u 8u
    let align = extract b 5u 4u
    isUndefined (extract b 7u 6u = 0b11u || (typ = 0b1000u && align = 0b11u) ||
                              (typ = 0b1001u && align = 0b11u))
let chkUndefAJ b _ = isUndefined (extract b 7u 6u = 3u || pickBit b 5u = 1u)
let chkUndefAK b _ = isUndefined (extract b 7u 6u = 0b11u)
let chkUndefAL b _ =
    let size = extract b 11u 10u
    let ia = extract b 7u 4u
    isUndefined ((size = 0b00u && pickBit ia 0u <> 0b0u) ||
                              (size = 0b01u && pickBit ia 1u <> 0b0u) ||
                              (size = 0b10u && pickBit ia 2u <> 0b0u) ||
                              (size = 0b10u && extract ia 1u 0u = 0b01u) ||
                              (size = 0b10u && extract ia 1u 0u = 0b10u))
let chkUndefAM b _ =
    isUndefined (extract b 11u 10u = 0b10u && pickBit b 5u <> 0b0u)
let chkUndefAN b _ =
    let size = extract b 11u 10u
    let ia = extract b 7u 4u
    isUndefined ((size = 0b00u && pickBit ia 0u <> 0b0u) ||
                              (size = 0b01u && pickBit ia 0u <> 0b0u) ||
                              (size = 0b10u && extract ia 1u 0u <> 0b00u))
let chkUndefAO b _ =
    isUndefined (extract b 11u 10u = 0b10u && extract b 5u 4u = 0b11u)
let chkUndefAP b _ =
    let size = extract b 7u 6u
    isUndefined (size = 0b11u || (size = 0b00u && pickBit b 4u = 0b1u))
let chkUndefAQ b _ = isUndefined (extract b 7u 6u = 0b11u)
let chkUndefAR b _ = isUndefined (extract b 7u 6u = 3u || pickBit b 4u = 1u)
let chkUndefAS b _ = isUndefined (extract b 7u 6u = 3u && pickBit b 4u = 0u)
let chkUndefAT b _ =
    isUndefined (pickBit b 12u = 1u || pickBit b 0u = 1u ||
                              extract b 19u 18u <> 0u)
let chkUndefAU b _ =
    isUndefined (pickBit b 12u = 1u || pickBit b 0u = 1u ||
                              extract b 19u 18u <> 2u)

let chkBothA (b1, b2) (op1, op2) =
    isUndefined (getRegister (extract b1 3u 0u |> byte) = R.PC)
    chkUnpreBL (b1, b2) (op1, op2)
let chkBothB (b1, b2) (op1, op2, op3, op4) =
    chkUnpreBX (b1, b2) (op1, op2, op3, op4)
    isUndefined (pickBit b1 4u = 0b1u || pickBit b2 4u = 0b1u)
let chkBothC (b1, b2) (op1 ,_) =
    let rn = getRegister (extract b1 3u 0u |> byte)
    let opr1 = op1 (b1, b2)
    isUndefined (rn = R.PC)
    isUnpredictable (opr1 = Register R.SP || opr1 = Register R.PC ||
                                      (pickBit b2 8u = 1u && Register rn = opr1))
let chkBothD (b1, b2) (op1, _) =
    let rn = getRegister (extract b1 3u 0u |> byte)
    isUndefined (rn = R.PC)
    isUnpredictable (op1 (b1, b2) = Register R.PC ||
                                      (pickBit b2 8u = 0b1u && Register rn = op1 (b1, b2)))
let chkBothE (b1, b2) (op1, op2) =
    isUndefined (getRegister (extract b1 3u 0u |> byte) = R.PC)
    chkUnpreBL (b1, b2) (op1, op2)
let chkBothF (b1, b2) (op1, _) =
    isUndefined (getRegister (extract b1 3u 0u |> byte) = R.PC)
    isUnpredictable (op1 (b1, b2) = Register R.PC)
let chkBothG (b1, b2) (op1, _) =
    let rm = getRegister (extract b2 3u 0u |> byte)
    let opr1 = op1 (b1, b2)
    isUndefined (getRegister (extract b1 3u 0u |> byte) = R.PC)
    isUnpredictable (opr1 = Register R.SP || opr1 = Register R.PC ||
                                      rm = R.SP || rm = R.PC)
let chkBothH (b1, b2) (op1, _) =
    let rm = getRegister (extract b2 3u 0u |> byte)
    isUndefined (getRegister (extract b1 3u 0u |> byte) = R.PC)
    isUnpredictable (op1 (b1, b2) = Register R.PC || rm = R.SP || rm = R.PC)

let oneDt dt = Some (OneDT dt)
let twoDt (dt1, dt2) = Some (TwoDT (dt1, dt2))

let getOneDtA b = extract b 21u 20u |> getSignedSizeBySize |> oneDt
let getOneDtB b =
    getIntSizeBySizeNF (extract b 21u 20u) (pickBit b 8u) |> oneDt
let getOneDtC b =
    getSignednessSizeBySizeNU (extract b 19u 18u) (pickBit b 7u) |> oneDt
let getOneDtD u b = getSignednessSizeBySizeNU (extract b 21u 20u) u |> oneDt
let getOneDtE () = oneDt SIMDTyp8
let getOneDtF b = extract b 21u 20u |> getIntegerSizeBySize |> oneDt
let getOneDtG b = pickBit b 20u |> getFloatSizeBySz |> oneDt
let getOneDtH b =
    match concat (pickBit b 5u) (extract b 11u 9u) 3 with
    | r when r &&& 0b0100u = 0b0000u -> SIMDTypI32
    | r when r &&& 0b0111u = 0b0110u -> SIMDTypI32
    | r when r &&& 0b0110u = 0b0100u -> SIMDTypI16
    | 0b1111u when pickBit b 8u = 0u -> SIMDTypI64
    | 0b0111u when pickBit b 8u = 0u -> SIMDTypI8
    | 0b0111u when pickBit b 8u = 1u -> SIMDTypF32
    | _ -> raise UndefinedException
    |> oneDt
let getOneDtI b =
    match concat (pickBit b 22u) (pickBit b 5u) 1 with
    | 0b00u -> SIMDTyp32
    | 0b01u -> SIMDTyp16
    | 0b10u -> SIMDTyp8
    | _ -> raise InvalidSizeException
    |> oneDt
let getOneDtJ u b =
    match u, concat (pickBit b 7u) (extract b 21u 19u) 3 with
    | 0u, 1u -> SIMDTypS8
    | 1u, 1u -> SIMDTypU8
    | 0u, i when i &&& 0b1110u = 0b0010u -> SIMDTypS16
    | 1u, i when i &&& 0b1110u = 0b0010u -> SIMDTypU16
    | 0u, i when i &&& 0b1100u = 0b0100u -> SIMDTypS32
    | 1u, i when i &&& 0b1100u = 0b0100u -> SIMDTypU32
    | 0u, i when i &&& 0b1000u = 0b1000u -> SIMDTypS64
    | 1u, i when i &&& 0b1000u = 0b1000u -> SIMDTypU64
    | _ -> failwith "Wrong encoding in getOneDtJ"
    |> oneDt

let getOneDtK b =
    match concat (pickBit b 7u) (extract b 21u 19u) 3 with
    | 1u -> SIMDTyp8
    | i when i &&& 0b1110u = 0b0010u -> SIMDTyp16
    | i when i &&& 0b1100u = 0b0100u -> SIMDTyp32
    | i when i &&& 0b1000u = 0b1000u -> SIMDTyp64
    | _ -> failwith "Wrong encoding in getOneDtK"
    |> oneDt

let getOneDtL b =
    match concat (pickBit b 7u) (extract b 21u 19u) 3 with
    | i when i &&& 0b1111u = 0b0001u -> SIMDTypI8
    | i when i &&& 0b1110u = 0b0010u -> SIMDTypI16
    | i when i &&& 0b1100u = 0b0100u -> SIMDTypI32
    | i when i &&& 0b1000u = 0b1000u -> SIMDTypI64
    | _ -> failwith "Wrong encoding getOneDtL"
    |> oneDt

let getOneDtM b =
    match extract b 21u 19u with
    | 1u -> SIMDTypI16
    | i when i &&& 0b110u = 0b010u -> SIMDTypI32
    | i when i &&& 0b100u = 0b100u -> SIMDTypI64
    | _ -> failwith "Wrong encoding in getOneDtM"
    |> oneDt

let getOneDtN b =
    match extract b 21u 19u with
    | 1u -> SIMDTypS16
    | i when i &&& 0b110u = 0b010u -> SIMDTypS32
    | i when i &&& 0b100u = 0b100u -> SIMDTypS64
    | _ -> failwith "Wrong encoding in getOneDtN"
    |> oneDt

let getOneDtO u b =
    match u, extract b 21u 19u with
    | 0u, i when i &&& 0b111u = 0b001u -> SIMDTypS16
    | 1u, i when i &&& 0b111u = 0b001u -> SIMDTypU16
    | 0u, i when i &&& 0b110u = 0b010u -> SIMDTypS32
    | 1u, i when i &&& 0b110u = 0b010u -> SIMDTypU32
    | 0u, i when i &&& 0b100u = 0b100u -> SIMDTypS64
    | 1u, i when i &&& 0b100u = 0b100u -> SIMDTypU64
    | _ -> failwith "Wrong encoding in getOneDtO"
    |> oneDt

let getOneDtP u b =
    match u, extract b 21u 19u with
    | 0u, i when i &&& 0b111u = 0b001u -> SIMDTypS8
    | 1u, i when i &&& 0b111u = 0b001u -> SIMDTypU8
    | 0u, i when i &&& 0b110u = 0b010u -> SIMDTypS16
    | 1u, i when i &&& 0b110u = 0b010u -> SIMDTypU16
    | 0u, i when i &&& 0b100u = 0b100u -> SIMDTypS32
    | 1u, i when i &&& 0b100u = 0b100u -> SIMDTypU32
    | _ -> failwith "Wrong encoding in getOneDtP"
    |> oneDt

let getOneDtQ b =
    extract b 21u 20u |> getIntegerSizeBySize2 |> oneDt
let getOneDtR u b =
    match pickBit b 9u, u, extract b 21u 20u with
    | 0b0u, 0b0u, 0b00u -> SIMDTypS8
    | 0b0u, 0b0u, 0b01u -> SIMDTypS16
    | 0b0u, 0b0u, 0b10u -> SIMDTypS32
    | 0b0u, 0b1u, 0b00u -> SIMDTypU8
    | 0b0u, 0b1u, 0b01u -> SIMDTypU16
    | 0b0u, 0b1u, 0b10u -> SIMDTypU32
    | 0b1u, 0b0u, 0b00u -> SIMDTypP8
    | _ -> raise InvalidSizeException
    |> oneDt
let getOneDtS b = extract b 19u 18u |> getSizeBySize |> oneDt
let getOneDtT b = extract b 19u 18u |> getSignedSizeBySize |> oneDt
let getOneDtU b = extract b 19u 18u |> getIntegerSizeBySize |> oneDt
let getOneDtV b =
    match extract b 19u 18u, pickBit b 10u with
    | 0b00u, 0b0u -> SIMDTypS8
    | 0b01u, 0b0u -> SIMDTypS16
    | 0b10u, 0b0u -> SIMDTypS32
    | 0b10u, 0b1u -> SIMDTypF32
    | _ -> raise InvalidSizeException
    |> oneDt
let getOneDtW b =
    getIntSizeBySizeNF (extract b 19u 18u) (pickBit b 10u) |> oneDt
let getOneDtX b = extract b 19u 18u |> getIntegerSizeBySize2 |> oneDt
let getOneDtY b =
    match extract b 7u 6u, extract b 19u 18u with
    | 0b01u, 0b00u -> SIMDTypS16
    | 0b01u, 0b01u -> SIMDTypS32
    | 0b01u, 0b10u -> SIMDTypS64
    | 0b11u, 0b00u -> SIMDTypU16
    | 0b11u, 0b01u -> SIMDTypU32
    | 0b11u, 0b10u -> SIMDTypU64
    | _ -> raise InvalidSizeException
    |> oneDt
let getOneDtZ b =
    match extract b 19u 18u, pickBit b 8u with
    | 0b10u, 0u -> SIMDTypU32
    | 0b10u, 1u -> SIMDTypF32
    | _ -> raise InvalidSizeException
    |> oneDt
let getOneDtAA () = SIMDTypF32 |> oneDt
let getOneDtAB b =
    match extract b 19u 16u with
    | i4 when i4 &&& 0b0001u = 0b0001u -> SIMDTyp8
    | i4 when i4 &&& 0b0011u = 0b0010u -> SIMDTyp16
    | i4 when i4 &&& 0b0111u = 0b0100u -> SIMDTyp32
    | _ -> raise InvalidSizeException
    |> oneDt
let getOneDtAC b = extract b 7u 6u |> getSizeBySize |> oneDt
let getOneDtAD b = extract b 11u 10u |> getSizeBySize |> oneDt
let getOneDtAE b = extract b 7u 6u |> getSizeBySizeForVLD4 |> oneDt
let getOneDtAF b = pickBit b 8u |> getFloatSizeBySz |> oneDt
let getOneDtAG b =
    match concat (extract b 22u 21u) (extract b 6u 5u) 2 with
    | opc when opc &&& 0b1000u = 0b1000u -> SIMDTyp8
    | opc when opc &&& 0b1001u = 0b0001u -> SIMDTyp16
    | opc when opc &&& 0b1011u = 0b0000u -> SIMDTyp32
    | opc when opc &&& 0b1011u = 0b0010u -> raise UndefinedException
    | _ -> failwith "Wrong oneAuxAG encoding."
    |> oneDt
let getOneDtAH b =
    let opc = concat (extract b 22u 21u) (extract b 6u 5u) 2
    match concat (pickBit b 23u) opc 4 with
    | o when o &&& 0b11000u = 0b01000u -> SIMDTypS8
    | o when o &&& 0b11000u = 0b11000u -> SIMDTypU8
    | o when o &&& 0b11001u = 0b00001u -> SIMDTypS16
    | o when o &&& 0b11001u = 0b10001u -> SIMDTypU16
    | o when o &&& 0b11011u = 0b00000u -> SIMDTyp32
    | o when o &&& 0b11011u = 0b10000u -> raise UndefinedException
    | o when o &&& 0b01011u = 0b00010u -> raise UndefinedException
    | _ -> failwith "Wrong operand encoding."
    |> oneDt
let getOneDtAI () = SIMDTyp32 |> oneDt
let getQfW () = Some W
let getQfN () = Some N
let getTwoDtA u b =
    match u, pickBit b 8u with
    | 0b0u, 0b1u -> SIMDTypS32, SIMDTypF32
    | 0b1u, 0b1u -> SIMDTypU32, SIMDTypF32
    | 0b0u, 0b0u -> SIMDTypF32, SIMDTypS32
    | 0b1u, 0b0u -> SIMDTypF32, SIMDTypU32
    | _ -> failwith "Wrong encoding getTwoDtA"
    |> twoDt
let getTwoDtB b =
    match extract b 8u 7u, extract b 19u 18u with
    | 0b10u, 0b10u -> SIMDTypS32, SIMDTypF32
    | 0b11u, 0b10u -> SIMDTypU32, SIMDTypF32
    | 0b00u, 0b10u -> SIMDTypF32, SIMDTypS32
    | 0b01u, 0b10u -> SIMDTypF32, SIMDTypU32
    | _ -> raise InvalidSizeException
    |> twoDt
let getTwoDtC b =
    match pickBit b 8u with
    | 0b0u -> SIMDTypF16, SIMDTypF32
    | 0b1u -> SIMDTypF32, SIMDTypF16
    | _ -> raise InvalidSizeException
    |> twoDt
let getTwoDtD b =
    match pickBit b 8u with
    | 0b0u -> SIMDTypF64, SIMDTypF32
    | 0b1u -> SIMDTypF32, SIMDTypF64
    | _ -> raise InvalidSizeException
    |> twoDt
let getTwoDtE b =
    match pickBit b 16u with
    | 0b0u -> SIMDTypF32, SIMDTypF16
    | 0b1u -> SIMDTypF16, SIMDTypF32
    | _ -> raise InvalidSizeException
    |> twoDt
let getTwoDtF b =
    match extract b 18u 16u, pickBit b 8u with
    | 0b101u, 1u -> SIMDTypS32, SIMDTypF64
    | 0b101u, 0u -> SIMDTypS32, SIMDTypF32
    | 0b100u, 1u -> SIMDTypU32, SIMDTypF64
    | 0b100u, 0u -> SIMDTypU32, SIMDTypF32
    | 0b000u, 1u -> SIMDTypF64, (getSignednessSize32ByOp (pickBit b 7u))
    | 0b000u, 0u -> SIMDTypF32, (getSignednessSize32ByOp (pickBit b 7u))
    | _ -> failwith "Wrong twoAuxF encoding."
    |> twoDt
let getTwoDtG b =
    match extract b 18u 16u, pickBit b 8u with
    | 0b101u, 1u -> SIMDTypS32, SIMDTypF64
    | 0b101u, 0u -> SIMDTypS32, SIMDTypF32
    | 0b100u, 1u -> SIMDTypU32, SIMDTypF64
    | 0b100u, 0u -> SIMDTypU32, SIMDTypF32
    | _ -> failwith "Wrong twoAuxG encoding."
    |> twoDt
let getTwoDtH b =
    let u = pickBit b 16u
    let sx = pickBit b 7u
    match pickBit b 18u, pickBit b 8u with
    | 0b1u, 1u -> (getSignednessSizeByUNSx u sx), SIMDTypF64
    | 0b1u, 0u -> (getSignednessSizeByUNSx u sx), SIMDTypF32
    | 0b0u, 1u -> SIMDTypF64, (getSignednessSizeByUNSx u sx)
    | 0b0u, 0u -> SIMDTypF32, (getSignednessSizeByUNSx u sx)
    | _ -> failwith "Wrong twoAuxH encoding."
    |> twoDt

let getRrRsSCa q = getRegR q, getRegS q, getScalarA
let getRxIa opcode i = getRegX, getImmA opcode i

/// Multiply and multiply-accumulate, page A5-202 in ARMv7-A , DDI0406C.b
/// Multiply and Accumulate, page F4.2.2 in ARMv8-A ARM DDI 0487A.k
let parseMulNMulAcc bin =
    match extract bin 23u 20u with
    | 0b0000u ->
        Op.MUL, parseThreeOprs bin chkUnpreA (getRegC, getRegA, getRegB)
    | 0b0001u ->
        Op.MULS, parseThreeOprs bin chkUnpreA (getRegC, getRegA, getRegB)
    | 0b0010u ->
        Op.MLA, parseFourOprs bin chkUnpreB (getRegC, getRegA, getRegB, getRegD)
    | 0b0011u ->
        Op.MLAS, parseFourOprs bin chkUnpreB (getRegC, getRegA, getRegB, getRegD)
    | 0b0100u ->
        Op.UMAAL, parseFourOprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
    | 0b0101u -> raise UndefinedException
    | 0b0110u ->
        Op.MLS, parseFourOprs bin chkUnpreB (getRegC, getRegA, getRegB, getRegD)
    | 0b0111u -> raise UndefinedException
    | 0b1000u ->
        Op.UMULL, parseFourOprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
    | 0b1001u ->
        Op.UMULLS, parseFourOprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
    | 0b1010u ->
        Op.UMLAL, parseFourOprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
    | 0b1011u ->
        Op.UMLALS, parseFourOprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
    | 0b1100u ->
        Op.SMULL, parseFourOprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
    | 0b1101u ->
        Op.SMULLS, parseFourOprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
    | 0b1110u ->
        Op.SMLAL, parseFourOprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
    | 0b1111u ->
        Op.SMLALS, parseFourOprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
    | _ -> failwith "Wrong Multiply & mul-accumulate encoding."

/// Halfword multiply and multi..., page A5-203 in ARMv7-A , DDI0406C.b
/// Halfword Multiply and Accumulate on page F4-2510  in ARMv8-A ARM DDI 0487A.k
let parseHalfMulNMulAcc bin =
    match concat (extract bin 22u 21u) (extract bin 6u 5u) 2 with
    | 0b0000u ->
        Op.SMLABB, parseFourOprs bin chkUnpreB (getRegC, getRegA, getRegB, getRegD)
    | 0b0001u ->
        Op.SMLATB, parseFourOprs bin chkUnpreB (getRegC, getRegA, getRegB, getRegD)
    | 0b0010u ->
        Op.SMLABT, parseFourOprs bin chkUnpreB (getRegC, getRegA, getRegB, getRegD)
    | 0b0011u ->
        Op.SMLATT, parseFourOprs bin chkUnpreB (getRegC, getRegA, getRegB, getRegD)
    | 0b0100u ->
        Op.SMLAWB, parseFourOprs bin chkUnpreB (getRegC, getRegA, getRegB, getRegD)
    | 0b0110u ->
        Op.SMLAWT, parseFourOprs bin chkUnpreB (getRegC, getRegA, getRegB, getRegD)
    | 0b0101u ->
        Op.SMULWB, parseThreeOprs bin dummyChk (getRegD, getRegA, getRegB)
    | 0b0111u ->
        Op.SMULWT, parseThreeOprs bin chkUnpreA (getRegC, getRegA, getRegB)
    | 0b1000u ->
        Op.SMLALBB, parseFourOprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
    | 0b1001u ->
        Op.SMLALTB, parseFourOprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
    | 0b1010u ->
        Op.SMLALBT, parseFourOprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
    | 0b1011u ->
        Op.SMLALTT, parseFourOprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
    | 0b1100u ->
        Op.SMULBB, parseThreeOprs bin chkUnpreA (getRegC, getRegA, getRegB)
    | 0b1101u ->
        Op.SMULTB, parseThreeOprs bin chkUnpreA (getRegC, getRegA, getRegB)
    | 0b1110u ->
        Op.SMULBT, parseThreeOprs bin chkUnpreA (getRegC, getRegA, getRegB)
    | 0b1111u ->
        Op.SMULTT, parseThreeOprs bin chkUnpreA (getRegC, getRegA, getRegB)
    | _ -> failwith "Wrong Halfword multiply & mul-accumulate encoding."

/// Memory hints, Adv SIMD instrs, and miscellaneous instrs, page A5-217
/// CPS, CPSID, CPSIE on page F4-2645 in ARMv8-A ARM DDI 0487A.k
let getCPS bin =
    match extract bin 19u 18u, pickBit bin 17u with
    | 0u, 0u -> raise UnpredictableException
    | 0u, 1u -> Op.CPS, parseOneOpr bin dummyChk getImm5B
    | 1u, _ -> raise UnpredictableException
    | 2u, 0u -> Op.CPSIE, parseOneOpr bin dummyChk getFlagA
    | 2u, 1u -> Op.CPSIE, parseTwoOprs bin dummyChk (getFlagA, getImm5B)
    | 3u, 0u -> Op.CPSID, parseOneOpr bin dummyChk getFlagA
    | 3u, 1u -> Op.CPSID, parseTwoOprs bin dummyChk (getFlagA, getImm5B)
    | _ -> failwith "Wrong Uncond Miscellaneous instrs encoding."

// vim: set tw=80 sts=2 sw=2:
