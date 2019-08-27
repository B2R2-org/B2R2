(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Seung Il Jung <sijung@kaist.ac.kr>

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

module internal B2R2.FrontEnd.ARM64.OperandHelper

open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.ARM64.Utils
open System.Runtime.CompilerServices

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.Tests")>]
do ()

let memBaseImm offset = Memory (BaseMode (ImmOffset (BaseOffset offset)))
let memBaseReg offset = Memory (BaseMode (RegOffset offset))
let memPreIdxImm offset = Memory (PreIdxMode (ImmOffset (BaseOffset offset)))
let memPreIdxReg offset = Memory (PreIdxMode (RegOffset offset))
let memPostIdxImm offset = Memory (PostIdxMode (ImmOffset (BaseOffset offset)))
let memPostIdxReg offset = Memory (PostIdxMode (RegOffset offset))
let memLabel lbl = Memory (LiteralMode (ImmOffset (Lbl lbl)))
let sVRegIdx vReg vec idx = SIMDVecRegWithIdx (vReg, vec, idx)
let scalReg reg = SIMDOpr (SFReg (SIMDFPScalarReg reg))

let getRegister64 oprSize = function
  | 0x0uy -> if oprSize = 32<rt> then R.W0 else R.X0
  | 0x1uy -> if oprSize = 32<rt> then R.W1 else R.X1
  | 0x2uy -> if oprSize = 32<rt> then R.W2 else R.X2
  | 0x3uy -> if oprSize = 32<rt> then R.W3 else R.X3
  | 0x4uy -> if oprSize = 32<rt> then R.W4 else R.X4
  | 0x5uy -> if oprSize = 32<rt> then R.W5 else R.X5
  | 0x6uy -> if oprSize = 32<rt> then R.W6 else R.X6
  | 0x7uy -> if oprSize = 32<rt> then R.W7 else R.X7
  | 0x8uy -> if oprSize = 32<rt> then R.W8 else R.X8
  | 0x9uy -> if oprSize = 32<rt> then R.W9 else R.X9
  | 0xAuy -> if oprSize = 32<rt> then R.W10 else R.X10
  | 0xBuy -> if oprSize = 32<rt> then R.W11 else R.X11
  | 0xCuy -> if oprSize = 32<rt> then R.W12 else R.X12
  | 0xDuy -> if oprSize = 32<rt> then R.W13 else R.X13
  | 0xEuy -> if oprSize = 32<rt> then R.W14 else R.X14
  | 0xFuy -> if oprSize = 32<rt> then R.W15 else R.X15
  | 0x10uy -> if oprSize = 32<rt> then R.W16 else R.X16
  | 0x11uy -> if oprSize = 32<rt> then R.W17 else R.X17
  | 0x12uy -> if oprSize = 32<rt> then R.W18 else R.X18
  | 0x13uy -> if oprSize = 32<rt> then R.W19 else R.X19
  | 0x14uy -> if oprSize = 32<rt> then R.W20 else R.X20
  | 0x15uy -> if oprSize = 32<rt> then R.W21 else R.X21
  | 0x16uy -> if oprSize = 32<rt> then R.W22 else R.X22
  | 0x17uy -> if oprSize = 32<rt> then R.W23 else R.X23
  | 0x18uy -> if oprSize = 32<rt> then R.W24 else R.X24
  | 0x19uy -> if oprSize = 32<rt> then R.W25 else R.X25
  | 0x1Auy -> if oprSize = 32<rt> then R.W26 else R.X26
  | 0x1Buy -> if oprSize = 32<rt> then R.W27 else R.X27
  | 0x1Cuy -> if oprSize = 32<rt> then R.W28 else R.X28
  | 0x1Duy -> if oprSize = 32<rt> then R.W29 else R.X29
  | 0x1Euy -> if oprSize = 32<rt> then R.W30 else R.X30
  | 0x1Fuy -> if oprSize = 32<rt> then R.WZR else R.XZR
  | _ -> raise InvalidRegisterException

let getRegister64orSP oprSize = function
  | 0x1Fuy -> if oprSize = 32<rt> then R.WSP else R.SP
  | b -> getRegister64 oprSize b

let getControlRegister = function (* 1:op0:op1:CRn:CRm:op2 *)
  | 0b1100000010000001u -> R.ACTLREL1
  | 0b1110000010000001u -> R.ACTLREL2
  | 0b1111000010000001u -> R.ACTLREL3
  | 0b1100001010001000u -> R.AFSR0EL1
  | 0b1110001010001000u -> R.AFSR0EL2
  | 0b1111001010001000u -> R.AFSR0EL3
  | 0b1100001010001001u -> R.AFSR1EL1
  | 0b1110001010001001u -> R.AFSR1EL2
  | 0b1111001010001001u -> R.AFSR1EL3
  | 0b1100100000000111u -> R.AIDREL1
  | 0b1100010100011000u -> R.AMAIREL1
  | 0b1110010100011000u -> R.AMAIREL2
  | 0b1111010100011000u -> R.AMAIREL3
  | 0b1100100000000000u -> R.CCSIDREL1
  | 0b1100100000000001u -> R.CLIDREL1
  | 0b1100011010000001u -> R.CONTEXTIDREL1
  | 0b1100000010000010u -> R.CPACREL1
  | 0b1110000010001010u -> R.CPTREL2
  | 0b1111000010001010u -> R.CPTREL3
  | 0b1101000000000000u -> R.CSSELREL1
  | 0b1101100000000001u -> R.CTREL0
  | 0b1110000110000000u -> R.DACR32EL2
  | 0b1101100000000111u -> R.DCZIDEL0
  | 0b1100001010010000u -> R.ESREL1
  | 0b1110001010010000u -> R.ESREL2
  | 0b1111001010010000u -> R.ESREL3
  | 0b1110001100000100u -> R.HPFAREL2
  | 0b1101111010000010u -> R.TPIDREL0
  | 0b1101101000100000u -> R.FPCR
  | 0b1101101000100001u -> R.FPSR
  | _ -> failwith "Implement" (* D7.2 General system control registers *)

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

let getDCOpr = function
 | 0b0000110001u -> IVAC
 | 0b0000110010u -> ISW
 | 0b0001010010u -> CSW
 | 0b0001110010u -> CISW
 | 0b0110100001u -> ZVA
 | 0b0111010001u -> CVAC
 | 0b0111011001u -> CVAU
 | 0b0111110001u -> CIVAC
 (* C5.3 A64 system instructions for cache maintenance *)
 | _ -> failwith "Invalid DC Operand"

let SIMDFP0  = [| R.B0; R.H0; R.S0; R.D0; R.Q0 |]
let SIMDFP1  = [| R.B1; R.H1; R.S1; R.D1; R.Q1 |]
let SIMDFP2  = [| R.B2; R.H2; R.S2; R.D2; R.Q2 |]
let SIMDFP3  = [| R.B3; R.H3; R.S3; R.D3; R.Q3 |]
let SIMDFP4  = [| R.B4; R.H4; R.S4; R.D4; R.Q4 |]
let SIMDFP5  = [| R.B5; R.H5; R.S5; R.D5; R.Q5 |]
let SIMDFP6  = [| R.B6; R.H6; R.S6; R.D6; R.Q6 |]
let SIMDFP7  = [| R.B7; R.H7; R.S7; R.D7; R.Q7 |]
let SIMDFP8  = [| R.B8; R.H8; R.S8; R.D8; R.Q8 |]
let SIMDFP9  = [| R.B9; R.H9; R.S9; R.D9; R.Q9 |]
let SIMDFP10 = [| R.B10; R.H10; R.S10; R.D10; R.Q10 |]
let SIMDFP11 = [| R.B11; R.H11; R.S11; R.D11; R.Q11 |]
let SIMDFP12 = [| R.B12; R.H12; R.S12; R.D12; R.Q12 |]
let SIMDFP13 = [| R.B13; R.H13; R.S13; R.D13; R.Q13 |]
let SIMDFP14 = [| R.B14; R.H14; R.S14; R.D14; R.Q14 |]
let SIMDFP15 = [| R.B15; R.H15; R.S15; R.D15; R.Q15 |]
let SIMDFP16 = [| R.B16; R.H16; R.S16; R.D16; R.Q16 |]
let SIMDFP17 = [| R.B17; R.H17; R.S17; R.D17; R.Q17 |]
let SIMDFP18 = [| R.B18; R.H18; R.S18; R.D18; R.Q18 |]
let SIMDFP19 = [| R.B19; R.H19; R.S19; R.D19; R.Q19 |]
let SIMDFP20 = [| R.B20; R.H20; R.S20; R.D20; R.Q20 |]
let SIMDFP21 = [| R.B21; R.H21; R.S21; R.D21; R.Q21 |]
let SIMDFP22 = [| R.B22; R.H22; R.S22; R.D22; R.Q22 |]
let SIMDFP23 = [| R.B23; R.H23; R.S23; R.D23; R.Q23 |]
let SIMDFP24 = [| R.B24; R.H24; R.S24; R.D24; R.Q24 |]
let SIMDFP25 = [| R.B25; R.H25; R.S25; R.D25; R.Q25 |]
let SIMDFP26 = [| R.B26; R.H26; R.S26; R.D26; R.Q26 |]
let SIMDFP27 = [| R.B27; R.H27; R.S27; R.D27; R.Q27 |]
let SIMDFP28 = [| R.B28; R.H28; R.S28; R.D28; R.Q28 |]
let SIMDFP29 = [| R.B29; R.H29; R.S29; R.D29; R.Q29 |]
let SIMDFP30 = [| R.B30; R.H30; R.S30; R.D30; R.Q30 |]
let SIMDFP31 = [| R.B31; R.H31; R.S31; R.D31; R.Q31 |]

let convReg (grp: Register []) = function
  | 8 -> grp.[0]
  | 16 -> grp.[1]
  | 32 -> grp.[2]
  | 64 -> grp.[3]
  | 128 -> grp.[4]
  | _ -> raise InvalidOperandSizeException

let getSIMDFPRegister64 oprSize = function
  | 0x0uy -> convReg SIMDFP0 oprSize
  | 0x1uy -> convReg SIMDFP1 oprSize
  | 0x2uy -> convReg SIMDFP2 oprSize
  | 0x3uy -> convReg SIMDFP3 oprSize
  | 0x4uy -> convReg SIMDFP4 oprSize
  | 0x5uy -> convReg SIMDFP5 oprSize
  | 0x6uy -> convReg SIMDFP6 oprSize
  | 0x7uy -> convReg SIMDFP7 oprSize
  | 0x8uy -> convReg SIMDFP8 oprSize
  | 0x9uy -> convReg SIMDFP9 oprSize
  | 0xAuy -> convReg SIMDFP10 oprSize
  | 0xBuy -> convReg SIMDFP11 oprSize
  | 0xCuy -> convReg SIMDFP12 oprSize
  | 0xDuy -> convReg SIMDFP13 oprSize
  | 0xEuy -> convReg SIMDFP14 oprSize
  | 0xFuy -> convReg SIMDFP15 oprSize
  | 0x10uy -> convReg SIMDFP16 oprSize
  | 0x11uy -> convReg SIMDFP17 oprSize
  | 0x12uy -> convReg SIMDFP18 oprSize
  | 0x13uy -> convReg SIMDFP19 oprSize
  | 0x14uy -> convReg SIMDFP20 oprSize
  | 0x15uy -> convReg SIMDFP21 oprSize
  | 0x16uy -> convReg SIMDFP22 oprSize
  | 0x17uy -> convReg SIMDFP23 oprSize
  | 0x18uy -> convReg SIMDFP24 oprSize
  | 0x19uy -> convReg SIMDFP25 oprSize
  | 0x1Auy -> convReg SIMDFP26 oprSize
  | 0x1Buy -> convReg SIMDFP27 oprSize
  | 0x1Cuy -> convReg SIMDFP28 oprSize
  | 0x1Duy -> convReg SIMDFP29 oprSize
  | 0x1Euy -> convReg SIMDFP30 oprSize
  | 0x1Fuy -> convReg SIMDFP31 oprSize
  | _ -> raise InvalidRegisterException

let getVRegister64 = function
  | 0x00uy -> R.V0
  | 0x01uy -> R.V1
  | 0x02uy -> R.V2
  | 0x03uy -> R.V3
  | 0x04uy -> R.V4
  | 0x05uy -> R.V5
  | 0x06uy -> R.V6
  | 0x07uy -> R.V7
  | 0x08uy -> R.V8
  | 0x09uy -> R.V9
  | 0x0Auy -> R.V10
  | 0x0Buy -> R.V11
  | 0x0Cuy -> R.V12
  | 0x0Duy -> R.V13
  | 0x0Euy -> R.V14
  | 0x0Fuy -> R.V15
  | 0x10uy -> R.V16
  | 0x11uy -> R.V17
  | 0x12uy -> R.V18
  | 0x13uy -> R.V19
  | 0x14uy -> R.V20
  | 0x15uy -> R.V21
  | 0x16uy -> R.V22
  | 0x17uy -> R.V23
  | 0x18uy -> R.V24
  | 0x19uy -> R.V25
  | 0x1Auy -> R.V26
  | 0x1Buy -> R.V27
  | 0x1Cuy -> R.V28
  | 0x1Duy -> R.V29
  | 0x1Euy -> R.V30
  | 0x1Fuy -> R.V31
  | _ -> raise InvalidRegisterException

let getSIMDVector8B = function
  | 0b000u -> EightB
  | 0b001u -> SixteenB
  | 0b010u -> FourH
  | 0b011u -> EightH
  | 0b100u -> TwoS
  | 0b101u -> FourS
  | 0b111u -> TwoD
  | 0b110u -> OneD
  | _ -> failwith "Invalid SIMD vector"

let getSIMDVector4H = function
  | 0b000u -> FourH
  | 0b001u -> EightH
  | 0b010u -> TwoS
  | 0b011u -> FourS
  | 0b100u -> OneD
  | 0b101u -> TwoD
  | _ -> failwith "Invalid SIMD vector"

let getSIMDVectorBySize1 = function
  | 0b00u -> EightH
  | 0b01u -> FourS
  | 0b10u -> TwoD
  | 0b11u -> OneQ
  | _ -> failwith "Invalid SIMD vector by size"

let getSIMDVectorBySize2 value =
  if value = 0b11u then TwoD else failwith "Invalid SIMD vector"

let getSIMDVectorBySz1 value = if value = 0b0u then FourS else TwoD
let getSIMDVectorBySz2 value = if value = 0b0u then VecS else VecD
let getSIMDVectorBySz3 value = if value = 0b0u then TwoS else TwoD

let getSIMDVectorByQ1 value = if value = 0b0u then EightB else SixteenB
let getSIMDVectorByQ2 value = if value = 0b0u then TwoS else FourS
let getSIMDVectorByQ3 value = if value = 0b0u then FourH else EightH

let getSIMDVectorBySizeWithIdx = function
  | 0b00u -> VecB
  | 0b01u -> VecH
  | 0b10u -> VecS
  | 0b11u -> VecD
  | _ -> failwith "Invalid SIMD vector by size with element indexed"

let getSIMDVectorBySzQ4H = function
  | 0b00u -> FourH
  | 0b01u -> EightH
  | 0b10u -> TwoS
  | 0b11u -> FourS
  | _ -> failwith "Invalid SIMD vector by szQ"

let getSIMDVectorBySzQ2S = function
  | 0b00u -> TwoS
  | 0b01u -> FourS
  | 0b11u -> TwoD
  | _ -> failwith "Invalid SIMD vector by szQ"

let getSIMDVectorByImmhQ = function // ImmhQ
  | 0b00010u -> EightB
  | 0b00011u -> SixteenB
  | i when i &&& 0b11101u = 0b00100u -> FourH
  | i when i &&& 0b11101u = 0b00101u -> EightH
  | i when i &&& 0b11001u = 0b01000u -> TwoS
  | i when i &&& 0b11001u = 0b01001u -> FourS
  | i when i &&& 0b10001u = 0b10001u -> TwoD
  | i when i &&& 0b11110u = 0b00000u -> failwith "Adv SIMD modified immediate"
  | _ -> failwith "Invalid SIMD vector"

let getSIMDVectorByImmh = function // Immh
  | 0b0001u -> EightH
  | i when i &&& 0b1110u = 0b0010u -> FourS
  | i when i &&& 0b1100u = 0b0100u -> TwoD
  | 0b0000u -> failwith "Adv SIMD modified immediate"
  | _ -> failwith "Invalid SIMD vector"

let getSIMDVectorByImm5Q = function
  | i when i &&& 0b000011u = 0b000010u -> EightB
  | i when i &&& 0b000011u = 0b000011u -> SixteenB
  | i when i &&& 0b000111u = 0b000100u -> FourH
  | i when i &&& 0b000111u = 0b000101u -> EightH
  | i when i &&& 0b001111u = 0b001000u -> TwoS
  | i when i &&& 0b001111u = 0b001001u -> FourS
  | i when i &&& 0b011111u = 0b010001u -> TwoD
  | _ -> failwith "Invalid SIMD vector"

let getSIMDVectorByImm5 = function
  | i when i &&& 0b00001u = 0b00001u -> VecB
  | i when i &&& 0b00011u = 0b00010u -> VecH
  | i when i &&& 0b00111u = 0b00100u -> VecS
  | i when i &&& 0b01111u = 0b01000u -> VecD
  | _ -> failwith "Invaild SIMD vector"

/// x - UInt(immh:immb) : right shift amount
let getShiftAmountByImmh1 immb = function
  | 0b0001u as immh -> 16u - concat immh immb 3
  | imm when imm &&& 0b1110u = 0b0010u -> 32u - concat imm immb 3
  | imm when imm &&& 0b1100u = 0b0100u -> 64u - concat imm immb 3
  | imm when imm &&& 0b1000u = 0b1000u -> 128u - concat imm immb 3
  | 0b0000u -> failwith "Advanced SIMD modified immediate"
  | _ -> failwith "Invalid shift amount"

/// UInt(immh:immb) - x : left shift amount
let getShiftAmountByImmh2 immb = function
  | 0b0001u as immh -> concat immh immb 3 - 8u
  | imm when imm &&& 0b1110u = 0b0010u -> concat imm immb 3 - 16u
  | imm when imm &&& 0b1100u = 0b0100u -> concat imm immb 3 - 32u
  | imm when imm &&& 0b1000u = 0b1000u -> concat imm immb 3 - 64u
  | 0b0000u -> failwith "Advanced SIMD modified immediate"
  | _ -> failwith "Invalid shift amount"

let getShiftAmountByShift = function
  | 0b00u -> 0u
  | 0b01u -> 12u
  | _ -> failwith "Invalid shift"

let getRmBySize m rm = function
  | 0b01u -> concat 0u rm 4
  | 0b10u -> concat m rm 4
  | _ -> failwith "Invalid size"

let getIdxBySize l h m = function
  | 0b01u -> concat (concat h l 1) m 1
  | 0b10u -> concat h l 1
  | _ -> failwith "Invalid size"

let getIdxBySz l h = function
  | 0b0u -> concat h l 1
  | 0b1u -> h
  | _ -> failwith "Invalid sz"

let getIdxByImm4 imm4 = function
  | 0b0u, 0b0u -> extract imm4 2u 0u
  | 0b1u, _ -> imm4
  | _ -> failwith "Invalid index"

let getIdxByImm5 = function
  | i when i &&& 0b00001u = 0b00001u -> extract i 4u 1u
  | i when i &&& 0b00011u = 0b00010u -> extract i 4u 2u
  | i when i &&& 0b00111u = 0b00100u -> extract i 4u 3u
  | i when i &&& 0b01111u = 0b01000u -> extract i 4u 4u
  | _ -> failwith "Invaild SIMD vector"

let getIdxByImm5Imm4 imm4 = function
  | i when i &&& 0b00001u = 0b00001u -> extract imm4 3u 0u
  | i when i &&& 0b00011u = 0b00010u -> extract imm4 3u 1u
  | i when i &&& 0b00111u = 0b00100u -> extract imm4 3u 2u
  | i when i &&& 0b01111u = 0b01000u -> pickBit imm4 3u
  | _ -> failwith "Invaild SIMD vector"

let getOption64 = function
  | 0b0001uy -> Some OSHLD
  | 0b0010uy -> Some OSHST
  | 0b0011uy -> Some OSH
  | 0b0101uy -> Some OSHLD
  | 0b0110uy -> Some NSHST
  | 0b0111uy -> Some NSH
  | 0b1001uy -> Some ISHLD
  | 0b1010uy -> Some ISHST
  | 0b1011uy -> Some ISH
  | 0b1101uy -> Some LD
  | 0b1110uy -> Some ST
  | 0b1111uy -> Some SY
  | _ -> None

let getExtend = function
  | 0b000u -> ExtUXTB
  | 0b001u -> ExtUXTH
  | 0b010u -> ExtUXTW
  | 0b011u -> ExtUXTX
  | 0b100u -> ExtSXTB
  | 0b101u -> ExtSXTH
  | 0b110u -> ExtSXTW
  | 0b111u -> ExtSXTX
  | _ -> failwith "Invalid extend"

let getPstate = function
  | 0b000101u -> SPSEL
  | 0b011110u -> DAIFSET
  | 0b011111u -> DAIFCLR
  | _ -> failwith "Pstate field is reserved"

let getPrefetchOperation = function
  | 0b00000uy -> PrfOp PLDL1KEEP
  | 0b00001uy -> PrfOp PLDL1STRM
  | 0b00010uy -> PrfOp PLDL2KEEP
  | 0b00011uy -> PrfOp PLDL2STRM
  | 0b00100uy -> PrfOp PLDL3KEEP
  | 0b00101uy -> PrfOp PLDL3STRM
  | 0b01000uy -> PrfOp PLIL1KEEP
  | 0b01001uy -> PrfOp PLIL1STRM
  | 0b01010uy -> PrfOp PLIL2KEEP
  | 0b01011uy -> PrfOp PLIL2STRM
  | 0b01100uy -> PrfOp PLIL3KEEP
  | 0b01101uy -> PrfOp PLIL3STRM
  | 0b10000uy -> PrfOp PSTL1KEEP
  | 0b10001uy -> PrfOp PSTL1STRM
  | 0b10010uy -> PrfOp PSTL2KEEP
  | 0b10011uy -> PrfOp PSTL2STRM
  | 0b10100uy -> PrfOp PSTL3KEEP
  | 0b10101uy -> PrfOp PSTL3STRM
  | rt -> Immediate (int64 rt)

/// Table C1-1 Condition codes.
let getCondition = function
  | 0x0uy -> EQ
  | 0x1uy -> NE
  | 0x2uy -> CS (* or HS *)
  | 0x3uy -> CC (* or LO *)
  | 0x4uy -> MI
  | 0x5uy -> PL
  | 0x6uy -> VS
  | 0x7uy -> VC
  | 0x8uy -> HI
  | 0x9uy -> LS
  | 0xauy -> GE
  | 0xbuy -> LT
  | 0xcuy -> GT
  | 0xduy -> LE
  | 0xeuy -> AL
  | 0xfuy -> NV
  | _ -> failwith "Invalid condition"

let getConditionOpcode = function
  | 0x0uy -> Opcode.BEQ
  | 0x1uy -> Opcode.BNE
  | 0x2uy -> Opcode.BCS (* or HS *)
  | 0x3uy -> Opcode.BCC (* or LO *)
  | 0x4uy -> Opcode.BMI
  | 0x5uy -> Opcode.BPL
  | 0x6uy -> Opcode.BVS
  | 0x7uy -> Opcode.BVC
  | 0x8uy -> Opcode.BHI
  | 0x9uy -> Opcode.BLS
  | 0xauy -> Opcode.BGE
  | 0xbuy -> Opcode.BLT
  | 0xcuy -> Opcode.BGT
  | 0xduy -> Opcode.BLE
  | 0xeuy -> Opcode.BAL
  | 0xfuy -> Opcode.BNV
  | _ -> failwith "Invalid condition"

/// Table C2-2 Floating-point constant values
let getFloatingPointConstantValues fimm =
  let isPositive = pickBit fimm 7u = 0u (* a *)
  match extract fimm 6u 0u with (* bcdefgh *)
  | 0b0000000u -> 2.0
  | 0b0000001u -> 2.125
  | 0b0000010u -> 2.25
  | 0b0000011u -> 2.375
  | 0b0000100u -> 2.5
  | 0b0000101u -> 2.625
  | 0b0000110u -> 2.75
  | 0b0000111u -> 2.875
  | 0b0001000u -> 3.0
  | 0b0001001u -> 3.125
  | 0b0001010u -> 3.25
  | 0b0001011u -> 3.375
  | 0b0001100u -> 3.5
  | 0b0001101u -> 3.625
  | 0b0001110u -> 3.75
  | 0b0001111u -> 3.875
  | 0b0010000u -> 4.0
  | 0b0010001u -> 4.25
  | 0b0010010u -> 4.5
  | 0b0010011u -> 4.75
  | 0b0010100u -> 5.0
  | 0b0010101u -> 5.25
  | 0b0010110u -> 5.5
  | 0b0010111u -> 5.75
  | 0b0011000u -> 6.0
  | 0b0011001u -> 6.25
  | 0b0011010u -> 6.5
  | 0b0011011u -> 6.75
  | 0b0011100u -> 7.0
  | 0b0011101u -> 7.25
  | 0b0011110u -> 7.5
  | 0b0011111u -> 7.75
  | 0b0100000u -> 8.0
  | 0b0100001u -> 8.5
  | 0b0100010u -> 9.0
  | 0b0100011u -> 9.5
  | 0b0100100u -> 10.0
  | 0b0100101u -> 10.5
  | 0b0100110u -> 11.0
  | 0b0100111u -> 11.5
  | 0b0101000u -> 12.0
  | 0b0101001u -> 12.5
  | 0b0101010u -> 13.0
  | 0b0101011u -> 13.5
  | 0b0101100u -> 14.0
  | 0b0101101u -> 14.5
  | 0b0101110u -> 15.0
  | 0b0101111u -> 15.5
  | 0b0110000u -> 16.0
  | 0b0110001u -> 17.0
  | 0b0110010u -> 18.0
  | 0b0110011u -> 19.0
  | 0b0110100u -> 20.0
  | 0b0110101u -> 21.0
  | 0b0110110u -> 22.0
  | 0b0110111u -> 23.0
  | 0b0111000u -> 24.0
  | 0b0111001u -> 25.0
  | 0b0111010u -> 26.0
  | 0b0111011u -> 27.0
  | 0b0111100u -> 28.0
  | 0b0111101u -> 29.0
  | 0b0111110u -> 30.0
  | 0b0111111u -> 31.0
  | 0b1000000u -> 0.125
  | 0b1000001u -> 0.1328125
  | 0b1000010u -> 0.140625
  | 0b1000011u -> 0.1484375
  | 0b1000100u -> 0.15625
  | 0b1000101u -> 0.1640625
  | 0b1000110u -> 0.171875
  | 0b1000111u -> 0.1796875
  | 0b1001000u -> 0.1875
  | 0b1001001u -> 0.1953125
  | 0b1001010u -> 0.203125
  | 0b1001011u -> 0.2109375
  | 0b1001100u -> 0.21875
  | 0b1001101u -> 0.2265625
  | 0b1001110u -> 0.234375
  | 0b1001111u -> 0.2421875
  | 0b1010000u -> 0.25
  | 0b1010001u -> 0.265625
  | 0b1010010u -> 0.28125
  | 0b1010011u -> 0.296875
  | 0b1010100u -> 0.3125
  | 0b1010101u -> 0.328125
  | 0b1010110u -> 0.34375
  | 0b1010111u -> 0.359375
  | 0b1011000u -> 0.375
  | 0b1011001u -> 0.390625
  | 0b1011010u -> 0.40625
  | 0b1011011u -> 0.421875
  | 0b1011100u -> 0.4375
  | 0b1011101u -> 0.453125
  | 0b1011110u -> 0.46875
  | 0b1011111u -> 0.484375
  | 0b1100000u -> 0.5
  | 0b1100001u -> 0.53125
  | 0b1100010u -> 0.5625
  | 0b1100011u -> 0.59375
  | 0b1100100u -> 0.625
  | 0b1100101u -> 0.65625
  | 0b1100110u -> 0.6875
  | 0b1100111u -> 0.71875
  | 0b1101000u -> 0.75
  | 0b1101001u -> 0.78125
  | 0b1101010u -> 0.8125
  | 0b1101011u -> 0.84375
  | 0b1101100u -> 0.875
  | 0b1101101u -> 0.90625
  | 0b1101110u -> 0.9375
  | 0b1101111u -> 0.96875
  | 0b1110000u -> 1.0
  | 0b1110001u -> 1.0625
  | 0b1110010u -> 1.125
  | 0b1110011u -> 1.1875
  | 0b1110100u -> 1.25
  | 0b1110101u -> 1.3125
  | 0b1110110u -> 1.375
  | 0b1110111u -> 1.4375
  | 0b1111000u -> 1.5
  | 0b1111001u -> 1.5625
  | 0b1111010u -> 1.625
  | 0b1111011u -> 1.6875
  | 0b1111100u -> 1.75
  | 0b1111101u -> 1.8125
  | 0b1111110u -> 1.875
  | 0b1111111u -> 1.9375
  | _ -> failwith "Invalid FP"
  |> fun fp -> if isPositive then fp else -fp

/// Operand size functions
let getOprSizeByMSB msb = if msb = 0u then 32<rt> else 64<rt>
let getOprSizeBySfN bin =
  match concat (pickBit bin 31u) (pickBit bin 22u) 1 with
  | 0b00u -> 32<rt>
  | 0b11u -> 64<rt>
  | _ -> raise InvalidOperandSizeException

(* SIMD&FP scalar register *)
let getSIMDFPscalReg oprSize value =
  SIMDOpr (SFReg (SIMDFPScalarReg (getSIMDFPRegister64 oprSize (byte value))))

(* SIMD&FP vector register *)
let getSIMDFPVecReg value t =
  SIMDOpr (SFReg (SIMDVecReg (getVRegister64 (byte value), t)))

let getSIMDFPRegWithIdx value t idx =
  SIMDOpr (SFReg (SIMDVecRegWithIdx (getVRegister64 (byte value), t, idx)))

(* SIMD vector register list *)
let getSIMDVecReg t rLst =
  let sr v = SIMDVecReg (v, t)
  match rLst with
  | [ vt ] -> OneReg (sr vt) |> SIMDOpr
  | [ vt; vt2 ] -> TwoRegs (sr vt, sr vt2) |> SIMDOpr
  | [ vt; vt2; vt3 ] -> ThreeRegs (sr vt, sr vt2, sr vt3) |> SIMDOpr
  | [ vt; vt2; vt3; vt4 ] -> FourRegs (sr vt, sr vt2, sr vt3, sr vt4) |> SIMDOpr
  | _ -> failwith "Invalid SIMD operand"

(* SIMD vector element list *)
let getSIMDVecRegWithIdx vec idx rLst =
  let srIdx v = SIMDVecRegWithIdx (v, vec, idx)
  match rLst with
  | [ vt ] -> OneReg (srIdx vt) |> SIMDOpr
  | [ vt; vt2 ] -> TwoRegs (srIdx vt, srIdx vt2) |> SIMDOpr
  | [ vt; vt2; vt3 ] -> ThreeRegs (srIdx vt, srIdx vt2, srIdx vt3) |> SIMDOpr
  | [ vt; vt2; vt3; vt4 ] ->
    FourRegs (srIdx vt, srIdx vt2, srIdx vt3, srIdx vt4) |> SIMDOpr
  | _ -> failwith "Invalid SIMD operand"

/////////////////////////////////////////////////////////////
/// Extract value (* FIXME: Deduplication *)
let valA bin = extract bin 14u 10u (* T2 *)
let valCrm bin = extract bin 11u 8u
let valCrn bin = extract bin 15u 12u
let valD bin = extract bin 4u 0u (* T *)
let valH bin = pickBit bin 11u
let valImm3 bin = extract bin 12u 10u
let valImm4 bin = extract bin 14u 11u
let valImm5 bin = extract bin 20u 16u (* M, S *)
let valImm12 bin = extract bin 21u 10u
let valImm16 bin = extract bin 20u 5u
let valImm19 bin = extract bin 23u 5u
let valImmb bin = extract bin 18u 16u (* Op1 *)
let valImmh bin = extract bin 22u 19u
let valImmr bin = extract bin 21u 16u
let valImms bin = extract bin 15u 10u (* Scale *)
let valL bin = pickBit bin 21u
let valM bin = extract bin 20u 16u (* Imm5, S *)
let valM1 bin = pickBit bin 20u
let valM2 bin = extract bin 19u 16u (* valM1:valM2 = valM *)
let valMSB bin = pickBit bin 31u
let valN bin = extract bin 9u 5u
let valOp1 bin = extract bin 18u 16u (* Immb *)
let valOp2 bin = extract bin 7u 5u
let valOption bin = extract bin 15u 13u
let valQ bin = pickBit bin 30u
let valS1 bin = extract bin 20u 16u (* Imm5, M *)
let valS2 bin = pickBit bin 12u
let valScale bin = extract bin 15u 10u (* Imms *)
let valShift bin = extract bin 23u 22u (* Size1 *)
let valSize1 bin = extract bin 23u 22u (* Shift *)
let valSize2 bin = extract bin 11u 10u
let valSz bin = pickBit bin 22u
let valT1 bin = extract bin 4u 0u (* D *)
let valT2 bin = extract bin 14u 10u (* A *)

/// Concat value
let conImm5Q bin = concat (valImm5 bin) (valQ bin) 1
let conImmhQ bin = concat (valImmh bin) (valQ bin) 1
let conImmsr bin = concat (valImms bin) (valImmr bin) 6
let conOp1Op2 bin = concat (valOp1 bin) (valOp2 bin) 3
let conSizeQ1 bin = concat (valSize1 bin) (valQ bin) 1
let conSizeQ2 bin = concat (valSize2 bin) (valQ bin) 1
let conSzL bin = concat (valSz bin) (valL bin) 1
let conSzQ bin = concat (valSz bin) (valQ bin) 1

/// Operand element type
(* Function to get register width *)
let getWidthByOption w x = function
  | 0b011u | 0b111u -> x
  | _ -> w
let getWidthByImm5 w x = function
  | i when i &&& 0b01111u = 0b01000u -> x
  | _ -> w

(* Genearl-purpose registers *)
let W value = getRegister64 32<rt> (byte value)
let X value = getRegister64 64<rt> (byte value)
let WS value = getRegister64orSP 32<rt> (byte value)
let XS value = getRegister64orSP 64<rt> (byte value)
let R1 bin = getWidthByOption W X (valOption bin)
let R2 bin = getWidthByImm5 W X (valImm5 bin)
(* SIMD Vector registers *)
let V value = getVRegister64 (byte value)
(* SIMD and floating-point scalar registers *)
let Q value = getSIMDFPscalReg 128 (byte value)
let D value = getSIMDFPscalReg 64 (byte value)
let S value = getSIMDFPscalReg 32 (byte value)
let H value = getSIMDFPscalReg 16 (byte value)
let VB value = getSIMDFPscalReg 8 (byte value)
(* <T> : Arrangement specifier *)
let Ts1 value = getSIMDVectorBySize1 value       (* size *)
let Ts2 value = getSIMDVectorBySize2 value       (* size *)
let Ts3 value = getSIMDVectorBySizeWithIdx value (* size *)
let Tsq1 value = getSIMDVector8B value           (* size:Q *)
let Tsq2 value = getSIMDVector4H value           (* size:Q *)
let Tsz1 value = getSIMDVectorBySz1 value        (* sz *)
let Tsz2 value = getSIMDVectorBySz2 value        (* sz *)
let Tsz3 value = getSIMDVectorBySz3 value        (* sz *)
let Tszq1 value = getSIMDVectorBySzQ2S value     (* sz:Q *)
let Tszq2 value = getSIMDVectorBySzQ4H value     (* sz:Q *)
let Tq1 value = getSIMDVectorByQ1 value          (* Q *)
let Tq2 value = getSIMDVectorByQ2 value          (* Q *)
let Tq3 value = getSIMDVectorByQ3 value          (* Q *)
let Ti5 value = getSIMDVectorByImm5 value        (* imm5 *)
let Ti5q value = getSIMDVectorByImm5Q value      (* imm5:Q *)
let Tih value = getSIMDVectorByImmh value        (* immh *)
let Tihq value = getSIMDVectorByImmhQ value      (* immh:Q *)

let chkReserved resLst v =
  if List.contains v resLst then failwith "Reserved" else ()

let chkRange max imm = if max < imm then failwith "Reserved" else imm

(* Load/store addressing modes (Register offset) *)
let extRegOffset option amount = ExtRegOffset (getExtend option, amount)
let getRegOffset s option amount =
  match option with
  | 0b011u -> if s = 0b0u then None
              else Some (ShiftOffset (SRTypeLSL, Imm amount))
  | _ -> Some (extRegOffset option (if s = 0b0u then None else Some amount))

let getWidthBySize1 = function
  | 0b00u -> H
  | 0b01u -> S
  | 0b10u -> D
  | _ -> raise InvalidOperandSizeException

let getWidthBySize2 = function
  | 0b00u -> VB
  | 0b01u -> H
  | 0b10u -> S
  | 0b11u -> D
  | _ -> raise InvalidOperandSizeException

let getWidthBySz1 vSz = if vSz = 0b0u then S else D
let getWidthBySz2 vSz = if vSz = 0b0u then failwith "Invalid width" else S

let getVectorWidthBySize1 = function
  | 0b00u -> 8<rt>   // B
  | 0b01u -> 16<rt>  // H
  | 0b10u -> 32<rt>  // S
  | 0b11u -> 64<rt>  // D
  | _ -> raise InvalidOperandSizeException

let getVectorWidthBySize2 = function
  | 0b00u -> 16<rt>  // H
  | 0b01u -> 32<rt>  // S
  | 0b10u -> 64<rt>  // D
  | 0b11u -> 128<rt> // Q
  | _ -> raise InvalidOperandSizeException

let getWidthByImmh1 = function
  | 0b0001u -> VB
  | imm when imm &&& 0b1110u = 0b0010u -> H
  | imm when imm &&& 0b1100u = 0b0100u -> S
  | imm when imm &&& 0b1000u = 0b1000u -> D
  | _ -> raise InvalidOperandSizeException

let getWidthByImmh2 = function
  | 0b0001u -> H
  | imm when imm &&& 0b1110u = 0b0010u -> S
  | imm when imm &&& 0b1100u = 0b0100u -> D
  | imm when imm &&& 0b1000u = 0b1000u -> Q
  | _ -> raise InvalidOperandSizeException

let getDestWidthByImm5 = function
  | i when i &&& 0b00001u = 0b00001u -> VB
  | i when i &&& 0b00011u = 0b00010u -> H
  | i when i &&& 0b00111u = 0b00100u -> S
  | i when i &&& 0b01111u = 0b01000u -> D
  | _ -> raise InvalidOperandSizeException

let getElemWidthByImm5 = function
  | i when i &&& 0b00001u = 0b00001u -> VecB
  | i when i &&& 0b00011u = 0b00010u -> VecH
  | i when i &&& 0b00111u = 0b00100u -> VecS
  | i when i &&& 0b01111u = 0b01000u -> VecD
  | _ -> raise InvalidOperandSizeException

/// Operand type
let VTs1 bin v = getSIMDFPVecReg (v bin) (Ts1 (valSize1 bin))
let VTs2 bin v = getSIMDFPVecReg (v bin) (Ts2 (valSize1 bin))
let VTsq1 bin v = getSIMDFPVecReg (v bin) (Tsq1 (conSizeQ1 bin))
let VTsq2 bin v = getSIMDFPVecReg (v bin) (Tsq2 (conSizeQ1 bin))
let VTsz1 bin v = getSIMDFPVecReg (v bin) (Tsz1 (valSz bin))
let VTsz3 bin v = getSIMDFPVecReg (v bin) (Tsz3 (valSz bin))
let VTszq1 bin v = getSIMDFPVecReg (v bin) (Tszq1 (conSzQ bin))
let VTszq2 bin v = getSIMDFPVecReg (v bin) (Tszq2 (conSzQ bin))
let VTq1 bin v = getSIMDFPVecReg (v bin) (Tq1 (valQ bin))
let VTq2 bin v = getSIMDFPVecReg (v bin) (Tq2 (valQ bin))
let VTq3 bin v = getSIMDFPVecReg (v bin) (Tq3 (valQ bin))
let VTi5q bin v = getSIMDFPVecReg (v bin) (Ti5q (conImm5Q bin))
let VTih bin v = getSIMDFPVecReg (v bin) (Tih (valImmh bin))
let VTihq bin v = getSIMDFPVecReg (v bin) (Tihq (conImmhQ bin))

let VdTs1 bin = VTs1 bin valD
let VdTsq1 bin = VTsq1 bin valD
let VdTsq2 bin = VTsq2 bin valD
let VdTsz1 bin = VTsz1 bin valD
let VdTszq1 bin = VTszq1 bin valD
let VdTszq2 bin = VTszq2 bin valD
let VdTq1 bin = VTq1 bin valD
let VdTq2 bin = VTq2 bin valD
let VdTq3 bin = VTq3 bin valD
let VdTih bin = VTih bin valD
let VdTihq bin = VTihq bin valD
let VdTi5q bin = VTi5q bin valD
let VnTs1 bin = VTs1 bin valN
let VnTs2 bin = VTs2 bin valN
let VnTsq1 bin = VTsq1 bin valN
let VnTsz1 bin = VTsz1 bin valN
let VnTsz3 bin = VTsz3 bin valN
let VnTszq1 bin = VTszq1 bin valN
let VnTszq2 bin = VTszq2 bin valN
let VnTq1 bin = VTq1 bin valN
let VnTih bin = VTih bin valN
let VnTihq bin = VTihq bin valN
let VmTs1 bin = VTs1 bin valM
let VmTsq1 bin = VTsq1 bin valM
let VmTszq1 bin = VTszq1 bin valM
let VmTq1 bin = VTq1 bin valM

(* <Vm>.<Ts>[<index>] *)
let Vm bin = getRmBySize (valM1 bin) (valM2 bin) (valSize1 bin)
let index1 bin =
  getIdxBySize (valL bin) (valH bin) (valM1 bin) (valSize1 bin) |> uint8
let index2 bin = getIdxBySz (valL bin) (valH bin) (valSz bin) |> uint8

let Vmtsidx1 bin =
  getSIMDFPRegWithIdx (Vm bin) (Ts3 (valSize1 bin)) (index1 bin)
let Vmtsidx2 bin =
  getSIMDFPRegWithIdx (valM bin) (Tsz2 (valSz bin)) (index2 bin)

let Vtsidx1 bin value =
  let idx = getIdxByImm5 (valImm5 bin) |> uint8
  getSIMDFPRegWithIdx (value bin) (Ti5 (valImm5 bin)) idx
let Vtsidx2 bin value =
  let idx = getIdxByImm5Imm4 (valImm4 bin) (valImm5 bin) |> uint8
  getSIMDFPRegWithIdx (value bin) (Ti5 (valImm5 bin)) idx

let Vntidx bin =
  let idx = getIdxByImm5 (valImm5 bin) |> uint8
  getSIMDFPRegWithIdx (valN bin) (getElemWidthByImm5 (valImm5 bin)) idx

let vd b i = getVRegister64 ((valD b + i) % 32u |> byte)
let vn b i = getVRegister64 ((valN b + i) % 32u |> byte)
let vt b i = getVRegister64 ((valT1 b + i) % 32u |> byte)
let V1t b v t = getSIMDVecReg t [ v b 0u ]
let V2t b v t = getSIMDVecReg t [ v b 0u; v b 1u ]
let V3t b v t = getSIMDVecReg t [ v b 0u; v b 1u; v b 2u ]
let V4t b v t = getSIMDVecReg t [ v b 0u; v b 1u; v b 2u; v b 3u ]

let Vd2D bin = getSIMDFPVecReg (valD bin) TwoD
let VdD1 bin = getSIMDFPRegWithIdx (valD bin) VecD 1uy
let VnD1 bin = getSIMDFPRegWithIdx (valN bin) VecD 1uy
let Vd16B bin = getSIMDFPVecReg (valD bin) SixteenB
let Vn16B bin = getSIMDFPVecReg (valN bin) SixteenB
let Vn116B bin = V1t bin vn SixteenB
let Vn216B bin = V2t bin vn SixteenB
let Vn316B bin = V3t bin vn SixteenB
let Vn416B bin = V4t bin vn SixteenB

let Vt1t b = V1t b vt (Tsq1 (conSizeQ2 b))
let Vt2t b = V2t b vt (Tsq1 (conSizeQ2 b))
let Vt3t b = V3t b vt (Tsq1 (conSizeQ2 b))
let Vt4t b = V4t b vt (Tsq1 (conSizeQ2 b))

let getIdxByVecSize bin = function
  | VecB -> concat (valQ bin) (extract bin 12u 10u) 3 (* Q:S:size *)
  | VecH -> concat (valQ bin) (extract bin 12u 11u) 2 (* Q:S:size<1> *)
  | VecS -> concat (valQ bin) (pickBit bin 12u) 1 (* Q:S *)
  | VecD -> valQ bin (* Q *)
  | _ -> failwith "Invalid bit width"
let getVRegsByNum bin n =  List.map (vt bin) [ 0u .. (n - 1u) ]
let Vtntidx b t n =
  getSIMDVecRegWithIdx t (getIdxByVecSize b t |> uint8) (getVRegsByNum b n)

let Bt bin = VB (valT1 bin)
let Da bin = D (valA bin)
let Dd bin = D (valD bin)
let Dm bin = D (valM bin)
let Dn bin = D (valN bin)
let Dt1 bin = D (valT1 bin)
let Dt2 bin = D (valT2 bin)
let Hd bin = H (valD bin)
let Hn bin = H (valN bin)
let Ht bin = H (valT1 bin)
let Qd bin = Q (valD bin)
let Qn bin = Q (valN bin)
let Qt1 bin = Q (valT1 bin)
let Qt2 bin = Q (valT2 bin)
let Sa bin = S (valA bin)
let Sd bin = S (valD bin)
let Sm bin = S (valM bin)
let Sn bin = S (valN bin)
let St1 bin = S (valT1 bin)
let St2 bin = S (valT2 bin)
let Rm bin = (R1 bin) (valM bin) |> OprRegister
let Rn bin = (R2 bin) (valN bin) |> OprRegister
let Wa bin = W (valA bin) |> OprRegister
let Wd bin = W (valD bin) |> OprRegister
let Wm bin = W (valM bin) |> OprRegister
let Wn bin = W (valN bin) |> OprRegister
let Ws bin = W (valS1 bin) |> OprRegister
let WSd bin = WS (valD bin) |> OprRegister
let WSn bin = WS (valN bin) |> OprRegister
let Wt1 bin = W (valT1 bin) |> OprRegister
let Wt2 bin = W (valT2 bin) |> OprRegister
let Xa bin = X (valA bin) |> OprRegister
let Xd bin = X (valD bin) |> OprRegister
let Xm bin = X (valM bin) |> OprRegister
let Xn bin = X (valN bin) |> OprRegister
let XSd bin = XS (valD bin) |> OprRegister
let XSn bin = XS (valN bin) |> OprRegister
let Xt1 bin = X (valT1 bin) |> OprRegister
let Xt2 bin = X (valT2 bin) |> OprRegister
let Vd1 bin = getWidthBySize1 (valSize1 bin) (valD bin)
let Vd2 bin = getWidthBySize2 (valSize1 bin) (valD bin)
let Vd3a bin = getWidthBySz1 (valSz bin) (valD bin)
let Vd3b bin = getWidthBySz2 (valSz bin) (valD bin)
let Vd4 bin = getDestWidthByImm5 (valImm5 bin) (valD bin)
let Vd5 bin = getWidthByImmh1 (valImmh bin) (valD bin)
let Vm2 bin = getWidthBySize2 (valSize1 bin) (valM bin)
let Vm3 bin = getWidthBySz1 (valSz bin) (valM bin)
let Vn1 bin = getWidthBySize1 (valSize1 bin) (valN bin)
let Vn2 bin = getWidthBySize2 (valSize1 bin) (valN bin)
let Vn3 bin = getWidthBySz1 (valSz bin) (valN bin)
let Vn5 bin = getWidthByImmh1 (valImmh bin) (valN bin)
let Vn6 bin = getWidthByImmh2 (valImmh bin) (valN bin)
let Vd4S bin = getSIMDFPVecReg (valD bin) FourS
let Vm4S bin = getSIMDFPVecReg (valM bin) FourS
let Vn4S bin = getSIMDFPVecReg (valN bin) FourS
let Cn bin = getCoprocCRegister (valCrn bin |> byte) |> OprRegister
let Cm bin = getCoprocCRegister (valCrm bin |> byte) |> OprRegister

(* Immedate *)
let toImm imm = imm |> int64 |> Immediate
let imm bin = valCrm bin |> toImm
let imm3 bin = valImm3 bin |> int64
let imm5 bin = valImm5 bin |> toImm
let imm6 bin = extract bin 15u 10u
let imm8 bin = concat (extract bin 18u 16u) (extract bin 9u 5u) 5 |> toImm
let imm12 bin = valImm12 bin |> toImm
let imm16 bin = valImm16 bin |> toImm
let imm19 bin = valImm19 bin
let immr bin max = extract bin 21u 16u |> chkRange max |> toImm
(* FIXME: the leftmost *)
let imms bin max = extract bin 15u 10u |> chkRange max |> toImm
let immNsr bin oprSize = (* FIXME: bitmask immediate *)
  decodeBitMasks (pickBit bin 22u) (valImms bin) (valImmr bin) true oprSize
  |> Immediate
let Imm64 bin =
  let extBitToBytes n = if n = 0uy then 0UL else 255UL
  intToBits (concat (extract bin 18u 16u) (extract bin 9u 5u) 5) 8
  |> List.rev |> List.toArray
  |> Array.foldi (fun acc i e -> ((extBitToBytes e) <<< (i * 8)) + acc) 0UL
  |> fst |> int64 |> Immediate
let pimm12 bin scale = valImm12 bin * scale
let simm7 bin scale =
  extract bin 21u 15u |> uint64 |> signExtend 7 64 <<< scale
let simm9 bin = extract bin 20u 12u |> uint64 |> signExtend 9 64
let getFPImm fimm = getFloatingPointConstantValues fimm |> FPImmediate
let FImm8 bin = (extract bin 20u 13u) |> getFPImm (* FMOV (scalar, immediate) *)
let fimm8 bin = (* FMOV (vector, immediate) *)
  concat (extract bin 18u 16u) (extract bin 9u 5u) 5 |> getFPImm
let P0 = FPImmediate 0.0
let lsb bin max = extract bin 15u 10u |> chkRange max |> uint8 |> LSB
let immQ bin n = if valQ bin = 0b0u then 8L * n else 16L * n
let getAmount = function
  | VecB -> 1u
  | VecH -> 2u
  | VecS -> 4u
  | VecD -> 8u
  | _ -> failwith "Invalid amount"
let iX t n = (getAmount t) * n |> int64
let iN bin n = n <<< (valSize2 bin |> int) |> int64
let index bin = getIdxByImm4 (valImm4 bin) (valQ bin, pickBit bin 14u) |> toImm
let op1 bin = valOp1 bin |> toImm
let op2 bin = valOp2 bin |> toImm

(* Shift amount *)
let Amt16Imm bin = if pickBit bin 13u = 0b0u then 0L else 8L
let Amt32Imm bin =
  match extract bin 14u 13u with
  | 0b00u -> 0L
  | 0b01u -> 8L
  | 0b10u -> 16L
  | 0b11u -> 24L
  | _ -> failwith "Invalid amount"
let Amt32Ones bin = if pickBit bin 12u = 0b0u then 8L else 16L
let LAmt bin amtFn =
  let amt = amtFn bin
  if amt = 0L then None
  else Some (Shift (SRTypeLSL, Imm amt)) (* LSL #<amount> *)
let MAmt bin = Shift (SRTypeMSL, Imm (Amt32Ones bin))
let RShfAmt bin = (* Right shift amount *)
  Immediate (getShiftAmountByImmh1 (valImmb bin) (valImmh bin) |> int64)
let LShfAmt bin = (* Left shift amount *)
  Immediate (getShiftAmountByImmh2 (valImmb bin) (valImmh bin) |> int64)

(* Load/Store Offset (Register offset/Extend register offset) *)
let regOffset bin amount = getRegOffset (valS2 bin) (valOption bin) amount
let WmXm bin = if pickBit bin 13u = 0b0u then W (valM bin) else X (valM bin)

(* Shift *)
let LShf1 bin = Shift (SRTypeLSL, Imm (8 <<< (valSize1 bin |> int) |> int64))
let LShf2 bin = (* FIXME: If shift amount is 0, not present. *)
  Shift (SRTypeLSL, Imm (getShiftAmountByShift (valShift bin) |> int64))
let LShf3 bin = (* FIXME: If shift amount is 0, not present. *)
  Shift (SRTypeLSL, Imm ((extract bin 22u 21u) <<< 4 |> int64))
let Shfamt bin = Shift (decodeRegShift (valShift bin), Imm (imm6 bin |> int64))

(* Extend *)
let Extamt bin = (* FIXME: refactoring *)
  let amt = imm3 bin
  let o = valOption bin
  let oprSize = getOprSizeByMSB (valMSB bin)
  let isRdOrRn11111 = valD bin = 0b11111u || valN bin = 0b11111u
  match oprSize with
  | 32<rt> when isRdOrRn11111 && (o = 0b010u) && amt = 0b000L -> None
  | 64<rt> when isRdOrRn11111 && (o = 0b011u) && amt = 0b000L -> None
  | 32<rt> when isRdOrRn11111 && (o = 0b010u) ->
    Some (ShiftOffset (SRTypeLSL, Imm amt))
  | 64<rt> when isRdOrRn11111 && (o = 0b011u) ->
    Some (ShiftOffset (SRTypeLSL, Imm amt))
  | _ -> Some (ExtRegOffset (getExtend o, Some amt))
  |> ExtReg

(* Fractional bits *)
let fbits1 bin = (* immh:immb *)
  Fbits (getShiftAmountByImmh1 (valImmb bin) (valImmh bin) |> uint8)
let fbits2 bin = Fbits (64u - (valScale bin) |> uint8) (* scale *)

(* Memory *)
let memXSn bin = memBaseImm (XS (valN bin), None)
let memXSnPimm bin s = memBaseImm (XS (valN bin), Some (pimm12 bin s |> int64))
let memXSnSimm7 bin s = memBaseImm (XS (valN bin), Some (simm7 bin s |> int64))
let memXSnSimm9 bin = memBaseImm (XS (valN bin), Some (simm9 bin |> int64))
let memPostXSnSimm b = memPostIdxImm (XS (valN b), Some (simm9 b |> int64))
let memPostImmXSnimm bin imm = memPostIdxImm (XS (valN bin), Some imm)
let memPostRegXSnxm bin = memPostIdxReg (XS (valN bin), X (valM bin), None)
let memPreXSnSimm bin = memPreIdxImm (XS (valN bin), Some (simm9 bin |> int64))
let memPostXSnImm b s = memPostIdxImm (XS (valN b), Some (simm7 b s |> int64))
let memPreXSnImm b s = memPreIdxImm (XS (valN b), Some (simm7 b s |> int64))
let memExtXSnRmAmt b amt = memBaseReg (XS (valN b), WmXm b, regOffset b amt)
let memShfXSnXmAmt b amt = memBaseReg (XS (valN b), X (valM b), regOffset b amt)
let lbImm19 bin =
  memLabel (concat (imm19 bin) 0b00u 2 |> uint64 |> signExtend 21 64 |> int64)
let label bin amount =
  let imm = concat (extract bin 23u 5u) (extract bin 30u 29u) 2
  let imm = signExtend (21 + amount) 64 ((uint64 imm) <<< amount)
  memLabel (int64 imm)

(* Etc *)
let cond bin = getCondition (extract bin 15u 12u |> byte) |> Cond
let nzcv bin = extract bin 3u 0u |> uint8 |> NZCV
let prfopImm5 bin = getPrefetchOperation (valT1 bin |> byte)
let getOptOrImm bin = function
  | Some option -> Option option
  | None -> Immediate (valCrm bin |> int64)
let pstatefield bin = getPstate (conOp1Op2 bin) |> Pstate
let optionOrimm bin = getOption64 (valCrm bin |> byte) |> getOptOrImm bin
let systemregOrctrl bin = getControlRegister (extract bin 20u 5u) |> OprRegister
let dcOp bin = getDCOpr (concat (extract bin 18u 16u) (extract bin 11u 5u) 7)
               |> DCOpr |> SysOpr

/// Reserved check function
let resNone _ = ()
(* size = 0b11 *)
let size11 bin = chkReserved [ 0b11u ] (valSize1 bin)
(* size = 0b00, 0b11 *)
let size0011 bin = chkReserved [ 0b00u; 0b11u ] (valSize1 bin)
(* size = 0b01, 0b10 *)
let size0110 bin = chkReserved [ 0b01u; 0b10u ] (valSize1 bin)
(* size = 0b01, 0b10, 0b11 *)
let size011011 bin = chkReserved [ 0b01u; 0b10u; 0b11u ] (valSize1 bin)
(* size = 0b0x, 0b10 *)
let size0x10 bin = chkReserved [ 0b00u; 0b01u; 0b10u ] (valSize1 bin)
(* size:Q = 0b110 *)
let sizeQ110 bin = chkReserved [ 0b110u ] (conSizeQ1 bin)
let sizeQ110b bin = chkReserved [ 0b110u ] (conSizeQ2 bin)
(* size:Q = 0b01x, size:Q = 0b1xx *)
let sizeQ01x1xx bin = chkReserved [ 0b010u .. 0b111u ] (conSizeQ1 bin)
(* size:Q = 0b11x *)
let sizeQ11x bin = chkReserved [ 0b110u; 0b111u ] (conSizeQ1 bin)
(* size:Q = 0b1xx *)
let sizeQ1xx bin = chkReserved [ 0b100u .. 0b111u ] (conSizeQ1 bin)
(* size:Q = 0b100, 0b11x *)
let sizeQ10011x bin = chkReserved [ 0b100u; 0b110u; 0b111u ] (conSizeQ1 bin)
(* sz = 0b0 *)
let sz0 bin = chkReserved [ 0b0u ] (valSz bin)
(* sz:Q = 0b10 *)
let szQ10 bin = chkReserved [ 0b10u ] (conSzQ bin)
(* sz:Q = 0b1x *)
let szQ1x bin = chkReserved [ 0b10u; 0b11u ] (conSzQ bin)
(* sz:Q = 0b0x *)
let szQ0x bin = chkReserved [ 0b00u; 0b01u ] (conSzQ bin)
(* sz:Q = 0bx0, 0b11 *)
let szQx011 bin = chkReserved [ 0b00u; 0b10u; 0b11u ] (conSzQ bin)
(* sz:L = 0b11 *)
let szL11 bin = chkReserved [ 0b11u ] (conSzL bin)
(* immh = 0b0000 *)
let immh0000 bin = chkReserved [ 0b0000u ] (valImmh bin)
(* immh = 0b00xx *)
let immh00xx bin = chkReserved [ 0b0000u .. 0b0011u ] (valImmh bin)
(* immh = 0b1xxx *)
let immh1xxx bin = chkReserved [ 0b1000u .. 0b1111u ] (valImmh bin)
(* immh = 0b0xxx *)
let immh0xxx bin = chkReserved [ 0b0000u .. 0b0111u ] (valImmh bin)
(* immh = 0b0000, 0b1xxx *)
let immh00001xxx bin =
  chkReserved (0b0000u :: [ 0b1000u .. 0b1111u ]) (valImmh bin)
(* immh = 0b0001, 0b001x *)
let immh2 bin = chkReserved [ 0b0001u; 0b0010u; 0b0011u ] (valImmh bin)
(* immh:Q = 0b0001x, 0b001xx, 0b1xxx0 *)
let immhQ1 bin = chkReserved ([ 0b00010u .. 0b00111u ] @
                              [ for i in 0u .. 7u do yield 16u + (i * 2u) ])
                              (conImmhQ bin)
let imm5xxx00 bin =
  chkReserved (List.map (fun e -> e <<< 2) [ 0b000u .. 0b111u ]) (valImm5 bin)
let imm5xx000 bin =
  chkReserved (List.map (fun e -> e <<< 3) [ 0b00u .. 0b11u ]) (valImm5 bin)
let imm5notx1000 bin =
  chkReserved (List.filter (fun e -> e <> 0b01000u && e <> 0b11000u)
                           [ 0b00000u .. 0b11111u ]) (valImm5 bin)

// vim: set tw=80 sts=2 sw=2:
