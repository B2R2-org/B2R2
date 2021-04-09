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

namespace B2R2.FrontEnd.BinLifter.ARM32

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.ARM32.ParseUtils
open B2R2.FrontEnd.BinLifter.ARM32.OperandHelper

type OprDesc =
  | OprNo = 0
  | OprBankregRn = 1
  | OprCoprocCRdMem = 2
  | OprCpOpc1CRdCRnCRmOpc2 = 3
  | OprCpOpc1RtCRnCRmOpc2 = 4
  | OprCpOpc1RtRt2CRm = 5
  | OprDd0Rt = 6
  | OprDd1Rt = 7
  | OprDd2Rt = 8
  | OprDd3Rt = 9
  | OprDd4Rt = 10
  | OprDd5Rt = 11
  | OprDd6Rt = 12
  | OprDd7Rt = 13
  | OprDdDm = 14
  | OprDdDmDn = 15
  | OprDdDmFbits = 16
  | OprDdDmImm = 17
  | OprDdDmImm0 = 18
  | OprDdDmImmLeft = 19
  | OprDdDmx = 20
  | OprDdDnDm = 21
  | OprDdDnDm0Rotate = 22
  | OprDdDnDmidx = 23
  | OprDdDnDmidxRotate = 24
  | OprDdDnDmImm = 25
  | OprDdDnDmRotate = 26
  | OprDdDnDmx = 27
  | OprDdImm = 28
  | OprDdImm0 = 29
  | OprDdLabel = 30
  | OprDdListDm = 31
  | OprDdmDdmFbits = 32
  | OprDdMem = 33
  | OprDdQm = 34
  | OprDdQmImm = 35
  | OprDdQnQm = 36
  | OprDdRt = 37
  | OprDdSm = 38
  | OprDdSnSm = 39
  | OprDdSnSmidx = 40
  | OprDdVImm = 41
  | OprDmRtRt2 = 42
  | OprEndian = 43
  | OprIflags = 44
  | OprIflagsMode = 45
  | OprImm1 = 46
  | OprImm16 = 47
  | OprImm24 = 48
  | OprImm4 = 49
  | OprLabel = 50
  | OprLabel12 = 51
  | OprLabelH = 52
  | OprListMem = 53
  | OprListMem1 = 54
  | OprListMem2 = 55
  | OprListMem3 = 56
  | OprListMem4 = 57
  | OprListMemA = 58
  | OprListMemB = 59
  | OprListMemC = 60
  | OprListMemD = 61
  | OprMemImm = 62
  | OprMemReg = 63
  | OprMode = 64
  | OprOption = 65
  | OprP14C5Label = 66
  | OprP14C5Mem = 67
  | OprP14C5Option = 68
  | OprQdDm = 69
  | OprQdDmImm = 70
  | OprQdDmImm16 = 71
  | OprQdDmImm32 = 72
  | OprQdDmImm8 = 73
  | OprQdDmx = 74
  | OprQdDnDm = 75
  | OprQdDnDmidx = 76
  | OprQdDnDmx = 77
  | OprQdImm = 78
  | OprQdQm = 79
  | OprQdQmFbits = 80
  | OprQdQmImm = 81
  | OprQdQmImm0 = 82
  | OprQdQmImmLeft = 83
  | OprQdQmQn = 84
  | OprQdQnDm = 85
  | OprQdQnDm0Rotate = 86
  | OprQdQnDmidx = 87
  | OprQdQnDmidxm = 88
  | OprQdQnDmidxRotate = 89
  | OprQdQnDmx = 90
  | OprQdQnQm = 91
  | OprQdQnQmImm = 92
  | OprQdQnQmRotate = 93
  | OprQdRt = 94
  | OprRdBankreg = 95
  | OprRdConst = 96
  | OprRdConstCF = 97
  | OprRdImm16 = 98
  | OprRdImmRn = 99
  | OprRdImmRnShf = 100
  | OprRdLabel = 101
  | OprRdlRdhRnRm = 102
  | OprRdLsbWidth = 103
  | OprRdRm = 104
  | OprRdRmImm = 105
  | OprRdRmRn = 106
  | OprRdRmROR = 107
  | OprRdRmRs = 108
  | OprRdRmShf = 109
  | OprRdRmShfRs = 110
  | OprRdRnConst = 111
  | OprRdRnConstCF = 112
  | OprRdRnLsbWidth = 113
  | OprRdRnLsbWidthM1 = 114
  | OprRdRnRm = 115
  | OprRdRnRmOpt = 116
  | OprRdRnRmRa = 117
  | OprRdRnRmROR = 118
  | OprRdRnRmShf = 119
  | OprRdRnRmShfRs = 120
  | OprRdRtMem = 121
  | OprRdRtMemImm = 122
  | OprRdRtRt2Mem = 123
  | OprRdSPConst = 124
  | OprRdSreg = 125
  | OprRegs = 126
  | OprRm = 127
  | OprRn = 128
  | OprRnConst = 129
  | OprRnConstCF = 130
  | OprRnDreglist = 131
  | OprRnRegs = 132
  | OprRnRegsCaret = 133
  | OprRnRmShf = 134
  | OprRnRmShfRs = 135
  | OprRnSreglist = 136
  | OprRtAMem = 137
  | OprRtDn0 = 138
  | OprRtDn1 = 139
  | OprRtDn2 = 140
  | OprRtDn3 = 141
  | OprRtDn4 = 142
  | OprRtDn5 = 143
  | OprRtDn6 = 144
  | OprRtDn7 = 145
  | OprRtLabel = 146
  | OprRtLabelHL = 147
  | OprRtMem = 148
  | OprRtMemImm = 149
  | OprRtMemImm0 = 150
  | OprRtMemImm12 = 151
  | OprRtMemImm12P = 152
  | OprRtMemImmP = 153
  | OprRtMemReg = 154
  | OprRtMemRegP = 155
  | OprRtMemShf = 156
  | OprRtMemShfP = 157
  | OprRtRt2Dm = 158
  | OprRtRt2Label = 159
  | OprRtRt2Mem = 160
  | OprRtRt2Mem2 = 161
  | OprRtRt2MemImm = 162
  | OprRtRt2MemReg = 163
  | OprRtRt2SmSm1 = 164
  | OprRtSn = 165
  | OprRtSreg = 166
  | OprSdDm = 167
  | OprSdImm0 = 168
  | OprSdLabel = 169
  | OprSdMem = 170
  | OprSdmSdmFbits = 171
  | OprSdSm = 172
  | OprSdSnSm = 173
  | OprSdVImm = 174
  | OprSingleRegs = 175
  | OprSmSm1RtRt2 = 176
  | OprSnRt = 177
  | OprSPMode = 178
  | OprSregImm = 179
  | OprSregRn = 180
  | OprSregRt = 181

type OD = OprDesc

module OperandParsingHelper =

  /// shared/functions/common/Replicate on page J1-7848.
  let replicate value bits oprSize =
    let rec loop acc shift =
      if shift >= RegType.toBitWidth oprSize then acc
      else loop (acc ||| (value <<< shift)) (shift + bits)
    loop value bits

  /// shared/functions/vector/AdvSIMDExpandImm on page J1-7926.
  let advSIMDExpandImm bin =
    let cmode = extract bin 11 8
    let cmode0 = pickBit cmode 0 (* cmode<0> *)
    let op = pickBit bin 5
    let imm8 =
      (pickBit bin 24 <<< 7) + (extract bin 18 16 <<< 4) + (extract bin 3 0)
    match extract cmode 3 1 (* cmode<3:1> *) with
    | 0b000u -> replicate (imm8 |> int64) (* Zeros(24):imm8 *) 32 64<rt>
    | 0b001u ->
      replicate (imm8 <<< 8 |> int64) 32 64<rt> (* Zeros(16):imm8:Zeros(8) *)
    | 0b010u ->
      replicate (imm8 <<< 16 |> int64) 32 64<rt> (* Zeros(8):imm8:Zeros(16) *)
    | 0b011u -> replicate (imm8 <<< 24 |> int64) 32 64<rt> (* imm8:Zeros(24) *)
    | 0b100u -> replicate (imm8 |> int64) 16 64<rt> (* Zeros(8):imm8 *)
    | 0b101u -> replicate (imm8 <<< 8 |> int64) 16 64<rt> (* imm8:Zeros(8) *)
    | 0b110u ->
      let imm =
        if cmode0 = 0u && op = 0u
        then (imm8 <<< 8 |> int64) ||| 0xFL (* Zeros(16):imm8:Ones(8) *)
        else (imm8 <<< 16 |> int64) ||| 0xFFL (* Zeros(8):imm8:Ones(16) *)
      replicate (imm |> int64) 32 64<rt>
    | 0b111u ->
      if cmode0 = 0u && op = 0u then replicate (imm8 |> int64) 8 64<rt>
      elif cmode0 = 0u && op = 1u then
        (* imm8a = Replicate(imm8<7>, 8); imm8b = Replicate(imm8<6>, 8)
           imm8c = Replicate(imm8<5>, 8); imm8d = Replicate(imm8<4>, 8)
           imm8e = Replicate(imm8<3>, 8); imm8f = Replicate(imm8<2>, 8)
           imm8g = Replicate(imm8<1>, 8); imm8h = Replicate(imm8<0>, 8)
           imm64 = imm8a:imm8b:imm8c:imm8d:imm8e:imm8f:imm8g:imm8h *)
        (replicate (pickBit imm8 7 |> int64) 1 8<rt>) <<< 56 |||
        (replicate (pickBit imm8 6 |> int64) 1 8<rt>) <<< 48 |||
        (replicate (pickBit imm8 5 |> int64) 1 8<rt>) <<< 40 |||
        (replicate (pickBit imm8 4 |> int64) 1 8<rt>) <<< 32 |||
        (replicate (pickBit imm8 3 |> int64) 1 8<rt>) <<< 24 |||
        (replicate (pickBit imm8 2 |> int64) 1 8<rt>) <<< 16 |||
        (replicate (pickBit imm8 1 |> int64) 1 8<rt>) <<< 8 |||
        (replicate (pickBit imm8 0 |> int64) 1 8<rt>)
      elif cmode0 = 1u && op = 0u then
        (* imm32 = imm8<7>:NOT(imm8<6>):Replicate(imm8<6>,5):imm8<5:0>:Zeros(19)
           imm64 = Replicate(imm32, 2) *)
        let imm32 =
          ((pickBit imm8 7 |> int64) <<< 12 |||
           (~~~ (pickBit imm8 6) |> int64) <<< 11 |||
           (replicate (pickBit imm8 6 |> int64) 1 5<rt>) <<< 6 |||
           (extract imm8 5 0 |> int64)) <<< 19
        replicate imm32 32 64<rt>
      else (* cmode0 = 1u && op = 1u *)
        (((pickBit imm8 7 |> int64) <<< 15) |||
         ((~~~ (pickBit imm8 6) |> int64) <<< 14) |||
         ((replicate (pickBit imm8 6 |> int64) 1 8<rt>) <<< 6) |||
         (extract imm8 5 0 |> int64)) <<< 48
    | _ -> raise ParsingFailureException

  /// shared/functions/float/vfpexpandimm/VFPExpandImm on page J1-7900.
  let vfpExpandImm bin imm8 =
    let size = extract bin 9 8 (* size *)
    let E =
      match size (* N *) with
      | 0b01u -> 5
      | 0b10u -> 8
      | 0b11u -> 11
      | _ (* 00 *) -> raise UndefinedException
    let F = (8 <<< (int size)) - E - 1
    let sign = pickBit imm8 7 |> int64
    let exp =
      let n = RegType.fromBitWidth (E - 3)
      ((~~~ (pickBit imm8 6) &&& 0b1u) |> int64 <<< ((E - 3) + 2)) +
      ((replicate (pickBit imm8 6 |> int64) 1 n) <<< 2) +
      ((extract imm8 5 4) |> int64)
    let frac = (extract imm8 3 0) <<< (F - 4) |> int64
    (sign <<< (E + F)) + (exp <<< F) + frac

  /// aarch32/functions/common/A32ExpandImm_C on page J1-7766.
  /// Modified immediate constants in A32 instructions on page F2-4136.
  let expandImmediate bin =
    let rotation = (extract bin 11 8 |> int32) * 2
    let value = extract bin 7 0
    if rotation = 0 then value
    else (value <<< (32 - rotation)) ||| (value >>> rotation)

  /// shared/functions/common/SignExtend on page J1-7849.
  let signExtend bits =
    bits |> uint64 |> signExtend 26 32 |> System.Convert.ToInt64 |> memLabel

  /// shared/functions/common/BitCount on page J1-7845.
  let bitCount bin =
    let regList = extract bin 15 0
    let rec loop cnt idx =
      if idx > 15 then cnt
      elif ((regList >>> idx) &&& 0b1u) = 1u then loop (cnt + 1) (idx + 1)
      else loop cnt (idx + 1)
    loop 0 0

  /// Data Type parsing
  (* S8  when U = 0, size = 00
     S16 when U = 0, size = 01
     S32 when U = 0, size = 10
     U8  when U = 1, size = 00
     U16 when U = 1, size = 01
     U32 when U = 1, size = 10 *)
  let getDT bin =
    match concat (pickBit bin 24) (extract bin 21 20) 2 (* U:size *) with
    | 0b000u -> SIMDTypS8
    | 0b001u -> SIMDTypS16
    | 0b010u -> SIMDTypS32
    | 0b100u -> SIMDTypU8
    | 0b101u -> SIMDTypU16
    | 0b110u -> SIMDTypU32
    | _ -> raise ParsingFailureException

  (* S16 when size = 01
     S32 when size = 10 *)
  let getDTSign = function (* [21:20] *)
    | 0b001u -> SIMDTypS16
    | 0b010u -> SIMDTypS32
    | _ -> raise UndefinedException

  let getDTInt = function (* [21:20] *)
    | 0b00u -> SIMDTypI16
    | 0b01u -> SIMDTypI32
    | 0b10u -> SIMDTypI64
    | _ -> raise ParsingFailureException

  let getDT64 = function (* [7:6] *)
    | 0b00u -> SIMDTyp8
    | 0b01u -> SIMDTyp16
    | 0b10u -> SIMDTyp32
    | _ (* 11 *) -> SIMDTyp64 (* or reserved *)

  let getDT32 = function (* [7:6] *)
    | 0b00u -> SIMDTyp8
    | 0b01u -> SIMDTyp16
    | _ (* 10 or 11 *) -> SIMDTyp32

  (* I16 when F = 0, size = 01
     I32 when F = 0, size = 10 *)
  let getDTF0 = function (* [21:20] *)
    | 0b01u -> SIMDTypI16
    | 0b10u -> SIMDTypI32
    | _ (* 00 or 11 *) -> raise UndefinedException

  (* F16 when F = 1, size = 01
     F32 when F = 1, size = 10 *)
  let getDTF1 = function (* [21:20] *)
    | 0b01u -> SIMDTypF16
    | 0b10u -> SIMDTypF32
    | _ (* 00 or 11 *) -> raise UndefinedException

  let getDTImm4 = function (* [19:16] *)
    | 0b0001u | 0b0011u | 0b0101u | 0b0111u | 0b1001u | 0b1011u | 0b1101u
    | 0b1111u (* xxx1 *) -> SIMDTyp8
    | 0b0010u | 0b0110u | 0b1010u | 0b1110u (* xx10 *) -> SIMDTyp16
    | 0b0100u | 0b1100u (* x100 *) -> SIMDTyp32
    | _ (* x000 *) -> raise UndefinedException

  (* 8 when  L = 0, imm6<5:3> = 001
     16 when L = 0, imm6<5:3> = 01x
     32 when L = 0, imm6<5:3> = 1xx
     64 when L = 1, imm6<5:3> = xxx *)
  let getDTLImm bin =
    let isSign = pickBit bin 24 (* U *) = 0u
    match concat (pickBit bin 7) (extract bin 21 19) 3 (* L:imm6<5:3> *) with
    | 0b0000u -> raise ParsingFailureException
    | 0b0001u -> if isSign then SIMDTypS8 else SIMDTypU16
    | 0b0010u | 0b0011u -> if isSign then SIMDTypS16 else SIMDTypU16
    | 0b0100u | 0b0101u | 0b0110u | 0b0111u ->
      if isSign then SIMDTypS32 else SIMDTypU32
    | _ (* 1xxx *) -> if isSign then SIMDTypS64 else SIMDTypU64
    |> oneDt

  (* S8 when  U = 0, imm3H = 001
     S16 when U = 0, imm3H = 010
     S32 when U = 0, imm3H = 100
     U8 when  U = 1, imm3H = 001
     U16 when U = 1, imm3H = 010
     U32 when U = 1, imm3H = 100 *)
  let getDTUImm3H bin =
    match concat (pickBit bin 24) (extract bin 21 19) 3 (* U:imm3H *) with
    | 0b0001u -> SIMDTypS8
    | 0b0010u -> SIMDTypS16
    | 0b0100u -> SIMDTypS32
    | 0b1001u -> SIMDTypU8
    | 0b1010u -> SIMDTypU16
    | 0b1100u -> SIMDTypU32
    | _ -> raise ParsingFailureException
    |> oneDt

  let getDTUSize bin =
    match concat (pickBit bin 24) (extract bin 21 20) 2 (* U:size *) with
    | 0b000u -> SIMDTypS8
    | 0b001u -> SIMDTypS16
    | 0b010u -> SIMDTypS32
    | 0b100u -> SIMDTypU8
    | 0b101u -> SIMDTypU16
    | 0b110u -> SIMDTypU32
    | _ (* x11 *) -> raise UndefinedException
    |> oneDt

  let getDTUSzQ bin =
    match concat (pickBit bin 24) (extract bin 21 20) 2 (* U:size *) with
    | 0b000u -> SIMDTypS8
    | 0b001u -> SIMDTypS16
    | 0b010u -> SIMDTypS32
    | 0b011u -> SIMDTypS64
    | 0b100u -> SIMDTypU8
    | 0b101u -> SIMDTypU16
    | 0b110u -> SIMDTypU32
    | _ (* 111 *) -> SIMDTypU64
    |> oneDt

  let getDTImm6Word bin =
    let isSign = pickBit bin 24 (* U *) = 0u
    match extract bin 21 19 (* imm6<5:3> *) with
    | 0b000u -> raise ParsingFailureException
    | 0b001u -> if isSign then SIMDTypS16 else SIMDTypU16
    | 0b010u | 0b011u (* 01x *) -> if isSign then SIMDTypS32 else SIMDTypU32
    | _ (* 1xx *) -> if isSign then SIMDTypS64 else SIMDTypU64
    |> oneDt

  let getDTImm6Byte bin =
    let isSign = pickBit bin 24 (* U *) = 0u
    match extract bin 21 19 (* imm6<5:3> *) with
    | 0b000u -> raise ParsingFailureException
    | 0b001u -> if isSign then SIMDTypS8 else SIMDTypU8
    | 0b010u | 0b011u (* 01x *) -> if isSign then SIMDTypS16 else SIMDTypU16
    | _ (* 1xx *) -> if isSign then SIMDTypS32 else SIMDTypU32
    |> oneDt

  let getDTImm6Int bin =
    match extract bin 21 19 (* imm6<5:3> *) with
    | 0b000u -> raise ParsingFailureException
    | 0b001u -> SIMDTypI16
    | 0b010u | 0b011u (* 01x *) -> SIMDTypI32
    | _ (* 1xx *) -> SIMDTypI64
    |> oneDt

  let getDTImm6 bin =
    match concat (pickBit bin 7) (extract bin 21 19) 3 (* L:imm6<5:3> *) with
    | 0b0000u -> raise ParsingFailureException
    | 0b0001u -> SIMDTyp8
    | 0b0010u | 0b0011u (* 001x *) -> SIMDTyp16
    | 0b0100u | 0b0101u | 0b0110u | 0b0111u (* 01xx *) -> SIMDTyp32
    | _ (* 1xxx *) -> SIMDTyp64
    |> oneDt

  let getDTImm6Sign bin =
    match extract bin 21 19 (* imm6<5:3> *) with
    | 0b000u -> raise ParsingFailureException
    | 0b001u -> SIMDTypS16
    | 0b010u | 0b011u (* 01x *) -> SIMDTypS32
    | _ (* 1xx *) -> SIMDTypS64
    |> oneDt

  let getBankedReg r sysM =
    match concat r sysM 5 with
    | 0b000000u -> R.R8usr
    | 0b000001u -> R.R9usr
    | 0b000010u -> R.R10usr
    | 0b000011u -> R.R11usr
    | 0b000100u -> R.R12usr
    | 0b000101u -> R.SPusr
    | 0b000110u -> R.LRusr
    | 0b001000u -> R.R8fiq
    | 0b001001u -> R.R9fiq
    | 0b001010u -> R.R10fiq
    | 0b001011u -> R.R11fiq
    | 0b001100u -> R.R12fiq
    | 0b001101u -> R.SPfiq
    | 0b001110u -> R.LRfiq
    | 0b010000u -> R.LRirq
    | 0b010001u -> R.SPirq
    | 0b010010u -> R.LRsvc
    | 0b010011u -> R.SPsvc
    | 0b010100u -> R.LRabt
    | 0b010101u -> R.SPabt
    | 0b010110u -> R.LRund
    | 0b010111u -> R.SPund
    | 0b011100u -> R.LRmon
    | 0b011101u -> R.SPmon
    | 0b011110u -> R.ELRhyp
    | 0b011111u -> R.SPhyp
    | 0b101110u -> R.SPSRfiq
    | 0b110000u -> R.SPSRirq
    | 0b110010u -> R.SPSRsvc
    | 0b110100u -> R.SPSRabt
    | 0b110110u -> R.SPSRund
    | 0b111100u -> R.SPSRmon
    | 0b111110u -> R.SPSRhyp
    | _ -> raise UnpredictableException

  let getAPSR = function
    | 0b00u -> struct (R.APSR, None)
    | 0b01u -> struct (R.APSR, Some PSRg)
    | 0b10u -> struct (R.APSR, Some PSRnzcvq)
    | _ (* 11 *) -> struct (R.APSR, Some PSRnzcvqg)

  let getCPSR = function
    | 0b0000u -> struct (R.CPSR, None)
    | 0b0001u -> struct (R.CPSR, Some PSRc)
    | 0b0010u -> struct (R.CPSR, Some PSRx)
    | 0b0011u -> struct (R.CPSR, Some PSRxc)
    | 0b0100u -> struct (R.CPSR, Some PSRs)
    | 0b0101u -> struct (R.CPSR, Some PSRsc)
    | 0b0110u -> struct (R.CPSR, Some PSRsx)
    | 0b0111u -> struct (R.CPSR, Some PSRsxc)
    | 0b1000u -> struct (R.CPSR, Some PSRf)
    | 0b1001u -> struct (R.CPSR, Some PSRfc)
    | 0b1010u -> struct (R.CPSR, Some PSRfx)
    | 0b1011u -> struct (R.CPSR, Some PSRfxc)
    | 0b1100u -> struct (R.CPSR, Some PSRfs)
    | 0b1101u -> struct (R.CPSR, Some PSRfsc)
    | 0b1110u -> struct (R.CPSR, Some PSRfsx)
    | _ (* 1111 *) -> struct (R.CPSR, Some PSRfsxc)

  let getSPSR = function
    | 0b0000u -> struct (R.SPSR, None)
    | 0b0001u -> struct (R.SPSR, Some PSRc)
    | 0b0010u -> struct (R.SPSR, Some PSRx)
    | 0b0011u -> struct (R.SPSR, Some PSRxc)
    | 0b0100u -> struct (R.SPSR, Some PSRs)
    | 0b0101u -> struct (R.SPSR, Some PSRsc)
    | 0b0110u -> struct (R.SPSR, Some PSRsx)
    | 0b0111u -> struct (R.SPSR, Some PSRsxc)
    | 0b1000u -> struct (R.SPSR, Some PSRf)
    | 0b1001u -> struct (R.SPSR, Some PSRfc)
    | 0b1010u -> struct (R.SPSR, Some PSRfx)
    | 0b1011u -> struct (R.SPSR, Some PSRfxc)
    | 0b1100u -> struct (R.SPSR, Some PSRfs)
    | 0b1101u -> struct (R.SPSR, Some PSRfsc)
    | 0b1110u -> struct (R.SPSR, Some PSRfsx)
    | _ (* 1111 *) -> struct (R.SPSR, Some PSRfsxc)

  let getIflag = function
    | 0b100u -> A
    | 0b010u -> I
    | 0b001u -> F
    | 0b110u -> AI
    | 0b101u -> AF
    | 0b011u -> IF
    | 0b111u -> AIF
    | _ (* 000 *) -> raise ParsingFailureException

  /// Operand function
  let getRegister n: Register = n |> int |> LanguagePrimitives.EnumOfValue

  ///let parseCond n: Condition = n |> LanguagePrimitives.EnumOfValue

  let getVecSReg n: Register = n + 0x100u |> int |> LanguagePrimitives.EnumOfValue

  let getVecDReg n: Register = n + 0x200u |> int |> LanguagePrimitives.EnumOfValue

  let getVecQReg n: Register =
    (n >>> 1) + 0x300u |> int |> LanguagePrimitives.EnumOfValue

  let getCoprocCReg n: Register =
    n + 0x400u |> int |> LanguagePrimitives.EnumOfValue

  let getCoprocDReg n: Register =
    n + 0x500u |> int |> LanguagePrimitives.EnumOfValue

  let getOption n: Option = n |> int |> LanguagePrimitives.EnumOfValue

  let getDRegList fReg rNum = (* fReg: First Register, rNum: Number of regs *)
    List.map (fun r -> r |> getVecDReg) [ fReg .. fReg + rNum - 1u ] |> OprRegList

  let getSRegList fReg rNum =
    List.map (fun r -> r |> getVecSReg) [ fReg .. fReg + rNum - 1u ] |> OprRegList

  let toMemAlign rn align = function
    | R.PC -> memOffsetAlign (rn, align, None)
    | R.SP -> memPreIdxAlign (rn, align, None)
    | rm -> memPostIdxAlign (rn, align, Some rm)

  let expandImm bin = expandImmediate bin |> int64 |> OprImm

  let expandImmCF bin =
    let imm32 = expandImmediate bin
    if extract bin 11 8 = 0u then struct (imm32 |> int64 |> OprImm, None)
    else struct (imm32 |> int64 |> OprImm, Some (pickBit imm32 31 = 1u))

  (* (P == '0') || (W == '1') *)
  let wback bin = (pickBit bin 24 = 0b0u || pickBit bin 21 = 0b1u)

  (* (W == '1') *)
  let wbackW bin = pickBit bin 21 = 0b1u

  (* (m != 15) *)
  let wbackM bin = extract bin 3 0 <> 15u

open OperandParsingHelper

type OprInfo (oprs, wback, cflags) =
  member __.Operands with get (): Operands = oprs
  member __.WBack with get (): bool = wback
  member __.CFlags with get (): bool option = cflags

type [<AbstractClass>] OperandParser () =
  abstract member Render: uint32 -> OprInfo

and ParsingHelper (arch, mode, bin, rd, addr, oprs, len, cond) =
  let mutable arch: Arch = arch
  let mutable mode: ArchOperationMode = mode
  let mutable bin: uint32 = bin
  let mutable r: IBinReader = rd
  let mutable addr: Addr = addr
  let mutable len: uint32 = len
  let mutable cond: Condition = cond
  let mutable isARMv7: bool = false
  new (oparsers) =
    ParsingHelper (Arch.AARCH32, ArchOperationMode.ARMMode, 0u,
                   BinReader.binReaderLE, 0UL, oparsers, 0u,
                   Condition.UN)
  member __.Arch with get () = arch and set (a) = arch <- a
  member __.Mode with get () = mode and set (m) = mode <- m
  member __.Bin with get () = bin and set (b) = bin <- b
  member __.BinReader with get () = r and set(r') = r <- r'
  member __.InsAddr with get () = addr and set(a) = addr <- a
  member __.OprParsers with get (): OperandParser [] = oprs
  member __.Len with get () = len and set (l) = len <- l
  member __.Cond with get () = cond and set (c) = cond <- c
  member __.IsARMv7 with get () = isARMv7 and set (ia) = isARMv7 <- ia

type internal OprNo () =
  inherit OperandParser ()
  override __.Render _ =
    ///NoOperand
    OprInfo (NoOperand, false, None)

(* <Rn>{!} *)
type internal OprRn () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister |> OprReg
    OprInfo (OneOperand rn, wbackW bin, None)
    ///OneOperand rn

(* <Rm> *)
type internal OprRm () =
  inherit OperandParser ()
  override __.Render bin =
    let rm = extract bin 3 0 |> getRegister |> OprReg
    OprInfo (OneOperand rm, false, None)
    ///OneOperand rm

(* [<Rn> {, #{+/-}<imm>}] *)
type internal OprMemImm () =
  inherit OperandParser ()
  override __.Render bin =
    let mem =
      let imm12 = extract bin 11 0 |> int64
      let rn = extract bin 19 16 |> getRegister
      let sign = pickBit bin 23 |> getSign |> Some
      match concat (pickBit bin 24) (pickBit bin 21) 1 with
      | 0b10u -> memOffsetImm (rn, sign, Some imm12)
      | 0b11u -> memPreIdxImm  (rn, sign, Some imm12)
      | _ (* 0b0xu *) -> memPostIdxImm (rn, sign, Some imm12)
    OprInfo (OneOperand mem, false, None)
    ///OneOperand mem

(* [<Rn>, {+/-}<Rm> , RRX] *)
(* [<Rn>, {+/-}<Rm> {, <shift> #<amount>}] *)
type internal OprMemReg () =
  inherit OperandParser ()
  override __.Render bin =
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let rm = extract bin 3 0 |> getRegister
      let struct (shift, imm) =
        decodeImmShift (extract bin 6 5) (extract bin 11 7)
      let shiftOffset = Some (shift, Imm imm)
      let sign = pickBit bin 23 |> getSign |> Some
      memOffsetReg (rn, sign, rm, shiftOffset)
    OprInfo (OneOperand mem, false, None)
    ///OneOperand mem

(* {#}<imm> *)
type internal OprImm16 () =
  inherit OperandParser ()
  override __.Render bin =
    let imm = concat (extract bin 19 8) (extract bin 3 0) 4 |> int64 |> OprImm
    OprInfo (OneOperand imm, false, None)
    ///OneOperand imm

(* {#}<imm> *)
type internal OprImm24 () =
  inherit OperandParser ()
  override __.Render bin =
    OprInfo (extract bin 23 0 |> int64 |> OprImm |> OneOperand, false, None)
    ///extract bin 23 0 |> int64 |> OprImm |> OneOperand

(* {#}<imm4> *)
type internal OprImm4 () =
  inherit OperandParser ()
  override __.Render bin =
    OprInfo (extract bin 3 0 |> int64 |> OprImm |> OneOperand, false, None)
    ///extract bin 3 0 |> int64 |> OprImm |> OneOperand

(* #<imm> *)
type internal OprImm1 () =
  inherit OperandParser ()
  override __.Render bin =
    OprInfo (pickBit bin 9 |> int64 |> OprImm |> OneOperand, false, None)
    ///pickBit bin 9 |> int64 |> OprImm |> OneOperand

(* [<Rn> {, #{+/-}<imm>}]
   <label> Normal form
   [PC, #{+/-}<imm>] Alternative form *)
type internal OprLabel12 () =
  inherit OperandParser ()
  override __.Render bin =
    let imm12 = extract bin 11 0 |> int64
    let label =
      if pickBit bin 23 = 1u then memLabel imm12 else memLabel (imm12 * -1L)
    OprInfo (OneOperand label, false, None)
    ///OneOperand label

(* <label> *)
type internal OprLabel () =
  inherit OperandParser ()
  override __.Render bin =
    let label = extract bin 23 0 <<< 2 |> signExtend
    OprInfo (OneOperand label, false, None)
    ///OneOperand label

(* <label> *)
type internal OprLabelH () =
  inherit OperandParser ()
  override __.Render bin =
    let label =
      (concat (extract bin 23 0) (pickBit bin 24) 1) <<< 1 |> signExtend
    OprInfo (OneOperand label, false, None)
    ///OneOperand label

(* {<option>} *)
type internal OprOpt () =
  inherit OperandParser ()
  override __.Render bin =
    let option = extract bin 3 0 |> getOption |> OprOption
    OprInfo (OneOperand option, false, None)
    ///OneOperand option

(* <endian_specifier> *)
type internal OprEnd () =
  inherit OperandParser ()
  override __.Render bin =
    let endian = pickBit bin 9 |> byte |> getEndian |> OprEndian
    OprInfo (OneOperand endian, false, None)
    ///OneOperand endian

(* <registers> *)
type internal OprRegs () =
  inherit OperandParser ()
  override __.Render bin =
    let regs = extract bin 15 0 |> getRegList |> OprRegList
    OprInfo (OneOperand regs, false, None)
    ///OneOperand regs

(* <single_register_list> *)
type internal OprSingleRegs () =
  inherit OperandParser ()
  override __.Render bin =
    let regs = OprRegList [ extract bin 15 12 |> getRegister ]
    OprInfo (OneOperand regs, wback bin, None)
    ///OneOperand regs

(* #<mode> *)
type internal OprMode () =
  inherit OperandParser ()
  override __.Render bin =
    OprInfo (OneOperand (extract bin 4 0 |> int64 |> OprImm), false, None)
    ///OneOperand (extract bin 4 0 |> int64 |> OprImm)

(* <iflags> *)
type internal OprIflags () =
  inherit OperandParser ()
  override __.Render bin =
    OprInfo (OneOperand (OprIflag (getIflag (extract bin 8 6))), false, None)
    ///OneOperand (OprIflag (getIflag (extract bin 8 6)))

(* <Rd>, <Rm> *)
type internal OprRdRm () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    OprInfo (TwoOperands (rd, rm), false, None)
    ///TwoOperands (rd, rm)

(* <Sd>, <Sm> *)
type internal OprSdSm () =
  inherit OperandParser ()
  override __.Render bin =
    let sd = (* Vd:D *)
      concat (extract bin 15 12) (pickBit bin 22) 1 |> getVecSReg |> toSVReg
    let sm = (* Vm:M *)
      concat (extract bin 3 0) (pickBit bin 5) 1 |> getVecSReg |> toSVReg
    OprInfo (TwoOperands (sd, sm), false, None)
    ///TwoOperands (sd, sm)

(* <Dd>, <Dm> *)
type internal OprDdDm () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    OprInfo (TwoOperands (dd, dm), false, None)
    ///TwoOperands (dd, dm)

(* <Dd>, <Sm> *)
type internal OprDdSm () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let sm = (* Vm:M *)
      concat (extract bin 3 0) (pickBit bin 5) 1 |> getVecSReg |> toSVReg
    OprInfo (TwoOperands (dd, sm), false, None)
    ///TwoOperands (dd, sm)

(* <Sd>, <Dm> *)
type internal OprSdDm () =
  inherit OperandParser ()
  override __.Render bin =
    let sd = (* Vd:D *)
      concat (extract bin 15 12) (pickBit bin 22) 1 |> getVecSReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    OprInfo (TwoOperands (sd, dm), false, None)
    ///TwoOperands (sd, dm)

(* <Sn>, <Rt> *)
type internal OprSnRt () =
  inherit OperandParser ()
  override __.Render bin =
    let sn = (* Vn:N *)
      concat (extract bin 19 16) (pickBit bin 7) 1 |> getVecSReg |> toSVReg
    let rt = extract bin 15 12 |> getRegister |> OprReg
    OprInfo (TwoOperands (sn, rt), false, None)
    ///TwoOperands (sn, rt)

(* <Rt>, <Sn> *)
type internal OprRtSn () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let sn = (* Vn:N *)
      concat (extract bin 19 16) (pickBit bin 7) 1 |> getVecSReg |> toSVReg
    OprInfo (TwoOperands (rt, sn), false, None)
    ///TwoOperands (rt, sn)

(* <Qd>, <Qm> *)
type internal OprQdQm () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let qm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecQReg |> toSVReg
    OprInfo (TwoOperands (qd, qm), false, None)
    ///TwoOperands (qd, qm)

(* <Dd>, <Qm> *)
type internal OprDdQm () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let qm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecQReg |> toSVReg
    OprInfo (TwoOperands (dd, qm), false, None)
    ///TwoOperands (dd, qm)

(* <Qd>, <Dm> *)
type internal OprQdDm () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    OprInfo (TwoOperands (qd, dm), false, None)
    ///TwoOperands (qd, dm)

(* <spec_reg>, <Rt> *)
type internal OprSregRt () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    OprInfo (TwoOperands (OprReg R.FPSCR, rt), false, None)
    ///TwoOperands (OprReg R.FPSCR, rt) /// FIXME: spec_reg

(* <Rt>, <spec_reg> *)
type internal OprRtSreg () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    OprInfo (TwoOperands (rt, OprReg R.FPSCR), false, None)
    ///TwoOperands (rt, OprReg R.FPSCR) /// FIXME: spec_reg

(* <Rd>, <spec_reg> *)
type internal OprRdSreg () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let sreg =
      if pickBit bin 22 = 1u then R.SPSR else R.APSR (* or CPSR *)
      |> uint |> getRegister |> OprReg
    OprInfo (TwoOperands (rd, sreg), false, None)
    ///TwoOperands (rd, sreg)

(* <spec_reg>, <Rn> *)
type internal OprSregRn () =
  inherit OperandParser ()
  override __.Render bin =
    let struct (sreg, flag) = (* FIXME: F5-4583 *)
      if pickBit bin 22 = 1u (* R *) then getSPSR (extract bin 19 16)
      else getAPSR (extract bin 19 18 (* mask<3:2> *)) (* or CPSR *)
    let rn = extract bin 3 0 |> getRegister |> OprReg
    OprInfo (TwoOperands (OprSpecReg (sreg, flag), rn), false, None)
    ///TwoOperands (OprSpecReg (sreg, flag), rn)

(* <Rd>, <banked_reg> *)
type internal OprRdBankreg () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let breg =
      concat (pickBit bin 8) (extract bin 19 16) 4
      |> getBankedReg (pickBit bin 22) |> OprReg
    OprInfo (TwoOperands (rd, breg), false, None)
    ///TwoOperands (rd, breg)

(* <banked_reg>, <Rn> *)
type internal OprBankregRn () =
  inherit OperandParser ()
  override __.Render bin =
    let breg =
      concat (pickBit bin 8) (extract bin 19 16) 4
      |> getBankedReg (pickBit bin 22) |> OprReg
    let rn = extract bin 3 0 |> getRegister |> OprReg
    OprInfo (TwoOperands (breg, rn), false, None)
    ///TwoOperands (breg, rn)

(* <Dd[x]>, <Rt> *)
type internal OprDd0Rt () =
  inherit OperandParser ()
  override __.Render bin =
    let d = concat (pickBit bin 7) (extract bin 19 16) 4 (* D:Vd *)
    let dd0 = toSSReg (d |> getVecDReg, Some 0uy)
    let rt = extract bin 15 12 |> getRegister |> OprReg
    OprInfo (TwoOperands (dd0, rt), false, None)
    ///TwoOperands (dd0, rt)

type internal OprDd1Rt () =
  inherit OperandParser ()
  override __.Render bin =
    let d = concat (pickBit bin 7) (extract bin 19 16) 4 (* D:Vd *)
    let dd1 = toSSReg (d |> getVecDReg, Some 1uy)
    let rt = extract bin 15 12 |> getRegister |> OprReg
    OprInfo (TwoOperands (dd1, rt), false, None)
    ///TwoOperands (dd1, rt)

type internal OprDd2Rt () =
  inherit OperandParser ()
  override __.Render bin =
    let d = concat (pickBit bin 7) (extract bin 19 16) 4 (* D:Vd *)
    let dd2 = toSSReg (d |> getVecDReg, Some 2uy)
    let rt = extract bin 15 12 |> getRegister |> OprReg
    OprInfo (TwoOperands (dd2, rt), false, None)
    ///TwoOperands (dd2, rt)

type internal OprDd3Rt () =
  inherit OperandParser ()
  override __.Render bin =
    let d = concat (pickBit bin 7) (extract bin 19 16) 4 (* D:Vd *)
    let dd3 = toSSReg (d |> getVecDReg, Some 3uy)
    let rt = extract bin 15 12 |> getRegister |> OprReg
    OprInfo (TwoOperands (dd3, rt), false, None)
    ///TwoOperands (dd3, rt)

type internal OprDd4Rt () =
  inherit OperandParser ()
  override __.Render bin =
    let d = concat (pickBit bin 7) (extract bin 19 16) 4 (* D:Vd *)
    let dd4 = toSSReg (d |> getVecDReg, Some 4uy)
    let rt = extract bin 15 12 |> getRegister |> OprReg
    OprInfo (TwoOperands (dd4, rt), false, None)
    ///TwoOperands (dd4, rt)

type internal OprDd5Rt () =
  inherit OperandParser ()
  override __.Render bin =
    let d = concat (pickBit bin 7) (extract bin 19 16) 4 (* D:Vd *)
    let dd5 = toSSReg (d |> getVecDReg, Some 5uy)
    let rt = extract bin 15 12 |> getRegister |> OprReg
    OprInfo (TwoOperands (dd5, rt), false, None)
    ///TwoOperands (dd5, rt)

type internal OprDd6Rt () =
  inherit OperandParser ()
  override __.Render bin =
    let d = concat (pickBit bin 7) (extract bin 19 16) 4 (* D:Vd *)
    let dd6 = toSSReg (d |> getVecDReg, Some 6uy)
    let rt = extract bin 15 12 |> getRegister |> OprReg
    OprInfo (TwoOperands (dd6, rt), false, None)
    ///TwoOperands (dd6, rt)

type internal OprDd7Rt () =
  inherit OperandParser ()
  override __.Render bin =
    let d = concat (pickBit bin 7) (extract bin 19 16) 4 (* D:Vd *)
    let dd7 = toSSReg (d |> getVecDReg, Some 7uy)
    let rt = extract bin 15 12 |> getRegister |> OprReg
    OprInfo (TwoOperands (dd7, rt), false, None)
    ///TwoOperands (dd7, rt)

(* <Rt>, <Dn[x]> *)
type internal OprRtDn0 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let n = concat (pickBit bin 7) (extract bin 19 16) 4 (* N:Vn *)
    let dn0 = toSSReg (n |> getVecDReg, Some 0uy)
    OprInfo (TwoOperands (rt, dn0), false, None)
    ///TwoOperands (rt, dn0)

type internal OprRtDn1 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let n = concat (pickBit bin 7) (extract bin 19 16) 4 (* N:Vn *)
    let dn1 = toSSReg (n |> getVecDReg, Some 1uy)
    OprInfo (TwoOperands (rt, dn1), false, None)
    ///TwoOperands (rt, dn1)

type internal OprRtDn2 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let n = concat (pickBit bin 7) (extract bin 19 16) 4 (* N:Vn *)
    let dn2 = toSSReg (n |> getVecDReg, Some 2uy)
    OprInfo (TwoOperands (rt, dn2), false, None)
    ///TwoOperands (rt, dn2)

type internal OprRtDn3 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let n = concat (pickBit bin 7) (extract bin 19 16) 4 (* N:Vn *)
    let dn3 = toSSReg (n |> getVecDReg, Some 3uy)
    OprInfo (TwoOperands (rt, dn3), false, None)
    ///TwoOperands (rt, dn3)

type internal OprRtDn4 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let n = concat (pickBit bin 7) (extract bin 19 16) 4 (* N:Vn *)
    let dn4 = toSSReg (n |> getVecDReg, Some 4uy)
    OprInfo (TwoOperands (rt, dn4), false, None)
    ///TwoOperands (rt, dn4)

type internal OprRtDn5 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let n = concat (pickBit bin 7) (extract bin 19 16) 4 (* N:Vn *)
    let dn5 = toSSReg (n |> getVecDReg, Some 5uy)
    OprInfo (TwoOperands (rt, dn5), false, None)
    ///TwoOperands (rt, dn5)

type internal OprRtDn6 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let n = concat (pickBit bin 7) (extract bin 19 16) 4 (* N:Vn *)
    let dn6 = toSSReg (n |> getVecDReg, Some 6uy)
    OprInfo (TwoOperands (rt, dn6), false, None)
    ///TwoOperands (rt, dn6)

type internal OprRtDn7 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let n = concat (pickBit bin 7) (extract bin 19 16) 4 (* N:Vn *)
    let dn7 = toSSReg (n |> getVecDReg, Some 7uy)
    OprInfo (TwoOperands (rt, dn7), false, None)
    ///TwoOperands (rt, dn7)

(* <Qd>, <Rt> *)
type internal OprQdRt () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 7) (extract bin 19 16) 4 |> getVecQReg |> toSVReg
    let rt = extract bin 15 12 |> getRegister |> OprReg
    OprInfo (TwoOperands (qd, rt), false, None)
    ///TwoOperands (qd, rt)

(* <Dd>, <Rt> *)
type internal OprDdRt () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 7) (extract bin 19 16) 4 |> getVecDReg |> toSVReg
    let rt = extract bin 15 12 |> getRegister |> OprReg
    OprInfo (TwoOperands (dd, rt), false, None)
    ///TwoOperands (dd, rt)

(* <Dd>, <Dm[x]> *)
type internal OprDdDmx () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let dmx =
      let idx =
        match extract bin 19 16 (* imm4 *) with
        | b when b &&& 0b0001u = 0b0001u (* xxx1 *) -> extract b 3 1
        | b when b &&& 0b0011u = 0b0010u (* xx10 *) -> extract b 3 2
        | b when b &&& 0b0111u = 0b0100u (* x100 *) -> pickBit b 3
        | _ (* x000 *) -> raise UndefinedException
        |> uint8
      let m = concat (pickBit bin 5) (extract bin 3 0) 4 (* M:Vm *)
      toSSReg (m |> getVecDReg, Some idx)
    OprInfo (TwoOperands (dd, dmx), false, None)
    ///TwoOperands (dd, dmx)

(* <Qd>, <Dm[x]> *)
type internal OprQdDmx () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let dmx =
      let idx =
        match extract bin 19 16 (* imm4 *) with
        | b when b &&& 0b0001u = 0b0001u (* xxx1 *) -> extract b 3 1
        | b when b &&& 0b0011u = 0b0010u (* xx10 *) -> extract b 3 2
        | b when b &&& 0b0111u = 0b0100u (* x100 *) -> pickBit b 3
        | _ (* x000 *) -> raise UndefinedException
        |> uint8
      let m = concat (pickBit bin 5) (extract bin 3 0) 4 (* M:Vm *)
      toSSReg (m |> getVecDReg, Some idx)
    OprInfo (TwoOperands (qd, dmx), false, None)
    ///TwoOperands (qd, dmx)

(* <Rt>, [<Rn>] *)
type internal OprRtAMem () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem = memOffsetImm (extract bin 19 16 |> getRegister, None, None)
    OprInfo (TwoOperands (rt, mem), false, None)
    ///TwoOperands (rt, mem)

(* <Rt>, [<Rn>] *)
type internal OprRtMem () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 3 0 |> getRegister |> OprReg
    let mem = memOffsetImm (extract bin 19 16 |> getRegister, None, None)
    OprInfo (TwoOperands (rt, mem), false, None)
    ///TwoOperands (rt, mem)

(* <Sd>, [<Rn>{, #{+/-}<imm>}] *)
type internal OprSdMem () =
  inherit OperandParser ()
  override __.Render bin =
    let sd = (* Vd:D *)
      concat (extract bin 15 12) (pickBit bin 22) 1 |> getVecSReg |> toSVReg
    let mem =
      let imm32 =
        match extract bin 9 8 (* size *) with
        | 0b01u -> extract bin 7 0 (* imm8 *) <<< 1 |> int64
        | _ -> extract bin 7 0 (* imm8 *) <<< 2 |> int64
      let rn = extract bin 19 16 (* Rn *) |> getRegister
      let sign = pickBit bin 23 (* U *) |> getSign |> Some
      memOffsetImm (rn, sign, Some imm32)
    OprInfo (TwoOperands (sd, mem), false, None)
    ///TwoOperands (sd, mem)

(* <Dd>, [<Rn>{, #{+/-}<imm>}] *)
type internal OprDdMem () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let mem =
      let imm32 =
        match extract bin 9 8 (* size *) with
        | 0b01u -> extract bin 7 0 (* imm8 *) <<< 1 |> int64
        | _ -> extract bin 7 0 (* imm8 *) <<< 2 |> int64
      let rn = extract bin 19 16 (* Rn *) |> getRegister
      let sign = pickBit bin 23 (* U *) |> getSign |> Some
      memOffsetImm (rn, sign, Some imm32)
    OprInfo (TwoOperands (dd, mem), false, None)
    ///TwoOperands (dd, mem)

(* <Rt>, [<Rn> {, {#}<imm>}] *)
type internal OprRtMemImm0 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem = (* imm32 = 0 *)
      memOffsetImm (extract bin 19 16 |> getRegister, None, None)
    OprInfo (TwoOperands (rt, mem), false, None)
    ///TwoOperands (rt, mem)

(* <Rt>, [<Rn> {, #{+/-}<imm>}]
   <Rt>, [<Rn>], #{+/-}<imm>
   <Rt>, [<Rn>, #{+/-}<imm>]! *)
type internal OprRtMemImm12 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem =
      let imm12 = extract bin 11 0 |> int64
      let rn = extract bin 19 16 |> getRegister
      let sign = pickBit bin 23 |> getSign |> Some
      match concat (pickBit bin 24) (pickBit bin 21) 1 (* P:W *) with
      | 0b10u -> memOffsetImm (rn, sign, Some imm12)
      | 0b00u -> memPostIdxImm (rn, sign, Some imm12)
      | 0b11u -> memPreIdxImm (rn, sign, Some imm12)
      | _ -> raise ParsingFailureException (* STRT *)
    OprInfo (TwoOperands (rt, mem), wback bin, None)
    ///TwoOperands (rt, mem)

(* <Rt>, [<Rn>, {+/-}<Rm>{, <shift>}]
   <Rt>, [<Rn>], {+/-}<Rm>{, <shift>}
   <Rt>, [<Rn>, {+/-}<Rm>{, <shift>}]! *)
type internal OprRtMemShf () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let rm = extract bin 3 0 |> getRegister
      let struct (shift, imm) = (* stype:imm5 *)
        decodeImmShift (extract bin 6 5) (extract bin 11 7)
      let shiftOffset = Some (shift, Imm imm)
      let sign = pickBit bin 23 |> getSign |> Some
      match concat (pickBit bin 24) (pickBit bin 21) 1 (* P:W *) with
      | 0b10u -> memOffsetReg (rn, sign, rm, shiftOffset)
      | 0b00u -> memPostIdxReg (rn, sign, rm, shiftOffset)
      | 0b11u -> memPreIdxReg (rn, sign, rm, shiftOffset)
      | _ -> raise ParsingFailureException (* STRT *)
    OprInfo (TwoOperands (rt, mem), wback bin, None)
    ///TwoOperands (rt, mem)

(* <Rt>, [<Rn>], {+/-}<Rm>{, <shift>} *)
type internal OprRtMemShfP () =
  inherit OperandParser ()
  override __.Render bin = (* Post-indexed *)
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let rm = extract bin 3 0 |> getRegister
      let struct (shift, imm) = (* stype:imm5 *)
        decodeImmShift (extract bin 6 5) (extract bin 11 7)
      let shiftOffset = Some (shift, Imm imm)
      let sign = pickBit bin 23 |> getSign |> Some
      memPostIdxReg (rn, sign, rm, shiftOffset)
    OprInfo (TwoOperands (rt, mem), false, None)
    ///TwoOperands (rt, mem)

(* <Rt>, [<Rn>, {+/-}<Rm>]
   <Rt>, [<Rn>], {+/-}<Rm>
   <Rt>, [<Rn>, {+/-}<Rm>]! *)
type internal OprRtMemReg () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let rm = extract bin 3 0 |> getRegister
      let sign = pickBit bin 23 |> getSign |> Some
      match concat (pickBit bin 24) (pickBit bin 21) 1 (* P:W *) with
      | 0b10u -> memOffsetReg (rn, sign, rm, None)
      | 0b00u -> memPostIdxReg (rn, sign, rm, None)
      | 0b11u -> memPreIdxReg (rn, sign, rm, None)
      | _ -> raise ParsingFailureException (* STRHT *)
    OprInfo (TwoOperands (rt, mem), wback bin, None)
    ///TwoOperands (rt, mem)

(* <Rt>, [<Rn>], {+/-}<Rm> *)
type internal OprRtMemRegP () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let rm = extract bin 3 0 |> getRegister
      let sign = pickBit bin 23 |> getSign |> Some
      memPostIdxReg (rn, sign, rm, None)
    OprInfo (TwoOperands (rt, mem), false, None)
    ///TwoOperands (rt, mem)

(* <Rt>, [<Rn> {, #{+/-}<imm>}]
   <Rt>, [<Rn>], #{+/-}<imm>
   <Rt>, [<Rn>, #{+/-}<imm>]! *)
type internal OprRtMemImm () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let imm = (* imm4H:imm4L *)
        concat (extract bin 11 8) (extract bin 3 0) 4 |> int64
      let sign = pickBit bin 23 |> getSign |> Some
      match concat (pickBit bin 24) (pickBit bin 21) 1 (* P:W *) with
      | 0b10u -> memOffsetImm (rn, sign, if imm = 0L then None else Some imm)
      | 0b00u -> memPostIdxImm (rn, sign, Some imm)
      | 0b11u -> memPreIdxImm (rn, sign, Some imm)
      | _ -> raise ParsingFailureException (* STRHT *)
    OprInfo (TwoOperands (rt, mem), wback bin, None)
    ///TwoOperands (rt, mem)

(* <Rt>, [<Rn>] {, #{+/-}<imm>} *)
type internal OprRtMemImmP () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let imm = (* imm4H:imm4L *)
        concat (extract bin 11 8) (extract bin 3 0) 4 |> int64
      let sign = pickBit bin 23 |> getSign |> Some
      memPostIdxImm (rn, sign, Some imm)
    OprInfo (TwoOperands (rt, mem), false, None)
    ///TwoOperands (rt, mem)

(* <Rt>, [<Rn>] {, #{+/-}<imm>} *)
type internal OprRtMemImm12P () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let imm = (extract bin 11 0 (* imm12 *)) |> int64
      let sign = pickBit bin 23 |> getSign |> Some
      memPostIdxImm (rn, sign, Some imm)
    OprInfo (TwoOperands (rt, mem), false, None)
    ///TwoOperands (rt, mem)

(* <Dd>, #<imm> *)
type internal OprDdImm () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let imm = advSIMDExpandImm bin |> int64 |> OprImm
    OprInfo (TwoOperands (dd, imm), false, None)
    ///TwoOperands (dd, imm)

(* <Qd>, #<imm> *)
type internal OprQdImm () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let imm = advSIMDExpandImm bin |> int64 |> OprImm
    OprInfo (TwoOperands (qd, imm), false, None)
    ///TwoOperands (qd, imm)

(* <Sd>, #<imm> *)
type internal OprSdVImm () =
  inherit OperandParser ()
  override __.Render bin =
    let sd = (* Vd:D *)
      concat (extract bin 15 12) (pickBit bin 22) 1 |> getVecSReg |> toSVReg
    let imm = (* imm4H:imm4L *)
      let imm8 = concat (extract bin 19 16) (extract bin 3 0) 4
      vfpExpandImm bin imm8 |> int64 |> OprImm
    OprInfo (TwoOperands (sd, imm), false, None)
    ///TwoOperands (sd, imm)

(* <Dd>, #<imm> *)
type internal OprDdVImm () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let imm = (* imm4H:imm4L *)
      let imm8 = concat (extract bin 19 16) (extract bin 3 0) 4
      vfpExpandImm bin imm8 |> int64 |> OprImm
    OprInfo (TwoOperands (dd, imm), false, None)
    ///TwoOperands (dd, imm)

(* <Sd>, #0.0 *)
type internal OprSdImm0 () =
  inherit OperandParser ()
  override __.Render bin =
    let sd = (* Vd:D *)
      concat (extract bin 15 12) (pickBit bin 22) 1 |> getVecSReg |> toSVReg
    OprInfo (TwoOperands (sd, OprImm 0L), false, None)
    ///TwoOperands (sd, OprImm 0L)

(* <Dd>, #0.0 *)
type internal OprDdImm0 () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    OprInfo (TwoOperands (dd, OprImm 0L), false, None)
    ///TwoOperands (dd, OprImm 0L)

(* <Rd>, #<imm16> *)
type internal OprRdImm16 () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let imm16 = (* imm4:imm12 *)
      concat (extract bin 19 16) (extract bin 11 0) 12 |> int64 |> OprImm
    OprInfo (TwoOperands (rd, imm16), false, None)
    ///TwoOperands (rd, imm16)

(* <spec_reg>, #<imm> *)
type internal OprSregImm () =
  inherit OperandParser ()
  override __.Render bin =
    let struct (sreg, flag) = (* FIXME: F5-4580 *)
      if pickBit bin 22 = 1u (* R *) then getSPSR (extract bin 19 16)
      else getAPSR (extract bin 19 18 (* mask<3:2> *)) (* or CPSR *)
    let imm = expandImmediate bin |> int64 |> OprImm
    OprInfo (TwoOperands (OprSpecReg (sreg, flag), imm), false, None)
    ///TwoOperands (OprSpecReg (sreg, flag), imm)

(* <Rd>, #<const> *)
type internal OprRdConst () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let imm = expandImmediate bin |> int64 |> OprImm
    OprInfo (TwoOperands (rd, imm), false, None)
    ///TwoOperands (rd, imm)

(* <Rd>, #<const> with carry *)
type internal OprRdConstCF () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let struct (imm32, carryOut) = expandImmCF bin
    OprInfo (TwoOperands (rd, imm32), false, carryOut)
    ///TwoOperands (rd, imm32)

(* <Rn>, #<const> *)
type internal OprRnConst () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let imm = expandImmediate bin |> int64 |> OprImm
    OprInfo (TwoOperands (rn, imm), false, None)
    ///TwoOperands (rn, imm)

(* <Rn>, #<const> with carry *)
type internal OprRnConstCF () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let struct (imm32, carryOut) = expandImmCF bin
    OprInfo (TwoOperands (rn, imm32), false, carryOut)
    ///TwoOperands (rn, imm32)

(* <Sd>, <label> *)
type internal OprSdLabel () =
  inherit OperandParser ()
  override __.Render bin =
    let sd = (* Vd:D *)
      concat (extract bin 15 12) (pickBit bin 22) 1 |> getVecSReg |> toSVReg
    let label = extract bin 7 0 (* imm8 *) |> int64 |> memLabel
    OprInfo (TwoOperands (sd, label), false, None)
    ///TwoOperands (sd, label)

(* <Dd>, <label> *)
type internal OprDdLabel () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let label = extract bin 7 0 (* imm8 *) |> int64 |> memLabel
    OprInfo (TwoOperands (dd, label), false, None)
    ///TwoOperands (dd, label)

(* <Rd>, <label> *)
type internal OprRdLabel () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let label = expandImmediate bin |> int64 |> memLabel
    OprInfo (TwoOperands (rd, label), false, None)
    ///TwoOperands (rd, label)

(* <Rt>, <label> *)
type internal OprRtLabel () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let imm12 = extract bin 11 0 |> int64
    let label =
      if pickBit bin 23 = 1u then memLabel imm12 else memLabel (imm12 * -1L)
    OprInfo (TwoOperands (rt, label), wback bin, None)
    ///TwoOperands (rt, label)

(* <Rt>, <label> *)
type internal OprRtLabelHL () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let label = (* imm4H:imm4L *)
      concat (extract bin 11 8) (extract bin 3 0) 4 |> int64 |> memLabel
    OprInfo (TwoOperands (rt, label), wback bin, None)
    ///TwoOperands (rt, label)

(* <Rn>{!}, <registers> *)
type internal OprRnRegs () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let regs = extract bin 15 0 (* register_list *) |> getRegList |> OprRegList
    OprInfo (TwoOperands (rn, regs), wbackW bin, None)
    ///TwoOperands (rn, regs)

(* <Rn>, <registers>^ *) /// FIXME: '^' not apply
type internal OprRnRegsCaret () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let regs = extract bin 15 0 (* register_list *) |> getRegList |> OprRegList
    OprInfo (TwoOperands (rn, regs), false, None)
    ///TwoOperands (rn, regs)

(* <Rn>{!}, <dreglist> *)
type internal OprRnDreglist () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let regs = extract bin 7 0 (* imm8 *) / 2u
    let dreglist = (* D:Vd *)
      getDRegList (concat (pickBit bin 22) (extract bin 15 12) 4) regs
    OprInfo (TwoOperands (rn, dreglist), wbackW bin, None)
    ///TwoOperands (rn, dreglist)

(* <Rn>{!}, <sreglist> *)
type internal OprRnSreglist () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let regs = extract bin 7 0 (* imm8 *)
    let sreglist = (* Vd:D *)
      getSRegList (concat (extract bin 15 12) (pickBit bin 22) 1) regs
    OprInfo (TwoOperands (rn, sreglist), wbackW bin, None)
    ///TwoOperands (rn, sreglist)

(* <list>, [<Rn>{:<align>}]
   <list>, [<Rn>{:<align>}]!
   <list>, [<Rn>{:<align>}], <Rm> *)
type internal OprListMem () =
  inherit OperandParser ()
  override __.Render bin =
    let list =
      let d = concat (pickBit bin 22) (extract bin 15 12) 4 (* D:Vd *)
      match extract bin 11 8 (* itype *) with
      | 0b0000u -> [ d; d + 1u; d + 2u; d + 3u ]
      | 0b0001u -> [ d; d + 2u; d + 4u; d + 6u ]
      | 0b0111u -> [ d ]
      | 0b1010u -> [ d; d + 1u ]
      | 0b0110u -> [ d; d + 1u; d + 2u ]
      | 0b0010u -> [ d; d + 1u; d + 2u; d + 3u ]
      | _ -> raise ParsingFailureException
      |> List.map getVecDReg |> getSIMDVector
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let rm = extract bin 3 0 |> getRegister
      let align =
        match extract bin 5 4 (* align *) with
        | 0b01u -> Some 64L
        | 0b10u -> Some 128L
        | 0b11u -> Some 256L
        | _ (* 00 *) -> None
      toMemAlign rn align rm
    OprInfo (TwoOperands (list, mem), wbackM bin, None)
    ///TwoOperands (list, mem)

(* <list>, [<Rn>{:<align>}]
   <list>, [<Rn>{:<align>}]!
   <list>, [<Rn>{:<align>}], <Rm> *)
/// VLD1 (single element to all lanes)
type internal OprListMem1 () =
  inherit OperandParser ()
  override __.Render bin =
    let list =
      let d = concat (pickBit bin 22) (extract bin 15 12) 4 (* D:Vd *)
      if pickBit bin 5 (* T *) = 0u then [ d ] else [ d; d + 1u ]
      |> List.map getVecDReg |> getSIMDScalar None
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let rm = extract bin 3 0 |> getRegister
      let align =
        match concat (extract bin 7 6) (pickBit bin 4) 1 (* size:a *) with
        | 0b011u -> Some 16L
        | 0b101u -> Some 32L
        | 0b000u | 0b010u | 0b100u (* <size> = 8 or a = 0 *) -> None
        | _ (* 001 & 11x *) -> raise UndefinedException
      toMemAlign rn align rm
    OprInfo (TwoOperands (list, mem), wbackM bin, None)
    ///TwoOperands (list, mem)

/// VLD2 (single 2-element structure to all lanes)
type internal OprListMem2 () =
  inherit OperandParser ()
  override __.Render bin =
    let list =
      let d = concat (pickBit bin 22) (extract bin 15 12) 4 (* D:Vd *)
      if pickBit bin 5 (* T *) = 0u then [ d; d + 1u ] else [ d; d + 2u ]
      |> List.map getVecDReg |> getSIMDScalar None
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let rm = extract bin 3 0 |> getRegister
      let align =
        match concat (extract bin 7 6) (pickBit bin 4) 1 (* size:a *) with
        | 0b001u -> Some 16L
        | 0b011u -> Some 32L
        | 0b101u -> Some 64L
        | 0b000u | 0b010u | 0b100u (* xx0 - except 110 *) -> None
        | _ (* 11x *) -> raise UndefinedException
      toMemAlign rn align rm
    OprInfo (TwoOperands (list, mem), wbackM bin, None)
    ///TwoOperands (list, mem)

/// VLD4 (single 4-element structure to all lanes)
type internal OprListMem4 () =
  inherit OperandParser ()
  override __.Render bin =
    let list =
      let d = concat (pickBit bin 22) (extract bin 15 12) 4 (* D:Vd *)
      if pickBit bin 5 (* T *) = 0u then [ d; d + 1u; d + 2u; d + 3u ]
      else [ d; d + 2u; d + 4u; d + 6u ]
      |> List.map getVecDReg |> getSIMDScalar None
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let rm = extract bin 3 0 |> getRegister
      let align =
        match concat (extract bin 7 6) (pickBit bin 4) 1 (* size:a *) with
        | 0b001u -> Some 32L
        | 0b011u -> Some 64L
        | 0b101u -> Some 64L
        | 0b111u -> Some 128L
        | 0b000u | 0b010u | 0b100u (* xx0 - except 110 *) -> None
        | _ (* 110 *) -> raise UndefinedException
      toMemAlign rn align rm
    OprInfo (TwoOperands (list, mem), wbackM bin, None)
    ///TwoOperands (list, mem)

(* <list>, [<Rn>]
   <list>, [<Rn>]!
   <list>, [<Rn>], <Rm> *)
/// VLD3 (single 3-element structure to all lanes)
type internal OprListMem3 () =
  inherit OperandParser ()
  override __.Render bin =
    let list =
      let d = concat (pickBit bin 22) (extract bin 15 12) 4 (* D:Vd *)
      if pickBit bin 5 (* T *) = 0u then [ d; d + 1u; d + 2u ]
      else [ d; d + 2u; d + 4u ]
      |> List.map getVecDReg |> getSIMDScalar None
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let rm = extract bin 3 0 |> getRegister
      match rm with
      | R.PC -> memOffsetImm (rn, None, None)
      | R.SP -> memPreIdxImm (rn, None, None)
      | _ -> memPostIdxReg (rn, None, rm, None)
    OprInfo (TwoOperands (list, mem), wbackM bin, None)
    ///TwoOperands (list, mem)

(* <list>, [<Rn>{:<align>}]
   <list>, [<Rn>{:<align>}]!
   <list>, [<Rn>{:<align>}], <Rm> *)
/// VST1: index_align
type internal OprListMemA () =
  inherit OperandParser ()
  override __.Render bin =
    let idx =
      match extract bin 11 10 (* size *) with
      | 0b00u -> extract (extract bin 7 4 (* index_align *)) 3 1
      | 0b01u -> extract (extract bin 7 4 (* index_align *)) 3 2
      | 0b10u -> pickBit (extract bin 7 4 (* index_align *)) 3
      | _ (* 11 *) -> raise UndefinedException
      |> uint8 |> Some
    let list = getSIMDScalar idx [ getVecDReg (extract bin 15 12 (* Rd *)) ]
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let rm = extract bin 3 0 |> getRegister
      let align =
        match extract bin 11 10 (* size *) with
        | 0b01u when extract bin 5 4 (* index_align<1:0> *) = 0b01u -> Some 16L
        | 0b10u when extract bin 6 4 (* index_align<2:0> *) = 0b011u -> Some 32L
        | _ -> None
      toMemAlign rn align rm
    OprInfo (TwoOperands (list, mem), wbackM bin, None)
    ///TwoOperands (list, mem)

/// VST2: index_align
type internal OprListMemB () =
  inherit OperandParser ()
  override __.Render bin =
    let idx =
      match extract bin 11 10 (* size *) with
      | 0b00u -> extract bin 7 5 (* index_align<3:1> *)
      | 0b01u -> extract bin 7 6 (* index_align<3:2> *)
      | 0b10u -> pickBit bin 7   (* index_align<3> *)
      | _ (* 11 *) -> raise UndefinedException
      |> uint8 |> Some
    let list =
      let d = concat (pickBit bin 22) (extract bin 15 12) 4 (* D:Vd *)
      match extract bin 11 10 (* size *) with
      | 0b00u -> [ d; d + 1u ]
      | 0b01u -> (* index_align<1> *)
        if pickBit bin 5 = 0u then [ d; d + 1u ] else [ d; d + 2u ]
      | 0b10u -> (* index_align<2> *)
        if pickBit bin 6 = 0u then [ d; d + 1u ] else [ d; d + 2u ]
      | _ -> raise UndefinedException
      |> List.map getVecDReg |> getSIMDScalar (idx)
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let rm = extract bin 3 0 |> getRegister
      let align =
        match extract bin 11 10 (* size *) with
        | 0b00u when pickBit bin 4 (* index_align<0> *) = 1u -> Some 16L
        | 0b01u when pickBit bin 4 (* index_align<0> *) = 1u -> Some 32L
        | 0b10u when extract bin 5 4 (* index_align<1:0> *) = 0b01u -> Some 64L
        | _ -> None
      toMemAlign rn align rm
    OprInfo (TwoOperands (list, mem), wbackM bin, None)
    ///TwoOperands (list, mem)

/// VST4: index_align
type internal OprListMemD () =
  inherit OperandParser ()
  override __.Render bin =
    let idx =
      match extract bin 11 10 (* size *) with
      | 0b00u -> extract bin 7 5 (* index_align<3:1> *)
      | 0b01u -> extract bin 7 6 (* index_align<3:2> *)
      | 0b10u -> pickBit bin 7    (* index_align<3> *)
      | _ (* 11 *) -> raise UndefinedException
      |> uint8 |> Some
    let list =
      let d = concat (pickBit bin 22) (extract bin 15 12) 4 (* D:Vd *)
      match extract bin 11 10 (* size *) with
      | 0b00u -> [ d; d + 1u; d + 2u; d + 3u ]
      | 0b01u -> (* index_align<1> *)
        if pickBit bin 5 = 0u then [ d; d + 1u; d + 2u; d + 3u ]
        else [ d; d + 2u; d + 4u; d + 6u ]
      | 0b10u -> (* index_align<2> *)
        if pickBit bin 6 = 0u then [ d; d + 1u; d + 2u; d + 3u ]
        else [ d; d + 2u; d + 4u; d + 6u ]
      | _ -> raise UndefinedException
      |> List.map getVecDReg |> getSIMDScalar (idx)
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let rm = extract bin 3 0 |> getRegister
      let align =
        match extract bin 11 10 (* size *) with
        | 0b00u when pickBit bin 4 (* index_align<0> *) = 1u -> Some 32L
        | 0b01u when pickBit bin 4 (* index_align<0> *) = 1u -> Some 64L
        | 0b10u when extract bin 5 4 (* index_align<1:0> *) = 0b01u -> Some 64L
        | 0b10u when extract bin 5 4 (* index_align<1:0> *) = 0b10u -> Some 128L
        | _ -> None
      toMemAlign rn align rm
    OprInfo (TwoOperands (list, mem), wbackM bin, None)
    ///TwoOperands (list, mem)

(* <list>, [<Rn>]
   <list>, [<Rn>]!
   <list>, [<Rn>], <Rm> *)
/// VST3: index_align
type internal OprListMemC () =
  inherit OperandParser ()
  override __.Render bin =
    let idx =
      match extract bin 11 10 (* size *) with
      | 0b00u -> extract bin 7 5 (* index_align<3:1> *)
      | 0b01u -> extract bin 7 6 (* index_align<3:2> *)
      | 0b10u -> pickBit bin 7 (* index_align<3> *)
      | _ (* 11 *) -> raise UndefinedException
      |> uint8 |> Some
    let list =
      let d = concat (pickBit bin 22) (extract bin 15 12) 4 (* D:Vd *)
      match extract bin 11 10 (* size *) with
      | 0b00u -> [ d; d + 1u; d + 2u ]
      | 0b01u -> if pickBit bin 5 (* index_align<1> *) = 0u
                 then [ d; d + 1u; d + 2u ] else [ d; d + 2u; d + 4u ]
      | 0b10u -> if pickBit bin 6 (* index_align<2> *) = 0u
                 then [ d; d + 1u; d + 2u ] else [ d; d + 2u; d + 4u ]
      | _ -> raise UndefinedException
      |> List.map getVecDReg |> getSIMDScalar idx
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let rm = extract bin 3 0 |> getRegister
      match rm with
      | R.PC -> memOffsetImm (rn, None, None)
      | R.SP -> memPreIdxImm (rn, None, None)
      | _ -> memPostIdxReg (rn, None, rm, None)
    OprInfo (TwoOperands (list, mem), wbackM bin, None)
    ///TwoOperands (list, mem)

(* SP{!}, #<mode> *)
type internal OprSPMode () =
  inherit OperandParser ()
  override __.Render bin =
    let mode = extract bin 5 0 |> int64 |> OprImm
    OprInfo (TwoOperands (OprReg R.SP, mode), wbackW bin, None)
    ///TwoOperands (OprReg R.SP, mode)

(* <iflags> , #<mode> *)
type internal OprIflagsMode () =
  inherit OperandParser ()
  override __.Render bin =
    let iflags = OprIflag (getIflag (extract bin 8 6))
    let mode = extract bin 4 0 |> int64 |> OprImm
    OprInfo (TwoOperands (iflags, mode), false, None)
    ///TwoOperands (iflags, mode)

(* <Dm>, <Rt>, <Rt2> *)
type internal OprDmRtRt2 () =
  inherit OperandParser ()
  override __.Render bin =
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let rt2 = extract bin 19 16 |> getRegister |> OprReg
    OprInfo (ThreeOperands (dm, rt, rt2), false, None)
    ///ThreeOperands (dm, rt, rt2)

(* <Rt>, <Rt2>, <Dm> *)
type internal OprRtRt2Dm () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let rt2 = extract bin 19 16 |> getRegister |> OprReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    OprInfo (ThreeOperands (rt, rt2, dm), false, None)
    ///ThreeOperands (rt, rt2, dm)

(* <Dd>, <Sn>, <Sm> *)
type internal OprDdSnSm () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 1 |> getVecDReg |> toSVReg
    let sn = (* Vn:N *)
      concat (extract bin 19 16) (pickBit bin 7) 1 |> getVecSReg |> toSVReg
    let sm = (* Vm:M *)
      concat (extract bin 3 0) (pickBit bin 5) 1 |> getVecSReg |> toSVReg
    OprInfo (ThreeOperands (dd, sn, sm), false, None)
    ///ThreeOperands (dd, sn, sm)

(* <Dd>, <Sn>, <Sm>[<index>] *)
type internal OprDdSnSmidx () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 1 |> getVecDReg |> toSVReg
    let sn = (* Vn:N *)
      concat (extract bin 19 16) (pickBit bin 7) 1 |> getVecSReg |> toSVReg
    let sm = concat (extract bin 2 0) (pickBit bin 5) 1 (* Vm<2:0>:M *)
    let smidx =
      toSSReg (sm |> getVecDReg, Some (pickBit bin 3 (* Vm<3> *) |> uint8))
    OprInfo (ThreeOperands (dd, sn, smidx), false, None)
    ///ThreeOperands (dd, sn, smidx)

(* <Sd>, <Sn>, <Sm> *)
type internal OprSdSnSm () =
  inherit OperandParser ()
  override __.Render bin =
    let sd = (* Vd:D *)
      concat (extract bin 15 12) (pickBit bin 22) 1 |> getVecSReg |> toSVReg
    let sn = (* Vn:N *)
      concat (extract bin 19 16) (pickBit bin 7) 1 |> getVecSReg |> toSVReg
    let sm = (* Vm:M *)
      concat (extract bin 3 0) (pickBit bin 5) 1 |> getVecSReg |> toSVReg
    OprInfo (ThreeOperands (sd, sn, sm), false, None)
    ///ThreeOperands (sd, sn, sm)

(* <Dd>, <Dn>, <Dm> *)
(* {<Dd>, }<Dn>, <Dm> *)
type internal OprDdDnDm () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let dn = (* N:Vn *)
      concat (pickBit bin 7) (extract bin 19 16) 4 |> getVecDReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    OprInfo (ThreeOperands (dd, dn, dm), false, None)
    ///ThreeOperands (dd, dn, dm)

(* <Dd>, <Dn>, <Dm>[<index>] *)
type internal OprDdDnDmidx () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let dn = (* N:Vn *)
      concat (pickBit bin 7) (extract bin 19 16) 4 |> getVecDReg |> toSVReg
    let dm = extract bin 3 0 (* Vm *) |> getVecDReg
    let dmidx = toSSReg (dm, Some (pickBit bin 5 (* M *) |> uint8))
    OprInfo (ThreeOperands (dd, dn, dmidx), false, None)
    ///ThreeOperands (dd, dn, dmidx)

(* {<Dd>,} <Dm>, <Dn> *)
type internal OprDdDmDn () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    let dn = (* N:Vn *)
      concat (pickBit bin 7) (extract bin 19 16) 4 |> getVecDReg |> toSVReg
    OprInfo (ThreeOperands (dd, dm, dn), false, None)
    ///ThreeOperands (dd, dm, dn)

(* <Qd>, <Qn>, <Qm> *)
(* {<Qd>, }<Qn>, <Qm> *)
type internal OprQdQnQm () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let qn = (* N:Vn *)
      concat (pickBit bin 7) (extract bin 19 16) 4 |> getVecQReg |> toSVReg
    let qm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecQReg |> toSVReg
    OprInfo (ThreeOperands (qd, qn, qm), false, None)
    ///ThreeOperands (qd, qn, qm)

(* {<Qd>,} <Qm>, <Qn> *)
type internal OprQdQmQn () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let qm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecQReg |> toSVReg
    let qn = (* N:Vn *)
      concat (pickBit bin 7) (extract bin 19 16) 4 |> getVecQReg |> toSVReg
    OprInfo (ThreeOperands (qd, qm, qn), false, None)
    ///ThreeOperands (qd, qm, qn)

(* <Qd>, <Dn>, <Dm>[<index>] *)
type internal OprQdDnDmidx () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let dn = (* N:Vn *)
      concat (pickBit bin 7) (extract bin 19 16) 4 |> getVecDReg |> toSVReg
    let index = concat (pickBit bin 5) (pickBit bin 3) 1 (* M:Vm<3> *)
    let dmidx =
      toSSReg (extract bin 2 0 (* Vm<2:0> *) |> getVecDReg, Some (index |> uint8))
    OprInfo (ThreeOperands (qd, dn, dmidx), false, None)
    ///ThreeOperands (qd, dn, dmidx)

(* <Qd>, <Dn>, <Dm> *)
type internal OprQdDnDm () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let dn = (* N:Vn *)
      concat (pickBit bin 7) (extract bin 19 16) 4 |> getVecDReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    OprInfo (ThreeOperands (qd, dn, dm), false, None)
    ///ThreeOperands (qd, dn, dm)

(* {<Qd>,} <Qn>, <Dm> *)
type internal OprQdQnDm () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let qn = (* N:Vn *)
      concat (pickBit bin 7) (extract bin 19 16) 4 |> getVecQReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    OprInfo (ThreeOperands (qd, qn, dm), false, None)
    ///ThreeOperands (qd, qn, dm)

(* <Qd>, <Qn>, <Dm>[<index>] *)
type internal OprQdQnDmidx () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let qn = (* N:Vn *)
      concat (pickBit bin 7) (extract bin 19 16) 4 |> getVecQReg |> toSVReg
    let dm = extract bin 3 0 (* Vm *) |> getVecDReg
    let dmidx = toSSReg (dm, Some (pickBit bin 5 (* M *) |> uint8))
    OprInfo (ThreeOperands (qd, qn, dmidx), false, None)
    ///ThreeOperands (qd, qn, dmidx)

(* <Qd>, <Qn>, <Dm>[<index>] *)
type internal OprQdQnDmidxm () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let qn = (* N:Vn *)
      concat (pickBit bin 7) (extract bin 19 16) 4 |> getVecQReg |> toSVReg
    let index = concat (pickBit bin 5) (pickBit bin 3) 1 (* M:Vm<3> *)
    let dmidx =
      toSSReg (extract bin 2 0 (* Vm<2:0> *) |> getVecDReg, Some (index |> uint8))
    OprInfo (ThreeOperands (qd, qn, dmidx), false, None)
    ///ThreeOperands (qd, qn, dmidx)

(* <Dd>, <Qn>, <Qm> *)
type internal OprDdQnQm () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let qn = (* N:Vn *)
      concat (pickBit bin 7) (extract bin 19 16) 4 |> getVecQReg |> toSVReg
    let qm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecQReg |> toSVReg
    OprInfo (ThreeOperands (dd, qn, qm), false, None)
    ///ThreeOperands (dd, qn, qm)

(* <Dd>, <Dn>, <Dm[x]> *)
type internal OprDdDnDmx () =
  inherit OperandParser ()
  override __.Render bin =
    let m =
      match extract bin 21 20 (* size *) with
      | 0b01u -> extract bin 2 0 (* Vm<2:0> *)
      | 0b10u -> extract bin 3 0 (* Vm *)
      | _ -> raise UndefinedException
    let index =
      match extract bin 21 20 (* size *) with
      | 0b01u -> concat (pickBit bin 5) (pickBit bin 3) 1 (* M:Vm<3> *)
      | 0b10u -> pickBit bin 5 (* Vm *)
      | _ -> raise UndefinedException
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let dn = (* N:Vn *)
      concat (pickBit bin 7) (extract bin 19 16) 4 |> getVecDReg |> toSVReg
    let dmx = toSSReg (m |> getVecDReg, Some (index |> uint8))
    OprInfo (ThreeOperands (dd, dn, dmx), false, None)
    ///ThreeOperands (dd, dn, dmx)

(* <Qd>, <Qn>, <Dm[x]> *)
type internal OprQdQnDmx () =
  inherit OperandParser ()
  override __.Render bin =
    let m =
      match extract bin 21 20 (* size *) with
      | 0b01u -> extract bin 2 0 (* Vm<2:0> *)
      | 0b10u -> extract bin 3 0 (* Vm *)
      | _ -> raise UndefinedException
    let index =
      match extract bin 21 20 (* size *) with
      | 0b01u -> concat (pickBit bin 5) (pickBit bin 3) 1 (* M:Vm<3> *)
      | 0b10u -> pickBit bin 5 (* Vm *)
      | _ -> raise UndefinedException
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let qn = (* N:Vn *)
      concat (pickBit bin 7) (extract bin 19 16) 4 |> getVecQReg |> toSVReg
    let dmx = toSSReg (m |> getVecDReg, Some (index |> uint8))
    OprInfo (ThreeOperands (qd, qn, dmx), false, None)
    ///ThreeOperands (qd, qn, dmx)

(* <Qd>, <Dn>, <Dm>[<index>] *)
type internal OprQdDnDmx () =
  inherit OperandParser ()
  override __.Render bin =
    let m =
      match extract bin 21 20 (* size *) with
      | 0b01u -> extract bin 2 0 (* Vm<2:0> *)
      | 0b10u -> extract bin 3 0 (* Vm *)
      | _ -> raise UndefinedException
    let index =
      match extract bin 21 20 (* size *) with
      | 0b01u -> concat (pickBit bin 5) (pickBit bin 3) 1 (* M:Vm<3> *)
      | 0b10u -> pickBit bin 5 (* Vm *)
      | _ -> raise UndefinedException
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let dn = (* N:Vn *)
      concat (pickBit bin 7) (extract bin 19 16) 4 |> getVecDReg |> toSVReg
    let dmx = toSSReg (m |> getVecDReg, Some (index |> uint8))
    OprInfo (ThreeOperands (qd, dn, dmx), false, None)
    ///ThreeOperands (qd, dn, dmx)

(* <Rd>, <Rn>, <Rm> *)
(* {<Rd>,} <Rn>, <Rm> : SADD16? *)
type internal OprRdRnRm () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    OprInfo (ThreeOperands (rd, rn, rm), false, None)
    ///ThreeOperands (rd, rn, rm)

(* <Rd>, <Rn>{, <Rm>} *)
(* {<Rd>,} <Rn>, <Rm> *)
type internal OprRdRnRmOpt () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 19 16 |> getRegister |> OprReg
    let rn = extract bin 3 0 |> getRegister |> OprReg
    let rm = extract bin 11 8 |> getRegister |> OprReg
    OprInfo (ThreeOperands (rd, rn, rm), false, None)
    ///ThreeOperands (rd, rn, rm)

(* {<Rd>,} <Rm>, <Rs> *)
type internal OprRdRmRs () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let rs = extract bin 11 8 |> getRegister |> OprReg
    OprInfo (ThreeOperands (rd, rm, rs), false, None)
    ///ThreeOperands (rd, rm, rs)

(* {<Rd>,} <Rm>, <Rn> *)
type internal OprRdRmRn () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    OprInfo (ThreeOperands (rd, rm, rn), false, None)
    ///ThreeOperands (rd, rm, rn)

(* <Rt>, <Rt2>, [<Rn>, {+/-}<Rm>]
   <Rt>, <Rt2>, [<Rn>], {+/-}<Rm>
   <Rt>, <Rt2>, [<Rn>, {+/-}<Rm>]! *)
type internal OprRtRt2MemReg () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let rt2 = extract bin 15 12 + 1u |> getRegister |> OprReg
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let rm = extract bin 3 0 |> getRegister
      let sign = pickBit bin 23 |> getSign |> Some
      match concat (pickBit bin 24) (pickBit bin 21) 1 (* P:W *) with
      | 0b10u -> memOffsetReg (rn, sign, rm, None)
      | 0b00u -> memPostIdxReg (rn, sign, rm, None)
      | 0b11u -> memPreIdxReg (rn, sign, rm, None)
      | _ -> raise ParsingFailureException (* SEE "STRHT" *)
    OprInfo (ThreeOperands (rt, rt2, mem), wback bin, None)
    ///ThreeOperands (rt, rt2, mem)

(* <Rt>, <Rt2>, [<Rn>] *)
type internal OprRtRt2Mem () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 3 0 |> getRegister |> OprReg
    let rt2 = extract bin 3 0 + 1u |> getRegister |> OprReg
    let mem =
      memOffsetImm (extract bin 19 16 (* Rn *) |> getRegister, None, None)
    OprInfo (ThreeOperands (rt, rt2, mem), false, None)
    ///ThreeOperands (rt, rt2, mem)

(* <Rt>, <Rt2>, [<Rn>] *)
type internal OprRtRt2Mem2 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let rt2 = extract bin 3 0 |> getRegister |> OprReg
    let mem =
      memOffsetImm (extract bin 19 16 (* Rn *) |> getRegister, None, None)
    OprInfo (ThreeOperands (rt, rt2, mem), false, None)
    ///ThreeOperands (rt, rt2, mem)

(* <Rt>, <Rt2>, [<Rn> {, #{+/-}<imm>}]
   <Rt>, <Rt2>, [<Rn>], #{+/-}<imm>
   <Rt>, <Rt2>, [<Rn>, #{+/-}<imm>]! *)
type internal OprRtRt2MemImm () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let rt2 = extract bin 15 12 + 1u |> getRegister |> OprReg
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let imm4H = extract bin 11 8
      let imm4L = extract bin 3 0
      let imm = concat imm4H imm4L 4 |> int64
      let sign = pickBit bin 23 |> getSign |> Some
      match concat (pickBit bin 24) (pickBit bin 21) 1 with
      | 0b10u -> memOffsetImm (rn, sign, if imm = 0L then None else Some imm)
      | 0b00u -> memPostIdxImm (rn, sign, Some imm)
      | 0b11u -> memPreIdxImm (rn, sign, Some imm)
      | _ (* 10 *) -> raise UnpredictableException
    OprInfo (ThreeOperands (rt, rt2, mem), wback bin, None)
    ///ThreeOperands (rt, rt2, mem)

(* <Rd>, <Rt>, [<Rn>] *)
type internal OprRdRtMem () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rt = extract bin 3 0 |> getRegister |> OprReg
    let mem = memOffsetImm (extract bin 19 16 |> getRegister, None, None)
    OprInfo (ThreeOperands (rd, rt, mem), false, None)
    ///ThreeOperands (rd, rt, mem)

(* <Rd>, <Rt>, [<Rn> {, {#}<imm>}] *)
type internal OprRdRtMemImm () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rt = extract bin 3 0 |> getRegister |> OprReg
    let mem = (* Rn, imm32 = 0 *)
      memOffsetImm (extract bin 19 16 |> getRegister, None, None)
    OprInfo (ThreeOperands (rd, rt, mem), false, None)
    ///ThreeOperands (rd, rt, mem)

(* p14, c5, [<Rn>], #{+/-}<imm> *)
type internal OprP14C5Mem () =
  inherit OperandParser ()
  override __.Render bin =
    let mem =
      let imm32 =
        match extract bin 9 8 (* size *) with
        | 0b01u -> (extract bin 7 0 (* imm8 *)) * 2u |> int64
        | _ -> (extract bin 7 0 (* imm8 *)) * 4u |> int64
      let rn = extract bin 19 16 |> getRegister
      let sign = pickBit bin 23 (* U *) |> getSign |> Some
      match concat (pickBit bin 24) (pickBit bin 21) 1 (* P:W *) with
      | 0b10u -> memOffsetImm (rn, sign, Some imm32)
      | 0b01u -> memPostIdxImm (rn, sign, Some imm32)
      | 0b11u -> memPreIdxImm (rn, sign, Some imm32)
      | _ -> raise ParsingFailureException
    OprInfo (ThreeOperands (OprReg R.P14, OprReg R.C5, mem), wbackW bin, None)
    ///ThreeOperands (OprReg R.P14, OprReg R.C5, mem)

(* p14, c5, [<Rn>], <option> *)
type internal OprP14C5Option () =
  inherit OperandParser ()
  override __.Render bin =
    let mem =
      let rn = extract bin 19 16 |> getRegister
      memUnIdxImm (rn, extract bin 7 0 (* imm8 *) |> int64)
    OprInfo (ThreeOperands (OprReg R.P14, OprReg R.C5, mem), wbackW bin, None)
    ///ThreeOperands (OprReg R.P14, OprReg R.C5, mem)

(* {<Rd>,} <Rn>, #<const> *)
type internal OprRdRnConst () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let cons = expandImmediate bin |> int64 |> OprImm
    OprInfo (ThreeOperands (rd, rn, cons), false, None)
    ///ThreeOperands (rd, rn, cons)

(* {<Rd>,} <Rn>, #<const> with carry *)
type internal OprRdRnConstCF () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let struct (imm32, carryOut) = expandImmCF bin
    OprInfo (ThreeOperands (rd, rn, imm32), false, carryOut)
    ///ThreeOperands (rd, rn, imm32)

(* {<Rd>,} SP, #<const> *)
type internal OprRdSPConst () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let cons = expandImmediate bin |> int64 |> OprImm
    OprInfo (ThreeOperands (rd, OprReg R.SP, cons), false, None)
    ///ThreeOperands (rd, OprReg R.SP, cons)

(* {<Rd>,} <Rm>, #<imm> : MOV alias *)
type internal OprRdRmImm () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let imm = extract bin 11 7 (* imm5 *) |> int64 |> OprImm
    OprInfo (ThreeOperands (rd, rm, imm), false, None)
    ///ThreeOperands (rd, rm, imm)

(* {<Dd>,} <Dm>, #<imm> *)
type internal OprDdDmImm () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    let imm6 = extract bin 21 16
    let imm =
      match concat (pickBit bin 7) (extract imm6 5 3) 3 (* L:imm6<5:3> *) with
      | 0b0000u -> raise ParsingFailureException
      | 0b0001u -> 16u - imm6
      | 0b0010u | 0b0011u (* 001x *) -> 32u - imm6
      | 0b0100u | 0b0101u | 0b0110u | 0b0111u (* 01xx *) -> 64u - imm6
      | _ (* 1xxx *) -> 64u - imm6
      |> int64 |> OprImm
    OprInfo (ThreeOperands (dd, dm, imm), false, None)
    ///ThreeOperands (dd, dm, imm)

(* {<Dd>,} <Dm>, #<imm> *)
type internal OprDdDmImmLeft () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    let imm6 = extract bin 21 16
    let imm =
      match concat (pickBit bin 7) (extract imm6 5 3) 3 (* L:imm6<5:3> *) with
      | 0b0000u -> raise ParsingFailureException
      | 0b0001u -> imm6 - 8u
      | 0b0010u | 0b0011u (* 001x *) -> imm6 - 16u
      | 0b0100u | 0b0101u | 0b0110u | 0b0111u (* 01xx *) -> imm6 - 32u
      | _ (* 1xxx *) -> imm6
      |> int64 |> OprImm
    OprInfo (ThreeOperands (dd, dm, imm), false, None)
    ///ThreeOperands (dd, dm, imm)

(* {<Qd>,} <Qm>, #<imm> *)
type internal OprQdQmImm () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let qm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecQReg |> toSVReg
    let imm6 = extract bin 21 16
    let imm =
      match concat (pickBit bin 7) (extract imm6 5 3) 3 (* L:imm6<5:3> *) with
      | 0b0000u -> raise ParsingFailureException
      | 0b0001u -> 16u - imm6
      | 0b0010u | 0b0011u (* 001x *) -> 32u - imm6
      | 0b0100u | 0b0101u | 0b0110u | 0b0111u (* 01xx *) -> 64u - imm6
      | _ (* 1xxx *) -> 64u - imm6
      |> int64 |> OprImm
    OprInfo (ThreeOperands (qd, qm, imm), false, None)
    ///ThreeOperands (qd, qm, imm)

(* {<Qd>,} <Qm>, #<imm> *)
type internal OprQdQmImmLeft () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let qm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecQReg |> toSVReg
    let imm6 = extract bin 21 16
    let imm =
      match concat (pickBit bin 7) (extract imm6 5 3) 3 (* L:imm6<5:3> *) with
      | 0b0000u -> raise ParsingFailureException
      | 0b0001u -> imm6 - 8u
      | 0b0010u | 0b0011u (* 001x *) -> imm6 - 16u
      | 0b0100u | 0b0101u | 0b0110u | 0b0111u (* 01xx *) -> imm6 - 32u
      | _ (* 1xxx *) -> imm6
      |> int64 |> OprImm
    OprInfo (ThreeOperands (qd, qm, imm), false, None)
    ///ThreeOperands (qd, qm, imm)

(* <Dd>, <Qm>, #<imm> *)
type internal OprDdQmImm () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let qm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecQReg |> toSVReg
    let imm6 = extract bin 21 16
    let imm =
      match extract imm6 5 3 (* imm6<5:3> *) with
      | 0b000u -> raise ParsingFailureException
      | 0b001u -> 16u - imm6
      | 0b010u | 0b011u (* 01x *) -> 32u - imm6
      | _ (* 1xx *) -> 64u - imm6
      |> int64 |> OprImm
    OprInfo (ThreeOperands (dd, qm, imm), false, None)
    ///ThreeOperands (dd, qm, imm)

(* <Qd>, <Dm>, #<imm> *)
type internal OprQdDmImm () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    let imm6 = extract bin 21 16
    let imm =
      match extract imm6 5 3 (* imm6<5:3> *) with
      | 0b000u -> raise ParsingFailureException
      | 0b001u -> imm6 - 8u
      | 0b010u | 0b011u (* 01x *) -> imm6 - 16u
      | _ (* 1xx *) -> imm6 - 32u
      |> int64 |> OprImm
    OprInfo (ThreeOperands (qd, dm, imm), false, None)
    ///ThreeOperands (qd, dm, imm)

(* <Qd>, <Dm>, #<imm> *)
type internal OprQdDmImm8 () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    OprInfo (ThreeOperands (qd, dm, OprImm 8L), false, None)
    ///ThreeOperands (qd, dm, OprImm 8L)

(* <Qd>, <Dm>, #<imm> *)
type internal OprQdDmImm16 () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    OprInfo (ThreeOperands (qd, dm, OprImm 16L), false, None)
    ///ThreeOperands (qd, dm, OprImm 16L)

(* <Qd>, <Dm>, #<imm> *)
type internal OprQdDmImm32 () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    OprInfo (ThreeOperands (qd, dm, OprImm 32L), false, None)
    ///ThreeOperands (qd, dm, OprImm 32L)

(* {<Dd>,} <Dm>, #0 *)
type internal OprDdDmImm0 () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    OprInfo (ThreeOperands (dd, dm, OprImm 0L), false, None)
    ///ThreeOperands (dd, dm, OprImm 0L)

(* {<Qd>,} <Qm>, #0 *)
type internal OprQdQmImm0 () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let qm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecQReg |> toSVReg
    OprInfo (ThreeOperands (qd, qm, OprImm 0L), false, None)
    ///ThreeOperands (qd, qm, OprImm 0L)

(* <Rn>, <Rm>, RRX *)
(* <Rn>, <Rm> {, <shift> #<amount>} *)
type internal OprRnRmShf () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let struct (shift, amount) =
      decodeImmShift (extract bin 6 5) (extract bin 11 7) (* stype imm5 *)
    OprInfo (ThreeOperands (rn, rm, OprShift (shift, Imm amount)), false, None)
    ///ThreeOperands (rn, rm, OprShift (shift, Imm amount))

(* <Rd>, <Rm>, RRX *)
(* <Rd>, <Rm> {, <shift> #<amount>} *)
type internal OprRdRmShf () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let struct (shift, amount) =
      decodeImmShift (extract bin 6 5) (extract bin 11 7) (* stype imm5 *)
    OprInfo (ThreeOperands (rd, rm, OprShift (shift, Imm amount)), false, None)
    ///ThreeOperands (rd, rm, OprShift (shift, Imm amount))

(* <Rn>, <Rm>, <type> <Rs> *)
type internal OprRnRmShfRs () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let shift =
      let rs = extract bin 11 8 |> getRegister
      OprRegShift (decodeRegShift (extract bin 6 5 (* stype *)), rs)
    OprInfo (ThreeOperands (rn, rm, shift), false, None)
    ///ThreeOperands (rn, rm, shift)

(* <Rd>, <Rm>, <shift> <Rs> *)
type internal OprRdRmShfRs () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let shift =
      let rs = extract bin 11 8 |> getRegister
      OprRegShift (decodeRegShift (extract bin 6 5 (* stype *)), rs)
    OprInfo (ThreeOperands (rd, rm, shift), false, None)
    ///ThreeOperands (rd, rm, shift)

(* {<Rd>,} <Rm> {, ROR #<amount>} *)
type internal OprRdRmROR () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let shift = OprShift (SRType.SRTypeROR, extract bin 11 10 <<< 3 |> Imm)
    OprInfo (ThreeOperands (rd, rm, shift), false, None)
    ///ThreeOperands (rd, rm, shift)

(* <Rd>, #<imm>, <Rn> *)
type internal OprRdImmRn () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let imm = extract bin 19 16 (* sat_imm *) + 1u |> int64 |> OprImm
    let rn = extract bin 3 0 |> getRegister |> OprReg
    OprInfo (ThreeOperands (rd, imm, rn), false, None)
    ///ThreeOperands (rd, imm, rn)

(* <Rd>, #<lsb>, #<width> *)
type internal OprRdLsbWidth () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let lsb = extract bin 11 7 |> int64 |> OprImm
    let width = (* msb - lsb + 1 *)
      (extract bin 20 16) - (extract bin 11 7) + 1u |> int64 |> OprImm
    OprInfo (ThreeOperands (rd, lsb, width), false, None)
    ///ThreeOperands (rd, lsb, width)

(* <Rt>, <Rt2>, <label> *)
type internal OprRtRt2Label () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let rt2 = extract bin 15 12 + 1u |> getRegister |> OprReg
    let label = (* imm4H:imm4L *)
      concat (extract bin 11 8) (extract bin 3 0) 4 |> int64 |> memLabel
    OprInfo (ThreeOperands (rt, rt2, label), false, None)
    ///ThreeOperands (rt, rt2, label)

(* p14, c5, <label> *)
type internal OprP14C5Label () =
  inherit OperandParser ()
  override __.Render bin =
    let label = extract bin 7 0 <<< 2 (* imm8:00 *) |> int64 |> memLabel
    OprInfo (ThreeOperands (OprReg R.P14, OprReg R.C5, label), wbackW bin, None)
    ///ThreeOperands (OprReg R.P14, OprReg R.C5, label)

(* <Sdm>, <Sdm>, #<fbits> *)
type internal OprSdmSdmFbits () =
  inherit OperandParser ()
  override __.Render bin =
    let sdm = (* Vd:D *)
      concat (extract bin 15 12) (pickBit bin 22) 1 |> getVecSReg |> toSVReg
    let fbits =
      let imm4i = concat (extract bin 3 0) (pickBit bin 5) 1 (* imm4:i *)
      if pickBit bin 7 = 0u then 16u - imm4i else 32u - imm4i
      |> int64 |> OprImm
    OprInfo (ThreeOperands (sdm, sdm, fbits), false, None)
    ///ThreeOperands (sdm, sdm, fbits)

(* <Ddm>, <Ddm>, #<fbits> *)
type internal OprDdmDdmFbits () =
  inherit OperandParser ()
  override __.Render bin =
    let ddm = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let fbits =
      let imm4i = concat (extract bin 3 0) (pickBit bin 5) 1 (* imm4:i *)
      if pickBit bin 7 = 0u then 16u - imm4i else 32u - imm4i
      |> int64 |> OprImm
    OprInfo (ThreeOperands (ddm, ddm, fbits), false, None)
    ///ThreeOperands (ddm, ddm, fbits)

(* <Dd>, <Dm>, #<fbits> *)
type internal OprDdDmFbits () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    let fbits = 64u - extract bin 21 16 |> int64 |> OprImm
    OprInfo (ThreeOperands (dd, dm, fbits), false, None)
    ///ThreeOperands (dd, dm, fbits)

(* <Qd>, <Qm>, #<fbits> *)
type internal OprQdQmFbits () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let qm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecQReg |> toSVReg
    let fbits = 64u - extract bin 21 16 |> int64 |> OprImm
    OprInfo (ThreeOperands (qd, qm, fbits), false, None)
    ///ThreeOperands (qd, qm, fbits)

(* <Dd>, <list>, <Dm> *)
type internal OprDdListDm () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let list =
      let n = concat (pickBit bin 7) (extract bin 19 16) 4 (* N:Vn *)
      match extract bin 9 8 (* len *) with
      | 0b00u -> [ n ]
      | 0b01u -> [ n; n + 1u ]
      | 0b10u -> [ n; n + 1u; n + 2u ]
      | _ (* 11u *) -> [ n; n + 1u; n + 2u; n + 3u ]
      |> List.map getVecDReg |> getSIMDVector
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    OprInfo (ThreeOperands (dd, list, dm), false, None)
    ///ThreeOperands (dd, list, dm)

(* <Rd>, <Rn>, <Rm>, <Ra> *)
type internal OprRdRnRmRa () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 19 16 |> getRegister |> OprReg
    let rn = extract bin 3 0 |> getRegister |> OprReg
    let rm = extract bin 11 8 |> getRegister |> OprReg
    let ra = extract bin 15 12 |> getRegister |> OprReg
    OprInfo (FourOperands (rd, rn, rm, ra), false, None)
    ///FourOperands (rd, rn, rm, ra)

(* <RdLo>, <RdHi>, <Rn>, <Rm> *)
type internal OprRdlRdhRnRm () =
  inherit OperandParser ()
  override __.Render bin =
    let rdLo = extract bin 15 12 |> getRegister |> OprReg
    let rdHi = extract bin 19 16 |> getRegister |> OprReg
    let rn = extract bin 3 0 |> getRegister |> OprReg
    let rm = extract bin 11 8 |> getRegister |> OprReg
    OprInfo (FourOperands (rdLo, rdHi, rn, rm), false, None)
    ///FourOperands (rdLo, rdHi, rn, rm)

(* <Sm>, <Sm1>, <Rt>, <Rt2> *)
type internal OprSmSm1RtRt2 () =
  inherit OperandParser ()
  override __.Render bin =
    let sm = (* Vm:M *)
      concat (extract bin 3 0) (pickBit bin 5) 1 |> getVecSReg |> toSVReg
    let sm1 = (* Vm:M *)
      concat (extract bin 3 0) (pickBit bin 5) 1 + 1u |> getVecSReg |> toSVReg
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let rt2 = extract bin 19 16 |> getRegister |> OprReg
    OprInfo (FourOperands (sm, sm1, rt, rt2), false, None)
    ///FourOperands (sm, sm1, rt, rt2)

(* <Rt>, <Rt2>, <Sm>, <Sm1> *)
type internal OprRtRt2SmSm1 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let rt2 = extract bin 19 16 |> getRegister |> OprReg
    let sm = (* Vm:M *)
      concat (extract bin 3 0) (pickBit bin 5) 1 |> getVecSReg |> toSVReg
    let sm1 = (* Vm:M *)
      concat (extract bin 3 0) (pickBit bin 5) 1 + 1u |> getVecSReg |> toSVReg
    OprInfo (FourOperands (rt, rt2, sm, sm1), false, None)
    ///FourOperands (rt, rt2, sm, sm1)

(* <Rd>, <Rt>, <Rt2>, [<Rn>] *)
type internal OprRdRtRt2Mem () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rt = extract bin 3 0 |> getRegister |> OprReg
    let rt2 = extract bin 3 0 + 1u |> getRegister |> OprReg
    let mem = memOffsetImm (extract bin 19 16 |> getRegister, None, None)
    OprInfo (FourOperands (rd, rt, rt2, mem), false, None)
    ///FourOperands (rd, rt, rt2, mem)

(* {<Dd>,} <Dn>, <Dm>, #<imm> *)
type internal OprDdDnDmImm () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let dn = (* N:Vn *)
      concat (pickBit bin 7) (extract bin 19 16) 4 |> getVecDReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    let imm = extract bin 11 8 (* imm4 *) |> int64 |> OprImm
    OprInfo (FourOperands (dd, dn, dm, imm), false, None)
    ///FourOperands (dd, dn, dm, imm)

(* {<Qd>,} <Qn>, <Qm>, #<imm> *)
type internal OprQdQnQmImm () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let qn = (* N:Vn *)
      concat (pickBit bin 7) (extract bin 19 16) 4 |> getVecQReg |> toSVReg
    let qm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecQReg |> toSVReg
    let imm = extract bin 11 8 (* imm4 *) |> int64 |> OprImm
    OprInfo (FourOperands (qd, qn, qm, imm), false, None)
    ///FourOperands (qd, qn, qm, imm)

(* {<Rd>,} <Rn>, <Rm>, RRX *)
(* {<Rd>,} <Rn>, <Rm> {, <shift> #<amount>} *)
type internal OprRdRnRmShf () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let struct (shift, amount) = (* stype imm5 *)
      decodeImmShift (extract bin 6 5) (extract bin 11 7)
    OprInfo (FourOperands (rd, rn, rm, OprShift (shift, Imm amount)), false, None)
    ///FourOperands (rd, rn, rm, OprShift (shift, Imm amount))

(* {<Rd>,} <Rn>, <Rm>, <shift> <Rs> *)
type internal OprRdRnRmShfRs () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let shift =
      let rs = extract bin 11 8 |> getRegister
      OprRegShift (decodeRegShift (extract bin 6 5), rs)
    OprInfo (FourOperands (rd, rn, rm, shift), false, None)
    ///FourOperands (rd, rn, rm, shift)

(* {<Rd>,} <Rn>, <Rm> {, ROR #<amount>} *)
type internal OprRdRnRmROR () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let shift = OprShift (SRType.SRTypeROR, extract bin 11 10 <<< 3 |> Imm)
    OprInfo (FourOperands (rd, rn, rm, shift), false, None)
    ///FourOperands (rd, rn, rm, shift)

(* <Rd>, #<imm>, <Rn>, ASR #<amount> *)
(* <Rd>, #<imm>, <Rn>, LSL #<amount> *)
type internal OprRdImmRnShf () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let imm = extract bin 20 16 (* sat_imm *) + 1u |> int64 |> OprImm
    let rn = extract bin 3 0 |> getRegister |> OprReg
    let struct (sTyp, amount) = (* sh:'0' *) (* imm5 *)
      decodeImmShift (extract bin 6 5) (extract bin 11 7)
    OprInfo (FourOperands (rd, imm, rn, OprShift (sTyp, Imm amount)), false, None)
    ///FourOperands (rd, imm, rn, OprShift (sTyp, Imm amount))

(* <Rd>, <Rn>, #<lsb>, #<width> *)
type internal OprRdRnLsbWidth () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rn = extract bin 3 0 |> getRegister |> OprReg
    let lsb = extract bin 11 7 |> int64 |> OprImm
    let width = (* msb - lsb + 1 *)
      (extract bin 20 16) - (extract bin 11 7) + 1u |> int64 |> OprImm
    OprInfo (FourOperands (rd, rn, lsb, width), false, None)
    ///FourOperands (rd, rn, lsb, width)

(* <Rd>, <Rn>, #<lsb>, #<width> *)
type internal OprRdRnLsbWidthM1 () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rn = extract bin 3 0 |> getRegister |> OprReg
    let lsb = extract bin 11 7 |> int64 |> OprImm
    let width = (* widthm1 + 1 *)
      (extract bin 20 16 (* widthm1 *)) + 1u |> int64 |> OprImm
    OprInfo (FourOperands (rd, rn, lsb, width), false, None)
    ///FourOperands (rd, rn, lsb, width)

(* <Dd>, <Dn>, <Dm>, #<rotate> *)
type internal OprDdDnDmRotate () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let dn = (* N:Vn *)
      concat (pickBit bin 7) (extract bin 19 16) 4 |> getVecDReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    let rotate =
      match extract bin 24 23 (* rot *) with
      | 0b00u -> 0L
      | 0b01u -> 90L
      | 0b10u -> 180L
      | _ (* 11 *) -> 270L
      |> OprImm
    OprInfo (FourOperands (dd, dn, dm, rotate), false, None)
    ///FourOperands (dd, dn, dm, rotate)

(* <Qd>, <Qn>, <Qm>, #<rotate> *)
type internal OprQdQnQmRotate () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let qn = (* N:Vn *)
      concat (pickBit bin 7) (extract bin 19 16) 4 |> getVecQReg |> toSVReg
    let qm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecQReg |> toSVReg
    let rotate =
      match extract bin 24 23 (* rot *) with
      | 0b00u -> 0L
      | 0b01u -> 90L
      | 0b10u -> 180L
      | _ (* 11 *) -> 270L
      |> OprImm
    OprInfo (FourOperands (qd, qn, qm, rotate), false, None)
    ///FourOperands (qd, qn, qm, rotate)

(* <Dd>, <Dn>, <Dm>[<index>], #<rotate> *)
type internal OprDdDnDmidxRotate () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let dn = (* N:Vn *)
      concat (pickBit bin 7) (extract bin 19 16) 4 |> getVecDReg |> toSVReg
    let dmidx (* Reg: Vm, Index: M *)  =
      toSSReg (extract bin 3 0 |> getVecDReg, Some (pickBit bin 5 |> uint8))
    let rotate =
      match extract bin 21 20 (* rot *) with
      | 0b00u -> 0L
      | 0b01u -> 90L
      | 0b10u -> 180L
      | _ (* 11 *) -> 270L
      |> OprImm
    OprInfo (FourOperands (dd, dn, dmidx, rotate), false, None)
    ///FourOperands (dd, dn, dmidx, rotate)

(* <Qd>, <Qn>, <Dm>[<index>], #<rotate> *)
type internal OprQdQnDmidxRotate () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let qn = (* N:Vn *)
      concat (pickBit bin 7) (extract bin 19 16) 4 |> getVecQReg |> toSVReg
    let dmidx (* Reg: Vm, Index: M *)  =
      toSSReg (extract bin 3 0 |> getVecDReg, Some (pickBit bin 5 |> uint8))
    let rotate =
      match extract bin 21 20 (* rot *) with
      | 0b00u -> 0L
      | 0b01u -> 90L
      | 0b10u -> 180L
      | _ (* 11 *) -> 270L
      |> OprImm
    OprInfo (FourOperands (qd, qn, dmidx, rotate), false, None)
    ///FourOperands (qd, qn, dmidx, rotate)

(* <Dd>, <Dn>, <Dm>[0], #<rotate> *)
type internal OprDdDnDm0Rotate () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let dn = (* N:Vn *)
      concat (pickBit bin 7) (extract bin 19 16) 4 |> getVecDReg |> toSVReg
    let dm0 (* M:Vm *)  =
      toSSReg (concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg, Some 0uy)
    let rotate =
      match extract bin 21 20 (* rot *) with
      | 0b00u -> 0L
      | 0b01u -> 90L
      | 0b10u -> 180L
      | _ (* 11 *) -> 270L
      |> OprImm
    OprInfo (FourOperands (dd, dn, dm0, rotate), false, None)
    ///FourOperands (dd, dn, dm0, rotate)

(* <Qd>, <Qn>, <Dm>[0], #<rotate> *)
type internal OprQdQnDm0Rotate () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let qn = (* N:Vn *)
      concat (pickBit bin 7) (extract bin 19 16) 4 |> getVecQReg |> toSVReg
    let dm0 (* M:Vm *)  =
      toSSReg (concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg, Some 0uy)
    let rotate =
      match extract bin 21 20 (* rot *) with
      | 0b00u -> 0L
      | 0b01u -> 90L
      | 0b10u -> 180L
      | _ (* 11 *) -> 270L
      |> OprImm
    OprInfo (FourOperands (qd, qn, dm0, rotate), false, None)
    ///FourOperands (qd, qn, dm0, rotate)

(* <coproc>, {#}<opc1>, <Rt>, <Rt2>, <CRm> *)
type internal OprCpOpc1RtRt2CRm () =
  inherit OperandParser ()
  override __.Render bin =
    let coproc = extract bin 11 8 |> getCoprocDReg |> OprReg
    let opc1 = extract bin 7 4 |> int64 |> OprImm
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let rt2 = extract bin 19 16 |> getRegister |> OprReg
    let crm = extract bin 3 0 |> getCoprocCReg |> OprReg
    OprInfo (FiveOperands (coproc, opc1, rt, rt2, crm), false, None)
    ///FiveOperands (coproc, opc1, rt, rt2, crm)

(* <coproc>, {#}<opc1>, <Rt>, <CRn>, <CRm>{, {#}<opc2>} *)
type internal OprCpOpc1RtCRnCRmOpc2 () =
  inherit OperandParser ()
  override __.Render bin =
    let coproc = extract bin 11 8 |> getCoprocDReg |> OprReg
    let opc1 = extract bin 23 21 |> int64 |> OprImm
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let crn = extract bin 19 16 |> getCoprocCReg |> OprReg
    let crm = extract bin 3 0 |> getCoprocCReg |> OprReg
    let opc2 = extract bin 7 5 |> int64 |> OprImm
    OprInfo (SixOperands (coproc, opc1, rt, crn, crm, opc2), false, None)
    ///SixOperands (coproc, opc1, rt, crn, crm, opc2)

(* <coproc>, <opc1>, <CRd>, <CRn>, <CRm>, <opc2> *)
type internal OprCpOpc1CRdCRnCRmOpc2 () =
  inherit OperandParser ()
  override __.Render bin =
    let coproc = extract bin 11 8 |> getCoprocDReg |> OprReg
    let opc1 = extract bin 23 21 |> int64 |> OprImm
    let crd = extract bin 15 12 |> getCoprocCReg |> OprReg
    let crn = extract bin 19 16 |> getCoprocCReg |> OprReg
    let crm = extract bin 3 0 |> getCoprocCReg |> OprReg
    let opc2 = extract bin 7 5 |> int64 |> OprImm
    OprInfo (SixOperands (coproc, opc1, crd, crn, crm, opc2), false, None)
    ///SixOperands (coproc, opc1, crd, crn, crm, opc2)

(* <coproc>, <CRd>, [<Rn>, #+/-<imm>]{!}
   <coproc>, <CRd>, [<Rn>], #+/-<imm>
   <coproc>, <CRd>, [<Rn>], <option> *)
type internal OprCoprocCRdMem () =
  inherit OperandParser ()
  override __.Render bin =
    let coproc = extract bin 11 8 |> getCoprocDReg |> OprReg
    let crd = extract bin 15 12 |> getCoprocCReg |> OprReg
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let imm = extract bin 7 0 <<< 2 |> int64
      let sign = pickBit bin 23 |> getSign |> Some
      match concat (pickBit bin 24) (pickBit bin 21) 1 (* P:W *) with
      | 0b10u -> memOffsetImm (rn, sign, Some imm)
      | 0b11u -> memPreIdxImm (rn, sign, Some imm)
      | 0b01u -> memPostIdxImm (rn, sign, Some imm)
      | 0b00u when pickBit bin 23 = 1u ->
        memUnIdxImm (rn, extract bin 7 0 (* imm8 *) |> int64)
      | _ (* 00 *) -> raise UndefinedException
    OprInfo (ThreeOperands (coproc, crd, mem), wbackW bin, None)
    ///ThreeOperands (coproc, crd, mem)

// vim: set tw=80 sts=2 sw=2:
