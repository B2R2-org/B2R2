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
  /// A32/T16/T32 operands
  | OprNo = 0
  | OprBankregRnA = 1
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
  | OprDdImm0 = 28
  | OprDdImmA = 29
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
  | OprEndianA = 43
  | OprIflagsA = 44
  | OprIflagsModeA = 45
  | OprImm16A = 46
  | OprImm1A = 47
  | OprImm24 = 48
  | OprImm4A = 49
  | OprLabel12A = 50
  | OprLabelA = 51
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
  | OprMemRegA = 63
  | OprMode = 64
  | OprOpt = 65
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
  | OprQdImmA = 78
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
  | OprRdBankregA = 95
  | OprRdConstA = 96
  | OprRdConstCF = 97
  | OprRdImm16A = 98
  | OprRdImmRnA = 99
  | OprRdImmRnShfA = 100
  | OprRdImmRnShfUA = 101
  | OprRdLabelA = 102
  | OprRdlRdhRnRmA = 103
  | OprRdLsbWidthA = 104
  | OprRdRm = 105
  | OprRdRmImmA = 106
  | OprRdRmRnA = 107
  | OprRdRmRorA = 108
  | OprRdRmRs = 109
  | OprRdRmShf = 110
  | OprRdRmShfRsA = 111
  | OprRdRnConstA = 112
  | OprRdRnConstCF = 113
  | OprRdRnLsbWidthA = 114
  | OprRdRnLsbWidthM1A = 115
  | OprRdRnRm = 116
  | OprRdRnRmOpt = 117
  | OprRdRnRmRaA = 118
  | OprRdRnRmRorA = 119
  | OprRdRnRmShfA = 120
  | OprRdRnRmShfRs = 121
  | OprRdRtMemA = 122
  | OprRdRtMemImmA = 123
  | OprRdRtRt2MemA = 124
  | OprRdSPConstA = 125
  | OprRdSregA = 126
  | OprRegs = 127
  | OprRm = 128
  | OprRn = 129
  | OprRnConstA = 130
  | OprRnConstCF = 131
  | OprRnDreglist = 132
  | OprRnRegsA = 133
  | OprRnRegsCaret = 134
  | OprRnRmShfA = 135
  | OprRnRmShfRs = 136
  | OprRnSreglist = 137
  | OprRt15Mem = 138
  | OprRtDn0 = 139
  | OprRtDn1 = 140
  | OprRtDn2 = 141
  | OprRtDn3 = 142
  | OprRtDn4 = 143
  | OprRtDn5 = 144
  | OprRtDn6 = 145
  | OprRtDn7 = 146
  | OprRtLabelA = 147
  | OprRtLabelHL = 148
  | OprRtMem = 149
  | OprRtMemImm = 150
  | OprRtMemImm0A = 151
  | OprRtMemImm12A = 152
  | OprRtMemImm12P = 153
  | OprRtMemImmP = 154
  | OprRtMemReg = 155
  | OprRtMemRegP = 156
  | OprRtMemShf = 157
  | OprRtMemShfP = 158
  | OprRtRt2Dm = 159
  | OprRtRt2LabelA = 160
  | OprRtRt2Mem2 = 161
  | OprRtRt2MemA = 162
  | OprRtRt2MemImmA = 163
  | OprRtRt2MemReg = 164
  | OprRtRt2SmSm1 = 165
  | OprRtSn = 166
  | OprRtSreg = 167
  | OprSdDm = 168
  | OprSdImm0 = 169
  | OprSdLabel = 170
  | OprSdMem = 171
  | OprSdmSdmFbits = 172
  | OprSdSm = 173
  | OprSdSnSm = 174
  | OprSdVImm = 175
  | OprSingleRegs = 176
  | OprSmSm1RtRt2 = 177
  | OprSnRt = 178
  | OprSPMode = 179
  | OprSregImm = 180
  | OprSregRnA = 181
  | OprSregRt = 182
  | OprBankregRnT = 183
  | OprCondition = 184
  | OprDdDm0 = 185
  | OprDdImmT = 186
  | OprEndianT = 187
  | OprIflagsModeT = 188
  | OprIflagsT = 189
  | OprImm16T = 190
  | OprImm1T = 191
  | OprImm4T = 192
  | OprImm6 = 193
  | OprImm8 = 194
  | OprLabel12T = 195
  | OprLabel8 = 196
  | OprLabelT = 197
  | OprLabelT2 = 198
  | OprLabelT3 = 199
  | OprLabelT4 = 200
  | OprMemImm12 = 201
  | OprMemImm8M = 202
  | OprMemRegLSL = 203
  | OprMemRegLSL1 = 204
  | OprMemRegT = 205
  | OprPCLRImm8 = 206
  | OprQdImmT = 207
  | OprQdQm0 = 208
  | OprRdBankregT = 209
  | OprRdConstT = 210
  | OprRdImm16T = 211
  | OprRdImm8 = 212
  | OprRdImmRnShfT = 213
  | OprRdImmRnShfUT = 214
  | OprRdImmRnT = 215
  | OprRdImmRnU = 216
  | OprRdLabelT = 217
  | OprRdlRdhRnRmT = 218
  | OprRdLsbWidthT = 219
  | OprRdmRdmASRRs = 220
  | OprRdmRdmLSLRs = 221
  | OprRdmRdmLSRRs = 222
  | OprRdmRdmRORRs = 223
  | OprRdmRnRdm = 224
  | OprRdmSPRdm = 225
  | OprRdnImm8 = 226
  | OprRdnRdnRm = 227
  | OprRdnRm = 228
  | OprRdRmExt = 229
  | OprRdRmImmT = 230
  | OprRdRmRnT = 231
  | OprRdRmRorT = 232
  | OprRdRmShfRsT = 233
  | OprRdRmShfT16 = 234
  | OprRdRmShfT32 = 235
  | OprRdRmT16 = 236
  | OprRdRmT32 = 237
  | OprRdRn0 = 238
  | OprRdRn0T32 = 239
  | OprRdRnConstT = 240
  | OprRdRnImm12 = 241
  | OprRdRnImm3 = 242
  | OprRdRnLsbWidthM1T = 243
  | OprRdRnLsbWidthT = 244
  | OprRdRnRmRaT = 245
  | OprRdRnRmRorT = 246
  | OprRdRnRmShfT = 247
  | OprRdRnRmT16 = 248
  | OprRdRnRmT32 = 249
  | OprRdRtMemImmT = 250
  | OprRdRtMemT = 251
  | OprRdRtRt2MemT = 252
  | OprRdSPConstT = 253
  | OprRdSPImm12 = 254
  | OprRdSPImm8 = 255
  | OprRdSPRmShf = 256
  | OprRdSregT = 257
  | OprRegsM = 258
  | OprRegsP = 259
  | OprRm16 = 260
  | OprRm32 = 261
  | OprRnConstT = 262
  | OprRnLabel = 263
  | OprRnRegsT = 264
  | OprRnRegsW = 265
  | OprRnRm = 266
  | OprRnRmExt = 267
  | OprRnRmShfT = 268
  | OprRtLabel12 = 269
  | OprRtLabelT = 270
  | OprRtMemImm0T = 271
  | OprRtMemImm1 = 272
  | OprRtMemImm12T = 273
  | OprRtMemImm2 = 274
  | OprRtMemImm8 = 275
  | OprRtMemImm8M = 276
  | OprRtMemImm8P = 277
  | OprRtMemImmPr = 278
  | OprRtMemImmPs = 279
  | OprRtMemReg16 = 280
  | OprRtMemReg32 = 281
  | OprRtMemRegLSL = 282
  | OprRtMemSP = 283
  | OprRtRt2LabelT = 284
  | OprRtRt2MemImmT = 285
  | OprRtRt2MemT = 286
  | OprSPSPImm7 = 287
  | OprSPSPRm = 288
  | OprSregRnT = 289

type OD = OprDesc

module OperandParsingHelper =

  /// shared/functions/common/Replicate on page J1-7848.
  let replicate value bits oprSize =
    let rec loop acc shift =
      if shift >= RegType.toBitWidth oprSize then acc
      else loop (acc ||| (value <<< shift)) (shift + bits)
    loop value bits

  /// shared/functions/vector/AdvSIMDExpandImm on page J1-7926.
  let advSIMDExpandImm bin i =
    let cmode = extract bin 11 8
    let cmode0 = pickBit cmode 0 (* cmode<0> *)
    let op = pickBit bin 5
    let imm8 = (i <<< 7) + (extract bin 18 16 <<< 4) + (extract bin 3 0)
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
  let signExtend bitSize (bits: uint32) =
    bits |> uint64 |> signExtend bitSize 32 |> System.Convert.ToInt64 |> memLabel

  /// shared/functions/common/BitCount on page J1-7845.
  let bitCount bits len =
    let rec loop cnt idx =
      if idx > len then cnt
      elif ((bits >>> idx) &&& 0b1u) = 1u then loop (cnt + 1) (idx + 1)
      else loop cnt (idx + 1)
    loop 0 0

  /// Data Type parsing
  (* S8  when U = 0, size = 00
     S16 when U = 0, size = 01
     S32 when U = 0, size = 10
     U8  when U = 1, size = 00
     U16 when U = 1, size = 01
     U32 when U = 1, size = 10 *)
  let getDtA bin =
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
  let getDTLImmA bin =
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
  let getDTUImm3hA bin =
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

  let getDTImm6WordA bin =
    let isSign = pickBit bin 24 (* U *) = 0u
    match extract bin 21 19 (* imm6<5:3> *) with
    | 0b000u -> raise ParsingFailureException
    | 0b001u -> if isSign then SIMDTypS16 else SIMDTypU16
    | 0b010u | 0b011u (* 01x *) -> if isSign then SIMDTypS32 else SIMDTypU32
    | _ (* 1xx *) -> if isSign then SIMDTypS64 else SIMDTypU64
    |> oneDt

  let getDTImm6ByteA bin =
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

  /// Thumb operands
  let updateITSTATE (itstate: byref<byte list>) =
    itstate <- List.tail itstate

  let getCondWithITSTATE itstate =
    match List.tryHead itstate with
    | Some st -> st |> parseCond |> Some
    | None -> Condition.AL |> Some

  /// aarch32/functions/common/T32ExpandImm_C on page J1-7767.
  // T32ExpandImm_C()
  // ================
  /// Modified immediate constants in A32 inOprInfoions on page F2-4135.
  let t32ExpandImm imm12 = (* _carryIn = *)
    if extract imm12 11 10 = 0b00u then
      let imm8 = extract imm12 7 0 (* imm12<7:0> *)
      let imm32 =
        match extract imm12 9 8 with
        | 0b00u -> imm8
        | 0b01u -> (imm8 <<< 16) + imm8
        | 0b10u -> (imm8 <<< 24) + (imm8 <<< 8)
        | _ (* 11 *) -> (imm8<<< 24) + (imm8 <<< 16) + (imm8 <<< 8) + imm8
      (* OprInfo (imm32, carryIn) *) /// FIMXE: carry = PSTATE.C
      imm32
    else
      let value = (1u <<< 7) + (extract imm12 6 0)
      let rotation = (extract imm12 11 7) % 32u |> int
      let imm32 =
        if rotation = 0 then value
        else (value >>> rotation) ||| (value <<< (32 - rotation))
      let _carryOut = pickBit imm32 (32 - 1)
      (* OprInfo (imm32, carryOut) *) /// FIMXE: carry = PSTATE.C
      imm32

  (* W == '1' *)
  let wbackW8 bin = pickBit bin 8 = 0b1u

  (* S8  when U = 0, size = 00
     S16 when U = 0, size = 01
     S32 when U = 0, size = 10
     U8  when U = 1, size = 00
     U16 when U = 1, size = 01
     U32 when U = 1, size = 10 *)
  let getDtT bin = (* FIXME: Integration with ARM32 *)
    match concat (pickBit bin 28) (extract bin 21 20) 2 (* U:size *) with
    | 0b000u -> SIMDTypS8
    | 0b001u -> SIMDTypS16
    | 0b010u -> SIMDTypS32
    | 0b100u -> SIMDTypU8
    | 0b101u -> SIMDTypU16
    | 0b110u -> SIMDTypU32
    | _ -> Utils.impossible ()

  (* U16 when size = 01
     U32 when size = 10 *)
  let getDTUSign = function (* [21:20] *)
    | 0b01u -> SIMDTypU16
    | 0b10u -> SIMDTypU32
    | _ -> raise UndefinedException

  (* 8 when  L = 0, imm6<5:3> = 001
     16 when L = 0, imm6<5:3> = 01x
     32 when L = 0, imm6<5:3> = 1xx
     64 when L = 1, imm6<5:3> = xxx *)
  let getDTLImmT bin = (* FIXME: Integration with ARM32 *)
    let isSign = pickBit bin 28 (* U *) = 0u
    match concat (pickBit bin 7) (extract bin 21 19) 3 (* L:imm6<5:3> *) with
    | 0b0000u -> Utils.impossible ()
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
  let getDTUImm3hT bin = (* FIXME: Integration with ARM32 *)
    match concat (pickBit bin 28) (extract bin 21 19) 3 (* U:imm3H *) with
    | 0b0001u -> SIMDTypS8
    | 0b0010u -> SIMDTypS16
    | 0b0100u -> SIMDTypS32
    | 0b1001u -> SIMDTypU8
    | 0b1010u -> SIMDTypU16
    | 0b1100u -> SIMDTypU32
    | _ -> Utils.impossible ()
    |> oneDt

  (* S when U = 0
     U when U = 1
     16 when imm6<5:3> = 001
     32 when imm6<5:3> = 01x
     64 when imm6<5:3> = 1xx *)
  let getDTImm6WordT bin = (* FIXME: Integration with ARM32 *)
    let isSign = pickBit bin 28 (* U *) = 0u
    match extract bin 21 19 (* imm6<5:3> *) with
    | 0b000u -> Utils.impossible ()
    | 0b001u -> if isSign then SIMDTypS16 else SIMDTypU16
    | 0b010u | 0b011u (* 01x *) -> if isSign then SIMDTypS32 else SIMDTypU32
    | _ (* 1xx *) -> if isSign then SIMDTypS64 else SIMDTypU64
    |> oneDt

  let getDTImm6ByteT bin = (* FIXME: Integration with ARM32 *)
    let isSign = pickBit bin 28 (* U *) = 0u
    match extract bin 21 19 (* imm6<5:3> *) with
    | 0b000u -> Utils.impossible ()
    | 0b001u -> if isSign then SIMDTypS8 else SIMDTypU8
    | 0b010u | 0b011u (* 01x *) -> if isSign then SIMDTypS16 else SIMDTypU16
    | _ (* 1xx *) -> if isSign then SIMDTypS32 else SIMDTypU32
    |> oneDt

  let getDTPoly b =
    (* op:U:size *)
    match (pickBit b 9 <<< 3) + (pickBit b 28 <<< 2) + (extract b 21 20) with
    | 0b0000u -> SIMDTypS8
    | 0b0001u -> SIMDTypS16
    | 0b0010u -> SIMDTypS32
    | 0b0100u -> SIMDTypU8
    | 0b0101u -> SIMDTypU16
    | 0b0110u -> SIMDTypU32
    | 0b1000u -> SIMDTypP8
    | 0b1010u -> SIMDTypP64
    | _ -> raise UndefinedException

  let getDTFP bin =
    match extract bin 9 8 (* size *) with
    | 0b00u -> raise UndefinedException
    | 0b01u -> SIMDTypF16
    | 0b10u -> SIMDTypF32
    | _ (* 11 *) -> SIMDTypF64
    |> oneDt

  /// Data types: FP, sign, unsign
  let getDTFSU bin =
    match extract bin 9 7 (* size:op *) with
    | 0b000u | 0b001u -> raise UndefinedException
    | 0b010u -> SIMDTypF16, SIMDTypU32
    | 0b011u -> SIMDTypF16, SIMDTypS32
    | 0b100u -> SIMDTypF32, SIMDTypU32
    | 0b101u -> SIMDTypF32, SIMDTypS32
    | 0b110u -> SIMDTypF64, SIMDTypU32
    | _ (* 111 *) -> SIMDTypF64, SIMDTypS32
    |> twoDt

  let getDTOpU bin =
    let opU = concat (extract bin 9 8) (pickBit bin 28) 1 (* op:U *)
    let dt1 =
      match opU with
      | 0b000u | 0b001u (* 00x *) -> SIMDTypF16
      | 0b010u -> SIMDTypS16
      | 0b011u -> SIMDTypU16
      | 0b100u | 0b101u (* 10x *) -> SIMDTypF32
      | 0b110u -> SIMDTypS32
      | _ (* 111 *) -> SIMDTypU32
    let dt2 =
      match opU with
      | 0b000u -> SIMDTypS16
      | 0b001u -> SIMDTypU16
      | 0b010u | 0b011u (* 01x *) -> SIMDTypF16
      | 0b100u -> SIMDTypS32
      | 0b101u -> SIMDTypU32
      | _ (* 11x *) -> SIMDTypF32
    twoDt (dt1, dt2)


  let inverseCond cond =
    (cond &&& 0xeuy) ||| ((~~~ cond) &&& 0b1uy)

  let getITOpcodeWithX cond x =
    let invCond = inverseCond cond
    if x then Op.ITT, [ cond; cond ] else Op.ITE, [ cond; invCond ]

  let getITOpcodeWithXY cond x y =
    let invCond = inverseCond cond
    match x, y with
    | true, true -> Op.ITTT, [ cond; cond; cond ]
    | true, false -> Op.ITTE, [ cond; cond; invCond ]
    | false, true -> Op.ITET, [ cond; invCond; cond ]
    | false, false -> Op.ITEE, [ cond; invCond; invCond ]

  let getITOpcodeWithXYZ cond x y z =
    let invCond = inverseCond cond
    match x, y, z with
    | true, true, true -> Op.ITTTT, [ cond; cond; cond; cond ]
    | true, true, false -> Op.ITTTE, [ cond; cond; cond; invCond ]
    | true, false, true -> Op.ITTET, [ cond; cond; invCond; cond ]
    | true, false, false -> Op.ITTEE, [ cond; cond; invCond; invCond ]
    | false, true, true -> Op.ITETT, [ cond; invCond; cond; cond ]
    | false, true, false -> Op.ITETE, [ cond; invCond; cond; invCond ]
    | false, false, true -> Op.ITEET, [ cond; invCond; invCond; cond ]
    | false, false, false -> Op.ITEEE, [ cond; invCond; invCond; invCond ]

  let getIT fstCond cond mask =
    let mask0 = pickBit mask 0
    let mask1 = pickBit mask 1
    let mask2 = pickBit mask 2
    let mask3 = pickBit mask 3
    let x = fstCond = pickBit mask 3
    let y = fstCond = pickBit mask 2
    let z = fstCond = pickBit mask 1
    let opcode, itState =
      match mask3, mask2, mask1, mask0 with
      | 0b1u, 0b0u, 0b0u, 0b0u -> Op.IT, [ cond ]
      | _, 0b1u, 0b0u, 0b0u -> getITOpcodeWithX cond x
      | _, _, 0b1u, 0b0u -> getITOpcodeWithXY cond x y
      | _, _, _, 0b1u -> getITOpcodeWithXYZ cond x y z
      | _ -> failwith "Wrong opcode in IT instruction"
    opcode, itState

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
    OprInfo (NoOperand, false, None)

(* <Rn>{!} *)
type internal OprRn () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister |> OprReg
    OprInfo (OneOperand rn, wbackW bin, None)

(* <Rm> *)
type internal OprRm () =
  inherit OperandParser ()
  override __.Render bin =
    let rm = extract bin 3 0 |> getRegister |> OprReg
    OprInfo (OneOperand rm, false, None)

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

(* [<Rn>, {+/-}<Rm> , RRX] *)
(* [<Rn>, {+/-}<Rm> {, <shift> #<amount>}] *)
type internal OprMemRegA () =
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

(* {#}<imm> *)
type internal OprImm16A () =
  inherit OperandParser ()
  override __.Render bin =
    let imm = concat (extract bin 19 8) (extract bin 3 0) 4 |> int64 |> OprImm
    OprInfo (OneOperand imm, false, None)

(* {#}<imm> *)
type internal OprImm24 () =
  inherit OperandParser ()
  override __.Render bin =
    OprInfo (extract bin 23 0 |> int64 |> OprImm |> OneOperand, false, None)

(* {#}<imm4> *)
type internal OprImm4A () =
  inherit OperandParser ()
  override __.Render bin =
    OprInfo (extract bin 3 0 |> int64 |> OprImm |> OneOperand, false, None)

(* #<imm> *)
type internal OprImm1A () =
  inherit OperandParser ()
  override __.Render bin =
    OprInfo (pickBit bin 9 |> int64 |> OprImm |> OneOperand, false, None)

(* [<Rn> {, #{+/-}<imm>}]
   <label> Normal form
   [PC, #{+/-}<imm>] Alternative form *)
type internal OprLabel12A () =
  inherit OperandParser ()
  override __.Render bin =
    let imm12 = extract bin 11 0 |> int64
    let label =
      if pickBit bin 23 = 1u then memLabel imm12 else memLabel (imm12 * -1L)
    OprInfo (OneOperand label, false, None)

(* <label> *)
type internal OprLabelA () =
  inherit OperandParser ()
  override __.Render bin =
    let label = extract bin 23 0 <<< 2 |> signExtend 26
    OprInfo (OneOperand label, false, None)

(* <label> *)
type internal OprLabelH () =
  inherit OperandParser ()
  override __.Render bin =
    let label =
      (concat (extract bin 23 0) (pickBit bin 24) 1) <<< 1 |> signExtend 26
    OprInfo (OneOperand label, false, None)

(* {<option>} *)
type internal OprOpt () =
  inherit OperandParser ()
  override __.Render bin =
    let option = extract bin 3 0 |> getOption |> OprOption
    OprInfo (OneOperand option, false, None)

(* <endian_specifier> *)
type internal OprEndianA () =
  inherit OperandParser ()
  override __.Render bin =
    let endian = pickBit bin 9 |> byte |> getEndian |> OprEndian
    OprInfo (OneOperand endian, false, None)

(* <registers> *)
type internal OprRegs () =
  inherit OperandParser ()
  override __.Render bin =
    let regs = extract bin 15 0 |> getRegList |> OprRegList
    OprInfo (OneOperand regs, false, None)

(* <single_register_list> *)
type internal OprSingleRegs () =
  inherit OperandParser ()
  override __.Render bin =
    let regs = OprRegList [ extract bin 15 12 |> getRegister ]
    OprInfo (OneOperand regs, wback bin, None)

(* #<mode> *)
type internal OprMode () =
  inherit OperandParser ()
  override __.Render bin =
    OprInfo (OneOperand (extract bin 4 0 |> int64 |> OprImm), false, None)

(* <iflags> *)
type internal OprIflagsA () =
  inherit OperandParser ()
  override __.Render bin =
    OprInfo (OneOperand (OprIflag (getIflag (extract bin 8 6))), false, None)

(* <Rd>, <Rm> *)
type internal OprRdRm () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    OprInfo (TwoOperands (rd, rm), false, None)

(* <Sd>, <Sm> *)
type internal OprSdSm () =
  inherit OperandParser ()
  override __.Render bin =
    let sd = (* Vd:D *)
      concat (extract bin 15 12) (pickBit bin 22) 1 |> getVecSReg |> toSVReg
    let sm = (* Vm:M *)
      concat (extract bin 3 0) (pickBit bin 5) 1 |> getVecSReg |> toSVReg
    OprInfo (TwoOperands (sd, sm), false, None)

(* <Dd>, <Dm> *)
type internal OprDdDm () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    OprInfo (TwoOperands (dd, dm), false, None)

(* <Dd>, <Sm> *)
type internal OprDdSm () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let sm = (* Vm:M *)
      concat (extract bin 3 0) (pickBit bin 5) 1 |> getVecSReg |> toSVReg
    OprInfo (TwoOperands (dd, sm), false, None)

(* <Sd>, <Dm> *)
type internal OprSdDm () =
  inherit OperandParser ()
  override __.Render bin =
    let sd = (* Vd:D *)
      concat (extract bin 15 12) (pickBit bin 22) 1 |> getVecSReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    OprInfo (TwoOperands (sd, dm), false, None)

(* <Sn>, <Rt> *)
type internal OprSnRt () =
  inherit OperandParser ()
  override __.Render bin =
    let sn = (* Vn:N *)
      concat (extract bin 19 16) (pickBit bin 7) 1 |> getVecSReg |> toSVReg
    let rt = extract bin 15 12 |> getRegister |> OprReg
    OprInfo (TwoOperands (sn, rt), false, None)

(* <Rt>, <Sn> *)
type internal OprRtSn () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let sn = (* Vn:N *)
      concat (extract bin 19 16) (pickBit bin 7) 1 |> getVecSReg |> toSVReg
    OprInfo (TwoOperands (rt, sn), false, None)

(* <Qd>, <Qm> *)
type internal OprQdQm () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let qm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecQReg |> toSVReg
    OprInfo (TwoOperands (qd, qm), false, None)

(* <Dd>, <Qm> *)
type internal OprDdQm () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let qm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecQReg |> toSVReg
    OprInfo (TwoOperands (dd, qm), false, None)

(* <Qd>, <Dm> *)
type internal OprQdDm () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    OprInfo (TwoOperands (qd, dm), false, None)

(* <spec_reg>, <Rt> *)
type internal OprSregRt () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    OprInfo (TwoOperands (OprReg R.FPSCR, rt), false, None)

(* <Rt>, <spec_reg> *)
type internal OprRtSreg () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    OprInfo (TwoOperands (rt, OprReg R.FPSCR), false, None)

(* <Rd>, <spec_reg> *)
type internal OprRdSregA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let sreg =
      if pickBit bin 22 = 1u then R.SPSR else R.APSR (* or CPSR *)
      |> uint |> getRegister |> OprReg
    OprInfo (TwoOperands (rd, sreg), false, None)

(* <spec_reg>, <Rn> *)
type internal OprSregRnA () =
  inherit OperandParser ()
  override __.Render bin =
    let struct (sreg, flag) = (* FIXME: F5-4583 *)
      if pickBit bin 22 = 1u (* R *) then getSPSR (extract bin 19 16)
      else getAPSR (extract bin 19 18 (* mask<3:2> *)) (* or CPSR *)
    let rn = extract bin 3 0 |> getRegister |> OprReg
    OprInfo (TwoOperands (OprSpecReg (sreg, flag), rn), false, None)

(* <Rd>, <banked_reg> *)
type internal OprRdBankregA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let breg =
      concat (pickBit bin 8) (extract bin 19 16) 4
      |> getBankedReg (pickBit bin 22) |> OprReg
    OprInfo (TwoOperands (rd, breg), false, None)

(* <banked_reg>, <Rn> *)
type internal OprBankregRnA () =
  inherit OperandParser ()
  override __.Render bin =
    let breg =
      concat (pickBit bin 8) (extract bin 19 16) 4
      |> getBankedReg (pickBit bin 22) |> OprReg
    let rn = extract bin 3 0 |> getRegister |> OprReg
    OprInfo (TwoOperands (breg, rn), false, None)

(* <Dd[x]>, <Rt> *)
type internal OprDd0Rt () =
  inherit OperandParser ()
  override __.Render bin =
    let d = concat (pickBit bin 7) (extract bin 19 16) 4 (* D:Vd *)
    let dd0 = toSSReg (d |> getVecDReg, Some 0uy)
    let rt = extract bin 15 12 |> getRegister |> OprReg
    OprInfo (TwoOperands (dd0, rt), false, None)

type internal OprDd1Rt () =
  inherit OperandParser ()
  override __.Render bin =
    let d = concat (pickBit bin 7) (extract bin 19 16) 4 (* D:Vd *)
    let dd1 = toSSReg (d |> getVecDReg, Some 1uy)
    let rt = extract bin 15 12 |> getRegister |> OprReg
    OprInfo (TwoOperands (dd1, rt), false, None)

type internal OprDd2Rt () =
  inherit OperandParser ()
  override __.Render bin =
    let d = concat (pickBit bin 7) (extract bin 19 16) 4 (* D:Vd *)
    let dd2 = toSSReg (d |> getVecDReg, Some 2uy)
    let rt = extract bin 15 12 |> getRegister |> OprReg
    OprInfo (TwoOperands (dd2, rt), false, None)

type internal OprDd3Rt () =
  inherit OperandParser ()
  override __.Render bin =
    let d = concat (pickBit bin 7) (extract bin 19 16) 4 (* D:Vd *)
    let dd3 = toSSReg (d |> getVecDReg, Some 3uy)
    let rt = extract bin 15 12 |> getRegister |> OprReg
    OprInfo (TwoOperands (dd3, rt), false, None)

type internal OprDd4Rt () =
  inherit OperandParser ()
  override __.Render bin =
    let d = concat (pickBit bin 7) (extract bin 19 16) 4 (* D:Vd *)
    let dd4 = toSSReg (d |> getVecDReg, Some 4uy)
    let rt = extract bin 15 12 |> getRegister |> OprReg
    OprInfo (TwoOperands (dd4, rt), false, None)

type internal OprDd5Rt () =
  inherit OperandParser ()
  override __.Render bin =
    let d = concat (pickBit bin 7) (extract bin 19 16) 4 (* D:Vd *)
    let dd5 = toSSReg (d |> getVecDReg, Some 5uy)
    let rt = extract bin 15 12 |> getRegister |> OprReg
    OprInfo (TwoOperands (dd5, rt), false, None)

type internal OprDd6Rt () =
  inherit OperandParser ()
  override __.Render bin =
    let d = concat (pickBit bin 7) (extract bin 19 16) 4 (* D:Vd *)
    let dd6 = toSSReg (d |> getVecDReg, Some 6uy)
    let rt = extract bin 15 12 |> getRegister |> OprReg
    OprInfo (TwoOperands (dd6, rt), false, None)

type internal OprDd7Rt () =
  inherit OperandParser ()
  override __.Render bin =
    let d = concat (pickBit bin 7) (extract bin 19 16) 4 (* D:Vd *)
    let dd7 = toSSReg (d |> getVecDReg, Some 7uy)
    let rt = extract bin 15 12 |> getRegister |> OprReg
    OprInfo (TwoOperands (dd7, rt), false, None)

(* <Rt>, <Dn[x]> *)
type internal OprRtDn0 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let n = concat (pickBit bin 7) (extract bin 19 16) 4 (* N:Vn *)
    let dn0 = toSSReg (n |> getVecDReg, Some 0uy)
    OprInfo (TwoOperands (rt, dn0), false, None)

type internal OprRtDn1 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let n = concat (pickBit bin 7) (extract bin 19 16) 4 (* N:Vn *)
    let dn1 = toSSReg (n |> getVecDReg, Some 1uy)
    OprInfo (TwoOperands (rt, dn1), false, None)

type internal OprRtDn2 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let n = concat (pickBit bin 7) (extract bin 19 16) 4 (* N:Vn *)
    let dn2 = toSSReg (n |> getVecDReg, Some 2uy)
    OprInfo (TwoOperands (rt, dn2), false, None)

type internal OprRtDn3 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let n = concat (pickBit bin 7) (extract bin 19 16) 4 (* N:Vn *)
    let dn3 = toSSReg (n |> getVecDReg, Some 3uy)
    OprInfo (TwoOperands (rt, dn3), false, None)

type internal OprRtDn4 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let n = concat (pickBit bin 7) (extract bin 19 16) 4 (* N:Vn *)
    let dn4 = toSSReg (n |> getVecDReg, Some 4uy)
    OprInfo (TwoOperands (rt, dn4), false, None)

type internal OprRtDn5 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let n = concat (pickBit bin 7) (extract bin 19 16) 4 (* N:Vn *)
    let dn5 = toSSReg (n |> getVecDReg, Some 5uy)
    OprInfo (TwoOperands (rt, dn5), false, None)

type internal OprRtDn6 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let n = concat (pickBit bin 7) (extract bin 19 16) 4 (* N:Vn *)
    let dn6 = toSSReg (n |> getVecDReg, Some 6uy)
    OprInfo (TwoOperands (rt, dn6), false, None)

type internal OprRtDn7 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let n = concat (pickBit bin 7) (extract bin 19 16) 4 (* N:Vn *)
    let dn7 = toSSReg (n |> getVecDReg, Some 7uy)
    OprInfo (TwoOperands (rt, dn7), false, None)

(* <Qd>, <Rt> *)
type internal OprQdRt () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 7) (extract bin 19 16) 4 |> getVecQReg |> toSVReg
    let rt = extract bin 15 12 |> getRegister |> OprReg
    OprInfo (TwoOperands (qd, rt), false, None)

(* <Dd>, <Rt> *)
type internal OprDdRt () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 7) (extract bin 19 16) 4 |> getVecDReg |> toSVReg
    let rt = extract bin 15 12 |> getRegister |> OprReg
    OprInfo (TwoOperands (dd, rt), false, None)

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

(* <Rt>, [<Rn>] *)
type internal OprRt15Mem () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem = memOffsetImm (extract bin 19 16 |> getRegister, None, None)
    OprInfo (TwoOperands (rt, mem), false, None)

(* <Rt>, [<Rn>] *)
type internal OprRtMem () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 3 0 |> getRegister |> OprReg
    let mem = memOffsetImm (extract bin 19 16 |> getRegister, None, None)
    OprInfo (TwoOperands (rt, mem), false, None)

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

(* <Rt>, [<Rn> {, {#}<imm>}] *)
type internal OprRtMemImm0A () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem = (* imm32 = 0 *)
      memOffsetImm (extract bin 19 16 |> getRegister, None, None)
    OprInfo (TwoOperands (rt, mem), false, None)

(* <Rt>, [<Rn> {, #{+/-}<imm>}]
   <Rt>, [<Rn>], #{+/-}<imm>
   <Rt>, [<Rn>, #{+/-}<imm>]! *)
type internal OprRtMemImm12A () =
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

(* <Dd>, #<imm> *)
type internal OprDdImmA () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let imm = advSIMDExpandImm bin (pickBit bin 24) |> int64 |> OprImm
    OprInfo (TwoOperands (dd, imm), false, None)

(* <Qd>, #<imm> *)
type internal OprQdImmA () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let imm = advSIMDExpandImm bin (pickBit bin 24) |> int64 |> OprImm
    OprInfo (TwoOperands (qd, imm), false, None)

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

(* <Sd>, #0.0 *)
type internal OprSdImm0 () =
  inherit OperandParser ()
  override __.Render bin =
    let sd = (* Vd:D *)
      concat (extract bin 15 12) (pickBit bin 22) 1 |> getVecSReg |> toSVReg
    OprInfo (TwoOperands (sd, OprImm 0L), false, None)

(* <Dd>, #0.0 *)
type internal OprDdImm0 () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    OprInfo (TwoOperands (dd, OprImm 0L), false, None)

(* <Rd>, #<imm16> *)
type internal OprRdImm16A () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let imm16 = (* imm4:imm12 *)
      concat (extract bin 19 16) (extract bin 11 0) 12 |> int64 |> OprImm
    OprInfo (TwoOperands (rd, imm16), false, None)

(* <spec_reg>, #<imm> *)
type internal OprSregImm () =
  inherit OperandParser ()
  override __.Render bin =
    let struct (sreg, flag) = (* FIXME: F5-4580 *)
      if pickBit bin 22 = 1u (* R *) then getSPSR (extract bin 19 16)
      else getAPSR (extract bin 19 18 (* mask<3:2> *)) (* or CPSR *)
    let imm = expandImmediate bin |> int64 |> OprImm
    OprInfo (TwoOperands (OprSpecReg (sreg, flag), imm), false, None)

(* <Rd>, #<const> *)
type internal OprRdConstA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let imm = expandImmediate bin |> int64 |> OprImm
    OprInfo (TwoOperands (rd, imm), false, None)

(* <Rd>, #<const> with carry *)
type internal OprRdConstCF () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let struct (imm32, carryOut) = expandImmCF bin
    OprInfo (TwoOperands (rd, imm32), false, carryOut)

(* <Rn>, #<const> *)
type internal OprRnConstA () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let imm = expandImmediate bin |> int64 |> OprImm
    OprInfo (TwoOperands (rn, imm), false, None)

(* <Rn>, #<const> with carry *)
type internal OprRnConstCF () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let struct (imm32, carryOut) = expandImmCF bin
    OprInfo (TwoOperands (rn, imm32), false, carryOut)

(* <Sd>, <label> *)
type internal OprSdLabel () =
  inherit OperandParser ()
  override __.Render bin =
    let sd = (* Vd:D *)
      concat (extract bin 15 12) (pickBit bin 22) 1 |> getVecSReg |> toSVReg
    let label = extract bin 7 0 (* imm8 *) |> int64 |> memLabel
    OprInfo (TwoOperands (sd, label), false, None)

(* <Dd>, <label> *)
type internal OprDdLabel () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let label = extract bin 7 0 (* imm8 *) |> int64 |> memLabel
    OprInfo (TwoOperands (dd, label), false, None)

(* <Rd>, <label> *)
type internal OprRdLabelA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let label = expandImmediate bin |> int64 |> memLabel
    OprInfo (TwoOperands (rd, label), false, None)

(* <Rt>, <label> *)
type internal OprRtLabelA () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let imm12 = extract bin 11 0 |> int64
    let label =
      if pickBit bin 23 = 1u then memLabel imm12 else memLabel (imm12 * -1L)
    OprInfo (TwoOperands (rt, label), wback bin, None)

(* <Rt>, <label> *)
type internal OprRtLabelHL () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let label = (* imm4H:imm4L *)
      concat (extract bin 11 8) (extract bin 3 0) 4 |> int64 |> memLabel
    OprInfo (TwoOperands (rt, label), wback bin, None)

(* <Rn>{!}, <registers> *)
type internal OprRnRegsA () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let regs = extract bin 15 0 (* register_list *) |> getRegList |> OprRegList
    OprInfo (TwoOperands (rn, regs), wbackW bin, None)

(* <Rn>, <registers>^ *) /// FIXME: '^' not apply
type internal OprRnRegsCaret () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let regs = extract bin 15 0 (* register_list *) |> getRegList |> OprRegList
    OprInfo (TwoOperands (rn, regs), false, None)

(* <Rn>{!}, <dreglist> *)
type internal OprRnDreglist () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let regs = extract bin 7 0 (* imm8 *) / 2u
    let dreglist = (* D:Vd *)
      getDRegList (concat (pickBit bin 22) (extract bin 15 12) 4) regs
    OprInfo (TwoOperands (rn, dreglist), wbackW bin, None)

(* <Rn>{!}, <sreglist> *)
type internal OprRnSreglist () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let regs = extract bin 7 0 (* imm8 *)
    let sreglist = (* Vd:D *)
      getSRegList (concat (extract bin 15 12) (pickBit bin 22) 1) regs
    OprInfo (TwoOperands (rn, sreglist), wbackW bin, None)

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

(* SP{!}, #<mode> *)
type internal OprSPMode () =
  inherit OperandParser ()
  override __.Render bin =
    let mode = extract bin 5 0 |> int64 |> OprImm
    OprInfo (TwoOperands (OprReg R.SP, mode), wbackW bin, None)

(* <iflags> , #<mode> *)
type internal OprIflagsModeA () =
  inherit OperandParser ()
  override __.Render bin =
    let iflags = OprIflag (getIflag (extract bin 8 6))
    let mode = extract bin 4 0 |> int64 |> OprImm
    OprInfo (TwoOperands (iflags, mode), false, None)

(* <Dm>, <Rt>, <Rt2> *)
type internal OprDmRtRt2 () =
  inherit OperandParser ()
  override __.Render bin =
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let rt2 = extract bin 19 16 |> getRegister |> OprReg
    OprInfo (ThreeOperands (dm, rt, rt2), false, None)

(* <Rt>, <Rt2>, <Dm> *)
type internal OprRtRt2Dm () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let rt2 = extract bin 19 16 |> getRegister |> OprReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    OprInfo (ThreeOperands (rt, rt2, dm), false, None)

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

(* <Rd>, <Rn>, <Rm> *)
(* {<Rd>,} <Rn>, <Rm> : SADD16? *)
type internal OprRdRnRm () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    OprInfo (ThreeOperands (rd, rn, rm), false, None)

(* <Rd>, <Rn>{, <Rm>} *)
(* {<Rd>,} <Rn>, <Rm> *)
type internal OprRdRnRmOpt () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 19 16 |> getRegister |> OprReg
    let rn = extract bin 3 0 |> getRegister |> OprReg
    let rm = extract bin 11 8 |> getRegister |> OprReg
    OprInfo (ThreeOperands (rd, rn, rm), false, None)

(* {<Rd>,} <Rm>, <Rs> *)
type internal OprRdRmRs () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let rs = extract bin 11 8 |> getRegister |> OprReg
    OprInfo (ThreeOperands (rd, rm, rs), false, None)

(* {<Rd>,} <Rm>, <Rn> *)
type internal OprRdRmRnA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    OprInfo (ThreeOperands (rd, rm, rn), false, None)

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

(* <Rt>, <Rt2>, [<Rn>] *)
type internal OprRtRt2MemA () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 3 0 |> getRegister |> OprReg
    let rt2 = extract bin 3 0 + 1u |> getRegister |> OprReg
    let mem =
      memOffsetImm (extract bin 19 16 (* Rn *) |> getRegister, None, None)
    OprInfo (ThreeOperands (rt, rt2, mem), false, None)

(* <Rt>, <Rt2>, [<Rn>] *)
type internal OprRtRt2Mem2 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let rt2 = extract bin 3 0 |> getRegister |> OprReg
    let mem =
      memOffsetImm (extract bin 19 16 (* Rn *) |> getRegister, None, None)
    OprInfo (ThreeOperands (rt, rt2, mem), false, None)

(* <Rt>, <Rt2>, [<Rn> {, #{+/-}<imm>}]
   <Rt>, <Rt2>, [<Rn>], #{+/-}<imm>
   <Rt>, <Rt2>, [<Rn>, #{+/-}<imm>]! *)
type internal OprRtRt2MemImmA () =
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

(* <Rd>, <Rt>, [<Rn>] *)
type internal OprRdRtMemA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rt = extract bin 3 0 |> getRegister |> OprReg
    let mem = memOffsetImm (extract bin 19 16 |> getRegister, None, None)
    OprInfo (ThreeOperands (rd, rt, mem), false, None)

(* <Rd>, <Rt>, [<Rn> {, {#}<imm>}] *)
type internal OprRdRtMemImmA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rt = extract bin 3 0 |> getRegister |> OprReg
    let mem = (* Rn, imm32 = 0 *)
      memOffsetImm (extract bin 19 16 |> getRegister, None, None)
    OprInfo (ThreeOperands (rd, rt, mem), false, None)

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

(* p14, c5, [<Rn>], <option> *)
type internal OprP14C5Option () =
  inherit OperandParser ()
  override __.Render bin =
    let mem =
      let rn = extract bin 19 16 |> getRegister
      memUnIdxImm (rn, extract bin 7 0 (* imm8 *) |> int64)
    OprInfo (ThreeOperands (OprReg R.P14, OprReg R.C5, mem), wbackW bin, None)

(* {<Rd>,} <Rn>, #<const> *)
type internal OprRdRnConstA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let cons = expandImmediate bin |> int64 |> OprImm
    OprInfo (ThreeOperands (rd, rn, cons), false, None)

(* {<Rd>,} <Rn>, #<const> with carry *)
type internal OprRdRnConstCF () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let struct (imm32, carryOut) = expandImmCF bin
    OprInfo (ThreeOperands (rd, rn, imm32), false, carryOut)

(* {<Rd>,} SP, #<const> *)
type internal OprRdSPConstA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let cons = expandImmediate bin |> int64 |> OprImm
    OprInfo (ThreeOperands (rd, OprReg R.SP, cons), false, None)

(* {<Rd>,} <Rm>, #<imm> : MOV alias *)
type internal OprRdRmImmA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let imm = extract bin 11 7 (* imm5 *) |> int64 |> OprImm
    OprInfo (ThreeOperands (rd, rm, imm), false, None)

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

(* <Qd>, <Dm>, #<imm> *)
type internal OprQdDmImm8 () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    OprInfo (ThreeOperands (qd, dm, OprImm 8L), false, None)

(* <Qd>, <Dm>, #<imm> *)
type internal OprQdDmImm16 () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    OprInfo (ThreeOperands (qd, dm, OprImm 16L), false, None)

(* <Qd>, <Dm>, #<imm> *)
type internal OprQdDmImm32 () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    OprInfo (ThreeOperands (qd, dm, OprImm 32L), false, None)

(* {<Dd>,} <Dm>, #0 *)
type internal OprDdDmImm0 () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    OprInfo (ThreeOperands (dd, dm, OprImm 0L), false, None)

(* {<Qd>,} <Qm>, #0 *)
type internal OprQdQmImm0 () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let qm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecQReg |> toSVReg
    OprInfo (ThreeOperands (qd, qm, OprImm 0L), false, None)

(* <Rn>, <Rm>, RRX *)
(* <Rn>, <Rm> {, <shift> #<amount>} *)
type internal OprRnRmShfA () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let struct (shift, amount) =
      decodeImmShift (extract bin 6 5) (extract bin 11 7) (* stype imm5 *)
    OprInfo (ThreeOperands (rn, rm, OprShift (shift, Imm amount)), false, None)

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

(* <Rd>, <Rm>, <shift> <Rs> *)
type internal OprRdRmShfRsA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let shift =
      let rs = extract bin 11 8 |> getRegister
      OprRegShift (decodeRegShift (extract bin 6 5 (* stype *)), rs)
    OprInfo (ThreeOperands (rd, rm, shift), false, None)

(* {<Rd>,} <Rm> {, ROR #<amount>} *)
type internal OprRdRmRorA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let shift = OprShift (SRType.SRTypeROR, extract bin 11 10 <<< 3 |> Imm)
    OprInfo (ThreeOperands (rd, rm, shift), false, None)

(* <Rd>, #<imm>, <Rn> *)
type internal OprRdImmRnA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let imm = extract bin 19 16 (* sat_imm *) + 1u |> int64 |> OprImm
    let rn = extract bin 3 0 |> getRegister |> OprReg
    OprInfo (ThreeOperands (rd, imm, rn), false, None)

(* <Rd>, #<lsb>, #<width> *)
type internal OprRdLsbWidthA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let lsb = extract bin 11 7 |> int64 |> OprImm
    let width = (* msb - lsb + 1 *)
      (extract bin 20 16) - (extract bin 11 7) + 1u |> int64 |> OprImm
    OprInfo (ThreeOperands (rd, lsb, width), false, None)

(* <Rt>, <Rt2>, <label> *)
type internal OprRtRt2LabelA () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let rt2 = extract bin 15 12 + 1u |> getRegister |> OprReg
    let label = (* imm4H:imm4L *)
      concat (extract bin 11 8) (extract bin 3 0) 4 |> int64 |> memLabel
    OprInfo (ThreeOperands (rt, rt2, label), false, None)

(* p14, c5, <label> *)
type internal OprP14C5Label () =
  inherit OperandParser ()
  override __.Render bin =
    let label = extract bin 7 0 <<< 2 (* imm8:00 *) |> int64 |> memLabel
    OprInfo (ThreeOperands (OprReg R.P14, OprReg R.C5, label), false, None)

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

(* <Rd>, <Rn>, <Rm>, <Ra> *)
type internal OprRdRnRmRaA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 19 16 |> getRegister |> OprReg
    let rn = extract bin 3 0 |> getRegister |> OprReg
    let rm = extract bin 11 8 |> getRegister |> OprReg
    let ra = extract bin 15 12 |> getRegister |> OprReg
    OprInfo (FourOperands (rd, rn, rm, ra), false, None)

(* <RdLo>, <RdHi>, <Rn>, <Rm> *)
type internal OprRdlRdhRnRmA () =
  inherit OperandParser ()
  override __.Render bin =
    let rdLo = extract bin 15 12 |> getRegister |> OprReg
    let rdHi = extract bin 19 16 |> getRegister |> OprReg
    let rn = extract bin 3 0 |> getRegister |> OprReg
    let rm = extract bin 11 8 |> getRegister |> OprReg
    OprInfo (FourOperands (rdLo, rdHi, rn, rm), false, None)

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

(* <Rd>, <Rt>, <Rt2>, [<Rn>] *)
type internal OprRdRtRt2MemA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rt = extract bin 3 0 |> getRegister |> OprReg
    let rt2 = extract bin 3 0 + 1u |> getRegister |> OprReg
    let mem = memOffsetImm (extract bin 19 16 |> getRegister, None, None)
    OprInfo (FourOperands (rd, rt, rt2, mem), false, None)

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

(* {<Rd>,} <Rn>, <Rm>, RRX *)
(* {<Rd>,} <Rn>, <Rm> {, <shift> #<amount>} *)
type internal OprRdRnRmShfA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let struct (shift, amount) = (* stype imm5 *)
      decodeImmShift (extract bin 6 5) (extract bin 11 7)
    OprInfo (FourOperands (rd, rn, rm, OprShift (shift, Imm amount)), false, None)

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

(* {<Rd>,} <Rn>, <Rm> {, ROR #<amount>} *)
type internal OprRdRnRmRorA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let shift = OprShift (SRType.SRTypeROR, extract bin 11 10 <<< 3 |> Imm)
    OprInfo (FourOperands (rd, rn, rm, shift), false, None)

(* <Rd>, #<imm>, <Rn>, ASR #<amount> *)
(* <Rd>, #<imm>, <Rn>, LSL #<amount> *)
type internal OprRdImmRnShfA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let imm = extract bin 20 16 (* sat_imm *) + 1u |> int64 |> OprImm
    let rn = extract bin 3 0 |> getRegister |> OprReg
    let struct (sTyp, amount) = (* sh:'0' *) (* imm5 *)
      decodeImmShift (extract bin 6 5) (extract bin 11 7)
    OprInfo (FourOperands (rd, imm, rn, OprShift (sTyp, Imm amount)), false, None)

(* <Rd>, #<imm>, <Rn>, ASR #<amount> *)
(* <Rd>, #<imm>, <Rn>, LSL #<amount> *)
type internal OprRdImmRnShfUA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let imm = extract bin 20 16 (* sat_imm *) |> int64 |> OprImm
    let rn = extract bin 3 0 |> getRegister |> OprReg
    let struct (sTyp, amount) = (* sh:'0' *) (* imm5 *)
      decodeImmShift (extract bin 6 5) (extract bin 11 7)
    OprInfo (FourOperands (rd, imm, rn, OprShift (sTyp, Imm amount)), false, None)

(* <Rd>, <Rn>, #<lsb>, #<width> *)
type internal OprRdRnLsbWidthA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rn = extract bin 3 0 |> getRegister |> OprReg
    let lsb = extract bin 11 7 |> int64 |> OprImm
    let width = (* msb - lsb + 1 *)
      (extract bin 20 16) - (extract bin 11 7) + 1u |> int64 |> OprImm
    OprInfo (FourOperands (rd, rn, lsb, width), false, None)

(* <Rd>, <Rn>, #<lsb>, #<width> *)
type internal OprRdRnLsbWidthM1A () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rn = extract bin 3 0 |> getRegister |> OprReg
    let lsb = extract bin 11 7 |> int64 |> OprImm
    let width = (* widthm1 + 1 *)
      (extract bin 20 16 (* widthm1 *)) + 1u |> int64 |> OprImm
    OprInfo (FourOperands (rd, rn, lsb, width), false, None)

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

(* <label> *)
type internal OprLabelT () =
  inherit OperandParser ()
  override __.Render bin =
    let label = (extract bin 10 0 <<< 1) |> signExtend 12
    OprInfo (OneOperand label, false, None)

(* <label> *)
type internal OprLabel8 () =
  inherit OperandParser ()
  override __.Render bin =
    let label = extract bin 7 0 <<< 1 |> signExtend 9
    OprInfo (OneOperand label, false, None)

(* <label> // Preferred syntax
   [PC, #{+/-}<imm>] // Alternative syntax *)
type internal OprLabel12T () =
  inherit OperandParser ()
  override __.Render bin =
    let imm12 = extract bin 11 0 |> int64
    OprInfo (OneOperand (memLabel imm12), false, None)

(* <label> *)
type internal OprLabelT3 () =
  inherit OperandParser ()
  override __.Render bin =
    let imm32 (* S:J2:J1:imm6:imm11:'0' *) =
      ((pickBit bin 26 <<< 19) + (pickBit bin 11 <<< 18) +
       (pickBit bin 13 <<< 17) + (extract bin 21 16 <<< 11) +
       (extract bin 10 0)) <<< 1 |> signExtend 21
    OprInfo (OneOperand imm32, false, None)

(* <label> *)
type internal OprLabelT4 () =
  inherit OperandParser ()
  override __.Render bin = (* or BL T1 *)
    let i1 = if (pickBit bin 13 ^^^ pickBit bin 26) = 0u then 1u else 0u
    let i2 = if (pickBit bin 11 ^^^ pickBit bin 26) = 0u then 1u else 0u
    let imm32 (* S:I1:I2:imm10:imm11:'0' *) =
      ((pickBit bin 26 <<< 23) + (i1 <<< 22) + (i2 <<< 21) +
       (extract bin 25 16 <<< 11) + (extract bin 10 0)) <<< 1 |> signExtend 25
    OprInfo (OneOperand imm32, false, None)

(* <label> *)
type internal OprLabelT2 () =
  inherit OperandParser ()
  override __.Render bin =
    let i1 = if (pickBit bin 13 ^^^ pickBit bin 26) = 0u then 1u else 0u
    let i2 = if (pickBit bin 11 ^^^ pickBit bin 26) = 0u then 1u else 0u
    let imm32 (* S:I1:I2:imm10H:imm10L:'00' *) =
      ((pickBit bin 26 <<< 22) + (i1 <<< 21) + (i2 <<< 20) +
       (extract bin 25 16 <<< 10) + (extract bin 10 1)) <<< 2 |> signExtend 25
    OprInfo (OneOperand imm32, false, None)

(* <Rm> *)
type internal OprRm16 () =
  inherit OperandParser ()
  override __.Render bin =
    let rm = extract bin 6 3 |> getRegister |> OprReg
    OprInfo (OneOperand rm, false, None)

(* <Rm> *)
type internal OprRm32 () =
  inherit OperandParser ()
  override __.Render bin =
    let rm = extract bin 6 3 |> getRegister |> OprReg
    OprInfo (OneOperand rm, false, None)

(* #<imm> *)
type internal OprImm1T () =
  inherit OperandParser ()
  override __.Render bin =
    let imm = OprImm (pickBit bin 3 (* imm1 *) |> int64)
    OprInfo (OneOperand imm, false, None)

(* {#}<imm> *)
type internal OprImm6 () =
  inherit OperandParser ()
  override __.Render bin =
    let imm = OprImm (extract bin 5 0 (* imm6 *) |> int64)
    OprInfo (OneOperand imm, false, None)

(* {#}<imm> *)
type internal OprImm8 () =
  inherit OperandParser ()
  override __.Render bin =
    let imm = OprImm (extract bin 7 0 (* imm8 *) |> int64)
    OprInfo (OneOperand imm, false, None)

(* {#}<imm> *)
type internal OprImm16T () =
  inherit OperandParser ()
  override __.Render bin =
    let imm (* imm4:imm12 *) =
      concat (extract bin 19 16) (extract bin 11 0) 12 |> int64 |> OprImm
    OprInfo (OneOperand imm, false, None)

(* {#}<imm4> *)
type internal OprImm4T () =
  inherit OperandParser ()
  override __.Render bin =
    OprInfo (extract bin 19 16 |> int64 |> OprImm |> OneOperand, false, None)

(* <cond> *)
type internal OprCondition () =
  inherit OperandParser ()
  override __.Render bin =
    let cond = extract bin 7 4 |> byte |> parseCond |> OprCond
    OprInfo (OneOperand cond, false, None)

(* <endian_specifier> *)
type internal OprEndianT () =
  inherit OperandParser ()
  override __.Render bin =
    let endian = pickBit bin 3 |> byte |> getEndian |> OprEndian
    OprInfo (OneOperand endian, false, None)

(* <iflags> *)
type internal OprIflagsT () =
  inherit OperandParser ()
  override __.Render bin =
    OprInfo (OneOperand (OprIflag (getIflag (extract bin 7 5))), false, None)

(* <iflags> , #<mode> *)
type internal OprIflagsModeT () =
  inherit OperandParser ()
  override __.Render bin =
    let iflags = OprIflag (getIflag (extract bin 7 5))
    let mode = extract bin 4 0 |> int64 |> OprImm
    OprInfo (TwoOperands (iflags, mode), false, None)

(* <registers> *)
type internal OprRegsM () =
  inherit OperandParser ()
  override __.Render bin =
    let regs = (* '0':M:'000000':register_list *)
      concat (pickBit bin 8 <<< 6) (extract bin 7 0) 8 |> getRegList
      |> OprRegList
    OprInfo (OneOperand regs, false, None)

(* <registers> *)
type internal OprRegsP () =
  inherit OperandParser ()
  override __.Render bin =
    let regs = (* P:'0000000':register_list *)
      concat (pickBit bin 8 <<< 7) (extract bin 7 0) 8 |> getRegList
      |> OprRegList
    OprInfo (OneOperand regs, false, None)

(* [<Rn> {, #-<imm>}] *)
type internal OprMemImm8M () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister
    let imm = extract bin 7 0 (* imm8 *) |> int64
    OprInfo (OneOperand (memOffsetImm (rn, Some Minus, Some imm)), false, None)

(* [<Rn> {, #{+}<imm>}] *)
type internal OprMemImm12 () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister
    let imm = extract bin 11 0 (* imm12 *) |> int64
    OprInfo (OneOperand (memOffsetImm (rn, Some Plus, Some imm)), false, None)

(* [<Rn>, <Rm>] *)
type internal OprMemRegT () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = getRegister (extract bin 19 16)
    let rm = getRegister (extract bin 3 0)
    OprInfo (OneOperand (memOffsetReg (rn, None, rm, None)), false, None)

(* [<Rn>, <Rm>, LSL #1] *)
type internal OprMemRegLSL1 () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = getRegister (extract bin 19 16)
    let rm = getRegister (extract bin 3 0)
    let shf = Some (SRTypeLSL, Imm 1u)
    OprInfo (OneOperand (memOffsetReg (rn, None, rm, shf)), false, None)

(* [<Rn>, {+}<Rm> {, LSL #<amount>}] *)
type internal OprMemRegLSL () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = getRegister (extract bin 19 16)
    let rm = getRegister (extract bin 3 0)
    let shf = Some (SRTypeLSL, Imm (extract bin 5 4 (* imm2 *)))
    OprInfo (OneOperand (memOffsetReg (rn, None, rm, shf)), false, None)

(* <Rt>, <label> *)
type internal OprRtLabelT () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 10 8 |> getRegister |> OprReg
    let label = extract bin 7 0 <<< 2 |> int64 |> memLabel
    OprInfo (TwoOperands (rt, label), false, None)

(* <Rn>, <label> *)
type internal OprRnLabel () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 2 0 |> getRegister |> OprReg
    let label = (* i:imm5:'0' *)
      (concat (pickBit bin 9) (extract bin 7 3) 5) <<< 1 |> int64 |> memLabel
    OprInfo (TwoOperands (rn, label), false, None)

(* <Rt>, <label> // Preferred syntax
   <Rt>, [PC, #{+/-}<imm>] // Alternative syntax *)
type internal OprRtLabel12 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let label = extract bin 11 0 |> int64 |> memLabel
    OprInfo (TwoOperands (rt, label), false, None)

(* <Rd>, #<imm8> *)
type internal OprRdImm8 () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 10 8 |> getRegister |> OprReg
    let imm8 = extract bin 7 0 |> int64 |> OprImm
    OprInfo (TwoOperands (rd, imm8), false, None) /// FIXME: carry = PSTATE.C

(* <Rdn>, #<imm8> *)
type internal OprRdnImm8 () =
  inherit OperandParser ()
  override __.Render bin =
    let rdn = extract bin 10 8 |> getRegister |> OprReg
    let imm8 = extract bin 7 0 |> int64 |> OprImm
    OprInfo (TwoOperands (rdn, imm8), false, None)

(* <Dd>, #<imm> *)
type internal OprDdImmT () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let imm = advSIMDExpandImm bin (pickBit bin 28) |> int64 |> OprImm
    OprInfo (TwoOperands (dd, imm), false, None)

(* <Qd>, #<imm> *)
type internal OprQdImmT () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let imm = advSIMDExpandImm bin (pickBit bin 28) |> int64 |> OprImm
    OprInfo (TwoOperands (qd, imm), false, None)

(* <Rd>, <Rm> *)
type internal OprRdRmT16 () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 2 0 |> getRegister |> OprReg
    let rm = extract bin 5 3 |> getRegister |> OprReg
    OprInfo (TwoOperands (rd, rm), false, None)

(* <Rd>, <Rm> *)
type internal OprRdRmT32 () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    OprInfo (TwoOperands (rd, rm), false, None)

(* <Rd>, <Rm> *)
type internal OprRdRmExt () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = (* D:Rd *)
      concat (pickBit bin 7) (extract bin 2 0) 3 |> getRegister |> OprReg
    let rm = extract bin 6 3 |> getRegister |> OprReg
    OprInfo (TwoOperands (rd, rm), false, None)

(* <Rn>, <Rm> *)
type internal OprRnRm () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 2 0 |> getRegister |> OprReg
    let rm = extract bin 5 3 |> getRegister |> OprReg
    OprInfo (TwoOperands (rn, rm), false, None)

(* <Rn>, <Rm> *)
type internal OprRnRmExt () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = (* N:Rn *)
      concat (pickBit bin 7) (extract bin 2 0) 3 |> getRegister |> OprReg
    let rm = extract bin 6 3 |> getRegister |> OprReg
    OprInfo (TwoOperands (rn, rm), false, None)

(* <Rdn>, <Rm> *)
type internal OprRdnRm () =
  inherit OperandParser ()
  override __.Render bin =
    let rdn = (* DN:Rdn *)
      concat (pickBit bin 7) (extract bin 2 0) 3 |> getRegister |> OprReg
    let rm = extract bin 6 3 |> getRegister |> OprReg
    OprInfo (TwoOperands (rdn, rm), false, None)

(* <Rn>, #<const> *)
type internal OprRnConstT () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let imm12 (* i:imm3:imm8 *) =
      (pickBit bin 26 <<< 11) + (extract bin 14 12 <<< 8) + (extract bin 7 0)
    let cons = t32ExpandImm imm12 |> int64 |> OprImm
    OprInfo (TwoOperands (rn, cons), false, None)

(* <Rd>, #<const> *)
type internal OprRdConstT () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 11 8 |> getRegister |> OprReg
    let imm12 (* i:imm3:imm8 *) =
      (pickBit bin 26 <<< 11) + (extract bin 14 12 <<< 8) + (extract bin 7 0)
    let cons = t32ExpandImm imm12 |> int64 |> OprImm
    OprInfo (TwoOperands (rn, cons), false, None)

(* <Rn>!, <registers> *)
type internal OprRnRegsT () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 10 8 |> getRegister |> OprReg
    let regs = extract bin 7 0 (* register_list *) |> getRegList |> OprRegList
    OprInfo (TwoOperands (rn, regs), true, None)

(* <Rn>!, <registers> *)
type internal OprRnRegsW () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 10 8
    let regs = extract bin 7 0 (* register_list *)
    let wback = pickBit regs (int rn) = 0u
    let regs = regs |> getRegList |> OprRegList
    OprInfo (TwoOperands (rn |> getRegister |> OprReg, regs), wback, None)

(* <spec_reg>, <Rn> *)
type internal OprSregRnT () =
  inherit OperandParser ()
  override __.Render bin =
    let struct (sreg, flag) = (* FIXME: F5-4583 *)
      if pickBit bin 20 = 1u (* R *) then getSPSR (extract bin 19 16)
      else getAPSR (extract bin 11 10 (* mask<3:2> *)) (* or CPSR *)
    let rn = extract bin 19 16 |> getRegister |> OprReg
    OprInfo (TwoOperands (OprSpecReg (sreg, flag), rn), false, None)

(* <Rd>, <spec_reg> *)
type internal OprRdSregT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let sreg =
      if pickBit bin 20 = 1u then R.SPSR else R.APSR (* or CPSR *)
      |> uint |> getRegister |> OprReg
    OprInfo (TwoOperands (rd, sreg), false, None)

(* <banked_reg>, <Rn> *)
type internal OprBankregRnT () =
  inherit OperandParser ()
  override __.Render bin =
    let breg =
      concat (pickBit bin 4) (extract bin 11 8) 4 (* M:M1 *)
      |> getBankedReg (pickBit bin 20) (* R *) |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    OprInfo (TwoOperands (breg, rn), false, None)

(* <Rd>, <banked_reg> *)
type internal OprRdBankregT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let breg =
      concat (pickBit bin 4) (extract bin 19 16) 4 (* M:M1 *)
      |> getBankedReg (pickBit bin 20) (* R *) |> OprReg
    OprInfo (TwoOperands (rd, breg), false, None)

(* {<Dd>,} <Dm>, #0 *)
type internal OprDdDm0 () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    OprInfo (ThreeOperands (dd, dm, OprImm 0L), false, None)

(* {<Qd>,} <Qm>, #0 *)
type internal OprQdQm0 () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let qm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecQReg |> toSVReg
    OprInfo (ThreeOperands (qd, qm, OprImm 0L), false, None)

(* <Rt>, [<Rn>, {+}<Rm>] *)
type internal OprRtMemReg16 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 2 0 |> getRegister |> OprReg
    let mem =
      let rn = extract bin 5 3 |> getRegister
      let rm = extract bin 8 6 |> getRegister
      memOffsetReg (rn, Some Plus, rm, None)
    OprInfo (TwoOperands (rt, mem), false, None)

(* <Rt>, [<Rn>, {+}<Rm>] *)
type internal OprRtMemReg32 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let rm = extract bin 3 0 |> getRegister
      memOffsetReg (rn, Some Plus, rm, None)
    OprInfo (TwoOperands (rt, mem), false, None)

(* <Rt>, [<Rn>, {+}<Rm>{, LSL #<imm>}] *)
type internal OprRtMemRegLSL () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let rm = extract bin 3 0 |> getRegister
      let amount = Imm (extract bin 5 4 (* imm2 *))
      memOffsetReg (rn, Some Plus, rm, Some (SRTypeLSL, amount))
    OprInfo (TwoOperands (rt, mem), false, None)

(* <Rt>, [<Rn> {, #{+}<imm>}] *)
type internal OprRtMemImm0T () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 2 0 |> getRegister |> OprReg
    let mem =
      let rn = extract bin 5 3 |> getRegister
      let imm = extract bin 10 6 (* imm5 *) |> int64 (* ZeroExtend(imm5, 32) *)
      memOffsetImm (rn, Some Plus, Some imm)
    OprInfo (TwoOperands (rt, mem), false, None)

(* <Rt>, [<Rn> {, #{+}<imm>}] *)
type internal OprRtMemImm1 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 2 0 |> getRegister |> OprReg
    let mem =
      let rn = extract bin 5 3 |> getRegister
      let imm = (* ZeroExtend(imm5:'0', 32) *)
        extract bin 10 6 (* imm5 *) <<< 1 |> int64
      memOffsetImm (rn, Some Plus, Some imm)
    OprInfo (TwoOperands (rt, mem), false, None)

(* <Rt>, [<Rn> {, #{+}<imm>}] *)
type internal OprRtMemImm2 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 2 0 |> getRegister |> OprReg
    let mem =
      let rn = extract bin 5 3 |> getRegister
      let imm = (* ZeroExtend(imm5:'00', 32) *)
        extract bin 10 6 (* imm5 *) <<< 2 |> int64
      memOffsetImm (rn, Some Plus, Some imm)
    OprInfo (TwoOperands (rt, mem), false, None)

(* <Rt>, [<Rn> {, #<imm>}] *)
type internal OprRtMemImm8 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let imm = extract bin 7 0 <<< 2 (* imm8:'00' *) |> int64
      memOffsetImm (rn, None, Some imm)
    OprInfo (TwoOperands (rt, mem), false, None)

(* <Rt>, [<Rn> {, #{+}<imm>}] *)
type internal OprRtMemImm8P () =
  inherit OperandParser ()
  override __.Render bin = /// imm8 & Plus
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let imm = extract bin 7 0 (* imm8 *) |> int64
      memOffsetImm (rn, Some Plus, Some imm)
    OprInfo (TwoOperands (rt, mem), false, None)

(* <Rt>, [<Rn> {, #-<imm>}] *)
type internal OprRtMemImm8M () =
  inherit OperandParser ()
  override __.Render bin = /// imm8 & Minus
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let imm = extract bin 7 0 (* imm8 *) |> int64
      memOffsetImm (rn, Some Minus, Some imm)
    OprInfo (TwoOperands (rt, mem), wbackW8 bin, None)

(* <Rt>, [<Rn>], #{+/-}<imm> *)
type internal OprRtMemImmPs () =
  inherit OperandParser ()
  override __.Render bin = /// Post-indexed
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let imm = extract bin 7 0 (* imm8 *) |> int64
      let sign = pickBit bin 9 |> getSign |> Some
      memPostIdxImm (rn, sign, Some imm)
    OprInfo (TwoOperands (rt, mem), wbackW8 bin, None)

(* <Rt>, [<Rn>, #{+/-}<imm>]! *)
type internal OprRtMemImmPr () =
  inherit OperandParser ()
  override __.Render bin = /// Pre-indexed
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let imm = extract bin 7 0 (* imm8 *) |> int64
      let sign = pickBit bin 9 |> getSign |> Some
      memPreIdxImm (rn, sign, Some imm)
    OprInfo (TwoOperands (rt, mem), wbackW8 bin, None)

(* <Rt>, [<Rn> {, #{+}<imm>}] *)
type internal OprRtMemImm12T () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem =
      let imm12 = extract bin 11 0 |> int64
      let rn = extract bin 19 16 |> getRegister
      memOffsetImm (rn, Some Plus, Some imm12)
    OprInfo (TwoOperands (rt, mem), false, None)

(* <Rt>, [SP{, #{+}<imm>}] *)
type internal OprRtMemSP () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 10 8 |> getRegister |> OprReg
    let mem =
      let imm = extract bin 7 0 (* imm8 *) <<< 2 |> int64
      memOffsetImm (R.SP, Some Plus, Some imm)
    OprInfo (TwoOperands (rt, mem), false, None)

(* <Rd>, <label> *)
type internal OprRdLabelT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let imm32 (* i:imm3:imm8 *) =
      (pickBit bin 26 <<< 11) + (extract bin 14 12 <<< 8) + (extract bin 7 0)
      |> int64 |> memLabel
    OprInfo (TwoOperands (rd, imm32), false, None)

(* <Rt>, <Rt2>, <label> *)
type internal OprRtRt2LabelT () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let rt2 = extract bin 11 8 |> getRegister |> OprReg
    let label = extract bin 7 0 <<< 2 (* imm8:'00' *) |> int64 |> memLabel
    OprInfo (ThreeOperands (rt, rt2, label), false, None)

(* <Rd>, <Rn>, <Rm> *)
(* {<Rd>,} <Rn>, <Rm> *)
type internal OprRdRnRmT16 () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 2 0 |> getRegister |> OprReg
    let rn = extract bin 5 3 |> getRegister |> OprReg
    let rm = extract bin 8 6 |> getRegister |> OprReg
    OprInfo (ThreeOperands (rd, rn, rm), false, None)

(* {<Rd>,} <Rn>, <Rm> *)
type internal OprRdRnRmT32 () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    OprInfo (ThreeOperands (rd, rn, rm), false, None)

(* {<Rd>,} <Rm>, <Rn> *)
type internal OprRdRmRnT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    OprInfo (ThreeOperands (rd, rm, rn), false, None)

(* {<Rd>,} <Rm>, #<imm> *)
type internal OprRdRmImmT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 2 0 |> getRegister |> OprReg
    let rm = extract bin 5 3 |> getRegister |> OprReg
    let imm = extract bin 10 6 |> int64 |> OprImm
    OprInfo (ThreeOperands (rd, rm, imm), false, None)

(* <Rd>, <Rn>, #<imm3> *)
type internal OprRdRnImm3 () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 2 0 |> getRegister |> OprReg
    let rn = extract bin 5 3 |> getRegister |> OprReg
    let imm3 = extract bin 8 6 (* imm3 *) |> int64 |> OprImm
    OprInfo (ThreeOperands (rd, rn, imm3), false, None)

(* <Rd>, SP, #<imm8> *)
type internal OprRdSPImm8 () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 10 8 |> getRegister |> OprReg
    let imm8 = extract bin 7 0 (* imm8 *) <<< 2 |> int64 |> OprImm
    OprInfo (ThreeOperands (rd, OprReg R.SP, imm8), false, None)

(* {<Rd>,} <Rn>, #<imm12> *)
type internal OprRdRnImm12 () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let imm12 (* i:imm3:imm8 *) =
      (pickBit bin 26 <<< 11) + (extract bin 14 12 <<< 8) + (extract bin 7 0)
      |> int64
    OprInfo (ThreeOperands (rd, rn, OprImm imm12), false, None)

(* <Rd>, #<imm16> *)
type internal OprRdImm16T () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let imm16 = (* imm4:i:imm3:imm8 *)
      (extract bin 19 16 <<< 12) + (pickBit bin 26 <<< 11) +
      (extract bin 14 12 <<< 8) + (extract bin 7 0) |> int64 |> OprImm
    OprInfo (TwoOperands (rd, imm16), false, None)

(* {<Rd>,} SP, #<imm12> *)
type internal OprRdSPImm12 () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let imm12 (* i:imm3:imm8 *) =
      (pickBit bin 26 <<< 11) + (extract bin 14 12 <<< 8) + (extract bin 7 0)
      |> int64
    OprInfo (ThreeOperands (rd, OprReg R.SP, OprImm imm12), false, None)

(* PC, LR, #<imm8> *)
type internal OprPCLRImm8 () =
  inherit OperandParser ()
  override __.Render bin =
    let imm8 = extract bin 7 0 (* imm8 *) |> int64 |> OprImm
    OprInfo (ThreeOperands (OprReg R.PC, OprReg R.LR, imm8), false, None)

(* {SP,} SP, #<imm7> *)
type internal OprSPSPImm7 () =
  inherit OperandParser ()
  override __.Render bin =
    let imm = extract bin 6 0 (* imm7 *) <<< 2 |> int64 |> OprImm
    OprInfo (ThreeOperands (OprReg R.SP, OprReg R.SP, imm), false, None)

(* <Rd>, <Rm> {, <shift> #<amount>} *)
type internal OprRdRmShfT16 () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 2 0 |> getRegister |> OprReg
    let rm = extract bin 5 3 |> getRegister |> OprReg
    let struct (shift, amount) =
      decodeImmShift (extract bin 12 11) (extract bin 10 6) (* stype, imm5 *)
    OprInfo (ThreeOperands (rd, rm, OprShift (shift, Imm amount)), false, None)

(* <Rd>, <Rm> {, <shift> #<amount>} *)
type internal OprRdRmShfT32 () =
  inherit OperandParser ()
  override __.Render b =
    let rd = extract b 11 8 |> getRegister |> OprReg
    let rm = extract b 3 0 |> getRegister |> OprReg
    let struct (shift, amount) = (* stype, imm3:imm2 *)
      decodeImmShift (extract b 5 4) ((extract b 14 12 <<< 2) + (extract b 7 6))
    OprInfo (ThreeOperands (rd, rm, OprShift (shift, Imm amount)), false, None)

(* {<Rd>, }<Rn>, #0 *)
type internal OprRdRn0 () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 2 0 |> getRegister |> OprReg
    let rn = extract bin 5 3 |> getRegister |> OprReg
    OprInfo (ThreeOperands (rd, rn, OprImm 0L), false, None)

(* {<Rd>, }<Rn>, #0 *)
type internal OprRdRn0T32 () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    OprInfo (ThreeOperands (rd, rn, OprImm 0L), false, None)

(* {<Rdn>,} <Rdn>, <Rm> *)
type internal OprRdnRdnRm () =
  inherit OperandParser ()
  override __.Render bin =
    let rdn = extract bin 2 0 |> getRegister |> OprReg
    let rm = extract bin 5 3 |> getRegister |> OprReg
    OprInfo (ThreeOperands (rdn, rdn, rm), false, None)

(* <Rdm>, <Rn>{, <Rdm>} *)
type internal OprRdmRnRdm () =
  inherit OperandParser ()
  override __.Render bin =
    let rdm = extract bin 2 0 |> getRegister |> OprReg
    let rn = extract bin 5 3 |> getRegister |> OprReg
    OprInfo (ThreeOperands (rdm, rn, rdm), false, None)

(* {<Rdm>,} SP, <Rdm> *)
type internal OprRdmSPRdm () =
  inherit OperandParser ()
  override __.Render bin =
    let rdm = (* DM:Rdm *)
      concat (pickBit bin 7) (extract bin 2 0) 3 |> getRegister |> OprReg
    OprInfo (ThreeOperands (rdm, OprReg R.SP, rdm), false, None)

(* {SP,} SP, <Rm> *)
type internal OprSPSPRm () =
  inherit OperandParser ()
  override __.Render bin =
    let rm = extract bin 6 3 |> getRegister |> OprReg
    OprInfo (ThreeOperands (OprReg R.SP, OprReg R.SP, rm), false, None)

(* <Rd>, <Rt>, [<Rn>] *)
type internal OprRdRtMemT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 3 0 |> getRegister |> OprReg
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem = memOffsetImm (extract bin 19 16 |> getRegister, None, None)
    OprInfo (ThreeOperands (rd, rt, mem), false, None)

(* <Rt>, <Rt2>, [<Rn>] *)
type internal OprRtRt2MemT () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let rt2 = extract bin 11 8 |> getRegister |> OprReg
    let mem =
      memOffsetImm (extract bin 19 16 (* Rn *) |> getRegister, None, None)
    OprInfo (ThreeOperands (rt, rt2, mem), false, None)

(* <Rt>, <Rt2>, [<Rn> {, #{+/-}<imm>}]
   <Rt>, <Rt2>, [<Rn>], #{+/-}<imm>
   <Rt>, <Rt2>, [<Rn>, #{+/-}<imm>]! *)
type internal OprRtRt2MemImmT () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let rt2 = extract bin 11 8 |> getRegister |> OprReg
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let imm = extract bin 7 0 <<< 2 |> int64
      let sign = pickBit bin 23 |> getSign |> Some
      match concat (pickBit bin 24) (pickBit bin 21) 1 with
      | 0b10u -> memOffsetImm (rn, sign, Some imm)
      | 0b01u -> memPostIdxImm (rn, sign, Some imm)
      | 0b11u -> memPreIdxImm (rn, sign, Some imm)
      | _ (* 00 *) -> raise UnpredictableException
    OprInfo (ThreeOperands (rt, rt2, mem), wbackW bin, None)

(* <Rd>, <Rt>, [<Rn> {, #<imm>}] *)
type internal OprRdRtMemImmT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem =
      let imm = extract bin 7 0 <<< 2 (* imm8:'00' *) |> int64
      memOffsetImm (extract bin 19 16 |> getRegister, None, Some imm)
    OprInfo (ThreeOperands (rd, rt, mem), false, None)

(* <Rn>, <Rm>, RRX *)
(* <Rn>, <Rm> {, <shift> #<amount>} *)
type internal OprRnRmShfT () =
  inherit OperandParser ()
  override __.Render b =
    let rn = extract b 19 16 |> getRegister |> OprReg
    let rm = extract b 3 0 |> getRegister |> OprReg
    let struct (shift, amount) = (* stype, imm3:imm2 *)
      decodeImmShift (extract b 5 4) ((extract b 14 12 <<< 2) + (extract b 7 6))
    OprInfo (ThreeOperands (rn, rm, OprShift (shift, Imm amount)), false, None)

(* <Rd>, <Rm>, <shift> <Rs> *)
type internal OprRdRmShfRsT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let rm = extract bin 19 16 |> getRegister |> OprReg
    let shift =
      let rs = extract bin 3 0 |> getRegister
      OprRegShift (decodeRegShift (extract bin 22 21 (* stype *)), rs)
    OprInfo (ThreeOperands (rd, rm, shift), false, None)

(* {<Rd>,} <Rm> {, ROR #<amount>} *)
type internal OprRdRmRorT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let shift = OprShift (SRType.SRTypeROR, extract bin 5 4 <<< 3 |> Imm)
    OprInfo (ThreeOperands (rd, rm, shift), false, None)

(* {<Rd>,} <Rn>, #<const> *)
type internal OprRdRnConstT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let imm12 (* i:imm3:imm8 *) =
      (pickBit bin 26 <<< 11) + (extract bin 14 12 <<< 8) + (extract bin 7 0)
    let cons = t32ExpandImm imm12 |> int64 |> OprImm
    OprInfo (ThreeOperands (rd, rn, cons), false, None)

(* {<Rd>,} SP, #<const> *)
type internal OprRdSPConstT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let imm12 (* i:imm3:imm8 *) =
      (pickBit bin 26 <<< 11) + (extract bin 14 12 <<< 8) + (extract bin 7 0)
    let cons = t32ExpandImm imm12 |> int64 |> OprImm
    OprInfo (ThreeOperands (rd, OprReg R.SP, cons), false, None)

(* <Rd>, #<imm>, <Rn> *)
type internal OprRdImmRnT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let imm = extract bin 3 0 (* sat_imm *) + 1u |> int64 |> OprImm
    let rn = extract bin 19 16 |> getRegister |> OprReg
    OprInfo (ThreeOperands (rd, imm, rn), false, None)

(* <Rd>, #<imm>, <Rn> *)
type internal OprRdImmRnU () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let imm = extract bin 3 0 (* sat_imm *) |> int64 |> OprImm
    let rn = extract bin 19 16 |> getRegister |> OprReg
    OprInfo (ThreeOperands (rd, imm, rn), false, None)

(* <Rd>, #<lsb>, #<width> *)
type internal OprRdLsbWidthT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let lsb = concat (extract bin 14 12) (extract bin 7 6) 2
    let width = (* msb - lsb + 1 *)
      (extract bin 4 0) - lsb + 1u |> int64 |> OprImm
    OprInfo (ThreeOperands (rd, OprImm (int64 lsb), width), false, None)

(* {<Rd>,} <Rn>, <Rm>, RRX *)
(* {<Rd>,} <Rn>, <Rm> {, <shift> #<amount>} *)
type internal OprRdRnRmShfT () =
  inherit OperandParser ()
  override __.Render b =
    let rd = extract b 11 8 |> getRegister |> OprReg
    let rn = extract b 19 16 |> getRegister |> OprReg
    let rm = extract b 3 0 |> getRegister |> OprReg
    let struct (shift, amount) = (* stype, imm3:imm2 *)
      decodeImmShift (extract b 5 4) ((extract b 14 12 <<< 2) + (extract b 7 6))
    let shift = OprShift (shift, Imm amount)
    OprInfo (FourOperands (rd, rn, rm, shift), false, None)

(* {<Rd>,} SP, <Rm>, RRX *)
(* {<Rd>,} SP, <Rm> {, <shift> #<amount>} *)
type internal OprRdSPRmShf () =
  inherit OperandParser ()
  override __.Render b=
    let rd = extract b 11 8 |> getRegister |> OprReg
    let rm = extract b 3 0 |> getRegister |> OprReg
    let struct (shift, amount) = (* stype, imm3:imm2 *)
      decodeImmShift (extract b 5 4) ((extract b 14 12 <<< 2) + (extract b 7 6))
    let shf = OprShift (shift, Imm amount)
    OprInfo (FourOperands (rd, OprReg R.SP, rm, shf), false, None)

(* <Rdm>, <Rdm>, LSL <Rs> *)
type internal OprRdmRdmLSLRs () =
  inherit OperandParser ()
  override __.Render bin =
    let rdm = extract bin 2 0 |> getRegister |> OprReg
    let shift = OprRegShift (SRTypeLSL, extract bin 5 3 |> getRegister (* Rs *))
    OprInfo (ThreeOperands (rdm, rdm, shift), false, None)

(* <Rdm>, <Rdm>, LSR <Rs> *)
type internal OprRdmRdmLSRRs () =
  inherit OperandParser ()
  override __.Render bin =
    let rdm = extract bin 2 0 |> getRegister |> OprReg
    let shift = OprRegShift (SRTypeLSR, extract bin 5 3 |> getRegister (* Rs *))
    OprInfo (ThreeOperands (rdm, rdm, shift), false, None)

(* <Rdm>, <Rdm>, ASR <Rs> *)
type internal OprRdmRdmASRRs () =
  inherit OperandParser ()
  override __.Render bin =
    let rdm = extract bin 2 0 |> getRegister |> OprReg
    let shift = OprRegShift (SRTypeASR, extract bin 5 3 |> getRegister (* Rs *))
    OprInfo (ThreeOperands (rdm, rdm, shift), false, None)

(* <Rdm>, <Rdm>, ROR <Rs> *)
type internal OprRdmRdmRORRs () =
  inherit OperandParser ()
  override __.Render bin =
    let rdm = extract bin 2 0 |> getRegister |> OprReg
    let shift = OprRegShift (SRTypeROR, extract bin 5 3 |> getRegister (* Rs *))
    OprInfo (ThreeOperands (rdm, rdm, shift), false, None)

(* {<Rd>,} <Rn>, <Rm> {, ROR #<amount>} *)
type internal OprRdRnRmRorT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let shift = OprShift (SRType.SRTypeROR, extract bin 5 4 <<< 3 |> Imm)
    OprInfo (FourOperands (rd, rn, rm, shift), false, None)

(* <Rd>, <Rn>, <Rm>, <Ra> *)
type internal OprRdRnRmRaT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let ra = extract bin 15 12 |> getRegister |> OprReg
    OprInfo (FourOperands (rd, rn, rm, ra), false, None)

(* <RdLo>, <RdHi>, <Rn>, <Rm> *)
type internal OprRdlRdhRnRmT () =
  inherit OperandParser ()
  override __.Render bin =
    let rdLo = extract bin 15 12 |> getRegister |> OprReg
    let rdHi = extract bin 11 8 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    OprInfo (FourOperands (rdLo, rdHi, rn, rm), false, None)

(* <Rd>, <Rt>, <Rt2>, [<Rn>] *)
type internal OprRdRtRt2MemT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 3 0 |> getRegister |> OprReg
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let rt2 = extract bin 11 8 |> getRegister |> OprReg
    let mem = memOffsetImm (extract bin 19 16 |> getRegister, None, None)
    OprInfo (FourOperands (rd, rt, rt2, mem), false, None)

(* <Rd>, #<imm>, <Rn>, ASR #<amount> *)
(* <Rd>, #<imm>, <Rn>, LSL #<amount> *)
type internal OprRdImmRnShfT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let imm = extract bin 4 0 (* sat_imm *) + 1u |> int64 |> OprImm
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let imm5 (* imm3:imm2 *) = concat (extract bin 14 12) (extract bin 7 6) 2
    let struct (sTyp, amount) (* sh:'0' *) =
      decodeImmShift (extract bin 21 20) imm5
    let shift = OprShift (sTyp, Imm amount)
    OprInfo (FourOperands (rd, imm, rn, shift), false, None)

(* <Rd>, #<imm>, <Rn>, ASR #<amount> *)
(* <Rd>, #<imm>, <Rn>, LSL #<amount> *)
type internal OprRdImmRnShfUT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let imm = extract bin 4 0 (* sat_imm *) |> int64 |> OprImm
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let imm5 (* imm3:imm2 *) = concat (extract bin 14 12) (extract bin 7 6) 2
    let struct (sTyp, amount) (* sh:'0' *) =
      decodeImmShift (extract bin 21 20) imm5
    let shift = OprShift (sTyp, Imm amount)
    OprInfo (FourOperands (rd, imm, rn, shift), false, None)

(* <Rd>, <Rn>, #<lsb>, #<width> *)
type internal OprRdRnLsbWidthT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let lsb (* imm3:imm2 *) =
      concat (extract bin 14 12) (extract bin 7 6) 2
    let width = (* msb - lsb + 1 *)
      (extract bin 4 0) - lsb + 1u |> int64 |> OprImm
    OprInfo (FourOperands (rd, rn, OprImm (int64 lsb), width), false, None)

(* <Rd>, <Rn>, #<lsb>, #<width> *)
type internal OprRdRnLsbWidthM1T () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let lsb (* imm3:imm2 *) =
      concat (extract bin 14 12) (extract bin 7 6) 2 |> int64 |> OprImm
    let width (* widthm1 + 1 *) =
      (extract bin 4 0 (* widthm1 *)) + 1u |> int64 |> OprImm
    OprInfo (FourOperands (rd, rn, lsb, width), false, None)


// vim: set tw=80 sts=2 sw=2:
