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
  | OprDdImm8A = 29
  | OprDdImm16A = 30
  | OprDdImm32A = 31
  | OprDdImm64A = 32
  | OprDdImmF32A = 33
  | OprDdLabel = 34
  | OprDdListDm = 35
  | OprDdmDdmFbits = 36
  | OprDdMem = 37
  | OprDdQm = 38
  | OprDdQmImm = 39
  | OprDdQnQm = 40
  | OprDdRt = 41
  | OprDdSm = 42
  | OprDdSnSm = 43
  | OprDdSnSmidx = 44
  | OprDdVImm = 45
  | OprDmRtRt2 = 46
  | OprEndianA = 47
  | OprIflagsA = 48
  | OprIflagsModeA = 49
  | OprImm16A = 50
  | OprImm1A = 51
  | OprImm24 = 52
  | OprImm4A = 53
  | OprLabel12A = 54
  | OprLabelA = 55
  | OprLabelH = 56
  | OprListMem = 57
  | OprListMem1 = 58
  | OprListMem2 = 59
  | OprListMem3 = 60
  | OprListMem4 = 61
  | OprListMemA = 62
  | OprListMemB = 63
  | OprListMemC = 64
  | OprListMemD = 65
  | OprMemImm = 66
  | OprMemRegA = 67
  | OprMode = 68
  | OprOpt = 69
  | OprP14C5Label = 70
  | OprP14C5Mem = 71
  | OprP14C5Option = 72
  | OprQdDm = 73
  | OprQdDmImm = 74
  | OprQdDmImm16 = 75
  | OprQdDmImm32 = 76
  | OprQdDmImm8 = 77
  | OprQdDmx = 78
  | OprQdDnDm = 79
  | OprQdDnDmidx = 80
  | OprQdDnDmx = 81
  | OprQdImm8A = 82
  | OprQdImm16A = 83
  | OprQdImm32A = 84
  | OprQdImm64A = 85
  | OprQdImmF32A = 86
  | OprQdQm = 87
  | OprQdQmFbits = 88
  | OprQdQmImm = 89
  | OprQdQmImm0 = 90
  | OprQdQmImmLeft = 91
  | OprQdQmQn = 92
  | OprQdQnDm = 93
  | OprQdQnDm0Rotate = 94
  | OprQdQnDmidx = 95
  | OprQdQnDmidxm = 96
  | OprQdQnDmidxRotate = 97
  | OprQdQnDmx = 98
  | OprQdQnQm = 99
  | OprQdQnQmImm = 100
  | OprQdQnQmRotate = 101
  | OprQdRt = 102
  | OprRdBankregA = 103
  | OprRdConstA = 104
  | OprRdConstCF = 105
  | OprRdImm16A = 106
  | OprRdImmRnA = 107
  | OprRdImmRnShfA = 108
  | OprRdImmRnShfUA = 109
  | OprRdLabelA = 110
  | OprRdlRdhRnRmA = 111
  | OprRdLsbWidthA = 112
  | OprRdRm = 113
  | OprRdRmImmA = 114
  | OprRdRmRnA = 115
  | OprRdRmRorA = 116
  | OprRdRmRsA = 117
  | OprRdRmShf = 118
  | OprRdRmShfRsA = 119
  | OprRdRnConstA = 120
  | OprRdRnConstCF = 121
  | OprRdRnLsbWidthA = 122
  | OprRdRnLsbWidthM1A = 123
  | OprRdRnRm = 124
  | OprRdRnRmOpt = 125
  | OprRdRnRmRaA = 126
  | OprRdRnRmRorA = 127
  | OprRdRnRmShfA = 128
  | OprRdRnRmShfRs = 129
  | OprRdRtMemA = 130
  | OprRdRtMemImmA = 131
  | OprRdRtRt2MemA = 132
  | OprRdSPConstA = 133
  | OprRdSregA = 134
  | OprRegs = 135
  | OprRm = 136
  | OprRn = 137
  | OprRnConstA = 138
  | OprRnConstCF = 139
  | OprRnDreglist = 140
  | OprRnRegsA = 141
  | OprRnRegsCaret = 142
  | OprRnRmShfA = 143
  | OprRnRmShfRs = 144
  | OprRnSreglist = 145
  | OprRt15Mem = 146
  | OprRtDn0 = 147
  | OprRtDn1 = 148
  | OprRtDn2 = 149
  | OprRtDn3 = 150
  | OprRtDn4 = 151
  | OprRtDn5 = 152
  | OprRtDn6 = 153
  | OprRtDn7 = 154
  | OprRtLabelA = 155
  | OprRtLabelHL = 156
  | OprRtMem = 157
  | OprRtMemImm = 158
  | OprRtMemImm0A = 159
  | OprRtMemImm12A = 160
  | OprRtMemImm12P = 161
  | OprRtMemImmP = 162
  | OprRtMemReg = 163
  | OprRtMemRegP = 164
  | OprRtMemShf = 165
  | OprRtMemShfP = 166
  | OprRtRt2Dm = 167
  | OprRtRt2LabelA = 168
  | OprRtRt2Mem2 = 169
  | OprRtRt2MemA = 170
  | OprRtRt2MemImmA = 171
  | OprRtRt2MemReg = 172
  | OprRtRt2SmSm1 = 173
  | OprRtSn = 174
  | OprRtSreg = 175
  | OprSdDm = 176
  | OprSdImm0 = 177
  | OprSdLabel = 178
  | OprSdMem = 179
  | OprSdmSdmFbits = 180
  | OprSdSm = 181
  | OprSdSnSm = 182
  | OprSdVImm = 183
  | OprSingleRegsA = 184
  | OprSmSm1RtRt2 = 185
  | OprSnRt = 186
  | OprSPMode = 187
  | OprSregImm = 188
  | OprSregRnA = 189
  | OprSregRt = 190
  | OprBankregRnT = 191
  | OprCondition = 192
  | OprDdDm0 = 193
  | OprDdImm8T = 194
  | OprDdImm16T = 195
  | OprDdImm32T = 196
  | OprDdImm64T = 197
  | OprDdImmF32T = 198
  | OprEndianT = 199
  | OprIflagsModeT = 200
  | OprIflagsT16 = 201
  | OprIflagsT32 = 202
  | OprImm16T = 203
  | OprImm1T = 204
  | OprImm4T = 205
  | OprImm6 = 206
  | OprImm8 = 207
  | OprLabel12T = 208
  | OprLabel8 = 209
  | OprLabelT = 210
  | OprLabelT2 = 211
  | OprLabelT3 = 212
  | OprLabelT4 = 213
  | OprMemImm12 = 214
  | OprMemImm8M = 215
  | OprMemRegLSL = 216
  | OprMemRegLSL1 = 217
  | OprMemRegT = 218
  | OprOptImm = 219
  | OprPCLRImm8 = 220
  | OprQdImm8T = 221
  | OprQdImm16T = 222
  | OprQdImm32T = 223
  | OprQdImm64T = 224
  | OprQdImmF32T = 225
  | OprQdQm0 = 226
  | OprRdBankregT = 227
  | OprRdConstT = 228
  | OprRdImm16T = 229
  | OprRdImm8 = 230
  | OprRdImmRnShfT = 231
  | OprRdImmRnShfUT = 232
  | OprRdImmRnT = 233
  | OprRdImmRnU = 234
  | OprRdLabelT = 235
  | OprRdlRdhRnRmT = 236
  | OprRdLsbWidthT = 237
  | OprRdmRdmASRRs = 238
  | OprRdmRdmLSLRs = 239
  | OprRdmRdmLSRRs = 240
  | OprRdmRdmRORRs = 241
  | OprRdmRnRdm = 242
  | OprRdmSPRdm = 243
  | OprRdnImm8 = 244
  | OprRdnRdnRm = 245
  | OprRdnRm = 246
  | OprRdRmExt = 247
  | OprRdRmImmT16 = 248
  | OprRdRmImmT32 = 249
  | OprRdRmRnT = 250
  | OprRdRmRorT = 251
  | OprRdRmRsT = 252
  | OprRdRmShfT16 = 253
  | OprRdRmShfT32 = 254
  | OprRdRmT16 = 255
  | OprRdRmT32 = 256
  | OprRdRn0 = 257
  | OprRdRn0T32 = 258
  | OprRdRnConstT = 259
  | OprRdRnImm12 = 260
  | OprRdRnImm3 = 261
  | OprRdRnLsbWidthM1T = 262
  | OprRdRnLsbWidthT = 263
  | OprRdRnRmRaT = 264
  | OprRdRnRmRorT = 265
  | OprRdRnRmShfT = 266
  | OprRdRnRmT16 = 267
  | OprRdRnRmT32 = 268
  | OprRdRtMemImmT = 269
  | OprRdRtMemT = 270
  | OprRdRtRt2MemT = 271
  | OprRdSPConstT = 272
  | OprRdSPImm12 = 273
  | OprRdSPImm8 = 274
  | OprRdSPRmShf = 275
  | OprRdSregT = 276
  | OprRegsM = 277
  | OprRegsP = 278
  | OprRmT16 = 279
  | OprRmT32 = 280
  | OprRnConstT = 281
  | OprRnLabel = 282
  | OprRnRegsT16 = 283
  | OprRnRegsT32 = 284
  | OprRnRegsW = 285
  | OprRnRm = 286
  | OprRnRmExt = 287
  | OprRnRmShfT = 288
  | OprRtLabel12 = 289
  | OprRtLabelT = 290
  | OprRtMemImm0T = 291
  | OprRtMemImm1 = 292
  | OprRtMemImm12T = 293
  | OprRtMemImm2 = 294
  | OprRtMemImm8 = 295
  | OprRtMemImm8M = 296
  | OprRtMemImm8P = 297
  | OprRtMemImmPr = 298
  | OprRtMemImmPs = 299
  | OprRtMemReg16 = 300
  | OprRtMemReg32 = 301
  | OprRtMemRegLSL = 302
  | OprRtMemSP = 303
  | OprRtRt2LabelT = 304
  | OprRtRt2MemImmT = 305
  | OprRtRt2MemT = 306
  | OprSingleRegsT = 307
  | OprSPSPImm7 = 308
  | OprSPSPRm = 309
  | OprSregRnT = 310

type OD = OprDesc

[<AutoOpen>]
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
        ((replicate (pickBit imm8 7 |> int64) 1 8<rt>) <<< 56) |||
        ((replicate (pickBit imm8 6 |> int64) 1 8<rt>) <<< 48) |||
        ((replicate (pickBit imm8 5 |> int64) 1 8<rt>) <<< 40) |||
        ((replicate (pickBit imm8 4 |> int64) 1 8<rt>) <<< 32) |||
        ((replicate (pickBit imm8 3 |> int64) 1 8<rt>) <<< 24) |||
        ((replicate (pickBit imm8 2 |> int64) 1 8<rt>) <<< 16) |||
        ((replicate (pickBit imm8 1 |> int64) 1 8<rt>) <<< 8) |||
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
  let getDtA bin =
    match concat (pickBit bin 24) (extract bin 21 20) 2 (* U:size *) with
    | 0b000u -> SIMDTypS8
    | 0b001u -> SIMDTypS16
    | 0b010u -> SIMDTypS32
    | 0b100u -> SIMDTypU8
    | 0b101u -> SIMDTypU16
    | 0b110u -> SIMDTypU32
    | _ -> raise ParsingFailureException

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

  let getDTF0 = function (* [21:20] *)
    | 0b01u -> SIMDTypI16
    | 0b10u -> SIMDTypI32
    | _ (* 00 or 11 *) -> raise UndefinedException

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

  /// Operand functions
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

  ///let parseCond n: Condition = n |> LanguagePrimitives.EnumOfValue

  let getVecSReg n: Register =
    n + 0x100u |> int |> LanguagePrimitives.EnumOfValue

  let getVecDReg n: Register =
    n + 0x200u |> int |> LanguagePrimitives.EnumOfValue

  let getVecQReg n: Register =
    (n >>> 1) + 0x300u |> int |> LanguagePrimitives.EnumOfValue

  let getCoprocCReg n: Register =
    n + 0x400u |> int |> LanguagePrimitives.EnumOfValue

  let getCoprocDReg n: Register =
    n + 0x500u |> int |> LanguagePrimitives.EnumOfValue

  let getOption n: Option = n |> int |> LanguagePrimitives.EnumOfValue

  let getDRegList fReg rNum = (* fReg: First Register, rNum: Number of regs *)
    List.map (fun r -> r |> getVecDReg) [ fReg .. fReg + rNum - 1u ]
    |> OprRegList

  let getSRegList fReg rNum =
    List.map (fun r -> r |> getVecSReg) [ fReg .. fReg + rNum - 1u ]
    |> OprRegList

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
    | Some st -> st |> parseCond
    | None -> Condition.AL

  /// aarch32/functions/common/T32ExpandImm_C on page J1-7767.
  // T32ExpandImm_C()
  // ================
  /// Modified immediate constants in A32 inOprInfoions on page F2-4135.
  let t32ExpandImm imm12 = (* _carryIn = *)
    if extract imm12 11 10 = 0b00u then
      let imm8 = extract imm12 7 0 (* imm12<7:0> *)
      match extract imm12 9 8 with
      | 0b00u -> imm8
      | 0b01u -> (imm8 <<< 16) + imm8
      | 0b10u -> (imm8 <<< 24) + (imm8 <<< 8)
      | _ (* 11 *) -> (imm8<<< 24) + (imm8 <<< 16) + (imm8 <<< 8) + imm8
    else
      let value = (1u <<< 7) + (extract imm12 6 0)
      let rotation = (extract imm12 11 7) % 32u |> int
      if rotation = 0 then value
      else (value >>> rotation) ||| (value <<< (32 - rotation))

  (* W == '1' *)
  let wbackW8 bin = pickBit bin 8 = 0b1u

  (* S8  when U = 0, size = 00
     S16 when U = 0, size = 01
     S32 when U = 0, size = 10
     U8  when U = 1, size = 00
     U16 when U = 1, size = 01
     U32 when U = 1, size = 10 *)
  let getDtT bin =
    match concat (pickBit bin 28) (extract bin 21 20) 2 (* U:size *) with
    | 0b000u -> SIMDTypS8
    | 0b001u -> SIMDTypS16
    | 0b010u -> SIMDTypS32
    | 0b100u -> SIMDTypU8
    | 0b101u -> SIMDTypU16
    | 0b110u -> SIMDTypU32
    | _ -> raise ParsingFailureException

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
  let getDTLImmT bin =
    let isSign = pickBit bin 28 (* U *) = 0u
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
  let getDTUImm3hT bin =
    match concat (pickBit bin 28) (extract bin 21 19) 3 (* U:imm3H *) with
    | 0b0001u -> SIMDTypS8
    | 0b0010u -> SIMDTypS16
    | 0b0100u -> SIMDTypS32
    | 0b1001u -> SIMDTypU8
    | 0b1010u -> SIMDTypU16
    | 0b1100u -> SIMDTypU32
    | _ -> raise ParsingFailureException
    |> oneDt

  (* S when U = 0
     U when U = 1
     16 when imm6<5:3> = 001
     32 when imm6<5:3> = 01x
     64 when imm6<5:3> = 1xx *)
  let getDTImm6WordT bin =
    let isSign = pickBit bin 28 (* U *) = 0u
    match extract bin 21 19 (* imm6<5:3> *) with
    | 0b000u -> raise ParsingFailureException
    | 0b001u -> if isSign then SIMDTypS16 else SIMDTypU16
    | 0b010u | 0b011u (* 01x *) -> if isSign then SIMDTypS32 else SIMDTypU32
    | _ (* 1xx *) -> if isSign then SIMDTypS64 else SIMDTypU64
    |> oneDt

  let getDTImm6ByteT bin =
    let isSign = pickBit bin 28 (* U *) = 0u
    match extract bin 21 19 (* imm6<5:3> *) with
    | 0b000u -> raise ParsingFailureException
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

type [<AbstractClass>] OperandParser () =
  abstract member Render: uint32 -> struct (Operands * bool * bool option)

and ParsingHelper (arch, mode, rd, addr, oprs, len, cond) =
  let isARMv7 = (arch = Arch.ARMv7)
  let mutable mode: ArchOperationMode = mode
  let mutable addr: Addr = addr
  let mutable len: uint32 = len
  let mutable cond: Condition = cond
  new (arch, reader, oparsers) =
    ParsingHelper (arch, ArchOperationMode.ARMMode,
                   reader, 0UL, oparsers, 0u, Condition.UN)
  member __.Arch with get(): Arch = arch
  member __.Mode with get() = mode and set (m) = mode <- m
  member __.BinReader with get(): IBinReader = rd
  member __.InsAddr with get() = addr and set(a) = addr <- a
  member __.OprParsers with get(): OperandParser [] = oprs
  member __.Len with get() = len and set (l) = len <- l
  member __.Cond with get() = cond and set (c) = cond <- c
  member __.IsARMv7 with get() = isARMv7

type internal OprNo () =
  inherit OperandParser ()
  override __.Render _ =
    struct (NoOperand, false, None)

(* <Rn>{!} *)
type internal OprRn () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister |> OprReg
    struct (OneOperand rn, wbackW bin, None)

(* <Rm> *)
type internal OprRm () =
  inherit OperandParser ()
  override __.Render bin =
    let rm = extract bin 3 0 |> getRegister |> OprReg
    struct (OneOperand rm, false, None)

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
    struct (OneOperand mem, false, None)

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
    struct (OneOperand mem, false, None)

(* {#}<imm> *)
type internal OprImm16A () =
  inherit OperandParser ()
  override __.Render bin =
    let imm = concat (extract bin 19 8) (extract bin 3 0) 4 |> int64 |> OprImm
    struct (OneOperand imm, false, None)

(* {#}<imm> *)
type internal OprImm24 () =
  inherit OperandParser ()
  override __.Render bin =
    struct (extract bin 23 0 |> int64 |> OprImm |> OneOperand, false, None)

(* {#}<imm4> *)
type internal OprImm4A () =
  inherit OperandParser ()
  override __.Render bin =
    struct (extract bin 3 0 |> int64 |> OprImm |> OneOperand, false, None)

(* #<imm> *)
type internal OprImm1A () =
  inherit OperandParser ()
  override __.Render bin =
    struct (pickBit bin 9 |> int64 |> OprImm |> OneOperand, false, None)

(* [<Rn> {, #{+/-}<imm>}]
   <label> Normal form
   [PC, #{+/-}<imm>] Alternative form *)
type internal OprLabel12A () =
  inherit OperandParser ()
  override __.Render bin =
    let imm12 = extract bin 11 0 |> int64
    let label =
      if pickBit bin 23 = 1u then memLabel imm12 else memLabel (imm12 * -1L)
    struct (OneOperand label, false, None)

(* <label> *)
type internal OprLabelA () =
  inherit OperandParser ()
  override __.Render bin =
    let label = extract bin 23 0 <<< 2 |> signExtend 26
    struct (OneOperand label, false, None)

(* <label> *)
type internal OprLabelH () =
  inherit OperandParser ()
  override __.Render bin =
    let label =
      (concat (extract bin 23 0) (pickBit bin 24) 1) <<< 1 |> signExtend 26
    struct (OneOperand label, false, None)

(* {<option>} *)
type internal OprOpt () =
  inherit OperandParser ()
  override __.Render bin =
    let option = extract bin 3 0 |> getOption |> OprOption
    struct (OneOperand option, false, None)

(* <endian_specifier> *)
type internal OprEndianA () =
  inherit OperandParser ()
  override __.Render bin =
    let endian = pickBit bin 9 |> byte |> getEndian |> OprEndian
    struct (OneOperand endian, false, None)

(* <registers> *)
type internal OprRegs () =
  inherit OperandParser ()
  override __.Render bin =
    let regs = extract bin 15 0 |> getRegList |> OprRegList
    struct (OneOperand regs, false, None)

(* <single_register_list> *)
type internal OprSingleRegsA () =
  inherit OperandParser ()
  override __.Render bin =
    let regs = OprRegList [ extract bin 15 12 |> getRegister ]
    struct (OneOperand regs, wback bin, None)

(* #<mode> *)
type internal OprMode () =
  inherit OperandParser ()
  override __.Render bin =
    struct (OneOperand (extract bin 4 0 |> int64 |> OprImm), false, None)

(* <iflags> *)
type internal OprIflagsA () =
  inherit OperandParser ()
  override __.Render bin =
    struct (OneOperand (OprIflag (getIflag (extract bin 8 6))), false, None)

(* <Rd>, <Rm> *)
type internal OprRdRm () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    struct (TwoOperands (rd, rm), false, None)

(* <Sd>, <Sm> *)
type internal OprSdSm () =
  inherit OperandParser ()
  override __.Render bin =
    let sd = (* Vd:D *)
      concat (extract bin 15 12) (pickBit bin 22) 1 |> getVecSReg |> toSVReg
    let sm = (* Vm:M *)
      concat (extract bin 3 0) (pickBit bin 5) 1 |> getVecSReg |> toSVReg
    struct (TwoOperands (sd, sm), false, None)

(* <Dd>, <Dm> *)
type internal OprDdDm () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    struct (TwoOperands (dd, dm), false, None)

(* <Dd>, <Sm> *)
type internal OprDdSm () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let sm = (* Vm:M *)
      concat (extract bin 3 0) (pickBit bin 5) 1 |> getVecSReg |> toSVReg
    struct (TwoOperands (dd, sm), false, None)

(* <Sd>, <Dm> *)
type internal OprSdDm () =
  inherit OperandParser ()
  override __.Render bin =
    let sd = (* Vd:D *)
      concat (extract bin 15 12) (pickBit bin 22) 1 |> getVecSReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    struct (TwoOperands (sd, dm), false, None)

(* <Sn>, <Rt> *)
type internal OprSnRt () =
  inherit OperandParser ()
  override __.Render bin =
    let sn = (* Vn:N *)
      concat (extract bin 19 16) (pickBit bin 7) 1 |> getVecSReg |> toSVReg
    let rt = extract bin 15 12 |> getRegister |> OprReg
    struct (TwoOperands (sn, rt), false, None)

(* <Rt>, <Sn> *)
type internal OprRtSn () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let sn = (* Vn:N *)
      concat (extract bin 19 16) (pickBit bin 7) 1 |> getVecSReg |> toSVReg
    struct (TwoOperands (rt, sn), false, None)

(* <Qd>, <Qm> *)
type internal OprQdQm () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let qm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecQReg |> toSVReg
    struct (TwoOperands (qd, qm), false, None)

(* <Dd>, <Qm> *)
type internal OprDdQm () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let qm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecQReg |> toSVReg
    struct (TwoOperands (dd, qm), false, None)

(* <Qd>, <Dm> *)
type internal OprQdDm () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    struct (TwoOperands (qd, dm), false, None)

(* <spec_reg>, <Rt> *)
type internal OprSregRt () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    struct (TwoOperands (OprReg R.FPSCR, rt), false, None)

(* <Rt>, <spec_reg> *)
type internal OprRtSreg () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    struct (TwoOperands (rt, OprReg R.FPSCR), false, None)

(* <Rd>, <spec_reg> *)
type internal OprRdSregA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let sreg =
      if pickBit bin 22 = 0u then R.APSR (* or CPSR *) else R.SPSR
      |> uint |> getRegister |> OprReg
    struct (TwoOperands (rd, sreg), false, None)

(* <spec_reg>, <Rn> *)
type internal OprSregRnA () =
  inherit OperandParser ()
  override __.Render bin =
    let struct (sreg, flag) = getCPSR (extract bin 19 16)
    let rn = extract bin 3 0 |> getRegister |> OprReg
    struct (TwoOperands (OprSpecReg (sreg, flag), rn), false, None)

(* <Rd>, <banked_reg> *)
type internal OprRdBankregA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let breg =
      concat (pickBit bin 8) (extract bin 19 16) 4
      |> getBankedReg (pickBit bin 22) |> OprReg
    struct (TwoOperands (rd, breg), false, None)

(* <banked_reg>, <Rn> *)
type internal OprBankregRnA () =
  inherit OperandParser ()
  override __.Render bin =
    let breg =
      concat (pickBit bin 8) (extract bin 19 16) 4
      |> getBankedReg (pickBit bin 22) |> OprReg
    let rn = extract bin 3 0 |> getRegister |> OprReg
    struct (TwoOperands (breg, rn), false, None)

(* <Dd[x]>, <Rt> *)
type internal OprDd0Rt () =
  inherit OperandParser ()
  override __.Render bin =
    let d = concat (pickBit bin 7) (extract bin 19 16) 4 (* D:Vd *)
    let dd0 = toSSReg (d |> getVecDReg, Some 0uy)
    let rt = extract bin 15 12 |> getRegister |> OprReg
    struct (TwoOperands (dd0, rt), false, None)

type internal OprDd1Rt () =
  inherit OperandParser ()
  override __.Render bin =
    let d = concat (pickBit bin 7) (extract bin 19 16) 4 (* D:Vd *)
    let dd1 = toSSReg (d |> getVecDReg, Some 1uy)
    let rt = extract bin 15 12 |> getRegister |> OprReg
    struct (TwoOperands (dd1, rt), false, None)

type internal OprDd2Rt () =
  inherit OperandParser ()
  override __.Render bin =
    let d = concat (pickBit bin 7) (extract bin 19 16) 4 (* D:Vd *)
    let dd2 = toSSReg (d |> getVecDReg, Some 2uy)
    let rt = extract bin 15 12 |> getRegister |> OprReg
    struct (TwoOperands (dd2, rt), false, None)

type internal OprDd3Rt () =
  inherit OperandParser ()
  override __.Render bin =
    let d = concat (pickBit bin 7) (extract bin 19 16) 4 (* D:Vd *)
    let dd3 = toSSReg (d |> getVecDReg, Some 3uy)
    let rt = extract bin 15 12 |> getRegister |> OprReg
    struct (TwoOperands (dd3, rt), false, None)

type internal OprDd4Rt () =
  inherit OperandParser ()
  override __.Render bin =
    let d = concat (pickBit bin 7) (extract bin 19 16) 4 (* D:Vd *)
    let dd4 = toSSReg (d |> getVecDReg, Some 4uy)
    let rt = extract bin 15 12 |> getRegister |> OprReg
    struct (TwoOperands (dd4, rt), false, None)

type internal OprDd5Rt () =
  inherit OperandParser ()
  override __.Render bin =
    let d = concat (pickBit bin 7) (extract bin 19 16) 4 (* D:Vd *)
    let dd5 = toSSReg (d |> getVecDReg, Some 5uy)
    let rt = extract bin 15 12 |> getRegister |> OprReg
    struct (TwoOperands (dd5, rt), false, None)

type internal OprDd6Rt () =
  inherit OperandParser ()
  override __.Render bin =
    let d = concat (pickBit bin 7) (extract bin 19 16) 4 (* D:Vd *)
    let dd6 = toSSReg (d |> getVecDReg, Some 6uy)
    let rt = extract bin 15 12 |> getRegister |> OprReg
    struct (TwoOperands (dd6, rt), false, None)

type internal OprDd7Rt () =
  inherit OperandParser ()
  override __.Render bin =
    let d = concat (pickBit bin 7) (extract bin 19 16) 4 (* D:Vd *)
    let dd7 = toSSReg (d |> getVecDReg, Some 7uy)
    let rt = extract bin 15 12 |> getRegister |> OprReg
    struct (TwoOperands (dd7, rt), false, None)

(* <Rt>, <Dn[x]> *)
type internal OprRtDn0 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let n = concat (pickBit bin 7) (extract bin 19 16) 4 (* N:Vn *)
    let dn0 = toSSReg (n |> getVecDReg, Some 0uy)
    struct (TwoOperands (rt, dn0), false, None)

type internal OprRtDn1 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let n = concat (pickBit bin 7) (extract bin 19 16) 4 (* N:Vn *)
    let dn1 = toSSReg (n |> getVecDReg, Some 1uy)
    struct (TwoOperands (rt, dn1), false, None)

type internal OprRtDn2 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let n = concat (pickBit bin 7) (extract bin 19 16) 4 (* N:Vn *)
    let dn2 = toSSReg (n |> getVecDReg, Some 2uy)
    struct (TwoOperands (rt, dn2), false, None)

type internal OprRtDn3 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let n = concat (pickBit bin 7) (extract bin 19 16) 4 (* N:Vn *)
    let dn3 = toSSReg (n |> getVecDReg, Some 3uy)
    struct (TwoOperands (rt, dn3), false, None)

type internal OprRtDn4 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let n = concat (pickBit bin 7) (extract bin 19 16) 4 (* N:Vn *)
    let dn4 = toSSReg (n |> getVecDReg, Some 4uy)
    struct (TwoOperands (rt, dn4), false, None)

type internal OprRtDn5 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let n = concat (pickBit bin 7) (extract bin 19 16) 4 (* N:Vn *)
    let dn5 = toSSReg (n |> getVecDReg, Some 5uy)
    struct (TwoOperands (rt, dn5), false, None)

type internal OprRtDn6 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let n = concat (pickBit bin 7) (extract bin 19 16) 4 (* N:Vn *)
    let dn6 = toSSReg (n |> getVecDReg, Some 6uy)
    struct (TwoOperands (rt, dn6), false, None)

type internal OprRtDn7 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let n = concat (pickBit bin 7) (extract bin 19 16) 4 (* N:Vn *)
    let dn7 = toSSReg (n |> getVecDReg, Some 7uy)
    struct (TwoOperands (rt, dn7), false, None)

(* <Qd>, <Rt> *)
type internal OprQdRt () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 7) (extract bin 19 16) 4 |> getVecQReg |> toSVReg
    let rt = extract bin 15 12 |> getRegister |> OprReg
    struct (TwoOperands (qd, rt), false, None)

(* <Dd>, <Rt> *)
type internal OprDdRt () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 7) (extract bin 19 16) 4 |> getVecDReg |> toSVReg
    let rt = extract bin 15 12 |> getRegister |> OprReg
    struct (TwoOperands (dd, rt), false, None)

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
    struct (TwoOperands (dd, dmx), false, None)

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
    struct (TwoOperands (qd, dmx), false, None)

(* <Rt>, [<Rn>] *)
type internal OprRt15Mem () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem = memOffsetImm (extract bin 19 16 |> getRegister, None, None)
    struct (TwoOperands (rt, mem), false, None)

(* <Rt>, [<Rn>] *)
type internal OprRtMem () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 3 0 |> getRegister |> OprReg
    let mem = memOffsetImm (extract bin 19 16 |> getRegister, None, None)
    struct (TwoOperands (rt, mem), false, None)

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
    struct (TwoOperands (sd, mem), false, None)

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
    struct (TwoOperands (dd, mem), false, None)

(* <Rt>, [<Rn> {, {#}<imm>}] *)
type internal OprRtMemImm0A () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem = (* imm32 = 0 *)
      memOffsetImm (extract bin 19 16 |> getRegister, None, None)
    struct (TwoOperands (rt, mem), false, None)

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
    struct (TwoOperands (rt, mem), wback bin, None)

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
    struct (TwoOperands (rt, mem), wback bin, None)

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
    struct (TwoOperands (rt, mem), false, None)

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
    struct (TwoOperands (rt, mem), wback bin, None)

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
    struct (TwoOperands (rt, mem), false, None)

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
    struct (TwoOperands (rt, mem), wback bin, None)

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
    struct (TwoOperands (rt, mem), false, None)

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
    struct (TwoOperands (rt, mem), false, None)

(* <Dd>, #<imm> *)
type internal OprDdImm8A () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let imm = advSIMDExpandImm bin (pickBit bin 24) |> int64
    let imm = imm &&& 0xFFL |> OprImm
    struct (TwoOperands (dd, imm), false, None)

(* <Dd>, #<imm> *)
type internal OprDdImm16A () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let imm = advSIMDExpandImm bin (pickBit bin 24) |> int64
    let imm = imm &&& 0xFFFFL |> OprImm
    struct (TwoOperands (dd, imm), false, None)

(* <Dd>, #<imm> *)
type internal OprDdImm32A () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let imm = advSIMDExpandImm bin (pickBit bin 24) |> int64
    let imm = imm &&& 0xFFFFFFFFL |> OprImm
    struct (TwoOperands (dd, imm), false, None)

(* <Dd>, #<imm> *)
type internal OprDdImm64A () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let imm = advSIMDExpandImm bin (pickBit bin 24) |> int64 |> OprImm
    struct (TwoOperands (dd, imm), false, None)

(* <Dd>, #<imm> *)
type internal OprDdImmF32A () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let imm = advSIMDExpandImm bin (pickBit bin 24) |> int64
    let imm = imm &&& 0xFFFFFFFFL |> OprImm (* F32 *)
    struct (TwoOperands (dd, imm), false, None)

(* <Qd>, #<imm> *)
type internal OprQdImm8A () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let imm = advSIMDExpandImm bin (pickBit bin 24) |> int64
    let imm = imm &&& 0xFFL |> OprImm
    struct (TwoOperands (qd, imm), false, None)

(* <Qd>, #<imm> *)
type internal OprQdImm16A () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let imm = advSIMDExpandImm bin (pickBit bin 24) |> int64
    let imm = imm &&& 0xFFFFL |> OprImm
    struct (TwoOperands (qd, imm), false, None)

(* <Qd>, #<imm> *)
type internal OprQdImm32A () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let imm = advSIMDExpandImm bin (pickBit bin 24) |> int64
    let imm = imm &&& 0xFFFFFFFFL |> OprImm
    struct (TwoOperands (qd, imm), false, None)

(* <Qd>, #<imm> *)
type internal OprQdImm64A () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let imm = advSIMDExpandImm bin (pickBit bin 24) |> int64 |> OprImm
    struct (TwoOperands (qd, imm), false, None)

(* <Qd>, #<imm> *)
type internal OprQdImmF32A () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let imm = advSIMDExpandImm bin (pickBit bin 24) |> int64
    let imm = imm &&& 0xFFFFFFL |> OprImm
    struct (TwoOperands (qd, imm), false, None)

(* <Sd>, #<imm> *)
type internal OprSdVImm () =
  inherit OperandParser ()
  override __.Render bin =
    let sd = (* Vd:D *)
      concat (extract bin 15 12) (pickBit bin 22) 1 |> getVecSReg |> toSVReg
    let imm = (* imm4H:imm4L *)
      let imm8 = concat (extract bin 19 16) (extract bin 3 0) 4
      vfpExpandImm bin imm8 |> int64 |> OprImm
    struct (TwoOperands (sd, imm), false, None)

(* <Dd>, #<imm> *)
type internal OprDdVImm () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let imm = (* imm4H:imm4L *)
      let imm8 = concat (extract bin 19 16) (extract bin 3 0) 4
      vfpExpandImm bin imm8 |> int64 |> OprImm
    struct (TwoOperands (dd, imm), false, None)

(* <Sd>, #0.0 *)
type internal OprSdImm0 () =
  inherit OperandParser ()
  override __.Render bin =
    let sd = (* Vd:D *)
      concat (extract bin 15 12) (pickBit bin 22) 1 |> getVecSReg |> toSVReg
    struct (TwoOperands (sd, OprImm 0L), false, None)

(* <Dd>, #0.0 *)
type internal OprDdImm0 () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    struct (TwoOperands (dd, OprImm 0L), false, None)

(* <Rd>, #<imm16> *)
type internal OprRdImm16A () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let imm16 = (* imm4:imm12 *)
      concat (extract bin 19 16) (extract bin 11 0) 12 |> int64 |> OprImm
    struct (TwoOperands (rd, imm16), false, None)

(* <spec_reg>, #<imm> *)
type internal OprSregImm () =
  inherit OperandParser ()
  override __.Render bin =
    let struct (sreg, flag) = getCPSR (extract bin 19 16)
    let imm = expandImmediate bin |> int64 |> OprImm
    struct (TwoOperands (OprSpecReg (sreg, flag), imm), false, None)

(* <Rd>, #<const> *)
type internal OprRdConstA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let imm = expandImmediate bin |> int64 |> OprImm
    struct (TwoOperands (rd, imm), false, None)

(* <Rd>, #<const> with carry *)
type internal OprRdConstCF () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let struct (imm32, carryOut) = expandImmCF bin
    struct (TwoOperands (rd, imm32), false, carryOut)

(* <Rn>, #<const> *)
type internal OprRnConstA () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let imm = expandImmediate bin |> int64 |> OprImm
    struct (TwoOperands (rn, imm), false, None)

(* <Rn>, #<const> with carry *)
type internal OprRnConstCF () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let struct (imm32, carryOut) = expandImmCF bin
    struct (TwoOperands (rn, imm32), false, carryOut)

(* <Sd>, <label> *)
type internal OprSdLabel () =
  inherit OperandParser ()
  override __.Render bin =
    let sd = (* Vd:D *)
      concat (extract bin 15 12) (pickBit bin 22) 1 |> getVecSReg |> toSVReg
    let label = extract bin 7 0 (* imm8 *) |> int64 |> memLabel
    struct (TwoOperands (sd, label), false, None)

(* <Dd>, <label> *)
type internal OprDdLabel () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let label = extract bin 7 0 (* imm8 *) |> int64 |> memLabel
    struct (TwoOperands (dd, label), false, None)

(* <Rd>, <label> *)
type internal OprRdLabelA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let label = expandImmediate bin |> int64 |> memLabel
    struct (TwoOperands (rd, label), false, None)

(* <Rt>, <label> *)
type internal OprRtLabelA () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let imm12 = extract bin 11 0 |> int64
    let label =
      if pickBit bin 23 = 1u then memLabel imm12 else memLabel (imm12 * -1L)
    struct (TwoOperands (rt, label), wback bin, None)

(* <Rt>, <label> *)
type internal OprRtLabelHL () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let label = (* imm4H:imm4L *)
      concat (extract bin 11 8) (extract bin 3 0) 4 |> int64 |> memLabel
    struct (TwoOperands (rt, label), wback bin, None)

(* <Rn>{!}, <registers> *)
type internal OprRnRegsA () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let regs = extract bin 15 0 (* register_list *) |> getRegList |> OprRegList
    struct (TwoOperands (rn, regs), wbackW bin, None)

(* <Rn>, <registers>^ *)
type internal OprRnRegsCaret () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let regs = extract bin 15 0 (* register_list *) |> getRegList |> OprRegList
    struct (TwoOperands (rn, regs), false, None)

(* <Rn>{!}, <dreglist> *)
type internal OprRnDreglist () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let regs = extract bin 7 0 (* imm8 *) / 2u
    let dreglist = (* D:Vd *)
      getDRegList (concat (pickBit bin 22) (extract bin 15 12) 4) regs
    struct (TwoOperands (rn, dreglist), wbackW bin, None)

(* <Rn>{!}, <sreglist> *)
type internal OprRnSreglist () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let regs = extract bin 7 0 (* imm8 *)
    let sreglist = (* Vd:D *)
      getSRegList (concat (extract bin 15 12) (pickBit bin 22) 1) regs
    struct (TwoOperands (rn, sreglist), wbackW bin, None)

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
    struct (TwoOperands (list, mem), wbackM bin, None)

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
    struct (TwoOperands (list, mem), wbackM bin, None)

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
    struct (TwoOperands (list, mem), wbackM bin, None)

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
    struct (TwoOperands (list, mem), wbackM bin, None)

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
    struct (TwoOperands (list, mem), wbackM bin, None)

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
    struct (TwoOperands (list, mem), wbackM bin, None)

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
    struct (TwoOperands (list, mem), wbackM bin, None)

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
    struct (TwoOperands (list, mem), wbackM bin, None)

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
    struct (TwoOperands (list, mem), wbackM bin, None)

(* SP{!}, #<mode> *)
type internal OprSPMode () =
  inherit OperandParser ()
  override __.Render bin =
    let mode = extract bin 5 0 |> int64 |> OprImm
    struct (TwoOperands (OprReg R.SP, mode), wbackW bin, None)

(* <iflags> , #<mode> *)
type internal OprIflagsModeA () =
  inherit OperandParser ()
  override __.Render bin =
    let iflags = OprIflag (getIflag (extract bin 8 6))
    let mode = extract bin 4 0 |> int64 |> OprImm
    struct (TwoOperands (iflags, mode), false, None)

(* <Dm>, <Rt>, <Rt2> *)
type internal OprDmRtRt2 () =
  inherit OperandParser ()
  override __.Render bin =
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let rt2 = extract bin 19 16 |> getRegister |> OprReg
    struct (ThreeOperands (dm, rt, rt2), false, None)

(* <Rt>, <Rt2>, <Dm> *)
type internal OprRtRt2Dm () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let rt2 = extract bin 19 16 |> getRegister |> OprReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    struct (ThreeOperands (rt, rt2, dm), false, None)

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
    struct (ThreeOperands (dd, sn, sm), false, None)

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
    struct (ThreeOperands (dd, sn, smidx), false, None)

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
    struct (ThreeOperands (sd, sn, sm), false, None)

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
    struct (ThreeOperands (dd, dn, dm), false, None)

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
    struct (ThreeOperands (dd, dn, dmidx), false, None)

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
    struct (ThreeOperands (dd, dm, dn), false, None)

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
    struct (ThreeOperands (qd, qn, qm), false, None)

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
    struct (ThreeOperands (qd, qm, qn), false, None)

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
    struct (ThreeOperands (qd, dn, dmidx), false, None)

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
    struct (ThreeOperands (qd, dn, dm), false, None)

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
    struct (ThreeOperands (qd, qn, dm), false, None)

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
    struct (ThreeOperands (qd, qn, dmidx), false, None)

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
    struct (ThreeOperands (qd, qn, dmidx), false, None)

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
    struct (ThreeOperands (dd, qn, qm), false, None)

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
    struct (ThreeOperands (dd, dn, dmx), false, None)

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
    struct (ThreeOperands (qd, qn, dmx), false, None)

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
    struct (ThreeOperands (qd, dn, dmx), false, None)

(* <Rd>, <Rn>, <Rm> *)
(* {<Rd>,} <Rn>, <Rm> : SADD16? *)
type internal OprRdRnRm () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    struct (ThreeOperands (rd, rn, rm), false, None)

(* <Rd>, <Rn>{, <Rm>} *)
(* {<Rd>,} <Rn>, <Rm> *)
type internal OprRdRnRmOpt () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 19 16 |> getRegister |> OprReg
    let rn = extract bin 3 0 |> getRegister |> OprReg
    let rm = extract bin 11 8 |> getRegister |> OprReg
    struct (ThreeOperands (rd, rn, rm), false, None)

(* {<Rd>,} <Rm>, <Rs> *)
type internal OprRdRmRsA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let rs = extract bin 11 8 |> getRegister |> OprReg
    struct (ThreeOperands (rd, rm, rs), false, None)

(* {<Rd>,} <Rm>, <Rn> *)
type internal OprRdRmRnA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    struct (ThreeOperands (rd, rm, rn), false, None)

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
    struct (ThreeOperands (rt, rt2, mem), wback bin, None)

(* <Rt>, <Rt2>, [<Rn>] *)
type internal OprRtRt2MemA () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 3 0 |> getRegister |> OprReg
    let rt2 = extract bin 3 0 + 1u |> getRegister |> OprReg
    let mem =
      memOffsetImm (extract bin 19 16 (* Rn *) |> getRegister, None, None)
    struct (ThreeOperands (rt, rt2, mem), false, None)

(* <Rt>, <Rt2>, [<Rn>] *)
type internal OprRtRt2Mem2 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let rt2 = extract bin 3 0 |> getRegister |> OprReg
    let mem =
      memOffsetImm (extract bin 19 16 (* Rn *) |> getRegister, None, None)
    struct (ThreeOperands (rt, rt2, mem), false, None)

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
    struct (ThreeOperands (rt, rt2, mem), wback bin, None)

(* <Rd>, <Rt>, [<Rn>] *)
type internal OprRdRtMemA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rt = extract bin 3 0 |> getRegister |> OprReg
    let mem = memOffsetImm (extract bin 19 16 |> getRegister, None, None)
    struct (ThreeOperands (rd, rt, mem), false, None)

(* <Rd>, <Rt>, [<Rn> {, {#}<imm>}] *)
type internal OprRdRtMemImmA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rt = extract bin 3 0 |> getRegister |> OprReg
    let mem = (* Rn, imm32 = 0 *)
      memOffsetImm (extract bin 19 16 |> getRegister, None, None)
    struct (ThreeOperands (rd, rt, mem), false, None)

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
    struct (ThreeOperands (OprReg R.P14, OprReg R.C5, mem), wbackW bin, None)

(* p14, c5, [<Rn>], <option> *)
type internal OprP14C5Option () =
  inherit OperandParser ()
  override __.Render bin =
    let mem =
      let rn = extract bin 19 16 |> getRegister
      memUnIdxImm (rn, extract bin 7 0 (* imm8 *) |> int64)
    struct (ThreeOperands (OprReg R.P14, OprReg R.C5, mem), wbackW bin, None)

(* {<Rd>,} <Rn>, #<const> *)
type internal OprRdRnConstA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let cons = expandImmediate bin |> int64 |> OprImm
    struct (ThreeOperands (rd, rn, cons), false, None)

(* {<Rd>,} <Rn>, #<const> with carry *)
type internal OprRdRnConstCF () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let struct (imm32, carryOut) = expandImmCF bin
    struct (ThreeOperands (rd, rn, imm32), false, carryOut)

(* {<Rd>,} SP, #<const> *)
type internal OprRdSPConstA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let cons = expandImmediate bin |> int64 |> OprImm
    struct (ThreeOperands (rd, OprReg R.SP, cons), false, None)

(* {<Rd>,} <Rm>, #<imm> : MOV alias *)
type internal OprRdRmImmA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let imm = extract bin 11 7 (* imm5 *) |> int64 |> OprImm
    struct (ThreeOperands (rd, rm, imm), false, None)

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
    struct (ThreeOperands (dd, dm, imm), false, None)

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
    struct (ThreeOperands (dd, dm, imm), false, None)

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
    struct (ThreeOperands (qd, qm, imm), false, None)

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
    struct (ThreeOperands (qd, qm, imm), false, None)

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
    struct (ThreeOperands (dd, qm, imm), false, None)

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
    struct (ThreeOperands (qd, dm, imm), false, None)

(* <Qd>, <Dm>, #<imm> *)
type internal OprQdDmImm8 () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    struct (ThreeOperands (qd, dm, OprImm 8L), false, None)

(* <Qd>, <Dm>, #<imm> *)
type internal OprQdDmImm16 () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    struct (ThreeOperands (qd, dm, OprImm 16L), false, None)

(* <Qd>, <Dm>, #<imm> *)
type internal OprQdDmImm32 () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    struct (ThreeOperands (qd, dm, OprImm 32L), false, None)

(* {<Dd>,} <Dm>, #0 *)
type internal OprDdDmImm0 () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    struct (ThreeOperands (dd, dm, OprImm 0L), false, None)

(* {<Qd>,} <Qm>, #0 *)
type internal OprQdQmImm0 () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let qm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecQReg |> toSVReg
    struct (ThreeOperands (qd, qm, OprImm 0L), false, None)

(* <Rn>, <Rm>, RRX *)
(* <Rn>, <Rm> {, <shift> #<amount>} *)
type internal OprRnRmShfA () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let struct (shift, amount) =
      decodeImmShift (extract bin 6 5) (extract bin 11 7) (* stype imm5 *)
    struct (ThreeOperands (rn, rm, OprShift (shift, Imm amount)), false, None)

(* <Rd>, <Rm>, RRX *)
(* <Rd>, <Rm> {, <shift> #<amount>} *)
type internal OprRdRmShf () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let struct (shift, amount) =
      decodeImmShift (extract bin 6 5) (extract bin 11 7) (* stype imm5 *)
    struct (ThreeOperands (rd, rm, OprShift (shift, Imm amount)), false, None)

(* <Rn>, <Rm>, <type> <Rs> *)
type internal OprRnRmShfRs () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let shift =
      let rs = extract bin 11 8 |> getRegister
      OprRegShift (decodeRegShift (extract bin 6 5 (* stype *)), rs)
    struct (ThreeOperands (rn, rm, shift), false, None)

(* <Rd>, <Rm>, <shift> <Rs> *)
type internal OprRdRmShfRsA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let shift =
      let rs = extract bin 11 8 |> getRegister
      OprRegShift (decodeRegShift (extract bin 6 5 (* stype *)), rs)
    struct (ThreeOperands (rd, rm, shift), false, None)

(* {<Rd>,} <Rm> {, ROR #<amount>} *)
type internal OprRdRmRorA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let shift = OprShift (SRType.SRTypeROR, extract bin 11 10 <<< 3 |> Imm)
    struct (ThreeOperands (rd, rm, shift), false, None)

(* <Rd>, #<imm>, <Rn> *)
type internal OprRdImmRnA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let imm = extract bin 19 16 (* sat_imm *) + 1u |> int64 |> OprImm
    let rn = extract bin 3 0 |> getRegister |> OprReg
    struct (ThreeOperands (rd, imm, rn), false, None)

(* <Rd>, #<lsb>, #<width> *)
type internal OprRdLsbWidthA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let lsb = extract bin 11 7 |> int64 |> OprImm
    let width = (* msb - lsb + 1 *)
      (extract bin 20 16) - (extract bin 11 7) + 1u |> int64 |> OprImm
    struct (ThreeOperands (rd, lsb, width), false, None)

(* <Rt>, <Rt2>, <label> *)
type internal OprRtRt2LabelA () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let rt2 = extract bin 15 12 + 1u |> getRegister |> OprReg
    let label = (* imm4H:imm4L *)
      concat (extract bin 11 8) (extract bin 3 0) 4 |> int64 |> memLabel
    struct (ThreeOperands (rt, rt2, label), false, None)

(* p14, c5, <label> *)
type internal OprP14C5Label () =
  inherit OperandParser ()
  override __.Render bin =
    let label = extract bin 7 0 <<< 2 (* imm8:00 *) |> int64 |> memLabel
    struct (ThreeOperands (OprReg R.P14, OprReg R.C5, label), false, None)

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
    struct (ThreeOperands (sdm, sdm, fbits), false, None)

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
    struct (ThreeOperands (ddm, ddm, fbits), false, None)

(* <Dd>, <Dm>, #<fbits> *)
type internal OprDdDmFbits () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    let fbits = 64u - extract bin 21 16 |> int64 |> OprImm
    struct (ThreeOperands (dd, dm, fbits), false, None)

(* <Qd>, <Qm>, #<fbits> *)
type internal OprQdQmFbits () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let qm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecQReg |> toSVReg
    let fbits = 64u - extract bin 21 16 |> int64 |> OprImm
    struct (ThreeOperands (qd, qm, fbits), false, None)

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
    struct (ThreeOperands (dd, list, dm), false, None)

(* <Rd>, <Rn>, <Rm>, <Ra> *)
type internal OprRdRnRmRaA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 19 16 |> getRegister |> OprReg
    let rn = extract bin 3 0 |> getRegister |> OprReg
    let rm = extract bin 11 8 |> getRegister |> OprReg
    let ra = extract bin 15 12 |> getRegister |> OprReg
    struct (FourOperands (rd, rn, rm, ra), false, None)

(* <RdLo>, <RdHi>, <Rn>, <Rm> *)
type internal OprRdlRdhRnRmA () =
  inherit OperandParser ()
  override __.Render bin =
    let rdLo = extract bin 15 12 |> getRegister |> OprReg
    let rdHi = extract bin 19 16 |> getRegister |> OprReg
    let rn = extract bin 3 0 |> getRegister |> OprReg
    let rm = extract bin 11 8 |> getRegister |> OprReg
    struct (FourOperands (rdLo, rdHi, rn, rm), false, None)

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
    struct (FourOperands (sm, sm1, rt, rt2), false, None)

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
    struct (FourOperands (rt, rt2, sm, sm1), false, None)

(* <Rd>, <Rt>, <Rt2>, [<Rn>] *)
type internal OprRdRtRt2MemA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rt = extract bin 3 0 |> getRegister |> OprReg
    let rt2 = extract bin 3 0 + 1u |> getRegister |> OprReg
    let mem = memOffsetImm (extract bin 19 16 |> getRegister, None, None)
    struct (FourOperands (rd, rt, rt2, mem), false, None)

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
    struct (FourOperands (dd, dn, dm, imm), false, None)

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
    struct (FourOperands (qd, qn, qm, imm), false, None)

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
    struct (FourOperands (rd, rn, rm, OprShift (shift, Imm amount)), false, None)

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
    struct (FourOperands (rd, rn, rm, shift), false, None)

(* {<Rd>,} <Rn>, <Rm> {, ROR #<amount>} *)
type internal OprRdRnRmRorA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let shift = OprShift (SRType.SRTypeROR, extract bin 11 10 <<< 3 |> Imm)
    struct (FourOperands (rd, rn, rm, shift), false, None)

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
    struct (FourOperands (rd, imm, rn, OprShift (sTyp, Imm amount)), false, None)

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
    struct (FourOperands (rd, imm, rn, OprShift (sTyp, Imm amount)), false, None)

(* <Rd>, <Rn>, #<lsb>, #<width> *)
type internal OprRdRnLsbWidthA () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rn = extract bin 3 0 |> getRegister |> OprReg
    let lsb = extract bin 11 7 |> int64 |> OprImm
    let width = (* msb - lsb + 1 *)
      (extract bin 20 16) - (extract bin 11 7) + 1u |> int64 |> OprImm
    struct (FourOperands (rd, rn, lsb, width), false, None)

(* <Rd>, <Rn>, #<lsb>, #<width> *)
type internal OprRdRnLsbWidthM1A () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 15 12 |> getRegister |> OprReg
    let rn = extract bin 3 0 |> getRegister |> OprReg
    let lsb = extract bin 11 7 |> int64 |> OprImm
    let width = (* widthm1 + 1 *)
      (extract bin 20 16 (* widthm1 *)) + 1u |> int64 |> OprImm
    struct (FourOperands (rd, rn, lsb, width), false, None)

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
    struct (FourOperands (dd, dn, dm, rotate), false, None)

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
    struct (FourOperands (qd, qn, qm, rotate), false, None)

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
    struct (FourOperands (dd, dn, dmidx, rotate), false, None)

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
    struct (FourOperands (qd, qn, dmidx, rotate), false, None)

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
    struct (FourOperands (dd, dn, dm0, rotate), false, None)

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
    struct (FourOperands (qd, qn, dm0, rotate), false, None)

(* <coproc>, {#}<opc1>, <Rt>, <Rt2>, <CRm> *)
type internal OprCpOpc1RtRt2CRm () =
  inherit OperandParser ()
  override __.Render bin =
    let coproc = extract bin 11 8 |> getCoprocDReg |> OprReg
    let opc1 = extract bin 7 4 |> int64 |> OprImm
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let rt2 = extract bin 19 16 |> getRegister |> OprReg
    let crm = extract bin 3 0 |> getCoprocCReg |> OprReg
    struct (FiveOperands (coproc, opc1, rt, rt2, crm), false, None)

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
    struct (SixOperands (coproc, opc1, rt, crn, crm, opc2), false, None)

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
    struct (SixOperands (coproc, opc1, crd, crn, crm, opc2), false, None)

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
    struct (ThreeOperands (coproc, crd, mem), wbackW bin, None)

(* <label> *)
type internal OprLabelT () =
  inherit OperandParser ()
  override __.Render bin =
    let label = (extract bin 10 0 <<< 1) |> signExtend 12
    struct (OneOperand label, false, None)

(* <label> *)
type internal OprLabel8 () =
  inherit OperandParser ()
  override __.Render bin =
    let label = extract bin 7 0 <<< 1 |> signExtend 9
    struct (OneOperand label, false, None)

(* <label> // Preferred syntax
   [PC, #{+/-}<imm>] // Alternative syntax *)
type internal OprLabel12T () =
  inherit OperandParser ()
  override __.Render bin =
    let imm12 = extract bin 11 0 |> int64
    let imm12 = if pickBit bin 23 = 0u then imm12 * -1L else imm12
    struct (OneOperand (memLabel imm12), false, None)

(* <label> *)
type internal OprLabelT3 () =
  inherit OperandParser ()
  override __.Render bin =
    let imm32 (* S:J2:J1:imm6:imm11:'0' *) =
      ((pickBit bin 26 <<< 19) + (pickBit bin 11 <<< 18) +
       (pickBit bin 13 <<< 17) + (extract bin 21 16 <<< 11) +
       (extract bin 10 0)) <<< 1 |> signExtend 21
    struct (OneOperand imm32, false, None)

(* <label> *)
type internal OprLabelT4 () =
  inherit OperandParser ()
  override __.Render bin = (* or BL T1 *)
    let i1 = if (pickBit bin 13 ^^^ pickBit bin 26) = 0u then 1u else 0u
    let i2 = if (pickBit bin 11 ^^^ pickBit bin 26) = 0u then 1u else 0u
    let imm32 (* S:I1:I2:imm10:imm11:'0' *) =
      ((pickBit bin 26 <<< 23) + (i1 <<< 22) + (i2 <<< 21) +
       (extract bin 25 16 <<< 11) + (extract bin 10 0)) <<< 1 |> signExtend 25
    struct (OneOperand imm32, false, None)

(* <label> *)
type internal OprLabelT2 () =
  inherit OperandParser ()
  override __.Render bin =
    let i1 = if (pickBit bin 13 ^^^ pickBit bin 26) = 0u then 1u else 0u
    let i2 = if (pickBit bin 11 ^^^ pickBit bin 26) = 0u then 1u else 0u
    let imm32 (* S:I1:I2:imm10H:imm10L:'00' *) =
      ((pickBit bin 26 <<< 22) + (i1 <<< 21) + (i2 <<< 20) +
       (extract bin 25 16 <<< 10) + (extract bin 10 1)) <<< 2 |> signExtend 25
    struct (OneOperand imm32, false, None)

(* <Rm> *)
type internal OprRmT16 () =
  inherit OperandParser ()
  override __.Render bin =
    let rm = extract bin 6 3 |> getRegister |> OprReg
    struct (OneOperand rm, false, None)

(* <Rm> *)
type internal OprRmT32 () =
  inherit OperandParser ()
  override __.Render bin =
    let rm = extract bin 19 16 |> getRegister |> OprReg
    struct (OneOperand rm, false, None)

(* #<imm> *)
type internal OprImm1T () =
  inherit OperandParser ()
  override __.Render bin =
    let imm = OprImm (pickBit bin 3 (* imm1 *) |> int64)
    struct (OneOperand imm, false, None)

(* {#}<imm> *)
type internal OprImm6 () =
  inherit OperandParser ()
  override __.Render bin =
    let imm = OprImm (extract bin 5 0 (* imm6 *) |> int64)
    struct (OneOperand imm, false, None)

(* {#}<imm> *)
type internal OprImm8 () =
  inherit OperandParser ()
  override __.Render bin =
    let imm = OprImm (extract bin 7 0 (* imm8 *) |> int64)
    struct (OneOperand imm, false, None)

(* {#}<imm> *)
type internal OprImm16T () =
  inherit OperandParser ()
  override __.Render bin =
    let imm (* imm4:imm12 *) =
      concat (extract bin 19 16) (extract bin 11 0) 12 |> int64 |> OprImm
    struct (OneOperand imm, false, None)

(* {#}<imm4> *)
type internal OprImm4T () =
  inherit OperandParser ()
  override __.Render bin =
    struct (extract bin 19 16 |> int64 |> OprImm |> OneOperand, false, None)

(* <cond> *)
type internal OprCondition () =
  inherit OperandParser ()
  override __.Render bin =
    let cond = extract bin 7 4 |> byte |> parseCond |> OprCond
    struct (OneOperand cond, false, None)

(* <endian_specifier> *)
type internal OprEndianT () =
  inherit OperandParser ()
  override __.Render bin =
    let endian = pickBit bin 3 |> byte |> getEndian |> OprEndian
    struct (OneOperand endian, false, None)

(* <iflags> *)
type internal OprIflagsT16 () =
  inherit OperandParser ()
  override __.Render bin =
    struct (OneOperand (OprIflag (getIflag (extract bin 2 0))), false, None)

(* <iflags> *)
type internal OprIflagsT32 () =
  inherit OperandParser ()
  override __.Render bin =
    struct (OneOperand (OprIflag (getIflag (extract bin 7 5))), false, None)

(* <iflags> , #<mode> *)
type internal OprIflagsModeT () =
  inherit OperandParser ()
  override __.Render bin =
    let iflags = OprIflag (getIflag (extract bin 7 5))
    let mode = extract bin 4 0 |> int64 |> OprImm
    struct (TwoOperands (iflags, mode), false, None)

(* <registers> *)
type internal OprRegsM () =
  inherit OperandParser ()
  override __.Render bin =
    let regs = (* '0':M:'000000':register_list *)
      concat (pickBit bin 8 <<< 6) (extract bin 7 0) 8 |> getRegList
      |> OprRegList
    struct (OneOperand regs, false, None)

(* <registers> *)
type internal OprRegsP () =
  inherit OperandParser ()
  override __.Render bin =
    let regs = (* P:'0000000':register_list *)
      concat (pickBit bin 8 <<< 7) (extract bin 7 0) 8 |> getRegList
      |> OprRegList
    struct (OneOperand regs, false, None)

(* [<Rn> {, #-<imm>}] *)
type internal OprMemImm8M () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister
    let imm = extract bin 7 0 (* imm8 *) |> int64
    struct (OneOperand (memOffsetImm (rn, Some Minus, Some imm)), false, None)

(* [<Rn> {, #{+}<imm>}] *)
type internal OprMemImm12 () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister
    let imm = extract bin 11 0 (* imm12 *) |> int64
    struct (OneOperand (memOffsetImm (rn, Some Plus, Some imm)), false, None)

(* [<Rn>, <Rm>] *)
type internal OprMemRegT () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = getRegister (extract bin 19 16)
    let rm = getRegister (extract bin 3 0)
    struct (OneOperand (memOffsetReg (rn, None, rm, None)), false, None)

(* #<option> *)
type internal OprOptImm () =
  inherit OperandParser ()
  override __.Render bin =
    struct (extract bin 3 0 |> int64 |> OprImm |> OneOperand, false, None)

(* [<Rn>, <Rm>, LSL #1] *)
type internal OprMemRegLSL1 () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = getRegister (extract bin 19 16)
    let rm = getRegister (extract bin 3 0)
    let shf = Some (SRTypeLSL, Imm 1u)
    struct (OneOperand (memOffsetReg (rn, None, rm, shf)), false, None)

(* [<Rn>, {+}<Rm> {, LSL #<amount>}] *)
type internal OprMemRegLSL () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = getRegister (extract bin 19 16)
    let rm = getRegister (extract bin 3 0)
    let shf = Some (SRTypeLSL, Imm (extract bin 5 4 (* imm2 *)))
    struct (OneOperand (memOffsetReg (rn, None, rm, shf)), false, None)

(* <single_register_list> *)
type internal OprSingleRegsT () =
  inherit OperandParser ()
  override __.Render bin =
    let regs = OprRegList [ extract bin 15 12 |> getRegister ]
    struct (OneOperand regs, false, None)

(* <Rt>, <label> *)
type internal OprRtLabelT () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 10 8 |> getRegister |> OprReg
    let label = extract bin 7 0 <<< 2 |> int64 |> memLabel
    struct (TwoOperands (rt, label), false, None)

(* <Rn>, <label> *)
type internal OprRnLabel () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 2 0 |> getRegister |> OprReg
    let label = (* i:imm5:'0' *)
      (concat (pickBit bin 9) (extract bin 7 3) 5) <<< 1 |> int64 |> memLabel
    struct (TwoOperands (rn, label), false, None)

(* <Rt>, <label> // Preferred syntax
   <Rt>, [PC, #{+/-}<imm>] // Alternative syntax *)
type internal OprRtLabel12 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let add (* U *) = if pickBit bin 23 = 1u then 1L else -1L
    let imm12 = (int64 (extract bin 11 0)) * add
    struct (TwoOperands (rt, imm12 |> memLabel), false, None)

(* <Rd>, #<imm8> *)
type internal OprRdImm8 () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 10 8 |> getRegister |> OprReg
    let imm8 = extract bin 7 0 |> int64 |> OprImm
    struct (TwoOperands (rd, imm8), false, None)

(* <Rdn>, #<imm8> *)
type internal OprRdnImm8 () =
  inherit OperandParser ()
  override __.Render bin =
    let rdn = extract bin 10 8 |> getRegister |> OprReg
    let imm8 = extract bin 7 0 |> int64 |> OprImm
    struct (TwoOperands (rdn, imm8), false, None)

(* <Dd>, #<imm> *)
type internal OprDdImm8T () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let imm = advSIMDExpandImm bin (pickBit bin 28) |> int64
    let imm = imm &&& 0xFFL |> OprImm
    struct (TwoOperands (dd, imm), false, None)

(* <Dd>, #<imm> *)
type internal OprDdImm16T () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let imm = advSIMDExpandImm bin (pickBit bin 28) |> int64
    let imm = imm &&& 0xFFFFL |> OprImm
    struct (TwoOperands (dd, imm), false, None)

(* <Dd>, #<imm> *)
type internal OprDdImm32T () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let imm = advSIMDExpandImm bin (pickBit bin 28) |> int64
    let imm = imm &&& 0xFFFFFFFFL |> OprImm
    struct (TwoOperands (dd, imm), false, None)

(* <Dd>, #<imm> *)
type internal OprDdImm64T () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let imm = advSIMDExpandImm bin (pickBit bin 28) |> int64 |> OprImm
    struct (TwoOperands (dd, imm), false, None)

(* <Dd>, #<imm> *)
type internal OprDdImmF32T () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let imm = advSIMDExpandImm bin (pickBit bin 28) |> int64
    let imm = imm &&& 0xFFFFFFFFL |> OprImm (* F32 *)
    struct (TwoOperands (dd, imm), false, None)

(* <Qd>, #<imm> *)
type internal OprQdImm8T () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let imm = advSIMDExpandImm bin (pickBit bin 28) |> int64
    let imm = imm &&& 0xFFL |> OprImm
    struct (TwoOperands (qd, imm), false, None)

(* <Qd>, #<imm> *)
type internal OprQdImm16T () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let imm = advSIMDExpandImm bin (pickBit bin 28) |> int64
    let imm = imm &&& 0xFFFFL |> OprImm
    struct (TwoOperands (qd, imm), false, None)

(* <Qd>, #<imm> *)
type internal OprQdImm32T () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let imm = advSIMDExpandImm bin (pickBit bin 28) |> int64
    let imm = imm &&& 0xFFFFFFFFL |> OprImm
    struct (TwoOperands (qd, imm), false, None)

(* <Qd>, #<imm> *)
type internal OprQdImm64T () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let imm = advSIMDExpandImm bin (pickBit bin 28) |> int64 |> OprImm
    struct (TwoOperands (qd, imm), false, None)

(* <Qd>, #<imm> *)
type internal OprQdImmF32T () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let imm = advSIMDExpandImm bin (pickBit bin 28) |> int64
    let imm = imm &&& 0xFFFFFFFFL |> OprImm (* F32 *)
    struct (TwoOperands (qd, imm), false, None)

(* <Rd>, <Rm> *)
type internal OprRdRmT16 () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 2 0 |> getRegister |> OprReg
    let rm = extract bin 5 3 |> getRegister |> OprReg
    struct (TwoOperands (rd, rm), false, None)

(* <Rd>, <Rm> *)
type internal OprRdRmT32 () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    struct (TwoOperands (rd, rm), false, None)

(* <Rd>, <Rm> *)
type internal OprRdRmExt () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = (* D:Rd *)
      concat (pickBit bin 7) (extract bin 2 0) 3 |> getRegister |> OprReg
    let rm = extract bin 6 3 |> getRegister |> OprReg
    struct (TwoOperands (rd, rm), false, None)

(* <Rn>, <Rm> *)
type internal OprRnRm () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 2 0 |> getRegister |> OprReg
    let rm = extract bin 5 3 |> getRegister |> OprReg
    struct (TwoOperands (rn, rm), false, None)

(* <Rn>, <Rm> *)
type internal OprRnRmExt () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = (* N:Rn *)
      concat (pickBit bin 7) (extract bin 2 0) 3 |> getRegister |> OprReg
    let rm = extract bin 6 3 |> getRegister |> OprReg
    struct (TwoOperands (rn, rm), false, None)

(* <Rdn>, <Rm> *)
type internal OprRdnRm () =
  inherit OperandParser ()
  override __.Render bin =
    let rdn = (* DN:Rdn *)
      concat (pickBit bin 7) (extract bin 2 0) 3 |> getRegister |> OprReg
    let rm = extract bin 6 3 |> getRegister |> OprReg
    struct (TwoOperands (rdn, rm), false, None)

(* <Rn>, #<const> *)
type internal OprRnConstT () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let imm12 (* i:imm3:imm8 *) =
      (pickBit bin 26 <<< 11) + (extract bin 14 12 <<< 8) + (extract bin 7 0)
    let cons = t32ExpandImm imm12 |> int64 |> OprImm
    struct (TwoOperands (rn, cons), false, None)

(* <Rd>, #<const> *)
type internal OprRdConstT () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 11 8 |> getRegister |> OprReg
    let imm12 (* i:imm3:imm8 *) =
      (pickBit bin 26 <<< 11) + (extract bin 14 12 <<< 8) + (extract bin 7 0)
    let cons = t32ExpandImm imm12 |> int64 |> OprImm
    struct (TwoOperands (rn, cons), false, None)

(* <Rn>!, <registers> *)
type internal OprRnRegsT16 () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 10 8 |> getRegister |> OprReg
    let regs = extract bin 7 0 (* register_list *) |> getRegList |> OprRegList
    struct (TwoOperands (rn, regs), true, None)

(* <Rn>!, <registers> *)
type internal OprRnRegsT32 () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let regs =
      extract bin 15 0 (* P:M:register_list *) |> getRegList |> OprRegList
    struct (TwoOperands (rn, regs), wbackW bin, None)

(* <Rn>!, <registers> *)
type internal OprRnRegsW () =
  inherit OperandParser ()
  override __.Render bin =
    let rn = extract bin 10 8
    let regs = extract bin 7 0 (* register_list *)
    let wback = pickBit regs (int rn) = 0u
    let regs = regs |> getRegList |> OprRegList
    struct (TwoOperands (rn |> getRegister |> OprReg, regs), wback, None)

(* <spec_reg>, <Rn> *)
type internal OprSregRnT () =
  inherit OperandParser ()
  override __.Render bin =
    let struct (sreg, flag) = getCPSR (extract bin 11 8) (* mask *)
    let rn = extract bin 19 16 |> getRegister |> OprReg
    struct (TwoOperands (OprSpecReg (sreg, flag), rn), false, None)

(* <Rd>, <spec_reg> *)
type internal OprRdSregT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let sreg =
      if pickBit bin 20 = 0u then R.APSR (* or CPSR *) else R.SPSR
      |> uint |> getRegister |> OprReg
    struct (TwoOperands (rd, sreg), false, None)

(* <banked_reg>, <Rn> *)
type internal OprBankregRnT () =
  inherit OperandParser ()
  override __.Render bin =
    let breg =
      concat (pickBit bin 4) (extract bin 11 8) 4 (* M:M1 *)
      |> getBankedReg (pickBit bin 20) (* R *) |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    struct (TwoOperands (breg, rn), false, None)

(* <Rd>, <banked_reg> *)
type internal OprRdBankregT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let breg =
      concat (pickBit bin 4) (extract bin 19 16) 4 (* M:M1 *)
      |> getBankedReg (pickBit bin 20) (* R *) |> OprReg
    struct (TwoOperands (rd, breg), false, None)

(* {<Dd>,} <Dm>, #0 *)
type internal OprDdDm0 () =
  inherit OperandParser ()
  override __.Render bin =
    let dd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
    let dm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
    struct (ThreeOperands (dd, dm, OprImm 0L), false, None)

(* {<Qd>,} <Qm>, #0 *)
type internal OprQdQm0 () =
  inherit OperandParser ()
  override __.Render bin =
    let qd = (* D:Vd *)
      concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
    let qm = (* M:Vm *)
      concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecQReg |> toSVReg
    struct (ThreeOperands (qd, qm, OprImm 0L), false, None)

(* <Rt>, [<Rn>, {+}<Rm>] *)
type internal OprRtMemReg16 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 2 0 |> getRegister |> OprReg
    let mem =
      let rn = extract bin 5 3 |> getRegister
      let rm = extract bin 8 6 |> getRegister
      memOffsetReg (rn, Some Plus, rm, None)
    struct (TwoOperands (rt, mem), false, None)

(* <Rt>, [<Rn>, {+}<Rm>] *)
type internal OprRtMemReg32 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let rm = extract bin 3 0 |> getRegister
      memOffsetReg (rn, Some Plus, rm, None)
    struct (TwoOperands (rt, mem), false, None)

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
    struct (TwoOperands (rt, mem), false, None)

(* <Rt>, [<Rn> {, #{+}<imm>}] *)
type internal OprRtMemImm0T () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 2 0 |> getRegister |> OprReg
    let mem =
      let rn = extract bin 5 3 |> getRegister
      let imm = extract bin 10 6 (* imm5 *) |> int64 (* ZeroExtend(imm5, 32) *)
      memOffsetImm (rn, Some Plus, Some imm)
    struct (TwoOperands (rt, mem), false, None)

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
    struct (TwoOperands (rt, mem), false, None)

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
    struct (TwoOperands (rt, mem), false, None)

(* <Rt>, [<Rn> {, #<imm>}] *)
type internal OprRtMemImm8 () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let imm = extract bin 7 0 <<< 2 (* imm8:'00' *) |> int64
      memOffsetImm (rn, None, Some imm)
    struct (TwoOperands (rt, mem), false, None)

(* <Rt>, [<Rn> {, #{+}<imm>}] *)
type internal OprRtMemImm8P () =
  inherit OperandParser ()
  override __.Render bin = /// imm8 & Plus
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let imm = extract bin 7 0 (* imm8 *) |> int64
      memOffsetImm (rn, None (* {+} *), Some imm)
    struct (TwoOperands (rt, mem), false, None)

(* <Rt>, [<Rn> {, #-<imm>}] *)
type internal OprRtMemImm8M () =
  inherit OperandParser ()
  override __.Render bin = /// imm8 & Minus
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem =
      let rn = extract bin 19 16 |> getRegister
      let imm = extract bin 7 0 (* imm8 *) |> int64
      memOffsetImm (rn, Some Minus, Some imm)
    struct (TwoOperands (rt, mem), wbackW8 bin, None)

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
    struct (TwoOperands (rt, mem), wbackW8 bin, None)

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
    struct (TwoOperands (rt, mem), wbackW8 bin, None)

(* <Rt>, [<Rn> {, #{+}<imm>}] *)
type internal OprRtMemImm12T () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem =
      let imm12 = extract bin 11 0 |> int64
      let rn = extract bin 19 16 |> getRegister
      memOffsetImm (rn, Some Plus, Some imm12)
    struct (TwoOperands (rt, mem), false, None)

(* <Rt>, [SP{, #{+}<imm>}] *)
type internal OprRtMemSP () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 10 8 |> getRegister |> OprReg
    let mem =
      let imm = extract bin 7 0 (* imm8 *) <<< 2 |> int64
      memOffsetImm (R.SP, Some Plus, Some imm)
    struct (TwoOperands (rt, mem), false, None)

(* <Rd>, <label> *)
type internal OprRdLabelT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let imm32 (* i:imm3:imm8 *) =
      (pickBit bin 26 <<< 11) + (extract bin 14 12 <<< 8) + (extract bin 7 0)
      |> int64 |> memLabel
    struct (TwoOperands (rd, imm32), false, None)

(* <Rt>, <Rt2>, <label> *)
type internal OprRtRt2LabelT () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let rt2 = extract bin 11 8 |> getRegister |> OprReg
    let label = extract bin 7 0 <<< 2 (* imm8:'00' *) |> int64
    let label =
      if pickBit bin 23 = 1u then memLabel label else memLabel (label * -1L)
    struct (ThreeOperands (rt, rt2, label), false, None)

(* <Rd>, <Rn>, <Rm> *)
(* {<Rd>,} <Rn>, <Rm> *)
type internal OprRdRnRmT16 () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 2 0 |> getRegister |> OprReg
    let rn = extract bin 5 3 |> getRegister |> OprReg
    let rm = extract bin 8 6 |> getRegister |> OprReg
    struct (ThreeOperands (rd, rn, rm), false, None)

(* {<Rd>,} <Rn>, <Rm> *)
type internal OprRdRnRmT32 () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    struct (ThreeOperands (rd, rn, rm), false, None)

(* {<Rd>,} <Rm>, <Rn> *)
type internal OprRdRmRnT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    struct (ThreeOperands (rd, rm, rn), false, None)

(* {<Rd>,} <Rm>, #<imm> *)
type internal OprRdRmImmT16 () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 2 0 |> getRegister |> OprReg
    let rm = extract bin 5 3 |> getRegister |> OprReg
    let imm5 = extract bin 10 6
    let imm = if imm5 = 0u then 32u else imm5
    struct (ThreeOperands (rd, rm, imm |> int64 |> OprImm), false, None)

(* {<Rd>,} <Rm>, #<imm> *)
type internal OprRdRmImmT32 () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let imm5 (* imm3:imm2 *) = concat (extract bin 14 12) (extract bin 7 6) 2
    let imm = if imm5 = 0u then 32u else imm5
    struct (ThreeOperands (rd, rm, imm |> int64 |> OprImm ), false, None)

(* <Rd>, <Rn>, #<imm3> *)
type internal OprRdRnImm3 () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 2 0 |> getRegister |> OprReg
    let rn = extract bin 5 3 |> getRegister |> OprReg
    let imm3 = extract bin 8 6 (* imm3 *) |> int64 |> OprImm
    struct (ThreeOperands (rd, rn, imm3), false, None)

(* <Rd>, SP, #<imm8> *)
type internal OprRdSPImm8 () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 10 8 |> getRegister |> OprReg
    let imm8 = extract bin 7 0 (* imm8 *) <<< 2 |> int64 |> OprImm
    struct (ThreeOperands (rd, OprReg R.SP, imm8), false, None)

(* {<Rd>,} <Rn>, #<imm12> *)
type internal OprRdRnImm12 () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let imm12 (* i:imm3:imm8 *) =
      (pickBit bin 26 <<< 11) + (extract bin 14 12 <<< 8) + (extract bin 7 0)
      |> int64
    struct (ThreeOperands (rd, rn, OprImm imm12), false, None)

(* <Rd>, #<imm16> *)
type internal OprRdImm16T () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let imm16 = (* imm4:i:imm3:imm8 *)
      (extract bin 19 16 <<< 12) + (pickBit bin 26 <<< 11) +
      (extract bin 14 12 <<< 8) + (extract bin 7 0) |> int64 |> OprImm
    struct (TwoOperands (rd, imm16), false, None)

(* {<Rd>,} SP, #<imm12> *)
type internal OprRdSPImm12 () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let imm12 (* i:imm3:imm8 *) =
      (pickBit bin 26 <<< 11) + (extract bin 14 12 <<< 8) + (extract bin 7 0)
      |> int64
    struct (ThreeOperands (rd, OprReg R.SP, OprImm imm12), false, None)

(* PC, LR, #<imm8> *)
type internal OprPCLRImm8 () =
  inherit OperandParser ()
  override __.Render bin =
    let imm8 = extract bin 7 0 (* imm8 *) |> int64 |> OprImm
    struct (ThreeOperands (OprReg R.PC, OprReg R.LR, imm8), false, None)

(* {SP,} SP, #<imm7> *)
type internal OprSPSPImm7 () =
  inherit OperandParser ()
  override __.Render bin =
    let imm = extract bin 6 0 (* imm7 *) <<< 2 |> int64 |> OprImm
    struct (ThreeOperands (OprReg R.SP, OprReg R.SP, imm), false, None)

(* <Rd>, <Rm> {, <shift> #<amount>} *)
type internal OprRdRmShfT16 () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 2 0 |> getRegister |> OprReg
    let rm = extract bin 5 3 |> getRegister |> OprReg
    let struct (shift, amount) =
      decodeImmShift (extract bin 12 11) (extract bin 10 6) (* stype, imm5 *)
    struct (ThreeOperands (rd, rm, OprShift (shift, Imm amount)), false, None)

(* <Rd>, <Rm> {, <shift> #<amount>} *)
type internal OprRdRmShfT32 () =
  inherit OperandParser ()
  override __.Render b =
    let rd = extract b 11 8 |> getRegister |> OprReg
    let rm = extract b 3 0 |> getRegister |> OprReg
    let struct (shift, amount) = (* stype, imm3:imm2 *)
      decodeImmShift (extract b 5 4) ((extract b 14 12 <<< 2) + (extract b 7 6))
    struct (ThreeOperands (rd, rm, OprShift (shift, Imm amount)), false, None)

(* {<Rd>, }<Rn>, #0 *)
type internal OprRdRn0 () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 2 0 |> getRegister |> OprReg
    let rn = extract bin 5 3 |> getRegister |> OprReg
    struct (ThreeOperands (rd, rn, OprImm 0L), false, None)

(* {<Rd>, }<Rn>, #0 *)
type internal OprRdRn0T32 () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    struct (ThreeOperands (rd, rn, OprImm 0L), false, None)

(* {<Rdn>,} <Rdn>, <Rm> *)
type internal OprRdnRdnRm () =
  inherit OperandParser ()
  override __.Render bin =
    let rdn = extract bin 2 0 |> getRegister |> OprReg
    let rm = extract bin 5 3 |> getRegister |> OprReg
    struct (ThreeOperands (rdn, rdn, rm), false, None)

(* <Rdm>, <Rn>{, <Rdm>} *)
type internal OprRdmRnRdm () =
  inherit OperandParser ()
  override __.Render bin =
    let rdm = extract bin 2 0 |> getRegister |> OprReg
    let rn = extract bin 5 3 |> getRegister |> OprReg
    struct (ThreeOperands (rdm, rn, rdm), false, None)

(* {<Rdm>,} SP, <Rdm> *)
type internal OprRdmSPRdm () =
  inherit OperandParser ()
  override __.Render bin =
    let rdm = (* DM:Rdm *)
      concat (pickBit bin 7) (extract bin 2 0) 3 |> getRegister |> OprReg
    struct (ThreeOperands (rdm, OprReg R.SP, rdm), false, None)

(* {SP,} SP, <Rm> *)
type internal OprSPSPRm () =
  inherit OperandParser ()
  override __.Render bin =
    let rm = extract bin 6 3 |> getRegister |> OprReg
    struct (ThreeOperands (OprReg R.SP, OprReg R.SP, rm), false, None)

(* <Rd>, <Rt>, [<Rn>] *)
type internal OprRdRtMemT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 3 0 |> getRegister |> OprReg
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem = memOffsetImm (extract bin 19 16 |> getRegister, None, None)
    struct (ThreeOperands (rd, rt, mem), false, None)

(* <Rt>, <Rt2>, [<Rn>] *)
type internal OprRtRt2MemT () =
  inherit OperandParser ()
  override __.Render bin =
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let rt2 = extract bin 11 8 |> getRegister |> OprReg
    let mem =
      memOffsetImm (extract bin 19 16 (* Rn *) |> getRegister, None, None)
    struct (ThreeOperands (rt, rt2, mem), false, None)

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
    struct (ThreeOperands (rt, rt2, mem), wbackW bin, None)

(* <Rd>, <Rt>, [<Rn> {, #<imm>}] *)
type internal OprRdRtMemImmT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let mem =
      let imm = extract bin 7 0 <<< 2 (* imm8:'00' *) |> int64
      memOffsetImm (extract bin 19 16 |> getRegister, None, Some imm)
    struct (ThreeOperands (rd, rt, mem), false, None)

(* <Rn>, <Rm>, RRX *)
(* <Rn>, <Rm> {, <shift> #<amount>} *)
type internal OprRnRmShfT () =
  inherit OperandParser ()
  override __.Render b =
    let rn = extract b 19 16 |> getRegister |> OprReg
    let rm = extract b 3 0 |> getRegister |> OprReg
    let struct (shift, amount) = (* stype, imm3:imm2 *)
      decodeImmShift (extract b 5 4) ((extract b 14 12 <<< 2) + (extract b 7 6))
    struct (ThreeOperands (rn, rm, OprShift (shift, Imm amount)), false, None)

(* <Rd>, <Rm>, <shift> <Rs> *)
type internal OprRdRmRsT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let rm = extract bin 19 16 |> getRegister |> OprReg
    let rs = extract bin 3 0 |> getRegister |> OprReg
    struct (ThreeOperands (rd, rm, rs), false, None)

(* {<Rd>,} <Rm> {, ROR #<amount>} *)
type internal OprRdRmRorT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let shift = OprShift (SRType.SRTypeROR, extract bin 5 4 <<< 3 |> Imm)
    struct (ThreeOperands (rd, rm, shift), false, None)

(* {<Rd>,} <Rn>, #<const> *)
type internal OprRdRnConstT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let imm12 (* i:imm3:imm8 *) =
      (pickBit bin 26 <<< 11) + (extract bin 14 12 <<< 8) + (extract bin 7 0)
    let cons = t32ExpandImm imm12 |> int64 |> OprImm
    struct (ThreeOperands (rd, rn, cons), false, None)

(* {<Rd>,} SP, #<const> *)
type internal OprRdSPConstT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let imm12 (* i:imm3:imm8 *) =
      (pickBit bin 26 <<< 11) + (extract bin 14 12 <<< 8) + (extract bin 7 0)
    let cons = t32ExpandImm imm12 |> int64 |> OprImm
    struct (ThreeOperands (rd, OprReg R.SP, cons), false, None)

(* <Rd>, #<imm>, <Rn> *)
type internal OprRdImmRnT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let imm = extract bin 3 0 (* sat_imm *) + 1u |> int64 |> OprImm
    let rn = extract bin 19 16 |> getRegister |> OprReg
    struct (ThreeOperands (rd, imm, rn), false, None)

(* <Rd>, #<imm>, <Rn> *)
type internal OprRdImmRnU () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let imm = extract bin 3 0 (* sat_imm *) |> int64 |> OprImm
    let rn = extract bin 19 16 |> getRegister |> OprReg
    struct (ThreeOperands (rd, imm, rn), false, None)

(* <Rd>, #<lsb>, #<width> *)
type internal OprRdLsbWidthT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let lsb = concat (extract bin 14 12) (extract bin 7 6) 2
    let width = (* msb - lsb + 1 *)
      (extract bin 4 0) - lsb + 1u |> int64 |> OprImm
    struct (ThreeOperands (rd, OprImm (int64 lsb), width), false, None)

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
    struct (FourOperands (rd, rn, rm, shift), false, None)

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
    struct (FourOperands (rd, OprReg R.SP, rm, shf), false, None)

(* <Rdm>, <Rdm>, LSL <Rs> *)
type internal OprRdmRdmLSLRs () =
  inherit OperandParser ()
  override __.Render bin =
    let rdm = extract bin 2 0 |> getRegister |> OprReg
    let shift = OprRegShift (SRTypeLSL, extract bin 5 3 |> getRegister (* Rs *))
    struct (ThreeOperands (rdm, rdm, shift), false, None)

(* <Rdm>, <Rdm>, LSR <Rs> *)
type internal OprRdmRdmLSRRs () =
  inherit OperandParser ()
  override __.Render bin =
    let rdm = extract bin 2 0 |> getRegister |> OprReg
    let shift = OprRegShift (SRTypeLSR, extract bin 5 3 |> getRegister (* Rs *))
    struct (ThreeOperands (rdm, rdm, shift), false, None)

(* <Rdm>, <Rdm>, ASR <Rs> *)
type internal OprRdmRdmASRRs () =
  inherit OperandParser ()
  override __.Render bin =
    let rdm = extract bin 2 0 |> getRegister |> OprReg
    let shift = OprRegShift (SRTypeASR, extract bin 5 3 |> getRegister (* Rs *))
    struct (ThreeOperands (rdm, rdm, shift), false, None)

(* <Rdm>, <Rdm>, ROR <Rs> *)
type internal OprRdmRdmRORRs () =
  inherit OperandParser ()
  override __.Render bin =
    let rdm = extract bin 2 0 |> getRegister |> OprReg
    let shift = OprRegShift (SRTypeROR, extract bin 5 3 |> getRegister (* Rs *))
    struct (ThreeOperands (rdm, rdm, shift), false, None)

(* {<Rd>,} <Rn>, <Rm> {, ROR #<amount>} *)
type internal OprRdRnRmRorT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let shift = OprShift (SRType.SRTypeROR, extract bin 5 4 <<< 3 |> Imm)
    struct (FourOperands (rd, rn, rm, shift), false, None)

(* <Rd>, <Rn>, <Rm>, <Ra> *)
type internal OprRdRnRmRaT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 11 8 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    let ra = extract bin 15 12 |> getRegister |> OprReg
    struct (FourOperands (rd, rn, rm, ra), false, None)

(* <RdLo>, <RdHi>, <Rn>, <Rm> *)
type internal OprRdlRdhRnRmT () =
  inherit OperandParser ()
  override __.Render bin =
    let rdLo = extract bin 15 12 |> getRegister |> OprReg
    let rdHi = extract bin 11 8 |> getRegister |> OprReg
    let rn = extract bin 19 16 |> getRegister |> OprReg
    let rm = extract bin 3 0 |> getRegister |> OprReg
    struct (FourOperands (rdLo, rdHi, rn, rm), false, None)

(* <Rd>, <Rt>, <Rt2>, [<Rn>] *)
type internal OprRdRtRt2MemT () =
  inherit OperandParser ()
  override __.Render bin =
    let rd = extract bin 3 0 |> getRegister |> OprReg
    let rt = extract bin 15 12 |> getRegister |> OprReg
    let rt2 = extract bin 11 8 |> getRegister |> OprReg
    let mem = memOffsetImm (extract bin 19 16 |> getRegister, None, None)
    struct (FourOperands (rd, rt, rt2, mem), false, None)

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
    struct (FourOperands (rd, imm, rn, shift), false, None)

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
    struct (FourOperands (rd, imm, rn, shift), false, None)

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
    struct (FourOperands (rd, rn, OprImm (int64 lsb), width), false, None)

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
    struct (FourOperands (rd, rn, lsb, width), false, None)

// vim: set tw=80 sts=2 sw=2:
