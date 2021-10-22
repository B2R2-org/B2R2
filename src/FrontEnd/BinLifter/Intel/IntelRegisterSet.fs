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

namespace B2R2.FrontEnd.BinLifter.Intel

open B2R2

module private RegisterSetLiteral =
  let [<Literal>] arrLen = 4

open RegisterSetLiteral

type IntelRegisterSet (bitArray: uint64 [], s: Set<RegisterID>) =
  inherit NonEmptyRegisterSet (bitArray, s)

  new () = IntelRegisterSet (RegisterSet.MakeInternalBitArray arrLen, Set.empty)

  override __.Tag = RegisterSetTag.Intel

  override __.ArrSize = arrLen

  override __.New arr s = new IntelRegisterSet (arr, s) :> RegisterSet

  override __.RegIDToIndex rid =
    match Register.ofRegID rid with
    | R.EAX -> 0
    | R.EBX -> 1
    | R.ECX -> 2
    | R.EDX -> 3
    | R.ESP -> 4
    | R.EBP -> 5
    | R.ESI -> 6
    | R.EDI -> 7
    | R.RAX -> 8
    | R.RBX -> 9
    | R.RCX -> 10
    | R.RDX -> 11
    | R.RSP -> 12
    | R.RBP -> 13
    | R.RSI -> 14
    | R.RDI -> 15
    | R.R8  -> 16
    | R.R9  -> 17
    | R.R10 -> 18
    | R.R11 -> 19
    | R.R12 -> 20
    | R.R13 -> 21
    | R.R14 -> 22
    | R.R15 -> 23
    | R.SPL -> 24
    | R.BPL -> 25
    | R.SIL -> 26
    | R.DIL -> 27
    | R.ES -> 28
    | R.CS -> 29
    | R.SS -> 30
    | R.DS -> 31
    | R.FS -> 32
    | R.GS -> 33
    | R.ESBase -> 34
    | R.CSBase -> 35
    | R.SSBase -> 36
    | R.DSBase -> 37
    | R.FSBase -> 38
    | R.GSBase -> 39
    | R.OF -> 40
    | R.DF -> 41
    | R.IF -> 42
    | R.TF -> 43
    | R.SF -> 44
    | R.ZF -> 45
    | R.AF -> 46
    | R.PF -> 47
    | R.CF -> 48
    | R.MM0 -> 49
    | R.MM1 -> 50
    | R.MM2 -> 51
    | R.MM3 -> 52
    | R.MM4 -> 53
    | R.MM5 -> 54
    | R.MM6 -> 55
    | R.MM7 -> 56
    | R.ZMM0A -> 57
    | R.ZMM0B -> 58
    | R.ZMM0C -> 59
    | R.ZMM0D -> 60
    | R.ZMM0E -> 61
    | R.ZMM0F -> 62
    | R.ZMM0G -> 63
    | R.ZMM0H -> 64
    | R.ZMM1A -> 65
    | R.ZMM1B -> 66
    | R.ZMM1C -> 67
    | R.ZMM1D -> 68
    | R.ZMM1E -> 69
    | R.ZMM1F -> 70
    | R.ZMM1G -> 71
    | R.ZMM1H -> 72
    | R.ZMM2A -> 73
    | R.ZMM2B -> 74
    | R.ZMM2C -> 75
    | R.ZMM2D -> 76
    | R.ZMM2E -> 77
    | R.ZMM2F -> 78
    | R.ZMM2G -> 79
    | R.ZMM2H -> 80
    | R.ZMM3A -> 81
    | R.ZMM3B -> 82
    | R.ZMM3C -> 83
    | R.ZMM3D -> 84
    | R.ZMM3E -> 85
    | R.ZMM3F -> 86
    | R.ZMM3G -> 87
    | R.ZMM3H -> 88
    | R.ZMM4A -> 89
    | R.ZMM4B -> 90
    | R.ZMM4C -> 91
    | R.ZMM4D -> 92
    | R.ZMM4E -> 93
    | R.ZMM4F -> 94
    | R.ZMM4G -> 95
    | R.ZMM4H -> 96
    | R.ZMM5A -> 97
    | R.ZMM5B -> 98
    | R.ZMM5C -> 99
    | R.ZMM5D -> 100
    | R.ZMM5E -> 101
    | R.ZMM5F -> 102
    | R.ZMM5G -> 103
    | R.ZMM5H -> 104
    | R.ZMM6A -> 105
    | R.ZMM6B -> 106
    | R.ZMM6C -> 107
    | R.ZMM6D -> 108
    | R.ZMM6E -> 109
    | R.ZMM6F -> 110
    | R.ZMM6G -> 111
    | R.ZMM6H -> 112
    | R.ZMM7A -> 113
    | R.ZMM7B -> 114
    | R.ZMM7C -> 115
    | R.ZMM7D -> 116
    | R.ZMM7E -> 117
    | R.ZMM7F -> 118
    | R.ZMM7G -> 119
    | R.ZMM7H -> 120
    | R.ZMM8A -> 121
    | R.ZMM8B -> 122
    | R.ZMM8C -> 123
    | R.ZMM8D -> 124
    | R.ZMM8E -> 125
    | R.ZMM8F -> 126
    | R.ZMM8G -> 127
    | R.ZMM8H -> 128
    | R.ZMM9A -> 129
    | R.ZMM9B -> 130
    | R.ZMM9C -> 131
    | R.ZMM9D -> 132
    | R.ZMM9E -> 133
    | R.ZMM9F -> 134
    | R.ZMM9G -> 135
    | R.ZMM9H -> 136
    | R.ZMM10A -> 137
    | R.ZMM10B -> 138
    | R.ZMM10C -> 139
    | R.ZMM10D -> 140
    | R.ZMM10E -> 141
    | R.ZMM10F -> 142
    | R.ZMM10G -> 143
    | R.ZMM10H -> 144
    | R.ZMM11A -> 145
    | R.ZMM11B -> 146
    | R.ZMM11C -> 147
    | R.ZMM11D -> 148
    | R.ZMM11E -> 149
    | R.ZMM11F -> 150
    | R.ZMM11G -> 151
    | R.ZMM11H -> 152
    | R.ZMM12A -> 153
    | R.ZMM12B -> 154
    | R.ZMM12C -> 155
    | R.ZMM12D -> 156
    | R.ZMM12E -> 157
    | R.ZMM12F -> 158
    | R.ZMM12G -> 159
    | R.ZMM12H -> 160
    | R.ZMM13A -> 161
    | R.ZMM13B -> 162
    | R.ZMM13C -> 163
    | R.ZMM13D -> 164
    | R.ZMM13E -> 165
    | R.ZMM13F -> 166
    | R.ZMM13G -> 167
    | R.ZMM13H -> 168
    | R.ZMM14A -> 169
    | R.ZMM14B -> 170
    | R.ZMM14C -> 171
    | R.ZMM14D -> 172
    | R.ZMM14E -> 173
    | R.ZMM14F -> 174
    | R.ZMM14G -> 175
    | R.ZMM14H -> 176
    | R.ZMM15A -> 177
    | R.ZMM15B -> 178
    | R.ZMM15C -> 179
    | R.ZMM15D -> 180
    | R.ZMM15E -> 181
    | R.ZMM15F -> 182
    | R.ZMM15G -> 183
    | R.ZMM15H -> 184
    | R.BND0A -> 185
    | R.BND0B -> 186
    | R.BND1A -> 187
    | R.BND1B -> 188
    | R.BND2A -> 189
    | R.BND2B -> 190
    | R.BND3A -> 191
    | R.BND3B -> 192
    | R.FCW -> 193
    | R.FSW -> 194
    | R.FTW -> 195
    | R.FOP -> 196
    | R.FIP -> 197
    | R.FCS -> 198
    | R.FDP -> 199
    | R.FDS -> 200
    | R.MXCSR -> 201
    | R.MXCSRMASK -> 202
    | R.PKRU -> 203
    | R.DR0 -> 204
    | R.DR1 -> 205
    | R.DR2 -> 206
    | R.DR3 -> 207
    | R.DR6 -> 208
    | R.DR7 -> 209
    | _ -> -1

  override __.IndexToRegID index =
    match index with
    | 0 -> R.EAX
    | 1 -> R.EBX
    | 2 -> R.ECX
    | 3 -> R.EDX
    | 4 -> R.ESP
    | 5 -> R.EBP
    | 6 -> R.ESI
    | 7 -> R.EDI
    | 8 -> R.RAX
    | 9 -> R.RBX
    | 10 -> R.RCX
    | 11 -> R.RDX
    | 12 -> R.RSP
    | 13 -> R.RBP
    | 14 -> R.RSI
    | 15 -> R.RDI
    | 16 -> R.R8
    | 17 -> R.R9
    | 18 -> R.R10
    | 19 -> R.R11
    | 20 -> R.R12
    | 21 -> R.R13
    | 22 -> R.R14
    | 23 -> R.R15
    | 24 -> R.SPL
    | 25 -> R.BPL
    | 26 -> R.SIL
    | 27 -> R.DIL
    | 28 -> R.ES
    | 29 -> R.CS
    | 30 -> R.SS
    | 31 -> R.DS
    | 32 -> R.FS
    | 33 -> R.GS
    | 34 -> R.ESBase
    | 35 -> R.CSBase
    | 36 -> R.SSBase
    | 37 -> R.DSBase
    | 38 -> R.FSBase
    | 39 -> R.GSBase
    | 40 -> R.OF
    | 41 -> R.DF
    | 42 -> R.IF
    | 43 -> R.TF
    | 44 -> R.SF
    | 45 -> R.ZF
    | 46 -> R.AF
    | 47 -> R.PF
    | 48 -> R.CF
    | 49 -> R.MM0
    | 50 -> R.MM1
    | 51 -> R.MM2
    | 52 -> R.MM3
    | 53 -> R.MM4
    | 54 -> R.MM5
    | 55 -> R.MM6
    | 56 -> R.MM7
    | 57 -> R.ZMM0A
    | 58 -> R.ZMM0B
    | 59 -> R.ZMM0C
    | 60 -> R.ZMM0D
    | 61 -> R.ZMM0E
    | 62 -> R.ZMM0F
    | 63 -> R.ZMM0G
    | 64 -> R.ZMM0H
    | 65 -> R.ZMM1A
    | 66 -> R.ZMM1B
    | 67 -> R.ZMM1C
    | 68 -> R.ZMM1D
    | 69 -> R.ZMM1E
    | 70 -> R.ZMM1F
    | 71 -> R.ZMM1G
    | 72 -> R.ZMM1H
    | 73 -> R.ZMM2A
    | 74 -> R.ZMM2B
    | 75 -> R.ZMM2C
    | 76 -> R.ZMM2D
    | 77 -> R.ZMM2E
    | 78 -> R.ZMM2F
    | 79 -> R.ZMM2G
    | 80 -> R.ZMM2H
    | 81 -> R.ZMM3A
    | 82 -> R.ZMM3B
    | 83 -> R.ZMM3C
    | 84 -> R.ZMM3D
    | 85 -> R.ZMM3E
    | 86 -> R.ZMM3F
    | 87 -> R.ZMM3G
    | 88 -> R.ZMM3H
    | 89 -> R.ZMM4A
    | 90 -> R.ZMM4B
    | 91 -> R.ZMM4C
    | 92 -> R.ZMM4D
    | 93 -> R.ZMM4E
    | 94 -> R.ZMM4F
    | 95 -> R.ZMM4G
    | 96 -> R.ZMM4H
    | 97 -> R.ZMM5A
    | 98 -> R.ZMM5B
    | 99 -> R.ZMM5C
    | 100 -> R.ZMM5D
    | 101 -> R.ZMM5E
    | 102 -> R.ZMM5F
    | 103 -> R.ZMM5G
    | 104 -> R.ZMM5H
    | 105 -> R.ZMM6A
    | 106 -> R.ZMM6B
    | 107 -> R.ZMM6C
    | 108 -> R.ZMM6D
    | 109 -> R.ZMM6E
    | 110 -> R.ZMM6F
    | 111 -> R.ZMM6G
    | 112 -> R.ZMM6H
    | 113 -> R.ZMM7A
    | 114 -> R.ZMM7B
    | 115 -> R.ZMM7C
    | 116 -> R.ZMM7D
    | 117 -> R.ZMM7E
    | 118 -> R.ZMM7F
    | 119 -> R.ZMM7G
    | 120 -> R.ZMM7H
    | 121 -> R.ZMM8A
    | 122 -> R.ZMM8B
    | 123 -> R.ZMM8C
    | 124 -> R.ZMM8D
    | 125 -> R.ZMM8E
    | 126 -> R.ZMM8F
    | 127 -> R.ZMM8G
    | 128 -> R.ZMM8H
    | 129 -> R.ZMM9A
    | 130 -> R.ZMM9B
    | 131 -> R.ZMM9C
    | 132 -> R.ZMM9D
    | 133 -> R.ZMM9E
    | 134 -> R.ZMM9F
    | 135 -> R.ZMM9G
    | 136 -> R.ZMM9H
    | 137 -> R.ZMM10A
    | 138 -> R.ZMM10B
    | 139 -> R.ZMM10C
    | 140 -> R.ZMM10D
    | 141 -> R.ZMM10E
    | 142 -> R.ZMM10F
    | 143 -> R.ZMM10G
    | 144 -> R.ZMM10H
    | 145 -> R.ZMM11A
    | 146 -> R.ZMM11B
    | 147 -> R.ZMM11C
    | 148 -> R.ZMM11D
    | 149 -> R.ZMM11E
    | 150 -> R.ZMM11F
    | 151 -> R.ZMM11G
    | 152 -> R.ZMM11H
    | 153 -> R.ZMM12A
    | 154 -> R.ZMM12B
    | 155 -> R.ZMM12C
    | 156 -> R.ZMM12D
    | 157 -> R.ZMM12E
    | 158 -> R.ZMM12F
    | 159 -> R.ZMM12G
    | 160 -> R.ZMM12H
    | 161 -> R.ZMM13A
    | 162 -> R.ZMM13B
    | 163 -> R.ZMM13C
    | 164 -> R.ZMM13D
    | 165 -> R.ZMM13E
    | 166 -> R.ZMM13F
    | 167 -> R.ZMM13G
    | 168 -> R.ZMM13H
    | 169 -> R.ZMM14A
    | 170 -> R.ZMM14B
    | 171 -> R.ZMM14C
    | 172 -> R.ZMM14D
    | 173 -> R.ZMM14E
    | 174 -> R.ZMM14F
    | 175 -> R.ZMM14G
    | 176 -> R.ZMM14H
    | 177 -> R.ZMM15A
    | 178 -> R.ZMM15B
    | 179 -> R.ZMM15C
    | 180 -> R.ZMM15D
    | 181 -> R.ZMM15E
    | 182 -> R.ZMM15F
    | 183 -> R.ZMM15G
    | 184 -> R.ZMM15H
    | 185 -> R.BND0A
    | 186 -> R.BND0B
    | 187 -> R.BND1A
    | 188 -> R.BND1B
    | 189 -> R.BND2A
    | 190 -> R.BND2B
    | 191 -> R.BND3A
    | 192 -> R.BND3B
    | 193 -> R.FCW
    | 194 -> R.FSW
    | 195 -> R.FTW
    | 196 -> R.FOP
    | 197 -> R.FIP
    | 198 -> R.FCS
    | 199 -> R.FDP
    | 200 -> R.FDS
    | 201 -> R.MXCSR
    | 202 -> R.MXCSRMASK
    | 203 -> R.PKRU
    | 204 -> R.DR0
    | 205 -> R.DR1
    | 206 -> R.DR2
    | 207 -> R.DR3
    | 208 -> R.DR6
    | 209 -> R.DR7
    | _ -> Utils.impossible ()
    |> Register.toRegID

  override __.ToString () =
    sprintf "IntelRegisterSet<%x, %x, %x, %x>" __.BitArray.[0] __.BitArray.[1]
      __.BitArray.[2] __.BitArray.[3]

[<RequireQualifiedAccess>]
module IntelRegisterSet =
  let singleton rid = IntelRegisterSet().Add(rid)
  let empty = IntelRegisterSet () :> RegisterSet
