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

type IntelRegisterSet (bitArray: uint64 [], s: Set<RegisterID>) =
  inherit NonEmptyRegisterSet (bitArray, s)

  static let defaultSize = 4
  static let emptyArr = Array.init defaultSize (fun _ -> 0UL)
  static member EmptySet =
    new IntelRegisterSet (emptyArr, Set.empty) :> RegisterSet

  override __.Tag = RegisterSetTag.Intel
  override __.ArrSize = defaultSize
  override __.New x s = new IntelRegisterSet (x, s) :> RegisterSet
  override __.Empty = IntelRegisterSet.EmptySet
  override __.EmptyArr = emptyArr
  override __.Project x =
    match Register.ofRegID x with
    | R.RAX | R.EAX -> 0
    | R.RBX | R.EBX -> 1
    | R.RCX | R.ECX -> 2
    | R.RDX | R.EDX -> 3
    | R.RSP | R.ESP -> 4
    | R.RBP | R.EBP -> 5
    | R.RSI | R.ESI -> 6
    | R.RDI | R.EDI -> 7
    | R.R8  -> 8
    | R.R9  -> 9
    | R.R10 -> 10
    | R.R11 -> 11
    | R.R12 -> 12
    | R.R13 -> 13
    | R.R14 -> 14
    | R.R15 -> 15
    | R.SPL -> 16
    | R.BPL -> 17
    | R.SIL -> 18
    | R.DIL -> 19
    | R.ES -> 20
    | R.CS -> 21
    | R.SS -> 22
    | R.DS -> 23
    | R.FS -> 24
    | R.GS -> 25
    | R.ESBase -> 26
    | R.CSBase -> 27
    | R.SSBase -> 28
    | R.DSBase -> 29
    | R.FSBase -> 30
    | R.GSBase -> 31
    | R.OF -> 32
    | R.DF -> 33
    | R.IF -> 34
    | R.TF -> 35
    | R.SF -> 36
    | R.ZF -> 37
    | R.AF -> 38
    | R.PF -> 39
    | R.CF -> 40
    | R.MM0 -> 41
    | R.MM1 -> 42
    | R.MM2 -> 43
    | R.MM3 -> 44
    | R.MM4 -> 45
    | R.MM5 -> 46
    | R.MM6 -> 47
    | R.MM7 -> 48
    | R.ZMM0A -> 49
    | R.ZMM0B -> 50
    | R.ZMM0C -> 51
    | R.ZMM0D -> 52
    | R.ZMM0E -> 53
    | R.ZMM0F -> 54
    | R.ZMM0G -> 55
    | R.ZMM0H -> 56
    | R.ZMM1A -> 57
    | R.ZMM1B -> 58
    | R.ZMM1C -> 59
    | R.ZMM1D -> 60
    | R.ZMM1E -> 61
    | R.ZMM1F -> 62
    | R.ZMM1G -> 63
    | R.ZMM1H -> 64
    | R.ZMM2A -> 65
    | R.ZMM2B -> 66
    | R.ZMM2C -> 67
    | R.ZMM2D -> 68
    | R.ZMM2E -> 69
    | R.ZMM2F -> 70
    | R.ZMM2G -> 71
    | R.ZMM2H -> 72
    | R.ZMM3A -> 73
    | R.ZMM3B -> 74
    | R.ZMM3C -> 75
    | R.ZMM3D -> 76
    | R.ZMM3E -> 77
    | R.ZMM3F -> 78
    | R.ZMM3G -> 79
    | R.ZMM3H -> 80
    | R.ZMM4A -> 81
    | R.ZMM4B -> 82
    | R.ZMM4C -> 83
    | R.ZMM4D -> 84
    | R.ZMM4E -> 85
    | R.ZMM4F -> 86
    | R.ZMM4G -> 87
    | R.ZMM4H -> 88
    | R.ZMM5A -> 89
    | R.ZMM5B -> 90
    | R.ZMM5C -> 91
    | R.ZMM5D -> 92
    | R.ZMM5E -> 93
    | R.ZMM5F -> 94
    | R.ZMM5G -> 95
    | R.ZMM5H -> 96
    | R.ZMM6A -> 97
    | R.ZMM6B -> 98
    | R.ZMM6C -> 99
    | R.ZMM6D -> 100
    | R.ZMM6E -> 101
    | R.ZMM6F -> 102
    | R.ZMM6G -> 103
    | R.ZMM6H -> 104
    | R.ZMM7A -> 105
    | R.ZMM7B -> 106
    | R.ZMM7C -> 107
    | R.ZMM7D -> 108
    | R.ZMM7E -> 109
    | R.ZMM7F -> 110
    | R.ZMM7G -> 111
    | R.ZMM7H -> 112
    | R.ZMM8A -> 113
    | R.ZMM8B -> 114
    | R.ZMM8C -> 115
    | R.ZMM8D -> 116
    | R.ZMM8E -> 117
    | R.ZMM8F -> 118
    | R.ZMM8G -> 119
    | R.ZMM8H -> 120
    | R.ZMM9A -> 121
    | R.ZMM9B -> 122
    | R.ZMM9C -> 123
    | R.ZMM9D -> 124
    | R.ZMM9E -> 125
    | R.ZMM9F -> 126
    | R.ZMM9G -> 127
    | R.ZMM9H -> 128
    | R.ZMM10A -> 129
    | R.ZMM10B -> 130
    | R.ZMM10C -> 131
    | R.ZMM10D -> 132
    | R.ZMM10E -> 133
    | R.ZMM10F -> 134
    | R.ZMM10G -> 135
    | R.ZMM10H -> 136
    | R.ZMM11A -> 137
    | R.ZMM11B -> 138
    | R.ZMM11C -> 139
    | R.ZMM11D -> 140
    | R.ZMM11E -> 141
    | R.ZMM11F -> 142
    | R.ZMM11G -> 143
    | R.ZMM11H -> 144
    | R.ZMM12A -> 145
    | R.ZMM12B -> 146
    | R.ZMM12C -> 147
    | R.ZMM12D -> 148
    | R.ZMM12E -> 149
    | R.ZMM12F -> 150
    | R.ZMM12G -> 151
    | R.ZMM12H -> 152
    | R.ZMM13A -> 153
    | R.ZMM13B -> 154
    | R.ZMM13C -> 155
    | R.ZMM13D -> 156
    | R.ZMM13E -> 157
    | R.ZMM13F -> 158
    | R.ZMM13G -> 159
    | R.ZMM13H -> 160
    | R.ZMM14A -> 161
    | R.ZMM14B -> 162
    | R.ZMM14C -> 163
    | R.ZMM14D -> 164
    | R.ZMM14E -> 165
    | R.ZMM14F -> 166
    | R.ZMM14G -> 167
    | R.ZMM14H -> 168
    | R.ZMM15A -> 169
    | R.ZMM15B -> 170
    | R.ZMM15C -> 171
    | R.ZMM15D -> 172
    | R.ZMM15E -> 173
    | R.ZMM15F -> 174
    | R.ZMM15G -> 175
    | R.ZMM15H -> 176
    | R.BND0A -> 177
    | R.BND0B -> 178
    | R.BND1A -> 179
    | R.BND1B -> 180
    | R.BND2A -> 181
    | R.BND2B -> 182
    | R.BND3A -> 183
    | R.BND3B -> 184
    | R.FCW -> 185
    | R.FSW -> 186
    | R.FTW -> 187
    | R.FOP -> 188
    | R.FIP -> 189
    | R.FCS -> 190
    | R.FDP -> 191
    | R.FDS -> 192
    | R.MXCSR -> 193
    | R.MXCSRMASK -> 194
    | R.PKRU -> 195
    | _ -> -1

  member __.InverseProject wordSize projectedId =
    match projectedId with
    | 0 -> if WordSize.is64 wordSize then R.RAX else R.EAX
    | 1 -> if WordSize.is64 wordSize then R.RBX else R.EBX
    | 2 -> if WordSize.is64 wordSize then R.RCX else R.ECX
    | 3 -> if WordSize.is64 wordSize then R.RDX else R.EDX
    | 4 -> if WordSize.is64 wordSize then R.RSP else R.ESP
    | 5 -> if WordSize.is64 wordSize then R.RBP else R.EBP
    | 6 -> if WordSize.is64 wordSize then R.RSI else R.ESI
    | 7 -> if WordSize.is64 wordSize then R.RDI else R.EDI
    | 8 -> R.R8
    | 9 -> R.R9
    | 10 -> R.R10
    | 11 -> R.R11
    | 12 -> R.R12
    | 13 -> R.R13
    | 14 -> R.R14
    | 15 -> R.R15
    | 16 -> R.SPL
    | 17 -> R.BPL
    | 18 -> R.SIL
    | 19 -> R.DIL
    | 20 -> R.ES
    | 21 -> R.CS
    | 22 -> R.SS
    | 23 -> R.DS
    | 24 -> R.FS
    | 25 -> R.GS
    | 26 -> R.ESBase
    | 27 -> R.CSBase
    | 28 -> R.SSBase
    | 29 -> R.DSBase
    | 30 -> R.FSBase
    | 31 -> R.GSBase
    | 32 -> R.OF
    | 33 -> R.DF
    | 34 -> R.IF
    | 35 -> R.TF
    | 36 -> R.SF
    | 37 -> R.ZF
    | 38 -> R.AF
    | 39 -> R.PF
    | 40 -> R.CF
    | 41 -> R.MM0
    | 42 -> R.MM1
    | 43 -> R.MM2
    | 44 -> R.MM3
    | 45 -> R.MM4
    | 46 -> R.MM5
    | 47 -> R.MM6
    | 48 -> R.MM7
    | 49 -> R.ZMM0A
    | 50 -> R.ZMM0B
    | 51 -> R.ZMM0C
    | 52 -> R.ZMM0D
    | 53 -> R.ZMM0E
    | 54 -> R.ZMM0F
    | 55 -> R.ZMM0G
    | 56 -> R.ZMM0H
    | 57 -> R.ZMM1A
    | 58 -> R.ZMM1B
    | 59 -> R.ZMM1C
    | 60 -> R.ZMM1D
    | 61 -> R.ZMM1E
    | 62 -> R.ZMM1F
    | 63 -> R.ZMM1G
    | 64 -> R.ZMM1H
    | 65 -> R.ZMM2A
    | 66 -> R.ZMM2B
    | 67 -> R.ZMM2C
    | 68 -> R.ZMM2D
    | 69 -> R.ZMM2E
    | 70 -> R.ZMM2F
    | 71 -> R.ZMM2G
    | 72 -> R.ZMM2H
    | 73 -> R.ZMM3A
    | 74 -> R.ZMM3B
    | 75 -> R.ZMM3C
    | 76 -> R.ZMM3D
    | 77 -> R.ZMM3E
    | 78 -> R.ZMM3F
    | 79 -> R.ZMM3G
    | 80 -> R.ZMM3H
    | 81 -> R.ZMM4A
    | 82 -> R.ZMM4B
    | 83 -> R.ZMM4C
    | 84 -> R.ZMM4D
    | 85 -> R.ZMM4E
    | 86 -> R.ZMM4F
    | 87 -> R.ZMM4G
    | 88 -> R.ZMM4H
    | 89 -> R.ZMM5A
    | 90 -> R.ZMM5B
    | 91 -> R.ZMM5C
    | 92 -> R.ZMM5D
    | 93 -> R.ZMM5E
    | 94 -> R.ZMM5F
    | 95 -> R.ZMM5G
    | 96 -> R.ZMM5H
    | 97 -> R.ZMM6A
    | 98 -> R.ZMM6B
    | 99 -> R.ZMM6C
    | 100 -> R.ZMM6D
    | 101 -> R.ZMM6E
    | 102 -> R.ZMM6F
    | 103 -> R.ZMM6G
    | 104 -> R.ZMM6H
    | 105 -> R.ZMM7A
    | 106 -> R.ZMM7B
    | 107 -> R.ZMM7C
    | 108 -> R.ZMM7D
    | 109 -> R.ZMM7E
    | 110 -> R.ZMM7F
    | 111 -> R.ZMM7G
    | 112 -> R.ZMM7H
    | 113 -> R.ZMM8A
    | 114 -> R.ZMM8B
    | 115 -> R.ZMM8C
    | 116 -> R.ZMM8D
    | 117 -> R.ZMM8E
    | 118 -> R.ZMM8F
    | 119 -> R.ZMM8G
    | 120 -> R.ZMM8H
    | 121 -> R.ZMM9A
    | 122 -> R.ZMM9B
    | 123 -> R.ZMM9C
    | 124 -> R.ZMM9D
    | 125 -> R.ZMM9E
    | 126 -> R.ZMM9F
    | 127 -> R.ZMM9G
    | 128 -> R.ZMM9H
    | 129 -> R.ZMM10A
    | 130 -> R.ZMM10B
    | 131 -> R.ZMM10C
    | 132 -> R.ZMM10D
    | 133 -> R.ZMM10E
    | 134 -> R.ZMM10F
    | 135 -> R.ZMM10G
    | 136 -> R.ZMM10H
    | 137 -> R.ZMM11A
    | 138 -> R.ZMM11B
    | 139 -> R.ZMM11C
    | 140 -> R.ZMM11D
    | 141 -> R.ZMM11E
    | 142 -> R.ZMM11F
    | 143 -> R.ZMM11G
    | 144 -> R.ZMM11H
    | 145 -> R.ZMM12A
    | 146 -> R.ZMM12B
    | 147 -> R.ZMM12C
    | 148 -> R.ZMM12D
    | 149 -> R.ZMM12E
    | 150 -> R.ZMM12F
    | 151 -> R.ZMM12G
    | 152 -> R.ZMM12H
    | 153 -> R.ZMM13A
    | 154 -> R.ZMM13B
    | 155 -> R.ZMM13C
    | 156 -> R.ZMM13D
    | 157 -> R.ZMM13E
    | 158 -> R.ZMM13F
    | 159 -> R.ZMM13G
    | 160 -> R.ZMM13H
    | 161 -> R.ZMM14A
    | 162 -> R.ZMM14B
    | 163 -> R.ZMM14C
    | 164 -> R.ZMM14D
    | 165 -> R.ZMM14E
    | 166 -> R.ZMM14F
    | 167 -> R.ZMM14G
    | 168 -> R.ZMM14H
    | 169 -> R.ZMM15A
    | 170 -> R.ZMM15B
    | 171 -> R.ZMM15C
    | 172 -> R.ZMM15D
    | 173 -> R.ZMM15E
    | 174 -> R.ZMM15F
    | 175 -> R.ZMM15G
    | 176 -> R.ZMM15H
    | 177 -> R.BND0A
    | 178 -> R.BND0B
    | 179 -> R.BND1A
    | 180 -> R.BND1B
    | 181 -> R.BND2A
    | 182 -> R.BND2B
    | 183 -> R.BND3A
    | 184 -> R.BND3B
    | 185 -> R.FCW
    | 186 -> R.FSW
    | 187 -> R.FTW
    | 188 -> R.FOP
    | 189 -> R.FIP
    | 190 -> R.FCS
    | 191 -> R.FDP
    | 192 -> R.FDS
    | 193 -> R.MXCSR
    | 194 -> R.MXCSRMASK
    | 195 -> R.PKRU
    | _ -> Utils.impossible ()
    |> Register.toRegID

  member __.ToSet wordSize =
    __.GetProjectedSet () |> Set.map (__.InverseProject wordSize) |> Set.union s

  override __.ToString () =
    sprintf "IntelRegisterSet<%x, %x, %x, %x>" __.BitArray.[0] __.BitArray.[1]
      __.BitArray.[2] __.BitArray.[3]

[<RequireQualifiedAccess>]
module IntelRegisterSet =
  let singleton = RegisterSetBuilder.singletonBuilder IntelRegisterSet.EmptySet
  let empty = IntelRegisterSet.EmptySet
