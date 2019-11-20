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

namespace B2R2.FrontEnd.TMS320C6000

open B2R2
open System.Runtime.CompilerServices

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.Tests")>]
do ()

type Register =
  | A0 = 0x0
  | A1 = 0x1
  | A2 = 0x2
  | A3 = 0x3
  | A4 = 0x4
  | A5 = 0x5
  | A6 = 0x6
  | A7 = 0x7
  | A8 = 0x8
  | A9 = 0x9
  | A10 = 0xA
  | A11 = 0xB
  | A12 = 0xC
  | A13 = 0xD
  | A14 = 0xE
  | A15 = 0xF
  | A16 = 0x10
  | A17 = 0x11
  | A18 = 0x12
  | A19 = 0x13
  | A20 = 0x14
  | A21 = 0x15
  | A22 = 0x16
  | A23 = 0x17
  | A24 = 0x18
  | A25 = 0x19
  | A26 = 0x1A
  | A27 = 0x1B
  | A28 = 0x1C
  | A29 = 0x1D
  | A30 = 0x1E
  | A31 = 0x1F
  | B0 = 0x20
  | B1 = 0x21
  | B2 = 0x22
  | B3 = 0x23
  | B4 = 0x24
  | B5 = 0x25
  | B6 = 0x26
  | B7 = 0x27
  | B8 = 0x28
  | B9 = 0x29
  | B10 = 0x2A
  | B11 = 0x2B
  | B12 = 0x2C
  | B13 = 0x2D
  | B14 = 0x2E
  | B15 = 0x2F
  | B16 = 0x30
  | B17 = 0x31
  | B18 = 0x32
  | B19 = 0x33
  | B20 = 0x34
  | B21 = 0x35
  | B22 = 0x36
  | B23 = 0x37
  | B24 = 0x38
  | B25 = 0x39
  | B26 = 0x3A
  | B27 = 0x3B
  | B28 = 0x3C
  | B29 = 0x3D
  | B30 = 0x3E
  | B31 = 0x3F

/// Shortcut for Register type.
type internal R = Register

/// This module exposes several useful functions to handle TMS320C6000
/// registers.
[<RequireQualifiedAccess>]
module Register =
  let inline ofRegID (n: RegisterID): Register =
    int n |> LanguagePrimitives.EnumOfValue

  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

/// <summary>
///   TMS320C6000 opcodes. This type should be generated using
///   <c>scripts/genOpcode.fsx</c> from the `TMS320C6000SupportedOpcode.txt`
///   file.
/// </summary>
type Opcode =
  | ABS = 0
  | ABS2 = 1
  | ABSDP = 2
  | ABSSP = 3
  | ADD = 4
  | ADD2 = 5
  | ADD4 = 6
  | ADDAB = 7
  | ADDAD = 8
  | ADDAH = 9
  | ADDAW = 10
  | ADDDP = 11
  | ADDK = 12
  | ADDKPC = 13
  | ADDSP = 14
  | ADDSUB = 15
  | ADDSUB2 = 16
  | ADDU = 17
  | AND = 18
  | ANDN = 19
  | AVG2 = 20
  | AVGU4 = 21
  | B = 22
  | BDEC = 23
  | BITC4 = 24
  | BITR = 25
  | BNOP = 26
  | BPOS = 27
  | CALLP = 28
  | CLR = 29
  | CMPEQ = 30
  | CMPEQ2 = 31
  | CMPEQ4 = 32
  | CMPEQDP = 33
  | CMPEQSP = 34
  | CMPGT = 35
  | CMPGT2 = 36
  | CMPGTDP = 37
  | CMPGTSP = 38
  | CMPGTU = 39
  | CMPGTU4 = 40
  | CMPLT = 41
  | CMPLT2 = 42
  | CMPLTDP = 43
  | CMPLTSP = 44
  | CMPLTU = 45
  | CMPLTU4 = 46
  | CMPY = 47
  | CMPYR = 48
  | CMPYR1 = 49
  | DDOTP4 = 50
  | DDOTPH2 = 51
  | DDOTPH2R = 52
  | DDOTPL2 = 53
  | DDOTPL2R = 54
  | DEAL = 55
  | DINT = 56
  | DMV = 57
  | DOTP2 = 58
  | DOTPN2 = 59
  | DOTPNRSU2 = 60
  | DOTPNRUS2 = 61
  | DOTPRSU2 = 62
  | DOTPRUS2 = 63
  | DOTPSU4 = 64
  | DOTPU4 = 65
  | DOTPUS4 = 66
  | DPACK2 = 67
  | DPACKX2 = 68
  | DPINT = 69
  | DPSP = 70
  | DPTRUNC = 71
  | EXT = 72
  | EXTU = 73
  | GMPY = 74
  | GMPY4 = 75
  | IDLE = 76
  | INTDP = 77
  | INTDPU = 78
  | INTSP = 79
  | INTSPU = 80
  | LDB = 81
  | LDBU = 82
  | LDDW = 83
  | LDH = 84
  | LDHU = 85
  | LDNDW = 86
  | LDNW = 87
  | LDW = 88
  | LMBD = 89
  | MAX2 = 90
  | MAXU4 = 91
  | MIN2 = 92
  | MINU4 = 93
  | MPY = 94
  | MPY2 = 95
  | MPY2IR = 96
  | MPY32 = 97
  | MPY32SU = 98
  | MPY32U = 99
  | MPY32US = 100
  | MPYDP = 101
  | MPYH = 102
  | MPYHI = 103
  | MPYHIR = 104
  | MPYHL = 105
  | MPYHLU = 106
  | MPYHSLU = 107
  | MPYHSU = 108
  | MPYHU = 109
  | MPYHULS = 110
  | MPYHUS = 111
  | MPYI = 112
  | MPYID = 113
  | MPYIH = 114
  | MPYIHR = 115
  | MPYIL = 116
  | MPYILR = 117
  | MPYLH = 118
  | MPYLHU = 119
  | MPYLI = 120
  | MPYLIR = 121
  | MPYLSHU = 122
  | MPYLUHS = 123
  | MPYSP = 124
  | MPYSP2DP = 125
  | MPYSPDP = 126
  | MPYSU = 127
  | MPYSU4 = 128
  | MPYU = 129
  | MPYU4 = 130
  | MPYUS = 131
  | MPYUS4 = 132
  | MV = 133
  | MVC = 134
  | MVD = 135
  | MVK = 136
  | MVKH = 137
  | MVKL = 138
  | MVKLH = 139
  | NEG = 140
  | NOP = 141
  | NORM = 142
  | NOT = 143
  | OR = 144
  | PACK2 = 145
  | PACKH2 = 146
  | PACKH4 = 147
  | PACKHL2 = 148
  | PACKL4 = 149
  | PACKLH2 = 150
  | RCPDP = 151
  | RCPSP = 152
  | RINT = 153
  | ROTL = 154
  | RPACK2 = 155
  | RSQRDP = 156
  | RSQRSP = 157
  | SADD = 158
  | SADD2 = 159
  | SADDSU2 = 160
  | SADDSUB = 161
  | SADDSUB2 = 162
  | SADDU4 = 163
  | SADDUS2 = 164
  | SAT = 165
  | SET = 166
  | SHFL = 167
  | SHFL3 = 168
  | SHL = 169
  | SHLMB = 170
  | SHR = 171
  | SHR2 = 172
  | SHRMB = 173
  | SHRU = 174
  | SHRU2 = 175
  | SMPY = 176
  | SMPY2 = 177
  | SMPY32 = 178
  | SMPYH = 179
  | SMPYHL = 180
  | SMPYLH = 181
  | SPACK2 = 182
  | SPACKU4 = 183
  | SPDP = 184
  | SPINT = 185
  | SPKERNEL = 186
  | SPKERNELR = 187
  | SPLOOP = 188
  | SPLOOPD = 189
  | SPLOOPW = 190
  | SPMASK = 191
  | SPMASKR = 192
  | SPTRUNC = 193
  | SSHL = 194
  | SSHVL = 195
  | SSHVR = 196
  | SSUB = 197
  | SSUB2 = 198
  | STB = 199
  | STDW = 200
  | STH = 201
  | STNDW = 202
  | STNW = 203
  | STW = 204
  | SUB = 205
  | SUB2 = 206
  | SUB4 = 207
  | SUBAB = 208
  | SUBABS4 = 209
  | SUBAH = 210
  | SUBAW = 211
  | SUBC = 212
  | SUBDP = 213
  | SUBSP = 214
  | SUBU = 215
  | SWAP2 = 216
  | SWAP4 = 217
  | SWE = 218
  | SWENR = 219
  | UNPKHU4 = 220
  | UNPKLU4 = 221
  | XOR = 222
  | XORMPY = 223
  | XPND2 = 224
  | XPND4 = 225
  | ZERO = 226
  | InvalOP = 227

type internal Op = Opcode

type Offset =
  | OffsetR of Register
  | UCst5 of uint64

type ModificationPerformed =
  | NegativeOffset
  | PositiveOffset
  | PreDecrement
  | PreIncrement
  | PostDecrement
  | PostIncrement

type Operand =
  | Register of Register
  | RegisterPair of Register * Register
  | OprMem of Register * ModificationPerformed * Offset
  | Immediate of Imm
and Imm = uint64

type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
  | ThreeOperands of Operand * Operand * Operand
  | FourOperands of Operand * Operand * Operand * Operand

type Side =
  | SideA
  | SideB

type FunctionalUnit =
  | L1
  | L2
  | L1X
  | L2X
  | S1
  | S2
  | S1X
  | S2X
  | M1
  | M2
  | M1X
  | M2X
  | D1
  | D2
  | NoUnit

type internal Instruction =
  Opcode * FunctionalUnit

/// Basic information obtained by parsing a TMS320C6000 instruction.
[<NoComparison; CustomEquality>]
type InsInfo = {
  /// Address.
  Address: Addr
  /// Instruction length.
  NumBytes: uint32
  /// Opcode.
  Opcode: Opcode
  /// Operands.
  Operands: Operands
  /// Functional Units.
  FunctionalUnit: FunctionalUnit
  /// Operation Size.
  OperationSize: RegType
  /// Parallel bit. If this is true, this instruction will get executed in
  /// parallel with the previous instruction. Note that this is not exactly the
  /// same as the P bit used in the processor.
  IsParallel: bool
  /// Effective address (after applying delay slots)
  EffectiveAddress: Addr
}
with
  override __.GetHashCode () =
    hash (__.Address,
          __.NumBytes,
          __.Opcode,
          __.Operands,
          __.OperationSize)
  override __.Equals (i) =
    match i with
    | :? InsInfo as i ->
      i.Address = __.Address
      && i.NumBytes = __.NumBytes
      && i.Opcode = __.Opcode
      && i.Operands = __.Operands
      && i.OperationSize = __.OperationSize
    | _ -> false

// vim: set tw=80 sts=2 sw=2:
