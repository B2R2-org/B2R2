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

namespace B2R2.FrontEnd.PPC

/// <summary>
/// Represents a PPC opcode.
/// </summary>
type Opcode =
  | B = 0
  | BA = 1
  | BL = 2
  | BLA = 3
  | BC = 4
  | BCA = 5
  | BCL = 6
  | BCLA = 7
  | BCLR = 8
  | BCLRL = 9
  | BCCTR = 10
  | BCCTRL = 11
  | BCTAR = 12
  | BCTARL = 13
  | ADDI = 14
  | ADDIS = 15
  | ADDPCIS = 16
  | ADD = 17
  | ADD_DOT = 18
  | ADDO = 19
  | ADDO_DOT = 20
  | ADDIC = 21
  | SUBF = 22
  | SUBF_DOT = 23
  | SUBFO = 24
  | SUBFO_DOT = 25
  | ADDIC_DOT = 26
  | SUBFIC = 27
  | ADDC = 28
  | ADDC_DOT = 29
  | ADDCO = 30
  | ADDCO_DOT = 31
  | SUBFC = 32
  | SUBFC_DOT = 33
  | SUBFCO = 34
  | SUBFCO_DOT = 35
  | ADDE = 36
  | ADDE_DOT = 37
  | ADDEO = 38
  | ADDEO_DOT = 39
  | ADDME = 40
  | ADDME_DOT = 41
  | ADDMEO = 42
  | ADDMEO_DOT = 43
  | SUBFE = 44
  | SUBFE_DOT = 45
  | SUBFEO = 46
  | SUBFEO_DOT = 47
  | SUBFME = 48
  | SUBFME_DOT = 49
  | SUBFMEO = 50
  | SUBFMEO_DOT = 51
  | ADDEX = 52
  | ADDZE = 53
  | ADDZE_DOT = 54
  | ADDZEO = 55
  | ADDZEO_DOT = 56
  | SUBFZE = 57
  | SUBFZE_DOT = 58
  | SUBFZEO = 59
  | SUBFZEO_DOT = 60
  | NEG = 61
  | NEG_DOT = 62
  | NEGO = 63
  | NEGO_DOT = 64
  | MULLI = 65
  | MULLW = 66
  | MULLW_DOT = 67
  | MULLWO = 68
  | MULLWO_DOT = 69
  | MULHW = 70
  | MULHW_DOT = 71
  | MULHWU = 72
  | MULHWU_DOT = 73
  | DIVW = 74
  | DIVW_DOT = 75
  | DIVWO = 76
  | DIVWO_DOT = 77
  | DIVWU = 78
  | DIVWU_DOT = 79
  | DIVWUO = 80
  | DIVWUO_DOT = 81
  | DIVWE = 82
  | DIVWE_DOT = 83
  | DIVWEO = 84
  | DIVWEO_DOT = 85
  | DIVWEU = 86
  | DIVWEU_DOT = 87
  | DIVWEUO = 88
  | DIVWEUO_DOT = 89
  | MODSW = 90
  | MODUW = 91
  | DARN = 92
  | LBZ = 93
  | LBZU = 94
  | LBZX = 95
  | LBZUX = 96
  | LHZ = 97
  | LHZU = 98
  | LHZX = 99
  | LHZUX = 100
  | LHA = 101
  | LHAU = 102
  | LHAX = 103
  | LHAUX = 104
  | LWZ = 105
  | LWZU = 106
  | LWZX = 107
  | LWZUX = 108
  | LWA = 109
  | LWAX = 110
  | LWAUX = 111
  | LD = 112
  | LDU = 113
  | LDX = 114
  | LDUX = 115
  | STB = 116
  | STBU = 117
  | STBX = 118
  | STBUX = 119
  | STH = 120
  | STHU = 121
  | STHX = 122
  | STHUX = 123
  | STW = 124
  | STWU = 125
  | STWX = 126
  | STWUX = 127
  | STD = 128
  | STDU = 129
  | STDX = 130
  | STDUX = 131
  | LQ = 132
  | STQ = 133
  | LHBRX = 134
  | LWBRX = 135
  | STHBRX = 136
  | STWBRX = 137
  | LDBRX = 138
  | STDBRX = 139
  | LMW = 140
  | STMW = 141
  | LSWI = 142
  | LSWX = 143
  | STSWI = 144
  | STSWX = 145

type internal Op = Opcode
