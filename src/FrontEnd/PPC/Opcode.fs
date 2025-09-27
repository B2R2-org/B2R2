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
  | ADDI = 0
  | ADDIS = 1
  | ADDPCIS = 2
  | ADD = 3
  | ADD_DOT = 4
  | ADDO = 5
  | ADDO_DOT = 6
  | SUBF = 7
  | SUBF_DOT = 8
  | SUBFO = 9
  | SUBFO_DOT = 10
  | ADDIC = 11
  | ADDIC_DOT = 12
  | SUBFIC = 13
  | ADDC = 14
  | ADDC_DOT = 15
  | ADDCO = 16
  | ADDCO_DOT = 17
  | SUBFC = 18
  | SUBFC_DOT = 19
  | SUBFCO = 20
  | SUBFCO_DOT = 21
  | ADDE = 22
  | ADDE_DOT = 23
  | ADDEO = 24
  | ADDEO_DOT = 25
  | SUBFE = 26
  | SUBFE_DOT = 27
  | SUBFEO = 28
  | SUBFEO_DOT = 29
  | ADDME = 30
  | ADDME_DOT = 31
  | ADDMEO = 32
  | ADDMEO_DOT = 33
  | SUBFME = 34
  | SUBFME_DOT = 35
  | SUBFMEO = 36
  | SUBFMEO_DOT = 37
  | ADDEX = 38
  | SUBFZE = 39
  | SUBFZE_DOT = 40
  | SUBFZEO = 41
  | SUBFZEO_DOT = 42
  | ADDZE = 43
  | ADDZE_DOT = 44
  | ADDZEO = 45
  | ADDZEO_DOT = 46
  | NEG = 47
  | NEG_DOT = 48
  | NEGO = 49
  | NEGO_DOT = 50
  | MULLI = 51
  | MULHW = 52
  | MULHW_DOT = 53
  | MULLW = 54
  | MULLW_DOT = 55
  | MULLWO = 56
  | MULLWO_DOT = 57
  | MULHWU = 58
  | MULHWU_DOT = 59
  | DIVW = 60
  | DIVW_DOT = 61
  | DIVWO = 62
  | DIVWO_DOT = 63
  | DIVWU = 64
  | DIVWU_DOT = 65
  | DIVWUO = 66
  | DIVWUO_DOT = 67
  | DIVWE = 68
  | DIVWE_DOT = 69
  | DIVWEO = 70
  | DIVWEO_DOT = 71
  | DIVWEU = 72
  | DIVWEU_DOT = 73
  | DIVWEUO = 74
  | DIVWEUO_DOT = 75
  | MODSW = 76
  | MODUW = 77
  | DARN = 78
  | B = 79
  | BA = 80
  | BL = 81
  | BLA = 82
  | BC = 83
  | BCA = 84
  | BCL = 85
  | BCLA = 86
  | BCLR = 87
  | BCLRL = 88
  | BCCTR = 89
  | BCCTRL = 90
  | BCTAR = 91
  | BCTARL = 92

type internal Op = Opcode
