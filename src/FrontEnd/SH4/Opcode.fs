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

namespace B2R2.FrontEnd.SH4

/// <summary>
/// Represents an SH4 opcode.
/// </summary>
type Opcode =
  // Add.
  | ADD = 0
  // Add with carry.
  | ADDC = 1
  // Add with V-flag overflow check.
  | ADDV = 2
  // Logical AND.
  | AND = 3
  // Logical AND.
  | ANDB = 4
  // Branch if False.
  | BF = 5
  // Branch if False with delay slot.
  | BFS = 6
  // Unconditional branch.
  | BRA = 7
  // Branch Far.
  | BRAF = 8
  // Branch to Subroutine.
  | BSR = 9
  // Branch to Subroutine Far.
  | BSRF = 10
  // Branch if True.
  | BT = 11
  // Branch if True with delay slot.
  | BTS = 12
  // Clear MAC Register.
  | CLRMAC = 13
  // Clear 'S' bit.
  | CLRS = 14
  // Clear 'T' bit.
  | CLRT = 15
  // Equality comparison.
  | CMPEQ = 16
  // Signed greater than or equal comparison.
  | CMPGE = 17
  // Signed greater than comparison.
  | CMPGT = 18
  // Unsigned greater than comparison.
  | CMPHI = 19
  // Unsigned greater than or equal comparison.
  | CMPHS = 20
  // Greater than 0 comparison.
  | CMPPL = 21
  // Greater than or equal to 0 comparison.
  | CMPPZ = 22
  // Any bytes equal (string) comparison.
  | CMPSTR = 23
  // Divide (step 0) as Signed.
  | DIV0S = 24
  // Divide (step 0) as Unsigned.
  | DIV0U = 25
  // Divide step 1.
  | DIV1 = 26
  // Double-length multiply as Signed.
  | DMULSL = 27
  // Double-length multiply as Unsigned.
  | DMULUL = 28
  // Decrement and Test.
  | DT = 29
  // Extend as Signed.
  | EXTS = 30
  // Extend as Signed.
  | EXTSB = 31
  // Extend as Signed.
  | EXTSW = 32
  // Extend as Unsigned.
  | EXTU = 33
  // Extend as Unsigned.
  | EXTUB = 34
  // Extend as Unsigned.
  | EXTUW = 35
  // Floating-point Absolute Value.
  | FABS = 36
  // Floating-point Add.
  | FADD = 37
  // Floating-point Compare.
  | FCMP = 38
  // Floating-point Compare.
  | FCMPEQ = 39
  // Floating-point Compare.
  | FCMPGT = 40
  // Floating-point Convert Double to Single-Precision.
  | FCNVDS = 41
  // Floating-point Convert Single to Double-Precision.
  | FCNVSD = 42
  // Floating-point Divide.
  | FDIV = 43
  // Floatin4-point Inner Product.
  | FIPR = 44
  // Floating-point load immediate 0.0
  | FLDI0 = 45
  // Floating-point load immediate 1.0
  | FLDI1 = 46
  // Floating-point load to System Register.
  | FLDS = 47
  // Floating-point convert from Integer.
  | FLOAT = 48
  // Floating-point Multiply and Accumulate.
  | FMAC = 49
  // Floating-point Move / Move with Extension.
  | FMOV = 50
  // Floating-point Move.
  | FMOVS = 51
  // Floating-point Multiply.
  | FMUL = 52
  // Floating-point Negate Value.
  | FNEG = 53
  // FR bit Change.
  | FRCHG = 54
  // SZ bit Change.
  | FSCHG = 55
  // Floating-point Square Root.
  | FSQRT = 56
  // Floating-point Store System Register.
  | FSTS = 57
  // Floating-point Subtract.
  | FSUB = 58
  // Floating-point Truncate and Convert to Integer.
  | FTRC = 59
  // Floating-point Transform Vector.
  | FTRV = 60
  // Unconditional Jump.
  | JMP = 61
  // Jump to Subroutine.
  | JSR = 62
  // Load to Control Register.
  | LDC = 63
  // Load to Control Register.
  | LDCL = 64
  // Load to FPU System Register / Load to System Register.
  | LDS = 65
  // Load to FPU System Register / Load to System Register.
  | LDSL = 66
  // Load PTEH/PTEA/PTEL to TLB.
  | LDTLB = 67
  // Multiply and Accumulate Long.
  | MACL = 68
  // Multiply and Accumulate Word.
  | MACW = 69
  // Move Data / Constant Value / Global Data / Structure Data.
  | MOV = 70
  // Move effective Address.
  | MOVA = 71
  // Move effective Address.
  | MOVB = 72
  // Move effective Address.
  | MOVW = 73
  // Move effective Address.
  | MOVL = 74
  // Move with Cache block Allocation.
  | MOVCAL = 75
  // Move 'T' bit.
  | MOVT = 76
  // Multiply Long.
  | MULL = 77
  // Multiply as Signed Word.
  | MULSW = 78
  // Multiply as Unsigned Word.
  | MULUW = 79
  // Negate.
  | NEG = 80
  // Negate with Carry.
  | NEGC = 81
  // No Operation.
  | NOP = 82
  // Logical NOT.
  | NOT = 83
  // Operand Cache Block Invalidate.
  | OCBI = 84
  // Operand Cache Block Purge.
  | OCBP = 85
  // Operand Cache Block Write-back.
  | OCBWB = 86
  // Logical OR.
  | OR = 87
  // Logical OR.
  | ORB = 88
  // Pre-fetch data to cache.
  | PREF = 89
  // Rotate with Carry left.
  | ROTCL = 90
  // Rotate with Carry right.
  | ROTCR = 91
  // Rotate left.
  | ROTL = 92
  // Rotate right.
  | ROTR = 93
  // Return from Exception.
  | RTE = 94
  // Return from Subroutine.
  | RTS = 95
  // Set 'S' bit.
  | SETS = 96
  // Set 'T' bit.
  | SETT = 97
  // Shift Arithmetic Dynamically.
  | SHAD = 98
  // Shift Arithmetic Left.
  | SHAL = 99
  // Shift Arithmetic Right.
  | SHAR = 100
  // Shift Logical Dynamically.
  | SHLD = 101
  // Shift Logical Left.
  | SHLL = 102
  // 2-bits Shift Logical Left.
  | SHLL2 = 103
  // 8-bits Shift Logical Left.
  | SHLL8 = 104
  // 16-bits Shift Logical Left.
  | SHLL16 = 105
  // Shift Logical Right.
  | SHLR = 106
  // 2-bits Shift Logical Right.
  | SHLR2 = 107
  // 2-bits Shift Logical Right.
  | SHLR8 = 108
  // 2-bits Shift Logical Right.
  | SHLR16 = 109
  // Sleep.
  | SLEEP = 110
  // Store Control register.
  | STC = 111
  // Store Control register.
  | STCL = 112
  // Store System Register / Store from SPU System register.
  | STS = 113
  // Store System Register / Store from SPU System register.
  | STSL = 114
  // Subtract.
  | SUB = 115
  // Subtract with Carry.
  | SUBC = 116
  // Subtract with V-flag underflow check.
  | SUBV = 117
  // Swap regsiter halves.
  | SWAP = 118
  // Swap regsiter halves.
  | SWAPB = 119
  // Swap regsiter halves.
  | SWAPW = 120
  // Test and Set.
  | TAS = 121
  // Test and Set.
  | TASB = 122
  // Trap Always.
  | TRAPA = 123
  // Logical Test.
  | TST = 124
  // Logical Test.
  | TSTB = 125
  // Logical XOR.
  | XOR = 126
  // Logical XOR.
  | XORB = 127
  // Extract.
  | XTRCT = 128
  // Invalid Instruction.
  | InvalidOp = 129