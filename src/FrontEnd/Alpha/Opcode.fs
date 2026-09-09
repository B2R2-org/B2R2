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

namespace B2R2.FrontEnd.Alpha

open B2R2

/// <summary>
/// Represents an Alpha opcode. An instruction that hangs a qualifier off its
/// name is one opcode however it rounds and whatever it traps on, because what
/// it computes is the same; which qualifier a word carries is kept beside the
/// opcode rather than in it (see <see
/// cref='T:B2R2.FrontEnd.Alpha.Qualifier'/>).
/// </summary>
type Opcode =
  (* Memory format *)
  /// Loads an address.
  | LDA = 0
  /// Loads an address, the displacement scaled by 65536.
  | LDAH = 1
  /// Loads a zero-extended byte.
  | LDBU = 2
  /// Loads a zero-extended word.
  | LDWU = 3
  /// Loads a sign-extended longword.
  | LDL = 4
  /// Loads a quadword.
  | LDQ = 5
  /// Loads a sign-extended longword, locking the address.
  | LDL_L = 6
  /// Loads a quadword, locking the address.
  | LDQ_L = 7
  /// Loads the quadword the address lies in, ignoring alignment.
  | LDQ_U = 8
  /// Stores a byte.
  | STB = 9
  /// Stores a word.
  | STW = 10
  /// Stores a longword.
  | STL = 11
  /// Stores a quadword.
  | STQ = 12
  /// Stores a longword only where the lock still holds.
  | STL_C = 13
  /// Stores a quadword only where the lock still holds.
  | STQ_C = 14
  /// Stores a quadword to the address with its low bits cleared.
  | STQ_U = 15
  /// Loads an F_floating number.
  | LDF = 16
  /// Loads a G_floating number.
  | LDG = 17
  /// Loads an S_floating number.
  | LDS = 18
  /// Loads a T_floating number.
  | LDT = 19
  /// Stores an F_floating number.
  | STF = 20
  /// Stores a G_floating number.
  | STG = 21
  /// Stores an S_floating number.
  | STS = 22
  /// Stores a T_floating number.
  | STT = 23
  /// Prefetches a cache block.
  | PREFETCH = 24
  /// Prefetches a cache block, evicting it next.
  | PREFETCH_EN = 25
  /// Prefetches a cache block, meaning to modify it.
  | PREFETCH_M = 26
  /// Prefetches a cache block, meaning to modify it, evicting it next.
  | PREFETCH_MEN = 27
  (* Memory format with a function code *)
  /// Waits for every arithmetic trap of the instructions before it.
  | TRAPB = 28
  /// Waits for every exception of the instructions before it.
  | EXCB = 29
  /// Orders every access to memory around it.
  | MB = 30
  /// Orders every write to memory around it.
  | WMB = 31
  /// Prefetches an aligned 512-byte block.
  | FETCH = 32
  /// Prefetches an aligned 512-byte block, meaning to modify it.
  | FETCH_M = 33
  /// Reads the process cycle counter.
  | RPCC = 34
  /// Reads the intr_flag and clears it.
  | RC = 35
  /// Reads the intr_flag and sets it.
  | RS = 36
  /// Evicts a cache block.
  | ECB = 37
  /// Says the 64 bytes will be written before they are read.
  | WH64 = 38
  /// Says the same, and that the block is to be evicted next.
  | WH64EN = 39
  (* Memory format jump *)
  /// Jumps to a computed address.
  | JMP = 40
  /// Jumps to a subroutine at a computed address.
  | JSR = 41
  /// Returns from a subroutine.
  | RET = 42
  /// Jumps to a subroutine, returning to where it came.
  | JSR_COROUTINE = 43
  (* Branch format *)
  /// Branches unconditionally, keeping where it came from.
  | BR = 44
  /// Branches to a subroutine, keeping where it came from.
  | BSR = 45
  /// Branches where the register holds zero.
  | BEQ = 46
  /// Branches where the register holds anything else.
  | BNE = 47
  /// Branches where the register holds less than zero.
  | BLT = 48
  /// Branches where the register holds zero or less.
  | BLE = 49
  /// Branches where the register holds more than zero.
  | BGT = 50
  /// Branches where the register holds zero or more.
  | BGE = 51
  /// Branches where the register's low bit is clear.
  | BLBC = 52
  /// Branches where the register's low bit is set.
  | BLBS = 53
  /// Branches where the floating-point register holds zero.
  | FBEQ = 54
  /// Branches where the floating-point register holds anything else.
  | FBNE = 55
  /// Branches where the floating-point register holds less than zero.
  | FBLT = 56
  /// Branches where the floating-point register holds zero or less.
  | FBLE = 57
  /// Branches where the floating-point register holds more than zero.
  | FBGT = 58
  /// Branches where the floating-point register holds zero or more.
  | FBGE = 59
  (* Integer arithmetic *)
  /// Adds longwords.
  | ADDL = 60
  /// Adds longwords, trapping on overflow.
  | ADDLV = 61
  /// Adds quadwords.
  | ADDQ = 62
  /// Adds quadwords, trapping on overflow.
  | ADDQV = 63
  /// Subtracts longwords.
  | SUBL = 64
  /// Subtracts longwords, trapping on overflow.
  | SUBLV = 65
  /// Subtracts quadwords.
  | SUBQ = 66
  /// Subtracts quadwords, trapping on overflow.
  | SUBQV = 67
  /// Adds longwords, the first scaled by four.
  | S4ADDL = 68
  /// Adds quadwords, the first scaled by four.
  | S4ADDQ = 69
  /// Adds longwords, the first scaled by eight.
  | S8ADDL = 70
  /// Adds quadwords, the first scaled by eight.
  | S8ADDQ = 71
  /// Subtracts longwords, the first scaled by four.
  | S4SUBL = 72
  /// Subtracts quadwords, the first scaled by four.
  | S4SUBQ = 73
  /// Subtracts longwords, the first scaled by eight.
  | S8SUBL = 74
  /// Subtracts quadwords, the first scaled by eight.
  | S8SUBQ = 75
  /// Compares each of the eight bytes for being no smaller.
  | CMPBGE = 76
  /// Compares quadwords for being equal.
  | CMPEQ = 77
  /// Compares signed quadwords for being smaller.
  | CMPLT = 78
  /// Compares signed quadwords for being no larger.
  | CMPLE = 79
  /// Compares unsigned quadwords for being smaller.
  | CMPULT = 80
  /// Compares unsigned quadwords for being no larger.
  | CMPULE = 81
  (* Integer logic and conditional move *)
  /// Takes the logical product.
  | AND = 82
  /// Takes the logical product with the complement.
  | BIC = 83
  /// Takes the logical sum.
  | BIS = 84
  /// Takes the logical sum with the complement.
  | ORNOT = 85
  /// Takes the logical difference.
  | XOR = 86
  /// Takes the logical equivalence.
  | EQV = 87
  /// Moves where the register holds zero.
  | CMOVEQ = 88
  /// Moves where the register holds anything else.
  | CMOVNE = 89
  /// Moves where the register holds less than zero.
  | CMOVLT = 90
  /// Moves where the register holds zero or less.
  | CMOVLE = 91
  /// Moves where the register holds more than zero.
  | CMOVGT = 92
  /// Moves where the register holds zero or more.
  | CMOVGE = 93
  /// Moves where the register's low bit is set.
  | CMOVLBS = 94
  /// Moves where the register's low bit is clear.
  | CMOVLBC = 95
  /// Clears the bits naming the extensions this machine has.
  | AMASK = 96
  /// Reads which implementation of the architecture this is.
  | IMPLVER = 97
  (* Integer shift, extract, insert and mask *)
  /// Shifts left, filling with zero.
  | SLL = 98
  /// Shifts right, filling with zero.
  | SRL = 99
  /// Shifts right, filling with the sign.
  | SRA = 100
  /// Extracts a byte from the low part of a quadword.
  | EXTBL = 101
  /// Extracts a word from the low part of a quadword.
  | EXTWL = 102
  /// Extracts a longword from the low part of a quadword.
  | EXTLL = 103
  /// Extracts a quadword from the low part of a quadword.
  | EXTQL = 104
  /// Extracts a word from the high part of a quadword.
  | EXTWH = 105
  /// Extracts a longword from the high part of a quadword.
  | EXTLH = 106
  /// Extracts a quadword from the high part of a quadword.
  | EXTQH = 107
  /// Inserts a byte into the low part of a quadword.
  | INSBL = 108
  /// Inserts a word into the low part of a quadword.
  | INSWL = 109
  /// Inserts a longword into the low part of a quadword.
  | INSLL = 110
  /// Inserts a quadword into the low part of a quadword.
  | INSQL = 111
  /// Inserts a word into the high part of a quadword.
  | INSWH = 112
  /// Inserts a longword into the high part of a quadword.
  | INSLH = 113
  /// Inserts a quadword into the high part of a quadword.
  | INSQH = 114
  /// Clears a byte in the low part of a quadword.
  | MSKBL = 115
  /// Clears a word in the low part of a quadword.
  | MSKWL = 116
  /// Clears a longword in the low part of a quadword.
  | MSKLL = 117
  /// Clears a quadword in the low part of a quadword.
  | MSKQL = 118
  /// Clears a word in the high part of a quadword.
  | MSKWH = 119
  /// Clears a longword in the high part of a quadword.
  | MSKLH = 120
  /// Clears a quadword in the high part of a quadword.
  | MSKQH = 121
  /// Clears each byte the mask names.
  | ZAP = 122
  /// Clears each byte the mask does not name.
  | ZAPNOT = 123
  (* Integer multiply *)
  /// Multiplies longwords.
  | MULL = 124
  /// Multiplies longwords, trapping on overflow.
  | MULLV = 125
  /// Multiplies quadwords.
  | MULQ = 126
  /// Multiplies quadwords, trapping on overflow.
  | MULQV = 127
  /// Takes the high quadword of an unsigned quadword product.
  | UMULH = 128
  (* Byte, count and multimedia extensions *)
  /// Sign-extends a byte.
  | SEXTB = 129
  /// Sign-extends a word.
  | SEXTW = 130
  /// Counts how many bits are set.
  | CTPOP = 131
  /// Counts the zero bits above the highest set one.
  | CTLZ = 132
  /// Counts the zero bits below the lowest set one.
  | CTTZ = 133
  /// Sums how far apart each of the eight bytes is.
  | PERR = 134
  /// Unpacks four bytes into four words.
  | UNPKBW = 135
  /// Unpacks two bytes into two longwords.
  | UNPKBL = 136
  /// Packs four words into four bytes.
  | PKWB = 137
  /// Packs two longwords into two bytes.
  | PKLB = 138
  /// Takes the smaller of each of the eight signed bytes.
  | MINSB8 = 139
  /// Takes the smaller of each of the four signed words.
  | MINSW4 = 140
  /// Takes the smaller of each of the eight unsigned bytes.
  | MINUB8 = 141
  /// Takes the smaller of each of the four unsigned words.
  | MINUW4 = 142
  /// Takes the larger of each of the eight signed bytes.
  | MAXSB8 = 143
  /// Takes the larger of each of the four signed words.
  | MAXSW4 = 144
  /// Takes the larger of each of the eight unsigned bytes.
  | MAXUB8 = 145
  /// Takes the larger of each of the four unsigned words.
  | MAXUW4 = 146
  /// Moves an S_floating number into an integer register.
  | FTOIS = 147
  /// Moves a T_floating number into an integer register.
  | FTOIT = 148
  (* Integer to floating-point register moves and square roots *)
  /// Moves an integer register into an S_floating number.
  | ITOFS = 149
  /// Moves an integer register into an F_floating number.
  | ITOFF = 150
  /// Moves an integer register into a T_floating number.
  | ITOFT = 151
  /// Takes the square root of an F_floating number.
  | SQRTF = 152
  /// Takes the square root of a G_floating number.
  | SQRTG = 153
  /// Takes the square root of an S_floating number.
  | SQRTS = 154
  /// Takes the square root of a T_floating number.
  | SQRTT = 155
  (* VAX floating-point *)
  /// Adds F_floating numbers.
  | ADDF = 156
  /// Subtracts F_floating numbers.
  | SUBF = 157
  /// Multiplies F_floating numbers.
  | MULF = 158
  /// Divides F_floating numbers.
  | DIVF = 159
  /// Adds G_floating numbers.
  | ADDG = 160
  /// Subtracts G_floating numbers.
  | SUBG = 161
  /// Multiplies G_floating numbers.
  | MULG = 162
  /// Divides G_floating numbers.
  | DIVG = 163
  /// Compares G_floating numbers for being equal.
  | CMPGEQ = 164
  /// Compares G_floating numbers for being smaller.
  | CMPGLT = 165
  /// Compares G_floating numbers for being no larger.
  | CMPGLE = 166
  /// Converts a D_floating number to a G_floating one.
  | CVTDG = 167
  /// Converts a G_floating number to an F_floating one.
  | CVTGF = 168
  /// Converts a G_floating number to a D_floating one.
  | CVTGD = 169
  /// Converts a G_floating number to a quadword.
  | CVTGQ = 170
  /// Converts a quadword to an F_floating number.
  | CVTQF = 171
  /// Converts a quadword to a G_floating number.
  | CVTQG = 172
  (* IEEE floating-point *)
  /// Adds S_floating numbers.
  | ADDS = 173
  /// Subtracts S_floating numbers.
  | SUBS = 174
  /// Multiplies S_floating numbers.
  | MULS = 175
  /// Divides S_floating numbers.
  | DIVS = 176
  /// Adds T_floating numbers.
  | ADDT = 177
  /// Subtracts T_floating numbers.
  | SUBT = 178
  /// Multiplies T_floating numbers.
  | MULT = 179
  /// Divides T_floating numbers.
  | DIVT = 180
  /// Compares T_floating numbers for being unordered.
  | CMPTUN = 181
  /// Compares T_floating numbers for being equal.
  | CMPTEQ = 182
  /// Compares T_floating numbers for being smaller.
  | CMPTLT = 183
  /// Compares T_floating numbers for being no larger.
  | CMPTLE = 184
  /// Converts a T_floating number to an S_floating one.
  | CVTTS = 185
  /// Converts an S_floating number to a T_floating one.
  | CVTST = 186
  /// Converts a T_floating number to a quadword.
  | CVTTQ = 187
  /// Converts a quadword to an S_floating number.
  | CVTQS = 188
  /// Converts a quadword to a T_floating number.
  | CVTQT = 189
  (* Floating-point operate *)
  /// Copies the sign.
  | CPYS = 190
  /// Copies the sign, negated.
  | CPYSN = 191
  /// Copies the sign and the exponent.
  | CPYSE = 192
  /// Converts a longword to a quadword.
  | CVTLQ = 193
  /// Converts a quadword to a longword.
  | CVTQL = 194
  /// Writes the floating-point control register.
  | MT_FPCR = 195
  /// Reads the floating-point control register.
  | MF_FPCR = 196
  /// Moves where the floating-point register holds zero.
  | FCMOVEQ = 197
  /// Moves where the floating-point register holds anything else.
  | FCMOVNE = 198
  /// Moves where the floating-point register holds less than zero.
  | FCMOVLT = 199
  /// Moves where the floating-point register holds zero or less.
  | FCMOVLE = 200
  /// Moves where the floating-point register holds more than zero.
  | FCMOVGT = 201
  /// Moves where the floating-point register holds zero or more.
  | FCMOVGE = 202
  (* PALcode format *)
  /// Traps to the PALcode routine the function code names.
  | CALL_PAL = 203
  /// An encoding this decoder reads no instruction out of.
  | InvalidOp = 204

/// Provides functions to handle Alpha opcodes.
module Opcode =
  /// <summary>
  /// Returns the mnemonic an Alpha opcode is written as.
  ///
  /// This is the one place a mnemonic is spelled, so that what the assembler
  /// reads cannot drift from what the disassembler writes: the assembler builds
  /// its vocabulary out of this rather than out of a list of its own.
  /// </summary>
  [<CompiledName "ToString">]
  let toString opcode =
    match opcode with
    | Opcode.LDA -> "lda"
    | Opcode.LDAH -> "ldah"
    | Opcode.LDBU -> "ldbu"
    | Opcode.LDWU -> "ldwu"
    | Opcode.LDL -> "ldl"
    | Opcode.LDQ -> "ldq"
    | Opcode.LDL_L -> "ldl_l"
    | Opcode.LDQ_L -> "ldq_l"
    | Opcode.LDQ_U -> "ldq_u"
    | Opcode.STB -> "stb"
    | Opcode.STW -> "stw"
    | Opcode.STL -> "stl"
    | Opcode.STQ -> "stq"
    | Opcode.STL_C -> "stl_c"
    | Opcode.STQ_C -> "stq_c"
    | Opcode.STQ_U -> "stq_u"
    | Opcode.LDF -> "ldf"
    | Opcode.LDG -> "ldg"
    | Opcode.LDS -> "lds"
    | Opcode.LDT -> "ldt"
    | Opcode.STF -> "stf"
    | Opcode.STG -> "stg"
    | Opcode.STS -> "sts"
    | Opcode.STT -> "stt"
    | Opcode.PREFETCH -> "prefetch"
    | Opcode.PREFETCH_EN -> "prefetch_en"
    | Opcode.PREFETCH_M -> "prefetch_m"
    | Opcode.PREFETCH_MEN -> "prefetch_men"
    | Opcode.TRAPB -> "trapb"
    | Opcode.EXCB -> "excb"
    | Opcode.MB -> "mb"
    | Opcode.WMB -> "wmb"
    | Opcode.FETCH -> "fetch"
    | Opcode.FETCH_M -> "fetch_m"
    | Opcode.RPCC -> "rpcc"
    | Opcode.RC -> "rc"
    | Opcode.RS -> "rs"
    | Opcode.ECB -> "ecb"
    | Opcode.WH64 -> "wh64"
    | Opcode.WH64EN -> "wh64en"
    | Opcode.JMP -> "jmp"
    | Opcode.JSR -> "jsr"
    | Opcode.RET -> "ret"
    | Opcode.JSR_COROUTINE -> "jsr_coroutine"
    | Opcode.BR -> "br"
    | Opcode.BSR -> "bsr"
    | Opcode.BEQ -> "beq"
    | Opcode.BNE -> "bne"
    | Opcode.BLT -> "blt"
    | Opcode.BLE -> "ble"
    | Opcode.BGT -> "bgt"
    | Opcode.BGE -> "bge"
    | Opcode.BLBC -> "blbc"
    | Opcode.BLBS -> "blbs"
    | Opcode.FBEQ -> "fbeq"
    | Opcode.FBNE -> "fbne"
    | Opcode.FBLT -> "fblt"
    | Opcode.FBLE -> "fble"
    | Opcode.FBGT -> "fbgt"
    | Opcode.FBGE -> "fbge"
    | Opcode.ADDL -> "addl"
    | Opcode.ADDLV -> "addl/v"
    | Opcode.ADDQ -> "addq"
    | Opcode.ADDQV -> "addq/v"
    | Opcode.SUBL -> "subl"
    | Opcode.SUBLV -> "subl/v"
    | Opcode.SUBQ -> "subq"
    | Opcode.SUBQV -> "subq/v"
    | Opcode.S4ADDL -> "s4addl"
    | Opcode.S4ADDQ -> "s4addq"
    | Opcode.S8ADDL -> "s8addl"
    | Opcode.S8ADDQ -> "s8addq"
    | Opcode.S4SUBL -> "s4subl"
    | Opcode.S4SUBQ -> "s4subq"
    | Opcode.S8SUBL -> "s8subl"
    | Opcode.S8SUBQ -> "s8subq"
    | Opcode.CMPBGE -> "cmpbge"
    | Opcode.CMPEQ -> "cmpeq"
    | Opcode.CMPLT -> "cmplt"
    | Opcode.CMPLE -> "cmple"
    | Opcode.CMPULT -> "cmpult"
    | Opcode.CMPULE -> "cmpule"
    | Opcode.AND -> "and"
    | Opcode.BIC -> "bic"
    | Opcode.BIS -> "bis"
    | Opcode.ORNOT -> "ornot"
    | Opcode.XOR -> "xor"
    | Opcode.EQV -> "eqv"
    | Opcode.CMOVEQ -> "cmoveq"
    | Opcode.CMOVNE -> "cmovne"
    | Opcode.CMOVLT -> "cmovlt"
    | Opcode.CMOVLE -> "cmovle"
    | Opcode.CMOVGT -> "cmovgt"
    | Opcode.CMOVGE -> "cmovge"
    | Opcode.CMOVLBS -> "cmovlbs"
    | Opcode.CMOVLBC -> "cmovlbc"
    | Opcode.AMASK -> "amask"
    | Opcode.IMPLVER -> "implver"
    | Opcode.SLL -> "sll"
    | Opcode.SRL -> "srl"
    | Opcode.SRA -> "sra"
    | Opcode.EXTBL -> "extbl"
    | Opcode.EXTWL -> "extwl"
    | Opcode.EXTLL -> "extll"
    | Opcode.EXTQL -> "extql"
    | Opcode.EXTWH -> "extwh"
    | Opcode.EXTLH -> "extlh"
    | Opcode.EXTQH -> "extqh"
    | Opcode.INSBL -> "insbl"
    | Opcode.INSWL -> "inswl"
    | Opcode.INSLL -> "insll"
    | Opcode.INSQL -> "insql"
    | Opcode.INSWH -> "inswh"
    | Opcode.INSLH -> "inslh"
    | Opcode.INSQH -> "insqh"
    | Opcode.MSKBL -> "mskbl"
    | Opcode.MSKWL -> "mskwl"
    | Opcode.MSKLL -> "mskll"
    | Opcode.MSKQL -> "mskql"
    | Opcode.MSKWH -> "mskwh"
    | Opcode.MSKLH -> "msklh"
    | Opcode.MSKQH -> "mskqh"
    | Opcode.ZAP -> "zap"
    | Opcode.ZAPNOT -> "zapnot"
    | Opcode.MULL -> "mull"
    | Opcode.MULLV -> "mull/v"
    | Opcode.MULQ -> "mulq"
    | Opcode.MULQV -> "mulq/v"
    | Opcode.UMULH -> "umulh"
    | Opcode.SEXTB -> "sextb"
    | Opcode.SEXTW -> "sextw"
    | Opcode.CTPOP -> "ctpop"
    | Opcode.CTLZ -> "ctlz"
    | Opcode.CTTZ -> "cttz"
    | Opcode.PERR -> "perr"
    | Opcode.UNPKBW -> "unpkbw"
    | Opcode.UNPKBL -> "unpkbl"
    | Opcode.PKWB -> "pkwb"
    | Opcode.PKLB -> "pklb"
    | Opcode.MINSB8 -> "minsb8"
    | Opcode.MINSW4 -> "minsw4"
    | Opcode.MINUB8 -> "minub8"
    | Opcode.MINUW4 -> "minuw4"
    | Opcode.MAXSB8 -> "maxsb8"
    | Opcode.MAXSW4 -> "maxsw4"
    | Opcode.MAXUB8 -> "maxub8"
    | Opcode.MAXUW4 -> "maxuw4"
    | Opcode.FTOIS -> "ftois"
    | Opcode.FTOIT -> "ftoit"
    | Opcode.ITOFS -> "itofs"
    | Opcode.ITOFF -> "itoff"
    | Opcode.ITOFT -> "itoft"
    | Opcode.SQRTF -> "sqrtf"
    | Opcode.SQRTG -> "sqrtg"
    | Opcode.SQRTS -> "sqrts"
    | Opcode.SQRTT -> "sqrtt"
    | Opcode.ADDF -> "addf"
    | Opcode.SUBF -> "subf"
    | Opcode.MULF -> "mulf"
    | Opcode.DIVF -> "divf"
    | Opcode.ADDG -> "addg"
    | Opcode.SUBG -> "subg"
    | Opcode.MULG -> "mulg"
    | Opcode.DIVG -> "divg"
    | Opcode.CMPGEQ -> "cmpgeq"
    | Opcode.CMPGLT -> "cmpglt"
    | Opcode.CMPGLE -> "cmpgle"
    | Opcode.CVTDG -> "cvtdg"
    | Opcode.CVTGF -> "cvtgf"
    | Opcode.CVTGD -> "cvtgd"
    | Opcode.CVTGQ -> "cvtgq"
    | Opcode.CVTQF -> "cvtqf"
    | Opcode.CVTQG -> "cvtqg"
    | Opcode.ADDS -> "adds"
    | Opcode.SUBS -> "subs"
    | Opcode.MULS -> "muls"
    | Opcode.DIVS -> "divs"
    | Opcode.ADDT -> "addt"
    | Opcode.SUBT -> "subt"
    | Opcode.MULT -> "mult"
    | Opcode.DIVT -> "divt"
    | Opcode.CMPTUN -> "cmptun"
    | Opcode.CMPTEQ -> "cmpteq"
    | Opcode.CMPTLT -> "cmptlt"
    | Opcode.CMPTLE -> "cmptle"
    | Opcode.CVTTS -> "cvtts"
    | Opcode.CVTST -> "cvtst"
    | Opcode.CVTTQ -> "cvttq"
    | Opcode.CVTQS -> "cvtqs"
    | Opcode.CVTQT -> "cvtqt"
    | Opcode.CPYS -> "cpys"
    | Opcode.CPYSN -> "cpysn"
    | Opcode.CPYSE -> "cpyse"
    | Opcode.CVTLQ -> "cvtlq"
    | Opcode.CVTQL -> "cvtql"
    | Opcode.MT_FPCR -> "mt_fpcr"
    | Opcode.MF_FPCR -> "mf_fpcr"
    | Opcode.FCMOVEQ -> "fcmoveq"
    | Opcode.FCMOVNE -> "fcmovne"
    | Opcode.FCMOVLT -> "fcmovlt"
    | Opcode.FCMOVLE -> "fcmovle"
    | Opcode.FCMOVGT -> "fcmovgt"
    | Opcode.FCMOVGE -> "fcmovge"
    | Opcode.CALL_PAL -> "call_pal"
    | _ -> Terminator.impossible ()

type internal Op = Opcode

// vim: set tw=80 sts=2 sw=2:
