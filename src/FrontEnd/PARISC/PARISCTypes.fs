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

namespace B2R2.FrontEnd.PARISC

open System.Runtime.CompilerServices
open B2R2

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.PARISC.Tests")>]
do ()

/// <summary>
///   PARISC opcodes.
/// </summary>
type Opcode =
  /// To cause a break instruction trap for debugging purposes.
  | BREAK = 0
  /// To enforce program order of instruction execution.
  | SYNC = 1
  /// To enforce DMA completion order.
  | SYNCDMA = 2
  /// To restore processor state
  | RFI = 3
  /// To selectively set bits in the system mask to 1.
  | SSM = 4
  /// To selectively reset bits in the system mask to 0.
  | RSM = 5
  /// To set PSW system mask bits to a value from a register.
  | MTSM = 6
  /// To calculate the space register number referenced by an implicit pointer
  | LDSID = 7
  /// To move a value from a general register to a space register.
  | MTSP = 8
  /// To move a value to a general register from a space register.
  | MFSP = 9
  /// To move a value from a general register to a control register.
  | MTCTL = 10
  /// To take the one’s complement of a value from a general register.
  | MTSARCM = 11
  /// To move the current instruction address to a general register.
  | MFIA = 12
  /// To move a value to a general register from a control register.
  | MFCTL = 13
  /// To provide implementation-dependent operations for system initialization
  | DIAG = 14
  /// To add an entry to the instruction TLB.
  | IITLBT = 15
  /// To invalidate an instruction TLB entry.
  | PITLB = 16
  /// To invalidate an instruction TLB entry without matching
  | PITLBE = 17
  /// To invalidate an instruction cache line.
  | FIC = 18
  /// To provide for flushing the entire instruction or combined cache
  | FICE = 19
  /// To add an entry to the data TLB.
  | IDTLBT = 20
  /// To invalidate a data TLB entry.
  | PDTLB = 21
  /// To invalidate a data TLB entry without matching the address portion.
  | PDTLBE = 22
  /// To invalidate a data cache line and write it back to memory if it dirty.
  | FDC = 23
  /// To provide for flushing the entire data or combined cache
  | FDCE = 24
  /// To invalidate a data cache line.
  | PDC = 25
  /// To determine whether read or write access to a given address is allowed.
  | PROBE = 26
  /// To determine whether read or write access to a given address is allowed.
  | PROBEI = 27
  /// To determine the absolute address of a mapped virtual page.
  | LPA = 28
  /// To determine the coherence index corresponding to a virtual address.
  | LCI = 29
  /// To do 64-bit integer addition and conditionally
  | ADD = 30
  /// To provide a primitive operation for multiplication.
  | SHLADD = 31
  /// To do 64-bit integer subtraction, and conditionally
  | SUB = 32
  /// To provide the primitive operation for integer division.
  | DS = 33
  /// To do a 64-bit bitwise AND with complement.
  | ANDCM = 34
  /// To do a 64-bit, bitwise AND.
  | AND = 35
  /// To do a 64-bit, bitwise inclusive OR.
  | OR = 36
  /// To do a 64-bit, bitwise exclusive OR.
  | XOR = 37
  /// To individually compare corresponding sub-units
  | UXOR = 38
  /// To compare two registers, set a register to 0, and conditionally
  | CMPCLR = 39
  /// To individually compare corresponding sub-units of a doubleword
  | UADDCM = 40
  /// To separately correct the 16 BCD digits of the result
  | DCOR = 41
  /// To add multiple halfwords in parallel with optional saturation.
  | HADD = 42
  /// To subtract multiple halfwords in parallel with optional saturation.
  | HSUB = 43
  /// To average multiple halfwords in parallel.
  | HAVG = 44
  /// To perform multiple halfword shift left and add
  | HSHLADD = 45
  /// To perform multiple halfword shift right and add
  | HSHRADD = 46
  /// To load a byte into a general register.
  | LDB = 47
  /// To load a halfword into a general register.
  | LDH = 48
  /// To load a word into a general register.
  | LDW = 49
  /// To load a doubleword into a general register.
  | LDD = 50
  /// To load a doubleword into a general register from an absolute address.
  | LDDA = 51
  /// To read and lock a doubleword semaphore in main memory.
  | LDCD = 52
  /// To load a word into a general register from an absolute address.
  | LDWA = 53
  /// To read and lock a word semaphore in main memory.
  | LDCW = 54
  /// To store a byte from a general register.
  | STB = 55
  /// To store a halfword from a general register.
  | STH = 56
  /// To store a word from a general register.
  | STW = 57
  /// To store a doubleword from a general register.
  | STD = 58
  /// To implement the beginning, middle, and ending cases
  | STBY = 59
  /// To implement the beginning, middle, and ending cases
  | STDBY = 60
  /// To store a word from a general register to an absolute address.
  | STWA = 61
  /// To store a doubleword from a general register to an absolute address.
  | STDA = 62
  /// To load a word into a floating-point coprocessor register.
  | FLDW = 63
  /// To store a word from a floating-point coprocessor register.
  | FSTW = 64
  /// To load a doubleword into a floating-point coprocessor register.
  | FLDD = 65
  /// To store a doubleword from a floating-point coprocessor register.
  | FSTD = 66
  /// To add an immediate value to a register and conditionally
  | ADDI = 67
  /// To subtract a register from an immediate value and conditionally
  | SUBI = 68
  /// To shift a pair of registers by fixed or variable amount and conditionally
  | SHRPD = 69
  /// To shift the rightmost 32 bits of a pair of registers
  | SHRPW = 70
  /// To extract any 64-bit or shorter field from a fixed or variable position
  | EXTRD = 71
  /// To extract any 32-bit or shorter field from a fixed or variable position
  | EXTRW = 72
  /// To deposit a value into a register at a fixed or variable position
  | DEPD = 73
  /// To deposit an immediate value into a register
  | DEPDI = 74
  /// To deposit a value into the rightmost 32 bits of a register
  | DEPW = 75
  /// To deposit an immediate value into the rightmost 32 bits of a register
  | DEPWI = 76
  /// To select any combination of four halfwords from a source register
  | PERMH = 77
  /// To perform multiple parallel halfword shift left operations.
  | HSHL = 78
  /// To perform multiple parallel halfword
  | HSHR = 79
  /// To combine two words from two source registers
  | MIXW = 80
  /// To combine four halfwords from two source registers
  | MIXH = 81
  /// To do IA-relative branches with optional privilege level change
  | B = 82
  /// To do IA-relative branches with a dynamic displacement
  | BLR = 83
  /// To do base-relative branches with a dynamic displacement
  | BV = 84
  /// To do procedure calls, branches and returns to another space.
  | BE = 85
  /// To do base-relative branches and procedure calls to another space.
  | BVE = 86
  /// To add two values and perform an IA-relative branch conditionally
  | ADDB = 87
  /// To add two values and perform an IA-relative branch conditionally
  | ADDIB = 88
  /// To perform an IA-relative branch conditionally
  | BB = 89
  /// To compare two values and perform an IA-relative branch conditionally
  | CMPB = 90
  /// To compare two values and perform an IA-relative branch conditionally
  | CMPIB = 91
  /// To copy one register to another and perform an IA-relative branch
  | MOVB = 92
  /// To copy an immediate value into a register
  | MOVIB = 93
  /// To compare an immediate value with the contents of a register
  | CMPICLR = 94
  /// To load a word into a coprocessor register.
  | CLDW = 95
  /// To load a doubleword into a coprocessor register.
  | CLDD = 96
  /// To store a word from a coprocessor register.
  | CSTW = 97
  /// To store a doubleword from a coprocessor register.
  | CSTD = 98
  /// To invoke a coprocessor unit operation.
  | COPR = 99
  /// To invoke a special function unit operation.
  | SPOP0 = 100
  /// To copy a special function unit register or result to a general register.
  | SPOP1 = 101
  /// To perform a parameterized special function unit operation.
  | SPOP2 = 102
  /// To perform a parameterized special function unit operation.
  | SPOP3 = 103
  /// To validate fields in the Status Register
  | FID = 104
  /// To copy a floating-point value to another floating-point register.
  | FCPY = 105
  /// To perform a floating-point absolute value.
  | FABS = 106
  /// To perform a floating-point square root.
  | FSQRT = 107
  /// To round a floating-point value to an integral value.
  | FRND = 108
  /// To negate a floating-point value.
  | FNEG = 109
  /// To negate a floating-point absolute value.
  | FNEGABS = 110
  /// To change the value in a floating-point register
  | FCNV = 111
  /// To perform a floating-point comparison.
  | FCMP = 112
  /// To test the results of one or more earlier comparisons.
  | FTEST = 113
  /// To perform a floating-point addition.
  | FADD = 114
  /// To perform a floating-point subtraction.
  | FSUB = 115
  /// To perform a floating-point multiply.
  | FMPY = 116
  /// To perform a floating-point division.
  | FDIV = 117
  /// To perform a floating-point multiply and fused add.
  | FMPYFADD = 118
  /// To perform a floating-point multiply, negate, and fused add.
  | FMPYNFADD = 119
  /// To disable the implementation-dependent performance monitor coprocessor
  | PMDIS = 120
  /// To enable the implementation-dependent performance monitor coprocessor.
  | PMENB = 121
  /// To load an offset into a general register.
  | LDO = 122
  /// To load the upper portion of a 32-bit immediate value
  | LDIL = 123
  /// To add the upper portion of 32-bit immediate value to a general register.
  | ADDIL = 124
  /// To push a value from a GR onto the branch target stack.
  | PUSHBTS = 125
  /// To push the currently nominated address onto the branch target stack.
  | PUSHNOM = 126
  /// To clear the branch target stack.
  | CLRBTS = 127
  /// To perform a floating-point multiply and a floating-point add.
  | FMPYADD = 128
  /// To perform a floating-point multiply and a floating-point subtract.
  | FMPYSUB = 129
  /// To perform unsigned fixed-point multiplication.
  | XMPYU = 130

type internal Op = Opcode

type RoundMode =
  /// Round to Nearest
  | RN = 0
  /// Round toward Zero
  | RZ = 1
  /// Round toward +∞
  | RP = 2
  /// Round toward −∞
  | RM = 3

/// PARISC completers
type Completer =
  | B = 0
  | C = 1
  | GATE = 2
  | I = 3
  | L = 4
  | R = 5
  | S = 6
  | T = 7
  | U = 8
  | W = 9
  | Z = 10
  | M = 11
  | O = 12
  | E = 13
  | NEVER = 14
  | EQ = 15
  | LT = 16
  | LE = 17
  | LTU = 18
  | LEU = 19
  | SV = 20
  | OD = 21
  | TR = 22
  | NEQ = 23
  | GE = 24
  | GT = 25
  | GEU = 26
  | GTU = 27
  | NSV = 28
  | EV = 29
  | NUV = 30
  | ZNV = 31
  | UV = 32
  | VNZ = 33
  | NWC = 34
  | NWZ = 35
  | NHC = 36
  | NHZ = 37
  | NBC = 38
  | NBZ = 39
  | NDC = 40
  | SWC = 41
  | SWZ = 42
  | SHC = 43
  | SHZ = 44
  | SBC = 45
  | SBZ = 46
  | SDC = 47
  | DNEVER = 48
  | DEQ = 49
  | DLT = 50
  | DLE = 51
  | DLTU = 52
  | DLEU = 53
  | DSV = 54
  | DOD = 55
  | DTR = 56
  | DNEQ = 57
  | DGE = 58
  | DGT = 59
  | DGEU = 60
  | DGTU = 61
  | DNSV = 62
  | DEV = 63
  | DNUV = 64
  | DZNV = 65
  | DUV = 66
  | DVNZ = 67
  | DNWC = 68
  | DNWZ = 69
  | DNHC = 70
  | DNHZ = 71
  | DNBC = 72
  | DNBZ = 73
  | DNDC = 74
  | DSWC = 75
  | DSWZ = 76
  | DSHC = 77
  | DSHZ = 78
  | DSBC = 79
  | DSBZ = 80
  | DSDC = 81
  | DB = 82
  | DC = 83
  | TC = 84
  | TSV = 85
  | MA = 88
  | MB = 89
  | SM = 90
  | SGL = 97
  | DBL = 98
  | QUAD = 99
  | UW = 100
  | DW = 101
  | UDW = 102
  | QW = 103
  | UQW = 104
  | SS = 105
  | US = 106
  | LDISP = 107
  | SDISP = 108
  | N = 113
  | BC = 114
  | SL = 115
  | PUSH = 116
  | FALSEQ = 164
  | FALSE = 165
  | FQ = 166
  | FBGTLE = 167
  | FEQ = 168
  | FEQT = 169
  | FQEQ = 170
  | FBNEQ = 171
  | FBQGE = 172
  | FLT = 173
  | FQLT = 174
  | FBGE = 175
  | FBQGT = 176
  | FLE = 177
  | FQLE = 178
  | FBGT = 179
  | FBQLE = 180
  | FGT = 181
  | FQGT = 182
  | FBLE = 183
  | FBQLT = 184
  | FGE = 185
  | FQGE = 186
  | FBLT = 187
  | FBQEQ = 188
  | FNEQ = 189
  | FBEQ = 190
  | FBEQT = 191
  | FBQ = 192
  | FGTLE = 193
  | TRUEQ = 194
  | TRUE = 195
  | ACC = 196
  | ACC2 = 197
  | ACC4 = 198
  | ACC6 = 199
  | ACC8 = 200
  | REJ = 201
  | REJ8 = 202
  | CO = 203

type SHIFTST =
  | SARSHFT = 0

type Operand =
  | OpReg of Register
  | OpImm of Imm
  | OpMem of Base * Space option * Offset option * AccessLength
  | OpAddr of JumpTarget
  | OpShiftAmount of Imm
  | OpRoundMode of RoundMode
  | OpAtomMemOper of Aq * Rl
  | OpCSR of uint16
  | OpCond of Completer
and Aq = bool
and Rl = bool
and Imm = uint64
and JumpTarget =
  | Relative of int64
  | RelativeBase of Base * Imm
and Offset =
  | Imm of int64
  | Reg of Register
and AccessLength = RegType
and Base = Register
and Space = Register

type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
  | ThreeOperands of Operand * Operand * Operand
  | FourOperands of Operand * Operand * Operand * Operand
  | FiveOperands of Operand * Operand * Operand * Operand * Operand

type internal Instruction = Opcode * Operands

/// Basic information obtained by parsing a PARISC instruction.
[<NoComparison; CustomEquality>]
type InsInfo = {
  /// Address.
  Address: Addr
  /// Instruction length.
  NumBytes: uint32
  /// Completer.
  Completer: Completer array option
  /// Completer condition or fmt.
  Condition: Completer option
  /// Completer swap and uid.
  ID: uint64[] option
  /// Opcode.
  Opcode: Opcode
  /// Operands.
  Operands: Operands
  /// Operation Size.
  OperationSize: RegType
  /// PA-RISC architecture.
  Arch: Architecture
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
