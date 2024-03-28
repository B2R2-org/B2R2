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

namespace B2R2.FrontEnd.BinLifter.AVR

open B2R2
open System.Runtime.CompilerServices

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.BinLifter.Tests")>]
do ()

type Opcode =
  /// Add with Carry
  | ADC = 0
  /// Add without Carry
  | ADD = 1
  /// Add immediate to Word
  | ADIW = 2
  /// Logical AND
  | AND = 3
  /// Logical AND with Immediate
  | ANDI = 4
  /// Arithmetic Shift Right
  | ASR = 5
  /// Bit Clear in SREG
  | BCLR = 6
  /// Bit Load from the T Flag in SREG to a Bit in Register
  | BLD = 7
  /// Branch if Bit in SREG is Cleared
  | BRBC = 8
  /// Branch if Bit in SREG is Set
  | BRBS = 9
  /// Branch if Carry Cleared
  | BRCC = 10
  /// Branch if Carry Se
  | BRCS = 11
  /// Break
  | BREAK = 12
  /// Branch if Equal
  | BREQ = 13
  /// Branch if Greater or Equal (Signed)
  | BRGE = 14
  /// Branch if Half Carry Flag is Cleared
  | BRHC = 15
  /// Branch if Half Carry Flag is Set
  | BRHS = 16
  /// Branch if GLobal Interrupt is Disabled
  | BRID = 17
  /// Branch if Global Interrupt is Enabled
  | BRIE = 18
  /// Branch is Lower (Unsigned)
  | BRLAO = 19
  /// Branch if Less Than (Signed)
  | BRLT = 20
  /// Branch if Minus
  | BRMI = 21
  /// Branch if Not Equal
  | BRNE = 22
  /// Branch if Plus
  | BRPL = 23
  /// Branch if Same or Higher (Unsigned)
  | BRSH = 24
  /// Branch if the T Flag is Cleared
  | BRTC = 25
  /// Branch if the T Flag is Set
  | BRTS = 26
  /// Branch if Overflow Cleared
  | BRVC = 27
  /// Branch if Overflow Set
  | BRVS = 28
  /// Bit Set in SREG
  | BSET = 29
  /// Bit Store from Bit in Register to T Flag in SREG
  | BST = 30
  /// Long Call to a Subroutine
  | CALL = 31
  /// Clear Bit in I/O Register
  | CBI = 32
  /// Clear Bits in Register
  | CBR = 33
  /// Clear Carry Flag
  | CLC = 34
  /// Clear Half Carry Flag
  | CLH = 35
  /// Clear Global Interrup Flag
  | CLI = 36
  /// Clear Negative Flag
  | CLN = 37
  /// Clear Register
  | CLR = 38
  /// Clear Signed Flag
  | CLS = 39
  /// Clear T Flag
  | CLT = 40
  /// Clear Overflow Flag
  | CLV = 41
  /// Clear Zero Flag
  | CLZ = 42
  /// One's Complement
  | COM = 43
  /// Compare
  | CP = 44
  /// Compare with Carry
  | CPC = 45
  /// Compare with Immediate
  | CPI = 46
  /// Compare Skip if Equal
  | CPSE = 47
  /// Decrement
  | DEC = 48
  /// Data Encryption Standard
  | DES = 49
  /// Extended Indirect Call to Subroutine
  | EICALL = 50
  /// Extended Indirect Jump
  | EIJMP = 51
  /// Extended Load Program Memory
  | ELPM = 52
  /// Exclusive OR
  | EOR = 53
  /// Fractional Multiply Unsigned
  | FMUL = 54
  /// Fractional Multiply Signed
  | FMULS = 55
  /// Fractional Multiply SIgned with Unsigned
  | FMULSU = 56
  /// Indirect Call to Subroutine
  | ICALL = 57
  /// Indirect Jump
  | IJMP = 58
  /// Load an I/O Location to Register
  | IN = 59
  /// Increment
  | INC = 60
  /// Jump
  | JMP = 61
  /// Load and Clear
  | LAC = 62
  /// Load and Set
  | LAS = 63
  /// Load and Toggle
  | LAT = 64
  /// Load Indirect from Data Space to Register using Index Y and Index Z
  | LDD = 65
  /// Load Immediate
  | LDI = 66
  /// Load Direct from Data Space
  | LDS = 67
  /// Load Program Memory
  | LPM = 68
  /// Logical Shift Left
  | LSL = 69
  /// Logical Shift Right
  | LSR = 70
  /// Copy Register
  | MOV = 71
  /// Copy Register Word
  | MOVW = 72
  /// Multiply Unsigned
  | MUL = 73
  /// Multiply Signed
  | MULS = 74
  /// Multiple Signed with Unsigned
  | MULSU = 75
  /// Two's Complement
  | NEG = 76
  /// No Operation
  | NOP = 77
  /// Logical OR
  | OR = 78
  /// Logical OR with Immediate
  | ORI = 79
  /// Store Register to I/O Location
  | OUT = 80
  /// Pop Register from Stack
  | POP = 81
  /// Push Register on Stack
  | PUSH = 82
  /// Relative Call to Subroutine
  | RCALL = 83
  /// Return from Subroutine
  | RET = 84
  /// Return from Interrupt
  | RETI = 85
  /// Relative Jump
  | RJMP = 86
  /// Rotate Left through Carry
  | ROL = 87
  /// Roatate Right through Carry
  | ROR = 88
  /// Subtract with Carry
  | SBC = 89
  /// Subtract Immediate with Carry SBI - Set Bit in I/O Register
  | SBCI = 90
  /// Set Bit in I/O Register
  | SBI = 91
  /// Skip if Bit in I/O Register is Cleared
  | SBIC = 92
  /// Skip if Bit in I/O Register is Set
  | SBIS = 93
  /// Subtract Immediate from Word
  | SBIW = 94
  /// Set Bits in Register
  | SBR = 95
  /// Skip if Bit in Register is Cleared
  | SBRC = 96
  /// Skip if Bit in Register is Set
  | SBRS = 97
  /// Set Carry Flag
  | SEC = 98
  /// Set Half Carry Flag
  | SEH = 99
  /// Set Global Interrupt Flag
  | SEI = 100
  /// Set Negative Flag
  | SEN = 101
  /// Set all Bits in Register
  | SER = 102
  /// Set Signed Flag
  | SES = 103
  /// Set T Flag
  | SET = 104
  /// Set Overflow Flag
  | SEV = 105
  /// Set Zero Flag
  | SEZ = 106
  /// Sets the circuit in sleep mode
  | SLEEP = 107
  /// Store Program Memory ***
  | SPM = 108
  /// Store Indirect From Register to Data Space using Index Y and Index Z ***
  | STD = 109
  /// Store Direct to Data Space ***
  | STS = 110
  /// Subtract without Carry
  | SUB = 111
  /// Subtract Immediate
  | SUBI = 112
  /// Swap Nibbles
  | SWAP = 113
  /// Test for Zero or Minus
  | TST = 114
  /// Watchdog Reset
  | WDR = 115
  /// Exchange
  | XCH = 116
  /// Load Indirect from Data Space to Register using Index X
  | LD = 117
  /// Store Indirect From Register to Data Space using Index X
  | ST = 118
  /// Invalid Op code
  | InvalidOp = 119

type Const = int32

type AddressingMode =
  | DispMode of Register * Const
  | PreIdxMode of Register
  | PostIdxMode of Register
  | UnchMode of Register

type Operand =
  | OprReg of Register
  | OprImm of Const
  | OprAddr of Const
  | OprMemory of AddressingMode

type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand

/// Basic information obtained by parsing a AVR instruction.
[<NoComparison; CustomEquality>]
type InsInfo = {
  /// Address.
  Address: Addr
  /// Instruction length.
  NumBytes: uint32
  /// Opcode.
  Opcode: Opcode
  /// Operands
  Operands: Operands
}
with
  override __.GetHashCode () =
    hash (__.Address,
          __.NumBytes,
          __.Opcode)
  override __.Equals (i) =
    match i with
    | :? InsInfo as i ->
      i.Address = __.Address
      && i.NumBytes = __.NumBytes
      && i.Opcode = __.Opcode
    | _ -> false

// vim: set tw=80 sts=2 sw=2:
