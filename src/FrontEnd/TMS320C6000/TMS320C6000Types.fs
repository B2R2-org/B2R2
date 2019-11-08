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
  | ABSDP = 1
  | ABSSP = 2
  | ADD = 3
  | ADD2 = 4
  | ADDAB = 5
  | ADDAD = 6
  | ADDAH = 7
  | ADDAW = 8
  | ADDDP = 9
  | ADDK = 10
  | ADDSP = 11
  | ADDU = 12
  | AND = 13
  | B = 14
  | CLR = 15
  | CMPEQ = 16
  | CMPEQDP = 17
  | CMPEQSP = 18
  | CMPGT = 19
  | CMPGTDP = 20
  | CMPGTSP = 21
  | CMPGTU = 22
  | CMPLT = 23
  | CMPLTDP = 24
  | CMPLTSP = 25
  | CMPLTU = 26
  | DPINT = 27
  | DPSP = 28
  | DPTRUNC = 29
  | EXT = 30
  | EXTU = 31
  | IDLE = 32
  | INTDP = 33
  | INTDPU = 34
  | INTSP = 35
  | INTSPU = 36
  | LDB = 37
  | LDBU = 38
  | LDDW = 39
  | LDH = 40
  | LDHU = 41
  | LDW = 42
  | LMBD = 43
  | MPY = 44
  | MPYDP = 45
  | MPYH = 46
  | MPYHL = 47
  | MPYHLU = 48
  | MPYHSLU = 49
  | MPYHSU = 50
  | MPYHU = 51
  | MPYHULS = 52
  | MPYHUS = 53
  | MPYI = 54
  | MPYID = 55
  | MPYLH = 56
  | MPYLHU = 57
  | MPYLSHU = 58
  | MPYLUHS = 59
  | MPYSP = 60
  | MPYSP2DP = 61
  | MPYSPDP = 62
  | MPYSU = 63
  | MPYU = 64
  | MPYUS = 65
  | MV = 66
  | MVC = 67
  | MVK = 68
  | MVKH = 69
  | MVKL = 70
  | MVKLH = 71
  | NEG = 72
  | NOP = 73
  | NORM = 74
  | NOT = 75
  | OR = 76
  | RCPDP = 77
  | RCPSP = 78
  | RSQRDP = 79
  | RSQRSP = 80
  | SADD = 81
  | SAT = 82
  | SET = 83
  | SHL = 84
  | SHR = 85
  | SHRU = 86
  | SMPY = 87
  | SMPYH = 88
  | SMPYHL = 89
  | SMPYLH = 90
  | SPDP = 91
  | SPINT = 92
  | SPTRUNC = 93
  | SSHL = 94
  | SSUB = 95
  | STB = 96
  | STH = 97
  | STW = 98
  | SUB = 99
  | SUB2 = 100
  | SUBAB = 101
  | SUBAH = 102
  | SUBAW = 103
  | SUBC = 104
  | SUBDP = 105
  | SUBSP = 106
  | SUBU = 107
  | XOR = 108
  | ZERO = 109
  | InvalOP = 110

type internal Op = Opcode

type Operand =
  | Register of Register
  | RegisterPair of Register * Register
  | Immediate of Imm
and Imm = uint64

type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
  | ThreeOperands of Operand * Operand * Operand
  | FourOperands of Operand * Operand * Operand * Operand

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
  /// Cycle packet index
  PacketIndex : int
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
