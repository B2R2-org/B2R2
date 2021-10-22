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
open System.Runtime.CompilerServices

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.BinLifter.Tests")>]
do ()

/// This exception occurs when an UnknownReg is explicitly used. This exception
/// should not happen in general.
exception UnknownRegException

/// <summary>
/// Registers for x86 (and x86-64).<para/>
///
/// Internally, a Register is represented with an integer (we use only 22 bits).
/// The most significant 10 bits (from 12th to 21th bits) represent the size of
/// the register. The next 4 bits (from 8th to 11th bits) represent the register
/// kind, and the reset of 8 bits are used to represent a register ID. There are
/// currently 13 kinds of registers including GP, FPU, MMX, etc. <para/>
/// <code>
/// 21 ... 13 12 11 10 09 08 07 06 05 04 03 02 01 00 (bit position)
/// +------------+----------+----------------------+
/// |  Size      | Kind     |  Register ID.        |
/// +------------+----------+----------------------+
/// </code>
/// </summary>
type Register =
  /// Accumulator for operands and results data (64bit).
  | RAX = 0x40000
  /// TCounter for string and loop operations (64bit).
  | RCX = 0x40001
  /// I/O pointer (64bit).
  | RDX = 0x40002
  /// Pointer to data in the DS segment (64bit).
  | RBX = 0x40003
  /// Stack pointer (in the SS segment) (64bit).
  | RSP = 0x40004
  /// Pointer to data on the stack (in the SS segment) (64bit).
  | RBP = 0x40005
  /// Pointer to data in the segment pointed to by the DS register (64bit).
  | RSI = 0x40006
  /// Pointer to data in the segment pointed to by the ES register (64bit).
  | RDI = 0x40007
  /// General-Purpose Registers for 64bit Mode.
  | R8 = 0x40008
  /// General-Purpose Registers for 64bit Mode.
  | R9 = 0x40009
  /// General-Purpose Registers for 64bit Mode.
  | R10 = 0x4000A
  /// General-Purpose Registers for 64bit Mode.
  | R11 = 0x4000B
  /// General-Purpose Registers for 64bit Mode.
  | R12 = 0x4000C
  /// General-Purpose Registers for 64bit Mode.
  | R13 = 0x4000D
  /// General-Purpose Registers for 64bit Mode.
  | R14 = 0x4000E
  /// General-Purpose Registers for 64bit Mode.
  | R15 = 0x4000F
  /// Accumulator for operands and results data (32bit).
  | EAX = 0x20010
  /// TCounter for string and loop operations (32bit).
  | ECX = 0x20011
  /// I/O pointer (32bit).
  | EDX = 0x20012
  /// Pointer to data in the DS segment (32bit).
  | EBX = 0x20013
  /// Stack pointer (in the SS segment) (32bit).
  | ESP = 0x20014
  /// Pointer to data on the stack (in the SS segment) (32bit).
  | EBP = 0x20015
  /// Pointer to data in the segment pointed to by the DS register (32bit).
  | ESI = 0x20016
  /// Pointer to data in the segment pointed to by the ES register (32bit).
  | EDI = 0x20017
  /// General-Purpose Registers for 64bit Mode (Doubleword Register).
  | R8D = 0x20018
  /// General-Purpose Registers for 64bit Mode (Doubleword Register).
  | R9D = 0x20019
  /// General-Purpose Registers for 64bit Mode (Doubleword Register).
  | R10D = 0x2001A
  /// General-Purpose Registers for 64bit Mode (Doubleword Register).
  | R11D = 0x2001B
  /// General-Purpose Registers for 64bit Mode (Doubleword Register).
  | R12D = 0x2001C
  /// General-Purpose Registers for 64bit Mode (Doubleword Register).
  | R13D = 0x2001D
  /// General-Purpose Registers for 64bit Mode (Doubleword Register).
  | R14D = 0x2001E
  /// General-Purpose Registers for 64bit Mode (Doubleword Register).
  | R15D = 0x2001F
  /// General-Purpose Registers (lower 16bits EAX).
  | AX = 0x10020
  /// General-Purpose Registers (lower 16bits ECX).
  | CX = 0x10021
  /// General-Purpose Registers (lower 16bits EDX).
  | DX = 0x10022
  /// General-Purpose Registers (lower 16bits EBX).
  | BX = 0x10023
  /// General-Purpose Registers (lower 16bits ESP).
  | SP = 0x10024
  /// General-Purpose Registers (lower 16bits EBP).
  | BP = 0x10025
  /// General-Purpose Registers (lower 16bits ESI).
  | SI = 0x10026
  /// General-Purpose Registers (lower 16bits EDI).
  | DI = 0x10027
  /// General-Purpose Registers for 64bit Mode (Word Register).
  | R8W = 0x10028
  /// General-Purpose Registers for 64bit Mode (Word Register).
  | R9W = 0x10029
  /// General-Purpose Registers for 64bit Mode (Word Register).
  | R10W = 0x1002A
  /// General-Purpose Registers for 64bit Mode (Word Register).
  | R11W = 0x1002B
  /// General-Purpose Registers for 64bit Mode (Word Register).
  | R12W = 0x1002C
  /// General-Purpose Registers for 64bit Mode (Word Register).
  | R13W = 0x1002D
  /// General-Purpose Registers for 64bit Mode (Word Register).
  | R14W = 0x1002E
  /// General-Purpose Registers for 64bit Mode (Word Register).
  | R15W = 0x1002F
  /// General-Purpose Registers (lower 8bits AX).
  | AL = 0x8030
  /// General-Purpose Registers (lower 8bits CX).
  | CL = 0x8031
  /// General-Purpose Registers (lower 8bits DX).
  | DL = 0x8032
  /// General-Purpose Registers (lower 8bits BX).
  | BL = 0x8033
  /// General-Purpose Registers (Higher 8bits AX).
  | AH = 0x8034
  /// General-Purpose Registers (Higher 8bits CX).
  | CH = 0x8035
  /// General-Purpose Registers (Higher 8bits DX).
  | DH = 0x8036
  /// General-Purpose Registers (Higher 8bits BX).
  | BH = 0x8037
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | R8L = 0x8038
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | R9L = 0x8039
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | R10L = 0x803A
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | R11L = 0x803B
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | R12L = 0x803C
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | R13L = 0x803D
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | R14L = 0x803E
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | R15L = 0x803F
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | SPL = 0x8040
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | BPL = 0x8041
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | SIL = 0x8042
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | DIL = 0x8043
  /// Instruction Pointer (32Bit).
  | EIP = 0x20044
  /// Instruction Pointer (64Bit).
  | RIP = 0x40045
  /// x87 FPU registers.
  | ST0 = 0x50100
  /// x87 FPU registers.
  | ST1 = 0x50101
  /// x87 FPU registers.
  | ST2 = 0x50102
  /// x87 FPU registers.
  | ST3 = 0x50103
  /// x87 FPU registers.
  | ST4 = 0x50104
  /// x87 FPU registers.
  | ST5 = 0x50105
  /// x87 FPU registers.
  | ST6 = 0x50106
  /// x87 FPU registers.
  | ST7 = 0x50107
  /// C87 FPU Control Word.
  | FCW = 0x10108
  /// x87 FPU Status Word.
  | FSW = 0x10109
  /// x87 FPU Tag Word.
  | FTW = 0x1010A
  /// x87 FPU Opcode.
  | FOP = 0x1010B
  /// x87 FPU Instruction Pointer Offset.
  | FIP = 0x4010C
  /// x87 FPU Instruction Pointer Selector.
  | FCS = 0x1010D
  /// x87 FPU Data Pointer Offset.
  | FDP = 0x4010E
  /// x87 FPU Data Pointer Selector.
  | FDS = 0x1010F
  /// x87 FPU Top indicator bits of Status Word.
  | FTOP = 0x2110
  /// x87 FPU Tag word section.
  | FTW0 = 0x2111
  /// x87 FPU Tag word section.
  | FTW1 = 0x2112
  /// x87 FPU Tag word section.
  | FTW2 = 0x2113
  /// x87 FPU Tag word section.
  | FTW3 = 0x2114
  /// x87 FPU Tag word section.
  | FTW4 = 0x2115
  /// x87 FPU Tag word section.
  | FTW5 = 0x2116
  /// x87 FPU Tag word section.
  | FTW6 = 0x2117
  /// x87 FPU Tag word section.
  | FTW7 = 0x2118
  /// x87 FPU Status Word C flag.
  | FSWC0 = 0x10119
  /// x87 FPU Status Word C flag.
  | FSWC1 = 0x411A
  /// x87 FPU Status Word C flag.
  | FSWC2 = 0x411B
  /// x87 FPU Status Word C flag.
  | FSWC3 = 0x411C
  /// MXCSR Control and Status Register.
  | MXCSR = 0x20411D
  /// MXCSR_MASK.
  | MXCSRMASK = 0x2011E
  /// MMX registers.
  | MM0 = 0x40200
  /// MMX registers.
  | MM1 = 0x40201
  /// MMX registers.
  | MM2 = 0x40202
  /// MMX registers.
  | MM3 = 0x40203
  /// MMX registers.
  | MM4 = 0x40204
  /// MMX registers.
  | MM5 = 0x40205
  /// MMX registers.
  | MM6 = 0x40206
  /// MMX registers.
  | MM7 = 0x40207
  /// XMM registers.
  | XMM0 = 0x80300
  /// XMM registers.
  | XMM1 = 0x80301
  /// XMM registers.
  | XMM2 = 0x80302
  /// XMM registers.
  | XMM3 = 0x80303
  /// XMM registers.
  | XMM4 = 0x80304
  /// XMM registers.
  | XMM5 = 0x80305
  /// XMM registers.
  | XMM6 = 0x80306
  /// XMM registers.
  | XMM7 = 0x80307
  /// XMM registers.
  | XMM8 = 0x80308
  /// XMM registers.
  | XMM9 = 0x80309
  /// XMM registers.
  | XMM10 = 0x8030A
  /// XMM registers.
  | XMM11 = 0x8030B
  /// XMM registers.
  | XMM12 = 0x8030C
  /// XMM registers.
  | XMM13 = 0x8030D
  /// XMM registers.
  | XMM14 = 0x8030E
  /// XMM registers.
  | XMM15 = 0x8030F
  /// 256-bit vector registers.
  | YMM0 = 0x100400
  /// 256-bit vector registers.
  | YMM1 = 0x100401
  /// 256-bit vector registers.
  | YMM2 = 0x100402
  /// 256-bit vector registers.
  | YMM3 = 0x100403
  /// 256-bit vector registers.
  | YMM4 = 0x100404
  /// 256-bit vector registers.
  | YMM5 = 0x100405
  /// 256-bit vector registers.
  | YMM6 = 0x100406
  /// 256-bit vector registers.
  | YMM7 = 0x100407
  /// 256-bit vector registers.
  | YMM8 = 0x100408
  /// 256-bit vector registers.
  | YMM9 = 0x100409
  /// 256-bit vector registers.
  | YMM10 = 0x10040A
  /// 256-bit vector registers.
  | YMM11 = 0x10040B
  /// 256-bit vector registers.
  | YMM12 = 0x10040C
  /// 256-bit vector registers.
  | YMM13 = 0x10040D
  /// 256-bit vector registers.
  | YMM14 = 0x10040E
  /// 256-bit vector registers.
  | YMM15 = 0x10040F
  /// 512-bit vector registers.
  | ZMM0 = 0x200500
  /// 512-bit vector registers.
  | ZMM1 = 0x200501
  /// 512-bit vector registers.
  | ZMM2 = 0x200502
  /// 512-bit vector registers.
  | ZMM3 = 0x200503
  /// 512-bit vector registers.
  | ZMM4 = 0x200504
  /// 512-bit vector registers.
  | ZMM5 = 0x200505
  /// 512-bit vector registers.
  | ZMM6 = 0x200506
  /// 512-bit vector registers.
  | ZMM7 = 0x200507
  /// 512-bit vector registers.
  | ZMM8 = 0x200508
  /// 512-bit vector registers.
  | ZMM9 = 0x200509
  /// 512-bit vector registers.
  | ZMM10 = 0x20050A
  /// 512-bit vector registers.
  | ZMM11 = 0x20050B
  /// 512-bit vector registers.
  | ZMM12 = 0x20050C
  /// 512-bit vector registers.
  | ZMM13 = 0x20050D
  /// 512-bit vector registers.
  | ZMM14 = 0x20050E
  /// 512-bit vector registers.
  | ZMM15 = 0x20050F
  /// Segment registers.
  | ES = 0x10600
  /// Segment registers.
  | CS = 0x10601
  /// Segment registers.
  | SS = 0x10602
  /// Segment registers.
  | DS = 0x10603
  /// Segment registers.
  | FS = 0x10604
  /// Segment registers.
  | GS = 0x10605
  /// ES.base.
  | ESBase = 0x700
  /// CS.base.
  | CSBase = 0x701
  /// SS.base.
  | SSBase = 0x702
  /// DS.base.
  | DSBase = 0x703
  /// FS.base.
  | FSBase = 0x704
  /// ES.base.
  | GSBase = 0x705
  /// Control registers.
  | CR0 = 0x20800
  /// Control registers.
  | CR2 = 0x20802
  /// Control registers.
  | CR3 = 0x20803
  /// Control registers.
  | CR4 = 0x20804
  /// Control registers.
  | CR8 = 0x20808
  /// Debug registers.
  | DR0 = 0x900
  /// Debug registers.
  | DR1 = 0x901
  /// Debug registers.
  | DR2 = 0x902
  /// Debug registers.
  | DR3 = 0x903
  /// Debug registers.
  | DR6 = 0x906
  /// Debug registers.
  | DR7 = 0x907
  /// BND registers.
  | BND0 = 0x80A00
  /// BND registers.
  | BND1 = 0x80A01
  /// BND registers.
  | BND2 = 0x80A02
  /// BND registers.
  | BND3 = 0x80A03
  /// Overflow Flag in EFLAGS Register
  | OF = 0x1B00
  /// Direction Flag in EFLAGS Register
  | DF = 0x1B01
  /// Interrupt Enable Flag in EFLAGS Register
  | IF = 0x1B02
  /// Trap Flag in EFLAGS Register
  | TF = 0x1B03
  /// Sign Flag in EFLAGS Register
  | SF = 0x1B04
  /// Zero Flag in EFLAGS Register
  | ZF = 0x1B05
  /// Auxiliary Carry Flag in EFLAGS Register
  | AF = 0x1B06
  /// Parity Flag in EFLAGS Register
  | PF = 0x1B07
  /// Carry Flag in EFLAGS Register
  | CF = 0x1B08
  /// Protection-key features register.
  | PKRU = 0x20C00
  /// BND Register (lower 64bits BND0).
  | BND0A = 0x40D80
  /// BND Register (Higher 64bits BND0).
  | BND0B = 0x40D81
  /// BND Register (lower 64bits BND1).
  | BND1A = 0x40D82
  /// BND Register (Higher 64bits BND1).
  | BND1B = 0x40D83
  /// BND Register (lower 64bits BND2).
  | BND2A = 0x40D84
  /// BND Register (Higher 64bits BND2).
  | BND2B = 0x40D85
  /// BND Register (lower 64bits BND3).
  | BND3A = 0x40D86
  /// BND Register (Higher 64bits BND3).
  | BND3B = 0x40D87
  /// ST Register (lower 64bits ST0).
  | ST0A = 0x40D88
  /// ST Register (Higher 16bits ST0).
  | ST0B = 0x10D89
  /// ST Register (lower 64bits ST1).
  | ST1A = 0x40D8A
  /// ST Register (Higher 16bits ST1).
  | ST1B = 0x10D8B
  /// ST Register (lower 64bits ST2).
  | ST2A = 0x40D8C
  /// ST Register (Higher 16bits ST2).
  | ST2B = 0x10D8D
  /// ST Register (lower 64bits ST3).
  | ST3A = 0x40D8E
  /// ST Register (Higher 16bits ST3).
  | ST3B = 0x10D8F
  /// ST Register (lower 64bits ST4).
  | ST4A = 0x40D90
  /// ST Register (Higher 16bits ST4).
  | ST4B = 0x10D91
  /// ST Register (lower 64bits ST5).
  | ST5A = 0x40D92
  /// ST Register (Higher 16bits ST5).
  | ST5B = 0x10D93
  /// ST Register (lower 64bits ST6).
  | ST6A = 0x40D94
  /// ST Register (Higher 16bits ST6).
  | ST6B = 0x10D95
  /// ST Register (lower 64bits ST7).
  | ST7A = 0x40D96
  /// ST Register (Higher 16bits ST7).
  | ST7B = 0x10D97
  /// ZMM0A is the 1st 64-bit chunk of ZMM0.
  | ZMM0A = 0x40D00
  /// ZMM0B is the 2nd 64-bit chunk of ZMM0.
  | ZMM0B = 0x40D01
  /// ZMM0C is the 3rd 64-bit chunk of ZMM0.
  | ZMM0C = 0x40D02
  /// ZMM0D is the 4th 64-bit chunk of ZMM0.
  | ZMM0D = 0x40D03
  /// ZMM0E is the 5th 64-bit chunk of ZMM0.
  | ZMM0E = 0x40D04
  /// ZMM0F is the 6th 64-bit chunk of ZMM0.
  | ZMM0F = 0x40D05
  /// ZMM0G is the 7th 64-bit chunk of ZMM0.
  | ZMM0G = 0x40D06
  /// ZMM0H is the 8th 64-bit chunk of ZMM0.
  | ZMM0H = 0x40D07
  /// ZMM1A is the 1st 64-bit chunk of ZMM1.
  | ZMM1A = 0x40D08
  /// ZMM1B is the 2nd 64-bit chunk of ZMM1.
  | ZMM1B = 0x40D09
  /// ZMM1C is the 3rd 64-bit chunk of ZMM1.
  | ZMM1C = 0x40D0A
  /// ZMM1D is the 4th 64-bit chunk of ZMM1.
  | ZMM1D = 0x40D0B
  /// ZMM1E is the 5th 64-bit chunk of ZMM1.
  | ZMM1E = 0x40D0C
  /// ZMM1F is the 6th 64-bit chunk of ZMM1.
  | ZMM1F = 0x40D0D
  /// ZMM1G is the 7th 64-bit chunk of ZMM1.
  | ZMM1G = 0x40D0E
  /// ZMM1H is the 8th 64-bit chunk of ZMM1.
  | ZMM1H = 0x40D0F
  /// ZMM2A is the 1st 64-bit chunk of ZMM2.
  | ZMM2A = 0x40D10
  /// ZMM2B is the 2nd 64-bit chunk of ZMM2.
  | ZMM2B = 0x40D11
  /// ZMM2C is the 3rd 64-bit chunk of ZMM2.
  | ZMM2C = 0x40D12
  /// ZMM2D is the 4th 64-bit chunk of ZMM2.
  | ZMM2D = 0x40D13
  /// ZMM2E is the 5th 64-bit chunk of ZMM2.
  | ZMM2E = 0x40D14
  /// ZMM2F is the 6th 64-bit chunk of ZMM2.
  | ZMM2F = 0x40D15
  /// ZMM2G is the 7th 64-bit chunk of ZMM2.
  | ZMM2G = 0x40D16
  /// ZMM2H is the 8th 64-bit chunk of ZMM2.
  | ZMM2H = 0x40D17
  /// ZMM3A is the 1st 64-bit chunk of ZMM3.
  | ZMM3A = 0x40D18
  /// ZMM3B is the 2nd 64-bit chunk of ZMM3.
  | ZMM3B = 0x40D19
  /// ZMM3C is the 3rd 64-bit chunk of ZMM3.
  | ZMM3C = 0x40D1A
  /// ZMM3D is the 4th 64-bit chunk of ZMM3.
  | ZMM3D = 0x40D1B
  /// ZMM3E is the 5th 64-bit chunk of ZMM3.
  | ZMM3E = 0x40D1C
  /// ZMM3F is the 6th 64-bit chunk of ZMM3.
  | ZMM3F = 0x40D1D
  /// ZMM3G is the 7th 64-bit chunk of ZMM3.
  | ZMM3G = 0x40D1E
  /// ZMM3H is the 8th 64-bit chunk of ZMM3.
  | ZMM3H = 0x40D1F
  /// ZMM4A is the 1st 64-bit chunk of ZMM4.
  | ZMM4A = 0x40D20
  /// ZMM4B is the 2nd 64-bit chunk of ZMM4.
  | ZMM4B = 0x40D21
  /// ZMM4C is the 3rd 64-bit chunk of ZMM4.
  | ZMM4C = 0x40D22
  /// ZMM4D is the 4th 64-bit chunk of ZMM4.
  | ZMM4D = 0x40D23
  /// ZMM4E is the 5th 64-bit chunk of ZMM4.
  | ZMM4E = 0x40D24
  /// ZMM4F is the 6th 64-bit chunk of ZMM4.
  | ZMM4F = 0x40D25
  /// ZMM4G is the 7th 64-bit chunk of ZMM4.
  | ZMM4G = 0x40D26
  /// ZMM4H is the 8th 64-bit chunk of ZMM4.
  | ZMM4H = 0x40D27
  /// ZMM5A is the 1st 64-bit chunk of ZMM5.
  | ZMM5A = 0x40D28
  /// ZMM5B is the 2nd 64-bit chunk of ZMM5.
  | ZMM5B = 0x40D29
  /// ZMM5C is the 3rd 64-bit chunk of ZMM5.
  | ZMM5C = 0x40D2A
  /// ZMM5D is the 4th 64-bit chunk of ZMM5.
  | ZMM5D = 0x40D2B
  /// ZMM5E is the 5th 64-bit chunk of ZMM5.
  | ZMM5E = 0x40D2C
  /// ZMM5F is the 6th 64-bit chunk of ZMM5.
  | ZMM5F = 0x40D2D
  /// ZMM5G is the 7th 64-bit chunk of ZMM5.
  | ZMM5G = 0x40D2E
  /// ZMM5H is the 8th 64-bit chunk of ZMM5.
  | ZMM5H = 0x40D2F
  /// ZMM6A is the 1st 64-bit chunk of ZMM6.
  | ZMM6A = 0x40D30
  /// ZMM6B is the 2nd 64-bit chunk of ZMM6.
  | ZMM6B = 0x40D31
  /// ZMM6C is the 3rd 64-bit chunk of ZMM6.
  | ZMM6C = 0x40D32
  /// ZMM6D is the 4th 64-bit chunk of ZMM6.
  | ZMM6D = 0x40D33
  /// ZMM6E is the 5th 64-bit chunk of ZMM6.
  | ZMM6E = 0x40D34
  /// ZMM6F is the 6th 64-bit chunk of ZMM6.
  | ZMM6F = 0x40D35
  /// ZMM6G is the 7th 64-bit chunk of ZMM6.
  | ZMM6G = 0x40D36
  /// ZMM6H is the 8th 64-bit chunk of ZMM6.
  | ZMM6H = 0x40D37
  /// ZMM7A is the 1st 64-bit chunk of ZMM7.
  | ZMM7A = 0x40D38
  /// ZMM7B is the 2nd 64-bit chunk of ZMM7.
  | ZMM7B = 0x40D39
  /// ZMM7C is the 3rd 64-bit chunk of ZMM7.
  | ZMM7C = 0x40D3A
  /// ZMM7D is the 4th 64-bit chunk of ZMM7.
  | ZMM7D = 0x40D3B
  /// ZMM7E is the 5th 64-bit chunk of ZMM7.
  | ZMM7E = 0x40D3C
  /// ZMM7F is the 6th 64-bit chunk of ZMM7.
  | ZMM7F = 0x40D3D
  /// ZMM7G is the 7th 64-bit chunk of ZMM7.
  | ZMM7G = 0x40D3E
  /// ZMM7H is the 8th 64-bit chunk of ZMM7.
  | ZMM7H = 0x40D3F
  /// ZMM8A is the 1st 64-bit chunk of ZMM8.
  | ZMM8A = 0x40D40
  /// ZMM8B is the 2nd 64-bit chunk of ZMM8.
  | ZMM8B = 0x40D41
  /// ZMM8C is the 3rd 64-bit chunk of ZMM8.
  | ZMM8C = 0x40D42
  /// ZMM8D is the 4th 64-bit chunk of ZMM8.
  | ZMM8D = 0x40D43
  /// ZMM8E is the 5th 64-bit chunk of ZMM8.
  | ZMM8E = 0x40D44
  /// ZMM8F is the 6th 64-bit chunk of ZMM8.
  | ZMM8F = 0x40D45
  /// ZMM8G is the 7th 64-bit chunk of ZMM8.
  | ZMM8G = 0x40D46
  /// ZMM8H is the 8th 64-bit chunk of ZMM8.
  | ZMM8H = 0x40D47
  /// ZMM9A is the 1st 64-bit chunk of ZMM9.
  | ZMM9A = 0x40D48
  /// ZMM9B is the 2nd 64-bit chunk of ZMM9.
  | ZMM9B = 0x40D49
  /// ZMM9C is the 3rd 64-bit chunk of ZMM9.
  | ZMM9C = 0x40D4A
  /// ZMM9D is the 4th 64-bit chunk of ZMM9.
  | ZMM9D = 0x40D4B
  /// ZMM9E is the 5th 64-bit chunk of ZMM9.
  | ZMM9E = 0x40D4C
  /// ZMM9F is the 6th 64-bit chunk of ZMM9.
  | ZMM9F = 0x40D4D
  /// ZMM9G is the 7th 64-bit chunk of ZMM9.
  | ZMM9G = 0x40D4E
  /// ZMM9H is the 8th 64-bit chunk of ZMM9.
  | ZMM9H = 0x40D4F
  /// ZMM10A is the 1st 64-bit chunk of ZMM10.
  | ZMM10A = 0x40D50
  /// ZMM10B is the 2nd 64-bit chunk of ZMM10.
  | ZMM10B = 0x40D51
  /// ZMM10C is the 3rd 64-bit chunk of ZMM10.
  | ZMM10C = 0x40D52
  /// ZMM10D is the 4th 64-bit chunk of ZMM10.
  | ZMM10D = 0x40D53
  /// ZMM10E is the 5th 64-bit chunk of ZMM10.
  | ZMM10E = 0x40D54
  /// ZMM10F is the 6th 64-bit chunk of ZMM10.
  | ZMM10F = 0x40D55
  /// ZMM10G is the 7th 64-bit chunk of ZMM10.
  | ZMM10G = 0x40D56
  /// ZMM10H is the 8th 64-bit chunk of ZMM10.
  | ZMM10H = 0x40D57
  /// ZMM11A is the 1st 64-bit chunk of ZMM11.
  | ZMM11A = 0x40D58
  /// ZMM11B is the 2nd 64-bit chunk of ZMM11.
  | ZMM11B = 0x40D59
  /// ZMM11C is the 3rd 64-bit chunk of ZMM11.
  | ZMM11C = 0x40D5A
  /// ZMM11D is the 4th 64-bit chunk of ZMM11.
  | ZMM11D = 0x40D5B
  /// ZMM11E is the 5th 64-bit chunk of ZMM11.
  | ZMM11E = 0x40D5C
  /// ZMM11F is the 6th 64-bit chunk of ZMM11.
  | ZMM11F = 0x40D5D
  /// ZMM11G is the 7th 64-bit chunk of ZMM11.
  | ZMM11G = 0x40D5E
  /// ZMM11H is the 8th 64-bit chunk of ZMM11.
  | ZMM11H = 0x40D5F
  /// ZMM12A is the 1st 64-bit chunk of ZMM12.
  | ZMM12A = 0x40D60
  /// ZMM12B is the 2nd 64-bit chunk of ZMM12.
  | ZMM12B = 0x40D61
  /// ZMM12C is the 3rd 64-bit chunk of ZMM12.
  | ZMM12C = 0x40D62
  /// ZMM12D is the 4th 64-bit chunk of ZMM12.
  | ZMM12D = 0x40D63
  /// ZMM12E is the 5th 64-bit chunk of ZMM12.
  | ZMM12E = 0x40D64
  /// ZMM12F is the 6th 64-bit chunk of ZMM12.
  | ZMM12F = 0x40D65
  /// ZMM12G is the 7th 64-bit chunk of ZMM12.
  | ZMM12G = 0x40D66
  /// ZMM12H is the 8th 64-bit chunk of ZMM12.
  | ZMM12H = 0x40D67
  /// ZMM13A is the 1st 64-bit chunk of ZMM13.
  | ZMM13A = 0x40D68
  /// ZMM13B is the 2nd 64-bit chunk of ZMM13.
  | ZMM13B = 0x40D69
  /// ZMM13C is the 3rd 64-bit chunk of ZMM13.
  | ZMM13C = 0x40D6A
  /// ZMM13D is the 4th 64-bit chunk of ZMM13.
  | ZMM13D = 0x40D6B
  /// ZMM13E is the 5th 64-bit chunk of ZMM13.
  | ZMM13E = 0x40D6C
  /// ZMM13F is the 6th 64-bit chunk of ZMM13.
  | ZMM13F = 0x40D6D
  /// ZMM13G is the 7th 64-bit chunk of ZMM13.
  | ZMM13G = 0x40D6E
  /// ZMM13H is the 8th 64-bit chunk of ZMM13.
  | ZMM13H = 0x40D6F
  /// ZMM14A is the 1st 64-bit chunk of ZMM14.
  | ZMM14A = 0x40D70
  /// ZMM14B is the 2nd 64-bit chunk of ZMM14.
  | ZMM14B = 0x40D71
  /// ZMM14C is the 3rd 64-bit chunk of ZMM14.
  | ZMM14C = 0x40D72
  /// ZMM14D is the 4th 64-bit chunk of ZMM14.
  | ZMM14D = 0x40D73
  /// ZMM14E is the 5th 64-bit chunk of ZMM14.
  | ZMM14E = 0x40D74
  /// ZMM14F is the 6th 64-bit chunk of ZMM14.
  | ZMM14F = 0x40D75
  /// ZMM14G is the 7th 64-bit chunk of ZMM14.
  | ZMM14G = 0x40D76
  /// ZMM14H is the 8th 64-bit chunk of ZMM14.
  | ZMM14H = 0x40D77
  /// ZMM15A is the 1st 64-bit chunk of ZMM15.
  | ZMM15A = 0x40D78
  /// ZMM15B is the 2nd 64-bit chunk of ZMM15.
  | ZMM15B = 0x40D79
  /// ZMM15C is the 3rd 64-bit chunk of ZMM15.
  | ZMM15C = 0x40D7A
  /// ZMM15D is the 4th 64-bit chunk of ZMM15.
  | ZMM15D = 0x40D7B
  /// ZMM15E is the 5th 64-bit chunk of ZMM15.
  | ZMM15E = 0x40D7C
  /// ZMM15F is the 6th 64-bit chunk of ZMM15.
  | ZMM15F = 0x40D7D
  /// ZMM15G is the 7th 64-bit chunk of ZMM15.
  | ZMM15G = 0x40D7E
  /// ZMM15H is the 8th 64-bit chunk of ZMM15.
  | ZMM15H = 0x40D7F
  /// Opmask registers. For EVEX.
  | K0 = 0x40E00
  /// Opmask registers. For EVEX.
  | K1 = 0x40E01
  /// Opmask registers. For EVEX.
  | K2 = 0x40E02
  /// Opmask registers. For EVEX.
  | K3 = 0x40E03
  /// Opmask registers. For EVEX.
  | K4 = 0x40E04
  /// Opmask registers. For EVEX.
  | K5 = 0x40E05
  /// Opmask registers. For EVEX.
  | K6 = 0x40E06
  /// Opmask registers. For EVEX.
  | K7 = 0x40E07
  /// Unknown Register.
  | UnknownReg = 0xF00

/// Shortcut for Register type.
type internal R = Register

/// This module exposes several useful functions to handle Intel registers.
[<RequireQualifiedAccess>]
module Register = begin
  /// Intel register kind, which is based on their usage.
  type Kind =
    /// General purpose registers.
    | GP = 0x0
    /// Floating-point registers.
    | FPU = 0x1
    /// MMX registers.
    | MMX = 0x2
    /// XMM registers.
    | XMM = 0x3
    /// YMM registers.
    | YMM = 0x4
    /// ZMM registers.
    | ZMM = 0x5
    /// Segment registers.
    | Segment = 0x6
    /// Registers represeting a segment base.
    | SegBase = 0x7
    /// Control registers.
    | Control = 0x8
    /// Debug registers.
    | Debug = 0x9
    /// Bound registers.
    | Bound = 0xA
    /// Flags registers.
    | Flags = 0xB
    /// Unclassified registers.
    | Unclassified = 0xC
    /// PseudoRegisters are the ones that we create to ease handling AVX
    /// registers and operations. Each AVX register is divided into a series of
    /// 64-bit pseudoregisters, and we name each pseudoregister using a suffix
    /// character from 'A' to 'H'. For example, XMM0A refers to the first 64-bit
    /// chunk of XMM0.
    | PseudoRegister = 0xD
    /// OpMask registers of EVEX.
    | OpMaskRegister = 0xE

  let getKind (reg: Register): Kind =
    (int reg >>> 8) &&& 0b1111 |> LanguagePrimitives.EnumOfValue

  let make id (kind: Kind) size =
    (size <<< 12) ||| (int kind <<< 8) ||| id
    |> LanguagePrimitives.EnumOfValue<int, Register>

  let inline ofRegID (n: RegisterID): Register =
    int n |> LanguagePrimitives.EnumOfValue

  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  let inline getSize (reg: Register) =
    int reg >>> 12 |> RegType.fromBitWidth

  let ofString (str: string) =
    match str.ToLower () with
    | "rax" -> R.RAX
    | "rbx" -> R.RBX
    | "rcx" -> R.RCX
    | "rdx" -> R.RDX
    | "rsp" -> R.RSP
    | "rbp" -> R.RBP
    | "rsi" -> R.RSI
    | "rdi" -> R.RDI
    | "eax" -> R.EAX
    | "ebx" -> R.EBX
    | "ecx" -> R.ECX
    | "edx" -> R.EDX
    | "esp" -> R.ESP
    | "ebp" -> R.EBP
    | "esi" -> R.ESI
    | "edi" -> R.EDI
    | "ax" -> R.AX
    | "bx" -> R.BX
    | "cx" -> R.CX
    | "dx" -> R.DX
    | "sp" -> R.SP
    | "bp" -> R.BP
    | "si" -> R.SI
    | "di" -> R.DI
    | "al" -> R.AL
    | "bl" -> R.BL
    | "cl" -> R.CL
    | "dl" -> R.DL
    | "ah" -> R.AH
    | "bh" -> R.BH
    | "ch" -> R.CH
    | "dh" -> R.DH
    | "r8" -> R.R8
    | "r9" -> R.R9
    | "r10" -> R.R10
    | "r11" -> R.R11
    | "r12" -> R.R12
    | "r13" -> R.R13
    | "r14" -> R.R14
    | "r15" -> R.R15
    | "r8d" -> R.R8D
    | "r9d" -> R.R9D
    | "r10d" -> R.R10D
    | "r11d" -> R.R11D
    | "r12d" -> R.R12D
    | "r13d" -> R.R13D
    | "r14d" -> R.R14D
    | "r15d" -> R.R15D
    | "r8w" -> R.R8W
    | "r9w" -> R.R9W
    | "r10w" -> R.R10W
    | "r11w" -> R.R11W
    | "r12w" -> R.R12W
    | "r13w" -> R.R13W
    | "r14w" -> R.R14W
    | "r15w" -> R.R15W
    | "r8l" -> R.R8L
    | "r9l" -> R.R9L
    | "r10l" -> R.R10L
    | "r11l" -> R.R11L
    | "r12l" -> R.R12L
    | "r13l" -> R.R13L
    | "r14l" -> R.R14L
    | "r15l" -> R.R15L
    | "spl" -> R.SPL
    | "bpl" -> R.BPL
    | "sil" -> R.SIL
    | "dil" -> R.DIL
    | "eip" -> R.EIP
    | "rip" -> R.RIP
    | "st0" -> R.ST0
    | "st1" -> R.ST1
    | "st2" -> R.ST2
    | "st3" -> R.ST3
    | "st4" -> R.ST4
    | "st5" -> R.ST5
    | "st6" -> R.ST6
    | "st7" -> R.ST7
    | "mm0" -> R.MM0
    | "mm1" -> R.MM1
    | "mm2" -> R.MM2
    | "mm3" -> R.MM3
    | "mm4" -> R.MM4
    | "mm5" -> R.MM5
    | "mm6" -> R.MM6
    | "mm7" -> R.MM7
    | "xmm0" -> R.XMM0
    | "xmm1" -> R.XMM1
    | "xmm2" -> R.XMM2
    | "xmm3" -> R.XMM3
    | "xmm4" -> R.XMM4
    | "xmm5" -> R.XMM5
    | "xmm6" -> R.XMM6
    | "xmm7" -> R.XMM7
    | "xmm8" -> R.XMM8
    | "xmm9" -> R.XMM9
    | "xmm10" -> R.XMM10
    | "xmm11" -> R.XMM11
    | "xmm12" -> R.XMM12
    | "xmm13" -> R.XMM13
    | "xmm14" -> R.XMM14
    | "xmm15" -> R.XMM15
    | "ymm0" -> R.YMM0
    | "ymm1" -> R.YMM1
    | "ymm2" -> R.YMM2
    | "ymm3" -> R.YMM3
    | "ymm4" -> R.YMM4
    | "ymm5" -> R.YMM5
    | "ymm6" -> R.YMM6
    | "ymm7" -> R.YMM7
    | "ymm8" -> R.YMM8
    | "ymm9" -> R.YMM9
    | "ymm10" -> R.YMM10
    | "ymm11" -> R.YMM11
    | "ymm12" -> R.YMM12
    | "ymm13" -> R.YMM13
    | "ymm14" -> R.YMM14
    | "ymm15" -> R.YMM15
    | "zmm0" -> R.ZMM0
    | "zmm1" -> R.ZMM1
    | "zmm2" -> R.ZMM2
    | "zmm3" -> R.ZMM3
    | "zmm4" -> R.ZMM4
    | "zmm5" -> R.ZMM5
    | "zmm6" -> R.ZMM6
    | "zmm7" -> R.ZMM7
    | "zmm8" -> R.ZMM8
    | "zmm9" -> R.ZMM9
    | "zmm10" -> R.ZMM10
    | "zmm11" -> R.ZMM11
    | "zmm12" -> R.ZMM12
    | "zmm13" -> R.ZMM13
    | "zmm14" -> R.ZMM14
    | "zmm15" -> R.ZMM15
    | "es" -> R.ES
    | "cs" -> R.CS
    | "ss" -> R.SS
    | "ds" -> R.DS
    | "fs" -> R.FS
    | "gs" -> R.GS
    | "esbASE" -> R.ESBase
    | "csbASE" -> R.CSBase
    | "ssbASE" -> R.SSBase
    | "dsbASE" -> R.DSBase
    | "fsbASE" -> R.FSBase
    | "gsbASE" -> R.GSBase
    | "cr0" -> R.CR0
    | "cr2" -> R.CR2
    | "cr3" -> R.CR3
    | "cr4" -> R.CR4
    | "cr8" -> R.CR8
    | "dr0" -> R.DR0
    | "dr1" -> R.DR1
    | "dr2" -> R.DR2
    | "dr3" -> R.DR3
    | "dr6" -> R.DR6
    | "dr7" -> R.DR7
    | "bnd0" -> R.BND0
    | "bnd1" -> R.BND1
    | "bnd2" -> R.BND2
    | "bnd3" -> R.BND3
    | "of" -> R.OF
    | "df" -> R.DF
    | "if" -> R.IF
    | "tf" -> R.TF
    | "sf" -> R.SF
    | "zf" -> R.ZF
    | "af" -> R.AF
    | "pf" -> R.PF
    | "cf" -> R.CF
    | "fcw" -> R.FCW
    | "fsw" -> R.FSW
    | "ftw" -> R.FTW
    | "fop" -> R.FOP
    | "fip" -> R.FIP
    | "fcs" -> R.FCS
    | "fdp" -> R.FDP
    | "fds" -> R.FDS
    | "ftop" -> R.FTOP
    | "ftw0" -> R.FTW0
    | "ftw1" -> R.FTW1
    | "ftw2" -> R.FTW2
    | "ftw3" -> R.FTW3
    | "ftw4" -> R.FTW4
    | "ftw5" -> R.FTW5
    | "ftw6" -> R.FTW6
    | "ftw7" -> R.FTW7
    | "fswc0" -> R.FSWC0
    | "fswc1" -> R.FSWC1
    | "fswc2" -> R.FSWC2
    | "fswc3" -> R.FSWC3
    | "mxcsr" -> R.MXCSR
    | "mxcsrmask" -> R.MXCSRMASK
    | "pkru" -> R.PKRU
    | "bnd0a" -> R.BND0A
    | "bnd0b" -> R.BND0B
    | "bnd1a" -> R.BND1A
    | "bnd1b" -> R.BND1B
    | "bnd2a" -> R.BND2A
    | "bnd2b" -> R.BND2B
    | "bnd3a" -> R.BND3A
    | "bnd3b" -> R.BND3B
    | "st0a" -> R.ST0A
    | "st0b" -> R.ST0B
    | "st1a" -> R.ST1A
    | "st1b" -> R.ST1B
    | "st2a" -> R.ST2A
    | "st2b" -> R.ST2B
    | "st3a" -> R.ST3A
    | "st3b" -> R.ST3B
    | "st4a" -> R.ST4A
    | "st4b" -> R.ST4B
    | "st5a" -> R.ST5A
    | "st5b" -> R.ST5B
    | "st6a" -> R.ST6A
    | "st6b" -> R.ST6B
    | "st7a" -> R.ST7A
    | "st7b" -> R.ST7B
    | "zmm0a" -> R.ZMM0A
    | "zmm0b" -> R.ZMM0B
    | "zmm0c" -> R.ZMM0C
    | "zmm0d" -> R.ZMM0D
    | "zmm0e" -> R.ZMM0E
    | "zmm0f" -> R.ZMM0F
    | "zmm0g" -> R.ZMM0G
    | "zmm0h" -> R.ZMM0H
    | "zmm1a" -> R.ZMM1A
    | "zmm1b" -> R.ZMM1B
    | "zmm1c" -> R.ZMM1C
    | "zmm1d" -> R.ZMM1D
    | "zmm1e" -> R.ZMM1E
    | "zmm1f" -> R.ZMM1F
    | "zmm1g" -> R.ZMM1G
    | "zmm1h" -> R.ZMM1H
    | "zmm2a" -> R.ZMM2A
    | "zmm2b" -> R.ZMM2B
    | "zmm2c" -> R.ZMM2C
    | "zmm2d" -> R.ZMM2D
    | "zmm2e" -> R.ZMM2E
    | "zmm2f" -> R.ZMM2F
    | "zmm2g" -> R.ZMM2G
    | "zmm2h" -> R.ZMM2H
    | "zmm3a" -> R.ZMM3A
    | "zmm3b" -> R.ZMM3B
    | "zmm3c" -> R.ZMM3C
    | "zmm3d" -> R.ZMM3D
    | "zmm3e" -> R.ZMM3E
    | "zmm3f" -> R.ZMM3F
    | "zmm3g" -> R.ZMM3G
    | "zmm3h" -> R.ZMM3H
    | "zmm4a" -> R.ZMM4A
    | "zmm4b" -> R.ZMM4B
    | "zmm4c" -> R.ZMM4C
    | "zmm4d" -> R.ZMM4D
    | "zmm4e" -> R.ZMM4E
    | "zmm4f" -> R.ZMM4F
    | "zmm4g" -> R.ZMM4G
    | "zmm4h" -> R.ZMM4H
    | "zmm5a" -> R.ZMM5A
    | "zmm5b" -> R.ZMM5B
    | "zmm5c" -> R.ZMM5C
    | "zmm5d" -> R.ZMM5D
    | "zmm5e" -> R.ZMM5E
    | "zmm5f" -> R.ZMM5F
    | "zmm5g" -> R.ZMM5G
    | "zmm5h" -> R.ZMM5H
    | "zmm6a" -> R.ZMM6A
    | "zmm6b" -> R.ZMM6B
    | "zmm6c" -> R.ZMM6C
    | "zmm6d" -> R.ZMM6D
    | "zmm6e" -> R.ZMM6E
    | "zmm6f" -> R.ZMM6F
    | "zmm6g" -> R.ZMM6G
    | "zmm6h" -> R.ZMM6H
    | "zmm7a" -> R.ZMM7A
    | "zmm7b" -> R.ZMM7B
    | "zmm7c" -> R.ZMM7C
    | "zmm7d" -> R.ZMM7D
    | "zmm7e" -> R.ZMM7E
    | "zmm7f" -> R.ZMM7F
    | "zmm7g" -> R.ZMM7G
    | "zmm7h" -> R.ZMM7H
    | "zmm8a" -> R.ZMM8A
    | "zmm8b" -> R.ZMM8B
    | "zmm8c" -> R.ZMM8C
    | "zmm8d" -> R.ZMM8D
    | "zmm8e" -> R.ZMM8E
    | "zmm8f" -> R.ZMM8F
    | "zmm8g" -> R.ZMM8G
    | "zmm8h" -> R.ZMM8H
    | "zmm9a" -> R.ZMM9A
    | "zmm9b" -> R.ZMM9B
    | "zmm9c" -> R.ZMM9C
    | "zmm9d" -> R.ZMM9D
    | "zmm9e" -> R.ZMM9E
    | "zmm9f" -> R.ZMM9F
    | "zmm9g" -> R.ZMM9G
    | "zmm9h" -> R.ZMM9H
    | "zmm10a" -> R.ZMM10A
    | "zmm10b" -> R.ZMM10B
    | "zmm10c" -> R.ZMM10C
    | "zmm10d" -> R.ZMM10D
    | "zmm10e" -> R.ZMM10E
    | "zmm10f" -> R.ZMM10F
    | "zmm10g" -> R.ZMM10G
    | "zmm10h" -> R.ZMM10H
    | "zmm11a" -> R.ZMM11A
    | "zmm11b" -> R.ZMM11B
    | "zmm11c" -> R.ZMM11C
    | "zmm11d" -> R.ZMM11D
    | "zmm11e" -> R.ZMM11E
    | "zmm11f" -> R.ZMM11F
    | "zmm11g" -> R.ZMM11G
    | "zmm11h" -> R.ZMM11H
    | "zmm12a" -> R.ZMM12A
    | "zmm12b" -> R.ZMM12B
    | "zmm12c" -> R.ZMM12C
    | "zmm12d" -> R.ZMM12D
    | "zmm12e" -> R.ZMM12E
    | "zmm12f" -> R.ZMM12F
    | "zmm12g" -> R.ZMM12G
    | "zmm12h" -> R.ZMM12H
    | "zmm13a" -> R.ZMM13A
    | "zmm13b" -> R.ZMM13B
    | "zmm13c" -> R.ZMM13C
    | "zmm13d" -> R.ZMM13D
    | "zmm13e" -> R.ZMM13E
    | "zmm13f" -> R.ZMM13F
    | "zmm13g" -> R.ZMM13G
    | "zmm13h" -> R.ZMM13H
    | "zmm14a" -> R.ZMM14A
    | "zmm14b" -> R.ZMM14B
    | "zmm14c" -> R.ZMM14C
    | "zmm14d" -> R.ZMM14D
    | "zmm14e" -> R.ZMM14E
    | "zmm14f" -> R.ZMM14F
    | "zmm14g" -> R.ZMM14G
    | "zmm14h" -> R.ZMM14H
    | "zmm15a" -> R.ZMM15A
    | "zmm15b" -> R.ZMM15B
    | "zmm15c" -> R.ZMM15C
    | "zmm15d" -> R.ZMM15D
    | "zmm15e" -> R.ZMM15E
    | "zmm15f" -> R.ZMM15F
    | "zmm15g" -> R.ZMM15G
    | "zmm15h" -> R.ZMM15H
    | "k0" -> R.K0
    | "k1" -> R.K1
    | "k2" -> R.K2
    | "k3" -> R.K3
    | "k4" -> R.K4
    | "k5" -> R.K5
    | "k6" -> R.K6
    | "k7" -> R.K7
    | _ -> Utils.impossible ()

  let toString = function
    | R.RAX -> "RAX"
    | R.RBX -> "RBX"
    | R.RCX -> "RCX"
    | R.RDX -> "RDX"
    | R.RSP -> "RSP"
    | R.RBP -> "RBP"
    | R.RSI -> "RSI"
    | R.RDI -> "RDI"
    | R.EAX -> "EAX"
    | R.EBX -> "EBX"
    | R.ECX -> "ECX"
    | R.EDX -> "EDX"
    | R.ESP -> "ESP"
    | R.EBP -> "EBP"
    | R.ESI -> "ESI"
    | R.EDI -> "EDI"
    | R.AX -> "AX"
    | R.BX -> "BX"
    | R.CX -> "CX"
    | R.DX -> "DX"
    | R.SP -> "SP"
    | R.BP -> "BP"
    | R.SI -> "SI"
    | R.DI -> "DI"
    | R.AL -> "AL"
    | R.BL -> "BL"
    | R.CL -> "CL"
    | R.DL -> "DL"
    | R.AH -> "AH"
    | R.BH -> "BH"
    | R.CH -> "CH"
    | R.DH -> "DH"
    | R.R8 -> "R8"
    | R.R9 -> "R9"
    | R.R10 -> "R10"
    | R.R11 -> "R11"
    | R.R12 -> "R12"
    | R.R13 -> "R13"
    | R.R14 -> "R14"
    | R.R15 -> "R15"
    | R.R8D -> "R8D"
    | R.R9D -> "R9D"
    | R.R10D -> "R10D"
    | R.R11D -> "R11D"
    | R.R12D -> "R12D"
    | R.R13D -> "R13D"
    | R.R14D -> "R14D"
    | R.R15D -> "R15D"
    | R.R8W -> "R8W"
    | R.R9W -> "R9W"
    | R.R10W -> "R10W"
    | R.R11W -> "R11W"
    | R.R12W -> "R12W"
    | R.R13W -> "R13W"
    | R.R14W -> "R14W"
    | R.R15W -> "R15W"
    | R.R8L -> "R8L"
    | R.R9L -> "R9L"
    | R.R10L -> "R10L"
    | R.R11L -> "R11L"
    | R.R12L -> "R12L"
    | R.R13L -> "R13L"
    | R.R14L -> "R14L"
    | R.R15L -> "R15L"
    | R.SPL -> "SPL"
    | R.BPL -> "BPL"
    | R.SIL -> "SIL"
    | R.DIL -> "DIL"
    | R.EIP -> "EIP"
    | R.RIP -> "RIP"
    | R.ST0 -> "ST0"
    | R.ST1 -> "ST1"
    | R.ST2 -> "ST2"
    | R.ST3 -> "ST3"
    | R.ST4 -> "ST4"
    | R.ST5 -> "ST5"
    | R.ST6 -> "ST6"
    | R.ST7 -> "ST7"
    | R.FCW -> "FCW"
    | R.FSW -> "FSW"
    | R.FTW -> "FTW"
    | R.FOP -> "FOP"
    | R.FIP -> "FIP"
    | R.FCS -> "FCS"
    | R.FDP -> "FDP"
    | R.FDS -> "FDS"
    | R.FTOP -> "FTOP"
    | R.FTW0 -> "FTW0"
    | R.FTW1 -> "FTW1"
    | R.FTW2 -> "FTW2"
    | R.FTW3 -> "FTW3"
    | R.FTW4 -> "FTW4"
    | R.FTW5 -> "FTW5"
    | R.FTW6 -> "FTW6"
    | R.FTW7 -> "FTW7"
    | R.FSWC0 -> "FSWC0"
    | R.FSWC1 -> "FSWC1"
    | R.FSWC2 -> "FSWC2"
    | R.FSWC3 -> "FSWC3"
    | R.MXCSR -> "MXCSR"
    | R.MXCSRMASK -> "MXCSRMASK"
    | R.MM0 -> "MM0"
    | R.MM1 -> "MM1"
    | R.MM2 -> "MM2"
    | R.MM3 -> "MM3"
    | R.MM4 -> "MM4"
    | R.MM5 -> "MM5"
    | R.MM6 -> "MM6"
    | R.MM7 -> "MM7"
    | R.XMM0 -> "XMM0"
    | R.XMM1 -> "XMM1"
    | R.XMM2 -> "XMM2"
    | R.XMM3 -> "XMM3"
    | R.XMM4 -> "XMM4"
    | R.XMM5 -> "XMM5"
    | R.XMM6 -> "XMM6"
    | R.XMM7 -> "XMM7"
    | R.XMM8 -> "XMM8"
    | R.XMM9 -> "XMM9"
    | R.XMM10 -> "XMM10"
    | R.XMM11 -> "XMM11"
    | R.XMM12 -> "XMM12"
    | R.XMM13 -> "XMM13"
    | R.XMM14 -> "XMM14"
    | R.XMM15 -> "XMM15"
    | R.YMM0 -> "YMM0"
    | R.YMM1 -> "YMM1"
    | R.YMM2 -> "YMM2"
    | R.YMM3 -> "YMM3"
    | R.YMM4 -> "YMM4"
    | R.YMM5 -> "YMM5"
    | R.YMM6 -> "YMM6"
    | R.YMM7 -> "YMM7"
    | R.YMM8 -> "YMM8"
    | R.YMM9 -> "YMM9"
    | R.YMM10 -> "YMM10"
    | R.YMM11 -> "YMM11"
    | R.YMM12 -> "YMM12"
    | R.YMM13 -> "YMM13"
    | R.YMM14 -> "YMM14"
    | R.YMM15 -> "YMM15"
    | R.ZMM0 -> "ZMM0"
    | R.ZMM1 -> "ZMM1"
    | R.ZMM2 -> "ZMM2"
    | R.ZMM3 -> "ZMM3"
    | R.ZMM4 -> "ZMM4"
    | R.ZMM5 -> "ZMM5"
    | R.ZMM6 -> "ZMM6"
    | R.ZMM7 -> "ZMM7"
    | R.ZMM8 -> "ZMM8"
    | R.ZMM9 -> "ZMM9"
    | R.ZMM10 -> "ZMM10"
    | R.ZMM11 -> "ZMM11"
    | R.ZMM12 -> "ZMM12"
    | R.ZMM13 -> "ZMM13"
    | R.ZMM14 -> "ZMM14"
    | R.ZMM15 -> "ZMM15"
    | R.CS -> "CS"
    | R.DS -> "DS"
    | R.SS -> "SS"
    | R.ES -> "ES"
    | R.FS -> "FS"
    | R.GS -> "GS"
    | R.CSBase -> "CSBase"
    | R.DSBase -> "DSBase"
    | R.ESBase -> "ESBase"
    | R.FSBase -> "FSBase"
    | R.GSBase -> "GSBase"
    | R.SSBase -> "SSBase"
    | R.CR0 -> "CR0"
    | R.CR2 -> "CR2"
    | R.CR3 -> "CR3"
    | R.CR4 -> "CR4"
    | R.CR8 -> "CR8"
    | R.DR0 -> "DR0"
    | R.DR1 -> "DR1"
    | R.DR2 -> "DR2"
    | R.DR3 -> "DR3"
    | R.DR6 -> "DR6"
    | R.DR7 -> "DR7"
    | R.BND0 -> "BND0"
    | R.BND1 -> "BND1"
    | R.BND2 -> "BND2"
    | R.BND3 -> "BND3"
    | R.OF -> "OF"
    | R.DF -> "DF"
    | R.IF -> "IF"
    | R.TF -> "TF"
    | R.SF -> "SF"
    | R.ZF -> "ZF"
    | R.AF -> "AF"
    | R.PF -> "PF"
    | R.CF -> "CF"
    | R.ST0A -> "ST0A"
    | R.ST0B -> "ST0B"
    | R.ST1A -> "ST1A"
    | R.ST1B -> "ST1B"
    | R.ST2A -> "ST2A"
    | R.ST2B -> "ST2B"
    | R.ST3A -> "ST3A"
    | R.ST3B -> "ST3B"
    | R.ST4A -> "ST4A"
    | R.ST4B -> "ST4B"
    | R.ST5A -> "ST5A"
    | R.ST5B -> "ST5B"
    | R.ST6A -> "ST6A"
    | R.ST6B -> "ST6B"
    | R.ST7A -> "ST7A"
    | R.ST7B -> "ST7B"
    | R.ZMM0A -> "ZMM0A"
    | R.ZMM0B -> "ZMM0B"
    | R.ZMM0C -> "ZMM0C"
    | R.ZMM0D -> "ZMM0D"
    | R.ZMM0E -> "ZMM0E"
    | R.ZMM0F -> "ZMM0F"
    | R.ZMM0G -> "ZMM0G"
    | R.ZMM0H -> "ZMM0H"
    | R.ZMM1A -> "ZMM1A"
    | R.ZMM1B -> "ZMM1B"
    | R.ZMM1C -> "ZMM1C"
    | R.ZMM1D -> "ZMM1D"
    | R.ZMM1E -> "ZMM1E"
    | R.ZMM1F -> "ZMM1F"
    | R.ZMM1G -> "ZMM1G"
    | R.ZMM1H -> "ZMM1H"
    | R.ZMM2A -> "ZMM2A"
    | R.ZMM2B -> "ZMM2B"
    | R.ZMM2C -> "ZMM2C"
    | R.ZMM2D -> "ZMM2D"
    | R.ZMM2E -> "ZMM2E"
    | R.ZMM2F -> "ZMM2F"
    | R.ZMM2G -> "ZMM2G"
    | R.ZMM2H -> "ZMM2H"
    | R.ZMM3A -> "ZMM3A"
    | R.ZMM3B -> "ZMM3B"
    | R.ZMM3C -> "ZMM3C"
    | R.ZMM3D -> "ZMM3D"
    | R.ZMM3E -> "ZMM3E"
    | R.ZMM3F -> "ZMM3F"
    | R.ZMM3G -> "ZMM3G"
    | R.ZMM3H -> "ZMM3H"
    | R.ZMM4A -> "ZMM4A"
    | R.ZMM4B -> "ZMM4B"
    | R.ZMM4C -> "ZMM4C"
    | R.ZMM4D -> "ZMM4D"
    | R.ZMM4E -> "ZMM4E"
    | R.ZMM4F -> "ZMM4F"
    | R.ZMM4G -> "ZMM4G"
    | R.ZMM4H -> "ZMM4H"
    | R.ZMM5A -> "ZMM5A"
    | R.ZMM5B -> "ZMM5B"
    | R.ZMM5C -> "ZMM5C"
    | R.ZMM5D -> "ZMM5D"
    | R.ZMM5E -> "ZMM5E"
    | R.ZMM5F -> "ZMM5F"
    | R.ZMM5G -> "ZMM5G"
    | R.ZMM5H -> "ZMM5H"
    | R.ZMM6A -> "ZMM6A"
    | R.ZMM6B -> "ZMM6B"
    | R.ZMM6C -> "ZMM6C"
    | R.ZMM6D -> "ZMM6D"
    | R.ZMM6E -> "ZMM6E"
    | R.ZMM6F -> "ZMM6F"
    | R.ZMM6G -> "ZMM6G"
    | R.ZMM6H -> "ZMM6H"
    | R.ZMM7A -> "ZMM7A"
    | R.ZMM7B -> "ZMM7B"
    | R.ZMM7C -> "ZMM7C"
    | R.ZMM7D -> "ZMM7D"
    | R.ZMM7E -> "ZMM7E"
    | R.ZMM7F -> "ZMM7F"
    | R.ZMM7G -> "ZMM7G"
    | R.ZMM7H -> "ZMM7H"
    | R.ZMM8A -> "ZMM8A"
    | R.ZMM8B -> "ZMM8B"
    | R.ZMM8C -> "ZMM8C"
    | R.ZMM8D -> "ZMM8D"
    | R.ZMM8E -> "ZMM8E"
    | R.ZMM8F -> "ZMM8F"
    | R.ZMM8G -> "ZMM8G"
    | R.ZMM8H -> "ZMM8H"
    | R.ZMM9A -> "ZMM9A"
    | R.ZMM9B -> "ZMM9B"
    | R.ZMM9C -> "ZMM9C"
    | R.ZMM9D -> "ZMM9D"
    | R.ZMM9E -> "ZMM9E"
    | R.ZMM9F -> "ZMM9F"
    | R.ZMM9G -> "ZMM9G"
    | R.ZMM9H -> "ZMM9H"
    | R.ZMM10A -> "ZMM10A"
    | R.ZMM10B -> "ZMM10B"
    | R.ZMM10C -> "ZMM10C"
    | R.ZMM10D -> "ZMM10D"
    | R.ZMM10E -> "ZMM10E"
    | R.ZMM10F -> "ZMM10F"
    | R.ZMM10G -> "ZMM10G"
    | R.ZMM10H -> "ZMM10H"
    | R.ZMM11A -> "ZMM11A"
    | R.ZMM11B -> "ZMM11B"
    | R.ZMM11C -> "ZMM11C"
    | R.ZMM11D -> "ZMM11D"
    | R.ZMM11E -> "ZMM11E"
    | R.ZMM11F -> "ZMM11F"
    | R.ZMM11G -> "ZMM11G"
    | R.ZMM11H -> "ZMM11H"
    | R.ZMM12A -> "ZMM12A"
    | R.ZMM12B -> "ZMM12B"
    | R.ZMM12C -> "ZMM12C"
    | R.ZMM12D -> "ZMM12D"
    | R.ZMM12E -> "ZMM12E"
    | R.ZMM12F -> "ZMM12F"
    | R.ZMM12G -> "ZMM12G"
    | R.ZMM12H -> "ZMM12H"
    | R.ZMM13A -> "ZMM13A"
    | R.ZMM13B -> "ZMM13B"
    | R.ZMM13C -> "ZMM13C"
    | R.ZMM13D -> "ZMM13D"
    | R.ZMM13E -> "ZMM13E"
    | R.ZMM13F -> "ZMM13F"
    | R.ZMM13G -> "ZMM13G"
    | R.ZMM13H -> "ZMM13H"
    | R.ZMM14A -> "ZMM14A"
    | R.ZMM14B -> "ZMM14B"
    | R.ZMM14C -> "ZMM14C"
    | R.ZMM14D -> "ZMM14D"
    | R.ZMM14E -> "ZMM14E"
    | R.ZMM14F -> "ZMM14F"
    | R.ZMM14G -> "ZMM14G"
    | R.ZMM14H -> "ZMM14H"
    | R.ZMM15A -> "ZMM15A"
    | R.ZMM15B -> "ZMM15B"
    | R.ZMM15C -> "ZMM15C"
    | R.ZMM15D -> "ZMM15D"
    | R.ZMM15E -> "ZMM15E"
    | R.ZMM15F -> "ZMM15F"
    | R.ZMM15G -> "ZMM15G"
    | R.ZMM15H -> "ZMM15H"
    | R.K0 -> "K0"
    | R.K1 -> "K1"
    | R.K2 -> "K2"
    | R.K3 -> "K3"
    | R.K4 -> "K4"
    | R.K5 -> "K5"
    | R.K6 -> "K6"
    | R.K7 -> "K7"
    | R.PKRU -> "PKRU"
#if DEBUG
    | _ -> Utils.impossible ()
#else
    | _ -> "?"
#endif

  let toRegType = function
    | R.MM0 | R.MM1 | R.MM2 | R.MM3 | R.MM4 | R.MM5 | R.MM6 | R.MM7
    | R.ST0A | R.ST1A | R.ST2A | R.ST3A | R.ST4A | R.ST5A | R.ST6A | R.ST7A
    | R.RIP | R.R8 | R.R9 | R.R10 | R.R11 | R.R12 | R.R13 | R.R14 | R.R15
    | R.RAX | R.RBX | R.RCX | R.RDX | R.RSP | R.RBP | R.RSI | R.RDI
    | R.FIP | R.FDP -> 64<rt>
    | R.R8D | R.R9D | R.R10D | R.R11D
    | R.R12D | R.R13D | R.R14D | R.R15D
    | R.EAX | R.EBX | R.ECX | R.EDX
    | R.ESP | R.EBP | R.ESI | R.EDI | R.EIP | R.PKRU
    | R.MXCSR | R.MXCSRMASK -> 32<rt>
    | R.R8W | R.R9W | R.R10W | R.R11W
    | R.R12W | R.R13W | R.R14W | R.R15W
    | R.ST0B | R.ST1B | R.ST2B | R.ST3B | R.ST4B | R.ST5B | R.ST6B | R.ST7B
    | R.ES | R.CS | R.SS | R.DS | R.FS | R.GS
    | R.AX | R.BX | R.CX | R.DX | R.SP | R.BP | R.SI | R.DI
    | R.FCW | R.FSW | R.FTW | R.FOP | R.FCS | R.FDS
    | R.K0 | R.K1 | R.K2 | R.K3 | R.K4 | R.K5 | R.K6 | R.K7 -> 16<rt>
    | R.R8L | R.R9L | R.R10L | R.R11L
    | R.R12L | R.R13L | R.R14L | R.R15L
    | R.SPL | R.BPL | R.SIL | R.DIL
    | R.AL | R.BL | R.CL | R.DL | R.AH | R.BH | R.CH | R.DH -> 8<rt>
    | R.XMM0 | R.XMM1 | R.XMM2 | R.XMM3
    | R.XMM4 | R.XMM5 | R.XMM6 | R.XMM7
    | R.XMM8 | R.XMM9 | R.XMM10 | R.XMM11
    | R.XMM12 | R.XMM13 | R.XMM14 | R.XMM15
    | R.BND0 | R.BND1 | R.BND2 | R.BND3 -> 128<rt>
    | R.ZMM0A | R.ZMM1A | R.ZMM2A | R.ZMM3A
    | R.ZMM4A | R.ZMM5A | R.ZMM6A | R.ZMM7A
    | R.ZMM8A | R.ZMM9A | R.ZMM10A | R.ZMM11A
    | R.ZMM12A | R.ZMM13A | R.ZMM14A | R.ZMM15A
    | R.ZMM0B | R.ZMM1B | R.ZMM2B | R.ZMM3B
    | R.ZMM4B | R.ZMM5B | R.ZMM6B | R.ZMM7B
    | R.ZMM8B | R.ZMM9B | R.ZMM10B | R.ZMM11B
    | R.ZMM12B | R.ZMM13B | R.ZMM14B | R.ZMM15B
    | R.YMM0 | R.YMM1 | R.YMM2 | R.YMM3
    | R.YMM4 | R.YMM5 | R.YMM6 | R.YMM7
    | R.YMM8 | R.YMM9 | R.YMM10 | R.YMM11
    | R.YMM12 | R.YMM13 | R.YMM14 | R.YMM15 -> 256<rt>
    | R.ZMM0 | R.ZMM1 | R.ZMM2 | R.ZMM3
    | R.ZMM4 | R.ZMM5 | R.ZMM6 | R.ZMM7
    | R.ZMM8 | R.ZMM9 | R.ZMM10 | R.ZMM11
    | R.ZMM12 | R.ZMM13 | R.ZMM14 | R.ZMM15 -> 512<rt>
    | R.ST0 | R.ST1 | R.ST2 | R.ST3 | R.ST4 | R.ST5 | R.ST6 | R.ST7 -> 80<rt>
    | R.DF | R.CF | R.PF | R.AF | R.ZF | R.SF | R.OF | R.IF
    | R.FSWC0 | R.FSWC1 | R.FSWC2 | R.FSWC3 -> 1<rt>
    | R.FTW0 | R.FTW1 | R.FTW2 | R.FTW3
    | R.FTW4 | R.FTW5 | R.FTW6 | R.FTW7 -> 2<rt>
    | R.FTOP -> 3<rt>
    | _ -> raise UnknownRegException

  let extendRegister32 = function
    | R.EAX | R.AX | R.AL | R.AH -> R.EAX
    | R.EBX | R.BX | R.BL | R.BH -> R.EBX
    | R.ECX | R.CX | R.CL | R.CH -> R.ECX
    | R.EDX | R.DX | R.DL | R.DH -> R.EDX
    | R.ESP | R.SP | R.SPL -> R.ESP
    | R.EBP | R.BP | R.BPL -> R.EBP
    | R.ESI | R.SI | R.SIL -> R.ESI
    | R.EDI | R.DI | R.DIL -> R.EDI
    | R.XMM0 | R.YMM0 | R.ZMM0 -> R.YMM0
    | R.XMM1 | R.YMM1 | R.ZMM1 -> R.YMM1
    | R.XMM2 | R.YMM2 | R.ZMM2 -> R.YMM2
    | R.XMM3 | R.YMM3 | R.ZMM3 -> R.YMM3
    | R.XMM4 | R.YMM4 | R.ZMM4 -> R.YMM4
    | R.XMM5 | R.YMM5 | R.ZMM5 -> R.YMM5
    | R.XMM6 | R.YMM6 | R.ZMM6 -> R.YMM6
    | R.XMM7 | R.YMM7 | R.ZMM7 -> R.YMM7
    | R.DF | R.CF | R.PF | R.AF | R.ZF | R.SF | R.OF
    | R.BND0 | R.BND1 | R.BND2 | R.BND3 as e -> e
    | R.ESBase | R.ES -> R.ESBase
    | R.CSBase | R.CS -> R.CSBase
    | R.SSBase | R.SS -> R.SSBase
    | R.DSBase | R.DS -> R.DSBase
    | R.FSBase | R.FS -> R.FSBase
    | R.GSBase | R.GS -> R.GSBase
    | R.EIP -> R.EIP
    | e -> e

  let extendRegister64 = function
    | R.RAX | R.EAX | R.AX | R.AL | R.AH -> R.RAX
    | R.RBX | R.EBX | R.BX | R.BL | R.BH -> R.RBX
    | R.RCX | R.ECX | R.CX | R.CL | R.CH -> R.RCX
    | R.RDX | R.EDX | R.DX | R.DL | R.DH -> R.RDX
    | R.RSP | R.ESP | R.SP | R.SPL -> R.RSP
    | R.RBP | R.EBP | R.BP | R.BPL -> R.RBP
    | R.RSI | R.ESI | R.SI | R.SIL -> R.RSI
    | R.RDI | R.EDI | R.DI | R.DIL-> R.RDI
    | R.R8  | R.R8D | R.R8L | R.R8W -> R.R8
    | R.R9  | R.R9D | R.R9L | R.R9W -> R.R9
    | R.R10 | R.R10D | R.R10L | R.R10W -> R.R10
    | R.R11 | R.R11D | R.R11L | R.R11W -> R.R11
    | R.R12 | R.R12D | R.R12L | R.R12W -> R.R12
    | R.R13 | R.R13D | R.R13L | R.R13W -> R.R13
    | R.R14 | R.R14D | R.R14L | R.R14W -> R.R14
    | R.R15 | R.R15D | R.R15L | R.R15W -> R.R15
    | R.XMM0 | R.YMM0 | R.ZMM0 -> R.YMM0
    | R.XMM1 | R.YMM1 | R.ZMM1 -> R.YMM1
    | R.XMM2 | R.YMM2 | R.ZMM2 -> R.YMM2
    | R.XMM3 | R.YMM3 | R.ZMM3 -> R.YMM3
    | R.XMM4 | R.YMM4 | R.ZMM4 -> R.YMM4
    | R.XMM5 | R.YMM5 | R.ZMM5 -> R.YMM5
    | R.XMM6 | R.YMM6 | R.ZMM6 -> R.YMM6
    | R.XMM7 | R.YMM7 | R.ZMM7 -> R.YMM7
    | R.XMM8 | R.YMM8 | R.ZMM8 -> R.YMM8
    | R.XMM9 | R.YMM9 | R.ZMM9 -> R.YMM9
    | R.XMM10 | R.YMM10 | R.ZMM10 -> R.YMM10
    | R.XMM11 | R.YMM11 | R.ZMM11 -> R.YMM11
    | R.XMM12 | R.YMM12 | R.ZMM12 -> R.YMM12
    | R.XMM13 | R.YMM13 | R.ZMM13 -> R.YMM13
    | R.XMM14 | R.YMM14 | R.ZMM14 -> R.YMM14
    | R.XMM15 | R.YMM15 | R.ZMM15 -> R.YMM15
    | R.DF | R.CF | R.PF | R.AF | R.ZF | R.SF | R.OF
    | R.BND0 | R.BND1 | R.BND2 | R.BND3 as e -> e
    | R.ESBase | R.ES -> R.ESBase
    | R.CSBase | R.CS -> R.CSBase
    | R.SSBase | R.SS -> R.SSBase
    | R.DSBase | R.DS -> R.DSBase
    | R.FSBase | R.FS -> R.FSBase
    | R.GSBase | R.GS -> R.GSBase
    | R.RIP | R.EIP -> R.RIP
    | e -> e

  let getAliases = function
    | R.RAX | R.EAX | R.AX | R.AL | R.AH -> [| R.RAX; R.EAX; R.AX; R.AL; R.AH |]
    | R.RBX | R.EBX | R.BX | R.BL | R.BH -> [| R.RBX; R.EBX; R.BX; R.BL; R.BH |]
    | R.RCX | R.ECX | R.CX | R.CL | R.CH -> [| R.RCX; R.ECX; R.CX; R.CL; R.CH |]
    | R.RDX | R.EDX | R.DX | R.DL | R.DH -> [| R.RDX; R.EDX; R.DX; R.DL; R.DH |]
    | R.RSP | R.ESP | R.SP | R.SPL -> [| R.RSP; R.ESP; R.SP; R.SPL |]
    | R.RBP | R.EBP | R.BP | R.BPL -> [| R.RBP; R.EBP; R.BP; R.BPL |]
    | R.RSI | R.ESI | R.SI | R.SIL -> [| R.RSI; R.ESI; R.SI; R.SIL |]
    | R.RDI | R.EDI | R.DI | R.DIL -> [| R.RDI; R.EDI; R.DI; R.DIL |]
    | R.R8  | R.R8D | R.R8L | R.R8W -> [| R.R8; R.R8D; R.R8L; R.R8W |]
    | R.R9  | R.R9D | R.R9L | R.R9W -> [| R.R9; R.R9D; R.R9L; R.R9W |]
    | R.R10  | R.R10D | R.R10L | R.R10W -> [| R.R10; R.R10D; R.R10L; R.R10W |]
    | R.R11  | R.R11D | R.R11L | R.R11W -> [| R.R11; R.R11D; R.R11L; R.R11W |]
    | R.R12  | R.R12D | R.R12L | R.R12W -> [| R.R12; R.R12D; R.R12L; R.R12W |]
    | R.R13  | R.R13D | R.R13L | R.R13W -> [| R.R13; R.R13D; R.R13L; R.R13W |]
    | R.R14  | R.R14D | R.R14L | R.R14W -> [| R.R14; R.R14D; R.R14L; R.R14W |]
    | R.R15  | R.R15D | R.R15L | R.R15W -> [| R.R15; R.R15D; R.R15L; R.R15W |]
    | R.XMM0 | R.YMM0 | R.ZMM0 -> [| R.XMM0; R.YMM0; R.ZMM0 |]
    | R.XMM1 | R.YMM1 | R.ZMM1 -> [| R.XMM1; R.YMM1; R.ZMM1 |]
    | R.XMM2 | R.YMM2 | R.ZMM2 -> [| R.XMM2; R.YMM2; R.ZMM2 |]
    | R.XMM3 | R.YMM3 | R.ZMM3 -> [| R.XMM3; R.YMM3; R.ZMM3 |]
    | R.XMM4 | R.YMM4 | R.ZMM4 -> [| R.XMM4; R.YMM4; R.ZMM4 |]
    | R.XMM5 | R.YMM5 | R.ZMM5 -> [| R.XMM5; R.YMM5; R.ZMM5 |]
    | R.XMM6 | R.YMM6 | R.ZMM6 -> [| R.XMM6; R.YMM6; R.ZMM6 |]
    | R.XMM7 | R.YMM7 | R.ZMM7 -> [| R.XMM7; R.YMM7; R.ZMM7 |]
    | R.XMM8 | R.YMM8 | R.ZMM8 -> [| R.XMM8; R.YMM8; R.ZMM8 |]
    | R.XMM9 | R.YMM9 | R.ZMM9 -> [| R.XMM9; R.YMM9; R.ZMM9 |]
    | R.XMM10 | R.YMM10 | R.ZMM10 -> [| R.XMM10; R.YMM10; R.ZMM10 |]
    | R.XMM11 | R.YMM11 | R.ZMM11 -> [| R.XMM11; R.YMM11; R.ZMM11 |]
    | R.XMM12 | R.YMM12 | R.ZMM12 -> [| R.XMM12; R.YMM12; R.ZMM12 |]
    | R.XMM13 | R.YMM13 | R.ZMM13 -> [| R.XMM13; R.YMM13; R.ZMM13 |]
    | R.XMM14 | R.YMM14 | R.ZMM14 -> [| R.XMM14; R.YMM14; R.ZMM14 |]
    | R.XMM15 | R.YMM15 | R.ZMM15 -> [| R.XMM15; R.YMM15; R.ZMM15 |]
    | R.EIP | R.RIP -> [| R.EIP; R.RIP |]
    | r -> [| r |]

  let regToPseudoReg = function
    | R.XMM0  -> [ R.ZMM0B; R.ZMM0A ]
    | R.XMM1  -> [ R.ZMM1B; R.ZMM1A ]
    | R.XMM2  -> [ R.ZMM2B; R.ZMM2A ]
    | R.XMM3  -> [ R.ZMM3B; R.ZMM3A ]
    | R.XMM4  -> [ R.ZMM4B; R.ZMM4A ]
    | R.XMM5  -> [ R.ZMM5B; R.ZMM5A ]
    | R.XMM6  -> [ R.ZMM6B; R.ZMM6A ]
    | R.XMM7  -> [ R.ZMM7B; R.ZMM7A ]
    | R.XMM8  -> [ R.ZMM8B; R.ZMM8A ]
    | R.XMM9  -> [ R.ZMM9B; R.ZMM9A ]
    | R.XMM10 -> [ R.ZMM10B; R.ZMM10A ]
    | R.XMM11 -> [ R.ZMM11B; R.ZMM11A ]
    | R.XMM12 -> [ R.ZMM12B; R.ZMM12A ]
    | R.XMM13 -> [ R.ZMM13B; R.ZMM13A ]
    | R.XMM14 -> [ R.ZMM14B; R.ZMM14A ]
    | R.XMM15 -> [ R.ZMM15B; R.ZMM15A ]
    | R.YMM0  -> [ R.ZMM0D; R.ZMM0C; R.ZMM0B; R.ZMM0A ]
    | R.YMM1  -> [ R.ZMM1D; R.ZMM1C; R.ZMM1B; R.ZMM1A ]
    | R.YMM2  -> [ R.ZMM2D; R.ZMM2C; R.ZMM2B; R.ZMM2A ]
    | R.YMM3  -> [ R.ZMM3D; R.ZMM3C; R.ZMM3B; R.ZMM3A ]
    | R.YMM4  -> [ R.ZMM4D; R.ZMM4C; R.ZMM4B; R.ZMM4A ]
    | R.YMM5  -> [ R.ZMM5D; R.ZMM5C; R.ZMM5B; R.ZMM5A ]
    | R.YMM6  -> [ R.ZMM6D; R.ZMM6C; R.ZMM6B; R.ZMM6A ]
    | R.YMM7  -> [ R.ZMM7D; R.ZMM7C; R.ZMM7B; R.ZMM7A ]
    | R.YMM8  -> [ R.ZMM8D; R.ZMM8C; R.ZMM8B; R.ZMM8A ]
    | R.YMM9  -> [ R.ZMM9D; R.ZMM9C; R.ZMM9B; R.ZMM9A ]
    | R.YMM10 -> [ R.ZMM10D; R.ZMM10C; R.ZMM10B; R.ZMM10A ]
    | R.YMM11 -> [ R.ZMM11D; R.ZMM11C; R.ZMM11B; R.ZMM11A ]
    | R.YMM12 -> [ R.ZMM12D; R.ZMM12C; R.ZMM12B; R.ZMM12A ]
    | R.YMM13 -> [ R.ZMM13D; R.ZMM13C; R.ZMM13B; R.ZMM13A ]
    | R.YMM14 -> [ R.ZMM14D; R.ZMM14C; R.ZMM14B; R.ZMM14A ]
    | R.YMM15 -> [ R.ZMM15D; R.ZMM15C; R.ZMM15B; R.ZMM15A ]
    | R.ST0 -> [ R.ST0B; R.ST0A ]
    | R.ST1 -> [ R.ST1B; R.ST1A ]
    | R.ST2 -> [ R.ST2B; R.ST2A ]
    | R.ST3 -> [ R.ST3B; R.ST3A ]
    | R.ST4 -> [ R.ST4B; R.ST4A ]
    | R.ST5 -> [ R.ST5B; R.ST5A ]
    | R.ST6 -> [ R.ST6B; R.ST6A ]
    | R.ST7 -> [ R.ST7B; R.ST7A ]
    | R.MM0 -> [ R.ST0A ]
    | R.MM1 -> [ R.ST1A ]
    | R.MM2 -> [ R.ST2A ]
    | R.MM3 -> [ R.ST3A ]
    | R.MM4 -> [ R.ST4A ]
    | R.MM5 -> [ R.ST5A ]
    | R.MM6 -> [ R.ST6A ]
    | R.MM7 -> [ R.ST7A ]
    | e -> failwithf "Unhandled register: %A" e

  let pseudoRegToReg = function
    | R.ZMM0A
    | R.ZMM0B
    | R.ZMM0C
    | R.ZMM0D
    | R.ZMM0E
    | R.ZMM0F
    | R.ZMM0G
    | R.ZMM0H -> R.ZMM0
    | R.ZMM1A
    | R.ZMM1B
    | R.ZMM1C
    | R.ZMM1D
    | R.ZMM1E
    | R.ZMM1F
    | R.ZMM1G
    | R.ZMM1H -> R.ZMM1
    | R.ZMM2A
    | R.ZMM2B
    | R.ZMM2C
    | R.ZMM2D
    | R.ZMM2E
    | R.ZMM2F
    | R.ZMM2G
    | R.ZMM2H -> R.ZMM2
    | R.ZMM3A
    | R.ZMM3B
    | R.ZMM3C
    | R.ZMM3D
    | R.ZMM3E
    | R.ZMM3F
    | R.ZMM3G
    | R.ZMM3H -> R.ZMM3
    | R.ZMM4A
    | R.ZMM4B
    | R.ZMM4C
    | R.ZMM4D
    | R.ZMM4E
    | R.ZMM4F
    | R.ZMM4G
    | R.ZMM4H -> R.ZMM4
    | R.ZMM5A
    | R.ZMM5B
    | R.ZMM5C
    | R.ZMM5D
    | R.ZMM5E
    | R.ZMM5F
    | R.ZMM5G
    | R.ZMM5H -> R.ZMM5
    | R.ZMM6A
    | R.ZMM6B
    | R.ZMM6C
    | R.ZMM6D
    | R.ZMM6E
    | R.ZMM6F
    | R.ZMM6G
    | R.ZMM6H -> R.ZMM6
    | R.ZMM7A
    | R.ZMM7B
    | R.ZMM7C
    | R.ZMM7D
    | R.ZMM7E
    | R.ZMM7F
    | R.ZMM7G
    | R.ZMM7H -> R.ZMM7
    | R.ZMM8A
    | R.ZMM8B
    | R.ZMM8C
    | R.ZMM8D
    | R.ZMM8E
    | R.ZMM8F
    | R.ZMM8G
    | R.ZMM8H -> R.ZMM8
    | R.ZMM9A
    | R.ZMM9B
    | R.ZMM9C
    | R.ZMM9D
    | R.ZMM9E
    | R.ZMM9F
    | R.ZMM9G
    | R.ZMM9H -> R.ZMM9
    | R.ZMM10A
    | R.ZMM10B
    | R.ZMM10C
    | R.ZMM10D
    | R.ZMM10E
    | R.ZMM10F
    | R.ZMM10G
    | R.ZMM10H -> R.ZMM10
    | R.ZMM11A
    | R.ZMM11B
    | R.ZMM11C
    | R.ZMM11D
    | R.ZMM11E
    | R.ZMM11F
    | R.ZMM11G
    | R.ZMM11H -> R.ZMM11
    | R.ZMM12A
    | R.ZMM12B
    | R.ZMM12C
    | R.ZMM12D
    | R.ZMM12E
    | R.ZMM12F
    | R.ZMM12G
    | R.ZMM12H -> R.ZMM12
    | R.ZMM13A
    | R.ZMM13B
    | R.ZMM13C
    | R.ZMM13D
    | R.ZMM13E
    | R.ZMM13F
    | R.ZMM13G
    | R.ZMM13H -> R.ZMM13
    | R.ZMM14A
    | R.ZMM14B
    | R.ZMM14C
    | R.ZMM14D
    | R.ZMM14E
    | R.ZMM14F
    | R.ZMM14G
    | R.ZMM14H -> R.ZMM14
    | R.ZMM15A
    | R.ZMM15B
    | R.ZMM15C
    | R.ZMM15D
    | R.ZMM15E
    | R.ZMM15F
    | R.ZMM15G
    | R.ZMM15H -> R.ZMM15
    | R.ST0A | R.ST0B -> R.ST0
    | R.ST1A | R.ST1B -> R.ST1
    | R.ST2A | R.ST2B -> R.ST2
    | R.ST3A | R.ST3B -> R.ST3
    | R.ST4A | R.ST4B -> R.ST4
    | R.ST5A | R.ST5B -> R.ST5
    | R.ST6A | R.ST6B -> R.ST6
    | R.ST7A | R.ST7B -> R.ST7
    | e -> failwithf "Unhandled register: %A" e
end

/// This module defines sets of registers that are frequently grouped by Intel.
/// Table 3-1. Register Codes Associated With +rb, +rw, +rd, +ro
module internal RegGroup = begin
  /// Grp 0.
  let grpEAX = function
    | 64<rt> -> R.RAX
    | 32<rt> -> R.EAX
    | 16<rt> -> R.AX
    | 8<rt> -> R.AL
    | 128<rt> -> R.XMM0
    | 256<rt> -> R.YMM0
    | 512<rt> -> R.ZMM0
    | _ -> Utils.impossible ()

  /// Grp 1.
  let grpECX = function
    | 64<rt> -> R.RCX
    | 32<rt> -> R.ECX
    | 16<rt> -> R.CX
    | 8<rt> -> R.CL
    | 128<rt> -> R.XMM1
    | 256<rt> -> R.YMM1
    | 512<rt> -> R.ZMM1
    | _ -> Utils.impossible ()

  /// Grp 2.
  let grpEDX = function
    | 64<rt> -> R.RDX
    | 32<rt> -> R.EDX
    | 16<rt> -> R.DX
    | 8<rt> -> R.DL
    | 128<rt> -> R.XMM2
    | 256<rt> -> R.YMM2
    | 512<rt> -> R.ZMM2
    | _ -> Utils.impossible ()

  /// Grp 3.
  let grpEBX = function
    | 64<rt> -> R.RBX
    | 32<rt> -> R.EBX
    | 16<rt> -> R.BX
    | 8<rt> -> R.BL
    | 128<rt> -> R.XMM3
    | 256<rt> -> R.YMM3
    | 512<rt> -> R.ZMM3
    | _ -> Utils.impossible ()
end
