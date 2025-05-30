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

namespace B2R2.FrontEnd.Intel

open B2R2

/// <summary>
/// Represents registers for Intel x86 and x86-64.<para/>
/// </summary>
type Register =
  /// Accumulator for operands and results data (64bit).
  | RAX = 0x0
  /// TCounter for string and loop operations (64bit).
  | RCX = 0x1
  /// I/O pointer (64bit).
  | RDX = 0x2
  /// Pointer to data in the DS segment (64bit).
  | RBX = 0x3
  /// Stack pointer (in the SS segment) (64bit).
  | RSP = 0x4
  /// Pointer to data on the stack (in the SS segment) (64bit).
  | RBP = 0x5
  /// Pointer to data in the segment pointed to by the DS register (64bit).
  | RSI = 0x6
  /// Pointer to data in the segment pointed to by the ES register (64bit).
  | RDI = 0x7
  /// General-Purpose Registers for 64bit Mode.
  | R8 = 0x8
  /// General-Purpose Registers for 64bit Mode.
  | R9 = 0x9
  /// General-Purpose Registers for 64bit Mode.
  | R10 = 0xA
  /// General-Purpose Registers for 64bit Mode.
  | R11 = 0xB
  /// General-Purpose Registers for 64bit Mode.
  | R12 = 0xC
  /// General-Purpose Registers for 64bit Mode.
  | R13 = 0xD
  /// General-Purpose Registers for 64bit Mode.
  | R14 = 0xE
  /// General-Purpose Registers for 64bit Mode.
  | R15 = 0xF
  /// Accumulator for operands and results data (32bit).
  | EAX = 0x10
  /// TCounter for string and loop operations (32bit).
  | ECX = 0x11
  /// I/O pointer (32bit).
  | EDX = 0x12
  /// Pointer to data in the DS segment (32bit).
  | EBX = 0x13
  /// Stack pointer (in the SS segment) (32bit).
  | ESP = 0x14
  /// Pointer to data on the stack (in the SS segment) (32bit).
  | EBP = 0x15
  /// Pointer to data in the segment pointed to by the DS register (32bit).
  | ESI = 0x16
  /// Pointer to data in the segment pointed to by the ES register (32bit).
  | EDI = 0x17
  /// General-Purpose Registers for 64bit Mode (Doubleword Register).
  | R8D = 0x18
  /// General-Purpose Registers for 64bit Mode (Doubleword Register).
  | R9D = 0x19
  /// General-Purpose Registers for 64bit Mode (Doubleword Register).
  | R10D = 0x1A
  /// General-Purpose Registers for 64bit Mode (Doubleword Register).
  | R11D = 0x1B
  /// General-Purpose Registers for 64bit Mode (Doubleword Register).
  | R12D = 0x1C
  /// General-Purpose Registers for 64bit Mode (Doubleword Register).
  | R13D = 0x1D
  /// General-Purpose Registers for 64bit Mode (Doubleword Register).
  | R14D = 0x1E
  /// General-Purpose Registers for 64bit Mode (Doubleword Register).
  | R15D = 0x1F
  /// General-Purpose Registers (lower 16bits EAX).
  | AX = 0x20
  /// General-Purpose Registers (lower 16bits ECX).
  | CX = 0x21
  /// General-Purpose Registers (lower 16bits EDX).
  | DX = 0x22
  /// General-Purpose Registers (lower 16bits EBX).
  | BX = 0x23
  /// General-Purpose Registers (lower 16bits ESP).
  | SP = 0x24
  /// General-Purpose Registers (lower 16bits EBP).
  | BP = 0x25
  /// General-Purpose Registers (lower 16bits ESI).
  | SI = 0x26
  /// General-Purpose Registers (lower 16bits EDI).
  | DI = 0x27
  /// General-Purpose Registers for 64bit Mode (Word Register).
  | R8W = 0x28
  /// General-Purpose Registers for 64bit Mode (Word Register).
  | R9W = 0x29
  /// General-Purpose Registers for 64bit Mode (Word Register).
  | R10W = 0x2A
  /// General-Purpose Registers for 64bit Mode (Word Register).
  | R11W = 0x2B
  /// General-Purpose Registers for 64bit Mode (Word Register).
  | R12W = 0x2C
  /// General-Purpose Registers for 64bit Mode (Word Register).
  | R13W = 0x2D
  /// General-Purpose Registers for 64bit Mode (Word Register).
  | R14W = 0x2E
  /// General-Purpose Registers for 64bit Mode (Word Register).
  | R15W = 0x2F
  /// General-Purpose Registers (lower 8bits AX).
  | AL = 0x30
  /// General-Purpose Registers (lower 8bits CX).
  | CL = 0x31
  /// General-Purpose Registers (lower 8bits DX).
  | DL = 0x32
  /// General-Purpose Registers (lower 8bits BX).
  | BL = 0x33
  /// General-Purpose Registers (Higher 8bits AX).
  | AH = 0x34
  /// General-Purpose Registers (Higher 8bits CX).
  | CH = 0x35
  /// General-Purpose Registers (Higher 8bits DX).
  | DH = 0x36
  /// General-Purpose Registers (Higher 8bits BX).
  | BH = 0x37
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | R8B = 0x38
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | R9B = 0x39
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | R10B = 0x3A
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | R11B = 0x3B
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | R12B = 0x3C
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | R13B = 0x3D
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | R14B = 0x3E
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | R15B = 0x3F
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | SPL = 0x40
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | BPL = 0x41
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | SIL = 0x42
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | DIL = 0x43
  /// Instruction Pointer (32Bit).
  | EIP = 0x44
  /// Instruction Pointer (64Bit).
  | RIP = 0x45
  /// x87 FPU registers.
  | ST0 = 0x46
  /// x87 FPU registers.
  | ST1 = 0x47
  /// x87 FPU registers.
  | ST2 = 0x48
  /// x87 FPU registers.
  | ST3 = 0x49
  /// x87 FPU registers.
  | ST4 = 0x4A
  /// x87 FPU registers.
  | ST5 = 0x4B
  /// x87 FPU registers.
  | ST6 = 0x4C
  /// x87 FPU registers.
  | ST7 = 0x4D
  /// C87 FPU Control Word.
  | FCW = 0x4E
  /// x87 FPU Status Word.
  | FSW = 0x4F
  /// x87 FPU Tag Word.
  | FTW = 0x50
  /// x87 FPU Opcode.
  | FOP = 0x51
  /// x87 FPU Instruction Pointer Offset.
  | FIP = 0x52
  /// x87 FPU Instruction Pointer Selector.
  | FCS = 0x53
  /// x87 FPU Data Pointer Offset.
  | FDP = 0x54
  /// x87 FPU Data Pointer Selector.
  | FDS = 0x55
  /// x87 FPU Top indicator bits of Status Word.
  | FTOP = 0x56
  /// x87 FPU Tag word section.
  | FTW0 = 0x57
  /// x87 FPU Tag word section.
  | FTW1 = 0x58
  /// x87 FPU Tag word section.
  | FTW2 = 0x59
  /// x87 FPU Tag word section.
  | FTW3 = 0x5A
  /// x87 FPU Tag word section.
  | FTW4 = 0x5B
  /// x87 FPU Tag word section.
  | FTW5 = 0x5C
  /// x87 FPU Tag word section.
  | FTW6 = 0x5D
  /// x87 FPU Tag word section.
  | FTW7 = 0x5E
  /// x87 FPU Status Word C flag.
  | FSWC0 = 0x5F
  /// x87 FPU Status Word C flag.
  | FSWC1 = 0x60
  /// x87 FPU Status Word C flag.
  | FSWC2 = 0x61
  /// x87 FPU Status Word C flag.
  | FSWC3 = 0x62
  /// MXCSR Control and Status Register.
  | MXCSR = 0x63
  /// MXCSR_MASK.
  | MXCSRMASK = 0x64
  /// MMX registers.
  | MM0 = 0x65
  /// MMX registers.
  | MM1 = 0x66
  /// MMX registers.
  | MM2 = 0x67
  /// MMX registers.
  | MM3 = 0x68
  /// MMX registers.
  | MM4 = 0x69
  /// MMX registers.
  | MM5 = 0x6A
  /// MMX registers.
  | MM6 = 0x6B
  /// MMX registers.
  | MM7 = 0x6C
  /// XMM registers.
  | XMM0 = 0x6D
  /// XMM registers.
  | XMM1 = 0x6E
  /// XMM registers.
  | XMM2 = 0x6F
  /// XMM registers.
  | XMM3 = 0x70
  /// XMM registers.
  | XMM4 = 0x71
  /// XMM registers.
  | XMM5 = 0x72
  /// XMM registers.
  | XMM6 = 0x73
  /// XMM registers.
  | XMM7 = 0x74
  /// XMM registers.
  | XMM8 = 0x75
  /// XMM registers.
  | XMM9 = 0x76
  /// XMM registers.
  | XMM10 = 0x77
  /// XMM registers.
  | XMM11 = 0x78
  /// XMM registers.
  | XMM12 = 0x79
  /// XMM registers.
  | XMM13 = 0x7A
  /// XMM registers.
  | XMM14 = 0x7B
  /// XMM registers.
  | XMM15 = 0x7C
  /// 256-bit vector registers.
  | YMM0 = 0x7D
  /// 256-bit vector registers.
  | YMM1 = 0x7E
  /// 256-bit vector registers.
  | YMM2 = 0x7F
  /// 256-bit vector registers.
  | YMM3 = 0x80
  /// 256-bit vector registers.
  | YMM4 = 0x81
  /// 256-bit vector registers.
  | YMM5 = 0x82
  /// 256-bit vector registers.
  | YMM6 = 0x83
  /// 256-bit vector registers.
  | YMM7 = 0x84
  /// 256-bit vector registers.
  | YMM8 = 0x85
  /// 256-bit vector registers.
  | YMM9 = 0x86
  /// 256-bit vector registers.
  | YMM10 = 0x87
  /// 256-bit vector registers.
  | YMM11 = 0x88
  /// 256-bit vector registers.
  | YMM12 = 0x89
  /// 256-bit vector registers.
  | YMM13 = 0x8A
  /// 256-bit vector registers.
  | YMM14 = 0x8B
  /// 256-bit vector registers.
  | YMM15 = 0x8C
  /// 512-bit vector registers.
  | ZMM0 = 0x8D
  /// 512-bit vector registers.
  | ZMM1 = 0x8E
  /// 512-bit vector registers.
  | ZMM2 = 0x8F
  /// 512-bit vector registers.
  | ZMM3 = 0x90
  /// 512-bit vector registers.
  | ZMM4 = 0x91
  /// 512-bit vector registers.
  | ZMM5 = 0x92
  /// 512-bit vector registers.
  | ZMM6 = 0x93
  /// 512-bit vector registers.
  | ZMM7 = 0x94
  /// 512-bit vector registers.
  | ZMM8 = 0x95
  /// 512-bit vector registers.
  | ZMM9 = 0x96
  /// 512-bit vector registers.
  | ZMM10 = 0x97
  /// 512-bit vector registers.
  | ZMM11 = 0x98
  /// 512-bit vector registers.
  | ZMM12 = 0x99
  /// 512-bit vector registers.
  | ZMM13 = 0x9A
  /// 512-bit vector registers.
  | ZMM14 = 0x9B
  /// 512-bit vector registers.
  | ZMM15 = 0x9C
  /// Segment registers.
  | ES = 0x9D
  /// Segment registers.
  | CS = 0x9E
  /// Segment registers.
  | SS = 0x9F
  /// Segment registers.
  | DS = 0xA0
  /// Segment registers.
  | FS = 0xA1
  /// Segment registers.
  | GS = 0xA2
  /// ES.base.
  | ESBase = 0xA3
  /// CS.base.
  | CSBase = 0xA4
  /// SS.base.
  | SSBase = 0xA5
  /// DS.base.
  | DSBase = 0xA6
  /// FS.base.
  | FSBase = 0xA7
  /// GS.base.
  | GSBase = 0xA8
  /// Control registers.
  | CR0 = 0xA9
  /// Control registers.
  | CR2 = 0xAA
  /// Control registers.
  | CR3 = 0xAB
  /// Control registers.
  | CR4 = 0xAC
  /// Control registers.
  | CR8 = 0xAD
  /// Debug registers.
  | DR0 = 0xAE
  /// Debug registers.
  | DR1 = 0xAF
  /// Debug registers.
  | DR2 = 0xB0
  /// Debug registers.
  | DR3 = 0xB1
  /// Debug registers.
  | DR6 = 0xB2
  /// Debug registers.
  | DR7 = 0xB3
  /// BND registers.
  | BND0 = 0xB4
  /// BND registers.
  | BND1 = 0xB5
  /// BND registers.
  | BND2 = 0xB6
  /// BND registers.
  | BND3 = 0xB7
  /// Overflow Flag in EFLAGS Register
  | OF = 0xB8
  /// Direction Flag in EFLAGS Register
  | DF = 0xB9
  /// Interrupt Enable Flag in EFLAGS Register
  | IF = 0xBA
  /// Trap Flag in EFLAGS Register
  | TF = 0xBB
  /// Sign Flag in EFLAGS Register
  | SF = 0xBC
  /// Zero Flag in EFLAGS Register
  | ZF = 0xBD
  /// Auxiliary Carry Flag in EFLAGS Register
  | AF = 0xBE
  /// Parity Flag in EFLAGS Register
  | PF = 0xBF
  /// Carry Flag in EFLAGS Register
  | CF = 0xC0
  /// Protection-key features register.
  | PKRU = 0xC1
  /// BND Register (lower 64bits BND0).
  | BND0A = 0xC2
  /// BND Register (Higher 64bits BND0).
  | BND0B = 0xC3
  /// BND Register (lower 64bits BND1).
  | BND1A = 0xC4
  /// BND Register (Higher 64bits BND1).
  | BND1B = 0xC5
  /// BND Register (lower 64bits BND2).
  | BND2A = 0xC6
  /// BND Register (Higher 64bits BND2).
  | BND2B = 0xC7
  /// BND Register (lower 64bits BND3).
  | BND3A = 0xC8
  /// BND Register (Higher 64bits BND3).
  | BND3B = 0xC9
  /// ST Register (lower 64bits ST0).
  | ST0A = 0xCA
  /// ST Register (Higher 16bits ST0).
  | ST0B = 0xCB
  /// ST Register (lower 64bits ST1).
  | ST1A = 0xCC
  /// ST Register (Higher 16bits ST1).
  | ST1B = 0xCD
  /// ST Register (lower 64bits ST2).
  | ST2A = 0xCE
  /// ST Register (Higher 16bits ST2).
  | ST2B = 0xCF
  /// ST Register (lower 64bits ST3).
  | ST3A = 0xD0
  /// ST Register (Higher 16bits ST3).
  | ST3B = 0xD1
  /// ST Register (lower 64bits ST4).
  | ST4A = 0xD2
  /// ST Register (Higher 16bits ST4).
  | ST4B = 0xD3
  /// ST Register (lower 64bits ST5).
  | ST5A = 0xD4
  /// ST Register (Higher 16bits ST5).
  | ST5B = 0xD5
  /// ST Register (lower 64bits ST6).
  | ST6A = 0xD6
  /// ST Register (Higher 16bits ST6).
  | ST6B = 0xD7
  /// ST Register (lower 64bits ST7).
  | ST7A = 0xD8
  /// ST Register (Higher 16bits ST7).
  | ST7B = 0xD9
  /// ZMM0A is the 1st 64-bit chunk of ZMM0.
  | ZMM0A = 0xDA
  /// ZMM0B is the 2nd 64-bit chunk of ZMM0.
  | ZMM0B = 0xDB
  /// ZMM0C is the 3rd 64-bit chunk of ZMM0.
  | ZMM0C = 0xDC
  /// ZMM0D is the 4th 64-bit chunk of ZMM0.
  | ZMM0D = 0xDD
  /// ZMM0E is the 5th 64-bit chunk of ZMM0.
  | ZMM0E = 0xDE
  /// ZMM0F is the 6th 64-bit chunk of ZMM0.
  | ZMM0F = 0xDF
  /// ZMM0G is the 7th 64-bit chunk of ZMM0.
  | ZMM0G = 0xE0
  /// ZMM0H is the 8th 64-bit chunk of ZMM0.
  | ZMM0H = 0xE1
  /// ZMM1A is the 1st 64-bit chunk of ZMM1.
  | ZMM1A = 0xE2
  /// ZMM1B is the 2nd 64-bit chunk of ZMM1.
  | ZMM1B = 0xE3
  /// ZMM1C is the 3rd 64-bit chunk of ZMM1.
  | ZMM1C = 0xE4
  /// ZMM1D is the 4th 64-bit chunk of ZMM1.
  | ZMM1D = 0xE5
  /// ZMM1E is the 5th 64-bit chunk of ZMM1.
  | ZMM1E = 0xE6
  /// ZMM1F is the 6th 64-bit chunk of ZMM1.
  | ZMM1F = 0xE7
  /// ZMM1G is the 7th 64-bit chunk of ZMM1.
  | ZMM1G = 0xE8
  /// ZMM1H is the 8th 64-bit chunk of ZMM1.
  | ZMM1H = 0xE9
  /// ZMM2A is the 1st 64-bit chunk of ZMM2.
  | ZMM2A = 0xEA
  /// ZMM2B is the 2nd 64-bit chunk of ZMM2.
  | ZMM2B = 0xEB
  /// ZMM2C is the 3rd 64-bit chunk of ZMM2.
  | ZMM2C = 0xEC
  /// ZMM2D is the 4th 64-bit chunk of ZMM2.
  | ZMM2D = 0xED
  /// ZMM2E is the 5th 64-bit chunk of ZMM2.
  | ZMM2E = 0xEE
  /// ZMM2F is the 6th 64-bit chunk of ZMM2.
  | ZMM2F = 0xEF
  /// ZMM2G is the 7th 64-bit chunk of ZMM2.
  | ZMM2G = 0xF0
  /// ZMM2H is the 8th 64-bit chunk of ZMM2.
  | ZMM2H = 0xF1
  /// ZMM3A is the 1st 64-bit chunk of ZMM3.
  | ZMM3A = 0xF2
  /// ZMM3B is the 2nd 64-bit chunk of ZMM3.
  | ZMM3B = 0xF3
  /// ZMM3C is the 3rd 64-bit chunk of ZMM3.
  | ZMM3C = 0xF4
  /// ZMM3D is the 4th 64-bit chunk of ZMM3.
  | ZMM3D = 0xF5
  /// ZMM3E is the 5th 64-bit chunk of ZMM3.
  | ZMM3E = 0xF6
  /// ZMM3F is the 6th 64-bit chunk of ZMM3.
  | ZMM3F = 0xF7
  /// ZMM3G is the 7th 64-bit chunk of ZMM3.
  | ZMM3G = 0xF8
  /// ZMM3H is the 8th 64-bit chunk of ZMM3.
  | ZMM3H = 0xF9
  /// ZMM4A is the 1st 64-bit chunk of ZMM4.
  | ZMM4A = 0xFA
  /// ZMM4B is the 2nd 64-bit chunk of ZMM4.
  | ZMM4B = 0xFB
  /// ZMM4C is the 3rd 64-bit chunk of ZMM4.
  | ZMM4C = 0xFC
  /// ZMM4D is the 4th 64-bit chunk of ZMM4.
  | ZMM4D = 0xFD
  /// ZMM4E is the 5th 64-bit chunk of ZMM4.
  | ZMM4E = 0xFE
  /// ZMM4F is the 6th 64-bit chunk of ZMM4.
  | ZMM4F = 0xFF
  /// ZMM4G is the 7th 64-bit chunk of ZMM4.
  | ZMM4G = 0x100
  /// ZMM4H is the 8th 64-bit chunk of ZMM4.
  | ZMM4H = 0x101
  /// ZMM5A is the 1st 64-bit chunk of ZMM5.
  | ZMM5A = 0x102
  /// ZMM5B is the 2nd 64-bit chunk of ZMM5.
  | ZMM5B = 0x103
  /// ZMM5C is the 3rd 64-bit chunk of ZMM5.
  | ZMM5C = 0x104
  /// ZMM5D is the 4th 64-bit chunk of ZMM5.
  | ZMM5D = 0x105
  /// ZMM5E is the 5th 64-bit chunk of ZMM5.
  | ZMM5E = 0x106
  /// ZMM5F is the 6th 64-bit chunk of ZMM5.
  | ZMM5F = 0x107
  /// ZMM5G is the 7th 64-bit chunk of ZMM5.
  | ZMM5G = 0x108
  /// ZMM5H is the 8th 64-bit chunk of ZMM5.
  | ZMM5H = 0x109
  /// ZMM6A is the 1st 64-bit chunk of ZMM6.
  | ZMM6A = 0x10A
  /// ZMM6B is the 2nd 64-bit chunk of ZMM6.
  | ZMM6B = 0x10B
  /// ZMM6C is the 3rd 64-bit chunk of ZMM6.
  | ZMM6C = 0x10C
  /// ZMM6D is the 4th 64-bit chunk of ZMM6.
  | ZMM6D = 0x10D
  /// ZMM6E is the 5th 64-bit chunk of ZMM6.
  | ZMM6E = 0x10E
  /// ZMM6F is the 6th 64-bit chunk of ZMM6.
  | ZMM6F = 0x10F
  /// ZMM6G is the 7th 64-bit chunk of ZMM6.
  | ZMM6G = 0x110
  /// ZMM6H is the 8th 64-bit chunk of ZMM6.
  | ZMM6H = 0x111
  /// ZMM7A is the 1st 64-bit chunk of ZMM7.
  | ZMM7A = 0x112
  /// ZMM7B is the 2nd 64-bit chunk of ZMM7.
  | ZMM7B = 0x113
  /// ZMM7C is the 3rd 64-bit chunk of ZMM7.
  | ZMM7C = 0x114
  /// ZMM7D is the 4th 64-bit chunk of ZMM7.
  | ZMM7D = 0x115
  /// ZMM7E is the 5th 64-bit chunk of ZMM7.
  | ZMM7E = 0x116
  /// ZMM7F is the 6th 64-bit chunk of ZMM7.
  | ZMM7F = 0x117
  /// ZMM7G is the 7th 64-bit chunk of ZMM7.
  | ZMM7G = 0x118
  /// ZMM7H is the 8th 64-bit chunk of ZMM7.
  | ZMM7H = 0x119
  /// ZMM8A is the 1st 64-bit chunk of ZMM8.
  | ZMM8A = 0x11A
  /// ZMM8B is the 2nd 64-bit chunk of ZMM8.
  | ZMM8B = 0x11B
  /// ZMM8C is the 3rd 64-bit chunk of ZMM8.
  | ZMM8C = 0x11C
  /// ZMM8D is the 4th 64-bit chunk of ZMM8.
  | ZMM8D = 0x11D
  /// ZMM8E is the 5th 64-bit chunk of ZMM8.
  | ZMM8E = 0x11E
  /// ZMM8F is the 6th 64-bit chunk of ZMM8.
  | ZMM8F = 0x11F
  /// ZMM8G is the 7th 64-bit chunk of ZMM8.
  | ZMM8G = 0x120
  /// ZMM8H is the 8th 64-bit chunk of ZMM8.
  | ZMM8H = 0x121
  /// ZMM9A is the 1st 64-bit chunk of ZMM9.
  | ZMM9A = 0x122
  /// ZMM9B is the 2nd 64-bit chunk of ZMM9.
  | ZMM9B = 0x123
  /// ZMM9C is the 3rd 64-bit chunk of ZMM9.
  | ZMM9C = 0x124
  /// ZMM9D is the 4th 64-bit chunk of ZMM9.
  | ZMM9D = 0x125
  /// ZMM9E is the 5th 64-bit chunk of ZMM9.
  | ZMM9E = 0x126
  /// ZMM9F is the 6th 64-bit chunk of ZMM9.
  | ZMM9F = 0x127
  /// ZMM9G is the 7th 64-bit chunk of ZMM9.
  | ZMM9G = 0x128
  /// ZMM9H is the 8th 64-bit chunk of ZMM9.
  | ZMM9H = 0x129
  /// ZMM10A is the 1st 64-bit chunk of ZMM10.
  | ZMM10A = 0x12A
  /// ZMM10B is the 2nd 64-bit chunk of ZMM10.
  | ZMM10B = 0x12B
  /// ZMM10C is the 3rd 64-bit chunk of ZMM10.
  | ZMM10C = 0x12C
  /// ZMM10D is the 4th 64-bit chunk of ZMM10.
  | ZMM10D = 0x12D
  /// ZMM10E is the 5th 64-bit chunk of ZMM10.
  | ZMM10E = 0x12E
  /// ZMM10F is the 6th 64-bit chunk of ZMM10.
  | ZMM10F = 0x12F
  /// ZMM10G is the 7th 64-bit chunk of ZMM10.
  | ZMM10G = 0x130
  /// ZMM10H is the 8th 64-bit chunk of ZMM10.
  | ZMM10H = 0x131
  /// ZMM11A is the 1st 64-bit chunk of ZMM11.
  | ZMM11A = 0x132
  /// ZMM11B is the 2nd 64-bit chunk of ZMM11.
  | ZMM11B = 0x133
  /// ZMM11C is the 3rd 64-bit chunk of ZMM11.
  | ZMM11C = 0x134
  /// ZMM11D is the 4th 64-bit chunk of ZMM11.
  | ZMM11D = 0x135
  /// ZMM11E is the 5th 64-bit chunk of ZMM11.
  | ZMM11E = 0x136
  /// ZMM11F is the 6th 64-bit chunk of ZMM11.
  | ZMM11F = 0x137
  /// ZMM11G is the 7th 64-bit chunk of ZMM11.
  | ZMM11G = 0x138
  /// ZMM11H is the 8th 64-bit chunk of ZMM11.
  | ZMM11H = 0x139
  /// ZMM12A is the 1st 64-bit chunk of ZMM12.
  | ZMM12A = 0x13A
  /// ZMM12B is the 2nd 64-bit chunk of ZMM12.
  | ZMM12B = 0x13B
  /// ZMM12C is the 3rd 64-bit chunk of ZMM12.
  | ZMM12C = 0x13C
  /// ZMM12D is the 4th 64-bit chunk of ZMM12.
  | ZMM12D = 0x13D
  /// ZMM12E is the 5th 64-bit chunk of ZMM12.
  | ZMM12E = 0x13E
  /// ZMM12F is the 6th 64-bit chunk of ZMM12.
  | ZMM12F = 0x13F
  /// ZMM12G is the 7th 64-bit chunk of ZMM12.
  | ZMM12G = 0x140
  /// ZMM12H is the 8th 64-bit chunk of ZMM12.
  | ZMM12H = 0x141
  /// ZMM13A is the 1st 64-bit chunk of ZMM13.
  | ZMM13A = 0x142
  /// ZMM13B is the 2nd 64-bit chunk of ZMM13.
  | ZMM13B = 0x143
  /// ZMM13C is the 3rd 64-bit chunk of ZMM13.
  | ZMM13C = 0x144
  /// ZMM13D is the 4th 64-bit chunk of ZMM13.
  | ZMM13D = 0x145
  /// ZMM13E is the 5th 64-bit chunk of ZMM13.
  | ZMM13E = 0x146
  /// ZMM13F is the 6th 64-bit chunk of ZMM13.
  | ZMM13F = 0x147
  /// ZMM13G is the 7th 64-bit chunk of ZMM13.
  | ZMM13G = 0x148
  /// ZMM13H is the 8th 64-bit chunk of ZMM13.
  | ZMM13H = 0x149
  /// ZMM14A is the 1st 64-bit chunk of ZMM14.
  | ZMM14A = 0x14A
  /// ZMM14B is the 2nd 64-bit chunk of ZMM14.
  | ZMM14B = 0x14B
  /// ZMM14C is the 3rd 64-bit chunk of ZMM14.
  | ZMM14C = 0x14C
  /// ZMM14D is the 4th 64-bit chunk of ZMM14.
  | ZMM14D = 0x14D
  /// ZMM14E is the 5th 64-bit chunk of ZMM14.
  | ZMM14E = 0x14E
  /// ZMM14F is the 6th 64-bit chunk of ZMM14.
  | ZMM14F = 0x14F
  /// ZMM14G is the 7th 64-bit chunk of ZMM14.
  | ZMM14G = 0x150
  /// ZMM14H is the 8th 64-bit chunk of ZMM14.
  | ZMM14H = 0x151
  /// ZMM15A is the 1st 64-bit chunk of ZMM15.
  | ZMM15A = 0x152
  /// ZMM15B is the 2nd 64-bit chunk of ZMM15.
  | ZMM15B = 0x153
  /// ZMM15C is the 3rd 64-bit chunk of ZMM15.
  | ZMM15C = 0x154
  /// ZMM15D is the 4th 64-bit chunk of ZMM15.
  | ZMM15D = 0x155
  /// ZMM15E is the 5th 64-bit chunk of ZMM15.
  | ZMM15E = 0x156
  /// ZMM15F is the 6th 64-bit chunk of ZMM15.
  | ZMM15F = 0x157
  /// ZMM15G is the 7th 64-bit chunk of ZMM15.
  | ZMM15G = 0x158
  /// ZMM15H is the 8th 64-bit chunk of ZMM15.
  | ZMM15H = 0x159
  /// Opmask registers. For EVEX.
  | K0 = 0x15A
  /// Opmask registers. For EVEX.
  | K1 = 0x15B
  /// Opmask registers. For EVEX.
  | K2 = 0x15C
  /// Opmask registers. For EVEX.
  | K3 = 0x15D
  /// Opmask registers. For EVEX.
  | K4 = 0x15E
  /// Opmask registers. For EVEX.
  | K5 = 0x15F
  /// Opmask registers. For EVEX.
  | K6 = 0x160
  /// Opmask registers. For EVEX.
  | K7 = 0x161
  /// Unknown Register.
  | UnknownReg = 0x162
#if EMULATION
  /// Opcode of the last instruction that modified EFlags
  | CCOP = 0x163
  /// Result value of the last instruction that modified EFlags
  | CCDST = 0x164
  | CCDSTD = 0x165
  | CCDSTW = 0x166
  | CCDSTB = 0x167
  /// First source operand of the last instruction that modified EFlags
  | CCSRC1 = 0x168
  | CCSRC1D = 0x169
  | CCSRC1W = 0x16a
  | CCSRC1B = 0x16b
  /// Second source operand of the last instruction that modified EFlags
  | CCSRC2 = 0x16c
  | CCSRC2D = 0x16d
  | CCSRC2W = 0x16e
  | CCSRC2B = 0x16f
#endif

/// Provides functions to handle Intel registers.
[<RequireQualifiedAccess>]
module Register =
  /// Returns the Intel register from a register ID.
  [<CompiledName "OfRegID">]
  let inline ofRegID (rid: RegisterID): Register =
    int rid |> LanguagePrimitives.EnumOfValue

  /// Returns the Intel register from a string representation.
  [<CompiledName "OfString">]
  let ofString (str: string) =
    match str.ToLowerInvariant () with
    | "rax" -> Register.RAX
    | "rbx" -> Register.RBX
    | "rcx" -> Register.RCX
    | "rdx" -> Register.RDX
    | "rsp" -> Register.RSP
    | "rbp" -> Register.RBP
    | "rsi" -> Register.RSI
    | "rdi" -> Register.RDI
    | "eax" -> Register.EAX
    | "ebx" -> Register.EBX
    | "ecx" -> Register.ECX
    | "edx" -> Register.EDX
    | "esp" -> Register.ESP
    | "ebp" -> Register.EBP
    | "esi" -> Register.ESI
    | "edi" -> Register.EDI
    | "ax" -> Register.AX
    | "bx" -> Register.BX
    | "cx" -> Register.CX
    | "dx" -> Register.DX
    | "sp" -> Register.SP
    | "bp" -> Register.BP
    | "si" -> Register.SI
    | "di" -> Register.DI
    | "al" -> Register.AL
    | "bl" -> Register.BL
    | "cl" -> Register.CL
    | "dl" -> Register.DL
    | "ah" -> Register.AH
    | "bh" -> Register.BH
    | "ch" -> Register.CH
    | "dh" -> Register.DH
    | "r8" -> Register.R8
    | "r9" -> Register.R9
    | "r10" -> Register.R10
    | "r11" -> Register.R11
    | "r12" -> Register.R12
    | "r13" -> Register.R13
    | "r14" -> Register.R14
    | "r15" -> Register.R15
    | "r8d" -> Register.R8D
    | "r9d" -> Register.R9D
    | "r10d" -> Register.R10D
    | "r11d" -> Register.R11D
    | "r12d" -> Register.R12D
    | "r13d" -> Register.R13D
    | "r14d" -> Register.R14D
    | "r15d" -> Register.R15D
    | "r8w" -> Register.R8W
    | "r9w" -> Register.R9W
    | "r10w" -> Register.R10W
    | "r11w" -> Register.R11W
    | "r12w" -> Register.R12W
    | "r13w" -> Register.R13W
    | "r14w" -> Register.R14W
    | "r15w" -> Register.R15W
    | "r8b" -> Register.R8B
    | "r9b" -> Register.R9B
    | "r10b" -> Register.R10B
    | "r11b" -> Register.R11B
    | "r12b" -> Register.R12B
    | "r13b" -> Register.R13B
    | "r14b" -> Register.R14B
    | "r15b" -> Register.R15B
    | "spl" -> Register.SPL
    | "bpl" -> Register.BPL
    | "sil" -> Register.SIL
    | "dil" -> Register.DIL
    | "eip" -> Register.EIP
    | "rip" -> Register.RIP
    | "st0" -> Register.ST0
    | "st1" -> Register.ST1
    | "st2" -> Register.ST2
    | "st3" -> Register.ST3
    | "st4" -> Register.ST4
    | "st5" -> Register.ST5
    | "st6" -> Register.ST6
    | "st7" -> Register.ST7
    | "mm0" -> Register.MM0
    | "mm1" -> Register.MM1
    | "mm2" -> Register.MM2
    | "mm3" -> Register.MM3
    | "mm4" -> Register.MM4
    | "mm5" -> Register.MM5
    | "mm6" -> Register.MM6
    | "mm7" -> Register.MM7
    | "xmm0" -> Register.XMM0
    | "xmm1" -> Register.XMM1
    | "xmm2" -> Register.XMM2
    | "xmm3" -> Register.XMM3
    | "xmm4" -> Register.XMM4
    | "xmm5" -> Register.XMM5
    | "xmm6" -> Register.XMM6
    | "xmm7" -> Register.XMM7
    | "xmm8" -> Register.XMM8
    | "xmm9" -> Register.XMM9
    | "xmm10" -> Register.XMM10
    | "xmm11" -> Register.XMM11
    | "xmm12" -> Register.XMM12
    | "xmm13" -> Register.XMM13
    | "xmm14" -> Register.XMM14
    | "xmm15" -> Register.XMM15
    | "ymm0" -> Register.YMM0
    | "ymm1" -> Register.YMM1
    | "ymm2" -> Register.YMM2
    | "ymm3" -> Register.YMM3
    | "ymm4" -> Register.YMM4
    | "ymm5" -> Register.YMM5
    | "ymm6" -> Register.YMM6
    | "ymm7" -> Register.YMM7
    | "ymm8" -> Register.YMM8
    | "ymm9" -> Register.YMM9
    | "ymm10" -> Register.YMM10
    | "ymm11" -> Register.YMM11
    | "ymm12" -> Register.YMM12
    | "ymm13" -> Register.YMM13
    | "ymm14" -> Register.YMM14
    | "ymm15" -> Register.YMM15
    | "zmm0" -> Register.ZMM0
    | "zmm1" -> Register.ZMM1
    | "zmm2" -> Register.ZMM2
    | "zmm3" -> Register.ZMM3
    | "zmm4" -> Register.ZMM4
    | "zmm5" -> Register.ZMM5
    | "zmm6" -> Register.ZMM6
    | "zmm7" -> Register.ZMM7
    | "zmm8" -> Register.ZMM8
    | "zmm9" -> Register.ZMM9
    | "zmm10" -> Register.ZMM10
    | "zmm11" -> Register.ZMM11
    | "zmm12" -> Register.ZMM12
    | "zmm13" -> Register.ZMM13
    | "zmm14" -> Register.ZMM14
    | "zmm15" -> Register.ZMM15
    | "es" -> Register.ES
    | "cs" -> Register.CS
    | "ss" -> Register.SS
    | "ds" -> Register.DS
    | "fs" -> Register.FS
    | "gs" -> Register.GS
    | "esbASE" -> Register.ESBase
    | "csbASE" -> Register.CSBase
    | "ssbASE" -> Register.SSBase
    | "dsbASE" -> Register.DSBase
    | "fsbASE" -> Register.FSBase
    | "gsbASE" -> Register.GSBase
    | "cr0" -> Register.CR0
    | "cr2" -> Register.CR2
    | "cr3" -> Register.CR3
    | "cr4" -> Register.CR4
    | "cr8" -> Register.CR8
    | "dr0" -> Register.DR0
    | "dr1" -> Register.DR1
    | "dr2" -> Register.DR2
    | "dr3" -> Register.DR3
    | "dr6" -> Register.DR6
    | "dr7" -> Register.DR7
    | "bnd0" -> Register.BND0
    | "bnd1" -> Register.BND1
    | "bnd2" -> Register.BND2
    | "bnd3" -> Register.BND3
    | "of" -> Register.OF
    | "df" -> Register.DF
    | "if" -> Register.IF
    | "tf" -> Register.TF
    | "sf" -> Register.SF
    | "zf" -> Register.ZF
    | "af" -> Register.AF
    | "pf" -> Register.PF
    | "cf" -> Register.CF
    | "fcw" -> Register.FCW
    | "fsw" -> Register.FSW
    | "ftw" -> Register.FTW
    | "fop" -> Register.FOP
    | "fip" -> Register.FIP
    | "fcs" -> Register.FCS
    | "fdp" -> Register.FDP
    | "fds" -> Register.FDS
    | "ftop" -> Register.FTOP
    | "ftw0" -> Register.FTW0
    | "ftw1" -> Register.FTW1
    | "ftw2" -> Register.FTW2
    | "ftw3" -> Register.FTW3
    | "ftw4" -> Register.FTW4
    | "ftw5" -> Register.FTW5
    | "ftw6" -> Register.FTW6
    | "ftw7" -> Register.FTW7
    | "fswc0" -> Register.FSWC0
    | "fswc1" -> Register.FSWC1
    | "fswc2" -> Register.FSWC2
    | "fswc3" -> Register.FSWC3
    | "mxcsr" -> Register.MXCSR
    | "mxcsrmask" -> Register.MXCSRMASK
    | "pkru" -> Register.PKRU
    | "bnd0a" -> Register.BND0A
    | "bnd0b" -> Register.BND0B
    | "bnd1a" -> Register.BND1A
    | "bnd1b" -> Register.BND1B
    | "bnd2a" -> Register.BND2A
    | "bnd2b" -> Register.BND2B
    | "bnd3a" -> Register.BND3A
    | "bnd3b" -> Register.BND3B
    | "st0a" -> Register.ST0A
    | "st0b" -> Register.ST0B
    | "st1a" -> Register.ST1A
    | "st1b" -> Register.ST1B
    | "st2a" -> Register.ST2A
    | "st2b" -> Register.ST2B
    | "st3a" -> Register.ST3A
    | "st3b" -> Register.ST3B
    | "st4a" -> Register.ST4A
    | "st4b" -> Register.ST4B
    | "st5a" -> Register.ST5A
    | "st5b" -> Register.ST5B
    | "st6a" -> Register.ST6A
    | "st6b" -> Register.ST6B
    | "st7a" -> Register.ST7A
    | "st7b" -> Register.ST7B
    | "zmm0a" -> Register.ZMM0A
    | "zmm0b" -> Register.ZMM0B
    | "zmm0c" -> Register.ZMM0C
    | "zmm0d" -> Register.ZMM0D
    | "zmm0e" -> Register.ZMM0E
    | "zmm0f" -> Register.ZMM0F
    | "zmm0g" -> Register.ZMM0G
    | "zmm0h" -> Register.ZMM0H
    | "zmm1a" -> Register.ZMM1A
    | "zmm1b" -> Register.ZMM1B
    | "zmm1c" -> Register.ZMM1C
    | "zmm1d" -> Register.ZMM1D
    | "zmm1e" -> Register.ZMM1E
    | "zmm1f" -> Register.ZMM1F
    | "zmm1g" -> Register.ZMM1G
    | "zmm1h" -> Register.ZMM1H
    | "zmm2a" -> Register.ZMM2A
    | "zmm2b" -> Register.ZMM2B
    | "zmm2c" -> Register.ZMM2C
    | "zmm2d" -> Register.ZMM2D
    | "zmm2e" -> Register.ZMM2E
    | "zmm2f" -> Register.ZMM2F
    | "zmm2g" -> Register.ZMM2G
    | "zmm2h" -> Register.ZMM2H
    | "zmm3a" -> Register.ZMM3A
    | "zmm3b" -> Register.ZMM3B
    | "zmm3c" -> Register.ZMM3C
    | "zmm3d" -> Register.ZMM3D
    | "zmm3e" -> Register.ZMM3E
    | "zmm3f" -> Register.ZMM3F
    | "zmm3g" -> Register.ZMM3G
    | "zmm3h" -> Register.ZMM3H
    | "zmm4a" -> Register.ZMM4A
    | "zmm4b" -> Register.ZMM4B
    | "zmm4c" -> Register.ZMM4C
    | "zmm4d" -> Register.ZMM4D
    | "zmm4e" -> Register.ZMM4E
    | "zmm4f" -> Register.ZMM4F
    | "zmm4g" -> Register.ZMM4G
    | "zmm4h" -> Register.ZMM4H
    | "zmm5a" -> Register.ZMM5A
    | "zmm5b" -> Register.ZMM5B
    | "zmm5c" -> Register.ZMM5C
    | "zmm5d" -> Register.ZMM5D
    | "zmm5e" -> Register.ZMM5E
    | "zmm5f" -> Register.ZMM5F
    | "zmm5g" -> Register.ZMM5G
    | "zmm5h" -> Register.ZMM5H
    | "zmm6a" -> Register.ZMM6A
    | "zmm6b" -> Register.ZMM6B
    | "zmm6c" -> Register.ZMM6C
    | "zmm6d" -> Register.ZMM6D
    | "zmm6e" -> Register.ZMM6E
    | "zmm6f" -> Register.ZMM6F
    | "zmm6g" -> Register.ZMM6G
    | "zmm6h" -> Register.ZMM6H
    | "zmm7a" -> Register.ZMM7A
    | "zmm7b" -> Register.ZMM7B
    | "zmm7c" -> Register.ZMM7C
    | "zmm7d" -> Register.ZMM7D
    | "zmm7e" -> Register.ZMM7E
    | "zmm7f" -> Register.ZMM7F
    | "zmm7g" -> Register.ZMM7G
    | "zmm7h" -> Register.ZMM7H
    | "zmm8a" -> Register.ZMM8A
    | "zmm8b" -> Register.ZMM8B
    | "zmm8c" -> Register.ZMM8C
    | "zmm8d" -> Register.ZMM8D
    | "zmm8e" -> Register.ZMM8E
    | "zmm8f" -> Register.ZMM8F
    | "zmm8g" -> Register.ZMM8G
    | "zmm8h" -> Register.ZMM8H
    | "zmm9a" -> Register.ZMM9A
    | "zmm9b" -> Register.ZMM9B
    | "zmm9c" -> Register.ZMM9C
    | "zmm9d" -> Register.ZMM9D
    | "zmm9e" -> Register.ZMM9E
    | "zmm9f" -> Register.ZMM9F
    | "zmm9g" -> Register.ZMM9G
    | "zmm9h" -> Register.ZMM9H
    | "zmm10a" -> Register.ZMM10A
    | "zmm10b" -> Register.ZMM10B
    | "zmm10c" -> Register.ZMM10C
    | "zmm10d" -> Register.ZMM10D
    | "zmm10e" -> Register.ZMM10E
    | "zmm10f" -> Register.ZMM10F
    | "zmm10g" -> Register.ZMM10G
    | "zmm10h" -> Register.ZMM10H
    | "zmm11a" -> Register.ZMM11A
    | "zmm11b" -> Register.ZMM11B
    | "zmm11c" -> Register.ZMM11C
    | "zmm11d" -> Register.ZMM11D
    | "zmm11e" -> Register.ZMM11E
    | "zmm11f" -> Register.ZMM11F
    | "zmm11g" -> Register.ZMM11G
    | "zmm11h" -> Register.ZMM11H
    | "zmm12a" -> Register.ZMM12A
    | "zmm12b" -> Register.ZMM12B
    | "zmm12c" -> Register.ZMM12C
    | "zmm12d" -> Register.ZMM12D
    | "zmm12e" -> Register.ZMM12E
    | "zmm12f" -> Register.ZMM12F
    | "zmm12g" -> Register.ZMM12G
    | "zmm12h" -> Register.ZMM12H
    | "zmm13a" -> Register.ZMM13A
    | "zmm13b" -> Register.ZMM13B
    | "zmm13c" -> Register.ZMM13C
    | "zmm13d" -> Register.ZMM13D
    | "zmm13e" -> Register.ZMM13E
    | "zmm13f" -> Register.ZMM13F
    | "zmm13g" -> Register.ZMM13G
    | "zmm13h" -> Register.ZMM13H
    | "zmm14a" -> Register.ZMM14A
    | "zmm14b" -> Register.ZMM14B
    | "zmm14c" -> Register.ZMM14C
    | "zmm14d" -> Register.ZMM14D
    | "zmm14e" -> Register.ZMM14E
    | "zmm14f" -> Register.ZMM14F
    | "zmm14g" -> Register.ZMM14G
    | "zmm14h" -> Register.ZMM14H
    | "zmm15a" -> Register.ZMM15A
    | "zmm15b" -> Register.ZMM15B
    | "zmm15c" -> Register.ZMM15C
    | "zmm15d" -> Register.ZMM15D
    | "zmm15e" -> Register.ZMM15E
    | "zmm15f" -> Register.ZMM15F
    | "zmm15g" -> Register.ZMM15G
    | "zmm15h" -> Register.ZMM15H
    | "k0" -> Register.K0
    | "k1" -> Register.K1
    | "k2" -> Register.K2
    | "k3" -> Register.K3
    | "k4" -> Register.K4
    | "k5" -> Register.K5
    | "k6" -> Register.K6
    | "k7" -> Register.K7
    | _ -> Terminator.impossible ()

  /// Returns the register ID of an Intel register.
  [<CompiledName "ToRegID">]
  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  /// Returns the string representation of an Intel register.
  [<CompiledName "ToString">]
  let toString reg =
    match reg with
    | Register.RAX -> "RAX"
    | Register.RBX -> "RBX"
    | Register.RCX -> "RCX"
    | Register.RDX -> "RDX"
    | Register.RSP -> "RSP"
    | Register.RBP -> "RBP"
    | Register.RSI -> "RSI"
    | Register.RDI -> "RDI"
    | Register.EAX -> "EAX"
    | Register.EBX -> "EBX"
    | Register.ECX -> "ECX"
    | Register.EDX -> "EDX"
    | Register.ESP -> "ESP"
    | Register.EBP -> "EBP"
    | Register.ESI -> "ESI"
    | Register.EDI -> "EDI"
    | Register.AX -> "AX"
    | Register.BX -> "BX"
    | Register.CX -> "CX"
    | Register.DX -> "DX"
    | Register.SP -> "SP"
    | Register.BP -> "BP"
    | Register.SI -> "SI"
    | Register.DI -> "DI"
    | Register.AL -> "AL"
    | Register.BL -> "BL"
    | Register.CL -> "CL"
    | Register.DL -> "DL"
    | Register.AH -> "AH"
    | Register.BH -> "BH"
    | Register.CH -> "CH"
    | Register.DH -> "DH"
    | Register.R8 -> "R8"
    | Register.R9 -> "R9"
    | Register.R10 -> "R10"
    | Register.R11 -> "R11"
    | Register.R12 -> "R12"
    | Register.R13 -> "R13"
    | Register.R14 -> "R14"
    | Register.R15 -> "R15"
    | Register.R8D -> "R8D"
    | Register.R9D -> "R9D"
    | Register.R10D -> "R10D"
    | Register.R11D -> "R11D"
    | Register.R12D -> "R12D"
    | Register.R13D -> "R13D"
    | Register.R14D -> "R14D"
    | Register.R15D -> "R15D"
    | Register.R8W -> "R8W"
    | Register.R9W -> "R9W"
    | Register.R10W -> "R10W"
    | Register.R11W -> "R11W"
    | Register.R12W -> "R12W"
    | Register.R13W -> "R13W"
    | Register.R14W -> "R14W"
    | Register.R15W -> "R15W"
    | Register.R8B -> "R8B"
    | Register.R9B -> "R9B"
    | Register.R10B -> "R10B"
    | Register.R11B -> "R11B"
    | Register.R12B -> "R12B"
    | Register.R13B -> "R13B"
    | Register.R14B -> "R14B"
    | Register.R15B -> "R15B"
    | Register.SPL -> "SPL"
    | Register.BPL -> "BPL"
    | Register.SIL -> "SIL"
    | Register.DIL -> "DIL"
    | Register.EIP -> "EIP"
    | Register.RIP -> "RIP"
    | Register.ST0 -> "ST0"
    | Register.ST1 -> "ST1"
    | Register.ST2 -> "ST2"
    | Register.ST3 -> "ST3"
    | Register.ST4 -> "ST4"
    | Register.ST5 -> "ST5"
    | Register.ST6 -> "ST6"
    | Register.ST7 -> "ST7"
    | Register.FCW -> "FCW"
    | Register.FSW -> "FSW"
    | Register.FTW -> "FTW"
    | Register.FOP -> "FOP"
    | Register.FIP -> "FIP"
    | Register.FCS -> "FCS"
    | Register.FDP -> "FDP"
    | Register.FDS -> "FDS"
    | Register.FTOP -> "FTOP"
    | Register.FTW0 -> "FTW0"
    | Register.FTW1 -> "FTW1"
    | Register.FTW2 -> "FTW2"
    | Register.FTW3 -> "FTW3"
    | Register.FTW4 -> "FTW4"
    | Register.FTW5 -> "FTW5"
    | Register.FTW6 -> "FTW6"
    | Register.FTW7 -> "FTW7"
    | Register.FSWC0 -> "FSWC0"
    | Register.FSWC1 -> "FSWC1"
    | Register.FSWC2 -> "FSWC2"
    | Register.FSWC3 -> "FSWC3"
    | Register.MXCSR -> "MXCSR"
    | Register.MXCSRMASK -> "MXCSRMASK"
    | Register.MM0 -> "MM0"
    | Register.MM1 -> "MM1"
    | Register.MM2 -> "MM2"
    | Register.MM3 -> "MM3"
    | Register.MM4 -> "MM4"
    | Register.MM5 -> "MM5"
    | Register.MM6 -> "MM6"
    | Register.MM7 -> "MM7"
    | Register.XMM0 -> "XMM0"
    | Register.XMM1 -> "XMM1"
    | Register.XMM2 -> "XMM2"
    | Register.XMM3 -> "XMM3"
    | Register.XMM4 -> "XMM4"
    | Register.XMM5 -> "XMM5"
    | Register.XMM6 -> "XMM6"
    | Register.XMM7 -> "XMM7"
    | Register.XMM8 -> "XMM8"
    | Register.XMM9 -> "XMM9"
    | Register.XMM10 -> "XMM10"
    | Register.XMM11 -> "XMM11"
    | Register.XMM12 -> "XMM12"
    | Register.XMM13 -> "XMM13"
    | Register.XMM14 -> "XMM14"
    | Register.XMM15 -> "XMM15"
    | Register.YMM0 -> "YMM0"
    | Register.YMM1 -> "YMM1"
    | Register.YMM2 -> "YMM2"
    | Register.YMM3 -> "YMM3"
    | Register.YMM4 -> "YMM4"
    | Register.YMM5 -> "YMM5"
    | Register.YMM6 -> "YMM6"
    | Register.YMM7 -> "YMM7"
    | Register.YMM8 -> "YMM8"
    | Register.YMM9 -> "YMM9"
    | Register.YMM10 -> "YMM10"
    | Register.YMM11 -> "YMM11"
    | Register.YMM12 -> "YMM12"
    | Register.YMM13 -> "YMM13"
    | Register.YMM14 -> "YMM14"
    | Register.YMM15 -> "YMM15"
    | Register.ZMM0 -> "ZMM0"
    | Register.ZMM1 -> "ZMM1"
    | Register.ZMM2 -> "ZMM2"
    | Register.ZMM3 -> "ZMM3"
    | Register.ZMM4 -> "ZMM4"
    | Register.ZMM5 -> "ZMM5"
    | Register.ZMM6 -> "ZMM6"
    | Register.ZMM7 -> "ZMM7"
    | Register.ZMM8 -> "ZMM8"
    | Register.ZMM9 -> "ZMM9"
    | Register.ZMM10 -> "ZMM10"
    | Register.ZMM11 -> "ZMM11"
    | Register.ZMM12 -> "ZMM12"
    | Register.ZMM13 -> "ZMM13"
    | Register.ZMM14 -> "ZMM14"
    | Register.ZMM15 -> "ZMM15"
    | Register.CS -> "CS"
    | Register.DS -> "DS"
    | Register.SS -> "SS"
    | Register.ES -> "ES"
    | Register.FS -> "FS"
    | Register.GS -> "GS"
    | Register.CSBase -> "CSBase"
    | Register.DSBase -> "DSBase"
    | Register.ESBase -> "ESBase"
    | Register.FSBase -> "FSBase"
    | Register.GSBase -> "GSBase"
    | Register.SSBase -> "SSBase"
    | Register.CR0 -> "CR0"
    | Register.CR2 -> "CR2"
    | Register.CR3 -> "CR3"
    | Register.CR4 -> "CR4"
    | Register.CR8 -> "CR8"
    | Register.DR0 -> "DR0"
    | Register.DR1 -> "DR1"
    | Register.DR2 -> "DR2"
    | Register.DR3 -> "DR3"
    | Register.DR6 -> "DR6"
    | Register.DR7 -> "DR7"
    | Register.BND0 -> "BND0"
    | Register.BND1 -> "BND1"
    | Register.BND2 -> "BND2"
    | Register.BND3 -> "BND3"
    | Register.OF -> "OF"
    | Register.DF -> "DF"
    | Register.IF -> "IF"
    | Register.TF -> "TF"
    | Register.SF -> "SF"
    | Register.ZF -> "ZF"
    | Register.AF -> "AF"
    | Register.PF -> "PF"
    | Register.CF -> "CF"
    | Register.ST0A -> "ST0A"
    | Register.ST0B -> "ST0B"
    | Register.ST1A -> "ST1A"
    | Register.ST1B -> "ST1B"
    | Register.ST2A -> "ST2A"
    | Register.ST2B -> "ST2B"
    | Register.ST3A -> "ST3A"
    | Register.ST3B -> "ST3B"
    | Register.ST4A -> "ST4A"
    | Register.ST4B -> "ST4B"
    | Register.ST5A -> "ST5A"
    | Register.ST5B -> "ST5B"
    | Register.ST6A -> "ST6A"
    | Register.ST6B -> "ST6B"
    | Register.ST7A -> "ST7A"
    | Register.ST7B -> "ST7B"
    | Register.ZMM0A -> "ZMM0A"
    | Register.ZMM0B -> "ZMM0B"
    | Register.ZMM0C -> "ZMM0C"
    | Register.ZMM0D -> "ZMM0D"
    | Register.ZMM0E -> "ZMM0E"
    | Register.ZMM0F -> "ZMM0F"
    | Register.ZMM0G -> "ZMM0G"
    | Register.ZMM0H -> "ZMM0H"
    | Register.ZMM1A -> "ZMM1A"
    | Register.ZMM1B -> "ZMM1B"
    | Register.ZMM1C -> "ZMM1C"
    | Register.ZMM1D -> "ZMM1D"
    | Register.ZMM1E -> "ZMM1E"
    | Register.ZMM1F -> "ZMM1F"
    | Register.ZMM1G -> "ZMM1G"
    | Register.ZMM1H -> "ZMM1H"
    | Register.ZMM2A -> "ZMM2A"
    | Register.ZMM2B -> "ZMM2B"
    | Register.ZMM2C -> "ZMM2C"
    | Register.ZMM2D -> "ZMM2D"
    | Register.ZMM2E -> "ZMM2E"
    | Register.ZMM2F -> "ZMM2F"
    | Register.ZMM2G -> "ZMM2G"
    | Register.ZMM2H -> "ZMM2H"
    | Register.ZMM3A -> "ZMM3A"
    | Register.ZMM3B -> "ZMM3B"
    | Register.ZMM3C -> "ZMM3C"
    | Register.ZMM3D -> "ZMM3D"
    | Register.ZMM3E -> "ZMM3E"
    | Register.ZMM3F -> "ZMM3F"
    | Register.ZMM3G -> "ZMM3G"
    | Register.ZMM3H -> "ZMM3H"
    | Register.ZMM4A -> "ZMM4A"
    | Register.ZMM4B -> "ZMM4B"
    | Register.ZMM4C -> "ZMM4C"
    | Register.ZMM4D -> "ZMM4D"
    | Register.ZMM4E -> "ZMM4E"
    | Register.ZMM4F -> "ZMM4F"
    | Register.ZMM4G -> "ZMM4G"
    | Register.ZMM4H -> "ZMM4H"
    | Register.ZMM5A -> "ZMM5A"
    | Register.ZMM5B -> "ZMM5B"
    | Register.ZMM5C -> "ZMM5C"
    | Register.ZMM5D -> "ZMM5D"
    | Register.ZMM5E -> "ZMM5E"
    | Register.ZMM5F -> "ZMM5F"
    | Register.ZMM5G -> "ZMM5G"
    | Register.ZMM5H -> "ZMM5H"
    | Register.ZMM6A -> "ZMM6A"
    | Register.ZMM6B -> "ZMM6B"
    | Register.ZMM6C -> "ZMM6C"
    | Register.ZMM6D -> "ZMM6D"
    | Register.ZMM6E -> "ZMM6E"
    | Register.ZMM6F -> "ZMM6F"
    | Register.ZMM6G -> "ZMM6G"
    | Register.ZMM6H -> "ZMM6H"
    | Register.ZMM7A -> "ZMM7A"
    | Register.ZMM7B -> "ZMM7B"
    | Register.ZMM7C -> "ZMM7C"
    | Register.ZMM7D -> "ZMM7D"
    | Register.ZMM7E -> "ZMM7E"
    | Register.ZMM7F -> "ZMM7F"
    | Register.ZMM7G -> "ZMM7G"
    | Register.ZMM7H -> "ZMM7H"
    | Register.ZMM8A -> "ZMM8A"
    | Register.ZMM8B -> "ZMM8B"
    | Register.ZMM8C -> "ZMM8C"
    | Register.ZMM8D -> "ZMM8D"
    | Register.ZMM8E -> "ZMM8E"
    | Register.ZMM8F -> "ZMM8F"
    | Register.ZMM8G -> "ZMM8G"
    | Register.ZMM8H -> "ZMM8H"
    | Register.ZMM9A -> "ZMM9A"
    | Register.ZMM9B -> "ZMM9B"
    | Register.ZMM9C -> "ZMM9C"
    | Register.ZMM9D -> "ZMM9D"
    | Register.ZMM9E -> "ZMM9E"
    | Register.ZMM9F -> "ZMM9F"
    | Register.ZMM9G -> "ZMM9G"
    | Register.ZMM9H -> "ZMM9H"
    | Register.ZMM10A -> "ZMM10A"
    | Register.ZMM10B -> "ZMM10B"
    | Register.ZMM10C -> "ZMM10C"
    | Register.ZMM10D -> "ZMM10D"
    | Register.ZMM10E -> "ZMM10E"
    | Register.ZMM10F -> "ZMM10F"
    | Register.ZMM10G -> "ZMM10G"
    | Register.ZMM10H -> "ZMM10H"
    | Register.ZMM11A -> "ZMM11A"
    | Register.ZMM11B -> "ZMM11B"
    | Register.ZMM11C -> "ZMM11C"
    | Register.ZMM11D -> "ZMM11D"
    | Register.ZMM11E -> "ZMM11E"
    | Register.ZMM11F -> "ZMM11F"
    | Register.ZMM11G -> "ZMM11G"
    | Register.ZMM11H -> "ZMM11H"
    | Register.ZMM12A -> "ZMM12A"
    | Register.ZMM12B -> "ZMM12B"
    | Register.ZMM12C -> "ZMM12C"
    | Register.ZMM12D -> "ZMM12D"
    | Register.ZMM12E -> "ZMM12E"
    | Register.ZMM12F -> "ZMM12F"
    | Register.ZMM12G -> "ZMM12G"
    | Register.ZMM12H -> "ZMM12H"
    | Register.ZMM13A -> "ZMM13A"
    | Register.ZMM13B -> "ZMM13B"
    | Register.ZMM13C -> "ZMM13C"
    | Register.ZMM13D -> "ZMM13D"
    | Register.ZMM13E -> "ZMM13E"
    | Register.ZMM13F -> "ZMM13F"
    | Register.ZMM13G -> "ZMM13G"
    | Register.ZMM13H -> "ZMM13H"
    | Register.ZMM14A -> "ZMM14A"
    | Register.ZMM14B -> "ZMM14B"
    | Register.ZMM14C -> "ZMM14C"
    | Register.ZMM14D -> "ZMM14D"
    | Register.ZMM14E -> "ZMM14E"
    | Register.ZMM14F -> "ZMM14F"
    | Register.ZMM14G -> "ZMM14G"
    | Register.ZMM14H -> "ZMM14H"
    | Register.ZMM15A -> "ZMM15A"
    | Register.ZMM15B -> "ZMM15B"
    | Register.ZMM15C -> "ZMM15C"
    | Register.ZMM15D -> "ZMM15D"
    | Register.ZMM15E -> "ZMM15E"
    | Register.ZMM15F -> "ZMM15F"
    | Register.ZMM15G -> "ZMM15G"
    | Register.ZMM15H -> "ZMM15H"
    | Register.K0 -> "K0"
    | Register.K1 -> "K1"
    | Register.K2 -> "K2"
    | Register.K3 -> "K3"
    | Register.K4 -> "K4"
    | Register.K5 -> "K5"
    | Register.K6 -> "K6"
    | Register.K7 -> "K7"
    | Register.PKRU -> "PKRU"
#if EMULATION
    | Register.CCOP -> "CCOP"
    | Register.CCDST -> "CCDST"
    | Register.CCSRC1 -> "CCSRC1"
    | Register.CCSRC2 -> "CCSRC2"
#endif
#if DEBUG
    | _ -> Terminator.impossible ()
#else
    | _ -> "?"
#endif
