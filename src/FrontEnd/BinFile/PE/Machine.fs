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

namespace B2R2.FrontEnd.BinFile.PE

/// Represents the machine a PE file was built for, which is what the Machine
/// field of its COFF header names.
type internal Machine =
  /// Applicable to any machine type.
  | Unknown = 0x0us
  /// Intel 386 or later, and compatible processors.
  | I386 = 0x14cus
  /// MIPS little-endian WCE v2.
  | WceMipsV2 = 0x169us
  /// Alpha AXP.
  | Alpha = 0x184us
  /// Hitachi SH3.
  | SH3 = 0x1a2us
  /// Hitachi SH3 DSP.
  | SH3Dsp = 0x1a3us
  /// Hitachi SH3E little-endian.
  | SH3E = 0x1a4us
  /// Hitachi SH4.
  | SH4 = 0x1a6us
  /// Hitachi SH5.
  | SH5 = 0x1a8us
  /// ARM little-endian.
  | Arm = 0x1c0us
  /// ARM Thumb/Thumb-2 little-endian.
  | Thumb = 0x1c2us
  /// ARM Thumb-2 little-endian.
  | ArmThumb2 = 0x1c4us
  /// Matsushita AM33.
  | AM33 = 0x1d3us
  /// Power PC little-endian.
  | PowerPC = 0x1f0us
  /// Power PC with floating point support.
  | PowerPCFP = 0x1f1us
  /// Intel Itanium processor family.
  | IA64 = 0x200us
  /// MIPS16.
  | MIPS16 = 0x266us
  /// Alpha 64.
  | Alpha64 = 0x284us
  /// MIPS with FPU.
  | MipsFpu = 0x366us
  /// MIPS16 with FPU.
  | MipsFpu16 = 0x466us
  /// Infineon TriCore.
  | Tricore = 0x520us
  /// EFI byte code.
  | Ebc = 0xebcus
  /// RISC-V 32-bit address space.
  | RiscV32 = 0x5032us
  /// RISC-V 64-bit address space.
  | RiscV64 = 0x5064us
  /// RISC-V 128-bit address space.
  | RiscV128 = 0x5128us
  /// LoongArch 32-bit processor family.
  | LoongArch32 = 0x6232us
  /// LoongArch 64-bit processor family.
  | LoongArch64 = 0x6264us
  /// x64.
  | Amd64 = 0x8664us
  /// Mitsubishi M32R little-endian.
  | M32R = 0x9041us
  /// ARM64 little-endian.
  | Arm64 = 0xaa64us
