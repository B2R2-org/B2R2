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

namespace B2R2

/// <summary>
/// Represents CPU architecture types that are supported by B2R2.
/// </summary>
type Architecture =
  /// Intel x86 or x86-64.
  | Intel = 0
  /// ARMv7.
  | ARMv7 = 1
  /// ARMv8 (aarch32 and aarch64).
  | ARMv8 = 2
  /// MIPS.
  | MIPS = 3
  /// PowerPC.
  | PPC = 4
  /// RISC-V.
  | RISCV = 5
  /// SPARC.
  | SPARC = 6
  /// IBM System/390.
  | S390 = 7
  /// SuperH (SH-4).
  | SH4 = 8
  /// PA-RISC.
  | PARISC = 9
  /// Motorola 68000 series.
  | M68K = 10
  /// DEC Alpha.
  | Alpha = 11
  /// Atmel AVR 8-bit microcontroller.
  | AVR = 20
  /// TMS320C64x, TMS320C67x, etc.
  | TMS320C6000 = 21
  /// EVM.
  | EVM = 30
  /// Python bytecode.
  | Python = 31
  /// WASM.
  | WASM = 32
  /// Common Intermediate Language (CIL), aka MSIL.
  | CIL = 33
  /// Extended Berkeley Packet Filter (eBPF), the instruction set of the virtual
  /// machine the Linux kernel runs programs of its own on.
  | BPF = 34
  /// Used internally to signal an unrecognized ISA combination. Passing this
  /// value to any ISA constructor raises InvalidISAException.
  | UnknownISA = 42

/// Represents which of the two instruction sets a 32-bit ARM ISA means. A
/// 32-bit ARM processor runs both, and nothing but the mode it is in says
/// which one a word belongs to.
and ARM32Mode =
  /// The A32 instruction set, whose instructions are one word each.
  | ARM = 0
  /// The T32 instruction set, whose instructions are one or two halfwords.
  | Thumb = 1

/// <summary>
/// Represents which version of the ARM architecture an ARM ISA means.
///
/// "ARMv8" is not one instruction set: each version adds instructions that the
/// versions below it leave UNDEFINED, and what a processor reads is what its
/// version makes mandatory plus the OPTIONAL features it has, which the
/// extensions name. Any names no version and reads every encoding the front
/// end knows, which is what an ARM ISA without one has always meant.
/// </summary>
and ARMArchVersion =
  /// No version named: every encoding is read.
  | Any = 0
  /// ARMv7-A.
  | V7 = 1
  /// ARMv7-A with the Virtualization Extensions, which bring the integer
  /// divides, the Security Extensions and the Multiprocessing Extensions with
  /// them.
  | V7VE = 2
  /// Armv8.0-A.
  | V8 = 3
  /// Armv8.1-A.
  | V8_1 = 4
  /// Armv8.2-A.
  | V8_2 = 5
  /// Armv8.3-A.
  | V8_3 = 6
  /// Armv8.4-A.
  | V8_4 = 7
  /// Armv8.5-A.
  | V8_5 = 8
  /// Armv8.6-A.
  | V8_6 = 9

/// <summary>
/// Represents the OPTIONAL features an AArch64 ISA has beyond what its version
/// makes mandatory, named as GCC's -march extensions name them. Each value is
/// the bit it takes in an ISA's flags.
/// </summary>
and [<System.Flags>] AArch64Extension =
  /// Nothing beyond the version.
  | None = 0
  /// FEAT_CRC32.
  | CRC = 0x100
  /// FEAT_AES and FEAT_PMULL.
  | AES = 0x200
  /// FEAT_SHA1 and FEAT_SHA256.
  | SHA2 = 0x400
  /// FEAT_SHA512 and FEAT_SHA3.
  | SHA3 = 0x800
  /// FEAT_SM3 and FEAT_SM4.
  | SM4 = 0x1000
  /// FEAT_FP16.
  | FP16 = 0x2000
  /// FEAT_FHM, which cannot be had without FEAT_FP16.
  | FP16FML = 0x4000
  /// FEAT_DotProd.
  | DotProd = 0x8000
  /// FEAT_LSE.
  | LSE = 0x10000
  /// FEAT_RDM.
  | RDMA = 0x20000
  /// FEAT_LRCPC.
  | RCPC = 0x40000
  /// FEAT_I8MM.
  | I8MM = 0x80000
  /// FEAT_BF16.
  | BF16 = 0x100000
  /// FEAT_MTE.
  | MemTag = 0x200000
  /// FEAT_SB.
  | SB = 0x400000
  /// FEAT_FlagM.
  | FlagM = 0x800000
  /// FEAT_PAuth.
  | PAuth = 0x1000000
  /// FEAT_SSBS.
  | SSBS = 0x2000000
  /// FEAT_RAS.
  | RAS = 0x4000000
  /// FEAT_SPE, the statistical profiling extension.
  | SPE = 0x8000000
  /// FEAT_TRF, the self-hosted trace extensions.
  | TRF = 0x10000000

/// <summary>
/// Represents the extensions an ARMv7 ISA has beyond its version, named as
/// GCC's -march and -mfpu name them. Each value is the bit it takes in an
/// ISA's flags.
/// </summary>
and [<System.Flags>] ARMv7Extension =
  /// Nothing beyond the version.
  | None = 0
  /// VFPv3, the floating-point instructions.
  | FP = 0x100
  /// Advanced SIMD.
  | SIMD = 0x200
  /// VFPv4, the fused multiply-adds.
  | VFPv4 = 0x400
  /// The half-precision conversions.
  | FP16 = 0x800
  /// SDIV and UDIV.
  | IDIV = 0x1000
  /// The Multiprocessing Extensions, which add PLDW.
  | MP = 0x2000
  /// The Security Extensions, which add SMC.
  | Sec = 0x4000
  /// The Virtualization Extensions, which add HVC and ERET and bring the
  /// integer divides.
  | Virt = 0x8000

/// Represents which release of the MIPS architecture a MIPS ISA means.
/// Release 6 is a different encoding space, not an extension of the earlier
/// ones, so nothing but this says what a word of MIPS code belongs to.
and MIPSRelease =
  /// Release 1 through 5, which share one encoding space.
  | PreR6 = 0
  /// Release 6.
  | R6 = 1

/// <summary>
/// Represents which encoding of the MIPS instruction set a MIPS ISA means.
///
/// All three stand for the same instructions and a processor reads whichever
/// its ISA Mode bit names, so nothing but that bit says what a halfword of
/// MIPS code belongs to. They sit beside the release in the same flags word,
/// which is why this counts from the second bit.
///
/// The bit is ONE bit on the processor: MD00076 gives it as "0: the
/// processor is executing 32-bit MIPS instructions, 1: the processor is
/// executing MIPS16e or microMIPS instructions". Which of the two compressed
/// encodings a 1 means is a property of the processor rather than of the
/// code, and no implementation has both -- so the two occupy separate values
/// here, where what is being said is which decoder to use.
/// </summary>
and MIPSISAMode =
  /// The MIPS32 and MIPS64 encoding, whose instructions are one word each.
  | MIPS = 0
  /// The microMIPS encoding, whose instructions are one halfword or two.
  | MicroMIPS = 2
  /// <summary>
  /// The MIPS16e encoding, whose instructions are one halfword, or two where
  /// an EXTEND prefix widens the immediate. It is an Application-Specific
  /// Extension rather than a base encoding -- MD00076 and MD00077, Volume
  /// IV-a of each architecture -- and Release 6 removes it.
  /// </summary>
  | MIPS16 = 4

/// Represents which member of the 68000 family an m68k ISA means. The family
/// shares one encoding space, and a later model reads encodings an earlier one
/// rejects -- including addressing modes that change how long an instruction is
/// -- so nothing but the model says what a halfword of code belongs to.
and M68KModel =
  /// MC68000, MC68008, MC68HC000, MC68HC001, and MC68EC000.
  | M68000 = 0
  /// MC68010.
  | M68010 = 1
  /// MC68020 and MC68EC020.
  | M68020 = 2
  /// MC68030 and MC68EC030.
  | M68030 = 3
  /// MC68040, MC68EC040, and MC68LC040.
  | M68040 = 4
  /// MC68060, MC68EC060, and MC68LC060.
  | M68060 = 5

/// Represents how wide an AVR core's program counter is, which is the one way
/// the AVR cores differ that an instruction's encoding does not already settle.
/// avr6 -- the cores reaching more than 128 KiB of program memory -- needs
/// three bytes of program counter, so a call there pushes three bytes of return
/// address where every earlier core pushes two, and a frame laid out for the
/// wrong one puts every saved register at the wrong offset. The finer core
/// levels (avr2, avr25, avr51, ...) differ only in which instructions they
/// have, which the decoder settles on its own, so nothing names them here.
and AVRCore =
  /// Every core up to avr51, whose program counter fits in two bytes. This is
  /// also what a raw image reports, having nothing to say which core it is for.
  | Classic = 0
  /// avr6, whose program counter needs three bytes.
  | Avr6 = 1

/// Represents the Python version.
and PythonVersion =
  /// Python 3.0.
  | Python300 = 300
  /// Python 3.1.
  | Python301 = 301
  /// Python 3.2.
  | Python302 = 302
  /// Python 3.3.
  | Python303 = 303
  /// Python 3.4.
  | Python304 = 304
  /// Python 3.5.
  | Python305 = 305
  /// Python 3.6
  | Python306 = 306
  /// Python 3.7
  | Python307 = 307
  /// Python 3.8.
  | Python308 = 308
  /// Python 3.9.
  | Python309 = 309
  /// Python 3.10.
  | Python310 = 310
  /// Python 3.11.
  | Python311 = 311
  /// Python 3.12.
  | Python312 = 312
  /// Python 3.13.
  | Python313 = 313
  /// Python 3.14.
  | Python314 = 314
  /// Python 3.15.
  | Python315 = 315

module PythonVersion =
  let minor (ver: PythonVersion) = int ver % 100

/// Raised when an invalid ISA is given as a parameter.
exception InvalidISAException
