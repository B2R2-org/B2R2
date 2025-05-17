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

namespace B2R2.FrontEnd.BinFile.ELF

/// Represents the target machine architecture of the ELF file.
type MachineType =
  /// No machine
  | EM_NONE = 0x0s
  /// AT&T WE 32100
  | EM_M32 = 0x1s
  /// SUN SPARC
  | EM_SPARC = 0x2s
  /// Intel 80386
  | EM_386 = 0x3s
  /// Motorola m68k family
  | EM_68K = 0x4s
  /// Motorola m88k family
  | EM_88K = 0x5s
  /// Intel MCU
  | EM_IAMCU = 0x6s
  /// Intel 80860
  | EM_860 = 0x7s
  /// MIPS R3000 (officially, big-endian only)
  | EM_MIPS = 0x8s
  /// IBM System/370
  | EM_S370 = 0x9s
  /// MIPS R3000 little-endian (Oct 4 1999 Draft). Deprecated.
  | EM_MIPS_RS3_LE = 0xAs
  /// Old version of Sparc v9, from before the ABI. Deprecated.
  | EM_OLD_SPARCV9 = 0xBs
  /// HPPA
  | EM_PARISC = 0xFs
  /// Old version of PowerPC. Deprecated.
  | EM_PPC_OLD = 0x11s
  /// Fujitsu VPP500
  | EM_VPP550 = 0x11s
  /// Sun's "v8plus"
  | EM_SPARC32PLUS = 0x12s
  /// Intel 80960
  | EM_960 = 0x13s
  /// PowerPC
  | EM_PPC = 0x14s
  /// 64-bit PowerPC
  | EM_PPC64 = 0x15s
  /// IBM S/390
  | EM_S390 = 0x16s
  /// Sony/Toshiba/IBM SPU
  | EM_SPU = 0x17s
  /// NEC V800 series
  | EM_V800 = 0x24s
  /// Fujitsu FR20
  | EM_FR20 = 0x25s
  /// TRW RH32
  | EM_RH32 = 0x26s
  /// Motorola M*Core May also be taken by Fujitsu MMA
  | EM_MCORE = 0x27s
  /// Old name for MCore
  | EM_RCE = 0x27s
  /// ARM
  | EM_ARM = 0x28s
  /// Digital Alpha
  | EM_OLD_ALPHA = 0x29s
  /// Renesas (formerly Hitachi) / SuperH SH
  | EM_SH = 0x2As
  /// SPARC v9 64-bit
  | EM_SPARCV9 = 0x2Bs
  /// Siemens Tricore embedded processor
  | EM_TRICORE = 0x2Cs
  /// ARC Cores
  | EM_ARC = 0x2Ds
  /// Renesas (formerly Hitachi) H8/300
  | EM_H8_300 = 0x2Es
  /// Renesas (formerly Hitachi) H8/300H
  | EM_H8_300H = 0x2Fs
  /// Renesas (formerly Hitachi) H8S
  | EM_H8S = 0x30s
  /// Renesas (formerly Hitachi) H8/500
  | EM_H8_500 = 0x31s
  /// Intel IA-64 Processor
  | EM_IA_64 = 0x32s
  /// Stanford MIPS-X
  | EM_MIPS_X = 0x33s
  /// Motorola Coldfire
  | EM_COLDFIRE = 0x34s
  /// Motorola M68HC12
  | EM_68HC12 = 0x35s
  /// Fujitsu Multimedia Accelerator
  | EM_MMA = 0x36s
  /// Siemens PCP
  | EM_PCP = 0x37s
  /// Sony nCPU embedded RISC processor
  | EM_NCPU = 0x38s
  /// Denso NDR1 microprocessor
  | EM_NDR1 = 0x39s
  /// Motorola Star*Core processor
  | EM_STARCORE = 0x3As
  /// Toyota ME16 processor
  | EM_ME16 = 0x3Bs
  /// STMicroelectronics ST100 processor
  | EM_ST100 = 0x3Cs
  /// Advanced Logic Corp. TinyJ embedded processor
  | EM_TINYJ = 0x3Ds
  /// Advanced Micro Devices X86-64 processor
  | EM_X86_64 = 0x3Es
  /// Sony DSP Processor
  | EM_PDSP = 0x3Fs
  /// Digital Equipment Corp. PDP-10
  | EM_PDP10 = 0x40s
  /// Digital Equipment Corp. PDP-11
  | EM_PDP11 = 0x41s
  /// Siemens FX66 microcontroller
  | EM_FX66 = 0x42s
  /// STMicroelectronics ST9+ 8/16 bit microcontroller
  | EM_ST9PLUS = 0x43s
  /// STMicroelectronics ST7 8-bit microcontroller
  | EM_ST7 = 0x44s
  /// Motorola MC68HC16 Microcontroller
  | EM_68HC16 = 0x45s
  /// Motorola MC68HC11 Microcontroller
  | EM_68HC11 = 0x46s
  /// Motorola MC68HC08 Microcontroller
  | EM_68HC08 = 0x47s
  /// Motorola MC68HC05 Microcontroller
  | EM_68HC05 = 0x48s
  /// Silicon Graphics SVx
  | EM_SVX = 0x49s
  /// STMicroelectronics ST19 8-bit cpu
  | EM_ST19 = 0x4As
  /// Digital VAX
  | EM_VAX = 0x4Bs
  /// Axis Communications 32-bit embedded processor
  | EM_CRIS = 0x4Cs
  /// Infineon Technologies 32-bit embedded cpu
  | EM_JAVELIN = 0x4Ds
  /// Element 14 64-bit DSP processor
  | EM_FIREPATH = 0x4Es
  /// LSI Logic's 16-bit DSP processor
  | EM_ZSP = 0x4Fs
  /// Donald Knuth's educational 64-bit processor
  | EM_MMIX = 0x50s
  /// Harvard's machine-independent format
  | EM_HUANY = 0x51s
  /// SiTera Prism
  | EM_PRISM = 0x52s
  /// Atmel AVR 8-bit microcontroller
  | EM_AVR = 0x53s
  /// Fujitsu FR30
  | EM_FR30 = 0x54s
  /// Mitsubishi D10V
  | EM_D10V = 0x55s
  /// Mitsubishi D30V
  | EM_D30V = 0x56s
  /// Renesas V850 (formerly NEC V850)
  | EM_V850 = 0x57s
  /// Renesas M32R (formerly Mitsubishi M32R)
  | EM_M32R = 0x58s
  /// Matsushita MN10300
  | EM_MN10300 = 0x59s
  /// Matsushita MN10200
  | EM_MN10200 = 0x5As
  /// picoJava
  | EM_PJ = 0x5Bs
  /// OpenRISC 1000 32-bit embedded processor
  | EM_OR1K = 0x5Cs
  /// ARC International ARCompact processor
  | EM_ARC_COMPACT = 0x5Ds
  /// Tensilica Xtensa Architecture
  | EM_XTENSA = 0x5Es
  /// Old Sunplus S+core7 backend magic number. Written in the absence of an
  /// ABI.
  | EM_SCORE_OLD = 0x5Fs
  /// Alphamosaic VideoCore processor
  | EM_VIDEOCORE = 0x5Fs
  /// Thompson Multimedia General Purpose Processor
  | EM_TMM_GPP = 0x60s
  /// National Semiconductor 32000 series
  | EM_NS32K = 0x61s
  /// Tenor Network TPC processor
  | EM_TPC = 0x62s
  /// Old value for picoJava. Deprecated.
  | EM_PJ_OLD = 0x63s
  /// Trebia SNP 1000 processor
  | EM_SNP1K = 0x63s
  /// STMicroelectronics ST200 microcontroller
  | EM_ST200 = 0x64s
  /// Ubicom IP2022 micro controller
  | EM_IP2K = 0x65s
  /// MAX Processor
  | EM_MAX = 0x66s
  /// National Semiconductor CompactRISC
  | EM_CR = 0x67s
  /// Fujitsu F2MC16
  | EM_F2MC16 = 0x68s
  /// TI msp430 micro controller
  | EM_MSP430 = 0x69s
  /// ADI Blackfin
  | EM_BLACKFIN = 0x6As
  /// S1C33 Family of Seiko Epson processors
  | EM_SE_C33 = 0x6Bs
  /// Sharp embedded microprocessor
  | EM_SEP = 0x6Cs
  /// Arca RISC Microprocessor
  | EM_ARCA = 0x6Ds
  /// Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University
  | EM_UNICORE = 0x6Es
  /// eXcess: 16/32/64-bit configurable embedded CPU
  | EM_EXCESS = 0x6Fs
  /// Icera Semiconductor Inc. Deep Execution Processor
  | EM_DXP = 0x70s
  /// Altera Nios II soft-core processor
  | EM_ALTERA_NIOS2 = 0x71s
  /// National Semiconductor CRX
  | EM_CRX = 0x72s
  /// Old, value for National Semiconductor CompactRISC. Deprecated.
  | EM_CR16_OLD = 0x73s
  /// Motorola XGATE embedded processor
  | EM_XGATE = 0x73s
  /// Infineon C16x/XC16x processor
  | EM_C166 = 0x74s
  /// Renesas M16C series microprocessors
  | EM_M16C = 0x75s
  /// Microchip Technology dsPIC30F Digital Signal Controller
  | EM_DSPIC30F = 0x76s
  /// Freescale Communication Engine RISC core
  | EM_CE = 0x77s
  /// Renesas M32C series microprocessors
  | EM_M32C = 0x78s
  /// Altium TSK3000 core
  | EM_TSK3000 = 0x83s
  /// Freescale RS08 embedded processor
  | EM_RS08 = 0x84s
  /// Cyan Technology eCOG2 microprocessor
  | EM_ECOG2 = 0x86s
  /// Sunplus Score
  | EM_SCORE = 0x87s
  /// Sunplus S+core7 RISC processor
  | EM_SCORE7 = 0x87s
  /// New Japan Radio (NJR) 24-bit DSP Processor
  | EM_DSP24 = 0x88s
  /// Broadcom VideoCore III processor
  | EM_VIDEOCORE3 = 0x89s
  /// RISC processor for Lattice FPGA architecture
  | EM_LATTICEMICO32 = 0x8As
  /// Seiko Epson C17 family
  | EM_SE_C17 = 0x8Bs
  /// Texas Instruments TMS320C6000 DSP family
  | EM_TI_C6000 = 0x8Cs
  /// Texas Instruments TMS320C2000 DSP family
  | EM_TI_C2000 = 0x8Ds
  /// Texas Instruments TMS320C55x DSP family
  | EM_TI_C5500 = 0x8Es
  /// Texas Instruments Programmable Realtime Unit
  | EM_TI_PRU = 0x90s
  /// STMicroelectronics 64bit VLIW Data Signal Processor
  | EM_MMDSP_PLUS = 0xA0s
  /// Cypress M8C microprocessor
  | EM_CYPRESS_M8C = 0xA1s
  /// Renesas R32C series microprocessors
  | EM_R32C = 0xA2s
  /// NXP Semiconductors TriMedia architecture family
  | EM_TRIMEDIA = 0xA3s
  /// QUALCOMM DSP6 Processor
  | EM_QDSP6 = 0xA4s
  /// Intel 8051 and variants
  | EM_8051 = 0xA5s
  /// STMicroelectronics STxP7x family
  | EM_STXP7X = 0xA6s
  /// Andes Technology compact code size embedded RISC processor family
  | EM_NDS32 = 0xA7s
  /// Cyan Technology eCOG1X family
  | EM_ECOG1 = 0xA8s
  /// Cyan Technology eCOG1X family
  | EM_ECOG1X = 0xA8s
  /// Dallas Semiconductor MAXQ30 Core Micro-controllers
  | EM_MAXQ30 = 0xA9s
  /// New Japan Radio (NJR) 16-bit DSP Processor
  | EM_XIMO16 = 0xAAs
  /// M2000 Reconfigurable RISC Microprocessor
  | EM_MANIK = 0xABs
  /// Cray Inc. NV2 vector architecture
  | EM_CRAYNV2 = 0xACs
  /// Renesas RX family
  | EM_RX = 0xADs
  /// Imagination Technologies Meta processor architecture
  | EM_METAG = 0xAEs
  /// MCST Elbrus general purpose hardware architecture
  | EM_MCST_ELBRUS = 0xAFs
  /// Cyan Technology eCOG16 family
  | EM_ECOG16 = 0xB0s
  /// National Semiconductor CompactRISC 16-bit processor
  | EM_CR16 = 0xB1s
  /// Freescale Extended Time Processing Unit
  | EM_ETPU = 0xB2s
  /// Infineon Technologies SLE9X core
  | EM_SLE9X = 0xB3s
  /// Intel L1OM
  | EM_L1OM = 0xB4s
  /// Intel K1OM
  | EM_K1OM = 0xB5s
  /// ARM 64-bit architecture
  | EM_AARCH64 = 0xB7s
  /// Atmel Corporation 32-bit microprocessor family
  | EM_AVR32 = 0xB9s
  /// STMicroeletronics STM8 8-bit microcontroller
  | EM_STM8 = 0xBAs
  /// Tilera TILE64 multicore architecture family
  | EM_TILE64 = 0xBBs
  /// Tilera TILEPro multicore architecture family
  | EM_TILEPRO = 0xBCs
  /// Xilinx MicroBlaze 32-bit RISC soft processor core
  | EM_MICROBLAZE = 0xBDs
  /// NVIDIA CUDA architecture
  | EM_CUDA = 0xBEs
  /// Tilera TILE-Gx multicore architecture family
  | EM_TILEGX = 0xBFs
  /// CloudShield architecture family
  | EM_CLOUDSHIELD = 0xC0s
  /// KIPO-KAIST Core-A 1st generation processor family
  | EM_COREA_1ST = 0xC1s
  /// KIPO-KAIST Core-A 2nd generation processor family
  | EM_COREA_2ND = 0xC2s
  /// Synopsys ARCompact V2
  | EM_ARC_COMPACT2 = 0xC3s
  /// Open8 8-bit RISC soft processor core
  | EM_OPEN8 = 0xC4s
  /// Renesas RL78 family.
  | EM_RL78 = 0xC5s
  /// Broadcom VideoCore V processor
  | EM_VIDEOCORE5 = 0xC6s
  /// Renesas 78K0R.
  | EM_78K0R = 0xC7s
  /// Freescale 56800EX Digital Signal Controller (DSC)
  | EM_56800EX = 0xC8s
  /// Beyond BA1 CPU architecture
  | EM_BA1 = 0xC9s
  /// Beyond BA2 CPU architecture
  | EM_BA2 = 0xCAs
  /// XMOS xCORE processor family
  | EM_XCORE = 0xCBs
  /// Microchip 8-bit PIC(r) family
  | EM_MCHP_PIC = 0xCCs
  /// KM211 KM32 32-bit processor
  | EM_KM32 = 0xD2s
  /// KM211 KMX32 32-bit processor
  | EM_KMX32 = 0xD3s
  /// KM211 KMX16 16-bit processor
  | EM_KMX16 = 0xD4s
  /// KM211 KMX8 8-bit processor
  | EM_KMX8 = 0xD5s
  /// KM211 KVARC processor
  | EM_KVARC = 0xD6s
  /// Paneve CDP architecture family
  | EM_CDP = 0xD7s
  /// Cognitive Smart Memory Processor
  | EM_COGE = 0xD8s
  /// Bluechip Systems CoolEngine
  | EM_COOL = 0xD9s
  /// Nanoradio Optimized RISC
  | EM_NORC = 0xDAs
  /// CSR Kalimba architecture family
  | EM_CSR_KALIMBA = 0xDBs
  /// Zilog Z80
  | EM_Z80 = 0xDCs
  /// Controls and Data Services VISIUMcore processor
  | EM_VISIUM = 0xDDs
  /// FTDI Chip FT32 high performance 32-bit RISC architecture
  | EM_FT32 = 0xDEs
  /// Moxie processor family
  | EM_MOXIE = 0xDFs
  /// AMD GPU architecture
  | EM_AMDGPU = 0xE0s
  /// RISC-V
  | EM_RISCV = 0xF3s
  /// Lanai 32-bit processor.
  | EM_LANAI = 0xF4s
  /// Linux BPF – in-kernel virtual machine.
  | EM_BPF = 0xF7s
  /// Netronome Flow Processor.
  | EM_NFP = 0xFAs
