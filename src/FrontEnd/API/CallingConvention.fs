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

/// Builds the function-call calling convention for a given binary. This is the
/// front-end factory that produces the architecture-independent
/// CallingConvention type defined in B2R2.Core from a target OS and ISA.
[<RequireQualifiedAccess>]
module B2R2.FrontEnd.CallingConvention

open B2R2
open B2R2.FrontEnd.BinFile

let inline private intel r = Intel.Register.toRegID r

let inline private arm32 r = ARM32.Register.toRegID r

let inline private arm64 r = ARM64.Register.toRegID r

let inline private mips r = MIPS.Register.toRegID r

let inline private ppc r = PPC.Register.toRegID r

let inline private riscv r = RISCV64.Register.toRegID r

let inline private sparc r = SPARC.Register.toRegID r

let inline private s390 r = S390.Register.toRegID r

let inline private sh4 r = SH4.Register.toRegID r

let inline private parisc r = PARISC.Register.toRegID r

let private linuxX86 () = (* cdecl: all integer arguments on the stack *)
  { Args = [| ArgLocation.Stack { FirstOffset = 4; SlotSize = 4 } |]
    ReturnLocation = ArgLocation.Reg(intel Intel.Register.EAX)
    CalleeSavedRegisters =
      set [ intel Intel.Register.EBP
            intel Intel.Register.EBX
            intel Intel.Register.ESI
            intel Intel.Register.EDI ]
    CallerSavedRegisters =
      set [ intel Intel.Register.EAX
            intel Intel.Register.ECX
            intel Intel.Register.EDX ] }

let private linuxX64 () = (* System V AMD64 ABI *)
  { Args =
      [| ArgLocation.Reg(intel Intel.Register.RDI)
         ArgLocation.Reg(intel Intel.Register.RSI)
         ArgLocation.Reg(intel Intel.Register.RDX)
         ArgLocation.Reg(intel Intel.Register.RCX)
         ArgLocation.Reg(intel Intel.Register.R8)
         ArgLocation.Reg(intel Intel.Register.R9)
         ArgLocation.Stack { FirstOffset = 8; SlotSize = 8 } |]
    ReturnLocation = ArgLocation.Reg(intel Intel.Register.RAX)
    CalleeSavedRegisters =
      set [ intel Intel.Register.RBX
            intel Intel.Register.RSP
            intel Intel.Register.RBP
            intel Intel.Register.R12
            intel Intel.Register.R13
            intel Intel.Register.R14
            intel Intel.Register.R15 ]
    CallerSavedRegisters =
      set [ intel Intel.Register.RAX
            intel Intel.Register.RCX
            intel Intel.Register.RDX
            intel Intel.Register.R8
            intel Intel.Register.R9
            intel Intel.Register.R10
            intel Intel.Register.R11 ] }

let private linuxARM32 () = (* AAPCS (EABI) *)
  { Args =
      [| ArgLocation.Reg(arm32 ARM32.Register.R0)
         ArgLocation.Reg(arm32 ARM32.Register.R1)
         ArgLocation.Reg(arm32 ARM32.Register.R2)
         ArgLocation.Reg(arm32 ARM32.Register.R3)
         ArgLocation.Reg(arm32 ARM32.Register.R4)
         ArgLocation.Reg(arm32 ARM32.Register.R5) |]
    ReturnLocation = ArgLocation.Reg(arm32 ARM32.Register.R0)
    CalleeSavedRegisters =
      set [ arm32 ARM32.Register.R4
            arm32 ARM32.Register.R5
            arm32 ARM32.Register.R6
            arm32 ARM32.Register.R7
            arm32 ARM32.Register.R8
            arm32 ARM32.Register.SL
            arm32 ARM32.Register.FP ]
    CallerSavedRegisters =
      set [ arm32 ARM32.Register.R0
            arm32 ARM32.Register.R1
            arm32 ARM32.Register.R2
            arm32 ARM32.Register.R3 ] }

let private linuxAArch64 () = (* AAPCS64 *)
  { Args =
      [| ArgLocation.Reg(arm64 ARM64.Register.X0)
         ArgLocation.Reg(arm64 ARM64.Register.X1)
         ArgLocation.Reg(arm64 ARM64.Register.X2)
         ArgLocation.Reg(arm64 ARM64.Register.X3)
         ArgLocation.Reg(arm64 ARM64.Register.X4)
         ArgLocation.Reg(arm64 ARM64.Register.X5) |]
    ReturnLocation = ArgLocation.Reg(arm64 ARM64.Register.X0)
    CalleeSavedRegisters =
      set [ arm64 ARM64.Register.X19
            arm64 ARM64.Register.X20
            arm64 ARM64.Register.X21
            arm64 ARM64.Register.X22
            arm64 ARM64.Register.X23
            arm64 ARM64.Register.X24
            arm64 ARM64.Register.X25
            arm64 ARM64.Register.X26
            arm64 ARM64.Register.X27
            arm64 ARM64.Register.X28
            arm64 ARM64.Register.X29 ]
    CallerSavedRegisters =
      set [ arm64 ARM64.Register.X9
            arm64 ARM64.Register.X10
            arm64 ARM64.Register.X11
            arm64 ARM64.Register.X12
            arm64 ARM64.Register.X13
            arm64 ARM64.Register.X14
            arm64 ARM64.Register.X15 ] }

let private linuxMIPS () =
  { Args =
      [| ArgLocation.Reg(mips MIPS.Register.R4)
         ArgLocation.Reg(mips MIPS.Register.R5)
         ArgLocation.Reg(mips MIPS.Register.R6)
         ArgLocation.Reg(mips MIPS.Register.R7)
         ArgLocation.Reg(mips MIPS.Register.R8)
         ArgLocation.Reg(mips MIPS.Register.R9) |]
    ReturnLocation = ArgLocation.Reg(mips MIPS.Register.R2)
    CalleeSavedRegisters =
      set [ mips MIPS.Register.R16
            mips MIPS.Register.R17
            mips MIPS.Register.R18
            mips MIPS.Register.R19
            mips MIPS.Register.R20
            mips MIPS.Register.R21
            mips MIPS.Register.R22
            mips MIPS.Register.R23
            mips MIPS.Register.R30 ]
    CallerSavedRegisters =
      set [ mips MIPS.Register.R8
            mips MIPS.Register.R9
            mips MIPS.Register.R10
            mips MIPS.Register.R11
            mips MIPS.Register.R12
            mips MIPS.Register.R13
            mips MIPS.Register.R14
            mips MIPS.Register.R15 ] }

let private linuxPPC32 () = (* System V PowerPC ABI *)
  { Args =
      [| ArgLocation.Reg(ppc PPC.Register.R3)
         ArgLocation.Reg(ppc PPC.Register.R4)
         ArgLocation.Reg(ppc PPC.Register.R5)
         ArgLocation.Reg(ppc PPC.Register.R6)
         ArgLocation.Reg(ppc PPC.Register.R7)
         ArgLocation.Reg(ppc PPC.Register.R8)
         ArgLocation.Reg(ppc PPC.Register.R9)
         ArgLocation.Reg(ppc PPC.Register.R10) |]
    ReturnLocation = ArgLocation.Reg(ppc PPC.Register.R3)
    CalleeSavedRegisters =
      set [ ppc PPC.Register.R1
            ppc PPC.Register.R14
            ppc PPC.Register.R15
            ppc PPC.Register.R16
            ppc PPC.Register.R17
            ppc PPC.Register.R18
            ppc PPC.Register.R19
            ppc PPC.Register.R20
            ppc PPC.Register.R21
            ppc PPC.Register.R22
            ppc PPC.Register.R23
            ppc PPC.Register.R24
            ppc PPC.Register.R25
            ppc PPC.Register.R26
            ppc PPC.Register.R27
            ppc PPC.Register.R28
            ppc PPC.Register.R29
            ppc PPC.Register.R30
            ppc PPC.Register.R31 ]
    CallerSavedRegisters =
      set [ ppc PPC.Register.R0
            ppc PPC.Register.R3
            ppc PPC.Register.R4
            ppc PPC.Register.R5
            ppc PPC.Register.R6
            ppc PPC.Register.R7
            ppc PPC.Register.R8
            ppc PPC.Register.R9
            ppc PPC.Register.R10
            ppc PPC.Register.R11
            ppc PPC.Register.R12 ] }

let private linuxRISCV64 () = (* RISC-V LP64 ABI *)
  { Args =
      [| ArgLocation.Reg(riscv RISCV64.Register.X10)
         ArgLocation.Reg(riscv RISCV64.Register.X11)
         ArgLocation.Reg(riscv RISCV64.Register.X12)
         ArgLocation.Reg(riscv RISCV64.Register.X13)
         ArgLocation.Reg(riscv RISCV64.Register.X14)
         ArgLocation.Reg(riscv RISCV64.Register.X15)
         ArgLocation.Reg(riscv RISCV64.Register.X16)
         ArgLocation.Reg(riscv RISCV64.Register.X17) |]
    ReturnLocation = ArgLocation.Reg(riscv RISCV64.Register.X10)
    CalleeSavedRegisters =
      set [ riscv RISCV64.Register.X2
            riscv RISCV64.Register.X8
            riscv RISCV64.Register.X9
            riscv RISCV64.Register.X18
            riscv RISCV64.Register.X19
            riscv RISCV64.Register.X20
            riscv RISCV64.Register.X21
            riscv RISCV64.Register.X22
            riscv RISCV64.Register.X23
            riscv RISCV64.Register.X24
            riscv RISCV64.Register.X25
            riscv RISCV64.Register.X26
            riscv RISCV64.Register.X27 ]
    CallerSavedRegisters =
      set [ riscv RISCV64.Register.X1
            riscv RISCV64.Register.X5
            riscv RISCV64.Register.X6
            riscv RISCV64.Register.X7
            riscv RISCV64.Register.X10
            riscv RISCV64.Register.X11
            riscv RISCV64.Register.X12
            riscv RISCV64.Register.X13
            riscv RISCV64.Register.X14
            riscv RISCV64.Register.X15
            riscv RISCV64.Register.X16
            riscv RISCV64.Register.X17
            riscv RISCV64.Register.X28
            riscv RISCV64.Register.X29
            riscv RISCV64.Register.X30
            riscv RISCV64.Register.X31 ] }

let private linuxSPARC () = (* SPARC: caller's outs become callee's ins *)
  { Args =
      [| ArgLocation.Reg(sparc SPARC.Register.O0)
         ArgLocation.Reg(sparc SPARC.Register.O1)
         ArgLocation.Reg(sparc SPARC.Register.O2)
         ArgLocation.Reg(sparc SPARC.Register.O3)
         ArgLocation.Reg(sparc SPARC.Register.O4)
         ArgLocation.Reg(sparc SPARC.Register.O5) |]
    ReturnLocation = ArgLocation.Reg(sparc SPARC.Register.O0)
    CalleeSavedRegisters =
      set [ sparc SPARC.Register.L0
            sparc SPARC.Register.L1
            sparc SPARC.Register.L2
            sparc SPARC.Register.L3
            sparc SPARC.Register.L4
            sparc SPARC.Register.L5
            sparc SPARC.Register.L6
            sparc SPARC.Register.L7
            sparc SPARC.Register.I0
            sparc SPARC.Register.I1
            sparc SPARC.Register.I2
            sparc SPARC.Register.I3
            sparc SPARC.Register.I4
            sparc SPARC.Register.I5
            sparc SPARC.Register.I6
            sparc SPARC.Register.I7 ]
    CallerSavedRegisters =
      set [ sparc SPARC.Register.G1
            sparc SPARC.Register.G2
            sparc SPARC.Register.G3
            sparc SPARC.Register.G4
            sparc SPARC.Register.G5
            sparc SPARC.Register.O0
            sparc SPARC.Register.O1
            sparc SPARC.Register.O2
            sparc SPARC.Register.O3
            sparc SPARC.Register.O4
            sparc SPARC.Register.O5
            sparc SPARC.Register.O7 ] }

let private linuxS390 () = (* IBM Z (s390x) ELF ABI *)
  { Args =
      [| ArgLocation.Reg(s390 S390.Register.R2)
         ArgLocation.Reg(s390 S390.Register.R3)
         ArgLocation.Reg(s390 S390.Register.R4)
         ArgLocation.Reg(s390 S390.Register.R5)
         ArgLocation.Reg(s390 S390.Register.R6) |]
    ReturnLocation = ArgLocation.Reg(s390 S390.Register.R2)
    CalleeSavedRegisters =
      set [ s390 S390.Register.R6
            s390 S390.Register.R7
            s390 S390.Register.R8
            s390 S390.Register.R9
            s390 S390.Register.R10
            s390 S390.Register.R11
            s390 S390.Register.R12
            s390 S390.Register.R13
            s390 S390.Register.R15 ]
    CallerSavedRegisters =
      set [ s390 S390.Register.R0
            s390 S390.Register.R1
            s390 S390.Register.R2
            s390 S390.Register.R3
            s390 S390.Register.R4
            s390 S390.Register.R5
            s390 S390.Register.R14 ] }

let private linuxSH4 () = (* Renesas SH ABI *)
  { Args =
      [| ArgLocation.Reg(sh4 SH4.Register.R4)
         ArgLocation.Reg(sh4 SH4.Register.R5)
         ArgLocation.Reg(sh4 SH4.Register.R6)
         ArgLocation.Reg(sh4 SH4.Register.R7) |]
    ReturnLocation = ArgLocation.Reg(sh4 SH4.Register.R0)
    CalleeSavedRegisters =
      set [ sh4 SH4.Register.R8
            sh4 SH4.Register.R9
            sh4 SH4.Register.R10
            sh4 SH4.Register.R11
            sh4 SH4.Register.R12
            sh4 SH4.Register.R13
            sh4 SH4.Register.R14
            sh4 SH4.Register.R15 ]
    CallerSavedRegisters =
      set [ sh4 SH4.Register.R0
            sh4 SH4.Register.R1
            sh4 SH4.Register.R2
            sh4 SH4.Register.R3
            sh4 SH4.Register.R4
            sh4 SH4.Register.R5
            sh4 SH4.Register.R6
            sh4 SH4.Register.R7 ] }

let private linuxPARISC () = (* PA-RISC: arguments in descending GRs *)
  { Args =
      [| ArgLocation.Reg(parisc PARISC.Register.GR26)
         ArgLocation.Reg(parisc PARISC.Register.GR25)
         ArgLocation.Reg(parisc PARISC.Register.GR24)
         ArgLocation.Reg(parisc PARISC.Register.GR23) |]
    ReturnLocation = ArgLocation.Reg(parisc PARISC.Register.GR28)
    CalleeSavedRegisters =
      set [ parisc PARISC.Register.GR3
            parisc PARISC.Register.GR4
            parisc PARISC.Register.GR5
            parisc PARISC.Register.GR6
            parisc PARISC.Register.GR7
            parisc PARISC.Register.GR8
            parisc PARISC.Register.GR9
            parisc PARISC.Register.GR10
            parisc PARISC.Register.GR11
            parisc PARISC.Register.GR12
            parisc PARISC.Register.GR13
            parisc PARISC.Register.GR14
            parisc PARISC.Register.GR15
            parisc PARISC.Register.GR16
            parisc PARISC.Register.GR17
            parisc PARISC.Register.GR18 ]
    CallerSavedRegisters =
      set [ parisc PARISC.Register.GR1
            parisc PARISC.Register.GR19
            parisc PARISC.Register.GR20
            parisc PARISC.Register.GR21
            parisc PARISC.Register.GR22
            parisc PARISC.Register.GR23
            parisc PARISC.Register.GR24
            parisc PARISC.Register.GR25
            parisc PARISC.Register.GR26
            parisc PARISC.Register.GR28
            parisc PARISC.Register.GR29
            parisc PARISC.Register.GR31 ] }

let private windowsX86 () = (* fastcall: first two args in ECX, EDX *)
  { Args =
      [| ArgLocation.Reg(intel Intel.Register.ECX)
         ArgLocation.Reg(intel Intel.Register.EDX)
         ArgLocation.Stack { FirstOffset = 4; SlotSize = 4 } |]
    ReturnLocation = ArgLocation.Reg(intel Intel.Register.EAX)
    CalleeSavedRegisters =
      set [ intel Intel.Register.EBX
            intel Intel.Register.EBP
            intel Intel.Register.ESI
            intel Intel.Register.EDI ]
    CallerSavedRegisters =
      set [ intel Intel.Register.EAX
            intel Intel.Register.ECX
            intel Intel.Register.EDX ] }

let private windowsX64 () = (* Microsoft x64: 32-byte shadow space *)
  { Args =
      [| ArgLocation.Reg(intel Intel.Register.RCX)
         ArgLocation.Reg(intel Intel.Register.RDX)
         ArgLocation.Reg(intel Intel.Register.R8)
         ArgLocation.Reg(intel Intel.Register.R9)
         ArgLocation.Stack { FirstOffset = 40; SlotSize = 8 } |]
    ReturnLocation = ArgLocation.Reg(intel Intel.Register.RAX)
    CalleeSavedRegisters =
      set [ intel Intel.Register.RBX
            intel Intel.Register.RSP
            intel Intel.Register.RBP
            intel Intel.Register.RDI
            intel Intel.Register.RSI
            intel Intel.Register.R12
            intel Intel.Register.R13
            intel Intel.Register.R14
            intel Intel.Register.R15 ]
    CallerSavedRegisters =
      set [ intel Intel.Register.RAX
            intel Intel.Register.RCX
            intel Intel.Register.RDX
            intel Intel.Register.R8
            intel Intel.Register.R9
            intel Intel.Register.R10
            intel Intel.Register.R11 ] }

/// Builds the function-call calling convention for the given OS and ISA. Only
/// Windows diverges from the System V / AAPCS conventions; every other OS
/// (Linux, macOS, or an unknown OS such as a raw image) shares them. ISAs we do
/// not model fall back to the System V x64 convention, so this never throws.
[<CompiledName "Create">]
let create os isa =
  match os, isa with
  | OS.Windows, X86 -> windowsX86 ()
  | OS.Windows, X64 -> windowsX64 ()
  (* macOS shares the System V / AAPCS conventions for the architectures Mach-O
     targets, so these reuse the builders we model Linux-first. *)
  | OS.MacOSX, X86 -> linuxX86 ()
  | OS.MacOSX, X64 -> linuxX64 ()
  | OS.MacOSX, ARM32 -> linuxARM32 ()
  | OS.MacOSX, AArch64 -> linuxAArch64 ()
  (* Linux and any unknown OS (e.g. a raw image) also follow System V. *)
  | _, X86 -> linuxX86 ()
  | _, ARM32 -> linuxARM32 ()
  | _, AArch64 -> linuxAArch64 ()
  | _, MIPS -> linuxMIPS ()
  | _, PPC32 -> linuxPPC32 ()
  | _, RISCV64 -> linuxRISCV64 ()
  | _, SPARC -> linuxSPARC ()
  | _, S390 -> linuxS390 ()
  | _, SH4 -> linuxSH4 ()
  | _, PARISC -> linuxPARISC ()
  | _ -> linuxX64 ()
