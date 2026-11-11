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

namespace B2R2.ABI

open B2R2
open B2R2.FrontEnd

/// Represents the calling convention used for ordinary function calls under a
/// specific ISA and OS. This is an approximation: real binaries may deviate,
/// but it captures the dominant convention used by mainstream compilers.
type CallingConvention =
  { /// Integer/pointer argument locations in order (index 0 is the first such
    /// argument). A trailing Stack element, if present, covers every argument
    /// beyond the array as well.
    IntArgs: ArgLocation[]
    /// Floating-point/vector (SSE, NEON, etc.) argument locations in order.
    /// Empty when the ABI passes floating-point arguments in the integer
    /// registers or on the stack (e.g. x86, soft-float ARM).
    FloatArgs: ArgLocation[]
    /// Location of the integer/pointer return value.
    IntReturnLocation: ArgLocation
    /// Location of the floating-point return value.
    FloatReturnLocation: ArgLocation
    /// How integer and floating-point arguments are assigned to their pools.
    ArgClassification: ArgClassification
    /// Callee-saved (non-volatile) registers.
    CalleeSavedRegisters: Set<RegisterID>
    /// Caller-saved (volatile) registers.
    CallerSavedRegisters: Set<RegisterID>
    /// Where the return address is found at callee entry.
    ReturnAddressLocation: ReturnAddressLocation }
with
  /// Returns the location of the integer/pointer argument at the given
  /// zero-based index. For a stack argument, the returned Stack layout's
  /// FirstOffset is the offset of that specific argument.
  member this.GetIntArgLocation(i) = ArgLocation.resolve this.IntArgs i

  /// Returns the register holding the integer/pointer argument at the given
  /// zero-based index. Raises if the argument is not in a single register.
  member this.IntArgRegister(i) =
    this.GetIntArgLocation(i) |> ArgLocation.toRegister

  /// Returns the location of the floating-point/vector argument at the given
  /// zero-based index.
  member this.GetFloatArgLocation(i) = ArgLocation.resolve this.FloatArgs i

  /// Returns the register holding the floating-point/vector argument at the
  /// given zero-based index. Raises if the argument is not in a single
  /// register.
  member this.FloatArgRegister(i) =
    this.GetFloatArgLocation(i) |> ArgLocation.toRegister

  /// Returns the register holding the integer/pointer return value. Raises if
  /// the value is not returned in a single register under this convention.
  member this.IntReturnRegister = ArgLocation.toRegister this.IntReturnLocation

  /// Returns the register holding the floating-point return value. Raises if
  /// the value is not returned in a single register under this convention.
  member this.FloatReturnRegister =
    ArgLocation.toRegister this.FloatReturnLocation

  /// Returns true if the given register is callee-saved (non-volatile).
  member this.IsCalleeSaved(rid) = Set.contains rid this.CalleeSavedRegisters

  /// Returns true if the given register is caller-saved (volatile).
  member this.IsCallerSaved(rid) = Set.contains rid this.CallerSavedRegisters

/// Builds the function-call calling convention for a given binary, producing
/// the architecture-independent CallingConvention type from a target OS and
/// ISA.
[<RequireQualifiedAccess>]
module CallingConvention =
  let inline private intel r = Intel.Register.toRegID r

  let inline private arm32 r = ARM32.Register.toRegID r

  let inline private arm64 r = ARM64.Register.toRegID r

  let inline private mips r = MIPS.Register.toRegID r

  let inline private ppc r = PPC.Register.toRegID r

  let inline private riscv r = RISCV.Register.toRegID r

  let inline private sparc r = SPARC.Register.toRegID r

  let inline private s390 r = S390.Register.toRegID r

  let inline private m68k r = M68K.Register.toRegID r

  let inline private sh4 r = SH4.Register.toRegID r

  let inline private parisc r = PARISC.Register.toRegID r

  let inline private alpha r = Alpha.Register.toRegID r

  let private linuxX86 () = (* cdecl: int args on stack, floats via x87 *)
    { IntArgs = [| ArgLocation.Stack { FirstOffset = 4; SlotSize = 4 } |]
      FloatArgs = [||]
      IntReturnLocation = ArgLocation.Reg(intel Intel.Register.EAX)
      FloatReturnLocation = ArgLocation.Reg(intel Intel.Register.ST0)
      ArgClassification = Independent
      CalleeSavedRegisters =
        set [ intel Intel.Register.EBP
              intel Intel.Register.EBX
              intel Intel.Register.ESI
              intel Intel.Register.EDI ]
      CallerSavedRegisters =
        set [ intel Intel.Register.EAX
              intel Intel.Register.ECX
              intel Intel.Register.EDX ]
      ReturnAddressLocation = OnStack }

  let private linuxX64 () = (* System V AMD64 ABI *)
    { IntArgs =
        [| ArgLocation.Reg(intel Intel.Register.RDI)
           ArgLocation.Reg(intel Intel.Register.RSI)
           ArgLocation.Reg(intel Intel.Register.RDX)
           ArgLocation.Reg(intel Intel.Register.RCX)
           ArgLocation.Reg(intel Intel.Register.R8)
           ArgLocation.Reg(intel Intel.Register.R9)
           ArgLocation.Stack { FirstOffset = 8; SlotSize = 8 } |]
      FloatArgs =
        [| ArgLocation.Reg(intel Intel.Register.XMM0)
           ArgLocation.Reg(intel Intel.Register.XMM1)
           ArgLocation.Reg(intel Intel.Register.XMM2)
           ArgLocation.Reg(intel Intel.Register.XMM3)
           ArgLocation.Reg(intel Intel.Register.XMM4)
           ArgLocation.Reg(intel Intel.Register.XMM5)
           ArgLocation.Reg(intel Intel.Register.XMM6)
           ArgLocation.Reg(intel Intel.Register.XMM7) |]
      IntReturnLocation = ArgLocation.Reg(intel Intel.Register.RAX)
      FloatReturnLocation = ArgLocation.Reg(intel Intel.Register.XMM0)
      ArgClassification = Independent
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
              intel Intel.Register.R11 ]
      ReturnAddressLocation = OnStack }

  /// Returns the VFP doublewords from D(first) to D(last). AAPCS sorts them the
  /// same whichever variant passes the floats, so no variant names them twice.
  let private vfpDoubles first last =
    [ for i in first .. last ->
        arm32 (enum<ARM32.Register>(int ARM32.Register.D0 + i)) ]

  /// Returns where AAPCS passes floats and where it returns one. The VFP
  /// variant passes them in D0 to D7 and returns one in D0, whose low half is
  /// S0; the base standard leaves them to the core registers.
  let private aapcsFloats (isa: ISA) =
    match isa.ARMFloatABI with
    | ARMFloatABI.Hard ->
      let d0 = ArgLocation.Reg(arm32 ARM32.Register.D0)
      [| for d in vfpDoubles 0 7 -> ArgLocation.Reg d |], d0
    | _ ->
      [||], ArgLocation.Reg(arm32 ARM32.Register.R0)

  let private linuxARM32 isa = (* AAPCS (EABI), in either variant *)
    let floatArgs, floatReturn = aapcsFloats isa
    { IntArgs =
        [| ArgLocation.Reg(arm32 ARM32.Register.R0)
           ArgLocation.Reg(arm32 ARM32.Register.R1)
           ArgLocation.Reg(arm32 ARM32.Register.R2)
           ArgLocation.Reg(arm32 ARM32.Register.R3)
           ArgLocation.Stack { FirstOffset = 0; SlotSize = 4 } |]
      FloatArgs = floatArgs
      IntReturnLocation = ArgLocation.Reg(arm32 ARM32.Register.R0)
      FloatReturnLocation = floatReturn
      ArgClassification = Independent
      CalleeSavedRegisters = (* R9 (SB) is the platform's; GNU/Linux keeps it *)
        set [ arm32 ARM32.Register.R4
              arm32 ARM32.Register.R5
              arm32 ARM32.Register.R6
              arm32 ARM32.Register.R7
              arm32 ARM32.Register.R8
              arm32 ARM32.Register.SB
              arm32 ARM32.Register.SL
              arm32 ARM32.Register.FP
              yield! vfpDoubles 8 15 ]
      CallerSavedRegisters =
        set [ arm32 ARM32.Register.R0
              arm32 ARM32.Register.R1
              arm32 ARM32.Register.R2
              arm32 ARM32.Register.R3
              arm32 ARM32.Register.IP
              arm32 ARM32.Register.LR
              yield! vfpDoubles 0 7
              yield! vfpDoubles 16 31 ]
      ReturnAddressLocation = InRegister(arm32 ARM32.Register.LR) }

  /// Returns the general registers from X(first) to X(last).
  let private generals first last =
    [ for i in first .. last ->
        arm64 (enum<ARM64.Register>(int ARM64.Register.X0 + i)) ]

  /// Returns the low 64-bit halves of V(first) to V(last), which are D(first)
  /// to D(last). The lifter keeps a SIMD register in two halves, which are
  /// what a statement writes, and AAPCS64 sorts the two apart.
  let private lowHalves first last =
    [ for i in first .. last ->
        arm64 (enum<ARM64.Register>(int ARM64.Register.V0A + 2 * i)) ]

  /// Returns the high 64-bit halves of V(first) to V(last).
  let private highHalves first last =
    [ for i in first .. last ->
        arm64 (enum<ARM64.Register>(int ARM64.Register.V0B + 2 * i)) ]

  let private linuxAArch64 () = (* AAPCS64 *)
    { IntArgs =
        [| ArgLocation.Reg(arm64 ARM64.Register.X0)
           ArgLocation.Reg(arm64 ARM64.Register.X1)
           ArgLocation.Reg(arm64 ARM64.Register.X2)
           ArgLocation.Reg(arm64 ARM64.Register.X3)
           ArgLocation.Reg(arm64 ARM64.Register.X4)
           ArgLocation.Reg(arm64 ARM64.Register.X5)
           ArgLocation.Reg(arm64 ARM64.Register.X6)
           ArgLocation.Reg(arm64 ARM64.Register.X7)
           ArgLocation.Stack { FirstOffset = 0; SlotSize = 8 } |]
      FloatArgs =
        [| ArgLocation.Reg(arm64 ARM64.Register.V0)
           ArgLocation.Reg(arm64 ARM64.Register.V1)
           ArgLocation.Reg(arm64 ARM64.Register.V2)
           ArgLocation.Reg(arm64 ARM64.Register.V3)
           ArgLocation.Reg(arm64 ARM64.Register.V4)
           ArgLocation.Reg(arm64 ARM64.Register.V5)
           ArgLocation.Reg(arm64 ARM64.Register.V6)
           ArgLocation.Reg(arm64 ARM64.Register.V7) |]
      IntReturnLocation = ArgLocation.Reg(arm64 ARM64.Register.X0)
      FloatReturnLocation = ArgLocation.Reg(arm64 ARM64.Register.V0)
      ArgClassification = Independent
      CalleeSavedRegisters = (* X29 is the frame pointer *)
        set [ yield! generals 19 29
              arm64 ARM64.Register.SP
              yield! lowHalves 8 15 ]
      CallerSavedRegisters = (* X16 to X18 are IP0, IP1 and the platform's *)
        set [ yield! generals 0 18
              arm64 ARM64.Register.X30
              yield! lowHalves 0 7
              yield! lowHalves 16 31
              yield! highHalves 0 31 ]
      ReturnAddressLocation = InRegister(arm64 ARM64.Register.X30) }

  /// Returns the MIPS registers from first to last, by their numbers.
  let private mipsRange (first: MIPS.Register) (last: MIPS.Register) =
    [ for r in int first .. int last -> mips (enum<MIPS.Register> r) ]

  /// Returns the MIPS registers from first to last as argument locations.
  let private mipsArgs first last =
    mipsRange first last |> List.map ArgLocation.Reg

  let private linuxMIPS32 () = (* o32 *)
    { IntArgs =
        [| ArgLocation.Reg(mips MIPS.Register.R4)
           ArgLocation.Reg(mips MIPS.Register.R5)
           ArgLocation.Reg(mips MIPS.Register.R6)
           ArgLocation.Reg(mips MIPS.Register.R7)
           ArgLocation.Stack { FirstOffset = 16; SlotSize = 4 } |]
      FloatArgs =
        [| ArgLocation.Reg(mips MIPS.Register.F12)
           ArgLocation.Reg(mips MIPS.Register.F14) |]
      IntReturnLocation = ArgLocation.Reg(mips MIPS.Register.R2)
      FloatReturnLocation = ArgLocation.Reg(mips MIPS.Register.F0)
      ArgClassification = Independent
      CalleeSavedRegisters = (* R30 is s8, the frame pointer *)
        set [ yield! mipsRange MIPS.Register.R16 MIPS.Register.R23
              mips MIPS.Register.R29
              mips MIPS.Register.R30
              yield! mipsRange MIPS.Register.F20 MIPS.Register.F31 ]
      CallerSavedRegisters = (* gp too: the caller reloads it after a call *)
        set [ yield! mipsRange MIPS.Register.R1 MIPS.Register.R15
              mips MIPS.Register.R24
              mips MIPS.Register.R25
              mips MIPS.Register.R28
              mips MIPS.Register.R31
              mips MIPS.Register.HI
              mips MIPS.Register.LO
              yield! mipsRange MIPS.Register.F0 MIPS.Register.F19 ]
      ReturnAddressLocation = InRegister(mips MIPS.Register.R31) }

  let private linuxMIPS64 () = (* n64 *)
    { IntArgs =
        [| yield! mipsArgs MIPS.Register.R4 MIPS.Register.R11
           ArgLocation.Stack { FirstOffset = 0; SlotSize = 8 } |]
      FloatArgs = [| yield! mipsArgs MIPS.Register.F12 MIPS.Register.F19 |]
      IntReturnLocation = ArgLocation.Reg(mips MIPS.Register.R2)
      FloatReturnLocation = ArgLocation.Reg(mips MIPS.Register.F0)
      ArgClassification = Positional
      CalleeSavedRegisters = (* R28 is gp, R30 s8 *)
        set [ yield! mipsRange MIPS.Register.R16 MIPS.Register.R23
              mips MIPS.Register.R28
              mips MIPS.Register.R29
              mips MIPS.Register.R30
              yield! mipsRange MIPS.Register.F24 MIPS.Register.F31 ]
      CallerSavedRegisters =
        set [ yield! mipsRange MIPS.Register.R1 MIPS.Register.R15
              mips MIPS.Register.R24
              mips MIPS.Register.R25
              mips MIPS.Register.R31
              mips MIPS.Register.HI
              mips MIPS.Register.LO
              yield! mipsRange MIPS.Register.F0 MIPS.Register.F23 ]
      ReturnAddressLocation = InRegister(mips MIPS.Register.R31) }

  let private linuxPPC32 () = (* System V PowerPC ABI *)
    { IntArgs =
        [| ArgLocation.Reg(ppc PPC.Register.R3)
           ArgLocation.Reg(ppc PPC.Register.R4)
           ArgLocation.Reg(ppc PPC.Register.R5)
           ArgLocation.Reg(ppc PPC.Register.R6)
           ArgLocation.Reg(ppc PPC.Register.R7)
           ArgLocation.Reg(ppc PPC.Register.R8)
           ArgLocation.Reg(ppc PPC.Register.R9)
           ArgLocation.Reg(ppc PPC.Register.R10) |]
      FloatArgs =
        [| ArgLocation.Reg(ppc PPC.Register.F1)
           ArgLocation.Reg(ppc PPC.Register.F2)
           ArgLocation.Reg(ppc PPC.Register.F3)
           ArgLocation.Reg(ppc PPC.Register.F4)
           ArgLocation.Reg(ppc PPC.Register.F5)
           ArgLocation.Reg(ppc PPC.Register.F6)
           ArgLocation.Reg(ppc PPC.Register.F7)
           ArgLocation.Reg(ppc PPC.Register.F8) |]
      IntReturnLocation = ArgLocation.Reg(ppc PPC.Register.R3)
      FloatReturnLocation = ArgLocation.Reg(ppc PPC.Register.F1)
      ArgClassification = Independent
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
              ppc PPC.Register.R12 ]
      ReturnAddressLocation = InRegister(ppc PPC.Register.LR) }

  let private linuxPPC64 () = (* Power ELFv2 ABI *)
    { IntArgs =
        [| ArgLocation.Reg(ppc PPC.Register.R3)
           ArgLocation.Reg(ppc PPC.Register.R4)
           ArgLocation.Reg(ppc PPC.Register.R5)
           ArgLocation.Reg(ppc PPC.Register.R6)
           ArgLocation.Reg(ppc PPC.Register.R7)
           ArgLocation.Reg(ppc PPC.Register.R8)
           ArgLocation.Reg(ppc PPC.Register.R9)
           ArgLocation.Reg(ppc PPC.Register.R10) |]
      FloatArgs =
        [| ArgLocation.Reg(ppc PPC.Register.F1)
           ArgLocation.Reg(ppc PPC.Register.F2)
           ArgLocation.Reg(ppc PPC.Register.F3)
           ArgLocation.Reg(ppc PPC.Register.F4)
           ArgLocation.Reg(ppc PPC.Register.F5)
           ArgLocation.Reg(ppc PPC.Register.F6)
           ArgLocation.Reg(ppc PPC.Register.F7)
           ArgLocation.Reg(ppc PPC.Register.F8)
           ArgLocation.Reg(ppc PPC.Register.F9)
           ArgLocation.Reg(ppc PPC.Register.F10)
           ArgLocation.Reg(ppc PPC.Register.F11)
           ArgLocation.Reg(ppc PPC.Register.F12)
           ArgLocation.Reg(ppc PPC.Register.F13) |]
      IntReturnLocation = ArgLocation.Reg(ppc PPC.Register.R3)
      FloatReturnLocation = ArgLocation.Reg(ppc PPC.Register.F1)
      ArgClassification = Independent
      CalleeSavedRegisters =
        set [ ppc PPC.Register.R1
              ppc PPC.Register.R2
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
              ppc PPC.Register.R12 ]
      ReturnAddressLocation = InRegister(ppc PPC.Register.LR) }

  (* RISC-V LP64D and ILP32D, which differ in how wide what a register
     holds is rather than in which register holds it. *)
  let private linuxRISCV () =
    { IntArgs =
        [| ArgLocation.Reg(riscv RISCV.Register.X10)
           ArgLocation.Reg(riscv RISCV.Register.X11)
           ArgLocation.Reg(riscv RISCV.Register.X12)
           ArgLocation.Reg(riscv RISCV.Register.X13)
           ArgLocation.Reg(riscv RISCV.Register.X14)
           ArgLocation.Reg(riscv RISCV.Register.X15)
           ArgLocation.Reg(riscv RISCV.Register.X16)
           ArgLocation.Reg(riscv RISCV.Register.X17) |]
      FloatArgs =
        [| ArgLocation.Reg(riscv RISCV.Register.F10)
           ArgLocation.Reg(riscv RISCV.Register.F11)
           ArgLocation.Reg(riscv RISCV.Register.F12)
           ArgLocation.Reg(riscv RISCV.Register.F13)
           ArgLocation.Reg(riscv RISCV.Register.F14)
           ArgLocation.Reg(riscv RISCV.Register.F15)
           ArgLocation.Reg(riscv RISCV.Register.F16)
           ArgLocation.Reg(riscv RISCV.Register.F17) |]
      IntReturnLocation = ArgLocation.Reg(riscv RISCV.Register.X10)
      FloatReturnLocation = ArgLocation.Reg(riscv RISCV.Register.F10)
      ArgClassification = Independent
      CalleeSavedRegisters =
        set [ riscv RISCV.Register.X2
              riscv RISCV.Register.X8
              riscv RISCV.Register.X9
              riscv RISCV.Register.X18
              riscv RISCV.Register.X19
              riscv RISCV.Register.X20
              riscv RISCV.Register.X21
              riscv RISCV.Register.X22
              riscv RISCV.Register.X23
              riscv RISCV.Register.X24
              riscv RISCV.Register.X25
              riscv RISCV.Register.X26
              riscv RISCV.Register.X27 ]
      CallerSavedRegisters =
        set [ riscv RISCV.Register.X1
              riscv RISCV.Register.X5
              riscv RISCV.Register.X6
              riscv RISCV.Register.X7
              riscv RISCV.Register.X10
              riscv RISCV.Register.X11
              riscv RISCV.Register.X12
              riscv RISCV.Register.X13
              riscv RISCV.Register.X14
              riscv RISCV.Register.X15
              riscv RISCV.Register.X16
              riscv RISCV.Register.X17
              riscv RISCV.Register.X28
              riscv RISCV.Register.X29
              riscv RISCV.Register.X30
              riscv RISCV.Register.X31 ]
      ReturnAddressLocation = InRegister(riscv RISCV.Register.X1) }

  let private linuxSPARC () = (* SPARC: caller's outs become callee's ins *)
    { IntArgs =
        [| ArgLocation.Reg(sparc SPARC.Register.O0)
           ArgLocation.Reg(sparc SPARC.Register.O1)
           ArgLocation.Reg(sparc SPARC.Register.O2)
           ArgLocation.Reg(sparc SPARC.Register.O3)
           ArgLocation.Reg(sparc SPARC.Register.O4)
           ArgLocation.Reg(sparc SPARC.Register.O5) |]
      FloatArgs = [||]
      IntReturnLocation = ArgLocation.Reg(sparc SPARC.Register.O0)
      FloatReturnLocation = ArgLocation.Reg(sparc SPARC.Register.F0)
      ArgClassification = Independent
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
              sparc SPARC.Register.O7 ]
      ReturnAddressLocation = InRegister(sparc SPARC.Register.O7) }

  let private linuxS390 () = (* IBM Z (s390x) ELF ABI *)
    { IntArgs =
        [| ArgLocation.Reg(s390 S390.Register.R2)
           ArgLocation.Reg(s390 S390.Register.R3)
           ArgLocation.Reg(s390 S390.Register.R4)
           ArgLocation.Reg(s390 S390.Register.R5)
           ArgLocation.Reg(s390 S390.Register.R6) |]
      FloatArgs =
        [| ArgLocation.Reg(s390 S390.Register.FPR0)
           ArgLocation.Reg(s390 S390.Register.FPR2)
           ArgLocation.Reg(s390 S390.Register.FPR4)
           ArgLocation.Reg(s390 S390.Register.FPR6) |]
      IntReturnLocation = ArgLocation.Reg(s390 S390.Register.R2)
      FloatReturnLocation = ArgLocation.Reg(s390 S390.Register.FPR0)
      ArgClassification = Independent
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
              s390 S390.Register.R14 ]
      ReturnAddressLocation = InRegister(s390 S390.Register.R14) }

  let private linuxM68K () = (* System V m68k psABI: every argument on the
                                stack, and a return value in D0 or FP0 *)
    { IntArgs = [| ArgLocation.Stack { FirstOffset = 4; SlotSize = 4 } |]
      FloatArgs = [||]
      IntReturnLocation = ArgLocation.Reg(m68k M68K.Register.D0)
      FloatReturnLocation = ArgLocation.Reg(m68k M68K.Register.FP0)
      ArgClassification = Independent
      CalleeSavedRegisters =
        set [ m68k M68K.Register.D2
              m68k M68K.Register.D3
              m68k M68K.Register.D4
              m68k M68K.Register.D5
              m68k M68K.Register.D6
              m68k M68K.Register.D7
              m68k M68K.Register.A2
              m68k M68K.Register.A3
              m68k M68K.Register.A4
              m68k M68K.Register.A5
              m68k M68K.Register.A6 ]
      CallerSavedRegisters =
        set [ m68k M68K.Register.D0
              m68k M68K.Register.D1
              m68k M68K.Register.A0
              m68k M68K.Register.A1 ]
      ReturnAddressLocation = OnStack }

  let private linuxAlpha () = (* the OSF/1 calling standard *)
    (* An argument takes the same numbered slot in either file, so the third
       argument is a2 when it is a word and $f18 when it is a number -- which
       is what Positional says and what tells this ABI from the RISC ones that
       count the two kinds separately. *)
    { IntArgs =
        [| ArgLocation.Reg(alpha Alpha.Register.R16)
           ArgLocation.Reg(alpha Alpha.Register.R17)
           ArgLocation.Reg(alpha Alpha.Register.R18)
           ArgLocation.Reg(alpha Alpha.Register.R19)
           ArgLocation.Reg(alpha Alpha.Register.R20)
           ArgLocation.Reg(alpha Alpha.Register.R21)
           ArgLocation.Stack { FirstOffset = 0; SlotSize = 8 } |]
      FloatArgs =
        [| ArgLocation.Reg(alpha Alpha.Register.F16)
           ArgLocation.Reg(alpha Alpha.Register.F17)
           ArgLocation.Reg(alpha Alpha.Register.F18)
           ArgLocation.Reg(alpha Alpha.Register.F19)
           ArgLocation.Reg(alpha Alpha.Register.F20)
           ArgLocation.Reg(alpha Alpha.Register.F21)
           ArgLocation.Stack { FirstOffset = 0; SlotSize = 8 } |]
      IntReturnLocation = ArgLocation.Reg(alpha Alpha.Register.R0)
      FloatReturnLocation = ArgLocation.Reg(alpha Alpha.Register.F0)
      ArgClassification = Positional
      CalleeSavedRegisters =
        set [ alpha Alpha.Register.R9
              alpha Alpha.Register.R10
              alpha Alpha.Register.R11
              alpha Alpha.Register.R12
              alpha Alpha.Register.R13
              alpha Alpha.Register.R14
              alpha Alpha.Register.R15
              alpha Alpha.Register.R30
              alpha Alpha.Register.F2
              alpha Alpha.Register.F3
              alpha Alpha.Register.F4
              alpha Alpha.Register.F5
              alpha Alpha.Register.F6
              alpha Alpha.Register.F7
              alpha Alpha.Register.F8
              alpha Alpha.Register.F9 ]
      CallerSavedRegisters =
        set [ alpha Alpha.Register.R0
              alpha Alpha.Register.R1
              alpha Alpha.Register.R2
              alpha Alpha.Register.R3
              alpha Alpha.Register.R4
              alpha Alpha.Register.R5
              alpha Alpha.Register.R6
              alpha Alpha.Register.R7
              alpha Alpha.Register.R8
              alpha Alpha.Register.R16
              alpha Alpha.Register.R17
              alpha Alpha.Register.R18
              alpha Alpha.Register.R19
              alpha Alpha.Register.R20
              alpha Alpha.Register.R21
              alpha Alpha.Register.R22
              alpha Alpha.Register.R23
              alpha Alpha.Register.R24
              alpha Alpha.Register.R25
              alpha Alpha.Register.R26
              alpha Alpha.Register.R27
              alpha Alpha.Register.R28
              alpha Alpha.Register.F0
              alpha Alpha.Register.F1
              alpha Alpha.Register.F10
              alpha Alpha.Register.F11
              alpha Alpha.Register.F12
              alpha Alpha.Register.F13
              alpha Alpha.Register.F14
              alpha Alpha.Register.F15 ]
      ReturnAddressLocation = InRegister(alpha Alpha.Register.R26) }

  let private linuxSH4 () = (* Renesas SH ABI; FP arg regs not modeled *)
    { IntArgs =
        [| ArgLocation.Reg(sh4 SH4.Register.R4)
           ArgLocation.Reg(sh4 SH4.Register.R5)
           ArgLocation.Reg(sh4 SH4.Register.R6)
           ArgLocation.Reg(sh4 SH4.Register.R7) |]
      FloatArgs = [||]
      IntReturnLocation = ArgLocation.Reg(sh4 SH4.Register.R0)
      FloatReturnLocation = ArgLocation.Reg(sh4 SH4.Register.FR0)
      ArgClassification = Independent
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
              sh4 SH4.Register.R7 ]
      ReturnAddressLocation = InRegister(sh4 SH4.Register.PR) }

  let private linuxPARISC () = (* PA-RISC: arguments in descending GRs *)
    { IntArgs =
        [| ArgLocation.Reg(parisc PARISC.Register.GR26)
           ArgLocation.Reg(parisc PARISC.Register.GR25)
           ArgLocation.Reg(parisc PARISC.Register.GR24)
           ArgLocation.Reg(parisc PARISC.Register.GR23) |]
      FloatArgs = [||]
      IntReturnLocation = ArgLocation.Reg(parisc PARISC.Register.GR28)
      FloatReturnLocation = ArgLocation.Reg(parisc PARISC.Register.GR28)
      ArgClassification = Independent
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
              parisc PARISC.Register.GR31 ]
      ReturnAddressLocation = InRegister(parisc PARISC.Register.GR2) }

  let private windowsX86 () = (* fastcall: first two args in ECX, EDX *)
    { IntArgs =
        [| ArgLocation.Reg(intel Intel.Register.ECX)
           ArgLocation.Reg(intel Intel.Register.EDX)
           ArgLocation.Stack { FirstOffset = 4; SlotSize = 4 } |]
      FloatArgs = [||]
      IntReturnLocation = ArgLocation.Reg(intel Intel.Register.EAX)
      FloatReturnLocation = ArgLocation.Reg(intel Intel.Register.ST0)
      ArgClassification = Independent
      CalleeSavedRegisters =
        set [ intel Intel.Register.EBX
              intel Intel.Register.EBP
              intel Intel.Register.ESI
              intel Intel.Register.EDI ]
      CallerSavedRegisters =
        set [ intel Intel.Register.EAX
              intel Intel.Register.ECX
              intel Intel.Register.EDX ]
      ReturnAddressLocation = OnStack }

  let private windowsX64 () = (* Microsoft x64: positional XMM arg slots *)
    { IntArgs =
        [| ArgLocation.Reg(intel Intel.Register.RCX)
           ArgLocation.Reg(intel Intel.Register.RDX)
           ArgLocation.Reg(intel Intel.Register.R8)
           ArgLocation.Reg(intel Intel.Register.R9)
           ArgLocation.Stack { FirstOffset = 40; SlotSize = 8 } |]
      FloatArgs =
        [| ArgLocation.Reg(intel Intel.Register.XMM0)
           ArgLocation.Reg(intel Intel.Register.XMM1)
           ArgLocation.Reg(intel Intel.Register.XMM2)
           ArgLocation.Reg(intel Intel.Register.XMM3) |]
      IntReturnLocation = ArgLocation.Reg(intel Intel.Register.RAX)
      FloatReturnLocation = ArgLocation.Reg(intel Intel.Register.XMM0)
      ArgClassification = Positional
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
              intel Intel.Register.R11 ]
      ReturnAddressLocation = OnStack }

  /// Builds the function-call calling convention for the given OS and ISA.
  /// Only Windows diverges from the System V / AAPCS conventions; every other
  /// OS (Linux, macOS, the bare machine, or an unknown OS such as a raw image)
  /// shares them. ISAs we do not model fall back to the System V x64
  /// convention, so this never throws.
  [<CompiledName "Create">]
  let create os isa =
    match os, isa with
    | OS.Windows, X86 -> windowsX86 ()
    | OS.Windows, X64 -> windowsX64 ()
    (* macOS shares the System V / AAPCS conventions for the architectures
       Mach-O targets, so these reuse the builders we model Linux-first. *)
    | OS.MacOSX, X86 -> linuxX86 ()
    | OS.MacOSX, X64 -> linuxX64 ()
    | OS.MacOSX, ARM32 -> linuxARM32 isa
    | OS.MacOSX, AArch64 -> linuxAArch64 ()
    (* Linux and any unknown OS (e.g. a raw image) also follow System V. *)
    | _, X86 -> linuxX86 ()
    | _, ARM32 -> linuxARM32 isa
    | _, AArch64 -> linuxAArch64 ()
    | _, MIPS32 -> linuxMIPS32 ()
    | _, MIPS64 -> linuxMIPS64 ()
    | _, PPC32 -> linuxPPC32 ()
    | _, PPC64 -> linuxPPC64 ()
    | _, RISCV -> linuxRISCV ()
    | _, SPARC -> linuxSPARC ()
    | _, S390 -> linuxS390 ()
    | _, M68K -> linuxM68K ()
    | _, SH4 -> linuxSH4 ()
    | _, Alpha -> linuxAlpha ()
    | _, PARISC -> linuxPARISC ()
    | _ -> linuxX64 ()
