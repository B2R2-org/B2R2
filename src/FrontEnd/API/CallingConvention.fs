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

module B2R2.FrontEnd.CallingConvention

open B2R2
open B2R2.FrontEnd.BinLifter

[<CompiledName("VolatileRegisters")>]
let volatileRegisters (hdl: BinHandle) =
  match hdl.File.ISA.Arch with
  | Architecture.IntelX86 ->
    [ Intel.Register.EAX; Intel.Register.ECX; Intel.Register.EDX ]
    |> List.map Intel.Register.toRegID
  | Architecture.IntelX64 ->
    [ Intel.Register.RAX
      Intel.Register.RCX
      Intel.Register.RDX
      Intel.Register.R8
      Intel.Register.R9
      Intel.Register.R10
      Intel.Register.R11 ]
    |> List.map Intel.Register.toRegID
  | Architecture.ARMv7
  | Architecture.AARCH32 ->
    [ ARM32.Register.R0
      ARM32.Register.R1
      ARM32.Register.R2
      ARM32.Register.R3 ]
    |> List.map ARM32.Register.toRegID
  | Architecture.AARCH64 ->
    [ ARM64.Register.X9
      ARM64.Register.X10
      ARM64.Register.X11
      ARM64.Register.X12
      ARM64.Register.X13
      ARM64.Register.X14
      ARM64.Register.X15 ]
    |> List.map ARM64.Register.toRegID
  | Architecture.MIPS32
  | Architecture.MIPS64 ->
    [ MIPS.Register.R8
      MIPS.Register.R9
      MIPS.Register.R10
      MIPS.Register.R11
      MIPS.Register.R12
      MIPS.Register.R13
      MIPS.Register.R14
      MIPS.Register.R15 ]
    |> List.map MIPS.Register.toRegID
  | _ -> Terminator.futureFeature ()

[<CompiledName("ReturnRegister")>]
let returnRegister (hdl: BinHandle) =
  match hdl.File.ISA.Arch with
  | Architecture.IntelX86 ->
    Intel.Register.EAX |> Intel.Register.toRegID
  | Architecture.IntelX64 ->
    Intel.Register.RAX |> Intel.Register.toRegID
  | Architecture.ARMv7
  | Architecture.AARCH32 ->
    ARM32.Register.R0 |> ARM32.Register.toRegID
  | Architecture.AARCH64 ->
    ARM64.Register.X0 |> ARM64.Register.toRegID
  | Architecture.MIPS32 | Architecture.MIPS64 ->
    MIPS.Register.R2 |> MIPS.Register.toRegID
  | _ -> Terminator.futureFeature ()

[<CompiledName("SyscallNumRegister")>]
let syscallNumRegister (hdl: BinHandle) =
  match hdl.File.ISA.Arch with
  | Architecture.IntelX86 ->
    Intel.Register.EAX |> Intel.Register.toRegID
  | Architecture.IntelX64 ->
    Intel.Register.RAX |> Intel.Register.toRegID
  | Architecture.ARMv7
  | Architecture.AARCH32 ->
    ARM32.Register.R7 |> ARM32.Register.toRegID
  | Architecture.AARCH64 ->
    ARM64.Register.X8 |> ARM64.Register.toRegID
  | Architecture.MIPS32 | Architecture.MIPS64 ->
    MIPS.Register.R2 |> MIPS.Register.toRegID
  | _ -> Terminator.futureFeature ()

[<CompiledName("SyscallArgRegister")>]
let syscallArgRegister (hdl: BinHandle) os num =
  match os, hdl.File.ISA.Arch with
  | OS.Linux, Architecture.IntelX86 ->
    match num with
    | 1 -> Intel.Register.EBX |> Intel.Register.toRegID
    | 2 -> Intel.Register.ECX |> Intel.Register.toRegID
    | 3 -> Intel.Register.EDX |> Intel.Register.toRegID
    | 4 -> Intel.Register.ESI |> Intel.Register.toRegID
    | 5 -> Intel.Register.EDI |> Intel.Register.toRegID
    | 6 -> Intel.Register.EBP |> Intel.Register.toRegID
    | _ -> Terminator.impossible ()
  | OS.Linux, Architecture.IntelX64 ->
    match num with
    | 1 -> Intel.Register.RDI |> Intel.Register.toRegID
    | 2 -> Intel.Register.RSI |> Intel.Register.toRegID
    | 3 -> Intel.Register.RDX |> Intel.Register.toRegID
    | 4 -> Intel.Register.R10 |> Intel.Register.toRegID
    | 5 -> Intel.Register.R8 |> Intel.Register.toRegID
    | 6 -> Intel.Register.R9 |> Intel.Register.toRegID
    | _ -> Terminator.impossible ()
  | OS.Linux, Architecture.ARMv7
  | OS.Linux, Architecture.AARCH32 ->
    match num with
    | 1 -> ARM32.Register.R0 |> ARM32.Register.toRegID
    | 2 -> ARM32.Register.R1 |> ARM32.Register.toRegID
    | 3 -> ARM32.Register.R2 |> ARM32.Register.toRegID
    | 4 -> ARM32.Register.R3 |> ARM32.Register.toRegID
    | 5 -> ARM32.Register.R4 |> ARM32.Register.toRegID
    | 6 -> ARM32.Register.R5 |> ARM32.Register.toRegID
    | _ -> Terminator.impossible ()
  | OS.Linux, Architecture.AARCH64 ->
    match num with
    | 1 -> ARM64.Register.X0 |> ARM64.Register.toRegID
    | 2 -> ARM64.Register.X1 |> ARM64.Register.toRegID
    | 3 -> ARM64.Register.X2 |> ARM64.Register.toRegID
    | 4 -> ARM64.Register.X3 |> ARM64.Register.toRegID
    | 5 -> ARM64.Register.X4 |> ARM64.Register.toRegID
    | 6 -> ARM64.Register.X5 |> ARM64.Register.toRegID
    | _ -> Terminator.impossible ()
  | OS.Linux, Architecture.MIPS32 | OS.Linux, Architecture.MIPS64 ->
    match num with
    | 1 -> MIPS.Register.R4 |> MIPS.Register.toRegID
    | 2 -> MIPS.Register.R5 |> MIPS.Register.toRegID
    | 3 -> MIPS.Register.R6 |> MIPS.Register.toRegID
    | 4 -> MIPS.Register.R7 |> MIPS.Register.toRegID
    | 5 -> MIPS.Register.R8 |> MIPS.Register.toRegID
    | 6 -> MIPS.Register.R9 |> MIPS.Register.toRegID
    | _ -> Terminator.impossible ()
  | _ -> Terminator.futureFeature ()

[<CompiledName("FunctionArgRegister")>]
let functionArgRegister (hdl: BinHandle) os num =
  match os, hdl.File.ISA.Arch with
  | OS.Windows, Architecture.IntelX86 -> (* fast call *)
    match num with
    | 1 -> Intel.Register.ECX |> Intel.Register.toRegID
    | 2 -> Intel.Register.EDX |> Intel.Register.toRegID
    | _ -> Terminator.impossible ()
  | OS.Linux, Architecture.IntelX64 -> (* System V *)
    match num with
    | 1 -> Intel.Register.RDI |> Intel.Register.toRegID
    | 2 -> Intel.Register.RSI |> Intel.Register.toRegID
    | 3 -> Intel.Register.RDX |> Intel.Register.toRegID
    | 4 -> Intel.Register.RCX |> Intel.Register.toRegID
    | 5 -> Intel.Register.R8 |> Intel.Register.toRegID
    | 6 -> Intel.Register.R9 |> Intel.Register.toRegID
    | _ -> Terminator.impossible ()
  | OS.Windows, Architecture.IntelX64 ->
    match num with
    | 1 -> Intel.Register.RCX |> Intel.Register.toRegID
    | 2 -> Intel.Register.RDX |> Intel.Register.toRegID
    | 3 -> Intel.Register.R8 |> Intel.Register.toRegID
    | 4 -> Intel.Register.R9 |> Intel.Register.toRegID
    | _ -> Terminator.impossible ()
  | _ -> Terminator.futureFeature ()

[<CompiledName("IsNonVolatile")>]
let isNonVolatile (hdl: BinHandle) os rid =
  match os, hdl.File.ISA.Arch with
  | OS.Linux, Architecture.IntelX86 -> (* CDECL *)
    rid = (Intel.Register.EBP |> Intel.Register.toRegID)
    || rid = (Intel.Register.EBX |> Intel.Register.toRegID)
    || rid = (Intel.Register.ESI |> Intel.Register.toRegID)
    || rid = (Intel.Register.EDI |> Intel.Register.toRegID)
  | OS.Linux, Architecture.IntelX64 -> (* CDECL *)
    rid = (Intel.Register.RBX |> Intel.Register.toRegID)
    || rid = (Intel.Register.RSP |> Intel.Register.toRegID)
    || rid = (Intel.Register.RBP |> Intel.Register.toRegID)
    || rid = (Intel.Register.R12 |> Intel.Register.toRegID)
    || rid = (Intel.Register.R13 |> Intel.Register.toRegID)
    || rid = (Intel.Register.R14 |> Intel.Register.toRegID)
    || rid = (Intel.Register.R15 |> Intel.Register.toRegID)
  | OS.Linux, Architecture.ARMv7 -> (* EABI *)
    rid = (ARM32.Register.R4 |> ARM32.Register.toRegID)
    || rid = (ARM32.Register.R5 |> ARM32.Register.toRegID)
    || rid = (ARM32.Register.R6 |> ARM32.Register.toRegID)
    || rid = (ARM32.Register.R7 |> ARM32.Register.toRegID)
    || rid = (ARM32.Register.R8 |> ARM32.Register.toRegID)
    || rid = (ARM32.Register.SL |> ARM32.Register.toRegID)
    || rid = (ARM32.Register.FP |> ARM32.Register.toRegID)
  | OS.Linux, Architecture.AARCH64 -> (* EABI *)
    rid = (ARM64.Register.X19 |> ARM64.Register.toRegID)
    || rid = (ARM64.Register.X20 |> ARM64.Register.toRegID)
    || rid = (ARM64.Register.X21 |> ARM64.Register.toRegID)
    || rid = (ARM64.Register.X22 |> ARM64.Register.toRegID)
    || rid = (ARM64.Register.X23 |> ARM64.Register.toRegID)
    || rid = (ARM64.Register.X24 |> ARM64.Register.toRegID)
    || rid = (ARM64.Register.X25 |> ARM64.Register.toRegID)
    || rid = (ARM64.Register.X26 |> ARM64.Register.toRegID)
    || rid = (ARM64.Register.X27 |> ARM64.Register.toRegID)
    || rid = (ARM64.Register.X28 |> ARM64.Register.toRegID)
    || rid = (ARM64.Register.X29 |> ARM64.Register.toRegID)
  | OS.Linux, Architecture.MIPS32 | OS.Linux, Architecture.MIPS64 ->
    rid = (MIPS.Register.R16 |> MIPS.Register.toRegID)
    || rid = (MIPS.Register.R17 |> MIPS.Register.toRegID)
    || rid = (MIPS.Register.R18 |> MIPS.Register.toRegID)
    || rid = (MIPS.Register.R19 |> MIPS.Register.toRegID)
    || rid = (MIPS.Register.R20 |> MIPS.Register.toRegID)
    || rid = (MIPS.Register.R21 |> MIPS.Register.toRegID)
    || rid = (MIPS.Register.R22 |> MIPS.Register.toRegID)
    || rid = (MIPS.Register.R23 |> MIPS.Register.toRegID)
    || rid = (MIPS.Register.R30 |> MIPS.Register.toRegID)
  | OS.Windows, Architecture.IntelX64 -> (* Microsoft x64 *)
    rid = (Intel.Register.RBX |> Intel.Register.toRegID)
    || rid = (Intel.Register.RSP |> Intel.Register.toRegID)
    || rid = (Intel.Register.RBP |> Intel.Register.toRegID)
    || rid = (Intel.Register.RDI |> Intel.Register.toRegID)
    || rid = (Intel.Register.RSI |> Intel.Register.toRegID)
    || rid = (Intel.Register.R12 |> Intel.Register.toRegID)
    || rid = (Intel.Register.R13 |> Intel.Register.toRegID)
    || rid = (Intel.Register.R14 |> Intel.Register.toRegID)
    || rid = (Intel.Register.R15 |> Intel.Register.toRegID)
  | _ -> false (* FIXME *)
