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
open B2R2.FrontEnd.Register

[<CompiledName("VolatileRegisters")>]
let volatileRegisters (hdl: BinHandle) =
  match hdl.File.ISA.Arch with
  | Architecture.IntelX86 ->
    [ Intel.EAX; Intel.ECX; Intel.EDX ]
    |> List.map IntelRegister.ID
  | Architecture.IntelX64 ->
    [ Intel.RAX; Intel.RCX; Intel.RDX; Intel.R8; Intel.R9; Intel.R10;
      Intel.R11 ]
    |> List.map IntelRegister.ID
  | Architecture.ARMv7
  | Architecture.AARCH32 ->
    [ ARM32.R0; ARM32.R1; ARM32.R2; ARM32.R3 ]
    |> List.map ARM32Register.ID
  | _ -> Utils.futureFeature ()

[<CompiledName("ReturnRegister")>]
let returnRegister (hdl: BinHandle) =
  match hdl.File.ISA.Arch with
  | Architecture.IntelX86 -> Intel.EAX |> IntelRegister.ID
  | Architecture.IntelX64 -> Intel.RAX |> IntelRegister.ID
  | Architecture.ARMv7
  | Architecture.AARCH32 -> ARM32.R0 |> ARM32Register.ID
  | Architecture.AARCH64 -> ARM64.X0 |> ARM64Register.ID
  | Architecture.MIPS32 | Architecture.MIPS64 -> MIPS.R2 |> MIPSRegister.ID
  | _ -> Utils.futureFeature ()

[<CompiledName("SyscallNumRegister")>]
let syscallNumRegister (hdl: BinHandle) =
  match hdl.File.ISA.Arch with
  | Architecture.IntelX86 -> Intel.EAX |> IntelRegister.ID
  | Architecture.IntelX64 -> Intel.RAX |> IntelRegister.ID
  | Architecture.ARMv7
  | Architecture.AARCH32 -> ARM32.R7 |> ARM32Register.ID
  | Architecture.AARCH64 -> ARM64.X8 |> ARM64Register.ID
  | Architecture.MIPS32 | Architecture.MIPS64 -> MIPS.R2 |> MIPSRegister.ID
  | _ -> Utils.futureFeature ()

[<CompiledName("SyscallArgRegister")>]
let syscallArgRegister (hdl: BinHandle) os num =
  match os, hdl.File.ISA.Arch with
  | OS.Linux, Architecture.IntelX86 ->
    match num with
    | 1 -> Intel.EBX |> IntelRegister.ID
    | 2 -> Intel.ECX |> IntelRegister.ID
    | 3 -> Intel.EDX |> IntelRegister.ID
    | 4 -> Intel.ESI |> IntelRegister.ID
    | 5 -> Intel.EDI |> IntelRegister.ID
    | 6 -> Intel.EBP |> IntelRegister.ID
    | _ -> Utils.impossible ()
  | OS.Linux, Architecture.IntelX64 ->
    match num with
    | 1 -> Intel.RDI |> IntelRegister.ID
    | 2 -> Intel.RSI |> IntelRegister.ID
    | 3 -> Intel.RDX |> IntelRegister.ID
    | 4 -> Intel.R10 |> IntelRegister.ID
    | 5 -> Intel.R8 |> IntelRegister.ID
    | 6 -> Intel.R9 |> IntelRegister.ID
    | _ -> Utils.impossible ()
  | OS.Linux, Architecture.ARMv7
  | OS.Linux, Architecture.AARCH32 ->
    match num with
    | 1 -> ARM32.R0 |> ARM32Register.ID
    | 2 -> ARM32.R1 |> ARM32Register.ID
    | 3 -> ARM32.R2 |> ARM32Register.ID
    | 4 -> ARM32.R3 |> ARM32Register.ID
    | 5 -> ARM32.R4 |> ARM32Register.ID
    | 6 -> ARM32.R5 |> ARM32Register.ID
    | _ -> Utils.impossible ()
  | OS.Linux, Architecture.AARCH64 ->
    match num with
    | 1 -> ARM64.X0 |> ARM64Register.ID
    | 2 -> ARM64.X1 |> ARM64Register.ID
    | 3 -> ARM64.X2 |> ARM64Register.ID
    | 4 -> ARM64.X3 |> ARM64Register.ID
    | 5 -> ARM64.X4 |> ARM64Register.ID
    | 6 -> ARM64.X5 |> ARM64Register.ID
    | _ -> Utils.impossible ()
  | OS.Linux, Architecture.MIPS32 | OS.Linux, Architecture.MIPS64 ->
    match num with
    | 1 -> MIPS.R4 |> MIPSRegister.ID
    | 2 -> MIPS.R5 |> MIPSRegister.ID
    | 3 -> MIPS.R6 |> MIPSRegister.ID
    | 4 -> MIPS.R7 |> MIPSRegister.ID
    | 5 -> MIPS.R8 |> MIPSRegister.ID
    | 6 -> MIPS.R9 |> MIPSRegister.ID
    | _ -> Utils.impossible ()
  | _ -> Utils.futureFeature ()

[<CompiledName("FunctionArgRegister")>]
let functionArgRegister (hdl: BinHandle) os num =
  match os, hdl.File.ISA.Arch with
  | OS.Windows, Architecture.IntelX86 -> (* fast call *)
    match num with
    | 1 -> Intel.ECX |> IntelRegister.ID
    | 2 -> Intel.EDX |> IntelRegister.ID
    | _ -> Utils.impossible ()
  | OS.Linux, Architecture.IntelX64 -> (* System V *)
    match num with
    | 1 -> Intel.RDI |> IntelRegister.ID
    | 2 -> Intel.RSI |> IntelRegister.ID
    | 3 -> Intel.RDX |> IntelRegister.ID
    | 4 -> Intel.RCX |> IntelRegister.ID
    | 5 -> Intel.R8 |> IntelRegister.ID
    | 6 -> Intel.R9 |> IntelRegister.ID
    | _ -> Utils.impossible ()
  | OS.Windows, Architecture.IntelX64 ->
    match num with
    | 1 -> Intel.RCX |> IntelRegister.ID
    | 2 -> Intel.RDX |> IntelRegister.ID
    | 3 -> Intel.R8 |> IntelRegister.ID
    | 4 -> Intel.R9 |> IntelRegister.ID
    | _ -> Utils.impossible ()
  | _ -> Utils.futureFeature ()

[<CompiledName("IsNonVolatile")>]
let isNonVolatile (hdl: BinHandle) os rid =
  match os, hdl.File.ISA.Arch with
  | OS.Linux, Architecture.IntelX86 -> (* CDECL *)
    rid = (Intel.EBP |> IntelRegister.ID)
    || rid = (Intel.EBX |> IntelRegister.ID)
    || rid = (Intel.ESI |> IntelRegister.ID)
    || rid = (Intel.EDI |> IntelRegister.ID)
  | OS.Linux, Architecture.IntelX64 -> (* CDECL *)
    rid = (Intel.RBX |> IntelRegister.ID)
    || rid = (Intel.RSP |> IntelRegister.ID)
    || rid = (Intel.RBP |> IntelRegister.ID)
    || rid = (Intel.R12 |> IntelRegister.ID)
    || rid = (Intel.R13 |> IntelRegister.ID)
    || rid = (Intel.R14 |> IntelRegister.ID)
    || rid = (Intel.R15 |> IntelRegister.ID)
  | OS.Linux, Architecture.ARMv7 -> (* EABI *)
    rid = (ARM32.R4 |> ARM32Register.ID)
    || rid = (ARM32.R5 |> ARM32Register.ID)
    || rid = (ARM32.R6 |> ARM32Register.ID)
    || rid = (ARM32.R7 |> ARM32Register.ID)
    || rid = (ARM32.R8 |> ARM32Register.ID)
    || rid = (ARM32.SL |> ARM32Register.ID)
    || rid = (ARM32.FP |> ARM32Register.ID)
  | OS.Linux, Architecture.AARCH64 -> (* EABI *)
    rid = (ARM64.X19 |> ARM64Register.ID)
    || rid = (ARM64.X20 |> ARM64Register.ID)
    || rid = (ARM64.X21 |> ARM64Register.ID)
    || rid = (ARM64.X22 |> ARM64Register.ID)
    || rid = (ARM64.X23 |> ARM64Register.ID)
    || rid = (ARM64.X24 |> ARM64Register.ID)
    || rid = (ARM64.X25 |> ARM64Register.ID)
    || rid = (ARM64.X26 |> ARM64Register.ID)
    || rid = (ARM64.X27 |> ARM64Register.ID)
    || rid = (ARM64.X28 |> ARM64Register.ID)
    || rid = (ARM64.X29 |> ARM64Register.ID)
  | OS.Linux, Architecture.MIPS32 | OS.Linux, Architecture.MIPS64 ->
    rid = (MIPS.R16 |> MIPSRegister.ID)
    || rid = (MIPS.R17 |> MIPSRegister.ID)
    || rid = (MIPS.R18 |> MIPSRegister.ID)
    || rid = (MIPS.R19 |> MIPSRegister.ID)
    || rid = (MIPS.R20 |> MIPSRegister.ID)
    || rid = (MIPS.R21 |> MIPSRegister.ID)
    || rid = (MIPS.R22 |> MIPSRegister.ID)
    || rid = (MIPS.R23 |> MIPSRegister.ID)
    || rid = (MIPS.R30 |> MIPSRegister.ID)
  | OS.Windows, Architecture.IntelX64 -> (* Microsoft x64 *)
    rid = (Intel.RBX |> IntelRegister.ID)
    || rid = (Intel.RSP |> IntelRegister.ID)
    || rid = (Intel.RBP |> IntelRegister.ID)
    || rid = (Intel.RDI |> IntelRegister.ID)
    || rid = (Intel.RSI |> IntelRegister.ID)
    || rid = (Intel.R12 |> IntelRegister.ID)
    || rid = (Intel.R13 |> IntelRegister.ID)
    || rid = (Intel.R14 |> IntelRegister.ID)
    || rid = (Intel.R15 |> IntelRegister.ID)
  | _ -> false (* FIXME *)
