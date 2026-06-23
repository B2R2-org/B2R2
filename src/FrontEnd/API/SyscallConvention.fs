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

/// Builds the system-call convention for a given binary. This is the front-end
/// factory that turns a BinHandle into the architecture-independent
/// SyscallConvention type defined in B2R2.Core. The target OS is derived from
/// the binary's file format.
[<RequireQualifiedAccess>]
module B2R2.FrontEnd.SyscallConvention

open B2R2
open B2R2.FrontEnd.BinFile

let inline private intel r = Intel.Register.toRegID r

let inline private arm32 r = ARM32.Register.toRegID r

let inline private arm64 r = ARM64.Register.toRegID r

let inline private mips r = MIPS.Register.toRegID r

let private reg r = ArgLocation.Reg r

let private linuxX86 () =
  { NumberRegister = intel Intel.Register.EAX
    ReturnRegister = intel Intel.Register.EAX
    Args =
      [| reg (intel Intel.Register.EBX)
         reg (intel Intel.Register.ECX)
         reg (intel Intel.Register.EDX)
         reg (intel Intel.Register.ESI)
         reg (intel Intel.Register.EDI)
         reg (intel Intel.Register.EBP) |] }

let private linuxX64 () =
  { NumberRegister = intel Intel.Register.RAX
    ReturnRegister = intel Intel.Register.RAX
    Args =
      [| reg (intel Intel.Register.RDI)
         reg (intel Intel.Register.RSI)
         reg (intel Intel.Register.RDX)
         reg (intel Intel.Register.R10)
         reg (intel Intel.Register.R8)
         reg (intel Intel.Register.R9) |] }

let private linuxARM32 () =
  { NumberRegister = arm32 ARM32.Register.R7
    ReturnRegister = arm32 ARM32.Register.R0
    Args =
      [| reg (arm32 ARM32.Register.R0)
         reg (arm32 ARM32.Register.R1)
         reg (arm32 ARM32.Register.R2)
         reg (arm32 ARM32.Register.R3)
         reg (arm32 ARM32.Register.R4)
         reg (arm32 ARM32.Register.R5) |] }

let private linuxAArch64 () =
  { NumberRegister = arm64 ARM64.Register.X8
    ReturnRegister = arm64 ARM64.Register.X0
    Args =
      [| reg (arm64 ARM64.Register.X0)
         reg (arm64 ARM64.Register.X1)
         reg (arm64 ARM64.Register.X2)
         reg (arm64 ARM64.Register.X3)
         reg (arm64 ARM64.Register.X4)
         reg (arm64 ARM64.Register.X5) |] }

let private linuxMIPS () =
  { NumberRegister = mips MIPS.Register.R2
    ReturnRegister = mips MIPS.Register.R2
    Args =
      [| reg (mips MIPS.Register.R4)
         reg (mips MIPS.Register.R5)
         reg (mips MIPS.Register.R6)
         reg (mips MIPS.Register.R7)
         reg (mips MIPS.Register.R8)
         reg (mips MIPS.Register.R9) |] }

let private windowsX86 () = (* args on the stack via the stdcall Nt* stub *)
  { NumberRegister = intel Intel.Register.EAX
    ReturnRegister = intel Intel.Register.EAX
    Args = [| ArgLocation.Stack { FirstOffset = 4; SlotSize = 4 } |] }

let private windowsX64 () = (* first arg in R10, not RCX *)
  { NumberRegister = intel Intel.Register.RAX
    ReturnRegister = intel Intel.Register.RAX
    Args =
      [| reg (intel Intel.Register.R10)
         reg (intel Intel.Register.RDX)
         reg (intel Intel.Register.R8)
         reg (intel Intel.Register.R9)
         ArgLocation.Stack { FirstOffset = 40; SlotSize = 8 } |] }

/// Builds the system-call convention for the given handle. Combinations we do
/// not model fall back to the Linux x64 syscall convention, so this never
/// throws.
let create format isa =
  match format, isa with
  | FileFormat.ELFBinary, X86 -> linuxX86 ()
  | FileFormat.ELFBinary, ARM32 -> linuxARM32 ()
  | FileFormat.ELFBinary, AArch64 -> linuxAArch64 ()
  | FileFormat.ELFBinary, MIPS -> linuxMIPS ()
  | FileFormat.PEBinary, X86 -> windowsX86 ()
  | FileFormat.PEBinary, X64 -> windowsX64 ()
  | _ -> linuxX64 ()
