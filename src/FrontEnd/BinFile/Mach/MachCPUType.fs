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

namespace B2R2.FrontEnd.BinFile.Mach

open B2R2

/// CPUType indicates the architecture.
type CPUType =
  | Any = 0xFFFFFFFF
  | VAX = 0x00000001
  | ROMP = 0x00000002
  | NS32032 = 0x00000004
  | NS32332 = 0x00000005
  | MC680x0 = 0x00000006
  | I386 = 0x00000007
  | X64 = 0x01000007
  | MIPS = 0x00000008
  | NS32532 = 0x00000009
  | HPPA = 0x0000000B
  | ARM = 0x0000000C
  | MC88000 = 0x0000000D
  | SPARC = 0x0000000E
  | I860 = 0x0000000F
  | I860LITTLE = 0x00000010
  | RS6000 = 0x00000011
  | POWERPC = 0x00000012
  | ABI64 = 0x01000000
  | POWERPC64 = 0x01000012
  | VEO = 0x000000FF
  | ARM64 = 0x0100000C

/// CPUSubType specifies the exact model of the CPU.
type CPUSubType =
  | MIPSAll = 0
  | MIPSR2300 = 1
  | MIPSR2600 = 2
  | MIPSR2800 = 3
  | MIPSR2000A = 4

module internal CPUType =
  let private toMIPSArch = function
    | CPUSubType.MIPSAll
    | CPUSubType.MIPSR2300
    | CPUSubType.MIPSR2600
    | CPUSubType.MIPSR2800
    | CPUSubType.MIPSR2000A -> Arch.MIPS32 (* MIPS32R2 *)
    | _ -> raise InvalidISAException

  let toArch cputype subtype =
    match cputype with
    | CPUType.I386 -> Arch.IntelX86
    | CPUType.X64 -> Arch.IntelX64
    | CPUType.ARM -> Arch.ARMv7
    | CPUType.ARM64 -> Arch.AARCH64
    | CPUType.MIPS -> toMIPSArch subtype
    | _ -> Arch.UnknownISA
