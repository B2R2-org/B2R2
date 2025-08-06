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

module internal B2R2.FrontEnd.BinFile.ELF.DWRegister

open LanguagePrimitives
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter

let private toIntelx86Register = function
  | 0uy -> Intel.Register.toRegID Intel.Register.EAX
  | 1uy -> Intel.Register.toRegID Intel.Register.ECX
  | 2uy -> Intel.Register.toRegID Intel.Register.EDX
  | 3uy -> Intel.Register.toRegID Intel.Register.EBX
  | 4uy -> Intel.Register.toRegID Intel.Register.ESP
  | 5uy -> Intel.Register.toRegID Intel.Register.EBP
  | 6uy -> Intel.Register.toRegID Intel.Register.ESI
  | 7uy -> Intel.Register.toRegID Intel.Register.EDI
  | 8uy -> Intel.Register.toRegID Intel.Register.EIP
  | _ -> Terminator.futureFeature ()

let private toIntelx64Register = function
  | 0uy -> Intel.Register.toRegID Intel.Register.RAX
  | 1uy -> Intel.Register.toRegID Intel.Register.RDX
  | 2uy -> Intel.Register.toRegID Intel.Register.RCX
  | 3uy -> Intel.Register.toRegID Intel.Register.RBX
  | 4uy -> Intel.Register.toRegID Intel.Register.RSI
  | 5uy -> Intel.Register.toRegID Intel.Register.RDI
  | 6uy -> Intel.Register.toRegID Intel.Register.RBP
  | 7uy -> Intel.Register.toRegID Intel.Register.RSP
  | 8uy -> Intel.Register.toRegID Intel.Register.R8
  | 9uy -> Intel.Register.toRegID Intel.Register.R9
  | 10uy -> Intel.Register.toRegID Intel.Register.R10
  | 11uy -> Intel.Register.toRegID Intel.Register.R11
  | 12uy -> Intel.Register.toRegID Intel.Register.R12
  | 13uy -> Intel.Register.toRegID Intel.Register.R13
  | 14uy -> Intel.Register.toRegID Intel.Register.R14
  | 15uy -> Intel.Register.toRegID Intel.Register.R15
  | 16uy -> Intel.Register.toRegID Intel.Register.RIP
  | 17uy -> Intel.Register.toRegID Intel.Register.XMM0
  | 18uy -> Intel.Register.toRegID Intel.Register.XMM1
  | 19uy -> Intel.Register.toRegID Intel.Register.XMM2
  | 20uy -> Intel.Register.toRegID Intel.Register.XMM3
  | 21uy -> Intel.Register.toRegID Intel.Register.XMM4
  | 22uy -> Intel.Register.toRegID Intel.Register.XMM5
  | 23uy -> Intel.Register.toRegID Intel.Register.XMM6
  | 24uy -> Intel.Register.toRegID Intel.Register.XMM7
  | 25uy -> Intel.Register.toRegID Intel.Register.XMM8
  | 26uy -> Intel.Register.toRegID Intel.Register.XMM9
  | 27uy -> Intel.Register.toRegID Intel.Register.XMM10
  | 28uy -> Intel.Register.toRegID Intel.Register.XMM11
  | 29uy -> Intel.Register.toRegID Intel.Register.XMM12
  | 30uy -> Intel.Register.toRegID Intel.Register.XMM13
  | 31uy -> Intel.Register.toRegID Intel.Register.XMM14
  | 32uy -> Intel.Register.toRegID Intel.Register.XMM15
  | _ -> Terminator.futureFeature ()

let private toAArch64Register = function
  | 0uy -> ARM64.Register.toRegID ARM64.Register.X0
  | 1uy -> ARM64.Register.toRegID ARM64.Register.X1
  | 2uy -> ARM64.Register.toRegID ARM64.Register.X2
  | 3uy -> ARM64.Register.toRegID ARM64.Register.X3
  | 4uy -> ARM64.Register.toRegID ARM64.Register.X4
  | 5uy -> ARM64.Register.toRegID ARM64.Register.X5
  | 6uy -> ARM64.Register.toRegID ARM64.Register.X6
  | 7uy -> ARM64.Register.toRegID ARM64.Register.X7
  | 8uy -> ARM64.Register.toRegID ARM64.Register.X8
  | 9uy -> ARM64.Register.toRegID ARM64.Register.X9
  | 10uy -> ARM64.Register.toRegID ARM64.Register.X10
  | 11uy -> ARM64.Register.toRegID ARM64.Register.X11
  | 12uy -> ARM64.Register.toRegID ARM64.Register.X12
  | 13uy -> ARM64.Register.toRegID ARM64.Register.X13
  | 14uy -> ARM64.Register.toRegID ARM64.Register.X14
  | 15uy -> ARM64.Register.toRegID ARM64.Register.X15
  | 16uy -> ARM64.Register.toRegID ARM64.Register.X16
  | 17uy -> ARM64.Register.toRegID ARM64.Register.X17
  | 18uy -> ARM64.Register.toRegID ARM64.Register.X18
  | 19uy -> ARM64.Register.toRegID ARM64.Register.X19
  | 20uy -> ARM64.Register.toRegID ARM64.Register.X20
  | 21uy -> ARM64.Register.toRegID ARM64.Register.X21
  | 22uy -> ARM64.Register.toRegID ARM64.Register.X22
  | 23uy -> ARM64.Register.toRegID ARM64.Register.X23
  | 24uy -> ARM64.Register.toRegID ARM64.Register.X24
  | 25uy -> ARM64.Register.toRegID ARM64.Register.X25
  | 26uy -> ARM64.Register.toRegID ARM64.Register.X26
  | 27uy -> ARM64.Register.toRegID ARM64.Register.X27
  | 28uy -> ARM64.Register.toRegID ARM64.Register.X28
  | 29uy -> ARM64.Register.toRegID ARM64.Register.X29
  | 30uy -> ARM64.Register.toRegID ARM64.Register.X30
  | 31uy -> ARM64.Register.toRegID ARM64.Register.SP
  | 64uy -> ARM64.Register.toRegID ARM64.Register.V0
  | 65uy -> ARM64.Register.toRegID ARM64.Register.V1
  | 66uy -> ARM64.Register.toRegID ARM64.Register.V2
  | 67uy -> ARM64.Register.toRegID ARM64.Register.V3
  | 68uy -> ARM64.Register.toRegID ARM64.Register.V4
  | 69uy -> ARM64.Register.toRegID ARM64.Register.V5
  | 70uy -> ARM64.Register.toRegID ARM64.Register.V6
  | 71uy -> ARM64.Register.toRegID ARM64.Register.V7
  | 72uy -> ARM64.Register.toRegID ARM64.Register.V8
  | 73uy -> ARM64.Register.toRegID ARM64.Register.V9
  | 74uy -> ARM64.Register.toRegID ARM64.Register.V10
  | 75uy -> ARM64.Register.toRegID ARM64.Register.V11
  | 76uy -> ARM64.Register.toRegID ARM64.Register.V12
  | 77uy -> ARM64.Register.toRegID ARM64.Register.V13
  | 78uy -> ARM64.Register.toRegID ARM64.Register.V14
  | 79uy -> ARM64.Register.toRegID ARM64.Register.V15
  | 80uy -> ARM64.Register.toRegID ARM64.Register.V16
  | 81uy -> ARM64.Register.toRegID ARM64.Register.V17
  | 82uy -> ARM64.Register.toRegID ARM64.Register.V18
  | 83uy -> ARM64.Register.toRegID ARM64.Register.V19
  | 84uy -> ARM64.Register.toRegID ARM64.Register.V20
  | 85uy -> ARM64.Register.toRegID ARM64.Register.V21
  | 86uy -> ARM64.Register.toRegID ARM64.Register.V22
  | 87uy -> ARM64.Register.toRegID ARM64.Register.V23
  | 88uy -> ARM64.Register.toRegID ARM64.Register.V24
  | 89uy -> ARM64.Register.toRegID ARM64.Register.V25
  | 90uy -> ARM64.Register.toRegID ARM64.Register.V26
  | 91uy -> ARM64.Register.toRegID ARM64.Register.V27
  | 92uy -> ARM64.Register.toRegID ARM64.Register.V28
  | 93uy -> ARM64.Register.toRegID ARM64.Register.V29
  | 94uy -> ARM64.Register.toRegID ARM64.Register.V30
  | 95uy -> ARM64.Register.toRegID ARM64.Register.V31
  | x -> Terminator.futureFeature ()

let private toMIPSRegister (n: byte) =
  MIPS.Register.toRegID (EnumOfValue(int n))

let private toRISCVRegister (n: byte) =
  RISCV64.Register.toRegID (EnumOfValue(int n))

let private toPPC32Register (n: byte) =
  PPC32.Register.toRegID (EnumOfValue(int n))

let private toSH4Register (n: byte) =
  SH4.Register.toRegID (EnumOfValue(int n))

let toRegID isa regnum =
  match isa with
  | X86 -> toIntelx86Register regnum
  | X64 -> toIntelx64Register regnum
  | AArch64 -> toAArch64Register regnum
  | MIPS -> toMIPSRegister regnum
  | RISCV64 -> toRISCVRegister regnum
  | PPC32 -> toPPC32Register regnum
  | SH4 -> toSH4Register regnum
  | _ -> Terminator.futureFeature ()

let toRegisterExpr isa (regFactory: IRegisterFactory) regnum =
  toRegID isa regnum |> regFactory.GetRegVar
