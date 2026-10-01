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

/// Provides active patterns for matching against specific ISAs.
[<AutoOpen>]
module ISAPatterns =
  [<return: Struct>]
  let (|X86|_|) (isa: ISA) =
    match isa.Arch, isa.WordSize with
    | Architecture.Intel, WordSize.Bit32 -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|X64|_|) (isa: ISA) =
    match isa.Arch, isa.WordSize with
    | Architecture.Intel, WordSize.Bit64 -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|Intel|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.Intel -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|ARMv7|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.ARMv7 -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|ARM32|_|) (isa: ISA) =
    match isa.Arch, isa.WordSize with
    | Architecture.ARMv7, _
    | Architecture.ARMv8, WordSize.Bit32 -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|AArch64|_|) (isa: ISA) =
    match isa.Arch, isa.WordSize with
    | Architecture.ARMv8, WordSize.Bit64 -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|MIPS|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.MIPS -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|MIPS32|_|) (isa: ISA) =
    match isa.Arch, isa.WordSize with
    | Architecture.MIPS, WordSize.Bit32 -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|MIPS64|_|) (isa: ISA) =
    match isa.Arch, isa.WordSize with
    | Architecture.MIPS, WordSize.Bit64 -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|PPC|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.PPC -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|PPC32|_|) (isa: ISA) =
    match isa.Arch, isa.WordSize with
    | Architecture.PPC, WordSize.Bit32 -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|PPC64|_|) (isa: ISA) =
    match isa.Arch, isa.WordSize with
    | Architecture.PPC, WordSize.Bit64 -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|RISCV|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.RISCV -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|RISCV32|_|) (isa: ISA) =
    match isa.Arch, isa.WordSize with
    | Architecture.RISCV, WordSize.Bit32 -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|RISCV64|_|) (isa: ISA) =
    match isa.Arch, isa.WordSize with
    | Architecture.RISCV, WordSize.Bit64 -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|SPARC|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.SPARC -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|S390|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.S390 -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|SH4|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.SH4 -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|PARISC|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.PARISC -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|M68K|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.M68K -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|Alpha|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.Alpha -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|AVR|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.AVR -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|TMS320C6000|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.TMS320C6000 -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|BPF|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.BPF -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|EVM|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.EVM -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|WASM|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.WASM -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|Python|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.Python -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|CIL|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.CIL -> ValueSome()
    | _ -> ValueNone
