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

namespace B2R2.FrontEnd.BinFile

open B2R2
open B2R2.FrontEnd.BinLifter

[<RequireQualifiedAccess>]
module FileFactory =
  let private loadRegBay isa =
    match isa.Arch with
    | Arch.IntelX64
    | Arch.IntelX86 -> Intel.Basis.initRegBay isa.WordSize
    | Arch.ARMv7 | Arch.AARCH32 -> ARM32.Basis.initRegBay ()
    | Arch.AARCH64 -> ARM64.Basis.initRegBay ()
    | Arch.MIPS32 | Arch.MIPS64 -> MIPS.Basis.initRegBay isa
    | Arch.PPC32 -> PPC32.Basis.initRegBay isa
    | Arch.RISCV64 -> RISCV.Basis.initRegBay isa
    | Arch.SH4 -> SH4.Basis.initRegBay isa
    | _ -> Utils.futureFeature ()

  let load path bytes fmt isa baseAddrOpt =
    let regbay = loadRegBay isa
    match fmt with
    | FileFormat.ELFBinary ->
      ELFBinFile (path, bytes, baseAddrOpt, Some regbay) :> IBinFile
    | FileFormat.PEBinary ->
      PEBinFile (path, bytes, baseAddrOpt, [||]) :> IBinFile
    | FileFormat.MachBinary ->
      MachBinFile (path, bytes, isa, baseAddrOpt) :> IBinFile
    | FileFormat.WasmBinary ->
      WasmBinFile (bytes, path) :> IBinFile
    | _ ->
      RawBinFile (bytes, path, isa, baseAddrOpt) :> IBinFile

  let loadELF path bytes isa baseAddrOpt =
    let regbay = loadRegBay isa
    ELFBinFile (path, bytes, baseAddrOpt, Some regbay)