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

/// FileLoader provides an interface for loading a binary.
[<RequireQualifiedAccess>]
module B2R2.FrontEnd.BinFile.FileLoader

open B2R2
open B2R2.FrontEnd.BinLifter

let private loadRegBay isa =
  match isa.Arch with
  | Arch.IntelX64
  | Arch.IntelX86 -> Intel.Basis.initRegBay isa.WordSize
  | Arch.ARMv7 | Arch.AARCH32 -> ARM32.Basis.initRegBay ()
  | Arch.AARCH64 -> ARM64.Basis.initRegBay ()
  | Arch.MIPS32 | Arch.MIPS64 -> MIPS.Basis.initRegBay isa
  | Arch.PPC32 -> PPC32.Basis.initRegBay isa
  | Arch.RISCV64 -> RISCV.Basis.initRegBay isa
  | _ -> Utils.futureFeature ()

/// Load a given byte array (binary file) and return a `BinFile`.
[<CompiledName ("Load")>]
let load (binPath: string) (bytes: byte[]) isa baseAddr =
  let fmt, isa = FormatDetector.identify bytes isa
  let regbay = loadRegBay isa
  match fmt with
  | FileFormat.ELFBinary ->
    ELFBinFile (bytes, binPath, baseAddr, Some regbay) :> BinFile
  | FileFormat.PEBinary ->
    PEBinFile (bytes, binPath, baseAddr) :> BinFile
  | FileFormat.MachBinary ->
    MachBinFile (bytes, binPath, isa, baseAddr) :> BinFile
  | _ -> RawBinFile (bytes, binPath, isa, baseAddr) :> BinFile

/// Load a given byte array (binary file) and return a `ELFBinFile`.
[<CompiledName ("LoadELF")>]
let loadELF (binPath: string) (bytes: byte[]) isa baseAddr =
  let fmt, isa = FormatDetector.identify bytes isa
  let regbay = loadRegBay isa
  match fmt with
  | FileFormat.ELFBinary -> ELFBinFile (bytes, binPath, baseAddr, Some regbay)
  | _ -> raise InvalidFileFormatException

/// Load a given byte array (binary file) and return a `ELFBinFile` while
/// parsing only basic information of the binary. This is to enable faster
/// loading of BinFile when emulating binaries.
[<CompiledName ("LoadELFForEmulation")>]
let loadELFForEmulation (binPath: string) (bytes: byte[]) isa baseAddr =
  let fmt, isa = FormatDetector.identify bytes isa
  let regbay = loadRegBay isa
  match fmt with
  | FileFormat.ELFBinary ->
    ELFBinFile (bytes, binPath, baseAddr, Some regbay, true)
  | _ -> raise InvalidFileFormatException

/// Load a given byte array (binary file) and return a `PEBinFile`.
[<CompiledName ("LoadPE")>]
let loadPE (binPath: string) (bytes: byte[]) isa baseAddr =
  let fmt, _isa = FormatDetector.identify bytes isa
  match fmt with
  | FileFormat.PEBinary -> PEBinFile (bytes, binPath, baseAddr=baseAddr)
  | _ -> raise InvalidFileFormatException

/// Load a given byte array (binary file) and return a `MachBinFile`.
[<CompiledName ("LoadMach")>]
let loadMach (binPath: string) (bytes: byte[]) isa baseAddr =
  let fmt, isa = FormatDetector.identify bytes isa
  match fmt with
  | FileFormat.MachBinary -> MachBinFile (bytes, binPath, isa, baseAddr)
  | _ -> raise InvalidFileFormatException
