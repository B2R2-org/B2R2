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

open System
open System.IO
open B2R2
open B2R2.FrontEnd.BinLifter

[<AutoOpen>]
module private FileHandle =
  let loadRegBay isa =
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

  let loadFile path baseAddrOpt stream fmt isa =
    let regbay = loadRegBay isa
    match fmt with
    | FileFormat.ELFBinary ->
      ELFBinFile (path, stream, baseAddrOpt, Some regbay) :> IBinFile
    | FileFormat.PEBinary ->
      PEBinFile (path, stream, baseAddrOpt, [||]) :> IBinFile
    | FileFormat.MachBinary ->
      MachBinFile (path, stream, isa, baseAddrOpt) :> IBinFile
    | FileFormat.WasmBinary ->
      use ms = new MemoryStream ()
      stream.CopyTo ms
      WasmBinFile (ms.ToArray (), path) :> IBinFile
    | _ ->
      use ms = new MemoryStream ()
      stream.CopyTo ms
      RawBinFile (ms.ToArray (), path, isa, baseAddrOpt) :> IBinFile

/// This is B2R2's abstraction of a binary file. Given a file path, and an ISA,
/// this class will automatically detect the file format and load the file.
/// Since this implements IDisposable interface, it is recommended to use this
/// class with `use` keyword, and properly dispose it after use.
type FileHandle (path: string, isa, baseAddrOpt) =
  let stream = new FileStream (path, FileMode.Open, FileAccess.Read)
  let struct (fmt, isa) = FormatDetector.identify stream isa
  let binFile = loadFile path baseAddrOpt stream fmt isa

  /// File format of the binary file.
  member __.Format with get() = fmt

  /// ISA that this binary file is compiled for.
  member __.ISA with get() = isa

  /// Return a `IBinFile` object.
  member __.BinFile with get() = binFile

  interface IDisposable with
    member __.Dispose () = stream.Dispose ()
