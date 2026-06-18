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
open B2R2.FrontEnd.BinFile.FileHelper
open B2R2.FrontEnd.BinFile.Python.Helper

/// Represents a Python binary file.
type PythonBinFile(path, bytes: byte[], baseAddrOpt) =
  let size = bytes.Length
  let baseAddr = defaultArg baseAddrOpt 0UL
  let reader = BinReader.Init Endian.Little
  let magic = reader.ReadUInt32(bytes, 0)
  let codeObject, _, _ = parse bytes reader [||] 16
  let consts = extractConsts codeObject
  let names = extractNames codeObject
  let varnames = extractVarNames codeObject
  let operator = [||]

  /// Python magic
  member _.Magic with get() = magic

  /// Code Object.
  member _.CodeObj with get() = codeObject

  /// Consts.
  member _.Consts with get() = consts

  /// Varnames.
  member _.Varnames with get() = varnames

  /// Names.
  member _.Names with get() = names

  /// Operator.
  member _.Operator with get() = operator

  interface IBinFile with
    member _.Reader with get() = reader

    member _.RawBytes with get() = System.ReadOnlyMemory bytes

    member _.Length with get() = bytes.Length

    member _.Path with get() = path

    member _.Format with get() = FileFormat.PythonBinary

    member _.Kind with get() = BinFileKind.Unknown

    member _.ISA with get() = ISA(Architecture.Python, Endian.Little)

    member _.EntryPoint with get() = Some 0UL

    member _.BaseAddress with get() = 0UL

    member _.InterpreterPath with get() = None

    member _.RPath with get() = [||]

    member _.RunPath with get() = [||]

    member _.IsNXEnabled with get() = false

    member _.IsPIE with get() = false

    member _.IsBaseRelative with get() = false

    member _.Relro with get() = None

    member _.NameResolver with get() = None

    member _.SymbolTable with get() = None

    member _.Structure with get() = None

    member _.Relocations with get() = None

    member _.ExceptionTable with get() = None

    member _.ImportTable with get() = None

    member _.MemoryLayout with get() = None

    member _.Slice(addr, len) = sliceBySafeOffset bytes addr len

    member _.IsValidAddr(addr) = addr >= 0UL && addr < (uint64 bytes.LongLength)

    member this.IsValidRange range =
      (this :> IAddressSpace).IsValidAddr range.Min
      && (this :> IAddressSpace).IsValidAddr range.Max

    member this.IsAddrMappedToFile addr =
      (this :> IAddressSpace).IsValidAddr addr

    member this.IsRangeMappedToFile range =
      (this :> IAddressSpace).IsValidRange range

    member this.IsExecutableAddr addr =
      (this :> IAddressSpace).IsValidAddr addr

    member _.GetBoundedPointer(addr) =
      if addr < uint64 size then
        BinFilePointer.CreateFileBacked(addr, uint64 size - 1UL, int addr,
                                        size - 1)
      else
        BinFilePointer.Null
