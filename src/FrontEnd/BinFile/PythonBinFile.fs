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

open System.Collections.Generic
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile.FileHelper
open B2R2.FrontEnd.BinFile.Python.Helper

/// Represents a Python binary file.
type PythonBinFile(path, inputBytes: byte[], baseAddrOpt) =
  let baseAddr = defaultArg baseAddrOpt 0UL

  let reader = BinReader.Init Endian.Little

  let magic = reader.ReadUInt32(inputBytes, 0)

  let version = getVersionFromMagicNumber magic

  let parsedCodeObject, _, _ =
    let hdr = headerSize version
    parse version inputBytes reader [||] hdr (Dictionary<int, uint64>())

  (* Pre-3.11 only: two distinct functions can share one `co_code` file
     offset via marshal's own byte-identity dedup -- see
     deduplicateCodeOffsets's own doc comment. Giving each its own real,
     distinct address here, before anything else (function
     identification, CFG recovery, lifting) ever runs, restores the
     address<->function invariant every one of those already assumes,
     instead of every downstream consumer having to special-case the
     collision (or worse, silently picking one of the two at random). *)
  let bytes, codeObject =
    match parsedCodeObject with
    | Python.PyCode co ->
      let bytes, co = deduplicateCodeOffsets inputBytes co
      bytes, Python.PyCode co
    | other ->
      inputBytes, other

  (* Deliberately the post-dedup buffer, not `inputBytes`: dedup extends
     the buffer, and that extension is the file's own address space from
     here on, so `RawBytes` must expose it too. *)
  let rawBytes = System.ReadOnlyMemory bytes

  let size = bytes.Length

  let consts = extractConsts codeObject

  let names = extractNames codeObject

  let varnames = extractVarNames codeObject

  let freevars = extractFreeVars codeObject

  let operator = [||]

  /// Python magic
  member _.Magic with get() = magic

  /// Python version
  member _.Version with get() = version

  /// Code Object.
  member _.CodeObj with get() = codeObject

  /// Consts.
  member _.Consts with get() = consts

  /// Varnames.
  member _.Varnames with get() = varnames

  /// Pre-3.11 `co_cellvars ++ co_freevars` -- see FreeVars' own doc comment
  /// on PyCodeObject.
  member _.FreeVars with get() = freevars

  /// Names.
  member _.Names with get() = names

  /// Operator.
  member _.Operator with get() = operator

  interface IBinFile with
    member _.Reader with get() = reader

    member _.RawBytes with get() = rawBytes

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

    member _.ProgramHeaderTable with get() = None

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

    member this.IsExecutableAddr addr = (this :> IAddressSpace).IsValidAddr addr

    member _.GetBoundedPointer(addr) =
      if addr < uint64 size then
        BinFilePointer.CreateFileBacked(addr, uint64 size - 1UL, int addr,
                                        size - 1)
      else
        BinFilePointer.Null
