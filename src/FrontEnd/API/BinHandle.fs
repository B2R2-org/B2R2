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

namespace B2R2.FrontEnd

open System
open System.IO
open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter
open type FileFormat

type BinHandle private (path, bytes, fmt, isa, baseAddrOpt) =
  let regFactory = GroundWork.CreateRegisterFactory isa

  let binFile = FileFactory.load path bytes fmt isa regFactory baseAddrOpt

  let reader = binFile.Reader

  let tryReadIntBySize size (span: ByteSpan) =
    match size with
    | 1 -> reader.ReadInt8 (span, 0) |> int64 |> Ok
    | 2 -> reader.ReadInt16 (span, 0) |> int64 |> Ok
    | 4 -> reader.ReadInt32 (span, 0) |> int64 |> Ok
    | 8 -> reader.ReadInt64 (span, 0) |> Ok
    | _ -> Error ErrorCase.InvalidMemoryRead

  let readIntBySize size (span: ByteSpan) =
    match size with
    | 1 -> reader.ReadInt8 (span, 0) |> int64
    | 2 -> reader.ReadInt16 (span, 0) |> int64
    | 4 -> reader.ReadInt32 (span, 0) |> int64
    | 8 -> reader.ReadInt64 (span, 0)
    | _ ->
      invalidArg (nameof size) (ErrorCase.toString ErrorCase.InvalidMemoryRead)

  let tryReadUIntBySize size (span: ByteSpan) =
    match size with
    | 1 -> reader.ReadUInt8 (span, 0) |> uint64 |> Ok
    | 2 -> reader.ReadUInt16 (span, 0) |> uint64 |> Ok
    | 4 -> reader.ReadUInt32 (span, 0) |> uint64 |> Ok
    | 8 -> reader.ReadUInt64 (span, 0) |> Ok
    | _ -> Error ErrorCase.InvalidMemoryRead

  let readUIntBySize size (span: ByteSpan) =
    match size with
    | 1 -> reader.ReadUInt8 (span, 0) |> uint64
    | 2 -> reader.ReadUInt16 (span, 0) |> uint64
    | 4 -> reader.ReadUInt32 (span, 0) |> uint64
    | 8 -> reader.ReadUInt64 (span, 0)
    | _ ->
      invalidArg (nameof size) (ErrorCase.toString ErrorCase.InvalidMemoryRead)

  let rec readAscii acc (ptr: BinFilePointer) =
    if ptr.IsValid && not ptr.IsVirtual then
      let b = binFile.RawBytes[ptr.Offset]
      if b = 0uy then List.rev (b :: acc) |> List.toArray
      else readAscii (b :: acc) (ptr.Advance 1)
    else List.rev acc |> List.toArray

  let readOrPartialReadBytes (ptr: BinFilePointer) nBytes =
    let arr =
      if ptr.IsVirtual then Array.zeroCreate nBytes
      else
        let len = ptr.MaxOffset - ptr.Offset + 1
        let span = ReadOnlySpan(binFile.RawBytes, ptr.Offset, len)
        span.Slice(0, nBytes).ToArray ()
    if ptr.CanRead nBytes then Ok arr (* full result *)
    else Error arr (* partial result *)

  let rec tryReadBytes (ptr: BinFilePointer) nBytes =
    if ptr.CanRead nBytes then
      match readOrPartialReadBytes ptr nBytes with
      | Ok bs -> Ok bs
      | Error bs ->
        let rest = nBytes - bs.Length
        let nextPtr = binFile.GetBoundedPointer (ptr.MaxAddr + 1UL)
        match tryReadBytes nextPtr rest with
        | Ok restBytes -> Ok <| Array.append bs restBytes
        | Error e -> Error e
    else Error ErrorCase.InvalidMemoryRead

  let rec readBytes (ptr: BinFilePointer) nBytes =
    if ptr.IsValid then
      match readOrPartialReadBytes ptr nBytes with
      | Ok bs -> bs
      | Error bs ->
        let rest = nBytes - bs.Length
        let nextPtr = binFile.GetBoundedPointer (ptr.MaxAddr + 1UL)
        Array.append bs (readBytes nextPtr rest)
    else
      invalidArg (nameof ptr) (ErrorCase.toString ErrorCase.InvalidMemoryRead)

  new (path, isa, baseAddrOpt) =
    let bytes = File.ReadAllBytes path
    let struct (fmt, isa) = FormatDetector.identify bytes isa
    BinHandle (path, bytes, fmt, isa, baseAddrOpt)

  new (path, isa) =
    BinHandle (path = path, isa = isa, baseAddrOpt = None)

  new (path) =
    let defaultISA = ISA (Architecture.Intel, WordSize.Bit64)
    BinHandle (path = path, isa = defaultISA, baseAddrOpt = None)

  new (bytes, isa, baseAddrOpt, detectFormat) =
    if detectFormat then
      let struct (fmt, isa) = FormatDetector.identify bytes isa
      BinHandle ("", bytes, fmt, isa, baseAddrOpt)
    else
      BinHandle ("", bytes, RawBinary, isa, baseAddrOpt)

  new (bytes, isa) =
    BinHandle ("", bytes, RawBinary, isa, None)

  new (isa) =
    BinHandle ([||], isa, None, false)

  member _.File with get(): IBinFile = binFile

  member _.RegisterFactory with get() = regFactory

  member _.NewLiftingUnit () =
    let parser = GroundWork.CreateParser binFile
    match binFile.ISA.Arch, binFile.EntryPoint with
    | Architecture.ARMv7, Some entryPoint when entryPoint % 2UL <> 0UL ->
      let armParser = parser :?> ARM32.IModeSwitchable
      armParser.IsThumb <- true
    | _ -> ()
    LiftingUnit (binFile, regFactory, parser)

  member _.TryReadBytes (ptr: BinFilePointer, nBytes) =
    tryReadBytes ptr nBytes

  member _.TryReadBytes (addr: Addr, nBytes) =
    let ptr = binFile.GetBoundedPointer addr
    tryReadBytes ptr nBytes

  member _.ReadBytes (ptr: BinFilePointer, nBytes) =
    readBytes ptr nBytes

  member _.ReadBytes (addr: Addr, nBytes) =
    let ptr = binFile.GetBoundedPointer addr
    readBytes ptr nBytes

  member _.TryReadInt (ptr: BinFilePointer, size) =
    match tryReadBytes ptr size with
    | Ok bs -> tryReadIntBySize size (ReadOnlySpan bs)
    | _ -> Error ErrorCase.InvalidMemoryRead

  member this.TryReadInt (addr: Addr, size) =
    let ptr = binFile.GetBoundedPointer addr
    this.TryReadInt (ptr, size)

  member _.ReadInt (ptr: BinFilePointer, size) =
    let bs = readBytes ptr size
    readIntBySize size (ReadOnlySpan bs)

  member this.ReadInt (addr: Addr, size) =
    let ptr = binFile.GetBoundedPointer addr
    this.ReadInt (ptr, size)

  member _.TryReadUInt (ptr: BinFilePointer, size) =
    match tryReadBytes ptr size with
    | Ok bs -> tryReadUIntBySize size (ReadOnlySpan bs)
    | _ -> Error ErrorCase.InvalidMemoryRead

  member this.TryReadUInt (addr: Addr, size) =
    let ptr = binFile.GetBoundedPointer addr
    this.TryReadUInt (ptr, size)

  member _.ReadUInt (ptr: BinFilePointer, size) =
    let bs = readBytes ptr size
    readUIntBySize size (ReadOnlySpan bs)

  member this.ReadUInt (addr: Addr, size) =
    let ptr = binFile.GetBoundedPointer addr
    this.ReadUInt (ptr, size)

  member _.ReadASCII (addr: Addr) =
    let bs = binFile.GetBoundedPointer addr |> readAscii []
    ByteArray.extractCString bs 0

  member _.ReadASCII (ptr: BinFilePointer) =
    let bs = readAscii [] ptr
    ByteArray.extractCString bs 0

  member _.MakeNew (bs: byte[]) =
    BinHandle (path, bs, fmt, isa, baseAddrOpt)

  member _.MakeNew (bs: byte[], baseAddr) =
    BinHandle (path, bs, fmt, isa, Some baseAddr)

// vim: set tw=80 sts=2 sw=2:
