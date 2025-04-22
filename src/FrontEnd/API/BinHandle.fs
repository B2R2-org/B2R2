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

open System.IO
open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter
open type FileFormat

type BinHandle private (path, bytes, fmt, isa, baseAddrOpt) =
  let regFactory = GroundWork.CreateRegisterFactory isa

  let binFile = FileFactory.load path bytes fmt isa regFactory baseAddrOpt

  let reader = binFile.Reader

  /// Subdivide the given range into in-file and not-in-file ranges. This
  /// function returns (AddrRange * bool) list where the bool value indicates
  /// whether the range is in-file or not-in-file.
  let classifyRanges myrange =
    binFile.GetNotInFileIntervals myrange (* not-in-file ranges *)
    |> Seq.fold (fun (infiles, saddr) r ->
         let l = AddrRange.GetMin r
         let h = AddrRange.GetMax r
         if saddr = l then (r, false) :: infiles, h
         else (r, false) :: ((AddrRange (saddr, l), true) :: infiles), h
       ) ([], AddrRange.GetMin myrange)
    |> (fun (infiles, saddr) ->
         if saddr = myrange.Max then infiles
         else ((AddrRange (saddr, myrange.Max), true) :: infiles))
    |> List.rev

  let readIntBySize size (span: ByteSpan) =
    match size with
    | 1 -> reader.ReadInt8 (span, 0) |> int64 |> Ok
    | 2 -> reader.ReadInt16 (span, 0) |> int64 |> Ok
    | 4 -> reader.ReadInt32 (span, 0) |> int64 |> Ok
    | 8 -> reader.ReadInt64 (span, 0) |> Ok
    | _ -> Error ErrorCase.InvalidMemoryRead

  let readUIntBySize size (span: ByteSpan) =
    match size with
    | 1 -> reader.ReadUInt8 (span, 0) |> uint64 |> Ok
    | 2 -> reader.ReadUInt16 (span, 0) |> uint64 |> Ok
    | 4 -> reader.ReadUInt32 (span, 0) |> uint64 |> Ok
    | 8 -> reader.ReadUInt64 (span, 0) |> Ok
    | _ -> Error ErrorCase.InvalidMemoryRead

  let rec readAscii acc offset =
    let b = binFile.ReadByte (offset=offset)
    if b = 0uy then List.rev (b :: acc) |> List.toArray
    else readAscii (b :: acc) (offset + 1)

  new (path, isa, baseAddrOpt) =
    let bytes = File.ReadAllBytes path
    let struct (fmt, isa) = FormatDetector.identify bytes isa
    BinHandle (path, bytes, fmt, isa, baseAddrOpt)

  new (path, isa) =
    BinHandle (path=path, isa=isa, baseAddrOpt=None)

  new (path) =
    let defaultISA = ISA (Architecture.Intel, WordSize.Bit64)
    BinHandle (path=path, isa=defaultISA, baseAddrOpt=None)

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
    let parser = GroundWork.CreateParser binFile reader binFile.ISA
    match binFile.ISA.Arch, binFile.EntryPoint with
    | Architecture.ARMv7, Some entryPoint when entryPoint % 2UL <> 0UL ->
      let armParser = parser :?> ARM32.IModeSwitchable
      armParser.IsThumb <- true
    | _ -> ()
    LiftingUnit (binFile, regFactory, parser)

  member _.TryReadBytes (addr: Addr, nBytes) =
    let range = AddrRange (addr, addr + uint64 nBytes - 1UL)
    if binFile.IsInFileRange range then
      let slice = binFile.Slice (addr, nBytes)
      slice.ToArray () |> Ok
    elif binFile.IsValidRange range then
      classifyRanges range
      |> List.fold (fun bs (range, isInFile) ->
           let len = (range.Max - range.Min |> int) + 1
           if isInFile then
             let slice = binFile.Slice (range.Min, len)
             Array.append bs (slice.ToArray ())
           else Array.create len 0uy |> Array.append bs
         ) [||]
      |> Ok
    else Error ErrorCase.InvalidMemoryRead

  member _.TryReadBytes (ptr: BinFilePointer, nBytes) =
    if BinFilePointer.IsValidAccess ptr nBytes then
      let slice = binFile.Slice (ptr, nBytes)
      slice.ToArray () |> Ok
    else Error ErrorCase.InvalidMemoryRead

  member this.ReadBytes (addr: Addr, nBytes) =
    match this.TryReadBytes (addr, nBytes) with
    | Ok bs -> bs
    | Error e -> invalidArg (nameof addr) (ErrorCase.toString e)

  member this.ReadBytes (ptr: BinFilePointer, nBytes) =
    match this.TryReadBytes (ptr, nBytes) with
    | Ok bs -> bs
    | Error e -> invalidArg (nameof ptr) (ErrorCase.toString e)

  member _.TryReadInt (addr: Addr, size) =
    let pos = binFile.GetOffset addr
    if (pos + size) > binFile.Length || (pos < 0) then
      Error ErrorCase.InvalidMemoryRead
    else
      readIntBySize size (binFile.Slice (offset=pos))

  member _.TryReadInt (ptr: BinFilePointer, size) =
    if BinFilePointer.IsValidAccess ptr size then
      readIntBySize size (binFile.Slice (offset=ptr.Offset))
    else Error ErrorCase.InvalidMemoryRead

  member this.ReadInt (addr: Addr, size) =
    match this.TryReadInt (addr, size) with
    | Ok i -> i
    | Error e -> invalidArg (nameof addr) (ErrorCase.toString e)

  member this.ReadInt (ptr: BinFilePointer, size) =
    match this.TryReadInt (ptr, size) with
    | Ok i -> i
    | Error e -> invalidArg (nameof ptr) (ErrorCase.toString e)

  member _.TryReadUInt (addr: Addr, size) =
    let pos = binFile.GetOffset addr
    if (pos + size) > binFile.Length || (pos < 0) then
      Error ErrorCase.InvalidMemoryRead
    else
      readUIntBySize size (binFile.Slice (offset=pos))

  member _.TryReadUInt (ptr: BinFilePointer, size) =
    if BinFilePointer.IsValidAccess ptr size then
      readUIntBySize size (binFile.Slice (offset=ptr.Offset))
    else Error ErrorCase.InvalidMemoryRead

  member this.ReadUInt (addr: Addr, size) =
    match this.TryReadUInt (addr, size) with
    | Ok i -> i
    | Error e -> invalidArg (nameof addr) (ErrorCase.toString e)

  member this.ReadUInt (ptr: BinFilePointer, size) =
    match this.TryReadUInt (ptr, size) with
    | Ok i -> i
    | Error e -> invalidArg (nameof ptr) (ErrorCase.toString e)

  member _.ReadASCII (addr: Addr) =
    let bs = binFile.GetOffset addr |> readAscii []
    ByteArray.extractCString bs 0

  member _.ReadASCII (ptr: BinFilePointer) =
    let bs = readAscii [] ptr.Offset
    ByteArray.extractCString bs 0

  member _.MakeNew (bs: byte[]) =
    BinHandle (path, bs, fmt, isa, baseAddrOpt)

  member _.MakeNew (bs: byte[], baseAddr) =
    BinHandle (path, bs, fmt, isa, Some baseAddr)

// vim: set tw=80 sts=2 sw=2:
