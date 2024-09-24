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
open type ArchOperationMode

type BinHandle private (path, bytes, fmt, isa, mode, baseAddrOpt) =
  let regFactory = GroundWork.CreateRegisterFactory isa

  let binFile = FileFactory.load path bytes fmt isa regFactory baseAddrOpt

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
    | 1 -> binFile.Reader.ReadInt8 (span, 0) |> int64 |> Ok
    | 2 -> binFile.Reader.ReadInt16 (span, 0) |> int64 |> Ok
    | 4 -> binFile.Reader.ReadInt32 (span, 0) |> int64 |> Ok
    | 8 -> binFile.Reader.ReadInt64 (span, 0) |> Ok
    | _ -> Error ErrorCase.InvalidMemoryRead

  let readUIntBySize size (span: ByteSpan) =
    match size with
    | 1 -> binFile.Reader.ReadUInt8 (span, 0) |> uint64 |> Ok
    | 2 -> binFile.Reader.ReadUInt16 (span, 0) |> uint64 |> Ok
    | 4 -> binFile.Reader.ReadUInt32 (span, 0) |> uint64 |> Ok
    | 8 -> binFile.Reader.ReadUInt64 (span, 0) |> Ok
    | _ -> Error ErrorCase.InvalidMemoryRead

  let rec readAscii acc offset =
    let b = binFile.ReadByte (offset=offset)
    if b = 0uy then List.rev (b :: acc) |> List.toArray
    else readAscii (b :: acc) (offset + 1)

  new (path, isa, mode, baseAddrOpt) =
    let bytes = File.ReadAllBytes path
    let struct (fmt, isa) = FormatDetector.identify bytes isa
    BinHandle (path, bytes, fmt, isa, mode, baseAddrOpt)

  new (path, isa, baseAddrOpt) =
    BinHandle (path=path, isa=isa, mode=NoMode, baseAddrOpt=baseAddrOpt)

  new (path, isa) =
    BinHandle (path=path, isa=isa, mode=NoMode, baseAddrOpt=None)

  new (path) =
    BinHandle (path=path, isa=ISA.DefaultISA, mode=NoMode, baseAddrOpt=None)

  new (bytes, isa, mode, baseAddrOpt, detectFormat) =
    if detectFormat then
      let struct (fmt, isa) = FormatDetector.identify bytes isa
      BinHandle ("", bytes, fmt, isa, mode, baseAddrOpt)
    else
      BinHandle ("", bytes, RawBinary, isa, mode, baseAddrOpt)

  new (isa) =
    BinHandle ([||], isa, NoMode, None, false)

  /// Return the `IBinFile` object.
  member __.File with get(): IBinFile = binFile

  member __.RegisterFactory with get(): RegisterFactory = regFactory

  member __.NewLiftingUnit () =
    let mode =
      match binFile.ISA.Arch, binFile.EntryPoint, mode with
      | Architecture.ARMv7, Some entryPoint, ArchOperationMode.NoMode ->
        if entryPoint % 2UL <> 0UL then ThumbMode
        else ARMMode
      | _ -> mode
    let parser = GroundWork.CreateParser binFile.ISA mode
    LiftingUnit (binFile, parser)

  member __.TryReadBytes (addr: Addr, nBytes) =
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

  member __.TryReadBytes (ptr: BinFilePointer, nBytes) =
    if BinFilePointer.IsValidAccess ptr nBytes then
      let slice = binFile.Slice (ptr, nBytes)
      slice.ToArray () |> Ok
    else Error ErrorCase.InvalidMemoryRead

  member __.ReadBytes (addr: Addr, nBytes) =
    match __.TryReadBytes (addr, nBytes) with
    | Ok bs -> bs
    | Error e -> invalidArg (nameof addr) (ErrorCase.toString e)

  member __.ReadBytes (ptr: BinFilePointer, nBytes) =
    match __.TryReadBytes (ptr, nBytes) with
    | Ok bs -> bs
    | Error e -> invalidArg (nameof ptr) (ErrorCase.toString e)

  member __.TryReadInt (addr: Addr, size) =
    let pos = binFile.GetOffset addr
    if (pos + size) > binFile.Length || (pos < 0) then
      Error ErrorCase.InvalidMemoryRead
    else
      readIntBySize size (binFile.Slice (offset=pos))

  member __.TryReadInt (ptr: BinFilePointer, size) =
    if BinFilePointer.IsValidAccess ptr size then
      readIntBySize size (binFile.Slice (offset=ptr.Offset))
    else Error ErrorCase.InvalidMemoryRead

  member __.ReadInt (addr: Addr, size) =
    match __.TryReadInt (addr, size) with
    | Ok i -> i
    | Error e -> invalidArg (nameof addr) (ErrorCase.toString e)

  member __.ReadInt (ptr: BinFilePointer, size) =
    match __.TryReadInt (ptr, size) with
    | Ok i -> i
    | Error e -> invalidArg (nameof ptr) (ErrorCase.toString e)

  member __.TryReadUInt (addr: Addr, size) =
    let pos = binFile.GetOffset addr
    if (pos + size) > binFile.Length || (pos < 0) then
      Error ErrorCase.InvalidMemoryRead
    else
      readUIntBySize size (binFile.Slice (offset=pos))

  member __.TryReadUInt (ptr: BinFilePointer, size) =
    if BinFilePointer.IsValidAccess ptr size then
      readUIntBySize size (binFile.Slice (offset=ptr.Offset))
    else Error ErrorCase.InvalidMemoryRead

  member __.ReadUInt (addr: Addr, size) =
    match __.TryReadUInt (addr, size) with
    | Ok i -> i
    | Error e -> invalidArg (nameof addr) (ErrorCase.toString e)

  member __.ReadUInt (ptr: BinFilePointer, size) =
    match __.TryReadUInt (ptr, size) with
    | Ok i -> i
    | Error e -> invalidArg (nameof ptr) (ErrorCase.toString e)

  member __.ReadASCII (addr: Addr) =
    let bs = binFile.GetOffset addr |> readAscii []
    ByteArray.extractCString bs 0

  member __.ReadASCII (ptr: BinFilePointer) =
    let bs = readAscii [] ptr.Offset
    ByteArray.extractCString bs 0

  member __.MakeNew (bs: byte[]) =
    BinHandle (path, bs, fmt, isa, mode, baseAddrOpt)

  member __.MakeNew (bs: byte[], baseAddr) =
    BinHandle (path, bs, fmt, isa, mode, Some baseAddr)

// vim: set tw=80 sts=2 sw=2:
