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
open B2R2.ABI
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter
open type FileFormat

/// <summary>
/// Represents the main data structure for accessing a chunk of binary code.
/// It provides ways to read raw data from the binary through addresses and to
/// access binary file metadata through the <see
/// cref='T:B2R2.FrontEnd.BinFile.IBinFile'/> interface. It also provides ways
/// to parse/lift instructions from the binary through <see
/// cref='T:B2R2.FrontEnd.LiftingUnit'/>.
/// </summary>
type BinHandle private(path, bytes, fmt, isa, baseAddrOpt, osOpt) =
  let regFactory = ArchSupport.createRegisterFactory isa

  let binFile = FileFactory.load path bytes fmt isa regFactory baseAddrOpt

  (* A recognized file format decides the OS on its own, so an injected one only
     has a say for a raw image, which is the only case that carries no format to
     infer from. *)
  let os =
    match binFile.Format with
    | FileFormat.ELFBinary -> OS.Linux
    | FileFormat.PEBinary -> OS.Windows
    | FileFormat.MachBinary -> OS.MacOSX
    | _ -> defaultArg osOpt OS.UnknownOS

  let conv = Conventions.create os binFile.ISA

  let rawBytes = binFile.RawBytes

  let reader = binFile.Reader

  let tryReadIntBySize size (span: ByteSpan) =
    match size with
    | 1 -> reader.ReadInt8(span, 0) |> int64 |> Ok
    | 2 -> reader.ReadInt16(span, 0) |> int64 |> Ok
    | 4 -> reader.ReadInt32(span, 0) |> int64 |> Ok
    | 8 -> reader.ReadInt64(span, 0) |> Ok
    | _ -> Error ErrorCase.InvalidMemoryRead

  let readIntBySize size (span: ByteSpan) =
    match size with
    | 1 ->
      reader.ReadInt8(span, 0) |> int64
    | 2 ->
      reader.ReadInt16(span, 0) |> int64
    | 4 ->
      reader.ReadInt32(span, 0) |> int64
    | 8 ->
      reader.ReadInt64(span, 0)
    | _ ->
      invalidArg (nameof size) (ErrorCase.toMessage ErrorCase.InvalidMemoryRead)

  let tryReadUIntBySize size (span: ByteSpan) =
    match size with
    | 1 -> reader.ReadUInt8(span, 0) |> uint64 |> Ok
    | 2 -> reader.ReadUInt16(span, 0) |> uint64 |> Ok
    | 4 -> reader.ReadUInt32(span, 0) |> uint64 |> Ok
    | 8 -> reader.ReadUInt64(span, 0) |> Ok
    | _ -> Error ErrorCase.InvalidMemoryRead

  let readUIntBySize size (span: ByteSpan) =
    match size with
    | 1 ->
      reader.ReadUInt8(span, 0) |> uint64
    | 2 ->
      reader.ReadUInt16(span, 0) |> uint64
    | 4 ->
      reader.ReadUInt32(span, 0) |> uint64
    | 8 ->
      reader.ReadUInt64(span, 0)
    | _ ->
      invalidArg (nameof size) (ErrorCase.toMessage ErrorCase.InvalidMemoryRead)

  (* Walks forward from a pointer that is known to be file-backed, stopping at
     the terminating NUL or at the end of the pointed region. *)
  let rec readAsciiBytes acc (ptr: BinFilePointer) =
    if ptr.CanReadFileBytes then
      let b = rawBytes.Span[ptr.Offset]
      if b = 0uy then List.rev acc |> List.toArray
      else readAsciiBytes (b :: acc) (ptr.Advance 1)
    else
      List.rev acc |> List.toArray

  let tryReadAscii (ptr: BinFilePointer) =
    if ptr.CanReadFileBytes then
      Ok(ByteArray.extractCString (readAsciiBytes [] ptr) 0)
    else
      Error ErrorCase.InvalidMemoryRead

  let readAscii (ptr: BinFilePointer) =
    if ptr.CanReadFileBytes then
      ByteArray.extractCString (readAsciiBytes [] ptr) 0
    else
      invalidArg (nameof ptr) (ErrorCase.toMessage ErrorCase.InvalidMemoryRead)

  let readOrPartialReadBytes (ptr: BinFilePointer) nBytes =
    let available = ptr.MaxAddr - ptr.Addr + 1UL
    let amount = if available >= uint64 nBytes then nBytes else int available
    let arr =
      if ptr.IsVirtual then
        Array.zeroCreate amount
      else
        let len = min ptr.ReadableAmount amount
        rawBytes.Span.Slice(ptr.Offset, len).ToArray()
    if arr.Length = nBytes then Ok arr (* full result *)
    else Error arr (* partial result *)

  let rec tryReadBytes (ptr: BinFilePointer) nBytes =
    if nBytes > 0 && ptr.CanRead 1 then
      match readOrPartialReadBytes ptr nBytes with
      | Ok bs ->
        Ok bs
      | Error bs ->
        let nextPtr = binFile.GetBoundedPointer(ptr.MaxAddr + 1UL)
        match tryReadBytes nextPtr (nBytes - bs.Length) with
        | Ok restBytes -> Ok <| Array.append bs restBytes
        | Error e -> Error e
    else
      Error ErrorCase.InvalidMemoryRead

  let rec readBytes (ptr: BinFilePointer) nBytes =
    if ptr.CanReadFileBytes then
      match readOrPartialReadBytes ptr nBytes with
      | Ok bs ->
        bs
      | Error bs ->
        let rest = nBytes - bs.Length
        let nextPtr = binFile.GetBoundedPointer(ptr.MaxAddr + 1UL)
        Array.append bs (readBytes nextPtr rest)
    else
      invalidArg (nameof ptr) (ErrorCase.toMessage ErrorCase.InvalidMemoryRead)

  /// Gets the file handle.
  member _.File with get(): IBinFile = binFile

  /// Gets the ISA in effect for this binary, which is what the register factory
  /// and the ABI conventions below are derived from. This is not always the ISA
  /// passed to the constructor: for a recognized file format, format detection
  /// resolves the ISA from the file itself.
  member _.ISA with get() = binFile.ISA

  /// Gets the register factory.
  member _.RegisterFactory with get() = regFactory

  /// Gets the target OS. For a recognized file format the OS is inferred from
  /// the format; for a raw image it is the OS injected at construction (or
  /// UnknownOS if none was given).
  member _.OS with get() = os

  /// <summary>
  /// Gets the ABI conventions for this binary's OS and ISA, bundling the
  /// function-call calling convention, the stack-frame convention, and the
  /// system-call convention. See <see cref='T:B2R2.ABI.Conventions'/>.
  /// </summary>
  member _.Conventions with get() = conv

  (* Loading is exposed as named factories rather than constructors because the
     same byte array means two different things depending on whether it is the
     content of a file or a raw image, and a constructor cannot say which. A
     name can, so every entry point below states it: Load*File* detects the
     format, LoadRawImage does not. *)

  /// <summary>
  /// Reads the file at the given path and loads it, detecting its file format
  /// and rebasing it to the given base address (baseAddrOpt) when one is given.
  /// </summary>
  /// <param name="path">The path of the binary file.</param>
  /// <param name="isa">The ISA to fall back on when the format does not pin
  /// one.</param>
  /// <param name="baseAddrOpt">An optional base address to rebase to.</param>
  /// <returns>
  /// Returns a new BinHandle.
  /// </returns>
  static member LoadFile(path: string, isa, baseAddrOpt) =
    let bytes = File.ReadAllBytes path
    let struct (fmt, isa) = FormatDetector.identify bytes isa
    BinHandle(path, bytes, fmt, isa, baseAddrOpt, None)

  /// <summary>
  /// Reads the file at the given path and loads it, detecting its file format.
  /// </summary>
  /// <param name="path">The path of the binary file.</param>
  /// <param name="isa">The ISA to fall back on when the format does not pin
  /// one.</param>
  /// <returns>
  /// Returns a new BinHandle.
  /// </returns>
  static member LoadFile(path: string, isa) =
    BinHandle.LoadFile(path, isa, None)

  /// <summary>
  /// Reads the file at the given path and loads it, detecting its file format.
  /// The ISA to fall back on is x86-64.
  /// </summary>
  /// <param name="path">The path of the binary file.</param>
  /// <returns>
  /// Returns a new BinHandle.
  /// </returns>
  static member LoadFile(path: string) =
    let defaultISA = ISA(Architecture.Intel, WordSize.Bit64)
    BinHandle.LoadFile(path, defaultISA, None)

  /// <summary>
  /// Loads a byte array holding the whole content of a binary file, detecting
  /// its file format and rebasing it to the given base address (baseAddrOpt)
  /// when one is given. This is the in-memory counterpart of <see
  /// cref='M:B2R2.FrontEnd.BinHandle.LoadFile'/>.
  /// </summary>
  /// <param name="bytes">The whole content of a binary file.</param>
  /// <param name="isa">The ISA to fall back on when the format does not pin
  /// one.</param>
  /// <param name="baseAddrOpt">An optional base address to rebase to.</param>
  /// <returns>
  /// Returns a new BinHandle.
  /// </returns>
  static member LoadFileBytes(bytes: byte[], isa, baseAddrOpt) =
    let struct (fmt, isa) = FormatDetector.identify bytes isa
    BinHandle("", bytes, fmt, isa, baseAddrOpt, None)

  /// <summary>
  /// Loads a byte array holding the whole content of a binary file, detecting
  /// its file format. The OS follows from the detected format.
  /// </summary>
  /// <param name="bytes">The whole content of a binary file.</param>
  /// <param name="isa">The ISA to fall back on when the format does not pin
  /// one.</param>
  /// <returns>
  /// Returns a new BinHandle.
  /// </returns>
  static member LoadFileBytes(bytes: byte[], isa) =
    BinHandle.LoadFileBytes(bytes, isa, None)

  /// <summary>
  /// Loads a byte array as a raw image located at the given base address. No
  /// format detection runs over the array, so nothing implies an OS and it is
  /// spelled out here rather than defaulted, which is what keeps a rebased
  /// image from silently taking UnknownOS conventions.
  /// </summary>
  /// <param name="bytes">The raw image.</param>
  /// <param name="isa">The ISA of the image.</param>
  /// <param name="baseAddr">The address the image starts at.</param>
  /// <param name="os">The target OS of the image.</param>
  /// <returns>
  /// Returns a new BinHandle.
  /// </returns>
  static member LoadRawImage(bytes: byte[], isa, baseAddr: Addr, os: OS) =
    BinHandle("", bytes, RawBinary, isa, Some baseAddr, Some os)

  /// <summary>
  /// Loads a byte array as a raw image based at 0UL, for the given target OS.
  /// No format detection runs over the array. Useful for shellcode, whose OS
  /// cannot be inferred from a file format.
  /// </summary>
  /// <param name="bytes">The raw image.</param>
  /// <param name="isa">The ISA of the image.</param>
  /// <param name="os">The target OS of the image.</param>
  /// <returns>
  /// Returns a new BinHandle.
  /// </returns>
  static member LoadRawImage(bytes: byte[], isa, os: OS) =
    BinHandle("", bytes, RawBinary, isa, None, Some os)

  /// <summary>
  /// Loads a byte array as a raw image based at 0UL, with no target OS. No
  /// format detection runs over the array, so an array that happens to hold a
  /// whole binary file is still taken as a plain block of code; use <see
  /// cref='M:B2R2.FrontEnd.BinHandle.LoadFileBytes'/> for that.
  /// </summary>
  /// <param name="bytes">The raw image.</param>
  /// <param name="isa">The ISA of the image.</param>
  /// <returns>
  /// Returns a new BinHandle.
  /// </returns>
  static member LoadRawImage(bytes: byte[], isa) =
    BinHandle("", bytes, RawBinary, isa, None, None)

  /// <summary>
  /// Loads an empty image, over which no read can succeed. Useful when only the
  /// ISA-derived facilities, such as the register factory, are needed. This is
  /// the same as <see cref='M:B2R2.FrontEnd.BinHandle.LoadRawImage'/> over an
  /// empty array, named so that the degenerate case reads as one.
  /// </summary>
  /// <param name="isa">The ISA of the handle.</param>
  /// <returns>
  /// Returns a new BinHandle.
  /// </returns>
  static member LoadEmpty(isa) =
    BinHandle("", [||], RawBinary, isa, None, None)

  /// Gets a new instance of lifting unit.
  member _.NewLiftingUnit() =
    let parser = ArchSupport.createParserForFile binFile
    let liftingUnit = LiftingUnit(binFile, regFactory, parser)
    (* An odd entry point marks a Thumb entry. Setting the mode is inert where
       there is no Thumb to switch to, so no architecture test is needed. *)
    match binFile.EntryPoint with
    | Some addr when addr % 2UL <> 0UL -> liftingUnit.IsThumb <- true
    | _ -> ()
    liftingUnit

  /// <summary>
  /// Returns the byte array of size (nBytes) pointed to by the pointer (ptr).
  /// </summary>
  /// <param name="ptr">The binary file pointer.</param>
  /// <param name="nBytes">The size of the byte array (in bytes).</param>
  /// <returns>
  /// Returns (byte[]) if succeeded, (ErrorCase) otherwise.
  /// </returns>
  member _.TryReadBytes(ptr: BinFilePointer, nBytes) = tryReadBytes ptr nBytes

  /// <summary>
  /// Returns the byte array of size (nBytes) located at the address (addr).
  /// </summary>
  /// <param name="addr">The address</param>
  /// <param name="nBytes">The size of the byte array (in bytes).</param>
  /// <returns>
  /// Returns (byte[]) if succeeded, (ErrorCase) otherwise.
  /// </returns>
  member _.TryReadBytes(addr: Addr, nBytes) =
    let ptr = binFile.GetBoundedPointer addr
    tryReadBytes ptr nBytes

  /// <summary>
  /// Returns the byte array of size (nBytes) pointed to by the binary file
  /// pointer (ptr).
  /// </summary>
  /// <param name="ptr">The binary file pointer.</param>
  /// <param name="nBytes">The size of the byte array (in bytes).</param>
  /// <returns>
  /// Returns the byte array if succeed. Otherwise, raise an exception.
  /// </returns>
  member _.ReadBytes(ptr: BinFilePointer, nBytes) = readBytes ptr nBytes

  /// <summary>
  /// Returns the byte array of size (nBytes) at the addr from the current
  /// binary.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <param name="nBytes">The size of the byte array (in bytes).</param>
  /// <returns>
  /// Returns the byte array if succeed. Otherwise, raise an exception.
  /// </returns>
  member _.ReadBytes(addr: Addr, nBytes) =
    let ptr = binFile.GetBoundedPointer addr
    readBytes ptr nBytes

  /// <summary>
  /// Returns the corresponding integer of the size from the given address
  /// pointed to by the binary pointer (ptr).
  /// </summary>
  /// <param name="ptr">The binary file pointer.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  /// Returns the corresponding value (int64) if the address and the size is
  /// valid. Otherwise ErrorCase.
  /// </returns>
  member _.TryReadInt(ptr: BinFilePointer, size) =
    match tryReadBytes ptr size with
    | Ok bs -> tryReadIntBySize size (ReadOnlySpan bs)
    | _ -> Error ErrorCase.InvalidMemoryRead

  /// <summary>
  /// Returns the corresponding integer of the size from the given address.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  /// Returns the corresponding value (int64) if the address and the size is
  /// valid. Otherwise ErrorCase.
  /// </returns>
  member this.TryReadInt(addr: Addr, size) =
    let ptr = binFile.GetBoundedPointer addr
    this.TryReadInt(ptr, size)

  /// <summary>
  /// Returns the corresponding integer value of the size from the current
  /// binary, which is pointed to by the binary file pointer (ptr).
  /// </summary>
  /// <param name="ptr">The binary file pointer.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  /// Returns the corresponding integer (int64).
  /// </returns>
  member _.ReadInt(ptr: BinFilePointer, size) =
    let bs = readBytes ptr size
    readIntBySize size (ReadOnlySpan bs)

  /// <summary>
  /// Returns the corresponding integer value at the addr of the size from the
  /// current binary.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  /// Returns the corresponding integer (int64).
  /// </returns>
  member this.ReadInt(addr: Addr, size) =
    let ptr = binFile.GetBoundedPointer addr
    this.ReadInt(ptr, size)

  /// <summary>
  /// Returns the corresponding unsigned integer of the size from the address
  /// pointed to by the binary file pointer (ptr).
  /// </summary>
  /// <param name="ptr">The binary file pointer.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  /// Returns the corresponding unsigned integer (uint64) if the address and
  /// the size is valid. Otherwise, ErrorCase.
  /// </returns>
  member _.TryReadUInt(ptr: BinFilePointer, size) =
    match tryReadBytes ptr size with
    | Ok bs -> tryReadUIntBySize size (ReadOnlySpan bs)
    | _ -> Error ErrorCase.InvalidMemoryRead

  /// <summary>
  /// Returns the corresponding unsigned integer of the size from the given
  /// address.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  /// Returns the corresponding unsigned integer (uint64) if the address and
  /// the size is valid. Otherwise, ErrorCase.
  /// </returns>
  member this.TryReadUInt(addr: Addr, size) =
    let ptr = binFile.GetBoundedPointer addr
    this.TryReadUInt(ptr, size)

  /// <summary>
  /// Returns the corresponding unsigned integer value of the size from the
  /// binary, which is pointed to by the binary file pointer (ptr).
  /// </summary>
  /// <param name="ptr">The binary file pointer.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  /// Returns the corresponding unsigned integer (uint64).
  /// </returns>
  member _.ReadUInt(ptr: BinFilePointer, size) =
    let bs = readBytes ptr size
    readUIntBySize size (ReadOnlySpan bs)

  /// <summary>
  /// Returns the corresponding unsigned integer value at the addr of the size
  /// from the binary.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  /// Returns the corresponding unsigned integer (uint64).
  /// </returns>
  member this.ReadUInt(addr: Addr, size) =
    let ptr = binFile.GetBoundedPointer addr
    this.ReadUInt(ptr, size)

  /// <summary>
  /// Returns the NUL-terminated ASCII string starting at the address (addr).
  /// When the pointed region ends before a NUL is found, the string read so far
  /// is returned.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <returns>
  /// Returns the ASCII string if the address is backed by file bytes,
  /// (ErrorCase) otherwise.
  /// </returns>
  member _.TryReadASCII(addr: Addr) =
    binFile.GetBoundedPointer addr |> tryReadAscii

  /// <summary>
  /// Returns the NUL-terminated ASCII string pointed to by the binary file
  /// pointer (ptr). When the pointed region ends before a NUL is found, the
  /// string read so far is returned.
  /// </summary>
  /// <param name="ptr">The binary file pointer.</param>
  /// <returns>
  /// Returns the ASCII string if the pointer is backed by file bytes,
  /// (ErrorCase) otherwise.
  /// </returns>
  member _.TryReadASCII(ptr: BinFilePointer) = tryReadAscii ptr

  /// <summary>
  /// Returns the NUL-terminated ASCII string starting at the address (addr).
  /// When the pointed region ends before a NUL is found, the string read so far
  /// is returned.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <returns>
  /// Returns the ASCII string if succeed. Otherwise, raise an exception.
  /// </returns>
  member _.ReadASCII(addr: Addr) =
    binFile.GetBoundedPointer addr |> readAscii

  /// <summary>
  /// Returns the NUL-terminated ASCII string pointed to by the binary file
  /// pointer (ptr). When the pointed region ends before a NUL is found, the
  /// string read so far is returned.
  /// </summary>
  /// <param name="ptr">The binary file pointer.</param>
  /// <returns>
  /// Returns the ASCII string if succeed. Otherwise, raise an exception.
  /// </returns>
  member _.ReadASCII(ptr: BinFilePointer) = readAscii ptr
