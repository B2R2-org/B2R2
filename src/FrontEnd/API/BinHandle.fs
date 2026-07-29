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
    | 1 -> reader.ReadInt8(span, 0) |> int64
    | 2 -> reader.ReadInt16(span, 0) |> int64
    | 4 -> reader.ReadInt32(span, 0) |> int64
    | 8 -> reader.ReadInt64(span, 0)
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
    | 1 -> reader.ReadUInt8(span, 0) |> uint64
    | 2 -> reader.ReadUInt16(span, 0) |> uint64
    | 4 -> reader.ReadUInt32(span, 0) |> uint64
    | 8 -> reader.ReadUInt64(span, 0)
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

  /// Constructs a BinHandle from a given file path, ISA, optional base address
  /// (baseAddrOpt). File format will be automatically detected from the file.
  new(path, isa, baseAddrOpt) =
    let bytes = File.ReadAllBytes path
    let struct (fmt, isa) = FormatDetector.identify bytes isa
    BinHandle(path, bytes, fmt, isa, baseAddrOpt, None)

  /// Constructs a BinHandle from a given file path and ISA.
  new(path, isa) = BinHandle(path = path, isa = isa, baseAddrOpt = None)

  /// Constructs a BinHandle from a given file path. ISA is set to
  /// `ISA.DefaultISA`.
  new(path) =
    let defaultISA = ISA(Architecture.Intel, WordSize.Bit64)
    BinHandle(path = path, isa = defaultISA, baseAddrOpt = None)

  /// <summary>
  /// Constructs a BinHandle from a given byte array and ISA. The array is taken
  /// as a raw image: no format detection runs over it, the base address is 0UL,
  /// and the OS is unknown. Use <c>LoadFileBytes</c> instead when the array
  /// holds the whole content of a file whose format should be detected.
  /// </summary>
  new(bytes, isa) = BinHandle("", bytes, RawBinary, isa, None, None)

  /// Constructs a BinHandle from a given byte array, ISA, and target OS. The
  /// format is treated as a raw image (no detection) and the OS is used to pick
  /// the calling and system-call conventions. Useful for analyzing shellcode
  /// whose OS cannot be inferred from a file format.
  new(bytes, isa, os) = BinHandle("", bytes, RawBinary, isa, None, Some os)

  /// Constructs a BinHandle from a given byte array, ISA, base address, and
  /// target OS. The format is treated as a raw image (no detection). A raw
  /// image implies no OS, so the OS is spelled out here rather than defaulted,
  /// which is what keeps a rebased image from silently taking UnknownOS
  /// conventions.
  new(bytes, isa, baseAddr: Addr, os: OS) =
    BinHandle("", bytes, RawBinary, isa, Some baseAddr, Some os)

  /// Constructs an empty BinHandle.
  new(isa) = BinHandle("", [||], RawBinary, isa, None, None)

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

  /// <summary>
  /// Creates a BinHandle from a byte array holding the whole content of a
  /// binary file, detecting its file format and rebasing it to the given base
  /// address (baseAddrOpt) when one is given. This is the in-memory counterpart
  /// of the path-based constructors; the byte-array constructors differ in that
  /// they take the array as a raw image.
  /// </summary>
  /// <param name="bytes">The whole content of a binary file.</param>
  /// <param name="isa">The ISA to fall back on when the format does not pin
  /// one.</param>
  /// <param name="baseAddrOpt">An optional base address to rebase to.</param>
  /// <returns>
  /// Returns a new BinHandle.
  /// </returns>
  static member LoadFileBytes(bytes, isa, baseAddrOpt) =
    let struct (fmt, isa) = FormatDetector.identify bytes isa
    BinHandle("", bytes, fmt, isa, baseAddrOpt, None)

  /// <summary>
  /// Creates a BinHandle from a byte array holding the whole content of a
  /// binary file, detecting its file format. The OS follows from the detected
  /// format.
  /// </summary>
  /// <param name="bytes">The whole content of a binary file.</param>
  /// <param name="isa">The ISA to fall back on when the format does not pin
  /// one.</param>
  /// <returns>
  /// Returns a new BinHandle.
  /// </returns>
  static member LoadFileBytes(bytes: byte[], isa) =
    BinHandle.LoadFileBytes(bytes, isa, None)

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

// vim: set tw=80 sts=2 sw=2:
