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

open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter

/// The main handle for reading/parsing a binary code. `BinHandle` essentially
/// provides an interface for a chunk of binary code for parsing instructions,
/// lifting instructions, or reading data from it.
type BinHandle =
  /// Construct a BinHandle from a given file path, ISA, optional base
  /// address (baseAddrOpt), and ArchOperationMode. File format will be
  /// automatically detected.
  new: path: string
     * isa: ISA
     * mode: ArchOperationMode
     * baseAddrOpt: Addr option
    -> BinHandle

  /// Construct a BinHandle from a given file path, ISA, and optional base
  /// address (baseAddrOpt). ArchOperationMode is set to NoMode.
  new: path: string * isa: ISA * baseAddrOpt: Addr option -> BinHandle

  /// Construct a BinHandle from a given file path and ISA. ArchOperationMode
  /// is set to NoMode.
  new: path: string * isa: ISA -> BinHandle

  /// Construct a BinHandle from a given byte array. File format detection is
  /// performed only if detectFormat is set to true.
  new: bytes: byte[]
     * isa: ISA
     * mode: ArchOperationMode
     * baseAddrOpt: Addr option
     * detectFormat: bool
    -> BinHandle

  /// Construct an empty BinHandle.
  new: isa: ISA -> BinHandle

  /// File handle.
  member File: IBinFile

  /// Register factory.
  member RegisterFactory: RegisterFactory

  /// Get a new instance of lifting unit.
  member NewLiftingUnit: unit -> LiftingUnit

  /// <summary>
  ///   Return the byte array of size (nBytes) located at the address (addr).
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <param name="nBytes">The size of the byte array (in bytes).</param>
  /// <returns>
  ///   Return (byte[]) if succeeded, (ErrorCase) otherwise.
  /// </returns>
  member TryReadBytes:
    addr: Addr * nBytes: int -> Result<byte[], ErrorCase>

  /// <summary>
  ///   Return the byte array of size (nBytes) pointed to by the pointer (ptr).
  /// </summary>
  /// <param name="ptr">The binary pointer.</param>
  /// <param name="nBytes">The size of the byte array (in bytes).</param>
  /// <returns>
  ///   Return (byte[]) if succeeded, (ErrorCase) otherwise.
  /// </returns>
  member TryReadBytes:
    ptr: BinFilePointer * nBytes: int -> Result<byte[], ErrorCase>

  /// <summary>
  ///   Return the byte array of size (nBytes) at the addr from the current
  ///   binary.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <param name="nBytes">The size of the byte array (in bytes).</param>
  /// <returns>
  ///   Return the byte array if succeed. Otherwise, raise an exception.
  /// </returns>
  member ReadBytes: addr: Addr * nBytes: int -> byte[]

  /// <summary>
  ///   Return the byte array of size (nBytes) pointed to by the binary file
  ///   pointer (ptr).
  /// </summary>
  /// <param name="ptr">BInaryPointer.</param>
  /// <param name="nBytes">The size of the byte array (in bytes).</param>
  /// <returns>
  ///   Return the byte array if succeed. Otherwise, raise an exception.
  /// </returns>
  member ReadBytes: ptr: BinFilePointer * nBytes: int -> byte[]

  /// <summary>
  ///   Return the corresponding integer of the size from the given address.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding value (int64) if the address and the size is
  ///   valid. Otherwise ErrorCase.
  /// </returns>
  member TryReadInt:
    addr: Addr * size: int -> Result<int64, ErrorCase>

  /// <summary>
  ///   Return the corresponding integer of the size from the given address
  ///   pointed to by the binary pointer (ptr).
  /// </summary>
  /// <param name="ptr">BinFilePointer.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding value (int64) if the address and the size is
  ///   valid. Otherwise ErrorCase.
  /// </returns>
  member TryReadInt:
    ptr: BinFilePointer * size: int -> Result<int64, ErrorCase>

  /// <summary>
  ///   Return the corresponding integer value at the addr of the size from the
  ///   current binary.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding integer (int64).
  /// </returns>
  member ReadInt: addr: Addr * size: int -> int64

  /// <summary>
  ///   Return the corresponding integer value of the size from the current
  ///   binary, which is pointed to by the binary file pointer (ptr).
  /// </summary>
  /// <param name="ptr">The binary pointer.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding integer (int64).
  /// </returns>
  member ReadInt: ptr: BinFilePointer * size: int -> int64

  /// <summary>
  ///   Return the corresponding unsigned integer of the size from the given
  ///   address.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding unsigned integer (uint64) if the address and
  ///   the size is valid. Otherwise, ErrorCase.
  /// </returns>
  member TryReadUInt:
    addr: Addr * size: int -> Result<uint64, ErrorCase>

  /// <summary>
  ///   Return the corresponding unsigned integer of the size from the address
  ///   pointed to by the binary file pointer (ptr).
  /// </summary>
  /// <param name="ptr">BinFilePointer.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding unsigned integer (uint64) if the address and
  ///   the size is valid. Otherwise, ErrorCase.
  /// </returns>
  member TryReadUInt:
    ptr: BinFilePointer * size: int -> Result<uint64, ErrorCase>

  /// <summary>
  ///   Return the corresponding unsigned integer value at the addr of the size
  ///   from the binary.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding unsigned integer (uint64).
  /// </returns>
  member ReadUInt: addr: Addr * size: int -> uint64

  /// <summary>
  ///   Return the corresponding unsigned integer value of the size from the
  ///   binary, which is pointed to by the binary file pointer (ptr).
  /// </summary>
  /// <param name="ptr">BinFilePointer.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding unsigned integer (uint64).
  /// </returns>
  member ReadUInt: ptr: BinFilePointer * size: int -> uint64

  /// <summary>
  ///   Return the ASCII string at the addr from the given BinHandle.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <returns>
  ///   Return the corresponding ASCII string.
  /// </returns>
  member ReadASCII: addr: Addr -> string

  /// <summary>
  ///   Return the ASCII string pointed to by the binary file pointer from the
  ///   given BinHandle.
  /// </summary>
  /// <param name="ptr">BinFilePointer.</param>
  /// <returns>
  ///   Return the corresponding ASCII string.
  /// </returns>
  member ReadASCII: ptr: BinFilePointer -> string

  /// <summary>
  ///   Create a new BinHandle from the given byte array while keeping the other
  ///   properties of the original BinHandle.
  /// </summary>
  /// <param name="bs">The byte array.</param>
  /// <returns>
  ///   Return a new BinHandle.
  /// </returns>
  member MakeNew: bs: byte[] -> BinHandle

  /// <summary>
  ///   Create a new BinHandle from the given byte array while keeping the other
  ///   properties of the original BinHandle.
  /// </summary>
  /// <param name="bs">The byte array.</param>
  /// <param name="baseAddr">The new base address.</param>
  /// <returns>
  ///   Return a new BinHandle.
  /// </returns>
  member MakeNew: bs: byte[] * baseAddr: Addr -> BinHandle
