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

/// <summary>
/// Represents the main data structure for accessing a chunk of binary code.
/// It provides ways to read raw data from the binary through addresses and to
/// access binary file metadata through the <see
/// cref='T:B2R2.FrontEnd.BinFile.IBinFile'/> interface. It also provides ways
/// to parse/lift instructions from the binary through <see
/// cref='T:B2R2.FrontEnd.LiftingUnit'/>.
/// </summary>
type BinHandle =
  /// Constructs a BinHandle from a given file path, ISA, optional base address
  /// (baseAddrOpt). File format will be automatically detected from the file.
  new: path: string
     * isa: ISA
     * baseAddrOpt: Addr option
    -> BinHandle

  /// Constructs a BinHandle from a given file path and ISA.
  new: path: string * isa: ISA -> BinHandle

  /// Constructs a BinHandle from a given file path. ISA is set to
  /// `ISA.DefaultISA`.
  new: path: string -> BinHandle

  /// Constructs a BinHandle from a given byte array. File format detection is
  /// performed only if detectFormat is set to true.
  new: bytes: byte[]
     * isa: ISA
     * baseAddrOpt: Addr option
     * detectFormat: bool
    -> BinHandle

  /// Constructs a BinHandle from a given byte array and ISA. The base address is
  /// set to 0UL, and file format detection is disabled.
  new: bytes: byte[] * isa: ISA -> BinHandle

  /// Constructs an empty BinHandle.
  new: isa: ISA -> BinHandle

  /// Gets the file handle.
  member File: IBinFile

  /// Gets the register factory.
  member RegisterFactory: IRegisterFactory

  /// Gets the calling convention.
  member CallingConvention: CallingConvention

  /// Gets the system-call convention.
  member SyscallConvention: SyscallConvention

  /// Gets a new instance of lifting unit.
  member NewLiftingUnit: unit -> LiftingUnit

  /// <summary>
  /// Returns the byte array of size (nBytes) pointed to by the pointer (ptr).
  /// </summary>
  /// <param name="ptr">The binary pointer.</param>
  /// <param name="nBytes">The size of the byte array (in bytes).</param>
  /// <returns>
  /// Returns (byte[]) if succeeded, (ErrorCase) otherwise.
  /// </returns>
  member TryReadBytes:
    ptr: BinFilePointer * nBytes: int -> Result<byte[], ErrorCase>

  /// <summary>
  /// Returns the byte array of size (nBytes) located at the address (addr).
  /// </summary>
  /// <param name="addr">The address</param>
  /// <param name="nBytes">The size of the byte array (in bytes).</param>
  /// <returns>
  /// Returns (byte[]) if succeeded, (ErrorCase) otherwise.
  /// </returns>
  member TryReadBytes:
    addr: Addr * nBytes: int -> Result<byte[], ErrorCase>

  /// <summary>
  /// Returns the byte array of size (nBytes) pointed to by the binary file
  /// pointer (ptr).
  /// </summary>
  /// <param name="ptr">BInaryPointer.</param>
  /// <param name="nBytes">The size of the byte array (in bytes).</param>
  /// <returns>
  /// Returns the byte array if succeed. Otherwise, raise an exception.
  /// </returns>
  member ReadBytes: ptr: BinFilePointer * nBytes: int -> byte[]

  /// <summary>
  /// Returns the byte array of size (nBytes) at the addr from the current
  /// binary.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <param name="nBytes">The size of the byte array (in bytes).</param>
  /// <returns>
  /// Returns the byte array if succeed. Otherwise, raise an exception.
  /// </returns>
  member ReadBytes: addr: Addr * nBytes: int -> byte[]

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
  member TryReadInt:
    addr: Addr * size: int -> Result<int64, ErrorCase>

  /// <summary>
  /// Returns the corresponding integer of the size from the given address
  /// pointed to by the binary pointer (ptr).
  /// </summary>
  /// <param name="ptr">BinFilePointer.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  /// Returns the corresponding value (int64) if the address and the size is
  /// valid. Otherwise ErrorCase.
  /// </returns>
  member TryReadInt:
    ptr: BinFilePointer * size: int -> Result<int64, ErrorCase>

  /// <summary>
  /// Returns the corresponding integer value of the size from the current
  /// binary, which is pointed to by the binary file pointer (ptr).
  /// </summary>
  /// <param name="ptr">The binary pointer.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  /// Returns the corresponding integer (int64).
  /// </returns>
  member ReadInt: ptr: BinFilePointer * size: int -> int64

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
  member ReadInt: addr: Addr * size: int -> int64

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
  member TryReadUInt:
    addr: Addr * size: int -> Result<uint64, ErrorCase>

  /// <summary>
  /// Returns the corresponding unsigned integer of the size from the address
  /// pointed to by the binary file pointer (ptr).
  /// </summary>
  /// <param name="ptr">BinFilePointer.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  /// Returns the corresponding unsigned integer (uint64) if the address and
  /// the size is valid. Otherwise, ErrorCase.
  /// </returns>
  member TryReadUInt:
    ptr: BinFilePointer * size: int -> Result<uint64, ErrorCase>

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
  member ReadUInt: addr: Addr * size: int -> uint64

  /// <summary>
  /// Returns the corresponding unsigned integer value of the size from the
  /// binary, which is pointed to by the binary file pointer (ptr).
  /// </summary>
  /// <param name="ptr">BinFilePointer.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  /// Returns the corresponding unsigned integer (uint64).
  /// </returns>
  member ReadUInt: ptr: BinFilePointer * size: int -> uint64

  /// <summary>
  /// Returns the ASCII string at the addr from the given BinHandle.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <returns>
  /// Returns the corresponding ASCII string.
  /// </returns>
  member ReadASCII: addr: Addr -> string

  /// <summary>
  /// Returns the ASCII string pointed to by the binary file pointer from the
  /// given BinHandle.
  /// </summary>
  /// <param name="ptr">BinFilePointer.</param>
  /// <returns>
  /// Returns the corresponding ASCII string.
  /// </returns>
  member ReadASCII: ptr: BinFilePointer -> string

  /// <summary>
  /// Creates a new BinHandle from the given byte array while keeping the other
  /// properties of the original BinHandle.
  /// </summary>
  /// <param name="bs">The byte array.</param>
  /// <returns>
  /// Returns a new BinHandle.
  /// </returns>
  member MakeNew: bs: byte[] -> BinHandle

  /// <summary>
  /// Creates a new BinHandle from the given byte array while keeping the other
  /// properties of the original BinHandle.
  /// </summary>
  /// <param name="bs">The byte array.</param>
  /// <param name="baseAddr">The new base address.</param>
  /// <returns>
  /// Returns a new BinHandle.
  /// </returns>
  member MakeNew: bs: byte[] * baseAddr: Addr -> BinHandle
