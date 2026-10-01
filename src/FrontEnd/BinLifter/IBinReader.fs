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

namespace B2R2.FrontEnd.BinLifter

open System
open B2R2

/// Provides an interface for reading byte sequences from a byte array (or a
/// ByteSpan). The endianness is determined by the implementation of the
/// interface.
type IBinReader =
  /// The endianness of this reader.
  abstract Endianness: Endian

  /// Reads a single byte as an int8 from the given byte array.
  abstract ReadInt8: bs: byte[] * offset: int -> int8

  /// Reads a single byte as an int8 from the given byte span.
  abstract ReadInt8: span: ByteSpan * offset: int -> int8

  /// Reads a single byte as a uint8 from the given byte array.
  abstract ReadUInt8: bs: byte[] * offset: int -> uint8

  /// Reads a single byte as a uint8 from the given byte array.
  abstract ReadUInt8: span: ByteSpan * offset: int -> uint8

  /// Reads an int16 value from the given byte array.
  abstract ReadInt16: bs: byte[] * offset: int -> int16

  /// Reads an int16 value from the given byte span.
  abstract ReadInt16: span: ByteSpan * offset: int -> int16

  /// Reads a uint16 value from the given byte array.
  abstract ReadUInt16: bs: byte[] * offset: int -> uint16

  /// Reads a uint16 value from the given byte span.
  abstract ReadUInt16: span: ByteSpan * offset: int -> uint16

  /// Reads an int32 value from the given byte array.
  abstract ReadInt32: bs: byte[] * offset: int -> int32

  /// Reads an int32 value from the given byte span.
  abstract ReadInt32: span: ByteSpan * offset: int -> int32

  /// Reads a uint32 value from the given byte array.
  abstract ReadUInt32: bs: byte[] * offset: int -> uint32

  /// Reads a uint32 value from the given byte span.
  abstract ReadUInt32: span: ByteSpan * offset: int -> uint32

  /// Reads an int64 value from the given byte array.
  abstract ReadInt64: bs: byte[] * offset: int -> int64

  /// Reads an int64 value from the given byte span.
  abstract ReadInt64: span: ByteSpan * offset: int -> int64

  /// Reads a uint64 value from the given byte array.
  abstract ReadUInt64: bs: byte[] * offset: int -> uint64

  /// Reads a uint64 value from the given byte span.
  abstract ReadUInt64: span: ByteSpan * offset: int -> uint64

  /// Reads a character array of size n from the given byte array.
  abstract ReadChars: bs: byte[] * offset: int * size: int -> char[]

  /// Reads a character array of `size` from the given byte span.
  abstract ReadChars:
    span: ByteSpan * offset: int * size: int -> char[]

  /// Reads a LEB128-encoded integer from the given byte array. This function
  /// returns a tuple of (the decoded int64, and the count of how many bytes
  /// were read).
  abstract ReadInt64LEB128: bs: byte[] * offset: int -> int64 * int

  /// Reads a LEB128-encoded integer from the given byte span. This function
  /// returns a tuple of (the decoded int64, and the count of how many bytes
  /// were read).
  abstract ReadInt64LEB128:
    span: ByteSpan * offset: int -> int64 * int

  /// Reads a LEB128-encoded integer from the given byte array. This function
  /// returns a tuple of (the decoded uint64, and the count of how many bytes
  /// were read).
  abstract ReadUInt64LEB128: bs: byte[] * offset: int -> uint64 * int

  /// Reads a LEB128-encoded integer from the given byte span. This function
  /// returns a tuple of (the decoded uint64, and the count of how many bytes
  /// were read).
  abstract ReadUInt64LEB128:
    span: ByteSpan * offset: int -> uint64 * int

  /// Reads a LEB128-encoded integer from the given byte array. This function
  /// returns a tuple of (the decoded int32, and the count of how many bytes
  /// were read).
  abstract ReadInt32LEB128: bs: byte[] * offset: int -> int32 * int

  /// Reads a LEB128-encoded integer from the given byte span. This function
  /// returns a tuple of (the decoded int32, and the count of how many bytes
  /// were read).
  abstract ReadInt32LEB128:
    span: ByteSpan * offset: int -> int32 * int

  /// Reads a LEB128-encoded integer from the given byte array. This function
  /// returns a tuple of (the decoded uint32, and the count of how many bytes
  /// were read).
  abstract ReadUInt32LEB128: bs: byte[] * offset: int -> uint32 * int

  /// Reads a LEB128-encoded integer from the given byte span. This function
  /// returns a tuple of (the decoded uint32, and the count of how many bytes
  /// were read).
  abstract ReadUInt32LEB128:
    span: ByteSpan * offset: int -> uint32 * int

/// <summary>
/// Represents a read-only span for byte arrays. This is a type alias for
/// <c>ReadOnlySpan&lt;byte&gt;</c>. We define this alias because B2R2 uses this
/// type quite frequently.
/// </summary>
and ByteSpan = ReadOnlySpan<byte>
