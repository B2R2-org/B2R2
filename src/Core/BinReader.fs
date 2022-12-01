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

namespace B2R2

open System
open System.Buffers.Binary

/// This is a type alias for `ReadOnlySpan<byte>`. We define this alias because
/// B2R2 uses this type quite frequently.
type ByteSpan = ReadOnlySpan<byte>

/// IBinReader provides an interface for reading byte sequences from a byte
/// array (or a Span). The way of reading can change depending on the endianness
/// used by the target binary.
type IBinReader =
  /// Get a read-only span of bytes (ByteSpan) from the given byte
  /// array.
  abstract GetReadOnlySpan:
    bs: byte[] * offset: int * size: int -> ByteSpan

  /// The endianness of this reader.
  abstract Endianness: Endian

  /// Read a single byte from the given byte array.
  abstract ReadByte: bs: byte[] * offset: int -> byte

  /// Read a single byte from the given byte span.
  abstract ReadByte: span: ByteSpan * offset: int -> byte

  /// Read a single byte as an int8 from the given byte array.
  abstract ReadInt8: bs: byte[] * offset: int -> int8

  /// Read a single byte as an int8 from the given byte span.
  abstract ReadInt8: span: ByteSpan * offset: int -> int8

  /// Read a single byte as a uint8 from the given byte array.
  abstract ReadUInt8: bs: byte[] * offset: int -> uint8

  /// Read a single byte as a uint8 from the given byte array.
  abstract ReadUInt8: span: ByteSpan * offset: int -> uint8

  /// Read an int16 value from the given byte array.
  abstract ReadInt16: bs: byte[] * offset: int -> int16

  /// Read an int16 value from the given byte span.
  abstract ReadInt16: span: ByteSpan * offset: int -> int16

  /// Read a uint16 value from the given byte array.
  abstract ReadUInt16: bs: byte[] * offset: int -> uint16

  /// Read a uint16 value from the given byte span.
  abstract ReadUInt16: span: ByteSpan * offset: int -> uint16

  /// Read an int32 value from the given byte array.
  abstract ReadInt32: bs: byte[] * offset: int -> int32

  /// Read an int32 value from the given byte span.
  abstract ReadInt32: span: ByteSpan * offset: int -> int32

  /// Read a uint32 value from the given byte array.
  abstract ReadUInt32: bs: byte[] * offset: int -> uint32

  /// Read a uint32 value from the given byte span.
  abstract ReadUInt32: span: ByteSpan * offset: int -> uint32

  /// Read an int64 value from the given byte array.
  abstract ReadInt64: bs: byte[] * offset: int -> int64

  /// Read an int64 value from the given byte span.
  abstract ReadInt64: span: ByteSpan * offset: int -> int64

  /// Read a uint64 value from the given byte array.
  abstract ReadUInt64: bs: byte[] * offset: int -> uint64

  /// Read a uint64 value from the given byte span.
  abstract ReadUInt64: span: ByteSpan * offset: int -> uint64

  /// Read a byte array of `size` from the given byte array.
  abstract ReadBytes: bs: byte[] * offset: int * size: int -> byte[]

  /// Read a byte array of `size` from the given byte span.
  abstract ReadBytes:
    span: ByteSpan * offset: int * size: int -> byte[]

  /// Read a character array of size n from the given byte array.
  abstract ReadChars: bs: byte[] * offset: int * size: int -> char[]

  /// Read a character array of `size` from the given byte span.
  abstract ReadChars:
    span: ByteSpan * offset: int * size: int -> char[]

  /// Read a LEB128-encoded integer from the given byte array. This function
  /// returns a tuple of (the decoded int64, and the count of how many bytes
  /// were read).
  abstract ReadInt64LEB128: bs: byte[] * offset: int -> int64 * int

  /// Read a LEB128-encoded integer from the given byte span. This function
  /// returns a tuple of (the decoded int64, and the count of how many bytes
  /// were read).
  abstract ReadInt64LEB128:
    span: ByteSpan * offset: int -> int64 * int

  /// Read a LEB128-encoded integer from the given byte array. This function
  /// returns a tuple of (the decoded uint64, and the count of how many bytes
  /// were read).
  abstract ReadUInt64LEB128: bs: byte[] * offset: int -> uint64 * int

  /// Read a LEB128-encoded integer from the given byte span. This function
  /// returns a tuple of (the decoded uint64, and the count of how many bytes
  /// were read).
  abstract ReadUInt64LEB128:
    span: ByteSpan * offset: int -> uint64 * int

  /// Read a LEB128-encoded integer from the given byte array. This function
  /// returns a tuple of (the decoded int32, and the count of how many bytes
  /// were read).
  abstract ReadInt32LEB128: bs: byte[] * offset: int -> int32 * int

  /// Read a LEB128-encoded integer from the given byte span. This function
  /// returns a tuple of (the decoded int32, and the count of how many bytes
  /// were read).
  abstract ReadInt32LEB128:
    span: ByteSpan * offset: int -> int32 * int

  /// Read a LEB128-encoded integer from the given byte array. This function
  /// returns a tuple of (the decoded uint32, and the count of how many bytes
  /// were read).
  abstract ReadUInt32LEB128: bs: byte[] * offset: int -> uint32 * int

  /// Read a LEB128-encoded integer from the given byte span. This function
  /// returns a tuple of (the decoded uint32, and the count of how many bytes
  /// were read).
  abstract ReadUInt32LEB128:
    span: ByteSpan * offset: int -> uint32 * int

/// Little-endian binary reader.
type BinReaderLE () =
  interface IBinReader with
    member __.GetReadOnlySpan (bs, offset, size) =
      let span = ReadOnlySpan (bs)
      span.Slice (offset, size)

    member __.Endianness with get() = Endian.Little

    member __.ReadByte (bs: byte[], offset) =
      bs[offset]

    member __.ReadByte (span: ByteSpan, offset) =
      span[offset]

    member __.ReadInt8 (bs: byte[], offset) =
      bs[offset] |> int8

    member __.ReadInt8 (span: ByteSpan, offset) =
      span[offset] |> int8

    member __.ReadUInt8 (bs: byte[], offset) =
      bs[offset] |> uint8

    member __.ReadUInt8 (span: ByteSpan, offset) =
      span[offset] |> uint8

    member __.ReadInt16 (bs: byte[], offset) =
      let span = ReadOnlySpan (bs)
      BinaryPrimitives.ReadInt16LittleEndian (span.Slice offset)

    member __.ReadInt16 (span: ByteSpan, offset) =
      BinaryPrimitives.ReadInt16LittleEndian (span.Slice offset)

    member __.ReadUInt16 (bs: byte[], offset) =
      let span = ReadOnlySpan (bs)
      BinaryPrimitives.ReadUInt16LittleEndian (span.Slice offset)

    member __.ReadUInt16 (span: ByteSpan, offset) =
      BinaryPrimitives.ReadUInt16LittleEndian (span.Slice offset)

    member __.ReadInt32 (bs: byte[], offset) =
      let span = ReadOnlySpan (bs)
      BinaryPrimitives.ReadInt32LittleEndian (span.Slice offset)

    member __.ReadInt32 (span: ByteSpan, offset) =
      BinaryPrimitives.ReadInt32LittleEndian (span.Slice offset)

    member __.ReadUInt32 (bs: byte[], offset) =
      let span = ReadOnlySpan (bs)
      BinaryPrimitives.ReadUInt32LittleEndian (span.Slice offset)

    member __.ReadUInt32 (span: ByteSpan, offset) =
      BinaryPrimitives.ReadUInt32LittleEndian (span.Slice offset)

    member __.ReadInt64 (bs: byte[], offset) =
      let span = ReadOnlySpan (bs)
      BinaryPrimitives.ReadInt64LittleEndian (span.Slice offset)

    member __.ReadInt64 (span: ByteSpan, offset) =
      BinaryPrimitives.ReadInt64LittleEndian (span.Slice offset)

    member __.ReadUInt64 (bs: byte[], offset) =
      let span = ReadOnlySpan (bs)
      BinaryPrimitives.ReadUInt64LittleEndian (span.Slice offset)

    member __.ReadUInt64 (span: ByteSpan, offset) =
      BinaryPrimitives.ReadUInt64LittleEndian (span.Slice offset)

    member __.ReadBytes (bs: byte[], offset, size) =
      Array.sub bs offset size

    member __.ReadBytes (span: ByteSpan, offset, size) =
      span.Slice(offset, size).ToArray()

    member __.ReadChars (bs: byte[], offset, size) =
      Array.sub bs offset size
      |> Array.map char

    member __.ReadChars (span: ByteSpan, offset, size) =
      span.Slice(offset, size).ToArray()
      |> Array.map char

    member __.ReadInt64LEB128 (bs: byte[], offset) =
      let span = ReadOnlySpan (bs)
      LEB128.DecodeSInt64 (span.Slice offset)

    member __.ReadInt64LEB128 (span: ByteSpan, offset) =
      LEB128.DecodeSInt64 (span.Slice offset)

    member __.ReadUInt64LEB128 (bs: byte[], offset) =
      let span = ReadOnlySpan (bs)
      LEB128.DecodeUInt64 (span.Slice offset)

    member __.ReadUInt64LEB128 (span: ByteSpan, offset) =
      LEB128.DecodeUInt64 (span.Slice offset)

    member __.ReadInt32LEB128 (bs: byte[], offset) =
      let span = ReadOnlySpan (bs)
      LEB128.DecodeSInt32 (span.Slice offset)

    member __.ReadInt32LEB128 (span: ByteSpan, offset) =
      LEB128.DecodeSInt32 (span.Slice offset)

    member __.ReadUInt32LEB128 (bs: byte[], offset) =
      let span = ReadOnlySpan (bs)
      LEB128.DecodeUInt32 (span.Slice offset)

    member __.ReadUInt32LEB128 (span: ByteSpan, offset) =
      LEB128.DecodeUInt32 (span.Slice offset)

/// Big-endian binary reader.
type BinReaderBE () =
  interface IBinReader with
    member __.GetReadOnlySpan (bs, offset, size) =
      let span = ReadOnlySpan (bs)
      span.Slice (offset, size)

    member __.Endianness with get() = Endian.Big

    member __.ReadByte (bs: byte[], offset) =
      bs[offset]

    member __.ReadByte (span: ByteSpan, offset) =
      span[offset]

    member __.ReadInt8 (bs: byte[], offset) =
      bs[offset] |> int8

    member __.ReadInt8 (span: ByteSpan, offset) =
      span[offset] |> int8

    member __.ReadUInt8 (bs: byte[], offset) =
      bs[offset] |> uint8

    member __.ReadUInt8 (span: ByteSpan, offset) =
      span[offset] |> uint8

    member __.ReadInt16 (bs: byte[], offset) =
      let span = ReadOnlySpan (bs)
      BinaryPrimitives.ReadInt16BigEndian (span.Slice offset)

    member __.ReadInt16 (span: ByteSpan, offset) =
      BinaryPrimitives.ReadInt16BigEndian (span.Slice offset)

    member __.ReadUInt16 (bs: byte[], offset) =
      let span = ReadOnlySpan (bs)
      BinaryPrimitives.ReadUInt16BigEndian (span.Slice offset)

    member __.ReadUInt16 (span: ByteSpan, offset) =
      BinaryPrimitives.ReadUInt16BigEndian (span.Slice offset)

    member __.ReadInt32 (bs: byte[], offset) =
      let span = ReadOnlySpan (bs)
      BinaryPrimitives.ReadInt32BigEndian (span.Slice offset)

    member __.ReadInt32 (span: ByteSpan, offset) =
      BinaryPrimitives.ReadInt32BigEndian (span.Slice offset)

    member __.ReadUInt32 (bs: byte[], offset) =
      let span = ReadOnlySpan (bs)
      BinaryPrimitives.ReadUInt32BigEndian (span.Slice offset)

    member __.ReadUInt32 (span: ByteSpan, offset) =
      BinaryPrimitives.ReadUInt32BigEndian (span.Slice offset)

    member __.ReadInt64 (bs: byte[], offset) =
      let span = ReadOnlySpan (bs)
      BinaryPrimitives.ReadInt64BigEndian (span.Slice offset)

    member __.ReadInt64 (span: ByteSpan, offset) =
      BinaryPrimitives.ReadInt64BigEndian (span.Slice offset)

    member __.ReadUInt64 (bs: byte[], offset) =
      let span = ReadOnlySpan (bs)
      BinaryPrimitives.ReadUInt64BigEndian (span.Slice offset)

    member __.ReadUInt64 (span: ByteSpan, offset) =
      BinaryPrimitives.ReadUInt64BigEndian (span.Slice offset)

    member __.ReadBytes (bs: byte[], offset, size) =
      Array.sub bs offset size

    member __.ReadBytes (span: ByteSpan, offset, size) =
      span.Slice(offset, size).ToArray()

    member __.ReadChars (bs: byte[], offset, size) =
      Array.sub bs offset size
      |> Array.map char

    member __.ReadChars (span: ByteSpan, offset, size) =
      span.Slice(offset, size).ToArray()
      |> Array.map char

    member __.ReadInt64LEB128 (bs: byte[], offset) =
      let span = ReadOnlySpan (bs)
      LEB128.DecodeSInt64 (span.Slice offset)

    member __.ReadInt64LEB128 (span: ByteSpan, offset) =
      LEB128.DecodeSInt64 (span.Slice offset)

    member __.ReadUInt64LEB128 (bs: byte[], offset) =
      let span = ReadOnlySpan (bs)
      LEB128.DecodeUInt64 (span.Slice offset)

    member __.ReadUInt64LEB128 (span: ByteSpan, offset) =
      LEB128.DecodeUInt64 (span.Slice offset)

    member __.ReadInt32LEB128 (bs: byte[], offset) =
      let span = ReadOnlySpan (bs)
      LEB128.DecodeSInt32 (span.Slice offset)

    member __.ReadInt32LEB128 (span: ByteSpan, offset) =
      LEB128.DecodeSInt32 (span.Slice offset)

    member __.ReadUInt32LEB128 (bs: byte[], offset) =
      let span = ReadOnlySpan (bs)
      LEB128.DecodeUInt32 (span.Slice offset)

    member __.ReadUInt32LEB128 (span: ByteSpan, offset) =
      LEB128.DecodeUInt32 (span.Slice offset)

[<RequireQualifiedAccess>]
module BinReader =
  [<CompiledName ("BinReaderLE")>]
  let binReaderLE = BinReaderLE () :> IBinReader

  [<CompiledName ("BinReaderBE")>]
  let binReaderBE = BinReaderBE () :> IBinReader
