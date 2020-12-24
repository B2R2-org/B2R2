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
open System.Runtime.InteropServices

/// BinReader abstracts away the process of reading byte sequences. This is the
/// base class for BinReader, which has two kinds of implementations:
/// little-endian and big-endian BinReader.
[<AbstractClass>]
type BinReader (bytes: byte []) =
  let mutable bytes = bytes

  /// The byte array stored for this reader.
  member __.Bytes with get () = bytes and set (bs) = bytes <- bs

  /// Peek a single byte at the given offset.
  member __.PeekByte (o) = bytes.[o]

  /// Peek a single byte as an int8 type at the given offset.
  member __.PeekInt8 (o) = int8 bytes.[o]

  /// Peek a single byte as a uint8 type at the given offset.
  member __.PeekUInt8 (o) = uint8 bytes.[o]

  /// Peek span of bytes of size n at the given offset.
  member __.PeekSpan (n, o) =
    let span = ReadOnlySpan bytes
    span.Slice (o, n)

  /// Peek span of bytes at the given offset to the end.
  member __.PeekSpan (o) =
    let span = ReadOnlySpan bytes
    span.Slice (o)

  /// Peek Memory of size n at the given offset.
  member __.PeekMem (n, o) =
    let span = ReadOnlyMemory bytes
    span.Slice (o, n)

  /// Peek byte array of size n at the given offset.
  member __.PeekBytes (n, o) = Array.sub bytes o n

  /// Peek a character array of size n at the given offset.
  member __.PeekChars (n, o) = __.PeekBytes (n, o) |> Array.map char

  member inline private __.peekLEB128 (o) cast maxLen =
    let rec readLoop offset count value len =
      let b = __.PeekByte(offset)
      let value' = value ||| (cast (b &&& 0x7fuy) <<< (count * 7))
      let offset' = offset + 1
      let count' = count + 1
      if b &&& 0x80uy <> 0uy && count = len - 1
      then raise LEB128DecodeException
      elif b &&& 0x80uy = 0uy then value', count'
      else readLoop offset' count' value' len
    readLoop o 0 (cast 0uy) maxLen

  member inline private __.extendSign b offset currentValue bitmask maxLen =
    if b &&& 0x40uy <> 0uy then
      let shiftOffset = if offset < (maxLen - 1) then offset + 1 else offset
      bitmask <<< (7 * (shiftOffset)) ||| currentValue
    else
      currentValue

  /// Peek a LEB128-encoded integer at the given offset.
  /// This function returns a tuple of
  /// (the decoded uint64, and the count of how many bytes were peeked).
  member __.PeekUInt64LEB128 (o: int) =
    __.peekLEB128 o uint64 LEB128.Max64

  /// Peek a LEB128-encoded integer at the given offset.
  /// This function returns a tuple of
  /// (the decoded uint32, and the count of how many bytes were peeked).
  member __.PeekUInt32LEB128 (o: int) =
    __.peekLEB128 o uint32 LEB128.Max32

  /// Peek a LEB128-encoded integer at the given offset.
  /// This function returns a tuple of
  /// (the decoded int64, and the count of how many bytes were peeked).
  member __.PeekInt64LEB128 (o: int) =
    let decoded, len = __.peekLEB128 o int64 LEB128.Max64
    let offset = len - 1
    let b = __.PeekByte(offset)
    __.extendSign b offset decoded 0xFFFFFFFFFFFFFFFFL LEB128.Max64, len

  /// Peek a LEB128-encoded integer at the given offset.
  /// This function returns a tuple of
  /// (the decoded int32, and the count of how many bytes were peeked).
  member __.PeekInt32LEB128 (o: int) =
    let decoded, len = __.peekLEB128 o int32 LEB128.Max32
    let offset = len - 1
    let b = __.PeekByte(offset)
    __.extendSign b offset decoded 0xFFFFFFFF LEB128.Max32, len

  /// Peek an int16 value at the given offset.
  abstract member PeekInt16: o: int -> int16

  /// Peek a uint16 value at the given offset.
  abstract member PeekUInt16: o: int -> uint16

  /// Peek an int32 value at the given offset.
  abstract member PeekInt32: o: int -> int32

  /// Peek a uint32 value at the given offset.
  abstract member PeekUInt32: o: int -> uint32

  /// Peek an int64 value at the given offset.
  abstract member PeekInt64: o: int -> int64

  /// Peek a uint64 value at the given offset.
  abstract member PeekUInt64: o: int -> uint64

  /// My endianness.
  abstract member Endianness: Endian

  /// Return a sub BinReader that serves a subset of the bytes starting at the
  /// offset (offset) and of the length (len).
  member __.SubReader offset len =
    let bs = Array.sub bytes offset len
    match __.Endianness with
    | Endian.Little -> BinReaderLE (bs) :> BinReader
    | _ -> BinReaderBE (bs) :> BinReader

  /// Read a character array of size n at the given offset. This function,
  /// unlike PeekChars, will return the next offset.
  member __.ReadChars (n, o) = struct (__.PeekChars (n, o), o + n)

  /// Read a byte array of size n at the given offset. This function, unlike
  /// PeekBytes, will return the next offset.
  member __.ReadBytes (n: int, o: int) = struct (__.PeekBytes (n, o), o + n)

  /// Read a byte at the given offset. This function, unlike PeekByte, will
  /// return the next offset.
  member __.ReadByte (o) = struct (__.PeekByte (o), o + 1)

  /// Read an int8 value at the given offset. This function, unlike PeekInt8,
  /// will return the next offset.
  member __.ReadInt8 (o) = struct (__.PeekInt8 (o), o + 1)

  /// Read a uint8 value at the given offset. This function, unlike PeekUInt8,
  /// will return the next offset.
  member __.ReadUInt8 (o) = struct (__.PeekUInt8 (o), o + 1)

  /// Read an int16 value at the given offset. This function, unlike PeekInt16,
  /// will return the next offset.
  member __.ReadInt16 (o) = struct (__.PeekInt16 (o), o + 2)

  /// Read a uint16 value at the given offset. This function, unlike PeekUInt16,
  /// will return the next offset.
  member __.ReadUInt16 (o) = struct (__.PeekUInt16 (o), o + 2)

  /// Read an int32 value at the given offset. This function, unlike PeekInt32,
  /// will return the next offset.
  member __.ReadInt32 (o) = struct (__.PeekInt32 (o), o + 4)

  /// Read a uint32 value at the given offset. This function, unlike PeekUInt32,
  /// will return the next offset.
  member __.ReadUInt32 (o) = struct (__.PeekUInt32 (o), o + 4)

  /// Read an int64 value at the given offset. This function, unlike PeekInt64,
  /// will return the next offset.
  member __.ReadInt64 (o) = struct (__.PeekInt64 (o), o + 8)

  /// Read a uint64 value at the given offset. This function, unlike PeekUInt64,
  /// will return the next offset.
  member __.ReadUInt64 (o) = struct (__.PeekUInt64 (o), o + 8)

  /// Read a LEB128-encoded integer into uint64 at the given offset.
  /// This function, unlike PeekUInt64LEB128, will return the next offset.
  member __.ReadUInt64LEB128 (o) =
    let decoded, len = __.PeekUInt64LEB128 (o)
    struct (decoded, o + len)

  /// Read a LEB128-encoded integer into uint32 at the given offset.
  /// This function, unlike PeekUInt32LEB128, will return the next offset.
  member __.ReadUInt32LEB128 (o) =
    let decoded, len = __.PeekUInt32LEB128 (o)
    struct (decoded, o + len)

  /// Read a LEB128-encoded integer into int64 at the given offset.
  /// This function, unlike PeekInt64LEB128, will return the next offset.
  member __.ReadInt64LEB128 (o) =
    let decoded, len = __.PeekInt64LEB128 (o)
    struct (decoded, o + len)

  /// Read a LEB128-encoded integer into int32 at the given offset.
  /// This function, unlike PeekInt32LEB128, will return the next offset.
  member __.ReadInt32LEB128 (o) =
    let decoded, len = __.PeekInt32LEB128 (o)
    struct (decoded, o + len)

  /// Length of the file for this reader.
  member __.Length () = Array.length bytes

  /// Is the given offset points to a position out of the range of the file?
  member __.IsOutOfRange (o) = o < 0 || Array.length bytes <= o

  /// Instantiate BinReader from a given byte array and endianness.
  static member Init
    (bytes, [<Optional; DefaultParameterValue(Endian.Little)>] endian) =
    match endian with
    | Endian.Little -> BinReaderLE (bytes) :> BinReader
    | Endian.Big -> BinReaderBE (bytes) :> BinReader
    | _ -> invalidArg (nameof endian) "Invalid endian is given."

  /// Return a new BinReader of the given endianness. This function will return
  /// the same reader if the given endianness is the same as the endianness of
  /// the original reader.
  static member RenewReader (reader: BinReader) endian =
    if reader.Endianness = endian then reader
    else BinReader.Init (reader.Bytes, endian)

/// This is a BinReader that reads values in a little-endian manner.
and internal BinReaderLE (bytes: byte []) =
  inherit BinReader (bytes)

  override __.PeekInt16 (o) =
    (int16 base.Bytes.[o + 1] <<< 8) ||| int16 base.Bytes.[o]

  override __.PeekUInt16 (o) =
    (uint16 base.Bytes.[o + 1] <<< 8) ||| uint16 base.Bytes.[o]

  override __.PeekInt32 (o) =
    (int32 base.Bytes.[o + 3] <<< 24)
    ||| (int32 base.Bytes.[o + 2] <<< 16)
    ||| (int32 base.Bytes.[o + 1] <<< 8)
    ||| (int32 base.Bytes.[o])

  override __.PeekUInt32 (o) =
    (uint32 base.Bytes.[o + 3] <<< 24)
    ||| (uint32 base.Bytes.[o + 2] <<< 16)
    ||| (uint32 base.Bytes.[o + 1] <<< 8)
    ||| (uint32 base.Bytes.[o])

  override __.PeekInt64 (o) =
    (int64 base.Bytes.[o + 7] <<< 56)
    ||| (int64 base.Bytes.[o + 6] <<< 48)
    ||| (int64 base.Bytes.[o + 5] <<< 40)
    ||| (int64 base.Bytes.[o + 4] <<< 32)
    ||| (int64 base.Bytes.[o + 3] <<< 24)
    ||| (int64 base.Bytes.[o + 2] <<< 16)
    ||| (int64 base.Bytes.[o + 1] <<< 8)
    ||| (int64 base.Bytes.[o])

  override __.PeekUInt64 (o) =
    (uint64 base.Bytes.[o + 7] <<< 56)
    ||| (uint64 base.Bytes.[o + 6] <<< 48)
    ||| (uint64 base.Bytes.[o + 5] <<< 40)
    ||| (uint64 base.Bytes.[o + 4] <<< 32)
    ||| (uint64 base.Bytes.[o + 3] <<< 24)
    ||| (uint64 base.Bytes.[o + 2] <<< 16)
    ||| (uint64 base.Bytes.[o + 1] <<< 8)
    ||| (uint64 base.Bytes.[o])

  override __.Endianness = Endian.Little

/// This is a BinReader that reads values in a big-endian manner.
and internal BinReaderBE (bytes: byte []) =
  inherit BinReader (bytes)

  override __.PeekInt16 (o) =
    (int16 base.Bytes.[o] <<< 8) ||| int16 base.Bytes.[o + 1]

  override __.PeekUInt16 (o) =
    (uint16 base.Bytes.[o] <<< 8) ||| uint16 base.Bytes.[o + 1]

  override __.PeekInt32 (o) =
    (int32 base.Bytes.[o] <<< 24)
    ||| (int32 base.Bytes.[o + 1] <<< 16)
    ||| (int32 base.Bytes.[o + 2] <<< 8)
    ||| (int32 base.Bytes.[o + 3])

  override __.PeekUInt32 (o) =
    (uint32 base.Bytes.[o] <<< 24)
    ||| (uint32 base.Bytes.[o + 1] <<< 16)
    ||| (uint32 base.Bytes.[o + 2] <<< 8)
    ||| (uint32 base.Bytes.[o + 3])

  override __.PeekInt64 (o) =
    (int64 base.Bytes.[o] <<< 56)
    ||| (int64 base.Bytes.[o + 1] <<< 48)
    ||| (int64 base.Bytes.[o + 2] <<< 40)
    ||| (int64 base.Bytes.[o + 3] <<< 32)
    ||| (int64 base.Bytes.[o + 4] <<< 24)
    ||| (int64 base.Bytes.[o + 5] <<< 16)
    ||| (int64 base.Bytes.[o + 6] <<< 8)
    ||| (int64 base.Bytes.[o + 7])

  override __.PeekUInt64 (o) =
    (uint64 base.Bytes.[o] <<< 56)
    ||| (uint64 base.Bytes.[o + 1] <<< 48)
    ||| (uint64 base.Bytes.[o + 2] <<< 40)
    ||| (uint64 base.Bytes.[o + 3] <<< 32)
    ||| (uint64 base.Bytes.[o + 4] <<< 24)
    ||| (uint64 base.Bytes.[o + 5] <<< 16)
    ||| (uint64 base.Bytes.[o + 6] <<< 8)
    ||| (uint64 base.Bytes.[o + 7])

  override __.Endianness = Endian.Big

// vim: set tw=80 sts=2 sw=2:
