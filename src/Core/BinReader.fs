(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>
          Seung Il Jung <sijung@kaist.ac.kr>
          DongYeop Oh <oh51dy@kaist.ac.kr>

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

open System.Runtime.InteropServices

/// BinReader abstracts away the process of reading byte sequences. This is the
/// base class for BinReader, which has two kinds of implementations:
/// little-endian and big-endian BinReader.
[<AbstractClass>]
type BinReader (bytes: byte []) =
  /// The byte array stored for this reader.
  member val Bytes = bytes with get

  /// Peek a single byte at the given offset.
  member __.PeekByte (o) = bytes.[o]

  /// Peek a single byte as an int8 type at the given offset.
  member __.PeekInt8 (o) = int8 bytes.[o]

  /// Peek a single byte as a uint8 type at the given offset.
  member __.PeekUInt8 (o) = uint8 bytes.[o]

  /// Peek byte array of size n at the given offset.
  member __.PeekBytes (n, o) = Array.sub bytes o n

  /// Peek byte array of size n at the given offset.
  member __.PeekBytes (n: uint64, o: uint64) =
    __.PeekBytes (System.Convert.ToInt32 n, System.Convert.ToInt32 o)

  /// Peek a character array of size n at the given offset.
  member __.PeekChars (n: int, o: int) = __.PeekBytes (n, o) |> Array.map char

  /// Peek a number (64-bit integer) using the ULEB128 method.
  member __.PeekULEB128 (o: int) =
    let rec readLoop n cnt offset  =
      let b = __.PeekByte (offset)
      let acc = (uint64 (b &&& 0x7Fuy) <<< (cnt * 7)) ||| n
      if b &&& 0x80uy <> 0uy then readLoop acc (cnt + 1) (offset + 1)
      else acc, cnt + 1
    readLoop 0UL 0 o

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

  /// Length of the file for this reader.
  member __.Length () = Array.length bytes

  /// Is the given offset points to a position out of the range of the file?
  member __.IsOutOfRange (o) = Array.length bytes <= o

  /// Instantiate BinReader  from a given byte array and endianness.
  static member Init
    (bytes, [<Optional; DefaultParameterValue(Endian.Little)>] endian) =
    match endian with
    | Endian.Little -> BinReaderLE (bytes) :> BinReader
    | Endian.Big -> BinReaderBE (bytes) :> BinReader
    | _ -> invalidArg "BinReader.init" "Invalid endian is given."

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
    (int16 bytes.[o + 1] <<< 8) ||| int16 bytes.[o]

  override __.PeekUInt16 (o) =
    (uint16 bytes.[o + 1] <<< 8) ||| uint16 bytes.[o]

  override __.PeekInt32 (o) =
    (int32 bytes.[o + 3] <<< 24)
    ||| (int32 bytes.[o + 2] <<< 16)
    ||| (int32 bytes.[o + 1] <<< 8)
    ||| (int32 bytes.[o])

  override __.PeekUInt32 (o) =
    (uint32 bytes.[o + 3] <<< 24)
    ||| (uint32 bytes.[o + 2] <<< 16)
    ||| (uint32 bytes.[o + 1] <<< 8)
    ||| (uint32 bytes.[o])

  override __.PeekInt64 (o) =
    (int64 bytes.[o + 7] <<< 56)
    ||| (int64 bytes.[o + 6] <<< 48)
    ||| (int64 bytes.[o + 5] <<< 40)
    ||| (int64 bytes.[o + 4] <<< 32)
    ||| (int64 bytes.[o + 3] <<< 24)
    ||| (int64 bytes.[o + 2] <<< 16)
    ||| (int64 bytes.[o + 1] <<< 8)
    ||| (int64 bytes.[o])

  override __.PeekUInt64 (o) =
    (uint64 bytes.[o + 7] <<< 56)
    ||| (uint64 bytes.[o + 6] <<< 48)
    ||| (uint64 bytes.[o + 5] <<< 40)
    ||| (uint64 bytes.[o + 4] <<< 32)
    ||| (uint64 bytes.[o + 3] <<< 24)
    ||| (uint64 bytes.[o + 2] <<< 16)
    ||| (uint64 bytes.[o + 1] <<< 8)
    ||| (uint64 bytes.[o])

  override __.Endianness = Endian.Little

/// This is a BinReader that reads values in a big-endian manner.
and internal BinReaderBE (bytes: byte []) =
  inherit BinReader (bytes)

  override __.PeekInt16 (o) =
    (int16 bytes.[o] <<< 8) ||| int16 bytes.[o + 1]

  override __.PeekUInt16 (o) =
    (uint16 bytes.[o] <<< 8) ||| uint16 bytes.[o + 1]

  override __.PeekInt32 (o) =
    (int32 bytes.[o] <<< 24)
    ||| (int32 bytes.[o + 1] <<< 16)
    ||| (int32 bytes.[o + 2] <<< 8)
    ||| (int32 bytes.[o + 3])

  override __.PeekUInt32 (o) =
    (uint32 bytes.[o] <<< 24)
    ||| (uint32 bytes.[o + 1] <<< 16)
    ||| (uint32 bytes.[o + 2] <<< 8)
    ||| (uint32 bytes.[o + 3])

  override __.PeekInt64 (o) =
    (int64 bytes.[o] <<< 56)
    ||| (int64 bytes.[o + 1] <<< 48)
    ||| (int64 bytes.[o + 2] <<< 40)
    ||| (int64 bytes.[o + 3] <<< 32)
    ||| (int64 bytes.[o + 4] <<< 24)
    ||| (int64 bytes.[o + 5] <<< 16)
    ||| (int64 bytes.[o + 6] <<< 8)
    ||| (int64 bytes.[o + 7])

  override __.PeekUInt64 (o) =
    (uint64 bytes.[o] <<< 56)
    ||| (uint64 bytes.[o + 1] <<< 48)
    ||| (uint64 bytes.[o + 2] <<< 40)
    ||| (uint64 bytes.[o + 3] <<< 32)
    ||| (uint64 bytes.[o + 4] <<< 24)
    ||| (uint64 bytes.[o + 5] <<< 16)
    ||| (uint64 bytes.[o + 6] <<< 8)
    ||| (uint64 bytes.[o + 7])

  override __.Endianness = Endian.Big

// vim: set tw=80 sts=2 sw=2:
