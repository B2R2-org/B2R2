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

namespace B2R2.FrontEnd.BinFile.PE

open System
open System.IO
open Microsoft.Win32.SafeHandles
open B2R2.FrontEnd.BinFile

/// Represents where the bytes of a PDB are read from. One whose bytes a
/// caller hands over is read out of the array holding them; one this reader
/// opens for itself is read out of the file a block at a time, because a PDB
/// runs to sizes no array can hold and reading symbols out of one touches
/// almost none of it.
type internal BlockSource =
  /// An array holding the whole of it.
  | ArraySource of byte[]
  /// A file it is read out of, and how many bytes that file holds.
  | FileSource of SafeFileHandle * int64

[<RequireQualifiedAccess>]
module internal BlockSource =
  /// Returns how many bytes the given source holds.
  let length = function
    | ArraySource bs -> int64 bs.Length
    | FileSource(_, len) -> len

  /// Fills the given stretch of the buffer from the given offset of the
  /// source. A read of a file comes back in as many pieces as the system
  /// cares to hand it over in, so it is asked again until it has given every
  /// byte asked of it, and a source running out before then is one to give
  /// up on rather than one to read a half of a block out of.
  let readInto source (buf: byte[]) bufOffset offset count =
    match source with
    | ArraySource bs ->
      if offset < 0L || offset + int64 count > int64 bs.Length then
        raise InvalidFileFormatException
      else
        Array.blit bs (int offset) buf bufOffset count
    | FileSource(handle, _) ->
      let mutable got = 0
      let mutable last = 1
      while got < count && last > 0 do
        let span = Span(buf, bufOffset + got, count - got)
        last <- RandomAccess.Read(handle, span, offset + int64 got)
        got <- got + last
      if got < count then raise InvalidFileFormatException else ()

  /// Returns the given count of bytes at the given offset of the source, as
  /// an array of their own.
  let read source offset count =
    let buf: byte[] = Array.zeroCreate count
    readInto source buf 0 offset count
    buf
