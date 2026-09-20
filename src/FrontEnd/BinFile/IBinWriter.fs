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

namespace B2R2.FrontEnd.BinFile

open B2R2

/// <summary>
/// Represents a binary file that can be edited and written back out. A writer
/// remembers every edit asked of it until <see
/// cref='M:B2R2.FrontEnd.BinFile.IBinWriter.Emit'/> turns them into the bytes
/// of a file, so an edit changes the writer rather than handing back another.
/// </summary>
/// <remarks>
/// Only what a file of any format can be asked for is here: the bytes of the
/// file, and the two ways of reaching a place in it. What one format alone
/// can be asked for, such as the sections ELF numbers or the symbols it keeps
/// for itself, belongs to the writer of that format.
/// </remarks>
type IBinWriter =
  /// <summary>
  /// Returns the bytes of the file as the edits asked for so far leave it. A
  /// writer nothing has been asked of hands back the file it started from.
  /// </summary>
  abstract Emit: unit -> byte[]

  /// <summary>
  /// Puts the given bytes at the given offset into the file. Raises <see
  /// cref='T:B2R2.FrontEnd.BinFile.InvalidAddrWriteException'/> where the file
  /// does not reach that far.
  /// </summary>
  abstract PatchByOffset: offset: int * bytes: byte[] -> unit

  /// <summary>
  /// Puts the given bytes where the file keeps the given address. Raises <see
  /// cref='T:B2R2.FrontEnd.BinFile.InvalidAddrWriteException'/> where the
  /// address is not one the file holds bytes for, which is what an address of
  /// a section occupying memory alone is.
  /// </summary>
  abstract PatchByAddr: addr: Addr * bytes: byte[] -> unit
