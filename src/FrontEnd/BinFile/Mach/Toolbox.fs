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

namespace B2R2.FrontEnd.BinFile.Mach

open B2R2
open B2R2.FrontEnd.BinLifter

/// Represents a basic toolbox for parsing Mach-O files, which is used by other
/// parsing functions.
type internal Toolbox =
  { /// Raw bytes of the Mach-O file.
    Bytes: byte[]
    /// Binary reader for reading the Mach-O file.
    Reader: IBinReader
    /// Base address.
    BaseAddress: Addr
    /// Mach-O header.
    Header: Header
    /// Offset from the start of the file to the Mach-O file format header. This
    /// is only meaningful for universal binaries.
    MachOffset: uint64
    /// ISA.
    ISA: ISA }
with
  /// Initializes a toolbox for Mach-O files.
  static member Init(bytes, struct (hdr, reader, baseAddr, machOffset, isa)) =
    { Bytes = bytes
      Reader = reader
      BaseAddress = baseAddr
      Header = hdr
      MachOffset = machOffset
      ISA = isa }
