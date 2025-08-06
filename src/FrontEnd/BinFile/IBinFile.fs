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

open System
open B2R2.FrontEnd.BinLifter

/// <summary>
/// Represents a format-agnostic binary file interface.
/// </summary>
[<Interface>]
type IBinFile =
  inherit IBinMetadata
  inherit IBinProperty
  inherit IContentAddressable
  inherit INameReadable
  inherit IBinOrganization
  inherit IRelocationTable
  inherit ILinkageTable

  /// Returns a reader for this binary file.
  abstract Reader: IBinReader

  /// Returns the raw file content as a byte array.
  abstract RawBytes: byte[]

  /// Returns the size of the associated binary file.
  abstract Length: int

  /// Slices the given binary file into a span of bytes of the specified length
  /// starting from the specified offset.
  static member Slice(file: IBinFile, offset, len) =
    ReadOnlySpan(file.RawBytes).Slice(offset, len)
