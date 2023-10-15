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

/// IBinFile describes a binary file in a format-agnostic way.
type IBinFile =
  inherit IBinMetadata
  inherit IBinProperty
  inherit IContentAddressable
  inherit IBinSymbolTable
  inherit IBinOrganization

  /// <summary>
  ///   Return a new BinFile by replacing the content with the given byte array,
  ///   assuming the file format, ISA, and its file path do not change. The new
  ///   byte array is placed at the same base address as the original one. This
  ///   function does not directly affect the corresponding file in the file
  ///   system, though.
  /// </summary>
  /// <return>
  ///   A newly generated BinFile.
  /// </return>
  abstract NewBinFile: byte[] -> IBinFile

  /// <summary>
  ///   Return a new BinFile by replacing the content with the given byte array,
  ///   assuming the file format, ISA, and its file path do not change. The new
  ///   byte array is placed at the given base address (baseAddr). This function
  ///   does not directly affect the corresponding file in the file system,
  ///   though.
  /// </summary>
  /// <return>
  ///   A newly generated BinFile.
  /// </return>
  abstract NewBinFile: byte[] * baseAddr: Addr -> IBinFile
