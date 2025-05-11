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

/// Represents the category of a binary file.
type FileType =
  /// Executable.
  | ExecutableFile = 1
  /// Core (core dump).
  | CoreFile = 2
  /// Library.
  | LibFile = 3
  /// Object.
  | ObjFile = 4
  /// Other types.
  | UnknownFile = 5

/// <summary>
/// Provides functions to work with <see
/// cref='T:B2R2.FrontEnd.BinFile.FileType'/>.
/// </summary>
[<RequireQualifiedAccess>]
module FileType =
  /// <summary>
  /// Convert <see cref="T:B2R2.FrontEnd.BinFile.FileType">FileType</see> to
  /// string.
  /// </summary>
  /// <param name="ty">A FileType to convert.</param>
  /// <returns>
  /// A converted string.
  /// </returns>
  [<CompiledName ("ToString")>]
  let toString ty =
    match ty with
    | FileType.ExecutableFile -> "Executable"
    | FileType.CoreFile -> "Core dump"
    | FileType.LibFile -> "Library"
    | FileType.ObjFile -> "Object"
    | _ -> "Unknown"
