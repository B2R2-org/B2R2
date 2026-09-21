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

/// Represents what a runtime is to make of a managed image, which is what the
/// Flags field of its CLI header holds.
[<FlagsAttribute>]
type internal CorFlags =
  /// The image holds IL alone, and no native code at all.
  | ILOnly = 0x1
  /// The image can only be loaded into a 32-bit process.
  | Requires32Bit = 0x2
  /// The image is a library rather than a program.
  | ILLibrary = 0x4
  /// The image carries a strong name signature.
  | StrongNameSigned = 0x8
  /// The entry point of the image is native code rather than a token.
  | NativeEntryPoint = 0x10
  /// Debugging information is to be tracked.
  | TrackDebugData = 0x10000
  /// The image is to be run as a 32-bit process where that is a choice.
  | Prefers32Bit = 0x20000
