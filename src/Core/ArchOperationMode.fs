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

/// Raised when an invalid ArchOperationMode is given.
exception InvalidTargetArchModeException

/// Some ISA, such as ARM, have their own operation mode, which can vary at
/// runtime. For example, ARM architecture can switch between Thumb and ARM
/// mode. In such architectures, the parsing/lifting logic will vary depending
/// on the ArchOperationMode. For most other architectures, it will always be
/// NoMode.
type ArchOperationMode =
  /// ARM mode.
  | ARMMode = 1
  /// Thumb mode.
  | ThumbMode = 2
  /// No mode. This is used for architectures that do not have any operation
  /// mode.
  | NoMode = 3

/// A helper module for ArchOperationMode.
[<RequireQualifiedAccess>]
module ArchOperationMode =
  let ofString (s: string) =
    match s.ToLowerInvariant () with
    | "arm" -> ArchOperationMode.ARMMode
    | "thumb" -> ArchOperationMode.ThumbMode
    | _ -> ArchOperationMode.NoMode

  let toString mode =
    match mode with
    | ArchOperationMode.ARMMode -> "arm"
    | ArchOperationMode.ThumbMode -> "thumb"
    | _ -> "nomode"
