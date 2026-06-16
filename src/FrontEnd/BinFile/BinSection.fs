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

/// Represents a format-agnostic binary section.
type BinSection =
  { /// Section name.
    Name: string
    /// Virtual address of the section.
    Address: Addr
    /// Section size in memory.
    Size: uint64
    /// File offset of the section. None when the format records no meaningful
    /// file position for the section. A section can have an offset yet hold no
    /// file-backed data (e.g., ELF .bss), in which case FileSize is 0.
    Offset: uint64 option
    /// Size of the section's file-backed data. 0 when the section occupies no
    /// space in the file (e.g., uninitialized data).
    FileSize: uint64
    /// Section permission.
    Permission: Permission
    /// Section kind.
    Kind: BinSectionKind }

/// Represents the kind of a binary section.
and BinSectionKind =
  /// The section contains executable code.
  | Code
  /// The section contains initialized data.
  | Data
  /// The section occupies memory but has no file-backed contents.
  | UninitializedData
  /// The section contains thread-local storage data.
  | ThreadLocalStorage
  /// The section contains resources.
  | Resource
  /// The section contains debug information.
  | Debug
  /// The section contains linker, loader, symbol, relocation, or other
  /// structural metadata.
  | Metadata
  /// The section implements dynamic linkage, such as a PLT, stubs, or
  /// symbol-pointer tables.
  | DynamicLinkage
  /// The section kind is unknown or not classified.
  | Unknown