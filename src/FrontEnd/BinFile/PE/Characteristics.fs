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

/// Represents the attributes of a PE file, which is what the Characteristics
/// field of its COFF header holds.
[<FlagsAttribute>]
type internal Characteristics =
  /// Relocation information is stripped from the file.
  | RelocsStripped = 0x1us
  /// The file is executable, which is to say nothing is left unresolved in it.
  | ExecutableImage = 0x2us
  /// Line numbers are stripped from the file.
  | LineNumsStripped = 0x4us
  /// Local symbols are stripped from the file.
  | LocalSymsStripped = 0x8us
  /// The working set is to be trimmed aggressively.
  | AggressiveWSTrim = 0x10us
  /// The application can handle addresses larger than 2GB.
  | LargeAddressAware = 0x20us
  /// The bytes of a word are reversed, the low ones coming first.
  | BytesReversedLo = 0x80us
  /// The machine the file is built for has a 32-bit word.
  | Bit32Machine = 0x100us
  /// Debugging information is stripped from the file.
  | DebugStripped = 0x200us
  /// The image is to be copied to the swap file and run from there when it
  /// sits on removable media.
  | RemovableRunFromSwap = 0x400us
  /// The image is to be copied to the swap file and run from there when it
  /// sits on the network.
  | NetRunFromSwap = 0x800us
  /// The image is a system file rather than a user program.
  | System = 0x1000us
  /// The image is a dynamic-link library.
  | Dll = 0x2000us
  /// The file is to be run on a uniprocessor machine alone.
  | UpSystemOnly = 0x4000us
  /// The bytes of a word are reversed, the high ones coming first.
  | BytesReversedHi = 0x8000us
