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

/// Represents what a loader is to make of an image, which is what the
/// DllCharacteristics field of its optional header holds.
[<FlagsAttribute>]
type internal DllCharacteristics =
  /// Reserved: a per-process initialization routine, which no loader calls.
  | ProcessInit = 0x1us
  /// Reserved: a per-process termination routine, which no loader calls.
  | ProcessTerm = 0x2us
  /// Reserved: a per-thread initialization routine, which no loader calls.
  | ThreadInit = 0x4us
  /// Reserved: a per-thread termination routine, which no loader calls.
  | ThreadTerm = 0x8us
  /// The image can handle a 64-bit address space laid out at random.
  | HighEntropyVirtualAddressSpace = 0x20us
  /// The image can be relocated at load time.
  | DynamicBase = 0x40us
  /// Code integrity checks are enforced.
  | ForceIntegrity = 0x80us
  /// The image is compatible with data execution prevention.
  | NxCompatible = 0x100us
  /// The image is isolation aware, and is not to be isolated.
  | NoIsolation = 0x200us
  /// The image uses no structured exception handling.
  | NoSeh = 0x400us
  /// The image is not to be bound.
  | NoBind = 0x800us
  /// The image is to be run inside an AppContainer.
  | AppContainer = 0x1000us
  /// The image is a WDM driver.
  | WdmDriver = 0x2000us
  /// The image supports control flow guard.
  | ControlFlowGuard = 0x4000us
  /// The image is terminal server aware.
  | TerminalServerAware = 0x8000us
