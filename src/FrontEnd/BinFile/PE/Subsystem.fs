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

/// Represents the subsystem an image is to be run under, which is what the
/// Subsystem field of its optional header names.
type internal Subsystem =
  /// An unknown subsystem.
  | Unknown = 0x0us
  /// Device drivers and native Windows processes.
  | Native = 0x1us
  /// The Windows graphical user interface subsystem.
  | WindowsGui = 0x2us
  /// The Windows character subsystem.
  | WindowsCui = 0x3us
  /// The OS/2 character subsystem.
  | OS2Cui = 0x5us
  /// The POSIX character subsystem.
  | PosixCui = 0x7us
  /// A native Win9x driver.
  | NativeWindows = 0x8us
  /// The Windows CE graphical user interface subsystem.
  | WindowsCEGui = 0x9us
  /// An Extensible Firmware Interface application.
  | EfiApplication = 0xaus
  /// An EFI driver with boot services.
  | EfiBootServiceDriver = 0xbus
  /// An EFI driver with run-time services.
  | EfiRuntimeDriver = 0xcus
  /// An EFI ROM image.
  | EfiRom = 0xdus
  /// Xbox.
  | Xbox = 0xeus
  /// A Windows boot application.
  | WindowsBootApplication = 0x10us
