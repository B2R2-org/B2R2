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

/// Represents the platform that a Mach-O image is built to run on, as the
/// platform field of its LC_BUILD_VERSION names it. An image older than that
/// command names one of the same platforms by carrying the LC_VERSION_MIN_*
/// command that belongs to it.
type internal Platform =
  /// No platform, which is what an image carrying neither LC_BUILD_VERSION nor
  /// an LC_VERSION_MIN_* command names.
  | UNKNOWN = 0
  /// macOS.
  | MACOS = 1
  /// iOS.
  | IOS = 2
  /// tvOS.
  | TVOS = 3
  /// watchOS.
  | WATCHOS = 4
  /// bridgeOS, which runs on the T2 coprocessor.
  | BRIDGEOS = 5
  /// Mac Catalyst: an iOS image built to run on macOS.
  | MACCATALYST = 6
  /// The iOS simulator, which runs on the host rather than on a device.
  | IOSSIMULATOR = 7
  /// The tvOS simulator.
  | TVOSSIMULATOR = 8
  /// The watchOS simulator.
  | WATCHOSSIMULATOR = 9
  /// DriverKit, which is how a driver runs outside the kernel.
  | DRIVERKIT = 10
  /// visionOS.
  | VISIONOS = 11
  /// The visionOS simulator.
  | VISIONOSSIMULATOR = 12
  /// Firmware, which runs on no operating system at all.
  | FIRMWARE = 13
  /// sepOS, which runs on the Secure Enclave.
  | SEPOS = 14

/// <summary>
/// Provides functions to work with <see
/// cref='T:B2R2.FrontEnd.BinFile.Mach.Platform'/>.
/// </summary>
[<RequireQualifiedAccess>]
module internal Platform =
  /// Returns the platform that the given LC_VERSION_MIN_* command names, which
  /// is which of the four commands it is: that is all an image built before
  /// LC_BUILD_VERSION says. Any other command names no platform.
  let ofCmdType cmdType =
    match cmdType with
    | CmdType.LC_VERSION_MIN_MACOSX -> Platform.MACOS
    | CmdType.LC_VERSION_MIN_IPHONEOS -> Platform.IOS
    | CmdType.LC_VERSION_MIN_TVOS -> Platform.TVOS
    | CmdType.LC_VERSION_MIN_WATCHOS -> Platform.WATCHOS
    | _ -> Platform.UNKNOWN

  /// <summary>
  /// Returns the <see cref='T:B2R2.OS'/> that the given platform belongs to.
  /// What an OS tells apart is which ABI a binary follows, and every Apple
  /// platform follows the one macOS stands for here, so they share it. Only
  /// the two that run on the bare machine belong to no system at all; an image
  /// naming no platform is a Mach-O built for macOS before any command said
  /// so, and belongs to macOS like the rest.
  /// </summary>
  let toOS platform =
    match platform with
    | Platform.FIRMWARE | Platform.SEPOS -> OS.BareMetal
    | _ -> OS.MacOSX
