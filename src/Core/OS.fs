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

/// Raised when unknown OS type is detected.
exception UnknownOSException

/// Represents the target operating system type that the binary is compiled for.
type OS =
  /// Windows.
  | Windows = 1
  /// Linux.
  | Linux = 2
  /// MacOSX.
  | MacOSX = 3
  /// Unknown
  | UnknownOS = 4

/// Provides functions to work with OS types.
[<RequireQualifiedAccess>]
module OS =
  open System.IO

  /// <summary>
  /// Checks if the given program name is runnable in the current environment by
  /// searching the PATH environment variable.
  /// </summary>
  /// <param name="progName">The program name or path to check.</param>
  /// <returns>
  /// <c>true</c> if the program exists at the given path or is found in PATH;
  /// otherwise <c>false</c>.
  /// </returns>
  [<CompiledName "IsRunnable">]
  let isRunnable progName =
    let testPath path =
      let fullPath = Path.Combine(path, progName)
      File.Exists fullPath || if fullPath.EndsWith ".exe" then false
                              else File.Exists(fullPath + ".exe")
    if File.Exists progName then
      true
    else
      let vars = System.Environment.GetEnvironmentVariable "PATH"
      if isNull vars then false
      else vars.Split Path.PathSeparator |> Array.exists testPath

  /// <summary>
  /// Gets an <see cref='T:B2R2.OS'/> value from a string. Accepts "windows" or
  /// "win", "linux", "macos"/"macosx"/"mac"/"osx", or "unknown"
  /// (case-insensitive). Raises <see cref='T:B2R2.UnknownOSException'/> if the
  /// string is not recognized.
  /// </summary>
  /// <param name="s">A string representing the OS type.</param>
  /// <returns>
  /// An <see cref='T:B2R2.OS'/> value corresponding to <paramref name="s"/>.
  /// </returns>
  [<CompiledName "OfString">]
  let ofString (s: string) =
    match s.ToLowerInvariant() with
    | "windows" | "win" -> OS.Windows
    | "linux" -> OS.Linux
    | "macos" | "macosx" | "mac" | "osx" -> OS.MacOSX
    | "unknown" -> OS.UnknownOS
    | _ -> raise UnknownOSException

  /// <summary>
  /// Gets the string representation of the given <see cref='T:B2R2.OS'/>
  /// value. Raises <see cref='T:B2R2.UnknownOSException'/> for invalid values.
  /// </summary>
  /// <param name="os">The OS value to convert.</param>
  /// <returns>
  /// "Windows", "Linux", "Mac", or "UnknownOS".
  /// </returns>
  [<CompiledName "ToString">]
  let toString os =
    match os with
    | OS.Windows -> "Windows"
    | OS.Linux -> "Linux"
    | OS.MacOSX -> "Mac"
    | OS.UnknownOS -> "UnknownOS"
    | _ -> raise UnknownOSException