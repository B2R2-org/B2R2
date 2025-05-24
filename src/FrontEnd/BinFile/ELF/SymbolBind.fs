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

namespace B2R2.FrontEnd.BinFile.ELF

/// Represents a symbol's binding, which determines the linkage visibility and
/// behavior.
type SymbolBind =
  /// Local symbols are not visible outside. Local symbols of the same name may
  /// exist in multiple files without interfering with each other.
  | STB_LOCAL = 0uy
  /// Global symbols are visible to all object files being combined.
  | STB_GLOBAL = 1uy
  /// Weak symbols resemble global symbols, but their definitions have lower
  /// precedence.
  | STB_WEAK = 2uy
  /// The lower bound of OS-specific binding type.
  | STB_LOOS = 10uy
  /// The upper bound of OS-specific binding type.
  | STB_HIOS = 12uy
  /// The lower bound of processor-specific binding type.
  | STB_LOPROC = 13uy
  /// The upper bound of processor-specific binding type.
  | STB_HIPROC = 15uy

/// Provides functions to convert a SymbolBind to a string and vice versa.
[<RequireQualifiedAccess>]
module SymbolBind =
  open B2R2

  [<CompiledName "ToString">]
  /// Converts a SymbolBind to a string.
  let toString = function
    | SymbolBind.STB_LOCAL -> "LOCAL"
    | SymbolBind.STB_GLOBAL -> "GLOBAL"
    | SymbolBind.STB_WEAK -> "WEAK"
    | _ -> Terminator.futureFeature ()
