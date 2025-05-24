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

/// Represents a symbol's visibility
type SymbolVisibility =
  /// Use the visibility specified by the symbol's binding type (SymbolBind).
  | STV_DEFAULT = 0x0uy
  /// This visibility attribute is currently reserved.
  | STV_INTERNAL = 0x01uy
  /// A symbol defined in the current component is hidden if its name is not
  /// visible to other components. Such a symbol is necessarily protected. This
  /// attribute is used to control the external interface of a component. An
  /// object named by such a symbol may still be referenced from another
  /// component if its address is passed outside.
  | STV_HIDDEN = 0x02uy
  /// A symbol defined in the current component is protected if it is visible in
  /// other components but cannot be preempted. Any reference to such a symbol
  /// from within the defining component must be resolved to the definition in
  /// that component, even if there is a definition in another component that
  /// would interpose by the default rules.
  | STV_PROTECTED = 0x03uy

/// Provides functions to convert a SymbolVisibility to a string and vice versa.
[<RequireQualifiedAccess>]
module SymbolVisibility =
  open B2R2

  [<CompiledName "ToString">]
  /// Converts a SymbolVisibility to a string.
  let toString = function
    | SymbolVisibility.STV_DEFAULT -> "DEFAULT"
    | SymbolVisibility.STV_INTERNAL -> "INTERNAL"
    | SymbolVisibility.STV_HIDDEN -> "HIDDEN"
    | SymbolVisibility.STV_PROTECTED -> "PROTECTED"
    | _ -> Terminator.futureFeature ()
