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
open B2R2.FrontEnd.BinLifter

/// Symbol table of a binary file.
type IBinSymbolTable =
  inherit INameReadable

  /// Return a list of all the symbols from the binary.
  abstract GetSymbols: unit -> seq<Symbol>

  /// Return a list of all the static symbols from the binary. Static symbols
  /// can be removed when we strip the binary. Unlike dynamic symbols, static
  /// symbols are not required to run the binary, thus they can be safely
  /// removed before releasing it.
  abstract GetStaticSymbols: unit -> seq<Symbol>

  /// Returns a sequence of local function symbols (excluding external
  /// functions) from a given binary.
  abstract GetFunctionSymbols: unit -> seq<Symbol>

  /// Return a list of all the dynamic symbols from the binary. Dynamic symbols
  /// are the ones that are required to run the binary. The "excludeImported"
  /// argument indicates whether to exclude external symbols that are imported
  /// from other files. However, even if "excludeImported" is true, returned
  /// symbols may include a forwarding entry that redirects to another function
  /// in an external file (cf. SymbolKind.ForwardType). When "excludeImported"
  /// argument is not given, this function will simply return all possible
  /// dynamic symbols.
  abstract GetDynamicSymbols: ?excludeImported: bool -> seq<Symbol>

  /// Return a list of all symbols for relocatable entries in the binary.
  abstract GetRelocationSymbols: unit -> seq<Symbol>

  /// Add a symbol for the address. This function is useful when we can obtain
  /// extra symbol information from outside of B2R2.
  abstract AddSymbol: Addr -> Symbol -> unit