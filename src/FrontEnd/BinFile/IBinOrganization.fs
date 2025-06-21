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

/// Represents an interface for accessing the binary file organization, such as
/// sections and functions.
type IBinOrganization =
  /// <summary>
  /// Returns a binary file pointer that points to the beginning of the text
  /// section, e.g., ".text" section of ELF.
  /// </summary>
  abstract GetTextSectionPointer: unit -> BinFilePointer

  /// <summary>
  /// Returns a binary file pointer of the given section whose name is given as
  /// an argument. The resulting pointer will point to the beginning of the
  /// section. If the address is not in any section, then this function returns
  /// a null pointer.
  /// </summary>
  abstract GetSectionPointer: name: string -> BinFilePointer

  /// <summary>
  /// Checks if the given address is within the text or data-only section of the
  /// binary. This function is useful for checking jump tables, which are
  /// usually located in a text or a data-only section.
  /// </summary>
  abstract IsInTextOrDataOnlySection: addr: Addr -> bool

  /// <summary>
  /// Returns an array of local function addresses (excluding external
  /// functions) from a given BinFile. This function only considers addresses
  /// that are certain. We do not include the entry point address (e.g., _start)
  /// in the result, because it is not necessarily a function address in
  /// general.
  /// </summary>
  /// <returns>
  /// An array of function addresses.
  /// </returns>
  abstract GetFunctionAddresses: unit -> Addr[]
