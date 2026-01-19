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

/// <summary>
/// Represents an address in binary code. Technically this is just an alias of
/// <c>uint64</c>.
/// </summary>
type Addr = uint64

/// <summary>
/// Provides a useful set of functions for handling <see cref='T:B2R2.Addr'/>
/// values.
/// </summary>
[<RequireQualifiedAccess>]
module Addr =
  let [<Literal>] private FunctionPrefix = "func_"

  /// <summary>
  /// Convert an address (<see cref='T:B2R2.Addr'/>) of a given word size (<see
  /// cref='T:B2R2.WordSize'/>) to a string.
  /// </summary>
  [<CompiledName "ToString">]
  let toString wordSize (addr: Addr) =
    if wordSize = WordSize.Bit32 then (uint32 addr).ToString "x8"
    else addr.ToString "x16"

  /// <summary>
  /// Convert an address (<see cref='T:B2R2.Addr'/>) to a function name, which
  /// starts with the <value>func_</value> prefix. This is used to provide
  /// consistent names for functions when symbols are not available.
  /// </summary>
  [<CompiledName "ToFuncName">]
  let toFuncName (addr: Addr) = FunctionPrefix + addr.ToString "x"

  /// <summary>
  /// Convert a function name used in B2R2 to an address (<see
  /// cref='T:B2R2.Addr'/>). This function assumes that the given string follows
  /// our function naming convention.
  /// </summary>
  [<CompiledName "OfFuncName">]
  let ofFuncName (name: string) =
    assert (name.StartsWith FunctionPrefix)
    let addrStr = name.Substring FunctionPrefix.Length
    System.UInt64.Parse(addrStr, System.Globalization.NumberStyles.HexNumber)
