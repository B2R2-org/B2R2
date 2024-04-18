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

/// Addresses are represented with a 64-bit integer in B2R2.
type Addr = uint64

[<RequireQualifiedAccess>]
module Addr =
  let [<Literal>] private FunctionPrefix = "func_"

  /// Convert an address of a given word size to a string.
  [<CompiledName "ToString">]
  let toString wordSize (addr: Addr) =
    if wordSize = WordSize.Bit32 then (uint32 addr).ToString ("x8")
    else addr.ToString ("x16")

  /// Convert an address to a function name used in B2R2.
  [<CompiledName "ToFuncName">]
  let toFuncName (addr: Addr) =
    FunctionPrefix + addr.ToString ("x")

  /// Convert a function name used in B2R2 to an address.
  [<CompiledName "OfFuncName">]
  let ofFuncName (name: string) =
    assert (name.StartsWith FunctionPrefix)
    let addrStr = name.Substring FunctionPrefix.Length
    System.UInt64.Parse (addrStr, System.Globalization.NumberStyles.HexNumber)
