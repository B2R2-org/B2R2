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
  /// Converts an address (<see cref='T:B2R2.Addr'/>) of a given word size (<see
  /// cref='T:B2R2.WordSize'/>) to a string.
  /// </summary>
  /// <param name="wordSize">The word size of the target architecture.</param>
  /// <param name="addr">The address to convert.</param>
  /// <returns>
  /// A zero-padded lowercase hex string without a "0x" prefix: at least 8
  /// digits for a 32-bit word size and at least 16 for any other. The width is
  /// the least an address is written out to and never the most, so an address
  /// too wide for the given word size is written out in full rather than cut
  /// down, a cut address being another address.
  /// </returns>
  [<CompiledName "ToString">]
  let toString wordSize (addr: Addr) =
    (* Written out by hand rather than through a format string: a dumper
       formats one address per instruction, and the general formatter was a
       twentieth of its time. *)
    let minWidth = if wordSize = WordSize.Bit32 then 8 else 16
    let digits =
      (67 - System.Numerics.BitOperations.LeadingZeroCount(addr ||| 1UL)) / 4
    let width = max minWidth digits
    let chars = Array.zeroCreate<char> width
    let mutable v = addr
    for i = width - 1 downto 0 do
      chars[i] <- "0123456789abcdef"[int (v &&& 0xFUL)]
      v <- v >>> 4
    System.String chars

  /// <summary>
  /// Converts an address (<see cref='T:B2R2.Addr'/>) to a function name, which
  /// starts with the <c>func_</c> prefix. This is used to provide consistent
  /// names for functions when symbols are not available. The address part is
  /// zero-padded to at least 8 hex digits, e.g., <c>func_00401000</c>.
  /// </summary>
  [<CompiledName "ToFuncName">]
  let toFuncName (addr: Addr) = FunctionPrefix + addr.ToString "x8"

  /// <summary>
  /// Converts a function name used in B2R2 to an address (<see
  /// cref='T:B2R2.Addr'/>). This function assumes that the given string follows
  /// our function naming convention.
  /// </summary>
  [<CompiledName "OfFuncName">]
  let ofFuncName (name: string) =
    assert (name.StartsWith FunctionPrefix)
    let addrStr = name.Substring FunctionPrefix.Length
    System.UInt64.Parse(addrStr, System.Globalization.NumberStyles.HexNumber)
