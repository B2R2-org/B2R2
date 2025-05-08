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

/// Raised when an invalid RegType is encountered.
exception InvalidRegTypeException

/// A unit of measure for register types.
/// <exclude/>
[<Measure>]
type rt

/// <summary>
/// Represents a register type in terms of its bit width. We use a unit of
/// measure to represent the bit width of a register. For example, a 32-bit
/// register is represented as <c>32&lt;rt&gt;</c>, and a 64-bit register is
/// represented as <c>64&lt;rt&gt;</c>.
/// </summary>
type RegType = int<rt>

/// <summary>
/// Provides several helper functions to deal with <see cref="T:B2R2.RegType"/>.
/// </summary>
[<RequireQualifiedAccess>]
module RegType =
#if DEBUG
  let checkIfValidRegType t =
    if t > 0<rt> then ()
    else raise InvalidRegTypeException
#endif

  /// <summary>
  /// Convert <see cref="T:B2R2.RegType"/> to string.
  /// </summary>
  /// <param name="t">RegType.</param>
  /// <returns>
  /// A string representation for RegType. For example, I32 means a 32-bit
  /// integer type.
  /// </returns>
  [<CompiledName "ToString">]
  let toString (t: RegType) =
#if DEBUG
    checkIfValidRegType t
#endif
    "I" + t.ToString ()

  /// <summary>
  /// Convert a <see cref="T:B2R2.RegType"/> to an integer of bit width.
  /// </summary>
  /// <param name="t">RegType.</param>
  /// <returns>
  /// A bit width in integer of the given RegType.
  /// </returns>
  [<CompiledName "ToBitWidth">]
  let toBitWidth (t: RegType) =
#if DEBUG
    checkIfValidRegType t
#endif
    int t

  /// <summary>
  /// Get a byte width from a RegType.
  /// </summary>
  /// <param name="t">RegType.</param>
  /// <returns>
  /// A byte width in integer of the given RegType.
  /// </returns>
  [<CompiledName "ToByteWidth">]
  let toByteWidth t =
    let t = toBitWidth t
    if t % 8 = 0 then t / 8
    else raise InvalidRegTypeException

  /// <summary>
  /// Get the corresponding integer RegType from the given bit width.
  /// </summary>
  /// <param name="n">Bit width in integer.</param>
  /// <returns>
  /// A <see cref="T:B2R2.RegType"/>.
  /// </returns>
  [<CompiledName "FromBitWidth">]
  let inline fromBitWidth n =
    let t = LanguagePrimitives.Int32WithMeasure n
#if DEBUG
    checkIfValidRegType t
#endif
    t

  /// <summary>
  /// Get the corresponding integer RegType from the given byte width.
  /// </summary>
  /// <param name="n">Byte width in integer.</param>
  /// <returns>
  /// A <see cref="T:B2R2.RegType"/>.
  /// </returns>
  [<CompiledName "FromByteWidth">]
  let fromByteWidth n = fromBitWidth (n * 8)

  /// <summary>
  /// Get a bitmask (in integer) from the given RegType.
  /// </summary>
  /// <returns>
  /// A bit mask in big integer.
  /// </returns>
  [<CompiledName "GetMask">]
  let getMask t =
    if t <= 64<rt> then System.UInt64.MaxValue >>> (64 - int t) |> bigint
    else (bigint.One <<< (int t)) - bigint.One
