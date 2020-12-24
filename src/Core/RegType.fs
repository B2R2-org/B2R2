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

/// A unit for RegType.
[<Measure>]
type rt

/// Types that a register can have. This essentially means how many bits are in
/// the register.
type RegType = int<rt>

/// This exception is raised when an invalid RegType is encountered.
exception InvalidRegTypeException

/// <summary>
///   A helper for <see cref="T:B2R2.RegType"/>.
/// </summary>
[<RequireQualifiedAccess>]
module RegType =
  /// <summary>
  ///   Convert <see cref="T:B2R2.RegType"/> to string.
  /// </summary>
  /// <param name="t">RegType.</param>
  /// <returns>
  ///   A string representation for RegType. For example, I32 means a 32-bit
  ///   integer type.
  /// </returns>
  let toString (t: RegType) =
    if t >= 0<rt> then "I" + t.ToString ()
    else "F" + t.ToString ()

#if DEBUG
  let checkIfValidRegType t =
    if t > 0<rt> then ()
    elif t < 0<rt> && t >= -512<rt> then ()
    else raise InvalidRegTypeException
#endif

  /// <summary>
  ///   Check if the given <see cref="T:B2R2.RegType"/> is a floating-point (FP)
  ///   type.
  /// </summary>
  /// <param name="t">RegType.</param>
  /// <returns>
  ///   A Boolean value that is true if the given RegType is a floating-point
  ///   type, false otherwise.
  /// </returns>
  let isFP (t: RegType) = t < 0<rt>

  /// <summary>
  ///   Convert a <see cref="T:B2R2.RegType"/> to an integer of bit width.
  /// </summary>
  /// <param name="t">RegType.</param>
  /// <returns>
  ///   A bit width in integer of the given RegType.
  /// </returns>
  let toBitWidth (t: RegType) =
#if DEBUG
    checkIfValidRegType t
#endif
    if t > 0<rt> then int t else int (-t)

  /// <summary>
  ///   Get a byte width from a RegType.
  /// </summary>
  /// <param name="t">RegType.</param>
  /// <returns>
  ///   A byte width in integer of the given RegType.
  /// </returns>
  let toByteWidth t =
    let t = toBitWidth t
    if t % 8 = 0 then t / 8
    else Utils.impossible ()

  /// <summary>
  ///   Get the corresponding integer RegType from the given bit width. When a
  ///   negative integer is given, it will return a floating point type.
  /// </summary>
  /// <param name="n">Bit width in integer.</param>
  /// <returns>
  ///   A <see cref="T:B2R2.RegType"/>.
  /// </returns>
  let inline fromBitWidth n =
    let t = LanguagePrimitives.Int32WithMeasure n
#if DEBUG
    checkIfValidRegType t
#endif
    t

  /// <summary>
  ///   Get the corresponding integer RegType from the given byte width.
  /// </summary>
  /// <param name="n">Byte width in integer.</param>
  /// <returns>
  ///   A <see cref="T:B2R2.RegType"/>.
  /// </returns>
  let fromByteWidth n = fromBitWidth (n * 8)

  /// Get the double width of RegType.

  /// <summary>
  ///   Get a double-sized RegType from a given RegType.
  /// </summary>
  /// <param name="t">RegType.</param>
  /// <returns>
  ///   A <see cref="T:B2R2.RegType"/>.
  /// </returns>
  let double (t: RegType) =  2 * t

  /// Get a bitmask of the given RegType size.

  /// <summary>
  ///   Get a bitmask (in integer) from the given RegType.
  /// </summary>
  /// <returns>
  ///   A bit mask in big integer.
  /// </returns>
  let getMask = function
    | 1<rt> -> 1I
    | 8<rt> -> 255I
    | 16<rt> -> 65535I
    | 32<rt> -> 4294967295I
    | 64<rt> -> 18446744073709551615I
    | 128<rt> -> BigInteger.mask128
    | 256<rt> -> BigInteger.mask256
    | 512<rt> -> BigInteger.mask512
    | t when t < 512<rt> -> (bigint.One <<< (int t)) - bigint.One
    | _ -> raise InvalidRegTypeException

  /// <summary>
  ///   Get a bitmask (in integer) from the given RegType.
  /// </summary>
  /// <returns>
  ///   A bit mask in uint64.
  /// </returns>
  let getUInt64Mask = function
    | 1<rt> -> 1UL
    | 8<rt> -> 255UL
    | 16<rt> -> 65535UL
    | 32<rt> -> 4294967295UL
    | 64<rt> -> 18446744073709551615UL
    | t when t < 64<rt> -> (1UL <<< (int t)) - 1UL
    | _ -> raise InvalidRegTypeException
