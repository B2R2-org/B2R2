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

open System

/// Raised when two BitVectors have incompatible types (different bit lengths)
/// in a binary operation.
exception RegTypeMismatchException

/// Represents a helper module for BitVector.
[<AutoOpen>]
module private BitVector = begin

  let inline adaptSmall (len: RegType) (n: uint64) =
    (UInt64.MaxValue >>> (64 - int len)) &&& n

  let inline adaptBig (len: RegType) (n: bigint) = ((1I <<< int len) - 1I) &&& n

  /// Converts an already-rounded float into a signed integer bit pattern of the
  /// given (<= 64-bit) width. NaN or out-of-range inputs yield MIN_INT, as the
  /// CastKind documentation and x86 integer-indefinite semantics require.
  let ftoiToSmall (targetLen: RegType) (f: float) =
    let minInt = 1UL <<< int targetLen - 1
    let bound = float minInt
    if Double.IsNaN f || f < -bound || f >= bound then minInt
    else adaptSmall targetLen (uint64 (int64 f))

  let inline isSmallPositive (len: RegType) (n: uint64) =
    (n >>> (int len - 1)) &&& 1UL = 0UL

  /// Sign-extends a len-bit value held in a uint64 to a full signed int64.
  let inline sExtSmall (len: RegType) (n: uint64) =
    if len >= 64<rt> || isSmallPositive len n then int64 n
    else int64 (n ||| (UInt64.MaxValue <<< int len))

  let inline isBigPositive (len: RegType) (n: bigint) =
    (n >>> (int len - 1)) &&& 1I = 0I

  let inline neg (len: RegType) (n: bigint) = (1I <<< int len) - n

  let inline toFloat32 (n: uint64) =
    n |> int32 |> BitConverter.Int32BitsToSingle

  let inline toFloat64 (n: uint64) =
    n |> int64 |> BitConverter.Int64BitsToDouble

  let inline toBigFloat (n: bigint) =
    let sign = n >>> 79 <<< 63 |> uint64
    let exponent = n >>> 64 &&& 32767I
    let adjustedExp = exponent - 15360I |> uint64 <<< 52
    let significand = n &&& (bigint 0x7FFFFFFFFFFFFFFFUL) |> uint64 >>> 11
    let f64 = sign ||| adjustedExp ||| significand
    f64 |> int64 |> BitConverter.Int64BitsToDouble

  let inline encodeBigFloat (n: uint64) =
    let signOnly = n &&& (1UL <<< 63) >>> 48
    let exp = n &&& 0x7FF0000000000000UL >>> 52
    let expAndSign = exp + 0x3C00UL ||| signOnly |> bigint
    let significand = n &&& 0x000FFFFFFFFFFFFFUL
    let significand = significand ||| 0x0010000000000000UL <<< 11 |> bigint
    expAndSign <<< 64 ||| significand

end (* The end of BitVector module. *)

/// <summary>
/// Represents a bit vector, which is a sequence of bits. This type internally
/// uses two different representations to represent a bit vector depending on
/// its size. The numeric value of the bit vector is stored in little-endian
/// order. For those with less than or equal to 64 bits, it uses <c>uint64</c>.
/// For those with more than 64 bits, it uses <c>bigint</c>. This is to avoid
/// the overhead of using <c>bigint</c> for small numbers as most CPU operations
/// are in 64 bits or less. This is a value type, so creating a BitVector of 64
/// bits or less never allocates on the heap.
/// </summary>
[<Struct; CustomEquality; NoComparison>]
type BitVector =
  /// The value of the BitVector when its length is 64 bits or less.
  val private Num: uint64

  /// The value of the BitVector when its length is greater than 64 bits.
  val private BNum: bigint

  /// The bit length of the BitVector, which decides which field is in use.
  val private Len: RegType

  private new(num, bnum, len) = { Num = num; BNum = bnum; Len = len }

  /// Returns a BitVector from a uint64 value.
  new(u64: uint64, bitLen) =
#if DEBUG
    if bitLen <= 0<rt> then raise InvalidRegTypeException else ()
#endif
    if bitLen <= 64<rt> then
      { Num = u64 &&& (UInt64.MaxValue >>> (64 - int bitLen))
        BNum = 0I
        Len = bitLen }
    else
      { Num = 0UL; BNum = bigint u64; Len = bitLen }

  /// Returns a BitVector from an int64 value.
  new(i64: int64, bitLen) =
#if DEBUG
    if bitLen <= 0<rt> then raise InvalidRegTypeException else ()
#endif
    if bitLen <= 64<rt> then
      { Num = uint64 i64 &&& (UInt64.MaxValue >>> (64 - int bitLen))
        BNum = 0I
        Len = bitLen }
    elif i64 < 0L then
      { Num = 0UL; BNum = (1I <<< int bitLen) - (-i64 |> bigint); Len = bitLen }
    else
      { Num = 0UL; BNum = bigint i64; Len = bitLen }

  /// Returns a BitVector from a uint32 value.
  new(u32: uint32, bitLen) = BitVector(uint64 u32, bitLen)

  /// Returns a BitVector from an int32 value.
  new(i32: int32, bitLen) = BitVector(int64 i32, bitLen)

  /// Returns a BitVector from a bigint value. We assume that the given bitLen
  /// is big enough to hold the given bigint. Otherwise, the resulting BitVector
  /// may contain an unexpected value.
  new(bi: bigint, bitLen) =
#if DEBUG
    if bitLen <= 0<rt> then raise InvalidRegTypeException else ()
#endif
    if bitLen <= 64<rt> then
      { Num = uint64 bi &&& (UInt64.MaxValue >>> (64 - int bitLen))
        BNum = 0I
        Len = bitLen }
    elif bi.Sign < 0 then
      { Num = 0UL; BNum = (1I <<< int bitLen) + bi; Len = bitLen }
    else
      { Num = 0UL; BNum = bi; Len = bitLen }

  /// Returns a BitVector from a byte array (in little endian).
  new(arr: byte[]) =
    match arr.Length with
    | 1 ->
      { Num = uint64 arr[0]; BNum = 0I; Len = 8<rt> }
    | 2 ->
      let n = BitConverter.ToUInt16(arr, 0) |> uint64
      { Num = n; BNum = 0I; Len = 16<rt> }
    | 3 ->
      let n = BitConverter.ToUInt32(Array.append arr [| 0uy |], 0) |> uint64
      { Num = n; BNum = 0I; Len = 24<rt> }
    | 4 ->
      let n = BitConverter.ToUInt32(arr, 0) |> uint64
      { Num = n; BNum = 0I; Len = 32<rt> }
    | 5 ->
      let n = BitConverter.ToUInt64(Array.append arr [| 0uy; 0uy; 0uy |], 0)
      { Num = n; BNum = 0I; Len = 40<rt> }
    | 6 ->
      let n = BitConverter.ToUInt64(Array.append arr [| 0uy; 0uy |], 0)
      { Num = n; BNum = 0I; Len = 48<rt> }
    | 7 ->
      let n = BitConverter.ToUInt64(Array.append arr [| 0uy |], 0)
      { Num = n; BNum = 0I; Len = 56<rt> }
    | 8 ->
      { Num = BitConverter.ToUInt64(arr, 0); BNum = 0I; Len = 64<rt> }
    | sz ->
      if sz <= 0 then raise InvalidRegTypeException else ()
      let n = Array.append arr [| 0uy |] |> bigint
      { Num = 0UL; BNum = n; Len = sz * 8<rt> }

  /// Returns a BitVector representing a true (1-bit one) value.
  static member T = BitVector.OfSmall(1UL, 1<rt>)

  /// Returns a BitVector representing a false (1-bit zero) value.
  static member F = BitVector.OfSmall(0UL, 1<rt>)

  /// Returns a BitVector representing the maximum unsigned 8-bit value (255).
  static member MaxUInt8 = BitVector(0xFFUL, 8<rt>)

  /// Returns a BitVector representing the maximum unsigned 16-bit value.
  static member MaxUInt16 = BitVector(0xFFFFUL, 16<rt>)

  /// Returns a BitVector representing the maximum unsigned 32-bit value.
  static member MaxUInt32 = BitVector(0xFFFFFFFFUL, 32<rt>)

  /// Returns a BitVector representing the maximum unsigned 64-bit value.
  static member MaxUInt64 = BitVector(0xFFFFFFFFFFFFFFFFUL, 64<rt>)

  /// Returns the raw uint64 value regardless of the representation in use.
  member private this.RawSmall with get() =
    if this.Len <= 64<rt> then this.Num else uint64 this.BNum

  /// Returns the raw bigint value regardless of the representation in use.
  member private this.RawBig with get() =
    if this.Len <= 64<rt> then bigint this.Num else this.BNum

  /// Returns the bit length of the BitVector.
  member this.Length with get() = this.Len

  /// <summary>
  /// Returns <c>true</c> if the BitVector is zero; otherwise, <c>false</c>.
  /// </summary>
  member this.IsZero with get() =
    if this.Len <= 64<rt> then this.Num = 0UL else this.BNum = 0I

  /// <summary>
  /// Returns <c>true</c> if the BitVector is one; otherwise, <c>false</c>.
  /// </summary>
  member this.IsOne with get() =
    if this.Len <= 64<rt> then this.Num = 1UL else this.BNum = 1I

  /// <summary>
  /// Returns <c>true</c> if the BitVector is a 1-bit zero; otherwise,
  /// <c>false</c>.
  /// </summary>
  member this.IsFalse with get() = this.Len = 1<rt> && this.Num = 0UL

  /// <summary>
  /// Returns <c>true</c> if the BitVector is a 1-bit one; otherwise,
  /// <c>false</c>.
  /// </summary>
  member this.IsTrue with get() = this.Len = 1<rt> && this.Num = 1UL

  /// <summary>
  /// Returns <c>true</c> if the BitVector represents an unsigned max value;
  /// otherwise, <c>false</c>.
  /// </summary>
  member this.IsUnsignedMax with get() =
    if this.Len <= 64<rt> then
      this.Num = (UInt64.MaxValue >>> (64 - int this.Len))
    else
      this.BNum = (1I <<< int this.Len) - 1I

  /// <summary>
  /// Returns <c>true</c> if the BitVector represents a signed max value;
  /// otherwise, <c>false</c>.
  /// </summary>
  member this.IsSignedMax with get() =
    if this.Len <= 64<rt> then
      this.Num = (UInt64.MaxValue >>> (65 - int this.Len))
    else
      this.BNum = (1I <<< (int this.Len - 1)) - 1I

  /// <summary>
  /// Returns <c>true</c> if the BitVector represents a signed min value;
  /// otherwise, <c>false</c>.
  /// </summary>
  member this.IsSignedMin with get() =
    if this.Len <= 64<rt> then this.Num = (1UL <<< (int this.Len - 1))
    else this.BNum = (1I <<< (int this.Len - 1))

  /// <summary>
  /// Returns <c>true</c> if the BitVector is positive when interpreted as a
  /// signed integer; otherwise, <c>false</c>.
  /// </summary>
  member this.IsPositive with get() =
    if this.Len <= 64<rt> then isSmallPositive this.Len this.Num
    else isBigPositive this.Len this.BNum

  /// <summary>
  /// Returns <c>true</c> if the BitVector is negative when interpreted as a
  /// signed integer; otherwise, <c>false</c>.
  /// </summary>
  member this.IsNegative with get() = not this.IsPositive

  /// Builds a BitVector of 64 bits or less from its raw uint64 value.
  static member private OfSmall(n: uint64, len: RegType) =
#if DEBUG
    if len > 64<rt> then raise InvalidRegTypeException else ()
#endif
    BitVector(n, 0I, len)

  /// Builds a BitVector of more than 64 bits from its raw bigint value.
  static member private OfBig(n: bigint, len: RegType) =
#if DEBUG
    if len <= 64<rt> then raise InvalidRegTypeException else ()
#endif
    BitVector(0UL, n, len)

  /// Returns zero (0) of the given bit length.
  static member Zero t =
    if t <= 64<rt> then BitVector.OfSmall(0UL, t) else BitVector.OfBig(0I, t)

  /// Returns one (1) of the given bit length.
  static member One t =
    if t <= 64<rt> then BitVector.OfSmall(1UL, t) else BitVector.OfBig(1I, t)

  /// Returns a BitVector representing the maximum unsigned integer of the given
  /// RegType.
  static member UnsignedMax rt =
#if DEBUG
    if rt <= 0<rt> then raise InvalidRegTypeException else ()
#endif
    if rt <= 64<rt> then
      BitVector.OfSmall(UInt64.MaxValue >>> (64 - int rt), rt)
    else
      BitVector.OfBig((1I <<< int rt) - 1I, rt)

  /// Returns a BitVector representing the maximum signed integer of the given
  /// RegType.
  static member SignedMax rt =
#if DEBUG
    if rt <= 0<rt> then raise InvalidRegTypeException else ()
#endif
    if rt <= 64<rt> then
      BitVector.OfSmall(UInt64.MaxValue >>> (65 - int rt), rt)
    else
      BitVector.OfBig((1I <<< (int rt - 1)) - 1I, rt)

  /// Returns a BitVector representing the minimum signed integer of the given
  /// RegType.
  static member SignedMin rt =
#if DEBUG
    if rt <= 0<rt> then raise InvalidRegTypeException else ()
#endif
    if rt <= 64<rt> then
      BitVector.OfSmall(1UL <<< (int rt - 1), rt)
    else
      BitVector.OfBig(1I <<< (int rt - 1), rt)

  /// Adds two BitVectors.
  static member Add(v1: BitVector, v2: BitVector) =
    if v1.Len <> v2.Len then raise RegTypeMismatchException else ()
    if v1.Len <= 64<rt> then
      BitVector.OfSmall(v1.Num + v2.Num |> adaptSmall v1.Len, v1.Len)
    else
      BitVector.OfBig(v1.BNum + v2.BNum |> adaptBig v1.Len, v1.Len)

  /// Subtracts two BitVectors.
  static member Sub(v1: BitVector, v2: BitVector) =
    if v1.Len <> v2.Len then raise RegTypeMismatchException else ()
    if v1.Len <= 64<rt> then
      BitVector.OfSmall(v1.Num - v2.Num |> adaptSmall v1.Len, v1.Len)
    else
      BitVector.OfBig(v1.BNum - v2.BNum |> adaptBig v1.Len, v1.Len)

  /// Multiplies two BitVectors.
  static member Mul(v1: BitVector, v2: BitVector) =
    if v1.Len <> v2.Len then raise RegTypeMismatchException else ()
    if v1.Len <= 64<rt> then
      BitVector.OfSmall(v1.Num * v2.Num |> adaptSmall v1.Len, v1.Len)
    else
      BitVector.OfBig(v1.BNum * v2.BNum |> adaptBig v1.Len, v1.Len)

  /// Divides two BitVectors of 64 bits or less (signed division).
  static member private SDivSmall(v1: BitVector, v2: BitVector) =
    let len = v1.Len
    let isPos1 = isSmallPositive len v1.Num
    let isPos2 = isSmallPositive len v2.Num
    let n1 =
      int64 (if isPos1 then v1.Num else ((~~~v1.Num) + 1UL) |> adaptSmall len)
    let n2 =
      int64 (if isPos2 then v2.Num else ((~~~v2.Num) + 1UL) |> adaptSmall len)
    let result = if isPos1 = isPos2 then n1 / n2 else -(n1 / n2)
    BitVector.OfSmall(result |> uint64 |> adaptSmall len, len)

  /// Divides two BitVectors of more than 64 bits (signed division).
  static member private SDivBig(v1: BitVector, v2: BitVector) =
    let len = v1.Len
    let isPos1 = isBigPositive len v1.BNum
    let isPos2 = isBigPositive len v2.BNum
    let n1 = if isPos1 then v1.BNum else neg len v1.BNum
    let n2 = if isPos2 then v2.BNum else neg len v2.BNum
    let result = if isPos1 = isPos2 then n1 / n2 else neg len (n1 / n2)
    BitVector.OfBig(result |> adaptBig len, len)

  /// Divides two BitVectors (signed division).
  static member SDiv(v1: BitVector, v2: BitVector) =
    if v1.Len <> v2.Len then raise RegTypeMismatchException else ()
    if v1.Len <= 64<rt> then BitVector.SDivSmall(v1, v2)
    else BitVector.SDivBig(v1, v2)

  /// Divides two BitVectors (unsigned division).
  static member Div(v1: BitVector, v2: BitVector) =
    if v1.Len <> v2.Len then raise RegTypeMismatchException else ()
    if v1.Len <= 64<rt> then
      BitVector.OfSmall(v1.Num / v2.Num |> adaptSmall v1.Len, v1.Len)
    else
      BitVector.OfBig(v1.BNum / v2.BNum |> adaptBig v1.Len, v1.Len)

  /// Calculates the signed modulo of two BitVectors of 64 bits or less.
  static member private SModSmall(v1: BitVector, v2: BitVector) =
    let len = v1.Len
    let isPos1 = isSmallPositive len v1.Num
    let isPos2 = isSmallPositive len v2.Num
    let n1 =
      int64 (if isPos1 then v1.Num else ((~~~v1.Num) + 1UL) |> adaptSmall len)
    let n2 =
      int64 (if isPos2 then v2.Num else ((~~~v2.Num) + 1UL) |> adaptSmall len)
    let result = if isPos1 then n1 % n2 else -(n1 % n2)
    BitVector.OfSmall(result |> uint64 |> adaptSmall len, len)

  /// Calculates the signed modulo of two BitVectors of more than 64 bits.
  static member private SModBig(v1: BitVector, v2: BitVector) =
    let len = v1.Len
    let isPos1 = isBigPositive len v1.BNum
    let isPos2 = isBigPositive len v2.BNum
    let n1 = if isPos1 then v1.BNum else neg len v1.BNum
    let n2 = if isPos2 then v2.BNum else neg len v2.BNum
    let result = if isPos1 then n1 % n2 else neg len (n1 % n2)
    BitVector.OfBig(result |> adaptBig len, len)

  /// Calculates the signed modulo of two BitVectors.
  static member SModulo(v1: BitVector, v2: BitVector) =
    if v1.Len <> v2.Len then raise RegTypeMismatchException else ()
    if v1.Len <= 64<rt> then BitVector.SModSmall(v1, v2)
    else BitVector.SModBig(v1, v2)

  /// Calculates the unsigned modulo of a BitVector by another BitVector.
  static member Modulo(v1: BitVector, v2: BitVector) =
    if v1.Len <> v2.Len then raise RegTypeMismatchException else ()
    if v1.Len <= 64<rt> then
      BitVector.OfSmall(v1.Num % v2.Num |> adaptSmall v1.Len, v1.Len)
    else
      BitVector.OfBig(v1.BNum % v2.BNum |> adaptBig v1.Len, v1.Len)

  /// Calculates bitwise AND of two BitVectors.
  static member And(v1: BitVector, v2: BitVector) =
    if v1.Len <> v2.Len then raise RegTypeMismatchException else ()
    if v1.Len <= 64<rt> then
      BitVector.OfSmall(v1.Num &&& v2.Num |> adaptSmall v1.Len, v1.Len)
    else
      BitVector.OfBig(v1.BNum &&& v2.BNum |> adaptBig v1.Len, v1.Len)

  /// Calculates bitwise OR of two BitVectors.
  static member Or(v1: BitVector, v2: BitVector) =
    if v1.Len <> v2.Len then raise RegTypeMismatchException else ()
    if v1.Len <= 64<rt> then
      BitVector.OfSmall(v1.Num ||| v2.Num |> adaptSmall v1.Len, v1.Len)
    else
      BitVector.OfBig(v1.BNum ||| v2.BNum |> adaptBig v1.Len, v1.Len)

  /// Calculates bitwise XOR of two BitVectors.
  static member Xor(v1: BitVector, v2: BitVector) =
    if v1.Len <> v2.Len then raise RegTypeMismatchException else ()
    if v1.Len <= 64<rt> then
      BitVector.OfSmall(v1.Num ^^^ v2.Num |> adaptSmall v1.Len, v1.Len)
    else
      BitVector.OfBig(v1.BNum ^^^ v2.BNum |> adaptBig v1.Len, v1.Len)

  /// Calculates logical shift-left of v1 by v2.
  static member Shl(v1: BitVector, v2: BitVector) =
    if v1.Len <> v2.Len then raise RegTypeMismatchException else ()
    if v1.Len > 64<rt> then
      if v2.BNum >= bigint (int v1.Len) then
        BitVector.OfBig(0I, v1.Len)
      else
        BitVector.OfBig(adaptBig v1.Len (v1.BNum <<< int v2.BNum), v1.Len)
    elif v2.Num >= 64UL then
      BitVector.OfSmall(0UL, v1.Len)
    else
      BitVector.OfSmall(adaptSmall v1.Len (v1.Num <<< int v2.Num), v1.Len)

  /// Calculates logical shift-right of v1 by v2.
  static member Shr(v1: BitVector, v2: BitVector) =
    if v1.Len <> v2.Len then raise RegTypeMismatchException else ()
    (* In .NET, 1UL >>> 63 = 0, but 1UL >>> 64 = 1 *)
    if v1.Len > 64<rt> then
      if v2.BNum >= bigint (int v1.Len) then
        BitVector.OfBig(0I, v1.Len)
      else
        BitVector.OfBig(v1.BNum >>> int v2.BNum, v1.Len)
    elif v2.Num >= 64UL then
      BitVector.OfSmall(0UL, v1.Len)
    else
      BitVector.OfSmall(v1.Num >>> int v2.Num, v1.Len)

  /// Calculates arithmetic shift-right of a BitVector of 64 bits or less.
  static member private SarSmall(v1: BitVector, shift: uint64) =
    let len = v1.Len
    if shift >= 64UL then
      if isSmallPositive len v1.Num then BitVector.OfSmall(0UL, len)
      else BitVector.OfSmall(UInt64.MaxValue |> adaptSmall len, len)
    elif len = 1<rt> then
      v1
    elif isSmallPositive len v1.Num then
      BitVector.OfSmall(v1.Num >>> int shift, len)
    else
      let ones = UInt64.MaxValue >>> (64 - int len)
      let rest =
        if int len <= int shift then 0UL
        else UInt64.MaxValue >>> (64 - (int len - int shift))
      BitVector.OfSmall((v1.Num >>> int shift) ||| (ones - rest), len)

  /// Calculates arithmetic shift-right of a BitVector of more than 64 bits.
  static member private SarBig(v1: BitVector, shift: bigint) =
    let len = v1.Len
    let ones = (1I <<< int len) - 1I
    if isBigPositive len v1.BNum then
      if shift >= bigint (int len) then BitVector.OfBig(0I, len)
      else BitVector.OfBig(v1.BNum >>> int shift, len)
    elif shift >= bigint (int len) then
      BitVector.OfBig(ones, len)
    else
      let pad = ones - ((1I <<< (int len - int shift)) - 1I)
      BitVector.OfBig((v1.BNum >>> int shift) ||| pad, len)

  /// Calculates arithmetic shift-right of v1 by v2.
  static member Sar(v1: BitVector, v2: BitVector) =
    if v1.Len <> v2.Len then raise RegTypeMismatchException else ()
    if v1.Len <= 64<rt> then BitVector.SarSmall(v1, v2.Num)
    else BitVector.SarBig(v1, v2.BNum)

  /// Calculates bitwise NOT of a BitVector.
  static member Not(v1: BitVector) =
    if v1.Len <= 64<rt> then
      BitVector.OfSmall((~~~v1.Num) |> adaptSmall v1.Len, v1.Len)
    else
      BitVector.OfBig((1I <<< int v1.Len) - 1I - v1.BNum, v1.Len)

  /// Calculates the negation of a BitVector (as a signed integer).
  static member Neg(v1: BitVector) =
    if v1.Len <= 64<rt> then
      BitVector.OfSmall(((~~~v1.Num) + 1UL) |> adaptSmall v1.Len, v1.Len)
    else
      BitVector.OfBig(adaptBig v1.Len ((1I <<< int v1.Len) - v1.BNum), v1.Len)

  /// Casts a BitVector to a target length.
  static member Cast(v1: BitVector, targetLen) =
    if targetLen <= 64<rt> then
      BitVector.OfSmall(adaptSmall targetLen v1.RawSmall, targetLen)
    else
      BitVector.OfBig(adaptBig targetLen v1.RawBig, targetLen)

  /// <summary>
  /// Extracts a sub-BitVector of the given size from a BitVector starting at
  /// the specified bit position.
  /// </summary>
  /// <param name="src">The source BitVector.</param>
  /// <param name="rt">The size (in bits) of the extracted sub-BitVector.
  /// </param>
  /// <param name="pos">The starting bit position (zero-based, from LSB).
  /// </param>
  static member Extract(src: BitVector, rt, pos) =
    if src.Len < rt then
      raise InvalidRegTypeException
    elif src.Len = rt then
      src
    elif src.Len <= 64<rt> then
      BitVector.OfSmall(adaptSmall rt (src.Num >>> pos), rt)
    elif rt <= 64<rt> then
      BitVector.OfSmall(src.BNum >>> pos |> adaptBig rt |> uint64, rt)
    else
      BitVector.OfBig(adaptBig rt (src.BNum >>> pos), rt)

  /// Concatenates two BitVectors.
  static member Concat(v1: BitVector, v2: BitVector) =
    let targetLen = v1.Len + v2.Len
    if targetLen <= 64<rt> then
      BitVector.OfSmall((v1.Num <<< int v2.Len) + v2.Num, targetLen)
    else
      BitVector.OfBig((v1.RawBig <<< int v2.Len) + v2.RawBig, targetLen)

  /// Calculates signed extension of a BitVector.
  static member SExt(src: BitVector, targetLen) =
    if targetLen < src.Len then
      raise InvalidRegTypeException
    elif targetLen = src.Len then
      src
    elif targetLen <= 64<rt> then
      if src.IsPositive then
        BitVector.OfSmall(src.Num, targetLen)
      else
        let mask =
          (UInt64.MaxValue >>> (64 - int targetLen))
          - (UInt64.MaxValue >>> (64 - int src.Len))
        BitVector.OfSmall(src.Num + mask, targetLen)
    else
      let n = adaptBig targetLen src.RawBig
      if src.IsPositive then
        BitVector.OfBig(n, targetLen)
      else
        let mask = (1I <<< int targetLen) - (1I <<< int src.Len)
        BitVector.OfBig(n + mask, targetLen)

  /// Calculates zero extension of a BitVector.
  static member ZExt(src: BitVector, targetLen) =
    if targetLen < src.Len then
      raise InvalidRegTypeException
    elif targetLen = src.Len then
      src
    elif targetLen <= 64<rt> then
      BitVector.OfSmall(adaptSmall targetLen src.Num, targetLen)
    else
      BitVector.OfBig(adaptBig targetLen src.RawBig, targetLen)

  /// Compares two BitVectors for equality.
  static member Eq(v1: BitVector, v2: BitVector) =
    if v1.Equals v2 then BitVector.T else BitVector.F

  /// Compares two BitVectors for inequality.
  static member Neq(v1: BitVector, v2: BitVector) =
    if v1.Equals v2 then BitVector.F else BitVector.T

  /// Checks if v1 is greater than v2.
  static member Gt(v1: BitVector, v2: BitVector) =
    if v1.Len <> v2.Len then raise RegTypeMismatchException else ()
    if v1.Len <= 64<rt> then
      if v1.Num > v2.Num then BitVector.T else BitVector.F
    else
      if v1.BNum > v2.BNum then BitVector.T else BitVector.F

  /// Checks if v1 is greater than or equal to v2.
  static member Ge(v1: BitVector, v2: BitVector) =
    if v1.Len <> v2.Len then raise RegTypeMismatchException else ()
    if v1.Len <= 64<rt> then
      if v1.Num >= v2.Num then BitVector.T else BitVector.F
    else
      if v1.BNum >= v2.BNum then BitVector.T else BitVector.F

  /// Checks if v1 is greater than v2 (considering them as signed integers).
  static member SGt(v1: BitVector, v2: BitVector) =
    if v1.Len <> v2.Len then raise RegTypeMismatchException else ()
    let isPos1 = v1.IsPositive
    let isPos2 = v2.IsPositive
    if isPos1 <> isPos2 then
      if isPos1 then BitVector.T else BitVector.F
    elif v1.Len <= 64<rt> then
      if v1.Num > v2.Num then BitVector.T else BitVector.F
    else
      if v1.BNum > v2.BNum then BitVector.T else BitVector.F

  /// Checks if v1 is greater than or equal to v2 (considering them as signed
  /// integers).
  static member SGe(v1: BitVector, v2: BitVector) =
    if v1.Len <> v2.Len then raise RegTypeMismatchException else ()
    let isPos1 = v1.IsPositive
    let isPos2 = v2.IsPositive
    if isPos1 <> isPos2 then
      if isPos1 then BitVector.T else BitVector.F
    elif v1.Len <= 64<rt> then
      if v1.Num >= v2.Num then BitVector.T else BitVector.F
    else
      if v1.BNum >= v2.BNum then BitVector.T else BitVector.F

  /// Checks if v1 is less than v2.
  static member Lt(v1: BitVector, v2: BitVector) =
    if v1.Len <> v2.Len then raise RegTypeMismatchException else ()
    if v1.Len <= 64<rt> then
      if v1.Num < v2.Num then BitVector.T else BitVector.F
    else
      if v1.BNum < v2.BNum then BitVector.T else BitVector.F

  /// Checks if v1 is less than or equal to v2.
  static member Le(v1: BitVector, v2: BitVector) =
    if v1.Len <> v2.Len then raise RegTypeMismatchException else ()
    if v1.Len <= 64<rt> then
      if v1.Num <= v2.Num then BitVector.T else BitVector.F
    else
      if v1.BNum <= v2.BNum then BitVector.T else BitVector.F

  /// Checks if v1 is less than v2 (considering them as signed integers).
  static member SLt(v1: BitVector, v2: BitVector) =
    if v1.Len <> v2.Len then raise RegTypeMismatchException else ()
    let isPos1 = v1.IsPositive
    let isPos2 = v2.IsPositive
    if isPos1 <> isPos2 then
      if isPos1 then BitVector.F else BitVector.T
    elif v1.Len <= 64<rt> then
      if v1.Num < v2.Num then BitVector.T else BitVector.F
    else
      if v1.BNum < v2.BNum then BitVector.T else BitVector.F

  /// Checks if v1 is less than or equal to v2 (considering them as signed
  /// integers).
  static member SLe(v1: BitVector, v2: BitVector) =
    if v1.Len <> v2.Len then raise RegTypeMismatchException else ()
    let isPos1 = v1.IsPositive
    let isPos2 = v2.IsPositive
    if isPos1 <> isPos2 then
      if isPos1 then BitVector.F else BitVector.T
    elif v1.Len <= 64<rt> then
      if v1.Num <= v2.Num then BitVector.T else BitVector.F
    else
      if v1.BNum <= v2.BNum then BitVector.T else BitVector.F

  /// Calculates the absolute value of a BitVector (as a signed integer).
  static member Abs(v1: BitVector) =
    if v1.IsPositive then v1 else BitVector.Neg v1

  /// Builds a 32-bit BitVector holding the bit pattern of the given float32.
  static member private OfFloat32(f: float32) =
    BitVector.OfSmall(BitConverter.SingleToUInt32Bits f |> uint64, 32<rt>)

  /// Builds a 64-bit BitVector holding the bit pattern of the given float.
  static member private OfFloat64(f: float) =
    BitVector.OfSmall(BitConverter.DoubleToInt64Bits f |> uint64, 64<rt>)

  /// Builds an 80-bit BitVector from an arithmetic result, where an exact zero
  /// is kept as a zero rather than being encoded as an extended-precision one.
  static member private OfFloat80(f: float) =
    let u64 = BitConverter.DoubleToInt64Bits f |> uint64
    if u64 = 0UL then BitVector.Zero 80<rt>
    else BitVector.OfBig(encodeBigFloat u64, 80<rt>)

  /// Builds an 80-bit BitVector from a converted value, which is always encoded
  /// in the extended-precision format.
  static member private OfConvertedFloat80(f: float) =
    let u64 = BitConverter.DoubleToInt64Bits f |> uint64
    BitVector.OfBig(encodeBigFloat u64, 80<rt>)

  /// Builds an 80-bit BitVector holding the raw double bit pattern, which is
  /// what the transcendental functions have always stored.
  static member private OfRawFloat80(f: float) =
    let u64 = BitConverter.DoubleToInt64Bits f |> uint64
    BitVector.OfBig(bigint u64, 80<rt>)

  /// Adds two BitVectors as floating point numbers.
  static member FAdd(v1: BitVector, v2: BitVector) =
    if v1.Len <> v2.Len then raise RegTypeMismatchException else ()
    match v1.Len with
    | 32<rt> -> BitVector.OfFloat32(toFloat32 v1.Num + toFloat32 v2.Num)
    | 64<rt> -> BitVector.OfFloat64(toFloat64 v1.Num + toFloat64 v2.Num)
    | 80<rt> -> BitVector.OfFloat80(toBigFloat v1.BNum + toBigFloat v2.BNum)
    | _ -> raise InvalidRegTypeException

  /// Subtracts two BitVectors as floating point numbers.
  static member FSub(v1: BitVector, v2: BitVector) =
    if v1.Len <> v2.Len then raise RegTypeMismatchException else ()
    match v1.Len with
    | 32<rt> -> BitVector.OfFloat32(toFloat32 v1.Num - toFloat32 v2.Num)
    | 64<rt> -> BitVector.OfFloat64(toFloat64 v1.Num - toFloat64 v2.Num)
    | 80<rt> -> BitVector.OfFloat80(toBigFloat v1.BNum - toBigFloat v2.BNum)
    | _ -> raise InvalidRegTypeException

  /// Multiplies two BitVectors as floating point numbers.
  static member FMul(v1: BitVector, v2: BitVector) =
    if v1.Len <> v2.Len then raise RegTypeMismatchException else ()
    match v1.Len with
    | 32<rt> -> BitVector.OfFloat32(toFloat32 v1.Num * toFloat32 v2.Num)
    | 64<rt> -> BitVector.OfFloat64(toFloat64 v1.Num * toFloat64 v2.Num)
    | 80<rt> -> BitVector.OfFloat80(toBigFloat v1.BNum * toBigFloat v2.BNum)
    | _ -> raise InvalidRegTypeException

  /// Divides two BitVectors as floating point numbers.
  static member FDiv(v1: BitVector, v2: BitVector) =
    if v1.Len <> v2.Len then raise RegTypeMismatchException else ()
    match v1.Len with
    | 32<rt> -> BitVector.OfFloat32(toFloat32 v1.Num / toFloat32 v2.Num)
    | 64<rt> -> BitVector.OfFloat64(toFloat64 v1.Num / toFloat64 v2.Num)
    | 80<rt> -> BitVector.OfFloat80(toBigFloat v1.BNum / toBigFloat v2.BNum)
    | _ -> raise InvalidRegTypeException

  /// Calculates the logarithm of v2 to the base v1 as floating point numbers.
  static member FLog(v1: BitVector, v2: BitVector) =
    if v1.Len <> v2.Len then raise RegTypeMismatchException else ()
    match v1.Len with
    | 32<rt> ->
      BitVector.OfFloat32(MathF.Log(toFloat32 v2.Num, toFloat32 v1.Num))
    | 64<rt> ->
      BitVector.OfFloat64(Math.Log(toFloat64 v2.Num, toFloat64 v1.Num))
    | 80<rt> ->
      BitVector.OfFloat80(Math.Log(toBigFloat v2.BNum, toBigFloat v1.BNum))
    | _ ->
      raise InvalidRegTypeException

  /// Calculates the power of v1 raised to v2 as floating point numbers.
  static member FPow(v1: BitVector, v2: BitVector) =
    if v1.Len <> v2.Len then raise RegTypeMismatchException else ()
    match v1.Len with
    | 32<rt> ->
      BitVector.OfFloat32(MathF.Pow(toFloat32 v1.Num, toFloat32 v2.Num))
    | 64<rt> ->
      BitVector.OfFloat64(Math.Pow(toFloat64 v1.Num, toFloat64 v2.Num))
    | 80<rt> ->
      BitVector.OfFloat80(Math.Pow(toBigFloat v1.BNum, toBigFloat v2.BNum))
    | _ ->
      raise InvalidRegTypeException

  /// Converts a BitVector to a floating point number of the specified type.
  static member FCast(v1: BitVector, rt) =
    match v1.Len, rt with
    | 32<rt>, 32<rt> -> v1
    | 32<rt>, 64<rt> -> BitVector.OfFloat64(toFloat32 v1.Num |> float)
    | 32<rt>, 80<rt> -> BitVector.OfConvertedFloat80(toFloat32 v1.Num |> float)
    | 64<rt>, 32<rt> -> BitVector.OfFloat32(toFloat64 v1.Num |> float32)
    | 64<rt>, 64<rt> -> v1
    | 64<rt>, 80<rt> -> BitVector.OfConvertedFloat80(toFloat64 v1.Num)
    | 80<rt>, 32<rt> -> BitVector.OfFloat32(toBigFloat v1.BNum |> float32)
    | 80<rt>, 64<rt> -> BitVector.OfFloat64(toBigFloat v1.BNum)
    | 80<rt>, 80<rt> -> v1
    | _ -> raise InvalidRegTypeException

  /// Converts an integer of 64 bits or less into a floating point number.
  static member private ItofSmall(v1: BitVector, rt, isSigned) =
    match rt with
    | 32<rt> ->
      if isSigned then BitVector.OfFloat32(sExtSmall v1.Len v1.Num |> float32)
      else BitVector.OfFloat32(float32 v1.Num)
    | 64<rt> ->
      if isSigned then BitVector.OfFloat64(sExtSmall v1.Len v1.Num |> float)
      else BitVector.OfFloat64(float v1.Num)
    | 80<rt> ->
      if isSigned then
        BitVector.OfConvertedFloat80(sExtSmall v1.Len v1.Num |> float)
      else
        BitVector.OfConvertedFloat80(float v1.Num)
    | _ ->
      raise InvalidRegTypeException

  /// Converts an integer of more than 64 bits into a floating point number.
  static member private ItofBig(v1: BitVector, rt, isSigned) =
    let n = v1.BNum
    let v =
      if isSigned && not (isBigPositive v1.Len n) then n - (1I <<< int v1.Len)
      else n
    match rt with
    | 32<rt> -> BitVector.OfFloat32(float32 v)
    | 64<rt> -> BitVector.OfFloat64(float v)
    | 80<rt> -> BitVector.OfConvertedFloat80(float v)
    | _ -> raise InvalidRegTypeException

  /// Converts a BitVector representing an integer to another BitVector
  /// representing a floating point number of the specified type.
  static member Itof(v1: BitVector, rt, isSigned) =
    if v1.Len <= 64<rt> then BitVector.ItofSmall(v1, rt, isSigned)
    else BitVector.ItofBig(v1, rt, isSigned)

  /// Reads the floating point value that the given BitVector encodes.
  static member private ToFloatValue(v: BitVector) =
    match v.Len with
    | 32<rt> -> toFloat32 v.Num |> float
    | 64<rt> -> toFloat64 v.Num
    | 80<rt> -> toBigFloat v.BNum
    | _ -> raise InvalidRegTypeException

  /// Builds a BitVector of the given length from an already-rounded float.
  static member private OfIntegralFloat(f: float, rt) =
    if rt <= 64<rt> then BitVector.OfSmall(ftoiToSmall rt f, rt)
    else BitVector.OfBig(adaptBig rt (bigint f), rt)

  /// Converts a BitVector representing a floating point number to another
  /// BitVector representing an integer of the specified type with truncation.
  static member FtoiTrunc(v1: BitVector, rt) =
    BitVector.OfIntegralFloat(truncate (BitVector.ToFloatValue v1), rt)

  /// Converts a BitVector representing a floating point number to another
  /// BitVector representing an integer of the specified type with rounding.
  static member FtoiRound(v1: BitVector, rt) =
    BitVector.OfIntegralFloat(round (BitVector.ToFloatValue v1), rt)

  /// Converts a BitVector representing a floating point number to another
  /// BitVector representing an integer of the specified type with flooring.
  static member FtoiFloor(v1: BitVector, rt) =
    BitVector.OfIntegralFloat(floor (BitVector.ToFloatValue v1), rt)

  /// Converts a BitVector representing a floating point number to another
  /// BitVector representing an integer of the specified type with ceiling.
  static member FtoiCeil(v1: BitVector, rt) =
    BitVector.OfIntegralFloat(ceil (BitVector.ToFloatValue v1), rt)

  /// Calculates the square root of a BitVector as a floating point number.
  static member FSqrt(v1: BitVector) =
    match v1.Len with
    | 32<rt> -> BitVector.OfFloat32(sqrt (toFloat32 v1.Num))
    | 64<rt> -> BitVector.OfFloat64(sqrt (toFloat64 v1.Num))
    | 80<rt> -> BitVector.OfRawFloat80(sqrt (toBigFloat v1.BNum))
    | _ -> raise InvalidRegTypeException

  /// Calculates the tangent of a BitVector as a floating point number.
  static member FTan(v1: BitVector) =
    match v1.Len with
    | 32<rt> -> BitVector.OfFloat32(tan (toFloat32 v1.Num))
    | 64<rt> -> BitVector.OfFloat64(tan (toFloat64 v1.Num))
    | 80<rt> -> BitVector.OfRawFloat80(tan (toBigFloat v1.BNum))
    | _ -> raise InvalidRegTypeException

  /// Calculates the sine of a BitVector as a floating point number.
  static member FSin(v1: BitVector) =
    match v1.Len with
    | 32<rt> -> BitVector.OfFloat32(sin (toFloat32 v1.Num))
    | 64<rt> -> BitVector.OfFloat64(sin (toFloat64 v1.Num))
    | 80<rt> -> BitVector.OfRawFloat80(sin (toBigFloat v1.BNum))
    | _ -> raise InvalidRegTypeException

  /// Calculates the cosine of a BitVector as a floating point number.
  static member FCos(v1: BitVector) =
    match v1.Len with
    | 32<rt> -> BitVector.OfFloat32(cos (toFloat32 v1.Num))
    | 64<rt> -> BitVector.OfFloat64(cos (toFloat64 v1.Num))
    | 80<rt> -> BitVector.OfRawFloat80(cos (toBigFloat v1.BNum))
    | _ -> raise InvalidRegTypeException

  /// Calculates the arctangent of a BitVector as a floating point number.
  static member FAtan(v1: BitVector) =
    match v1.Len with
    | 32<rt> -> BitVector.OfFloat32(atan (toFloat32 v1.Num))
    | 64<rt> -> BitVector.OfFloat64(atan (toFloat64 v1.Num))
    | 80<rt> -> BitVector.OfRawFloat80(atan (toBigFloat v1.BNum))
    | _ -> raise InvalidRegTypeException

  /// Calculates the arc sine of a BitVector as a floating point number.
  static member FAsin(v1: BitVector) =
    match v1.Len with
    | 32<rt> -> BitVector.OfFloat32(asin (toFloat32 v1.Num))
    | 64<rt> -> BitVector.OfFloat64(asin (toFloat64 v1.Num))
    | 80<rt> -> BitVector.OfRawFloat80(asin (toBigFloat v1.BNum))
    | _ -> raise InvalidRegTypeException

  /// Calculates the arc cosine of a BitVector as a floating point number.
  static member FAcos(v1: BitVector) =
    match v1.Len with
    | 32<rt> -> BitVector.OfFloat32(acos (toFloat32 v1.Num))
    | 64<rt> -> BitVector.OfFloat64(acos (toFloat64 v1.Num))
    | 80<rt> -> BitVector.OfRawFloat80(acos (toBigFloat v1.BNum))
    | _ -> raise InvalidRegTypeException

  /// Calculates the hyperbolic sine of a BitVector as a float.
  static member FSinh(v1: BitVector) =
    match v1.Len with
    | 32<rt> -> BitVector.OfFloat32(sinh (toFloat32 v1.Num))
    | 64<rt> -> BitVector.OfFloat64(sinh (toFloat64 v1.Num))
    | 80<rt> -> BitVector.OfRawFloat80(sinh (toBigFloat v1.BNum))
    | _ -> raise InvalidRegTypeException

  /// Calculates the hyperbolic cosine of a BitVector as a float.
  static member FCosh(v1: BitVector) =
    match v1.Len with
    | 32<rt> -> BitVector.OfFloat32(cosh (toFloat32 v1.Num))
    | 64<rt> -> BitVector.OfFloat64(cosh (toFloat64 v1.Num))
    | 80<rt> -> BitVector.OfRawFloat80(cosh (toBigFloat v1.BNum))
    | _ -> raise InvalidRegTypeException

  /// Calculates the hyperbolic tangent of a BitVector as a float.
  static member FTanh(v1: BitVector) =
    match v1.Len with
    | 32<rt> -> BitVector.OfFloat32(tanh (toFloat32 v1.Num))
    | 64<rt> -> BitVector.OfFloat64(tanh (toFloat64 v1.Num))
    | 80<rt> -> BitVector.OfRawFloat80(tanh (toBigFloat v1.BNum))
    | _ -> raise InvalidRegTypeException

  /// Calculates the inverse hyperbolic tangent of a BitVector as a float.
  static member FAtanh(v1: BitVector) =
    match v1.Len with
    | 32<rt> -> BitVector.OfFloat32(MathF.Atanh(toFloat32 v1.Num))
    | 64<rt> -> BitVector.OfFloat64(Math.Atanh(toFloat64 v1.Num))
    | 80<rt> -> BitVector.OfRawFloat80(Math.Atanh(toBigFloat v1.BNum))
    | _ -> raise InvalidRegTypeException

  /// Reads the floating point values that the two BitVectors encode.
  static member private ToFloatPair(v1: BitVector, v2: BitVector) =
    if v1.Len <> v2.Len then raise RegTypeMismatchException else ()
    struct (BitVector.ToFloatValue v1, BitVector.ToFloatValue v2)

  /// Compares two BitVectors as floating point numbers for greater than.
  static member FGt(v1: BitVector, v2: BitVector) =
    let struct (f1, f2) = BitVector.ToFloatPair(v1, v2)
    if f1 > f2 then BitVector.T else BitVector.F

  /// Compares two BitVectors as floating point numbers for greater than or
  /// equal.
  static member FGe(v1: BitVector, v2: BitVector) =
    let struct (f1, f2) = BitVector.ToFloatPair(v1, v2)
    if f1 >= f2 then BitVector.T else BitVector.F

  /// Compares two BitVectors as floating point numbers for less than.
  static member FLt(v1: BitVector, v2: BitVector) =
    let struct (f1, f2) = BitVector.ToFloatPair(v1, v2)
    if f1 < f2 then BitVector.T else BitVector.F

  /// Compares two BitVectors as floating point numbers for less than or equal.
  static member FLe(v1: BitVector, v2: BitVector) =
    let struct (f1, f2) = BitVector.ToFloatPair(v1, v2)
    if f1 <= f2 then BitVector.T else BitVector.F

  /// Compares two BitVectors as floating point numbers for equality.
  static member FEq(v1: BitVector, v2: BitVector) =
    let struct (f1, f2) = BitVector.ToFloatPair(v1, v2)
    if f1 = f2 then BitVector.T else BitVector.F

  /// Adds a BitVector and a uint64 value.
  static member (+) (v1: BitVector, v2: uint64) =
    if v1.Len <= 64<rt> then
      BitVector.OfSmall(v1.Num + v2 |> adaptSmall v1.Len, v1.Len)
    else
      BitVector.OfBig(v1.BNum + bigint v2, v1.Len)

  /// Subtracts a uint64 value from a BitVector.
  static member (-) (v1: BitVector, v2: uint64) =
    if v1.Len <= 64<rt> then
      BitVector.OfSmall(v1.Num - v2 |> adaptSmall v1.Len, v1.Len)
    else
      BitVector.OfBig(v1.BNum - bigint v2, v1.Len)

  /// Multiplies a BitVector by a uint64 value.
  static member (*) (v1: BitVector, v2: uint64) =
    if v1.Len <= 64<rt> then
      BitVector.OfSmall(v1.Num * v2 |> adaptSmall v1.Len, v1.Len)
    else
      BitVector.OfBig(v1.BNum * bigint v2, v1.Len)

  /// Divides a BitVector by a uint64 value (unsigned division).
  static member (/) (v1: BitVector, v2: uint64) =
    if v1.Len <= 64<rt> then
      BitVector.OfSmall(v1.Num / v2 |> adaptSmall v1.Len, v1.Len)
    else
      BitVector.OfBig(v1.BNum / bigint v2, v1.Len)

  /// Calculates the modulo of a BitVector by a uint64 value (unsigned).
  static member (%) (v1: BitVector, v2: uint64) =
    if v1.Len <= 64<rt> then
      BitVector.OfSmall(v1.Num % v2 |> adaptSmall v1.Len, v1.Len)
    else
      BitVector.OfBig(v1.BNum % bigint v2, v1.Len)

  /// Calculates the bitwise AND of a BitVector and a uint64 value.
  static member (&&&) (v1: BitVector, v2: uint64) =
    if v1.Len <= 64<rt> then
      BitVector.OfSmall(v1.Num &&& v2 |> adaptSmall v1.Len, v1.Len)
    else
      BitVector.OfBig(v1.BNum &&& bigint v2, v1.Len)

  /// Calculates the bitwise OR of a BitVector and a uint64 value.
  static member (|||) (v1: BitVector, v2: uint64) =
    if v1.Len <= 64<rt> then
      BitVector.OfSmall(v1.Num ||| v2 |> adaptSmall v1.Len, v1.Len)
    else
      BitVector.OfBig(v1.BNum ||| bigint v2, v1.Len)

  /// Calculates the bitwise XOR of a BitVector and a uint64 value.
  static member (^^^) (v1: BitVector, v2: uint64) =
    if v1.Len <= 64<rt> then
      BitVector.OfSmall(v1.Num ^^^ v2 |> adaptSmall v1.Len, v1.Len)
    else
      BitVector.OfBig(v1.BNum ^^^ bigint v2, v1.Len)

  /// Adds two BitVectors.
  static member (+) (v1: BitVector, v2: BitVector) = BitVector.Add(v1, v2)

  /// Subtracts two BitVectors.
  static member (-) (v1: BitVector, v2: BitVector) = BitVector.Sub(v1, v2)

  /// Multiplies two BitVectors.
  static member (*) (v1: BitVector, v2: BitVector) = BitVector.Mul(v1, v2)

  /// Divides two BitVectors (unsigned division).
  static member (/) (v1: BitVector, v2: BitVector) = BitVector.Div(v1, v2)

  /// Divides two BitVectors (signed division).
  static member (?/) (v1: BitVector, v2: BitVector) = BitVector.SDiv(v1, v2)

  /// Calculates the unsigned modulo of a BitVector by another BitVector.
  static member (%) (v1: BitVector, v2: BitVector) = BitVector.Modulo(v1, v2)

  /// Calculates the signed modulo of a BitVector by another BitVector.
  static member (?%) (v1: BitVector, v2: BitVector) = BitVector.SModulo(v1, v2)

  /// Calculates the bitwise AND of two BitVectors.
  static member (&&&) (v1: BitVector, v2: BitVector) = BitVector.And(v1, v2)

  /// Calculates the bitwise OR of two BitVectors.
  static member (|||) (v1: BitVector, v2: BitVector) = BitVector.Or(v1, v2)

  /// Calculates the bitwise XOR of two BitVectors.
  static member (^^^) (v1: BitVector, v2: BitVector) = BitVector.Xor(v1, v2)

  /// Calculates the bitwise NOT of a BitVector.
  static member (~~~) (v1: BitVector) = BitVector.Not v1

  /// Calculates the negation of a BitVector (as a signed integer).
  static member (~-) (v1: BitVector) = BitVector.Neg v1

  /// <summary>
  /// Returns the value of the given BitVector as a <c>uint64</c>. If the
  /// BitVector is longer than 64 bits, the behavior is not guaranteed.
  /// </summary>
  member this.ToUInt64() =
#if DEBUG
    if this.Len > 64<rt> && this.BNum > bigint UInt64.MaxValue then
      raise InvalidRegTypeException
    else
      ()
#endif
    this.RawSmall

  /// <summary>
  /// Returns the value of the given BitVector as an <c>int64</c>. If the
  /// BitVector is longer than 64 bits, the behavior is not guaranteed.
  /// </summary>
  member this.ToInt64() = this.ToUInt64() |> int64

  /// <summary>
  /// Returns the value of the given BitVector as a <c>uint32</c>. If the
  /// BitVector is longer than 64 bits, the behavior is not guaranteed.
  /// </summary>
  member this.ToUInt32() = this.ToUInt64() |> uint32

  /// <summary>
  /// Returns the value of the given BitVector as an <c>int32</c>. If the
  /// BitVector is longer than 64 bits, the behavior is not guaranteed.
  /// </summary>
  member this.ToInt32() = this.ToUInt64() |> int32

  /// <summary>
  /// Returns the value of the BitVector as a <c>bigint</c>.
  /// </summary>
  member this.ToBigInt() = this.RawBig

  /// <summary>
  /// Returns the string representation of the BitVector without the type
  /// suffix.
  /// </summary>
  member this.ToValueString() =
    if this.Len <= 64<rt> then HexString.ofUInt64 this.Num
    elif this.BNum = 0I then "0x0"
    else "0x" + this.BNum.ToString("x").TrimStart('0')

  /// <summary>
  /// Checks whether this BitVector has the same length and the same value as
  /// the given one.
  /// </summary>
  member this.Equals(rhs: BitVector) =
    if this.Len <> rhs.Len then false
    elif this.Len <= 64<rt> then this.Num = rhs.Num
    else this.BNum = rhs.BNum

  override this.Equals obj =
    match obj with
    | :? BitVector as rhs -> this.Equals rhs
    | _ -> false

  override this.GetHashCode() =
    if this.Len <= 64<rt> then
      HashCode.Combine<uint64, RegType>(this.Num, this.Len)
    else
      HashCode.Combine<bigint, RegType>(this.BNum, this.Len)

  override this.ToString() =
    this.ToValueString() + ":" + RegType.toString this.Len

  (* This repeats the body of Equals instead of calling it, because F#'s
     generic equality operator reaches a struct through this interface, and
     delegating would copy the struct once more on every comparison. *)
  interface IEquatable<BitVector> with
    member this.Equals(rhs: BitVector) =
      if this.Len <> rhs.Len then false
      elif this.Len <= 64<rt> then this.Num = rhs.Num
      else this.BNum = rhs.BNum
