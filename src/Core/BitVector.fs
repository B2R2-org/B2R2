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

/// A helper module for BitVector.
[<AutoOpen>]
module internal BitVectorHelper =

  exception ArithTypeMismatchException

  let nSizeErr t =
    failwithf "Invalid BitVector value for its type: %s" (t.ToString())

  let inline adaptSmall (len: RegType) (n: uint64) =
    (UInt64.MaxValue >>> (64 - int len)) &&& n

  let inline adaptBig (len: RegType) (n: bigint) =
    ((1I <<< int len) - 1I) &&& n

  let inline isSmallPositive (len: RegType) (n: uint64) =
    (n >>> (int len - 1)) &&& 1UL = 0UL

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

/// <summary>
/// Represents a bit vector, which is a sequence of bits. This type internally
/// uses two different representations to represent a bit vector depending on
/// its size. For those with less than or equal to 64 bits, it uses
/// <c>uint64</c> (<see cref='M:B2R2.BitVector.SmallValue'/>). For those with
/// more than 64 bits, it uses <c>bigint</c> (<see
/// cref='M:B2R2.BitVector.BigValue'/>). This is to avoid the overhead of using
/// <c>bigint</c> for small numbers as most CPU operations are in 64 bits or
/// less.<br/>
///
/// N.B. SmallValue becomes zero when the Length becomes greater than 64. We
/// intentionally do not sync SmallValue and BigValue.
/// </summary>
[<AbstractClass; AllowNullLiteral>]
type BitVector internal (len) =
  /// BitVector length.
  member _.Length with get (): RegType = len

  /// Return the uint64 representation of the BitVector value.
  abstract SmallValue: unit -> uint64

  /// Return the BigInteger representation of the BitVector value.
  abstract BigValue: unit -> bigint

  /// Return true if the value is zero.
  abstract IsZero: unit -> bool

  /// Return true if the value is one.
  abstract IsOne: unit -> bool

  /// BitVector addition with uint64.
  abstract Add: uint64 -> BitVector

  /// BitVector addition.
  abstract Add: BitVector -> BitVector

  /// BitVector subtraction with uint64.
  abstract Sub: uint64 -> BitVector

  /// BitVector subtraction.
  abstract Sub: BitVector -> BitVector

  /// BitVector multiplication with uint64.
  abstract Mul: uint64 -> BitVector

  /// BitVector multiplication.
  abstract Mul: BitVector -> BitVector

  /// BitVector signed division.
  abstract SDiv: BitVector -> BitVector

  /// BitVector unsigned division with uint64.
  abstract Div: uint64 -> BitVector

  /// BitVector unsigned division.
  abstract Div: BitVector -> BitVector

  /// BitVector signed modulo.
  abstract SMod: BitVector -> BitVector

  /// BitVector unsigned modulo with uint64.
  abstract Mod: uint64 -> BitVector

  /// BitVector unsigned modulo.
  abstract Mod: BitVector -> BitVector

  /// BitVector bitwise AND with uint64.
  abstract And: uint64 -> BitVector

  /// BitVector bitwise AND.
  abstract And: BitVector -> BitVector

  /// BitVector bitwise OR with uint64.
  abstract Or: uint64 -> BitVector

  /// BitVector bitwise OR.
  abstract Or: BitVector -> BitVector

  /// BitVector bitwise XOR with uint64.
  abstract Xor: uint64 -> BitVector

  /// BitVector bitwise XOR.
  abstract Xor: BitVector -> BitVector

  /// BitVector logical shift-left.
  abstract Shl: BitVector -> BitVector

  /// BitVector logical shift-right.
  abstract Shr: BitVector -> BitVector

  /// BitVector arithmetic shift-right.
  abstract Sar: BitVector -> BitVector

  /// BitVector bitwise NOT.
  abstract Not: unit -> BitVector

  /// BitVector unary negation.
  abstract Neg: unit -> BitVector

  /// Type-cast a BitVector to another type. If the target type is bigger than
  /// the current type, then this works the same as ZExt.
  abstract Cast: RegType -> BitVector

  /// Extract a sub-BitVector of size (RegType) starting from the index (int).
  abstract Extract: RegType * int -> BitVector

  /// BitVector concatenation.
  abstract Concat: BitVector -> BitVector

  /// BitVector sign-extension.
  abstract SExt: RegType -> BitVector

  /// BitVector zero-extension.
  abstract ZExt: RegType -> BitVector

  /// BitVector equal.
  abstract Eq: BitVector -> BitVector

  /// BitVector not equal.
  abstract Neq: BitVector -> BitVector

  /// BitVector unsigned greater than.
  abstract Gt: BitVector -> BitVector

  /// BitVector unsigned greater than or equal.
  abstract Ge: BitVector -> BitVector

  /// BitVector signed greater than.
  abstract SGt: BitVector -> BitVector

  /// BitVector signed greater than or equal.
  abstract SGe: BitVector -> BitVector

  /// BitVector unsigned less than.
  abstract Lt: BitVector -> BitVector

  /// BitVector unsigned less than or equal.
  abstract Le: BitVector -> BitVector

  /// BitVector signed less than.
  abstract SLt: BitVector -> BitVector

  /// BitVector signed less than or equal.
  abstract SLe: BitVector -> BitVector

  /// BitVector absolute value.
  abstract Abs: unit -> BitVector

  /// Floating point addition.
  abstract FAdd: BitVector -> BitVector

  /// Floating point subtraction.
  abstract FSub: BitVector -> BitVector

  /// Floating point multiplication.
  abstract FMul: BitVector -> BitVector

  /// Floating point division.
  abstract FDiv: BitVector -> BitVector

  /// Floating point logarithm.
  abstract FLog: BitVector -> BitVector

  /// Floating point power.
  abstract FPow: BitVector -> BitVector

  /// Floating point casting.
  abstract FCast: RegType -> BitVector

  /// Integer to float conversion.
  abstract Itof: RegType * bool -> BitVector

  /// Floating point to integer conversion with truncation.
  abstract FtoiTrunc: RegType -> BitVector

  /// Floating point to integer conversion with rounding.
  abstract FtoiRound: RegType -> BitVector

  /// Floating point to integer conversion with flooring.
  abstract FtoiFloor: RegType -> BitVector

  /// Floating point to integer conversion with ceiling.
  abstract FtoiCeil: RegType -> BitVector

  /// Floating point square root.
  abstract FSqrt: unit -> BitVector

  /// Floating point tangent.
  abstract FTan: unit -> BitVector

  /// Floating point sine.
  abstract FSin: unit -> BitVector

  /// Floating point cosine.
  abstract FCos: unit -> BitVector

  /// Floating point arc tangent.
  abstract FATan: unit -> BitVector

  /// Floating point greater than.
  abstract FGt: BitVector -> BitVector

  /// Floating point greater than or equal.
  abstract FGe: BitVector -> BitVector

  /// Floating point less than.
  abstract FLt: BitVector -> BitVector

  /// Floating point less than or equal.
  abstract FLe: BitVector -> BitVector

  /// Return the string representation of the BitVector value. Type is not
  /// appended to the output string.
  abstract ValToString: unit -> string

  /// BitVector approximate equal. For high-precision floating point numbers,
  /// this function performs approximate equality check.
  abstract ApproxEq: BitVector -> BitVector

  /// Is this BitVector representing a positive number?
  abstract IsPositive: unit -> bool

  /// Is this BitVector representing a negative number?
  abstract IsNegative: unit -> bool

  /// Return zero (0) of the given bit length.
  static member Zero t =
    if t <= 64<rt> then BitVectorSmall(0UL, t) :> BitVector
    else BitVectorBig(0I, t) :> BitVector

  /// Return one (1) of the given bit length.
  static member One t =
    if t <= 64<rt> then BitVectorSmall(1UL, t) :> BitVector
    else BitVectorBig(1I, t) :> BitVector

  /// True value.
  static member T = BitVectorSmall(1UL, 1<rt>) :> BitVector

  /// False value.
  static member F = BitVectorSmall(0UL, 1<rt>) :> BitVector

  /// Return a smaller BitVector.
  static member Min(bv1: BitVector, bv2) =
    if bv1.Lt bv2 = BitVector.T then bv1 else bv2

  /// Return a larger BitVector.
  static member Max(bv1: BitVector, bv2) =
    if bv1.Gt bv2 = BitVector.T then bv1 else bv2

  /// Return a smaller BitVector (with signed comparison).
  static member SMin(bv1: BitVector, bv2) =
    if bv1.SLt bv2 = BitVector.T then bv1 else bv2

  /// Return a larger BitVector (with signed comparison).
  static member SMax(bv1: BitVector, bv2) =
    if bv1.SGt bv2 = BitVector.T then bv1 else bv2

  /// Get a BitVector from an unsigned integer.
  static member OfUInt64(i: uint64, typ) =
#if DEBUG
    if typ <= 0<rt> then raise ArithTypeMismatchException else ()
#endif
    if typ <= 64<rt> then
      let mask = UInt64.MaxValue >>> (64 - int typ)
      BitVectorSmall(i &&& mask, typ) :> BitVector
    else BitVectorBig(bigint i, typ) :> BitVector

  /// Get a BitVector from a signed integer.
  static member OfInt64(i: int64, typ) =
#if DEBUG
    if typ <= 0<rt> then raise ArithTypeMismatchException else ()
#endif
    if typ <= 64<rt> then
      let mask = UInt64.MaxValue >>> (64 - int typ)
      BitVectorSmall(uint64 i &&& mask, typ) :> BitVector
    else
      if i < 0L then
        BitVectorBig((1I <<< int typ) - (- i |> bigint), typ) :> BitVector
      else BitVectorBig(bigint i, typ) :> BitVector

  /// Get a BitVector from an unsigned integer.
  static member inline OfUInt32(i: uint32, typ) =
    BitVector.OfUInt64(uint64 i, typ)

  /// Get a BitVector from a signed integer.
  static member inline OfInt32(i: int32, typ) =
    BitVector.OfInt64(int64 i, typ)

  /// Get a BitVector from a bigint. We assume that the given RegType (typ) is
  /// big enough to hold the given bigint. Otherwise, the resulting BitVector
  /// may contain an unexpected value.
  static member OfBInt(i: bigint, typ) =
#if DEBUG
    if typ <= 0<rt> then nSizeErr typ else ()
#endif
    if typ <= 64<rt> then BitVector.OfUInt64(uint64 i, typ)
    else
      if i.Sign < 0 then
        BitVectorBig((1I <<< int typ) + i, typ) :> BitVector
      else BitVectorBig(i, typ) :> BitVector

  /// Get a BitVector from a byte array (in little endian).
  static member OfArr(arr: byte []) =
    match arr.Length with
    | 1 -> BitVectorSmall(uint64 arr[0], 8<rt>) :> BitVector
    | 2 ->
      let n = BitConverter.ToUInt16(arr, 0) |> uint64
      BitVectorSmall(n, 16<rt>) :> BitVector
    | 3 ->
      let n = BitConverter.ToUInt32(Array.append arr [| 0uy |], 0) |> uint64
      BitVectorSmall(n, 24<rt>) :> BitVector
    | 4 ->
      let n = BitConverter.ToUInt32(arr, 0) |> uint64
      BitVectorSmall(n, 32<rt>) :> BitVector
    | 5 ->
      let arr = Array.append arr [| 0uy; 0uy; 0uy |]
      let n = BitConverter.ToUInt64(arr, 0)
      BitVectorSmall(n, 40<rt>) :> BitVector
    | 6 ->
      let arr = Array.append arr [| 0uy; 0uy |]
      let n = BitConverter.ToUInt64(arr, 0)
      BitVectorSmall(n, 48<rt>) :> BitVector
    | 7 ->
      let arr = Array.append arr [| 0uy |]
      let n = BitConverter.ToUInt64(arr, 0)
      BitVectorSmall(n, 56<rt>) :> BitVector
    | 8 ->
      let n = BitConverter.ToUInt64(arr, 0)
      BitVectorSmall(n, 64<rt>) :> BitVector
    | sz ->
      if sz > 8 then
        let arr = Array.append arr [| 0uy |]
        BitVectorBig(bigint arr, sz * 8<rt>) :> BitVector
      else nSizeErr (sz * 8)

  /// Get a uint64 value from a BitVector.
  static member ToUInt64(bv: BitVector) =
    bv.SmallValue()

  /// Get an int64 value from a BitVector.
  static member ToInt64(bv: BitVector) =
    bv.SmallValue() |> int64

  /// Get a uint32 value from a BitVector.
  static member ToUInt32(bv: BitVector) =
    bv.SmallValue() |> uint32

  /// Get an int32 value from a BitVector.
  static member ToInt32(bv: BitVector) =
    bv.SmallValue() |> int32

  /// Get a numeric value (bigint) from a BitVector.
  static member GetValue(bv: BitVector) =
    bv.BigValue()

  /// Get the type (length of the BitVector).
  static member GetType(bv: BitVector) = bv.Length

  /// Get the string representation of a BitVector without appended type info.
  static member ValToString(n: BitVector) = n.ValToString()

  /// Get the string representation of a BitVector.
  static member ToString(n: BitVector) = n.ToString()

  /// Bitvector of unsigned 8-bit maxvalue.
  static member MaxUInt8 = BitVector.OfUInt64(0xFFUL, 8<rt>)

  /// Bitvector of unsigned 16-bit maxvalue.
  static member MaxUInt16 = BitVector.OfUInt64(0xFFFFUL, 16<rt>)

  /// Bitvector of unsigned 32-bit maxvalue.
  static member MaxUInt32 = BitVector.OfUInt64(0xFFFFFFFFUL, 32<rt>)

  /// Bitvector of unsigned 64-bit maxvalue.
  static member MaxUInt64 = BitVector.OfUInt64(0xFFFFFFFFFFFFFFFFUL, 64<rt>)

  /// Check if the given BitVector is zero.
  static member IsZero(bv: BitVector) =
    bv.IsZero()

  /// Check if the given BitVector is one.
  static member IsOne(bv: BitVector) =
    bv.IsOne()

  /// Check if the given BitVector is "false".
  static member IsFalse(bv: BitVector) =
    bv = BitVector.F

  /// Check if the given BitVector is "true".
  static member IsTrue(bv: BitVector) =
    bv = BitVector.T

  /// Check if the given BitVector represents the specified number.
  static member IsNum(bv: BitVector, n: uint64) =
    if bv.Length <= 64<rt> then bv.SmallValue() = n
    else bigint n = bv.BigValue()

  /// BitVector representing a unsigned maximum integer for the given RegType.
  static member UnsignedMax rt =
#if DEBUG
    if rt <= 0<rt> then nSizeErr rt else ()
#endif
    if rt <= 64<rt> then
      BitVectorSmall(UInt64.MaxValue >>> (64 - int rt), rt) :> BitVector
    else BitVectorBig((1I <<< int rt) - 1I, rt) :> BitVector

  /// BitVector representing a unsigned minimum integer for the given RegType.
  static member UnsignedMin rt =
#if DEBUG
    if rt <= 0<rt> then nSizeErr rt else ()
#endif
    if rt <= 64<rt> then BitVectorSmall(0UL, rt) :> BitVector
    else BitVectorBig(0I, rt) :> BitVector

  /// BitVector representing a signed maximum integer for the given RegType.
  static member SignedMax rt =
#if DEBUG
    if rt <= 0<rt> then nSizeErr rt else ()
#endif
    if rt <= 64<rt> then
      BitVectorSmall(UInt64.MaxValue >>> (65 - int rt), rt) :> BitVector
    else BitVectorBig((1I <<< (int rt - 1)) - 1I, rt) :> BitVector

  /// BitVector representing a signed minimum integer for the given RegType.
  static member SignedMin rt =
#if DEBUG
    if rt <= 0<rt> then nSizeErr rt else ()
#endif
    if rt <= 64<rt> then BitVectorSmall(1UL <<< (int rt - 1), rt) :> BitVector
    else BitVectorBig(1I <<< (int rt - 1), rt) :> BitVector

  /// Does the BitVector represent an unsigned max value?
  static member IsUnsignedMax(bv: BitVector) =
    BitVector.UnsignedMax bv.Length = bv

  /// Does the BitVector represent a signed max value?
  static member IsSignedMax(bv: BitVector) =
    BitVector.SignedMax bv.Length = bv

  /// Does the BitVector represent a signed min value?
  static member IsSignedMin(bv: BitVector) =
    BitVector.SignedMin bv.Length = bv

  /// Is the BitVector positive?
  static member IsPositive(bv: BitVector) = bv.IsPositive()

  /// Is the BitVector negative?
  static member IsNegative(bv: BitVector) = bv.IsNegative()

  /// BitVector addition.
  static member inline Add(v1: BitVector, v2: BitVector) = v1.Add v2

  /// BitVector subtraction.
  static member inline Sub(v1: BitVector, v2: BitVector) = v1.Sub v2

  /// BitVector multiplication.
  static member inline Mul(v1: BitVector, v2: BitVector) = v1.Mul v2

  /// BitVector signed division.
  static member inline SDiv(v1: BitVector, v2: BitVector) = v1.SDiv v2

  /// BitVector unsigned division.
  static member inline Div(v1: BitVector, v2: BitVector) = v1.Div v2

  /// BitVector signed modulo.
  static member inline SModulo(v1: BitVector, v2: BitVector) = v1.SMod v2

  /// BitVector unsigned modulo.
  static member inline Modulo(v1: BitVector, v2: BitVector) = v1.Mod v2

  /// BitVector bitwise AND.
  static member inline BAnd(v1: BitVector, v2: BitVector) = v1.And v2

  /// BitVector bitwise OR.
  static member inline BOr(v1: BitVector, v2: BitVector) = v1.Or v2

  /// BitVector bitwise XOR.
  static member inline BXor(v1: BitVector, v2: BitVector) = v1.Xor v2

  /// BitVector logical shift-left.
  static member inline Shl(v1: BitVector, v2: BitVector) = v1.Shl v2

  /// BitVector logical shift-right.
  static member inline Shr(v1: BitVector, v2: BitVector) = v1.Shr v2

  /// BitVector arithmetic shift-right.
  static member inline Sar(v1: BitVector, v2: BitVector) = v1.Sar v2

  /// BitVector bitwise NOT.
  static member inline BNot(v1: BitVector) = v1.Not()

  /// BitVector negation.
  static member inline Neg(v1: BitVector) = v1.Neg()

  /// BitVector type cast.
  static member inline Cast(v1: BitVector, targetLen) = v1.Cast targetLen

  /// BitVector extraction.
  static member inline Extract(v1: BitVector, rt, pos) = v1.Extract(rt, pos)

  /// BitVector concatenation.
  static member inline Concat(v1: BitVector, v2: BitVector) = v1.Concat v2

  /// BitVector sign-extension.
  static member inline SExt(v1: BitVector, targetLen) = v1.SExt targetLen

  /// BitVector zero-extension.
  static member inline ZExt(v1: BitVector, targetLen) = v1.ZExt targetLen

  /// BitVector equal.
  static member inline Eq(v1: BitVector, v2: BitVector) = v1.Eq v2

  /// BitVector not equal.
  static member inline Neq(v1: BitVector, v2: BitVector) = v1.Neq v2

  /// BitVector greater than.
  static member inline Gt(v1: BitVector, v2: BitVector) = v1.Gt v2

  /// BitVector greater than or equal.
  static member inline Ge(v1: BitVector, v2: BitVector) = v1.Ge v2

  /// BitVector signed greater than.
  static member inline SGt(v1: BitVector, v2: BitVector) = v1.SGt v2

  /// BitVector signed greater than or equal.
  static member inline SGe(v1: BitVector, v2: BitVector) = v1.SGe v2

  /// BitVector less than.
  static member inline Lt(v1: BitVector, v2: BitVector) = v1.Lt v2

  /// BitVector less than or equal.
  static member inline Le(v1: BitVector, v2: BitVector) = v1.Le v2

  /// BitVector signed less than.
  static member inline SLt(v1: BitVector, v2: BitVector) = v1.SLt v2

  /// BitVector signed less than or equal.
  static member inline SLe(v1: BitVector, v2: BitVector) = v1.SLe v2

  /// BitVector absolute value.
  static member inline Abs(v1: BitVector) = v1.Abs()

  /// BitVector floating point addition.
  static member inline FAdd(v1: BitVector, v2: BitVector) = v1.FAdd v2

  /// BitVector floating point subtraction.
  static member inline FSub(v1: BitVector, v2: BitVector) = v1.FSub v2

  /// BitVector floating point multiplication.
  static member inline FMul(v1: BitVector, v2: BitVector) = v1.FMul v2

  /// BitVector floating point division.
  static member inline FDiv(v1: BitVector, v2: BitVector) = v1.FDiv v2

  /// BitVector floating point logarithm.
  static member inline FLog(v1: BitVector, v2: BitVector) = v1.FLog v2

  /// BitVector floating point power.
  static member inline FPow(v1: BitVector, v2: BitVector) = v1.FPow v2

  /// BitVector floating point casting.
  static member inline FCast(v1: BitVector, rt) = v1.FCast rt

  /// BitVector integer to float conversion.
  static member inline Itof(v1: BitVector, rt, isSigned) =
    v1.Itof(rt, isSigned)

  /// BitVector float to integer conversion with truncation.
  static member inline FtoiTrunc(v1: BitVector, rt) = v1.FtoiTrunc rt

  /// BitVector float to integer conversion with round.
  static member inline FtoiRound(v1: BitVector, rt) = v1.FtoiRound rt

  /// BitVector float to integer conversion with flooring.
  static member inline FtoiFloor(v1: BitVector, rt) = v1.FtoiFloor rt

  /// BitVector float to integer conversion with ceiling.
  static member inline FtoiCeil(v1: BitVector, rt) = v1.FtoiCeil rt

  /// BitVector square root.
  static member inline FSqrt(v1: BitVector) = v1.FSqrt()

  /// BitVector tangent.
  static member inline FTan(v1: BitVector) = v1.FTan()

  /// BitVector sine.
  static member inline FSin(v1: BitVector) = v1.FSin()

  /// BitVector cosine.
  static member inline FCos(v1: BitVector) = v1.FCos()

  /// BitVector arc tangent.
  static member inline FAtan(v1: BitVector) = v1.FATan()

  /// BitVector floating point greater than.
  static member inline FGt(v1: BitVector, v2: BitVector) = v1.FGt v2

  /// BitVector floating point greater than or equal.
  static member inline FGe(v1: BitVector, v2: BitVector) = v1.FGe v2

  /// BitVector floating point less than.
  static member inline FLt(v1: BitVector, v2: BitVector) = v1.FLt v2

  /// BitVector floating point less than or equal.
  static member inline FLe(v1: BitVector, v2: BitVector) = v1.FLe v2

  /// BitVector addition.
  static member inline (+) (v1: BitVector, v2: uint64) = v1.Add v2

  /// BitVector subtraction.
  static member inline (-) (v1: BitVector, v2: uint64) = v1.Sub v2

  /// BitVector multiplication.
  static member inline (*) (v1: BitVector, v2: uint64) = v1.Mul v2

  /// BitVector division.
  static member inline (/) (v1: BitVector, v2: uint64) = v1.Div v2

  /// BitVector modulo.
  static member inline (%) (v1: BitVector, v2: uint64) = v1.Mod v2

  /// BitVector bitwise AND.
  static member inline (&&&) (v1: BitVector, v2: uint64) = v1.And v2

  /// BitVector bitwise OR.
  static member inline (|||) (v1: BitVector, v2: uint64) = v1.Or v2

  /// BitVector bitwise XOR.
  static member inline (^^^) (v1: BitVector, v2: uint64) = v1.Xor v2

  /// BitVector addition.
  static member inline (+) (v1: BitVector, v2: BitVector) = v1.Add v2

  /// BitVector subtraction.
  static member inline (-) (v1: BitVector, v2: BitVector) = v1.Sub v2

  /// BitVector multiplication.
  static member inline (*) (v1: BitVector, v2: BitVector) = v1.Mul v2

  /// BitVector unsigned division.
  static member inline (/) (v1: BitVector, v2: BitVector) = v1.Div v2

  /// BitVector signed division.
  static member inline (?/) (v1: BitVector, v2: BitVector) = v1.SDiv v2

  /// BitVector unsigned modulo.
  static member inline (%) (v1: BitVector, v2: BitVector) = v1.Mod v2

  /// BitVector signed modulo.
  static member inline (?%) (v1: BitVector, v2: BitVector) = v1.SMod v2

  /// BitVector bitwise AND.
  static member inline (&&&) (v1: BitVector, v2: BitVector) = v1.And v2

  /// BitVector bitwise OR.
  static member inline (|||) (v1: BitVector, v2: BitVector) = v1.Or v2

  /// BitVector bitwise XOR.
  static member inline (^^^) (v1: BitVector, v2: BitVector) = v1.Xor v2

  /// BitVector bitwise not.
  static member inline (~~~) (v1: BitVector) = v1.Not()

  /// BitVector negation.
  static member inline (~-) (v1: BitVector) = v1.Neg()

/// This is a BitVector with its length less than or equal to 64bit. This is
/// preferred because all the operations will be much faster than BitVectorBig.
and private BitVectorSmall(n, len) =
  inherit BitVector(len)

#if DEBUG
  do if len > 64<rt> then raise ArithTypeMismatchException else ()
#endif

  new (n: int64, len) = BitVectorSmall(uint64 n, len)
  new (n: int32, len) = BitVectorSmall(uint64 n, len)
  new (n: int16, len) = BitVectorSmall(uint64 n, len)
  new (n: int8, len) = BitVectorSmall(uint64 n, len)
  new (n: uint32, len) = BitVectorSmall(uint64 n, len)
  new (n: uint16, len) = BitVectorSmall(uint64 n, len)
  new (n: uint8, len) = BitVectorSmall(uint64 n, len)

  member _.Value with get (): uint64 = n

  override _.ValToString() = HexString.ofUInt64 n

  override _.Equals obj =
    match obj with
    | :? BitVectorSmall as obj -> len = obj.Length && n = obj.Value
    | _ -> false

  override this.ApproxEq(rhs: BitVector) =
#if DEBUG
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
#endif
    let shifter = BitVector.OfInt32(1, len)
    let v1 = this.Shr shifter
    let v2 = rhs.Shr shifter
    v1.Eq v2

  override _.IsPositive() = isSmallPositive len n

  override _.IsNegative() = not <| isSmallPositive len n

  override _.GetHashCode() =
    HashCode.Combine<uint64, RegType>(n, len)

  override this.ToString() =
    this.ValToString() + ":" + RegType.toString len

  override _.SmallValue() = n

  override _.BigValue() = bigint n

  override _.IsZero() = n = 0UL

  override _.IsOne() = n = 1UL

  override _.Add(rhs: uint64) =
    BitVectorSmall(n + rhs |> adaptSmall len, len) :> BitVector

  override _.Add(rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorSmall(n + rhs.SmallValue() |> adaptSmall len, len) :> BitVector

  override _.Sub(rhs: uint64) =
    BitVectorSmall(n - rhs |> adaptSmall len, len) :> BitVector

  override _.Sub(rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorSmall(n - rhs.SmallValue() |> adaptSmall len, len) :> BitVector

  override _.Mul(rhs: uint64) =
    BitVectorSmall(n * rhs |> adaptSmall len, len) :> BitVector

  override _.Mul(rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorSmall(n * rhs.SmallValue() |> adaptSmall len, len) :> BitVector

  override _.SDiv(rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    let v1 = n
    let v2 = rhs.SmallValue()
    let isPos1 = isSmallPositive len v1
    let isPos2 = isSmallPositive len v2
    let v1 = int64 (if isPos1 then v1 else ((~~~ v1) + 1UL) |> adaptSmall len)
    let v2 = int64 (if isPos2 then v2 else ((~~~ v2) + 1UL) |> adaptSmall len)
    let result = if isPos1 = isPos2 then v1 / v2 else - (v1 / v2)
    BitVectorSmall(result |> uint64 |> adaptSmall len, len) :> BitVector

  override _.Div(rhs: uint64) =
    BitVectorSmall(n / rhs |> adaptSmall len, len) :> BitVector

  override _.Div(rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorSmall(n / rhs.SmallValue() |> adaptSmall len, len) :> BitVector

  override _.SMod(rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    let v1 = n
    let v2 = rhs.SmallValue()
    let isPos1 = isSmallPositive len v1
    let isPos2 = isSmallPositive len v2
    let v1 = int64 (if isPos1 then v1 else ((~~~ v1) + 1UL) |> adaptSmall len)
    let v2 = int64 (if isPos2 then v2 else ((~~~ v2) + 1UL) |> adaptSmall len)
    let result = if isPos1 then v1 % v2 else - (v1 % v2)
    BitVectorSmall(result |> uint64 |> adaptSmall len, len) :> BitVector

  override _.Mod(rhs: uint64) =
    BitVectorSmall(n % rhs |> adaptSmall len, len) :> BitVector

  override _.Mod(rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorSmall(n % rhs.SmallValue() |> adaptSmall len, len) :> BitVector

  override _.And(rhs: uint64) =
    BitVectorSmall(n &&& rhs |> adaptSmall len, len) :> BitVector

  override _.And(rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorSmall(n &&& rhs.SmallValue() |> adaptSmall len, len)
    :> BitVector

  override _.Or(rhs: uint64) =
    BitVectorSmall(n ||| rhs |> adaptSmall len, len) :> BitVector

  override _.Or(rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorSmall(n ||| rhs.SmallValue() |> adaptSmall len, len)
    :> BitVector

  override _.Xor(rhs: uint64) =
    BitVectorSmall(n ^^^ rhs |> adaptSmall len, len) :> BitVector

  override _.Xor(rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorSmall(n ^^^ rhs.SmallValue() |> adaptSmall len, len)
    :> BitVector

  override _.Shl(rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    let v1 = n
    let v2 = rhs.SmallValue()
    if v2 >= 64UL then BitVectorSmall(0UL, len) :> BitVector
    else BitVectorSmall(adaptSmall len (v1 <<< int v2), len) :> BitVector

  override _.Shr(rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    let v1 = n
    let v2 = rhs.SmallValue()
    (* In .NET, 1UL >>> 63 = 0, but 1UL >>> 64 = 1 *)
    if v2 >= 64UL then BitVectorSmall(0UL, len) :> BitVector
    else BitVectorSmall(v1 >>> (int v2), len) :> BitVector

  override this.Sar(rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    let v1 = n
    let v2 = rhs.SmallValue()
    (* In .NET, 1UL >>> 63 = 0, but 1UL >>> 64 = 1 *)
    if v2 >= 64UL then
      BitVectorSmall(UInt64.MaxValue |> adaptSmall len, len) :> BitVector
    else
      let res = v1 >>> (int v2)
      if len = 1<rt> then this :> BitVector
      elif isSmallPositive len v1 then BitVectorSmall(res, len) :> BitVector
      else
        let pad =
          (UInt64.MaxValue >>> (64 - int len))
          - (if int len <= int v2 then 0UL
             else UInt64.MaxValue >>> (64 - (int len - int v2)))
        BitVectorSmall(res ||| pad, len) :> BitVector

  override _.Not() =
    BitVectorSmall((~~~ n) |> adaptSmall len, len) :> BitVector

  override _.Neg() =
    BitVectorSmall(((~~~ n) + 1UL) |> adaptSmall len, len) :> BitVector

  override this.Cast targetLen =
    if targetLen <= 64<rt> then
      BitVectorSmall(adaptSmall targetLen n, targetLen)
      :> BitVector
    else
      BitVectorBig(adaptBig targetLen (this.BigValue()), targetLen)
      :> BitVector

  override this.Extract(targetLen, pos) =
    if len < targetLen then raise ArithTypeMismatchException
    elif len = targetLen then this :> BitVector
    else
      BitVectorSmall(adaptSmall targetLen (n >>> pos), targetLen) :> BitVector

  override this.Concat(rhs: BitVector) =
    let rLen = rhs.Length
    let targetLen = len + rLen
    if targetLen <= 64<rt> then
      BitVectorSmall((n <<< int rLen) + rhs.SmallValue(), targetLen)
      :> BitVector
    else
      let v1 = this.BigValue()
      let v2 = rhs.BigValue()
      BitVectorBig((v1 <<< int rLen) + v2, targetLen) :> BitVector

  override this.SExt targetLen =
    if targetLen < len then raise ArithTypeMismatchException
    elif targetLen = len then this :> BitVector
    elif targetLen <= 64<rt> then
      if isSmallPositive len n then BitVectorSmall(n, targetLen) :> BitVector
      else
        let mask =
          (UInt64.MaxValue >>> (64 - int targetLen))
          - (UInt64.MaxValue >>> (64 - int len))
        BitVectorSmall(n + mask, targetLen) :> BitVector
    else
      let n' = adaptBig targetLen (this.BigValue())
      if isSmallPositive len n then BitVectorBig(n', targetLen) :> BitVector
      else
        let mask = (1I <<< int targetLen) - (1I <<< int len)
        BitVectorBig(n' + mask, targetLen) :> BitVector

  override this.ZExt targetLen =
    if targetLen < len then raise ArithTypeMismatchException
    elif targetLen = len then this :> BitVector
    elif targetLen <= 64<rt> then
      BitVectorSmall(adaptSmall targetLen n, targetLen)
      :> BitVector
    else
      BitVectorBig(adaptBig targetLen (this.BigValue()), targetLen)
      :> BitVector

  override _.Eq rhs =
    if len = rhs.Length && n = rhs.SmallValue() then BitVector.T
    else BitVector.F

  override _.Neq rhs =
    if len = rhs.Length && n = rhs.SmallValue() then BitVector.F
    else BitVector.T

  override _.Gt rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException
    elif n > rhs.SmallValue() then BitVector.T
    else BitVector.F

  override _.Ge rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException
    elif n >= rhs.SmallValue() then BitVector.T
    else BitVector.F

  override _.SGt rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException
    else
      let v1 = n
      let v2 = rhs.SmallValue()
      let isPos1 = isSmallPositive len v1
      let isPos2 = isSmallPositive len v2
      match isPos1, isPos2 with
      | true, false -> BitVector.T
      | false, true -> BitVector.F
      | _ -> if v1 > v2 then BitVector.T else BitVector.F

  override _.SGe rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException
    else
      let v1 = n
      let v2 = rhs.SmallValue()
      let isPos1 = isSmallPositive len v1
      let isPos2 = isSmallPositive len v2
      match isPos1, isPos2 with
      | true, false -> BitVector.T
      | false, true -> BitVector.F
      | _ -> if v1 >= v2 then BitVector.T else BitVector.F

  override _.Lt rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException
    elif n < rhs.SmallValue() then BitVector.T
    else BitVector.F

  override _.Le rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException
    elif n <= rhs.SmallValue() then BitVector.T
    else BitVector.F

  override _.SLt rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException
    else
      let v1 = n
      let v2 = rhs.SmallValue()
      let isPos1 = isSmallPositive len v1
      let isPos2 = isSmallPositive len v2
      match isPos1, isPos2 with
      | true, false -> BitVector.F
      | false, true -> BitVector.T
      | _ -> if v1 < v2 then BitVector.T else BitVector.F

  override _.SLe rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException
    else
      let v1 = n
      let v2 = rhs.SmallValue()
      let isPos1 = isSmallPositive len v1
      let isPos2 = isSmallPositive len v2
      match isPos1, isPos2 with
      | true, false -> BitVector.F
      | false, true -> BitVector.T
      | _ -> if v1 <= v2 then BitVector.T else BitVector.F

  override this.Abs() =
    if isSmallPositive len n then this :> BitVector
    else this.Neg()

  override this.FAdd rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 32<rt> ->
      let v1 = this.SmallValue() |> toFloat32
      let v2 = rhs.SmallValue() |> toFloat32
      let bs = v1 + v2 |> BitConverter.GetBytes
      BitVectorSmall(BitConverter.ToInt32(bs, 0) |> uint64, len) :> BitVector
    | 64<rt> ->
      let v1 = this.SmallValue() |> toFloat64
      let v2 = rhs.SmallValue() |> toFloat64
      let r = v1 + v2 |> BitConverter.DoubleToInt64Bits |> uint64
      BitVectorSmall(r, len) :> BitVector
    | _ -> raise ArithTypeMismatchException

  override this.FSub rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 32<rt> ->
      let v1 = this.SmallValue() |> toFloat32
      let v2 = rhs.SmallValue() |> toFloat32
      let bs = v1 - v2 |> BitConverter.GetBytes
      BitVectorSmall(BitConverter.ToInt32(bs, 0) |> uint64, len) :> BitVector
    | 64<rt> ->
      let v1 = this.SmallValue() |> toFloat64
      let v2 = rhs.SmallValue() |> toFloat64
      let r = v1 - v2 |> BitConverter.DoubleToInt64Bits |> uint64
      BitVectorSmall(r, len) :> BitVector
    | _ -> raise ArithTypeMismatchException

  override this.FMul rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 32<rt> ->
      let v1 = this.SmallValue() |> toFloat32
      let v2 = rhs.SmallValue() |> toFloat32
      let bs = v1 * v2 |> BitConverter.GetBytes
      BitVectorSmall(BitConverter.ToInt32(bs, 0) |> uint64, len) :> BitVector
    | 64<rt> ->
      let v1 = this.SmallValue() |> toFloat64
      let v2 = rhs.SmallValue() |> toFloat64
      let r = v1 * v2 |> BitConverter.DoubleToInt64Bits |> uint64
      BitVectorSmall(r, len) :> BitVector
    | _ -> raise ArithTypeMismatchException

  override this.FDiv rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 32<rt> ->
      let v1 = this.SmallValue() |> toFloat32
      let v2 = rhs.SmallValue() |> toFloat32
      let bs = v1 / v2 |> BitConverter.GetBytes
      BitVectorSmall(BitConverter.ToInt32(bs, 0) |> uint64, len) :> BitVector
    | 64<rt> ->
      let v1 = this.SmallValue() |> toFloat64
      let v2 = rhs.SmallValue() |> toFloat64
      let r = v1 / v2 |> BitConverter.DoubleToInt64Bits |> uint64
      BitVectorSmall(r, len) :> BitVector
    | _ -> raise ArithTypeMismatchException

  override this.FLog rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 32<rt> ->
      let v1 = this.SmallValue() |> toFloat32
      let v2 = rhs.SmallValue() |> toFloat32
      let bs = MathF.Log(v2, v1) |> BitConverter.GetBytes
      BitVectorSmall(BitConverter.ToInt32(bs, 0) |> uint64, len) :> BitVector
    | 64<rt> ->
      let v1 = this.SmallValue() |> toFloat64
      let v2 = rhs.SmallValue() |> toFloat64
      let r = Math.Log(v2, v1) |> BitConverter.DoubleToInt64Bits |> uint64
      BitVectorSmall(r, len) :> BitVector
    | _ -> raise ArithTypeMismatchException

  override this.FPow rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 32<rt> ->
      let v1 = this.SmallValue() |> toFloat32
      let v2 = rhs.SmallValue() |> toFloat32
      let bs = MathF.Pow(v1, v2) |> BitConverter.GetBytes
      BitVectorSmall(BitConverter.ToInt32(bs, 0) |> uint64, len) :> BitVector
    | 64<rt> ->
      let v1 = this.SmallValue() |> toFloat64
      let v2 = rhs.SmallValue() |> toFloat64
      let r = Math.Pow(v1, v2) |> BitConverter.DoubleToInt64Bits |> uint64
      BitVectorSmall(r, len) :> BitVector
    | _ -> raise ArithTypeMismatchException

  override this.FCast targetLen =
    match len, targetLen with
    | 32<rt>, 32<rt> -> this :> BitVector
    | 32<rt>, 64<rt> ->
      let f32 = this.SmallValue() |> toFloat32 |> float
      let u64 = BitConverter.DoubleToInt64Bits f32 |> uint64
      BitVectorSmall(u64, targetLen) :> BitVector
    | 32<rt>, 80<rt> ->
      let f32 = this.SmallValue() |> toFloat32 |> float
      let u64 = BitConverter.DoubleToInt64Bits f32 |> uint64
      BitVectorBig(encodeBigFloat u64, targetLen) :> BitVector
    | 64<rt>, 32<rt> ->
      let f64 = this.SmallValue() |> toFloat64
      let u64 = BitConverter.SingleToInt32Bits(float32 f64) |> uint64
      BitVectorSmall(u64, targetLen) :> BitVector
    | 64<rt>, 64<rt> -> this :> BitVector
    | 64<rt>, 80<rt> ->
      BitVectorBig(this.SmallValue() |> encodeBigFloat, targetLen)
      :> BitVector
    | _ -> raise ArithTypeMismatchException

  override _.Itof(targetLen, isSigned) =
    match targetLen with
    | 32<rt> ->
      let fpv = if isSigned then n |> int64 |> float32 else n |> float32
      let u64 = BitConverter.SingleToInt32Bits fpv |> uint64
      BitVectorSmall(u64, targetLen) :> BitVector
    | 64<rt> ->
      let fpv = if isSigned then n |> int64 |> float else n |> float
      let u64 = BitConverter.DoubleToInt64Bits fpv |> uint64
      BitVectorSmall(u64, targetLen) :> BitVector
    | 80<rt> ->
      let fpv = if isSigned then n |> int64 |> float else n |> float
      let u64 = BitConverter.DoubleToInt64Bits fpv |> uint64
      BitVectorBig(bigint u64, targetLen) :> BitVector
    | _ -> raise ArithTypeMismatchException

  override this.FtoiTrunc targetLen =
    let f =
      match len with
      | 32<rt> -> this.SmallValue() |> toFloat32 |> float |> truncate
      | 64<rt> -> this.SmallValue() |> toFloat64 |> truncate
      | _ -> raise ArithTypeMismatchException
    if targetLen <= 64<rt> then
      BitVectorSmall(adaptSmall targetLen (uint64 f), targetLen) :> BitVector
    else BitVectorBig(adaptBig targetLen (bigint f), targetLen) :> BitVector

  override this.FtoiRound targetLen =
    let f =
      match len with
      | 32<rt> -> this.SmallValue() |> toFloat32 |> float |> round
      | 64<rt> -> this.SmallValue() |> toFloat64 |> round
      | _ -> raise ArithTypeMismatchException
    if targetLen <= 64<rt> then
      BitVectorSmall(adaptSmall targetLen (uint64 f), targetLen) :> BitVector
    else BitVectorBig(adaptBig targetLen (bigint f), targetLen) :> BitVector

  override this.FtoiFloor targetLen =
    let f =
      match len with
      | 32<rt> -> this.SmallValue() |> toFloat32 |> float |> floor
      | 64<rt> -> this.SmallValue() |> toFloat64 |> floor
      | _ -> raise ArithTypeMismatchException
    if targetLen <= 64<rt> then
      BitVectorSmall(adaptSmall targetLen (uint64 f), targetLen) :> BitVector
    else BitVectorBig(adaptBig targetLen (bigint f), targetLen) :> BitVector

  override this.FtoiCeil targetLen =
    let f =
      match len with
      | 32<rt> -> this.SmallValue() |> toFloat32 |> float |> ceil
      | 64<rt> -> this.SmallValue() |> toFloat64 |> ceil
      | _ -> raise ArithTypeMismatchException
    if targetLen <= 64<rt> then
      BitVectorSmall(adaptSmall targetLen (uint64 f), targetLen) :> BitVector
    else BitVectorBig(adaptBig targetLen (bigint f), targetLen) :> BitVector

  override this.FSqrt() =
    match len with
    | 32<rt> ->
      let r = this.SmallValue() |> toFloat32 |> sqrt
      BitVectorSmall(BitConverter.SingleToInt32Bits r |> uint64, len)
      :> BitVector
    | 64<rt> ->
      let r = this.SmallValue() |> toFloat64 |> sqrt
      BitVectorSmall(BitConverter.DoubleToInt64Bits r |> uint64, len)
      :> BitVector
    | _ -> raise ArithTypeMismatchException

  override this.FTan() =
    match len with
    | 32<rt> ->
      let r = this.SmallValue() |> toFloat32 |> tan
      BitVectorSmall(BitConverter.SingleToInt32Bits r |> uint64, len)
      :> BitVector
    | 64<rt> ->
      let r = this.SmallValue() |> toFloat64 |> tan
      BitVectorSmall(BitConverter.DoubleToInt64Bits r |> uint64, len)
      :> BitVector
    | _ -> raise ArithTypeMismatchException

  override this.FATan() =
    match len with
    | 32<rt> ->
      let r = this.SmallValue() |> toFloat32 |> atan
      BitVectorSmall(BitConverter.SingleToInt32Bits r |> uint64, len)
      :> BitVector
    | 64<rt> ->
      let r = this.SmallValue() |> toFloat64 |> atan
      BitVectorSmall(BitConverter.DoubleToInt64Bits r |> uint64, len)
      :> BitVector
    | _ -> raise ArithTypeMismatchException

  override this.FSin() =
    match len with
    | 32<rt> ->
      let r = this.SmallValue() |> toFloat32 |> sin
      BitVectorSmall(BitConverter.SingleToInt32Bits r |> uint64, len)
      :> BitVector
    | 64<rt> ->
      let r = this.SmallValue() |> toFloat64 |> sin
      BitVectorSmall(BitConverter.DoubleToInt64Bits r |> uint64, len)
      :> BitVector
    | _ -> raise ArithTypeMismatchException

  override this.FCos() =
    match len with
    | 32<rt> ->
      let r = this.SmallValue() |> toFloat32 |> cos
      BitVectorSmall(BitConverter.SingleToInt32Bits r |> uint64, len)
      :> BitVector
    | 64<rt> ->
      let r = this.SmallValue() |> toFloat64 |> cos
      BitVectorSmall(BitConverter.DoubleToInt64Bits r |> uint64, len)
      :> BitVector
    | _ -> raise ArithTypeMismatchException

  override this.FGt rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 32<rt> ->
      let v1 = this.SmallValue() |> toFloat32
      let v2 = rhs.SmallValue() |> toFloat32
      if v1 > v2 then BitVector.T else BitVector.F
    | 64<rt> ->
      let v1 = this.SmallValue() |> toFloat64
      let v2 = rhs.SmallValue() |> toFloat64
      if v1 > v2 then BitVector.T else BitVector.F
    | _ -> raise ArithTypeMismatchException

  override this.FGe rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 32<rt> ->
      let v1 = this.SmallValue() |> toFloat32
      let v2 = rhs.SmallValue() |> toFloat32
      if v1 >= v2 then BitVector.T else BitVector.F
    | 64<rt> ->
      let v1 = this.SmallValue() |> toFloat64
      let v2 = rhs.SmallValue() |> toFloat64
      if v1 >= v2 then BitVector.T else BitVector.F
    | _ -> raise ArithTypeMismatchException

  override this.FLt rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 32<rt> ->
      let v1 = this.SmallValue() |> toFloat32
      let v2 = rhs.SmallValue() |> toFloat32
      if v1 < v2 then BitVector.T else BitVector.F
    | 64<rt> ->
      let v1 = this.SmallValue() |> toFloat64
      let v2 = rhs.SmallValue() |> toFloat64
      if v1 < v2 then BitVector.T else BitVector.F
    | _ -> raise ArithTypeMismatchException

  override this.FLe rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 32<rt> ->
      let v1 = this.SmallValue() |> toFloat32
      let v2 = rhs.SmallValue() |> toFloat32
      if v1 <= v2 then BitVector.T else BitVector.F
    | 64<rt> ->
      let v1 = this.SmallValue() |> toFloat64
      let v2 = rhs.SmallValue() |> toFloat64
      if v1 <= v2 then BitVector.T else BitVector.F
    | _ -> raise ArithTypeMismatchException

/// This is a BitVector with its length less than or equal to 64bit. This is
/// preferred because all the operations will be much faster than BitVectorBig.
and private BitVectorBig(n, len) =
  inherit BitVector(len)

#if DEBUG
  do if len <= 64<rt> then raise ArithTypeMismatchException else ()
#endif

  member _.Value with get (): bigint = n

  override _.ValToString() =
    if n = 0I then "0x0"
    else "0x" + n.ToString("x").TrimStart('0')

  override _.Equals obj =
    match obj with
    | :? BitVectorBig as obj -> len = obj.Length && n = obj.Value
    | _ -> false

  override this.ApproxEq(rhs: BitVector) =
#if DEBUG
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
#endif
    if len = 80<rt> then
      let shifter = BitVector.OfInt32(12, 80<rt>)
      let v1 = this.Shr shifter
      let v2 = rhs.Shr shifter
      v1.Eq v2
    else raise ArithTypeMismatchException

  override _.IsPositive() = isBigPositive len n

  override _.IsNegative() = not <| isBigPositive len n

  override _.GetHashCode() =
    HashCode.Combine<bigint, RegType>(n, len)

  override this.ToString() =
    this.ValToString() + ":" + RegType.toString len

  override _.SmallValue() =
#if DEBUG
    if n > bigint 0xFFFFFFFFFFFFFFFFUL then nSizeErr len else ()
#endif
    uint64 n

  override _.BigValue() = n

  override _.IsZero() = n = 0I

  override _.IsOne() = n = 1I

  override _.Add(rhs: uint64) =
    BitVectorBig(n + bigint rhs, len) :> BitVector

  override _.Add(rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorBig(n + rhs.BigValue() |> adaptBig len, len) :> BitVector

  override _.Sub(rhs: uint64) =
    BitVectorBig(n - bigint rhs, len) :> BitVector

  override _.Sub(rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorBig(n - rhs.BigValue() |> adaptBig len, len) :> BitVector

  override _.Mul(rhs: uint64) =
    BitVectorBig(n * bigint rhs, len) :> BitVector

  override _.Mul(rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorBig(n * rhs.BigValue() |> adaptBig len, len) :> BitVector

  override _.SDiv(rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    let v1 = n
    let v2 = rhs.BigValue()
    let isPos1 = isBigPositive len v1
    let isPos2 = isBigPositive rhs.Length v2
    let v1 = if isPos1 then v1 else neg len v1
    let v2 = if isPos2 then v2 else neg len v2
    let result = if isPos1 = isPos2 then v1 / v2 else neg len (v1 / v2)
    BitVectorBig(result |> adaptBig len, len) :> BitVector

  override _.Div(rhs: uint64) =
    BitVectorBig(n / bigint rhs, len) :> BitVector

  override _.Div(rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorBig(n / rhs.BigValue() |> adaptBig len, len) :> BitVector

  override _.SMod(rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    let v1 = n
    let v2 = rhs.BigValue()
    let isPos1 = isBigPositive len v1
    let isPos2 = isBigPositive rhs.Length v2
    let v1 = if isPos1 then v1 else neg len v1
    let v2 = if isPos2 then v2 else neg len v2
    let result = if isPos1 then v1 % v2 else neg len (v1 % v2)
    BitVectorBig(result |> adaptBig len, len) :> BitVector

  override _.Mod(rhs: uint64) =
    BitVectorBig(n % bigint rhs, len) :> BitVector

  override _.Mod(rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorBig(n % rhs.BigValue() |> adaptBig len, len) :> BitVector

  override _.And(rhs: uint64) =
    BitVectorBig(n &&& bigint rhs, len) :> BitVector

  override _.And(rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorBig(n &&& rhs.BigValue() |> adaptBig len, len) :> BitVector

  override _.Or(rhs: uint64) =
    BitVectorBig(n ||| bigint rhs, len) :> BitVector

  override _.Or(rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorBig(n ||| rhs.BigValue() |> adaptBig len, len) :> BitVector

  override _.Xor(rhs: uint64) =
    BitVectorBig(n ^^^ bigint rhs, len) :> BitVector

  override _.Xor(rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorBig(n ^^^ rhs.BigValue() |> adaptBig len, len) :> BitVector

  override _.Shl(rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    let v1 = n
    let v2 = rhs.SmallValue() |> uint16 |> int
    BitVectorBig(adaptBig len (v1 <<< v2), len) :> BitVector

  override _.Shr(rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    let v1 = n
    let v2 = rhs.SmallValue() |> uint16 |> int
    BitVectorBig(v1 >>> v2, len) :> BitVector

  override _.Sar(rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    let v1 = n
    let v2 = rhs.SmallValue() |> uint16 |> int
    if v2 >= int len then BitVectorBig((1I <<< int len) - 1I, len) :> BitVector
    else
      let res = v1 >>> v2
      if isBigPositive len v1 then BitVectorBig(res, len) :> BitVector
      else
        let pad =
          ((1I <<< int len) - 1I) - ((1I <<< (int len - v2)))
        BitVectorBig(res ||| pad, len) :> BitVector

  override _.Not() =
    BitVectorBig((1I <<< (int len)) - 1I - n, len) :> BitVector

  override _.Neg() =
    BitVectorBig(adaptBig len ((1I <<< (int len)) - n), len) :> BitVector

  override _.Cast targetLen =
    if targetLen <= 64<rt> then
      BitVectorSmall(adaptSmall targetLen (uint64 n), targetLen) :> BitVector
    else BitVectorBig(adaptBig targetLen n, targetLen) :> BitVector

  override this.Extract(targetLen, pos) =
    if len < targetLen then raise ArithTypeMismatchException
    elif len = targetLen then this :> BitVector
    elif targetLen <= 64<rt> then
      let n' = n >>> pos |> adaptBig targetLen |> uint64
      BitVectorSmall(n', targetLen) :> BitVector
    else BitVectorBig(adaptBig targetLen (n >>> pos), targetLen) :> BitVector

  override _.Concat(rhs: BitVector) =
    let rLen = rhs.Length
    let targetLen = len + rLen
    let v1 = n
    let v2 = rhs.BigValue()
    BitVectorBig((v1 <<< int rLen) + v2, targetLen) :> BitVector

  override this.SExt targetLen =
    if targetLen < len then raise ArithTypeMismatchException
    elif targetLen = len then this :> BitVector
    else
      let n' = adaptBig targetLen n
      if isBigPositive len n then
        BitVectorBig(n', targetLen) :> BitVector
      else
        let mask = (1I <<< int targetLen) - (1I <<< int len)
        BitVectorBig(n' + mask, targetLen) :> BitVector

  override this.ZExt targetLen =
    if targetLen < len then raise ArithTypeMismatchException
    elif targetLen = len then this :> BitVector
    else BitVectorBig(adaptBig targetLen n, targetLen) :> BitVector

  override _.Eq rhs =
    if len = rhs.Length && n = rhs.BigValue() then BitVector.T
    else BitVector.F

  override _.Neq rhs =
    if len = rhs.Length && n = rhs.BigValue() then BitVector.F
    else BitVector.T

  override _.Gt rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException
    elif n > rhs.BigValue() then BitVector.T
    else BitVector.F

  override _.Ge rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException
    elif n >= rhs.BigValue() then BitVector.T
    else BitVector.F

  override _.SGt rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    let isPos1 = isBigPositive len n
    let isPos2 = isBigPositive len (rhs.BigValue())
    if isPos1 && not isPos2 then BitVector.T
    elif not isPos1 && isPos2 then BitVector.F
    else
      if n > rhs.BigValue() then BitVector.T else BitVector.F

  override _.SGe rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    let isPos1 = isBigPositive len n
    let isPos2 = isBigPositive len (rhs.BigValue())
    if isPos1 && not isPos2 then BitVector.T
    elif not isPos1 && isPos2 then BitVector.F
    else
      if n >= rhs.BigValue() then BitVector.T else BitVector.F

  override _.Lt rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException
    elif n < rhs.BigValue() then BitVector.T
    else BitVector.F

  override _.Le rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException
    elif n <= rhs.BigValue() then BitVector.T
    else BitVector.F

  override _.SLt rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    let isPos1 = isBigPositive len n
    let isPos2 = isBigPositive len (rhs.BigValue())
    if isPos1 && not isPos2 then BitVector.F
    elif not isPos1 && isPos2 then BitVector.T
    else
      if n < rhs.BigValue() then BitVector.T else BitVector.F

  override _.SLe rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    let isPos1 = isBigPositive len n
    let isPos2 = isBigPositive len (rhs.BigValue())
    if isPos1 && not isPos2 then BitVector.F
    elif not isPos1 && isPos2 then BitVector.T
    else
      if n <= rhs.BigValue() then BitVector.T else BitVector.F

  override this.Abs() =
    if isBigPositive len n then this :> BitVector
    else this.Neg()

  override this.FAdd rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 80<rt> ->
      let v1 = this.BigValue() |> toBigFloat
      let v2 = rhs.BigValue() |> toBigFloat
      let n = v1 + v2 |> BitConverter.DoubleToInt64Bits |> uint64
      if n = 0UL then BitVector.Zero len
      else BitVectorBig(encodeBigFloat n, len) :> BitVector
    | _ -> raise ArithTypeMismatchException

  override this.FSub rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 80<rt> ->
      let v1 = this.BigValue() |> toBigFloat
      let v2 = rhs.BigValue() |> toBigFloat
      let n = v1 - v2 |> BitConverter.DoubleToInt64Bits |> uint64
      if n = 0UL then BitVector.Zero len
      else BitVectorBig(encodeBigFloat n, len) :> BitVector
    | _ -> raise ArithTypeMismatchException

  override this.FMul rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 80<rt> ->
      let v1 = this.BigValue() |> toBigFloat
      let v2 = rhs.BigValue() |> toBigFloat
      let n = v1 * v2 |> BitConverter.DoubleToInt64Bits |> uint64
      if n = 0UL then BitVector.Zero len
      else BitVectorBig(encodeBigFloat n, len) :> BitVector
    | _ -> raise ArithTypeMismatchException

  override this.FDiv rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 80<rt> ->
      let v1 = this.BigValue() |> toBigFloat
      let v2 = rhs.BigValue() |> toBigFloat
      let n = v1 / v2 |> BitConverter.DoubleToInt64Bits |> uint64
      if n = 0UL then BitVector.Zero len
      else BitVectorBig(encodeBigFloat n, len) :> BitVector
    | _ -> raise ArithTypeMismatchException

  override this.FLog rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 80<rt> ->
      let v1 = this.BigValue() |> toBigFloat
      let v2 = rhs.BigValue() |> toBigFloat
      let n = Math.Log(v2, v1) |> BitConverter.DoubleToInt64Bits |> uint64
      if n = 0UL then BitVector.Zero len
      else BitVectorBig(encodeBigFloat n, len) :> BitVector
    | _ -> raise ArithTypeMismatchException

  override this.FPow rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 80<rt> ->
      let v1 = this.BigValue() |> toBigFloat
      let v2 = rhs.BigValue() |> toBigFloat
      let n = Math.Pow(v1, v2) |> BitConverter.DoubleToInt64Bits |> uint64
      if n = 0UL then BitVector.Zero len
      else BitVectorBig(encodeBigFloat n, len) :> BitVector
    | _ -> raise ArithTypeMismatchException

  override this.FCast targetLen =
    match len, targetLen with
    | 80<rt>, 32<rt> ->
      let f32 = this.BigValue() |> toBigFloat |> float32
      BitVectorSmall(BitConverter.SingleToInt32Bits f32 |> uint64, targetLen)
      :> BitVector
    | 80<rt>, 64<rt> ->
      let f64 = this.BigValue() |> toBigFloat
      BitVectorSmall(BitConverter.DoubleToInt64Bits f64 |> uint64, targetLen)
      :> BitVector
    | 80<rt>, 80<rt> -> this :> BitVector
    | _ -> raise ArithTypeMismatchException

  override _.Itof(targetLen, _) =
    let v = if isBigPositive len n then n else - n
    match targetLen with
    | 32<rt> ->
      let u64 = BitConverter.SingleToInt32Bits(float32 v) |> uint64
      BitVectorSmall(u64, targetLen) :> BitVector
    | 64<rt> ->
      let u64 = BitConverter.DoubleToInt64Bits(float v) |> uint64
      BitVectorSmall(u64, targetLen) :> BitVector
    | 80<rt> ->
      let u64 = BitConverter.DoubleToInt64Bits(float v) |> uint64
      BitVectorBig(bigint u64, targetLen) :> BitVector
    | _ -> raise ArithTypeMismatchException

  override this.FtoiTrunc targetLen =
    let f =
      match len with
      | 80<rt> -> this.BigValue() |> toBigFloat |> truncate
      | _ -> raise ArithTypeMismatchException
    if targetLen <= 64<rt> then
      BitVectorSmall(adaptSmall targetLen (uint64 f), targetLen) :> BitVector
    else BitVectorBig(adaptBig targetLen (bigint f), targetLen) :> BitVector

  override this.FtoiRound targetLen =
    let f =
      match len with
      | 80<rt> -> this.BigValue() |> toBigFloat |> round
      | _ -> raise ArithTypeMismatchException
    if targetLen <= 64<rt> then
      BitVectorSmall(adaptSmall targetLen (uint64 f), targetLen) :> BitVector
    else BitVectorBig(adaptBig targetLen (bigint f), targetLen) :> BitVector

  override this.FtoiFloor targetLen =
    let f =
      match len with
      | 80<rt> -> this.BigValue() |> toBigFloat |> floor
      | _ -> raise ArithTypeMismatchException
    if targetLen <= 64<rt> then
      BitVectorSmall(adaptSmall targetLen (uint64 f), targetLen) :> BitVector
    else BitVectorBig(adaptBig targetLen (bigint f), targetLen) :> BitVector

  override this.FtoiCeil targetLen =
    let f =
      match len with
      | 80<rt> -> this.BigValue() |> toBigFloat |> ceil
      | _ -> raise ArithTypeMismatchException
    if targetLen <= 64<rt> then
      BitVectorSmall(adaptSmall targetLen (uint64 f), targetLen) :> BitVector
    else BitVectorBig(adaptBig targetLen (bigint f), targetLen) :> BitVector

  override this.FSqrt() =
    match len with
    | 80<rt> ->
      let r = this.BigValue() |> toBigFloat |> sqrt
      BitVectorBig(BitConverter.DoubleToInt64Bits r |> uint64 |> bigint, len)
      :> BitVector
    | _ -> raise ArithTypeMismatchException

  override this.FTan() =
    match len with
    | 80<rt> ->
      let r = this.BigValue() |> toBigFloat |> tan
      BitVectorBig(BitConverter.DoubleToInt64Bits r |> uint64 |> bigint, len)
      :> BitVector
    | _ -> raise ArithTypeMismatchException

  override this.FATan() =
    match len with
    | 80<rt> ->
      let r = this.BigValue() |> toBigFloat |> atan
      BitVectorBig(BitConverter.DoubleToInt64Bits r |> uint64 |> bigint, len)
      :> BitVector
    | _ -> raise ArithTypeMismatchException

  override this.FSin() =
    match len with
    | 80<rt> ->
      let r = this.BigValue() |> toBigFloat |> sin
      BitVectorBig(BitConverter.DoubleToInt64Bits r |> uint64 |> bigint, len)
      :> BitVector
    | _ -> raise ArithTypeMismatchException

  override this.FCos() =
    match len with
    | 80<rt> ->
      let r = this.BigValue() |> toBigFloat |> cos
      BitVectorBig(BitConverter.DoubleToInt64Bits r |> uint64 |> bigint, len)
      :> BitVector
    | _ -> raise ArithTypeMismatchException

  override this.FGt rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 80<rt> ->
      let v1 = this.BigValue() |> toBigFloat
      let v2 = rhs.BigValue() |> toBigFloat
      if v1 > v2 then BitVector.T else BitVector.F
    | _ -> raise ArithTypeMismatchException

  override this.FGe rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 80<rt> ->
      let v1 = this.BigValue() |> toBigFloat
      let v2 = rhs.BigValue() |> toBigFloat
      if v1 >= v2 then BitVector.T else BitVector.F
    | _ -> raise ArithTypeMismatchException

  override this.FLt rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 80<rt> ->
      let v1 = this.BigValue() |> toBigFloat
      let v2 = rhs.BigValue() |> toBigFloat
      if v1 < v2 then BitVector.T else BitVector.F
    | _ -> raise ArithTypeMismatchException

  override this.FLe rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 80<rt> ->
      let v1 = this.BigValue() |> toBigFloat
      let v2 = rhs.BigValue() |> toBigFloat
      if v1 <= v2 then BitVector.T else BitVector.F
    | _ -> raise ArithTypeMismatchException
