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

[<AutoOpen>]
module BitVectorConstants =
  /// BigInteger zero.
  let bigZero = 0I

  /// BigInteger one.
  let bigOne = 1I

/// A helper module for BitVector.
[<AutoOpen>]
module internal BitVectorHelper =

  exception ArithTypeMismatchException

  let nSizeErr t =
    failwithf "Invalid BitVector value for its type: %s" (t.ToString ())

  let inline adaptSmall (len: RegType) (n: uint64) =
    (UInt64.MaxValue >>> (64 - int len)) &&& n

  let inline adaptBig (len: RegType) (n: bigint) =
    ((bigOne <<< int len) - bigOne) &&& n

  let inline isSmallPositive (len: RegType) (n: uint64) =
    (n >>> (int len - 1)) &&& 1UL = 0UL

  let inline isBigPositive (len: RegType) (n: bigint) =
    (n >>> (int len - 1)) &&& bigOne = bigZero

  let inline neg (len: RegType) (n: bigint) = (bigOne <<< int len) - n

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
    let expAndSign = exp + 0x3C00UL ||| signOnly  |> bigint
    let significand = n &&& 0x000FFFFFFFFFFFFFUL
    let significand = significand ||| 0x0010000000000000UL <<< 11 |> bigint
    expAndSign <<< 64 ||| significand

/// BitVector is the fundamental data type for binary code, which is essentially
/// a bit vector. We want the size of a bit vector to be less than or equal to
/// 64 bits because bigint operation is slow, and most arithmetics on modern
/// architectures are in 64 bits any ways. For example, SIMD operations can also
/// be divided into a set of 64-bit operations.
///
/// N.B. Num becomes zero when the Length becomes greater than 64. We
/// intentionally do not sync Num and BigNum.
[<AbstractClass>]
type BitVector internal (len) =
  /// BitVector length.
  member __.Length with get(): RegType = len

  /// Return the uint64 representation of the bitvector value.
  abstract SmallValue: unit -> uint64

  /// Return the BigInteger representation of the bitvector value.
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
  abstract Extract: RegType -> int -> BitVector

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
  abstract Itof: RegType -> BitVector

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

  /// Is this bitvector representing a positive number?
  abstract IsPositive: unit -> bool

  /// Is this bitvector representing a negative number?
  abstract IsNegative: unit -> bool

  /// Return zero (0) of the given bit length.
  [<CompiledName("Zero")>]
  static member zero t =
    if t <= 64<rt> then BitVectorSmall (0UL, t) :> BitVector
    else BitVectorBig (bigZero, t) :> BitVector

  /// Return one (1) of the given bit length.
  [<CompiledName("One")>]
  static member one t =
    if t <= 64<rt> then BitVectorSmall (1UL, t) :> BitVector
    else BitVectorBig (bigOne, t) :> BitVector

  /// True value.
  static member T = BitVectorSmall (1UL, 1<rt>) :> BitVector

  /// False value.
  static member F = BitVectorSmall (0UL, 1<rt>) :> BitVector

  /// Return a smaller BitVector.
  [<CompiledName("Min")>]
  static member min (bv1: BitVector) bv2 =
    if bv1.Lt bv2 = BitVector.T then bv1 else bv2

  /// Return a larger BitVector.
  [<CompiledName("Max")>]
  static member max (bv1: BitVector) bv2 =
    if bv1.Gt bv2 = BitVector.T then bv1 else bv2

  /// Return a smaller BitVector (with signed comparison).
  [<CompiledName("SMin")>]
  static member smin (bv1: BitVector) bv2 =
    if bv1.SLt bv2 = BitVector.T then bv1 else bv2

  /// Return a larger BitVector (with signed comparison).
  [<CompiledName("SMax")>]
  static member smax (bv1: BitVector) bv2 =
    if bv1.SGt bv2 = BitVector.T then bv1 else bv2

  /// Get a BitVector from an unsigned integer.
  [<CompiledName("OfUInt64")>]
  static member inline ofUInt64 (i: uint64) typ =
#if DEBUG
    if typ <= 0<rt> then raise ArithTypeMismatchException else ()
#endif
    if typ <= 64<rt> then
      let mask = UInt64.MaxValue >>> (64 - int typ)
      BitVectorSmall (i &&& mask, typ) :> BitVector
    else BitVectorBig (bigint i, typ) :> BitVector

  /// Get a BitVector from a signed integer.
  [<CompiledName("OfInt64")>]
  static member inline ofInt64 (i: int64) typ =
#if DEBUG
    if typ <= 0<rt> then raise ArithTypeMismatchException else ()
#endif
    if typ <= 64<rt> then
      let mask = UInt64.MaxValue >>> (64 - int typ)
      BitVectorSmall (uint64 i &&& mask, typ) :> BitVector
    else
      if i < 0L then
        BitVectorBig ((bigOne <<< int typ) - (- i |> bigint), typ) :> BitVector
      else BitVectorBig (bigint i, typ) :> BitVector

  /// Get a BitVector from an unsigned integer.
  [<CompiledName("OfUInt32")>]
  static member inline ofUInt32 (i: uint32) typ =
    BitVector.ofUInt64 (uint64 i) typ

  /// Get a BitVector from a signed integer.
  [<CompiledName("OfInt32")>]
  static member inline ofInt32 (i: int32) typ =
    BitVector.ofInt64 (int64 i) typ

  /// Get a BitVector from a bigint. We assume that the given RegType (typ) is
  /// big enough to hold the given bigint. Otherwise, the resulting BitVector
  /// may contain an unexpected value.
  [<CompiledName("OfBInt")>]
  static member ofBInt (i: bigint) typ =
#if DEBUG
    if typ <= 0<rt> then nSizeErr typ else ()
#endif
    if typ <= 64<rt> then BitVector.ofUInt64 (uint64 i) typ
    else
      if i.Sign < 0 then
        BitVectorBig ((bigOne <<< int typ) + i, typ) :> BitVector
      else BitVectorBig (i, typ) :> BitVector

  /// Get a BitVector from a byte array (in little endian).
  [<CompiledName("OfArr")>]
  static member ofArr (arr: byte []) =
    match arr.Length with
    | 1 -> BitVectorSmall (uint64 arr[0], 8<rt>) :> BitVector
    | 2 ->
      let n = BitConverter.ToUInt16 (arr, 0) |> uint64
      BitVectorSmall (n, 16<rt>) :> BitVector
    | 3 ->
      let n = BitConverter.ToUInt32 (Array.append arr [| 0uy |], 0) |> uint64
      BitVectorSmall (n, 24<rt>) :> BitVector
    | 4 ->
      let n = BitConverter.ToUInt32 (arr, 0) |> uint64
      BitVectorSmall (n, 32<rt>) :> BitVector
    | 5 ->
      let arr = Array.append arr [| 0uy; 0uy; 0uy |]
      let n = BitConverter.ToUInt64 (arr, 0)
      BitVectorSmall (n, 40<rt>) :> BitVector
    | 6 ->
      let arr = Array.append arr [| 0uy; 0uy |]
      let n = BitConverter.ToUInt64 (arr, 0)
      BitVectorSmall (n, 48<rt>) :> BitVector
    | 7 ->
      let arr = Array.append arr [| 0uy |]
      let n = BitConverter.ToUInt64 (arr, 0)
      BitVectorSmall (n, 56<rt>) :> BitVector
    | 8 ->
      let n = BitConverter.ToUInt64 (arr, 0)
      BitVectorSmall (n, 64<rt>) :> BitVector
    | sz ->
      if sz > 8 then
        let arr = Array.append arr [| 0uy |]
        BitVectorBig (bigint arr, sz * 8<rt>) :> BitVector
      else nSizeErr (sz * 8)

  /// Get a uint64 value from a BitVector.
  [<CompiledName("ToUInt64")>]
  static member toUInt64 (bv: BitVector) =
    bv.SmallValue ()

  /// Get an int64 value from a BitVector.
  [<CompiledName("ToInt64")>]
  static member toInt64 (bv: BitVector) =
    bv.SmallValue () |> int64

  /// Get a uint32 value from a BitVector.
  [<CompiledName("ToUInt32")>]
  static member toUInt32 (bv: BitVector) =
    bv.SmallValue () |> uint32

  /// Get an int32 value from a BitVector.
  [<CompiledName("ToInt32")>]
  static member toInt32 (bv: BitVector) =
    bv.SmallValue () |> int32

  /// Get a numeric value (bigint) from a BitVector.
  [<CompiledName("GetValue")>]
  static member getValue (bv: BitVector) =
    bv.BigValue ()

  /// Get the type (length of the BitVector).
  [<CompiledName("GetType")>]
  static member getType (bv: BitVector) = bv.Length

  /// Get the string representation of a BitVector without appended type info.
  [<CompiledName("ValToString")>]
  static member valToString (n: BitVector) = n.ValToString ()

  /// Get the string representation of a BitVector.
  [<CompiledName("ToString")>]
  static member toString (n: BitVector) = n.ToString ()

  /// Bitvector of unsigned 8-bit maxvalue.
  static member maxUInt8 = BitVector.ofUInt64 0xFFUL 8<rt>

  /// Bitvector of unsigned 16-bit maxvalue.
  static member maxUInt16 = BitVector.ofUInt64 0xFFFFUL 16<rt>

  /// Bitvector of unsigned 32-bit maxvalue.
  static member maxUInt32 = BitVector.ofUInt64 0xFFFFFFFFUL 32<rt>

  /// Bitvector of unsigned 64-bit maxvalue.
  static member maxUInt64 = BitVector.ofUInt64 0xFFFFFFFFFFFFFFFFUL 64<rt>

  /// Check if the given BitVector is zero.
  [<CompiledName("IsZero")>]
  static member isZero (bv: BitVector) =
    bv.IsZero ()

  /// Check if the given BitVector is one.
  [<CompiledName("IsOne")>]
  static member isOne (bv: BitVector) =
    bv.IsOne ()

  /// Check if the given BitVector is "false".
  [<CompiledName("IsFalse")>]
  static member isFalse (bv: BitVector) =
    bv = BitVector.F

  /// Check if the given BitVector is "true".
  [<CompiledName("IsTrue")>]
  static member isTrue (bv: BitVector) =
    bv = BitVector.T

  /// Check if the given BitVector represents the specified number.
  [<CompiledName("IsNum")>]
  static member isNum (bv: BitVector) (n: uint64) =
    if bv.Length <= 64<rt> then bv.SmallValue () = n
    else bigint n = bv.BigValue ()

  /// BitVector representing a unsigned maximum integer for the given RegType.
  [<CompiledName("UnsignedMax")>]
  static member unsignedMax rt =
#if DEBUG
    if rt <= 0<rt> then nSizeErr rt else ()
#endif
    if rt <= 64<rt> then
      BitVectorSmall (UInt64.MaxValue >>> (64 - int rt), rt) :> BitVector
    else BitVectorBig ((bigOne <<< int rt) - bigOne, rt) :> BitVector

  /// BitVector representing a unsigned minimum integer for the given RegType.
  [<CompiledName("UnsignedMin")>]
  static member unsignedMin rt =
#if DEBUG
    if rt <= 0<rt> then nSizeErr rt else ()
#endif
    if rt <= 64<rt> then BitVectorSmall (0UL, rt) :> BitVector
    else BitVectorBig (bigZero, rt) :> BitVector

  /// BitVector representing a signed maximum integer for the given RegType.
  [<CompiledName("SignedMax")>]
  static member signedMax rt =
#if DEBUG
    if rt <= 0<rt> then nSizeErr rt else ()
#endif
    if rt <= 64<rt> then
      BitVectorSmall (UInt64.MaxValue >>> (65 - int rt), rt) :> BitVector
    else BitVectorBig ((bigOne <<< (int rt - 1)) - bigOne, rt) :> BitVector

  /// BitVector representing a signed minimum integer for the given RegType.
  [<CompiledName("SignedMin")>]
  static member signedMin rt =
#if DEBUG
    if rt <= 0<rt> then nSizeErr rt else ()
#endif
    if rt <= 64<rt> then BitVectorSmall (1UL <<< (int rt - 1), rt) :> BitVector
    else BitVectorBig (bigOne <<< (int rt - 1), rt) :> BitVector

  /// Does the bitvector represent an unsigned max value?
  [<CompiledName("IsUnsignedMax")>]
  static member isUnsignedMax (bv: BitVector) =
    BitVector.unsignedMax bv.Length = bv

  /// Does the bitvector represent a signed max value?
  [<CompiledName("IsSignedMax")>]
  static member isSignedMax (bv: BitVector) =
    BitVector.signedMax bv.Length = bv

  /// Does the bitvector represent a signed min value?
  [<CompiledName("IsSignedMin")>]
  static member isSignedMin (bv: BitVector) =
    BitVector.signedMin bv.Length = bv

  /// Is the bitvector positive?
  [<CompiledName("IsPositive")>]
  static member isPositive (bv: BitVector) = bv.IsPositive ()

  /// Is the bitvector negative?
  [<CompiledName("IsNegative")>]
  static member isNegative (bv: BitVector) = bv.IsNegative ()

  /// BitVector addition.
  [<CompiledName("Add")>]
  static member inline add (v1: BitVector) (v2: BitVector) = v1.Add v2

  /// BitVector subtraction.
  [<CompiledName("Sub")>]
  static member inline sub (v1: BitVector) (v2: BitVector) = v1.Sub v2

  /// BitVector multiplication.
  [<CompiledName("Mul")>]
  static member inline mul (v1: BitVector) (v2: BitVector) = v1.Mul v2

  /// BitVector signed division.
  [<CompiledName("SDiv")>]
  static member inline sdiv (v1: BitVector) (v2: BitVector) = v1.SDiv v2

  /// BitVector unsigned division.
  [<CompiledName("Div")>]
  static member inline div (v1: BitVector) (v2: BitVector) = v1.Div v2

  /// BitVector signed modulo.
  [<CompiledName("SMod")>]
  static member inline smodulo (v1: BitVector) (v2: BitVector) = v1.SMod v2

  /// BitVector unsigned modulo.
  [<CompiledName("Mod")>]
  static member inline modulo (v1: BitVector) (v2: BitVector) = v1.Mod v2

  /// BitVector bitwise AND.
  [<CompiledName("And")>]
  static member inline band (v1: BitVector) (v2: BitVector) = v1.And v2

  /// BitVector bitwise OR.
  [<CompiledName("Or")>]
  static member inline bor (v1: BitVector) (v2: BitVector) = v1.Or v2

  /// BitVector bitwise XOR.
  [<CompiledName("Xor")>]
  static member inline bxor (v1: BitVector) (v2: BitVector) = v1.Xor v2

  /// BitVector logical shift-left.
  [<CompiledName("Shl")>]
  static member inline shl (v1: BitVector) (v2: BitVector) = v1.Shl v2

  /// BitVector logical shift-right.
  [<CompiledName("Shr")>]
  static member inline shr (v1: BitVector) (v2: BitVector) = v1.Shr v2

  /// BitVector arithmetic shift-right.
  [<CompiledName("Sar")>]
  static member inline sar (v1: BitVector) (v2: BitVector) = v1.Sar v2

  /// BitVector bitwise NOT.
  [<CompiledName("Not")>]
  static member inline bnot (v1: BitVector) = v1.Not ()

  /// BitVector negation.
  [<CompiledName("Neg")>]
  static member inline neg (v1: BitVector) = v1.Neg ()

  /// BitVector type cast.
  [<CompiledName("Cast")>]
  static member inline cast (v1: BitVector) targetLen = v1.Cast targetLen

  /// BitVector extraction.
  [<CompiledName("Extract")>]
  static member inline extract (v1: BitVector) rt pos = v1.Extract rt pos

  /// BitVector concatenation.
  [<CompiledName("Concat")>]
  static member inline concat (v1: BitVector) (v2: BitVector) = v1.Concat v2

  /// BitVector sign-extension.
  [<CompiledName("SExt")>]
  static member inline sext (v1: BitVector) targetLen = v1.SExt targetLen

  /// BitVector zero-extension.
  [<CompiledName("ZExt")>]
  static member inline zext (v1: BitVector) targetLen = v1.ZExt targetLen

  /// BitVector equal.
  [<CompiledName("Eq")>]
  static member inline eq (v1: BitVector) (v2: BitVector) = v1.Eq v2

  /// BitVector not equal.
  [<CompiledName("Neq")>]
  static member inline neq (v1: BitVector) (v2: BitVector) = v1.Neq v2

  /// BitVector greater than.
  [<CompiledName("Gt")>]
  static member inline gt (v1: BitVector) (v2: BitVector) = v1.Gt v2

  /// BitVector greater than or equal.
  [<CompiledName("Ge")>]
  static member inline ge (v1: BitVector) (v2: BitVector) = v1.Ge v2

  /// BitVector signed greater than.
  [<CompiledName("SGt")>]
  static member inline sgt (v1: BitVector) (v2: BitVector) = v1.SGt v2

  /// BitVector signed greater than or equal.
  [<CompiledName("SGe")>]
  static member inline sge (v1: BitVector) (v2: BitVector) = v1.SGe v2

  /// BitVector less than.
  [<CompiledName("Lt")>]
  static member inline lt (v1: BitVector) (v2: BitVector) = v1.Lt v2

  /// BitVector less than or equal.
  [<CompiledName("Le")>]
  static member inline le (v1: BitVector) (v2: BitVector) = v1.Le v2

  /// BitVector signed less than.
  [<CompiledName("SLt")>]
  static member inline slt (v1: BitVector) (v2: BitVector) = v1.SLt v2

  /// BitVector signed less than or equal.
  [<CompiledName("SLe")>]
  static member inline sle (v1: BitVector) (v2: BitVector) = v1.SLe v2

  /// BitVector absolute value.
  [<CompiledName("Abs")>]
  static member inline abs (v1: BitVector) = v1.Abs ()

  /// BitVector floating point addition.
  [<CompiledName("FAdd")>]
  static member inline fadd (v1: BitVector) (v2: BitVector) = v1.FAdd v2

  /// BitVector floating point subtraction.
  [<CompiledName("FSub")>]
  static member inline fsub (v1: BitVector) (v2: BitVector) = v1.FSub v2

  /// BitVector floating point multiplication.
  [<CompiledName("FMul")>]
  static member inline fmul (v1: BitVector) (v2: BitVector) = v1.FMul v2

  /// BitVector floating point division.
  [<CompiledName("FDiv")>]
  static member inline fdiv (v1: BitVector) (v2: BitVector) = v1.FDiv v2

  /// BitVector floating point logarithm.
  [<CompiledName("FLog")>]
  static member inline flog (v1: BitVector) (v2: BitVector) = v1.FLog v2

  /// BitVector floating point power.
  [<CompiledName("FPow")>]
  static member inline fpow (v1: BitVector) (v2: BitVector) = v1.FPow v2

  /// BitVector floating point casting.
  [<CompiledName("FCast")>]
  static member inline fcast (v1: BitVector) rt = v1.FCast rt

  /// BitVector integer to float conversion.
  [<CompiledName("Itof")>]
  static member inline itof (v1: BitVector) rt = v1.Itof rt

  /// BitVector float to integer conversion with truncation.
  [<CompiledName("FToITrunc")>]
  static member inline ftoitrunc (v1: BitVector) rt = v1.FtoiTrunc rt

  /// BitVector float to integer conversion with round.
  [<CompiledName("FToIRound")>]
  static member inline ftoiround (v1: BitVector) rt = v1.FtoiRound rt

  /// BitVector float to integer conversion with flooring.
  [<CompiledName("FToIFloor")>]
  static member inline ftoifloor (v1: BitVector) rt = v1.FtoiFloor rt

  /// BitVector float to integer conversion with ceiling.
  [<CompiledName("FToICeil")>]
  static member inline ftoiceil (v1: BitVector) rt = v1.FtoiCeil rt

  /// BitVector square root.
  [<CompiledName("FSqrt")>]
  static member inline fsqrt (v1: BitVector) = v1.FSqrt ()

  /// BitVector tangent.
  [<CompiledName("FTan")>]
  static member inline ftan (v1: BitVector) = v1.FTan ()

  /// BitVector sine.
  [<CompiledName("FSin")>]
  static member inline fsin (v1: BitVector) = v1.FSin ()

  /// BitVector cosine.
  [<CompiledName("FCos")>]
  static member inline fcos (v1: BitVector) = v1.FCos ()

  /// BitVector arc tangent.
  [<CompiledName("FATan")>]
  static member inline fatan (v1: BitVector) = v1.FATan ()

  /// BitVector floating point greater than.
  [<CompiledName("FGt")>]
  static member inline fgt (v1: BitVector) (v2: BitVector) = v1.FGt v2

  /// BitVector floating point greater than or equal.
  [<CompiledName("FGe")>]
  static member inline fge (v1: BitVector) (v2: BitVector) = v1.FGe v2

  /// BitVector floating point less than.
  [<CompiledName("FLt")>]
  static member inline flt (v1: BitVector) (v2: BitVector) = v1.FLt v2

  /// BitVector floating point less than or equal.
  [<CompiledName("FLe")>]
  static member inline fle (v1: BitVector) (v2: BitVector) = v1.FLe v2

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
  static member inline (~~~) (v1: BitVector) = v1.Not ()

  /// BitVector negation.
  static member inline (~-) (v1: BitVector) = v1.Neg ()

/// This is a BitVector with its length less than or equal to 64<rt>. This is
/// preferred because all the operations will be much faster than BitVectorBig.
and BitVectorSmall (n, len) =
  inherit BitVector(len)

#if DEBUG
  do if len > 64<rt> then raise ArithTypeMismatchException else ()
#endif

  new (n: int64, len) = BitVectorSmall (uint64 n, len)
  new (n: int32, len) = BitVectorSmall (uint64 n, len)
  new (n: int16, len) = BitVectorSmall (uint64 n, len)
  new (n: int8, len) = BitVectorSmall (uint64 n, len)
  new (n: uint32, len) = BitVectorSmall (uint64 n, len)
  new (n: uint16, len) = BitVectorSmall (uint64 n, len)
  new (n: uint8, len) = BitVectorSmall (uint64 n, len)

  member __.Value with get(): uint64 = n

  override __.ValToString () = String.u64ToHex n

  override __.Equals obj =
    match obj with
    | :? BitVectorSmall as obj -> len = obj.Length && n = obj.Value
    | _ -> false

  override __.ApproxEq (rhs: BitVector) =
#if DEBUG
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
#endif
    let shifter = BitVector.ofInt32 1 len
    let v1 = __.Shr shifter
    let v2 = rhs.Shr shifter
    v1.Eq v2

  override __.IsPositive () = isSmallPositive len n

  override __.IsNegative () = not <| isSmallPositive len n

  override __.GetHashCode () =
    HashCode.Combine<uint64, RegType> (n, len)

  override __.ToString () =
    __.ValToString () + ":" + RegType.toString len

  override __.SmallValue () = n

  override __.BigValue () = bigint n

  override __.IsZero () = n = 0UL

  override __.IsOne () = n = 1UL

  override __.Add (rhs: uint64) =
    BitVectorSmall (n + rhs |> adaptSmall len, len) :> BitVector

  override __.Add (rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorSmall (n + rhs.SmallValue () |> adaptSmall len, len) :> BitVector

  override __.Sub (rhs: uint64) =
    BitVectorSmall (n - rhs |> adaptSmall len, len) :> BitVector

  override __.Sub (rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorSmall (n - rhs.SmallValue () |> adaptSmall len, len) :> BitVector

  override __.Mul (rhs: uint64) =
    BitVectorSmall (n * rhs |> adaptSmall len, len) :> BitVector

  override __.Mul (rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorSmall (n * rhs.SmallValue () |> adaptSmall len, len) :> BitVector

  override __.SDiv (rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    let v1 = n
    let v2 = rhs.SmallValue ()
    let isPos1 = isSmallPositive len v1
    let isPos2 = isSmallPositive len v2
    let v1 = int64 (if isPos1 then v1 else ((~~~ v1) + 1UL) |> adaptSmall len)
    let v2 = int64 (if isPos2 then v2 else ((~~~ v2) + 1UL) |> adaptSmall len)
    let result = if isPos1 = isPos2 then v1 / v2 else - (v1 / v2)
    BitVectorSmall (result |> uint64 |> adaptSmall len, len) :> BitVector

  override __.Div (rhs: uint64) =
    BitVectorSmall (n / rhs |> adaptSmall len, len) :> BitVector

  override __.Div (rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorSmall (n / rhs.SmallValue () |> adaptSmall len, len) :> BitVector

  override __.SMod (rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    let v1 = n
    let v2 = rhs.SmallValue ()
    let isPos1 = isSmallPositive len v1
    let isPos2 = isSmallPositive len v2
    let v1 = int64 (if isPos1 then v1 else ((~~~ v1) + 1UL) |> adaptSmall len)
    let v2 = int64 (if isPos2 then v2 else ((~~~ v2) + 1UL) |> adaptSmall len)
    let result = if isPos1 then v1 % v2 else - (v1 % v2)
    BitVectorSmall (result |> uint64 |> adaptSmall len, len) :> BitVector

  override __.Mod (rhs: uint64) =
    BitVectorSmall (n % rhs |> adaptSmall len, len) :> BitVector

  override __.Mod (rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorSmall (n % rhs.SmallValue () |> adaptSmall len, len) :> BitVector

  override __.And (rhs: uint64) =
    BitVectorSmall (n &&& rhs |> adaptSmall len, len) :> BitVector

  override __.And (rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorSmall (n &&& rhs.SmallValue () |> adaptSmall len, len)
    :> BitVector

  override __.Or (rhs: uint64) =
    BitVectorSmall (n ||| rhs |> adaptSmall len, len) :> BitVector

  override __.Or (rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorSmall (n ||| rhs.SmallValue () |> adaptSmall len, len)
    :> BitVector

  override __.Xor (rhs: uint64) =
    BitVectorSmall (n ^^^ rhs |> adaptSmall len, len) :> BitVector

  override __.Xor (rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorSmall (n ^^^ rhs.SmallValue () |> adaptSmall len, len)
    :> BitVector

  override __.Shl (rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    let v1 = n
    let v2 = rhs.SmallValue ()
    if v2 >= 64UL then BitVectorSmall (0UL, len) :> BitVector
    else BitVectorSmall (adaptSmall len (v1 <<< int v2), len) :> BitVector

  override __.Shr (rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    let v1 = n
    let v2 = rhs.SmallValue () |> uint16 |> int
    (* In .NET, 1UL >>> 63 = 0, but 1UL >>> 64 = 1 *)
    BitVectorSmall (v1 >>> (min v2 63), len) :> BitVector

  override __.Sar (rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    let v1 = n
    let v2 = rhs.SmallValue () |> uint16 |> int
    (* In .NET, 1UL >>> 63 = 0, but 1UL >>> 64 = 1 *)
    let res = v1 >>> (min v2 63)
    if len = 1<rt> then
      if v2 = 0 then __ :> BitVector else BitVector.zero len
    elif isSmallPositive len v1 then BitVectorSmall (res, len) :> BitVector
    else
      let pad =
        (UInt64.MaxValue >>> (64 - int len))
        - (if int len <= v2 then 0UL
           else UInt64.MaxValue >>> (64 - (int len - v2)))
      BitVectorSmall (res ||| pad, len) :> BitVector

  override __.Not () =
    BitVectorSmall ((~~~ n) |> adaptSmall len, len) :> BitVector

  override __.Neg () =
    BitVectorSmall (((~~~ n) + 1UL) |> adaptSmall len, len) :> BitVector

  override __.Cast targetLen =
    if targetLen <= 64<rt> then
      BitVectorSmall (adaptSmall targetLen n, targetLen) :> BitVector
    else
      BitVectorBig (adaptBig targetLen (__.BigValue ()), targetLen) :> BitVector

  override __.Extract targetLen pos =
    if len < targetLen then raise ArithTypeMismatchException
    elif len = targetLen then __ :> BitVector
    else
      BitVectorSmall (adaptSmall targetLen (n >>> pos), targetLen) :> BitVector

  override __.Concat (rhs: BitVector) =
    let rLen = rhs.Length
    let targetLen = len + rLen
    if targetLen <= 64<rt> then
      BitVectorSmall ((n <<< int rLen) + rhs.SmallValue (), targetLen)
      :> BitVector
    else
      let v1 = __.BigValue ()
      let v2 = rhs.BigValue ()
      BitVectorBig ((v1 <<< int rLen) + v2, targetLen) :> BitVector

  override __.SExt targetLen =
    if targetLen < len then raise ArithTypeMismatchException
    elif targetLen = len then __ :> BitVector
    elif targetLen <= 64<rt> then
      if isSmallPositive len n then BitVectorSmall (n, targetLen) :> BitVector
      else
        let mask =
          (UInt64.MaxValue >>> (64 - int targetLen))
          - (UInt64.MaxValue >>> (64 - int len))
        BitVectorSmall (n + mask, targetLen) :> BitVector
    else
      let n' = adaptBig targetLen (__.BigValue ())
      if isSmallPositive len n then BitVectorBig (n', targetLen) :> BitVector
      else
        let mask = (bigOne <<< int targetLen) - (bigOne <<< int len)
        BitVectorBig (n' + mask, targetLen) :> BitVector

  override __.ZExt targetLen =
    if targetLen < len then raise ArithTypeMismatchException
    elif targetLen = len then __ :> BitVector
    elif targetLen <= 64<rt> then
      BitVectorSmall (adaptSmall targetLen n, targetLen) :> BitVector
    else
      BitVectorBig (adaptBig targetLen (__.BigValue ()), targetLen) :> BitVector

  override __.Eq rhs =
    if len = rhs.Length && n = rhs.SmallValue () then BitVector.T
    else BitVector.F

  override __.Neq rhs =
    if len = rhs.Length && n = rhs.SmallValue () then BitVector.F
    else BitVector.T

  override __.Gt rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException
    elif n > rhs.SmallValue () then BitVector.T
    else BitVector.F

  override __.Ge rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException
    elif n >= rhs.SmallValue () then BitVector.T
    else BitVector.F

  override __.SGt rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException
    else
      let v1 = n
      let v2 = rhs.SmallValue ()
      let isPos1 = isSmallPositive len v1
      let isPos2 = isSmallPositive len v2
      match isPos1, isPos2 with
      | true, false -> BitVector.T
      | false, true -> BitVector.F
      | _ -> if v1 > v2 then BitVector.T else BitVector.F

  override __.SGe rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException
    else
      let v1 = n
      let v2 = rhs.SmallValue ()
      let isPos1 = isSmallPositive len v1
      let isPos2 = isSmallPositive len v2
      match isPos1, isPos2 with
      | true, false -> BitVector.T
      | false, true -> BitVector.F
      | _ -> if v1 >= v2 then BitVector.T else BitVector.F

  override __.Lt rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException
    elif n < rhs.SmallValue () then BitVector.T
    else BitVector.F

  override __.Le rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException
    elif n <= rhs.SmallValue () then BitVector.T
    else BitVector.F

  override __.SLt rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException
    else
      let v1 = n
      let v2 = rhs.SmallValue ()
      let isPos1 = isSmallPositive len v1
      let isPos2 = isSmallPositive len v2
      match isPos1, isPos2 with
      | true, false -> BitVector.F
      | false, true -> BitVector.T
      | _ -> if v1 < v2 then BitVector.T else BitVector.F

  override __.SLe rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException
    else
      let v1 = n
      let v2 = rhs.SmallValue ()
      let isPos1 = isSmallPositive len v1
      let isPos2 = isSmallPositive len v2
      match isPos1, isPos2 with
      | true, false -> BitVector.F
      | false, true -> BitVector.T
      | _ -> if v1 <= v2 then BitVector.T else BitVector.F

  override __.Abs () =
    if isSmallPositive len n then __ :> BitVector
    else __.Neg ()

  override __.FAdd rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 32<rt> ->
      let v1 = __.SmallValue () |> toFloat32
      let v2 = rhs.SmallValue () |> toFloat32
      let bs = v1 + v2 |> BitConverter.GetBytes
      BitVectorSmall (BitConverter.ToInt32 (bs, 0) |> uint64, len) :> BitVector
    | 64<rt> ->
      let v1 = __.SmallValue () |> toFloat64
      let v2 = rhs.SmallValue () |> toFloat64
      let r = v1 + v2 |> BitConverter.DoubleToInt64Bits |> uint64
      BitVectorSmall (r, len) :> BitVector
    | _ -> raise ArithTypeMismatchException

  override __.FSub rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 32<rt> ->
      let v1 = __.SmallValue () |> toFloat32
      let v2 = rhs.SmallValue () |> toFloat32
      let bs = v1 - v2 |> BitConverter.GetBytes
      BitVectorSmall (BitConverter.ToInt32 (bs, 0) |> uint64, len) :> BitVector
    | 64<rt> ->
      let v1 = __.SmallValue () |> toFloat64
      let v2 = rhs.SmallValue () |> toFloat64
      let r = v1 - v2 |> BitConverter.DoubleToInt64Bits |> uint64
      BitVectorSmall (r, len) :> BitVector
    | _ -> raise ArithTypeMismatchException

  override __.FMul rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 32<rt> ->
      let v1 = __.SmallValue () |> toFloat32
      let v2 = rhs.SmallValue () |> toFloat32
      let bs = v1 * v2 |> BitConverter.GetBytes
      BitVectorSmall (BitConverter.ToInt32 (bs, 0) |> uint64, len) :> BitVector
    | 64<rt> ->
      let v1 = __.SmallValue () |> toFloat64
      let v2 = rhs.SmallValue () |> toFloat64
      let r = v1 * v2 |> BitConverter.DoubleToInt64Bits |> uint64
      BitVectorSmall (r, len) :> BitVector
    | _ -> raise ArithTypeMismatchException

  override __.FDiv rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 32<rt> ->
      let v1 = __.SmallValue () |> toFloat32
      let v2 = rhs.SmallValue () |> toFloat32
      let bs = v1 / v2 |> BitConverter.GetBytes
      BitVectorSmall (BitConverter.ToInt32 (bs, 0) |> uint64, len) :> BitVector
    | 64<rt> ->
      let v1 = __.SmallValue () |> toFloat64
      let v2 = rhs.SmallValue () |> toFloat64
      let r = v1 / v2 |> BitConverter.DoubleToInt64Bits |> uint64
      BitVectorSmall (r, len) :> BitVector
    | _ -> raise ArithTypeMismatchException

  override __.FLog rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 32<rt> ->
      let v1 = __.SmallValue () |> toFloat32
      let v2 = rhs.SmallValue () |> toFloat32
      let bs = MathF.Log (v2, v1) |> BitConverter.GetBytes
      BitVectorSmall (BitConverter.ToInt32 (bs, 0) |> uint64, len) :> BitVector
    | 64<rt> ->
      let v1 = __.SmallValue () |> toFloat64
      let v2 = rhs.SmallValue () |> toFloat64
      let r = Math.Log (v2, v1) |> BitConverter.DoubleToInt64Bits |> uint64
      BitVectorSmall (r, len) :> BitVector
    | _ -> raise ArithTypeMismatchException

  override __.FPow rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 32<rt> ->
      let v1 = __.SmallValue () |> toFloat32
      let v2 = rhs.SmallValue () |> toFloat32
      let bs = MathF.Pow (v1, v2) |> BitConverter.GetBytes
      BitVectorSmall (BitConverter.ToInt32 (bs, 0) |> uint64, len) :> BitVector
    | 64<rt> ->
      let v1 = __.SmallValue () |> toFloat64
      let v2 = rhs.SmallValue () |> toFloat64
      let r = Math.Pow (v1, v2) |> BitConverter.DoubleToInt64Bits |> uint64
      BitVectorSmall (r, len) :> BitVector
    | _ -> raise ArithTypeMismatchException

  override __.FCast targetLen =
    match len, targetLen with
    | 32<rt>, 32<rt> -> __ :> BitVector
    | 32<rt>, 64<rt> ->
      let f32 = __.SmallValue () |> toFloat32 |> float
      let u64 = BitConverter.DoubleToInt64Bits f32 |> uint64
      BitVectorSmall (u64, targetLen) :> BitVector
    | 32<rt>, 80<rt> ->
      let f32 = __.SmallValue () |> toFloat32 |> float
      let u64 = BitConverter.DoubleToInt64Bits f32 |> uint64
      BitVectorBig (encodeBigFloat u64, targetLen) :> BitVector
    | 64<rt>, 32<rt> ->
      let f64 = __.SmallValue () |> toFloat64
      let u64 = BitConverter.SingleToInt32Bits (float32 f64) |> uint64
      BitVectorSmall (u64, targetLen) :> BitVector
    | 64<rt>, 64<rt> -> __ :> BitVector
    | 64<rt>, 80<rt> ->
      BitVectorBig (__.SmallValue () |> encodeBigFloat, targetLen) :> BitVector
    | _ -> raise ArithTypeMismatchException

  override __.Itof targetLen =
    let signedInt = n |> int64
    match targetLen with
    | 32<rt> ->
      let u64 = BitConverter.SingleToInt32Bits (float32 signedInt) |> uint64
      BitVectorSmall (u64, targetLen) :> BitVector
    | 64<rt> ->
      let u64 = BitConverter.DoubleToInt64Bits (float signedInt) |> uint64
      BitVectorSmall (u64, targetLen) :> BitVector
    | 80<rt> ->
      let u64 = BitConverter.DoubleToInt64Bits (float signedInt) |> uint64
      BitVectorBig (bigint u64, targetLen) :> BitVector
    | _ -> raise ArithTypeMismatchException

  override __.FtoiTrunc targetLen =
    let f =
      match len with
      | 32<rt> -> __.SmallValue () |> toFloat32 |> float |> truncate
      | 64<rt> -> __.SmallValue () |> toFloat64 |> truncate
      | _ -> raise ArithTypeMismatchException
    if targetLen <= 64<rt> then
      BitVectorSmall (adaptSmall targetLen (uint64 f), targetLen) :> BitVector
    else BitVectorBig (adaptBig targetLen (bigint f), targetLen) :> BitVector

  override __.FtoiRound targetLen =
    let f =
      match len with
      | 32<rt> -> __.SmallValue () |> toFloat32 |> float |> round
      | 64<rt> -> __.SmallValue () |> toFloat64 |> round
      | _ -> raise ArithTypeMismatchException
    if targetLen <= 64<rt> then
      BitVectorSmall (adaptSmall targetLen (uint64 f), targetLen) :> BitVector
    else BitVectorBig (adaptBig targetLen (bigint f), targetLen) :> BitVector

  override __.FtoiFloor targetLen =
    let f =
      match len with
      | 32<rt> -> __.SmallValue () |> toFloat32 |> float |> floor
      | 64<rt> -> __.SmallValue () |> toFloat64 |> floor
      | _ -> raise ArithTypeMismatchException
    if targetLen <= 64<rt> then
      BitVectorSmall (adaptSmall targetLen (uint64 f), targetLen) :> BitVector
    else BitVectorBig (adaptBig targetLen (bigint f), targetLen) :> BitVector

  override __.FtoiCeil targetLen =
    let f =
      match len with
      | 32<rt> -> __.SmallValue () |> toFloat32 |> float |> ceil
      | 64<rt> -> __.SmallValue () |> toFloat64 |> ceil
      | _ -> raise ArithTypeMismatchException
    if targetLen <= 64<rt> then
      BitVectorSmall (adaptSmall targetLen (uint64 f), targetLen) :> BitVector
    else BitVectorBig (adaptBig targetLen (bigint f), targetLen) :> BitVector

  override __.FSqrt () =
    match len with
    | 32<rt> ->
      let r = __.SmallValue () |> toFloat32 |> sqrt
      BitVectorSmall (BitConverter.SingleToInt32Bits r |> uint64, len)
      :> BitVector
    | 64<rt> ->
      let r = __.SmallValue () |> toFloat64 |> sqrt
      BitVectorSmall (BitConverter.DoubleToInt64Bits r |> uint64, len)
      :> BitVector
    | _ -> raise ArithTypeMismatchException

  override __.FTan () =
    match len with
    | 32<rt> ->
      let r = __.SmallValue () |> toFloat32 |> tan
      BitVectorSmall (BitConverter.SingleToInt32Bits r |> uint64, len)
      :> BitVector
    | 64<rt> ->
      let r = __.SmallValue () |> toFloat64 |> tan
      BitVectorSmall (BitConverter.DoubleToInt64Bits r |> uint64, len)
      :> BitVector
    | _ -> raise ArithTypeMismatchException

  override __.FATan () =
    match len with
    | 32<rt> ->
      let r = __.SmallValue () |> toFloat32 |> atan
      BitVectorSmall (BitConverter.SingleToInt32Bits r |> uint64, len)
      :> BitVector
    | 64<rt> ->
      let r = __.SmallValue () |> toFloat64 |> atan
      BitVectorSmall (BitConverter.DoubleToInt64Bits r |> uint64, len)
      :> BitVector
    | _ -> raise ArithTypeMismatchException

  override __.FSin () =
    match len with
    | 32<rt> ->
      let r = __.SmallValue () |> toFloat32 |> sin
      BitVectorSmall (BitConverter.SingleToInt32Bits r |> uint64, len)
      :> BitVector
    | 64<rt> ->
      let r = __.SmallValue () |> toFloat64 |> sin
      BitVectorSmall (BitConverter.DoubleToInt64Bits r |> uint64, len)
      :> BitVector
    | _ -> raise ArithTypeMismatchException

  override __.FCos () =
    match len with
    | 32<rt> ->
      let r = __.SmallValue () |> toFloat32 |> cos
      BitVectorSmall (BitConverter.SingleToInt32Bits r |> uint64, len)
      :> BitVector
    | 64<rt> ->
      let r = __.SmallValue () |> toFloat64 |> cos
      BitVectorSmall (BitConverter.DoubleToInt64Bits r |> uint64, len)
      :> BitVector
    | _ -> raise ArithTypeMismatchException

  override __.FGt rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 32<rt> ->
      let v1 = __.SmallValue () |> toFloat32
      let v2 = rhs.SmallValue () |> toFloat32
      if v1 > v2 then BitVector.T else BitVector.F
    | 64<rt> ->
      let v1 = __.SmallValue () |> toFloat64
      let v2 = rhs.SmallValue () |> toFloat64
      if v1 > v2 then BitVector.T else BitVector.F
    | _ -> raise ArithTypeMismatchException

  override __.FGe rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 32<rt> ->
      let v1 = __.SmallValue () |> toFloat32
      let v2 = rhs.SmallValue () |> toFloat32
      if v1 >= v2 then BitVector.T else BitVector.F
    | 64<rt> ->
      let v1 = __.SmallValue () |> toFloat64
      let v2 = rhs.SmallValue () |> toFloat64
      if v1 >= v2 then BitVector.T else BitVector.F
    | _ -> raise ArithTypeMismatchException

  override __.FLt rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 32<rt> ->
      let v1 = __.SmallValue () |> toFloat32
      let v2 = rhs.SmallValue () |> toFloat32
      if v1 < v2 then BitVector.T else BitVector.F
    | 64<rt> ->
      let v1 = __.SmallValue () |> toFloat64
      let v2 = rhs.SmallValue () |> toFloat64
      if v1 < v2 then BitVector.T else BitVector.F
    | _ -> raise ArithTypeMismatchException

  override __.FLe rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 32<rt> ->
      let v1 = __.SmallValue () |> toFloat32
      let v2 = rhs.SmallValue () |> toFloat32
      if v1 <= v2 then BitVector.T else BitVector.F
    | 64<rt> ->
      let v1 = __.SmallValue () |> toFloat64
      let v2 = rhs.SmallValue () |> toFloat64
      if v1 <= v2 then BitVector.T else BitVector.F
    | _ -> raise ArithTypeMismatchException

/// This is a BitVector with its length less than or equal to 64<rt>. This is
/// preferred because all the operations will be much faster than BitVectorBig.
and BitVectorBig (n, len) =
  inherit BitVector(len)

#if DEBUG
  do if len <= 64<rt> then raise ArithTypeMismatchException else ()
#endif

  member __.Value with get(): bigint = n

  override __.ValToString () =
    if n = bigZero then "0x0"
    else "0x" + n.ToString("x").TrimStart('0')

  override __.Equals obj =
    match obj with
    | :? BitVectorBig as obj -> len = obj.Length && n = obj.Value
    | _ -> false

  override __.ApproxEq (rhs: BitVector) =
#if DEBUG
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
#endif
    if len = 80<rt> then
      let shifter = BitVector.ofInt32 12 80<rt>
      let v1 = __.Shr shifter
      let v2 = rhs.Shr shifter
      v1.Eq v2
    else raise ArithTypeMismatchException

  override __.IsPositive () = isBigPositive len n

  override __.IsNegative () = not <| isBigPositive len n

  override __.GetHashCode () =
    HashCode.Combine<bigint, RegType> (n, len)

  override __.ToString () =
    __.ValToString () + ":" + RegType.toString len

  override __.SmallValue () =
#if DEBUG
    if n > bigint 0xFFFFFFFFFFFFFFFFUL then nSizeErr len else ()
#endif
    uint64 n

  override __.BigValue () = n

  override __.IsZero () = n = 0I

  override __.IsOne () = n = 1I

  override __.Add (rhs: uint64) =
    BitVectorBig (n + bigint rhs, len) :> BitVector

  override __.Add (rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorBig (n + rhs.BigValue () |> adaptBig len, len) :> BitVector

  override __.Sub (rhs: uint64) =
    BitVectorBig (n - bigint rhs, len) :> BitVector

  override __.Sub (rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorBig (n - rhs.BigValue () |> adaptBig len, len) :> BitVector

  override __.Mul (rhs: uint64) =
    BitVectorBig (n * bigint rhs, len) :> BitVector

  override __.Mul (rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorBig (n * rhs.BigValue () |> adaptBig len, len) :> BitVector

  override __.SDiv (rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    let v1 = n
    let v2 = rhs.BigValue ()
    let isPos1 = isBigPositive len v1
    let isPos2 = isBigPositive rhs.Length v2
    let v1 = if isPos1 then v1 else neg len v1
    let v2 = if isPos2 then v2 else neg len v2
    let result = if isPos1 = isPos2 then v1 / v2 else neg len (v1 / v2)
    BitVectorBig (result |> adaptBig len, len) :> BitVector

  override __.Div (rhs: uint64) =
    BitVectorBig (n / bigint rhs, len) :> BitVector

  override __.Div (rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorBig (n / rhs.BigValue () |> adaptBig len, len) :> BitVector

  override __.SMod (rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    let v1 = n
    let v2 = rhs.BigValue ()
    let isPos1 = isBigPositive len v1
    let isPos2 = isBigPositive rhs.Length v2
    let v1 = if isPos1 then v1 else neg len v1
    let v2 = if isPos2 then v2 else neg len v2
    let result = if isPos1 then v1 % v2 else neg len (v1 % v2)
    BitVectorBig (result |> adaptBig len, len) :> BitVector

  override __.Mod (rhs: uint64) =
    BitVectorBig (n % bigint rhs, len) :> BitVector

  override __.Mod (rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorBig (n % rhs.BigValue () |> adaptBig len, len) :> BitVector

  override __.And (rhs: uint64) =
    BitVectorBig (n &&& bigint rhs, len) :> BitVector

  override __.And (rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorBig (n &&& rhs.BigValue () |> adaptBig len, len) :> BitVector

  override __.Or (rhs: uint64) =
    BitVectorBig (n ||| bigint rhs, len) :> BitVector

  override __.Or (rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorBig (n ||| rhs.BigValue () |> adaptBig len, len) :> BitVector

  override __.Xor (rhs: uint64) =
    BitVectorBig (n ^^^ bigint rhs, len) :> BitVector

  override __.Xor (rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    BitVectorBig (n ^^^ rhs.BigValue () |> adaptBig len, len) :> BitVector

  override __.Shl (rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    let v1 = n
    let v2 = rhs.SmallValue () |> uint16 |> int
    BitVectorBig (adaptBig len (v1 <<< v2), len) :> BitVector

  override __.Shr (rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    let v1 = n
    let v2 = rhs.SmallValue () |> uint16 |> int
    BitVectorBig (v1 >>> v2, len) :> BitVector

  override __.Sar (rhs: BitVector) =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    let v1 = n
    let v2 = rhs.SmallValue () |> uint16 |> int
    let res = v1 >>> v2
    if isBigPositive len v1 then BitVectorBig (res, len) :> BitVector
    else
      let pad = ((bigOne <<< int len) - bigOne) - ((bigOne <<< (int len - v2)))
      BitVectorBig (res ||| pad, len) :> BitVector

  override __.Not () =
    BitVectorBig ((bigOne <<< (int len)) - bigOne - n, len) :> BitVector

  override __.Neg () =
    BitVectorBig (adaptBig len ((bigOne <<< (int len)) - n), len) :> BitVector

  override __.Cast targetLen =
    if targetLen <= 64<rt> then
      BitVectorSmall (adaptSmall targetLen (uint64 n), targetLen) :> BitVector
    else BitVectorBig (adaptBig targetLen n, targetLen) :> BitVector

  override __.Extract targetLen pos =
    if len < targetLen then raise ArithTypeMismatchException
    elif len = targetLen then __ :> BitVector
    elif targetLen <= 64<rt> then
      let n' = n >>> pos |> adaptBig targetLen |> uint64
      BitVectorSmall (n', targetLen) :> BitVector
    else BitVectorBig (adaptBig targetLen (n >>> pos), targetLen) :> BitVector

  override __.Concat (rhs: BitVector) =
    let rLen = rhs.Length
    let targetLen = len + rLen
    let v1 = n
    let v2 = rhs.BigValue ()
    BitVectorBig ((v1 <<< int rLen) + v2, targetLen) :> BitVector

  override __.SExt targetLen =
    if targetLen < len then raise ArithTypeMismatchException
    elif targetLen = len then __ :> BitVector
    else
      let n' = adaptBig targetLen n
      if isBigPositive len n then
        BitVectorBig (n', targetLen) :> BitVector
      else
        let mask = (bigOne <<< int targetLen) - (bigOne <<< int len)
        BitVectorBig (n' + mask, targetLen) :> BitVector

  override __.ZExt targetLen =
    if targetLen < len then raise ArithTypeMismatchException
    elif targetLen = len then __ :> BitVector
    else BitVectorBig (adaptBig targetLen n, targetLen) :> BitVector

  override __.Eq rhs =
    if len = rhs.Length && n = rhs.BigValue () then BitVector.T
    else BitVector.F

  override __.Neq rhs =
    if len = rhs.Length && n = rhs.BigValue () then BitVector.F
    else BitVector.T

  override __.Gt rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException
    elif n > rhs.BigValue () then BitVector.T
    else BitVector.F

  override __.Ge rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException
    elif n >= rhs.BigValue () then BitVector.T
    else BitVector.F

  override __.SGt rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    let isPos1 = isBigPositive len n
    let isPos2 = isBigPositive len (rhs.BigValue ())
    if isPos1 && not isPos2 then BitVector.T
    elif not isPos1 && isPos2 then BitVector.F
    else
      if n > rhs.BigValue () then BitVector.T else BitVector.F

  override __.SGe rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    let isPos1 = isBigPositive len n
    let isPos2 = isBigPositive len (rhs.BigValue ())
    if isPos1 && not isPos2 then BitVector.T
    elif not isPos1 && isPos2 then BitVector.F
    else
      if n >= rhs.BigValue () then BitVector.T else BitVector.F

  override __.Lt rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException
    elif n < rhs.BigValue () then BitVector.T
    else BitVector.F

  override __.Le rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException
    elif n <= rhs.BigValue () then BitVector.T
    else BitVector.F

  override __.SLt rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    let isPos1 = isBigPositive len n
    let isPos2 = isBigPositive len (rhs.BigValue ())
    if isPos1 && not isPos2 then BitVector.F
    elif not isPos1 && isPos2 then BitVector.T
    else
      if n < rhs.BigValue () then BitVector.T else BitVector.F

  override __.SLe rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    let isPos1 = isBigPositive len n
    let isPos2 = isBigPositive len (rhs.BigValue ())
    if isPos1 && not isPos2 then BitVector.F
    elif not isPos1 && isPos2 then BitVector.T
    else
      if n <= rhs.BigValue () then BitVector.T else BitVector.F

  override __.Abs () =
    if isBigPositive len n then __ :> BitVector
    else __.Neg ()

  override __.FAdd rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 80<rt> ->
      let v1 = __.BigValue () |> toBigFloat
      let v2 = rhs.BigValue () |> toBigFloat
      let n = v1 + v2 |> BitConverter.DoubleToInt64Bits |> uint64
      if n = 0UL then BitVector.zero len
      else BitVectorBig (encodeBigFloat n, len) :> BitVector
    | _ -> raise ArithTypeMismatchException

  override __.FSub rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 80<rt> ->
      let v1 = __.BigValue () |> toBigFloat
      let v2 = rhs.BigValue () |> toBigFloat
      let n = v1 - v2 |> BitConverter.DoubleToInt64Bits |> uint64
      if n = 0UL then BitVector.zero len
      else BitVectorBig (encodeBigFloat n, len) :> BitVector
    | _ -> raise ArithTypeMismatchException

  override __.FMul rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 80<rt> ->
      let v1 = __.BigValue () |> toBigFloat
      let v2 = rhs.BigValue () |> toBigFloat
      let n = v1 * v2 |> BitConverter.DoubleToInt64Bits |> uint64
      if n = 0UL then BitVector.zero len
      else BitVectorBig (encodeBigFloat n, len) :> BitVector
    | _ -> raise ArithTypeMismatchException

  override __.FDiv rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 80<rt> ->
      let v1 = __.BigValue () |> toBigFloat
      let v2 = rhs.BigValue () |> toBigFloat
      let n = v1 / v2 |> BitConverter.DoubleToInt64Bits |> uint64
      if n = 0UL then BitVector.zero len
      else BitVectorBig (encodeBigFloat n, len) :> BitVector
    | _ -> raise ArithTypeMismatchException

  override __.FLog rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 80<rt> ->
      let v1 = __.BigValue () |> toBigFloat
      let v2 = rhs.BigValue () |> toBigFloat
      let n = Math.Log (v2, v1) |> BitConverter.DoubleToInt64Bits |> uint64
      if n = 0UL then BitVector.zero len
      else BitVectorBig (encodeBigFloat n, len) :> BitVector
    | _ -> raise ArithTypeMismatchException

  override __.FPow rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 80<rt> ->
      let v1 = __.BigValue () |> toBigFloat
      let v2 = rhs.BigValue () |> toBigFloat
      let n = Math.Pow (v1, v2) |> BitConverter.DoubleToInt64Bits |> uint64
      if n = 0UL then BitVector.zero len
      else BitVectorBig (encodeBigFloat n, len) :> BitVector
    | _ -> raise ArithTypeMismatchException

  override __.FCast targetLen =
    match len, targetLen with
    | 80<rt>, 32<rt> ->
      let f32 = __.BigValue () |> toBigFloat |> float32
      BitVectorSmall (BitConverter.SingleToInt32Bits f32 |> uint64, targetLen)
      :> BitVector
    | 80<rt>, 64<rt> ->
      let f64 = __.BigValue () |> toBigFloat
      BitVectorSmall (BitConverter.DoubleToInt64Bits f64 |> uint64, targetLen)
      :> BitVector
    | 80<rt>, 80<rt> -> __ :> BitVector
    | _ -> raise ArithTypeMismatchException

  override __.Itof targetLen =
    let v = if isBigPositive len n then n else - n
    match targetLen with
    | 32<rt> ->
      let u64 = BitConverter.SingleToInt32Bits (float32 v) |> uint64
      BitVectorSmall (u64, targetLen) :> BitVector
    | 64<rt> ->
      let u64 = BitConverter.DoubleToInt64Bits (float v) |> uint64
      BitVectorSmall (u64, targetLen) :> BitVector
    | 80<rt> ->
      let u64 = BitConverter.DoubleToInt64Bits (float v) |> uint64
      BitVectorBig (bigint u64, targetLen) :> BitVector
    | _ -> raise ArithTypeMismatchException

  override __.FtoiTrunc targetLen =
    let f =
      match len with
      | 80<rt> -> __.BigValue () |> toBigFloat |> truncate
      | _ -> raise ArithTypeMismatchException
    if targetLen <= 64<rt> then
      BitVectorSmall (adaptSmall targetLen (uint64 f), targetLen) :> BitVector
    else BitVectorBig (adaptBig targetLen (bigint f), targetLen) :> BitVector

  override __.FtoiRound targetLen =
    let f =
      match len with
      | 80<rt> -> __.BigValue () |> toBigFloat |> round
      | _ -> raise ArithTypeMismatchException
    if targetLen <= 64<rt> then
      BitVectorSmall (adaptSmall targetLen (uint64 f), targetLen) :> BitVector
    else BitVectorBig (adaptBig targetLen (bigint f), targetLen) :> BitVector

  override __.FtoiFloor targetLen =
    let f =
      match len with
      | 80<rt> -> __.BigValue () |> toBigFloat |> floor
      | _ -> raise ArithTypeMismatchException
    if targetLen <= 64<rt> then
      BitVectorSmall (adaptSmall targetLen (uint64 f), targetLen) :> BitVector
    else BitVectorBig (adaptBig targetLen (bigint f), targetLen) :> BitVector

  override __.FtoiCeil targetLen =
    let f =
      match len with
      | 80<rt> -> __.BigValue () |> toBigFloat |> ceil
      | _ -> raise ArithTypeMismatchException
    if targetLen <= 64<rt> then
      BitVectorSmall (adaptSmall targetLen (uint64 f), targetLen) :> BitVector
    else BitVectorBig (adaptBig targetLen (bigint f), targetLen) :> BitVector

  override __.FSqrt () =
    match len with
    | 80<rt> ->
      let r = __.BigValue () |> toBigFloat |> sqrt
      BitVectorBig (BitConverter.DoubleToInt64Bits r |> uint64 |> bigint, len)
      :> BitVector
    | _ -> raise ArithTypeMismatchException

  override __.FTan () =
    match len with
    | 80<rt> ->
      let r = __.BigValue () |> toBigFloat |> tan
      BitVectorBig (BitConverter.DoubleToInt64Bits r |> uint64 |> bigint, len)
      :> BitVector
    | _ -> raise ArithTypeMismatchException

  override __.FATan () =
    match len with
    | 80<rt> ->
      let r = __.BigValue () |> toBigFloat |> atan
      BitVectorBig (BitConverter.DoubleToInt64Bits r |> uint64 |> bigint, len)
      :> BitVector
    | _ -> raise ArithTypeMismatchException

  override __.FSin () =
    match len with
    | 80<rt> ->
      let r = __.BigValue () |> toBigFloat |> sin
      BitVectorBig (BitConverter.DoubleToInt64Bits r |> uint64 |> bigint, len)
      :> BitVector
    | _ -> raise ArithTypeMismatchException

  override __.FCos () =
    match len with
    | 80<rt> ->
      let r = __.BigValue () |> toBigFloat |> cos
      BitVectorBig (BitConverter.DoubleToInt64Bits r |> uint64 |> bigint, len)
      :> BitVector
    | _ -> raise ArithTypeMismatchException

  override __.FGt rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 80<rt> ->
      let v1 = __.BigValue () |> toBigFloat
      let v2 = rhs.BigValue () |> toBigFloat
      if v1 > v2 then BitVector.T else BitVector.F
    | _ -> raise ArithTypeMismatchException

  override __.FGe rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 80<rt> ->
      let v1 = __.BigValue () |> toBigFloat
      let v2 = rhs.BigValue () |> toBigFloat
      if v1 >= v2 then BitVector.T else BitVector.F
    | _ -> raise ArithTypeMismatchException

  override __.FLt rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 80<rt> ->
      let v1 = __.BigValue () |> toBigFloat
      let v2 = rhs.BigValue () |> toBigFloat
      if v1 < v2 then BitVector.T else BitVector.F
    | _ -> raise ArithTypeMismatchException

  override __.FLe rhs =
    if len <> rhs.Length then raise ArithTypeMismatchException else ()
    match len with
    | 80<rt> ->
      let v1 = __.BigValue () |> toBigFloat
      let v2 = rhs.BigValue () |> toBigFloat
      if v1 <= v2 then BitVector.T else BitVector.F
    | _ -> raise ArithTypeMismatchException
