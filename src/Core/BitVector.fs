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

/// Represents a helper module for BitVector.
[<AutoOpen>]
module private BitVector = begin

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

  /// Private bitvector interface.
  type IBV =
    /// BitVector length.
    abstract Length: RegType

    /// Return the uint64 representation of the BitVector value.
    abstract SmallValue: uint64

    /// Return the BigInteger representation of the BitVector value.
    abstract BigValue: bigint

    /// Return true if the value is zero.
    abstract IsZero: bool

    /// Return true if the value is one.
    abstract IsOne: bool

    /// BitVector addition with uint64.
    abstract Add: uint64 -> IBV

    /// BitVector addition.
    abstract Add: IBV -> IBV

    /// BitVector subtraction with uint64.
    abstract Sub: uint64 -> IBV

    /// BitVector subtraction.
    abstract Sub: IBV -> IBV

    /// BitVector multiplication with uint64.
    abstract Mul: uint64 -> IBV

    /// BitVector multiplication.
    abstract Mul: IBV -> IBV

    /// BitVector signed division.
    abstract SDiv: IBV -> IBV

    /// BitVector unsigned division with uint64.
    abstract Div: uint64 -> IBV

    /// BitVector unsigned division.
    abstract Div: IBV -> IBV

    /// BitVector signed modulo.
    abstract SMod: IBV -> IBV

    /// BitVector unsigned modulo with uint64.
    abstract Mod: uint64 -> IBV

    /// BitVector unsigned modulo.
    abstract Mod: IBV -> IBV

    /// BitVector bitwise AND with uint64.
    abstract And: uint64 -> IBV

    /// BitVector bitwise AND.
    abstract And: IBV -> IBV

    /// BitVector bitwise OR with uint64.
    abstract Or: uint64 -> IBV

    /// BitVector bitwise OR.
    abstract Or: IBV -> IBV

    /// BitVector bitwise XOR with uint64.
    abstract Xor: uint64 -> IBV

    /// BitVector bitwise XOR.
    abstract Xor: IBV -> IBV

    /// BitVector logical shift-left.
    abstract Shl: IBV -> IBV

    /// BitVector logical shift-right.
    abstract Shr: IBV -> IBV

    /// BitVector arithmetic shift-right.
    abstract Sar: IBV -> IBV

    /// BitVector bitwise NOT.
    abstract Not: unit -> IBV

    /// BitVector unary negation.
    abstract Neg: unit -> IBV

    /// Type-cast a BitVector to another type. If the target type is bigger than
    /// the current type, then this works the same as ZExt.
    abstract Cast: RegType -> IBV

    /// Extract a sub-BitVector of size (RegType) starting from the index (int).
    abstract Extract: RegType * int -> IBV

    /// BitVector concatenation.
    abstract Concat: IBV -> IBV

    /// BitVector sign-extension.
    abstract SExt: RegType -> IBV

    /// BitVector zero-extension.
    abstract ZExt: RegType -> IBV

    /// BitVector equal.
    abstract Eq: IBV -> IBV

    /// BitVector not equal.
    abstract Neq: IBV -> IBV

    /// BitVector unsigned greater than.
    abstract Gt: IBV -> IBV

    /// BitVector unsigned greater than or equal.
    abstract Ge: IBV -> IBV

    /// BitVector signed greater than.
    abstract SGt: IBV -> IBV

    /// BitVector signed greater than or equal.
    abstract SGe: IBV -> IBV

    /// BitVector unsigned less than.
    abstract Lt: IBV -> IBV

    /// BitVector unsigned less than or equal.
    abstract Le: IBV -> IBV

    /// BitVector signed less than.
    abstract SLt: IBV -> IBV

    /// BitVector signed less than or equal.
    abstract SLe: IBV -> IBV

    /// BitVector absolute value.
    abstract Abs: unit -> IBV

    /// Floating point addition.
    abstract FAdd: IBV -> IBV

    /// Floating point subtraction.
    abstract FSub: IBV -> IBV

    /// Floating point multiplication.
    abstract FMul: IBV -> IBV

    /// Floating point division.
    abstract FDiv: IBV -> IBV

    /// Floating point logarithm.
    abstract FLog: IBV -> IBV

    /// Floating point power.
    abstract FPow: IBV -> IBV

    /// Floating point casting.
    abstract FCast: RegType -> IBV

    /// Integer to float conversion.
    abstract Itof: RegType * bool -> IBV

    /// Floating point to integer conversion with truncation.
    abstract FtoiTrunc: RegType -> IBV

    /// Floating point to integer conversion with rounding.
    abstract FtoiRound: RegType -> IBV

    /// Floating point to integer conversion with flooring.
    abstract FtoiFloor: RegType -> IBV

    /// Floating point to integer conversion with ceiling.
    abstract FtoiCeil: RegType -> IBV

    /// Floating point square root.
    abstract FSqrt: unit -> IBV

    /// Floating point tangent.
    abstract FTan: unit -> IBV

    /// Floating point sine.
    abstract FSin: unit -> IBV

    /// Floating point cosine.
    abstract FCos: unit -> IBV

    /// Floating point arc tangent.
    abstract FATan: unit -> IBV

    /// Floating point greater than.
    abstract FGt: IBV -> IBV

    /// Floating point greater than or equal.
    abstract FGe: IBV -> IBV

    /// Floating point less than.
    abstract FLt: IBV -> IBV

    /// Floating point less than or equal.
    abstract FLe: IBV -> IBV

    /// Return the string representation of the BitVector value. Type is not
    /// appended to the output string.
    abstract ValToString: unit -> string

    /// Is this BitVector representing a positive number?
    abstract IsPositive: unit -> bool

    /// Is this BitVector representing a negative number?
    abstract IsNegative: unit -> bool

  /// This is a BitVector with its length less than or equal to 64bit. This is
  /// preferred because all the operations will be much faster than
  /// BitVectorBig.
  type BitVectorSmall(n, len) =

#if DEBUG
    do if len > 64<rt> then raise ArithTypeMismatchException else ()
#endif

    new(n: int64, len) = BitVectorSmall(uint64 n, len)

    new(n: int32, len) = BitVectorSmall(uint64 n, len)

    new(n: int16, len) = BitVectorSmall(uint64 n, len)

    new(n: int8, len) = BitVectorSmall(uint64 n, len)

    new(n: uint32, len) = BitVectorSmall(uint64 n, len)

    new(n: uint16, len) = BitVectorSmall(uint64 n, len)

    new(n: uint8, len) = BitVectorSmall(uint64 n, len)

    member _.Value with get(): uint64 = n

    member _.Length with get(): RegType = len

    override _.Equals obj =
      match obj with
      | :? BitVectorSmall as obj -> len = obj.Length && n = obj.Value
      | _ -> false

    override _.GetHashCode() =
      HashCode.Combine<uint64, RegType>(n, len)

    override _.ToString() =
      HexString.ofUInt64 n + ":" + RegType.toString len

    interface IBV with
      member _.Length = len

      member _.SmallValue = n

      member _.BigValue = bigint n

      member _.IsZero = n = 0UL

      member _.IsOne = n = 1UL

      member _.Add(rhs: uint64) =
        BitVectorSmall(n + rhs |> adaptSmall len, len) :> IBV

      member _.Add(rhs: IBV) =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        BitVectorSmall(n + rhs.SmallValue |> adaptSmall len, len) :> IBV

      member _.Sub(rhs: uint64) =
        BitVectorSmall(n - rhs |> adaptSmall len, len) :> IBV

      member _.Sub(rhs: IBV) =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        BitVectorSmall(n - rhs.SmallValue |> adaptSmall len, len) :> IBV

      member _.Mul(rhs: uint64) =
        BitVectorSmall(n * rhs |> adaptSmall len, len) :> IBV

      member _.Mul(rhs: IBV) =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        BitVectorSmall(n * rhs.SmallValue |> adaptSmall len, len) :> IBV

      member _.SDiv(rhs: IBV) =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        let v1 = n
        let v2 = rhs.SmallValue
        let isPos1 = isSmallPositive len v1
        let isPos2 = isSmallPositive len v2
        let v1 =
          int64 (if isPos1 then v1 else ((~~~ v1) + 1UL) |> adaptSmall len)
        let v2 =
          int64 (if isPos2 then v2 else ((~~~ v2) + 1UL) |> adaptSmall len)
        let result = if isPos1 = isPos2 then v1 / v2 else - (v1 / v2)
        BitVectorSmall(result |> uint64 |> adaptSmall len, len)

      member _.Div(rhs: uint64) =
        BitVectorSmall(n / rhs |> adaptSmall len, len) :> IBV

      member _.Div(rhs: IBV) =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        BitVectorSmall(n / rhs.SmallValue |> adaptSmall len, len) :> IBV

      member _.SMod(rhs: IBV) =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        let v1 = n
        let v2 = rhs.SmallValue
        let isPos1 = isSmallPositive len v1
        let isPos2 = isSmallPositive len v2
        let v1 =
          int64 (if isPos1 then v1 else ((~~~ v1) + 1UL) |> adaptSmall len)
        let v2 =
          int64 (if isPos2 then v2 else ((~~~ v2) + 1UL) |> adaptSmall len)
        let result = if isPos1 then v1 % v2 else - (v1 % v2)
        BitVectorSmall(result |> uint64 |> adaptSmall len, len) :> IBV

      member _.Mod(rhs: uint64) =
        BitVectorSmall(n % rhs |> adaptSmall len, len) :> IBV

      member _.Mod(rhs: IBV) =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        BitVectorSmall(n % rhs.SmallValue |> adaptSmall len, len) :> IBV

      member _.And(rhs: uint64) =
        BitVectorSmall(n &&& rhs |> adaptSmall len, len) :> IBV

      member _.And(rhs: IBV) =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        BitVectorSmall(n &&& rhs.SmallValue |> adaptSmall len, len)
        :> IBV

      member _.Or(rhs: uint64) =
        BitVectorSmall(n ||| rhs |> adaptSmall len, len) :> IBV

      member _.Or(rhs: IBV) =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        BitVectorSmall(n ||| rhs.SmallValue |> adaptSmall len, len) :> IBV

      member _.Xor(rhs: uint64) =
        BitVectorSmall(n ^^^ rhs |> adaptSmall len, len) :> IBV

      member _.Xor(rhs: IBV) =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        BitVectorSmall(n ^^^ rhs.SmallValue |> adaptSmall len, len) :> IBV

      member _.Shl(rhs: IBV) =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        let v1 = n
        let v2 = rhs.SmallValue
        if v2 >= 64UL then BitVectorSmall(0UL, len)
        else BitVectorSmall(adaptSmall len (v1 <<< int v2), len)

      member _.Shr(rhs: IBV) =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        let v1 = n
        let v2 = rhs.SmallValue
        (* In .NET, 1UL >>> 63 = 0, but 1UL >>> 64 = 1 *)
        if v2 >= 64UL then BitVectorSmall(0UL, len)
        else BitVectorSmall(v1 >>> (int v2), len)

      member this.Sar(rhs: IBV) =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        let v1 = n
        let v2 = rhs.SmallValue
        (* In .NET, 1UL >>> 63 = 0, but 1UL >>> 64 = 1 *)
        if v2 >= 64UL then
          BitVectorSmall(UInt64.MaxValue |> adaptSmall len, len)
        else
          let res = v1 >>> (int v2)
          if len = 1<rt> then
            this
          elif isSmallPositive len v1 then
            BitVectorSmall(res, len)
          else
            let pad =
              (UInt64.MaxValue >>> (64 - int len))
              - (if int len <= int v2 then 0UL
                 else UInt64.MaxValue >>> (64 - (int len - int v2)))
            BitVectorSmall(res ||| pad, len)

      member _.Not() =
        BitVectorSmall((~~~ n) |> adaptSmall len, len)

      member _.Neg() =
        BitVectorSmall(((~~~ n) + 1UL) |> adaptSmall len, len)

      member this.Cast targetLen =
        if targetLen <= 64<rt> then
          BitVectorSmall(adaptSmall targetLen n, targetLen)
        else
          BitVectorBig(adaptBig targetLen (bigint this.Value), targetLen)

      member this.Extract(targetLen, pos) =
        if len < targetLen then
          raise ArithTypeMismatchException
        elif len = targetLen then
          this
        else
          BitVectorSmall(adaptSmall targetLen (n >>> pos), targetLen)

      member this.Concat(rhs: IBV) =
        let rLen = rhs.Length
        let targetLen = len + rLen
        if targetLen <= 64<rt> then
          BitVectorSmall((n <<< int rLen) + rhs.SmallValue, targetLen)
        else
          let v1 = bigint this.Value
          let v2 = rhs.BigValue
          BitVectorBig((v1 <<< int rLen) + v2, targetLen)

      member this.SExt targetLen =
        if targetLen < len then
          raise ArithTypeMismatchException
        elif targetLen = len then
          this
        elif targetLen <= 64<rt> then
          if isSmallPositive len n then
            BitVectorSmall(n, targetLen)
          else
            let mask =
              (UInt64.MaxValue >>> (64 - int targetLen))
              - (UInt64.MaxValue >>> (64 - int len))
            BitVectorSmall(n + mask, targetLen)
        else
          let n' = adaptBig targetLen (bigint this.Value)
          if isSmallPositive len n then
            BitVectorBig(n', targetLen)
          else
            let mask = (1I <<< int targetLen) - (1I <<< int len)
            BitVectorBig(n' + mask, targetLen)

      member this.ZExt targetLen =
        if targetLen < len then
          raise ArithTypeMismatchException
        elif targetLen = len then
          this
        elif targetLen <= 64<rt> then
          BitVectorSmall(adaptSmall targetLen n, targetLen)
        else
          BitVectorBig(adaptBig targetLen (bigint this.Value), targetLen)

      member _.Eq rhs =
        if len = rhs.Length && n = rhs.SmallValue then Value.T
        else Value.F

      member _.Neq rhs =
        if len = rhs.Length && n = rhs.SmallValue then Value.F
        else Value.T

      member _.Gt rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException
        elif n > rhs.SmallValue then Value.T
        else Value.F

      member _.Ge rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException
        elif n >= rhs.SmallValue then Value.T
        else Value.F

      member _.SGt rhs =
        if len <> rhs.Length then
          raise ArithTypeMismatchException
        else
          let v1 = n
          let v2 = rhs.SmallValue
          let isPos1 = isSmallPositive len v1
          let isPos2 = isSmallPositive len v2
          match isPos1, isPos2 with
          | true, false -> Value.T
          | false, true -> Value.F
          | _ -> if v1 > v2 then Value.T else Value.F

      member _.SGe rhs =
        if len <> rhs.Length then
          raise ArithTypeMismatchException
        else
          let v1 = n
          let v2 = rhs.SmallValue
          let isPos1 = isSmallPositive len v1
          let isPos2 = isSmallPositive len v2
          match isPos1, isPos2 with
          | true, false -> Value.T
          | false, true -> Value.F
          | _ -> if v1 >= v2 then Value.T else Value.F

      member _.Lt rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException
        elif n < rhs.SmallValue then Value.T
        else Value.F

      member _.Le rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException
        elif n <= rhs.SmallValue then Value.T
        else Value.F

      member _.SLt rhs =
        if len <> rhs.Length then
          raise ArithTypeMismatchException
        else
          let v1 = n
          let v2 = rhs.SmallValue
          let isPos1 = isSmallPositive len v1
          let isPos2 = isSmallPositive len v2
          match isPos1, isPos2 with
          | true, false -> Value.F
          | false, true -> Value.T
          | _ -> if v1 < v2 then Value.T else Value.F

      member _.SLe rhs =
        if len <> rhs.Length then
          raise ArithTypeMismatchException
        else
          let v1 = n
          let v2 = rhs.SmallValue
          let isPos1 = isSmallPositive len v1
          let isPos2 = isSmallPositive len v2
          match isPos1, isPos2 with
          | true, false -> Value.F
          | false, true -> Value.T
          | _ -> if v1 <= v2 then Value.T else Value.F

      member this.Abs() =
        if isSmallPositive len n then this
        else (this :> IBV).Neg()

      member this.FAdd rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        match len with
        | 32<rt> ->
          let v1 = this.Value |> toFloat32
          let v2 = rhs.SmallValue |> toFloat32
          let bs = v1 + v2 |> BitConverter.GetBytes
          BitVectorSmall(BitConverter.ToInt32(bs, 0) |> uint64, len)
        | 64<rt> ->
          let v1 = this.Value |> toFloat64
          let v2 = rhs.SmallValue |> toFloat64
          let r = v1 + v2 |> BitConverter.DoubleToInt64Bits |> uint64
          BitVectorSmall(r, len)
        | _ -> raise ArithTypeMismatchException

      member this.FSub rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        match len with
        | 32<rt> ->
          let v1 = this.Value |> toFloat32
          let v2 = rhs.SmallValue |> toFloat32
          let bs = v1 - v2 |> BitConverter.GetBytes
          BitVectorSmall(BitConverter.ToInt32(bs, 0) |> uint64, len)
        | 64<rt> ->
          let v1 = this.Value |> toFloat64
          let v2 = rhs.SmallValue |> toFloat64
          let r = v1 - v2 |> BitConverter.DoubleToInt64Bits |> uint64
          BitVectorSmall(r, len)
        | _ -> raise ArithTypeMismatchException

      member this.FMul rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        match len with
        | 32<rt> ->
          let v1 = this.Value |> toFloat32
          let v2 = rhs.SmallValue |> toFloat32
          let bs = v1 * v2 |> BitConverter.GetBytes
          BitVectorSmall(BitConverter.ToInt32(bs, 0) |> uint64, len)
        | 64<rt> ->
          let v1 = this.Value |> toFloat64
          let v2 = rhs.SmallValue |> toFloat64
          let r = v1 * v2 |> BitConverter.DoubleToInt64Bits |> uint64
          BitVectorSmall(r, len)
        | _ -> raise ArithTypeMismatchException

      member this.FDiv rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        match len with
        | 32<rt> ->
          let v1 = this.Value |> toFloat32
          let v2 = rhs.SmallValue |> toFloat32
          let bs = v1 / v2 |> BitConverter.GetBytes
          BitVectorSmall(BitConverter.ToInt32(bs, 0) |> uint64, len)
        | 64<rt> ->
          let v1 = this.Value |> toFloat64
          let v2 = rhs.SmallValue |> toFloat64
          let r = v1 / v2 |> BitConverter.DoubleToInt64Bits |> uint64
          BitVectorSmall(r, len)
        | _ -> raise ArithTypeMismatchException

      member this.FLog rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        match len with
        | 32<rt> ->
          let v1 = this.Value |> toFloat32
          let v2 = rhs.SmallValue |> toFloat32
          let bs = MathF.Log(v2, v1) |> BitConverter.GetBytes
          BitVectorSmall(BitConverter.ToInt32(bs, 0) |> uint64, len)
        | 64<rt> ->
          let v1 = this.Value |> toFloat64
          let v2 = rhs.SmallValue |> toFloat64
          let r = Math.Log(v2, v1) |> BitConverter.DoubleToInt64Bits |> uint64
          BitVectorSmall(r, len)
        | _ -> raise ArithTypeMismatchException

      member this.FPow rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        match len with
        | 32<rt> ->
          let v1 = this.Value |> toFloat32
          let v2 = rhs.SmallValue |> toFloat32
          let bs = MathF.Pow(v1, v2) |> BitConverter.GetBytes
          BitVectorSmall(BitConverter.ToInt32(bs, 0) |> uint64, len)
        | 64<rt> ->
          let v1 = this.Value |> toFloat64
          let v2 = rhs.SmallValue |> toFloat64
          let r = Math.Pow(v1, v2) |> BitConverter.DoubleToInt64Bits |> uint64
          BitVectorSmall(r, len)
        | _ -> raise ArithTypeMismatchException

      member this.FCast targetLen =
        match len, targetLen with
        | 32<rt>, 32<rt> -> this
        | 32<rt>, 64<rt> ->
          let f32 = this.Value |> toFloat32 |> float
          let u64 = BitConverter.DoubleToInt64Bits f32 |> uint64
          BitVectorSmall(u64, targetLen)
        | 32<rt>, 80<rt> ->
          let f32 = this.Value |> toFloat32 |> float
          let u64 = BitConverter.DoubleToInt64Bits f32 |> uint64
          BitVectorBig(encodeBigFloat u64, targetLen)
        | 64<rt>, 32<rt> ->
          let f64 = this.Value |> toFloat64
          let u64 = BitConverter.SingleToInt32Bits(float32 f64) |> uint64
          BitVectorSmall(u64, targetLen)
        | 64<rt>, 64<rt> -> this
        | 64<rt>, 80<rt> ->
          BitVectorBig(this.Value |> encodeBigFloat, targetLen)
        | _ -> raise ArithTypeMismatchException

      member _.Itof(targetLen, isSigned) =
        match targetLen with
        | 32<rt> ->
          let fpv = if isSigned then n |> int64 |> float32 else n |> float32
          let u64 = BitConverter.SingleToInt32Bits fpv |> uint64
          BitVectorSmall(u64, targetLen)
        | 64<rt> ->
          let fpv = if isSigned then n |> int64 |> float else n |> float
          let u64 = BitConverter.DoubleToInt64Bits fpv |> uint64
          BitVectorSmall(u64, targetLen)
        | 80<rt> ->
          let fpv = if isSigned then n |> int64 |> float else n |> float
          let u64 = BitConverter.DoubleToInt64Bits fpv |> uint64
          BitVectorBig(bigint u64, targetLen)
        | _ -> raise ArithTypeMismatchException

      member this.FtoiTrunc targetLen =
        let f =
          match len with
          | 32<rt> -> this.Value |> toFloat32 |> float |> truncate
          | 64<rt> -> this.Value |> toFloat64 |> truncate
          | _ -> raise ArithTypeMismatchException
        if targetLen <= 64<rt> then
          BitVectorSmall(adaptSmall targetLen (uint64 f), targetLen)
        else BitVectorBig(adaptBig targetLen (bigint f), targetLen)

      member this.FtoiRound targetLen =
        let f =
          match len with
          | 32<rt> -> this.Value |> toFloat32 |> float |> round
          | 64<rt> -> this.Value |> toFloat64 |> round
          | _ -> raise ArithTypeMismatchException
        if targetLen <= 64<rt> then
          BitVectorSmall(adaptSmall targetLen (uint64 f), targetLen)
        else BitVectorBig(adaptBig targetLen (bigint f), targetLen)

      member this.FtoiFloor targetLen =
        let f =
          match len with
          | 32<rt> -> this.Value |> toFloat32 |> float |> floor
          | 64<rt> -> this.Value |> toFloat64 |> floor
          | _ -> raise ArithTypeMismatchException
        if targetLen <= 64<rt> then
          BitVectorSmall(adaptSmall targetLen (uint64 f), targetLen)
        else BitVectorBig(adaptBig targetLen (bigint f), targetLen)

      member this.FtoiCeil targetLen =
        let f =
          match len with
          | 32<rt> -> this.Value |> toFloat32 |> float |> ceil
          | 64<rt> -> this.Value |> toFloat64 |> ceil
          | _ -> raise ArithTypeMismatchException
        if targetLen <= 64<rt> then
          BitVectorSmall(adaptSmall targetLen (uint64 f), targetLen)
        else
          BitVectorBig(adaptBig targetLen (bigint f), targetLen)

      member this.FSqrt() =
        match len with
        | 32<rt> ->
          let r = this.Value |> toFloat32 |> sqrt
          BitVectorSmall(BitConverter.SingleToInt32Bits r |> uint64, len)
        | 64<rt> ->
          let r = this.Value |> toFloat64 |> sqrt
          BitVectorSmall(BitConverter.DoubleToInt64Bits r |> uint64, len)
        | _ -> raise ArithTypeMismatchException

      member this.FTan() =
        match len with
        | 32<rt> ->
          let r = this.Value |> toFloat32 |> tan
          BitVectorSmall(BitConverter.SingleToInt32Bits r |> uint64, len)
        | 64<rt> ->
          let r = this.Value |> toFloat64 |> tan
          BitVectorSmall(BitConverter.DoubleToInt64Bits r |> uint64, len)
        | _ -> raise ArithTypeMismatchException

      member this.FATan() =
        match len with
        | 32<rt> ->
          let r = this.Value |> toFloat32 |> atan
          BitVectorSmall(BitConverter.SingleToInt32Bits r |> uint64, len)
        | 64<rt> ->
          let r = this.Value |> toFloat64 |> atan
          BitVectorSmall(BitConverter.DoubleToInt64Bits r |> uint64, len)
        | _ -> raise ArithTypeMismatchException

      member this.FSin() =
        match len with
        | 32<rt> ->
          let r = this.Value |> toFloat32 |> sin
          BitVectorSmall(BitConverter.SingleToInt32Bits r |> uint64, len)
        | 64<rt> ->
          let r = this.Value |> toFloat64 |> sin
          BitVectorSmall(BitConverter.DoubleToInt64Bits r |> uint64, len)
        | _ -> raise ArithTypeMismatchException

      member this.FCos() =
        match len with
        | 32<rt> ->
          let r = this.Value |> toFloat32 |> cos
          BitVectorSmall(BitConverter.SingleToInt32Bits r |> uint64, len)
        | 64<rt> ->
          let r = this.Value |> toFloat64 |> cos
          BitVectorSmall(BitConverter.DoubleToInt64Bits r |> uint64, len)
        | _ -> raise ArithTypeMismatchException

      member this.FGt rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        match len with
        | 32<rt> ->
          let v1 = this.Value |> toFloat32
          let v2 = rhs.SmallValue |> toFloat32
          if v1 > v2 then Value.T else Value.F
        | 64<rt> ->
          let v1 = this.Value |> toFloat64
          let v2 = rhs.SmallValue |> toFloat64
          if v1 > v2 then Value.T else Value.F
        | _ -> raise ArithTypeMismatchException

      member this.FGe rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        match len with
        | 32<rt> ->
          let v1 = this.Value |> toFloat32
          let v2 = rhs.SmallValue |> toFloat32
          if v1 >= v2 then Value.T else Value.F
        | 64<rt> ->
          let v1 = this.Value |> toFloat64
          let v2 = rhs.SmallValue |> toFloat64
          if v1 >= v2 then Value.T else Value.F
        | _ -> raise ArithTypeMismatchException

      member this.FLt rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        match len with
        | 32<rt> ->
          let v1 = this.Value |> toFloat32
          let v2 = rhs.SmallValue |> toFloat32
          if v1 < v2 then Value.T else Value.F
        | 64<rt> ->
          let v1 = this.Value |> toFloat64
          let v2 = rhs.SmallValue |> toFloat64
          if v1 < v2 then Value.T else Value.F
        | _ -> raise ArithTypeMismatchException

      member this.FLe rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        match len with
        | 32<rt> ->
          let v1 = this.Value |> toFloat32
          let v2 = rhs.SmallValue |> toFloat32
          if v1 <= v2 then Value.T else Value.F
        | 64<rt> ->
          let v1 = this.Value |> toFloat64
          let v2 = rhs.SmallValue |> toFloat64
          if v1 <= v2 then Value.T else Value.F
        | _ -> raise ArithTypeMismatchException

      member _.ValToString() = HexString.ofUInt64 n

      member _.IsPositive() = isSmallPositive len n

      member _.IsNegative() = not <| isSmallPositive len n

  /// This is a BitVector with its length less than or equal to 64bit. This is
  /// preferred because all the operations will be much faster than
  /// BitVectorBig.
  and BitVectorBig(n, len) =

#if DEBUG
    do if len <= 64<rt> then raise ArithTypeMismatchException else ()
#endif

    let valToString () =
      if n = 0I then "0x0"
      else "0x" + n.ToString("x").TrimStart('0')

    member _.Value with get(): bigint = n

    member _.Length with get(): RegType = len

    override _.Equals obj =
      match obj with
      | :? BitVectorBig as obj -> len = obj.Length && n = obj.Value
      | _ -> false

    override _.GetHashCode() =
      HashCode.Combine<bigint, RegType>(n, len)

    override _.ToString() =
      valToString () + ":" + RegType.toString len

    interface IBV with
      member _.Length = len

      member _.SmallValue =
#if DEBUG
        if n > bigint 0xFFFFFFFFFFFFFFFFUL then nSizeErr len else ()
#endif
        uint64 n

      member _.BigValue = n

      member _.IsZero = n = 0I

      member _.IsOne = n = 1I

      member _.Add(rhs: uint64) =
        BitVectorBig(n + bigint rhs, len) :> IBV

      member _.Add(rhs: IBV) =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        BitVectorBig(n + rhs.BigValue |> adaptBig len, len) :> IBV

      member _.Sub(rhs: uint64) =
        BitVectorBig(n - bigint rhs, len) :> IBV

      member _.Sub(rhs: IBV) =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        BitVectorBig(n - rhs.BigValue |> adaptBig len, len) :> IBV

      member _.Mul(rhs: uint64) =
        BitVectorBig(n * bigint rhs, len) :> IBV

      member _.Mul(rhs: IBV) =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        BitVectorBig(n * rhs.BigValue |> adaptBig len, len) :> IBV

      member _.SDiv(rhs: IBV) =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        let v1 = n
        let v2 = rhs.BigValue
        let isPos1 = isBigPositive len v1
        let isPos2 = isBigPositive rhs.Length v2
        let v1 = if isPos1 then v1 else neg len v1
        let v2 = if isPos2 then v2 else neg len v2
        let result = if isPos1 = isPos2 then v1 / v2 else neg len (v1 / v2)
        BitVectorBig(result |> adaptBig len, len) :> IBV

      member _.Div(rhs: uint64) =
        BitVectorBig(n / bigint rhs, len) :> IBV

      member _.Div(rhs: IBV) =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        BitVectorBig(n / rhs.BigValue |> adaptBig len, len) :> IBV

      member _.SMod(rhs: IBV) =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        let v1 = n
        let v2 = rhs.BigValue
        let isPos1 = isBigPositive len v1
        let isPos2 = isBigPositive rhs.Length v2
        let v1 = if isPos1 then v1 else neg len v1
        let v2 = if isPos2 then v2 else neg len v2
        let result = if isPos1 then v1 % v2 else neg len (v1 % v2)
        BitVectorBig(result |> adaptBig len, len)

      member _.Mod(rhs: uint64) =
        BitVectorBig(n % bigint rhs, len) :> IBV

      member _.Mod(rhs: IBV) =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        BitVectorBig(n % rhs.BigValue |> adaptBig len, len) :> IBV

      member _.And(rhs: uint64) =
        BitVectorBig(n &&& bigint rhs, len) :> IBV

      member _.And(rhs: IBV) =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        BitVectorBig(n &&& rhs.BigValue |> adaptBig len, len) :> IBV

      member _.Or(rhs: uint64) =
        BitVectorBig(n ||| bigint rhs, len) :> IBV

      member _.Or(rhs: IBV) =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        BitVectorBig(n ||| rhs.BigValue |> adaptBig len, len) :> IBV

      member _.Xor(rhs: uint64) =
        BitVectorBig(n ^^^ bigint rhs, len) :> IBV

      member _.Xor(rhs: IBV) =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        BitVectorBig(n ^^^ rhs.BigValue |> adaptBig len, len) :> IBV

      member _.Shl(rhs: IBV) =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        let v1 = n
        let v2 = rhs.SmallValue |> uint16 |> int
        BitVectorBig(adaptBig len (v1 <<< v2), len)

      member _.Shr(rhs: IBV) =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        let v1 = n
        let v2 = rhs.SmallValue |> uint16 |> int
        BitVectorBig(v1 >>> v2, len)

      member _.Sar(rhs: IBV) =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        let v1 = n
        let v2 = rhs.SmallValue |> uint16 |> int
        if v2 >= int len then
          BitVectorBig((1I <<< int len) - 1I, len)
        else
          let res = v1 >>> v2
          if isBigPositive len v1 then
            BitVectorBig(res, len)
          else
            let pad = ((1I <<< int len) - 1I) - ((1I <<< (int len - v2)))
            BitVectorBig(res ||| pad, len)

      member _.Not() =
        BitVectorBig((1I <<< (int len)) - 1I - n, len)

      member _.Neg() =
        BitVectorBig(adaptBig len ((1I <<< (int len)) - n), len)

      member _.Cast targetLen =
        if targetLen <= 64<rt> then
          BitVectorSmall(adaptSmall targetLen (uint64 n), targetLen)
        else
          BitVectorBig(adaptBig targetLen n, targetLen)

      member this.Extract(targetLen, pos) =
        if len < targetLen then
          raise ArithTypeMismatchException
        elif len = targetLen then
          this
        elif targetLen <= 64<rt> then
          let n' = n >>> pos |> adaptBig targetLen |> uint64
          BitVectorSmall(n', targetLen)
        else
          BitVectorBig(adaptBig targetLen (n >>> pos), targetLen)

      member _.Concat(rhs: IBV) =
        let rLen = rhs.Length
        let targetLen = len + rLen
        let v1 = n
        let v2 = rhs.BigValue
        BitVectorBig((v1 <<< int rLen) + v2, targetLen)

      member this.SExt targetLen =
        if targetLen < len then
          raise ArithTypeMismatchException
        elif targetLen = len then
          this
        else
          let n' = adaptBig targetLen n
          if isBigPositive len n then
            BitVectorBig(n', targetLen)
          else
            let mask = (1I <<< int targetLen) - (1I <<< int len)
            BitVectorBig(n' + mask, targetLen)

      member this.ZExt targetLen =
        if targetLen < len then raise ArithTypeMismatchException
        elif targetLen = len then this
        else BitVectorBig(adaptBig targetLen n, targetLen)

      member _.Eq rhs =
        if len = rhs.Length && n = rhs.BigValue then Value.T
        else Value.F

      member _.Neq rhs =
        if len = rhs.Length && n = rhs.BigValue then Value.F
        else Value.T

      member _.Gt rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException
        elif n > rhs.BigValue then Value.T
        else Value.F

      member _.Ge rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException
        elif n >= rhs.BigValue then Value.T
        else Value.F

      member _.SGt rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        let isPos1 = isBigPositive len n
        let isPos2 = isBigPositive len (rhs.BigValue)
        if isPos1 && not isPos2 then
          Value.T
        elif not isPos1 && isPos2 then
          Value.F
        else
          if n > rhs.BigValue then Value.T
          else Value.F

      member _.SGe rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        let isPos1 = isBigPositive len n
        let isPos2 = isBigPositive len (rhs.BigValue)
        if isPos1 && not isPos2 then
          Value.T
        elif not isPos1 && isPos2 then
          Value.F
        else
          if n >= rhs.BigValue then Value.T
          else Value.F

      member _.Lt rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException
        elif n < rhs.BigValue then Value.T
        else Value.F

      member _.Le rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException
        elif n <= rhs.BigValue then Value.T
        else Value.F

      member _.SLt rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        let isPos1 = isBigPositive len n
        let isPos2 = isBigPositive len (rhs.BigValue)
        if isPos1 && not isPos2 then Value.F
        elif not isPos1 && isPos2 then Value.T
        else
          if n < rhs.BigValue then Value.T else Value.F

      member _.SLe rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        let isPos1 = isBigPositive len n
        let isPos2 = isBigPositive len (rhs.BigValue)
        if isPos1 && not isPos2 then Value.F
        elif not isPos1 && isPos2 then Value.T
        else
          if n <= rhs.BigValue then Value.T else Value.F

      member this.Abs() =
        if isBigPositive len n then this
        else (this :> IBV).Neg()

      member this.FAdd rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        match len with
        | 80<rt> ->
          let v1 = this.Value |> toBigFloat
          let v2 = rhs.BigValue |> toBigFloat
          let n = v1 + v2 |> BitConverter.DoubleToInt64Bits |> uint64
          if n = 0UL then Value.Zero len
          else BitVectorBig(encodeBigFloat n, len)
        | _ -> raise ArithTypeMismatchException

      member this.FSub rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        match len with
        | 80<rt> ->
          let v1 = this.Value |> toBigFloat
          let v2 = rhs.BigValue |> toBigFloat
          let n = v1 - v2 |> BitConverter.DoubleToInt64Bits |> uint64
          if n = 0UL then Value.Zero len
          else BitVectorBig(encodeBigFloat n, len)
        | _ -> raise ArithTypeMismatchException

      member this.FMul rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        match len with
        | 80<rt> ->
          let v1 = this.Value |> toBigFloat
          let v2 = rhs.BigValue |> toBigFloat
          let n = v1 * v2 |> BitConverter.DoubleToInt64Bits |> uint64
          if n = 0UL then Value.Zero len
          else BitVectorBig(encodeBigFloat n, len)
        | _ -> raise ArithTypeMismatchException

      member this.FDiv rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        match len with
        | 80<rt> ->
          let v1 = this.Value |> toBigFloat
          let v2 = rhs.BigValue |> toBigFloat
          let n = v1 / v2 |> BitConverter.DoubleToInt64Bits |> uint64
          if n = 0UL then Value.Zero len
          else BitVectorBig(encodeBigFloat n, len)
        | _ -> raise ArithTypeMismatchException

      member this.FLog rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        match len with
        | 80<rt> ->
          let v1 = this.Value |> toBigFloat
          let v2 = rhs.BigValue |> toBigFloat
          let n = Math.Log(v2, v1) |> BitConverter.DoubleToInt64Bits |> uint64
          if n = 0UL then Value.Zero len
          else BitVectorBig(encodeBigFloat n, len)
        | _ -> raise ArithTypeMismatchException

      member this.FPow rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        match len with
        | 80<rt> ->
          let v1 = this.Value |> toBigFloat
          let v2 = rhs.BigValue |> toBigFloat
          let n = Math.Pow(v1, v2) |> BitConverter.DoubleToInt64Bits |> uint64
          if n = 0UL then Value.Zero len
          else BitVectorBig(encodeBigFloat n, len)
        | _ -> raise ArithTypeMismatchException

      member this.FCast targetLen =
        match len, targetLen with
        | 80<rt>, 32<rt> ->
          let f32 = this.Value |> toBigFloat |> float32
          BitVectorSmall(BitConverter.SingleToInt32Bits f32 |> uint64, 32<rt>)
        | 80<rt>, 64<rt> ->
          let f64 = this.Value |> toBigFloat
          BitVectorSmall(BitConverter.DoubleToInt64Bits f64 |> uint64, 64<rt>)
        | 80<rt>, 80<rt> -> this
        | _ -> raise ArithTypeMismatchException

      member _.Itof(targetLen, _) =
        let v = if isBigPositive len n then n else - n
        match targetLen with
        | 32<rt> ->
          let u64 = BitConverter.SingleToInt32Bits(float32 v) |> uint64
          BitVectorSmall(u64, targetLen)
        | 64<rt> ->
          let u64 = BitConverter.DoubleToInt64Bits(float v) |> uint64
          BitVectorSmall(u64, targetLen)
        | 80<rt> ->
          let u64 = BitConverter.DoubleToInt64Bits(float v) |> uint64
          BitVectorBig(bigint u64, targetLen)
        | _ -> raise ArithTypeMismatchException

      member this.FtoiTrunc targetLen =
        let f =
          match len with
          | 80<rt> -> this.Value |> toBigFloat |> truncate
          | _ -> raise ArithTypeMismatchException
        if targetLen <= 64<rt> then
          BitVectorSmall(adaptSmall targetLen (uint64 f), targetLen)
        else
          BitVectorBig(adaptBig targetLen (bigint f), targetLen)

      member this.FtoiRound targetLen =
        let f =
          match len with
          | 80<rt> -> this.Value |> toBigFloat |> round
          | _ -> raise ArithTypeMismatchException
        if targetLen <= 64<rt> then
          BitVectorSmall(adaptSmall targetLen (uint64 f), targetLen)
        else
          BitVectorBig(adaptBig targetLen (bigint f), targetLen)

      member this.FtoiFloor targetLen =
        let f =
          match len with
          | 80<rt> -> this.Value |> toBigFloat |> floor
          | _ -> raise ArithTypeMismatchException
        if targetLen <= 64<rt> then
          BitVectorSmall(adaptSmall targetLen (uint64 f), targetLen)
        else
          BitVectorBig(adaptBig targetLen (bigint f), targetLen)

      member this.FtoiCeil targetLen =
        let f =
          match len with
          | 80<rt> -> this.Value |> toBigFloat |> ceil
          | _ -> raise ArithTypeMismatchException
        if targetLen <= 64<rt> then
          BitVectorSmall(adaptSmall targetLen (uint64 f), targetLen)
        else
          BitVectorBig(adaptBig targetLen (bigint f), targetLen)

      member this.FSqrt() =
        match len with
        | 80<rt> ->
          let r = this.Value |> toBigFloat |> sqrt
          let v = BitConverter.DoubleToInt64Bits r |> uint64 |> bigint
          BitVectorBig(v, len)
        | _ -> raise ArithTypeMismatchException

      member this.FTan() =
        match len with
        | 80<rt> ->
          let r = this.Value |> toBigFloat |> tan
          let v = BitConverter.DoubleToInt64Bits r |> uint64 |> bigint
          BitVectorBig(v, len)
        | _ -> raise ArithTypeMismatchException

      member this.FATan() =
        match len with
        | 80<rt> ->
          let r = this.Value |> toBigFloat |> atan
          let v = BitConverter.DoubleToInt64Bits r |> uint64 |> bigint
          BitVectorBig(v, len)
        | _ -> raise ArithTypeMismatchException

      member this.FSin() =
        match len with
        | 80<rt> ->
          let r = this.Value |> toBigFloat |> sin
          let v = BitConverter.DoubleToInt64Bits r |> uint64 |> bigint
          BitVectorBig(v, len)
        | _ -> raise ArithTypeMismatchException

      member this.FCos() =
        match len with
        | 80<rt> ->
          let r = this.Value |> toBigFloat |> cos
          let v = BitConverter.DoubleToInt64Bits r |> uint64 |> bigint
          BitVectorBig(v, len)
        | _ -> raise ArithTypeMismatchException

      member this.FGt rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        match len with
        | 80<rt> ->
          let v1 = this.Value |> toBigFloat
          let v2 = rhs.BigValue |> toBigFloat
          if v1 > v2 then Value.T else Value.F
        | _ -> raise ArithTypeMismatchException

      member this.FGe rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        match len with
        | 80<rt> ->
          let v1 = this.Value |> toBigFloat
          let v2 = rhs.BigValue |> toBigFloat
          if v1 >= v2 then Value.T else Value.F
        | _ -> raise ArithTypeMismatchException

      member this.FLt rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        match len with
        | 80<rt> ->
          let v1 = this.Value |> toBigFloat
          let v2 = rhs.BigValue |> toBigFloat
          if v1 < v2 then Value.T else Value.F
        | _ -> raise ArithTypeMismatchException

      member this.FLe rhs =
        if len <> rhs.Length then raise ArithTypeMismatchException else ()
        match len with
        | 80<rt> ->
          let v1 = this.Value |> toBigFloat
          let v2 = rhs.BigValue |> toBigFloat
          if v1 <= v2 then Value.T else Value.F
        | _ -> raise ArithTypeMismatchException

      member _.ValToString() =
        if n = 0I then "0x0"
        else "0x" + n.ToString("x").TrimStart('0')

      member _.IsPositive() = isBigPositive len n

      member _.IsNegative() = not <| isBigPositive len n

  and Value =

    static member T: IBV = BitVectorSmall(1UL, 1<rt>)

    static member F: IBV = BitVectorSmall(0UL, 1<rt>)

    static member Zero t =
      if t <= 64<rt> then BitVectorSmall(0UL, t) :> IBV
      else BitVectorBig(0I, t) :> IBV

end (* The end of BitVector module. *)

/// <summary>
/// Represents a bit vector, which is a sequence of bits. This type internally
/// uses two different representations to represent a bit vector depending on
/// its size. The numeric value of the bit vector is stored in little-endian
/// order. For those with less than or equal to 64 bits, it uses <c>uint64</c>.
/// For those with more than 64 bits, it uses <c>bigint</c>. This is to avoid
/// the overhead of using <c>bigint</c> for small numbers as most CPU operations
/// are in 64 bits or less. N.B. SmallValue becomes zero when the Length becomes
/// greater than 64. We intentionally do not sync SmallValue and BigValue for
/// performance reasons.
/// </summary>
[<AllowNullLiteral>]
type BitVector private(bv: IBV) =

  /// Returns a BitVector from a uint64 value.
  new(u64: uint64, bitLen) =
#if DEBUG
    if bitLen <= 0<rt> then raise ArithTypeMismatchException else ()
#endif
    if bitLen <= 64<rt> then
      let mask = UInt64.MaxValue >>> (64 - int bitLen)
      BitVector(BitVectorSmall(u64 &&& mask, bitLen))
    else
      BitVector(BitVectorBig(bigint u64, bitLen))

  /// Returns a BitVector from an int64 value.
  new(i64: int64, bitLen) =
#if DEBUG
    if bitLen <= 0<rt> then raise ArithTypeMismatchException else ()
#endif
    if bitLen <= 64<rt> then
      let mask = UInt64.MaxValue >>> (64 - int bitLen)
      BitVector(BitVectorSmall(uint64 i64 &&& mask, bitLen))
    else
      if i64 < 0L then
        BitVector(BitVectorBig((1I <<< int bitLen) - (- i64 |> bigint), bitLen))
      else
        BitVector(BitVectorBig(bigint i64, bitLen))

  /// Returns a BitVector from a uint32 value.
  new(u32: uint32, bitLen) =
    BitVector(uint64 u32, bitLen)

  /// Returns a BitVector from an int32 value.
  new(i32: int32, bitLen) =
    BitVector(int64 i32, bitLen)

  /// Returns a BitVector from a bigint value. We assume that the given bitLen
  /// is big enough to hold the given bigint. Otherwise, the resulting BitVector
  /// may contain an unexpected value.
  new(bi: bigint, bitLen) =
#if DEBUG
    if bitLen <= 0<rt> then nSizeErr bitLen else ()
#endif
    if bitLen <= 64<rt> then
      BitVector(uint64 bi, bitLen)
    else
      if bi.Sign < 0 then
        BitVector(BitVectorBig((1I <<< int bitLen) + bi, bitLen))
      else
        BitVector(BitVectorBig(bi, bitLen))

  /// Returns a BitVector from a byte array (in little endian).
  new(arr: byte[]) =
    match arr.Length with
    | 1 ->
      BitVector(uint64 arr[0], 8<rt>)
    | 2 ->
      let n = BitConverter.ToUInt16(arr, 0) |> uint64
      BitVector(n, 16<rt>)
    | 3 ->
      let n = BitConverter.ToUInt32(Array.append arr [| 0uy |], 0) |> uint64
      BitVector(n, 24<rt>)
    | 4 ->
      let n = BitConverter.ToUInt32(arr, 0) |> uint64
      BitVector(n, 32<rt>)
    | 5 ->
      let arr = Array.append arr [| 0uy; 0uy; 0uy |]
      let n = BitConverter.ToUInt64(arr, 0)
      BitVector(n, 40<rt>)
    | 6 ->
      let arr = Array.append arr [| 0uy; 0uy |]
      let n = BitConverter.ToUInt64(arr, 0)
      BitVector(n, 48<rt>)
    | 7 ->
      let arr = Array.append arr [| 0uy |]
      let n = BitConverter.ToUInt64(arr, 0)
      BitVector(n, 56<rt>)
    | 8 ->
      let n = BitConverter.ToUInt64(arr, 0)
      BitVector(n, 64<rt>)
    | sz ->
      if sz <= 0 then nSizeErr (sz * 8) else ()
      let arr = Array.append arr [| 0uy |]
      BitVector(bigint arr, sz * 8<rt>)

  member inline private _.V with get() = bv

  /// Returns the bit length of the BitVector.
  member _.Length with get() = bv.Length

  /// Returns the value of the BitVector as a uint64. If the BitVector is longer
  /// than 64 bits, this will return zero or something unexpected (the behavior
  /// is not guaranteed).
  member _.SmallValue with get() = bv.SmallValue

  /// Returns the value of the BitVector as a bigint.
  member _.BigValue with get() = bv.BigValue

  /// Returns boolean value indicating whether the BitVector is zero.
  member _.IsZero with get() = bv.IsZero

  /// Returns boolean value indicating whether the BitVector is one.
  member _.IsOne with get() = bv.IsOne

  /// Returns boolean value indicating whether the BitVector is false (1-bit
  /// zero).
  member _.IsFalse with get() = bv.Length = 1<rt> && bv.SmallValue = 0UL

  /// Checks if the given BitVector is "true".
  member _.IsTrue with get() = bv.Length = 1<rt> && bv.SmallValue = 1UL

  override _.Equals obj =
    match obj with
    | :? BitVector as rhs -> bv.Equals(rhs.V)
    | _ -> false

  override _.GetHashCode() = bv.GetHashCode()

  override _.ToString() = bv.ToString()

  /// Returns a BitVector representing a true (1-bit one) value.
  static member T = Value.T |> BitVector

  /// Returns a BitVector representing a false (1-bit zero) value.
  static member F = Value.F |> BitVector

  /// Returns a BitVector representing the maximum unsigned 8-bit value (255).
  static member MaxUInt8 = BitVector(0xFFUL, 8<rt>)

  /// Returns a BitVector representing the maximum unsigned 16-bit value.
  static member MaxUInt16 = BitVector(0xFFFFUL, 16<rt>)

  /// Returns a BitVector representing the maximum unsigned 32-bit value.
  static member MaxUInt32 = BitVector(0xFFFFFFFFUL, 32<rt>)

  /// Returns a BitVector representing the maximum unsigned 64-bit value.
  static member MaxUInt64 = BitVector(0xFFFFFFFFFFFFFFFFUL, 64<rt>)

  /// Returns zero (0) of the given bit length.
  static member Zero t =
    if t <= 64<rt> then BitVectorSmall(0UL, t) |> BitVector
    else BitVectorBig(0I, t) |> BitVector

  /// Returns one (1) of the given bit length.
  static member One t =
    if t <= 64<rt> then BitVectorSmall(1UL, t) |> BitVector
    else BitVectorBig(1I, t) |> BitVector

  /// Returns a smaller BitVector.
  static member Min(bv1: BitVector, bv2: BitVector) =
    if bv1.V.Lt bv2.V = Value.T then bv1 else bv2

  /// Returns a larger BitVector.
  static member Max(bv1: BitVector, bv2: BitVector) =
    if bv1.V.Gt bv2.V = Value.T then bv1 else bv2

  /// Returns a smaller BitVector (with signed comparison).
  static member SMin(bv1: BitVector, bv2: BitVector) =
    if bv1.V.SLt bv2.V = Value.T then bv1 else bv2

  /// Returns a larger BitVector (with signed comparison).
  static member SMax(bv1: BitVector, bv2: BitVector) =
    if bv1.V.SGt bv2.V = Value.T then bv1 else bv2

  /// Returns a uint64 value from a BitVector.
  static member ToUInt64(bv: BitVector) =
    bv.SmallValue

  /// Returns an int64 value from a BitVector.
  static member ToInt64(bv: BitVector) =
    bv.SmallValue |> int64

  /// Returns a uint32 value from a BitVector.
  static member ToUInt32(bv: BitVector) =
    bv.SmallValue |> uint32

  /// Returns an int32 value from a BitVector.
  static member ToInt32(bv: BitVector) =
    bv.SmallValue |> int32

  /// Returns a numeric value (bigint) from a BitVector.
  static member GetValue(bv: BitVector) =
    bv.BigValue

  /// Returns the type (length of the BitVector).
  static member GetType(bv: BitVector) = bv.Length

  /// Returns the string representation of a BitVector without appended type
  /// info.
  static member ValToString(n: BitVector) = n.V.ValToString()

  /// Returns the string representation of a BitVector.
  static member ToString(n: BitVector) = n.ToString()

  /// Returns a BitVector representing the maximum unsigned integer of the given
  /// RegType.
  static member UnsignedMax rt =
#if DEBUG
    if rt <= 0<rt> then nSizeErr rt else ()
#endif
    if rt <= 64<rt> then
      BitVectorSmall(UInt64.MaxValue >>> (64 - int rt), rt) |> BitVector
    else
      BitVectorBig((1I <<< int rt) - 1I, rt) |> BitVector

  /// Returns a BitVector representing the maximum signed integer of the given
  /// RegType.
  static member SignedMax rt =
#if DEBUG
    if rt <= 0<rt> then nSizeErr rt else ()
#endif
    if rt <= 64<rt> then
      BitVectorSmall(UInt64.MaxValue >>> (65 - int rt), rt) |> BitVector
    else
      BitVectorBig((1I <<< (int rt - 1)) - 1I, rt) |> BitVector

  /// Returns a BitVector representing the minimum signed integer of the given
  /// RegType.
  static member SignedMin rt =
#if DEBUG
    if rt <= 0<rt> then nSizeErr rt else ()
#endif
    if rt <= 64<rt> then BitVectorSmall(1UL <<< (int rt - 1), rt) |> BitVector
    else BitVectorBig(1I <<< (int rt - 1), rt) |> BitVector

  /// Checks if the given BitVector represents a unsigned max value?
  static member IsUnsignedMax(bv: BitVector) =
    BitVector.UnsignedMax bv.Length = bv

  /// Checks if the given BitVector represents a signed max value?
  static member IsSignedMax(bv: BitVector) =
    BitVector.SignedMax bv.Length = bv

  /// Checks if the given BitVector represents a signed min value?
  static member IsSignedMin(bv: BitVector) =
    BitVector.SignedMin bv.Length = bv

  /// Checks if the given BitVector is positive when interpreted as a signed
  /// integer?
  static member IsPositive(bv: BitVector) = bv.V.IsPositive()

  /// Checks if the given BitVector is negative when interpreted as a signed
  /// integer?
  static member IsNegative(bv: BitVector) = bv.V.IsNegative()

  /// Adds two BitVectors.
  static member Add(v1: BitVector, v2: BitVector) =
    v1.V.Add v2.V |> BitVector

  /// Subtracts two BitVectors.
  static member Sub(v1: BitVector, v2: BitVector) =
    v1.V.Sub v2.V |> BitVector

  /// Multiplies two BitVectors.
  static member Mul(v1: BitVector, v2: BitVector) =
    v1.V.Mul v2.V |> BitVector

  /// Divides two BitVectors (signed division).
  static member SDiv(v1: BitVector, v2: BitVector) =
    v1.V.SDiv v2.V |> BitVector

  /// Divides two BitVectors (unsigned division).
  static member Div(v1: BitVector, v2: BitVector) =
    v1.V.Div v2.V |> BitVector

  /// Calculates the signed modulo of two BitVectors.
  static member SModulo(v1: BitVector, v2: BitVector) =
    v1.V.SMod v2.V |> BitVector

  /// Calculates the unsigned modulo of a BitVector by another BitVector.
  static member Modulo(v1: BitVector, v2: BitVector) =
    v1.V.Mod v2.V |> BitVector

  /// Calculates bitwise AND of two BitVectors.
  static member And(v1: BitVector, v2: BitVector) =
    v1.V.And v2.V |> BitVector

  /// Calculates bitwise OR of two BitVectors.
  static member Or(v1: BitVector, v2: BitVector) =
    v1.V.Or v2.V |> BitVector

  /// Calculates bitwise XOR of two BitVectors.
  static member Xor(v1: BitVector, v2: BitVector) =
    v1.V.Xor v2.V |> BitVector

  /// Calculates logical shift-left of v1 by v2.
  static member Shl(v1: BitVector, v2: BitVector) =
    v1.V.Shl v2.V |> BitVector

  /// Calculates logical shift-right of v1 by v2.
  static member Shr(v1: BitVector, v2: BitVector) =
    v1.V.Shr v2.V |> BitVector

  /// Calculates arithmetic shift-right of v1 by v2.
  static member Sar(v1: BitVector, v2: BitVector) =
    v1.V.Sar v2.V |> BitVector

  /// Calculates bitwise NOT of a BitVector.
  static member Not(v1: BitVector) =
    v1.V.Not() |> BitVector

  /// Calculates the negation of a BitVector (as a signed integer).
  static member Neg(v1: BitVector) =
    v1.V.Neg() |> BitVector

  /// Casts a BitVector to a target length.
  static member Cast(v1: BitVector, targetLen) =
    v1.V.Cast targetLen |> BitVector

  /// Extracts a sub-BitVector from a BitVector at the specified position
  static member Extract(v1: BitVector, rt, pos) =
    v1.V.Extract(rt, pos) |> BitVector

  /// Concatenates two BitVectors.
  static member Concat(v1: BitVector, v2: BitVector) =
    v1.V.Concat v2.V |> BitVector

  /// Calculates signed extension of a BitVector.
  static member SExt(v1: BitVector, targetLen) =
    v1.V.SExt targetLen |> BitVector

  /// Calculates zero extension of a BitVector.
  static member ZExt(v1: BitVector, targetLen) =
    v1.V.ZExt targetLen |> BitVector

  /// Compares two BitVectors for equality.
  static member Eq(v1: BitVector, v2: BitVector) =
    v1.V.Eq v2.V |> BitVector

  /// Compares two BitVectors for inequality.
  static member Neq(v1: BitVector, v2: BitVector) =
    v1.V.Neq v2.V |> BitVector

  /// Checks if v1 is greater than v2.
  static member Gt(v1: BitVector, v2: BitVector) =
    v1.V.Gt v2.V |> BitVector

  /// Checks if v1 is greater than or equal to v2.
  static member Ge(v1: BitVector, v2: BitVector) =
    v1.V.Ge v2.V |> BitVector

  /// Checks if v1 is greater than v2 (considering them as signed integers).
  static member SGt(v1: BitVector, v2: BitVector) =
    v1.V.SGt v2.V |> BitVector

  /// Checks if v1 is greater than or equal to v2 (considering them as signed
  /// integers).
  static member SGe(v1: BitVector, v2: BitVector) =
    v1.V.SGe v2.V |> BitVector

  /// Checks if v1 is less than v2.
  static member Lt(v1: BitVector, v2: BitVector) =
    v1.V.Lt v2.V |> BitVector

  /// Checks if v1 is less than or equal to v2.
  static member Le(v1: BitVector, v2: BitVector) =
    v1.V.Le v2.V |> BitVector

  /// Checks if v1 is less than v2 (considering them as signed integers).
  static member SLt(v1: BitVector, v2: BitVector) =
    v1.V.SLt v2.V |> BitVector

  /// Checks if v1 is less than or equal to v2 (considering them as signed
  /// integers).
  static member SLe(v1: BitVector, v2: BitVector) =
    v1.V.SLe v2.V |> BitVector

  /// Calculates the absolute value of a BitVector (as a signed integer).
  static member Abs(v1: BitVector) =
    v1.V.Abs() |> BitVector

  /// Adds two BitVectors as floating point numbers.
  static member FAdd(v1: BitVector, v2: BitVector) =
    v1.V.FAdd v2.V |> BitVector

  /// Subtracts two BitVectors as floating point numbers.
  static member FSub(v1: BitVector, v2: BitVector) =
    v1.V.FSub v2.V |> BitVector

  /// Multiplies two BitVectors as floating point numbers.
  static member FMul(v1: BitVector, v2: BitVector) =
    v1.V.FMul v2.V |> BitVector

  /// Divides two BitVectors as floating point numbers.
  static member FDiv(v1: BitVector, v2: BitVector) =
    v1.V.FDiv v2.V |> BitVector

  /// Calculates the logarithm of v2 to the base v1 as floating point numbers.
  static member FLog(v1: BitVector, v2: BitVector) =
    v1.V.FLog v2.V |> BitVector

  /// Calculates the power of v1 raised to v2 as floating point numbers.
  static member FPow(v1: BitVector, v2: BitVector) =
    v1.V.FPow v2.V |> BitVector

  /// Converts a BitVector to a floating point number of the specified type.
  static member FCast(v1: BitVector, rt) =
    v1.V.FCast rt |> BitVector

  /// Converts a BitVector representing an integer to another BitVector
  /// representing a floating point number of the specified type.
  static member Itof(v1: BitVector, rt, isSigned) =
    v1.V.Itof(rt, isSigned) |> BitVector

  /// Converts a BitVector representing a floating point number to another
  /// BitVector representing an integer of the specified type with truncation.
  static member FtoiTrunc(v1: BitVector, rt) =
    v1.V.FtoiTrunc rt |> BitVector

  /// Converts a BitVector representing a floating point number to another
  /// BitVector representing an integer of the specified type with rounding.
  static member FtoiRound(v1: BitVector, rt) =
    v1.V.FtoiRound rt |> BitVector

  /// Converts a BitVector representing a floating point number to another
  /// BitVector representing an integer of the specified type with flooring.
  static member FtoiFloor(v1: BitVector, rt) =
    v1.V.FtoiFloor rt |> BitVector

  /// Converts a BitVector representing a floating point number to another
  /// BitVector representing an integer of the specified type with ceiling.
  static member FtoiCeil(v1: BitVector, rt) =
    v1.V.FtoiCeil rt |> BitVector

  /// Calculates the square root of a BitVector as a floating point number.
  static member FSqrt(v1: BitVector) =
    v1.V.FSqrt() |> BitVector

  /// Calculates the tangent of a BitVector as a floating point number.
  static member FTan(v1: BitVector) =
    v1.V.FTan() |> BitVector

  /// Calculates the sine of a BitVector as a floating point number.
  static member FSin(v1: BitVector) =
    v1.V.FSin() |> BitVector

  /// Calculates the cosine of a BitVector as a floating point number.
  static member FCos(v1: BitVector) =
    v1.V.FCos() |> BitVector

  /// Calculates the arctangent of a BitVector as a floating point number.
  static member FAtan(v1: BitVector) =
    v1.V.FATan() |> BitVector

  /// Compares two BitVectors as floating point numbers for greater than.
  static member FGt(v1: BitVector, v2: BitVector) =
    v1.V.FGt v2.V |> BitVector

  /// Compares two BitVectors as floating point numbers for greater than or
  /// equal.
  static member FGe(v1: BitVector, v2: BitVector) =
    v1.V.FGe v2.V |> BitVector

  /// Compares two BitVectors as floating point numbers for less than.
  static member FLt(v1: BitVector, v2: BitVector) =
    v1.V.FLt v2.V |> BitVector

  /// Compares two BitVectors as floating point numbers for less than or equal.
  static member FLe(v1: BitVector, v2: BitVector) =
    v1.V.FLe v2.V |> BitVector

  /// Adds a BitVector and a uint64 value.
  static member (+) (v1: BitVector, v2: uint64) =
    v1.V.Add v2 |> BitVector

  /// Subtracts a uint64 value from a BitVector.
  static member (-) (v1: BitVector, v2: uint64) =
    v1.V.Sub v2 |> BitVector

  /// Multiplies a BitVector by a uint64 value.
  static member (*) (v1: BitVector, v2: uint64) =
    v1.V.Mul v2 |> BitVector

  /// Divides a BitVector by a uint64 value (unsigned division).
  static member (/) (v1: BitVector, v2: uint64) =
    v1.V.Div v2 |> BitVector

  /// Calculates the modulo of a BitVector by a uint64 value (unsigned).
  static member (%) (v1: BitVector, v2: uint64) =
    v1.V.Mod v2 |> BitVector

  /// Calculates the bitwise AND of a BitVector and a uint64 value.
  static member (&&&) (v1: BitVector, v2: uint64) =
    v1.V.And v2 |> BitVector

  /// Calculates the bitwise OR of a BitVector and a uint64 value.
  static member (|||) (v1: BitVector, v2: uint64) =
    v1.V.Or v2 |> BitVector

  /// Calculates the bitwise XOR of a BitVector and a uint64 value.
  static member (^^^) (v1: BitVector, v2: uint64) =
    v1.V.Xor v2 |> BitVector

  /// Adds two BitVectors.
  static member (+) (v1: BitVector, v2: BitVector) =
    v1.V.Add v2.V |> BitVector

  /// Subtracts two BitVectors.
  static member (-) (v1: BitVector, v2: BitVector) =
    v1.V.Sub v2.V |> BitVector

  /// Multiplies two BitVectors.
  static member (*) (v1: BitVector, v2: BitVector) =
    v1.V.Mul v2.V |> BitVector

  /// Divides two BitVectors (unsigned division).
  static member (/) (v1: BitVector, v2: BitVector) =
    v1.V.Div v2.V |> BitVector

  /// Divides two BitVectors (signed division).
  static member (?/) (v1: BitVector, v2: BitVector) =
    v1.V.SDiv v2.V |> BitVector

  /// Calculates the unsigned modulo of a BitVector by another BitVector.
  static member (%) (v1: BitVector, v2: BitVector) =
    v1.V.Mod v2.V |> BitVector

  /// Calculates the signed modulo of a BitVector by another BitVector.
  static member (?%) (v1: BitVector, v2: BitVector) =
    v1.V.SMod v2.V |> BitVector

  /// Calculates the bitwise AND of two BitVectors.
  static member (&&&) (v1: BitVector, v2: BitVector) =
    v1.V.And v2.V |> BitVector

  /// Calculates the bitwise OR of two BitVectors.
  static member (|||) (v1: BitVector, v2: BitVector) =
    v1.V.Or v2.V |> BitVector

  /// Calculates the bitwise XOR of two BitVectors.
  static member (^^^) (v1: BitVector, v2: BitVector) =
    v1.V.Xor v2.V |> BitVector

  /// Calculates the bitwise NOT of a BitVector.
  static member (~~~) (v1: BitVector) =
    v1.V.Not() |> BitVector

  /// Calculates the negation of a BitVector (as a signed integer).
  static member (~-) (v1: BitVector) =
    v1.V.Neg() |> BitVector
