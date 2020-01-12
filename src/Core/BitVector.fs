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
    failwithf "Invalid BitVector value for its type: %s" (t.ToString ())

  let bigNull = 0I

/// BitVector is the fundamental data type for binary code, which is essentially
/// a bit vector. We want the size of a bit vector to be less than or equal to
/// 64 bits because bigint operation is slow, and most arithmetics on modern
/// architectures are in 64 bits any ways. For example, SIMD operations can also
/// be divided into a set of 64-bit operations.
///
/// N.B. Num becomes zero when the Length becomes greater than 64. We
/// intentionally do not sync Num and BigNum.
[<NoComparison; CustomEquality>]
type BitVector =
  private
    {
      Num    : uint64
      Length : RegType
      BigNum : bigint
    }
  override __.Equals obj =
    match obj with
    | :? BitVector as obj ->
      __.Length = obj.Length && __.Num = obj.Num && __.BigNum = obj.BigNum
    | _ -> false

  override __.GetHashCode () =
    hash (__.Num, __.Length, __.BigNum)

  override __.ToString () =
    __.ValToString () + ":" + RegType.toString __.Length

  member __.ValToString () =
    if __.Length <= 64<rt> then "0x" + __.Num.ToString ("X")
    elif __.Num = 0UL && __.BigNum = 0I then "0x0"
    else "0x" + __.BigNum.ToString("X").TrimStart('0')

  static member inline BOp (v: BitVector) (b: uint64) op bigop =
    let a = v.Num
    match v.Length with
    | 8<rt> -> { v with Num = op a b |> uint8 |> uint64 }
    | 16<rt> -> { v with Num = op a b |> uint16 |> uint64 }
    | 32<rt> -> { v with Num = op a b |> uint32 |> uint64 }
    | 64<rt> -> { v with Num = op a b }
    | len when len > 64<rt> ->
      let n1 = v.BigNum
      let n2 = bigint b
      let a = bigint.op_BitwiseAnd (bigop (n1, n2), RegType.getMask v.Length)
      { v with BigNum = a }
    | _ -> { v with Num = op a b &&& uint64 (RegType.getMask v.Length) }

  static member (+) (v: BitVector, b: uint64) =
    BitVector.BOp v b (+) (bigint.Add)

  static member (-) (v: BitVector, b: uint64) =
    BitVector.BOp v b (-) (bigint.Subtract)

  static member (*) (v: BitVector, b: uint64) =
    BitVector.BOp v b (*) (bigint.Multiply)

  static member (&&&) (v: BitVector, b: uint64) =
    BitVector.BOp v b (&&&) (bigint.op_BitwiseAnd)

  static member (|||) (v: BitVector, b: uint64) =
    BitVector.BOp v b (|||) (bigint.op_BitwiseOr)

  static member (^^^) (v: BitVector, b: uint64) =
    BitVector.BOp v b (^^^) (bigint.op_ExclusiveOr)

  static member (/) (v: BitVector, b: uint64) =
    BitVector.BOp v b (/) (bigint.Divide)

  static member (%) (v: BitVector, b: uint64) =
    BitVector.BOp v b (%) (bigint.op_Modulus)

  static member (+) (v1: BitVector, v2: BitVector) =
    BitVector.add v1 v2

  static member (-) (v1: BitVector, v2: BitVector) =
    BitVector.sub v1 v2

  static member (*) (v1: BitVector, v2: BitVector) =
    BitVector.mul v1 v2

  static member (&&&) (v1: BitVector, v2: BitVector) =
    BitVector.band v1 v2

  static member (|||) (v1: BitVector, v2: BitVector) =
    BitVector.bor v1 v2

  static member (^^^) (v1: BitVector, v2: BitVector) =
    BitVector.bxor v1 v2

  static member (~~~) (v: BitVector) =
    BitVector.bnot v

  static member (/) (v1: BitVector, v2: BitVector) =
    BitVector.sdiv v1 v2

  static member (|/|) (v1: BitVector, v2: BitVector) =
    BitVector.div v1 v2

  static member (%) (v1: BitVector, v2: BitVector) =
    BitVector.smodulo v1 v2

  static member (|%|) (v1: BitVector, v2: BitVector) =
    BitVector.modulo v1 v2

  static member (~-) (v: BitVector) =
    BitVector.neg v

  [<CompiledName("OfUInt64")>]
  static member ofUInt64 (i: uint64) typ =
    match typ with
#if DEBUG
    | typ when typ <= 0<rt> -> nSizeErr typ
#endif
    | 1<rt> when i = 1UL -> { Num = 1UL; Length = typ; BigNum = bigNull }
    | 1<rt> when i = 0UL -> { Num = 0UL; Length = typ; BigNum = bigNull }
    | 2<rt> -> { Num = i &&& 0x3UL; Length = typ; BigNum = bigNull }
    | 4<rt> -> { Num = i &&& 0xFUL; Length = typ; BigNum = bigNull }
    | 8<rt> -> { Num = uint8 i |> uint64; Length = typ; BigNum = bigNull }
    | 16<rt> -> { Num = uint16 i |> uint64; Length = typ; BigNum = bigNull }
    | 32<rt> -> { Num = uint32 i |> uint64; Length = typ; BigNum = bigNull }
    | 64<rt> -> { Num = i; Length = typ; BigNum = bigNull }
    | t when t < 64<rt> ->
      { Num = i &&& (RegType.getUInt64Mask t); Length = typ; BigNum = bigNull }
    | _ -> { Num = 0UL; Length = typ; BigNum = bigint i}

  [<CompiledName("OfInt64")>]
  static member ofInt64 (i: int64) typ =
#if DEBUG
    if typ <= 0<rt> then nSizeErr typ else ()
#endif
    if typ <= 64<rt> then BitVector.ofUInt64 (uint64 i) typ
    else
      if i < 0L then
        let n = bigint.Pow (2I, int typ) - ((~-) i |> uint64 |> bigint)
        { Num = 0UL; Length = typ; BigNum = n }
      else
        { Num = 0UL; Length = typ; BigNum = bigint i }

  [<CompiledName("OfUInt32")>]
  static member ofUInt32 (i: uint32) typ =
#if DEBUG
    if typ <= 0<rt> then nSizeErr typ else ()
#endif
    BitVector.ofUInt64 (uint64 i) typ

  [<CompiledName("OfInt32")>]
  static member ofInt32 (i: int32) typ =
#if DEBUG
    if typ <= 0<rt> then nSizeErr typ else ()
#endif
    BitVector.ofInt64 (int64 i) typ

  [<CompiledName("OfUBInt")>]
  static member ofUBInt (i: bigint) typ =
#if DEBUG
    if typ <= 0<rt> then nSizeErr typ else ()
#endif
    if typ <= 64<rt> then BitVector.ofUInt64 (uint64 i) typ
    else { Num = 0UL; Length = typ; BigNum = i }

  [<CompiledName("OfArr")>]
  static member ofArr (arr: byte []) =
    match Array.length arr with
    | 1 ->
      { Num = uint64 arr.[0]; Length = 8<rt>; BigNum = bigNull }
    | 2 ->
      let n = BitConverter.ToUInt16 (arr, 0) |> uint64
      { Num = n; Length = 16<rt>; BigNum = bigNull }
    | 3 ->
      let arr = Array.append arr [| 0uy |]
      let n = BitConverter.ToUInt32 (arr, 0) |> uint64
      { Num = n; Length = 24<rt>; BigNum = bigNull }
    | 4 ->
      let n = BitConverter.ToUInt32 (arr, 0) |> uint64
      { Num = n; Length = 32<rt>; BigNum = bigNull }
    | 5 ->
      let arr = Array.append arr [| 0uy; 0uy; 0uy |]
      let n = BitConverter.ToUInt64 (arr, 0)
      { Num = n; Length = 40<rt>; BigNum = bigNull }
    | 6 ->
      let arr = Array.append arr [| 0uy; 0uy |]
      let n = BitConverter.ToUInt64 (arr, 0)
      { Num = n; Length = 48<rt>; BigNum = bigNull }
    | 7 ->
      let arr = Array.append arr [| 0uy |]
      let n = BitConverter.ToUInt64 (arr, 0)
      { Num = n; Length = 56<rt>; BigNum = bigNull }
    | 8 ->
      let n = BitConverter.ToUInt64 (arr, 0)
      { Num = n; Length = 64<rt>; BigNum = bigNull }
    | sz when sz > 8 ->
      let arr = Array.append arr [| 0uy |]
      { Num = 0UL; Length = sz * 8<rt>; BigNum = bigint arr }
    | sz -> nSizeErr (sz * 8)

  [<CompiledName("OfBv")>]
  static member ofBv bv typ =
#if DEBUG
    if typ <= 0<rt> then nSizeErr typ else ()
#endif
    { bv with Length = typ }

  [<CompiledName("ToUInt64")>]
  static member toUInt64 bv =
    if bv.Length <= 64<rt> then bv.Num
    elif bv.BigNum > bigint 0xFFFFFFFFFFFFFFFFUL then nSizeErr bv.Length
    else bv.BigNum |> uint64

  [<CompiledName("ToInt64")>]
  static member toInt64 bv = BitVector.toUInt64 bv |> int64

  [<CompiledName("ToUInt32")>]
  static member toUInt32 bv = BitVector.toUInt64 bv |> uint32

  [<CompiledName("ToInt32")>]
  static member toInt32 bv = BitVector.toInt64 bv |> int32

  [<CompiledName("GetValue")>]
  static member getValue bv =
    if bv.Length <= 64<rt> then bigint bv.Num else bv.BigNum

  [<CompiledName("GetType")>]
  static member getType (bv: BitVector) = bv.Length

  [<CompiledName("Zero")>]
  static member zero (t: RegType) = { Num = 0UL; Length = t; BigNum = bigNull }

  [<CompiledName("One")>]
  static member one (t: RegType) = { Num = 1UL; Length = t; BigNum = bigNull }

  /// True.
  static member T = BitVector.one 1<rt>

  /// False.
  static member F = BitVector.zero 1<rt>

  static member inline shiftRightAndCheckOne n len =
    bigint.op_BitwiseAnd (bigint.op_RightShift (n, len), 1I) = 0I

  [<CompiledName("IsPositive")>]
  static member isPositive bv =
    let len = int bv.Length
    if len <= 64 then ((bv.Num >>> (len - 1)) &&& 1UL) = 0UL
    else BitVector.shiftRightAndCheckOne bv.BigNum (len - 1)

  [<CompiledName("IsNegative")>]
  static member isNegative bv = BitVector.isPositive bv |> not

  static member inline castSmall n rt =
    match rt with
#if DEBUG
    | typ when typ <= 0<rt> -> nSizeErr typ
#endif
    | 1<rt> -> n &&& 1UL
    | 2<rt> -> n &&& 0x3UL
    | 4<rt> -> n &&& 0xFUL
    | 8<rt> -> n &&& 0xFFUL
    | 16<rt> -> n &&& 0xFFFFUL
    | 32<rt> -> n &&& 0xFFFFFFFFUL
    | 64<rt> -> n
    | t when t < 64<rt> -> n &&& (RegType.getUInt64Mask rt)
    | sz -> nSizeErr sz

  static member inline castBig n newLen =
    (RegType.getMask newLen) &&& n

  static member inline IntBinOp (op: uint64 -> uint64 -> uint64) opBigFn bv1 bv2 =
    let n1, n2 = bv1.Num, bv2.Num
    if bv1.Length <> bv2.Length then raise ArithTypeMismatchException
    elif bv1.Length <= 64<rt> then
      { bv1 with Num = BitVector.castSmall (op n1 n2) bv1.Length }
    else
      let n = opBigFn (bv1.BigNum, bv2.BigNum)
      { bv1 with BigNum = BitVector.castBig n bv1.Length }

  (* 80 bit floating point operations are currently not supported. *)
  static member inline FloatBinOp op32 op64 bv1 bv2 =
    match bv1.Length, bv2.Length with
    | 32<rt>, 32<rt> ->
      let f1 = int32 bv1.Num |> BitConverter.GetBytes
      let f2 = int32 bv2.Num |> BitConverter.GetBytes
      let f1 = BitConverter.ToSingle (f1, 0)
      let f2 = BitConverter.ToSingle (f2, 0)
      let result = op32 f1 f2 |> float32 |> BitConverter.GetBytes
      { bv1 with Num = BitConverter.ToInt32 (result, 0) |> uint64 }
    | 64<rt>, 64<rt> ->
      let f1 = BitConverter.Int64BitsToDouble <| int64 bv1.Num
      let f2 = BitConverter.Int64BitsToDouble <| int64 bv2.Num
      let result = op64 f1 f2 |> float |> BitConverter.DoubleToInt64Bits
      { bv1 with Num = uint64 result }
    | _ -> raise ArithTypeMismatchException



  [<CompiledName("Add")>]
  static member add v1 v2 = BitVector.IntBinOp (+) (bigint.Add) v1 v2

  [<CompiledName("Sub")>]
  static member sub v1 v2 = BitVector.IntBinOp (-) (bigint.Subtract) v1 v2

  [<CompiledName("Mul")>]
  static member mul v1 v2 = BitVector.IntBinOp (*) (bigint.Multiply) v1 v2

  [<CompiledName("FAdd")>]
  static member fAdd v1 v2 = BitVector.FloatBinOp (+) (+) v1 v2

  [<CompiledName("FSub")>]
  static member fSub v1 v2 = BitVector.FloatBinOp (-) (-) v1 v2

  [<CompiledName("FMul")>]
  static member fMul v1 v2 = BitVector.FloatBinOp (*) (*) v1 v2

  [<CompiledName("Neg")>]
  static member neg bv =
    match bv.Length with
    | 1<rt> -> bv
    | 8<rt> -> { bv with Num = (- (int8 bv.Num)) |> uint8 |> uint64 }
    | 16<rt> -> { bv with Num = (- (int16 bv.Num)) |> uint16 |> uint64 }
    | 32<rt> -> { bv with Num = (- (int32 bv.Num)) |> uint32 |> uint64 }
    | 64<rt> -> { bv with Num = (- (int64 bv.Num)) |> uint64 }
    | t when t < 64<rt> ->
      { bv with Num = ((~~~ bv.Num) + 1UL) &&& (RegType.getUInt64Mask t)}
    | _ ->
       let n = bigint.Pow (2I, int bv.Length) - bv.BigNum
       { bv with BigNum = BitVector.castBig n bv.Length }

  [<CompiledName("BitwiseAnd")>]
  static member band v1 v2 = BitVector.IntBinOp (&&&) (bigint.op_BitwiseAnd) v1 v2

  [<CompiledName("BitwiseOr")>]
  static member bor v1 v2 = BitVector.IntBinOp (|||) (bigint.op_BitwiseOr) v1 v2

  [<CompiledName("BitwiseXor")>]
  static member bxor v1 v2 = BitVector.IntBinOp (^^^) (bigint.op_ExclusiveOr) v1 v2

  [<CompiledName("BitwiseNot")>]
  static member bnot bv =
    if bv.Length = 1<rt> then
      { bv with Num = if bv.Num = 0UL then 1UL else 0UL }
    elif bv.Length <= 64<rt> then
      { bv with Num = BitVector.castSmall (~~~ bv.Num) bv.Length }
    else
      { bv with BigNum = bigint.Pow (2I, int bv.Length) - bv.BigNum - 1I }

  [<CompiledName("EQ")>]
  static member eq v1 v2 =
    if v1.Length = v2.Length && v1.Num = v2.Num && v1.BigNum = v2.BigNum then
      BitVector.T
    else BitVector.F

  [<CompiledName("NEQ")>]
  static member neq v1 v2 =
    if v1.Length = v2.Length && v1.Num = v2.Num && v1.BigNum = v2.BigNum then
      BitVector.F
    else BitVector.T

  static member inline unsignedComp v1 v2 op bigop =
    if v1.Length <> v2.Length then raise ArithTypeMismatchException
    elif v1.Length <= 64<rt> then
      if op v1.Num v2.Num then BitVector.T else BitVector.F
    else
      if bigop v1.BigNum v2.BigNum then BitVector.T else BitVector.F

  [<CompiledName("GT")>]
  static member gt v1 v2 = BitVector.unsignedComp v1 v2 (>) (>)

  [<CompiledName("GE")>]
  static member ge v1 v2 = BitVector.unsignedComp v1 v2 (>=) (>=)

  [<CompiledName("LT")>]
  static member lt v1 v2 = BitVector.unsignedComp v1 v2 (<) (<)

  [<CompiledName("LE")>]
  static member le v1 v2 = BitVector.unsignedComp v1 v2 (<=) (<=)

  static member inline signedComp v1 v2 op8 op16 op32 op64 opBigFn =
    if v1.Length <> v2.Length then raise ArithTypeMismatchException
    match v1.Length with
    | 8<rt> ->
      if op8 (int8 v1.Num) (int8 v2.Num) then BitVector.T else BitVector.F
    | 16<rt> ->
      if op16 (int16 v1.Num) (int16 v2.Num) then BitVector.T else BitVector.F
    | 32<rt> ->
      if op32 (int32 v1.Num) (int32 v2.Num) then BitVector.T else BitVector.F
    | 64<rt> ->
      if op64 (int64 v1.Num) (int64 v2.Num) then BitVector.T else BitVector.F
    | t when t < 64<rt> ->
      if BitVector.isPositive v1 && BitVector.isNegative v2 then BitVector.F
      elif BitVector.isNegative v1 && BitVector.isPositive v2 then BitVector.T
      elif BitVector.isNegative v1 && BitVector.isNegative v2 then
        if op64 (int64 v1.Num) (int64 v2.Num) then BitVector.F
        else BitVector.T
      else
        if op64 (int64 v1.Num) (int64 v2.Num) then BitVector.T
        else BitVector.F
    | _ ->
      if BitVector.isPositive v1 && BitVector.isNegative v2 then BitVector.F
      elif BitVector.isNegative v1 && BitVector.isPositive v2 then BitVector.T
      elif BitVector.isNegative v1 && BitVector.isNegative v2 then
        if opBigFn (v1.BigNum, v2.BigNum) then BitVector.F
        else BitVector.T
      else
        if opBigFn (v1.BigNum, v2.BigNum) then BitVector.T
        else BitVector.F

  [<CompiledName("SLT")>]
  static member slt v1 v2 =
    BitVector.signedComp v1 v2 (<) (<) (<) (<) bigint.op_LessThan

  [<CompiledName("SLE")>]
  static member sle v1 v2 =
    BitVector.signedComp v1 v2 (<=) (<=) (<=) (<=) (bigint.op_LessThanOrEqual)

  [<CompiledName("SGT")>]
  static member sgt v1 v2 = BitVector.slt v2 v1

  [<CompiledName("SGE")>]
  static member sge v1 v2 = BitVector.sle v2 v1

  [<CompiledName("Cast")>]
  static member cast (bv: BitVector) newLen =
    if bv.Length = newLen then bv
    elif bv.Length <= 64<rt> && newLen <= 64<rt> then
      { bv with Num = BitVector.castSmall bv.Num newLen; Length = newLen }
    elif bv.Length <= 64<rt> && newLen > 64<rt> then
      { Num = 0UL; Length = newLen
        BigNum = BitVector.castBig (bigint bv.Num) newLen }
    elif bv.Length > 64<rt> && newLen <= 64<rt> then
      { Num = BitVector.castSmall (BitVector.castBig bv.BigNum newLen |> uint64)
                                  newLen;
        Length = newLen; BigNum = bigNull }
    else
      { bv with BigNum = BitVector.castBig bv.BigNum newLen; Length = newLen }

  [<CompiledName("Extract")>]
  static member extract (bv: BitVector) newLen pos =
    if bv.Length = newLen then bv
    elif bv.Length <= 64<rt> then
      { bv with Num = BitVector.castSmall (bv.Num >>> pos) newLen
                Length = newLen }
    elif bv.Length > 64<rt> && newLen <= 64<rt> then
      { Num = BitVector.castSmall (BitVector.castBig (bv.BigNum >>> pos) newLen
                                   |> uint64) newLen;
        Length = newLen; BigNum = bigNull }
    else
      { bv with
          BigNum = BitVector.castBig (bv.BigNum >>> pos) newLen
          Length = newLen }

  [<CompiledName("Div")>]
  static member div v1 v2 = BitVector.IntBinOp (/) (bigint.Divide) v1 v2

  [<CompiledName("FDiv")>]
  static member fDiv v1 v2 = BitVector.FloatBinOp (/) (/) v1 v2

  [<CompiledName("Sdiv")>]
  static member sdiv v1 v2 =
    let sign1, sign2 = BitVector.isPositive v1, BitVector.isPositive v2
    let bv1 = if sign1 then v1 else BitVector.neg v1
    let bv2 = if sign2 then v2 else BitVector.neg v2
    let bv = BitVector.div bv1 bv2
    if sign1 = sign2 then bv
    else BitVector.neg bv

  [<CompiledName("Modulo")>]
  static member modulo v1 v2 = BitVector.IntBinOp (%) (bigint.op_Modulus) v1 v2

  [<CompiledName("SModulo")>]
  static member smodulo v1 v2 =
    let sign1, sign2 = BitVector.isPositive v1, BitVector.isPositive v2
    let bv1 = if sign1 then v1 else BitVector.neg v1
    let bv2 = if sign2 then v2 else BitVector.neg v2
    let bv = BitVector.modulo bv1 bv2
    if BitVector.isZero bv then bv
    else
      match sign1, sign2 with
      | true, true -> bv
      | true, false -> BitVector.add bv v2
      | false, true -> BitVector.sub v2 bv
      | false, false -> BitVector.neg bv

  [<CompiledName("Shl")>]
  static member shl v1 v2 =
    let len = v1.Length
    if len <> v2.Length then raise ArithTypeMismatchException
    elif len = 1<rt> then
      { v1 with Num = if v2.Num = 0UL then v1.Num else 0UL }
    elif len <= 64<rt> then
      { v1 with Num = if v2.Num >= 64UL then 0UL
                      else BitVector.castSmall (v1.Num <<< int v2.Num) len }
    else
      let n = bigint.op_LeftShift (v1.BigNum, int v2.BigNum)
      { v1 with BigNum = BitVector.castBig n len }

  [<CompiledName("Shr")>]
  static member shr v1 v2 =
    if v1.Length <> v2.Length then raise ArithTypeMismatchException
    elif v1.Length = 1<rt> then
      { v1 with Num = if v2.Num = 0UL then v1.Num else 0UL }
    elif v1.Length <= 64<rt> then
      (* In .NET, 1UL >>> 63 = 0, but 1UL >>> 64 = 1 *)
      { v1 with Num = v1.Num >>> min (int v2.Num) 0x3f }
    else
      { v1 with BigNum = bigint.op_RightShift (v1.BigNum, int v2.BigNum) }

  [<CompiledName("Sar")>]
  static member sar v1 v2 =
    let n1, n2 = v1.Num, v2.Num
    let l1, l2 = v1.Length, v2.Length
    if l1 <> l2 then raise ArithTypeMismatchException
    match l1 with
    | 1<rt> -> { v1 with Num = if n2 = 0UL then n1 else 0UL }
    | 8<rt> ->
      { v1 with Num = (int8 n1 >>> min (int n2) 0x7) |> uint8 |> uint64 }
    | 16<rt> ->
      { v1 with Num = (int16 n1 >>> min (int n2) 0xf) |> uint16 |> uint64 }
    | 32<rt> ->
      { v1 with Num = (int32 n1 >>> min (int n2) 0x1f) |> uint32 |> uint64 }
    | 64<rt> ->
      { v1 with Num = (int64 n1 >>> min (int n2) 0x3f) |> uint64 }
    | t when t < 64<rt> ->
      let res = BitVector.shr v1 v2
      if BitVector.isPositive v1 then res
      else
        let pad = RegType.getUInt64Mask v1.Length
        let pad =
          pad - (RegType.getUInt64Mask (v1.Length - (1<rt> * int v2.Num)))
        { res with Num = (res.Num ||| pad) }
    | _ ->
      let res = BitVector.shr v1 v2
      if BitVector.isPositive v1 then res
      else
        let pad = BigInteger.getMask (int v1.Length)
        let pad = pad - (BigInteger.getMask (int v1.Length - int v2.BigNum))
        { res with BigNum = (bigint.op_BitwiseOr (res.BigNum, pad)) }

  [<CompiledName("Concat")>]
  static member concat v1 v2 =
    let len1 = v1.Length
    let len2 = v2.Length
    let targetLen = len1 + len2
    if targetLen <= 64<rt> then
      let n = (v1.Num <<< int len2) + v2.Num
      { Num = n; Length = targetLen; BigNum = bigNull }
    else
      let v1 = BitVector.getValue v1
      let v2 = BitVector.getValue v2
      let n = bigint.op_LeftShift (v1, int len2) + v2
      { Num = 0UL; Length = targetLen; BigNum = n }

  [<CompiledName("Sext")>]
  static member sext bv typ =
    let bv' = BitVector.cast bv typ
    if BitVector.isPositive bv then bv'
    else
      let mask =
        BitVector.ofUBInt (RegType.getMask typ - RegType.getMask bv.Length) typ
      BitVector.add mask bv'

  [<CompiledName("Zext")>]
  static member zext bv t = BitVector.cast bv t

  [<CompiledName("Abs")>]
  static member abs bv =
    if BitVector.isPositive bv then bv else BitVector.neg bv

  [<CompiledName("Min")>]
  static member min bv1 bv2 =
    if BitVector.lt bv1 bv2 = BitVector.T then bv1
    else bv2

  [<CompiledName("Max")>]
  static member max bv1 bv2 =
    if BitVector.gt bv1 bv2 = BitVector.T then bv1
    else bv2

  [<CompiledName("Smin")>]
  static member smin bv1 bv2 =
    if BitVector.slt bv1 bv2 = BitVector.T then bv1
    else bv2

  [<CompiledName("Smax")>]
  static member smax bv1 bv2 =
    if BitVector.sgt bv1 bv2 = BitVector.T then bv1
    else bv2

  static member maxNum8 = BitVector.ofUInt64 0xFFUL 8<rt>
  static member maxNum16 = BitVector.ofUInt64 0xFFFFUL 16<rt>
  static member maxNum32 = BitVector.ofUInt64 0xFFFFFFFFUL 32<rt>
  static member maxNum64 = BitVector.ofUInt64 0xFFFFFFFFFFFFFFFFUL 64<rt>

  static member midNum8 =  BitVector.ofUInt64 0x80UL 8<rt>
  static member midNum16 = BitVector.ofUInt64 0x8000UL 16<rt>
  static member midNum32 = BitVector.ofUInt64 0x80000000UL 32<rt>
  static member midNum64 = BitVector.ofUInt64 0x8000000000000000UL 64<rt>

  [<CompiledName("UnsignedMax")>]
  static member unsignedMax rt =
    match rt with
#if DEBUG
    | typ when typ <= 0<rt> -> nSizeErr typ
#endif
    | 8<rt> -> BitVector.maxNum8
    | 16<rt> -> BitVector.maxNum16
    | 32<rt> -> BitVector.maxNum32
    | 64<rt> -> BitVector.maxNum64
    | t when t < 64<rt> -> BitVector.ofUInt64 (RegType.getUInt64Mask rt) rt
    | _ -> { Num = 0UL; Length = rt; BigNum = RegType.getMask rt }

  [<CompiledName("UnsignedMin")>]
  static member unsignedMin rt =
#if DEBUG
    if rt <= 0<rt> then nSizeErr rt else ()
#endif
    BitVector.zero rt

  [<CompiledName("SignedMax")>]
  static member signedMax rt =
    match rt with
#if DEBUG
    | typ when typ <= 0<rt> -> nSizeErr typ
#endif
    | 8<rt> -> BitVector.midNum8 - 1UL
    | 16<rt> -> BitVector.midNum16 - 1UL
    | 32<rt> -> BitVector.midNum32 - 1UL
    | 64<rt> -> BitVector.midNum64 - 1UL
    | t when t < 64<rt> ->
      BitVector.ofUInt64 (RegType.getUInt64Mask (rt - 1<rt>)) rt
    | _ ->
      { Num = 0UL ; Length = rt; BigNum = RegType.getMask (rt - 1<rt>)}

  [<CompiledName("SignedMin")>]
  static member signedMin rt =
    match rt with
#if DEBUG
    | typ when typ <= 0<rt> -> nSizeErr typ
#endif
    | 8<rt> -> BitVector.midNum8
    | 16<rt> -> BitVector.midNum16
    | 32<rt> -> BitVector.midNum32
    | 64<rt> -> BitVector.midNum64
    | t when t < 64<rt> -> BitVector.ofUInt64 (1UL <<< int (rt - 1<rt>)) rt
    | _ -> { Num = 0UL; Length = rt; BigNum = 1I <<< int (rt - 1<rt>) }

  [<CompiledName("IsUnsignedMax")>]
  static member isUnsignedMax bv =
    BitVector.unsignedMax bv.Length = bv

  [<CompiledName("IsSignedMax")>]
  static member isSignedMax bv =
    BitVector.signedMax bv.Length = bv

  [<CompiledName("IsSignedMin")>]
  static member isSignedMin bv =
    BitVector.signedMin bv.Length = bv

  [<CompiledName("IsZero")>]
  static member isZero bv =
    if bv.Length <= 64<rt> then bv.Num = 0UL
    else bv.BigNum = 0I

  [<CompiledName("IsOne")>]
  static member isOne bv =
    if bv.Length <= 64<rt> then bv.Num = 1UL
    else bv.BigNum = 1I

  [<CompiledName("IsFalse")>]
  static member isFalse bv =
    bv = BitVector.F

  [<CompiledName("IsTrue")>]
  static member isTrue bv =
    bv = BitVector.T

  [<CompiledName("IsNum")>]
  static member isNum bv n =
    if bv.Length <= 64<rt> then bv.Num = n
    else bv.BigNum = bigint n

  [<CompiledName("ValToString")>]
  static member valToString (n: BitVector) = n.ValToString ()

  [<CompiledName("ToString")>]
  static member toString (n: BitVector) = n.ToString ()

// vim: set tw=80 sts=2 sw=2:
