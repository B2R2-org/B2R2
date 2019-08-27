(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Mehdi Aghakishiyev <agakisiyev.mehdi@gmail.com>
          Sang Kil Cha <sangkilc@kaist.ac.kr>

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

namespace B2R2.Utilities.BinExplorer

open System.Numerics
open Size
open DataType
open Numbers
open SimpleArithHelper
open SimpleArithReference
open FParsec

module SimpleArithOperate =
  /// Getting common datatype for operations between two different types.
  /// If either side of operation is float or error, common type will always be
  /// float or error.
  let getUpcast a b =
    let priority1, type1 = getPriority (getSize (fst a)), getType (fst a)
    let priority2, type2 = getPriority (getSize (fst b)), getType (fst b)
    if type1 = type2 then
      if priority1 > priority2 then (fst a) else (fst b)
    elif type1 = 2 || type2 = 2 then
      if priority1 > priority2 then (fst a) else (fst b)
    elif type1 = 3 || type2 = 3 then
      if priority1 > priority2 then (fst a) else (fst b)
    else
      let unsigned_val = if (type1 = 1) then a else b
      let signed_val = if (type1 = 0) then a else b
      let upR = getPriority (getSize (fst unsigned_val))
      let pR = getPriority (getSize (fst signed_val))
      let ur1, ur2 = getIntegerRange (fst unsigned_val)
      let r1, r2 = getIntegerRange (fst signed_val)
      let uvalue = BigInteger.Parse (getValue (snd unsigned_val))
      let svalue = BigInteger.Parse (getValue (snd signed_val))
      if pR >= upR && uvalue >= r1 && uvalue <= r2 then
        fst signed_val
      elif upR >= pR && svalue >= ur1 && svalue <= ur2 then
        fst unsigned_val
      else
        getNextSignedInt (max upR pR)

  /// Maintaining integer overflow.
  let fixValue rep value =
    match rep with
    | Signed _ ->
      let r1, r2 = getIntegerRange rep
      if value >= r1 && value <= r2 then
        wrapValue rep value
      elif value > r2 then
        let cycle = abs r1 + r2 + 1I
        let remainder = value % cycle
        if remainder <= r2 then
          wrapValue rep remainder
        else
          let value = remainder - cycle
          wrapValue rep value
      else
        let cycle = abs r1 + r2 + 1I
        let remainder = value % cycle
        if remainder >= r1 then
          wrapValue rep remainder
        else
          let value = remainder + cycle
          wrapValue rep value
    | Unsigned _ ->
      let r1, r2 = getIntegerRange rep
      if value >= r1 && value <= r2 then
        wrapValue rep value
      elif value > r2 then
        let value = value % (r2 + 1I)
        wrapValue rep value
      else
        let value = value % (r2 + 1I)
        if value = 0I then
          wrapValue rep value
        else
          let value = r2 + value + 1I
          wrapValue rep value
    | _ -> CError Input, NError ("Wrong Input", 1L)

  let convertfromFloat rep (value : float) =
    match rep with
    | Signed B8 -> Signed B8, I8 (int8(value))
    | Unsigned B8 -> Unsigned B8, UI8 (uint8(value))
    | Signed B16 -> Signed B16, I16 (int16(value))
    | Unsigned B16 -> Unsigned B16, UI16 (uint16(value))
    | Signed B32 -> Signed B32, I32 (int(value))
    | Unsigned B32 -> Unsigned B32, UI32 (uint32(value))
    | Signed B64 -> Signed B64, I64 (int64(value))
    | Unsigned B64 -> Unsigned B64, UI64 (uint64(value))
    | Signed B128 -> fixValue (Signed B128) (bigint value)
    | Unsigned B128 -> fixValue (Unsigned B128) (bigint value)
    | Signed B256 -> fixValue (Signed B256) (bigint value)
    | Unsigned B256 -> fixValue (Unsigned B256) (bigint value)
    | Float BF32 -> Float BF32, F32 (float32(value))
    | Float BF64 -> Float BF64, F64 (float(value))
    | _ -> CError Input, NError ("Error", 1L)

  let convertFromBigint rep value =
    match rep with
    | Signed _ | Unsigned _ -> fixValue rep value
    | Float BF32 | Float BF64 ->
      if value >= ref "floatMin" && value <= ref "floatMax" then
        convertfromFloat rep (float value)
      else
        (CError OutofRange, NError ("Out of range", 1L))
    | _ -> CError Input, NError ("Error", 1L)

  /// Casting values.
  let convert curRep nextRep value =
    match curRep with
    | Signed _ | Unsigned _ ->
      let value = BigInteger.Parse value
      convertFromBigint nextRep value
    | Float _ -> convertfromFloat nextRep (float(value))
    | CError a -> CError a, NError (value, 1L)

  let shift val1 val2 op (pos : Position) =
    match fst val2 with
    | Signed _ | Unsigned _ | Float _ ->
      let right_side = float (getValue (snd val2))
      let flag = checkFloat (string right_side)
      if snd flag then
        let ty = getType (fst val2)
        let right_side =
          if (ty = 2) then (BigInteger.Parse (fst flag))
          else BigInteger.Parse (getValue (snd val2))
        let right_side = fixValue (Signed B32) right_side
        let right_side = int(getValue (snd right_side))
        match fst val1 with
        | Signed _ | Unsigned _ ->
          let left_side = BigInteger.Parse (getValue (snd val1))
          let result = op left_side right_side
          fixValue (fst val1) result
        | Float _ ->
          let left_side = float (getValue (snd val1))
          let check = checkFloat (string left_side)
          if snd check then
            let left_side = BigInteger.Parse (fst check)
            let result = op left_side right_side
            if result >= ref "int32Min" && result <= ref "int32Max" then
              (Signed B32, I32 (int result))
            elif result >= ref "int64Min" && result <= ref "int64Max" then
              (Signed B64, I64 (int64 result))
            elif result >= ref "int128Min" && result <= ref "int128Max" then
              (fixValue (Signed B128) result)
            else
              (fixValue (Signed B256) result)
          else
            (CError Shift,
              NError
                ("Left side of shift operator cannot be float", pos.Column))
        | CError _ -> val1
      else
        CError Shift,
          NError ("Right side of shift operator must be int32", pos.Column)
    | CError _ -> val2

  let add x y =
    match x, y with
    | (CError _, _), _ -> x
    | _, (CError _, _) -> y
    | _, _ ->
      let nextRep = getUpcast x y
      match nextRep with
      | Signed _ | Unsigned _ ->
        let val1 = BigInteger.Parse (getValue (snd x))
        let val2 = BigInteger.Parse (getValue (snd y))
        let result = val1 + val2
        fixValue nextRep result
      | Float BF32 ->
        Float BF32,
          F32 (float32 (getValue (snd x)) + float32 (getValue (snd y)))
      | Float BF64 ->
        Float BF64,
          F64 (float (getValue (snd x)) + float (getValue (snd y)))
      | CError _ ->
        let val1 = BigInteger.Parse (getValue (snd x))
        let val2 = BigInteger.Parse (getValue (snd y))
        fixValue (Unsigned B256) (val1 + val2)
      | _ -> CError Arithmetic, NError ("Add error", 1L)

  let sub x y =
    match x, y with
    | (CError _, _), _ -> x
    | _, (CError _, _) -> y
    | _, _ ->
      let nextRep = getUpcast x y
      match nextRep with
      | Signed _ | Unsigned _ ->
        let val1 = BigInteger.Parse (getValue (snd x))
        let val2 = BigInteger.Parse (getValue (snd y))
        let result = val1 - val2
        fixValue nextRep result
      | Float BF32 ->
        Float BF32,
          F32 (float32 (getValue (snd x)) - float32 (getValue (snd y)))
      | Float BF64 ->
        Float BF64,
          F64 (float (getValue (snd x)) - float (getValue (snd y)))
      | CError _ ->
        let val1 = BigInteger.Parse (getValue (snd x))
        let val2 = BigInteger.Parse (getValue (snd y))
        let type1 = getType (fst x)
        if type1 = 1 then
          fixValue (Unsigned B256) (val1 - val2)
        else
          fixValue (Signed B256) (val1 - val2)
      | _ -> CError Arithmetic, NError ("Sub error", 1L)

  let mul x y =
    match x, y with
    | (CError _, _), _ -> x
    | _, (CError _, _) -> y
    | _, _ ->
      let nextRep = getUpcast x y
      match nextRep with
      | Signed _ | Unsigned _ ->
        let val1 = BigInteger.Parse (getValue (snd x))
        let val2 = BigInteger.Parse (getValue (snd y))
        let result = val1 * val2
        fixValue nextRep result
      | Float BF32 ->
        Float BF32,
          F32 (float32 (getValue (snd x)) * float32 (getValue (snd y)))
      | Float BF64 ->
        Float BF64,
          F64 (float (getValue (snd x)) * float (getValue (snd y)))
      | CError _ ->
        let val1 = BigInteger.Parse (getValue (snd x))
        let val2 = BigInteger.Parse (getValue (snd y))
        fixValue (Signed B256) (val1 * val2)
      | _ -> CError Arithmetic, NError ("Mul error", 1L)

  let div x y (pos : Position) =
    match x, y with
    | (CError _, _), _ -> x
    | _, (CError _, _) -> y
    | _, _ ->
      if float (getValue (snd y)) = 0.0 then
        CError Arithmetic, NError ("Cannot divide by zero", pos.Column)
      else
        let nextRep = getUpcast x y
        match nextRep with
        | Signed _ | Unsigned _ ->
          let val1 = BigInteger.Parse (getValue (snd x))
          let val2 = BigInteger.Parse (getValue (snd y))
          let result = val1 / val2
          fixValue nextRep result
        | Float BF32 ->
          Float BF32,
            F32 (float32 (getValue (snd x)) / float32 (getValue (snd y)))
        | Float BF64 ->
          Float BF64,
            F64 (float (getValue (snd x)) / float (getValue (snd y)))
        | CError _ ->
          let val1 = BigInteger.Parse (getValue (snd x))
          let val2 = BigInteger.Parse (getValue (snd y))
          fixValue (Signed B256) (val1 / val2)
        | _ -> CError Arithmetic, NError ("Div error", 1L)

  let modulo x y (pos : Position) =
    match x, y with
    | (CError _, _), _ -> x
    | _, (CError _, _) -> y
    | _, _ ->
      if float (getValue (snd y)) = 0.0 then
        CError Arithmetic, NError ("Cannot divide by zero", pos.Column)
      else
        let nextRep = getUpcast x y
        match nextRep with
        | Signed _ | Unsigned _ ->
          let val1 = BigInteger.Parse (getValue (snd x))
          let val2 = BigInteger.Parse (getValue (snd y))
          let result = val1 % val2
          fixValue nextRep result
        | Float BF32 ->
          Float BF32,
            F32 (float32 (getValue (snd x)) % float32 (getValue (snd y)))
        | Float BF64 ->
          Float BF64,
            F64 (float (getValue (snd x)) % float (getValue (snd y)))
        | CError _ ->
          let val1 = BigInteger.Parse (getValue (snd x))
          let val2 = BigInteger.Parse (getValue (snd y))
          fixValue (Signed B256) (val1 % val2)
        | _ -> CError Arithmetic, NError ("Modulo error", 1L)

  let bitwiseANDORXOR op x y (pos : Position) =
    match x, y with
    | (CError _, _), _ -> x
    | _, (CError _, _) -> y
    | _, _ ->
      let nextRep = getUpcast x y
      match nextRep with
      | Signed _ | Unsigned _ ->
        let val1 = BigInteger.Parse (getValue (snd x))
        let val2 = BigInteger.Parse (getValue (snd y))
        let result = op val1 val2
        fixValue nextRep result
      | Float _ ->
        let right_side = float (getValue (snd y))
        let flag2 = checkFloat (string right_side)
        let left_side = float (getValue (snd x))
        let flag1 = checkFloat (string left_side)
        if snd flag1 && snd flag2 then
          let ty1 = getType (fst x)
          let ty2 = getType (fst y)
          let left_side =
            if (ty1 = 2) then (BigInteger.Parse (fst flag1))
            else BigInteger.Parse (getValue (snd x))
          let right_side =
            if (ty2 = 2) then (BigInteger.Parse (fst flag2))
            else BigInteger.Parse (getValue (snd y))
          let res = (op left_side right_side)
          if res >= ref "int32Min" && res <= ref "int32Max" then
            (Signed B32, I32 (int res))
          elif res >= ref "int64Min" && res <= ref "int64Max" then
            (Signed B64, I64 (int64 res))
          elif res >= ref "int128Min" && res <= ref "int128Max" then
            (Signed B128, I128 (res))
          else fixValue (Signed B256) res
        else
          (CError Shift,
              NError
                ("Bitwise operator does not support float", pos.Column))
      | CError _ ->
        let val1 = BigInteger.Parse (getValue (snd x))
        let val2 = BigInteger.Parse (getValue (snd y))
        fixValue (Unsigned B256) (op val1 val2)

  let bitwiseNOT x (pos : Position) =
    match fst x with
    | CError _ -> x
    | Signed _ | Unsigned _ ->
      let size = getPriority (getSize (fst x))
      let value = BigInteger.Parse (getValue (snd x))
      let binary = SimpleArithConverter.allDectoBinary value size
      let binaryRep =
        SimpleArithConverter.complement (List.rev (Seq.toList binary.[2 ..]))
      let binaryRep = "0b" + System.String (List.toArray binaryRep)
      if binaryRep.Length <= 34 then
        match fst x with
        | Signed _ -> Signed B32, I32 (int binaryRep)
        | Unsigned _ -> Unsigned B32, UI32 (uint32 binaryRep)
        | _ -> CError Arithmetic, NError ("Must be integer", pos.Column)
      elif binaryRep.Length <= 66 then
        match fst x with
        | Signed _ -> Signed B64, I64 (int64 binaryRep)
        | Unsigned _ -> Unsigned B64, UI64 (uint64 binaryRep)
        | _ -> CError Arithmetic, NError ("Must be integer", pos.Column)
      elif binaryRep.Length <= 130 then
        match fst x with
        | Signed _ ->
          Signed B128, I128 (turnBinaryto128Bigint binaryRep.[2.. ] 0 0I)
        | Unsigned _ ->
          Unsigned B128,
            UI128 (turnBinaryto128OR256UnsignedBigint binary.[2.. ] 0 0I)
        | _ -> CError Arithmetic, NError ("Must be integer", pos.Column)
      else
        match fst x with
        | Signed _ ->
          Signed B256, I256 (turnBinaryto256Bigint binaryRep.[2.. ] 0 0I)
        | Unsigned _ ->
          Unsigned B256,
            UI256 (turnBinaryto128OR256UnsignedBigint binary.[2.. ] 0 0I)
        | _ -> CError Arithmetic, NError ("Must be integer", pos.Column)
    | Float _ ->
      let left_side = float (getValue (snd x))
      let flag1 = checkFloat (string left_side)
      if snd flag1 then
        let value = BigInteger.Parse (fst flag1)
        let size =
          if value >= ref "int32Min" && value <= ref "int32Max" then 3
          elif value >= ref "int64Min" && value <= ref "int64Max" then 4
          elif value >= ref "int128Min" && value <= ref "int128Max" then 5
          else 6
        let value =
          if (size = 6) then
            let str = fixValue (Signed B256) (value)
            BigInteger.Parse (getValue (snd str))
          else value
        let binary = SimpleArithConverter.allDectoBinary value size
        let binaryRep =
          SimpleArithConverter.complement (List.rev (Seq.toList binary.[2 ..]))
        let binaryRep = "0b" + System.String (List.toArray binaryRep)
        if size = 3 then Signed B32, I32 (int binaryRep)
        elif size = 4 then Signed B64, I64 (int64 binaryRep)
        elif size = 5 then
          Signed B128, I128 (turnBinaryto128Bigint binaryRep 0 0I)
        else Signed B256, I256 (turnBinaryto256Bigint binaryRep 0 0I)
      else
        (CError Shift,
              NError
                ("~ operator does not support float", pos.Column))
