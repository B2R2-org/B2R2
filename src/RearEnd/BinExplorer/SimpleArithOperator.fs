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

namespace B2R2.RearEnd.BinExplorer

open System.Numerics
open SimpleArithHelper
open SimpleArithReference
open FParsec
open B2R2.RearEnd.BinExplorer

module SimpleArithOperate =
  let selectUnsignedOperand operand1 operand2 =
    match operand1.Type with
    | Unsigned _ -> operand1
    | _ -> operand2

  let selectSignedOperand operand1 operand2 =
    match operand1.Type with
    | Signed _ -> operand1
    | _ -> operand2

  /// Find suitable upcast Type between signed and unsigned integer operand
  let getSuperTypeOfBoth operand1 operand2 =
    let signedOperand = selectSignedOperand operand1 operand2
    let unsignedOperand = selectUnsignedOperand operand1 operand2
    if Number.isBiggerOperand signedOperand unsignedOperand then
      if NumType.isInRange unsignedOperand.IntValue signedOperand.Type then
        signedOperand.Type
      else
        NumType.getNextSignedInt signedOperand.Type
    else
      if NumType.isInRange signedOperand.IntValue unsignedOperand.Type then
        unsignedOperand.Type
      else
        NumType.getNextSignedInt unsignedOperand.Type

  /// Getting common datatype for operations between two different types.
  /// If either side of operation is float or error, common type will always be
  /// float or error.
  let getUpcast (operand1: Number) (operand2: Number) =
    let type1 = operand1.Type
    let type2 = operand2.Type
    match type1, type2 with
    | Signed _, Signed _ -> NumType.getBiggerType type1 type2
    | Unsigned _, Unsigned _ -> NumType.getBiggerType type1 type2
    | Float _, Float _ -> NumType.getBiggerType type1 type2
    | Float _, _ -> type1
    | _, Float _ -> type2
    | _, _ -> getSuperTypeOfBoth operand1 operand2

  /// Maintaining integer overflow.
  let castToType rep num =
    let min, max = NumType.getRange rep
    let range = max - min + 1I
    if num > max then Number.createInt rep ((num - max - 1I) % range + min)
    elif num < min then Number.createInt rep ((num - min + 1I) % range + max)
    else Number.createInt rep num

  let castToIntegerValue rep value =
    match rep with
    | Signed _
    | Unsigned _ -> castToType rep value
    | _ -> { IntValue = -1I; Type = CError Default; FloatValue = -1.0 }

  let getInferedType value =
    match value with
    | Between (NumType.getRange (Signed Bit32)) ->
      { IntValue = value; Type = Signed Bit32; FloatValue = -1.0 }
    | Between (NumType.getRange (Signed Bit64)) ->
      { IntValue = value; Type = Signed Bit64; FloatValue = -1.0 }
    | Between (NumType.getRange (Signed Bit128)) ->
      { IntValue = value; Type = Signed Bit128; FloatValue = -1.0 }
    | _ -> castToIntegerValue (Signed Bit256) value

  let convertfromFloat rep (value: float) =
    match rep with
    | Signed Bit8 -> value |> int8 |> int |> bigint |> Number.createInt rep
    | Unsigned Bit8 ->
      value |> uint8 |> uint32 |> bigint |> Number.createInt rep
    | Signed Bit16 -> value |> int16 |> int |> bigint |> Number.createInt rep
    | Unsigned Bit16 ->
      value |> uint16 |> uint32 |> bigint |> Number.createInt rep
    | Signed Bit32 -> value |> int |> bigint |> Number.createInt rep
    | Unsigned Bit32 -> value |> uint32 |> bigint |> Number.createInt rep
    | Signed Bit64 -> value |> int64 |> bigint |> Number.createInt rep
    | Unsigned Bit64 -> value |> uint64 |> bigint |> Number.createInt rep
    | Signed Bit128
    | Unsigned Bit128
    | Signed Bit256
    | Unsigned Bit256 -> castToIntegerValue rep (bigint value)
    | Float Bit32 -> value |> float32 |> float |> Number.createFloat rep
    | Float Bit64 -> Number.createFloat rep value
    | _ ->
      { IntValue = -1I; Type = CError Default; FloatValue = -1.0 }

  let convertFromBigint rep value =
    match rep with
    | Signed _ | Unsigned _ -> castToIntegerValue rep value
    | Float Bit32 ->
      { IntValue = -1I; Type = rep; FloatValue = float (float32 value) }
    | Float Bit64 ->
      { IntValue = -1I; Type = rep; FloatValue = float value }
    | _ -> { IntValue = -1I; Type = CError Default; FloatValue = -1.0 }

  /// Casting values.
  let cast num nextRep =
    let curRep = num.Type
    match curRep with
    | Signed _ | Unsigned _ -> convertFromBigint nextRep num.IntValue
    | Float _ -> convertfromFloat nextRep num.FloatValue
    | _ -> { IntValue = -1I; Type = CError Default; FloatValue = -1.0 }

  let doShiftFloat (val1: Number) (val2: Number) op (pos: Position) =
    let leftSide = Number.toString val1
    let rightSide = Number.toString val2
    let value1 = getIntegerPart leftSide
    let value2 = getIntegerPart rightSide
    if hasZeroFraction leftSide && hasZeroFraction rightSide then
      let leftSide = BigInteger.Parse value1
      let rightSide = BigInteger.Parse value2
      let rightSide = castToIntegerValue (Signed Bit32) rightSide
      let result = op leftSide (int rightSide.IntValue)
      getInferedType result
    else
      let errorType = BitwiseOperation (int pos.Column)
      { IntValue = -1I; Type = CError errorType; FloatValue = -1.0 }

  let shift (val1: Number) (val2: Number) op (pos: Position) =
    match val1.Type, val2.Type with
    | CError _, _ -> val1
    | _, CError _ -> val2
    | Signed _, Unsigned _
    | Unsigned _, Signed _ ->
      let leftSide = val1.IntValue
      let rightSide = castToIntegerValue (Signed Bit32) val2.IntValue
      let result = op leftSide (int rightSide.IntValue)
      castToIntegerValue val1.Type result
    | _ -> doShiftFloat val1 val2 op pos

  let shiftRight val1 val2 pos = shift val1 val2 (>>>) pos

  let shiftLeft val1 val2 pos = shift val1 val2 (<<<) pos

  let doArithmeticFloat32 op (x: Number) (y: Number) =
    let val1 = Number.toString x |> float32 |> float
    let val2 = Number.toString y |> float32 |> float
    let result = op val1 val2 |> float32
    { IntValue = -1I; Type = Float Bit32; FloatValue = float result }

  let doArithmeticFloat64 op (x: Number) (y: Number) =
    let val1 = Number.toString x |> float
    let val2 = Number.toString y |> float
    let result = op val1 val2
    { IntValue = -1I; Type = Float Bit64; FloatValue = result }

  let doAddition (x: Number) (y: Number) =
    let nextRep = getUpcast x y
    let val1 = x.IntValue
    let val2 = y.IntValue
    match nextRep with
    | Signed _ | Unsigned _ -> castToIntegerValue nextRep ((+) val1 val2)
    | Float Bit32 -> doArithmeticFloat32 (+) x y
    | Float Bit64 -> doArithmeticFloat64 (+) x y
    | CError Default -> castToIntegerValue (Unsigned Bit256) (val1 + val2)
    | _ -> { IntValue = -1I; Type = CError Default; FloatValue = -1.0 }

  let add (x: Number) (y: Number) =
    match x.Type, y.Type with
    | CError _, _ -> x
    | _, CError _ -> y
    | _ -> doAddition x y

  let doSubtraction (x: Number) (y: Number) =
    let nextRep = getUpcast x y
    let val1 = x.IntValue
    let val2 = y.IntValue
    match nextRep with
    | Signed _ | Unsigned _ -> castToIntegerValue nextRep ((-) val1 val2)
    | Float Bit32 -> doArithmeticFloat32 (-) x y
    | Float Bit64 -> doArithmeticFloat64 (-) x y
    | CError Default ->
      if Number.isUnsignedNumber x then
        castToIntegerValue (Unsigned Bit256) (val1 - val2)
      else
        castToIntegerValue (Signed Bit256) (val1 - val2)
    | _ -> { IntValue = -1I; Type = CError Default; FloatValue = -1.0 }

  let sub x y =
    match x.Type, y.Type with
    | CError _, _ -> x
    | _, CError _ -> y
    | _ -> doSubtraction x y

  let doMulDivModulo opInt opFloat (x: Number) (y: Number) =
    let nextRep = getUpcast x y
    let val1 = x.IntValue
    let val2 = y.IntValue
    match nextRep with
    | Signed _ | Unsigned _ -> castToIntegerValue nextRep (opInt val1 val2)
    | Float Bit32 -> doArithmeticFloat32 opFloat x y
    | Float Bit64 -> doArithmeticFloat64 opFloat x y
    | CError Default -> castToIntegerValue (Signed Bit256) (opInt val1 val2)
    | _ -> { IntValue = -1I; Type = CError Default; FloatValue = -1.0 }

  let mul (x: Number) (y: Number) =
    match x.Type, y.Type with
    | CError _, _ -> x
    | _, CError _ -> y
    | _ -> doMulDivModulo (*) (*) x y

  let div x y (pos: Position) =
    match x.Type, y.Type with
    | CError _, _ -> x
    | _, CError _ -> y
    | _ ->
      if y.IntValue = 0I || y.FloatValue = 0.0 then
        let errorType = DivisionByZero (int pos.Column)
        { IntValue = -1I; Type = CError errorType; FloatValue = -1.0 }
      else
        doMulDivModulo (/) (/) x y

  let modulo x y (pos: Position) =
    match x.Type, y.Type with
    | CError _, _ -> x
    | _, CError _ -> y
    | _ ->
      if y.IntValue = 0I || y.FloatValue = 0.0 then
        let errorType = DivisionByZero (int pos.Column)
        { IntValue = -1I; Type = CError errorType; FloatValue = -1.0 }
      else
        doMulDivModulo (%) (%) x y

  let doBitwiseFloat op val1 val2 (pos: Position) =
    let leftSide = Number.toString val1
    let rightSide = Number.toString val2
    let value1 = getIntegerPart leftSide
    let value2 = getIntegerPart rightSide
    if hasZeroFraction leftSide && hasZeroFraction rightSide then
      let leftSide = BigInteger.Parse value1
      let rightSide = BigInteger.Parse value2
      let result = op leftSide rightSide
      getInferedType result
    else
      let errorType = BitwiseOperation (int pos.Column)
      { IntValue = -1I; Type = CError errorType; FloatValue = -1.0 }

  let doBitwise op val1 val2 pos =
    let nextRep = getUpcast val1 val2
    match nextRep with
    | Signed _ | Unsigned _ ->
      let leftSide = val1.IntValue
      let rightSide = val2.IntValue
      let result = op leftSide rightSide
      castToIntegerValue nextRep result
    | Float _ -> doBitwiseFloat op val1 val2 pos
    | _ ->
      let leftside = val1.IntValue
      let rightside = val2.IntValue
      let result = op leftside rightside
      castToIntegerValue (Signed Bit256) (result)

  let bitwiseANDORXOR op val1 val2 (pos: Position) =
    match val1.Type, val2.Type with
    | CError _, _ -> val1
    | _, CError _ -> val2
    | _ -> doBitwise op val1 val2 pos

  let bitwiseAnd val1 val2 pos = bitwiseANDORXOR (&&&) val1 val2 pos

  let bitwiseOr val1 val2 pos = bitwiseANDORXOR (|||) val1 val2 pos

  let bitwiseXOR val1 val2 pos = bitwiseANDORXOR (^^^) val1 val2 pos

  let bitwiseNOT (x: Number) (pos: Position) =
    match x.Type with
    | CError _ -> x
    | Signed _ | Unsigned _ ->
      { IntValue = x.IntValue ^^^ (-1I); Type = x.Type; FloatValue = -1.0 }
    | _ ->
      let numberString = Number.toString x
      let value = getIntegerPart numberString
      if hasZeroFraction numberString then
        let value = BigInteger.Parse value
        let result = value ^^^ (-1I)
        getInferedType result
      else
        let errorType = BitwiseOperation (int pos.Column)
        { IntValue = -1I; Type = CError errorType; FloatValue = -1.0 }
