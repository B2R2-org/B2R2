(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Mehdi Aghakishiyev <agakisiyev.mehdi@gmail.com>
          Michael Tegegn <mick@kaist.ac.kr>
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
open SimpleArithReference
open System

type ErrorMessage =
  | BitwiseOperation of int
  | DivisionByZero of int
  | OutOfRange of int
  | Default

module ErrorMessage =
  let getErrorMessage = function
    | BitwiseOperation _ -> "Float does not support bitwise operations"
    | DivisionByZero _ -> "Cannot divide by zero"
    | OutOfRange _ -> "Number is out of range"
    | Default -> "Error"

  let getPosition = function
    | BitwiseOperation a
    | DivisionByZero a
    | OutOfRange a -> a
    | Default -> -1

  let constructErrorMessage str errorType =
    let result = str + "\n"
    let pos = getPosition errorType
    if pos <> -1 then
      let space = sprintf "%*s^" (pos - 2) ""
      [| result + space + "\n" + getErrorMessage errorType |]
    else
      [| str + "\n\nError" |]

type NumSize =
  | Bit8
  | Bit16
  | Bit32
  | Bit64
  | Bit128
  | Bit256

module NumSize =
  let getBitLength = function
    | Bit8 -> 8
    | Bit16 -> 16
    | Bit32 -> 32
    | Bit64 -> 64
    | Bit128 -> 128
    | Bit256 -> 256

type NumType =
  | Signed of NumSize
  | Unsigned of NumSize
  | Float of NumSize
  | CError of ErrorMessage

module NumType =
  let fromInt = function
    | 8 -> Signed Bit8
    | 16 -> Signed Bit16
    | 32 -> Signed Bit32
    | 64 -> Signed Bit64
    | 128 -> Signed Bit128
    | 256 -> Signed Bit256
    | _ -> CError Default

  let getBitLength = function
    | Signed a
    | Unsigned a
    | Float a ->
      NumSize.getBitLength a
    | _ -> -1

  let isSignedInt = function
    | Signed _ -> true
    | _ -> false

  let isUnsignedInt = function
    | Unsigned _ -> true
    | _ -> false

  let isFloat = function
    | Float _ -> true
    | _ -> false

  let isError = function
    | CError _ -> true
    | _ -> false

  let rec getMaxValue = function
    | Signed Bit8 -> 127I
    | Unsigned Bit8 -> 255I
    | Signed Bit16 -> int32 Int16.MaxValue |> bigint
    | Unsigned Bit16 -> int32 UInt16.MaxValue |> bigint
    | Signed Bit32 -> Int32.MaxValue |> bigint
    | Unsigned Bit32 -> UInt32.MaxValue |> bigint
    | Signed Bit64 -> Int64.MaxValue |> bigint
    | Unsigned Bit64 -> UInt64.MaxValue |> bigint
    | Signed Bit128 -> 170141183460469231731687303715884105727I
    | Unsigned Bit128 -> 340282366920938463463374607431768211455I
    | Signed Bit256 ->
      bigint.Pow (170141183460469231731687303715884105728I, 2) * 2I - 1I
    | Unsigned Bit256 -> getMaxValue (Signed Bit256) * 2I + 1I
    | Float Bit32 -> Single.MaxValue |> bigint
    | Float Bit64 -> Double.MaxValue |> bigint
    | _ -> failwith "Error has no max value"

  let getMinValue = function
    | Unsigned Bit8 | Unsigned Bit16 | Unsigned Bit32 | Unsigned Bit64 |
      Unsigned Bit128 | Unsigned Bit256 -> 0I
    | Signed Bit8
    | Signed Bit16
    | Signed Bit32
    | Signed Bit64
    | Signed Bit128
    | Signed Bit256 as typ ->  getMaxValue typ * -1I - 1I
    | Float Bit32 -> Single.MinValue |> bigint
    | Float Bit64 -> Double.MinValue |> bigint
    | _ -> failwith "Error has no min value"

  /// Checks if the number types have the same sign, or if they are both floats.
  let isSametype numType1 numtype2 =
    isSignedInt numType1 && isSignedInt numtype2 ||
    isUnsignedInt numType1 && isUnsignedInt numtype2 ||
    isFloat numType1 && isFloat numtype2 ||
    isError numType1 && isError numtype2

  let isBiggerType numType1 numType2 =
    getBitLength numType1 > getBitLength numType2

  let getBiggerType numType1 numType2 =
    if isBiggerType numType1 numType2 then
      numType1
    else
      numType2

  let getNextSignedInt = function
    | Signed Bit8 | Unsigned Bit8 -> Signed Bit16
    | Signed Bit16 | Unsigned Bit16 -> Signed Bit32
    | Signed Bit32 | Unsigned Bit32 -> Signed Bit64
    | Signed Bit64 | Unsigned Bit64 -> Signed Bit128
    | Signed Bit128 | Unsigned Bit128 -> Signed Bit256
    | Signed Bit256 | Unsigned Bit256 -> CError Default
    | _ -> CError Default

  let getRange (typ: NumType) = (getMinValue typ, getMaxValue typ)

  let isInRange value typ = value >= getMinValue typ && value <= getMaxValue typ

  let getInferedType = function
    | Between (getRange (Signed Bit32)) -> Signed Bit32
    | Between (getRange (Signed Bit64)) -> Signed Bit64
    | Between (getRange (Signed Bit128)) -> Signed Bit128
    | Between (getRange (Signed Bit256)) -> Signed Bit256
    | Between (getRange (Unsigned Bit256)) -> Unsigned Bit256
    | _ -> CError Default

type Number = {
    IntValue : bigint
    FloatValue: float
    Type : NumType
}

module Number =
  let createInt typ value =
    if NumType.isInRange value typ then
      { IntValue = value; Type = typ; FloatValue = -1.0 }
    else
      { IntValue = value; Type = CError Default; FloatValue = -1.0 }

  let createFloat typ dbl =
    { IntValue = -1I; Type = typ; FloatValue = dbl }

  let toString value =
    if NumType.isSignedInt value.Type || NumType.isUnsignedInt value.Type then
      string value.IntValue
    elif NumType.isFloat value.Type then
      string value.FloatValue
    else
      "Error"

  let isBiggerOperand operand1 operand2 =
    NumType.isBiggerType operand1.Type operand2.Type

  let isUnsignedNumber operand = NumType.isUnsignedInt operand.Type

  let isSignedNumber operand = NumType.isSignedInt operand.Type

type OutputFormat =
  | DecimalF
  | HexadecimalF
  | OctalF
  | BinaryF
  | FloatingPointF
  | CharacterF
