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

open B2R2.Utilities.BinExplorer
open FParsec
open SimpleArithHelper
open SimpleArithOperate

module SimpleArithParser =
  /// Returns a tuple of the big int value of the string and the number of bits
  /// required to represent the number.
  let calculateValue (str : string) =
    let rep = if (str.Length >= 2) then (str.[0 .. 1]) else ""
    if rep = "0x" || rep = "0X" || rep = "0o" || rep = "0O" ||
      rep = "0b" || rep = "oB" then
      stringToBigint (str)
    else
      (System.Numerics.BigInteger.Parse str, -1)

  type Parser<'a> = Parser<'a,unit>

  let dummyValue = { IntValue = 0I; Type = CError Default ; FloatValue = 0.0 }

  let charListToString charList =
    Seq.fold (fun str char -> str + string char) "" charList

  let pHexString =
    pstringCI "0x" .>>. many (anyOf "0123456789ABCDEFabcdef")
    |>> (fun (prefix, bits) -> prefix + charListToString bits)

  let pOctalString =
    pstringCI "0o" .>>. many (anyOf "01234567")
    |>> (fun (prefix, bits) -> prefix + charListToString bits)

  let pBinaryString =
    pstringCI "0b" .>>. many (anyOf "01")
    |>> (fun (prefix, bits) -> prefix + charListToString bits)

  let pBinOrHexInteger: Parser<Number> =
    attempt pBinaryString <|> attempt pHexString <|> attempt pOctalString
    |>> (fun str ->
           let value, numSize = calculateValue str
           Number.createInt value (NumType.fromInt numSize)
        )

  let pUnsignedBigInteger =
    many1 digit |>> charListToString |>> bigint.Parse

  let pInteger =
     opt (pchar '-') .>>. pUnsignedBigInteger
     |>> (fun (sign, value) -> if sign.IsSome then -1I * value else value )

  let pFloatNumber: Parser<Number> =
    opt (pchar '-') .>>. many1 digit .>> pchar '.' .>>. many digit
    |>> (fun ((sign, intPart), decPart) ->
           let value = charListToString intPart + "." + charListToString decPart
                       |> fun str -> if sign.IsNone then str else "-" + str
                       |> System.Double.Parse
           Number.createFloat (Float Bit64) value
        )

  let pImpliedSignedInteger: Parser<Number> =
    attempt pInteger
    |>> (fun bigIntValue ->
          { IntValue = bigIntValue; Type = NumType.getInferedType bigIntValue
            FloatValue = 0.0 })

  let pUInt32: Parser<Number> =
    pUnsignedBigInteger .>> anyOf "uU"
    |>> ( fun value -> Number.createInt value (Signed Bit32) )

  let pUInt64: Parser<Number> =
    pUnsignedBigInteger .>> (anyOf "uU" >>. (pstring "I" <|> pstringCI "L"))
    |>> ( fun value -> Number.createInt value (Unsigned Bit64) )

  let pUInt128: Parser<Number> =
    pUnsignedBigInteger .>> (anyOf "uU" >>. (pstring "II" <|> pstringCI "LL"))
    |>> ( fun value -> Number.createInt value (Unsigned Bit128) )

  let pLong: Parser<Number> =
    pInteger .>> anyOf "lLiI"
    |>> ( fun value -> Number.createInt value (Signed Bit64) )

  let pLongLong: Parser<Number> =
    pInteger .>> (pstringCI "II" <|> pstringCI "LL")
    |>> ( fun value -> Number.createInt value (Signed Bit128) )

  let pAllNumbers =
    attempt pBinOrHexInteger <|>
    attempt pFloatNumber <|>
    attempt pUInt128 <|>
    attempt pUInt64 <|>
    attempt pUInt32 <|>
    attempt pLongLong <|>
    attempt pLong <|>
    attempt pImpliedSignedInteger

  let constructInfixOp symbol op prec =
    InfixOperator(symbol, getPosition .>> spaces, prec, Associativity.Left, op)

  let constructInfixOpWithPos symbol op prec =
    InfixOperator(symbol, getPosition .>> spaces, prec, Associativity.Left, (),
        fun pos x y -> op x y pos)

  let constructCastingOp symbol typ =
    PrefixOperator(symbol, getPosition .>> spaces, 4, true, fun x -> cast x typ)

  let constructNOTOperator =
    PrefixOperator("~", getPosition .>> spaces, 4, true, (),
      fun pos x -> (bitwiseNOT x pos))

  let strWs s = pstring s >>. spaces

  let opp =
    new OperatorPrecedenceParser<Number, Position, unit>()

  let expr = opp.ExpressionParser

  let term =
    (pAllNumbers .>> spaces) <|> between (strWs "(") (strWs ")") expr

  do
    opp.TermParser <- term
    opp.AddOperator(constructInfixOp "+" add 2)
    opp.AddOperator(constructInfixOp "-" sub 2)
    opp.AddOperator(constructInfixOp "*" mul 3)
    opp.AddOperator(constructInfixOpWithPos "/" div 3)
    opp.AddOperator(constructInfixOpWithPos "%" modulo 3)
    opp.AddOperator(constructInfixOpWithPos ">>" shiftRight 1)
    opp.AddOperator(constructInfixOpWithPos "<<" shiftLeft 1)
    opp.AddOperator(constructInfixOpWithPos "|" bitwiseOr 1)
    opp.AddOperator(constructInfixOpWithPos "&" bitwiseAnd 1)
    opp.AddOperator(constructInfixOpWithPos "^" bitwiseXOR 1)
    opp.AddOperator(constructNOTOperator)
    opp.AddOperator(constructCastingOp "(int8)" (Signed Bit8))
    opp.AddOperator(constructCastingOp "(uint8)" (Unsigned Bit8))
    opp.AddOperator(constructCastingOp "(int16)" (Signed Bit16))
    opp.AddOperator(constructCastingOp "(uint16)" (Unsigned Bit16))
    opp.AddOperator(constructCastingOp "(int32)" (Signed Bit32))
    opp.AddOperator(constructCastingOp "(uint32)" (Unsigned Bit32))
    opp.AddOperator(constructCastingOp "(int)" (Signed Bit32))
    opp.AddOperator(constructCastingOp "(int64)" (Signed Bit64))
    opp.AddOperator(constructCastingOp "(uint64)" (Unsigned Bit64))
    opp.AddOperator(constructCastingOp "(int128)" (Signed Bit128))
    opp.AddOperator(constructCastingOp "(uint128)" (Unsigned Bit128))
    opp.AddOperator(constructCastingOp "(int256)" (Signed Bit256))
    opp.AddOperator(constructCastingOp "(uint256)" (Unsigned Bit256))
    opp.AddOperator(constructCastingOp "(float32)" (Float Bit32))
    opp.AddOperator(constructCastingOp "(float)" (Float Bit64))
