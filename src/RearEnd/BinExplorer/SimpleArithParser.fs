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

open B2R2.RearEnd.BinExplorer
open FParsec
open SimpleArithHelper
open SimpleArithOperate

module SimpleArithParser =
  /// Returns a tuple of the big int value of the string and the number of bits
  /// required to represent the number.
  let calculateValue (str : string) =
    let rep = if (str.Length >= 2) then (str[0 .. 1]) else ""
    if rep = "0x" || rep = "0X" || rep = "0o" || rep = "0O" ||
      rep = "0b" || rep = "oB" then
      stringToBigint str
    else
      (System.Numerics.BigInteger.Parse str, -1)

  type Parser<'A> = Parser<'A, unit>

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
           Number.createInt (NumType.fromInt numSize) value
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
    |>> ( fun value -> Number.createInt (Signed Bit32) value )

  let pUInt64: Parser<Number> =
    pUnsignedBigInteger .>> (anyOf "uU" >>. (pstring "I" <|> pstringCI "L"))
    |>> ( fun value -> Number.createInt (Unsigned Bit64) value )

  let pUInt128: Parser<Number> =
    pUnsignedBigInteger .>> (anyOf "uU" >>. (pstring "II" <|> pstringCI "LL"))
    |>> ( fun value -> Number.createInt (Unsigned Bit128) value )

  let pLong: Parser<Number> =
    pInteger .>> anyOf "lLiI"
    |>> ( fun value -> Number.createInt (Signed Bit64) value )

  let pLongLong: Parser<Number> =
    pInteger .>> (pstringCI "II" <|> pstringCI "LL")
    |>> ( fun value -> Number.createInt (Signed Bit128) value )

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
      fun pos x -> bitwiseNOT x pos)

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

module SimpleArithASCIIParser =
  let parseSingleByte =
    hex .>>. hex |>> (fun (a, b) -> "0x" + string a + string b)

  let singleHexToString ch = "0x0" + string ch

  let parseSingleHexDigit: Parser<string, unit> =
    hex |>> singleHexToString

  let parseOddNumberOfHexDigits =
    pstringCI "0x" >>. parseSingleHexDigit .>>. many parseSingleByte
    |>> (fun (a, b) -> a :: b)

  let parseEvenNumberOfHexDigits =
    pstringCI "0x" >>. many parseSingleByte

  let parseEvenHexWithoutPrefix =
    parseSingleByte .>>. many1 parseSingleByte |>> (fun (a, b) -> a :: b)

  let parseOddHexWithoutPrefix =
    parseSingleHexDigit .>>. parseSingleByte .>>. many1 parseSingleByte
    |>> (fun ((a, b), c) -> a :: b :: c)

  let parseDigit = anyOf "123456789"

  let parseSingleDigit = digit |>> (fun a -> [string a])

  let parseDoubleDigit =
    parseDigit .>>. digit |>> (fun (a, b) -> [string a + string b])

  let parseTripleDigit =
    parseDigit .>>. digit .>>. digit
    |>> (fun ((a, b), c) -> [string a + string b + string c])

  let parseDecimal =
    attempt parseTripleDigit
    <|> attempt parseDoubleDigit
    <|> parseSingleDigit

  let parseHexadecimal =
    attempt parseOddHexWithoutPrefix
    <|> attempt parseEvenHexWithoutPrefix
    <|> attempt parseOddNumberOfHexDigits
    <|> attempt parseEvenNumberOfHexDigits

  let parseOctal = anyOf "01234567"

  let singleOctalToString ch = "0o00" + string ch

  let parseSingleOctalDigit =
    parseOctal |>> singleOctalToString

  let parseDoubleOctalDigit =
    parseOctal .>>. parseOctal
    |>> (fun (a, b) -> "0o0" + string a + string b)

  let parseTripleOctalDigit =
    (parseOctal .>>. parseOctal .>>. parseOctal)
    |>> (fun ((a, b), c) -> "0o" + string a + string b + string c)

  let parseWholeOctalNumber = many1 parseTripleOctalDigit

  let parseOctalRemainderOne =
    parseSingleOctalDigit .>>. many parseTripleOctalDigit
    |>> (fun (a, b) -> a :: b)

  let parseOctalRemainderTwo =
    parseDoubleOctalDigit .>>. many parseTripleOctalDigit
    |>> (fun (a, b) -> a :: b)

  let parseOctalDigits =
    attempt parseOctalRemainderOne
    <|> attempt parseOctalRemainderTwo
    <|> parseWholeOctalNumber

  let parseOctalNumber =
    pstringCI "0o" >>. parseOctalDigits

  let all =
    attempt parseHexadecimal
    <|> attempt parseOctalNumber
    <|> parseDecimal

  let run str =
    runParserOnString all () "" str
