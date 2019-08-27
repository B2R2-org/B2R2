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

open B2R2.Utilities.BinExplorer
open FParsec
open SimpleArithHelper
open SimpleArithReference
open SimpleArithOperate
open Numbers

module SimpleArithParser =
  let numberformat =
    NumberLiteralOptions.AllowFraction |||
    NumberLiteralOptions.AllowFractionWOIntegerPart |||
    NumberLiteralOptions.AllowBinary |||
    NumberLiteralOptions.AllowHexadecimal |||
    NumberLiteralOptions.AllowMinusSign |||
    NumberLiteralOptions.AllowOctal |||
    NumberLiteralOptions.AllowSuffix

  let pV =
    numberLiteral numberformat "number" .>>. getPosition .>> spaces
    |>> fun (nl, pos) ->
          if nl.HasFraction then (Float BF64, F64 (float nl.String))
          else

            let value, flag = calculateValue nl.String
            let ch1 = nl.SuffixChar1
            let ch2 = string (nl.SuffixChar1) + string (nl.SuffixChar2)
            let ch3 = ch2 + string (nl.SuffixChar3)
            if nl.SuffixLength = 1 && (ch1 = 'u' || ch1 = 'U') then
              if value >= 0I && value <= ref "uint32Max" then
                (Unsigned B32, UI32 (uint32 value))
              else
                (CError OutofRange, NError ("Out of range", pos.Column))
            elif nl.SuffixLength = 1 && (ch1 = 'I' || ch1 = 'L') then
              if value >= ref "int64Min" && value <= ref "int64Max" &&
                flag <= 4 then
                (Signed B64, I64 (int64 value))
              else
                (CError OutofRange, NError ("Out of range", pos.Column))
            elif nl.SuffixLength = 2 && (ch2 = "uI" || ch2 = "UL") then
              if value >= 0I && value <= ref "uint64Max"  then
                (Unsigned B64, UI64 (uint64 value))
              else
                (CError OutofRange, NError ("Out of range", pos.Column))
            elif nl.SuffixLength = 2 && (ch2 = "II" || ch2 = "LL") then
              if value >= ref "int128Min" && value <= ref "int128Max" && flag <= 5
                then
                (Signed B128, I128 (value))
              else
                (CError OutofRange, NError ("Out of range", pos.Column))
            elif nl.SuffixLength = 3 && (ch3 = "uII" || ch3 = "ULL") then
              if value >= 0I && value <= ref "uint128Max" then
                (Unsigned B128, UI128 (value))
              else
                (CError OutofRange, NError ("Out of range", pos.Column))
            elif flag = 3 then
              (Signed B32, I32 (int value))
            elif flag = 4 then
              (Signed B64, I64 (int64 value))
            elif flag = 5 then
              (Signed B128, I128 (value))
            elif flag = 6 then
              (Signed B256, I256 (value))
            elif value >= ref "int32Min" && value <= ref "int32Max" then
              (Signed B32, I32 (int value))
            elif value >= ref "int64Min" && value <= ref "int64Max" then
              (Signed B64, I64 (int64 value))
            elif value >= ref "int128Min" && value <= ref "int128Max" then
              (Signed B128, I128 (value))
            elif value >= ref "int256Min" && value <= ref "int256Max" then
              (Signed B256, I256 (value))
            elif value > ref "int256Max" && value <= ref "uint256Max" then
              (Unsigned B256, UI256 (value))
            else
              (CError OutofRange, NError ("Out of range", pos.Column))

  let ws = spaces
  let str_ws s = pstring s >>. ws

  let opp =
    new OperatorPrecedenceParser<DataType*Numbers, Position, unit>()
  let expr = opp.ExpressionParser
  let term = pV <|> between (str_ws "(") (str_ws ")") expr

  do
    opp.TermParser <- term

    opp.AddOperator(
      InfixOperator("+", getPosition .>> ws, 2, Associativity.Left,
        fun x y -> (add x y))
    )

    opp.AddOperator(
      InfixOperator("-", getPosition .>> ws, 2, Associativity.Left,
        fun x y -> (sub x y))
    )
    opp.AddOperator(
      InfixOperator("/", getPosition .>> ws, 3, Associativity.Left, (),
        fun pos x y -> (div x y pos))
    )
    opp.AddOperator(
      InfixOperator("%", getPosition .>> ws, 3, Associativity.Left, (),
        fun pos x y -> (modulo x y pos))
    )
    opp.AddOperator(
      InfixOperator(">>", getPosition .>> ws, 1, Associativity.Left, (),
        fun pos x y -> shift x y (>>>) pos)
    )
    opp.AddOperator(
      InfixOperator("<<", getPosition .>> ws, 1, Associativity.Left, (),
        fun pos x y -> shift x y (<<<) pos)
    )

    opp.AddOperator(
      InfixOperator("&", getPosition .>> ws, 1, Associativity.Left, (),
        fun pos x y -> bitwiseANDORXOR (&&&) x y pos)
    )

    opp.AddOperator(
      InfixOperator("^", getPosition .>> ws, 1, Associativity.Left, (),
        fun pos x y -> bitwiseANDORXOR (^^^) x y pos)
    )

    opp.AddOperator(
      InfixOperator("|", getPosition .>> ws, 1, Associativity.Left, (),
        fun pos x y -> bitwiseANDORXOR (|||) x y pos)
    )

    opp.AddOperator(
      InfixOperator("*", getPosition .>> ws, 3, Associativity.Left,
        fun x y -> (mul x y))
    )

    opp.AddOperator(
      PrefixOperator("~", getPosition .>> ws, 4, true, (),
        fun pos x -> (bitwiseNOT x pos))
    )

    opp.AddOperator(
      PrefixOperator("(int8)", getPosition .>> ws, 4, true,
        fun x -> convert (fst x) (Signed B8) (getValue (snd x)))
    )
    opp.AddOperator(
      PrefixOperator("(uint8)", getPosition .>> ws, 4, true,
        fun x -> convert (fst x) (Unsigned B8) (getValue (snd x)))
    )
    opp.AddOperator(
      PrefixOperator("(int16)", getPosition .>> ws, 4, true,
        fun x -> convert (fst x) (Signed B16) (getValue (snd x)))
    )
    opp.AddOperator(
      PrefixOperator("(uint16)", getPosition .>> ws, 4, true,
        fun x -> convert (fst x) (Unsigned B16) (getValue (snd x)))
    )
    opp.AddOperator(
      PrefixOperator("(int)", getPosition .>> ws, 4, true,
        fun x -> convert (fst x) (Signed B32) (getValue (snd x)))
    )
    opp.AddOperator(
      PrefixOperator("(int32)", getPosition .>> ws, 4, true,
        fun x -> convert (fst x) (Signed B32) (getValue (snd x)))
    )
    opp.AddOperator(
      PrefixOperator("(uint32)", getPosition .>> ws, 4, true,
        fun x -> convert (fst x) (Unsigned B32) (getValue (snd x)))
    )
    opp.AddOperator(
      PrefixOperator("(int64)", getPosition .>> ws, 4, true,
        fun x -> convert (fst x) (Signed B64) (getValue (snd x)))
    )
    opp.AddOperator(
      PrefixOperator("(uint64)", getPosition .>> ws, 4, true,
        fun x -> convert (fst x) (Unsigned B64) (getValue (snd x)))
    )
    opp.AddOperator(
      PrefixOperator("(int128)", getPosition .>> ws, 4, true,
        fun x -> convert (fst x) (Signed B128) (getValue (snd x)))
    )
    opp.AddOperator(
      PrefixOperator("(uint128)", getPosition .>> ws, 4, true,
        fun x -> convert (fst x) (Unsigned B128) (getValue (snd x)))
    )
    opp.AddOperator(
      PrefixOperator("(int256)", getPosition .>> ws, 4, true,
        fun x -> convert (fst x) (Signed B256) (getValue (snd x)))
    )
    opp.AddOperator(
      PrefixOperator("(uint256)", getPosition .>> ws, 4, true,
        fun x -> convert (fst x) (Unsigned B256) (getValue (snd x)))
    )
    opp.AddOperator(
      PrefixOperator("(float32)", getPosition .>> ws, 4, true,
        fun x -> convert (fst x) (Float BF32) (getValue (snd x)))
    )
    opp.AddOperator(
      PrefixOperator("(float)", getPosition .>> ws, 4, true,
        fun x -> convert (fst x) (Float BF64) (getValue (snd x)))
    )
