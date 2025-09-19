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

namespace B2R2.RearEnd.BiHexLang

open FParsec

/// Represents a parser for BiHexLang expressions.
type Parser() =
  let convertHexCharsToBytes chars =
    Array.chunkBySize 2 chars
    |> Array.rev
    |> Array.map (fun pair ->
      System.Convert.ToInt32(System.String pair, 16) |> byte)

  let pHexWithoutPrefix =
    hex .>>. many1 hex
    |>> fun (head, tail) ->
      let chars = List.toArray (head :: tail)
      if chars.Length % 2 = 0 then
        convertHexCharsToBytes chars
        |> fun bs -> Number(Hex, bs)
      else
        let head, tail = System.Convert.ToInt32(string chars[0], 16), chars[1..]
        let bs = convertHexCharsToBytes tail
        Number(Hex, [| yield! bs; byte head |])

  let pSingleHexWithoutPrefix =
    hex
    |>> fun ch -> System.Convert.ToInt32($"{ch}", 16) |> byte
    |>> fun b -> Number(Hex, [| b |])

  /// Parser for a hexadecimal number with 0x prefix.
  let pHexadecimal =
    pstring "0x" >>.
    (attempt pHexWithoutPrefix <|> pSingleHexWithoutPrefix)

  let pBinaryDigit = anyOf "01"

  let pBinaryDigits =
    many1 pBinaryDigit
    |>> fun chars ->
      let chars = List.rev chars |> List.toArray |> Array.map (fun c -> c = '1')
      let bufLen = chars.Length / 8 + if chars.Length % 8 = 0 then 0 else 1
      let buf: byte[] = Array.zeroCreate bufLen
      System.Collections.BitArray(chars).CopyTo(buf, 0)
      Number(Bin, buf)

  /// Parser for a binary number with 0b prefix.
  let pBinary =
    pstring "0b" >>. pBinaryDigits

  let pOctalDigit = anyOf "01234567"

  let convertOctalCharsToBytes chars =
    Array.chunkBySize 8 chars
    |> Array.map (fun chunk ->
      let chunk =
        if chunk.Length = 8 then chunk
        else Array.append chunk (Array.create (8 - chunk.Length) '0')
      let s = System.String(Array.rev chunk)
      let n = System.Convert.ToInt32(s, 8)
      let b3 = n >>> 16 &&& 0xff
      let b2 = n >>> 8 &&& 0xff
      let b1 = n &&& 0xff
      [| if b3 <> 0 || b2 <> 0 || b1 <> 0 then yield byte b1
         if b3 <> 0 || b2 <> 0 then yield byte b2
         if b3 <> 0 then yield byte b3 |])
    |> Array.concat
    |> fun bs -> if bs.Length = 0 then [| 0uy |] else bs

  let pOctalDigits =
    many1 pOctalDigit
    |>> fun chars ->
      let chars = List.rev chars |> List.toArray
      Number(Oct, convertOctalCharsToBytes chars)

  /// Parser for an octal number with 0o prefix.
  let pOctal =
    pstring "0o" >>. pOctalDigits

  /// Parser for a decimal number.
  let pDecimal =
    pstring "0d" >>. many1 digit
    |>> (List.toArray >> System.String)
    |>> fun s -> Number(Dec, (bigint.Parse s).ToByteArray())

  /// Parser for a number in various formats.
  let pNumber =
    attempt pHexadecimal
    <|> attempt pBinary
    <|> attempt pOctal
    <|> attempt pDecimal
    <|> attempt pHexWithoutPrefix
    <|> pSingleHexWithoutPrefix

  /// Parser for a string literal.
  let pStringLiteral =
    let pNoQuote = many (noneOf "\"")
    between (pstring "\"" >>. spaces) (pstring "\"" >>. spaces) pNoQuote
    |>> fun chars ->
      Str(System.String(List.toArray chars))

  let opp = OperatorPrecedenceParser<Expr, unit, unit>()

  let expr = opp.ExpressionParser

  let pTerm =
    (pNumber .>> spaces)
    <|> (pStringLiteral .>> spaces)
    <|> between (pstring "(" >>. spaces) (pstring ")" >>. spaces) expr

  let addInfixOp str prec assoc mapping =
    let op =
      InfixOperator(str, spaces, prec, assoc, (),
                    fun () leftTerm rightTerm -> mapping () leftTerm rightTerm)
    opp.AddOperator(op)

  let addPrefixOp str prec mapping =
    let op =
      PrefixOperator(str, spaces, prec, true, (),
                     fun () term -> mapping () term)
    opp.AddOperator(op)

  do
    opp.TermParser <- pTerm
    addInfixOp "+" 3 Associativity.Left (fun () lhs rhs -> Add(lhs, rhs))
    addInfixOp "-" 3 Associativity.Left (fun () lhs rhs -> Sub(lhs, rhs))
    addInfixOp "*" 4 Associativity.Left (fun () lhs rhs -> Mul(lhs, rhs))
    addInfixOp "/" 4 Associativity.Left (fun () lhs rhs -> Div(lhs, rhs))
    addInfixOp "%" 4 Associativity.Left (fun () lhs rhs -> Mod(lhs, rhs))
    addInfixOp "&" 2 Associativity.Left (fun () lhs rhs -> And(lhs, rhs))
    addInfixOp "|" 2 Associativity.Left (fun () lhs rhs -> Or(lhs, rhs))
    addInfixOp "^" 2 Associativity.Left (fun () lhs rhs -> Xor(lhs, rhs))
    addInfixOp "<<" 2 Associativity.Left (fun () lhs rhs -> Shl(lhs, rhs))
    addInfixOp ">>" 2 Associativity.Left (fun () lhs rhs -> Shr(lhs, rhs))
    addPrefixOp "-" 7 (fun () term -> Neg(term))
    addPrefixOp "~" 7 (fun () term -> Not(term))
    addPrefixOp "(hex)" 6 (fun () term -> Cast(Hex, term))
    addPrefixOp "(bin)" 6 (fun () term -> Cast(Bin, term))
    addPrefixOp "(oct)" 6 (fun () term -> Cast(Oct, term))
    addPrefixOp "(dec)" 6 (fun () term -> Cast(Dec, term))
    addInfixOp "." 5 Associativity.Left (fun () lhs rhs -> Concat(lhs, rhs))

  /// Runs the BiHexLang parser on the given input string.
  member _.Run str =
    match runParserOnString opp () "" str with
    | Success(expr, _, _) -> Result.Ok expr
    | Failure(errMsg, _, _) -> Result.Error errMsg
