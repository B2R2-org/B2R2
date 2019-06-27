(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Kangsu Kim <kskim0610@kaist.ac.kr>

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

module B2R2.Assembler.MIPS.Parser

open B2R2.Assembler.MIPS
open B2R2.FrontEnd.MIPS
open FParsec
open System

type UserState = unit
type Parser<'t> = Parser<'t, UserState>
type Operand = B2R2.Assembler.MIPS.Operand

module private Rules =
  let registerNames =
    [| "zero"; "at"; "v0"; "v1"; "a0"; "a1"; "a2"; "a3"; "t0"; "t1"; "t2"; "t3";
       "t4"; "t5"; "t6"; "t7"; "s0"; "s1"; "s2"; "s3"; "s4"; "s5"; "s6"; "s7";
       "t8"; "t9"; "k0"; "k1"; "gp"; "sp"; "s8"; "fp"; "ra"; |]

  let isWhitespace c = [ ' '; '\t'; '\f' ] |> List.contains c
  let whitespace: Parser<_> = manySatisfy isWhitespace
  let whitespace1: Parser<_> = many1Satisfy isWhitespace
  let skipWhitespaces s = whitespace >>? s .>>? whitespace
  let terminator: Parser<_> = (pchar ';' <|> newline) |> skipWhitespaces

  let operandSeps: Parser<_> = (pchar ',' >>. whitespace) <|> whitespace1
  let betweenParen s = s |> skipWhitespaces |> between (pchar '(') (pchar ')')

  let alphanumericWithUnderscore s = Char.IsLetterOrDigit s || s = '_'

  let pId: Parser<_> = many1Satisfy alphanumericWithUnderscore
  let labelDef: Parser<_> = pId .>>? pchar ':' |>> Statement.Label

  let opcode: Parser<_> =
    (Enum.GetNames typeof<Opcode>)
    |> Array.map pstringCI
    |> choice

  let label: Parser<_> = pId |>> Operand.Label

  let numberFormat =
    NumberLiteralOptions.AllowBinary
    ||| NumberLiteralOptions.AllowOctal
    ||| NumberLiteralOptions.AllowHexadecimal
    ||| NumberLiteralOptions.AllowMinusSign
  let regNumberFormat = NumberLiteralOptions.None
  let pImm: Parser<_> =
    numberLiteral numberFormat "number" |>> (fun x -> x.String)
  let pRegImm: Parser<_> =
    numberLiteral regNumberFormat "number" |>> (fun x -> x.String)
  let operators: Parser<_> = pchar '+' <|> pchar '-'
  let immWithOperators: Parser<_> =
    attempt (pipe3 pImm operators pImm (fun a b c -> sprintf "%s%c%s" a b c))
  let imm: Parser<_> = immWithOperators <|> pImm |>> Operand.Immediate

  let registers: Parser<_> [] =
    (Enum.GetNames typeof<Register>)
    |> Array.append registerNames
    |> Array.map pstringCI

  let allRegisters: Parser<_> [] =
    Array.append [|pRegImm|] registers

  let pReg: Parser<_> =
    (pchar '$' >>. (allRegisters |> choice))
    <|> (registers |> choice)

  let reg: Parser<_> = pReg |>> Operand.Register
  let regAddr: Parser<_> = betweenParen pReg

  let paddr: Parser<_> = opt (pImm .>> whitespace) .>>.? regAddr
  let addr: Parser<_> = paddr |>> Operand.Address

  let operand: Parser<_> = addr <|> reg <|> imm <|> label
  let operands: Parser<_> = sepBy operand operandSeps

  let instruction: Parser<_> =
    opcode .>>. (whitespace >>. operands) |>> Statement.Instruction
  let statement: Parser<_> =
    (opt labelDef .>> whitespace) .>>. (opt instruction)
  let statements: Parser<_> = sepEndBy statement terminator .>> eof

let parse assembly =
  run Rules.statements assembly
