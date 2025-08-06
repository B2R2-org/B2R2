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

namespace B2R2.Peripheral.Assembly.MIPS

open B2R2
open B2R2.FrontEnd.MIPS
open B2R2.Peripheral.Assembly.MIPS.ParserHelper
open FParsec
open System

type LabelDefs = Map<string, Addr>

type AsmParser(mipsISA: ISA, startAddress: Addr) =

  let mutable address = startAddress

  (* Helper functions for updating the UserState. *)
  let addLabeldef lbl =
    updateUserState (fun (us: Map<string, Addr>) -> us.Add(lbl, address))
    >>. preturn ()

  let incrementAddress =
    preturn () |>> (fun _ -> address <- address + 4UL)

  let registerNames =
    [| "zero"
       "at"
       "v0"
       "v1"
       "a0"
       "a1"
       "a2"
       "a3"
       "t0"
       "t1"
       "t2"
       "t3"
       "t4"
       "t5"
       "t6"
       "t7"
       "s0"
       "s1"
       "s2"
       "s3"
       "s4"
       "s5"
       "s6"
       "s7"
       "t8"
       "t9"
       "k0"
       "k1"
       "gp"
       "sp"
       "s8"
       "fp"
       "ra" |]

  let isWhitespace c = [ ' '; '\t'; '\f' ] |> List.contains c

  let whitespace = manySatisfy isWhitespace

  let whitespace1 = many1Satisfy isWhitespace

  let skipWhitespaces s = whitespace >>? s .>>? whitespace

  let terminator = (pchar ';' <|> newline) |> skipWhitespaces

  let operandSeps = (pchar ',' >>. whitespace) <|> whitespace1

  let betweenParen s = s |> skipWhitespaces |> between (pchar '(') (pchar ')')

  let alphanumericWithUnderscore s = Char.IsLetterOrDigit s || s = '_'

  let pId = many1Satisfy alphanumericWithUnderscore

  let pLabelDef = pId .>>? pchar ':' >>= addLabeldef

  let pOpcode =
    (Enum.GetNames typeof<Opcode>)
    |> Array.map (fun s ->
      attempt (pstringCI s
              .>> (lookAhead (pchar '.') <|> lookAhead (pchar ' ')))
      |>> fun name -> Enum.Parse(typeof<Opcode>, name.ToUpper()) :?> Opcode
    )
    |> choice

  let pCondition =
    pchar '.'
    >>.
    (
      (Enum.GetNames typeof<Condition>)
      |> Array.map
        (fun s ->
          pstringCI s
          |>> (fun name ->
            Enum.Parse(typeof<Condition>, name.ToUpper()) :?> Condition))
      |> choice
    )

  let pFmtTemp =
    pchar '.'
    >>.
    (
      (Enum.GetNames typeof<FPRFormat>)
      |> Array.map
        (fun s ->
          pstringCI s
          |>> (fun name ->
            Enum.Parse(typeof<FPRFormat>, name.ToUpper()) :?> FPRFormat))
      |> choice
    )

  let pFmt =
    pFmtTemp .>> (opt pFmtTemp)

  let label = pId |>> Operand.GoToLabel

  let numberFormat =
    NumberLiteralOptions.AllowBinary
    ||| NumberLiteralOptions.AllowOctal
    ||| NumberLiteralOptions.AllowHexadecimal
    ||| NumberLiteralOptions.AllowMinusSign

  let regNumberFormat = NumberLiteralOptions.None

  let pImm =
    numberLiteral numberFormat "number" |>> (fun x -> x.String |> uint64)

  let pRegImm =
    numberLiteral regNumberFormat "number" |>> (fun x -> x.String)

  let operators = (pchar '+' |>> fun _ -> (+)) <|> (pchar '-' |>> fun _ -> (-))

  let immWithOperators =
    attempt (pipe3 pImm operators pImm (fun a op c -> op a c))

  let imm = immWithOperators <|> pImm |>> OpImm

  let registersList =
    Enum.GetNames typeof<Register>
    |> Array.append registerNames
    |> Array.map pstringCI

  let allRegistersList =
    Array.append [| pRegImm |] registersList

  let pReg =
    ((pchar '$' >>. (allRegistersList |> choice)) <|> (registersList |> choice))
    |>> (fun regName ->
           Enum.Parse(typeof<Register>, getRealRegName regName)
           :?> Register)
    <??> "registers"

  let reg = pReg |>> OpReg

  let regAddr = betweenParen pReg

  let paddr = opt (pImm .>> whitespace |>> int64) .>>.? regAddr

  let addr =
    paddr
    |>> (fun (ofstOp, reg) ->
      match ofstOp with
      | Some offset -> OpMem(reg, Imm offset, 32<rt>)
      | None -> OpMem(reg, Imm 0L, 32<rt>))

  let operand = addr <|> reg <|> imm <|> label

  let operands = sepBy operand operandSeps |>> extractOperands

  let pInsInfo =
      pOpcode .>>.
      (attempt (opt pCondition)) .>>.
      (opt pFmt) .>>.
      (whitespace >>. operands)
      |>> (fun (((opcode, cond), fmt), operands) ->
              newAssemblyIns mipsISA address opcode cond fmt operands)

  let statement =
    opt pLabelDef >>. spaces >>. pInsInfo .>> incrementAddress

  let statements = sepEndBy statement terminator .>> eof

  member _.Run assembly =
    match runParserOnString statements Map.empty<string, Addr> "" assembly with
    | Success(result, us, _) -> SecondPass.updateInstructions result us
    | Failure(str, _, _) -> printfn "Parser failed!\n%s" str; []
