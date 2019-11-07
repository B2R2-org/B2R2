(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Michael Tegegn <mick@kaist.ac.kr>
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

namespace B2R2.BinIR.LowUIR

open FParsec
open B2R2
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.Parser.Utils

type ExpectedType = RegType

type Parser<'t> = Parser<'t, ExpectedType>

type LowUIRParser (isa, regfactory: RegisterFactory) =

  (* Functions to help with manipulating the userState *)
  let makeExpectedType c =
    updateUserState ( fun us -> AST.typeOf c)
    >>. preturn c

  /// Parses name that can be used as a variable or register Name.
  let pNormalString =
    many1 (digit <|> letter) |>> (Seq.map string) |>> String.concat ""
  let pHexToUInt64 =
     many (digit <|> anyOf "ABCDEF") |>> (Seq.map string) |>> String.concat ""
     |>> (fun str -> uint64 ( "0x" + str))

  let pCaseString (s: string) =
    pstring s <|> (pstring ( s.ToLower () ) >>. preturn s) <?> s

  let numberFormat =     NumberLiteralOptions.AllowMinusSign
                     ||| NumberLiteralOptions.AllowBinary
                     ||| NumberLiteralOptions.AllowHexadecimal
                     ||| NumberLiteralOptions.AllowOctal
                     ||| NumberLiteralOptions.AllowPlusSign

  let pnumber : Parser<int64> =
      numberLiteral numberFormat "number"
      |>> fun nl ->
              int64 nl.String
  (*---------------------------Primitives.-----------------------------*)
  let pRegType =
    (anyOf "IiFf" ) >>. pint32 |>> RegType.fromBitWidth

  let pBitVector =
    pnumber .>> spaces
    .>>. (opt (pchar ':' >>. spaces >>. pRegType))
    >>= (fun (n, typ) ->
           if typ.IsNone then getUserState |>> (fun t -> BitVector.ofInt64 n t)
           else preturn (BitVector.ofInt64 n typ.Value))

  let pUnaryOperator = anyOf "-~" |>> string |>> unOpFromString

  let pBinaryOperator =
    [ "-|"; "++"; "+"; "-"; "*"; "/"; "?/"; "%";
      "?%"; "<<" ; ">>"; "?>>"; "&"; "|"; "^"; "::" ]
    |> List.map pstring |> List.map attempt |> choice |>> binOpFromString

  let pRelativeOperator =
    [ "="; "!=" ; ">"; ">="; "?>"; "<"; "<="; "?<="; "?<" ]
    |> List.map pstring |> List.map attempt |> choice |>> relOpFromString

  let pCastType =
    pstring "sext" <|> pstring "zext" |>> castTypeFromString

  // To Do: Usage example not known. How to parse differently from pVar.
  let pSymbol =
    pNormalString |>> AST.lblSymbol

  (*---------------------------Expressions.----------------------------*)

  (*Reference to Expression parser created here.*)
  let pExpr, pExprRef = createParserForwardedToRef ()

  let pNumE = pBitVector |>> AST.num

  let pVarE =
    List.map pCaseString regfactory.RegNames |> List.map attempt
    |> choice |>> regfactory.StrToReg

  let pPCVarE =
    pNormalString |>> regfactory.StrToReg

  let pTempVarE =
    spaces >>. pstring "T_" >>. pint32 .>> spaces .>> pchar ':' .>> spaces
    .>>. pRegType |>> (fun (num, typ) -> TempVar (typ, num))

  let pNameE = pSymbol |>> Name

  // To Do: Usage example not known. How to parse differently from pVar, pPCVar
  // and pSymbol.
  let pFuncNameE = pNormalString |>> FuncName

  let pUnOpE =
    pchar '(' >>. spaces >>. pUnaryOperator
    .>> spaces .>>. pExpr .>> spaces .>> pchar ')'
    |>> (fun (op, e1) -> AST.unop op e1)

  let pBinOpE =
    pchar '(' >>. spaces >>. pExpr .>> spaces .>>. pBinaryOperator .>> spaces
    .>>. pExpr .>> spaces .>> pchar ')'
    |>> (fun ((e1, op), e2 )-> AST.binop op e1 e2)

  let pRelOpE =
    pchar '(' >>. spaces >>. pExpr .>> spaces .>>. pRelativeOperator .>> spaces
    .>>. pExpr .>> spaces .>> pchar ')'
    |>> (fun ((e1, op), e2 )-> AST.relop op e1 e2)

  let pLoadE =
    pchar '[' >>. pExpr .>> spaces .>> pchar ']' .>> spaces .>> pchar ':'
    .>> spaces .>>. pRegType
    |>> (fun (e, typ) -> AST.load isa.Endian typ e)

  let pIteE =
    pchar '(' >>. pstring "ite" >>. spaces >>. pchar '(' >>. spaces
    >>. pExpr .>> spaces .>> pchar ')' .>> spaces .>> pchar '(' .>> spaces
    .>>. pExpr .>> spaces .>> pchar ')' .>> spaces .>> pchar '(' .>> spaces
    .>>. pExpr .>> pchar ')' .>> spaces .>> pchar ')'
    |>> (fun ((cond, e1), e2) -> AST.ite cond e1 e2)

  let pCastE =
    pCastType .>> spaces .>> pchar ':' .>> spaces .>>. pRegType .>> spaces
    .>> pchar '(' .>> spaces .>>. pExpr .>> spaces .>> pchar ')'
    |>> (fun ((kind, typ), expr) -> AST.cast kind typ expr)

  let pExtractE =
    pchar '(' .>> spaces >>. pExpr .>> spaces .>> pchar '[' .>> spaces
    .>>. pint32 .>> spaces .>> pchar ':' .>> spaces .>>. pint32 .>> spaces
    .>> pchar ']' .>> spaces .>> pchar ')'
    |>> (fun ((expr, n), pos) ->
           AST.extract expr (RegType.fromBitWidth (n + 1 - pos)) pos)

  let pUndefinedExprE =
    pstring "Undefined expression (" .>> spaces >>. pNormalString .>> spaces
    .>> pchar ')' |>> AST.unDef dummyRegType
  do
    pExprRef :=
      pNumE //<|> attempt pVarE <|> attempt pPCVarE
      <|> attempt pTempVarE
      //<|> attempt pNameE <|> attempt pFuncNameE
      <|> attempt pUnOpE
      <|> attempt pBinOpE <|> attempt pRelOpE <|> attempt pLoadE
      <|> attempt pIteE <|> attempt pCastE <|> attempt pExtractE
      <|> attempt pUndefinedExprE
      <|> pVarE

  (*-----------------------------Statements.---------------------------*)

  let pISMark =
    pstring "SMark" >>. spaces >>. pchar '(' >>. spaces >>. pHexToUInt64
    .>> spaces .>> pchar ')'
    |>> (fun addr -> ISMark (addr, 0u))

  let pIEMark =
    pstring "EMark" >>. spaces >>. pchar '(' >>. spaces
    >>. pstring "pc">>. spaces >>. pstring ":=" >>. spaces
    >>. pHexToUInt64 .>> spaces .>> pchar ')' |>> IEMark

  /// Parses ISMark or IEMark.
  let pStartOrEndMark =
    spaces >>. pstring "===" >>. spaces >>. pchar 'I'
    >>. (pISMark <|> pIEMark)

  let pLMark =
    spaces >>. pstring "===" >>. spaces >>. pstring "LMark" >>. spaces
    >>. pchar '(' >>. spaces >>. pNormalString .>> spaces .>> pchar ')'
    |>> AST.lblSymbol |>> LMark

  let pPut =
    (attempt pTempVarE <|> pVarE >>= makeExpectedType) .>> spaces
    .>> pstring ":=" .>> spaces .>>. pExpr
    |>> (fun (dest, value) -> AST.(:=) dest value)

  let pJmp =
    pstring "JmpLbl" .>> spaces >>. pExpr |>> Jmp

  let pInterJmp =
    pstring "Jmp" .>> spaces >>. pExpr
    |>> (fun expr -> InterJmp (dummyExpr, expr, dummyInterJmpInfo))

  let pStore =
    pchar '[' .>> spaces >>. pExpr .>> spaces .>> pchar ']' .>> spaces
    .>> pstring ":=" .>> spaces .>>. pExpr
    |>> (fun (expr1, expr2) -> Store (isa.Endian, expr1, expr2))

  let pCJmp =
    pstring "if" .>> spaces >>. pExpr .>> spaces .>> pstring "then" .>> spaces
    .>> pstring "JmpLbl" .>> spaces .>>. pExpr .>> spaces .>> pstring "else"
    .>> spaces .>> pstring "JmpLbl" .>> spaces .>>. pExpr
    |>> (fun ((cond, tExpr), fExpr) -> CJmp (cond, tExpr, fExpr))

  let pInterCJmp =
    pstring "if" .>> spaces >>. pExpr .>> spaces .>> pstring "then" .>> spaces
    .>> pstring "Jmp" .>> spaces .>>. pExpr .>> spaces .>> pstring "else"
    .>> spaces .>> pstring "Jmp" .>> spaces .>>. pExpr
    |>> (fun ((cond, tExp), fExp) -> InterCJmp (cond, dummyExpr, tExp, fExp))

  let pSideEffect =
    pstring "SideEffect" .>> spaces >>. pNormalString
    |>> (fun str -> sideEffectFromString str |> SideEffect)

  let statement =
    attempt pStartOrEndMark
    <|> pLMark
    <|> attempt pPut
    <|> attempt pInterJmp
    <|> attempt pJmp
    <|> attempt pStore
    <|> attempt pInterCJmp
    <|> attempt pCJmp
    <|> attempt pSideEffect
    >>= typeCheckR

  member __.Run str =
    match runParserOnString statement 0<rt> "" str with
    | FParsec.CharParsers.Success (result, _, pos) ->
      if pos.Column <> int64 (str.Length + 1) then
        printfn "[Invalid] Invalid characters at the end of input"
        ; None
      else Some result
    | FParsec.CharParsers.Failure (str, _, _) ->
      printfn "%s" str
      None
