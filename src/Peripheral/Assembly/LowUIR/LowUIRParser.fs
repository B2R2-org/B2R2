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

namespace B2R2.Peripheral.Assembly.LowUIR

open FParsec
open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.Peripheral.Assembly.Utils
open B2R2.Peripheral.Assembly.LowUIR.Helper

type Parser<'t> = Parser<'t, RegType>

type LowUIRParser (isa, regbay: RegisterBay) =

  let pIdentifier =
    let isAllowedFirstChar c = isAsciiLetter c
    let isAllowedChar c = isAsciiLetter c || isDigit c
    many1Satisfy2L isAllowedFirstChar isAllowedChar "identifier"

  let pHexUInt64 =
     many hex
     |>> (Seq.map string)
     |>> String.concat ""
     |>> (fun s -> Convert.ToUInt64 (s, 16))

  let ws = spaces

  let numberFormat =
    NumberLiteralOptions.AllowMinusSign |||
    NumberLiteralOptions.AllowBinary |||
    NumberLiteralOptions.AllowHexadecimal |||
    NumberLiteralOptions.AllowOctal |||
    NumberLiteralOptions.AllowPlusSign

  let pNumber =
    numberLiteral numberFormat "number"
    |>> fun n -> int64 n.String

  let pRegType =
    (anyOf "IiFf") >>. pint32 |>> RegType.fromBitWidth

  let pBitVector =
    pNumber
    .>>. opt (pchar ':' >>. ws >>. pRegType)
    >>= (fun (n, typ) ->
      match typ with
      | None -> getUserState |>> (fun t -> BitVector.ofInt64 n t)
      | Some typ -> preturn (BitVector.ofInt64 n typ))

  let pUnaryOperator =
    [ "-"; "~"; "sqrt"; "cos"; "sin"; "tan"; "atan" ]
    |> List.map pstring |> List.map attempt |> choice |>> UnOpType.ofString

  let pCastType =
    [ "sext"; "zext"; "itof"; "round"; "ceil"; "floor"; "trunc"; "fext" ]
    |> List.map pstring |> List.map attempt |> choice |>> CastKind.ofString

  let pExpr, pExprRef = createParserForwardedToRef ()

  let pNum = pBitVector |>> AST.num

  let regnames = regbay.GetAllRegNames ()

  let pVar =
    List.map pstringCI regnames
    |> List.map attempt
    |> choice
    |>> regbay.StrToRegExpr

  let pTempVar =
    pstring "T_" >>. pint32 .>> ws
    .>> pchar ':' .>> ws .>>. pRegType
    |>> (fun (num, typ) -> TempVar (typ, num))

  let pUnOp =
    pUnaryOperator .>> ws .>>. pExpr
    |>> (fun (op, e1) -> AST.unop op e1)

  let pLoad =
    pchar '[' >>. pExpr .>> ws .>> pchar ']' .>> ws
    .>> pchar ':' .>> ws .>>. pRegType
    |>> (fun (e, typ) -> AST.load isa.Endian typ e)

  let pCast =
    pCastType .>> ws .>> pchar ':' .>> ws .>>. pRegType .>> ws
    .>> pchar '(' .>> ws .>>. pExpr .>> ws .>> pchar ')'
    |>> (fun ((kind, typ), expr) -> AST.cast kind typ expr)

  let toExtractExpr ((expr, n), pos) =
    AST.extract expr (RegType.fromBitWidth (n + 1 - pos)) pos

  let pExtractVar =
    (pVar <|> pTempVar) .>> ws .>> pchar '[' .>> ws
    .>>. pint32 .>> ws .>> pchar ':' .>> ws .>>. pint32 .>> ws
    .>> pchar ']'
    |>> toExtractExpr

  let pExtractExpr =
    pBetweenParen pExpr .>> ws .>> pchar '[' .>> ws
    .>>. pint32 .>> ws .>> pchar ':' .>> ws .>>. pint32 .>> ws
    .>> pchar ']'
    |>> toExtractExpr

  let pExtract =
    (attempt pExtractVar) <|> (attempt pExtractExpr)

  let pComment =
    let isComment c =
      isLetter c || isDigit c || Char.IsWhiteSpace c || c = '.'
    many1Satisfy isComment

  let pUndefinedExpr =
    pstring "??" >>. ws
    >>. pchar '(' >>. ws >>. pComment .>> ws .>> pchar ')'
    >>= fun comment ->
      getUserState |>> (fun rt -> AST.unDef rt comment)

  let pNil = pstringCI "nil" |>> (fun _ -> AST.nil)

  let pPrimaryValue =
    [ attempt pExtract .>> ws
      pVar .>> ws
      pTempVar .>> ws
      pUnOp .>> ws
      pLoad .>> ws
      pNum .>> ws
      pCast .>> ws
      pUndefinedExpr .>> ws
      pNil .>> ws ] |> choice

  let pFLog =
    pstring "lg" >>. ws
    >>. pchar '(' >>. ws
    >>. pExpr .>> ws .>> pchar ',' .>> ws
    .>>. pExpr .>> ws .>> pchar ')'
    |>> (fun (e1, e2) -> AST.binop BinOpType.FLOG e1 e2)

  let initInfix (opp: OperatorPrecedenceParser<_, _, _>) ops =
    ops |> List.iter (fun (initializer, op, prec, assoc) ->
      opp.AddOperator (InfixOperator(op, ws, prec, assoc, initializer)))

  let initTernary (opp: OperatorPrecedenceParser<_, _, _>) args =
    args |> fun (initializer, opl, opr, assoc) ->
      opp.AddOperator (TernaryOperator(opl, ws, opr, ws, 1, assoc, initializer))

  let opp = OperatorPrecedenceParser<Expr, _, RegType> ()
  let pOps = opp.ExpressionParser
  let term =
    pPrimaryValue
    <|> pFLog
    <|> pBetweenParen pOps

  let () =
    opp.TermParser <- term
    pExprRef := pOps

    [ AST.binop BinOpType.ADD, "+", 3, Associativity.Left
      AST.binop BinOpType.SUB, "-", 3, Associativity.Left
      AST.binop BinOpType.MUL, "*", 4, Associativity.Left
      AST.binop BinOpType.DIV, "/", 4, Associativity.Left
      AST.binop BinOpType.SDIV, "?/", 4, Associativity.Left
      AST.binop BinOpType.MOD, "%", 4, Associativity.Left
      AST.binop BinOpType.SMOD, "?%", 4, Associativity.Left
      AST.binop BinOpType.SHL, "<<", 4, Associativity.Left
      AST.binop BinOpType.SHR, ">>", 4, Associativity.Left
      AST.binop BinOpType.SAR, "?>>", 4, Associativity.Left
      AST.binop BinOpType.AND, "&", 4, Associativity.Left
      AST.binop BinOpType.OR, "|", 4, Associativity.Left
      AST.binop BinOpType.XOR, "^", 4, Associativity.Left
      AST.binop BinOpType.CONCAT, "++", 4, Associativity.Left
      AST.binop BinOpType.APP, "-|", 5, Associativity.Right
      AST.binop BinOpType.CONS, "::", 4, Associativity.Right
      AST.binop BinOpType.FADD, "+.", 4, Associativity.Left
      AST.binop BinOpType.FSUB, "-.", 4, Associativity.Left
      AST.binop BinOpType.FMUL, "*.", 4, Associativity.Left
      AST.binop BinOpType.FDIV, "/.", 4, Associativity.Left
      AST.binop BinOpType.FPOW, "^^", 4, Associativity.Left ]
    |> initInfix opp

    [ AST.relop RelOpType.EQ, "=", 1, Associativity.Left
      AST.relop RelOpType.NEQ, "!=", 1, Associativity.Left
      AST.relop RelOpType.GT, ">", 2, Associativity.Left
      AST.relop RelOpType.GE, ">=", 2, Associativity.Left
      AST.relop RelOpType.SGT, "?>", 2, Associativity.Left
      AST.relop RelOpType.SGE, "?>=", 2, Associativity.Left
      AST.relop RelOpType.LT, "<", 2, Associativity.Left
      AST.relop RelOpType.LE, "<=", 2, Associativity.Left
      AST.relop RelOpType.SLT, "?<", 2, Associativity.Left
      AST.relop RelOpType.SLE, "?<=", 2, Associativity.Left
      AST.relop RelOpType.FGT, ">.", 2, Associativity.Left
      AST.relop RelOpType.FGE, ">=.", 2, Associativity.Left
      AST.relop RelOpType.FLT, "<.", 2, Associativity.Left
      AST.relop RelOpType.FLE, "<=.", 2, Associativity.Left ]
    |> initInfix opp

    (AST.ite, "?", ":", Associativity.Right)
    |> initTernary opp

  let pISMark =
    ws
    >>. pchar '('
    >>. ws >>. pHexUInt64
    .>> ws .>> pchar ';' .>> ws
    .>>. puint32 .>> ws
    .>> pchar ')'
    .>> ws .>> pchar '{'
    |>> ISMark

  let pIEMark =
    ws
    >>. pchar '}' >>. ws
    >>. pstring "//" >>. ws >>. pHexUInt64 .>> ws
    |>> IEMark

  let pLMark =
    ws >>. pchar ':' >>. pIdentifier
    |>> (AST.lblSymbol >> LMark)

  let pPut =
    ws
    >>. ((attempt pTempVar <|> pVar) >>= updateExpectedType)
    .>> ws .>> pstring ":=" .>> ws .>>. pExpr
    |>> (fun (dest, value) -> AST.(:=) dest value)

  let pStore =
    ws
    >>. pchar '[' .>> ws >>. pExpr .>> ws .>> pchar ']' .>> ws
    .>> pstring ":=" .>> ws .>>. pExpr
    |>> (fun (e1, e2) -> Store (isa.Endian, e1, e2))

  let pJmp =
    ws >>. pstring "jmp" >>. ws >>. pExpr |>> Jmp

  let pCJmp =
    ws
    >>. pstring "if" .>> ws >>. pExpr .>> ws
    .>> pstring "then" .>> ws
    .>> pstring "jmp" .>> ws .>>. pExpr .>> ws
    .>> pstring "else" .>> ws .>> pstring "jmp" .>> ws .>>. pExpr
    |>> (fun ((cond, tExpr), fExpr) -> CJmp (cond, tExpr, fExpr))

  let pInterJmp =
    pstring "ijmp" .>> ws >>. pExpr
    |>> (fun expr ->
      let rt = AST.typeOf expr
      InterJmp (dummyExpr rt, expr, InterJmpInfo.Base))

  let pInterCJmp =
    ws
    >>. pstring "if" .>> ws >>. pExpr .>> ws
    .>> pstring "then" .>> ws
    .>> pstring "ijmp" .>> ws .>>. pExpr .>> ws
    .>> pstring "else" .>> ws .>> pstring "ijmp" .>> ws .>>. pExpr
    |>> (fun ((cond, tExp), fExp) ->
      let rt = AST.typeOf tExp
      InterCJmp (cond, dummyExpr rt, tExp, fExp))

  let pSideEffect =
    ws
    >>. pstring "!!" .>> ws >>. pIdentifier
    |>> (fun str -> SideEffect.ofString str |> SideEffect)

  let pStatement =
    attempt pISMark
    <|> attempt pIEMark
    <|> attempt pLMark
    <|> attempt pPut
    <|> attempt pStore
    <|> attempt pJmp
    <|> attempt pCJmp
    <|> attempt pInterJmp
    <|> attempt pInterCJmp
    <|> attempt pSideEffect
    >>= typeCheck

  let pLines =
    sepBy (restOfLine false) newline

  member private __.SeparateLines str =
    match run pLines str with
    | Success (lines, _, _) -> Result.Ok lines
    | Failure (errStr, _, _) -> Result.Error (errStr)

  member private __.TryParseStmt line =
    try runParserOnString pStatement 0<rt> "" line
    with e ->
      let dummyPos = Position ("", 0L, 0L, 0L)
      let msg = e.Message + Environment.NewLine + "> " + line
      Failure (msg, ParserError (dummyPos, 0<rt>, unexpected ""), 0<rt>)

  member private __.ParseLines acc lines =
    match lines with
    | line :: rest ->
      if String.length line = 0 then __.ParseLines acc rest
      else (* A LowUIR stmt always occupies a single line. *)
        match __.TryParseStmt line with
        | Success (stmt, _, _pos) -> __.ParseLines (stmt :: acc) rest
        | Failure (errStr, _, _) -> Result.Error (errStr)
    | [] -> Result.Ok (List.rev acc |> List.toArray)

  member __.Parse str =
    __.SeparateLines str
    |> Result.bind (__.ParseLines [])
