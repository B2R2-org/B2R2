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
open System.Numerics
open System.Globalization
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.Peripheral.Assembly.Utils
open B2R2.Peripheral.Assembly.LowUIR.Helper

type Parser<'T> = Parser<'T, RegType>

type LowUIRParser (isa, regbay: RegisterBay) =

  let isAllowedFirstCharForID c = isAsciiLetter c

  let isAllowedCharForID c = isAsciiLetter c || isDigit c

  let pIdentifier =
    many1Satisfy2L isAllowedFirstCharForID isAllowedCharForID "identifier"

  let ws = spaces

  let numberFormat =
    NumberLiteralOptions.AllowMinusSign |||
    NumberLiteralOptions.AllowBinary |||
    NumberLiteralOptions.AllowHexadecimal |||
    NumberLiteralOptions.AllowOctal |||
    NumberLiteralOptions.AllowPlusSign

  let pNumber =
    numberLiteral numberFormat "number"
    |>> fun n ->
      let s = n.String
      if s.StartsWith ("0x") then
        BigInteger.Parse ("0" + s.Substring (2), NumberStyles.AllowHexSpecifier)
      else BigInteger.Parse (s)
      |> BitVector.OfBInt

  let pRegType =
    (anyOf "IiFf") >>. pint32 |>> RegType.fromBitWidth

  let pBitVector =
    pNumber
    .>>. opt (pchar ':' >>. ws >>. pRegType)
    >>= (fun (toBV, typ) ->
      match typ with
      | None -> getUserState |>> toBV
      | Some typ -> preturn (toBV typ))

  let pUnaryOperator =
    [ "-"; "~"; "sqrt"; "cos"; "sin"; "tan"; "atan" ]
    |> List.map (pstring >> attempt)
    |> choice
    |>> UnOpType.ofString

  let pCastType =
    [ "sext"; "zext"; "float"; "round"; "ceil"; "floor"; "trunc"; "fext"
      "roundf"; "ceilf"; "floorf"; "truncf" ]
    |> List.map (pstring >> attempt)
    |> choice
    |>> CastKind.ofString

  let pExpr, pExprRef = createParserForwardedToRef ()

  let pNum = pBitVector |>> AST.num

  let regnames = regbay.GetAllRegNames ()

  let pVar =
    regnames
    |> List.map (pstringCI >> attempt)
    |> choice
    |>> regbay.StrToRegExpr

  let pTempVar =
    pstring "T_" >>. pint32 .>> ws
    .>> pchar ':' .>> ws .>>. pRegType
    |>> (fun (num, typ) -> AST.tmpvar typ num)

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

  let pExtractNoParen =
    (pVar <|> pTempVar <|> pLoad <|> pNum <|> pCast)
    .>> ws .>> pchar '[' .>> ws
    .>>. pint32 .>> ws .>> pchar ':' .>> ws .>>. pint32 .>> ws
    .>> pchar ']'
    |>> toExtractExpr

  let pComment =
    let isComment c =
      isLetter c || isDigit c || Char.IsWhiteSpace c || c = '.'
    many1Satisfy isComment

  let pUndefinedExpr =
    pstring "??" >>. ws
    >>. pchar '(' >>. ws >>. pComment .>> ws .>> pchar ')'
    >>= fun comment ->
      getUserState |>> (fun rt -> AST.undef rt comment)

  let pNil = pstringCI "nil" |>> (fun _ -> AST.nil)

  let pPrimaryValue =
    [ attempt pExtractNoParen .>> ws
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

  let pExtractPattern =
    pchar '[' >>. ws
    >>. pint32 .>> ws .>> pchar ':' .>> ws .>>. pint32 .>> ws
    .>> pchar ']'

  let pParenOrExtract =
    pBetweenParen pOps .>>. opt pExtractPattern
    |>> (fun (e, extract) ->
      match extract with
      | Some (n, pos) ->
        AST.extract e (RegType.fromBitWidth (n + 1 - pos)) pos
      | None -> e)

  let term =
    attempt pParenOrExtract
    <|> pPrimaryValue
    <|> pFLog

  let () =
    opp.TermParser <- term
    pExprRef.Value <- pOps

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
    >>. ws >>. puint32 .>> ws
    .>> pchar ')'
    .>> ws .>> pchar '{'
    |>> AST.ismark

  let pIEMark =
    ws
    >>. pchar '}' >>. ws
    >>. pstring "//" >>. ws >>. puint32 .>> ws
    |>> AST.iemark

  let pLMark =
    ws >>. pchar ':' >>. pIdentifier
    |>> (fun name -> AST.symbol name 0 |> AST.lmark)

  let pPut =
    ws
    >>. ((attempt pTempVar <|> pVar) >>= updateExpectedType)
    .>> ws .>> pstring ":=" .>> ws .>>. pExpr
    |>> (fun (dest, value) -> AST.assign dest value)

  let pStore =
    ws
    >>. pchar '[' .>> ws >>. pExpr .>> ws .>> pchar ']' .>> ws
    .>> pstring ":=" .>> ws .>>. pExpr
    |>> (fun (e1, e2) -> AST.store isa.Endian e1 e2)

  let pJmp =
    ws >>. pstring "jmp" >>. ws >>. pIdentifier
    |>> (fun lab ->
      AST.jmp (AST.name <| AST.symbol lab 0))

  let pCJmp =
    ws
    >>. pstring "if" .>> ws >>. pExpr .>> ws
    .>> pstring "then" .>> ws
    .>> pstring "jmp" .>> ws .>>. pIdentifier .>> ws
    .>> pstring "else" .>> ws .>> pstring "jmp" .>> ws .>>. pIdentifier
    |>> (fun ((cond, tlab), flab) ->
      let tlab = AST.name <| AST.symbol tlab 0
      let flab = AST.name <| AST.symbol flab 0
      AST.cjmp cond tlab flab)

  let pInterJmp =
    pstring "ijmp" .>> ws >>. pExpr
    |>> (fun expr ->
      let rt = TypeCheck.typeOf expr
      AST.interjmp expr InterJmpKind.Base)

  let pInterCJmp =
    ws
    >>. pstring "if" .>> ws >>. pExpr .>> ws
    .>> pstring "then" .>> ws
    .>> pstring "ijmp" .>> ws .>>. pExpr .>> ws
    .>> pstring "else" .>> ws .>> pstring "ijmp" .>> ws .>>. pExpr
    |>> (fun ((cond, tExp), fExp) ->
      let rt = TypeCheck.typeOf tExp
      AST.intercjmp cond tExp fExp)

  let pExtCall =
    ws
    >>. (pstringCI "call " >>. pExpr)
    |>> AST.extCall

  let pException =
    pstringCI "Exception"
    >>. ws >>. pchar '(' >>. ws >>. pIdentifier .>> ws .>> pchar ')'
    |>> Exception

  let pSideEffectKind =
    attempt (pstringCI "breakpoint" >>% Breakpoint)
    <|> attempt (pstringCI "clk" >>% ClockCounter)
    <|> attempt (pstringCI "fence" >>% Fence)
    <|> attempt (pstringCI "delay" >>% Delay)
    <|> attempt (pstringCI "terminate" >>% Terminate)
    <|> attempt (pstringCI "int" >>. pint32 |>> Interrupt)
    <|> attempt pException
    <|> attempt (pstringCI "lock" >>% Lock)
    <|> attempt (pstringCI "pid" >>% ProcessorID)
    <|> attempt (pstringCI "syscall" >>% SysCall)
    <|> attempt (pstringCI "undef" >>% UndefinedInstr)
    <|> attempt (pstringCI "fp" >>% UnsupportedFP)
    <|> attempt (pstringCI "privinstr" >>% UnsupportedPrivInstr)
    <|> attempt (pstringCI "far" >>% UnsupportedFAR)
    <|> attempt (pstringCI "cpu extension" >>% UnsupportedExtension)

  let pSideEffect =
    ws
    >>. pstring "!!" .>> ws >>. pSideEffectKind
    |>> AST.sideEffect

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
    <|> attempt pExtCall
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
      let nl = Environment.NewLine
      let msg = e.Message + nl + e.StackTrace + nl + nl + "> " + line
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
