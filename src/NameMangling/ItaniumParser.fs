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

module B2R2.NameMangling.ItaniumParser

open FParsec
open System
open B2R2.NameMangling.ItaniumTables
open B2R2.NameMangling.ItaniumUtils


type ItaniumParserClass () =
  let rec convertbase36todecimal idx res input =
    match input with
    | [] -> res
    | hd :: tail ->
      if Char.IsDigit hd then
        let hd = int (hd) - int('0')
        let cur = pown 36 idx
        convertbase36todecimal (idx + 1) (res + hd * cur) tail
      else
        let hd = int (hd) + 10 - int('A')
        let cur = pown 36 idx
        convertbase36todecimal (idx + 1) (res + hd * cur) tail

  let pbase36 =
    many((satisfy Char.IsDigit) <|> (satisfy Char.IsUpper))

  let namebackrefS =
    pchar 'S' >>. ((pchar '_' |>> fun (c) -> (-1))
    <|> (pbase36 |>> List.rev |>> convertbase36todecimal 0 0 .>> pchar '_'))
    .>>. getUserState
    |>> (fun (x, us) ->
          if x + 2 <= us.Namelist.Length then
            let a2 = (List.rev us.Namelist).[x + 1]
            match a2 with
            | NestedName (a, b) -> NestedName (a, List.rev b)
            | _ -> a2
          else
            Dummy "" ) |>> SingleArg

  let namebackrefT =
    pchar 'T' >>. ((pchar '_' |>> fun (c) -> (-1))
    <|> (pbase36 |>> List.rev |>> convertbase36todecimal 0 0 .>> pchar '_'))
    .>>. getUserState
    |>> (fun (x, us) ->
          if x + 2 <= us.TemplateArgList.Length then
            let a2 = (us.TemplateArgList).[x + 1]
            a2
          else
            Dummy "")

  let nparray (a) b =
    (letter <|> pchar '_') .>>. parray (b - 1) a
    |>> (fun (a, c) -> (Array.append [|a|] c))

  let pvendor =
    pchar 'u' >>.
    (pint32 >>= (nparray (letter <|> digit <|> pchar '_')) |>> String)
    |>> Vendor

  let builtinsingle =
    satisfy (fun c -> if (getTypeS c <>"") then true else false)
    |>> string |>> BuiltinTypeIndicator.ofString

  let builtindouble =
    pchar 'D' .>>. (anyOf "dfheisan") |>> (fun (a, b) -> string(a) + string(b))
    |>> BuiltinTypeIndicator.ofString

  let builtin =
    builtinsingle <|> builtindouble
    |>> BuiltinType

  let pSxsubstitution =
    pchar 'S' .>>. (anyOf "iabsod") |>> (fun (a, b) -> string(a) + string(b))
    |>> Sxabbreviation.ofString
    |>> Sxsubstitution

  /// Parser for std.
  let pSt =
    pstring "St" |>> Sxabbreviation.ofString|>> Sxsubstitution

  let pReference =
    (pstring "R" <|> pstring "O") |>> ReferenceQualifier.ofString
    |>> Reference

  let pCVqualifier =
    (pchar 'K' .>>. opt (pchar 'V')) <|> (pchar 'V' .>>. opt (pchar 'K'))
    |>> ConsTandVolatile.ofChar |>> CVqualifier

  let pRCVqualifier =
    pstring "r" .>>. opt (pchar 'V') .>>. opt (pchar 'K') .>>.
    lookAhead (pstring "P") |>> fun (((a, b), c), d) -> (a, b, c)
    |>> RestrictQualifier.ofTuple |>> Restrict

  let pPointer =
    many1 (pchar 'P' |>> SingleP) |>> Pointer

  let pConstVolatile =
    attempt (pPointer .>>. (pCVqualifier <|> pRCVqualifier))
    |>> ConstVolatile

  let pCVR =
    (pCVqualifier <|> preturn (Name "")) .>>.
    (pReference <|> preturn (Name "")) |>> CVR

  let unaryOplist () = ["ps"; "ng"; "ad"; "de"; "nt"; "co"; "pp"; "mm"]

  let pUOperator =
    unaryOplist () |> List.map pstring |> choice |>> OperatorIndicator.ofString
    |>> Operators

  let pSpecificOp =
    pstring "nw" <|> pstring "na" <|> pstring "dl" <|> pstring "da"
    |>> OperatorIndicator.ofString |>> Operators

  let binaryOplist () =
    ["pl"; "pL"; "pm"; "pt"; "mi"; "ml"; "mI"; "mL"; "dv"; "dV";
    "rm"; "rM"; "rs"; "rS"; "ls"; "lS"; "lt"; "le"; "an"; "aN";
    "aa"; "aS"; "or"; "oR"; "oo"; "eo"; "eq"; "ne"; "cm"; "gt";
    "ge"; "cl"; "sr"; "ix"
    ]

  let pBOperator =
    binaryOplist () |> List.map pstring |> choice |>> OperatorIndicator.ofString
    |>> Operators

  let pOperator = pUOperator <|> pBOperator <|> pSpecificOp

  let name =
    opt (pchar 'L') >>.
    (pint32 >>= (nparray (letter <|> digit <|> pchar '_')) |>> String) |>> Name

  let psxname = pSt .>>. name |>> Sxname

  let pTemplate, pTemplateref = createParserForwardedToRef ()

  let pNestedname, pNestedNameref = createParserForwardedToRef ()

  let pUnaryExpr, pUnaryExprref = createParserForwardedToRef ()

  let pBinaryExpr, pBinaryExprref = createParserForwardedToRef ()

  let pPointerArg, pPointerArgref = createParserForwardedToRef ()

  let pfunc, pfuncref = createParserForwardedToRef ()

  let prefArg, prefArgref = createParserForwardedToRef ()

  let stmt, stmtref = createParserForwardedToRef ()

  let pConstructor =
    pchar 'C' .>> (pchar '1' <|> pchar '2' <|> pchar '3')
    |>> ConstructorDestructor.ofChar |>> ConsOrDes

  let pDestructor =
    pchar 'D' .>> (pchar '1' <|> pchar '2' <|> pchar '0')
    |>> ConstructorDestructor.ofChar
    |>> ConsOrDes

  let pConsOrDes = pDestructor  <|> pConstructor

  let pSxoperator = pSt .>>. pOperator |>> Sxoperator

  let pLiteral =
    pchar 'L' >>. builtin .>>.
    ((manyCharsTill (letter <|> digit) (pchar 'E')) |>> Name)
    |>> Literal

  let pValue =
    pchar 'L' >>. builtin .>>. (pint32 |>> Num) .>> pchar 'E' |>> Literal

  let pExpr =
    pchar 'X' >>. (pUnaryExpr <|> pBinaryExpr <|> namebackrefT) .>> pchar 'E'

  let pReferenceArg = pReference .>>. opt (pCVqualifier) |>> ReferenceArg

  let pNormalArg =
    attempt ((attempt pTemplate <|> name <|> pvendor <|> attempt (psxname)
    <|> attempt (pSxoperator)) >>= addargumenttolist .>> clearCarry)
    <|>
    (pPointerArg <|> pNestedname <|> builtin <|> attempt (pSxsubstitution)
    <|> namebackrefS <|> (namebackrefT >>=addTsubtolist))
    .>> clearCarry

  let pArray =
      pchar 'P' >>. many (pchar 'A' >>. pint32 .>> pchar '_') .>>.
      (attempt pfunc <|> pNormalArg<|> prefArg)
      |>> ArrayPointer

  let pfunctionarg =
      opt (pstring "Dp") >>. (attempt (opt (pCVqualifier))
      .>>. (attempt (pNormalArg) <|> attempt prefArg <|> pArray))
      |>> Functionarg >>= addargumenttolist

  let pFunctionArg =
    opt (pstring "Dp") >>. (attempt pfunc <|> pfunctionarg)

  let pTemplateArg =
    (attempt pfunc <|> pfunctionarg <|> attempt (pValue) <|> pLiteral <|> pExpr)

  let pTempArgPack =
    pchar 'J' >>. many (pTemplateArg) .>> pchar 'E'
    |>> Arguments

  let pArguments = (many1 (pFunctionArg.>> clearCarry)) |>> Arguments

  /// Template arguments.
  let pIarguments =
    saveandreturn (
      (many1 ((pTemplateArg <|> pTempArgPack) .>> clearCarry))
      |>> Arguments .>> clearCarry
    )

  let pFunctionRetArgs =
    (attempt pTemplate <|> name <|> pNestedname <|> pOperator
    <|> attempt (psxname) <|> pSxoperator)
    >>= checkcarry >>= addTemplate .>> removelast .>> clearCarry
    .>>. (pFunctionArg) .>>. (pArguments <|> preturn (Name ""))
    |>> (fun ((a, b), c) -> (a, b, c))
    |>> Function

  /// Parser for expression arguments.
  let pSingleArgument =
    (attempt pTemplate
    <|> attempt (name)
    <|> attempt (pchar 'L' >>. pchar '_' >>. pchar 'Z' >>. stmt .>> pchar 'E')
    <|> attempt (pValue)
    <|> (pLiteral)
    <|> pUnaryExpr
    <|> pBinaryExpr
    <|> attempt (psxname)
    <|> attempt (pSxoperator)
    <|> attempt (pSxsubstitution)
    <|> namebackrefS
    <|> namebackrefT)
    |>> SingleArg

  let pSimpleOperator =
    pOperator .>>. pArguments |>> SimpleOP

  /// Parser for all Sx abbreviation.
  let pStandard = (attempt (pSxsubstitution) <|> pSt) >>= updatecarry

  /// Seperating beginning of nested name from rest. First name cannot be
  /// Constructor or Destructor.
  let pNestedBeginning =
    (attempt pTemplate <|> attempt (pOperator) <|> name <|> namebackrefT)
    >>= addtoNamelist
    <|> attempt (pStandard) <|> (namebackrefS >>= updatecarry)

  let nparse =
    opt (many (pConstVolatile)) .>>. (pPointer)
    |>> FunctionBegin

  let tietheknot =
    pTemplateref :=
    saveandreturn (
      ((name <|> attempt (psxname) <|> pOperator <|> attempt pConsOrDes
      <|> attempt (pSxoperator)) >>= addtoNamelist
      <|> attempt (pSxsubstitution) <|> namebackrefS <|> namebackrefT)
      .>> clearCarry .>> pchar 'I'
      .>>. (pIarguments) .>> pchar 'E'
      |>> Template
    )

    pNestedNameref :=
      pchar 'N'
      >>. (pCVR <|> preturn (Name ""))
      .>>.
      (attempt (pNestedBeginning)
      .>>. many (pNestedBeginning <|> (pConsOrDes >>= addtoNamelist)))
      .>> pchar 'E'
      |>> fun (a, (b, c)) -> (a, b :: c)
      |>> NestedName

    pUnaryExprref :=
      (pUOperator .>>. pSingleArgument)
      |>> UnaryExpr

    pBinaryExprref :=
      ((pstring "sr" |>> OperatorIndicator.ofString |>> Operators)
      .>>. ((pSingleArgument) >>= addtoNamelist) .>>. pSingleArgument)
      <|>
      (pBOperator .>>. pSingleArgument .>>. pSingleArgument)
      |>> (fun ((a, b), c) -> (a, b, c))
      |>> BinaryExpr

    pPointerArgref :=
      (pstring "P" .>>. (opt (pRCVqualifier <|> pCVqualifier)
      ) .>>. (pNormalArg))
      |>> (fun ((a, b), c) -> (a, b, c)) |>> PointerArg >>= addargumenttolist
      .>> clearCarry

    pfuncref :=
      (nparse <|> pReference) .>> pchar 'F' .>>. pFunctionArg
      .>>. pArguments .>> pchar 'E' |>> (fun ((a, b), c) -> (a, b, c))
      |>> FunctionPointer
      >>= addfunctionptolist .>> clearCarry

    prefArgref :=
      pReferenceArg .>>. (pNormalArg <|> pfunc)
      |>> RefArg >>= addargumenttolist

    stmtref :=
      attempt (pFunctionRetArgs)
      <|> pNestedname
      <|> attempt pTemplate
      <|> pSimpleOperator
      <|> name
      <|> attempt (psxname)
      <|> pSxsubstitution

  member __.Parse str =
    runParserOnString (stmt) ItaniumUserState.Default "" str


