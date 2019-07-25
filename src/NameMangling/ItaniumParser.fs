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

let charListtoStr a =
  String (List.toArray a)

let namebackrefS =
  pchar 'S' >>. ((pchar '_' |>> fun (c) -> (-1))
  <|> (pint32 .>> pchar '_'))
  .>>. getUserState
  |>> (fun (x, us) ->
        if x + 2 <= us.Namelist.Length then
          let a2 = (List.rev us.Namelist).[x + 1]
          match a2 with
          | NestedName (a, b) -> NestedName (a, List.rev b)
          | _ -> a2
        else
          Dummy "")

let namebackrefT =
  pchar 'T' >>. ((pchar '_' |>> fun (c) -> (-1))
  <|> (pint32 .>> pchar '_'))
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

let typelist =
  ["Dd"; "Df"; "Dh"; "De"; "Di"; "Ds"; "Da"; "Dn"]

let builtindouble =
  typelist |> List.map pstring |> choice |>> BuiltinTypeIndicator.ofString

let builtin =
  builtinsingle <|> builtindouble
  |>> BuiltinType

let Sxsubstitutes =
  ["Si"; "Sa"; "Sb"; "Ss"; "So"; "Sd"]

let pSxsubstitution =
  Sxsubstitutes |> List.map pstring |> choice |>> Sxabbreviation.ofString
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
  pstring "r" .>>. opt (pchar 'V') .>>. opt (pchar 'K') .>>. pstring "P"
  |>> fun (((a, b), c), d) -> (a, b, c, d)
  |>> RestrictQualifier.ofTuple
  |>> Restrict

let pRCVandCV =
  pRCVqualifier .>>. opt pCVqualifier |>> RestrictCV

let pPointer=
  many1 (pchar 'P' |>> SingleP) |>> Pointer

let pConstVolatile =
  attempt (pPointer .>>. pCVqualifier) |>> ConstVolatile

let pCVR =
  opt pCVqualifier .>>. opt pReference |>> CVR

let pUOperator =
  ["ps"; "ng"; "ad"; "de"; "nt"; "co"; "pp"; "mm"]
  |> List.map pstring |> choice |>> OperatorIndicator.ofString
  |>> Operators

let pSpecificOp =
  pstring "nw" <|> pstring "na" <|> pstring "dl" <|> pstring "da"
  |>> OperatorIndicator.ofString |>> Operators

let pPostfixOp =
  pstring "pp" <|> pstring "mm" |>> OperatorIndicator.ofString |>> Operators

let pBOperator =
  ["pl"; "pL"; "pm"; "pt"; "mi"; "ml"; "mI"; "mL"; "dv"; "dV";
  "rm"; "rM"; "rs"; "rS"; "ls"; "lS"; "lt"; "le"; "an"; "aN";
  "aa"; "aS"; "or"; "oR"; "oo"; "eo"; "eq"; "ne"; "cm"; "gt";
  "ge"
  ]
  |> List.map pstring |> choice |>> OperatorIndicator.ofString
  |>> Operators

let pOperator = pUOperator <|> pBOperator <|> pSpecificOp <|> pPostfixOp

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

let pConsOrDes = pDestructor <|> pConstructor

let pSxoperator = pSt .>>. pOperator |>> Sxoperator

let pLiteral =
  pchar 'L' >>. builtin .>>.
  ((manyCharsTill (letter <|> digit) (pchar 'E')) |>> Name)
  |>> Literal

let pValue = pchar 'L' >>. builtin .>>. (pint32 |>> Num) |>> Literal

let pExpr = pchar 'X' >>. (pUnaryExpr <|> pBinaryExpr) .>> pchar 'E'

let pReferenceArg =
  pReference .>>. opt pCVqualifier
  |>> ReferenceArg

let pNormalArg =
  attempt ((attempt pTemplate <|> name <|> pvendor <|> attempt psxname
  <|> attempt pSxoperator)
  >>= addargumenttolist
  .>> clearCarry)
  <|>
  (pPointerArg <|> pNestedname <|> builtin <|> attempt pSxsubstitution
  <|> namebackrefS <|> (namebackrefT >>=addTsubtolist))
  .>> clearCarry

let pFunctionArg =
  attempt pNormalArg <|> attempt prefArg
  |>> SingleArg <|> pfunc

let pTemplateArg =
  (attempt pNormalArg <|> attempt pLiteral <|> pValue <|> pExpr <|> prefArg
  |>> SingleArg <|> pfunc)

let pArguments =
  (many1 (pFunctionArg .>> clearCarry)) |>> Arguments

/// Template arguments.
let pIarguments =
  saveandreturn (
    (many1 ((pTemplateArg) .>> clearCarry))
    |>> Arguments
    .>> clearCarry
  )

let pFunctionRetArgs =
  (attempt pTemplate <|> name <|> pNestedname <|> pOperator
  <|> attempt psxname
  <|> pSxoperator
  ) >>= checkcarry >>= addTemplate .>> removelast .>> clearCarry
  .>>. (pFunctionArg) .>>. opt pArguments
  |>> (fun ((a, b), c) -> (a, b, c))
  |>> Function

/// Parser for expression arguments.
let pSingleArgument =
  (attempt pTemplate
  <|> attempt name
  <|> (pchar 'L' >>. pchar '_' >>. pchar 'Z' >>. stmt .>> pchar 'E')
  <|> attempt pLiteral
  <|> pValue
  <|> pUnaryExpr
  <|> pBinaryExpr
  <|> attempt psxname
  <|> attempt pSxoperator
  <|> attempt pSxsubstitution
  <|> namebackrefS
  <|> namebackrefT)
  |>> SingleArg

let pSimpleOperator =
  pOperator .>>. pArguments |>> SimpleOP

pTemplateref :=
  saveandreturn (
    ((name <|> attempt psxname <|> pOperator <|> attempt pSxoperator)
    >>= addtoNamelist
    <|> attempt pSxsubstitution <|> namebackrefS <|> namebackrefT)
    .>> clearCarry .>> pchar 'I'
    .>>. (pIarguments) .>> pchar 'E'
    |>> Template
  )

/// Parser for all Sx abbreviation.
let pStandard = (pSxsubstitution <|> pSt) >>= updatecarry

/// Seperating beginning of nested name from rest. First name cannot be
/// Constructor or Destructor.
let pNestedBeginning =
  (attempt pTemplate <|> attempt pOperator <|> name) >>= addtoNamelist
  <|> attempt pStandard <|> namebackrefS
  <|> (namebackrefT >>= addTsubtolist)

pNestedNameref :=
  pchar 'N'
  >>. opt pCVR
  .>>.
  (attempt pNestedBeginning
  .>>. many (pNestedBeginning <|> (pConsOrDes >>= addtoNamelist)))
  .>> pchar 'E'
  |>> fun (a, (b, c)) -> (a, b :: c)
  |>> NestedName

pUnaryExprref :=
  (pUOperator .>>. pSingleArgument)
  |>> UnaryExpr

pBinaryExprref :=
  (pBOperator .>>. pSingleArgument .>>. pSingleArgument)
  |>> (fun ((a, b), c) -> (a, b, c))
  |>> BinaryExpr

pPointerArgref :=
  (pstring "P" .>>. (opt (pRCVandCV <|> pCVqualifier)
  ) .>>. (pNormalArg))
  |>> (fun ((a, b), c) -> (a, b, c)) |>> PointerArg >>= addargumenttolist
  .>> clearCarry

let pRestrictend =
  pRCVqualifier .>>. opt (pPointer)
  |>> (fun (a, b) ->
    match a, b with
    | Restrict v1, Some (Pointer plist) ->
      let first = Restrict JustPointer
      let second = Restrict v1
      List.rev (second :: first :: plist)
    | Restrict v1, None ->
      let first = Restrict JustPointer
      let second = Restrict v1
      first :: second :: []
    | _ -> []) |>> RestrictEnd

let nparse =
  opt (many (pConstVolatile)) .>>. (pPointer <|> pRestrictend)
  |>> FunctionBegin

pfuncref :=
  (nparse <|> pReference) .>> pchar 'F' .>>. pFunctionArg .>>. pArguments
  .>> pchar 'E'
  |>> (fun ((a, b), c) -> (a, b, c))
  |>> FunctionPointer
  >>= addfunctionptolist .>> clearCarry

prefArgref :=
  pReferenceArg .>>.
  (pNormalArg <|> pfunc)
  |>> RefArg >>= addargumenttolist

stmtref :=
  attempt pFunctionRetArgs
  <|> pNestedname
  <|> attempt pTemplate
  <|> pSimpleOperator
  <|> name
  <|> attempt psxname
  <|> pSxsubstitution

let prog = stmt

let run str =
  runParserOnString prog ItaniumUserState.Default "" str
