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

namespace B2R2.FrontEnd.NameMangling

open FParsec
open System
open B2R2
open B2R2.FrontEnd.NameMangling.ItaniumTables
open B2R2.FrontEnd.NameMangling.ItaniumUtils

/// Represents a demangler for Itanium C++ names.
type ItaniumDemangler() =
  let charListtoStr a = String(List.toArray a)

  let rec convertbase36todecimal idx res input =
    match input with
    | [] -> res
    | hd :: tail ->
      if Char.IsDigit hd then
        let hd = int (hd) - int ('0')
        let cur = pown 36 idx
        convertbase36todecimal (idx + 1) (res + hd * cur) tail
      else
        let hd = int (hd) + 10 - int ('A')
        let cur = pown 36 idx
        convertbase36todecimal (idx + 1) (res + hd * cur) tail

  let pbase36 = many ((satisfy Char.IsDigit) <|> (satisfy Char.IsUpper))

  let namebackrefS =
    pchar 'S' >>. ((pchar '_' |>> fun (c) -> (-1))
    <|> (pbase36 |>> List.rev |>> convertbase36todecimal 0 0 .>> pchar '_'))
    .>>. getUserState
    |>> (fun (x, us) ->
          if x + 2 <= us.Namelist.Length then
            let a2 = (List.rev us.Namelist)[x + 1]
            match a2 with
            | NestedName(a, b) -> NestedName(a, List.rev b)
            | PointerArg(a, b, Specific idx) ->
              let value = us.TemplateArgList[idx + 1]
              PointerArg(a, b, value)
            | RefArg(a, Specific idx) ->
              let value = us.TemplateArgList[idx + 1]
              RefArg(a, value)
            | Specific idx ->
              let value = us.TemplateArgList[idx + 1]
              value
            | _ -> a2
          else
            Dummy "") |>> SingleArg

  let namebackrefT =
    pchar 'T' >>. ((pchar '_' |>> fun (c) -> (-1))
    <|> (pint32 .>> pchar '_'))
    .>>. getUserState
    |>> (fun (x, us) ->
          if x + 2 <= us.TemplateArgList.Length then
            let a2 = (us.TemplateArgList)[x + 1]
            (a2, x)
          else
            (Dummy "", x)) |>> TemplateSub

  let nparray (a) b =
    (letter <|> pchar '_' <|> pchar '$') .>>. parray (b - 1) a
    |>> (fun (a, c) -> (Array.append [| a |] c))

  let pvendor =
    pchar 'u' >>.
    (pint32 >>= (nparray (letter <|> digit <|> pchar '_')) |>> String)
    |>> Vendor

  let builtinsingle =
    satisfy (fun c -> getTypeS c <> "")
    |>> string |>> BuiltinTypeIndicator.ofString

  let builtindouble =
    pchar 'D' .>>. (anyOf "dfheisanc") |>> (fun (a, b) -> string a + string b)
    |>> BuiltinTypeIndicator.ofString

  let builtin =
    builtinsingle <|> builtindouble
    |>> BuiltinType

  let pSxsubstitution =
    pchar 'S' .>>. (anyOf "iabsod") |>> (fun (a, b) -> string a + string b)
    |>> Sxabbreviation.ofString
    |>> Sxsubstitution

  /// Parser for std.
  let pSt = pstring "St" |>> Sxabbreviation.ofString |>> Sxsubstitution

  let pReference =
    (pstring "R" <|> pstring "O") |>> ReferenceQualifier.ofString |>> Reference

  let pCVqualifier =
    (pchar 'K' .>>. opt (pchar 'V')) <|> (pchar 'V' .>>. opt (pchar 'K'))
    |>> ConsTandVolatile.ofChar |>> CVqualifier

  let pRCVqualifier =
    pstring "r" .>>. opt (pchar 'V') .>>. opt (pchar 'K') .>>.
    lookAhead (pstring "P") |>> fun (((a, b), c), d) -> (a, b, c)
    |>> RestrictQualifier.ofTuple |>> Restrict

  let pCVR =
    (pCVqualifier <|> preturn (Name "")) .>>.
    (pReference <|> preturn (Name "")) |>> CVR

  let unaryOplist () = [ "ps"; "ng"; "ad"; "de"; "nt"; "co"; "pp"; "mm" ]

  let pUOperator =
    unaryOplist () |> List.map pstring |> choice |>> OperatorIndicator.ofString
    |>> Operators

  let pSpecificOp =
    pstring "nw" <|> pstring "na" <|> pstring "dl" <|> pstring "da"
    <|> pstring "cl"
    |>> OperatorIndicator.ofString |>> Operators

  let binaryOplist () =
    [ "pl"
      "pL"
      "pm"
      "pt"
      "mi"
      "ml"
      "mI"
      "mL"
      "dv"
      "dV"
      "rm"
      "rM"
      "rs"
      "rS"
      "ls"
      "lS"
      "lt"
      "le"
      "an"
      "aN"
      "aa"
      "aS"
      "or"
      "oR"
      "oo"
      "eo"
      "eq"
      "ne"
      "cm"
      "gt"
      "ge"
      "sr"
      "ix"
      "qu" ]

  let pBOperator =
    binaryOplist () |> List.map pstring |> choice |>> OperatorIndicator.ofString
    |>> Operators

  let pOperator = pUOperator <|> pBOperator <|> pSpecificOp

  let pABITag =
    opt (pchar 'L') >>.
    (pint32 >>= (nparray (letter <|> digit <|> pchar '_')) |>> String)
    .>> pchar 'B' .>>.
    (pint32 >>= (nparray (letter <|> digit <|> pchar '_')) |>> String)
    |>> ABITag

  let name =
    opt (pchar 'L') >>.
    (pint32 >>= (nparray (letter <|> digit <|> pchar '_')) |>> String) |>> Name

  let psxname = pSt .>>. (attempt pABITag <|> name) |>> Sxname

  let pTemplate, pTemplateref = createParserForwardedToRef ()

  let pNestedname, pNestedNameref = createParserForwardedToRef ()

  let pPointerArg, pPointerArgref = createParserForwardedToRef ()

  let pfunc, pfuncref = createParserForwardedToRef ()

  let prefArg, prefArgref = createParserForwardedToRef ()

  let stmt, stmtref = createParserForwardedToRef ()

  let scopeEncoding, scopeEncodingref = createParserForwardedToRef ()

  let pExpression, pExpressionRef = createParserForwardedToRef ()

  let pConstructor =
    pchar 'C' .>>
    (pchar '1' <|> pchar '2' <|> pchar '3' <|> pchar '4' <|> pchar '5')
    |>> ConstructorDestructor.ofChar |>> ConsOrDes

  let pDestructor =
    pchar 'D' .>>
    (pchar '1' <|> pchar '2' <|> pchar '0' <|> pchar '4' <|> pchar '5')
    |>> ConstructorDestructor.ofChar
    |>> ConsOrDes

  let pConsOrDes = pDestructor <|> pConstructor

  let pSxoperator = pSt .>>. pOperator |>> Sxoperator

  let pLiteral =
    pchar 'L' >>. builtin .>>.
    ((many1CharsTill (letter <|> digit) (pchar 'E')) |>> Name)
    |>> Literal


  let pCallOfset =
    (pchar 'h' .>> opt (pchar 'n') .>> pint32 .>> pchar '_')
    <|> (pchar 'v' .>> opt (pchar 'n') .>> pint32 .>> pchar '_'
    .>> opt (pchar 'n') .>> pint32 .>> pchar '_')
    |>> CallOffSet.ofString |>> CallOffset

  let pVirtualThunk = pchar 'T' >>. pCallOfset .>>. stmt |>> VirtualThunk

  let pVirtualThunkRet =
    pstring "Tc" >>. pCallOfset >>. pCallOfset >>. stmt |>> VirtualThunkRet

  let pDigitNozero = satisfy (fun x -> Char.IsDigit x && x <> '0')

  let pDiscard =
    attempt (pchar '_' .>> digit)
    <|> (pstring "__" >>. pDigitNozero >>. many1 digit >>. pchar '_')

  let pGuardVariable =
    pstring "GV" >>. many scopeEncoding .>>.
    (attempt pTemplate <|> pNestedname <|> attempt pABITag <|> name
    <|> pOperator <|> attempt psxname <|> attempt pSxsubstitution
    <|> pSxoperator) .>> opt pDiscard
    |>> GuardVariable

  let pTransactionSafeFunc = pstring "GTt" >>. stmt |>> TransactionSafeFunction

  let pReferenceArg = pReference .>>. opt (pCVqualifier) |>> ReferenceArg

  let pVector =
    pstring "Dv" >>. (pint32 |>> Num) .>> pchar '_'
    .>>.
    (attempt ((attempt pTemplate <|> attempt pABITag <|> name <|> pvendor
    <|> attempt (psxname)
    <|> attempt (pSxoperator)) >>= addargumenttolist .>> clearCarry)
    <|> (pPointerArg <|> pNestedname <|> builtin <|> attempt (pSxsubstitution)
    <|> namebackrefS <|> (namebackrefT >>= addTsubtolist))
    .>> clearCarry) |>> Vector

  let pNormalArg =
    attempt ((attempt pTemplate <|> attempt pABITag <|> name <|> pvendor
    <|> attempt (psxname) <|> pVector
    <|> attempt (pSxoperator))
    >>= addargumenttolist .>> clearCarry)
    <|>
    (pPointerArg <|> pNestedname <|> builtin <|> attempt (pSxsubstitution)
    <|> namebackrefS <|> (namebackrefT >>= addTsubtolist))
    .>> clearCarry

  /// During pack expansion of argument pack, reference qualifier before
  /// pack is applied to every element of pack individually.
  let pArgpack =
    pstring "Dp" >>. opt pReferenceArg .>>. namebackrefT
    |>>
    (fun (x, y) ->
      match x with
      | Some value ->
        RefArg(value, y)
      | None -> RefArg(ReferenceArg(Reference Empty, None), y))
    >>= addArgPack >>= addOnCondition
    |>>
    (fun b ->
      match b with
      | RefArg(a, Arguments alist)
      | RefArg(a, TemplateSub(Arguments alist, _)) ->
        List.map (fun x -> RefArg(a, x)) alist
      | _ -> [ b ]
    ) |>> Arguments

  let pMember = pchar 'M' >>. (pNormalArg <|> prefArg) |>> MemberPointer

  let pPointer = many1 (pchar 'P' |>> SingleP <|> pMember) |>> Pointer

  let pConstVolatile =
    attempt ((pPointer .>>. (pCVqualifier <|> pRCVqualifier))
    .>> lookAhead (pPointer))
    |>> ConstVolatile

  let pScope =
    scopeEncoding .>>.
    (attempt pTemplate <|> attempt pABITag <|> name <|> attempt psxname
    <|> attempt pSxoperator
    <|> pNestedname <|> namebackrefS) |>> ScopeEncoding
    >>= addargumenttolist

  let pfunctionarg =
    attempt (opt (pstring "Dp")) >>. (attempt (opt (pCVqualifier))
    .>>. (attempt (pNormalArg) <|> attempt prefArg))
    |>> Functionarg >>= addargumenttolist

  let pArray =
    opt (pchar 'P' |>> SingleP <|> pReference) .>>.
    many1 (pchar 'A' >>. ((pint32 |>> Num) <|> (namebackrefT)
    <|> preturn (Name "")) .>> pchar '_')
    .>>. (attempt pfunc <|> pfunctionarg)
    |>> (fun ((a, b), c) -> (a, b, c))
    |>> ArrayPointer >>= addArrayPointer

  let pMemberPAsArg =
    pMember .>>. (pNormalArg <|> prefArg) |>> MemberPAsArgument

  let pLambda =
    saveandreturn (
      opt (pchar 'M') >>.
      pstring "Ul" >>.
      (many1 (attempt pfunc <|> attempt pfunctionarg <|> attempt pArray
      <|> pMemberPAsArg) |>> Arguments) .>> pchar 'E'
      .>>. (pint32 |>> Num <|> preturn (Name "")) .>> pchar '_'
      |>> LambdaExpression >>= addLambda
    )

  let pUnnamedType =
    saveandreturn (
      pstring "Ut" >>. (pint32 |>> Num <|> preturn (Name "")) .>> pchar '_'
      |>> UnnamedType >>= addLambda
    )

  let pscopelambda =
    (scopeEncoding .>>.
      (opt (pchar 'd' >>. (pint32 |>> Num <|> preturn (Name "")) .>> pchar '_'))
    .>>. (pLambda <|> pUnnamedType)
    |>> (fun ((a, b), c) -> (a, b, c))
    |>> ScopedLambda)
    >>= addargumenttolist

  let pFunctionArg =
    (attempt pArgpack <|> attempt pfunc <|> pMemberPAsArg
    <|> attempt pfunctionarg <|> pArray)

  let pValue =
    pchar 'L' >>. pFunctionArg .>>. (attempt (pint32 |>> Num)
    <|> (puint64 |>> Num64))
    .>> pchar 'E' |>> Literal

  let pParameterRef =
    pstring "fp" >>. (pint32 |>> Num <|> preturn (Name "")) .>> pchar '_'
    |>> ParameterRef

  /// Parser for expression arguments.
  let pSingleArgument =
    (attempt pTemplate
    <|> attempt pABITag <|> attempt (name)
    <|> (attempt (pchar 'L' >>. pchar '_' >>. pchar 'Z' >>. stmt .>> pchar 'E')
    |>> ExternalName)
    <|> attempt (pValue) <|> (pLiteral)
    <|> attempt pExpression
    <|> attempt (psxname) <|> attempt (pSxoperator)
    <|> attempt (pSxsubstitution)
    <|> namebackrefS <|> (namebackrefT))
    <|> pParameterRef
    >>= expandArgs

  let pDecltype =
    (pstring "DT" <|> pstring "Dt") >>. pSingleArgument .>> pchar 'E'
    |>> DeclType

  let pBinaryExpr =
    ((pstring "sr" |>> OperatorIndicator.ofString |>> Operators)
    .>>. ((pSingleArgument) >>= addtoNamelist) .>>. pSingleArgument)
    <|> (pBOperator .>>. pSingleArgument .>>. pSingleArgument)
    |>> (fun ((a, b), c) -> (a, b, c))
    |>> BinaryExpr

  let pUnaryExpr = (pUOperator .>>. pSingleArgument) |>> UnaryExpr

  let pCallExpr =
    pstring "cl" >>. many1 pSingleArgument .>> pchar 'E'
    |>> CallExpr >>= expandCL

  let pConversionOneArg =
    pstring "cv" >>. pFunctionArg .>>. pSingleArgument |>> ConversionOne

  let pConversionMoreArg =
    pstring "cv" >>. pFunctionArg .>> pchar '_'
    .>>. many pSingleArgument .>> pchar 'E' |>> ConversionMore

  let pDotExpr =
    pstring "dt" >>. pSingleArgument .>>. (attempt pTemplate <|> name)
    |>> DotExpr >>= expandDT

  let pDotPointerExpr =
    pstring "ds" >>. pSingleArgument .>>. pSingleArgument |>> DotPointerExpr

  let pCastingExpr =
    (pstring "dc" <|> pstring "cc" <|> pstring "sc" <|> pstring "rc")
    |>> CasTing.ofString .>>. pFunctionArg .>>. pSingleArgument
    |>> (fun ((a, b), c) -> (a, b, c))
    |>> CastingExpr

  let pTypeMeasure =
    (pstring "ti" <|> pstring "st" <|> pstring "at") |>> MeasureType.ofString
    .>>. pFunctionArg |>> TypeMeasure

  let pExprMeasure =
    (pstring "te" <|> pstring "sz" <|> pstring "az" <|> pstring "nw")
    |>> MeasureExpr.ofString .>>. pSingleArgument
    |>> ExprMeasure

  let pExpressionArgPack =
    pstring "sp" >>. argPackFlagOn >>. pSingleArgument .>> argPackFlagOff
    |>> ExpressionArgPack

  let pExpr = pchar 'X' >>. (pExpression <|> pSingleArgument) .>> pchar 'E'

  let pCastOperator =
    (pstring "cv"
    .>>. pFunctionArg)
    <|> (pstring "li" .>>. name)
    <|> (pstring "v" .>> digit .>>. name)
    |>> CastOperator

  let pRTTiVirtualTable =
    (pstring "TT" <|> pstring "TI" <|> pstring "TS" <|> pstring "TV")
    |>> RTTIVirtualTable.ofString
    .>>. (pScope <|> attempt (pNormalArg) <|> pArray <|> prefArg <|> pfunc)
    .>> opt pDiscard
    |>> RTTIandVirtualTable

  let pTC =
    pstring "TC"
    >>. (pScope <|> attempt (pNormalArg) <|> pArray <|> prefArg <|> pfunc)
    .>> pint32 .>> pchar '_' .>>.
    (pScope <|> attempt (pNormalArg) <|> pArray <|> prefArg <|> pfunc)
    |>> ConstructionVtable

  let pReferenceTemporary =
    pstring "GR"
    >>. ((attempt (pchar 'L' >>. name .>> pchar '_') |>> (fun x -> (x, Num 0))
    |>> ReferenceTemporary)
    <|> ((attempt pScope
      <|> ((attempt pTemplate <|> attempt pABITag <|> name <|> attempt psxname
    <|> attempt pSxoperator) >>= addargumenttolist)
    <|> pNestedname <|> namebackrefS) .>>. ((pint32 <|> preturn 0) |>> Num)
    |>> ReferenceTemporary))

  let pTemplateArg =
    (attempt pscopelambda <|> attempt pScope <|> attempt pArgpack
    <|> attempt pfunc <|> pMemberPAsArg <|> attempt (pValue) <|> attempt pArray
    <|> attempt pfunctionarg <|> pLiteral <|> pExpr <|> pDecltype)

  let pTempArgPack =
    pchar 'J' >>. many (pTemplateArg) .>> pchar 'E'
    |>> Arguments

  let pArguments =
    (many1 ((attempt pFunctionArg <|> pDecltype) .>> clearCarry)) |>> Arguments

  let pClone =
    many (pchar '.'
    >>. ((many1 ((satisfy Char.IsLower) <|> pchar '_')
    |>> charListtoStr |>> Name)
    <|> (pint32 |>> Num)
    )) |>> Clone

  /// Template arguments.
  let pIarguments =
    saveandreturn (
      (many1 ((attempt pTemplateArg <|> attempt scopeEncoding <|> pTempArgPack)
      .>> clearCarry))
      |>> Arguments .>> clearCarry
    )

  let pFunctionRetArgs =
    many (scopeEncoding) .>>.
    ((attempt pTemplate <|> attempt pABITag <|> (name >>= addtoNamelist)
    <|> pNestedname
    <|> pOperator <|> pCastOperator
    <|> attempt (psxname) <|> attempt pSxoperator <|> pSxsubstitution)
    >>= checkcarry >>= addTemplate .>> removelast .>> clearCarry)
    .>>. (newsaveandreturn (pFunctionArg <|> pDecltype) <|> preturn (Name ""))
    .>>. (pArguments <|> preturn (Name ""))
    .>>. (pClone)
    |>> (fun ((((a, b), c), d), e) -> (a, b, c, d, e))
    |>> Function

  /// Parser for all Sx abbreviation.
  let pStandard = (attempt (pSxsubstitution) <|> pSt) >>= updatecarry

  /// Seperating beginning of nested name from rest. First name cannot be
  /// Constructor or Destructor.
  let pNestedBeginning =
    (attempt pTemplate <|> (attempt pOperator .>> flagOff)
    <|> (attempt pCastOperator .>> flagOff)
    <|> (attempt pABITag .>> flagOff) <|> (name .>> flagOff)
    <|> (pLambda .>> flagOff) <|> (pUnnamedType .>> flagOff) <|> (namebackrefT))
    >>= addtoNamelist
    <|> (attempt pStandard .>> flagOff)
    <|> (namebackrefS >>= updatecarry .>> flagOff)

  let nparse =
    attempt (opt (many (pConstVolatile))) .>>. (pPointer)
    |>> FunctionBegin

  do
    pTemplateref.Value <-
      saveandreturn (
        ((attempt pABITag <|> name <|> attempt psxname <|> pOperator
        <|> attempt pSxoperator <|> attempt pConsOrDes) >>= addtoNamelist
        <|> attempt pSxsubstitution <|> namebackrefS <|> (namebackrefT))
        .>> clearCarry .>> pchar 'I' .>>. (pIarguments) .>> pchar 'E'
        >>= checkBeginning
        |>> Template
      )

    pNestedNameref.Value <-
      pchar 'N' >>. (pCVR <|> preturn (Name ""))
      .>>.
      (attempt (pNestedBeginning)
      .>>. many (pNestedBeginning
      <|> (pConsOrDes >>= addtoNamelist .>> flagOff)))
      .>> pchar 'E'
      |>> fun (a, (b, c)) -> (a, b :: c)
      |>> NestedName

    pPointerArgref.Value <-
      (pstring "P" .>>. (opt (pRCVqualifier <|> pCVqualifier)
      ) .>>. (pNormalArg <|> pLambda <|> pUnnamedType <|> pDecltype))
      |>> (fun ((a, b), c) -> (a, b, c)) |>> PointerArg >>= addargumenttolist
      .>> clearCarry

    pfuncref.Value <-
      ((nparse <|> pReference) <|> preturn (Name "")) .>>. (opt pCVqualifier)
      .>> pchar 'F'
      .>>. pFunctionArg .>>. pArguments .>> pchar 'E'
      |>> (fun (((a, b), c), d) -> (a, b, c, d))
      |>> FunctionPointer
      >>= addfunctionptolist .>> clearCarry

    prefArgref.Value <-
      pReferenceArg .>>.
      (attempt pNormalArg <|> pfunc <|> pLambda <|> pDecltype)
      |>> RefArg >>= addargumenttolist

    pExpressionRef.Value <-
      attempt pBinaryExpr <|> attempt pUnaryExpr <|> attempt pCallExpr
      <|> attempt pConversionOneArg <|> pDotExpr <|> pDotPointerExpr
      <|> pConversionMoreArg <|> pCastingExpr <|> pTypeMeasure <|> pExprMeasure
      <|> pExpressionArgPack

    scopeEncodingref.Value <-
      pchar 'Z' >>.
      (attempt pFunctionRetArgs <|> scopeEncoding <|> namebackrefS
      <|> attempt pGuardVariable <|> pTransactionSafeFunc
      <|> attempt pRTTiVirtualTable <|> pReferenceTemporary
      <|> (attempt pVirtualThunk <|> attempt pVirtualThunkRet) <|> pTC
      ) .>> pchar 'E' |>> Scope

    stmtref.Value <-
      attempt pGuardVariable
      <|> pReferenceTemporary
      <|> pTransactionSafeFunc <|> attempt pRTTiVirtualTable
      <|> (attempt pVirtualThunk <|> attempt pVirtualThunkRet) <|> pTC
      <|> attempt (pScope .>> pDiscard)
      <|> attempt (pFunctionRetArgs)

  /// Check if the given string is a well-formed mangled string.
  static member IsWellFormed(str: string) = str.Length > 2 && str[0..1] = "_Z"

  interface IDemanglable with
    member _.Demangle str =
      match runParserOnString (stmt) ItaniumUserState.Default "" str[2..] with
      | Success(result, _, pos) ->
        if pos.Column = int64 str.Length - 1L then
          Result.Ok <| ItaniumInterpreter.interpret result
        else Result.Error ErrorCase.ParsingFailure (* Didn't consume all. *)
      | Failure(e, _, _) ->
        Result.Error ErrorCase.ParsingFailure
