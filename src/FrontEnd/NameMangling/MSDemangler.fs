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

open System
open FParsec
open B2R2
open B2R2.FrontEnd.NameMangling.MSUtils

/// Represents the demangler for Microsoft mangled names.
type MSDemangler () =
  (* Helper functions for updating the UserState. *)
  let addToNameList c =
    updateUserState ( fun us -> { us with NameList = c :: us.NameList })
    >>. preturn c

  let addToTypeList c =
    updateUserState ( fun us -> { us with TypeList = c :: us.TypeList })
    >>. preturn c

  let saveScopeAndReturn p =
    getUserState >>= (fun parent -> p .>> updateUserState (fun _ -> parent))

  let clearUserState =
    updateUserState ( fun _us -> MSUserState.Default)

  (* Helper functions to parse name. *)
  let charListToStr lst = String (List.toArray lst)

  let letterOrDigit = satisfy Char.IsLetterOrDigit

  let snum = digit |>> string |>> int64 |>> (+) 1L

  let szero = pchar '@' |>> (fun _ -> 0L)

  let phex =
    many1 upper .>> pchar '@' |>> List.map getHexChar |>> List.map string
    |>> List.fold (+) "0x"
    |>> int64

  /// Parses the encodedNumber in an MSMangled string.
  let pEncodedNum =
    opt (pchar '?' ) .>>. (snum <|> szero <|> phex)
    |>> (fun (sign, num) ->
           match sign with
           | Some (_) -> -1L * num
           | _ -> num)

  (* ---------------------Initialization.--------------------------------*)
  let nameFragment, nameFragmentRef = createParserForwardedToRef ()

  let fullName, fullNameRef = createParserForwardedToRef ()

  let possibleType, possibleTypeRef = createParserForwardedToRef ()

  let pFunc, pFuncRef = createParserForwardedToRef ()

  let pTemplate, pTemplateRef = createParserForwardedToRef ()

  let returnTypeOperator, returnTypeOperatorRef = createParserForwardedToRef ()

  /// Parses modifiers prefixes.
  let modifierPrefix = many (anyOf "EFGHI" |>> ModifierPrefix.fromChar)

  /// Parses normal cvModifier
  let normalcvModifier =
    modifierPrefix .>>. (anyOf "ABJCGKDHL" |>> CVModifier.fromChar)

  /// Parses cvModifier of a member.
  let memberPointerModifier =
    modifierPrefix .>>. (anyOf "QUYRVZSW0TX1" |>> CVModifier.fromChar)

  /// Parses cvModifier for a __based pointer.
  let dashBasedPointerModifier =
    modifierPrefix .>>. (anyOf "MNOP" |>> CVModifier.fromChar)

  /// Parses cvModifier for a __based member.
  let dashBasedMemberPointerModifier =
    modifierPrefix .>>. (anyOf "2345" |>> CVModifier.fromChar)

  /// Parses the calling convention.
  let pCallConv =
    upper |>> CallConvention.fromChar

  (*-------------------Non function mangled String.------------------------*)
  let pvalueInfo =
    anyOf "01234" .>>. (possibleType .>>. normalcvModifier |>> ModifiedType)
    |>> (fun (x, typeV) -> ConcatT [ Name (getVarAccessLevel x); typeV ])

  let modNameInfo =
    anyOf "67" >>. normalcvModifier .>> pchar '@'
    |>> (fun modifier -> ModifiedType (SimpleBuiltInType EmptyReturn, modifier))

  /// Parses a mangled string that does not represent a function.
  let nonFunctionString =
    fullName .>> pchar '@' >>= (fun name ->
      (pvalueInfo |>> (fun modifiedT -> ValueT (name, modifiedT) ))
       <|> (anyOf "89" >>% name)
       <|> (modNameInfo |>> (fun modifier -> ValueT (name, modifier)))
    )

  (* -------------------Name component of a function.---------------------*)

  /// Parse a name or just a variable string.
  let singleName =
    spaces >>. many1 (letter <|> anyOf "_<")
    .>>. many (letterOrDigit <|> anyOf "_<>")
    |>> (fun (a, b) -> List.concat [ a; b ] |> charListToStr)

  /// Parses a simple varaible name fragment.
  let pnameAndAt =
    singleName .>> pchar '@' |>> Name

  /// Parses anonymous namespaces
  let pAnonymousNameSpace =
    pstring "?A" >>. many (letter <|> digit) .>> pchar '@'
    >>= (fun lst -> 'A' :: lst |> charListToStr |> Name |> addToNameList
                     >>. preturn (Name "`anonymous namespace'"))

  (* For special names*)
  let pNSpecialName =
     upper <|> anyOf "23456789" |>> getSpecialName
  let pUSpecialName =
    pstring "_" >>. (noneOf [ 'R' ] <|> digit) |>> getUnderscoredSpecialName
  let pDUSpecialName =
    pstring "__" >>. (upper) |>> getdUnderscoredSpecialName
  let pUdtReturn =
    pstring "_P" >>. (pNSpecialName <|> pUSpecialName <|> pDUSpecialName)
    |>> (+) "'udt returning'"
  let pReturnTypeOperator =
    pchar 'B' >>. returnTypeOperator
  let stringConstant =
    pstring "_C@_" >>. digit >>. pnameAndAt >>. many anyChar >>% "`string'"
  let complexDynamicSpecialName =
    pchar '?'
    >>. many1 (attempt pFunc <|> attempt nonFunctionString <|> nameFragment)
    |>> FullName .>> pchar '@'
  let dynamicSpecialName =
    pstring "__" >>. anyOf "EF" |>> getdUnderscoredSpecialName .>>.
    (attempt complexDynamicSpecialName <|> nameFragment >>= addToNameList)
    |>> (fun (str, name) ->
          ConcatT [ Name str; name; Name "''" ])
  let simpleSpecialNames =
    (pNSpecialName <|> attempt pUdtReturn <|> attempt stringConstant)
     <|> attempt pUSpecialName <|> pDUSpecialName |>> Name
  /// Parses special Names like operators.
  let pSpecialName =
    pchar '?' >>.
    (pReturnTypeOperator <|> attempt dynamicSpecialName <|> simpleSpecialNames)

  (* For RTTI0 related codes*)
  let pRTTI0 = pstring "?_R0" >>. possibleType |>> RTTI0
  let pRTTI1 =
    pipe4 (pstring "?_R1" >>. pEncodedNum) pEncodedNum pEncodedNum pEncodedNum
      (sprintf "'RTTI Base Class Descriptor at (%d,%d,%d,%d)'") |>> Name
  let pRTTIrest = pstring "?_R" >>. digit |>> getRTTI |>> Name
  /// RTTI codes that come as name fragments.
  let pRTTICode = pRTTI0 <|> pRTTI1 <|> pRTTIrest

  /// Numbered name spaces.
  let numName = pchar '?' >>. pEncodedNum |>> (sprintf "`%d'") |>> Name

  /// Constructor/Deconstructor names.
  let constName =
    pchar '0' >>. (pnameAndAt <|> pTemplate >>= addToNameList) |>> Constructor
  let deconstName =
    pchar '1' >>. (pnameAndAt <|> pTemplate >>= addToNameList) |>> Destructor
  let constructedName =
    pchar '?' >>. (constName <|> deconstName)
  let nestedFunc =
    pstring "??" >>. (attempt pFunc <|> nonFunctionString) |>> NestedFunc
  /// Handles substitutions for the name components of the function.
  let nameBackRef =
    digit |>> string |>> int .>>. getUserState
    |>> (fun (x, us) ->
          if x >= us.NameList.Length then Name "???????"
          else (List.rev us.NameList)[x])

  (*---------------For the type components of functions.-----------------*)

  /// Parses built in types represented by just one letter.
  let normalBuiltInType =
    anyOf "CDEFGHIJKLMNOX" |>> NormalBuiltInType.fromChar |>> SimpleBuiltInType
  let underscoredType =
    pchar '_' >>. anyOf "DEFGHIJKLMNSUW" |>> UnderscoredBuiltInType.fromChar
    |>> ExtendedBuiltInType
  let nullPtrType = pstring "$$T" >>% Name "std::nullptr_t"
  /// Parses built in types reprsented by a longer string.
  let extendedBuiltInType = underscoredType <|> nullPtrType

  /// Parses the character that a mangled string would use to indicate the
  /// type that follows is a complex type.
  let complexTypeIndicator =
    choice (List.map pstring [ "T"; "U"; "V"; "_X"; "Y" ])
    |>> ComplexTypeKind.fromString

  /// Parsed an Enumerated type.
  let enumType =
     pchar 'W' >>. digit .>>. fullName .>> pchar '@' |>>
     (fun (c, name) -> EnumType (EnumTypeKind.fromChar c, name))
  /// Complex Type can be either a union, struct, class or cointerface.
  let complexType =
    complexTypeIndicator .>>. fullName .>> pchar '@'
    |>> (fun (complexTypeKind, comp) -> ComplexT (complexTypeKind, comp))

  /// Parses pointer and reference indicators.
  let pointerType = anyOf "ABPQRS" |>> PointerTypeIndicator.fromChar
  /// Assigns char 'X' for normal rReference and Z for volatile rReference.
  let rValueReference =
    pstring "$$" >>. ((pchar 'Q' >>% 'X') <|> (pchar 'R' >>% 'Z'))
    |>> PointerTypeIndicator.fromChar
  let blankTypeMod =
    pstring "$$C" <|> pstring "?" >>% 'C' |>> PointerTypeIndicator.fromChar
  /// Parses the whole pointer symbol with modifiers.
  let pPtrStrT =
    tuple3
      (pointerType <|> attempt rValueReference <|> blankTypeMod)
      normalcvModifier
      (preturn (Name ""))
    |>> PointerStrT
  /// Includes the normal pointers, references and empty modifiers.
  let normalPointer =
    pPtrStrT .>>. possibleType |>> PointerT <??> "Simple Pointer"

  (* --------For Microsoft Specific __based and member pointers.-----------*)
  let memberPointer =
    tuple3
      (pointerType <|> attempt rValueReference <|> blankTypeMod)
      memberPointerModifier
      (fullName |>> (fun name -> FullName [ Name ""; name ])) .>> pchar '@'
    |>> PointerStrT .>>. possibleType |>> PointerT

  let dashBasedPtrVoid = pchar '0' >>. (preturn (Name "__based(void)"))

  let dashBasedPtrName =
    pchar '2' >>. fullName .>> pchar '@'
    |>> (fun name -> ConcatT [ Name "__based("; name; Name ")" ])

  let dashBasedPointer =
    tuple2
      (pointerType <|> attempt rValueReference <|> blankTypeMod)
      dashBasedPointerModifier >>=
    (fun (ptr, mods) ->
         (dashBasedPtrVoid <|> dashBasedPtrName)
         |>> (fun carry -> PointerStrT (ptr, mods, carry))
     <|> (pchar '5' |>>
           (fun _ -> PointerStrT (EmptyPointer, ([], NoMod), Name "" )))
    ) .>>. possibleType |>> PointerT

  let dashBasedMemberPointer =
    tuple4
      (pointerType <|> attempt rValueReference <|> blankTypeMod)
      dashBasedMemberPointerModifier
      (fullName .>> pchar '@')
      (dashBasedPtrVoid <|> dashBasedPtrName)
    |>> (fun (ptr, mods, name, dname) ->
          PointerStrT
            (ptr, mods, ConcatT([ dname
                                  Name " "
                                  FullName [ Name ""; name ] ]))
        )
    .>>. possibleType |>> PointerT

  (*-------------For pointers to different data structures--------------*)
  /// All possible pointer types except for function and array pointers.
  let basicPointerTypes =
    attempt normalPointer <|> attempt memberPointer
    <|> attempt dashBasedPointer <|> dashBasedMemberPointer

  /// Pointer to an array type.
  let arrayPtr =
    tuple3
      (many1 pPtrStrT .>> pchar 'Y')
      (pEncodedNum |>> int >>= (fun n -> parray n (pEncodedNum |>> int))
         |>> Seq.toList)
      possibleType
    |>> ArrayPtr <??> " Array Pointer"

  /// Parses array type indicator and the following cv modifiers.
  let arrayTypeHelper =
    pstring "_O" >>. normalcvModifier
  /// Array Type (not pointer to array).
  let arrayType =
    pipe3 arrayTypeHelper (many arrayTypeHelper) possibleType
      (fun mods dimension dataT ->
         ArrayType (ModifiedType(dataT, mods), dimension.Length + 1))

  /// Handles back substitutions for arguments.
  let typeBackRef =
    digit |>> string |>> int .>>. getUserState
    |>> (fun (x, us) ->
          if x >= us.TypeList.Length then Name "?????"
          else (List.rev us.TypeList)[x])

  /// Parses a type and adds it to the typeList if it is not a simple type.
  let smartParseType =
    attempt normalBuiltInType
    <|> typeBackRef
    <|> (possibleType >>= addToTypeList)

  let pFuncParameters =
    many smartParseType .>>. opt (pchar 'Z')
    .>> opt (pstring "@Z" <|> pstring "Z")
    |>> (fun (typs, ender) ->
           if ender <> None && (List.rev typs).Head <> (SimpleBuiltInType VoidP)
             then List.append typs [ SimpleBuiltInType Ellipsis ]
           else typs
    )

  //Since all the function pointers are considered as normal pointers.
  let pointerAtFunc =
    tuple3
      pointerType
      normalcvModifier
      (preturn (Name ""))
    |>> PointerStrT

  /// A function pointer coming as a parameter to another function.
  let pFuncPointer =
    many (attempt pointerAtFunc) .>>.
    (pointerType |>> (fun p -> PointerStrT (p, ([], NoMod), Name "")))
    .>> anyOf "67" .>>. pCallConv .>>.
    (possibleType .>>. pFuncParameters |>> (fun (x, lst) -> x :: lst))
    |>> (fun (((ptrStrs,fPtr), cc), lst) ->
          FuncPointer
            (fPtr :: List.rev ptrStrs, cc, lst.Head, "", lst.Tail, None))
    <?> "function Type"
  let pMemberFuncPointer =
    many (attempt pointerAtFunc) .>>.
    (pointerType .>> anyOf "89" .>>. fullName .>> pchar '@'|>>
     (fun (p,n) -> PointerStrT (p, ([], NoMod), FullName [ Name ""; n ])))
    .>>. normalcvModifier .>>. pCallConv .>>.
    (possibleType .>>. pFuncParameters |>> (fun (x, lst) -> x :: lst))
    |>> (fun ((((ptrStrs,fPtr), mods), cc), lst) ->
          FuncPointer
            (fPtr :: List.rev ptrStrs, cc, lst.Head, "", lst.Tail, Some mods))
    <?> "member function pointer Type"
  let pDashBasedFuncPointer =
    many (attempt pointerAtFunc) .>>.
    (pointerType .>> pchar '_' .>> anyOf "AB" .>>.
      (dashBasedPtrVoid <|> dashBasedPtrName)
         |>> (fun (p, n) -> PointerStrT (p, ([], NoMod), n)))
    .>>. pCallConv .>>.
    (possibleType .>>. pFuncParameters |>> (fun (x, lst) -> x :: lst))
    |>> (fun (((ptrStrs,fPtr), cc), lst) ->
      FuncPointer
        (fPtr :: List.rev ptrStrs, cc, lst.Head, "", lst.Tail, None))

  // All types of function pointers.
  let allFuncPointers =
    attempt pFuncPointer
    <|> attempt pMemberFuncPointer
    <|> attempt pDashBasedFuncPointer

  (*---Parse the function information (call types,args, modifiers, scope).---*)
  /// Parses call scope that requires modifiers to be attached.
  let requireModS = anyOf "ABEFIJMNQRUV" |>> CallScope.fromChar
  /// Parses call scope that does not require modifiers to be attached.
  let noModS = anyOf "CDKLSTYZ" |>> CallScope.fromChar
  let emptyReturn = pchar '@' >>% EmptyReturn |>> SimpleBuiltInType
  let returnTmodifier = pchar '?' >>. normalcvModifier

  let pReqMod =
    requireModS .>>. normalcvModifier .>>. pCallConv .>>. (opt returnTmodifier)
    .>>. (possibleType <|> emptyReturn) .>>. pFuncParameters
    |>> (fun (((((s, modifier), cc), rtMod),r), tList) ->
           s, modifier, cc, r :: tList, rtMod)
  let pNoMod =
    noModS .>>. pCallConv .>>. (opt returnTmodifier)
    .>>. (possibleType <|> emptyReturn) .>>. pFuncParameters
    |>> (fun ((((s, cc),rtMod),r),tList) ->
           s, ([], NoMod), cc, r :: tList, rtMod)

  /// Differentiates the scopes requiring modifiers for function from the
  /// ones that don't. The function information parser parses all the
  /// information about the function except the name.
  let fInfo =
     opt (pstring "$$F") >>. opt (pchar '_') >>. (attempt pReqMod <|> pNoMod)

  (*---------------Unique Template Argument types---------------------*)
  let ignored = pchar '$' >>. (pchar 'Z' <|> pchar 'V') >>% IgnoredType
  let anonymousParam =
    pchar '?' >>. pEncodedNum |>> (sprintf "'template-parameter-%d'") |>> Name
  let numTempParam = pchar '0' >>. pEncodedNum |>> string |>> Name
  let ptrToMangledSymbol = pstring "1?" >>. pFunc |>> MangledSymbolPtr
  let expNumberParam =
    pchar '2' >>. pEncodedNum .>>. pEncodedNum
    |>> (fun (baseN, expN) ->
          let baseStr = (string baseN).ToCharArray ()
          sprintf "%c.%se%d" (Seq.head baseStr)
            (String.Concat (Seq.tail baseStr)) expN |> Name )
  let twoTuple =
    pipe2 (pchar 'F' >>. pEncodedNum) pEncodedNum (sprintf "{%d,%d}") |>> Name
  let threeTuple =
    pipe3 (pchar 'G' >>. pEncodedNum) pEncodedNum pEncodedNum
      (sprintf "{%d,%d,%d}")
    |>> Name
  let emptyPack = pchar 'S' >>% Name ""
  let specialTemplateParams =
    pchar '$' >>.
    (numTempParam <|> ptrToMangledSymbol <|> expNumberParam
    <|> twoTuple <|> threeTuple <|> emptyPack <|> ignored)
    <|> anonymousParam
  let constructedTemplate =
    pstring "?$?" >>. anyOf "01"
    >>. many (specialTemplateParams <|> possibleType) .>> pchar '@'.>>.
    ((pnameAndAt <|> attempt pTemplate) >>= addToNameList <|> nameFragment)
    |>> ConstructedTemplate

  (* ----------For adding names and templates to the UserState----------*)
  /// Parse a name and add to the UserState if it is a name or template.
  let smartParseName =
    pnameAndAt <|> attempt pTemplate >>= addToNameList
    <|> attempt pAnonymousNameSpace <|> nameFragment

  let smartParseExceptTemplate =
    pnameAndAt >>= addToNameList
    <|> attempt constructedTemplate
    <|> attempt constructedName
    <|> attempt pSpecialName
    <|> nameFragment

  let functionFullName =
    smartParseExceptTemplate .>>. many smartParseName
    |>> (fun (x, y) -> x :: y |> FullName)

  (*---------------------For Thunk Functions.--------------------------*)
  /// Parses thunk adjustor function.
  let pThunkFuncAdj =
    functionFullName .>> pchar '@' .>>. (anyOf "WXGHOP" |>> CallScope.fromChar)
    .>>. (pEncodedNum |>> sprintf "`adjustor{%d}'" |>> Name)
    .>>. normalcvModifier .>>. pCallConv .>>. (opt returnTmodifier)
    .>>. (possibleType <|> emptyReturn) .>>. many smartParseType |>>
    (fun ((((((((name, scope), adjustor), mods), cc), rtMod), rt), pts)) ->
       FunctionT (scope, mods, cc, ConcatT [ name; adjustor ], rt, pts, rtMod))

  /// Parses flat thunk function.
  let pThunkFuncFlat =
    functionFullName .>> pstring "@$" .>> pchar 'B' .>>. pEncodedNum
    .>> pchar 'A' .>>. (upper |>> CallConvention.fromChar)
    |>> (fun ((name, n), callT) ->
           let typeInfo = sprintf "{%d,{flat}}' }'" n
           ThunkF (callT, name, Name typeInfo, SimpleBuiltInType EmptyReturn))

  /// Parses Local static destructor helper function.
  let pThunkFuncStaticDestructor =
    functionFullName .>> pstring "@$" .>> pchar 'A' .>>.
    (possibleType .>>. normalcvModifier |>> ModifiedType)
    |>> (fun (name, typ) ->
         ThunkF (Free, name, Name "`local static destructor helper'", typ))

  /// Parses value {for <name>} construct.
  let pThunkFuncForName =
    functionFullName .>> pstring "@$" .>> pchar 'C' .>>. fullName .>> pchar '@'
    |>> (fun (name, vName) -> ConcatT[name; Name "{for "; vName; Name "}"])

  /// Parses vtordisp{<num>,<num>} thunk functions.
  let pThunkVDisplacement =
    functionFullName .>> pstring "@$" .>>. anyOf "012345" .>>. pEncodedNum
    .>>. pEncodedNum .>>. normalcvModifier .>>. pCallConv .>>.
    (possibleType .>>. pFuncParameters |>> (fun (x, lst) -> x :: lst))
    |>> (fun ((((((name, callS), num1), num2), cvMods), cc), typs) ->
           let addedName = Name (sprintf "`vtordisp{%d,%d}'" num1 num2)
           let newName = ConcatT [ name; addedName ]
           FunctionT (CallScope.fromChar callS, cvMods, cc,
                      newName, typs.Head, typs.Tail, None)
    )

  /// All supported Thunk Functions.
  let allThunkFunc =
    attempt pThunkFuncAdj
    <|> attempt pThunkFuncFlat
    <|> attempt pThunkFuncStaticDestructor
    <|> attempt pThunkVDisplacement
    <|> pThunkFuncForName

  (* -------------Tying the knot for the references created-----------------*)
  do
    nameFragmentRef.Value <-
       nameBackRef <|> pnameAndAt <|> attempt pTemplate
       <|> attempt nestedFunc <|> attempt pRTTICode <|> attempt numName
       <|> pSpecialName <|> attempt constructedName

    fullNameRef.Value <-
      smartParseName .>>. many (pAnonymousNameSpace <|> smartParseName )
      |>> (fun (fst, rst) -> FullName (fst :: rst))

    possibleTypeRef.Value <-
      attempt allFuncPointers <|> attempt arrayPtr <|> attempt complexType
      <|> enumType <|> attempt arrayType <|> normalBuiltInType
      <|> extendedBuiltInType
      <|> basicPointerTypes <|> typeBackRef

    pFuncRef.Value <-
      functionFullName .>> pchar '@' .>>. fInfo
      |>> (fun (name, (scope, modifier, callT, tList, rtMod)) ->
            (scope, modifier, callT, name, tList.Head, tList.Tail, rtMod)
            |> FunctionT)

    pTemplateRef.Value <-
      saveScopeAndReturn (
        clearUserState >>.pstring "?$"
        >>. (pnameAndAt >>= addToNameList <|> pSpecialName )
        .>>. many (attempt specialTemplateParams <|> possibleType)
        .>> pchar '@'
        |>> Template
      )
    returnTypeOperatorRef.Value <-
      fullName .>> pchar '@' .>>. fInfo |>>
      (fun (name, (scope, mods, callT, tList, rtMod)) ->
        let newName = FullName [ConcatT [Name "operator "; tList.Head]; name]
        let newReturn = SimpleBuiltInType EmptyReturn
        FunctionT (scope, mods, callT, newName, newReturn, tList.Tail, rtMod)
      )

  (* ---------------All Expressions from a mangled string------------------ *)
  let allExprs =
    attempt pFunc <|> attempt nonFunctionString <|> attempt allThunkFunc
    <|> attempt pTemplate <|> fullName

  /// Check if the given string is a well-formed mangled string.
  static member IsWellFormed (str: string) =
    let str = str.Trim ()
    str.Length <> 0 && str.StartsWith "?" && str.Contains "@"

  interface IDemanglable with
    member _.Demangle str =
      match runParserOnString allExprs MSUserState.Default "" str[1..] with
      | Success (result, _, _) ->
        let result = MSInterpreter.interpret result
        Result.Ok <| result.Trim ()
      | Failure _ ->
        Result.Error ErrorCase.ParsingFailure

