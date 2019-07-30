(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>
          Michael Tegegn <mick@kaist.ac.kr>

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

namespace B2R2.NameMangling

open System
open FParsec
open B2R2.NameMangling.MSUtils

type MSParser () =
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
    updateUserState ( fun us -> MSUserState.Default)

  (* Helper functions to parse name. *)
  let charListToStr lst = String (List.toArray lst)

  let letterOrDigit = satisfy Char.IsLetterOrDigit

  let snum = digit |>> string |>> int |>> (+) 1

  let szero = pchar '@' |>> (fun _ -> 0)

  let phex =
    many1 upper .>> pchar '@' |>> List.map getHexChar |>> List.map string
    |>> List.fold (fun s d -> s + d) "0x"
    |>> int

  /// Parses the encodedNumber in an MSMangled string.
  let pencodedNum =
    opt (pchar '?' ) .>>. (snum <|> szero <|> phex)
    |>> (fun (sign, num) ->
           match sign with
           | Some (_) -> -1 * num
           | _ -> num)

  (* ---------------------Initialization.--------------------------------*)
  let fullName, fullNameRef = createParserForwardedToRef ()

  let possibleType, possibleTypeRef = createParserForwardedToRef ()

  let pFunc, pFuncRef = createParserForwardedToRef ()

  let pTemplate, pTemplateRef = createParserForwardedToRef ()

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

  (*-------------------Non function mangled String.------------------------*)
  let pvalueInfo =
    anyOf "1234" .>>. (possibleType .>>. normalcvModifier |>> ModifiedType)
    |>> (fun (x, typeV) -> ConcatT [Name (getVarAccessLevel x); typeV])

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
    |>> (fun (a, b) -> List.concat [a; b] |> charListToStr)

  /// Parses a simple varaible name fragment.
  let pnameAndAt =
    singleName .>> pchar '@' |>> Name

  (* For special names*)
  let pNSpecialName =
     upper <|> anyOf "23456789" |>> getSpecialName
  let pUSpecialName =
    pstring "_" >>. (noneOf ['R'] <|> digit) |>> getUnderscoredSpecialName
  let pDUSpecialName =
    pstring "__" >>. (upper) |>> getdUnderscoredSpecialName
  let pUdtReturn =
    pstring "_P" >>. (pNSpecialName <|> pUSpecialName <|> pDUSpecialName)
    |>> (+) "'udt returning'"
  let returnTypeOperator =
    pchar 'B' >>. pFunc |>>
    (function
      | FunctionT (scope, modInfo, callConv, name, returnT, paramTs, rtMod) ->
        let newName = FullName [ConcatT [Name "operator "; returnT]; name]
        let newReturn = SimpleBuiltInType EmptyReturn
        FunctionT (scope, modInfo, callConv, newName, newReturn, paramTs, rtMod)
      | _ -> Name "???")
  let stringConstant =
    pstring "_C@_" >>. digit >>. pnameAndAt >>. many anyChar >>% "`string'"
  let complexDynamicSpecialName =
    pchar '?' >>. many (attempt pFunc <|> attempt nonFunctionString <|> fullName)
    |>> FullName .>> pchar '@'
  let dynamicSpecialName =
    pstring "__" >>. anyOf "EF" |>> getdUnderscoredSpecialName .>>.
    (attempt complexDynamicSpecialName <|> fullName)
    |>> (fun (str, name) ->
          ConcatT [Name str; name; Name "''" ])
  let simpleSpecialNames =
    (pNSpecialName <|> attempt pUdtReturn <|> attempt stringConstant)
     <|> attempt pUSpecialName <|> pDUSpecialName |>> Name
  /// Parses special Names like operators.
  let pSpecialName =
    pchar '?' >>.
    (returnTypeOperator <|> attempt dynamicSpecialName <|> simpleSpecialNames)

  (* For RTTI0 related codes*)
  let pRTTI0 = pstring "?_R0" >>. possibleType |>> RTTI0
  let pRTTI1 =
    pipe4 (pstring "?_R1" >>. pencodedNum) pencodedNum pencodedNum pencodedNum
      (sprintf "'RTTI Base Class Descriptor at (%d,%d,%d,%d)'") |>> Name
  let pRTTIrest = pstring "?_R" >>. digit |>> getRTTI |>> Name
  /// RTTI codes that come as name fragments.
  let pRTTICode = pRTTI0 <|> pRTTI1 <|> pRTTIrest

  /// Numbered name spaces.
  let numName = pchar '?' >>. snum |>> (sprintf "`%d'") |>> Name

  /// Constructor/Deconstructor names.
  let constName =
    pchar '0' >>. (pnameAndAt <|> pTemplate >>= addToNameList) |>> Constructor
  let deconstName =
    pchar '1' >>. (pnameAndAt <|> pTemplate >>= addToNameList) |>> Destructor
  let constructedName =
    getPosition >>=
     (fun pos -> if pos.Index <> 0L then fail "Did not appear first"
                 else pchar '?' >>. (constName <|> deconstName)
    )
  let nestedFunc =
    pstring "??" >>. (attempt pFunc <|> nonFunctionString) |>> NestedFunc
  /// Handles substitutions for the name components of the function.
  let nameBackRef =
    digit |>> string |>> int .>>. getUserState
    |>> (fun (x, us) ->
          if x >= us.NameList.Length then Name "???????"
          else (List.rev us.NameList).[x])

  /// All possible name fragments.
  let nameFragment =
     nameBackRef <|> pnameAndAt <|> attempt pTemplate
     <|> attempt nestedFunc <|> attempt constructedName
     <|> attempt pRTTICode <|> attempt numName <|> pSpecialName

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
    choice (List.map pstring ["T"; "U"; "V"; "_X"; "Y"])
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
      (fullName |>> (fun name -> FullName [Name ""; name])) .>> pchar '@'
    |>> PointerStrT .>>. possibleType |>> PointerT

  let dashBasedPtrVoid = pchar '0' >>. (preturn (Name "__based(void)"))

  let dashBasedPtrName =
    pchar '2' >>. fullName .>> pchar '@'
    |>> (fun name -> ConcatT [Name "__based("; name; Name ")"])

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
            (ptr, mods, ConcatT([dname; Name " "; FullName [Name ""; name]]))
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
      (pencodedNum >>= (fun n -> parray n pencodedNum) |>> Seq.toList)
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
    (pointerType |>> (fun p -> PointerStrT (p, ([],NoMod), Name "")))
    .>> anyOf "67" .>>. upper .>>. many (possibleType)
    .>> opt (pchar 'Z' |>> string <|> pstring "@Z")
    |>> (fun (((ptrStrs,fPtr), x), lst) ->
          FuncPointer
            (fPtr :: List.rev ptrStrs, CallConvention.fromChar x,
            lst.Head, "", lst.Tail))
    <?> "function Type"
  let pMemberFuncPointer =
    many (attempt pointerAtFunc) .>>.
    (pointerType .>> anyOf "89" .>>. fullName .>> pchar '@'|>>
     (fun (p,n) -> PointerStrT (p, ([], NoMod), FullName [Name ""; n])))
    .>>. normalcvModifier .>>. upper .>>. many (possibleType)
    .>> opt (pchar 'Z' |>> string <|> pstring "@Z")
    |>> (fun ((((ptrStrs,fPtr), _), x), lst) ->
          FuncPointer
            (fPtr :: List.rev ptrStrs, CallConvention.fromChar x,
            lst.Head, "", lst.Tail))
    <?> "member function pointer Type"
  let pDashBasedFuncPointer =
    many (attempt pointerAtFunc) .>>.
    (pointerType .>> pchar '_' .>> anyOf "AB" .>>.
      (dashBasedPtrVoid <|> dashBasedPtrName)
    |>> (fun (p, n) -> PointerStrT (p, ([], NoMod), n)))
    .>>. upper .>>. many possibleType
    .>> opt (pstring "Z" <|> pstring "@Z")
    |>> (fun (((ptrStrs,fPtr), x), lst) ->
      FuncPointer
        (fPtr :: List.rev ptrStrs, CallConvention.fromChar x,
        lst.Head, "", lst.Tail))
  let allFuncPointers =
    attempt pFuncPointer
    <|> attempt pMemberFuncPointer
    <|> attempt pDashBasedFuncPointer
  /// Handles the substitutions for arguments.
  let typeBackRef =
    digit |>> string |>> int .>>. getUserState
    |>> (fun (x, us) ->
          if x >= us.TypeList.Length then Name "?????"
          else (List.rev us.TypeList).[x])

  (*---Parse the function information (call types,args, modifiers, scope).---*)
  let requireMod = anyOf "ABEFIJMNQRUV"
  let emptyReturn = pchar '@' >>% EmptyReturn |>> SimpleBuiltInType
  let returnTmodifier = pchar '?' >>. normalcvModifier

  /// Parses a type and adds it to the typeList if it is not a simple type.
  let smartParseType =
    attempt normalBuiltInType
    <|> typeBackRef
    <|> (possibleType >>= addToTypeList)

  let pReqMod =
    requireMod .>>. normalcvModifier .>>. upper .>>. (opt returnTmodifier)
    .>>. (possibleType <|> emptyReturn) .>>. many smartParseType
    |>> (fun (((((s, modifier), c), rtMod),r), tList) ->
           CallScope.fromChar s, modifier,
           CallConvention.fromChar c, r :: tList, rtMod)
  let pNoMod =
    upper .>>. upper .>>. (opt returnTmodifier)
    .>>. (possibleType <|> emptyReturn) .>>. many smartParseType
    |>> (fun ((((s, c),rtMod),r),tList) ->
           CallScope.fromChar s, ([],NoMod),
           CallConvention.fromChar c, r :: tList, rtMod)

  /// Differentiates the scopes requiring modifiers for function from the
  /// ones that don't. The function information parser parses all the
  /// information about the function except the name.
  let fInfo =
     opt (pstring "$$F") >>. opt (pchar '_') >>. (attempt pReqMod <|> pNoMod)

  (*---------------Unique Template Argument types---------------------*)
  let ignored = pchar '$' >>. (pchar 'Z' <|> pchar 'V') >>% IgnoredType
  let anonymousParam =
    pchar '?' >>. pencodedNum |>> (sprintf "'template-parameter-%d'") |>> Name
  let numTempParam = pchar '0' >>. pencodedNum |>> string |>> Name
  let ptrToMangledSymbol = pstring "1?" >>. pFunc |>> MangledSymbolPtr
  let expNumberParam =
    pchar '2' >>. pencodedNum .>>. pencodedNum
    |>> (fun (baseN, expN) ->
          let baseStr = (string baseN).ToCharArray ()
          sprintf "%c.%se%d" (Seq.head baseStr)
            (String.Concat (Seq.tail baseStr)) expN |> Name )
  let twoTuple =
    pipe2 (pchar 'F' >>. pencodedNum) pencodedNum (sprintf "{%d,%d}") |>> Name
  let threeTuple =
    pipe3 (pchar 'G' >>. pencodedNum) pencodedNum pencodedNum
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
    pnameAndAt <|> attempt pTemplate >>= addToNameList <|> nameFragment

  let smartParseExceptTemplate =
    pnameAndAt >>= addToNameList
    <|> attempt constructedTemplate
    <|> attempt pSpecialName
    <|> nameFragment

  let functionFullName =
    smartParseExceptTemplate .>>. many smartParseName
    |>> (fun (x, y) -> x :: y |> FullName)

  (* -------------Tying the knot for the references created-----------------*)
  do
    fullNameRef :=
      many1 smartParseName |>> FullName

    possibleTypeRef :=
      attempt allFuncPointers <|> attempt arrayPtr <|> attempt complexType
      <|> enumType <|> attempt arrayType <|> normalBuiltInType
      <|> extendedBuiltInType
      <|> basicPointerTypes <|> typeBackRef

    pFuncRef :=
      functionFullName .>> pchar '@' .>>. fInfo
      .>> opt (pchar 'Z' |>> string <|> pstring "@Z")
      |>> (fun (name, (scope, modifier, callT, tList, rtMod)) ->
            (scope, modifier, callT, name, tList.Head, tList.Tail, rtMod)
            |> FunctionT)

    pTemplateRef :=
      saveScopeAndReturn (
        clearUserState >>.pstring "?$"
        >>. (pnameAndAt >>= addToNameList <|> pSpecialName )
        .>>. many (attempt specialTemplateParams <|> possibleType)
        .>> pchar '@'
        |>> Template
      )

  (*---------------All Expressions from a mangled string------------------*)
  let allExpressions =
    attempt pFunc <|> attempt nonFunctionString
    <|> attempt pTemplate <|> fullName

  /// Runs parser from a string.
  member __.Run str =
    runParserOnString allExpressions MSUserState.Default "" str
