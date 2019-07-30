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

module B2R2.NameMangling.MSInterpreter

open B2R2.NameMangling.MSUtils

/// Main interpreter function that outputs the demangled string
let rec interpret (sample: MSExpr) =
  match sample with
  | Name str -> str

  | Constructor name -> interpret (FullName [name; name])

  | Destructor name ->
    let constName = interpret name
    sprintf "%s::~%s" constName constName

  | FullName lst ->
    List.map interpret lst
    |> List.reduce (fun x y -> y + "::" + x)

  | SimpleBuiltInType t -> NormalBuiltInType.toString t

  | ExtendedBuiltInType t -> UnderscoredBuiltInType.toString t

  | PointerT (ptrStrT, PointerT(ptrStrT2, pt2)) ->
    let pointerStr = interpret ptrStrT
    let mainType =
      interpret (PointerT(changeToNormalPointer ptrStrT2, pt2))
    (mainType + pointerStr).Trim ()

  | PointerT (ptrStrT, pointedType) ->
    let pointerStr = interpret ptrStrT
    let mainType = interpret pointedType
    (mainType + pointerStr).Trim ()

  | FunctionT
    (s, mods, call, nm, FuncPointer(fPtrs, callr, rt, _ , plst), pTs, rtMod) ->
    let carry =
      interpret (FunctionT(FreeScope,mods,call,nm,Name(""),pTs,rtMod))
    CallScope.toString s +
      (interpret (FuncPointer(fPtrs, callr, rt, " " + carry.Trim (), plst)))

  | FunctionT (scope, modInfo, callConv, name, returnT, paramTs, rtMod) ->
    let paramTstr = makeFunParams (List.map interpret paramTs)
    let modPrefixes, modifier = modInfo
    let pre, post = getPrefixModStr modPrefixes
    let modString = CVModifier.toString modifier + pre + post
    let modstrUpdated = updatePrefix modPrefixes modString
    let funcName = interpret name
    let returnTstr =
      if rtMod = None && returnT = SimpleBuiltInType (EmptyReturn) then ""
      elif rtMod = None then interpret returnT + " "
      else interpret (ModifiedType (returnT, rtMod.Value))
    sprintf "%s%s%s %s%s%s" (CallScope.toString scope) returnTstr
      (CallConvention.toString callConv) funcName paramTstr modstrUpdated

  | Template (name, tList) ->
    let name = interpret name
    let tList = List.filter (fun x -> x <> IgnoredType) tList
    let argStr = makeTemplateArgs (List.map interpret tList)
    name + argStr

  | ComplexT (nm, comp) -> ComplexTypeKind.toString nm + interpret comp

  | EnumType (c, name) ->
    let enumName = interpret name
    let enumType = EnumTypeKind.toString c
    sprintf "enum%s %s" enumType enumName

  | FuncPointer
    (fPtrs, cc, FuncPointer (fPtrs2, cc2, rt2, _ , pLst2), car, pLst) ->
    let args = makeFunParams (List.map interpret pLst)
    let ptrStrs =
      List.mapi (fun index ptr ->
                    if index = fPtrs.Length - 1 then ptr
                    else changeToNormalPointer ptr) fPtrs
      |> List.map interpret |> (List.reduce (+))
    let newCarry =
      sprintf "(%s%s%s)%s"
        (CallConvention.toString cc) (ptrStrs.Trim ()) car args
    interpret (FuncPointer (fPtrs2, cc2, rt2, newCarry, pLst2))

  | FuncPointer (fPtrs, callC, rType, carry, pLst) ->
    let args = makeFunParams (List.map interpret pLst)
    let ptrStrs =
      (List.mapi (fun index ptr ->
                    if index = fPtrs.Length - 1 then ptr
                    else changeToNormalPointer ptr) fPtrs
      |> List.map interpret |> (List.reduce (+))).Trim ()
    let ptrStrsUpdated =
      if ptrStrs.[0] = '*' then ptrStrs
      else " " + ptrStrs
    sprintf "%s (%s%s%s)%s" (interpret rType) (CallConvention.toString callC)
      ptrStrsUpdated carry args

  | ArrayPtr (pointers, indices, dataType) ->
    let ptrStr = List.map interpret (List.rev pointers) |> List.reduce (+)
    let dimensionStr = List.map (sprintf "[%d]") indices |> List.reduce (+)
    sprintf "%s (%s)%s" (interpret dataType) (ptrStr.Trim ()) dimensionStr

  | ArrayType (dataT, dimension) ->
    let dimensionStr = String.replicate dimension "[]"
    let dataTString = interpret dataT
    dataTString.Trim () + dimensionStr

  | RTTI0 t -> interpret t + " 'RTTI Type Descriptor'"

  | NestedFunc f -> sprintf "`%s'" ((interpret f).Trim ())

  | MangledSymbolPtr c -> "&" + interpret c

  | ModifiedType (typeN, modInfo) ->
    let prefixes, modifier = modInfo
    let preStr, postStr = getPrefixModStr prefixes
    let postModifiedStr =
      if postStr.Length > 0 then postStr.[1..] + " " else ""
    interpret typeN + CVModifier.toString modifier + preStr + postModifiedStr

  | PointerStrT (p, (prefix, cvMod), pComp) ->
    let preP, postP = getPrefixModStr prefix
    let cvModStr = CVModifier.toString cvMod
    let cvTypeComponent = interpret pComp
    let pTypeStr = PointerTypeIndicator.getPointerType p
    let pSymbol = PointerTypeIndicator.getPointerSymbol p
    cvModStr + cvTypeComponent + preP + pSymbol + postP + pTypeStr

  | ValueT (name, typeInfo) -> interpret typeInfo + interpret name

  | ConstructedTemplate (types, name) ->
    interpret (Template (FullName [name; name], types))

  | ConcatT (compList) ->
    List.map interpret compList |>
    List.reduce (+)

  | IgnoredType -> ""
