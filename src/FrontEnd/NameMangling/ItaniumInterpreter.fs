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


module internal B2R2.FrontEnd.NameMangling.ItaniumInterpreter

open B2R2.FrontEnd.NameMangling.ItaniumFunctionPointer

let rec interpret (input: ItaniumExpr) =
  match input with
  | Name (x) -> x
  | ABITag (a, b) -> a + "[abi:" + b + "]"
  | Sxsubstitution sx -> Sxabbreviation.toString sx
  | Sxname (a, b) -> interpret a + "::" + interpret b
  | Sxoperator (a, b) -> interpret a + "::" + interpret b
  | Reference a -> ReferenceQualifier.toString a
  | CVR (cvqualifier, refqualifier) ->
    interpret cvqualifier + interpret refqualifier
  | Restrict a -> RestrictQualifier.toString a
  | CVqualifier a -> ConsTandVolatile.toString a
  | PointerArg (a, None, arg) ->
    let a = if (a = "") then "" else "*"
    match arg with
    | SingleArg (FunctionPointer (a1, k, a2, a3)) ->
      let args = interpret a3
      let args = if (args = "void") then "" else args
      let qualifier =
        match k with
        | Some value -> interpret value
        | None -> ""
      let retandargs =
        interpret a2
        + " ("
        + interpret a1
        + a
        + ")"
        + "("
        + args
        + ")"
        + qualifier
      let ret, arglist = getReturnList retandargs
      let final, _ = combine (List.rev arglist) 0 ""
      ret + " " + final
    | TemplateSub (c, _) -> interpret (PointerArg (a, None, c))
    | _ ->
      let a = if (a = "") then "" else "*"
      interpret arg + a
  | PointerArg (a, Some cvqualifier, arg) ->
    let a = if (a = "") then "" else "*"
    match arg with
    | SingleArg (FunctionPointer (a1, k, a2, a3)) ->
      let args = interpret a3
      let args = if (args = "void") then "" else args
      let qualifier =
        match k with
        | Some value -> interpret value
        | None -> ""
      let retandargs =
        interpret a2
        + " ("
        + interpret a1
        + interpret cvqualifier
        + a
        + ")"
        + "("
        + args
        + ")"
        + qualifier
      let ret, arglist = getReturnList retandargs
      let final, _ = combine (List.rev arglist) 0 ""
      ret + " " + final
    | TemplateSub (c, _) -> interpret (PointerArg (a, Some cvqualifier, c))
    | _ -> interpret arg + interpret cvqualifier + a
  | Arguments args ->
    let f =
      List.fold
        (fun acc elem ->
          let add = if (acc = "") then "" else ", "
          match elem with
          | FunctionPointer _ ->
            let retandargs = interpret elem
            let ret, arglist = getReturnList retandargs
            let final, _ = combine (List.rev arglist) 0 ""
            acc + add + (ret + " " + final)
          | _ ->
            let elem = interpret elem
            acc + add + elem)
        ""
        args
    if f = "" then f
    elif f[f.Length - 1] = ' ' then f[..(f.Length - 3)]
    else f
  | Num x -> string (x)
  | Num64 x -> string (x)
  | ReferenceArg (ref, None) -> interpret ref
  | ReferenceArg (ref, Some cvqualifier) ->
    interpret cvqualifier + interpret ref
  | SingleArg a ->
    match a with
    | FunctionPointer _ ->
      let retandargs = interpret a
      let ret, arglist = getReturnList retandargs
      let final, _ = combine (List.rev arglist) 0 ""
      ret + " " + final
    | _ -> interpret a
  | RefArg (ref, arg) ->
    match arg with
    | Functionarg (None,
                   RefArg (ReferenceArg (Reference LValueReference, _), _)) ->
      interpret arg
    | Functionarg (None,
                   RefArg (ReferenceArg (Reference RvalueReference, _), _)) ->
      interpret arg
    | SingleArg a -> interpret (RefArg (ref, a))
    | Functionarg (None, a) -> interpret (RefArg (ref, a))
    | FunctionPointer (a1, k, a2, a3) ->
      let args = interpret a3
      let args = if (args = "void") then "" else args
      let qualifier =
        match k with
        | Some value -> interpret value
        | None -> ""
      let retandargs =
        interpret a2
        + " ("
        + interpret a1
        + interpret ref
        + ")"
        + "("
        + args
        + ")"
        + qualifier
      let ret, arglist = getReturnList retandargs
      let final, _ = combine (List.rev arglist) 0 ""
      ret + " " + final
    | ArrayPointer (Some value, a, b) ->
      let flag = interpret value
      let array =
        List.fold (fun acc elem -> acc + "[" + interpret (elem) + "]") "" a
      if flag[flag.Length - 1] = '&' then
        interpret b + " (" + flag + ") " + array
      else
        interpret b + " (" + flag + interpret ref + ") " + array
    | ArrayPointer (None, a, b) ->
      let array =
        List.fold (fun acc elem -> acc + "[" + interpret (elem) + "]") "" a
      match ref with
      | ReferenceArg (c, Some d) ->
        interpret b + interpret d + " (" + interpret c + ") " + array
      | _ -> interpret b + " (" + interpret ref + ") " + array
    | TemplateSub (a, _) -> interpret (RefArg (ref, a))
    | _ ->
      let arg = interpret arg
      if arg <> "" && arg[String.length arg - 1] = '&' then arg
      else arg + interpret ref
  | ConsOrDes a1 -> ConstructorDestructor.toChar a1
  | Literal (a, Num b) ->
    let a = interpret a
    if a = "bool" && b <> 0 then "true"
    elif a = "bool" then "false"
    elif a = "int" then string (b)
    elif a = "unsigned int" then string (b) + "u"
    elif a = "unsigned long" then string (b) + "ul"
    else "(" + a + ")" + string (b)
  | Literal (a, Num64 b) ->
    let a = interpret a
    if a = "unsigned long" then string (b) + "ul"
    else "(" + a + ")" + string (b)
  | Literal (a, b) ->
    let a = interpret a
    let b = interpret b
    "(" + a + ")" + b
  | NestedName (a, namelist) ->
    let nestedname, _ =
      List.fold
        (fun acc elem ->
          let add = if (fst acc = "") then "" else "::"
          let idx = snd acc
          let prev = if (idx = 0) then Dummy "" else namelist[idx - 1]
          match elem, prev with
          | ConsOrDes _, Template (Sxname (_, b), _) ->
            let elem = interpret elem
            ((fst acc + add + elem + interpret b), (idx + 1))
          | ConsOrDes _, Template (Sxsubstitution sx, _) ->
            let elem = interpret elem
            ((fst acc + add + elem + Sxabbreviation.get sx), (idx + 1))
          | ConsOrDes _, Template (a, _) ->
            let elem = interpret elem
            ((fst acc + add + elem + interpret a), (idx + 1))
          | ConsOrDes _, Sxsubstitution sx ->
            let elem = interpret elem
            fst acc + add + elem + (Sxabbreviation.get sx), (idx + 1)
          | ConsOrDes _, UnnamedType _ ->
            let prev = namelist[idx - 2]
            let elem = interpret elem
            fst acc + add + elem + interpret (prev), (idx + 1)
          | ConsOrDes _, _ ->
            let elem = interpret elem
            fst acc + add + elem + interpret (prev), (idx + 1)
          | Template (ConsOrDes a, b), Template (Sxname (_, c), _) ->
            let elem = interpret (ConsOrDes a)
            let prev = interpret c
            let help = interpret b
            let help = if (help[help.Length - 1] = '>') then (" >") else ">"
            fst acc + add + elem + prev + "<" + interpret b + help, (idx + 1)
          | Template (ConsOrDes a, b), Template (Sxsubstitution sx, _) ->
            let elem = interpret (ConsOrDes a)
            let help = interpret b
            let help = if (help[help.Length - 1] = '>') then (" >") else ">"
            fst acc
            + add
            + elem
            + Sxabbreviation.get sx
            + "<"
            + interpret b
            + help,
            (idx + 1)
          | Template (ConsOrDes a, b), Template (c, _) ->
            let elem = interpret (ConsOrDes a)
            let prev = interpret c
            let help = interpret b
            let help = if (help[help.Length - 1] = '>') then (" >") else ">"
            fst acc + add + elem + prev + "<" + interpret b + help, (idx + 1)
          | Template (ConsOrDes a, b), _ ->
            let elem = interpret (ConsOrDes a)
            let prev = interpret prev
            let help = interpret b
            let help = if (help[help.Length - 1] = '>') then (" >") else ">"
            fst acc + add + elem + prev + "<" + interpret b + help, (idx + 1)
          | _ ->
            let elem = interpret elem
            if elem.Length >= 10 && elem[0..9] = "_GLOBAL__N" then
              fst acc + add + "(anonymous namespace)", (idx + 1)
            else
              fst acc + add + elem, (idx + 1))
        ("", 0)
        namelist
    match a with
    | CVR (c, Reference b) ->
      nestedname + interpret (c) + " " + interpret (Reference b)
    | _ -> nestedname + interpret a
  | Template (name, tempargs) ->
    let help = interpret tempargs
    let name = interpret name
    let helper = if (name[name.Length - 1] = '<') then (" <") else ("<")
    if help = "" then
      name + helper + help + ">"
    else
      let help = if (help[help.Length - 1] = '>') then (" >") else ">"
      name + helper + (interpret tempargs) + help
  | Clone (exprlist) ->
    let a =
      List.fold
        (fun acc elem ->
          match elem with
          | Name x -> acc + "]" + " " + "[" + "clone ." + x
          | Num x ->
            if acc = "" then
              acc + " [clone ." + string (x)
            else
              acc + "." + string (x)
          | _ -> acc)
        ""
        exprlist
    if a = "" then ""
    elif a[0] = ']' then a[1..(String.length a - 1)] + "]"
    else a + "]"
  | Function (scope, a, Name "", Name "", clone) ->
    let scope = List.fold (fun acc elem -> acc + interpret elem + "::") "" scope
    let clone = interpret clone
    if clone = "" then scope + interpret a
    else "not mangled properly"
  | Function (scope, a, ret, arglist, clone) ->
    let scope1 =
      List.fold (fun acc elem -> acc + interpret elem + "::") "" scope
    let name, add =
      match a with
      | NestedName (value, b1) ->
        let value =
          match value with
          | CVR (c, Reference b) ->
            interpret (c) + " " + interpret (Reference b)
          | _ -> interpret value
        interpret (NestedName (Name "", b1)), value
      | _ -> interpret a, ""
    let args = interpret arglist
    if ret <> Name "" && arglist = Name "" then
      "not mangled properly"
    elif ret <> Name "" then
      let args = if (args = "void") then "" else args
      match ret with
      | FunctionPointer _
      | SingleArg (FunctionPointer _)
      | Functionarg (_, SingleArg (FunctionPointer _)) ->
        let funcpointer = interpret ret
        let returned, arguments = getReturnList funcpointer
        let all, index = combine (List.rev arguments) 0 ""
        let fullname = name + "(" + (args) + ")" + add
        let len = String.length all
        let final = all[0..index] + fullname + all[(index + 1)..(len - 1)]
        returned + " " + scope1 + final + interpret clone
      | TemplateSub (a, _) -> interpret (Function (scope, a, a, arglist, clone))
      | _ ->
        (interpret ret)
        + " "
        + scope1
        + name
        + "("
        + (args)
        + ")"
        + add
        + interpret clone
    else
      let args = if (args = "void") then "" else args
      scope1 + name + "(" + args + ")" + add + interpret clone
  | UnaryExpr (a, b) ->
    let operator = interpret a
    let len = String.length operator
    let operator = operator[8..(len - 1)]
    if operator = "++" || operator = "--" then
      "(" + interpret b + ")" + operator
    elif operator = "&" then
      let b = interpret b
      if b[b.Length - 1] = '>' || b[b.Length - 1] = ')' then
        operator + "(" + b + ")"
      else
        operator + b
    elif operator = "*" then operator + interpret b
    else operator + "(" + interpret b + ")"
  | BinaryExpr (a, b, c) ->
    let operator = interpret a
    let len = String.length operator
    let operator = operator[8..(len - 1)]
    if operator = "::" then interpret b + operator + interpret c
    else "(" + interpret b + ")" + operator + "(" + interpret c + ")"
  | Operators a -> "operator" + OperatorIndicator.toString a
  | CastOperator (a, b) ->
    if a = "cv" || a = "v" then "operator " + interpret b
    else "operator\"\" " + interpret b
  | BuiltinType a -> BuiltinTypeIndicator.toString a
  | Pointer v -> List.fold (fun acc elem -> acc + interpret elem) "" v
  | FunctionBegin (Some qualifiers, pointer) ->
    let p = interpret pointer
    let a2 = List.rev qualifiers
    let qualifier = List.fold (fun acc elem -> acc + interpret elem) "" a2
    p + qualifier
  | ConstVolatile (a, b) -> interpret b + interpret a
  | FunctionPointer (pcv, Some value, ret, args) ->
    let args = interpret args
    let args = if (args = "void") then "" else args
    interpret ret
    + " ("
    + interpret pcv
    + ")"
    + "("
    + args
    + ")"
    + interpret value
  | FunctionPointer (pcv, None, ret, args) ->
    let args = interpret args
    let args = if (args = "void") then "" else args
    interpret ret + " (" + interpret pcv + ")" + "(" + args + ")"
  | Vendor s -> s
  | SingleP _ -> "*"
  | ArrayPointer (None, a, b) ->
    let array =
      List.fold (fun acc elem -> acc + "[" + interpret (elem) + "]") "" a
    interpret b + " " + array
  | ArrayPointer (Some value, a, b) ->
    let array =
      List.fold (fun acc elem -> acc + "[" + interpret (elem) + "]") "" a
    interpret b + " (" + interpret value + ") " + array
  | Functionarg (Some value, b) -> interpret b + interpret value
  | Functionarg (None, a) ->
    match a with
    | FunctionPointer _ ->
      let retandargs = interpret a
      let ret, arglist = getReturnList retandargs
      let final, _ = combine (List.rev arglist) 0 ""
      ret + " " + final
    | _ -> interpret a
  | RTTIandVirtualTable (a, b) -> RTTIVirtualTable.toString a + interpret b
  | CallOffset (a) -> CallOffSet.toString a
  | VirtualThunk (a, b) -> interpret a + interpret b
  | VirtualThunkRet a -> "covariant return thunk to " + interpret a
  | ConstructionVtable (a, b) ->
    "construction vtable for " + interpret b + "-in-" + interpret a
  | GuardVariable (a, b) ->
    let scope = List.fold (fun acc elem -> acc + interpret elem + "::") "" a
    "guard variable for " + scope + interpret b
  | TransactionSafeFunction a -> "transaction clone for " + interpret a
  | ReferenceTemporary (a, b) ->
    "reference temporary #" + interpret b + " for " + interpret a
  | ScopeEncoding (a, b) -> interpret a + "::" + interpret b
  | MemberPointer (a) -> interpret a + "::*"
  | MemberPAsArgument (a, b) -> interpret b + " " + interpret a
  | Scope a ->
    match a with
    | Function (a1, a2, _, a4, a5) ->
      let b = Function (a1, a2, Name "", a4, a5)
      interpret b
    | _ -> interpret a
  | Vector (a, b) -> interpret b + " __vector(" + interpret a + ")"
  | LambdaExpression (a, b) ->
    let num = interpret b
    let num = if (num = "") then "1" else (string (int (num) + 2))
    let a = interpret a
    let a = if (a = "void") then ("") else a
    "{lambda(" + a + ")#" + num + "}"
  | UnnamedType (a) ->
    let num = interpret a
    let num = if (num = "") then "1" else (string (int (num) + 2))
    "{unnamed type#" + num + "}"
  | ParameterRef a ->
    let num = interpret a
    let num = if (num = "") then "1" else (string (int (num) + 2))
    "{parm#" + num + "}"
  | ScopedLambda (a, Some value, b) ->
    let num = interpret value
    let num = if (num = "") then "1" else (string (int (num) + 2))
    interpret a + "::" + "{default arg#" + num + "}::" + interpret b
  | ScopedLambda (a, None, b) -> interpret a + "::" + interpret b
  | ExternalName a ->
    match a with
    | Function (a1, a2, _, _, _) ->
      let a2t = interpret a2
      if a2t.IndexOf ("::") = -1 then interpret a
      else interpret (Function (a1, a2, Name "", Name "", Name ""))
    | _ -> interpret a
  | CallExpr a ->
    let first = a[0]
    let rest = a[1..]
    let rest =
      List.fold
        (fun acc elem ->
          let add = if (acc = "") then "" else ", "
          acc + add + interpret elem)
        ""
        rest
    let a = interpret first
    if a.IndexOf ('<') <> -1 || a.IndexOf ('.') <> -1 then
      "(" + a + ")" + "(" + rest + ")"
    else
      a + "(" + rest + ")"
  | ConversionOne (a, b) -> "(" + interpret a + ")" + interpret b
  | ConversionMore (a, b) ->
    let rest =
      List.fold
        (fun acc elem ->
          let add = if (acc = "") then "" else ", "
          acc + add + interpret elem)
        ""
        b
    "(" + interpret a + ")" + "(" + rest + ")"
  | DeclType a -> "decltype " + "(" + interpret a + ")"
  | DotExpr (a, b) ->
    let first = interpret a
    if first.IndexOf ('.') <> -1
      || first.IndexOf ('(') <> -1
      || first.IndexOf ('<') <> -1
    then
      "(" + interpret a + ")" + "." + interpret b
    else
      interpret a + "." + interpret b
  | DotPointerExpr (a, b) ->
    let first = interpret a
    if first.IndexOf ('.') <> -1
      || first.IndexOf ('(') <> -1
      || first.IndexOf ('<') <> -1
      || first.IndexOf ('{') <> -1
    then
      "(" + interpret a + ")" + ".*" + interpret b
    else
      interpret a + ".*" + interpret b
  | CastingExpr (a, b, c) ->
    CasTing.toString a + "<" + interpret b + ">(" + interpret c + ")"
  | TypeMeasure (a, b) -> MeasureType.toString a + "(" + interpret b + ")"
  | ExprMeasure (a, b) -> MeasureExpr.toString a + "(" + interpret b + ")"
  | TemplateSub (a, _) -> interpret (SingleArg (a))
  | ExpressionArgPack a -> interpret a
  | Dummy _ -> "???"
  | _ -> ""
