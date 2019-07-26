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


module B2R2.NameMangling.ItaniumInterpreter

open B2R2.NameMangling.ItaniumFunctionPointer

let rec interpret (input: ItaniumExpr) =
  match input with
  | Name (x) -> x

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
    interpret arg + a

  | PointerArg (a, Some cvqualifier, arg) ->
    let a = if (a  ="") then "" else "*"
    interpret arg + interpret cvqualifier + a

  | Arguments args ->
    List.fold (
      fun acc elem ->
        let add = if (acc = "") then "" else ", "
        match elem with
        | FunctionPointer (_, _, _) | SingleArg (FunctionPointer (_, _, _)) ->
          let retandargs = interpret elem
          let ret, arglist = getReturnList retandargs
          let final, _ = combine (List.rev arglist) 0 ""
          acc + add + (ret + " " + final)
        | _ ->
          let elem = interpret elem
          if elem = "" then
            acc
          else
            acc + add + elem) "" args

  | Num x -> string(x)

  | ReferenceArg (ref, None) -> interpret ref

  | ReferenceArg (ref, Some cvqualifier) ->
    interpret cvqualifier + interpret ref

  | SingleArg a -> interpret a

  | RefArg (ref, arg) ->
    match arg with
    | FunctionPointer (a1, a2, a3)
    | SingleArg (FunctionPointer (a1, a2, a3)) ->
      let retandargs =
        interpret a2 +
        " (" + interpret a1 + interpret ref + ")" +
        "(" + interpret a3 + ")"
      let ret, arglist = getReturnList retandargs
      let final, _ = combine (List.rev arglist) 0 ""
      ret + " " + final
    | _ ->
      let arg = interpret arg
      if arg.[String.length arg - 1] = '&' then
        arg
      else
        arg + interpret ref

  | ConsOrDes a1 -> ConstructorDestructor.toChar a1

  | Literal (a, Num b) ->
    let a = interpret a
    if a = "bool" && b<>0 then
      "true"
    elif a ="bool" then
      "false"
    elif a = "int" then
      string(b)
    elif a = "unsigned int" then
      string(b)+"u"
    else
      "(" + a + ")" + string(b)


  | Literal (a, b) ->
    let a = interpret a
    let b = interpret b
    "(" + a + ")" + b

  | NestedName (a, namelist) ->
    let nestedname, _ =
      List.fold (
        fun acc elem ->
          let add = if (fst acc = "") then "" else "::"
          let idx = snd acc
          let prev = if (idx = 0) then Dummy "" else namelist.[idx - 1]
          match elem, prev with
          | ConsOrDes _, Template (Sxname (a, b), _) ->
            let elem = interpret elem
            ((fst acc + add + elem + interpret b), (idx + 1))
          | ConsOrDes _, Template (Sxsubstitution sx, _) ->
            let elem = interpret elem
            ((fst acc + add + elem + Sxabbreviation.get sx), (idx + 1))
          | ConsOrDes _, Template (a, _) ->
            let elem = interpret elem
            ((fst acc + add + elem + interpret a), (idx + 1))
          | ConsOrDes _, Sxname (_, b) ->
            let elem = interpret elem
            fst acc + add + elem + interpret (b), (idx + 1)
          | ConsOrDes _, Sxsubstitution sx ->
            let elem = interpret elem
            fst acc + add + elem + (Sxabbreviation.get sx), (idx + 1)
          | ConsOrDes _, _ ->
            let elem = interpret elem
            fst acc + add + elem + interpret (prev), (idx + 1)
          | Template (ConsOrDes a, b), Template (Sxname (_,c) , d) ->
            let elem = interpret (ConsOrDes a)
            let prev = interpret c
            fst acc + add + elem + prev + "<" + interpret b + ">0", (idx + 1)
          | Template (ConsOrDes a, b), Template (c, d) ->
            let elem = interpret (ConsOrDes a)
            let prev = interpret c
            fst acc + add + elem + prev + "<" + interpret b + ">0", (idx + 1)
          | Template (ConsOrDes a, b), _ ->
            let elem = interpret (ConsOrDes a)
            let prev = interpret prev
            fst acc + add + elem + prev + "<" + interpret b + ">0", (idx + 1)
          | _ ->
            fst acc + add + interpret elem, (idx+1)) ("", 0) namelist
    nestedname + interpret a

  | Template (name, tempargs) ->
    (interpret name) + "<" + (interpret tempargs) + ">"

  | Function (a, ret, arglist) ->
    let name, add =
      match a with
      | NestedName (value, b1) ->
        interpret (NestedName (Name "", b1)), interpret value
      | _ -> interpret a, ""
    let args = interpret arglist
    let length = String.length name
    if name.[length - 1] = '>' && args = "" then
      "not mangled properly"
    elif name.[length - 1] = '>' then
      match ret with
      | FunctionPointer (_, _ , _) |
        SingleArg (FunctionPointer (_, _, _)) ->
        let funcpointer = interpret ret
        let returned, arguments = getReturnList funcpointer
        let all, index = combine (List.rev arguments) 0 ""
        let fullname = name + "(" + (args) + ")" + add
        let len = String.length all
        let final = all.[0 .. index] + fullname + all.[(index + 1) .. len - 1]
        returned + " " + final
      | _->
      (interpret ret) + " " + name + "(" + (args) + ")" + add
    else
      let name =
        if (name.[length - 1] = '0' && name.[length - 2] = '>') then
          name.[0..(length - 2)]
        else name
      let h = if (args = "") then ("") else (", ")
      match ret with
      | FunctionPointer (_, _, _) |
        SingleArg (FunctionPointer (_, _, _))->
        let retandargs = interpret ret
        let returned, arguments = getReturnList retandargs
        let final, _ = combine (List.rev arguments) 0 ""
        name + "(" + (returned + " " + final) + h + (args) + ")" + add
      | _ ->
        name + "(" + interpret ret + h + (args) + ")" + add

  | SimpleOP (a, b) -> interpret a + "(" + interpret b + ")"

  | UnaryExpr (a, b) ->
    let operator = interpret a
    let len = String.length operator
    let operator = operator.[8 .. (len - 1)]
    if operator = "++" || operator = "--" then
      "(" + interpret b + ")" + operator
    else
      operator + "(" + interpret b + ")"

  | BinaryExpr (a, b, c) ->
    let operator = interpret a
    let len = String.length operator
    let operator = operator.[8 .. (len - 1)]
    if operator = "::" then
      interpret b + operator + interpret c
    else
      "(" + interpret b + ")" + operator + "(" + interpret c + ")"

  | Operators a -> "operator" + (OperatorIndicator.toString a)

  | BuiltinType a-> BuiltinTypeIndicator.toString a

  | Pointer v -> List.fold (fun acc _ -> acc + "*") "" v

  | FunctionBegin (Some qualifiers, pointer) ->
    let p = interpret pointer
    let a2 = List.rev qualifiers
    let qualifier = List.fold (fun acc elem -> acc + interpret elem) "" a2
    p + qualifier

  | ConstVolatile (a, b) -> interpret b + interpret a

  | FunctionPointer (pcv, ret, args) ->
    interpret ret + " (" + interpret pcv + ")" + "(" + interpret args + ")"

  | Vendor s -> s

  | SingleP _ -> "*"

  | ArrayPointer (a, b) ->
    let array = List.fold (fun acc elem -> acc + "[" + string(elem) + "]") "" a
    interpret b + " " + array

  | Functionarg (Some value, b) -> interpret b + interpret value

  | Functionarg (None, b) -> interpret b

  | Dummy _ -> "???"

  | _ -> ""
