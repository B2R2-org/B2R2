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

module internal B2R2.FrontEnd.NameMangling.ItaniumFunctionPointer

/// Getting return from string gained from interpreter for FunctionPointer in
/// ItaniumInterpreter.fs.
let rec getReturn (input: string) index count res =
  if input[index] = ' ' && count = 0 && input[index + 1] = '(' then
    (res, index)
  elif input[index] = '<' then
    getReturn input (index + 1) (count + 1) (res + string input[index])
  elif input[index] = '>' then
    getReturn input (index + 1) (count - 1) (res + string input[index])
  else
    getReturn input (index + 1) (count) (res + string input[index])

/// Seperating argument part of each function pointer.
let rec getArgs (input: string) index count res =
  let len = String.length input
  if index = len then
    (res, index)
  elif (input[index] = '(' || input[index] = ' ') && count = 0 then
    (res, index)
  elif input[index] = '(' then
    getArgs input (index + 1) (count + 1) (res + string input[index])
  elif input[index] = ')' then
    getArgs input (index + 1) (count - 1) (res + string input[index])
  else
    getArgs input (index + 1) (count) (res + string input[index])

/// Getting qualifiers.
let getQualifier (input: string) index =
  if input[index] = 'c' then
    ("const", index + 5)
  else
    ("volatile", index + 8)

/// Collecting seperated parts from previous function.
let rec getList input index result =
  let len = String.length input
  if index >= len then
    result
  else
    let first, nIdx = getArgs input (index + 1) 1 "("
    let second, nIdx = getArgs input (nIdx + 1) 1 "("
    if nIdx < len && (input[nIdx + 1] = 'c' || input[nIdx + 1] = 'v') then
      let a1, a2 = getQualifier input (nIdx + 1)
      getList input (a2 + 1) ((second + " " + a1) :: first :: result)
    else
      getList input (nIdx + 1) (second :: first :: result)

/// Getting return and argument list.
let getReturnList input =
  let first, index = getReturn input 0 0 ""
  let result = getList input (index + 1) []
  (first, result)

/// Combining arguments list.
let rec combine input cur res =
  match input with
  | [] -> (res, cur)
  | hd1 :: hd2 :: tail ->
    let hd1 = if (hd1 = "()") then "" else hd1
    if res = "" then
      let len = (String.length hd1) - 2
      combine tail len (res + hd1 + hd2)
    else
      let len = (String.length hd1) - 1
      let otherLen = String.length res
      let result = res[0..cur] + hd1 + hd2 + res[(cur + 1)..(otherLen - 1)]
      combine tail (cur + len) result
  | _ -> ("", 0)

/// Seperating pointers in start of beginning of function pointer for
/// substitution.
let rec getPointers input cur res flag =
  match input with
  | FunctionPointer(FunctionBegin(Some _, Pointer d), k, b, c) ->
    match d with
    | [] -> res
    | hd :: tail ->
      let newCur = hd :: cur
      let newBegin = FunctionBegin(Some [], Pointer newCur)
      let newItem = FunctionPointer(newBegin, k, b, c)
      let nextBegin = FunctionBegin(Some [], Pointer tail)
      let nextItem = FunctionPointer(nextBegin, k, b, c)
      if flag = 1 then
        let help = FunctionPointer(Name "", k, b, c)
        getPointers nextItem (newCur) (newItem :: help :: res) 0
      else
        getPointers nextItem (newCur) (newItem :: res) 0
  | _ -> res

/// Seperating pointers associated with qualifiers.
let rec getQualifierandP input cur res =
  match input with
  | FunctionPointer(FunctionBegin(Some(ConstVolatile(Pointer p, dis) :: tail1),
    d), k, b, c) ->
    match p with
    | [] -> res
    | hd :: tail2 ->
      let newCur = hd :: cur
      let newValue = ConstVolatile(Pointer newCur, dis) :: tail1
      let newBegin = FunctionBegin(Some newValue, d)
      let newItem = FunctionPointer(newBegin, k, b, c)
      let nextValue = ConstVolatile(Pointer tail2, dis) :: tail1
      let nextBegin = FunctionBegin(Some nextValue, d)
      let nextItem = FunctionPointer(nextBegin, k, b, c)
      getQualifierandP (nextItem) (newCur) (newItem :: res)
  | _ -> res

/// Applying previous function for every element in the list part of
/// FunctionBegin.
let rec merge input cur res =
  match input with
  | FunctionPointer(FunctionBegin(Some value, d), k, b, c) ->
    match List.rev value with
    | [] -> res
    | ConstVolatile(Pointer p, dis) :: tail1 ->
      let newValue = ConstVolatile(Pointer [], dis) :: cur
      let newBegin = FunctionBegin(Some newValue, d)
      let newRes = FunctionPointer(newBegin, k, b, c) :: res
      let newCur = ConstVolatile(Pointer p, dis) :: cur
      let nextBegin = FunctionBegin(Some newCur, d)
      let nextInput = FunctionPointer(nextBegin, k, b, c)
      let result = getQualifierandP nextInput [] newRes
      let lastBegin = FunctionBegin(Some(List.rev tail1), d)
      let lastItem = FunctionPointer(lastBegin, k, b, c)
      merge lastItem newCur (result)
    | _ -> res
  | _ -> res

let all input inputlist =
  match input with
  | FunctionPointer(Name "", _, _, _) ->
    (input :: inputlist)
  | _ ->
    let f1 = getPointers input [] inputlist 1
    let f2 = merge input [] f1
    f2
