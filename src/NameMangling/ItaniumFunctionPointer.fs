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

module B2R2.NameMangling.ItaniumFunctionPointer

/// Getting return from string gained from interpreter for FunctionPointer in
/// ItaniumInterpreter.fs.
let rec getReturn (input:string) index count res =
  if input.[index] = ' ' && count = 0 && input.[index + 1] = '(' then
    (res, index)
  elif input.[index] = '<' then
    getReturn input (index + 1) (count + 1) (res + string(input.[index]))
  elif input.[index] = '>' then
    getReturn input (index + 1) (count - 1) (res + string(input.[index]))
  else
    getReturn input (index + 1) (count) (res + string(input.[index]))

/// Seperating argument part of each function pointer.
let rec getArgs (input:string) index count res =
  let len = String.length input
  if index = len then
    (res, index)
  elif (input.[index] = '(' || input.[index] = ' ' ) && count = 0 then
    (res, index)
  elif input.[index] = '(' then
    getArgs input (index + 1) (count + 1) (res + string(input.[index]))
  elif input.[index] = ')' then
    getArgs input (index + 1) (count - 1) (res + string(input.[index]))
  else
    getArgs input (index + 1) (count) (res + string(input.[index]))

/// Getting qualifiers.
let getQualifier (input:string) index =
  if input.[index] = 'c' then
    ("const", index + 5)
  else
    ("volatile", index + 8)

/// Collecting seperated parts from previous function.
let rec getList input index result =
  let len = String.length input
  if index >= len then
    result
  else
    let first, new_idx = getArgs input (index + 1) 1 "("
    let second, n_idx = getArgs input (new_idx + 1) 1 "("
    if n_idx < len && (input.[n_idx + 1] = 'c' || input.[n_idx + 1] = 'v') then
      let a1, a2 = getQualifier input (n_idx + 1)
      getList input (a2 + 1) ((second + " " + a1) :: first :: result)
    else
      getList input (n_idx + 1) (second :: first :: result)

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
      let other_len = String.length res
      let result =
        res.[0 .. (cur)] + hd1 + hd2 + res.[(cur + 1) .. other_len - 1]
      combine tail (cur + len) result
  | _ -> ("", 0)

/// Seperating pointers in start of beginning of function pointer for
/// substitution.
let rec getPointers input cur res flag =
  match input with
  | FunctionPointer (FunctionBegin (Some _, Pointer d), k, b, c) ->
    match d with
    | [] -> res
    | hd :: tail ->
      let new_cur = hd :: cur
      let new_begin = FunctionBegin (Some [], Pointer new_cur)
      let new_item = FunctionPointer (new_begin, k, b, c)
      let next_begin = FunctionBegin (Some [], Pointer tail)
      let next_item = FunctionPointer (next_begin, k, b, c)
      if flag = 1 then
        let help = FunctionPointer (Name "", k, b, c)
        getPointers next_item (new_cur) (new_item :: help :: res) 0
      else
        getPointers next_item (new_cur) (new_item :: res) 0
  | _ -> res

/// Seperating pointers associated with qualifiers.
let rec getQualifierandP input cur res =
  match input with
  | FunctionPointer
    (FunctionBegin (Some (ConstVolatile (Pointer p, dis) :: tail1), d), k, b, c)
    ->
    match p with
    | [] -> res
    | hd :: tail2 ->
      let new_cur = hd :: cur
      let new_value = ConstVolatile (Pointer new_cur, dis) :: tail1
      let new_begin = FunctionBegin (Some new_value, d)
      let new_item = FunctionPointer (new_begin, k, b, c)
      let next_value = ConstVolatile (Pointer tail2, dis) :: tail1
      let next_begin = FunctionBegin (Some next_value, d)
      let next_item = FunctionPointer (next_begin, k, b, c)
      getQualifierandP (next_item) (new_cur) (new_item :: res)
  | _ -> res

/// Applying previous function for every element in the list part of
/// FunctionBegin.
let rec merge input cur res =
  match input with
  | FunctionPointer (FunctionBegin (Some value, d), k, b, c) ->
    match List.rev value with
    | [] -> res
    | ConstVolatile (Pointer p, dis) :: tail1 ->
      let new_value = ConstVolatile (Pointer [], dis) :: cur
      let new_begin = FunctionBegin (Some new_value, d)
      let new_res = FunctionPointer(new_begin, k, b, c) :: res
      let new_cur = ConstVolatile (Pointer p, dis) :: cur
      let next_begin = FunctionBegin (Some new_cur, d)
      let next_input = FunctionPointer (next_begin, k, b, c)
      let result = getQualifierandP next_input [] new_res
      let last_begin = FunctionBegin (Some (List.rev tail1), d)
      let last_item = FunctionPointer(last_begin, k, b, c)
      merge last_item new_cur (result)
    | _ -> res
  | _ -> res

let all input inputlist =
  match input with
  | FunctionPointer (Name "", _, _, _) ->
    (input :: inputlist)
  | _ ->
    let f1 = getPointers input [] inputlist 1
    let f2 = merge input [] f1
    f2
