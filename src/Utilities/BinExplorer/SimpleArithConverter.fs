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

module B2R2.Utilities.BinExplorer.SimpleArithConverter

open System
open System.Numerics
open SimpleArithReference

/// Positive decimal to binary.
let rec positiveDecToBinary a res =
  if a = 0I then
    if res = "" then "0b0"
    else "0b" + res
  else
    positiveDecToBinary (a/2I) (string(a%2I)+res)

/// Getting two's complement.
let complement input =
  List.fold
    (fun acc elem -> if (elem = '1') then '0' :: acc else '1' :: acc) [] input

/// Adding 1 after reversing all bit values.
let addOnetoBinary input =
  let a =
    List.fold
      (fun acc elem ->
        let flag = snd acc
        if flag = '1' && elem = '1' then
          ('0' :: fst acc, '1')
        elif flag = '1' || elem = '1' then
          ('1' :: fst acc, '0')
        else
          ('0' :: fst acc, '0')) ([], '1') input
  fst a

/// Completing number of bits to 32, 64, 128 or 256.
let addZeros (input : String) number =
  let a = String.replicate number "0"
  "0b" + a + input.[2 ..]

let complete_2 input size =
  if size <= 3 then
    addZeros input (32 - input.Length + 2)
  elif size = 4 then
    addZeros input (64 - input.Length + 2)
  elif size = 5 then
    addZeros input (128 - input.Length + 2)
  else
    addZeros input (256 - input.Length + 2)

let negativeDectoBinary input size =
  let absolute = abs input
  let binary = positiveDecToBinary absolute ""
  let binary = complete_2 binary size
  let com = complement (List.rev (Seq.toList binary.[2 ..]))
  let neg_value = String (List.toArray (addOnetoBinary (List.rev com)))
  "0b" + neg_value

let allDectoBinary input size =
  if input > 0I then
    let res = positiveDecToBinary input ""
    complete_2 res size
  else
    negativeDectoBinary input size

/// Converting binary string to hex string.
let rec binaryToHex (input: String) index res =
  if index >= input.Length then
    res
  else
    let add =
      if (index + 4 = input.Length) then (input.[index ..])
      else input.[index .. index + 3]
    binaryToHex input (index + 4) (res + (binaryToOctalOrHex add))

/// Converting binary string to octal string.
let rec binaryToOctal (input: String) index res =
  if index >= input.Length then
    res
  else
    let add =
      if (index + 3 = input.Length) then (input.[index ..])
      else input.[index .. index + 2]
    binaryToOctal input (index + 3) (res + (binaryToOctalOrHex add))

let final_converter input flag size =
  let res = allDectoBinary input size
  if flag = 0 then
    let str = res.[2 ..]
    if str.Length % 4 <> 0 then
      let add = String.replicate (4 - (str.Length % 4)) "0"
      "0x" + (binaryToHex (add + str) 0 "")
    else
      "0x" + (binaryToHex (str) 0 "")
  elif flag = 1 then
    string input
  elif flag = 2 then
    res
  elif flag = 3 then
    let str = res.[2 ..]
    if str.Length % 3 <> 0 then
      let add = String.replicate (3 - (str.Length % 3)) "0"
      "0x" + (binaryToOctal (add + str) 0 "")
    else
      "0x" + (binaryToOctal (str) 0 "")
  else
    "Flag Error"

