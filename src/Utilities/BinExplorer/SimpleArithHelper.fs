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

module B2R2.Utilities.BinExplorer.SimpleArithHelper

open System
open System.Numerics
open SimpleArithReference

let getWhole (str : string) =
  let a = str.IndexOf('.')
  if a = (-1) then str else str.[.. a - 1]

let rec checkFraction (str : String) index =
  if index >= str.Length then
    true
  elif str.[index] = '0' then
    checkFraction (str) (index + 1)
  else
    false

/// Checking floating point integer whether it has fraction part or not for
/// bitwise operations.
let checkFloat (str : String) =
  let a = str.IndexOf('.')
  if a = -1 then
    (str, true)
  else
    let new_str = str.[(a + 1) ..]
    if checkFraction new_str 0 then
      (str.[.. a - 1], true)
    else
      ("", false)

/// Reversing given string.
let rec rev_str (str : string) index res =
  if index = str.Length then res
  else rev_str (str) (index + 1) (res + string str.[str.Length - 1 - index])

/// Turning given hexadecimal string to binary string.
let rec turnHextoBinary (str : string) index res =
  if index = str.Length then res
  else turnHextoBinary str (index + 1) (res + hexToBinaryString str.[index])

/// Turning given octal string to binary string.
let rec turnOctaltoBinary (str : string) index res =
  if index = str.Length then res
  else
    turnOctaltoBinary str (index + 1) (res + octalToBinaryString str.[index])

/// Removing leading zeros in octal representation.
let rec removeLeadingZeros (str : string) =
  if str.[str.Length - 1] = '0' then
    removeLeadingZeros str.[.. str.Length - 2]
  else str

/// Turning binary string to 128 bit BigInteger value.
let rec turnBinaryto128Bigint (str : string) index res =
  if index = str.Length then res
  else
    let sign = if (index = 127) then (-1I) else 1I
    let cur = BigInteger.Parse (string str.[index])
    let add = sign * (pown 2I (index)) * cur
    turnBinaryto128Bigint str (index + 1) (add + res)

let rec turnBinaryto128OR256UnsignedBigint (str : string) index res =
  if index = str.Length then res
  else
    let sign = 1I
    let cur = BigInteger.Parse (string str.[index])
    let add = sign * (pown 2I (index)) * cur
    turnBinaryto128Bigint str (index + 1) (add + res)

/// Turning binary string to 256 bit BigInteger value.
let rec turnBinaryto256Bigint (str : string) index res =
  if index = str.Length then res
  else
    let sign = if (index = 255) then (-1I) else 1I
    let cur = BigInteger.Parse (string str.[index])
    let add = sign * (pown 2I (index)) * cur
    turnBinaryto256Bigint str (index + 1) (add + res)

/// Turning numbers given in other format than hexadecimal to BigInteger
/// values.
let stringToBigint (str : string) =
  let final_str =
    match str.[0 .. 1] with
    | "0x" | "0X" ->
      let a = rev_str str.[2 ..] 0 ""
      let a = turnHextoBinary a 0 ""
      a
    | "0b" | "0B" ->
      let a = rev_str str.[2 ..] 0 ""
      a
    | "0o" | "0O" ->
      let a = rev_str str.[2 ..] 0 ""
      let a = turnOctaltoBinary a 0 ""
      let a = removeLeadingZeros ("0o" + a)
      let a = a.[2 ..]
      let a = if (a = "") then "0" else a
      a
    | _ -> ""
  let rep = "0b"
  if final_str.Length <= 32 then
    let num = (rep + (rev_str final_str 0 ""))
    let value = int num
    (bigint value, 3)
  elif final_str.Length <= 64 then
    let value = int64 (rep + (rev_str final_str 0 ""))
    (bigint value, 4)
  elif final_str.Length <= 128 then
    let value = turnBinaryto128Bigint final_str 0 0I
    (value, 5)
  elif final_str.Length <= 256 then
    let value = turnBinaryto256Bigint final_str 0 0I
    (value, 6)
  else
    (-1I, 0)

let calculateValue (str : string) =
  let rep = if (str.Length >= 2) then (str.[0 .. 1]) else ""
  if rep = "0x" || rep = "0X" || rep = "0o" || rep = "0O" ||
    rep = "0b" || rep = "oB" then
    stringToBigint (str)
  else
    (BigInteger.Parse str, -1)

/// Concatenating given array of strings. Returning place of error when there
/// is space between digits of number.
let rec concatenate res arg flag =
  match arg with
  | [] -> (res, flag)
  | hd :: tail ->
    if hd = "" then
      concatenate res tail flag
    elif res = "" then
      concatenate (res + hd) tail flag
    else
      let last_char = res.[res.Length - 1]
      let first_char = hd.[0]
      if System.Char.IsDigit last_char && System.Char.IsDigit first_char then
        concatenate (res + " " + hd) tail (res.Length)
      else
        concatenate (res + hd) tail flag

