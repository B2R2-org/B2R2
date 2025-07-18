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

module B2R2.RearEnd.BinExplorer.SimpleArithHelper

open System
open System.Numerics
open SimpleArithReference

/// Getting integer part of float string.
let getIntegerPart (str: string) =
  if str.IndexOf 'E' <> -1 || str.IndexOf 'e' <> -1 then
    "0"
  else
    str.Split [| '.' |] |> Seq.head

/// Checking if fraction part is consisted of only zeros or not.
let hasZeroFraction (floatString: string) =
  if floatString.IndexOf 'E' <> -1 || floatString.IndexOf 'e' <> -1 then
    false
  elif floatString.IndexOf '.' = -1 then
    true
  else
    let fractionPart = floatString.Split [| '.' |] |> (Seq.item 1)
    Seq.fold (fun state char -> state && char = '0') true fractionPart

/// Reversing given string.
let reverseString (input: string) =
  Seq.rev input |> Seq.toArray |> String

/// Turning given hexadecimal string to binary string.
let turnHexToBinary (hexadecimalString: string) =
  let rec doConversion (str: string) index res =
    if index = str.Length then res
    else doConversion str (index + 1) (res + hexToBinaryString str[index])
  doConversion hexadecimalString 0 ""

/// Turning given octal string to binary string.
let turnOctalToBinary (octalString: string) =
  let rec doConversion (str: string) index res =
    if index = str.Length then res
    else
      doConversion str (index + 1) (res + octalToBinaryString str[index])
  doConversion octalString 0 ""

/// Turning binary string to 128 bit BigInteger value.
let convertBinaryTo128BitBigint (binaryString: string) =
  let rec doConversion (str: string) index res =
    if index = str.Length then res
    else
      let sign = if (index = 127) then (-1I) else 1I
      let cur = string str[index] |> BigInteger.Parse
      let add = sign * (pown 2I index) * cur
      doConversion str (index + 1) (add + res)
  doConversion binaryString 0 0I

/// Turning binary string to 256 bit BigInteger value.
let convertBinaryTo256BitBigint (binaryString: string) =
  let rec doConversion (str: string) index res =
    if index = str.Length then res
    else
      let sign = if (index = 255) then (-1I) else 1I
      let cur = string str[index] |> BigInteger.Parse
      let add = sign * (pown 2I index) * cur
      doConversion str (index + 1) (add + res)
  doConversion binaryString 0 0I

let removeLeadingZerosInOctalNumber (input: string) =
  match input.Length with
  | n when (n = 33 || n = 129) ->
    if input[0] = '0' then input[1..]
    else input
  | n when (n = 66 || n = 258) ->
    if input[0] = '0' && input[1] = '0' then input[2..]
    else input
  | _ -> input

let getBinaryRepresentation (input: string) =
  match input[0..1] with
  | "0x" | "0X" -> "0b" + turnHexToBinary input[2..]
  | "0b" | "0B" -> "0b" + input[2..]
  | "0o" | "0O" ->
    let binaryPart =
      turnOctalToBinary input[2..] |> removeLeadingZerosInOctalNumber
    "0b" + binaryPart
  | _ -> failwith "0"

let stringToBigint (str: string) =
  let binaryString = getBinaryRepresentation str
  match binaryString[2..].Length with
  | len when len <= 32 ->
    let num = binaryString
    let value = int num
    (bigint value, 32)
  | len when len <= 64 ->
    let value = int64 binaryString
    (bigint value, 64)
  | len when len <= 128 ->
    let binaryString = reverseString binaryString[2..]
    let value = convertBinaryTo128BitBigint binaryString
    (value, 128)
  | len when len <= 256 ->
    let binaryString = reverseString binaryString[2..]
    let value = convertBinaryTo256BitBigint binaryString
    (value, 256)
  | _ -> (-1I, 0)

let stringLiteralToBigint (str: string) =
  let rep = if (str.Length >= 2) then (str[0..1]) else ""
  if rep = "0x" || rep = "0X" || rep = "0o" || rep = "0O" ||
    rep = "0b" || rep = "oB" then
    stringToBigint str
  else
    (BigInteger.Parse str, -1)

let processBytes (numbers: string list) =
  let rec doProcessing (input: string list) res =
    match input with
    | [] -> [| res |]
    | hd :: tail ->
      let integerValue = int hd
      if integerValue < 33 || integerValue > 255 then
        doProcessing tail (res + ".")
      else
        doProcessing tail (res + String [| char integerValue |])
  doProcessing numbers ""
