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

module B2R2.RearEnd.BinExplorer.SimpleArithConverter

open System
open System.Numerics
open SimpleArithReference

/// Positive decimal to binary.
let positiveDecToBinary (decimalNumber: bigint) =
  let rec doConversion input (res: string) =
    if input = 0I then
      if res = "" then "0b0"
      else "0b" + res
    else
      let currentBit = input % 2I
      doConversion (input / 2I) (string currentBit + res)
  doConversion decimalNumber ""

/// Getting two's complement.
let complement (binaryString: string) =
  let charListInput = Seq.toList binaryString |> List.rev
  let res =
    List.fold
      (fun acc elem ->
        if (elem = '1') then '0' :: acc else '1' :: acc) [] charListInput
  List.toArray res |> String

/// Adding 1 after reversing all bit values.
let addOneToBinary (binaryString: string) =
  let charListInput = Seq.toList binaryString |> List.rev
  let res =
    List.fold
      (fun acc elem ->
        let flag = snd acc
        if flag = '1' && elem = '1' then
          ('0' :: fst acc, '1')
        elif flag = '1' || elem = '1' then
          ('1' :: fst acc, '0')
        else
          ('0' :: fst acc, '0')) ([], '1') charListInput
  fst res |> List.toArray |> String

/// Completing number of bits to 32, 64, 128 or 256.
let addZeros (binaryString: string) number =
  if number < 0 then binaryString
  else
    let a = String.replicate number "0"
    "0b" + a + binaryString[2..]

/// Completing number of bits to 32, 64, 128 or 256.
let fillWithZeros (binaryString: string) (size: NumType) =
  let numberOfBits = NumType.getBitLength size
  match numberOfBits with
  | n when n <= 32 -> addZeros binaryString (32 - binaryString.Length + 2)
  | n when n > 0 -> addZeros binaryString (n - binaryString.Length + 2)
  | _ -> "Wrong Input"

/// Negative decimal to binary.
let negativeDectoBinary decimalNumber size =
  let absolute = abs decimalNumber
  let binary = positiveDecToBinary absolute
  let binary = fillWithZeros binary size
  let com = complement binary[2..]
  let negValue = addOneToBinary com
  "0b" + negValue

let decToBinary decimalNumber size =
  if decimalNumber >= 0I then
    let res = positiveDecToBinary decimalNumber
    fillWithZeros res size
  else
    negativeDectoBinary decimalNumber size

let adjustBinaryStringToHex (binaryString: string) =
  if binaryString.Length % 4 <> 0 then
    let add = String.replicate (4 - (binaryString.Length % 4)) "0"
    add + binaryString
  else
    binaryString

let adjustBinaryStringToOctal (binaryString: string) =
  if binaryString.Length % 3 <> 0 then
    let add = String.replicate (3 - (binaryString.Length % 3)) "0"
    add + binaryString
  else
    binaryString

let rec toHex (input: string) index res =
  if index >= input.Length then
      res
    else
      let add =
        if (index + 4 = input.Length) then (input[index..])
        else input[index..(index + 3)]
      toHex input (index + 4) (res + binaryToHexString add)

let rec toOctal (input: string) index res =
  if index >= input.Length then
      res
    else
      let add =
        if (index + 3 = input.Length) then (input[index..])
        else input[index..(index + 2)]
      toOctal input (index + 3) (res + binaryToOctalString add)

/// Converting binary string to hex string.
let binaryToHex (binaryString: string) =
  let adjustedBinary = adjustBinaryStringToHex binaryString
  let hexString = toHex adjustedBinary 0 ""
  "0x" + hexString

/// Converting binary string to octal string.
let binaryToOctal (binaryString: string) =
  let adjustedBinary = adjustBinaryStringToOctal binaryString
  let octalString = toOctal adjustedBinary 0 ""
  "0o" + octalString

let getOutputValueString input outputFormat size =
  let inputInBinary = decToBinary input size
  match outputFormat with
  | HexadecimalF ->
    let str = inputInBinary[2..]
    binaryToHex str
  | DecimalF -> string input
  | BinaryF -> inputInBinary
  | OctalF ->
    let str = inputInBinary[2..]
    binaryToOctal str
  | _ -> "Flag Error"

