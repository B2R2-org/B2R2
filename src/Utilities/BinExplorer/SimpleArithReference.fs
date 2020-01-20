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

module B2R2.Utilities.BinExplorer.SimpleArithReference

let (|Between|_|) (lo, hi) x =
  if lo <= x && x <= hi then Some () else None

/// Representing single hexadecimal digit in binary with 4 digits.
let hexToBinaryString = function
  | '0' -> "0000"
  | '1' -> "0001"
  | '2' -> "0010"
  | '3' -> "0011"
  | '4' -> "0100"
  | '5' -> "0101"
  | '6' -> "0110"
  | '7' -> "0111"
  | '8' -> "1000"
  | '9' -> "1001"
  | 'A' | 'a' -> "1010"
  | 'B' | 'b' -> "1011"
  | 'C' | 'c' -> "1100"
  | 'D' | 'd' -> "1101"
  | 'E' | 'e' -> "1110"
  | 'F' | 'f' -> "1111"
  | _ -> ""

/// Representing single octal digit in binary with 3 digits.
let octalToBinaryString = function
  | '0' -> "000"
  | '1' -> "001"
  | '2' -> "010"
  | '3' -> "011"
  | '4' -> "100"
  | '5' -> "101"
  | '6' -> "110"
  | '7' -> "111"
  | _ -> ""

/// Representing 4 digit binary in single hexadecimal digit.
let binaryToHexString = function
  | "0000" -> "0"
  | "0001" -> "1"
  | "0010" -> "2"
  | "0011" -> "3"
  | "0100" -> "4"
  | "0101" -> "5"
  | "0110" -> "6"
  | "0111" -> "7"
  | "1000" -> "8"
  | "1001" -> "9"
  | "1010" -> "A"
  | "1011" -> "B"
  | "1100" -> "C"
  | "1101" -> "D"
  | "1110" -> "E"
  | "1111" -> "F"
  | _ -> ""

/// Representing 3 digit binary in single octal digit.
let binaryToOctalString = function
  | "000" -> "0"
  | "001" -> "1"
  | "010" -> "2"
  | "011" -> "3"
  | "100" -> "4"
  | "101" -> "5"
  | "110" -> "6"
  | "111" -> "7"
  | _ -> ""
