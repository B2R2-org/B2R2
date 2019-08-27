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

module B2R2.Utilities.BinExplorer.SimpleArithReference

let rec ref = function
  | "int128Max" -> 170141183460469231731687303715884105727I
  | "int128Min" -> -170141183460469231731687303715884105728I
  | "int256Max" -> (abs (ref "int128Min")) * (abs (ref "int128Min")) * 2I - 1I
  | "int256Min" -> -(ref "int256Max") - 1I
  | "uint256Max" -> (ref "int256Max" + 1I) * 2I - 1I
  | "uint128Max" -> 340282366920938463463374607431768211455I
  | "int32Max" -> 2147483647I
  | "int32Min" -> -2147483648I
  | "uint32Max" -> bigint System.UInt32.MaxValue
  | "int64Max" -> 9223372036854775807I
  | "int64Min" -> -9223372036854775808I
  | "uint64Max" -> 18446744073709551615I
  | "floatMax" -> bigint System.Double.MaxValue
  | "floatMin" -> bigint System.Double.MinValue
  | "int8Min" -> -128I
  | "int8Max" -> 127I
  | "int16Min" -> -32768I
  | "int16Max" -> 32767I
  | _ -> -1I

let hexToBinaryString = function
  | '0' -> "0000"
  | '1' -> "1000"
  | '2' -> "0100"
  | '3' -> "1100"
  | '4' -> "0010"
  | '5' -> "1010"
  | '6' -> "0110"
  | '7' -> "1110"
  | '8' -> "0001"
  | '9' -> "1001"
  | 'A' | 'a' -> "0101"
  | 'B' | 'b' -> "1101"
  | 'C' | 'c' -> "0011"
  | 'D' | 'd' -> "1011"
  | 'E' | 'e'-> "0111"
  | 'F' | 'f' -> "1111"
  | _ -> ""

let octalToBinaryString = function
  | '0' -> "000"
  | '1' -> "100"
  | '2' -> "010"
  | '3' -> "110"
  | '4' -> "001"
  | '5' -> "101"
  | '6' -> "011"
  | '7' -> "111"
  | _ -> ""

let binaryToOctalOrHex = function
  | "0000" | "000" -> "0"
  | "0001" | "001" -> "1"
  | "0010" | "010" -> "2"
  | "0011" | "011" -> "3"
  | "0100" | "100" -> "4"
  | "0101" | "101" -> "5"
  | "0110" | "110" -> "6"
  | "0111" | "111" -> "7"
  | "1000" -> "8"
  | "1001" -> "9"
  | "1010" -> "A"
  | "1011" -> "B"
  | "1100" -> "C"
  | "1101" -> "D"
  | "1110" -> "E"
  | "1111" -> "F"
  | _ -> ""
