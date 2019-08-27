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

namespace B2R2.Utilities.BinExplorer
open System.Numerics
open SimpleArithReference

/// Type for wrapping values
type Numbers =
  | I8 of int8
  | UI8 of uint8
  | I16 of int16
  | UI16 of uint16
  | I32 of int
  | UI32 of uint32
  | I64 of int64
  | UI64 of uint64
  | I128 of BigInteger
  | UI128 of BigInteger
  | I256 of BigInteger
  | UI256 of BigInteger
  | F32 of float32
  | F64 of float
  | NError of string * int64

module Numbers =
  let getValue = function
    | I8 a -> string(a)
    | UI8 a -> string(a)
    | I16 a -> string(a)
    | UI16 a -> string(a)
    | I32 a -> string(a)
    | UI32 a -> string(a)
    | I64 a -> string(a)
    | UI64 a -> string(a)
    | I128 a -> string(a)
    | UI128 a -> string(a)
    | I256 a -> string(a)
    | UI256 a -> string(a)
    | F32 a -> string(a)
    | F64 a -> string(a)
    | NError (a, _) -> a

/// Type for representing number of bits and error types.
type Size =
  | B8
  | B16
  | B32
  | B64
  | B128
  | B256
  | BF32
  | BF64
  | OutofRange
  | Arithmetic
  | Shift
  | Input

module Size =
  let getPriority = function
    | B8 -> 1
    | B16 -> 2
    | B32 -> 3
    | B64 -> 4
    | B128 -> 5
    | B256 -> 6
    | BF32 -> 7
    | BF64 -> 8
    | OutofRange | Arithmetic | Shift | Input -> 9

type DataType =
  | Signed of Size
  | Unsigned of Size
  | Float of Size
  | CError of Size

module DataType =
  let getType = function
    | Signed _ -> 0
    | Unsigned _ -> 1
    | Float _ -> 2
    | CError _ -> 3

  let getIntegerRange = function
    | Signed B8 -> (-128I, 127I)
    | Unsigned B8 -> (0I, 255I)
    | Signed B16 -> (-32768I, 32767I)
    | Unsigned B16 -> (0I, 65535I)
    | Signed B32 -> (ref "int32Min", ref "int32Max")
    | Unsigned B32 -> (0I, ref "uint32Max")
    | Signed B64 -> (ref "int64Min", ref "int64Max")
    | Unsigned B64 -> (0I, ref "uint64Max")
    | Signed B128 -> (ref "int128Min", ref "int128Max")
    | Unsigned B128 -> (0I, ref "uint128Max")
    | Signed B256 -> (ref "int256Min", ref "int256Max")
    | Unsigned B256 -> (0I, ref "uint256Max")
    | _ -> (-1I, -1I)

  let getNextSignedInt = function
    | 1 -> Signed B16
    | 2 -> Signed B32
    | 3 -> Signed B64
    | 4 -> Signed B128
    | 5 -> Signed B256
    | _ -> CError OutofRange

  let getSize = function
    | Signed a -> a
    | Unsigned a -> a
    | Float a -> a
    | CError a -> a

  let wrapValue dataType value =
    match dataType with
    | Signed B8 -> Signed B8, I8 (int8(value))
    | Unsigned B8 -> Unsigned B8, UI8 (uint8(value))
    | Signed B16 -> Signed B16, I16 (int16(value))
    | Unsigned B16 -> Unsigned B16, UI16 (uint16(value))
    | Signed B32 -> Signed B32, I32 (int32(value))
    | Unsigned B32 -> Unsigned B32, UI32 (uint32(value))
    | Signed B64 -> Signed B64, I64 (int64(value))
    | Unsigned B64 -> Unsigned B64, UI64 (uint64(value))
    | Signed B128 -> Signed B128, I128 value
    | Unsigned B128 -> Unsigned B128, UI128 value
    | Signed B256 -> Signed B256, I256 value
    | Unsigned B256 -> Unsigned B256, UI256 value
    | _ -> CError Input, NError ("Wrong Input", 1L)
