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

namespace B2R2.FrontEnd.ARM32

/// Represents a set of SIMD data types.
type SIMDDataTypes =
  | OneDT of SIMDDataType
  | TwoDT of SIMDDataType * SIMDDataType

/// Represents a specific SIMD data type (e.g., 8B, 4H, 2S).
and SIMDDataType =
  (* Any element of <size> bits *)
  | SIMDTyp8
  | SIMDTyp16
  | SIMDTyp32
  | SIMDTyp64
  (* Floating-point number of <size> bits *)
  | SIMDTypF16
  | SIMDTypF32
  | SIMDTypF64
  (* Signed or unsigned integer of <size> bits *)
  | SIMDTypI8
  | SIMDTypI16
  | SIMDTypI32
  | SIMDTypI64
  (* Polynomial over {0, 1} of degree less than <size> *)
  | SIMDTypP8
  | SIMDTypP64
  (* Signed integer of <size> bits *)
  | SIMDTypS8
  | SIMDTypS16
  | SIMDTypS32
  | SIMDTypS64
  (* Unsigned integer of <size> bits *)
  | SIMDTypU8
  | SIMDTypU16
  | SIMDTypU32
  | SIMDTypU64
  | BF16
