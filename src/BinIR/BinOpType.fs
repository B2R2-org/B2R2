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

namespace B2R2.BinIR

/// Represents a binary operator.
type BinOpType =
  /// Addition
  | ADD = 0
  /// Subtraction
  | SUB = 1
  /// Multiplication
  | MUL = 2
  /// Unsigned division
  | DIV = 3
  /// Signed division
  | SDIV = 4
  /// Unsigned modulo
  | MOD = 5
  /// Signed modulo
  | SMOD = 6
  /// Shift left
  | SHL = 7
  /// Shift right
  | SHR = 8
  /// Sign-extended shift right
  | SAR = 9
  /// Bitwise and
  | AND = 10
  /// Bitwise or
  | OR = 11
  /// Bitwise xor
  | XOR = 12
  /// Concat two reg values
  | CONCAT = 13
  /// Apply a function
  | APP = 14
  /// Floating point addition
  | FADD = 16
  /// Floating point subtraction
  | FSUB = 17
  /// Floating point multiplication
  | FMUL = 18
  /// Floating point division
  | FDIV = 19
  /// Power (x1^x2)
  | FPOW = 20
  /// Log (log of x2 in base x1)
  | FLOG = 21

/// <summary>
/// Provides functions to access <see cref='T:B2R2.BinIR.BinOpType'/>.
/// </summary>
[<RequireQualifiedAccess>]
module BinOpType =
  let private symbols =
    [ (BinOpType.ADD, "+")
      (BinOpType.SUB, "-")
      (BinOpType.MUL, "*")
      (BinOpType.DIV, "/")
      (BinOpType.SDIV, "?/")
      (BinOpType.MOD, "%")
      (BinOpType.SMOD, "?%")
      (BinOpType.SHL, "<<")
      (BinOpType.SHR, ">>")
      (BinOpType.SAR, "?>>")
      (BinOpType.AND, "&")
      (BinOpType.OR, "|")
      (BinOpType.XOR, "^")
      (BinOpType.CONCAT, "++")
      (BinOpType.APP, "@")
      (BinOpType.FADD, "+.")
      (BinOpType.FSUB, "-.")
      (BinOpType.FMUL, "*.")
      (BinOpType.FDIV, "/.")
      (BinOpType.FPOW, "^^")
      (BinOpType.FLOG, "lg") ]

  let private opToStr = symbols |> Map.ofList

  let private strToOp =
    symbols
    |> List.map (fun (k, v) -> (v, k))
    |> Map.ofList

  let private findOrRaise key map exc =
    Map.tryFind key map |> Option.defaultWith (fun _ -> raise exc)

  /// <summary>
  /// Retrieves the string representation of the binary operator.
  /// </summary>
  [<CompiledName "ToString">]
  let toString opType = findOrRaise opType opToStr IllegalASTTypeException

  /// <summary>
  /// Retrieves the binary operator from a string.
  /// </summary>
  [<CompiledName "OfString">]
  let ofString opStr = findOrRaise opStr strToOp IllegalASTTypeException
