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

namespace B2R2.RearEnd.BiHexLang

/// Represents an expression in BiHexLang, which is a language for simple
/// arithmetic expressions on numbers represented in binary and hexadecimal
/// formats (as well as decimal for convenience). Every expression is evaluated
/// to a byte array (little-endian) in the end.
type Expr =
  /// Number literal.
  | Number of NumberType * byte[]
  /// String literal.
  | Str of string
  /// Addition.
  | Add of Expr * Expr
  /// Subtraction.
  | Sub of Expr * Expr
  /// Multiplication.
  | Mul of Expr * Expr
  /// Division.
  | Div of Expr * Expr
  /// Modulus.
  | Mod of Expr * Expr
  /// Bitwise AND.
  | And of Expr * Expr
  /// Bitwise OR.
  | Or of Expr * Expr
  /// Bitwise XOR.
  | Xor of Expr * Expr
  /// Shift left.
  | Shl of Expr * Expr
  /// Shift right.
  | Shr of Expr * Expr
  /// Negation.
  | Neg of Expr
  /// Bitwise NOT.
  | Not of Expr
  /// Casting to a specific representation.
  | Cast of NumberType * Expr
  /// Concatenation.
  | Concat of Expr * Expr
with
  /// Converts an expression back to string.
  static member ToString expr =
    match expr with
    | Number(Hex, bs) ->
      "0x" + System.BitConverter.ToString(Array.rev bs).Replace("-", "")
    | Number(Bin, bs) ->
      let bits =
        bs
        |> Array.map (fun b ->
          System.Convert.ToString(b, 2).PadLeft(8, '0'))
        |> Array.rev
        |> String.concat ""
      "0b" + bits.TrimStart('0').PadLeft(1, '0')
    | Number(Oct, bs) ->
      let num =
        Array.chunkBySize 3 bs
        |> Array.map (fun chunk ->
          let chunk =
            if chunk.Length = 3 then chunk
            else Array.append chunk (Array.zeroCreate (3 - chunk.Length))
          let b2, b1, b0 = chunk[2], chunk[1], chunk[0]
          let n = (int b2 <<< 16) ^^^ (int b1 <<< 8) ^^^ (int b0)
          System.Convert.ToString(n, 8))
        |> Array.rev
        |> String.concat ""
      "0o" + num
    | Number(Dec, bs) ->
      let s = (bigint bs).ToString()
      if s.StartsWith('-') then $"-0d{s[1..]}"
      else $"0d{s}"
    | Str(s) ->
      $"\"{s}\""
    | Add(lhs, rhs) ->
      $"({Expr.ToString lhs} + {Expr.ToString rhs})"
    | Sub(lhs, rhs) ->
      $"({Expr.ToString lhs} - {Expr.ToString rhs})"
    | Mul(lhs, rhs) ->
      $"({Expr.ToString lhs} * {Expr.ToString rhs})"
    | Div(lhs, rhs) ->
      $"({Expr.ToString lhs} / {Expr.ToString rhs})"
    | Mod(lhs, rhs) ->
      $"({Expr.ToString lhs} %% {Expr.ToString rhs})"
    | And(lhs, rhs) ->
      $"({Expr.ToString lhs} & {Expr.ToString rhs})"
    | Or(lhs, rhs) ->
      $"({Expr.ToString lhs} | {Expr.ToString rhs})"
    | Xor(lhs, rhs) ->
      $"({Expr.ToString lhs} ^ {Expr.ToString rhs})"
    | Shl(lhs, rhs) ->
      $"({Expr.ToString lhs} << {Expr.ToString rhs})"
    | Shr(lhs, rhs) ->
      $"({Expr.ToString lhs} >> {Expr.ToString rhs})"
    | Neg e ->
      $"-{Expr.ToString e}"
    | Not e ->
      $"~{Expr.ToString e}"
    | Cast(Hex, e) ->
      $"(hex) {Expr.ToString e}"
    | Cast(Bin, e) ->
      $"(bin) {Expr.ToString e}"
    | Cast(Oct, e) ->
      $"(oct) {Expr.ToString e}"
    | Cast(Dec, e) ->
      $"(dec) {Expr.ToString e}"
    | Concat(lhs, rhs) ->
      $"({Expr.ToString lhs} . {Expr.ToString rhs})"

/// Represents the type of number literal.
and NumberType =
  /// Hexadecimal number.
  | Hex
  /// Binary number.
  | Bin
  /// Octal number.
  | Oct
  /// Decimal number.
  | Dec
