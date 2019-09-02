(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Michael Tegegn <mick@kaist.ac.kr>
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

module B2R2.BinIR.LowUIR.Parser.Utils

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open FParsec

/// Used when parsing Undefined expression(not relevant).
let dummyRegType = 32<rt>
/// Used when parsing InterJmp statments(not relevant).
let dummyExpr = Undefined (dummyRegType, "dummy value")
/// Used when parsing InterJmp statements(not relevant).
let dummyInterJmpInfo = InterJmpInfo.Base

let typeCheckR st =
  if AST.typeCheck st then preturn st else fail "statment type check failed"

let pcFromRegName n = PCVar ((RegType.fromBitWidth 32), n)

let binOpFromString = function
  | "+" -> BinOpType.ADD
  |  "-" -> BinOpType.SUB
  | "*" -> BinOpType.MUL
  | "/" -> BinOpType.DIV
  | "?/" -> BinOpType.SDIV
  | "%" -> BinOpType.MOD
  | "?%" -> BinOpType. SMOD
  | "<<" -> BinOpType.SHL
  | ">>" -> BinOpType. SHR
  | "?>>" -> BinOpType. SAR
  | "&" -> BinOpType. AND
  | "|" -> BinOpType. OR
  | "^" -> BinOpType. XOR
  | "++" -> BinOpType.CONCAT
  | "-|" -> BinOpType.APP
  | "::" -> BinOpType.CONS
  | _ -> raise IllegalASTTypeException

let unOpFromString = function
  | "-" -> UnOpType.NEG
  | "~" -> UnOpType.NOT
  | _ -> raise IllegalASTTypeException

let relOpFromString = function
  | "=" -> RelOpType.EQ
  | "!=" -> RelOpType.NEQ
  | ">" -> RelOpType.GT
  | ">=" -> RelOpType.GE
  | "?>" -> RelOpType.SGT
  | "?>=" -> RelOpType.SGE
  | "<" -> RelOpType.LT
  | "<=" -> RelOpType.LE
  | "?<" -> RelOpType.SLT
  | "?<=" -> RelOpType.SLE
  | _ -> raise IllegalASTTypeException

let castTypeFromString = function
  | "sext" -> CastKind.SignExt
  | "zext" -> CastKind.ZeroExt
  | _ -> raise IllegalASTTypeException

let sideEffectFromString = function
  | _ -> ClockCounter
