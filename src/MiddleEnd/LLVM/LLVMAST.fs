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

namespace B2R2.MiddleEnd.LLVM

/// Identifier.
type LLVMIdentifier = {
  mutable Num: int
  IDType: string
}

/// Simplified LLVM expression.
type LLVMExpr =
  /// Identifier.
  | Ident of LLVMIdentifier
  /// LLVM instruction.
  | Opcode of string
  /// Label expression used in a branch.
  | Label of string
  /// Phi expression in square brackets, e.g., [ %1, %2 ].
  | PhiNode of id: LLVMExpr * lbl: LLVMExpr
  /// Number.
  | Number of uint64 * typ: string
  /// Comma-separated list of expressions.
  | ExprList of LLVMExpr list
  /// All the rest become a string chunk to make things simple. This includes
  /// type strings, space characters, and all the other tokens.
  | Token of string
  /// LLVM expression prefixed with a type.
  | TypedExpr of string * LLVMExpr

module LLVMExpr =
  let mkTypedId id =
    TypedExpr (id.IDType, Ident id)

/// Simplified LLVM statement.
type LLVMStmt =
  /// Label statement.
  | LMark of string
  /// Definition of an identifier.
  | Def of lhs: LLVMIdentifier * rhs: LLVMExpr[]
  /// Memory store.
  | Store of LLVMExpr * LLVMExpr * align: string option * comment: string option
  /// Branch.
  | Branch of LLVMExpr[]
  /// A comment line.
  | Comment of string

module LLVMStmt =
  open LLVMExpr

  let mkGetElementPtr id ptr (offset: int) =
    let args = [ Token "i8"; mkTypedId ptr; Token $"i64 {offset}" ]
    Def (id, [| Opcode "getelementptr"; ExprList args |])

  let mkBitcast id expr typ =
    Def (id, [| Opcode "bitcast"; expr; Token "to"; Token typ |])

  let mkTrunc id expr typ =
    Def (id, [| Opcode "trunc"; expr; Token "to"; Token typ |])

  let mkZExt id expr typ =
    Def (id, [| Opcode "zext"; expr; Token "to"; Token typ |])

  let mkIntToPtr id itype expr ptyp =
    Def (id, [| Opcode "inttoptr"; Token itype; expr; Token "to"; Token ptyp |])

  let mkLoad id addr comment =
    let args = [ Token id.IDType; mkTypedId addr ]
    match comment with
    | Some c -> Def (id, [| Opcode "load";  ExprList args; Token c |])
    | None -> Def (id, [| Opcode "load";  ExprList args |])

  let mkStore v addr align comment =
    Store (v, Ident addr, align, comment)

  let mkBinop id op sz lhs rhs =
    Def (id, [| Opcode op; Token sz; ExprList [ lhs; rhs ] |])

  let mkIcmp id op sz lhs rhs =
    Def (id, [| Opcode "icmp"; Token op; Token sz; ExprList [ lhs; rhs ] |])

  let mkCast id op fromSz e toSz =
    Def (id, [| Opcode op; Token fromSz; e; Token "to"; Token toSz |])

  let mkSelect id cond typ t f =
    let t, f = TypedExpr (typ, t), TypedExpr (typ, f)
    Def (id, [| Opcode "select"; Token "i1"; ExprList [ cond; t; f ] |])
