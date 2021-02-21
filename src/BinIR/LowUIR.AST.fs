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

/// LowUIR AST construction must be done through this module.
module B2R2.BinIR.LowUIR.AST

open B2R2
open B2R2.BinIR

/// Get the expression info from the given expression (Expr).
[<CompiledName("GetExprInfo")>]
let getExprInfo e = ASTHelper.getExprInfo e

/// Construct a number (Num).
[<CompiledName("Num")>]
let num bv = Num (bv) |> ASTHelper.buildExpr

/// Construct a variable (Var).
[<CompiledName("Var")>]
let var t id name rs = Var (t, id, name, rs) |> ASTHelper.buildExpr

/// Construct a pc variable (PCVar).
[<CompiledName("PCVar")>]
let pcvar t name = PCVar (t, name) |> ASTHelper.buildExpr

let private tvarCnt = ref -1

/// Construct a temporary variable (TempVar).
[<CompiledName("TmpVar")>]
let tmpvar t =
  let id = System.Threading.Interlocked.Increment (tvarCnt)
  if id >= 0 then TempVar (t, id) |> ASTHelper.buildExpr
  else Utils.impossible ()

/// Construct a temporary variable (TempVar) with the given ID.
[<CompiledName("TmpVar")>]
let tmpvarWithID t id = TempVar (t, id) |> ASTHelper.buildExpr

let private lblCnt = ref -1

/// Construct a symbol (for a label) from a string.
[<CompiledName("Symbol")>]
let symbol name =
  let id = System.Threading.Interlocked.Increment (lblCnt)
  if id >= 0 then Symbol (name, id)
  else Utils.impossible ()

/// Construct an unary operator (UnOp).
[<CompiledName("UnOp")>]
let unop rt e = ASTHelper.unop rt e

/// Construct a symbolic name (Name).
[<CompiledName("Name")>]
let name symb = Name symb |> ASTHelper.buildExpr

/// Construct a binary operator (BinOp).
[<CompiledName("BinOp")>]
let binop op e1 e2 =
  let t =
    match op with
    | BinOpType.CONCAT -> TypeCheck.concat e1 e2
    | _ ->
#if DEBUG
      TypeCheck.binop e1 e2
#else
      TypeCheck.typeOf e1
#endif
  ASTHelper.binop op t e1 e2

/// Consing two expr.
[<CompiledName("Cons")>]
let cons a b = ASTHelper.cons a b

/// Construct a function application.
[<CompiledName("App")>]
let app name args retType = ASTHelper.app name args retType

/// Construct a relative operator (RelOp).
[<CompiledName("RelOp")>]
let relop op e1 e2 = ASTHelper.relop op e1 e2

/// Construct a load expression (Load).
[<CompiledName("Load")>]
let load endian rt addr = ASTHelper.load endian rt addr

/// Construct a load expression in little-endian.
[<CompiledName("LoadLE")>]
let loadLE t expr = ASTHelper.load Endian.Little t expr

/// Construct a load expression in big-endian.
[<CompiledName("LoadBE")>]
let loadBE t expr = ASTHelper.load Endian.Big t expr

/// Construct an ITE (if-then-else) expression (Ite).
[<CompiledName("Ite")>]
let ite cond e1 e2 = ASTHelper.ite cond e1 e2

/// Construct a cast expression (Cast).
[<CompiledName("Cast")>]
let cast kind rt e = ASTHelper.cast kind rt e

/// Construct a extract expression (Extract).
[<CompiledName("Extract")>]
let extract e rt pos = ASTHelper.extract e rt pos

/// Undefined expression.
[<CompiledName("Undef")>]
let undef rt s = Undefined (rt, s) |> ASTHelper.buildExpr

/// Construct a (Num 0) of size t.
[<CompiledName("Num0")>]
let num0 rt = num (BitVector.zero rt)

/// Construct a (Num 1) of size t.
[<CompiledName("Num1")>]
let num1 rt = num (BitVector.one rt)

/// Num expression for a one-bit number zero.
[<CompiledName("B0")>]
let b0 = num (BitVector.zero 1<rt>)

/// Num expression for a one-bit number one.
[<CompiledName("B1")>]
let b1 = num (BitVector.one 1<rt>)

/// Nil.
[<CompiledName("Nil")>]
let nil = Nil |> ASTHelper.buildExpr

/// Concatenation.
[<CompiledName("Concat")>]
let concat e1 e2 = ASTHelper.concat e1 e2

/// Concatenate an array of expressions.
[<CompiledName("Concat")>]
let concatArr (arr: Expr[]) = ASTHelper.concatArr arr

/// Unwrap (casted) expression.
[<CompiledName("Unwrap")>]
let unwrap e = ASTHelper.unwrap e

/// Zero-extend an expression.
[<CompiledName("ZExt")>]
let zext addrSize expr = ASTHelper.cast CastKind.ZeroExt addrSize expr

/// Sign-extend an expression.
[<CompiledName("SExt")>]
let sext addrSize expr = ASTHelper.cast CastKind.SignExt addrSize expr

/// Take the low half bits of an expression.
[<CompiledName("XtLo")>]
let xtlo addrSize expr = ASTHelper.extract expr addrSize 0

/// Take the high half bits of an expression.
[<CompiledName("XtHi")>]
let xthi addrSize expr =
  ASTHelper.extract expr addrSize (int (TypeCheck.typeOf expr - addrSize))

/// Add two expressions.
[<CompiledName("Add")>]
let add e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    TypeCheck.typeOf e1
#endif
  ASTHelper.binop BinOpType.ADD t e1 e2

/// Subtract two expressions.
[<CompiledName("Sub")>]
let sub e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    TypeCheck.typeOf e1
#endif
  ASTHelper.binop BinOpType.SUB t e1 e2

/// Multiply two expressions.
[<CompiledName("Mul")>]
let mul e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    TypeCheck.typeOf e1
#endif
  ASTHelper.binop BinOpType.MUL t e1 e2

/// Unsigned division.
[<CompiledName("Div")>]
let div e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    TypeCheck.typeOf e1
#endif
  ASTHelper.binop BinOpType.DIV t e1 e2

/// Signed division.
[<CompiledName("SDiv")>]
let sdiv e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    TypeCheck.typeOf e1
#endif
  ASTHelper.binop BinOpType.SDIV t e1 e2

/// Unsigned modulus.
[<CompiledName("Mod")>]
let ``mod`` e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    TypeCheck.typeOf e1
#endif
  ASTHelper.binop BinOpType.MOD t e1 e2

/// Signed modulus.
[<CompiledName("SMod")>]
let smod e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    TypeCheck.typeOf e1
#endif
  ASTHelper.binop BinOpType.SMOD t e1 e2

/// Equal.
[<CompiledName("Eq")>]
let eq e1 e2 = ASTHelper.relop RelOpType.EQ e1 e2

/// Not equal.
[<CompiledName("Neq")>]
let neq e1 e2 = ASTHelper.relop RelOpType.NEQ e1 e2

/// Unsigned greater than.
[<CompiledName("Gt")>]
let gt e1 e2 = ASTHelper.relop RelOpType.GT e1 e2

/// Unsigned greater than or equal.
[<CompiledName("Ge")>]
let ge e1 e2 = ASTHelper.relop RelOpType.GE e1 e2

/// Signed greater than.
[<CompiledName("SGt")>]
let sgt e1 e2 = ASTHelper.relop RelOpType.SGT e1 e2

/// Signed greater than or equal.
[<CompiledName("SGe")>]
let sge e1 e2 = ASTHelper.relop RelOpType.SGE e1 e2

/// Unsigned less than.
[<CompiledName("Lt")>]
let lt e1 e2 = ASTHelper.relop RelOpType.LT e1 e2

/// Unsigned less than or equal.
[<CompiledName("Le")>]
let le e1 e2 = ASTHelper.relop RelOpType.LE e1 e2

/// Signed less than.
[<CompiledName("SLt")>]
let slt e1 e2 = ASTHelper.relop RelOpType.SLT e1 e2

/// Signed less than or equal.
[<CompiledName("SLe")>]
let sle e1 e2 = ASTHelper.relop RelOpType.SLE e1 e2

/// Bitwise AND.
[<CompiledName("And")>]
let ``and`` e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    TypeCheck.typeOf e1
#endif
  ASTHelper.binop BinOpType.AND t e1 e2

/// Bitwise OR.
[<CompiledName("Or")>]
let ``or`` e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    TypeCheck.typeOf e1
#endif
  ASTHelper.binop BinOpType.OR t e1 e2

/// Bitwise XOR.
[<CompiledName("Xor")>]
let xor e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    TypeCheck.typeOf e1
#endif
  ASTHelper.binop BinOpType.XOR t e1 e2

/// Shift arithmetic right.
[<CompiledName("Sar")>]
let sar e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    TypeCheck.typeOf e1
#endif
  ASTHelper.binop BinOpType.SAR t e1 e2

/// Shift logical right.
[<CompiledName("Shr")>]
let shr e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    TypeCheck.typeOf e1
#endif
  ASTHelper.binop BinOpType.SHR t e1 e2

/// Shift logical left.
[<CompiledName("Shl")>]
let shl e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    TypeCheck.typeOf e1
#endif
  ASTHelper.binop BinOpType.SHL t e1 e2

/// Negation (Two's complement).
[<CompiledName("Neg")>]
let neg e = ASTHelper.unop UnOpType.NEG e

/// Logical not.
[<CompiledName("Not")>]
let not e = ASTHelper.unop UnOpType.NOT e

/// Floating point add two expressions.
[<CompiledName("FAdd")>]
let fadd e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    TypeCheck.typeOf e1
#endif
  ASTHelper.binop BinOpType.FADD t e1 e2

/// Floating point subtract two expressions.
[<CompiledName("FSub")>]
let fsub e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    TypeCheck.typeOf e1
#endif
  ASTHelper.binop BinOpType.FSUB t e1 e2

/// Floating point multiplication.
[<CompiledName("FMul")>]
let fmul e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    TypeCheck.typeOf e1
#endif
  ASTHelper.binop BinOpType.FMUL t e1 e2

/// Floating point division.
[<CompiledName("FDiv")>]
let fdiv e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    TypeCheck.typeOf e1
#endif
  ASTHelper.binop BinOpType.FDIV t e1 e2

/// Floating point greater than.
[<CompiledName("FGt")>]
let fgt e1 e2 = ASTHelper.relop RelOpType.FGT e1 e2

/// Floating point greater than or equal.
[<CompiledName("FGe")>]
let fge e1 e2 = ASTHelper.relop RelOpType.FGE e1 e2

/// Floating point less than.
[<CompiledName("FLt")>]
let flt e1 e2 = ASTHelper.relop RelOpType.FLT e1 e2

/// Floating point less than or equal.
[<CompiledName("FLe")>]
let fle e1 e2 = ASTHelper.relop RelOpType.FLE e1 e2

/// Floating point power.
[<CompiledName("FPow")>]
let fpow e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    TypeCheck.typeOf e1
#endif
  ASTHelper.binop BinOpType.FPOW t e1 e2

/// Floating point logarithm.
[<CompiledName("FLog")>]
let flog e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    TypeCheck.typeOf e1
#endif
  ASTHelper.binop BinOpType.FLOG t e1 e2

/// Floating point square root.
[<CompiledName("FSqrt")>]
let fsqrt e = ASTHelper.unop UnOpType.FSQRT e

/// Floating point sine.
[<CompiledName("FSin")>]
let fsin e = ASTHelper.unop UnOpType.FSIN e

/// Floating point cosine.
[<CompiledName("FCos")>]
let fcos e = ASTHelper.unop UnOpType.FCOS e

/// Floating point tangent.
[<CompiledName("FTan")>]
let ftan e = ASTHelper.unop UnOpType.FTAN e

/// Floating point arc tangent.
[<CompiledName("FATan")>]
let fatan e = ASTHelper.unop UnOpType.FATAN e

/// An assignment statement.
[<CompiledName("Assign")>]
let assign dst src = ASTHelper.assign dst src

/// An ISMark statement.
[<CompiledName("ISMark")>]
let ismark nBytes = ISMark nBytes |> ASTHelper.buildStmt

/// An IEMark statement.
[<CompiledName("IEMark")>]
let iemark nBytes = IEMark nBytes |> ASTHelper.buildStmt

/// An LMark statement.
[<CompiledName("LMark")>]
let lmark s = LMark s |> ASTHelper.buildStmt

/// A Put statement.
[<CompiledName("Put")>]
let put dst src = Put (dst, src) |> ASTHelper.buildStmt

/// A Store statement.
[<CompiledName("Store")>]
let store endian addr v = Store (endian, addr, v) |> ASTHelper.buildStmt

/// A Jmp statement.
[<CompiledName("Jmp")>]
let jmp target = Jmp (target) |> ASTHelper.buildStmt

/// A CJmp statement.
[<CompiledName("CJmp")>]
let cjmp cond dst1 dst2 = CJmp (cond, dst1, dst2) |> ASTHelper.buildStmt

/// An InterJmp statement.
[<CompiledName("InterJmp")>]
let interjmp dst kind = InterJmp (dst, kind) |> ASTHelper.buildStmt

/// A InterCJmp statement.
[<CompiledName("InterCJmp")>]
let intercjmp cond dst1 dst2 =
  InterCJmp (cond, dst1, dst2) |> ASTHelper.buildStmt

/// A SideEffect statement.
[<CompiledName("SideEffect")>]
let sideEffect eff = SideEffect eff |> ASTHelper.buildStmt

module InfixOp =
  /// Assignment.
  let inline (:=) e1 e2 = assign e1 e2

  /// Addition.
  let inline (.+) e1 e2 = add e1 e2

  /// Subtraction.
  let inline (.-) e1 e2 = sub e1 e2

  /// Multiplication.
  let inline (.*) e1 e2 = mul e1 e2

  /// Unsigned division.
  let inline (./) e1 e2 = div e1 e2

  /// Signed division.
  let inline (?/) e1 e2 = sdiv e1 e2

  /// Unsigned modulus.
  let inline (.%) e1 e2 = ``mod`` e1 e2

  /// Signed modulus.
  let inline (?%) e1 e2 = smod e1 e2

  /// Equal.
  let inline (==) e1 e2 = eq e1 e2

  /// Not equal.
  let inline (!=) e1 e2 = neq e1 e2

  /// Unsigned greater than.
  let inline (.>) e1 e2 = gt e1 e2

  /// Unsigned greater than or equal.
  let inline (.>=) e1 e2 = ge e1 e2

  /// Signed greater than.
  let inline (?>) e1 e2 = sgt e1 e2

  /// Signed greater than or equal.
  let inline (?>=) e1 e2 = sge e1 e2

  /// Signed less than.
  let inline (.<) e1 e2 = lt e1 e2

  /// Signed less than or equal.
  let inline (.<=) e1 e2 = le e1 e2

  /// Signed less than.
  let inline (?<) e1 e2 = slt e1 e2

  /// Signed less than or equal.
  let inline (?<=) e1 e2 = sle e1 e2

  /// Bitwise AND.
  let inline (.&) e1 e2 = ``and`` e1 e2

  /// Bitwise OR.
  let inline (.|) e1 e2 = ``or`` e1 e2

  /// Bitwise XOR.
  let inline (<+>) e1 e2 = xor e1 e2

  /// Shift arithmetic right.
  let inline (?>>) e1 e2 = sar e1 e2

  /// Shift logical right.
  let inline (>>) e1 e2 = shr e1 e2

  /// Shift logical left.
  let inline (<<) e1 e2 = shl e1 e2
