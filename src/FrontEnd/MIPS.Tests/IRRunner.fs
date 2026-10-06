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

namespace B2R2.FrontEnd.MIPS.Tests

open System.Collections.Generic
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR

/// <summary>
/// Runs the statements an instruction lifts to over registers given values,
/// for a test whose claim is the value an instruction computes. It knows the
/// straight-line LowUIR of the floating-point arithmetic, rounded to nearest,
/// and fails on anything else rather than guess what it means.
///
/// <para>The exception query answers what a test names, nothing unless it
/// names something: the query works out what an operation raised, which this
/// does not, so a test that reads FCSR reads either what comes from
/// somewhere the query is not asked, such as a flush, or what the lifter
/// made of the answer it was given.</para>
/// </summary>
module internal IRRunner =
  /// The register a register variable names.
  let private idOf = function
    | Var(RegisterID = r) -> r
    | e -> failwith $"IRRunner: {e} is not a register"

  let private readReg (regs: Dictionary<RegisterID, BitVector>) r t =
    match regs.TryGetValue r with
    | true, v -> v
    | false, _ -> BitVector.Zero t

  let private binOp op (a: BitVector) (b: BitVector) =
    match op with
    | BinOpType.ADD -> BitVector.Add(a, b)
    | BinOpType.SUB -> BitVector.Sub(a, b)
    | BinOpType.AND -> BitVector.And(a, b)
    | BinOpType.OR -> BitVector.Or(a, b)
    | BinOpType.XOR -> BitVector.Xor(a, b)
    | BinOpType.SHL -> BitVector.Shl(a, b)
    | BinOpType.SHR -> BitVector.Shr(a, b)
    | BinOpType.CONCAT -> BitVector.Concat(a, b)
    | BinOpType.FADD -> BitVector.FAdd(a, b)
    | BinOpType.FSUB -> BitVector.FSub(a, b)
    | BinOpType.FMUL -> BitVector.FMul(a, b)
    | BinOpType.FDIV -> BitVector.FDiv(a, b)
    | _ -> failwith $"IRRunner: no {op}"

  let private relOp op (a: BitVector) (b: BitVector) =
    match op with
    | RelOpType.EQ -> BitVector.Eq(a, b)
    | RelOpType.NEQ -> BitVector.Neq(a, b)
    | RelOpType.GT -> BitVector.Gt(a, b)
    | RelOpType.GE -> BitVector.Ge(a, b)
    | RelOpType.LT -> BitVector.Lt(a, b)
    | RelOpType.LE -> BitVector.Le(a, b)
    | RelOpType.FEQ -> BitVector.FEq(a, b)
    | RelOpType.FGT -> BitVector.FGt(a, b)
    | RelOpType.FLT -> BitVector.FLt(a, b)
    | _ -> failwith $"IRRunner: no {op}"

  /// The named calls the lifters make: the exception query, which answers
  /// the flags it is given.
  let private app answer name =
    match name with
    | "FEXC32" | "FEXC64" -> answer
    | _ -> failwith $"IRRunner: no {name}"

  let rec private eval answer regs (temps: Dictionary<int, BitVector>) e =
    let eval = eval answer regs temps
    match e with
    | Num(Value = v) ->
      v
    | Var(Type = t; RegisterID = r) ->
      readReg regs r t
    | TempVar(Index = n) ->
      temps[n]
    | BinOp(Op = BinOpType.APP; Left = FuncName(Name = n)) ->
      app answer n
    | BinOp(Op = op; Left = l; Right = r) ->
      binOp op (eval l) (eval r)
    | RelOp(Op = op; Left = l; Right = r) ->
      relOp op (eval l) (eval r)
    | UnOp(Op = UnOpType.NOT; Operand = x) ->
      BitVector.Not(eval x)
    | UnOp(Op = UnOpType.FSQRT; Operand = x) ->
      BitVector.FSqrt(eval x)
    | Cast(Kind = CastKind.ZeroExt; Type = t; Operand = x) ->
      BitVector.ZExt(eval x, t)
    | Cast(Kind = CastKind.SignExt; Type = t; Operand = x) ->
      BitVector.SExt(eval x, t)
    | Cast(Kind = CastKind.FloatCast; Type = t; Operand = x) ->
      BitVector.FCast(eval x, t)
    | Extract(Operand = x; Type = t; StartPos = p) ->
      BitVector.Extract(eval x, t, p)
    | Ite(Cond = c; TrueExpr = a; FalseExpr = b) ->
      if (eval c).IsTrue then eval a else eval b
    | _ ->
      failwith $"IRRunner: no {e}"

  /// What each register holds after the statements ran, starting from the
  /// given values and from zero everywhere else, with the exception query
  /// answering the given flags.
  let runAnswering flags stmts inputs =
    let answer = BitVector((flags: uint32), 32<rt>)
    let regs = Dictionary<RegisterID, BitVector>()
    let temps = Dictionary<int, BitVector>()
    for reg, v in inputs do regs[idOf reg] <- v
    for stmt in stmts do
      match stmt with
      | ISMark _ | IEMark _ | LMark _ ->
        ()
      | Put(Dst = Var(RegisterID = r); Src = src) ->
        regs[r] <- eval answer regs temps src
      | Put(Dst = TempVar(Index = n); Src = src) ->
        temps[n] <- eval answer regs temps src
      | _ ->
        failwith $"IRRunner: no {stmt}"
    fun reg -> readReg regs (idOf reg) (Expr.typeOf reg)

  /// What each register holds after the statements ran, with the exception
  /// query answering that nothing was raised.
  let run stmts inputs = runAnswering 0u stmts inputs
