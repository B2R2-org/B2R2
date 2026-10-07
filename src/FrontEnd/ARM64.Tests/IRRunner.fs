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

namespace B2R2.FrontEnd.ARM64.Tests

open System.Collections.Generic
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR

/// Runs the statements an instruction lifts to over registers given values,
/// for a test whose claim is the value an instruction computes. It knows the
/// straight-line integer LowUIR a lane of SIMD arithmetic lifts to, and of
/// doubles the rounding to an integral value an exactness check asks for and
/// the conversion and scaling a fixed-point operand goes through, and fails
/// on anything else rather than guess what it means.
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
    | BinOpType.MUL -> BitVector.Mul(a, b)
    | BinOpType.MOD -> BitVector.Modulo(a, b)
    | BinOpType.AND -> BitVector.And(a, b)
    | BinOpType.OR -> BitVector.Or(a, b)
    | BinOpType.XOR -> BitVector.Xor(a, b)
    | BinOpType.SHL -> BitVector.Shl(a, b)
    | BinOpType.SHR -> BitVector.Shr(a, b)
    | BinOpType.SAR -> BitVector.Sar(a, b)
    | BinOpType.CONCAT -> BitVector.Concat(a, b)
    | _ -> failwith $"IRRunner: no {op}"

  let private relOp op (a: BitVector) (b: BitVector) =
    match op with
    | RelOpType.EQ -> BitVector.Eq(a, b)
    | RelOpType.NEQ -> BitVector.Neq(a, b)
    | RelOpType.GT -> BitVector.Gt(a, b)
    | RelOpType.GE -> BitVector.Ge(a, b)
    | RelOpType.LT -> BitVector.Lt(a, b)
    | RelOpType.LE -> BitVector.Le(a, b)
    | RelOpType.SGT -> BitVector.SGt(a, b)
    | RelOpType.SGE -> BitVector.SGe(a, b)
    | RelOpType.SLT -> BitVector.SLt(a, b)
    | RelOpType.SLE -> BitVector.SLe(a, b)
    | _ -> failwith $"IRRunner: no {op}"

  /// The double a 64-bit pattern holds.
  let private toDouble (x: BitVector) =
    System.BitConverter.UInt64BitsToDouble(x.ToUInt64())

  /// A double's 64-bit pattern.
  let private ofDouble (d: float) =
    BitVector(System.BitConverter.DoubleToUInt64Bits(d), 64<rt>)

  /// A double rounded to an integral value in a direction of the
  /// RoundingMode encoding.
  let private roundToIntegral (mode: BitVector) (x: BitVector) =
    let d = toDouble x
    match enum<RoundingMode> (int (mode.ToUInt64())) with
    | RoundingMode.ToNearestEven -> ofDouble (System.Math.Round(d))
    | RoundingMode.TowardNegative -> ofDouble (System.Math.Floor(d))
    | RoundingMode.TowardPositive -> ofDouble (System.Math.Ceiling(d))
    | RoundingMode.TowardZero -> ofDouble (System.Math.Truncate(d))
    | m -> failwith $"IRRunner: no {m}"

  let rec private eval regs (temps: Dictionary<int, BitVector>) e =
    let eval = eval regs temps
    match e with
    | Num(Value = v) ->
      v
    | Var(Type = t; RegisterID = r) ->
      readReg regs r t
    | TempVar(Index = n) ->
      temps[n]
    | BinOp(Op = BinOpType.FMUL; Left = l; Right = r)
      when Expr.typeOf l = 64<rt> ->
      ofDouble (toDouble (eval l) * toDouble (eval r))
    | BinOp(Op = op; Left = l; Right = r) ->
      binOp op (eval l) (eval r)
    | RelOp(Op = op; Left = l; Right = r) ->
      relOp op (eval l) (eval r)
    | UnOp(Op = UnOpType.NEG; Operand = x) ->
      BitVector.Neg(eval x)
    | UnOp(Op = UnOpType.NOT; Operand = x) ->
      BitVector.Not(eval x)
    | Cast(Kind = CastKind.ZeroExt; Type = t; Operand = x) ->
      BitVector.ZExt(eval x, t)
    | Cast(Kind = CastKind.SignExt; Type = t; Operand = x) ->
      BitVector.SExt(eval x, t)
    | Cast(Kind = CastKind.SIntToFloat; Type = 64<rt>; Operand = x)
      when Expr.typeOf x = 64<rt> ->
      ofDouble (float (int64 ((eval x).ToUInt64())))
    | Cast(Kind = CastKind.UIntToFloat; Type = 64<rt>; Operand = x)
      when Expr.typeOf x = 64<rt> ->
      ofDouble (float ((eval x).ToUInt64()))
    | Extract(Operand = x; Type = t; StartPos = p) ->
      BitVector.Extract(eval x, t, p)
    | Ite(Cond = c; TrueExpr = a; FalseExpr = b) ->
      if (eval c).IsTrue then eval a else eval b
    | RoundCtrl(Mode = mode; Body = Cast(Kind = kind; Operand = x))
      when kind = CastKind.RoundToIntegral && Expr.typeOf x = 64<rt> ->
      roundToIntegral (eval mode) (eval x)
    | _ ->
      failwith $"IRRunner: no {e}"

  /// What each register holds after the statements ran, starting from the
  /// given values and from zero everywhere else.
  let run (stmts: Stmt[]) (inputs: (Expr * BitVector) list) =
    let regs = Dictionary<RegisterID, BitVector>()
    let temps = Dictionary<int, BitVector>()
    for reg, v in inputs do regs[idOf reg] <- v
    for stmt in stmts do
      match stmt with
      | ISMark _ | IEMark _ | LMark _ ->
        ()
      | Put(Dst = Var(RegisterID = r); Src = src) ->
        regs[r] <- eval regs temps src
      | Put(Dst = TempVar(Index = n); Src = src) ->
        temps[n] <- eval regs temps src
      | _ ->
        failwith $"IRRunner: no {stmt}"
    fun reg -> readReg regs (idOf reg) (Expr.typeOf reg)

  /// The labels of the statements, by where each one sits.
  let private labelsOf (stmts: Stmt[]) =
    let at = Dictionary<Label, int>()
    stmts
    |> Array.iteri (fun i stmt ->
      match stmt with
      | LMark(Label = l) -> at[l] <- i
      | _ -> ())
    at

  /// The side effect the statements reach, if any, run from the given
  /// register values: a jump inside the instruction goes to its label, and a
  /// side effect ends the run, as the exception it stands for would.
  let effects (stmts: Stmt[]) (inputs: (Expr * BitVector) list) =
    let regs = Dictionary<RegisterID, BitVector>()
    let temps = Dictionary<int, BitVector>()
    for reg, v in inputs do regs[idOf reg] <- v
    let at = labelsOf stmts
    let found = ResizeArray()
    let mutable pc = 0
    while pc < stmts.Length do
      let stmt = stmts[pc]
      pc <- pc + 1
      match stmt with
      | ISMark _ | IEMark _ | LMark _ ->
        ()
      | Put(Dst = Var(RegisterID = r); Src = src) ->
        regs[r] <- eval regs temps src
      | Put(Dst = TempVar(Index = n); Src = src) ->
        temps[n] <- eval regs temps src
      | Jmp(Target = JmpDest(Target = l)) ->
        pc <- at[l]
      | CJmp(Cond = c; TrueTarget = JmpDest(Target = t);
             FalseTarget = JmpDest(Target = f)) ->
        pc <- at[if (eval regs temps c).IsTrue then t else f]
      | SideEffect(Effect = e) ->
        found.Add e
        pc <- stmts.Length
      | _ ->
        failwith $"IRRunner: no {stmt}"
    List.ofSeq found
