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

open System
open System.Collections.Generic
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR

/// <summary>
/// Runs the statements an instruction lifts to over registers given values,
/// for a test whose claim is the value an instruction computes. It knows the
/// straight-line LowUIR of the floating-point arithmetic, rounded to nearest
/// unless a RoundCtrl names a direction for a rounding to an integer, and
/// fails on anything else rather than guess what it means.
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
    | RelOpType.SGT -> BitVector.SGt(a, b)
    | RelOpType.SLT -> BitVector.SLt(a, b)
    | RelOpType.FEQ -> BitVector.FEq(a, b)
    | RelOpType.FGT -> BitVector.FGt(a, b)
    | RelOpType.FGE -> BitVector.FGe(a, b)
    | RelOpType.FLT -> BitVector.FLt(a, b)
    | _ -> failwith $"IRRunner: no {op}"

  /// The value a single or a double holds, which a double holds exactly.
  let private toDouble (x: BitVector) =
    if x.Length = 32<rt> then
      float (BitConverter.UInt32BitsToSingle(uint32 (x.ToUInt64())))
    else
      BitConverter.UInt64BitsToDouble(x.ToUInt64())

  /// A value as a single or a double, which it must be exactly.
  let private ofDouble rt (d: float) =
    if rt = 32<rt> then
      BitVector(uint64 (BitConverter.SingleToUInt32Bits(float32 d)), 32<rt>)
    else
      BitVector(BitConverter.DoubleToUInt64Bits(d), 64<rt>)

  /// A value rounded to an integral one in a direction of the RoundingMode
  /// encoding.
  let private integral mode (d: float) =
    match mode with
    | RoundingMode.ToNearestEven -> Math.Round(d)
    | RoundingMode.TowardNegative -> Math.Floor(d)
    | RoundingMode.TowardPositive -> Math.Ceiling(d)
    | RoundingMode.TowardZero -> Math.Truncate(d)
    | m -> failwith $"IRRunner: no {m}"

  /// A float rounded to an integer in a direction, the low bits of it kept.
  let private toInt mode rt x =
    let v = int64 (integral mode (toDouble x))
    BitVector.Cast(BitVector(uint64 v, 64<rt>), rt)

  /// The named calls the lifters make: the fused multiply-add, with bit 0 of
  /// its flags negating the product and bit 1 the addend, and the exception
  /// query, which answers the flags it is given.
  let private app answer name (args: BitVector list) =
    match name, args with
    | ("FEXC32" | "FEXC64"), _ ->
      answer
    | ("FMA32" | "FMA64"), [ x; y; z; flags ] ->
      let f = flags.ToUInt64()
      let product = if f &&& 1UL = 0UL then toDouble x else -(toDouble x)
      let addend = if f &&& 2UL = 0UL then toDouble z else -(toDouble z)
      if x.Length = 32<rt> then
        let p, m, a = float32 product, float32 (toDouble y), float32 addend
        let r = MathF.FusedMultiplyAdd(p, m, a)
        BitVector(uint64 (BitConverter.SingleToUInt32Bits(r)), 32<rt>)
      else
        let r = Math.FusedMultiplyAdd(product, toDouble y, addend)
        BitVector(BitConverter.DoubleToUInt64Bits(r), 64<rt>)
    | _ ->
      failwith $"IRRunner: no {name}"

  let rec private eval answer regs (temps: Dictionary<int, BitVector>) e =
    let eval = eval answer regs temps
    match e with
    | Num(Value = v) ->
      v
    | Var(Type = t; RegisterID = r) ->
      readReg regs r t
    | TempVar(Index = n) ->
      temps[n]
    | BinOp(Op = BinOpType.APP; Left = FuncName(Name = n); Right = es) ->
      match es with
      | ExprList(Elements = args) -> app answer n (List.map eval args)
      | _ -> failwith $"IRRunner: no {e}"
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
    | Cast(Kind = CastKind.FloatToSInt; Type = t; Operand = x) ->
      toInt RoundingMode.ToNearestEven t (eval x)
    | RoundCtrl(Mode = m; Body = Cast(Kind = k; Type = t; Operand = x)) ->
      let mode = enum<RoundingMode> (int ((eval m).ToUInt64()))
      match k with
      | CastKind.RoundToIntegral ->
        ofDouble t (integral mode (toDouble (eval x)))
      | CastKind.FloatToSInt ->
        toInt mode t (eval x)
      | _ ->
        failwith $"IRRunner: no {e}"
    | Extract(Operand = x; Type = t; StartPos = p) ->
      BitVector.Extract(eval x, t, p)
    | Ite(Cond = c; TrueExpr = a; FalseExpr = b) ->
      if (eval c).IsTrue then eval a else eval b
    | _ ->
      failwith $"IRRunner: no {e}"

  let private put answer regs (temps: Dictionary<int, BitVector>) stmt =
    match stmt with
    | Put(Dst = Var(RegisterID = r); Src = src) ->
      (regs: Dictionary<RegisterID, BitVector>)[r] <-
        eval answer regs temps src
    | Put(Dst = TempVar(Index = n); Src = src) ->
      temps[n] <- eval answer regs temps src
    | _ ->
      failwith $"IRRunner: no {stmt}"

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
      | ISMark _ | IEMark _ | LMark _ -> ()
      | _ -> put answer regs temps stmt
    fun reg -> readReg regs (idOf reg) (Expr.typeOf reg)

  /// What each register holds after the statements ran, with the exception
  /// query answering that nothing was raised.
  let run stmts inputs = runAnswering 0u stmts inputs

  /// <summary>
  /// The side effects the statements raise and what each register holds
  /// after them, taking each jump between their labels the way the given
  /// values decide it: for a test whose claim is which way an instruction
  /// goes. A jump out of the instruction ends the run.
  /// </summary>
  let follow (stmts: Stmt[]) inputs =
    let answer = BitVector(0u, 32<rt>)
    let regs = Dictionary<RegisterID, BitVector>()
    let temps = Dictionary<int, BitVector>()
    for reg, v in inputs do regs[idOf reg] <- v
    let at label =
      stmts
      |> Array.findIndex (function
        | LMark(Label = l) -> l = label
        | _ -> false)
    let rec step i effects =
      if i >= stmts.Length then
        List.rev effects
      else
        match stmts[i] with
        | ISMark _ | IEMark _ | LMark _ ->
          step (i + 1) effects
        | SideEffect(Effect = e) ->
          step (i + 1) (e :: effects)
        | Jmp(Target = JmpDest(Target = l)) ->
          step (at l) effects
        | CJmp(c, JmpDest(Target = t), JmpDest(Target = f)) ->
          let taken = (eval answer regs temps c).IsTrue
          step (at (if taken then t else f)) effects
        | InterJmp _ ->
          List.rev effects
        | stmt ->
          put answer regs temps stmt
          step (i + 1) effects
    let effects = step 0 []
    effects, fun reg -> readReg regs (idOf reg) (Expr.typeOf reg)
