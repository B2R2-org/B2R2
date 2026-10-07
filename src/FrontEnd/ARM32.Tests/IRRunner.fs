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

namespace B2R2.FrontEnd.ARM32.Tests

open System
open System.Collections.Generic
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR

/// <summary>
/// Runs the statements an instruction lifts to over registers given values,
/// for a test whose claim is the value an instruction computes. It knows the
/// integer LowUIR a lane of SIMD arithmetic lifts to, the floating-point
/// LowUIR of singles and doubles rounded to nearest, and the jumps an
/// instruction makes inside itself, and fails on anything else rather than
/// guess what it means.
///
/// <para>A RoundCtrl that names another direction is run only around a
/// rounding to an integral value, a conversion to an integer, or one from an
/// integer, which is where the lifters name one. The exception query answers
/// that nothing was raised: a test reads the value an operation computes,
/// which the query does not decide, or FPSCR where a flag comes from
/// somewhere the query is not asked, such as a flush or a NaN.</para>
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
    | BinOpType.MUL -> BitVector.Mul(a, b)
    | BinOpType.AND -> BitVector.And(a, b)
    | BinOpType.OR -> BitVector.Or(a, b)
    | BinOpType.XOR -> BitVector.Xor(a, b)
    | BinOpType.SHL -> BitVector.Shl(a, b)
    | BinOpType.SHR -> BitVector.Shr(a, b)
    | BinOpType.SAR -> BitVector.Sar(a, b)
    | BinOpType.CONCAT -> BitVector.Concat(a, b)
    | BinOpType.DIV -> BitVector.Div(a, b)
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
    | RelOpType.SGE -> BitVector.SGe(a, b)
    | RelOpType.SLT -> BitVector.SLt(a, b)
    | RelOpType.SLE -> BitVector.SLe(a, b)
    | RelOpType.FEQ -> BitVector.FEq(a, b)
    | RelOpType.FGT -> BitVector.FGt(a, b)
    | RelOpType.FGE -> BitVector.FGe(a, b)
    | RelOpType.FLT -> BitVector.FLt(a, b)
    | RelOpType.FLE -> BitVector.FLe(a, b)
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
      let bits = BitConverter.SingleToUInt32Bits(float32 d)
      BitVector(uint64 bits, 32<rt>)
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

  /// An integer of at most 53 bits, which a double holds exactly, rounded
  /// into a single in a direction of the RoundingMode encoding.
  let private intToSingle mode (v: int64) =
    let d = float v
    let f = float32 d
    let up = if float f >= d then f else MathF.BitIncrement(f)
    let down = if float f <= d then f else MathF.BitDecrement(f)
    match mode with
    | RoundingMode.TowardPositive -> up
    | RoundingMode.TowardNegative -> down
    | RoundingMode.TowardZero -> if d >= 0.0 then down else up
    | _ -> f

  /// A conversion from a 64-bit integer to a single or a double.
  let private intToFloat mode rt (x: BitVector) =
    let v = int64 (x.ToUInt64())
    if rt = 32<rt> then
      let bits = BitConverter.SingleToUInt32Bits(intToSingle mode v)
      BitVector(uint64 bits, 32<rt>)
    else
      BitVector(BitConverter.DoubleToUInt64Bits(float v), 64<rt>)

  /// The named calls the lifters make: the fused multiply-add, with bit 0 of
  /// its flags negating the product and bit 1 the addend, and the exception
  /// query, which answers that nothing was raised.
  let private app name (args: BitVector list) =
    match name, args with
    | ("FEXC32" | "FEXC64"), _ ->
      BitVector.Zero 32<rt>
    | ("FMA32" | "FMA64"), [ x; y; z; flags ] ->
      let f = flags.ToUInt64()
      let product = if f &&& 1UL = 0UL then toDouble x else -(toDouble x)
      let addend = if f &&& 2UL = 0UL then toDouble z else -(toDouble z)
      let y = toDouble y
      if x.Length = 32<rt> then
        let p, m, a = float32 product, float32 y, float32 addend
        let r = MathF.FusedMultiplyAdd(p, m, a)
        BitVector(uint64 (BitConverter.SingleToUInt32Bits(r)), 32<rt>)
      else
        let r = Math.FusedMultiplyAdd(product, y, addend)
        BitVector(BitConverter.DoubleToUInt64Bits(r), 64<rt>)
    | _ ->
      failwith $"IRRunner: no {name}"

  let rec private eval regs (temps: Dictionary<int, BitVector>) e =
    let eval = eval regs temps
    match e with
    | BinOp(Op = BinOpType.APP; Left = FuncName(Name = n); Right = es) ->
      match es with
      | ExprList(Elements = args) -> app n (List.map eval args)
      | _ -> failwith $"IRRunner: no {e}"
    | UnOp(Op = UnOpType.FSQRT; Operand = x) ->
      BitVector.FSqrt(eval x)
    | Cast(Kind = CastKind.FloatCast; Type = t; Operand = x) ->
      BitVector.FCast(eval x, t)
    | RoundCtrl(Mode = m; Body = body) ->
      let mode = enum<RoundingMode> (int ((eval m).ToUInt64()))
      directed regs temps mode body
    | Num(Value = v) ->
      v
    | Var(Type = t; RegisterID = r) ->
      readReg regs r t
    | TempVar(Index = n) ->
      temps[n]
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
    | Cast(Kind = CastKind.SIntToFloat; Type = t; Operand = x) ->
      intToFloat RoundingMode.ToNearestEven t (eval x)
    | Cast(Kind = CastKind.RoundToIntegral; Type = t; Operand = x) ->
      ofDouble t (integral RoundingMode.ToNearestEven (toDouble (eval x)))
    | Extract(Operand = x; Type = t; StartPos = p) ->
      BitVector.Extract(eval x, t, p)
    | Ite(Cond = c; TrueExpr = a; FalseExpr = b) ->
      if (eval c).IsTrue then eval a else eval b
    | _ ->
      failwith $"IRRunner: no {e}"

  and private directed regs temps mode body =
    let eval = eval regs temps
    match body with
    | _ when mode = RoundingMode.ToNearestEven ->
      eval body
    | Cast(Kind = CastKind.RoundToIntegral; Type = t; Operand = x) ->
      ofDouble t (integral mode (toDouble (eval x)))
    | Cast(Kind = CastKind.FloatToSInt; Type = t; Operand = x) ->
      let v = int64 (integral mode (toDouble (eval x)))
      BitVector.Cast(BitVector(uint64 v, 64<rt>), t)
    | Cast(Kind = CastKind.SIntToFloat; Type = t; Operand = x) ->
      intToFloat mode t (eval x)
    | _ ->
      failwith $"IRRunner: no {mode} {body}"

  /// Where each label of an instruction's statements is.
  let private labelsOf (stmts: Stmt[]) =
    let at = Dictionary<Label, int>()
    stmts
    |> Array.iteri (fun i stmt ->
      match stmt with
      | LMark(Label = l) -> at[l] <- i
      | _ -> ())
    at

  /// The statement a jump goes to.
  let private target (at: Dictionary<Label, int>) = function
    | JmpDest(Target = l) -> at[l]
    | e -> failwith $"IRRunner: no jump to {e}"

  /// <summary>
  /// What each register holds after the statements ran, starting from the
  /// given values and from zero everywhere else. A jump inside the
  /// instruction goes to its label; one out of it is not followed.
  /// </summary>
  let run (stmts: Stmt[]) (inputs: (Expr * BitVector) list) =
    let regs = Dictionary<RegisterID, BitVector>()
    let temps = Dictionary<int, BitVector>()
    let at = labelsOf stmts
    for reg, v in inputs do regs[idOf reg] <- v
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
      | Jmp(Target = t) ->
        pc <- target at t
      | CJmp(Cond = c; TrueTarget = t; FalseTarget = f) ->
        pc <- target at (if (eval regs temps c).IsTrue then t else f)
      | InterJmp _ ->
        pc <- stmts.Length
      | _ ->
        failwith $"IRRunner: no {stmt}"
    fun reg -> readReg regs (idOf reg) (Expr.typeOf reg)
