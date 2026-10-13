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
open B2R2.FrontEnd.MIPS

/// <summary>
/// Runs the statements an instruction lifts to over registers given values,
/// for a test whose claim is the value an instruction computes. It knows the
/// integer operations at any width, loads and stores over the bytes a test
/// gives it at the endianness each one names, and the straight-line LowUIR of
/// the floating-point arithmetic, rounded to nearest unless a RoundCtrl names
/// a direction for a rounding to an integer, and fails on anything else
/// rather than guess what it means -- a byte nobody gave included.
///
/// <para>The exception query answers what a test names, nothing unless it
/// names something: the query works out what an operation raised, which this
/// does not, so a test that reads FCSR reads either what comes from
/// somewhere the query is not asked, such as a flush, or what the lifter
/// made of the answer it was given.</para>
/// </summary>
module internal IRRunner =
  /// What a run reads and writes: the registers, the temporaries, the bytes
  /// of memory by address, and the answer the exception query gives.
  type private Context =
    { Answer: BitVector
      Regs: Dictionary<RegisterID, BitVector>
      Temps: Dictionary<int, BitVector>
      Memory: Dictionary<uint64, byte>
      Unpredictable: HashSet<RegisterID> }

  /// The register a register variable names; the program counter is a
  /// variable of its own kind and carries no ID, so it is given MIPS's.
  let private idOf = function
    | Var(RegisterID = r) -> r
    | PCVar _ -> Register.toRegID Register.PC
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
    | BinOpType.DIV -> BitVector.Div(a, b)
    | BinOpType.SDIV -> BitVector.SDiv(a, b)
    | BinOpType.MOD -> BitVector.Modulo(a, b)
    | BinOpType.SMOD -> BitVector.SModulo(a, b)
    | BinOpType.AND -> BitVector.And(a, b)
    | BinOpType.OR -> BitVector.Or(a, b)
    | BinOpType.XOR -> BitVector.Xor(a, b)
    | BinOpType.SHL -> BitVector.Shl(a, b)
    | BinOpType.SHR -> BitVector.Shr(a, b)
    | BinOpType.SAR -> BitVector.Sar(a, b)
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

  /// A float rounded to an integral float in a direction.
  let private roundIn mode rt x = ofDouble rt (integral mode (toDouble x))

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

  /// The bytes at an address, in address order, every one of them given.
  let private bytesAt (memory: Dictionary<uint64, byte>) (addr: uint64) n =
    Array.init n (fun i ->
      let a = addr + uint64 i
      match memory.TryGetValue a with
      | true, b -> b
      | false, _ -> failwith $"IRRunner: no byte at {a:x}")

  /// A value of a type read from memory at an endianness.
  let private load ctx endian (t: RegType) (addr: BitVector) =
    let bytes = bytesAt ctx.Memory (addr.ToUInt64()) (RegType.toByteWidth t)
    let ordered = if endian = Endian.Big then bytes else Array.rev bytes
    let v = ordered |> Array.fold (fun acc b -> (acc <<< 8) + bigint b) 0I
    BitVector(v, t)

  /// A value written to memory at an address and an endianness.
  let private store ctx endian (addr: BitVector) (v: BitVector) =
    let n = RegType.toByteWidth v.Length
    let a = addr.ToUInt64()
    let num = v.ToBigInt()
    for i in 0 .. n - 1 do
      let shift = if endian = Endian.Big then 8 * (n - 1 - i) else 8 * i
      ctx.Memory[a + uint64 i] <- byte ((num >>> shift) &&& 255I)

  /// The direction FCSR.RM names, which is what a rounding no RoundCtrl
  /// encloses rounds in: nearest, toward zero, up, down.
  let private fcsrMode ctx =
    let fcsr = readReg ctx.Regs (Register.toRegID Register.FCSR) 32<rt>
    match fcsr.ToUInt64() &&& 3UL with
    | 0UL -> RoundingMode.ToNearestEven
    | 1UL -> RoundingMode.TowardZero
    | 2UL -> RoundingMode.TowardPositive
    | _ -> RoundingMode.TowardNegative

  /// A cast of a value to a type, outside a rounding control.
  let private cast ctx kind t (x: BitVector) =
    match kind with
    | CastKind.ZeroExt -> BitVector.ZExt(x, t)
    | CastKind.SignExt -> BitVector.SExt(x, t)
    | CastKind.FloatCast -> BitVector.FCast(x, t)
    | CastKind.SIntToFloat -> BitVector.Itof(x, t, true)
    | CastKind.UIntToFloat -> BitVector.Itof(x, t, false)
    | CastKind.FloatToSInt -> toInt (fcsrMode ctx) t x
    | CastKind.RoundToIntegral -> roundIn (fcsrMode ctx) t x
    | k -> failwith $"IRRunner: no {k}"

  let rec private eval ctx e =
    let eval = eval ctx
    match e with
    | Num(Value = v) ->
      v
    | Var(Type = t; RegisterID = r) ->
      readReg ctx.Regs r t
    | PCVar(Type = t) ->
      readReg ctx.Regs (idOf e) t
    | TempVar(Index = n) ->
      ctx.Temps[n]
    | BinOp(Op = BinOpType.APP; Left = FuncName(Name = n); Right = es) ->
      match es with
      | ExprList(Elements = args) -> app ctx.Answer n (List.map eval args)
      | _ -> failwith $"IRRunner: no {e}"
    | BinOp(Op = op; Left = l; Right = r) ->
      binOp op (eval l) (eval r)
    | RelOp(Op = op; Left = l; Right = r) ->
      relOp op (eval l) (eval r)
    | UnOp(Op = UnOpType.NOT; Operand = x) ->
      BitVector.Not(eval x)
    | UnOp(Op = UnOpType.NEG; Operand = x) ->
      BitVector.Neg(eval x)
    | UnOp(Op = UnOpType.FSQRT; Operand = x) ->
      BitVector.FSqrt(eval x)
    | Load(Endian = endian; Type = t; Addr = a) ->
      load ctx endian t (eval a)
    | Cast(Kind = k; Type = t; Operand = x) ->
      cast ctx k t (eval x)
    | RoundCtrl(Mode = m; Body = Cast(Kind = k; Type = t; Operand = x)) ->
      let mode = enum<RoundingMode> (int ((eval m).ToUInt64()))
      match k with
      | CastKind.RoundToIntegral ->
        roundIn mode t (eval x)
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

  /// One statement that neither jumps nor raises anything. A register given
  /// a value the manual leaves UNPREDICTABLE is recorded as such, since no
  /// value of it can be asked about.
  let private put ctx stmt =
    match stmt with
    | Put(Dst = Var(RegisterID = r); Src = Undefined _) ->
      ctx.Regs.Remove r |> ignore
      ctx.Unpredictable.Add r |> ignore
    | Put(Dst = Var(RegisterID = r); Src = src) ->
      ctx.Regs[r] <- eval ctx src
      ctx.Unpredictable.Remove r |> ignore
    | Put(Dst = PCVar _ as pc; Src = src) ->
      ctx.Regs[idOf pc] <- eval ctx src
    | Put(Dst = TempVar(Index = n); Src = src) ->
      ctx.Temps[n] <- eval ctx src
    | Store(Endian = endian; Addr = a; Value = v) ->
      store ctx endian (eval ctx a) (eval ctx v)
    | _ ->
      failwith $"IRRunner: no {stmt}"

  let private newContext (flags: uint32) inputs =
    let ctx =
      { Answer = BitVector(flags, 32<rt>)
        Regs = Dictionary()
        Temps = Dictionary()
        Memory = Dictionary()
        Unpredictable = HashSet() }
    for reg, v in inputs do ctx.Regs[idOf reg] <- v
    ctx

  /// What each register holds after the statements ran, starting from the
  /// given values and from zero everywhere else, with the exception query
  /// answering the given flags.
  let runAnswering flags stmts inputs =
    let ctx = newContext flags inputs
    for stmt in stmts do
      match stmt with
      | ISMark _ | IEMark _ | LMark _ -> ()
      | _ -> put ctx stmt
    fun reg -> readReg ctx.Regs (idOf reg) (Expr.typeOf reg)

  /// What each register holds after the statements ran, with the exception
  /// query answering that nothing was raised.
  let run stmts inputs = runAnswering 0u stmts inputs

  /// Where a run left the instruction, if it did: the target and the kind
  /// of the jump that took it out.
  type Exit =
    | Fallthrough
    | Left of target: uint64 * kind: InterJmpKind

  /// The end of an instruction, which moves the program counter past it.
  let private advance ctx (n: uint32) =
    let pc = Register.toRegID Register.PC
    match ctx.Regs.TryGetValue pc with
    | true, v ->
      ctx.Regs[pc] <- BitVector.Add(v, BitVector(uint64 n, v.Length))
    | false, _ ->
      ()

  /// The statements run from the first, each jump between their labels taken
  /// the way the values decide it; a jump out of the instruction ends the
  /// run and is the exit.
  let private walk ctx (stmts: Stmt[]) =
    let at label =
      stmts
      |> Array.findIndex (function
        | LMark(Label = l) -> l = label
        | _ -> false)
    let rec step i effects =
      if i >= stmts.Length then
        List.rev effects, Fallthrough
      else
        match stmts[i] with
        | ISMark _ | LMark _ ->
          step (i + 1) effects
        | IEMark(Length = n) ->
          advance ctx n
          step (i + 1) effects
        | SideEffect(Effect = e) ->
          step (i + 1) (e :: effects)
        | Jmp(Target = JmpDest(Target = l)) ->
          step (at l) effects
        | CJmp(c, JmpDest(Target = t), JmpDest(Target = f)) ->
          let taken = (eval ctx c).IsTrue
          step (at (if taken then t else f)) effects
        | InterJmp(Target = t; Kind = kind) ->
          List.rev effects, Left((eval ctx t).ToUInt64(), kind)
        | InterCJmp(Cond = c; TrueTarget = t; FalseTarget = f) ->
          let target = if (eval ctx c).IsTrue then t else f
          let address = (eval ctx target).ToUInt64()
          List.rev effects, Left(address, InterJmpKind.Base)
        | stmt ->
          put ctx stmt
          step (i + 1) effects
    step 0 []

  /// <summary>
  /// The side effects the statements raise and what each register holds
  /// after them, taking each jump between their labels the way the given
  /// values decide it: for a test whose claim is which way an instruction
  /// goes. A jump out of the instruction ends the run.
  /// </summary>
  let follow (stmts: Stmt[]) inputs =
    let ctx = newContext 0u inputs
    let effects, _ = walk ctx stmts
    effects, fun reg -> readReg ctx.Regs (idOf reg) (Expr.typeOf reg)

  /// <summary>
  /// The jump out of the instruction the statements reach, as its target and
  /// its kind, taking each jump on the way, and a conditional one out of the
  /// instruction too, the way the given values decide it; and what each
  /// register holds by then: for a test whose claim is where an instruction
  /// goes. Statements that run to their end reach none.
  /// </summary>
  let leave (stmts: Stmt[]) inputs =
    let ctx = newContext 0u inputs
    let exit =
      match walk ctx stmts with
      | _, Left(target, kind) -> Some(target, kind)
      | _, Fallthrough -> None
    exit, fun reg -> readReg ctx.Regs (idOf reg) (Expr.typeOf reg)

  /// What a run of whole instructions leaves behind.
  type Outcome =
    { /// The side effects raised, in order.
      Effects: SideEffect list
      /// Where the run left, if it did.
      Exit: Exit
      /// The registers by ID, as they are after the run.
      Registers: IReadOnlyDictionary<RegisterID, BitVector>
      /// The registers given a value the manual leaves UNPREDICTABLE.
      Unpredictable: IReadOnlySet<RegisterID>
      /// Every byte of memory given or written, by address.
      Memory: IReadOnlyDictionary<uint64, byte> }

  /// <summary>
  /// Runs the statements of whole instructions, as follow does, over the
  /// registers given and the bytes of memory given, with the exception query
  /// answering that nothing was raised. A load of a byte nobody gave fails
  /// the run.
  /// </summary>
  let exec (stmts: Stmt[]) inputs (memory: (uint64 * byte) list) =
    let ctx = newContext 0u inputs
    for addr, b in memory do ctx.Memory[addr] <- b
    let effects, exit = walk ctx stmts
    { Effects = effects
      Exit = exit
      Registers = ctx.Regs
      Unpredictable = ctx.Unpredictable
      Memory = ctx.Memory }
