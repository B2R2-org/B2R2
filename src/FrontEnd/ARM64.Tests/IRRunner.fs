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

/// What the statements of an instruction left behind: what each register
/// holds, what each byte of memory holds, and the side effects reached.
type internal IROutcome =
  { Read: Expr -> BitVector
    Byte: uint64 -> byte option
    Effects: SideEffect list }

/// <summary>
/// Runs the statements an instruction lifts to over registers and memory
/// given values, for a test whose claim is the value an instruction
/// computes. It knows the integer LowUIR, the loads and stores of a byte
/// memory, the floating-point LowUIR of singles and doubles IRFloat knows,
/// a RoundCtrl naming the direction its body rounds in (FPCR.RMode's outside
/// one), the jumps inside one instruction, a jump out of it, which sets PC
/// and ends the run, and a side effect, which ends it too, as the exception
/// it stands for would. It fails on anything else -- a load from a byte no
/// one gave a value, a named call it does not know -- rather than guess what
/// it means.
/// </summary>
module internal IRRunner =
  let private regID r = B2R2.FrontEnd.ARM64.Register.toRegID r

  let private pcID = regID B2R2.FrontEnd.ARM64.Register.PC

  /// The register a register variable names.
  let private idOf = function
    | Var(RegisterID = r) -> r
    | PCVar _ -> pcID
    | e -> failwith $"IRRunner: {e} is not a register"

  /// The registers, temporaries and memory the statements run over.
  type private Machine =
    { Regs: Dictionary<RegisterID, BitVector>
      Temps: Dictionary<int, BitVector>
      Memory: Dictionary<uint64, byte> }

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

  let private bits (v: BitVector) = v.ToUInt64()

  let private floatOp = function
    | BinOpType.FADD -> Some Add
    | BinOpType.FSUB -> Some Sub
    | BinOpType.FMUL -> Some Mul
    | BinOpType.FDIV -> Some Div
    | _ -> None

  let private isFloatRel = function
    | RelOpType.FEQ | RelOpType.FNEQ | RelOpType.FGT | RelOpType.FGE
    | RelOpType.FLT | RelOpType.FLE -> true
    | _ -> false

  /// The value the bytes at an address hold, little-endian.
  let private load (mem: Dictionary<uint64, byte>) (t: RegType) addr =
    let read i =
      let at = addr + uint64 i
      match mem.TryGetValue at with
      | true, b -> b
      | false, _ -> failwith $"IRRunner: no memory at 0x{at:x}"
    BitVector(Array.init (int t / 8) read)

  /// The named calls the lifter makes: the exception query, in its form for
  /// one operation and for a fused multiply-add, and the fused multiply-add.
  let private app mode (name: string) (args: BitVector list) =
    let t = if name.EndsWith "32" then 32<rt> else 64<rt>
    let narrow = args |> List.forall (fun a -> a.Length <= 64<rt>)
    match name, (if narrow then List.map bits args else []) with
    | ("FEXC32" | "FEXC64"), [ code; a; b ] ->
      BitVector(IRFloat.exceptions t mode code a b, 32<rt>)
    | ("FEXC32" | "FEXC64"), [ 8UL; x; y; z; flags ] ->
      BitVector(IRFloat.fusedExceptions t mode flags x y z, 32<rt>)
    | ("FMA32" | "FMA64"), [ x; y; z; flags ] ->
      BitVector(IRFloat.fma t mode flags x y z, t)
    | _ ->
      failwith $"IRRunner: no {name}"

  /// A cast that converts between integers and floats.
  let private convert mode kind t src (v: BitVector) =
    let r =
      match kind with
      | CastKind.SIntToFloat -> IRFloat.ofSInt src t mode (bits v)
      | CastKind.UIntToFloat -> IRFloat.ofUInt src t mode (bits v)
      | CastKind.FloatToSInt -> IRFloat.toSInt src t mode (bits v)
      | CastKind.FloatCast -> IRFloat.cast src t mode (bits v)
      | CastKind.RoundToIntegral -> IRFloat.roundToIntegral t mode (bits v)
      | k -> failwith $"IRRunner: no {k}"
    BitVector(r, t)

  let rec private eval m mode e =
    let go = eval m mode
    match e with
    | Num(Value = v) ->
      v
    | Var(Type = t; RegisterID = r) ->
      readReg m.Regs r t
    | PCVar(Type = t) ->
      readReg m.Regs pcID t
    | TempVar(Index = n) ->
      m.Temps[n]
    | Load(Type = t; Addr = a) ->
      load m.Memory t (bits (go a))
    | BinOp(Op = BinOpType.APP; Left = FuncName(Name = n); Right = es) ->
      evalApp m mode n es
    | BinOp(Op = op; Left = l; Right = r) when (floatOp op).IsSome ->
      let a, b = bits (go l), bits (go r)
      let t = Expr.typeOf l
      BitVector(IRFloat.arith t mode (floatOp op).Value a b, t)
    | BinOp(Op = op; Left = l; Right = r) ->
      binOp op (go l) (go r)
    | RelOp(Op = op; Left = l; Right = r) when isFloatRel op ->
      let a, b = bits (go l), bits (go r)
      if IRFloat.relation op (Expr.typeOf l) a b then BitVector.T
      else BitVector.F
    | RelOp(Op = op; Left = l; Right = r) ->
      relOp op (go l) (go r)
    | UnOp(Op = UnOpType.NEG; Operand = x) ->
      BitVector.Neg(go x)
    | UnOp(Op = UnOpType.NOT; Operand = x) ->
      BitVector.Not(go x)
    | UnOp(Op = UnOpType.FSQRT; Operand = x) ->
      let t = Expr.typeOf x
      BitVector(IRFloat.arith t mode Sqrt (bits (go x)) 0UL, t)
    | Cast(Kind = CastKind.ZeroExt; Type = t; Operand = x) ->
      BitVector.ZExt(go x, t)
    | Cast(Kind = CastKind.SignExt; Type = t; Operand = x) ->
      BitVector.SExt(go x, t)
    | Cast(Kind = kind; Type = t; Operand = x) ->
      convert mode kind t (Expr.typeOf x) (go x)
    | Extract(Operand = x; Type = t; StartPos = p) ->
      BitVector.Extract(go x, t, p)
    | Ite(Cond = c; TrueExpr = a; FalseExpr = b) ->
      if (go c).IsTrue then go a else go b
    | RoundCtrl(Mode = md; Body = body) ->
      let named = enum<RoundingMode> (int (bits (go md)))
      eval m named body
    | _ ->
      failwith $"IRRunner: no {e}"

  and private evalApp m mode name es =
    match es with
    | ExprList(Elements = args) -> app mode name (List.map (eval m mode) args)
    | e -> failwith $"IRRunner: no {name} of {e}"

  /// The bytes a value is, little-endian.
  let private bytesOf (v: BitVector) =
    let n = int v.Length / 8
    if n <= 8 then
      Array.init n (fun i -> byte (bits v >>> (8 * i)))
    else
      let raw = v.ToBigInt().ToByteArray()
      Array.init n (fun i -> if i < raw.Length then raw[i] else 0uy)

  let private store (mem: Dictionary<uint64, byte>) addr (v: BitVector) =
    bytesOf v |> Array.iteri (fun i b -> mem[addr + uint64 i] <- b)

  /// The labels of the statements, by where each one sits.
  let private labelsOf (stmts: Stmt[]) =
    let at = Dictionary<Label, int>()
    stmts
    |> Array.iteri (fun i stmt ->
      match stmt with
      | LMark(Label = l) -> at[l] <- i
      | _ -> ())
    at

  /// The machine the inputs describe, from zero everywhere else, and with
  /// no memory but the given bytes.
  let private machineOf inputs (memory: (uint64 * byte[]) list) =
    let m =
      { Regs = Dictionary()
        Temps = Dictionary()
        Memory = Dictionary() }
    for reg, v in inputs do m.Regs[idOf reg] <- v
    for addr, bytes in memory do
      bytes |> Array.iteri (fun i b -> m.Memory[addr + uint64 i] <- b)
    m

  /// The direction FPCR.RMode names, which is in force outside a RoundCtrl.
  let private fpcrMode (regs: Dictionary<RegisterID, BitVector>) =
    let fpcr = readReg regs (regID B2R2.FrontEnd.ARM64.Register.FPCR) 64<rt>
    match (bits fpcr >>> 22) &&& 3UL with
    | 0UL -> RoundingMode.ToNearestEven
    | 1UL -> RoundingMode.TowardPositive
    | 2UL -> RoundingMode.TowardNegative
    | _ -> RoundingMode.TowardZero

  /// Where a run that left the instruction goes on: past every statement.
  let private gone = System.Int32.MaxValue

  /// Runs one statement and gives the index of the next one.
  let private step m (at: Dictionary<Label, int>) found stmt next =
    let eval = eval m (fpcrMode m.Regs)
    match stmt with
    | ISMark _ | IEMark _ | LMark _ ->
      next
    | Put(Dst = Var(RegisterID = r); Src = src) ->
      m.Regs[r] <- eval src
      next
    | Put(Dst = TempVar(Index = n); Src = src) ->
      m.Temps[n] <- eval src
      next
    | Store(Addr = a; Value = v) ->
      store m.Memory (bits (eval a)) (eval v)
      next
    | Jmp(Target = JmpDest(Target = l)) ->
      at[l]
    | CJmp(Cond = c; TrueTarget = JmpDest(Target = t);
           FalseTarget = JmpDest(Target = f)) ->
      at[if (eval c).IsTrue then t else f]
    | InterJmp(Target = t) ->
      m.Regs[pcID] <- eval t
      gone
    | InterCJmp(Cond = c; TrueTarget = t; FalseTarget = f) ->
      m.Regs[pcID] <- eval (if (eval c).IsTrue then t else f)
      gone
    | SideEffect(Effect = e) ->
      (found: ResizeArray<SideEffect>).Add e
      gone
    | _ ->
      failwith $"IRRunner: no {stmt}"

  /// What a byte of memory holds, if anything does.
  let private byteAt (mem: Dictionary<uint64, byte>) addr =
    match mem.TryGetValue addr with
    | true, b -> Some b
    | false, _ -> None

  /// Runs the statements from the given register values and memory bytes.
  let execute (stmts: Stmt[]) inputs memory =
    let m = machineOf inputs memory
    let at = labelsOf stmts
    let found = ResizeArray()
    let mutable pc = 0
    while pc < stmts.Length do
      pc <- step m at found stmts[pc] (pc + 1)
    { Read = fun reg -> readReg m.Regs (idOf reg) (Expr.typeOf reg)
      Byte = byteAt m.Memory
      Effects = List.ofSeq found }

  /// What each register holds after the statements ran over the given
  /// register values, from zero everywhere else.
  let run stmts inputs = (execute stmts inputs []).Read

  /// The side effect the statements reach, if any.
  let effects stmts inputs = (execute stmts inputs []).Effects
