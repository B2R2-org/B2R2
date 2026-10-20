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

namespace B2R2.FrontEnd.PPC.Tests

open System
open System.Collections.Generic
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.PPC

/// <summary>
/// Runs the statements an instruction lifts to over registers given values,
/// for a test whose claim is the value an instruction computes. It knows the
/// integer operations at any width, loads and stores over the bytes a test
/// gives it at the endianness each one names, the jumps between the labels
/// of one instruction, and the straight-line LowUIR of the floating-point
/// arithmetic (IRFloat), rounded the way a RoundCtrl names or, outside one,
/// the way FPSCR[RN] does.
/// Of the named calls it knows the fused multiply-add and the exception
/// query (FEXC64), which IRFloat answers exactly, and the conversions to the
/// half and bfloat16 formats, worked out over exact values. It fails on
/// anything else rather than guess what it means -- a byte nobody gave, a
/// jump out of the instruction and a side effect included.
/// </summary>
module internal IRRunner =
  /// What a run leaves behind.
  type Outcome =
    { /// What each register holds, by its variable.
      Read: Expr -> BitVector
      /// Every byte of memory given or written, by address.
      Memory: IReadOnlyDictionary<uint64, byte>
      /// Every named call made, in order, with its arguments.
      Calls: (string * BitVector list) list }

  /// What a run reads and writes: the registers, the temporaries and the
  /// bytes of memory by address.
  type private Context =
    { Regs: Dictionary<RegisterID, BitVector>
      Temps: Dictionary<int, BitVector>
      Memory: Dictionary<uint64, byte>
      /// What a test answers for a named call IRRunner does not know.
      Answer: string -> BitVector list -> BitVector option
      /// Every named call made, in order, with its arguments.
      Calls: List<string * BitVector list> }

  let private readReg (regs: Dictionary<RegisterID, BitVector>) r t =
    match regs.TryGetValue r with
    | true, v -> v
    | false, _ -> BitVector.Zero t

  /// The register a register variable names; the program counter is a
  /// variable of its own kind and carries no ID, so it is given IAR's.
  let private idOf = function
    | Var(RegisterID = r) -> r
    | PCVar _ -> Register.toRegID Register.IAR
    | e -> failwith $"IRRunner: {e} is not a register"

  /// The bits of a value of at most 64 bits.
  let private bits (v: BitVector) = v.ToUInt64()

  (* Lane X: exact binary floating point, for the named calls the half,
     bfloat16 and quad-precision forms make. A value is decoded to the exact
     number it stands for and rounded once into the format asked for. *)
  /// A binary interchange format, by the widths of its exponent and its
  /// fraction.
  type private BinFormat =
    { ExpBits: int
      FracBits: int }

  /// IEEE binary16.
  let private binary16 = { ExpBits = 5; FracBits = 10 }

  /// bfloat16.
  let private bfloat16 = { ExpBits = 8; FracBits = 7 }

  /// IEEE binary32.
  let private binary32 = { ExpBits = 8; FracBits = 23 }

  /// IEEE binary64.
  let private binary64 = { ExpBits = 11; FracBits = 52 }

  /// A value of a format: a NaN with its fraction, an infinity, or exactly
  /// sign times m times two to the e.
  type private Exact =
    | NaN of nanSign: bool * fraction: bigint
    | Inf of infSign: bool
    | Finite of sign: bool * m: bigint * e: int

  let private biasOf fmt = (1 <<< (fmt.ExpBits - 1)) - 1

  /// The number a format's bits stand for.
  let private decodeAs fmt (bits: bigint) =
    let frac = bits &&& ((1I <<< fmt.FracBits) - 1I)
    let biased = int ((bits >>> fmt.FracBits) &&& ((1I <<< fmt.ExpBits) - 1I))
    let sign = (bits >>> (fmt.ExpBits + fmt.FracBits)) &&& 1I = 1I
    if biased = (1 <<< fmt.ExpBits) - 1 then
      if frac.IsZero then Inf sign else NaN(sign, frac)
    elif biased = 0 then
      Finite(sign, frac, 1 - biasOf fmt - fmt.FracBits)
    else
      let m = frac ||| (1I <<< fmt.FracBits)
      Finite(sign, m, biased - biasOf fmt - fmt.FracBits)

  /// The format a BitVector of a float holds, by its width.
  let private formatOf (x: BitVector) =
    match x.Length with
    | 16<rt> -> binary16
    | 32<rt> -> binary32
    | 64<rt> -> binary64
    | _ -> { ExpBits = 15; FracBits = 112 }

  let private signBits fmt sign =
    if sign then 1I <<< (fmt.ExpBits + fmt.FracBits) else 0I

  let private infBits fmt sign =
    signBits fmt sign ||| (((1I <<< fmt.ExpBits) - 1I) <<< fmt.FracBits)

  /// A NaN carried into a format: quiet, its fraction's top bits kept.
  let private nanBits fmt srcFracBits sign (frac: bigint) =
    let moved =
      if srcFracBits >= fmt.FracBits then frac >>> (srcFracBits - fmt.FracBits)
      else frac <<< (fmt.FracBits - srcFracBits)
    infBits fmt sign ||| moved ||| (1I <<< (fmt.FracBits - 1))

  /// What overflows answers with in a direction: an infinity, or the largest
  /// finite number where the direction rounds toward zero.
  let private overflowBits fmt mode sign =
    match mode, sign with
    | 0, _ | 2, false | 3, true -> infBits fmt sign
    | _ -> infBits fmt sign - 1I

  /// Whether the cut-off part decides an increment, in a direction: 0 to
  /// nearest with ties to even, 1 toward zero, 2 toward +Inf, 3 toward -Inf.
  let private roundsUp mode sign (kept: bigint) (rest: bigint) half =
    match mode with
    | 0 -> rest > half || (rest = half && not rest.IsZero && not kept.IsEven)
    | 2 -> not rest.IsZero && not sign
    | 3 -> not rest.IsZero && sign
    | _ -> false

  /// Encodes a significand already rounded at the quantum exponent q.
  let private encodeRounded fmt mode sign (n: bigint) q =
    let n, q = if n >= (1I <<< (fmt.FracBits + 1)) then n >>> 1, q + 1 else n, q
    let biased =
      if n >= (1I <<< fmt.FracBits) then q + fmt.FracBits + biasOf fmt else 0
    if biased >= (1 <<< fmt.ExpBits) - 1 then
      overflowBits fmt mode sign
    else
      let frac = n &&& ((1I <<< fmt.FracBits) - 1I)
      signBits fmt sign ||| (bigint biased <<< fmt.FracBits) ||| frac

  /// <summary>
  /// sign times m times two to the e rounded once into a format, in a
  /// direction: 0 to nearest with ties to even, 1 toward zero, 2 toward
  /// +Inf, 3 toward -Inf, 4 to odd (truncated, the last bit set where
  /// anything was cut off).
  /// </summary>
  let private roundInto fmt mode sign (m: bigint) e =
    if m.IsZero then
      signBits fmt sign
    else
      let top = int (m.GetBitLength()) - 1 + e
      let q = max top (1 - biasOf fmt) - fmt.FracBits
      let shift = q - e
      if shift <= 0 then
        encodeRounded fmt mode sign (m <<< -shift) q
      else
        let kept = m >>> shift
        let rest = m - (kept <<< shift)
        let half = 1I <<< (shift - 1)
        let n =
          if mode = 4 then (if rest.IsZero then kept else kept ||| 1I)
          elif roundsUp mode sign kept rest half then kept + 1I
          else kept
        encodeRounded fmt mode sign n q

  /// A float converted into a narrower format, rounded in a direction, a
  /// NaN quieted with its fraction's top bits.
  let private narrow fmt (x: BitVector) (mode: BitVector) =
    let src = formatOf x
    let bits =
      match decodeAs src (x.ToBigInt()) with
      | NaN(sign, frac) -> nanBits fmt src.FracBits sign frac
      | Inf sign -> infBits fmt sign
      | Finite(sign, m, e) -> roundInto fmt (int (mode.ToUInt64())) sign m e
    BitVector(bits, 16<rt>)

  /// The named calls the wide and the half-precision forms make, which are
  /// answered over exact values and carry their own direction as an argument.
  let private exactApp (name: string) (args: BitVector list) =
    match name, args with
    | "FCVTHALF", [ x; mode ] ->
      Some(narrow binary16 x mode)
    | "FCVTBF16", [ x; mode ] ->
      Some(narrow bfloat16 x mode)
    | _ ->
      None

  /// The named calls the lifter makes: the fused multiply-add, with bit 0 of
  /// its flags negating the product and bit 1 the addend, and the exception
  /// query of one operation or of a fused multiply-add.
  let private floatApp mode (name: string) args =
    let t = if name.EndsWith "32" then 32<rt> else 64<rt>
    match name, List.map bits args with
    | ("FMA32" | "FMA64"), [ x; y; z; flags ] ->
      Some(BitVector(IRFloat.fma t mode flags x y z, t))
    | ("FEXC32" | "FEXC64"), [ code; a; b ] ->
      Some(BitVector(IRFloat.exceptions t mode code a b, 32<rt>))
    | ("FEXC32" | "FEXC64"), [ 8UL; x; y; z; flags ] ->
      Some(BitVector(IRFloat.fusedExceptions t mode flags x y z, 32<rt>))
    | _ ->
      None

  /// A named call IRRunner knows, or else what the test answers for it.
  let private app ctx mode (name: string) (args: BitVector list) =
    let known = name.StartsWith "FMA" || name.StartsWith "FEXC"
    let value =
      match exactApp name args with
      | Some v -> Some v
      | None when known -> floatApp mode name args
      | None -> ctx.Answer name args
    match value with
    | Some v -> v
    | None -> failwith $"IRRunner: no {name}"

  /// A named call: recorded, then answered.
  let private call ctx mode name args =
    ctx.Calls.Add((name, args))
    app ctx mode name args

  /// The floating-point operation of a BinOpType, if it is one.
  let private floatOp = function
    | BinOpType.FADD -> Some Add
    | BinOpType.FSUB -> Some Sub
    | BinOpType.FMUL -> Some Mul
    | BinOpType.FDIV -> Some Div
    | _ -> None

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
    | RelOpType.FEQ -> BitVector.FEq(a, b)
    | RelOpType.FGT -> BitVector.FGt(a, b)
    | RelOpType.FGE -> BitVector.FGe(a, b)
    | RelOpType.FLT -> BitVector.FLt(a, b)
    | RelOpType.FLE -> BitVector.FLe(a, b)
    | _ -> failwith $"IRRunner: no {op}"

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

  /// The direction FPSCR[RN] names, which is what a rounding no RoundCtrl
  /// encloses rounds in: nearest, toward zero, up, down.
  let private fpscrMode ctx =
    let fpscr = readReg ctx.Regs (Register.toRegID Register.FPSCR) 32<rt>
    match fpscr.ToUInt64() &&& 3UL with
    | 0UL -> RoundingMode.ToNearestEven
    | 1UL -> RoundingMode.TowardZero
    | 2UL -> RoundingMode.TowardPositive
    | _ -> RoundingMode.TowardNegative

  /// A cast in a direction: a conversion between integers and floats, or
  /// between the two float formats, rounds in it.
  let private cast mode kind t (x: BitVector) =
    let src = x.Length
    let convert (f: uint64 -> uint64) = BitVector(f (bits x), t)
    match kind with
    | CastKind.ZeroExt -> BitVector.ZExt(x, t)
    | CastKind.SignExt -> BitVector.SExt(x, t)
    | CastKind.FloatCast -> convert (IRFloat.cast src t mode)
    | CastKind.SIntToFloat -> convert (IRFloat.ofSInt src t mode)
    | CastKind.UIntToFloat -> convert (IRFloat.ofUInt src t mode)
    | CastKind.FloatToSInt -> convert (IRFloat.toSInt src t mode)
    | CastKind.RoundToIntegral -> convert (IRFloat.roundToIntegral t mode)
    | k -> failwith $"IRRunner: no {k}"

  /// An expression's value, a rounding in it going the way the innermost
  /// RoundCtrl around it names, or the given way outside every one.
  let rec private eval ctx mode e =
    let go = eval ctx mode
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
      | ExprList(Elements = args) -> call ctx mode n (List.map go args)
      | _ -> failwith $"IRRunner: no {e}"
    | BinOp(Op = op; Left = l; Right = r) when (floatOp op).IsSome ->
      let t = Expr.typeOf l
      let a, b = bits (go l), bits (go r)
      BitVector(IRFloat.arith t mode (floatOp op).Value a b, t)
    | BinOp(Op = op; Left = l; Right = r) ->
      binOp op (go l) (go r)
    | RelOp(Op = op; Left = l; Right = r) ->
      relOp op (go l) (go r)
    | UnOp(Op = UnOpType.NOT; Operand = x) ->
      BitVector.Not(go x)
    | UnOp(Op = UnOpType.NEG; Operand = x) ->
      BitVector.Neg(go x)
    | UnOp(Op = UnOpType.FSQRT; Operand = x) ->
      let t = Expr.typeOf x
      BitVector(IRFloat.arith t mode Sqrt (bits (go x)) 0UL, t)
    | Load(Endian = endian; Type = t; Addr = a) ->
      load ctx endian t (go a)
    | Cast(Kind = k; Type = t; Operand = x) ->
      cast mode k t (go x)
    | RoundCtrl(Mode = m; Body = body) ->
      eval ctx (enum<RoundingMode> (int (bits (go m)))) body
    | Extract(Operand = x; Type = t; StartPos = p) ->
      BitVector.Extract(go x, t, p)
    | Ite(Cond = c; TrueExpr = a; FalseExpr = b) ->
      if (go c).IsTrue then go a else go b
    | _ ->
      failwith $"IRRunner: no {e}"

  /// The registers and the bytes of memory given, everything else zero for a
  /// register and absent for a byte.
  let private newContext answer inputs (memory: (uint64 * byte[]) list) =
    let ctx =
      { Regs = Dictionary()
        Temps = Dictionary()
        Memory = Dictionary()
        Answer = answer
        Calls = List() }
    for reg, v in inputs do ctx.Regs[idOf reg] <- v
    for addr, bytes in memory do
      bytes |> Array.iteri (fun i b -> ctx.Memory[addr + uint64 i] <- b)
    ctx

  /// Where each label of the statements sits.
  let private labelsOf (stmts: Stmt[]) =
    let at = Dictionary<Label, int>()
    stmts
    |> Array.iteri (fun i stmt ->
      match stmt with
      | LMark(Label = l) -> at[l] <- i
      | _ -> ())
    at

  /// A value written to memory at an address and an endianness.
  let private store ctx endian (addr: BitVector) (v: BitVector) =
    let n = RegType.toByteWidth v.Length
    let a = addr.ToUInt64()
    let num = v.ToBigInt()
    for i in 0 .. n - 1 do
      let shift = if endian = Endian.Big then 8 * (n - 1 - i) else 8 * i
      ctx.Memory[a + uint64 i] <- byte ((num >>> shift) &&& 255I)

  /// One statement that neither jumps nor raises anything.
  let private put ctx stmt =
    match stmt with
    | Put(Dst = Var(RegisterID = r); Src = src) ->
      ctx.Regs[r] <- eval ctx (fpscrMode ctx) src
    | Put(Dst = TempVar(Index = n); Src = src) ->
      ctx.Temps[n] <- eval ctx (fpscrMode ctx) src
    | Store(Endian = endian; Addr = a; Value = v) ->
      let mode = fpscrMode ctx
      store ctx endian (eval ctx mode a) (eval ctx mode v)
    | _ ->
      failwith $"IRRunner: no {stmt}"

  /// Runs one statement and gives the index of the one that runs next.
  let private step ctx (at: Dictionary<Label, int>) stmt next =
    match stmt with
    | ISMark _ | IEMark _ | LMark _ ->
      next
    | Jmp(Target = JmpDest(Target = l)) ->
      at[l]
    | CJmp(Cond = c; TrueTarget = JmpDest(Target = t);
           FalseTarget = JmpDest(Target = f)) ->
      at[if (eval ctx (fpscrMode ctx) c).IsTrue then t else f]
    | _ ->
      put ctx stmt
      next

  /// <summary>
  /// Runs the statements from the first, each jump between their labels
  /// taken the way the values decide it, over the registers given and the
  /// bytes of memory given. A load of a byte nobody gave fails the run. A
  /// named call IRRunner does not know is put to `answer`, which a test
  /// gives to stand in for the evaluator: the run then shows where the
  /// lifter took each call's arguments from and where its answer went.
  /// </summary>
  let execAnswering answer (stmts: Stmt[]) inputs memory =
    let ctx = newContext answer inputs memory
    let at = labelsOf stmts
    let rec go i =
      if i < stmts.Length then go (step ctx at stmts[i] (i + 1)) else ()
    go 0
    { Read = fun reg -> readReg ctx.Regs (idOf reg) (Expr.typeOf reg)
      Memory = ctx.Memory
      Calls = List.ofSeq ctx.Calls }

  /// The same with no named call answered but the ones IRRunner knows.
  let exec stmts inputs memory =
    execAnswering (fun _ _ -> None) stmts inputs memory

  /// What each register holds after the statements ran, starting from the
  /// given values and from zero everywhere else, with no memory at all.
  let run stmts inputs = (exec stmts inputs []).Read
