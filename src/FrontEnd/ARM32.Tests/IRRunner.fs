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
/// LowUIR of singles and doubles, loads and stores over memory given as
/// bytes, and the jumps an instruction makes inside itself; a jump out of it
/// or an exception it takes ends the run. It fails on anything else rather
/// than guess what it means.
///
/// <para>A RoundCtrl that names another direction is run around a rounding
/// to an integral value, a conversion to an integer or from one, and the
/// arithmetic of finite singles and doubles, which ExactFloat does exactly
/// and rounds once. The exception query is answered the same way: what the
/// operation raised, with tininess decided before rounding.</para>
/// </summary>
module internal IRRunner =
  /// What a run reads and writes: the registers, the temporaries, the value
  /// the program counter reads as, if given, and memory, a byte an address;
  /// and how it ended, by a jump out of the instruction or at an exception.
  type private Machine =
    { Regs: Dictionary<RegisterID, BitVector>
      Temps: Dictionary<int, BitVector>
      PC: BitVector option
      Memory: Dictionary<uint64, byte>
      mutable Jump: Expr option
      mutable Effect: SideEffect option }

  /// The register a register variable names.
  let private idOf = function
    | Var(RegisterID = r) -> r
    | e -> failwith $"IRRunner: {e} is not a register"

  let private readReg (regs: Dictionary<RegisterID, BitVector>) r t =
    match regs.TryGetValue r with
    | true, v -> v
    | false, _ -> BitVector.Zero t

  /// The value the program counter reads as, which a run has to be given.
  let private readPC m =
    match m.PC with
    | Some v -> v
    | None -> failwith "IRRunner: no value for PC"

  /// The bytes of an access between address order and the order of a
  /// value's bytes, lowest first: the same order for a little-endian access.
  let private inOrder endian (bytes: byte[]) =
    if endian = Endian.Little then bytes else Array.rev bytes

  /// The address of the byte i of an access, which memory has to hold: a
  /// test gives a run every byte it reads or writes.
  let private byteAddr m (addr: BitVector) i =
    let a = addr.ToUInt64() + uint64 i
    if m.Memory.ContainsKey a then a
    else failwith $"IRRunner: no byte at 0x{a:x}"

  /// A load from memory.
  let private load m endian t addr =
    Array.init (RegType.toByteWidth t) (fun i -> m.Memory[byteAddr m addr i])
    |> inOrder endian
    |> BitVector

  /// A store to memory.
  let private store m endian addr (v: BitVector) =
    let width = RegType.toByteWidth v.Length
    let raw = v.ToBigInt().ToByteArray()
    let bytes =
      Array.init width (fun i -> if i < raw.Length then raw[i] else 0uy)
      |> inOrder endian
    for i in 0 .. width - 1 do m.Memory[byteAddr m addr i] <- bytes[i]

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
    | BinOpType.SDIV -> BitVector.SDiv(a, b)
    | BinOpType.MOD -> BitVector.Modulo(a, b)
    | BinOpType.SMOD -> BitVector.SModulo(a, b)
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

  /// GF(2^8) multiplication modulo the AES polynomial.
  let rec private gfMul (a: int) (b: int) =
    if b = 0 then
      0
    else
      let rest = gfMul ((a <<< 1) ^^^ (if a &&& 0x80 <> 0 then 0x11b else 0))
      (if b &&& 1 <> 0 then a else 0) ^^^ rest (b >>> 1)

  /// The AES S-box from its definition: the inverse in GF(2^8), zero for
  /// zero, through the affine map.
  let private sbox =
    let inverse a =
      if a = 0 then 0 else Seq.find (fun b -> gfMul a b = 1) [ 1 .. 255 ]
    let rotl (b: int) n = ((b <<< n) ||| (b >>> (8 - n))) &&& 0xff
    Array.init 256 (fun a ->
      let b = inverse a
      b ^^^ rotl b 1 ^^^ rotl b 2 ^^^ rotl b 3 ^^^ rotl b 4 ^^^ 0x63)

  let private invSbox =
    let inv = Array.zeroCreate 256
    sbox |> Array.iteri (fun a s -> inv[s] <- a)
    inv

  /// The sixteen bytes of an AES state, byte 0 lowest, row r of column c
  /// being byte r + 4c.
  let private stateOf (v: BitVector) =
    let raw = v.ToBigInt().ToByteArray()
    Array.init 16 (fun i -> if i < raw.Length then int raw[i] else 0)

  let private ofState (bytes: int[]) =
    BitVector(Array.map byte bytes)

  let private shiftRows (s: int[]) =
    Array.init 16 (fun i -> s[i % 4 + 4 * ((i / 4 + i % 4) % 4)])

  let private invShiftRows (s: int[]) =
    Array.init 16 (fun i -> s[i % 4 + 4 * ((i / 4 + 4 - i % 4) % 4)])

  /// Each column times a circulant matrix whose first row is given.
  let private mixWith (row: int[]) (s: int[]) =
    Array.init 16 (fun i ->
      let c, r = i / 4, i % 4
      let term k = gfMul row[(k - r + 4) % 4] s[4 * c + k]
      term 0 ^^^ term 1 ^^^ term 2 ^^^ term 3)

  /// The x86 AES operations the lifters name, of a state and a round key.
  let private aes name (args: BitVector list) =
    let key k s = Array.map2 (^^^) s (stateOf k)
    match name, args with
    | "AESENC", [ s; k ] ->
      stateOf s |> shiftRows |> Array.map (fun b -> sbox[b])
      |> mixWith [| 2; 3; 1; 1 |] |> key k |> ofState
    | "AESENCLAST", [ s; k ] ->
      stateOf s |> shiftRows |> Array.map (fun b -> sbox[b]) |> key k
      |> ofState
    | "AESDECLAST", [ s; k ] ->
      stateOf s |> invShiftRows |> Array.map (fun b -> invSbox[b]) |> key k
      |> ofState
    | "AESIMC", [ s ] ->
      stateOf s |> mixWith [| 14; 11; 13; 9 |] |> ofState
    | _ ->
      failwith $"IRRunner: no {name}"

  /// The exception query: the flags, in FPSCR's order, of what an
  /// operation raised. It has to be asked for tininess before rounding and
  /// for that order (0xC0), which is how the lifters ask.
  let private raised mode (args: BitVector list) =
    let asked (arm: BitVector) = arm.ToUInt64() &&& 0xC0UL = 0xC0UL
    let flags =
      match args with
      | [ code; x; y; z; arm ] when code.ToUInt64() = 8UL && asked arm ->
        ExactFloat.fusedRaised mode x y z
      | [ code; a; b ] when asked code ->
        ExactFloat.raised mode (int (code.ToUInt64() &&& 0xfUL)) a b
      | _ ->
        failwith $"IRRunner: no exception query {args}"
    BitVector(flags, 32<rt>)

  /// The named calls the lifters make: the exception query, the fused
  /// multiply-add, with bit 0 of its flags negating the product and bit 1
  /// the addend, rounded to nearest, and the AES operations.
  let private app mode name (args: BitVector list) =
    match name, args with
    | ("FEXC32" | "FEXC64"), _ ->
      raised mode args
    | ("FMA32" | "FMA64"), [ x; y; z; flags ]
      when mode = RoundingMode.ToNearestEven ->
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
    | ("AESENC" | "AESENCLAST" | "AESDECLAST" | "AESIMC"), _ ->
      aes name args
    | _ ->
      failwith $"IRRunner: no {name} rounding {mode}"

  let rec private eval m e =
    let eval = eval m
    match e with
    | BinOp(Op = BinOpType.APP; Left = FuncName(Name = n); Right = es) ->
      match es with
      | ExprList(Elements = args) ->
        app RoundingMode.ToNearestEven n (List.map eval args)
      | _ ->
        failwith $"IRRunner: no {e}"
    | UnOp(Op = UnOpType.FSQRT; Operand = x) ->
      BitVector.FSqrt(eval x)
    | Cast(Kind = CastKind.FloatCast; Type = t; Operand = x) ->
      BitVector.FCast(eval x, t)
    | RoundCtrl(Mode = mode; Body = body) ->
      let mode = enum<RoundingMode> (int ((eval mode).ToUInt64()))
      directed m mode body
    | Num(Value = v) ->
      v
    | Var(Type = t; RegisterID = r) ->
      readReg m.Regs r t
    | PCVar _ ->
      readPC m
    | TempVar(Index = n) ->
      m.Temps[n]
    | Load(Endian = endian; Type = t; Addr = addr) ->
      load m endian t (eval addr)
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

  and private directed m mode body =
    let eval = eval m
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
    | BinOp(Op = BinOpType.APP; Left = FuncName(Name = n); Right = es) ->
      match es with
      | ExprList(Elements = args) -> app mode n (List.map eval args)
      | _ -> failwith $"IRRunner: no {body}"
    | BinOp(Op = BinOpType.FADD | BinOpType.FSUB | BinOpType.FMUL
                 | BinOpType.FDIV as op; Left = l; Right = r) ->
      let a, b = eval l, eval r
      match ExactFloat.arith mode op a b with
      | Some v -> v
      | None -> binOp op a b
    | UnOp(Op = UnOpType.FSQRT; Operand = x) ->
      let a = eval x
      match ExactFloat.sqrt mode a with
      | Some v -> v
      | None -> BitVector.FSqrt a
    | _ ->
      failwith $"IRRunner: no {mode} {body}"

  /// A machine holding the given values, PC's among them if it is given, and
  /// the given memory.
  let private machineOf inputs memory =
    let regs = Dictionary<RegisterID, BitVector>()
    for reg, v in inputs do
      match reg with
      | PCVar _ -> ()
      | _ -> regs[idOf reg] <- v
    let pc =
      inputs
      |> List.tryPick (function
        | PCVar _, v -> Some v
        | _ -> None)
    { Regs = regs
      Temps = Dictionary()
      PC = pc
      Memory = memory
      Jump = None
      Effect = None }

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

  /// Whether a side effect is an exception the instruction takes, after
  /// which nothing of it runs.
  let private isException = function
    | SideEffect.UndefinedInstruction
    | SideEffect.UnsupportedInstruction
    | SideEffect.Breakpoint
    | SideEffect.SysCall
    | SideEffect.Interrupt _
    | SideEffect.Exception _ -> true
    | _ -> false

  /// Runs one statement and answers the index of the one to run next.
  let private step m (at: Dictionary<Label, int>) next stmt =
    match stmt with
    | ISMark _ | IEMark _ | LMark _ ->
      next
    | Put(Dst = Var(RegisterID = r); Src = src) ->
      m.Regs[r] <- eval m src
      next
    | Put(Dst = TempVar(Index = n); Src = src) ->
      m.Temps[n] <- eval m src
      next
    | Store(Endian = endian; Addr = addr; Value = v) ->
      store m endian (eval m addr) (eval m v)
      next
    | Jmp(Target = t) ->
      target at t
    | CJmp(Cond = c; TrueTarget = t; FalseTarget = f) ->
      target at (if (eval m c).IsTrue then t else f)
    | InterJmp(Target = t) ->
      m.Jump <- Some t
      Int32.MaxValue
    | SideEffect(Effect = e) when isException e ->
      m.Effect <- Some e
      Int32.MaxValue
    | _ ->
      failwith $"IRRunner: no {stmt}"

  /// The machine the statements leave, run from the given values.
  let private runMachine (stmts: Stmt[]) inputs memory =
    let m = machineOf inputs memory
    let at = labelsOf stmts
    let mutable pc = 0
    while pc < stmts.Length do pc <- step m at (pc + 1) stmts[pc]
    m

  /// What a register holds in a machine.
  let private reader m reg = readReg m.Regs (idOf reg) (Expr.typeOf reg)

  /// <summary>
  /// What each register holds after the statements ran, starting from the
  /// given values and from zero everywhere else, over memory given as its
  /// bytes by address, which a store changes in place. PC reads as the value
  /// given for it. A jump inside the instruction goes to its label; one out
  /// of it, or an exception the instruction takes, ends the run.
  /// </summary>
  let runOn (stmts: Stmt[]) inputs (memory: Dictionary<uint64, byte>) =
    runMachine stmts inputs memory |> reader

  /// <summary>
  /// What runOn answers, where the instruction jumped out to, if it did, and
  /// the exception it took, if it took one.
  /// </summary>
  let runToEnd (stmts: Stmt[]) inputs (memory: Dictionary<uint64, byte>) =
    let m = runMachine stmts inputs memory
    struct (reader m, Option.map (eval m) m.Jump, m.Effect)

  /// <summary>
  /// What each register holds after the statements ran, starting from the
  /// given values and from zero everywhere else, with no memory to reach.
  /// </summary>
  let run (stmts: Stmt[]) (inputs: (Expr * BitVector) list) =
    runOn stmts inputs (Dictionary())
