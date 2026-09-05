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

/// Provides several utility functions for lifting binary code to IR.
module B2R2.FrontEnd.BinLifter.LiftingUtils

open B2R2
open B2R2.BinIR.LowUIR

/// Creates a new number expression from a given uint32 value.
let inline numU32 n t = BitVector(u32 = n, bitLen = t) |> AST.num

/// Creates a new number expression from a given int32 value.
let inline numI32 n t = BitVector(i32 = n, bitLen = t) |> AST.num

/// Creates a new number expression from a given uint64 value.
let inline numU64 n t = BitVector(u64 = n, bitLen = t) |> AST.num

/// Creates a new number expression from a given int64 value.
let inline numI64 n t = BitVector(i64 = n, bitLen = t) |> AST.num

/// Creates a new temporary variable with the given type.
let inline tmpVar (builder: ILowUIRBuilder) rt = builder.Stream.NewTempVar rt

/// Creates two new temporary variables with the given type.
let inline tmpVars2 (builder: ILowUIRBuilder) rt =
  struct (tmpVar builder rt, tmpVar builder rt)

/// Creates three new temporary variables with the given type.
let inline tmpVars3 (builder: ILowUIRBuilder) rt =
  struct (tmpVar builder rt, tmpVar builder rt, tmpVar builder rt)

/// Creates four new temporary variables with the given type.
let inline tmpVars4 (builder: ILowUIRBuilder) rt =
  let struct (t1, t2) = tmpVars2 builder rt
  let struct (t3, t4) = tmpVars2 builder rt
  struct (t1, t2, t3, t4)

/// Creates a new label with the given name.
let inline label (builder: ILowUIRBuilder) name = builder.Stream.NewLabel name

/// Creates a new register variable with the given register enum.
let inline regVar (builder: ILowUIRBuilder) reg =
  LanguagePrimitives.EnumToValue reg
  |> RegisterID.create
  |> builder.GetRegVar

/// Creates a new pseudo-register variable with the given register enum.
let inline pseudoRegVar (builder: ILowUIRBuilder) reg pos =
  let rid = LanguagePrimitives.EnumToValue reg |> RegisterID.create
  builder.GetPseudoRegVar(rid, pos)

/// Creates two new pseudo-register variables for a 128-bit register of the
/// given register enum.
let inline pseudoRegVar128 (builder: ILowUIRBuilder) reg =
  struct (pseudoRegVar builder reg 2, pseudoRegVar builder reg 1)

/// Creates four new pseudo-register variables for a 256-bit register of the
/// given register enum.
let inline pseudoRegVar256 (builder: ILowUIRBuilder) reg =
  let pseudoRegVar = pseudoRegVar builder reg
  struct (pseudoRegVar 4, pseudoRegVar 3, pseudoRegVar 2, pseudoRegVar 1)

/// Creates eight new pseudo-register variables for a 512-bit register of the
/// given register enum.
let inline pseudoRegVar512 (builder: ILowUIRBuilder) reg =
  let regV = pseudoRegVar builder reg
  struct (regV 8, regV 7, regV 6, regV 5, regV 4, regV 3, regV 2, regV 1)

/// Represents a deferred stream of statements. A block is a function of the
/// builder, so nothing in it runs until a control-flow combinator decides to
/// run it; that is what keeps branch bodies allocation-free.
type Block = ILowUIRBuilder -> unit

/// Provides the `lift` computation expression, which brackets the statements
/// of one instruction with its ISMark and, unless the body terminates the
/// instruction itself, its IEMark. Every member is inlined, so a block emits
/// exactly what the equivalent hand-written stream emits.
and [<Struct>] LiftBuilder =
  /// Builder that the statements are emitted into.
  val Bld: ILowUIRBuilder

  /// Address of the instruction being lifted.
  val Address: Addr

  /// Length of the instruction being lifted.
  val InsLen: uint32

  /// Whether to close the instruction with an IEMark.
  val ClosesInstruction: bool

  /// Creates a lift builder for the instruction at the given address.
  new(bld, addr, insLen, closes) =
    { Bld = bld
      Address = addr
      InsLen = insLen
      ClosesInstruction = closes }

  member inline _.Zero() = ()

  member inline _.Delay([<InlineIfLambda>] f: unit -> unit) = f

  member inline _.Combine((), [<InlineIfLambda>] f: unit -> unit) = f ()

  member inline this.Yield(stmt: Stmt) = this.Bld.Stream.Append stmt

  member inline _.For(xs: seq<'T>, [<InlineIfLambda>] f: 'T -> unit) =
    for x in xs do f x

  member inline _.While([<InlineIfLambda>] cond, [<InlineIfLambda>] body) =
    while cond () do body ()

  member inline this.Run([<InlineIfLambda>] f: unit -> unit) =
    this.Bld.Stream.MarkStart(this.Address, this.InsLen)
    f ()
    if this.ClosesInstruction then this.Bld.Stream.MarkEnd this.InsLen else ()
    this.Bld

/// Provides the `append` computation expression, which appends a statement
/// stream to a builder without bracketing it with instruction marks. Use it
/// for the helpers that lifters share, and `lift` for the lifters themselves.
and [<Struct>] AppendBuilder =
  /// Builder that the statements are emitted into.
  val Bld: ILowUIRBuilder

  /// Creates an append builder over the given builder.
  new bld = { Bld = bld }

  member inline _.Zero() = ()

  member inline _.Delay([<InlineIfLambda>] f: unit -> unit) = f

  member inline _.Combine((), [<InlineIfLambda>] f: unit -> unit) = f ()

  member inline this.Yield(stmt: Stmt) = this.Bld.Stream.Append stmt

  member inline _.For(xs: seq<'T>, [<InlineIfLambda>] f: 'T -> unit) =
    for x in xs do f x

  member inline _.While([<InlineIfLambda>] cond, [<InlineIfLambda>] body) =
    while cond () do body ()

  member inline _.Run([<InlineIfLambda>] f: unit -> unit) = f ()

/// Provides the `block` computation expression, which builds a deferred
/// statement stream for a control-flow combinator to run.
and [<Struct>] BlockBuilder =
  member inline _.Zero(): Block = fun _ -> ()

  (* Delay MUST defer the body itself. Writing `Delay f = f ()` compiles and
     warns about nothing, but then the body runs at construction time, so any
     helper that emits directly escapes the branch. *)
  member inline _.Delay([<InlineIfLambda>] f: unit -> Block): Block =
    fun bld -> (f ()) bld

  member inline _.Yield(stmt: Stmt): Block =
    fun bld -> bld.Stream.Append stmt

  member inline _.Combine([<InlineIfLambda>] a: Block,
                          [<InlineIfLambda>] b: Block): Block =
    fun bld -> a bld; b bld

  member inline _.For(xs: seq<'T>, [<InlineIfLambda>] f: 'T -> Block): Block =
    fun bld -> for x in xs do f x bld

  member inline _.Run([<InlineIfLambda>] f: Block) = f

/// Builds a deferred statement stream for a control-flow combinator to run.
let block = BlockBuilder()

/// Appends a statement stream to the given builder, marking neither the start
/// nor the end of an instruction.
let inline append bld = AppendBuilder bld

/// Starts lifting the given instruction, closing it with an IEMark once the
/// body of the computation expression ends.
let inline lift bld (ins: #IInstruction) insLen =
  LiftBuilder(bld, ins.Address, insLen, true)

/// Starts lifting the given instruction without closing it with an IEMark.
/// Use this only when the body terminates the instruction on its own, e.g.
/// with an inter-jump.
let inline liftOpen bld (ins: #IInstruction) insLen =
  LiftBuilder(bld, ins.Address, insLen, false)

/// Starts a new instruction with an ISMark. Use it where a lifter marks the
/// start somewhere other than the top of its body, which `lift` cannot reach.
let inline markStart (bld: ILowUIRBuilder) addr insLen =
  bld.Stream.MarkStart(addr, insLen)

/// Closes the current instruction with an IEMark. Use it inside a `liftOpen`
/// body, on the path that ends the instruction the ordinary way.
let inline markEnd (bld: ILowUIRBuilder) insLen = bld.Stream.MarkEnd insLen

/// Runs the given block when the condition holds, and falls through to the
/// end otherwise. Emits two labels, named after `name`, and no jump.
let inline _when bld name cond ([<InlineIfLambda>] thn: Block) =
  let lblThen = label bld name
  let lblEnd = label bld (name + "End")
  bld.Stream.Append <| AST.cjmp cond (AST.jmpDest lblThen) (AST.jmpDest lblEnd)
  bld.Stream.Append <| AST.lmark lblThen
  thn bld
  bld.Stream.Append <| AST.lmark lblEnd

/// Runs the given block unless the condition holds, and falls through to the
/// end otherwise. Emits two labels, named after `name`, and no jump, swapping
/// the jump targets instead of negating the condition.
let inline _unless bld name cond ([<InlineIfLambda>] thn: Block) =
  let lblThen = label bld name
  let lblEnd = label bld (name + "End")
  bld.Stream.Append <| AST.cjmp cond (AST.jmpDest lblEnd) (AST.jmpDest lblThen)
  bld.Stream.Append <| AST.lmark lblThen
  thn bld
  bld.Stream.Append <| AST.lmark lblEnd

/// Runs the first block when the condition holds and the second one otherwise.
/// Emits three labels, named after `name`, and one jump.
let inline _if bld name cond ([<InlineIfLambda>] thn: Block)
                             ([<InlineIfLambda>] els: Block) =
  let lblThen = label bld name
  let lblElse = label bld ("Not" + name)
  let lblEnd = label bld (name + "End")
  bld.Stream.Append <| AST.cjmp cond (AST.jmpDest lblThen) (AST.jmpDest lblElse)
  bld.Stream.Append <| AST.lmark lblThen
  thn bld
  bld.Stream.Append <| AST.jmp (AST.jmpDest lblEnd)
  bld.Stream.Append <| AST.lmark lblElse
  els bld
  bld.Stream.Append <| AST.lmark lblEnd

/// Runs the given block as long as the condition holds, testing it before
/// every iteration. Emits three labels, named after `name`, and one jump.
let inline _while bld name cond ([<InlineIfLambda>] body: Block) =
  let lblCond = label bld (name + "Cond")
  let lblBody = label bld name
  let lblEnd = label bld (name + "End")
  bld.Stream.Append <| AST.lmark lblCond
  bld.Stream.Append <| AST.cjmp cond (AST.jmpDest lblBody) (AST.jmpDest lblEnd)
  bld.Stream.Append <| AST.lmark lblBody
  body bld
  bld.Stream.Append <| AST.jmp (AST.jmpDest lblCond)
  bld.Stream.Append <| AST.lmark lblEnd

/// Runs the first block as long as the condition holds, testing it before the
/// first iteration and after every one, and runs the second block instead when
/// the condition does not hold at all. Emits three labels, named after `name`,
/// and no jump.
let inline _repeat bld name cond ([<InlineIfLambda>] body: Block)
                                 ([<InlineIfLambda>] els: Block) =
  let lblBody = label bld name
  let lblElse = label bld ("No" + name)
  let lblEnd = label bld (name + "End")
  bld.Stream.Append <| AST.cjmp cond (AST.jmpDest lblBody) (AST.jmpDest lblElse)
  bld.Stream.Append <| AST.lmark lblBody
  body bld
  bld.Stream.Append <| AST.cjmp cond (AST.jmpDest lblBody) (AST.jmpDest lblEnd)
  bld.Stream.Append <| AST.lmark lblElse
  els bld
  bld.Stream.Append <| AST.lmark lblEnd

[<RequireQualifiedAccess>]
module IEEE754Single =
  open B2R2.BinIR.LowUIR.AST.InfixOp

  let inline private hasFraction x =
    (x .& numU32 0x7fffffu 32<rt>) != AST.num0 32<rt>

  let isNaN x =
    let exponent = (x >> numI32 23 32<rt>) .& numI32 0xff 32<rt>
    let e = numI32 0xff 32<rt>
    AST.xtlo 1<rt> ((exponent == e) .& hasFraction x)

  let isSNaN x =
    let nanChecker = isNaN x
    let signalBit = numU32 (1u <<< 22) 32<rt>
    nanChecker .& ((x .& signalBit) == AST.num0 32<rt>)

  let isQNaN x =
    let nanChecker = isNaN x
    let signalBit = numU32 (1u <<< 22) 32<rt>
    nanChecker .& ((x .& signalBit) != AST.num0 32<rt>)

  let isInfinity x =
    let exponent = (x >> numI32 23 32<rt>) .& numI32 0xff 32<rt>
    let fraction = x .& numU32 0x7fffffu 32<rt>
    let e = numI32 0xff 32<rt>
    let zero = AST.num0 32<rt>
    AST.xtlo 1<rt> ((exponent == e) .& (fraction == zero))

  let isZero x =
    let mask = numU32 0x7fffffffu 32<rt>
    AST.eq (x .& mask) (AST.num0 32<rt>)

[<RequireQualifiedAccess>]
module IEEE754Double =
  open B2R2.BinIR.LowUIR.AST.InfixOp

  let inline private hasFraction x =
    (x .& numU64 0xfffff_ffffffffUL 64<rt>) != AST.num0 64<rt>

  let isNaN x =
    let exponent = (x >> numI32 52 64<rt>) .& numI32 0x7ff 64<rt>
    let e = numI32 0x7ff 64<rt>
    AST.xtlo 1<rt> ((exponent == e) .& hasFraction x)

  let isSNaN x =
    let nanChecker = isNaN x
    let signalBit = numU64 (1UL <<< 51) 64<rt>
    nanChecker .& ((x .& signalBit) == AST.num0 64<rt>)

  let isQNaN x =
    let nanChecker = isNaN x
    let signalBit = numU64 (1UL <<< 51) 64<rt>
    nanChecker .& ((x .& signalBit) != AST.num0 64<rt>)

  let isInfinity x =
    let exponent = (x >> numI32 52 64<rt>) .& numI32 0x7ff 64<rt>
    let fraction = x .& numU64 0xfffff_ffffffffUL 64<rt>
    let e = numI32 0x7ff 64<rt>
    let zero = AST.num0 64<rt>
    AST.xtlo 1<rt> ((exponent == e) .& (fraction == zero))

  let isZero x =
    let mask = numU64 0x7fffffff_ffffffffUL 64<rt>
    AST.eq (x .& mask) (AST.num0 64<rt>)
