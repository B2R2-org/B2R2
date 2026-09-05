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

module internal B2R2.FrontEnd.PARISC.GeneralLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils

/// PA-RISC's GR0 reads as zero and discards writes. This shadows AST's := for
/// every lifter below so an assignment to GR0 becomes a self-assign the
/// optimizer drops; GR0 thus stays at its initial zero and reads back as zero,
/// which is what "copy" (an OR into GR0's place), a compare that throws its
/// difference away, and a branch discarding its link all rely on.
let inline (:=) dst src =
  match dst with
  | Var(_, rid, _, _) when rid = Register.toRegID Register.GR0 -> dst := dst
  | _ -> dst := src

/// Zero-extends to the given width, or leaves the expression alone when it is
/// already that wide (LowUIR rejects a cast between equal widths).
let private zextTo rt e = if Expr.typeOf e = rt then e else AST.zext rt e

/// The most significant bit of a word -- the sign bit, and for a carry vector
/// the carry out of the whole word.
let private msb e = AST.xthi 1<rt> e

/// Doubleword condition completers sit exactly 34 places above their word
/// counterparts in the completer enumeration, so this folds one onto the other:
/// the width a condition is evaluated at is the builder's register type either
/// way, which is what a doubleword condition means on a 64-bit machine and what
/// a word one means on a 32-bit machine.
let private baseCond (c: Completer) =
  if c >= Completer.DNEVER && c <= Completer.DSDC then
    enum<Completer> (int c - 34)
  else
    c

/// How a memory reference updates its base register.
type private Modify =
  /// The base is left alone; the address is base + offset.
  | NoModify
  /// The base is updated before the access, so the new base is the address.
  | PreModify
  /// The base is updated after the access, so the old base is the address.
  | PostModify

/// The base-register update a load or store completer asks for. The "o"
/// completer marks an ordered access, whose displacement is always zero, so
/// folding it onto a post-modify leaves the base unchanged as it should.
let private modifyOf (ins: Instruction) =
  match ins.Completer with
  | None -> NoModify
  | Some c when Array.contains Completer.MB c -> PreModify
  | Some c when Array.contains Completer.MA c -> PostModify
  | Some c when Array.contains Completer.O c -> PostModify
  | Some c when Array.contains Completer.SM c -> PostModify
  | Some c when Array.contains Completer.M c -> PostModify
  | Some _ -> NoModify

/// How far an indexed reference scales its index register: by the width of the
/// access when the completer says to shift it, not at all otherwise.
let private scaleOf (ins: Instruction) sh =
  match ins.Completer with
  | Some c when Array.contains Completer.S c -> sh
  | Some c when Array.contains Completer.SM c -> sh
  | _ -> 0

/// Emits the nullify guard: the instruction's body runs only when the nullify
/// bit is clear, and the bit is consumed either way, so the instruction after
/// this one is never nullified by this one's arrival. The guard is left out
/// when the instruction lifted just before this one is known to have been the
/// immediately preceding one and to be unable to nullify -- then the bit is
/// provably clear and the whole test folds away.
let private guard (bld: LowUIRBuilder) addr =
  let ibld = bld :> ILowUIRBuilder
  let stale =
    match bld.PrevEnd with
    | ValueSome e -> e <> addr || bld.PrevMayNullify
    | ValueNone -> true
  if stale then
    let rt = ibld.RegType
    let n = regVar ibld Register.PSW_N
    let pending = tmpVar ibld rt
    let runLbl = label ibld "NullifyRun"
    let skipLbl = label ibld "NullifySkip"
    append ibld {
      pending := n
      n := AST.num0 rt
      AST.cjmp (pending != AST.num0 rt)
               (AST.jmpDest skipLbl)
               (AST.jmpDest runLbl)
      AST.lmark runLbl
    }
    bld.NullifySkip <- ValueSome skipLbl
  else
    ()
  bld.PrevMayNullify <- false

/// Marks the start of an instruction and plants its nullify guard. A transfer
/// of control with nothing pending additionally seeds the back of the
/// instruction-address queue with the address past its delay slot -- before the
/// guard, so that a nullified transfer, whose body never runs, still leaves the
/// queue naming the sequential continuation, and so that a conditional one need
/// only overwrite it when taken. With a transfer already pending the queue
/// holds that transfer's target, which must not be disturbed.
let markAt (bld: ILowUIRBuilder) addr insLen isTransfer =
  bld.Stream.MarkStart(addr, insLen)
  match bld with
  | :? LowUIRBuilder as pbld ->
    (* A transfer deferred by a prior block's decode expects its delay slot at a
       fixed address; reaching a different address instead means that state
       leaked across the block boundary (the slot was never lifted here), so
       drop it rather than flush this unrelated instruction as the slot. *)
    match pbld.DelaySlotAddr with
    | ValueSome expected when
        pbld.PendingKind <> InterJmpKind.NotAJmp && addr <> expected ->
      pbld.ResetPending()
    | ValueNone when pbld.PendingKind <> InterJmpKind.NotAJmp ->
      pbld.ResetPending()
    | _ ->
      ()
    pbld.CurAddr <- addr
    if isTransfer && pbld.PendingKind = InterJmpKind.NotAJmp then
      let back = regVar bld Register.IAOQ_Back
      append bld {
        back := numU64 (addr + uint64 insLen + 4UL) bld.RegType
      }
    else
      ()
    guard pbld addr
  | _ ->
    ()

/// Marks the start of an ordinary instruction. It takes the place of the
/// plain ISMark.
let markInsStart (bld: ILowUIRBuilder) addr insLen =
  markAt bld addr insLen false

/// Marks the start of a control transfer. See markAt.
let markTransfer (bld: ILowUIRBuilder) (addr, insLen) =
  markAt bld addr insLen true

/// Emits one compare-and-exchange at the given width: the value found at the
/// address goes to GR28 unchanged, and the replacement is written over it only
/// where what was found is what was expected. Indivisible as a whole, which is
/// the point of the primitive.
let private casDirect (bld: ILowUIRBuilder) width =
  append bld {
    let rt = bld.RegType
    let addr = regVar bld Register.GR26
    let found = tmpVar bld width
    let lblSwap = label bld "LwsSwap"
    let lblOut = label bld "LwsOut"
    AST.sideEffect AtomicBegin
    found := loadNative bld width addr
    AST.cjmp (found == AST.xtlo width (regVar bld Register.GR25))
             (AST.jmpDest lblSwap)
             (AST.jmpDest lblOut)
    AST.lmark lblSwap
    storeNative bld addr (AST.xtlo width (regVar bld Register.GR24))
    AST.lmark lblOut
    regVar bld Register.GR28 := zextTo rt found
    regVar bld Register.GR21 := AST.num0 rt
    AST.sideEffect AtomicEnd
  }

/// The same exchange, in the form the second light-weight call takes: what is
/// expected and what replaces it are named by pointers rather than held in the
/// registers, and the answer is whether the exchange failed rather than the
/// value that was there.
let private casIndirect (bld: ILowUIRBuilder) width =
  append bld {
    let rt = bld.RegType
    let addr = regVar bld Register.GR26
    let found = tmpVar bld width
    let expected = tmpVar bld width
    let lblSwap = label bld "LwsSwap"
    let lblOut = label bld "LwsOut"
    AST.sideEffect AtomicBegin
    found := loadNative bld width addr
    expected := loadNative bld width (regVar bld Register.GR25)
    AST.cjmp (found == expected)
             (AST.jmpDest lblSwap)
             (AST.jmpDest lblOut)
    AST.lmark lblSwap
    storeNative bld addr (loadNative bld width (regVar bld Register.GR24))
    AST.lmark lblOut
    regVar bld Register.GR28 :=
      AST.ite (found == expected) (AST.num0 rt) (AST.num1 rt)
    regVar bld Register.GR21 := AST.num0 rt
    AST.sideEffect AtomicEnd
  }

/// Emits the second light-weight call, whose width GR23 names as a power of two
/// from a single byte up to a doubleword.
let private lwsCasSized (bld: ILowUIRBuilder) =
  append bld {
    let rt = bld.RegType
    let size = regVar bld Register.GR23
    let lblOut = label bld "LwsSizeOut"
    let widths = [| 8<rt>; 16<rt>; 32<rt>; 64<rt> |]
    let lbls = Array.init 4 (fun i -> label bld $"LwsSize{i}")
    let lblBad = label bld "LwsSizeBad"
    for i = 0 to 3 do
      let next = if i = 3 then lblBad else lbls[i + 1]
      AST.cjmp (size == numI32 i rt)
               (AST.jmpDest lbls[i])
               (AST.jmpDest next)
      AST.lmark lbls[i]
      casIndirect bld widths[i]
      AST.jmp (AST.jmpDest lblOut)
    AST.lmark lblBad
    AST.sideEffect UnsupportedInstruction
    AST.lmark lblOut
  }

/// Emits the light-weight system call the guest reached the gateway page for:
/// the compare-and-exchange primitives PA-RISC has no instruction of its own
/// for, and which Linux therefore serves from a fixed address. GR20 names which
/// one -- placed, as an ordinary call's number is, by the delay slot of the
/// branch that got here -- and the kernel returns to the address just past that
/// slot, which is simply where the block carries on, so nothing has to jump.
let private lws (bld: ILowUIRBuilder) =
  append bld {
    let rt = bld.RegType
    let which = regVar bld Register.GR20
    let lblCas = label bld "Lws0"
    let lblSized = label bld "Lws2"
    let lblTry2 = label bld "LwsTry2"
    let lblBad = label bld "LwsBad"
    let lblOut = label bld "LwsEnd"
    AST.cjmp (which == AST.num0 rt)
             (AST.jmpDest lblCas)
             (AST.jmpDest lblTry2)
    AST.lmark lblCas
    casDirect bld 32<rt>
    AST.jmp (AST.jmpDest lblOut)
    AST.lmark lblTry2
    AST.cjmp (which == numI32 2 rt)
             (AST.jmpDest lblSized)
             (AST.jmpDest lblBad)
    AST.lmark lblSized
    lwsCasSized bld
    AST.jmp (AST.jmpDest lblOut)
    AST.lmark lblBad
    AST.sideEffect UnsupportedInstruction
    AST.lmark lblOut
  }

/// Emits the flush of the pending transfer: the deferred jump to whatever the
/// back of the instruction-address queue names, or -- where the transfer
/// entered the Linux gateway page -- the service the gateway offers at the
/// address it entered, since the number of the call is what its delay slot
/// places.
let private flushPending (bld: ILowUIRBuilder) (pbld: LowUIRBuilder) =
  append bld {
    match pbld.PendingGateway with
    | SystemCall ->
      AST.sideEffect SysCall
    | LightWeightCall ->
      lws bld
    | SetThreadPointer ->
      regVar bld Register.CR27 := regVar bld Register.GR26
    | NotGateway ->
      let back = regVar bld Register.IAOQ_Back
      AST.interjmp back pbld.PendingKind
  }

/// Finalizes an instruction: closes any nullify guard and flushes the transfer
/// pending on it. A PA-RISC transfer stores its target in the back of the
/// instruction-address queue rather than jumping, so the delay-slot instruction
/// that follows executes and then this emits the deferred jump. The flush sits
/// after the nullify label so that a nullified delay slot still transfers
/// control, as the architecture requires.
///
/// A transfer standing in another's delay slot is the one case where the flush
/// must not be unconditional. Such an instruction is only ever reached with the
/// outer transfer untaken -- a transfer that puts one in its delay slot always
/// nullifies that slot on the taken side, since otherwise the architecture
/// leaves the pair undefined -- and untaken means the queue already names this
/// instruction's own successor, which the block simply falls through to. So the
/// outer flush is emitted on the nullified path alone, and the block carries on
/// to the delay slot of the inner transfer. It takes the place of the plain
/// IEMark.
let markInsEnd (bld: ILowUIRBuilder) insLen =
  match bld with
  | :? LowUIRBuilder as pbld ->
    let skip = pbld.NullifySkip
    match pbld.PendingKind, pbld.ArmedKind, skip with
    | InterJmpKind.NotAJmp, _, ValueSome lbl ->
      append bld {
        AST.lmark lbl
      }
    | InterJmpKind.NotAJmp, _, ValueNone ->
      ()
    | _, InterJmpKind.NotAJmp, _ ->
      (match skip with
       | ValueSome lbl -> append bld { AST.lmark lbl }
       | ValueNone -> ())
      flushPending bld pbld
    | _, _, ValueSome lbl ->
      let doneLbl = label bld "TransferDone"
      append bld {
        AST.jmp (AST.jmpDest doneLbl)
        AST.lmark lbl
      }
      flushPending bld pbld
      append bld {
        AST.lmark doneLbl
      }
    | _, _, ValueNone ->
      flushPending bld pbld
    pbld.NullifySkip <- ValueNone
    pbld.Promote()
    pbld.DelaySlotAddr <- ValueSome(pbld.CurAddr + uint64 insLen)
    pbld.PrevEnd <- ValueSome(pbld.CurAddr + uint64 insLen)
    bld.Stream.MarkEnd insLen
    bld
  | _ ->
    bld.Stream.MarkEnd insLen
    bld


/// Provides the `lift` computation expression for PARISC, whose instruction
/// marks carry the delay-slot and nullification bookkeeping that
/// LiftingUtils's cannot. It shadows the one from LiftingUtils, so a lifter in
/// this module gets the PARISC marks without asking for them.
[<Struct>]
type LiftBuilder =
  /// Builder that the statements are emitted into.
  val Bld: ILowUIRBuilder

  /// Address of the instruction being lifted.
  val Address: Addr

  /// Length of the instruction being lifted.
  val InsLen: uint32

  /// Whether the instruction is a control transfer, which owns a delay slot.
  val IsTransfer: bool

  /// Creates a lift builder for the instruction at the given address.
  new(bld, addr, insLen, isTransfer) =
    { Bld = bld
      Address = addr
      InsLen = insLen
      IsTransfer = isTransfer }

  member inline _.Zero() = ()

  member inline _.Delay([<InlineIfLambda>] f: unit -> unit) = f

  member inline _.Combine((), [<InlineIfLambda>] f: unit -> unit) = f ()

  member inline this.Yield(stmt: Stmt) = this.Bld.Stream.Append stmt

  member inline _.For(xs: seq<'T>, [<InlineIfLambda>] f: 'T -> unit) =
    for x in xs do f x

  member inline this.Run([<InlineIfLambda>] f: unit -> unit) =
    markAt this.Bld this.Address this.InsLen this.IsTransfer
    f ()
    markInsEnd this.Bld this.InsLen

/// Starts lifting an ordinary instruction, closing it with the PARISC
/// instruction end rather than a plain IEMark.
let inline lift bld (ins: Instruction) =
  LiftBuilder(bld, ins.Address, ins.Length, false)

/// Starts lifting a control transfer, which owns the delay slot that follows.
let inline liftTransfer bld (ins: Instruction) =
  LiftBuilder(bld, ins.Address, ins.Length, true)

/// Records that the instruction just lifted can nullify the next one, so that
/// one keeps its guard.
let private mayNullify (bld: ILowUIRBuilder) =
  (bld :?> LowUIRBuilder).PrevMayNullify <- true

/// Arms a delayed transfer of the given kind; its target must already have been
/// stored into the back of the instruction-address queue.
let private arm (bld: ILowUIRBuilder) kind = (bld :?> LowUIRBuilder).Arm kind

/// Arms a delayed entry into one of the gateway page's services.
let private armGateway (bld: ILowUIRBuilder) service =
  (bld :?> LowUIRBuilder).ArmGateway service

(* Bit patterns with one bit per sub-unit of a doubleword, truncated to the
   register width when they are built, so the same constant serves the word and
   doubleword forms of the unit conditions: the low bit of every byte,
   halfword, or word, and the high bit of each. *)
let [<Literal>] private ByteOnes = 0x0101010101010101UL
let [<Literal>] private ByteSgns = 0x8080808080808080UL
let [<Literal>] private HalfOnes = 0x0001000100010001UL
let [<Literal>] private HalfSgns = 0x8000800080008000UL
let [<Literal>] private WordOnes = 0x0000000100000001UL
let [<Literal>] private WordSgns = 0x8000000080000000UL

/// Whether any sub-unit of the result is zero: subtracting one from every
/// sub-unit borrows out of its high bit exactly where that unit was zero, and
/// the borrow is only spurious where the unit's high bit was already set, which
/// the complement of the result masks off.
let private someUnitZero rt res ones sgns =
  let ones = numU64 ones rt
  let sgns = numU64 sgns rt
  (((res .- ones) .& AST.not res) .& sgns) != AST.num0 rt

/// Whether any sub-unit produced a carry, read off the carry-out vector the
/// last add or subtract left: its bit i holds the carry out of bit i, so the
/// high bit of each sub-unit holds that unit's carry out.
let private someUnitCarry rt cb sgns = (cb .& numU64 sgns rt) != AST.num0 rt

/// The carry out of every bit position of an addition, as a vector: a bit
/// carries out when both addends have it set, or when either does and the sum
/// does not. Holds whatever the carry into the low bit was, so it serves the
/// subtractions too, which add the complement and a one.
let private carryOut in1 in2 res = (in1 .& in2) .| ((in1 .| in2) .& AST.not res)

/// Signed overflow of an addition: the addends agree in sign and the sum does
/// not agree with them.
let private addOverflow in1 in2 res =
  msb ((res <+> in1) .& AST.not (in1 <+> in2))

/// Signed overflow of a subtraction: the operands differ in sign and the
/// difference does not agree with the minuend.
let private subOverflow in1 in2 res = msb ((in1 <+> in2) .& (in1 <+> res))

/// The condition an arithmetic completer names as a one-bit expression, or None
/// when it never holds -- which is the common case, and one where nothing need
/// be emitted at all since the nullify bit is already clear.
let private subCond (bld: ILowUIRBuilder) cond in1 in2 res =
  let rt = bld.RegType
  match baseCond cond with
  | Completer.NEVER -> None
  | Completer.TR -> Some AST.b1
  | Completer.EQ -> Some(in1 == in2)
  | Completer.NEQ -> Some(in1 != in2)
  | Completer.LT -> Some(in1 ?< in2)
  | Completer.GE -> Some(in1 ?>= in2)
  | Completer.LE -> Some(in1 ?<= in2)
  | Completer.GT -> Some(in1 ?> in2)
  | Completer.LTU -> Some(in1 .< in2)
  | Completer.GEU -> Some(in1 .>= in2)
  | Completer.LEU -> Some(in1 .<= in2)
  | Completer.GTU -> Some(in1 .> in2)
  | Completer.SV -> Some(subOverflow in1 in2 res)
  | Completer.NSV -> Some(AST.not (subOverflow in1 in2 res))
  | Completer.OD -> Some(AST.xtlo 1<rt> res)
  | Completer.EV -> Some(AST.not (AST.xtlo 1<rt> res))
  | _ -> ignore rt; None

/// The condition an addition's completer names. The signed comparisons are the
/// sign of the sum corrected by its overflow, since a sum that overflowed has
/// the wrong sign; the unsigned ones read the carry out of the word.
let private addCond (bld: ILowUIRBuilder) cond in1 in2 res cb =
  let rt = bld.RegType
  let zero = AST.num0 rt
  let neg () = msb res <+> addOverflow in1 in2 res
  let noCarry () = msb cb == AST.b0
  match baseCond cond with
  | Completer.NEVER -> None
  | Completer.TR -> Some AST.b1
  | Completer.EQ -> Some(res == zero)
  | Completer.NEQ -> Some(res != zero)
  | Completer.LT -> Some(neg ())
  | Completer.GE -> Some(AST.not (neg ()))
  | Completer.LE -> Some(neg () .| (res == zero))
  | Completer.GT -> Some(AST.not (neg () .| (res == zero)))
  | Completer.NUV -> Some(noCarry ())
  | Completer.UV -> Some(AST.not (noCarry ()))
  | Completer.ZNV -> Some(noCarry () .| (res == zero))
  | Completer.VNZ -> Some(AST.not (noCarry () .| (res == zero)))
  | Completer.SV -> Some(addOverflow in1 in2 res)
  | Completer.NSV -> Some(AST.not (addOverflow in1 in2 res))
  | Completer.OD -> Some(AST.xtlo 1<rt> res)
  | Completer.EV -> Some(AST.not (AST.xtlo 1<rt> res))
  | _ -> None

/// The condition a logical completer names, read off the result alone. The
/// shift, extract, deposit, and move-and-branch instructions use this same set.
let private logCond (bld: ILowUIRBuilder) cond res =
  let zero = AST.num0 bld.RegType
  match baseCond cond with
  | Completer.NEVER -> None
  | Completer.TR -> Some AST.b1
  | Completer.EQ -> Some(res == zero)
  | Completer.NEQ -> Some(res != zero)
  | Completer.LT -> Some(msb res)
  | Completer.GE -> Some(AST.not (msb res))
  | Completer.LE -> Some(res ?<= zero)
  | Completer.GT -> Some(res ?> zero)
  | Completer.OD -> Some(AST.xtlo 1<rt> res)
  | Completer.EV -> Some(AST.not (AST.xtlo 1<rt> res))
  | _ -> None

/// The condition a unit completer names: whether some (or no) byte, halfword,
/// word, or doubleword of the result came out zero, or produced a carry. A
/// 32-bit register holds no doubleword boundary, so a doubleword carry can
/// never arise there.
let private unitCond (bld: ILowUIRBuilder) cond res cb =
  let rt = bld.RegType
  let dwCarry () =
    if rt = 32<rt> then AST.b0 else someUnitCarry rt cb 0x8000000000000000UL
  match baseCond cond with
  | Completer.NEVER -> None
  | Completer.TR -> Some AST.b1
  | Completer.SWZ -> Some(someUnitZero rt res WordOnes WordSgns)
  | Completer.NWZ -> Some(AST.not (someUnitZero rt res WordOnes WordSgns))
  | Completer.SBZ -> Some(someUnitZero rt res ByteOnes ByteSgns)
  | Completer.NBZ -> Some(AST.not (someUnitZero rt res ByteOnes ByteSgns))
  | Completer.SHZ -> Some(someUnitZero rt res HalfOnes HalfSgns)
  | Completer.NHZ -> Some(AST.not (someUnitZero rt res HalfOnes HalfSgns))
  | Completer.SWC -> Some(someUnitCarry rt cb WordSgns)
  | Completer.NWC -> Some(AST.not (someUnitCarry rt cb WordSgns))
  | Completer.SBC -> Some(someUnitCarry rt cb ByteSgns)
  | Completer.NBC -> Some(AST.not (someUnitCarry rt cb ByteSgns))
  | Completer.SHC -> Some(someUnitCarry rt cb HalfSgns)
  | Completer.NHC -> Some(AST.not (someUnitCarry rt cb HalfSgns))
  | Completer.SDC -> Some(dwCarry ())
  | Completer.NDC -> Some(AST.not (dwCarry ()))
  | _ -> None

/// Emits the update of the nullify bit from a condition: the instruction that
/// follows is nullified exactly when the condition holds. A condition that
/// never holds needs no statement, since the bit is already clear there.
let nullifyOn (bld: ILowUIRBuilder) cond =
  match cond with
  | None ->
    ()
  | Some c ->
    append bld {
      regVar bld Register.PSW_N := zextTo bld.RegType c
    }
    mayNullify bld

/// The condition completer an instruction carries where the completer array is
/// what holds it (the compare-and-branch family and CMPICLR), rather than the
/// dedicated condition slot the arithmetic instructions use.
let private firstCompleter (ins: Instruction) =
  match ins.Completer with
  | Some c when c.Length > 0 -> Some c[0]
  | _ -> None

/// Whether a transfer of control nullifies its delay slot when the rule for its
/// kind says to, i.e. whether it carries the "n" completer.
let private hasNullify (ins: Instruction) = ins.Condition = Some Completer.N

let private transOpr (bld: ILowUIRBuilder) = function
  | OpReg r -> regVar bld r
  | OpImm imm
  | OpShiftAmount imm -> numU64 imm bld.RegType
  | _ -> raise InvalidOperandException

let private getOneOpr (ins: Instruction) =
  match ins.Operands with
  | OneOperand o -> o
  | _ -> raise InvalidOperandException

let private getTwoOprs (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(o1, o2) -> struct (o1, o2)
  | _ -> raise InvalidOperandException

let private getThreeOprs (ins: Instruction) =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) -> struct (o1, o2, o3)
  | _ -> raise InvalidOperandException

let private getFourOprs (ins: Instruction) =
  match ins.Operands with
  | FourOperands(o1, o2, o3, o4) -> struct (o1, o2, o3, o4)
  | _ -> raise InvalidOperandException

/// Forms the effective address of a memory reference and applies the base
/// update its completer asks for, returning the address the access uses: the
/// updated base for a plain or pre-modify reference, the original base -- held
/// in a temporary, so the update cannot disturb it -- for a post-modify one.
let effAddr (bld: ILowUIRBuilder) ins sh opr =
  match opr with
  | OpMem(b, _, off, _) ->
    let rt = bld.RegType
    let bse = regVar bld b
    let scale = scaleOf ins sh
    let ofs = tmpVar bld rt
    match off with
    | None ->
      append bld { ofs := bse }
    | Some(Imm i) ->
      append bld { ofs := bse .+ numI64 i rt }
    | Some(Reg x) when scale = 0 ->
      append bld { ofs := bse .+ regVar bld x }
    | Some(Reg x) ->
      append bld { ofs := bse .+ (regVar bld x << numI32 scale rt) }
    match modifyOf ins with
    | NoModify ->
      ofs
    | PreModify ->
      append bld {
        bse := ofs
      }
      ofs
    | PostModify ->
      let addr = tmpVar bld rt
      append bld {
        addr := bse
        bse := ofs
      }
      addr
  | _ ->
    raise InvalidOperandException

/// The width in bits a load or store transfers, and the number of places an
/// indexed reference shifts its index register to scale it by that width.
let accessSize (ins: Instruction) =
  match ins.Opcode with
  | Op.LDB | Op.STB -> struct (8<rt>, 0)
  | Op.LDH | Op.STH -> struct (16<rt>, 1)
  | Op.LDW | Op.LDWA | Op.LDCW | Op.STW | Op.STWA | Op.STBY
  | Op.FLDW | Op.FSTW -> struct (32<rt>, 2)
  | Op.LDD | Op.LDDA | Op.LDCD | Op.STD | Op.STDA | Op.STDBY
  | Op.FLDD | Op.FSTD -> struct (64<rt>, 3)
  | o -> raise (NotImplementedIRException(Disasm.opCodeToString o))

/// Rejects an access wider than the machine word, which only a doubleword
/// instruction decoded against a 32-bit builder can ask for.
let private checkWidth (bld: ILowUIRBuilder) (ins: Instruction) sz =
  if sz > bld.RegType then
    raise (NotImplementedIRException(Disasm.opCodeToString ins.Opcode))
  else
    ()

let load (ins: Instruction) bld =
  lift bld ins {
    let struct (mem, dst) = getTwoOprs ins
    let struct (sz, sh) = accessSize ins
    checkWidth bld ins sz
    let addr = effAddr bld ins sh mem
    transOpr bld dst := zextTo bld.RegType (loadNative bld sz addr)
  }

let store (ins: Instruction) bld =
  lift bld ins {
    let struct (src, mem) = getTwoOprs ins
    let struct (sz, sh) = accessSize ins
    checkWidth bld ins sz
    let addr = effAddr bld ins sh mem
    let v = transOpr bld src
    storeNative bld addr (if sz = bld.RegType then v else AST.xtlo sz v)
  }

/// Load and clear word: the semaphore primitive. It reads the word at the
/// sixteen-byte-aligned address the operand names and leaves zero in its place;
/// the whole of it is one indivisible operation.
let ldcw (ins: Instruction) bld =
  lift bld ins {
    let struct (mem, dst) = getTwoOprs ins
    let struct (sz, sh) = accessSize ins
    checkWidth bld ins sz
    let addr = effAddr bld ins sh mem
    let aligned = tmpVar bld bld.RegType
    AST.sideEffect AtomicBegin
    aligned := addr .& numI64 -16L bld.RegType
    transOpr bld dst := zextTo bld.RegType (loadNative bld sz aligned)
    storeNative bld aligned (AST.num0 sz)
    AST.sideEffect AtomicEnd
  }

/// Store bytes: the partial store a byte-at-a-time copy loop uses to write the
/// ragged ends of its buffer without touching the bytes beyond them. The "b"
/// form writes the addressed byte and every byte after it within the word; the
/// "e" form writes the bytes of the word before the addressed one, and writes
/// nothing at all when the address is already word-aligned. Both take the bytes
/// from the corresponding places in the source register, so in the memory order
/// of a big-endian machine the register and the word line up.
let stby (ins: Instruction) (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (src, mem) = getTwoOprs ins
    let struct (_, sh) = accessSize ins
    let rt = bld.RegType
    let isEnd =
      match ins.Completer with
      | Some c -> Array.contains Completer.E c
      | None -> false
    let addr = effAddr bld ins sh mem
    let v = transOpr bld src
    let low = tmpVar bld rt
    let lblEnd = label bld "StbyEnd"
    let lbls = Array.init 4 (fun i -> label bld $"StbyCase{i}")
    low := addr .& numI32 3 rt
    for i = 0 to 3 do
      let next = if i = 3 then lblEnd else lbls[i + 1]
      AST.cjmp (low == numI32 i rt)
               (AST.jmpDest lbls[i])
               (AST.jmpDest next)
      AST.lmark lbls[i]
      (* The addressed byte's place in the word decides how many bytes are
         written and, for the "e" form, where they start; each is taken from the
         matching byte of the source register. *)
      let count = if isEnd then i else 4 - i
      let start = if isEnd then addr .- numI32 i rt else addr
      for k = 0 to count - 1 do
        let at = if isEnd then k else i + k
        let byteVal = AST.extract v 8<rt> ((3 - at) * 8)
        storeNative bld (start .+ numI32 k rt) byteVal
      if i = 3 then () else append bld { AST.jmp (AST.jmpDest lblEnd) }
    AST.lmark lblEnd
  }

/// Load offset: the address a memory reference would use, left in a register
/// rather than followed. It is how a small constant is loaded and how the
/// address of a stack slot is taken.
let ldo (ins: Instruction) bld =
  lift bld ins {
    let struct (mem, dst) = getTwoOprs ins
    let addr = effAddr bld ins 0 mem
    transOpr bld dst := addr
  }

/// Load immediate left: the upper portion of a 32-bit constant, already shifted
/// into place by the decoder.
let ldil (ins: Instruction) bld =
  lift bld ins {
    let struct (imm, dst) = getTwoOprs ins
    transOpr bld dst := transOpr bld imm
  }

/// Add immediate left: the upper portion of a 32-bit constant added to a
/// register, always landing in GR1, which is why the pair of instructions that
/// forms a long displacement always goes through it.
let addil (ins: Instruction) bld =
  lift bld ins {
    let struct (imm, src) = getTwoOprs ins
    regVar bld Register.GR1 := transOpr bld src .+ transOpr bld imm
  }

/// The carry the add-with-carry and subtract-with-borrow forms take in: the
/// carry out of the whole word that the last add or subtract recorded.
let private carryIn (bld: ILowUIRBuilder) =
  zextTo bld.RegType (msb (regVar bld Register.PSW_CB))

/// Whether an arithmetic completer array asks for the carry (or borrow) of the
/// preceding add or subtract to be taken in.
let private takesCarry (ins: Instruction) =
  match ins.Completer with
  | Some c ->
    Array.contains Completer.C c || Array.contains Completer.DC c
    || Array.contains Completer.B c || Array.contains Completer.DB c
  | None ->
    false

/// Whether an arithmetic completer array marks the "logical" form, which is the
/// one that leaves the recorded carries alone. That is the whole point of it:
/// the carry a plain add records is what the add-with-carry completing a
/// multi-word sum reads, and the address arithmetic a compiler slips between
/// the two is written this way so as not to disturb it. Recording a carry here
/// anyway is enough to put a word of every long addition out by one.
let private isLogical (ins: Instruction) =
  match ins.Completer with
  | Some c -> Array.contains Completer.L c
  | None -> false

/// Adds two values, recording the carry out of every bit position, and
/// nullifies the next instruction when the completer's condition holds. The
/// trapping forms are lifted as their non-trapping counterparts: an overflow
/// trap terminates the program, which an emulator running user code models by
/// letting the wrong value through rather than by inventing a trap it has no
/// handler for.
let private addWith (ins: Instruction)
                    (bld: ILowUIRBuilder)
                    in1
                    in2
                    dst =
  let rt = bld.RegType
  let res = tmpVar bld rt
  let carries = tmpVar bld rt
  let carry = if takesCarry ins then in2 .+ carryIn bld else in2
  let addend = tmpVar bld rt
  append bld { addend := carry }
  append bld { res := in1 .+ addend }
  append bld { carries := carryOut in1 addend res }
  if not (isLogical ins) then
    append bld { regVar bld Register.PSW_CB := carries }
  else
    ()
  match ins.Condition with
  | Some c -> nullifyOn bld (addCond bld c in1 addend res carries)
  | None -> ()
  append bld { dst := res }

let add (ins: Instruction) bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  lift bld ins {
    addWith ins bld (transOpr bld o1) (transOpr bld o2) (transOpr bld o3)
  }

/// Shift one operand left by one, two, or three places and add the other: the
/// primitive that scales an index before it is added to a base.
let shladd (ins: Instruction) bld =
  let struct (o1, sa, o2, o3) = getFourOprs ins
  lift bld ins {
    let shifted = transOpr bld o1 << transOpr bld sa
    addWith ins bld shifted (transOpr bld o2) (transOpr bld o3)
  }

let addi (ins: Instruction) bld =
  let struct (imm, src, dst) = getThreeOprs ins
  lift bld ins {
    addWith ins bld (transOpr bld src) (transOpr bld imm) (transOpr bld dst)
  }

/// Subtracts the second operand from the first as the machine does it, by
/// adding the complement and a one, so that the recorded carries are the ones
/// the borrow forms and the unit conditions expect. The borrow forms leave the
/// one out and take the recorded carry in its place.
let private subWith (ins: Instruction)
                    (bld: ILowUIRBuilder)
                    in1
                    in2
                    dst =
  let rt = bld.RegType
  let res = tmpVar bld rt
  let cmpl = tmpVar bld rt
  let cb = regVar bld Register.PSW_CB
  let one = if takesCarry ins then carryIn bld else AST.num1 rt
  append bld { cmpl := AST.not in2 }
  append bld { res := (in1 .+ cmpl) .+ one }
  append bld { cb := carryOut in1 cmpl res }
  (* Unlike an addition, a subtraction has no form that leaves the carries
     alone: every one of them records the borrows it produced. *)
  match ins.Condition with
  | Some c -> nullifyOn bld (subCond bld c in1 in2 res)
  | None -> ()
  append bld { dst := res }

let sub (ins: Instruction) bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  lift bld ins {
    subWith ins bld (transOpr bld o1) (transOpr bld o2) (transOpr bld o3)
  }

let subi (ins: Instruction) bld =
  let struct (imm, src, dst) = getThreeOprs ins
  lift bld ins {
    subWith ins bld (transOpr bld imm) (transOpr bld src) (transOpr bld dst)
  }

/// Compare and clear: the difference is thrown away and the target is set to
/// zero, leaving only the nullification the comparison decides. Paired with the
/// instruction it nullifies, it is how a boolean is computed without a branch.
let cmpclr (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let in1 = transOpr bld o1
    let in2 = transOpr bld o2
    let dst = transOpr bld o3
    let rt = bld.RegType
    let res = tmpVar bld rt
    res := in1 .- in2
    let cond =
      match ins.Opcode with
      | Op.CMPICLR -> firstCompleter ins
      | _ -> ins.Condition
    match cond with
    | Some c -> nullifyOn bld (subCond bld c in1 in2 res)
    | None -> ()
    dst := AST.num0 rt
  }

/// Divide step: one step of the non-restoring division the millicode routines
/// build a full divide out of. It doubles the partial remainder, shifts in the
/// bit the preceding add left in the carry, and then adds or subtracts the
/// divisor according to the divide-step bit, which it re-derives for the next
/// step from the new carry and the divisor's sign.
let ds (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rt = bld.RegType
    let in1 = transOpr bld o1
    let in2 = transOpr bld o2
    let dst = transOpr bld o3
    let v = regVar bld Register.PSW_V
    let cb = regVar bld Register.PSW_CB
    let doubled = tmpVar bld rt
    let sign = tmpVar bld rt
    let addend = tmpVar bld rt
    let res = tmpVar bld rt
    doubled := (in1 .+ in1) .+ carryIn bld
    sign := AST.sext rt (msb v)
    addend := in2 <+> sign
    res := (doubled .+ addend) .+ (sign .& AST.num1 rt)
    cb := carryOut doubled addend res
    v := AST.sext rt (msb cb) <+> in2
    match ins.Condition with
    | Some c -> nullifyOn bld (addCond bld c doubled addend res cb)
    | None -> ()
    dst := res
  }

/// The bitwise operations, whose conditions read the result alone.
let private logical (ins: Instruction) bld f =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let res = tmpVar bld bld.RegType
    res := f (transOpr bld o1) (transOpr bld o2)
    match ins.Condition with
    | Some c -> nullifyOn bld (logCond bld c res)
    | None -> ()
    transOpr bld o3 := res
  }

let ``and`` ins bld = logical ins bld (.&)

let andcm ins bld = logical ins bld (fun a b -> a .& AST.not b)

let ``or`` ins bld = logical ins bld (.|)

let xor ins bld = logical ins bld (<+>)

/// The unit operations: the same bitwise or arithmetic result as their ordinary
/// counterparts, but with conditions that look at each byte, halfword, or word
/// of it separately, which is what makes them the primitive a string routine
/// scans a word of characters with.
/// The unit operations leave the recorded carries alone -- their own carries
/// are theirs alone, computed here for the conditions that read them -- which
/// matters most for the complement form, since a compiler writes every bitwise
/// "not" as one of those and would otherwise wipe the carry of any addition it
/// sits between.
let private unit (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rt = bld.RegType
    let in1 = transOpr bld o1
    let in2 = transOpr bld o2
    let res = tmpVar bld rt
    let carries = tmpVar bld rt
    match ins.Opcode with
    | Op.UXOR ->
      res := in1 <+> in2
    | _ ->
      let cmpl = tmpVar bld rt
      cmpl := AST.not in2
      res := in1 .+ cmpl
      append bld { carries := carryOut in1 cmpl res }
    match ins.Condition with
    | Some c -> nullifyOn bld (unitCond bld c res carries)
    | None -> ()
    transOpr bld o3 := res
  }

let uxor ins bld = unit ins bld

/// Unit add complement: the complement of the second operand added to the
/// first. With zero as the first operand it is how a register is complemented.
let uaddcm ins bld = unit ins bld

/// The number of places a field's big-endian bit position must be shifted by:
/// a position counts from the most significant bit, so the field's least
/// significant bit sits that far up from the bottom of the word.
let private shiftOfPos (bld: ILowUIRBuilder) pos =
  let rt = bld.RegType
  let width = RegType.toBitWidth rt
  let widthm1 = numI32 (width - 1) rt
  match pos with
  | OpReg Register.CR11 -> (regVar bld Register.CR11 .& widthm1) <+> widthm1
  | OpImm p
  | OpShiftAmount p when p < uint64 width -> numU64 (uint64 (width - 1) - p) rt
  | _ -> raise (NotImplementedIRException "field position")

/// Shift right a pair of registers: the first operand supplies the high half
/// and the second the low half of a double-width value, of which the 32 (or 64)
/// bits ending at the given position are kept. It is how a field straddling two
/// words is brought together, and how a rotate is built.
let shrp (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2, sa, dst) = getFourOprs ins
    let rt = bld.RegType
    let width = RegType.toBitWidth rt
    let hi = transOpr bld o1
    let lo = transOpr bld o2
    let sh = tmpVar bld rt
    let res = tmpVar bld rt
    match sa with
    | OpReg Register.CR11 ->
      sh := regVar bld Register.CR11 .& numI32 (width - 1) rt
    | _ ->
      append bld { sh := transOpr bld sa }
    (* A shift of none keeps the low half untouched; shifting the high half by
       the whole width would be a shift out of range, which LowUIR reads as
       zero -- the same answer, but reached by a rule the hardware does not
       share, so the two cases are kept apart. *)
    res := AST.ite (sh == AST.num0 rt)
                   lo
                   ((hi << (numI32 width rt .- sh)) .| (lo >> sh))
    match ins.Condition with
    | Some c -> nullifyOn bld (logCond bld c res)
    | None -> ()
    transOpr bld dst := res
  }

/// The mask of a field's length, as a value of the register's width. A length
/// equal to the whole width leaves every bit set.
let private lenMask (bld: ILowUIRBuilder) len =
  let rt = bld.RegType
  let width = RegType.toBitWidth rt
  if int len >= width then numI64 -1L rt
  else numU64 ((1UL <<< int len) - 1UL) rt

/// Extract: the field of the given length ending at the given bit position,
/// right-justified in the target and either zero- or sign-extended. It is how a
/// right shift, a bitfield read, and a zero-extension are all expressed.
///
/// The shift itself follows the extension: the signed form shifts the sign down
/// with the value and the unsigned form shifts zeroes in. Below the register's
/// width that makes no difference, since re-extending the field afterwards
/// covers whatever came down from above -- but a field as wide as the register
/// *is* the whole of it, and that case is exactly how a compiler writes a
/// variable arithmetic shift right, where filling from the wrong side turns
/// every negative value positive.
let extr (ins: Instruction) bld =
  lift bld ins {
    let struct (src, pos, len, dst) = getFourOprs ins
    let rt = bld.RegType
    let signed =
      match ins.Completer with
      | Some c -> Array.contains Completer.S c
      | None -> false
    let width = RegType.toBitWidth rt
    let n =
      match len with
      | OpImm l -> int l
      | _ -> raise InvalidOperandException
    let res = tmpVar bld rt
    let sh = shiftOfPos bld pos
    if signed then append bld { res := transOpr bld src ?>> sh }
    else append bld { res := transOpr bld src >> sh }
    if n >= width then
      ()
    elif signed then
      let shift = numI32 (width - n) rt
      res := (res << shift) ?>> shift
    else
      res := res .& lenMask bld (uint64 n)
    match ins.Condition with
    | Some c -> nullifyOn bld (logCond bld c res)
    | None -> ()
    transOpr bld dst := res
  }

/// Deposit: the rightmost bits of the source laid into the target at the field
/// of the given length ending at the given bit position. The "z" form clears
/// everything around the field instead of preserving it, which is how a left
/// shift is expressed.
let dep (ins: Instruction) bld =
  lift bld ins {
    let struct (src, pos, len, dst) = getFourOprs ins
    let rt = bld.RegType
    let zeroRest =
      match ins.Completer with
      | Some c -> Array.contains Completer.Z c
      | None -> false
    let n =
      match len with
      | OpImm l -> uint64 l
      | _ -> raise InvalidOperandException
    let mask = lenMask bld n
    let sh = shiftOfPos bld pos
    let dst = transOpr bld dst
    let field = tmpVar bld rt
    let placed = tmpVar bld rt
    let res = tmpVar bld rt
    field := transOpr bld src .& mask
    placed := field << sh
    if zeroRest then append bld { res := placed }
    else append bld { res := (dst .& AST.not (mask << sh)) .| placed }
    match ins.Condition with
    | Some c -> nullifyOn bld (logCond bld c res)
    | None -> ()
    dst := res
  }

/// The privilege level user code runs at, which an instruction address carries
/// in its low two bits. It is not decoration: position-independent code takes
/// its own address with a linking branch and then reaches its data through
/// displacements that already have this offset folded out of them, so a link
/// register left without it sends every one of those references two bytes
/// wide.
let [<Literal>] private PrivUser = 3UL

/// Writes the return address a linking transfer leaves behind: the address one
/// past the delay slot, which is where the callee returns to, carrying the
/// privilege level as the instruction-address queue does.
let private link (bld: ILowUIRBuilder) addr reg =
  append bld {
    regVar bld reg := numU64 (addr + 8UL ||| PrivUser) bld.RegType
  }

/// Strips the privilege level an instruction address carries in its low two
/// bits, which every transfer through a register has to do before it can treat
/// the register's contents as an address.
let private stripPriv (bld: ILowUIRBuilder) e = e .& numI64 -4L bld.RegType

/// The address a branch's target operand names. The decoder has already folded
/// in the eight bytes a PA-RISC displacement is measured from, so the target is
/// simply the instruction's address plus the operand.
let private branchTarget (bld: ILowUIRBuilder) (ins: Instruction) imm =
  numU64 (ins.Address + imm) bld.RegType

/// Whether a branch's displacement runs forwards, which decides -- together
/// with whether it is taken -- which side of a conditional branch its delay
/// slot belongs to.
let private isForward imm = int64 (imm - 8UL) >= 0L

/// Completes an unconditional transfer: the target goes to the back of the
/// instruction-address queue, and the delay slot runs before the jump does.
///
/// With the "n" completer the jump is taken here and now instead, because for
/// an unconditional transfer that completer nullifies the delay slot every
/// time, so nothing whatever happens between the two. PA-RISC code counts on
/// that: a jump table's entries and a literal pool are placed immediately
/// after such a
/// transfer, where looking for a delay slot to lift would find data rather than
/// an instruction.
let private transfer (bld: ILowUIRBuilder) ins kind target =
  append bld {
    regVar bld Register.IAOQ_Back := target
  }
  if hasNullify ins then
    append bld { AST.interjmp target kind }
  else
    arm bld kind

/// Completes a conditional transfer. The target replaces the seeded
/// fall-through only when the branch is taken, and the nullify bit follows
/// PA-RISC's rule: with the "n" completer, a taken forward branch or an untaken
/// backward one nullifies the delay slot, so that the slot always belongs to
/// the path which stays with the branch's own body -- the loop it closes, or
/// the code it skips past.
let private condTransfer bld (ins: Instruction) taken imm =
  let rt = (bld: ILowUIRBuilder).RegType
  let tk = tmpVar bld 1<rt>
  let back = regVar bld Register.IAOQ_Back
  let fall = numU64 (ins.Address + 8UL) rt
  append bld {
    tk := match taken with
          | Some t -> t
          | None -> AST.b0
    back := AST.ite tk (branchTarget bld ins imm) fall
  }
  if hasNullify ins then
    let cond = if isForward imm then tk else AST.not tk
    append bld {
      regVar bld Register.PSW_N := zextTo rt cond
    }
    mayNullify bld
  else
    ()
  arm bld InterJmpKind.Base

/// The displacement operand of a compare-and-branch instruction.
let private branchImm opr =
  match opr with
  | OpImm imm -> imm
  | _ -> raise InvalidOperandException

/// An IA-relative branch, optionally leaving its return address in a register.
/// A branch that links GR0 keeps no return address, so it is a plain jump; one
/// that links any other register is a call.
let b (ins: Instruction) bld =
  liftTransfer bld ins {
    let struct (target, linkReg) = getTwoOprs ins
    let kind =
      match linkReg with
      | OpReg Register.GR0 ->
        InterJmpKind.Base
      | OpReg r ->
        link bld ins.Address r
        InterJmpKind.IsCall
      | _ ->
        raise InvalidOperandException
    transfer bld ins kind (branchTarget bld ins (branchImm target))
  }

/// Branch and link register: the target is the address past the delay slot
/// advanced by eight times the index register, which is how a jump table of
/// two-instruction entries is entered.
let blr (ins: Instruction) bld =
  liftTransfer bld ins {
    let struct (idx, linkReg) = getTwoOprs ins
    let rt = bld.RegType
    let target = tmpVar bld rt
    let kind =
      match linkReg with
      | OpReg Register.GR0 ->
        InterJmpKind.Base
      | OpReg r ->
        link bld ins.Address r
        InterJmpKind.IsCall
      | _ ->
        raise InvalidOperandException
    target := numU64 (ins.Address + 8UL) rt
              .+ (transOpr bld idx << numI32 3 rt)
    transfer bld ins kind target
  }

/// Branch vectored: the transfer through a register that both a computed jump
/// and a procedure return are made of. A return goes through GR2, the register
/// a call leaves its return address in, so that is what marks one.
let bv (ins: Instruction) bld =
  liftTransfer bld ins {
    let opr = getOneOpr ins
    let rt = bld.RegType
    let target = tmpVar bld rt
    let struct (bse, kind) =
      match opr with
      | OpMem(b, _, off, _) ->
        let scaled =
          match off with
          | Some(Reg x) -> regVar bld b .+ (regVar bld x << numI32 3 rt)
          | _ -> regVar bld b
        let kind =
          if b = Register.GR2 then InterJmpKind.IsRet else InterJmpKind.Base
        struct (scaled, kind)
      | _ ->
        raise InvalidOperandException
    target := stripPriv bld bse
    transfer bld ins kind target
  }

/// Branch vectored to an external address: the same transfer through a
/// register, reaching another space. Its linking form leaves the return
/// address in GR2.
let bve (ins: Instruction) bld =
  liftTransfer bld ins {
    let rt = (bld: ILowUIRBuilder).RegType
    let links =
      match ins.Completer with
      | Some c -> Array.contains Completer.L c
      | None -> false
    let bse =
      match ins.Operands with
      | OneOperand(OpMem(b, _, _, _))
      | TwoOperands(OpMem(b, _, _, _), _) -> b
      | _ -> raise InvalidOperandException
    let target = tmpVar bld rt
    target := stripPriv bld (regVar bld bse)
    let kind =
      if links then
        link bld ins.Address Register.GR2
        InterJmpKind.IsCall
      elif bse = Register.GR2 then
        InterJmpKind.IsRet
      else
        InterJmpKind.Base
    transfer bld ins kind target
  }

/// The service the Linux/PA-RISC gateway page offers at an offset into the page
/// of zero, which is the page the kernel keeps it in. There is no system-call
/// instruction on PA-RISC, nor an atomic exchange, nor a way for user code to
/// reach the control register that holds a thread's own pointer; a branch to
/// one of these three fixed addresses through space register 2 is how each is
/// asked
/// for instead. Each takes its argument -- the call number, the operation
/// number, the pointer -- from a register the delay slot of that very branch
/// writes, so the service is performed once the delay slot has run.
let private gatewayAt offset =
  match offset with
  | 0xb0UL -> LightWeightCall
  | 0xe0UL -> SetThreadPointer
  | 0x100UL -> SystemCall
  | _ -> NotGateway

/// Branch external: a transfer to an absolute address in another space. Where
/// it names the gateway page it asks for one of the kernel's services rather
/// than branching; its linking form leaves the address to return to in GR31,
/// which is where each of those services returns.
let be (ins: Instruction) bld =
  liftTransfer bld ins {
    let struct (bse, off) =
      match ins.Operands with
      | OneOperand(OpMem(b, _, off, _))
      | ThreeOperands(OpMem(b, _, off, _), _, _) -> struct (b, off)
      | _ -> raise InvalidOperandException
    let links =
      match ins.Completer with
      | Some c -> Array.contains Completer.L c
      | None -> false
    let disp =
      match off with
      | Some(Imm i) -> i
      | _ -> 0L
    let rt = bld.RegType
    if links then link bld ins.Address Register.GR31 else ()
    let service =
      if bse = Register.GR0 then gatewayAt (uint64 disp) else NotGateway
    match service with
    | NotGateway ->
      let target = tmpVar bld rt
      target := stripPriv bld (regVar bld bse .+ numI64 disp rt)
      let kind = if links then InterJmpKind.IsCall else InterJmpKind.Base
      transfer bld ins kind target
    | _ ->
      armGateway bld service
  }

/// Compare and branch: the comparison of the two operands decides the branch,
/// and nothing is written. Its immediate form compares the immediate with the
/// register, in that order.
let cmpb (ins: Instruction) bld =
  liftTransfer bld ins {
    let struct (o1, o2, target) = getThreeOprs ins
    let rt = bld.RegType
    let in1 = transOpr bld o1
    let in2 = transOpr bld o2
    let res = tmpVar bld rt
    res := in1 .- in2
    let taken =
      match firstCompleter ins with
      | Some c -> subCond bld c in1 in2 res
      | None -> None
    condTransfer bld ins taken (branchImm target)
  }

/// Add and branch: the sum is written back to the second operand's register and
/// also decides the branch, which is what makes one instruction out of a loop's
/// counter update and its test. Its immediate form adds the immediate to the
/// register.
let addb (ins: Instruction) bld =
  liftTransfer bld ins {
    let struct (o1, o2, target) = getThreeOprs ins
    let rt = bld.RegType
    let in1 = transOpr bld o1
    let in2 = transOpr bld o2
    let res = tmpVar bld rt
    let carries = tmpVar bld rt
    res := in1 .+ in2
    (* The sum's carries decide the condition but are not recorded: an add that
       also branches leaves the carry bits as it found them. *)
    carries := carryOut in1 in2 res
    let taken =
      match firstCompleter ins with
      | Some c -> addCond bld c in1 in2 res carries
      | None -> None
    in2 := res
    condTransfer bld ins taken (branchImm target)
  }

/// Move and branch: the first operand is copied to the second's register and
/// decides the branch.
let movb (ins: Instruction) bld =
  liftTransfer bld ins {
    let struct (o1, o2, target) = getThreeOprs ins
    let res = tmpVar bld bld.RegType
    let dst = transOpr bld o2
    res := transOpr bld o1
    let taken =
      match firstCompleter ins with
      | Some c -> logCond bld c res
      | None -> None
    dst := res
    condTransfer bld ins taken (branchImm target)
  }

/// Branch on bit: the named bit of the register, counted from the most
/// significant, decides the branch. The bit is brought to the top of the word
/// and its sign tested, which is how the architecture states it.
let bb (ins: Instruction) bld =
  liftTransfer bld ins {
    let struct (src, pos, target) = getThreeOprs ins
    let rt = bld.RegType
    let width = RegType.toBitWidth rt
    let shifted = tmpVar bld rt
    let sh =
      match pos with
      | OpReg Register.CR11 -> regVar bld Register.CR11 .& numI32 (width - 1) rt
      | _ -> transOpr bld pos
    shifted := transOpr bld src << sh
    let taken =
      match firstCompleter ins with
      | Some c when baseCond c = Completer.GE -> Some(AST.not (msb shifted))
      | Some _ -> Some(msb shifted)
      | None -> None
    condTransfer bld ins taken (branchImm target)
  }

/// Move to control register. Only the shift-amount register and the two
/// registers the ABI leaves to a thread matter to user code, and all of them
/// are plain register moves.
let mtctl (ins: Instruction) bld =
  lift bld ins {
    let struct (src, dst) = getTwoOprs ins
    transOpr bld dst := transOpr bld src
  }

/// Move to the shift-amount register the complement of a value, which is how
/// the count of a variable shift is turned into the bit position a deposit or
/// an extract wants.
let mtsarcm (ins: Instruction) bld =
  lift bld ins {
    let src = getOneOpr ins
    regVar bld Register.CR11 := AST.not (transOpr bld src)
  }

/// Move from control register, or from the instruction address, which is how
/// position-independent code finds out where it is.
let mfctl (ins: Instruction) bld =
  lift bld ins {
    match ins.Opcode, ins.Operands with
    | Op.MFIA, OneOperand dst ->
      transOpr bld dst := numU64 (ins.Address ||| 3UL) bld.RegType
    | _, TwoOperands(src, dst) ->
      transOpr bld dst := transOpr bld src
    | _ ->
      raise InvalidOperandException
  }

/// Load space identifier: the space register number an address would be
/// resolved through. Under the flat address space a user process sees there is
/// only one space, so the answer is always zero -- which is what makes the
/// three-instruction indirect call PA-RISC code uses (load the identifier, move
/// it to a space register, branch external through it) come out as a plain
/// branch to the address in the register.
let ldsid (ins: Instruction) bld =
  lift bld ins {
    let struct (_, dst) = getTwoOprs ins
    transOpr bld dst := AST.num0 bld.RegType
  }

/// A register move between the general and the space registers. Space
/// registers hold no meaning under a flat address space, so the move is a plain
/// one and its value never reaches an address.
let movsp (ins: Instruction) bld =
  lift bld ins {
    let struct (src, dst) = getTwoOprs ins
    transOpr bld dst := transOpr bld src
  }

/// Probe: whether the address may be read (or written) at a given level of
/// trust, left in a register as one or zero. It is not a privileged instruction
/// -- it is there so a program can ask before it reads -- and the answer is
/// always yes here: a user process sees one flat space it may read all of, and
/// an address outside what is mapped faults when it is actually read, which is
/// the
/// same answer by a different route. Leaving the register alone instead would
/// have the dynamic linker read a stale word as "no" and abandon every function
/// descriptor it resolves.
let probe (ins: Instruction) bld =
  lift bld ins {
    let struct (_, _, dst) = getThreeOprs ins
    transOpr bld dst := AST.num1 bld.RegType
  }

/// An instruction with no effect an emulator of user code can observe: the
/// cache and translation-buffer maintenance, the performance monitor, and the
/// branch-target stack, none of which change a register or a byte of memory.
let nop (ins: Instruction) bld =
  lift bld ins {
  }

/// The memory ordering instructions.
let sync (ins: Instruction) bld =
  lift bld ins {
    AST.sideEffect Fence
  }

/// Break: the trap a debugger plants and a runtime check raises.
let ``break`` (ins: Instruction) bld =
  lift bld ins {
    AST.sideEffect Breakpoint
  }

/// An instruction that is valid but outside what this lifter models, left to
/// the emulator to report rather than silently mis-executed.
let unsupported (ins: Instruction) bld =
  lift bld ins {
    AST.sideEffect UnsupportedInstruction
  }

/// A privileged instruction, which user code reaching raises the
/// illegal-instruction trap that is the only reason it would be there.
let illegal (ins: Instruction) bld =
  lift bld ins {
    AST.sideEffect UndefinedInstruction
  }
