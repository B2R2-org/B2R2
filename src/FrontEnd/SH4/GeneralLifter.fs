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

module internal B2R2.FrontEnd.SH4.GeneralLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils

/// A thirty-two-bit constant, the width of every SH4 register and address.
let inline private num (n: int) = numI32 n 32<rt>

/// A sixty-four-bit constant, for the double-width temporary a carry-out or a
/// multiply result needs.
let inline private num64 (n: int) = numI32 n 64<rt>

/// A byte-wide constant, for the immediate a byte-wide logical instruction
/// combines with memory.
let inline private numByte (n: int) = numU32 (uint32 n) 8<rt>

/// A thirty-two-bit constant naming a code address.
let inline private numAddr (addr: Addr) = numU32 (uint32 addr) 32<rt>

/// Marks the start of an instruction and records its address, so a delayed
/// branch can name where its delay slot must appear. It takes the place of
/// the plain ISMark.
let markInsStart (bld: ILowUIRBuilder) addr insLen =
  bld.Stream.MarkStart(addr, insLen)
  match bld with
  | :? LowUIRBuilder as sbld ->
    (* A branch deferred by a prior block's decode expects its delay slot at a
       fixed address; reaching a different address instead means that state
       leaked across the block boundary (the slot was never lifted here), so
       drop it rather than flush this unrelated instruction as the slot. *)
    match sbld.DelaySlotAddr with
    | ValueSome expected when sbld.DelayedBranch <> InterJmpKind.NotAJmp
                              && not sbld.Armed
                              && addr <> expected -> sbld.ResetDelayState()
    | _ -> ()
    sbld.CurAddr <- addr
  | _ ->
    ()

/// Finalizes an instruction, flushing a pending delayed branch. An SH4 control
/// transfer that has a delay slot stores its target in NPC rather than jumping,
/// so the instruction that follows executes and then this emits the InterJmp.
/// The transfer's own end (Armed) defers; the delay slot's end flushes. It
/// takes the place of the plain IEMark.
let markInsEnd (bld: ILowUIRBuilder) insLen =
  match bld with
  | :? LowUIRBuilder as sbld ->
    if sbld.DelayedBranch <> InterJmpKind.NotAJmp then
      if sbld.Armed then
        sbld.Armed <- false
        sbld.DelaySlotAddr <- ValueSome(sbld.CurAddr + uint64 insLen)
      else
        append bld {
          AST.interjmp (regVar bld R.NPC) sbld.DelayedBranch
        }
        sbld.Disarm()
    else
      ()
    bld.Stream.MarkEnd insLen
    bld
  | _ ->
    bld.Stream.MarkEnd insLen
    bld


/// Provides the `lift` computation expression for SH4, whose instruction
/// marks carry the delay-slot bookkeeping that LiftingUtils's cannot. It
/// shadows the one from LiftingUtils, so a lifter in this module gets the
/// SH4 marks without asking for them.
[<Struct>]
type LiftBuilder =
  /// Builder that the statements are emitted into.
  val Bld: ILowUIRBuilder

  /// Address of the instruction being lifted.
  val Address: Addr

  /// Length of the instruction being lifted.
  val InsLen: uint32

  /// Creates a lift builder for the instruction at the given address.
  new(bld, addr, insLen) = { Bld = bld; Address = addr; InsLen = insLen }

  member inline _.Zero() = ()

  member inline _.Delay([<InlineIfLambda>] f: unit -> unit) = f

  member inline _.Combine((), [<InlineIfLambda>] f: unit -> unit) = f ()

  member inline this.Yield(stmt: Stmt) = this.Bld.Stream.Append stmt

  member inline _.For(xs: seq<'T>, [<InlineIfLambda>] f: 'T -> unit) =
    for x in xs do f x

  member inline this.Run([<InlineIfLambda>] f: unit -> unit) =
    markInsStart this.Bld this.Address this.InsLen
    f ()
    markInsEnd this.Bld this.InsLen

/// Starts lifting the given instruction, closing it with the SH4
/// instruction end rather than a plain IEMark.
let inline lift bld (ins: Instruction) insLen =
  LiftBuilder(bld, ins.Address, insLen)

/// Arms a delayed control transfer of the given kind; its target must already
/// have been stored into NPC. The following instruction end (after the
/// delay slot) emits
/// the InterJmp.
let private arm (bld: ILowUIRBuilder) kind = (bld :?> LowUIRBuilder).Arm kind

/// Reports an instruction this lifter does not model, so the caller ends its
/// block at it rather than running arithmetic that is merely plausible. The
/// floating-point unit and the privileged instructions are what reach here.
let private notLifted (ins: Instruction) =
  raise (NotImplementedIRException(ins.Opcode.ToString()))

let private getOneOpr (ins: Instruction) =
  match ins.Operands with
  | OneOperand o -> o
  | _ -> raise InvalidOperandException

let private getTwoOprs (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(o1, o2) -> struct (o1, o2)
  | _ -> raise InvalidOperandException

/// The register a register-direct operand names.
let private regEnumOf = function
  | OpReg(Regdir r) -> r
  | _ -> raise InvalidOperandException

/// The register variable a register-direct operand names.
let private regOf bld opr = regEnumOf opr |> regVar bld

/// The source and destination registers of a two-register instruction, in the
/// assembly's own order: SH4 writes the source first.
let private twoRegs ins bld =
  let struct (o1, o2) = getTwoOprs ins
  struct (regOf bld o1, regOf bld o2)

/// The single register a one-operand instruction reads and writes.
let private oneReg ins bld = getOneOpr ins |> regOf bld

/// The raw immediate field of an operand, as the parser read it: unsigned, so
/// the instruction owning the field is what decides whether it is signed.
let private immOf = function
  | OpReg(Imm imm) | OpImm imm -> imm
  | _ -> raise InvalidOperandException

/// Sign-extends the low `width` bits of a raw operand field.
let private signExtend width v =
  let signBit = 1 <<< (width - 1)
  (v &&& (signBit - 1)) - (v &&& signBit)

/// Reads memory in the guest's byte order, which an SH4 part fixes by pin.
let private loadMem (bld: ILowUIRBuilder) rt addr =
  AST.load bld.Endianness rt addr

/// Writes memory in the guest's byte order.
let private storeMem (bld: ILowUIRBuilder) addr v =
  AST.store bld.Endianness addr v

/// The value a load of the given width leaves in a general register: SH4
/// sign-extends a byte or a word to the register's full width.
let private loadExt bld rt addr =
  if rt = 32<rt> then loadMem bld rt addr
  else loadMem bld rt addr |> AST.sext 32<rt>

/// The part of a register a store of the given width writes.
let private storeVal rt v = if rt = 32<rt> then v else AST.xtlo rt v

/// The address @(R0,GBR) names, the only memory operand the byte-wide logical
/// instructions take.
let private gbrIndexed bld = regVar bld R.R0 .+ regVar bld R.GBR

/// The target a PC-relative branch displacement names. SH4 measures it from the
/// branch's own address plus four -- what the pipeline's PC holds while the
/// branch executes -- and scales the displacement by an instruction's two
/// bytes.
let private pcRelTarget (ins: Instruction) width =
  let disp =
    match getOneOpr ins with
    | OpReg(PCRelative d) -> d
    | _ -> raise InvalidOperandException
  let scaled = uint32 (signExtend width disp * 2)
  numU32 (uint32 ins.Address + 4u + scaled) 32<rt>

/// The address a PC-relative operand names for a longword access. SH4 aligns
/// the instruction's own address down to four bytes before adding the scaled
/// displacement, so the same table entry is read whichever half of a longword
/// the instruction itself sits in.
let private pcRelLongAddr (ins: Instruction) disp =
  (uint32 ins.Address &&& 0xFFFFFFFCu) + 4u + uint32 (disp * 4)

/// The address a PC-relative operand names for a word access, which needs no
/// such alignment: an instruction is always even.
let private pcRelWordAddr (ins: Instruction) disp =
  uint32 ins.Address + 4u + uint32 (disp * 2)

/// Emits one form of mov.b, mov.w, or mov.l, which differ only in the access
/// width -- what also scales a displacement and an auto-update step. The
/// thirty-two-bit fmov.s takes the same operand forms, differing only in which
/// register file its register operand names, so it shares this.
let private movMemBody (ins: Instruction) bld rt =
  let step = RegType.toByteWidth rt
  let struct (o1, o2) = getTwoOprs ins
  match o1, o2 with
  | OpReg(Regdir m), OpReg(RegIndir n) ->
    append bld {
      storeMem bld (regVar bld n) (storeVal rt (regVar bld m))
    }
  | OpReg(Regdir m), OpReg(RegIndirPreDec n) ->
    let addr = tmpVar bld 32<rt>
    (* The stored value is the source as it was, so pushing a register onto its
       own stack pointer writes the pointer the push started from. *)
    append bld {
      addr := regVar bld n .- num step
      storeMem bld addr (storeVal rt (regVar bld m))
      regVar bld n := addr
    }
  | OpReg(Regdir m), OpReg(IdxRegIndir(idx, n)) ->
    let addr = regVar bld idx .+ regVar bld n
    append bld {
      storeMem bld addr (storeVal rt (regVar bld m))
    }
  | OpReg(Regdir m), OpReg(GBRIndirDisp(disp, gbr)) ->
    let addr = regVar bld gbr .+ num (disp * step)
    append bld {
      storeMem bld addr (storeVal rt (regVar bld m))
    }
  | OpReg(Regdir m), OpReg(RegIndirDisp(disp, n)) ->
    let addr = regVar bld n .+ num (disp * step)
    append bld {
      storeMem bld addr (storeVal rt (regVar bld m))
    }
  | OpReg(RegIndir m), OpReg(Regdir n) ->
    append bld {
      regVar bld n := loadExt bld rt (regVar bld m)
    }
  | OpReg(RegIndirPostInc m), OpReg(Regdir n) ->
    (* One register named twice takes the loaded value and no increment. *)
    append bld {
      regVar bld n := loadExt bld rt (regVar bld m)
    }
    if m <> n then
      append bld { regVar bld m := regVar bld m .+ num step }
    else
      ()
  | OpReg(IdxRegIndir(idx, m)), OpReg(Regdir n) ->
    let addr = regVar bld idx .+ regVar bld m
    append bld {
      regVar bld n := loadExt bld rt addr
    }
  | OpReg(GBRIndirDisp(disp, gbr)), OpReg(Regdir n) ->
    let addr = regVar bld gbr .+ num (disp * step)
    append bld {
      regVar bld n := loadExt bld rt addr
    }
  | OpReg(RegIndirDisp(disp, m)), OpReg(Regdir n) ->
    let addr = regVar bld m .+ num (disp * step)
    append bld {
      regVar bld n := loadExt bld rt addr
    }
  | OpReg(PCRelDisp(disp, _)), OpReg(Regdir n) ->
    let addr =
      if rt = 32<rt> then pcRelLongAddr ins disp else pcRelWordAddr ins disp
    append bld {
      regVar bld n := loadExt bld rt (numU32 addr 32<rt>)
    }
  | _ ->
    raise InvalidOperandException

/// Lifts one form of mov.b, mov.w, or mov.l.
let private movMem (ins: Instruction) len bld rt =
  lift bld ins len {
    movMemBody ins bld rt
  }

/// Moves one register into another, the shape ldc, lds, stc, sts, flds, and
/// fsts share: only which side is the control, system, or floating-point
/// register differs, and this lifter keeps every one of them in the register
/// file.
let private moveReg (ins: Instruction) len bld =
  lift bld ins len {
    let struct (src, dst) = twoRegs ins bld
    dst := src
  }

let add (ins: Instruction) len bld =
  lift bld ins len {
    let struct (o1, o2) = getTwoOprs ins
    let dst = regOf bld o2
    match o1 with
    | OpReg(Imm imm) -> append bld { dst := dst .+ num (signExtend 8 imm) }
    | _ -> append bld { dst := dst .+ regOf bld o1 }
  }

let addc (ins: Instruction) len bld =
  lift bld ins len {
    let struct (src, dst) = twoRegs ins bld
    let t = regVar bld R.T
    let res = tmpVar bld 64<rt>
    (* Widening to sixty-four bits puts the carry-out in bit thirty-two,
       where it can be read off directly rather than rebuilt from the operand
       signs. *)
    res := (AST.zext 64<rt> dst)
           .+ (AST.zext 64<rt> src)
           .+ (AST.zext 64<rt> t)
    dst := AST.xtlo 32<rt> res
    t := AST.extract res 1<rt> 32
  }

let addv (ins: Instruction) len bld =
  lift bld ins len {
    let struct (src, dst) = twoRegs ins bld
    let res = tmpVar bld 32<rt>
    res := dst .+ src
    (* A signed sum overflows exactly when the operands share a sign the sum
       does not. *)
    regVar bld R.T :=
      ((AST.xthi 1<rt> dst == AST.xthi 1<rt> src)
       .& (AST.xthi 1<rt> res != AST.xthi 1<rt> dst))
    dst := res
  }

let ``and`` (ins: Instruction) len bld =
  lift bld ins len {
    let struct (o1, o2) = getTwoOprs ins
    let dst = regOf bld o2
    (* The immediate form is zero-extended, so it clears the upper three
       bytes. *)
    match o1 with
    | OpReg(Imm imm) -> append bld { dst := dst .& num imm }
    | _ -> append bld { dst := dst .& regOf bld o1 }
  }

let andb (ins: Instruction) len bld =
  lift bld ins len {
    let struct (o1, _) = getTwoOprs ins
    let imm = immOf o1
    let addr = tmpVar bld 32<rt>
    addr := gbrIndexed bld
    storeMem bld addr ((loadMem bld 8<rt> addr) .& numByte imm)
  }

let bf (ins: Instruction) len bld =
  lift bld ins len {
    let target = pcRelTarget ins 8
    let fallThrough = numAddr (ins.Address + uint64 len)
    (* Plain bf and bt have no delay slot, so they transfer control at once. *)
    AST.intercjmp (AST.not (regVar bld R.T)) target fallThrough
  }

let bfs (ins: Instruction) len bld =
  lift bld ins len {
    let target = pcRelTarget ins 8
    (* The delay slot runs either way, so the untaken path resumes past it. *)
    let fallThrough = numAddr (ins.Address + 4UL)
    regVar bld R.NPC :=
      AST.ite (AST.not (regVar bld R.T)) target fallThrough
    arm bld InterJmpKind.Base
  }

let bra (ins: Instruction) len bld =
  lift bld ins len {
    regVar bld R.NPC := pcRelTarget ins 12
    arm bld InterJmpKind.Base
  }

let braf (ins: Instruction) len bld =
  lift bld ins len {
    let src = oneReg ins bld
    regVar bld R.NPC := numAddr (ins.Address + 4UL) .+ src
    arm bld InterJmpKind.Base
  }

let bsr (ins: Instruction) len bld =
  lift bld ins len {
    regVar bld R.PR := numAddr (ins.Address + 4UL)
    regVar bld R.NPC := pcRelTarget ins 12
    arm bld InterJmpKind.IsCall
  }

let bsrf (ins: Instruction) len bld =
  lift bld ins len {
    let src = oneReg ins bld
    regVar bld R.PR := numAddr (ins.Address + 4UL)
    regVar bld R.NPC := numAddr (ins.Address + 4UL) .+ src
    arm bld InterJmpKind.IsCall
  }

let bt (ins: Instruction) len bld =
  lift bld ins len {
    let target = pcRelTarget ins 8
    let fallThrough = numAddr (ins.Address + uint64 len)
    AST.intercjmp (regVar bld R.T) target fallThrough
  }

let bts (ins: Instruction) len bld =
  lift bld ins len {
    let target = pcRelTarget ins 8
    let fallThrough = numAddr (ins.Address + 4UL)
    regVar bld R.NPC := AST.ite (regVar bld R.T) target fallThrough
    arm bld InterJmpKind.Base
  }

let clrmac (ins: Instruction) len bld =
  lift bld ins len {
    regVar bld R.MACH := num 0
    regVar bld R.MACL := num 0
  }

let clrs (ins: Instruction) len bld =
  lift bld ins len {
    regVar bld R.S := AST.b0
  }

let clrt (ins: Instruction) len bld =
  lift bld ins len {
    regVar bld R.T := AST.b0
  }

let cmpeq (ins: Instruction) len bld =
  lift bld ins len {
    let struct (o1, o2) = getTwoOprs ins
    let dst = regOf bld o2
    match o1 with
    | OpReg(Imm imm) ->
      append bld { regVar bld R.T := (dst == num (signExtend 8 imm)) }
    | _ ->
      append bld { regVar bld R.T := (dst == regOf bld o1) }
  }

let cmpge (ins: Instruction) len bld =
  lift bld ins len {
    let struct (src, dst) = twoRegs ins bld
    regVar bld R.T := (dst ?>= src)
  }

let cmpgt (ins: Instruction) len bld =
  lift bld ins len {
    let struct (src, dst) = twoRegs ins bld
    regVar bld R.T := (dst ?> src)
  }

let cmphi (ins: Instruction) len bld =
  lift bld ins len {
    let struct (src, dst) = twoRegs ins bld
    regVar bld R.T := (dst .> src)
  }

let cmphs (ins: Instruction) len bld =
  lift bld ins len {
    let struct (src, dst) = twoRegs ins bld
    regVar bld R.T := (dst .>= src)
  }

let cmppl (ins: Instruction) len bld =
  lift bld ins len {
    let dst = oneReg ins bld
    regVar bld R.T := (dst ?> num 0)
  }

let cmppz (ins: Instruction) len bld =
  lift bld ins len {
    let dst = oneReg ins bld
    regVar bld R.T := (dst ?>= num 0)
  }

let cmpstr (ins: Instruction) len bld =
  lift bld ins len {
    let struct (src, dst) = twoRegs ins bld
    let diff = tmpVar bld 32<rt>
    (* Any byte the two registers share leaves that byte of the difference zero,
       which is what a string scan looks for. *)
    diff := dst <+> src
    regVar bld R.T :=
      (((AST.xtlo 8<rt> diff == AST.num0 8<rt>)
        .| (AST.extract diff 8<rt> 8 == AST.num0 8<rt>))
       .| ((AST.extract diff 8<rt> 16 == AST.num0 8<rt>)
           .| (AST.extract diff 8<rt> 24 == AST.num0 8<rt>)))
  }

let div0s (ins: Instruction) len bld =
  lift bld ins len {
    let struct (src, dst) = twoRegs ins bld
    let q = regVar bld R.Q
    let m = regVar bld R.M
    q := AST.xthi 1<rt> dst
    m := AST.xthi 1<rt> src
    regVar bld R.T := (q <+> m)
  }

let div0u (ins: Instruction) len bld =
  lift bld ins len {
    regVar bld R.M := AST.b0
    regVar bld R.Q := AST.b0
    regVar bld R.T := AST.b0
  }

let div1 (ins: Instruction) len bld =
  lift bld ins len {
    let struct (src, dst) = twoRegs ins bld
    let q = regVar bld R.Q
    let m = regVar bld R.M
    let t = regVar bld R.T
    let struct (oldQ, shiftedIn, doSub, borrow) = tmpVars4 bld 1<rt>
    let struct (shifted, res) = tmpVars2 bld 32<rt>
    (* One non-restoring division step. The dividend shifts left through T, then
       the divisor is subtracted when the running quotient bit and the divisor's
       sign agree and added when they differ; the manual's four-way switch on
       the old Q and M collapses to that choice plus a parity update of Q. *)
    oldQ := q
    shiftedIn := AST.xthi 1<rt> dst
    shifted := (dst << num 1) .| (AST.zext 32<rt> t)
    doSub := (oldQ == m)
    res := AST.ite doSub (shifted .- src) (shifted .+ src)
    borrow := AST.ite doSub (res .> shifted) (res .< shifted)
    dst := res
    q := ((shiftedIn <+> borrow) <+> m)
    t := (q == m)
  }

let dmulsl (ins: Instruction) len bld =
  lift bld ins len {
    let struct (src, dst) = twoRegs ins bld
    let res = tmpVar bld 64<rt>
    res := (AST.sext 64<rt> dst) .* (AST.sext 64<rt> src)
    regVar bld R.MACL := AST.xtlo 32<rt> res
    regVar bld R.MACH := AST.xthi 32<rt> res
  }

let dmulul (ins: Instruction) len bld =
  lift bld ins len {
    let struct (src, dst) = twoRegs ins bld
    let res = tmpVar bld 64<rt>
    res := (AST.zext 64<rt> dst) .* (AST.zext 64<rt> src)
    regVar bld R.MACL := AST.xtlo 32<rt> res
    regVar bld R.MACH := AST.xthi 32<rt> res
  }

let dt (ins: Instruction) len bld =
  lift bld ins len {
    let dst = oneReg ins bld
    dst := dst .- num 1
    regVar bld R.T := (dst == num 0)
  }

let extsb (ins: Instruction) len bld =
  lift bld ins len {
    let struct (src, dst) = twoRegs ins bld
    dst := AST.xtlo 8<rt> src |> AST.sext 32<rt>
  }

let extsw (ins: Instruction) len bld =
  lift bld ins len {
    let struct (src, dst) = twoRegs ins bld
    dst := AST.xtlo 16<rt> src |> AST.sext 32<rt>
  }

let extub (ins: Instruction) len bld =
  lift bld ins len {
    let struct (src, dst) = twoRegs ins bld
    dst := AST.xtlo 8<rt> src |> AST.zext 32<rt>
  }

let extuw (ins: Instruction) len bld =
  lift bld ins len {
    let struct (src, dst) = twoRegs ins bld
    dst := AST.xtlo 16<rt> src |> AST.zext 32<rt>
  }

/// The FPSCR bit that makes the arithmetic double-precision.
let [<Literal>] private PrBit = 19

/// The FPSCR bit that makes a floating-point transfer sixty-four bits wide.
let [<Literal>] private SzBit = 20

/// An FPSCR mode bit. The fields are read out of FPSCR itself rather than the
/// separate one-bit registers the register file also defines, because an lds to
/// FPSCR writes the whole word and would leave those behind.
let private fpscrBit bld pos = AST.extract (regVar bld R.FPSCR) 1<rt> pos

/// The number of a floating-point register operand. FR0 through FR15 count
/// themselves; a double-precision register counts as the first of the two
/// single-precision registers it spans.
let private fpNum r =
  if r >= R.FR0 && r <= R.FR15 then int r - int R.FR0
  elif r >= R.DR0 && r <= R.DR14 then (int r - int R.DR0) * 2
  else raise InvalidOperandException

/// The single-precision register with the given number.
let private frOfNum n: Register = LanguagePrimitives.EnumOfValue(int R.FR0 + n)

/// Whether a floating-point operand names an odd-numbered register. A double
/// occupies an even-numbered pair, so under a double-precision or wide-transfer
/// mode an odd number either reaches the second register bank -- which nothing
/// here models -- or names an encoding the architecture leaves undefined.
let private isOddFpNum r = fpNum r % 2 = 1

/// The two single-precision registers a double-precision operand spans: SH4
/// pairs them with the even-numbered one holding the upper half.
let private doubleHalves bld r =
  let n = fpNum r
  struct (regVar bld (frOfNum n), regVar bld (frOfNum (n + 1)))

/// The sixty-four-bit value a double-precision operand holds, read out of the
/// pair it spans.
let private doubleOf bld r =
  let struct (hi, lo) = doubleHalves bld r
  ((AST.zext 64<rt> hi) << num64 32) .| (AST.zext 64<rt> lo)

/// Writes a sixty-four-bit result into the pair a double-precision operand
/// spans. The value must already sit in a temporary: writing the upper half
/// first would otherwise change what an expression over the pair still reads.
let private setDouble bld r v =
  append bld {
    let struct (hi, lo) = doubleHalves bld r
    hi := AST.xthi 32<rt> v
    lo := AST.xtlo 32<rt> v
  }

/// Emits an instruction that an FPSCR mode bit gives two meanings: `off` runs
/// when the bit is clear and `on` when it is set. The paths differ in which
/// registers they write and in how wide their memory accesses are, so a single
/// result selected by an ite cannot express them -- and a parser cannot choose
/// between them at all, the bit being state the program writes at run time.
let private byMode bld pos off on =
  append bld {
    let lblOn = label bld "ModeOn"
    let lblOff = label bld "ModeOff"
    let lblEnd = label bld "ModeEnd"
    AST.cjmp (fpscrBit bld pos) (AST.jmpDest lblOn) (AST.jmpDest lblOff)
    AST.lmark lblOff
    off ()
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblOn
    on ()
    AST.lmark lblEnd
  }

/// Reports the wide path of an odd-numbered operand as unsupported: it names
/// the second register bank, which nothing here models. Only a program that
/// actually sets the mode bit runs into it.
let private unsupportedBank bld =
  append bld { AST.sideEffect UnsupportedInstruction }

/// The sign bit of a floating-point value, which fabs clears and fneg flips.
/// Both work the same at either precision, since a double keeps its sign bit in
/// the upper half -- the very register the operand names.
let [<Literal>] private SignBit = 0x80000000

let fabs (ins: Instruction) len bld =
  lift bld ins len {
    let dst = oneReg ins bld
    dst := dst .& num (~~~SignBit)
  }

/// Lifts a floating-point operation over two registers whose width FPSCR.PR
/// picks, given how to combine two values of that width.
let private fpBinary (ins: Instruction) len bld op =
  lift bld ins len {
    let struct (o1, o2) = getTwoOprs ins
    let m = regEnumOf o1
    let n = regEnumOf o2
    byMode bld PrBit
      (fun () ->
        append bld { regVar bld n := op (regVar bld n) (regVar bld m) })
      (fun () ->
        if isOddFpNum m || isOddFpNum n then
          unsupportedBank bld
        else
          let res = tmpVar bld 64<rt>
          append bld {
            res := op (doubleOf bld n) (doubleOf bld m)
          }
          setDouble bld n res)
  }

let fadd ins len bld = fpBinary ins len bld AST.fadd

/// Lifts a floating-point comparison whose width FPSCR.PR picks; either width
/// leaves the answer in T.
let private fpCompare (ins: Instruction) len bld cmp =
  lift bld ins len {
    let struct (o1, o2) = getTwoOprs ins
    let m = regEnumOf o1
    let n = regEnumOf o2
    byMode bld PrBit
      (fun () ->
        append bld { regVar bld R.T := cmp (regVar bld n) (regVar bld m) })
      (fun () ->
        if isOddFpNum m || isOddFpNum n then
          unsupportedBank bld
        else
          let res = cmp (doubleOf bld n) (doubleOf bld m)
          append bld { regVar bld R.T := res })
  }

let fcmpeq ins len bld = fpCompare ins len bld AST.feq

let fcmpgt ins len bld = fpCompare ins len bld AST.fgt

/// Converts the double-precision value a register pair holds to single
/// precision in FPUL. The architecture defines it only while FPSCR.PR is set,
/// so it takes no mode branch, and the operand names an even register by
/// construction.
let fcnvds (ins: Instruction) len bld =
  lift bld ins len {
    let struct (o1, o2) = getTwoOprs ins
    let src = doubleOf bld (regEnumOf o1)
    let dst = regOf bld o2
    dst := AST.cast CastKind.FloatCast 32<rt> src
  }

/// Converts the single-precision value in FPUL to double precision in a
/// register pair, the counterpart of fcnvds.
let fcnvsd (ins: Instruction) len bld =
  lift bld ins len {
    let struct (o1, o2) = getTwoOprs ins
    let src = regOf bld o1
    let res = tmpVar bld 64<rt>
    res := AST.cast CastKind.FloatCast 64<rt> src
    setDouble bld (regEnumOf o2) res
  }

let fdiv ins len bld = fpBinary ins len bld AST.fdiv

let fipr ins _len _bld = notLifted ins

/// The single-precision encoding of 0.0, which fldi0 loads.
let [<Literal>] private SingleZero = 0x00000000

/// The single-precision encoding of 1.0, which fldi1 loads.
let [<Literal>] private SingleOne = 0x3F800000

let fldi0 (ins: Instruction) len bld =
  lift bld ins len {
    let dst = oneReg ins bld
    dst := num SingleZero
  }

let fldi1 (ins: Instruction) len bld =
  lift bld ins len {
    let dst = oneReg ins bld
    dst := num SingleOne
  }

let flds ins len bld = moveReg ins len bld

let ``float`` (ins: Instruction) len bld =
  lift bld ins len {
    let struct (o1, o2) = getTwoOprs ins
    let src = regOf bld o1
    let n = regEnumOf o2
    byMode bld PrBit
      (fun () ->
        append bld { regVar bld n := AST.cast CastKind.SIntToFloat 32<rt> src })
      (fun () ->
        if isOddFpNum n then
          unsupportedBank bld
        else
          let res = tmpVar bld 64<rt>
          append bld {
            res := AST.cast CastKind.SIntToFloat 64<rt> src
          }
          setDouble bld n res)
  }

let fmac (ins: Instruction) len bld =
  lift bld ins len {
    let struct (o1, o2, o3) =
      match ins.Operands with
      | ThreeOperands(a, b, c) -> struct (a, b, c)
      | _ -> raise InvalidOperandException
    let fr0 = regOf bld o1
    let src = regOf bld o2
    let dst = regOf bld o3
    dst := AST.fadd (AST.fmul fr0 src) dst
  }

/// The floating-point register a transfer between memory and the register file
/// names: whichever side of the operand pair is a plain register, the other
/// being the memory operand.
let private fpMemReg o1 o2 =
  match o1, o2 with
  | OpReg(Regdir r), _ -> r
  | _, OpReg(Regdir r) -> r
  | _ -> raise InvalidOperandException

/// Emits a sixty-four-bit transfer between memory and the register pair a
/// double-precision operand spans, the wide counterpart of what movMemBody
/// emits at thirty-two bits.
let private fpMemDouble (ins: Instruction) bld =
  let struct (o1, o2) = getTwoOprs ins
  if isOddFpNum (fpMemReg o1 o2) then
    unsupportedBank bld
  else
    let value = tmpVar bld 64<rt>
    match o1, o2 with
    | OpReg(Regdir m), OpReg(RegIndir n) ->
      append bld {
        storeMem bld (regVar bld n) (doubleOf bld m)
      }
    | OpReg(Regdir m), OpReg(RegIndirPreDec n) ->
      let addr = tmpVar bld 32<rt>
      append bld {
        addr := regVar bld n .- num 8
        storeMem bld addr (doubleOf bld m)
        regVar bld n := addr
      }
    | OpReg(Regdir m), OpReg(IdxRegIndir(idx, n)) ->
      let addr = regVar bld idx .+ regVar bld n
      append bld {
        storeMem bld addr (doubleOf bld m)
      }
    | OpReg(RegIndir m), OpReg(Regdir n) ->
      append bld {
        value := loadMem bld 64<rt> (regVar bld m)
      }
      setDouble bld n value
    | OpReg(RegIndirPostInc m), OpReg(Regdir n) ->
      append bld {
        value := loadMem bld 64<rt> (regVar bld m)
        regVar bld m := regVar bld m .+ num 8
      }
      setDouble bld n value
    | OpReg(IdxRegIndir(idx, m)), OpReg(Regdir n) ->
      append bld {
        value := loadMem bld 64<rt> (regVar bld idx .+ regVar bld m)
      }
      setDouble bld n value
    | _ ->
      raise InvalidOperandException

/// Lifts a floating-point move, whose width FPSCR.SZ picks: thirty-two bits
/// between single-precision registers, or sixty-four between the pairs they
/// span -- which also changes how much memory a transfer touches and how far a
/// post-increment or pre-decrement steps.
let private fpMove (ins: Instruction) len bld =
  lift bld ins len {
    match ins.Operands with
    | TwoOperands(OpReg(Regdir m), OpReg(Regdir n)) ->
      byMode bld SzBit
        (fun () -> append bld { regVar bld n := regVar bld m })
        (fun () ->
          if isOddFpNum m || isOddFpNum n then
            unsupportedBank bld
          else
            let value = tmpVar bld 64<rt>
            append bld {
              value := doubleOf bld m
            }
            setDouble bld n value)
    | _ ->
      byMode bld
        SzBit
        (fun () -> movMemBody ins bld 32<rt>)
        (fun () -> fpMemDouble ins bld)
  }

let fmov ins len bld = fpMove ins len bld

let fmovs ins len bld = fpMove ins len bld

let fmul ins len bld = fpBinary ins len bld AST.fmul

let fneg (ins: Instruction) len bld =
  lift bld ins len {
    let dst = oneReg ins bld
    dst := dst <+> num SignBit
  }

let frchg ins _len _bld = notLifted ins

/// Flips FPSCR.SZ, so that the transfers which read it move the other width
/// from here on.
let fschg (ins: Instruction) len bld =
  lift bld ins len {
    let fpscr = regVar bld R.FPSCR
    fpscr := fpscr <+> num (1 <<< SzBit)
  }

let fsqrt (ins: Instruction) len bld =
  lift bld ins len {
    let n = getOneOpr ins |> regEnumOf
    byMode bld PrBit
      (fun () -> append bld { regVar bld n := AST.fsqrt (regVar bld n) })
      (fun () ->
        if isOddFpNum n then
          unsupportedBank bld
        else
          let res = tmpVar bld 64<rt>
          append bld {
            res := AST.fsqrt (doubleOf bld n)
          }
          setDouble bld n res)
  }

let fsts ins len bld = moveReg ins len bld

let fsub ins len bld = fpBinary ins len bld AST.fsub

let ftrc (ins: Instruction) len bld =
  lift bld ins len {
    let struct (o1, o2) = getTwoOprs ins
    let m = regEnumOf o1
    let dst = regOf bld o2
    byMode bld PrBit
      (fun () ->
        append bld { dst := AST.cast CastKind.FtoITrunc 32<rt> (regVar bld m) })
      (fun () ->
        if isOddFpNum m then
          unsupportedBank bld
        else
          let d = doubleOf bld m
          append bld { dst := AST.cast CastKind.FtoITrunc 32<rt> d })
  }

let ftrv ins _len _bld = notLifted ins

/// The register a register-indirect operand names.
let private indirOf bld = function
  | OpReg(RegIndir r) -> regVar bld r
  | _ -> raise InvalidOperandException

let jmp (ins: Instruction) len bld =
  lift bld ins len {
    let src = getOneOpr ins |> indirOf bld
    regVar bld R.NPC := src
    arm bld InterJmpKind.Base
  }

let jsr (ins: Instruction) len bld =
  lift bld ins len {
    let src = getOneOpr ins |> indirOf bld
    regVar bld R.PR := numAddr (ins.Address + 4UL)
    regVar bld R.NPC := src
    arm bld InterJmpKind.IsCall
  }

/// Loads a control or system register from @Rm+, the form ldc.l and lds.l
/// share.
let private loadPostInc (ins: Instruction) len bld =
  lift bld ins len {
    let struct (o1, o2) = getTwoOprs ins
    let dst = regOf bld o2
    let src =
      match o1 with
      | OpReg(RegIndirPostInc r) -> regVar bld r
      | _ -> raise InvalidOperandException
    dst := loadMem bld 32<rt> src
    src := src .+ num 4
  }

/// Stores a control or system register to @-Rn, the form stc.l and sts.l
/// share.
let private storePreDec (ins: Instruction) len bld =
  lift bld ins len {
    let struct (o1, o2) = getTwoOprs ins
    let src = regOf bld o1
    let dst =
      match o2 with
      | OpReg(RegIndirPreDec r) -> regVar bld r
      | _ -> raise InvalidOperandException
    let addr = tmpVar bld 32<rt>
    addr := dst .- num 4
    storeMem bld addr src
    dst := addr
  }

let ldc ins len bld = moveReg ins len bld

let ldcl ins len bld = loadPostInc ins len bld

let lds ins len bld = moveReg ins len bld

let ldsl ins len bld = loadPostInc ins len bld

let ldtlb ins _len _bld = notLifted ins

/// The register a post-increment operand names, which the multiply-accumulate
/// instructions read both of their operands through.
let private postIncOf bld = function
  | OpReg(RegIndirPostInc r) -> regVar bld r
  | _ -> raise InvalidOperandException

let macl (ins: Instruction) len bld =
  lift bld ins len {
    let struct (o1, o2) = getTwoOprs ins
    let src = postIncOf bld o1
    let dst = postIncOf bld o2
    let mach = regVar bld R.MACH
    let macl = regVar bld R.MACL
    let struct (vn, vm) = tmpVars2 bld 32<rt>
    let struct (mac, saturated) = tmpVars2 bld 64<rt>
    (* The reads and the updates interleave as the manual has them, so that a
       mac.l @Rn+,@Rn+ naming one register twice reads two successive longwords
       and advances it by eight. *)
    vn := loadMem bld 32<rt> dst
    dst := dst .+ num 4
    vm := loadMem bld 32<rt> src
    src := src .+ num 4
    mac := ((AST.zext 64<rt> mach) << num64 32) .| (AST.zext 64<rt> macl)
    mac := mac .+ ((AST.sext 64<rt> vn) .* (AST.sext 64<rt> vm))
    (* With S set the accumulator saturates to a signed forty-eight-bit
       range. *)
    saturated :=
      AST.ite (mac ?> num64 0x7FFFFFFF)
              (numI64 0x00007FFFFFFFFFFFL 64<rt>)
              (AST.ite (mac ?< num64 -0x80000000)
                       (numI64 0xFFFF800000000000L 64<rt>)
                       mac)
    mac := AST.ite (regVar bld R.S) saturated mac
    macl := AST.xtlo 32<rt> mac
    mach := AST.xthi 32<rt> mac
  }

let macw (ins: Instruction) len bld =
  lift bld ins len {
    let struct (o1, o2) = getTwoOprs ins
    let src = postIncOf bld o1
    let dst = postIncOf bld o2
    let mach = regVar bld R.MACH
    let macl = regVar bld R.MACL
    let struct (vn, vm) = tmpVars2 bld 16<rt>
    let prod = tmpVar bld 32<rt>
    let struct (mac, sum) = tmpVars2 bld 64<rt>
    let satL = tmpVar bld 32<rt>
    vn := loadMem bld 16<rt> dst
    dst := dst .+ num 2
    vm := loadMem bld 16<rt> src
    src := src .+ num 2
    prod := (AST.sext 32<rt> vn) .* (AST.sext 32<rt> vm)
    mac := ((AST.zext 64<rt> mach) << num64 32) .| (AST.zext 64<rt> macl)
    mac := mac .+ (AST.sext 64<rt> prod)
    (* With S set mac.w saturates the low half alone and leaves MACH be. *)
    sum := (AST.sext 64<rt> macl) .+ (AST.sext 64<rt> prod)
    satL :=
      AST.ite (sum ?> num64 0x7FFFFFFF)
              (num 0x7FFFFFFF)
              (AST.ite (sum ?< num64 -0x80000000)
                       (num 0x80000000)
                       (AST.xtlo 32<rt> sum))
    macl := AST.ite (regVar bld R.S) satL (AST.xtlo 32<rt> mac)
    mach := AST.ite (regVar bld R.S) mach (AST.xthi 32<rt> mac)
  }

let mov (ins: Instruction) len bld =
  lift bld ins len {
    let struct (o1, o2) = getTwoOprs ins
    let dst = regOf bld o2
    match o1 with
    | OpReg(Imm imm) -> append bld { dst := num (signExtend 8 imm) }
    | _ -> append bld { dst := regOf bld o1 }
  }

let mova (ins: Instruction) len bld =
  lift bld ins len {
    let struct (o1, _) = getTwoOprs ins
    let disp =
      match o1 with
      | OpReg(PCRelDisp(d, _)) -> d
      | _ -> raise InvalidOperandException
    regVar bld R.R0 := numU32 (pcRelLongAddr ins disp) 32<rt>
  }

let movb ins len bld = movMem ins len bld 8<rt>

let movw ins len bld = movMem ins len bld 16<rt>

let movl ins len bld = movMem ins len bld 32<rt>

let movcal ins len bld = movMem ins len bld 32<rt>

let movt (ins: Instruction) len bld =
  lift bld ins len {
    let dst = oneReg ins bld
    dst := AST.zext 32<rt> (regVar bld R.T)
  }

let mull (ins: Instruction) len bld =
  lift bld ins len {
    let struct (src, dst) = twoRegs ins bld
    regVar bld R.MACL := dst .* src
  }

let mulsw (ins: Instruction) len bld =
  lift bld ins len {
    let struct (src, dst) = twoRegs ins bld
    regVar bld R.MACL :=
      (AST.xtlo 16<rt> dst |> AST.sext 32<rt>)
      .* (AST.xtlo 16<rt> src |> AST.sext 32<rt>)
  }

let muluw (ins: Instruction) len bld =
  lift bld ins len {
    let struct (src, dst) = twoRegs ins bld
    regVar bld R.MACL :=
      (AST.xtlo 16<rt> dst |> AST.zext 32<rt>)
      .* (AST.xtlo 16<rt> src |> AST.zext 32<rt>)
  }

let neg (ins: Instruction) len bld =
  lift bld ins len {
    let struct (src, dst) = twoRegs ins bld
    dst := num 0 .- src
  }

let negc (ins: Instruction) len bld =
  lift bld ins len {
    let struct (src, dst) = twoRegs ins bld
    let t = regVar bld R.T
    let struct (negated, res) = tmpVars2 bld 32<rt>
    negated := num 0 .- src
    res := negated .- (AST.zext 32<rt> t)
    t := ((num 0 .< negated) .| (negated .< res))
    dst := res
  }

let nop (ins: Instruction) len bld =
  lift bld ins len {
  }

let ``not`` (ins: Instruction) len bld =
  lift bld ins len {
    let struct (src, dst) = twoRegs ins bld
    dst := AST.not src
  }

/// Lifts a cache-control instruction, which only hints at what the cache should
/// hold and so changes no state this emulator models.
let private cacheHint (ins: Instruction) len bld =
  lift bld ins len {
  }

let ocbi ins len bld = cacheHint ins len bld

let ocbp ins len bld = cacheHint ins len bld

let ocbwb ins len bld = cacheHint ins len bld

let ``or`` (ins: Instruction) len bld =
  lift bld ins len {
    let struct (o1, o2) = getTwoOprs ins
    let dst = regOf bld o2
    match o1 with
    | OpReg(Imm imm) -> append bld { dst := dst .| num imm }
    | _ -> append bld { dst := dst .| regOf bld o1 }
  }

let orb (ins: Instruction) len bld =
  lift bld ins len {
    let struct (o1, _) = getTwoOprs ins
    let imm = immOf o1
    let addr = tmpVar bld 32<rt>
    addr := gbrIndexed bld
    storeMem bld addr ((loadMem bld 8<rt> addr) .| numByte imm)
  }

let pref ins len bld = cacheHint ins len bld

let rotcl (ins: Instruction) len bld =
  lift bld ins len {
    let dst = oneReg ins bld
    let t = regVar bld R.T
    let carry = tmpVar bld 1<rt>
    carry := AST.xthi 1<rt> dst
    dst := (dst << num 1) .| (AST.zext 32<rt> t)
    t := carry
  }

let rotcr (ins: Instruction) len bld =
  lift bld ins len {
    let dst = oneReg ins bld
    let t = regVar bld R.T
    let carry = tmpVar bld 1<rt>
    carry := AST.xtlo 1<rt> dst
    dst := (dst >> num 1) .| ((AST.zext 32<rt> t) << num 31)
    t := carry
  }

let rotl (ins: Instruction) len bld =
  lift bld ins len {
    let dst = oneReg ins bld
    let carry = tmpVar bld 1<rt>
    carry := AST.xthi 1<rt> dst
    dst := (dst << num 1) .| (AST.zext 32<rt> carry)
    regVar bld R.T := carry
  }

let rotr (ins: Instruction) len bld =
  lift bld ins len {
    let dst = oneReg ins bld
    let carry = tmpVar bld 1<rt>
    carry := AST.xtlo 1<rt> dst
    dst := (dst >> num 1) .| ((AST.zext 32<rt> carry) << num 31)
    regVar bld R.T := carry
  }

let rte ins _len _bld = notLifted ins

let rts (ins: Instruction) len bld =
  lift bld ins len {
    regVar bld R.NPC := regVar bld R.PR
    arm bld InterJmpKind.IsRet
  }

let sets (ins: Instruction) len bld =
  lift bld ins len {
    regVar bld R.S := AST.b1
  }

let sett (ins: Instruction) len bld =
  lift bld ins len {
    regVar bld R.T := AST.b1
  }

let shad (ins: Instruction) len bld =
  lift bld ins len {
    let struct (src, dst) = twoRegs ins bld
    let struct (left, right, amount) = tmpVars3 bld 32<rt>
    let wide = tmpVar bld 64<rt>
    (* A negative count shifts right by its magnitude, and a count of minus
       thirty-two -- a zero in the low five bits -- fills the register with the
       sign bit. Shifting the sign-extended sixty-four-bit value keeps that
       thirty-two-bit shift defined. *)
    left := dst << (src .& num 0x1F)
    amount := ((AST.not src) .& num 0x1F) .+ num 1
    wide := (AST.sext 64<rt> dst) ?>> (AST.zext 64<rt> amount)
    right := AST.xtlo 32<rt> wide
    dst := AST.ite (AST.xthi 1<rt> src == AST.b0) left right
  }

let shal (ins: Instruction) len bld =
  lift bld ins len {
    let dst = oneReg ins bld
    regVar bld R.T := AST.xthi 1<rt> dst
    dst := dst << num 1
  }

let shar (ins: Instruction) len bld =
  lift bld ins len {
    let dst = oneReg ins bld
    regVar bld R.T := AST.xtlo 1<rt> dst
    dst := dst ?>> num 1
  }

let shld (ins: Instruction) len bld =
  lift bld ins len {
    let struct (src, dst) = twoRegs ins bld
    let struct (left, right, amount) = tmpVars3 bld 32<rt>
    let wide = tmpVar bld 64<rt>
    left := dst << (src .& num 0x1F)
    amount := ((AST.not src) .& num 0x1F) .+ num 1
    wide := (AST.zext 64<rt> dst) >> (AST.zext 64<rt> amount)
    right := AST.xtlo 32<rt> wide
    dst := AST.ite (AST.xthi 1<rt> src == AST.b0) left right
  }

let shll (ins: Instruction) len bld =
  lift bld ins len {
    let dst = oneReg ins bld
    regVar bld R.T := AST.xthi 1<rt> dst
    dst := dst << num 1
  }

/// Shifts by a fixed count, which unlike a shift by one leaves T alone.
let private shiftFixed (ins: Instruction) len bld count isLeft =
  lift bld ins len {
    let dst = oneReg ins bld
    if isLeft then append bld { dst := dst << num count }
    else append bld { dst := dst >> num count }
  }

let shll2 ins len bld = shiftFixed ins len bld 2 true

let shll8 ins len bld = shiftFixed ins len bld 8 true

let shll16 ins len bld = shiftFixed ins len bld 16 true

let shlr (ins: Instruction) len bld =
  lift bld ins len {
    let dst = oneReg ins bld
    regVar bld R.T := AST.xtlo 1<rt> dst
    dst := dst >> num 1
  }

let shlr2 ins len bld = shiftFixed ins len bld 2 false

let shlr8 ins len bld = shiftFixed ins len bld 8 false

let shlr16 ins len bld = shiftFixed ins len bld 16 false

let sleep ins _len _bld = notLifted ins

let stc ins len bld = moveReg ins len bld

let stcl ins len bld = storePreDec ins len bld

let sts ins len bld = moveReg ins len bld

let stsl ins len bld = storePreDec ins len bld

let sub (ins: Instruction) len bld =
  lift bld ins len {
    let struct (src, dst) = twoRegs ins bld
    dst := dst .- src
  }

let subc (ins: Instruction) len bld =
  lift bld ins len {
    let struct (src, dst) = twoRegs ins bld
    let t = regVar bld R.T
    let struct (diff, res) = tmpVars2 bld 32<rt>
    diff := dst .- src
    res := diff .- (AST.zext 32<rt> t)
    t := ((dst .< diff) .| (diff .< res))
    dst := res
  }

let subv (ins: Instruction) len bld =
  lift bld ins len {
    let struct (src, dst) = twoRegs ins bld
    let res = tmpVar bld 32<rt>
    res := dst .- src
    (* A signed difference overflows exactly when the operands differ in sign
       and the result does not match the minuend's. *)
    regVar bld R.T :=
      ((AST.xthi 1<rt> dst != AST.xthi 1<rt> src)
       .& (AST.xthi 1<rt> res != AST.xthi 1<rt> dst))
    dst := res
  }

let swapb (ins: Instruction) len bld =
  lift bld ins len {
    let struct (src, dst) = twoRegs ins bld
    dst := (src .& num 0xFFFF0000)
           .| (((src .& num 0xFF) << num 8)
               .| ((src >> num 8) .& num 0xFF))
  }

let swapw (ins: Instruction) len bld =
  lift bld ins len {
    let struct (src, dst) = twoRegs ins bld
    dst := (src << num 16) .| (src >> num 16)
  }

let tasb (ins: Instruction) len bld =
  lift bld ins len {
    let addr = getOneOpr ins |> indirOf bld
    let value = tmpVar bld 8<rt>
    value := loadMem bld 8<rt> addr
    regVar bld R.T := (value == AST.num0 8<rt>)
    storeMem bld addr (value .| numByte 0x80)
  }

let trapa (ins: Instruction) len bld =
  lift bld ins len {
    let imm = getOneOpr ins |> immOf
    (* Linux reads the trap number out of TRA, shifted up by two as the hardware
       leaves it there. *)
    regVar bld R.TRA := num (imm <<< 2)
    AST.sideEffect SysCall
  }

let tst (ins: Instruction) len bld =
  lift bld ins len {
    let struct (o1, o2) = getTwoOprs ins
    let dst = regOf bld o2
    match o1 with
    | OpReg(Imm imm) ->
      append bld { regVar bld R.T := ((dst .& num imm) == num 0) }
    | _ ->
      append bld { regVar bld R.T := ((dst .& regOf bld o1) == num 0) }
  }

let tstb (ins: Instruction) len bld =
  lift bld ins len {
    let struct (o1, _) = getTwoOprs ins
    let imm = immOf o1
    let addr = tmpVar bld 32<rt>
    addr := gbrIndexed bld
    regVar bld R.T :=
      (((loadMem bld 8<rt> addr) .& numByte imm) == AST.num0 8<rt>)
  }

let xor (ins: Instruction) len bld =
  lift bld ins len {
    let struct (o1, o2) = getTwoOprs ins
    let dst = regOf bld o2
    match o1 with
    | OpReg(Imm imm) -> append bld { dst := dst <+> num imm }
    | _ -> append bld { dst := dst <+> regOf bld o1 }
  }

let xorb (ins: Instruction) len bld =
  lift bld ins len {
    let struct (o1, _) = getTwoOprs ins
    let imm = immOf o1
    let addr = tmpVar bld 32<rt>
    addr := gbrIndexed bld
    storeMem bld addr ((loadMem bld 8<rt> addr) <+> numByte imm)
  }

let xtrct (ins: Instruction) len bld =
  lift bld ins len {
    let struct (src, dst) = twoRegs ins bld
    dst := (src << num 16) .| (dst >> num 16)
  }
