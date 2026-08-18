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
/// branch can name where its delay slot must appear. Shadows LiftingUtils's
/// <!-- below.
let (<!--) (bld: ILowUIRBuilder) (addr, insLen) =
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
/// The transfer's own end (Armed) defers; the delay slot's end flushes. Shadows
/// LiftingUtils's --!> below.
let (--!>) (bld: ILowUIRBuilder) insLen =
  match bld with
  | :? LowUIRBuilder as sbld ->
    if sbld.DelayedBranch <> InterJmpKind.NotAJmp then
      if sbld.Armed then
        sbld.Armed <- false
        sbld.DelaySlotAddr <- ValueSome(sbld.CurAddr + uint64 insLen)
      else
        bld <+ (AST.interjmp (regVar bld R.NPC) sbld.DelayedBranch)
        sbld.Disarm()
    else
      ()
    bld.Stream.MarkEnd insLen
    bld
  | _ ->
    bld.Stream.MarkEnd insLen
    bld

/// Arms a delayed control transfer of the given kind; its target must already
/// have been stored into NPC. The following --!> (after the delay slot) emits
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
    bld <+ (storeMem bld (regVar bld n) (storeVal rt (regVar bld m)))
  | OpReg(Regdir m), OpReg(RegIndirPreDec n) ->
    let addr = tmpVar bld 32<rt>
    (* The stored value is the source as it was, so pushing a register onto its
       own stack pointer writes the pointer the push started from. *)
    bld <+ (addr := regVar bld n .- num step)
    bld <+ (storeMem bld addr (storeVal rt (regVar bld m)))
    bld <+ (regVar bld n := addr)
  | OpReg(Regdir m), OpReg(IdxRegIndir(idx, n)) ->
    let addr = regVar bld idx .+ regVar bld n
    bld <+ (storeMem bld addr (storeVal rt (regVar bld m)))
  | OpReg(Regdir m), OpReg(GBRIndirDisp(disp, gbr)) ->
    let addr = regVar bld gbr .+ num (disp * step)
    bld <+ (storeMem bld addr (storeVal rt (regVar bld m)))
  | OpReg(Regdir m), OpReg(RegIndirDisp(disp, n)) ->
    let addr = regVar bld n .+ num (disp * step)
    bld <+ (storeMem bld addr (storeVal rt (regVar bld m)))
  | OpReg(RegIndir m), OpReg(Regdir n) ->
    bld <+ (regVar bld n := loadExt bld rt (regVar bld m))
  | OpReg(RegIndirPostInc m), OpReg(Regdir n) ->
    (* One register named twice takes the loaded value and no increment. *)
    bld <+ (regVar bld n := loadExt bld rt (regVar bld m))
    if m <> n then bld <+ (regVar bld m := regVar bld m .+ num step) else ()
  | OpReg(IdxRegIndir(idx, m)), OpReg(Regdir n) ->
    let addr = regVar bld idx .+ regVar bld m
    bld <+ (regVar bld n := loadExt bld rt addr)
  | OpReg(GBRIndirDisp(disp, gbr)), OpReg(Regdir n) ->
    let addr = regVar bld gbr .+ num (disp * step)
    bld <+ (regVar bld n := loadExt bld rt addr)
  | OpReg(RegIndirDisp(disp, m)), OpReg(Regdir n) ->
    let addr = regVar bld m .+ num (disp * step)
    bld <+ (regVar bld n := loadExt bld rt addr)
  | OpReg(PCRelDisp(disp, _)), OpReg(Regdir n) ->
    let addr =
      if rt = 32<rt> then pcRelLongAddr ins disp else pcRelWordAddr ins disp
    bld <+ (regVar bld n := loadExt bld rt (numU32 addr 32<rt>))
  | _ ->
    raise InvalidOperandException

/// Lifts one form of mov.b, mov.w, or mov.l.
let private movMem (ins: Instruction) len bld rt =
  bld <!-- (ins.Address, len)
  movMemBody ins bld rt
  bld --!> len

/// Moves one register into another, the shape ldc, lds, stc, sts, flds, and
/// fsts share: only which side is the control, system, or floating-point
/// register differs, and this lifter keeps every one of them in the register
/// file.
let private moveReg (ins: Instruction) len bld =
  let struct (src, dst) = twoRegs ins bld
  bld <!-- (ins.Address, len)
  bld <+ (dst := src)
  bld --!> len

let add (ins: Instruction) len bld =
  let struct (o1, o2) = getTwoOprs ins
  let dst = regOf bld o2
  bld <!-- (ins.Address, len)
  match o1 with
  | OpReg(Imm imm) -> bld <+ (dst := dst .+ num (signExtend 8 imm))
  | _ -> bld <+ (dst := dst .+ regOf bld o1)
  bld --!> len

let addc (ins: Instruction) len bld =
  let struct (src, dst) = twoRegs ins bld
  let t = regVar bld R.T
  let res = tmpVar bld 64<rt>
  bld <!-- (ins.Address, len)
  (* Widening to sixty-four bits puts the carry-out in bit thirty-two, where it
     can be read off directly rather than rebuilt from the operand signs. *)
  bld <+ (res := (AST.zext 64<rt> dst)
                 .+ (AST.zext 64<rt> src)
                 .+ (AST.zext 64<rt> t))
  bld <+ (dst := AST.xtlo 32<rt> res)
  bld <+ (t := AST.extract res 1<rt> 32)
  bld --!> len

let addv (ins: Instruction) len bld =
  let struct (src, dst) = twoRegs ins bld
  let res = tmpVar bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (res := dst .+ src)
  (* A signed sum overflows exactly when the operands share a sign the sum does
     not. *)
  bld <+ (regVar bld R.T :=
            ((AST.xthi 1<rt> dst == AST.xthi 1<rt> src)
             .& (AST.xthi 1<rt> res != AST.xthi 1<rt> dst)))
  bld <+ (dst := res)
  bld --!> len

let ``and`` (ins: Instruction) len bld =
  let struct (o1, o2) = getTwoOprs ins
  let dst = regOf bld o2
  bld <!-- (ins.Address, len)
  (* The immediate form is zero-extended, so it clears the upper three bytes. *)
  match o1 with
  | OpReg(Imm imm) -> bld <+ (dst := dst .& num imm)
  | _ -> bld <+ (dst := dst .& regOf bld o1)
  bld --!> len

let andb (ins: Instruction) len bld =
  let struct (o1, _) = getTwoOprs ins
  let imm = immOf o1
  let addr = tmpVar bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (addr := gbrIndexed bld)
  bld <+ (storeMem bld addr ((loadMem bld 8<rt> addr) .& numByte imm))
  bld --!> len

let bf (ins: Instruction) len bld =
  let target = pcRelTarget ins 8
  let fallThrough = numAddr (ins.Address + uint64 len)
  bld <!-- (ins.Address, len)
  (* Plain bf and bt have no delay slot, so they transfer control at once. *)
  bld <+ (AST.intercjmp (AST.not (regVar bld R.T)) target fallThrough)
  bld --!> len

let bfs (ins: Instruction) len bld =
  let target = pcRelTarget ins 8
  (* The delay slot runs either way, so the untaken path resumes past it. *)
  let fallThrough = numAddr (ins.Address + 4UL)
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld R.NPC :=
            AST.ite (AST.not (regVar bld R.T)) target fallThrough)
  arm bld InterJmpKind.Base
  bld --!> len

let bra (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld R.NPC := pcRelTarget ins 12)
  arm bld InterJmpKind.Base
  bld --!> len

let braf (ins: Instruction) len bld =
  let src = oneReg ins bld
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld R.NPC := numAddr (ins.Address + 4UL) .+ src)
  arm bld InterJmpKind.Base
  bld --!> len

let bsr (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld R.PR := numAddr (ins.Address + 4UL))
  bld <+ (regVar bld R.NPC := pcRelTarget ins 12)
  arm bld InterJmpKind.IsCall
  bld --!> len

let bsrf (ins: Instruction) len bld =
  let src = oneReg ins bld
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld R.PR := numAddr (ins.Address + 4UL))
  bld <+ (regVar bld R.NPC := numAddr (ins.Address + 4UL) .+ src)
  arm bld InterJmpKind.IsCall
  bld --!> len

let bt (ins: Instruction) len bld =
  let target = pcRelTarget ins 8
  let fallThrough = numAddr (ins.Address + uint64 len)
  bld <!-- (ins.Address, len)
  bld <+ (AST.intercjmp (regVar bld R.T) target fallThrough)
  bld --!> len

let bts (ins: Instruction) len bld =
  let target = pcRelTarget ins 8
  let fallThrough = numAddr (ins.Address + 4UL)
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld R.NPC := AST.ite (regVar bld R.T) target fallThrough)
  arm bld InterJmpKind.Base
  bld --!> len

let clrmac (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld R.MACH := num 0)
  bld <+ (regVar bld R.MACL := num 0)
  bld --!> len

let clrs (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld R.S := AST.b0)
  bld --!> len

let clrt (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld R.T := AST.b0)
  bld --!> len

let cmpeq (ins: Instruction) len bld =
  let struct (o1, o2) = getTwoOprs ins
  let dst = regOf bld o2
  bld <!-- (ins.Address, len)
  match o1 with
  | OpReg(Imm imm) -> bld <+ (regVar bld R.T := (dst == num (signExtend 8 imm)))
  | _ -> bld <+ (regVar bld R.T := (dst == regOf bld o1))
  bld --!> len

let cmpge (ins: Instruction) len bld =
  let struct (src, dst) = twoRegs ins bld
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld R.T := (dst ?>= src))
  bld --!> len

let cmpgt (ins: Instruction) len bld =
  let struct (src, dst) = twoRegs ins bld
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld R.T := (dst ?> src))
  bld --!> len

let cmphi (ins: Instruction) len bld =
  let struct (src, dst) = twoRegs ins bld
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld R.T := (dst .> src))
  bld --!> len

let cmphs (ins: Instruction) len bld =
  let struct (src, dst) = twoRegs ins bld
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld R.T := (dst .>= src))
  bld --!> len

let cmppl (ins: Instruction) len bld =
  let dst = oneReg ins bld
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld R.T := (dst ?> num 0))
  bld --!> len

let cmppz (ins: Instruction) len bld =
  let dst = oneReg ins bld
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld R.T := (dst ?>= num 0))
  bld --!> len

let cmpstr (ins: Instruction) len bld =
  let struct (src, dst) = twoRegs ins bld
  let diff = tmpVar bld 32<rt>
  bld <!-- (ins.Address, len)
  (* Any byte the two registers share leaves that byte of the difference zero,
     which is what a string scan looks for. *)
  bld <+ (diff := dst <+> src)
  bld <+ (regVar bld R.T :=
            (((AST.xtlo 8<rt> diff == AST.num0 8<rt>)
              .| (AST.extract diff 8<rt> 8 == AST.num0 8<rt>))
             .| ((AST.extract diff 8<rt> 16 == AST.num0 8<rt>)
                 .| (AST.extract diff 8<rt> 24 == AST.num0 8<rt>))))
  bld --!> len

let div0s (ins: Instruction) len bld =
  let struct (src, dst) = twoRegs ins bld
  let q = regVar bld R.Q
  let m = regVar bld R.M
  bld <!-- (ins.Address, len)
  bld <+ (q := AST.xthi 1<rt> dst)
  bld <+ (m := AST.xthi 1<rt> src)
  bld <+ (regVar bld R.T := (q <+> m))
  bld --!> len

let div0u (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld R.M := AST.b0)
  bld <+ (regVar bld R.Q := AST.b0)
  bld <+ (regVar bld R.T := AST.b0)
  bld --!> len

let div1 (ins: Instruction) len bld =
  let struct (src, dst) = twoRegs ins bld
  let q = regVar bld R.Q
  let m = regVar bld R.M
  let t = regVar bld R.T
  let struct (oldQ, shiftedIn, doSub, borrow) = tmpVars4 bld 1<rt>
  let struct (shifted, res) = tmpVars2 bld 32<rt>
  bld <!-- (ins.Address, len)
  (* One non-restoring division step. The dividend shifts left through T, then
     the divisor is subtracted when the running quotient bit and the divisor's
     sign agree and added when they differ; the manual's four-way switch on the
     old Q and M collapses to that choice plus a parity update of Q. *)
  bld <+ (oldQ := q)
  bld <+ (shiftedIn := AST.xthi 1<rt> dst)
  bld <+ (shifted := (dst << num 1) .| (AST.zext 32<rt> t))
  bld <+ (doSub := (oldQ == m))
  bld <+ (res := AST.ite doSub (shifted .- src) (shifted .+ src))
  bld <+ (borrow := AST.ite doSub (res .> shifted) (res .< shifted))
  bld <+ (dst := res)
  bld <+ (q := ((shiftedIn <+> borrow) <+> m))
  bld <+ (t := (q == m))
  bld --!> len

let dmulsl (ins: Instruction) len bld =
  let struct (src, dst) = twoRegs ins bld
  let res = tmpVar bld 64<rt>
  bld <!-- (ins.Address, len)
  bld <+ (res := (AST.sext 64<rt> dst) .* (AST.sext 64<rt> src))
  bld <+ (regVar bld R.MACL := AST.xtlo 32<rt> res)
  bld <+ (regVar bld R.MACH := AST.xthi 32<rt> res)
  bld --!> len

let dmulul (ins: Instruction) len bld =
  let struct (src, dst) = twoRegs ins bld
  let res = tmpVar bld 64<rt>
  bld <!-- (ins.Address, len)
  bld <+ (res := (AST.zext 64<rt> dst) .* (AST.zext 64<rt> src))
  bld <+ (regVar bld R.MACL := AST.xtlo 32<rt> res)
  bld <+ (regVar bld R.MACH := AST.xthi 32<rt> res)
  bld --!> len

let dt (ins: Instruction) len bld =
  let dst = oneReg ins bld
  bld <!-- (ins.Address, len)
  bld <+ (dst := dst .- num 1)
  bld <+ (regVar bld R.T := (dst == num 0))
  bld --!> len

let extsb (ins: Instruction) len bld =
  let struct (src, dst) = twoRegs ins bld
  bld <!-- (ins.Address, len)
  bld <+ (dst := AST.xtlo 8<rt> src |> AST.sext 32<rt>)
  bld --!> len

let extsw (ins: Instruction) len bld =
  let struct (src, dst) = twoRegs ins bld
  bld <!-- (ins.Address, len)
  bld <+ (dst := AST.xtlo 16<rt> src |> AST.sext 32<rt>)
  bld --!> len

let extub (ins: Instruction) len bld =
  let struct (src, dst) = twoRegs ins bld
  bld <!-- (ins.Address, len)
  bld <+ (dst := AST.xtlo 8<rt> src |> AST.zext 32<rt>)
  bld --!> len

let extuw (ins: Instruction) len bld =
  let struct (src, dst) = twoRegs ins bld
  bld <!-- (ins.Address, len)
  bld <+ (dst := AST.xtlo 16<rt> src |> AST.zext 32<rt>)
  bld --!> len

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
  let struct (hi, lo) = doubleHalves bld r
  bld <+ (hi := AST.xthi 32<rt> v)
  bld <+ (lo := AST.xtlo 32<rt> v)

/// Emits an instruction that an FPSCR mode bit gives two meanings: `off` runs
/// when the bit is clear and `on` when it is set. The paths differ in which
/// registers they write and in how wide their memory accesses are, so a single
/// result selected by an ite cannot express them -- and a parser cannot choose
/// between them at all, the bit being state the program writes at run time.
let private byMode bld pos off on =
  let lblOn = label bld "ModeOn"
  let lblOff = label bld "ModeOff"
  let lblEnd = label bld "ModeEnd"
  bld <+ (AST.cjmp (fpscrBit bld pos) (AST.jmpDest lblOn) (AST.jmpDest lblOff))
  bld <+ (AST.lmark lblOff)
  off ()
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblOn)
  on ()
  bld <+ (AST.lmark lblEnd)

/// Reports the wide path of an odd-numbered operand as unsupported: it names
/// the second register bank, which nothing here models. Only a program that
/// actually sets the mode bit runs into it.
let private unsupportedBank bld = bld <+ AST.sideEffect UnsupportedInstruction

/// The sign bit of a floating-point value, which fabs clears and fneg flips.
/// Both work the same at either precision, since a double keeps its sign bit in
/// the upper half -- the very register the operand names.
let [<Literal>] private SignBit = 0x80000000

let fabs (ins: Instruction) len bld =
  let dst = oneReg ins bld
  bld <!-- (ins.Address, len)
  bld <+ (dst := dst .& num (~~~SignBit))
  bld --!> len

/// Lifts a floating-point operation over two registers whose width FPSCR.PR
/// picks, given how to combine two values of that width.
let private fpBinary (ins: Instruction) len bld op =
  let struct (o1, o2) = getTwoOprs ins
  let m = regEnumOf o1
  let n = regEnumOf o2
  bld <!-- (ins.Address, len)
  byMode bld PrBit
    (fun () -> bld <+ (regVar bld n := op (regVar bld n) (regVar bld m)))
    (fun () ->
      if isOddFpNum m || isOddFpNum n then
        unsupportedBank bld
      else
        let res = tmpVar bld 64<rt>
        bld <+ (res := op (doubleOf bld n) (doubleOf bld m))
        setDouble bld n res)
  bld --!> len

let fadd ins len bld = fpBinary ins len bld AST.fadd

/// Lifts a floating-point comparison whose width FPSCR.PR picks; either width
/// leaves the answer in T.
let private fpCompare (ins: Instruction) len bld cmp =
  let struct (o1, o2) = getTwoOprs ins
  let m = regEnumOf o1
  let n = regEnumOf o2
  bld <!-- (ins.Address, len)
  byMode bld PrBit
    (fun () ->
      bld <+ (regVar bld R.T := cmp (regVar bld n) (regVar bld m)))
    (fun () ->
      if isOddFpNum m || isOddFpNum n then unsupportedBank bld
      else bld <+ (regVar bld R.T := cmp (doubleOf bld n) (doubleOf bld m)))
  bld --!> len

let fcmpeq ins len bld = fpCompare ins len bld AST.feq

let fcmpgt ins len bld = fpCompare ins len bld AST.fgt

/// Converts the double-precision value a register pair holds to single
/// precision in FPUL. The architecture defines it only while FPSCR.PR is set,
/// so it takes no mode branch, and the operand names an even register by
/// construction.
let fcnvds (ins: Instruction) len bld =
  let struct (o1, o2) = getTwoOprs ins
  let src = doubleOf bld (regEnumOf o1)
  let dst = regOf bld o2
  bld <!-- (ins.Address, len)
  bld <+ (dst := AST.cast CastKind.FloatCast 32<rt> src)
  bld --!> len

/// Converts the single-precision value in FPUL to double precision in a
/// register pair, the counterpart of fcnvds.
let fcnvsd (ins: Instruction) len bld =
  let struct (o1, o2) = getTwoOprs ins
  let src = regOf bld o1
  let res = tmpVar bld 64<rt>
  bld <!-- (ins.Address, len)
  bld <+ (res := AST.cast CastKind.FloatCast 64<rt> src)
  setDouble bld (regEnumOf o2) res
  bld --!> len

let fdiv ins len bld = fpBinary ins len bld AST.fdiv

let fipr ins _len _bld = notLifted ins

/// The single-precision encoding of 0.0, which fldi0 loads.
let [<Literal>] private SingleZero = 0x00000000

/// The single-precision encoding of 1.0, which fldi1 loads.
let [<Literal>] private SingleOne = 0x3F800000

let fldi0 (ins: Instruction) len bld =
  let dst = oneReg ins bld
  bld <!-- (ins.Address, len)
  bld <+ (dst := num SingleZero)
  bld --!> len

let fldi1 (ins: Instruction) len bld =
  let dst = oneReg ins bld
  bld <!-- (ins.Address, len)
  bld <+ (dst := num SingleOne)
  bld --!> len

let flds ins len bld = moveReg ins len bld

let ``float`` (ins: Instruction) len bld =
  let struct (o1, o2) = getTwoOprs ins
  let src = regOf bld o1
  let n = regEnumOf o2
  bld <!-- (ins.Address, len)
  byMode bld PrBit
    (fun () ->
      bld <+ (regVar bld n := AST.cast CastKind.SIntToFloat 32<rt> src))
    (fun () ->
      if isOddFpNum n then
        unsupportedBank bld
      else
        let res = tmpVar bld 64<rt>
        bld <+ (res := AST.cast CastKind.SIntToFloat 64<rt> src)
        setDouble bld n res)
  bld --!> len

let fmac (ins: Instruction) len bld =
  let struct (o1, o2, o3) =
    match ins.Operands with
    | ThreeOperands(a, b, c) -> struct (a, b, c)
    | _ -> raise InvalidOperandException
  let fr0 = regOf bld o1
  let src = regOf bld o2
  let dst = regOf bld o3
  bld <!-- (ins.Address, len)
  bld <+ (dst := AST.fadd (AST.fmul fr0 src) dst)
  bld --!> len

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
      bld <+ (storeMem bld (regVar bld n) (doubleOf bld m))
    | OpReg(Regdir m), OpReg(RegIndirPreDec n) ->
      let addr = tmpVar bld 32<rt>
      bld <+ (addr := regVar bld n .- num 8)
      bld <+ (storeMem bld addr (doubleOf bld m))
      bld <+ (regVar bld n := addr)
    | OpReg(Regdir m), OpReg(IdxRegIndir(idx, n)) ->
      let addr = regVar bld idx .+ regVar bld n
      bld <+ (storeMem bld addr (doubleOf bld m))
    | OpReg(RegIndir m), OpReg(Regdir n) ->
      bld <+ (value := loadMem bld 64<rt> (regVar bld m))
      setDouble bld n value
    | OpReg(RegIndirPostInc m), OpReg(Regdir n) ->
      bld <+ (value := loadMem bld 64<rt> (regVar bld m))
      bld <+ (regVar bld m := regVar bld m .+ num 8)
      setDouble bld n value
    | OpReg(IdxRegIndir(idx, m)), OpReg(Regdir n) ->
      bld <+ (value := loadMem bld 64<rt> (regVar bld idx .+ regVar bld m))
      setDouble bld n value
    | _ ->
      raise InvalidOperandException

/// Lifts a floating-point move, whose width FPSCR.SZ picks: thirty-two bits
/// between single-precision registers, or sixty-four between the pairs they
/// span -- which also changes how much memory a transfer touches and how far a
/// post-increment or pre-decrement steps.
let private fpMove (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  match ins.Operands with
  | TwoOperands(OpReg(Regdir m), OpReg(Regdir n)) ->
    byMode bld SzBit
      (fun () -> bld <+ (regVar bld n := regVar bld m))
      (fun () ->
        if isOddFpNum m || isOddFpNum n then
          unsupportedBank bld
        else
          let value = tmpVar bld 64<rt>
          bld <+ (value := doubleOf bld m)
          setDouble bld n value)
  | _ ->
    byMode bld
      SzBit
      (fun () -> movMemBody ins bld 32<rt>)
      (fun () -> fpMemDouble ins bld)
  bld --!> len

let fmov ins len bld = fpMove ins len bld

let fmovs ins len bld = fpMove ins len bld

let fmul ins len bld = fpBinary ins len bld AST.fmul

let fneg (ins: Instruction) len bld =
  let dst = oneReg ins bld
  bld <!-- (ins.Address, len)
  bld <+ (dst := dst <+> num SignBit)
  bld --!> len

let frchg ins _len _bld = notLifted ins

/// Flips FPSCR.SZ, so that the transfers which read it move the other width
/// from here on.
let fschg (ins: Instruction) len bld =
  let fpscr = regVar bld R.FPSCR
  bld <!-- (ins.Address, len)
  bld <+ (fpscr := fpscr <+> num (1 <<< SzBit))
  bld --!> len

let fsqrt (ins: Instruction) len bld =
  let n = getOneOpr ins |> regEnumOf
  bld <!-- (ins.Address, len)
  byMode bld PrBit
    (fun () -> bld <+ (regVar bld n := AST.fsqrt (regVar bld n)))
    (fun () ->
      if isOddFpNum n then
        unsupportedBank bld
      else
        let res = tmpVar bld 64<rt>
        bld <+ (res := AST.fsqrt (doubleOf bld n))
        setDouble bld n res)
  bld --!> len

let fsts ins len bld = moveReg ins len bld

let fsub ins len bld = fpBinary ins len bld AST.fsub

let ftrc (ins: Instruction) len bld =
  let struct (o1, o2) = getTwoOprs ins
  let m = regEnumOf o1
  let dst = regOf bld o2
  bld <!-- (ins.Address, len)
  byMode bld PrBit
    (fun () ->
      bld <+ (dst := AST.cast CastKind.FtoITrunc 32<rt> (regVar bld m)))
    (fun () ->
      if isOddFpNum m then unsupportedBank bld
      else bld <+ (dst := AST.cast CastKind.FtoITrunc 32<rt> (doubleOf bld m)))
  bld --!> len

let ftrv ins _len _bld = notLifted ins

/// The register a register-indirect operand names.
let private indirOf bld = function
  | OpReg(RegIndir r) -> regVar bld r
  | _ -> raise InvalidOperandException

let jmp (ins: Instruction) len bld =
  let src = getOneOpr ins |> indirOf bld
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld R.NPC := src)
  arm bld InterJmpKind.Base
  bld --!> len

let jsr (ins: Instruction) len bld =
  let src = getOneOpr ins |> indirOf bld
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld R.PR := numAddr (ins.Address + 4UL))
  bld <+ (regVar bld R.NPC := src)
  arm bld InterJmpKind.IsCall
  bld --!> len

/// Loads a control or system register from @Rm+, the form ldc.l and lds.l
/// share.
let private loadPostInc (ins: Instruction) len bld =
  let struct (o1, o2) = getTwoOprs ins
  let dst = regOf bld o2
  let src =
    match o1 with
    | OpReg(RegIndirPostInc r) -> regVar bld r
    | _ -> raise InvalidOperandException
  bld <!-- (ins.Address, len)
  bld <+ (dst := loadMem bld 32<rt> src)
  bld <+ (src := src .+ num 4)
  bld --!> len

/// Stores a control or system register to @-Rn, the form stc.l and sts.l
/// share.
let private storePreDec (ins: Instruction) len bld =
  let struct (o1, o2) = getTwoOprs ins
  let src = regOf bld o1
  let dst =
    match o2 with
    | OpReg(RegIndirPreDec r) -> regVar bld r
    | _ -> raise InvalidOperandException
  let addr = tmpVar bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (addr := dst .- num 4)
  bld <+ (storeMem bld addr src)
  bld <+ (dst := addr)
  bld --!> len

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
  let struct (o1, o2) = getTwoOprs ins
  let src = postIncOf bld o1
  let dst = postIncOf bld o2
  let mach = regVar bld R.MACH
  let macl = regVar bld R.MACL
  let struct (vn, vm) = tmpVars2 bld 32<rt>
  let struct (mac, saturated) = tmpVars2 bld 64<rt>
  bld <!-- (ins.Address, len)
  (* The reads and the updates interleave as the manual has them, so that a
     mac.l @Rn+,@Rn+ naming one register twice reads two successive longwords
     and advances it by eight. *)
  bld <+ (vn := loadMem bld 32<rt> dst)
  bld <+ (dst := dst .+ num 4)
  bld <+ (vm := loadMem bld 32<rt> src)
  bld <+ (src := src .+ num 4)
  bld <+ (mac := ((AST.zext 64<rt> mach) << num64 32) .| (AST.zext 64<rt> macl))
  bld <+ (mac := mac .+ ((AST.sext 64<rt> vn) .* (AST.sext 64<rt> vm)))
  (* With S set the accumulator saturates to a signed forty-eight-bit range. *)
  bld <+ (saturated :=
            AST.ite (mac ?> num64 0x7FFFFFFF)
                    (numI64 0x00007FFFFFFFFFFFL 64<rt>)
                    (AST.ite (mac ?< num64 -0x80000000)
                             (numI64 0xFFFF800000000000L 64<rt>)
                             mac))
  bld <+ (mac := AST.ite (regVar bld R.S) saturated mac)
  bld <+ (macl := AST.xtlo 32<rt> mac)
  bld <+ (mach := AST.xthi 32<rt> mac)
  bld --!> len

let macw (ins: Instruction) len bld =
  let struct (o1, o2) = getTwoOprs ins
  let src = postIncOf bld o1
  let dst = postIncOf bld o2
  let mach = regVar bld R.MACH
  let macl = regVar bld R.MACL
  let struct (vn, vm) = tmpVars2 bld 16<rt>
  let prod = tmpVar bld 32<rt>
  let struct (mac, sum) = tmpVars2 bld 64<rt>
  let satL = tmpVar bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (vn := loadMem bld 16<rt> dst)
  bld <+ (dst := dst .+ num 2)
  bld <+ (vm := loadMem bld 16<rt> src)
  bld <+ (src := src .+ num 2)
  bld <+ (prod := (AST.sext 32<rt> vn) .* (AST.sext 32<rt> vm))
  bld <+ (mac := ((AST.zext 64<rt> mach) << num64 32) .| (AST.zext 64<rt> macl))
  bld <+ (mac := mac .+ (AST.sext 64<rt> prod))
  (* With S set mac.w saturates the low half alone and leaves MACH be. *)
  bld <+ (sum := (AST.sext 64<rt> macl) .+ (AST.sext 64<rt> prod))
  bld <+ (satL :=
            AST.ite (sum ?> num64 0x7FFFFFFF)
                    (num 0x7FFFFFFF)
                    (AST.ite (sum ?< num64 -0x80000000)
                             (num 0x80000000)
                             (AST.xtlo 32<rt> sum)))
  bld <+ (macl := AST.ite (regVar bld R.S) satL (AST.xtlo 32<rt> mac))
  bld <+ (mach := AST.ite (regVar bld R.S) mach (AST.xthi 32<rt> mac))
  bld --!> len

let mov (ins: Instruction) len bld =
  let struct (o1, o2) = getTwoOprs ins
  let dst = regOf bld o2
  bld <!-- (ins.Address, len)
  match o1 with
  | OpReg(Imm imm) -> bld <+ (dst := num (signExtend 8 imm))
  | _ -> bld <+ (dst := regOf bld o1)
  bld --!> len

let mova (ins: Instruction) len bld =
  let struct (o1, _) = getTwoOprs ins
  let disp =
    match o1 with
    | OpReg(PCRelDisp(d, _)) -> d
    | _ -> raise InvalidOperandException
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld R.R0 := numU32 (pcRelLongAddr ins disp) 32<rt>)
  bld --!> len

let movb ins len bld = movMem ins len bld 8<rt>

let movw ins len bld = movMem ins len bld 16<rt>

let movl ins len bld = movMem ins len bld 32<rt>

let movcal ins len bld = movMem ins len bld 32<rt>

let movt (ins: Instruction) len bld =
  let dst = oneReg ins bld
  bld <!-- (ins.Address, len)
  bld <+ (dst := AST.zext 32<rt> (regVar bld R.T))
  bld --!> len

let mull (ins: Instruction) len bld =
  let struct (src, dst) = twoRegs ins bld
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld R.MACL := dst .* src)
  bld --!> len

let mulsw (ins: Instruction) len bld =
  let struct (src, dst) = twoRegs ins bld
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld R.MACL :=
            (AST.xtlo 16<rt> dst |> AST.sext 32<rt>)
            .* (AST.xtlo 16<rt> src |> AST.sext 32<rt>))
  bld --!> len

let muluw (ins: Instruction) len bld =
  let struct (src, dst) = twoRegs ins bld
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld R.MACL :=
            (AST.xtlo 16<rt> dst |> AST.zext 32<rt>)
            .* (AST.xtlo 16<rt> src |> AST.zext 32<rt>))
  bld --!> len

let neg (ins: Instruction) len bld =
  let struct (src, dst) = twoRegs ins bld
  bld <!-- (ins.Address, len)
  bld <+ (dst := num 0 .- src)
  bld --!> len

let negc (ins: Instruction) len bld =
  let struct (src, dst) = twoRegs ins bld
  let t = regVar bld R.T
  let struct (negated, res) = tmpVars2 bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (negated := num 0 .- src)
  bld <+ (res := negated .- (AST.zext 32<rt> t))
  bld <+ (t := ((num 0 .< negated) .| (negated .< res)))
  bld <+ (dst := res)
  bld --!> len

let nop (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  bld --!> len

let ``not`` (ins: Instruction) len bld =
  let struct (src, dst) = twoRegs ins bld
  bld <!-- (ins.Address, len)
  bld <+ (dst := AST.not src)
  bld --!> len

/// Lifts a cache-control instruction, which only hints at what the cache should
/// hold and so changes no state this emulator models.
let private cacheHint (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  bld --!> len

let ocbi ins len bld = cacheHint ins len bld

let ocbp ins len bld = cacheHint ins len bld

let ocbwb ins len bld = cacheHint ins len bld

let ``or`` (ins: Instruction) len bld =
  let struct (o1, o2) = getTwoOprs ins
  let dst = regOf bld o2
  bld <!-- (ins.Address, len)
  match o1 with
  | OpReg(Imm imm) -> bld <+ (dst := dst .| num imm)
  | _ -> bld <+ (dst := dst .| regOf bld o1)
  bld --!> len

let orb (ins: Instruction) len bld =
  let struct (o1, _) = getTwoOprs ins
  let imm = immOf o1
  let addr = tmpVar bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (addr := gbrIndexed bld)
  bld <+ (storeMem bld addr ((loadMem bld 8<rt> addr) .| numByte imm))
  bld --!> len

let pref ins len bld = cacheHint ins len bld

let rotcl (ins: Instruction) len bld =
  let dst = oneReg ins bld
  let t = regVar bld R.T
  let carry = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (carry := AST.xthi 1<rt> dst)
  bld <+ (dst := (dst << num 1) .| (AST.zext 32<rt> t))
  bld <+ (t := carry)
  bld --!> len

let rotcr (ins: Instruction) len bld =
  let dst = oneReg ins bld
  let t = regVar bld R.T
  let carry = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (carry := AST.xtlo 1<rt> dst)
  bld <+ (dst := (dst >> num 1) .| ((AST.zext 32<rt> t) << num 31))
  bld <+ (t := carry)
  bld --!> len

let rotl (ins: Instruction) len bld =
  let dst = oneReg ins bld
  let carry = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (carry := AST.xthi 1<rt> dst)
  bld <+ (dst := (dst << num 1) .| (AST.zext 32<rt> carry))
  bld <+ (regVar bld R.T := carry)
  bld --!> len

let rotr (ins: Instruction) len bld =
  let dst = oneReg ins bld
  let carry = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (carry := AST.xtlo 1<rt> dst)
  bld <+ (dst := (dst >> num 1) .| ((AST.zext 32<rt> carry) << num 31))
  bld <+ (regVar bld R.T := carry)
  bld --!> len

let rte ins _len _bld = notLifted ins

let rts (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld R.NPC := regVar bld R.PR)
  arm bld InterJmpKind.IsRet
  bld --!> len

let sets (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld R.S := AST.b1)
  bld --!> len

let sett (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld R.T := AST.b1)
  bld --!> len

let shad (ins: Instruction) len bld =
  let struct (src, dst) = twoRegs ins bld
  let struct (left, right, amount) = tmpVars3 bld 32<rt>
  let wide = tmpVar bld 64<rt>
  bld <!-- (ins.Address, len)
  (* A negative count shifts right by its magnitude, and a count of minus
     thirty-two -- a zero in the low five bits -- fills the register with the
     sign bit. Shifting the sign-extended sixty-four-bit value keeps that
     thirty-two-bit shift defined. *)
  bld <+ (left := dst << (src .& num 0x1F))
  bld <+ (amount := ((AST.not src) .& num 0x1F) .+ num 1)
  bld <+ (wide := (AST.sext 64<rt> dst) ?>> (AST.zext 64<rt> amount))
  bld <+ (right := AST.xtlo 32<rt> wide)
  bld <+ (dst := AST.ite (AST.xthi 1<rt> src == AST.b0) left right)
  bld --!> len

let shal (ins: Instruction) len bld =
  let dst = oneReg ins bld
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld R.T := AST.xthi 1<rt> dst)
  bld <+ (dst := dst << num 1)
  bld --!> len

let shar (ins: Instruction) len bld =
  let dst = oneReg ins bld
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld R.T := AST.xtlo 1<rt> dst)
  bld <+ (dst := dst ?>> num 1)
  bld --!> len

let shld (ins: Instruction) len bld =
  let struct (src, dst) = twoRegs ins bld
  let struct (left, right, amount) = tmpVars3 bld 32<rt>
  let wide = tmpVar bld 64<rt>
  bld <!-- (ins.Address, len)
  bld <+ (left := dst << (src .& num 0x1F))
  bld <+ (amount := ((AST.not src) .& num 0x1F) .+ num 1)
  bld <+ (wide := (AST.zext 64<rt> dst) >> (AST.zext 64<rt> amount))
  bld <+ (right := AST.xtlo 32<rt> wide)
  bld <+ (dst := AST.ite (AST.xthi 1<rt> src == AST.b0) left right)
  bld --!> len

let shll (ins: Instruction) len bld =
  let dst = oneReg ins bld
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld R.T := AST.xthi 1<rt> dst)
  bld <+ (dst := dst << num 1)
  bld --!> len

/// Shifts by a fixed count, which unlike a shift by one leaves T alone.
let private shiftFixed (ins: Instruction) len bld count isLeft =
  let dst = oneReg ins bld
  bld <!-- (ins.Address, len)
  if isLeft then bld <+ (dst := dst << num count)
  else bld <+ (dst := dst >> num count)
  bld --!> len

let shll2 ins len bld = shiftFixed ins len bld 2 true

let shll8 ins len bld = shiftFixed ins len bld 8 true

let shll16 ins len bld = shiftFixed ins len bld 16 true

let shlr (ins: Instruction) len bld =
  let dst = oneReg ins bld
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld R.T := AST.xtlo 1<rt> dst)
  bld <+ (dst := dst >> num 1)
  bld --!> len

let shlr2 ins len bld = shiftFixed ins len bld 2 false

let shlr8 ins len bld = shiftFixed ins len bld 8 false

let shlr16 ins len bld = shiftFixed ins len bld 16 false

let sleep ins _len _bld = notLifted ins

let stc ins len bld = moveReg ins len bld

let stcl ins len bld = storePreDec ins len bld

let sts ins len bld = moveReg ins len bld

let stsl ins len bld = storePreDec ins len bld

let sub (ins: Instruction) len bld =
  let struct (src, dst) = twoRegs ins bld
  bld <!-- (ins.Address, len)
  bld <+ (dst := dst .- src)
  bld --!> len

let subc (ins: Instruction) len bld =
  let struct (src, dst) = twoRegs ins bld
  let t = regVar bld R.T
  let struct (diff, res) = tmpVars2 bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (diff := dst .- src)
  bld <+ (res := diff .- (AST.zext 32<rt> t))
  bld <+ (t := ((dst .< diff) .| (diff .< res)))
  bld <+ (dst := res)
  bld --!> len

let subv (ins: Instruction) len bld =
  let struct (src, dst) = twoRegs ins bld
  let res = tmpVar bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (res := dst .- src)
  (* A signed difference overflows exactly when the operands differ in sign and
     the result does not match the minuend's. *)
  bld <+ (regVar bld R.T :=
            ((AST.xthi 1<rt> dst != AST.xthi 1<rt> src)
             .& (AST.xthi 1<rt> res != AST.xthi 1<rt> dst)))
  bld <+ (dst := res)
  bld --!> len

let swapb (ins: Instruction) len bld =
  let struct (src, dst) = twoRegs ins bld
  bld <!-- (ins.Address, len)
  bld <+ (dst := (src .& num 0xFFFF0000)
                 .| (((src .& num 0xFF) << num 8)
                     .| ((src >> num 8) .& num 0xFF)))
  bld --!> len

let swapw (ins: Instruction) len bld =
  let struct (src, dst) = twoRegs ins bld
  bld <!-- (ins.Address, len)
  bld <+ (dst := (src << num 16) .| (src >> num 16))
  bld --!> len

let tasb (ins: Instruction) len bld =
  let addr = getOneOpr ins |> indirOf bld
  let value = tmpVar bld 8<rt>
  bld <!-- (ins.Address, len)
  bld <+ (value := loadMem bld 8<rt> addr)
  bld <+ (regVar bld R.T := (value == AST.num0 8<rt>))
  bld <+ (storeMem bld addr (value .| numByte 0x80))
  bld --!> len

let trapa (ins: Instruction) len bld =
  let imm = getOneOpr ins |> immOf
  bld <!-- (ins.Address, len)
  (* Linux reads the trap number out of TRA, shifted up by two as the hardware
     leaves it there. *)
  bld <+ (regVar bld R.TRA := num (imm <<< 2))
  bld <+ (AST.sideEffect SysCall)
  bld --!> len

let tst (ins: Instruction) len bld =
  let struct (o1, o2) = getTwoOprs ins
  let dst = regOf bld o2
  bld <!-- (ins.Address, len)
  match o1 with
  | OpReg(Imm imm) -> bld <+ (regVar bld R.T := ((dst .& num imm) == num 0))
  | _ -> bld <+ (regVar bld R.T := ((dst .& regOf bld o1) == num 0))
  bld --!> len

let tstb (ins: Instruction) len bld =
  let struct (o1, _) = getTwoOprs ins
  let imm = immOf o1
  let addr = tmpVar bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (addr := gbrIndexed bld)
  bld <+ (regVar bld R.T :=
            (((loadMem bld 8<rt> addr) .& numByte imm) == AST.num0 8<rt>))
  bld --!> len

let xor (ins: Instruction) len bld =
  let struct (o1, o2) = getTwoOprs ins
  let dst = regOf bld o2
  bld <!-- (ins.Address, len)
  match o1 with
  | OpReg(Imm imm) -> bld <+ (dst := dst <+> num imm)
  | _ -> bld <+ (dst := dst <+> regOf bld o1)
  bld --!> len

let xorb (ins: Instruction) len bld =
  let struct (o1, _) = getTwoOprs ins
  let imm = immOf o1
  let addr = tmpVar bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (addr := gbrIndexed bld)
  bld <+ (storeMem bld addr ((loadMem bld 8<rt> addr) <+> numByte imm))
  bld --!> len

let xtrct (ins: Instruction) len bld =
  let struct (src, dst) = twoRegs ins bld
  bld <!-- (ins.Address, len)
  bld <+ (dst := (src << num 16) .| (dst >> num 16))
  bld --!> len
