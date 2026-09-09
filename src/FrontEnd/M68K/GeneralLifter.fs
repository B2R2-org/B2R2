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


/// Lifts the m68k instructions that work on integers, addresses, and the
/// condition codes.
module internal B2R2.FrontEnd.M68K.GeneralLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.M68K.LiftHelper

/// Returns the value of an operand widened to a long word, sign-extending it
/// where the operation is a word one. This is what the instructions that name
/// an address register do with their source, an address register holding
/// nothing narrower than the whole of one.
let private srcAsLong bld ins size opr =
  let v = readLoc bld size (transOpr bld ins size opr)
  if size = Sz.Long then v else AST.sext 32<rt> v

/// Lifts a MOVE that names the condition code register or the status
/// register, the low byte of which the condition codes are.
let private moveCcr (ins: Instruction) bld o1 o2 =
  lift bld ins {
    match o1, o2 with
    | _, OpReg R.CCR | _, OpReg R.SR ->
      let src = transOpr bld ins Sz.Word o1
      setCCR bld (AST.xtlo 8<rt> (readLoc bld Sz.Word src))
    | OpReg R.CCR, _ | OpReg R.SR, _ ->
      (* Reading the status register gives a word whose high byte holds the
         system bits, which a user-mode program has none of. *)
      let dst = transOpr bld ins Sz.Word o2
      writeLoc bld Sz.Word dst (AST.zext 16<rt> (ccrValue bld))
    | _ ->
      AST.sideEffect UnsupportedInstruction
  }

/// Lifts a MOVE, which is the one instruction that names two effective
/// addresses and so the one whose source is computed before its destination.
let move (ins: Instruction) bld =
  let struct (o1, o2) = getTwoOprs ins
  match o1, o2 with
  | OpReg R.CCR, _ | OpReg R.SR, _ | _, OpReg R.CCR | _, OpReg R.SR ->
    moveCcr ins bld o1 o2
  | OpReg R.USP, _ | _, OpReg R.USP ->
    lift bld ins {
      let dst = regOf bld o2
      dst := regOf bld o1
    }
  | _ ->
    lift bld ins {
      let size = ins.Size
      let rt = regTypeOf size
      let src = transOpr bld ins size o1
      let t = tmpVar bld rt
      t := readLoc bld size src
      let dst = transOpr bld ins size o2
      setLogicFlags bld rt t
      writeLoc bld size dst t
    }

/// Lifts a MOVEA, which fills the whole of an address register and leaves
/// every condition code alone.
let movea (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let v = srcAsLong bld ins ins.Size o1
    regOf bld o2 := v
  }

/// Lifts a MOVEQ, whose byte of data the processor sign-extends over the whole
/// of the register it names.
let moveq (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let t = tmpVar bld 32<rt>
    t := readLoc bld Sz.Long (transOpr bld ins Sz.Long o1)
    setLogicFlags bld 32<rt> t
    regOf bld o2 := t
  }

/// Lifts a LEA, which computes an address and keeps it rather than what lies
/// at it.
let lea (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    match transOpr bld ins Sz.Long o1 with
    | LMem addr -> regOf bld o2 := addr
    | _ -> raise InvalidOperandException
  }

/// Pushes a long word onto the stack, which is what a call and a PEA do. The
/// stack pointer moves only once the write has gone through: a write that
/// faults leaves the instruction to be run again from its start, and a
/// pointer already moved would move a second time.
let private push bld v =
  let sp = regVar bld R.A7
  let t = tmpVar bld 32<rt>
  append bld {
    t := sp .- num32 4
    storeNative bld t v
    sp := t
  }

/// Pops a long word off the stack into the given destination.
let private pop bld dst =
  let sp = regVar bld R.A7
  append bld {
    dst := loadNative bld 32<rt> sp
    sp := sp .+ num32 4
  }

/// Lifts a PEA, which puts an address on the stack rather than in a register.
let pea (ins: Instruction) bld =
  lift bld ins {
    match transOpr bld ins Sz.Long (getOneOpr ins) with
    | LMem addr ->
      let t = tmpVar bld 32<rt>
      t := addr
      push bld t
    | _ ->
      raise InvalidOperandException
  }

/// Lifts a LINK, which saves an address register on the stack, points it at
/// where it landed, and then makes room below it for the frame.
let link (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let an = regOf bld o1
    let sp = regVar bld R.A7
    let disp =
      match o2 with
      | OpImm d when ins.Size = Sz.Long -> num32 (int32 d)
      | OpImm d -> num32 (int32 (int16 d))
      | _ -> raise InvalidOperandException
    let t = tmpVar bld 32<rt>
    t := sp .- num32 4
    storeNative bld t an
    an := t
    sp := t .+ disp
  }

/// Lifts an UNLK, which undoes what a LINK did.
let unlk (ins: Instruction) bld =
  lift bld ins {
    let an = regOf bld (getOneOpr ins)
    let sp = regVar bld R.A7
    sp := an
    pop bld an
  }

/// Lifts an EXG, which exchanges the whole of two registers.
let exg (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let x = regOf bld o1
    let y = regOf bld o2
    let t = tmpVar bld 32<rt>
    t := x
    x := y
    y := t
  }

/// Lifts a SWAP, which exchanges the halves of a data register.
let swap (ins: Instruction) bld =
  lift bld ins {
    let dn = regOf bld (getOneOpr ins)
    let t = tmpVar bld 32<rt>
    t := AST.concat (AST.xtlo 16<rt> dn) (AST.xthi 16<rt> dn)
    setLogicFlags bld 32<rt> t
    dn := t
  }

/// Lifts a CLR, which writes zero and says so in the condition codes.
let clr (ins: Instruction) bld =
  lift bld ins {
    let size = ins.Size
    let rt = regTypeOf size
    let dst = transOpr bld ins size (getOneOpr ins)
    nf bld := AST.b0
    zf bld := AST.b1
    vf bld := AST.b0
    cf bld := AST.b0
    writeLoc bld size dst (AST.num0 rt)
  }

/// Lifts an EXT or an EXTB, which fills the upper part of a data register with
/// copies of the sign bit of its lower part.
let ext (ins: Instruction) bld =
  lift bld ins {
    let dn = regOf bld (getOneOpr ins)
    let srcRt =
      if ins.Opcode = Op.EXTB || ins.Size = Sz.Word then 8<rt> else 16<rt>
    let dstRt = regTypeOf ins.Size
    let dst = if dstRt = 32<rt> then dn else AST.xtlo dstRt dn
    let t = tmpVar bld dstRt
    t := AST.sext dstRt (AST.xtlo srcRt dn)
    setLogicFlags bld dstRt t
    dst := t
  }

/// Lifts an instruction that adds a source into a destination or subtracts it
/// from one: ADD, ADDI, and ADDQ share one shape, SUB, SUBI, and SUBQ the
/// other.
let private arith (ins: Instruction) bld isAdd =
  lift bld ins {
    let size = ins.Size
    let rt = regTypeOf size
    let struct (o1, o2) = getTwoOprs ins
    match o2 with
    | OpReg r when isAddrReg r ->
      (* A quick add or subtract that names an address register works on the
         whole of it and leaves every condition code alone, however wide the
         mnemonic says the operation is. *)
      let v = srcAsLong bld ins size o1
      let an = regVar bld r
      an := (if isAdd then an .+ v else an .- v)
    | _ ->
      let src = transOpr bld ins size o1
      let s = tmpVar bld rt
      s := readLoc bld size src
      let dst = transOpr bld ins size o2
      let d = tmpVar bld rt
      let res = tmpVar bld rt
      d := readLoc bld size dst
      res := (if isAdd then d .+ s else d .- s)
      if isAdd then setAddFlags bld rt d s res else setSubFlags bld rt d s res
      writeLoc bld size dst res
  }

/// Lifts an ADD.
let add ins bld = arith ins bld true

/// Lifts a SUB.
let sub ins bld = arith ins bld false

/// Lifts an ADDA or a SUBA, which works on the whole of an address register
/// and leaves every condition code alone.
let private arithAddr (ins: Instruction) bld isAdd =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let v = srcAsLong bld ins ins.Size o1
    let an = regOf bld o2
    an := (if isAdd then an .+ v else an .- v)
  }

/// Lifts an ADDA.
let adda ins bld = arithAddr ins bld true

/// Lifts a SUBA.
let suba ins bld = arithAddr ins bld false

/// Lifts an ADDX or a SUBX, which carries the extend flag into the operation
/// so that a sum or a difference can be built one word at a time.
let private arithX (ins: Instruction) bld isAdd =
  lift bld ins {
    let size = ins.Size
    let rt = regTypeOf size
    let struct (o1, o2) = getTwoOprs ins
    let src = transOpr bld ins size o1
    let s = tmpVar bld rt
    s := readLoc bld size src
    let dst = transOpr bld ins size o2
    let d = tmpVar bld rt
    let res = tmpVar bld rt
    let x = AST.zext rt (xf bld)
    d := readLoc bld size dst
    res := (if isAdd then d .+ s .+ x else d .- s .- x)
    if isAdd then setAddXFlags bld rt d s res
    else setSubXFlags bld rt d s res
    writeLoc bld size dst res
  }

/// Lifts an ADDX.
let addx ins bld = arithX ins bld true

/// Lifts a SUBX.
let subx ins bld = arithX ins bld false

/// Adds two packed-BCD bytes and the extend bit, in the order the hardware
/// does it: the two low digits and the extend first, corrected by six if they
/// carried out of a decimal digit, then the two high digits, corrected by ten
/// tens if the byte as a whole carried. The order is the whole of the
/// algorithm -- a carry out of the units has to reach the tens before the
/// tens decide the carry out of the byte.
///
/// The temporaries are thirty-two bits wide and the comparisons are unsigned
/// on purpose. Nothing here can go below zero, but bcdSub's mirror image can,
/// and it relies on the wraparound: this is the shape both need, so both are
/// written the same way.
let private bcdAdd bld dst src =
  let res = tmpVar bld 32<rt>
  let sum = tmpVar bld 32<rt>
  append bld {
    res :=
      (dst .& num32 0x0f) .+ (src .& num32 0x0f) .+ AST.zext 32<rt> (xf bld)
    res := AST.ite (res .> num32 9) (res .+ num32 6) res
    sum := res .+ (dst .& num32 0xf0) .+ (src .& num32 0xf0)
    res := AST.ite (sum .> num32 0x99) (sum .- num32 0xa0) sum
  }
  struct (res, sum .> num32 0x99)

/// Subtracts one packed-BCD byte and the extend bit from another, as bcdAdd
/// adds them.
///
/// The intermediate goes below zero whenever a digit borrows, and the
/// thirty-two bit temporary wraps to something enormous when it does -- which
/// is exactly what the unsigned "greater than nine" test is there to catch,
/// the correction for a borrow being the same test as the correction for a
/// carry. It reads like an oversight and is the reason the sequence works.
let private bcdSub bld dst src =
  let res = tmpVar bld 32<rt>
  let sum = tmpVar bld 32<rt>
  append bld {
    res :=
      (dst .& num32 0x0f) .- (src .& num32 0x0f) .- AST.zext 32<rt> (xf bld)
    res := AST.ite (res .> num32 9) (res .- num32 6) res
    sum := res .+ ((dst .& num32 0xf0) .- (src .& num32 0xf0))
    res := AST.ite (sum .> num32 0x99) (sum .+ num32 0xa0) sum
  }
  struct (res, sum .> num32 0x99)

/// Sets the flags that the BCD group leaves. X and C are both the decimal
/// carry or borrow. The zero flag is CLEARED IF THE RESULT IS NONZERO AND LEFT
/// ALONE OTHERWISE (M68000PRM, "ABCD"), which is what lets a multiprecision
/// chain read as zero exactly when every byte of it did -- the same rule ADDX
/// and SUBX follow. N and V are undefined, and N is given the sign of the byte
/// because that is the most an implementation can usefully leave there.
let private setBcdFlags bld res carry =
  let b = AST.xtlo 8<rt> res
  append bld {
    xf bld := carry
    cf bld := carry
    nf bld := AST.xthi 1<rt> b
    zf bld := zf bld .& (b == AST.num0 8<rt>)
  }

/// Lifts an ABCD or an SBCD, whose two operands are either both data registers
/// or both predecremented addresses -- the shape a decimal string is walked in,
/// from its least significant byte upwards.
let private bcdOp (ins: Instruction) bld isAdd =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let src = transOpr bld ins Sz.Byte o1
    let dst = transOpr bld ins Sz.Byte o2
    let s = tmpVar bld 32<rt>
    let d = tmpVar bld 32<rt>
    s := AST.zext 32<rt> (readLoc bld Sz.Byte src)
    d := AST.zext 32<rt> (readLoc bld Sz.Byte dst)
    let struct (res, carry) = if isAdd then bcdAdd bld d s else bcdSub bld d s
    setBcdFlags bld res carry
    writeLoc bld Sz.Byte dst (AST.xtlo 8<rt> res)
  }

/// Lifts an ABCD.
let abcd ins bld = bcdOp ins bld true

/// Lifts an SBCD.
let sbcd ins bld = bcdOp ins bld false

/// Lifts an NBCD, the ten's complement of a packed-BCD byte: zero minus the
/// operand minus the extend bit, which is an SBCD with nothing to subtract
/// from. That is why the extend bit decides the answer for every input rather
/// than only at a digit boundary -- NBCD of zero is zero when it is clear and
/// 0x99 when it is set.
let nbcd (ins: Instruction) bld =
  lift bld ins {
    let dst = transOpr bld ins Sz.Byte (getOneOpr ins)
    let d = tmpVar bld 32<rt>
    d := AST.zext 32<rt> (readLoc bld Sz.Byte dst)
    let struct (res, carry) = bcdSub bld (AST.num0 32<rt>) d
    setBcdFlags bld res carry
    writeLoc bld Sz.Byte dst (AST.xtlo 8<rt> res)
  }

/// Lifts a PACK, which turns two unpacked digits into one packed byte: the
/// adjustment is added to the source WORD, and bits 11 to 8 and 3 to 0 of that
/// sum are concatenated into the destination BYTE.
///
/// The adjustment is added before the nibbles are taken, so a carry out of the
/// low digit reaches the high one; taking the nibbles first and adjusting them
/// separately agrees on most operands and parts company exactly there. The two
/// operands are different widths, which is what makes the predecrement form
/// move its two address registers by different amounts -- two for the source
/// word, one for the destination byte.
///
/// Neither PACK nor UNPK affects a condition code (M68000PRM).
let pack (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let src = transOpr bld ins Sz.Word o1
    let dst = transOpr bld ins Sz.Byte o2
    let adj = transOpr bld ins Sz.Word o3
    let sum = tmpVar bld 16<rt>
    sum := readLoc bld Sz.Word src .+ readLoc bld Sz.Word adj
    writeLoc bld Sz.Byte dst
      (AST.xtlo 8<rt> (((sum >> numI32 4 16<rt>) .& numI32 0xf0 16<rt>)
                       .| (sum .& numI32 0x0f 16<rt>)))
  }

/// Lifts an UNPK, which is PACK run backwards: the source BYTE's two nibbles
/// are spread into bits 11 to 8 and 3 to 0 of a word, everything else is zero,
/// and only THEN is the adjustment added.
///
/// The order is the opposite of PACK's, and sharing one routine between the two
/// is how an implementation gets one of them right and the other wrong. The
/// widths are the opposite way round as well, so the predecrement form moves
/// its source pointer by one and its destination pointer by two.
let unpk (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let src = transOpr bld ins Sz.Byte o1
    let dst = transOpr bld ins Sz.Word o2
    let adj = transOpr bld ins Sz.Word o3
    let b = tmpVar bld 16<rt>
    b := AST.zext 16<rt> (readLoc bld Sz.Byte src)
    writeLoc bld Sz.Word dst
      ((((b .& numI32 0xf0 16<rt>) << numI32 4 16<rt>)
        .| (b .& numI32 0x0f 16<rt>)) .+ readLoc bld Sz.Word adj)
  }

/// Lifts a NEG or a NEGX, each of which subtracts its operand from zero, the
/// latter taking the extend flag away as well.
let private negate (ins: Instruction) bld withExtend =
  lift bld ins {
    let size = ins.Size
    let rt = regTypeOf size
    let dst = transOpr bld ins size (getOneOpr ins)
    let zero = AST.num0 rt
    let d = tmpVar bld rt
    let res = tmpVar bld rt
    d := readLoc bld size dst
    res := (if withExtend then zero .- d .- AST.zext rt (xf bld) else zero .- d)
    if withExtend then setSubXFlags bld rt zero d res
    else setSubFlags bld rt zero d res
    writeLoc bld size dst res
  }

/// Lifts a NEG.
let neg ins bld = negate ins bld false

/// Lifts a NEGX.
let negx ins bld = negate ins bld true

/// Lifts a CMP, a CMPI, or a CMPM, each of which subtracts without keeping the
/// difference.
let cmp (ins: Instruction) bld =
  lift bld ins {
    let size = ins.Size
    let rt = regTypeOf size
    let struct (o1, o2) = getTwoOprs ins
    let src = transOpr bld ins size o1
    let s = tmpVar bld rt
    s := readLoc bld size src
    let dst = transOpr bld ins size o2
    let d = tmpVar bld rt
    let res = tmpVar bld rt
    d := readLoc bld size dst
    res := d .- s
    setCmpFlags bld rt d s res
  }

/// Lifts a CMPA, which compares against the whole of an address register.
let cmpa (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let s = tmpVar bld 32<rt>
    let d = tmpVar bld 32<rt>
    let res = tmpVar bld 32<rt>
    s := srcAsLong bld ins ins.Size o1
    d := regOf bld o2
    res := d .- s
    setCmpFlags bld 32<rt> d s res
  }

/// Lifts a TST, which reads an operand for the sake of the condition codes it
/// leaves.
let tst (ins: Instruction) bld =
  lift bld ins {
    let size = ins.Size
    let rt = regTypeOf size
    let src = transOpr bld ins size (getOneOpr ins)
    let t = tmpVar bld rt
    t := readLoc bld size src
    setLogicFlags bld rt t
  }

/// Lifts a NOT, which complements every bit of its operand.
let logicNot (ins: Instruction) bld =
  lift bld ins {
    let size = ins.Size
    let rt = regTypeOf size
    let dst = transOpr bld ins size (getOneOpr ins)
    let t = tmpVar bld rt
    t := AST.not (readLoc bld size dst)
    setLogicFlags bld rt t
    writeLoc bld size dst t
  }

/// Lifts an ANDI, an ORI, or an EORI whose destination is the condition code
/// register or the status register, of which a user-mode program has only the
/// condition codes.
let private logicCcr (ins: Instruction) bld op =
  lift bld ins {
    let size = ins.Size
    let struct (o1, _) = getTwoOprs ins
    let v = readLoc bld size (transOpr bld ins size o1)
    let imm = if size = Sz.Byte then v else AST.xtlo 8<rt> v
    setCCR bld (op (ccrValue bld) imm)
  }

/// Lifts one of the logical instructions, which leave the negative and the
/// zero flags of the result behind and clear the other two.
let private logic (ins: Instruction) bld op =
  let struct (o1, o2) = getTwoOprs ins
  match o2 with
  | OpReg R.CCR | OpReg R.SR ->
    logicCcr ins bld op
  | _ ->
    lift bld ins {
      let size = ins.Size
      let rt = regTypeOf size
      let src = transOpr bld ins size o1
      let s = tmpVar bld rt
      s := readLoc bld size src
      let dst = transOpr bld ins size o2
      let t = tmpVar bld rt
      t := op (readLoc bld size dst) s
      setLogicFlags bld rt t
      writeLoc bld size dst t
    }

/// Lifts an AND or an ANDI.
let logicAnd ins bld = logic ins bld AST.``and``

/// Lifts an OR or an ORI.
let logicOr ins bld = logic ins bld AST.``or``

/// Lifts an EOR or an EORI.
let logicXor ins bld = logic ins bld AST.xor

/// Lifts a MULU or a MULS whose operands are words, which multiply into the
/// whole of a data register.
let private mulWord (ins: Instruction) bld isSigned =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let widen = if isSigned then AST.sext 32<rt> else AST.zext 32<rt>
    let src = transOpr bld ins Sz.Word o1
    let dn = regOf bld o2
    let t = tmpVar bld 32<rt>
    t := widen (readLoc bld Sz.Word src) .* widen (AST.xtlo 16<rt> dn)
    setLogicFlags bld 32<rt> t
    dn := t
  }

/// Lifts a MULU.L or a MULS.L, whose product fills either one register or the
/// pair of them that the extension word names.
let private mulLong (ins: Instruction) bld isSigned =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let widen = if isSigned then AST.sext 64<rt> else AST.zext 64<rt>
    let src = transOpr bld ins Sz.Long o1
    let res = tmpVar bld 64<rt>
    match o2 with
    | OpRegPair(dh, dl) ->
      res := widen (readLoc bld Sz.Long src) .* widen (regVar bld dl)
      setLogicFlags bld 64<rt> res
      regVar bld dh := AST.xthi 32<rt> res
      regVar bld dl := AST.xtlo 32<rt> res
    | OpReg dl ->
      res := widen (readLoc bld Sz.Long src) .* widen (regVar bld dl)
      nf bld := AST.extract res 1<rt> 31
      zf bld := AST.xtlo 32<rt> res == AST.num0 32<rt>
      vf bld := widen (AST.xtlo 32<rt> res) != res
      cf bld := AST.b0
      regVar bld dl := AST.xtlo 32<rt> res
    | _ ->
      raise InvalidOperandException
  }

/// Lifts a MULU.
let mulu (ins: Instruction) bld =
  if ins.Size = Sz.Long then mulLong ins bld false else mulWord ins bld false

/// Lifts a MULS.
let muls (ins: Instruction) bld =
  if ins.Size = Sz.Long then mulLong ins bld true else mulWord ins bld true

/// A sixty-four-bit constant, the width every divide is computed at so that no
/// quotient of an m68k divide can overflow the operation that produces it.
let inline private num64 (n: int64) = numI64 n 64<rt>

/// Emits the quotient and the remainder of a signed division, standing in for
/// the one division a sixty-four-bit machine cannot perform -- the smallest
/// value over minus one -- with the negation that it would be. The overflow
/// the m68k reports for it is what the range check on the quotient finds
/// afterwards.
let private sdivInto bld q r d s =
  let isMinusOne = s == num64 -1L
  let safe = tmpVar bld 64<rt>
  append bld {
    safe := AST.ite isMinusOne (AST.num1 64<rt>) s
    q := AST.ite isMinusOne (AST.num0 64<rt> .- d) (d ?/ safe)
    r := AST.ite isMinusOne (AST.num0 64<rt>) (d ?% safe)
  }

/// Emits the quotient and the remainder of an unsigned division, no case of
/// which overflows.
let private udivInto bld q r d s =
  append bld {
    q := d ./ s
    r := d .% s
  }

/// Whether a quotient is too wide for the register it has to go into, which
/// is the overflow a divide reports rather than writing anything at all.
let private divOverflow isSigned bits q =
  if isSigned then
    let hi = num64 ((1L <<< (bits - 1)) - 1L)
    (q ?> hi) .| (q ?< AST.num0 64<rt> .- hi .- AST.num1 64<rt>)
  else
    q .> num64 ((1L <<< bits) - 1L)

/// Lifts a DIVU or a DIVS whose divisor is a word, whose quotient and
/// remainder share the data register the dividend came from.
let private divWord (ins: Instruction) bld isSigned =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let widen = if isSigned then AST.sext 64<rt> else AST.zext 64<rt>
    let src = transOpr bld ins Sz.Word o1
    let dn = regOf bld o2
    let s = tmpVar bld 64<rt>
    let d = tmpVar bld 64<rt>
    let q = tmpVar bld 64<rt>
    let r = tmpVar bld 64<rt>
    s := widen (readLoc bld Sz.Word src)
    d := widen dn
    _if bld "DivZero" (s == AST.num0 64<rt>)
      (block { AST.sideEffect (Exception DivideError) })
      (block {
        if isSigned then sdivInto bld q r d s else udivInto bld q r d s
        cf bld := AST.b0
        _if bld "DivOverflow" (divOverflow isSigned 16 q)
          (block { vf bld := AST.b1 })
          (block {
            vf bld := AST.b0
            setNZ bld 16<rt> (AST.xtlo 16<rt> q)
            dn := AST.concat (AST.xtlo 16<rt> r) (AST.xtlo 16<rt> q)
          })
      })
  }

/// Lifts one of the long divides the 68020 added, whose dividend is either the
/// pair of registers the extension word names or the lower of them alone, and
/// whose quotient and remainder each get a register of their own.
let private divLong (ins: Instruction) bld isSigned isWide =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let widen = if isSigned then AST.sext 64<rt> else AST.zext 64<rt>
    let src = transOpr bld ins Sz.Long o1
    let struct (dr, dq) =
      match o2 with
      | OpRegPair(dr, dq) -> struct (regVar bld dr, regVar bld dq)
      | _ -> raise InvalidOperandException
    let s = tmpVar bld 64<rt>
    let d = tmpVar bld 64<rt>
    let q = tmpVar bld 64<rt>
    let r = tmpVar bld 64<rt>
    s := widen (readLoc bld Sz.Long src)
    d := (if isWide then AST.concat dr dq else widen dq)
    _if bld "DivZero" (s == AST.num0 64<rt>)
      (block { AST.sideEffect (Exception DivideError) })
      (block {
        if isSigned then sdivInto bld q r d s else udivInto bld q r d s
        cf bld := AST.b0
        _if bld "DivOverflow" (divOverflow isSigned 32 q)
          (block { vf bld := AST.b1 })
          (block {
            vf bld := AST.b0
            setNZ bld 32<rt> (AST.xtlo 32<rt> q)
            dr := AST.xtlo 32<rt> r
            dq := AST.xtlo 32<rt> q
          })
      })
  }

/// Lifts a DIVU, which is the word divide or the wide long one.
let divu (ins: Instruction) bld =
  if ins.Size = Sz.Long then divLong ins bld false true
  else divWord ins bld false

/// Lifts a DIVS, which is the word divide or the wide long one.
let divs (ins: Instruction) bld =
  if ins.Size = Sz.Long then divLong ins bld true true
  else divWord ins bld true

/// Lifts a DIVUL, the long divide whose dividend is one register.
let divul ins bld = divLong ins bld false false

/// Lifts a DIVSL, the long divide whose dividend is one register.
let divsl ins bld = divLong ins bld true false

/// The number of bits an operation of the given width works on.
let inline private width rt = RegType.toBitWidth rt

/// Shifts left by a count that may reach or pass the width of the operand,
/// which the intermediate representation leaves to whoever emits it.
let private shlSafe rt d n =
  AST.ite (n .>= numI32 (width rt) rt) (AST.num0 rt) (d << n)

/// Shifts right by a count that may reach or pass the width of the operand.
let private shrSafe rt d n =
  AST.ite (n .>= numI32 (width rt) rt) (AST.num0 rt) (d >> n)

/// Shifts right, filling with the sign bit, by a count that may reach or pass
/// the width of the operand.
let private sarSafe rt d n =
  let top = numI32 (width rt - 1) rt
  AST.ite (n .>= numI32 (width rt) rt) (d ?>> top) (d ?>> n)

/// The bit a left shift of the given count last moves out of the top, which is
/// the carry it leaves. A count past the width moves only zeroes out.
let private lastOutLeft rt d n =
  let w = numI32 (width rt) rt
  AST.ite (n .> w) AST.b0 (AST.xtlo 1<rt> (shrSafe rt d (w .- n)))

/// The bit a right shift of the given count last moves out of the bottom.
let private lastOutRight rt d n =
  let w = numI32 (width rt) rt
  AST.ite (n .> w) AST.b0 (AST.xtlo 1<rt> (shrSafe rt d (n .- AST.num1 rt)))

/// Whether the sign bit changed at any point during an arithmetic left shift,
/// which is the overflow such a shift reports. Where the count reaches the
/// width every bit leaves, so the sign changed just when there was a bit to
/// change it; short of that, the bits the shift moves through the sign
/// position have to have been the sign already.
let private aslOverflow rt d n =
  let top = numI32 (width rt - 1) rt
  let s = sarSafe rt d (top .- n)
  let allSame = (s == AST.num0 rt) .| (s == AST.not (AST.num0 rt))
  AST.ite (n .>= numI32 (width rt) rt)
          (d != AST.num0 rt)
          (AST.not allSame)

/// Emits a shift or a rotate of the given kind, leaving the condition codes
/// that it does. A count of zero shifts nothing and clears the carry, except
/// in a rotate through the extend flag, where the carry takes that flag's
/// value instead.
let private doShift bld rt opcode d n =
  let w = numI32 (width rt) rt
  let res = tmpVar bld rt
  let isZero = n == AST.num0 rt
  match opcode with
  | Op.LSL | Op.ASL ->
    append bld {
      res := shlSafe rt d n
      cf bld := AST.ite isZero AST.b0 (lastOutLeft rt d n)
      xf bld := AST.ite isZero (xf bld) (cf bld)
      vf bld := (if opcode = Op.ASL then aslOverflow rt d n else AST.b0)
    }
  | Op.LSR ->
    append bld {
      res := shrSafe rt d n
      cf bld := AST.ite isZero AST.b0 (lastOutRight rt d n)
      xf bld := AST.ite isZero (xf bld) (cf bld)
      vf bld := AST.b0
    }
  | Op.ASR ->
    append bld {
      res := sarSafe rt d n
      cf bld :=
        AST.ite isZero AST.b0 (AST.xtlo 1<rt> (sarSafe rt d (n .- AST.num1 rt)))
      xf bld := AST.ite isZero (xf bld) (cf bld)
      vf bld := AST.b0
    }
  | Op.ROL | Op.ROR ->
    let k = tmpVar bld rt
    append bld {
      k := n .% w
      res :=
        AST.ite (k == AST.num0 rt)
                d
                (if opcode = Op.ROL then (d << k) .| (d >> (w .- k))
                 else (d >> k) .| (d << (w .- k)))
      cf bld :=
        AST.ite isZero
                AST.b0
                (if opcode = Op.ROL then AST.xtlo 1<rt> res
                 else AST.xthi 1<rt> res)
      vf bld := AST.b0
    }
  | _ ->
    (* A rotate through the extend flag turns that flag into one more bit above
       the top of the operand, so the whole of it is one rotation of a value a
       bit wider, and a count that comes round to nothing leaves both the flag
       and the operand as they were. *)
    let wide = RegType.fromBitWidth (width rt + 1)
    let m = numI32 (width rt + 1) wide
    let v = tmpVar bld wide
    let k = tmpVar bld wide
    let wres = tmpVar bld wide
    append bld {
      v := AST.concat (xf bld) d
      k := AST.zext wide n .% m
      wres :=
        AST.ite (k == AST.num0 wide)
                v
                (if opcode = Op.ROXL then (v << k) .| (v >> (m .- k))
                 else (v >> k) .| (v << (m .- k)))
      xf bld := AST.xthi 1<rt> wres
      cf bld := xf bld
      vf bld := AST.b0
      res := AST.xtlo rt wres
    }
  append bld { nf bld := AST.xthi 1<rt> res }
  append bld { zf bld := res == AST.num0 rt }
  res

/// Lifts one of the shifts or the rotates, whose count is a small literal, the
/// low six bits of a data register, or -- where what it moves is a word in
/// memory -- one place and no more.
let private shift (ins: Instruction) bld =
  lift bld ins {
    match ins.Operands with
    | OneOperand o ->
      let dst = transOpr bld ins Sz.Word o
      let d = tmpVar bld 16<rt>
      d := readLoc bld Sz.Word dst
      let r = doShift bld 16<rt> ins.Opcode d (AST.num1 16<rt>)
      writeLoc bld Sz.Word dst r
    | TwoOperands(o1, o2) ->
      let size = ins.Size
      let rt = regTypeOf size
      let dst = transOpr bld ins size o2
      let d = tmpVar bld rt
      let n = tmpVar bld rt
      n :=
        (match o1 with
         | OpImm v -> numI64 v rt
         | OpReg r -> AST.xtlo rt (regVar bld r .% num32 64)
         | _ -> raise InvalidOperandException)
      d := readLoc bld size dst
      writeLoc bld size dst (doShift bld rt ins.Opcode d n)
    | _ ->
      raise InvalidOperandException
  }

/// Lifts an ASL, an ASR, an LSL, an LSR, a ROL, a ROR, a ROXL, or a ROXR.
let shiftOrRotate ins bld = shift ins bld

/// Lifts a MOVEM, which moves a list of registers to or from consecutive
/// places in memory. A predecrementing store fills memory downwards from the
/// last register of the bank; every other mode runs from the first register
/// upwards.
let movem (ins: Instruction) bld =
  lift bld ins {
    let size = ins.Size
    let rt = regTypeOf size
    let step = if size = Sz.Long then 4 else 2
    let struct (o1, o2) = getTwoOprs ins
    match o1, o2 with
    | OpRegList regs, OpMem(PreDec an) ->
      let ar = regVar bld an
      let t = tmpVar bld 32<rt>
      t := ar
      for r in Array.rev regs do
        t := t .- num32 step
        storeNative bld t (AST.xtlo rt (regVar bld r))
      ar := t
    | OpRegList regs, dstOpr ->
      let addr = tmpVar bld 32<rt>
      match transOpr bld ins size dstOpr with
      | LMem a -> addr := a
      | _ -> raise InvalidOperandException
      for i in 0 .. regs.Length - 1 do
        storeNative bld (addr .+ num32 (i * step))
                        (AST.xtlo rt (regVar bld regs[i]))
    | OpMem(PostInc an), OpRegList regs ->
      let ar = regVar bld an
      let t = tmpVar bld 32<rt>
      t := ar
      for r in regs do
        regVar bld r := AST.sext 32<rt> (loadNative bld rt t)
        t := t .+ num32 step
      ar := t
    | srcOpr, OpRegList regs ->
      let addr = tmpVar bld 32<rt>
      match transOpr bld ins size srcOpr with
      | LMem a -> addr := a
      | _ -> raise InvalidOperandException
      for i in 0 .. regs.Length - 1 do
        regVar bld regs[i] :=
          AST.sext 32<rt> (loadNative bld rt (addr .+ num32 (i * step)))
    | _ ->
      raise InvalidOperandException
  }

/// Lifts a BTST, a BSET, a BCLR, or a BCHG, each of which reports the bit it
/// names in the zero flag before doing whatever it does to it. A bit of a data
/// register is one of thirty-two and a bit in memory one of eight.
let bit (ins: Instruction) bld =
  lift bld ins {
    let size = ins.Size
    let rt = regTypeOf size
    let struct (o1, o2) = getTwoOprs ins
    let bitno =
      match o1 with
      | OpImm v -> numI64 v 32<rt>
      | OpReg r -> regVar bld r
      | _ -> raise InvalidOperandException
    let dst = transOpr bld ins size o2
    let n = tmpVar bld rt
    let d = tmpVar bld rt
    n := AST.xtlo rt (bitno .% numI32 (width rt) 32<rt>)
    d := readLoc bld size dst
    zf bld := AST.not (AST.xtlo 1<rt> (d >> n))
    match ins.Opcode with
    | Op.BTST -> ()
    | Op.BSET -> writeLoc bld size dst (d .| (AST.num1 rt << n))
    | Op.BCLR -> writeLoc bld size dst (d .& AST.not (AST.num1 rt << n))
    | _ -> writeLoc bld size dst (d <+> (AST.num1 rt << n))
  }

/// Lifts a BRA.
let bra (ins: Instruction) bld =
  lift bld ins {
    AST.interjmp (branchTarget ins) InterJmpKind.Base
    return NoEndMark
  }

/// Lifts a BSR, which leaves the address it came from on the stack.
let bsr (ins: Instruction) bld =
  lift bld ins {
    let t = tmpVar bld 32<rt>
    t := fallThrough ins
    push bld t
    AST.interjmp (branchTarget ins) InterJmpKind.IsCall
    return NoEndMark
  }

/// Lifts a Bcc.
let bcc (ins: Instruction) bld =
  lift bld ins {
    AST.intercjmp (condExpr bld ins.Opcode) (branchTarget ins) (fallThrough ins)
    return NoEndMark
  }

/// Lifts a DBcc, which branches only where its condition fails and the counter
/// it decrements has not yet run past zero.
let dbcc (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, _) = getTwoOprs ins
    let dn = regOf bld o1
    let counter = AST.xtlo 16<rt> dn
    let fall = fallThrough ins
    _if bld "DbccTaken" (condExpr bld ins.Opcode)
      (block { AST.interjmp fall InterJmpKind.Base })
      (block {
        counter := counter .- AST.num1 16<rt>
        AST.intercjmp (counter != AST.not (AST.num0 16<rt>))
                      (branchTarget ins)
                      fall
      })
    return NoEndMark
  }

/// Lifts an Scc, which fills a byte with ones where its condition holds and
/// with zeroes where it does not.
let scc (ins: Instruction) bld =
  lift bld ins {
    let dst = transOpr bld ins Sz.Byte (getOneOpr ins)
    writeLoc bld Sz.Byte dst
      (AST.ite (condExpr bld ins.Opcode)
               (AST.not (AST.num0 8<rt>))
               (AST.num0 8<rt>))
  }

/// Returns the address a JMP or a JSR names, which is the effective address
/// itself rather than what lies at it.
let private jumpTarget bld ins =
  match transOpr bld ins Sz.NoSize (getOneOpr ins) with
  | LMem addr -> addr
  | _ -> raise InvalidOperandException

/// Lifts a JMP.
let jmp (ins: Instruction) bld =
  lift bld ins {
    AST.interjmp (jumpTarget bld ins) InterJmpKind.Base
    return NoEndMark
  }

/// Lifts a JSR, which leaves the address it came from on the stack.
let jsr (ins: Instruction) bld =
  lift bld ins {
    let target = tmpVar bld 32<rt>
    let ret = tmpVar bld 32<rt>
    target := jumpTarget bld ins
    ret := fallThrough ins
    push bld ret
    AST.interjmp target InterJmpKind.IsCall
    return NoEndMark
  }

/// Lifts an RTS, which returns to the address the matching call left on the
/// stack.
let rts (ins: Instruction) bld =
  lift bld ins {
    let t = tmpVar bld 32<rt>
    pop bld t
    AST.interjmp t InterJmpKind.IsRet
    return NoEndMark
  }

/// Lifts an RTD, which returns and then drops the arguments the caller pushed.
let rtd (ins: Instruction) bld =
  lift bld ins {
    let t = tmpVar bld 32<rt>
    let disp =
      match getOneOpr ins with
      | OpImm d -> num32 (int32 (int16 d))
      | _ -> raise InvalidOperandException
    pop bld t
    regVar bld R.A7 := regVar bld R.A7 .+ disp
    AST.interjmp t InterJmpKind.IsRet
    return NoEndMark
  }

/// Lifts an RTR, which restores the condition codes the matching call saved
/// before returning.
let rtr (ins: Instruction) bld =
  lift bld ins {
    let sp = regVar bld R.A7
    let t = tmpVar bld 32<rt>
    setCCR bld (loadNative bld 8<rt> (sp .+ num32 1))
    sp := sp .+ num32 2
    pop bld t
    AST.interjmp t InterJmpKind.IsRet
    return NoEndMark
  }

/// Rotates a long word left by fewer than thirty-two places, which is what
/// brings the first bit of a bit field in a register up to the top of it.
let private rotl32 v n =
  AST.ite (n == AST.num0 32<rt>) v ((v << n) .| (v >> (num32 32 .- n)))

/// Rotates a long word right by fewer than thirty-two places, undoing what
/// rotating it left by the same count did.
let private rotr32 v n =
  AST.ite (n == AST.num0 32<rt>) v ((v >> n) .| (v << (num32 32 .- n)))

/// Returns the offset and the width a bit field names, each of which is a
/// literal or the low bits of a data register. A width taken from a register
/// is one of thirty-two, of which none at all means all of them.
let private bfSpec bld (spec: BitFieldSpec) =
  let offset =
    match spec.Offset with
    | OpImm v -> numI64 v 32<rt>
    | OpReg r -> regVar bld r
    | _ -> raise InvalidOperandException
  let wid =
    match spec.Width with
    | OpImm v ->
      numI64 v 32<rt>
    | OpReg r ->
      let m = regVar bld r .& num32 31
      AST.ite (m == AST.num0 32<rt>) (num32 32) m
    | _ ->
      raise InvalidOperandException
  struct (offset, wid)

/// Reads the given number of bytes beginning at an address as one value, in
/// the one, two, and four byte pieces the memory system takes.
let private loadBytes bld addr nbytes =
  match nbytes with
  | 1 ->
    loadNative bld 8<rt> addr
  | 2 ->
    loadNative bld 16<rt> addr
  | 3 ->
    AST.concat (loadNative bld 16<rt> addr)
               (loadNative bld 8<rt> (addr .+ num32 2))
  | 4 ->
    loadNative bld 32<rt> addr
  | _ ->
    AST.concat (loadNative bld 32<rt> addr)
               (loadNative bld 8<rt> (addr .+ num32 4))

/// Writes a value of the given number of bytes at an address, in the pieces a
/// read of it is split into.
let private storeBytes bld addr nbytes v =
  match nbytes with
  | 1 | 2 | 4 ->
    append bld { storeNative bld addr v }
  | 3 ->
    append bld {
      storeNative bld addr (AST.xthi 16<rt> v)
      storeNative bld (addr .+ num32 2) (AST.xtlo 8<rt> v)
    }
  | _ ->
    append bld {
      storeNative bld addr (AST.xthi 32<rt> v)
      storeNative bld (addr .+ num32 4) (AST.xtlo 8<rt> v)
    }

/// How many bytes a bit field in memory falls in. Where the offset and the
/// width are both literals the run is known exactly; where either comes from a
/// register the widest run a field can span is taken instead, which is the
/// five bytes that seven bits of offset and thirty-two of width reach.
let private bfByteCount (spec: BitFieldSpec) =
  match spec.Offset, spec.Width with
  | OpImm off, OpImm wid -> ((int off &&& 7) + int wid + 7) / 8
  | _ -> 5

/// Reads a bit field out of a data register into the low bits of a long word,
/// and returns it with the writer that puts a new one back. Rotating the
/// register until the first bit of the field is at the top is what makes a
/// field that wraps around the register a run of bits like any other.
let private bfRegAccess bld dn spec =
  let struct (off, wid) = bfSpec bld spec
  let dnv = regVar bld dn
  let off31 = tmpVar bld 32<rt>
  let rot = tmpVar bld 32<rt>
  let sh = tmpVar bld 32<rt>
  let keep = tmpVar bld 32<rt>
  append bld {
    off31 := off .& num32 31
    rot := rotl32 dnv off31
    sh := num32 32 .- wid
    keep := AST.not (AST.not (AST.num0 32<rt>) << sh)
  }
  let write v =
    append bld { dnv := rotr32 ((rot .& keep) .| (v << sh)) off31 }
  struct (off, wid, rot >> sh, write)

/// Reads a bit field out of memory into the low bits of a long word, and
/// returns it with the writer that puts a new one back. The bytes the field
/// falls in are read as one value, which the field is then taken out of.
let private bfMemAccess bld ins ea spec =
  let struct (off, wid) = bfSpec bld spec
  let nbytes = bfByteCount spec
  let crt = RegType.fromBitWidth (nbytes * 8)
  let addr =
    match transOpr bld ins Sz.NoSize ea with
    | LMem a -> a
    | _ -> raise InvalidOperandException
  let a = tmpVar bld 32<rt>
  let c = tmpVar bld 64<rt>
  let sh = tmpVar bld 64<rt>
  let mask = tmpVar bld 64<rt>
  append bld {
    a := addr .+ (off ?>> num32 3)
    c := AST.zext 64<rt> (loadBytes bld a nbytes)
    sh :=
      AST.zext 64<rt> (numI32 (nbytes * 8) 32<rt> .- (off .& num32 7) .- wid)
    mask := (AST.num1 64<rt> << AST.zext 64<rt> wid) .- AST.num1 64<rt>
  }
  let write v =
    let nv = (c .& AST.not (mask << sh)) .| ((AST.zext 64<rt> v .& mask) << sh)
    storeBytes bld a nbytes (AST.xtlo crt nv)
  struct (off, wid, AST.xtlo 32<rt> ((c >> sh) .& mask), write)

/// Reads the bit field an instruction names, wherever it lives.
let private bfAccess bld ins opr =
  match opr with
  | OpBitField(OpReg dn, spec) when not (isAddrReg dn) ->
    bfRegAccess bld dn spec
  | OpBitField(ea, spec) ->
    bfMemAccess bld ins ea spec
  | _ ->
    raise InvalidOperandException

/// Sets the condition codes a bit field instruction leaves: the top bit of the
/// field and whether it holds anything, with the other two cleared.
let private setBfFlags bld wid f =
  append bld {
    nf bld := AST.xtlo 1<rt> (f >> (wid .- num32 1))
    zf bld := f == AST.num0 32<rt>
    vf bld := AST.b0
    cf bld := AST.b0
  }

/// Lifts a BFTST, a BFCHG, a BFCLR, or a BFSET, none of which names a register
/// beside the field itself.
let private bitFieldInPlace (ins: Instruction) bld =
  lift bld ins {
    let struct (_, wid, field, write) = bfAccess bld ins (getOneOpr ins)
    let t = tmpVar bld 32<rt>
    t := field
    setBfFlags bld wid t
    match ins.Opcode with
    | Op.BFTST -> ()
    | Op.BFCLR -> write (AST.num0 32<rt>)
    | Op.BFSET -> write (AST.not (AST.num0 32<rt>))
    | _ -> write (AST.not t)
  }

/// Lifts a BFINS, which puts the low bits of a data register into the field.
let private bitFieldIns (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let dn = regOf bld o1
    let struct (_, wid, _, write) = bfAccess bld ins o2
    let sh = tmpVar bld 32<rt>
    let t = tmpVar bld 32<rt>
    sh := num32 32 .- wid
    t := (dn << sh) >> sh
    setBfFlags bld wid t
    write t
  }

/// Lifts a BFEXTU, a BFEXTS, or a BFFFO, each of which takes something out of
/// the field and into a data register.
let private bitFieldExtract (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (off, wid, field, _) = bfAccess bld ins o1
    let dn = regOf bld o2
    let t = tmpVar bld 32<rt>
    t := field
    setBfFlags bld wid t
    match ins.Opcode with
    | Op.BFEXTU ->
      dn := t
    | Op.BFEXTS ->
      let sh = tmpVar bld 32<rt>
      sh := num32 32 .- wid
      dn := (t << sh) ?>> sh
    | _ ->
      (* A search for the first bit set runs from the top of the field down,
         and where the field holds nothing at all it stops just past the end,
         which is the offset plus the width. *)
      let top = tmpVar bld 32<rt>
      let i = tmpVar bld 32<rt>
      top := t << (num32 32 .- wid)
      i := AST.num0 32<rt>
      let unset = AST.xthi 1<rt> (shlSafe 32<rt> top i) == AST.b0
      _while bld "Bfffo" ((i .< wid) .& unset)
        (block {
          i := i .+ num32 1
        })
      dn := off .+ i
  }

/// Lifts one of the bit field instructions the 68020 added.
let bitFieldOp (ins: Instruction) bld =
  match ins.Opcode with
  | Op.BFINS -> bitFieldIns ins bld
  | Op.BFEXTU | Op.BFEXTS | Op.BFFFO -> bitFieldExtract ins bld
  | _ -> bitFieldInPlace ins bld

/// Lifts a NOP, which does nothing at all.
let nop (ins: Instruction) bld =
  lift bld ins { () }

/// Lifts a TRAP, of which the one that takes vector zero is how a program on
/// Linux asks the kernel for something.
let trap (ins: Instruction) bld =
  lift bld ins {
    match getOneOpr ins with
    | OpImm 0L -> AST.sideEffect SysCall
    | OpImm n -> AST.sideEffect (Interrupt(int n))
    | _ -> raise InvalidOperandException
  }

/// Lifts a TRAPV, which traps where the last operation overflowed.
let trapv (ins: Instruction) bld =
  lift bld ins {
    _when bld "Trapv" (vf bld)
      (block {
        AST.sideEffect (Exception IntegerOverflow)
      })
  }

/// Lifts a TRAPcc, which traps where its condition holds.
let trapcc (ins: Instruction) bld =
  lift bld ins {
    _when bld "Trapcc" (condExpr bld ins.Opcode)
      (block {
        AST.sideEffect (Exception IntegerOverflow)
      })
  }

/// Lifts an ILLEGAL, the encoding that is defined to be undefined.
let illegal (ins: Instruction) bld =
  lift bld ins { AST.sideEffect UndefinedInstruction }

/// Lifts a BKPT, which is how a debugger stops a program.
let bkpt (ins: Instruction) bld =
  lift bld ins { AST.sideEffect Breakpoint }

/// Lifts a CHK, which traps where the value it checks falls outside the bound
/// the source gives.
let chk (ins: Instruction) bld =
  lift bld ins {
    let size = ins.Size
    let rt = regTypeOf size
    let struct (o1, o2) = getTwoOprs ins
    let bound = tmpVar bld rt
    let v = tmpVar bld rt
    bound := readLoc bld size (transOpr bld ins size o1)
    v := AST.xtlo rt (regOf bld o2)
    nf bld := v ?< AST.num0 rt
    _when bld "Chk" ((v ?< AST.num0 rt) .| (v ?> bound))
      (block {
        AST.sideEffect (Exception IntegerOverflow)
      })
  }

/// Lifts a TAS, which reports what a byte held and then sets its top bit,
/// which is how a lock is taken on an m68k.
let tas (ins: Instruction) bld =
  lift bld ins {
    let dst = transOpr bld ins Sz.Byte (getOneOpr ins)
    let t = tmpVar bld 8<rt>
    AST.sideEffect AtomicBegin
    t := readLoc bld Sz.Byte dst
    setLogicFlags bld 8<rt> t
    writeLoc bld Sz.Byte dst (t .| numI32 0x80 8<rt>)
    AST.sideEffect AtomicEnd
  }

/// Lifts a CAS, which writes one register into a place only where another
/// register still holds what that place does, and takes what it holds away
/// where it does not.
let cas (ins: Instruction) bld =
  lift bld ins {
    let size = ins.Size
    let rt = regTypeOf size
    let struct (o1, o2, o3) = getThreeOprs ins
    let dc = transOpr bld ins size o1
    let du = transOpr bld ins size o2
    let dst = transOpr bld ins size o3
    let d = tmpVar bld rt
    let c = tmpVar bld rt
    let res = tmpVar bld rt
    AST.sideEffect AtomicBegin
    d := readLoc bld size dst
    c := readLoc bld size dc
    res := d .- c
    setCmpFlags bld rt d c res
    _if bld "CasEqual" (res == AST.num0 rt)
      (block {
        writeLoc bld size dst (readLoc bld size du)
      })
      (block {
        writeLoc bld size dc d
      })
    AST.sideEffect AtomicEnd
  }

/// Returns the two registers of a pair operand, which is how CAS2 names each
/// of its three.
let private regPairOf opr =
  match opr with
  | OpRegPair(a, b) -> struct (a, b)
  | _ -> raise InvalidOperandException

/// Returns the two registers whose contents CAS2 compares and swaps through.
let private memPairOf opr =
  match opr with
  | OpMemPair(a, b) -> struct (a, b)
  | _ -> raise InvalidOperandException

/// Lifts a CAS2, the double compare and swap, and the one instruction here with
/// control flow inside it. From the manual:
///
///   Destination 1 - Compare 1 -> cc
///   if Z then
///     Destination 2 - Compare 2 -> cc
///     if Z then Update 1 -> Destination 1; Update 2 -> Destination 2
///          else Destination 1 -> Compare 1; Destination 2 -> Compare 2
///   else Destination 1 -> Compare 1; Destination 2 -> Compare 2
///
/// Four things follow that are easy to get wrong. The subtraction is MEMORY
/// MINUS REGISTER, so an implementation with the operands the wrong way round
/// still sets Z correctly -- equality being symmetric -- and gets N and C
/// backwards on every round that fails. The failing path writes BOTH compare
/// registers, not merely the one that missed, which is why both locations are
/// read before anything is decided. The condition codes are the second
/// comparison's whenever the first one held, including on the successful path.
/// And the extend bit is not touched, setCmpFlags leaving it alone.
let cas2 (ins: Instruction) bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (c1, c2) = regPairOf o1
  let struct (u1, u2) = regPairOf o2
  let struct (m1, m2) = memPairOf o3
  lift bld ins {
    let size = ins.Size
    let rt = regTypeOf size
    let cv1 = readLoc bld size (LReg c1)
    let cv2 = readLoc bld size (LReg c2)
    let a1 = tmpVar bld 32<rt>
    let a2 = tmpVar bld 32<rt>
    let d1 = tmpVar bld rt
    let d2 = tmpVar bld rt
    let res = tmpVar bld rt
    AST.sideEffect AtomicBegin
    a1 := regVar bld m1
    a2 := regVar bld m2
    d1 := loadNative bld rt a1
    d2 := loadNative bld rt a2
    res := d1 .- cv1
    setCmpFlags bld rt d1 cv1 res
    _if bld "Cas2First" (res == AST.num0 rt)
      (block {
        res := d2 .- cv2
        setCmpFlags bld rt d2 cv2 res
        _if bld "Cas2Second" (res == AST.num0 rt)
          (block {
            storeNative bld a1 (readLoc bld size (LReg u1))
            storeNative bld a2 (readLoc bld size (LReg u2))
          })
          (block {
            writeLoc bld size (LReg c1) d1
            writeLoc bld size (LReg c2) d2
          })
      })
      (block {
        writeLoc bld size (LReg c1) d1
        writeLoc bld size (LReg c2) d2
      })
    AST.sideEffect AtomicEnd
  }

/// Returns the address a MOVE16 operand names, emitting the register update
/// that a postincrement performs.
///
/// The transfer is aligned to a sixteen-byte line: the low four bits of the
/// address are IGNORED (M68040UM, "MOVE16"), so a pointer into the middle of a
/// line moves the whole line it sits in. A postincrement, though, adds sixteen
/// to the register AS IT STANDS, unmasked -- so a register that went in
/// misaligned comes out misaligned by the same amount, and an implementation
/// that masks the register rather than only the address it uses passes every
/// aligned case and fails every other one.
let private move16Addr bld opr =
  let t = tmpVar bld 32<rt>
  match opr with
  | OpMem(PostInc r) ->
    let rv = regVar bld r
    append bld {
      t := rv .& numU32 0xfffffff0u 32<rt>
      rv := rv .+ num32 16
    }
  | OpMem(Direct r) ->
    append bld {
      t := regVar bld r .& numU32 0xfffffff0u 32<rt>
    }
  | OpAddr addr ->
    append bld {
      t := numU32 (uint32 addr &&& 0xfffffff0u) 32<rt>
    }
  | _ ->
    raise InvalidOperandException
  t

/// Lifts a MOVE16, the 68040's block move: one sixteen-byte line, in the five
/// forms the encoding gives it. Which register moves afterwards is what
/// separates them -- both for "(Ax)+,(Ay)+", one for the two forms with an
/// absolute address and a postincrement, and neither for the two with an
/// absolute address and a plain indirect.
///
/// Both halves are read before either is written, so that a source and a
/// destination naming the same line copy it rather than smear it. The manual
/// leaves that case undefined; this is the more useful of the two answers.
/// MOVE16 touches no condition code.
let move16 (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let s = move16Addr bld o1
    let d = move16Addr bld o2
    let v0 = tmpVar bld 64<rt>
    let v1 = tmpVar bld 64<rt>
    v0 := loadNative bld 64<rt> s
    v1 := loadNative bld 64<rt> (s .+ num32 8)
    storeNative bld d v0
    storeNative bld (d .+ num32 8) v1
  }

/// Lifts a MOVEP, which moves the bytes of a data register to or from every
/// other byte of memory, which is how a peripheral on a byte-wide bus is
/// reached.
let movep (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let count = if ins.Size = Sz.Long then 4 else 2
    let toMemory =
      match o1 with
      | OpReg _ -> true
      | _ -> false
    let regOpr = if toMemory then o1 else o2
    let memOpr = if toMemory then o2 else o1
    let dn = regOf bld regOpr
    let addr = tmpVar bld 32<rt>
    match transOpr bld ins Sz.NoSize memOpr with
    | LMem a ->
      addr := a
    | _ ->
      raise InvalidOperandException
    if toMemory then
      for i in 0 .. count - 1 do
        let sh = num32 ((count - 1 - i) * 8)
        storeNative bld (addr .+ num32 (i * 2)) (AST.xtlo 8<rt> (dn >> sh))
    else
      let bytes =
        [| for i in count - 1 .. -1 .. 0 ->
             loadNative bld 8<rt> (addr .+ num32 (i * 2)) |]
      let dst = if ins.Size = Sz.Long then dn else AST.xtlo 16<rt> dn
      dst := AST.revConcat bytes
  }

/// Lifts a CMP2 or a CHK2, which compare a register against the pair of bounds
/// that lie at the effective address, the latter trapping where it falls
/// outside them.
let cmp2 (ins: Instruction) bld =
  lift bld ins {
    let size = ins.Size
    let rt = regTypeOf size
    let struct (o1, o2) = getTwoOprs ins
    let step = RegType.toByteWidth rt
    let addr = tmpVar bld 32<rt>
    match transOpr bld ins size o1 with
    | LMem a -> addr := a
    | _ -> raise InvalidOperandException
    let lower = tmpVar bld rt
    let upper = tmpVar bld rt
    let v = tmpVar bld rt
    lower := loadNative bld rt addr
    upper := loadNative bld rt (addr .+ num32 step)
    v := AST.xtlo rt (regOf bld o2)
    zf bld := (v == lower) .| (v == upper)
    cf bld := (v ?< lower) .| (v ?> upper)
    match ins.Opcode with
    | Op.CHK2 ->
      _when bld "Chk2" (cf bld)
        (block {
          AST.sideEffect (Exception IntegerOverflow)
        })
    | _ ->
      ()
  }

/// Lifts an instruction that the m68k has and this lifter does not yet model,
/// which the emulator reports rather than running past.
let unsupported (ins: Instruction) bld =
  lift bld ins { AST.sideEffect UnsupportedInstruction }
