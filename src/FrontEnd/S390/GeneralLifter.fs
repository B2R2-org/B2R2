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

module internal B2R2.FrontEnd.S390.GeneralLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.S390.LiftingUtils

/// The destination an operation of the given width writes: the whole register
/// for a doubleword, only its low word for a word, which is how z/Architecture
/// kept the ESA/390 operations meaningful on registers it had widened.
let private dst rt d = if rt = GRSize then d else low d

/// The part of a register an operation of the given width reads.
let private srcReg rt r = if rt = GRSize then r else low r

/// The value a source operand supplies, read at the given width. A register
/// gives its rightmost bits of that width, which is where the byte and
/// halfword operations take theirs from.
let private srcOf bld rt o =
  match o with
  | OpReg r -> narrowTo rt (reg bld r)
  | OpImm i -> numI64 (immValue i) rt
  | OpMask m -> numI64 (int64 m) rt
  | OpStore _ | OpStoreLen _ -> loadMem rt (transMem bld o)
  | OpRImm _ -> raise InvalidOperandException

/// Puts a value in a temporary when reading it twice would repeat work -- for
/// a field of storage, a second load of the same bytes.
let private hold bld rt o e =
  match o with
  | OpStore _ | OpStoreLen _ ->
    let t = tmpVar bld rt
    append bld {
      t := e
    }
    t
  | _ ->
    e

let ccNone _ _ _ _ = ()

let ccAdd bld res a b = setCCAdd bld res a b

let ccSub bld res a b = setCCSub bld res a b

let ccSign bld res _ _ = setCCSign bld res

let ccLogic bld res _ _ = setCCLogic bld res

let ccAddL bld res a _ = setCCAddLogical bld res (res .< a)

let ccSubL bld _ a b = setCCSubLogical bld a b

/// A plain load: the second operand's value, widened as the operation names,
/// becomes the first operand's.
let load ins bld rt accW ext =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    dst rt d := ext rt (srcOf bld accW o2)
  }

/// LOAD LOGICAL THIRTY ONE BITS, which takes a word and drops its top bit --
/// the one a 31-bit address space used to carry the addressing mode in.
let loadThirtyOne ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    d := zextTo GRSize (srcOf bld WSize o2) .& numG 0x7fffffffL
  }

/// INSERT IMMEDIATE: an immediate replaces one field of a register and leaves
/// the rest of it as it was.
let insertImm ins bld pos width =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    AST.extract d width pos := numI64 (oprImm o2) width
  }

/// LOAD LOGICAL IMMEDIATE: an immediate becomes the whole register, shifted to
/// the field the operation names and zero everywhere else.
let loadLogicalImm ins bld shift =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let v = uint64 (oprImm o2) <<< (shift: int)
    d := numG (int64 v)
  }

/// A load that also reports the sign of what it loaded.
let loadTest ins bld rt accW ext =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let t = tmpVar bld rt
    t := ext rt (srcOf bld accW o2)
    setCCSign bld t
    dst rt d := t
  }

/// A load whose storage operand is named relative to the instruction rather
/// than by a base and displacement.
let loadRel ins bld rt accW ext =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let addr = numG (int64 (codeAddr bld (relTarget ins.Address (oprImm o2))))
    dst rt d := ext rt (loadMem accW addr)
  }

/// LOAD ADDRESS: the address the second operand names, rather than what is
/// stored there, becomes the first operand's value.
let la ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    d := transMem bld o2
  }

/// LOAD ADDRESS RELATIVE LONG: the address the instruction's own halfword
/// offset names, which is how position-independent code reaches its data.
let larl ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    d := numG (int64 (codeAddr bld (relTarget ins.Address (oprImm o2))))
  }

/// A plain store of the first operand's low bits.
let store ins bld accW =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    storeMem (transMem bld o2) (narrowTo accW (oprRegVar bld o1))
  }

/// A value with its bytes in the opposite order, which is what the
/// byte-reversing loads and stores exist to produce: s390 stores everything
/// most significant byte first, and reads a little-endian file or protocol by
/// turning each field around as it goes past.
let private byteSwap rt e =
  let n = RegType.toBitWidth rt / 8
  let bytes = [| for i in 0 .. n - 1 -> AST.extract e 8<rt> (i * 8) |]
  Array.reduce (fun acc b -> AST.concat acc b) bytes

/// LOAD REVERSED, from a register or from storage.
let loadReversed ins bld rt accW =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let v = byteSwap accW (srcOf bld accW o2)
    if accW = rt then append bld { dst rt d := v }
    else append bld { AST.extract d accW 0 := v }
  }

/// STORE REVERSED, the mirror of LOAD REVERSED.
let storeReversed ins bld accW =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let v = byteSwap accW (narrowTo accW (oprRegVar bld o1))
    storeMem (transMem bld o2) v
  }

/// A store of a register's leftmost word, which is where a short
/// floating-point value lives.
let storeHigh ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    storeMem (transMem bld o2) (AST.xthi WSize (oprRegVar bld o1))
  }

/// A store to storage the instruction names relative to itself.
let storeRel ins bld accW =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let addr = numG (int64 (codeAddr bld (relTarget ins.Address (oprImm o2))))
    storeMem addr (narrowTo accW (oprRegVar bld o1))
  }

/// MOVE IMMEDIATE: an immediate, widened where the field is narrower than the
/// unit stored, is written straight to storage.
let moveImm ins bld accW =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    storeMem (transMem bld o1) (numI64 (oprImm o2) accW)
  }

/// The registers a load- or store-multiple walks, from the first operand's
/// through the third's, wrapping around R15 to R0 as the architecture does.
let private regRange (r1: Register) (r3: Register) =
  let first = int r1
  let count = ((int r3 - first) &&& 0xf) + 1
  [| for i in 0 .. count - 1 -> enum<Register> ((first + i) &&& 0xf) |]

/// LOAD MULTIPLE: consecutive registers take consecutive units of storage.
let loadMultiple ins bld rt =
  lift bld (ins: Instruction) {
    let struct (o1, o2, o3) = getThreeOprs ins
    let regs = regRange (oprReg o1) (oprReg o3)
    let width = int64 (RegType.toByteWidth rt)
    let addr = tmpVar bld GRSize
    addr := transMem bld o2
    for i in 0 .. regs.Length - 1 do
      let at = addr .+ numG (int64 i * width)
      dst rt (reg bld regs[i]) := loadMem rt at
  }

/// STORE MULTIPLE: the mirror of LOAD MULTIPLE, which together are how a
/// function prologue and epilogue save and restore the registers it uses.
let storeMultiple ins bld rt =
  lift bld (ins: Instruction) {
    let struct (o1, o2, o3) = getThreeOprs ins
    let regs = regRange (oprReg o1) (oprReg o3)
    let width = int64 (RegType.toByteWidth rt)
    let addr = tmpVar bld GRSize
    addr := transMem bld o2
    for i in 0 .. regs.Length - 1 do
      let at = addr .+ numG (int64 i * width)
      storeMem at (narrowTo rt (reg bld regs[i]))
  }

/// A storage-to-storage operation: the first operand's field takes, byte by
/// byte, the result of combining it with the second's.
let ssOp ins bld f =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let len = numG (int64 (lenOfMem o1))
    let d = tmpVar bld GRSize
    let s = tmpVar bld GRSize
    d := transMem bld o1
    s := transMem bld o2
    emitByteLoop bld len d s f
  }

/// The storage-to-storage bitwise operations, which report whether any bit of
/// the result is one.
let ssLogic ins bld f =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let len = numG (int64 (lenOfMem o1))
    let d = tmpVar bld GRSize
    let s = tmpVar bld GRSize
    d := transMem bld o1
    s := transMem bld o2
    emitLogicLoop bld len d s f
  }

/// The shape every two-operand arithmetic and logical instruction shares: the
/// first operand supplies one input and receives the result, the second the
/// other input.
let alu2 ins bld rt f cc =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let a = srcReg rt d
    let t = tmpVar bld rt
    let b = hold bld rt o2 (srcOf bld rt o2)
    t := f a b
    cc bld t a b
    dst rt d := t
  }

/// A two-operand operation whose source is narrower than the operation itself,
/// and so is widened by ext before taking part.
let alu2Ext ins bld rt accW ext f cc =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let a = srcReg rt d
    let t = tmpVar bld rt
    let b = tmpVar bld rt
    b := ext rt (srcOf bld accW o2)
    t := f a b
    cc bld t a b
    dst rt d := t
  }

/// The three-operand ("K") forms, which leave both inputs alone.
let alu3 ins bld rt f cc =
  lift bld (ins: Instruction) {
    let struct (o1, o2, o3) = getThreeOprs ins
    let d = oprRegVar bld o1
    let t = tmpVar bld rt
    let a = srcOf bld rt o2
    let b = srcOf bld rt o3
    t := f a b
    cc bld t a b
    dst rt d := t
  }

/// The immediate three-operand forms, whose parsed operands put the immediate
/// where the register-to-register forms put the second source.
let alu3Imm ins bld rt f cc =
  lift bld (ins: Instruction) {
    let struct (o1, o2, o3) = getThreeOprs ins
    let d = oprRegVar bld o1
    let t = tmpVar bld rt
    let a = srcOf bld rt o3
    let b = srcOf bld rt o2
    t := f a b
    cc bld t a b
    dst rt d := t
  }

/// ADD IMMEDIATE to storage, whose sum goes back where the addend came from.
let addToStorage ins bld rt =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let addr = tmpVar bld GRSize
    let a = tmpVar bld rt
    let t = tmpVar bld rt
    addr := transMem bld o1
    a := loadMem rt addr
    let b = numI64 (oprImm o2) rt
    t := a .+ b
    setCCAdd bld t a b
    storeMem addr t
  }

/// The immediate bitwise operations on storage, which read, combine, and write
/// back a single byte.
let logicImmStorage ins bld f setsCC =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let addr = tmpVar bld GRSize
    let t = tmpVar bld 8<rt>
    addr := transMem bld o1
    t := f (loadMem 8<rt> addr) (numI64 (oprImm o2) 8<rt>)
    if setsCC then setCCLogic bld t else ()
    storeMem addr t
  }

/// The immediate bitwise operations that touch one 16- or 32-bit field of a
/// register and leave the rest of it alone.
let logicImmField ins bld pos width f =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let field = AST.extract d width pos
    let t = tmpVar bld width
    t := f field (numI64 (oprImm o2) width)
    setCCLogic bld t
    field := t
  }

/// ADD WITH CARRY and SUBTRACT WITH BORROW, which chain the previous
/// operation's carry -- the high bit of its condition code -- into this one.
let addCarry ins bld rt =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let a = srcReg rt d
    let cin = tmpVar bld rt
    let t = tmpVar bld rt
    let b = hold bld rt o2 (srcOf bld rt o2)
    cin := zextTo rt ((ccVar bld >> numCC 1) .& numCC 1)
    t := a .+ b .+ cin
    let carry = AST.ite (cin == AST.num0 rt) (t .< a) (t .<= a)
    setCCAddLogical bld t carry
    dst rt d := t
  }

/// SUBTRACT LOGICAL WITH BORROW: the borrow is the complement of the carry the
/// condition code's high bit records.
let subBorrow ins bld rt =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let a = srcReg rt d
    let borrow = tmpVar bld rt
    let t = tmpVar bld rt
    let b = hold bld rt o2 (srcOf bld rt o2)
    borrow := zextTo rt (AST.num1 1<rt> <+> ((ccVar bld >> numCC 1)
                                             .& numCC 1 == numCC 1))
    t := a .- b .- borrow
    let carry = AST.ite (borrow == AST.num0 rt) (a .>= b) (a .> b)
    setCCAddLogical bld t carry
    dst rt d := t
  }

/// The magnitude of a two's-complement value.
let absValue e = AST.ite (e ?< AST.num0 (Expr.typeOf e)) (AST.neg e) e

/// The negated magnitude, which is what LOAD NEGATIVE produces.
let negAbsValue e = AST.ite (e ?> AST.num0 (Expr.typeOf e)) (AST.neg e) e

/// The one-input arithmetic loads: complement, positive, and negative, each of
/// which reports the sign of what it produced.
let unaryArith ins bld rt accW f =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let t = tmpVar bld rt
    t := f (sextTo rt (srcOf bld accW o2))
    setCCSign bld t
    dst rt d := t
  }

/// MULTIPLY SINGLE, whose product is as wide as its operands and so needs no
/// register pair; it leaves the condition code alone.
let mul ins bld rt accW ext =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let b = ext rt (srcOf bld accW o2)
    dst rt d := srcReg rt d .* b
  }

/// The three-operand multiply, which leaves its inputs alone.
let mul3 ins bld rt =
  lift bld (ins: Instruction) {
    let struct (o1, o2, o3) = getThreeOprs ins
    let d = oprRegVar bld o1
    let a = srcOf bld rt o2
    let b = srcOf bld rt o3
    dst rt d := a .* b
  }

/// The register a pair's even member pairs with, which holds the high half of
/// a double-width product and the remainder of a division. Only an even
/// register names a pair; an odd one is a specification exception on real
/// hardware, and here it names itself so that lifting such an encoding -- which
/// only ever turns up in bytes that are not really code -- yields an
/// instruction the emulator rejects rather than a lifter that gives up.
let private pairOf r =
  if int (r: Register) % 2 = 0 then RegisterHelper.getRpairReg r else r

/// Whether a register-pair operand names a pair at all.
let private isPair (r: Register) = int r % 2 = 0

/// An encoding that names a register pair with an odd register, which is not
/// a pair; real hardware raises a specification exception for it.
let private specException ins bld =
  lift bld (ins: Instruction) {
    AST.sideEffect UndefinedInstruction
  }

/// MULTIPLY LOGICAL, whose double-width product fills a register pair: the
/// even register takes the high half and the odd one the low.
let mulLogical ins bld (rt: RegType) accW =
  let struct (o1, o2) = getTwoOprs ins
  let r1 = oprReg o1
  if not (isPair r1) then
    specException ins bld
  else
    let hi = reg bld r1
    let lo = reg bld (pairOf r1)
    let wide = rt * 2
    let t = tmpVar bld wide
    lift bld (ins: Instruction) {
      let b = AST.zext wide (srcOf bld accW o2)
      t := AST.zext wide (srcReg rt lo) .* b
      dst rt hi := AST.xthi rt t
      dst rt lo := AST.xtlo rt t
    }

/// DIVIDE LOGICAL: the dividend spans the register pair, and the quotient and
/// remainder replace its odd and even members.
let divLogical ins bld (rt: RegType) accW =
  let struct (o1, o2) = getTwoOprs ins
  let r1 = oprReg o1
  if not (isPair r1) then
    specException ins bld
  else
    let hi = reg bld r1
    let lo = reg bld (pairOf r1)
    let wide = rt * 2
    let num = tmpVar bld wide
    let den = tmpVar bld wide
    lift bld (ins: Instruction) {
      den := AST.zext wide (srcOf bld accW o2)
      num := AST.concat (srcReg rt hi) (srcReg rt lo)
      let q = tmpVar bld wide
      let r = tmpVar bld wide
      q := num ./ den
      r := num .% den
      dst rt hi := AST.xtlo rt r
      dst rt lo := AST.xtlo rt q
    }

/// DIVIDE SINGLE: a signed division whose dividend is the odd register of the
/// pair alone, wide though the pair is.
let divSingle ins bld rt accW =
  let struct (o1, o2) = getTwoOprs ins
  let r1 = oprReg o1
  if not (isPair r1) then
    specException ins bld
  else
    let hi = reg bld r1
    let lo = reg bld (pairOf r1)
    let den = tmpVar bld rt
    let num = tmpVar bld rt
    lift bld (ins: Instruction) {
      den := sextTo rt (srcOf bld accW o2)
      num := srcReg rt lo
      let q = tmpVar bld rt
      let r = tmpVar bld rt
      q := num ?/ den
      r := num ?% den
      dst rt hi := r
      dst rt lo := q
    }

/// FIND LEFTMOST ONE: the bit number of the highest one bit goes to the even
/// register of a pair and the operand with that bit cleared to the odd one.
let flogr ins bld =
  let struct (o1, o2) = getTwoOprs ins
  let r1 = oprReg o1
  if not (isPair r1) then
    specException ins bld
  else
    let hi = reg bld r1
    let lo = reg bld (pairOf r1)
    let v = tmpVar bld GRSize
    let n = tmpVar bld GRSize
    let bit = tmpVar bld GRSize
    let body = label bld "FlogrBody"
    let step = label bld "FlogrStep"
    let out = label bld "FlogrOut"
    lift bld (ins: Instruction) {
      v := srcOf bld GRSize o2
      n := AST.num0 GRSize
      bit := numG 0x8000000000000000L
      AST.lmark body
      AST.cjmp ((n == numG 64L) .| ((v .& bit) != AST.num0 GRSize))
               (AST.jmpDest out)
               (AST.jmpDest step)
      AST.lmark step
      n := n .+ AST.num1 GRSize
      bit := bit >> AST.num1 GRSize
      AST.jmp (AST.jmpDest body)
      AST.lmark out
      ccVar bld := AST.ite (v == AST.num0 GRSize) (numCC 0) (numCC 2)
      lo := v .& AST.not bit
      hi := n
    }

/// POPULATION COUNT, which the architecture defines per byte: each byte of the
/// result counts the one bits of the matching byte of the operand.
let popcnt ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let v = tmpVar bld GRSize
    let acc = tmpVar bld GRSize
    v := srcOf bld GRSize o2
    acc := v .- ((v >> numG 1L) .& numG 0x5555555555555555L)
    acc := (acc .& numG 0x3333333333333333L)
           .+ ((acc >> numG 2L) .& numG 0x3333333333333333L)
    acc := (acc .+ (acc >> numG 4L)) .& numG 0x0f0f0f0f0f0f0f0fL
    setCCLogic bld v
    d := acc
  }

/// The count a shift takes: the low six bits of the address its second operand
/// names, which is an address only in how it is written.
let private shiftCount bld o rt = narrowTo rt (transMem bld o .& numG 63L)

/// The two-operand shifts, which shift a register's low word in place.
let shift2 ins bld f setsCC =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let t = tmpVar bld WSize
    t := f (low d) (shiftCount bld o2 WSize)
    if setsCC then setCCSign bld t else ()
    low d := t
  }

/// The three-operand shifts, which take their input from a third register.
let shift3 ins bld rt f setsCC =
  lift bld (ins: Instruction) {
    let struct (o1, o2, o3) = getThreeOprs ins
    let d = oprRegVar bld o1
    let t = tmpVar bld rt
    t := f (srcReg rt (oprRegVar bld o3)) (shiftCount bld o2 rt)
    if setsCC then setCCSign bld t else ()
    dst rt d := t
  }

/// A rotate left by a count only the low bits of which matter, written as the
/// pair of shifts that make one.
let private rotl rt v amount =
  let width = numI64 (int64 (RegType.toBitWidth rt)) rt
  let n = amount .& (width .- AST.num1 rt)
  let hi = v << n
  let lo = AST.ite (n == AST.num0 rt) (AST.num0 rt) (v >> (width .- n))
  hi .| lo

/// ROTATE LEFT SINGLE LOGICAL, which unlike the shifts has a three-operand
/// form at both widths.
let rotate ins bld rt =
  lift bld (ins: Instruction) {
    let struct (o1, o2, o3) = getThreeOprs ins
    let d = oprRegVar bld o1
    let t = tmpVar bld rt
    t := rotl rt (srcReg rt (oprRegVar bld o3)) (shiftCount bld o2 rt)
    dst rt d := t
  }

/// The mask a rotate-then-insert selects: the bits from the starting position
/// through the ending one, counted from the left, wrapping around the register
/// when the start lies after the end.
let private selectMask (start: int) (fin: int) =
  let bitAt i = 1UL <<< (63 - i)
  let rec ones i acc = if i > fin then acc else ones (i + 1) (acc ||| bitAt i)
  if start <= fin then
    ones start 0UL
  else
    let rec upper i acc =
      if i > 63 then acc else upper (i + 1) (acc ||| bitAt i)
    upper start 0UL ||| ones 0 0UL

/// ROTATE THEN INSERT SELECTED BITS and its relatives: the second operand is
/// rotated left, and the bits a start-and-end pair names are combined into the
/// first. The zero-remaining-bits control, which the assembler spells as the
/// "z" suffix, makes the unselected bits zero rather than leaving them.
let rotateInsert (ins: Instruction) bld f setsCC =
  match ins.Operands with
  | FiveOperands(o1, o2, o3, o4, o5) ->
    let d = oprRegVar bld o1
    let i3 = int (oprImm o3)
    let i4 = int (oprImm o4)
    let mask = selectMask (i3 &&& 63) (i4 &&& 63)
    let zero = i4 &&& 0x80 <> 0
    let t = tmpVar bld GRSize
    lift bld (ins: Instruction) {
      let rotated = rotl GRSize (srcOf bld GRSize o2) (numG (oprImm o5 &&& 63L))
      let selected = rotated .& numG (int64 mask)
      if zero then append bld { t := selected }
      else append bld { t := f (d .& numG (int64 (~~~mask))) selected }
      if setsCC then setCCSign bld t else ()
      d := t
    }
  | _ ->
    raise InvalidOperandException

/// ROTATE THEN combine SELECTED BITS: the rotated bits the mask selects are
/// ORed, ANDed, or XORed into the first operand rather than replacing it, and
/// the condition code reports what the selected positions ended up holding. A
/// test control -- the high bit of the starting position -- asks for that
/// report without the update, which is how a program tests scattered bits.
let rotateCombine (ins: Instruction) bld f =
  match ins.Operands with
  | FiveOperands(o1, o2, o3, o4, o5) ->
    let d = oprRegVar bld o1
    let i3 = int (oprImm o3)
    let mask = selectMask (i3 &&& 63) (int (oprImm o4) &&& 63)
    let testOnly = i3 &&& 0x80 <> 0
    let t = tmpVar bld GRSize
    lift bld (ins: Instruction) {
      let rotated = rotl GRSize (srcOf bld GRSize o2) (numG (oprImm o5 &&& 63L))
      t := f d rotated mask
      setCCLogic bld (t .& numG (int64 mask))
      if testOnly then () else append bld { d := t }
    }
  | _ ->
    raise InvalidOperandException

/// A comparison, which reports how the first operand stands to the second and
/// changes nothing else.
let compare ins bld rt accW ext signed =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let a = tmpVar bld rt
    let b = tmpVar bld rt
    a := srcReg rt (oprRegVar bld o1)
    b := ext rt (srcOf bld accW o2)
    if signed then setCCCmp bld a b else setCCCmpLogical bld a b
  }

/// A comparison against storage the instruction names relative to itself.
let compareRel ins bld rt accW ext signed =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let addr = numG (int64 (codeAddr bld (relTarget ins.Address (oprImm o2))))
    let a = tmpVar bld rt
    let b = tmpVar bld rt
    a := srcReg rt (oprRegVar bld o1)
    b := ext rt (loadMem accW addr)
    if signed then setCCCmp bld a b else setCCCmpLogical bld a b
  }

/// A comparison of a field of storage against an immediate.
let compareStorageImm ins bld accW signed =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let a = tmpVar bld accW
    a := loadMem accW (transMem bld o1)
    let b = numI64 (oprImm o2) accW
    if signed then setCCCmp bld a b else setCCCmpLogical bld a b
  }

/// COMPARE LOGICAL, storage to storage.
let compareStorage ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let len = numG (int64 (lenOfMem o1))
    let a = tmpVar bld GRSize
    let b = tmpVar bld GRSize
    a := transMem bld o1
    b := transMem bld o2
    emitCompareLoop bld len a b
  }

/// TEST UNDER MASK on a byte of storage.
let testMaskStorage ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let v = tmpVar bld 8<rt>
    v := loadMem 8<rt> (transMem bld o1)
    setCCTestMask bld v (uint64 (oprImm o2) &&& 0xffUL)
  }

/// TEST UNDER MASK on one of a register's four halfwords.
let testMaskReg ins bld pos =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let v = tmpVar bld 16<rt>
    v := AST.extract (oprRegVar bld o1) 16<rt> pos
    setCCTestMask bld v (uint64 (oprMask o2))
  }

/// The address of the instruction after the one being lifted, as an
/// expression, which is where a branch not taken carries on and where a call
/// leaves its return address.
let private fallThrough bld (ins: Instruction) =
  numG (int64 (codeAddr bld (nextAddr ins)))

/// The value a call leaves in its link register. On z/Architecture that is the
/// return address and nothing else. ESA/390 has the addressing mode to record
/// as well, and puts it in the bit above the 31 an address occupies -- which is
/// why the branch back has to mask that bit off again.
let private linkValue bld (ins: Instruction) =
  let next = codeAddr bld (nextAddr ins)
  if esaMode bld then numG (int64 (next ||| 0x80000000UL))
  else numG (int64 next)

/// A branch a condition-code mask decides, whose target the instruction names
/// relative to itself.
let branchRelative ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let m = oprMask o1
    let target = numG (int64 (codeAddr bld (relTarget ins.Address (oprImm o2))))
    if isNever m then
      ()
    elif isAlways m then
      AST.interjmp target InterJmpKind.Base
    else
      let next = fallThrough bld ins
      AST.intercjmp (condOfMask bld m) target next
  }

/// A branch a mask decides, whose target is the address its base, index, and
/// displacement form -- not what is stored there.
let branchOnCondition ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let m = oprMask o1
    if isNever m then
      ()
    else
      let target = transMem bld o2
      if isAlways m then
        AST.interjmp target InterJmpKind.Base
      else
        let next = fallThrough bld ins
        AST.intercjmp (condOfMask bld m) target next
  }

/// A branch a mask decides, to the address a register holds. A second operand
/// of R0 names no register and so never branches, which is how the assembler
/// spells a no-operation; a mask that takes every code and a second operand of
/// the link register is how a function returns.
let branchOnConditionReg ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let m = oprMask o1
    let r2 = oprReg o2
    if isNever m || r2 = Register.R0 then
      ()
    else
      let target = maskAddr bld (reg bld r2)
      let kind =
        if r2 = Register.R14 then InterJmpKind.IsRet else InterJmpKind.Base
      if isAlways m then
        AST.interjmp target kind
      else
        let next = fallThrough bld ins
        AST.intercjmp (condOfMask bld m) target next
  }

/// BRANCH AND SAVE, in the relative form the compiler uses for every call: the
/// return address goes to the first operand and control to the target.
let branchAndSaveRel ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let target = numG (int64 (codeAddr bld (relTarget ins.Address (oprImm o2))))
    d := linkValue bld ins
    AST.interjmp target InterJmpKind.IsCall
  }

/// BRANCH AND SAVE to the address the second operand names.
let branchAndSave ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let t = tmpVar bld GRSize
    t := transMem bld o2
    d := linkValue bld ins
    AST.interjmp t InterJmpKind.IsCall
  }

/// BRANCH AND SAVE to the address a register holds. As with a branch on
/// condition, a second operand of R0 saves the return address and goes nowhere.
let branchAndSaveReg ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let r2 = oprReg o2
    let t = tmpVar bld GRSize
    if r2 = Register.R0 then
      d := linkValue bld ins
    else
      t := maskAddr bld (reg bld r2)
      d := linkValue bld ins
      AST.interjmp t InterJmpKind.IsCall
  }

/// BRANCH ON COUNT, relative: the first operand counts down and control goes
/// to the target while the count has not reached zero.
let branchOnCountRel ins bld rt =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let target = numG (int64 (codeAddr bld (relTarget ins.Address (oprImm o2))))
    let t = tmpVar bld rt
    t := srcReg rt d .- AST.num1 rt
    dst rt d := t
    AST.intercjmp (t != AST.num0 rt) target (fallThrough bld ins)
  }

/// BRANCH ON COUNT, to the address the second operand names.
let branchOnCount ins bld rt =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let t = tmpVar bld rt
    let target = tmpVar bld GRSize
    target := transMem bld o2
    t := srcReg rt d .- AST.num1 rt
    dst rt d := t
    AST.intercjmp (t != AST.num0 rt) target (fallThrough bld ins)
  }

/// BRANCH ON COUNT to a register's address, which counts down whether or not
/// the second operand names anywhere to go.
let branchOnCountReg ins bld rt =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let r2 = oprReg o2
    let t = tmpVar bld rt
    let target = tmpVar bld GRSize
    if r2 = Register.R0 then
      t := srcReg rt d .- AST.num1 rt
      dst rt d := t
    else
      target := maskAddr bld (reg bld r2)
      t := srcReg rt d .- AST.num1 rt
      dst rt d := t
      AST.intercjmp (t != AST.num0 rt) target (fallThrough bld ins)
  }

/// BRANCH ON INDEX: the first operand takes an increment from the third, and
/// the sum is compared against the third register's odd partner -- the third
/// register itself when it is already the odd one -- to decide the branch.
let branchOnIndexRel ins bld rt high =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let d = oprRegVar bld o1
    let r3 = oprReg o3
    let cmp = if int r3 % 2 = 1 then r3 else pairOf r3
    let target = numG (int64 (codeAddr bld (relTarget ins.Address (oprImm o2))))
    let t = tmpVar bld rt
    let limit = tmpVar bld rt
    limit := srcReg rt (reg bld cmp)
    t := srcReg rt d .+ srcReg rt (reg bld r3)
    dst rt d := t
    let cond = if high then t ?> limit else t ?<= limit
    AST.intercjmp cond target (fallThrough bld ins)
  }

/// BRANCH ON INDEX to the address the second operand names.
let branchOnIndex ins bld rt high =
  lift bld (ins: Instruction) {
    let struct (o1, o2, o3) = getThreeOprs ins
    let d = oprRegVar bld o1
    let r3 = oprReg o3
    let cmp = if int r3 % 2 = 1 then r3 else pairOf r3
    let t = tmpVar bld rt
    let limit = tmpVar bld rt
    let target = tmpVar bld GRSize
    target := transMem bld o2
    limit := srcReg rt (reg bld cmp)
    t := srcReg rt d .+ srcReg rt (reg bld r3)
    dst rt d := t
    let cond = if high then t ?> limit else t ?<= limit
    AST.intercjmp cond target (fallThrough bld ins)
  }

/// The condition a compare-and-branch mask names, taken straight from the
/// comparison rather than through the condition code, which these instructions
/// leave alone: the mask's bits stand for equal, low, and high.
let private cmpCond (m: Mask) signed a b =
  let eq = if m &&& 8us <> 0us then [ a == b ] else []
  let lo =
    if m &&& 4us <> 0us then [ if signed then a ?< b else a .< b ] else []
  let hi =
    if m &&& 2us <> 0us then [ if signed then a ?> b else a .> b ] else []
  match eq @ lo @ hi with
  | [] -> AST.b0
  | h :: t -> List.fold (.|) h t

/// COMPARE AND BRANCH RELATIVE, which folds a comparison and the branch that
/// acts on it into one instruction.
let compareAndBranchRel ins bld rt signed =
  lift bld ins {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let m = oprMask o3
    let target = numG (int64 (codeAddr bld (relTarget ins.Address (oprImm o4))))
    if m &&& 0xeus = 0us then
      ()
    else
      let a = srcReg rt (oprRegVar bld o1)
      let b =
        match o2 with
        | OpReg _ -> srcReg rt (oprRegVar bld o2)
        | _ -> numI64 (oprImm o2) rt
      if m &&& 0xeus = 0xeus then
        AST.interjmp target InterJmpKind.Base
      else
        let cond = cmpCond m signed a b
        AST.intercjmp cond target (fallThrough bld ins)
  }

/// COMPARE AND BRANCH to the address the last operand names.
let compareAndBranch ins bld rt signed =
  lift bld (ins: Instruction) {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let m = oprMask o3
    if m &&& 0xeus = 0us then
      ()
    else
      let target = transMem bld o4
      let a = srcReg rt (oprRegVar bld o1)
      let b =
        match o2 with
        | OpReg _ -> srcReg rt (oprRegVar bld o2)
        | _ -> numI64 (oprImm o2) rt
      if m &&& 0xeus = 0xeus then
        AST.interjmp target InterJmpKind.Base
      else
        let cond = cmpCond m signed a b
        AST.intercjmp cond target (fallThrough bld ins)
  }

/// COMPARE AND TRAP, which a compiler plants where a check must not be allowed
/// to fall through -- a division by zero, a bound a pointer must respect.
let compareAndTrap ins bld rt signed =
  lift bld (ins: Instruction) {
    let struct (o1, o2, o3) = getThreeOprs ins
    let m = oprMask o3
    if m &&& 0xeus = 0us then
      ()
    else
      let a = srcReg rt (oprRegVar bld o1)
      let b =
        match o2 with
        | OpReg _ -> srcReg rt (oprRegVar bld o2)
        | _ -> numI64 (oprImm o2) rt
      let trap = label bld "Trap"
      let out = label bld "NoTrap"
      AST.cjmp (cmpCond m signed a b)
               (AST.jmpDest trap)
               (AST.jmpDest out)
      AST.lmark trap
      AST.sideEffect (Exception IntegerOverflow)
      AST.lmark out
  }

/// LOAD ON CONDITION, whose mask selects the condition codes it acts on. The
/// load is written as a select so the lifted block stays straight-line.
let loadOnCondition ins bld rt =
  lift bld (ins: Instruction) {
    let struct (o1, o2, o3) = getThreeOprs ins
    let d = oprRegVar bld o1
    let m = oprMask o3
    if isNever m then
      ()
    else
      let v = srcOf bld rt o2
      let value =
        if isAlways m then v else AST.ite (condOfMask bld m) v (srcReg rt d)
      dst rt d := value
  }

/// LOAD HALFWORD IMMEDIATE ON CONDITION, whose immediate is sign-extended to
/// the operation's width.
let loadImmOnCondition ins bld rt =
  lift bld (ins: Instruction) {
    let struct (o1, o2, o3) = getThreeOprs ins
    let d = oprRegVar bld o1
    let m = oprMask o3
    if isNever m then
      ()
    else
      let v = numI64 (oprImm o2) rt
      let value =
        if isAlways m then v else AST.ite (condOfMask bld m) v (srcReg rt d)
      dst rt d := value
  }

/// STORE ON CONDITION. Unlike the load, a store that must not happen cannot be
/// written as a select, so this one does branch.
let storeOnCondition ins bld rt =
  lift bld (ins: Instruction) {
    let struct (o1, o2, o3) = getThreeOprs ins
    let m = oprMask o3
    if isNever m then
      ()
    elif isAlways m then
      storeMem (transMem bld o2) (narrowTo rt (oprRegVar bld o1))
    else
      let doIt = label bld "StoreOnCond"
      let out = label bld "SkipStore"
      AST.cjmp (condOfMask bld m) (AST.jmpDest doIt) (AST.jmpDest out)
      AST.lmark doIt
      storeMem (transMem bld o2) (narrowTo rt (oprRegVar bld o1))
      AST.lmark out
  }

/// The byte positions a four-bit mask selects, leftmost bit first, as offsets
/// into the field of storage the instruction reads or writes.
let private maskedBytes (m: Mask) =
  [| 0 .. 3 |] |> Array.filter (fun i -> m &&& (8us >>> i) <> 0us)

/// INSERT CHARACTERS UNDER MASK: the bytes the mask selects, taken from
/// consecutive bytes of storage, replace the matching bytes of one word of the
/// first operand -- its low one, or, for the "high" form, the other -- and the
/// condition code reports what was inserted.
let icm ins bld half =
  lift bld (ins: Instruction) {
    let struct (o1, o2, o3) = getThreeOprs ins
    let d = oprRegVar bld o1
    let sel = maskedBytes (oprMask o3)
    let at k = (half: int) + 8 * (3 - sel[k])
    let addr = tmpVar bld GRSize
    addr := transMem bld o2
    let acc = tmpVar bld 8<rt>
    acc := AST.num0 8<rt>
    for k in 0 .. sel.Length - 1 do
      let v = tmpVar bld 8<rt>
      v := loadMem 8<rt> (addr .+ numG (int64 k))
      AST.extract d 8<rt> (at k) := v
      acc := acc .| v
    if sel.Length = 0 then
      setCC bld 0
    else
      let first = AST.extract d 8<rt> (at 0)
      let neg = AST.ite ((first .& numI32 0x80 8<rt>) == AST.num0 8<rt>)
                        (numCC 2)
                        (numCC 1)
      ccVar bld := AST.ite (acc == AST.num0 8<rt>) (numCC 0) neg
  }

/// STORE CHARACTERS UNDER MASK: the mirror of INSERT, which writes only the
/// bytes the mask selects and touches no condition code.
let stcm ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2, o3) = getThreeOprs ins
    let d = oprRegVar bld o1
    let sel = maskedBytes (oprMask o3)
    let addr = tmpVar bld GRSize
    addr := transMem bld o2
    for k in 0 .. sel.Length - 1 do
      let v = AST.extract d 8<rt> (8 * (3 - sel[k]))
      storeMem (addr .+ numG (int64 k)) v
  }

/// COMPARE LOGICAL CHARACTERS UNDER MASK.
let clm ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2, o3) = getThreeOprs ins
    let d = oprRegVar bld o1
    let sel = maskedBytes (oprMask o3)
    let addr = tmpVar bld GRSize
    addr := transMem bld o2
    if sel.Length = 0 then
      setCC bld 0
    else
      let out = label bld "ClmOut"
      setCC bld 0
      for k in 0 .. sel.Length - 1 do
        let a = tmpVar bld 8<rt>
        let b = tmpVar bld 8<rt>
        let next = label bld $"ClmNext{k}"
        let diff = label bld $"ClmDiff{k}"
        a := AST.extract d 8<rt> (8 * (3 - sel[k]))
        b := loadMem 8<rt> (addr .+ numG (int64 k))
        AST.cjmp (a == b) (AST.jmpDest next) (AST.jmpDest diff)
        AST.lmark diff
        ccVar bld := AST.ite (a .< b) (numCC 1) (numCC 2)
        AST.jmp (AST.jmpDest out)
        AST.lmark next
      AST.lmark out
  }

/// INSERT CHARACTER: a byte of storage replaces the lowest byte of the first
/// operand and leaves the rest of the register as it was.
let ic ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    AST.xtlo 8<rt> d := loadMem 8<rt> (transMem bld o2)
  }

/// COMPARE AND SWAP, the primitive every lock in the guest is built from: the
/// first operand's value is replaced by what was found, and the third
/// operand's is stored only where the two matched.
let compareAndSwap ins bld rt =
  lift bld (ins: Instruction) {
    let struct (o1, o2, o3) = getThreeOprs ins
    let d = oprRegVar bld o1
    let addr = tmpVar bld GRSize
    let found = tmpVar bld rt
    let swap = label bld "CasSwap"
    let out = label bld "CasOut"
    AST.sideEffect AtomicBegin
    addr := transMem bld o2
    found := loadMem rt addr
    AST.cjmp (found == srcReg rt d) (AST.jmpDest swap) (AST.jmpDest out)
    AST.lmark swap
    storeMem addr (srcReg rt (oprRegVar bld o3))
    AST.lmark out
    ccVar bld := AST.ite (found == srcReg rt d) (numCC 0) (numCC 1)
    dst rt d := found
    AST.sideEffect AtomicEnd
  }

/// LOAD AND ADD and its bitwise relatives: the value found in storage goes to
/// the first operand and the combination of it with the third is stored back,
/// indivisibly.
let loadAndOp ins bld rt f =
  lift bld (ins: Instruction) {
    let struct (o1, o2, o3) = getThreeOprs ins
    let d = oprRegVar bld o1
    let addr = tmpVar bld GRSize
    let found = tmpVar bld rt
    let t = tmpVar bld rt
    AST.sideEffect AtomicBegin
    addr := transMem bld o2
    found := loadMem rt addr
    t := f found (srcReg rt (oprRegVar bld o3))
    storeMem addr t
    AST.sideEffect AtomicEnd
    setCCSign bld t
    dst rt d := found
  }

/// The register a four-bit field of an executed instruction names. Which one
/// it is can only be known once the instruction is reached, so the choice is
/// made at run time rather than at lifting time; a field of zero names no
/// register and so contributes nothing to an address.
let private regOfField bld n =
  let rec pick i =
    if i = 15 then
      reg bld Register.R15
    else
      let e = reg bld (enum<Register> i)
      AST.ite (n == numG (int64 i)) e (pick (i + 1))
  AST.ite (n == AST.num0 GRSize) (AST.num0 GRSize) (pick 1)

/// The address the base-and-displacement pair at the given offset of an
/// executed instruction names: a register number in the first byte's left half
/// and twelve bits of displacement in the rest.
let private fieldAddress bld tgt k =
  let hi = tmpVar bld GRSize
  let lo = tmpVar bld GRSize
  append bld {
    hi := zextTo GRSize (loadMem 8<rt> (tgt .+ numG (int64 k)))
    lo := zextTo GRSize (loadMem 8<rt> (tgt .+ numG (int64 k + 1L)))
  }
  let b = tmpVar bld GRSize
  append bld {
    b := hi >> numG 4L
  }
  regOfField bld b .+ (((hi .& numG 0xfL) << numG 8L) .| lo)

/// The loop TRANSLATE runs: each of the first operand's bytes is replaced by
/// the table byte it indexes.
let private emitTransLoop bld len d table =
  append bld {
    let i = tmpVar bld GRSize
    let body = label bld "TrBody"
    let out = label bld "TrOut"
    i := AST.num0 GRSize
    AST.lmark body
    let at = d .+ i
    storeMem at (loadMem 8<rt> (table .+ zextTo GRSize (loadMem 8<rt> at)))
    i := i .+ AST.num1 GRSize
    AST.cjmp (i == len) (AST.jmpDest out) (AST.jmpDest body)
    AST.lmark out
  }

/// The loop TRANSLATE AND TEST runs: the same indexing, but the first non-zero
/// table byte stops the scan and is reported instead of stored.
let private emitTransTestLoop bld len d table backwards =
  append bld {
    let i = tmpVar bld GRSize
    let fn = tmpVar bld 8<rt>
    let body = label bld "TrtBody"
    let step = label bld "TrtStep"
    let found = label bld "TrtFound"
    let out = label bld "TrtOut"
    i := AST.num0 GRSize
    setCC bld 0
    AST.lmark body
    let at = if backwards then d .- i else d .+ i
    fn := loadMem 8<rt> (table .+ zextTo GRSize (loadMem 8<rt> at))
    AST.cjmp (fn == AST.num0 8<rt>)
             (AST.jmpDest step)
             (AST.jmpDest found)
    AST.lmark step
    i := i .+ AST.num1 GRSize
    AST.cjmp (i == len) (AST.jmpDest out) (AST.jmpDest body)
    AST.lmark found
    reg bld Register.R1 := at
    AST.xtlo 8<rt> (reg bld Register.R2) := fn
    ccVar bld := AST.ite (i == len .- AST.num1 GRSize)
                         (numCC 2)
                         (numCC 1)
    AST.lmark out
  }

/// The half-byte move EXECUTE reaches through MOVE NUMERICS and MOVE ZONES,
/// which take one nibble of each byte from the source and leave the other as
/// it was.
let private halfByte keep take d s =
  (d .& numI32 keep 8<rt>) .| (s .& numI32 take 8<rt>)

/// Emits one arm of an EXECUTE: the body runs only where the target opcode is
/// the one this arm answers for, and jumps out once it has.
let private executeArm bld op lblOut code body =
  let hit = label bld "ExHit"
  let miss = label bld "ExMiss"
  append bld {
    AST.cjmp (op == numI32 code 8<rt>) (AST.jmpDest hit) (AST.jmpDest miss)
    AST.lmark hit
  }
  body ()
  append bld {
    AST.jmp (AST.jmpDest lblOut)
    AST.lmark miss
  }

/// EXECUTE: the instruction at the target address runs as if it stood here,
/// with its second byte -- the length, in every form a compiler uses this for
/// -- ORed with the rightmost byte of the first operand. That is how a program
/// gives a storage-to-storage operation a length it only knows at run time,
/// and it is why the target has to be read as data rather than lifted with the
/// code around it. A supervisor call is the one target that is not such an
/// operation: there the same byte is the call number, which is how a program
/// asks for a call it only names at run time.
let private executeAt ins bld r1 target =
  append bld {
    let tgt = tmpVar bld GRSize
    let op = tmpVar bld 8<rt>
    let modified = tmpVar bld 8<rt>
    let len = tmpVar bld GRSize
    let a1 = tmpVar bld GRSize
    let a2 = tmpVar bld GRSize
    let lblOut = label bld "ExOut"
    tgt := target
    op := loadMem 8<rt> tgt
    let modifier =
      if (r1: Register) = Register.R0 then AST.num0 8<rt>
      else AST.xtlo 8<rt> (reg bld r1)
    modified := loadMem 8<rt> (tgt .+ AST.num1 GRSize) .| modifier
    len := zextTo GRSize modified .+ AST.num1 GRSize
    a1 := fieldAddress bld tgt 2
    a2 := fieldAddress bld tgt 4
    let arm code body = executeArm bld op lblOut code body
    arm 0x0a (fun () ->
      append bld {
        regVar bld Register.SVCCODE := modified
      }
      append bld { AST.sideEffect SysCall })
    arm 0xd1 (fun () -> emitByteLoop bld len a1 a2 (halfByte 0xf0 0x0f))
    arm 0xd2 (fun () -> emitByteLoop bld len a1 a2 (fun _ s -> s))
    arm 0xd3 (fun () -> emitByteLoop bld len a1 a2 (halfByte 0x0f 0xf0))
    arm 0xd4 (fun () -> emitLogicLoop bld len a1 a2 (.&))
    arm 0xd5 (fun () -> emitCompareLoop bld len a1 a2)
    arm 0xd6 (fun () -> emitLogicLoop bld len a1 a2 (.|))
    arm 0xd7 (fun () -> emitLogicLoop bld len a1 a2 (<+>))
    arm 0xdc (fun () -> emitTransLoop bld len a1 a2)
    arm 0xdd (fun () -> emitTransTestLoop bld len a1 a2 false)
    AST.sideEffect UnsupportedInstruction
    AST.lmark lblOut
  }

/// EXECUTE, whose target a base, index, and displacement name.
let execute ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    executeAt ins bld (oprReg o1) (transMem bld o2)
  }

/// EXECUTE RELATIVE LONG, whose target the instruction names by its own
/// distance from it, which is the form position-independent code uses.
let executeRel ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let target = numG (int64 (codeAddr bld (relTarget ins.Address (oprImm o2))))
    executeAt ins bld (oprReg o1) target
  }

/// The byte the string operations stop at, which R0's rightmost byte names.
let private terminator bld = AST.xtlo 8<rt> (reg bld Register.R0)

/// SEARCH STRING: the bytes from the second operand's address up to, but not
/// including, the first operand's are searched for the terminator. Finding it
/// puts its address in the first operand and reports 1; running out reports 2.
/// This is how the C library finds the end of a string without the vector
/// facility.
let srst ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let s = oprRegVar bld o2
    let limit = tmpVar bld GRSize
    let p = tmpVar bld GRSize
    let body = label bld "SrstBody"
    let step = label bld "SrstStep"
    let cont = label bld "SrstCont"
    let found = label bld "SrstFound"
    let none = label bld "SrstNone"
    let out = label bld "SrstOut"
    limit := d
    p := s
    AST.lmark body
    AST.cjmp (p == limit) (AST.jmpDest none) (AST.jmpDest step)
    AST.lmark step
    AST.cjmp (loadMem 8<rt> p == terminator bld)
             (AST.jmpDest found)
             (AST.jmpDest cont)
    AST.lmark cont
    p := p .+ AST.num1 GRSize
    AST.jmp (AST.jmpDest body)
    AST.lmark found
    d := p
    setCC bld 1
    AST.jmp (AST.jmpDest out)
    AST.lmark none
    s := limit
    setCC bld 2
    AST.lmark out
  }

/// MOVE STRING: bytes go from the second operand's address to the first's
/// until the terminator has been moved, which then names where it landed.
let mvst ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let s = oprRegVar bld o2
    let p = tmpVar bld GRSize
    let q = tmpVar bld GRSize
    let v = tmpVar bld 8<rt>
    let body = label bld "MvstBody"
    let out = label bld "MvstOut"
    let next = label bld "MvstNext"
    p := d
    q := s
    AST.lmark body
    v := loadMem 8<rt> q
    storeMem p v
    AST.cjmp (v == terminator bld) (AST.jmpDest out) (AST.jmpDest next)
    AST.lmark next
    p := p .+ AST.num1 GRSize
    q := q .+ AST.num1 GRSize
    AST.jmp (AST.jmpDest body)
    AST.lmark out
    d := p
    setCC bld 1
  }

/// COMPARE LOGICAL STRING: the two operands are compared byte by byte until
/// they differ or both reach the terminator, and the operands are left naming
/// the bytes that decided it.
let clst ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let s = oprRegVar bld o2
    let p = tmpVar bld GRSize
    let q = tmpVar bld GRSize
    let x = tmpVar bld 8<rt>
    let y = tmpVar bld 8<rt>
    let body = label bld "ClstBody"
    let same = label bld "ClstSame"
    let cont = label bld "ClstCont"
    let diff = label bld "ClstDiff"
    let out = label bld "ClstOut"
    p := d
    q := s
    setCC bld 0
    AST.lmark body
    x := loadMem 8<rt> p
    y := loadMem 8<rt> q
    AST.cjmp (x == y) (AST.jmpDest same) (AST.jmpDest diff)
    AST.lmark same
    AST.cjmp (x == terminator bld) (AST.jmpDest out) (AST.jmpDest cont)
    AST.lmark cont
    p := p .+ AST.num1 GRSize
    q := q .+ AST.num1 GRSize
    AST.jmp (AST.jmpDest body)
    AST.lmark diff
    ccVar bld := AST.ite (x .< y) (numCC 1) (numCC 2)
    d := p
    s := q
    AST.lmark out
  }

/// EXTRACT CACHE ATTRIBUTE, whose answer describes a cache hierarchy this
/// emulator does not have: zero, which reads as "no such level".
let ecag ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, _, _) = getThreeOprs ins
    let d = oprRegVar bld o1
    d := AST.num0 GRSize
  }

/// A storage-to-storage move of one nibble of each byte: the numerics are the
/// right-hand halves and the zones the left-hand ones, which is how decimal
/// code rearranges a field without disturbing its signs.
let ssNibble ins bld numerics =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let len = numG (int64 (lenOfMem o1))
    let d = tmpVar bld GRSize
    let s = tmpVar bld GRSize
    let keep = if numerics then 0xf0 else 0x0f
    let take = if numerics then 0x0f else 0xf0
    d := transMem bld o1
    s := transMem bld o2
    emitByteLoop bld len d s (halfByte keep take)
  }

/// MOVE INVERSE, which copies the second operand's bytes into the first in the
/// opposite order -- the second operand's address names its *rightmost* byte.
let moveInverse ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let len = lenOfMem o1
    let d = tmpVar bld GRSize
    let s = tmpVar bld GRSize
    let i = tmpVar bld GRSize
    let body = label bld "MvcinBody"
    let out = label bld "MvcinOut"
    d := transMem bld o1
    s := transMem bld o2
    i := AST.num0 GRSize
    AST.lmark body
    storeMem (d .+ i) (loadMem 8<rt> (s .- i))
    i := i .+ AST.num1 GRSize
    AST.cjmp (i == numG (int64 len)) (AST.jmpDest out) (AST.jmpDest body)
    AST.lmark out
  }

/// MOVE RIGHT TO LEFT, which copies from the right-hand end so that operands
/// overlapping the other way round still come out whole. Its length comes from
/// R0 rather than the encoding, so it can be as long as 4096 bytes.
let moveRightToLeft ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = tmpVar bld GRSize
    let s = tmpVar bld GRSize
    let i = tmpVar bld GRSize
    let body = label bld "MvcrlBody"
    let out = label bld "MvcrlOut"
    d := transMem bld o1
    s := transMem bld o2
    i := (zextTo GRSize (AST.xtlo 12<rt> (reg bld Register.R0)))
    AST.lmark body
    storeMem (d .+ i) (loadMem 8<rt> (s .+ i))
    AST.cjmp (i == AST.num0 GRSize) (AST.jmpDest out) (AST.jmpDest body)
    i := i .- AST.num1 GRSize
    AST.jmp (AST.jmpDest body)
    AST.lmark out
  }

/// MOVE WITH OFFSET, the decimal-support move: the second operand goes into
/// the first right-aligned and shifted one digit left, so that the first
/// operand's rightmost digit -- which holds the sign -- survives.
let moveWithOffset ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let n1 = lenOfMem o1
    let n2 = lenOfMem o2
    let d = tmpVar bld GRSize
    let s = tmpVar bld GRSize
    d := transMem bld o1
    s := transMem bld o2
    let byteAt (from: Expr) k =
      if k < 0 then AST.num0 8<rt> else loadMem 8<rt> (from .+ numG (int64 k))
    (* Walking right to left keeps a byte's own old value available: each
       destination byte takes the low digit of one source byte and the high
       digit of the next one along. *)
    for k in 0 .. n1 - 1 do
      let dpos = n1 - 1 - k
      let lowDigit =
        if k = 0 then byteAt d dpos .& numI32 0x0f 8<rt>
        else (byteAt s (n2 - k) .& numI32 0xf0 8<rt>) >> numI32 4 8<rt>
      let highDigit =
        let src = n2 - 1 - k
        if src < 0 then AST.num0 8<rt>
        else (byteAt s src .& numI32 0x0f 8<rt>) << numI32 4 8<rt>
      storeMem (d .+ numG (int64 dpos)) (highDigit .| lowDigit)
  }

/// The pad byte a long move or compare supplies once its source runs out,
/// which the second-operand address's rightmost byte names.
let private padOf bld o = AST.xtlo 8<rt> (transMem bld o)

/// The loop both padded moves run: while the destination still has room, take
/// one unit from the source and store it, and once the source has run out pad
/// the rest of the destination instead. Both lengths count down as they go, so
/// what the registers hold on the way out is what has yet to be moved.
let private moveLoop bld width step dst src pad labels =
  append bld {
    let da, dl = dst
    let sa, sl = src
    let body, more, copy, fill, out = labels
    AST.lmark body
    AST.cjmp (dl == AST.num0 GRSize)
             (AST.jmpDest out)
             (AST.jmpDest more)
    AST.lmark more
    AST.cjmp (sl == AST.num0 GRSize)
             (AST.jmpDest fill)
             (AST.jmpDest copy)
    AST.lmark copy
    storeMem da (loadMem width sa)
    sa := sa .+ step
    sl := sl .- step
    da := da .+ step
    dl := dl .- step
    AST.jmp (AST.jmpDest body)
    AST.lmark fill
    storeMem da pad
    da := da .+ step
    dl := dl .- step
    AST.jmp (AST.jmpDest body)
    AST.lmark out
  }

/// MOVE LONG EXTENDED: the first operand is filled from the second, and once
/// the second runs out the rest takes a pad byte. Both addresses and lengths
/// live in register pairs, which are left naming what has yet to be moved so
/// that a partial completion could be resumed -- this one always completes.
let moveLongExtended ins bld unit =
  let struct (o1, o2, o3) = getThreeOprs ins
  let r1 = oprReg o1
  let r3 = oprReg o3
  if not (isPair r1 && isPair r3) then
    specException ins bld
  else
    let da = reg bld r1
    let dl = reg bld (pairOf r1)
    let sa = reg bld r3
    let sl = reg bld (pairOf r3)
    let width = if (unit: int) = 2 then 16<rt> else 8<rt>
    let step = numG (int64 unit)
    let pad = tmpVar bld width
    let cmp = tmpVar bld CCSize
    let body = label bld "MvcleBody"
    let more = label bld "MvcleMore"
    let copy = label bld "MvcleCopy"
    let fill = label bld "MvcleFill"
    let out = label bld "MvcleOut"
    lift bld (ins: Instruction) {
      pad := AST.xtlo width (transMem bld o2)
      cmp := AST.ite (dl == sl)
                     (numCC 0)
                     (AST.ite (dl .< sl) (numCC 1) (numCC 2))
      let labels = body, more, copy, fill, out
      moveLoop bld width step (da, dl) (sa, sl) pad labels
      ccVar bld := cmp
    }

/// COMPARE LOGICAL LONG EXTENDED: the two operands are compared over the
/// longer of their lengths, the shorter one padded out, and the registers are
/// left naming the units that decided it.
let compareLongExtended ins bld unit =
  let struct (o1, o2, o3) = getThreeOprs ins
  let r1 = oprReg o1
  let r3 = oprReg o3
  if not (isPair r1 && isPair r3) then
    specException ins bld
  else
    let aa = reg bld r1
    let al = reg bld (pairOf r1)
    let ba = reg bld r3
    let bl = reg bld (pairOf r3)
    let width = if (unit: int) = 2 then 16<rt> else 8<rt>
    let step = numG (int64 unit)
    let pad = tmpVar bld width
    let x = tmpVar bld width
    let y = tmpVar bld width
    let body = label bld "ClcleBody"
    let more = label bld "ClcleMore"
    let same = label bld "ClcleSame"
    let diff = label bld "ClcleDiff"
    let out = label bld "ClcleOut"
    lift bld (ins: Instruction) {
      pad := AST.xtlo width (transMem bld o2)
      setCC bld 0
      AST.lmark body
      AST.cjmp ((al == AST.num0 GRSize) .& (bl == AST.num0 GRSize))
               (AST.jmpDest out)
               (AST.jmpDest more)
      AST.lmark more
      x := AST.ite (al == AST.num0 GRSize) pad (loadMem width aa)
      y := AST.ite (bl == AST.num0 GRSize) pad (loadMem width ba)
      AST.cjmp (x == y) (AST.jmpDest same) (AST.jmpDest diff)
      AST.lmark same
      aa := AST.ite (al == AST.num0 GRSize) aa (aa .+ step)
      al := AST.ite (al == AST.num0 GRSize) al (al .- step)
      ba := AST.ite (bl == AST.num0 GRSize) ba (ba .+ step)
      bl := AST.ite (bl == AST.num0 GRSize) bl (bl .- step)
      AST.jmp (AST.jmpDest body)
      AST.lmark diff
      ccVar bld := AST.ite (x .< y) (numCC 1) (numCC 2)
      AST.lmark out
    }

/// What MOVE LONG leaves behind: the lengths still outstanding written back
/// into the rightmost twenty-four bits of the odd registers, and the condition
/// code the two lengths were compared for beforehand. A destructive overlap
/// arrives here having moved nothing, and reports the fourth code instead.
let private finishMoveLong bld dst src cmp labels =
  append bld {
    let dlr, dl = dst
    let slr, sl = src
    let overlap, out = labels
    dlr := (dlr .& numG ~~~0xffffffL) .| dl
    slr := (slr .& numG ~~~0xffffffL) .| sl
    ccVar bld := cmp
    AST.jmp (AST.jmpDest out)
    AST.lmark overlap
    setCC bld 3
    AST.lmark out
  }

/// MOVE LONG, the older form, whose lengths are the rightmost twenty-four bits
/// of the odd registers and whose pad byte travels in the source length
/// register. Operands that overlap so that the move would destroy what it has
/// yet to read leave the storage alone and report the fourth condition code.
let moveLong ins bld =
  let struct (o1, o2) = getTwoOprs ins
  let r1 = oprReg o1
  let r2 = oprReg o2
  if not (isPair r1 && isPair r2) then
    specException ins bld
  else
    let da = reg bld r1
    let dlr = reg bld (pairOf r1)
    let sa = reg bld r2
    let slr = reg bld (pairOf r2)
    let dl = tmpVar bld GRSize
    let sl = tmpVar bld GRSize
    let pad = tmpVar bld 8<rt>
    let cmp = tmpVar bld CCSize
    let body = label bld "MvclBody"
    let more = label bld "MvclMore"
    let copy = label bld "MvclCopy"
    let fill = label bld "MvclFill"
    let over = label bld "MvclDone"
    let overlap = label bld "MvclOverlap"
    let out = label bld "MvclOut"
    lift bld (ins: Instruction) {
      dl := dlr .& numG 0xffffffL
      sl := slr .& numG 0xffffffL
      pad := AST.extract slr 8<rt> 24
      cmp := AST.ite (dl == sl)
                     (numCC 0)
                     (AST.ite (dl .< sl) (numCC 1) (numCC 2))
      (* Destructive overlap: the destination begins inside the part of the
         source still to be read, so a byte-at-a-time move would read what it
         had already written. *)
      AST.cjmp ((da .> sa) .& (da .< (sa .+ sl)))
               (AST.jmpDest overlap)
               (AST.jmpDest body)
      let labels = body, more, copy, fill, over
      moveLoop bld 8<rt> (AST.num1 GRSize) (da, dl) (sa, sl) pad labels
      finishMoveLong bld (dlr, dl) (slr, sl) cmp (overlap, out)
    }

/// The loop the padded comparison runs: while either operand has units left,
/// take one from each -- the pad byte standing in for whichever has run out --
/// and stop at the first pair that differs, which is what decides the
/// condition code. Only an operand still holding units walks on, so the
/// addresses and lengths left behind name the pair that decided it.
let private compareLoop bld a b pad bytes labels =
  append bld {
    let aa, al = a
    let ba, bl = b
    let x, y = bytes
    let body, more, same, diff, out = labels
    AST.lmark body
    AST.cjmp ((al == AST.num0 GRSize) .& (bl == AST.num0 GRSize))
             (AST.jmpDest out)
             (AST.jmpDest more)
    AST.lmark more
    x := AST.ite (al == AST.num0 GRSize) pad (loadMem 8<rt> aa)
    y := AST.ite (bl == AST.num0 GRSize) pad (loadMem 8<rt> ba)
    AST.cjmp (x == y) (AST.jmpDest same) (AST.jmpDest diff)
    AST.lmark same
    aa := AST.ite (al == AST.num0 GRSize) aa (aa .+ AST.num1 GRSize)
    al := AST.ite (al == AST.num0 GRSize) al (al .- AST.num1 GRSize)
    ba := AST.ite (bl == AST.num0 GRSize) ba (ba .+ AST.num1 GRSize)
    bl := AST.ite (bl == AST.num0 GRSize) bl (bl .- AST.num1 GRSize)
    AST.jmp (AST.jmpDest body)
    AST.lmark diff
    ccVar bld := AST.ite (x .< y) (numCC 1) (numCC 2)
    AST.lmark out
  }

/// COMPARE LOGICAL LONG, the older form of the padded comparison, whose
/// lengths and pad byte sit in the odd registers as MOVE LONG's do.
let compareLong ins bld =
  let struct (o1, o2) = getTwoOprs ins
  let r1 = oprReg o1
  let r2 = oprReg o2
  if not (isPair r1 && isPair r2) then
    specException ins bld
  else
    let aa = reg bld r1
    let alr = reg bld (pairOf r1)
    let ba = reg bld r2
    let blr = reg bld (pairOf r2)
    let al = tmpVar bld GRSize
    let bl = tmpVar bld GRSize
    let pad = tmpVar bld 8<rt>
    let x = tmpVar bld 8<rt>
    let y = tmpVar bld 8<rt>
    let body = label bld "ClclBody"
    let more = label bld "ClclMore"
    let same = label bld "ClclSame"
    let diff = label bld "ClclDiff"
    let out = label bld "ClclOut"
    lift bld (ins: Instruction) {
      al := alr .& numG 0xffffffL
      bl := blr .& numG 0xffffffL
      pad := AST.extract blr 8<rt> 24
      setCC bld 0
      let labels = body, more, same, diff, out
      compareLoop bld (aa, al) (ba, bl) pad (x, y) labels
      alr := (alr .& numG ~~~0xffffffL) .| al
      blr := (blr .& numG ~~~0xffffffL) .| bl
    }

/// TEST AND SET, the oldest of the architecture's atomic primitives: the
/// leftmost bit of a byte decides the condition code and the whole byte is then
/// set to ones.
let testAndSet ins bld =
  lift bld (ins: Instruction) {
    let o = getOneOpr ins
    let addr = tmpVar bld GRSize
    let v = tmpVar bld 8<rt>
    AST.sideEffect AtomicBegin
    addr := transMem bld o
    v := loadMem 8<rt> addr
    storeMem addr (numI32 0xff 8<rt>)
    AST.sideEffect AtomicEnd
    ccVar bld := AST.ite ((v .& numI32 0x80 8<rt>) == AST.num0 8<rt>)
                         (numCC 0)
                         (numCC 1)
  }

/// TRANSLATE: each byte of the first operand is replaced by the byte the table
/// the second operand names holds at that byte's own value.
let translate ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = tmpVar bld GRSize
    let table = tmpVar bld GRSize
    d := transMem bld o1
    table := transMem bld o2
    emitTransLoop bld (numG (int64 (lenOfMem o1))) d table
  }

/// TRANSLATE AND TEST: the first operand's bytes index the same kind of table,
/// but nothing is written -- the first non-zero entry stops the scan, naming
/// the byte it came from in R1 and itself in R2. It is how a program finds the
/// first byte of a field that belongs to a given class.
let translateAndTest ins bld backwards =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = tmpVar bld GRSize
    let table = tmpVar bld GRSize
    d := transMem bld o1
    table := transMem bld o2
    emitTransTestLoop bld (numG (int64 (lenOfMem o1))) d table backwards
  }

/// ADD LOGICAL WITH SIGNED IMMEDIATE to storage. The immediate field is a
/// signed byte, which the parser hands over as the unsigned bits it holds, so
/// the sign is put back here before the addition.
let addLogicalToStorage ins bld rt =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let addr = tmpVar bld GRSize
    let a = tmpVar bld rt
    let t = tmpVar bld rt
    addr := transMem bld o1
    a := loadMem rt addr
    let b = numI64 (int64 (sbyte (oprImm o2))) rt
    t := a .+ b
    setCCAddLogical bld t (t .< a)
    storeMem addr t
  }

/// PERFORM TIMING FACILITY FUNCTION, whose third condition code says the
/// function asked for is not available -- which is the honest answer from a
/// machine with no timing facility to query.
let ptff ins bld =
  lift bld (ins: Instruction) {
    setCC bld 3
  }

/// MULTIPLY, whose product is twice as wide as its operands and so fills a
/// register pair: the even register takes the high half, the odd one the low,
/// and it is the odd one that supplied the multiplicand.
let mulPair ins bld (rt: RegType) accW =
  let struct (o1, o2) = getTwoOprs ins
  let r1 = oprReg o1
  if not (isPair r1) then
    specException ins bld
  else
    let hi = reg bld r1
    let lo = reg bld (pairOf r1)
    let wide = rt * 2
    let t = tmpVar bld wide
    lift bld (ins: Instruction) {
      let b = AST.sext wide (srcOf bld accW o2)
      t := AST.sext wide (srcReg rt lo) .* b
      dst rt hi := AST.xthi rt t
      dst rt lo := AST.xtlo rt t
    }

/// The three-operand form of the double-width multiply, which names both
/// factors and so leaves them alone.
let mulPair3 ins bld (rt: RegType) =
  let struct (o1, o2, o3) = getThreeOprs ins
  let r1 = oprReg o1
  if not (isPair r1) then
    specException ins bld
  else
    let hi = reg bld r1
    let lo = reg bld (pairOf r1)
    let wide = rt * 2
    let t = tmpVar bld wide
    lift bld (ins: Instruction) {
      let a = AST.sext wide (srcOf bld rt o2)
      let b = AST.sext wide (srcOf bld rt o3)
      t := a .* b
      dst rt hi := AST.xthi rt t
      dst rt lo := AST.xtlo rt t
    }

/// MULTIPLY SINGLE with a condition code, which reports whether the product
/// left the range its width can hold.
let mulCC ins bld (rt: RegType) accW ext =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let wide = rt * 2
    let t = tmpVar bld wide
    let r = tmpVar bld rt
    let b = AST.sext wide (ext rt (srcOf bld accW o2))
    t := AST.sext wide (srcReg rt d) .* b
    r := AST.xtlo rt t
    let fits = AST.sext wide r == t
    ccVar bld := AST.ite fits (AST.ite (r == AST.num0 rt) (numCC 0)
                                       (AST.ite (r ?< AST.num0 rt)
                                                (numCC 1)
                                                (numCC 2)))
                         (numCC 3)
    dst rt d := r
  }

/// DIVIDE, whose dividend spans a register pair: the quotient replaces the odd
/// register and the remainder the even one.
let divPair ins bld (rt: RegType) accW =
  let struct (o1, o2) = getTwoOprs ins
  let r1 = oprReg o1
  if not (isPair r1) then
    specException ins bld
  else
    let hi = reg bld r1
    let lo = reg bld (pairOf r1)
    let wide = rt * 2
    let num = tmpVar bld wide
    let den = tmpVar bld wide
    let q = tmpVar bld wide
    let r = tmpVar bld wide
    lift bld (ins: Instruction) {
      den := AST.sext wide (srcOf bld accW o2)
      num := AST.concat (srcReg rt hi) (srcReg rt lo)
      q := num ?/ den
      r := num ?% den
      dst rt hi := AST.xtlo rt r
      dst rt lo := AST.xtlo rt q
    }

/// The double shifts, which work on the 64-bit value a register pair's two low
/// words make up. The arithmetic ones report the sign of what they produced.
let shiftDouble ins bld f setsCC =
  let struct (o1, o2) = getTwoOprs ins
  let r1 = oprReg o1
  if not (isPair r1) then
    specException ins bld
  else
    let hi = reg bld r1
    let lo = reg bld (pairOf r1)
    let t = tmpVar bld GRSize
    lift bld (ins: Instruction) {
      let value = AST.concat (low hi) (low lo)
      t := f value (transMem bld o2 .& numG 63L)
      if setsCC then setCCSign bld t else ()
      low hi := AST.xthi WSize t
      low lo := AST.xtlo WSize t
    }

/// COMPARE DOUBLE AND SWAP, the pair-wide form of the atomic exchange: the
/// comparand and the replacement each span two registers, so a program can
/// swap a pointer and its counter together.
let compareDoubleAndSwap ins bld (rt: RegType) =
  let struct (o1, o2, o3) = getThreeOprs ins
  let r1 = oprReg o1
  let r3 = oprReg o3
  if not (isPair r1 && isPair r3) then
    specException ins bld
  else
    let wide = rt * 2
    let ahi = reg bld r1
    let alo = reg bld (pairOf r1)
    let bhi = reg bld r3
    let blo = reg bld (pairOf r3)
    let addr = tmpVar bld GRSize
    let found = tmpVar bld wide
    let want = tmpVar bld wide
    let swap = label bld "CdsSwap"
    let out = label bld "CdsOut"
    lift bld (ins: Instruction) {
      AST.sideEffect AtomicBegin
      addr := transMem bld o2
      found := loadMem wide addr
      want := AST.concat (srcReg rt ahi) (srcReg rt alo)
      AST.cjmp (found == want) (AST.jmpDest swap) (AST.jmpDest out)
      AST.lmark swap
      storeMem addr (AST.concat (srcReg rt bhi) (srcReg rt blo))
      AST.lmark out
      ccVar bld := AST.ite (found == want) (numCC 0) (numCC 1)
      dst rt ahi := AST.xthi rt found
      dst rt alo := AST.xtlo rt found
      AST.sideEffect AtomicEnd
    }

/// LOAD PAIR DISJOINT, which fetches two words or doublewords from unrelated
/// places and reports whether it managed to do so as one indivisible access.
/// One thread at a time means it always does.
let loadPairDisjoint ins bld rt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let r3 = oprReg o3
  if not (isPair r3) then
    specException ins bld
  else
    lift bld (ins: Instruction) {
      AST.sideEffect AtomicBegin
      dst rt (reg bld r3) := loadMem rt (transMem bld o1)
      dst rt (reg bld (pairOf r3)) := loadMem rt (transMem bld o2)
      AST.sideEffect AtomicEnd
      setCC bld 0
    }

/// LOAD PAIR FROM QUADWORD and its mirror, the sixteen-byte accesses a program
/// uses when it needs two doublewords to move together.
let quadPair ins bld isLoad =
  let struct (o1, o2) = getTwoOprs ins
  let r1 = oprReg o1
  if not (isPair r1) then
    specException ins bld
  else
    let hi = reg bld r1
    let lo = reg bld (pairOf r1)
    let addr = tmpVar bld GRSize
    lift bld (ins: Instruction) {
      AST.sideEffect AtomicBegin
      addr := transMem bld o2
      if isLoad then
        let v = tmpVar bld 128<rt>
        v := loadMem 128<rt> addr
        hi := AST.xthi GRSize v
        lo := AST.xtlo GRSize v
      else
        storeMem addr (AST.concat hi lo)
      AST.sideEffect AtomicEnd
    }

/// A load that traps on a zero result, which a compiler plants where a null
/// pointer must not be allowed to travel any further.
let loadAndTrap ins bld rt accW ext =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let t = tmpVar bld rt
    let trap = label bld "LatTrap"
    let out = label bld "LatOut"
    t := ext rt (srcOf bld accW o2)
    AST.cjmp (t == AST.num0 rt) (AST.jmpDest trap) (AST.jmpDest out)
    AST.lmark trap
    AST.sideEffect (Exception IntegerOverflow)
    AST.lmark out
    dst rt d := t
  }

/// A load that clears the value's rightmost byte, which is how a pointer that
/// carries tag bits there is stripped as it is loaded.
let loadZeroRightmost ins bld rt accW ext =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let v = ext rt (srcOf bld accW o2)
    dst rt d := v .& numI64 -256L rt
  }

/// LOAD ADDRESS EXTENDED, which is LOAD ADDRESS with an access register set
/// alongside. A program in the primary-space mode -- the only mode Linux runs
/// its processes in -- gets zero there.
let loadAddressExtended ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let r1 = oprReg o1
    reg bld r1 := transMem bld o2
    reg bld (enum<Register> (int Register.AR0 + int r1))
            := AST.num0 WSize
  }

/// The access registers a load- or store-multiple-access walks, wrapping
/// around AR15 to AR0 as the general registers do.
let private accessRange (a1: Register) (a3: Register) =
  let first = int a1 - int Register.AR0
  let count = ((int a3 - int a1) &&& 0xf) + 1
  [| for i in 0 .. count - 1 ->
       enum<Register> (int Register.AR0 + ((first + i) &&& 0xf)) |]

/// LOAD or STORE ACCESS MULTIPLE: consecutive access registers take, or fill,
/// consecutive words of storage.
let accessMultiple ins bld isLoad =
  lift bld (ins: Instruction) {
    let struct (o1, o2, o3) = getThreeOprs ins
    let regs = accessRange (oprReg o1) (oprReg o3)
    let addr = tmpVar bld GRSize
    addr := transMem bld o2
    for i in 0 .. regs.Length - 1 do
      let at = addr .+ numG (int64 i * 4L)
      if isLoad then append bld { reg bld regs[i] := loadMem WSize at }
      else append bld { storeMem at (reg bld regs[i]) }
  }

/// COPY ACCESS, a move between two access registers.
let copyAccess ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    oprRegVar bld o1 := oprRegVar bld o2
  }

/// TEST ACCESS, which asks what an access-list entry token names. Every token
/// a Linux process holds is the primary one, which is what a zero condition
/// code says.
let testAccess ins bld =
  lift bld (ins: Instruction) {
    setCC bld 0
  }

/// TEST ADDRESSING MODE, whose condition code names the mode a program is
/// running in: none for 24-bit addressing, the first for 31-bit, the third for
/// 64-bit.
let testAddressingMode ins bld =
  lift bld (ins: Instruction) {
    setCC bld (if esaMode bld then 1 else 3)
  }

/// CHECKSUM, which adds the second operand's words into the first with the
/// carries folded back in -- the ones' complement sum a network header needs.
let checksum ins bld =
  let struct (o1, o2) = getTwoOprs ins
  let r2 = oprReg o2
  if not (isPair r2) then
    specException ins bld
  else
    let acc = oprRegVar bld o1
    let addr = reg bld r2
    let len = reg bld (pairOf r2)
    let sum = tmpVar bld GRSize
    let body = label bld "CksmBody"
    let more = label bld "CksmMore"
    let out = label bld "CksmOut"
    lift bld (ins: Instruction) {
      sum := zextTo GRSize (low acc)
      AST.lmark body
      AST.cjmp (len .< numG 4L) (AST.jmpDest out) (AST.jmpDest more)
      AST.lmark more
      sum := sum .+ zextTo GRSize (loadMem WSize addr)
      addr := addr .+ numG 4L
      len := len .- numG 4L
      AST.jmp (AST.jmpDest body)
      AST.lmark out
      (* Fold the carries out of the word back into it, twice, so that a carry
         the first fold produces is itself folded in. *)
      sum := (sum .& numG 0xffffffffL) .+ (sum >> numG 32L)
      sum := (sum .& numG 0xffffffffL) .+ (sum >> numG 32L)
      low acc := AST.xtlo WSize sum
      setCC bld 0
    }

/// COMPARE LOGICAL AND TRAP, which compares a register against storage and
/// takes the trap when the mask names the code the comparison produced.
let compareTrapStorage ins bld rt =
  lift bld (ins: Instruction) {
    let struct (o1, o2, o3) = getThreeOprs ins
    let m = oprMask o3
    if m &&& 0xeus = 0us then
      ()
    else
      let a = tmpVar bld rt
      let b = tmpVar bld rt
      a := srcReg rt (oprRegVar bld o1)
      b := loadMem rt (transMem bld o2)
      let trap = label bld "CltTrap"
      let out = label bld "CltOut"
      let eq = if m &&& 8us <> 0us then [ a == b ] else []
      let lo = if m &&& 4us <> 0us then [ a .< b ] else []
      let hi = if m &&& 2us <> 0us then [ a .> b ] else []
      let cond = List.reduce (.|) (eq @ lo @ hi)
      AST.cjmp cond (AST.jmpDest trap) (AST.jmpDest out)
      AST.lmark trap
      AST.sideEffect (Exception IntegerOverflow)
      AST.lmark out
  }

/// BRANCH INDIRECT ON CONDITION, which takes its target from storage rather
/// than from a register -- a jump through a table without a register to spare.
let branchIndirect ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let m = oprMask o1
    if isNever m then
      ()
    else
      let target = tmpVar bld GRSize
      target := loadMem GRSize (transMem bld o2)
      if isAlways m then
        AST.interjmp target InterJmpKind.Base
      else
        let next = numG (int64 (codeAddr bld (nextAddr ins)))
        AST.intercjmp (condOfMask bld m) target next
  }

/// MOVE PAGE, which copies a whole 4096-byte page.
let movePage ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = tmpVar bld GRSize
    let s = tmpVar bld GRSize
    d := oprRegVar bld o1 .& numG -4096L
    s := oprRegVar bld o2 .& numG -4096L
    emitByteLoop bld (numG 4096L) d s (fun _ sv -> sv)
    setCC bld 0
  }

/// SEARCH STRING UNICODE, the halfword-at-a-time form of the string search.
let searchStringUnicode ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let s = oprRegVar bld o2
    let limit = tmpVar bld GRSize
    let p = tmpVar bld GRSize
    let body = label bld "SrstuBody"
    let step = label bld "SrstuStep"
    let cont = label bld "SrstuCont"
    let found = label bld "SrstuFound"
    let none = label bld "SrstuNone"
    let out = label bld "SrstuOut"
    limit := d
    p := s
    AST.lmark body
    AST.cjmp (p .>= limit) (AST.jmpDest none) (AST.jmpDest step)
    AST.lmark step
    AST.cjmp (loadMem 16<rt> p == AST.xtlo 16<rt> (reg bld Register.R0))
             (AST.jmpDest found)
             (AST.jmpDest cont)
    AST.lmark cont
    p := p .+ numG 2L
    AST.jmp (AST.jmpDest body)
    AST.lmark found
    d := p
    setCC bld 1
    AST.jmp (AST.jmpDest out)
    AST.lmark none
    s := limit
    setCC bld 2
    AST.lmark out
  }

/// TRANSLATE EXTENDED, which translates through a table until it meets the
/// byte R0 names -- the length lives in a register, so the field can be longer
/// than an encoded length could say.
let translateExtended ins bld =
  let struct (o1, o2) = getTwoOprs ins
  let r1 = oprReg o1
  if not (isPair r1) then
    specException ins bld
  else
    let addr = reg bld r1
    let len = reg bld (pairOf r1)
    let table = oprRegVar bld o2
    let v = tmpVar bld 8<rt>
    let body = label bld "TreBody"
    let more = label bld "TreMore"
    let step = label bld "TreStep"
    let found = label bld "TreFound"
    let out = label bld "TreOut"
    lift bld (ins: Instruction) {
      setCC bld 0
      AST.lmark body
      AST.cjmp (len == AST.num0 GRSize)
               (AST.jmpDest out)
               (AST.jmpDest more)
      AST.lmark more
      v := loadMem 8<rt> addr
      AST.cjmp (v == AST.xtlo 8<rt> (reg bld Register.R0))
               (AST.jmpDest found)
               (AST.jmpDest step)
      AST.lmark step
      storeMem addr (loadMem 8<rt> (table .+ zextTo GRSize v))
      addr := addr .+ AST.num1 GRSize
      len := len .- AST.num1 GRSize
      AST.jmp (AST.jmpDest body)
      AST.lmark found
      setCC bld 1
      AST.lmark out
    }

/// The translate-and-test instructions that work in units wider than a byte:
/// the second operand's units index a table whose entries are the first
/// operand's units, and a unit equal to the one R0 names stops the operation
/// before it is stored. The mask's rightmost bit turns that test off.
let translateUnits ins bld srcW dstW =
  let struct (o1, o2, o3) = getThreeOprs ins
  let r1 = oprReg o1
  if not (isPair r1) then
    specException ins bld
  else
    let da = reg bld r1
    let len = reg bld (pairOf r1)
    let sa = oprRegVar bld o2
    let table = reg bld Register.R1
    let noTest = oprMask o3 &&& 1us <> 0us
    let srcStep = numG (int64 (RegType.toByteWidth srcW))
    let dstStep = numG (int64 (RegType.toByteWidth dstW))
    let scale = numG (int64 (RegType.toByteWidth dstW))
    let v = tmpVar bld dstW
    let body = label bld "TrxBody"
    let more = label bld "TrxMore"
    let step = label bld "TrxStep"
    let found = label bld "TrxFound"
    let out = label bld "TrxOut"
    lift bld (ins: Instruction) {
      setCC bld 0
      AST.lmark body
      AST.cjmp (len .< srcStep) (AST.jmpDest out) (AST.jmpDest more)
      AST.lmark more
      let index = zextTo GRSize (loadMem srcW sa) .* scale
      v := loadMem dstW (table .+ index)
      if noTest then
        AST.jmp (AST.jmpDest step)
      else
        AST.cjmp (v == narrowTo dstW (reg bld Register.R0))
                 (AST.jmpDest found)
               (AST.jmpDest step)
      AST.lmark step
      storeMem da v
      da := da .+ dstStep
      sa := sa .+ srcStep
      len := len .- srcStep
      AST.jmp (AST.jmpDest body)
      AST.lmark found
      setCC bld 1
      AST.lmark out
    }

/// TRANSLATE AND TEST EXTENDED: the argument characters index a table of
/// function codes, and the first non-zero code stops the scan, naming the
/// argument it came from and itself in the registers the older TRANSLATE AND
/// TEST uses. The mask says how wide the arguments and the codes are.
let translateTestExtended ins bld backwards =
  let struct (o1, o2, o3) = getThreeOprs ins
  let r1 = oprReg o1
  if not (isPair r1) then
    specException ins bld
  else
    let m = oprMask o3
    let argW = if m &&& 8us <> 0us then 16<rt> else 8<rt>
    let fnW = if m &&& 4us <> 0us then 16<rt> else 8<rt>
    let addr = reg bld r1
    let len = reg bld (pairOf r1)
    let table = oprRegVar bld o2
    let argStep = numG (int64 (RegType.toByteWidth argW))
    let scale = numG (int64 (RegType.toByteWidth fnW))
    let fn = tmpVar bld fnW
    let body = label bld "TrteBody"
    let more = label bld "TrteMore"
    let step = label bld "TrteStep"
    let found = label bld "TrteFound"
    let out = label bld "TrteOut"
    lift bld (ins: Instruction) {
      setCC bld 0
      AST.lmark body
      AST.cjmp (len .< argStep) (AST.jmpDest out) (AST.jmpDest more)
      AST.lmark more
      let index = zextTo GRSize (loadMem argW addr) .* scale
      fn := loadMem fnW (table .+ index)
      AST.cjmp (fn == AST.num0 fnW)
               (AST.jmpDest step)
               (AST.jmpDest found)
      AST.lmark step
      if backwards then append bld { addr := addr .- argStep }
      else append bld { addr := addr .+ argStep }
      len := len .- argStep
      AST.jmp (AST.jmpDest body)
      AST.lmark found
      narrowTo fnW (reg bld Register.R1) := fn
      setCC bld 1
      AST.lmark out
    }

/// TRANSACTION END, which ends nothing here because no transaction ever
/// begins; outside one it reports 0 as the architecture says.
let tend ins bld =
  lift bld (ins: Instruction) {
    setCC bld 0
  }

/// INSERT PROGRAM MASK: the condition code and the program mask are laid into
/// one byte of the first operand, which is how a program reads the code it
/// cannot otherwise see. The program mask is zero throughout, since nothing
/// here enables the interruptions it would unmask.
let ipm ins bld =
  lift bld (ins: Instruction) {
    let d = oprRegVar bld (getOneOpr ins)
    AST.extract d 8<rt> 24 := ccVar bld << numCC 4
  }

/// SET PROGRAM MASK, which takes the condition code back out of that byte.
let spm ins bld =
  lift bld (ins: Instruction) {
    let d = oprRegVar bld (getOneOpr ins)
    ccVar bld := (AST.extract d 8<rt> 28) .& numCC 3
  }

/// EXTRACT ACCESS: the access register a thread's own storage is reached
/// through, which is where the s390 ABI keeps the thread pointer.
let ear ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    low d := oprRegVar bld o2
  }

/// SET ACCESS, the write that matches EXTRACT ACCESS.
let sar ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    d := low (oprRegVar bld o2)
  }

/// A copy between a floating-point and a general register, which compilers use
/// to park a value without touching storage.
let regCopy ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    oprRegVar bld o1 := oprRegVar bld o2
  }

/// SUPERVISOR CALL. The immediate names the call whenever it is not zero; a
/// zero one means the number is in R1 instead, so it is handed on as it stands
/// and the kernel reads whichever applies.
let svc ins bld =
  lift bld (ins: Instruction) {
    let imm = oprImm (getOneOpr ins)
    regVar bld Register.SVCCODE := numI64 imm 8<rt>
    AST.sideEffect SysCall
  }

/// EXTRACT PSW, which hands a program the program-status word it otherwise
/// cannot see. Only the condition code of it is modelled, and it sits where the
/// word carries it; the rest reads as zero, as do the bits no supervisor here
/// ever sets.
let extractPsw ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let r1 = oprReg o1
    let r2 = oprReg o2
    low (reg bld r1) := zextTo WSize (ccVar bld) << numW 12L
    if r2 <> Register.R0 then
      append bld { low (reg bld r2) := AST.num0 WSize }
    else
      ()
  }

/// LOAD COUNT TO BLOCK BOUNDARY, which says how many of the sixteen bytes a
/// vector load would want lie before the boundary the mask names. The third
/// condition code means all sixteen do.
let loadCountToBoundary ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2, o3) = getThreeOprs ins
    let d = oprRegVar bld o1
    let bound =
      match oprMask o3 &&& 0xfus with
      | 1us -> 128L
      | 2us -> 256L
      | 3us -> 512L
      | 4us -> 1024L
      | 5us -> 2048L
      | 6us -> 4096L
      | _ -> 64L
    let room = tmpVar bld GRSize
    room := numG bound .- (transMem bld o2 .& numG (bound - 1L))
    room := AST.ite (room .> numG 16L) (numG 16L) room
    low d := AST.xtlo WSize room
    ccVar bld := AST.ite (room == numG 16L) (numCC 0) (numCC 3)
  }

/// STORE CLOCK EXTENDED, whose sixteen bytes are the clock this emulator does
/// not keep, so they read as zero -- as the plain STORE CLOCK's eight do.
let storeClockExtended ins bld =
  lift bld (ins: Instruction) {
    let o = getOneOpr ins
    let addr = tmpVar bld GRSize
    addr := transMem bld o
    storeMem addr (AST.num0 GRSize)
    storeMem (addr .+ numG 8L) (AST.num0 GRSize)
    setCC bld 0
  }

/// LOAD MULTIPLE DISJOINT, which fills a range of registers from two places at
/// once: the high halves come from one and the low halves from the other.
let loadMultipleDisjoint (ins: Instruction) bld =
  match ins.Operands with
  | FourOperands(o1, o2, o3, o4) ->
    let regs = regRange (oprReg o1) (oprReg o3)
    let hi = tmpVar bld GRSize
    let lo = tmpVar bld GRSize
    lift bld (ins: Instruction) {
      hi := transMem bld o2
      lo := transMem bld o4
      for i in 0 .. regs.Length - 1 do
        let at k = numG (int64 i * 4L) .+ k
        high (reg bld regs[i]) := loadMem WSize (at hi)
        low (reg bld regs[i]) := loadMem WSize (at lo)
    }
  | _ ->
    raise InvalidOperandException

/// The inner walk: compare the two substrings a byte at a time from where the
/// outer scan stands, and give this position up the moment a byte differs.
/// Reaching the full length means they agree, which is what was looked for.
let private compareSubstring bld operands counters labels =
  append bld {
    let aa, ba = operands
    let n, k, ok = counters
    let inner, step, advance, found = labels
    AST.lmark inner
    AST.cjmp (k == n) (AST.jmpDest found) (AST.jmpDest step)
    AST.lmark step
    ok := AST.ite (loadMem 8<rt> (aa .+ k) == loadMem 8<rt> (ba .+ k))
                  ok
                  AST.b0
    k := k .+ AST.num1 GRSize
    AST.cjmp (ok == AST.b1) (AST.jmpDest inner) (AST.jmpDest advance)
  }

/// COMPARE UNTIL SUBSTRING EQUAL, which looks for the first place the two
/// operands agree over a whole substring, whose length R0 gives.
let compareUntilEqual ins bld =
  let struct (o1, o2) = getTwoOprs ins
  let r1 = oprReg o1
  let r2 = oprReg o2
  if not (isPair r1 && isPair r2) then
    specException ins bld
  else
    let aa = reg bld r1
    let al = reg bld (pairOf r1)
    let ba = reg bld r2
    let bl = reg bld (pairOf r2)
    let n = tmpVar bld GRSize
    let k = tmpVar bld GRSize
    let ok = tmpVar bld 1<rt>
    let body = label bld "CuseBody"
    let more = label bld "CuseMore"
    let inner = label bld "CuseInner"
    let step = label bld "CuseStep"
    let advance = label bld "CuseAdvance"
    let found = label bld "CuseFound"
    let out = label bld "CuseOut"
    lift bld (ins: Instruction) {
      n := reg bld Register.R0 .& numG 0xffffffL
      setCC bld 2
      AST.lmark body
      (* Neither operand may run out before the substring could fit. *)
      AST.cjmp ((al .< n) .| (bl .< n))
               (AST.jmpDest out)
               (AST.jmpDest more)
      AST.lmark more
      k := AST.num0 GRSize
      ok := AST.b1
      compareSubstring bld (aa, ba) (n, k, ok) (inner, step, advance, found)
      AST.lmark advance
      aa := aa .+ AST.num1 GRSize
      al := al .- AST.num1 GRSize
      ba := ba .+ AST.num1 GRSize
      bl := bl .- AST.num1 GRSize
      AST.jmp (AST.jmpDest body)
      AST.lmark found
      setCC bld 0
      AST.lmark out
    }

/// A privileged or control-program instruction. Reaching one from problem
/// state is a privileged-operation exception, which Linux turns into the
/// illegal-instruction signal -- so raising the trap is the behaviour, not a
/// gap in what is modelled here.
let illegal ins bld =
  lift bld (ins: Instruction) {
    AST.sideEffect UndefinedInstruction
  }

/// An instruction with nothing for an emulator of user code to do: a prefetch,
/// a serialization, or a hint about how the code ahead will behave.
let nop ins bld =
  lift bld (ins: Instruction) {
  }

/// A serializing instruction, which orders the accesses around it and does
/// nothing else that can be seen.
let fence ins bld =
  lift bld (ins: Instruction) {
    AST.sideEffect Fence
  }

/// An instruction that is valid but outside what this lifter models.
let unsupported ins bld =
  lift bld (ins: Instruction) {
    AST.sideEffect UnsupportedInstruction
  }

/// SET ADDRESSING MODE, which moves a program between the 24-, 31-, and 64-bit
/// modes. Only the one the guest already runs in is modelled -- a Linux process
/// is put in its mode by the kernel and never leaves it -- so asking for that
/// one does nothing and asking for another raises the unsupported trap rather
/// than carrying on with addresses of the wrong width.
let setAddressMode ins bld bits =
  let current = if esaMode bld then 31 else 64
  if bits = current then nop ins bld else unsupported ins bld

/// TRANSACTION BEGIN, which this lifter always reports as having failed for a
/// reason that will persist: no transactional execution happens here, so a
/// guest that elides a lock must fall back to taking it.
let tbegin ins bld =
  lift bld (ins: Instruction) {
    setCC bld 2
  }

/// EXTRACT TRANSACTION NESTING DEPTH, which is zero because no transaction
/// ever begins.
let etnd ins bld =
  lift bld (ins: Instruction) {
    let d = oprRegVar bld (getOneOpr ins)
    low d := AST.num0 WSize
  }

/// STORE CLOCK, whose value the emulator supplies.
let storeClock ins bld =
  lift bld (ins: Instruction) {
    let o = getOneOpr ins
    let addr = tmpVar bld GRSize
    addr := transMem bld o
    storeMem addr (AST.num0 GRSize)
    setCC bld 0
  }

/// STORE FACILITY LIST EXTENDED, which reports the facilities the machine has.
/// Reporting none keeps a guest that chooses an implementation by facility --
/// as the C library's string routines do -- on the one every machine can run.
let stfle ins bld =
  lift bld (ins: Instruction) {
    let o = getOneOpr ins
    let addr = tmpVar bld GRSize
    addr := transMem bld o
    storeMem addr (AST.num0 GRSize)
    low (reg bld Register.R0) := AST.num0 WSize
    setCC bld 0
  }
