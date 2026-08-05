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
    bld <+ (t := e)
    t
  | _ -> e

let ccNone _ _ _ _ = ()

let ccAdd bld res a b = setCCAdd bld res a b

let ccSub bld res a b = setCCSub bld res a b

let ccSign bld res _ _ = setCCSign bld res

let ccLogic bld res _ _ = setCCLogic bld res

let ccAddL bld res a _ = setCCAddLogical bld res (res .< a)

let ccSubL bld _ a b = setCCSubLogical bld a b

/// A plain load: the second operand's value, widened as the operation names,
/// becomes the first operand's.
let load ins insLen bld rt accW ext =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (dst rt d := ext rt (srcOf bld accW o2))
  bld --!> insLen

/// LOAD LOGICAL THIRTY ONE BITS, which takes a word and drops its top bit --
/// the one a 31-bit address space used to carry the addressing mode in.
let loadThirtyOne ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (d := zextTo GRSize (srcOf bld WSize o2) .& numG 0x7fffffffL)
  bld --!> insLen

/// INSERT IMMEDIATE: an immediate replaces one field of a register and leaves
/// the rest of it as it was.
let insertImm ins insLen bld pos width =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (AST.extract d width pos := numI64 (oprImm o2) width)
  bld --!> insLen

/// LOAD LOGICAL IMMEDIATE: an immediate becomes the whole register, shifted to
/// the field the operation names and zero everywhere else.
let loadLogicalImm ins insLen bld shift =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  let v = uint64 (oprImm o2) <<< (shift: int)
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (d := numG (int64 v))
  bld --!> insLen

/// A load that also reports the sign of what it loaded.
let loadTest ins insLen bld rt accW ext =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  let t = tmpVar bld rt
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (t := ext rt (srcOf bld accW o2))
  setCCSign bld t
  bld <+ (dst rt d := t)
  bld --!> insLen

/// A load whose storage operand is named relative to the instruction rather
/// than by a base and displacement.
let loadRel ins insLen bld rt accW ext =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  let addr = numG (int64 (codeAddr bld (relTarget ins.Address (oprImm o2))))
  bld <!-- (ins.Address, insLen)
  bld <+ (dst rt d := ext rt (loadMem accW addr))
  bld --!> insLen

/// LOAD ADDRESS: the address the second operand names, rather than what is
/// stored there, becomes the first operand's value.
let la ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (d := transMem bld o2)
  bld --!> insLen

/// LOAD ADDRESS RELATIVE LONG: the address the instruction's own halfword
/// offset names, which is how position-independent code reaches its data.
let larl ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (d := numG (int64 (codeAddr bld (relTarget ins.Address (oprImm o2)))))
  bld --!> insLen

/// A plain store of the first operand's low bits.
let store ins insLen bld accW =
  let struct (o1, o2) = getTwoOprs ins
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ storeMem (transMem bld o2) (narrowTo accW (oprRegVar bld o1))
  bld --!> insLen

/// A value with its bytes in the opposite order, which is what the
/// byte-reversing loads and stores exist to produce: s390 stores everything
/// most significant byte first, and reads a little-endian file or protocol by
/// turning each field around as it goes past.
let private byteSwap rt e =
  let n = RegType.toBitWidth rt / 8
  let bytes = [| for i in 0 .. n - 1 -> AST.extract e 8<rt> (i * 8) |]
  Array.reduce (fun acc b -> AST.concat acc b) bytes

/// LOAD REVERSED, from a register or from storage.
let loadReversed ins insLen bld rt accW =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  bld <!-- ((ins: Instruction).Address, insLen)
  let v = byteSwap accW (srcOf bld accW o2)
  if accW = rt then bld <+ (dst rt d := v)
  else bld <+ (AST.extract d accW 0 := v)
  bld --!> insLen

/// STORE REVERSED, the mirror of LOAD REVERSED.
let storeReversed ins insLen bld accW =
  let struct (o1, o2) = getTwoOprs ins
  bld <!-- ((ins: Instruction).Address, insLen)
  let v = byteSwap accW (narrowTo accW (oprRegVar bld o1))
  bld <+ storeMem (transMem bld o2) v
  bld --!> insLen

/// A store of a register's leftmost word, which is where a short
/// floating-point value lives.
let storeHigh ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ storeMem (transMem bld o2) (AST.xthi WSize (oprRegVar bld o1))
  bld --!> insLen

/// A store to storage the instruction names relative to itself.
let storeRel ins insLen bld accW =
  let struct (o1, o2) = getTwoOprs ins
  let addr = numG (int64 (codeAddr bld (relTarget ins.Address (oprImm o2))))
  bld <!-- (ins.Address, insLen)
  bld <+ storeMem addr (narrowTo accW (oprRegVar bld o1))
  bld --!> insLen

/// MOVE IMMEDIATE: an immediate, widened where the field is narrower than the
/// unit stored, is written straight to storage.
let moveImm ins insLen bld accW =
  let struct (o1, o2) = getTwoOprs ins
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ storeMem (transMem bld o1) (numI64 (oprImm o2) accW)
  bld --!> insLen

/// The registers a load- or store-multiple walks, from the first operand's
/// through the third's, wrapping around R15 to R0 as the architecture does.
let private regRange (r1: Register) (r3: Register) =
  let first = int r1
  let count = ((int r3 - first) &&& 0xf) + 1
  [| for i in 0 .. count - 1 -> enum<Register> ((first + i) &&& 0xf) |]

/// LOAD MULTIPLE: consecutive registers take consecutive units of storage.
let loadMultiple ins insLen bld rt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let regs = regRange (oprReg o1) (oprReg o3)
  let width = int64 (RegType.toByteWidth rt)
  let addr = tmpVar bld GRSize
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (addr := transMem bld o2)
  for i in 0 .. regs.Length - 1 do
    let at = addr .+ numG (int64 i * width)
    bld <+ (dst rt (reg bld regs[i]) := loadMem rt at)
  bld --!> insLen

/// STORE MULTIPLE: the mirror of LOAD MULTIPLE, which together are how a
/// function prologue and epilogue save and restore the registers it uses.
let storeMultiple ins insLen bld rt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let regs = regRange (oprReg o1) (oprReg o3)
  let width = int64 (RegType.toByteWidth rt)
  let addr = tmpVar bld GRSize
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (addr := transMem bld o2)
  for i in 0 .. regs.Length - 1 do
    let at = addr .+ numG (int64 i * width)
    bld <+ storeMem at (narrowTo rt (reg bld regs[i]))
  bld --!> insLen

/// A storage-to-storage operation: the first operand's field takes, byte by
/// byte, the result of combining it with the second's.
let ssOp ins insLen bld f =
  let struct (o1, o2) = getTwoOprs ins
  let len = numG (int64 (lenOfMem o1))
  let d = tmpVar bld GRSize
  let s = tmpVar bld GRSize
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (d := transMem bld o1)
  bld <+ (s := transMem bld o2)
  emitByteLoop bld len d s f
  bld --!> insLen

/// The storage-to-storage bitwise operations, which report whether any bit of
/// the result is one.
let ssLogic ins insLen bld f =
  let struct (o1, o2) = getTwoOprs ins
  let len = numG (int64 (lenOfMem o1))
  let d = tmpVar bld GRSize
  let s = tmpVar bld GRSize
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (d := transMem bld o1)
  bld <+ (s := transMem bld o2)
  emitLogicLoop bld len d s f
  bld --!> insLen

/// The shape every two-operand arithmetic and logical instruction shares: the
/// first operand supplies one input and receives the result, the second the
/// other input.
let alu2 ins insLen bld rt f cc =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  let a = srcReg rt d
  let t = tmpVar bld rt
  bld <!-- ((ins: Instruction).Address, insLen)
  let b = hold bld rt o2 (srcOf bld rt o2)
  bld <+ (t := f a b)
  cc bld t a b
  bld <+ (dst rt d := t)
  bld --!> insLen

/// A two-operand operation whose source is narrower than the operation itself,
/// and so is widened by ext before taking part.
let alu2Ext ins insLen bld rt accW ext f cc =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  let a = srcReg rt d
  let t = tmpVar bld rt
  let b = tmpVar bld rt
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (b := ext rt (srcOf bld accW o2))
  bld <+ (t := f a b)
  cc bld t a b
  bld <+ (dst rt d := t)
  bld --!> insLen

/// The three-operand ("K") forms, which leave both inputs alone.
let alu3 ins insLen bld rt f cc =
  let struct (o1, o2, o3) = getThreeOprs ins
  let d = oprRegVar bld o1
  let t = tmpVar bld rt
  bld <!-- ((ins: Instruction).Address, insLen)
  let a = srcOf bld rt o2
  let b = srcOf bld rt o3
  bld <+ (t := f a b)
  cc bld t a b
  bld <+ (dst rt d := t)
  bld --!> insLen

/// The immediate three-operand forms, whose parsed operands put the immediate
/// where the register-to-register forms put the second source.
let alu3Imm ins insLen bld rt f cc =
  let struct (o1, o2, o3) = getThreeOprs ins
  let d = oprRegVar bld o1
  let t = tmpVar bld rt
  bld <!-- ((ins: Instruction).Address, insLen)
  let a = srcOf bld rt o3
  let b = srcOf bld rt o2
  bld <+ (t := f a b)
  cc bld t a b
  bld <+ (dst rt d := t)
  bld --!> insLen

/// ADD IMMEDIATE to storage, whose sum goes back where the addend came from.
let addToStorage ins insLen bld rt =
  let struct (o1, o2) = getTwoOprs ins
  let addr = tmpVar bld GRSize
  let a = tmpVar bld rt
  let t = tmpVar bld rt
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (addr := transMem bld o1)
  bld <+ (a := loadMem rt addr)
  let b = numI64 (oprImm o2) rt
  bld <+ (t := a .+ b)
  setCCAdd bld t a b
  bld <+ storeMem addr t
  bld --!> insLen

/// The immediate bitwise operations on storage, which read, combine, and write
/// back a single byte.
let logicImmStorage ins insLen bld f setsCC =
  let struct (o1, o2) = getTwoOprs ins
  let addr = tmpVar bld GRSize
  let t = tmpVar bld 8<rt>
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (addr := transMem bld o1)
  bld <+ (t := f (loadMem 8<rt> addr) (numI64 (oprImm o2) 8<rt>))
  if setsCC then setCCLogic bld t else ()
  bld <+ storeMem addr t
  bld --!> insLen

/// The immediate bitwise operations that touch one 16- or 32-bit field of a
/// register and leave the rest of it alone.
let logicImmField ins insLen bld pos width f =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  let field = AST.extract d width pos
  let t = tmpVar bld width
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (t := f field (numI64 (oprImm o2) width))
  setCCLogic bld t
  bld <+ (field := t)
  bld --!> insLen

/// ADD WITH CARRY and SUBTRACT WITH BORROW, which chain the previous
/// operation's carry -- the high bit of its condition code -- into this one.
let addCarry ins insLen bld rt =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  let a = srcReg rt d
  let cin = tmpVar bld rt
  let t = tmpVar bld rt
  bld <!-- ((ins: Instruction).Address, insLen)
  let b = hold bld rt o2 (srcOf bld rt o2)
  bld <+ (cin := zextTo rt ((ccVar bld >> numCC 1) .& numCC 1))
  bld <+ (t := a .+ b .+ cin)
  let carry = AST.ite (cin == AST.num0 rt) (t .< a) (t .<= a)
  setCCAddLogical bld t carry
  bld <+ (dst rt d := t)
  bld --!> insLen

/// SUBTRACT LOGICAL WITH BORROW: the borrow is the complement of the carry the
/// condition code's high bit records.
let subBorrow ins insLen bld rt =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  let a = srcReg rt d
  let borrow = tmpVar bld rt
  let t = tmpVar bld rt
  bld <!-- ((ins: Instruction).Address, insLen)
  let b = hold bld rt o2 (srcOf bld rt o2)
  bld <+ (borrow := zextTo rt (AST.num1 1<rt> <+> ((ccVar bld >> numCC 1)
                                                   .& numCC 1 == numCC 1)))
  bld <+ (t := a .- b .- borrow)
  let carry = AST.ite (borrow == AST.num0 rt) (a .>= b) (a .> b)
  setCCAddLogical bld t carry
  bld <+ (dst rt d := t)
  bld --!> insLen

/// The magnitude of a two's-complement value.
let absValue e =
  AST.ite (e ?< AST.num0 (Expr.typeOf e)) (AST.neg e) e

/// The negated magnitude, which is what LOAD NEGATIVE produces.
let negAbsValue e =
  AST.ite (e ?> AST.num0 (Expr.typeOf e)) (AST.neg e) e

/// The one-input arithmetic loads: complement, positive, and negative, each of
/// which reports the sign of what it produced.
let unaryArith ins insLen bld rt accW f =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  let t = tmpVar bld rt
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (t := f (sextTo rt (srcOf bld accW o2)))
  setCCSign bld t
  bld <+ (dst rt d := t)
  bld --!> insLen

/// MULTIPLY SINGLE, whose product is as wide as its operands and so needs no
/// register pair; it leaves the condition code alone.
let mul ins insLen bld rt accW ext =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  bld <!-- ((ins: Instruction).Address, insLen)
  let b = ext rt (srcOf bld accW o2)
  bld <+ (dst rt d := srcReg rt d .* b)
  bld --!> insLen

/// The three-operand multiply, which leaves its inputs alone.
let mul3 ins insLen bld rt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let d = oprRegVar bld o1
  bld <!-- ((ins: Instruction).Address, insLen)
  let a = srcOf bld rt o2
  let b = srcOf bld rt o3
  bld <+ (dst rt d := a .* b)
  bld --!> insLen

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
let private specException ins insLen bld =
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ AST.sideEffect UndefinedInstruction
  bld --!> insLen

/// MULTIPLY LOGICAL, whose double-width product fills a register pair: the
/// even register takes the high half and the odd one the low.
let mulLogical ins insLen bld (rt: RegType) accW =
  let struct (o1, o2) = getTwoOprs ins
  let r1 = oprReg o1
  if not (isPair r1) then
    specException ins insLen bld
  else
    let hi = reg bld r1
    let lo = reg bld (pairOf r1)
    let wide = rt * 2
    let t = tmpVar bld wide
    bld <!-- ((ins: Instruction).Address, insLen)
    let b = AST.zext wide (srcOf bld accW o2)
    bld <+ (t := AST.zext wide (srcReg rt lo) .* b)
    bld <+ (dst rt hi := AST.xthi rt t)
    bld <+ (dst rt lo := AST.xtlo rt t)
    bld --!> insLen

/// DIVIDE LOGICAL: the dividend spans the register pair, and the quotient and
/// remainder replace its odd and even members.
let divLogical ins insLen bld (rt: RegType) accW =
  let struct (o1, o2) = getTwoOprs ins
  let r1 = oprReg o1
  if not (isPair r1) then
    specException ins insLen bld
  else
    let hi = reg bld r1
    let lo = reg bld (pairOf r1)
    let wide = rt * 2
    let num = tmpVar bld wide
    let den = tmpVar bld wide
    bld <!-- ((ins: Instruction).Address, insLen)
    bld <+ (den := AST.zext wide (srcOf bld accW o2))
    bld <+ (num := AST.concat (srcReg rt hi) (srcReg rt lo))
    let q = tmpVar bld wide
    let r = tmpVar bld wide
    bld <+ (q := num ./ den)
    bld <+ (r := num .% den)
    bld <+ (dst rt hi := AST.xtlo rt r)
    bld <+ (dst rt lo := AST.xtlo rt q)
    bld --!> insLen

/// DIVIDE SINGLE: a signed division whose dividend is the odd register of the
/// pair alone, wide though the pair is.
let divSingle ins insLen bld rt accW =
  let struct (o1, o2) = getTwoOprs ins
  let r1 = oprReg o1
  if not (isPair r1) then
    specException ins insLen bld
  else
    let hi = reg bld r1
    let lo = reg bld (pairOf r1)
    let den = tmpVar bld rt
    let num = tmpVar bld rt
    bld <!-- ((ins: Instruction).Address, insLen)
    bld <+ (den := sextTo rt (srcOf bld accW o2))
    bld <+ (num := srcReg rt lo)
    let q = tmpVar bld rt
    let r = tmpVar bld rt
    bld <+ (q := num ?/ den)
    bld <+ (r := num ?% den)
    bld <+ (dst rt hi := r)
    bld <+ (dst rt lo := q)
    bld --!> insLen

/// FIND LEFTMOST ONE: the bit number of the highest one bit goes to the even
/// register of a pair and the operand with that bit cleared to the odd one.
let flogr ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let r1 = oprReg o1
  if not (isPair r1) then
    specException ins insLen bld
  else
    let hi = reg bld r1
    let lo = reg bld (pairOf r1)
    let v = tmpVar bld GRSize
    let n = tmpVar bld GRSize
    let bit = tmpVar bld GRSize
    let body = label bld "FlogrBody"
    let step = label bld "FlogrStep"
    let out = label bld "FlogrOut"
    bld <!-- ((ins: Instruction).Address, insLen)
    bld <+ (v := srcOf bld GRSize o2)
    bld <+ (n := AST.num0 GRSize)
    bld <+ (bit := numG 0x8000000000000000L)
    bld <+ (AST.lmark body)
    bld <+ (AST.cjmp ((n == numG 64L) .| ((v .& bit) != AST.num0 GRSize))
                     (AST.jmpDest out) (AST.jmpDest step))
    bld <+ (AST.lmark step)
    bld <+ (n := n .+ AST.num1 GRSize)
    bld <+ (bit := bit >> AST.num1 GRSize)
    bld <+ (AST.jmp (AST.jmpDest body))
    bld <+ (AST.lmark out)
    bld <+ (ccVar bld := AST.ite (v == AST.num0 GRSize) (numCC 0) (numCC 2))
    bld <+ (lo := v .& AST.not bit)
    bld <+ (hi := n)
    bld --!> insLen

/// POPULATION COUNT, which the architecture defines per byte: each byte of the
/// result counts the one bits of the matching byte of the operand.
let popcnt ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  let v = tmpVar bld GRSize
  let acc = tmpVar bld GRSize
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (v := srcOf bld GRSize o2)
  bld <+ (acc := v .- ((v >> numG 1L) .& numG 0x5555555555555555L))
  bld <+ (acc := (acc .& numG 0x3333333333333333L)
                 .+ ((acc >> numG 2L) .& numG 0x3333333333333333L))
  bld <+ (acc := (acc .+ (acc >> numG 4L)) .& numG 0x0f0f0f0f0f0f0f0fL)
  setCCLogic bld v
  bld <+ (d := acc)
  bld --!> insLen

/// The count a shift takes: the low six bits of the address its second operand
/// names, which is an address only in how it is written.
let private shiftCount bld o rt =
  narrowTo rt (transMem bld o .& numG 63L)

/// The two-operand shifts, which shift a register's low word in place.
let shift2 ins insLen bld f setsCC =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  let t = tmpVar bld WSize
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (t := f (low d) (shiftCount bld o2 WSize))
  if setsCC then setCCSign bld t else ()
  bld <+ (low d := t)
  bld --!> insLen

/// The three-operand shifts, which take their input from a third register.
let shift3 ins insLen bld rt f setsCC =
  let struct (o1, o2, o3) = getThreeOprs ins
  let d = oprRegVar bld o1
  let t = tmpVar bld rt
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (t := f (srcReg rt (oprRegVar bld o3)) (shiftCount bld o2 rt))
  if setsCC then setCCSign bld t else ()
  bld <+ (dst rt d := t)
  bld --!> insLen

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
let rotate ins insLen bld rt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let d = oprRegVar bld o1
  let t = tmpVar bld rt
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (t := rotl rt (srcReg rt (oprRegVar bld o3)) (shiftCount bld o2 rt))
  bld <+ (dst rt d := t)
  bld --!> insLen

/// The mask a rotate-then-insert selects: the bits from the starting position
/// through the ending one, counted from the left, wrapping around the register
/// when the start lies after the end.
let private selectMask (start: int) (fin: int) =
  let bitAt i = 1UL <<< (63 - i)
  let rec ones i acc = if i > fin then acc else ones (i + 1) (acc ||| bitAt i)
  if start <= fin then ones start 0UL
  else
    let rec upper i acc =
      if i > 63 then acc else upper (i + 1) (acc ||| bitAt i)
    upper start 0UL ||| ones 0 0UL

/// ROTATE THEN INSERT SELECTED BITS and its relatives: the second operand is
/// rotated left, and the bits a start-and-end pair names are combined into the
/// first. The zero-remaining-bits control, which the assembler spells as the
/// "z" suffix, makes the unselected bits zero rather than leaving them.
let rotateInsert (ins: Instruction) insLen bld f setsCC =
  match ins.Operands with
  | FiveOperands(o1, o2, o3, o4, o5) ->
    let d = oprRegVar bld o1
    let i3 = int (oprImm o3)
    let i4 = int (oprImm o4)
    let mask = selectMask (i3 &&& 63) (i4 &&& 63)
    let zero = i4 &&& 0x80 <> 0
    let t = tmpVar bld GRSize
    bld <!-- ((ins: Instruction).Address, insLen)
    let rotated = rotl GRSize (srcOf bld GRSize o2) (numG (oprImm o5 &&& 63L))
    let selected = rotated .& numG (int64 mask)
    if zero then bld <+ (t := selected)
    else bld <+ (t := f (d .& numG (int64 (~~~mask))) selected)
    if setsCC then setCCSign bld t else ()
    bld <+ (d := t)
    bld --!> insLen
  | _ -> raise InvalidOperandException

/// ROTATE THEN combine SELECTED BITS: the rotated bits the mask selects are
/// ORed, ANDed, or XORed into the first operand rather than replacing it, and
/// the condition code reports what the selected positions ended up holding. A
/// test control -- the high bit of the starting position -- asks for that
/// report without the update, which is how a program tests scattered bits.
let rotateCombine (ins: Instruction) insLen bld f =
  match ins.Operands with
  | FiveOperands(o1, o2, o3, o4, o5) ->
    let d = oprRegVar bld o1
    let i3 = int (oprImm o3)
    let mask = selectMask (i3 &&& 63) (int (oprImm o4) &&& 63)
    let testOnly = i3 &&& 0x80 <> 0
    let t = tmpVar bld GRSize
    bld <!-- ((ins: Instruction).Address, insLen)
    let rotated = rotl GRSize (srcOf bld GRSize o2) (numG (oprImm o5 &&& 63L))
    bld <+ (t := f d rotated mask)
    setCCLogic bld (t .& numG (int64 mask))
    if testOnly then () else bld <+ (d := t)
    bld --!> insLen
  | _ -> raise InvalidOperandException

/// A comparison, which reports how the first operand stands to the second and
/// changes nothing else.
let compare ins insLen bld rt accW ext signed =
  let struct (o1, o2) = getTwoOprs ins
  let a = tmpVar bld rt
  let b = tmpVar bld rt
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (a := srcReg rt (oprRegVar bld o1))
  bld <+ (b := ext rt (srcOf bld accW o2))
  if signed then setCCCmp bld a b else setCCCmpLogical bld a b
  bld --!> insLen

/// A comparison against storage the instruction names relative to itself.
let compareRel ins insLen bld rt accW ext signed =
  let struct (o1, o2) = getTwoOprs ins
  let addr = numG (int64 (codeAddr bld (relTarget ins.Address (oprImm o2))))
  let a = tmpVar bld rt
  let b = tmpVar bld rt
  bld <!-- (ins.Address, insLen)
  bld <+ (a := srcReg rt (oprRegVar bld o1))
  bld <+ (b := ext rt (loadMem accW addr))
  if signed then setCCCmp bld a b else setCCCmpLogical bld a b
  bld --!> insLen

/// A comparison of a field of storage against an immediate.
let compareStorageImm ins insLen bld accW signed =
  let struct (o1, o2) = getTwoOprs ins
  let a = tmpVar bld accW
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (a := loadMem accW (transMem bld o1))
  let b = numI64 (oprImm o2) accW
  if signed then setCCCmp bld a b else setCCCmpLogical bld a b
  bld --!> insLen

/// COMPARE LOGICAL, storage to storage.
let compareStorage ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let len = numG (int64 (lenOfMem o1))
  let a = tmpVar bld GRSize
  let b = tmpVar bld GRSize
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (a := transMem bld o1)
  bld <+ (b := transMem bld o2)
  emitCompareLoop bld len a b
  bld --!> insLen

/// TEST UNDER MASK on a byte of storage.
let testMaskStorage ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let v = tmpVar bld 8<rt>
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (v := loadMem 8<rt> (transMem bld o1))
  setCCTestMask bld v (uint64 (oprImm o2) &&& 0xffUL)
  bld --!> insLen

/// TEST UNDER MASK on one of a register's four halfwords.
let testMaskReg ins insLen bld pos =
  let struct (o1, o2) = getTwoOprs ins
  let v = tmpVar bld 16<rt>
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (v := AST.extract (oprRegVar bld o1) 16<rt> pos)
  setCCTestMask bld v (uint64 (oprMask o2))
  bld --!> insLen

/// The address of the instruction after the one being lifted, as an
/// expression, which is where a branch not taken carries on and where a call
/// leaves its return address.
let private fallThrough bld (ins: Instruction) insLen =
  numG (int64 (codeAddr bld (nextAddr ins.Address insLen)))

/// The value a call leaves in its link register. On z/Architecture that is the
/// return address and nothing else. ESA/390 has the addressing mode to record
/// as well, and puts it in the bit above the 31 an address occupies -- which is
/// why the branch back has to mask that bit off again.
let private linkValue bld (ins: Instruction) insLen =
  let next = codeAddr bld (nextAddr ins.Address insLen)
  if esaMode bld then numG (int64 (next ||| 0x80000000UL))
  else numG (int64 next)

/// A branch a condition-code mask decides, whose target the instruction names
/// relative to itself.
let branchRelative ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let m = oprMask o1
  let target = numG (int64 (codeAddr bld (relTarget ins.Address (oprImm o2))))
  bld <!-- (ins.Address, insLen)
  if isNever m then ()
  elif isAlways m then bld <+ AST.interjmp target InterJmpKind.Base
  else
    let next = fallThrough bld ins insLen
    bld <+ AST.intercjmp (condOfMask bld m) target next
  bld --!> insLen

/// A branch a mask decides, whose target is the address its base, index, and
/// displacement form -- not what is stored there.
let branchOnCondition ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let m = oprMask o1
  bld <!-- ((ins: Instruction).Address, insLen)
  if isNever m then ()
  else
    let target = transMem bld o2
    if isAlways m then bld <+ AST.interjmp target InterJmpKind.Base
    else
      let next = fallThrough bld ins insLen
      bld <+ AST.intercjmp (condOfMask bld m) target next
  bld --!> insLen

/// A branch a mask decides, to the address a register holds. A second operand
/// of R0 names no register and so never branches, which is how the assembler
/// spells a no-operation; a mask that takes every code and a second operand of
/// the link register is how a function returns.
let branchOnConditionReg ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let m = oprMask o1
  let r2 = oprReg o2
  bld <!-- ((ins: Instruction).Address, insLen)
  if isNever m || r2 = Register.R0 then ()
  else
    let target = maskAddr bld (reg bld r2)
    let kind =
      if r2 = Register.R14 then InterJmpKind.IsRet else InterJmpKind.Base
    if isAlways m then bld <+ AST.interjmp target kind
    else
      let next = fallThrough bld ins insLen
      bld <+ AST.intercjmp (condOfMask bld m) target next
  bld --!> insLen

/// BRANCH AND SAVE, in the relative form the compiler uses for every call: the
/// return address goes to the first operand and control to the target.
let branchAndSaveRel ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  let target = numG (int64 (codeAddr bld (relTarget ins.Address (oprImm o2))))
  bld <!-- (ins.Address, insLen)
  bld <+ (d := linkValue bld ins insLen)
  bld <+ AST.interjmp target InterJmpKind.IsCall
  bld --!> insLen

/// BRANCH AND SAVE to the address the second operand names.
let branchAndSave ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  let t = tmpVar bld GRSize
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (t := transMem bld o2)
  bld <+ (d := linkValue bld ins insLen)
  bld <+ AST.interjmp t InterJmpKind.IsCall
  bld --!> insLen

/// BRANCH AND SAVE to the address a register holds. As with a branch on
/// condition, a second operand of R0 saves the return address and goes nowhere.
let branchAndSaveReg ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  let r2 = oprReg o2
  let t = tmpVar bld GRSize
  bld <!-- ((ins: Instruction).Address, insLen)
  if r2 = Register.R0 then bld <+ (d := linkValue bld ins insLen)
  else
    bld <+ (t := maskAddr bld (reg bld r2))
    bld <+ (d := linkValue bld ins insLen)
    bld <+ AST.interjmp t InterJmpKind.IsCall
  bld --!> insLen

/// BRANCH ON COUNT, relative: the first operand counts down and control goes
/// to the target while the count has not reached zero.
let branchOnCountRel ins insLen bld rt =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  let target = numG (int64 (codeAddr bld (relTarget ins.Address (oprImm o2))))
  let t = tmpVar bld rt
  bld <!-- (ins.Address, insLen)
  bld <+ (t := srcReg rt d .- AST.num1 rt)
  bld <+ (dst rt d := t)
  bld <+ AST.intercjmp (t != AST.num0 rt) target (fallThrough bld ins insLen)
  bld --!> insLen

/// BRANCH ON COUNT, to the address the second operand names.
let branchOnCount ins insLen bld rt =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  let t = tmpVar bld rt
  let target = tmpVar bld GRSize
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (target := transMem bld o2)
  bld <+ (t := srcReg rt d .- AST.num1 rt)
  bld <+ (dst rt d := t)
  bld <+ AST.intercjmp (t != AST.num0 rt) target (fallThrough bld ins insLen)
  bld --!> insLen

/// BRANCH ON COUNT to a register's address, which counts down whether or not
/// the second operand names anywhere to go.
let branchOnCountReg ins insLen bld rt =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  let r2 = oprReg o2
  let t = tmpVar bld rt
  let target = tmpVar bld GRSize
  bld <!-- ((ins: Instruction).Address, insLen)
  if r2 = Register.R0 then
    bld <+ (t := srcReg rt d .- AST.num1 rt)
    bld <+ (dst rt d := t)
  else
    bld <+ (target := maskAddr bld (reg bld r2))
    bld <+ (t := srcReg rt d .- AST.num1 rt)
    bld <+ (dst rt d := t)
    bld <+ AST.intercjmp (t != AST.num0 rt) target (fallThrough bld ins insLen)
  bld --!> insLen

/// BRANCH ON INDEX: the first operand takes an increment from the third, and
/// the sum is compared against the third register's odd partner -- the third
/// register itself when it is already the odd one -- to decide the branch.
let branchOnIndexRel ins insLen bld rt high =
  let struct (o1, o2, o3) = getThreeOprs ins
  let d = oprRegVar bld o1
  let r3 = oprReg o3
  let cmp = if int r3 % 2 = 1 then r3 else pairOf r3
  let target = numG (int64 (codeAddr bld (relTarget ins.Address (oprImm o2))))
  let t = tmpVar bld rt
  let limit = tmpVar bld rt
  bld <!-- (ins.Address, insLen)
  bld <+ (limit := srcReg rt (reg bld cmp))
  bld <+ (t := srcReg rt d .+ srcReg rt (reg bld r3))
  bld <+ (dst rt d := t)
  let cond = if high then t ?> limit else t ?<= limit
  bld <+ AST.intercjmp cond target (fallThrough bld ins insLen)
  bld --!> insLen

/// BRANCH ON INDEX to the address the second operand names.
let branchOnIndex ins insLen bld rt high =
  let struct (o1, o2, o3) = getThreeOprs ins
  let d = oprRegVar bld o1
  let r3 = oprReg o3
  let cmp = if int r3 % 2 = 1 then r3 else pairOf r3
  let t = tmpVar bld rt
  let limit = tmpVar bld rt
  let target = tmpVar bld GRSize
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (target := transMem bld o2)
  bld <+ (limit := srcReg rt (reg bld cmp))
  bld <+ (t := srcReg rt d .+ srcReg rt (reg bld r3))
  bld <+ (dst rt d := t)
  let cond = if high then t ?> limit else t ?<= limit
  bld <+ AST.intercjmp cond target (fallThrough bld ins insLen)
  bld --!> insLen

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
let compareAndBranchRel ins insLen bld rt signed =
  let struct (o1, o2, o3, o4) = getFourOprs ins
  let m = oprMask o3
  let target = numG (int64 (codeAddr bld (relTarget ins.Address (oprImm o4))))
  bld <!-- (ins.Address, insLen)
  if m &&& 0xeus = 0us then ()
  else
    let a = srcReg rt (oprRegVar bld o1)
    let b =
      match o2 with
      | OpReg _ -> srcReg rt (oprRegVar bld o2)
      | _ -> numI64 (oprImm o2) rt
    if m &&& 0xeus = 0xeus then
      bld <+ AST.interjmp target InterJmpKind.Base
    else
      let cond = cmpCond m signed a b
      bld <+ AST.intercjmp cond target (fallThrough bld ins insLen)
  bld --!> insLen

/// COMPARE AND BRANCH to the address the last operand names.
let compareAndBranch ins insLen bld rt signed =
  let struct (o1, o2, o3, o4) = getFourOprs ins
  let m = oprMask o3
  bld <!-- ((ins: Instruction).Address, insLen)
  if m &&& 0xeus = 0us then ()
  else
    let target = transMem bld o4
    let a = srcReg rt (oprRegVar bld o1)
    let b =
      match o2 with
      | OpReg _ -> srcReg rt (oprRegVar bld o2)
      | _ -> numI64 (oprImm o2) rt
    if m &&& 0xeus = 0xeus then
      bld <+ AST.interjmp target InterJmpKind.Base
    else
      let cond = cmpCond m signed a b
      bld <+ AST.intercjmp cond target (fallThrough bld ins insLen)
  bld --!> insLen

/// COMPARE AND TRAP, which a compiler plants where a check must not be allowed
/// to fall through -- a division by zero, a bound a pointer must respect.
let compareAndTrap ins insLen bld rt signed =
  let struct (o1, o2, o3) = getThreeOprs ins
  let m = oprMask o3
  bld <!-- ((ins: Instruction).Address, insLen)
  if m &&& 0xeus = 0us then ()
  else
    let a = srcReg rt (oprRegVar bld o1)
    let b =
      match o2 with
      | OpReg _ -> srcReg rt (oprRegVar bld o2)
      | _ -> numI64 (oprImm o2) rt
    let trap = label bld "Trap"
    let out = label bld "NoTrap"
    bld <+ (AST.cjmp (cmpCond m signed a b)
                     (AST.jmpDest trap) (AST.jmpDest out))
    bld <+ (AST.lmark trap)
    bld <+ AST.sideEffect (Exception IntegerOverflow)
    bld <+ (AST.lmark out)
  bld --!> insLen

/// LOAD ON CONDITION, whose mask selects the condition codes it acts on. The
/// load is written as a select so the lifted block stays straight-line.
let loadOnCondition ins insLen bld rt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let d = oprRegVar bld o1
  let m = oprMask o3
  bld <!-- ((ins: Instruction).Address, insLen)
  if isNever m then ()
  else
    let v = srcOf bld rt o2
    let value = if isAlways m then v else AST.ite (condOfMask bld m) v
                                                  (srcReg rt d)
    bld <+ (dst rt d := value)
  bld --!> insLen

/// LOAD HALFWORD IMMEDIATE ON CONDITION, whose immediate is sign-extended to
/// the operation's width.
let loadImmOnCondition ins insLen bld rt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let d = oprRegVar bld o1
  let m = oprMask o3
  bld <!-- ((ins: Instruction).Address, insLen)
  if isNever m then ()
  else
    let v = numI64 (oprImm o2) rt
    let value = if isAlways m then v else AST.ite (condOfMask bld m) v
                                                  (srcReg rt d)
    bld <+ (dst rt d := value)
  bld --!> insLen

/// STORE ON CONDITION. Unlike the load, a store that must not happen cannot be
/// written as a select, so this one does branch.
let storeOnCondition ins insLen bld rt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let m = oprMask o3
  bld <!-- ((ins: Instruction).Address, insLen)
  if isNever m then ()
  elif isAlways m then
    bld <+ storeMem (transMem bld o2) (narrowTo rt (oprRegVar bld o1))
  else
    let doIt = label bld "StoreOnCond"
    let out = label bld "SkipStore"
    bld <+ (AST.cjmp (condOfMask bld m)
                     (AST.jmpDest doIt) (AST.jmpDest out))
    bld <+ (AST.lmark doIt)
    bld <+ storeMem (transMem bld o2) (narrowTo rt (oprRegVar bld o1))
    bld <+ (AST.lmark out)
  bld --!> insLen

/// The byte positions a four-bit mask selects, leftmost bit first, as offsets
/// into the field of storage the instruction reads or writes.
let private maskedBytes (m: Mask) =
  [| 0 .. 3 |] |> Array.filter (fun i -> m &&& (8us >>> i) <> 0us)

/// INSERT CHARACTERS UNDER MASK: the bytes the mask selects, taken from
/// consecutive bytes of storage, replace the matching bytes of one word of the
/// first operand -- its low one, or, for the "high" form, the other -- and the
/// condition code reports what was inserted.
let icm ins insLen bld half =
  let struct (o1, o2, o3) = getThreeOprs ins
  let d = oprRegVar bld o1
  let sel = maskedBytes (oprMask o3)
  let at k = (half: int) + 8 * (3 - sel[k])
  let addr = tmpVar bld GRSize
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (addr := transMem bld o2)
  let acc = tmpVar bld 8<rt>
  bld <+ (acc := AST.num0 8<rt>)
  for k in 0 .. sel.Length - 1 do
    let v = tmpVar bld 8<rt>
    bld <+ (v := loadMem 8<rt> (addr .+ numG (int64 k)))
    bld <+ (AST.extract d 8<rt> (at k) := v)
    bld <+ (acc := acc .| v)
  if sel.Length = 0 then setCC bld 0
  else
    let first = AST.extract d 8<rt> (at 0)
    let neg = AST.ite ((first .& numI32 0x80 8<rt>) == AST.num0 8<rt>)
                      (numCC 2) (numCC 1)
    bld <+ (ccVar bld := AST.ite (acc == AST.num0 8<rt>) (numCC 0) neg)
  bld --!> insLen

/// STORE CHARACTERS UNDER MASK: the mirror of INSERT, which writes only the
/// bytes the mask selects and touches no condition code.
let stcm ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let d = oprRegVar bld o1
  let sel = maskedBytes (oprMask o3)
  let addr = tmpVar bld GRSize
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (addr := transMem bld o2)
  for k in 0 .. sel.Length - 1 do
    let v = AST.extract d 8<rt> (8 * (3 - sel[k]))
    bld <+ storeMem (addr .+ numG (int64 k)) v
  bld --!> insLen

/// COMPARE LOGICAL CHARACTERS UNDER MASK.
let clm ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let d = oprRegVar bld o1
  let sel = maskedBytes (oprMask o3)
  let addr = tmpVar bld GRSize
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (addr := transMem bld o2)
  if sel.Length = 0 then setCC bld 0
  else
    let out = label bld "ClmOut"
    setCC bld 0
    for k in 0 .. sel.Length - 1 do
      let a = tmpVar bld 8<rt>
      let b = tmpVar bld 8<rt>
      let next = label bld $"ClmNext{k}"
      let diff = label bld $"ClmDiff{k}"
      bld <+ (a := AST.extract d 8<rt> (8 * (3 - sel[k])))
      bld <+ (b := loadMem 8<rt> (addr .+ numG (int64 k)))
      bld <+ (AST.cjmp (a == b) (AST.jmpDest next) (AST.jmpDest diff))
      bld <+ (AST.lmark diff)
      bld <+ (ccVar bld := AST.ite (a .< b) (numCC 1) (numCC 2))
      bld <+ (AST.jmp (AST.jmpDest out))
      bld <+ (AST.lmark next)
    bld <+ (AST.lmark out)
  bld --!> insLen

/// INSERT CHARACTER: a byte of storage replaces the lowest byte of the first
/// operand and leaves the rest of the register as it was.
let ic ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (AST.xtlo 8<rt> d := loadMem 8<rt> (transMem bld o2))
  bld --!> insLen

/// COMPARE AND SWAP, the primitive every lock in the guest is built from: the
/// first operand's value is replaced by what was found, and the third
/// operand's is stored only where the two matched.
let compareAndSwap ins insLen bld rt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let d = oprRegVar bld o1
  let addr = tmpVar bld GRSize
  let found = tmpVar bld rt
  let swap = label bld "CasSwap"
  let out = label bld "CasOut"
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ AST.sideEffect AtomicBegin
  bld <+ (addr := transMem bld o2)
  bld <+ (found := loadMem rt addr)
  bld <+ (AST.cjmp (found == srcReg rt d) (AST.jmpDest swap)
                   (AST.jmpDest out))
  bld <+ (AST.lmark swap)
  bld <+ storeMem addr (srcReg rt (oprRegVar bld o3))
  bld <+ (AST.lmark out)
  bld <+ (ccVar bld := AST.ite (found == srcReg rt d) (numCC 0) (numCC 1))
  bld <+ (dst rt d := found)
  bld <+ AST.sideEffect AtomicEnd
  bld --!> insLen

/// LOAD AND ADD and its bitwise relatives: the value found in storage goes to
/// the first operand and the combination of it with the third is stored back,
/// indivisibly.
let loadAndOp ins insLen bld rt f =
  let struct (o1, o2, o3) = getThreeOprs ins
  let d = oprRegVar bld o1
  let addr = tmpVar bld GRSize
  let found = tmpVar bld rt
  let t = tmpVar bld rt
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ AST.sideEffect AtomicBegin
  bld <+ (addr := transMem bld o2)
  bld <+ (found := loadMem rt addr)
  bld <+ (t := f found (srcReg rt (oprRegVar bld o3)))
  bld <+ storeMem addr t
  bld <+ AST.sideEffect AtomicEnd
  setCCSign bld t
  bld <+ (dst rt d := found)
  bld --!> insLen

/// The register a four-bit field of an executed instruction names. Which one
/// it is can only be known once the instruction is reached, so the choice is
/// made at run time rather than at lifting time; a field of zero names no
/// register and so contributes nothing to an address.
let private regOfField bld n =
  let rec pick i =
    if i = 15 then reg bld Register.R15
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
  bld <+ (hi := zextTo GRSize (loadMem 8<rt> (tgt .+ numG (int64 k))))
  bld <+ (lo := zextTo GRSize (loadMem 8<rt> (tgt .+ numG (int64 k + 1L))))
  let b = tmpVar bld GRSize
  bld <+ (b := hi >> numG 4L)
  regOfField bld b .+ (((hi .& numG 0xfL) << numG 8L) .| lo)

/// The loop TRANSLATE runs: each of the first operand's bytes is replaced by
/// the table byte it indexes.
let private emitTransLoop bld len d table =
  let i = tmpVar bld GRSize
  let body = label bld "TrBody"
  let out = label bld "TrOut"
  bld <+ (i := AST.num0 GRSize)
  bld <+ (AST.lmark body)
  let at = d .+ i
  bld <+ storeMem at (loadMem 8<rt> (table .+ zextTo GRSize (loadMem 8<rt> at)))
  bld <+ (i := i .+ AST.num1 GRSize)
  bld <+ (AST.cjmp (i == len) (AST.jmpDest out) (AST.jmpDest body))
  bld <+ (AST.lmark out)

/// The loop TRANSLATE AND TEST runs: the same indexing, but the first non-zero
/// table byte stops the scan and is reported instead of stored.
let private emitTransTestLoop bld len d table backwards =
  let i = tmpVar bld GRSize
  let fn = tmpVar bld 8<rt>
  let body = label bld "TrtBody"
  let step = label bld "TrtStep"
  let found = label bld "TrtFound"
  let out = label bld "TrtOut"
  bld <+ (i := AST.num0 GRSize)
  setCC bld 0
  bld <+ (AST.lmark body)
  let at = if backwards then d .- i else d .+ i
  bld <+ (fn := loadMem 8<rt> (table .+ zextTo GRSize (loadMem 8<rt> at)))
  bld <+ (AST.cjmp (fn == AST.num0 8<rt>)
                   (AST.jmpDest step) (AST.jmpDest found))
  bld <+ (AST.lmark step)
  bld <+ (i := i .+ AST.num1 GRSize)
  bld <+ (AST.cjmp (i == len) (AST.jmpDest out) (AST.jmpDest body))
  bld <+ (AST.lmark found)
  bld <+ (reg bld Register.R1 := at)
  bld <+ (AST.xtlo 8<rt> (reg bld Register.R2) := fn)
  bld <+ (ccVar bld := AST.ite (i == len .- AST.num1 GRSize)
                               (numCC 2) (numCC 1))
  bld <+ (AST.lmark out)

/// The half-byte move EXECUTE reaches through MOVE NUMERICS and MOVE ZONES,
/// which take one nibble of each byte from the source and leave the other as
/// it was.
let private halfByte keep take d s =
  (d .& numI32 keep 8<rt>) .| (s .& numI32 take 8<rt>)

/// EXECUTE: the instruction at the target address runs as if it stood here,
/// with its second byte -- the length, in every form a compiler uses this for
/// -- ORed with the rightmost byte of the first operand. That is how a program
/// gives a storage-to-storage operation a length it only knows at run time,
/// and it is why the target has to be read as data rather than lifted with the
/// code around it. A supervisor call is the one target that is not such an
/// operation: there the same byte is the call number, which is how a program
/// asks for a call it only names at run time.
let private executeAt ins insLen bld r1 target =
  let tgt = tmpVar bld GRSize
  let op = tmpVar bld 8<rt>
  let modified = tmpVar bld 8<rt>
  let len = tmpVar bld GRSize
  let a1 = tmpVar bld GRSize
  let a2 = tmpVar bld GRSize
  let lblOut = label bld "ExOut"
  bld <+ (tgt := target)
  bld <+ (op := loadMem 8<rt> tgt)
  let modifier =
    if (r1: Register) = Register.R0 then AST.num0 8<rt>
    else AST.xtlo 8<rt> (reg bld r1)
  bld <+ (modified := loadMem 8<rt> (tgt .+ AST.num1 GRSize) .| modifier)
  bld <+ (len := zextTo GRSize modified .+ AST.num1 GRSize)
  bld <+ (a1 := fieldAddress bld tgt 2)
  bld <+ (a2 := fieldAddress bld tgt 4)
  let arm code body =
    let hit = label bld "ExHit"
    let miss = label bld "ExMiss"
    bld <+ (AST.cjmp (op == numI32 code 8<rt>)
                     (AST.jmpDest hit) (AST.jmpDest miss))
    bld <+ (AST.lmark hit)
    body ()
    bld <+ (AST.jmp (AST.jmpDest lblOut))
    bld <+ (AST.lmark miss)
  arm 0x0a (fun () ->
    bld <+ (regVar bld Register.SVCCODE := modified)
    bld <+ AST.sideEffect SysCall)
  arm 0xd1 (fun () -> emitByteLoop bld len a1 a2 (halfByte 0xf0 0x0f))
  arm 0xd2 (fun () -> emitByteLoop bld len a1 a2 (fun _ s -> s))
  arm 0xd3 (fun () -> emitByteLoop bld len a1 a2 (halfByte 0x0f 0xf0))
  arm 0xd4 (fun () -> emitLogicLoop bld len a1 a2 (.&))
  arm 0xd5 (fun () -> emitCompareLoop bld len a1 a2)
  arm 0xd6 (fun () -> emitLogicLoop bld len a1 a2 (.|))
  arm 0xd7 (fun () -> emitLogicLoop bld len a1 a2 (<+>))
  arm 0xdc (fun () -> emitTransLoop bld len a1 a2)
  arm 0xdd (fun () -> emitTransTestLoop bld len a1 a2 false)
  bld <+ AST.sideEffect UnsupportedInstruction
  bld <+ (AST.lmark lblOut)

/// EXECUTE, whose target a base, index, and displacement name.
let execute ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  bld <!-- ((ins: Instruction).Address, insLen)
  executeAt ins insLen bld (oprReg o1) (transMem bld o2)
  bld --!> insLen

/// EXECUTE RELATIVE LONG, whose target the instruction names by its own
/// distance from it, which is the form position-independent code uses.
let executeRel ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let target = numG (int64 (codeAddr bld (relTarget ins.Address (oprImm o2))))
  bld <!-- (ins.Address, insLen)
  executeAt ins insLen bld (oprReg o1) target
  bld --!> insLen

/// The byte the string operations stop at, which R0's rightmost byte names.
let private terminator bld = AST.xtlo 8<rt> (reg bld Register.R0)

/// SEARCH STRING: the bytes from the second operand's address up to, but not
/// including, the first operand's are searched for the terminator. Finding it
/// puts its address in the first operand and reports 1; running out reports 2.
/// This is how the C library finds the end of a string without the vector
/// facility.
let srst ins insLen bld =
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
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (limit := d)
  bld <+ (p := s)
  bld <+ (AST.lmark body)
  bld <+ (AST.cjmp (p == limit) (AST.jmpDest none) (AST.jmpDest step))
  bld <+ (AST.lmark step)
  bld <+ (AST.cjmp (loadMem 8<rt> p == terminator bld)
                   (AST.jmpDest found) (AST.jmpDest cont))
  bld <+ (AST.lmark cont)
  bld <+ (p := p .+ AST.num1 GRSize)
  bld <+ (AST.jmp (AST.jmpDest body))
  bld <+ (AST.lmark found)
  bld <+ (d := p)
  setCC bld 1
  bld <+ (AST.jmp (AST.jmpDest out))
  bld <+ (AST.lmark none)
  bld <+ (s := limit)
  setCC bld 2
  bld <+ (AST.lmark out)
  bld --!> insLen

/// MOVE STRING: bytes go from the second operand's address to the first's
/// until the terminator has been moved, which then names where it landed.
let mvst ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  let s = oprRegVar bld o2
  let p = tmpVar bld GRSize
  let q = tmpVar bld GRSize
  let v = tmpVar bld 8<rt>
  let body = label bld "MvstBody"
  let out = label bld "MvstOut"
  let next = label bld "MvstNext"
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (p := d)
  bld <+ (q := s)
  bld <+ (AST.lmark body)
  bld <+ (v := loadMem 8<rt> q)
  bld <+ storeMem p v
  bld <+ (AST.cjmp (v == terminator bld) (AST.jmpDest out) (AST.jmpDest next))
  bld <+ (AST.lmark next)
  bld <+ (p := p .+ AST.num1 GRSize)
  bld <+ (q := q .+ AST.num1 GRSize)
  bld <+ (AST.jmp (AST.jmpDest body))
  bld <+ (AST.lmark out)
  bld <+ (d := p)
  setCC bld 1
  bld --!> insLen

/// COMPARE LOGICAL STRING: the two operands are compared byte by byte until
/// they differ or both reach the terminator, and the operands are left naming
/// the bytes that decided it.
let clst ins insLen bld =
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
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (p := d)
  bld <+ (q := s)
  setCC bld 0
  bld <+ (AST.lmark body)
  bld <+ (x := loadMem 8<rt> p)
  bld <+ (y := loadMem 8<rt> q)
  bld <+ (AST.cjmp (x == y) (AST.jmpDest same) (AST.jmpDest diff))
  bld <+ (AST.lmark same)
  bld <+ (AST.cjmp (x == terminator bld) (AST.jmpDest out)
                   (AST.jmpDest cont))
  bld <+ (AST.lmark cont)
  bld <+ (p := p .+ AST.num1 GRSize)
  bld <+ (q := q .+ AST.num1 GRSize)
  bld <+ (AST.jmp (AST.jmpDest body))
  bld <+ (AST.lmark diff)
  bld <+ (ccVar bld := AST.ite (x .< y) (numCC 1) (numCC 2))
  bld <+ (d := p)
  bld <+ (s := q)
  bld <+ (AST.lmark out)
  bld --!> insLen

/// EXTRACT CACHE ATTRIBUTE, whose answer describes a cache hierarchy this
/// emulator does not have: zero, which reads as "no such level".
let ecag ins insLen bld =
  let struct (o1, _, _) = getThreeOprs ins
  let d = oprRegVar bld o1
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (d := AST.num0 GRSize)
  bld --!> insLen

/// A storage-to-storage move of one nibble of each byte: the numerics are the
/// right-hand halves and the zones the left-hand ones, which is how decimal
/// code rearranges a field without disturbing its signs.
let ssNibble ins insLen bld numerics =
  let struct (o1, o2) = getTwoOprs ins
  let len = numG (int64 (lenOfMem o1))
  let d = tmpVar bld GRSize
  let s = tmpVar bld GRSize
  let keep = if numerics then 0xf0 else 0x0f
  let take = if numerics then 0x0f else 0xf0
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (d := transMem bld o1)
  bld <+ (s := transMem bld o2)
  emitByteLoop bld len d s (halfByte keep take)
  bld --!> insLen

/// MOVE INVERSE, which copies the second operand's bytes into the first in the
/// opposite order -- the second operand's address names its *rightmost* byte.
let moveInverse ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let len = lenOfMem o1
  let d = tmpVar bld GRSize
  let s = tmpVar bld GRSize
  let i = tmpVar bld GRSize
  let body = label bld "MvcinBody"
  let out = label bld "MvcinOut"
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (d := transMem bld o1)
  bld <+ (s := transMem bld o2)
  bld <+ (i := AST.num0 GRSize)
  bld <+ (AST.lmark body)
  bld <+ storeMem (d .+ i) (loadMem 8<rt> (s .- i))
  bld <+ (i := i .+ AST.num1 GRSize)
  bld <+ (AST.cjmp (i == numG (int64 len))
                   (AST.jmpDest out) (AST.jmpDest body))
  bld <+ (AST.lmark out)
  bld --!> insLen

/// MOVE RIGHT TO LEFT, which copies from the right-hand end so that operands
/// overlapping the other way round still come out whole. Its length comes from
/// R0 rather than the encoding, so it can be as long as 4096 bytes.
let moveRightToLeft ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let d = tmpVar bld GRSize
  let s = tmpVar bld GRSize
  let i = tmpVar bld GRSize
  let body = label bld "MvcrlBody"
  let out = label bld "MvcrlOut"
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (d := transMem bld o1)
  bld <+ (s := transMem bld o2)
  bld <+ (i := (zextTo GRSize (AST.xtlo 12<rt> (reg bld Register.R0))))
  bld <+ (AST.lmark body)
  bld <+ storeMem (d .+ i) (loadMem 8<rt> (s .+ i))
  bld <+ (AST.cjmp (i == AST.num0 GRSize)
                   (AST.jmpDest out) (AST.jmpDest body))
  bld <+ (i := i .- AST.num1 GRSize)
  bld <+ (AST.jmp (AST.jmpDest body))
  bld <+ (AST.lmark out)
  bld --!> insLen

/// MOVE WITH OFFSET, the decimal-support move: the second operand goes into
/// the first right-aligned and shifted one digit left, so that the first
/// operand's rightmost digit -- which holds the sign -- survives.
let moveWithOffset ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let n1 = lenOfMem o1
  let n2 = lenOfMem o2
  let d = tmpVar bld GRSize
  let s = tmpVar bld GRSize
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (d := transMem bld o1)
  bld <+ (s := transMem bld o2)
  let byteAt (from: Expr) k =
    if k < 0 then AST.num0 8<rt> else loadMem 8<rt> (from .+ numG (int64 k))
  (* Walking right to left keeps a byte's own old value available: each
     destination byte takes the low digit of one source byte and the high digit
     of the next one along. *)
  for k in 0 .. n1 - 1 do
    let dpos = n1 - 1 - k
    let lowDigit =
      if k = 0 then byteAt d dpos .& numI32 0x0f 8<rt>
      else (byteAt s (n2 - k) .& numI32 0xf0 8<rt>) >> numI32 4 8<rt>
    let highDigit =
      let src = n2 - 1 - k
      if src < 0 then AST.num0 8<rt>
      else (byteAt s src .& numI32 0x0f 8<rt>) << numI32 4 8<rt>
    bld <+ storeMem (d .+ numG (int64 dpos)) (highDigit .| lowDigit)
  bld --!> insLen

/// The pad byte a long move or compare supplies once its source runs out,
/// which the second-operand address's rightmost byte names.
let private padOf bld o = AST.xtlo 8<rt> (transMem bld o)

/// MOVE LONG EXTENDED: the first operand is filled from the second, and once
/// the second runs out the rest takes a pad byte. Both addresses and lengths
/// live in register pairs, which are left naming what has yet to be moved so
/// that a partial completion could be resumed -- this one always completes.
let moveLongExtended ins insLen bld unit =
  let struct (o1, o2, o3) = getThreeOprs ins
  let r1 = oprReg o1
  let r3 = oprReg o3
  if not (isPair r1 && isPair r3) then
    specException ins insLen bld
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
    bld <!-- ((ins: Instruction).Address, insLen)
    bld <+ (pad := AST.xtlo width (transMem bld o2))
    bld <+ (cmp := AST.ite (dl == sl) (numCC 0)
                           (AST.ite (dl .< sl) (numCC 1) (numCC 2)))
    bld <+ (AST.lmark body)
    bld <+ (AST.cjmp (dl == AST.num0 GRSize)
                     (AST.jmpDest out) (AST.jmpDest more))
    bld <+ (AST.lmark more)
    bld <+ (AST.cjmp (sl == AST.num0 GRSize)
                     (AST.jmpDest fill) (AST.jmpDest copy))
    bld <+ (AST.lmark copy)
    bld <+ storeMem da (loadMem width sa)
    bld <+ (sa := sa .+ step)
    bld <+ (sl := sl .- step)
    bld <+ (da := da .+ step)
    bld <+ (dl := dl .- step)
    bld <+ (AST.jmp (AST.jmpDest body))
    bld <+ (AST.lmark fill)
    bld <+ storeMem da pad
    bld <+ (da := da .+ step)
    bld <+ (dl := dl .- step)
    bld <+ (AST.jmp (AST.jmpDest body))
    bld <+ (AST.lmark out)
    bld <+ (ccVar bld := cmp)
    bld --!> insLen

/// COMPARE LOGICAL LONG EXTENDED: the two operands are compared over the
/// longer of their lengths, the shorter one padded out, and the registers are
/// left naming the units that decided it.
let compareLongExtended ins insLen bld unit =
  let struct (o1, o2, o3) = getThreeOprs ins
  let r1 = oprReg o1
  let r3 = oprReg o3
  if not (isPair r1 && isPair r3) then
    specException ins insLen bld
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
    bld <!-- ((ins: Instruction).Address, insLen)
    bld <+ (pad := AST.xtlo width (transMem bld o2))
    setCC bld 0
    bld <+ (AST.lmark body)
    bld <+ (AST.cjmp ((al == AST.num0 GRSize) .& (bl == AST.num0 GRSize))
                     (AST.jmpDest out) (AST.jmpDest more))
    bld <+ (AST.lmark more)
    bld <+ (x := AST.ite (al == AST.num0 GRSize) pad (loadMem width aa))
    bld <+ (y := AST.ite (bl == AST.num0 GRSize) pad (loadMem width ba))
    bld <+ (AST.cjmp (x == y) (AST.jmpDest same) (AST.jmpDest diff))
    bld <+ (AST.lmark same)
    bld <+ (aa := AST.ite (al == AST.num0 GRSize) aa (aa .+ step))
    bld <+ (al := AST.ite (al == AST.num0 GRSize) al (al .- step))
    bld <+ (ba := AST.ite (bl == AST.num0 GRSize) ba (ba .+ step))
    bld <+ (bl := AST.ite (bl == AST.num0 GRSize) bl (bl .- step))
    bld <+ (AST.jmp (AST.jmpDest body))
    bld <+ (AST.lmark diff)
    bld <+ (ccVar bld := AST.ite (x .< y) (numCC 1) (numCC 2))
    bld <+ (AST.lmark out)
    bld --!> insLen

/// MOVE LONG, the older form, whose lengths are the rightmost twenty-four bits
/// of the odd registers and whose pad byte travels in the source length
/// register. Operands that overlap so that the move would destroy what it has
/// yet to read leave the storage alone and report the fourth condition code.
let moveLong ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let r1 = oprReg o1
  let r2 = oprReg o2
  if not (isPair r1 && isPair r2) then
    specException ins insLen bld
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
    bld <!-- ((ins: Instruction).Address, insLen)
    bld <+ (dl := dlr .& numG 0xffffffL)
    bld <+ (sl := slr .& numG 0xffffffL)
    bld <+ (pad := AST.extract slr 8<rt> 24)
    bld <+ (cmp := AST.ite (dl == sl) (numCC 0)
                           (AST.ite (dl .< sl) (numCC 1) (numCC 2)))
    (* Destructive overlap: the destination begins inside the part of the source
       still to be read, so a byte-at-a-time move would read what it had already
       written. *)
    bld <+ (AST.cjmp ((da .> sa) .& (da .< (sa .+ sl)))
                     (AST.jmpDest overlap) (AST.jmpDest body))
    bld <+ (AST.lmark body)
    bld <+ (AST.cjmp (dl == AST.num0 GRSize)
                     (AST.jmpDest over) (AST.jmpDest more))
    bld <+ (AST.lmark more)
    bld <+ (AST.cjmp (sl == AST.num0 GRSize)
                     (AST.jmpDest fill) (AST.jmpDest copy))
    bld <+ (AST.lmark copy)
    bld <+ storeMem da (loadMem 8<rt> sa)
    bld <+ (sa := sa .+ AST.num1 GRSize)
    bld <+ (sl := sl .- AST.num1 GRSize)
    bld <+ (da := da .+ AST.num1 GRSize)
    bld <+ (dl := dl .- AST.num1 GRSize)
    bld <+ (AST.jmp (AST.jmpDest body))
    bld <+ (AST.lmark fill)
    bld <+ storeMem da pad
    bld <+ (da := da .+ AST.num1 GRSize)
    bld <+ (dl := dl .- AST.num1 GRSize)
    bld <+ (AST.jmp (AST.jmpDest body))
    bld <+ (AST.lmark over)
    bld <+ (dlr := (dlr .& numG ~~~0xffffffL) .| dl)
    bld <+ (slr := (slr .& numG ~~~0xffffffL) .| sl)
    bld <+ (ccVar bld := cmp)
    bld <+ (AST.jmp (AST.jmpDest out))
    bld <+ (AST.lmark overlap)
    setCC bld 3
    bld <+ (AST.lmark out)
    bld --!> insLen

/// COMPARE LOGICAL LONG, the older form of the padded comparison, whose
/// lengths and pad byte sit in the odd registers as MOVE LONG's do.
let compareLong ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let r1 = oprReg o1
  let r2 = oprReg o2
  if not (isPair r1 && isPair r2) then
    specException ins insLen bld
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
    bld <!-- ((ins: Instruction).Address, insLen)
    bld <+ (al := alr .& numG 0xffffffL)
    bld <+ (bl := blr .& numG 0xffffffL)
    bld <+ (pad := AST.extract blr 8<rt> 24)
    setCC bld 0
    bld <+ (AST.lmark body)
    bld <+ (AST.cjmp ((al == AST.num0 GRSize) .& (bl == AST.num0 GRSize))
                     (AST.jmpDest out) (AST.jmpDest more))
    bld <+ (AST.lmark more)
    bld <+ (x := AST.ite (al == AST.num0 GRSize) pad (loadMem 8<rt> aa))
    bld <+ (y := AST.ite (bl == AST.num0 GRSize) pad (loadMem 8<rt> ba))
    bld <+ (AST.cjmp (x == y) (AST.jmpDest same) (AST.jmpDest diff))
    bld <+ (AST.lmark same)
    bld <+ (aa := AST.ite (al == AST.num0 GRSize) aa (aa .+ AST.num1 GRSize))
    bld <+ (al := AST.ite (al == AST.num0 GRSize) al (al .- AST.num1 GRSize))
    bld <+ (ba := AST.ite (bl == AST.num0 GRSize) ba (ba .+ AST.num1 GRSize))
    bld <+ (bl := AST.ite (bl == AST.num0 GRSize) bl (bl .- AST.num1 GRSize))
    bld <+ (AST.jmp (AST.jmpDest body))
    bld <+ (AST.lmark diff)
    bld <+ (ccVar bld := AST.ite (x .< y) (numCC 1) (numCC 2))
    bld <+ (AST.lmark out)
    bld <+ (alr := (alr .& numG ~~~0xffffffL) .| al)
    bld <+ (blr := (blr .& numG ~~~0xffffffL) .| bl)
    bld --!> insLen

/// TEST AND SET, the oldest of the architecture's atomic primitives: the
/// leftmost bit of a byte decides the condition code and the whole byte is then
/// set to ones.
let testAndSet ins insLen bld =
  let o = getOneOpr ins
  let addr = tmpVar bld GRSize
  let v = tmpVar bld 8<rt>
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ AST.sideEffect AtomicBegin
  bld <+ (addr := transMem bld o)
  bld <+ (v := loadMem 8<rt> addr)
  bld <+ storeMem addr (numI32 0xff 8<rt>)
  bld <+ AST.sideEffect AtomicEnd
  bld <+ (ccVar bld := AST.ite ((v .& numI32 0x80 8<rt>) == AST.num0 8<rt>)
                               (numCC 0) (numCC 1))
  bld --!> insLen

/// TRANSLATE: each byte of the first operand is replaced by the byte the table
/// the second operand names holds at that byte's own value.
let translate ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let d = tmpVar bld GRSize
  let table = tmpVar bld GRSize
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (d := transMem bld o1)
  bld <+ (table := transMem bld o2)
  emitTransLoop bld (numG (int64 (lenOfMem o1))) d table
  bld --!> insLen

/// TRANSLATE AND TEST: the first operand's bytes index the same kind of table,
/// but nothing is written -- the first non-zero entry stops the scan, naming
/// the byte it came from in R1 and itself in R2. It is how a program finds the
/// first byte of a field that belongs to a given class.
let translateAndTest ins insLen bld backwards =
  let struct (o1, o2) = getTwoOprs ins
  let d = tmpVar bld GRSize
  let table = tmpVar bld GRSize
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (d := transMem bld o1)
  bld <+ (table := transMem bld o2)
  emitTransTestLoop bld (numG (int64 (lenOfMem o1))) d table backwards
  bld --!> insLen

/// ADD LOGICAL WITH SIGNED IMMEDIATE to storage. The immediate field is a
/// signed byte, which the parser hands over as the unsigned bits it holds, so
/// the sign is put back here before the addition.
let addLogicalToStorage ins insLen bld rt =
  let struct (o1, o2) = getTwoOprs ins
  let addr = tmpVar bld GRSize
  let a = tmpVar bld rt
  let t = tmpVar bld rt
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (addr := transMem bld o1)
  bld <+ (a := loadMem rt addr)
  let b = numI64 (int64 (sbyte (oprImm o2))) rt
  bld <+ (t := a .+ b)
  setCCAddLogical bld t (t .< a)
  bld <+ storeMem addr t
  bld --!> insLen

/// PERFORM TIMING FACILITY FUNCTION, whose third condition code says the
/// function asked for is not available -- which is the honest answer from a
/// machine with no timing facility to query.
let ptff ins insLen bld =
  bld <!-- ((ins: Instruction).Address, insLen)
  setCC bld 3
  bld --!> insLen

/// MULTIPLY, whose product is twice as wide as its operands and so fills a
/// register pair: the even register takes the high half, the odd one the low,
/// and it is the odd one that supplied the multiplicand.
let mulPair ins insLen bld (rt: RegType) accW =
  let struct (o1, o2) = getTwoOprs ins
  let r1 = oprReg o1
  if not (isPair r1) then
    specException ins insLen bld
  else
    let hi = reg bld r1
    let lo = reg bld (pairOf r1)
    let wide = rt * 2
    let t = tmpVar bld wide
    bld <!-- ((ins: Instruction).Address, insLen)
    let b = AST.sext wide (srcOf bld accW o2)
    bld <+ (t := AST.sext wide (srcReg rt lo) .* b)
    bld <+ (dst rt hi := AST.xthi rt t)
    bld <+ (dst rt lo := AST.xtlo rt t)
    bld --!> insLen

/// The three-operand form of the double-width multiply, which names both
/// factors and so leaves them alone.
let mulPair3 ins insLen bld (rt: RegType) =
  let struct (o1, o2, o3) = getThreeOprs ins
  let r1 = oprReg o1
  if not (isPair r1) then
    specException ins insLen bld
  else
    let hi = reg bld r1
    let lo = reg bld (pairOf r1)
    let wide = rt * 2
    let t = tmpVar bld wide
    bld <!-- ((ins: Instruction).Address, insLen)
    let a = AST.sext wide (srcOf bld rt o2)
    let b = AST.sext wide (srcOf bld rt o3)
    bld <+ (t := a .* b)
    bld <+ (dst rt hi := AST.xthi rt t)
    bld <+ (dst rt lo := AST.xtlo rt t)
    bld --!> insLen

/// MULTIPLY SINGLE with a condition code, which reports whether the product
/// left the range its width can hold.
let mulCC ins insLen bld (rt: RegType) accW ext =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  let wide = rt * 2
  let t = tmpVar bld wide
  let r = tmpVar bld rt
  bld <!-- ((ins: Instruction).Address, insLen)
  let b = AST.sext wide (ext rt (srcOf bld accW o2))
  bld <+ (t := AST.sext wide (srcReg rt d) .* b)
  bld <+ (r := AST.xtlo rt t)
  let fits = AST.sext wide r == t
  bld <+ (ccVar bld := AST.ite fits (AST.ite (r == AST.num0 rt) (numCC 0)
                                             (AST.ite (r ?< AST.num0 rt)
                                                      (numCC 1) (numCC 2)))
                               (numCC 3))
  bld <+ (dst rt d := r)
  bld --!> insLen

/// DIVIDE, whose dividend spans a register pair: the quotient replaces the odd
/// register and the remainder the even one.
let divPair ins insLen bld (rt: RegType) accW =
  let struct (o1, o2) = getTwoOprs ins
  let r1 = oprReg o1
  if not (isPair r1) then
    specException ins insLen bld
  else
    let hi = reg bld r1
    let lo = reg bld (pairOf r1)
    let wide = rt * 2
    let num = tmpVar bld wide
    let den = tmpVar bld wide
    let q = tmpVar bld wide
    let r = tmpVar bld wide
    bld <!-- ((ins: Instruction).Address, insLen)
    bld <+ (den := AST.sext wide (srcOf bld accW o2))
    bld <+ (num := AST.concat (srcReg rt hi) (srcReg rt lo))
    bld <+ (q := num ?/ den)
    bld <+ (r := num ?% den)
    bld <+ (dst rt hi := AST.xtlo rt r)
    bld <+ (dst rt lo := AST.xtlo rt q)
    bld --!> insLen

/// The double shifts, which work on the 64-bit value a register pair's two low
/// words make up. The arithmetic ones report the sign of what they produced.
let shiftDouble ins insLen bld f setsCC =
  let struct (o1, o2) = getTwoOprs ins
  let r1 = oprReg o1
  if not (isPair r1) then
    specException ins insLen bld
  else
    let hi = reg bld r1
    let lo = reg bld (pairOf r1)
    let t = tmpVar bld GRSize
    bld <!-- ((ins: Instruction).Address, insLen)
    let value = AST.concat (low hi) (low lo)
    bld <+ (t := f value (transMem bld o2 .& numG 63L))
    if setsCC then setCCSign bld t else ()
    bld <+ (low hi := AST.xthi WSize t)
    bld <+ (low lo := AST.xtlo WSize t)
    bld --!> insLen

/// COMPARE DOUBLE AND SWAP, the pair-wide form of the atomic exchange: the
/// comparand and the replacement each span two registers, so a program can
/// swap a pointer and its counter together.
let compareDoubleAndSwap ins insLen bld (rt: RegType) =
  let struct (o1, o2, o3) = getThreeOprs ins
  let r1 = oprReg o1
  let r3 = oprReg o3
  if not (isPair r1 && isPair r3) then
    specException ins insLen bld
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
    bld <!-- ((ins: Instruction).Address, insLen)
    bld <+ AST.sideEffect AtomicBegin
    bld <+ (addr := transMem bld o2)
    bld <+ (found := loadMem wide addr)
    bld <+ (want := AST.concat (srcReg rt ahi) (srcReg rt alo))
    bld <+ (AST.cjmp (found == want) (AST.jmpDest swap) (AST.jmpDest out))
    bld <+ (AST.lmark swap)
    bld <+ storeMem addr (AST.concat (srcReg rt bhi) (srcReg rt blo))
    bld <+ (AST.lmark out)
    bld <+ (ccVar bld := AST.ite (found == want) (numCC 0) (numCC 1))
    bld <+ (dst rt ahi := AST.xthi rt found)
    bld <+ (dst rt alo := AST.xtlo rt found)
    bld <+ AST.sideEffect AtomicEnd
    bld --!> insLen

/// LOAD PAIR DISJOINT, which fetches two words or doublewords from unrelated
/// places and reports whether it managed to do so as one indivisible access.
/// One thread at a time means it always does.
let loadPairDisjoint ins insLen bld rt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let r3 = oprReg o3
  if not (isPair r3) then
    specException ins insLen bld
  else
    bld <!-- ((ins: Instruction).Address, insLen)
    bld <+ AST.sideEffect AtomicBegin
    bld <+ (dst rt (reg bld r3) := loadMem rt (transMem bld o1))
    bld <+ (dst rt (reg bld (pairOf r3)) := loadMem rt (transMem bld o2))
    bld <+ AST.sideEffect AtomicEnd
    setCC bld 0
    bld --!> insLen

/// LOAD PAIR FROM QUADWORD and its mirror, the sixteen-byte accesses a program
/// uses when it needs two doublewords to move together.
let quadPair ins insLen bld isLoad =
  let struct (o1, o2) = getTwoOprs ins
  let r1 = oprReg o1
  if not (isPair r1) then
    specException ins insLen bld
  else
    let hi = reg bld r1
    let lo = reg bld (pairOf r1)
    let addr = tmpVar bld GRSize
    bld <!-- ((ins: Instruction).Address, insLen)
    bld <+ AST.sideEffect AtomicBegin
    bld <+ (addr := transMem bld o2)
    if isLoad then
      let v = tmpVar bld 128<rt>
      bld <+ (v := loadMem 128<rt> addr)
      bld <+ (hi := AST.xthi GRSize v)
      bld <+ (lo := AST.xtlo GRSize v)
    else
      bld <+ storeMem addr (AST.concat hi lo)
    bld <+ AST.sideEffect AtomicEnd
    bld --!> insLen

/// A load that traps on a zero result, which a compiler plants where a null
/// pointer must not be allowed to travel any further.
let loadAndTrap ins insLen bld rt accW ext =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  let t = tmpVar bld rt
  let trap = label bld "LatTrap"
  let out = label bld "LatOut"
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (t := ext rt (srcOf bld accW o2))
  bld <+ (AST.cjmp (t == AST.num0 rt) (AST.jmpDest trap) (AST.jmpDest out))
  bld <+ (AST.lmark trap)
  bld <+ AST.sideEffect (Exception IntegerOverflow)
  bld <+ (AST.lmark out)
  bld <+ (dst rt d := t)
  bld --!> insLen

/// A load that clears the value's rightmost byte, which is how a pointer that
/// carries tag bits there is stripped as it is loaded.
let loadZeroRightmost ins insLen bld rt accW ext =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  bld <!-- ((ins: Instruction).Address, insLen)
  let v = ext rt (srcOf bld accW o2)
  bld <+ (dst rt d := v .& numI64 -256L rt)
  bld --!> insLen

/// LOAD ADDRESS EXTENDED, which is LOAD ADDRESS with an access register set
/// alongside. A program in the primary-space mode -- the only mode Linux runs
/// its processes in -- gets zero there.
let loadAddressExtended ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let r1 = oprReg o1
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (reg bld r1 := transMem bld o2)
  bld <+ (reg bld (enum<Register> (int Register.AR0 + int r1))
          := AST.num0 WSize)
  bld --!> insLen

/// The access registers a load- or store-multiple-access walks, wrapping
/// around AR15 to AR0 as the general registers do.
let private accessRange (a1: Register) (a3: Register) =
  let first = int a1 - int Register.AR0
  let count = ((int a3 - int a1) &&& 0xf) + 1
  [| for i in 0 .. count - 1 ->
       enum<Register> (int Register.AR0 + ((first + i) &&& 0xf)) |]

/// LOAD or STORE ACCESS MULTIPLE: consecutive access registers take, or fill,
/// consecutive words of storage.
let accessMultiple ins insLen bld isLoad =
  let struct (o1, o2, o3) = getThreeOprs ins
  let regs = accessRange (oprReg o1) (oprReg o3)
  let addr = tmpVar bld GRSize
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (addr := transMem bld o2)
  for i in 0 .. regs.Length - 1 do
    let at = addr .+ numG (int64 i * 4L)
    if isLoad then bld <+ (reg bld regs[i] := loadMem WSize at)
    else bld <+ storeMem at (reg bld regs[i])
  bld --!> insLen

/// COPY ACCESS, a move between two access registers.
let copyAccess ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (oprRegVar bld o1 := oprRegVar bld o2)
  bld --!> insLen

/// TEST ACCESS, which asks what an access-list entry token names. Every token
/// a Linux process holds is the primary one, which is what a zero condition
/// code says.
let testAccess ins insLen bld =
  bld <!-- ((ins: Instruction).Address, insLen)
  setCC bld 0
  bld --!> insLen

/// TEST ADDRESSING MODE, whose condition code names the mode a program is
/// running in: none for 24-bit addressing, the first for 31-bit, the third for
/// 64-bit.
let testAddressingMode ins insLen bld =
  bld <!-- ((ins: Instruction).Address, insLen)
  setCC bld (if esaMode bld then 1 else 3)
  bld --!> insLen

/// CHECKSUM, which adds the second operand's words into the first with the
/// carries folded back in -- the ones' complement sum a network header needs.
let checksum ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let r2 = oprReg o2
  if not (isPair r2) then
    specException ins insLen bld
  else
    let acc = oprRegVar bld o1
    let addr = reg bld r2
    let len = reg bld (pairOf r2)
    let sum = tmpVar bld GRSize
    let body = label bld "CksmBody"
    let more = label bld "CksmMore"
    let out = label bld "CksmOut"
    bld <!-- ((ins: Instruction).Address, insLen)
    bld <+ (sum := zextTo GRSize (low acc))
    bld <+ (AST.lmark body)
    bld <+ (AST.cjmp (len .< numG 4L) (AST.jmpDest out) (AST.jmpDest more))
    bld <+ (AST.lmark more)
    bld <+ (sum := sum .+ zextTo GRSize (loadMem WSize addr))
    bld <+ (addr := addr .+ numG 4L)
    bld <+ (len := len .- numG 4L)
    bld <+ (AST.jmp (AST.jmpDest body))
    bld <+ (AST.lmark out)
    (* Fold the carries out of the word back into it, twice, so that a carry the
       first fold produces is itself folded in. *)
    bld <+ (sum := (sum .& numG 0xffffffffL) .+ (sum >> numG 32L))
    bld <+ (sum := (sum .& numG 0xffffffffL) .+ (sum >> numG 32L))
    bld <+ (low acc := AST.xtlo WSize sum)
    setCC bld 0
    bld --!> insLen

/// COMPARE LOGICAL AND TRAP, which compares a register against storage and
/// takes the trap when the mask names the code the comparison produced.
let compareTrapStorage ins insLen bld rt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let m = oprMask o3
  bld <!-- ((ins: Instruction).Address, insLen)
  if m &&& 0xeus = 0us then ()
  else
    let a = tmpVar bld rt
    let b = tmpVar bld rt
    bld <+ (a := srcReg rt (oprRegVar bld o1))
    bld <+ (b := loadMem rt (transMem bld o2))
    let trap = label bld "CltTrap"
    let out = label bld "CltOut"
    let eq = if m &&& 8us <> 0us then [ a == b ] else []
    let lo = if m &&& 4us <> 0us then [ a .< b ] else []
    let hi = if m &&& 2us <> 0us then [ a .> b ] else []
    let cond = List.reduce (.|) (eq @ lo @ hi)
    bld <+ (AST.cjmp cond (AST.jmpDest trap) (AST.jmpDest out))
    bld <+ (AST.lmark trap)
    bld <+ AST.sideEffect (Exception IntegerOverflow)
    bld <+ (AST.lmark out)
  bld --!> insLen

/// BRANCH INDIRECT ON CONDITION, which takes its target from storage rather
/// than from a register -- a jump through a table without a register to spare.
let branchIndirect ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let m = oprMask o1
  bld <!-- ((ins: Instruction).Address, insLen)
  if isNever m then ()
  else
    let target = tmpVar bld GRSize
    bld <+ (target := loadMem GRSize (transMem bld o2))
    if isAlways m then bld <+ AST.interjmp target InterJmpKind.Base
    else
      let next = numG (int64 (codeAddr bld (nextAddr ins.Address insLen)))
      bld <+ AST.intercjmp (condOfMask bld m) target next
  bld --!> insLen

/// MOVE PAGE, which copies a whole 4096-byte page.
let movePage ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let d = tmpVar bld GRSize
  let s = tmpVar bld GRSize
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (d := oprRegVar bld o1 .& numG -4096L)
  bld <+ (s := oprRegVar bld o2 .& numG -4096L)
  emitByteLoop bld (numG 4096L) d s (fun _ sv -> sv)
  setCC bld 0
  bld --!> insLen

/// SEARCH STRING UNICODE, the halfword-at-a-time form of the string search.
let searchStringUnicode ins insLen bld =
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
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (limit := d)
  bld <+ (p := s)
  bld <+ (AST.lmark body)
  bld <+ (AST.cjmp (p .>= limit) (AST.jmpDest none) (AST.jmpDest step))
  bld <+ (AST.lmark step)
  bld <+ (AST.cjmp (loadMem 16<rt> p == AST.xtlo 16<rt> (reg bld Register.R0))
                   (AST.jmpDest found) (AST.jmpDest cont))
  bld <+ (AST.lmark cont)
  bld <+ (p := p .+ numG 2L)
  bld <+ (AST.jmp (AST.jmpDest body))
  bld <+ (AST.lmark found)
  bld <+ (d := p)
  setCC bld 1
  bld <+ (AST.jmp (AST.jmpDest out))
  bld <+ (AST.lmark none)
  bld <+ (s := limit)
  setCC bld 2
  bld <+ (AST.lmark out)
  bld --!> insLen

/// TRANSLATE EXTENDED, which translates through a table until it meets the
/// byte R0 names -- the length lives in a register, so the field can be longer
/// than an encoded length could say.
let translateExtended ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let r1 = oprReg o1
  if not (isPair r1) then
    specException ins insLen bld
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
    bld <!-- ((ins: Instruction).Address, insLen)
    setCC bld 0
    bld <+ (AST.lmark body)
    bld <+ (AST.cjmp (len == AST.num0 GRSize)
                     (AST.jmpDest out) (AST.jmpDest more))
    bld <+ (AST.lmark more)
    bld <+ (v := loadMem 8<rt> addr)
    bld <+ (AST.cjmp (v == AST.xtlo 8<rt> (reg bld Register.R0))
                     (AST.jmpDest found) (AST.jmpDest step))
    bld <+ (AST.lmark step)
    bld <+ storeMem addr (loadMem 8<rt> (table .+ zextTo GRSize v))
    bld <+ (addr := addr .+ AST.num1 GRSize)
    bld <+ (len := len .- AST.num1 GRSize)
    bld <+ (AST.jmp (AST.jmpDest body))
    bld <+ (AST.lmark found)
    setCC bld 1
    bld <+ (AST.lmark out)
    bld --!> insLen

/// The translate-and-test instructions that work in units wider than a byte:
/// the second operand's units index a table whose entries are the first
/// operand's units, and a unit equal to the one R0 names stops the operation
/// before it is stored. The mask's rightmost bit turns that test off.
let translateUnits ins insLen bld srcW dstW =
  let struct (o1, o2, o3) = getThreeOprs ins
  let r1 = oprReg o1
  if not (isPair r1) then
    specException ins insLen bld
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
    bld <!-- ((ins: Instruction).Address, insLen)
    setCC bld 0
    bld <+ (AST.lmark body)
    bld <+ (AST.cjmp (len .< srcStep) (AST.jmpDest out) (AST.jmpDest more))
    bld <+ (AST.lmark more)
    let index = zextTo GRSize (loadMem srcW sa) .* scale
    bld <+ (v := loadMem dstW (table .+ index))
    if noTest then bld <+ (AST.jmp (AST.jmpDest step))
    else
      bld <+ (AST.cjmp (v == narrowTo dstW (reg bld Register.R0))
                       (AST.jmpDest found) (AST.jmpDest step))
    bld <+ (AST.lmark step)
    bld <+ storeMem da v
    bld <+ (da := da .+ dstStep)
    bld <+ (sa := sa .+ srcStep)
    bld <+ (len := len .- srcStep)
    bld <+ (AST.jmp (AST.jmpDest body))
    bld <+ (AST.lmark found)
    setCC bld 1
    bld <+ (AST.lmark out)
    bld --!> insLen

/// TRANSLATE AND TEST EXTENDED: the argument characters index a table of
/// function codes, and the first non-zero code stops the scan, naming the
/// argument it came from and itself in the registers the older TRANSLATE AND
/// TEST uses. The mask says how wide the arguments and the codes are.
let translateTestExtended ins insLen bld backwards =
  let struct (o1, o2, o3) = getThreeOprs ins
  let r1 = oprReg o1
  if not (isPair r1) then
    specException ins insLen bld
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
    bld <!-- ((ins: Instruction).Address, insLen)
    setCC bld 0
    bld <+ (AST.lmark body)
    bld <+ (AST.cjmp (len .< argStep) (AST.jmpDest out) (AST.jmpDest more))
    bld <+ (AST.lmark more)
    let index = zextTo GRSize (loadMem argW addr) .* scale
    bld <+ (fn := loadMem fnW (table .+ index))
    bld <+ (AST.cjmp (fn == AST.num0 fnW)
                     (AST.jmpDest step) (AST.jmpDest found))
    bld <+ (AST.lmark step)
    if backwards then bld <+ (addr := addr .- argStep)
    else bld <+ (addr := addr .+ argStep)
    bld <+ (len := len .- argStep)
    bld <+ (AST.jmp (AST.jmpDest body))
    bld <+ (AST.lmark found)
    bld <+ (narrowTo fnW (reg bld Register.R1) := fn)
    setCC bld 1
    bld <+ (AST.lmark out)
    bld --!> insLen

/// TRANSACTION END, which ends nothing here because no transaction ever
/// begins; outside one it reports 0 as the architecture says.
let tend ins insLen bld =
  bld <!-- ((ins: Instruction).Address, insLen)
  setCC bld 0
  bld --!> insLen

/// INSERT PROGRAM MASK: the condition code and the program mask are laid into
/// one byte of the first operand, which is how a program reads the code it
/// cannot otherwise see. The program mask is zero throughout, since nothing
/// here enables the interruptions it would unmask.
let ipm ins insLen bld =
  let d = oprRegVar bld (getOneOpr ins)
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (AST.extract d 8<rt> 24 := ccVar bld << numCC 4)
  bld --!> insLen

/// SET PROGRAM MASK, which takes the condition code back out of that byte.
let spm ins insLen bld =
  let d = oprRegVar bld (getOneOpr ins)
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (ccVar bld := (AST.extract d 8<rt> 28) .& numCC 3)
  bld --!> insLen

/// EXTRACT ACCESS: the access register a thread's own storage is reached
/// through, which is where the s390 ABI keeps the thread pointer.
let ear ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (low d := oprRegVar bld o2)
  bld --!> insLen

/// SET ACCESS, the write that matches EXTRACT ACCESS.
let sar ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (d := low (oprRegVar bld o2))
  bld --!> insLen

/// A copy between a floating-point and a general register, which compilers use
/// to park a value without touching storage.
let regCopy ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (oprRegVar bld o1 := oprRegVar bld o2)
  bld --!> insLen

/// SUPERVISOR CALL. The immediate names the call whenever it is not zero; a
/// zero one means the number is in R1 instead, so it is handed on as it stands
/// and the kernel reads whichever applies.
let svc ins insLen bld =
  let imm = oprImm (getOneOpr ins)
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (regVar bld Register.SVCCODE := numI64 imm 8<rt>)
  bld <+ AST.sideEffect SysCall
  bld --!> insLen

/// EXTRACT PSW, which hands a program the program-status word it otherwise
/// cannot see. Only the condition code of it is modelled, and it sits where the
/// word carries it; the rest reads as zero, as do the bits no supervisor here
/// ever sets.
let extractPsw ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let r1 = oprReg o1
  let r2 = oprReg o2
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (low (reg bld r1) := zextTo WSize (ccVar bld) << numW 12L)
  if r2 <> Register.R0 then bld <+ (low (reg bld r2) := AST.num0 WSize)
  else ()
  bld --!> insLen

/// LOAD COUNT TO BLOCK BOUNDARY, which says how many of the sixteen bytes a
/// vector load would want lie before the boundary the mask names. The third
/// condition code means all sixteen do.
let loadCountToBoundary ins insLen bld =
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
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (room := numG bound .- (transMem bld o2 .& numG (bound - 1L)))
  bld <+ (room := AST.ite (room .> numG 16L) (numG 16L) room)
  bld <+ (low d := AST.xtlo WSize room)
  bld <+ (ccVar bld := AST.ite (room == numG 16L) (numCC 0) (numCC 3))
  bld --!> insLen

/// STORE CLOCK EXTENDED, whose sixteen bytes are the clock this emulator does
/// not keep, so they read as zero -- as the plain STORE CLOCK's eight do.
let storeClockExtended ins insLen bld =
  let o = getOneOpr ins
  let addr = tmpVar bld GRSize
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (addr := transMem bld o)
  bld <+ storeMem addr (AST.num0 GRSize)
  bld <+ storeMem (addr .+ numG 8L) (AST.num0 GRSize)
  setCC bld 0
  bld --!> insLen

/// LOAD MULTIPLE DISJOINT, which fills a range of registers from two places at
/// once: the high halves come from one and the low halves from the other.
let loadMultipleDisjoint (ins: Instruction) insLen bld =
  match ins.Operands with
  | FourOperands(o1, o2, o3, o4) ->
    let regs = regRange (oprReg o1) (oprReg o3)
    let hi = tmpVar bld GRSize
    let lo = tmpVar bld GRSize
    bld <!-- ((ins: Instruction).Address, insLen)
    bld <+ (hi := transMem bld o2)
    bld <+ (lo := transMem bld o4)
    for i in 0 .. regs.Length - 1 do
      let at k = numG (int64 i * 4L) .+ k
      bld <+ (high (reg bld regs[i]) := loadMem WSize (at hi))
      bld <+ (low (reg bld regs[i]) := loadMem WSize (at lo))
    bld --!> insLen
  | _ -> raise InvalidOperandException

/// COMPARE UNTIL SUBSTRING EQUAL, which looks for the first place the two
/// operands agree over a whole substring, whose length R0 gives.
let compareUntilEqual ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let r1 = oprReg o1
  let r2 = oprReg o2
  if not (isPair r1 && isPair r2) then
    specException ins insLen bld
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
    bld <!-- ((ins: Instruction).Address, insLen)
    bld <+ (n := reg bld Register.R0 .& numG 0xffffffL)
    setCC bld 2
    bld <+ (AST.lmark body)
    (* Neither operand may run out before the substring could fit. *)
    bld <+ (AST.cjmp ((al .< n) .| (bl .< n))
                     (AST.jmpDest out) (AST.jmpDest more))
    bld <+ (AST.lmark more)
    bld <+ (k := AST.num0 GRSize)
    bld <+ (ok := AST.b1)
    bld <+ (AST.lmark inner)
    bld <+ (AST.cjmp (k == n) (AST.jmpDest found) (AST.jmpDest step))
    bld <+ (AST.lmark step)
    bld <+ (ok := AST.ite (loadMem 8<rt> (aa .+ k) == loadMem 8<rt> (ba .+ k))
                          ok AST.b0)
    bld <+ (k := k .+ AST.num1 GRSize)
    bld <+ (AST.cjmp (ok == AST.b1)
                     (AST.jmpDest inner) (AST.jmpDest advance))
    bld <+ (AST.lmark advance)
    bld <+ (aa := aa .+ AST.num1 GRSize)
    bld <+ (al := al .- AST.num1 GRSize)
    bld <+ (ba := ba .+ AST.num1 GRSize)
    bld <+ (bl := bl .- AST.num1 GRSize)
    bld <+ (AST.jmp (AST.jmpDest body))
    bld <+ (AST.lmark found)
    setCC bld 0
    bld <+ (AST.lmark out)
    bld --!> insLen

/// A privileged or control-program instruction. Reaching one from problem
/// state is a privileged-operation exception, which Linux turns into the
/// illegal-instruction signal -- so raising the trap is the behaviour, not a
/// gap in what is modelled here.
let illegal ins insLen bld =
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ AST.sideEffect UndefinedInstruction
  bld --!> insLen

/// An instruction with nothing for an emulator of user code to do: a prefetch,
/// a serialization, or a hint about how the code ahead will behave.
let nop ins insLen bld =
  bld <!-- ((ins: Instruction).Address, insLen)
  bld --!> insLen

/// A serializing instruction, which orders the accesses around it and does
/// nothing else that can be seen.
let fence ins insLen bld =
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ AST.sideEffect Fence
  bld --!> insLen

/// An instruction that is valid but outside what this lifter models.
let unsupported ins insLen bld =
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ AST.sideEffect UnsupportedInstruction
  bld --!> insLen

/// SET ADDRESSING MODE, which moves a program between the 24-, 31-, and 64-bit
/// modes. Only the one the guest already runs in is modelled -- a Linux process
/// is put in its mode by the kernel and never leaves it -- so asking for that
/// one does nothing and asking for another raises the unsupported trap rather
/// than carrying on with addresses of the wrong width.
let setAddressMode ins insLen bld bits =
  let current = if esaMode bld then 31 else 64
  if bits = current then nop ins insLen bld else unsupported ins insLen bld

/// TRANSACTION BEGIN, which this lifter always reports as having failed for a
/// reason that will persist: no transactional execution happens here, so a
/// guest that elides a lock must fall back to taking it.
let tbegin ins insLen bld =
  bld <!-- ((ins: Instruction).Address, insLen)
  setCC bld 2
  bld --!> insLen

/// EXTRACT TRANSACTION NESTING DEPTH, which is zero because no transaction
/// ever begins.
let etnd ins insLen bld =
  let d = oprRegVar bld (getOneOpr ins)
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (low d := AST.num0 WSize)
  bld --!> insLen

/// STORE CLOCK, whose value the emulator supplies.
let storeClock ins insLen bld =
  let o = getOneOpr ins
  let addr = tmpVar bld GRSize
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (addr := transMem bld o)
  bld <+ storeMem addr (AST.num0 GRSize)
  setCC bld 0
  bld --!> insLen

/// STORE FACILITY LIST EXTENDED, which reports the facilities the machine has.
/// Reporting none keeps a guest that chooses an implementation by facility --
/// as the C library's string routines do -- on the one every machine can run.
let stfle ins insLen bld =
  let o = getOneOpr ins
  let addr = tmpVar bld GRSize
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (addr := transMem bld o)
  bld <+ storeMem addr (AST.num0 GRSize)
  bld <+ (low (reg bld Register.R0) := AST.num0 WSize)
  setCC bld 0
  bld --!> insLen
