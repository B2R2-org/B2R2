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

/// The high-word facility, which lets code address bits 0 to 31 of a general
/// register as a register of its own. z/Architecture widened the sixteen
/// registers to 64 bits but left every word operation working on the low half,
/// so the high halves sat unused; these instructions hand a compiler short of
/// registers those halves as sixteen more words.
module internal B2R2.FrontEnd.S390.HighWordLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.S390.LiftingUtils

/// The value a source operand supplies at the given width, taking a register's
/// rightmost bits of that width.
let private srcOf bld rt o =
  match o with
  | OpReg r -> narrowTo rt (reg bld r)
  | OpImm i -> numI64 (immValue i) rt
  | OpStore _ | OpStoreLen _ -> loadMem rt (transMem bld o)
  | _ -> raise InvalidOperandException

/// A load into a register's high word, widening a narrower unit of storage as
/// the operation names.
let load ins insLen bld accW ext =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (high d := ext WSize (srcOf bld accW o2))
  bld --!> insLen

/// LOAD HIGH AND TRAP, which a compiler plants where a null pointer must not
/// be allowed to travel any further.
let loadAndTrap ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  let t = tmpVar bld WSize
  let trap = label bld "LfhatTrap"
  let out = label bld "LfhatOut"
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (t := srcOf bld WSize o2)
  bld <+ (AST.cjmp (t == AST.num0 WSize)
                   (AST.jmpDest trap) (AST.jmpDest out))
  bld <+ (AST.lmark trap)
  bld <+ AST.sideEffect (Exception IntegerOverflow)
  bld <+ (AST.lmark out)
  bld <+ (high d := t)
  bld --!> insLen

/// A store of a field of a register's high word: the whole word, or the byte or
/// halfword at its right-hand end.
let store ins insLen bld width =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ storeMem (transMem bld o2) (AST.extract d width 32)
  bld --!> insLen

/// The three-operand high-word arithmetic. The first two operands name high
/// words throughout; the third names one too in the "HH" forms and a low word
/// in the "HL" ones, which is how a value crosses between the two halves.
let alu3 ins insLen bld thirdIsLow f cc =
  let struct (o1, o2, o3) = getThreeOprs ins
  let d = oprRegVar bld o1
  let t = tmpVar bld WSize
  bld <!-- ((ins: Instruction).Address, insLen)
  let a = high (oprRegVar bld o2)
  let b =
    if thirdIsLow then low (oprRegVar bld o3) else high (oprRegVar bld o3)
  bld <+ (t := f a b)
  cc bld t a b
  bld <+ (high d := t)
  bld --!> insLen

/// ADD IMMEDIATE HIGH and its logical relatives, which add a full word to a
/// register's high half.
let addImm ins insLen bld cc =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  let a = high d
  let b = numI64 (oprImm o2) WSize
  let t = tmpVar bld WSize
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (t := a .+ b)
  cc bld t a b
  bld <+ (high d := t)
  bld --!> insLen

/// A comparison of a register's high word against a word: an immediate, a
/// field of storage, or another register's high or low half.
let compare ins insLen bld signed other =
  let struct (o1, o2) = getTwoOprs ins
  let a = tmpVar bld WSize
  let b = tmpVar bld WSize
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (a := high (oprRegVar bld o1))
  bld <+ (b := other bld o2)
  if signed then setCCCmp bld a b else setCCCmpLogical bld a b
  bld --!> insLen

/// The second operand of a high-word comparison, read as another register's
/// high half.
let highOf bld o = high (oprRegVar bld o)

/// The second operand read as another register's low half.
let lowOf bld o = low (oprRegVar bld o)

/// The second operand read as an immediate or a field of storage.
let wordOf bld o = srcOf bld WSize o

/// BRANCH RELATIVE ON COUNT HIGH: the count lives in a register's high word,
/// so a loop can keep its counter there and leave the low halves to the body.
let branchOnCount ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let d = oprRegVar bld o1
  let target = numG (int64 (codeAddr bld (relTarget ins.Address (oprImm o2))))
  let next = numG (int64 (codeAddr bld (nextAddr ins.Address insLen)))
  let t = tmpVar bld WSize
  bld <!-- (ins.Address, insLen)
  bld <+ (t := high d .- AST.num1 WSize)
  bld <+ (high d := t)
  bld <+ AST.intercjmp (t != AST.num0 WSize) target next
  bld --!> insLen

/// LOAD HIGH ON CONDITION, whose mask names the condition codes it acts on.
/// Written as a select, so the lifted block stays straight-line.
let loadOnCondition ins insLen bld other =
  let struct (o1, o2, o3) = getThreeOprs ins
  let d = oprRegVar bld o1
  let m = oprMask o3
  bld <!-- ((ins: Instruction).Address, insLen)
  if isNever m then ()
  else
    let v = other bld o2
    let value =
      if isAlways m then v else AST.ite (condOfMask bld m) v (high d)
    bld <+ (high d := value)
  bld --!> insLen

/// STORE HIGH ON CONDITION. A store that must not happen cannot be written as
/// a select, so this one does branch.
let storeOnCondition ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let m = oprMask o3
  let value = AST.extract (oprRegVar bld o1) WSize 32
  bld <!-- ((ins: Instruction).Address, insLen)
  if isNever m then ()
  elif isAlways m then bld <+ storeMem (transMem bld o2) value
  else
    let doIt = label bld "StoreHighOnCond"
    let out = label bld "SkipStoreHigh"
    bld <+ (AST.cjmp (condOfMask bld m)
                     (AST.jmpDest doIt) (AST.jmpDest out))
    bld <+ (AST.lmark doIt)
    bld <+ storeMem (transMem bld o2) value
    bld <+ (AST.lmark out)
  bld --!> insLen

/// The registers a load- or store-multiple-high walks, from the first
/// operand's through the third's, wrapping around R15 to R0.
let private regRange (r1: Register) (r3: Register) =
  let first = int r1
  let count = ((int r3 - first) &&& 0xf) + 1
  [| for i in 0 .. count - 1 -> enum<Register> ((first + i) &&& 0xf) |]

/// LOAD MULTIPLE HIGH: consecutive high words take consecutive words of
/// storage, leaving every low half alone.
let loadMultiple ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let regs = regRange (oprReg o1) (oprReg o3)
  let addr = tmpVar bld GRSize
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (addr := transMem bld o2)
  for i in 0 .. regs.Length - 1 do
    let at = addr .+ numG (int64 i * 4L)
    bld <+ (high (reg bld regs[i]) := loadMem WSize at)
  bld --!> insLen

/// STORE MULTIPLE HIGH, the mirror of LOAD MULTIPLE HIGH.
let storeMultiple ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let regs = regRange (oprReg o1) (oprReg o3)
  let addr = tmpVar bld GRSize
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (addr := transMem bld o2)
  for i in 0 .. regs.Length - 1 do
    let at = addr .+ numG (int64 i * 4L)
    bld <+ storeMem at (AST.extract (reg bld regs[i]) WSize 32)
  bld --!> insLen

/// The byte positions a four-bit mask selects within a word, leftmost bit
/// first, as offsets into the field of storage the instruction touches.
let private maskedBytes (m: Mask) =
  [| 0 .. 3 |] |> Array.filter (fun i -> m &&& (8us >>> i) <> 0us)

/// STORE CHARACTERS UNDER MASK HIGH: only the bytes of the high word the mask
/// selects are written, most significant first.
let storeUnderMask ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let d = oprRegVar bld o1
  let sel = maskedBytes (oprMask o3)
  let addr = tmpVar bld GRSize
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (addr := transMem bld o2)
  for k in 0 .. sel.Length - 1 do
    let v = AST.extract d 8<rt> (32 + 8 * (3 - sel[k]))
    bld <+ storeMem (addr .+ numG (int64 k)) v
  bld --!> insLen

/// COMPARE LOGICAL CHARACTERS UNDER MASK HIGH: the leftmost selected byte the
/// two differ in decides.
let compareUnderMask ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let d = oprRegVar bld o1
  let sel = maskedBytes (oprMask o3)
  let addr = tmpVar bld GRSize
  bld <!-- ((ins: Instruction).Address, insLen)
  bld <+ (addr := transMem bld o2)
  if sel.Length = 0 then setCC bld 0
  else
    let out = label bld "ClmhOut"
    setCC bld 0
    for k in 0 .. sel.Length - 1 do
      let a = tmpVar bld 8<rt>
      let b = tmpVar bld 8<rt>
      let next = label bld $"ClmhNext{k}"
      let diff = label bld $"ClmhDiff{k}"
      bld <+ (a := AST.extract d 8<rt> (32 + 8 * (3 - sel[k])))
      bld <+ (b := loadMem 8<rt> (addr .+ numG (int64 k)))
      bld <+ (AST.cjmp (a == b) (AST.jmpDest next) (AST.jmpDest diff))
      bld <+ (AST.lmark diff)
      bld <+ (ccVar bld := AST.ite (a .< b) (numCC 1) (numCC 2))
      bld <+ (AST.jmp (AST.jmpDest out))
      bld <+ (AST.lmark next)
    bld <+ (AST.lmark out)
  bld --!> insLen

/// The mask a rotate-then-insert into one word selects: the bits from the
/// starting position through the ending one, counted from the left of that
/// word, wrapping around it when the start lies after the end.
let private wordMask (start: int) (fin: int) =
  let bitAt i = 1L <<< (31 - i)
  let rec ones i acc = if i > fin then acc else ones (i + 1) (acc ||| bitAt i)
  if start <= fin then ones start 0L
  else
    let rec upper i acc =
      if i > 31 then acc else upper (i + 1) (acc ||| bitAt i)
    upper start 0L ||| ones 0 0L

/// A rotate left of the whole doubleword by a count known at lifting time,
/// written as the pair of shifts that make one.
let private rotl amount v =
  if (amount: int) = 0 then v
  else (v << numG (int64 amount)) .| (v >> numG (64L - int64 amount))

/// ROTATE THEN INSERT SELECTED BITS HIGH or LOW: the doubleword second operand
/// is rotated left, and the word at its right-hand end is inserted into one
/// word of the first operand under a mask a start-and-end pair names. Unlike
/// the full-register form these leave the condition code alone.
let rotateInsert ins insLen bld toHigh =
  match (ins: Instruction).Operands with
  | FiveOperands(o1, o2, o3, o4, o5) ->
    let d = oprRegVar bld o1
    let field = if toHigh then AST.extract d WSize 32 else low d
    let mask = wordMask (int (oprImm o3) &&& 31) (int (oprImm o4) &&& 31)
    let zero = int (oprImm o4) &&& 0x80 <> 0
    let t = tmpVar bld WSize
    bld <!-- (ins.Address, insLen)
    let rotated = rotl (int (oprImm o5) &&& 63) (oprRegVar bld o2)
    let selected = low rotated .& numW mask
    if zero then bld <+ (t := selected)
    else bld <+ (t := (field .& numW ~~~mask) .| selected)
    bld <+ (field := t)
    bld --!> insLen
  | _ -> raise InvalidOperandException
