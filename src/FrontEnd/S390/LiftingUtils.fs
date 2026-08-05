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

module internal B2R2.FrontEnd.S390.LiftingUtils

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils

/// The width of a general register. z/Architecture widened the ESA/390
/// registers to 64 bits and kept the old operations as ones that touch only
/// their low half, so a register is this wide whichever of the two an
/// instruction belongs to.
let [<Literal>] GRSize = 64<rt>

/// The width of a word -- the half of a general register the ESA/390-era
/// operations read and write.
let [<Literal>] WSize = 32<rt>

/// The width of the condition code register.
let [<Literal>] CCSize = 8<rt>

/// Big-endian, which is the only order S390 stores anything in.
let [<Literal>] BE = Endian.Big

/// The register variable of a general, floating-point, or access register.
let inline reg bld r = regVar bld (r: Register)

/// The condition-code register variable.
let inline ccVar bld = regVar bld Register.CC

/// The low word (bits 32 to 63) of a general register: what an operation named
/// without the "G" reads, and -- as an assignment target -- what it writes,
/// leaving the register's high half as it found it.
let inline low e = AST.xtlo WSize e

/// The high word (bits 0 to 31) of a general register, which the high-word
/// facility turns into a register in its own right so that code short of
/// registers has thirty-two words to spend rather than sixteen.
let inline high e = AST.xthi WSize e

/// A number of the general-register width.
let inline numG (v: int64) = numI64 v GRSize

/// A number of the word width.
let inline numW (v: int64) = numI64 v WSize

/// A condition code constant.
let inline numCC (v: int) = numI32 v CCSize

/// Zero-extends to the given width, leaving an expression that is already that
/// wide alone (LowUIR rejects a cast between equal widths).
let zextTo rt e = if Expr.typeOf e = rt then e else AST.zext rt e

/// Sign-extends to the given width, leaving an already-wide expression alone.
let sextTo rt e = if Expr.typeOf e = rt then e else AST.sext rt e

/// Narrows to the given width, leaving an expression that is already that wide
/// alone (an extraction of the whole would only bloat the IR).
let narrowTo rt e = if Expr.typeOf e = rt then e else AST.xtlo rt e

/// A bit vector read as the signed value its own width gives it, which is not
/// what its raw contents say once the field is narrower than a word.
let private sextBv (bv: BitVector) =
  let width = RegType.toBitWidth bv.Length
  let sign = 1UL <<< (width - 1)
  int64 ((bv.ToUInt64() ^^^ sign) - sign)

/// The value of a displacement field, signed where the format gives it a sign.
let dispValue = function
  | DispS v -> int64 v
  | DispU v -> int64 v
  | DispS20 bv -> sextBv bv
  | DispU12 bv -> int64 (bv.ToUInt64())

/// The value of an immediate field, sign-extended to 64 bits where the field is
/// signed and zero-extended where it is not.
let immValue = function
  | ImmU4 bv -> int64 (bv.ToUInt64())
  | ImmU8 v -> int64 v
  | ImmS8 v -> int64 v
  | ImmU12 bv -> int64 (bv.ToUInt64())
  | ImmS12 bv -> sextBv bv
  | ImmU16 v -> int64 v
  | ImmS16 v -> int64 v
  | ImmS24 bv -> sextBv bv
  | ImmU32 v -> int64 v
  | ImmS32 v -> int64 v

/// The address a D(X,B) or D(B) reference names: the sum of the index and base
/// registers and the displacement. A register field of zero means "no register"
/// rather than R0, so R0's contents never take part in address arithmetic.
let transAddr bld idx b disp =
  let d = dispValue disp
  let acc =
    match idx with
    | Some r when r <> Register.R0 -> Some(reg bld r)
    | _ -> None
  let acc =
    if (b: Register) <> Register.R0 then
      match acc with
      | Some e -> Some(e .+ reg bld b)
      | None -> Some(reg bld b)
    else acc
  match acc with
  | Some e when d = 0L -> e
  | Some e -> e .+ numG d
  | None -> numG d

/// The address the sole memory operand of an instruction names.
let transMem bld = function
  | OpStore(idx, b, disp) -> transAddr bld idx b disp
  | OpStoreLen(_, b, disp) -> transAddr bld None b disp
  | _ -> raise InvalidOperandException

/// The byte count a storage-to-storage operand carries. The encoded field is
/// one less than the count; the parser has already added the one back.
let lenOfMem = function
  | OpStoreLen(len, _, _) -> int len
  | _ -> raise InvalidOperandException

/// The target of a relative branch: the immediate counts halfwords from the
/// address of the instruction it belongs to.
let relTarget (addr: Addr) (imm: int64) = addr + uint64 (2L * imm)

/// The address of the instruction that follows the one being lifted.
let nextAddr (addr: Addr) insLen = addr + uint64 (insLen: uint32)

/// An instruction's operands as an array, so that a lifter can reach them by
/// position. The vector instructions need this: their formats put the same
/// thing -- a register, an element-size mask, a control mask -- at different
/// places from one another, and there are too many shapes to name each.
let oprArray (ins: Instruction) =
  match ins.Operands with
  | NoOperand -> [||]
  | OneOperand o1 -> [| o1 |]
  | TwoOperands(o1, o2) -> [| o1; o2 |]
  | ThreeOperands(o1, o2, o3) -> [| o1; o2; o3 |]
  | FourOperands(o1, o2, o3, o4) -> [| o1; o2; o3; o4 |]
  | FiveOperands(o1, o2, o3, o4, o5) -> [| o1; o2; o3; o4; o5 |]
  | SixOperands(o1, o2, o3, o4, o5, o6) -> [| o1; o2; o3; o4; o5; o6 |]

let getOneOpr (ins: Instruction) =
  match ins.Operands with
  | OneOperand o -> o
  | _ -> raise InvalidOperandException

let getTwoOprs (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(o1, o2) -> struct (o1, o2)
  | _ -> raise InvalidOperandException

let getThreeOprs (ins: Instruction) =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) -> struct (o1, o2, o3)
  | _ -> raise InvalidOperandException

let getFourOprs (ins: Instruction) =
  match ins.Operands with
  | FourOperands(o1, o2, o3, o4) -> struct (o1, o2, o3, o4)
  | _ -> raise InvalidOperandException

/// The register an operand names.
let oprReg = function
  | OpReg r -> r
  | _ -> raise InvalidOperandException

/// The mask an operand carries.
let oprMask = function
  | OpMask m -> m
  | _ -> raise InvalidOperandException

/// The immediate an operand carries, as a signed 64-bit value.
let oprImm = function
  | OpImm i | OpRImm i -> immValue i
  | _ -> raise InvalidOperandException

/// The register variable an operand names.
let inline oprRegVar bld o = reg bld (oprReg o)

/// Sets the condition code to a value known at lifting time.
let setCC bld v = bld <+ (ccVar bld := numCC v)

/// Sets the condition code from the sign of a result, which is what an
/// arithmetic instruction reports when it does not overflow: 0 for a zero
/// result, 1 for a negative one, and 2 for a positive one.
let setCCSign bld res =
  let rt = Expr.typeOf res
  let zero = AST.num0 rt
  let sign = AST.ite (res ?< zero) (numCC 1) (numCC 2)
  bld <+ (ccVar bld := AST.ite (res == zero) (numCC 0) sign)

/// Sets the condition code the way a signed add reports it: the sign of the
/// result, or 3 when the two operands share a sign the result does not, which
/// is the only way a two's-complement sum can leave the representable range.
let setCCAdd bld res a b =
  let rt = Expr.typeOf res
  let zero = AST.num0 rt
  let ovf = ((a <+> res) .& (b <+> res)) ?< zero
  let sign = AST.ite (res ?< zero) (numCC 1) (numCC 2)
  let noOvf = AST.ite (res == zero) (numCC 0) sign
  bld <+ (ccVar bld := AST.ite ovf (numCC 3) noOvf)

/// Sets the condition code the way a signed subtract reports it. A difference
/// leaves the range only when the operands differ in sign and the result takes
/// the subtrahend's.
let setCCSub bld res a b =
  let rt = Expr.typeOf res
  let zero = AST.num0 rt
  let ovf = ((a <+> b) .& (a <+> res)) ?< zero
  let sign = AST.ite (res ?< zero) (numCC 1) (numCC 2)
  let noOvf = AST.ite (res == zero) (numCC 0) sign
  bld <+ (ccVar bld := AST.ite ovf (numCC 3) noOvf)

/// Sets the condition code the way a logical (unsigned) add reports it: the
/// carry out of the leftmost bit weighs two and a non-zero result one, so the
/// four codes name the four combinations.
let setCCAddLogical bld res carry =
  let rt = Expr.typeOf res
  let nz = AST.ite (res == AST.num0 rt) (numCC 0) (numCC 1)
  bld <+ (ccVar bld := AST.ite carry (nz .+ numCC 2) nz)

/// Sets the condition code the way a logical (unsigned) subtract reports it.
/// The difference carries out exactly when the minuend is not the smaller, so
/// an equal pair gives 2, a larger minuend 3, and a smaller one 1.
let setCCSubLogical bld a b =
  let hi = AST.ite (a .> b) (numCC 3) (numCC 1)
  bld <+ (ccVar bld := AST.ite (a == b) (numCC 2) hi)

/// Sets the condition code a bitwise operation reports: 0 for an all-zero
/// result and 1 for any other.
let setCCLogic bld res =
  let rt = Expr.typeOf res
  bld <+ (ccVar bld := AST.ite (res == AST.num0 rt) (numCC 0) (numCC 1))

/// Sets the condition code a signed comparison reports: 0 when the operands
/// are equal, 1 when the first is the smaller, and 2 when it is the larger.
let setCCCmp bld a b =
  let hi = AST.ite (a ?< b) (numCC 1) (numCC 2)
  bld <+ (ccVar bld := AST.ite (a == b) (numCC 0) hi)

/// Sets the condition code an unsigned comparison reports.
let setCCCmpLogical bld a b =
  let hi = AST.ite (a .< b) (numCC 1) (numCC 2)
  bld <+ (ccVar bld := AST.ite (a == b) (numCC 0) hi)

/// The leftmost one bit of a test mask, which is the bit TEST UNDER MASK looks
/// at to tell a mixed result's two codes apart.
let private leftmostBit (m: uint64) =
  let rec loop b = if b = 0UL || m &&& b <> 0UL then b else loop (b >>> 1)
  loop 0x8000000000000000UL

/// Sets the condition code TEST UNDER MASK reports for a value and a mask known
/// at lifting time: 0 when no selected bit is one, 3 when every one of them is,
/// and otherwise 1 or 2 as the leftmost selected bit is zero or one. A zero
/// mask selects nothing and so always reports 0.
let setCCTestMask bld value (mask: uint64) =
  let rt = Expr.typeOf value
  if mask = 0UL then setCC bld 0
  else
    let sel = value .& numI64 (int64 mask) rt
    let zero = AST.num0 rt
    let all = numI64 (int64 mask) rt
    let left = numI64 (int64 (leftmostBit mask)) rt
    let mixed = AST.ite ((sel .& left) == zero) (numCC 1) (numCC 2)
    let some = AST.ite (sel == all) (numCC 3) mixed
    bld <+ (ccVar bld := AST.ite (sel == zero) (numCC 0) some)

/// The one-bit condition a branch mask selects. The mask's four bits stand for
/// condition codes 0 to 3, the leftmost for 0, so the bit to test is the one
/// the code shifts down to. The common masks are spelled out because a compare
/// against the code reads better -- and folds better -- than a shift does.
let condOfMask bld (m: Mask) =
  let cc = ccVar bld
  match m &&& 0xfus with
  | 0us -> AST.b0
  | 1us -> cc == numCC 3
  | 2us -> cc == numCC 2
  | 3us -> cc ?>= numCC 2
  | 4us -> cc == numCC 1
  | 6us -> (cc == numCC 1) .| (cc == numCC 2)
  | 7us -> cc != numCC 0
  | 8us -> cc == numCC 0
  | 11us -> cc != numCC 1
  | 12us -> cc ?<= numCC 1
  | 13us -> cc != numCC 2
  | 14us -> cc != numCC 3
  | 15us -> AST.b1
  | m ->
    let bit = numCC (int m) >> (numCC 3 .- cc)
    (bit .& numCC 1) == numCC 1

/// Whether a mask branches whatever the condition code is.
let isAlways (m: Mask) = m &&& 0xfus = 15us

/// Whether a mask branches on no condition code at all, which makes the
/// instruction carrying it a no-operation.
let isNever (m: Mask) = m &&& 0xfus = 0us

/// Loads a value of the given width from memory.
let inline loadMem rt addr = AST.load BE rt addr

/// Stores a value of the given width to memory.
let inline storeMem addr v = AST.store BE addr v

/// Emits a byte-by-byte pass of the given length over a field of storage,
/// which is what the storage-to-storage operations do -- and why a program can
/// use one whose operands overlap to propagate a byte through a field. The
/// length is an expression because EXECUTE supplies one only at run time.
let emitByteLoop bld len dst src (f: Expr -> Expr -> Expr) =
  let i = tmpVar bld GRSize
  let body = label bld "SSBody"
  let out = label bld "SSOut"
  bld <+ (i := AST.num0 GRSize)
  bld <+ (AST.lmark body)
  let d = dst .+ i
  let s = src .+ i
  bld <+ storeMem d (f (loadMem 8<rt> d) (loadMem 8<rt> s))
  bld <+ (i := i .+ AST.num1 GRSize)
  bld <+ (AST.cjmp (i == len) (AST.jmpDest out) (AST.jmpDest body))
  bld <+ (AST.lmark out)

/// Emits the same pass, reporting whether any bit of the result is one, which
/// is what makes an exclusive-or of a field with itself both a clear and a
/// test.
let emitLogicLoop bld len dst src (f: Expr -> Expr -> Expr) =
  let i = tmpVar bld GRSize
  let acc = tmpVar bld 8<rt>
  let v = tmpVar bld 8<rt>
  let body = label bld "SSLogicBody"
  let out = label bld "SSLogicOut"
  bld <+ (acc := AST.num0 8<rt>)
  bld <+ (i := AST.num0 GRSize)
  bld <+ (AST.lmark body)
  let d = dst .+ i
  bld <+ (v := f (loadMem 8<rt> d) (loadMem 8<rt> (src .+ i)))
  bld <+ storeMem d v
  bld <+ (acc := acc .| v)
  bld <+ (i := i .+ AST.num1 GRSize)
  bld <+ (AST.cjmp (i == len) (AST.jmpDest out) (AST.jmpDest body))
  bld <+ (AST.lmark out)
  setCCLogic bld acc

/// Emits a comparison of two fields of storage: the leftmost byte they differ
/// in decides, and equal fields report equality.
let emitCompareLoop bld len a b =
  let i = tmpVar bld GRSize
  let x = tmpVar bld 8<rt>
  let y = tmpVar bld 8<rt>
  let body = label bld "ClcBody"
  let diff = label bld "ClcDiff"
  let next = label bld "ClcNext"
  let out = label bld "ClcOut"
  bld <+ (i := AST.num0 GRSize)
  setCC bld 0
  bld <+ (AST.lmark body)
  bld <+ (x := loadMem 8<rt> (a .+ i))
  bld <+ (y := loadMem 8<rt> (b .+ i))
  bld <+ (AST.cjmp (x == y) (AST.jmpDest next) (AST.jmpDest diff))
  bld <+ (AST.lmark diff)
  bld <+ (ccVar bld := AST.ite (x .< y) (numCC 1) (numCC 2))
  bld <+ (AST.jmp (AST.jmpDest out))
  bld <+ (AST.lmark next)
  bld <+ (i := i .+ AST.num1 GRSize)
  bld <+ (AST.cjmp (i == len) (AST.jmpDest out) (AST.jmpDest body))
  bld <+ (AST.lmark out)
