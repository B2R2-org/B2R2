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

module internal B2R2.FrontEnd.PARISC.FloatLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PARISC.GeneralLifter

/// The bit of the floating-point status register a comparison leaves its answer
/// in and a test reads back. PA-RISC keeps that status in the register named
/// %fr0, whose left half this is a bit of.
let [<Literal>] private CompareBit = 0x4000000UL

/// The register holding the left half of a floating-point register, given
/// either half's name: the two halves of one register sit exactly 32 places
/// apart in
/// the register enumeration.
let private leftHalf (reg: Register) =
  if reg >= Register.FPR0R then enum<Register> (int reg - 32) else reg

/// The width a floating-point format occupies: a single fills one half of a
/// register, a double both.
let private fmtWidth = function
  | Completer.SGL | Completer.W | Completer.UW -> 32<rt>
  | Completer.DBL | Completer.DW | Completer.UDW -> 64<rt>
  | c -> raise (NotImplementedIRException(Disasm.condToString c))

/// Narrows to a single's width, or leaves the expression alone when it is
/// already that wide.
let private low32 e = if Expr.typeOf e = 32<rt> then e else AST.xtlo 32<rt> e

/// Reads a floating-point operand of the given width: one half of the named
/// register for a single, both halves joined for a double.
let private readFp (bld: ILowUIRBuilder) width reg =
  if width = 32<rt> then
    low32 (regVar bld reg)
  else
    let l = leftHalf reg
    AST.concat (low32 (regVar bld l))
               (low32 (regVar bld (enum<Register> (int l + 32))))

/// Writes a floating-point result of the given width back to the named
/// register, filling one half for a single and both for a double.
let private writeFp (bld: ILowUIRBuilder) width reg v =
  let rt = bld.RegType
  let widen e = if Expr.typeOf e = rt then e else AST.zext rt e
  if width = 32<rt> then
    bld <+ (regVar bld reg := widen v)
  else
    let l = leftHalf reg
    bld <+ (regVar bld l := widen (AST.xthi 32<rt> v))
    bld <+ (regVar bld (enum<Register> (int l + 32)) := widen
                                                          (AST.xtlo 32<rt> v))

/// The format completer a floating-point instruction carries, which says the
/// width every one of its operands has.
let private formatOf (ins: Instruction) =
  match ins.Completer with
  | Some c when c.Length > 0 -> fmtWidth c[c.Length - 1]
  | _ -> raise (NotImplementedIRException(Disasm.opCodeToString ins.Opcode))

let private getReg = function
  | OpReg r -> r
  | _ -> raise InvalidOperandException

let private twoRegs (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(a, b) -> struct (getReg a, getReg b)
  | _ -> raise InvalidOperandException

let private threeRegs (ins: Instruction) =
  match ins.Operands with
  | ThreeOperands(a, b, c) -> struct (getReg a, getReg b, getReg c)
  | _ -> raise InvalidOperandException

/// Loads a word or doubleword from memory into a floating-point register.
let fpLoad (ins: Instruction) insLen bld =
  let struct (mem, dst) =
    match ins.Operands with
    | TwoOperands(m, d) -> struct (m, getReg d)
    | _ -> raise InvalidOperandException
  let struct (sz, sh) = accessSize ins
  bld <!-- (ins.Address, insLen)
  let addr = effAddr bld ins sh mem
  writeFp bld sz dst (AST.load bld.Endianness sz addr)
  bld --!> insLen

/// Stores a word or doubleword from a floating-point register to memory.
let fpStore (ins: Instruction) insLen bld =
  let struct (src, mem) =
    match ins.Operands with
    | TwoOperands(s, m) -> struct (getReg s, m)
    | _ -> raise InvalidOperandException
  let struct (sz, sh) = accessSize ins
  bld <!-- (ins.Address, insLen)
  let addr = effAddr bld ins sh mem
  bld <+ AST.store bld.Endianness addr (readFp bld sz src)
  bld --!> insLen

/// The sign-manipulating moves, which are bit operations on the value's high
/// bit rather than arithmetic, so they leave a signalling NaN alone as the
/// architecture asks.
let private signMove (ins: Instruction) insLen bld f =
  let struct (src, dst) = twoRegs ins
  let width = formatOf ins
  bld <!-- (ins.Address, insLen)
  let v = tmpVar bld width
  bld <+ (v := readFp bld width src)
  writeFp bld width dst (f width v)
  bld --!> insLen

let fcpy ins insLen bld = signMove ins insLen bld (fun _ v -> v)

let fabs ins insLen bld =
  signMove ins insLen bld (fun w v -> v .& (numI64 -1L w >> AST.num1 w))

let fneg ins insLen bld =
  signMove ins insLen bld (fun w v ->
    v <+> AST.not (numI64 -1L w >> AST.num1 w))

let fnegabs ins insLen bld =
  signMove ins insLen bld (fun w v ->
    v .| AST.not (numI64 -1L w >> AST.num1 w))

/// The unary arithmetic: a square root and a round to an integral value.
let private unary (ins: Instruction) insLen bld f =
  let struct (src, dst) = twoRegs ins
  let width = formatOf ins
  bld <!-- (ins.Address, insLen)
  let v = tmpVar bld width
  bld <+ (v := readFp bld width src)
  writeFp bld width dst (f width v)
  bld --!> insLen

let fsqrt ins insLen bld = unary ins insLen bld (fun _ v -> AST.fsqrt v)

let frnd ins insLen bld =
  unary ins insLen bld (fun w v -> AST.cast CastKind.FtoFRound w v)

/// The binary arithmetic. The operands come in the order they are written,
/// which for the two that are not commutative is the order that decides the
/// answer: a
/// subtraction takes the first from the second's place and a division puts the
/// first over the second.
let private binary (ins: Instruction) insLen bld f =
  let struct (o1, o2, dst) = threeRegs ins
  let width = formatOf ins
  bld <!-- (ins.Address, insLen)
  let a = tmpVar bld width
  let b = tmpVar bld width
  bld <+ (a := readFp bld width o1)
  bld <+ (b := readFp bld width o2)
  writeFp bld width dst (f a b)
  bld --!> insLen

let fadd ins insLen bld = binary ins insLen bld AST.fadd

let fsub ins insLen bld = binary ins insLen bld AST.fsub

let fmpy ins insLen bld = binary ins insLen bld AST.fmul

let fdiv ins insLen bld = binary ins insLen bld AST.fdiv

/// Whether either operand of a comparison is a NaN, which is what makes the two
/// unordered: with no ordering between them, every one of less, equal, and
/// greater is false at once.
let private unordered width a b =
  if width = 32<rt> then IEEE754Single.isNaN a .| IEEE754Single.isNaN b
  else IEEE754Double.isNaN a .| IEEE754Double.isNaN b

/// The predicate a comparison completer names, as a combination of the four
/// mutually exclusive outcomes a floating-point comparison has: less, equal,
/// greater, and unordered. The completer's own spelling is that combination
/// written out -- "?<=" is unordered, less, or equal, and a leading "!" negates
/// the whole of it -- so each name below is just its spelling read off.
let private compareCond (cond: Completer) lt eq gt un =
  let no = AST.b0
  let all = AST.b1
  match cond with
  | Completer.FALSEQ | Completer.FALSE -> no
  | Completer.FQ | Completer.FBGTLE -> un
  | Completer.FEQ | Completer.FEQT -> eq
  | Completer.FQEQ | Completer.FBNEQ -> un .| eq
  | Completer.FBQGE -> lt
  | Completer.FLT -> lt
  | Completer.FQLT | Completer.FBGE -> un .| lt
  | Completer.FBQGT -> lt .| eq
  | Completer.FLE -> lt .| eq
  | Completer.FQLE | Completer.FBGT -> un .| lt .| eq
  | Completer.FBQLE -> gt
  | Completer.FGT -> gt
  | Completer.FQGT | Completer.FBLE -> un .| gt
  | Completer.FBQLT -> eq .| gt
  | Completer.FGE -> gt .| eq
  | Completer.FQGE | Completer.FBLT -> un .| gt .| eq
  | Completer.FBQEQ -> lt .| gt
  | Completer.FNEQ -> lt .| gt
  | Completer.FBEQ | Completer.FBEQT -> un .| lt .| gt
  | Completer.FBQ | Completer.FGTLE -> lt .| eq .| gt
  | Completer.TRUEQ | Completer.TRUE -> all
  | c -> raise (NotImplementedIRException(Disasm.condToString c))

/// Compares two floating-point values and records the answer in the compare bit
/// of the status register, which the test instruction then reads. Nothing else
/// is written, so a comparison and its test together are what a floating-point
/// branch is made of.
let fcmp (ins: Instruction) insLen (bld: ILowUIRBuilder) =
  let struct (o1, o2) =
    match ins.Operands with
    | TwoOperands(a, b) -> struct (getReg a, getReg b)
    | ThreeOperands(a, b, _) -> struct (getReg a, getReg b)
    | _ -> raise InvalidOperandException
  let width = formatOf ins
  let rt = bld.RegType
  bld <!-- (ins.Address, insLen)
  let a = tmpVar bld width
  let b = tmpVar bld width
  bld <+ (a := readFp bld width o1)
  bld <+ (b := readFp bld width o2)
  let un = unordered width a b
  let cond =
    match ins.Condition with
    | Some c -> compareCond c (AST.flt a b) (AST.feq a b) (AST.fgt a b) un
    | None -> AST.b0
  let fpsr = regVar bld Register.FPR0L
  let bit = numU64 CompareBit rt
  bld <+ (fpsr := (fpsr .& AST.not bit)
                  .| AST.ite cond bit (AST.num0 rt))
  bld --!> insLen

/// Tests the compare bit the last comparison left, nullifying the instruction
/// that follows when it is set -- so the branch a floating-point comparison
/// guards is the one written for the comparison's negation.
let ftest (ins: Instruction) insLen (bld: ILowUIRBuilder) =
  let rt = bld.RegType
  bld <!-- (ins.Address, insLen)
  let set = (regVar bld Register.FPR0L .& numU64 CompareBit rt)
            != AST.num0 rt
  nullifyOn bld (Some set)
  bld --!> insLen

/// Whether a conversion's format completer names an integer rather than a
/// floating-point format, and whether that integer is signed.
let private isFixed = function
  | Completer.W | Completer.DW | Completer.UW | Completer.UDW -> true
  | _ -> false

let private isUnsigned = function
  | Completer.UW | Completer.UDW -> true
  | _ -> false

/// The source and destination formats of a conversion. Where the two are the
/// same the completer names it once; a truncating conversion prefixes a "t",
/// which says how to round rather than what to convert.
let private convFormats (ins: Instruction) =
  let fmts =
    match ins.Completer with
    | Some c -> c |> Array.filter (fun x -> x <> Completer.T)
    | None -> [||]
  match fmts with
  | [| a; b |] -> struct (a, b)
  | [| a |] -> struct (a, a)
  | _ -> raise (NotImplementedIRException(Disasm.opCodeToString ins.Opcode))

/// Converts between the floating-point formats and the integer ones. A
/// conversion to an integer rounds to nearest unless the "t" completer asks for
/// truncation, which is what a cast in C needs.
let fcnv (ins: Instruction) insLen bld =
  let struct (src, dst) = twoRegs ins
  let struct (sf, df) = convFormats ins
  let sw = fmtWidth sf
  let dw = fmtWidth df
  let truncates =
    match ins.Completer with
    | Some c -> Array.contains Completer.T c
    | None -> false
  bld <!-- (ins.Address, insLen)
  let v = tmpVar bld sw
  bld <+ (v := readFp bld sw src)
  let res =
    match isFixed sf, isFixed df with
    | false, false ->
      if sw = dw then v else AST.cast CastKind.FloatCast dw v
    | true, false ->
      let kind =
        if isUnsigned sf then CastKind.UIntToFloat else CastKind.SIntToFloat
      AST.cast kind dw v
    | false, true ->
      let kind =
        if truncates then CastKind.FtoITrunc else CastKind.FtoIRound
      AST.cast kind dw v
    | true, true ->
      raise (NotImplementedIRException(Disasm.opCodeToString ins.Opcode))
  writeFp bld dw dst res
  bld --!> insLen

/// Fixed-point multiply unsigned: the one integer multiply PA-RISC has, done in
/// the floating-point unit, which is why a compiler moves its operands there
/// and back around it.
let xmpyu (ins: Instruction) insLen bld =
  let struct (o1, o2, dst) = threeRegs ins
  bld <!-- (ins.Address, insLen)
  let a = tmpVar bld 64<rt>
  let b = tmpVar bld 64<rt>
  bld <+ (a := AST.zext 64<rt> (readFp bld 32<rt> o1))
  bld <+ (b := AST.zext 64<rt> (readFp bld 32<rt> o2))
  writeFp bld 64<rt> dst (a .* b)
  bld --!> insLen

/// The paired multiply and add (or subtract): two independent operations issued
/// as one instruction, a multiply into one target and an add into another.
let fmpyadd (ins: Instruction) insLen bld =
  let struct (rm1, rm2, tm, ra, ta) =
    match ins.Operands with
    | FiveOperands(a, b, c, d, e) ->
      struct (getReg a, getReg b, getReg c, getReg d, getReg e)
    | _ ->
      raise InvalidOperandException
  let width = formatOf ins
  bld <!-- (ins.Address, insLen)
  let m1 = tmpVar bld width
  let m2 = tmpVar bld width
  let addend = tmpVar bld width
  let target = tmpVar bld width
  bld <+ (m1 := readFp bld width rm1)
  bld <+ (m2 := readFp bld width rm2)
  bld <+ (addend := readFp bld width ra)
  bld <+ (target := readFp bld width ta)
  writeFp bld width tm (AST.fmul m1 m2)
  if ins.Opcode = Op.FMPYSUB then writeFp bld width ta (AST.fsub addend target)
  else writeFp bld width ta (AST.fadd addend target)
  bld --!> insLen

/// The fused multiply and add: one rounding for the whole of it, and a negating
/// form that subtracts the product instead of adding it.
let fmpyfadd (ins: Instruction) insLen bld =
  let struct (rm1, rm2, ra, dst) =
    match ins.Operands with
    | FourOperands(a, b, c, d) ->
      struct (getReg a, getReg b, getReg c, getReg d)
    | _ ->
      raise InvalidOperandException
  let width = formatOf ins
  bld <!-- (ins.Address, insLen)
  let m1 = tmpVar bld width
  let m2 = tmpVar bld width
  let addend = tmpVar bld width
  let prod = tmpVar bld width
  bld <+ (m1 := readFp bld width rm1)
  bld <+ (m2 := readFp bld width rm2)
  bld <+ (addend := readFp bld width ra)
  bld <+ (prod := AST.fmul m1 m2)
  if ins.Opcode = Op.FMPYNFADD then writeFp bld width dst (AST.fsub addend prod)
  else writeFp bld width dst (AST.fadd prod addend)
  bld --!> insLen
