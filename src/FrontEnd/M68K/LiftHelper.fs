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


/// Provides the pieces every m68k lifter shares: the effective addresses its
/// operands name, the reads and the writes those stand for, and the condition
/// codes its arithmetic leaves behind.
module internal B2R2.FrontEnd.M68K.LiftHelper

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils

/// A thirty-two-bit constant, the width of every m68k register and address.
let inline num32 (n: int) = numI32 n 32<rt>

/// Returns the width of an operation whose mnemonic carries the given size.
let regTypeOf size =
  match size with
  | Sz.Byte -> 8<rt>
  | Sz.Word -> 16<rt>
  | Sz.Long | Sz.Single -> 32<rt>
  | Sz.Double -> 64<rt>
  | _ -> raise InvalidOperandSizeException

/// Returns whether the given register is one of the address registers, which
/// an instruction writes the whole of however wide the operation is.
let isAddrReg reg =
  match reg with
  | R.A0 | R.A1 | R.A2 | R.A3 | R.A4 | R.A5 | R.A6 | R.A7 -> true
  | _ -> false

/// Returns how many extension words an instruction places before those of its
/// effective address. A PC-relative mode counts its base from the first
/// extension word of the address itself, so whatever the instruction puts in
/// front of that word moves the base along with it.
let private preEAWords (ins: Instruction) =
  match ins.Opcode with
  | Op.FMOVE | Op.FMOVEM
  | Op.MOVEM | Op.CMP2 | Op.CHK2 | Op.CAS
  | Op.BFTST | Op.BFEXTU | Op.BFEXTS | Op.BFFFO
  | Op.BFINS | Op.BFCHG | Op.BFCLR | Op.BFSET ->
    2u
  | Op.DIVUL | Op.DIVSL ->
    2u
  | Op.MULU | Op.MULS | Op.DIVU | Op.DIVS ->
    if ins.Size = Sz.Long then 2u else 0u
  | Op.BTST ->
    match ins.Operands with
    | TwoOperands(OpImm _, _) -> 2u
    | _ -> 0u
  | Op.CMPI ->
    if ins.Size = Sz.Long then 4u else 2u
  | _ ->
    0u

/// Returns the address that a PC-relative mode of this instruction counts
/// from, which is where the first extension word of its effective address
/// sits.
let pcBase (ins: Instruction) =
  uint32 ins.Address + 2u + preEAWords ins

/// Represents where an operand lives once its effective address is computed.
type Loc =
  /// A register, of which a byte or a word operation names the low part.
  | LReg of Register
  /// A memory location whose address has been computed already.
  | LMem of Expr
  /// A value with no location of its own, which is what an immediate is.
  | LVal of Expr

/// Returns what an index register contributes to an address: the whole long
/// word or the sign-extended low word, times the scale the extension word
/// names.
let private indexValue bld (idx: IndexReg) =
  let r = regVar bld idx.Reg
  let v = if idx.IsLong then r else AST.sext 32<rt> (AST.xtlo 16<rt> r)
  if idx.Scale = 1 then v else v .* num32 idx.Scale

/// Returns the base an indexed mode counts from: the register it names, the
/// program counter where the mode is PC-relative, or zero where the extension
/// word suppresses the base altogether.
let private indexedBase bld ins (mem: IndexedMem) =
  match mem.Base with
  | Some R.PC -> numU32 (pcBase ins) 32<rt>
  | Some r -> regVar bld r
  | None -> AST.num0 32<rt>

/// Returns the address an indexed mode names. Where the mode is memory
/// indirect, the base, the base displacement, and -- when the index is
/// preindexed -- the index together address a long word, and the outer
/// displacement and any postindexed index are added to what that holds.
let private indexedAddr bld ins (mem: IndexedMem) =
  let bse = indexedBase bld ins mem .+ num32 mem.BaseDisp
  let idx = mem.Index |> Option.map (indexValue bld)
  match mem.OuterDisp with
  | None ->
    match idx with
    | Some i -> bse .+ i
    | None -> bse
  | Some od ->
    let inner =
      match idx with
      | Some i when mem.IsPreIndexed -> bse .+ i
      | _ -> bse
    let outer = loadNative bld 32<rt> inner .+ num32 od
    match idx with
    | Some i when not mem.IsPreIndexed -> outer .+ i
    | _ -> outer

/// Returns how far an autoincrement or an autodecrement mode moves the
/// register it names. The stack pointer moves by two even at byte size, so
/// that it stays even.
let incrOf reg size =
  match size with
  | Sz.Byte -> if reg = R.A7 then 2 else 1
  | Sz.Word -> 2
  | Sz.Long | Sz.Single -> 4
  | Sz.Double -> 8
  | Sz.Extended | Sz.Packed -> 12
  | _ -> raise InvalidOperandSizeException

/// Computes the address a memory operand names into a temporary, emitting the
/// register update that an autoincrement or an autodecrement mode performs.
/// The address goes into a temporary of its own so that a read-modify-write
/// reaches the same place twice however the register moves under it.
let private memLoc bld ins size mem =
  let t = tmpVar bld 32<rt>
  match mem with
  | Direct r ->
    append bld { t := regVar bld r }
  | PostInc r ->
    let rv = regVar bld r
    append bld {
      t := rv
      rv := rv .+ num32 (incrOf r size)
    }
  | PreDec r ->
    let rv = regVar bld r
    append bld {
      rv := rv .- num32 (incrOf r size)
      t := rv
    }
  | Disp(disp, R.PC) ->
    append bld { t := numU32 (pcBase ins + uint32 (int32 disp)) 32<rt> }
  | Disp(disp, r) ->
    append bld { t := regVar bld r .+ num32 (int32 disp) }
  | Indexed idxMem ->
    append bld { t := indexedAddr bld ins idxMem }
  LMem t

/// Translates an operand into the place it names, emitting whatever the
/// addressing mode does to the register it counts from.
let transOpr bld ins size opr =
  match opr with
  | OpReg r -> LReg r
  | OpImm imm -> LVal(numI64 imm (regTypeOf size))
  | OpAddr addr -> LMem(numU32 (uint32 addr) 32<rt>)
  | OpMem mem -> memLoc bld ins size mem
  | _ -> raise InvalidOperandException

/// Returns the value an operand holds at the given size. A register names its
/// low part, which is what a byte or a word operation reads of one.
let readLoc bld size loc =
  let rt = regTypeOf size
  match loc with
  | LReg r -> if rt = 32<rt> then regVar bld r else AST.xtlo rt (regVar bld r)
  | LMem addr -> loadNative bld rt addr
  | LVal v -> v

/// Returns the statement that writes a value to an operand. A byte or a word
/// written to a register leaves the rest of it alone, which is what lets a
/// data register hold all three sizes at once.
let writeLoc bld size loc v =
  let rt = regTypeOf size
  match loc with
  | LReg r ->
    let rv = regVar bld r
    if rt = 32<rt> then rv := v else AST.xtlo rt rv := v
  | LMem addr ->
    storeNative bld addr v
  | LVal _ ->
    raise InvalidOperandException

/// The extend flag, which carries between the words that an extended
/// arithmetic instruction adds or subtracts one at a time.
let inline xf bld = regVar bld R.XF

/// The negative flag, which is the top bit of a result.
let inline nf bld = regVar bld R.NF

/// The zero flag.
let inline zf bld = regVar bld R.ZF

/// The overflow flag, which a signed result too wide for its size sets.
let inline vf bld = regVar bld R.VF

/// The carry flag.
let inline cf bld = regVar bld R.CF

/// Sets the negative and the zero flags from a result of the given width.
let setNZ bld rt res =
  append bld {
    nf bld := AST.xthi 1<rt> res
    zf bld := res == AST.num0 rt
  }

/// Sets the flags a move or a logical operation leaves: the negative and the
/// zero flags from the result, with the overflow and the carry cleared.
let setLogicFlags bld rt res =
  append bld {
    nf bld := AST.xthi 1<rt> res
    zf bld := res == AST.num0 rt
    vf bld := AST.b0
    cf bld := AST.b0
  }

/// Sets the flags an addition leaves. The carry out of the top bit is what a
/// full adder gives whether or not the extend flag went in at the bottom, so
/// this serves the extended addition as well as the plain one, and the
/// overflow is two operands of one sign making a result of the other.
let private addFlags bld rt dst src res =
  let a = AST.xthi 1<rt> dst
  let b = AST.xthi 1<rt> src
  let r = AST.xthi 1<rt> res
  append bld {
    vf bld := (a == b) .& (r != a)
    cf bld := (a .& b) .| (AST.not r .& (a .| b))
    xf bld := cf bld
    nf bld := r
  }

/// Sets the flags a subtraction leaves, the borrow out of the top bit standing
/// for the carry. This serves the extended subtraction too, for the same
/// reason the addition's does.
let private subFlags bld rt dst src res =
  let a = AST.xthi 1<rt> dst
  let b = AST.xthi 1<rt> src
  let r = AST.xthi 1<rt> res
  append bld {
    vf bld := (a != b) .& (r != a)
    cf bld := (AST.not a .& b) .| (r .& (AST.not a .| b))
    xf bld := cf bld
    nf bld := r
  }

/// Sets every flag an addition of the whole operands leaves.
let setAddFlags bld rt dst src res =
  addFlags bld rt dst src res
  append bld { zf bld := res == AST.num0 rt }

/// Sets every flag a subtraction of the whole operands leaves.
let setSubFlags bld rt dst src res =
  subFlags bld rt dst src res
  append bld { zf bld := res == AST.num0 rt }

/// Sets the flags a comparison leaves, which are a subtraction's but for the
/// extend flag: a comparison keeps no result, so there is nothing to carry.
let setCmpFlags bld rt dst src res =
  let a = AST.xthi 1<rt> dst
  let b = AST.xthi 1<rt> src
  let r = AST.xthi 1<rt> res
  append bld {
    vf bld := (a != b) .& (r != a)
    cf bld := (AST.not a .& b) .| (r .& (AST.not a .| b))
    nf bld := r
    zf bld := res == AST.num0 rt
  }

/// Sets the flags an extended addition leaves. Its zero flag falls only when
/// a word of the result does not, so that a multiword sum reads as zero just
/// when every word of it does.
let setAddXFlags bld rt dst src res =
  addFlags bld rt dst src res
  append bld { zf bld := zf bld .& (res == AST.num0 rt) }

/// Sets the flags an extended subtraction leaves, whose zero flag behaves as
/// the extended addition's does.
let setSubXFlags bld rt dst src res =
  subFlags bld rt dst src res
  append bld { zf bld := zf bld .& (res == AST.num0 rt) }

/// Returns the four-bit condition that a conditional opcode names, in the
/// numbering of the manual's condition code table.
let private ccIndex opcode =
  match opcode with
  | Op.ST | Op.DBT | Op.TRAPT -> 0
  | Op.SF | Op.DBF | Op.TRAPF -> 1
  | Op.BHI | Op.SHI | Op.DBHI | Op.TRAPHI -> 2
  | Op.BLS | Op.SLS | Op.DBLS | Op.TRAPLS -> 3
  | Op.BCC | Op.SCC | Op.DBCC | Op.TRAPCC -> 4
  | Op.BCS | Op.SCS | Op.DBCS | Op.TRAPCS -> 5
  | Op.BNE | Op.SNE | Op.DBNE | Op.TRAPNE -> 6
  | Op.BEQ | Op.SEQ | Op.DBEQ | Op.TRAPEQ -> 7
  | Op.BVC | Op.SVC | Op.DBVC | Op.TRAPVC -> 8
  | Op.BVS | Op.SVS | Op.DBVS | Op.TRAPVS -> 9
  | Op.BPL | Op.SPL | Op.DBPL | Op.TRAPPL -> 10
  | Op.BMI | Op.SMI | Op.DBMI | Op.TRAPMI -> 11
  | Op.BGE | Op.SGE | Op.DBGE | Op.TRAPGE -> 12
  | Op.BLT | Op.SLT | Op.DBLT | Op.TRAPLT -> 13
  | Op.BGT | Op.SGT | Op.DBGT | Op.TRAPGT -> 14
  | Op.BLE | Op.SLE | Op.DBLE | Op.TRAPLE -> 15
  | _ -> raise InvalidOpcodeException

/// Returns the expression a conditional opcode tests.
let condExpr bld opcode =
  match ccIndex opcode with
  | 0 -> AST.b1
  | 1 -> AST.b0
  | 2 -> AST.not (cf bld .| zf bld)
  | 3 -> cf bld .| zf bld
  | 4 -> AST.not (cf bld)
  | 5 -> cf bld
  | 6 -> AST.not (zf bld)
  | 7 -> zf bld
  | 8 -> AST.not (vf bld)
  | 9 -> vf bld
  | 10 -> AST.not (nf bld)
  | 11 -> nf bld
  | 12 -> nf bld == vf bld
  | 13 -> nf bld != vf bld
  | 14 -> AST.not (zf bld) .& (nf bld == vf bld)
  | _ -> zf bld .| (nf bld != vf bld)

/// Returns the byte that the condition code register holds, which is the five
/// flags in the places the manual gives them.
let ccrValue bld =
  AST.revConcat [| cf bld; vf bld; zf bld; nf bld; xf bld; AST.num0 3<rt> |]

/// Spreads a condition code byte back over the five flags it holds.
let setCCR bld v =
  append bld {
    xf bld := AST.extract v 1<rt> 4
    nf bld := AST.extract v 1<rt> 3
    zf bld := AST.extract v 1<rt> 2
    vf bld := AST.extract v 1<rt> 1
    cf bld := AST.xtlo 1<rt> v
  }

/// Returns the register variable that an operand names, which is what the
/// instructions that work on a register and nothing else are given.
let regOf bld opr =
  match opr with
  | OpReg r -> regVar bld r
  | _ -> raise InvalidOperandException

/// Returns the address that a branch of this instruction reaches.
let branchTarget (ins: Instruction) =
  match ins.Operands with
  | OneOperand(OpRelAddr d)
  | TwoOperands(_, OpRelAddr d) -> numU32 (uint32 (ins.TargetOf d)) 32<rt>
  | _ -> raise InvalidOperandException

/// The address of the instruction after this one, which is where a call
/// returns to and where a branch not taken carries on.
let fallThrough (ins: Instruction) =
  numU32 (uint32 ins.Address + ins.Length) 32<rt>

/// Returns the one operand of an instruction that names exactly one.
let getOneOpr (ins: Instruction) =
  match ins.Operands with
  | OneOperand o -> o
  | _ -> raise InvalidOperandException

/// Returns the two operands of an instruction that names exactly two.
let getTwoOprs (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(o1, o2) -> struct (o1, o2)
  | _ -> raise InvalidOperandException

/// Returns the three operands of an instruction that names exactly three.
let getThreeOprs (ins: Instruction) =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) -> struct (o1, o2, o3)
  | _ -> raise InvalidOperandException
