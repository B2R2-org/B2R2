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

module internal B2R2.FrontEnd.AVR.GeneralLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.AVR
open type Register

let inline numI32 n = numI32 n 8<rt>

/// The width of the program counter. AVR's own is 16 or 22 bits wide depending
/// on the core, and it counts words rather than bytes; B2R2 addresses code by
/// the byte, so this is wide enough to hold the largest AVR program address
/// doubled, on every core, without a case for each.
let private pcSize = 32<rt>

/// Creates a constant at the width of the program counter.
let numI32PC n = LiftingUtils.numI32 n pcSize

/// Creates a constant at the width of one of AVR's own data addresses -- a
/// pointer pair, the stack pointer, or an I/O address.
let private numAddr n = LiftingUtils.numI32 n 16<rt>

/// AVR is a Harvard machine: its data space and its program space are separate
/// address spaces that both start at zero. The two are folded into the one
/// address space an emulator gives the guest by leaving program addresses where
/// they are and biasing data addresses by this, which is the layout avr-gcc,
/// GDB, and the AVR ELF format already agree on (a linked image places .data at
/// 0x800000 + its data address). LD, ST, LDS, STS, PUSH, POP, and the I/O space
/// take the bias; LPM and the program counter do not.
let [<Literal>] private DataSpaceBase = 0x800000

/// The width the folded space needs, wider than either of AVR's own 16-bit
/// spaces because of the bias above.
let private foldedAddrSize = 32<rt>

/// Returns a byte of the guest's data space at a 16-bit data address.
let private dataMem addr =
  AST.zext foldedAddrSize addr
  .+ LiftingUtils.numI32 DataSpaceBase foldedAddrSize
  |> AST.loadLE 8<rt>

/// Returns a byte of the guest's program space at a program address, already at
/// the program counter's width. This is what LPM and ELPM reach, and the one
/// load that takes no bias.
let private codeMem addr = AST.loadLE 8<rt> addr

/// The data address the I/O space starts at, the 32 bytes of the register file
/// being what precedes it, so an `in` of I/O address A reads A plus this.
let [<Literal>] private IoSpaceBase = 0x20

/// The data addresses of the two registers that extend an address past the 16
/// bits a pointer pair holds: RAMPZ, which supplies bits 23:16 of the program
/// address ELPM reads, and EIND, which supplies bits 23:16 of the one EIJMP
/// and EICALL go to. Unlike the status register or the stack pointer, these
/// are ordinary bytes of the data space to everything else, and reading them
/// here is what the instruction itself does -- the reference simulator reads
/// them out of data memory in the same place.
let [<Literal>] private AddrRampz = 0x3B + IoSpaceBase

let [<Literal>] private AddrEind = 0x3C + IoSpaceBase

/// Returns the 24-bit program address formed by putting one of the extension
/// registers above the 16 bits of Z.
let private farAddr bld ext =
  AST.zext pcSize (dataMem (numAddr ext)) << numI32PC 16
  .| AST.zext pcSize (regVar bld Z)

/// Returns the byte of the data space an I/O address names. Which of those
/// addresses is a peripheral register, which is the status register, and which
/// is the stack pointer is the platform's business, not this translation's: an
/// I/O access is a data access at a fixed offset, and an emulator that models a
/// register there answers it whichever instruction arrives -- including a
/// pointer this could never have recognized.
let private ioMem a = dataMem (numAddr (a + IoSpaceBase))

/// Returns the I/O address and bit number of a CBI, SBI, SBIC, or SBIS.
let private transIoBit (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(OprImm a, OprImm b) -> struct (a, b)
  | _ -> raise InvalidOperandException

/// Emits a skip instruction: CPSE, SBRC/SBRS, and SBIC/SBIS all jump over the
/// instruction that follows when their condition holds. How far that is depends
/// on how long the instruction after it is, which the decoder reads ahead for
/// (see Instruction.SkipBytes) -- exactly as the hardware does. avr-libc's
/// isspace, for one, skips over a jump, which is four bytes on any part with
/// more than 8 KiB of program memory and two on the rest.
///
/// A decode that ran out of bytes before the successor reports nothing, and the
/// skip is then taken to clear a two-byte instruction: the alternative would be
/// to refuse an instruction that is perfectly valid.
let private skipOn cond (ins: Instruction) len bld =
  lift bld ins len {
    let pc = regVar bld PC
    let over = if ins.SkipBytes = 0u then 4 else int ins.SkipBytes
    AST.intercjmp cond (pc .+ numI32PC over) (pc .+ numI32PC 2)
  }

/// Returns the two 8-bit halves of one of the R26-R31 pointer pairs, which is
/// how a pointer write-back reaches the registers behind the pair.
let private ptrHalves ptr =
  match ptr with
  | BinOp(BinOpType.CONCAT, _, hi, lo, _) -> struct (hi, lo)
  | _ -> Terminator.impossible ()

/// Emits the pointer write-back of a post-increment or pre-decrement access.
let private setPtr bld ptr v =
  append bld {
    let struct (hi, lo) = ptrHalves ptr
    hi := AST.extract v 8<rt> 8
    lo := AST.extract v 8<rt> 0
  }

/// How many bytes of return address a call frame holds on the given core.
let private retBytes (core: AVRCore) = if core = AVRCore.Avr6 then 3 else 2

/// Emits the return-address push of CALL, RCALL, ICALL, and EICALL. Like the
/// hardware, the value pushed is the *word* address of the instruction after
/// this one -- every AVR code address a program handles is a word address --
/// and its bytes are laid out most significant first, so they occupy the bytes
/// just below the stack pointer and it ends that many lower. RET reads them
/// back the same way, and libgcc's frame helpers count on the size matching
/// the core.
let private pushRet core (ins: Instruction) len bld =
  append bld {
    let sp = regVar bld SP
    let n = retBytes core
    let ret = int ((ins.Address + uint64 len) >>> 1)
    let below i = if i = 0 then sp else sp .- numAddr i
    for i = 0 to n - 1 do
      dataMem (below i) := numI32 ((ret >>> (8 * i)) &&& 0xff)
    sp := sp .- numAddr n
  }

/// Wraps a relative branch's target around the end of program memory, which is
/// what the hardware does and what lets a reset vector reach startup code
/// sitting at the top of a small part's flash. A zero mask means nothing said
/// how big program memory is, so the target is left alone and a branch that
/// relied on the wrap runs off the end instead of landing somewhere plausible.
let private wrapPC (pcMask: uint64) target =
  if pcMask = 0UL then target else target .& LiftingUtils.numU64 pcMask pcSize

/// Returns the byte address IJMP and ICALL go to, which Z alone names. Every
/// AVR code address a program handles counts words, so the byte address is
/// twice it.
let private indTarget bld = AST.zext pcSize (regVar bld Z) << numI32PC 1

/// Returns the byte address EIJMP and EICALL go to, which EIND extends Z to
/// name -- the cores with more program memory than Z alone can reach.
let private farTarget bld = farAddr bld AddrEind << numI32PC 1

let private cfOnAdd e1 e2 r =
  let e1High = AST.xthi 1<rt> e1
  let e2High = AST.xthi 1<rt> e2
  let rHighComp = AST.not (AST.xthi 1<rt> r)
  (e1High .& e2High) .| (e1High .& rHighComp) .| (e2High .& rHighComp)

/// OF on add.
let private ofOnAdd e1 e2 r =
  let e1High = AST.xthi 1<rt> e1
  let e2High = AST.xthi 1<rt> e2
  let rHigh = AST.xthi 1<rt> r
  (e1High .& e2High .& (AST.not rHigh))
    .| ((AST.not e1High) .& (AST.not e2High) .& rHigh)

let transOprToExpr bld = function
| OprReg reg -> regVar bld reg
| OprImm imm -> numI32 imm
| OprAddr addr -> numI32PC addr
| OprAbsAddr addr -> numI32PC addr
| _ -> Terminator.impossible ()

let transMemOprToExpr (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprReg reg, OprMemory(PreIdxMode(reg1))) ->
    regVar bld reg, regVar bld reg1, -1
  | TwoOperands(OprReg reg, OprMemory(PostIdxMode(reg1))) ->
    regVar bld reg, regVar bld reg1, 1
  | TwoOperands(OprReg reg, OprMemory(UnchMode(reg1))) ->
    regVar bld reg, regVar bld reg1, 0
  | _ ->
    Terminator.impossible ()

let transMemOprToExpr2 (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprMemory(PreIdxMode(reg1)), OprReg reg) ->
    regVar bld reg1, regVar bld reg, -1
  | TwoOperands(OprMemory(PostIdxMode(reg1)), OprReg reg) ->
    regVar bld reg1, regVar bld reg, 1
  | TwoOperands(OprMemory(UnchMode(reg1)), OprReg reg) ->
    regVar bld reg1, regVar bld reg, 0
  | _ ->
    Terminator.impossible ()

let transMemOprToExpr1 (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprReg reg, OprMemory(DispMode(reg1, imm))) ->
    regVar bld reg, regVar bld reg1, numAddr imm
  | _ ->
    Terminator.impossible ()

let transMemOprToExpr3 (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprMemory(DispMode(reg1, imm)), OprReg reg) ->
    regVar bld reg1, regVar bld reg, numAddr imm
  | _ ->
    Terminator.impossible ()

let transOneOpr (ins: Instruction) bld =
  match ins.Operands with
  | OneOperand o1 -> transOprToExpr bld o1
  | _ -> raise InvalidOperandException

let transTwoOprs (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(o1, o2) -> struct (transOprToExpr bld o1, transOprToExpr bld o2)
  | _ -> raise InvalidOperandException

let sideEffects insAddr insLen name bld =
  liftAt bld insAddr insLen {
    AST.sideEffect name
  }

let getIndAdrReg (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(_, OprReg reg1) ->
    let dst = reg1 |> regVar bld
    let dst1 = reg1 |> Register.toRegID |> int |> (fun n -> n + 1)
               |> RegisterID.create |> Register.ofRegID |> regVar bld
    AST.concat dst1 dst
  | _ ->
    raise InvalidOperandException

let adc ins len bld =
  lift bld ins len {
    let struct (dst, src) = transTwoOprs ins bld
    let oprSize = 8<rt>
    let struct (t1, t2, t3) = tmpVars3 bld oprSize
    t1 := dst
    t2 := src
    t3 := t1 .+ t2 .+ AST.zext 8<rt> (regVar bld CF)
    dst := t3
    regVar bld HF := cfOnAdd (AST.extract t1 1<rt> 3)
                             (AST.extract t2 1<rt> 3)
                             (AST.extract t3 1<rt> 3)
    regVar bld CF := cfOnAdd t1 t2 t3
    regVar bld VF := ofOnAdd t1 t2 t3
    regVar bld NF := AST.xthi 1<rt> t3
    regVar bld ZF := t3 == (AST.num0 oprSize)
    regVar bld SF := regVar bld NF <+> regVar bld VF
  }

let add ins len bld =
  lift bld ins len {
    let struct (dst, src) = transTwoOprs ins bld
    let oprSize = 8<rt>
    let struct (t1, t2, t3) = tmpVars3 bld oprSize
    t1 := dst
    t2 := src
    t3 := t1 .+ t2
    dst := t3
    regVar bld HF := cfOnAdd (AST.extract t1 1<rt> 3)
                             (AST.extract t2 1<rt> 3)
                             (AST.extract t3 1<rt> 3)
    regVar bld CF := cfOnAdd t1 t2 t3
    regVar bld VF := ofOnAdd t1 t2 t3
    regVar bld NF := AST.xthi 1<rt> t3
    regVar bld ZF := t3 == (AST.num0 oprSize)
    regVar bld SF := regVar bld NF <+> regVar bld VF
  }

let adiw (ins: Instruction) len bld =
  lift bld ins len {
    let struct (t1, t2) = tmpVars2 bld 8<rt>
    let t3 = tmpVar bld 16<rt>
    let struct (dst, dst1, src) =
      match ins.Operands with
      | TwoOperands(OprReg reg1, OprImm imm) ->
        let dst = reg1 |> regVar bld
        let dst1 =
          reg1 |> Register.toRegID |> int
          |> (fun n -> n + 1)
          |> RegisterID.create |> Register.ofRegID |> regVar bld
        let src = imm |> numI32
        struct (dst, dst1, src)
      | _ ->
        raise InvalidOperandException
    t1 := dst1
    t2 := dst
    t3 := (AST.concat t1 t2) .+ AST.zext 16<rt> src
    dst1 := AST.extract t3 8<rt> 8
    dst := AST.extract t3 8<rt> 0
    regVar bld NF := AST.xthi 1<rt> dst1
    regVar bld VF := (AST.not (AST.xthi 1<rt> t1)) .& AST.xthi 1<rt> dst1
    regVar bld ZF := t3 == (AST.num0 16<rt>)
    regVar bld CF := (AST.not (AST.xthi 1<rt> dst1)) .& AST.xthi 1<rt> t1
    regVar bld SF := regVar bld NF <+> regVar bld VF
  }

let ``and`` ins len bld =
  lift bld ins len {
    let struct (dst, src) = transTwoOprs ins bld
    let oprSize = 8<rt>
    let r = tmpVar bld oprSize
    r := dst .& src
    dst := r
    regVar bld VF := AST.b0
    regVar bld NF := AST.xthi 1<rt> r
    regVar bld ZF := r == (AST.num0 oprSize)
    regVar bld SF := regVar bld NF <+> regVar bld VF
  }

let andi ins len bld =
  lift bld ins len {
    let struct (dst, src) = transTwoOprs ins bld
    let oprSize = 8<rt>
    let r = tmpVar bld oprSize
    r := dst .& src
    dst := r
    regVar bld VF := AST.b0
    regVar bld NF := AST.xthi 1<rt> r
    regVar bld ZF := r == (AST.num0 oprSize)
    regVar bld SF := regVar bld NF <+> regVar bld VF
  }

let ``asr`` ins len bld =
  lift bld ins len {
    let dst = transOneOpr ins bld
    let oprSize = 8<rt>
    let t1 = tmpVar bld oprSize
    t1 := dst
    dst := dst ?>> AST.num1 oprSize
    regVar bld ZF := dst == (AST.num0 oprSize)
    regVar bld NF := AST.xthi 1<rt> dst
    regVar bld CF := AST.xtlo 1<rt> t1
    regVar bld VF := regVar bld NF <+> regVar bld CF
    regVar bld SF := regVar bld NF <+> regVar bld VF
  }

let bld ins len bld =
  lift bld ins len {
    let struct (dst, src) = transTwoOprs ins bld
    let imm =
      match ins.Operands with
      | TwoOperands(_, OprImm imm) -> imm
      | _ -> Terminator.impossible ()
    (AST.extract dst 1<rt> imm) := regVar bld TF
  }

let bst ins len bld =
  lift bld ins len {
    let struct (dst, _) = transTwoOprs ins bld
    let imm =
      match ins.Operands with
      | TwoOperands(_, OprImm imm) -> imm
      | _ -> Terminator.impossible ()
    let r = tmpVar bld 1<rt>
    regVar bld TF := (AST.extract dst 1<rt> imm)
  }

let call core ins len bld =
  lift bld ins len {
    let dst = transOneOpr ins bld
    pushRet core ins len bld
    AST.interjmp dst InterJmpKind.IsCall
  }

let clc (ins: Instruction) len bld =
  lift bld ins len {
    regVar bld CF := AST.b0
  }

let clh (ins: Instruction) len bld =
  lift bld ins len {
    regVar bld HF := AST.b0
  }

let cli (ins: Instruction) len bld =
  lift bld ins len {
    regVar bld IF := AST.b0
  }

let cln (ins: Instruction) len bld =
  lift bld ins len {
    regVar bld NF := AST.b0
  }

let clr ins len bld =
  lift bld ins len {
    let dst = transOneOpr ins bld
    dst := dst <+> dst
    regVar bld SF := AST.b0
    regVar bld VF := AST.b0
    regVar bld NF := AST.b0
    regVar bld ZF := AST.b1
  }

let cls (ins: Instruction) len bld =
  lift bld ins len {
    regVar bld SF := AST.b0
  }

let clt (ins: Instruction) len bld =
  lift bld ins len {
    regVar bld TF := AST.b0
  }

let clv (ins: Instruction) len bld =
  lift bld ins len {
    regVar bld VF := AST.b0
  }

let clz (ins: Instruction) len bld =
  lift bld ins len {
    regVar bld ZF := AST.b0
  }

let com ins len bld =
  lift bld ins len {
    let oprSize = 8<rt>
    let dst = transOneOpr ins bld
    dst := numI32 0xff .- dst
    regVar bld CF := AST.b1
    regVar bld VF := AST.b0
    regVar bld NF := AST.xthi 1<rt> dst
    regVar bld ZF := dst == (AST.num0 oprSize)
    regVar bld SF := regVar bld NF <+> regVar bld VF
  }

let cp ins len bld =
  lift bld ins len {
    let oprSize = 8<rt>
    let struct (dst, src) = transTwoOprs ins bld
    let struct (t1, t2, t3) = tmpVars3 bld oprSize
    t1 := dst
    t2 := src
    t3 := t1 .- t2
    regVar bld HF := cfOnAdd t3 t2 t1
    regVar bld CF := cfOnAdd t3 t2 t1
    regVar bld VF := ofOnAdd t3 t2 t1
    regVar bld NF := AST.xthi 1<rt> t3
    regVar bld ZF := t3 == (AST.num0 oprSize)
    regVar bld SF := regVar bld NF <+> regVar bld VF
  }

let cpc ins len bld =
  lift bld ins len {
    let struct (dst, src) = transTwoOprs ins bld
    let oprSize = 8<rt>
    let struct (t1, t2, t3) = tmpVars3 bld oprSize
    t1 := dst
    t2 := src
    t3 := t1 .- t2 .- AST.zext 8<rt> (regVar bld CF)
    regVar bld HF := cfOnAdd t3 t2 t1
    regVar bld CF := cfOnAdd t3 t2 t1
    regVar bld VF := ofOnAdd t3 t2 t1
    regVar bld NF := AST.xthi 1<rt> t3
    regVar bld ZF := (t3 == (AST.num0 oprSize)) .& regVar bld ZF
    regVar bld SF := regVar bld NF <+> regVar bld VF
  }

let cpi ins len bld =
  lift bld ins len {
    let struct (dst, src) = transTwoOprs ins bld
    let oprSize = 8<rt>
    let struct (t1, t2, t3) = tmpVars3 bld oprSize
    t1 := dst
    t2 := src
    t3 := t1 .- t2
    regVar bld HF := cfOnAdd t3 t2 t1
    regVar bld CF := cfOnAdd t3 t2 t1
    regVar bld VF := ofOnAdd t3 t2 t1
    regVar bld NF := AST.xthi 1<rt> t3
    regVar bld ZF := t3 == (AST.num0 oprSize)
    regVar bld SF := regVar bld NF <+> regVar bld VF
  }

let cpse ins len bld =
  let struct (dst, src) = transTwoOprs ins bld
  skipOn (dst == src) ins len bld

let sbrc ins len bld =
  let struct (dst, _) = transTwoOprs ins bld
  let b =
    match ins.Operands with
    | TwoOperands(_, OprImm b) -> b
    | _ -> raise InvalidOperandException
  skipOn (AST.extract dst 1<rt> b == AST.b0) ins len bld

let sbrs ins len bld =
  let struct (dst, _) = transTwoOprs ins bld
  let b =
    match ins.Operands with
    | TwoOperands(_, OprImm b) -> b
    | _ -> raise InvalidOperandException
  skipOn (AST.extract dst 1<rt> b == AST.b1) ins len bld

let sbic ins len bld =
  let struct (a, b) = transIoBit ins
  skipOn (AST.extract (ioMem a) 1<rt> b == AST.b0) ins len bld

let sbis ins len bld =
  let struct (a, b) = transIoBit ins
  skipOn (AST.extract (ioMem a) 1<rt> b == AST.b1) ins len bld

let cbi (ins: Instruction) len bld =
  lift bld ins len {
    let struct (a, b) = transIoBit ins
    let t = tmpVar bld 8<rt>
    t := ioMem a
    AST.extract t 1<rt> b := AST.b0
    ioMem a := t
  }

let sbi (ins: Instruction) len bld =
  lift bld ins len {
    let struct (a, b) = transIoBit ins
    let t = tmpVar bld 8<rt>
    t := ioMem a
    AST.extract t 1<rt> b := AST.b1
    ioMem a := t
  }

let ``in`` (ins: Instruction) len bld =
  lift bld ins len {
    let struct (dst, a) =
      match ins.Operands with
      | TwoOperands(OprReg reg, OprImm a) -> struct (regVar bld reg, a)
      | _ -> raise InvalidOperandException
    dst := ioMem a
  }

let out (ins: Instruction) len bld =
  lift bld ins len {
    let struct (a, src) =
      match ins.Operands with
      | TwoOperands(OprImm a, OprReg reg) -> struct (a, regVar bld reg)
      | _ -> raise InvalidOperandException
    ioMem a := src
  }

let dec ins len bld =
  lift bld ins len {
    let dst = transOneOpr ins bld
    let oprSize = 8<rt>
    let t1 = tmpVar bld oprSize
    t1 := dst
    dst := t1 .- AST.num1 oprSize
    regVar bld VF := t1 == numI32 0x80
    regVar bld NF := AST.xthi 1<rt> dst
    regVar bld ZF := dst == (AST.num0 oprSize)
    regVar bld SF := regVar bld NF <+> regVar bld VF
  }

let fmul ins len bld =
  lift bld ins len {
    let struct (dst, src) = transTwoOprs ins bld
    let oprSize = 16<rt>
    let struct (t1, t2, t3) = tmpVars3 bld oprSize
    let t4 = tmpVar bld 16<rt>
    t1 := AST.zext oprSize dst
    t2 := AST.zext oprSize src
    t3 := t1 .* t2
    t4 := t3 << AST.num1 oprSize
    regVar bld R1 := AST.extract t4 8<rt> 8
    regVar bld R0 := AST.extract t4 8<rt> 0
    regVar bld CF := AST.extract t3 1<rt> 15
    regVar bld ZF := t4 == AST.num0 oprSize
  }

let fmuls ins len bld =
  lift bld ins len {
    let struct (dst, src) = transTwoOprs ins bld
    let oprSize = 16<rt>
    let struct (t1, t2, t3) = tmpVars3 bld oprSize
    let t4 = tmpVar bld 16<rt>
    t1 := AST.sext oprSize dst
    t2 := AST.sext oprSize src
    t3 := t1 .* t2
    t4 := t3 << AST.num1 oprSize
    regVar bld R1 := AST.extract t4 8<rt> 8
    regVar bld R0 := AST.extract t4 8<rt> 0
    regVar bld CF := AST.extract t3 1<rt> 15
    regVar bld ZF := t4 == AST.num0 oprSize
  }

let fmulsu ins len bld =
  lift bld ins len {
    let struct (dst, src) = transTwoOprs ins bld
    let oprSize = 16<rt>
    let struct (t1, t2, t3) = tmpVars3 bld oprSize
    let t4 = tmpVar bld 16<rt>
    t1 := AST.sext oprSize dst
    t2 := AST.zext oprSize src
    t3 := t1 .* t2
    t4 := t3 << AST.num1 oprSize
    regVar bld R1 := AST.extract t4 8<rt> 8
    regVar bld R0 := AST.extract t4 8<rt> 0
    regVar bld CF := AST.extract t3 1<rt> 15
    regVar bld ZF := t4 == AST.num0 oprSize
  }

let eor ins len bld =
  lift bld ins len {
    let struct (dst, src) = transTwoOprs ins bld
    let oprSize = 8<rt>
    dst := dst <+> src
    regVar bld VF := AST.b0
    regVar bld NF := AST.xthi 1<rt> dst
    regVar bld ZF := dst == AST.num0 oprSize
    regVar bld SF := regVar bld NF <+> regVar bld VF
  }

let icall core (ins: Instruction) len bld =
  lift bld ins len {
    pushRet core ins len bld
    AST.interjmp (indTarget bld) InterJmpKind.IsCall
  }

let ijmp (ins: Instruction) len bld =
  lift bld ins len {
    AST.interjmp (indTarget bld) InterJmpKind.Base
  }

/// EICALL and EIJMP reach the program memory past what Z alone addresses, EIND
/// carrying the bits above it.
let eicall core (ins: Instruction) len bld =
  lift bld ins len {
    pushRet core ins len bld
    AST.interjmp (farTarget bld) InterJmpKind.IsCall
  }

let eijmp (ins: Instruction) len bld =
  lift bld ins len {
    AST.interjmp (farTarget bld) InterJmpKind.Base
  }

let inc ins len bld =
  lift bld ins len {
    let dst = transOneOpr ins bld
    let oprSize = 8<rt>
    let t1 = tmpVar bld oprSize
    t1 := dst
    dst := t1 .+ AST.num1 oprSize
    regVar bld VF := t1 == numI32 0x7f
    regVar bld NF := AST.xthi 1<rt> dst
    regVar bld ZF := dst == (AST.num0 oprSize)
    regVar bld SF := regVar bld NF <+> regVar bld VF
  }

let ``lsr`` ins len bld =
  lift bld ins len {
    let dst = transOneOpr ins bld
    let oprSize = 8<rt>
    let t1 = tmpVar bld oprSize
    t1 := dst
    dst := dst >> AST.num1 oprSize
    regVar bld ZF := dst == (AST.num0 oprSize)
    regVar bld NF := AST.b0
    regVar bld CF := AST.xtlo 1<rt> t1
    regVar bld VF := regVar bld NF <+> regVar bld CF
    regVar bld SF := regVar bld NF <+> regVar bld VF
  }

let branch pcMask ins len bld =
  lift bld ins len {
    let dst = transOneOpr ins bld
    let pc = regVar bld PC
    let branchCond =
      match ins.Opcode with
      | Opcode.BRCC -> regVar bld CF == AST.b0
      | Opcode.BRCS -> regVar bld CF == AST.b1
      | Opcode.BREQ -> regVar bld ZF == AST.b1
      | Opcode.BRGE -> regVar bld SF == AST.b0
      | Opcode.BRHC -> regVar bld HF == AST.b0
      | Opcode.BRHS -> regVar bld HF == AST.b1
      | Opcode.BRID -> regVar bld IF == AST.b0
      | Opcode.BRIE -> regVar bld IF == AST.b1
      | Opcode.BRLT -> regVar bld SF == AST.b1
      | Opcode.BRMI -> regVar bld NF == AST.b1
      | Opcode.BRNE -> regVar bld ZF == AST.b0
      | Opcode.BRPL -> regVar bld NF == AST.b0
      | Opcode.BRTC -> regVar bld TF == AST.b0
      | Opcode.BRTS -> regVar bld TF == AST.b1
      | Opcode.BRVC -> regVar bld VF == AST.b0
      | Opcode.BRVS -> regVar bld VF == AST.b1
      | _ -> raise InvalidOpcodeException
    let fallThrough = pc .+ numI32PC 2
    let jumpTarget = wrapPC pcMask (pc .+ dst .+ numI32PC 2)
    AST.intercjmp branchCond jumpTarget fallThrough
  }

let jmp ins len bld =
  lift bld ins len {
    let dst = transOneOpr ins bld
    AST.interjmp dst InterJmpKind.Base
  }

let mov ins len bld =
  lift bld ins len {
    let struct (dst, src) = transTwoOprs ins bld
    dst := src
  }

let movw (ins: Instruction) len bld =
  lift bld ins len {
    let struct (dst, dst1, src, src1) =
      match ins.Operands with
      | TwoOperands(OprReg reg1, OprReg reg2) ->
        let dst = reg1 |> regVar bld
        let dst1 =
          reg1 |> Register.toRegID |> int |> (fun n -> n + 1)
          |> RegisterID.create |> Register.ofRegID |> regVar bld
        let src = reg2 |> regVar bld
        let src1 =
          reg2 |> Register.toRegID |> int |> (fun n -> n + 1)
          |> RegisterID.create |> Register.ofRegID |> regVar bld
        struct (dst, dst1, src, src1)
      | _ ->
        raise InvalidOperandException
    dst := src
    dst1 := src1
  }

let neg ins len bld =
  lift bld ins len {
    let dst = transOneOpr ins bld
    let oprSize = 8<rt>
    let t1 = tmpVar bld oprSize
    t1 := AST.num0 oprSize .- dst
    (* H is set from bit 3 of the result or of the operand, so it has to be read
       before the result lands in the destination. *)
    regVar bld HF := AST.extract t1 1<rt> 3 .| AST.extract dst 1<rt> 3
    dst := t1
    regVar bld CF := t1 != AST.num0 oprSize
    regVar bld VF := t1 == numI32 0x80
    regVar bld NF := AST.xthi 1<rt> t1
    regVar bld ZF := t1 == AST.num0 oprSize
    regVar bld SF := regVar bld NF <+> regVar bld VF
  }

let nop insAddr len bld =
  liftAt bld insAddr len { }

let ``or`` ins len bld =
  lift bld ins len {
    let struct (dst, src) = transTwoOprs ins bld
    let oprSize = 8<rt>
    dst := dst .| src
    regVar bld ZF := dst == (AST.num0 oprSize)
    regVar bld NF := AST.xthi 1<rt> dst
    regVar bld VF := AST.b0
    regVar bld SF := regVar bld NF <+> regVar bld VF
  }

let rjmp pcMask ins len bld =
  lift bld ins len {
    let dst = transOneOpr ins bld
    let target = wrapPC pcMask (regVar bld PC .+ dst .+ numI32PC 2)
    AST.interjmp target InterJmpKind.Base
  }

let ror ins len bld =
  lift bld ins len {
    let dst = transOneOpr ins bld
    let oprSize = 8<rt>
    let t1 = tmpVar bld oprSize
    t1 := dst
    dst := t1 >> AST.num1 oprSize
    (AST.extract dst 1<rt> 7) := regVar bld CF
    regVar bld ZF := dst == (AST.num0 oprSize)
    regVar bld CF := AST.xtlo 1<rt> t1
    regVar bld NF := AST.xthi 1<rt> dst
    regVar bld VF := regVar bld NF <+> regVar bld CF
    regVar bld SF := regVar bld NF <+> regVar bld VF
  }

let sbc ins len bld =
  lift bld ins len {
    let struct(dst, src) = transTwoOprs ins bld
    let oprSize = 8<rt>
    let struct (t1, t2, t3) = tmpVars3 bld oprSize
    t1 := dst
    t2 := src
    t3 := t1 .- t2 .- AST.zext 8<rt> (regVar bld CF)
    dst := t3
    regVar bld HF := cfOnAdd (AST.extract t3 1<rt> 3)
                           (AST.extract t2 1<rt> 3)
                           (AST.extract t1 1<rt> 3)
    regVar bld CF := cfOnAdd t3 t2 t1
    regVar bld VF := ofOnAdd t3 t2 t1
    (* Z is cleared, never set, by a subtract-with-carry: it says the whole
       multi-byte result is zero, not just this byte of it. *)
    regVar bld ZF := (t3 == AST.num0 oprSize) .& regVar bld ZF
    regVar bld NF := AST.xthi 1<rt> t3
    regVar bld SF := regVar bld NF <+> regVar bld VF
  }

let sbiw (ins: Instruction) len bld =
  lift bld ins len {
    let struct (t1, t2) = tmpVars2 bld 8<rt>
    let t3 = tmpVar bld 16<rt>
    let struct (dst, dst1, src) =
      match ins.Operands with
      | TwoOperands(OprReg reg1, OprImm imm) ->
        let dst = reg1 |> regVar bld
        let dst1 =
          reg1 |> Register.toRegID |> int |> (fun n -> n + 1)
          |> RegisterID.create |> Register.ofRegID |> regVar bld
        let src = imm |> numI32
        struct (dst, dst1, src)
      | _ ->
        raise InvalidOperandException
    t1 := dst1
    t2 := dst
    t3 := (AST.concat t1 t2) .- AST.zext 16<rt> src
    dst1 := AST.extract t3 8<rt> 8
    dst := AST.extract t3 8<rt> 0
    regVar bld NF := AST.xthi 1<rt> dst1
    (* Subtracting a word overflows when the high bit was set and is not any
       more, and borrows the other way round -- the mirror of ADIW above. *)
    regVar bld VF := AST.xthi 1<rt> t1 .& AST.not (AST.xthi 1<rt> dst1)
    regVar bld ZF := t3 == (AST.num0 16<rt>)
    regVar bld CF := AST.xthi 1<rt> dst1 .& AST.not (AST.xthi 1<rt> t1)
    regVar bld SF := regVar bld NF <+> regVar bld VF
  }

let sf (ins: Instruction) len bld =
  lift bld ins len {
    let setFlag =
      match ins.Opcode with
      | Opcode.SEC -> regVar bld CF := AST.b1
      | Opcode.SEH -> regVar bld HF := AST.b1
      | Opcode.SEI -> regVar bld IF := AST.b1
      | Opcode.SEN -> regVar bld NF := AST.b1
      | Opcode.SES -> regVar bld SF := AST.b1
      | Opcode.SET -> regVar bld TF := AST.b1
      | Opcode.SEV -> regVar bld VF := AST.b1
      | Opcode.SEZ -> regVar bld ZF := AST.b1
      | _ -> raise InvalidOpcodeException
    setFlag
  }

let sub ins len bld =
  lift bld ins len {
    let struct(dst, src) = transTwoOprs ins bld
    let oprSize = 8<rt>
    let struct (t1, t2, t3) = tmpVars3 bld oprSize
    t1 := dst
    t2 := src
    t3 := t1 .- t2
    dst := t3
    regVar bld ZF := dst == AST.num0 oprSize
    regVar bld NF := AST.xtlo 1<rt> dst
    regVar bld HF := cfOnAdd t3 t2 t1
    regVar bld CF := cfOnAdd t3 t2 t1
    regVar bld VF := ofOnAdd t3 t2 t1
    regVar bld NF := AST.xthi 1<rt> t3
    regVar bld ZF := t3 == AST.num0 oprSize
    regVar bld SF := regVar bld NF <+> regVar bld VF
  }

let swap ins len bld =
  lift bld ins len {
    let dst = transOneOpr ins bld
    let t1 = tmpVar bld 8<rt>
    t1 := dst
    AST.extract t1 4<rt> 4 := AST.extract dst 4<rt> 0
    AST.extract t1 4<rt> 0 := AST.extract dst 4<rt> 4
    dst := t1
  }

let lac ins len bld =
  lift bld ins len {
    let struct (dst, src) = transTwoOprs ins bld
    let t1 = tmpVar bld 8<rt>
    t1 := dataMem dst
    dataMem dst := (numI32 0xff .- src) .& t1
    src := t1
  }

let las ins len bld =
  lift bld ins len {
    let struct (dst, src) = transTwoOprs ins bld
    let t1 = tmpVar bld 8<rt>
    t1 := dataMem dst
    dataMem dst := src .| t1
    src := t1
  }

let lat ins len bld =
  lift bld ins len {
    let struct (dst, src) = transTwoOprs ins bld
    let t1 = tmpVar bld 8<rt>
    t1 := dataMem dst
    dataMem dst := src <+> t1
    src := t1
  }

let ld ins len bld =
  lift bld ins len {
    let (dst, ptr, mode) = transMemOprToExpr ins bld
    let t = tmpVar bld 16<rt>
    match mode with
    | 0 ->
      dst := dataMem ptr
    | 1 ->
      t := ptr .+ numAddr 1
      dst := dataMem ptr
      setPtr bld ptr t
    | -1 ->
      t := ptr .- numAddr 1
      setPtr bld ptr t
      dst := dataMem ptr
    | _ ->
      Terminator.impossible ()
  }

let ldd ins len bld =
  lift bld ins len {
    let (dst, src, src1) = transMemOprToExpr1 ins bld
    dst := dataMem (src .+ src1)
  }

/// LPM reads the program space, so unlike every other load it takes no data
/// bias. Z is a byte address here, its low bit picking the half of the word.
let lpm (ins: Instruction) len bld =
  lift bld ins len {
    let z = regVar bld Z
    let at = AST.zext pcSize z
    let t = tmpVar bld 16<rt>
    match ins.Operands with
    | NoOperand ->
      regVar bld R0 := codeMem at
    | TwoOperands(OprReg reg, OprMemory(UnchMode _)) ->
      regVar bld reg := codeMem at
    | TwoOperands(OprReg reg, OprMemory(PostIdxMode _)) ->
      t := z .+ numAddr 1
      regVar bld reg := codeMem at
      setPtr bld z t
    | _ ->
      raise InvalidOperandException
  }

/// ELPM is LPM over an address RAMPZ extends past the 64 KiB Z alone reaches,
/// which is how a program on a larger core reads its far constants. Its
/// post-increment carries into RAMPZ, so walking a table across the boundary
/// works without the program touching RAMPZ itself.
let elpm (ins: Instruction) len bld =
  lift bld ins len {
    let addr = farAddr bld AddrRampz
    let t = tmpVar bld pcSize
    match ins.Operands with
    | NoOperand ->
      regVar bld R0 := codeMem addr
    | TwoOperands(OprReg reg, OprMemory(UnchMode _)) ->
      regVar bld reg := codeMem addr
    | TwoOperands(OprReg reg, OprMemory(PostIdxMode _)) ->
      t := addr .+ numI32PC 1
      regVar bld reg := codeMem addr
      setPtr bld (regVar bld Z) (AST.xtlo 16<rt> t)
      dataMem (numAddr AddrRampz) := AST.extract t 8<rt> 16
    | _ ->
      raise InvalidOperandException
  }

/// POP raises the stack pointer first and reads the byte it then points at,
/// which is the reverse of PUSH below.
let pop ins len bld =
  lift bld ins len {
    let dst = transOneOpr ins bld
    let sp = regVar bld SP
    let t = tmpVar bld 16<rt>
    t := sp .+ numAddr 1
    dst := dataMem t
    sp := t
  }

/// PUSH writes the byte where the stack pointer already points and lowers it
/// after, so the pointer always rests one below the newest entry.
let push ins len bld =
  lift bld ins len {
    let src = transOneOpr ins bld
    let sp = regVar bld SP
    dataMem sp := src
    sp := sp .- numAddr 1
  }

let ldi ins len bld =
  lift bld ins len {
    let struct(dst, src) = transTwoOprs ins bld
    dst := src
  }

let lds ins len bld =
  lift bld ins len {
    let struct (dst, src) = transTwoOprs ins bld
    dst := dataMem src
  }

let mul ins len bld =
  lift bld ins len {
    let struct(dst, src) = transTwoOprs ins bld
    let struct (t1, t2, t3) = tmpVars3 bld 16<rt>
    t1 := AST.zext 16<rt> dst
    t2 := AST.zext 16<rt> src
    t3 := t1 .* t2
    regVar bld R1 := AST.extract t3 8<rt> 8
    regVar bld R0 := AST.extract t3 8<rt> 0
    regVar bld CF := AST.extract t3 1<rt> 15
    regVar bld ZF := t3 == AST.num0 16<rt>
  }

let muls ins len bld =
  lift bld ins len {
    let struct(dst, src) = transTwoOprs ins bld
    let struct (t1, t2, t3) = tmpVars3 bld 16<rt>
    t1 := AST.sext 16<rt> dst
    t2 := AST.sext 16<rt> src
    t3 := t1 .* t2
    regVar bld R1 := AST.extract t3 8<rt> 8
    regVar bld R0 := AST.extract t3 8<rt> 0
    regVar bld CF := AST.extract t3 1<rt> 15
    regVar bld ZF := t3 == AST.num0 16<rt>
  }

let mulsu ins len bld =
  lift bld ins len {
    let struct(dst, src) = transTwoOprs ins bld
    let struct (t1, t2, t3) = tmpVars3 bld 16<rt>
    t1 := AST.sext 16<rt> dst
    t2 := AST.zext 16<rt> src
    t3 := t1 .* t2
    regVar bld R1 := AST.extract t3 8<rt> 8
    regVar bld R0 := AST.extract t3 8<rt> 0
    regVar bld CF := AST.extract t3 1<rt> 15
    regVar bld ZF := t3 == AST.num0 16<rt>
  }

/// RET raises the stack pointer by the bytes a call left and reads the word
/// address back from them, most significant byte first (see pushRet).
/// Reads the n bytes of a return address sitting at t into word, most
/// significant byte first (see pushRet). The loop stays out of the lift block,
/// where it would allocate an enumerator per lifted instruction.
let private popRetAddr bld t word n =
  append bld { word := AST.zext pcSize (dataMem t) }
  for i = 1 to n - 1 do
    let byteAt = AST.zext pcSize (dataMem (t .- numAddr i))
    append bld { word := word .| (byteAt << numI32PC (8 * i)) }

let ret core insAddr len opr bld =
  liftAt bld insAddr len {
    let sp = regVar bld SP
    let n = retBytes core
    let t = tmpVar bld 16<rt>
    let word = tmpVar bld pcSize
    t := sp .+ numAddr n
    popRetAddr bld t word n
    sp := t
    if opr = Opcode.RETI then regVar bld IF := AST.b1 else ()
    AST.interjmp (word << numI32PC 1) InterJmpKind.IsRet
  }

let rcall core pcMask ins len bld =
  lift bld ins len {
    let dst = transOneOpr ins bld
    let target = wrapPC pcMask (regVar bld PC .+ dst .+ numI32PC 2)
    pushRet core ins len bld
    AST.interjmp target InterJmpKind.IsCall
  }

let st ins len bld =
  lift bld ins len {
    let (ptr, src, mode) = transMemOprToExpr2 ins bld
    let t = tmpVar bld 16<rt>
    match mode with
    | 0 ->
      dataMem ptr := src
    | 1 ->
      t := ptr .+ numAddr 1
      dataMem ptr := src
      setPtr bld ptr t
    | -1 ->
      t := ptr .- numAddr 1
      setPtr bld ptr t
      dataMem ptr := src
    | _ ->
      Terminator.impossible ()
  }

let std ins len bld =
  lift bld ins len {
    let (dst, src, disp) = transMemOprToExpr3 ins bld
    dataMem (dst .+ disp) := src
  }

let sts ins len bld =
  lift bld ins len {
    let struct (dst, src) = transTwoOprs ins bld
    dataMem dst := src
  }

let des (ins: Instruction) len bld =
  lift bld ins len {
    AST.sideEffect UnsupportedInstruction
  }

let xch ins len bld =
  lift bld ins len {
    let struct (dst, src) = transTwoOprs ins bld
    let t1 = tmpVar bld 8<rt>
    t1 := dataMem dst
    dataMem dst := src
    src := t1
  }
