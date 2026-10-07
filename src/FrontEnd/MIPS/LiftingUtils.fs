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

module internal B2R2.FrontEnd.MIPS.LiftingUtils

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.MIPS

let inline (:=) dst src =
  match dst with
  | Var(RegisterID = rid) when rid = Register.toRegID Register.R0 ->
    dst := dst (* Prevent setting r0. Our optimizer will remove this anyways. *)
  | _ ->
    dst := src

let transOpr (ins: Instruction) bld = function
  | OpReg reg ->
    regVar bld reg
  | OpImm imm
  | OpShiftAmount imm ->
    numU64 imm bld.RegType
  | OpMem(b, Imm o, sz) ->
    loadNative bld sz (regVar bld b .+ numI64 o bld.RegType)
  | OpMem(b, Reg o, sz) ->
    loadNative bld sz (regVar bld b .+ regVar bld o)
  | OpAddr(Relative o) ->
    numI64 (int64 ins.Address + o) bld.RegType
  | OpAddr(Region idx) ->
    numU64 (JumpTarget.regionTarget ins.Address ins.WordSize idx) bld.RegType
  | OpRegList _
  | GoToLabel _ ->
    raise InvalidOperandException

let inline is32Bit (bld: ILowUIRBuilder) = bld.RegType = 32<rt>

let transOprToFPConvert (ins: Instruction) bld = function
  | OpReg reg ->
    if is32Bit bld then
      regVar bld reg
    else
      match ins.Fmt with
      | Some Fmt.S | Some Fmt.W -> regVar bld reg |> AST.xtlo 32<rt>
      | Some Fmt.D | Some Fmt.L -> regVar bld reg
      | _ -> raise InvalidOperandException
  | _ ->
    raise InvalidOperandException

let transOprToSingleFP bld = function
  | OpReg reg ->
    if is32Bit bld then regVar bld reg else regVar bld reg |> AST.xtlo 32<rt>
  | _ ->
    raise InvalidOperandException

let transTwoSingleFP bld (o1, o2) =
  transOprToSingleFP bld o1, transOprToSingleFP bld o2

let transThreeSingleFP bld (o1, o2, o3) =
  let o1 = transOprToSingleFP bld o1
  let o2 = transOprToSingleFP bld o2
  let o3 = transOprToSingleFP bld o3
  o1, o2, o3

let transFourSingleFP bld (o1, o2, o3, o4) =
  let o1 = transOprToSingleFP bld o1
  let o2 = transOprToSingleFP bld o2
  let o3 = transOprToSingleFP bld o3
  let o4 = transOprToSingleFP bld o4
  o1, o2, o3, o4

let transTwoOprFPConvert ins bld (o1, o2) =
  transOprToFPConvert ins bld o1, transOprToFPConvert ins bld o2

/// <summary>
/// Raised where a thirty-two bit FPU is asked for a double in an odd
/// register. Its doubles are register PAIRS, the even register and the one
/// above it, which is what Status.FR = 0 means; an odd register names no
/// pair, and MD00087 makes the operation UNPREDICTABLE. The lifter answers
/// it with a Reserved Instruction, which is what the reference raises.
/// </summary>
exception UnpairedRegisterException

/// The register that holds the upper half of the double whose lower half an
/// even register holds.
let private upperOfPair reg =
  match reg with
  | R.F1 | R.F3 | R.F5 | R.F7 | R.F9 | R.F11 | R.F13 | R.F15
  | R.F17 | R.F19 | R.F21 | R.F23 | R.F25 | R.F27 | R.F29 | R.F31 ->
    raise UnpairedRegisterException
  | _ ->
    RegisterHelper.getFPPairReg reg

let transOprToFPPair bld = function
  | OpReg reg ->
    if is32Bit bld then
      regVar bld (upperOfPair reg), regVar bld reg
    else
      (* On a 64-bit FPU the high half is a FIELD of the one register, not a
         register of its own. AST.b0 stood in for it, which broke both
         directions: MFHC1 read the high half as the constant zero, and MTHC1
         assigned to it -- an assignment to a constant, which AST.assign
         rejects outright. An Extract is both readable and assignable, and
         AST.assign rewrites `Extract(Var, 32, 32) := v` into the
         read-modify-write that MTHC1's own `newdata || olddata` asks for. *)
      AST.xthi 32<rt> (regVar bld reg), regVar bld reg
  | _ ->
    raise InvalidOperandException

let transOprToFPPairConcat bld = function
  | OpReg reg ->
    if is32Bit bld then
      AST.concat (regVar bld (upperOfPair reg)) (regVar bld reg)
    else
      regVar bld reg
  | _ ->
    raise InvalidOperandException

/// <summary>
/// The pair an FPR belongs to, upper register first, for the instructions
/// that move a double without reading it as a number: LDC1 and SDC1, MFHC1
/// and MTHC1, and the conditional moves. An odd register names no pair of
/// its own, which MD00087 makes UNPREDICTABLE; the reference moves the pair
/// it is the upper half of, and so does this.
/// </summary>
let transOprToFPPairHolding bld = function
  | OpReg reg when is32Bit bld ->
    let lower: Register = LanguagePrimitives.EnumOfValue(int reg &&& ~~~1)
    regVar bld (RegisterHelper.getFPPairReg lower), regVar bld lower
  | opr ->
    transOprToFPPair bld opr

/// The same pair as one value, upper half first.
let transOprToFPPairHoldingConcat bld opr =
  if is32Bit bld then
    let upper, lower = transOprToFPPairHolding bld opr
    AST.concat upper lower
  else
    transOprToFPPairConcat bld opr

/// Commit a double-precision result to its destination.
///
/// On o32 that destination is a PAIR of 32-bit registers, and the value goes
/// through a temporary first because the pair is very often the source as well
/// -- `sqrt.d $f12, $f12` is what a compiler emits for x = sqrt(x). Assigning
/// the low half straight from the result would change what the expression for
/// the high half then reads, and the answer would come back with its low
/// thirty-two bits right and its top ones computed from a value nobody wrote.
let writeFPResult dstB dstA result bld =
  if is32Bit bld then
    let value = tmpVar bld 64<rt>
    append bld {
      value := result
      dstA := AST.xtlo 32<rt> value
      dstB := AST.xthi 32<rt> value
    }
  else
    append bld { dstA := result }

let private fpneg bld oprSz reg =
  append bld {
    let mask =
      if oprSz = 32<rt> then numU64 0x80000000UL oprSz
      else numU64 0x8000000000000000UL oprSz
    reg := reg <+> mask
  }

let transOprToImm = function
  | OpImm imm
  | OpShiftAmount imm -> imm
  | _ -> raise InvalidOperandException

let transOprToImmToInt = function
  | OpImm imm
  | OpShiftAmount imm -> int imm
  | _ -> raise InvalidOperandException

let transOprToBaseOffset bld = function
  | OpMem(b, Imm o, _) -> regVar bld b .+ numI64 o bld.RegType
  | OpMem(b, Reg o, _) -> regVar bld b .+ regVar bld o
  | _ -> raise InvalidOperandException

let getOneOpr (ins: Instruction) =
  match ins.Operands with
  | OneOperand opr -> opr
  | _ -> raise InvalidOperandException

let getTwoOprs (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(o1, o2) -> o1, o2
  | _ -> raise InvalidOperandException

let getThreeOprs (ins: Instruction) =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) -> o1, o2, o3
  | _ -> raise InvalidOperandException

let getFourOprs (ins: Instruction) =
  match ins.Operands with
  | FourOperands(o1, o2, o3, o4) -> o1, o2, o3, o4
  | _ -> raise InvalidOperandException

let transOneOpr (ins: Instruction) bld =
  match ins.Operands with
  | OneOperand o -> transOpr ins bld o
  | _ -> raise InvalidOperandException

let transTwoOprs (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(o1, o2) -> transOpr ins bld o1, transOpr ins bld o2
  | _ -> raise InvalidOperandException

let transThreeOprs (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) ->
    let o1 = transOpr ins bld o1
    let o2 = transOpr ins bld o2
    let o3 = transOpr ins bld o3
    o1, o2, o3
  | _ ->
    raise InvalidOperandException

let transFourOprs (ins: Instruction) bld =
  match ins.Operands with
  | FourOperands(o1, o2, o3, o4) ->
    let o1 = transOpr ins bld o1
    let o2 = transOpr ins bld o2
    let o3 = transOpr ins bld o3
    let o4 = transOpr ins bld o4
    o1, o2, o3, o4
  | _ ->
    raise InvalidOperandException

let transFPConcatTwoOprs bld (o1, o2) =
  transOprToFPPairConcat bld o1, transOprToFPPairConcat bld o2

let transFPConcatThreeOprs bld (o1, o2, o3) =
  let o1 = transOprToFPPairConcat bld o1
  let o2 = transOprToFPPairConcat bld o2
  let o3 = transOprToFPPairConcat bld o3
  o1, o2, o3

/// <summary>
/// The source converted to an integer in whichever direction FCSR.RM names,
/// which is what a bare conversion is: an expression no <c>RoundCtrl</c>
/// encloses rounds by the target's own control register. The four directions
/// the field can name therefore need not be spelled out, nor the conversion
/// built four times over.
/// </summary>
let roundToInt src oprSz = AST.cast CastKind.FloatToSInt oprSz src

let private isSNaN32 signalBit nanCheck =
  nanCheck .& (signalBit == AST.num0 32<rt>)

let private isSNaN64 signalBit nanCheck =
  nanCheck .& (signalBit == AST.num0 64<rt>)

let private isQNaN32 signalBit nanCheck =
  nanCheck .& (signalBit != AST.num0 32<rt>)

let private isQNaN64 signalBit nanCheck =
  nanCheck .& (signalBit != AST.num0 64<rt>)

let isNaN oprSz fullExpo mantissa =
  match oprSz with
  | 32<rt> -> AST.xtlo 1<rt> (fullExpo .& (mantissa != AST.num0 32<rt>))
  | 64<rt> -> AST.xtlo 1<rt> (fullExpo .& (mantissa != AST.num0 64<rt>))
  | _ -> Terminator.impossible ()

let private isSNaN oprSz signalBit isNaN =
  match oprSz with
  | 32<rt> -> isSNaN32 signalBit isNaN
  | 64<rt> -> isSNaN64 signalBit isNaN
  | _ -> Terminator.impossible ()

let private isQNaN oprSz signalBit isNaN =
  match oprSz with
  | 32<rt> -> isQNaN32 signalBit isNaN
  | 64<rt> -> isQNaN64 signalBit isNaN
  | _ -> Terminator.impossible ()

let isInfinity oprSz fullExpo mantissa =
  match oprSz with
  | 32<rt> -> AST.xtlo 1<rt> (fullExpo .& (mantissa == AST.num0 32<rt>))
  | 64<rt> -> AST.xtlo 1<rt> (fullExpo .& (mantissa == AST.num0 64<rt>))
  | _ -> Terminator.impossible ()

let private isZero oprSz baseExpr =
  match oprSz with
  | 32<rt> ->
    let mask = numU32 0x7fffffffu 32<rt>
    AST.eq (baseExpr .& mask) (AST.num0 32<rt>)
  | 64<rt> ->
    let mask = numU64 0x7fffffff_ffffffffUL 64<rt>
    AST.eq (baseExpr .& mask) (AST.num0 64<rt>)
  | _ ->
    Terminator.impossible ()

let transBigEndianCPU (bld: ILowUIRBuilder) opSz =
  match bld.Endianness, opSz with
  | Endian.Little, 32<rt> -> AST.num0 32<rt>
  | Endian.Big, 32<rt> -> numI32 0b11 32<rt>
  | Endian.Little, 64<rt> -> AST.num0 64<rt>
  | Endian.Big, 64<rt> -> numI32 0b111 64<rt>
  | _ -> raise InvalidOperandException

let checkOverflowOnAdd e1 e2 r =
  let e1High = AST.extract e1 1<rt> 31
  let e2High = AST.extract e2 1<rt> 31
  let rHigh = AST.extract r 1<rt> 31
  (e1High == e2High) .& (e1High <+> rHigh)

let checkOverflowOnDadd e1 e2 r =
  let e1High = AST.extract e1 1<rt> 63
  let e2High = AST.extract e2 1<rt> 63
  let rHigh = AST.extract r 1<rt> 63
  (e1High == e2High) .& (e1High <+> rHigh)

/// Subtract overflows when the operands' signs DIFFER and the result takes
/// the subtrahend's. The add test asks the opposite of its first question,
/// which is the whole difference between the two.
let checkOverflowOnSub e1 e2 r =
  let e1High = AST.extract e1 1<rt> 31
  let e2High = AST.extract e2 1<rt> 31
  let rHigh = AST.extract r 1<rt> 31
  (e1High <+> e2High) .& (e1High <+> rHigh)

let checkOverflowOnDsub e1 e2 r =
  let e1High = AST.extract e1 1<rt> 63
  let e2High = AST.extract e2 1<rt> 63
  let rHigh = AST.extract r 1<rt> 63
  (e1High <+> e2High) .& (e1High <+> rHigh)

let getExponentFull src oprSz =
  if oprSz = 32<rt> then
    ((src >> numI32 23 32<rt>) .& numI32 0xff 32<rt>) == numI32 0xff 32<rt>
  else
    ((src >> numI32 52 64<rt>) .& numI32 0x7ff 64<rt>) == numI32 0x7ff 64<rt>

let getMantissa src oprSz =
  if oprSz = 32<rt> then src .& numU32 0x7fffffu 32<rt>
  else src .& numU64 0xfffff_ffffffffUL 64<rt>

let private getSignalBit src oprSz =
  if oprSz = 32<rt> then src .& numU32 (1u <<< 22) 32<rt>
  else src .& numU64 (1UL <<< 51) 64<rt>

/// <summary>
/// The kind of a jump into the compressed encoding of the processor an ISA
/// names: MIPS16e where it names MIPS16e, and microMIPS otherwise. No processor
/// has both, so the processor settles which one a compressed target is in.
/// </summary>
let compressedSwitch (bld: ILowUIRBuilder) =
  if bld.ISA.MIPSISAMode = MIPSISAMode.MIPS16 then InterJmpKind.SwitchToMIPS16
  else InterJmpKind.SwitchToMicroMIPS

/// <summary>
/// The jump a delay slot ends with, where the address it jumps to says which
/// encoding to read there.
///
/// Two jumps with the same target and different kinds, chosen on the bit an
/// instruction address cannot use. Nothing in the words at the target says
/// which encoding they belong to, so the kind is the only way an evaluator
/// following the program can be told -- and the address itself is handed over
/// with that bit cleared, which MD00076 requires: "Bit 0 of PC is loaded with
/// a 0, and no Address exception can occur".
/// </summary>
let interJmpByMode (bld: LowUIRBuilder) target kind =
  append bld {
    let lblCompressed = label bld "ToCompressed"
    let lblWide = label bld "ToMIPS32"
    let addr = target .& AST.not (AST.num1 bld.RegType)
    let compressed = AST.xtlo 1<rt> target
    AST.cjmp compressed (AST.jmpDest lblCompressed) (AST.jmpDest lblWide)
    AST.lmark lblCompressed
    AST.interjmp addr (kind ||| compressedSwitch bld)
    AST.lmark lblWide
    AST.interjmp addr (kind ||| InterJmpKind.SwitchToMIPS)
  }

let advancePC (bld: LowUIRBuilder) insLen =
  if bld.DelayedBranch = InterJmpKind.NotAJmp then
    (* Do nothing, because IEMark will advance PC. *)
    (bld :> ILowUIRBuilder).Stream.MarkEnd insLen
  else
    let nPC = regVar bld R.NPC
    (* A conditional branch that was not taken left this slot's own address
       behind, because where it continues is the end of the slot and the
       branch could not see how wide that is. See BranchFallsPastSlot. *)
    let target =
      if bld.BranchFallsPastSlot then
        let pc = regVar bld R.PC
        AST.ite (nPC == pc) (pc .+ numI32 (int insLen) bld.RegType) nPC
      else
        nPC
    if bld.BranchCarriesMode then
      interJmpByMode bld target bld.DelayedBranch
    else
      append bld { AST.interjmp target bld.DelayedBranch }
    bld.DelayedBranch <- InterJmpKind.NotAJmp
    bld.BranchCarriesMode <- false
    bld.BranchFallsPastSlot <- false

/// The Release 6 compact branches. A compact branch has no delay slot:
/// it takes effect at the branch itself, so the not-taken path is the
/// very next instruction rather than the one after a slot, and there is
/// nothing left armed for advancePC to consume. That is the whole of the
/// difference from updatePCCond below, which is why the two share a
/// shape and not a body.
let updatePCCondCompact (ins: Instruction) (bld: LowUIRBuilder) offset cond =
  let pc = regVar bld R.PC
  append bld {
    AST.intercjmp cond offset (pc .+ numI32 (int ins.Length) bld.RegType)
  }

/// <summary>
/// Where a conditional branch that was not taken continues.
///
/// In the 32-bit encoding that is a fixed PC+8, every instruction being a
/// word. In a compressed one it is the end of the delay slot, whose width the
/// branch cannot see -- so what goes here is the SLOT's own address, which
/// the slot turns into the address past itself. See BranchFallsPastSlot.
/// </summary>
let private notTaken (ins: Instruction) (bld: LowUIRBuilder) =
  let pc = regVar bld R.PC
  if ins.ISAMode = MIPSISAMode.MIPS then pc .+ numI32 8 bld.RegType
  else pc .+ numI32 (int ins.Length) bld.RegType

let updatePCCond (ins: Instruction) (bld: LowUIRBuilder) offset cond kind =
  append bld {
    let lblTrueCase = label bld "TrueCase"
    let lblFalseCase = label bld "FalseCase"
    let lblEnd = label bld "End"
    let nPC = regVar bld R.NPC
    bld.DelayedBranch <- kind
    bld.BranchFallsPastSlot <- ins.ISAMode <> MIPSISAMode.MIPS
    AST.cjmp cond (AST.jmpDest lblTrueCase) (AST.jmpDest lblFalseCase)
    AST.lmark lblTrueCase
    nPC := offset
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblFalseCase
    nPC := notTaken ins bld
    AST.lmark lblEnd
  }

/// A likely branch executes its delay slot only when the branch is taken, and
/// nullifies it otherwise. Nothing in the IR can reach forward and suppress the
/// next instruction, so the not-taken path leaves for PC+8 immediately: the
/// delay slot sits at PC+4 and is stepped over rather than executed, which is
/// what nullification means. The taken path arms the delayed branch exactly as
/// an ordinary branch does, so the slot runs and the transfer follows it.
///
/// This is why the two paths are not symmetric. `updatePCCond` can write NPC on
/// both arms and let the delay slot carry the transfer, because there the slot
/// runs either way; here it must not.
///
/// And it is why the marker `updatePCCond` uses cannot be used here. That one
/// works by leaving the answer to the delay slot, which is the only place the
/// slot's width is known; a nullified slot never runs, so there is nothing to
/// leave it to and PC+8 is the best this can do. A microMIPS branch-likely
/// whose slot is a halfword therefore resumes two bytes late. No compiler
/// writes one -- the family is gone in Release 6 and gcc does not emit it for
/// microMIPS -- so this is a known gap rather than a reachable defect.
let updatePCCondLikely (bld: LowUIRBuilder) offset cond kind =
  append bld {
    let lblTrueCase = label bld "TrueCase"
    let lblFalseCase = label bld "FalseCase"
    let lblEnd = label bld "End"
    let pc = regVar bld R.PC
    let nPC = regVar bld R.NPC
    bld.DelayedBranch <- kind
    AST.cjmp cond (AST.jmpDest lblTrueCase) (AST.jmpDest lblFalseCase)
    AST.lmark lblTrueCase
    nPC := offset
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblFalseCase
    nPC := pc .+ numI32 8 bld.RegType
    AST.interjmp nPC kind
    AST.lmark lblEnd
  }

let signExtLo64 expr = AST.xtlo 32<rt> expr |> AST.sext 64<rt>

let signExtHi64 expr = AST.xthi 32<rt> expr |> AST.sext 64<rt>

let getMask size = (1L <<< size) - 1L

let shifterLoad fstShf sndShf rRt t1 t2 t3 =
  (sndShf (fstShf rRt t1) t1) .| (fstShf t3 t2)

let shifterStore fstShf sndShf rRt t1 t2 t3 =
  (fstShf (sndShf t3 t2) t2) .| (sndShf rRt t1)

let mul64BitReg src1 src2 bld isSign =
  (* The full 64x64->128 product held in one wide temp, from which HI and LO
     are the high and low halves. The evaluator holds the 128-bit value, so the
     former hand-rolled 32-bit decomposition is unnecessary. *)
  let prod = tmpVar bld 128<rt>
  let ext = if isSign then AST.sext 128<rt> else AST.zext 128<rt>
  append bld {
    prod := ext src1 .* ext src2
  }
  struct (AST.xthi 64<rt> prod, AST.xtlo 64<rt> prod)

/// <summary>
/// Whether an instruction reaches the privileged state: the CP0 moves, the
/// TLB, cache and interrupt controls, the exception returns, WAIT, and the
/// EVA loads and stores, which reach user memory from the kernel. Each lists
/// Coprocessor Unusable among its exceptions.
/// </summary>
let usesCP0 = function
  | Op.MFC0 | Op.DMFC0 | Op.MFHC0 | Op.MTC0 | Op.DMTC0 | Op.MTHC0
  | Op.RDPGPR | Op.WRPGPR | Op.DI | Op.EI | Op.DVP | Op.EVP
  | Op.ERET | Op.ERETNC | Op.DERET | Op.WAIT
  | Op.CACHE | Op.CACHEE | Op.GINVI | Op.GINVT
  | Op.TLBWI | Op.TLBR | Op.TLBP | Op.TLBWR | Op.TLBINV | Op.TLBINVF
  | Op.LBE | Op.LBUE | Op.LHE | Op.LHUE | Op.LWE | Op.LWLE | Op.LWRE
  | Op.LLE | Op.LLWPE | Op.SBE | Op.SHE | Op.SWE | Op.SWLE | Op.SWRE
  | Op.SCE | Op.SCWPE | Op.PREFE -> true
  | _ -> false

/// <summary>
/// Refuses an instruction that reaches the privileged state where CP0 may
/// not be used, and returns the label the instruction ends at. MD00087 1.2
/// lets CP0 be used "in Kernel Mode or Debug Mode, or with the CP0 usable bit
/// set in the Status register"; Kernel Mode is Status.KSU zero, or EXL or ERL
/// set, and Debug Mode is never entered here. A refused instruction raises
/// Coprocessor Unusable and does nothing it would have done.
/// </summary>
let refuseOutsideKernel (bld: ILowUIRBuilder) =
  let status = regVar bld CP0Register.Status
  let bit n = AST.extract status 1<rt> n
  let ksu = AST.extract status 2<rt> 3
  let kernel = (ksu == AST.num0 2<rt>) .| bit 1 .| bit 2
  let lblRefuse = label bld "CpU"
  let lblRun = label bld "CP0"
  let lblEnd = label bld "End"
  append bld {
    AST.cjmp (kernel .| bit 28) (AST.jmpDest lblRun) (AST.jmpDest lblRefuse)
    AST.lmark lblRefuse
    AST.sideEffect UndefinedInstruction
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblRun
  }
  lblEnd

/// Provides the `lift` computation expression for MIPS, which closes an
/// instruction by advancing the PC rather than with a plain IEMark: an
/// ordinary instruction ends with an IEMark, and one sitting in the delay slot
/// of an armed branch ends with the transfer that branch deferred. It shadows
/// the one from LiftingUtils, so a lifter in this module gets the MIPS closing
/// without asking for it.
[<Struct>]
type LiftBuilder =
  /// Builder that the statements are emitted into.
  val Bld: ILowUIRBuilder

  /// Address of the instruction being lifted.
  val Address: Addr

  /// Length of the instruction being lifted.
  val InsLen: uint32

  /// Whether the instruction arms the delay slot that follows it.
  val ArmsDelaySlot: bool

  /// Whether the instruction reaches the privileged state, and so is refused
  /// before it does anything where CP0 may not be used.
  val UsesCP0: bool

  /// Creates a lift builder for the instruction at the given address.
  new(bld, addr, insLen, arms, cp0) =
    { Bld = bld
      Address = addr
      InsLen = insLen
      ArmsDelaySlot = arms
      UsesCP0 = cp0 }

  member inline _.Zero() = ()

  member inline _.Delay([<InlineIfLambda>] f: unit -> unit) = f

  member inline _.Combine((), [<InlineIfLambda>] f: unit -> unit) = f ()

  member inline this.Yield(stmt: Stmt) = this.Bld.Stream.Append stmt

  member inline _.For(xs: seq<'T>, [<InlineIfLambda>] f: 'T -> unit) =
    for x in xs do f x

  member inline _.While([<InlineIfLambda>] cond, [<InlineIfLambda>] body) =
    while cond () do body ()

  member inline this.Run([<InlineIfLambda>] f: unit -> unit) =
    this.Bld.Stream.MarkStart(this.Address, this.InsLen)
    let refused =
      if this.UsesCP0 then ValueSome(refuseOutsideKernel this.Bld)
      else ValueNone
    f ()
    match refused with
    | ValueSome lblEnd -> this.Bld.Stream.Append(AST.lmark lblEnd)
    | ValueNone -> ()
    if this.ArmsDelaySlot then this.Bld.Stream.MarkEnd this.InsLen
    else advancePC (this.Bld :?> LowUIRBuilder) this.InsLen
    this.Bld

/// Starts lifting an ordinary instruction, closing it by advancing the PC.
let inline lift bld (ins: Instruction) =
  LiftBuilder(bld, ins.Address, ins.Length, false, usesCP0 ins.Opcode)

/// Starts lifting a branch, which arms the delay slot that follows it. The
/// transfer belongs to that slot, so this one closes with a plain IEMark.
let inline liftTransfer bld (ins: Instruction) =
  LiftBuilder(bld, ins.Address, ins.Length, true, false)

let sideEffects (ins: Instruction) bld name =
  lift bld ins {
    AST.sideEffect name
  }

/// An instruction that is valid but outside what this lifter models, left to
/// the emulator to report rather than silently mis-executed.
let unsupported ins bld = sideEffects ins bld UnsupportedInstruction

/// <summary>
/// A fused multiply-add: <c>x * y + z</c> with a SINGLE rounding.
///
/// It is one operation and not a multiply followed by an add. The product is
/// kept exact and rounded once with the sum, where a multiply and an add
/// round twice, and the two answers differ whenever the product is not
/// exactly representable -- by a unit in the last place usually, and by far
/// more where the addition cancels. This architecture carries both a fused
/// and an unfused multiply-add, so it is telling the two apart, and writing
/// the fused one as the unfused pair lifts the wrong instruction.
///
/// It goes out as a named call because that is what the IR already offers for
/// an operation of three arguments. The negations ride along as a flag rather
/// than being applied to the operands: a negation flips a sign bit, and
/// flipping a NaN operand's sign before the operation would change which NaN
/// the answer carries. Bit 0 of the flag negates the product and bit 1 the
/// addend.
/// </summary>
let fma sz negProduct negAddend x y z =
  let prodBit = if negProduct then 1UL else 0UL
  let addBit = if negAddend then 2UL else 0UL
  let args = [ x; y; z; numU64 (prodBit ||| addBit) 8<rt> ]
  let name =
    match sz with
    | 32<rt> -> "FMA32"
    | 64<rt> -> "FMA64"
    | _ -> raise InvalidRegTypeException
  AST.app name args sz

/// <summary>
/// The arithmetic an IEEE exception can be raised by.
///
/// Which operation it was is what the evaluator is asked about with the
/// operands, and the divide is the only one of the five that can raise the
/// zero divide.
/// </summary>
type FPArith =
  | FPAdd
  | FPSub
  | FPMul
  | FPDiv
  | FPSqrt

/// The sign bit of a width.
let private signBitOfWidth oprSz =
  if oprSz = 32<rt> then numU32 0x80000000u 32<rt>
  else numU64 0x8000000000000000UL 64<rt>

/// Everything below the sign bit, which is the magnitude.
let private magnitudeOfWidth oprSz =
  if oprSz = 32<rt> then numU32 0x7fffffffu 32<rt>
  else numU64 0x7fffffff_ffffffffUL 64<rt>

/// The biased exponent as a number, which is zero for a subnormal and for a
/// zero, and all ones for an infinity and for a NaN.
let private biasedExponent oprSz v =
  if oprSz = 32<rt> then (v >> numI32 23 32<rt>) .& numI32 0xff 32<rt>
  else (v >> numI32 52 64<rt>) .& numI32 0x7ff 64<rt>

/// The value that exponent holds for an infinity and for a NaN.
let private exponentAllOnes oprSz =
  if oprSz = 32<rt> then numI32 0xff 32<rt> else numI32 0x7ff 64<rt>

/// The leading mantissa bit, which is the one that tells a quiet NaN from a
/// signalling one -- in whichever direction the guest has selected.
let private quietBitOfWidth oprSz =
  if oprSz = 32<rt> then numU32 0x400000u 32<rt>
  else numU64 0x8000000000000UL 64<rt>

/// A NaN by its bits: the exponent all ones and a mantissa that is not zero.
let private fpIsNaN oprSz v =
  (biasedExponent oprSz v == exponentAllOnes oprSz)
  .& (getMantissa v oprSz != AST.num0 oprSz)

/// An infinity by its bits: the same exponent and a mantissa that is zero.
let private fpIsInfinite oprSz v =
  (biasedExponent oprSz v == exponentAllOnes oprSz)
  .& (getMantissa v oprSz == AST.num0 oprSz)

/// Either zero, whose sign this does not ask about.
let private fpIsZero oprSz v =
  (v .& magnitudeOfWidth oprSz) == AST.num0 oprSz

/// <summary>
/// Whether the guest is on the IEEE-2008 side of the NaN encoding.
///
/// Which leading mantissa bit means which is not fixed. IEEE-2008 reads a set
/// bit as quiet; MIPS before that release read it the other way round, its
/// default NaN being 0x7fbfffff, whose leading mantissa bit is clear.
///
/// Release 6 settled it: NAN2008 is read-only ONE there, so the question has
/// an answer before the register is read and the bit cannot say otherwise.
/// Earlier releases leave it to the processor, and there FCSR bit 18 is what
/// says which side the guest is on.
/// </summary>
let fpNaN2008 (bld: ILowUIRBuilder) =
  if bld.ISA.MIPSRelease = MIPSRelease.R6 then AST.b1
  else (regVar bld R.FCSR .& numU32 0x40000u 32<rt>) != AST.num0 32<rt>

/// Whether the value is a NaN this guest reads as signalling.
let private fpIsSignalling bld oprSz v =
  let quiet = (v .& quietBitOfWidth oprSz) != AST.num0 oprSz
  fpIsNaN oprSz v .& AST.ite (fpNaN2008 bld) (AST.not quiet) quiet

/// <summary>
/// The NaN MIPS answers before NAN2008, wherever an operation is invalid or
/// has met a NaN: 0x7fbfffff at single precision and 0x7ff7ffffffffffff at
/// double. It is that value whatever the operands were, and it is positive,
/// so it replaces whatever NaN the host arithmetic produced.
/// </summary>
let private fpLegacyNaN oprSz =
  if oprSz = 32<rt> then numU32 0x7fbfffffu 32<rt>
  else numU64 0x7ff7ffffffffffffUL 64<rt>

/// <summary>
/// The NaN an arithmetic operation answers, put in place of whatever NaN the
/// host's arithmetic made: the default one before NAN2008, and with NAN2008,
/// which Release 6 always has, what IEEE-2008 propagates -- the first
/// signalling operand quieted, else the first quiet one as it is, and the
/// default NaN, 0x7fc00000 or 0x7ff8000000000000, only where no operand
/// brought one. The host picks among NaN operands by a rule of its own, so
/// the choice is made here.
/// </summary>
let fpSettleNaN bld oprSz operands result =
  let quietBit = quietBitOfWidth oprSz
  let fresh =
    if oprSz = 32<rt> then numU32 0x7fc00000u 32<rt>
    else numU64 0x7ff8000000000000UL 64<rt>
  let signalling v = fpIsNaN oprSz v .& ((v .& quietBit) == AST.num0 oprSz)
  let pickQuiet v rest = AST.ite (fpIsNaN oprSz v) v rest
  let pickSignalling v rest = AST.ite (signalling v) (v .| quietBit) rest
  let quiet = List.foldBack pickQuiet operands fresh
  let propagated = List.foldBack pickSignalling operands quiet
  let settled = AST.ite (fpNaN2008 bld) propagated (fpLegacyNaN oprSz)
  append bld {
    result := AST.ite (fpIsNaN oprSz result) settled result
  }

/// <summary>
/// The NaN a conversion between the two formats answers: the default one
/// before NAN2008, and with it the operand's own, quieted, with its payload
/// cut or extended -- which is what the host's conversion makes of it.
/// </summary>
let fpSettleConvertedNaN bld oprSz result =
  let replaced = fpIsNaN oprSz result .& AST.not (fpNaN2008 bld)
  append bld {
    result := AST.ite replaced (fpLegacyNaN oprSz) result
  }

/// The operation codes of the exception query, which are the evaluator's
/// contract.
let private fpExcCode = function
  | FPAdd -> 0UL
  | FPSub -> 1UL
  | FPMul -> 2UL
  | FPDiv -> 3UL
  | FPSqrt -> 4UL

/// The fused multiply-add's code in the same query.
let private fpExcFused = 8UL

/// <summary>
/// What the query is asked beyond the operation where FCSR.FS is decided:
/// tininess BEFORE rounding (0x40), which is where the reference flushes. The
/// exceptions themselves are asked without it, since MIPS decides tininess
/// after rounding, and the query answers in FCSR's own order: Invalid highest
/// and Inexact lowest.
/// </summary>
let private fpExcBeforeRounding = 0x40UL

let private fpExcName oprSz = if oprSz = 32<rt> then "FEXC32" else "FEXC64"

/// Asks the evaluator what an operation raised.
let private fpQuery oprSz code args =
  AST.app (fpExcName oprSz) (numU64 code 8<rt> :: args) 32<rt>

/// The five exceptions as the bits FCSR keeps them in -- Invalid highest and
/// Inexact lowest -- from one-bit conditions.
let private fpBits invalid divZero overflow underflow inexact =
  (AST.zext 32<rt> invalid << numI32 4 32<rt>)
  .| (AST.zext 32<rt> divZero << numI32 3 32<rt>)
  .| (AST.zext 32<rt> overflow << numI32 2 32<rt>)
  .| (AST.zext 32<rt> underflow << numI32 1 32<rt>)
  .| AST.zext 32<rt> inexact

/// Nothing raised, for the exceptions an operation cannot have.
let private fpNone = AST.num0 1<rt>

/// Whether either operand is a NaN this guest reads as signalling, which is
/// the one thing an operation that does not round can still raise.
let fpEitherSignalling bld oprSz a b =
  fpIsSignalling bld oprSz a .| fpIsSignalling bld oprSz b

/// FCSR.FS, flush subnormal results to zero.
let private fpFlushing bld =
  AST.xtlo 1<rt> (regVar bld R.FCSR >> numI32 24 32<rt>)

/// A subnormal by its bits: the exponent zero and the value not.
let private fpIsSubnormal oprSz v =
  (biasedExponent oprSz v == AST.num0 oprSz) .& AST.not (fpIsZero oprSz v)

/// <summary>
/// FCSR.FS applied to a result, and to what its operation raised.
///
/// With FS set, a result whose exact value was below the smallest normal
/// becomes a zero of its own sign, and the operation raises nothing: the
/// reference decides it before rounding, so an answer that rounds up to the
/// smallest normal is flushed as well, and the Underflow and Inexact the
/// rounding would have raised go with it. The operands are not flushed.
/// MD00087 says they are, for MADDF.fmt, but the reference reads them as
/// they are, and only it can be measured against.
///
/// The exact value was tiny where the answer came out subnormal, or where
/// the query, asked to decide tininess before rounding, says the operation
/// underflowed: an inexact answer that rounded to zero, or up to the
/// smallest normal. The query is asked only under FS -- an if, unlike an
/// and, leaves the other side unevaluated -- so an operation pays for it
/// only where it can matter.
/// </summary>
let private fpFlushOut bld oprSz tinyQuery result raised =
  let flushed = tmpVar bld 1<rt>
  let underflow = AST.xtlo 1<rt> (tinyQuery >> AST.num1 32<rt>)
  let tiny = fpIsSubnormal oprSz result .| underflow
  append bld {
    flushed := AST.ite (fpFlushing bld) tiny AST.b0
    result := AST.ite flushed (result .& signBitOfWidth oprSz) result
  }
  AST.ite flushed (AST.num0 32<rt>) raised

/// <summary>
/// The exceptions an arithmetic operation raised, as the five bits FCSR
/// keeps them in, with FCSR.FS applied to its result -- so this is asked
/// before the result is written or read again.
///
/// Three of the five are about the rounding -- whether it lost anything,
/// whether the answer was tiny, whether it was past the range -- and an
/// answer does not say: an inexact sum and an exact one look the same. So
/// the question goes to the evaluator as a named call, which works the
/// operation out again with its exact error in hand, in the direction
/// FCSR.RM names.
///
/// Where the answer is a NaN the operation either met one or made one, and
/// Invalid is all there is to decide: a NaN this guest reads as signalling
/// raises it, which the evaluator cannot tell on the legacy encoding, and so
/// does a NaN nothing brought in, which is what an invalid operation makes.
/// That is asked here instead, under an ite only a NaN answer takes.
///
/// The square root reads one operand, and its caller passes that one twice.
/// </summary>
let fpRaised bld oprSz op src1 src2 result =
  let raised = tmpVar bld 32<rt>
  let code = fpExcCode op
  let nanIn = fpIsNaN oprSz src1 .| fpIsNaN oprSz src2
  let invalid = fpEitherSignalling bld oprSz src1 src2 .| AST.not nanIn
  let made = fpBits invalid fpNone fpNone fpNone fpNone
  append bld {
    raised :=
      AST.ite (fpIsNaN oprSz result) made (fpQuery oprSz code [ src1; src2 ])
  }
  let tiny = fpQuery oprSz (code ||| fpExcBeforeRounding) [ src1; src2 ]
  fpFlushOut bld oprSz tiny result raised

/// <summary>
/// Records in FCSR the IEEE exceptions an arithmetic operation raised.
///
/// MIPS keeps them three times over. Cause holds what THIS instruction
/// raised and is written whole by every one of them; Enables says which of
/// the five trap; Flags accumulates the ones that did not, until software
/// clears it. An instruction that traps never reaches the next one, so what
/// is modelled here is the untrapped case -- Cause takes everything raised,
/// and Flags takes what is not enabled.
/// </summary>
let fpRecord bld raised =
  let fcsr = regVar bld R.FCSR
  let enabled = (fcsr >> numI32 7 32<rt>) .& numI32 0x1f 32<rt>
  append bld {
    fcsr :=
      (fcsr .& numU32 0xfffc0fffu 32<rt>)
      .| (raised << numI32 12 32<rt>)
      .| ((raised .& AST.not enabled) << numI32 2 32<rt>)
  }

let fpExceptions bld oprSz op src1 src2 result =
  fpRecord bld (fpRaised bld oprSz op src1 src2 result)

/// FCSR.FS applied to a result that was chosen rather than rounded: MIN.fmt
/// and its kind answer one of their operands, and the reference still writes
/// that back through its rounding, so under FS a subnormal one comes out a
/// zero of its own sign. Nothing is raised for it.
let fpFlushChosen bld oprSz result =
  let flushed = fpFlushing bld .& fpIsSubnormal oprSz result
  append bld {
    result := AST.ite flushed (result .& signBitOfWidth oprSz) result
  }

/// <summary>
/// What a conversion to an INTEGER raises, which is two of the five and
/// neither of them a rounding of the kind the arithmetic does.
///
/// Invalid is the operand having no integer at all -- a NaN, an infinity, or
/// a magnitude the destination cannot hold -- which the architecture answers
/// with a default result rather than with a number, and which the caller has
/// already worked out to choose that result.
///
/// Inexact is the operand having a fraction for the conversion to discard,
/// and it is asked of the OPERAND rather than of the answer: every rounding
/// leaves an exact integer alone, so which direction the instruction rounds
/// in does not come into it.
/// </summary>
let fpExceptionsToInt bld oprSz src noInteger =
  let struct (invalid, inexact) = tmpVars2 bld 1<rt>
  append bld {
    invalid := noInteger
    inexact :=
      AST.not invalid
      .& (AST.roundToIntegral RoundingMode.TowardZero oprSz src != src)
  }
  fpRecord bld (fpBits invalid fpNone fpNone fpNone inexact)

/// What widening a single to a double raises: Invalid for a signalling NaN,
/// and nothing else, since every single is a double exactly.
let fpExceptionsWiden bld src =
  let invalid = fpIsSignalling bld 32<rt> src
  fpRecord bld (fpBits invalid fpNone fpNone fpNone fpNone)

/// Two to the 64th, by which a double is scaled to ask how it rounds to a
/// single's precision with no bound on the exponent.
let private twoTo64 = numU64 0x43f0000000000000UL 64<rt>

/// <summary>
/// What narrowing a double to a single raised, with FCSR.FS applied to the
/// result.
///
/// The answer widened back is exact, so it is inexact where that does not
/// give the operand. Overflow is asked of the operand, which is the exact
/// value: out of range from two to the 128th whichever way the rounding
/// went, or wherever the rounding made an infinity of it. Tininess is
/// decided after rounding, as MIPS decides it -- on the operand rounded to a
/// single's precision with no bound on the exponent, which is the operand
/// scaled up by two to the 64th, exactly, and narrowed there: tiny below two
/// to the -62nd. Under FS, an operand below the smallest normal single
/// flushes the answer to a zero of its sign, raising nothing.
/// </summary>
let fpExceptionsNarrow bld src result =
  let struct (overflow, underflow, inexact) = tmpVars3 bld 1<rt>
  let struct (finiteIn, flushed) = tmpVars2 bld 1<rt>
  let rt = 64<rt>
  let magnitude = src .& magnitudeOfWidth rt
  let beyond = magnitude .>= numU64 0x47f0000000000000UL rt
  let tinyIn = magnitude .< numU64 0x3810000000000000UL rt
  let scaled = AST.cast CastKind.FloatCast 32<rt> (AST.fmul src twoTo64)
  let tinyOut =
    (scaled .& magnitudeOfWidth 32<rt>) .< numU32 0x20800000u 32<rt>
  let back = AST.cast CastKind.FloatCast rt result
  append bld {
    finiteIn := AST.not (fpIsNaN rt src .| fpIsInfinite rt src)
    overflow := finiteIn .& (beyond .| fpIsInfinite 32<rt> result)
    inexact := finiteIn .& (overflow .| (back != src))
    underflow := inexact .& AST.not overflow .& tinyOut
    flushed := fpFlushing bld .& tinyIn .& AST.not (fpIsZero rt src)
    result := AST.ite flushed (result .& signBitOfWidth 32<rt>) result
  }
  let invalid = fpIsSignalling bld rt src
  let raised = fpBits invalid fpNone overflow underflow inexact
  fpRecord bld (AST.ite flushed (AST.num0 32<rt>) raised)

/// <summary>
/// What a conversion FROM an integer raises, which is Inexact and nothing
/// else.
///
/// An integer is never a NaN and never an infinity, and every one of them is
/// inside the range of both floating formats, so the only thing such a
/// conversion can do is round -- and whether it did is asked by converting
/// the answer back and seeing whether the integer comes out.
/// </summary>
let fpExceptionsFromInt bld src back =
  let inexact = tmpVar bld 1<rt>
  append bld {
    inexact := back != src
  }
  fpRecord bld (fpBits fpNone fpNone fpNone fpNone inexact)

/// <summary>
/// Whether a comparison of these two operands raises Invalid.
///
/// A signalling NaN always does. A quiet one does only where the predicate is
/// one of the signalling half -- the manual gives every condition two
/// spellings for exactly this, one that signals on an unordered comparison
/// and one that does not -- which is what the caller passes here.
/// </summary>
let fpCompareInvalid bld oprSz signalsOnQuiet a b =
  if signalsOnQuiet then fpIsNaN oprSz a .| fpIsNaN oprSz b
  else fpIsSignalling bld oprSz a .| fpIsSignalling bld oprSz b

/// Whether the value was changed by being rounded to an integer, which is
/// what RINT can lose. An operand that is already one loses nothing whichever
/// direction the rounding goes in.
let fpRoundChanged bld oprSz src result =
  AST.not (fpIsNaN oprSz src .| fpIsInfinite oprSz src) .& (result != src)

/// <summary>
/// What a FUSED multiply-add raised, x times y plus z with the product
/// negated first where asked, with FCSR.FS applied to its result.
///
/// It is one operation with one rounding, so it is not the union of a
/// multiply's exceptions and an add's -- an intermediate product that would
/// have overflowed on its own does not overflow here, because there is no
/// intermediate product -- and a zero times an infinity raises Invalid even
/// with a quiet NaN to add, as the reference has it. The query's fused form
/// answers for both. Only Release 6 has the instruction, and it reads a
/// NaN's quiet bit the way the evaluator does, so no NaN needs asking about
/// here.
/// </summary>
let fpExceptionsFused bld oprSz negProduct x y z result =
  let flag = if negProduct then 1UL else 0UL
  let ask flags =
    fpQuery oprSz fpExcFused [ x; y; z; numU64 flags 8<rt> ]
  let tiny = ask (flag ||| fpExcBeforeRounding)
  fpRecord bld (fpFlushOut bld oprSz tiny result (ask flag))

/// What an operation raises where rounding is all it can lose: Invalid for a
/// signalling operand and Inexact for a result that was rounded. Nothing it
/// answers can overflow or be subnormal, so the other three cannot happen.
let fpExceptionsRounded bld invalid inexact =
  fpRecord bld (fpBits invalid fpNone fpNone fpNone inexact)

/// <summary>
/// What an operation raises where the only thing it can raise is Invalid.
///
/// The comparisons are the family: they answer a condition rather than a
/// number, so nothing is rounded and nothing overflows, and the one thing
/// that can go wrong is being asked to order a NaN. A signalling one always
/// signals; a quiet one signals only where the predicate is one of the
/// signalling half, which is what the manual's ordered conditions are.
/// </summary>
let fpExceptionsInvalidOnly bld invalid =
  fpRecord bld (fpBits invalid fpNone fpNone fpNone fpNone)
