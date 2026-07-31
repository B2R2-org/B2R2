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

module internal B2R2.Assembly.Intel.AsmMain

open System
open B2R2
open B2R2.Assembly.BinLowerer
open B2R2.FrontEnd.Intel
open B2R2.Assembly.Intel.ParserHelper
open B2R2.Assembly.Intel.AsmPrefix
open B2R2.Assembly.Intel.AsmOpcode

type UserState =
  { /// Label string to an index of an instruction. The index starts from zero,
    /// and labels do not increase the index.
    LabelMap: Map<string, int>
    /// Current instruction index. This will change as we encounter an
    /// instruction, but labels would not change this.
    CurIndex: int }

let private isMemorySizeExceptionOpcode = function
  | Opcode.MOV -> true
  | _ -> false

let private checkMissingMemoryOperandSize (ins: AsmInsInfo) =
  if isMemorySizeExceptionOpcode ins.Opcode then ()
  else
    match ins.Operands with
    | OneOperand(OprMem(_, _, _, 0<rt>))
    | TwoOperands(OprMem(_, _, _, 0<rt>), _)
    | TwoOperands(_, OprMem(_, _, _, 0<rt>))
    | ThreeOperands(OprMem(_, _, _, 0<rt>), _, _)
    | ThreeOperands(_, OprMem(_, _, _, 0<rt>), _)
    | ThreeOperands(_, _, OprMem(_, _, _, 0<rt>))
    | FourOperands(_, _, OprMem(_, _, _, 0<rt>), _) ->
      raise <| EncodingFailureException "Memory operand size is required."
    | _ -> ()

/// Rejects a memory operand addressed through 16-bit registers. That form
/// needs the 16-bit ModRM layout, which this assembler does not emit; without
/// the check the operand is encoded as though the registers were 32-bit ones
/// sharing their numbers, which silently addresses somewhere else entirely.
let private checkAddressingMode wordSz (ins: AsmInsInfo) =
  let isAddressable16 reg = isReg16 wordSz reg
  let uses16BitAddress = function
    | OprMem(baseReg, scaledIdx, _, _) ->
      Option.exists isAddressable16 baseReg
      || Option.exists (fst >> isAddressable16) scaledIdx
    | _ -> false
  if getOperandsAsList ins.Operands |> List.exists uses16BitAddress then
    raise <| EncodingFailureException "16-bit addressing is not supported"
  else ()

let encodeInstruction ins wordSz =
  checkMissingMemoryOperandSize ins
  checkGroup1Prefix ins
  checkAddressingMode wordSz ins
  match ins.Opcode with
  | Opcode.AAA -> aaa wordSz ins.Operands
  | Opcode.AAD -> aad wordSz ins.Operands
  | Opcode.AAM -> aam wordSz ins.Operands
  | Opcode.AAS -> aas wordSz ins.Operands
  | Opcode.ADC -> adc wordSz ins
  | Opcode.ADD -> add wordSz ins
  | Opcode.ADDPD -> addpd wordSz ins
  | Opcode.ADDPS -> addps wordSz ins
  | Opcode.ADDSD -> addsd wordSz ins
  | Opcode.ADDSS -> addss wordSz ins
  | Opcode.AND -> logAnd wordSz ins
  | Opcode.ANDPD -> andpd wordSz ins
  | Opcode.ANDPS -> andps wordSz ins
  | Opcode.BSR -> bsr wordSz ins
  | Opcode.BT -> bt wordSz ins
  | Opcode.CALL -> call wordSz ins
  | Opcode.CBW -> cbw wordSz ins.Operands
  | Opcode.CDQ -> cdq wordSz ins.Operands
  | Opcode.CDQE -> cdqe wordSz ins.Operands
  | Opcode.CMOVA -> cmova wordSz ins
  | Opcode.CMOVAE -> cmovae wordSz ins
  | Opcode.CMOVB -> cmovb wordSz ins
  | Opcode.CMOVBE -> cmovbe wordSz ins
  | Opcode.CMOVG -> cmovg wordSz ins
  | Opcode.CMOVGE -> cmovge wordSz ins
  | Opcode.CMOVL -> cmovl wordSz ins
  | Opcode.CMOVLE -> cmovle wordSz ins
  | Opcode.CMOVNO -> cmovno wordSz ins
  | Opcode.CMOVNP -> cmovnp wordSz ins
  | Opcode.CMOVNS -> cmovns wordSz ins
  | Opcode.CMOVNZ -> cmovnz wordSz ins
  | Opcode.CMOVO -> cmovo wordSz ins
  | Opcode.CMOVP -> cmovp wordSz ins
  | Opcode.CMOVS -> cmovs wordSz ins
  | Opcode.CMOVZ -> cmovz wordSz ins
  | Opcode.CMP -> cmp wordSz ins
  | Opcode.CMPSB -> cmpsb wordSz ins
  | Opcode.CMPXCHG -> cmpxchg wordSz ins
  | Opcode.CMPXCHG8B -> cmpxchg8b wordSz ins
  | Opcode.CMPXCHG16B -> cmpxchg16b wordSz ins
  | Opcode.CVTSD2SS -> cvtsd2ss wordSz ins
  | Opcode.CVTSI2SD -> cvtsi2sd wordSz ins
  | Opcode.CVTSI2SS -> cvtsi2ss wordSz ins
  | Opcode.CVTSS2SI -> cvtss2si wordSz ins
  | Opcode.CVTTSS2SI -> cvttss2si wordSz ins
  | Opcode.CWDE -> cwde wordSz ins.Operands
  | Opcode.DEC -> dec wordSz ins
  | Opcode.DIV -> div wordSz ins
  | Opcode.DIVSD -> divsd wordSz ins
  | Opcode.DIVSS -> divss wordSz ins
  | Opcode.FADD -> fadd wordSz ins
  | Opcode.FCMOVB -> fcmovb wordSz ins
  | Opcode.FDIV -> fdiv wordSz ins
  | Opcode.FDIVP -> fdivp wordSz ins.Operands
  | Opcode.FDIVRP -> fdivrp wordSz ins.Operands
  | Opcode.FILD -> fild wordSz ins
  | Opcode.FISTP -> fistp wordSz ins
  | Opcode.FLD -> fld wordSz ins
  | Opcode.FLD1 -> fld1 wordSz ins.Operands
  | Opcode.FLDCW -> fldcw wordSz ins
  | Opcode.FLDZ -> fldz wordSz ins.Operands
  | Opcode.FMUL -> fmul wordSz ins
  | Opcode.FMULP -> fmulp wordSz ins.Operands
  | Opcode.FNSTCW -> fnstcw wordSz ins
  | Opcode.FSTP -> fstp wordSz ins
  | Opcode.FSUB -> fsub wordSz ins
  | Opcode.FSUBR -> fsubr wordSz ins
  | Opcode.FUCOMI -> fucomi wordSz ins.Operands
  | Opcode.FUCOMIP -> fucomip wordSz ins.Operands
  | Opcode.FXCH -> fxch wordSz ins.Operands
  | Opcode.HLT -> hlt wordSz ins.Operands
  | Opcode.IDIV -> idiv wordSz ins
  | Opcode.IMUL -> imul wordSz ins
  | Opcode.INC -> inc wordSz ins
  | Opcode.INT -> interrupt ins
  | Opcode.INT3 -> interrupt3 ()
  | Opcode.JA -> jcc wordSz ins
  | Opcode.JB -> jcc wordSz ins
  | Opcode.JBE -> jcc wordSz ins
  | Opcode.JG -> jcc wordSz ins
  | Opcode.JL -> jcc wordSz ins
  | Opcode.JLE -> jcc wordSz ins
  | Opcode.JNB -> jcc wordSz ins
  | Opcode.JNL -> jcc wordSz ins
  | Opcode.JNO -> jcc wordSz ins
  | Opcode.JNP -> jcc wordSz ins
  | Opcode.JNS -> jcc wordSz ins
  | Opcode.JNZ -> jcc wordSz ins
  | Opcode.JO -> jcc wordSz ins
  | Opcode.JP -> jcc wordSz ins
  | Opcode.JS -> jcc wordSz ins
  | Opcode.JZ -> jcc wordSz ins
  | Opcode.JMP -> jmp wordSz ins
  | Opcode.LAHF -> lahf wordSz ins.Operands
  | Opcode.LEA -> lea wordSz ins
  | Opcode.LEAVE -> leave wordSz ins.Operands
  | Opcode.MOV -> mov wordSz ins
  | Opcode.MOVAPS -> movaps wordSz ins
  | Opcode.MOVD -> movd wordSz ins
  | Opcode.MOVDQA -> movdqa wordSz ins
  | Opcode.MOVDQU -> movdqu wordSz ins
  | Opcode.MOVSD -> movsd wordSz ins
  | Opcode.MOVSS -> movss wordSz ins
  | Opcode.MOVSX -> movsx wordSz ins
  | Opcode.MOVSXD -> movsxd wordSz ins
  | Opcode.MOVUPS -> movups wordSz ins
  | Opcode.MOVZX -> movzx wordSz ins
  | Opcode.MUL -> mul wordSz ins
  | Opcode.MULSD -> mulsd wordSz ins
  | Opcode.MULSS -> mulss wordSz ins
  | Opcode.NEG -> neg wordSz ins
  | Opcode.NOP -> nop wordSz ins
  | Opcode.NOT -> not wordSz ins
  | Opcode.OR -> logOr wordSz ins
  | Opcode.ORPD -> orpd wordSz ins
  | Opcode.PADDD -> paddd wordSz ins
  | Opcode.PALIGNR -> palignr wordSz ins
  | Opcode.POP -> pop wordSz ins
  | Opcode.PSHUFD -> pshufd wordSz ins
  | Opcode.PUNPCKLDQ -> punpckldq wordSz ins
  | Opcode.PUSH -> push wordSz ins
  | Opcode.PXOR -> pxor wordSz ins
  | Opcode.RCL -> rcl wordSz ins
  | Opcode.RET -> ret wordSz ins
  | Opcode.ROL -> rol wordSz ins
  | Opcode.ROR -> ror wordSz ins
  | Opcode.SAR -> sar wordSz ins
  | Opcode.SAHF -> sahf wordSz ins.Operands
  | Opcode.SBB -> sbb wordSz ins
  | Opcode.SCASB -> scasb wordSz ins
  | Opcode.SCASD -> scasd wordSz ins
  | Opcode.SCASQ -> scasq wordSz ins
  | Opcode.SCASW -> scasw wordSz ins
  | Opcode.SETA -> seta wordSz ins
  | Opcode.SETB -> setb wordSz ins
  | Opcode.SETBE -> setbe wordSz ins
  | Opcode.SETG -> setg wordSz ins
  | Opcode.SETL -> setl wordSz ins
  | Opcode.SETLE -> setle wordSz ins
  | Opcode.SETNB -> setnb wordSz ins
  | Opcode.SETNL -> setnl wordSz ins
  | Opcode.SETNO -> setno wordSz ins
  | Opcode.SETNP -> setnp wordSz ins
  | Opcode.SETNS -> setns wordSz ins
  | Opcode.SETNZ -> setnz wordSz ins
  | Opcode.SETO -> seto wordSz ins
  | Opcode.SETP -> setp wordSz ins
  | Opcode.SETS -> sets wordSz ins
  | Opcode.SETZ -> setz wordSz ins
  | Opcode.SHL -> shl wordSz ins
  | Opcode.SHLD -> shld wordSz ins
  | Opcode.SHR -> shr wordSz ins
  | Opcode.STOSB -> stosb wordSz ins
  | Opcode.STOSD -> stosd wordSz ins
  | Opcode.STOSQ -> stosq wordSz ins
  | Opcode.STOSW -> stosw wordSz ins
  | Opcode.SUB -> sub wordSz ins
  | Opcode.SUBSD -> subsd wordSz ins
  | Opcode.SUBSS -> subss wordSz ins
  | Opcode.TEST -> test wordSz ins
  | Opcode.UCOMISS -> ucomiss wordSz ins
  | Opcode.VADDPD -> vaddpd wordSz ins
  | Opcode.VADDPS -> vaddps wordSz ins
  | Opcode.VADDSD -> vaddsd wordSz ins
  | Opcode.VADDSS -> vaddss wordSz ins
  | Opcode.VPALIGNR -> vpalignr wordSz ins
  | Opcode.XCHG -> xchg wordSz ins
  | Opcode.XOR -> xor wordSz ins
  | Opcode.XORPS -> xorps wordSz ins
  | Opcode.SYSCALL -> syscall ()
  | op -> raise <| EncodingFailureException $"{op} is not supported yet"

let computeIncompMaxLen op = (relBranch op).MaxLength

/// Resolves a label to the index of the instruction it marks. A label that was
/// never defined is a mistake in the assembly source, not in this assembler,
/// so it must not surface as a lookup failure from the map.
let findLabelIndex parserState lbl =
  match Map.tryFind lbl parserState.LabelMap with
  | Some idx -> idx
  | None -> raise <| EncodingFailureException $"Undefined label '{lbl}'"

let private fixupLength (fixup: Fixup) =
  fixup.Head.Length + RegType.toByteWidth fixup.Width + fixup.Tail.Length

/// Bounds every instruction's length before any label is resolved, which is
/// what the distances feeding computeFitType are measured with.
let computeMaxLen (encodings: Encoded list) =
  encodings
  |> List.map (function
    | Resolved bytes -> bytes.Length
    | PendingBranch(op, _) -> computeIncompMaxLen op
    | PendingFixup fixup -> fixupLength fixup)
  |> List.toArray

/// Chooses the displacement width for a branch to a label. Only rel8 and
/// rel32 are available: a rel16 branch needs an operand-size prefix that the
/// fixup below does not emit, so choosing it used to produce an instruction
/// two bytes shorter than the opcode implies. It does not exist in 64-bit
/// mode either.
let computeFitType dist =
  if isInt8 dist then 8<rt>
  elif isInt32 dist then 32<rt>
  else raise <| EncodingFailureException "Branch target is out of range"

let getOpByteOfIncomp relSz op =
  let branch = relBranch op
  let form = if relSz = 8<rt> then branch.ShortForm else branch.NearForm
  if Array.isEmpty form then
    raise <| EncodingFailureException $"{op} has no relative form to encode"
  else form

let computeDistance myIdx labelIdx maxLenArr =
  let sIdx, count, sign =
    if myIdx < labelIdx then myIdx + 1, labelIdx - myIdx - 1, id (* forward *)
    else labelIdx, myIdx - labelIdx + 1, (~-) (* backward *)
  match Array.sub maxLenArr sIdx count with
  | [||] -> 0L
  | arr -> Array.reduce (+) arr |> sign |> int64

let computeAddr idx realLenArr =
  match Array.sub realLenArr 0 idx with
  | [||] -> 0L
  | arr -> Array.reduce (+) arr |> int64

/// Settles how wide a branch's displacement has to be, which also settles its
/// opcode bytes. Everything else is already as resolved as it is going to get.
let decideOp parserState maxLenArr myIdx encoded =
  match encoded with
  | Resolved _ | PendingFixup _ -> encoded
  | PendingBranch(op, lbl) ->
    let labelIdx = findLabelIndex parserState lbl
    let width = computeDistance myIdx labelIdx maxLenArr |> computeFitType
    let width = if op = Opcode.CALL then 32<rt> (* FIXME *) else width
    PendingFixup { Head = getOpByteOfIncomp width op
                   Width = width
                   Tail = [||]
                   Label = lbl
                   IsBranch = true }

/// Every instruction's final length, which the distances that go into the
/// displacements are measured with.
let computeRealLen encodings =
  encodings
  |> List.map (function
    | Resolved bytes -> bytes.Length
    | PendingFixup fixup -> fixupLength fixup
    | PendingBranch _ -> Terminator.impossible () (* decideOp settled these *))
  |> List.toArray

/// Widens the distance to the label into the displacement chosen by
/// computeFitType, which is why rel16 is absent here.
let concretizeLabel sz (offset: int64) =
  match sz with
  | 8<rt> -> [| byte offset |]
  | 32<rt> -> BitConverter.GetBytes(int32 offset)
  | _ -> Terminator.impossible ()

let finalize wordSz parserState realLenArr baseAddr myIdx encoded =
  match encoded with
  | Resolved bytes -> bytes
  | PendingBranch _ -> Terminator.impossible () (* decideOp settled these *)
  | PendingFixup fixup ->
    let labelIdx = findLabelIndex parserState fixup.Label
    let displacement =
      if fixup.IsBranch then
        computeDistance myIdx labelIdx realLenArr
      elif wordSz = WordSize.Bit32 then
        computeAddr labelIdx realLenArr + int64 baseAddr
      else
        computeDistance myIdx labelIdx realLenArr + int64 baseAddr
    [| yield! fixup.Head
       yield! concretizeLabel fixup.Width displacement
       yield! fixup.Tail |]

let assemble parserState wordSz (baseAddr: Addr) (instrs: AsmInsInfo list) =
  let encodings =
    instrs |> List.map (fun ins -> encodeInstruction ins wordSz)
  let maxLenArr = computeMaxLen encodings
  let decided = encodings |> List.mapi (decideOp parserState maxLenArr)
  let realLenArr = computeRealLen decided
  decided |> List.mapi (finalize wordSz parserState realLenArr baseAddr)

// vim: set tw=80 sts=2 sw=2:
