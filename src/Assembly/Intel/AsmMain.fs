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
open B2R2.Assembly.Intel.AsmOpcode

type AssemblyInfo =
  { Index: int
    PC: Addr
    ByteStr: string
    AsmComponents: AsmComponent[]
    AsmLabel: string option }

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

let encodeInstruction ins ctx =
  checkMissingMemoryOperandSize ins
  match ins.Opcode with
  | Opcode.AAA -> aaa ctx ins.Operands
  | Opcode.AAD -> aad ctx ins.Operands
  | Opcode.AAM -> aam ctx ins.Operands
  | Opcode.AAS -> aas ctx ins.Operands
  | Opcode.ADC -> adc ctx ins
  | Opcode.ADD -> add ctx ins
  | Opcode.ADDPD -> addpd ctx ins
  | Opcode.ADDPS -> addps ctx ins
  | Opcode.ADDSD -> addsd ctx ins
  | Opcode.ADDSS -> addss ctx ins
  | Opcode.AND -> logAnd ctx ins
  | Opcode.ANDPD -> andpd ctx ins
  | Opcode.ANDPS -> andps ctx ins
  | Opcode.BSR -> bsr ctx ins
  | Opcode.BT -> bt ctx ins
  | Opcode.CALLNear -> call ctx ins
  | Opcode.CBW -> cbw ctx ins.Operands
  | Opcode.CDQ -> cdq ctx ins.Operands
  | Opcode.CDQE -> cdqe ctx ins.Operands
  | Opcode.CMOVA -> cmova ctx ins
  | Opcode.CMOVAE -> cmovae ctx ins
  | Opcode.CMOVB -> cmovb ctx ins
  | Opcode.CMOVBE -> cmovbe ctx ins
  | Opcode.CMOVG -> cmovg ctx ins
  | Opcode.CMOVGE -> cmovge ctx ins
  | Opcode.CMOVL -> cmovl ctx ins
  | Opcode.CMOVLE -> cmovle ctx ins
  | Opcode.CMOVNO -> cmovno ctx ins
  | Opcode.CMOVNP -> cmovnp ctx ins
  | Opcode.CMOVNS -> cmovns ctx ins
  | Opcode.CMOVNZ -> cmovnz ctx ins
  | Opcode.CMOVO -> cmovo ctx ins
  | Opcode.CMOVP -> cmovp ctx ins
  | Opcode.CMOVS -> cmovs ctx ins
  | Opcode.CMOVZ -> cmovz ctx ins
  | Opcode.CMP -> cmp ctx ins
  | Opcode.CMPSB -> cmpsb ctx ins
  | Opcode.CMPXCHG -> cmpxchg ctx ins
  | Opcode.CMPXCHG8B -> cmpxchg8b ctx ins
  | Opcode.CMPXCHG16B -> cmpxchg16b ctx ins
  | Opcode.CVTSD2SS -> cvtsd2ss ctx ins
  | Opcode.CVTSI2SD -> cvtsi2sd ctx ins
  | Opcode.CVTSI2SS -> cvtsi2ss ctx ins
  | Opcode.CVTSS2SI -> cvtss2si ctx ins
  | Opcode.CVTTSS2SI -> cvttss2si ctx ins
  | Opcode.CWDE -> cwde ctx ins.Operands
  | Opcode.DEC -> dec ctx ins
  | Opcode.DIV -> div ctx ins
  | Opcode.DIVSD -> divsd ctx ins
  | Opcode.DIVSS -> divss ctx ins
  | Opcode.FADD -> fadd ctx ins
  | Opcode.FCMOVB -> fcmovb ctx ins
  | Opcode.FDIV -> fdiv ctx ins
  | Opcode.FDIVP -> fdivp ctx ins.Operands
  | Opcode.FDIVRP -> fdivrp ctx ins.Operands
  | Opcode.FILD -> fild ctx ins
  | Opcode.FISTP -> fistp ctx ins
  | Opcode.FLD -> fld ctx ins
  | Opcode.FLD1 -> fld1 ctx ins.Operands
  | Opcode.FLDCW -> fldcw ctx ins
  | Opcode.FLDZ -> fldz ctx ins.Operands
  | Opcode.FMUL -> fmul ctx ins
  | Opcode.FMULP -> fmulp ctx ins.Operands
  | Opcode.FNSTCW -> fnstcw ctx ins
  | Opcode.FSTP -> fstp ctx ins
  | Opcode.FSUB -> fsub ctx ins
  | Opcode.FSUBR -> fsubr ctx ins
  | Opcode.FUCOMI -> fucomi ctx ins.Operands
  | Opcode.FUCOMIP -> fucomip ctx ins.Operands
  | Opcode.FXCH -> fxch ctx ins.Operands
  | Opcode.HLT -> hlt ctx ins.Operands
  | Opcode.IDIV -> idiv ctx ins
  | Opcode.IMUL -> imul ctx ins
  | Opcode.INC -> inc ctx ins
  | Opcode.INT -> interrupt ins
  | Opcode.INT3 -> interrupt3 ()
  | Opcode.JA -> ja ctx ins
  | Opcode.JB -> jb ctx ins
  | Opcode.JBE -> jbe ctx ins
  | Opcode.JG -> jg ctx ins
  | Opcode.JL -> jl ctx ins
  | Opcode.JLE -> jle ctx ins
  | Opcode.JNB -> jnb ctx ins
  | Opcode.JNL -> jnl ctx ins
  | Opcode.JNO -> jno ctx ins
  | Opcode.JNP -> jnp ctx ins
  | Opcode.JNS -> jns ctx ins
  | Opcode.JNZ -> jnz ctx ins
  | Opcode.JO -> jo ctx ins
  | Opcode.JP -> jp ctx ins
  | Opcode.JS -> js ctx ins
  | Opcode.JZ -> jz ctx ins
  | Opcode.JMPNear -> jmp ctx ins
  | Opcode.LAHF -> lahf ctx ins.Operands
  | Opcode.LEA -> lea ctx ins
  | Opcode.LEAVE -> leave ctx ins.Operands
  | Opcode.MOV -> mov ctx ins
  | Opcode.MOVAPS -> movaps ctx ins
  | Opcode.MOVD -> movd ctx ins
  | Opcode.MOVDQA -> movdqa ctx ins
  | Opcode.MOVDQU -> movdqu ctx ins
  | Opcode.MOVSD -> movsd ctx ins
  | Opcode.MOVSS -> movss ctx ins
  | Opcode.MOVSX -> movsx ctx ins
  | Opcode.MOVSXD -> movsxd ctx ins
  | Opcode.MOVUPS -> movups ctx ins
  | Opcode.MOVZX -> movzx ctx ins
  | Opcode.MUL -> mul ctx ins
  | Opcode.MULSD -> mulsd ctx ins
  | Opcode.MULSS -> mulss ctx ins
  | Opcode.NEG -> neg ctx ins
  | Opcode.NOP -> nop ctx ins
  | Opcode.NOT -> not ctx ins
  | Opcode.OR -> logOr ctx ins
  | Opcode.ORPD -> orpd ctx ins
  | Opcode.PADDD -> paddd ctx ins
  | Opcode.PALIGNR -> palignr ctx ins
  | Opcode.POP -> pop ctx ins
  | Opcode.PSHUFD -> pshufd ctx ins
  | Opcode.PUNPCKLDQ -> punpckldq ctx ins
  | Opcode.PUSH -> push ctx ins
  | Opcode.PXOR -> pxor ctx ins
  | Opcode.RCL -> rcl ctx ins
  | Opcode.RETNear | Opcode.RETNearImm -> ret ctx ins
  | Opcode.ROL -> rol ctx ins
  | Opcode.ROR -> ror ctx ins
  | Opcode.SAR -> sar ctx ins
  | Opcode.SAHF -> sahf ctx ins.Operands
  | Opcode.SBB -> sbb ctx ins
  | Opcode.SCASB -> scasb ctx ins
  | Opcode.SCASD -> scasd ctx ins
  | Opcode.SCASQ -> scasq ctx ins
  | Opcode.SCASW -> scasw ctx ins
  | Opcode.SETA -> seta ctx ins
  | Opcode.SETB -> setb ctx ins
  | Opcode.SETBE -> setbe ctx ins
  | Opcode.SETG -> setg ctx ins
  | Opcode.SETL -> setl ctx ins
  | Opcode.SETLE -> setle ctx ins
  | Opcode.SETNB -> setnb ctx ins
  | Opcode.SETNL -> setnl ctx ins
  | Opcode.SETNO -> setno ctx ins
  | Opcode.SETNP -> setnp ctx ins
  | Opcode.SETNS -> setns ctx ins
  | Opcode.SETNZ -> setnz ctx ins
  | Opcode.SETO -> seto ctx ins
  | Opcode.SETP -> setp ctx ins
  | Opcode.SETS -> sets ctx ins
  | Opcode.SETZ -> setz ctx ins
  | Opcode.SHL -> shl ctx ins
  | Opcode.SHLD -> shld ctx ins
  | Opcode.SHR -> shr ctx ins
  | Opcode.STOSB -> stosb ctx ins
  | Opcode.STOSD -> stosd ctx ins
  | Opcode.STOSQ -> stosq ctx ins
  | Opcode.STOSW -> stosw ctx ins
  | Opcode.SUB -> sub ctx ins
  | Opcode.SUBSD -> subsd ctx ins
  | Opcode.SUBSS -> subss ctx ins
  | Opcode.TEST -> test ctx ins
  | Opcode.UCOMISS -> ucomiss ctx ins
  | Opcode.VADDPD -> vaddpd ctx ins
  | Opcode.VADDPS -> vaddps ctx ins
  | Opcode.VADDSD -> vaddsd ctx ins
  | Opcode.VADDSS -> vaddss ctx ins
  | Opcode.VPALIGNR -> vpalignr ctx ins
  | Opcode.XCHG -> xchg ctx ins
  | Opcode.XOR -> xor ctx ins
  | Opcode.XORPS -> xorps ctx ins
  | Opcode.SYSCALL -> syscall ()
  | op -> printfn "%A" op; Terminator.futureFeature ()

let computeIncompMaxLen = function
  | Opcode.LOOP | Opcode.LOOPE | Opcode.LOOPNE -> 2
  | Opcode.CALLNear | Opcode.JMPNear -> 5
  | Opcode.JA | Opcode.JB | Opcode.JBE | Opcode.JG | Opcode.JL | Opcode.JLE
  | Opcode.JNB | Opcode.JNL | Opcode.JNO | Opcode.JNP | Opcode.JNS | Opcode.JNZ
  | Opcode.JO | Opcode.JP | Opcode.JS | Opcode.JZ
  | Opcode.XBEGIN -> 6
  | _ -> Terminator.futureFeature ()

let getImm imm = if Option.isSome imm then Option.get imm else [||]

let computeMaxLen (components: AsmComponent[] list) =
  components
  |> List.map (fun comp ->
       match comp[0] with
       | Normal _ -> Array.length comp
       | CompOp(_, _, bytes, imm) ->
         Array.length bytes + 4 + Array.length (getImm imm)
       | IncompleteOp(op, _) -> computeIncompMaxLen op
       | _ -> Terminator.impossible ())
  |> List.toArray

let computeFitType dist =
  if isInt8 dist then 8<rt>
  elif isInt16 dist then 16<rt>
  elif isInt32 dist then 32<rt>
  else failwith "Invalid Relative length"

let getOpByteOfIncomp relSz = function
  | Opcode.JMPNear -> if relSz = 8<rt> then [| 0xEBuy |] else [| 0xE9uy |]
  | Opcode.JA -> if relSz = 8<rt> then [| 0x77uy |] else [| 0x0Fuy; 0x87uy |]
  | Opcode.JB -> if relSz = 8<rt> then [| 0x72uy |] else [| 0x0Fuy; 0x82uy |]
  | Opcode.JBE -> if relSz = 8<rt> then [| 0x76uy |] else [| 0x0Fuy; 0x86uy |]
  | Opcode.JG -> if relSz = 8<rt> then [| 0x7Fuy |] else [| 0x0Fuy; 0x8Fuy |]
  | Opcode.JL -> if relSz = 8<rt> then [| 0x7Cuy |] else [| 0x0Fuy; 0x8Cuy |]
  | Opcode.JLE -> if relSz = 8<rt> then [| 0x7Euy |] else [| 0x0Fuy; 0x8Euy |]
  | Opcode.JNB -> if relSz = 8<rt> then [| 0x73uy |] else [| 0x0Fuy; 0x83uy |]
  | Opcode.JNL -> if relSz = 8<rt> then [| 0x7Duy |] else [| 0x0Fuy; 0x8Duy |]
  | Opcode.JNO -> if relSz = 8<rt> then [| 0x71uy |] else [| 0x0Fuy; 0x81uy |]
  | Opcode.JNP -> if relSz = 8<rt> then [| 0x7Buy |] else [| 0x0Fuy; 0x8Buy |]
  | Opcode.JNS -> if relSz = 8<rt> then [| 0x79uy |] else [| 0x0Fuy; 0x89uy |]
  | Opcode.JNZ -> if relSz = 8<rt> then [| 0x75uy |] else [| 0x0Fuy; 0x85uy |]
  | Opcode.JO -> if relSz = 8<rt> then [| 0x70uy |] else [| 0x0Fuy; 0x80uy |]
  | Opcode.JP -> if relSz = 8<rt> then [| 0x7auy |] else [| 0x0Fuy; 0x8Auy |]
  | Opcode.JS -> if relSz = 8<rt> then [| 0x78uy |] else [| 0x0Fuy; 0x88uy |]
  | Opcode.JZ -> if relSz = 8<rt> then [| 0x74uy |] else [| 0x0Fuy; 0x84uy |]
  | Opcode.CALLNear -> [| 0xE8uy |]
  | _ -> Terminator.futureFeature ()

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

let decideOp parserState maxLenArr myIdx (comp: _[]) =
  match comp[0] with
  | Normal _ | CompOp _ -> comp
  | IncompleteOp(op, (OneOperand(Label(lbl, _)) as oprs)) ->
    let labelIdx = Map.find lbl parserState.LabelMap
    let t = computeDistance myIdx labelIdx maxLenArr |> computeFitType
    let t = if op = Opcode.CALLNear then 32<rt> (* FIXME *) else t
    [| CompOp(op, oprs, getOpByteOfIncomp t op, None)
       IncompLabel t |]
  | _ -> Terminator.impossible ()

let computeRealLen components =
  components
  |> List.map (fun (comp: AsmComponent[]) ->
    match comp[0] with
    | CompOp(_, _, bytes, imm) ->
      match comp[1] with
      | IncompLabel sz ->
        Array.length bytes + RegType.toByteWidth sz + Array.length (getImm imm)
      | _ -> Terminator.impossible ()
    | _ -> Array.length comp)
  |> List.toArray

let concretizeLabel sz (offset: int64) =
  match sz with
  | 8<rt> -> [| byte offset |]
  | 16<rt> -> BitConverter.GetBytes(int16 offset)
  | 32<rt> -> BitConverter.GetBytes(int32 offset)
  | _ -> Terminator.impossible ()

let normalToByte = function
  | Normal b -> b
  | comp -> printfn "%A" comp; Terminator.impossible ()

let finalize wordSize parserState realLenArr baseAddr myIdx comp =
  match comp with
  | [| CompOp(_, OneOperand(Label(lbl, _)), bs, _); IncompLabel sz |] ->
    let labelIdx = Map.find lbl parserState.LabelMap
    let dist = computeDistance myIdx labelIdx realLenArr
    [| yield! bs; yield! concretizeLabel sz dist |]
  | [| CompOp(_, TwoOperands(_, Label(lbl, _)), bs, imm); IncompLabel sz |]
  | [| CompOp(_, TwoOperands(Label(lbl, _), _), bs, imm); IncompLabel sz |]
  | [| CompOp(_, ThreeOperands(_, Label(lbl, _), _), bs, imm)
       IncompLabel sz |] ->
    let labelIdx = Map.find lbl parserState.LabelMap
    let addr =
      if wordSize = WordSize.Bit32 then computeAddr labelIdx realLenArr
      else computeDistance myIdx labelIdx realLenArr
    [| yield! bs
       yield! concretizeLabel sz (addr + int64 baseAddr)
       yield! getImm imm |]
  | _ -> comp |> Array.map normalToByte

let assemble parserState wordSize (baseAddr: Addr) (instrs: AsmInsInfo list) =
  let ctx = EncodingContext wordSize
  let components = instrs |> List.map (fun ins -> encodeInstruction ins ctx)
  let maxLenArr = computeMaxLen components
  let components' = components |> List.mapi (decideOp parserState maxLenArr)
  let realLenArr = computeRealLen components'
  components'
  |> List.mapi (finalize wordSize parserState realLenArr baseAddr)

// vim: set tw=80 sts=2 sw=2:
