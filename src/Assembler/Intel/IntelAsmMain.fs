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

module B2R2.Assembler.Intel.AsmMain

open System
open B2R2
open B2R2.FrontEnd.Intel
open B2R2.Assembler.Intel.AsmOpcode

type AssemblyInfo = {
  Index         : int
  PC            : Addr
  ByteStr       : string
  AsmComponents : AsmComponent []
  AsmLabel      : string option
}

type UserState = {
  /// Label string to an index of an instruction. The index starts from zero,
  /// and labels do not increase the index.
  LabelMap: Map<string, int>
  /// Current instruction index. This will change as we encounter an
  /// instruction, but labels would not change this.
  CurIndex: int
}

let encodeInstruction ins ctxt =
  match ins.Opcode with
  | Opcode.AAA -> aaa ctxt ins.Operands
  | Opcode.AAD -> aad ctxt ins.Operands
  | Opcode.AAM -> aam ctxt ins.Operands
  | Opcode.AAS -> aas ctxt ins.Operands
  | Opcode.ADC -> adc ctxt ins
  | Opcode.ADD -> add ctxt ins
  | Opcode.ADDPD -> addpd ctxt ins
  | Opcode.ADDPS -> addps ctxt ins
  | Opcode.ADDSD -> addsd ctxt ins
  | Opcode.ADDSS -> addss ctxt ins
  | Opcode.AND -> logAnd ctxt ins
  | Opcode.ANDPD -> andpd ctxt ins
  | Opcode.ANDPS -> andps ctxt ins
  | Opcode.BT -> bt ctxt ins
  | Opcode.CALLNear -> call ctxt ins
  | Opcode.CBW -> cbw ctxt ins.Operands
  | Opcode.CDQE -> cdqe ctxt ins.Operands
  | Opcode.CMOVA -> cmova ctxt ins
  | Opcode.CMOVAE -> cmovae ctxt ins
  | Opcode.CMOVB -> cmovb ctxt ins
  | Opcode.CMOVBE -> cmovbe ctxt ins
  | Opcode.CMOVG -> cmovg ctxt ins
  | Opcode.CMOVGE -> cmovge ctxt ins
  | Opcode.CMOVL -> cmovl ctxt ins
  | Opcode.CMOVLE -> cmovle ctxt ins
  | Opcode.CMOVNO -> cmovno ctxt ins
  | Opcode.CMOVNP -> cmovnp ctxt ins
  | Opcode.CMOVNS -> cmovns ctxt ins
  | Opcode.CMOVNZ -> cmovnz ctxt ins
  | Opcode.CMOVO -> cmovo ctxt ins
  | Opcode.CMOVP -> cmovp ctxt ins
  | Opcode.CMOVS -> cmovs ctxt ins
  | Opcode.CMOVZ -> cmovz ctxt ins
  | Opcode.CMP -> cmp ctxt ins
  | Opcode.CMPSB -> cmpsb ctxt ins
  | Opcode.CMPXCHG -> cmpxchg ctxt ins
  | Opcode.CMPXCHG8B -> cmpxchg8b ctxt ins
  | Opcode.CMPXCHG16B -> cmpxchg16b ctxt ins
  | Opcode.CVTSI2SD -> cvtsi2sd ctxt ins
  | Opcode.CVTSI2SS -> cvtsi2ss ctxt ins
  | Opcode.CVTTSS2SI -> cvttss2si ctxt ins
  | Opcode.CWDE -> cwde ctxt ins.Operands
  | Opcode.DIV -> div ctxt ins
  | Opcode.DIVSD -> divsd ctxt ins
  | Opcode.DIVSS -> divss ctxt ins
  | Opcode.FADD -> fadd ctxt ins
  | Opcode.FDIVP -> fdivp ctxt ins.Operands
  | Opcode.FDIVRP -> fdivrp ctxt ins.Operands
  | Opcode.FILD -> fild ctxt ins
  | Opcode.FISTP -> fistp ctxt ins
  | Opcode.FLD -> fld ctxt ins
  | Opcode.FLDCW -> fldcw ctxt ins
  | Opcode.FMUL -> fmul ctxt ins
  | Opcode.FMULP -> fmulp ctxt ins.Operands
  | Opcode.FNSTCW -> fnstcw ctxt ins
  | Opcode.FSTP -> fstp ctxt ins
  | Opcode.FSUBR -> fsubr ctxt ins
  | Opcode.FUCOMI -> fucomi ctxt ins.Operands
  | Opcode.FUCOMIP -> fucomip ctxt ins.Operands
  | Opcode.FXCH -> fxch ctxt ins.Operands
  | Opcode.HLT -> hlt ctxt ins.Operands
  | Opcode.IMUL -> imul ctxt ins
  | Opcode.INC -> inc ctxt ins
  | Opcode.JA -> ja ctxt ins
  | Opcode.JB -> jb ctxt ins
  | Opcode.JBE -> jbe ctxt ins
  | Opcode.JG -> jg ctxt ins
  | Opcode.JL -> jl ctxt ins
  | Opcode.JLE -> jle ctxt ins
  | Opcode.JNB -> jnb ctxt ins
  | Opcode.JNL -> jnl ctxt ins
  | Opcode.JNO -> jno ctxt ins
  | Opcode.JNP -> jnp ctxt ins
  | Opcode.JNS -> jns ctxt ins
  | Opcode.JNZ -> jnz ctxt ins
  | Opcode.JO -> jo ctxt ins
  | Opcode.JP -> jp ctxt ins
  | Opcode.JS -> js ctxt ins
  | Opcode.JZ -> jz ctxt ins
  | Opcode.JMPNear -> jmp ctxt ins
  | Opcode.LEA -> lea ctxt ins
  | Opcode.MOV -> mov ctxt ins
  | Opcode.MOVAPS -> movaps ctxt ins
  | Opcode.MOVSS -> movss ctxt ins
  | Opcode.MOVSX -> movsx ctxt ins
  | Opcode.MOVSXD -> movsxd ctxt ins
  | Opcode.MOVZX -> movzx ctxt ins
  | Opcode.MUL -> mul ctxt ins
  | Opcode.MULSD -> mulsd ctxt ins
  | Opcode.MULSS -> mulss ctxt ins
  | Opcode.NEG -> neg ctxt ins
  | Opcode.NOP -> nop ctxt ins
  | Opcode.NOT -> not ctxt ins
  | Opcode.OR -> logOr ctxt ins
  | Opcode.PALIGNR -> palignr ctxt ins
  | Opcode.POP -> pop ctxt ins
  | Opcode.PUSH -> push ctxt ins
  | Opcode.PXOR -> pxor ctxt ins
  | Opcode.RCL -> rcl ctxt ins
  | Opcode.RETNear | Opcode.RETNearImm -> ret ctxt ins
  | Opcode.ROL -> rol ctxt ins
  | Opcode.ROR -> ror ctxt ins
  | Opcode.SAR -> sar ctxt ins
  | Opcode.SBB -> sbb ctxt ins
  | Opcode.SCASB -> scasb ctxt ins
  | Opcode.SCASD -> scasd ctxt ins
  | Opcode.SCASQ -> scasq ctxt ins
  | Opcode.SCASW -> scasw ctxt ins
  | Opcode.SETA -> seta ctxt ins
  | Opcode.SETB -> setb ctxt ins
  | Opcode.SETBE -> setbe ctxt ins
  | Opcode.SETG -> setg ctxt ins
  | Opcode.SETL -> setl ctxt ins
  | Opcode.SETLE -> setle ctxt ins
  | Opcode.SETNB -> setnb ctxt ins
  | Opcode.SETNL -> setnl ctxt ins
  | Opcode.SETNO -> setno ctxt ins
  | Opcode.SETNP -> setnp ctxt ins
  | Opcode.SETNS -> setns ctxt ins
  | Opcode.SETNZ -> setnz ctxt ins
  | Opcode.SETO -> seto ctxt ins
  | Opcode.SETP -> setp ctxt ins
  | Opcode.SETS -> sets ctxt ins
  | Opcode.SETZ -> setz ctxt ins
  | Opcode.SHL -> shl ctxt ins
  | Opcode.SHR -> shr ctxt ins
  | Opcode.STOSB -> stosb ctxt ins
  | Opcode.STOSD -> stosd ctxt ins
  | Opcode.STOSQ -> stosq ctxt ins
  | Opcode.STOSW -> stosw ctxt ins
  | Opcode.SUB -> sub ctxt ins
  | Opcode.SUBSS -> subss ctxt ins
  | Opcode.TEST -> test ctxt ins
  | Opcode.UCOMISS -> ucomiss ctxt ins
  | Opcode.VADDPD -> vaddpd ctxt ins
  | Opcode.VADDPS -> vaddps ctxt ins
  | Opcode.VADDSD -> vaddsd ctxt ins
  | Opcode.VADDSS -> vaddss ctxt ins
  | Opcode.VPALIGNR -> vpalignr ctxt ins
  | Opcode.XCHG -> xchg ctxt ins
  | Opcode.XOR -> xor ctxt ins
  | op -> printfn "%A" op; Utils.futureFeature ()

let computeMaxLen (components: AsmComponent [] list) =
  components
  |> List.map (fun comp ->
       match comp.[0] with
       | Normal _ -> Array.length comp
       | CompleteOp (_, _, bytes) -> Array.length bytes + 4
       | IncompleteOp _ -> 6 // FIXME
       | _ -> Utils.impossible ())
  |> List.toArray

let computeFitType dist =
  if isInt8 dist then 8<rt>
  elif isInt16 dist then 16<rt>
  elif isInt32 dist then 32<rt>
  else failwith "Invalid Relative length"

let getOpByteOfIncomp relSz = function
  | Opcode.JMPNear -> if relSz = 8<rt> then [| 0xEBuy |] else [| 0xE9uy |]
  | Opcode.JNE -> if relSz = 8<rt> then [| 0x75uy |] else [| 0x85uy; 0x85uy |]
  | _ -> Utils.futureFeature ()

let computeDistance myIdx labelIdx maxLenArr =
  let sIdx, count =
    if myIdx >= labelIdx then labelIdx + 1, myIdx - labelIdx - 2
    else myIdx + 1, labelIdx - myIdx - 2
  Array.sub maxLenArr sIdx count
  |> Array.reduce (+)
  |> int64

let computeAddr idx realLenArr =
  Array.sub realLenArr 0 (idx - 1)
  |> Array.reduce (+)
  |> int64

let decideOp parserState maxLenArr myIdx (comp: _ []) =
  match comp.[0] with
  | Normal _ | CompleteOp _ -> comp
  | IncompleteOp (op, (OneOperand (Label lbl) as oprs)) ->
    let labelIdx = Map.find lbl parserState.LabelMap
    let t = computeDistance myIdx labelIdx maxLenArr |> computeFitType
    [| CompleteOp (op, oprs, getOpByteOfIncomp t op)
       IncompLabel t |]
  | _ -> Utils.impossible ()

let computeRealLen components =
  components
  |> List.map (fun (comp: AsmComponent []) ->
    match comp.[0] with
    | CompleteOp (_, _, bytes) ->
      match comp.[1] with
      | IncompLabel sz -> Array.length bytes + RegType.toByteWidth sz
      | _ -> Utils.impossible ()
    | _ -> Array.length comp)
  |> List.toArray

let concretizeLabel sz (offset: int64) =
  match sz with
  | 8<rt> -> [| byte offset |]
  | 16<rt> -> BitConverter.GetBytes (int16 offset)
  | 32<rt> -> BitConverter.GetBytes (int32 offset)
  | _ -> Utils.impossible ()

let normalToByte = function
  | Normal b -> b
  | _ -> Utils.impossible ()

let finalize parserState realLenArr baseAddr myIdx comp =
  match comp with
  | [| CompleteOp (_, OneOperand (Label lbl), bs); IncompLabel sz |] ->
    let labelIdx = Map.find lbl parserState.LabelMap
    let dist = computeDistance myIdx labelIdx realLenArr
    [| yield! bs; yield! concretizeLabel sz dist |]
  | [| CompleteOp (_, TwoOperands (_, Label lbl), bs); IncompLabel sz |] ->
    let labelIdx = Map.find lbl parserState.LabelMap
    let addr = computeAddr labelIdx realLenArr + int64 baseAddr
    [| yield! bs; yield! concretizeLabel sz addr |]
  | _ -> comp |> Array.map normalToByte

let assemble parserState isa (baseAddr: Addr) (instrs: InsInfo list) =
  let ctxt = EncContext (isa.Arch)
  let components = instrs |> List.map (fun ins -> encodeInstruction ins ctxt)
  let maxLenArr = computeMaxLen components
  let components' = components |> List.mapi (decideOp parserState maxLenArr)
  let realLenArr = computeRealLen components'
  components'
  |> List.mapi (finalize parserState realLenArr baseAddr)

// vim: set tw=80 sts=2 sw=2:
