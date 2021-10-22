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

module B2R2.Peripheral.Assembly.Intel.AsmMain

open System
open B2R2
open B2R2.FrontEnd.BinLifter.Intel
open B2R2.Peripheral.Assembly.Intel.ParserHelper
open B2R2.Peripheral.Assembly.Intel.AsmOpcode

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

let encodeInstruction (ins: AsmInsInfo) ctxt =
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
  | Opcode.BSR -> bsr ctxt ins
  | Opcode.BT -> bt ctxt ins
  | Opcode.CALLNear -> call ctxt ins
  | Opcode.CBW -> cbw ctxt ins.Operands
  | Opcode.CDQ -> cdq ctxt ins.Operands
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
  | Opcode.CVTSD2SS -> cvtsd2ss ctxt ins
  | Opcode.CVTSI2SD -> cvtsi2sd ctxt ins
  | Opcode.CVTSI2SS -> cvtsi2ss ctxt ins
  | Opcode.CVTSS2SI-> cvtss2si ctxt ins
  | Opcode.CVTTSS2SI -> cvttss2si ctxt ins
  | Opcode.CWDE -> cwde ctxt ins.Operands
  | Opcode.DEC -> dec ctxt ins
  | Opcode.DIV -> div ctxt ins
  | Opcode.DIVSD -> divsd ctxt ins
  | Opcode.DIVSS -> divss ctxt ins
  | Opcode.FADD -> fadd ctxt ins
  | Opcode.FCMOVB -> fcmovb ctxt ins
  | Opcode.FDIV -> fdiv ctxt ins
  | Opcode.FDIVP -> fdivp ctxt ins.Operands
  | Opcode.FDIVRP -> fdivrp ctxt ins.Operands
  | Opcode.FILD -> fild ctxt ins
  | Opcode.FISTP -> fistp ctxt ins
  | Opcode.FLD -> fld ctxt ins
  | Opcode.FLD1 -> fld1 ctxt ins.Operands
  | Opcode.FLDCW -> fldcw ctxt ins
  | Opcode.FLDZ -> fldz ctxt ins.Operands
  | Opcode.FMUL -> fmul ctxt ins
  | Opcode.FMULP -> fmulp ctxt ins.Operands
  | Opcode.FNSTCW -> fnstcw ctxt ins
  | Opcode.FSTP -> fstp ctxt ins
  | Opcode.FSUB -> fsub ctxt ins
  | Opcode.FSUBR -> fsubr ctxt ins
  | Opcode.FUCOMI -> fucomi ctxt ins.Operands
  | Opcode.FUCOMIP -> fucomip ctxt ins.Operands
  | Opcode.FXCH -> fxch ctxt ins.Operands
  | Opcode.HLT -> hlt ctxt ins.Operands
  | Opcode.IDIV -> idiv ctxt ins
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
  | Opcode.LAHF -> lahf ctxt ins.Operands
  | Opcode.LEA -> lea ctxt ins
  | Opcode.LEAVE -> leave ctxt ins.Operands
  | Opcode.MOV -> mov ctxt ins
  | Opcode.MOVAPS -> movaps ctxt ins
  | Opcode.MOVD -> movd ctxt ins
  | Opcode.MOVDQA -> movdqa ctxt ins
  | Opcode.MOVDQU -> movdqu ctxt ins
  | Opcode.MOVSD -> movsd ctxt ins
  | Opcode.MOVSS -> movss ctxt ins
  | Opcode.MOVSX -> movsx ctxt ins
  | Opcode.MOVSXD -> movsxd ctxt ins
  | Opcode.MOVUPS -> movups ctxt ins
  | Opcode.MOVZX -> movzx ctxt ins
  | Opcode.MUL -> mul ctxt ins
  | Opcode.MULSD -> mulsd ctxt ins
  | Opcode.MULSS -> mulss ctxt ins
  | Opcode.NEG -> neg ctxt ins
  | Opcode.NOP -> nop ctxt ins
  | Opcode.NOT -> not ctxt ins
  | Opcode.OR -> logOr ctxt ins
  | Opcode.ORPD -> orpd ctxt ins
  | Opcode.PADDD -> paddd ctxt ins
  | Opcode.PALIGNR -> palignr ctxt ins
  | Opcode.POP -> pop ctxt ins
  | Opcode.PSHUFD -> pshufd ctxt ins
  | Opcode.PUNPCKLDQ -> punpckldq ctxt ins
  | Opcode.PUSH -> push ctxt ins
  | Opcode.PXOR -> pxor ctxt ins
  | Opcode.RCL -> rcl ctxt ins
  | Opcode.RETNear | Opcode.RETNearImm -> ret ctxt ins
  | Opcode.ROL -> rol ctxt ins
  | Opcode.ROR -> ror ctxt ins
  | Opcode.SAR -> sar ctxt ins
  | Opcode.SAHF -> sahf ctxt ins.Operands
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
  | Opcode.SHLD -> shld ctxt ins
  | Opcode.SHR -> shr ctxt ins
  | Opcode.STOSB -> stosb ctxt ins
  | Opcode.STOSD -> stosd ctxt ins
  | Opcode.STOSQ -> stosq ctxt ins
  | Opcode.STOSW -> stosw ctxt ins
  | Opcode.SUB -> sub ctxt ins
  | Opcode.SUBSD -> subsd ctxt ins
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
  | Opcode.XORPS -> xorps ctxt ins
  | op -> printfn "%A" op; Utils.futureFeature ()

let computeIncompMaxLen = function
  | Opcode.LOOP | Opcode.LOOPE | Opcode.LOOPNE -> 2
  | Opcode.CALLNear | Opcode.JMPNear -> 5
  | Opcode.JA | Opcode.JB | Opcode.JBE | Opcode.JG | Opcode.JL | Opcode.JLE
  | Opcode.JNB | Opcode.JNL | Opcode.JNO | Opcode.JNP | Opcode.JNS | Opcode.JNZ
  | Opcode.JO | Opcode.JP | Opcode.JS | Opcode.JZ
  | Opcode.XBEGIN -> 6
  | _ -> Utils.futureFeature ()

let getImm imm = if Option.isSome imm then Option.get imm else [||]

let computeMaxLen (components: AsmComponent [] list) =
  components
  |> List.map (fun comp ->
       match comp.[0] with
       | Normal _ -> Array.length comp
       | CompOp (_, _, bytes, imm) ->
         Array.length bytes + 4 + Array.length (getImm imm)
       | IncompleteOp (op, _) -> computeIncompMaxLen op
       | _ -> Utils.impossible ())
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
  | _ -> Utils.futureFeature ()

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

let decideOp parserState maxLenArr myIdx (comp: _ []) =
  match comp.[0] with
  | Normal _ | CompOp _ -> comp
  | IncompleteOp (op, (OneOperand (Label (lbl, _)) as oprs)) ->
    let labelIdx = Map.find lbl parserState.LabelMap
    let t = computeDistance myIdx labelIdx maxLenArr |> computeFitType
    let t = if op = Opcode.CALLNear then 32<rt> (* FIXME *) else t
    [| CompOp (op, oprs, getOpByteOfIncomp t op, None)
       IncompLabel t |]
  | _ -> Utils.impossible ()

let computeRealLen components =
  components
  |> List.map (fun (comp: AsmComponent []) ->
    match comp.[0] with
    | CompOp (_, _, bytes, imm) ->
      match comp.[1] with
      | IncompLabel sz ->
        Array.length bytes + RegType.toByteWidth sz + Array.length (getImm imm)
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
  | comp -> printfn "%A" comp; Utils.impossible ()

let finalize arch parserState realLenArr baseAddr myIdx comp =
  match comp with
  | [| CompOp (_, OneOperand (Label (lbl, _)), bs, _); IncompLabel sz |] ->
    let labelIdx = Map.find lbl parserState.LabelMap
    let dist = computeDistance myIdx labelIdx realLenArr
    [| yield! bs; yield! concretizeLabel sz dist |]
  | [| CompOp (_, TwoOperands (_, Label (lbl, _)), bs, imm); IncompLabel sz |]
  | [| CompOp (_, TwoOperands (Label (lbl, _), _), bs, imm); IncompLabel sz |]
  | [| CompOp (_, ThreeOperands (_, Label (lbl, _), _), bs, imm)
       IncompLabel sz |] ->
    let labelIdx = Map.find lbl parserState.LabelMap
    let addr =
      if arch = Arch.IntelX86 then computeAddr labelIdx realLenArr
      else computeDistance myIdx labelIdx realLenArr
    [| yield! bs; yield! concretizeLabel sz (addr  + int64 baseAddr)
       yield! getImm imm |]
  | _ -> comp |> Array.map normalToByte

let assemble parserState isa (baseAddr: Addr) (instrs: AsmInsInfo list) =
  let ctxt = EncContext (isa.Arch)
  let components = instrs |> List.map (fun ins -> encodeInstruction ins ctxt)
  let maxLenArr = computeMaxLen components
  let components' = components |> List.mapi (decideOp parserState maxLenArr)
  let realLenArr = computeRealLen components'
  components'
  |> List.mapi (finalize isa.Arch parserState realLenArr baseAddr)

// vim: set tw=80 sts=2 sw=2:
