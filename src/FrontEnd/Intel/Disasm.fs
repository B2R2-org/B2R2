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

module internal B2R2.FrontEnd.Intel.Disasm

open B2R2
open B2R2.FrontEnd.BinLifter

type Delegate = delegate of IDisasmBuilder * Instruction -> unit

let inline private iToHexStr (i: int64) (builder: IDisasmBuilder) =
  builder.Accumulate(AsmWordKind.Value, HexString.ofInt64 i)

let inline private uToHexStr (i: uint64) (builder: IDisasmBuilder) =
  builder.Accumulate(AsmWordKind.Value, HexString.ofUInt64 i)

let inline private getMask sz =
  match sz with
  | 8<rt> -> 0xFFL
  | 16<rt> -> 0xFFFFL
  | 32<rt> -> 0xFFFFFFFFL
  | _ -> 0xFFFFFFFFFFFFFFFFL

let inline private buildPref (prefs: Prefix) (builder: IDisasmBuilder) =
  if prefs = Prefix.None then ()
  elif (prefs &&& Prefix.LOCK) <> Prefix.None then
    builder.Accumulate(AsmWordKind.String, "lock ")
  elif (prefs &&& Prefix.REPNZ) <> Prefix.None then
    builder.Accumulate(AsmWordKind.String, "repnz ")
  elif (prefs &&& Prefix.REPZ) <> Prefix.None then
    builder.Accumulate(AsmWordKind.String, "repz ")
  elif (prefs &&& Prefix.BND) <> Prefix.None then
    builder.Accumulate(AsmWordKind.String, "bnd ")
  else ()

let inline private buildOpcode opcode (builder: IDisasmBuilder) =
  builder.Accumulate(AsmWordKind.Mnemonic, Opcode.opcodeToString opcode)

let private buildDisplacement showSign (disp: Displacement) wordSize builder =
  let mask = WordSize.toRegType wordSize |> RegType.getMask |> uint64
  if showSign && disp < 0L then
    (builder: IDisasmBuilder).Accumulate(AsmWordKind.String, "-")
    iToHexStr (-disp) builder
  elif showSign then
    builder.Accumulate(AsmWordKind.String, "+")
    iToHexStr disp builder
  else
    uToHexStr (uint64 disp &&& mask) builder

let inline private buildAbsAddr selector (offset: Addr) builder =
  uToHexStr (uint64 selector) builder
  builder.Accumulate(AsmWordKind.String, ":")
  uToHexStr offset builder

let private prefix = { AsmWordKind = AsmWordKind.String; AsmWordValue = " ; <" }

let private suffix = { AsmWordKind = AsmWordKind.String; AsmWordValue = ">" }

let private mapNoSymbol addr =
  [| { AsmWordKind = AsmWordKind.String; AsmWordValue = " ; " }
     { AsmWordKind = AsmWordKind.Value
       AsmWordValue = HexString.ofUInt64 addr } |]

let private buildComment (builder: IDisasmBuilder) targetAddr =
  builder.AccumulateSymbol(targetAddr, prefix, suffix, mapNoSymbol)

let inline private buildRelAddr offset (builder: IDisasmBuilder) addr =
  if offset < 0L then builder.Accumulate(AsmWordKind.String, "-")
  else builder.Accumulate(AsmWordKind.String, "+")
  iToHexStr (abs offset) builder
  buildComment builder (addr + uint64 offset)

/// Zeroing/Merging (EVEX.z)
let inline buildEVEXZ ev (builder: IDisasmBuilder) =
  if ev.Z = Zeroing then builder.Accumulate(AsmWordKind.String, "{z}")
  else ()

module IntelSyntax = begin

  let inline private memDispToStr showSign disp wordSize builder =
    match disp with
    | None -> ()
    | Some d -> buildDisplacement showSign d wordSize builder

  let inline scaleToString (scale: Scale) (builder: IDisasmBuilder) =
    if scale = Scale.X1 then ()
    else
      builder.Accumulate(AsmWordKind.String, "*")
      builder.Accumulate(AsmWordKind.Value, (int scale).ToString())

  let private memScaleDispToStr emptyBase si d wordSize builder =
    match si with
    | None -> memDispToStr (not emptyBase) d wordSize builder
    | Some(i, scale) ->
      if emptyBase then () else builder.Accumulate(AsmWordKind.String, "+")
      builder.Accumulate(AsmWordKind.Variable, Register.toString i)
      scaleToString scale builder
      memDispToStr true d wordSize builder

  let private memAddrToStr b si disp wordSize builder =
    match b with
    | None -> memScaleDispToStr true si disp wordSize builder
    | Some b ->
      builder.Accumulate(AsmWordKind.Variable, Register.toString b)
      memScaleDispToStr false si disp wordSize builder

  let inline isFar (ins: Instruction) =
    match ins.Opcode, ins.Operands with
    | Opcode.JMP, OneOperand(OprDirAddr(Absolute _))
    | Opcode.CALL, OneOperand(OprDirAddr(Absolute _)) -> true
    | _ -> false

  let private ptrDirectiveString isFar = function
    | 8<rt> -> "byte ptr"
    | 16<rt> -> "word ptr"
    | 32<rt> -> if isFar then "word far ptr" else "dword ptr"
    | 48<rt> -> "fword ptr"
    | 64<rt> -> "qword ptr"
    | 80<rt> -> if isFar then "fword ptr" else "tbyte ptr"
    | 128<rt> -> "xmmword ptr"
    | 256<rt> -> "ymmword ptr"
    | 512<rt> -> "zmmword ptr"
    | 224<rt> | 864<rt> -> "" (* x87 FPU state *)
    | _ -> Terminator.impossible ()

  let mToString (ins: Instruction) (builder: IDisasmBuilder) b si d oprSz =
    let ptrDirective = ptrDirectiveString (isFar ins) oprSz
    match Prefix.getSegment ins.Prefixes with
    | None ->
      builder.Accumulate(AsmWordKind.String, ptrDirective)
      builder.Accumulate(AsmWordKind.String, " [")
      memAddrToStr b si d builder.WordSize builder
      builder.Accumulate(AsmWordKind.String, "]")
    | Some seg ->
      builder.Accumulate(AsmWordKind.String, ptrDirective)
      builder.Accumulate(AsmWordKind.String, " [")
      builder.Accumulate(AsmWordKind.Variable, Register.toString seg)
      builder.Accumulate(AsmWordKind.String, ":")
      memAddrToStr b si d builder.WordSize builder
      builder.Accumulate(AsmWordKind.String, "]")

  /// Opmask register
  let buildOpMask ePrx (builder: IDisasmBuilder) =
    if ePrx.AAA = 0uy then ()
    else
      builder.Accumulate(AsmWordKind.String, "{")
      builder.Accumulate(AsmWordKind.Variable,
        ePrx.AAA |> int |> Register.opmask |> Register.toString)
      builder.Accumulate(AsmWordKind.String, "}")

  let buildMask (ins: Instruction) builder =
    match ins.VEXInfo with
    | Some { EVEXPrx = Some ePrx } ->
      buildOpMask ePrx builder
      buildEVEXZ ePrx builder
    | _ -> ()

  let buildBroadcast (ins: Instruction) (builder: IDisasmBuilder) memSz =
    match ins.VEXInfo with
    | Some { EVEXPrx = Some ePrx; VectorLength = vl } ->
      if ePrx.B = 1uy then
        builder.Accumulate(AsmWordKind.String, "{1to")
        builder.Accumulate(AsmWordKind.Value, (vl / memSz).ToString())
        builder.Accumulate(AsmWordKind.String, "}")
      else ()
    | _ -> ()

  let buildRoundingControl (ins: Instruction) (builder: IDisasmBuilder) =
    match ins.VEXInfo with
    | Some { EVEXPrx = Some ePrx } ->
      if ePrx.B = 1uy then
        builder.Accumulate(AsmWordKind.String, ", {")
        builder.Accumulate(AsmWordKind.String, ePrx.RC.ToString().ToLower())
        builder.Accumulate(AsmWordKind.String, "-sae}")
      else ()
    | _ -> ()

  let oprToString ins opr (builder: IDisasmBuilder) =
    match opr with
    | OprReg reg ->
      builder.Accumulate(AsmWordKind.Variable, Register.toString reg)
    | OprMem(b, si, disp, oprSz) ->
      mToString ins builder b si disp oprSz
    | OprImm(imm, _) ->
      iToHexStr (imm &&& getMask ins.MainOperationSize) builder
    | OprDirAddr(Absolute(sel, offset, _)) -> buildAbsAddr sel offset builder
    | OprDirAddr(Relative(offset)) ->
      buildRelAddr offset builder ins.Address
    | Label _ -> Terminator.impossible ()

  let buildOprs (ins: Instruction) (builder: IDisasmBuilder) =
    match ins.Operands with
    | NoOperand -> ()
    | OneOperand(OprMem(Some Register.RIP, None, Some off, 64<rt>)) ->
      builder.Accumulate(AsmWordKind.String, " ")
      mToString ins builder (Some Register.RIP) None (Some off) 64<rt>
      buildComment builder (ins.Address + uint64 ins.Length + uint64 off)
    | OneOperand opr ->
      builder.Accumulate(AsmWordKind.String, " ")
      oprToString ins opr builder
    | TwoOperands(OprMem(Some R.RIP, None, Some disp, sz), opr) ->
      builder.Accumulate(AsmWordKind.String, " ")
      mToString ins builder (Some Register.RIP) None (Some disp) sz
      builder.Accumulate(AsmWordKind.String, ", ")
      oprToString ins opr builder
      buildComment builder (ins.Address + uint64 ins.Length + uint64 disp)
    | TwoOperands(opr, OprMem(Some R.RIP, None, Some disp, sz)) ->
      builder.Accumulate(AsmWordKind.String, " ")
      oprToString ins opr builder
      builder.Accumulate(AsmWordKind.String, ", ")
      mToString ins builder (Some Register.RIP) None (Some disp) sz
      buildComment builder (ins.Address + uint64 ins.Length + uint64 disp)
    | TwoOperands(opr1, (OprMem(_, _, _, memSz) as opr2)) ->
      builder.Accumulate(AsmWordKind.String, " ")
      oprToString ins opr1 builder
      buildMask ins builder
      builder.Accumulate(AsmWordKind.String, ", ")
      oprToString ins opr2 builder
      buildBroadcast ins builder memSz
    | TwoOperands(opr1, opr2) ->
      builder.Accumulate(AsmWordKind.String, " ")
      oprToString ins opr1 builder
      buildMask ins builder
      builder.Accumulate(AsmWordKind.String, ", ")
      oprToString ins opr2 builder
    | ThreeOperands(opr1, opr2, (OprMem(_, _, _, memSz) as opr3)) ->
      builder.Accumulate(AsmWordKind.String, " ")
      oprToString ins opr1 builder
      buildMask ins builder
      builder.Accumulate(AsmWordKind.String, ", ")
      oprToString ins opr2 builder
      builder.Accumulate(AsmWordKind.String, ", ")
      oprToString ins opr3 builder
      buildBroadcast ins builder memSz
    | ThreeOperands(opr1, opr2, (OprReg _ as opr3)) ->
      builder.Accumulate(AsmWordKind.String, " ")
      oprToString ins opr1 builder
      buildMask ins builder
      builder.Accumulate(AsmWordKind.String, ", ")
      oprToString ins opr2 builder
      builder.Accumulate(AsmWordKind.String, ", ")
      oprToString ins opr3 builder
      buildRoundingControl ins builder
    | ThreeOperands(opr1, opr2, opr3) ->
      builder.Accumulate(AsmWordKind.String, " ")
      oprToString ins opr1 builder
      buildMask ins builder
      builder.Accumulate(AsmWordKind.String, ", ")
      oprToString ins opr2 builder
      builder.Accumulate(AsmWordKind.String, ", ")
      oprToString ins opr3 builder
    | FourOperands(opr1, opr2, (OprMem(_, _, _, memSz) as opr3), opr4) ->
      builder.Accumulate(AsmWordKind.String, " ")
      oprToString ins opr1 builder
      buildMask ins builder
      builder.Accumulate(AsmWordKind.String, ", ")
      oprToString ins opr2 builder
      builder.Accumulate(AsmWordKind.String, ", ")
      oprToString ins opr3 builder
      buildBroadcast ins builder memSz
      builder.Accumulate(AsmWordKind.String, ", ")
      oprToString ins opr4 builder
    | FourOperands(opr1, opr2, opr3, opr4) ->
      builder.Accumulate(AsmWordKind.String, " ")
      oprToString ins opr1 builder
      buildMask ins builder
      builder.Accumulate(AsmWordKind.String, ", ")
      oprToString ins opr2 builder
      builder.Accumulate(AsmWordKind.String, ", ")
      oprToString ins opr3 builder
      builder.Accumulate(AsmWordKind.String, ", ")
      oprToString ins opr4 builder

  let disasm (builder: IDisasmBuilder) (ins: Instruction) =
    builder.AccumulateAddrMarker ins.Address
    buildPref ins.Prefixes builder
    buildOpcode ins.Opcode builder
    buildOprs ins builder

end

module ATTSyntax = begin

  let buildDisp disp showSign wordSize builder =
    match disp with
    | Some d -> buildDisplacement showSign d wordSize builder
    | None -> ()

  let buildScaledIndex si (builder: IDisasmBuilder) =
    match si with
    | None -> ()
    | Some(i, Scale.X1) ->
      builder.Accumulate(AsmWordKind.String, ", %")
      builder.Accumulate(AsmWordKind.Variable, Register.toString i)
    | Some(i, scale) ->
      builder.Accumulate(AsmWordKind.String, ", %")
      builder.Accumulate(AsmWordKind.Variable, Register.toString i)
      builder.Accumulate(AsmWordKind.String, ", ")
      builder.Accumulate(AsmWordKind.Value, (int scale).ToString())

  let buildSeg seg (builder: IDisasmBuilder) =
    builder.Accumulate(AsmWordKind.String, "%")
    builder.Accumulate(AsmWordKind.Variable, Register.toString seg)
    builder.Accumulate(AsmWordKind.String, ":")

  let buildBasedMemory b si d wordSize builder =
    buildDisp d true wordSize builder
    builder.Accumulate(AsmWordKind.String, "(%")
    builder.Accumulate(AsmWordKind.Variable, Register.toString b)
    buildScaledIndex si builder
    builder.Accumulate(AsmWordKind.String, ")")

  let buildNobaseMemory (i, s) d wordSize builder =
    buildDisp d true wordSize builder
    match s with
    | Scale.X1 ->
      builder.Accumulate(AsmWordKind.String, "(%")
      builder.Accumulate(AsmWordKind.Variable, Register.toString i)
    | _ ->
      builder.Accumulate(AsmWordKind.String, "(, %")
      builder.Accumulate(AsmWordKind.Variable, Register.toString i)
      builder.Accumulate(AsmWordKind.String, ", ")
      builder.Accumulate(AsmWordKind.Value, (int s).ToString())
    builder.Accumulate(AsmWordKind.String, ")")

  let buildMemOp (ins: Instruction) wordSize builder b si d isFst =
    if (ins :> IInstruction).IsBranch then
      (builder: IDisasmBuilder).Accumulate(AsmWordKind.String, " *")
    elif isFst then
      builder.Accumulate(AsmWordKind.String, " ")
    else
      builder.Accumulate(AsmWordKind.String, ", ")
    match Prefix.getSegment ins.Prefixes, b, si with
    | None, Some b, _ ->
      buildBasedMemory b si d wordSize builder
    | None, None, None ->
      buildDisp d false wordSize builder
    | None, None, Some si ->
      buildNobaseMemory si d wordSize builder
    | Some seg, Some b, _ ->
      buildSeg seg builder
      buildBasedMemory b si d wordSize builder
    | Some seg, None, _ ->
      buildSeg seg builder
      buildDisp d false wordSize builder

  let buildMask (ins: Instruction) (builder: IDisasmBuilder) =
    match ins.VEXInfo with
    | Some { EVEXPrx = Some ePrx } ->
      if ePrx.AAA = 0uy then
        ()
      else
        builder.Accumulate(AsmWordKind.String, "{%")
        builder.Accumulate(AsmWordKind.Variable,
          ePrx.AAA |> int |> Register.opmask |> Register.toString)
        builder.Accumulate(AsmWordKind.String, "}")
      buildEVEXZ ePrx builder
    | _ -> ()

  let buildOpr (ins: Instruction) wordSize isFst (builder: IDisasmBuilder) opr =
    match opr with
    | OprReg reg ->
      if isFst then
        if (ins :> IInstruction).IsBranch then
          builder.Accumulate(AsmWordKind.String, " *%")
        else
          builder.Accumulate(AsmWordKind.String, " %")
      else
        builder.Accumulate(AsmWordKind.String, ", %")
      builder.Accumulate(AsmWordKind.Variable, Register.toString reg)
    | OprMem(b, si, disp, _oprSz) ->
      buildMemOp ins wordSize builder b si disp isFst
    | OprImm(imm, _) ->
      if isFst then builder.Accumulate(AsmWordKind.String, " $")
      else builder.Accumulate(AsmWordKind.String, ", $")
      iToHexStr (imm &&& getMask ins.MainOperationSize) builder
    | OprDirAddr(Absolute(sel, offset, _)) ->
      builder.Accumulate(AsmWordKind.String, " ")
      buildAbsAddr sel offset builder
    | OprDirAddr(Relative(offset)) ->
      builder.Accumulate(AsmWordKind.String, " ")
      buildRelAddr offset builder ins.Address
    | Label _ -> Terminator.impossible ()

  let addOpSuffix (builder: IDisasmBuilder) = function
    | 8<rt> -> builder.Accumulate(AsmWordKind.Mnemonic, "b")
    | 16<rt> -> builder.Accumulate(AsmWordKind.Mnemonic, "w")
    | 32<rt> -> builder.Accumulate(AsmWordKind.Mnemonic, "l")
    | 64<rt> -> builder.Accumulate(AsmWordKind.Mnemonic, "q")
    | 80<rt> -> builder.Accumulate(AsmWordKind.Mnemonic, "t")
    | _ -> ()

  let buildOpSuffix operands builder =
    match operands with
    | OneOperand(OprMem(_, _, _, sz)) -> addOpSuffix builder sz
    | TwoOperands(OprMem(_, _, _, sz), _)
    | TwoOperands(_, OprMem(_, _, _, sz)) -> addOpSuffix builder sz
    | ThreeOperands(OprMem(_, _, _, sz), _, _)
    | ThreeOperands(_, OprMem(_, _, _, sz), _)
    | ThreeOperands(_, _, OprMem(_, _, _, sz)) -> addOpSuffix builder sz
    | FourOperands(OprMem(_, _, _, sz), _, _, _)
    | FourOperands(_, OprMem(_, _, _, sz), _, _)
    | FourOperands(_, _, OprMem(_, _, _, sz), _)
    | FourOperands(_, _, _, OprMem(_, _, _, sz)) -> addOpSuffix builder sz
    | _ -> ()

  let buildSrcSizeSuffix operands wordSize builder =
    match operands with
    | TwoOperands(_, OprMem(_, _, _, sz)) -> addOpSuffix builder sz
    | TwoOperands(_, OprReg src) ->
      Register.toRegType wordSize src |> addOpSuffix builder
    | _ -> Terminator.impossible ()

  let buildDstSizeSuffix operands wordSize builder =
    match operands with
    | TwoOperands(OprReg dst, _) ->
      Register.toRegType wordSize dst |> addOpSuffix builder
    | _ -> Terminator.impossible ()

  let buildOprs (ins: Instruction) (builder: IDisasmBuilder) =
    match ins.Operands with
    | NoOperand -> ()
    | OneOperand opr ->
      buildOpr ins builder.WordSize true builder opr
    | TwoOperands(opr1, opr2) ->
      buildOpr ins builder.WordSize true builder opr2
      buildOpr ins builder.WordSize false builder opr1
      buildMask ins builder
    | ThreeOperands(opr1, opr2, opr3) ->
      buildOpr ins builder.WordSize true builder opr3
      buildOpr ins builder.WordSize false builder opr2
      buildOpr ins builder.WordSize false builder opr1
      buildMask ins builder
    | FourOperands(opr1, opr2, opr3, opr4) ->
      buildOpr ins builder.WordSize true builder opr4
      buildOpr ins builder.WordSize false builder opr3
      buildOpr ins builder.WordSize false builder opr2
      buildOpr ins builder.WordSize false builder opr1
      buildMask ins builder

  let disasm (builder: IDisasmBuilder) (ins: Instruction) =
    let wordSize = builder.WordSize
    builder.AccumulateAddrMarker ins.Address
    buildPref ins.Prefixes builder
    match ins.Opcode with
    | Opcode.MOVSX ->
      builder.Accumulate(AsmWordKind.Mnemonic, "movs")
      buildSrcSizeSuffix ins.Operands wordSize builder
      buildDstSizeSuffix ins.Operands wordSize builder
    | Opcode.MOVZX ->
      builder.Accumulate(AsmWordKind.Mnemonic, "movz")
      buildSrcSizeSuffix ins.Operands wordSize builder
      buildDstSizeSuffix ins.Operands wordSize builder
    | Opcode.MOVSXD ->
      builder.Accumulate(AsmWordKind.Mnemonic, "movslq")
    (* Below are the list of opcodes that should not be used with a suffix. *)
    | Opcode.ADDSD
    | Opcode.ADDSS
    | Opcode.CMPSD
    | Opcode.CMPSS
    | Opcode.COMISD
    | Opcode.COMISS
    | Opcode.CVTDQ2PD
    | Opcode.CVTPI2PS
    | Opcode.CVTPS2PD
    | Opcode.CVTPS2PI
    | Opcode.CVTSD2SS
    | Opcode.CVTSS2SD
    | Opcode.CVTTPS2PI
    | Opcode.CVTTSD2SI
    | Opcode.CVTTSS2SI
    | Opcode.DIVSD
    | Opcode.DIVSS
    | Opcode.FBLD
    | Opcode.FBSTP
    | Opcode.FCOMP
    | Opcode.FCOM
    | Opcode.FDIV
    | Opcode.FDIVR
    | Opcode.FIADD
    | Opcode.FICOMP
    | Opcode.FICOM
    | Opcode.FIDIVR
    | Opcode.FIDIV
    | Opcode.FILD
    | Opcode.FIMUL
    | Opcode.FISTP
    | Opcode.FISTTP
    | Opcode.FISUBR
    | Opcode.FISUB
    | Opcode.FMUL
    | Opcode.FST
    | Opcode.FSUB
    | Opcode.FSUBR
    | Opcode.IRET
    | Opcode.LAR
    | Opcode.LDMXCSR
    | Opcode.MAXSD
    | Opcode.MAXSS
    | Opcode.MINSD
    | Opcode.MINSS
    | Opcode.MOVD
    | Opcode.MOVHPD
    | Opcode.MOVHPS
    | Opcode.MOVLPD
    | Opcode.MOVLPS
    | Opcode.MOVQ
    | Opcode.MOVSD
    | Opcode.MOVSS
    | Opcode.MULSD
    | Opcode.MULSS
    | Opcode.PACKUSWB
    | Opcode.PADDSW
    | Opcode.PCMPEQB
    | Opcode.PCMPGTD
    | Opcode.PINSRW
    | Opcode.PMAXSW
    | Opcode.POR
    | Opcode.PREFETCHNTA
    | Opcode.PREFETCHT0
    | Opcode.PSADBW
    | Opcode.PSLLD
    | Opcode.PSUBSB
    | Opcode.PXOR
    | Opcode.SGDT
    | Opcode.SIDT
    | Opcode.SQRTSD
    | Opcode.SQRTSS
    | Opcode.STMXCSR
    | Opcode.SUBSD
    | Opcode.SUBSS
    | Opcode.UCOMISD
    | Opcode.UCOMISS
    | Opcode.VFMSUB213SD
    | Opcode.VFMSUB213PD
    | Opcode.VFNMSUB231SD
    | Opcode.VFNMSUB231PD
    | Opcode.VMOVDDUP
    | Opcode.VMOVD
    | Opcode.VMOVQ
    | Opcode.VPBROADCASTB
    | Opcode.VPBROADCASTQ ->
      buildOpcode ins.Opcode builder
    (* Far jmp/call *)
    | Opcode.JMP when IntelSyntax.isFar ins ->
      builder.Accumulate(AsmWordKind.Mnemonic, "ljmp")
      buildOpSuffix ins.Operands builder
    | Opcode.CALL when IntelSyntax.isFar ins ->
      builder.Accumulate(AsmWordKind.Mnemonic, "lcall")
      buildOpSuffix ins.Operands builder
    | opcode ->
      buildOpcode opcode builder
      buildOpSuffix ins.Operands builder
    buildOprs ins builder

end
