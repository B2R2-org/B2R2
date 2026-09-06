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
  if prefs = Prefix.None then
    ()
  elif (prefs &&& Prefix.LOCK) <> Prefix.None then
    builder.Accumulate(AsmWordKind.String, "lock ")
  elif (prefs &&& Prefix.REPNZ) <> Prefix.None then
    builder.Accumulate(AsmWordKind.String, "repnz ")
  elif (prefs &&& Prefix.REPZ) <> Prefix.None then
    builder.Accumulate(AsmWordKind.String, "repz ")
  elif (prefs &&& Prefix.BND) <> Prefix.None then
    builder.Accumulate(AsmWordKind.String, "bnd ")
  else
    ()

let inline private buildOpcode opcode (builder: IDisasmBuilder) =
  builder.Accumulate(AsmWordKind.Mnemonic, Opcode.toString opcode)

let private buildDisplacement showSign (disp: Displacement) wordSize builder =
  let mask = WordSize.toRegType wordSize |> RegType.makeMask |> uint64
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

let private prefix = { AsmWordKind = AsmWordKind.String; AsmWordValue = "<" }

let private suffix = { AsmWordKind = AsmWordKind.String; AsmWordValue = ">" }

let private mapNoSymbol addr =
  [| { AsmWordKind = AsmWordKind.Value
       AsmWordValue = HexString.ofUInt64 addr } |]

let private buildComment (builder: IDisasmBuilder) targetAddr =
  builder.Accumulate(AsmWordKind.CommentDelimiter, " ; ")
  builder.AccumulateSymbol(targetAddr, prefix, suffix, mapNoSymbol)

let inline private buildRelAddr offset (builder: IDisasmBuilder) addr =
  let prefix = if offset < 0L then "-" else "+"
  builder.Accumulate(AsmWordKind.Value, prefix + HexString.ofInt64 (abs offset))
  buildComment builder (addr + uint64 offset)

/// Zeroing/Merging (EVEX.z)
let inline buildEVEXZ ev (builder: IDisasmBuilder) =
  if ev.Z = Zeroing then builder.Accumulate(AsmWordKind.String, "{z}") else ()

/// The EVEX prefix of an instruction that carries one.
let private evexPrefixOf (ins: Instruction) =
  match ins.VEXInfo with
  | Some { EVEXPrx = Some ePrx } -> ValueSome ePrx
  | _ -> ValueNone

/// Whether an operand is an immediate, which is the one kind a static rounding
/// decoration never attaches to.
let private isImmediate = function
  | OprImm _ -> true
  | _ -> false

/// The operand a static rounding or SAE decoration belongs to: the last one
/// that is not an immediate. Every form in the manual puts it there, whether
/// or not an immediate follows -- VGETMANTPS carries it on its source and
/// VFIXUPIMMPS on its second, both ahead of an imm8. Negative when the
/// instruction carries no such decoration.
let private roundingOperandIndex (ins: Instruction) count =
  match evexPrefixOf ins with
  | ValueSome ePrx when ePrx.RCDecor <> NoRounding ->
    let mutable i = count - 1
    while i >= 0 && isImmediate (Operands.item i ins.Operands) do
      i <- i - 1
    i
  | _ ->
    -1

/// The text of a static rounding decoration: the rounding mode with SAE where
/// the instruction takes one, SAE alone where it does not.
let private roundingText (ePrx: EVEXPrefix) =
  match ePrx.RCDecor with
  | StaticRounding -> ePrx.RC.ToString().ToLower() + "-sae"
  | _ -> "sae"

/// The count of lanes an embedded broadcast fills, from the width of the one
/// element it reads. The operand declared that width, which is why the memory
/// operand's own size cannot stand in for it. Both syntaxes spell it the same
/// way and attach it to the same operand.
let private buildBroadcast (ins: Instruction) (builder: IDisasmBuilder) =
  match ins.VEXInfo, ins.BroadcastElemSize with
  | Some { VectorLength = vl }, ValueSome elemSz ->
    builder.Accumulate(AsmWordKind.String, "{1to")
    builder.Accumulate(AsmWordKind.Value, (vl / elemSz).ToString())
    builder.Accumulate(AsmWordKind.String, "}")
  | _ ->
    ()

module IntelSyntax = begin

  let inline private memDispToStr showSign disp wordSize builder =
    match disp with
    | None -> ()
    | Some d -> buildDisplacement showSign d wordSize builder

  let inline scaleToString (scale: Scale) (builder: IDisasmBuilder) =
    if scale = Scale.X1 then
      ()
    else
      builder.Accumulate(AsmWordKind.String, "*")
      builder.Accumulate(AsmWordKind.Value, (int scale).ToString())

  let private memScaleDispToStr emptyBase si d wordSize builder =
    match si with
    | None ->
      memDispToStr (not emptyBase) d wordSize builder
    | Some(i, scale) ->
      if emptyBase then () else builder.Accumulate(AsmWordKind.String, "+")
      builder.Accumulate(AsmWordKind.Variable, Register.toString i)
      scaleToString scale builder
      memDispToStr true d wordSize builder

  let private memAddrToStr b si disp wordSize builder =
    match b with
    | None ->
      memScaleDispToStr true si disp wordSize builder
    | Some b ->
      builder.Accumulate(AsmWordKind.Variable, Register.toString b)
      memScaleDispToStr false si disp wordSize builder

  let inline private isFar (ins: Instruction) =
    match ins.Opcode with
    | Opcode.JMP | Opcode.CALL -> ins.IsFar
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
    (* Intel syntax has no directive this wide: the x87 state areas FLDENV
       and FRSTOR read, and the 48-byte Key Locker handle. objdump prints
       these bare too. *)
    | 224<rt> | 384<rt> | 864<rt> -> ""
    | _ -> Terminator.impossible ()

  /// Opens a memory operand, leaving out the separating space when the width
  /// brings no directive for it to separate.
  let private openMemOperand (builder: IDisasmBuilder) ptrDirective =
    if ptrDirective = "" then
      builder.Accumulate(AsmWordKind.String, "[")
    else
      builder.Accumulate(AsmWordKind.String, ptrDirective)
      builder.Accumulate(AsmWordKind.String, " [")

  let mToString (ins: Instruction) (builder: IDisasmBuilder) b si d oprSz =
    (* LEA computes an address and reads no memory, so no access width is being
       named. Vol 2A tables 3-57 and 3-58 give it an operand size and an address
       size, which the destination and base registers already show, and neither
       is a width read from memory. objdump and Capstone print it bare, and GNU
       as encodes the same bytes whichever directive is written there. *)
    let ptrDirective =
      if ins.Opcode = Opcode.LEA then
        ""
      else
        ptrDirectiveString (isFar ins) oprSz
    match Prefix.getSegment ins.Prefixes with
    | None ->
      openMemOperand builder ptrDirective
      memAddrToStr b si d builder.WordSize builder
      builder.Accumulate(AsmWordKind.String, "]")
    | Some seg ->
      openMemOperand builder ptrDirective
      builder.Accumulate(AsmWordKind.Variable, Register.toString seg)
      builder.Accumulate(AsmWordKind.String, ":")
      memAddrToStr b si d builder.WordSize builder
      builder.Accumulate(AsmWordKind.String, "]")

  /// Opmask register
  let buildOpMask ePrx (builder: IDisasmBuilder) =
    if ePrx.AAA = 0uy then
      ()
    else
      builder.Accumulate(AsmWordKind.String, "{")
      builder.Accumulate(AsmWordKind.Variable,
        ePrx.AAA |> int |> RegisterHelper.opmask |> Register.toString)
      builder.Accumulate(AsmWordKind.String, "}")

  let buildMask (ins: Instruction) builder =
    match ins.VEXInfo with
    | Some { EVEXPrx = Some ePrx } ->
      buildOpMask ePrx builder
      buildEVEXZ ePrx builder
    | _ ->
      ()

  let buildRoundingControl (ins: Instruction) (builder: IDisasmBuilder) =
    match evexPrefixOf ins with
    | ValueSome ePrx ->
      builder.Accumulate(AsmWordKind.String, "{")
      builder.Accumulate(AsmWordKind.String, roundingText ePrx)
      builder.Accumulate(AsmWordKind.String, "}")
    | ValueNone ->
      ()

  let oprToString ins opr (builder: IDisasmBuilder) =
    match opr with
    | OprReg reg ->
      builder.Accumulate(AsmWordKind.Variable, Register.toString reg)
    | OprMem(b, si, disp, oprSz) ->
      mToString ins builder b si disp oprSz
    | OprImm(imm, _) ->
      iToHexStr (imm &&& getMask ins.MainOperationSize) builder
    | OprDirAddr(Absolute(sel, offset, _)) ->
      buildAbsAddr sel offset builder
    | OprDirAddr(Relative(offset)) ->
      buildRelAddr offset builder ins.Address
    | Label _ ->
      Terminator.impossible ()

  /// The RIP-relative target an operand names, for the comment that follows
  /// the operands. At most one operand can name one.
  let private ripTargetOf (ins: Instruction) count =
    let mutable target = ValueNone
    for i in 0 .. count - 1 do
      match Operands.item i ins.Operands with
      | OprMem(Some Register.RIP, None, Some disp, _) ->
        target <- ValueSome(ins.Address + uint64 ins.Length + uint64 disp)
      | _ ->
        ()
    target

  /// The decorations that follow one operand. Which operand each belongs to is
  /// decided by position rather than guessed from the operand's shape, which
  /// is what used to let a RIP-relative destination lose its write mask and a
  /// broadcast anywhere but the last operand go unprinted.
  let private buildDecorations ins builder idx isRoundingOpr opr =
    if idx = 0 then buildMask ins builder else ()
    match opr with
    | OprMem _ -> buildBroadcast ins builder
    | _ -> ()
    if isRoundingOpr then buildRoundingControl ins builder else ()

  let buildOprs (ins: Instruction) (builder: IDisasmBuilder) =
    let count = Operands.count ins.Operands
    let roundingIdx = roundingOperandIndex ins count
    for i in 0 .. count - 1 do
      let opr = Operands.item i ins.Operands
      builder.Accumulate(AsmWordKind.String, if i = 0 then " " else ", ")
      oprToString ins opr builder
      buildDecorations ins builder i (i = roundingIdx) opr
    match ripTargetOf ins count with
    | ValueSome target -> buildComment builder target
    | ValueNone -> ()

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
    | None ->
      ()
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
          ePrx.AAA |> int |> RegisterHelper.opmask |> Register.toString)
        builder.Accumulate(AsmWordKind.String, "}")
      buildEVEXZ ePrx builder
    | _ ->
      ()

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
    | Label _ ->
      Terminator.impossible ()

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
    | TwoOperands(_, OprMem(_, _, _, sz)) ->
      addOpSuffix builder sz
    | TwoOperands(_, OprReg src) ->
      RegisterHelper.toRegType wordSize src |> addOpSuffix builder
    | _ ->
      Terminator.impossible ()

  let buildDstSizeSuffix operands wordSize builder =
    match operands with
    | TwoOperands(OprReg dst, _) ->
      RegisterHelper.toRegType wordSize dst |> addOpSuffix builder
    | _ ->
      Terminator.impossible ()

  /// A static rounding decoration in AT&T order, where it precedes the operand
  /// it belongs to rather than following it. It takes a separator of its own,
  /// and the first slot when nothing has been printed yet.
  let private buildRounding ins (builder: IDisasmBuilder) isFst =
    builder.Accumulate(AsmWordKind.String, if isFst then " {" else ", {")
    match evexPrefixOf ins with
    | ValueSome ePrx ->
      builder.Accumulate(AsmWordKind.String, roundingText ePrx)
    | ValueNone ->
      ()
    builder.Accumulate(AsmWordKind.String, "}")

  /// AT&T writes the operands in the opposite order, so the walk runs
  /// backwards; the decorations still belong to the positions they do in the
  /// manual, and are placed by index rather than by shape.
  let buildOprs (ins: Instruction) (builder: IDisasmBuilder) =
    let count = Operands.count ins.Operands
    let roundingIdx = roundingOperandIndex ins count
    let mutable isFst = true
    for i in count - 1 .. -1 .. 0 do
      let opr = Operands.item i ins.Operands
      if i = roundingIdx then
        buildRounding ins builder isFst
        isFst <- false
      else
        ()
      buildOpr ins builder.WordSize isFst builder opr
      isFst <- false
      match opr with
      | OprMem _ -> buildBroadcast ins builder
      | _ -> ()
      if i = 0 then buildMask ins builder else ()

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
    | Opcode.JMP when ins.IsFar ->
      builder.Accumulate(AsmWordKind.Mnemonic, "ljmp")
      buildOpSuffix ins.Operands builder
    | Opcode.CALL when ins.IsFar ->
      builder.Accumulate(AsmWordKind.Mnemonic, "lcall")
      buildOpSuffix ins.Operands builder
    | opcode ->
      buildOpcode opcode builder
      buildOpSuffix ins.Operands builder
    buildOprs ins builder

end
