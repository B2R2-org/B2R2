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

namespace B2R2.FrontEnd.Intel

open System
open B2R2
open B2R2.FrontEnd.BinLifter
(* Shadows B2R2's own OneByte, which the opcode-map cases need. *)
open B2R2.FrontEnd.Intel
open B2R2.FrontEnd.Intel.ParsingFunctions
open LanguagePrimitives

/// Represents a parser for Intel (x86 or x86-64) instructions.
type IntelParser(wordSz, reader) =
  /// Split a byte value into two fileds (high 3 bits; low 5 bits), and
  /// categorize prefix values into 8 groups based on the high 3 bits (= 2^3).
  /// The below array is a collection of bitmaps that maps the low 5-bit value
  /// to a bit value indicating whether the given byte value is a prefix value
  /// or not.
  let prefixCheck =
    [| 0x0u        (* 000xxxxx = cannot be a prefix value *)
       0x40404040u (* 001xxxxx = 26/2e/36/3e is possible *)
       0x0u        (* 010xxxxx = cannot be a prefix value *)
       0x000000f0u (* 011xxxxx = 64/65/66/67 is possible *)
       0x0u
       0x0u
       0x0u
       0x000d0000u (* 111xxxxx = f0/f2/f3 is possible *) |]

  let mutable disasm = Disasm.Delegate Disasm.IntelSyntax.disasm

  let lifter =
    { new ILiftable with
        member _.Lift(ins, builder) = Lifter.translate ins ins.Length builder
        member _.Disasm(ins, builder) = disasm.Invoke(builder, ins); builder }

  let phlp = ParsingHelper(reader, wordSz, lifter)

  /// Returns true when the instruction offers embedded rounding, which is what
  /// gives EVEX.b its {er} meaning. {sae} alone does not: it leaves L'L as the
  /// vector length.
  let declaresStaticRounding (insCore: InstructionCore) =
    insCore.Operands
    |> Array.exists (function
      | RMEr _ | RMBcstEr _ -> true
      | _ -> false)

  /// Returns true when EVEX.b on a register form selects a rounding mode. L'L
  /// then holds that mode rather than the vector length, so only the variant
  /// offering {er} can match. See Intel SDM Vol. 2A, Section 2.6.7.
  let usesStaticRounding (span: ByteSpan) (phlp: ParsingHelper) ins =
    match phlp.VEXInfo with
    | Some { EVEXPrx = Some evex } when evex.B = 1uy ->
      Operands.modIsReg span[phlp.CurrPos]
      && Array.exists declaresStaticRounding ins
    | _ -> false

  /// Returns true when the VEX/EVEX vector length satisfies the instruction's
  /// vector-length constraint (or the constraint is absent).
  let matchVectorLength isRounding (vex: VEXInfo option) (i: InstructionCore) =
    if i.VectorLength = VectorLength.None then true
    elif isRounding then declaresStaticRounding i
    else
      match vex with
      | Some v ->
        match v.VectorLength with
        | 128<rt> -> i.VectorLength = VectorLength.V128
        | 256<rt> -> i.VectorLength = VectorLength.V256
        | 512<rt> -> i.VectorLength = VectorLength.V512
        | _ -> false
      | _ -> true

  /// Returns the distinct operand sizes from an instruction's descriptors.
  /// None entries represent operands with no explicit size.
  let collectDistinctOpSizes operands =
    Array.map (fun o ->
      match o with
      | RM sz | Reg(sz, _) | Mem sz | Imm sz | Rel sz | Moffs sz
      | Far sz -> Some sz
      | FixedReg(Register.AX) -> Some 16<rt>
      | _ -> None) operands
    |> Array.distinct

  /// Returns true when every operand is 8-bit, meaning REX semantics do not
  /// apply to this instruction. Reads the descriptors directly rather than
  /// the distinct sizes: this is the first thing matchREX asks, so it runs
  /// once per candidate of every instruction, and building an array to ask
  /// it cost more than the question.
  let isAllOprSize8 (operands: OperandType[]) =
    operands.Length > 0
    && operands
       |> Array.forall (fun o ->
         match o with
         | RM sz | Reg(sz, _) | Mem sz | Imm sz | Rel sz | Moffs sz
         | Far sz -> sz = 8<rt>
         | _ -> false)

  /// Returns true when REX.W picks nothing out of this slot and so rides
  /// along inert. A row has to ask for the wider form before W is doing any
  /// work: TEST's 64-bit row asks at 85h and so keeps the 32-bit row from
  /// answering the prefixed bytes, while nothing asks at A8h, where the
  /// operand is a byte and there is no width to switch to. VEX and EVEX
  /// carry a W of their own, which this leaves alone.
  let ignoresREXW (phlp: ParsingHelper) (ins: InstructionCore[]) =
    let asksForW (i: InstructionCore) =
      i.REXPrefixType = REXPrefixType.W1
      || i.REXPrefixType = REXPrefixType.REXW
    phlp.VEXInfo.IsNone && not (Array.exists asksForW ins)

  /// Returns true when the observed REX prefix satisfies the constraint
  /// declared in the instruction core (NOREX / W0 / W1 / WIG / REXW).
  let matchREX (phlp: ParsingHelper) ins (insCore: InstructionCore) =
    let insREX = insCore.REXPrefixType
    match phlp.REXPrefix with
    | _ when isAllOprSize8 insCore.Operands -> true
    | REXPrefix.NOREX ->
      (insREX = REXPrefixType.WIG) || (insREX = REXPrefixType.W0) ||
      (insREX = REXPrefixType.NOREX)
    | r when (r &&& REXPrefix.REXW) = REXPrefix.REXW ->
      (insREX = REXPrefixType.WIG) || (insREX = REXPrefixType.W1) ||
      (insREX = REXPrefixType.REXW) ||
      (insREX = REXPrefixType.NOREX && ignoresREXW phlp ins)
    | _ ->
      (* A prefix with W clear. It still extends registers, so a row that says
         nothing about W matches; one that asks for W1 does not, and letting it
         through leaves VFMADD132PS and VFMADD132PD both matching their shared
         opcode byte with nothing but table order to tell them apart. *)
      (insREX = REXPrefixType.WIG) || (insREX = REXPrefixType.W0) ||
      (insREX = REXPrefixType.NOREX) || (insREX = REXPrefixType.REX)

  /// Returns true when pref satisfies insPref, treating Legacy NP as a fallback
  /// for Mandatory NP.
  let matchPrefixType pref insPref =
    match pref with
    | Mandatory NP -> insPref = Mandatory NP || insPref = Legacy NP
    | Mandatory _ ->
      if insPref = Legacy NP then false
      else pref = insPref
    | _ -> true

  /// Returns true when 66h names an instruction in this slot rather than
  /// setting the operand size. A row has to ask for it: MOVUPD asks at 0F 10
  /// and so keeps MOVUPS from answering the prefixed bytes, while nothing
  /// asks at 0F 38 F1, which leaves 66h free to mean the width MOVBE's
  /// 16-bit form is written with. Under F2h a row asks for the pair, so
  /// CRC32's narrow source is a separate question from MOVBE's.
  let is66hOpcodeSelector (ins: InstructionCore[]) mPref =
    let asked =
      if Prefix.hasREPNZ mPref then Mandatory P66F2 else Mandatory P66
    ins |> Array.exists (fun i -> i.PrefixType = asked)

  /// Returns true when the current prefix state satisfies insPref, with Legacy
  /// NP as a fallback for Mandatory NP.
  let matchPrefixWithLegacyFallback (phlp: ParsingHelper) ins insPref =
    let pref =
      match phlp.VEXInfo with
      | Some v -> v.VPrefixes
      | _ -> phlp.Prefixes
    let sel = pref &&& (Prefix.OPSIZE ||| Prefix.REPZ ||| Prefix.REPNZ)
    (* Where no row asks for 66h it is not selecting anything, so it is left
       out of the question here and matchOperandSize reads it instead. *)
    let mPref =
      if Prefix.hasOprSz sel && not (is66hOpcodeSelector ins sel) then
        sel &&& (Prefix.REPZ ||| Prefix.REPNZ)
      else sel
    if Prefix.hasOprSz mPref && Prefix.hasREPNZ mPref then
      insPref = Mandatory P66F2
    elif Prefix.hasOprSz mPref then
      insPref = Mandatory P66 || insPref = Legacy NP
    elif Prefix.hasREPZ mPref then
      insPref = Mandatory F3 || insPref = Legacy NP
    elif Prefix.hasREPNZ mPref then
      insPref = Mandatory F2 || insPref = Legacy NP
    elif mPref = Prefix.None then
      insPref = Legacy NP || insPref = Mandatory NP
    else
      false

  /// Returns the effective PrefixType for opcodes that deviate from standard
  /// mandatory-prefix rules; None for all other opcodes.
  let tryResolveSpecialPrefix (phlp: ParsingHelper) opByte =
    if phlp.VEXInfo.IsSome then None
    else
      match phlp.OpcodeClass with
      | OpcodeClass.Normal OneByte
        when opByte = 0x90uy && Prefix.hasREPZ phlp.Prefixes ->
        Some(Mandatory F3) // F3 90 = PAUSE
      | _ -> None

  /// Returns true when the current prefix satisfies the instruction's
  /// requirement, applying special-case resolution where needed.
  let matchPrefix (phlp: ParsingHelper) ins opByte insPref =
    match tryResolveSpecialPrefix phlp opByte with
    | Some pref -> matchPrefixType pref insPref
    | None -> matchPrefixWithLegacyFallback phlp ins insPref

  /// The prefixes a row named, which are the ones that picked it out rather
  /// than describing its operands. Dropping the rest would lose what they
  /// said: the 66h ahead of TZCNT's F3 set the operand size and nothing else
  /// records that it was there.
  let selectorPrefixes = function
    | Mandatory P66 -> Prefix.OPSIZE
    | Mandatory F3 -> Prefix.REPZ
    | Mandatory F2 -> Prefix.REPNZ
    | Mandatory P66F2 -> Prefix.OPSIZE ||| Prefix.REPNZ
    | _ -> Prefix.None

  /// The prefixes to drop after parsing. A VEX prefix carries its own copy of
  /// all three, so none of the legacy set outlives it.
  let consumedPrefixes (phlp: ParsingHelper) (insCore: InstructionCore) =
    match phlp.VEXInfo with
    | Some _ -> Prefix.OPSIZE ||| Prefix.REPZ ||| Prefix.REPNZ
    | None ->
      match tryResolveSpecialPrefix phlp (uint8 insCore.OpcodeByte) with
      | Some pref -> selectorPrefixes pref
      | None -> selectorPrefixes insCore.PrefixType

  /// Returns true for opcodes that implicitly operate on 16-bit operands
  /// without encoding an explicit size (e.g., MOVSW, PUSHF, IRET).
  let hasImplicit16BitOprSize = function
    | Opcode.CBW | Opcode.CWD
    | Opcode.PUSHF | Opcode.PUSHA
    | Opcode.POPF | Opcode.POPA
    | Opcode.MOVSW | Opcode.CMPSW | Opcode.SCASW | Opcode.LODSW | Opcode.STOSW
    | Opcode.INSW | Opcode.OUTSW
    | Opcode.IRET -> true
    | _ -> false

  /// The width a descriptor declares. A negative stands in for "declares
  /// none", so that the sizes below can be compared without wrapping each in
  /// an option: zero is a real width here, carried by an operand the manual
  /// gives no size for.
  let noWidth = -1<rt>

  let declaredWidth = function
    | RM sz | Reg(sz, _) | Mem sz | Imm sz | Rel sz | Moffs sz
    | Far sz -> sz
    | FixedReg Register.AX -> 16<rt>
    | _ -> noWidth

  /// How many distinct widths the descriptors declare and what the first two
  /// are. Only those three facts decide whether 66h is required, and a scan
  /// finds them without the two arrays Array.distinct would build on every
  /// candidate of every instruction.
  let firstTwoWidths (operands: OperandType[]) =
    let mutable count = 0
    let mutable first = noWidth
    let mutable second = noWidth
    for o in operands do
      let w = declaredWidth o
      if count = 0 then
        count <- 1
        first <- w
      elif count = 1 && w <> first then
        second <- w
        count <- 2
      elif count >= 2 && w <> first && w <> second then
        count <- count + 1
      else ()
    struct (count, first, second)

  /// Returns true when this instruction variant requires the 66h prefix. Some
  /// opcodes are excluded because their 16-bit form omits it.
  let needs66hPrefix (operands: OperandType[]) op =
    let struct (count, first, second) = firstTwoWidths operands
    if count = 1 && first = 16<rt> then op <> Opcode.RET
    elif count = 2 && first = 16<rt> then op <> Opcode.ENTER
    elif count = 2 && first = noWidth && second = 16<rt> then op <> Opcode.MOV
    elif count = 2 && first = 8<rt> && second = 16<rt> then op = Opcode.OUT
    elif count = 1 && first = noWidth then hasImplicit16BitOprSize op
    else false

  /// The width a fixed-register operand implies. Segment registers give
  /// 0<rt>: an operand-size prefix never selects between them.
  let fixedRegSize = function
    | Register.AL | Register.CL -> 8<rt>
    | Register.AX | Register.DX -> 16<rt>
    | Register.EAX -> 32<rt>
    | Register.RAX -> 64<rt>
    | _ -> 0<rt>

  /// The width an operand descriptor declares, or 0<rt> when it carries none.
  /// A multi-size form reports its register width, which is the side an
  /// operand-size prefix selects.
  let oprWidth = function
    | RM sz | Reg(sz, _) | RegSae sz | Mem sz | MemVSIB sz | Moffs sz
    | Far sz | Imm sz | Rel sz | KM sz | MM sz | BM sz -> sz
    | RMdiff(sz, _) | RMEr(sz, _) | RMSae(sz, _) -> sz
    | RMBcst(sz, _, _) | RMBcstEr(sz, _, _) | RMBcstSae(sz, _, _) -> sz
    | FixedReg r -> fixedRegSize r
    | _ -> 0<rt>

  /// Returns the widest declared operand size in the descriptors, or 0<rt>
  /// when none of them carries one.
  let maxOprSize (insCore: InstructionCore) =
    insCore.Operands |> Array.fold (fun acc o -> max acc (oprWidth o)) 0<rt>

  /// Returns true when 66h is what picks this variant out of its slot, i.e.
  /// the slot also holds the same opcode with a wider operand. Opcodes whose
  /// 16-bit form encodes no explicit size (MOVSW, PUSHF, ...) have nothing to
  /// compare, and hasImplicit16BitOprSize already names them.
  let is66hSelector (ins: InstructionCore[]) (insCore: InstructionCore) =
    let sz = maxOprSize insCore
    if sz = 0<rt> then true
    else
      ins
      |> Array.exists (fun i ->
        i.Opcode = insCore.Opcode && maxOprSize i > sz)

  /// Returns true when the current prefix is compatible with the operand size
  /// implied by the instruction's descriptors.
  let matchOperandSize pref ins (insCore: InstructionCore) =
    if insCore.OpEn = OpEn.None then true
    else
      if needs66hPrefix insCore.Operands insCore.Opcode
         && is66hSelector ins insCore then
        pref &&& Prefix.OPSIZE = Prefix.OPSIZE
      else true

  /// Returns true when the CPU word size is compatible with the instruction's
  /// Mode64/Compat flags.
  let matchCPUMode wordSize mode64 compat =
    match wordSize with
    (* The manual spells the same verdict "Inv." in some tables and
       "Invalid" in others. *)
    | WordSize.Bit64 when mode64 = Mode64.Invalid || mode64 = Mode64.Inv ->
      false
    | WordSize.Bit64 -> mode64 <> Mode64.NE && mode64 <> Mode64.NS // ??
    | WordSize.Bit32 ->
      compat <> CompatLegMode.NE && compat <> CompatLegMode.Invalid
    | _ -> failwith "Unsupported word size."

  /// Returns true when the ModRM type encodes an opcode group extension (/0–/7)
  /// that further disambiguates the instruction.
  let isOpcodeGroupExtension = function
    | ModRMType.ModRMOp0 _ | ModRMType.ModRMOp1 _ | ModRMType.ModRMOp2 _
    | ModRMType.ModRMOp3 _ | ModRMType.ModRMOp4 _ | ModRMType.ModRMOp5 _
    | ModRMType.ModRMOp6 _ | ModRMType.ModRMOp7 _ -> true
    | _ -> false

  /// Returns true when the ModRM reg field satisfies the operand type and
  /// expected register index constraints.
  let matchModRMRegConstraint (span: ByteSpan) (phlp: ParsingHelper)
    oprType insReg =
    let modRM = span[phlp.CurrPos]
    let reg = Operands.getReg modRM
    match oprType with
    | OpReg -> Operands.modIsReg modRM && reg = insReg
    | OpMem -> Operands.modIsMemory modRM && reg = insReg
    | _ -> reg = insReg

  /// Returns true when the ModRM byte satisfies all constraints in the
  /// instruction core (fixed, STi, group digit, reg/mem form, or
  /// unconstrained). A plain /r carries a reg-or-mem constraint too: the
  /// mod field is what separates MOVHLPS (register only) from MOVLPS
  /// (memory only), which share opcode 0F 12.
  let matchModRM (span: ByteSpan) (phlp: ParsingHelper)
    (i: InstructionCore) =
    match i.ModRM with
    | ModRMType.ModRM OpReg -> Operands.modIsReg span[phlp.CurrPos]
    | ModRMType.ModRM OpMem -> Operands.modIsMemory span[phlp.CurrPos]
    | ModRMType.ModRMOp0 o -> matchModRMRegConstraint span phlp o 0
    | ModRMType.ModRMOp1 o -> matchModRMRegConstraint span phlp o 1
    | ModRMType.ModRMOp2 o -> matchModRMRegConstraint span phlp o 2
    | ModRMType.ModRMOp3 o -> matchModRMRegConstraint span phlp o 3
    | ModRMType.ModRMOp4 o -> matchModRMRegConstraint span phlp o 4
    | ModRMType.ModRMOp5 o -> matchModRMRegConstraint span phlp o 5
    | ModRMType.ModRMOp6 o -> matchModRMRegConstraint span phlp o 6
    | ModRMType.ModRMOp7 o -> matchModRMRegConstraint span phlp o 7
    | ModRMType.FixedModRM v -> span[phlp.CurrPos] = v
    | ModRMType.STiModRM v ->
      let modRM = span[phlp.CurrPos]
      v <= modRM && modRM <= v + 7uy
    | _ -> true

  /// JCXZ/JECXZ/JRCXZ share opcode 0xE3 and are selected by the effective
  /// address size determined by the current mode and the 67h prefix:
  /// 32-bit mode  -> JECXZ, 67h -> JCXZ
  /// 64-bit mode  -> JRCXZ, 67h -> JECXZ
  /// Only the one-byte map is concerned: 0xE3 is PAVGW, VPAVGW or CMPccXADD
  /// in the escape and VEX maps.
  let matchJcxzAddrSize (phlp: ParsingHelper) (insCore: InstructionCore) =
    if uint8 insCore.OpcodeByte <> 0xE3uy
       || phlp.OpcodeClass <> OpcodeClass.Normal OneByte then true
    else
      match ParsingHelper.GetEffAddrSize phlp, insCore.Opcode with
      | 16<rt>, Opcode.JCXZ
      | 32<rt>, Opcode.JECXZ
      | 64<rt>, Opcode.JRCXZ -> true
      | _ -> false

  /// Returns true when every constraint the instruction core declares holds
  /// for the bytes at hand.
  let matchesInstrCore span (phlp: ParsingHelper) ins isRounding insCore =
    matchPrefix phlp ins (uint8 insCore.OpcodeByte) insCore.PrefixType
    && matchCPUMode phlp.WordSize insCore.Mode64 insCore.Compat
    && matchOperandSize phlp.Prefixes ins insCore
    && matchREX phlp ins insCore
    && matchVectorLength isRounding phlp.VEXInfo insCore
    && matchModRM span phlp insCore
    && matchJcxzAddrSize phlp insCore

#if DEBUG
  /// Reports each constraint's verdict on one entry. matchesInstrCore stops
  /// at the first failure, so this runs them all again to show which ones
  /// rejected an entry, or which entry won and why.
  let traceInstrCore span (phlp: ParsingHelper) ins isRounding i insCore =
    printfn
      "[%d] %A pref=%b mode=%b size=%b rex=%b vlen=%b modrm=%b addrsz=%b"
      i insCore.Opcode
      (matchPrefix phlp ins (uint8 insCore.OpcodeByte) insCore.PrefixType)
      (matchCPUMode phlp.WordSize insCore.Mode64 insCore.Compat)
      (matchOperandSize phlp.Prefixes ins insCore)
      (matchREX phlp ins insCore)
      (matchVectorLength isRounding phlp.VEXInfo insCore)
      (matchModRM span phlp insCore)
      (matchJcxzAddrSize phlp insCore)
#endif

  /// Returns the index of the first instruction-core entry that satisfies
  /// all matching constraints; raises if no variant matches.
  let selectInstrVariant (span: ByteSpan) (phlp: ParsingHelper)
    (ins: InstructionCore[]) =
    if Array.isEmpty ins then
      failwith "Error: Instruction core array is empty."
    else
      let isRounding = usesStaticRounding span phlp ins
      (* A span cannot be captured by a closure, so this cannot be a
         tryFindIndex. *)
      let mutable idx = -1
      let mutable i = 0
      while idx < 0 && i < ins.Length do
#if DEBUG
        traceInstrCore span phlp ins isRounding i ins[i]
#endif
        if matchesInstrCore span phlp ins isRounding ins[i] then idx <- i
        else i <- i + 1
#if DEBUG
      printfn "maps: %A, pref: %A, rex: %A, vex: %A -> selected %d"
        phlp.OpcodeClass phlp.Prefixes phlp.REXPrefix phlp.VEXInfo idx
#endif
      if idx < 0 then failwith "No matching instruction format."
      else idx

  /// Returns the RegType size for a FixedImm operand inferred from the
  /// surrounding operand size array.
  let getFixedImmSize = function
    | [| Some 8<rt>; None |] -> 8<rt>
    | [| Some 16<rt>; None |] -> 16<rt>
    | [| Some 32<rt>; None |] -> 32<rt>
    | [| Some 64<rt>; None |] -> 64<rt>
    | _ -> 0<rt> // Temp

  /// Writes addrSz, regSz, and memSz into the parsing-helper context for use by
  /// subsequent operand parsers.
  let setupOprContext (phlp: ParsingHelper) addrSz regSz memSz =
    phlp.MemEffOprSize <- memSz
    phlp.MemEffAddrSize <- addrSz
    phlp.MemEffRegSize <- regSz
    phlp.RegSize <- regSz
    phlp.OperationSize <- regSz
    (* Cleared here so a broadcast width never outlives its operand; the
       RMBcst cases set it again right after this call. *)
    phlp.BroadcastSize <- 0<rt>

  /// Calls setupOprContext with the effective address size derived from the
  /// current prefix/mode state.
  let setupOprContextWithEffAddr (phlp: ParsingHelper) regSz memSz =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    setupOprContext phlp effAddrSz regSz memSz

  /// Sizes an operand that carries no width of its own from the prefixes and
  /// the CPU mode, under the given size condition.
  let setupOprContextFromPrefixes (phlp: ParsingHelper) szCond =
    let effOprSz = ParsingHelper.GetEffOprSize(phlp, szCond)
    setupOprContextWithEffAddr phlp effOprSz effOprSz

  /// Returns true when the opcode has a sign-extending immediate encoding.
  let supportsSignExtendedImmediate = function
    | Opcode.ADC | Opcode.ADD | Opcode.AND | Opcode.CMP | Opcode.IMUL
    | Opcode.MOV | Opcode.OR | Opcode.SBB | Opcode.SUB | Opcode.TEST
    | Opcode.XOR | Opcode.PUSH -> true
    | _ -> false

  /// Returns true when the immediate is narrower than the effective operand
  /// width and must be sign-extended (includes PUSH imm8).
  let hasSignExtendedImmediateSizeMismatch opcode szs =
    match szs with
    (* Implicit accumulator + imm8; no widening. *)
    | [| None; Some 8<rt> |] -> false
    (* PUSH imm8 is sign-extended to the stack operand width. *)
    | [| Some _ |] when opcode = Opcode.PUSH -> true
    (* Single-size operand shape; no sign-extension case. *)
    | [| None |] | [| Some _ |] -> false
    | _ -> true

  /// The register index a mask or MMX operand names. These registers have no
  /// extension bit, so the raw three-bit field is the whole index.
  let shortRegIndex (phlp: ParsingHelper) modRM = function
    | RegBit -> Operands.getReg modRM
    | RMBit -> Operands.getRM modRM
    | VVVV ->
      match phlp.VEXInfo with
      | Some v -> int v.VVVV
      | None -> failwith "VEXInfo is required to get VVVV bits."
    | ort -> failwithf "Invalid OprRegType for a short register: %A" ort

  /// Parses one operand descriptor into a concrete Operand value and updates
  /// the context so subsequent operands derive the correct width.
  let parseOperand span (phlp: ParsingHelper) szs modRM ic o =
    match o with
    (* {er} and {sae} decorate the operand without changing how it is read;
       the variant they select was already settled by matchVectorLength. *)
    | RM sz ->
      setupOprContextWithEffAddr phlp sz sz
      OperandParsers.parseMemOrReg modRM span phlp
    | RMdiff(regSz, memSz)
    | RMEr(regSz, memSz)
    | RMSae(regSz, memSz) ->
      setupOprContextWithEffAddr phlp regSz memSz
      OperandParsers.parseMemOrReg modRM span phlp
    | RMBcst(regSz, memSz, bcstSz)
    | RMBcstEr(regSz, memSz, bcstSz)
    | RMBcstSae(regSz, memSz, bcstSz) ->
      setupOprContextWithEffAddr phlp regSz memSz
      phlp.BroadcastSize <- bcstSz
      OperandParsers.parseMemOrReg modRM span phlp
    | MemVSIB elemSz ->
      (* A gathered element occupies max(index, data) bits, so the vector
         length says how many of them there are. The index register then
         holds that many indices, never narrower than an XMM, and the memory
         access covers that many data elements. See Intel SDM Vol. 2C, the
         vm32x/vm32y/vm32z and vm64x/vm64y/vm64z operand tables. *)
      let vl = phlp.VEXInfo.Value.VectorLength
      let dataSz = if REXPrefix.hasW phlp.REXPrefix then 64<rt> else 32<rt>
      let count = vl / max elemSz dataSz
      let idxVl = max 128<rt> (count * elemSz)
      let memSz = count * dataSz
      setupOprContextWithEffAddr phlp memSz memSz
      let modVal = modRM &&& 0b11000000uy
      OperandParsers.parseOprMemVSIB span phlp modVal idxVl
    | Reg(sz, oprRegType) ->
      setupOprContextWithEffAddr phlp sz sz
      match oprRegType with
      | OprRegType.OpRd -> (* Opcode[2:0] holds the register. *)
        OperandParsers.getOprFromRegGrpREX
          (Operands.getRM(uint8 (ic: InstructionCore).OpcodeByte)) phlp
      | OprRegType.VVVV ->
        (* BMI/CMPccXADD encode a GPR in vvvv, not a vector register. *)
        if sz <= 64<rt> then OperandParsers.parseVEXtoGPR phlp
        else OperandParsers.parseVVVVReg phlp
      | OprRegType.RMBit -> OperandParsers.findRegRM modRM phlp |> OprReg
      | OprRegType.RegBit ->
        OperandParsers.findRegReg sz modRM phlp |> OprReg
      | OprRegType.IS4 -> (* imm8[7:4] holds the register. *)
        let regBit = phlp.ReadByte span >>> 4 &&& 0b1111uy |> int
        OperandParsers.findRegIS4 phlp.WordSize sz regBit |> OprReg
      | OprRegType.Unused -> failwith "Unused OprRegType." (* FixedReg *)
    | RegSae sz ->
      setupOprContextWithEffAddr phlp sz sz
      OperandParsers.findRegReg sz modRM phlp |> OprReg
    | Mem 0<rt> when ic.Opcode = Opcode.LDDQU ->
      setupOprContextWithEffAddr phlp 128<rt> 128<rt>
      OperandParsers.parseMemory modRM span phlp
    | Mem 0<rt> -> (* No declared width: the prefixes decide. *)
      setupOprContextFromPrefixes phlp ic.SzCond
      OperandParsers.parseMemory modRM span phlp
    | Mem sz ->
      setupOprContextWithEffAddr phlp sz sz
      OperandParsers.parseMemory modRM span phlp
    | Imm sz ->
      setupOprContextFromPrefixes phlp ic.SzCond
      if supportsSignExtendedImmediate ic.Opcode
         && hasSignExtendedImmediateSizeMismatch ic.Opcode szs then
        OperandParsers.parseOprSImm span phlp sz
      else OperandParsers.parseOprImm span phlp sz
    | Rel sz ->
      setupOprContextFromPrefixes phlp ic.SzCond
      OperandParsers.parseOprForRelJmp span phlp sz
    | FixedReg reg ->
      let sz = RegisterHelper.toRegType phlp.WordSize reg
      setupOprContextWithEffAddr phlp sz sz
      OprReg reg
    | STReg None -> Operands.getRM modRM |> Operands.getSTReg
    | STReg(Some reg) -> OprReg reg
    | BM sz ->
      if Operands.modIsReg modRM then
        OperandParsers.parseBoundRegister (Operands.getRM modRM)
      else
        setupOprContextWithEffAddr phlp sz sz
        OperandParsers.parseMemory modRM span phlp
    | BndReg -> OperandParsers.parseBoundRegister (Operands.getReg modRM)
    | OpMaskReg oprRegType ->
      shortRegIndex phlp modRM oprRegType |> OperandParsers.parseOpMaskReg
    | KM sz ->
      setupOprContextWithEffAddr phlp sz sz
      if Operands.modIsReg modRM then
        OperandParsers.parseOpMaskReg (Operands.getRM modRM)
      else
        OperandParsers.parseMemory modRM span phlp
    | MMXReg oprRegType ->
      shortRegIndex phlp modRM oprRegType |> OperandParsers.parseMMXReg
    | MM sz ->
      if Operands.modIsReg modRM then
        OperandParsers.parseMMXReg (Operands.getRM modRM)
      else
        setupOprContextWithEffAddr phlp sz sz
        OperandParsers.parseMemory modRM span phlp
    | FixedImm imm -> OprImm(int64 imm, getFixedImmSize szs)
    | Moffs sz ->
      setupOprContextWithEffAddr phlp sz sz
      OperandParsers.parseOprOnlyDisp span phlp
    | CtrlReg ->
      OperandParsers.sysRegIndex modRM phlp.REXPrefix
      |> OperandParsers.parseControlReg
    | DebugReg ->
      OperandParsers.sysRegIndex modRM phlp.REXPrefix
      |> OperandParsers.parseDebugReg
    | RegAddr ->
      let sz = ParsingHelper.GetEffAddrSize phlp
      setupOprContextWithEffAddr phlp sz sz
      if isOpcodeGroupExtension ic.ModRM then
        let rm = Operands.getRM modRM
        OperandParsers.findRegRmAndSIBBase sz phlp.REXPrefix rm |> OprReg
      else
        let reg = Operands.getReg modRM
        OperandParsers.findRegRBits sz phlp.REXPrefix reg |> OprReg
    | Sreg -> OperandParsers.parseSegReg (Operands.getReg modRM)
    | Far sz ->
      (* sz is the offset width; a far pointer also carries a 16-bit segment
         selector, so the whole thing is 16 bits wider. OperationSize holds
         that whole width rather than the register width. *)
      let oprSz = sz + 16<rt>
      setupOprContextWithEffAddr phlp sz oprSz
      phlp.OperationSize <- oprSz
      if ic.ModRM = ModRMType.NoModRM then
        (* ptr16:16 or ptr16:32, spelled out in the instruction (9A, EA). *)
        let addrValue =
          OperandParsers.parseUnsignedImm span phlp (RegType.toByteWidth sz)
        let selector = phlp.ReadInt16 span
        OprDirAddr(Absolute(selector, addrValue, sz))
      else
        (* m16:16, m16:32 or m16:64, read through ModRM (FF /3, FF /5). *)
        phlp.IsFar <- true
        OperandParsers.parseMemory modRM span phlp
    (* NoOpr among other operands, or an Unknown the extractor could not
       classify. Neither occurs in the generated tables today. *)
    | o -> failwithf "Unsupported operand type: %A" o

  /// Wraps a concrete operand array into the Operands discriminated union
  /// (NoOperand / OneOperand / … / FourOperands).
  let buildOperands = function
    | [||] -> Operands.NoOperand
    | [| op1 |] -> Operands.OneOperand(op1)
    | [| op1; op2 |] -> Operands.TwoOperands(op1, op2)
    | [| op1; op2; op3 |] -> Operands.ThreeOperands(op1, op2, op3)
    | [| op1; op2; op3; op4 |] -> Operands.FourOperands(op1, op2, op3, op4)
    | _ -> failwith "Invalid number of operands."

  /// Reads the ModRM byte where one follows the opcode. The table is the only
  /// authority on whether it does: reading one that is not there overstates
  /// the length and swallows the instruction after it, as GETSEC showed.
  let readModRM span (phlp: ParsingHelper) (ic: InstructionCore) =
    match ic.ModRM with
    | ModRMType.NoModRM -> 0uy
    | _ -> phlp.ReadByte span (* every other kind, FixedModRM included *)

  /// Reads the ModRM byte if required, then parses all operand descriptors
  /// and returns the assembled Operands value.
  let parseAllOperands span (phlp: ParsingHelper) (ic: InstructionCore) =
    let modRM = readModRM span phlp ic
    match ic.Operands with
    | [| NoOpr |] ->
      (* Nothing else sizes an operand-less instruction, yet the lifter still
         reads OperationSize: auxPop needs it for RET and LEAVE. *)
      setupOprContextFromPrefixes phlp ic.SzCond
      Operands.NoOperand
    | operandTypes ->
      let szs = collectDistinctOpSizes operandTypes
      let operands = Array.zeroCreate operandTypes.Length
      for i = 0 to operandTypes.Length - 1 do
        operands[i] <- parseOperand span phlp szs modRM ic operandTypes[i]
      buildOperands operands

  /// Removes the prefixes the matched instruction consumed as opcode
  /// selectors, leaving the ones that kept their ordinary meaning.
  let consumePrefixIfNeeded (phlp: ParsingHelper) insCore =
    let consumed = consumedPrefixes phlp insCore
    phlp.Prefixes <- phlp.Prefixes &&& ~~~consumed

  member _.SetDisassemblySyntax syntax =
    match syntax with
    | DefaultSyntax -> disasm <- Disasm.Delegate Disasm.IntelSyntax.disasm
    | ATTSyntax -> disasm <- Disasm.Delegate Disasm.ATTSyntax.disasm

  member inline private _.ParsePrefix(span: ByteSpan) =
    let mutable pos = 0
    let mutable pref = Prefix.None
    let mutable b = span[0]
    while ((prefixCheck[(int b >>> 5)] >>> (int b &&& 0b11111)) &&& 1u) > 0u do
      match b with
      | 0xF0uy -> pref <- Prefix.LOCK ||| (Prefix.ClearGrp1PrefMask &&& pref)
      | 0xF2uy -> pref <- Prefix.REPNZ ||| (Prefix.ClearGrp1PrefMask &&& pref)
      | 0xF3uy -> pref <- Prefix.REPZ ||| (Prefix.ClearGrp1PrefMask &&& pref)
      | 0x2Euy -> pref <- Prefix.CS ||| (Prefix.ClearSegMask &&& pref)
      | 0x36uy -> pref <- Prefix.SS ||| (Prefix.ClearSegMask &&& pref)
      | 0x3Euy -> pref <- Prefix.DS ||| (Prefix.ClearSegMask &&& pref)
      | 0x26uy -> pref <- Prefix.ES ||| (Prefix.ClearSegMask &&& pref)
      | 0x64uy -> pref <- Prefix.FS ||| (Prefix.ClearSegMask &&& pref)
      | 0x65uy -> pref <- Prefix.GS ||| (Prefix.ClearSegMask &&& pref)
      | 0x66uy -> pref <- Prefix.OPSIZE ||| pref
      | 0x67uy -> pref <- Prefix.ADDRSIZE ||| pref
      | _ -> pos <- pos - 1
      pos <- pos + 1
      b <- span[pos]
    phlp.Prefixes <- pref
    pos

  member inline private _.ParseREX(bs: ByteSpan, pos, rex: REXPrefix byref) =
    if wordSz = WordSize.Bit32 then pos
    else
      let rb = bs[pos] |> int
      if rb &&& 0b11110000 = 0b01000000 then
        rex <- EnumOfValue rb
        pos + 1
      else pos

  member inline private _.ParseVEX(bs: ByteSpan, pos, rex: REXPrefix byref,
    vex: VEXInfo option byref) =
    match bs[pos] with
    | 0xC5uy when bs[pos + 1] < 0xC0uy && wordSz <> WordSize.Bit64 ->
      pos
    | 0xC5uy ->
      vex <- Some(getTwoVEXInfo bs &rex (pos + 1))
      pos + 2
    | 0xC4uy when bs[pos + 1] < 0xC0uy && wordSz <> WordSize.Bit64 ->
      pos
    | 0xC4uy ->
      vex <- Some(getThreeVEXInfo bs &rex (pos + 1))
      pos + 3
    (* Outside 64-bit mode 0x62 is BOUND unless the ModRM that follows names
       a register, exactly as 0xC4 and 0xC5 are LES and LDS. *)
    | 0x62uy when bs[pos + 1] < 0xC0uy && wordSz <> WordSize.Bit64 ->
      pos
    | 0x62uy ->
      vex <- Some(getEVEXInfo bs &rex (pos + 1))
      pos + 4
    | 0x0Fuy ->
      match bs[pos + 1] with
      | 0x38uy ->
        phlp.OpcodeClass <- OpcodeClass.Normal ThreeBytes38
        pos + 2
      | 0x3Auy ->
        phlp.OpcodeClass <- OpcodeClass.Normal ThreeBytes3A
        pos + 2
      | _ ->
        phlp.OpcodeClass <- OpcodeClass.Normal TwoBytes
        pos + 1
    | _ ->
      phlp.OpcodeClass <- OpcodeClass.Normal OneByte
      pos

  interface IInstructionParsable with
    member _.MaxInstructionSize = 15

    member _.InstructionAlignment = 1

    member this.Parse(bs: byte[], addr) =
      (this :> IInstructionParsable).Parse(ReadOnlySpan bs, addr)

    member this.Parse(span: ByteSpan, addr) =
      try
        let mutable rex = REXPrefix.NOREX
        let mutable vex = None
        let prefEndPos = this.ParsePrefix span
        let rexEndPos = this.ParseREX(span, prefEndPos, &rex)
        let nextPos = this.ParseVEX(span, rexEndPos, &rex, &vex)
        phlp.VEXInfo <- None
        phlp.IsFar <- false
        phlp.InsAddr <- addr
        phlp.REXPrefix <- rex
        phlp.VEXInfo <- vex
        phlp.CurrPos <- nextPos
#if LCACHE
        phlp.MarkPrefixEnd(prefEndPos)
#endif
        let insCores =
          match phlp.VEXInfo with
          | Some vInfo ->
            match vInfo.VEXType with
            | v when v &&& VEXType.EVEX = VEXType.EVEX ->
              match vInfo.VEXType &&& (~~~VEXType.EVEX) with
              | VEXType.TwoByteOp ->
                phlp.OpcodeClass <- OpcodeClass.EVEX TwoBytes
                InstructionArrays.evexTwo[int (phlp.ReadByte span)]
              | VEXType.ThreeByteOpOne ->
                phlp.OpcodeClass <- OpcodeClass.EVEX ThreeBytes38
                InstructionArrays.evexThree38[int (phlp.ReadByte span)]
              | VEXType.ThreeByteOpTwo ->
                phlp.OpcodeClass <- OpcodeClass.EVEX ThreeBytes3A
                InstructionArrays.evexThree3A[int (phlp.ReadByte span)]
              | VEXType.Map5 ->
                phlp.OpcodeClass <- OpcodeClass.EVEX MAP5
                InstructionArrays.evexMap5[int (phlp.ReadByte span)]
              | VEXType.Map6 ->
                phlp.OpcodeClass <- OpcodeClass.EVEX MAP6
                InstructionArrays.evexMap6[int (phlp.ReadByte span)]
              | _ -> raise ParsingFailureException
            | VEXType.TwoByteOp ->
              phlp.OpcodeClass <- OpcodeClass.VEX TwoBytes
              InstructionArrays.vexTwo[int (phlp.ReadByte span)]
            | VEXType.ThreeByteOpOne ->
              phlp.OpcodeClass <- OpcodeClass.VEX ThreeBytes38
              InstructionArrays.vexThree38[int (phlp.ReadByte span)]
            | VEXType.ThreeByteOpTwo ->
              phlp.OpcodeClass <- OpcodeClass.VEX ThreeBytes3A
              InstructionArrays.vexThree3A[int (phlp.ReadByte span)]
            | _ -> raise ParsingFailureException
          | None ->
            match phlp.OpcodeClass with
            | OpcodeClass.Normal ThreeBytes38 ->
              InstructionArrays.norThree38[int (phlp.ReadByte span)]
            | OpcodeClass.Normal ThreeBytes3A ->
              InstructionArrays.norThree3A[int (phlp.ReadByte span)]
            | OpcodeClass.Normal TwoBytes ->
              InstructionArrays.norTwo[int (phlp.ReadByte span)]
            | _ -> InstructionArrays.norOne[int (phlp.ReadByte span)]
        let subIdx = selectInstrVariant span phlp insCores
#if DEBUG
        //printfn "\nSelected InstructionCore(%d)\n%A\nOpcode Class: %A"
        //  subIdx insCores[subIdx] phlp.OpcodeClass
#endif
        let insCore = insCores[subIdx]
        phlp.TupleType <- insCore.TupleType
        let operands = parseAllOperands span phlp insCore
        consumePrefixIfNeeded phlp insCore
        newInstruction phlp insCore.Opcode operands :> IInstruction
      with e when not (Terminator.isCritical e) ->
        raise ParsingFailureException
