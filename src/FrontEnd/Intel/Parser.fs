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

  /// Returns true when the VEX/EVEX vector length satisfies the instruction's
  /// vector-length constraint (or the constraint is absent).
  let matchVectorLength (vex: VEXInfo option) insVecLen =
    if insVecLen = VectorLength.None then true
    else
      match vex with
      | Some v ->
        match v.VectorLength with
        | 128<rt> -> insVecLen = VectorLength.V128
        | 256<rt> -> insVecLen = VectorLength.V256
        | 512<rt> -> insVecLen = VectorLength.V512
        | _ -> false
      | _ -> true

  /// Returns the distinct operand sizes from an instruction's descriptors.
  /// None entries represent operands with no explicit size.
  let collectDistinctOpSizes operands =
    Array.map (fun o ->
      match o with
      | RM sz | Reg(sz, _) | Mem sz | Imm sz | Rel sz | Moffs sz -> Some sz
      | FixedReg(Register.AX) -> Some 16<rt>
      | _ -> None) operands
    |> Array.distinct

  /// Returns true when every operand is 8-bit, meaning REX semantics do not
  /// apply to this instruction.
  let isAllOprSize8 oprSz =
    match oprSz with
    | [| Some 8<rt> |] -> true
    | _ -> false

  /// Returns true when the observed REX prefix satisfies the constraint
  /// declared in the instruction core (NOREX / W0 / W1 / WIG / REXW).
  let matchREX (phlp: ParsingHelper) (insCore: InstructionCore) =
    let insREX = insCore.REXPrefixType
    match phlp.REXPrefix with
    | _ when isAllOprSize8 (collectDistinctOpSizes insCore.Operands) -> true
    | REXPrefix.NOREX ->
      (insREX = REXPrefixType.WIG) || (insREX = REXPrefixType.W0) ||
      (insREX = REXPrefixType.NOREX)
    | r when (r &&& REXPrefix.REXW) = REXPrefix.REXW ->
      (insREX = REXPrefixType.WIG) || (insREX = REXPrefixType.W1) ||
      (insREX = REXPrefixType.REXW)
    //| r when (r &&& REXPrefix.REX) = REXPrefix.REX ->
    //  (insREX = REXPrefixType.WIG) || (insREX = REXPrefixType.W0) ||
    //  (insREX = REXPrefixType.REX)
    | _ -> true

  /// Returns true when pref satisfies insPref, treating Legacy NP as a fallback
  /// for Mandatory NP.
  let matchPrefixType pref insPref =
    match pref with
    | Mandatory NP -> insPref = Mandatory NP || insPref = Legacy NP
    | Mandatory _ ->
      if insPref = Legacy NP then false
      else pref = insPref
    | _ -> true

  /// Returns true when the current prefix state satisfies insPref, with Legacy
  /// NP as a fallback for Mandatory NP.
  let matchPrefixWithLegacyFallback (phlp: ParsingHelper) insPref =
    let pref =
      match phlp.VEXInfo with
      | Some v -> v.VPrefixes
      | _ -> phlp.Prefixes
    let mPref = pref &&& (Prefix.OPSIZE ||| Prefix.REPZ ||| Prefix.REPNZ)
    if Prefix.hasOprSz mPref then insPref = Mandatory P66 || insPref = Legacy NP
    elif Prefix.hasREPZ mPref then insPref = Mandatory F3 || insPref = Legacy NP
    elif Prefix.hasREPNZ mPref then
      insPref = Mandatory F2 || insPref = Legacy NP
    elif mPref = Prefix.None then
      insPref = Legacy NP || insPref = Mandatory NP
    else false

  /// Returns the effective PrefixType for opcodes that deviate from standard
  /// mandatory-prefix rules; None for all other opcodes.
  let tryResolveSpecialPrefix (phlp: ParsingHelper) opByte =
    if phlp.VEXInfo.IsSome then None
    else
      match phlp.OpcodeClass with
      | OpcodeClass.Normal OneByte
        when opByte = 0x90uy && Prefix.hasREPZ phlp.Prefixes ->
        Some(Mandatory F3) // F3 90 = PAUSE
      | OpcodeClass.Normal TwoBytes when opByte = 0xBCuy || opByte = 0xBDuy ->
        // 0F BC/BD use F3 as an opcode selector (TZCNT/LZCNT), while 66 still
        // acts as the ordinary operand-size prefix for BSF/BSR.
        if Prefix.hasREPZ phlp.Prefixes then Some(Mandatory F3)
        else Some(Mandatory NP)
      | _ -> None

  /// Returns true when the current prefix satisfies the instruction's
  /// requirement, applying special-case resolution where needed.
  let matchPrefix (phlp: ParsingHelper) opByte insPref =
    match tryResolveSpecialPrefix phlp opByte with
    | Some pref -> matchPrefixType pref insPref
    | None -> matchPrefixWithLegacyFallback phlp insPref

  /// Returns true when the special-case prefix acted as an opcode selector and
  /// should be stripped after matching.
  let shouldConsumeSpecialPrefix pref =
    match pref with
    | Mandatory NP -> false
    | Mandatory _ -> true
    | _ -> false

  /// Returns true when the matched prefix should be removed after parsing
  /// (VEX always; legacy mandatory only when used as an opcode selector).
  let shouldConsumePrefix (phlp: ParsingHelper) (insCore: InstructionCore) =
    match phlp.VEXInfo with
    | Some _ -> true
    | None ->
      match tryResolveSpecialPrefix phlp (uint8 insCore.OpcodeByte) with
      | Some pref -> shouldConsumeSpecialPrefix pref
      | None ->
        match insCore.PrefixType with
        | Mandatory _ -> true
        | _ -> false

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

  /// Returns true when this instruction variant requires the 66h prefix. Some
  /// opcodes are excluded because their 16-bit form omits it.
  let needs66hPrefix oprSz op =
    match oprSz with
    | [| Some 16<rt> |] when op = Opcode.RET -> false
    | [| Some 16<rt>; _ |] when op = Opcode.ENTER -> false
    | [| None; Some 16<rt> |] when op = Opcode.MOV -> false
    | [| Some 8<rt>; Some 16<rt> |] when op = Opcode.OUT -> true
    | [| None |] when hasImplicit16BitOprSize op -> true
    | [| Some 16<rt> |]
    | [| Some 16<rt>; _ |]
    | [| None; Some 16<rt> |] (* Temp *) -> true
    | _ -> false

  /// Returns true when the current prefix is compatible with the operand size
  /// implied by the instruction's descriptors.
  let matchOperandSize pref (insCore: InstructionCore) =
    if insCore.OpEn = OpEn.None then true
    else
      let oprSz = collectDistinctOpSizes insCore.Operands
      if needs66hPrefix oprSz insCore.Opcode then
        // FIXME: 16-bit operands do not always require a 66h prefix.
        pref &&& Prefix.OPSIZE = Prefix.OPSIZE
      else true

  /// Returns true when the CPU word size is compatible with the instruction's
  /// Mode64/Compat flags.
  let matchCPUMode wordSize mode64 compat =
    match wordSize with
    | WordSize.Bit64 when mode64 = Mode64.Invalid -> false
    | WordSize.Bit64 -> mode64 <> Mode64.NE && mode64 <> Mode64.NS // ??
    | WordSize.Bit32 -> compat <> CompatLegMode.NE
    | _ -> failwith "Unsupported word size."

  /// Returns true when the ModRM type encodes an opcode group extension (/0–/7)
  /// that further disambiguates the instruction.
  let isOpcodeGroupExtension = function
    | ModRMType.ModRMOp0 _ | ModRMType.ModRMOp1 _ | ModRMType.ModRMOp2 _
    | ModRMType.ModRMOp3 _ | ModRMType.ModRMOp4 _ | ModRMType.ModRMOp5 _
    | ModRMType.ModRMOp6 _ | ModRMType.ModRMOp7 _ -> true
    | _ -> false

  /// Returns true when the ModRM reg field matches the opcode group extension
  /// digit (/0-/7) declared in the instruction core.
  let matchOpcodeGroupExtension (span: ByteSpan) (phlp: ParsingHelper)
    (i: InstructionCore) =
    if isOpcodeGroupExtension i.ModRM then
      let modRM = span[phlp.CurrPos]
      let reg = (modRM >>> 3) &&& 0b111uy
      match reg with
      | 0uy -> i.ModRM = ModRMType.ModRMOp0 OpRegMem
      | 1uy -> i.ModRM = ModRMType.ModRMOp1 OpRegMem
      | 2uy -> i.ModRM = ModRMType.ModRMOp2 OpRegMem
      | 3uy -> i.ModRM = ModRMType.ModRMOp3 OpRegMem
      | 4uy -> i.ModRM = ModRMType.ModRMOp4 OpRegMem
      | 5uy -> i.ModRM = ModRMType.ModRMOp5 OpRegMem
      | 6uy -> i.ModRM = ModRMType.ModRMOp6 OpRegMem
      | 7uy -> i.ModRM = ModRMType.ModRMOp7 OpRegMem
      | _ -> false
    else true

  /// Returns true when the ModRM reg field satisfies the operand type and
  /// expected register index constraints.
  let matchModRMRegConstraint (span: ByteSpan) (phlp: ParsingHelper)
    (i: InstructionCore) oprType insReg =
    let modRM = span[phlp.CurrPos]
    let reg = Operands.getReg modRM
    match oprType with
    | OpReg -> Operands.modIsReg modRM && reg = insReg
    | OpMem -> Operands.modIsMemory modRM && reg = insReg
    | _ -> reg = insReg

  /// Returns true when the ModRM byte satisfies all constraints in the
  /// instruction core (fixed, STi, group digit, or unconstrained).
  let matchModRM (span: ByteSpan) (phlp: ParsingHelper)
    (i: InstructionCore) =
    match i.ModRM with
    | ModRMType.ModRMOp0 o -> matchModRMRegConstraint span phlp i o 0
    | ModRMType.ModRMOp1 o -> matchModRMRegConstraint span phlp i o 1
    | ModRMType.ModRMOp2 o -> matchModRMRegConstraint span phlp i o 2
    | ModRMType.ModRMOp3 o -> matchModRMRegConstraint span phlp i o 3
    | ModRMType.ModRMOp4 o -> matchModRMRegConstraint span phlp i o 4
    | ModRMType.ModRMOp5 o -> matchModRMRegConstraint span phlp i o 5
    | ModRMType.ModRMOp6 o -> matchModRMRegConstraint span phlp i o 6
    | ModRMType.ModRMOp7 o -> matchModRMRegConstraint span phlp i o 7
    | ModRMType.FixedModRM v -> span[phlp.CurrPos] = v
    | ModRMType.STiModRM v ->
      let modRM = span[phlp.CurrPos]
      v <= modRM && modRM <= v + 7uy
    | _ -> true

  /// JCXZ/JECXZ/JRCXZ share opcode 0xE3 and are selected by the effective
  /// address size determined by the current mode and the 67h prefix:
  /// 32-bit mode  -> JECXZ, 67h -> JCXZ
  /// 64-bit mode  -> JRCXZ, 67h -> JECXZ
  let matchJcxzAddrSize phlp (insCore: InstructionCore) =
    if uint8 insCore.OpcodeByte <> 0xE3uy then true
    else
      match ParsingHelper.GetEffAddrSize phlp, insCore.Opcode with
      | 16<rt>, Opcode.JCXZ
      | 32<rt>, Opcode.JECXZ
      | 64<rt>, Opcode.JRCXZ -> true
      | _ -> false

  /// Returns the index of the first instruction-core entry that satisfies
  /// all matching constraints; raises if no variant matches.
  let selectInstrVariant (span: ByteSpan) (phlp: ParsingHelper)
    (ins: InstructionCore[]) =
    let insLen = ins.Length
    if insLen = 0 then failwith "Error: Instruction core array is empty."
    else
      let mutable idx = -1
      let mutable i = 0
      while i < insLen && idx = -1 do
        let insCore = ins[i]
        let p =
          matchPrefix phlp (uint8 insCore.OpcodeByte)
            insCore.PrefixType
        let s = matchOperandSize phlp.Prefixes insCore
        let c = matchCPUMode phlp.WordSize insCore.Mode64 insCore.Compat
        let r = matchREX phlp insCore
        let v = matchVectorLength phlp.VEXInfo insCore.VectorLength
        let x = matchModRM span phlp insCore
        let a = matchJcxzAddrSize phlp insCore
#if DEBUG
        printfn "Checking %d: p=%b, s=%b, c=%b, r=%b, v=%b, x=%b, a=%b"
          i p s c r v x a
#endif
        if p && c && s && r && v && x && a then
#if DEBUG
          printfn "[Success] maps: %A, pref: %A, rex: %A, vex: %A\nIdx:%d\n%A"
            phlp.OpcodeClass phlp.Prefixes phlp.REXPrefix phlp.VEXInfo i insCore
#endif
          idx <- i
        else ()
        i <- i + 1
      if idx = -1 then
#if DEBUG
        printfn "Fail: find sub index\n maps: %A, pref: %A, rex: %A, vex: %A"
          phlp.OpcodeClass phlp.Prefixes phlp.REXPrefix phlp.VEXInfo
        Array.iteri (printfn "[%d] %A") ins
#endif
        failwithf "No matching instruction format."
      else ()
      idx

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

  /// Calls setupOprContext with the effective address size derived from the
  /// current prefix/mode state.
  let setupOprContextWithEffAddr (phlp: ParsingHelper) regSz memSz =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    setupOprContext phlp effAddrSz regSz memSz

  /// Returns the SzCond for a standalone immediate operand.
  /// PUSH/POP use D64; all others use Normal.
  let getImmSzCond = function
    | Opcode.POP | Opcode.PUSH -> SzCond.D64
    | _ -> SzCond.Normal

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

  /// Parses one operand descriptor into a concrete Operand value and updates
  /// the context so subsequent operands derive the correct width.
  let parseOperand span (phlp: ParsingHelper) szs modRM
    (ic: InstructionCore) o =
    // FIXME: need operand size determination logic
    match o with
    | RM sz ->
      setupOprContextWithEffAddr phlp sz sz
      OperandParsers.parseMemOrReg modRM span phlp
    | RMdiff(regSz, memSz) ->
      setupOprContextWithEffAddr phlp regSz memSz
      OperandParsers.parseMemOrReg modRM span phlp
    | Reg(sz, OprRegType.OpRd) -> (* Opcode[2:0] contains the operand. *)
      setupOprContextWithEffAddr phlp sz sz
      let regBit = Operands.getRM (uint8 ic.OpcodeByte)
      OperandParsers.getOprFromRegGrpREX regBit phlp
    | Reg(sz, oprRegType) ->
      setupOprContextWithEffAddr phlp sz sz
      match oprRegType with
      | OprRegType.OpRd ->
        let regBit = Operands.getRM (uint8 ic.OpcodeByte)
        OperandParsers.getOprFromRegGrpREX regBit phlp
      | OprRegType.VVVV -> OperandParsers.parseVVVVReg phlp
      | OprRegType.RMBit ->
        OperandParsers.findRegRmAndSIBBase phlp.MemEffRegSize phlp.REXPrefix
          (Operands.getRM modRM) |> OprReg
      | OprRegType.RegBit ->
        OperandParsers.findRegRBits sz phlp.REXPrefix (Operands.getReg modRM)
        |> OprReg
      | OprRegType.IS4 ->
        let regBit = phlp.ReadByte span >>> 4 &&& 0b1111uy |> int
        OperandParsers.findRegRBits sz phlp.REXPrefix regBit |> OprReg
      | OprRegType.Unused -> failwith "Unused OprRegType." (* FixedReg *)
    | Mem 0<rt> when ic.Opcode = Opcode.LDDQU ->
      setupOprContextWithEffAddr phlp 128<rt> 128<rt>
      OperandParsers.parseMemory modRM span phlp
    | Mem 0<rt> ->
      let effAddrSz = ParsingHelper.GetEffAddrSize phlp
      let effOprSz = ParsingHelper.GetEffOprSize(phlp, SzCond.Normal)
      setupOprContext phlp effAddrSz effOprSz effOprSz
      OperandParsers.parseMemory modRM span (phlp: ParsingHelper)
    | Mem sz ->
      setupOprContextWithEffAddr phlp sz sz
      OperandParsers.parseMemory modRM span phlp
    | Imm sz ->
      let szCond = getImmSzCond ic.Opcode
      let effAddrSz = ParsingHelper.GetEffAddrSize phlp
      let effOprSz = ParsingHelper.GetEffOprSize(phlp, szCond)
      setupOprContext phlp effAddrSz effOprSz effOprSz
      if supportsSignExtendedImmediate ic.Opcode
         && hasSignExtendedImmediateSizeMismatch ic.Opcode szs then
        OperandParsers.parseOprSImm span phlp sz
      else OperandParsers.parseOprImm span phlp sz
    | Rel sz ->
      let effAddrSz = ParsingHelper.GetEffAddrSize phlp
      let effOprSz = ParsingHelper.GetEffOprSize(phlp, SzCond.F64)
      setupOprContext phlp effAddrSz effOprSz effOprSz
      OperandParsers.parseOprForRelJmp span phlp sz
    | FixedReg reg ->
      let sz = Register.toRegType phlp.WordSize reg
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
    | MMXReg oprRegType ->
      let regBit =
        match oprRegType with
        | RegBit -> Operands.getReg modRM
        | RMBit -> Operands.getRM modRM
        | _ -> failwith "Invalid OprRegType for MMXReg."
      OperandParsers.parseMMXReg regBit
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
    | Sreg -> OperandParsers.parseSegReg (Operands.getReg modRM)
    | Far sz -> // XXX
      let effAddrSz = ParsingHelper.GetEffAddrSize phlp
      let effOprSz = ParsingHelper.GetEffOprSize(phlp, SzCond.Normal)
      let struct (regSz, oprSz) =
        if sz = 16<rt> then struct (16<rt>, 32<rt>)
        elif sz = 32<rt> then struct (32<rt>, 48<rt>)
        else struct (64<rt>, 80<rt>)
      phlp.MemEffOprSize <- oprSz
      phlp.MemEffAddrSize <- effAddrSz
      phlp.MemEffRegSize <- regSz
      phlp.RegSize <- effOprSz
      phlp.OperationSize <- oprSz (* Far ptr: OperationSize holds total ptr size *)
      let addrSz = RegType.toByteWidth phlp.MemEffAddrSize
      let addrValue = OperandParsers.parseUnsignedImm span phlp addrSz
      let selector = phlp.ReadInt16 span
      let absAddr = Absolute(selector, addrValue, RegType.fromByteWidth addrSz)
      OprDirAddr absAddr
    | Unknown s ->
      failwithf "Need unknown operand type handling logic: %s" s
    | o ->
      failwithf "Unsupported operand type: %A" o

  /// Wraps a concrete operand array into the Operands discriminated union
  /// (NoOperand / OneOperand / … / FourOperands).
  let buildOperands = function
    | [||] -> Operands.NoOperand
    | [| op1 |] -> Operands.OneOperand(op1)
    | [| op1; op2 |] -> Operands.TwoOperands(op1, op2)
    | [| op1; op2; op3 |] -> Operands.ThreeOperands(op1, op2, op3)
    | [| op1; op2; op3; op4 |] -> Operands.FourOperands(op1, op2, op3, op4)
    | _ -> failwith "Invalid number of operands."

  /// Reads the ModRM byte if required, then parses all operand descriptors
  /// and returns the assembled Operands value.
  let parseAllOperands span (phlp: ParsingHelper) (ic: InstructionCore) =
    let modRM =
      match ic.ModRM with
      | ModRMType.NoModRM when ic.OpEn = OpEn.M ->
        phlp.ReadByte span (* SETcc *)
      | ModRMType.NoModRM when ic.OpEn = OpEn.None ->
        phlp.ReadByte span (* Escape Opcode *)
      | ModRMType.NoModRM -> 0uy
      | _ -> phlp.ReadByte span (* all other ModRM, including FixedModRM *)
    match ic.Operands with
    | [| NoOpr |] -> Operands.NoOperand
    | _ ->
      let operands = Array.zeroCreate ic.Operands.Length
      let szs = collectDistinctOpSizes ic.Operands
      for i = 0 to ic.Operands.Length - 1 do
        let opr = ic.Operands[i]
        operands[i] <- parseOperand span phlp szs modRM ic opr
      operands |> buildOperands

  /// Removes the prefix from the set when the matched instruction consumed
  /// it as an opcode selector rather than a plain prefix.
  let consumePrefixIfNeeded phlp insCore =
    if shouldConsumePrefix phlp insCore then
      phlp.Prefixes <- filterPrefs phlp.Prefixes
    else ()

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

    member this.Parse(bs: byte[], addr) =
      (this :> IInstructionParsable).Parse(ReadOnlySpan bs, addr)

    member this.Parse(span: ByteSpan, addr) =
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
