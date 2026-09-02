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

  let is64 = wordSz = WordSize.Bit64

  /// The legacy opcode maps end to end, in the order ParseVEX numbers them,
  /// as ordered for this parser's mode.
  let legacyMaps =
    if is64 then InstructionTable.legacy64.Value
    else InstructionTable.legacy32.Value

  /// The VEX and EVEX maps for this parser's mode, each built when the first
  /// VEX prefix selecting it shows up.
  let vexMaps = if is64 then InstructionTable.vex64 else InstructionTable.vex32

  let mutable disasm = Disasm.Delegate Disasm.IntelSyntax.disasm

  let lifter =
    { new ILiftable with
        member _.Lift(ins, builder) = Lifter.translate ins ins.Length builder
        member _.Disasm(ins, builder) = disasm.Invoke(builder, ins); builder }

  let phlp = ParsingHelper(reader, wordSz, lifter)

  /// Returns true when EVEX.b on a register form selects a rounding mode. L'L
  /// then holds that mode rather than the vector length, so only the variant
  /// offering {er} can match. See Intel SDM Vol. 2A, Section 2.6.7.
  let usesStaticRounding (phlp: ParsingHelper) modRM (row: Row) =
    match phlp.VEXInfo with
    | Some { EVEXPrx = Some evex } when evex.B = 1uy ->
      Operands.modIsReg modRM && row.SlotDeclaresER
    | _ ->
      false

  /// Returns true when the VEX/EVEX vector length satisfies the row's
  /// vector-length constraint, which the caller has found it declares.
  let matchDeclaredVectorLength (vex: VEXInfo option) (row: Row) =
    match vex with
    | Some v ->
      match v.VectorLength with
      | 128<rt> -> row.VectorLength = VectorLength.V128
      | 256<rt> -> row.VectorLength = VectorLength.V256
      | 512<rt> -> row.VectorLength = VectorLength.V512
      | _ -> false
    | _ ->
      true

  /// Returns true when the VEX/EVEX vector length satisfies the row's
  /// vector-length constraint (or the constraint is absent). With EVEX.b
  /// selecting a rounding mode that question is asked first: EVEX.b spends
  /// L'L on the rounding mode, so the row offering {er} answers whether or
  /// not the row constrains the length.
  let matchVectorLength isRounding vex (row: Row) =
    if isRounding then
      row.DeclaresER
    else
      row.VectorLength = VectorLength.None
      || matchDeclaredVectorLength vex row

  /// The match context of the instruction at hand (see MatchContext): which
  /// REX state, whether a VEX prefix is present, and which of 66h, F3h and F2h
  /// are set. A VEX prefix carries its own copy of the three, which then
  /// speaks for them.
  let matchContext (phlp: ParsingHelper) =
    let rex = phlp.REXPrefix
    let rexState =
      if rex = REXPrefix.NOREX then 0
      elif REXPrefix.hasW rex then 2
      else 1
    match phlp.VEXInfo with
    | Some v ->
      MatchContext.index rexState 1 (MatchContext.prefState v.VPrefixes)
    | None ->
      MatchContext.index rexState 0 (MatchContext.prefState phlp.Prefixes)

  /// Returns true when the row answers the REX and mandatory prefix state of
  /// the instruction at hand; the row already carries the mask of the CPU
  /// mode at hand.
  let matchREXAndPrefix ctxBit (row: Row) = row.Accept &&& ctxBit <> 0UL

  /// Returns true for the one opcode that deviates from the standard
  /// mandatory-prefix rules: F3 90 is PAUSE, a separate instruction the F3
  /// prefix names.
  let isPause (phlp: ParsingHelper) (row: Row) =
    row.IsNopOrPause && phlp.VEXInfo.IsNone && Prefix.hasREPZ phlp.Prefixes

  /// The prefixes to drop after parsing. A VEX prefix carries its own copy of
  /// all three, so none of the legacy set outlives it.
  let consumedPrefixes (phlp: ParsingHelper) (row: Row) =
    if phlp.VEXInfo.IsSome then Prefix.OPSIZE ||| Prefix.REPZ ||| Prefix.REPNZ
    elif isPause phlp row then Prefix.REPZ
    else row.SelectorPrefixes

  /// Returns true when the current prefix is compatible with the operand size
  /// implied by the instruction's descriptors. REX.W settles the operand size
  /// by itself and outranks 66h, so the row only 66h can select is not the
  /// one an encoding carrying both asked for. SDM Vol. 2A, 2.2.1.2. The
  /// accept mask settles this wherever there is no VEX prefix; with one, the
  /// 66h asked about is the legacy prefix in front of it, which only the
  /// parsing state knows.
  let matchOperandSize (phlp: ParsingHelper) (row: Row) =
    not row.Requires66h
    || (Prefix.hasOprSz phlp.Prefixes && not (REXPrefix.hasW phlp.REXPrefix))

  /// Returns true when the ModRM byte satisfies the row's constraint: fixed,
  /// ST(i), group digit, reg/mem form, or none. A plain /r carries a reg-or-mem
  /// constraint too: the mod field is what separates MOVHLPS (register only)
  /// from MOVLPS (memory only), which share opcode 0F 12.
  let matchModRM modRM (row: Row) =
    let w = row.MatchWord
    (w &&& MatchWord.Any) <> 0UL
    || ((uint64 modRM &&& w &&& 0xFFUL) = ((w >>> 8) &&& 0xFFUL)
        && not ((w &&& MatchWord.NotReg) <> 0UL && Operands.modIsReg modRM))

  /// JCXZ/JECXZ/JRCXZ share opcode 0xE3 and are selected by the effective
  /// address size determined by the current mode and the 67h prefix:
  /// 32-bit mode  -> JECXZ, 67h -> JCXZ
  /// 64-bit mode  -> JRCXZ, 67h -> JECXZ
  /// Only the one-byte map is concerned, which is the only one whose E3h row
  /// answers here: 0xE3 is PAVGW, VPAVGW or CMPccXADD in the escape and VEX
  /// maps.
  let matchJcxzAddrSize (phlp: ParsingHelper) (row: Row) =
    match ParsingHelper.GetEffAddrSize phlp, row.Opcode with
    | 16<rt>, Opcode.JCXZ
    | 32<rt>, Opcode.JECXZ
    | 64<rt>, Opcode.JRCXZ -> true
    | _ -> false

  /// Returns true unless the row is the one-byte NOP answering an encoding
  /// that sets REX.B. NOP at 90h is, in the manual's own words, an alias
  /// mnemonic for the XCHG (E)AX, (E)AX instruction, and REX.B moves the
  /// second register to r8, so those bytes exchange rather than do nothing.
  /// The multi-byte NOP carries a ModRM byte, where REX.B extends the r/m
  /// register as it does anywhere else, and PAUSE shares the opcode byte but
  /// is a separate instruction the F3 prefix names, so REX.B is inert there.
  let matchNopAlias (phlp: ParsingHelper) (row: Row) =
    not row.IsPlainNop
    || (phlp.REXPrefix &&& REXPrefix.REXB) <> REXPrefix.REXB

  /// Returns true unless the row is an EVEX gather or scatter answering an
  /// encoding whose opmask is k0. Those instructions take the mask as a
  /// completion record, writing an element only where its bit is set and
  /// clearing the bit as they go, so k0 cannot serve: it reads as all ones and
  /// has nowhere to record progress. Every one of their pages gives #UD for
  /// EVEX.aaa = 0, and the hardware raises it. The VEX forms at the same
  /// opcodes take a vector register as the mask instead and are left alone.
  let matchGatherMask (vex: VEXInfo option) (row: Row) =
    match vex with
    | Some { EVEXPrx = Some evex } when evex.AAA = 0uy -> not row.UsesVSIB
    | _ -> true

  /// Returns true unless a LOCK prefix sits where it cannot: on an
  /// instruction outside the list, or on a form whose destination is a
  /// register rather than memory.
  let matchLock (phlp: ParsingHelper) modRM (row: Row) =
    not (Prefix.hasLock phlp.Prefixes)
    || (row.LockableDest && Operands.modIsMemory modRM)

  /// Returns true when the constraints the accept mask leaves for parse time
  /// hold: the legacy 66h under a VEX prefix, the vector length, JCXZ's
  /// address size, NOP's REX.B, a gather's opmask and LOCK's destination.
  /// Together they turn away under two percent of the candidates that reach
  /// them; JCXZ's address size rejected two in 385,588 instructions.
  let matchRareConstraints (phlp: ParsingHelper) isRounding modRM (row: Row) =
    (phlp.VEXInfo.IsNone || matchOperandSize phlp row)
    && matchVectorLength isRounding phlp.VEXInfo row
    && (not row.IsE3 || matchJcxzAddrSize phlp row)
    && matchNopAlias phlp row
    && (phlp.VEXInfo.IsNone || matchGatherMask phlp.VEXInfo row)
    && matchLock phlp modRM row

  /// Returns true when every constraint the row declares holds for the bytes
  /// at hand. Ordered by what each test costs against how much it turns away,
  /// measured over real binaries in both modes. The ModRM byte leads because
  /// it is the cheapest question here - one masked compare - and still
  /// rejects about a quarter of the candidates that reach it. The accept mask
  /// then answers for the REX prefix, the mandatory prefix, the operand size
  /// and the CPU mode at once. A plain row under a simple state, one with no
  /// LOCK and no VEX prefix, has nothing left to be asked; the rest go through
  /// the remaining constraints one by one.
  let matchesRow phlp ctxBit isRounding simple modRM (row: Row) =
    matchModRM modRM row
    && matchREXAndPrefix ctxBit row
    && ((simple && (row.MatchWord &&& MatchWord.Plain) <> 0UL)
        || matchRareConstraints phlp isRounding modRM row)

#if DEBUG
  /// Reports each constraint's verdict on one entry. The candidate loop stops
  /// at the first failure, so this runs them all again to show which ones
  /// rejected an entry, or which entry won and why.
  let traceInstrCore (phlp: ParsingHelper) ctxBit isRounding modRM row =
    printfn
      "%A rex+pref+size+mode=%b modrm=%b rare=%b"
      (row: Row).Opcode
      (matchREXAndPrefix ctxBit row)
      (matchModRM modRM row)
      (matchRareConstraints phlp isRounding modRM row)
#endif

  /// Returns the first row of the chain that satisfies all matching
  /// constraints; raises if no variant matches. modRM is the byte after the
  /// opcode, or 0 where the bytes end there: a row that needs one then fails
  /// to read it whichever row is picked, as it did when the byte was read
  /// here.
  let selectInstrVariant (phlp: ParsingHelper) modRM (head: Row) =
    if isNull (box head) then
      failwith "Error: Instruction core array is empty."
    else
      let ctxBit = 1UL <<< matchContext phlp
      let isRounding = usesStaticRounding phlp modRM head
      let simple = phlp.VEXInfo.IsNone && not (Prefix.hasLock phlp.Prefixes)
      let mutable row = head
      let mutable found = Unchecked.defaultof<Row>
      while isNull (box found) && not (isNull (box row)) do
#if DEBUG
        traceInstrCore phlp ctxBit isRounding modRM row
#endif
        if matchesRow phlp ctxBit isRounding simple modRM row then
          found <- row
        else
          row <- row.Next
#if DEBUG
      printfn "pref: %A, rex: %A, vex: %A -> selected %b"
        phlp.Prefixes phlp.REXPrefix phlp.VEXInfo (not (isNull (box found)))
#endif
      if isNull (box found) then failwith "No matching instruction format."
      else found

  /// Writes regSz and memSz into the parsing-helper context for use by
  /// subsequent operand parsers. The address size was settled once for the
  /// whole instruction before any operand was read, and the operation size is
  /// settled once after every operand has been.
  let setupOprContext (phlp: ParsingHelper) regSz memSz =
    phlp.MemEffOprSize <- memSz
    phlp.RegSize <- regSz

  /// Sizes an operand that carries no width of its own from the prefixes and
  /// the CPU mode, under the given size condition.
  let setupOprContextFromPrefixes (phlp: ParsingHelper) szCond =
    let effOprSz = ParsingHelper.GetEffOprSize(phlp, szCond)
    setupOprContext phlp effOprSz effOprSz

  /// The register index a mask or MMX operand names. These registers have no
  /// extension bit, so the raw three-bit field is the whole index.
  let shortRegIndex (phlp: ParsingHelper) modRM = function
    | RegBit ->
      Operands.getReg modRM
    | RMBit ->
      Operands.getRM modRM
    | VVVV ->
      match phlp.VEXInfo with
      | Some v -> int v.VVVV
      | None -> failwith "VEXInfo is required to get VVVV bits."
    | ort ->
      failwithf "Invalid OprRegType for a short register: %A" ort

  /// Parses one register operand named by the given field.
  let parseRegOperand span (phlp: ParsingHelper) modRM opByte sz =
    function
    | OprRegType.OpRd -> (* Opcode[2:0] holds the register. *)
      OperandParsers.getOprFromRegGrpREX (Operands.getRM opByte) phlp
    | OprRegType.VVVV ->
      (* BMI/CMPccXADD encode a GPR in vvvv, not a vector register. *)
      if sz <= 64<rt> then OperandParsers.parseVEXtoGPR phlp
      else OperandParsers.parseVVVVReg phlp
    | OprRegType.RMBit ->
      OperandParsers.findRegRM modRM phlp |> Operands.oprReg
    | OprRegType.RegBit ->
      OperandParsers.findRegReg sz modRM phlp |> Operands.oprReg
    | OprRegType.IS4 -> (* imm8[7:4] holds the register. *)
      let regBit = phlp.ReadByte span >>> 4 &&& 0b1111uy |> int
      OperandParsers.findRegIS4 phlp.WordSize sz regBit |> Operands.oprReg
    | OprRegType.Unused ->
      failwith "Unused OprRegType." (* FixedReg *)

  /// Parses a VSIB memory operand. A gathered element occupies max(index,
  /// data) bits, so the vector length says how many of them there are. The
  /// index register then holds that many indices, never narrower than an XMM,
  /// and the memory access covers that many data elements. See Intel SDM Vol.
  /// 2C, the vm32x/vm32y/vm32z and vm64x/vm64y/vm64z operand tables.
  let parseVSIBOperand span (phlp: ParsingHelper) modRM elemSz =
    let vl = phlp.VEXInfo.Value.VectorLength
    let dataSz = if REXPrefix.hasW phlp.REXPrefix then 64<rt> else 32<rt>
    let count = vl / max elemSz dataSz
    let idxVl = max 128<rt> (count * elemSz)
    let memSz = count * dataSz
    (* A vector index lives in the SIB byte, and only r/m = 100b brings one.
       Any other r/m is #UD; reading a SIB that is not there invented an
       index and swallowed the byte after the instruction. *)
    if Operands.getRM modRM <> 0b100 then failwith "VSIB without a SIB byte."
    else ()
    setupOprContext phlp memSz memSz
    let modVal = modRM &&& 0b11000000uy
    OperandParsers.parseOprMemVSIB span phlp modVal idxVl

  /// Parses a far pointer. sz is the offset width; a far pointer also carries
  /// a 16-bit segment selector, so the whole thing is 16 bits wider.
  /// OperationSize holds that whole width rather than the register width.
  let parseFarOperand span (phlp: ParsingHelper) modRM hasModRM sz =
    let oprSz = sz + 16<rt>
    setupOprContext phlp sz oprSz
    phlp.OperationSize <- oprSz
    phlp.IsFar <- true
    if not hasModRM then
      (* ptr16:16 or ptr16:32, spelled out in the instruction (9A, EA). *)
      let addrValue =
        OperandParsers.parseUnsignedImm span phlp (RegType.toByteWidth sz)
      let selector = phlp.ReadInt16 span
      OprDirAddr(Absolute(selector, addrValue, sz))
    else
      (* m16:16, m16:32 or m16:64, read through ModRM (FF /3, FF /5). *)
      OperandParsers.parseMemory modRM span phlp

  /// Parses the register the address-size-dependent operand names.
  let parseRegAddrOperand (phlp: ParsingHelper) (row: Row) modRM =
    let sz = phlp.MemEffAddrSize
    setupOprContext phlp sz sz
    if row.IsGroupExtension then
      let rm = Operands.getRM modRM
      OperandParsers.findRegRmAndSIBBase sz phlp.REXPrefix rm |> Operands.oprReg
    else
      let reg = Operands.getReg modRM
      OperandParsers.findRegRBits sz phlp.REXPrefix reg |> Operands.oprReg

  /// Parses one operand descriptor into a concrete Operand value and updates
  /// the context so subsequent operands derive the correct width.
  let parseOperand span (phlp: ParsingHelper) (row: Row) modRM (o: OprSpec) =
    match o.Kind with
    | OprKind.RM ->
      setupOprContext phlp o.Size o.Size
      OperandParsers.parseMemOrReg modRM span phlp
    | OprKind.RMTwoWidths ->
      setupOprContext phlp o.Size o.MemSize
      OperandParsers.parseMemOrReg modRM span phlp
    | OprKind.RMBroadcast ->
      setupOprContext phlp o.Size o.MemSize
      phlp.BroadcastSize <- o.BcstSize
      OperandParsers.parseMemOrReg modRM span phlp
    | OprKind.MemVSIB ->
      parseVSIBOperand span phlp modRM o.Size
    | OprKind.Reg ->
      setupOprContext phlp o.Size o.Size
      parseRegOperand span phlp modRM row.OpcodeByte o.Size o.Field
    | OprKind.Mem ->
      setupOprContext phlp o.Size o.Size
      OperandParsers.parseMemory modRM span phlp
    | OprKind.MemFromPrefixes ->
      setupOprContextFromPrefixes phlp row.SzCond
      OperandParsers.parseMemory modRM span phlp
    | OprKind.Imm ->
      setupOprContextFromPrefixes phlp row.SzCond
      if row.SignExtendsImm then OperandParsers.parseOprSImm span phlp o.Size
      else OperandParsers.parseOprImm span phlp o.Size
    | OprKind.Rel ->
      setupOprContextFromPrefixes phlp row.SzCond
      OperandParsers.parseOprForRelJmp span phlp o.Size
    | OprKind.FixedReg ->
      setupOprContext phlp o.Size o.Size
      Operands.oprReg (EnumOfValue o.Value)
    | OprKind.FixedRegModeWidth ->
      let reg: Register = EnumOfValue o.Value
      let sz = RegisterHelper.toRegType phlp.WordSize reg
      setupOprContext phlp sz sz
      Operands.oprReg reg
    | OprKind.STRegRM ->
      Operands.getRM modRM |> Operands.getSTReg
    | OprKind.STRegFixed ->
      Operands.oprReg (EnumOfValue o.Value)
    | OprKind.BM ->
      if Operands.modIsReg modRM then
        OperandParsers.parseBoundRegister (Operands.getRM modRM)
      else
        setupOprContext phlp o.Size o.Size
        OperandParsers.parseMemory modRM span phlp
    | OprKind.BndReg ->
      OperandParsers.parseBoundRegister (Operands.getReg modRM)
    | OprKind.OpMaskReg ->
      shortRegIndex phlp modRM o.Field |> OperandParsers.parseOpMaskReg
    | OprKind.KM ->
      setupOprContext phlp o.Size o.Size
      if Operands.modIsReg modRM then
        OperandParsers.parseOpMaskReg (Operands.getRM modRM)
      else
        OperandParsers.parseMemory modRM span phlp
    | OprKind.MMXReg ->
      shortRegIndex phlp modRM o.Field |> OperandParsers.parseMMXReg
    | OprKind.MM ->
      if Operands.modIsReg modRM then
        OperandParsers.parseMMXReg (Operands.getRM modRM)
      else
        setupOprContext phlp o.Size o.Size
        OperandParsers.parseMemory modRM span phlp
    | OprKind.FixedImm ->
      Operands.oprImm (int64 o.Value) row.FixedImmSize
    | OprKind.Moffs ->
      setupOprContext phlp o.Size o.Size
      OperandParsers.parseOprOnlyDisp span phlp
    | OprKind.CtrlReg ->
      OperandParsers.sysRegIndex modRM phlp.REXPrefix
      |> OperandParsers.parseControlReg
    | OprKind.DebugReg ->
      OperandParsers.sysRegIndex modRM phlp.REXPrefix
      |> OperandParsers.parseDebugReg
    | OprKind.RegAddr ->
      parseRegAddrOperand phlp row modRM
    | OprKind.Sreg ->
      OperandParsers.parseSegReg (Operands.getReg modRM)
    | OprKind.Far ->
      parseFarOperand span phlp modRM row.HasModRM o.Size
    | _ ->
      failwithf "Unsupported operand type: %A" o.Kind

  /// Reads the ModRM byte where one follows the opcode. The table is the only
  /// authority on whether it does: reading one that is not there overstates
  /// the length and swallows the instruction after it, as GETSEC showed.
  let readModRM span (phlp: ParsingHelper) (row: Row) =
    if row.HasModRM then phlp.ReadByte span else 0uy

  /// The width the whole operation runs at. The table settled it wherever it
  /// could; the rest depends on the ModRM byte, the prefixes or the mode.
  let operationSize (phlp: ParsingHelper) modRM (row: Row) =
    match row.OpWidthKind with
    | OpWidthKind.Fixed ->
      row.OpWidth
    | OpWidthKind.ByModRMForm ->
      if Operands.modIsReg modRM then row.OpWidth else row.OpWidthMem
    | OpWidthKind.FixedRegister ->
      RegisterHelper.toRegType phlp.WordSize row.OpWidthReg
    | OpWidthKind.EffectiveAddress ->
      phlp.MemEffAddrSize
    | _ (* OpWidthKind.FromPrefixes *) ->
      ParsingHelper.GetEffOprSize(phlp, row.EffSzCond)

  /// Parses a register named by ModRM.reg followed by a register-or-memory
  /// operand, the way parseOperand would read the two descriptors, without
  /// asking either descriptor what it is.
  let parseRegThenRM span (phlp: ParsingHelper) modRM (row: Row) =
    let regSz = row.Size0
    setupOprContext phlp regSz regSz
    let reg = OperandParsers.findRegReg regSz modRM phlp |> Operands.oprReg
    let rmSz = row.Size1
    setupOprContext phlp rmSz rmSz
    let rm = OperandParsers.parseMemOrReg modRM span phlp
    Operands.twoOperands reg rm

  /// Parses a register-or-memory operand followed by a register named by
  /// ModRM.reg, the same way.
  let parseRMThenReg span (phlp: ParsingHelper) modRM (row: Row) =
    let rmSz = row.Size0
    setupOprContext phlp rmSz rmSz
    let rm = OperandParsers.parseMemOrReg modRM span phlp
    let regSz = row.Size1
    setupOprContext phlp regSz regSz
    let reg = OperandParsers.findRegReg regSz modRM phlp |> Operands.oprReg
    Operands.twoOperands rm reg

  /// Parses a register-or-memory operand followed by an immediate, the way
  /// parseOperand would read the two descriptors.
  let parseRMThenImm span (phlp: ParsingHelper) modRM (row: Row) =
    let rmSz = row.Size0
    setupOprContext phlp rmSz rmSz
    let rm = OperandParsers.parseMemOrReg modRM span phlp
    setupOprContextFromPrefixes phlp row.SzCond
    let imm =
      if row.SignExtendsImm then OperandParsers.parseOprSImm span phlp row.Size1
      else OperandParsers.parseOprImm span phlp row.Size1
    Operands.twoOperands rm imm

  /// Parses the one operand of a row whose shape is read by code of its own,
  /// the way parseOperand would read its descriptor.
  let parseSingleOperand span (phlp: ParsingHelper) modRM (row: Row) =
    match row.Shape with
    | OprShape.RMOnly ->
      let sz = row.Size0
      setupOprContext phlp sz sz
      OperandParsers.parseMemOrReg modRM span phlp
    | OprShape.RelOnly ->
      setupOprContextFromPrefixes phlp row.SzCond
      OperandParsers.parseOprForRelJmp span phlp row.Size0
    | OprShape.RegOpRdOnly ->
      let sz = row.Size0
      setupOprContext phlp sz sz
      OperandParsers.getOprFromRegGrpREX (Operands.getRM row.OpcodeByte) phlp
    | _ ->
      parseOperand span phlp row modRM row.OprSpecs[0]

  /// Parses every operand descriptor of the row in order and assembles the
  /// Operands value. Each parse reads its own bytes and leaves the width the
  /// next one starts from, so every operand is bound where it is read rather
  /// than handed to a constructor that says nothing about the order.
  let parseOperands span phlp (row: Row) modRM =
    match row.OperandCount with
    | 2 ->
      match row.Shape with
      | OprShape.RegThenRM ->
        parseRegThenRM span phlp modRM row
      | OprShape.RMThenReg ->
        parseRMThenReg span phlp modRM row
      | OprShape.RMThenImm ->
        parseRMThenImm span phlp modRM row
      | _ ->
        let operandTypes = row.OprSpecs
        let op1 = parseOperand span phlp row modRM operandTypes[0]
        let op2 = parseOperand span phlp row modRM operandTypes[1]
        Operands.twoOperands op1 op2
    | 1 ->
      Operands.oneOperand (parseSingleOperand span phlp modRM row)
    | 3 ->
      let operandTypes = row.OprSpecs
      let op1 = parseOperand span phlp row modRM operandTypes[0]
      let op2 = parseOperand span phlp row modRM operandTypes[1]
      let op3 = parseOperand span phlp row modRM operandTypes[2]
      Operands.ThreeOperands(op1, op2, op3)
    | 4 ->
      let operandTypes = row.OprSpecs
      let op1 = parseOperand span phlp row modRM operandTypes[0]
      let op2 = parseOperand span phlp row modRM operandTypes[1]
      let op3 = parseOperand span phlp row modRM operandTypes[2]
      let op4 = parseOperand span phlp row modRM operandTypes[3]
      Operands.FourOperands(op1, op2, op3, op4)
    | 0 ->
      Operands.NoOperand
    | _ ->
      failwith "Invalid number of operands."

  /// Reads the ModRM byte if required, then parses all operand descriptors
  /// and returns the assembled Operands value.
  let parseAllOperands span (phlp: ParsingHelper) (row: Row) =
    let modRM = readModRM span phlp row
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    (* Cleared once here: only a memory operand reads a broadcast width, an
       instruction has at most one, and the RMBroadcast case sets it. *)
    phlp.BroadcastSize <- 0<rt>
    if row.IsFarRet then phlp.IsFar <- true else ()
    if row.OperandCount = 0 then
      (* Nothing else sizes an operand-less instruction, yet the lifter still
         reads OperationSize: auxPop needs it for RET and LEAVE. *)
      setupOprContextFromPrefixes phlp row.EffSzCond
      phlp.OperationSize <-
        if row.IsByteString then 8<rt> else phlp.MemEffOprSize
      Operands.NoOperand
    else
      let operands = parseOperands span phlp row modRM
      phlp.OperationSize <- operationSize phlp modRM row
      operands

  /// Removes the prefixes the matched instruction consumed as opcode
  /// selectors, leaving the ones that kept their ordinary meaning.
  let consumePrefixIfNeeded (phlp: ParsingHelper) row =
    let consumed = consumedPrefixes phlp row
    phlp.Prefixes <- phlp.Prefixes &&& ~~~consumed

  /// The opcode map a VEX or EVEX prefix selects.
  let vexMap (vInfo: VEXInfo) =
    if vInfo.VEXType &&& VEXType.EVEX = VEXType.EVEX then
      match vInfo.VEXType &&& (~~~VEXType.EVEX) with
      | VEXType.TwoByteOp -> vexMaps[3].Value
      | VEXType.ThreeByteOpOne -> vexMaps[4].Value
      | VEXType.ThreeByteOpTwo -> vexMaps[5].Value
      | VEXType.Map5 -> vexMaps[6].Value
      | VEXType.Map6 -> vexMaps[7].Value
      | _ -> raise ParsingFailureException
    else
      match vInfo.VEXType with
      | VEXType.TwoByteOp -> vexMaps[0].Value
      | VEXType.ThreeByteOpOne -> vexMaps[1].Value
      | VEXType.ThreeByteOpTwo -> vexMaps[2].Value
      | _ -> raise ParsingFailureException

  member _.SetDisassemblySyntax syntax =
    match syntax with
    | DefaultSyntax -> disasm <- Disasm.Delegate Disasm.IntelSyntax.disasm
    | ATTSyntax -> disasm <- Disasm.Delegate Disasm.ATTSyntax.disasm

  member inline private _.IsPrefixByte(b: byte) =
    ((prefixCheck[(int b >>> 5)] >>> (int b &&& 0b11111)) &&& 1u) > 0u

  /// In 64-bit mode 40h through 4Fh are REX prefixes; below it they are the
  /// one-byte INC and DEC forms and no prefix at all.
  member inline private _.IsREXByte(b: byte) =
    is64 && (int b &&& 0b11110000) = 0b01000000

  member inline private this.ParsePrefix(span: ByteSpan, startPos, startPref) =
    let mutable pos = startPos
    let mutable pref = startPref
    let mutable b = span[pos]
    while this.IsPrefixByte b do
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
    if not is64 then
      pos
    else
      let rb = bs[pos] |> int
      if rb &&& 0b11110000 = 0b01000000 then
        rex <- EnumOfValue rb
        pos + 1
      else
        pos

  /// Reads a VEX or EVEX prefix where one sits, or else the escape bytes that
  /// select a legacy map, whose index into legacyMaps is left in map.
  member inline private _.ParseVEX(bs: ByteSpan,
                                   pos,
                                   rex: REXPrefix byref,
                                   vex: VEXInfo option byref,
                                   map: int byref) =
    match bs[pos] with
    | 0x0Fuy ->
      match bs[pos + 1] with
      | 0x38uy ->
        map <- 2
        pos + 2
      | 0x3Auy ->
        map <- 3
        pos + 2
      | _ ->
        map <- 1
        pos + 1
    (* Outside 64-bit mode C5h, C4h and 62h are LDS, LES and BOUND unless the
       ModRM byte that follows names a register. *)
    | 0xC5uy when bs[pos + 1] >= 0xC0uy || is64 ->
      vex <- Some(getTwoVEXInfo bs &rex (pos + 1))
      pos + 2
    | 0xC4uy when bs[pos + 1] >= 0xC0uy || is64 ->
      vex <- Some(getThreeVEXInfo bs &rex (pos + 1))
      pos + 3
    | 0x62uy when bs[pos + 1] >= 0xC0uy || is64 ->
      vex <- Some(getEVEXInfo bs &rex (pos + 1))
      pos + 4
    | _ ->
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
        let mutable map = 0
        let mutable prefEndPos = this.ParsePrefix(span, 0, Prefix.None)
        let mutable rexEndPos = this.ParseREX(span, prefEndPos, &rex)
        (* SDM Vol 2A 2.2.1: a REX prefix has to sit immediately before the
           opcode, so one that another prefix follows is ignored and the scan
           carries on past it. Two REX bytes in a row read the same way: only
           the last one is doing anything. *)
        while rexEndPos > prefEndPos
              && (this.IsPrefixByte(span[rexEndPos])
                  || this.IsREXByte(span[rexEndPos])) do
          rex <- REXPrefix.NOREX
          prefEndPos <- this.ParsePrefix(span, rexEndPos, phlp.Prefixes)
          rexEndPos <- this.ParseREX(span, prefEndPos, &rex)
        let nextPos = this.ParseVEX(span, rexEndPos, &rex, &vex, &map)
        phlp.IsFar <- false
        phlp.InsAddr <- addr
        phlp.REXPrefix <- rex
        (* A reference store costs a GC write barrier; None over None does
           not have to be stored, and that is nearly every instruction. *)
        if vex.IsSome || phlp.VEXInfo.IsSome then phlp.VEXInfo <- vex else ()
        phlp.CurrPos <- nextPos
#if LCACHE
        phlp.MarkPrefixEnd(prefEndPos)
#endif
        let b = int (phlp.ReadByte span)
        (* The ModRM byte, where the bytes reach that far: the digit it
           carries picks the rows in play, and the rows then test it. *)
        let modRM =
          if phlp.CurrPos < span.Length then span[phlp.CurrPos] else 0uy
        let digit = Operands.getReg modRM
        let head =
          match vex with
          | Some vInfo -> (vexMap vInfo)[(b <<< 3) ||| digit]
          | None -> legacyMaps[(map <<< 11) ||| (b <<< 3) ||| digit]
        let row = selectInstrVariant phlp modRM head
        (* Only an EVEX displacement reads the tuple type. *)
        if vex.IsSome then phlp.TupleType <- row.TupleType else ()
        let operands = parseAllOperands span phlp row
        consumePrefixIfNeeded phlp row
        newInstruction phlp row.Opcode operands :> IInstruction
      with e when not (Terminator.isCritical e) ->
        raise ParsingFailureException

// vim: set tw=80 sts=2 sw=2:
