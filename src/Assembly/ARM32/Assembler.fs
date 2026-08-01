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

namespace B2R2.Assembly.ARM32

open System
open FParsec
open B2R2
open B2R2.FrontEnd.ARM32
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.ARM32.ParserHelper
open B2R2.Assembly.ARM32.AsmMain

/// <namespacedoc>
///   <summary>
///   Contains ARM32-specific assembly components and types.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Represents an assembler for ARM32 binaries. The syntax it reads is the one
/// B2R2's ARM32 disassembler writes, so a line of disassembly can be handed
/// straight back to it.
///
/// Which instruction set a source starts in comes from the ISA it is built
/// with, since nothing in a line of either says which of the two it is; the
/// directives in the source switch between them from there.
/// </summary>
type Assembler(isa: ISA, baseAddr: Addr) =

  /// The ISA of each instruction set, which is what the caller is told an
  /// instruction was assembled for.
  let isAArch32 = isa.Arch = Architecture.ARMv8

  let armISA = ISA(isa.Endian, isAArch32, ARM32Mode.ARM)

  let thumbISA = ISA(isa.Endian, isAArch32, ARM32Mode.Thumb)

  let isThumb = isa.ARM32Mode = ARM32Mode.Thumb

  /// The table-driven encoders, built here so that they are collected with the
  /// assembler instead of living for as long as the process does, and built
  /// only if a source asks for them: one that never leaves the instruction set
  /// it starts in never pays for the other's table.
  let armEncoders = lazy (buildEncoderTable ())

  let thumbEncoders = lazy (buildThumbEncoderTable ())

  /// Which instruction set the line being parsed belongs to, which a directive
  /// changes and nothing else does.
  let mutable inThumbMode = isThumb

  /// Whether the instruction being parsed wrote a "!" after a register, which
  /// is how the forms that keep no offset in brackets spell writeback.
  let mutable writeBack = false

  /// Whether it wrote a "^" after a register list, which is how a block
  /// transfer says it names the registers of another mode.
  let mutable caret = false

  let addLabeldef lbl =
    updateUserState (fun us ->
      if Map.containsKey lbl us.LabelMap then
        raise <| EncodingFailureException $"Label '{lbl}' already defined"
      else
        { us with LabelMap = Map.add lbl us.CurIndex us.LabelMap })
    >>. preturn ()

  let incrementIndex =
    updateUserState (fun us -> { us with CurIndex = us.CurIndex + 1 })
    >>. preturn ()

  let isWhitespace c = [ ' '; '\t'; '\f' ] |> List.contains c

  let whitespace = manySatisfy isWhitespace

  let skipWhitespaces s = whitespace >>? s .>>? whitespace

  /// A comment runs to the end of its line. The disassembler writes the symbol
  /// a resolved branch target belongs to as one, so that a line it printed can
  /// be read back as it stands.
  let comment = pchar ';' >>. manySatisfy (fun c -> c <> '\n')

  /// Whatever may sit between the end of a statement and the end of its line.
  let restOfLine = whitespace >>. optional comment

  let terminator = newline |>> ignore <?> ""

  let operandSeps = pchar ',' >>. whitespace

  let isIdentifierChar c = Char.IsLetterOrDigit c || c = '_'

  let pIdentifier = many1Satisfy isIdentifierChar

  let pLabelDef = pIdentifier .>>? pchar ':' >>= addLabeldef <?> "label"

  let numberFormat =
    NumberLiteralOptions.AllowBinary
    ||| NumberLiteralOptions.AllowOctal
    ||| NumberLiteralOptions.AllowHexadecimal
    ||| NumberLiteralOptions.AllowMinusSign
    ||| NumberLiteralOptions.AllowPlusSign

  let pNumber =
    numberLiteral numberFormat "number"
    |>> fun n ->
      if n.String.StartsWith "-" then -(int64 n.String[1..])
      elif n.String.StartsWith "+" then int64 n.String[1..]
      else int64 n.String

  let pFraction =
    numberLiteral
      (NumberLiteralOptions.AllowFraction
       ||| NumberLiteralOptions.AllowMinusSign) "number"
    >>= fun n ->
      if n.IsInteger then fail "not a fraction" else preturn (float n.String)

  let pSign = (pchar '-' >>. preturn Minus) <|> (pchar '+' >>. preturn Plus)

  /// An identifier as a name to look something up by, which is case-insensitive
  /// wherever the vocabulary is the assembler's own rather than the source's.
  let pName = pIdentifier |>> fun name -> name.ToLowerInvariant()

  let pRegisterName =
    pName >>= fun name ->
      match Map.tryFind name registers with
      | Some reg -> preturn reg
      | None -> fail $"'{name}' is not a register"

  /// Whether a register is one of the SIMD and floating-point registers, which
  /// are written as an operand of their own kind rather than as a register.
  let isSIMDRegister reg =
    (int reg >= int Register.S0 && int reg <= int Register.D31)
    || (int reg >= int Register.Q0 && int reg <= int Register.Q15)

  /// The element index a SIMD register may carry, which the disassembler writes
  /// even when it does not know which element is meant.
  let pElementIndex = between (pchar '[') (pchar ']') (opt puint8)

  let toSIMDRegister reg = function
    | Some index -> Scalar(reg, index)
    | None -> Vector reg

  /// A register, a status register with the fields it names written after an
  /// underscore, or one of the SIMD registers with an element index.
  let pRegisterOperand =
    pName >>= fun name ->
      match Map.tryFind name registers with
      | Some reg when isSIMDRegister reg ->
        opt pElementIndex
        |>> fun index -> OprSIMD(SFReg(toSIMDRegister reg index))
      | Some reg -> preturn (OprReg reg)
      | None ->
        match name.LastIndexOf '_' with
        | -1 -> fail $"'{name}' is not a register"
        | index ->
          let regName = name[..index - 1]
          let flagName = name[index + 1..]
          match Map.tryFind regName registers,
                Map.tryFind flagName psrFlags with
          | Some reg, Some flag -> preturn (OprSpecReg(reg, Some flag))
          | _ -> fail $"'{name}' is not a register"

  let noteWriteBack = function
    | Some _ -> writeBack <- true
    | None -> ()

  let pOprRegister =
    pRegisterOperand .>>. opt (pchar '!')
    |>> fun (operand, bang) -> noteWriteBack bang; operand

  let pShiftName =
    pName >>= fun name ->
      match Map.tryFind name shiftOps with
      | Some shift -> preturn shift
      | None -> fail $"'{name}' is not a shift"

  /// How much to shift by: an immediate, or a register holding the amount. RRX
  /// shifts by exactly one place, which is the amount the disassembler writes
  /// for it, so an absent amount stands for none.
  let pShiftAmount =
    (pchar '#' >>. pNumber |>> Choice1Of2)
    <|> (pRegisterName |>> Choice2Of2)

  let toShiftOperand shift = function
    | Some(Choice1Of2 amount) -> OprShift(shift, Imm(uint32 amount))
    | Some(Choice2Of2 reg) -> OprRegShift(shift, reg)
    | None when shift = ShiftOp.RRX -> OprShift(shift, Imm 1u)
    | None -> OprShift(shift, Imm 0u)

  let pOprShift =
    pShiftName .>> whitespace .>>. opt pShiftAmount
    |>> fun (shift, amount) -> toShiftOperand shift amount

  /// The shift written after a register offset, which is the same syntax
  /// without a register amount: a memory offset shifts by an immediate only.
  let pOffsetShift =
    pShiftName .>> whitespace .>>. opt (pchar '#' >>. pNumber)
    |>> fun (shift, amount) ->
      match amount with
      | Some amount -> shift, Imm(uint32 amount)
      | None when shift = ShiftOp.RRX -> shift, Imm 1u
      | None -> shift, Imm 0u

  /// #{+/-}<imm>, which writes the sign of an offset apart from its size.
  let pImmediateOffset =
    pchar '#' >>. opt pSign .>>. pNumber
    |>> fun (sign, value) ->
      let negative = (sign = Some Minus) <> (value < 0L)
      let sign = if negative then Some Minus else Some Plus
      fun rn -> ImmOffset(rn, sign, Some(abs value))

  /// {+/-}<Rm>{, <shift>}, the register offset form.
  let pRegisterOffset =
    opt pSign .>>. pRegisterName
    .>>. opt (attempt (skipWhitespaces (pchar ',') >>. pOffsetShift))
    |>> fun ((sign, rm), shift) ->
      let sign = if sign = Some Minus then Some Minus else Some Plus
      fun rn -> RegOffset(rn, sign, rm, shift)

  let pOffset = pImmediateOffset <|> pRegisterOffset

  /// The option of an unindexed memory operand, which names something the
  /// coprocessor reads rather than a place.
  let pUnIdxOption =
    between (pchar '{') (pchar '}') (skipWhitespaces pNumber)

  /// What may follow the closing bracket of a memory operand, which is what
  /// tells the addressing modes apart.
  let pMemorySuffix =
    (pchar '!' >>. preturn WriteBackSuffix)
    <|> attempt (operandSeps >>. pUnIdxOption |>> UnindexedSuffix)
    <|> attempt (operandSeps >>. pOffset |>> PostIndexedSuffix)
    <|> preturn PlainSuffix

  let toAddressingMode rn inner suffix =
    match inner, suffix with
    | Some makeOffset, PlainSuffix -> Some(OffsetMode(makeOffset rn))
    | Some makeOffset, WriteBackSuffix -> Some(PreIdxMode(makeOffset rn))
    | None, PlainSuffix -> Some(OffsetMode(ImmOffset(rn, None, None)))
    | None, WriteBackSuffix -> Some(PreIdxMode(ImmOffset(rn, None, None)))
    | None, PostIndexedSuffix makeOffset -> Some(PostIdxMode(makeOffset rn))
    | None, UnindexedSuffix option -> Some(UnIdxMode(rn, option))
    | _ -> None

  /// [<Rn>{, <offset>}]{!}, [<Rn>], <offset> and [<Rn>], {<option>}, which
  /// differ only in where the bracket closes and in what follows it.
  let pMemoryIndexed =
    pchar '[' >>. skipWhitespaces pRegisterName
    .>>. opt (operandSeps >>. pOffset) .>> pchar ']' .>>. pMemorySuffix
    >>= fun ((rn, inner), suffix) ->
      match toAddressingMode rn inner suffix with
      | Some mode -> preturn mode
      | None -> fail "an offset cannot sit both inside and after the brackets"

  /// Whether the opcode is one of the SIMD accesses that name whole structures.
  /// Their memory operand may promise an alignment, and a register written
  /// after it says how far to step the base afterwards rather than where to
  /// read.
  let isStructureAccess opcode =
    match opcode with
    | Opcode.VLD1 | Opcode.VLD2 | Opcode.VLD3 | Opcode.VLD4
    | Opcode.VST1 | Opcode.VST2 | Opcode.VST3 | Opcode.VST4 -> true
    | _ -> false

  /// [<Rn>{:<align>}]{!} and [<Rn>{:<align>}], <Rm>.
  let pAlignedMemory =
    pchar '[' >>. skipWhitespaces pRegisterName
    .>>. opt (pchar ':' >>. pNumber) .>> pchar ']' .>>. opt (pchar '!')
    .>>. opt (attempt (operandSeps >>. pRegisterName))
    |>> fun (((rn, align), bang), rm) ->
      let offset = AlignOffset(rn, align, rm)
      match bang, rm with
      | Some _, _ -> OprMemory(PreIdxMode offset)
      | None, Some _ -> OprMemory(PostIdxMode offset)
      | None, None -> OprMemory(OffsetMode offset)

  /// [<address>], which is how the disassembler writes a literal it resolved.
  /// What the source names is where to read, so how far that is from here is
  /// worked out once the instruction's own place is known.
  let pMemoryLiteral =
    pchar '[' >>. skipWhitespaces pNumber .>> pchar ']' |>> LiteralMode

  let pOprMemory = attempt pMemoryLiteral <|> pMemoryIndexed |>> OprMemory

  /// A branch target, which the disassembler writes as the address it resolved
  /// rather than as an offset from anywhere.
  let pOprAddress = pNumber |>> (LiteralMode >> OprMemory)

  let makeRegisterList elements =
    if elements |> List.forall (fun (reg, index) ->
         Option.isNone index && not (isSIMDRegister reg)) then
      elements |> List.map fst |> OprRegList
    else
      elements
      |> List.map (fun (reg, index) -> toSIMDRegister reg index)
      |> makeSIMDOperand
      |> OprSIMD

  let pRegisterListElement = pRegisterName .>>. opt pElementIndex

  let noteCaret = function
    | Some _ -> caret <- true
    | None -> ()

  /// Whether a braced list names the registers a floating-point transfer moves.
  /// Those are written the way a SIMD list is, but they stand for a run of
  /// registers rather than for one operand each, and the run may be longer than
  /// any SIMD operand.
  let isRegisterListOpcode opcode =
    match opcode with
    | Opcode.VLDMIA | Opcode.VLDMDB | Opcode.VSTMIA | Opcode.VSTMDB
    | Opcode.VPUSH | Opcode.VPOP
    | Opcode.FLDMIAX | Opcode.FLDMDBX | Opcode.FSTMIAX | Opcode.FSTMDBX ->
      true
    | _ -> false

  /// {<registers>}{^}, which holds either core registers or SIMD ones.
  let pOprRegisterList opcode =
    between (pchar '{') (pchar '}')
      (sepBy (skipWhitespaces pRegisterListElement) (pchar ','))
    .>>. opt (pchar '^')
    |>> fun (elements, hat) ->
      noteCaret hat
      if isRegisterListOpcode opcode then
        elements |> List.map fst |> OprRegList
      else
        makeRegisterList elements

  let pOprImm =
    attempt (pchar '#' >>. pFraction |>> OprFPImm)
    <|> (pchar '#' >>. pNumber |>> OprImm)

  /// The option a barrier names, which the disassembler writes as a number
  /// when the option has no name of its own.
  let pOprBarrierOption =
    attempt (pName >>= fun name ->
      match Map.tryFind name barrierOptions with
      | Some option -> preturn (OprOption option)
      | None -> fail $"'{name}' is not a barrier option")
    <|> (pNumber |>> (barrierOptionOfValue >> OprOption))

  let pOprEndian =
    (pstringCI "le" >>. preturn (OprEndian Endian.Little))
    <|> (pstringCI "be" >>. preturn (OprEndian Endian.Big))

  let pOprIflag =
    pName >>= fun name ->
      match Map.tryFind name iflags with
      | Some flag -> preturn (OprIflag flag)
      | None -> fail $"'{name}' is not an interrupt flag"

  let pOprCondition =
    pName >>= fun name ->
      match Map.tryFind name conditions with
      | Some cond -> preturn (OprCond cond)
      | None -> fail $"'{name}' is not a condition"

  /// The operands only one family takes, and that would read as something else
  /// anywhere else: a barrier option, an endianness, the interrupt flags, and
  /// the condition an IT instruction names.
  let pOpcodeSpecificOperand opcode =
    match opcode with
    | Opcode.DMB | Opcode.DSB | Opcode.ISB -> pOprBarrierOption
    | Opcode.SETEND -> pOprEndian
    | Opcode.CPS | Opcode.CPSIE | Opcode.CPSID -> pOprIflag
    | opcode when isITInstruction opcode -> pOprCondition
    | _ -> fail "not an operand of this instruction"

  let pOprLabel = pIdentifier |>> GoToLabel

  let pOperand opcode =
    attempt (pOpcodeSpecificOperand opcode)
    <|> attempt pOprShift
    <|> (if isStructureAccess opcode then attempt pAlignedMemory
         else attempt pOprMemory)
    <|> attempt (pOprRegisterList opcode)
    <|> attempt pOprImm
    <|> attempt pOprRegister
    <|> attempt pOprAddress
    <|> pOprLabel

  /// Reads the operands of an already-parsed opcode. Which operands an
  /// instruction takes depends on which one it is, so the opcode has to be
  /// known before they can be read.
  let pOperands (opcode, cond, qualifier, dataTypes) =
    sepBy (pOperand opcode) operandSeps |>> extractOperands
    |>> (fun operands -> opcode, cond, qualifier, dataTypes, operands)
    |> skipWhitespaces

  let pMnemonic =
    many1Satisfy (fun c -> Char.IsLetterOrDigit c || c = '.')
    >>= fun token ->
      match decomposeMnemonic token with
      | Some parts -> preturn parts
      | None -> fail $"'{token}' is not an instruction"

  /// Clears the marks a register may carry, which are read once the operands
  /// they sit on have been.
  let resetMarks =
    preturn () |>> fun _ ->
      writeBack <- false
      caret <- false

  let pInsInfo =
    resetMarks >>. (pMnemonic >>= pOperands)
    |>> fun (opcode, cond, qualifier, dataTypes, operands) ->
      let marks = writeBack, caret
      let ins = newInfo opcode cond qualifier dataTypes operands marks
      { ins with IsThumb = inThumbMode }

  /// A directive that says which instruction set the lines after it belong to,
  /// so that one source may hold both.
  let pModeDirective =
    pchar '.' >>. (pstringCI "arm" <|> pstringCI "thumb")
    |>> fun name -> inThumbMode <- name.ToLowerInvariant() = "thumb"

  let pInstructionLine = pInsInfo .>> incrementIndex |>> InstructionLine

  /// A line holds a label definition, an instruction, both, or neither. A
  /// label takes the index the next instruction will get, so that one written
  /// on a line of its own marks the instruction below it.
  let statement =
    whitespace
    >>. ((attempt (pLabelDef .>> whitespace)
      >>. (pInstructionLine <|> preturn LabelDefLine))
     <|> (pModeDirective |>> fun _ -> LabelDefLine)
     <|> pInstructionLine
     <|> preturn LabelDefLine)
    .>> restOfLine

  let statements = sepEndBy statement terminator .>> (eof <?> "")

  interface ILowerable with
    override _.Lower assembly =
      (* A source that fails to parse can leave these set, because what clears
         them runs at the start of an instruction that was never reached. An
         assembler is meant to be reused, so the state has to start clean here
         rather than only end clean there. *)
      writeBack <- false
      caret <- false
      inThumbMode <- isThumb
      let st = { LabelMap = Map.empty; CurIndex = 0 }
      match runParserOnString statements st "" assembly with
      | Success(result, us, _) ->
        filterInstructionLines result
        |> assemble armEncoders thumbEncoders us isa.Endian baseAddr
        |> List.map (fun (isThumb, bytes) ->
          (if isThumb then thumbISA else armISA), bytes)
        |> Result.Ok
      | Failure(str, _, _) -> Result.Error str
