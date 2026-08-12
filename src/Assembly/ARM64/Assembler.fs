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

namespace B2R2.Assembly.ARM64

open System
open FParsec
open B2R2
open B2R2.FrontEnd.ARM64
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.ARM64.ParserHelper
open B2R2.Assembly.ARM64.AsmMain

/// <namespacedoc>
///   <summary>
///   Contains ARM64-specific assembly components and types.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Represents an assembler for ARM64 binaries. The syntax it reads is the one
/// B2R2's ARM64 disassembler writes, so a line of disassembly can be handed
/// straight back to it.
///
/// What it encodes is the whole of the A64 instruction set the disassembler
/// reads: the instructions that take an immediate, the branches together with
/// the exception and system space, the loads and stores, the instructions on
/// general registers, the arithmetic on whole vectors, and the arithmetic on
/// one element of a vector and on the floating-point registers.
/// </summary>
type Assembler(isa: ISA, baseAddr: Addr) =

  /// The table-driven encoders, built here so that they are collected with the
  /// assembler instead of living for as long as the process does.
  let encoders = lazy (buildEncoderTable ())

  /// The label the instruction being parsed names, which is read once the
  /// operand it sits in has been.
  let mutable label = None

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

  /// <summary>
  /// The value a written number stands for.
  ///
  /// The disassembler prints a negative number as the bits it is kept in rather
  /// than with a sign, so a sixty-four bit one arrives here too large to read
  /// as a signed number; it is read unsigned and then taken for the number
  /// those bits stand for.
  /// </summary>
  let valueOf (text: string) =
    let negative = text.StartsWith "-"
    let text = if negative || text.StartsWith "+" then text[1..] else text
    let value =
      if text.StartsWith "0x" || text.StartsWith "0X" then
        Convert.ToUInt64(text[2..], 16)
      elif text.StartsWith "0b" || text.StartsWith "0B" then
        Convert.ToUInt64(text[2..], 2)
      elif text.StartsWith "0o" || text.StartsWith "0O" then
        Convert.ToUInt64(text[2..], 8)
      else
        UInt64.Parse text
    if negative then -(int64 value) else int64 value

  let pNumber =
    numberLiteral numberFormat "number" |>> fun n -> valueOf n.String

  /// An identifier as a name to look something up by, which is case-insensitive
  /// wherever the vocabulary is the assembler's own rather than the source's.
  let pName = pIdentifier |>> fun name -> name.ToLowerInvariant()

  let pRegisterName =
    pName >>= fun name ->
      match Map.tryFind name registers with
      | Some reg -> preturn reg
      | None -> fail $"'{name}' is not a register"

  /// Whether a register names one of the SIMD and floating-point registers by
  /// the width it is read at, which is written as an operand of its own kind.
  let isScalarRegister reg =
    int reg >= int Register.B0 && int reg <= int Register.Q31

  let toRegisterOperand reg =
    if isScalarRegister reg then OprSIMD(ScalarReg reg) else OprRegister reg

  /// The arrangement written after a vector register, which says how wide one
  /// element of it is and how many of them it holds.
  let pArrangement =
    pchar '.' >>. pName >>= fun name ->
      match Map.tryFind name vectorArrangements with
      | Some vec -> preturn vec
      | None -> fail $"'{name}' is not an arrangement"

  /// The element index a vector register may carry.
  let pElementIndex = between (pchar '[') (pchar ']') puint8

  let toVectorRegister reg vec = function
    | Some index -> VecRegWithIdx(reg, vec, index)
    | None -> VecReg(reg, vec)

  /// A vector register together with the arrangement it is read in.
  let pVectorRegister = pRegisterName .>>. pArrangement

  /// A register, which a vector one follows with the arrangement it is read in
  /// and, where it names one element, with which element that is.
  let pOprRegister =
    pName >>= fun name ->
      match Map.tryFind name registers with
      | None ->
        fail $"'{name}' is not a register"
      | Some reg ->
        (pArrangement .>>. opt pElementIndex
         |>> fun (vec, index) -> OprSIMD(toVectorRegister reg vec index))
        <|> preturn (toRegisterOperand reg)

  /// The run of registers that starts at the given one and holds as many as
  /// asked for, wrapping round after the last register there is.
  let runOfRegisters first count =
    let first = int first - int Register.V0
    [ for i in 0 .. count - 1 ->
        let number = int Register.V0 + (first + i) % 32
        LanguagePrimitives.EnumOfValue<int, Register> number ]

  /// The registers a braced list names, which is written either as each of them
  /// in turn or, where the list is longest, as the first and the last with a
  /// dash between them.
  let expandList (first, vec) rest =
    match rest with
    | [ ('-', (last, _)) ] ->
      let count = (int last - int first + 32) % 32 + 1
      runOfRegisters first count |> List.map (fun reg -> reg, vec)
    | rest ->
      (first, vec) :: List.map snd rest

  let pListSeparator = skipWhitespaces (anyOf ",-")

  let pListElements =
    skipWhitespaces pVectorRegister
    .>>. many (pListSeparator .>>. skipWhitespaces pVectorRegister)

  /// {<registers>}{[<index>]}, the list of vector registers a structure access
  /// names.
  let pOprSIMDList =
    between (pchar '{') (pchar '}') pListElements .>>. opt pElementIndex
    |>> fun ((first, rest), index) ->
      expandList first rest
      |> List.map (fun (reg, vec) -> toVectorRegister reg vec index)
      |> OprSIMDList

  let pShiftName =
    pName >>= fun name ->
      match Map.tryFind name shiftOps with
      | Some shift -> preturn shift
      | None -> fail $"'{name}' is not a shift"

  let pExtendName =
    pName >>= fun name ->
      match Map.tryFind name extendTypes with
      | Some ext -> preturn ext
      | None -> fail $"'{name}' is not an extension"

  let pAmount = pchar '#' >>. pNumber

  /// <shift> #<amount>, which shifts what was written before it.
  let pOprShift =
    pShiftName .>> whitespace .>>. opt pAmount
    |>> fun (shift, amount) -> OprShift(shift, Imm(defaultArg amount 0L))

  /// <extend> {#<amount>}, which reads a part of what was written before it and
  /// may shift what it read.
  let pOprExtend =
    pExtendName .>> whitespace .>>. opt pAmount
    |>> fun (ext, amount) -> OprExtReg(Some(ExtRegOffset(ext, amount)))

  /// The shift or extension a register offset carries, which is written inside
  /// the brackets rather than after them.
  let pOffsetShift =
    attempt (pShiftName .>> whitespace .>>. opt pAmount
             |>> fun (shift, amount) ->
                   ShiftOffset(shift, Imm(defaultArg amount 0L)))
    <|> (pExtendName .>> whitespace .>>. opt pAmount
         |>> fun (ext, amount) -> ExtRegOffset(ext, amount))

  /// What may sit inside the brackets after the base register: a byte count, or
  /// a register read as itself or as a part of itself.
  let pInnerOffset =
    (pchar '#' >>. pNumber |>> Choice1Of2)
    <|> (pRegisterName .>>. opt (attempt (skipWhitespaces (pchar ',')
                                          >>. pOffsetShift))
         |>> Choice2Of2)

  /// What may follow the closing bracket, which is how the forms that keep the
  /// sum after reading are written.
  let pPostOffset =
    (pchar '#' >>. pNumber |>> Choice1Of2)
    <|> (pRegisterName |>> fun reg -> Choice2Of2(reg, None))

  let toOffset rn = function
    | Choice1Of2 imm -> ImmOffset(BaseOffset(rn, Some imm))
    | Choice2Of2(rm, shift) -> RegOffset(rn, rm, shift)

  let toAddressingMode rn inner bang post =
    match inner, bang, post with
    | Some offset, None, None -> Some(BaseMode(toOffset rn offset))
    | Some offset, Some _, None -> Some(PreIdxMode(toOffset rn offset))
    | None, None, None -> Some(BaseMode(ImmOffset(BaseOffset(rn, None))))
    | None, Some _, None -> Some(PreIdxMode(ImmOffset(BaseOffset(rn, None))))
    | None, None, Some offset -> Some(PostIdxMode(toOffset rn offset))
    | _ -> None

  /// [<Xn|SP>{, <offset>}]{!} and [<Xn|SP>], <offset>, which differ only in
  /// where the bracket closes and in what follows it.
  let pOprMemory =
    pchar '[' >>. skipWhitespaces pRegisterName
    .>>. opt (operandSeps >>. pInnerOffset) .>> pchar ']' .>>. opt (pchar '!')
    .>>. opt (attempt (operandSeps >>. pPostOffset))
    >>= fun (((rn, inner), bang), post) ->
      match toAddressingMode rn inner bang post with
      | Some mode -> preturn (OprMemory mode)
      | None -> fail "an offset cannot sit both inside and after the brackets"

  /// A number with a fraction, which is how the immediate of a floating-point
  /// move is written: what it names is a value rather than a bit pattern.
  let pFraction =
    numberLiteral
      (NumberLiteralOptions.AllowFraction
       ||| NumberLiteralOptions.AllowMinusSign) "number"
    >>= fun n ->
      if n.IsInteger then fail "not a fraction" else preturn (float n.String)

  let pOprImm =
    attempt (pchar '#' >>. pFraction |>> OprFPImm)
    <|> (pchar '#' >>. pNumber |>> OprImm)

  /// A place, which the disassembler writes as the address it resolved rather
  /// than as an offset from anywhere.
  let pOprAddress = pNumber |>> (Lbl >> ImmOffset >> LiteralMode >> OprMemory)

  let noteLabel lbl =
    label <- Some lbl
    OprMemory(LiteralMode(ImmOffset(Lbl 0L)))

  let pOprLabel = pIdentifier |>> noteLabel

  let pOprBarrier =
    pName >>= fun name ->
      match Map.tryFind name barrierOptions with
      | Some option -> preturn (OprOption option)
      | None -> fail $"'{name}' is not a barrier option"

  let pOprPrefetch =
    pName >>= fun name ->
      match Map.tryFind name prefetchOperations with
      | Some operation -> preturn (OprPrfOp operation)
      | None -> fail $"'{name}' is not a prefetch"

  let pOprPstate =
    pName >>= fun name ->
      match Map.tryFind name pstates with
      | Some state -> preturn (OprPstate state)
      | None -> fail $"'{name}' is not a part of the processor state"

  let pOprCondition =
    pName >>= fun name ->
      match Map.tryFind name conditions with
      | Some cond -> preturn (OprCond cond)
      | None -> fail $"'{name}' is not a condition"

  /// Whether the instruction takes a condition as its last operand, which is
  /// how the ones that are not branches say what they run under.
  let takesCondition opcode =
    match opcode with
    | Opcode.CSEL | Opcode.CSINC | Opcode.CSINV | Opcode.CSNEG
    | Opcode.CINC | Opcode.CINV | Opcode.CNEG | Opcode.CSET | Opcode.CSETM
    | Opcode.CCMP | Opcode.CCMN
    | Opcode.FCSEL | Opcode.FCCMP | Opcode.FCCMPE -> true
    | _ -> false

  /// The operands only one family takes, and that would read as something else
  /// anywhere else: a barrier's option, what to prefetch, a part of the
  /// processor state, and the condition an instruction runs under.
  let pOpcodeSpecificOperand opcode =
    match opcode with
    | Opcode.DMB | Opcode.DSB | Opcode.ISB -> pOprBarrier
    | Opcode.PRFM | Opcode.PRFUM -> pOprPrefetch
    | Opcode.MSR -> pOprPstate
    | opcode when takesCondition opcode -> pOprCondition
    | _ -> fail "not an operand of this instruction"

  /// <summary>
  /// The condition that was not written, which stands for the one that always
  /// holds: the disassembler prints that one as nothing at all, so a line it
  /// wrote ends with the comma that would have come before it.
  /// </summary>
  let pOmittedCondition opcode =
    if takesCondition opcode then preturn (OprCond AL)
    else fail "not an operand of this instruction"

  let pOperand opcode =
    attempt (pOpcodeSpecificOperand opcode)
    <|> attempt pOprMemory
    <|> attempt pOprSIMDList
    <|> attempt pOprImm
    <|> attempt pOprShift
    <|> attempt pOprExtend
    <|> attempt pOprRegister
    <|> attempt pOprAddress
    <|> attempt pOprLabel
    <|> pOmittedCondition opcode

  /// Reads the operands of an already-parsed opcode. Which operands an
  /// instruction takes depends on which one it is, so the opcode has to be
  /// known before they can be read.
  let pOperands opcode =
    sepBy (pOperand opcode) operandSeps |>> extractOperands
    |>> (fun operands -> opcode, operands)
    |> skipWhitespaces

  let pMnemonic =
    many1Satisfy Char.IsLetterOrDigit
    >>= fun token ->
      match Map.tryFind (token.ToLowerInvariant()) opcodes with
      | Some opcode -> preturn opcode
      | None -> fail $"'{token}' is not an instruction"

  /// Clears the label a line may name, which is read once the operand it sits
  /// in has been.
  let resetLabel = preturn () |>> fun _ -> label <- None

  let pInsInfo =
    resetLabel >>. (pMnemonic >>= pOperands)
    |>> fun (opcode, operands) -> newInfo opcode operands label

  let pInstructionLine = pInsInfo .>> incrementIndex |>> InstructionLine

  /// A line holds a label definition, an instruction, both, or neither. A
  /// label takes the index the next instruction will get, so that one written
  /// on a line of its own marks the instruction below it.
  let statement =
    whitespace
    >>. ((attempt (pLabelDef .>> whitespace)
      >>. (pInstructionLine <|> preturn LabelDefLine))
     <|> pInstructionLine
     <|> preturn LabelDefLine)
    .>> restOfLine

  let statements = sepEndBy statement terminator .>> (eof <?> "")

  interface ILowerable with
    override _.Lower assembly =
      (* A source that fails to parse can leave this set, because what clears
         it runs at the start of an instruction that was never reached. An
         assembler is meant to be reused, so the state has to start clean here
         rather than only end clean there. *)
      label <- None
      let st = { LabelMap = Map.empty; CurIndex = 0 }
      match runParserOnString statements st "" assembly with
      | Success(result, us, _) ->
        filterInstructionLines result
        |> assemble encoders us isa.Endian baseAddr
        |> List.map (fun bytes -> isa, bytes)
        |> Result.Ok
      | Failure(str, _, _) ->
        Result.Error str
