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

namespace B2R2.Assembly.M68K

open System
open FParsec
open B2R2
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.M68K.ParserHelper
open B2R2.Assembly.M68K.AsmMain

/// <namespacedoc>
///   <summary>
///   Contains m68k-specific assembly components and types.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Represents an assembler for m68k binaries. The syntax it reads is the one
/// B2R2's m68k disassembler writes, so a line of disassembly can be handed
/// straight back to it.
///
/// What it encodes is the whole of the instruction set the disassembler reads:
/// the integer and the supervisor instruction sets of the 68000 through the
/// 68060, the floating-point unit in every format it converts between and every
/// precision it rounds to, and the cache, translation, and block move
/// instructions the 68040 added, each of them through every one of the
/// addressing modes it may name.
///
/// The family shares one encoding space and every model both added to it and
/// dropped from it, so this refuses to write for one an instruction it could
/// not read back -- an addressing mode as much as an instruction, the earlier
/// models leaving undecoded the bits that say which of the indexed modes is
/// meant.
/// </summary>
type Assembler(isa: ISA, baseAddr: Addr) =

  /// The table-driven encodings, built here so that they are collected with the
  /// assembler instead of living for as long as the process does.
  let table = lazy (buildTable ())

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

  let whitespace1 = many1Satisfy isWhitespace

  let skipWhitespaces s = whitespace >>? s .>>? whitespace

  /// A comment runs to the end of its line. The mark an immediate operand
  /// carries is the one this architecture writes numbers with, so the marks a
  /// comment may begin with are the two an assembler for it conventionally
  /// takes.
  let comment = anyOf ";|" >>. manySatisfy (fun c -> c <> '\n')

  /// Whatever may sit between the end of a statement and the end of its line.
  let restOfLine = whitespace >>. optional comment

  let terminator = newline |>> ignore <?> ""

  let isIdentifierChar c = Char.IsLetterOrDigit c || c = '_'

  let pIdentifier = many1Satisfy isIdentifierChar

  let pLabelDef = pIdentifier .>>? pchar ':' >>= addLabeldef <?> "label"

  let numberFormat =
    NumberLiteralOptions.AllowBinary
    ||| NumberLiteralOptions.AllowOctal
    ||| NumberLiteralOptions.AllowHexadecimal
    ||| NumberLiteralOptions.AllowMinusSign
    ||| NumberLiteralOptions.AllowPlusSign

  /// The digits of a number written in hexadecimal, or nothing where it was
  /// not.
  let hexDigits (text: string) =
    let isHex = text.StartsWith "0x" || text.StartsWith "0X"
    if isHex then Some text[2..] else None

  /// The bytes a run of hexadecimal digits holds, the first of them first.
  let bytesOfHex (digits: string) =
    let digits = if digits.Length % 2 = 0 then digits else "0" + digits
    [| for i in 0 .. 2 .. digits.Length - 2 ->
         Convert.ToByte(digits.Substring(i, 2), 16) |]

  /// <summary>
  /// What a written number stands for: the integer it is, or the bytes it holds
  /// where it is too wide for an integer.
  ///
  /// The disassembler writes a number that the encoding reads as unsigned as
  /// the bits it holds, and one it reads as signed with a sign, so both are
  /// read here and the field they land in decides which of them fits. A real
  /// format wider than a long word is written as the bits themselves, there
  /// being no integer wide enough to hold the widest of them.
  /// </summary>
  let numberOf (text: string) =
    let negative = text.StartsWith "-"
    let body = if negative || text.StartsWith "+" then text[1..] else text
    match hexDigits body with
    | Some digits when digits.Length > 16 && not negative ->
      Choice2Of2(bytesOfHex digits)
    | Some digits ->
      let value = Convert.ToUInt64(digits, 16)
      Choice1Of2(if negative then -(int64 value) else int64 value)
    | None ->
      let value =
        if body.StartsWith "0b" || body.StartsWith "0B" then
          Convert.ToUInt64(body[2..], 2)
        elif body.StartsWith "0o" || body.StartsWith "0O" then
          Convert.ToUInt64(body[2..], 8)
        else
          UInt64.Parse body
      Choice1Of2(if negative then -(int64 value) else int64 value)

  let pNumber =
    numberLiteral numberFormat "number" |>> fun n -> numberOf n.String

  /// A written number that an integer holds, which is every one but the bits of
  /// a real format too wide for one.
  let pInt =
    pNumber
    >>= (function
      | Choice1Of2 value -> preturn value
      | Choice2Of2 _ -> fail "this number is too wide to be written here")

  let pRegister =
    pIdentifier
    >>= fun name ->
      match Map.tryFind (name.ToLowerInvariant()) registers with
      | Some reg -> preturn reg
      | None -> fail $"'{name}' names no register"

  /// One of the parts an address is written out of: the distance counted off
  /// whatever the address is built on, the base register, or the index register
  /// together with the width it is read at and the factor it is scaled by.
  let pMemPart =
    (pInt |>> PartDisp)
    <|> (pRegister
         .>>. opt (pchar '.' >>. anyOf "wlWL" .>>. opt (pchar '*' >>. pint32))
         |>> fun (reg, index) ->
           match index with
           | None ->
             PartBase reg
           | Some(width, scale) ->
             PartIndex
               { Reg = reg
                 IsLong = width = 'l' || width = 'L'
                 Scale = defaultArg scale 1 })

  let pMemParts = sepBy (skipWhitespaces pMemPart) (pchar ',')

  /// An address written between parentheses, which is every mode but the one
  /// reaching through memory and the two that move the register they name.
  let pPlain = between (pchar '(') (pchar ')') pMemParts |>> plainAddress

  /// An address written with brackets inside the parentheses, which is one of
  /// the modes reaching through memory.
  let pIndirect =
    pstring "([" >>. pMemParts .>> pchar ']'
    .>>. many (pchar ',' >>. skipWhitespaces pMemPart)
    .>> pchar ')'
    |>> fun (inner, outer) -> indirectAddress inner outer

  /// An address written between parentheses, together with the mark saying that
  /// the register it names moves on past what was read.
  let pPlainOrPostInc =
    pPlain .>>. opt (pchar '+')
    >>= fun (mem, moved) ->
      match mem, moved with
      | _, None -> preturn mem
      | AsmDirect reg, Some _ -> preturn (AsmPostInc reg)
      | _, Some _ -> fail "only a register moves on past what was read"

  /// Every way of naming memory, of which the one that moves the register back
  /// before anything is written is the only one written outside the
  /// parentheses.
  let pMemory =
    (pstring "-(" >>. skipWhitespaces pRegister .>> pchar ')' |>> AsmPreDec)
    <|> attempt pIndirect
    <|> pPlainOrPostInc

  /// The memory an instruction reaches, or the pair of places that a compare
  /// and swap of two of them reaches.
  let pMemOperand =
    pMemory .>>. opt (pchar ':' >>. pMemory)
    >>= fun (first, second) ->
      match first, second with
      | _, None -> preturn (AsmMem first)
      | AsmDirect one, Some(AsmDirect other) -> preturn (AsmMemPair(one, other))
      | _, Some _ -> fail "a pair of places is written as two registers"

  /// An address written with the distance in front of the parentheses, which is
  /// how the manual writes one and how a person does, rather than inside them,
  /// which is how the disassembler writes one.
  let pOffsetMem value =
    between (pchar '(') (pchar ')') pMemParts
    |>> fun parts -> AsmMem(plainAddress (PartDisp value :: parts))

  /// <summary>
  /// An operand that begins with a number, which is one of three things: the
  /// distance an address is counted off by, where parentheses follow it; how
  /// far away a place is, where a sign was written in front of it, that being
  /// how the disassembler writes such a distance; and an address, where
  /// neither.
  /// </summary>
  let pNumbered =
    numberLiteral numberFormat "number"
    >>= fun n ->
      let signed = n.String.StartsWith "+" || n.String.StartsWith "-"
      match numberOf n.String with
      | Choice2Of2 _ ->
        fail "this number is too wide to be written here"
      | Choice1Of2 value ->
        attempt (pOffsetMem value)
        <|> preturn (if signed then AsmRel value else AsmAddr(uint64 value))

  /// A run of registers, written as the first and the last of it with a dash
  /// between them, or as one register on its own.
  let pRegRun =
    pRegister .>>. opt (attempt (pchar '-' >>. pRegister))
    |>> fun (first, last) ->
      match last with
      | None -> [ first ]
      | Some last -> runTo first last

  /// A list of registers, whose runs a slash separates.
  let pRegList =
    pRegRun .>>. many (attempt (pchar '/' >>. pRegRun))
    |>> fun (first, rest) -> List.concat (first :: rest)

  /// One or more registers, which is a list where several of them are written,
  /// a pair where a colon separates two, and one register where it is one
  /// alone.
  let pRegisters =
    pRegList .>>. opt (attempt (pchar ':' >>. pRegister))
    >>= fun (regs, other) ->
      match regs, other with
      | [ one ], Some other -> preturn (AsmRegPair(one, other))
      | _, Some _ -> fail "a pair of registers is written as two of them"
      | [ one ], None -> preturn (AsmReg one)
      | _, None -> preturn (AsmRegList regs)

  /// An operand written as a name that no register goes by, which is the caches
  /// an instruction of the 68040 names or the name of a place.
  let pNamed =
    pIdentifier
    |>> fun name ->
      match Map.tryFind (name.ToLowerInvariant()) caches with
      | Some which -> AsmCaches which
      | None -> AsmLabel name

  /// A number written with the mark an instruction computing from one puts in
  /// front of it.
  let pImmediate =
    pchar '#' >>. pNumber
    |>> function
      | Choice1Of2 value -> AsmImm value
      | Choice2Of2 bytes -> AsmWideImm bytes

  /// What the disassembler writes after an instruction naming a place, which
  /// says over again where that place ends up and so is passed over here.
  let pTargetNote = whitespace >>. pchar ';' >>. whitespace >>. pNumber

  /// The offset or the width of a bit field, either of which a data register
  /// can supply in place of a written number. Neither carries the mark an
  /// immediate operand does, there being nothing else either of them could be.
  let pFieldPart = (pInt |>> AsmImm) <|> (pRegister |>> AsmReg)

  /// The bit field that a BFxxx instruction names within the operand it
  /// follows.
  let pBitField =
    between (pchar '{')
      (pchar '}')
      (skipWhitespaces pFieldPart .>> pchar ':' .>>. skipWhitespaces pFieldPart)

  let pOperand =
    (pImmediate
     <|> pMemOperand
     <|> attempt pNumbered
     <|> attempt pRegisters
     <|> pNamed)
    .>>. opt pBitField
    .>> optional (attempt pTargetNote)
    |>> fun (core, field) ->
      match field with
      | None -> core
      | Some(offset, width) -> AsmBitField(core, offset, width)

  let operandSep = attempt (whitespace >>. pchar ',' >>. whitespace |>> ignore)

  let pOperandList =
    pOperand .>>. many (attempt (operandSep >>. pOperand))
    |>> fun (first, rest) -> first :: rest

  let pOperands = attempt (whitespace1 >>. pOperandList) <|> preturn []

  /// The name of an instruction, which says at its end how wide the operation
  /// is, that being a thing an m68k mnemonic names separately from the
  /// operation itself.
  let pMnemonic = many1Satisfy (fun c -> Char.IsLetterOrDigit c || c = '.')

  let pInstructionLine =
    pMnemonic >>= fun name ->
      pOperands |>> (newInfo name >> InstructionLine)
    .>> incrementIndex

  /// A line holds a label definition, an instruction, both, or neither. A label
  /// takes the index the next instruction will get, so that one written on a
  /// line of its own marks the instruction below it.
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
      let st = { LabelMap = Map.empty; CurIndex = 0 }
      match runParserOnString statements st "" assembly with
      | Success(result, us, _) ->
        filterInstructionLines result
        |> assemble table us isa.M68KModel baseAddr
        |> List.map (fun bytes -> isa, bytes)
        |> Result.Ok
      | Failure(str, _, _) ->
        Result.Error str

// vim: set tw=80 sts=2 sw=2:
