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

namespace B2R2.Assembly.S390

open System
open FParsec
open B2R2
open B2R2.FrontEnd.S390
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.S390.ParserHelper
open B2R2.Assembly.S390.AsmMain

/// <namespacedoc>
///   <summary>
///   Contains S390-specific assembly components and types.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Represents an assembler for S390 binaries. The syntax it reads is the one
/// B2R2's S390 disassembler writes, so a line of disassembly can be handed
/// straight back to it.
///
/// What it encodes is the whole of the instruction set the disassembler reads,
/// across every one of the formats the architecture holds: the two-, four-, and
/// six-byte instructions alike, the arithmetic and the logic on words,
/// halfwords, and doublewords, the loads and the stores at both lengths of
/// displacement, the branches on a condition and the branches counting down,
/// the decimal instructions and the ones moving a run of storage about, what a
/// program says to the machine it runs on, the floating-point unit in its
/// hexadecimal, binary, and decimal forms, and the vector facility.
///
/// A 32-bit target runs ESA/390, which knows nothing of what z/Architecture
/// added, so this refuses to write for one an instruction it could not read
/// back.
/// </summary>
type Assembler(isa: ISA, baseAddr: Addr) =

  /// The table-driven encodings, built here so that they are collected with the
  /// assembler instead of living for as long as the process does.
  let table = lazy (AsmOpcode.buildTable ())

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

  /// A comment runs to the end of its line. The disassembler writes none of
  /// its own except the one saying where a branch ends up, which is read as
  /// part of the operand naming that place rather than as a comment, because
  /// one instruction writes an operand after it.
  let comment = pchar '#' >>. manySatisfy (fun c -> c <> '\n')

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

  /// <summary>
  /// The bits a written number stands for.
  ///
  /// The disassembler writes a number the encoding reads as signed as the bits
  /// it lands in once widened rather than with a sign, so one below zero
  /// arrives here too large to read as a signed number. What is read is
  /// therefore the bits, and what they stand for is left to the field they land
  /// in.
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
    if negative then uint64 -(int64 value) else value

  let pNumber =
    numberLiteral numberFormat "number" |>> fun n -> valueOf n.String

  /// A set of bits selecting what an instruction does, which the disassembler
  /// writes out one bit at a time between quotes.
  let pMask =
    pstringCI "b'" >>. many1Satisfy (fun c -> c = '0' || c = '1')
    .>> pchar '\''
    >>= fun bits ->
      if bits.Length > 16 then fail "a mask holds sixteen bits at most"
      else preturn (AsmMask(Convert.ToUInt16(bits, 2)))

  let pRegister =
    pIdentifier >>= fun name ->
      match Map.tryFind (name.ToUpperInvariant()) registers with
      | Some reg -> preturn reg
      | None -> fail $"'{name}' names no register"

  /// What is written where a register added to the base one would be, which is
  /// either such a register or how many bytes of storage are touched.
  let pInner =
    attempt (pNumber |>> Choice2Of2) <|> (pRegister |>> Choice1Of2)

  /// <summary>
  /// The rest of an address, once the number counted off the base register has
  /// been read.
  ///
  /// Every instruction reaching storage names the register that storage is
  /// counted off between parentheses, either on its own, with a register added
  /// to it before it, or with how many bytes are touched written there instead.
  /// </summary>
  let pAddress disp =
    between (pchar '(') (pchar ')')
      (skipWhitespaces pInner
       .>>. opt (pchar ',' >>. skipWhitespaces pRegister))
    >>= fun (first, second) ->
      match first, second with
      | Choice1Of2 idx, Some bse -> preturn (AsmMem(Some idx, bse, disp))
      | Choice1Of2 bse, None -> preturn (AsmMem(None, bse, disp))
      | Choice2Of2 len, Some bse -> preturn (AsmMemLen(uint16 len, bse, disp))
      | Choice2Of2 _, None -> fail "storage is counted off a register"

  /// An operand beginning with a number, which is either the whole of it or the
  /// number an address is counted off its base register by.
  let pNumbered =
    pNumber >>= fun value -> pAddress value <|> preturn (AsmImm value)

  /// An operand written as a name, which is a register where one is known by
  /// that name and the name of a place where none is.
  let pNamed =
    pIdentifier |>> fun name ->
      match Map.tryFind (name.ToUpperInvariant()) registers with
      | Some reg -> AsmReg reg
      | None -> AsmLabel name

  /// What the disassembler writes after an instruction naming a place, which
  /// says over again where that place ends up and so is passed over here.
  let pTarget = whitespace >>. pchar ';' >>. whitespace >>. pNumber

  let pOperand =
    (attempt pMask <|> pNumbered <|> pNamed) .>> optional (attempt pTarget)

  let operandSep = attempt (whitespace >>. pchar ',' >>. whitespace |>> ignore)

  let pOperandList =
    pOperand .>>. many (attempt (operandSep >>. pOperand))
    |>> fun (first, rest) -> first :: rest

  let pOperands = attempt (whitespace1 >>. pOperandList) <|> preturn []

  let pMnemonic =
    many1Satisfy Char.IsLetterOrDigit |>> fun name -> name.ToLowerInvariant()

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
        |> assemble table us isa.WordSize baseAddr
        |> List.map (fun bytes -> isa, bytes)
        |> Result.Ok
      | Failure(str, _, _) ->
        Result.Error str

// vim: set tw=80 sts=2 sw=2:
