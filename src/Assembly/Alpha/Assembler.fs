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

namespace B2R2.Assembly.Alpha

open System
open FParsec
open B2R2
open B2R2.FrontEnd.Alpha
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.Alpha.ParserHelper
open B2R2.Assembly.Alpha.AsmMain

/// <namespacedoc>
///   <summary>
///   Contains Alpha-specific assembly components and types.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Represents an assembler for Alpha binaries. The syntax it reads is the one
/// B2R2's Alpha disassembler writes, so a line of disassembly can be handed
/// straight back to it.
///
/// What it encodes is the whole of the instruction set the disassembler reads:
/// the arithmetic and the logic, the shifts and the instructions reaching a
/// byte or a word inside a quadword, the multiplication, the loads and the
/// stores at every width, the branches both counted and computed, the
/// instructions ordering memory and reading the counters, the trap to PALcode,
/// and the floating-point unit in both of the formats it keeps -- each
/// floating-point instruction under every combination of trapping and rounding
/// it takes.
/// </summary>
type Assembler(isa: ISA, baseAddr: Addr) =

  /// The table-driven encoders, built here so that they are collected with the
  /// assembler instead of living for as long as the process does.
  let encoders = lazy (buildEncoderTable ())

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

  /// A comment runs to the end of its line, and is written the way an
  /// assembler for this architecture has always written one.
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
  /// of the word it was widened to rather than with a sign, so one below zero
  /// arrives here too large to read as a signed number. What is read is
  /// therefore the bits, and what they stand for is left to the operand they
  /// land in.
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

  /// A register, which an Alpha source writes bare: the general ones are
  /// numbered and the floating-point ones are the same numbers under another
  /// letter.
  let pRegister =
    pIdentifier >>= fun name ->
      match Map.tryFind (name.ToLowerInvariant()) registers with
      | Some reg -> preturn reg
      | None -> fail $"'{name}' names no register"

  /// (<base>), the way the instructions naming the memory they reach without
  /// counting a distance to it write where they reach.
  let pBase = between (pchar '(') (pchar ')') (skipWhitespaces pRegister)

  /// <summary>
  /// An operand written as a number, which is either a number on its own or
  /// the distance the memory an instruction reaches is counted by.
  ///
  /// Which of the two it is, is said by what follows it, so the number is read
  /// first and the register it may be counted from after.
  /// </summary>
  let pNumberOrMemory =
    pNumber >>= fun value ->
      (attempt (whitespace >>. pBase) |>> fun reg -> AsmMem(reg, value))
      <|> preturn (AsmImm value)

  /// An operand written as a name, which is either a register or the name of a
  /// place.
  let pNamed =
    pIdentifier |>> fun name ->
      match Map.tryFind (name.ToLowerInvariant()) registers with
      | Some reg -> AsmReg reg
      | None -> AsmLabel name

  let pOperand = (pBase |>> AsmBase) <|> pNumberOrMemory <|> pNamed

  let pOperandList =
    pOperand .>>. many (attempt (skipWhitespaces (pchar ',') >>. pOperand))
    |>> fun (first, rest) -> first :: rest

  let pOperands = attempt (whitespace1 >>. pOperandList) <|> preturn []

  /// <summary>
  /// The name of an instruction, together with whatever qualifier it carries.
  ///
  /// A qualifier is written glued to the name with a slash rather than beside
  /// it, because how an instruction rounds and what it traps on are part of
  /// which instruction it is, so the whole of it is read as one word and looked
  /// up as one.
  /// </summary>
  let pMnemonic =
    many1Satisfy (fun c -> Char.IsLetterOrDigit c || c = '_' || c = '/')
    |>> fun token -> token.ToLowerInvariant()

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
        |> assemble encoders us isa.Endian baseAddr
        |> List.map (fun bytes -> isa, bytes)
        |> Result.Ok
      | Failure(str, _, _) ->
        Result.Error str

// vim: set tw=80 sts=2 sw=2:
