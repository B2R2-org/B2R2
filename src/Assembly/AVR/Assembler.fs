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

namespace B2R2.Assembly.AVR

open System
open FParsec
open B2R2
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.AVR.ParserHelper
open B2R2.Assembly.AVR.AsmMain

/// <namespacedoc>
///   <summary>
///   Contains AVR-specific assembly components and types.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Represents an assembler for AVR binaries. The syntax it reads is the one
/// B2R2's AVR disassembler writes, so a line of disassembly can be handed
/// straight back to it.
///
/// What it encodes is the whole of the instruction set the disassembler reads:
/// the arithmetic and the logic over registers and over written numbers, the
/// shifts and the rotations, the loads and the stores in every way they reach
/// memory, the reads of the code space, the moves to and from the peripherals,
/// the branches and the jumps, the instructions working on a single bit, and
/// what a program says to the machine it runs on.
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

  /// A comment runs to the end of its line, and is written the way an assembler
  /// for this architecture has always written one. The disassembler says in one
  /// what a written number comes to, so reading a comment is not a courtesy
  /// here but the only way to read back what it wrote.
  let comment = pchar ';' >>. manySatisfy (fun c -> c <> '\n')

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
  /// The number a written one stands for.
  ///
  /// What the disassembler writes is the field itself, which is never below
  /// zero however the instruction reads it; a source of its own writes what the
  /// instruction reads, which for the fields read as signed may be. Both are
  /// read here and the field they land in decides which of them fits.
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
    if negative then -(int32 value) else int32 value

  let pNumber =
    numberLiteral numberFormat "number" |>> fun n -> valueOf n.String

  let pRegister =
    pIdentifier >>= fun name ->
      match Map.tryFind (name.ToLowerInvariant()) registers with
      | Some reg -> preturn reg
      | None -> fail $"'{name}' names no register"

  /// <summary>
  /// An operand written without any mark in front of it.
  ///
  /// A register, the memory it names, the memory a written distance from it, or
  /// the name of a place: all four begin with a word, and what follows that
  /// word is what tells them apart. The mark saying that a register moves on
  /// past what was read through it is the same one that separates a register
  /// from the distance counted off it, so the two are read together here.
  /// </summary>
  let pIndexed =
    pIdentifier .>>. opt (pchar '+' >>. opt pNumber)
    >>= fun (name, moved) ->
      match Map.tryFind (name.ToLowerInvariant()) registers, moved with
      | Some reg, None -> preturn (AsmReg reg)
      | Some reg, Some None -> preturn (AsmPostInc reg)
      | Some reg, Some(Some value) -> preturn (AsmDisp(reg, value))
      | None, None -> preturn (AsmLabel name)
      | None, Some _ -> fail $"'{name}' names no register"

  /// Every way of writing an operand. The mark in front of a distance from
  /// where the instruction sits and the one in front of a register that moves
  /// back before anything is read are both read before a bare number is,
  /// because a number below zero begins with the latter of the two.
  let pOperand =
    (pchar '.' >>. pNumber |>> AsmRel)
    <|> attempt (pchar '-' >>. pRegister |>> AsmPreDec)
    <|> attempt (pNumber |>> AsmNum)
    <|> pIndexed

  let operandSep = whitespace >>. pchar ',' >>. whitespace |>> ignore

  let pOperandList =
    pOperand .>>. many (attempt (operandSep >>. pOperand))
    |>> fun (first, rest) -> first :: rest

  let pOperands = attempt (whitespace1 >>. pOperandList) <|> preturn []

  /// The name of an instruction, which for this architecture is one word.
  let pMnemonic = many1Satisfy Char.IsLetterOrDigit

  let pInstructionLine =
    pMnemonic >>= fun name -> pOperands |>> (newInfo name >> InstructionLine)
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
      | Failure(str, _, _) -> Result.Error str

// vim: set tw=80 sts=2 sw=2:
