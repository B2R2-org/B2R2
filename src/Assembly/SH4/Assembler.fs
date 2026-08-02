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

namespace B2R2.Assembly.SH4

open System
open FParsec
open B2R2
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.SH4.ParserHelper
open B2R2.Assembly.SH4.AsmMain

/// <namespacedoc>
///   <summary>
///   Contains SH4-specific assembly components and types.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Represents an assembler for SH4 binaries. The syntax it reads is the one
/// B2R2's SH4 disassembler writes, so a line of disassembly can be handed
/// straight back to it.
///
/// What it encodes is the whole of the instruction set the disassembler reads:
/// the arithmetic and the logic, the shifts and the rotations, the moves at all
/// three widths and in every way they reach memory, the branches, the
/// instructions moving the registers a program does not compute with, what a
/// program says to the cache and to the machine, and the floating-point unit.
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

  /// A comment runs to the end of its line, and is written the way an assembler
  /// for this architecture has always written one. The mark a person elsewhere
  /// writes a comment with is the one this architecture puts in front of a
  /// written number, so it cannot be one here.
  let comment = pchar '!' >>. manySatisfy (fun c -> c <> '\n')

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

  /// The memory at a written distance from what a register holds, which is how
  /// a source reaches a field of a structure and how it reads a number written
  /// into the instruction stream beside the code reading it.
  let pDispMem =
    skipWhitespaces pNumber .>> pchar ',' .>>. skipWhitespaces pRegister
    |>> AsmDispMem

  /// The memory at the distance another register holds, which is always the
  /// first of the general registers.
  let pIdxMem =
    skipWhitespaces pRegister .>> pchar ',' .>>. skipWhitespaces pRegister
    |>> AsmIdxMem

  /// The register the memory an instruction reaches is named by, together with
  /// the mark saying that the register moves on past what was read.
  let pIndirect =
    pRegister .>>. opt (pchar '+')
    |>> fun (reg, moved) ->
      if Option.isSome moved then AsmPostInc reg else AsmIndir reg

  /// Every way of naming memory, all of which begin with the same mark.
  let pMemory =
    pchar '@'
    >>. ((pchar '-' >>. pRegister |>> AsmPreDec)
     <|> between (pchar '(') (pchar ')') (attempt pDispMem <|> pIdxMem)
     <|> pIndirect)

  /// An operand written without any mark, which is either a register or the
  /// name of a place.
  let pBare =
    pIdentifier
    |>> fun name ->
      match Map.tryFind (name.ToLowerInvariant()) registers with
      | Some reg -> AsmReg reg
      | None -> AsmLabel name

  let pOperand =
    pMemory
    <|> (pchar '#' >>. pNumber |>> AsmImm)
    <|> (pNumber |>> AsmNum)
    <|> pBare

  let operandSep = whitespace >>. pchar ',' >>. whitespace |>> ignore

  let pOperandList =
    pOperand .>>. many (attempt (operandSep >>. pOperand))
    |>> fun (first, rest) -> first :: rest

  let pOperands = attempt (whitespace1 >>. pOperandList) <|> preturn []

  /// <summary>
  /// The name of an instruction.
  ///
  /// A name says at its end the width or the condition the instruction works
  /// on, and a person writing a source separates that from the rest with a mark
  /// the disassembler leaves out. Both are read here and the mark is dropped,
  /// so that mov.l and movl name the same instruction.
  /// </summary>
  let pMnemonic =
    many1Satisfy (fun c -> Char.IsLetterOrDigit c || c = '.' || c = '/')

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
