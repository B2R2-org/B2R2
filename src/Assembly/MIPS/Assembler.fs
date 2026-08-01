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

namespace B2R2.Assembly.MIPS

open System
open FParsec
open B2R2
open B2R2.FrontEnd.MIPS
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.MIPS.ParserHelper
open B2R2.Assembly.MIPS.AsmMain

/// <namespacedoc>
///   <summary>
///   Contains MIPS-specific assembly components and types.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Represents an assembler for MIPS binaries. The syntax it reads is the one
/// B2R2's MIPS disassembler writes, so a line of disassembly can be handed
/// straight back to it.
///
/// What it encodes is the whole of the instruction set the disassembler reads:
/// the arithmetic and the logic on registers, the instructions that take a
/// written number, the branches and the jumps, the loads and the stores, the
/// instructions that read or write one field of a register, and the two spaces
/// of the floating-point unit. Both word sizes are read, and the two differ:
/// eight of the general registers are written by one name in a thirty-two bit
/// source and by another in a sixty-four bit one.
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

  let skipWhitespaces s = whitespace >>? s .>>? whitespace

  /// A comment runs to the end of its line, and is written the way an
  /// assembler for this architecture has always written one.
  let comment = (pchar '#' <|> pchar ';') >>. manySatisfy (fun c -> c <> '\n')

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
  /// The bits a written number stands for.
  ///
  /// The disassembler prints a number the encoding reads as signed as the bits
  /// it is kept in rather than with a sign, so one below zero arrives here too
  /// large to read as a signed number. What is read is therefore the bits, and
  /// what they stand for is left to the operand they land in.
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

  /// An identifier as a name to look something up by, which is case-insensitive
  /// wherever the vocabulary is the assembler's own rather than the source's.
  let pName = pIdentifier |>> fun name -> name.ToLowerInvariant()

  /// A register named by its number, which is how a source that writes the
  /// dollar sign may name one instead of by the name it is printed under.
  let pNumberedRegister =
    puint32 >>= fun number ->
      if number < 32u then
        preturn (LanguagePrimitives.EnumOfValue<int, Register>(int number))
      else
        fail $"'${number}' is not a register"

  /// A register, which may carry the dollar sign a source that is not the
  /// disassembler's own output writes before one.
  let pRegisterIn names =
    let named =
      pName >>= fun name ->
        match Map.tryFind name names with
        | Some reg -> preturn reg
        | None -> fail $"'{name}' is not a register"
    (pchar '$' >>. (attempt pNumberedRegister <|> named)) <|> named

  /// How far from the base register the access is, which is either a written
  /// number or a register holding one.
  let pOffsetIn names =
    attempt (pRegisterIn names |>> Reg) <|> (pNumber |>> (int64 >> Imm))

  /// {<offset>}(<base>), the only way a MIPS instruction names memory: what
  /// lies at a distance from what a register holds.
  let pOprMemory names opcode =
    opt (pOffsetIn names)
    .>>. between (pchar '(') (pchar ')') (skipWhitespaces (pRegisterIn names))
    |>> fun (offset, baseReg) ->
      let length = accessLength opcode isa.WordSize
      OpMem(baseReg, defaultArg offset (Imm 0L), length)

  let pOperand names opcode =
    attempt (pOprMemory names opcode)
    <|> attempt (pRegisterIn names |>> OpReg)
    <|> attempt (pNumber |>> OpImm)
    <|> (pIdentifier |>> GoToLabel)

  /// Which of the two vocabularies the registers of this instruction are
  /// written in, which is what the disassembler wrote them in.
  let namesFor opcode =
    if registerNaming opcode isa.WordSize = WordSize.Bit64 then registers64
    else registers32

  /// Reads the operands of an already-parsed mnemonic. Which operands an
  /// instruction takes depends on which one it is, so the opcode has to be
  /// known before they can be read.
  let pOperands (opcode, cond, fmt) =
    sepBy (pOperand (namesFor opcode) opcode) operandSeps
    .>>. getUserState
    |>> (fun (operands, us) ->
      let pc = baseAddr + uint64 (us.CurIndex * 4)
      markPlace opcode pc operands
      |> extractOperands
      |> newInfo opcode cond fmt)
    |> skipWhitespaces

  /// The name of an instruction, together with the condition and the format it
  /// hangs off that name.
  let pMnemonic =
    many1Satisfy (fun c -> Char.IsLetterOrDigit c || c = '.')
    >>= fun token ->
      match decomposeMnemonic token with
      | Some parts -> preturn parts
      | None -> fail $"'{token}' is not an instruction"

  let pInstructionLine =
    pMnemonic >>= pOperands .>> incrementIndex |>> InstructionLine

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
      let st = { LabelMap = Map.empty; CurIndex = 0 }
      match runParserOnString statements st "" assembly with
      | Success(result, us, _) ->
        filterInstructionLines result
        |> assemble encoders us isa.Endian baseAddr
        |> List.map (fun bytes -> isa, bytes)
        |> Result.Ok
      | Failure(str, _, _) -> Result.Error str
