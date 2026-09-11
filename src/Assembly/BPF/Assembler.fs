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

namespace B2R2.Assembly.BPF

open System
open FParsec
open B2R2
open B2R2.FrontEnd.BPF
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.BPF.ParserHelper
open B2R2.Assembly.BPF.AsmMain

/// <namespacedoc>
///   <summary>
///   Contains eBPF-specific assembly components and types.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Represents an assembler for eBPF binaries. The syntax it reads is the one
/// B2R2's eBPF disassembler writes, so a line of disassembly can be handed
/// straight back to it.
///
/// What it encodes is the whole of the instruction set the disassembler reads:
/// the arithmetic and the logic on the whole of a register and on its lower
/// half, the moves both plain and widening, the instructions writing a register
/// back in a given byte order, the loads and the stores at every width, the
/// atomic stores, the reads of a packet, the jumps both comparing and
/// unconditional, the calls, and the return.
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
  /// for this architecture has always written one.
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

  /// A register, which an eBPF source writes bare: they are numbered, and the
  /// one holding where this program's frame begins goes by a name of its own as
  /// well.
  let pRegister =
    pIdentifier >>= fun name ->
      match Map.tryFind (name.ToLowerInvariant()) registers with
      | Some reg -> preturn reg
      | None -> fail $"'{name}' names no register"

  /// What lies between the brackets: the register holding where to start from
  /// and how far from there to reach.
  let pReach =
    skipWhitespaces pRegister .>>. (pchar '+' >>. skipWhitespaces pNumber)

  /// [<base>+<disp>], the way an instruction reaching memory writes where it
  /// reaches.
  let pMemory = between (pchar '[') (pchar ']') pReach |>> AsmMem

  /// An operand written as a name, which is either a register or the name of a
  /// place.
  let pNamed =
    pIdentifier |>> fun name ->
      match Map.tryFind (name.ToLowerInvariant()) registers with
      | Some reg -> AsmReg reg
      | None -> AsmLabel name

  let pOperand = pMemory <|> (pNumber |>> AsmImm) <|> pNamed

  let pOperandList =
    pOperand .>>. many (attempt (skipWhitespaces (pchar ',') >>. pOperand))
    |>> fun (first, rest) -> first :: rest

  let pOperands = attempt (whitespace1 >>. pOperandList) <|> preturn []

  /// The name of an instruction, which is one word: how wide the thing it
  /// reaches is, and which of the two classes it belongs to, are part of the
  /// name rather than written beside it.
  let pMnemonic = many1Satisfy isIdentifierChar |>> _.ToLowerInvariant()

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
