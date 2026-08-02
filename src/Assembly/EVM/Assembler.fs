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

namespace B2R2.Assembly.EVM

open System
open System.Globalization
open System.Numerics
open FParsec
open B2R2
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.EVM.ParserHelper
open B2R2.Assembly.EVM.AsmMain

/// <namespacedoc>
///   <summary>
///   Contains EVM-specific assembly components and types.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Represents an assembler for EVM bytecode. The syntax it reads is the one
/// B2R2's EVM disassembler writes, so a line of disassembly can be handed
/// straight back to it.
///
/// What it encodes is the whole of the instruction set the disassembler reads:
/// the arithmetic and the logic over the numbers the stack holds, the reads of
/// what the program was called with and of the chain it runs on, the moves to
/// and from memory and from what a contract keeps between calls, the jumps and
/// the places they land, every push there is, the reaches back into the stack,
/// the records a program files, and the calls it makes to other programs.
///
/// A source may name a place rather than write where it is. There is no
/// instruction here holding where it goes, so a name stands where a push holds
/// a number, which is how a program says where a jump is bound for: the push
/// naming the place holds the address of the instruction that place marks.
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
  /// has always written one.
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

  /// The number a run of digits comes to in the given radix.
  let inRadix radix (digits: string) =
    Seq.fold (fun acc c -> acc * radix + bigint (int c - int '0')) 0I digits

  /// <summary>
  /// The number a written one stands for.
  ///
  /// What a push holds reaches two hundred and fifty-six bits, so nothing
  /// narrower than a big integer holds every number a source may write. A
  /// number below zero is written with a sign, and what the field it lands in
  /// makes of that is left to the field.
  /// </summary>
  let valueOf (text: string) =
    let negative = text.StartsWith "-"
    let text = if negative || text.StartsWith "+" then text[1..] else text
    let value =
      if text.StartsWith "0x" || text.StartsWith "0X" then
        BigInteger.Parse("0" + text[2..], NumberStyles.HexNumber)
      elif text.StartsWith "0b" || text.StartsWith "0B" then
        inRadix 2I text[2..]
      elif text.StartsWith "0o" || text.StartsWith "0O" then
        inRadix 8I text[2..]
      else
        BigInteger.Parse text
    if negative then -value else value

  /// <summary>
  /// A number written bare.
  ///
  /// It may not run straight into a word, so that a name beginning with a digit
  /// is read as the name it is rather than as a number that stopped early.
  /// </summary>
  let pNumber =
    numberLiteral numberFormat "number"
    .>> notFollowedBy (satisfy isIdentifierChar)
    |>> fun n -> valueOf n.String

  /// Every way of writing an operand, which for this architecture is the number
  /// a push holds or the name of the place whose address it holds.
  let pOperand = attempt (pNumber |>> AsmNum) <|> (pIdentifier |>> AsmLabel)

  /// What an instruction is written with, which is one number, one name, or
  /// nothing at all: no EVM instruction names two things.
  let pOperands =
    attempt (whitespace1 >>. pOperand |>> List.singleton) <|> preturn []

  /// Whatever the name of an instruction may be spelt with. Three of them are
  /// written with a mark in the middle rather than as one word, which is what
  /// the disassembler writes and so what this has to read.
  let isMnemonicChar c = Char.IsLetterOrDigit c || c = '_' || c = '.'

  let pMnemonic = many1Satisfy isMnemonicChar

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
        |> assemble encoders us baseAddr
        |> List.map (fun bytes -> isa, bytes)
        |> Result.Ok
      | Failure(str, _, _) -> Result.Error str

// vim: set tw=80 sts=2 sw=2:
