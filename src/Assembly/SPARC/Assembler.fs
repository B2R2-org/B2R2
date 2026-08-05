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

namespace B2R2.Assembly.SPARC

open System
open FParsec
open B2R2
open B2R2.FrontEnd.SPARC
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.SPARC.ParserHelper
open B2R2.Assembly.SPARC.AsmMain

/// <namespacedoc>
///   <summary>
///   Contains SPARC-specific assembly components and types.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Represents an assembler for SPARC binaries. The syntax it reads is the one
/// B2R2's SPARC disassembler writes, so a line of disassembly can be handed
/// straight back to it.
///
/// What it encodes is the whole of the instruction set the disassembler reads:
/// the arithmetic and the logic, the shifts, the multiplication and the
/// division, the loads and the stores in every address space, the branches and
/// the calls, the traps, the moves that happen only where something holds, what
/// a program says to the machine it runs on, and the floating-point unit at all
/// three of its widths.
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
  /// assembler for this architecture has always written one. The disassembler
  /// writes one of its own after an instruction holding a number, saying what
  /// that number is where it is not written as one.
  let comment = (pchar '!' <|> pchar '#') >>. manySatisfy (fun c -> c <> '\n')

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
  /// The disassembler writes a number the encoding reads as signed as the whole
  /// word it was widened to rather than with a sign, so one below zero arrives
  /// here too large to read as a signed number. What is read is therefore the
  /// bits, and what they stand for is left to the operand they land in.
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

  /// <summary>
  /// An operand written with the mark every register but a handful carries.
  ///
  /// A set of condition bits is written the same way, and so is the one thing
  /// that is neither: the upper part of an address, which is written as what it
  /// is taken out of rather than as itself.
  /// </summary>
  let pMarked =
    pchar '%' >>. pIdentifier >>= fun name ->
      let key = "%" + name.ToLowerInvariant()
      if key = "%hi" then
        between (pchar '(') (pchar ')') (skipWhitespaces pNumber) |>> AsmHi
      else
        match Map.tryFind key registers with
        | Some reg ->
          preturn (AsmReg reg)
        | None ->
          match Map.tryFind key conditionCodes with
          | Some cc -> preturn (AsmCC cc)
          | None -> fail $"'{key}' names nothing"

  /// An operand written without that mark, which is one of the six registers
  /// the disassembler writes bare or else the name of a place.
  let pBare =
    pIdentifier |>> fun name ->
      match Map.tryFind (name.ToLowerInvariant()) registers with
      | Some reg -> AsmReg reg
      | None -> AsmLabel name

  let pRegister =
    pMarked >>= function
      | AsmReg reg -> preturn reg
      | _ -> fail "this is not a register"

  /// What is added to the register the memory an instruction reaches is counted
  /// from, which is either a second register or a written number.
  let pIndex = (pNumber |>> AsmImm) <|> (pRegister |>> AsmReg)

  /// [<base>{ + <index>}], the way every instruction reaching memory names
  /// where it reaches.
  let pAdded = pchar '+' >>. skipWhitespaces pIndex

  let pMemory =
    between (pchar '[') (pchar ']')
      (skipWhitespaces pRegister .>>. opt pAdded)
    |>> AsmMem

  let pOperand =
    pMemory <|> pMarked <|> (pNumber |>> AsmImm) <|> pBare

  /// <summary>
  /// What stands between two operands.
  ///
  /// The disassembler writes a comma between most pairs of them, a plus sign
  /// between the two an address is built out of, and nothing at all between the
  /// memory an instruction reaches and the address space it reaches it in.
  /// </summary>
  let operandSep =
    attempt (whitespace >>. (pchar ',' <|> pchar '+') >>. whitespace |>> ignore)
    <|> (whitespace1 |>> ignore)

  let pOperandList =
    pOperand .>>. many (attempt (operandSep >>. pOperand))
    |>> fun (first, rest) -> first :: rest

  let pOperands = attempt (whitespace1 >>. pOperandList) <|> preturn []

  /// Which of the three suffixes a branch may hang off its name each one is.
  let suffixOf annul predict = function
    | "a" -> true, predict
    | "pt" -> annul, Some true
    | "pn" -> annul, Some false
    | other -> raise <| EncodingFailureException $"',{other}' says nothing"

  /// <summary>
  /// The name of an instruction, together with what a branch hangs off it.
  ///
  /// A suffix is written glued to the name with a comma rather than beside it,
  /// because it is part of what the instruction is rather than something it
  /// works on; so the whole of it is read as one word and taken apart here.
  /// </summary>
  let pMnemonic =
    many1Satisfy (fun c -> Char.IsLetterOrDigit c || c = ',')
    >>= fun token ->
      let parts = token.ToLowerInvariant().Split ','
      try
        let annul, predict =
          Array.fold (fun (a, p) s -> suffixOf a p s) (false, None) parts[1..]
        preturn (parts[0], annul, predict)
      with EncodingFailureException msg ->
        fail msg

  let pInstructionLine =
    pMnemonic >>= fun (name, annul, predict) ->
      pOperands |>> (newInfo name annul predict >> InstructionLine)
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
