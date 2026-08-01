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

namespace B2R2.Assembly.RISCV64

open System
open FParsec
open B2R2
open B2R2.FrontEnd.RISCV64
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.RISCV64.ParserHelper
open B2R2.Assembly.RISCV64.AsmMain

/// <namespacedoc>
///   <summary>
///   Contains RISCV64-specific assembly components and types.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Represents an assembler for RISCV64 binaries. The syntax it reads is the one
/// B2R2's RISCV64 disassembler writes, so a line of disassembly can be handed
/// straight back to it.
///
/// What it encodes is the whole of the instruction set the disassembler reads:
/// the arithmetic and the logic on a doubleword and on a word, the shifts, the
/// multiplication and the division, the loads and the stores, the jumps and the
/// branches, the atomic instructions, what a program says to the machine it
/// runs on, and the floating-point unit at both of its widths. A compressed
/// instruction is written under the name of the full-width one that does the
/// same thing, and that is the one encoded for it.
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
  /// The disassembler prints a number the encoding reads as signed as the whole
  /// register it lands in rather than with a sign, so one below zero arrives
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
  /// An operand written as a name.
  ///
  /// A register is one, and so is the mode a floating-point instruction rounds
  /// by; whatever is neither names a place the source defines elsewhere. The
  /// three are told apart here rather than by trying one parser after another,
  /// because all three read exactly the same characters.
  /// </summary>
  let pNamed =
    pIdentifier |>> fun name ->
      let name' = name.ToLowerInvariant()
      match Map.tryFind name' registers with
      | Some reg -> AsmReg reg
      | None ->
        match Map.tryFind name' roundModes with
        | Some mode -> AsmRound mode
        | None -> AsmLabel name

  let pRegister =
    pNamed >>= function
      | AsmReg reg -> preturn reg
      | _ -> fail "this is not a register"

  /// {<offset>}(<base>), the only way a RISCV64 instruction names memory: what
  /// lies at a distance from what a register holds. The jump to a register
  /// names where it goes the same way.
  let pMemory =
    opt pNumber
    .>>. between (pchar '(') (pchar ')') (skipWhitespaces pRegister)
    |>> fun (offset, baseReg) -> AsmMem(defaultArg offset 0UL, baseReg)

  let pOperand =
    attempt pMemory <|> attempt (pNumber |>> AsmImm) <|> pNamed

  /// <summary>
  /// Whether an atomic instruction takes the lock before what it does and gives
  /// it up after.
  ///
  /// The disassembler writes this glued to the memory the instruction reaches
  /// rather than beside it, because it is part of what the instruction is
  /// rather than something it works on.
  /// </summary>
  let pOrdering =
    (attempt (pstring "aqrl") >>% AsmOrder(true, true))
    <|> (attempt (pstring "aq") >>% AsmOrder(true, false))
    <|> (pstring "rl" >>% AsmOrder(false, true))

  let pOperandList =
    sepBy pOperand operandSeps .>>. opt pOrdering
    |>> fun (operands, ordering) -> operands @ Option.toList ordering

  /// One of the two masks a fence carries, each naming which of the four kinds
  /// of access it keeps on that side of itself. A mask naming none of them is
  /// written as nothing at all.
  let pFenceMask =
    manySatisfy (fun c -> Map.containsKey (Char.ToLowerInvariant c) fenceBits)
    |>> Seq.fold (fun mask c -> mask ||| fenceBits[Char.ToLowerInvariant c]) 0u

  let pFence =
    pFenceMask .>> pchar ',' .>>. pFenceMask
    |>> fun (pred, succ) -> [ AsmFence(pred, succ) ]

  /// What is written after the name of an instruction. Only the fence is read
  /// differently from everything else, because its two masks are written with a
  /// comma between them yet are one operand rather than two.
  let pOperands opcode =
    (if opcode = Op.FENCE then pFence else pOperandList)
    |>> newInfo opcode
    |> skipWhitespaces

  /// The name of an instruction, which is written in parts separated by dots
  /// wherever it says more than one thing.
  let pMnemonic =
    many1Satisfy (fun c -> Char.IsLetterOrDigit c || c = '.')
    >>= fun token ->
      match Map.tryFind (token.ToLowerInvariant()) opcodes with
      | Some opcode -> preturn opcode
      | None -> fail $"'{token}' is not an instruction"

  let pInstructionLine =
    pMnemonic >>= pOperands .>> incrementIndex |>> InstructionLine

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
