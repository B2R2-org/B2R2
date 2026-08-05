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

/// <summary>
/// Turns the pieces of an instruction into the bit fields a PA-RISC encoding
/// is built from. Every function here rejects what does not fit rather than
/// truncating it, because a field that silently drops a bit encodes an
/// instruction the source did not ask for.
/// </summary>
module internal B2R2.Assembly.PARISC.AsmField

open System
open B2R2.FrontEnd.PARISC
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.PARISC.ParserHelper

/// Reports a source this assembler cannot encode.
let fail msg = raise <| EncodingFailureException msg

/// Reports operands that do not belong to the given mnemonic.
let wrongOperands (ins: AsmInsInfo) =
  fail $"{ins.Mnemonic} does not take these operands"

/// Reports words written after a name that do not belong to it.
let wrongSuffixes (ins: AsmInsInfo) =
  fail $"{ins.Mnemonic} does not take these completers"

/// <summary>
/// Tries one encoding and falls back on another where the first does not fit.
///
/// The disassembler writes several instructions under one name, so a name on
/// its own does not say which instruction a line is; the forms that share a
/// name are tried in turn, and the one whose operands fit is the one meant.
/// </summary>
let orTry first second ins =
  try first ins with EncodingFailureException _ -> second ins

/// A register operand.
let (|Rg|_|) = function
  | AsmReg reg -> Some reg
  | _ -> None

/// An operand that stands for a number.
let (|Im|_|) = function
  | AsmImm value -> Some value
  | _ -> None

/// The memory an instruction reaches, which is what is added to a register,
/// the space it is reached in, and the register itself.
let (|Mem|_|) = function
  | AsmMem(offset, space, baseReg) -> Some(offset, space, baseReg)
  | _ -> None

/// The five bits that name one of the general registers.
let gpr (reg: Register) =
  if reg >= Register.GR0 && reg <= Register.GR31 then uint32 (int reg)
  else fail $"{Register.toString reg} is not a general register"

/// The five bits that name one of the floating-point registers, which are the
/// registers a whole doubleword is kept in.
let fpr (reg: Register) =
  if reg >= Register.FPR0L && reg <= Register.FPR31L then
    uint32 (int reg - int Register.FPR0L)
  else
    fail $"{Register.toString reg} does not hold a whole doubleword"

/// <summary>
/// The same, together with the bit saying which half of that register is
/// meant.
///
/// An instruction working on a word alone reaches one half of a
/// floating-point register, and the bit saying which half lies nowhere near
/// the five naming the register, so the two are handed back apart.
/// </summary>
let fprHalf (reg: Register) =
  if reg >= Register.FPR0L && reg <= Register.FPR31L then
    uint32 (int reg - int Register.FPR0L), 0u
  elif reg >= Register.FPR0R && reg <= Register.FPR31R then
    uint32 (int reg - int Register.FPR0R), 1u
  else
    fail $"{Register.toString reg} is not a floating-point register"

/// The five bits that name one of the control registers.
let ctrl (reg: Register) =
  if reg >= Register.CR0 && reg <= Register.CR31 then
    uint32 (int reg - int Register.CR0)
  else
    fail $"{Register.toString reg} is not a control register"

/// The bits naming one of the spaces an instruction reaches memory in, where
/// a source writing none of them means the first, which is the one the
/// disassembler leaves unwritten.
let private spaceOf count = function
  | None ->
    0u
  | Some(reg: Register) when
      reg >= Register.SR0 && int reg - int Register.SR0 < count ->
    uint32 (int reg - int Register.SR0)
  | Some reg ->
    fail $"{Register.toString reg} is not one of these spaces"

/// The two bits naming one of the first four spaces, in the place the encoding
/// keeps them.
let space2 space = spaceOf 4 space <<< 14

/// <summary>
/// The three bits naming any of the eight spaces, in the places the encoding
/// keeps them.
///
/// The two lower bits sit where the two bits naming one of the first four
/// spaces sit, and the third lies alone just below them, so that an
/// instruction reaching only the first four leaves that bit to say something
/// else.
/// </summary>
let space3 space =
  let s = spaceOf 8 space
  ((s &&& 3u) <<< 14) ||| ((s >>> 2) <<< 13)

/// <summary>
/// The bits a field naming a whole number holds.
///
/// The disassembler writes such a number as the whole word it was widened to
/// rather than with a sign, so one below zero arrives as its sixty-four bit
/// form whether the source wrote it that way or with a sign.
/// </summary>
let unsigned width (value: uint64) =
  if value < (1UL <<< width) then uint32 value
  else fail $"0x{value:x} does not fit in {width} bits"

/// <summary>
/// The bits a field holds where it keeps a signed number with its sign at the
/// bottom rather than at the top.
///
/// PA-RISC writes the sign of a small number in the lowest bit of the field
/// holding it, so that the bits above it read as a count either way.
/// </summary>
let lowSignExt width (value: uint64) =
  let v = int64 value
  let bound = 1L <<< (width - 1)
  if v >= -bound && v < bound then
    let magnitude = uint32 (uint64 v &&& (uint64 bound - 1UL))
    (magnitude <<< 1) ||| (if v < 0L then 1u else 0u)
  else
    fail $"{v} does not fit in {width} signed bits"

/// <summary>
/// The bits the field holding a distance of fourteen signed bits keeps.
///
/// The field is sixteen bits wide and the three above it all hold the sign, so
/// what it reaches is narrower than its width suggests. The sign itself sits
/// in the lowest bit, below the rest of the number.
/// </summary>
let assemble16 (value: uint64) =
  let v = int64 value
  if v >= -8192L && v <= 8191L then
    (uint32 (uint64 v &&& 0x1FFFUL) <<< 1) ||| (if v < 0L then 1u else 0u)
  else
    fail $"{v} is more than a sixteen-bit field reaches"

/// How far away a place is, in words, given how far away it is in bytes and
/// how many bits the field saying so holds.
let private words width (value: uint64) =
  let v = int64 value
  let bound = 1L <<< (width + 1)
  if v % 4L <> 0L then fail "a branch reaches only a whole word away"
  elif v < -bound || v >= bound then fail $"{v} is out of a branch's reach"
  else uint32 (uint64 (v / 4L)) &&& ((1u <<< width) - 1u)

/// <summary>
/// The pieces of the twelve-bit distance a branch on a comparison holds.
///
/// The distance lies in three pieces: the ten bits just below the field
/// saying whether the instruction after the branch is thrown away, the bit
/// below those, and the sign, which sits in the lowest bit of the word.
/// </summary>
let assemble12 (value: uint64) =
  let w = words 12 value
  ((w &&& 0x3FFu) <<< 3) ||| (((w >>> 10) &&& 1u) <<< 2) ||| ((w >>> 11) &&& 1u)

/// The same, for the seventeen-bit distance a call holds, which keeps five
/// more of its bits where a second register would be named.
let assemble17 (value: uint64) =
  let w = words 17 value
  ((w &&& 0x3FFu) <<< 3) ||| (((w >>> 10) &&& 1u) <<< 2)
  ||| (((w >>> 11) &&& 0x1Fu) <<< 16) ||| ((w >>> 16) &&& 1u)

/// The same, for the twenty-two bits the longest branch holds, which spends
/// the field naming its first register on five bits more.
let assemble22 (value: uint64) =
  let w = words 22 value
  ((w &&& 0x3FFu) <<< 3) ||| (((w >>> 10) &&& 1u) <<< 2)
  ||| (((w >>> 11) &&& 0x1Fu) <<< 16) ||| (((w >>> 16) &&& 0x1Fu) <<< 21)
  ||| ((w >>> 21) &&& 1u)

/// <summary>
/// The twenty-one bits the instruction building the upper part of a word
/// holds, scattered the way the encoding keeps them.
///
/// What the instruction builds is a whole word whose lowest eleven bits are
/// zero, so the disassembler writes that word rather than the field, and the
/// field is read back out of it here. The bits of the field are kept in five
/// pieces, in an order that has nothing to do with what they mean.
/// </summary>
let assemble21 (value: uint64) =
  let v = int64 value
  if v <> int64 (int32 v) then
    fail $"0x{value:x} is more than a word holds"
  elif v % 0x800L <> 0L then
    fail $"0x{value:x} is not an upper part of a word"
  else
    let a = (uint32 v) >>> 11
    (((a >>> 20) &&& 1u)) ||| (((a >>> 9) &&& 0x7FFu) <<< 1)
    ||| (((a >>> 7) &&& 3u) <<< 14) ||| (((a >>> 2) &&& 0x1Fu) <<< 16)
    ||| ((a &&& 3u) <<< 12)

/// <summary>
/// The bit saying which half of a doubleword a length is counted in, and the
/// five bits counting it, given a length of anything up to a whole one.
///
/// The two are read as one number counting backwards from a doubleword, so
/// that the widest length a field can hold is the one whose bits are all
/// clear.
/// </summary>
let dwordLength (value: uint64) =
  if value >= 1UL && value <= 64UL then
    let q = 64u - uint32 value
    ((q >>> 5) ^^^ 1u), (q &&& 0x1Fu)
  else
    fail $"{value} is not a length"

/// The same, where the bit above the five is not part of the length, so that
/// nothing wider than a word can be said.
let wordLength (value: uint64) =
  let cl, clen = dwordLength value
  if cl = 0u then clen else fail $"{value} is more than a word holds"

/// The same again, where the two pieces are read as one number counting
/// backwards from either a word or a doubleword rather than always from a
/// doubleword.
let extendedLength (value: uint64) =
  if value >= 1UL && value <= 64UL then
    let cl = if value <= 32UL then 0u else 1u
    cl, ((cl + 1u) * 32u - uint32 value)
  else
    fail $"{value} is not a length"

/// <summary>
/// The bit and the five bits naming where in a doubleword a field starts.
///
/// What the encoding holds is how far the start is from the far end and what
/// the disassembler writes is how far it is from the near one, so the two are
/// subtracted here.
/// </summary>
let dwordPosition (value: uint64) =
  if value <= 63UL then
    let q = 63u - uint32 value
    (q >>> 5), (q &&& 0x1Fu)
  else
    fail $"{value} is not a place in a doubleword"

/// The same, where only the lower half of a doubleword can be named, so that
/// the bit above the five is always set.
let wordPosition (value: uint64) =
  let cp, cpos = dwordPosition value
  if cp = 1u then cpos else fail $"{value} is not a place in a word"

(* The word standing where a condition has no name of its own, which no source
   can write, because what is written after the name of an instruction is
   taken apart at its commas and so holds no space. *)
let [<Literal>] private Unnamed = " "

/// <summary>
/// Which of the conditions in a table a word names, and whether it is read off
/// the whole of a doubleword.
///
/// A condition written with a star ahead of it is read off all sixty-four bits
/// of what was computed rather than off its lower half, and the two are told
/// apart by the lowest bit of the field naming the condition.
/// </summary>
let private conditionOf (names: string[]) (token: string) =
  let wide = token.StartsWith "*"
  let name = if wide then token[1..] else token
  match Array.tryFindIndex ((=) name) names with
  | Some index -> uint32 index, (if wide then 1u else 0u)
  | None -> fail $"'{token}' names no condition here"

/// The five bits naming the condition an instruction goes on, which are the
/// three saying which condition it is, the one saying whether it goes on the
/// condition holding or on its not holding, and the one saying how much of
/// what was computed the condition is read off.
let private field5 names token =
  let index, wide = conditionOf names token
  (index <<< 1) ||| wide

/// The four bits naming a condition where how much is read off is fixed, which
/// is what the instructions computing from a written number hold.
let private field4 names token =
  let index, wide = conditionOf names token
  if wide = 0u then index
  else fail $"'{token}' is read off more than this instruction computes"

/// The sixteen conditions an addition is read by.
let private addNames =
  [| ""
     "tr"
     "="
     "<>"
     "<"
     ">="
     "<="
     ">"
     "nuv"
     "uv"
     "znv"
     "vnz"
     "sv"
     "nsv"
     "od"
     "ev" |]

/// The sixteen a subtraction and a comparison are read by, which differ from
/// those of an addition only where they say something about a borrow rather
/// than about an overflow.
let private compSubNames =
  [| ""
     "tr"
     "="
     "<>"
     "<"
     ">="
     "<="
     ">"
     "<<"
     ">>="
     "<<="
     ">>"
     "sv"
     "nsv"
     "od"
     "ev" |]

/// The conditions a bitwise operation is read by, which are the ones of an
/// addition that say nothing about a carry; the rest name nothing here.
let private logicalNames =
  [| ""
     "tr"
     "="
     "<>"
     "<"
     ">="
     Unnamed
     ">"
     Unnamed
     Unnamed
     Unnamed
     Unnamed
     Unnamed
     Unnamed
     "od"
     "ev" |]

/// The conditions an operation on the parts of a doubleword is read by, which
/// speak of the parts rather than of the whole.
let private unitNames =
  [| ""
     "tr"
     "swz"
     "nwz"
     "sbz"
     "nbz"
     "shz"
     "nhz"
     "sdc"
     "ndc"
     "swc"
     "nwc"
     "sbc"
     "nbc"
     "shc"
     "nhc" |]

/// The eight a shift, an extraction and a deposit are read by.
let private shiftNames =
  [| ""; "="; "<"; "od"; "tr"; "<>"; ">="; "ev" |]

/// <summary>
/// Scatters the five bits naming a condition into the places the encoding
/// keeps them.
///
/// The three saying which condition it is and the one saying whether the
/// instruction goes on its holding lie together above the field naming what is
/// computed, and the one saying how much of the result the condition is read
/// off lies below it, beside the bit naming what is computed.
/// </summary>
let scatterCondition cf =
  ((cf >>> 2) <<< 13) ||| (((cf >>> 1) &&& 1u) <<< 12) ||| ((cf &&& 1u) <<< 5)

/// The five bits naming the condition an addition goes on.
let addCondition token = field5 addNames token

/// The five bits naming the condition a subtraction or a comparison goes on.
let compSubCondition token = field5 compSubNames token

/// The five bits naming the condition a bitwise operation goes on.
let logicalCondition token = field5 logicalNames token

/// The five bits naming the condition an operation on the parts of a
/// doubleword goes on.
let unitCondition token = field5 unitNames token

/// The four bits naming the condition an addition to a written number goes on,
/// which are read off a word alone.
let addCondition4 token = field4 addNames token

/// The four bits naming the condition a subtraction from a written number goes
/// on.
let compSubCondition4 token = field4 compSubNames token

/// <summary>
/// The three bits naming the condition a shift, an extraction or a deposit
/// goes on.
///
/// How much of the result such a condition is read off is fixed by which
/// instruction it belongs to rather than by a bit of its own, so a condition
/// written with a star where the instruction works on a word alone, or without
/// one where it works on a whole doubleword, names nothing.
/// </summary>
let shiftCondition wide token =
  let cf = field5 shiftNames token
  if (cf &&& 1u) = wide then cf >>> 1
  else fail $"'{token}' is not read off what this instruction computes"

/// The three bits naming the condition the comparison of a doubleword against
/// a written number branches on, which are read off the whole of it and are
/// counted in an order of their own.
let cmpibCondition (token: string) =
  let names = [| "*<<"; "*="; "*<"; "*<="; "*>>="; "*<>"; "*>="; "*>" |]
  match Array.tryFindIndex ((=) token) names with
  | Some index -> uint32 index
  | None -> fail $"'{token}' says nothing about a doubleword"

/// The two bits naming the condition a branch on one bit goes on, which are
/// whether the bit is to be set or clear and how much of the register the bit
/// is counted in.
let branchOnBitCondition (token: string) =
  match token with
  | "<" -> 0u
  | ">=" -> 2u
  | "*<" -> 1u
  | "*>=" -> 3u
  | _ -> fail $"'{token}' says nothing about one bit"

/// The five bits naming what a comparison of floating-point numbers leaves
/// behind, which is one of thirty-two answers rather than one of sixteen,
/// because such a comparison may also say that the two are not comparable.
let floatCompareCondition (token: string) =
  let names =
    [| "false?"
       "false"
       "?"
       "!<=>"
       "="
       "=t"
       "?="
       "!<>"
       "!?>="
       "<"
       "?<"
       "!>="
       "!?>"
       "<="
       "?<="
       "!>"
       "!?<="
       ">"
       "?>"
       "!<="
       "!?<"
       ">="
       "?>="
       "!<"
       "!?="
       "<>"
       "!="
       "!=t"
       "!?"
       "<=>"
       "true?"
       "true" |]
  match Array.tryFindIndex ((=) token) names with
  | Some index -> uint32 index
  | None -> fail $"'{token}' names no floating-point comparison"

/// The five bits naming which of the answers a comparison left an instruction
/// reading them asks after.
let floatTestCondition (token: string) =
  match token with
  | "acc" -> 1u
  | "rej" -> 2u
  | "acc8" -> 5u
  | "rej8" -> 6u
  | "acc6" -> 9u
  | "acc4" -> 13u
  | "acc2" -> 17u
  | _ -> fail $"'{token}' asks after no comparison"

/// The two bits naming the width a floating-point number is kept at, where a
/// source writing none of them leaves the field at the value the disassembler
/// writes nothing for.
let floatFormat = function
  | [] -> 2u
  | [ "sgl" ] -> 0u
  | [ "dbl" ] -> 1u
  | [ "quad" ] -> 3u
  | _ -> fail "this names no floating-point width"

/// Splits the words written after the name of an instruction into the ones the
/// given list holds and the ones it does not, keeping the order they were
/// written in.
let split names suffixes =
  List.partition (fun s -> List.contains s names) suffixes

/// Whether a word was written after the name of an instruction.
let has name suffixes = List.contains name (suffixes: string list)

/// The bit a word written after the name of an instruction stands for.
let bit name suffixes = if has name suffixes then 1u else 0u

/// <summary>
/// The condition left over once the words a name carries have been taken away.
///
/// An instruction whose condition is left unwritten goes on nothing, and the
/// field naming the condition is then the one standing for that.
/// </summary>
let condition = function
  | [] ->
    ""
  | [ token ] ->
    token
  | tokens ->
    let written = String.concat "," tokens
    fail $"'{written}' says too much"

/// Refuses anything left over where nothing was expected.
let nothingLeft (ins: AsmInsInfo) = function
  | [] -> ()
  | _ -> wrongSuffixes ins

/// <summary>
/// The numbers written just after the name of an instruction, and whatever was
/// written after them.
///
/// A number is written there where the encoding holds something the
/// disassembler has no name for: which unit outside the processor an
/// instruction is meant for, and what that unit is to do with it.
/// </summary>
let takeNumbers count (suffixes: string list) =
  let taken = List.truncate count suffixes
  if List.length taken < count then
    fail "this names no unit"
  else
    let read (token: string) =
      match UInt64.TryParse token with
      | true, value -> value
      | _ -> fail $"'{token}' is not a number"
    List.map read taken, List.skip count suffixes

// vim: set tw=80 sts=2 sw=2:
