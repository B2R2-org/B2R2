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

/// Turns CIL disassembly back into the bytes it was written from. The syntax
/// read here is the one B2R2's own CIL disassembler writes, so a line of its
/// output can be handed straight back: a mnemonic of ECMA-335, and the one
/// operand the instruction takes beside it, a token standing in for the thing
/// it names and a branch written by the address it reaches.
module B2R2.Assembly.CIL.Encoder

open System
open System.Globalization
open B2R2

/// <summary>
/// One statement, as the syntax has it: a name, and the words written beside
/// it. Words rather than operands, because a switch is written as one word for
/// each target it has, however many that is.
/// </summary>
type Statement =
  { Mnemonic: string
    Words: string list }

/// What a line is split on. The parentheses and commas a switch table is
/// written with are among them, so that the table reads as its targets alone;
/// a carriage return is too, so that a source written on a machine that ends
/// its lines with one reads the same.
let private separators = [| ' '; '\t'; '\r'; ','; '('; ')' |]

/// The culture a number is read in, which is the one the disassembler writes
/// in: a source says what it means rather than where it was written.
let private invariant = CultureInfo.InvariantCulture

/// The line up to the first of the given text, which is where a comment
/// begins.
let private dropAfter (mark: string) (line: string) =
  match line.IndexOf mark with
  | -1 -> line
  | i -> line.Substring(0, i)

/// The line after the first of the given character, which is where the
/// address a line may be marked with ends.
let private dropThrough (c: char) (line: string) =
  match line.IndexOf c with
  | -1 -> line
  | i -> line.Substring(i + 1)

/// <summary>
/// The name an instruction is written under, for the few ECMA-335 gives a
/// second one: endfault is endfinally, the branches on null and on zero are
/// the branch on false, the branch on an instance is the branch on true, and
/// the ".any" forms of ldelem and stelem are the bare ones.
/// </summary>
let private canonical = function
  | "endfault" -> "endfinally"
  | "brnull" | "brzero" -> "brfalse"
  | "brnull.s" | "brzero.s" -> "brfalse.s"
  | "brinst" -> "brtrue"
  | "brinst.s" -> "brtrue.s"
  | "ldelem.any" -> "ldelem"
  | "stelem.any" -> "stelem"
  | name -> name

/// <summary>
/// Reads one line. Two things beside the instruction may be there and both
/// are dropped: the address the disassembler marks a line with, and a
/// comment, which ilasm writes behind a double slash and B2R2 behind a
/// semicolon.
///
/// Everything is folded to lower case, which nothing this syntax writes
/// distinguishes: a mnemonic is written in lower case, and a number reads the
/// same either way.
/// </summary>
let parseLine (line: string) =
  let line = dropAfter "//" line |> dropAfter ";" |> dropThrough ':'
  let words = line.Split(separators, StringSplitOptions.RemoveEmptyEntries)
  if words.Length = 0 then
    None
  else
    let words = words |> Array.map (fun w -> w.ToLowerInvariant())
    Some { Mnemonic = canonical words[0]; Words = List.ofArray words[1..] }

/// Whether a run of digits names the base it is written in.
let private isBased (body: string) =
  body.StartsWith "0x" || body.StartsWith "0b" || body.StartsWith "0o"

/// The number a run of digits spells in whichever base it names, or nothing
/// when it spells no number at all.
let private parseDigits (body: string) =
  try
    if body.StartsWith "0x" then Convert.ToInt64(body[2..], 16) |> Some
    elif body.StartsWith "0b" then Convert.ToInt64(body[2..], 2) |> Some
    elif body.StartsWith "0o" then Convert.ToInt64(body[2..], 8) |> Some
    else Convert.ToInt64(body, 10) |> Some
  with _ ->
    None

/// <summary>
/// Reads an integer written the way a source writes one.
///
/// A number below zero may be written with a sign, which is how the
/// disassembler writes a constant, or as the bits it lands in, which for a
/// number of the full width is the same thing.
///
/// A decimal number keeps its sign rather than having it taken off and put
/// back, because the smallest number there is has no positive counterpart to
/// negate. One written in another base has no sign of its own to keep.
/// </summary>
let private parseInt (word: string) =
  let isNegative = word.StartsWith "-"
  let body = if isNegative || word.StartsWith "+" then word[1..] else word
  if not (isBased body) then
    parseDigits word
  else
    match parseDigits body with
    | Some v when isNegative -> Some(-v)
    | v -> v

/// Reads a number that cannot be below zero and has to fit the given number
/// of bytes, of which there are fewer than eight.
let private parseUnsigned width word =
  match parseInt word with
  | Some v when v >= 0L && v < (1L <<< (8 * width)) -> Some(uint64 v)
  | _ -> None

/// Reads a number that has to fit the given number of bytes, of which there
/// are fewer than eight, whether it was written below zero or as the bits it
/// lands in.
let private parseSigned width word =
  match parseInt word with
  | Some v when v >= -(1L <<< (8 * width - 1)) && v < (1L <<< (8 * width)) ->
    Some v
  | _ ->
    None

/// The three values a decimal point cannot spell, written the way .NET writes
/// them, which is what the disassembler prints, and the way ilasm does.
let private specialFloat = function
  | "nan" | "+nan" | "-nan" -> Some Double.NaN
  | "inf" | "+inf" | "infinity" | "+infinity" -> Some Double.PositiveInfinity
  | "-inf" | "-infinity" -> Some Double.NegativeInfinity
  | _ -> None

/// Reads a 32-bit float.
let private parseSingle (word: string) =
  match specialFloat word with
  | Some v ->
    Some(float32 v)
  | None ->
    match Single.TryParse(word, NumberStyles.Float, invariant) with
    | true, v -> Some v
    | _ -> None

/// Reads a 64-bit float.
let private parseDouble (word: string) =
  match specialFloat word with
  | Some v ->
    Some v
  | None ->
    match Double.TryParse(word, NumberStyles.Float, invariant) with
    | true, v -> Some v
    | _ -> None

/// The low bytes of a number, as many as asked for, least telling first,
/// which is the order the machine reads them in.
let private leBytes (v: uint64) width =
  Array.init width (fun i -> byte (v >>> (8 * i)))

/// Encodes a variable index, which cannot be below zero and has to fit the
/// width its instruction gives it.
let private encodeVar width word =
  match parseUnsigned width word with
  | Some v -> Ok(leBytes v width)
  | None -> Error $"'{word}' does not fit a variable index of {8 * width} bits"

/// Encodes a 32-bit constant in the width its instruction gives it, which for
/// the short form is one byte.
let private encodeI4 width word =
  match parseSigned width word with
  | Some v -> Ok(leBytes (uint64 v) width)
  | None -> Error $"'{word}' does not fit a constant of {8 * width} bits"

/// Encodes a 64-bit constant, which every integer a source can write fits.
let private encodeI8 word =
  match parseInt word with
  | Some v -> Ok(leBytes (uint64 v) 8)
  | None -> Error $"'{word}' does not fit a 64-bit constant"

/// Encodes a 32-bit float, which the encoding carries as the raw bits rather
/// than as the number they spell.
let private encodeR4 word =
  match parseSingle word with
  | Some v -> Ok(leBytes (uint64 (BitConverter.SingleToUInt32Bits v)) 4)
  | None -> Error $"'{word}' is not a 32-bit float"

/// Encodes a 64-bit float the way encodeR4 encodes a 32-bit one.
let private encodeR8 word =
  match parseDouble word with
  | Some v -> Ok(leBytes (BitConverter.DoubleToUInt64Bits v) 8)
  | None -> Error $"'{word}' is not a 64-bit float"

/// <summary>
/// Encodes the address a branch reaches as the distance from the instruction
/// after the branch, which is where the machine counts from.
///
/// The difference is taken in the sixty-four bits of an address, so a target
/// below the branch comes out below zero however near the bottom of the space
/// the two are. What does not fit the width the instruction gives it is out
/// of reach, and is refused rather than cut down to a place the source did
/// not name.
/// </summary>
let private encodeTarget width (next: Addr) word =
  match parseInt word with
  | None ->
    Error $"'{word}' is not an address"
  | Some target ->
    let rel = int64 (uint64 target - next)
    let bits = 8 * width - 1
    if rel < -(1L <<< bits) || rel >= (1L <<< bits) then
      Error $"'{word}' is out of reach"
    else
      Ok(leBytes (uint64 rel) width)

/// Encodes a metadata token, which is four bytes whatever it names.
let private encodeToken word =
  match parseUnsigned 4 word with
  | Some v -> Ok(leBytes v 4)
  | None -> Error $"'{word}' is not a token"

/// Encodes the one byte a prefix carries.
let private encodeByte word =
  match parseUnsigned 1 word with
  | Some v -> Ok(leBytes v 1)
  | None -> Error $"'{word}' does not fit a byte"

/// Encodes the one operand of the given kind and width from the word it is
/// written with. The address of the instruction after this one is what a
/// branch is measured from.
let private encodeOperand kind width next word =
  match kind with
  | VarKind -> encodeVar width word
  | I4Kind -> encodeI4 width word
  | I8Kind -> encodeI8 word
  | R4Kind -> encodeR4 word
  | R8Kind -> encodeR8 word
  | TargetKind -> encodeTarget width next word
  | TokenKind -> encodeToken word
  | ByteKind -> encodeByte word

/// Encodes a fixed operand, which is written as exactly one word.
let private encodeFixed kind width next words =
  match words with
  | [ word ] -> encodeOperand kind width next word
  | [] -> Error "too few operands"
  | _ -> Error "too many operands"

/// The bytes of every entry in order, or the first complaint any of them
/// raised.
let rec private concatResults acc = function
  | [] -> Ok(Array.concat (List.rev acc))
  | Ok bytes :: rest -> concatResults (bytes :: acc) rest
  | Error e :: _ -> Error e

/// Encodes a switch table: how many targets there are, and then each of them
/// as the distance from the instruction after the whole table.
let private encodeTable next words =
  let count = Ok(leBytes (uint64 (List.length words)) 4)
  concatResults [] (count :: List.map (encodeTarget 4 next) words)

/// How long an instruction of the given encoding is, which for a switch
/// depends on how many targets were written for it.
let private lengthOf encoding words =
  match encoding.Shape with
  | Bare -> encoding.Code.Length
  | Fixed(_, width) -> encoding.Code.Length + width
  | Table -> encoding.Code.Length + 4 + 4 * List.length words

/// Encodes one statement at the given address as the given encoding has it.
let private encodeWith (addr: Addr) encoding words =
  let next = addr + uint64 (lengthOf encoding words)
  let operand =
    match encoding.Shape with
    | Bare when List.isEmpty words -> Ok [||]
    | Bare -> Error "too many operands"
    | Fixed(kind, width) -> encodeFixed kind width next words
    | Table -> encodeTable next words
  operand |> Result.map (Array.append encoding.Code)

/// Encodes one statement at the given address, or says why it cannot be.
let encode addr statement =
  match Tables.lookup statement.Mnemonic with
  | Some encoding -> encodeWith addr encoding statement.Words
  | None -> Error $"unknown instruction '{statement.Mnemonic}'"

/// <summary>
/// Encodes a whole source from the given address, one byte array per
/// instruction.
///
/// Where each line lands is what the branches on the lines after it are
/// measured against, so the lines are read in order and each one is placed
/// behind the last.
/// </summary>
let encodeAll (baseAddr: Addr) (source: string) =
  let rec go addr acc = function
    | [] ->
      Ok(List.rev acc)
    | line :: rest ->
      match parseLine line with
      | None ->
        go addr acc rest
      | Some statement ->
        match encode addr statement with
        | Ok bytes -> go (addr + uint64 bytes.Length) (bytes :: acc) rest
        | Error e -> Error e
  source.Split '\n' |> List.ofArray |> go baseAddr []

// vim: set tw=80 sts=2 sw=2:
