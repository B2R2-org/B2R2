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

/// Turns WASM disassembly back into the bytes it was written from. The syntax
/// read here is the one B2R2's own WASM disassembler writes, so a line of its
/// output can be handed straight back.
module B2R2.Assembly.WASM.Encoder

open System
open System.Globalization
open B2R2

/// <summary>
/// One statement, as the syntax has it: a name, and the words written beside
/// it.
///
/// Words rather than operands, because the two are not the same count: a v128
/// is written as four words and a memarg as two or three, so how many words a
/// line holds says nothing on its own about how many operands it names.
/// </summary>
type Statement =
  { Mnemonic: string
    Words: string list }

/// What a line is split on. A carriage return is among them so that a source
/// written on a machine that ends its lines with one reads the same.
let private separators = [| ' '; '\t'; '\r' |]

/// The culture a number is read in, which is the one the disassembler writes
/// in: a source says what it means rather than where it was written.
let private invariant = CultureInfo.InvariantCulture

/// The line up to the first of the given character, which is where a comment
/// begins.
let private dropAfter (c: char) (line: string) =
  match line.IndexOf c with
  | -1 -> line
  | i -> line.Substring(0, i)

/// The line after the first of the given character, which is where the
/// address a line may be marked with ends.
let private dropThrough (c: char) (line: string) =
  match line.IndexOf c with
  | -1 -> line
  | i -> line.Substring(i + 1)

/// <summary>
/// Reads one line. Two things beside the instruction may be there and both
/// are dropped: the address the disassembler marks a line with, and a
/// comment, which the text format writes with a double semicolon.
///
/// Everything is folded to lower case, which nothing this syntax writes
/// distinguishes: a mnemonic and a type name are written in lower case, and a
/// number reads the same either way.
/// </summary>
let parseLine (line: string) =
  let line = dropAfter ';' line |> dropThrough ':'
  let words = line.Split(separators, StringSplitOptions.RemoveEmptyEntries)
  if words.Length = 0 then
    None
  else
    let words = words |> Array.map (fun w -> w.ToLowerInvariant())
    Some { Mnemonic = words[0]; Words = List.ofArray words[1..] }

let [<Literal>] private MinI32 = -2147483648L
let [<Literal>] private MaxI32 = 2147483647L
let [<Literal>] private MaxU32 = 4294967295L

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

/// Reads a number that has to fit in 32 bits and cannot be below zero.
let private parseWord32 word =
  match parseInt word with
  | Some v when v >= 0L && v <= MaxU32 -> Some(uint32 v)
  | _ -> None

/// The three values a decimal point cannot spell, written the way .NET writes
/// them, which is what the disassembler prints, and the way the text format
/// does.
let private specialFloat = function
  | "nan" | "+nan" | "-nan" -> Some Double.NaN
  | "inf" | "+inf" | "infinity" -> Some Double.PositiveInfinity
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

/// The bytes of a 32-bit word, least telling first, which is the order the
/// machine reads them in.
let private wordBytes (v: uint32) =
  [| byte v; byte (v >>> 8); byte (v >>> 16); byte (v >>> 24) |]

/// The bytes of a 64-bit word, in that same order.
let private longBytes (v: uint64) =
  Array.append (wordBytes (uint32 v)) (wordBytes (uint32 (v >>> 32)))

/// Encodes an index, which is a number no smaller than zero and no wider than
/// the 32 bits it is read back as.
let private encodeIndex word =
  match parseInt word with
  | Some v when v >= 0L && v <= MaxU32 ->
    Ok(LEB128.encodeUInt32 (uint32 v))
  | _ ->
    Error $"'{word}' is not an index"

/// Encodes a 32-bit constant, which a source may write below zero or as the
/// bits it lands in.
let private encodeI32 word =
  match parseInt word with
  | Some v when v >= MinI32 && v <= MaxU32 ->
    Ok(LEB128.encodeSInt32 (int32 v))
  | _ ->
    Error $"'{word}' does not fit a 32-bit constant"

/// Encodes a 64-bit constant.
let private encodeI64 word =
  match parseInt word with
  | Some v ->
    Ok(LEB128.encodeSInt64 v)
  | None ->
    Error $"'{word}' does not fit a 64-bit constant"

/// Encodes a 32-bit float, which the encoding carries as the raw bits rather
/// than as the number they spell.
let private encodeF32 word =
  match parseSingle word with
  | Some v ->
    Ok(wordBytes (BitConverter.SingleToUInt32Bits v))
  | None ->
    Error $"'{word}' is not a 32-bit float"

/// Encodes a 64-bit float the way encodeF32 encodes a 32-bit one.
let private encodeF64 word =
  match parseDouble word with
  | Some v ->
    Ok(longBytes (BitConverter.DoubleToUInt64Bits v))
  | None ->
    Error $"'{word}' is not a 64-bit float"

/// Encodes a 128-bit constant, whose four words come out in the order they
/// were written, each in the order the machine reads its bytes in.
let private encodeV128 words =
  let parsed = List.map parseWord32 words
  if List.contains None parsed then
    Error "a v128 is written as four 32-bit words"
  else
    parsed |> List.map (Option.get >> wordBytes) |> Array.concat |> Ok

/// The number a value-type name spells, which the field holds below zero so
/// that a type index, which is not, can share it.
let private valueTypeOf = function
  | "i32" -> Some -0x01
  | "i64" -> Some -0x02
  | "f32" -> Some -0x03
  | "f64" -> Some -0x04
  | "v128" -> Some -0x05
  | "funcref" -> Some -0x10
  | "externref" -> Some -0x11
  | _ -> None

/// The index inside the brackets the disassembler writes a type index in.
let private bracketedIndexOf (word: string) =
  if word.StartsWith "type[" && word.EndsWith "]" then
    match parseInt word[5..word.Length - 2] with
    | Some v when v >= 0L && v <= MaxI32 -> Some(int32 v)
    | _ -> None
  else
    None

/// A type written as the number it is, which is what a type the disassembler
/// has no name for comes back as.
let private plainTypeOf word =
  match parseInt word with
  | Some v when v >= MinI32 && v <= MaxI32 -> Some(int32 v)
  | _ -> None

/// Encodes a block type, in any of the three ways one is written.
let private encodeType word =
  let named = valueTypeOf word
  let numbered = Option.orElse (plainTypeOf word) (bracketedIndexOf word)
  match Option.orElse numbered named with
  | Some t -> Ok(LEB128.encodeSInt32 t)
  | None -> Error $"'{word}' is not a type"

/// The type ref.null takes, spelled without the suffix a value type of the
/// same byte carries.
let private refTypeOf = function
  | "func" -> Some -0x10
  | "extern" -> Some -0x11
  | _ -> None

/// Encodes the type ref.null takes.
let private encodeRefType word =
  match Option.orElse (plainTypeOf word) (refTypeOf word) with
  | Some t -> Ok(LEB128.encodeSInt32 t)
  | None -> Error $"'{word}' is not a reference type"

/// Encodes an operand the encoding carries as one byte rather than as a
/// LEB128 number.
let private encodeByte word =
  match parseInt word with
  | Some v when v >= 0L && v <= 255L -> Ok [| byte v |]
  | _ -> Error $"'{word}' does not fit a byte"

/// Encodes one operand of the given kind from the words it is written with.
let private encodeOperand kind words =
  match kind, words with
  | IndexKind, [ w ] -> encodeIndex w
  | I32Kind, [ w ] -> encodeI32 w
  | I64Kind, [ w ] -> encodeI64 w
  | F32Kind, [ w ] -> encodeF32 w
  | F64Kind, [ w ] -> encodeF64 w
  | V128Kind, ws -> encodeV128 ws
  | TypeKind, [ w ] -> encodeType w
  | RefTypeKind, [ w ] -> encodeRefType w
  | (AlignmentKind, [ w ]) | (AddressKind, [ w ]) -> encodeIndex w
  | (LaneKind, [ w ]) | (ConsistencyKind, [ w ]) -> encodeByte w
  | _, ws -> Error $"""'{String.concat " " ws}' is not an operand"""

/// How many words of a source line one operand of the given kind is written
/// with. A v128 is the four 32-bit words it spells out; everything else is
/// one word.
let private wordsOf = function
  | V128Kind -> 4
  | _ -> 1

/// <summary>
/// Encodes a fixed run of operands, handing each kind the words it takes.
///
/// A block type is the one operand that may be left out, and it is left out
/// far more often than not: a block yielding nothing is written as a bare
/// mnemonic, which is also how the disassembler writes it.
/// </summary>
let rec private encodeFixed acc kinds words =
  match kinds, words with
  | [], [] ->
    Ok(Array.concat (List.rev acc))
  | [], _ ->
    Error "too many operands"
  | [ TypeKind ], [] ->
    Ok(Array.concat (List.rev (LEB128.encodeSInt32 -0x40 :: acc)))
  | kind :: rest, _ ->
    encodeNextOperand acc kind rest words

and private encodeNextOperand acc kind rest words =
  let count = wordsOf kind
  if List.length words < count then
    Error "too few operands"
  else
    match encodeOperand kind (List.truncate count words) with
    | Ok bytes -> encodeFixed (bytes :: acc) rest (List.skip count words)
    | Error e -> Error e

/// <summary>
/// Encodes a memarg from the numbers its fields hold.
///
/// The memory index is not a field of its own: bit 6 of the alignment is what
/// says it is there. So an alignment that already has that bit names no
/// memarg a source can mean, whichever of the two forms it was written in.
/// </summary>
let private memArgBytes align memory offset =
  if align &&& 0x40u <> 0u then
    Error "bit 6 of an alignment says a memory index is there"
  else
    let flag = if Option.isSome memory then 0x40u else 0u
    [ Some(align ||| flag); memory; Some offset ]
    |> List.choose id
    |> List.map LEB128.encodeUInt32
    |> Array.concat
    |> Ok

/// Reads the fields of a memarg and encodes them.
let private memArgOf align memory offset =
  match memory, parseWord32 align, parseWord32 offset with
  | Some m, Some align, Some offset ->
    match parseWord32 m with
    | Some index -> memArgBytes align (Some index) offset
    | None -> Error $"'{m}' is not a memory index"
  | None, Some align, Some offset ->
    memArgBytes align None offset
  | _ ->
    Error "a memarg is written as numbers"

/// Encodes a memarg, which is written with a memory index between its two
/// fields or with nothing there at all.
let private encodeMemArg words =
  match words with
  | [ align; offset ] -> memArgOf align None offset
  | [ align; memory; offset ] -> memArgOf align (Some memory) offset
  | _ -> Error "a memarg is written as an alignment and an offset"

/// Encodes a memarg with the lane of a v128 written after it.
let private encodeMemArgLane words =
  match List.rev words with
  | lane :: rest when List.length rest >= 2 ->
    match encodeMemArg (List.rev rest) with
    | Error e ->
      Error e
    | Ok memarg ->
      match encodeByte lane with
      | Ok lane -> Ok(Array.append memarg lane)
      | Error e -> Error e
  | _ ->
    Error "a lane is written after the memarg"

/// The bytes of every operand in order, or the first complaint any of them
/// raised.
let rec private concatResults acc = function
  | [] -> Ok(Array.concat (List.rev acc))
  | Ok bytes :: rest -> concatResults (bytes :: acc) rest
  | Error e :: _ -> Error e

/// Encodes a run of operands written one word each, behind the count the
/// decoder reads them with.
let private encodeCounted encodeOne count words =
  let head = Ok(LEB128.encodeUInt32 (uint32 (count: int)))
  concatResults [] (head :: List.map encodeOne words)

/// Encodes a br_table. The label it goes to when none of the others is picked
/// is written last and is not part of the count.
let private encodeLabelTable words =
  match words with
  | [] -> Error "a br_table is written with at least a default label"
  | _ -> encodeCounted encodeIndex (List.length words - 1) words

/// Encodes the value types a select is written with.
let private encodeTypeVector words =
  encodeCounted encodeType (List.length words) words

/// Encodes one instruction as the given encoding has it.
let private encodeWith encoding words =
  let operands =
    match encoding.Shape with
    | Fixed kinds -> encodeFixed [] kinds words
    | MemArg -> encodeMemArg words
    | MemArgLane -> encodeMemArgLane words
    | LabelTable -> encodeLabelTable words
    | TypeVector -> encodeTypeVector words
  operands |> Result.map (Array.append encoding.Code)

/// <summary>
/// Encodes one statement with the first encoding of its name that fits, and
/// complains the way the first of them complained when none does.
///
/// Only select is written with two, and which of the two a source means is
/// what it writes beside the name: the narrower was found first, so a bare
/// select is the one-byte instruction and a select written with types is the
/// other.
/// </summary>
let rec private tryEncodings statement first encodings =
  match encodings with
  | [] ->
    Error(defaultArg first $"unknown instruction '{statement.Mnemonic}'")
  | encoding :: rest ->
    match encodeWith encoding statement.Words with
    | Ok bytes -> Ok bytes
    | Error e -> tryEncodings statement (Some(defaultArg first e)) rest

/// Encodes one statement, or says why it cannot be.
let encode statement =
  tryEncodings statement None (Tables.lookup statement.Mnemonic)

/// Encodes a whole source, one byte array per instruction.
let encodeAll (source: string) =
  let rec go acc = function
    | [] ->
      Ok(List.rev acc)
    | line :: rest ->
      match parseLine line with
      | None ->
        go acc rest
      | Some statement ->
        match encode statement with
        | Ok bytes -> go (bytes :: acc) rest
        | Error e -> Error e
  source.Split '\n' |> List.ofArray |> go []

// vim: set tw=80 sts=2 sw=2:
