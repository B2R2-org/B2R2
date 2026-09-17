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

namespace B2R2.RearEnd.Transformer

open System
open System.Collections.Generic
open System.Threading
open B2R2
open B2R2.RearEnd.Transformer.Utils

type LineDiffEdit =
  | Equal of left: int * right: int
  | Delete of left: int
  | Insert of right: int

/// The `diff` action.
type DiffAction() =
  let [<Literal>] NumBytesPerLine = 16
  let [<Literal>] MaxLineDiffCells = 2000000L

  let byteAt (bytes: byte[]) index =
    if index < bytes.Length then Some bytes[index] else None

  let byteText = function
    | Some(byte: byte) ->
      byte.ToString("x2")
    | None ->
      "  "

  let byteColor left right color =
    if left = right then NoColor else color

  let appendText color text (cs: ColoredString) =
    cs.Append(color, text)

  let appendLine color text cs =
    cs
    |> appendText color text
    |> appendText NoColor Environment.NewLine

  let appendByte color byte cs =
    appendText color (byteText byte) cs

  let appendSide (bytes: byte[]) (other: byte[]) color offset cs =
    [ 0 .. NumBytesPerLine - 1 ]
    |> List.fold (fun cs column ->
      let index = offset + column
      let byte = byteAt bytes index
      let otherByte = byteAt other index
      let cs = appendByte (byteColor byte otherByte color) byte cs
      if column = NumBytesPerLine - 1 then cs else appendText NoColor " " cs)
      cs

  let appendByteRow marker bytes other color baseAddress (offset: int) cs =
    let address = baseAddress + uint64 offset
    let addressStr = $"0x{address:x}".PadLeft 10
    cs
    |> appendText color marker
    |> appendText NoColor $" {addressStr} | "
    |> appendSide bytes other color offset
    |> appendText NoColor Environment.NewLine

  let rowChanged (left: byte[]) (right: byte[]) offset =
    [ 0 .. NumBytesPerLine - 1 ]
    |> List.exists (fun column ->
      let index = offset + column
      byteAt left index <> byteAt right index)

  let appendEqualRows count (cs: ColoredString) =
    if count = 0 then
      cs
    elif count = 1 then
      appendLine DarkCyan "  1 equal row" cs
    else
      appendLine DarkCyan $"  {count} equal rows" cs

  let appendChangedByteRow
    (left: byte[])
    (right: byte[])
    leftBase
    rightBase
    row
    cs =
    let offset = row * NumBytesPerLine
    cs
    |> appendByteRow "-" left right Red leftBase offset
    |> appendByteRow "+" right left Green rightBase offset

  let appendByteDiffRows
    left
    right
    leftBase
    rightBase
    (changed: int list)
    rowCount
    cs =
    let changed = HashSet<int>(changed)
    let rec loop row equalRows cs =
      if row = rowCount then
        appendEqualRows equalRows cs
      elif changed.Contains row then
        cs
        |> appendEqualRows equalRows
        |> appendChangedByteRow left right leftBase rightBase row
        |> loop (row + 1) 0
      else
        loop (row + 1) (equalRows + 1) cs
    loop 0 0 cs

  let buildLcsTable (left: string[]) (right: string[]) =
    let table = Array2D.zeroCreate (left.Length + 1) (right.Length + 1)
    for i = left.Length - 1 downto 0 do
      for j = right.Length - 1 downto 0 do
        if left[i] = right[j] then
          table[i, j] <- table[i + 1, j + 1] + 1
        else
          table[i, j] <- max table[i + 1, j] table[i, j + 1]
    table

  let lineEdits (left: string[]) (right: string[]) =
    let cells = int64 (left.Length + 1) * int64 (right.Length + 1)
    if cells > MaxLineDiffCells then
      let count = max left.Length right.Length
      [ 0 .. count - 1 ]
      |> List.collect (fun index ->
        match index < left.Length, index < right.Length with
        | true, true when left[index] = right[index] ->
          [ Equal(index, index) ]
        | true, true ->
          [ Delete index; Insert index ]
        | true, false ->
          [ Delete index ]
        | false, true ->
          [ Insert index ]
        | false, false ->
          [])
    else
      let table = buildLcsTable left right
      let rec loop i j edits =
        if i < left.Length && j < right.Length && left[i] = right[j] then
          loop (i + 1) (j + 1) (Equal(i, j) :: edits)
        elif i < left.Length then
          if j = right.Length || table[i + 1, j] >= table[i, j + 1] then
            loop (i + 1) j (Delete i :: edits)
          else
            loop i (j + 1) (Insert j :: edits)
        elif j < right.Length then
          loop i (j + 1) (Insert j :: edits)
        else
          List.rev edits
      loop 0 0 []

  let appendLineDiff title (left: string[]) (right: string[]) =
    let edits = lineEdits left right
    let rec apply edits equalRows cs =
      match edits with
      | [] ->
        appendEqualRows equalRows cs
      | Equal _ :: rest ->
        apply rest (equalRows + 1) cs
      | Delete leftIndex :: rest ->
        let lineNo = (leftIndex + 1).ToString().PadLeft 4
        cs
        |> appendEqualRows equalRows
        |> appendLine Red $"- {lineNo}: {left[leftIndex]}"
        |> apply rest 0
      | Insert rightIndex :: rest ->
        let lineNo = (rightIndex + 1).ToString().PadLeft 4
        cs
        |> appendEqualRows equalRows
        |> appendLine Green $"+ {lineNo}: {right[rightIndex]}"
        |> apply rest 0
    let cs = ColoredString()
    cs
    |> appendLine NoColor title
    |> apply edits 0
    |> OutputColored

  let appendPlainLines title lines =
    let cs = ColoredString()
    let lines = lines |> List.toArray
    (cs |> appendLine NoColor title, lines)
    ||> Array.fold (fun cs line -> appendLine NoColor line cs)
    |> OutputColored

  let binaryBytes (bin: Binary) =
    let hdl = Binary.Handle bin
    hdl.File.RawBytes.ToArray()

  let diffBytes
    cancellationToken
    title
    leftBase
    rightBase
    (bs1: byte[])
    (bs2: byte[]) =
    let cancellationToken: CancellationToken = cancellationToken
    cancellationToken.ThrowIfCancellationRequested()
    let maxLength = max bs1.Length bs2.Length
    let rowCount = (maxLength + NumBytesPerLine - 1) / NumBytesPerLine
    let changedRows =
      [ 0 .. rowCount - 1 ]
      |> List.filter (fun row ->
        cancellationToken.ThrowIfCancellationRequested()
        rowChanged bs1 bs2 (row * NumBytesPerLine))
    if List.isEmpty changedRows then
      OutputColored(ColoredString(NoColor, "No diff."))
    else
      let cs = ColoredString()
      cs
      |> appendLine NoColor title
      |> appendByteDiffRows bs1 bs2 leftBase rightBase changedRows rowCount
      |> OutputColored

  let binaryBase (bin: Binary) =
    let hdl = Binary.Handle bin
    hdl.File.BaseAddress

  let tryBinaryInput (input: obj) =
    match input with
    | :? Binary as bin ->
      Some(binaryBase bin, binaryBytes bin)
    | :? BinarySlice as slice ->
      Some(slice.StartAddress, slice.Bytes)
    | _ ->
      None

  let diffBinary cancellationToken bin1 bin2 =
    diffBytes
      cancellationToken
      "byte diff"
      (binaryBase bin1)
      (binaryBase bin2)
      (binaryBytes bin1)
      (binaryBytes bin2)

  let splitText (text: string) =
    text.Replace("\r\n", "\n").Split '\n'

  let instructionLines (instructions: Instruction[]) =
    instructions |> Array.map (fun instruction -> instruction.ToString())

  let cfgLines = function
    | CFG(entry, cfg, _) ->
      [| $"entry: 0x{entry:x}"
         $"vertices: {cfg.Vertices.Length}"
         $"edges: {cfg.Edges.Length}"
         $"roots: {cfg.Roots.Length}"
         $"exits: {cfg.Exits.Length}" |]
    | NoCFG error ->
      [| $"error: {error}" |]

  let diffValues cancellationToken (left: obj) (right: obj) =
    match tryBinaryInput left, tryBinaryInput right with
    | Some(leftBase, leftBytes), Some(rightBase, rightBytes) ->
      diffBytes
        cancellationToken
        "byte diff"
        leftBase
        rightBase
        leftBytes
        rightBytes
    | _ ->
      match left, right with
      | (:? BinaryBytes as left), (:? BinaryBytes as right) ->
        diffBytes
          cancellationToken
          "byte diff"
          left.BaseAddress
          right.BaseAddress
          left.Bytes
          right.Bytes
      | (:? (Instruction[]) as left), (:? (Instruction[]) as right) ->
        appendLineDiff "instruction diff" (instructionLines left)
          (instructionLines right)
      | (:? CFG as left), (:? CFG as right) ->
        appendLineDiff "cfg diff" (cfgLines left) (cfgLines right)
      | (:? TextArtifact as left), (:? TextArtifact as right) ->
        appendLineDiff "text artifact diff" (splitText left.Content)
          (splitText right.Content)
      | (:? string as left), (:? string as right) ->
        appendLineDiff "text diff" (splitText left) (splitText right)
      | (:? OutString as left), (:? OutString as right) ->
        appendLineDiff "text diff" (splitText (left.ToString()))
          (splitText (right.ToString()))
      | (:? ConcExecutorValue as left), (:? ConcExecutorValue as right) ->
        left.DiffLines right |> appendPlainLines "concrete context diff"
      | _ ->
        let message =
          "diff supports Binary, BinarySlice, ByteArray, InstructionArray, "
          + "CFG, Text, and ConcExecutor pairs."
        invalidArg (nameof DiffAction) message

  let transform cancellationToken args collection =
    let values = collection.Values
    if values.Length <> 2 then
      invalidArg (nameof DiffAction) "Can only diff exactly two values."
    else
      match args with
      | [] ->
        let outstr = diffValues cancellationToken values[0] values[1]
        { Values = [| box outstr |] }
      | _ ->
        invalidArg (nameof DiffAction) "Invalid input to diff"

  interface IAction with
    member _.ActionID with get() = "diff"
    member _.Signature with get() =
      "Binary|BinarySlice|ByteArray|InstructionArray|CFG|Text|ConcExecutor "
      + "pair -> OutString"
    member _.Description with get() =
      """
    Take a tuple of two values of the same supported type and return a diff.
"""
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection
