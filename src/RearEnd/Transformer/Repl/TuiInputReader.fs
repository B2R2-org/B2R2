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
open System.Text
open System.Threading

/// Reads native console records or terminal key and mouse sequences.
type internal TuiInputReader() =
  let pending = Queue<TuiInputEvent>()
  let escapeContinuationMs = 15

  let restoreKey key shift alt control =
    ConsoleKeyInfo(char 0, key, shift, alt, control)

  let plainKey key = restoreKey key false false false

  let tryModifier (value: string) key =
    match Int32.TryParse value with
    | true, code when code >= 1 && code <= 8 ->
      let bits = code - 1
      let shift = bits &&& 1 <> 0
      let alt = bits &&& 2 <> 0
      let control = bits &&& 4 <> 0
      restoreKey key shift alt control |> Some
    | _ ->
      None

  let tryFinalKey = function
    | 'A' -> Some ConsoleKey.UpArrow
    | 'B' -> Some ConsoleKey.DownArrow
    | 'C' -> Some ConsoleKey.RightArrow
    | 'D' -> Some ConsoleKey.LeftArrow
    | 'H' -> Some ConsoleKey.Home
    | 'F' -> Some ConsoleKey.End
    | 'P' -> Some ConsoleKey.F1
    | 'Q' -> Some ConsoleKey.F2
    | 'R' -> Some ConsoleKey.F3
    | 'S' -> Some ConsoleKey.F4
    | _ -> None

  let tryTildeKey (value: string) =
    match Int32.TryParse value with
    | true, 1 -> Some ConsoleKey.Home
    | true, 2 -> Some ConsoleKey.Insert
    | true, 3 -> Some ConsoleKey.Delete
    | true, 4 -> Some ConsoleKey.End
    | true, 5 -> Some ConsoleKey.PageUp
    | true, 6 -> Some ConsoleKey.PageDown
    | true, 11 -> Some ConsoleKey.F1
    | true, 12 -> Some ConsoleKey.F2
    | true, 13 -> Some ConsoleKey.F3
    | true, 14 -> Some ConsoleKey.F4
    | true, 15 -> Some ConsoleKey.F5
    | true, 17 -> Some ConsoleKey.F6
    | true, 18 -> Some ConsoleKey.F7
    | true, 19 -> Some ConsoleKey.F8
    | true, 20 -> Some ConsoleKey.F9
    | true, 21 -> Some ConsoleKey.F10
    | true, 23 -> Some ConsoleKey.F11
    | true, 24 -> Some ConsoleKey.F12
    | _ -> None

  let tryCharacterKey (value: string) =
    match Int32.TryParse value with
    | true, 9 ->
      Some ConsoleKey.Tab
    | true, 13 ->
      Some ConsoleKey.Enter
    | true, 27 ->
      Some ConsoleKey.Escape
    | true, 32 ->
      Some ConsoleKey.Spacebar
    | true, 127 ->
      Some ConsoleKey.Backspace
    | true, code when code >= 97 && code <= 122 ->
      enum<ConsoleKey> (code - 32) |> Some
    | true, code when code >= 65 && code <= 90 ->
      enum<ConsoleKey> code |> Some
    | true, code when code >= 48 && code <= 57 ->
      enum<ConsoleKey> code |> Some
    | _ ->
      None

  let tryCsiKey (sequence: string) =
    let final = sequence[sequence.Length - 1]
    let body = sequence[1..sequence.Length - 2]
    let parts = body.Split ';'
    match final, parts with
    | 'Z', [| "" |] ->
      restoreKey ConsoleKey.Tab true false false |> Some
    | '~', [| key |] ->
      tryTildeKey key |> Option.map plainKey
    | '~', [| key; modifier |] ->
      tryTildeKey key |> Option.bind (tryModifier modifier)
    | '~', [| "27"; modifier; key |] ->
      tryCharacterKey key |> Option.bind (tryModifier modifier)
    | 'u', [| key; modifier |] ->
      tryCharacterKey key |> Option.bind (tryModifier modifier)
    | _, [| "" |]
    | _, [| "1" |] ->
      tryFinalKey final |> Option.map plainKey
    | _, [| "1"; modifier |] ->
      tryFinalKey final |> Option.bind (tryModifier modifier)
    | _ ->
      None

  let tryTerminalKey (sequence: string) =
    if sequence.StartsWith("[", StringComparison.Ordinal)
       && sequence.Length >= 2 then
      tryCsiKey sequence
    elif sequence.StartsWith("O", StringComparison.Ordinal)
         && sequence.Length = 2 then
      tryFinalKey sequence[1] |> Option.map plainKey
    else
      None

  let normalizeControlKey (key: ConsoleKeyInfo) =
    let code = int key.KeyChar
    let isLetter = code >= 1 && code <= 26
    let isStructural =
      code = 8 || code = 9 || code = 10 || code = 13
    if isLetter && not isStructural then
      let letter = enum<ConsoleKey> (int ConsoleKey.A + code - 1)
      let shift = key.Modifiers.HasFlag ConsoleModifiers.Shift
      let alt = key.Modifiers.HasFlag ConsoleModifiers.Alt
      ConsoleKeyInfo(key.KeyChar, letter, shift, alt, true)
    else
      key

  let tryParseMouseEvent (sequence: string) =
    if String.IsNullOrEmpty sequence
       || not (sequence.StartsWith("[<", StringComparison.Ordinal)) then
      None
    else
      let terminator = sequence[sequence.Length - 1]
      if terminator <> 'M' && terminator <> 'm' then
        None
      else
        let values = sequence[2..sequence.Length - 2].Split ';'
        match values with
        | [| button; column; row |] ->
          let buttonResult = Int32.TryParse button
          let columnResult = Int32.TryParse column
          let rowResult = Int32.TryParse row
          match buttonResult, columnResult, rowResult with
          | (true, button), (true, column), (true, row) ->
            let isDrag = button &&& 32 <> 0
            { Button = button &&& (~~~32)
              Column = column
              Row = row
              IsRelease = terminator = 'm'
              IsDrag = isDrag }
            |> TuiInputEvent.Mouse
            |> Some
          | _ ->
            None
        | _ ->
          None

  let restoreEscapeSequence sequence =
    match tryTerminalKey sequence with
    | Some key ->
      TuiInputEvent.Key key
    | None ->
      sequence
      |> Seq.map (fun character ->
        if Char.IsControl character then
          $"<0x{int character:X2}>"
        else
          string character)
      |> String.concat ""
      |> TuiInputEvent.UnknownKey

  let keyAvailable () =
    Console.KeyAvailable
    || SpinWait.SpinUntil((fun () -> Console.KeyAvailable),
                          escapeContinuationMs)

  let readEscapeSequence first =
    if not (keyAvailable ()) then
      TuiInputEvent.Key first
    else
      let text = StringBuilder()
      let mutable isComplete = false
      while not isComplete && text.Length < 64 && keyAvailable () do
        let key = Console.ReadKey true
        text.Append key.KeyChar |> ignore
        let sequence = text.ToString()
        isComplete <-
          if sequence.StartsWith("[<", StringComparison.Ordinal) then
            key.KeyChar = 'M' || key.KeyChar = 'm'
          elif sequence.StartsWith("[", StringComparison.Ordinal) then
            sequence.Length > 1
            && key.KeyChar >= '@' && key.KeyChar <= '~'
          elif sequence.StartsWith("O", StringComparison.Ordinal) then
            sequence.Length > 1
          else
            true
      let sequence = text.ToString()
      match tryParseMouseEvent sequence with
      | Some input -> input
      | None -> restoreEscapeSequence sequence

  member _.Read() =
    if pending.Count > 0 then
      Some(pending.Dequeue())
    elif TransformerTuiWindowsConsole.isEnabled () then
      TransformerTuiWindowsConsole.tryReadInputEvent ()
    elif Console.KeyAvailable then
      let key = Console.ReadKey true
      if key.Key = ConsoleKey.Escape && key.KeyChar = '\u001b' then
        Some(readEscapeSequence key)
      else
        Some(TuiInputEvent.Key(normalizeControlKey key))
    else
      None

  member _.PutBack input = pending.Enqueue input
