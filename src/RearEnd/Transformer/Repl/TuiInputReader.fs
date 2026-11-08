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

/// Reads native console records or terminal key and mouse sequences.
type internal TuiInputReader() =
  let pending = Queue<TuiInputEvent>()

  let restoreKey key =
    ConsoleKeyInfo(char 0, key, false, false, false)

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

  let restoreEscapeSequence first keys sequence =
    let key =
      match sequence with
      | "[A" -> Some ConsoleKey.UpArrow
      | "[B" -> Some ConsoleKey.DownArrow
      | "[C" -> Some ConsoleKey.RightArrow
      | "[D" -> Some ConsoleKey.LeftArrow
      | "[H"
      | "[1~" -> Some ConsoleKey.Home
      | "[F"
      | "[4~" -> Some ConsoleKey.End
      | "[3~" -> Some ConsoleKey.Delete
      | "[5~" -> Some ConsoleKey.PageUp
      | "[6~" -> Some ConsoleKey.PageDown
      | "[17~" -> Some ConsoleKey.F6
      | _ -> None
    match key with
    | Some key ->
      TuiInputEvent.Key(restoreKey key)
    | None ->
      keys |> Seq.iter (fun key -> pending.Enqueue(TuiInputEvent.Key key))
      TuiInputEvent.Key first

  let readEscapeSequence first =
    if not Console.KeyAvailable then
      TuiInputEvent.Key first
    else
      let keys = ResizeArray<ConsoleKeyInfo>()
      let text = StringBuilder()
      let mutable isComplete = false
      while Console.KeyAvailable && text.Length < 64 && not isComplete do
        let key = Console.ReadKey true
        keys.Add key
        text.Append key.KeyChar |> ignore
        let sequence = text.ToString()
        isComplete <-
          if sequence.StartsWith("[<", StringComparison.Ordinal) then
            key.KeyChar = 'M' || key.KeyChar = 'm'
          elif sequence.StartsWith("[", StringComparison.Ordinal) then
            Char.IsLetter key.KeyChar || key.KeyChar = '~'
          else
            true
      let sequence = text.ToString()
      match tryParseMouseEvent sequence with
      | Some input -> input
      | None -> restoreEscapeSequence first keys sequence

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
        Some(TuiInputEvent.Key key)
    else
      None

  member _.PutBack input = pending.Enqueue input
