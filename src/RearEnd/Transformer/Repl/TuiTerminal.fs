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
open System.Text

/// A pointer event reported by a terminal using the SGR mouse protocol.
type TuiMouseEvent =
  { Button: int
    Column: int
    Row: int
    IsRelease: bool }

[<RequireQualifiedAccess>]
type TuiInputEvent =
  | Key of ConsoleKeyInfo
  | Mouse of TuiMouseEvent

module TransformerTuiTerminal =
  module private Ansi =
    let private csi = "\x1b["
    let enterAlternateScreen = csi + "?1049h"
    let leaveAlternateScreen = csi + "?1049l"
    let disableAutoWrap = csi + "?7l"
    let enableAutoWrap = csi + "?7h"
    let enableMouseClickTracking = csi + "?1000h"
    let disableMouseClickTracking = csi + "?1000l"
    let enableSgrMouseEncoding = csi + "?1006h"
    let disableSgrMouseEncoding = csi + "?1006l"
    let hideCursor = csi + "?25l"
    let showCursor = csi + "?25h"
    let clearScreen = csi + "2J"
    let cursorHome = csi + "H"
    let moveCursor row column = $"{csi}{row};{column}H"

  let private enterTuiScreen =
    Ansi.enterAlternateScreen
    + Ansi.disableAutoWrap
    + Ansi.enableMouseClickTracking
    + Ansi.enableSgrMouseEncoding
    + Ansi.clearScreen
    + Ansi.cursorHome

  let private leaveTuiScreen =
    Ansi.showCursor
    + Ansi.enableAutoWrap
    + Ansi.disableMouseClickTracking
    + Ansi.disableSgrMouseEncoding
    + Ansi.leaveAlternateScreen

  let mutable private previousFrameLines: string[] = [||]

  let isInteractive () =
    not Console.IsInputRedirected && not Console.IsOutputRedirected

  let tryParseInputEvent (sequence: string) =
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
            { Button = button
              Column = column
              Row = row
              IsRelease = terminator = 'm' }
            |> TuiInputEvent.Mouse
            |> Some
          | _ ->
            None
        | _ ->
          None

  let dimensions () =
    try max 1 Console.WindowWidth, max 1 Console.WindowHeight
    with _ -> 80, 24

  let enter () =
    let originalEncoding = Console.OutputEncoding
    let originalControlC = Console.TreatControlCAsInput
    Console.OutputEncoding <- Encoding.UTF8
    Console.TreatControlCAsInput <- true
    previousFrameLines <- [||]
    Console.Write enterTuiScreen
    Console.Out.Flush()
    fun () ->
      previousFrameLines <- [||]
      Console.Write leaveTuiScreen
      Console.Out.Flush()
      Console.TreatControlCAsInput <- originalControlC
      Console.OutputEncoding <- originalEncoding

  let draw busy (frame: TransformerTuiFrame) =
    let visibility = if busy then Ansi.hideCursor else Ansi.showCursor
    let cursor = Ansi.moveCursor frame.CursorRow frame.CursorColumn
    let lines = frame.Lines
    let redrawAll = lines.Length <> previousFrameLines.Length
    let output = StringBuilder Ansi.hideCursor
    lines
    |> Array.iteri (fun index line ->
      if redrawAll || previousFrameLines[index] <> line then
        output.Append(Ansi.moveCursor (index + 1) 1).Append(line) |> ignore
      else
        ())
    previousFrameLines <- lines
    output.Append(cursor).Append(visibility) |> ignore
    Console.Write(output.ToString())
    Console.Out.Flush()
