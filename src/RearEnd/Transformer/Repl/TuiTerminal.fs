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

module TransformerTuiTerminal =
  module private Ansi =
    let private csi = "\x1b["
    let enterAlternateScreen = csi + "?1049h"
    let leaveAlternateScreen = csi + "?1049l"
    let disableAutoWrap = csi + "?7l"
    let enableAutoWrap = csi + "?7h"
    let enableMouseButtonTracking = csi + "?1002h"
    let disableMouseButtonTracking = csi + "?1002l"
    let enableSgrMouseEncoding = csi + "?1006h"
    let disableSgrMouseEncoding = csi + "?1006l"
    let hideCursor = csi + "?25l"
    let showCursor = csi + "?25h"
    let clearScreen = csi + "2J"
    let cursorHome = csi + "H"
    let moveCursor row column = $"{csi}{row};{column}H"

    let copyToClipboard (text: string) =
      let bytes = Encoding.UTF8.GetBytes text
      let encoded = Convert.ToBase64String bytes
      $"\x1b]52;c;{encoded}\a"

  let private enterTuiScreen useSgrMouse =
    let mouse =
      if useSgrMouse then
        Ansi.enableMouseButtonTracking + Ansi.enableSgrMouseEncoding
      else
        ""
    Ansi.enterAlternateScreen
    + Ansi.disableAutoWrap
    + mouse
    + Ansi.clearScreen
    + Ansi.cursorHome

  let private leaveTuiScreen useSgrMouse =
    let mouse =
      if useSgrMouse then
        Ansi.disableMouseButtonTracking + Ansi.disableSgrMouseEncoding
      else
        ""
    Ansi.showCursor
    + Ansi.enableAutoWrap
    + mouse
    + Ansi.leaveAlternateScreen

  let mutable private previousFrameLines: string[] = [||]

  let isInteractive () =
    not Console.IsInputRedirected && not Console.IsOutputRedirected

  let tryCopyText text =
    if String.IsNullOrEmpty text then
      false
    elif OperatingSystem.IsWindows() then
      TransformerTuiWindowsConsole.tryCopyText text
    else
      try
        Console.Write(Ansi.copyToClipboard text)
        Console.Out.Flush()
        true
      with _ ->
        false

  let dimensions () =
    try max 1 Console.WindowWidth, max 1 Console.WindowHeight
    with _ -> 80, 24

  let enter () =
    let originalEncoding = Console.OutputEncoding
    let originalControlC = Console.TreatControlCAsInput
    Console.OutputEncoding <- Encoding.UTF8
    Console.TreatControlCAsInput <- true
    let nativeMouse = TransformerTuiWindowsConsole.enable ()
    previousFrameLines <- [||]
    Console.Write(enterTuiScreen (not nativeMouse))
    Console.Out.Flush()
    fun () ->
      previousFrameLines <- [||]
      Console.Write(leaveTuiScreen (not nativeMouse))
      Console.Out.Flush()
      TransformerTuiWindowsConsole.restore ()
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
