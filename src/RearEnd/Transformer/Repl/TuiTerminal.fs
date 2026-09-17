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
open System.Diagnostics
open System.Runtime.InteropServices
open System.Text

module TransformerTuiTerminal =
  let private enterAlternateScreen = "\x1b[?1049h\x1b[?7l\x1b[2J\x1b[H"
  let private leaveAlternateScreen = "\x1b[?25h\x1b[?7h\x1b[?1049l"
  let mutable private previousFrameLines: string[] = [||]

  let private runClipboardProcess file arguments (input: string option) =
    try
      let startInfo = ProcessStartInfo()
      startInfo.FileName <- file
      startInfo.Arguments <- arguments
      startInfo.CreateNoWindow <- true
      startInfo.UseShellExecute <- false
      startInfo.RedirectStandardOutput <- Option.isNone input
      startInfo.RedirectStandardInput <- Option.isSome input
      let child = Process.Start startInfo
      match input with
      | Some text ->
        child.StandardInput.Write text
        child.StandardInput.Close()
        if child.WaitForExit 1000 && child.ExitCode = 0 then Some ""
        else None
      | None ->
        let output = child.StandardOutput.ReadToEnd()
        if child.WaitForExit 1000 && child.ExitCode = 0 then Some output
        else None
    with _ ->
      None

  let private windowsClipboardRead () =
    let arguments = "-NoProfile -Command Get-Clipboard -Raw"
    runClipboardProcess "powershell.exe" arguments
      None

  let private windowsClipboardWrite text =
    let command = "-NoProfile -Command [Console]::In.ReadToEnd()|Set-Clipboard"
    runClipboardProcess "powershell.exe" command (Some text) |> Option.isSome

  let tryReadClipboard () =
    if RuntimeInformation.IsOSPlatform OSPlatform.Windows then
      windowsClipboardRead ()
    elif RuntimeInformation.IsOSPlatform OSPlatform.OSX then
      runClipboardProcess "pbpaste" "" None
    else
      runClipboardProcess "wl-paste" "--no-newline" None
      |> Option.orElseWith (fun () ->
        runClipboardProcess "xclip" "-selection clipboard -o" None)
      |> Option.orElseWith (fun () ->
        runClipboardProcess "xsel" "--clipboard --output" None)

  let tryWriteClipboard text =
    if RuntimeInformation.IsOSPlatform OSPlatform.Windows then
      windowsClipboardWrite text
    elif RuntimeInformation.IsOSPlatform OSPlatform.OSX then
      runClipboardProcess "pbcopy" "" (Some text) |> Option.isSome
    else
      runClipboardProcess "wl-copy" "" (Some text)
      |> Option.orElseWith (fun () ->
        runClipboardProcess "xclip" "-selection clipboard" (Some text))
      |> Option.orElseWith (fun () ->
        runClipboardProcess "xsel" "--clipboard --input" (Some text))
      |> Option.isSome

  let isInteractive () =
    not Console.IsInputRedirected && not Console.IsOutputRedirected

  let dimensions () =
    try max 1 Console.WindowWidth, max 1 Console.WindowHeight
    with _ -> 80, 24

  let enter () =
    let originalEncoding = Console.OutputEncoding
    let originalControlC = Console.TreatControlCAsInput
    Console.OutputEncoding <- Encoding.UTF8
    Console.TreatControlCAsInput <- true
    previousFrameLines <- [||]
    Console.Write enterAlternateScreen
    Console.Out.Flush()
    fun () ->
      previousFrameLines <- [||]
      Console.Write leaveAlternateScreen
      Console.Out.Flush()
      Console.TreatControlCAsInput <- originalControlC
      Console.OutputEncoding <- originalEncoding

  let private frameLines (content: string) =
    let home = "\x1b[H"
    let content =
      if content.StartsWith home then content[home.Length..] else content
    content.Split '\n'

  let draw busy frame =
    let visibility = if busy then "\x1b[?25l" else "\x1b[?25h"
    let cursor = $"\x1b[{frame.CursorRow};{frame.CursorColumn}H"
    let lines = frameLines frame.Content
    let redrawAll = lines.Length <> previousFrameLines.Length
    Console.Write "\x1b[?25l"
    lines
    |> Array.iteri (fun index line ->
      if redrawAll || previousFrameLines[index] <> line then
        Console.Write($"\x1b[{index + 1};1H{line}")
      else
        ())
    previousFrameLines <- lines
    Console.Write(cursor + visibility)
    Console.Out.Flush()
