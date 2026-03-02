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

module internal B2R2.RearEnd.BinExplore.CLI

open B2R2

/// Command specification.
let spec =
  [ Commands.EvalExpr("?", []) :> Commands.ICmd
    Commands.BinInfo()
    Commands.Credits()
    Commands.Demangle()
    Commands.Disasm()
    Commands.HexDump()
    Commands.List()
    Commands.Print()
    Commands.Search()
    Commands.Show()
    Commands.GadgetSearch()
    Commands.ROP() ]

let runCommandLine (cmdStore: CmdStore) arbiter (line: string) =
  match line.Split(' ') |> Array.toList with
  | cmd :: args ->
    let brew = (arbiter: Arbiter<_, _>).GetBinaryBrew()
    cmdStore.Handle(brew, cmd, args)
  | [] -> [||]

let private clearCmdWindow paddingHeight =
  let rows = System.Console.WindowHeight
  for i = rows downto rows - 1 - paddingHeight do
    System.Console.Write $"\x1B[{i};1H\x1B[K"

let private redrawCmdWindow windowHeight prompt (input: string) candidates =
  if windowHeight > 0 then
    clearCmdWindow windowHeight
    System.Console.Write $"{prompt}"
    if Array.isEmpty candidates then System.Console.Write input
    else ()
  else
    ()

let private drawCandidates (candidates: string[]) =
  System.Console.WriteLine()
  for candidate in candidates do
    System.Console.WriteLine candidate
  candidates.Length

let private showCandidates height prompt candidates =
  clearCmdWindow height
  System.Console.Write $"{prompt}"
  let struct (x, y) = System.Console.GetCursorPosition()
  let candidateLineCount = drawCandidates candidates + 1
  let diff =
    if candidateLineCount <= height then 0
    else candidateLineCount - height
  System.Console.SetCursorPosition(x, y - diff)
  candidateLineCount

let private callback =
  let mutable lastWindowHeight = 0
  { new FsReadLine.ICallback with
      member _.OnReadLine line =
        clearCmdWindow lastWindowHeight
        if System.String.IsNullOrWhiteSpace line then
          ()
        else
          System.Console.WriteLine $"{DefaultPrompt}{line}"
          lastWindowHeight <- 0
      member _.OnTabComplete(prompt, input, candidates) =
        match candidates with
        | [||]
        | [| _ |] ->
          redrawCmdWindow lastWindowHeight prompt input candidates
        | _ ->
          let count = showCandidates lastWindowHeight prompt candidates
          lastWindowHeight <- max lastWindowHeight count
      member _.OnClearScreen _ = () }

let private cliPrinter (arbiter: Arbiter<_, _>) (output: OutString) =
  printon output
  output.ToString() |> arbiter.LogString

let rec private cliLoop cmdStore arbiter (console: FsReadLine.Console) =
  match console.ReadLine() with
  | "" ->
    cliLoop cmdStore arbiter console
  | "quit" | "q" | "exit" ->
    (arbiter: Arbiter<_, _>).Terminate()
  | line ->
    runCommandLine cmdStore arbiter line |> Array.iter (cliPrinter arbiter)
    printsn ""
    cliLoop cmdStore arbiter console

let private getDivider () =
  String.replicate System.Console.WindowWidth "━"

let start arbiter (cmdStore: CmdStore) =
  let console = FsReadLine.Console(DefaultPrompt, cmdStore.Commands, callback)
  let div = getDivider ()
  console.UpdatePrompt $"{div}{System.Environment.NewLine}{DefaultPrompt}"
  cliLoop cmdStore arbiter console
