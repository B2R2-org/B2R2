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

let start arbiter (cmdStore: CmdStore) =
  FsReadLine.Console(Prompt, cmdStore.Commands)
  |> cliLoop cmdStore arbiter
