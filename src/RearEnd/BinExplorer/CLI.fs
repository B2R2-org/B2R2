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

module internal B2R2.RearEnd.BinExplorer.CLI

open B2R2
open B2R2.RearEnd.BinExplorer.CmdUtils

let cliPrinter arbiter () (output: OutString) =
  out.PrintLine output
  OutString.toString output |> Protocol.logString arbiter

let handle cmds arbiter (line: string) acc printer =
  match line.Split (' ') |> Array.toList with
  | cmd :: args ->
    let brew = Protocol.getBinaryBrew arbiter
    let acc = Cmd.handle cmds brew cmd args |> Array.fold (printer arbiter) acc
    printer arbiter acc (OutputNormal "")
  | [] -> acc

let rec cliLoop cmds arbiter (console: FsReadLine.Console) =
  let line = console.ReadLine ()
  match line with
  | "" -> cliLoop cmds arbiter console
  | "quit" | "q" | "exit" -> Protocol.terminate arbiter
  | line ->
    handle cmds arbiter line () cliPrinter
    cliLoop cmds arbiter console

let rec noReadLineLoop cmds arbiter =
  System.Console.Write ("B2R2> ")
  let line = System.Console.ReadLine ()
  match line with
  | "" -> noReadLineLoop cmds arbiter
  | "quit" | "q" | "exit" -> Protocol.terminate arbiter
  | line ->
    handle cmds arbiter line () cliPrinter
    noReadLineLoop cmds arbiter

let start enableReadLine arbiter =
  let cmds = CmdSpec.speclist |> CmdMap.build
  if enableReadLine then
    FsReadLine.Console ("B2R2> ", cmds.CmdList)
    |> cliLoop cmds arbiter
  else
    noReadLineLoop cmds arbiter
