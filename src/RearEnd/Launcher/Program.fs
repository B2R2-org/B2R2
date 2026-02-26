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

module B2R2.RearEnd.Launcher

open System
open System.Reflection
open B2R2

let showUsage () =
  printsn
  <| $"""
          _..-..._
      .;'          ';.
     ;' *      *     ';           888888b.           8888888b.
 .. ,,                ,, ..       888  "88b          888   "88b
;MMcl                  l:'':      888  .88P  .oPYo.  888    888 .oPYo.
MMMc.dooooooooooooooood.:  |      8888888K.      `8  888   d88P     `8
:MMcdMMMMMMMMMMMMMMMMMMd:  ;      888  "Y88b    oP'  8888888P"     oP'
 .\c.WMMMMMWWMMMMMMWMMW. :/       888    888 .oP'    888 T88b   .oP'
     'XMMMMX XMMMMX XM/           888   d88P 8'      888  T88b  8'
       cKMMMMMMMMMMKc             8888888P"  8ooooo  888   T88b 8ooooo
         `~co@@ocd'

B2R2 is the next-generation binary analysis framework that runs purely
on .NET. This is the B2R2 launcher, which is a .NET CLI tool that can
invoke various tools provided by our framework. To know more about
B2R2, please visit our official website: https://b2r2.org/."""
  printcn
  <| ColoredString().Add(NoColor, Environment.NewLine + "Usage: ")
                    .Add(DarkCyan, "b2r2")
                    .Add(DarkYellow, " [app name]")
  printsn """
[Available Apps]
"""
  printcn
  <| ColoredString().Add(NoColor, "- ")
                    .Add(DarkYellow, "scan")
                    .Add(NoColor, " (a.k.a. binscan)")
  printsn """
  This is a file format scanner that is similar to readelf or otool.
  You can read various file format information using this app. To
  learn more about the tool, type the following command:

  $ b2r2 scan --help
"""
  printcn
  <| ColoredString().Add(NoColor, "- ")
                    .Add(DarkYellow, "disasm")
                    .Add(NoColor, " (a.k.a. bindisasm)")
  printsn """
  This is a linear-sweep disassembler similar to objdump, although
  this app is more powerful and versatile. To learn more about the
  tool, type the following command:

  $ b2r2 disasm --help
"""
  printcn
  <| ColoredString().Add(NoColor, "- ")
                    .Add(DarkYellow, "explore")
                    .Add(NoColor, " (a.k.a. binexplore)")
  printsn """
  This is a recursive-descent disassembler that provides a web-based
  GUI as well as its own CLI terminal. To learn more about the tool,
  type the following command:

  $ b2r2 explore --help
"""
  printcn
  <| ColoredString().Add(NoColor, "- ")
                    .Add(DarkYellow, "repl")
  printsn """
  This is a REPL (Read Evaluate Print Loop) for our binary IR as well
  as binary assembly languages. To learn more about the tool type the
  following command:

  $ b2r2 repl --help
"""
  printcn
  <| ColoredString().Add(NoColor, "- ")
                    .Add(DarkYellow, "asm")
                     .Add(NoColor, " (a.k.a. assembler)")
  printsn """
  This is a simple cross-platform assembler. To learn more about the
  tool, type the following command:

  $ b2r2 asm --help
"""

let printMyVersion () =
  let asm = Assembly.GetEntryAssembly()
  let attr = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
  printsn <| "v" + attr.InformationalVersion.ToString()

let handleCommands (cmd: string) (rest: string[]) =
  match cmd.ToLowerInvariant() with
  | "help" | "--help" | "-h" ->
    showUsage (); 0
  | "version" | "--version" | "-v" ->
    printMyVersion (); 0
  | "binscan" | "scan" ->
    BinScan.Program.main rest
  | "bindisasm" | "disasm" ->
    BinDisasm.Program.main rest
  | "binexplore" | "explore" ->
    BinExplorer.Program.main rest
  | "repl" ->
    Repl.Program.main rest
  | "assembler" | "asm" ->
    Assembler.Program.main rest
  | _ ->
    Terminator.futureFeature ()

[<EntryPoint>]
let main argv =
  if argv.Length = 0 then showUsage (); 1
  else handleCommands argv[0] argv[1..]
