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

open System.Reflection
open B2R2
open B2R2.RearEnd.Utils

let showUsage () =
  Printer.PrintToConsole $"""
         ''''''''''
      .;'          ';.
     ;' o      o     ';           888888b.           8888888b.
 .. ,,                ,, ..       888  "88b          888   "88b
;''cl                  l:MMO      888  .88P  .oPYo.  888    888 .oPYo.
l  c.dooooooooooooooood.:MMM      8888888K.      `8  888   d88P     `8
:  cdMMMMMMMMMMMMMMMMMMd:MMk      888  "Y88b    oP'  8888888P"     oP'
 .. .WMMMMMWWMMMMMMWMMW. :/       888    888 .oP'    888 T88b   .oP'
     'XMMMMl.MMMMMX.xX'           888   d88P 8'      888  T88b  8'
       cKMMMMMMMMMMKc             8888888P"  8ooooo  888   T88b 8ooooo
         `dcoddocd'{"\n"}
B2R2 is the next-generation binary reversing framework that runs
purely on .NET, that is it runs on any platform that .NET supports.
This is the B2R2 launcher, which is a .NET tool that can invoke
various tools provided by our framework. To know more about B2R2,
please visit our official website: https://b2r2.org/.{"\n"}
Usage: b2r2 [app name]{"\n"}
[Available Applications]{"\n"}
- file (a.k.a. peek, fileview){"\n"}
  This is a file format reader that is similar to readelf or otool.
  You can read various file format information using this app. To
  learn more about the tool, type the following command:{"\n"}
  $ b2r2 file --help{"\n"}
- dump (a.k.a. disasm, bindump){"\n"}
  This is a linear-sweep disassembler similar to objdump, although
  this app is more powerful and versatile. To learn more about the
  tool, type the following command:{"\n"}
  $ b2r2 dump --help{"\n"}
- explore (a.k.a. binexplorer, analyze){"\n"}
  This is a recursive-descent disassembler that provides a web-based
  GUI as well as its own CLI terminal. To learn more about the tool,
  type the following command:{"\n"}
  $ b2r2 explore --help{"\n"}
- repl{"\n"}
  This is a REPL (Read Evaluate Print Loop) for our binary IR as well
  as binary assembly languages. To learn more about the tool type the
  following command:{"\n"}
  $ b2r2 repl --help{"\n"}
- asm (a.k.a. assembler){"\n"}
  This is a simple cross-platform assembler. To learn more about the
  tool, type the following command:{"\n"}
  $ b2r2 asm --help
"""

let printMyVersion () =
  let asm = Assembly.GetEntryAssembly()
  let attr = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
  attr.InformationalVersion.ToString()
  |> Printer.PrintToConsole

let handleCommands (cmd: string) (rest: string []) =
  match cmd.ToLowerInvariant() with
  | "help" | "--help" | "-h" -> showUsage (); 0
  | "fileviewer" | "file" | "fileview" | "peek" -> FileViewer.Program.main rest
  | "bindump" | "disasm" | "dump" | "disas" | "dis" -> BinDump.Program.main rest
  | "binexplorer" | "explore" | "binexplore" | "analyze" ->
    BinExplorer.Program.main rest
  | "repl" -> Repl.Program.main rest
  | "assembler" | "asm" -> Assembler.Program.main rest
  | _ -> Terminator.futureFeature ()

[<EntryPoint>]
let main argv =
  if argv.Length = 0 then showUsage (); 1
  else handleCommands argv[0] argv[1..]
