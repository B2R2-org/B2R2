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

namespace B2R2.RearEnd.BinExplorer.Commands

open B2R2.Logging
open B2R2.FrontEnd.BinFile
open B2R2.RearEnd.Utils
open B2R2.RearEnd.BinExplorer

type BinInfo() =
  interface ICmd with

    member _.CmdName = "bininfo"

    member _.CmdAlias = [ "bi" ]

    member _.CmdDescr = "Show the current binary information."

    member _.CmdHelp =
      "Usage: bininfo\n\n\
      Show the current binary information. This command will show some basic\n\
      information such as the entry point address, binary file format, symbol\n\
      numbers, etc."

    member _.SubCommands = []

    member _.CallBack(brew, _args) =
      let file = brew.BinHandle.File
      let isa = brew.BinHandle.File.ISA
      let fmt = brew.BinHandle.File.Format |> FileFormat.toString
      let entry = file.EntryPoint |> String.ofEntryPointOpt
      let nx = if file.IsNXEnabled then "Enabled" else "Disabled"
      [| "[*] Binary information:\n"
         sprintf "- Executable Path: %s" file.Path
         sprintf "- Machine: %s" (isa.ToString())
         sprintf "- File Format: %s" fmt
         sprintf "- Entry Point Address: %s" entry
         sprintf "- NX bit: %s" nx |]
      |> Array.map OutputNormal
