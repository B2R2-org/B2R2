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

namespace B2R2.RearEnd.BinExplorer

open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.RearEnd.StringUtils

type CmdBinInfo () =
  inherit Cmd ()

  override __.CmdName = "bininfo"

  override __.CmdAlias = [ "bi" ]

  override __.CmdDescr = "Show the current binary information."

  override __.CmdHelp =
    "Usage: bininfo\n\n\
     Show the current binary information. This command will show some basic\n\
     information such as the entry point address, binary file format, symbol \n\
     numbers, etc."

  override __.SubCommands = []

  override __.CallBack _ brew _args =
    let file = brew.BinHandle.File
    let isa = brew.BinHandle.File.ISA
    let machine = isa.Arch |> ISA.ArchToString
    let fmt = brew.BinHandle.File.Format |> FileFormat.toString
    let entry = file.EntryPoint |> entryPointToString
    let secNum = file.GetSections () |> Seq.length
    let staticSymNum = file.GetStaticSymbols () |> Seq.length
    let dynamicSymNum = file.GetDynamicSymbols () |> Seq.length
    let fileType = file.Type |> FileType.toString
    let nx = if file.IsNXEnabled then "Enabled" else "Disabled"
    [| "[*] Binary information:\n"
       sprintf "- Executable Path: %s" file.Path
       sprintf "- Machine: %s" machine
       sprintf "- File Format: %s" fmt
       sprintf "- File Type: %s" fileType
       sprintf "- Entry Point Address: %s" entry
       sprintf "- Number of Sections: %d" secNum
       sprintf "- Number of Static Symbols: %d" staticSymNum
       sprintf "- Number of Dynamic Symbols: %d" dynamicSymNum
       sprintf "- NX bit: %s" nx |]
    |> Array.map OutputNormal

// vim: set tw=80 sts=2 sw=2:
