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
open B2R2.MiddleEnd.BinEssence

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

  override __.CallBack _ ess _args =
    let fileInfo = ess.BinHandle.BinFile
    let path = ess.BinHandle.BinFile.FilePath
    let isa = ess.BinHandle.ISA
    let machine = isa.Arch |> ISA.ArchToString
    let fmt = ess.BinHandle.BinFile.FileFormat |> FileFormat.toString
    let entry = fileInfo.EntryPoint |> BinFile.EntryPointToString
    let textAddr = fileInfo.TextStartAddr
    let secNum = fileInfo.GetSections () |> Seq.length
    let staticSymNum = fileInfo.GetStaticSymbols () |> Seq.length
    let dynamicSymNum = fileInfo.GetDynamicSymbols () |> Seq.length
    let fileType = fileInfo.FileType |> BinFile.FileTypeToString
    let nx = if fileInfo.IsNXEnabled then "Enabled" else "Disabled"
    [|
       "[*] Binary information:\n"
       sprintf "- Executable Path: %s" path
       sprintf "- Machine: %s" machine
       sprintf "- File Format: %s" fmt
       sprintf "- File Type: %s" fileType
       sprintf "- Start of Text Section Address: 0x%x" textAddr
       sprintf "- Entry Point Address: %s" entry
       sprintf "- Number of Sections: %d" secNum
       sprintf "- Number of Static Symbols: %d" staticSymNum
       sprintf "- Number of Dynamic Symbols: %d" dynamicSymNum
       sprintf "- NX bit: %s" nx
    |]
    |> Array.map OutputNormal

// vim: set tw=80 sts=2 sw=2:
