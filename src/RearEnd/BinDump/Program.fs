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

module B2R2.RearEnd.BinDump.Program

open B2R2
open B2R2.BinIR
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinInterface
open B2R2.RearEnd
open B2R2.RearEnd.Printer
open B2R2.RearEnd.BinDump.Helper
open B2R2.RearEnd.BinDump.DisasmLiftHelper

let printFileName filepath =
  [ Green, "["; Yellow, filepath; Green, "]" ] |> Printer.println
  Printer.println ()

let dumpRawBinary (hdl: BinHandle) (opts: BinDumpOpts) =
  let addrRange =
    AddrRange (0UL, uint64 (hdl.FileInfo.BinReader.Bytes.Length))
  if opts.ShowLowUIR then
    printSubsectionTitle ("Disassembly of raw binary")
    Printer.println ""
    printBlkDisasm hdl opts addrRange
    Printer.println ""
  else
    printSectionTitle ("LowUIR of raw binary")
    Printer.println ""
    printBlkLowUIR hdl opts addrRange
    Printer.println ""

let printHexdump (opts: BinDumpOpts) size offset addr (fi: FileInfo) =
  let bytes =
    fi.BinReader.PeekBytes (size, offset)
  let chunkSize = if opts.ShowWide then 32 else 16
  if opts.ShowColor then
    hexdumpColored chunkSize fi.WordSize addr bytes
    |> Array.iter Printer.println
  else
    hexdump chunkSize fi.WordSize addr bytes
    |> Array.iter Printer.print

let dumpHex (opts: BinDumpOpts) secname (fi: FileInfo) =
  match fi with
  | :? ELFFileInfo as fi ->
    match fi.ELF.SecInfo.SecByName.TryFind secname with
    | Some section ->
      printSubsectionTitle ("Contents of section " + section.SecName + ":")
      Printer.println ""
      if section.SecType = ELF.SectionType.SHTNoBits then
        printTwoCols "" "Not found in this file (NOBITS)"
      else
        let size = int section.SecSize
        let offset = int section.SecOffset
        let addr = section.SecAddr
        printHexdump opts size offset addr fi
    | None -> printTwoCols "" "Not found."
  | :? PEFileInfo as fi ->
    match fi.PE.SectionHeaders |> Array.tryFind (fun s -> s.Name = secname) with
    | Some section ->
      printSubsectionTitle ("Contents of section " + section.Name + ":")
      Printer.println ""
      let size = section.VirtualSize
      let offset = section.PointerToRawData
      let addr = fi.BaseAddress + uint64 section.VirtualAddress
      printHexdump opts size offset addr fi
    | None -> printTwoCols "" "Not found."
  | :? MachFileInfo as fi ->
    match fi.Mach.Sections.SecByName.TryFind secname with
    | Some section ->
      printSubsectionTitle ("Contents of section " + section.SecName + ":")
      Printer.println ""
      let size = int section.SecSize
      let offset = int section.SecOffset
      let addr = section.SecAddr
      printHexdump opts size offset addr fi
    | None -> printTwoCols "" "Not found."
  | _ -> Utils.futureFeature ()

let dumpSection hdl (opts: BinDumpOpts) (secname: string) =
  printSectionTitle "Dump a section"
  let section = hdl.FileInfo.GetSections (secname)
  if Seq.isEmpty section then
     printTwoCols "" "Not found."
     Printer.println ""
  else
    section
    |> Seq.iter (fun s ->
      if s.Size > 0UL then
        match s.Kind with
        | SectionKind.ExecutableSection
        | SectionKind.LinkageTableSection ->
          if opts.ShowLowUIR then
            printSubsectionTitle ("LowUIR of section " + s.Name + ":")
            Printer.println ""
            printBlkLowUIR hdl opts (s.ToAddrRange ())
            Printer.println ""
          else
            printSubsectionTitle ("Disassembly of section " + s.Name + ":")
            Printer.println ""
            printBlkDisasm hdl opts (s.ToAddrRange ())
            Printer.println ""
        | _ ->
          dumpHex opts secname hdl.FileInfo
          Printer.println ""
      else
        printTwoCols "" "Empty section."
        Printer.println "")

let dumpAllSections hdl (opts: BinDumpOpts) =
  printSectionTitle "Dump all sections"
  hdl.FileInfo.GetSections ()
  |> Seq.iter (fun s ->
    if s.Size > 0UL then
      match s.Kind with
      | SectionKind.ExecutableSection
      | SectionKind.LinkageTableSection ->
        if opts.ShowLowUIR then
          printSubsectionTitle ("LowUIR of section " + s.Name + ":")
          Printer.println ""
          printBlkLowUIR hdl opts (s.ToAddrRange ())
          Printer.println ""
        else
          printSubsectionTitle ("Disassembly of section " + s.Name + ":")
          Printer.println ""
          printBlkDisasm hdl opts (s.ToAddrRange ())
          Printer.println ""
      | _ ->
        dumpHex opts s.Name hdl.FileInfo
        Printer.println ""
      Printer.println "")

let dumpFile (opts: BinDumpOpts) (filepath: string) =
  opts.ShowAddress <- true
  let hdl =
    BinHandle.Init (opts.ISA,
                    opts.ArchOperationMode,
                    opts.AutoDetect,
                    opts.BaseAddress,
                    filepath)
  printFileName hdl.FileInfo.FilePath
  let isRawBinary =
    match hdl.FileInfo with
    | :? ELFFileInfo | :? PEFileInfo | :? MachFileInfo -> false
    | _ -> true
  if isRawBinary then dumpRawBinary hdl opts
  else
    match opts.InputSecName with
    | Some secname -> dumpSection hdl opts secname
    | None -> dumpAllSections hdl opts

let dumpHexString (opts: BinDumpOpts) =
  opts.ShowSymbols <- false
  let hdl =
    BinHandle.Init (opts.ISA,
                    opts.ArchOperationMode,
                    false,
                    opts.BaseAddress,
                    opts.InputHexStr)
  let leastHexLen =
    match opts.ISA.Arch with
    | Arch.IntelX86 | Arch.IntelX64 -> 1
    | Arch.ARMv7 ->
      match hdl.DefaultParsingContext.ArchOperationMode with
      | ArchOperationMode.ARMMode -> 4
      | ArchOperationMode.ThumbMode -> 2
      | _ -> 4
    | Arch.AARCH32 | Arch.AARCH64 -> 4
    | _ -> 4
  if Array.length opts.InputHexStr % leastHexLen = 0 then
    if opts.ShowLowUIR then
      printSectionTitle ("LowUIR of hexstring")
      let addrRange = AddrRange (0UL, uint64 (opts.InputHexStr.Length))
      printBlkLowUIR hdl opts addrRange
    else
      opts.ShowAddress <- true
      printSectionTitle ("Disassembly of hexstring")
      let addrRange = AddrRange (0UL, uint64 (opts.InputHexStr.Length))
      printBlkDisasm hdl opts addrRange
  else
    Printer.println
      ("The hexstring is invalid in length, must be multiple of "
        + leastHexLen.ToString ())
  Printer.println ""

let [<Literal>] private toolName = "bindump"
let [<Literal>] private usageTail = "<binary file(s)>"

let dump files (opts: BinDumpOpts) =
  if Array.isEmpty opts.InputHexStr then
    match files with
    | [] ->
      printError "File(s) must be given."
      CmdOpts.PrintUsage toolName usageTail Cmd.spec
    | files -> files |> List.iter (dumpFile opts)
  else
    dumpHexString opts

[<EntryPoint>]
let main args =
  let opts = BinDumpOpts ()
  CmdOpts.ParseAndRun dump toolName usageTail Cmd.spec opts args
// vim: set tw=80 sts=2 sw=2:
