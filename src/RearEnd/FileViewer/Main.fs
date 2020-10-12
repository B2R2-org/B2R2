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

module B2R2.RearEnd.FileViewer.Main

open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinInterface
open B2R2.RearEnd

let dumpBasic (fi: FileInfo) =
  printfn "## Basic Information"
  printfn "- Format       : %s" <| FileFormat.toString fi.FileFormat
  printfn "- Architecture : %s" <| ISA.ArchToString fi.ISA.Arch
  printfn "- Endianness   : %s" <| Endian.toString fi.ISA.Endian
  printfn "- Word size    : %d bit" <| WordSize.toRegType fi.WordSize
  printfn "- File type    : %s" <| FileInfo.FileTypeToString fi.FileType
  printfn "- Entry point  : %s" <| FileInfo.EntryPointToString fi.EntryPoint
  printfn ""

let dumpSecurity (fi: FileInfo) =
  printfn "## Security Information"
  printfn "- Stripped binary  : %b" fi.IsStripped
  printfn "- DEP (NX) enabled : %b" fi.IsNXEnabled
  printfn "- Relocatable (PIE): %b" fi.IsRelocatable
  printfn ""

let dumpFileHeader (fi: FileInfo) (opts: CmdOptions.FileViewerOpts) =
  printfn "## File Header"
  match fi with
  | :? ELFFileInfo as fi -> ELFViewer.dumpFileHeader fi opts
  | :? PEFileInfo as fi -> PEViewer.dumpFileHeader fi opts
  | :? MachFileInfo as fi -> MachViewer.dumpFileHeader fi opts
  | _ -> printfn "Not supported format"
  printfn ""

let dumpSections (fi: FileInfo) (opts: CmdOptions.FileViewerOpts) =
  printfn "## Section Information"
  match fi with
  | :? ELFFileInfo as fi -> ELFViewer.dumpSections fi opts
  | :? PEFileInfo as fi -> PEViewer.dumpSections fi opts
  | :? MachFileInfo as fi -> MachViewer.dumpSections fi opts
  | _ -> printfn "Not supported format"
  printfn ""

let dumpTextSection (fi: FileInfo) (opts: CmdOptions.FileViewerOpts) =
  printfn "## Text Section"
  if Seq.isEmpty <| fi.GetTextSections () then
    printfn "- Not found"
  else
    fi.GetTextSections ()
    |> Seq.iter (fun s ->
      printfn "- Start address : %s"
        <| Helper.addrToString fi.WordSize s.Address
      printfn "- End address   : %s"
        <| Helper.addrToString fi.WordSize (s.Address + s.Size)
      printfn "- Size: %d" s.Size
      printfn "")
    match fi with
    | :? ELFFileInfo as fi -> ELFViewer.dumpTextSection fi opts
    | :? PEFileInfo as fi -> PEViewer.dumpTextSection fi opts
    | :? MachFileInfo as fi -> MachViewer.dumpTextSection fi opts
    | _ -> printfn "Not supported format"
    printfn ""

let dumpSectionDetails (fi: FileInfo) (opts: CmdOptions.FileViewerOpts) =
  printfn "## Section Details"
  let sections = fi.GetSections opts.DisplayTargets.["d"].[0]
  if Seq.isEmpty sections then
    printfn "- Not found"
  else
    sections
    |> Seq.iter (fun s ->
      printfn "- Start address : %s"
        <| Helper.addrToString fi.WordSize s.Address
      printfn "- End address   : %s"
        <| Helper.addrToString fi.WordSize (s.Address + s.Size)
      printfn "- Size: %d" s.Size
      printfn "")
    match fi with
    | :? ELFFileInfo as fi -> ELFViewer.dumpSectionDetails fi opts
    | :? PEFileInfo as fi -> PEViewer.dumpSectionDetails fi opts
    | :? MachFileInfo as fi -> MachViewer.dumpSectionDetails fi opts
    | _ -> printfn "Not supported format"
  printfn ""

let dumpSegments (fi: FileInfo) (opts: CmdOptions.FileViewerOpts) =
  printfn "## Segment Information"
  match fi with
  | :? ELFFileInfo as fi -> ELFViewer.dumpSegments fi opts
  | :? PEFileInfo as fi -> PEViewer.dumpSegments fi opts
  | :? MachFileInfo as fi -> MachViewer.dumpSegments fi opts
  | _ -> printfn "Not supported format"
  printfn ""

let dumpSymbols (fi: FileInfo) (opts: CmdOptions.FileViewerOpts) =
  printfn "## Symbol Information"
  match fi with
  | :? ELFFileInfo as fi -> ELFViewer.dumpSymbols fi opts
  | :? PEFileInfo as fi -> PEViewer.dumpSymbols fi opts
  | :? MachFileInfo as fi -> MachViewer.dumpSymbols fi opts
  | _ -> printfn "Not supported format"
  printfn ""

let dumpRelocs (fi: FileInfo) (opts: CmdOptions.FileViewerOpts) =
  printfn "## Relocation Information"
  match fi with
  | :? ELFFileInfo as fi -> ELFViewer.dumpRelocs fi opts
  | :? PEFileInfo as fi -> PEViewer.dumpRelocs fi opts
  | :? MachFileInfo as fi -> MachViewer.dumpRelocs fi opts
  | _ -> printfn "Not supported format"
  printfn ""

let dumpFunctions (fi: FileInfo) (opts: CmdOptions.FileViewerOpts) =
  printfn "## Functions Information"
  match fi with
  | :? ELFFileInfo as fi -> ELFViewer.dumpFunctions fi opts
  | :? PEFileInfo as fi -> PEViewer.dumpFunctions fi opts
  | :? MachFileInfo as fi -> MachViewer.dumpFunctions fi opts
  | _ -> printfn "Not supported format"
  printfn ""

let dumpLinkageTable (fi: FileInfo) (opts: CmdOptions.FileViewerOpts) =
  printfn "## Linkage Table Information"
  match fi with
  | :? ELFFileInfo as fi -> ELFViewer.dumpLinkageTable fi opts
  | :? PEFileInfo as fi -> PEViewer.dumpLinkageTable fi opts
  | :? MachFileInfo as fi -> MachViewer.dumpLinkageTable fi opts
  | _ -> printfn "Not supported format"
  printfn ""

let dumpFile (opts: CmdOptions.FileViewerOpts) (filepath: string) =
  let hdl = BinHandle.Init (opts.ISA, opts.BaseAddress, filepath)
  let displayTargets = opts.DisplayTargets
  let fi = hdl.FileInfo
  printfn "# %s" fi.FilePath
  printfn ""

  if displayTargets.ContainsKey "a" then
    dumpBasic fi
    dumpSecurity fi
    dumpFileHeader fi opts
    dumpSections fi opts
    dumpSegments fi opts
    dumpSymbols fi opts
    dumpRelocs fi opts
    dumpFunctions fi opts
    dumpLinkageTable fi opts
  else
    if displayTargets.ContainsKey "e" then
      dumpFileHeader fi opts
      dumpSections fi opts
      dumpSegments fi opts
    else
      if displayTargets.ContainsKey "B" then
        dumpBasic fi
        dumpSecurity fi
      if displayTargets.ContainsKey "f" then
        dumpFileHeader fi opts
      if displayTargets.ContainsKey "S" then
        dumpSections fi opts
      if displayTargets.ContainsKey "T" then
        dumpTextSection fi opts
      if displayTargets.ContainsKey "d" then
        dumpSectionDetails fi opts
      if displayTargets.ContainsKey "p" then
        dumpSegments fi opts
      if displayTargets.ContainsKey "s" then
        dumpSymbols fi opts
      if displayTargets.ContainsKey "r" then
        dumpRelocs fi opts
      if displayTargets.ContainsKey "F" then
        dumpFunctions fi opts
      if displayTargets.ContainsKey "L" then
        dumpLinkageTable fi opts

#if false
  let fi = fi :?> ELFFileInfo
  fi.ELF.ExceptionFrame
  |> List.iter (fun cfi ->
    printfn "CIE: %x \"%s\" cf=%d df=%d"
      cfi.CIERecord.Version
      cfi.CIERecord.AugmentationString
      cfi.CIERecord.CodeAlignmentFactor
      cfi.CIERecord.DataAlignmentFactor
    cfi.FDERecord
    |> Array.iter (fun fde ->
      printfn "  FDE: %x..%x (%x)"
        fde.PCBegin
        fde.PCEnd
        (if fde.LSDAPointer.IsNone then 0UL else fde.LSDAPointer.Value)
      fde.UnwindingInfo |> List.iter (fun i ->
        printfn "%x; %s; %s"
          i.Location
          (ELF.CanonicalFrameAddress.toString fi.RegisterBay i.CanonicalFrameAddress)
          (i.Rule |> Map.fold (fun s k v ->
                      match k with
                      | ELF.ReturnAddress -> s + "(ra:" + ELF.Action.toString v + ")"
                      | ELF.NormalReg rid -> s + "(" + fi.RegisterBay.RegIDToString rid + ":" + ELF.Action.toString v + ")") ""))

      )
    )
#endif

let dump files opts =
  files |> List.iter (dumpFile opts)

[<EntryPoint>]
let main args =
  let opts = CmdOptions.FileViewerOpts ()
  CmdOpts.ParseAndRun dump "<binary file(s)>" CmdOptions.spec opts args
