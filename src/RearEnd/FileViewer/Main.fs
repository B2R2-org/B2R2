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
open B2R2.FrontEnd.BinHandleNS
open B2R2.RearEnd

let dumpBasic (fi: FileInfo) =
  printfn "## Basic Information"
  printfn "- Format       : %s" <| FileFormat.toString fi.FileFormat
  printfn "- Architecture : %s" <| ISA.ArchToString fi.ISA.Arch
  printfn "- Endianness   : %s" <| Endian.toString fi.ISA.Endian
  printfn "- Word size    : %d bit" <| WordSize.toRegType fi.ISA.WordSize
  printfn "- File type    : %s" <| FileInfo.FileTypeToString fi.FileType
  printfn "- Entry point  : %s" <| FileInfo.EntryPointToString fi.EntryPoint
  printfn ""

let dumpSecurity (fi: FileInfo) =
  printfn "## Security Information"
  printfn "- Stripped binary  : %b" fi.IsStripped
  printfn "- DEP (NX) enabled : %b" fi.IsNXEnabled
  printfn "- Relocatable (PIE): %b" fi.IsRelocatable
  printfn ""

let dumpSections (fi: FileInfo) addrToString =
  printfn "## Section Information"
  fi.GetSections ()
  |> Seq.iteri (fun idx s ->
       printfn "%2d. %s:%s [%s]"
        idx
        (addrToString s.Address)
        (addrToString (s.Address + s.Size))
        s.Name)
  printfn ""

let dumpSegments (fi: FileInfo) addrToString =
  printfn "## Segment Information"
  fi.GetSegments ()
  |> Seq.iteri (fun idx s ->
    printfn "%2d. %s:%s [%s]"
      idx
      (addrToString s.Address)
      (addrToString (s.Address + s.Size))
      (FileInfo.PermissionToString s.Permission))
  printfn ""

let targetString s =
  match s.Target with
  | TargetKind.StaticSymbol -> "(s)"
  | TargetKind.DynamicSymbol -> "(d)"
  | _ -> failwith "Invalid symbol target kind."

let dumpSymbols (fi: FileInfo) addrToString dumpAll =
  let lib s = if System.String.IsNullOrWhiteSpace s then "" else " @ " + s
  let name (s: Symbol) = if s.Name.Length > 0 then " " + s.Name else ""
  let filterNoType (s: Symbol) =
    s.Target = TargetKind.DynamicSymbol
    || (s.Kind <> SymbolKind.NoType && s.Name.Length > 0)
  printfn "## Symbol Information (s: static / d: dynamic)"
  fi.GetSymbols ()
  |> (fun symbs -> if dumpAll then symbs else Seq.filter filterNoType symbs)
  |> Seq.sortBy (fun s -> s.Name)
  |> Seq.sortBy (fun s -> s.Address)
  |> Seq.sortBy (fun s -> s.Target)
  |> Seq.iter (fun s ->
       printfn "- %s %s%s%s"
        (targetString s) (addrToString s.Address) (name s) (lib s.LibraryName))
  printfn ""

let dumpRelocs (fi: FileInfo) addrToString =
  printfn "## Relocation Information"
  fi.GetRelocationSymbols ()
  |> Seq.sortBy (fun s -> s.Address)
  |> Seq.iter (fun r ->
    printfn "- (%d) %s: %s%s"
      (int r.Kind)
      (addrToString r.Address)
      r.Name
      (if r.LibraryName = "" then "" else " @ " + r.LibraryName))
  printfn ""

let dumpIfNotEmpty s =
  if System.String.IsNullOrEmpty s then "" else "@" + s

let dumpLinkageTable (fi: FileInfo) addrToString =
  printfn "## Linkage Table (PLT -> GOT) Information"
  fi.GetLinkageTableEntries ()
  |> Seq.iter (fun a ->
       printfn "- %s -> %s %s%s"
        (addrToString a.TrampolineAddress)
        (addrToString a.TableAddress)
        a.FuncName
        (dumpIfNotEmpty a.LibraryName))
  printfn ""

let dumpFunctions (fi: FileInfo) addrToString =
  printfn "## Functions"
  fi.GetFunctionSymbols ()
  |> Seq.iter (fun s -> printfn "- %s: %s" (addrToString s.Address) s.Name)

let dumpFile (opts: CmdOptions.FileViewerOpts) (filepath: string) =
  let hdl = BinHandle.Init (opts.ISA, opts.BaseAddress, filepath)
  let fi = hdl.FileInfo
  let addrToString = Addr.toString hdl.ISA.WordSize
  printfn "# %s" fi.FilePath
  printfn ""
  dumpBasic fi
  dumpSecurity fi
  dumpSections fi addrToString
  dumpSegments fi addrToString
  dumpSymbols fi addrToString opts.Verbose
  dumpRelocs fi addrToString
  dumpLinkageTable fi addrToString
  dumpFunctions fi addrToString
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
