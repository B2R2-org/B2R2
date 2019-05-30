(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>

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

module B2R2.Utilities.FileViewer.Main

open B2R2
open B2R2.BinFile
open B2R2.FrontEnd
open B2R2.Utilities
open B2R2.Utilities.FileViewer.CmdOptions

let dumpBasic (fi: FileInfo) =
  printfn "## Basic Information"
  printfn "- Format       : %s" <| FileFormat.toString fi.FileFormat
  printfn "- Architecture : %s" <| ISA.ArchToString fi.ISA.Arch
  printfn "- Endianness   : %s" <| Endian.toString fi.ISA.Endian
  printfn "- Word size    : %d bit" <| WordSize.toRegType fi.ISA.WordSize
  printfn "- File type    : %s" <| FileInfo.FileTypeToString fi.FileType
  printfn "- Entry point  : 0x%x" fi.EntryPoint
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
  Seq.append (fi.GetStaticSymbols ()) (fi.GetDynamicSymbols true)
  |> Seq.filter (fun s -> s.Kind = SymbolKind.FunctionType)
  |> Seq.iter (fun s -> printfn "- %s: %s" (addrToString s.Address) s.Name)

let dumpFile (opts: FileViewerOpts) (filepath: string) =
  let hdl = BinHandler.Init (opts.ISA, filepath)
  let fi = hdl.FileInfo
  let addrToString =
    if fi.WordSize = WordSize.Bit32 then fun (a: Addr) -> a.ToString ("X8")
    else fun (a: Addr) -> a.ToString ("X16")
  printfn "# %s" fi.FilePath
  printfn ""
  dumpBasic fi
  dumpSecurity fi
  dumpSections fi addrToString
  dumpSymbols fi addrToString opts.Verbose
  dumpLinkageTable fi addrToString
  dumpFunctions fi addrToString

let dump files opts =
  files |> List.iter (dumpFile opts)

[<EntryPoint>]
let main args =
  let opts = FileViewerOpts ()
  CmdOpts.ParseAndRun dump "<binary file(s)>" CmdOptions.spec opts args
