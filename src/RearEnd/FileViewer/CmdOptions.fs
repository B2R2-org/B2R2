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

namespace B2R2.RearEnd.FileViewer

open B2R2
open B2R2.RearEnd
open System
open System.Collections.Generic

type FileViewerOpts () =
  inherit CmdOpts ()

  let items = HashSet<DisplayItem> ()

  /// Display items.
  member val DisplayItems = items with get

  /// Specific ISA. This is only meaningful for universal (fat) binaries because
  /// BinHandle will automatically detect file format by default. When a fat
  /// binary is given, we need to choose which architecture to explorer with
  /// this option.
  member val ISA = ISA.DefaultISA with get, set

  /// Base address to use. By default, it is zero (0).
  member val BaseAddress: Addr = 0UL with get, set

  static member private ToThis (opts: CmdOpts) =
    match opts with
    | :? FileViewerOpts as opts -> opts
    | _ -> failwith "Invalid Opts."

  static member private AddOpt (opts: #CmdOpts) item =
    (FileViewerOpts.ToThis opts).DisplayItems.Add item |> ignore
    opts

  /// "-h" or "--help" option.
  static member OptHelp () =
    CmdOpts.New (descr = "Show this usage", help = true, long = "--help")

  /// "-b" or "--base-addr" option for specifying a base address.
  static member OptBaseAddr () =
    let cb opts (arg: string []) =
      (FileViewerOpts.ToThis opts).BaseAddress <- Convert.ToUInt64 (arg.[0], 16)
      opts
    CmdOpts.New (descr = "Specify the base <address> in hex (default=0)",
                 extra = 1, callback = cb, short = "-b", long = "--base-addr")

  /// "-a" or "--all" option for displaying all the file information.
  static member OptAll () =
    let cb opts _ = FileViewerOpts.AddOpt opts DisplayAll
    CmdOpts.New (descr = "Display all the file information",
                 callback = cb, short = "-a", long = "--all")

  /// "-h" or "--file-header" option for displaying the file header.
  static member OptFileHeader () =
    let cb opts _ =
      FileViewerOpts.AddOpt opts DisplayFileHeader
    CmdOpts.New (descr = "Display the file header",
                 callback = cb, short = "-h", long = "--file-header")

  /// "-s" or "--symbols" option for displaying the symbols.
  static member OptSymbols () =
    let cb opts _ =
      FileViewerOpts.AddOpt opts DisplaySymbols
    CmdOpts.New (descr = "Display the symbols",
                 callback = cb, short = "-s", long = "--symbols")

  /// "-f" or "--functions" option for displaying the symbols.
  static member OptFunctions () =
    let cb opts _ =
      FileViewerOpts.AddOpt opts DisplayFunctions
    CmdOpts.New (descr = "Display the function symbols",
                 callback = cb, short = "-f", long = "--functions")

  /// "--program-headers" option for displaying the program headers.
  static member OptProgramHeaders () =
    let cb opts _ =
      FileViewerOpts.AddOpt opts (DisplayELFSpecific ELFDisplayProgramHeader)
    CmdOpts.New (descr = "Display the program headers",
                 callback = cb, long = "--program-headers")

  /// "--section-headers" option for displaying the section headers.
  static member OptSectionHeaders () =
    let cb opts _ =
      FileViewerOpts.AddOpt opts (DisplayELFSpecific ELFDisplaySectionHeader)
    CmdOpts.New (descr = "Display the section headers",
                 callback = cb, long = "--section-headers")

  /// "--section-details" option for displaying the target section
  /// details.
  static member OptSectionDetails () =
    let cb opts (arg: string []) =
      DisplayELFSpecific (ELFDisplaySectionDetails arg.[0])
      |> FileViewerOpts.AddOpt opts
    CmdOpts.New (descr = "Display the <name> section details", extra = 1,
                 callback = cb, long = "--section-details")

  /// "--relocs" option for displaying the relocation section.
  static member OptRelocs () =
    let cb opts _ =
      FileViewerOpts.AddOpt opts (DisplayELFSpecific ELFDisplayRelocations)
    CmdOpts.New (descr = "Display the relocation section",
                 callback = cb, long = "--relocations")

  /// "--plt" option for displaying the PLT.
  static member OptPLT () =
    let cb opts _ =
      FileViewerOpts.AddOpt opts (DisplayELFSpecific ELFDisplayPLT)
    CmdOpts.New (descr = "Display the PLT-GOT information",
                 callback = cb, long = "--plt")

  /// "--ehframe" option for displaying the eh_frame section information.
  static member OptEHFrame () =
    let cb opts _ =
      FileViewerOpts.AddOpt opts (DisplayELFSpecific ELFDisplayEHFrame)
    CmdOpts.New (descr = "Display the eh_frame information",
                 callback = cb, long = "--ehframe")

  /// "-i" or "--isa" option for specifying ISA.
  static member OptISA () =
    let cb opts (arg: string []) =
      (FileViewerOpts.ToThis opts).ISA <- ISA.OfString arg.[0]; opts
    CmdOpts.New (descr = "Specify <ISA> (e.g., x86) for fat binaries",
                 extra = 1, callback = cb, short = "-i", long= "--isa")

[<RequireQualifiedAccess>]
module Cmd =
  let spec: FileViewerOpts FsOptParse.Option list =
    [ CmdOpts.New (descr = "[General options]", dummy = true)
      CmdOpts.New (descr = "", dummy = true)

      FileViewerOpts.OptHelp ()
      CmdOpts.OptVerbose ()
      FileViewerOpts.OptBaseAddr ()
      FileViewerOpts.OptAll ()
      FileViewerOpts.OptFileHeader ()
      FileViewerOpts.OptSymbols ()
      FileViewerOpts.OptFunctions ()

      CmdOpts.New (descr = "", dummy = true)
      CmdOpts.New (descr = "[ELF options]", dummy = true)
      CmdOpts.New (descr = "", dummy = true)

      FileViewerOpts.OptProgramHeaders ()
      FileViewerOpts.OptSectionHeaders ()
      FileViewerOpts.OptSectionDetails ()
      FileViewerOpts.OptRelocs ()
      FileViewerOpts.OptPLT ()
      FileViewerOpts.OptEHFrame ()

      CmdOpts.New (descr = "", dummy = true)
      CmdOpts.New (descr = "[Mach-O options]", dummy = true)
      CmdOpts.New (descr = "", dummy = true)
      FileViewerOpts.OptISA () ]
