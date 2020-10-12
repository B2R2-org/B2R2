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

module B2R2.RearEnd.FileViewer.CmdOptions

open B2R2
open B2R2.RearEnd
open System

type FileViewerOpts () =
  inherit CmdOpts ()

  /// Specify ISA. This is only meaningful for universal (fat) binaries because
  /// BinHandler will automatically detect file format by default. When a fat
  /// binary is given, we need to choose which architecture to explorer with
  /// this option.
  member val ISA = ISA.DefaultISA with get, set

  /// Base address
  member val BaseAddress: Addr = 0UL with get, set

  /// Display targets
  member val DisplayTargets = Map.empty with get, set

  /// Hexdump
  member val HexDump = false with get, set

  static member private ToThis (opts: CmdOpts) =
    match opts with
    | :? FileViewerOpts as opts -> opts
    | _ -> failwith "Invalid Opts."

  /// "-i" or "--isa" option for specifying ISA.
  static member OptISA () =
    let cb (opts: #CmdOpts) (arg: string []) =
      (FileViewerOpts.ToThis opts).ISA <- ISA.OfString arg.[0]; opts
    CmdOpts.New ( descr = "Specify <ISA> (e.g., x86) for fat binaries",
                  extra = 1, callback = cb, short = "-i", long= "--isa" )

  /// "-b" or "--base-addr" option for specifying a base address.
  static member OptBaseAddr () =
    let cb (opts: #CmdOpts) (arg: string []) =
      (FileViewerOpts.ToThis opts).BaseAddress <- Convert.ToUInt64 (arg.[0], 16)
      opts
    CmdOpts.New ( descr = "Specify the base <address> in hex (default=0)",
                  extra = 1, callback = cb, short = "-b", long = "--base-addr" )

  /// "-x" or "--hexdump" option for displaying the additional hexdump.
  static member OptHexdump () =
    let cb (opts: #CmdOpts) _ =
      let targets = (FileViewerOpts.ToThis opts).DisplayTargets
      (FileViewerOpts.ToThis opts).HexDump <- true
      opts
    CmdOpts.New ( descr = "Display the additional hexdump",
                  callback = cb, short = "-x", long = "--hexdump" )

  /// "-a" or "--all" option for displaying all the file information.
  static member OptAll () =
    let cb (opts: #CmdOpts) _ =
      let targets = (FileViewerOpts.ToThis opts).DisplayTargets
      (FileViewerOpts.ToThis opts).DisplayTargets <- Map.add "a" [||] targets
      opts
    CmdOpts.New ( descr = "Display all the file information",
                  callback = cb, short = "-a", long = "--all" )

  /// "-B" or "--basic" option for displaying the basic file information.
  static member OptBasic () =
    let cb (opts: #CmdOpts) _ =
      let targets = (FileViewerOpts.ToThis opts).DisplayTargets
      (FileViewerOpts.ToThis opts).DisplayTargets <- Map.add "B" [||] targets
      opts
    CmdOpts.New ( descr = "Display the basic file information",
                  callback = cb, short = "-B", long = "--basic" )

  /// "-e" or "--headers" option for displaying all the headers.
  static member OptHeaders () =
    let cb (opts: #CmdOpts) _ =
      let targets = (FileViewerOpts.ToThis opts).DisplayTargets
      (FileViewerOpts.ToThis opts).DisplayTargets <- Map.add "e" [||] targets
      opts
    CmdOpts.New ( descr = "Display all the headers",
                  callback = cb, short = "-e", long = "--headers" )

  /// "-f" or "--file-header" option for displaying the file header.
  static member OptFileHeader () =
    let cb (opts: #CmdOpts) _ =
      let targets = (FileViewerOpts.ToThis opts).DisplayTargets
      (FileViewerOpts.ToThis opts).DisplayTargets <- Map.add "f" [||] targets
      opts
    CmdOpts.New ( descr = "Display the file header",
                  callback = cb, short = "-f", long = "--file-header" )

  /// "-p" or "--program-headers" option for displaying the program headers.
  static member OptProgramHeaders () =
    let cb (opts: #CmdOpts) _ =
      let targets = (FileViewerOpts.ToThis opts).DisplayTargets
      (FileViewerOpts.ToThis opts).DisplayTargets <- Map.add "p" [||] targets
      opts
    CmdOpts.New ( descr = "Display the program headers",
                  callback = cb, short = "-p", long = "--program-headers" )

  /// "-S" or "--section-headers" option for displaying the section headers.
  static member OptSectionHeaders () =
    let cb (opts: #CmdOpts) _ =
      let targets = (FileViewerOpts.ToThis opts).DisplayTargets
      (FileViewerOpts.ToThis opts).DisplayTargets <- Map.add "S" [||] targets
      opts
    CmdOpts.New ( descr = "Display the section headers",
                  callback = cb, short = "-S", long = "--section-headers" )

  /// "-d" or "--section-details" option for displaying the target section
  /// details.
  static member OptSectionDetails () =
    let cb (opts: #CmdOpts) (arg: string []) =
      let targets = (FileViewerOpts.ToThis opts).DisplayTargets
      (FileViewerOpts.ToThis opts).DisplayTargets
        <- Map.add "d" arg targets
      opts
    CmdOpts.New ( descr = "Display the <name> section details", extra = 1,
                  callback = cb, short = "-d", long = "--section-details" )

  /// "-T" or "--text" option for displaying the text section.
  static member OptTextSection () =
    let cb (opts: #CmdOpts) _ =
      let targets = (FileViewerOpts.ToThis opts).DisplayTargets
      (FileViewerOpts.ToThis opts).DisplayTargets <- Map.add "T" [||] targets
      opts
    CmdOpts.New ( descr = "Display the text section",
                  callback = cb, short = "-T", long = "--text" )

  /// "-s" or "--symbols" option for displaying the symbols.
  static member OptSymbols () =
    let cb (opts: #CmdOpts) _ =
      let targets = (FileViewerOpts.ToThis opts).DisplayTargets
      (FileViewerOpts.ToThis opts).DisplayTargets <- Map.add "s" [||] targets
      opts
    CmdOpts.New ( descr = "Display the symbols",
                  callback = cb, short = "-s", long = "--symbols" )

  /// "-r" or "--relocs" option for displaying the relocation section.
  static member OptRelocs () =
    let cb (opts: #CmdOpts) _ =
      let targets = (FileViewerOpts.ToThis opts).DisplayTargets
      (FileViewerOpts.ToThis opts).DisplayTargets <- Map.add "r" [||] targets
      opts
    CmdOpts.New ( descr = "Display the relocation section",
                  callback = cb, short = "-r", long = "--relocs" )

  /// "-F" or "--functions" option for displaying the functions.
  static member OptFunctions () =
    let cb (opts: #CmdOpts) _ =
      let targets = (FileViewerOpts.ToThis opts).DisplayTargets
      (FileViewerOpts.ToThis opts).DisplayTargets <- Map.add "F" [||] targets
      opts
    CmdOpts.New ( descr = "Display the functions",
                  callback = cb, short = "-F", long = "--functions" )

  /// "-L" or "--linkage-table" option for displaying the linkage table.
  static member OptLinkageTable () =
    let cb (opts: #CmdOpts) _ =
      let targets = (FileViewerOpts.ToThis opts).DisplayTargets
      (FileViewerOpts.ToThis opts).DisplayTargets <- Map.add "L" [||] targets
      opts
    CmdOpts.New ( descr = "Display the linkage table",
                  callback = cb, short = "-L", long = "--linkage-table" )

let spec: FileViewerOpts FsOptParse.Option list =
  [ FileViewerOpts.OptISA ()
    FileViewerOpts.OptBaseAddr ()
    FileViewerOpts.OptHexdump ()
    FileViewerOpts.OptAll ()
    FileViewerOpts.OptBasic ()
    FileViewerOpts.OptHeaders ()
    FileViewerOpts.OptFileHeader ()
    FileViewerOpts.OptProgramHeaders ()
    FileViewerOpts.OptSectionHeaders ()
    FileViewerOpts.OptSectionDetails ()
    FileViewerOpts.OptTextSection ()
    FileViewerOpts.OptSymbols ()
    FileViewerOpts.OptRelocs ()
    FileViewerOpts.OptFunctions ()
    FileViewerOpts.OptLinkageTable ()
    CmdOpts.OptVerbose ()
    CmdOpts.OptHelp () ]
