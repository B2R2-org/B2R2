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

open System
open System.Collections.Generic
open B2R2
open B2R2.RearEnd.Utils
open B2R2.FsOptParse

/// Represents the command-line options for the FileViewer.
type FileViewerOpts =
  { /// Display items.
    DisplayItems: HashSet<DisplayItem>
    ///  ISA. This is only meaningful for universal (FAT) binaries
    /// because BinHandle will automatically detect file format by default. When
    /// a FAT binary is given, we need to choose which ISA to use with this
    /// option.
    ISA: ISA
    /// Base address to use. By default, it is zero (0).
    BaseAddress: Addr option
    /// Verbosity.
    Verbose: bool }
with
  interface IVerboseOption with
    member this.IsVerbose with get() = this.Verbose

  /// Adds a display item to the current FileViewerOpts.
  member private this.Add(item) =
    this.DisplayItems.Add item |> ignore
    this

  /// Returns the default FileViewerOpts.
  static member Default() =
    { DisplayItems = HashSet<DisplayItem>()
      ISA = ISA Architecture.Intel
      BaseAddress = None
      Verbose = false }

  static let cbBaseAddress opts (args: _[]) =
    { opts with BaseAddress = Some(Convert.ToUInt64(args[0], 16)) }

  static member Spec =
    [ CmdOpt(descr = "[General options]",
             dummy = true)
      CmdOpt(descr = "",
             dummy = true)
      CmdOpt(descr = "Show this usage",
             short = "-h", long = "--help",
             help = true)
      CmdOpt(descr = "Verbose mode",
             short = "-v", long = "--verbose",
             callback = fun opts _ -> { opts with Verbose = true })
      CmdOpt(descr = "Specify the base <address> in hex (default=0)",
             short = "-b", long = "--base-addr", extra = 1,
             callback = cbBaseAddress)
      CmdOpt(descr = "Display all the file information",
             short = "-a", long = "--all",
             callback = fun opts _ -> opts.Add DisplayAll)
      CmdOpt(descr = "Display the file header",
             short = "-H", long = "--file-header",
             callback = fun opts _ -> opts.Add DisplayFileHeader)
      CmdOpt(descr = "Display the section headers",
             short = "-S", long = "--section-headers",
             callback = fun opts _ -> opts.Add DisplaySectionHeaders)
      CmdOpt(descr = "Display the <name> section details", extra = 1,
             short = "-d", long = "--section-details",
             callback = fun opts arg -> opts.Add(DisplaySectionDetails arg[0]))
      CmdOpt(descr = "Display the symbols",
             short = "-s", long = "--symbols",
             callback = fun opts _ -> opts.Add DisplaySymbols)
      CmdOpt(descr = "Display the relocation section",
             short = "-r", long = "--relocations",
             callback = fun opts _ -> opts.Add DisplayRelocations)
      CmdOpt(descr = "Display the function symbols",
             short = "-f", long = "--functions",
             callback = fun opts _ -> opts.Add DisplayFunctions)
      CmdOpt(descr = "Display the exception table",
             short = "-x", long = "--exceptions",
             callback = fun opts _ -> opts.Add DisplayExceptionTable)
      CmdOpt(descr = "",
             dummy = true)
      CmdOpt(descr = "[ELF options]",
             dummy = true)
      CmdOpt(descr = "",
             dummy = true)
      CmdOpt(descr = "Display the program headers",
             long = "--program-headers",
             callback = fun opts _ -> opts.Add(DisplayELF ELFProgHeader))
      CmdOpt(descr = "Display the PLT-GOT information",
             long = "--plt",
             callback = fun opts _ -> opts.Add(DisplayELF ELFPLT))
      CmdOpt(descr = "Display the eh_frame information",
             long = "--ehframe",
             callback = fun opts _ -> opts.Add(DisplayELF ELFEHFrame))
      CmdOpt(descr = "Display the gcc_except_table information",
             long = "--gcc-except-table",
             callback = fun opts _ -> opts.Add(DisplayELF ELFGccExceptTbl))
      CmdOpt(descr = "Display the notes information",
             long = "--notes",
             callback = fun opts _ -> opts.Add(DisplayELF ELFNotes))
      CmdOpt(descr = "",
             dummy = true)
      CmdOpt(descr = "[PE options]",
             dummy = true)
      CmdOpt(descr = "",
             dummy = true)
      CmdOpt(descr = "Display the import table",
             long = "--imports",
             callback = fun opts _ -> opts.Add(DisplayPE PEImports))
      CmdOpt(descr = "Display the export table",
             long = "--exports",
             callback = fun opts _ -> opts.Add(DisplayPE PEExports))
      CmdOpt(descr = "Display the optional header",
             long = "--optional-header",
             callback = fun opts _ -> opts.Add(DisplayPE PEOptionalHeader))
      CmdOpt(descr = "Display the CLR header",
             long = "--clr-header",
             callback = fun opts _ -> opts.Add(DisplayPE PECLRHeader))
      CmdOpt(descr = "Display the dependencies",
             long = "--dependencies",
             callback = fun opts _ -> opts.Add(DisplayPE PEDependencies))
      CmdOpt(descr = "",
             dummy = true)
      CmdOpt(descr = "[Mach-O options]",
             dummy = true)
      CmdOpt(descr = "",
             dummy = true)
      CmdOpt(descr = "Display the archive header",
             long = "--archive-header",
             callback = fun opts _ -> opts.Add(DisplayMach MachArchiveHdr))
      CmdOpt(descr = "Display the universal header",
             long = "--universal-header",
             callback = fun opts _ -> opts.Add(DisplayMach MachUniversalHdr))
      CmdOpt(descr = "Display the load commands",
             long = "--load-commands",
             callback = fun opts _ -> opts.Add(DisplayMach MachLoadCmds))
      CmdOpt(descr = "Display the shared libraries",
             long = "--shared-libs",
             callback = fun opts _ -> opts.Add(DisplayMach MachSharedLibs))
      CmdOpt(descr = "Specify <ISA> (e.g., x86) for fat binaries",
             short = "-i", long = "--isa", extra = 1,
             callback = fun opts arg -> { opts with ISA = ISA arg[0] }) ]
