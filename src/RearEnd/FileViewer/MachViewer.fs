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

module B2R2.RearEnd.FileViewer.MachViewer

open B2R2
open B2R2.FrontEnd.BinFile

let dumpFileHeader (fi: MachFileInfo) (opts: CmdOptions.FileViewerOpts) =
  printfn "mach dumpFileHeader"

let dumpSections (fi: MachFileInfo) (opts: CmdOptions.FileViewerOpts) =
  printfn "mach dumpSections"

let dumpTextSection (fi: MachFileInfo) (opts: CmdOptions.FileViewerOpts) =
  printfn "mach dumpTextSection"

let dumpSectionDetails (fi: MachFileInfo) (opts: CmdOptions.FileViewerOpts) =
  printfn "mach dumpSectionDetails"

let dumpSegments (fi: MachFileInfo) (opts: CmdOptions.FileViewerOpts) =
  printfn "mach dumpSegments"

let dumpSymbols (fi: MachFileInfo) (opts: CmdOptions.FileViewerOpts) =
  printfn "mach dumpSymbols"

let dumpRelocs (fi: MachFileInfo) (opts: CmdOptions.FileViewerOpts) =
  printfn "mach dumpRelocs"

let dumpFunctions (fi: MachFileInfo) (opts: CmdOptions.FileViewerOpts) =
  printfn "mach dumpFunctions"

let dumpLinkageTable (fi: MachFileInfo) (opts: CmdOptions.FileViewerOpts) =
  printfn "mach dumpLinkageTable"
