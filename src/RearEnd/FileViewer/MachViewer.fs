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
open B2R2.RearEnd
open B2R2.RearEnd.FileViewer.Helper

let badAccess _ _ =
  raise InvalidFileTypeException

let dumpFileHeader _ (fi: MachFileInfo) =
  let hdr = fi.Mach.MachHdr
  printTwoCols
    (toHexString (uint64 hdr.Magic))
    ("Magic " + wrapParen (hdr.Magic.ToString ()))
  printTwoCols
    (hdr.CPUType.ToString ())
    "Cpu type"
  printTwoCols
    (hdr.CPUSubType.ToString ())
    "Cpu subtype"
  printTwoCols
    (hdr.FileType.ToString ())
    "File type"
  printTwoCols
    (hdr.NumCmds.ToString ())
    "Number of commands"
  printTwoCols
    (hdr.SizeOfCmds.ToString ())
    "Size of commands"
  printTwoCols
    (toHexString (uint64 hdr.Flags))
    "Flags"

let dumpSectionHeaders (opts: FileViewerOpts) (fi: MachFileInfo) =
  if opts.Verbose then
    let cfg = [ LeftAligned 24; LeftAligned 20; LeftAligned 20; LeftAligned 24 ]
    Printer.printrow true cfg [ "Num"; "Start"; "End"; "Name" ]
    Printer.printrow true cfg [ "SegmentName"; "Size"; "Offset"; "Alignment" ]
    Printer.printrow true cfg [ "SecRelOff"; "SecNumOfReloc"; "Type"; "Attrib" ]
    Printer.println "  ---"
    fi.Mach.Sections.SecByNum
    |> Array.iteri (fun idx s ->
      Printer.printrow true cfg
        [ wrapSqrdBrac (idx.ToString ())
          (addrToString fi.WordSize s.SecAddr)
          (addrToString fi.WordSize (s.SecAddr + s.SecSize - uint64 1))
          normalizeEmpty s.SecName ]
      Printer.printrow true cfg
        [ normalizeEmpty s.SegName
          toHexString s.SecSize
          toHexString (uint64 s.SecOffset)
          toHexString (uint64 s.SecAlignment) ]
      Printer.printrow true cfg
        [ s.SecRelOff.ToString ()
          s.SecNumOfReloc.ToString ()
          s.SecType.ToString ()
          toHexString (uint64 s.SecAttrib) ])
  else
    let addrColumn = columnWidthOfAddr fi |> LeftAligned
    let cfg = [ LeftAligned 4; addrColumn; addrColumn; LeftAligned 24 ]
    Printer.printrow true cfg [ "Num"; "Start"; "End"; "Name" ]
    Printer.println "  ---"
    fi.GetSections ()
    |> Seq.iteri (fun idx s ->
      Printer.printrow true cfg
        [ wrapSqrdBrac (idx.ToString ())
          (addrToString fi.WordSize s.Address)
          (addrToString fi.WordSize (s.Address + s.Size - uint64 1))
          normalizeEmpty s.Name ])

let dumpSectionDetails (secname: string) (fi: MachFileInfo) =
  Utils.futureFeature ()

let dumpSymbols (opts: FileViewerOpts) (fi: MachFileInfo) =
  Utils.futureFeature ()

let dumpRelocs (opts: FileViewerOpts) (fi: MachFileInfo) =
  Utils.futureFeature ()

let dumpFunctions (opts: FileViewerOpts) (fi: MachFileInfo) =
  Utils.futureFeature ()

let dumpSegments (opts: FileViewerOpts) (fi: MachFileInfo) =
  Utils.futureFeature ()

let dumpLinkageTable (opts: FileViewerOpts) (fi: MachFileInfo) =
  Utils.futureFeature ()
