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

namespace B2R2.BinFile

open B2R2

/// <summary>
///   This class represents a raw binary file (containing only binary code and
///   data without file format)
/// </summary>
type RawFileInfo (bytes: byte [], baseAddr) =
    inherit FileInfo ()

    override __.FileFormat = FileFormat.RawBinary

    override __.FilePath = ""

    override __.EntryPoint = baseAddr

    override __.IsStripped = false

    override __.FileType = FileType.UnknownFile

    override __.WordSize = WordSize.Bit32

    override __.NXEnabled = false

    override __.TextStartAddr = baseAddr

    override __.TranslateAddress addr = System.Convert.ToInt32 (addr - baseAddr)

    override __.FindSymbolChunkStartAddress _addr = 0UL

    override __.GetSymbols () = Seq.empty

    override __.GetStaticSymbols () = Seq.empty

    override __.GetDynamicSymbols () = Seq.empty

    override __.GetSections () =
        Seq.singleton {
            Address = baseAddr
            Kind = SectionKind.ExecutableSection
            Size = uint64 bytes.LongLength
            Name = ""
        }

    override __.GetSections (addr: Addr) =
        if addr >= baseAddr && addr < (baseAddr + uint64 bytes.LongLength) then
            __.GetSections ()
        else
            Seq.empty

    override __.GetSectionsByName (_: string) = Seq.empty

    override __.GetSegments () =
        Seq.singleton {
            Address = baseAddr
            Size = uint64 bytes.LongLength
            Permission = Permission.Readable ||| Permission.Executable
        }

    override __.TryFindFunctionSymbolName (_addr, _) = false

    override __.GetLinkageTableEntries () = Seq.empty

    override __.IsValidAddr (addr) =
        addr >= baseAddr && addr < (baseAddr + uint64 bytes.LongLength)

// vim: set tw=80 sts=2 sw=2:
