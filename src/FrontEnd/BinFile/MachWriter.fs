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

namespace B2R2.FrontEnd.BinFile

open B2R2.FrontEnd.BinFile.Mach

/// <summary>
/// Represents a Mach-O file that can be edited and written back out. It
/// starts as the file it is given and remembers every edit asked of it until
/// <see cref='M:B2R2.FrontEnd.BinFile.MachWriter.Emit'/> turns them into the
/// bytes of a file, which is what makes this type a mutable one: an edit
/// changes the writer rather than handing back another. The edits any format
/// can be asked for are those of
/// <see cref='T:B2R2.FrontEnd.BinFile.IBinWriter'/>; the rest are Mach-O's
/// own.
/// </summary>
/// <remarks>
/// An edit the writer cannot carry out raises
/// <see cref='T:B2R2.FrontEnd.BinFile.UnsupportedEditException'/>, whose
/// message says which of them it was. Emitting a writer nothing has been
/// asked of hands back the file it was given, byte for byte. A signed file is
/// another matter: its signature covers the bytes as they were, so a file
/// this writer has changed has to be signed again before it will run.
/// </remarks>
type MachWriter(file: MachBinFile) =
  (* An image opened out of a fileset container names offsets into that
     container rather than into itself, so it is no file to write back. *)
  do
    if file.HeaderOffset <> 0UL then
      raise (UnsupportedEditException "A fileset entry cannot be written.")
    else
      ()

  (* The base address is the one the file resolved rather than the one it was
     given, and feeding it back resolves to itself. The bytes are the image's
     own, a universal binary having been narrowed to one slice already. *)
  let mutable image =
    let bin = file :> IBinFile
    Image.ofBytes file.Bytes bin.ISA (Some bin.BaseAddress)

  /// Returns the bytes of the Mach-O file as the edits asked for so far leave
  /// it.
  member _.Emit() = Emitter.emit image

  /// Puts the given bytes at the given offset into the file.
  member _.PatchByOffset(offset, bytes) =
    image <- Image.patchByOffset offset bytes image

  /// Puts the given bytes where the file keeps the given address.
  member _.PatchByAddr(addr, bytes) =
    image <- Image.patchByAddr addr bytes image

  /// Makes the given address the entry point of the file, which it names
  /// through its main command or through a thread state, whichever it
  /// carries.
  member _.SetEntryPoint addr =
    image <- Image.setEntryPoint addr image

  /// Gives the named section the given type and attributes. It takes both
  /// names to say which section is meant, a section name being unique within
  /// its own segment alone.
  member _.SetSectionAttributes(segName, secName, secType, attrib) =
    image <- Image.setSectionAttributes segName secName secType attrib image

  /// Puts the given bytes in the named section. A section can only be given
  /// as many bytes as it already holds: every one of them sits inside a
  /// segment the file maps whole, so nothing can be made longer without
  /// moving what follows it out from under that segment.
  member _.SetSectionContent(segName, secName, bytes) =
    image <- Image.setSectionContent segName secName bytes image

  /// Adds the given section, inside a segment made to hold it. The command
  /// describing the two of them goes after the ones the file already
  /// carries, so it has to fit in the room the file left there.
  member _.AddSection spec =
    image <- Image.addSection spec image

  /// Adds the given symbol to the symbol table of the file, as a defined
  /// external one. It goes at the end of the group of those, so that the
  /// three groups the dynamic symbol table names go on naming what they
  /// named, and every index from there on moves up by one to follow it.
  member _.AddSymbol spec =
    image <- Image.addSymbol spec image

  /// Takes the code signature off the file. A signature covers the bytes as
  /// they were, so it is no use to a file anything has changed; taking it
  /// off is what leaves the file the shorter for it.
  member _.RemoveCodeSignature() =
    image <- Image.removeCodeSignature image

  interface IBinWriter with
    member this.Emit() = this.Emit()

    member this.PatchByOffset(offset, bytes) = this.PatchByOffset(offset, bytes)

    member this.PatchByAddr(addr, bytes) = this.PatchByAddr(addr, bytes)
