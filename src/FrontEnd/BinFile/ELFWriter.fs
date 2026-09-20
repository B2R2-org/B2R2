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

open B2R2.FrontEnd.BinFile.ELF

/// <summary>
/// Represents an ELF file that can be edited and written back out. It starts
/// as the file it is given and remembers every edit asked of it until
/// <see cref='M:B2R2.FrontEnd.BinFile.ELFWriter.Emit'/> turns them into the
/// bytes of a file, which is what makes this type a mutable one: an edit
/// changes the writer rather than handing back another. The edits any format
/// can be asked for are those of
/// <see cref='T:B2R2.FrontEnd.BinFile.IBinWriter'/>; the rest are ELF's own.
/// </summary>
/// <remarks>
/// An edit the writer cannot carry out raises
/// <see cref='T:B2R2.FrontEnd.BinFile.UnsupportedEditException'/>, whose
/// message says which of them it was. Emitting a writer nothing has been
/// asked of hands back the file it was given, byte for byte.
/// </remarks>
type ELFWriter(file: ELFBinFile) =
  (* The base address is the one the file resolved rather than the one it was
     given, and feeding it back resolves to itself. *)
  let mutable image =
    Image.ofBytes file.Bytes (Some (file :> IBinFile).BaseAddress)

  /// Returns the bytes of the ELF file as the edits asked for so far leave it.
  member _.Emit() = Emitter.emit image

  /// Puts the given bytes at the given offset into the file.
  member _.PatchByOffset(offset, bytes) =
    image <- Image.patchByOffset offset bytes image

  /// Puts the given bytes where the file keeps the given address.
  member _.PatchByAddr(addr, bytes) =
    image <- Image.patchByAddr addr bytes image

  /// Makes the given address the entry point of the file.
  member _.SetEntryPoint addr =
    image <- Image.setEntryPoint addr image

  /// Gives the section of the given name the given attributes.
  member _.SetSectionFlags(name, flags) =
    image <- Image.setSectionFlags name flags image

  /// Puts the given bytes in the section of the given name. A section the
  /// file loads can only be given as many bytes as it already holds, moving
  /// one being what would break the segment mapping it.
  member _.SetSectionContent(name, bytes) =
    image <- Image.setSectionContent name bytes image

  /// Adds the given section after the ones the file has, where it leaves
  /// every section index the file already uses naming what it named.
  member _.AddSection spec =
    image <- Image.addSection spec image

  /// Puts the given section at the given index, moving every index that
  /// names a section from there on up by one to follow it.
  member _.InsertSection(spec, at) =
    image <- Image.insertSection spec at image

  /// Adds the given symbol to the table of symbols the file keeps for itself.
  /// It goes last, so only one the linker calls global can be added.
  member _.AddSymbol spec =
    image <- Image.addSymbol spec image

  interface IBinWriter with
    member this.Emit() = this.Emit()

    member this.PatchByOffset(offset, bytes) = this.PatchByOffset(offset, bytes)

    member this.PatchByAddr(addr, bytes) = this.PatchByAddr(addr, bytes)
