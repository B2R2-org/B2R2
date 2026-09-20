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

namespace B2R2.FrontEnd.BinFile.ELF

open System
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile.FileHelper

/// Represents a program property, which is what the NT_GNU_PROPERTY_TYPE_0
/// note carries to tell the loader what the binary asks of it.
type internal GNUProperty =
  { /// Kind of the property.
    PropertyType: uint32
    /// Payload of the property, whose layout its kind decides.
    PropertyData: byte[]
    /// First word of the payload, read in the endianness of the file. Every
    /// property that holds a single word of flags, such as the two feature
    /// properties, records all it has here; the rest leave it zero.
    PropertyValue: uint32 }

/// Represents the kinds of program properties.
and internal GNUPropertyType =
  /// Asks the loader for a stack of at least the given size.
  | GNU_PROPERTY_STACK_SIZE = 1u
  /// Asks the loader not to copy the data of the binary onto a protected
  /// page.
  | GNU_PROPERTY_NO_COPY_ON_PROTECTED = 2u
  /// Records the AArch64 hardening features that every input was built for.
  | GNU_PROPERTY_AARCH64_FEATURE_1_AND = 0xc0000000u
  /// Records the x86 hardening features that every input was built for.
  | GNU_PROPERTY_X86_FEATURE_1_AND = 0xc0000002u
  /// Records the x86 instruction set that the binary needs.
  | GNU_PROPERTY_X86_ISA_1_NEEDED = 0xc0008002u

[<RequireQualifiedAccess>]
module internal GNUProperties =
  let private x86Kind = GNUPropertyType.GNU_PROPERTY_X86_FEATURE_1_AND

  let private armKind = GNUPropertyType.GNU_PROPERTY_AARCH64_FEATURE_1_AND

  /// Rounds the given size up to the boundary that a property pads its
  /// payload to, which is the natural alignment of the class.
  let private padToWord cls (n: int) =
    let align = selectByWordSize cls 4 8
    (n + align - 1) / align * align

  /// Reads the first word of a payload, which is all that a property holding
  /// a single word of flags carries. A shorter payload holds no word at all.
  let private readFirstWord (reader: IBinReader) (data: byte[]) =
    if data.Length < 4 then 0u else reader.ReadUInt32(ReadOnlySpan data, 0)

  /// Reads the property that starts at the given offset, along with where the
  /// next one starts. A property that reaches past the end of the payload is
  /// dropped, and so is every property behind it.
  let private tryReadProperty (reader: IBinReader) cls (span: ByteSpan) off =
    if off + 8 > span.Length then
      None
    else
      let propType = reader.ReadUInt32(span, off)
      let dataSize = int (reader.ReadUInt32(span, off + 4))
      if dataSize < 0 || off + 8 + dataSize > span.Length then
        None
      else
        let data = span.Slice(off + 8, dataSize).ToArray()
        let prop =
          { PropertyType = propType
            PropertyData = data
            PropertyValue = readFirstWord reader data }
        Some(prop, off + 8 + padToWord cls dataSize)

  let rec private parseLoop reader cls (span: ByteSpan) offset acc =
    match tryReadProperty reader cls span offset with
    | Some(prop, nextOffset) ->
      parseLoop reader cls span nextOffset (prop :: acc)
    | None ->
      List.rev acc |> List.toArray

  /// Reads the program properties that the NT_GNU_PROPERTY_TYPE_0 note
  /// carries, or none when the file has no such note.
  let parse toolBox notes =
    let propertyNote = uint32 GNUNoteType.NT_GNU_PROPERTY_TYPE_0
    match Notes.tryFind Notes.GNUOwner propertyNote notes with
    | Some note ->
      let span = ReadOnlySpan note.NoteDesc
      parseLoop toolBox.Reader toolBox.Header.Class span 0 []
    | None ->
      [||]

  let private hasFeature (kind: GNUPropertyType) bit properties =
    properties
    |> Array.exists (fun p ->
      p.PropertyType = uint32 kind && p.PropertyValue &&& bit <> 0u)

  /// Checks whether the binary asks for Indirect Branch Tracking (IBT), the
  /// forward-edge half of Intel CET, which makes every indirect branch land
  /// on an ENDBR instruction.
  let hasIBT properties = hasFeature x86Kind 0x1u properties

  /// Checks whether the binary asks for a Shadow Stack (SHSTK), the
  /// backward-edge half of Intel CET, which checks every return address
  /// against a second, protected copy of it.
  let hasShadowStack properties = hasFeature x86Kind 0x2u properties

  /// Checks whether the binary asks for Branch Target Identification (BTI),
  /// the AArch64 counterpart of IBT.
  let hasBTI properties = hasFeature armKind 0x1u properties

  /// Checks whether the binary signs its return addresses with Pointer
  /// Authentication (PAC), the AArch64 counterpart of a shadow stack.
  let hasPointerAuth properties = hasFeature armKind 0x2u properties
