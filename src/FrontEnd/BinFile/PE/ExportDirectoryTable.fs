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

namespace B2R2.FrontEnd.BinFile.PE

/// Represents the Export Directory Table (EDT) entry in a PE file. The export
/// symbol information begins with the EDT, which describes the remainder of the
/// export symbol information. The EDT contains address information that is used
/// to resolve imports to the entry points within this image.
type ExportDirectoryTable = {
  /// The name of the DLL to export.
  ExportDLLName: string
  /// The starting ordinal number for exports in this image. This field
  /// specifies the starting ordinal number for the export address table. It is
  /// usually set to 1.
  OrdinalBase: int
  /// The number of entries in the export address table.
  AddressTableEntries: int
  /// The number of entries in the name pointer table. This is also the number
  /// of entries in the ordinal table.
  NumNamePointers: int
  /// The address of the export address table, relative to the image base.
  ExportAddressTableRVA: int
  /// The address of the export name pointer table, relative to the image base.
  /// The table size is given by the Number of Name Pointers field.
  NamePointerRVA: int
  /// The address of the ordinal table, relative to the image base.
  OrdinalTableRVA: int
}
