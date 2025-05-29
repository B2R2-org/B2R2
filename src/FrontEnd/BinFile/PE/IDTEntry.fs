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

/// Represents an import directory table (IDT) in a PE file. The import
/// information (typically located at the .idata section) begins with the import
/// directory table, which describes the remainder of the import information.
/// This type includes both delay IDT and normal IDT.
type IDTEntry = {
  /// The RVA of the import lookup table.
  ImportLookupTableRVA: int
  /// The index of the first forwarder reference.
  ForwarderChain: int
  /// The name of the DLL to import.
  ImportDLLName: string
  /// The RVA of the import address table. The contents of this table are
  /// identical to the contents of the import lookup table until the image is
  /// bound.
  ImportAddressTableRVA: int
  /// Indicate whether this IDT is delay IDT or not.
  DelayLoad: bool
}
with
  /// Checks if the IDT entry is a null entry.
  static member inline IsNull (entry: IDTEntry) =
    entry.ImportLookupTableRVA = 0
    && entry.ForwarderChain = 0
    && entry.ImportDLLName = ""
    && entry.ImportAddressTableRVA = 0
