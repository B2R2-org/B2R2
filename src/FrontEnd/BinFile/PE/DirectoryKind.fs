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

/// Represents which table a data directory names, which is the place it takes
/// in the table of them that ends the optional header.
type internal DirectoryKind =
  /// The export table.
  | ExportTable = 0
  /// The import table.
  | ImportTable = 1
  /// The resource table.
  | ResourceTable = 2
  /// The exception table.
  | ExceptionTable = 3
  /// The attribute certificate table, which names a file offset rather than
  /// an address, being the one directory no section maps.
  | CertificateTable = 4
  /// The base relocation table.
  | BaseRelocationTable = 5
  /// The debug directory.
  | Debug = 6
  /// Architecture-specific data, which every machine in use leaves empty.
  | Architecture = 7
  /// The value the global pointer register is to hold.
  | GlobalPointer = 8
  /// The thread local storage directory.
  | ThreadLocalStorageTable = 9
  /// The load configuration directory.
  | LoadConfigTable = 10
  /// The bound import table.
  | BoundImport = 11
  /// The import address table.
  | ImportAddressTable = 12
  /// The delay import descriptor.
  | DelayImportDescriptor = 13
  /// The CLI header a managed image carries.
  | CorHeaderTable = 14
  /// Reserved, and zero in every image.
  | Reserved = 15
