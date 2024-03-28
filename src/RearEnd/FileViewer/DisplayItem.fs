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

/// Display items for ELF.
type ELFDisplayItem =
  | ELFDisplayProgramHeader
  | ELFDisplayPLT
  | ELFDisplayEHFrame
  | ELFDisplayGccExceptTable
  | ELFDisplayNotes

/// Display items for PE.
type PEDisplayItem =
  | PEDisplayImports
  | PEDisplayExports
  | PEDisplayOptionalHeader
  | PEDisplayCLRHeader
  | PEDisplayDependencies

/// Display items for Mach-O.
type MachDisplayItem =
  | MachDisplayArchiveHeader
  | MachDisplayUniversalHeader
  | MachDisplayLoadCommands
  | MachDisplaySharedLibs

/// Display items for FileViewer.
type DisplayItem =
  /// Special item that represents all items.
  | DisplayAll
  /// Basic file header information.
  | DisplayFileHeader
  /// Section headers.
  | DisplaySectionHeaders
  /// Section details.
  | DisplaySectionDetails of string
  /// Symbols.
  | DisplaySymbols
  /// Relocations.
  | DisplayRelocations
  /// Functions.
  | DisplayFunctions
  /// Exception table.
  | DisplayExceptionTable
  /// ELF-specific item.
  | DisplayELFSpecific of ELFDisplayItem
  /// PE-specific item.
  | DisplayPESpecific of PEDisplayItem
  /// Mach-specific item.
  | DisplayMachSpecific of MachDisplayItem
