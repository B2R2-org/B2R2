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

namespace B2R2.BinFile.PE

open B2R2
open System.Reflection.PortableExecutable

/// The import information begins with the import directory table, which
/// describes the remainder of the import information. There is one
/// ImportDirectoryTable per DLL.
type ImportDirectoryTable = {
  /// The RVA of the import lookup table.
  ImportLookupTableRVA: int
  /// The index of the first forwarder reference.
  ForwarderChain: int
  /// The name of the DLL to import.
  ImportDLLName: string
  /// The RVA of the import address table. The contents of this table are
  /// identical to the contents of the import lookup table until the image is
  /// bound.
  ImportAddressTableRVA : int
}

/// Import information.
type ImportInfo =
  /// Import by ordinal.
  | ImportByOrdinal of ordinal: int16 * dllname: string
  /// Import by name.
  | ImportByName of hint: int16 * funname: string * dllname: string

/// The export directory table contains address information that is used to
/// resolve imports to the entry points within this image.
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

/// Each entry in the export address table is a field that uses one of two
/// formats: ExportRVA and ForwarderRVA.
type ExportAddressTableField =
  /// The address of the exported symbol when loaded into memory, relative to
  /// the image base. For example, the address of an exported function.
  | ExportRVA of int
  /// The pointer to a null-terminated ASCII string in the export section. This
  /// string must be within the range that is given by the export table data
  /// directory entry.
  | ForwarderRVA of int

/// SuperBlock forms the header of a PDB file.
type SuperBlock = {
  /// The block size of the internal file system. PDB can be considered as a
  /// file system within the file.
  BlockSize: int
  /// The index of a block within the file, at which begins a bit field
  /// representing the set of all blocks within the file, which are free.
  FreeBlockMapIdx: int
  /// The total number of blocks in the file.
  NumBlocks: int
  /// The size of the stream directory, in bytes. The stream directory contains
  /// information about each stream's size and the set of blocks that it
  /// occupies.
  NumDirectoryBytes: int
  /// The index of a block within the MSF file.
  BlockMapAddr: int
}

/// The Stream Directory contains information about the other streams in an MSF
/// file. MSF is a file system internally used in a PDB file, and a file in MSF
/// is often called as a stream.
type StreamDirectory = {
  /// Number of streams.
  NumStreams: int
  /// The sizes of streams.
  StreamSizes: int []
  /// The block indices for streams.
  StreamBlocks: int [][]
}

/// DBI stream version.
type DBIStreamVersion =
  | VC41 = 930803
  | V50 = 19960307
  | V60 = 19970606
  | V70 = 19990903
  | V110 = 20091201

/// DBI stream header.
type DBIStreamHeader = {
  /// Compiler version
  DBIVersion: DBIStreamVersion
  /// The index to the global stream.
  GlobalStreamIdx: int
  /// The index to the public stream.
  PublicStreamIdx: int
  /// The index to the stream containing all CodeView symbol records used by the
  /// program.
  SymRecordStreamIdx: int
  /// Size of the module info substream.
  ModInfoSize: int
}

/// Module information.
type ModuleInfo = {
  /// The section in the binary which contains the code/data from this module.
  SectionIndex: int
  /// The index of the stream that contains symbol information for this module.
  SymStreamIndex: int
  /// Module name
  ModuleName: string
  /// Object file name.
  ObjFileName: string
}

/// PE symbol type.
type SymType =
  /// Compile flags symbol.
  | SCOMPILE = 0x0001us
  /// Address of virtual function table.
  | SVFTABLE32 = 0x100cus
  /// Public symbol.
  | SPUB32 = 0x110eus
  /// Reference to a procedure.
  | SPROCREF = 0x1125us
  /// Local Reference to a procedure.
  | SLPROCREF = 0x1127us
  /// Local procedure start.
  | SLPROC32 = 0x110fus
  /// Global procedure start.
  | SGPROC32 = 0x1110us

/// GSI hash header.
type GSIHashHeader = {
  VersionSignature: uint32
  VersionHeader: uint32
  HashRecordSize: uint32
  NumBuckets: uint32
}

/// GSI (global symbol information) hash record.
type GSIHashRecord = {
  /// An offset.
  HROffset: int
  /// A cross reference.
  HRCRef: int
}

/// PE symbol flag.
type SymFlags =
  | None = 0b0000
  | Code = 0b0001
  | Function = 0b0010
  | Managed = 0b0100
  | MSIL = 0b1000

/// PE symbol. We separate B2R2.BinFile.Symbol from format-specific symbol type
/// for future references.
type PESymbol = {
  Flags   : SymFlags
  Address : Addr
  Segment : uint16
  Name    : string
}

/// PDB information.
type PDBInfo = {
  SymbolByAddr: Map<Addr, PESymbol>
  SymbolByName: Map<string, PESymbol>
  SymbolArray: PESymbol []
}

/// Main PE format representation.
type PE = {
  /// PE headers.
  PEHeaders: PEHeaders
  /// Section headers.
  SectionHeaders: SectionHeader []
  /// RVA to import information.
  ImportMap: Map<int, ImportInfo>
  /// Address to exported function name.
  ExportMap: Map<Addr, string>
  /// Word size for the binary.
  WordSize: WordSize
  /// Symbol information from PDB.
  PDB: PDBInfo
  /// BinReader
  BinReader: BinReader
}
