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

namespace B2R2.FrontEnd.BinFile.Wasm

open B2R2.Collections

/// <namespacedoc>
///   <summary>
///   Contains types and functions for working with Wasm file types.
///   </summary>
/// </namespacedoc>
///
/// <summary>
/// Represents a vector of elements in WebAssembly.
/// </summary>
type internal Vector<'TElement> =
  { /// Length of encoded elements
    Length: uint32
    /// The actual elements sequence
    Elements: 'TElement[]
    /// Size of the vector in bytes
    Size: uint32 }

type internal ValueType =
  | I32 = 0x7Fuy
  | I64 = 0x7Euy
  | F32 = 0x7Duy
  | F64 = 0x7Cuy

type internal ConstExprValueType =
  | GlobalGet = 0x23uy
  | I32 = 0x41uy
  | I64 = 0x42uy
  | F32 = 0x43uy
  | F64 = 0x44uy

type internal ConstExpr =
  | I32 of uint32
  | I64 of uint64
  | F32 of single
  | F64 of double
  /// A reference to an immutable global through the global.get instruction.
  | GlobalGet of uint32

type internal FuncTypeStart =
  | FunctionType = 0x60uy

type internal FuncType =
  { ParameterTypes: Vector<ValueType>
    ResultTypes: Vector<ValueType> }

type internal LimitsKind =
  | Min = 0x00uy
  | MinMax = 0x01uy

type internal Limits =
  | Min of uint32
  | MinMax of uint32 * uint32

type internal TableElemType =
  | FuncRef = 0x70uy

type internal TableType =
  { ElemType: TableElemType
    Limits: Limits }

type internal Mutability =
  /// Constant
  | Immut = 0x00uy
  /// Variable
  | Mut = 0x01uy

type internal GlobalType =
  { ValueType: ValueType
    Mutable: Mutability }

type internal TypeIdx = uint32

type internal FuncIdx = uint32

type internal TableIdx = uint32

type internal MemIdx = uint32

type internal GlobalIdx = uint32

type internal SectionId =
  | Custom = 0uy
  | Type = 1uy
  | Import = 2uy
  | Function = 3uy
  | Table = 4uy
  | Memory = 5uy
  | Global = 6uy
  | Export = 7uy
  | Start = 8uy
  | Element = 9uy
  | Code = 10uy
  | Data = 11uy

type internal ExpressionEnd =
  | ExprEnd = 0x0Buy

/// Represents the summary of a section information.
type internal SectionSummary =
  { /// Section Identifier.
    Id: SectionId
    /// Section Name.
    Name: string
    /// Section offset.
    Offset: int
    /// Section header size in bytes.
    HeaderSize: uint32
    /// Section contents size in bytes.
    ContentsSize: uint32 }

type internal SectionsInfo =
  { /// Section summary by address.
    SecByAddr: NoOverlapIntervalMap<SectionSummary>
    /// Section summary by name.
    SecByName: Map<string, SectionSummary>
    /// Section summary by its number.
    SecArray: SectionSummary[] }

type internal IndexKind =
  | Type
  | Function
  | Table
  | Memory
  | Global

type internal IndexInfo =
  { /// Element parent section offset.
    SecOffset: int
    /// Element index.
    Index: uint32
    /// Index kind.
    Kind: IndexKind
    /// Element offset.
    ElemOffset: int }

type internal Section<'TContents> =
  { Id: SectionId
    /// The Size of the contents in bytes
    Size: uint32
    /// The Offset of the section
    Offset: int
    /// The actual contents of the section
    Contents: 'TContents option }

/// Represents the subsection identifiers of the "name" custom section.
type internal NameSubsectionId =
  | Module = 0x00uy
  | Function = 0x01uy
  | Local = 0x02uy

/// Represents an index-to-name association in a name map.
type internal NameAssoc =
  { /// The associated index (e.g., a function index).
    Index: uint32
    /// The name bound to the index.
    Name: string }

/// Represents the parsed contents of the "name" custom section.
type internal NameSection =
  { /// The module name, if the module-name subsection is present.
    ModuleName: string option
    /// The function names, from the function-name subsection.
    FunctionNames: NameAssoc[] }

type internal CustomContents =
  { /// Name of the custom section
    Name: string
    /// Size of the contents in bytes
    Size: uint32
    /// Parsed "name" custom section, present only for the "name" section.
    NameSection: NameSection option }

type internal CustomSection = Section<CustomContents>

type internal TypeSection = Section<Vector<FuncType>>

type internal ImportDescKind =
  | Func = 0x00uy
  | Table = 0x01uy
  | Mem = 0x02uy
  | Global = 0x03uy

type internal ImportDesc =
  | ImpFunc of TypeIdx
  | ImpTable of TableType
  | ImpMem of Limits
  | ImpGlobal of GlobalType

type internal Import =
  { Offset: int
    ModuleName: string
    Name: string
    Desc: ImportDesc }

type internal ImportSection = Section<Vector<Import>>

type internal FunctionSection = Section<Vector<TypeIdx>>

type internal TableSection = Section<Vector<TableType>>

type internal MemorySection = Section<Vector<Limits>>

type internal Global =
  { Type: GlobalType
    InitExpr: ConstExpr }

type internal GlobalSection = Section<Vector<Global>>

type internal ExportDescKind =
  | Func = 0x00uy
  | Table = 0x01uy
  | Mem = 0x02uy
  | Global = 0x03uy

type internal ExportDesc =
  | ExpFunc of TypeIdx
  | ExpTable of TableIdx
  | ExpMem of MemIdx
  | ExpGlobal of GlobalIdx

type internal Export =
  { Offset: int
    Name: string
    Desc: ExportDesc }

type internal ExportSection = Section<Vector<Export>>

type internal StartSection = Section<FuncIdx>

type internal Elem =
  { TableIndex: TableIdx
    OffsetExpr: ConstExpr
    InitFuncs: Vector<FuncIdx> }

type internal ElementSection = Section<Vector<Elem>>

type internal LocalDecl =
  { LocalDeclCount: uint32
    LocalDeclType: byte
    LocalDeclLen: int }

type internal Code =
  { Offset: int
    LenFieldSize: int
    CodeSize: uint32
    Locals: LocalDecl list }

type internal CodeSection = Section<Vector<Code>>

type internal Data =
  { MemoryIndex: MemIdx
    OffsetExpr: ConstExpr
    InitBytes: Vector<byte> }

type internal DataSection = Section<Vector<Data>>

type internal FormatVersion =
  | One = 0x00000001u

type internal Module =
  { FormatVersion: FormatVersion
    CustomSections: CustomSection list
    TypeSection: TypeSection option
    ImportSection: ImportSection option
    FunctionSection: FunctionSection option
    TableSection: TableSection option
    MemorySection: MemorySection option
    GlobalSection: GlobalSection option
    ExportSection: ExportSection option
    StartSection: StartSection option
    ElementSection: ElementSection option
    CodeSection: CodeSection option
    DataSection: DataSection option
    /// Contains a summary of all sections information.
    SectionsInfo: SectionsInfo
    /// An element location translation map (Index to/from Offset).
    IndexMap: IndexInfo[] }