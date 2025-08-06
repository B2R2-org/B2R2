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
type Vector<'TElement> =
  { /// Length of encoded elements
    Length: uint32
    /// The actual elements sequence
    Elements: 'TElement[]
    /// Size of the vector in bytes
    Size: uint32 }

type ValueType =
  | I32 = 0x7Fuy
  | I64 = 0x7Euy
  | F32 = 0x7Duy
  | F64 = 0x7Cuy

type ConstExprValueType =
  | I32 = 0x41uy
  | I64 = 0x42uy
  | F32 = 0x43uy
  | F64 = 0x44uy

type ConstExpr =
  | I32 of uint32
  | I64 of uint64
  | F32 of single
  | F64 of double

type FuncTypeStart =
  | FunctionType = 0x60uy

type FuncType =
  { ParameterTypes: Vector<ValueType>
    ResultTypes: Vector<ValueType> }

type LimitsKind =
  | Min = 0x00uy
  | MinMax = 0x01uy

type Limits =
  | Min of uint32
  | MinMax of uint32 * uint32

type TableElemType =
  | FuncRef = 0x70uy

type TableType =
  { ElemType: TableElemType
    Limits: Limits }

type Mutability =
  /// Constant
  | Immut = 0x00uy
  /// Variable
  | Mut = 0x01uy

type GlobalType =
  { ValueType: ValueType
    Mutable: Mutability }

type TypeIdx = uint32

type FuncIdx = uint32

type TableIdx = uint32

type MemIdx = uint32

type GlobalIdx = uint32

type SectionId =
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

type ExpressionEnd =
  | ExprEnd = 0x0Buy

/// Represents the summary of a section information.
type SectionSummary =
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

type SectionsInfo =
  { /// Section summary by address.
    SecByAddr: NoOverlapIntervalMap<SectionSummary>
    /// Section summary by name.
    SecByName: Map<string, SectionSummary>
    /// Section summary by its number.
    SecArray: SectionSummary [] }

type IndexKind =
  | Type
  | Function
  | Table
  | Memory
  | Global

type IndexInfo =
  { /// Element parent section offset.
    SecOffset: int
    /// Element index.
    Index: uint32
    /// Index kind.
    Kind: IndexKind
    /// Element offset.
    ElemOffset: int }

type Section<'TContents> =
  { Id: SectionId
    /// The Size of the contents in bytes
    Size: uint32
    /// The Offset of the section
    Offset: int
    /// The actual contents of the section
    Contents: 'TContents option }

type CustomContents =
  { /// Name of the custom section
    Name: string
    /// Size of the contents in bytes
    Size: uint32 }

type CustomSection = Section<CustomContents>

type TypeSection = Section<Vector<FuncType>>

type ImportDescKind =
  | Func = 0x00uy
  | Table = 0x01uy
  | Mem = 0x02uy
  | Global = 0x03uy

type ImportDesc =
  | ImpFunc of TypeIdx
  | ImpTable of TableType
  | ImpMem of Limits
  | ImpGlobal of GlobalType

type Import =
  { Offset: int
    ModuleName: string
    Name: string
    Desc: ImportDesc }

type ImportSection = Section<Vector<Import>>

type FunctionSection = Section<Vector<TypeIdx>>

type TableSection = Section<Vector<TableType>>

type MemorySection = Section<Vector<Limits>>

type Global =
  { Type: GlobalType
    InitExpr: ConstExpr }

type GlobalSection = Section<Vector<Global>>

type ExportDescKind =
  | Func = 0x00uy
  | Table = 0x01uy
  | Mem = 0x02uy
  | Global = 0x03uy

type ExportDesc =
  | ExpFunc of TypeIdx
  | ExpTable of TableIdx
  | ExpMem of MemIdx
  | ExpGlobal of GlobalIdx

type Export =
  { Offset: int
    Name: string
    Desc: ExportDesc }

type ExportSection = Section<Vector<Export>>

type StartSection = Section<FuncIdx>

type Elem =
  { TableIndex: TableIdx
    OffsetExpr: ConstExpr
    InitFuncs: Vector<FuncIdx> }

type ElementSection = Section<Vector<Elem>>

type LocalDecl =
  { LocalDeclCount: uint32
    LocalDeclType: byte
    LocalDeclLen: int }

type Code =
  { Offset: int
    LenFieldSize: int
    CodeSize: uint32
    Locals: LocalDecl list }

type CodeSection = Section<Vector<Code>>

type Data =
  { MemoryIndex: MemIdx
    OffsetExpr: ConstExpr
    InitBytes: Vector<byte> }

type DataSection = Section<Vector<Data>>

type FormatVersion =
  | One = 0x00000001u

type Module =
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
    IndexMap: IndexInfo [] }