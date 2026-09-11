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

namespace B2R2.Assembly.WASM

/// <namespacedoc>
///   <summary>
///   Contains WASM-specific assembly components and types.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Represents one instruction the assembler can write: the bytes that name it,
/// and how whatever a source writes beside the mnemonic turns into the bytes
/// that follow them.
/// </summary>
type Encoding =
  { /// The opcode bytes, which in the three prefixed spaces is more than one.
    Code: byte[]
    /// How the operands are laid out behind those bytes.
    Shape: Shape }

/// <summary>
/// Represents how the operands of one instruction are laid out. Almost every
/// instruction takes a fixed run of them; the four that do not are the ones
/// whose length is decided by what the instruction holds rather than by which
/// instruction it is.
/// </summary>
and Shape =
  /// A fixed run of operands, one after another.
  | Fixed of OperandKind list
  /// An alignment and an offset, or an alignment, a memory index and an
  /// offset. Bit 6 of the alignment is what says which of the two it is.
  | MemArg
  /// A memarg with the lane of a v128 written after it.
  | MemArgLane
  /// The labels a br_table may go to, counted, and then the one it goes to
  /// when none of them is picked, which the count leaves out.
  | LabelTable
  /// The value types a select is written with, counted.
  | TypeVector

/// <summary>
/// Represents the kind of one operand, which says both how a source writes it
/// and how it is encoded. The kinds are the very cases the decoder hands back,
/// so that what an instruction takes can be read off a decoded one.
/// </summary>
and OperandKind =
  /// An index into one of the spaces a module has.
  | IndexKind
  /// A 32-bit constant.
  | I32Kind
  /// A 64-bit constant.
  | I64Kind
  /// A 32-bit float, which the encoding carries as the raw bits.
  | F32Kind
  /// A 64-bit float, which the encoding carries as the raw bits.
  | F64Kind
  /// A 128-bit constant, written as the four 32-bit words it spells out.
  | V128Kind
  /// A block type, which is the one operand a source may leave out: a block
  /// written without one carries the type that says it yields nothing.
  | TypeKind
  /// The type ref.null takes, spelled without the suffix a value type of the
  /// same byte carries.
  | RefTypeKind
  /// The alignment of a memarg.
  | AlignmentKind
  /// The offset of a memarg.
  | AddressKind
  /// A lane of a v128, which is one byte rather than a LEB128 number.
  | LaneKind
  /// The consistency model atomic.fence takes, also one byte.
  | ConsistencyKind

// vim: set tw=80 sts=2 sw=2:
