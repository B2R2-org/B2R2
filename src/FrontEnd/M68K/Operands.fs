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

namespace B2R2.FrontEnd.M68K

open B2R2

/// Represents a set of operands in an m68k instruction.
type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
  | ThreeOperands of Operand * Operand * Operand
  | FourOperands of Operand * Operand * Operand * Operand

/// Represents an operand used in an m68k instruction.
and Operand =
  | OpReg of Register
  | OpImm of int64
  | OpAddr of Addr
  | OpMem of MemOperand
  /// A program counter relative displacement, which is how a branch names its
  /// target. The base is the address just past the opcode word, which is what
  /// the manual means by the program counter holding the address of the
  /// extension word.
  | OpRelAddr of int32
  /// The register list of a MOVEM or an FMOVEM, lowest register first. The mask
  /// the encoding carries says which registers those are only together with the
  /// addressing mode, so it is the list itself that is kept here.
  | OpRegList of Register[]
  /// The caches that a CINV or a CPUSH names: neither, the data cache, the
  /// instruction cache, or both.
  | OpCaches of uint8
  /// Immediate data of a floating-point format too wide for an integer to hold,
  /// kept as the bytes it is.
  | OpFImm of byte[]
  /// A pair of registers named with a colon between them, which is how CAS2
  /// names each of its three operands.
  | OpRegPair of Register * Register
  /// A pair of memory locations that two registers point at, which is what
  /// CAS2 compares and swaps.
  | OpMemPair of Register * Register
  /// An effective address together with the bit field that a BFxxx instruction
  /// names within it, written "&lt;ea&gt;{offset:width}".
  | OpBitField of Operand * BitFieldSpec

/// Represents the offset and the width of a bit field, either of which a data
/// register can supply in place of a literal.
and BitFieldSpec =
  { /// Where the field starts, counted from the most significant bit.
    Offset: Operand
    /// How many bits the field holds, which is one to thirty-two.
    Width: Operand }

/// Represents a memory operand, which an m68k instruction names through one of
/// the addressing modes its effective-address field can hold.
and MemOperand =
  /// Address register indirect, written (An).
  | Direct of Register
  /// Address register indirect with postincrement, written (An)+.
  | PostInc of Register
  /// Address register indirect with predecrement, written -(An).
  | PreDec of Register
  /// Address register or program counter indirect with displacement, written
  /// (d16,An) or (d16,PC).
  | Disp of int16 * Register
  /// Any of the indexed modes, which the brief extension word format and the
  /// full one the 68020 added both encode.
  | Indexed of IndexedMem

/// <summary>
/// Represents an indexed memory operand. Base register, index register, base
/// displacement, and outer displacement are each optional, and which of them
/// are present is what tells the several indexed modes apart: a suppressed base
/// leaves <c>Base</c> at None, and an absent outer displacement leaves
/// <c>OuterDisp</c> at None, which is what "no memory indirect action" means.
/// </summary>
and IndexedMem =
  { /// The base register, or None when the extension word suppresses it. The
    /// program counter appears here for the PC-relative indexed modes.
    Base: Register option
    /// The index register together with its size and scale, or None when the
    /// extension word suppresses it.
    Index: IndexReg option
    /// The base displacement, which is zero when null.
    BaseDisp: int32
    /// The outer displacement, present only for the memory indirect modes. Zero
    /// when null but still indirect, hence Some 0.
    OuterDisp: int32 option
    /// Whether the index is added before the indirect memory access rather than
    /// after it. Only a mode that has both an index and an outer displacement
    /// draws that distinction, and this is false for every other one, so that
    /// two operands that mean the same thing are the same value.
    IsPreIndexed: bool }

/// Represents the index register of an indexed memory operand, which an m68k
/// instruction names together with the width to read it at and the factor to
/// scale it by.
and IndexReg =
  { /// The data or address register holding the index.
    Reg: Register
    /// Whether the whole long word is read rather than a sign-extended word.
    IsLong: bool
    /// The factor the index is scaled by, which is 1, 2, 4, or 8.
    Scale: int }
