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

namespace B2R2

/// BitVector is the fundamental data type for binary code. We use bigint
/// (arbitrary precision integer) for numbers because registers can have a very
/// large number, e.g., YMM0 in x86.
[<NoComparison; CustomEquality>]
type BitVector =
  private
    {
      Num    : uint64
      Length : RegType
      BigNum : bigint
    }
  with
    override Equals : obj -> bool
    override GetHashCode : unit -> int
    override ToString : unit -> string

    /// <summary>
    ///   Create a BitVector from an integer.
    /// </summary>
    [<CompiledName("OfInt32")>]
    static member ofInt32 : i: int32 -> RegType -> BitVector

    /// Get a BitVector from an unsigned integer.
    [<CompiledName("OfUInt32")>]
    static member ofUInt32 : i: uint32 -> RegType -> BitVector

    /// Get a BitVector from a 64-bit integer.
    [<CompiledName("OfInt64")>]
    static member ofInt64 : i: int64 -> RegType -> BitVector

    /// Get a BitVector from an unsigned integer.
    [<CompiledName("OfUInt64")>]
    static member ofUInt64 : i: uint64 -> RegType -> BitVector

    /// Get a BitVector from an unsigned bigint.
    [<CompiledName("OfUBInt")>]
    static member ofUBInt : i: bigint -> RegType -> BitVector

    /// Get a BitVector from a byte array (in little endian).
    [<CompiledName("OfArr")>]
    static member ofArr : byte [] -> BitVector

    /// Get a BitVector of a specified size from another BitVector.
    [<CompiledName("OfBv")>]
    static member ofBv : BitVector -> RegType -> BitVector

    /// Get a uint64 value from a BitVector.
    [<CompiledName("ToUInt64")>]
    static member toUInt64 : BitVector -> uint64

    /// Get a int64 value from a BitVector.
    [<CompiledName("ToInt64")>]
    static member toInt64 : BitVector -> int64

    /// Get a uint32 value from a BitVector.
    [<CompiledName("ToUInt32")>]
    static member toUInt32 : BitVector -> uint32

    /// Get a int32 value from a BitVector.
    [<CompiledName("ToInt32")>]
    static member toInt32 : BitVector -> int32

    /// Get a numeric value from a BitVector.
    [<CompiledName("GetValue")>]
    static member getValue : BitVector -> bigint

    /// Get a type of a BitVector.
    [<CompiledName("GetType")>]
    static member getType : BitVector -> RegType

    /// BitVector zero (= 0) of the bit length.
    [<CompiledName("Zero")>]
    static member zero : RegType -> BitVector

    /// BitVector one (= 1) of the bit length.
    [<CompiledName("One")>]
    static member one : RegType -> BitVector

    /// Cast a type of a BitVector.
    [<CompiledName("Cast")>]
    static member cast : BitVector -> RegType -> BitVector

    /// Extract a type of a BitVector.
    [<CompiledName("Extract")>]
    static member extract : BitVector -> RegType -> int -> BitVector

    /// BitVector addition.
    [<CompiledName("Add")>]
    static member add : BitVector -> BitVector -> BitVector

    /// BitVector subtraction.
    [<CompiledName("Sub")>]
    static member sub : BitVector -> BitVector -> BitVector

    /// BitVector multiplication.
    [<CompiledName("Mul")>]
    static member mul : BitVector -> BitVector -> BitVector

    /// BitVector Unsigned division.
    [<CompiledName("Div")>]
    static member div : BitVector -> BitVector -> BitVector

    /// BitVector Signed division.
    [<CompiledName("Sdiv")>]
    static member sdiv : BitVector -> BitVector -> BitVector

    /// BitVector logical shift-left.
    [<CompiledName("Shl")>]
    static member shl : BitVector -> BitVector -> BitVector

    /// BitVector logical shift-right.
    [<CompiledName("Shr")>]
    static member shr : BitVector -> BitVector -> BitVector

    /// BitVector arithmetic shift-right.
    [<CompiledName("Sar")>]
    static member sar : BitVector -> BitVector -> BitVector

    /// BitVector concat.
    [<CompiledName("Concat")>]
    static member concat : BitVector -> BitVector -> BitVector

    /// BitVector sign-extend.
    [<CompiledName("Sext")>]
    static member sext : BitVector -> RegType -> BitVector

    /// BitVector sign-extend.
    [<CompiledName("Zext")>]
    static member zext : BitVector -> RegType -> BitVector

    /// BitVector unsigned modulo.
    [<CompiledName("Modulo")>]
    static member modulo : BitVector -> BitVector -> BitVector

    /// BitVector signed modulo.
    [<CompiledName("SModulo")>]
    static member smodulo : BitVector -> BitVector -> BitVector

    /// BitVector Bitwise And.
    [<CompiledName("BitwiseAnd")>]
    static member band : BitVector -> BitVector -> BitVector

    /// BitVector Bitwise Or.
    [<CompiledName("BitwiseOr")>]
    static member bor : BitVector -> BitVector -> BitVector

    /// BitVector Bitwise Xor.
    [<CompiledName("BitwiseXor")>]
    static member bxor : BitVector -> BitVector -> BitVector

    /// BitVector Bitwise Not.
    [<CompiledName("BitwiseNot")>]
    static member bnot : BitVector -> BitVector

    /// Make it negative.
    [<CompiledName("Neg")>]
    static member neg : BitVector -> BitVector

    /// BitVector equal.
    [<CompiledName("EQ")>]
    static member eq : BitVector -> BitVector -> BitVector

    // BitVector not equal.
    [<CompiledName("NEQ")>]
    static member neq : BitVector -> BitVector -> BitVector

    /// BitVector unsigned greater than.
    [<CompiledName("GT")>]
    static member gt : BitVector -> BitVector -> BitVector

    /// BitVector unsigned greater than or equal.
    [<CompiledName("GE")>]
    static member ge : BitVector -> BitVector -> BitVector

    /// BitVector signed grater than.
    [<CompiledName("SGT")>]
    static member sgt : BitVector -> BitVector -> BitVector

    /// BitVector signed greater than or equal.
    [<CompiledName("SGE")>]
    static member sge : BitVector -> BitVector -> BitVector

    /// BitVector unsigned less than.
    [<CompiledName("LT")>]
    static member lt : BitVector -> BitVector -> BitVector

    /// BitVector unsigned less than or equal.
    [<CompiledName("LE")>]
    static member le : BitVector -> BitVector -> BitVector

    /// BitVector signed less than.
    [<CompiledName("SLT")>]
    static member slt : BitVector -> BitVector -> BitVector

    /// BitVector signed less than or equal.
    [<CompiledName("SLE")>]
    static member sle : BitVector -> BitVector -> BitVector

    /// BitVector Absolute Value.
    [<CompiledName("Abs")>]
    static member abs : BitVector -> BitVector

    /// BitVector of maximum 8-bit integer.
    [<CompiledName("MaxNum8")>]
    static member maxNum8 : BitVector

    /// BitVector of maximum 16-bit integer.
    [<CompiledName("MaxNum16")>]
    static member maxNum16 : BitVector

    /// BitVector of maximum 32-bit integer.
    [<CompiledName("MaxNum32")>]
    static member maxNum32 : BitVector

    /// BitVector of maximum 64-bit integer.
    [<CompiledName("MaxNum64")>]
    static member maxNum64 : BitVector

    /// BitVector to string.
    [<CompiledName("ToString")>]
    static member toString : BitVector -> string

    /// A value of a BitVector to string.
    [<CompiledName("ValToString")>]
    static member valToString : BitVector -> string

    /// Does the bitvector represent a positive number?
    [<CompiledName("IsPositive")>]
    static member isPositive : BitVector -> bool

    /// Does the bitvector represent a negative number?
    [<CompiledName("IsNegative")>]
    static member isNegative : BitVector -> bool

    /// Does the bitvector represent a signed min value?
    [<CompiledName("IsSignedMin")>]
    static member isSignedMin: BitVector -> bool

    /// Does the bitvector represent a value zero (0)?
    [<CompiledName("IsZero")>]
    static member isZero : BitVector -> bool

    /// Does the bitvector represent a value one (1)?
    [<CompiledName("IsOne")>]
    static member isOne : BitVector -> bool

    /// Does the bitvector represent the specified integer number?
    [<CompiledName("IsNum")>]
    static member isNum : BitVector -> uint64  -> bool

  end

// vim: set tw=80 sts=2 sw=2:
