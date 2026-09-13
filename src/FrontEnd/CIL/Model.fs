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
namespace B2R2.FrontEnd.CIL

/// <summary>
/// Represents what a slot holds, which is the one thing about a CIL
/// instruction the instruction itself does not say. The evaluation stack, the
/// arguments and the local variables are all kept in slots of the same shape:
/// a quadword holding the value and a quadword holding one of these, so that
/// an instruction polymorphic over the type of what it pops -- add, div, conv
/// and their kin -- can read which meaning it has. On a native architecture
/// the width an instruction computes in is written in the instruction; here
/// it is written in the operand, and this is where.
///
/// A slot of the evaluation stack holds one of the seven kinds ECMA-335
/// (III.1.1) lets it: the first seven values below. An argument or a local
/// variable is of whatever type its signature says, and what it holds is kept
/// in the representation of that type -- an int32 in its low four bytes, a
/// float32 as single-precision bits -- so that the address of the variable can
/// be handed to a load or a store of that type. Loading a variable widens what
/// it holds to the kind the stack keeps of its type and tags the slot with
/// that kind; the values from I1 on are the types whose widening is not a
/// no-op, and they only ever tag a variable. An unsigned int32 variable is
/// tagged I4, an unsigned int64 I8, a native unsigned int I, a bool U1, a char
/// U2 and a float64 F8, their loads being the same as those.
/// </summary>
type SlotType =
  /// A 32-bit integer (int32), which the stack keeps sign-extended to 64 bits.
  | I4 = 0
  /// A 64-bit integer (int64).
  | I8 = 1
  /// A native integer (native int), which is 64 bits wide here, or an
  /// unmanaged pointer.
  | I = 2
  /// A managed pointer (&).
  | Ref = 3
  /// A floating-point number of the internal type F holding a float32 value,
  /// kept as the single's own bits in the low half of the word. Arithmetic
  /// widens it to a double and rounds the result back to a single, which lands
  /// where single-precision arithmetic would; a load, a store, a negation or
  /// a dup moves the bits as they are, a signaling NaN included, as the
  /// runtime's single-precision registers do.
  | F4 = 4
  /// A floating-point number of the internal type F holding a float64 value.
  | F8 = 5
  /// An object reference (O).
  | O = 6
  /// A variable of type int8, which loads sign-extended as an I4.
  | I1 = 8
  /// A variable of type unsigned int8 or bool, which loads zero-extended as an
  /// I4.
  | U1 = 9
  /// A variable of type int16, which loads sign-extended as an I4.
  | I2 = 10
  /// A variable of type unsigned int16 or char, which loads zero-extended as
  /// an I4.
  | U2 = 11
  /// A variable of type float32, holding single-precision bits in its low four
  /// bytes, which loads widened as an F4.
  | R4 = 12

/// <summary>
/// Represents an exception the machine raises of its own accord, which the
/// lifter names to the runtime through the external call "raise" with the
/// value as its one argument. A program's own throw carries an object instead
/// and goes through the external call "throw".
/// </summary>
type CILException =
  /// An integer division or remainder by zero.
  | DivideByZero = 1
  /// A checked arithmetic or conversion instruction whose result does not fit,
  /// or an integer division of the most negative value by minus one.
  | Overflow = 2
  /// An array instruction handed a null reference.
  | NullReference = 3
  /// An array instruction handed an index at or past the length.
  | IndexOutOfRange = 4
  /// A ckfinite handed a NaN or an infinity. ECMA-335 names
  /// ArithmeticException for it; the runtime throws that class's subclass
  /// OverflowException, which a runtime naming the exception has to know.
  | Arithmetic = 5

/// <summary>
/// Provides the layout of a slot, which the lifter and a runtime holding the
/// stack agree on.
///
/// The evaluation stack grows downwards: SP holds the address of the slot on
/// top, and a push moves it down by one slot. The arguments and the local
/// variables are kept in slots too, and are counted downwards from AP and FP
/// respectively, so that argument n sits at AP - n * Size. That order is the
/// order a call finds them in: the caller pushed the arguments first to last,
/// so the first sits deepest, and a callee's AP is where the caller's stack
/// had that one. The frame of a callee is laid out by the runtime below the
/// arguments: the local variables, and below them the evaluation stack.
/// </summary>
[<RequireQualifiedAccess>]
module Slot =
  /// The size of a slot in bytes: a quadword for the value and one for the
  /// tag, which is the SlotType of what the value is.
  let [<Literal>] Size = 16

  /// Where within a slot the tag word sits.
  let [<Literal>] TagOffset = 8

/// <summary>
/// Provides the layout of an array object, which the array instructions the
/// lifter translates on its own -- ldlen, and the ldelem and stelem forms whose
/// element type is in the opcode -- read, and which a runtime allocating one
/// through newarr therefore has to lay out. It follows the runtime this
/// instruction set is most often run by: a type word, a 32-bit length, and the
/// elements from the next quadword boundary on.
/// </summary>
[<RequireQualifiedAccess>]
module ArrayLayout =
  /// Where the length of an array sits, counted from the reference to it, as
  /// an unsigned 32-bit integer.
  let [<Literal>] LengthOffset = 8

  /// Where the first element of an array sits, counted from the reference to
  /// it.
  let [<Literal>] DataOffset = 16

// vim: set tw=80 sts=2 sw=2:
