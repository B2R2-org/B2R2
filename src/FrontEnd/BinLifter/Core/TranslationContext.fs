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

namespace B2R2.FrontEnd.BinLifter

open B2R2
open B2R2.BinIR.LowUIR

/// A high-level interface for the translation context, which stores several
/// states for translating/lifting instructions.
[<AbstractClass>]
type TranslationContext (isa) =
  let irb = IRBuilder (241)
  let mutable delayedJump = InterJmpKind.NotAJmp

  /// Word size in bits (RegType).
  member __.WordBitSize with get(): RegType = WordSize.toRegType isa.WordSize

  /// The endianness.
  member __.Endianness with get(): Endian = isa.Endian

  /// IRBuilder for lifting IRs.
  member __.IRBuilder with get() = irb

  /// Remember if a branch is delayed. If delayed, we store its InterJmpKind.
  /// Lifting results may vary depending on this variable.
  member __.DelayedBranch
    with get() = delayedJump and set(f) = delayedJump <- f

  /// <summary>
  ///   Get register expression from a given register ID.
  /// </summary>
  /// <param name="id">Register ID.</param>
  /// <returns>
  ///   Returns an IR expression of a register.
  /// </returns>
  abstract member GetRegVar: id: RegisterID -> Expr

  /// <summary>
  ///   Get pseudo register expression from a given register ID and an index.
  /// </summary>
  /// <param name="id">Register ID.</param>
  /// <param name="idx">Register index.</param>
  /// <returns>
  ///   Returns an IR expression of a pseudo-register.
  /// </returns>
  abstract member GetPseudoRegVar: id: RegisterID -> idx: int -> Expr
