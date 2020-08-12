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

namespace B2R2.FrontEnd

open B2R2
open B2R2.BinIR.LowUIR

/// A high-level interface for the parsing context, which stores several states
/// for parsing machine instructions.
type ParsingContext private (archMode, itstate, offset, inParallel) =
  /// Target architecture mode (e.g., ARM/thumb mode).
  member __.ArchOperationMode with get(): ArchOperationMode = archMode

  /// ITState for ARM.
  member __.ITState with get(): byte list = itstate

  /// Indicate the address offset of the code. This is used in several
  /// architectures, such as EVM, to correctly resolve jump offsets in a
  /// dynamically generated code snippet.
  member __.CodeOffset with get(): uint64 = offset

  /// Indicate whether the next instruction should be executed in parallel.
  /// This is used by DSP architectures.
  member __.InParallel with get(): bool = inParallel

  static member Init () =
    ParsingContext (ArchOperationMode.NoMode, [], 0UL, false)

  static member Init (mode) =
    ParsingContext (mode, [], 0UL, false)

  static member InitThumb (archMode, itstate) =
    ParsingContext (archMode, itstate, 0UL, false)

  static member InitDSP (ctxt: ParsingContext, flag) =
    ParsingContext (ctxt.ArchOperationMode, ctxt.ITState, ctxt.CodeOffset, flag)

  static member InitEVM (offset) =
    ParsingContext (ArchOperationMode.NoMode, [], offset, false)

  static member ARMSwitchOperationMode (ctxt: ParsingContext) =
    match ctxt.ArchOperationMode with
    | ArchOperationMode.ARMMode ->
      ParsingContext.Init (ArchOperationMode.ThumbMode)
    | ArchOperationMode.ThumbMode ->
      ParsingContext.Init (ArchOperationMode.ARMMode)
    | _ -> Utils.impossible ()

/// A high-level interface for the translation context, which stores several
/// states for translating/lifting instructions.
[<AbstractClass>]
type TranslationContext (isa) =
  /// Word size in bits (RegType).
  member val WordBitSize: RegType = WordSize.toRegType isa.WordSize

  /// The endianness.
  member val Endianness: Endian = isa.Endian

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
