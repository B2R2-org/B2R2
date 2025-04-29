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

/// <summary>
/// Provides a platform-agnostic interface for accessing register information.
/// </summary>
type IRegisterFactory =
  /// <summary>
  /// Get register expression from a given register ID.
  /// </summary>
  /// <param name="id">Register ID.</param>
  /// <returns>
  /// Returns an IR expression of a register.
  /// </returns>
  abstract GetRegVar: id: RegisterID -> Expr

  /// <summary>
  /// Get register expression from a given register name.
  /// </summary>
  /// <param name="name">Register name.</param>
  /// <returns>
  /// Returns an IR expression of a register.
  /// </returns>
  abstract GetRegVar: name: string -> Expr

  /// <summary>
  /// Get pseudo register expression from a given register ID and an index.
  /// </summary>
  /// <param name="id">Register ID.</param>
  /// <param name="idx">Register index.</param>
  /// <returns>
  /// Returns an IR expression of a pseudo-register.
  /// </returns>
  abstract GetPseudoRegVar: id: RegisterID -> idx: int -> Expr

  /// Return all register expressions.
  abstract GetAllRegVars: unit -> Expr[]

  /// Return all general register expressions excluding FPU registers, vector
  /// registers, etc.
  abstract GetGeneralRegVars: unit -> Expr[]

  /// Return RegisterID from a given RegExpr.
  abstract GetRegisterID: expr: Expr -> RegisterID

  /// <summary>
  /// Return RegisterID from a given register string. Depending on the
  /// underlying architecture of the BinHandle, we may have different
  /// RegisterID.
  /// </summary>
  abstract GetRegisterID: name: string -> RegisterID

  /// <summary>
  /// Return an array of aliases of a given register based on the current
  /// architecture of BinHandle.
  /// </summary>
  abstract GetRegisterIDAliases: RegisterID -> RegisterID[]

  /// <summary>
  /// Return a register string from a given RegisterID. Depending on the
  /// underlying architecture of the BinHandle, we may have a different string
  /// result.
  /// </summary>
  abstract GetRegString: RegisterID -> string

  /// Return all register names.
  abstract GetAllRegStrings: unit -> string[]

  /// <summary>
  /// Return a RegType from a given RegisterID.
  /// </summary>
  abstract GetRegType: RegisterID -> RegType

  /// <summary>
  /// Return a program counter register for a given BinHandle.
  /// </summary>
  abstract ProgramCounter: RegisterID

  /// <summary>
  /// Return a stack pointer register for a given BinHandle.
  /// </summary>
  abstract StackPointer: RegisterID option

  /// <summary>
  /// Return a frame pointer register for a given BinHandle.
  /// </summary>
  abstract FramePointer: RegisterID option

  /// <summary>
  /// Check if the given RegisterID represents PC.
  /// </summary>
  abstract IsProgramCounter: RegisterID -> bool

  /// <summary>
  /// Check if the given RegisterID represents a stack pointer.
  /// </summary>
  abstract IsStackPointer: RegisterID -> bool

  /// <summary>
  /// Check if the given RegisterID represents a frame pointer.
  /// </summary>
  abstract IsFramePointer: RegisterID -> bool
