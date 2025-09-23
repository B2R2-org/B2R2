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

namespace B2R2.BinIR.LowUIR

open B2R2

/// <summary>
/// Provides methods to retrieve register expressions by register ID or name,
/// obtain pseudo-registers, and enumerate all or general-purpose registers.
/// This interface abstracts architecture-specific details and enables
/// consistent interaction with register variables within the LowUIR
/// intermediate representation.
/// </summary>
type IRegisterVarAccessor =
  /// <summary>
  /// Gets variable expression in LowUIR from a given register ID.
  /// </summary>
  /// <param name="rid">Register ID.</param>
  /// <returns>
  /// Returns an IR expression of a register.
  /// </returns>
  abstract GetRegVar: rid: RegisterID -> Expr

  /// <summary>
  /// Gets variable expression in LowUIR from a given register name.
  /// </summary>
  /// <param name="name">Register name.</param>
  /// <returns>
  /// Returns an IR expression of a register.
  /// </returns>
  abstract GetRegVar: name: string -> Expr

  /// <summary>
  /// Gets pseudo register expression from a given register ID and an index.
  /// </summary>
  /// <param name="rid">Register ID.</param>
  /// <param name="idx">Register index.</param>
  /// <returns>
  /// Returns an IR expression of a pseudo-register.
  /// </returns>
  abstract GetPseudoRegVar: rid: RegisterID * idx: int -> Expr

  /// Returns all register expressions.
  abstract GetAllRegVars: unit -> Expr[]

  /// Returns all general register expressions excluding FPU registers, vector
  /// registers, etc.
  abstract GetGeneralRegVars: unit -> Expr[]
