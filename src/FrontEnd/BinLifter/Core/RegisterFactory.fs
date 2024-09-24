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

/// RegisterFactory provides a useful interface for accessing register related
/// information such as register names, register expressions, register types,
/// and their IDs, in a platform-agnostic manner.
[<AbstractClass>]
type RegisterFactory () =
  /// Return all register expressions.
  abstract GetAllRegExprs: unit -> Expr list

  /// Return all register names.
  abstract GetAllRegNames: unit -> string list

  /// Return all general register expressions excluding FPU registers, vector
  /// registers, etc.
  abstract GetGeneralRegExprs: unit -> Expr list

  /// Return RegType from a given RegExpr.
  member __.RegTypeFromRegExpr (e: Expr) =
    match e.E with
    | Var (rt, _, _)
    | PCVar (rt, _) -> rt
    | _ -> raise InvalidRegisterException

  /// Return RegID from a given RegExpr.
  abstract RegIDFromRegExpr: Expr -> RegisterID

  /// Return RegExpr from a given RegID.
  abstract RegIDToRegExpr: RegisterID -> Expr

  /// Return RegExpr from a string.
  abstract StrToRegExpr: string -> Expr

  /// <summary>
  /// Return RegisterID from a given register string. Depending on the
  /// underlying architecture of the BinHandle, we may have different
  /// RegisterID.
  /// </summary>
  abstract RegIDFromString: string -> RegisterID

  /// <summary>
  /// Return a register string from a given RegisterID. Depending on the
  /// underlying architecture of the BinHandle, we may have a different string
  /// result.
  /// </summary>
  abstract RegIDToString: RegisterID -> string

  /// <summary>
  /// Return a RegType from a given RegisterID.
  /// </summary>
  abstract RegIDToRegType: RegisterID -> RegType

  /// <summary>
  /// Return an array of aliases of a given register based on the current
  /// architecture of BinHandle.
  /// </summary>
  abstract GetRegisterAliases: RegisterID -> RegisterID []

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
