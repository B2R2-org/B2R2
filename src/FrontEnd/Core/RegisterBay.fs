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

/// RegisterBay provides a useful interface for accessing register information
/// in a platform-agnostic manner.
[<AbstractClass>]
type RegisterBay () =
  abstract member GetAllRegExprs: unit -> Expr list

  abstract member GetAllRegNames: unit -> string list

  abstract member RegIDFromRegExpr: Expr -> RegisterID

  abstract member StrToRegExpr: string -> Expr

  /// <summary>
  /// Return RegisterID from a given register string. Depending on the
  /// underlying architecture of the BinHandler, we may have different
  /// RegisterID.
  /// </summary>
  abstract member RegIDFromString: string -> RegisterID

  /// <summary>
  /// Return a register string from a given RegisterID. Depending on the
  /// underlying architecture of the BinHandler, we may have a different string
  /// result.
  /// </summary>
  abstract member RegIDToString: RegisterID -> string

  /// <summary>
  /// Return an array of aliases of a given register based on the current
  /// architecture of BinHandler.
  /// </summary>
  abstract member GetRegisterAliases: RegisterID -> RegisterID []

  /// <summary>
  /// Return a program counter register for a given BinHandler.
  /// </summary>
  abstract member ProgramCounter: RegisterID

  /// <summary>
  /// Return a stack pointer register for a given BinHandler.
  /// </summary>
  abstract member StackPointer: RegisterID option

  /// <summary>
  /// Return a frame pointer register for a given BinHandler.
  /// </summary>
  abstract member FramePointer: RegisterID option
