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

module B2R2.FrontEnd.BinLifter.LiftingOperators

open B2R2.BinIR.LowUIR

/// This is the special operator that we use for writing a lifter. There are
/// several major operators we use including this one. This one simply appends a
/// statement to the IRBuilder. We always put a IRBuilder variable immediately
/// after each operator without any space to make it visually distinct. For
/// example, for a builder variable "ir", we write a lifting logic as follows:
/// !<ir insAddr insLen
/// !!ir (t1 := v1 .+ v2)
/// !!ir (t2 := t1 .* t1)
/// !>ir insAddr insLen
let inline ( !! ) (ir: IRBuilder) (s) = ir.Append s

/// The special operator for creating a temporary variable.
let inline ( !+ ) (ir: IRBuilder) rt = ir.NewTempVar rt

/// The special operator for creating a symbol.
let inline ( !% ) (ir: IRBuilder) label = ir.NewLabel label

/// The special operator for starting an instruction (ISMark).
let inline ( !< ) (ir: IRBuilder) insAddr insLen =
  ir.Append (insAddr, AST.ismark insLen)

/// The special operator for finishing an instruction (IEMark).
let inline ( !> ) (ir: IRBuilder) (insLen: uint32) =
  ir.Append (AST.iemark insLen)
  ir

/// The special operator for applying a function with a IRBuilder as input.
let inline ( !? ) (ir: IRBuilder) fn =
  fn ir

/// Fetch IRBuilder from the given translation context.
let inline ( !* ) (ctxt: TranslationContext) =
  ctxt.IRBuilder
