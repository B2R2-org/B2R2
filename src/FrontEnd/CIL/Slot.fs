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

// vim: set tw=80 sts=2 sw=2:
