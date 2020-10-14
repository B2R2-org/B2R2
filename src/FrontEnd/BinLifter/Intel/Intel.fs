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

namespace B2R2.FrontEnd.BinLifter.Intel

open B2R2.FrontEnd.BinLifter

/// Translation context for Intel (x86 or x86-64) instructions.
type IntelTranslationContext (isa) =
  inherit TranslationContext (isa)
  /// Register expressions.
  member val private RegExprs: RegExprs = RegExprs (isa.WordSize)
  override __.GetRegVar id = Register.ofRegID id |> __.RegExprs.GetRegVar
  override __.GetPseudoRegVar id pos =
    __.RegExprs.GetPseudoRegVar (Register.ofRegID id ) pos

/// Parser for Intel (x86 or x86-64) instructions. Parser will return a
/// platform-agnostic instruction type (Instruction).
type IntelParser (wordSize) =
  inherit Parser ()
  override __.Parse binReader _ctxt addr pos =
    Parser.parse binReader wordSize addr pos :> Instruction

// vim: set tw=80 sts=2 sw=2:
