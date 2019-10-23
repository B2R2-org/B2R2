(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>
          Minkyu Jung <hestati@kaist.ac.kr>

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

namespace B2R2.FrontEnd.ARM32

open B2R2.FrontEnd

/// Translation context for 32-bit ARM instructions.
type ARM32TranslationContext (isa) =
  inherit TranslationContext (isa)
  member val private RegExprs: RegExprs = RegExprs ()
  override __.GetRegVar id = Register.ofRegID id |> __.RegExprs.GetRegVar
  override __.GetPseudoRegVar _id _pos = failwith "Implement" // XXX
  override __.Push _ = B2R2.Utils.impossible ()
  override __.Pop () = B2R2.Utils.impossible ()
  override __.Peek _ = B2R2.Utils.impossible ()

/// Parser for 32-bit ARM instructions. Parser will return a platform-agnostic
/// instruction type (Instruction).
type ARM32Parser (arch) =
  inherit Parser ()
  override __.Parse reader ctxt addr pos =
    Parser.parse reader ctxt arch addr pos
    :> Instruction

// vim: set tw=80 sts=2 sw=2:
