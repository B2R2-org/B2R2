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

namespace B2R2.FrontEnd.BinLifter.ARM32

open B2R2
open B2R2.FrontEnd.BinLifter

/// Translation context for 32-bit ARM instructions.
type ARM32TranslationContext internal (isa, regexprs) =
  inherit TranslationContext (isa)
  member val private RegExprs: RegExprs = regexprs
  override __.GetRegVar id = Register.ofRegID id |> __.RegExprs.GetRegVar
  override __.GetPseudoRegVar _id _pos = failwith "Implement" // XXX

module Basis =
  let init isa =
    let regexprs = RegExprs ()
    struct (
      ARM32TranslationContext (isa, regexprs) :> TranslationContext,
      ARM32RegisterBay (regexprs) :> RegisterBay
    )

  let initRegBay () =
    let regexprs = RegExprs ()
    ARM32RegisterBay (regexprs) :> RegisterBay

  let detectThumb entryPoint (isa: ISA) =
    match entryPoint, isa.Arch with
    | Some entry, Arch.ARMv7 when entry % 2UL <> 0UL -> (* XXX: LIbraries? *)
      ArchOperationMode.ThumbMode
    | _ -> ArchOperationMode.ARMMode

/// Parser for 32-bit ARM instructions. Parser will return a platform-agnostic
/// instruction type (Instruction).
type ARM32Parser (isa: ISA, mode, entryPoint: Addr option) =
  inherit Parser ()
  let mutable mode: ArchOperationMode =
    if mode = ArchOperationMode.NoMode then Basis.detectThumb entryPoint isa
    else mode
  let mutable itstate: byte list = []

  override __.OperationMode with get() = mode and set(m) = mode <- m

  override __.Parse reader addr pos =
    Parser.parse reader mode &itstate isa.Arch addr pos
    :> Instruction

// vim: set tw=80 sts=2 sw=2:
