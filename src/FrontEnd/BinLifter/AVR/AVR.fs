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

namespace B2R2.FrontEnd.BinLifter.AVR

open System
open B2R2
open B2R2.FrontEnd.BinLifter

/// Translation context for AVR instructions.
type AVRTranslationContext internal (isa, regexprs) =
  inherit TranslationContext (isa)
  /// Register expressions.
  member val private RegExprs: RegExprs = regexprs
  override __.GetRegVar id = Register.ofRegID id |> __.RegExprs.GetRegVar
  override __.GetPseudoRegVar _id _pos = failwith "Implement"

/// Parser for AVR instructions. Parser will return a platform-agnostic
/// instruction type (Instruction).
type AVRParser () =
  inherit Parser ()
  let reader = BinReader.Init Endian.Little

  override __.Parse (bs: byte[], addr) =
    let span = ReadOnlySpan bs
    Parser.parse span reader addr :> Instruction

  override __.Parse (span: ByteSpan, addr) =
    Parser.parse span reader addr :> Instruction

  override __.OperationMode with get() = ArchOperationMode.NoMode and set _ = ()

module Basis =
  let init (isa: ISA) =
    let regexprs = RegExprs (isa.WordSize)
    struct (
      AVRTranslationContext (isa, regexprs) :> TranslationContext,
      AVRRegisterBay () :> RegisterBay
    )

// vim: set tw=80 sts=2 sw=2:
