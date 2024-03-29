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

namespace B2R2.FrontEnd.BinLifter.TMS320C6000

open System
open B2R2
open B2R2.FrontEnd.BinLifter

/// Parser for TMS320C6000 instructions. Parser will return a platform-agnostic
/// instruction type (Instruction).
type TMS320C6000Parser () =
  let mutable inParallel = false
  let reader = BinReader.Init Endian.Little

  interface IInstructionParsable with
    member __.Parse (bs: byte[], addr) =
      let span = ReadOnlySpan bs
      ParsingMain.parse span reader &inParallel addr :> Instruction

    member __.Parse (span: ByteSpan, addr) =
      ParsingMain.parse span reader &inParallel addr :> Instruction

    member __.MaxInstructionSize = 4

    member __.OperationMode with get() = ArchOperationMode.NoMode and set _ = ()
