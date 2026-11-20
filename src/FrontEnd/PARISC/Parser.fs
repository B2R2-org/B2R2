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

namespace B2R2.FrontEnd.PARISC

open System
open B2R2
open B2R2.FrontEnd.BinLifter

/// Represents a parser for PARISC instructions.
type Parser(isa: ISA, reader) =
  let wordSize = isa.WordSize

  let lifter =
    { new ILiftable with
        member _.Lift(ins, builder) = Lifter.translate ins builder
        member _.Disasm(ins, builder) = Disasm.disasm ins builder; builder }

  /// Reads the instruction in a transfer's delay slot into the transfer, which
  /// lifts the two as one. Bytes that end before the slot, or that hold no
  /// instruction there, leave it unread, and the transfer is then not lifted.
  let withDelaySlot (ins: Instruction) (span: ByteSpan) =
    let rest = span.Slice(int ins.Length)
    if ins.HasDelaySlot && not rest.IsEmpty then
      let slotAddr = ins.Address + uint64 ins.Length
      try
        ins.DelaySlot <-
          Some(ParsingMain.parse lifter rest reader wordSize slotAddr)
      with e when not (Terminator.isCritical e) ->
        ()
    else
      ()
    ins

  interface IInstructionParsable with
    member _.MaxInstructionSize = 4

    member _.InstructionAlignment = 4

    member _.Parse(span: ByteSpan, addr: Addr) =
      try
        let ins = ParsingMain.parse lifter span reader wordSize addr
        withDelaySlot ins span :> IInstruction
      with e when not (Terminator.isCritical e) ->
        raise ParsingFailureException

    member this.Parse(bs: byte[], addr: Addr) =
      (this :> IInstructionParsable).Parse(ReadOnlySpan bs, addr)
