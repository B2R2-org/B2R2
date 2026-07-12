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

namespace B2R2.FrontEnd.SPARC

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter

/// The LowUIR builder for SPARC. Beyond the plain register/stream builder it
/// carries the delayed-branch state SPARC's delay slots need: a control
/// transfer stores its target in %nPC, records its InterJmpKind here, and does
/// NOT jump; the following (delay-slot) instruction runs and then flushes the
/// deferred jump. Armed distinguishes the transfer's own instruction end (which
/// must defer) from the delay slot's end (which flushes), since the shared
/// builder sees both.
type LowUIRBuilder(isa: ISA,
                   regFactory: IRegisterFactory,
                   stream: LowUIRStream) =
  let regType = WordSize.toRegType isa.WordSize
  let mutable delayedBranch = InterJmpKind.NotAJmp
  let mutable armed = false
  let mutable annulCond: Expr voption = ValueNone
  let mutable annulSkip: Label voption = ValueNone

  /// The kind of a pending delayed branch, or NotAJmp when none is pending.
  member _.DelayedBranch with get() = delayedBranch

  /// Whether the pending branch was armed by the instruction now ending, so its
  /// own end defers rather than flushes.
  member _.Armed with get() = armed and set v = armed <- v

  /// When ValueSome, the next instruction is an annulling branch's delay slot
  /// that runs only when this (taken) condition holds, else is annulled.
  member _.AnnulCond with get() = annulCond and set v = annulCond <- v

  /// The label the annulled delay slot's body jumps past, shared from that
  /// instruction's MarkStart to its MarkEnd.
  member _.AnnulSkip with get() = annulSkip and set v = annulSkip <- v

  member _.RegType with get() = regType

  /// Arms a delayed branch of the given kind (the target lives in %nPC).
  member _.Arm kind =
    delayedBranch <- kind
    armed <- true

  /// Clears the pending branch after the delay slot flushes it.
  member _.Disarm() = delayedBranch <- InterJmpKind.NotAJmp

  interface ILowUIRBuilder with
    member _.ISA with get() = isa
    member _.WordSize with get() = isa.WordSize
    member _.RegType with get() = regType
    member _.Endianness with get() = isa.Endian
    member _.Stream with get() = stream
#if EMULATION
    member _.ConditionCodeOp
      with get() = Terminator.impossible ()
        and set _ = Terminator.impossible ()
#endif
    member _.ProgramCounter = regFactory.ProgramCounter
    member _.StackPointer with get() = regFactory.StackPointer
    member _.FramePointer with get() = regFactory.FramePointer
    member _.GetRegVar rid = regFactory.GetRegVar(rid = rid)
    member _.GetRegVar name = regFactory.GetRegVar(name = name)
    member _.GetPseudoRegVar(id, idx) = regFactory.GetPseudoRegVar(id, idx)
    member _.GetAllRegVars() = regFactory.GetAllRegVars()
    member _.GetGeneralRegVars() = regFactory.GetGeneralRegVars()
    member _.GetRegisterID expr = regFactory.GetRegisterID(expr = expr)
    member _.GetRegisterID name = regFactory.GetRegisterID(name = name)
    member _.GetRegisterIDAliases id = regFactory.GetRegisterIDAliases id
    member _.GetRegisterName id = regFactory.GetRegisterName id
    member _.GetAllRegisterNames() = regFactory.GetAllRegisterNames()
    member _.GetRegType id = regFactory.GetRegType id
    member _.IsProgramCounter id = regFactory.IsProgramCounter id
    member _.IsStackPointer id = regFactory.IsStackPointer id
    member _.IsFramePointer id = regFactory.IsFramePointer id
