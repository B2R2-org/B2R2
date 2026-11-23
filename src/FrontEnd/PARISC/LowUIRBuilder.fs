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

open System.Collections.Generic
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter

/// The LowUIR builder for PARISC. Beyond the plain register/stream builder it
/// carries what a transfer of control and the delay slot it lifts with it
/// share, and what the nullify guard needs.
///
/// A transfer lifts the instruction in its delay slot itself, so the two end
/// as one instruction. What the transfer writes -- a link, the sum of an add
/// and branch, the copy of a move and branch, the nullify bit -- the slot must
/// read, yet the transfer only writes it once the slot has run: a slot that
/// faults then leaves the registers as they were, and running the transfer
/// again does not count its add twice. So while the slot is lifted, each such
/// register is read and written through a temporary instead (see Defer).
///
/// Nullification travels in a register (%psw_n), because an instruction that
/// nullifies and the instruction it nullifies can fall on either side of a
/// lifted block's boundary -- which for PA-RISC is the common case, not a
/// corner one, since most arithmetic can nullify. What is kept here is only
/// the knowledge that lets the guard be *omitted*: an instruction lifted right
/// after one that cannot nullify needs no guard at all.
type LowUIRBuilder(isa: ISA,
                   regFactory: IRegisterFactory,
                   stream: LowUIRStream) =
  let regType = WordSize.toRegType isa.WordSize
  let deferred = List<struct (RegisterID * Expr)>()
  let mutable inDelaySlot = false
  let mutable nullifySkip: Label voption = ValueNone
  let mutable prevEnd: Addr voption = ValueNone
  let mutable prevMayNullify = true

  let shadowOf rid =
    let mutable found = ValueNone
    for struct (r, tmp) in deferred do
      if r = rid then found <- ValueSome tmp else ()
    found

  /// Whether the instruction now being lifted sits in the delay slot of the
  /// transfer that lifts it, which writes the marks for both.
  member _.InDelaySlot with get() = inDelaySlot and set v = inDelaySlot <- v

  /// The label a nullified instruction's body jumps past, shared from that
  /// instruction's MarkStart to its MarkEnd.
  member _.NullifySkip with get() = nullifySkip and set v = nullifySkip <- v

  /// The address one past the instruction lifted most recently, so the next
  /// one can tell whether it really follows it.
  member _.PrevEnd with get() = prevEnd and set v = prevEnd <- v

  /// Whether the instruction lifted most recently can set the nullify bit.
  member _.PrevMayNullify
    with get() = prevMayNullify and set v = prevMayNullify <- v

  member _.RegType with get() = regType

  /// Holds a transfer's write of a register in a temporary until its delay
  /// slot has run: the slot reads and writes the temporary in place of the
  /// register.
  member _.Defer(rid, tmp) = deferred.Add(struct (rid, tmp))

  /// The writes Defer held, in the order they were made, given up for the
  /// transfer to make now.
  member _.TakeDeferred() =
    let writes = deferred.ToArray()
    deferred.Clear()
    writes

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
    member _.GetRegVar(rid: RegisterID) =
      let shadow = if inDelaySlot then shadowOf rid else ValueNone
      match shadow with
      | ValueSome tmp -> tmp
      | ValueNone -> regFactory.GetRegVar(rid = rid)
    member _.GetRegVar(name: string) = regFactory.GetRegVar(name = name)
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
    member _.BeginRegion() =
      stream.Clear()
      deferred.Clear()
      inDelaySlot <- false
      nullifySkip <- ValueNone
      prevEnd <- ValueNone
      prevMayNullify <- true
