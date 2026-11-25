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
/// share, and what an instruction nullifies.
///
/// A transfer lifts the instruction in its delay slot itself, so the two end
/// as one instruction. What the transfer writes -- a link, the sum of an add
/// and branch, the copy of a move and branch -- the slot must read, yet the
/// transfer only writes it once the slot has run: a slot that faults then
/// leaves the registers as they were, and running the transfer again does not
/// count its add twice. So while the slot is lifted, each such register is
/// read and written through a temporary instead (see Defer).
///
/// An instruction that nullifies the next one branches past it, as nothing
/// but the instruction before tells whether one is nullified: a block that
/// starts at one does not know its way in, and a guard there would leave each
/// such block two ways through it. The condition waits here until the
/// instruction ends (see Skip), or until its transfer leaves, where it sits
/// in a delay slot and nullifies the instruction the transfer goes on to.
type LowUIRBuilder(isa: ISA,
                   regFactory: IRegisterFactory,
                   stream: LowUIRStream) =
  let regType = WordSize.toRegType isa.WordSize
  let deferred = List<struct (RegisterID * Expr)>()
  let mutable inDelaySlot = false
  let mutable skip: Expr voption = ValueNone

  let shadowOf rid =
    let mutable found = ValueNone
    for struct (r, tmp) in deferred do
      if r = rid then found <- ValueSome tmp else ()
    found

  /// Whether the instruction now being lifted sits in the delay slot of the
  /// transfer that lifts it, which writes the marks for both.
  member _.InDelaySlot with get() = inDelaySlot and set v = inDelaySlot <- v

  /// The condition on which the instruction now being lifted nullifies the
  /// next one, from where its condition is read up to where it ends.
  member _.Skip with get() = skip and set v = skip <- v

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
      skip <- ValueNone
