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

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter

/// Which of the services the Linux/PA-RISC gateway page offers a transfer of
/// control entered, if any. PA-RISC has no instruction for a system call, nor
/// for an atomic exchange, nor for reaching the one control register a thread
/// owns; what it has instead is a page at a fixed address whose entry points
/// the kernel fills in, and a branch through space register 2 is how each is
/// reached. The offset branched to says which, so it is decided when the branch
/// is lifted, while the argument each takes -- the call number, the operation
/// number, the pointer -- is placed by that branch's delay slot and so is only
/// there once the slot has run.
type Gateway =
  /// A transfer that goes somewhere other than the gateway page.
  | NotGateway
  /// A system call, whose number GR20 carries.
  | SystemCall
  /// A light-weight call: a compare-and-exchange, selected by GR20.
  | LightWeightCall
  /// The write of the thread pointer GR26 carries into the control register a
  /// thread's own storage is reached through.
  | SetThreadPointer

/// The LowUIR builder for PARISC. Beyond the plain register/stream builder it
/// carries the two pieces of cross-instruction state PA-RISC needs.
///
/// A control transfer does not jump: it stores its target in the back of the
/// instruction-address queue (%iaoq_back), records its InterJmpKind here, and
/// lets the following (delay-slot) instruction run; that instruction's end
/// flushes the deferred jump. A transfer therefore holds two slots at once --
/// the one it inherited from the transfer before it, which its own end must
/// flush, and the one it arms for the instruction after it -- so the two are
/// kept apart here as the pending and the armed transfer.
///
/// Nullification, by contrast, travels in a register (%psw_n) rather than here,
/// because an instruction that nullifies and the instruction it nullifies can
/// fall on either side of a lifted block's boundary -- which for PA-RISC is the
/// common case, not a corner one, since most arithmetic can nullify. What is
/// kept here is only the knowledge that lets the guard be *omitted*: an
/// instruction lifted right after one that cannot nullify needs no guard at
/// all.
type LowUIRBuilder(isa: ISA,
                   regFactory: IRegisterFactory,
                   stream: LowUIRStream) =
  let regType = WordSize.toRegType isa.WordSize
  let mutable pendingKind = InterJmpKind.NotAJmp
  let mutable pendingGateway = NotGateway
  let mutable armedKind = InterJmpKind.NotAJmp
  let mutable armedGateway = NotGateway
  let mutable curAddr = 0UL
  let mutable delaySlotAddr: Addr voption = ValueNone
  let mutable nullifySkip: Label voption = ValueNone
  let mutable prevEnd: Addr voption = ValueNone
  let mutable prevMayNullify = true

  /// The address of the instruction currently being lifted, so a deferred
  /// branch can record where its delay slot must appear.
  member _.CurAddr with get() = curAddr and set v = curAddr <- v

  /// The address the pending deferred branch's delay slot must be lifted at.
  /// A later instruction lifted at a different address means the branch is
  /// stale state leaked from a prior block's decode, not this branch's slot.
  member _.DelaySlotAddr
    with get() = delaySlotAddr and set v = delaySlotAddr <- v

  /// The kind of the transfer awaiting a flush at the end of the instruction
  /// now being lifted, or NotAJmp when none is.
  member _.PendingKind with get() = pendingKind

  /// Which gateway service the pending transfer entered, if any. Its delay slot
  /// -- which is where that service's argument is placed -- still runs, and the
  /// flush then performs the service.
  member _.PendingGateway with get() = pendingGateway

  /// The kind of the transfer the instruction now being lifted has armed for
  /// its own delay slot, or NotAJmp when it armed none.
  member _.ArmedKind with get() = armedKind

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

  /// Drops the pending transfer. Called when a leaked deferred branch surfaces
  /// at the wrong delay-slot address so it does not mis-flush against an
  /// unrelated instruction.
  member _.ResetPending() =
    pendingKind <- InterJmpKind.NotAJmp
    pendingGateway <- NotGateway

  /// Arms a delayed branch of the given kind (the target lives in %iaoq_back).
  member _.Arm kind =
    armedKind <- kind
    armedGateway <- NotGateway

  /// Arms a delayed entry into one of the gateway page's services.
  member _.ArmGateway service =
    armedKind <- InterJmpKind.Base
    armedGateway <- service

  /// Hands the armed transfer on to the instruction that follows, which is what
  /// makes it the pending one there. Called once an instruction has ended.
  member _.Promote() =
    pendingKind <- armedKind
    pendingGateway <- armedGateway
    armedKind <- InterJmpKind.NotAJmp
    armedGateway <- NotGateway

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
