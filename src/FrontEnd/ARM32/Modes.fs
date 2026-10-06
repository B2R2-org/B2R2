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

/// <summary>
/// The processor modes, what a change of mode does to the registers, the
/// return from an exception, which changes mode as it branches, the User
/// mode registers, which LDM and STM with ^ reach from any mode, and the SP
/// of the mode SRS names.
///
/// <para>The mode is CPSR.M, and each mode but User and System keeps its own
/// SP, LR and SPSR -- FIQ mode R8 to R12 as well. A mode change does not copy
/// them: it changes which copy each register names. That is modelled the way
/// a processor without a register file per mode would do it, by swapping: the
/// live registers are the running mode's, and a change of mode puts each one
/// back in the old mode's copy and takes the new mode's out.</para>
/// </summary>
module internal B2R2.FrontEnd.ARM32.Modes

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.ARM32

/// The modes, as CPSR.M names them.
type private Mode =
  | User = 0x10u
  | FIQ = 0x11u
  | IRQ = 0x12u
  | Supervisor = 0x13u
  | Monitor = 0x16u
  | Abort = 0x17u
  | Hyp = 0x1au
  | Undefined = 0x1bu
  | System = 0x1fu

/// The mode field of CPSR.
let modeOf (psr: Expr) = psr .& numU32 0x1fu 32<rt>

let private modeNum (mode: Mode) = numU32 (uint32 mode) 32<rt>

/// Whether the processor is in User mode, which is PL0.
let inUserMode bld =
  modeOf (regVar bld R.CPSR) == modeNum Mode.User

/// Raises an Undefined Instruction exception in User mode, for an access only
/// PL1 may make, and carries on otherwise.
let undefinedInUserMode bld =
  _when bld "UserMode" (inUserMode bld) (block {
    AST.sideEffect UndefinedInstruction
  })

/// Whether a mode is one of the given ones.
let private isOneOf (mode: Expr) modes =
  modes
  |> List.map (fun m -> mode == modeNum m)
  |> List.reduce (.|)

/// Where each mode keeps its own SP. User and System mode share one.
let private spBanks =
  [ [ Mode.User; Mode.System ], R.SPusr
    [ Mode.FIQ ], R.SPfiq
    [ Mode.IRQ ], R.SPirq
    [ Mode.Supervisor ], R.SPsvc
    [ Mode.Monitor ], R.SPmon
    [ Mode.Abort ], R.SPabt
    [ Mode.Hyp ], R.SPhyp
    [ Mode.Undefined ], R.SPund ]

/// Where each mode keeps its own LR. Hyp mode has none, and uses User mode's;
/// what it returns to is in ELR_hyp.
let private lrBanks =
  [ [ Mode.User; Mode.System; Mode.Hyp ], R.LRusr
    [ Mode.FIQ ], R.LRfiq
    [ Mode.IRQ ], R.LRirq
    [ Mode.Supervisor ], R.LRsvc
    [ Mode.Monitor ], R.LRmon
    [ Mode.Abort ], R.LRabt
    [ Mode.Undefined ], R.LRund ]

/// Where each mode keeps its own SPSR. User and System mode have none.
let private spsrBanks =
  [ [ Mode.FIQ ], R.SPSRfiq
    [ Mode.IRQ ], R.SPSRirq
    [ Mode.Supervisor ], R.SPSRsvc
    [ Mode.Monitor ], R.SPSRmon
    [ Mode.Abort ], R.SPSRabt
    [ Mode.Hyp ], R.SPSRhyp
    [ Mode.Undefined ], R.SPSRund ]

/// R8 to R12, with the copy every other mode shares and FIQ mode's own.
let private fiqBanks =
  [ R.R8, R.R8usr, R.R8fiq
    R.SB, R.R9usr, R.R9fiq
    R.SL, R.R10usr, R.R10fiq
    R.FP, R.R11usr, R.R11fiq
    R.IP, R.R12usr, R.R12fiq ]

/// Swaps R8 to R12 on a change into or out of FIQ mode, and leaves them alone
/// on any other.
let private swapFiqBanks bld oldMode newMode =
  let fiq = modeNum Mode.FIQ
  let leaves = (oldMode == fiq) .& (newMode != fiq)
  let enters = (newMode == fiq) .& (oldMode != fiq)
  append bld {
    for live, usrCopy, fiqCopy in fiqBanks do
      let live = regVar bld live
      let usrCopy = regVar bld usrCopy
      let fiqCopy = regVar bld fiqCopy
      fiqCopy := AST.ite leaves live fiqCopy
      usrCopy := AST.ite enters live usrCopy
      live := AST.ite leaves usrCopy (AST.ite enters fiqCopy live)
  }

/// Puts a banked register back in the copy the old mode keeps, and takes the
/// one the new mode keeps out. A mode with no copy of its own leaves it as it
/// is.
let private swapBanks bld banks live oldMode newMode =
  let live = regVar bld live
  let fromNewMode =
    banks
    |> List.fold (fun acc (modes, bank) ->
      AST.ite (isOneOf newMode modes) (regVar bld bank) acc) live
  append bld {
    for modes, bank in banks do
      let bank = regVar bld bank
      bank := AST.ite (isOneOf oldMode modes) live bank
    live := fromNewMode
  }

/// <summary>
/// Changes mode, the way a write to CPSR.M does: each register the old mode
/// banks goes back to its copy, and the new mode's copies become the live
/// registers. The two modes are temporaries, so that nothing written here
/// moves either; when they are the same, everything goes back where it came
/// from.
/// </summary>
let private switchMode bld oldMode newMode =
  swapFiqBanks bld oldMode newMode
  swapBanks bld spBanks R.SP oldMode newMode
  swapBanks bld lrBanks R.LR oldMode newMode
  swapBanks bld spsrBanks R.SPSR oldMode newMode

/// The modes PL1 software runs in: all but Monitor and Hyp, which a processor
/// without the Security and the Virtualization Extensions does not have, and
/// which one with them enters only by an exception.
let private plainModes =
  [ Mode.User
    Mode.FIQ
    Mode.IRQ
    Mode.Supervisor
    Mode.Abort
    Mode.Undefined
    Mode.System ]

/// <summary>
/// Whether a write to CPSR at PL1 may change to a mode: any PL1 software runs
/// in. Staying in the mode running is always allowed.
/// </summary>
let private isReachable mode current =
  isOneOf mode plainModes .| (mode == current)

/// <summary>
/// Changes mode to the one a write names, where the write may: at PL1, and to
/// a mode it may reach. Returns the mode CPSR.M is to hold afterwards.
/// </summary>
let changeMode bld (named: Expr) =
  let struct (oldMode, newMode) = tmpVars2 bld 32<rt>
  let privileged = AST.not (inUserMode bld)
  append bld {
    oldMode := modeOf (regVar bld R.CPSR)
    newMode :=
      AST.ite (privileged .& isReachable named oldMode) named oldMode
  }
  switchMode bld oldMode newMode
  newMode

/// <summary>
/// Raises an Undefined Instruction exception in Hyp mode and in User mode, as
/// a return from an exception and a transfer of the User mode registers do.
/// Each is UNDEFINED in Hyp mode, which returns by ERET alone (DDI0406C
/// B9.3.5, B9.3.6, B9.3.13, B9.3.17, B9.3.19 and B9.3.20), and UNPREDICTABLE
/// in User mode and -- all but RFE -- in System mode (B9.1.1): User mode,
/// which has no SPSR or registers of another mode to reach, takes it as
/// UNDEFINED, and System mode runs it, as the reference does.
/// </summary>
let undefinedInUserOrHypMode bld =
  let hyp = modeOf (regVar bld R.CPSR) == modeNum Mode.Hyp
  _when bld "UserOrHypMode" (inUserMode bld .| hyp) (block {
    AST.sideEffect UndefinedInstruction
  })

/// <summary>
/// Raises an Undefined Instruction exception in User, System and Hyp mode, as
/// SRS does: UNDEFINED in Hyp mode and UNPREDICTABLE in the other two
/// (DDI0406C B9.3.16), which the reference takes as UNDEFINED in System mode
/// too -- unlike RFE, which it runs there.
/// </summary>
let undefinedInUserSystemOrHypMode bld =
  let mode = modeOf (regVar bld R.CPSR)
  let refused = isOneOf mode [ Mode.User; Mode.System; Mode.Hyp ]
  _when bld "UserSystemOrHypMode" refused (block {
    AST.sideEffect UndefinedInstruction
  })

/// The bits of CPSR a return from an exception restores from the value saved
/// for it: every one but the reserved 23:20 -- and the mode, which is a change
/// of mode rather than a write (CPSRWriteByInstr, DDI0406C B1.3.3).
let private restoredBits = 0xff0fffe0u

/// <summary>
/// Returns from an exception: CPSR takes the value saved for the return, and
/// execution goes on at the target, in the instruction set the restored T bit
/// names -- a Thumb target with its low bit clear, an A32 one with its two low
/// bits clear. Both are temporaries, read before the change of mode moves the
/// registers they came from. The modes a return may reach are the ones a
/// write may, which leaves out Monitor and Hyp mode: the returns into them
/// belong to the Security and the Virtualization Extensions, which this
/// model of the processor does not have.
/// </summary>
let exceptionReturn bld (target: Expr) (saved: Expr) =
  let newMode = changeMode bld (modeOf saved)
  let cpsr = regVar bld R.CPSR
  let toThumb = (saved .& numU32 0x20u 32<rt>) != AST.num0 32<rt>
  append bld { cpsr := (saved .& numU32 restoredBits 32<rt>) .| newMode }
  _if bld "ReturnToThumb" toThumb (block {
    let thumbTarget = target .& numU32 0xfffffffeu 32<rt>
    AST.interjmp thumbTarget InterJmpKind.SwitchToThumb
  }) (block {
    let armTarget = target .& numU32 0xfffffffcu 32<rt>
    AST.interjmp armTarget InterJmpKind.SwitchToARM
  })

/// <summary>
/// Returns from an exception to the given address with the state SPSR holds,
/// which is what SUBS PC, LR and the instructions related to it do at PL1,
/// and LDM with the PC and ^. The caller has checked the mode it runs in.
/// </summary>
let returnWithSPSR bld (target: Expr) =
  let struct (address, saved) = tmpVars2 bld 32<rt>
  append bld {
    address := target
    saved := regVar bld R.SPSR
  }
  exceptionReturn bld address saved

/// <summary>
/// The User mode copy of a register, which an LDM or STM with ^ moves
/// whatever mode is running, with the modes that bank the register away
/// from it: FIQ mode has its own R8 to R12, and every mode but User and
/// System its own SP and LR -- but for Hyp mode's LR, which is User mode's.
/// </summary>
let private userCopyOf reg =
  let banksSPLR =
    [ Mode.FIQ
      Mode.IRQ
      Mode.Supervisor
      Mode.Monitor
      Mode.Abort
      Mode.Undefined ]
  match reg with
  | R.R8 -> Some(R.R8usr, [ Mode.FIQ ])
  | R.SB -> Some(R.R9usr, [ Mode.FIQ ])
  | R.SL -> Some(R.R10usr, [ Mode.FIQ ])
  | R.FP -> Some(R.R11usr, [ Mode.FIQ ])
  | R.IP -> Some(R.R12usr, [ Mode.FIQ ])
  | R.SP -> Some(R.SPusr, Mode.Hyp :: banksSPLR)
  | R.LR -> Some(R.LRusr, banksSPLR)
  | _ -> None

/// What the User mode copy of a register holds, in the mode running: the
/// copy where that mode banks the register away, and the register itself
/// where it does not.
let readUserRegister bld reg =
  match userCopyOf reg with
  | Some(copy, banked) ->
    let elsewhere = isOneOf (modeOf (regVar bld R.CPSR)) banked
    AST.ite elsewhere (regVar bld copy) (regVar bld reg)
  | None ->
    regVar bld reg

/// Writes the User mode copy of a register, and leaves the running mode's
/// own copy as it was.
let writeUserRegister bld reg value =
  match userCopyOf reg with
  | Some(copy, banked) ->
    let elsewhere = isOneOf (modeOf (regVar bld R.CPSR)) banked
    let copy = regVar bld copy
    let reg = regVar bld reg
    append bld {
      copy := AST.ite elsewhere value copy
      reg := AST.ite elsewhere reg value
    }
  | None ->
    append bld { regVar bld reg := value }

/// Whether a number names a mode SRS may store to: any PL1 software runs in.
/// Hyp and Monitor mode are UNPREDICTABLE there (DDI0406C B9.3.16) and taken
/// as UNDEFINED, as the reference takes them, and so is a number that names
/// no mode at all.
let isStackOfPlainMode (mode: uint32) =
  plainModes |> List.exists (fun m -> uint32 m = mode)

/// <summary>
/// The SP of the mode a number names, with whether it is the live SP: it is
/// when the mode running keeps its SP in the same copy, and the copy is the
/// SP otherwise.
/// </summary>
let private spOfMode bld (mode: uint32) =
  let mode: Mode = LanguagePrimitives.EnumOfValue mode
  let modes, copy = spBanks |> List.find (fun (ms, _) -> List.contains mode ms)
  let isLive = isOneOf (modeOf (regVar bld R.CPSR)) modes
  struct (isLive, regVar bld copy)

/// What the SP of the mode a number names holds.
let readSPOf bld mode =
  let struct (isLive, copy) = spOfMode bld mode
  AST.ite isLive (regVar bld R.SP) copy

/// Writes the SP of the mode a number names.
let writeSPOf bld mode value =
  let struct (isLive, copy) = spOfMode bld mode
  let sp = regVar bld R.SP
  append bld {
    sp := AST.ite isLive value sp
    copy := AST.ite isLive copy value
  }
