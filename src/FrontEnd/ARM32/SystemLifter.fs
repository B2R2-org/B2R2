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
/// The instructions only PL1 has: the ones that read and write the system
/// registers of coprocessor 15, change mode, and return from an exception.
///
/// <para>The mode is CPSR.M, and each mode but User and System keeps its own
/// SP, LR and SPSR -- FIQ mode R8 to R12 as well. A mode change does not copy
/// them: it changes which copy each register names. That is modelled the way
/// a processor without a register file per mode would do it, by swapping: the
/// live registers are the running mode's, and a change of mode puts each one
/// back in the old mode's copy and takes the new mode's out.</para>
/// </summary>
module internal B2R2.FrontEnd.ARM32.SystemLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.ARM32
open B2R2.FrontEnd.ARM32.LiftingUtils
open B2R2.FrontEnd.ARM32.GeneralLifter

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
let private modeOf (psr: Expr) = psr .& numU32 0x1fu 32<rt>

let private modeNum (mode: Mode) = numU32 (uint32 mode) 32<rt>

/// Whether the processor is in User mode, which is PL0.
let private inUserMode bld =
  modeOf (regVar bld R.CPSR) == modeNum Mode.User

/// Raises an Undefined Instruction exception in User mode, for an access only
/// PL1 may make, and carries on otherwise.
let private undefinedInUserMode bld =
  _when bld "UserMode" (inUserMode bld) (block {
    AST.sideEffect UndefinedInstruction
  })

/// Runs the body under the instruction's condition, after checking that the
/// mode running may do what it does.
let private underCondition (ins: Instruction) bld userMay body =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  lift bld ins {
    let lblIgnore = checkCondition ins bld isUnconditional
    if not userMay then undefinedInUserMode bld else ()
    body ()
    putEndLabel bld lblIgnore
  }

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

/// <summary>
/// Whether a write to CPSR at PL1 may change to a mode. Any but Monitor and
/// Hyp may be entered this way: a processor without the Security and the
/// Virtualization Extensions has neither, and one with them enters each only
/// by an exception. Staying in the mode running is always allowed.
/// </summary>
let private isReachable mode current =
  let modes =
    [ Mode.User
      Mode.FIQ
      Mode.IRQ
      Mode.Supervisor
      Mode.Abort
      Mode.Undefined
      Mode.System ]
  isOneOf mode modes .| (mode == current)

/// <summary>
/// Changes mode to the one a write names, where the write may: at PL1, and to
/// a mode it may reach. Returns the mode CPSR.M is to hold afterwards.
/// </summary>
let private changeMode bld (named: Expr) =
  let struct (oldMode, newMode) = tmpVars2 bld 32<rt>
  let privileged = AST.not (inUserMode bld)
  append bld {
    oldMode := modeOf (regVar bld R.CPSR)
    newMode :=
      AST.ite (privileged .& isReachable named oldMode) named oldMode
  }
  switchMode bld oldMode newMode
  newMode

(* The interrupt masks CPSIE and CPSID name, at A, I and F. *)
let private iflagBits = function
  | A -> 0x100u
  | I -> 0x80u
  | F -> 0x40u
  | AI -> 0x180u
  | AF -> 0x140u
  | IF -> 0xc0u
  | AIF -> 0x1c0u

/// The masks CPS leaves set: the ones CPSIE names cleared, or the ones CPSID
/// names set.
let private maskedBy (ins: Instruction) flags (cpsr: Expr) =
  match flags with
  | Some f when ins.Opcode = Op.CPSIE ->
    cpsr .& numU32 (~~~(iflagBits f)) 32<rt>
  | Some f ->
    cpsr .| numU32 (iflagBits f) 32<rt>
  | None ->
    cpsr

/// <summary>
/// CPS, CPSIE and CPSID: a change to the interrupt masks they name, to the
/// mode, or to both. In User mode each of them does nothing at all.
/// </summary>
let cps (ins: Instruction) bld =
  let struct (flags, mode) =
    match ins.Operands with
    | OneOperand(OprIflag f) -> struct (Some f, None)
    | TwoOperands(OprIflag f, OprImm m) -> struct (Some f, Some m)
    | OneOperand(OprImm m) -> struct (None, Some m)
    | _ -> raise InvalidOperandException
  lift bld ins {
    let cpsr = regVar bld R.CPSR
    let user = inUserMode bld
    match mode with
    | Some m ->
      let newMode = changeMode bld (numI64 m 32<rt>)
      let changed = maskedBy ins flags cpsr .& numU32 0xffffffe0u 32<rt>
      cpsr := AST.ite user cpsr (changed .| newMode)
    | None ->
      cpsr := AST.ite user cpsr (maskedBy ins flags cpsr)
  }

/// The bits of CPSR an MRS reads: every one but the execution state -- the IT,
/// J and T bits -- which read as zero (F5-4571).
let private readableCPSR = 0xf80f03dfu

/// MRS, which reads CPSR or, at PL1, the current mode's SPSR.
let mrs (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprReg rd, OprReg R.SPSR) ->
    underCondition ins bld false (fun () ->
      append bld { regVar bld rd := regVar bld R.SPSR })
  | TwoOperands(OprReg rd, OprReg(R.APSR | R.CPSR)) ->
    underCondition ins bld true (fun () ->
      let cpsr = regVar bld R.CPSR
      append bld { regVar bld rd := cpsr .& numU32 readableCPSR 32<rt> })
  | _ ->
    unsupported ins bld

/// The bytes of a status register an MSR names, as a mask of them.
let private namedBytes = function
  | PSRc -> 0x000000ffu
  | PSRx -> 0x0000ff00u
  | PSRxc -> 0x0000ffffu
  | PSRs | PSRg -> 0x00ff0000u
  | PSRsc -> 0x00ff00ffu
  | PSRsx -> 0x00ffff00u
  | PSRsxc -> 0x00ffffffu
  | PSRf | PSRnzcv | PSRnzcvq -> 0xff000000u
  | PSRfc -> 0xff0000ffu
  | PSRfx -> 0xff00ff00u
  | PSRfxc -> 0xff00ffffu
  | PSRfs | PSRnzcvqg -> 0xffff0000u
  | PSRfsc -> 0xffff00ffu
  | PSRfsx -> 0xffffff00u
  | PSRfsxc -> 0xffffffffu

/// <summary>
/// The bits of CPSR an MSR writes at PL1, within the bytes it names: the
/// flags, GE, E and the three interrupt masks. The execution state is not an
/// MSR's to write, and the mode is a change of mode rather than a write.
/// </summary>
let private writableCPSR = 0xf80f03c0u

/// The bits it writes in User mode: the flags, GE and E.
let private userWritableCPSR = 0xf80f0200u

/// The bits of SPSR an MSR writes, within the bytes it names: all but 23:21,
/// which are reserved.
let private writableSPSR = 0xff1fffffu

/// Writes the bits a mask names of a value into a register, keeping the rest.
let private writeMasked (reg: Expr) (mask: Expr) value =
  (reg .& AST.not mask) .| (value .& mask)

/// <summary>
/// MSR to CPSR. Which bits it writes depends on the mode running, unless the
/// bytes named hold none that differ between User mode and PL1; a write of
/// the control byte at PL1 is a change of mode as well, which is made before
/// CPSR is.
/// </summary>
let private msrCPSR ins bld bytes src =
  let userMask = bytes &&& userWritableCPSR
  let privMask = bytes &&& writableCPSR
  underCondition ins bld true (fun () ->
    let cpsr = regVar bld R.CPSR
    let mask =
      if userMask = privMask then
        numU32 privMask 32<rt>
      else
        let user = numU32 userMask 32<rt>
        AST.ite (inUserMode bld) user (numU32 privMask 32<rt>)
    if bytes &&& 0xffu = 0u then
      append bld { cpsr := writeMasked cpsr mask src }
    else
      let value = tmpVar bld 32<rt>
      append bld { value := src }
      let newMode = changeMode bld (modeOf value)
      let written = writeMasked cpsr mask value
      append bld { cpsr := (written .& numU32 0xffffffe0u 32<rt>) .| newMode })

/// MSR, which writes the bytes of CPSR or, at PL1, of the current mode's SPSR
/// that it names.
let msr (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprSpecReg(R.SPSR, Some flag), src) ->
    let mask = numU32 (namedBytes flag &&& writableSPSR) 32<rt>
    underCondition ins bld false (fun () ->
      let spsr = regVar bld R.SPSR
      let src = transOpr ins bld src
      append bld { spsr := writeMasked spsr mask src })
  | TwoOperands(OprSpecReg((R.CPSR | R.APSR), Some flag), src) ->
    msrCPSR ins bld (namedBytes flag) (transOpr ins bld src)
  | _ ->
    unsupported ins bld

/// What an MRC of a coprocessor 15 register reads, or nothing for one that
/// cannot be read.
let private cp15Read bld = function
  | Held reg -> Some(regVar bld reg)
  | FixedZero | ReadAsZero -> Some(AST.num0 32<rt>)
  | MainIDAlias -> Some(regVar bld R.MIDR)
  | Barrier -> None

let private readCP15 ins bld access rt value =
  underCondition ins bld (CP15.isUserAccessible access false) (fun () ->
    append bld { regVar bld rt := value })

/// MRC p15, which reads a coprocessor 15 register into a core register.
/// Reading into the PC is a form only the debug registers have.
let mrc (ins: Instruction) bld =
  match ins.Operands with
  | SixOperands(OprReg R.P15,
                OprImm opc1,
                OprReg rt,
                OprReg crn,
                OprReg crm,
                OprImm opc2) when rt <> R.PC ->
    match CP15.access opc1 crn crm opc2 with
    | Some access ->
      match cp15Read bld access with
      | Some value -> readCP15 ins bld access rt value
      | None -> undefined ins bld
    | None ->
      unsupported ins bld
  | _ ->
    unsupported ins bld

/// What a write leaves in a register: the bits it keeps of the value, and
/// for TTBCR those of the format the value itself selects.
let private keptBits reg mask (value: Expr) =
  match reg with
  | R.TTBCR ->
    let long = numU32 CP15.longTTBCRMask 32<rt>
    let short = numU32 mask 32<rt>
    AST.ite (AST.xthi 1<rt> value) (value .& long) (value .& short)
  | _ when mask = 0xffffffffu ->
    value
  | _ ->
    value .& numU32 mask 32<rt>

let private writeCP15 ins bld reg mask rt =
  underCondition ins bld (CP15.isUserAccessible (Held reg) true) (fun () ->
    append bld { regVar bld reg := keptBits reg mask (regVar bld rt) })

let private writeNothing ins bld access =
  underCondition ins bld (CP15.isUserAccessible access true) ignore

/// MCR p15, which writes a core register into a coprocessor 15 register. A
/// register that may not be written makes the instruction UNDEFINED, and a
/// barrier is a write of nothing.
let mcr (ins: Instruction) bld =
  match ins.Operands with
  | SixOperands(OprReg R.P15,
                OprImm opc1,
                OprReg rt,
                OprReg crn,
                OprReg crm,
                OprImm opc2) when rt <> R.PC ->
    match CP15.access opc1 crn crm opc2 with
    | Some(Held reg) ->
      match CP15.writeMask reg with
      | Some mask -> writeCP15 ins bld reg mask rt
      | None -> undefined ins bld
    | Some(ReadAsZero | Barrier as access) ->
      writeNothing ins bld access
    | Some(FixedZero | MainIDAlias) ->
      undefined ins bld
    | None ->
      unsupported ins bld
  | _ ->
    unsupported ins bld
