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

namespace B2R2.FrontEnd.Intel

open System.Collections.Generic
open B2R2

/// The mandatory prefix a row asks for, as one small number: the matcher asks
/// this of every candidate of every instruction, and comparing two union
/// values costs a virtual call where comparing two integers costs none.
type internal PrefixSel =
  | LegacyNP = 0
  | MandatoryNP = 1
  | Mandatory66 = 2
  | MandatoryF3 = 3
  | MandatoryF2 = 4
  | Mandatory66F2 = 5
  /// A legacy row asking for 66h, F2h or F3h. No encoding ever matches one.
  | LegacyOther = 6

/// How wide the operation runs, as far as the table alone can tell. The first
/// operand to declare a width is the one the manual sizes the instruction by,
/// and only when none declares one do the prefixes decide.
type internal OpWidthKind =
  /// The table settles it.
  | Fixed = 0
  /// r32/m16 and its kin run at the width of the side ModRM picked: MOV m16,
  /// Sreg stores a selector, MOV r32, Sreg fills a whole register.
  | ByModRMForm = 1
  /// A fixed register whose width depends on the CPU mode.
  | FixedRegister = 2
  /// The effective address size.
  | EffectiveAddress = 3
  /// Nothing declares a width, so the prefixes and the CPU mode decide.
  | FromPrefixes = 4

/// The ways an operand descriptor is read. Descriptors that are read the same
/// way share a kind: {er} and {sae} decorate an operand without changing how
/// it is read, and a register with {sae} is read like any other register.
type internal OprKind =
  /// Register or memory of one width.
  | RM = 0
  /// Register or memory, the two of different widths.
  | RMTwoWidths = 1
  /// Register or memory with embedded broadcast.
  | RMBroadcast = 2
  /// Memory with VSIB addressing.
  | MemVSIB = 3
  /// A register named by a field of the encoding.
  | Reg = 4
  /// Memory of a declared width.
  | Mem = 5
  /// Memory with no declared width: the prefixes decide.
  | MemFromPrefixes = 6
  | Imm = 7
  | Rel = 8
  /// A fixed register the table sized.
  | FixedReg = 9
  /// A fixed register whose width depends on the CPU mode.
  | FixedRegModeWidth = 10
  /// ST(i), selected by ModRM.rm.
  | STRegRM = 11
  /// A fixed ST(i).
  | STRegFixed = 12
  /// Bound register or memory.
  | BM = 13
  | BndReg = 14
  | OpMaskReg = 15
  /// Opmask register or memory.
  | KM = 16
  | MMXReg = 17
  /// MMX register or memory.
  | MM = 18
  | FixedImm = 19
  | Moffs = 20
  | CtrlReg = 21
  | DebugReg = 22
  | RegAddr = 23
  | Sreg = 24
  | Far = 25
  /// NoOpr among other operands, or an Unknown the extractor could not
  /// classify. Neither occurs in the generated tables today.
  | Unsupported = 26

/// The operand shapes common enough to be read by code of their own rather
/// than descriptor by descriptor: a register named by ModRM.reg beside a
/// register-or-memory operand, in either order; a register-or-memory
/// operand alone or ahead of an immediate; a relative offset alone; and a
/// register named by the opcode byte alone. Between them they cover most of
/// the instructions in compiled code.
type internal OprShape =
  | Other = 0
  | RegThenRM = 1
  | RMThenReg = 2
  | RMThenImm = 3
  | RMOnly = 4
  | RelOnly = 5
  | RegOpRdOnly = 6

/// One operand descriptor laid out flat, so that reading it costs no pointer
/// hop: the generated table describes an operand with a union value, which
/// sits in an object of its own.
[<Struct>]
type internal OprSpec =
  { Kind: OprKind
    /// The register width, or the one width of a single-width operand, or the
    /// element width of a VSIB operand.
    Size: RegType
    /// The memory width of a two-width operand.
    MemSize: RegType
    /// The element width an embedded broadcast reads.
    BcstSize: RegType
    /// The register a fixed-register operand names, or the immediate a fixed
    /// immediate carries.
    Value: int
    /// The field of the encoding a register operand is read from.
    Field: OprRegType }

/// The parsing state the REX, mandatory-prefix and mode checks read, as one
/// small number, so that a row can say in one bit mask which states it
/// answers. Three REX states (none, present without W, present with W), a VEX
/// prefix present or not, and the eight combinations of 66h, F3h and F2h make
/// 48 states; the CPU mode gets a mask of its own.
module internal MatchContext =
  /// The state's number.
  let inline index rexState vexPresent prefState =
    (rexState * 2 + vexPresent) * 8 + prefState

  /// The prefix state of the given prefixes: bit 2 for 66h, bit 1 for F3h and
  /// bit 0 for F2h.
  let inline prefState (pref: Prefix) =
    let p = int pref
    ((p >>> 8) &&& 0b100) ||| ((p >>> 2) &&& 0b010) ||| ((p >>> 1) &&& 0b001)

/// One row of the opcode table together with every fact about it that depends
/// on nothing but the table, laid out flat so that a candidate costs one load
/// of one object. The matcher used to work these facts out again for every
/// candidate of every instruction, scanning the operand descriptors and the
/// whole slot each time; here they are settled once, when the table is built.
/// The fields the matcher reads come first, so that a rejected candidate
/// touches as little of the row as possible. The rows in play for one opcode
/// byte and ModRM.reg digit form a chain through Next, so that the table
/// hands the parser its first candidate directly rather than an array to
/// index into.
[<ReferenceEquality>]
type internal Row =
  { /// What the ModRM byte has to satisfy for the row to answer, as one masked
    /// comparison: the byte, masked, has to equal ModRMValue. A /digit row
    /// masks bits 5:3, a fixed byte masks all eight, an ST(i) row masks all
    /// but the three that select the register, and a row that takes any
    /// ModRM byte, or none, masks nothing. The union the generated table
    /// carries took two pointer hops and a nine-way switch to read, and this
    /// is asked of every candidate.
    ModRMMask: byte
    ModRMValue: byte
    /// The row takes only a memory form, whatever else the mask says.
    ModRMNotReg: bool
    /// The row takes any ModRM byte, or none: nothing to compare.
    ModRMAny: bool
    /// The match contexts (see MatchContext) whose REX and mandatory prefix
    /// the row answers in 32-bit mode, one bit apiece.
    Accept32: uint64
    /// The same for 64-bit mode.
    Accept64: uint64
    /// 66h is what picks this row out of its slot: it declares a 16-bit form
    /// and the slot also holds the same opcode wider.
    Requires66h: bool
    /// None of the constraints the accept mask leaves for parse time applies
    /// to the row: it is neither JCXZ nor the one-byte NOP and constrains no
    /// vector length. Under no LOCK and no VEX prefix, such a row has nothing
    /// left to be asked once its ModRM byte and accept mask agree.
    Plain: bool
    VectorLength: VectorLength
    /// The row offers embedded rounding, which is what gives EVEX.b its {er}
    /// meaning.
    DeclaresER: bool
    /// Opcode byte E3h of the one-byte map: JCXZ, JECXZ or JRCXZ.
    IsE3: bool
    /// The one-byte NOP, which REX.B turns into an XCHG.
    IsPlainNop: bool
    /// The row reads memory through VSIB.
    UsesVSIB: bool
    /// A LOCK prefix may sit on the row provided ModRM names memory.
    LockableDest: bool
    /// A row of the slot offers embedded rounding.
    SlotDeclaresER: bool
    Opcode: Opcode
    /// The low byte of the opcode, which an OpRd operand reads a register from.
    OpcodeByte: byte
    OprSpecs: OprSpec[]
    /// How many operands the row has; a lone NoOpr counts for none.
    OperandCount: int
    Shape: OprShape
    /// The widths of the first two operands, for the shapes read by code of
    /// their own; 0<rt> where there is no such operand.
    Size0: RegType
    Size1: RegType
    /// A ModRM byte follows the opcode.
    HasModRM: bool
    /// ModRM.reg is spent on naming the instruction.
    IsGroupExtension: bool
    TupleType: TupleType
    /// The size condition as the table declares it.
    SzCond: SzCond
    /// The size condition with the far return's d64 taken away.
    EffSzCond: SzCond
    /// The prefixes the row named, which are the ones that picked it out
    /// rather than describing its operands. Dropping the rest would lose what
    /// they said: the 66h ahead of TZCNT's F3 set the operand size and nothing
    /// else records that it was there.
    SelectorPrefixes: Prefix
    /// The row is 90h in the one-byte map, which F3h turns into PAUSE.
    IsNopOrPause: bool
    /// The far return, which the table cannot tell from the near one.
    IsFarRet: bool
    /// A string instruction that moves a byte at a time whatever the prefixes
    /// say.
    IsByteString: bool
    /// The immediate is narrower than the operand and is sign-extended.
    SignExtendsImm: bool
    /// The width of a FixedImm operand.
    FixedImmSize: RegType
    /// How the width of the whole operation is settled.
    OpWidthKind: OpWidthKind
    /// The width, or the register-form width of a ByModRMForm row.
    OpWidth: RegType
    /// The memory-form width of a ByModRMForm row.
    OpWidthMem: RegType
    /// The register a FixedRegister row is sized by.
    OpWidthReg: Register
    /// The next row in play after this one, or null at the end of the chain.
    /// Set once, when the chains are built.
    mutable Next: Row }

/// Builds the opcode tables the parser reads: the generated rows, each paired
/// with the facts about it that never change.
module internal InstructionTable =
  let private prefixSel = function
    | Legacy NP -> PrefixSel.LegacyNP
    | Mandatory NP -> PrefixSel.MandatoryNP
    | Mandatory P66 -> PrefixSel.Mandatory66
    | Mandatory F3 -> PrefixSel.MandatoryF3
    | Mandatory F2 -> PrefixSel.MandatoryF2
    | Mandatory P66F2 -> PrefixSel.Mandatory66F2
    | Legacy _ -> PrefixSel.LegacyOther

  let private selectorPrefixes = function
    | Mandatory P66 -> Prefix.OPSIZE
    | Mandatory F3 -> Prefix.REPZ
    | Mandatory F2 -> Prefix.REPNZ
    | Mandatory P66F2 -> Prefix.OPSIZE ||| Prefix.REPNZ
    | _ -> Prefix.None

  /// Returns true when every operand is 8-bit, meaning REX semantics do not
  /// apply to this instruction.
  let private isAllOprSize8 (operands: OperandType[]) =
    operands.Length > 0
    && operands
       |> Array.forall (function
         | RM sz | Reg(sz, _) | Mem sz | Imm sz | Rel sz | Moffs sz
         | Far sz -> sz = 8<rt>
         | _ -> false)

  /// The ModRM.reg digit a row spends on naming itself, or -1 where it spends
  /// none. Rows that name different digits are different instructions sharing
  /// an opcode byte, so neither answers the other's bytes.
  let private groupDigit = function
    | ModRMType.ModRMOp0 _ -> 0
    | ModRMType.ModRMOp1 _ -> 1
    | ModRMType.ModRMOp2 _ -> 2
    | ModRMType.ModRMOp3 _ -> 3
    | ModRMType.ModRMOp4 _ -> 4
    | ModRMType.ModRMOp5 _ -> 5
    | ModRMType.ModRMOp6 _ -> 6
    | ModRMType.ModRMOp7 _ -> 7
    | _ -> -1

  /// Returns true when no row that REX.W could have chosen instead of this
  /// one asks for it. A row has to ask for the wider form before W is doing
  /// any work: TEST's 64-bit row asks at 85h and so keeps the 32-bit row from
  /// answering the prefixed bytes, while nothing asks at A8h, where the
  /// operand is a byte and there is no width to switch to. The question is
  /// put to the rows sharing this one's group digit, not to the whole slot:
  /// FF holds CALL at /2 and the far CALL at /3, and the far form's REX.W
  /// says nothing about the near one, which has no wider form to switch to
  /// and is written with a REX.W by MSVC all the same. Only a row sharing the
  /// mandatory prefix counts, too: CVTTSD2SI asks for W under F2 and
  /// CVTTPS2PI sits at the same opcode byte under no prefix, and reading the
  /// F2 row as a rival left REX.W + 0F 2C decoding as nothing.
  let private noRivalAsksForW slot (core: InstructionCore) =
    let digit = groupDigit core.ModRM
    let asksForW (i: InstructionCore) =
      (i.REXPrefixType = REXPrefixType.W1
       || i.REXPrefixType = REXPrefixType.REXW)
      && groupDigit i.ModRM = digit
      && i.PrefixType = core.PrefixType
    not (Array.exists asksForW slot)

  /// Returns true for opcodes that implicitly operate on 16-bit operands
  /// without encoding an explicit size (e.g., MOVSW, PUSHF, IRET).
  let private hasImplicit16BitOprSize = function
    | Opcode.CBW | Opcode.CWD
    | Opcode.PUSHF | Opcode.PUSHA
    | Opcode.POPF | Opcode.POPA
    | Opcode.MOVSW | Opcode.CMPSW | Opcode.SCASW | Opcode.LODSW | Opcode.STOSW
    | Opcode.INSW | Opcode.OUTSW
    | Opcode.IRET -> true
    | _ -> false

  /// The width a descriptor declares. A negative stands in for "declares
  /// none", so that the sizes below can be compared without wrapping each in
  /// an option: zero is a real width here, carried by an operand the manual
  /// gives no size for.
  let private noWidth = -1<rt>

  let private declaredWidth = function
    | RM sz | Reg(sz, _) | Mem sz | Imm sz | Rel sz | Moffs sz
    | Far sz -> sz
    | FixedReg Register.AX -> 16<rt>
    | _ -> noWidth

  /// How many distinct widths the descriptors declare and what the first two
  /// are. Only those three facts decide whether 66h is required.
  let private firstTwoWidths (operands: OperandType[]) =
    let mutable count = 0
    let mutable first = noWidth
    let mutable second = noWidth
    for o in operands do
      let w = declaredWidth o
      if count = 0 then
        count <- 1
        first <- w
      elif count = 1 && w <> first then
        second <- w
        count <- 2
      elif count >= 2 && w <> first && w <> second then
        count <- count + 1
      else
        ()
    struct (count, first, second)

  /// Returns true when this instruction variant requires the 66h prefix. Some
  /// opcodes are excluded because their 16-bit form omits it.
  let private needs66hPrefix widths op =
    let struct (count, first, second) = widths
    if count = 1 && first = 16<rt> then op <> Opcode.RET
    elif count = 2 && first = 16<rt> then op <> Opcode.ENTER
    elif count = 2 && first = noWidth && second = 16<rt> then op <> Opcode.MOV
    elif count = 2 && first = 8<rt> && second = 16<rt> then op = Opcode.OUT
    elif count = 1 && first = noWidth then hasImplicit16BitOprSize op
    else false

  /// The width a fixed-register operand implies. Segment registers give
  /// 0<rt>: an operand-size prefix never selects between them.
  let private fixedRegSize = function
    | Register.AL | Register.CL -> 8<rt>
    | Register.AX | Register.DX -> 16<rt>
    | Register.EAX -> 32<rt>
    | Register.RAX -> 64<rt>
    | _ -> 0<rt>

  /// The width an operand descriptor declares, or 0<rt> when it carries none.
  /// A multi-size form reports its register width, which is the side an
  /// operand-size prefix selects.
  let private oprWidth = function
    | RM sz | Reg(sz, _) | RegSae sz | Mem sz | MemVSIB sz | Moffs sz
    | Far sz | Imm sz | Rel sz | KM sz | MM sz | BM sz -> sz
    | RMdiff(sz, _) | RMEr(sz, _) | RMSae(sz, _) -> sz
    | RMBcst(sz, _, _) | RMBcstEr(sz, _, _) | RMBcstSae(sz, _, _) -> sz
    | FixedReg r -> fixedRegSize r
    | _ -> 0<rt>

  /// Returns the widest declared operand size in the descriptors, or 0<rt>
  /// when none of them carries one.
  let private maxOprSize (core: InstructionCore) =
    core.Operands |> Array.fold (fun w o -> max w (oprWidth o)) 0<rt>

  /// Returns true when 66h is what picks this variant out of its slot, i.e.
  /// the slot also holds the same opcode with a wider operand. Opcodes whose
  /// 16-bit form encodes no explicit size (MOVSW, PUSHF, ...) have nothing to
  /// compare, and hasImplicit16BitOprSize already names them.
  let private is66hSelector slot (core: InstructionCore) =
    let sz = maxOprSize core
    sz = 0<rt>
    || slot
       |> Array.exists (fun (i: InstructionCore) ->
         i.Opcode = core.Opcode && maxOprSize i > sz)

  /// Returns true when the row names a vector or an MMX register. The SIMD
  /// opcodes spend 66h, F2h and F3h on naming the instruction, so a
  /// combination no row asks for is invalid there; everywhere else those
  /// bytes stay ordinary prefixes and the unprefixed row answers. The
  /// processor draws the line exactly here: F2 0F BC runs BSF while F2 0F 28
  /// raises #UD.
  let private namesAVectorRegister (core: InstructionCore) =
    core.Operands
    |> Array.exists (function
      | MMXReg _ | MM _ | KM _ | MemVSIB _ ->
        true
      | RM sz | Reg(sz, _) | RegSae sz | Mem sz | Moffs sz
      | RMdiff(sz, _) | RMEr(sz, _) | RMSae(sz, _)
      | RMBcst(sz, _, _) | RMBcstEr(sz, _, _) | RMBcstSae(sz, _, _) ->
        sz >= 128<rt>
      | _ ->
        false)

  /// Returns true when the instruction offers embedded rounding, which is what
  /// gives EVEX.b its {er} meaning. {sae} alone does not: it leaves L'L as the
  /// vector length.
  let private declaresStaticRounding (core: InstructionCore) =
    core.Operands
    |> Array.exists (function
      | RMEr _ | RMBcstEr _ -> true
      | _ -> false)

  let private usesVSIB (core: InstructionCore) =
    core.Operands
    |> Array.exists (function
      | MemVSIB _ -> true
      | _ -> false)

  /// The instructions a LOCK prefix may be prepended to, transcribed from the
  /// manual's LOCK page. That page also states the second half of the rule,
  /// which the parser checks: "The LOCK prefix can be prepended only to the
  /// following instructions and only to those forms of the instructions where
  /// the destination operand is a memory operand." Anything else raises #UD,
  /// which the hardware does.
  let private takesLock = function
    | Opcode.ADD | Opcode.ADC | Opcode.AND | Opcode.BTC | Opcode.BTR
    | Opcode.BTS | Opcode.CMPXCHG | Opcode.CMPXCHG8B | Opcode.CMPXCHG16B
    | Opcode.DEC | Opcode.INC | Opcode.NEG | Opcode.NOT | Opcode.OR
    | Opcode.SBB | Opcode.SUB | Opcode.XOR | Opcode.XADD | Opcode.XCHG -> true
    | _ -> false

  /// Returns true when the row's destination, which is its first operand, is
  /// one that can name memory. XCHG reaches here from 90h+rd as well, where
  /// both operands are registers and no ModRM byte follows, so this settles
  /// those before the ModRM byte would be read.
  let private destCanBeMemory (operands: OperandType[]) =
    operands.Length > 0
    && (match operands[0] with
        | RM _ | RMdiff _ | Mem _ | MM _ | BM _ | KM _ -> true
        | _ -> false)

  /// Returns true when the row is valid in 64-bit mode. The manual spells the
  /// same verdict "Inv." in some tables and "Invalid" in others.
  let private okIn64 (core: InstructionCore) =
    match core.Mode64 with
    | Mode64.Invalid | Mode64.Inv | Mode64.NE | Mode64.NS -> false
    | _ -> true

  /// Returns true when the row is valid in 32-bit mode.
  let private okIn32 (core: InstructionCore) =
    core.Compat <> CompatLegMode.NE && core.Compat <> CompatLegMode.Invalid

  /// The far returns. The SDM writes CB and C3 both as "RET" over an empty
  /// operand column, and CA and C2 both as "RET imm16", so nothing the table
  /// carries tells a return that crosses a segment from one that does not and
  /// the opcode byte is all that is left to ask. Being far costs the row its
  /// d64 default too: the opcode maps annotate RETN with d64 and leave RETF
  /// alone. SDM Vol. 2D, Table A-2.
  let private isFarReturn (core: InstructionCore) =
    core.Opcode = Opcode.RET
    && (core.OpcodeByte = 0xCAu || core.OpcodeByte = 0xCBu)

  /// The string instructions the manual writes with a B suffix always move a
  /// byte at a time, whatever the operand-size prefix says. The table leaves
  /// their operands implicit, so the mnemonic is the only thing left to ask.
  let private isByteStringOp = function
    | Opcode.INSB | Opcode.OUTSB | Opcode.MOVSB | Opcode.CMPSB
    | Opcode.STOSB | Opcode.LODSB | Opcode.SCASB -> true
    | _ -> false

  /// Returns true when the opcode has a sign-extending immediate encoding.
  let private supportsSignExtendedImmediate = function
    | Opcode.ADC | Opcode.ADD | Opcode.AND | Opcode.CMP | Opcode.IMUL
    | Opcode.MOV | Opcode.OR | Opcode.SBB | Opcode.SUB | Opcode.TEST
    | Opcode.XOR | Opcode.PUSH -> true
    | _ -> false

  /// Returns true when the immediate is narrower than the effective operand
  /// width and must be sign-extended (includes PUSH imm8).
  let private hasSignExtendedImmediateSizeMismatch opcode widths =
    let struct (count, first, second) = widths
    if count = 2 && first = noWidth && second = 8<rt> then
      false (* Implicit accumulator + imm8; no widening. *)
    elif count = 1 && first <> noWidth && opcode = Opcode.PUSH then
      true (* PUSH imm8 is sign-extended to the stack operand width. *)
    elif count = 1 then
      false (* Single-size operand shape; no sign-extension case. *)
    else
      true

  /// Returns the RegType size for a FixedImm operand inferred from the
  /// surrounding operand size array.
  let private getFixedImmSize widths =
    let struct (count, first, second) = widths
    let isGprWidth =
      first = 8<rt> || first = 16<rt> || first = 32<rt> || first = 64<rt>
    if count = 2 && second = noWidth && isGprWidth then first
    else 0<rt>

  let private isSegmentRegister = function
    | Register.ES | Register.CS | Register.SS
    | Register.DS | Register.FS | Register.GS -> true
    | _ -> false

  /// The width an operand descriptor lends to the instruction as a whole, as
  /// a kind and its widths, or None when it lends none. An immediate or a
  /// relative offset is read at the width the opcode gives it and says nothing
  /// about how wide the operation runs, so neither answers here. A segment
  /// register lends nothing either: PUSH FS runs at the width of the stack,
  /// not at the sixteen bits the selector occupies. Any other fixed register
  /// that is as wide in one mode as in the other is settled here; one that is
  /// not is left for the parser to size.
  let private operandOperationWidth = function
    | RM sz | RegSae sz | Reg(sz, _) | KM sz | MM sz | BM sz | Moffs sz
    | Mem sz ->
      Some(struct (OpWidthKind.Fixed, sz, 0<rt>, Register.EAX))
    | RMdiff(regSz, memSz) ->
      Some(struct (OpWidthKind.ByModRMForm, regSz, memSz, Register.EAX))
    | RMEr(sz, _) | RMSae(sz, _)
    | RMBcst(sz, _, _) | RMBcstEr(sz, _, _) | RMBcstSae(sz, _, _) ->
      Some(struct (OpWidthKind.Fixed, sz, 0<rt>, Register.EAX))
    | Far sz ->
      Some(struct (OpWidthKind.Fixed, sz + 16<rt>, 0<rt>, Register.EAX))
    | MMXReg _ -> (* An MMX register is a whole 64 bits wide. *)
      Some(struct (OpWidthKind.Fixed, 64<rt>, 0<rt>, Register.EAX))
    | Sreg -> (* A selector is sixteen bits wherever it is written. *)
      Some(struct (OpWidthKind.Fixed, 16<rt>, 0<rt>, Register.EAX))
    | FixedReg reg when isSegmentRegister reg ->
      None
    | FixedReg reg ->
      let w32 = RegisterHelper.toRegType WordSize.Bit32 reg
      let w64 = RegisterHelper.toRegType WordSize.Bit64 reg
      if w32 = w64 then Some(struct (OpWidthKind.Fixed, w32, 0<rt>, reg))
      else Some(struct (OpWidthKind.FixedRegister, 0<rt>, 0<rt>, reg))
    | RegAddr ->
      Some(struct (OpWidthKind.EffectiveAddress, 0<rt>, 0<rt>, Register.EAX))
    | _ ->
      None

  /// The width the whole operation runs at. Parsing leaves behind whatever
  /// the last operand happened to need, which is the wrong answer wherever
  /// the operands differ: MOV r/m8, imm8 runs at eight bits however wide the
  /// prefixes would read a bare immediate.
  let private operationWidth (core: InstructionCore) =
    core.Operands
    |> Array.tryPick operandOperationWidth
    |> Option.defaultValue
      (struct (OpWidthKind.FromPrefixes, 0<rt>, 0<rt>, Register.EAX))

  /// A register descriptor of the given width, read from the given field.
  let private regSpec sz field =
    { Kind = OprKind.Reg
      Size = sz
      MemSize = 0<rt>
      BcstSize = 0<rt>
      Value = 0
      Field = field }

  /// A descriptor of the given kind and widths that names no field.
  let private spec kind sz memSz bcstSz value =
    { Kind = kind
      Size = sz
      MemSize = memSz
      BcstSize = bcstSz
      Value = value
      Field = Unused }

  /// The flat form of one operand descriptor. LDDQU is the one instruction
  /// whose sizeless memory operand is not sized by the prefixes: it reads a
  /// whole XMM register's worth.
  let private oprSpec opcode = function
    | RM sz ->
      spec OprKind.RM sz sz 0<rt> 0
    | RMdiff(regSz, memSz) | RMEr(regSz, memSz) | RMSae(regSz, memSz) ->
      spec OprKind.RMTwoWidths regSz memSz 0<rt> 0
    | RMBcst(regSz, memSz, bcstSz)
    | RMBcstEr(regSz, memSz, bcstSz)
    | RMBcstSae(regSz, memSz, bcstSz) ->
      spec OprKind.RMBroadcast regSz memSz bcstSz 0
    | MemVSIB elemSz ->
      spec OprKind.MemVSIB elemSz 0<rt> 0<rt> 0
    | Reg(sz, field) ->
      regSpec sz field
    | RegSae sz ->
      regSpec sz RegBit
    | Mem 0<rt> when opcode = Opcode.LDDQU ->
      spec OprKind.Mem 128<rt> 128<rt> 0<rt> 0
    | Mem 0<rt> ->
      spec OprKind.MemFromPrefixes 0<rt> 0<rt> 0<rt> 0
    | Mem sz ->
      spec OprKind.Mem sz sz 0<rt> 0
    | Imm sz ->
      spec OprKind.Imm sz 0<rt> 0<rt> 0
    | Rel sz ->
      spec OprKind.Rel sz 0<rt> 0<rt> 0
    | FixedReg reg ->
      let w32 = RegisterHelper.toRegType WordSize.Bit32 reg
      let w64 = RegisterHelper.toRegType WordSize.Bit64 reg
      if w32 = w64 then spec OprKind.FixedReg w32 0<rt> 0<rt> (int reg)
      else spec OprKind.FixedRegModeWidth 0<rt> 0<rt> 0<rt> (int reg)
    | STReg None ->
      spec OprKind.STRegRM 0<rt> 0<rt> 0<rt> 0
    | STReg(Some reg) ->
      spec OprKind.STRegFixed 0<rt> 0<rt> 0<rt> (int reg)
    | BM sz ->
      spec OprKind.BM sz sz 0<rt> 0
    | BndReg ->
      spec OprKind.BndReg 0<rt> 0<rt> 0<rt> 0
    | OpMaskReg field ->
      { regSpec 0<rt> field with Kind = OprKind.OpMaskReg }
    | KM sz ->
      spec OprKind.KM sz sz 0<rt> 0
    | MMXReg field ->
      { regSpec 0<rt> field with Kind = OprKind.MMXReg }
    | MM sz ->
      spec OprKind.MM sz sz 0<rt> 0
    | FixedImm imm ->
      spec OprKind.FixedImm 0<rt> 0<rt> 0<rt> imm
    | Moffs sz ->
      spec OprKind.Moffs sz sz 0<rt> 0
    | CtrlReg ->
      spec OprKind.CtrlReg 0<rt> 0<rt> 0<rt> 0
    | DebugReg ->
      spec OprKind.DebugReg 0<rt> 0<rt> 0<rt> 0
    | RegAddr ->
      spec OprKind.RegAddr 0<rt> 0<rt> 0<rt> 0
    | Sreg ->
      spec OprKind.Sreg 0<rt> 0<rt> 0<rt> 0
    | Far sz ->
      spec OprKind.Far sz 0<rt> 0<rt> 0
    | NoOpr | Unknown _ ->
      spec OprKind.Unsupported 0<rt> 0<rt> 0<rt> 0

  /// The ModRM constraint of a row as a mask, the value the masked byte has
  /// to equal, and whether the row takes only a memory form. A register-only
  /// form asks for mod = 11 through the mask; a memory-only form cannot,
  /// since three values of mod name memory, so it says so beside the mask.
  let private modRMTest (core: InstructionCore) =
    let digit = groupDigit core.ModRM
    match core.ModRM with
    | ModRMType.NoModRM | ModRMType.ModRM OpRegMem ->
      struct (0uy, 0uy, false)
    | ModRMType.ModRM OpReg ->
      struct (0b11000000uy, 0b11000000uy, false)
    | ModRMType.ModRM OpMem ->
      struct (0uy, 0uy, true)
    | ModRMType.FixedModRM v ->
      struct (0xFFuy, v, false)
    | ModRMType.STiModRM v when v &&& 0b111uy = 0uy ->
      struct (0b11111000uy, v, false)
    | ModRMType.STiModRM v ->
      failwithf "An ST(i) row has to start at a multiple of 8: %02x" v
    | ModRMType.ModRMOp0 o | ModRMType.ModRMOp1 o | ModRMType.ModRMOp2 o
    | ModRMType.ModRMOp3 o | ModRMType.ModRMOp4 o | ModRMType.ModRMOp5 o
    | ModRMType.ModRMOp6 o | ModRMType.ModRMOp7 o ->
      let value = byte (digit <<< 3)
      match o with
      | OpRegMem -> struct (0b00111000uy, value, false)
      | OpReg -> struct (0b11111000uy, 0b11000000uy ||| value, false)
      | OpMem -> struct (0b00111000uy, value, true)

  /// The ModRM.reg digit that leaves the row in play, or -1 when every digit
  /// does. A fixed byte names its digit in bits 5:3, and so do the eight
  /// bytes an ST(i) row accepts, which differ only below bit 3.
  let private digitInPlay (core: InstructionCore) =
    match core.ModRM with
    | ModRMType.FixedModRM v -> (int v >>> 3) &&& 0b111
    | ModRMType.STiModRM v when v &&& 0b111uy = 0uy -> (int v >>> 3) &&& 0b111
    | ModRMType.STiModRM _ -> -1
    | modRM -> groupDigit modRM

  /// The facts about a row and its slot that the REX and mandatory-prefix
  /// checks read.
  type private Asks =
    { PrefixSel: PrefixSel
      REXType: REXPrefixType
      /// 66h is what picks the row out of its slot.
      Requires66h: bool
      /// Every operand is eight bits wide, so REX.W has no wider form to pick.
      AllOpr8: bool
      /// No row sharing this one's group digit and mandatory prefix asks for
      /// REX.W, so a REX.W in front of this row rides along inert.
      NoRivalAsksForW: bool
      /// The row names a vector or an MMX register.
      NamesVector: bool
      /// The row is 90h in the one-byte map, which F3h turns into PAUSE.
      IsNopOrPause: bool
      /// The row sits in one of the legacy three-byte maps.
      IsThreeByteMap: bool
      /// A row of the slot asks for 66h.
      SlotHas66: bool
      /// A row of the slot asks for 66h and F2h together.
      SlotHas66F2: bool
      /// A row of the slot asks for F3h.
      SlotHasF3: bool
      /// A row of the slot asks for F2h.
      SlotHasF2: bool }

  /// Returns true when the given REX state satisfies the constraint the row
  /// declares (NOREX / W0 / W1 / WIG / REXW). An all-8-bit row answers
  /// whatever REX says, because there is no wider form for W to select. VEX
  /// and EVEX carry a W of their own, so a REX.W that nothing asks for is
  /// inert only where there is no VEX prefix.
  let private acceptsREX (asks: Asks) rexState vexPresent =
    let insREX = asks.REXType
    match rexState with
    | 0 ->
      insREX = REXPrefixType.WIG || insREX = REXPrefixType.W0
      || insREX = REXPrefixType.NOREX || asks.AllOpr8
    | 2 ->
      insREX = REXPrefixType.WIG || insREX = REXPrefixType.W1
      || insREX = REXPrefixType.REXW
      || (insREX = REXPrefixType.NOREX
          && vexPresent = 0 && asks.NoRivalAsksForW)
      || asks.AllOpr8
    | _ ->
      (* A prefix with W clear. It still extends registers, so a row that says
         nothing about W matches; one that asks for W1 does not, and letting it
         through leaves VFMADD132PS and VFMADD132PD both matching their shared
         opcode byte with nothing but table order to tell them apart. *)
      insREX = REXPrefixType.WIG || insREX = REXPrefixType.W0
      || insREX = REXPrefixType.NOREX || insREX = REXPrefixType.REX
      || asks.AllOpr8

  /// Returns true when a repeat prefix is naming the instruction rather than
  /// repeating it. It names one where a row asks for it, and it names one on
  /// a SIMD opcode or anywhere in the three-byte maps whether or not a row
  /// asks: there an unclaimed prefix is invalid rather than ignored. The
  /// three-byte maps arrived with the SIMD extensions and spend the repeat
  /// prefixes on naming instructions throughout them, GPR opcodes included:
  /// F3 0F 38 F1 is not MOVBE with a repeat in front of it, it is invalid,
  /// while F3 0F C8 is BSWAP with one.
  let private isRepOpcodeSelector (asks: Asks) vexPresent asked =
    vexPresent = 1 || asks.IsThreeByteMap || asks.NamesVector || asked

  /// Returns true when the prefix state satisfies the row's mandatory prefix,
  /// with Legacy NP as a fallback for Mandatory NP. Where no row asks for 66h
  /// it is not selecting anything, so it is left out of the question here and
  /// the operand-size check reads it instead: MOVUPD asks at 0F 10 and so
  /// keeps MOVUPS from answering the prefixed bytes, while nothing asks at 0F
  /// 38 F1, which leaves 66h free to mean the width MOVBE's 16-bit form is
  /// written with. Under F2h a row asks for the pair, so CRC32's narrow
  /// source is a separate question from MOVBE's.
  let private acceptsPrefix (asks: Asks) vexPresent prefState =
    let sel = asks.PrefixSel
    let repz = prefState &&& 0b010 <> 0
    let repnz = prefState &&& 0b001 <> 0
    let selects66 = if repnz then asks.SlotHas66F2 else asks.SlotHas66
    let has66 = prefState &&& 0b100 <> 0 && selects66
    if not has66 && not repz && not repnz then
      sel = PrefixSel.LegacyNP || sel = PrefixSel.MandatoryNP
    elif has66 && repnz then
      sel = PrefixSel.Mandatory66F2
    elif has66 then
      sel = PrefixSel.Mandatory66 || sel = PrefixSel.LegacyNP
    elif repz then
      sel = PrefixSel.MandatoryF3 || sel = PrefixSel.LegacyNP
      || (sel = PrefixSel.MandatoryNP
          && not (isRepOpcodeSelector asks vexPresent asks.SlotHasF3))
    elif repnz then
      sel = PrefixSel.MandatoryF2 || sel = PrefixSel.LegacyNP
      || (sel = PrefixSel.MandatoryNP
          && not (isRepOpcodeSelector asks vexPresent asks.SlotHasF2))
    else
      false

  /// Returns true when the prefix state is compatible with the operand size
  /// the row's descriptors imply. REX.W settles the operand size by itself
  /// and outranks 66h, so the row only 66h can select is not the one an
  /// encoding carrying both asked for. SDM Vol. 2A, 2.2.1.2. With a VEX
  /// prefix the 66h asked about is the legacy one in front of it, which the
  /// prefix state does not carry, so that case is left for parse time.
  let private acceptsOperandSize (asks: Asks) rexState vexPresent prefState =
    vexPresent = 1 || not asks.Requires66h
    || (prefState &&& 0b100 <> 0 && rexState <> 2)

  /// Returns true when the row answers the REX and prefix state. F3 90 is the
  /// one opcode that deviates from the mandatory-prefix rules: it is PAUSE, a
  /// separate instruction the F3 prefix names.
  let private accepts asks rexState vexPresent prefState =
    let isPause =
      asks.IsNopOrPause && vexPresent = 0 && prefState &&& 0b010 <> 0
    acceptsREX asks rexState vexPresent
    && (if isPause then asks.PrefixSel = PrefixSel.MandatoryF3
        else acceptsPrefix asks vexPresent prefState)
    && acceptsOperandSize asks rexState vexPresent prefState

  /// The match contexts the row answers, one bit apiece.
  let private acceptMask asks =
    let mutable mask = 0UL
    for rexState in 0 .. 2 do
      for vexPresent in 0 .. 1 do
        for prefState in 0 .. 7 do
          if accepts asks rexState vexPresent prefState then
            let i = MatchContext.index rexState vexPresent prefState
            mask <- mask ||| (1UL <<< i)
          else
            ()
    mask

  /// The shape of the operands, where it is one read by code of its own.
  let private oprShape (operands: OperandType[]) =
    match operands with
    | [| Reg(_, RegBit); RM _ |] -> OprShape.RegThenRM
    | [| RM _; Reg(_, RegBit) |] -> OprShape.RMThenReg
    | [| RM _; Imm _ |] -> OprShape.RMThenImm
    | [| RM _ |] -> OprShape.RMOnly
    | [| Rel _ |] -> OprShape.RelOnly
    | [| Reg(_, OpRd) |] -> OprShape.RegOpRdOnly
    | _ -> OprShape.Other

  let private buildRow map (slot: InstructionCore[]) (core: InstructionCore) =
    let widths = firstTwoWidths core.Operands
    let isFarRet = isFarReturn core
    let struct (modRMMask, modRMValue, modRMNotReg) = modRMTest core
    let digit = groupDigit core.ModRM
    let prefixSels = slot |> Array.map (fun c -> prefixSel c.PrefixType)
    let isOneByteMap =
      match map with
      | OpcodeClass.Normal OpcodeMap.OneByte -> true
      | _ -> false
    let requires66h =
      core.OpEn <> OpEn.None
      && needs66hPrefix widths core.Opcode
      && is66hSelector slot core
    let asks =
      { PrefixSel = prefixSel core.PrefixType
        REXType = core.REXPrefixType
        Requires66h = requires66h
        AllOpr8 = isAllOprSize8 core.Operands
        NoRivalAsksForW = noRivalAsksForW slot core
        NamesVector = namesAVectorRegister core
        IsNopOrPause = isOneByteMap && core.OpcodeByte = 0x90u
        IsThreeByteMap =
          (match map with
           | OpcodeClass.Normal ThreeBytes38
           | OpcodeClass.Normal ThreeBytes3A -> true
           | _ -> false)
        SlotHas66 = Array.contains PrefixSel.Mandatory66 prefixSels
        SlotHas66F2 = Array.contains PrefixSel.Mandatory66F2 prefixSels
        SlotHasF3 = Array.contains PrefixSel.MandatoryF3 prefixSels
        SlotHasF2 = Array.contains PrefixSel.MandatoryF2 prefixSels }
    let accept = acceptMask asks
    let isE3 = isOneByteMap && core.OpcodeByte = 0xE3u
    let isPlainNop =
      core.Opcode = Opcode.NOP && core.ModRM = ModRMType.NoModRM
    let struct (opWidthKind, opWidth, opWidthMem, opWidthReg) =
      operationWidth core
    let specs = core.Operands |> Array.map (oprSpec core.Opcode)
    { ModRMMask = modRMMask
      ModRMValue = modRMValue
      ModRMNotReg = modRMNotReg
      ModRMAny = modRMMask = 0uy && not modRMNotReg
      Accept32 = if okIn32 core then accept else 0UL
      Accept64 = if okIn64 core then accept else 0UL
      Requires66h = requires66h
      Plain =
        not isE3 && not isPlainNop && core.VectorLength = VectorLength.None
      VectorLength = core.VectorLength
      DeclaresER = declaresStaticRounding core
      IsE3 = isE3
      IsPlainNop = isPlainNop
      UsesVSIB = usesVSIB core
      LockableDest = takesLock core.Opcode && destCanBeMemory core.Operands
      SlotDeclaresER = Array.exists declaresStaticRounding slot
      Opcode = core.Opcode
      OpcodeByte = byte core.OpcodeByte
      OprSpecs = specs
      OperandCount =
        if core.Operands = [| NoOpr |] then 0 else core.Operands.Length
      Shape = oprShape core.Operands
      Size0 = if specs.Length > 0 then specs[0].Size else 0<rt>
      Size1 = if specs.Length > 1 then specs[1].Size else 0<rt>
      HasModRM = core.ModRM <> ModRMType.NoModRM
      IsGroupExtension = digit >= 0
      TupleType = core.TupleType
      SzCond = core.SzCond
      EffSzCond = if isFarRet then SzCond.Normal else core.SzCond
      SelectorPrefixes = selectorPrefixes core.PrefixType
      IsNopOrPause = asks.IsNopOrPause
      IsFarRet = isFarRet
      IsByteString = isByteStringOp core.Opcode
      SignExtendsImm =
        supportsSignExtendedImmediate core.Opcode
        && hasSignExtendedImmediateSizeMismatch core.Opcode widths
      FixedImmSize = getFixedImmSize widths
      OpWidthKind = opWidthKind
      OpWidth = opWidth
      OpWidthMem = opWidthMem
      OpWidthReg = opWidthReg
      Next = Unchecked.defaultof<Row> }

  /// The rows of one slot that a ModRM.reg digit leaves in play, in order.
  let private rowsForDigit (slot: InstructionCore[]) (rows: Row[]) digit =
    Array.zip slot rows
    |> Array.filter (fun (core, _) ->
      let d = digitInPlay core
      d < 0 || d = digit)
    |> Array.map snd

  /// One opcode map in table order: the rows a ModRM.reg digit leaves in
  /// play for each opcode byte, at index (byte <<< 3) ||| digit. A row that
  /// spends ModRM.reg on naming itself sits under its digit alone; every
  /// other row sits under all eight, so each list keeps the table's order.
  /// The group opcodes hold up to 24 rows, of which a digit leaves three.
  /// An instruction that ends where the bytes do has no ModRM byte to read a
  /// digit from and reads digit 0. Only D4 and D5 hold a row that spends
  /// ModRM.reg beside one that reads no ModRM byte at all, and both of those
  /// rows go on to read an immediate the bytes have no room for either, so
  /// that instruction fails to parse as it did when digit rows led. The
  /// eight lists of a byte no digit narrows are one and the same array.
  let private buildTable map (slots: InstructionCore[][]) =
    let rows =
      slots |> Array.map (fun slot -> Array.map (buildRow map slot) slot)
    Array.init (256 * 8) (fun i ->
      let b, digit = i >>> 3, i &&& 0b111
      if Array.exists (fun core -> digitInPlay core >= 0) slots[b] then
        rowsForDigit slots[b] rows[b] digit
      else
        rows[b])

  let private norOne =
    buildTable (OpcodeClass.Normal OpcodeMap.OneByte) InstructionArrays.norOne

  let private norTwo =
    buildTable (OpcodeClass.Normal OpcodeMap.TwoBytes) InstructionArrays.norTwo

  let private norThree38 =
    buildTable (OpcodeClass.Normal ThreeBytes38) InstructionArrays.norThree38

  let private norThree3A =
    buildTable (OpcodeClass.Normal ThreeBytes3A) InstructionArrays.norThree3A

  let private vexTwoRows =
    buildTable (OpcodeClass.VEX OpcodeMap.TwoBytes) InstructionArrays.vexTwo

  let private vexThree38Rows =
    buildTable (OpcodeClass.VEX ThreeBytes38) InstructionArrays.vexThree38

  let private vexThree3ARows =
    buildTable (OpcodeClass.VEX ThreeBytes3A) InstructionArrays.vexThree3A

  let private evexTwoRows =
    buildTable (OpcodeClass.EVEX OpcodeMap.TwoBytes) InstructionArrays.evexTwo

  let private evexThree38Rows =
    buildTable (OpcodeClass.EVEX ThreeBytes38) InstructionArrays.evexThree38

  let private evexThree3ARows =
    buildTable (OpcodeClass.EVEX ThreeBytes3A) InstructionArrays.evexThree3A

  let private evexMap5Rows =
    buildTable (OpcodeClass.EVEX MAP5) InstructionArrays.evexMap5

  let private evexMap6Rows =
    buildTable (OpcodeClass.EVEX MAP6) InstructionArrays.evexMap6

  /// Returns true when some encoding could match both rows in the given mode,
  /// which is when their accept masks intersect. Two rows that no encoding
  /// matches both of may change places without changing which row answers
  /// any instruction.
  let private mayShareEncoding is64 (a: Row) (b: Row) =
    if is64 then a.Accept64 &&& b.Accept64 <> 0UL
    else a.Accept32 &&& b.Accept32 <> 0UL

  /// The rows in an order that puts those answering the plainest state, no
  /// REX, no VEX and none of 66h, F3h and F2h, ahead of those that do not,
  /// moving a row only past rows it shares no encoding with. The first row the
  /// parser tries is then the one most instructions want, while the table's
  /// order still decides wherever it could matter: the 16-bit form of MOV
  /// sits ahead of the 32-bit one in the table, and every 32-bit MOV had to
  /// be refused it first.
  let private orderForMode is64 (rows: Row[]) =
    let plainBit = 1UL <<< MatchContext.index 0 0 0
    let answersPlain (r: Row) =
      (if is64 then r.Accept64 else r.Accept32) &&& plainBit <> 0UL
    let rows = Array.copy rows
    let mutable swapped = true
    while swapped do
      swapped <- false
      for i in 0 .. rows.Length - 2 do
        if not (answersPlain rows[i])
           && answersPlain rows[i + 1]
           && not (mayShareEncoding is64 rows[i] rows[i + 1]) then
          let row = rows[i]
          rows[i] <- rows[i + 1]
          rows[i + 1] <- row
          swapped <- true
        else
          ()
    rows

  /// The rows of one list, copied and chained through Next in the order the
  /// given mode reads them, or null for an empty list. A row sits in up to
  /// eight lists with a different successor in each, so every list gets
  /// copies of its own; copies of a row are the same row for every purpose
  /// but their place in a chain. Lists that are the same array are chained
  /// once and shared.
  let private chain is64 (shared: Dictionary<Row[], Row>) (rows: Row[]) =
    match shared.TryGetValue rows with
    | true, head ->
      head
    | _ ->
      let mutable next = Unchecked.defaultof<Row>
      for row in Array.rev (orderForMode is64 rows) do
        next <- { row with Next = next }
      shared[rows] <- next
      next

  /// One opcode map as the parser reads it: the first row in play for each
  /// opcode byte and ModRM.reg digit, the rest chained behind it.
  let private chains is64 (tables: Row[][][]) =
    let shared = Dictionary<Row[], Row>(HashIdentity.Reference)
    tables |> Array.concat |> Array.map (chain is64 shared)

  /// The four legacy maps end to end, so that the parser reaches a slot of
  /// any of them through one array: the map's number goes in bits 13:11,
  /// above the opcode byte and the digit. One copy per mode, each ordered
  /// for it.
  let private legacy is64 =
    chains is64 [| norOne; norTwo; norThree38; norThree3A |]

  /// The legacy maps as a 32-bit parser reads them.
  let legacy32 = legacy false

  /// The legacy maps as a 64-bit parser reads them.
  let legacy64 = legacy true

  (* No VEX row answers the plainest state, so the mode leaves their order
     alone and both modes read the same chains. *)
  let vexTwo = chains true [| vexTwoRows |]

  let vexThree38 = chains true [| vexThree38Rows |]

  let vexThree3A = chains true [| vexThree3ARows |]

  let evexTwo = chains true [| evexTwoRows |]

  let evexThree38 = chains true [| evexThree38Rows |]

  let evexThree3A = chains true [| evexThree3ARows |]

  let evexMap5 = chains true [| evexMap5Rows |]

  let evexMap6 = chains true [| evexMap6Rows |]

// vim: set tw=80 sts=2 sw=2:
