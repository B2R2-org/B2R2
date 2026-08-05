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
/// Encodes the instructions of the floating-point unit, which answers to the
/// coprocessor identifier of one and reads a command word of its own after the
/// opcode word: the arithmetic in every precision it rounds to, the moves in
/// every format it converts between, the moves of the registers it keeps for
/// itself, the branches and the conditionals on its predicates, and the two
/// that move the whole of its internal state.
/// </summary>
module internal B2R2.Assembly.M68K.AsmFloat

open B2R2
open B2R2.FrontEnd.M68K
open B2R2.Assembly.M68K.ParserHelper
open B2R2.Assembly.M68K.AsmField

/// The three bits saying which format an address is read in, which is what the
/// suffix of the mnemonic says.
let private formatSpec ins =
  match ins.Size with
  | Sz.Long -> 0us
  | Sz.Single -> 1us
  | Sz.Extended -> 2us
  | Sz.Packed -> 3us
  | Sz.Word -> 4us
  | Sz.Double -> 5us
  | Sz.Byte -> 6us
  | _ -> fail $"{ins.Mnemonic} is not written in this format"

/// The words of an instruction of the unit whose source is one of its own
/// registers, which it reads at the extended precision it keeps its numbers in.
/// No operand is fetched, so the effective-address field is not decoded at all
/// and is written as zero.
let private regSourceWords src dst opmode =
  [ 0xf200us
    (floatNum src <<< 10) ||| (floatNum dst <<< 7) ||| opmode ]

/// The words of an instruction of the unit whose source is an address, whose
/// format the suffix of the mnemonic says.
let private eaSourceWords ins src dst opmode =
  let mode, reg, exts = floatEA isAny ins ins.Size src
  let cmd = 0x4000us ||| (formatSpec ins <<< 10) ||| (dst <<< 7) ||| opmode
  eaWord 0xf200us mode reg :: (cmd :: exts)

/// One of the arithmetic instructions of the unit, which computes from one of
/// its own registers or from an address into one of its registers.
let private floatArith opmode ins =
  match ins.Operands with
  | [ AsmReg src; AsmReg dst ] when isFloatReg src && isFloatReg dst ->
    requireOnlySize ins Sz.Extended
    regSourceWords src dst opmode
  | [ src; AsmReg dst ] when isFloatReg dst ->
    eaSourceWords ins src (floatNum dst) opmode
  | _ ->
    wrongOperands ins

/// An FTST, which sets the condition bits from one number and keeps nothing, so
/// that the field naming a register to keep it in holds nothing either.
let private floatTest ins =
  match ins.Operands with
  | [ AsmReg src ] when isFloatReg src ->
    requireOnlySize ins Sz.Extended
    regSourceWords src Register.FP0 0x3aus
  | [ src ] ->
    eaSourceWords ins src 0us 0x3aus
  | _ ->
    wrongOperands ins

/// An FSINCOS, which computes both at once and so names two of its own
/// registers to keep the answers in, the second of them in the low bits of the
/// command word.
let private floatSinCos ins =
  match ins.Operands with
  | [ AsmReg src; AsmReg cos; AsmReg dst ] when isFloatReg src ->
    requireOnlySize ins Sz.Extended
    regSourceWords src dst (0x30us ||| floatNum cos)
  | [ src; AsmReg cos; AsmReg dst ] ->
    eaSourceWords ins src (floatNum dst) (0x30us ||| floatNum cos)
  | _ ->
    wrongOperands ins

/// An FMOVECR, which loads one of the constants the unit keeps in a table of
/// its own and so names no address at all.
let private floatMoveCr ins =
  requireOnlySize ins Sz.Extended
  match ins.Operands with
  | [ AsmImm v; AsmReg dst ] when v >= 0L && v <= 127L ->
    [ 0xf200us; 0x5c00us ||| (floatNum dst <<< 7) ||| uint16 v ]
  | _ ->
    wrongOperands ins

/// The seven bits holding a k-factor, which says how much of a packed decimal
/// number to write and which is read as a number below zero.
let private kFactor v =
  if v >= -64L && v <= 63L then uint16 v &&& 0x7fus
  else fail $"{v} is not a k-factor"

/// <summary>
/// An FMOVE that writes one of the unit's registers out to an address.
///
/// A packed decimal destination carries a k-factor of its own, and which of the
/// two packed specifiers is used says whether that k-factor is written out or
/// held in a data register.
/// </summary>
let private floatToMem ins src dst rest =
  let allows mode reg =
    mode = 0us || (isMemory mode reg && isAlterable mode reg)
  let mode, reg, exts = floatEA allows ins ins.Size dst
  let head = eaWord 0xf200us mode reg
  match rest with
  | [] when ins.Size = Sz.Packed ->
    fail "a packed destination names a k-factor"
  | [] ->
    let cmd = 0x6000us ||| (formatSpec ins <<< 10) ||| (floatNum src <<< 7)
    head :: (cmd :: exts)
  | [ AsmImm k ] ->
    requireSize ins Sz.Packed
    let cmd = 0x6c00us ||| (floatNum src <<< 7) ||| kFactor k
    head :: (cmd :: exts)
  | [ AsmReg dk ] ->
    requireSize ins Sz.Packed
    let cmd = 0x7c00us ||| (floatNum src <<< 7) ||| (dataNum dk <<< 4)
    head :: (cmd :: exts)
  | _ ->
    wrongOperands ins

/// The three bits selecting which of the registers the unit keeps for itself
/// are moved.
let private controlSelect ins regs =
  let bit reg =
    match reg with
    | Register.FPCR -> 4us
    | Register.FPSR -> 2us
    | Register.FPIAR -> 1us
    | _ -> wrongOperands ins
  regs |> List.fold (fun acc reg -> acc ||| bit reg) 0us

/// Whether an operand names the registers the unit keeps for itself, which is
/// what tells which way one of the moves naming them goes.
let private isCtrlReg (reg: Register) =
  reg = Register.FPCR || reg = Register.FPSR || reg = Register.FPIAR

/// Whether an operand is a list of those registers, however many of them it
/// names.
let private isCtrlList opr =
  match opr with
  | AsmReg reg -> isCtrlReg reg
  | AsmRegList(reg :: _) -> isCtrlReg reg
  | _ -> false

/// <summary>
/// An FMOVE or an FMOVEM naming the registers the unit keeps for itself.
///
/// One register makes it an FMOVE and any other number of them an FMOVEM, there
/// being no single register for the latter to move. A register of the processor
/// holds one long word, so it can stand for one of these and no more; a list of
/// several has to be somewhere in memory. An address register is allowed here,
/// which is what the instruction address register is for.
/// </summary>
let private floatCtrl single ins list ea toMem =
  requireOnlySize ins Sz.Long
  let regs = regsOf ins list
  let select = controlSelect ins regs
  if select = 0us then fail "this names no register of the unit" else ()
  if single <> (List.length regs = 1) then
    fail $"{ins.Mnemonic} does not name this many registers"
  else
    ()
  let allows = if toMem then isAlterable else isAny
  let allows = if single then allows else both allows isMemory
  let mode, reg, exts = eaOf allows ins Sz.Long ea
  let dir = if toMem then 0x2000us else 0us
  eaWord 0xf200us mode reg :: ((0x8000us ||| dir ||| (select <<< 10)) :: exts)

/// Whether an operand is one that names the registers of the unit an FMOVEM
/// moves, which is a list of them, one of them alone, the data register holding
/// such a list, or the zero a list of none is written as.
let private isFloatListLike opr =
  match opr with
  | AsmRegList _ | AsmImm 0L -> true
  | AsmReg reg -> isFloatReg reg || isDataReg reg
  | _ -> false

/// <summary>
/// An FMOVEM of the registers the unit computes with, whose list is either the
/// eight bits of the command word or a data register holding them.
///
/// Which way it goes and which addressing mode it uses have to agree: a
/// predecrement address walks memory downwards, which is what writing the
/// registers out to it does, and a postincrement one walks upwards, which is
/// what reading them back in does. Predecrement addressing runs a written-out
/// list the other way round, as it does for an integer MOVEM.
/// </summary>
let private floatMovem ins list ea toMem =
  requireOnlySize ins Sz.Extended
  let allows = if toMem then isWritableRun else isReadableRun
  let mode, reg, exts = floatEA allows ins Sz.Extended ea
  let dynamic =
    match list with
    | AsmReg dn -> isDataReg dn
    | _ -> false
  let toPredec = toMem && mode = 4us
  let mmode = (if toPredec then 0us else 2us) ||| (if dynamic then 1us else 0us)
  let bits =
    match list with
    | AsmReg dn when dynamic -> dataNum dn <<< 4
    | _ -> regMask Register.FP0 8 (mmode = 0us) (regsOf ins list)
  let dir = if toMem then 0x2000us else 0us
  let cmd = 0xc000us ||| dir ||| (mmode <<< 11) ||| bits
  eaWord 0xf200us mode reg :: (cmd :: exts)

/// An FMOVE, which is the one name covering the move into a register of the
/// unit, the move out of one, and the move of one of the registers it keeps for
/// itself.
let private floatMove ins =
  match ins.Operands with
  | [ src; dst ] when isCtrlList dst ->
    floatCtrl true ins dst src false
  | [ src; dst ] when isCtrlList src ->
    floatCtrl true ins src dst true
  | [ AsmReg src; AsmReg dst ] when isFloatReg src && isFloatReg dst ->
    requireOnlySize ins Sz.Extended
    regSourceWords src dst 0us
  | [ src; AsmReg dst ] when isFloatReg dst ->
    eaSourceWords ins src (floatNum dst) 0us
  | [ AsmReg src; dst ] when isFloatReg src ->
    floatToMem ins src dst []
  | [ AsmReg src; dst; k ] when isFloatReg src ->
    floatToMem ins src dst [ k ]
  | _ ->
    wrongOperands ins

/// An FMOVEM, which moves a list of the registers the unit computes with or two
/// or three of the ones it keeps for itself.
let private floatMovemAny ins =
  match ins.Operands with
  | [ src; dst ] when isCtrlList dst -> floatCtrl false ins dst src false
  | [ src; dst ] when isCtrlList src -> floatCtrl false ins src dst true
  | [ list; dst ] when isFloatListLike list -> floatMovem ins list dst true
  | [ src; list ] -> floatMovem ins list src false
  | _ -> wrongOperands ins

/// An FBcc, whose predicate is in the opcode word itself and whose displacement
/// is one extension word or two.
let private floatBranch pred ins =
  match ins.Operands with
  | [ target ] ->
    let disp = relOf ins target
    if ins.Size = Sz.Long then
      (0xf2c0us ||| pred) :: relLongWords disp
    else
      requireOnlySize ins Sz.Word
      (0xf280us ||| pred) :: relWord disp
  | _ ->
    wrongOperands ins

/// An FScc, which writes one byte saying whether its predicate holds.
let private floatSet pred ins =
  requireOnlySize ins Sz.Byte
  match ins.Operands with
  | [ dst ] ->
    let mode, reg, exts = eaOf (both isData isAlterable) ins Sz.Byte dst
    eaWord 0xf240us mode reg :: (pred :: exts)
  | _ ->
    wrongOperands ins

/// An FDBcc, which counts a register down and branches while the count lasts
/// and its predicate does not hold.
let private floatDbcc pred ins =
  requireOnlySize ins Sz.Word
  match ins.Operands with
  | [ AsmReg dn; target ] ->
    (0xf248us ||| dataNum dn) :: pred :: relWord (relOf ins target)
  | _ ->
    wrongOperands ins

/// An FTRAPcc, whose operand the low three bits of the opcode word name: one
/// word of immediate data, two, or none at all.
let private floatTrapcc pred ins =
  match ins.Operands with
  | [] ->
    requireOnlySize ins Sz.NoSize
    [ 0xf27cus; pred ]
  | [ AsmImm v ] when ins.Size = Sz.Long ->
    0xf27bus :: pred :: longWords (longOf v)
  | [ AsmImm v ] ->
    requireOnlySize ins Sz.Word
    [ 0xf27aus; pred; wordOf v ]
  | _ ->
    wrongOperands ins

/// An FSAVE or an FRESTORE, which move the whole internal state of the unit and
/// so name a control address and no format.
let private floatState isSave ins =
  requireOnlySize ins Sz.NoSize
  let allows = if isSave then isWritableRun else isReadableRun
  match ins.Operands with
  | [ dst ] ->
    let mode, reg, exts = eaOf allows ins Sz.NoSize dst
    eaWord (if isSave then 0xf300us else 0xf340us) mode reg :: exts
  | _ ->
    wrongOperands ins

/// The predicates the unit tests, in the order the field holding one counts
/// them, which is Table 8-1 of the manual read down.
let private predicates =
  [ "f"
    "eq"
    "ogt"
    "oge"
    "olt"
    "ole"
    "ogl"
    "or"
    "un"
    "ueq"
    "ugt"
    "uge"
    "ult"
    "ule"
    "ne"
    "t"
    "sf"
    "seq"
    "gt"
    "ge"
    "lt"
    "le"
    "gl"
    "gle"
    "ngle"
    "ngl"
    "nle"
    "nlt"
    "nge"
    "ngt"
    "sne"
    "st" ]

/// Every instruction of the floating-point unit.
let floatEncoders () =
  [ yield "fmove", since M68KModel.M68020 floatMove
    yield "fmovecr", since M68KModel.M68020 floatMoveCr
    yield "fmovem", since M68KModel.M68020 floatMovemAny
    yield "ftst", since M68KModel.M68020 floatTest
    yield "fsincos", since M68KModel.M68020 floatSinCos
    yield "fsave", since M68KModel.M68020 (floatState true)
    yield "frestore", since M68KModel.M68020 (floatState false)
    (* The arithmetic the unit has had since the 68881, each named by the
       seven bits of its command word that say which operation it is. *)
    yield "fint", since M68KModel.M68020 (floatArith 0x01us)
    yield "fsinh", since M68KModel.M68020 (floatArith 0x02us)
    yield "fintrz", since M68KModel.M68020 (floatArith 0x03us)
    yield "fsqrt", since M68KModel.M68020 (floatArith 0x04us)
    yield "flognp1", since M68KModel.M68020 (floatArith 0x06us)
    yield "fetoxm1", since M68KModel.M68020 (floatArith 0x08us)
    yield "ftanh", since M68KModel.M68020 (floatArith 0x09us)
    yield "fatan", since M68KModel.M68020 (floatArith 0x0aus)
    yield "fasin", since M68KModel.M68020 (floatArith 0x0cus)
    yield "fatanh", since M68KModel.M68020 (floatArith 0x0dus)
    yield "fsin", since M68KModel.M68020 (floatArith 0x0eus)
    yield "ftan", since M68KModel.M68020 (floatArith 0x0fus)
    yield "fetox", since M68KModel.M68020 (floatArith 0x10us)
    yield "ftwotox", since M68KModel.M68020 (floatArith 0x11us)
    yield "ftentox", since M68KModel.M68020 (floatArith 0x12us)
    yield "flogn", since M68KModel.M68020 (floatArith 0x14us)
    yield "flog10", since M68KModel.M68020 (floatArith 0x15us)
    yield "flog2", since M68KModel.M68020 (floatArith 0x16us)
    yield "fabs", since M68KModel.M68020 (floatArith 0x18us)
    yield "fcosh", since M68KModel.M68020 (floatArith 0x19us)
    yield "fneg", since M68KModel.M68020 (floatArith 0x1aus)
    yield "facos", since M68KModel.M68020 (floatArith 0x1cus)
    yield "fcos", since M68KModel.M68020 (floatArith 0x1dus)
    yield "fgetexp", since M68KModel.M68020 (floatArith 0x1eus)
    yield "fgetman", since M68KModel.M68020 (floatArith 0x1fus)
    yield "fdiv", since M68KModel.M68020 (floatArith 0x20us)
    yield "fmod", since M68KModel.M68020 (floatArith 0x21us)
    yield "fadd", since M68KModel.M68020 (floatArith 0x22us)
    yield "fmul", since M68KModel.M68020 (floatArith 0x23us)
    yield "fsgldiv", since M68KModel.M68020 (floatArith 0x24us)
    yield "frem", since M68KModel.M68020 (floatArith 0x25us)
    yield "fscale", since M68KModel.M68020 (floatArith 0x26us)
    yield "fsglmul", since M68KModel.M68020 (floatArith 0x27us)
    yield "fsub", since M68KModel.M68020 (floatArith 0x28us)
    yield "fcmp", since M68KModel.M68020 (floatArith 0x38us)
    (* The same operations again with their results rounded to a narrower
       precision than the extended one the unit works in, which the 68040
       added. *)
    yield "fsmove", since M68KModel.M68040 (floatArith 0x40us)
    yield "fssqrt", since M68KModel.M68040 (floatArith 0x41us)
    yield "fdmove", since M68KModel.M68040 (floatArith 0x44us)
    yield "fdsqrt", since M68KModel.M68040 (floatArith 0x45us)
    yield "fsabs", since M68KModel.M68040 (floatArith 0x58us)
    yield "fsneg", since M68KModel.M68040 (floatArith 0x5aus)
    yield "fdabs", since M68KModel.M68040 (floatArith 0x5cus)
    yield "fdneg", since M68KModel.M68040 (floatArith 0x5eus)
    yield "fsdiv", since M68KModel.M68040 (floatArith 0x60us)
    yield "fsadd", since M68KModel.M68040 (floatArith 0x62us)
    yield "fsmul", since M68KModel.M68040 (floatArith 0x63us)
    yield "fddiv", since M68KModel.M68040 (floatArith 0x64us)
    yield "fdadd", since M68KModel.M68040 (floatArith 0x66us)
    yield "fdmul", since M68KModel.M68040 (floatArith 0x67us)
    yield "fssub", since M68KModel.M68040 (floatArith 0x68us)
    yield "fdsub", since M68KModel.M68040 (floatArith 0x6cus)
    for index, name in List.indexed predicates do
      let pred = uint16 index
      yield $"fb{name}", since M68KModel.M68020 (floatBranch pred)
      yield $"fs{name}", since M68KModel.M68020 (floatSet pred)
      yield $"fdb{name}", since M68KModel.M68020 (floatDbcc pred)
      yield $"ftrap{name}", since M68KModel.M68020 (floatTrapcc pred) ]

// vim: set tw=80 sts=2 sw=2:
