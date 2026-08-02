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
/// Encodes the instructions that work on the general registers: the arithmetic
/// and the logic, the shifts, the multiplication and the division, the loads
/// and the stores, the branches and the calls, the moves on a condition, and
/// what a program says to the machine it runs on.
/// </summary>
module internal B2R2.Assembly.SPARC.AsmOpcode

open B2R2.FrontEnd.SPARC
open B2R2.Assembly.SPARC.ParserHelper
open B2R2.Assembly.SPARC.AsmField

(* The two bits every SPARC word begins with, which are the coarsest thing
   saying what an instruction is: what is reached without naming a register,
   the call, what computes from registers, and what reaches memory. The first
   of the four is zero, so what carries it says nothing here. *)
let [<Literal>] private OpCall = 1u
let [<Literal>] private OpArith = 2u
let [<Literal>] private OpMemory = 3u

/// An instruction computing from a register and either a second register or a
/// written number, into a third register.
let private arith op3 ins =
  match ins.Operands with
  | [ Rg s1; operand; Rg d ] ->
    format3 OpArith op3 (gpr d) (gpr s1) (rs2OrImm operand)
  | _ -> wrongOperands ins

/// The instructions computing from two registers into a third, which the jump
/// to a computed address and the two instructions turning a register window
/// share the shape of.
let arithmeticEncoders () =
  [ "add", arith 0x00u
    "and", arith 0x01u
    "or", arith 0x02u
    "xor", arith 0x03u
    "sub", arith 0x04u
    "andn", arith 0x05u
    "opn", arith 0x06u
    "xnor", arith 0x07u
    "addc", arith 0x08u
    "mulx", arith 0x09u
    "umul", arith 0x0Au
    "smul", arith 0x0Bu
    "subc", arith 0x0Cu
    "udivx", arith 0x0Du
    "udiv", arith 0x0Eu
    "sdiv", arith 0x0Fu
    "addcc", arith 0x10u
    "andcc", arith 0x11u
    "orcc", arith 0x12u
    "xorcc", arith 0x13u
    "subcc", arith 0x14u
    "andncc", arith 0x15u
    "orncc", arith 0x16u
    "xnorcc", arith 0x17u
    "addccc", arith 0x18u
    "umulcc", arith 0x1Au
    "smulcc", arith 0x1Bu
    "subccc", arith 0x1Cu
    "udivcc", arith 0x1Eu
    "sdivcc", arith 0x1Fu
    "taddcc", arith 0x20u
    "tsubcc", arith 0x21u
    "taddcctv", arith 0x22u
    "tsubcctv", arith 0x23u
    "mulscc", arith 0x24u
    "sdivx", arith 0x2Du
    "jmpl", arith 0x38u
    "save", arith 0x3Cu
    "restore", arith 0x3Du ]

/// <summary>
/// A shift.
///
/// The three shifts each come in two widths, and which of the two a word is
/// comes from the bit just below the one saying whether what is shifted by is
/// written or held in a register. How far a shift of a doubleword goes takes
/// one bit more than how far a shift of a word goes.
/// </summary>
let private shift op3 wide ins =
  let width = if wide then 1u <<< 12 else 0u
  match ins.Operands with
  | [ Rg s1; Rg s2; Rg d ] ->
    format3 OpArith op3 (gpr d) (gpr s1) (width ||| gpr s2)
  | [ Rg s1; Im amount; Rg d ] ->
    let count = if wide then shcnt64 amount else shcnt32 amount
    format3 OpArith op3 (gpr d) (gpr s1) ((1u <<< 13) ||| width ||| count)
  | _ -> wrongOperands ins

/// The instructions counting how many bits are set in what a register holds,
/// which name no first register at all.
let private popc ins =
  match ins.Operands with
  | [ operand; Rg d ] ->
    format3 OpArith 0x2Eu (gpr d) 0u (rs2OrImm operand)
  | _ -> wrongOperands ins

/// An instruction naming a register and what is added to it and nothing else,
/// which is what the return from a window takes and what the instruction making
/// a written word visible as an instruction takes.
let private pairForm op3 ins =
  match ins.Operands with
  | [ Rg s1; operand ] ->
    format3 OpArith op3 0u (gpr s1) (rs2OrImm operand)
  | _ -> wrongOperands ins

/// The shifts and the few other instructions computing from registers whose
/// operands are not the three every other one of them takes.
let shiftEncoders () =
  [ "sll", shift 0x25u false
    "sllx", shift 0x25u true
    "srl", shift 0x26u false
    "srlx", shift 0x26u true
    "sra", shift 0x27u false
    "srax", shift 0x27u true
    "popc", popc
    "return", pairForm 0x39u
    "flush", pairForm 0x3Bu ]

/// <summary>
/// Which of the sixteen conditions a name stands for.
///
/// A condition has two names where the two kinds of comparison both leave
/// something it can be read off: one for what a comparison of integers left
/// and one for what a comparison of floating-point numbers left. Where a
/// condition can only be read off one of the two, it has only that one name,
/// and the other is left unwritten here.
/// </summary>
let conditions =
  [ "n", Some 0x0u, Some 0x0u
    "e", Some 0x1u, Some 0x9u
    "le", Some 0x2u, Some 0xDu
    "l", Some 0x3u, Some 0x4u
    "leu", Some 0x4u, None
    "cs", Some 0x5u, None
    "neg", Some 0x6u, None
    "vs", Some 0x7u, None
    "a", Some 0x8u, Some 0x8u
    "ne", Some 0x9u, Some 0x1u
    "g", Some 0xAu, Some 0x6u
    "ge", Some 0xBu, Some 0xBu
    "gu", Some 0xCu, None
    "cc", Some 0xDu, None
    "pos", Some 0xEu, None
    "vc", Some 0xFu, None
    "lg", None, Some 0x2u
    "ul", None, Some 0x3u
    "ug", None, Some 0x5u
    "u", None, Some 0x7u
    "ue", None, Some 0xAu
    "uge", None, Some 0xCu
    "ule", None, Some 0xEu
    "o", None, Some 0xFu ]

/// The condition a name stands for where it is read off what the given kind of
/// comparison left.
let conditionOf name cc =
  let integer, float =
    conditions
    |> List.tryPick (fun (n, i, f) -> if n = name then Some(i, f) else None)
    |> Option.defaultValue (None, None)
  match (if isIntegerCC cc then integer else float) with
  | Some cond -> cond
  | None -> fail $"nothing named {name} is read off {cc}"

/// <summary>
/// Which of the six conditions on what a register holds a name stands for.
///
/// Two of them are written by one name where what is moved is what a general
/// register holds and by another where it is what a floating-point one holds:
/// the test for zero is written as a test against zero in the first and as a
/// test for equality in the second, and so is the test for anything else.
/// </summary>
let registerConditions =
  [ "z", "e", 0x1u
    "lez", "lez", 0x2u
    "lz", "lz", 0x3u
    "nz", "ne", 0x5u
    "gz", "gz", 0x6u
    "gez", "gez", 0x7u ]

/// <summary>
/// A move that happens only where the named condition holds.
///
/// Which condition it tests is written into the name, and which set of bits
/// that condition is read off is the first operand; the two together settle the
/// four bits naming the condition, because the two kinds of comparison number
/// their conditions differently.
/// </summary>
let private moveOnCondition name ins =
  match ins.Operands with
  | [ Cc cc; operand; Rg d ] ->
    let bits = ccThree cc
    let cond = conditionOf name cc
    let selector =
      ((bits >>> 2) <<< 18) ||| (cond <<< 14) ||| ((bits &&& 3u) <<< 11)
    format3 OpArith 0x2Cu (gpr d) 0u (selector ||| rs2OrSimm11 operand)
  | _ -> wrongOperands ins

/// A move that happens only where what a register holds compares as the name
/// says against zero.
let private moveOnRegister rcond ins =
  match ins.Operands with
  | [ Rg s1; operand; Rg d ] ->
    let low = (rcond <<< 10) ||| rs2OrSimm10 operand
    format3 OpArith 0x2Fu (gpr d) (gpr s1) low
  | _ -> wrongOperands ins

/// The moves that happen only where something holds.
let moveEncoders () =
  [ for name, _, _ in conditions -> "mov" + name, moveOnCondition name
    for name, _, rcond in registerConditions ->
      "movr" + name, moveOnRegister rcond ]

/// A trap, which names the set of condition bits it reads and where to trap
/// to. What it names the place by is a register added to a first register the
/// disassembler does not write, so nothing is written into that first one.
let private trap name ins =
  match ins.Operands with
  | [ Cc cc; operand ] ->
    let low =
      match operand with
      | AsmReg reg -> gpr reg
      | AsmImm number -> (1u <<< 13) ||| trapNumber number
      | _ -> fail "a trap goes to a register or to a written number"
    let selector = integerCC cc <<< 11
    format3 OpArith 0x3Au (conditionOf name cc) 0u (selector ||| low)
  | _ -> wrongOperands ins

/// The traps, one for each condition a comparison of integers leaves something
/// to read.
let trapEncoders () =
  conditions
  |> List.choose (fun (name, integer, _) ->
    integer |> Option.map (fun _ -> "t" + name, trap name))

/// Whether the branch throws away the instruction after it when it does not
/// go, which is the uppermost bit of the field every other instruction names
/// the register it writes to with.
let private annulOf ins = if ins.Annul then 0x10u else 0u

/// <summary>
/// A branch that reads no set of condition bits by name.
///
/// The two kinds of comparison each have a branch of this shape, and which one
/// a word is comes from the three bits below the condition. Such a branch says
/// nothing about whether it expects to go.
/// </summary>
let private branch op2 cond ins =
  match ins.Operands, ins.Predict with
  | [ Im target ], None ->
    format2 (annulOf ins ||| cond) op2 (disp22 target)
  | _, Some _ -> fail $"{ins.Mnemonic} says nothing about where it goes"
  | _, None -> wrongOperands ins

/// A branch that names the set of condition bits it reads, which reaches less
/// far than the one that does not because the name takes bits of the distance.
let private branchOnCondition op2 name ins =
  match ins.Operands, ins.Predict with
  | [ Cc cc; Im target ], Some predict ->
    let bits = if op2 = 1u then integerCC cc else floatCC cc
    let expects = if predict then 1u <<< 19 else 0u
    let head = annulOf ins ||| conditionOf name cc
    format2 head op2 ((bits <<< 20) ||| expects ||| disp19 target)
  | _, None -> fail $"{ins.Mnemonic} has to say whether it expects to go"
  | _, Some _ -> wrongOperands ins

/// A branch on how what a register holds compares against zero, which always
/// says whether it expects to go and keeps the distance in two pieces so that
/// the register it reads lies where every other instruction keeps one.
let private branchOnRegister rcond ins =
  match ins.Operands, ins.Predict with
  | [ Rg s1; Im target ], Some predict ->
    let distance = disp16 target
    let expects = if predict then 1u <<< 19 else 0u
    let low =
      ((distance >>> 14) <<< 20) ||| expects ||| (gpr s1 <<< 14)
      ||| (distance &&& 0x3FFFu)
    format2 (annulOf ins ||| rcond) 3u low
  | _, None -> fail $"{ins.Mnemonic} has to say whether it expects to go"
  | _, Some _ -> wrongOperands ins

/// The call, which reaches anywhere a word away and is the only instruction
/// whose whole body below the two bits naming it is one distance.
let private call ins =
  match ins.Operands with
  | [ Im target ] -> (OpCall <<< 30) ||| disp30 target
  | _ -> wrongOperands ins

/// <summary>
/// The instructions that go somewhere other than the next word.
///
/// A branch reading a set of condition bits is written under the same name as
/// the one that does not, and what tells them apart is that the first says
/// whether it expects to go and the second cannot.
/// </summary>
let branchEncoders () =
  [ for name, integer, float in conditions do
      match integer with
      | Some cond ->
        yield "b" + name, orTry (branch 2u cond) (branchOnCondition 1u name)
      | None -> ()
      match float with
      | Some cond ->
        yield "fb" + name, orTry (branch 6u cond) (branchOnCondition 5u name)
      | None -> ()
    for name, _, rcond in registerConditions ->
      "br" + name, branchOnRegister rcond
    yield "call", call ]

/// A load, which names where it reads as a register and what is added to it.
let private load op3 destination ins =
  match ins.Operands with
  | [ Mem mem; dest ] ->
    let rs1, low = address (AsmMem mem)
    format3 OpMemory op3 (destination dest) rs1 low
  | _ -> wrongOperands ins

/// A store, which names where it writes the same way and keeps the register it
/// writes from where a load keeps the one it writes to.
let private store op3 source ins =
  match ins.Operands with
  | [ src; Mem mem ] ->
    let rs1, low = address (AsmMem mem)
    format3 OpMemory op3 (source src) rs1 low
  | _ -> wrongOperands ins

/// A load that names which address space it reaches.
let private loadAlt op3 destination ins =
  match ins.Operands with
  | [ Mem mem; asi; dest ] ->
    let rs1, low = alternateAddress (AsmMem mem) asi
    format3 OpMemory op3 (destination dest) rs1 low
  | _ -> wrongOperands ins

/// A store that names which address space it reaches.
let private storeAlt op3 source ins =
  match ins.Operands with
  | [ src; Mem mem; asi ] ->
    let rs1, low = alternateAddress (AsmMem mem) asi
    format3 OpMemory op3 (source src) rs1 low
  | _ -> wrongOperands ins

/// The register a load writes to or a store writes from, where that register is
/// one of the general ones.
let private generalOperand = function
  | AsmReg reg -> gpr reg
  | _ -> fail "this is not a general register"

/// The register naming what a floating-point comparison left, which is the one
/// operand the two instructions saving and restoring it name.
let private stateRegister = function
  | AsmReg Register.FSR -> 0u
  | _ -> fail "this is not the floating-point state register"

/// The same, for the wider of the two instructions saving and restoring it,
/// which is told from the narrower by the field naming a register.
let private wideStateRegister = function
  | AsmReg Register.FSR -> 1u
  | _ -> fail "this is not the floating-point state register"

/// The register a floating-point load writes to or a store writes from, at
/// each of the three widths a floating-point number is kept at.
let private singleOperand = function
  | AsmReg reg -> single reg
  | _ -> fail "this is not a floating-point register"

let private doubleOperand = function
  | AsmReg reg -> double reg
  | _ -> fail "this is not a floating-point register"

let private quadOperand = function
  | AsmReg reg -> quad reg
  | _ -> fail "this is not a floating-point register"

/// <summary>
/// The instruction that reads memory, writes what a register holds into it, and
/// gives back what it read, all without anything else reaching that memory in
/// between.
///
/// It names the memory it reaches by a register alone, because it reaches
/// exactly what that register holds.
/// </summary>
let private compareAndSwap op3 ins =
  match ins.Operands with
  | [ Mem mem; asi; Rg s2; Rg d ] ->
    let rs1, low = alternateAddress (AsmMem mem) asi
    format3 OpMemory op3 (gpr d) rs1 (low ||| gpr s2)
  | _ -> wrongOperands ins

/// <summary>
/// The instructions that reach memory.
///
/// The disassembler writes a load under a name saying how wide what it reads
/// is rather than where it lands, so one name covers both the load landing in a
/// general register and the one landing in a floating-point register; which of
/// the two a line names is settled by the register it writes to.
/// </summary>
let memoryEncoders () =
  [ "lduw", load 0x00u generalOperand
    "ldub", load 0x01u generalOperand
    "lduh", load 0x02u generalOperand
    "ldd", orTry (load 0x03u generalOperand) (load 0x23u doubleOperand)
    "stw", store 0x04u generalOperand
    "stb", store 0x05u generalOperand
    "sth", store 0x06u generalOperand
    "std", orTry (store 0x07u generalOperand) (store 0x27u doubleOperand)
    "ldsw", load 0x08u generalOperand
    "ldsb", load 0x09u generalOperand
    "ldsh", load 0x0Au generalOperand
    "ldx", orTry (load 0x0Bu generalOperand) (load 0x21u wideStateRegister)
    "ldstub", load 0x0Du generalOperand
    "stx", orTry (store 0x0Eu generalOperand) (store 0x25u wideStateRegister)
    "swap", load 0x0Fu generalOperand
    "lduwa", loadAlt 0x10u generalOperand
    "lduba", loadAlt 0x11u generalOperand
    "lduha", loadAlt 0x12u generalOperand
    "ldda", orTry (loadAlt 0x13u generalOperand) (loadAlt 0x33u doubleOperand)
    "stwa", storeAlt 0x14u generalOperand
    "stba", storeAlt 0x15u generalOperand
    "stha", storeAlt 0x16u generalOperand
    "stda", orTry (storeAlt 0x17u generalOperand) (storeAlt 0x37u doubleOperand)
    "ldswa", loadAlt 0x18u generalOperand
    "ldsba", loadAlt 0x19u generalOperand
    "ldsha", loadAlt 0x1Au generalOperand
    "ldxa", loadAlt 0x1Bu generalOperand
    "ldstuba", loadAlt 0x1Du generalOperand
    "stxa", storeAlt 0x1Eu generalOperand
    "swapa", loadAlt 0x1Fu generalOperand
    "ld", orTry (load 0x20u singleOperand) (load 0x21u stateRegister)
    "ldq", load 0x22u quadOperand
    "st", orTry (store 0x24u singleOperand) (store 0x25u stateRegister)
    "stqf", store 0x26u quadOperand
    "prefetch", load 0x2Du generalOperand
    "lda", loadAlt 0x30u singleOperand
    "ldqa", loadAlt 0x32u quadOperand
    "sta", storeAlt 0x34u singleOperand
    "stqa", storeAlt 0x36u quadOperand
    "casa", compareAndSwap 0x3Cu
    "prefetcha", loadAlt 0x3Du generalOperand
    "casxa", compareAndSwap 0x3Eu ]

/// <summary>
/// Which of the registers the machine keeps for itself an instruction reads or
/// writes, where the instruction is the one reaching them by name.
///
/// The disassembler writes each of them under the name it goes by, and the
/// field naming one holds the number below rather than the name.
/// </summary>
let private privileged = function
  | Register.TPC -> 0u
  | Register.TNPC -> 1u
  | Register.TSTATE -> 2u
  | Register.TT -> 3u
  | Register.TICK -> 4u
  | Register.TBA -> 5u
  | Register.PSTATE -> 6u
  | Register.TL -> 7u
  | Register.PIL -> 8u
  | Register.CWP -> 9u
  | Register.CANSAVE -> 10u
  | Register.CANRESTORE -> 11u
  | Register.CLEANWIN -> 12u
  | Register.OTHERWIN -> 13u
  | Register.WSTATE -> 14u
  | Register.FQ -> 15u
  | Register.VER -> 31u
  | reg -> fail $"{Register.toString reg} is not a privileged register"

/// <summary>
/// Which of the registers the machine keeps for itself a name stands for, where
/// the instruction reaching it is the one reading and writing them by name.
///
/// Every other number that field holds names a register belonging to whatever
/// the machine was built with, and the disassembler writes one of those as the
/// general register carrying the same number.
/// </summary>
let private stateOf = function
  | Register.Y -> Some 0u
  | Register.CCR -> Some 2u
  | Register.ASI -> Some 3u
  | Register.TICK -> Some 4u
  | Register.PC -> Some 5u
  | Register.FPRS -> Some 6u
  | _ -> None

/// The instruction reading one of the registers the machine keeps for itself.
let private readState ins =
  match ins.Operands with
  | [ Rg source; Rg d ] ->
    let number = stateOf source |> Option.defaultWith (fun () -> gpr source)
    format3 OpArith 0x28u (gpr d) number 0u
  | _ -> wrongOperands ins

/// The instruction reading one of the registers only what the machine trusts
/// may read.
let private readPrivileged ins =
  match ins.Operands with
  | [ Rg source; Rg d ] ->
    format3 OpArith 0x2Au (gpr d) (privileged source) 0u
  | _ -> wrongOperands ins

/// <summary>
/// Which register the instruction writing one of the registers the machine
/// keeps for itself writes to.
///
/// The numbers below sixteen that name no register by name name an instruction
/// the disassembler writes without a destination at all, so a source naming one
/// of those and a destination both says something no encoding holds.
/// </summary>
let private writtenState reg =
  match stateOf reg with
  | Some number ->
    number
  | None ->
    let number = gpr reg
    if number >= 16u then number
    else fail $"{Register.toString reg} is written under no name"

/// <summary>
/// The instruction writing one of the registers the machine keeps for itself.
///
/// What it writes is what a register holds combined with a second register or a
/// written number, and which register it writes lands where every other
/// instruction keeps the register it writes to; so where the disassembler
/// writes no destination at all, one is chosen here that it will not write.
/// </summary>
let private writeState ins =
  match ins.Operands with
  | [ Rg s1; operand; Rg dest ] ->
    format3 OpArith 0x30u (writtenState dest) (gpr s1) (rs2OrImm operand)
  | [ Rg s1; operand ] ->
    format3 OpArith 0x30u 4u (gpr s1) (rs2OrImm operand)
  | _ -> wrongOperands ins

/// The instruction writing one of the registers only what the machine trusts
/// may write.
let private writePrivileged ins =
  match ins.Operands with
  | [ Rg s1; operand; Rg dest ] ->
    format3 OpArith 0x32u (privileged dest) (gpr s1) (rs2OrImm operand)
  | _ -> wrongOperands ins

/// An instruction whose name is the whole of it.
let private wordForm word ins =
  match ins.Operands with
  | [] -> word
  | _ -> wrongOperands ins

/// The memory barrier, which says what may not cross it. What the encoding
/// keeps as two masks the disassembler writes as the one number they stand
/// for, so what is read back here goes into the lower of the two.
let private membar ins =
  match ins.Operands with
  | [ Im mask ] ->
    format3 OpArith 0x28u 0u 0u ((1u <<< 13) ||| membarMask mask)
  | _ -> wrongOperands ins

/// The instruction resetting the machine, which carries a number where it
/// carries anything at all.
let private softwareReset ins =
  match ins.Operands with
  | [] -> format3 OpArith 0x30u 15u 0u 0u
  | [ Im number ] ->
    format3 OpArith 0x30u 15u 0u ((1u <<< 13) ||| simm13 number)
  | _ -> wrongOperands ins

/// The instruction building the upper part of an address, which is all one
/// word can hold of one. Writing that part into the register that discards
/// everything is how the instruction doing nothing is written.
let private sethi ins =
  match ins.Operands with
  | [ Hi value; Rg d ] ->
    let number = gpr d
    if number = 0u then fail "an address built into nothing does nothing"
    else format2 number 4u (hi22 value)
  | _ -> wrongOperands ins

/// The instruction the machine traps on, which carries a number saying why.
let private illtrap ins =
  match ins.Operands with
  | [ Im value ] -> format2 0u 0u (const22 value)
  | _ -> wrongOperands ins

/// One of the two instructions the machine it runs on is left to say what to do
/// with, which carry nothing but a number that machine reads.
let private implementationDependent op3 ins =
  match ins.Operands with
  | [ Im value ] -> format3 OpArith op3 0u 0u 0u ||| implDep value
  | _ -> wrongOperands ins

/// <summary>
/// What a program says to the machine it runs on.
///
/// The instruction doing nothing is the one building an address into the
/// register that discards everything, and the disassembler writes it under a
/// name of its own; so is the barrier that keeps nothing on either side of
/// itself.
/// </summary>
let systemEncoders () =
  [ "nop", wordForm (format2 0u 4u 0u)
    "sethi", sethi
    "illtrap", illtrap
    "rd", readState
    "rdpr", readPrivileged
    "wr", writeState
    "wrpr", writePrivileged
    "membar", membar
    "stbar", wordForm (format3 OpArith 0x28u 0u 15u 0u)
    "flushw", wordForm (format3 OpArith 0x2Bu 0u 0u 0u)
    "saved", wordForm (format3 OpArith 0x31u 0u 0u 0u)
    "restored", wordForm (format3 OpArith 0x31u 1u 0u 0u)
    "done", wordForm (format3 OpArith 0x3Eu 0u 0u 0u)
    "retry", wordForm (format3 OpArith 0x3Eu 1u 0u 0u)
    "sir", softwareReset
    "impdep1", implementationDependent 0x36u
    "impdep2", implementationDependent 0x37u ]

// vim: set tw=80 sts=2 sw=2:
