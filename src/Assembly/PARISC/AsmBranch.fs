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
/// Encodes everything that goes somewhere other than the next instruction, and
/// the few instructions building an address to go to or to read from.
/// </summary>
module internal B2R2.Assembly.PARISC.AsmBranch

open B2R2.FrontEnd.PARISC
open B2R2.Assembly.PARISC.ParserHelper
open B2R2.Assembly.PARISC.AsmField

(* The six bits the branches that always go begin with, already in the place
   they sit. *)
let [<Literal>] private OpBranch = 0xE8000000u

(* The whole of the two branches that carry nothing at all, which lie where a
   branch to an address held in a register would. *)
let [<Literal>] private ClearStack = 16389u
let [<Literal>] private PushNominated = 16385u

/// <summary>
/// The bit saying that the instruction after a branch is thrown away where the
/// branch goes, and whatever was written after the name besides.
///
/// PA-RISC puts the instruction after a branch through the processor while the
/// branch is still being worked out, so a branch says whether what it started
/// is to be finished or dropped.
/// </summary>
let private nullify ins =
  let flags, rest = split [ "n" ] ins.Suffixes
  bit "n" flags, rest

/// One word of the kind going somewhere else where two things compare a
/// certain way.
let private branchOn opcode c rs2 rs1 rest =
  (opcode <<< 26) ||| (rs2 <<< 21) ||| (rs1 <<< 16) ||| (c <<< 13) ||| rest

/// <summary>
/// The six bits naming which of the branches on a comparison an instruction
/// is, given the two bits of its condition that are not written where the rest
/// of the condition is.
///
/// A branch keeps the three bits saying which condition it goes on where every
/// other instruction does, but the bit saying whether it goes on the condition
/// holding, and the bit saying how much of what was compared it is read off,
/// are spent on the name of the instruction instead.
/// </summary>
let private opcodeFor table cf =
  match List.tryFind (fst >> (=) (cf &&& 3u)) table with
  | Some(_, opcode) -> opcode
  | None -> fail "no branch compares that way"

/// The branch comparing what two registers hold.
let private compareBranch table readCondition ins =
  let n, rest = nullify ins
  let cf = readCondition (condition rest)
  let opcode = opcodeFor table cf
  match ins.Operands with
  | [ Rg s1; Rg s2; Im target ] ->
    branchOn opcode (cf >>> 2) (gpr s2) (gpr s1)
      (assemble12 (target - 8UL) ||| (n <<< 1))
  | _ -> wrongOperands ins

/// The same, where what a register holds is compared against a written number.
let private compareImmBranch table readCondition ins =
  let n, rest = nullify ins
  let cf = readCondition (condition rest)
  let opcode = opcodeFor table cf
  match ins.Operands with
  | [ Im value; Rg s2; Im target ] ->
    branchOn opcode (cf >>> 2) (gpr s2) (lowSignExt 5 value)
      (assemble12 (target - 8UL) ||| (n <<< 1))
  | _ -> wrongOperands ins

/// <summary>
/// The branch comparing a whole doubleword against a written number, which is
/// written under the same name as the branch comparing a word.
///
/// It counts its conditions in an order of its own and has room for eight of
/// them rather than sixteen, because the two bits every other branch spends on
/// the rest of its condition are spent here on saying that a doubleword is
/// what is compared.
/// </summary>
let private cmpibWide ins =
  let n, rest = nullify ins
  let c = cmpibCondition (condition rest)
  match ins.Operands with
  | [ Im value; Rg s2; Im target ] ->
    branchOn 0b111011u c (gpr s2) (lowSignExt 5 value)
      (assemble12 (target - 8UL) ||| (n <<< 1))
  | _ -> wrongOperands ins

/// The branch copying one register into another, which goes on how much the
/// first of them holds.
let private moveBranch opcode ins =
  let n, rest = nullify ins
  let c = shiftCondition 0u (condition rest)
  match ins.Operands with
  | [ Rg s1; Rg s2; Im target ] ->
    branchOn opcode c (gpr s2) (gpr s1)
      (assemble12 (target - 8UL) ||| (n <<< 1))
  | _ -> wrongOperands ins

/// The same, where what is copied is a written number.
let private moveImmBranch opcode ins =
  let n, rest = nullify ins
  let c = shiftCondition 0u (condition rest)
  match ins.Operands with
  | [ Im value; Rg s2; Im target ] ->
    branchOn opcode c (gpr s2) (lowSignExt 5 value)
      (assemble12 (target - 8UL) ||| (n <<< 1))
  | _ -> wrongOperands ins

/// <summary>
/// The branch going on one bit of a register.
///
/// Which bit is either held in the register saying how far a shift goes or
/// written out, and the two bits of the condition lie apart from one another
/// with the bit naming nothing between them.
/// </summary>
let private bitBranch ins =
  let n, rest = nullify ins
  let cd = branchOnBitCondition (condition rest)
  let c = ((cd >>> 1) <<< 2) ||| (cd &&& 1u)
  match ins.Operands with
  | [ Rg s1; Rg sar; Im target ] when sar = Register.CR11 ->
    branchOn 0b110000u c 0u (gpr s1)
      (assemble12 (target - 8UL) ||| (n <<< 1))
  | [ Rg s1; Im pos; Im target ] ->
    branchOn 0b110001u c (unsigned 5 pos) (gpr s1)
      (assemble12 (target - 8UL) ||| (n <<< 1))
  | _ -> wrongOperands ins

/// One word of the kind that always goes somewhere else, given the three bits
/// saying which of them it is.
let private goes key rest = OpBranch ||| (key <<< 13) ||| rest

/// The branch that always goes, which says where it came from in a register
/// and reaches seventeen bits' distance away.
let private nearBranch key ins =
  let n, rest = nullify ins
  nothingLeft ins rest
  match ins.Operands with
  | [ Im target; Rg r ] ->
    goes key ((gpr r <<< 21) ||| assemble17 (target - 8UL) ||| (n <<< 1))
  | _ -> wrongOperands ins

/// <summary>
/// The same, reaching twenty-two bits' distance away.
///
/// The five bits naming the register such a branch says where it came from in
/// are spent on five bits more of the distance, so the two must agree: the
/// register is whatever those bits of the distance happen to be.
/// </summary>
let private farBranch key ins =
  let n, rest = nullify ins
  nothingLeft ins rest
  match ins.Operands with
  | [ Im target; Rg r ] ->
    let bits = assemble22 (target - 8UL)
    if ((bits >>> 21) &&& 0x1Fu) <> gpr r then
      fail "this branch does not say where it came from"
    else
      goes key (bits ||| (n <<< 1))
  | _ -> wrongOperands ins

/// The branch that always goes, whose three forms differ in how far they
/// reach and in what they leave behind.
let private branch ins =
  let flags, rest = split [ "l"; "gate"; "push" ] ins.Suffixes
  let ins = { ins with Suffixes = rest }
  match List.sort flags with
  | [ "l" ] -> orTry (nearBranch 0b000u) (farBranch 0b101u) ins
  | [ "gate" ] -> nearBranch 0b001u ins
  | [ "l"; "push" ] -> farBranch 0b100u ins
  | _ -> wrongSuffixes ins

/// The branch going to an address held in a register and saying where it came
/// from in a second one.
let private blr ins =
  let n, rest = nullify ins
  nothingLeft ins rest
  match ins.Operands with
  | [ Rg s1; Rg s2 ] ->
    goes 0b010u ((gpr s2 <<< 21) ||| (gpr s1 <<< 16) ||| (n <<< 1))
  | _ -> wrongOperands ins

/// The branch going to an address counted from a register, which is how a
/// program returns from where it was called.
let private bv ins =
  let n, rest = nullify ins
  nothingLeft ins rest
  match ins.Operands with
  | [ Mem(Some(Rg index), None, baseReg) ] ->
    goes 0b110u ((gpr baseReg <<< 21) ||| (gpr index <<< 16) ||| (n <<< 1))
  | _ -> wrongOperands ins

/// <summary>
/// The same, where the address is the whole of what a register holds.
///
/// Such a branch may say in a second register where it came from, and it may
/// take an address off the stack the processor guesses from or put one on it.
/// Which of those two it does follows from whether it says where it came from,
/// so one bit says only that it does either.
/// </summary>
let private bve ins =
  let flags, rest = split [ "l"; "pop"; "push" ] ins.Suffixes
  let n, rest = nullify { ins with Suffixes = rest }
  nothingLeft ins rest
  let onStack =
    match List.sort flags with
    | [] | [ "l" ] -> 0u
    | [ "pop" ] | [ "l"; "push" ] -> 1u
    | _ -> fail "no branch to another space is written this way"
  match has "l" flags, ins.Operands with
  | false, [ Mem(None, None, baseReg) ] ->
    goes 0b110u (0x1000u ||| (gpr baseReg <<< 21) ||| (n <<< 1) ||| onStack)
  | true, [ Mem(None, None, baseReg); Rg r ] when r = Register.GR2 ->
    goes 0b111u (0x1000u ||| (gpr baseReg <<< 21) ||| (n <<< 1) ||| onStack)
  | _ -> wrongOperands ins

/// <summary>
/// The instruction pushing an address onto the stack of addresses the
/// processor keeps for guessing where a program will go next.
///
/// The lowest bit of the word is what tells this family from the branch to an
/// address held in a register, which is written the same way otherwise.
/// </summary>
let private pushbts ins =
  nothingLeft ins ins.Suffixes
  match ins.Operands with
  | [ Rg s ] -> goes 0b010u ((gpr s <<< 16) ||| 1u)
  | _ -> wrongOperands ins

/// <summary>
/// The instruction taking one or more addresses off that stack.
///
/// Taking none off is what clearing the whole of it is written as, so a count
/// of nothing names that instruction instead and is not written here.
/// </summary>
let private popbts ins =
  nothingLeft ins ins.Suffixes
  match ins.Operands with
  | [ Im count ] when count <> 0UL ->
    OpBranch ||| ClearStack ||| (unsigned 9 count <<< 3)
  | _ -> wrongOperands ins

/// One of the two instructions working on that stack that carry nothing at
/// all.
let private wholeWord word ins =
  nothingLeft ins ins.Suffixes
  match ins.Operands with
  | [] -> OpBranch ||| word
  | _ -> wrongOperands ins

/// <summary>
/// The branch going to an address in another space, which may say where it
/// came from.
///
/// Where it does, it says so in the two registers the processor always uses
/// for that, and the disassembler writes them out although the encoding holds
/// nothing of them.
/// </summary>
let private be ins =
  let flags, rest = split [ "l" ] ins.Suffixes
  let n, rest = nullify { ins with Suffixes = rest }
  nothingLeft ins rest
  match has "l" flags, ins.Operands with
  | false, [ Mem(Some(Im offset), sp, baseReg) ] ->
    (0b111000u <<< 26) ||| (gpr baseReg <<< 21) ||| assemble17 offset
    ||| space3 sp ||| (n <<< 1)
  | true, [ Mem(Some(Im offset), sp, baseReg); Rg space; Rg back ]
      when space = Register.SR0 && back = Register.GR31 ->
    (0b111001u <<< 26) ||| (gpr baseReg <<< 21) ||| assemble17 offset
    ||| space3 sp ||| (n <<< 1)
  | _ -> wrongOperands ins

/// The four branches comparing what two registers hold, paired with the two
/// bits of the condition that tell them apart.
let private compareForms =
  [ 0u, 0b100000u
    2u, 0b100010u
    1u, 0b100111u
    3u, 0b101111u ]

/// The two comparing a register against a written number, of which the two
/// reading a whole doubleword are written under a name of their own.
let private compareImmForms = [ 0u, 0b100001u; 2u, 0b100011u ]

/// The two adding what two registers hold, which never read more than a word.
let private addForms = [ 0u, 0b101000u; 2u, 0b101010u ]

/// The two adding a written number to a register.
let private addImmForms = [ 0u, 0b101001u; 2u, 0b101011u ]

/// The instructions that always go somewhere else.
let branchEncoders () =
  [ "cmpb", compareBranch compareForms compSubCondition
    "addb", compareBranch addForms addCondition
    "movb", moveBranch 0b110010u
    "cmpib",
      orTry (compareImmBranch compareImmForms compSubCondition) cmpibWide
    "addib", compareImmBranch addImmForms addCondition
    "movib", moveImmBranch 0b110011u
    "bb", bitBranch
    "b", branch
    "blr", blr
    "bv", bv
    "bve", bve
    "pushbts", pushbts
    "pushnom", wholeWord PushNominated
    "popbts", popbts
    "clrbts", wholeWord ClearStack
    "be", be ]

/// The instruction building the upper part of a word in a register, either on
/// its own or added to what the register already held.
let private longImm opcode ins =
  nothingLeft ins ins.Suffixes
  match ins.Operands with
  | [ Im value; Rg r ] ->
    (opcode <<< 26) ||| (gpr r <<< 21) ||| assemble21 value
  | _ -> wrongOperands ins

/// The instruction adding a written number to a register without ever saying
/// anything about what came of it, which is how an address is built.
let private ldo ins =
  nothingLeft ins ins.Suffixes
  match ins.Operands with
  | [ Mem(Some(Im offset), None, baseReg); Rg d ] ->
    (0b001101u <<< 26) ||| (gpr baseReg <<< 21) ||| (gpr d <<< 16)
    ||| assemble16 offset
  | _ -> wrongOperands ins

/// The instruction comparing a register against a written number and clearing
/// a second register where the comparison holds.
let private cmpiclr ins =
  let cf = compSubCondition (condition ins.Suffixes)
  match ins.Operands with
  | [ Im value; Rg s2; Rg d ] ->
    (0b100100u <<< 26) ||| (gpr s2 <<< 21) ||| (gpr d <<< 16) ||| (cf <<< 11)
    ||| lowSignExt 11 value
  | _ -> wrongOperands ins

/// The instruction left to the machine a program runs on to give a meaning to,
/// which carries nothing but a number the whole width of the word below its
/// name.
let private diag ins =
  nothingLeft ins ins.Suffixes
  match ins.Operands with
  | [ Im value ] -> (0b000101u <<< 26) ||| unsigned 26 value
  | _ -> wrongOperands ins

/// The instructions carrying a number too wide to compute from.
let longImmediateEncoders () =
  [ "ldil", longImm 0b001000u
    "addil", longImm 0b001010u
    "ldo", ldo
    "cmpiclr", cmpiclr
    "diag", diag ]

// vim: set tw=80 sts=2 sw=2:
