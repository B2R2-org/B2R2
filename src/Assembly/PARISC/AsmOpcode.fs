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
/// Encodes what a program says to the machine it runs on, what it says about
/// how memory is looked up, the arithmetic and the logic, the shifts, the
/// extractions and the deposits, and the instructions working on several parts
/// of a doubleword at once.
/// </summary>
module internal B2R2.Assembly.PARISC.AsmOpcode

open B2R2.FrontEnd.PARISC
open B2R2.Assembly.PARISC.ParserHelper
open B2R2.Assembly.PARISC.AsmField

(* The six bits every PA-RISC word begins with are the coarsest thing saying
   what an instruction is. Those the instructions here begin with are named
   below, already in the place they sit. *)
let [<Literal>] private OpSystem = 0x00000000u
let [<Literal>] private OpMemMgmt = 0x04000000u
let [<Literal>] private OpCompute = 0x08000000u
let [<Literal>] private OpVarShift = 0xD0000000u
let [<Literal>] private OpVarDeposit = 0xD4000000u
let [<Literal>] private OpExtract = 0xD8000000u
let [<Literal>] private OpDeposit = 0xF0000000u
let [<Literal>] private OpDepositImm = 0xF4000000u
let [<Literal>] private OpMultimedia = 0xF8000000u

/// One word of the kind a program says something to the machine it runs on
/// with, given the eight bits saying which of them it is.
let private system (op8: uint32) rest = OpSystem ||| (op8 <<< 5) ||| rest

/// An instruction saying something to the machine and naming nothing at all.
let private bare op8 ins =
  nothingLeft ins ins.Suffixes
  match ins.Operands with
  | [] -> system op8 0u
  | _ -> wrongOperands ins

/// The instruction stopping a program so that something else may look at it,
/// which carries two numbers saying why it stopped.
let private breakIns ins =
  nothingLeft ins ins.Suffixes
  match ins.Operands with
  | [ Im low; Im high ] ->
    system 0x00u ((unsigned 13 high <<< 13) ||| unsigned 5 low)
  | _ -> wrongOperands ins

/// The instruction waiting until everything a device outside the processor was
/// asked to do is done.
let private syncdma ins =
  nothingLeft ins ins.Suffixes
  match ins.Operands with
  | [] -> system 0x20u (0x10u <<< 16)
  | _ -> wrongOperands ins

/// The instruction giving back a program the processor had taken away from,
/// which is written with a word after its name where it gives back two.
let private rfi ins =
  match ins.Suffixes, ins.Operands with
  | [], [] -> system 0x60u 0u
  | [ "r" ], [] -> system 0x65u 0u
  | _, [] -> wrongSuffixes ins
  | _ -> wrongOperands ins

/// An instruction turning on or off the things a program may do, given as a
/// written mask, and saying in a register what they had been.
let private maskIns op8 ins =
  nothingLeft ins ins.Suffixes
  match ins.Operands with
  | [ Im mask; Rg d ] -> system op8 ((unsigned 10 mask <<< 16) ||| gpr d)
  | _ -> wrongOperands ins

/// An instruction naming one general register to read and nothing else.
let private oneSource op8 ins =
  nothingLeft ins ins.Suffixes
  match ins.Operands with
  | [ Rg s ] -> system op8 (gpr s <<< 16)
  | _ -> wrongOperands ins

/// An instruction landing in one general register and naming nothing else.
let private oneTarget op8 ins =
  nothingLeft ins ins.Suffixes
  match ins.Operands with
  | [ Rg d ] -> system op8 (gpr d)
  | _ -> wrongOperands ins

/// The instruction working out which space the pointer a register holds
/// reaches into.
let private ldsid ins =
  nothingLeft ins ins.Suffixes
  match ins.Operands with
  | [ Mem(None, space, baseReg); Rg d ] ->
    system 0x85u ((gpr baseReg <<< 21) ||| space2 space ||| gpr d)
  | _ -> wrongOperands ins

/// Moving what a general register holds into one of the eight space registers.
let private mtsp ins =
  nothingLeft ins ins.Suffixes
  match ins.Operands with
  | [ Rg s; Rg sp ] -> system 0xC1u ((gpr s <<< 16) ||| space3 (Some sp))
  | _ -> wrongOperands ins

/// Moving what one of the eight space registers holds into a general one.
let private mfsp ins =
  nothingLeft ins ins.Suffixes
  match ins.Operands with
  | [ Rg sp; Rg d ] -> system 0x25u (space3 (Some sp) ||| gpr d)
  | _ -> wrongOperands ins

/// Moving what a general register holds into one of the registers the
/// processor keeps for itself.
let private mtctl ins =
  nothingLeft ins ins.Suffixes
  match ins.Operands with
  | [ Rg s; Rg cr ] -> system 0xC2u ((ctrl cr <<< 21) ||| (gpr s <<< 16))
  | _ -> wrongOperands ins

/// <summary>
/// Moving what one of the registers the processor keeps for itself holds into
/// a general one.
///
/// A word after the name says that only the lower half of the register is
/// read, which only the register saying how far a shift goes is read half of.
/// </summary>
let private mfctl ins =
  let flags, rest = split [ "w" ] ins.Suffixes
  nothingLeft ins rest
  match ins.Operands with
  | [ Rg cr; Rg d ] when not (has "w" flags) || cr = Register.CR11 ->
    system 0x45u ((ctrl cr <<< 21) ||| (bit "w" flags <<< 14) ||| gpr d)
  | _ -> wrongOperands ins

/// The instructions a program says something to the machine it runs on with.
let systemEncoders () =
  [ "break", breakIns
    "sync", bare 0x20u
    "syncdma", syncdma
    "rfi", rfi
    "ssm", maskIns 0x6Bu
    "rsm", maskIns 0x73u
    "mtsm", oneSource 0xC3u
    "ldsid", ldsid
    "mtsp", mtsp
    "mfsp", mfsp
    "mtctl", mtctl
    "mfctl", mfctl
    "mtsarcm", oneSource 0xC6u
    "mfia", oneTarget 0xA5u ]

/// One word of the kind saying something about how memory is looked up, given
/// the six bits saying which of them it is.
let private mgmt ext6 rest = OpMemMgmt ||| (ext6 <<< 6) ||| rest

(* The bit saying that an instruction is about the data the processor
   remembers rather than about the instructions it fetches. *)
let [<Literal>] private DataSide = 0x1000u

(* The bit saying that how far from a register an instruction reaches is
   written out rather than held in a second register. *)
let [<Literal>] private Written = 0x2000u

/// The bit saying that the register an address is counted from is left holding
/// that address, which is the only word most of these instructions carry.
let private modifyBit = function
  | [] -> 0u
  | [ "m" ] -> 1u
  | _ -> fail "this instruction is not written with those words"

/// <summary>
/// An instruction throwing away what the processor had remembered about an
/// address, which it names by a register and a second register added to it.
///
/// Which of the two things the processor remembers is meant - where it fetches
/// instructions from or where it reads data from - decides both a bit of the
/// word and how many spaces the address may lie in.
/// </summary>
let private cache side space ext6 ins =
  let m = modifyBit ins.Suffixes
  match ins.Operands with
  | [ Mem(Some(Rg index), sp, baseReg) ] ->
    mgmt ext6 ((gpr baseReg <<< 21) ||| (gpr index <<< 16) ||| space sp
               ||| side ||| (m <<< 5))
  | _ -> wrongOperands ins

/// The same, for the instructions the processor fetches, which lie in any of
/// the eight spaces.
let private insCache ext6 ins = cache 0u space3 ext6 ins

/// The same, for the data it reads, which lies in one of four.
let private dataCache ext6 ins = cache DataSide space2 ext6 ins

/// <summary>
/// The six bits and the bit naming which of the two instructions throwing away
/// a whole page rather than one line of it is meant.
///
/// The wider of the two is written only where the register an address is
/// counted from is left holding that address, because the bit saying so is
/// what tells it from an instruction naming nothing of the kind.
/// </summary>
let private pageForm = function
  | [] -> 0b001000u, 0u
  | [ "m" ] -> 0b001000u, 1u
  | [ "l"; "m" ] -> 0b011000u, 1u
  | _ -> fail "no lookup is thrown away this way"

/// An instruction throwing away what the processor had remembered about a
/// whole page.
let private page side space ins =
  let ext6, m = pageForm (List.sort ins.Suffixes)
  match ins.Operands with
  | [ Mem(Some(Rg index), sp, baseReg) ] ->
    mgmt ext6 ((gpr baseReg <<< 21) ||| (gpr index <<< 16) ||| space sp
               ||| side ||| (m <<< 5))
  | _ -> wrongOperands ins

/// <summary>
/// The instruction writing back and throwing away one line of what the
/// processor holds on to of the data it has read.
///
/// It is the one instruction of its kind naming how far from a register it
/// reaches with a written number as well as with a second register.
/// </summary>
let private fdc ins =
  let m = modifyBit ins.Suffixes
  match ins.Operands with
  | [ Mem(Some(Im offset), sp, baseReg) ] ->
    mgmt 0b001010u ((gpr baseReg <<< 21) ||| (lowSignExt 5 offset <<< 16)
                    ||| space2 sp ||| Written ||| DataSide ||| (m <<< 5))
  | _ -> dataCache 0b001010u ins

/// An instruction adding to what the processor remembers about where something
/// was found, which names two registers and no memory.
let private tlbInsert side ins =
  nothingLeft ins ins.Suffixes
  match ins.Operands with
  | [ Rg s1; Rg s2 ] ->
    mgmt 0b100000u ((gpr s2 <<< 21) ||| (gpr s1 <<< 16) ||| side)
  | _ -> wrongOperands ins

/// <summary>
/// An instruction adding one half of an entry to what the processor remembers
/// about where something was found.
///
/// The earlier architecture split an entry into the address it holds and the
/// protection that goes with it, and had one instruction for each half; the bit
/// just above the field naming which instruction a word is says which half. The
/// entry itself is named by a space and a register holding an address, so
/// unlike the merged instruction that replaced these, they name memory.
/// </summary>
let private tlbInsertHalf side half space ins =
  nothingLeft ins ins.Suffixes
  match ins.Operands with
  | [ Rg index; Mem(None, sp, baseReg) ] ->
    mgmt half ((gpr baseReg <<< 21) ||| (gpr index <<< 16) ||| space sp
               ||| side)
  | _ -> wrongOperands ins

/// The six bits saying which way a program asks whether it may reach an
/// address, which every such instruction is written with.
let private probeForm = function
  | [ "r" ] -> 0b000110u
  | [ "w" ] -> 0b000111u
  | _ -> fail "a probe asks about reading or about writing"

/// The instruction asking whether a program is allowed to reach an address at
/// the level of trust a register holds.
let private probe ins =
  let ext6 = probeForm ins.Suffixes
  match ins.Operands with
  | [ Mem(None, sp, baseReg); Rg s; Rg d ] ->
    mgmt ext6 ((gpr baseReg <<< 21) ||| (gpr s <<< 16) ||| space2 sp
               ||| DataSide ||| gpr d)
  | _ -> wrongOperands ins

/// The same, at a level of trust written out.
let private probei ins =
  let ext6 = probeForm ins.Suffixes
  match ins.Operands with
  | [ Mem(None, sp, baseReg); Im level; Rg d ] ->
    mgmt ext6 ((gpr baseReg <<< 21) ||| (unsigned 5 level <<< 16)
               ||| space2 sp ||| Written ||| DataSide ||| gpr d)
  | _ -> wrongOperands ins

/// An instruction working out something about an address and leaving it in a
/// general register.
let private lookup ext6 m ins =
  match ins.Operands with
  | [ Mem(Some(Rg index), sp, baseReg); Rg d ] ->
    mgmt ext6 ((gpr baseReg <<< 21) ||| (gpr index <<< 16) ||| space2 sp
               ||| DataSide ||| (m <<< 5) ||| gpr d)
  | _ -> wrongOperands ins

/// The instruction working out where in memory itself an address really is,
/// which may leave the register it counted from holding that address.
let private lpa ins = lookup 0b001101u (modifyBit ins.Suffixes) ins

/// The instruction working out what the processor calls an address.
let private lci ins =
  nothingLeft ins ins.Suffixes
  lookup 0b001100u 0u ins

/// The instructions saying something about how memory is looked up.
let memoryManagementEncoders () =
  [ "iitlbt", tlbInsert 0u
    "idtlbt", tlbInsert DataSide
    "iitlbp", tlbInsertHalf 0u 0b000000u space3
    "iitlba", tlbInsertHalf 0u 0b000001u space3
    "idtlbp", tlbInsertHalf DataSide 0b000000u space2
    "idtlba", tlbInsertHalf DataSide 0b000001u space2
    "pitlb", page 0u space3
    "pitlbe", insCache 0b001001u
    "fic", insCache 0b001010u
    "fice", insCache 0b001011u
    "pdtlb", page DataSide space2
    "pdtlbe", dataCache 0b001001u
    "fdc", fdc
    "fdce", dataCache 0b001011u
    "pdc", dataCache 0b001110u
    "probe", probe
    "probei", probei
    "lpa", lpa
    "lci", lci ]

/// One word of the kind computing from what two registers hold into a third.
let private compute ext6 cf rs2 rs1 rd =
  OpCompute ||| (rs2 <<< 21) ||| (rs1 <<< 16) ||| scatterCondition cf
  ||| (ext6 <<< 6) ||| rd

/// <summary>
/// An instruction computing from two registers into a third, going on a
/// condition read out of the given table.
///
/// The bit saying how much of what was computed the condition is read off is
/// the same bit that says whether a carry or a borrow is taken from a whole
/// doubleword, so where a word after the name has already said one of those,
/// the condition must say the same.
/// </summary>
let private threeReg ext6 wide readCondition ins rest =
  let cf = readCondition (condition rest)
  if Option.exists (fun d -> d <> (cf &&& 1u)) wide then
    fail $"{ins.Mnemonic} cannot say two things about a doubleword"
  else
    match ins.Operands with
    | [ Rg s1; Rg s2; Rg d ] -> compute ext6 cf (gpr s2) (gpr s1) (gpr d)
    | _ -> wrongOperands ins

/// The six bits naming which addition an instruction is, and whether the carry
/// it takes is taken from a whole doubleword.
let private addForm = function
  | [] -> 0b011000u, None
  | [ "l" ] -> 0b101000u, None
  | [ "tsv" ] -> 0b111000u, None
  | [ "c" ] -> 0b011100u, Some 0u
  | [ "dc" ] -> 0b011100u, Some 1u
  | [ "c"; "tsv" ] -> 0b111100u, Some 0u
  | [ "dc"; "tsv" ] -> 0b111100u, Some 1u
  | _ -> fail "no addition is written this way"

/// An addition, which may take a carry, may leave what it computes where the
/// program cannot see it, and may stop the program where it overflows.
let private add ins =
  let flags, rest = split [ "l"; "tsv"; "c"; "dc" ] ins.Suffixes
  let ext6, wide = addForm (List.sort flags)
  threeReg ext6 wide addCondition ins rest

/// The six bits naming which subtraction an instruction is, and whether the
/// borrow it takes is taken from a whole doubleword.
let private subForm = function
  | [] -> 0b010000u, None
  | [ "tsv" ] -> 0b110000u, None
  | [ "tc" ] -> 0b010011u, None
  | [ "tc"; "tsv" ] -> 0b110011u, None
  | [ "b" ] -> 0b010100u, Some 0u
  | [ "db" ] -> 0b010100u, Some 1u
  | [ "b"; "tsv" ] -> 0b110100u, Some 0u
  | [ "db"; "tsv" ] -> 0b110100u, Some 1u
  | _ -> fail "no subtraction is written this way"

/// A subtraction, which may take a borrow and may stop the program where what
/// it computes overflows or is not a decimal number.
let private sub ins =
  let flags, rest = split [ "tsv"; "tc"; "b"; "db" ] ins.Suffixes
  let ext6, wide = subForm (List.sort flags)
  threeReg ext6 wide compSubCondition ins rest

/// An instruction computing from two registers into a third whose name carries
/// no word beyond the condition it goes on.
let private plainThree ext6 readCondition ins =
  threeReg ext6 None readCondition ins ins.Suffixes

/// The instruction dividing one step at a time, whose condition is read off a
/// word alone and so is never written with a star.
let private ds ins =
  let cf = compSubCondition (condition ins.Suffixes)
  if cf &&& 1u = 1u then
    fail "a division step is read off a word alone"
  else
    match ins.Operands with
    | [ Rg s1; Rg s2; Rg d ] -> compute 0b010001u cf (gpr s2) (gpr s1) (gpr d)
    | _ -> wrongOperands ins

/// The instruction correcting a decimal number, whose name carries a word
/// where what it corrects was subtracted rather than added.
let private dcor ins =
  let flags, rest = split [ "i" ] ins.Suffixes
  let ext6 = if has "i" flags then 0b101111u else 0b101110u
  let cf = unitCondition (condition rest)
  match ins.Operands with
  | [ Rg s2; Rg d ] -> compute ext6 cf (gpr s2) 0u (gpr d)
  | _ -> wrongOperands ins

/// The instruction adding with a complement, which may stop the program where
/// what it computes is not a decimal number.
let private uaddcm ins =
  let flags, rest = split [ "tc" ] ins.Suffixes
  let ext6 = if has "tc" flags then 0b100111u else 0b100110u
  threeReg ext6 None unitCondition ins rest

/// An instruction working on several parts of a doubleword at once, which goes
/// on nothing at all.
let private parallelThree ext6 ins =
  nothingLeft ins ins.Suffixes
  match ins.Operands with
  | [ Rg s1; Rg s2; Rg d ] -> compute ext6 0u (gpr s2) (gpr s1) (gpr d)
  | _ -> wrongOperands ins

/// The instructions adding and subtracting several halves of a doubleword at
/// once, where a word after the name says what becomes of a half that will not
/// fit in the room left for it.
let private saturating plain signedFit unsignedFit ins =
  let bare = { ins with Suffixes = [] }
  match ins.Suffixes with
  | [] -> parallelThree plain bare
  | [ "ss" ] -> parallelThree signedFit bare
  | [ "us" ] -> parallelThree unsignedFit bare
  | _ -> wrongSuffixes ins

/// <summary>
/// An instruction shifting what one register holds a little way to the left
/// and adding a second register to it.
///
/// How far it shifts is the two lowest bits of the field naming what is
/// computed, so shifting no distance at all would name a plain addition
/// instead and is therefore not written.
/// </summary>
let private shiftAdd ext6 cf ins =
  match ins.Operands with
  | [ Rg s1; Im amount; Rg s2; Rg d ] when amount >= 1UL && amount <= 3UL ->
    compute (ext6 ||| uint32 amount) cf (gpr s2) (gpr s1) (gpr d)
  | _ -> wrongOperands ins

/// The instruction shifting and adding, which may leave what it computes where
/// the program cannot see it and may stop the program where it overflows.
let private shladd ins =
  let flags, rest = split [ "l"; "tsv" ] ins.Suffixes
  let ext6 =
    match List.sort flags with
    | [] -> 0b011000u
    | [ "l" ] -> 0b101000u
    | [ "tsv" ] -> 0b111000u
    | _ -> fail "no shifted addition is written this way"
  shiftAdd ext6 (addCondition (condition rest)) ins

/// The instructions shifting and adding several halves of a doubleword at
/// once, which go on nothing at all.
let private parallelShiftAdd ext6 ins =
  nothingLeft ins ins.Suffixes
  shiftAdd ext6 0u ins

/// The instructions computing from what the general registers hold.
let arithmeticEncoders () =
  [ "add", add
    "shladd", shladd
    "sub", sub
    "ds", ds
    "andcm", plainThree 0b000000u logicalCondition
    "and", plainThree 0b001000u logicalCondition
    "or", plainThree 0b001001u logicalCondition
    "xor", plainThree 0b001010u logicalCondition
    "uxor", plainThree 0b001110u unitCondition
    "cmpclr", plainThree 0b100010u compSubCondition
    "uaddcm", uaddcm
    "dcor", dcor
    "hadd", saturating 0b001111u 0b001101u 0b001100u
    "hsub", saturating 0b000111u 0b000101u 0b000100u
    "havg", parallelThree 0b001011u
    "hshladd", parallelShiftAdd 0b011100u
    "hshradd", parallelShiftAdd 0b010100u ]

/// One word of the kind computing from a register and a written number into a
/// second register.
let private computeImm opcode cond tsv rs2 rs1 imm =
  (opcode <<< 26) ||| (rs2 <<< 21) ||| (rs1 <<< 16) ||| (cond <<< 12)
  ||| (tsv <<< 11) ||| imm

/// An instruction computing from a register and a written number, which may
/// stop the program where what it computes overflows or is not a decimal
/// number.
let private immForm opcode carrying readCondition ins =
  let flags, rest = split [ "tsv"; "tc" ] ins.Suffixes
  let opcode = if has "tc" flags then carrying else opcode
  let cond = readCondition (condition rest)
  let tsv = bit "tsv" flags
  match ins.Operands with
  | [ Im imm; Rg s2; Rg d ] ->
    computeImm opcode cond tsv (gpr s2) (gpr d) (lowSignExt 11 imm)
  | _ -> wrongOperands ins

/// The instruction subtracting a register from a written number, which is the
/// one of the two that never corrects a decimal number.
let private subi ins =
  if has "tc" ins.Suffixes then
    fail "no subtraction from a written number corrects a decimal number"
  else
    immForm 0b100101u 0b100101u compSubCondition4 ins

/// The instructions computing from a register and a written number.
let immediateEncoders () =
  [ "addi", immForm 0b101101u 0b101100u addCondition4
    "subi", subi ]

/// One word of the kind shifting a pair of registers, taking a field out of
/// one, or laying a field into one.
let private field opcode c rs2 rs1 rest =
  opcode ||| (rs2 <<< 21) ||| (rs1 <<< 16) ||| (c <<< 13) ||| rest

/// The instruction taking a field out of the middle of a pair of registers,
/// where how far in it starts is held in the register saying how far a shift
/// goes.
let private shrpVar wide low ins =
  let c = shiftCondition wide (condition ins.Suffixes)
  match ins.Operands with
  | [ Rg s1; Rg s2; Rg sar; Rg d ] when sar = Register.CR11 ->
    field OpVarShift c (gpr s2) (gpr s1) (low ||| gpr d)
  | _ -> wrongOperands ins

/// The same, where how far in the field starts is written out.
let private shrpFixed wide position low ins =
  let c = shiftCondition wide (condition ins.Suffixes)
  match ins.Operands with
  | [ Rg s1; Rg s2; Im pos; Rg d ] ->
    let cp, cpos = position pos
    field OpVarShift c (gpr s2) (gpr s1)
      ((cp <<< 11) ||| low ||| (cpos <<< 5) ||| gpr d)
  | _ -> wrongOperands ins

/// Where in a word a field taken out of a pair of registers starts, which is
/// always named as a place in the lower half of a doubleword.
let private wordPair pos = 1u, wordPosition pos

/// The instruction shifting the lower halves of a pair of registers, which
/// starts either where a register says or where the source wrote.
let private shrpw ins = orTry (shrpVar 0u 0u) (shrpFixed 0u wordPair 0u) ins

/// The same, for a whole pair of doublewords.
let private shrpd ins =
  orTry (shrpVar 1u 0x200u) (shrpFixed 1u dwordPosition 0x400u) ins

/// The bit saying whether what is taken out of a register is widened by its
/// own sign or by nothing at all, which every extraction is written with.
let private extractBit = function
  | [ "s" ] -> 0x400u
  | [ "u" ] -> 0u
  | _ -> fail "an extraction says how what it takes out is widened"

/// The instruction taking a field out of a register, where the field starts
/// where the register saying how far a shift goes says.
let private extrVar wide low ins =
  let flags, rest = split [ "s"; "u" ] ins.Suffixes
  let se = extractBit flags
  let c = shiftCondition wide (condition rest)
  match ins.Operands with
  | [ Rg s2; Rg sar; Im len; Rg d ] when sar = Register.CR11 ->
    let cl, clen = if wide = 1u then dwordLength len else (0u, wordLength len)
    field OpVarShift c (gpr s2) (gpr d)
      (0x1000u ||| se ||| low ||| (cl <<< 8) ||| clen)
  | _ -> wrongOperands ins

/// The same, for a field of the lower half of a register whose place is
/// written out.
let private extrwFixed ins =
  let flags, rest = split [ "s"; "u" ] ins.Suffixes
  let se = extractBit flags
  let c = shiftCondition 0u (condition rest)
  match ins.Operands with
  | [ Rg s2; Im pos; Im len; Rg d ] ->
    field OpVarShift c (gpr s2) (gpr d)
      (0x1800u ||| se ||| (unsigned 5 pos <<< 5) ||| wordLength len)
  | _ -> wrongOperands ins

/// The same, for a field anywhere in a whole doubleword, which is the one form
/// of these with six bits' room for where the field starts.
let private extrdFixed ins =
  let flags, rest = split [ "s"; "u" ] ins.Suffixes
  let se = extractBit flags
  let c = shiftCondition 1u (condition rest)
  match ins.Operands with
  | [ Rg s2; Im pos; Im len; Rg d ] ->
    let cl, clen = extendedLength len
    let p = unsigned 6 pos
    field OpExtract c (gpr s2) (gpr d)
      ((cl <<< 12) ||| ((p >>> 5) <<< 11) ||| se ||| ((p &&& 0x1Fu) <<< 5)
       ||| clen)
  | _ -> wrongOperands ins

/// The instruction taking a field out of the lower half of a register.
let private extrw ins = orTry (extrVar 0u 0u) extrwFixed ins

/// The same, for a whole doubleword.
let private extrd ins = orTry (extrVar 1u 0x200u) extrdFixed ins

/// The bit saying that what lies outside the field laid into a register is
/// left as it was, which is written the other way round: a word after the name
/// says that it is cleared instead.
let private depositBit = function
  | [] -> 0x400u
  | [ "z" ] -> 0u
  | _ -> fail "a deposit either clears what lies around it or does not"

/// What is laid into a register, which is what a second register holds.
let private fromRegister = function
  | Rg s -> gpr s
  | _ -> fail "this is not a register"

/// The same, where what is laid in is a written number.
let private fromNumber = function
  | Im value -> lowSignExt 5 value
  | _ -> fail "this is not a number"

/// The instruction laying a field into a register, where where it lands is
/// said by the register saying how far a shift goes.
let private depVar wide low source ins =
  let flags, rest = split [ "z" ] ins.Suffixes
  let nz = depositBit flags
  let c = shiftCondition wide (condition rest)
  match ins.Operands with
  | [ head; Rg sar; Im len; Rg d ] when sar = Register.CR11 ->
    let cl, clen = if wide = 1u then dwordLength len else (0u, wordLength len)
    field OpVarDeposit c (gpr d) (source head)
      (nz ||| low ||| (cl <<< 8) ||| clen)
  | _ -> wrongOperands ins

/// The same, where where the field lands is written out.
let private depFixed opcode wide position length source ins =
  let flags, rest = split [ "z" ] ins.Suffixes
  let nz = depositBit flags
  let c = shiftCondition wide (condition rest)
  match ins.Operands with
  | [ head; Im pos; Im len; Rg d ] ->
    let cp, cpos = position pos
    let cl, clen = length len
    field opcode c (gpr d) (source head)
      ((cl <<< 12) ||| (cp <<< 11) ||| nz ||| (cpos <<< 5) ||| clen)
  | _ -> wrongOperands ins

/// How long a field laid into the lower half of a register is, together with
/// the bit that tells such a deposit from one laying in a written number.
let private wordField written len = written, wordLength len

/// The instruction laying a field into the lower half of a register.
let private depw ins =
  let fixedForm = depFixed OpVarDeposit 0u wordPair (wordField 0u) fromRegister
  orTry (depVar 0u 0u fromRegister) fixedForm ins

/// The same, where what is laid in is a written number.
let private depwi ins =
  let fixedForm = depFixed OpVarDeposit 0u wordPair (wordField 1u) fromNumber
  orTry (depVar 0u 0x1000u fromNumber) fixedForm ins

/// The same, for a field anywhere in a whole doubleword.
let private depd ins =
  let fixedForm =
    depFixed OpDeposit 1u dwordPosition extendedLength fromRegister
  orTry (depVar 1u 0x200u fromRegister) fixedForm ins

/// The same, where what is laid in is a written number.
let private depdi ins =
  let fixedForm =
    depFixed OpDepositImm 1u dwordPosition extendedLength fromNumber
  orTry (depVar 1u 0x1200u fromNumber) fixedForm ins

/// The instructions shifting a pair of registers, taking a field out of one,
/// and laying a field into one.
let fieldEncoders () =
  [ "shrpw", shrpw
    "shrpd", shrpd
    "extrw", extrw
    "extrd", extrd
    "depw", depw
    "depwi", depwi
    "depd", depd
    "depdi", depdi ]

/// The instruction rearranging the four halves of a doubleword, which says
/// where each of them comes from as one number of four digits.
let private permh ins =
  let numbers, rest = takeNumbers 1 ins.Suffixes
  nothingLeft ins rest
  let order = List.head numbers
  let digits =
    [ order / 1000UL; order / 100UL % 10UL; order / 10UL % 10UL; order % 10UL ]
  if List.exists (fun digit -> digit > 3UL) digits then
    fail $"{order} says nothing about where four halves come from"
  else
    match ins.Operands with
    | [ Rg s2; Rg d ] ->
      let places = [ 13; 10; 8; 6 ]
      List.map2 (fun digit place -> uint32 digit <<< place) digits places
      |> List.fold (|||) (OpMultimedia ||| (gpr s2 <<< 21) ||| gpr d)
    | _ -> wrongOperands ins

/// One word of the kind working on several halves of a doubleword at once,
/// given the four bits saying which of them it is, which the encoding keeps in
/// two pieces on either side of the field naming a register.
let private multimedia key rest =
  OpMultimedia ||| 0x8000u ||| (((key >>> 2) &&& 3u) <<< 13)
  ||| ((key &&& 3u) <<< 10) ||| rest

/// The instructions shifting every half of a doubleword the same way at once.
let private halfShift key first ins =
  match ins.Operands with
  | [ Rg s; Im amount; Rg d ] ->
    multimedia key ((gpr s <<< first) ||| (unsigned 4 amount <<< 6) ||| gpr d)
  | _ -> wrongOperands ins

/// The instruction shifting every half of a doubleword to the left, which
/// names the register it reads where the arithmetic names its first.
let private hshl ins =
  nothingLeft ins ins.Suffixes
  halfShift 0b0010u 16 ins

/// The same, to the right, where a word after the name says whether what comes
/// in at the top is nothing or the sign of what was there.
let private hshr ins =
  let bare = { ins with Suffixes = [] }
  match ins.Suffixes with
  | [ "u" ] -> halfShift 0b1010u 21 bare
  | [ "s" ] -> halfShift 0b1011u 21 bare
  | _ -> fail "this says nothing about how a shift is filled"

/// The instructions taking halves or words from two registers in turn.
let private mix key ins =
  match ins.Operands with
  | [ Rg s1; Rg s2; Rg d ] ->
    multimedia key ((gpr s2 <<< 21) ||| (gpr s1 <<< 16) ||| gpr d)
  | _ -> wrongOperands ins

/// The same, where a word after the name says which of each pair is taken.
let private mixForm left right ins =
  let bare = { ins with Suffixes = [] }
  match ins.Suffixes with
  | [ "l" ] -> mix left bare
  | [ "r" ] -> mix right bare
  | _ -> fail "this says nothing about which halves are taken"

/// The instructions working on several halves of a doubleword at once.
let multimediaEncoders () =
  [ "permh", permh
    "hshl", hshl
    "hshr", hshr
    "mixw", mixForm 0b0000u 0b1000u
    "mixh", mixForm 0b0001u 0b1001u ]

// vim: set tw=80 sts=2 sw=2:
