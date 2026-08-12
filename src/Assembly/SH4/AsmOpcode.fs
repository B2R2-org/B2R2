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
/// and the logic, the shifts, the moves at all three widths, the branches, and
/// what a program says to the machine it runs on.
/// </summary>
module internal B2R2.Assembly.SH4.AsmOpcode

open B2R2.FrontEnd.SH4
open B2R2.Assembly.SH4.ParserHelper
open B2R2.Assembly.SH4.AsmField

(* The four bits every SH4 word begins with, which are the coarsest thing
   saying what an instruction is. Only the families several instructions share
   are named here; one holding a single instruction is written where it is
   used. *)
let [<Literal>] private FamZero = 0x0us
let [<Literal>] private FamStore = 0x2us
let [<Literal>] private FamArith = 0x3us
let [<Literal>] private FamOne = 0x4us
let [<Literal>] private FamLoad = 0x6us

/// An instruction naming the register it reads and the register it writes,
/// which is the shape most of the instruction set has.
let private regPair family rest ins =
  match ins.Operands with
  | [ Rg m; Rg n ] -> nmWord family (gpr n) (gpr m) rest
  | _ -> wrongOperands ins

/// An addition, which is written the same whether what is added is held in a
/// register or written out.
let private add ins =
  match ins.Operands with
  | [ Rg m; Rg n ] -> nmWord FamArith (gpr n) (gpr m) 0xCus
  | [ Im value; Rg n ] -> nWord 0x7us (gpr n) (imm8 value)
  | _ -> wrongOperands ins

/// A comparison for equality, which is written out only against the first of
/// the general registers.
let private compareEqual ins =
  match ins.Operands with
  | [ Rg m; Rg n ] -> nmWord FamArith (gpr n) (gpr m) 0x0us
  | [ Im value; Rg Register.R0 ] -> immWord 0x88us (imm8 value)
  | _ -> wrongOperands ins

/// The instructions computing one number out of two, of which everything but
/// the two multiplications keeping a narrow result sits in one of three
/// families.
let arithmeticEncoders () =
  [ "add", add
    "cmpeq", compareEqual
    "addc", regPair FamArith 0xEus
    "addv", regPair FamArith 0xFus
    "cmphs", regPair FamArith 0x2us
    "cmpge", regPair FamArith 0x3us
    "cmphi", regPair FamArith 0x6us
    "cmpgt", regPair FamArith 0x7us
    "div1", regPair FamArith 0x4us
    "dmulul", regPair FamArith 0x5us
    "dmulsl", regPair FamArith 0xDus
    "sub", regPair FamArith 0x8us
    "subc", regPair FamArith 0xAus
    "subv", regPair FamArith 0xBus
    "div0s", regPair FamStore 0x7us
    "cmpstr", regPair FamStore 0xCus
    "xtrct", regPair FamStore 0xDus
    "muluw", regPair FamStore 0xEus
    "mulsw", regPair FamStore 0xFus
    "mull", regPair FamZero 0x7us
    "not", regPair FamLoad 0x7us
    "swapb", regPair FamLoad 0x8us
    "swapw", regPair FamLoad 0x9us
    "negc", regPair FamLoad 0xAus
    "neg", regPair FamLoad 0xBus
    "extub", regPair FamLoad 0xCus
    "extuw", regPair FamLoad 0xDus
    "extsb", regPair FamLoad 0xEus
    "extsw", regPair FamLoad 0xFus
    "shad", regPair FamOne 0xCus
    "shld", regPair FamOne 0xDus ]

/// <summary>
/// One of the four instructions computing a bit at a time.
///
/// Each is written three ways: over two registers, over the first of the
/// general registers and a written number, and over the one byte of memory the
/// global base names together with that same register. The third goes under a
/// name of its own because it works on a byte where the other two work on a
/// word, so only the first two are written here.
/// </summary>
let private bitwise rest head ins =
  match ins.Operands with
  | [ Rg m; Rg n ] -> nmWord FamStore (gpr n) (gpr m) rest
  | [ Im value; Rg Register.R0 ] -> immWord head (imm8 value)
  | _ -> wrongOperands ins

/// The third of those forms, which is the whole of what its name covers.
let private bitwiseByte head ins =
  match ins.Operands with
  | [ Im value; Idx Register.GBR ] -> immWord head (imm8 value)
  | _ -> wrongOperands ins

let logicEncoders () =
  [ "and", bitwise 0x9us 0xC9us
    "or", bitwise 0xBus 0xCBus
    "tst", bitwise 0x8us 0xC8us
    "xor", bitwise 0xAus 0xCAus
    "andb", bitwiseByte 0xCDus
    "orb", bitwiseByte 0xCFus
    "tstb", bitwiseByte 0xCCus
    "xorb", bitwiseByte 0xCEus ]

/// An instruction naming one register and nothing else, where everything below
/// the field naming it is spelt out.
let private oneReg family rest ins =
  match ins.Operands with
  | [ Rg n ] -> nWord family (gpr n) rest
  | _ -> wrongOperands ins

/// The instructions moving what one register holds by a distance the
/// instruction itself says, together with the two that read a register without
/// writing one and the one counting a register down to zero.
let shiftEncoders () =
  [ "shll", oneReg FamOne 0x00us
    "shlr", oneReg FamOne 0x01us
    "rotl", oneReg FamOne 0x04us
    "rotr", oneReg FamOne 0x05us
    "shll2", oneReg FamOne 0x08us
    "shlr2", oneReg FamOne 0x09us
    "dt", oneReg FamOne 0x10us
    "cmppz", oneReg FamOne 0x11us
    "cmppl", oneReg FamOne 0x15us
    "shll8", oneReg FamOne 0x18us
    "shlr8", oneReg FamOne 0x19us
    "shal", oneReg FamOne 0x20us
    "shar", oneReg FamOne 0x21us
    "rotcl", oneReg FamOne 0x24us
    "rotcr", oneReg FamOne 0x25us
    "shll16", oneReg FamOne 0x28us
    "shlr16", oneReg FamOne 0x29us ]

/// <summary>
/// The forms of a move that every width of it shares.
///
/// Which width a move works at is the last thing its name says and the lowest
/// bits of its encoding say, so the three widths differ by a number counting
/// them and the forms below are written once for all three.
/// </summary>
let private movShared w ins =
  match ins.Operands with
  | [ Rg m; Ind n ] -> nmWord FamStore (gpr n) (gpr m) w
  | [ Rg m; Pre n ] -> nmWord FamStore (gpr n) (gpr m) (w + 4us)
  | [ Ind m; Rg n ] -> nmWord FamLoad (gpr n) (gpr m) w
  | [ Post m; Rg n ] -> nmWord FamLoad (gpr n) (gpr m) (w + 4us)
  | [ Rg m; Idx n ] -> nmWord FamZero (gpr n) (gpr m) (w + 4us)
  | [ Idx m; Rg n ] -> nmWord FamZero (gpr n) (gpr m) (w + 12us)
  | [ Rg Register.R0; Disp(d, Register.GBR) ] -> immWord (0xC0us + w) (disp8 d)
  | [ Disp(d, Register.GBR); Rg Register.R0 ] -> immWord (0xC4us + w) (disp8 d)
  | _ -> wrongOperands ins

/// A move of one byte, which reaches a written distance from a register only
/// out of and into the first of the general registers.
let private moveByte ins =
  match ins.Operands with
  | [ Rg Register.R0; Disp(d, n) ] when isGeneral n ->
    nmWord 0x8us 0x0us (gpr n) (disp4 d)
  | [ Disp(d, m); Rg Register.R0 ] when isGeneral m ->
    nmWord 0x8us 0x4us (gpr m) (disp4 d)
  | _ ->
    movShared 0x0us ins

/// A move of one word, which reaches the same way, and reads besides what lies
/// a written distance from where the instruction itself sits.
let private moveWord ins =
  match ins.Operands with
  | [ Rg Register.R0; Disp(d, n) ] when isGeneral n ->
    nmWord 0x8us 0x1us (gpr n) (disp4 d)
  | [ Disp(d, m); Rg Register.R0 ] when isGeneral m ->
    nmWord 0x8us 0x5us (gpr m) (disp4 d)
  | [ Disp(d, Register.PC); Rg n ] ->
    nWord 0x9us (gpr n) (disp8 d)
  | _ ->
    movShared 0x1us ins

/// A move of one longword, which reaches a written distance out of and into any
/// register at all, because it has both of its register fields free where the
/// narrower moves spend one of them on the distance.
let private moveLong ins =
  match ins.Operands with
  | [ Rg m; Disp(d, n) ] when isGeneral n ->
    nmWord 0x1us (gpr n) (gpr m) (disp4 d)
  | [ Disp(d, m); Rg n ] when isGeneral m ->
    nmWord 0x5us (gpr n) (gpr m) (disp4 d)
  | [ Disp(d, Register.PC); Rg n ] ->
    nWord 0xDus (gpr n) (disp8 d)
  | _ ->
    movShared 0x2us ins

/// A move between two registers, or of a written number into one.
let private move ins =
  match ins.Operands with
  | [ Rg m; Rg n ] -> nmWord FamLoad (gpr n) (gpr m) 0x3us
  | [ Im value; Rg n ] -> nWord 0xEus (gpr n) (imm8 value)
  | _ -> wrongOperands ins

/// The instruction working out the address a move of a longword would read
/// from, without reading it.
let private moveAddress ins =
  match ins.Operands with
  | [ Disp(d, Register.PC); Rg Register.R0 ] -> immWord 0xC7us (disp8 d)
  | _ -> wrongOperands ins

/// The instruction taking a block of the cache for itself instead of reading
/// what memory already holds there.
let private moveCacheAllocate ins =
  match ins.Operands with
  | [ Rg Register.R0; Ind n ] -> nWord FamZero (gpr n) 0xC3us
  | _ -> wrongOperands ins

let moveEncoders () =
  [ "mov", move
    "movb", moveByte
    "movw", moveWord
    "movl", moveLong
    "mova", moveAddress
    "movcal", moveCacheAllocate
    "movt", oneReg FamZero 0x29us ]

/// <summary>
/// A branch reading the bit a comparison left, which says where it goes either
/// as the bits its encoding holds or as the place it wants to end up at.
///
/// What the disassembler writes there is the field itself rather than anywhere
/// in particular, because a word on its own does not say where it sits. A
/// source naming a place says where it wants to end up instead, and the two are
/// the same thing once the distance between them has been worked out.
/// </summary>
let private shortBranch head ins =
  match ins.Operands with
  | [ Nm value ] -> immWord head (bdisp8 value)
  | [ Tgt target ] -> immWord head (branchTo 8 ins target)
  | _ -> wrongOperands ins

/// A branch reading nothing, which reaches sixteen times as far because it
/// spends on the distance the bits the others spend saying what to read.
let private longBranch family ins =
  match ins.Operands with
  | [ Nm value ] -> dispWord family (bdisp12 value)
  | [ Tgt target ] -> dispWord family (branchTo 12 ins target)
  | _ -> wrongOperands ins

/// An instruction naming the memory whose address a register holds, and nothing
/// else.
let private oneIndir family rest ins =
  match ins.Operands with
  | [ Ind n ] -> nWord family (gpr n) rest
  | _ -> wrongOperands ins

/// The instructions going somewhere other than the next word: the four reading
/// a bit a comparison left, the two reaching furthest, the two going a distance
/// a register holds, and the two going to an address one holds.
let branchEncoders () =
  [ "bt", shortBranch 0x89us
    "bts", shortBranch 0x8Dus
    "bf", shortBranch 0x8Bus
    "bfs", shortBranch 0x8Fus
    "bra", longBranch 0xAus
    "bsr", longBranch 0xBus
    "bsrf", oneReg FamZero 0x03us
    "braf", oneReg FamZero 0x23us
    "jsr", oneIndir FamOne 0x0Bus
    "jmp", oneIndir FamOne 0x2Bus ]

/// <summary>
/// Which of the registers the machine keeps to itself is named, in the four
/// bits above the four saying how it is moved.
///
/// A bank is named the same way with the bit above its number set, which is
/// what says that a bank is named at all. The two registers added after the
/// rest are reached by the other member of the pair of ways such an instruction
/// is written, so they are not named here.
/// </summary>
let private controlIndex reg =
  match reg with
  | Register.SR ->
    0x00us
  | Register.GBR ->
    0x10us
  | Register.VBR ->
    0x20us
  | Register.SSR ->
    0x30us
  | Register.SPC ->
    0x40us
  | _ when reg >= Register.R0_BANK && reg <= Register.R7_BANK ->
    (0x8us ||| bank reg) <<< 4
  | _ ->
    fail $"{Register.toString reg} is not a control register"

/// The same, for the registers the multiplier and the floating-point unit keep.
let private systemIndex reg =
  match reg with
  | Register.MACH -> 0x00us
  | Register.MACL -> 0x10us
  | Register.PR -> 0x20us
  | Register.FPUL -> 0x50us
  | Register.FPSCR -> 0x60us
  | _ -> fail $"{Register.toString reg} is not a system register"

/// The eight bits below the field naming the general register, for the two
/// instructions copying a control register into one a program may name.
let private storeControl toMemory reg =
  match reg, toMemory with
  | Register.SGR, false -> 0x3Aus
  | Register.SGR, true -> 0x32us
  | Register.DBR, false -> 0xFAus
  | Register.DBR, true -> 0xF2us
  | _ -> controlIndex reg ||| (if toMemory then 0x3us else 0x2us)

/// The same, for the two copying one the other way. Nothing writes the register
/// holding the stack the machine saved, so only one of the two added after the
/// rest is named here.
let private loadControl fromMemory reg =
  match reg, fromMemory with
  | Register.DBR, false -> 0xFAus
  | Register.DBR, true -> 0xF6us
  | Register.SGR, _ -> fail "sgr is written by the machine alone"
  | _ -> controlIndex reg ||| (if fromMemory then 0x7us else 0xEus)

/// The same, for the system registers, which differ only in the nibble below
/// the one naming them.
let private storeSystem toMemory reg =
  systemIndex reg ||| (if toMemory then 0x2us else 0xAus)

/// The same, the other way about.
let private loadSystem fromMemory reg =
  systemIndex reg ||| (if fromMemory then 0x6us else 0xAus)

/// An instruction copying a register the machine keeps to itself into a general
/// register, or into the memory one names once it has moved back.
let private store bits toMemory ins =
  match ins.Operands, toMemory with
  | [ Rg src; Rg n ], false -> nWord FamZero (gpr n) (bits false src)
  | [ Rg src; Pre n ], true -> nWord FamOne (gpr n) (bits true src)
  | _ -> wrongOperands ins

/// The same, the other way about.
let private load bits fromMemory ins =
  match ins.Operands, fromMemory with
  | [ Rg m; Rg dst ], false -> nWord FamOne (gpr m) (bits false dst)
  | [ Post m; Rg dst ], true -> nWord FamOne (gpr m) (bits true dst)
  | _ -> wrongOperands ins

/// An instruction naming two registers, each of which moves on past what was
/// read through it.
let private postIncPair family ins =
  match ins.Operands with
  | [ Post m; Post n ] -> nmWord family (gpr n) (gpr m) 0xFus
  | _ -> wrongOperands ins

/// An instruction naming a written number and nothing else.
let private oneImm head ins =
  match ins.Operands with
  | [ Im value ] -> immWord head (imm8 value)
  | _ -> wrongOperands ins

/// An instruction naming nothing at all, and therefore one word spelt out to
/// the last bit.
let private noOperand word ins =
  match ins.Operands with
  | [] -> word
  | _ -> wrongOperands ins

/// The instructions moving the registers a program does not compute with,
/// saying something to the cache or to the machine, or saying nothing at all.
let systemEncoders () =
  [ "stc", store storeControl false
    "stcl", store storeControl true
    "sts", store storeSystem false
    "stsl", store storeSystem true
    "ldc", load loadControl false
    "ldcl", load loadControl true
    "lds", load loadSystem false
    "ldsl", load loadSystem true
    "macl", postIncPair FamZero
    "macw", postIncPair FamOne
    "tasb", oneIndir FamOne 0x1Bus
    "pref", oneIndir FamZero 0x83us
    "ocbi", oneIndir FamZero 0x93us
    "ocbp", oneIndir FamZero 0xA3us
    "ocbwb", oneIndir FamZero 0xB3us
    "trapa", oneImm 0xC3us
    "clrt", noOperand 0x0008us
    "sett", noOperand 0x0018us
    "clrmac", noOperand 0x0028us
    "ldtlb", noOperand 0x0038us
    "clrs", noOperand 0x0048us
    "sets", noOperand 0x0058us
    "nop", noOperand 0x0009us
    "div0u", noOperand 0x0019us
    "rts", noOperand 0x000Bus
    "sleep", noOperand 0x001Bus
    "rte", noOperand 0x002Bus ]

// vim: set tw=80 sts=2 sw=2:
