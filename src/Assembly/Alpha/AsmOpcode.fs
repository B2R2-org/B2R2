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
/// Encodes every Alpha instruction but the floating-point ones: the arithmetic
/// and the logic, the shifts and the instructions reaching inside a word, the
/// multiplication, the loads and the stores, the branches both counted and
/// computed, the instructions ordering memory and reading the counters, and the
/// trap to PALcode.
///
/// Each group below pairs the instructions sharing a shape with the bits naming
/// each of them, and the name every one of them goes under comes from <see
/// cref='M:B2R2.FrontEnd.Alpha.Opcode.ToString'/>, which the disassembler
/// writes by, so the two cannot drift.
/// </summary>
module internal B2R2.Assembly.Alpha.AsmOpcode

open B2R2.FrontEnd.Alpha
open B2R2.Assembly.Alpha.ParserHelper
open B2R2.Assembly.Alpha.AsmField

(* The six bits the instructions each written on their own below begin with:
   the ones holding a function code where a displacement would sit, the branches
   to a computed address, and the group the instruction saying which
   implementation this is belongs to. *)
let [<Literal>] private OpMisc = 0x18u
let [<Literal>] private OpJump = 0x1Au
let [<Literal>] private OpLogic = 0x11u

/// An instruction reaching memory with a general register.
let private intMemory op ins =
  match ins.Operands with
  | [ Rg ra; Mem(rb, disp) ] -> memWord op (gpr ra) (gpr rb) (memDisp disp)
  | _ -> wrongOperands ins

/// The loads and the stores of a general register.
let intMemoryEncoders () =
  [ Opcode.LDA, 0x08u
    Opcode.LDAH, 0x09u
    Opcode.LDBU, 0x0Au
    Opcode.LDQ_U, 0x0Bu
    Opcode.LDWU, 0x0Cu
    Opcode.STW, 0x0Du
    Opcode.STB, 0x0Eu
    Opcode.STQ_U, 0x0Fu
    Opcode.LDL, 0x28u
    Opcode.LDQ, 0x29u
    Opcode.LDL_L, 0x2Au
    Opcode.LDQ_L, 0x2Bu
    Opcode.STL, 0x2Cu
    Opcode.STQ, 0x2Du
    Opcode.STL_C, 0x2Eu
    Opcode.STQ_C, 0x2Fu ]
  |> List.map (fun (op, major) -> Opcode.toString op, intMemory major)

/// The same, where the register the instruction names is a floating-point one.
let private fltMemory op ins =
  match ins.Operands with
  | [ Rg fa; Mem(rb, disp) ] -> memWord op (fpr fa) (gpr rb) (memDisp disp)
  | _ -> wrongOperands ins

/// The loads and the stores of a floating-point register.
let fltMemoryEncoders () =
  [ Opcode.LDF, 0x20u
    Opcode.LDG, 0x21u
    Opcode.LDS, 0x22u
    Opcode.LDT, 0x23u
    Opcode.STF, 0x24u
    Opcode.STG, 0x25u
    Opcode.STS, 0x26u
    Opcode.STT, 0x27u ]
  |> List.map (fun (op, major) -> Opcode.toString op, fltMemory major)

/// <summary>
/// A prefetch, which names the memory it reaches and no register at all.
///
/// It shares an opcode with the load of the same width, and what tells the two
/// apart is that a prefetch loads into the register that always reads as zero.
/// </summary>
let private prefetch op ins =
  match ins.Operands with
  | [ Mem(rb, disp) ] -> memWord op Unused (gpr rb) (memDisp disp)
  | _ -> wrongOperands ins

/// The prefetches, one for each of the four ways of asking for one.
let prefetchEncoders () =
  [ Opcode.PREFETCH_M, 0x22u
    Opcode.PREFETCH_MEN, 0x23u
    Opcode.PREFETCH, 0x28u
    Opcode.PREFETCH_EN, 0x29u ]
  |> List.map (fun (op, major) -> Opcode.toString op, prefetch major)

/// An instruction ordering the accesses to memory around it, which names
/// nothing.
let private barrier func ins =
  match ins.Operands with
  | [] -> memWord OpMisc Unused Unused func
  | _ -> wrongOperands ins

/// The instructions ordering memory and waiting for what came before them.
let barrierEncoders () =
  [ Opcode.TRAPB, 0x0000u
    Opcode.EXCB, 0x0400u
    Opcode.MB, 0x4000u
    Opcode.WMB, 0x4400u ]
  |> List.map (fun (op, func) -> Opcode.toString op, barrier func)

/// An instruction naming the memory it says something about and nothing else.
let private hinted func ins =
  match ins.Operands with
  | [ Base rb ] -> memWord OpMisc Unused (gpr rb) func
  | _ -> wrongOperands ins

/// The instructions saying what is about to be done to a block of memory.
let hintedEncoders () =
  [ Opcode.FETCH, 0x8000u
    Opcode.FETCH_M, 0xA000u
    Opcode.ECB, 0xE800u
    Opcode.WH64, 0xF800u
    Opcode.WH64EN, 0xFC00u ]
  |> List.map (fun (op, func) -> Opcode.toString op, hinted func)

/// An instruction naming only the register it writes what it read into.
let private counter func ins =
  match ins.Operands with
  | [ Rg ra ] -> memWord OpMisc (gpr ra) Unused func
  | _ -> wrongOperands ins

/// The instructions reading a counter or a flag.
let counterEncoders () =
  [ Opcode.RPCC, 0xC000u
    Opcode.RC, 0xE000u
    Opcode.RS, 0xF000u ]
  |> List.map (fun (op, func) -> Opcode.toString op, counter func)

/// <summary>
/// A branch to a computed address.
///
/// Which of the four it is, is said by the two bits at the top of the field a
/// displacement would sit in; what is left of that field is the guess at where
/// it ends up.
/// </summary>
let private jump kind ins =
  match ins.Operands with
  | [ Rg ra; Base rb; Im h ] ->
    memWord OpJump (gpr ra) (gpr rb) ((kind <<< 14) ||| hint h)
  | _ ->
    wrongOperands ins

/// The four branches to a computed address.
let jumpEncoders () =
  [ Opcode.JMP, 0x00u
    Opcode.JSR, 0x01u
    Opcode.RET, 0x02u
    Opcode.JSR_COROUTINE, 0x03u ]
  |> List.map (fun (op, kind) -> Opcode.toString op, jump kind)

/// A branch counting how far away the place it names is, testing a general
/// register.
let private intBranch op ins =
  match ins.Operands with
  | [ Rg ra; Im target ] -> braWord op (gpr ra) (branchDisp target)
  | _ -> wrongOperands ins

/// The branches testing a general register, and the two keeping where they
/// came from.
let intBranchEncoders () =
  [ Opcode.BR, 0x30u
    Opcode.BSR, 0x34u
    Opcode.BLBC, 0x38u
    Opcode.BEQ, 0x39u
    Opcode.BLT, 0x3Au
    Opcode.BLE, 0x3Bu
    Opcode.BLBS, 0x3Cu
    Opcode.BNE, 0x3Du
    Opcode.BGE, 0x3Eu
    Opcode.BGT, 0x3Fu ]
  |> List.map (fun (op, major) -> Opcode.toString op, intBranch major)

/// The same, where what it tests is a floating-point register.
let private fltBranch op ins =
  match ins.Operands with
  | [ Rg fa; Im target ] -> braWord op (fpr fa) (branchDisp target)
  | _ -> wrongOperands ins

/// The branches testing a floating-point register.
let fltBranchEncoders () =
  [ Opcode.FBEQ, 0x31u
    Opcode.FBLT, 0x32u
    Opcode.FBLE, 0x33u
    Opcode.FBNE, 0x35u
    Opcode.FBGE, 0x36u
    Opcode.FBGT, 0x37u ]
  |> List.map (fun (op, major) -> Opcode.toString op, fltBranch major)

/// An instruction computing from a register and either a second register or a
/// number written in its place, into a third register.
let private operate op func ins =
  match ins.Operands with
  | [ Rg ra; source; Rg rc ] ->
    oprWord op func (gpr ra) (operateSource source) (gpr rc)
  | _ ->
    wrongOperands ins

/// The instructions computing from two things into a third.
let operateEncoders () =
  [ Opcode.ADDL, 0x10u, 0x00u
    Opcode.S4ADDL, 0x10u, 0x02u
    Opcode.SUBL, 0x10u, 0x09u
    Opcode.S4SUBL, 0x10u, 0x0Bu
    Opcode.CMPBGE, 0x10u, 0x0Fu
    Opcode.S8ADDL, 0x10u, 0x12u
    Opcode.S8SUBL, 0x10u, 0x1Bu
    Opcode.CMPULT, 0x10u, 0x1Du
    Opcode.ADDQ, 0x10u, 0x20u
    Opcode.S4ADDQ, 0x10u, 0x22u
    Opcode.SUBQ, 0x10u, 0x29u
    Opcode.S4SUBQ, 0x10u, 0x2Bu
    Opcode.CMPEQ, 0x10u, 0x2Du
    Opcode.S8ADDQ, 0x10u, 0x32u
    Opcode.S8SUBQ, 0x10u, 0x3Bu
    Opcode.CMPULE, 0x10u, 0x3Du
    Opcode.ADDLV, 0x10u, 0x40u
    Opcode.SUBLV, 0x10u, 0x49u
    Opcode.CMPLT, 0x10u, 0x4Du
    Opcode.ADDQV, 0x10u, 0x60u
    Opcode.SUBQV, 0x10u, 0x69u
    Opcode.CMPLE, 0x10u, 0x6Du
    Opcode.AND, 0x11u, 0x00u
    Opcode.BIC, 0x11u, 0x08u
    Opcode.CMOVLBS, 0x11u, 0x14u
    Opcode.CMOVLBC, 0x11u, 0x16u
    Opcode.BIS, 0x11u, 0x20u
    Opcode.CMOVEQ, 0x11u, 0x24u
    Opcode.CMOVNE, 0x11u, 0x26u
    Opcode.ORNOT, 0x11u, 0x28u
    Opcode.XOR, 0x11u, 0x40u
    Opcode.CMOVLT, 0x11u, 0x44u
    Opcode.CMOVGE, 0x11u, 0x46u
    Opcode.EQV, 0x11u, 0x48u
    Opcode.CMOVLE, 0x11u, 0x64u
    Opcode.CMOVGT, 0x11u, 0x66u
    Opcode.MSKBL, 0x12u, 0x02u
    Opcode.EXTBL, 0x12u, 0x06u
    Opcode.INSBL, 0x12u, 0x0Bu
    Opcode.MSKWL, 0x12u, 0x12u
    Opcode.EXTWL, 0x12u, 0x16u
    Opcode.INSWL, 0x12u, 0x1Bu
    Opcode.MSKLL, 0x12u, 0x22u
    Opcode.EXTLL, 0x12u, 0x26u
    Opcode.INSLL, 0x12u, 0x2Bu
    Opcode.ZAP, 0x12u, 0x30u
    Opcode.ZAPNOT, 0x12u, 0x31u
    Opcode.MSKQL, 0x12u, 0x32u
    Opcode.SRL, 0x12u, 0x34u
    Opcode.EXTQL, 0x12u, 0x36u
    Opcode.SLL, 0x12u, 0x39u
    Opcode.INSQL, 0x12u, 0x3Bu
    Opcode.SRA, 0x12u, 0x3Cu
    Opcode.MSKWH, 0x12u, 0x52u
    Opcode.INSWH, 0x12u, 0x57u
    Opcode.EXTWH, 0x12u, 0x5Au
    Opcode.MSKLH, 0x12u, 0x62u
    Opcode.INSLH, 0x12u, 0x67u
    Opcode.EXTLH, 0x12u, 0x6Au
    Opcode.MSKQH, 0x12u, 0x72u
    Opcode.INSQH, 0x12u, 0x77u
    Opcode.EXTQH, 0x12u, 0x7Au
    Opcode.MULL, 0x13u, 0x00u
    Opcode.MULQ, 0x13u, 0x20u
    Opcode.UMULH, 0x13u, 0x30u
    Opcode.MULLV, 0x13u, 0x40u
    Opcode.MULQV, 0x13u, 0x60u
    Opcode.PERR, 0x1Cu, 0x31u
    Opcode.MINSB8, 0x1Cu, 0x38u
    Opcode.MINSW4, 0x1Cu, 0x39u
    Opcode.MINUB8, 0x1Cu, 0x3Au
    Opcode.MINUW4, 0x1Cu, 0x3Bu
    Opcode.MAXUB8, 0x1Cu, 0x3Cu
    Opcode.MAXUW4, 0x1Cu, 0x3Du
    Opcode.MAXSB8, 0x1Cu, 0x3Eu
    Opcode.MAXSW4, 0x1Cu, 0x3Fu ]
  |> List.map (fun (op, major, func) -> Opcode.toString op, operate major func)

/// The same, for the instructions reading one thing only, which leave the
/// field naming the first register unused.
let private reduced op func ins =
  match ins.Operands with
  | [ source; Rg rc ] ->
    oprWord op func Unused (operateSource source) (gpr rc)
  | _ ->
    wrongOperands ins

/// The instructions computing from one thing into another.
let reducedEncoders () =
  [ Opcode.AMASK, 0x11u, 0x61u
    Opcode.SEXTB, 0x1Cu, 0x00u
    Opcode.SEXTW, 0x1Cu, 0x01u
    Opcode.CTPOP, 0x1Cu, 0x30u
    Opcode.CTLZ, 0x1Cu, 0x32u
    Opcode.CTTZ, 0x1Cu, 0x33u
    Opcode.UNPKBW, 0x1Cu, 0x34u
    Opcode.UNPKBL, 0x1Cu, 0x35u
    Opcode.PKWB, 0x1Cu, 0x36u
    Opcode.PKLB, 0x1Cu, 0x37u ]
  |> List.map (fun (op, major, func) -> Opcode.toString op, reduced major func)

/// <summary>
/// The instruction saying which implementation of the architecture this is,
/// which reads nothing at all.
///
/// The architecture asks it to hold the number one where a second register
/// would be, so that is what is written there rather than the unused register
/// everything else leaves in such a field.
/// </summary>
let private implver ins =
  match ins.Operands with
  | [ Rg rc ] ->
    oprWord OpLogic 0x6Cu Unused (operateSource (AsmImm 1UL)) (gpr rc)
  | _ ->
    wrongOperands ins

/// An instruction moving what a floating-point register holds into a general
/// one, which names the floating-point register where a first register would
/// be and leaves the field for a second one unused.
let private floatToInt op func ins =
  match ins.Operands with
  | [ Rg fa; Rg rc ] ->
    oprWord op func (fpr fa) (Unused <<< 16) (gpr rc)
  | _ ->
    wrongOperands ins

/// A trap to PALcode, which names the routine it traps to and nothing else.
let private callPal ins =
  match ins.Operands with
  | [ Im func ] -> palFunction func
  | _ -> wrongOperands ins

/// The instructions whose operands are not the ones any group above takes.
let singularEncoders () =
  [ Opcode.toString Opcode.IMPLVER, implver
    Opcode.toString Opcode.CALL_PAL, callPal ]
  @ ([ Opcode.FTOIT, 0x1Cu, 0x70u
       Opcode.FTOIS, 0x1Cu, 0x78u ]
     |> List.map (fun (op, major, func) ->
       Opcode.toString op, floatToInt major func))

// vim: set tw=80 sts=2 sw=2:
