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
/// Encodes every eBPF instruction: the arithmetic and the logic on the whole of
/// a register and on its lower half, the moves both plain and widening, the
/// instructions writing a register back in a given byte order, the loads and
/// the stores at every width, the atomic stores, the reads of a packet, the
/// jumps both comparing and unconditional, the calls, and the return.
///
/// Each group below pairs the instructions sharing a shape with the bits naming
/// each of them, and the name every one of them goes under comes from <see
/// cref='M:B2R2.FrontEnd.BPF.Opcode.ToString'/>, which the disassembler writes
/// by, so the two cannot drift.
/// </summary>
module internal B2R2.Assembly.BPF.AsmOpcode

open B2R2.FrontEnd.BPF
open B2R2.Assembly.BPF.ParserHelper
open B2R2.Assembly.BPF.AsmField

(* The three bits every word begins with, which say what kind of instruction it
   is, and the bit just above them, which says that what an instruction computes
   from is a register rather than a number. *)
let [<Literal>] private ClsLdx = 0x01u
let [<Literal>] private ClsSt = 0x02u
let [<Literal>] private ClsStx = 0x03u
let [<Literal>] private ClsAlu = 0x04u
let [<Literal>] private ClsJmp = 0x05u
let [<Literal>] private ClsJmp32 = 0x06u
let [<Literal>] private ClsAlu64 = 0x07u
let [<Literal>] private SrcReg = 0x08u

/// An instruction computing on a register, which computes either from a second
/// register or from a number written in its place.
let private arithmetic cls op off ins =
  match ins.Operands with
  | [ Rg dst; Rg src ] ->
    [ word (op ||| SrcReg ||| cls) (gpr dst) (gpr src) off 0u ]
  | [ Rg dst; Im value ] ->
    [ word (op ||| cls) (gpr dst) 0u off (imm32 value) ]
  | _ ->
    wrongOperands ins

/// The instructions computing on a register, each under the name it goes by in
/// each of the two classes.
let arithmeticEncoders () =
  [ Opcode.ADD, Opcode.ADD32, 0x00u, 0u
    Opcode.SUB, Opcode.SUB32, 0x10u, 0u
    Opcode.MUL, Opcode.MUL32, 0x20u, 0u
    Opcode.DIV, Opcode.DIV32, 0x30u, 0u
    Opcode.SDIV, Opcode.SDIV32, 0x30u, 1u
    Opcode.OR, Opcode.OR32, 0x40u, 0u
    Opcode.AND, Opcode.AND32, 0x50u, 0u
    Opcode.LSH, Opcode.LSH32, 0x60u, 0u
    Opcode.RSH, Opcode.RSH32, 0x70u, 0u
    Opcode.MOD, Opcode.MOD32, 0x90u, 0u
    Opcode.SMOD, Opcode.SMOD32, 0x90u, 1u
    Opcode.XOR, Opcode.XOR32, 0xA0u, 0u
    Opcode.MOV, Opcode.MOV32, 0xB0u, 0u
    Opcode.ARSH, Opcode.ARSH32, 0xC0u, 0u ]
  |> List.collect (fun (wide, narrow, op, off) ->
    [ Opcode.toString wide, arithmetic ClsAlu64 op off
      Opcode.toString narrow, arithmetic ClsAlu op off ])

/// A negation, which names the one register it works on.
let private negate cls ins =
  match ins.Operands with
  | [ Rg dst ] -> [ word (0x80u ||| cls) (gpr dst) 0u 0u 0u ]
  | _ -> wrongOperands ins

/// The negations, one in each of the two classes.
let negateEncoders () =
  [ Opcode.toString Opcode.NEG, negate ClsAlu64
    Opcode.toString Opcode.NEG32, negate ClsAlu ]

/// A move widening what it reads, which names how much of its source it reads
/// where the instructions above name what they compute from.
let private widen cls allowWord ins =
  match ins.Operands with
  | [ Rg dst; Rg src; Im width ] ->
    let off = widenWidth allowWord width
    [ word (0xB0u ||| SrcReg ||| cls) (gpr dst) (gpr src) off 0u ]
  | _ ->
    wrongOperands ins

/// The widening moves. The one writing the lower half of a register cannot
/// widen a whole word, that being the whole of what it writes.
let widenEncoders () =
  [ Opcode.toString Opcode.MOVSX, widen ClsAlu64 true
    Opcode.toString Opcode.MOVSX32, widen ClsAlu false ]

/// An instruction writing a register back in a given byte order, how much of it
/// to reverse being part of the name and held where a number would sit.
let private swap code width ins =
  match ins.Operands with
  | [ Rg dst ] -> [ word code (gpr dst) 0u 0u width ]
  | _ -> wrongOperands ins

/// The instructions writing a register back in a given byte order.
let swapEncoders () =
  [ Opcode.LE16, 0xD4u, 16u
    Opcode.LE32, 0xD4u, 32u
    Opcode.LE64, 0xD4u, 64u
    Opcode.BE16, 0xDCu, 16u
    Opcode.BE32, 0xDCu, 32u
    Opcode.BE64, 0xDCu, 64u
    Opcode.BSWAP16, 0xD7u, 16u
    Opcode.BSWAP32, 0xD7u, 32u
    Opcode.BSWAP64, 0xD7u, 64u ]
  |> List.map (fun (op, code, width) -> Opcode.toString op, swap code width)

/// A jump comparing two registers, or a register and a number written in place
/// of one, and going where it names if they compare as its name says.
let private conditional cls op ins =
  match ins.Operands with
  | [ Rg dst; Rg src; Im target ] ->
    [ word (op ||| SrcReg ||| cls) (gpr dst) (gpr src) (jumpDisp target) 0u ]
  | [ Rg dst; Im value; Im target ] ->
    [ word (op ||| cls) (gpr dst) 0u (jumpDisp target) (imm32 value) ]
  | _ ->
    wrongOperands ins

/// The jumps comparing, each under the name it goes by in each of the two
/// classes.
let conditionalEncoders () =
  [ Opcode.JEQ, Opcode.JEQ32, 0x10u
    Opcode.JGT, Opcode.JGT32, 0x20u
    Opcode.JGE, Opcode.JGE32, 0x30u
    Opcode.JSET, Opcode.JSET32, 0x40u
    Opcode.JNE, Opcode.JNE32, 0x50u
    Opcode.JSGT, Opcode.JSGT32, 0x60u
    Opcode.JSGE, Opcode.JSGE32, 0x70u
    Opcode.JLT, Opcode.JLT32, 0xA0u
    Opcode.JLE, Opcode.JLE32, 0xB0u
    Opcode.JSLT, Opcode.JSLT32, 0xC0u
    Opcode.JSLE, Opcode.JSLE32, 0xD0u ]
  |> List.collect (fun (wide, narrow, op) ->
    [ Opcode.toString wide, conditional ClsJmp op
      Opcode.toString narrow, conditional ClsJmp32 op ])

/// The jump going where it names whatever holds.
let private goto ins =
  match ins.Operands with
  | [ Im target ] -> [ word ClsJmp 0u 0u (jumpDisp target) 0u ]
  | _ -> wrongOperands ins

/// The jump reaching furthest, which counts how far away the place it goes to
/// is where every other instruction holds a number.
let private longGoto ins =
  match ins.Operands with
  | [ Im target ] -> [ word ClsJmp32 0u 0u 0u (longJumpDisp target) ]
  | _ -> wrongOperands ins

/// A call naming what it calls by a number.
let private call src ins =
  match ins.Operands with
  | [ Im value ] -> [ word (0x80u ||| ClsJmp) 0u src 0u (imm32 value) ]
  | _ -> wrongOperands ins

/// A call to a function of this same program, which names how far away that
/// function is rather than naming it by a number.
let private localCall ins =
  match ins.Operands with
  | [ Im target ] ->
    [ word (0x80u ||| ClsJmp) 0u 1u 0u (longJumpDisp target) ]
  | _ ->
    wrongOperands ins

/// The instruction returning to whatever called this.
let private ret ins =
  match ins.Operands with
  | [] -> [ bare (0x90u ||| ClsJmp) ]
  | _ -> wrongOperands ins

/// The jumps going where they name whatever holds, the calls, and the return.
let jumpEncoders () =
  [ Opcode.toString Opcode.JA, goto
    Opcode.toString Opcode.GOTOL, longGoto
    Opcode.toString Opcode.CALL, call 0u
    Opcode.toString Opcode.CALL_LOCAL, localCall
    Opcode.toString Opcode.CALL_KFUNC, call 2u
    Opcode.toString Opcode.EXIT, ret ]

/// The one instruction two words wide, whose source field says what the loader
/// is to put where it carries a quadword. The upper half of that quadword sits
/// in the word after, every other field of which holds zero.
let private wideLoad src ins =
  match ins.Operands with
  | [ Rg dst; Im value ] ->
    [ word 0x18u (gpr dst) src 0u (uint32 value)
      word 0u 0u 0u 0u (uint32 (value >>> 32)) ]
  | _ ->
    wrongOperands ins

/// The instruction carrying a whole quadword, under each of the names saying
/// what the loader is to put there.
let wideLoadEncoders () =
  [ Opcode.LDDW, 0u
    Opcode.LDDW_MAPFD, 1u
    Opcode.LDDW_MAPVAL, 2u
    Opcode.LDDW_BTFID, 3u
    Opcode.LDDW_FUNC, 4u
    Opcode.LDDW_MAPIDX, 5u
    Opcode.LDDW_MAPIDXVAL, 6u ]
  |> List.map (fun (op, src) -> Opcode.toString op, wideLoad src)

/// A read of the packet at the offset it names, what it reads landing in the
/// first register, which it therefore does not name.
let private absoluteLoad code ins =
  match ins.Operands with
  | [ Im value ] -> [ word code 0u 0u 0u (imm32 value) ]
  | _ -> wrongOperands ins

/// A read of the packet, the offset counted from what a register holds.
let private indexedLoad code ins =
  match ins.Operands with
  | [ Rg src; Im value ] -> [ word code 0u (gpr src) 0u (imm32 value) ]
  | _ -> wrongOperands ins

/// The reads of a packet, which are what the classic filters had.
let packetEncoders () =
  [ Opcode.toString Opcode.LDABSB, absoluteLoad (0x10u ||| 0x20u)
    Opcode.toString Opcode.LDABSH, absoluteLoad (0x08u ||| 0x20u)
    Opcode.toString Opcode.LDABSW, absoluteLoad (0x00u ||| 0x20u)
    Opcode.toString Opcode.LDINDB, indexedLoad (0x10u ||| 0x40u)
    Opcode.toString Opcode.LDINDH, indexedLoad (0x08u ||| 0x40u)
    Opcode.toString Opcode.LDINDW, indexedLoad (0x00u ||| 0x40u) ]

/// A load from the memory a register points into.
let private load code ins =
  match ins.Operands with
  | [ Rg dst; Mem(baseReg, disp) ] ->
    [ word code (gpr dst) (gpr baseReg) (memDisp disp) 0u ]
  | _ ->
    wrongOperands ins

/// The loads from the memory a register points into, at every width and in both
/// of the ways they widen what they read.
let loadEncoders () =
  [ Opcode.LDXB, 0x10u ||| 0x60u ||| ClsLdx
    Opcode.LDXH, 0x08u ||| 0x60u ||| ClsLdx
    Opcode.LDXW, 0x00u ||| 0x60u ||| ClsLdx
    Opcode.LDXDW, 0x18u ||| 0x60u ||| ClsLdx
    Opcode.LDXSB, 0x10u ||| 0x80u ||| ClsLdx
    Opcode.LDXSH, 0x08u ||| 0x80u ||| ClsLdx
    Opcode.LDXSW, 0x00u ||| 0x80u ||| ClsLdx ]
  |> List.map (fun (op, code) -> Opcode.toString op, load code)

/// A store of a number written in the instruction itself.
let private immediateStore code ins =
  match ins.Operands with
  | [ Mem(baseReg, disp); Im value ] ->
    [ word code (gpr baseReg) 0u (memDisp disp) (imm32 value) ]
  | _ ->
    wrongOperands ins

/// The stores of a number written in the instruction itself.
let immediateStoreEncoders () =
  [ Opcode.STB, 0x10u ||| 0x60u ||| ClsSt
    Opcode.STH, 0x08u ||| 0x60u ||| ClsSt
    Opcode.STW, 0x00u ||| 0x60u ||| ClsSt
    Opcode.STDW, 0x18u ||| 0x60u ||| ClsSt ]
  |> List.map (fun (op, code) -> Opcode.toString op, immediateStore code)

/// A store of what a register holds, atomic or otherwise, the operation an
/// atomic one performs being held where a number would sit.
let private registerStore code imm ins =
  match ins.Operands with
  | [ Mem(baseReg, disp); Rg src ] ->
    [ word code (gpr baseReg) (gpr src) (memDisp disp) imm ]
  | _ ->
    wrongOperands ins

/// The stores of what a register holds.
let registerStoreEncoders () =
  [ Opcode.STXB, 0x10u ||| 0x60u ||| ClsStx
    Opcode.STXH, 0x08u ||| 0x60u ||| ClsStx
    Opcode.STXW, 0x00u ||| 0x60u ||| ClsStx
    Opcode.STXDW, 0x18u ||| 0x60u ||| ClsStx ]
  |> List.map (fun (op, code) -> Opcode.toString op, registerStore code 0u)

/// The stores reading, computing, and writing back as one, each reaching a word
/// and a quadword.
let atomicEncoders () =
  [ Opcode.ATOMIC_ADD_W, Opcode.ATOMIC_ADD_DW, 0x00u
    Opcode.ATOMIC_FADD_W, Opcode.ATOMIC_FADD_DW, 0x01u
    Opcode.ATOMIC_OR_W, Opcode.ATOMIC_OR_DW, 0x40u
    Opcode.ATOMIC_FOR_W, Opcode.ATOMIC_FOR_DW, 0x41u
    Opcode.ATOMIC_AND_W, Opcode.ATOMIC_AND_DW, 0x50u
    Opcode.ATOMIC_FAND_W, Opcode.ATOMIC_FAND_DW, 0x51u
    Opcode.ATOMIC_XOR_W, Opcode.ATOMIC_XOR_DW, 0xA0u
    Opcode.ATOMIC_FXOR_W, Opcode.ATOMIC_FXOR_DW, 0xA1u
    Opcode.ATOMIC_XCHG_W, Opcode.ATOMIC_XCHG_DW, 0xE1u
    Opcode.ATOMIC_CMPXCHG_W, Opcode.ATOMIC_CMPXCHG_DW, 0xF1u ]
  |> List.collect (fun (narrow, wide, imm) ->
    [ Opcode.toString narrow, registerStore (0xC0u ||| ClsStx) imm
      Opcode.toString wide, registerStore (0x18u ||| 0xC0u ||| ClsStx) imm ])

// vim: set tw=80 sts=2 sw=2:
