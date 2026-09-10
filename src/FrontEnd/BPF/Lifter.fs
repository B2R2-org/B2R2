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
/// Chooses the lifter that each eBPF opcode is translated by.
///
/// The width each one is given is the one its class computes in: a quadword
/// for the names carrying no "32" and a word for the ones that do, which is
/// the whole of the difference between the two arithmetic classes and between
/// the two classes of conditional jump. The loads, the stores and the atomic
/// stores are given the width of the memory they reach in the same way.
/// </summary>
module internal B2R2.FrontEnd.BPF.Lifter

open B2R2
open B2R2.FrontEnd.BPF.GeneralLifter

/// Translates an eBPF instruction into its LowUIR statements.
let translate (ins: Instruction) bld =
  match ins.Opcode with
  (* Arithmetic on the whole of a register. *)
  | Opcode.ADD -> add ins bld 64<rt>
  | Opcode.SUB -> sub ins bld 64<rt>
  | Opcode.MUL -> mul ins bld 64<rt>
  | Opcode.DIV -> div ins bld 64<rt>
  | Opcode.SDIV -> sdiv ins bld 64<rt>
  | Opcode.OR -> logicOr ins bld 64<rt>
  | Opcode.AND -> logicAnd ins bld 64<rt>
  | Opcode.LSH -> lsh ins bld 64<rt>
  | Opcode.RSH -> rsh ins bld 64<rt>
  | Opcode.NEG -> neg ins bld 64<rt>
  | Opcode.MOD -> modulo ins bld 64<rt>
  | Opcode.SMOD -> smod ins bld 64<rt>
  | Opcode.XOR -> logicXor ins bld 64<rt>
  | Opcode.MOV -> mov ins bld 64<rt>
  | Opcode.MOVSX -> movsx ins bld 64<rt>
  | Opcode.ARSH -> arsh ins bld 64<rt>
  | Opcode.BSWAP16 -> bswap ins bld 16<rt>
  | Opcode.BSWAP32 -> bswap ins bld 32<rt>
  | Opcode.BSWAP64 -> bswap ins bld 64<rt>
  (* Arithmetic on the lower half of a register. *)
  | Opcode.ADD32 -> add ins bld 32<rt>
  | Opcode.SUB32 -> sub ins bld 32<rt>
  | Opcode.MUL32 -> mul ins bld 32<rt>
  | Opcode.DIV32 -> div ins bld 32<rt>
  | Opcode.SDIV32 -> sdiv ins bld 32<rt>
  | Opcode.OR32 -> logicOr ins bld 32<rt>
  | Opcode.AND32 -> logicAnd ins bld 32<rt>
  | Opcode.LSH32 -> lsh ins bld 32<rt>
  | Opcode.RSH32 -> rsh ins bld 32<rt>
  | Opcode.NEG32 -> neg ins bld 32<rt>
  | Opcode.MOD32 -> modulo ins bld 32<rt>
  | Opcode.SMOD32 -> smod ins bld 32<rt>
  | Opcode.XOR32 -> logicXor ins bld 32<rt>
  | Opcode.MOV32 -> mov ins bld 32<rt>
  | Opcode.MOVSX32 -> movsx ins bld 32<rt>
  | Opcode.ARSH32 -> arsh ins bld 32<rt>
  | Opcode.LE16 -> toLittle ins bld 16<rt>
  | Opcode.LE32 -> toLittle ins bld 32<rt>
  | Opcode.LE64 -> toLittle ins bld 64<rt>
  | Opcode.BE16 -> toBig ins bld 16<rt>
  | Opcode.BE32 -> toBig ins bld 32<rt>
  | Opcode.BE64 -> toBig ins bld 64<rt>
  (* Jumps comparing the whole of what a register holds, and the call and the
     return, which are kept among them. *)
  | Opcode.JA -> goto ins bld
  | Opcode.JEQ -> jeq ins bld 64<rt>
  | Opcode.JGT -> jgt ins bld 64<rt>
  | Opcode.JGE -> jge ins bld 64<rt>
  | Opcode.JSET -> jset ins bld 64<rt>
  | Opcode.JNE -> jne ins bld 64<rt>
  | Opcode.JSGT -> jsgt ins bld 64<rt>
  | Opcode.JSGE -> jsge ins bld 64<rt>
  | Opcode.JLT -> jlt ins bld 64<rt>
  | Opcode.JLE -> jle ins bld 64<rt>
  | Opcode.JSLT -> jslt ins bld 64<rt>
  | Opcode.JSLE -> jsle ins bld 64<rt>
  | Opcode.CALL -> callHelper ins bld
  | Opcode.CALL_LOCAL -> callLocal ins bld
  | Opcode.EXIT -> exitProgram ins bld
  (* Jumps comparing the lower half of what a register holds. *)
  | Opcode.GOTOL -> goto ins bld
  | Opcode.JEQ32 -> jeq ins bld 32<rt>
  | Opcode.JGT32 -> jgt ins bld 32<rt>
  | Opcode.JGE32 -> jge ins bld 32<rt>
  | Opcode.JSET32 -> jset ins bld 32<rt>
  | Opcode.JNE32 -> jne ins bld 32<rt>
  | Opcode.JSGT32 -> jsgt ins bld 32<rt>
  | Opcode.JSGE32 -> jsge ins bld 32<rt>
  | Opcode.JLT32 -> jlt ins bld 32<rt>
  | Opcode.JLE32 -> jle ins bld 32<rt>
  | Opcode.JSLT32 -> jslt ins bld 32<rt>
  | Opcode.JSLE32 -> jsle ins bld 32<rt>
  (* The instruction carrying a whole quadword. *)
  | Opcode.LDDW -> lddw ins bld
  (* Loads from the memory a register points into. *)
  | Opcode.LDXB -> ldxu ins bld 8<rt>
  | Opcode.LDXH -> ldxu ins bld 16<rt>
  | Opcode.LDXW -> ldxu ins bld 32<rt>
  | Opcode.LDXDW -> ldxu ins bld 64<rt>
  | Opcode.LDXSB -> ldxs ins bld 8<rt>
  | Opcode.LDXSH -> ldxs ins bld 16<rt>
  | Opcode.LDXSW -> ldxs ins bld 32<rt>
  (* Stores of a number written in the instruction itself. *)
  | Opcode.STB -> stImm ins bld 8<rt>
  | Opcode.STH -> stImm ins bld 16<rt>
  | Opcode.STW -> stImm ins bld 32<rt>
  | Opcode.STDW -> stImm ins bld 64<rt>
  (* Stores of what a register holds. *)
  | Opcode.STXB -> stxReg ins bld 8<rt>
  | Opcode.STXH -> stxReg ins bld 16<rt>
  | Opcode.STXW -> stxReg ins bld 32<rt>
  | Opcode.STXDW -> stxReg ins bld 64<rt>
  (* Stores that read, compute, and write back as one. *)
  | Opcode.ATOMIC_ADD_W -> atomicAdd ins bld 32<rt>
  | Opcode.ATOMIC_ADD_DW -> atomicAdd ins bld 64<rt>
  | Opcode.ATOMIC_FADD_W -> atomicFetchAdd ins bld 32<rt>
  | Opcode.ATOMIC_FADD_DW -> atomicFetchAdd ins bld 64<rt>
  | Opcode.ATOMIC_AND_W -> atomicAnd ins bld 32<rt>
  | Opcode.ATOMIC_AND_DW -> atomicAnd ins bld 64<rt>
  | Opcode.ATOMIC_FAND_W -> atomicFetchAnd ins bld 32<rt>
  | Opcode.ATOMIC_FAND_DW -> atomicFetchAnd ins bld 64<rt>
  | Opcode.ATOMIC_OR_W -> atomicOr ins bld 32<rt>
  | Opcode.ATOMIC_OR_DW -> atomicOr ins bld 64<rt>
  | Opcode.ATOMIC_FOR_W -> atomicFetchOr ins bld 32<rt>
  | Opcode.ATOMIC_FOR_DW -> atomicFetchOr ins bld 64<rt>
  | Opcode.ATOMIC_XOR_W -> atomicXor ins bld 32<rt>
  | Opcode.ATOMIC_XOR_DW -> atomicXor ins bld 64<rt>
  | Opcode.ATOMIC_FXOR_W -> atomicFetchXor ins bld 32<rt>
  | Opcode.ATOMIC_FXOR_DW -> atomicFetchXor ins bld 64<rt>
  | Opcode.ATOMIC_XCHG_W -> atomicXchg ins bld 32<rt>
  | Opcode.ATOMIC_XCHG_DW -> atomicXchg ins bld 64<rt>
  | Opcode.ATOMIC_CMPXCHG_W -> atomicCas ins bld 32<rt>
  | Opcode.ATOMIC_CMPXCHG_DW -> atomicCas ins bld 64<rt>
  (* What needs the platform the program was loaded by rather than the
     program's own state: a call into a kernel named by a type identifier, a
     number a loader was to have replaced with an address, and the reads of a
     packet the classic filters had. *)
  | Opcode.CALL_KFUNC
  | Opcode.LDDW_MAPFD
  | Opcode.LDDW_MAPVAL
  | Opcode.LDDW_BTFID
  | Opcode.LDDW_FUNC
  | Opcode.LDDW_MAPIDX
  | Opcode.LDDW_MAPIDXVAL
  | Opcode.LDABSB
  | Opcode.LDABSH
  | Opcode.LDABSW
  | Opcode.LDINDB
  | Opcode.LDINDH
  | Opcode.LDINDW -> unsupported ins bld
  | _ -> Terminator.impossible ()

// vim: set tw=80 sts=2 sw=2:
