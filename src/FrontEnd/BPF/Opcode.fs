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

namespace B2R2.FrontEnd.BPF

open B2R2

/// <summary>
/// Represents an eBPF opcode.
///
/// The machine keeps two arithmetic classes, one computing on the whole of a
/// register and one on its lower half, and the same for the jumps comparing
/// what two registers hold. What tells the halves apart here is a name: the one
/// working on thirty-two bits carries a "32" where the one working on
/// sixty-four carries nothing, which is how the instruction set is written
/// wherever it is written as mnemonics rather than as C.
///
/// The width a load or a store reaches is part of the name for the same reason,
/// and so is which of the atomic operations an atomic store performs, that
/// being held in a field the disassembler would otherwise write as a bare
/// number.
/// </summary>
type Opcode =
  (* Arithmetic on the whole of a register. *)
  /// Adds.
  | ADD = 0
  /// Subtracts.
  | SUB = 1
  /// Multiplies.
  | MUL = 2
  /// Divides, reading both sides as unsigned.
  | DIV = 3
  /// Divides, reading both sides as signed.
  | SDIV = 4
  /// Computes the logical sum.
  | OR = 5
  /// Computes the logical product.
  | AND = 6
  /// Shifts left.
  | LSH = 7
  /// Shifts right, bringing in zeroes.
  | RSH = 8
  /// Negates.
  | NEG = 9
  /// Takes the remainder, reading both sides as unsigned.
  | MOD = 10
  /// Takes the remainder, reading both sides as signed.
  | SMOD = 11
  /// Computes the exclusive sum.
  | XOR = 12
  /// Moves.
  | MOV = 13
  /// Moves, widening the low byte, halfword, or word of the source as signed.
  | MOVSX = 14
  /// Shifts right, bringing in the sign.
  | ARSH = 15
  /// Reverses the bytes of a halfword.
  | BSWAP16 = 16
  /// Reverses the bytes of a word.
  | BSWAP32 = 17
  /// Reverses the bytes of a quadword.
  | BSWAP64 = 18
  (* Arithmetic on the lower half of a register, which clears the upper half. *)
  /// Adds.
  | ADD32 = 19
  /// Subtracts.
  | SUB32 = 20
  /// Multiplies.
  | MUL32 = 21
  /// Divides, reading both sides as unsigned.
  | DIV32 = 22
  /// Divides, reading both sides as signed.
  | SDIV32 = 23
  /// Computes the logical sum.
  | OR32 = 24
  /// Computes the logical product.
  | AND32 = 25
  /// Shifts left.
  | LSH32 = 26
  /// Shifts right, bringing in zeroes.
  | RSH32 = 27
  /// Negates.
  | NEG32 = 28
  /// Takes the remainder, reading both sides as unsigned.
  | MOD32 = 29
  /// Takes the remainder, reading both sides as signed.
  | SMOD32 = 30
  /// Computes the exclusive sum.
  | XOR32 = 31
  /// Moves.
  | MOV32 = 32
  /// Moves, widening the low byte or halfword of the source as signed.
  | MOVSX32 = 33
  /// Shifts right, bringing in the sign.
  | ARSH32 = 34
  /// Writes the low halfword back in little-endian order.
  | LE16 = 35
  /// Writes the low word back in little-endian order.
  | LE32 = 36
  /// Writes the register back in little-endian order.
  | LE64 = 37
  /// Writes the low halfword back in big-endian order.
  | BE16 = 38
  /// Writes the low word back in big-endian order.
  | BE32 = 39
  /// Writes the register back in big-endian order.
  | BE64 = 40
  (* Jumps comparing the whole of what a register holds. *)
  /// Goes where it names, whatever holds.
  | JA = 41
  /// Goes where it names if the two are equal.
  | JEQ = 42
  /// Goes where it names if the first is above, read as unsigned.
  | JGT = 43
  /// Goes where it names if the first is at least, read as unsigned.
  | JGE = 44
  /// Goes where it names if the two have a bit in common.
  | JSET = 45
  /// Goes where it names if the two differ.
  | JNE = 46
  /// Goes where it names if the first is above, read as signed.
  | JSGT = 47
  /// Goes where it names if the first is at least, read as signed.
  | JSGE = 48
  /// Goes where it names if the first is below, read as unsigned.
  | JLT = 49
  /// Goes where it names if the first is at most, read as unsigned.
  | JLE = 50
  /// Goes where it names if the first is below, read as signed.
  | JSLT = 51
  /// Goes where it names if the first is at most, read as signed.
  | JSLE = 52
  /// Calls the helper the kernel numbers.
  | CALL = 53
  /// Calls a function of this same program, naming how far away it is.
  | CALL_LOCAL = 54
  /// Calls a kernel function, naming the type the kernel numbers it by.
  | CALL_KFUNC = 55
  /// Returns to whatever called this.
  | EXIT = 56
  (* Jumps comparing the lower half of what a register holds. *)
  /// Goes where it names, whatever holds, reaching further than JA does.
  | GOTOL = 57
  /// Goes where it names if the two are equal.
  | JEQ32 = 58
  /// Goes where it names if the first is above, read as unsigned.
  | JGT32 = 59
  /// Goes where it names if the first is at least, read as unsigned.
  | JGE32 = 60
  /// Goes where it names if the two have a bit in common.
  | JSET32 = 61
  /// Goes where it names if the two differ.
  | JNE32 = 62
  /// Goes where it names if the first is above, read as signed.
  | JSGT32 = 63
  /// Goes where it names if the first is at least, read as signed.
  | JSGE32 = 64
  /// Goes where it names if the first is below, read as unsigned.
  | JLT32 = 65
  /// Goes where it names if the first is at most, read as unsigned.
  | JLE32 = 66
  /// Goes where it names if the first is below, read as signed.
  | JSLT32 = 67
  /// Goes where it names if the first is at most, read as signed.
  | JSLE32 = 68
  (* The one instruction two words wide, which carries a whole quadword. *)
  /// Loads the quadword written in the instruction itself.
  | LDDW = 69
  /// Loads the address of the map the loader names by descriptor.
  | LDDW_MAPFD = 70
  /// Loads the address of a place inside the map the loader names.
  | LDDW_MAPVAL = 71
  /// Loads the kernel identifier of the type the loader names.
  | LDDW_BTFID = 72
  /// Loads the address of a function of this same program.
  | LDDW_FUNC = 73
  /// Loads the address of the map the loader names by index.
  | LDDW_MAPIDX = 74
  /// Loads the address of a place inside the map the loader names by index.
  | LDDW_MAPIDXVAL = 75
  (* Reads of a packet, which name where in it to read and leave what they read
     in R0. These are what the classic filters had, and nothing but a socket
     filter may use them. *)
  /// Reads a byte of the packet at the offset it names.
  | LDABSB = 76
  /// Reads a halfword of the packet at the offset it names.
  | LDABSH = 77
  /// Reads a word of the packet at the offset it names.
  | LDABSW = 78
  /// Reads a byte of the packet, the offset counted from a register.
  | LDINDB = 79
  /// Reads a halfword of the packet, the offset counted from a register.
  | LDINDH = 80
  /// Reads a word of the packet, the offset counted from a register.
  | LDINDW = 81
  (* Loads from the memory a register points into. *)
  /// Loads a byte, bringing in zeroes.
  | LDXB = 82
  /// Loads a halfword, bringing in zeroes.
  | LDXH = 83
  /// Loads a word, bringing in zeroes.
  | LDXW = 84
  /// Loads a quadword.
  | LDXDW = 85
  /// Loads a byte, bringing in the sign.
  | LDXSB = 86
  /// Loads a halfword, bringing in the sign.
  | LDXSH = 87
  /// Loads a word, bringing in the sign.
  | LDXSW = 88
  (* Stores of a number written in the instruction itself. *)
  /// Stores a byte.
  | STB = 89
  /// Stores a halfword.
  | STH = 90
  /// Stores a word.
  | STW = 91
  /// Stores a quadword.
  | STDW = 92
  (* Stores of what a register holds. *)
  /// Stores a byte.
  | STXB = 93
  /// Stores a halfword.
  | STXH = 94
  /// Stores a word.
  | STXW = 95
  /// Stores a quadword.
  | STXDW = 96
  (* Stores that read, compute, and write back as one, which the encoding says
     by holding the operation where a number would sit. The ones whose name
     carries an "f" leave what they found in the register they read from. *)
  /// Adds a word into memory.
  | ATOMIC_ADD_W = 97
  /// Adds a quadword into memory.
  | ATOMIC_ADD_DW = 98
  /// Adds a word into memory, returning what was there.
  | ATOMIC_FADD_W = 99
  /// Adds a quadword into memory, returning what was there.
  | ATOMIC_FADD_DW = 100
  /// Computes the logical product of a word with memory.
  | ATOMIC_AND_W = 101
  /// Computes the logical product of a quadword with memory.
  | ATOMIC_AND_DW = 102
  /// Computes the logical product of a word with memory, returning what was
  /// there.
  | ATOMIC_FAND_W = 103
  /// Computes the logical product of a quadword with memory, returning what was
  /// there.
  | ATOMIC_FAND_DW = 104
  /// Computes the logical sum of a word with memory.
  | ATOMIC_OR_W = 105
  /// Computes the logical sum of a quadword with memory.
  | ATOMIC_OR_DW = 106
  /// Computes the logical sum of a word with memory, returning what was there.
  | ATOMIC_FOR_W = 107
  /// Computes the logical sum of a quadword with memory, returning what was
  /// there.
  | ATOMIC_FOR_DW = 108
  /// Computes the exclusive sum of a word with memory.
  | ATOMIC_XOR_W = 109
  /// Computes the exclusive sum of a quadword with memory.
  | ATOMIC_XOR_DW = 110
  /// Computes the exclusive sum of a word with memory, returning what was
  /// there.
  | ATOMIC_FXOR_W = 111
  /// Computes the exclusive sum of a quadword with memory, returning what was
  /// there.
  | ATOMIC_FXOR_DW = 112
  /// Swaps a word with memory.
  | ATOMIC_XCHG_W = 113
  /// Swaps a quadword with memory.
  | ATOMIC_XCHG_DW = 114
  /// Swaps a word with memory if what is there is what R0 holds.
  | ATOMIC_CMPXCHG_W = 115
  /// Swaps a quadword with memory if what is there is what R0 holds.
  | ATOMIC_CMPXCHG_DW = 116

/// Provides functions to handle eBPF opcodes.
[<RequireQualifiedAccess>]
module Opcode =
  /// <summary>
  /// Returns the mnemonic an eBPF opcode is written as.
  ///
  /// This is the one place a mnemonic is spelled, so that what the assembler
  /// reads cannot drift from what the disassembler writes: the assembler builds
  /// its vocabulary out of this rather than out of a list of its own.
  /// </summary>
  [<CompiledName "ToString">]
  let toString opcode =
    match opcode with
    | Opcode.ADD -> "add"
    | Opcode.SUB -> "sub"
    | Opcode.MUL -> "mul"
    | Opcode.DIV -> "div"
    | Opcode.SDIV -> "sdiv"
    | Opcode.OR -> "or"
    | Opcode.AND -> "and"
    | Opcode.LSH -> "lsh"
    | Opcode.RSH -> "rsh"
    | Opcode.NEG -> "neg"
    | Opcode.MOD -> "mod"
    | Opcode.SMOD -> "smod"
    | Opcode.XOR -> "xor"
    | Opcode.MOV -> "mov"
    | Opcode.MOVSX -> "movsx"
    | Opcode.ARSH -> "arsh"
    | Opcode.BSWAP16 -> "bswap16"
    | Opcode.BSWAP32 -> "bswap32"
    | Opcode.BSWAP64 -> "bswap64"
    | Opcode.ADD32 -> "add32"
    | Opcode.SUB32 -> "sub32"
    | Opcode.MUL32 -> "mul32"
    | Opcode.DIV32 -> "div32"
    | Opcode.SDIV32 -> "sdiv32"
    | Opcode.OR32 -> "or32"
    | Opcode.AND32 -> "and32"
    | Opcode.LSH32 -> "lsh32"
    | Opcode.RSH32 -> "rsh32"
    | Opcode.NEG32 -> "neg32"
    | Opcode.MOD32 -> "mod32"
    | Opcode.SMOD32 -> "smod32"
    | Opcode.XOR32 -> "xor32"
    | Opcode.MOV32 -> "mov32"
    | Opcode.MOVSX32 -> "movsx32"
    | Opcode.ARSH32 -> "arsh32"
    | Opcode.LE16 -> "le16"
    | Opcode.LE32 -> "le32"
    | Opcode.LE64 -> "le64"
    | Opcode.BE16 -> "be16"
    | Opcode.BE32 -> "be32"
    | Opcode.BE64 -> "be64"
    | Opcode.JA -> "ja"
    | Opcode.JEQ -> "jeq"
    | Opcode.JGT -> "jgt"
    | Opcode.JGE -> "jge"
    | Opcode.JSET -> "jset"
    | Opcode.JNE -> "jne"
    | Opcode.JSGT -> "jsgt"
    | Opcode.JSGE -> "jsge"
    | Opcode.JLT -> "jlt"
    | Opcode.JLE -> "jle"
    | Opcode.JSLT -> "jslt"
    | Opcode.JSLE -> "jsle"
    | Opcode.CALL -> "call"
    | Opcode.CALL_LOCAL -> "call_local"
    | Opcode.CALL_KFUNC -> "call_kfunc"
    | Opcode.EXIT -> "exit"
    | Opcode.GOTOL -> "gotol"
    | Opcode.JEQ32 -> "jeq32"
    | Opcode.JGT32 -> "jgt32"
    | Opcode.JGE32 -> "jge32"
    | Opcode.JSET32 -> "jset32"
    | Opcode.JNE32 -> "jne32"
    | Opcode.JSGT32 -> "jsgt32"
    | Opcode.JSGE32 -> "jsge32"
    | Opcode.JLT32 -> "jlt32"
    | Opcode.JLE32 -> "jle32"
    | Opcode.JSLT32 -> "jslt32"
    | Opcode.JSLE32 -> "jsle32"
    | Opcode.LDDW -> "lddw"
    | Opcode.LDDW_MAPFD -> "lddw_mapfd"
    | Opcode.LDDW_MAPVAL -> "lddw_mapval"
    | Opcode.LDDW_BTFID -> "lddw_btfid"
    | Opcode.LDDW_FUNC -> "lddw_func"
    | Opcode.LDDW_MAPIDX -> "lddw_mapidx"
    | Opcode.LDDW_MAPIDXVAL -> "lddw_mapidxval"
    | Opcode.LDABSB -> "ldabsb"
    | Opcode.LDABSH -> "ldabsh"
    | Opcode.LDABSW -> "ldabsw"
    | Opcode.LDINDB -> "ldindb"
    | Opcode.LDINDH -> "ldindh"
    | Opcode.LDINDW -> "ldindw"
    | Opcode.LDXB -> "ldxb"
    | Opcode.LDXH -> "ldxh"
    | Opcode.LDXW -> "ldxw"
    | Opcode.LDXDW -> "ldxdw"
    | Opcode.LDXSB -> "ldxsb"
    | Opcode.LDXSH -> "ldxsh"
    | Opcode.LDXSW -> "ldxsw"
    | Opcode.STB -> "stb"
    | Opcode.STH -> "sth"
    | Opcode.STW -> "stw"
    | Opcode.STDW -> "stdw"
    | Opcode.STXB -> "stxb"
    | Opcode.STXH -> "stxh"
    | Opcode.STXW -> "stxw"
    | Opcode.STXDW -> "stxdw"
    | Opcode.ATOMIC_ADD_W -> "atomic_add_w"
    | Opcode.ATOMIC_ADD_DW -> "atomic_add_dw"
    | Opcode.ATOMIC_FADD_W -> "atomic_fadd_w"
    | Opcode.ATOMIC_FADD_DW -> "atomic_fadd_dw"
    | Opcode.ATOMIC_AND_W -> "atomic_and_w"
    | Opcode.ATOMIC_AND_DW -> "atomic_and_dw"
    | Opcode.ATOMIC_FAND_W -> "atomic_fand_w"
    | Opcode.ATOMIC_FAND_DW -> "atomic_fand_dw"
    | Opcode.ATOMIC_OR_W -> "atomic_or_w"
    | Opcode.ATOMIC_OR_DW -> "atomic_or_dw"
    | Opcode.ATOMIC_FOR_W -> "atomic_for_w"
    | Opcode.ATOMIC_FOR_DW -> "atomic_for_dw"
    | Opcode.ATOMIC_XOR_W -> "atomic_xor_w"
    | Opcode.ATOMIC_XOR_DW -> "atomic_xor_dw"
    | Opcode.ATOMIC_FXOR_W -> "atomic_fxor_w"
    | Opcode.ATOMIC_FXOR_DW -> "atomic_fxor_dw"
    | Opcode.ATOMIC_XCHG_W -> "atomic_xchg_w"
    | Opcode.ATOMIC_XCHG_DW -> "atomic_xchg_dw"
    | Opcode.ATOMIC_CMPXCHG_W -> "atomic_cmpxchg_w"
    | Opcode.ATOMIC_CMPXCHG_DW -> "atomic_cmpxchg_dw"
    | _ -> Terminator.impossible ()

// vim: set tw=80 sts=2 sw=2:
