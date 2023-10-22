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

namespace B2R2.FrontEnd

open B2R2
open B2R2.BinIR
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter

/// The main handle for reading/parsing a binary code. `BinHandle` essentially
/// provides an interface for a chunk of binary code for parsing instructions,
/// lifting instructions, or reading data from it.
type BinHandle =
  /// Construct a BinHandle from a given file path, ISA, optional base
  /// address (baseAddrOpt), and ArchOperationMode. File format will be
  /// automatically detected.
  new: path: string
     * isa: ISA
     * baseAddrOpt: Addr option
     * mode: ArchOperationMode
    -> BinHandle

  /// Construct a BinHandle from a given file path, ISA, and optional base
  /// address (baseAddrOpt). ArchOperationMode is set to NoMode.
  new: path: string * isa: ISA * baseAddrOpt: Addr option -> BinHandle

  /// Construct a BinHandle from a given file path and ISA. ArchOperationMode
  /// is set to NoMode.
  new: path: string * isa: ISA -> BinHandle

  /// Construct a BinHandle from a given byte array. File format detection is
  /// performed only if detectFormat is set to true.
  new: bytes: byte[]
     * isa: ISA
     * baseAddrOpt: Addr option
     * detectFormat: bool
    -> BinHandle

  /// Construct an empty BinHandle.
  new: isa: ISA -> BinHandle

  /// File handle.
  member File: IBinFile

  /// Disassembly helper.
  member DisasmHelper: DisasmHelper

  /// Translation context.
  member TranslationContext: TranslationContext

  /// Parser.
  member Parser: IInstructionParsable

  /// Register bay.
  member RegisterBay: RegisterBay

  /// <summary>
  ///   Return the byte array of size (nBytes) located at the address (addr).
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <param name="nBytes">The size of the byte array (in bytes).</param>
  /// <returns>
  ///   Return (byte[]) if succeeded, (ErrorCase) otherwise.
  /// </returns>
  member TryReadBytes:
    addr: Addr * nBytes: int -> Result<byte [], ErrorCase>

  /// <summary>
  ///   Return the byte array of size (nBytes) pointed to by the pointer (ptr).
  /// </summary>
  /// <param name="ptr">The binary pointer.</param>
  /// <param name="nBytes">The size of the byte array (in bytes).</param>
  /// <returns>
  ///   Return (byte[]) if succeeded, (ErrorCase) otherwise.
  /// </returns>
  member TryReadBytes:
    ptr: BinFilePointer * nBytes: int -> Result<byte [], ErrorCase>

  /// <summary>
  ///   Return the byte array of size (nBytes) at the addr from the current
  ///   binary.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <param name="nBytes">The size of the byte array (in bytes).</param>
  /// <returns>
  ///   Return the byte array if succeed. Otherwise, raise an exception.
  /// </returns>
  member ReadBytes: addr: Addr * nBytes: int -> byte []

  /// <summary>
  ///   Return the byte array of size (nBytes) pointed to by the binary file
  ///   pointer (ptr).
  /// </summary>
  /// <param name="ptr">BInaryPointer.</param>
  /// <param name="nBytes">The size of the byte array (in bytes).</param>
  /// <returns>
  ///   Return the byte array if succeed. Otherwise, raise an exception.
  /// </returns>
  member ReadBytes: ptr: BinFilePointer * nBytes: int -> byte []

  /// <summary>
  ///   Return the corresponding integer of the size from the given address.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding value (int64) if the address and the size is
  ///   valid. Otherwise ErrorCase.
  /// </returns>
  member TryReadInt:
    addr: Addr * size: int -> Result<int64, ErrorCase>

  /// <summary>
  ///   Return the corresponding integer of the size from the given address
  ///   pointed to by the binary pointer (ptr).
  /// </summary>
  /// <param name="ptr">BinFilePointer.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding value (int64) if the address and the size is
  ///   valid. Otherwise ErrorCase.
  /// </returns>
  member TryReadInt:
    ptr: BinFilePointer * size: int -> Result<int64, ErrorCase>

  /// <summary>
  ///   Return the corresponding integer value at the addr of the size from the
  ///   current binary.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding integer (int64).
  /// </returns>
  member ReadInt: addr: Addr * size: int -> int64

  /// <summary>
  ///   Return the corresponding integer value of the size from the current
  ///   binary, which is pointed to by the binary file pointer (ptr).
  /// </summary>
  /// <param name="ptr">The binary pointer.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding integer (int64).
  /// </returns>
  member ReadInt: ptr: BinFilePointer * size: int -> int64

  /// <summary>
  ///   Return the corresponding unsigned integer of the size from the given
  ///   address.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding unsigned integer (uint64) if the address and
  ///   the size is valid. Otherwise, ErrorCase.
  /// </returns>
  member TryReadUInt:
    addr: Addr * size: int -> Result<uint64, ErrorCase>

  /// <summary>
  ///   Return the corresponding unsigned integer of the size from the address
  ///   pointed to by the binary file pointer (ptr).
  /// </summary>
  /// <param name="ptr">BinFilePointer.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding unsigned integer (uint64) if the address and
  ///   the size is valid. Otherwise, ErrorCase.
  /// </returns>
  member TryReadUInt:
    ptr: BinFilePointer * size: int -> Result<uint64, ErrorCase>

  /// <summary>
  ///   Return the corresponding unsigned integer value at the addr of the size
  ///   from the binary.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding unsigned integer (uint64).
  /// </returns>
  member ReadUInt: addr: Addr * size: int -> uint64

  /// <summary>
  ///   Return the corresponding unsigned integer value of the size from the
  ///   binary, which is pointed to by the binary file pointer (ptr).
  /// </summary>
  /// <param name="ptr">BinFilePointer.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding unsigned integer (uint64).
  /// </returns>
  member ReadUInt: ptr: BinFilePointer * size: int -> uint64

  /// <summary>
  ///   Return the ASCII string at the addr from the given BinHandle.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <returns>
  ///   Return the corresponding ASCII string.
  /// </returns>
  member ReadASCII: addr: Addr -> string

  /// <summary>
  ///   Return the ASCII string pointed to by the binary file pointer from the
  ///   given BinHandle.
  /// </summary>
  /// <param name="ptr">BinFilePointer.</param>
  /// <returns>
  ///   Return the corresponding ASCII string.
  /// </returns>
  member ReadASCII: ptr: BinFilePointer -> string

  /// <summary>
  ///   Parse one instruction at the given address (addr), and return the
  ///   corresponding instruction. This function raises an exception if the
  ///   parsing process fails.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <returns>
  ///   Parsed instruction.
  /// </returns>
  member ParseInstr: addr: Addr -> Instruction

  /// <summary>
  ///   Parse one instruction pointed to by the binary file pointer (ptr), and
  ///   return the corresponding instruction. This function raises an exception
  ///   if the parsing process fails.
  /// </summary>
  /// <param name="ptr">BinFilePointer.</param>
  /// <returns>
  ///   Parsed instruction.
  /// </returns>
  member ParseInstr: ptr: BinFilePointer -> Instruction

  /// <summary>
  ///   Parse one instruction at the given address (addr), and return the
  ///   corresponding instruction.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <returns>
  ///   Parsed instruction if succeeded, ErrorCase if otherwise.
  /// </returns>
  member TryParseInstr: addr: Addr -> Result<Instruction, ErrorCase>

  /// <summary>
  ///   Parse one instruction pointed to by the binary file pointer (ptr), and
  ///   return the corresponding instruction.
  /// </summary>
  /// <param name="ptr">BinFilePointer.</param>
  /// <returns>
  ///   Parsed instruction if succeeded, ErrorCase if otherwise.
  /// </returns>
  member TryParseInstr: ptr: BinFilePointer -> Result<Instruction, ErrorCase>

  /// Parse a basic block from the given address, and return the sequence of the
  /// instructions of the basic block. This function may return an incomplete
  /// basic block as an Error type. This function can be safely used for any
  /// ISAs, and thus, this should be the main parsing function.
  member ParseBBlock:
    addr: Addr -> Result<Instruction list, Instruction list>

  /// Parse a basic block pointed to by the binary file pointer (ptr), and
  /// return the sequence of the instructions of the basic block. This function
  /// may return an incomplete basic block as an Error type. This function can
  /// be safely used for any ISAs, and thus, this should be the main parsing
  /// function.
  member ParseBBlock:
    ptr: BinFilePointer -> Result<Instruction list, Instruction list>

  /// Lift an instruction located at the given address to produce an array of IR
  /// statements.
  member LiftInstr: addr: Addr -> LowUIR.Stmt []

  /// Lift an instruction pointed to by the given binary file pointer to produce
  /// an array of IR statements.
  member LiftInstr: ptr: BinFilePointer -> LowUIR.Stmt []

  /// Lift the given instruction to produce an array of IR statements.
  member LiftInstr: ins: Instruction -> LowUIR.Stmt []

  /// Lift an instruction located at the given address to produce an array of
  /// optimized IR statements.
  member LiftOptimizedInstr: addr: Addr -> LowUIR.Stmt []

  /// Lift an instruction pointed to by the given binary file pointer to produce
  /// an array of optimized IR statements.
  member LiftOptimizedInstr: ptr: BinFilePointer -> LowUIR.Stmt []

  /// Lift a parsed instruction (Instruction) to produce an array of optimized
  /// IR statements from a given BinHandle.
  member LiftOptimizedInstr: ins: Instruction -> LowUIR.Stmt []

  /// Return the lifted IR (an array of statements) of a basic block at the
  /// given address. This function returns a partial bblock with Error, if the
  /// parsing of the bblock was not successful.
  member LiftBBlock:
    addr: Addr -> Result<(LowUIR.Stmt [] * Addr), (LowUIR.Stmt [] * Addr)>

  /// Return the lifted IR (an array of statements) of a basic block pointed to
  /// by the binary file pointer (ptr). This function returns a partial bblock
  /// with Error, if the parsing of the bblock was not successful.
  member LiftBBlock:
       ptr: BinFilePointer
    -> Result<(LowUIR.Stmt [] * BinFilePointer),
              (LowUIR.Stmt [] * BinFilePointer)>

  /// Return a disassembled string of an instruction located at the given
  /// address. The disassembled string contains the instruction address and
  /// symbols if the corresponding options are set to true.
  member DisasmInstr:
    addr: Addr * showAddr: bool * resolveSymbol: bool -> string

  /// Return a disassembled string of an instruction pointed to by the binary
  /// file pointer. The disassembled string contains the instruction address and
  /// symbols if the corresponding options are set to true.
  member DisasmInstr:
    ptr: BinFilePointer * showAddr: bool * resolveSymbol: bool -> string

  /// Return a disassembled string of the given instruction. The disassembled
  /// string contains the instruction address and symbols if the corresponding
  /// options are set to true.
  member DisasmInstr:
    ins: Instruction * showAddr: bool * resolveSymbol: bool -> string

  /// Return a disassembled string of an instruction located at the given
  /// address without the instruction address nor symbols.
  member DisasmInstr: addr: Addr -> string

  /// Return a disassembled string of an instruction pointed to by the binary
  /// file pointer without the instruction address nor symbols.
  member DisasmInstr: ptr: BinFilePointer -> string

  /// Return a disassembled string of the given instruction without the
  /// instruction address nor symbols.
  member inline DisasmInstr: ins: Instruction -> string

  /// Return the disassembled string for a basic block starting at the given
  /// address along with the fall-through address of the block. This function
  /// returns a partial disassembly if parsing of the bblock was not successful.
  member DisasmBBlock:
       addr: Addr
     * showAddr:bool
     * resolveSymbol: bool
    -> Result<(string * Addr), (string * Addr)>

  /// Return the disassembled string for a basic block starting at address
  /// pointed to by the binary pointer (ptr) along with the fall-through address
  /// of the block. This function returns a partial disassembly if parsing of
  /// the bblock was not successful.
  member DisasmBBlock:
       ptr: BinFilePointer
     * showAddr:bool
     * resolveSymbol: bool
    -> Result<(string * BinFilePointer),
              (string * BinFilePointer)>
