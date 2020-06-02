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

open System.Threading.Tasks
open B2R2
open B2R2.BinFile
open B2R2.BinIR

/// The main handler for reading/parsing a binary code. BinHandler essentially
/// represents a chunk of binary code either from a string or from an actual
/// binary file.
type BinHandler = {
  ISA: ISA
  FileInfo: FileInfo
  ParsingContext: ParsingContext
  TranslationContext: TranslationContext
  Parser: Parser
  RegisterBay: RegisterBay
}
with
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
  ///   Return the ASCII string at the addr from the given BinHandler.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <returns>
  ///   Return the corresponding ASCII string.
  /// </returns>
  member ReadASCII: addr: Addr -> string

  /// <summary>
  ///   Initialize a BInHnalder from a given binary byte sequence. This function
  ///   will read the byte sequence and automatically detect its binary format
  ///   if autoDetect is true. Otherwise, it will consider the given binary
  ///   sequence as a raw binary (just a series of machine instructions without
  ///   specific file format).
  /// </summary>
  /// <param name="isa">ISA.</param>
  /// <param name="archMode">ArchOperatinoMode.</param>
  /// <param name="autoDetect">Perform auto format detection or not.</param>
  /// <param name="baseAddr">Base address for calculating instruction
  /// addresses.</param>
  /// <param name="bytes">Raw binary sequence.</param>
  /// <returns>BinHandler.</returns>
  static member Init:
      isa: ISA
    * archMode: ArchOperationMode
    * autoDetect: bool
    * baseAddr: Addr
    * bytes: byte []
    -> BinHandler

  /// <summary>
  ///   Initialize a BinHandler from a given binary file (fileName). This
  ///   function will read the file and parse it. It will automatically detect
  ///   the file format if autoDetect is true. Otherwise, it will cnosider the
  ///   file as a raw binary.
  /// </summary>
  /// <param name="isa">ISA.</param>
  /// <param name="archMode">ArchOperatinoMode.</param>
  /// <param name="autoDetect">Whether to perform auto format detection.</param>
  /// <param name="baseAddr">Base address for calculating instruction
  /// addresses.</param>
  /// <param name="fileName">Binary file.</param>
  /// <returns>BinHandler.</returns>
  static member Init:
      isa: ISA
    * archMode: ArchOperationMode
    * autoDetect: bool
    * baseAddr: Addr
    * fileName: string
    -> BinHandler

  /// <summary>
  ///   Initialize a BinHandler from an ISA and a binary file path, assuming
  ///   that the archMode is NoMode. This function behaves the same as the
  ///   2-argument constructor Init (isa, fileName), with a difference of using
  ///   the specified base address when initializing the BinHandler.
  /// </summary>
  /// <param name="isa">ISA.</param>
  /// <param name="baseAddr">Base address.</param>
  /// <param name="fileName">Binary file path.</param>
  /// <returns>BinHandler.</returns>
  static member Init: isa: ISA * baseAddr: Addr * fileName: string -> BinHandler

  /// <summary>
  ///   Initialize a BinHandler from an ISA and a byte sequence, assuming that
  ///   the archMode is NoMode. This function behaves the same as the 2-argument
  ///   constructor Init (isa, bytes), with a difference of using the specified
  ///   base address when initializing the BinHandler.
  /// </summary>
  /// <param name="isa">ISA.</param>
  /// <param name="baseAddr">Base address.</param>
  /// <param name="bytes">Byte sequence.</param>
  /// <returns>BinHandler.</returns>
  static member Init: isa: ISA * baseAddr: Addr * bytes: byte [] -> BinHandler

  /// <summary>
  ///   Initialize a BinHandler from an ISA and a binary file path, assuming
  ///   that the archMode is NoMode. B2R2 will automatically detect the file
  ///   format of the given binary file, but it will refer to the given ISA
  ///   parameter either when the binary has multiple architectures, e.g., a fat
  ///   binary on macOS, or when B2R2 cannot recognize the given file format. If
  ///   the given binary file does not follow the known formats, then B2R2
  ///   consider it as a raw binary with base address at 0.
  /// </summary>
  /// <param name="isa">ISA.</param>
  /// <param name="fileName">Binary file path.</param>
  /// <returns>BinHandler.</returns>
  static member Init: isa: ISA * fileName: string -> BinHandler

  /// <summary>
  ///   Initialize a BinHandler from an ISA and a byte sequence, assuming that
  ///   the archMode is NoMode, and the format is RawBinary.
  /// </summary>
  /// <param name="isa">ISA.</param>
  /// <param name="bytes">Byte sequence.</param>
  /// <returns>BinHandler.</returns>
  static member Init: isa: ISA * bytes: byte [] -> BinHandler

  /// <summary>
  ///   Initialize an empty BinHandler. This function is useful when you want to
  ///   delay loading the actual body of your binary blob.
  /// </summary>
  /// <param name="isa">ISA.</param>
  /// <param name="archMode">ArchOperatinoMode.</param>
  /// <returns>BinHandler.</returns>
  static member Init:
      isa: ISA
    * archMode: ArchOperationMode
    -> BinHandler

  /// <summary>
  ///   Initialize an empty BinHandler solely from an ISA, assuming that the
  ///   archMode is NoMode, and the format is RawBinary. This function is useful
  ///   when you want to delay loading the actual body of your binary blob.
  /// </summary>
  /// <param name="isa">ISA.</param>
  /// <returns>BinHandler.</returns>
  static member Init: isa: ISA -> BinHandler

  /// <summary>
  ///   Update BinHandler to have new code at a new address (addr). BinHandler
  ///   is immutable.
  /// </summary>
  /// <param name="handler">The new address to use.</param>
  /// <param name="addr">The new address to use.</param>
  /// <param name="bs">The new address to use.</param>
  /// <returns>New BinHandler.</returns>
  static member UpdateCode:
    handler: BinHandler -> addr: Addr -> bs: byte [] -> BinHandler

  /// <summary>
  ///   Return the byte array of size (nBytes) at the addr from the given
  ///   BinHandler. The return value is an option type. When the given address
  ///   is invalid, this function returns None.
  /// </summary>
  /// <param name="handler">BinHandler.</param>
  /// <param name="addr">The address.</param>
  /// <param name="nBytes">The size of the byte array (in bytes).</param>
  /// <returns>
  ///   Return (Some bytes) if succeeded, (None) otherwise.
  /// </returns>
  static member TryReadBytes:
    handler: BinHandler * addr: Addr * nBytes: int -> byte [] option

  /// <summary>
  ///   Return the byte array of size (nBytes) at the addr from the given
  ///   BinHandler.
  /// </summary>
  /// <param name="handler">BinHandler.</param>
  /// <param name="addr">The address.</param>
  /// <param name="nBytes">The size of the byte array (in bytes).</param>
  /// <returns>
  ///   Return the byte array if succeed. Otherwise, raise an exception.
  /// </returns>
  static member ReadBytes:
    handler: BinHandler * addr: Addr * nBytes: int -> byte []

  /// <summary>
  ///   Return the corresponding integer option value at the addr of the size
  ///   from the given BinHandler.
  /// </summary>
  /// <param name="handler">BinHandler.</param>
  /// <param name="addr">The address.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding value (Some int64) if the address and the size
  ///   is valid. Otherwise None.
  /// </returns>
  static member TryReadInt:
    handler: BinHandler * addr: Addr * size: int -> int64 option

  /// <summary>
  ///   Return the corresponding integer value at the addr of the size from the
  ///   given BinHandler.
  /// </summary>
  /// <param name="handler">BinHandler.</param>
  /// <param name="addr">The address.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding integer (int64).
  /// </returns>
  static member ReadInt:
    handler: BinHandler * addr: Addr * size: int -> int64

  /// <summary>
  ///   Return the corresponding unsigned integer option value at the addr of
  ///   the size from the given BinHandler.
  /// </summary>
  /// <param name="handler">BinHandler.</param>
  /// <param name="addr">The address.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding unsigned integer (Some uint64) if the address
  ///   and the size is valid. Otherwise, None.
  /// </returns>
  static member TryReadUInt:
    handler: BinHandler * addr: Addr * size: int -> uint64 option

  /// <summary>
  ///   Return the corresponding unsigned integer value at the addr of the size
  ///   from the given BinHandler.
  /// </summary>
  /// <param name="handler">BinHandler.</param>
  /// <param name="addr">The address.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding unsigned integer (uint64).
  /// </returns>
  static member ReadUInt:
    handler: BinHandler * addr: Addr * size: int -> uint64

  /// <summary>
  ///   Return the ASCII string at the addr from the given BinHandler.
  /// </summary>
  /// <param name="handler">BinHandler.</param>
  /// <param name="addr">The address.</param>
  /// <returns>
  ///   Return the corresponding ASCII string.
  /// </returns>
  static member ReadASCII:
    handler: BinHandler * addr: Addr -> string

  /// <summary>
  ///   Parse one instruction at the given address (addr) from the BinHandler,
  ///   and return the corresponding instruction. This function raises an
  ///   exception if the parsing process failed.
  /// </summary>
  /// <param name="handler">BinHandler.</param>
  /// <param name="addr">The address.</param>
  /// <returns>
  ///   Parsed instruction.
  /// </returns>
  static member ParseInstr:
    handler: BinHandler -> addr: Addr -> Instruction

  /// <summary>
  ///   Parse one instruction at the given address (addr) from the BinHandler,
  ///   and return the corresponding instruction. This function does not raise
  ///   an exception, but returns an option type.
  /// </summary>
  /// <param name="handler">BinHandler.</param>
  /// <param name="addr">The address.</param>
  /// <returns>
  ///   Parsed instruction (option type).
  /// </returns>
  static member TryParseInstr:
    handler: BinHandler -> addr: Addr -> Instruction option

  /// Parse a basic block from the given address, and return the sequence of the
  /// instructions of the basic block. This function may return an incomplete
  /// basic block as an Error type.
  static member ParseBBlock:
       BinHandler
    -> addr:Addr
    -> Result<Instruction list, Instruction list>

  /// Parse a basic block from the given address, and return the sequence of the
  /// instructions of the basic block and next address to parse. This function
  /// may return an incomplete basic block as an Error type with error address.
  static member ParseBBlockWithAddr:
      BinHandler
    * addr: Addr
    -> Result<Instruction list, Instruction list> * Addr

  /// Lift a parsed instruction (Instruction) to produce an array of IR
  /// statements from a given BinHandler.
  static member inline LiftInstr:
    handler: BinHandler -> ins: Instruction -> LowUIR.Stmt []

  /// Return the lifted IR (an array of statements) of a basic block at the
  /// given address. This function returns a partial bblock with Error, if the
  /// parsing of the bblock was not successful.
  static member LiftBBlock:
       handler: BinHandler
    -> addr: Addr
    -> Result<(LowUIR.Stmt [] * Addr), (LowUIR.Stmt [] * Addr)>

  /// Return the lifted IR (an array of statements) of a basic block at the
  /// given address. This function returns a partial bblock with Error, if the
  /// parsing of the bblock was not successful. Unlike liftBBlock where the end
  /// of a basic block is decided by insInfo, liftIRBBlock decides the end of a
  /// basic block when any branch IR statement is encountered. This means that
  /// control flows within complex instructions like rep are reflected in
  /// splitting basic blocks.
  static member LiftIRBBlock:
        handler: BinHandler
     -> addr: Addr
     -> Result<(Instruction * LowUIR.Stmt []) list * Addr, 'a list>

  /// <summary>
  ///   Return a disassembled string from the parsed instruction.
  /// </summary>
  /// <param name="handler">BinHandler.</param>
  /// <param name="showAddr">Whether to show the instruction address or
  /// not.</param>
  /// <param name="resolveSymbol">Whether to resolve symbols while disassembling
  /// the instruction.</param>
  /// <param name="ins">The instruction to disassemble.</param>
  /// <returns>
  ///   Disassembled string.
  /// </returns>
  static member inline DisasmInstr:
       handler: BinHandler
    -> showAddr: bool
    -> resolveSymbol: bool
    -> ins: Instruction
    -> string

  /// <summary>
  ///   Return a disassembled string from the parsed instruction. This function
  ///   returns a simplified disassembly, which does not contain the instruction
  ///   address nor symbols.
  /// </summary>
  /// <param name="handler">BinHandler.</param>
  /// <param name="ins">The instruction to disassemble.</param>
  /// <returns>
  ///   Disassembled string.
  /// </returns>
  static member inline DisasmInstrSimple: ins: Instruction -> string

  /// <summary>
  ///   Return the disassembled string for a basic block starting at the given
  ///   address along with the fall-through address of the block. This function
  ///   returns a partial disassembly if parsing of the bblock was not
  ///   successful.
  /// </summary>
  static member DisasmBBlock:
       handler: BinHandler
    -> showAddr:bool
    -> resolveSymbol: bool
    -> addr: Addr
    -> Result<(string * Addr), (string * Addr)>

  /// <summary>
  /// Return optimized statements from the given statements.
  /// </summary>
  static member Optimize: stmts: LowUIR.Stmt [] -> LowUIR.Stmt []

  /// <summary>
  /// Return the task that lift a basic block and next address.
  /// The task return the lifted IR (an array of statements) and boolean value
  /// that indicate whether parsing of the bblock was successful or not.
  /// </summary>
  static member CreateLiftBBlockTask:
       handler: BinHandler
     * addr: Addr
     * optimize: bool
     * nxt: byref<Addr>
     -> Task<LowUIR.Stmt [] * bool>

// vim: set tw=80 sts=2 sw=2:
