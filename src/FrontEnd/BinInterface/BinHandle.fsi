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

namespace B2R2.FrontEnd.BinInterface

open B2R2
open B2R2.BinIR
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter

/// The main handle for reading/parsing a binary code. BinHandle essentially
/// provides a low-level interface for a chunk of binary code. One can use
/// BinHandle to parse/lift/disassemble instructions at a specific address or to
/// access file-specific data.
type BinHandle = {
  BinFile: BinFile
  DisasmHelper: DisasmHelper
  TranslationContext: TranslationContext
  Parser: Parser
  RegisterBay: RegisterBay
  BinReader: IBinReader
  OS: OS
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
  ///   Initialize a BInHnalder from a given binary byte sequence. This function
  ///   will read the byte sequence and automatically detect its binary format
  ///   if autoDetect is true. Otherwise, it will consider the given binary
  ///   sequence as a raw binary (just a series of machine instructions without
  ///   specific file format).
  /// </summary>
  /// <param name="isa">ISA.</param>
  /// <param name="archMode">ArchOperationMode.</param>
  /// <param name="autoDetect">Perform auto format detection or not.</param>
  /// <param name="baseAddr">Base address for calculating instruction
  /// addresses.</param>
  /// <param name="bytes">Raw binary sequence.</param>
  /// <returns>BinHandle.</returns>
  static member Init:
      isa: ISA
    * archMode: ArchOperationMode
    * autoDetect: bool
    * baseAddr: Addr option
    * bytes: byte []
    -> BinHandle

  /// <summary>
  ///   Initialize a BinHandle from a given binary file (fileName). This
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
  /// <returns>BinHandle.</returns>
  static member Init:
      isa: ISA
    * archMode: ArchOperationMode
    * autoDetect: bool
    * baseAddr: Addr option
    * fileName: string
    -> BinHandle

  /// <summary>
  ///   Initialize a BinHandle from an ISA and a binary file path, assuming
  ///   that the archMode is NoMode. This function behaves the same as the
  ///   2-argument constructor Init (isa, fileName), with a difference of using
  ///   the specified base address when initializing the BinHandle.
  /// </summary>
  /// <param name="isa">ISA.</param>
  /// <param name="baseAddr">Base address.</param>
  /// <param name="fileName">Binary file path.</param>
  /// <returns>BinHandle.</returns>
  static member Init:
    isa: ISA * baseAddr: Addr option * fileName: string -> BinHandle

  /// <summary>
  ///   Initialize a BinHandle from an ISA and a byte sequence, assuming that
  ///   the archMode is NoMode. This function behaves the same as the 2-argument
  ///   constructor Init (isa, bytes), with a difference of using the specified
  ///   base address when initializing the BinHandle.
  /// </summary>
  /// <param name="isa">ISA.</param>
  /// <param name="baseAddr">Base address.</param>
  /// <param name="bytes">Byte sequence.</param>
  /// <returns>BinHandle.</returns>
  static member Init:
    isa: ISA * baseAddr: Addr option * bytes: byte [] -> BinHandle

  /// <summary>
  ///   Initialize a BinHandle from an ISA and a binary file path, assuming
  ///   that the archMode is NoMode. B2R2 will automatically detect the file
  ///   format of the given binary file, but it will refer to the given ISA
  ///   parameter either when the binary has multiple architectures, e.g., a fat
  ///   binary on macOS, or when B2R2 cannot recognize the given file format. If
  ///   the given binary file does not follow the known formats, then B2R2
  ///   consider it as a raw binary with base address at 0.
  /// </summary>
  /// <param name="isa">ISA.</param>
  /// <param name="fileName">Binary file path.</param>
  /// <returns>BinHandle.</returns>
  static member Init: isa: ISA * fileName: string -> BinHandle

  /// <summary>
  ///   Initialize a BinHandle from an ISA and a byte sequence, assuming that
  ///   the archMode is NoMode, and the format is RawBinary.
  /// </summary>
  /// <param name="isa">ISA.</param>
  /// <param name="bytes">Byte sequence.</param>
  /// <returns>BinHandle.</returns>
  static member Init: isa: ISA * bytes: byte [] -> BinHandle

  /// <summary>
  ///   Initialize an empty BinHandle. This function is useful when you want to
  ///   delay loading the actual body of your binary blob.
  /// </summary>
  /// <param name="isa">ISA.</param>
  /// <param name="archMode">ArchOperatinoMode.</param>
  /// <returns>BinHandle.</returns>
  static member Init: isa: ISA * archMode: ArchOperationMode -> BinHandle

  /// <summary>
  ///   Initialize an empty BinHandle solely from an ISA, assuming that the
  ///   archMode is NoMode, and the format is RawBinary. This function is useful
  ///   when you want to delay loading the actual body of your binary blob.
  /// </summary>
  /// <param name="isa">ISA.</param>
  /// <returns>BinHandle.</returns>
  static member Init: isa: ISA -> BinHandle

  /// <summary>
  ///   Initialize an empty BinHandle. This function is useful when you want to
  ///   delay loading the actual body of your binary blob but also want to
  ///   specify the os.
  /// </summary>
  /// <param name="isa">ISA.</param>
  /// <param name="os">OS.</param>
  /// <returns>BinHandle.</returns>
  static member Init: isa: ISA * os: OS -> BinHandle

  /// <summary>
  ///   Return a new BinHandle that contains the given byte array as its core.
  ///   Since BinHandle is *immutable*, this will not affect the given
  ///   BinHandle.
  /// </summary>
  /// <param name="hdl">The BinHandle to update.</param>
  /// <param name="bs">The new code in bytes.</param>
  /// <returns>New BinHandle.</returns>
  static member NewBinHandle:
    hdl: BinHandle * bs: byte [] -> BinHandle

  /// <summary>
  ///   Return a new BinHandle that contains the given byte array as its core
  ///   located at the given address.  Since BinHandle is *immutable*, this will
  ///   not affect the given BinHandle.
  /// </summary>
  /// <param name="hdl">The BinHandle to update.</param>
  /// <param name="addr">The new address to use for the binary.</param>
  /// <param name="bs">The new code in bytes.</param>
  /// <returns>New BinHandle.</returns>
  static member NewBinHandle:
    hdl: BinHandle * addr: Addr * bs: byte [] -> BinHandle

  /// <summary>
  ///   Return the byte array of size (nBytes) at the addr from the given
  ///   BinHandle (hdl). The return value is an option type. When the given
  ///   address is invalid, this function returns None.
  /// </summary>
  /// <param name="hdl">BinHandle.</param>
  /// <param name="addr">The address.</param>
  /// <param name="nBytes">The size of the byte array (in bytes).</param>
  /// <returns>
  ///   Return (byte []) if succeeded, (ErrorCase) otherwise.
  /// </returns>
  static member TryReadBytes:
    hdl: BinHandle * addr: Addr * nBytes: int -> Result<byte [], ErrorCase>

  /// <summary>
  ///   Return the byte array of size (nBytes) from the BinHandler (hdl), which
  ///   is pointed to by the BinFilePointer (ptr). The return value is an option
  ///   type. When the given address is invalid, this function returns None.
  /// </summary>
  /// <param name="hdl">BinHandle.</param>
  /// <param name="ptr">BinFilePointer.</param>
  /// <param name="nBytes">The size of the byte array (in bytes).</param>
  /// <returns>
  ///   Return (byte []) if succeeded, (ErrorCase) otherwise.
  /// </returns>
  static member TryReadBytes:
    hdl: BinHandle * ptr: BinFilePointer * nBytes: int
    -> Result<byte [], ErrorCase>

  /// <summary>
  ///   Return the byte array of size (nBytes) at the addr from the given
  ///   BinHandle.
  /// </summary>
  /// <param name="hdl">BinHandle.</param>
  /// <param name="addr">The address.</param>
  /// <param name="nBytes">The size of the byte array (in bytes).</param>
  /// <returns>
  ///   Return the byte array if succeed. Otherwise, raise an exception.
  /// </returns>
  static member ReadBytes:
    hdl: BinHandle * addr: Addr * nBytes: int -> byte []

  /// <summary>
  ///   Return the byte array of size (nBytes) from the given BinHandle, which
  ///   is pointed to by the BinFilePointer (ptr).
  /// </summary>
  /// <param name="hdl">BinHandle.</param>
  /// <param name="ptr">BinFilePointer.</param>
  /// <param name="nBytes">The size of the byte array (in bytes).</param>
  /// <returns>
  ///   Return the byte array if succeed. Otherwise, raise an exception.
  /// </returns>
  static member ReadBytes:
    hdl: BinHandle * ptr: BinFilePointer * nBytes: int -> byte []

  /// <summary>
  ///   Return the corresponding integer option value at the addr of the size
  ///   from the given BinHandle.
  /// </summary>
  /// <param name="hdl">BinHandle.</param>
  /// <param name="addr">The address.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding value (int64) if the address and the size is
  ///   valid. Otherwise ErrorCase.
  /// </returns>
  static member TryReadInt:
    hdl: BinHandle * addr: Addr * size: int -> Result<int64, ErrorCase>

  /// <summary>
  ///   Return the corresponding integer option value of the size from the given
  ///   BinHandle (hdl), which is pointed to by the binary pointer (ptr).
  /// </summary>
  /// <param name="hdl">BinHandle.</param>
  /// <param name="ptr">BinFilePointer.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding value (int64) if the address and the size is
  ///   valid. Otherwise ErrorCase.
  /// </returns>
  static member TryReadInt:
    hdl: BinHandle * ptr: BinFilePointer * size: int -> Result<int64, ErrorCase>

  /// <summary>
  ///   Return the corresponding integer value at the addr of the size from the
  ///   given BinHandle.
  /// </summary>
  /// <param name="hdl">BinHandle.</param>
  /// <param name="addr">The address.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding integer (int64).
  /// </returns>
  static member ReadInt:
    hdl: BinHandle * addr: Addr * size: int -> int64

  /// <summary>
  ///   Return the corresponding integer value of the size from the given
  ///   BinHandle (hdl), which is pointed to by the binary file pointer (ptr).
  /// </summary>
  /// <param name="hdl">BinHandle.</param>
  /// <param name="ptr">BinFilePointer.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding integer (int64).
  /// </returns>
  static member ReadInt:
    hdl: BinHandle * ptr: BinFilePointer * size: int -> int64

  /// <summary>
  ///   Return the corresponding unsigned integer option value at the addr of
  ///   the size from the given BinHandle.
  /// </summary>
  /// <param name="hdl">BinHandle.</param>
  /// <param name="addr">The address.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding unsigned integer (uint64) if the address and
  ///   the size is valid. Otherwise, ErrorCase.
  /// </returns>
  static member TryReadUInt:
    hdl: BinHandle * addr: Addr * size: int -> Result<uint64, ErrorCase>

  /// <summary>
  ///   Return the corresponding unsigned integer option value of the size from
  ///   the given BinHandle (hdl), which is pointed to by the binary file
  ///   pointer (ptr).
  /// </summary>
  /// <param name="hdl">BinHandle.</param>
  /// <param name="ptr">BinFilePointer.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding unsigned integer (uint64) if the address and
  ///   the size is valid. Otherwise, ErrorCase.
  /// </returns>
  static member TryReadUInt:
    hdl: BinHandle * ptr: BinFilePointer * size: int -> Result<uint64, ErrorCase>

  /// <summary>
  ///   Return the corresponding unsigned integer value at the addr of the size
  ///   from the given BinHandle.
  /// </summary>
  /// <param name="hdl">BinHandle.</param>
  /// <param name="addr">The address.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding unsigned integer (uint64).
  /// </returns>
  static member ReadUInt:
    hdl: BinHandle * addr: Addr * size: int -> uint64

  /// <summary>
  ///   Return the corresponding unsigned integer value of the size from the
  ///   given BinHandle (hdl), which is pointed to by the binary file pointer
  ///   (ptr).
  /// </summary>
  /// <param name="hdl">BinHandle.</param>
  /// <param name="ptr">BinFilePointer.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding unsigned integer (uint64).
  /// </returns>
  static member ReadUInt:
    hdl: BinHandle * ptr: BinFilePointer * size: int -> uint64

  /// <summary>
  ///   Return the ASCII string at the addr from the given BinHandle.
  /// </summary>
  /// <param name="hdl">BinHandle.</param>
  /// <param name="addr">The address.</param>
  /// <returns>
  ///   Return the corresponding ASCII string.
  /// </returns>
  static member ReadASCII:
    hdl: BinHandle * addr: Addr -> string

  /// <summary>
  ///   Return the ASCII string pointed to by the binary pointer from the given
  ///   BinHandle.
  /// </summary>
  /// <param name="hdl">BinHandle.</param>
  /// <param name="ptr">BinFilePointer.</param>
  /// <returns>
  ///   Return the corresponding ASCII string.
  /// </returns>
  static member ReadASCII:
    hdl: BinHandle * ptr: BinFilePointer -> string

  /// <summary>
  ///   Parse one instruction at the given address (addr) from the BinHandle,
  ///   and return the corresponding instruction. This function raises an
  ///   exception if the parsing process failed.
  /// </summary>
  /// <param name="hdl">BinHandle.</param>
  /// <param name="addr">The address.</param>
  /// <returns>
  ///   Parsed instruction.
  /// </returns>
  static member ParseInstr:
    hdl: BinHandle * addr: Addr -> Instruction

  /// <summary>
  ///   Parse one instruction pointed to by the binary file pointer (ptr) from
  ///   the BinHandle, and return the corresponding instruction. This function
  ///   raises an exception if the parsing process failed.
  /// </summary>
  /// <param name="hdl">BinHandle.</param>
  /// <param name="ptr">BinFilePointer.</param>
  /// <returns>
  ///   Parsed instruction.
  /// </returns>
  static member ParseInstr:
    hdl: BinHandle * ptr: BinFilePointer -> Instruction

  /// <summary>
  ///   Parse one instruction at the given address (addr) from the BinHandle,
  ///   and return the corresponding instruction. This function does not raise
  ///   an exception, but returns an option type.
  /// </summary>
  /// <param name="hdl">BinHandle.</param>
  /// <param name="addr">The address.</param>
  /// <returns>
  ///   Parsed instruction (option type).
  /// </returns>
  static member TryParseInstr:
    hdl: BinHandle * addr: Addr -> Result<Instruction, ErrorCase>

  /// <summary>
  ///   Parse one instruction pointed to by the binary file pointer (ptr) from
  ///   the BinHandle, and return the corresponding instruction. This function
  ///   does not raise an exception, but returns an option type.
  /// </summary>
  /// <param name="hdl">BinHandle.</param>
  /// <param name="ptr">BinFilePointer.</param>
  /// <returns>
  ///   Parsed instruction (option type).
  /// </returns>
  static member TryParseInstr:
       hdl: BinHandle * ptr: BinFilePointer -> Result<Instruction, ErrorCase>

  /// Parse a basic block from the given address, and return the sequence of the
  /// instructions of the basic block. This function may return an incomplete
  /// basic block as an Error type. This function can be safely used for any
  /// ISAs, and thus, this should be the main parsing function.
  static member ParseBBlock:
       BinHandle * addr: Addr
    -> Result<Instruction list, Instruction list>

  /// Parse a basic block pointed to by the binary file pointer (ptr), and
  /// return the sequence of the instructions of the basic block. This function
  /// may return an incomplete basic block as an Error type. This function can
  /// be safely used for any ISAs, and thus, this should be the main parsing
  /// function.
  static member ParseBBlock:
       BinHandle * ptr: BinFilePointer
    -> Result<Instruction list, Instruction list>

  /// Lift a parsed instruction (Instruction) to produce an array of IR
  /// statements from a given BinHandle.
  static member inline LiftInstr:
    hdl: BinHandle -> ins: Instruction -> LowUIR.Stmt []

  /// Lift a parsed instruction (Instruction) to produce an array of optimized
  /// IR statements from a given BinHandle.
  static member LiftOptimizedInstr:
    hdl: BinHandle -> ins: Instruction -> LowUIR.Stmt []

  /// Return the lifted IR (an array of statements) of a basic block at the
  /// given address. This function returns a partial bblock with Error, if the
  /// parsing of the bblock was not successful.
  static member LiftBBlock:
       hdl: BinHandle * addr: Addr
    -> Result<(LowUIR.Stmt [] * Addr),
              (LowUIR.Stmt [] * Addr)>

  /// Return the lifted IR (an array of statements) of a basic block pointed to
  /// by the binary file pointer (ptr). This function returns a partial bblock
  /// with Error, if the parsing of the bblock was not successful.
  static member LiftBBlock:
       hdl: BinHandle * ptr: BinFilePointer
    -> Result<(LowUIR.Stmt [] * BinFilePointer),
              (LowUIR.Stmt [] * BinFilePointer)>

  /// <summary>
  ///   Return a disassembled string from the parsed instruction.
  /// </summary>
  /// <param name="hdl">BinHandle.</param>
  /// <param name="showAddr">Whether to show the instruction address or
  /// not.</param>
  /// <param name="resolveSymbol">Whether to resolve symbols while disassembling
  /// the instruction.</param>
  /// <param name="ins">The instruction to disassemble.</param>
  /// <returns>
  ///   Disassembled string.
  /// </returns>
  static member inline DisasmInstr:
       hdl: BinHandle
    -> showAddr: bool
    -> resolveSymbol: bool
    -> ins: Instruction
    -> string

  /// <summary>
  ///   Return a disassembled string from the parsed instruction. This function
  ///   returns a simplified disassembly, which does not contain the instruction
  ///   address nor symbols.
  /// </summary>
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
    hdl: BinHandle
    * showAddr:bool
    * resolveSymbol: bool
    * addr: Addr
    -> Result<(string * Addr), (string * Addr)>

  /// <summary>
  ///   Return the disassembled string for a basic block starting at address
  ///   pointed to by the binary pointer (ptr) along with the fall-through
  ///   address of the block. This function returns a partial disassembly if
  ///   parsing of the bblock was not successful.
  /// </summary>
  static member DisasmBBlock:
    hdl: BinHandle
    * showAddr:bool
    * resolveSymbol: bool
    * ptr: BinFilePointer
    -> Result<(string * BinFilePointer),
              (string * BinFilePointer)>

  /// <summary>
  /// Return optimized statements from the given statements.
  /// </summary>
  static member Optimize: stmts: LowUIR.Stmt [] -> LowUIR.Stmt []

// vim: set tw=80 sts=2 sw=2:
