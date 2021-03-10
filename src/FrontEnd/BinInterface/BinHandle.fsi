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

/// The main hdl for reading/parsing a binary code. BinHandle essentially
/// provides a basic interface for a chunk of binary code either from a string
/// or from an actual binary file.
type BinHandle = {
  ISA: ISA
  FileInfo: FileInfo
  DisasmHelper: DisasmHelper
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
  ///   Return the byte array of size (nBytes) pointed to by the binary pointer
  ///   (bp).
  /// </summary>
  /// <param name="bp">BInaryPointer.</param>
  /// <param name="nBytes">The size of the byte array (in bytes).</param>
  /// <returns>
  ///   Return the byte array if succeed. Otherwise, raise an exception.
  /// </returns>
  member ReadBytes: bp: BinaryPointer * nBytes: int -> byte []

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
  ///   binary, which is pointed to by the binary pointer (bp).
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding integer (int64).
  /// </returns>
  member ReadInt: bp: BinaryPointer * size: int -> int64

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
  ///   binary, which is pointed to by the binary pointer (bp).
  /// </summary>
  /// <param name="bp">BinaryPointer.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding unsigned integer (uint64).
  /// </returns>
  member ReadUInt: bp: BinaryPointer * size: int -> uint64

  /// <summary>
  ///   Return the ASCII string at the addr from the given BinHandle.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <returns>
  ///   Return the corresponding ASCII string.
  /// </returns>
  member ReadASCII: addr: Addr -> string

  /// <summary>
  ///   Return the ASCII string pointed to by the binary pointer from the given
  ///   BinHandle.
  /// </summary>
  /// <param name="bp">BinaryPointer.</param>
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
  static member Init:
      isa: ISA
    * archMode: ArchOperationMode
    -> BinHandle

  /// <summary>
  ///   Initialize an empty BinHandle solely from an ISA, assuming that the
  ///   archMode is NoMode, and the format is RawBinary. This function is useful
  ///   when you want to delay loading the actual body of your binary blob.
  /// </summary>
  /// <param name="isa">ISA.</param>
  /// <returns>BinHandle.</returns>
  static member Init: isa: ISA -> BinHandle

  /// <summary>
  ///   Update BinHandle to have new code at a new address (addr). BinHandle
  ///   is *immutable*.
  /// </summary>
  /// <param name="hdl">The BinHandle to update.</param>
  /// <param name="addr">The new address to use.</param>
  /// <param name="bs">The new code in bytes.</param>
  /// <returns>New BinHandle.</returns>
  static member UpdateCode:
    hdl: BinHandle -> addr: Addr -> bs: byte [] -> BinHandle

  /// <summary>
  ///   Update BinHandle to patch the code at the address (addr). BinHandle
  ///   is *immutable*.
  /// </summary>
  /// <param name="hdl">The BinHandle to update.</param>
  /// <param name="addr">The new address to use.</param>
  /// <param name="bs">The new code in bytes.</param>
  /// <returns>
  ///   Return (BinHandle) if succeeded, (ErrorCase) otherwise.
  /// </returns>
  static member PatchCode:
    hdl: BinHandle -> addr: Addr -> bs: byte [] -> Result<BinHandle, ErrorCase>

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
  ///   is pointed to by the BinaryPointer (bp). The return value is an option
  ///   type. When the given address is invalid, this function returns None.
  /// </summary>
  /// <param name="hdl">BinHandle.</param>
  /// <param name="bp">BinaryPointer.</param>
  /// <param name="nBytes">The size of the byte array (in bytes).</param>
  /// <returns>
  ///   Return (byte []) if succeeded, (ErrorCase) otherwise.
  /// </returns>
  static member TryReadBytes:
    hdl: BinHandle * bp: BinaryPointer * nBytes: int
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
  ///   is pointed to by the BinaryPointer (bp).
  /// </summary>
  /// <param name="hdl">BinHandle.</param>
  /// <param name="bp">BinaryPointer.</param>
  /// <param name="nBytes">The size of the byte array (in bytes).</param>
  /// <returns>
  ///   Return the byte array if succeed. Otherwise, raise an exception.
  /// </returns>
  static member ReadBytes:
    hdl: BinHandle * bp: BinaryPointer * nBytes: int -> byte []

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
  ///   BinHandle (hdl), which is pointed to by the binary pointer (bp).
  /// </summary>
  /// <param name="hdl">BinHandle.</param>
  /// <param name="bp">BinaryPointer.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding value (int64) if the address and the size is
  ///   valid. Otherwise ErrorCase.
  /// </returns>
  static member TryReadInt:
    hdl: BinHandle * bp: BinaryPointer * size: int -> Result<int64, ErrorCase>

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
  ///   BinHandle (hdl), which is pointed to by the binary pointer (bp).
  /// </summary>
  /// <param name="hdl">BinHandle.</param>
  /// <param name="bp">BinaryPointer.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding integer (int64).
  /// </returns>
  static member ReadInt:
    hdl: BinHandle * bp: BinaryPointer * size: int -> int64

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
  ///   the given BinHandle (hdl), which is pointed to by the binary pointer
  ///   (bp).
  /// </summary>
  /// <param name="hdl">BinHandle.</param>
  /// <param name="bp">BinaryPointer.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding unsigned integer (uint64) if the address and
  ///   the size is valid. Otherwise, ErrorCase.
  /// </returns>
  static member TryReadUInt:
    hdl: BinHandle * bp: BinaryPointer * size: int -> Result<uint64, ErrorCase>

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
  ///   given BinHandle (hdl), which is pointed to by the binary pointer (bp).
  /// </summary>
  /// <param name="hdl">BinHandle.</param>
  /// <param name="bp">BinaryPointer.</param>
  /// <param name="size">The size of the integer in bytes. Maximum 8 bytes is
  /// possible.</param>
  /// <returns>
  ///   Return the corresponding unsigned integer (uint64).
  /// </returns>
  static member ReadUInt:
    hdl: BinHandle * bp: BinaryPointer * size: int -> uint64

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
  /// <param name="bp">BinaryPointer.</param>
  /// <returns>
  ///   Return the corresponding ASCII string.
  /// </returns>
  static member ReadASCII:
    hdl: BinHandle * bp: BinaryPointer -> string

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
  ///   Parse one instruction pointed to by binary pointer (bp) from the
  ///   BinHandle, and return the corresponding instruction. This function
  ///   raises an exception if the parsing process failed.
  /// </summary>
  /// <param name="hdl">BinHandle.</param>
  /// <param name="bp">BinaryPointer.</param>
  /// <returns>
  ///   Parsed instruction.
  /// </returns>
  static member ParseInstr:
    hdl: BinHandle * bp: BinaryPointer -> Instruction

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
  ///   Parse one instruction pointed to by the binary pointer (bp) from the
  ///   BinHandle, and return the corresponding instruction. This function does
  ///   not raise an exception, but returns an option type.
  /// </summary>
  /// <param name="hdl">BinHandle.</param>
  /// <param name="bp">BinaryPointer.</param>
  /// <returns>
  ///   Parsed instruction (option type).
  /// </returns>
  static member TryParseInstr:
       hdl: BinHandle * bp: BinaryPointer -> Result<Instruction, ErrorCase>

  /// Parse a basic block from the given address, and return the sequence of the
  /// instructions of the basic block. This function may return an incomplete
  /// basic block as an Error type. This function can be safely used for any
  /// ISAs, and thus, this should be the main parsing function.
  static member ParseBBlock:
       BinHandle * addr: Addr
    -> Result<Instruction list, Instruction list>

  /// Parse a basic block pointed to by the binary pointer (bp), and return the
  /// sequence of the instructions of the basic block. This function may return
  /// an incomplete basic block as an Error type. This function can be safely
  /// used for any ISAs, and thus, this should be the main parsing function.
  static member ParseBBlock:
       BinHandle * bp: BinaryPointer
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
  /// by the binary pointer (bp). This function returns a partial bblock with
  /// Error, if the parsing of the bblock was not successful.
  static member LiftBBlock:
       hdl: BinHandle * bp: BinaryPointer
    -> Result<(LowUIR.Stmt [] * BinaryPointer),
              (LowUIR.Stmt [] * BinaryPointer)>

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
  /// <param name="hdl">BinHandle.</param>
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
  ///   pointed to by the binary pointer (bp) along with the fall-through
  ///   address of the block. This function returns a partial disassembly if
  ///   parsing of the bblock was not successful.
  /// </summary>
  static member DisasmBBlock:
    hdl: BinHandle
    * showAddr:bool
    * resolveSymbol: bool
    * bp: BinaryPointer
    -> Result<(string * BinaryPointer),
              (string * BinaryPointer)>

  /// <summary>
  /// Return optimized statements from the given statements.
  /// </summary>
  static member Optimize: stmts: LowUIR.Stmt [] -> LowUIR.Stmt []

// vim: set tw=80 sts=2 sw=2:
