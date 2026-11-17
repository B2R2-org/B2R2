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

/// Reads the memory of a binary that only the loader writes, which holds what
/// the binary holds unless a relocation applies.
[<RequireQualifiedAccess>]
module B2R2.MiddleEnd.DataFlow.LoaderOnlyMemory

open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile

/// Checks if only the loader writes to the given address, so that the code
/// reads there what the binary holds, unless a relocation applies.
let contains (file: IBinFile) addr =
  match file with
  | :? ELFBinFile as elf -> elf.IsReadOnlyAfterLoading addr
  | _ -> file.IsExecutableAddr addr

/// Reads the value of the given type that the binary holds at the given
/// address, where only the loader writes and no relocation does, e.g., the
/// address of a table in the literal pool of ARM code.
let tryRead (hdl: BinHandle) addr rt =
  let file = hdl.File
  let isFixed =
    contains file addr && not (BinFileOps.isRelocationAddr file addr)
  match rt with
  | 8<rt> | 16<rt> | 32<rt> | 64<rt> when isFixed ->
    match hdl.TryReadUInt(addr, RegType.toByteWidth rt) with
    | Ok value -> Some(BitVector(value, rt))
    | Error _ -> None
  | _ ->
    None

/// Checks if the given address lies in a GOT, which code reads through the
/// GOT pointer of its function, as MIPS code reads the GOT through gp and
/// 32-bit PowerPC PIC reads .got2 through r30, rather than through a pointer
/// that walks memory.
let isInGOT (file: IBinFile) addr =
  match BinFileOps.tryFindSectionNameByAddr file addr with
  | Ok name -> name = ".got" || name = ".got2"
  | Error _ -> false

/// Reads the value of the given type that the binary holds at the given
/// address, as tryRead does, only if the address lies in a GOT. A slot that
/// the loader rebases holds the address that the binary itself determines for
/// it, as a slot of .got2 that points to a table does.
let tryReadGOT (hdl: BinHandle) addr rt =
  let file = hdl.File
  if not (isInGOT file addr) then
    None
  else
    match BinFileOps.tryResolveRelocationValue file addr with
    | Ok(BinRelocationValue.Rebased target)
      when rt = WordSize.toRegType file.ISA.WordSize ->
      Some(BitVector(u64 = target, bitLen = rt))
    | _ ->
      tryRead hdl addr rt

/// Checks if the given address lies in a section of code.
let private isInCode (file: IBinFile) addr =
  match BinFileOps.tryFindSectionByAddr file addr with
  | Ok sec -> sec.Kind = CodeSection
  | Error _ -> false

/// Reads the value of the given type that code reads through a register that
/// holds the given address: a slot of a GOT, or a word of code on PowerPC,
/// which has no load relative to the PC. 32-bit PIC there reads the offset of
/// .got2 that lies next to its function through the address that bcl
/// 20,31,$+4 leaves in LR.
let tryReadThroughRegister (hdl: BinHandle) addr rt =
  match tryReadGOT hdl addr rt with
  | None when hdl.ISA.IsPPC && isInCode hdl.File addr -> tryRead hdl addr rt
  | value -> value
