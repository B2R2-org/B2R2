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

[<RequireQualifiedAccess>]
module internal B2R2.FrontEnd.BinFile.ELF.ARMExceptionData

open System
open B2R2
open B2R2.FrontEnd.BinLifter

/// This is a value that the index table can have.
type ExceptionIndexValue =
  /// This is the most typical entry value, which stores a pointer to an
  /// exception table entry (in `prel31` format).
  | PointerToExceptionEntry of Addr
  /// This index table entry contains the actual table entry in a compact form.
  | CompactEntry
  /// This function cannot be unwound.
  | CantUnwind

/// ARM-specific exception handling index table entry.
type IndexTableEntry =
  { /// The function who will be in charge of catching an exception.
    FuncAddr: Addr
    /// Index table entry value.
    EntryValue: ExceptionIndexValue }

let [<Literal>] private ARMIndexTable = ".ARM.exidx"

let [<Literal>] private ARMTable = ".ARM.extab"

let inline private prel31ToI32 (v: int) =
  ((v <<< 1) &&& 0x80000000) ||| v

let private toExceptionIndexValue myAddr v =
  if (v &&& 0xF0000000) = 0x80000000 then CompactEntry
  elif v = 1 then CantUnwind
  else PointerToExceptionEntry(uint64 (prel31ToI32 v) + myAddr)

let rec private readIndexTableEntry acc reader (span: ByteSpan) sAddr offset =
  if offset >= (span: ByteSpan).Length then List.rev acc
  else
    let prel31FnAddr = (reader: IBinReader).ReadInt32(span, offset)
    let fnAddr = uint64 (prel31ToI32 prel31FnAddr) + sAddr
    let prel31Value = reader.ReadInt32(span, offset + 4)
    let v = toExceptionIndexValue (sAddr + 4UL) prel31Value
    let acc = { FuncAddr = fnAddr; EntryValue = v } :: acc
    readIndexTableEntry acc reader span (sAddr + 8UL) (offset + 8)

let private parseIndexTable toolBox indexTableSection =
  let offset, size = indexTableSection.SecOffset, indexTableSection.SecSize
  let span = ReadOnlySpan(toolBox.Bytes, int offset, int size)
  readIndexTableEntry [] toolBox.Reader span indexTableSection.SecAddr 0

let private computeLSDAOffset currentOffset (n: int) =
  if (n &&& 0xF0000000) = 0x80000000 then (* Compact format *) currentOffset + 4
  else
    let msb = (n >>> 24) &&& 0xff (* This means the number of words to parse. *)
    currentOffset + 4 + msb * 4

/// Reads LSDA if the personality routine is a custom model.
let private readLSDAFromCustom reader cls span (sAddr: Addr) addr =
  let offset = Convert.ToInt32(addr - sAddr)
  let n = (reader: IBinReader).ReadInt32(span = span, offset = offset)
  if (n &&& 0x80000000) = 0 then (* Custom personality routine with LSDA *)
    let _personalityOffset = uint64 (prel31ToI32 n) + addr (* No need for now *)
    let offset = offset + 4
    let n = reader.ReadInt32(span, offset)
    let lsdaOffset = computeLSDAOffset offset n
    let struct (lsda, _) = LSDA.parse cls span reader sAddr lsdaOffset
    let lsdaAddr = sAddr + uint64 lsdaOffset
    Some(lsda, lsdaAddr)
  elif (n &&& 0xF0000000) = 0x80000000 then (* Compact model. *) None
  else Terminator.impossible () (* Unknown format *)

let rec private readExnTableEntry (fdes, lsdas) reader cls span sAddr = function
  | entry :: tl ->
    match entry.EntryValue with
    | PointerToExceptionEntry(addr) ->
      match readLSDAFromCustom reader cls span sAddr addr with
      | Some(lsda, lsdaAddr) ->
        let fde =
          { PCBegin = entry.FuncAddr
            PCEnd = entry.FuncAddr
            LSDAPointer = Some lsdaAddr
            UnwindingInfo = [] }
        let acc = (fde :: fdes, Map.add lsdaAddr lsda lsdas)
        readExnTableEntry acc reader cls span sAddr tl
      | None ->
        readExnTableEntry (fdes, lsdas) reader cls span sAddr tl
    | CantUnwind | CompactEntry ->
      readExnTableEntry (fdes, lsdas) reader cls span sAddr tl
  | [] -> (fdes, lsdas)

let private parseExnTable toolBox cls exnTblSection entries =
  let offset, size = int exnTblSection.SecOffset, int exnTblSection.SecSize
  let span = ReadOnlySpan(toolBox.Bytes, offset, size)
  let secAddr = exnTblSection.SecAddr
  let cie = (* Create a dummy CIE. *)
    { Version = 0uy
      AugmentationString = ""
      CodeAlignmentFactor = 0UL
      DataAlignmentFactor = 0L
      ReturnAddressRegister = 0uy
      InitialRule = Map.empty
      InitialCFARegister = 0uy
      InitialCFA = UnknownCFA
      Augmentations = [] }
  let fdes, lsdas =
    readExnTableEntry ([], Map.empty) toolBox.Reader cls span secAddr entries
  struct ([ { CIE = cie; FDEs = List.toArray fdes } ], lsdas)

/// Parses ARM-specific exception handler. The specification is found @
/// https://github.com/ARM-software/abi-aa/blob/main/ehabi32/ehabi32.rst
let parse toolBox cls shdrs =
  match Array.tryFind (fun s -> s.SecName = ARMIndexTable) shdrs,
        Array.tryFind (fun s -> s.SecName = ARMTable) shdrs with
  | Some indexTable, Some exnTable ->
    let indexTable = parseIndexTable toolBox indexTable
    parseExnTable toolBox cls exnTable indexTable
  | _ -> struct ([], Map.empty)
