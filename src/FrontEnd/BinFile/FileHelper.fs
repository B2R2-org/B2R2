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

module internal B2R2.FrontEnd.BinFile.FileHelper

open B2R2
open B2R2.FrontEnd.BinLifter

let peekUIntOfType (reader: BinReader) bitType o =
  if bitType = WordSize.Bit32 then reader.PeekUInt32 (o) |> uint64
  else reader.PeekUInt64 (o)

let readUIntOfType reader bitType o =
  let inline sizeByCls bitType = if bitType = WordSize.Bit32 then 4 else 8
  struct (peekUIntOfType reader bitType o, o + sizeByCls bitType)

let peekHeaderB (reader: BinReader) cls offset d32 d64 =
  offset + (if cls = WordSize.Bit32 then d32 else d64)
  |> reader.PeekByte

let peekHeaderU16 (reader: BinReader) cls offset d32 d64 =
  offset + (if cls = WordSize.Bit32 then d32 else d64)
  |> reader.PeekUInt16

let peekHeaderI32 (reader: BinReader) cls offset d32 d64 =
  offset + (if cls = WordSize.Bit32 then d32 else d64)
  |> reader.PeekInt32

let peekHeaderU32 (reader: BinReader) cls offset d32 d64 =
  offset + (if cls = WordSize.Bit32 then d32 else d64)
  |> reader.PeekUInt32

let peekHeaderNative reader cls offset d32 d64 =
  offset + (if cls = WordSize.Bit32 then d32 else d64)
  |> peekUIntOfType reader cls

let peekCString (reader: BinReader) offset =
  let rec loop acc pos =
    let byte = reader.PeekByte pos
    if byte = 0uy then List.rev (0uy :: acc) |> List.toArray
    else loop (byte :: acc) (pos + 1)
  let bs = loop [] offset
  ByteArray.extractCString bs 0

let peekCStringOfSize (reader: BinReader) offset (size: int) =
  let span = reader.PeekSpan (size, offset)
  ByteArray.extractCStringFromSpan span 0

let addInvRange set saddr eaddr =
  if saddr = eaddr then set
  else IntervalSet.add (AddrRange (saddr, eaddr)) set

let addLastInvRange wordSize (set, saddr) =
  let laddr =
    if wordSize = WordSize.Bit32 then 0xFFFFFFFFUL else 0xFFFFFFFFFFFFFFFFUL
  IntervalSet.add (AddrRange (saddr, laddr)) set

/// Trim the target range based on my range (myrange) in such a way that the
/// resulting range is always included in myrange.
let trimByRange myrange target =
  let l = max (AddrRange.GetMin myrange) (AddrRange.GetMin target)
  let h = min (AddrRange.GetMax myrange) (AddrRange.GetMax target)
  AddrRange (l, h)

let initRegisterBay isa =
  match isa.Arch with
  | Arch.IntelX64
  | Arch.IntelX86 ->
    Intel.IntelRegisterBay (isa.WordSize) :> RegisterBay
  | Arch.ARMv7 ->
    ARM32.ARM32RegisterBay () :> RegisterBay
  | Arch.AARCH64 ->
    ARM64.ARM64RegisterBay () :> RegisterBay
  | Arch.MIPS1 | Arch.MIPS2 | Arch.MIPS3 | Arch.MIPS4 | Arch.MIPS5
  | Arch.MIPS32 | Arch.MIPS32R2 | Arch.MIPS32R6
  | Arch.MIPS64 | Arch.MIPS64R2 | Arch.MIPS64R6 ->
    MIPS.MIPSRegisterBay (isa.WordSize) :> RegisterBay
  | Arch.EVM ->
    EVM.EVMRegisterBay () :> RegisterBay
  | Arch.TMS320C6000 ->
    TMS320C6000.TMS320C6000RegisterBay () :> RegisterBay
  | _ -> Utils.futureFeature ()

