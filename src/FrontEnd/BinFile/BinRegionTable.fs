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

namespace B2R2.FrontEnd.BinFile

open B2R2

/// Represents the regions a loader maps, and turns an address into a pointer
/// bounded by the region that maps it. An ELF program header table, a Mach-O
/// segment command list and a PE section header table are each this table once
/// the format is out of the way, so the scan that finds an address is written
/// only here.
type internal BinRegionTable(regions: BinRegion[]) =
  /// The region the last lookup settled on, which the next one tries before
  /// scanning the table. It is a hint and never an answer: it is taken only
  /// where it passes the very test a scan would apply, so a stale one costs a
  /// bounds check and nothing else. It belongs to the table rather than to the
  /// module, or every file open at once would share the one hint.
  let mutable lastHit = 0

  /// Returns the index of the region mapping the given address, or -1 where
  /// none of them does. The scan is written out rather than picked so that it
  /// allocates nothing: every read of an address goes through it.
  member private _.FindRegion addr =
    let hint = lastHit
    if hint < regions.Length && regions[hint].Maps addr then
      hint
    else
      let mutable idx = 0
      let mutable found = -1
      while found < 0 && idx < regions.Length do
        if regions[idx].Maps addr then found <- idx else idx <- idx + 1
      if found >= 0 then lastHit <- found else ()
      found

  /// Returns a pointer to the given address, bounded by the region that maps
  /// it. An address a region gives room to but the file keeps no bytes for, as
  /// the zero-filled tail of one is, names no file offset and gives a virtual
  /// pointer; an address no region maps at all gives a null one.
  member this.GetBoundedPointer addr =
    match this.FindRegion addr with
    | -1 ->
      BinFilePointer.Null
    | idx ->
      let r = regions[idx]
      if addr < r.Address + r.FileSize then
        let offset = int r.Offset + int (addr - r.Address)
        let maxOffset = int r.Offset + int r.FileSize - 1
        BinFilePointer.CreateFileBacked(
          addr, r.Address + r.FileSize - 1UL, offset, maxOffset
        )
      else
        BinFilePointer.CreateVirtual(addr, r.Address + r.VMSize - 1UL)

/// Represents one region a loader maps: where it begins in memory, how far it
/// reaches there, and what part of the file backs it.
and [<Struct>] internal BinRegion =
  { /// Virtual address the region begins at.
    Address: Addr
    /// How far the region reaches in the virtual memory.
    VMSize: uint64
    /// File offset of the bytes backing the region.
    Offset: uint64
    /// How much of the region the file keeps, which is VMSize where the whole
    /// of it is on disk, and less where its tail is zero at run time.
    FileSize: uint64 }

  /// Checks whether the region maps the given address, whether or not the file
  /// keeps bytes for it.
  member this.Maps addr =
    addr >= this.Address && addr < this.Address + this.VMSize
