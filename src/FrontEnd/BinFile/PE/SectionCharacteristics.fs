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

namespace B2R2.FrontEnd.BinFile.PE

open System

/// Represents what a section holds and how it is to be mapped, which is what
/// the Characteristics field of its section header holds.
[<FlagsAttribute>]
type SectionCharacteristics =
  /// Reserved, and what a section naming no attribute at all reads as.
  | TypeReg = 0x0u
  /// Reserved.
  | TypeDSect = 0x1u
  /// The section is not to be padded to the next boundary.
  | TypeNoLoad = 0x2u
  /// Reserved.
  | TypeGroup = 0x4u
  /// The section is not to be padded, which COFF alignment has replaced.
  | TypeNoPad = 0x8u
  /// Reserved.
  | TypeCopy = 0x10u
  /// The section holds executable code.
  | ContainsCode = 0x20u
  /// The section holds initialized data.
  | ContainsInitializedData = 0x40u
  /// The section holds uninitialized data.
  | ContainsUninitializedData = 0x80u
  /// Reserved.
  | LinkerOther = 0x100u
  /// The section holds comments or other information for the linker.
  | LinkerInfo = 0x200u
  /// Reserved.
  | TypeOver = 0x400u
  /// The section is to be left out of the image the linker builds.
  | LinkerRemove = 0x800u
  /// The section holds COMDAT data.
  | LinkerComdat = 0x1000u
  /// Reserved.
  | MemProtected = 0x4000u
  /// Reserved.
  | NoDeferSpecExc = 0x4000u
  /// The section holds data referenced through the global pointer.
  | GPRel = 0x8000u
  /// Reserved.
  | MemFardata = 0x8000u
  /// Reserved.
  | MemSysheap = 0x10000u
  /// Reserved.
  | MemPurgeable = 0x20000u
  /// Reserved.
  | Mem16Bit = 0x20000u
  /// Reserved.
  | MemLocked = 0x40000u
  /// Reserved.
  | MemPreload = 0x80000u
  /// The section is aligned on a 1-byte boundary.
  | Align1Bytes = 0x100000u
  /// The section is aligned on a 2-byte boundary.
  | Align2Bytes = 0x200000u
  /// The section is aligned on a 4-byte boundary.
  | Align4Bytes = 0x300000u
  /// The section is aligned on an 8-byte boundary.
  | Align8Bytes = 0x400000u
  /// The section is aligned on a 16-byte boundary.
  | Align16Bytes = 0x500000u
  /// The section is aligned on a 32-byte boundary.
  | Align32Bytes = 0x600000u
  /// The section is aligned on a 64-byte boundary.
  | Align64Bytes = 0x700000u
  /// The section is aligned on a 128-byte boundary.
  | Align128Bytes = 0x800000u
  /// The section is aligned on a 256-byte boundary.
  | Align256Bytes = 0x900000u
  /// The section is aligned on a 512-byte boundary.
  | Align512Bytes = 0xa00000u
  /// The section is aligned on a 1024-byte boundary.
  | Align1024Bytes = 0xb00000u
  /// The section is aligned on a 2048-byte boundary.
  | Align2048Bytes = 0xc00000u
  /// The section is aligned on a 4096-byte boundary.
  | Align4096Bytes = 0xd00000u
  /// The section is aligned on an 8192-byte boundary.
  | Align8192Bytes = 0xe00000u
  /// The bits the alignment of a section is held in.
  | AlignMask = 0xf00000u
  /// The section holds more relocations than its 16-bit count can say.
  | LinkerNRelocOvfl = 0x1000000u
  /// The section can be discarded as needed.
  | MemDiscardable = 0x2000000u
  /// The section cannot be cached.
  | MemNotCached = 0x4000000u
  /// The section cannot be paged out.
  | MemNotPaged = 0x8000000u
  /// The section can be shared in memory.
  | MemShared = 0x10000000u
  /// The section can be executed as code.
  | MemExecute = 0x20000000u
  /// The section can be read.
  | MemRead = 0x40000000u
  /// The section can be written to.
  | MemWrite = 0x80000000u
