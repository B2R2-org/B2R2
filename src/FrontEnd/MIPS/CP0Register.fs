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

namespace B2R2.FrontEnd.MIPS

/// <summary>
/// Represents a CP0 (System Control Coprocessor) register.
///
/// <para>A CP0 register is named by a (rd, sel) PAIR rather than by a single
/// number, so the pair cannot BE the RegisterID: deriving one arithmetically
/// from the two fields leaves gaps, and a RegisterID has to be a dense index
/// from zero. <c>RegisterSet</c> uses it directly as a bit position and is
/// sized for the widest architecture there is, so a sparse id lands outside
/// the set and every pass that collects register uses throws on it. The ids
/// below therefore run on from the highest the MIPS register set already uses
/// (ULR at 0x109), and the pair each one answers to is a table rather than a
/// shift.</para>
///
/// <para>The register numbers were verified against binutils: assembling
/// <c>mfc0 $8, $12</c> for mips64r2 yields 0x40086000, which objdump renders
/// as <c>mfc0 a4, c0_status</c> -- rd = 12 is Status. The same check fixed
/// Index=0, BadVAddr=8, Count=9, EntryHi=10, Compare=11, Cause=13, EPC=14,
/// PRId=15 and Config=16 (sel 1 of which is Config1).</para>
/// </summary>
type CP0Register =
  /// TLB index for TLBR / TLBWI. Bit 31 (P) is set by TLBP and read-only.
  | Index = 0x10A
  /// Virtual-processor control, which DVP and EVP read and change.
  | VPControl = 0x10B
  /// Which entry TLBWR writes. Read-only, and the one register here whose
  /// VALUE no model can be right about -- see the write mask below.
  | Random = 0x122
  /// Faulting virtual address. Written by hardware only; read-only to MTC0.
  | BadVAddr = 0x10C
  /// Free-running counter half of the CP0 timer.
  | Count = 0x10D
  /// VPN2 and ASID of the TLB entry a TLB instruction reads or writes.
  | EntryHi = 0x10E
  /// Compare half of the CP0 timer: a match raises the timer interrupt, and
  /// writing it clears that interrupt.
  | Compare = 0x10F
  /// Processor status and control: interrupt masks and the operating mode.
  | Status = 0x110
  /// Cause of the last exception. Mostly written by hardware.
  | Cause = 0x111
  /// Exception program counter: where ERET returns to.
  | EPC = 0x112
  /// Processor identification. Entirely read-only.
  | PRId = 0x113
  /// Configuration register 0. Only the K0 cache-coherency field is writable.
  | Config = 0x114
  /// Configuration register 1, which says how big the TLB and the caches
  /// are. Entirely read-only.
  | Config1 = 0x11D
  /// Configuration register 2, whose top bit says Config3 follows it.
  /// Entirely read-only.
  | Config2 = 0x11E
  /// Configuration register 3, which announces the optional features a core
  /// has -- segmentation control and the extended virtual addressing among
  /// them. Entirely read-only.
  | Config3 = 0x11F
  /// Configuration register 4. Entirely read-only.
  | Config4 = 0x120
  /// Configuration register 5, which is where the extended virtual
  /// addressing is switched on where a core has it.
  | Config5 = 0x121
  /// How large a page the TLB can hold, and -- the part that matters here --
  /// whether the extended PHYSICAL addressing is switched on.
  | PageGrain = 0x123
  /// Where DERET resumes.
  | DEPC = 0x115
  /// Where ERET resumes when Status.ERL says the last exception was an error
  /// rather than an ordinary one.
  | ErrorEPC = 0x116
  /// The even page of the pair a TLB entry holds: its physical page number
  /// and the attributes that go with it.
  | EntryLo0 = 0x117
  /// The odd page of that pair.
  | EntryLo1 = 0x118
  /// A pointer into the page table, which a refill handler reads to find the
  /// entry the faulting address needs.
  | Context = 0x119
  /// How big the pair of pages a TLB entry maps is.
  | PageMask = 0x11A
  /// How many entries at the bottom of the TLB a random replacement must not
  /// touch.
  | Wired = 0x11B
  /// Context's counterpart for a 64-bit address space.
  | XContext = 0x11C
