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

namespace B2R2.FrontEnd.ARM32

/// <summary>
/// The coprocessor 15 registers this front end models, and what MRC and MCR
/// do with each: which register an encoding names, what it holds out of
/// reset, and which of its bits a write keeps.
///
/// <para>The processor is a Cortex-A15 r4p0 implemented without the Security
/// or the Virtualization Extensions and without a trace unit, which is what
/// ID_PFR1 and ID_DFR0 say; the other identification registers are what that
/// processor says of itself. Code with no operating system under it reads
/// them before anything else, so they are part of the model rather than a
/// detail of it, the way SysReg.fs keeps the AArch64 ones.</para>
///
/// <para>The cache, TLB and address-translation operations are not here: they
/// need a memory system this front end does not have, so an access to one is
/// left to the emulator to report.</para>
/// </summary>
[<RequireQualifiedAccess>]
module CP15 =
  /// <summary>
  /// What MRC and MCR reach through opc1, CRn, CRm and opc2, or nothing for an
  /// encoding this front end does not model.
  ///
  /// The auxiliary control, fault status and memory attribute registers are
  /// IMPLEMENTATION DEFINED, and nothing here acts on them, so they read as
  /// zero and take no notice of a write. TCMTR and TLBTR describe memories
  /// this processor does not have, and AIDR holds nothing; REVIDR is not
  /// implemented, so its encoding reads as MIDR.
  /// </summary>
  let access (opc1: int64) crn crm (opc2: int64) =
    match opc1, crn, crm, opc2 with
    | 0L, R.C0, R.C0, 0L -> Some(Held R.MIDR)
    | 0L, R.C0, R.C0, 1L -> Some(Held R.CTR)
    | 0L, R.C0, R.C0, 2L -> Some FixedZero (* TCMTR *)
    | 0L, R.C0, R.C0, 3L -> Some FixedZero (* TLBTR *)
    | 0L, R.C0, R.C0, 5L -> Some(Held R.MPIDR)
    | 0L, R.C0, R.C0, 6L -> Some MainIDAlias (* REVIDR *)
    | 0L, R.C0, R.C1, 0L -> Some(Held R.IDPFR0)
    | 0L, R.C0, R.C1, 1L -> Some(Held R.IDPFR1)
    | 0L, R.C0, R.C1, 2L -> Some(Held R.IDDFR0)
    | 0L, R.C0, R.C1, 3L -> Some(Held R.IDAFR0)
    | 0L, R.C0, R.C1, 4L -> Some(Held R.IDMMFR0)
    | 0L, R.C0, R.C1, 5L -> Some(Held R.IDMMFR1)
    | 0L, R.C0, R.C1, 6L -> Some(Held R.IDMMFR2)
    | 0L, R.C0, R.C1, 7L -> Some(Held R.IDMMFR3)
    | 0L, R.C0, R.C2, 0L -> Some(Held R.IDISAR0)
    | 0L, R.C0, R.C2, 1L -> Some(Held R.IDISAR1)
    | 0L, R.C0, R.C2, 2L -> Some(Held R.IDISAR2)
    | 0L, R.C0, R.C2, 3L -> Some(Held R.IDISAR3)
    | 0L, R.C0, R.C2, 4L -> Some(Held R.IDISAR4)
    | 0L, R.C0, R.C2, 5L -> Some(Held R.IDISAR5)
    | 1L, R.C0, R.C0, 1L -> Some(Held R.CLIDR)
    | 1L, R.C0, R.C0, 7L -> Some FixedZero (* AIDR *)
    | 2L, R.C0, R.C0, 0L -> Some(Held R.CSSELR)
    | 0L, R.C1, R.C0, 0L -> Some(Held R.SCTLR)
    | 0L, R.C1, R.C0, 1L -> Some ReadAsZero (* ACTLR *)
    | 0L, R.C1, R.C0, 2L -> Some(Held R.CPACR)
    | 0L, R.C2, R.C0, 0L -> Some(Held R.TTBR0)
    | 0L, R.C2, R.C0, 1L -> Some(Held R.TTBR1)
    | 0L, R.C2, R.C0, 2L -> Some(Held R.TTBCR)
    | 0L, R.C3, R.C0, 0L -> Some(Held R.DACR)
    | 0L, R.C5, R.C0, 0L -> Some(Held R.DFSR)
    | 0L, R.C5, R.C0, 1L -> Some(Held R.IFSR)
    | 0L, R.C5, R.C1, 0L -> Some ReadAsZero (* ADFSR *)
    | 0L, R.C5, R.C1, 1L -> Some ReadAsZero (* AIFSR *)
    | 0L, R.C6, R.C0, 0L -> Some(Held R.DFAR)
    | 0L, R.C6, R.C0, 2L -> Some(Held R.IFAR)
    | 0L, R.C7, R.C4, 0L -> Some(Held R.PAR)
    | 0L, R.C7, R.C5, 4L -> Some Barrier (* CP15ISB *)
    | 0L, R.C7, R.C10, 4L -> Some Barrier (* CP15DSB *)
    | 0L, R.C7, R.C10, 5L -> Some Barrier (* CP15DMB *)
    | 0L, R.C10, R.C2, 0L -> Some(Held R.PRRR)
    | 0L, R.C10, R.C2, 1L -> Some(Held R.NMRR)
    | 0L, R.C10, R.C3, 0L -> Some ReadAsZero (* AMAIR0 *)
    | 0L, R.C10, R.C3, 1L -> Some ReadAsZero (* AMAIR1 *)
    | 0L, R.C12, R.C0, 0L -> Some(Held R.VBAR)
    | 0L, R.C13, R.C0, 0L -> Some(Held R.FCSEIDR)
    | 0L, R.C13, R.C0, 1L -> Some(Held R.CONTEXTIDR)
    | 0L, R.C13, R.C0, 2L -> Some(Held R.TPIDRURW)
    | 0L, R.C13, R.C0, 3L -> Some(Held R.TPIDRURO)
    | 0L, R.C13, R.C0, 4L -> Some(Held R.TPIDRPRW)
    | 0L, R.C14, R.C0, 0L -> Some(Held R.CNTFRQ)
    | _ -> None

  /// <summary>
  /// The bits of a register a write keeps, or nothing for a register that may
  /// not be written. The identification registers are the processor's and
  /// fixed; of the rest, CSSELR names a cache by four bits, CPACR keeps the
  /// access rights of the two coprocessors there are and the two bits that
  /// turn Advanced SIMD and the upper half of the register file off, and VBAR
  /// is aligned to 32 bytes.
  ///
  /// TTBCR keeps more than this when the write sets EAE, its bit 31: that
  /// selects the long-descriptor format, whose fields the short-descriptor
  /// one has no room for. See longTTBCRMask.
  /// </summary>
  let writeMask = function
    | R.MIDR | R.CTR | R.MPIDR | R.IDPFR0 | R.IDPFR1 | R.IDDFR0 | R.IDAFR0
    | R.IDMMFR0 | R.IDMMFR1 | R.IDMMFR2 | R.IDMMFR3 | R.IDISAR0 | R.IDISAR1
    | R.IDISAR2 | R.IDISAR3 | R.IDISAR4 | R.IDISAR5 | R.CLIDR -> None
    | R.CSSELR -> Some 0xfu
    | R.CPACR -> Some 0xc0f00000u
    | R.TTBCR -> Some 0x7u
    | R.VBAR -> Some 0xffffffe0u
    | _ -> Some 0xffffffffu

  /// The bits of TTBCR a write keeps when it selects the long-descriptor
  /// format: EAE and the two halves' size, walk and shareability fields.
  let longTTBCRMask = 0xffc73f87u

  /// <summary>
  /// Whether User mode may make the access. It may read and write TPIDRURW,
  /// read TPIDRURO -- the thread pointer an operating system hands it -- and
  /// issue the three barriers; anything else coprocessor 15 holds is PL1's,
  /// and an access to it from User mode is UNDEFINED.
  /// </summary>
  let isUserAccessible access isWrite =
    match access with
    | Held R.TPIDRURW | Barrier -> true
    | Held R.TPIDRURO -> not isWrite
    | _ -> false

  /// Every register held here, which is every one a reset gives a value to.
  let modelled =
    [ R.MIDR
      R.CTR
      R.MPIDR
      R.IDPFR0
      R.IDPFR1
      R.IDDFR0
      R.IDAFR0
      R.IDMMFR0
      R.IDMMFR1
      R.IDMMFR2
      R.IDMMFR3
      R.IDISAR0
      R.IDISAR1
      R.IDISAR2
      R.IDISAR3
      R.IDISAR4
      R.IDISAR5
      R.CLIDR
      R.CSSELR
      R.SCTLR
      R.CPACR
      R.TTBR0
      R.TTBR1
      R.TTBCR
      R.DACR
      R.DFSR
      R.IFSR
      R.DFAR
      R.IFAR
      R.PAR
      R.PRRR
      R.NMRR
      R.VBAR
      R.FCSEIDR
      R.CONTEXTIDR
      R.TPIDRURW
      R.TPIDRURO
      R.TPIDRPRW
      R.CNTFRQ ]

  /// <summary>
  /// What a register holds out of reset. The identification registers hold
  /// what the processor says of itself, and SCTLR its reset value, with the
  /// MMU, the caches and alignment checking off. The rest reset to values
  /// the architecture leaves UNKNOWN, and zero is the one chosen.
  /// </summary>
  let resetValue = function
    | R.MIDR -> 0x414fc0f0UL
    | R.CTR -> 0x8444c004UL
    | R.MPIDR -> 0x80000000UL
    | R.IDPFR0 -> 0x00001131UL
    | R.IDPFR1 -> 0x00010001UL
    | R.IDDFR0 -> 0x02000505UL
    | R.IDMMFR0 -> 0x10201105UL
    | R.IDMMFR1 -> 0x20000000UL
    | R.IDMMFR2 -> 0x01240000UL
    | R.IDMMFR3 -> 0x02102211UL
    | R.IDISAR0 -> 0x02101110UL
    | R.IDISAR1 -> 0x13112111UL
    | R.IDISAR2 -> 0x21232041UL
    | R.IDISAR3 -> 0x11112131UL
    | R.IDISAR4 -> 0x10011142UL
    | R.CLIDR -> 0x0a200023UL
    | R.SCTLR -> 0x00c50078UL
    | _ -> 0UL
