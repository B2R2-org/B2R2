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

namespace B2R2.FrontEnd.ARM64

open B2R2

/// <summary>
/// The AArch64 system registers this front end models, and what each one
/// holds out of reset.
///
/// <para>Code running at EL0 never sees any of them: MRS and MSR to an EL1
/// register take an exception before they produce a value. Code that runs
/// with no operating system under it sees all of them from its first
/// instruction, and reads them before it writes them -- so what they hold at
/// reset is part of the model rather than a detail of it.</para>
///
/// <para>A register that answered zero where the processor answers something
/// else is worse than one that is absent: SCTLR_EL1 reads back
/// <c>0x00c50838</c> on reset, and a reader that finds zero there concludes
/// the caches and the MMU are configured in a way no processor ships with.
/// The values below are a Cortex-A57's.</para>
///
/// <para>They live beside the register enumeration rather than in whatever
/// executes the IR, so that the two cannot drift apart -- the arrangement
/// <c>MIPS/CP0.fs</c> already uses for the coprocessor 0 registers.</para>
/// </summary>
module SysReg =
  /// <summary>
  /// Every system register modelled here.
  ///
  /// The list is deliberately short: a register with no instruction to reach
  /// it and nothing that reads it is a name in an enumeration and nothing
  /// more. It grows as the instructions that name it do.
  /// </summary>
  let modelled =
    [ Register.SCTLREL1
      Register.TTBR0EL1
      Register.TTBR1EL1
      Register.TCREL1
      Register.MAIREL1
      Register.VBAREL1
      Register.FAREL1
      Register.ELREL1
      Register.SPSREL1
      Register.SPEL0
      Register.TPIDREL1
      Register.CURRENTEL
      Register.DAIF
      Register.MIDREL1
      Register.ESREL1
      Register.DCZIDEL0
      Register.CTREL0
      Register.SPSEL
      Register.PAN
      Register.UAO
      Register.DIT
      Register.SSBS
      Register.TCO
      Register.SPEL1
      Register.PAREL1
      Register.CNTFRQEL0
      Register.TPIDRROEL0
      Register.CLIDREL1
      Register.AIDREL1
      Register.CSSELREL1 ]

  /// <summary>
  /// What a register holds before anything has written it.
  ///
  /// Eight are not zero. CurrentEL says which exception level is running and
  /// execution with no operating system under it starts at EL1, which the
  /// field spells as one in bits 3:2. SCTLR_EL1 has bits that are RES1 and
  /// reset to them. MIDR_EL1 names the processor, and answering zero there
  /// would say there is none. DCZID_EL0 sizes the block DC ZVA and STZGM
  /// clear, as a log2 in words: a Cortex-A57 clears sixteen, and a zero
  /// there would have them clear one. CTR_EL0 gives the cache line sizes code
  /// that cleans caches by line steps by, and a zero there would say four
  /// bytes. CLIDR_EL1 says which caches there are. A reset masks every
  /// interrupt and selects the level's own stack pointer, which is DAIF with
  /// all four masks set and SPSel at one.
  ///
  /// Of the rest of PSTATE, DIT resets to zero and PAN, UAO, TCO and SSBS are
  /// UNKNOWN; zero is the value chosen for those, and for PAR_EL1, whose
  /// reset is UNKNOWN too. CNTFRQ_EL0 is what firmware sets, so it is left
  /// to whatever stands in for firmware.
  /// </summary>
  let resetValue = function
    | Register.CURRENTEL -> 0x4UL
    | Register.SCTLREL1 -> 0x00c50838UL
    | Register.MIDREL1 -> 0x411fd070UL
    | Register.DCZIDEL0 -> 0x4UL
    | Register.CTREL0 -> 0x8444c004UL
    | Register.CLIDREL1 -> 0x0a200023UL
    | Register.DAIF -> 0x3c0UL
    | Register.SPSEL -> 0x1UL
    | _ -> 0UL

  /// <summary>
  /// What a register of the ID space -- op0 3, op1 0, CRn 0, by CRm and op2
  /// -- reads at EL1, or None where the encoding is UNDEFINED. MIDR_EL1,
  /// MPIDR_EL1 and REVIDR_EL1 are CRm 0, which allocates nothing else; the
  /// AArch32 ID registers are CRm 1 to 3 and the AArch64 ones CRm 4 to 7, and
  /// an encoding there with no register reads zero. The values are a
  /// Cortex-A57's as qemu-system-aarch64 reports them on `virt`, with neither
  /// EL2 nor EL3, which ID_AA64PFR0_EL1 says.
  /// </summary>
  let idRegister crm op2 =
    match crm, op2 with
    | 0u, 0u -> Some 0x411fd070UL
    | 0u, 5u -> Some 0x80000000UL
    | 0u, 6u -> Some 0UL
    | 0u, _ -> None
    | 1u, 0u -> Some 0x131UL
    | 1u, 1u -> Some 0x10001UL
    | 1u, 2u -> Some 0x3000006UL
    | 1u, 4u -> Some 0x10101105UL
    | 1u, 5u -> Some 0x40000000UL
    | 1u, 6u -> Some 0x1260000UL
    | 1u, 7u -> Some 0x2102211UL
    | 2u, 0u -> Some 0x2101110UL
    | 2u, 1u -> Some 0x13112111UL
    | 2u, 2u -> Some 0x21232042UL
    | 2u, 3u -> Some 0x1112131UL
    | 2u, 4u -> Some 0x11142UL
    | 2u, 5u -> Some 0x11121UL
    | 3u, 0u -> Some 0x10110222UL
    | 3u, 1u -> Some 0x12111111UL
    | 3u, 2u -> Some 0x43UL
    | 4u, 0u -> Some 0x22UL
    | 5u, 0u -> Some 0x10305106UL
    | 6u, 0u -> Some 0x11120UL
    | 7u, 0u -> Some 0x1124UL
    | _ -> Some 0UL

  /// <summary>
  /// What CCSIDR_EL1 reads for the cache CSSELR_EL1 selects: the L1 data, L1
  /// instruction and L2 unified caches of a Cortex-A57 (CLIDR_EL1 lists those
  /// three), and zero for a level and kind it does not have.
  /// </summary>
  let cacheSize csselr =
    match csselr with
    | 0UL -> 0x701fe00aUL
    | 1UL -> 0x201fe012UL
    | 2UL -> 0x70ffe07aUL
    | _ -> 0UL
