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
      Register.SPSEL
      Register.PAN
      Register.UAO
      Register.DIT
      Register.SSBS
      Register.TCO
      Register.SPEL1 ]

  /// <summary>
  /// What a register holds before anything has written it.
  ///
  /// Six are not zero. CurrentEL says which exception level is running and
  /// execution with no operating system under it starts at EL1, which the
  /// field spells as one in bits 3:2. SCTLR_EL1 has bits that are RES1 and
  /// reset to them. MIDR_EL1 names the processor, and answering zero there
  /// would say there is none. DCZID_EL0 sizes the block DC ZVA and STZGM
  /// clear, as a log2 in words: a Cortex-A57 clears sixteen, and a zero
  /// there would have them clear one. A reset masks every interrupt and
  /// selects the level's own stack pointer, which is DAIF with all four masks
  /// set and SPSel at one.
  ///
  /// Of the rest of PSTATE, DIT resets to zero and PAN, UAO, TCO and SSBS are
  /// UNKNOWN; zero is the value chosen for those.
  /// </summary>
  let resetValue = function
    | Register.CURRENTEL -> 0x4UL
    | Register.SCTLREL1 -> 0x00c50838UL
    | Register.MIDREL1 -> 0x411fd070UL
    | Register.DCZIDEL0 -> 0x4UL
    | Register.DAIF -> 0x3c0UL
    | Register.SPSEL -> 0x1UL
    | _ -> 0UL
