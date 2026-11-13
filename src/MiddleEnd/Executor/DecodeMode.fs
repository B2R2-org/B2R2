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

namespace B2R2.MiddleEnd.Executor

open B2R2
open B2R2.BinIR
open B2R2.FrontEnd

/// <summary>
/// Represents the mode an instruction is decoded in, where an instruction set
/// has more than one: ARM's Thumb state and the IT (If-Then) block it may sit
/// in, and the MIPS encoding being read. A running program moves between them,
/// so the mode belongs to its state at an address rather than to the binary,
/// and the same bytes decode to different instructions under different modes.
/// An architecture without such a mode ignores all of it.
/// </summary>
[<Struct>]
type DecodeMode =
  { /// Whether ARM code is read as Thumb.
    IsThumb: bool
    /// The IT state Thumb code is read under, in the IT[7:0] encoding that
    /// CPSR holds it in; zero outside an IT block.
    ITState: byte
    /// Which MIPS encoding is read.
    ISAMode: MIPSISAMode }

/// <summary>
/// Provides functions to access <see
/// cref='T:B2R2.MiddleEnd.Executor.DecodeMode'/>.
/// </summary>
[<RequireQualifiedAccess>]
module DecodeMode =
  /// The CPSR bit that says ARM code is read as Thumb.
  let [<Literal>] private CPSRThumb = 0x20UL

  /// <summary>
  /// The mode the given lifting unit decodes in, which for a fresh one is the
  /// mode the binary starts in.
  /// </summary>
  [<CompiledName "OfLiftingUnit">]
  let ofLiftingUnit (unit: LiftingUnit) =
    { IsThumb = unit.IsThumb; ITState = unit.ITState; ISAMode = unit.ISAMode }

  /// <summary>
  /// Puts the given lifting unit in the mode, so that what it parses next is
  /// read the way the mode says.
  /// </summary>
  [<CompiledName "Apply">]
  let apply (unit: LiftingUnit) mode =
    unit.IsThumb <- mode.IsThumb
    unit.ITState <- mode.ITState
    unit.ISAMode <- mode.ISAMode

  /// <summary>
  /// The mode an ARM CPSR value names, over the given one: the T bit, and the
  /// IT field, whose IT[1:0] sit at bits 26:25 and IT[7:2] at bits 15:10.
  /// </summary>
  [<CompiledName "OfCPSR">]
  let ofCPSR (cpsr: uint64) mode =
    let low = (cpsr >>> 25) &&& 0x3UL
    let high = (cpsr >>> 10) &&& 0x3fUL
    { mode with
        IsThumb = cpsr &&& CPSRThumb <> 0UL
        ITState = byte (low ||| (high <<< 2)) }

  /// <summary>
  /// The CPSR bits that name the mode's instruction set, which is what an ARM
  /// processor that starts in the mode holds there.
  /// </summary>
  [<CompiledName "ToCPSR">]
  let toCPSR mode = if mode.IsThumb then CPSRThumb else 0UL

  let private has (kind: InterJmpKind) flag = kind &&& flag = flag

  /// <summary>
  /// The mode an inter-instruction jump of the given kind leaves the given one
  /// in. The kind names the instruction set that its target is read in, where
  /// the jump switches; any other jump leaves the mode as it is.
  /// </summary>
  [<CompiledName "SwitchTo">]
  let switchTo kind mode =
    if has kind InterJmpKind.SwitchToThumb then
      { mode with IsThumb = true }
    elif has kind InterJmpKind.SwitchToARM then
      { mode with IsThumb = false }
    elif has kind InterJmpKind.SwitchToMIPS then
      { mode with ISAMode = MIPSISAMode.MIPS }
    elif has kind InterJmpKind.SwitchToMicroMIPS then
      { mode with ISAMode = MIPSISAMode.MicroMIPS }
    elif has kind InterJmpKind.SwitchToMIPS16 then
      { mode with ISAMode = MIPSISAMode.MIPS16 }
    else
      mode
