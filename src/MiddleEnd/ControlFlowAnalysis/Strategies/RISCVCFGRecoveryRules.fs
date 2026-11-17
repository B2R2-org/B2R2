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


namespace B2R2.MiddleEnd.ControlFlowAnalysis.Strategies

open B2R2.FrontEnd.BinFile
open B2R2.MiddleEnd.ControlFlowAnalysis

[<AutoOpen>]
module private RISCVCFGRecoveryRules =
  /// Checks if the given address lies within the frame of a function, past
  /// where the FDE of the function starts.
  let isWithinFrame (ctx: CFGBuildingContext<_, _>) addr =
    match ctx.BinHandle.File with
    | :? ELFBinFile as elf ->
      match elf.TryFindFDERange addr with
      | Some frame -> frame.Min < addr
      | None -> false
    | _ ->
      false

  /// Checks if the given address lies within an instruction of a block that
  /// the function of the given context has built, past the start of the
  /// instruction.
  let splitsInstruction (ctx: CFGBuildingContext<_, _>) addr =
    ctx.CFG.Vertices
    |> Array.exists (fun v ->
      let bbl = v.VData.Internals
      not bbl.IsAbstract && bbl.Range.IsIncluding addr
      && bbl.LiftedInstructions
         |> Array.forall (fun lifted -> lifted.Original.Address <> addr))

/// Represents the rules of the CFG recovery for RISCV: the rules of every
/// architecture, except that a call into the frame of a function, past where
/// its FDE starts, calls nothing, that a jump table ends before an entry that
/// sends its jump into the middle of an instruction of the function, that the
/// load of a jump table entry may fold a negative offset of the index into its
/// displacement, and that a call forgets the stack slots that its callee may
/// write. With RVC, the words past a table, read as its entries, often send the
/// jump into the upper half of an instruction, which reads as another one,
/// such as a C.JAL that would start a function within the one of the table,
/// whether the recovery has reached the instruction yet or not.
/// Clang folds the smallest value of a switch into the displacement of LW past
/// the base of the table, which AUIPC or LUI and ADDI build in full. GAS reads
/// the index of a switch from an object that a callee fills, whose range check
/// would otherwise admit entries past the table, where another table starts.
type internal RISCVCFGRecoveryRules<'FnCtx, 'GlCtx>() =
  inherit CFGRecoveryRules<'FnCtx, 'GlCtx>()

  override _.RefutesCallee(ctx, callee) = isWithinFrame ctx callee

  override _.EndsJumpTableBefore(ctx, jmptbl, idx) =
    match JmpTableInfo.tryReadTarget ctx.BinHandle jmptbl idx with
    | Some target -> splitsInstruction ctx target
    | None -> false

  override _.FoldsIndexOffsetIntoLoad _ = true

  override _.ForgetsWrittenSlots _ = true
