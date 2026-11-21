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

open B2R2.ABI
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.ControlFlowAnalysis.Strategies.CFGRecoveryCommon
open B2R2.MiddleEnd.DataFlow

[<AutoOpen>]
module private S390CFGRecoveryRules =
  /// Checks if the given value is what the given link register held on entry
  /// to the function.
  let isLinkOnEntry link value =
    match value with
    | UntouchedValueDomain.Untouched(UntouchedValueDomain.RegisterTag r) ->
      r = Regular link
    | _ ->
      false

  /// Checks if the indirect jump that ends the given vertex goes to the value
  /// that the link register of the calling convention, R14, held on entry to
  /// the function, wherever the function has kept it since, such as in a
  /// stack slot and then in another register.
  let jumpsToLink (ctx: CFGBuildingContext<_, _>) v =
    match ctx.BinHandle.Conventions.Calling.ReturnAddressLocation with
    | InRegister link ->
      let uva = ctx.UVA
      (uva :> IDataFlowComputable<_, _, _>).Compute ctx.CFG |> ignore
      let state = uva.State
      let stmts = state.GetStmtInfos v
      match stmts[stmts.Length - 1] with
      | InterJmp(Target = target), pp ->
        isLinkOnEntry link (state.Scheme.EvalExpr(pp, target))
      | _ ->
        false
    | OnStack ->
      false

  /// Checks if the call that ends the given block saves the address past it in
  /// a register other than the link register of the calling convention, R14,
  /// as code does that branches over a pool of literals to learn where the
  /// pool lies, rather than calls a function. Every call names the register
  /// that it saves the address in first.
  let branchesOverLiterals (ctx: CFGBuildingContext<_, _>) bbl =
    let ins = (bbl: ILowUIRBasicBlock).LastInstruction :?> S390.Instruction
    let conv = ctx.BinHandle.Conventions.Calling
    match conv.ReturnAddressLocation, ins.Operands with
    | InRegister link, S390.TwoOperands(S390.OpReg r, _) ->
      S390.Register.toRegID r <> link
    | _ ->
      false

  /// Checks if the jump at jmpAddr enters a part that its function splits
  /// off, as the call frame information tells.
  let entersSplitOffPart (hdl: BinHandle) jmpAddr target =
    match hdl.File with
    | :? ELFBinFile as elf -> elf.IsWithinSplitOffPart(jmpAddr, target)
    | _ -> false

  /// Checks if the entry at the given index of the given table sends the jump
  /// below the function, where no part that the function splits off lies.
  let leadsBelowFunction (ctx: CFGBuildingContext<_, _>) jmptbl idx =
    let hdl = ctx.BinHandle
    match JmpTableInfo.tryReadTarget hdl jmptbl idx with
    | Some target when target < ctx.FunctionAddress ->
      not (entersSplitOffPart hdl jmptbl.InsAddr target)
    | _ ->
      false

  /// Checks if the instruction at the given address works on two operands in
  /// storage, and code of the function from its entry up to there runs it by
  /// EXRL, which gives it a length that a register holds. The instruction is
  /// then a template that runs only that way, which clang lays past the code
  /// of its function, where the label of an unreachable default lands.
  let isExecuteTemplate (ctx: CFGBuildingContext<_, _>) addr =
    let rec scan insAddr =
      if insAddr >= addr then
        false
      else
        match ctx.BBLFactory.PeekInstruction insAddr with
        | Ok ins ->
          S390Code.tryExecutedAddress (ins :?> S390.Instruction) = Some addr
          || scan (insAddr + uint64 ins.Length)
        | Error _ ->
          false
    match ctx.BBLFactory.PeekInstruction addr with
    | Ok ins when (ins :?> S390.Instruction).Fmt = S390.InstructionFormat.SS ->
      scan ctx.FunctionAddress
    | _ ->
      false

  /// Checks if the instruction stores the registers from R14 or one below up
  /// to R15 where R15 points.
  let storesLinkAndStack (ins: S390.Instruction) =
    match ins.Operands with
    | S390.ThreeOperands(S390.OpReg first,
                         S390.OpStore(_, S390.Register.R15, _),
                         S390.OpReg S390.Register.R15) ->
      let op = ins.Opcode
      (op = S390.Opcode.STMG || op = S390.Opcode.STMY || op = S390.Opcode.STM)
      && first <= S390.Register.R14
    | _ ->
      false

  /// Checks if the code at the given address looks like the start of a
  /// function: it starts by saving R14 and R15 in the area that the caller
  /// keeps for them, as a function does to save the address that it returns
  /// to and the stack pointer of its caller, and no code runs into it. GCC
  /// saves them amid a function past code that may return early, which runs
  /// into the saving otherwise.
  let startsLikeFunction (ctx: CFGBuildingContext<_, _>) addr =
    match ctx.BBLFactory.PeekInstruction addr with
    | Ok ins ->
      storesLinkAndStack (ins :?> S390.Instruction)
      && S390Code.liesPastFlowEnd ctx.ScanningUnit addr
    | Error _ ->
      false

/// Represents the rules of the CFG recovery for S390: the rules of every
/// architecture, except that an indirect jump returns where it goes to the
/// address that the caller left in R14, and that a jump table ends where the
/// range check before its indirect jump says, or where a mask on its index
/// does, or before an entry that sends the jump below its function. S390 has
/// no return instruction, and GCC reloads the saved R14 into another register
/// to return through, while both GCC and clang jump through a table by way of
/// R14. Both lay the tables of a function next to each other, so the entries
/// of the next table read as more of the first, and clang without PIC fills
/// them with addresses that all lie in the function. Neither lays a case below
/// its function, apart from a part that the function splits off, which the
/// call frame information tells, while clang indexes a table of callbacks as
/// it does a jump table, to call one as its tail. A function that jumps to
/// another one before the recovery has found that one is built again to call
/// it as its tail, as clang emits no call frame information for C code that
/// would tell every function up front. An entry that sends the jump to an
/// instruction that EXRL runs is a hole, as clang lays such templates past the
/// code of a function, where the label of an unreachable default lands. A call
/// that saves the address past it in another register than R14 calls nothing,
/// as 31-bit code branches over a pool of literals that way to learn where the
/// pool lies. A jump to code that no code runs into and that starts by saving
/// R14 and R15 may call a function there as its tail, as clang lays a function
/// that only such jumps lead to right past the one that jumps to it, before
/// the recovery knows of the next function.
type internal S390CFGRecoveryRules<'FnCtx, 'GlCtx>() =
  inherit CFGRecoveryRules<'FnCtx, 'GlCtx>()

  override _.ReturnsThroughLink(ctx, v: IVertex<LowUIRBasicBlock>) =
    jumpsToLink ctx v

  override _.IsGetPCThunk(ctx, bbl, _) =
    branchesOverLiterals ctx bbl

  override _.IsJumpTableHole(ctx, target) =
    isExecuteTemplate ctx target

  override _.EndsJumpTableBefore(ctx, jmptbl, idx) =
    let isPast = Option.exists (fun n -> idx >= n)
    isPast jmptbl.OwnRangeEntries
    || isPast jmptbl.MaskedEntries
    || leadsBelowFunction ctx jmptbl idx

  /// Judges a jump to the entry of another function a tail call, as every
  /// architecture does, while a jump to code that looks like the start of a
  /// function may call one there, where none starts yet, as its tail.
  override _.JudgeTailCall(ctx, jmpAddr, target) =
    match base.JudgeTailCall(ctx, jmpAddr, target) with
    | NotTailCall when target <> ctx.FunctionAddress
                       && startsLikeFunction ctx target ->
      TentativeTailCall
    | judgment ->
      judgment

  override this.FindFunctionsToRebuild builders =
    findFunctionsMissingTailCalls this builders
