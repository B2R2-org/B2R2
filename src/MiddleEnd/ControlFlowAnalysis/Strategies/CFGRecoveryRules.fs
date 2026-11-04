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

open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.ControlFlowAnalysis.Strategies.CFGRecoveryCommon

[<AutoOpen>]
module private CFGRecoveryRules =
  /// Checks if the given address is the entry of a function other than the
  /// current one. A jump to the entry of the current function loops rather
  /// than calls it.
  let isOtherFuncEntry (ctx: CFGBuildingContext<_, _>) target =
    target <> ctx.FunctionAddress && isFuncEntryPoint ctx target

  /// Checks if the jump at jmpAddr enters a part split off the current
  /// function, such as a GCC cold part, which the FDEs tell even when the
  /// function runs without a frame and a symbol names the part a function.
  let entersSplitOffPart (ctx: CFGBuildingContext<_, _>) jmpAddr target =
    match ctx.BinHandle.File with
    | :? BinFile.ELFBinFile as elf -> elf.IsWithinSplitOffPart(jmpAddr, target)
    | _ -> false

  /// Checks if the jump at jmpAddr calls the function at target as its tail: it
  /// leaves for the entry of another function rather than for a part split off
  /// the current one.
  let isTailCall ctx jmpAddr target =
    isOtherFuncEntry ctx target && not (entersSplitOffPart ctx jmpAddr target)

  /// Finds how deep in its frame the code at the given address runs, which is
  /// how far its canonical frame address lies above the stack pointer.
  let tryFindFrameDepth (hdl: BinHandle) (elf: BinFile.ELFBinFile) addr =
    match elf.TryFindCFARegOffset addr with
    | Some(rid, offset) when hdl.RegisterFactory.IsStackPointer rid ->
      Some offset
    | _ ->
      None

  /// Checks if the code at the given address runs as deep in its frame as the
  /// entry of the current function does, which means the frame is torn down.
  let runsAtEntryDepth (ctx: CFGBuildingContext<_, _>) addr =
    let hdl = ctx.BinHandle
    match hdl.File with
    | :? BinFile.ELFBinFile as elf ->
      let entryDepth = tryFindFrameDepth hdl elf ctx.FunctionAddress
      entryDepth.IsSome && entryDepth = tryFindFrameDepth hdl elf addr
    | _ ->
      false

  /// Checks if the conditional jump at jmpAddr calls the function at target as
  /// its tail: it leaves for the entry of another function with its own frame
  /// torn down, so that the callee returns to its caller.
  let isCondTailCall ctx jmpAddr target =
    runsAtEntryDepth ctx jmpAddr && isTailCall ctx jmpAddr target

  let rec skipNops (instrs: IInstruction list) addr =
    match instrs with
    | ins :: rest when ins.IsNop -> skipNops rest (addr + uint64 ins.Length)
    | _ -> addr

  /// Finds the first instruction from the given address on that is not a nop,
  /// skipping the padding that a compiler may put after a call.
  let skipPadding (ctx: CFGBuildingContext<_, _>) addr =
    match ctx.BBLFactory.PeekBBL addr with
    | Ok instrs
    | Error instrs -> skipNops instrs addr

  /// Judges whether a call returns, given how many bytes shallower in the
  /// frame the code after it runs than the call itself.
  let judgeByPoppedBytes (hdl: BinHandle) popped =
    if popped = 0 || popped = WordSize.toByteWidth hdl.ISA.WordSize then
      NotNoRet, popped
    else
      NoRet, 0

  /// Judges whether the call at callAddr returns, comparing how deep in their
  /// frame it and the code at nextAddr run.
  let judgeByFrameDepth hdl elf callAddr nextAddr =
    let callDepth = tryFindFrameDepth hdl elf callAddr
    match callDepth, tryFindFrameDepth hdl elf nextAddr with
    | Some c, Some n -> Some(judgeByPoppedBytes hdl (c - n))
    | _ -> None

  /// Judges from the call frame information whether the given indirect call
  /// returns, along with how many bytes its callee pops when it does. The code
  /// after a call that returns, past any padding, lies in the frame of the
  /// call and runs as deep in it as the call, less what the callee pops, which
  /// is a word at most: a hidden sret pointer. Code anywhere else is not where
  /// the call returns to, so the call never does. Returns None when the
  /// information does not tell.
  let tryJudgeReturnByCFA (ctx: CFGBuildingContext<_, _>) (ins: IInstruction) =
    let hdl = ctx.BinHandle
    match hdl.File with
    | :? BinFile.ELFBinFile as elf ->
      let nextAddr = skipPadding ctx (ins.Address + uint64 ins.Length)
      match elf.TryFindFDERange ins.Address with
      | Some frame when frame.IsIncluding nextAddr ->
        judgeByFrameDepth hdl elf ins.Address nextAddr
      | Some _ ->
        Some(NoRet, 0)
      | None ->
        None
    | _ ->
      None

/// Represents the rules of the CFG recovery that hold on every architecture.
/// They read what the call frame information of a binary tells, if it has
/// any: which part of a function lies apart from it, and how deep in its frame
/// code runs. The rules of an architecture inherit these and override what
/// differs there.
type internal CFGRecoveryRules<'FnCtx, 'GlCtx>() =
  /// Returns the address of the function that a call or a jump to the given
  /// target enters.
  abstract ToCalleeAddr:
       CFGBuildingContext<'FnCtx, 'GlCtx>
    * target: Addr
    -> Addr

  /// Checks if the jump at jmpAddr calls the function at target as its tail.
  abstract IsTailCall:
       CFGBuildingContext<'FnCtx, 'GlCtx>
    * jmpAddr: Addr
    * target: Addr
    -> bool

  /// Checks if the conditional jump at jmpAddr calls the function at target as
  /// its tail.
  abstract IsCondTailCall:
       CFGBuildingContext<'FnCtx, 'GlCtx>
    * jmpAddr: Addr
    * target: Addr
    -> bool

  /// Checks if the call that ends the given block reads the PC rather than
  /// calls a function.
  abstract IsGetPCThunk:
       CFGBuildingContext<'FnCtx, 'GlCtx>
    * ILowUIRBasicBlock
    * callee: Addr
    -> bool

  /// Judges whether the indirect call that ends the given vertex returns, along
  /// with how many bytes its callee pops when it does.
  abstract TryJudgeIndirectReturn:
       CFGBuildingContext<'FnCtx, 'GlCtx>
    * IVertex<LowUIRBasicBlock>
    -> (NonReturningStatus * int) option

  /// Checks if the entries of a jump table that point to the given target are
  /// holes, which lead to no code.
  abstract IsJumpTableHole:
       CFGBuildingContext<'FnCtx, 'GlCtx>
    * target: Addr
    -> bool

  /// Checks if the function that the given context has built needs building
  /// again.
  abstract RequiresRebuild: CFGBuildingContext<'FnCtx, 'GlCtx> -> bool

  /// Finds the functions to build again among the given builders, once all of
  /// them are done building.
  abstract FindFunctionsToRebuild: IFunctionBuilder[] -> Addr[]

  /// Returns the target itself.
  default _.ToCalleeAddr(_, target) = target

  /// Checks if the jump leaves for the entry of another function rather than
  /// for a part split off the current one.
  default _.IsTailCall(ctx, jmpAddr, target) = isTailCall ctx jmpAddr target

  /// Checks if the jump leaves for the entry of another function with its own
  /// frame torn down.
  default _.IsCondTailCall(ctx, jmpAddr, target) =
    isCondTailCall ctx jmpAddr target

  /// Takes every call for a call to a function.
  default _.IsGetPCThunk(_, _, _) = false

  /// Judges by the call frame information.
  default _.TryJudgeIndirectReturn(ctx, caller) =
    tryJudgeReturnByCFA ctx caller.VData.Internals.LastInstruction

  /// Takes no target for a hole, leaving the padding at the end of a function
  /// to the recovery itself.
  default _.IsJumpTableHole(_, _) = false

  /// Finds nothing in a built function that calls for building it again.
  default _.RequiresRebuild _ = false

  /// Finds none.
  default _.FindFunctionsToRebuild _ = [||]

  interface ICFGRecoveryRules<'FnCtx, 'GlCtx> with
    member this.ToCalleeAddr(ctx, target) = this.ToCalleeAddr(ctx, target)

    member this.IsTailCall(ctx, jmpAddr, target) =
      this.IsTailCall(ctx, jmpAddr, target)

    member this.IsCondTailCall(ctx, jmpAddr, target) =
      this.IsCondTailCall(ctx, jmpAddr, target)

    member this.IsGetPCThunk(ctx, bbl, callee) =
      this.IsGetPCThunk(ctx, bbl, callee)

    member this.TryJudgeIndirectReturn(ctx, caller) =
      this.TryJudgeIndirectReturn(ctx, caller)

    member this.IsJumpTableHole(ctx, target) =
      this.IsJumpTableHole(ctx, target)

    member this.RequiresRebuild ctx = this.RequiresRebuild ctx

    member this.FindFunctionsToRebuild builders =
      this.FindFunctionsToRebuild builders
