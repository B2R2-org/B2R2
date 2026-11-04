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

open System.Collections.Generic
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.ControlFlowAnalysis.Strategies.CFGRecoveryCommon

[<AutoOpen>]
module private ARM32CFGRecoveryRules =
  /// Returns the address of the function that a call or a jump to the given
  /// target enters: the trampoline of the PLT entry that covers the target,
  /// which a call that switches Thumb code to ARM enters past the Thumb stub
  /// starting it, or else the target itself.
  let toCalleeAddr (ctx: CFGBuildingContext<_, _>) target =
    match ctx.BinHandle.File with
    | :? BinFile.ELFBinFile as elf ->
      elf.TryFindTrampoline target |> Option.defaultValue target
    | _ ->
      target

  /// Returns the address of the literal that the given instruction loads, out
  /// of the pool that 32-bit ARM code keeps among its instructions, if it loads
  /// one. An ADR takes the address of what lies there, which may as well be
  /// code, rather than reading it.
  let tryFindLoadedLiteral (ins: IInstruction) =
    match ins with
    | :? ARM32.Instruction as arm
      when arm.Opcode = ARM32.Opcode.LDR || arm.Opcode = ARM32.Opcode.VLDR ->
      match ins.MemoryDereferences() with
      | true, [| addr |] -> Some addr
      | _ -> None
    | _ ->
      None

  /// Checks if the given instruction loads the literal at the given address.
  let loadsLiteralAt addr ins = tryFindLoadedLiteral ins = Some addr

  /// Checks if the block that ends with the given vertex loads the literal at
  /// the given address. The lifter splits an instruction that branches within
  /// itself, such as a BLX that picks the instruction set by the register it
  /// calls through, so such a block is several vertices that all end with its
  /// last instruction.
  let blockLoadsLiteralAt (g: LowUIRCFG) addr (v: IVertex<LowUIRBasicBlock>) =
    let lastAddr = v.VData.Internals.LastInstruction.Address
    let visited = HashSet [ v ]
    let isUnvisitedPart (p: IVertex<LowUIRBasicBlock>) =
      not p.VData.Internals.IsAbstract
      && p.VData.Internals.LastInstruction.Address = lastAddr
      && visited.Add p
    let rec loads (v: IVertex<LowUIRBasicBlock>) =
      Array.exists (loadsLiteralAt addr) v.VData.Internals.Instructions
      || Array.exists (fun p -> isUnvisitedPart p && loads p) (g.GetPreds v)
    loads v

  /// Judges from what the function loads whether the given indirect call
  /// returns. A compiler lays a literal pool only where control never comes,
  /// so a call right before a literal that the code loads never returns: one
  /// that its block loads, or one that an earlier build of the function found
  /// loaded elsewhere. Returns None when neither tells.
  let tryJudgeReturnByLiteral (ctx: CFGBuildingContext<_, _>) caller =
    let blk = (caller: IVertex<LowUIRBasicBlock>).VData.Internals
    let callIns = blk.LastInstruction
    let nextAddr = callIns.Address + uint64 callIns.Length
    if ctx.CallsBeforeLiterals.Contains callIns.Address then Some(NoRet, 0)
    elif blockLoadsLiteralAt ctx.CFG nextAddr caller then Some(NoRet, 0)
    else None

  /// Checks if the indirect call at the given call site is taken to return.
  let isTakenToReturn (ctx: CFGBuildingContext<_, _>) callsite =
    match ctx.Vertices.TryGetValue(getCalleePPoint callsite None) with
    | true, absV ->
      absV.VData.Internals.AbstractContent.ReturningStatus <> NoRet
    | false, _ ->
      false

  /// Returns the instruction at the given call site if it is a call in 32-bit
  /// ARM that is taken to return, unless it has been found right before a
  /// literal already: the call frame information may still say that such a
  /// call returns, and finding it again would rebuild the function forever.
  let tryGetReturningARMCall (ctx: CFGBuildingContext<_, _>) callsite =
    let ins = (getCallerVertex ctx callsite).VData.Internals.LastInstruction
    match ins with
    | :? ARM32.Instruction when ins.IsCall && isTakenToReturn ctx callsite ->
      if ctx.CallsBeforeLiterals.Contains ins.Address then None else Some ins
    | _ ->
      None

  /// Returns the address of the literal that the given instruction loads
  /// whenever it runs. A literal mostly holds a small number, whose top bits
  /// read as the condition EQ, so a load that runs on a condition may be a
  /// literal decoded as code rather than code.
  let tryFindAlwaysLoadedLiteral (ins: IInstruction) =
    match ins with
    | :? ARM32.Instruction as arm
      when arm.Condition = ARM32.Condition.AL
           || arm.Condition = ARM32.Condition.UN ->
      tryFindLoadedLiteral ins
    | _ ->
      None

  /// Collects the addresses of the literals that the function loads.
  let collectLoadedLiterals (ctx: CFGBuildingContext<_, _>) =
    ctx.CFG.Vertices
    |> Array.filter (fun v -> not v.VData.Internals.IsAbstract)
    |> Array.collect (fun v -> v.VData.Internals.Instructions)
    |> Array.choose tryFindAlwaysLoadedLiteral
    |> HashSet

  /// Finds the indirect calls of the function that are taken to return while
  /// the function loads the literal right after them.
  let findCallsBeforeLoadedLiterals (ctx: CFGBuildingContext<_, _>) =
    let calls =
      ctx.CallerVertices.Keys
      |> Seq.choose (tryGetReturningARMCall ctx)
      |> Seq.toArray
    if Array.isEmpty calls then
      [||]
    else
      let literals = collectLoadedLiterals ctx
      let isBeforeLiteral (ins: IInstruction) =
        literals.Contains(ins.Address + uint64 ins.Length)
      calls
      |> Array.filter isBeforeLiteral
      |> Array.map (fun ins -> ins.Address)

/// Represents the rules of the CFG recovery for 32-bit ARM. Besides the rules
/// of every architecture, a call that switches Thumb code to ARM enters a PLT
/// entry past the Thumb stub that starts it, and a call right before a literal
/// that the code loads never returns, as a compiler lays a literal pool only
/// where control never comes.
type internal ARM32CFGRecoveryRules<'FnCtx, 'GlCtx>() =
  inherit CFGRecoveryRules<'FnCtx, 'GlCtx>()

  override _.ToCalleeAddr(ctx, target) = toCalleeAddr ctx target

  override _.TryJudgeIndirectReturn(ctx, caller) =
    base.TryJudgeIndirectReturn(ctx, caller)
    |> Option.orElseWith (fun () -> tryJudgeReturnByLiteral ctx caller)

  override _.RequiresRebuild ctx =
    match findCallsBeforeLoadedLiterals ctx with
    | [||] ->
      false
    | calls ->
      ctx.CallsBeforeLiterals.UnionWith calls
      true
