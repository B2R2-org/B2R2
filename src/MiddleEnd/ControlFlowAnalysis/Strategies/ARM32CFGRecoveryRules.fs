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
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
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
  let tryFindLoadedLiteral (ins: ARM32.Instruction) =
    if ins.Opcode = ARM32.Opcode.LDR || ins.Opcode = ARM32.Opcode.VLDR then
      match (ins :> IInstruction).MemoryDereferences() with
      | true, [| addr |] -> Some addr
      | _ -> None
    else
      None

  /// Checks if the given instruction loads the literal at the given address.
  let loadsLiteralAt addr ins = tryFindLoadedLiteral ins = Some addr

  /// Returns the instructions of the given vertex, which are all of 32-bit
  /// ARM, as these rules see no other code.
  let instructionsOf (v: IVertex<LowUIRBasicBlock>) =
    v.VData.Internals.Instructions
    |> Array.map (fun ins -> ins :?> ARM32.Instruction)

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
      Array.exists (loadsLiteralAt addr) (instructionsOf v)
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

  /// Returns the address of the literal that the given instruction loads
  /// whenever it runs. A literal mostly holds a small number, whose top bits
  /// read as the condition EQ, so a load that runs on a condition may be a
  /// literal decoded as code rather than code.
  let tryFindAlwaysLoadedLiteral (ins: ARM32.Instruction) =
    match ins.Condition with
    | ARM32.Condition.AL | ARM32.Condition.UN -> tryFindLoadedLiteral ins
    | _ -> None

  /// Checks if the function loads the literal at the given address, as far as
  /// it has been built.
  let isLoadedLiteral (ctx: CFGBuildingContext<_, _>) addr =
    let loads ins = tryFindAlwaysLoadedLiteral ins = Some addr
    ctx.CFG.Vertices
    |> Array.exists (fun v ->
      not v.VData.Internals.IsAbstract && Array.exists loads (instructionsOf v))

  /// Checks if the indirect call at the given call site is taken to return.
  let isTakenToReturn (ctx: CFGBuildingContext<_, _>) callsite =
    match ctx.Vertices.TryGetValue(getCalleePPoint callsite None) with
    | true, absV ->
      absV.VData.Internals.AbstractContent.ReturningStatus <> NoRet
    | false, _ ->
      false

  /// Returns the instruction at the given call site if it is a call that is
  /// taken to return, unless it has been found right before a literal already:
  /// the call frame information may still say that such a call returns, and
  /// finding it again would rebuild the function forever.
  let tryGetReturningARMCall (ctx: CFGBuildingContext<_, _>) callsite =
    let ins = (getCallerVertex ctx callsite).VData.Internals.LastInstruction
    if ins.IsCall && isTakenToReturn ctx callsite then
      if ctx.CallsBeforeLiterals.Contains ins.Address then None else Some ins
    else
      None

  /// Collects the addresses of the literals that the function loads.
  let collectLoadedLiterals (ctx: CFGBuildingContext<_, _>) =
    ctx.CFG.Vertices
    |> Array.filter (fun v -> not v.VData.Internals.IsAbstract)
    |> Array.collect instructionsOf
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

  /// Checks if the building followed the jump that ends the given vertex
  /// within its function, rather than took it for a tail call.
  let isFollowedWithin (ctx: CFGBuildingContext<_, _>) v =
    ctx.CFG.GetSuccEdges v |> Array.exists (fun e -> e.Label = InterJmpEdge)

  /// Checks if the given vertex ends with a jump that the building followed
  /// within its function to where a function of the given entries starts, as
  /// none started there yet.
  let jumpsWithinToEntry entries ctx (v: IVertex<LowUIRBasicBlock>) =
    match v.VData.Internals.Terminator with
    | InterJmp(Target = Num(Value = n); Kind = InterJmpKind.Base) ->
      let callee = toCalleeAddr ctx (n.ToUInt64())
      callee <> ctx.FunctionAddress
      && (entries: HashSet<Addr>).Contains callee
      && isFollowedWithin ctx v
    | _ ->
      false

  /// Checks if the function that the given builder has built took for its own
  /// the code of a function of the given entries.
  let swallowsEntry entries (builder: ICFGBuildable<_, _>) =
    let ctx = builder.Context
    ctx.CFG.Vertices
    |> Array.exists (fun v ->
      not v.VData.Internals.IsAbstract && jumpsWithinToEntry entries ctx v)

/// Represents the rules of the CFG recovery for 32-bit ARM. Besides the rules
/// of every architecture, a call that switches Thumb code to ARM enters a PLT
/// entry past the Thumb stub that starts it, while a call right before a
/// literal that the code loads never returns, and a jump table entry to such a
/// literal is a hole, as a compiler lays a literal pool only where control
/// never comes. Functions come to light as calls reach them, so a function may
/// turn out to start in code that another one has taken for its own, which is
/// then built again.
type internal ARM32CFGRecoveryRules<'FnCtx, 'GlCtx>() =
  inherit CFGRecoveryRules<'FnCtx, 'GlCtx>()

  override _.ToCalleeAddr(ctx, target) = toCalleeAddr ctx target

  /// Takes a jump to the entry of another function for a tail call. Code of
  /// 32-bit ARM keeps each function in one piece, so no jump enters a part that
  /// the current function splits off.
  override _.IsTailCall(ctx, _, target) =
    target <> ctx.FunctionAddress && isFuncEntryPoint ctx target

  override _.TryJudgeIndirectReturn(ctx, caller) =
    base.TryJudgeIndirectReturn(ctx, caller)
    |> Option.orElseWith (fun () -> tryJudgeReturnByLiteral ctx caller)

  /// Takes a target for a hole if the function loads a literal there. Clang
  /// points the entries of the cases that never come to the end of the
  /// function, where 32-bit ARM code keeps its literal pool. A target where
  /// the function has built a block already is code.
  override _.IsJumpTableHole(ctx, target) =
    not (ctx.Vertices.ContainsKey(ProgramPoint(target, 0)))
    && isLoadedLiteral ctx target

  override _.RequiresRebuild ctx =
    match findCallsBeforeLoadedLiterals ctx with
    | [||] ->
      false
    | calls ->
      ctx.CallsBeforeLiterals.UnionWith calls
      true

  /// Finds the functions that took the code of another function for their
  /// own: they followed a jump to it before any call told that a function
  /// starts there. Built again, they call it as their tail.
  override _.FindFunctionsToRebuild builders =
    let entries =
      builders
      |> Array.filter (fun builder -> builder.BuilderState <> Invalid)
      |> Array.map (fun builder -> builder.EntryPoint)
      |> HashSet
    let isSwallower (builder: IFunctionBuilder) =
      match builder with
      | :? ICFGBuildable<'FnCtx, 'GlCtx> as built ->
        built.BuilderState = Finished && swallowsEntry entries built
      | _ ->
        false
    builders
    |> Array.filter isSwallower
    |> Array.map (fun builder -> builder.EntryPoint)
