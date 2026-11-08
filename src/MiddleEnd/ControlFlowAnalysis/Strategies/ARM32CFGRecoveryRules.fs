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

  /// Checks if the given address lies past every block that the function has
  /// built so far.
  let liesPastBuiltCode (ctx: CFGBuildingContext<_, _>) addr =
    ctx.CFG.Vertices
    |> Array.forall (fun v ->
      v.VData.Internals.IsAbstract || v.VData.Internals.Range.Max < addr)

  /// Returns the address of the literal that the given instruction loads
  /// whenever it runs. A literal mostly holds a small number, whose top bits
  /// read as the condition EQ, so a load that runs on a condition may be a
  /// literal decoded as code rather than code.
  let tryFindAlwaysLoadedLiteral (ins: ARM32.Instruction) =
    match ins.Condition with
    | ARM32.Condition.AL | ARM32.Condition.UN -> tryFindLoadedLiteral ins
    | _ -> None

  /// Checks if the given instruction loads the literal at the given address
  /// whenever it runs.
  let alwaysLoadsLiteralAt addr ins = tryFindAlwaysLoadedLiteral ins = Some addr

  /// Returns the lifting unit with which the function reads code on its own,
  /// set to read from a start: in its instruction set, outside an IT block.
  let scanningUnitOf (ctx: CFGBuildingContext<_, _>) =
    let lu = ctx.ScanningUnit
    lu.IsThumb <- ctx.EntryMode = ARM32Mode.Thumb
    lu.ITState <- 0uy
    lu

  /// Checks if the function loads the literal at the given address. Code of
  /// 32-bit ARM keeps a function in one piece and lays a pool after the code
  /// that loads it, so the instructions from the entry of the function up to
  /// the address tell, however far the building has come. Each of them is read
  /// from a start, as the scan may hit the middle of one in Thumb.
  let isLoadedLiteral (ctx: CFGBuildingContext<_, _>) addr =
    let step = if ctx.EntryMode = ARM32Mode.Thumb then 2UL else 4UL
    let reach = min addr ARM32Code.LiteralReach
    let lowest = max ctx.FunctionAddress (addr - reach)
    let loads insAddr =
      match (scanningUnitOf ctx).TryParseInstruction(insAddr: Addr) with
      | Ok ins -> alwaysLoadsLiteralAt addr (ins :?> ARM32.Instruction)
      | Error _ -> false
    let rec scan insAddr =
      loads insAddr || (insAddr >= lowest + step && scan (insAddr - step))
    addr >= lowest + step && scan (addr - step)

  /// The most instructions that the code at an address runs before it saves a
  /// preserved register, for it to look like the start of a function.
  let [<Literal>] MaxPrologueLength = 24

  /// Checks if the instruction branches only on a condition, as a branch that
  /// tests a register for zero does, though its condition says always.
  let branchesOnCondition (ins: IInstruction) =
    let arm = ins :?> ARM32.Instruction
    ins.IsCondBranch || (ins.IsBranch && ARM32Code.isConditional arm)

  /// Checks if the code from the address saves a preserved register on the
  /// stack within the given number of instructions, before it calls, returns,
  /// or leaves otherwise. It passes what runs on a condition, as code that
  /// starts a function may test its arguments before it saves registers, but
  /// stops at a jump, which may well leave for another function that saves.
  let rec savesFrom ctx (lu: LiftingUnit) (addr: Addr) count =
    if count = 0 then
      false
    else
      match lu.TryParseInstruction addr with
      | Ok ins -> savesAt ctx lu ins count
      | Error _ -> false

  and savesAt (ctx: CFGBuildingContext<_, _>) lu (ins: IInstruction) count =
    let arm = ins :?> ARM32.Instruction
    let next = ins.Address + uint64 ins.Length
    if ARM32Code.saves ctx.BinHandle.Conventions.Calling arm then
      true
    elif ins.IsCall || ins.IsExit || ins.IsInterrupt then
      false
    elif branchesOnCondition ins then
      savesFrom ctx lu next (count - 1)
    elif ins.IsBranch then
      false
    else
      savesFrom ctx lu next (count - 1)

  /// Checks if the instruction at the given address branches to the target on
  /// no condition, rather than runs on to it, as an instruction that runs on a
  /// condition does when the condition fails.
  let branchesTo (ctx: CFGBuildingContext<_, _>) jmpAddr (target: Addr) =
    match ctx.BBLFactory.PeekInstruction jmpAddr with
    | Ok ins when not (branchesOnCondition ins) ->
      ins.DirectBranchTarget() = (true, target)
    | _ ->
      false

  /// Checks if the jump at jmpAddr starts the function and branches to the
  /// instruction right past it on no condition. No function starts with a jump
  /// that does nothing, so the function only calls the code there as its tail,
  /// which a compiler lays right past it.
  let jumpsPastEntry (ctx: CFGBuildingContext<_, _>) jmpAddr target =
    if jmpAddr <> ctx.FunctionAddress then
      false
    else
      match ctx.BBLFactory.PeekInstruction jmpAddr with
      | Ok ins ->
        target = jmpAddr + uint64 ins.Length && branchesTo ctx jmpAddr target
      | Error _ ->
        false

  /// Checks if the code at the given address looks like the start of a
  /// function: code that the function has not built, which saves a preserved
  /// register before it leaves, starting with an instruction that runs on no
  /// condition.
  let looksLikeEntry (ctx: CFGBuildingContext<_, _>) (addr: Addr) =
    let lu = scanningUnitOf ctx
    match lu.TryParseInstruction addr with
    | Ok ins when not (ARM32Code.isConditional (ins :?> ARM32.Instruction)) ->
      savesAt ctx lu ins MaxPrologueLength && not (coversAddr ctx addr)
    | _ ->
      false

  /// Collects the addresses of the literals that the function loads.
  let collectLoadedLiterals (ctx: CFGBuildingContext<_, _>) =
    ctx.CFG.Vertices
    |> Array.filter (fun v -> not v.VData.Internals.IsAbstract)
    |> Array.collect instructionsOf
    |> Array.choose tryFindAlwaysLoadedLiteral
    |> HashSet

  /// Checks if the function loads, wherever it has built code, the literal
  /// at the given address.
  let loadsBuiltLiteral ctx addr =
    (collectLoadedLiterals ctx).Contains addr

  /// Checks if the code at the given address is a literal that ARM code nearby
  /// loads, which may be code that the function has yet to build. A literal is
  /// data, whatever it decodes as.
  let isLiteralNearby (ctx: CFGBuildingContext<_, _>) addr =
    let lu = scanningUnitOf ctx
    ctx.EntryMode = ARM32Mode.ARM
    && ARM32Code.isLoadedNearby (fun a -> lu.TryParseInstruction(a: Addr)) addr

  /// Checks if the code right above the address ends there rather than runs on
  /// into it: an instruction that leaves for good, a nop that pads, or a
  /// literal that ARM code nearby loads.
  let endsRightAbove ctx addr =
    match ARM32Code.tryDecodeAbove (scanningUnitOf ctx) addr with
    | Some ins when ins.IsNop || ARM32Code.leaves ins -> true
    | _ -> addr >= 4UL && isLiteralNearby ctx (addr - 4UL)

  /// Checks if the target lies past where the next function starts, right
  /// below code that ends there. Code of 32-bit ARM keeps each function in one
  /// piece, so a jump there leaves its function, for one that starts there
  /// even if it saves no register, unless the code above runs on into the
  /// target, as libgcc enters __cmpdf2 past its first instruction.
  let startsPastNextFunction (ctx: CFGBuildingContext<_, _>) target =
    match ctx.ManagerChannel.GetNextFunctionAddress ctx.FunctionAddress with
    | Some nextFnAddr -> target > nextFnAddr && endsRightAbove ctx target
    | None -> false

  /// Checks if the jump at jmpAddr may call a function at target as its tail:
  /// it branches there, and the code there looks like the start of one, or
  /// starts past the next function. A jump that the function loads as a
  /// literal is no jump, and code that ARM code nearby loads as a literal is
  /// no code.
  let mayCallAsTail ctx jmpAddr target =
    branchesTo ctx jmpAddr target
    && (looksLikeEntry ctx target || startsPastNextFunction ctx target)
    && not (loadsBuiltLiteral ctx jmpAddr)
    && not (isLiteralNearby ctx target)

  /// Checks if the function loads, wherever it has built code, the literal
  /// that ends right at the given address.
  let followsLoadedLiteral ctx addr =
    addr >= 4UL && loadsBuiltLiteral ctx (addr - 4UL)

  /// Checks if the function has built code below where it starts.
  let hasCodeBelowEntry (ctx: CFGBuildingContext<_, _>) =
    ctx.CFG.Vertices
    |> Array.exists (fun v ->
      let bbl = v.VData.Internals
      not bbl.IsAbstract && bbl.Range.Min < ctx.FunctionAddress)

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

  /// Checks if the building left out the code at the given address, as it
  /// lies past where the next function starts.
  let isLeftOut (ctx: CFGBuildingContext<_, _>) addr =
    ctx.BlocksPastBoundary |> Seq.exists (fun range -> range.Min = addr)

  /// Checks if the given vertex ends with a jump to where a function of the
  /// given entries starts, which the building did not take for a tail call as
  /// none started there yet: it followed the jump within its function, or left
  /// out the code there as lying past where the next function starts.
  let jumpsToEntryUncalled entries ctx (v: IVertex<LowUIRBasicBlock>) =
    match v.VData.Internals.Terminator with
    | InterJmp(Target = Num(Value = n); Kind = InterJmpKind.Base) ->
      let target = n.ToUInt64()
      let callee = toCalleeAddr ctx target
      callee <> ctx.FunctionAddress
      && (entries: HashSet<Addr>).Contains callee
      && (isFollowedWithin ctx v || isLeftOut ctx target)
    | _ ->
      false

  /// Checks if the function that the given builder has built jumps to a
  /// function of the given entries without calling it as its tail.
  let missesTailCall entries (builder: ICFGBuildable<_, _>) =
    let ctx = builder.Context
    ctx.CFG.Vertices
    |> Array.exists (fun v ->
      not v.VData.Internals.IsAbstract && jumpsToEntryUncalled entries ctx v)

/// Represents the rules of the CFG recovery for 32-bit ARM. Besides the rules
/// of every architecture, a call that switches Thumb code to ARM enters a PLT
/// entry past the Thumb stub that starts it, while a call right before a
/// literal that the code loads never returns, and a jump table entry to such a
/// literal is a hole, as a compiler lays a literal pool only where control
/// never comes. Functions come to light as calls reach them, so a function may
/// turn out to start in code that another one has taken for its own or left
/// out, which is then built again.
type internal ARM32CFGRecoveryRules<'FnCtx, 'GlCtx>() =
  inherit CFGRecoveryRules<'FnCtx, 'GlCtx>()

  override _.ToCalleeAddr(ctx, target) = toCalleeAddr ctx target

  override _.TryJudgeIndirectReturn(ctx, caller) =
    base.TryJudgeIndirectReturn(ctx, caller)
    |> Option.orElseWith (fun () -> tryJudgeReturnByLiteral ctx caller)

  /// Takes a target for a hole if the function loads a literal there. Clang
  /// points the entries of the cases that never come to the end of the
  /// function, where 32-bit ARM code keeps its literal pool, so only a target
  /// past every block that the function has built can be one.
  override _.IsJumpTableHole(ctx, target) =
    liesPastBuiltCode ctx target && isLoadedLiteral ctx target

  /// Judges a jump to the entry of another function a tail call. Code of
  /// 32-bit ARM keeps each function in one piece, so no jump enters a part that
  /// the current function splits off. A jump with which a function starts to
  /// the instruction right past it, or a jump to code that looks like the start
  /// of a function or starts past the next function, where none starts yet,
  /// may call one there.
  override _.JudgeTailCall(ctx, jmpAddr, target) =
    if target = ctx.FunctionAddress then NotTailCall
    elif isFuncEntryPoint ctx target then TailCall
    elif jumpsPastEntry ctx jmpAddr target then TentativeTailCall
    elif mayCallAsTail ctx jmpAddr target then TentativeTailCall
    else NotTailCall

  /// Refutes the guess also if the function loads the literal right before the
  /// callee: code amid a function may jump over its literal pool to where it
  /// saves registers late.
  override _.RefutesTailCall(ctx, callee) =
    base.RefutesTailCall(ctx, callee) || followsLoadedLiteral ctx callee

  /// Refutes the guess if the function has code below where it starts, as
  /// code of 32-bit ARM starts each function at its lowest address.
  override _.RefutesEntry ctx = hasCodeBelowEntry ctx

  override _.RequiresRebuild ctx =
    match findCallsBeforeLoadedLiterals ctx with
    | [||] ->
      false
    | calls ->
      ctx.CallsBeforeLiterals.UnionWith calls
      true

  /// Finds the functions that jump to another function without calling it as
  /// their tail, as they jumped there before any call told that a function
  /// starts there: they took its code for their own, or left it out as lying
  /// past the next function. Built again, they call it as their tail.
  override _.FindFunctionsToRebuild builders =
    let entries =
      builders
      |> Array.filter (fun builder -> builder.BuilderState <> Invalid)
      |> Array.map (fun builder -> builder.EntryPoint)
      |> HashSet
    let isToRebuild (builder: IFunctionBuilder) =
      match builder with
      | :? ICFGBuildable<'FnCtx, 'GlCtx> as built ->
        built.BuilderState = Finished && missesTailCall entries built
      | _ ->
        false
    builders
    |> Array.filter isToRebuild
    |> Array.map (fun builder -> builder.EntryPoint)
