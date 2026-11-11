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
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Represents what address ranges cover together: the ranges that remain once
/// those that overlap or touch merge, in the order of their addresses, along
/// with where each starts. Telling whether an address lies in any of them
/// takes a binary search, and building one takes a sort, which matters as
/// identification builds one for all the recovered code every round.
type internal AddrRangeUnion =
  { /// Where each of the merged ranges starts.
    Starts: Addr[]
    /// The merged ranges.
    Ranges: AddrRange[] }

/// Provides functions for AddrRangeUnion.
[<RequireQualifiedAccess>]
module internal AddrRangeUnion =
  /// Returns what the given ranges cover together.
  let ofArray (ranges: AddrRange[]) =
    let merged =
      ranges
      |> Array.sortBy (fun range -> range.Min)
      |> Array.fold (fun (merged: AddrRange list) range ->
        match merged with
        | last :: rest when range.Min <= last.Max + 1UL ->
          AddrRange.create last.Min (max last.Max range.Max) :: rest
        | _ ->
          range :: merged) []
      |> List.rev
      |> List.toArray
    { Starts = merged |> Array.map (fun range -> range.Min); Ranges = merged }

  /// Returns the index of the merged range that covers the address, or -1.
  let private indexOf (addr: Addr) union =
    match System.Array.BinarySearch(union.Starts, addr) with
    | i when i >= 0 -> i
    | i when ~~~i > 0 && union.Ranges[~~~i - 1].Max >= addr -> ~~~i - 1
    | _ -> -1

  /// Tells whether the address lies in what the union covers.
  let containsAddr addr union = indexOf addr union >= 0

  /// Finds the merged range that covers the address, if any.
  let tryFindByAddr addr union =
    match indexOf addr union with
    | -1 -> None
    | i -> Some union.Ranges[i]

/// Represents the code that the recovery has built for a function of 32-bit
/// ARM: the address ranges of its blocks, their instructions, and where the
/// literals that the instructions load lie.
type internal ARM32BuiltCode =
  { /// The address ranges of the blocks.
    Ranges: AddrRange[]
    /// The instructions of the blocks.
    Instructions: IInstruction[]
    /// Where the literals that the instructions load lie.
    Literals: AddrRange[] }

/// Represents what identification reads of the code of 32-bit ARM that stays
/// the same from round to round, which it keeps so that a round reads only
/// what is new: the code that the recovery has built for each function, by
/// its CFG, along with the count of its edges then, as the code stays the same
/// until the function is built again, while reading it takes walking the
/// whole CFG.
type internal ARM32CodeMemo(hdl: BinHandle) =
  let builtCodeByCFG =
    System.Runtime.CompilerServices.ConditionalWeakTable<LowUIRCFG, _>()

  let readBuiltCode (fn: Function) =
    let blocks =
      fn.CFG.Vertices
      |> Array.filter (fun v -> not v.VData.Internals.IsAbstract)
      |> Array.map (fun v -> v.VData.Internals)
    let instructions = blocks |> Array.collect (fun blk -> blk.Instructions)
    { Ranges = blocks |> Array.map (fun blk -> blk.Range)
      Instructions = instructions
      Literals = instructions |> Array.choose ARM32Code.tryLiteralRangeOf }

  /// The binary that the code belongs to.
  member _.BinHandle with get(): BinHandle = hdl

  /// Returns the code that the recovery has built for the function, reading
  /// it anew only once the function has been built again.
  member _.GetBuiltCode(fn: Function) =
    let cfg = fn.CFG
    match builtCodeByCFG.TryGetValue cfg with
    | true, (edgeCount, code) when edgeCount = cfg.EdgeCount ->
      code
    | _ ->
      let code = readBuiltCode fn
      builtCodeByCFG.AddOrUpdate(cfg, (cfg.EdgeCount, code))
      code

/// Represents what the code right above an address says about whether a
/// function starts there.
type private Hint =
  /// Shows the code above ending the way a function ends and no label does.
  | Supports
  /// Shows the code above ending the way both a function and a label may.
  | Neutral
  /// Shows the code above running on into the address, or jumping away the
  /// way the dispatch of a label does.
  | Refutes

/// Represents where code resumes past a recovered function of 32-bit ARM,
/// beyond the literals that the function loads and padding.
type internal ARM32Gap =
  { /// The address where code resumes.
    Start: Addr
    /// Tells whether the function is in Thumb.
    IsThumb: bool
    /// Tells whether literals that the function loads lie in between.
    FollowsLiterals: bool
    /// Tells whether the code of the function ends in a jump that never goes
    /// on to the next instruction.
    FollowsJump: bool
    /// Tells whether the code of the function ends in a call that never
    /// returns, as the recovery builds the code past every call that does.
    FollowsNoReturnCall: bool }

/// Represents where the code from an address leads first, as a function that
/// starts there runs.
type private Lead =
  /// Saves a preserved register at the instruction of the given index.
  | Saves of int
  /// Returns at the instruction of the given index, telling whether a branch
  /// or a return that runs on a condition came before.
  | Returns of int * bool
  /// Jumps to a recovered function as its tail at the instruction of the
  /// given index, telling whether a branch or a return that runs on a
  /// condition came before.
  | CallsTail of int * bool
  /// Calls, jumps back or past the next function, takes a return address from
  /// the stack, runs into what decodes as no instruction or into the next
  /// function, or goes on for too long.
  | Unclear

/// Represents what the code that the recovery has built tells about an address
/// that a pointer or a jump names in 32-bit ARM: whether a function starts
/// there. A function saves a register that its caller keeps as it starts, or
/// lies right below what ends another function and no label: a literal pool,
/// padding, a trap, or a call that never returns. A label of GNU C, whose
/// address a program may store, lies below a jump instead, mostly through a
/// register, as GCC gives each label its own dispatch. Neither does a function
/// start at a veneer, which only branches on, nor in a literal that the code
/// loads. The code past a recovered function and the literals that it loads
/// also tells whether the next function starts there.
type internal ARM32EntryEvidence(memo, recovered, toCalleeAddr, argJumpsOf) =
  let hdl = (memo: ARM32CodeMemo).BinHandle

  let cc = hdl.Conventions.Calling

  let lu = hdl.NewLiftingUnit()

  let builtCode =
    (recovered: Function[])
    |> Array.filter (fun fn -> not fn.IsExternal)
    |> Array.map memo.GetBuiltCode

  let covered =
    builtCode
    |> Array.collect (fun code -> code.Ranges)
    |> AddrRangeUnion.ofArray

  let isDecodable addr = lu.TryParseInstruction(addr: Addr) |> Result.isOk

  let instructions = builtCode |> Array.collect (fun code -> code.Instructions)

  let literalRanges = builtCode |> Array.collect (fun code -> code.Literals)

  let literalEnds =
    literalRanges |> Array.map (fun range -> range.Max + 1UL) |> HashSet

  let literals = AddrRangeUnion.ofArray literalRanges

  let sectionStarts =
    BinFileOps.getSections hdl.File
    |> Seq.filter (fun s -> s.Permission.HasFlag Permission.Executable)
    |> Seq.map (fun s -> s.Address)
    |> HashSet

  let instructionsByEnd =
    let byEnd = Dictionary<Addr, IInstruction>()
    for ins in instructions do byEnd[ins.Address + uint64 ins.Length] <- ins
    byEnd

  /// Returns the instruction that ends right at the address, telling whether
  /// the recovery has built it: the one built there, or else the one that
  /// decodes there.
  let tryFindAbove addr =
    match instructionsByEnd.TryGetValue addr with
    | true, ins ->
      Some(ins, true)
    | false, _ ->
      ARM32Code.tryDecodeAbove lu addr |> Option.map (fun ins -> ins, false)

  let returning =
    recovered
    |> Array.filter (fun fn -> fn.NoRet = NotNoRet)
    |> Array.map (fun fn -> fn.EntryPoint)
    |> HashSet

  /// Tells what a call above the address says. A built call that the code
  /// below does not follow is one that the recovery found never to return. A
  /// call that the recovery has not built may sit anywhere in a function, as
  /// one to __stack_chk_fail that a branch skips does, so it only tells that
  /// the code below is where a callee that returns comes back to.
  let hintOfCall (ins: IInstruction) isBuilt =
    if ARM32Code.isConditional (ins :?> ARM32.Instruction) then
      Refutes
    elif isBuilt then
      Supports
    else
      match ins.DirectBranchTarget() with
      | true, target when returning.Contains(toCalleeAddr target) -> Refutes
      | _ -> Neutral

  /// Tells whether the instruction writes the PC with what the function saved
  /// on its stack or with the link register, which ARM code does to return
  /// besides the ways an instruction reports itself as a return.
  let writesReturnAddress (ins: ARM32.Instruction) =
    match ins.Opcode, ins.Operands with
    | ARM32.Opcode.MOV,
      ARM32.TwoOperands(ARM32.OprReg ARM32.Register.PC,
                        ARM32.OprReg ARM32.Register.LR) ->
      true
    | ARM32.Opcode.LDR,
      ARM32.TwoOperands(ARM32.OprReg ARM32.Register.PC,
                        ARM32.OprMemory(ARM32.PostIdxMode(ARM32.ImmOffset(
                          ARM32.Register.SP, _, _)))) ->
      true
    | (ARM32.Opcode.LDM | ARM32.Opcode.LDMIA),
      ARM32.TwoOperands(ARM32.OprReg ARM32.Register.SP,
                        ARM32.OprRegList regs) ->
      List.contains ARM32.Register.PC regs
    | _ ->
      false

  let isReturn (ins: IInstruction) =
    ins.IsRET || writesReturnAddress (ins :?> ARM32.Instruction)

  /// Tells what the instruction right above the address says.
  let hintOf (ins: IInstruction, isBuilt) =
    if ins.IsNop || ins.IsExit then Supports
    elif ins.IsCall then hintOfCall ins isBuilt
    elif ins.IsCondBranch then Refutes
    elif isReturn ins then Neutral
    elif ins.IsIndirectBranch then Refutes
    else Neutral

  /// Tells what the code right above the address says.
  let hintAbove addr =
    if literalEnds.Contains addr || sectionStarts.Contains addr then
      Supports
    else
      tryFindAbove addr |> Option.map hintOf |> Option.defaultValue Neutral

  /// Tells whether the code from the address saves a preserved register on
  /// the stack within the given number of instructions, before it branches.
  let rec savesFrom addr count =
    if count = 0 then
      false
    else
      match lu.TryParseInstruction(addr: Addr) with
      | Ok ins when ARM32Code.saves cc (ins :?> ARM32.Instruction) -> true
      | Ok ins when ins.IsBranch || ins.IsExit -> false
      | Ok ins -> savesFrom (addr + uint64 ins.Length) (count - 1)
      | Error _ -> false

  /// Tells whether the code at the address shows a function starting there.
  let showsEntry addr =
    match hintAbove addr with
    | Supports -> true
    | Neutral -> savesFrom addr 4
    | Refutes -> false

  /// Tells whether ARM code within reach of the address loads a literal that
  /// covers it, though the recovery may not have built that code.
  let isLoadedFromNearby (addr: Addr) =
    not lu.IsThumb
    && ARM32Code.isLoadedNearby (fun a -> lu.TryParseInstruction(a: Addr)) addr

  /// Tells whether the code from the address reaches an unconditional direct
  /// branch through nothing but conditional ones, within the given number of
  /// instructions.
  let rec onlyBranchesFrom addr count =
    if count = 0 then
      false
    else
      match lu.TryParseInstruction(addr: Addr) with
      | Ok ins when ins.IsCondBranch && not ins.IsCall ->
        onlyBranchesFrom (addr + uint64 ins.Length) (count - 1)
      | Ok ins ->
        ins.IsBranch && not ins.IsCall && fst (ins.DirectBranchTarget())
      | Error _ ->
        false

  let blocksOf (fn: Function) =
    fn.CFG.Vertices
    |> Array.filter (fun v -> not v.VData.Internals.IsAbstract)
    |> Array.map (fun v -> v.VData.Internals)

  /// Adds to the given literals those that the code from the address up to the
  /// end loads, decoding one instruction after another, which reaches loads
  /// in code that the recovery has not built without reading an instruction
  /// out of the middle of another.
  let rec sweepLiterals literals (addr: Addr) codeEnd =
    if addr >= codeEnd then
      literals
    else
      match lu.TryParseInstruction addr with
      | Ok ins ->
        let literals =
          match ARM32Code.tryLiteralRangeOf ins with
          | Some range -> range :: literals
          | None -> literals
        sweepLiterals literals (addr + uint64 ins.Length) codeEnd
      | Error _ ->
        let step = if lu.IsThumb then 2UL else 4UL
        sweepLiterals literals (addr + step) codeEnd

  let isZeroAt (addr: Addr) size =
    match hdl.TryReadUInt(addr, size) with
    | Ok 0UL -> true
    | _ -> false

  /// Returns how many bytes of zeros pad the code at the address, if any: a
  /// halfword that aligns Thumb code to a word, or a whole word.
  let tryPaddingSize (addr: Addr) =
    if lu.IsThumb && addr % 4UL = 2UL && isZeroAt addr 2 then Some 2UL
    elif addr % 4UL = 0UL && isZeroAt addr 4 then Some 4UL
    else None

  /// Skips what may lie between a function and the next one from the address
  /// on: the given literals, none of which overlap, padding and nops. This
  /// returns where code resumes, telling whether it skipped a literal.
  let rec skipGap literals (addr: Addr) hasSkippedLiteral =
    match AddrRangeUnion.tryFindByAddr addr literals with
    | Some(range: AddrRange) ->
      skipGap literals (range.Max + 1UL) true
    | None ->
      match tryPaddingSize addr with
      | Some size ->
        skipGap literals (addr + size) hasSkippedLiteral
      | None ->
        match lu.TryParseInstruction addr with
        | Ok ins when ins.IsNop ->
          skipGap literals (addr + uint64 ins.Length) hasSkippedLiteral
        | _ ->
          addr, hasSkippedLiteral

  /// Tells whether the instruction calls on no condition.
  let callsUnconditionally (ins: IInstruction) =
    ins.IsCall && not (ARM32Code.isConditional (ins :?> ARM32.Instruction))

  let entries =
    recovered |> Array.map (fun fn -> fn.EntryPoint) |> Array.sort

  let isEntry (addr: Addr) = System.Array.BinarySearch(entries, addr) >= 0

  /// Returns where the first recovered function past the address starts.
  let nextEntryPast (addr: Addr) =
    match System.Array.BinarySearch(entries, addr) with
    | i when i >= 0 && i + 1 < entries.Length -> entries[i + 1]
    | i when i < 0 && ~~~i < entries.Length -> entries[~~~i]
    | _ -> System.UInt64.MaxValue

  /// The most instructions that a function may run before it saves a
  /// register, returns or calls its tail.
  let [<Literal>] MaxLeadLength = 24

  /// Reads where the code from the address leads, along the jumps forward
  /// within the span from where the reading started up to the next function,
  /// given how many instructions came before and whether a branch or a return
  /// among them runs on a condition. Any other instruction that runs on a
  /// condition, as a compiler writes a short if, leads nowhere else. Still, no
  /// function starts with an instruction that runs on a condition, as the
  /// flags mean nothing yet, nor does a function that saves nothing take a
  /// return address from the stack: that is the epilogue of another function,
  /// which its compiler may leave past a call that never returns. A literal
  /// that recovered code loads ends the reading, as it is data, whatever it
  /// decodes as.
  let rec leadFrom span (addr: Addr) idx isAfterCondition =
    if idx = MaxLeadLength || addr >= snd span then
      Unclear
    elif AddrRangeUnion.containsAddr addr literals then
      Unclear
    else
      match lu.TryParseInstruction addr with
      | Ok ins -> leadOf span ins idx isAfterCondition
      | Error _ -> Unclear

  and leadOf span ins idx isAfterCondition =
    let arm = ins :?> ARM32.Instruction
    let next = ins.Address + uint64 ins.Length
    let isConditional = ARM32Code.isConditional arm
    if idx = 0 && isConditional then
      Unclear
    elif ARM32Code.saves cc arm then
      Saves idx
    elif ins.IsCall || ins.IsExit || ins.IsInterrupt then
      Unclear
    elif ARM32Code.popsReturnAddress arm then
      Unclear
    elif isReturn ins && isConditional then
      leadFrom span next (idx + 1) true
    elif isReturn ins then
      Returns(idx, isAfterCondition)
    elif ins.IsBranch then
      leadOfBranch span ins idx isAfterCondition
    else
      leadFrom span next (idx + 1) isAfterCondition

  and leadOfBranch (start, limit) ins idx isAfterCondition =
    let next = ins.Address + uint64 ins.Length
    let isGuarded =
      ins.IsCondBranch || ARM32Code.isConditional (ins :?> ARM32.Instruction)
    match ins.DirectBranchTarget(), isGuarded with
    | (true, target), false when isEntry target ->
      CallsTail(idx, isAfterCondition)
    | (true, target), true when isEntry target ->
      leadFrom (start, limit) next (idx + 1) true
    | (true, target), _ when target < start || target >= limit ->
      Unclear
    | (true, target), false ->
      leadFrom (start, limit) target (idx + 1) isAfterCondition
    | _, true ->
      leadFrom (start, limit) next (idx + 1) true
    | _, false ->
      Unclear

  /// Reads where the code at the address leads in the given instruction set.
  let leadAt addr isThumb =
    lu.IsThumb <- isThumb
    leadFrom (addr, nextEntryPast addr) addr 0 false

  /// Tells whether the instruction jumps where only a table that the recovery
  /// reads tells, as a switch or a computed goto does, even with a BX, which
  /// Clang dispatches a computed goto with.
  let isOpenJump (ins: IInstruction) =
    ins.IsIndirectBranch && not ins.IsCall && not (isReturn ins)

  /// Tells whether the recovery knows where every jump of the function goes,
  /// so that no code of the function lies past what the recovery has built.
  /// A jump is known once a vertex of its instruction has targets, as a write
  /// to the PC in ARM splits into a jump for each instruction set, and the
  /// recovery reads a table only through the one that stays in ARM. A jump to
  /// an argument as the function received it is known too, as it leaves the
  /// function: no caller passes a label of it.
  let isClosed (fn: Function) =
    let cfg = fn.CFG
    let argJumps = argJumpsOf fn
    let hasTargets v =
      cfg.GetSuccEdges v |> Array.exists (fun e -> e.Label = IndirectJmpEdge)
    let isKnown (addr, vs) =
      Array.contains addr argJumps || Array.exists hasTargets vs
    cfg.Vertices
    |> Array.filter (fun v ->
      let blk = v.VData.Internals
      not blk.IsAbstract && isOpenJump blk.LastInstruction)
    |> Array.groupBy (fun v -> v.VData.Internals.LastInstruction.Address)
    |> Array.forall isKnown

  /// Tells whether the code where the lead starts begins the function past
  /// the given one. Code that saves a preserved register before it calls,
  /// returns or jumps back does, as no code in the middle of a function does.
  /// Code that saves nothing does if it returns or calls its tail first, and
  /// the given function ends right above in literals, a jump or a call that
  /// never returns, with no jump that the recovery cannot follow, which may
  /// lead to a label past it.
  /// Only past literals may a branch or a return on a condition come first, as
  /// the code that libgcc writes by hand returns so in the middle of a
  /// function.
  let startsFunction fn (gap: ARM32Gap) lead =
    match lead with
    | Saves _ ->
      true
    | Returns(_, false) | CallsTail(_, false) ->
      (gap.FollowsLiterals || gap.FollowsJump || gap.FollowsNoReturnCall)
      && isClosed fn
    | Returns(_, true) ->
      gap.FollowsLiterals && isClosed fn
    | CallsTail(_, true) | Unclear ->
      false

  let tryIndexOf lead =
    match lead with
    | Saves idx | Returns(idx, _) | CallsTail(idx, _) -> Some idx
    | Unclear -> None

  /// Tells whether the code leads somewhere sooner in the other instruction
  /// set, as the code that a linker puts after the Thumb start-up code of
  /// glibc is in ARM.
  let leadsSoonerInOther lead other =
    match tryIndexOf lead, tryIndexOf other with
    | Some idx, Some otherIdx -> otherIdx < idx
    | _ -> false

  /// Tells whether the code where the pointer leads, in the instruction set
  /// that its lowest bit names, shows a function starting, whatever the
  /// recovery has built there, while no ARM code nearby loads it as a literal.
  member _.ShowsEntry(pointer: Addr) =
    let addr = pointer &&& ~~~1UL
    lu.IsThumb <- pointer &&& 1UL = 1UL
    isDecodable addr && showsEntry addr && not (isLoadedFromNearby addr)

  /// Tells whether a function likely starts where the pointer leads: at code
  /// in the instruction set that its lowest bit names, which no function that
  /// the recovery has built covers, and which shows a function starting.
  member this.IsLikelyEntry(pointer: Addr) =
    not (AddrRangeUnion.containsAddr (pointer &&& ~~~1UL) covered)
    && this.ShowsEntry pointer

  /// Tells whether the code where the pointer leads, in the instruction set
  /// that its lowest bit names, only branches on: it reaches an unconditional
  /// branch through nothing but conditional ones, as a veneer does that a
  /// linker lays out to redirect a branch.
  member _.OnlyBranchesOn(pointer: Addr) =
    lu.IsThumb <- pointer &&& 1UL = 1UL
    onlyBranchesFrom (pointer &&& ~~~1UL) 3

  /// Tells whether the address lies in a literal that recovered code loads,
  /// which is data, whatever it decodes as.
  member _.IsInLoadedLiteral(addr: Addr) =
    AddrRangeUnion.containsAddr addr literals

  /// Tells whether code that the recovery has built covers the address.
  member _.Covers(addr: Addr) = AddrRangeUnion.containsAddr addr covered

  /// Finds where code resumes past the given function, which takes reading
  /// the function anew. Code of 32-bit ARM keeps each function in one piece,
  /// followed by the literals that it loads and padding, so the next function
  /// may start there.
  member _.TryFindGapPast(fn: Function) =
    match blocksOf fn with
    | [||] ->
      None
    | fnBlocks ->
      let first = fnBlocks[0].Instructions[0] :?> ARM32.Instruction
      let last = fnBlocks |> Array.maxBy (fun blk -> blk.Range.Max)
      let codeEnd = last.Range.Max + 1UL
      let built =
        fnBlocks
        |> Array.collect (fun blk -> blk.Instructions)
        |> Array.choose ARM32Code.tryLiteralRangeOf
        |> Array.toList
      lu.IsThumb <- first.IsThumb
      let literals =
        sweepLiterals built fn.EntryPoint codeEnd
        |> List.toArray
        |> AddrRangeUnion.ofArray
      let start, hasSkippedLiteral = skipGap literals codeEnd false
      Some
        { Start = start
          IsThumb = first.IsThumb
          FollowsLiterals = hasSkippedLiteral
          FollowsJump = ARM32Code.leaves last.LastInstruction
          FollowsNoReturnCall = callsUnconditionally last.LastInstruction }

  /// Finds the function that starts where code resumes past the given
  /// function, in the form that Identify gives, if one does.
  member _.TryFindStartIn(fn: Function, gap: ARM32Gap) =
    let lead = leadAt gap.Start gap.IsThumb
    let other = leadAt gap.Start (not gap.IsThumb)
    if startsFunction fn gap lead && not (leadsSoonerInOther lead other) then
      Some(if gap.IsThumb then gap.Start ||| 1UL else gap.Start)
    else
      None
