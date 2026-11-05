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
open B2R2.Collections
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Provides what address ranges cover together as an interval set, merging
/// the ranges that overlap or touch. Telling whether an address lies in any of
/// them needs no more, and far fewer ranges build an interval set far sooner,
/// which matters as identification builds one for all the recovered code
/// every round.
[<RequireQualifiedAccess>]
module internal AddrRangeUnion =
  /// Returns an interval set of what the given ranges cover together.
  let ofArray (ranges: AddrRange[]) =
    ranges
    |> Array.sortBy (fun range -> range.Min)
    |> Array.fold (fun (merged: AddrRange list) range ->
      match merged with
      | last :: rest when range.Min <= last.Max + 1UL ->
        AddrRange.create last.Min (max last.Max range.Max) :: rest
      | _ ->
        range :: merged) []
    |> IntervalSet.ofSeq

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
type internal ARM32EntryEvidence(hdl, recovered, toCalleeAddr) =
  let cc = (hdl: BinHandle).Conventions.Calling

  let lu = hdl.NewLiftingUnit()

  let blocksOf (fn: Function) =
    fn.CFG.Vertices
    |> Array.filter (fun v -> not v.VData.Internals.IsAbstract)
    |> Array.map (fun v -> v.VData.Internals)

  let blocks =
    (recovered: Function[])
    |> Array.filter (fun fn -> not fn.IsExternal)
    |> Array.collect blocksOf

  let covered =
    blocks |> Array.map (fun blk -> blk.Range) |> AddrRangeUnion.ofArray

  let isDecodable addr = lu.TryParseInstruction(addr: Addr) |> Result.isOk

  let instructions = blocks |> Array.collect (fun blk -> blk.Instructions)

  /// Returns how many bytes the load reads, if it reads a literal pool.
  let tryLiteralSizeOf (ins: ARM32.Instruction) =
    match ins.Opcode, ins.Operands with
    | ARM32.Opcode.LDR, _ ->
      Some 4UL
    | ARM32.Opcode.VLDR,
      ARM32.TwoOperands(ARM32.OprSIMD(ARM32.SFReg(ARM32.Vector r)), _)
      when r >= ARM32.Register.D0 && r <= ARM32.Register.D31 ->
      Some 8UL
    | ARM32.Opcode.VLDR, _ ->
      Some 4UL
    | _ ->
      None

  /// Returns where the literal that the instruction loads lies, if it loads
  /// one.
  let tryLiteralRangeOf (ins: IInstruction) =
    match ins.MemoryDereferences() with
    | true, [| addr |] ->
      tryLiteralSizeOf (ins :?> ARM32.Instruction)
      |> Option.map (fun size -> AddrRange.create addr (addr + size - 1UL))
    | _ ->
      None

  let literalRanges =
    instructions |> Array.choose tryLiteralRangeOf |> Array.distinct

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

  /// Returns the instruction that decodes right above the address, in the
  /// instruction set the lifting unit is in.
  let tryDecodeAbove addr =
    let endsAt (ins: IInstruction) = ins.Address + uint64 ins.Length = addr
    [ 4UL; 2UL ]
    |> List.filter (fun size -> addr >= size)
    |> List.tryPick (fun size ->
      match lu.TryParseInstruction(addr - size) with
      | Ok ins when endsAt ins -> Some ins
      | _ -> None)

  /// Returns the instruction that ends right at the address, telling whether
  /// the recovery has built it: the one built there, or else the one that
  /// decodes there.
  let tryFindAbove addr =
    match instructionsByEnd.TryGetValue addr with
    | true, ins -> Some(ins, true)
    | false, _ -> tryDecodeAbove addr |> Option.map (fun ins -> ins, false)

  let isConditional (ins: ARM32.Instruction) =
    match ins.Condition with
    | ARM32.Condition.AL | ARM32.Condition.NV | ARM32.Condition.UN -> false
    | _ -> true

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
    if isConditional (ins :?> ARM32.Instruction) then
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

  /// Tells whether the register keeps its value for the caller of a function
  /// that writes it: one that the convention has the callee save, or the link
  /// register, which holds where the function returns.
  let isPreserved r =
    r = ARM32.Register.LR || cc.IsCalleeSaved(ARM32.Register.toRegID r)

  /// Tells whether the instruction saves a preserved register on the stack.
  let saves (ins: ARM32.Instruction) =
    match ins.Opcode, ins.Operands with
    | (ARM32.Opcode.PUSH | ARM32.Opcode.VPUSH),
      ARM32.OneOperand(ARM32.OprRegList regs) ->
      List.exists isPreserved regs
    | (ARM32.Opcode.STMDB | ARM32.Opcode.VSTMDB),
      ARM32.TwoOperands(ARM32.OprReg ARM32.Register.SP,
                        ARM32.OprRegList regs) ->
      ins.WriteBack && List.exists isPreserved regs
    | _ ->
      false

  /// Tells whether the code from the address saves a preserved register on
  /// the stack within the given number of instructions, before it branches.
  let rec savesFrom addr count =
    if count = 0 then
      false
    else
      match lu.TryParseInstruction(addr: Addr) with
      | Ok ins when saves (ins :?> ARM32.Instruction) -> true
      | Ok ins when ins.IsBranch || ins.IsExit -> false
      | Ok ins -> savesFrom (addr + uint64 ins.Length) (count - 1)
      | Error _ -> false

  /// Tells whether the code at the address shows a function starting there.
  let showsEntry addr =
    match hintAbove addr with
    | Supports -> true
    | Neutral -> savesFrom addr 4
    | Refutes -> false

  /// The farthest that a load lies from the literal it loads: an offset from
  /// the PC reaches 4095 bytes, and the PC reads 8 bytes past the load in ARM.
  let [<Literal>] LiteralReach = 4104UL

  /// Tells whether code within reach of the address loads a literal that
  /// covers it, reading an instruction at every word, as the code that loads
  /// it may be code that the recovery has yet to build, such as a case of a
  /// switch that a literal pool amid the switch serves. Only ARM code is read
  /// this way, as one halfword in 32 reads as a load of a literal in Thumb,
  /// whether it is data, ARM code or the second half of a Thumb instruction.
  let isLoadedFromNearby (addr: Addr) =
    let covers ins =
      match tryLiteralRangeOf ins with
      | Some(range: AddrRange) -> range.IsIncluding addr
      | None -> false
    let rec scan (insAddr: Addr) =
      if insAddr > addr + LiteralReach then
        false
      else
        match lu.TryParseInstruction insAddr with
        | Ok ins when covers ins -> true
        | _ -> scan (insAddr + 4UL)
    not lu.IsThumb && scan ((addr - min addr LiteralReach) / 4UL * 4UL)

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
          match tryLiteralRangeOf ins with
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
  /// on: the given literals, none of which overlap, padding and nops.
  let rec skipGap literals (addr: Addr) =
    match IntervalSet.tryFindOverlappingOneByAddr addr literals with
    | Some(range: AddrRange) ->
      skipGap literals (range.Max + 1UL)
    | None ->
      match tryPaddingSize addr with
      | Some size ->
        skipGap literals (addr + size)
      | None ->
        match lu.TryParseInstruction addr with
        | Ok ins when ins.IsNop -> skipGap literals (addr + uint64 ins.Length)
        | _ -> addr

  /// Returns which of the first two instructions from the address saves a
  /// preserved register, after nothing but an instruction that runs whenever
  /// it is reached and goes on to the next.
  let trySaveIndex addr =
    let rec find (addr: Addr) idx =
      if idx = 2 then
        None
      else
        match lu.TryParseInstruction addr with
        | Ok ins ->
          let arm = ins :?> ARM32.Instruction
          if saves arm then Some idx
          elif ins.IsBranch || ins.IsExit || ins.IsInterrupt then None
          elif isConditional arm then None
          else find (addr + uint64 ins.Length) (idx + 1)
        | Error _ ->
          None
    find addr 0

  /// Tells whether the code at the address saves a preserved register first
  /// thing in the given instruction set, and no later than it would in the
  /// other one, as the code that a linker puts after the Thumb start-up code
  /// of glibc is in ARM.
  let savesFirst addr isThumb =
    lu.IsThumb <- not isThumb
    let other = trySaveIndex addr
    lu.IsThumb <- isThumb
    match trySaveIndex addr, other with
    | Some idx, Some otherIdx -> idx <= otherIdx
    | Some _, None -> true
    | None, _ -> false

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
    not (IntervalSet.containsAddr (pointer &&& ~~~1UL) covered)
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
    IntervalSet.containsAddr addr literals

  /// Tells whether code that the recovery has built covers the address.
  member _.Covers(addr: Addr) = IntervalSet.containsAddr addr covered

  /// Finds where the function after the given one may start, in the form that
  /// Identify gives, by the code of the given function alone. Code of 32-bit
  /// ARM keeps each function in one piece, followed by the literals that it
  /// loads and padding, so the code past them starts the next function if it
  /// saves a preserved register first thing, which no code in the middle of
  /// a function does.
  member _.TryFindStartPast(fn: Function) =
    match blocksOf fn with
    | [||] ->
      None
    | fnBlocks ->
      let first = fnBlocks[0].Instructions[0] :?> ARM32.Instruction
      let codeEnd =
        fnBlocks |> Array.map (fun blk -> blk.Range.Max + 1UL) |> Array.max
      let built =
        fnBlocks
        |> Array.collect (fun blk -> blk.Instructions)
        |> Array.choose tryLiteralRangeOf
        |> Array.toList
      lu.IsThumb <- first.IsThumb
      let literals =
        sweepLiterals built fn.EntryPoint codeEnd
        |> List.toArray
        |> AddrRangeUnion.ofArray
      let addr = skipGap literals codeEnd
      if savesFirst addr first.IsThumb then
        Some(if first.IsThumb then addr ||| 1UL else addr)
      else
        None
