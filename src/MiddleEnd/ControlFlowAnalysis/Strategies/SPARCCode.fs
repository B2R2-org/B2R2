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
open B2R2.FrontEnd.SPARC

/// Provides what SPARC code tells on its own of where a function starts. The
/// ABI of Linux hands a function its arguments in %o0 to %o5 and in the
/// floating-point registers, the address to return to in %o7, the stack
/// pointer in %o6 and the thread pointer in %g7, and a function keeps the %l
/// and %i of its caller, which it may change only once SAVE has turned the
/// window, which gives it its own. Code that reads another register before it
/// writes it, or changes an %l or an %i without having turned the window,
/// runs on what code above left there and starts no function, which code that
/// a switch jumps to does on the way to the end of the switch. A function
/// first turns the window, or lies where no code runs into it: the code above
/// returns, jumps, traps, pads with a nop, or calls a function that never
/// returns.
module internal SPARCCode =
  /// Returns the IDs of the registers from the first up to the last, which
  /// SPARC numbers one after another.
  let private idsFrom (first: Register) (last: Register) =
    [ int first .. int last ] |> List.map RegisterID.create

  /// The most instructions that the reading of where a function may start goes
  /// through.
  let [<Literal>] private MaxLeadLength = 24

  /// Adds the registers that the expression reads to the set.
  let rec private addReads (reads: HashSet<RegisterID>) e =
    match e with
    | Var(RegisterID = rid) ->
      reads.Add rid |> ignore
    | BinOp(Left = e1; Right = e2) | RelOp(Left = e1; Right = e2) ->
      addReads reads e1
      addReads reads e2
    | UnOp(Operand = e) | Cast(Operand = e) | Extract(Operand = e)
    | Load(Addr = e) ->
      addReads reads e
    | Ite(Cond = c; TrueExpr = e1; FalseExpr = e2) ->
      addReads reads c
      addReads reads e1
      addReads reads e2
    | RoundCtrl(Mode = mode; Body = body) ->
      addReads reads mode
      addReads reads body
    | ExprList(Elements = es) ->
      for e in es do addReads reads e
    | _ ->
      ()

  /// The stack pointer.
  let private sp = Register.toRegID Register.O6

  /// Substitutes the definitions of the temporaries of an instruction for
  /// them, given what each holds.
  let rec private resolve (temps: Dictionary<int, Expr>) e =
    match e with
    | TempVar(Index = n) when temps.ContainsKey n -> resolve temps temps[n]
    | _ -> e

  /// Returns the constant by which the value moves the stack pointer, if it
  /// does.
  let private tryMoveOfStack temps e =
    match resolve temps e with
    | BinOp(Op = BinOpType.ADD; Left = Var(RegisterID = rid); Right = Num n)
      when rid = sp ->
      Some(n.ToInt64())
    | _ ->
      None

  /// Represents what an instruction does with registers: the ones that it
  /// reads before it writes them, the ones that it writes, whether it turns
  /// the window to one of its own, and whether it takes room on the stack or
  /// gives some back.
  type private Effect =
    { Reads: HashSet<RegisterID>
      Writes: HashSet<RegisterID>
      mutable TurnsWindow: bool
      mutable Allocates: bool
      mutable Frees: bool }

  /// Notes what the statement does with registers in the effect, given what
  /// the temporaries of the instruction hold so far.
  let private note (eff: Effect) (temps: Dictionary<int, Expr>) stmt =
    let addNew e =
      let reads = HashSet<RegisterID>()
      addReads reads e
      reads.ExceptWith eff.Writes
      eff.Reads.UnionWith reads
    match stmt with
    | Put(Dst = TempVar(Index = n); Src = src) ->
      addNew src
      temps[n] <- src
    | Put(Dst = Var(RegisterID = rid); Src = src) ->
      addNew src
      if rid = sp then
        match tryMoveOfStack temps src with
        | Some n when n < 0L -> eff.Allocates <- true
        | Some n when n > 0L -> eff.Frees <- true
        | _ -> ()
      else
        ()
      eff.Writes.Add rid |> ignore
    | Store(Addr = addr; Value = v) ->
      addNew addr
      addNew v
    | InterJmp(Target = e) | CJmp(Cond = e) ->
      addNew e
    | InterCJmp(Cond = c; TrueTarget = t; FalseTarget = f) ->
      addNew c
      addNew t
      addNew f
    | SideEffect(Effect = SaveWindow) ->
      eff.TurnsWindow <- true
    | _ ->
      ()

  /// Returns what the instruction, with its delay slot, does with registers,
  /// as its IR tells.
  let private effectOf (lu: LiftingUnit) (ins: IInstruction) =
    let eff =
      { Reads = HashSet()
        Writes = HashSet()
        TurnsWindow = false
        Allocates = false
        Frees = false }
    let temps = Dictionary<int, Expr>()
    for stmt in lu.LiftInstruction ins do note eff temps stmt done
    eff

  /// The registers that hold what a function receives from its caller: its
  /// arguments, the address to return to, the stack pointer, the thread
  /// pointer, and %g0, which holds zero.
  let private received =
    [ idsFrom Register.G0 Register.G0
      idsFrom Register.G7 Register.G7
      idsFrom Register.O0 Register.O7
      idsFrom Register.F0 Register.F62 ]
    |> List.concat
    |> HashSet

  /// The registers of the window of the caller, which a function changes only
  /// in a window of its own.
  let private windowed = idsFrom Register.L0 Register.I7 |> HashSet

  /// Tells whether the instruction reads a register that the function has not
  /// received and that the code on the way to it has not written, or changes
  /// one of the window of the caller without having turned the window, or
  /// gives back room on the stack that the code on the way has not taken, as
  /// code right past a call to a function that never returns does with what
  /// its function took for the call.
  let private isLeftoverUse eff (written: Set<_>) turned took =
    eff.Reads
    |> Seq.exists (fun r -> not (received.Contains r || written.Contains r))
    || (not turned && Seq.exists windowed.Contains eff.Writes)
    || (eff.Frees && not (turned || took))

  /// The registers that a call may change: the volatile ones, which hold
  /// what the callee returns, and the condition codes.
  let private clobberedByCall =
    [ idsFrom Register.G1 Register.G5
      idsFrom Register.O0 Register.O5
      idsFrom Register.O7 Register.O7
      idsFrom Register.Y Register.Y
      idsFrom Register.F0 Register.F62
      idsFrom Register.CCN Register.CCC ]
    |> List.concat
    |> Set.ofList

  /// Tells whether the instruction calls a function that never returns, as
  /// the given test tells of the callee.
  let private callsNoReturn neverReturns (ins: IInstruction) =
    match ins.DirectBranchTarget() with
    | true, callee -> neverReturns callee
    | false, _ -> false

  /// Returns where the code goes past the instruction, given the registers
  /// written so far: past a call and its delay slot, which changes the
  /// volatile registers, unless the callee never returns, as the given test
  /// tells; and where the instruction goes on otherwise.
  let private successorsOf (ins: IInstruction) neverReturns written =
    if ins.IsCall then
      let next = ins.Address + uint64 ins.Extent
      if callsNoReturn neverReturns ins then []
      else [ next, Set.union written clobberedByCall ]
    else
      ins.GetNextInstrAddrs() |> Array.map (fun a -> a, written) |> Array.toList

  /// Tells whether the code from the given start, along any way that it goes
  /// within MaxLeadLength instructions, reads a register that code above left,
  /// changes one of the window of the caller without having turned the window,
  /// or gives back room on the stack that it has not taken. Code that does not
  /// decode may do anything. Code past a call to a
  /// function that never returns, as the given test tells of the callee, runs
  /// only from a branch to it, if at all.
  let private readsLeftover (lu: LiftingUnit) neverReturns (start: Addr) =
    let work = Stack<Addr * Set<RegisterID> * bool * bool>()
    let visited = HashSet<Addr>()
    let mutable found = false
    work.Push(start, Set.empty, false, false)
    while not found && work.Count > 0 && visited.Count < MaxLeadLength do
      let addr, written, turned, took = work.Pop()
      if visited.Add addr then
        match lu.TryParseInstruction addr with
        | Ok ins ->
          let eff = effectOf lu ins
          let turned = turned || eff.TurnsWindow
          if isLeftoverUse eff written turned took then
            found <- true
          else
            let written = Set.union written (Set.ofSeq eff.Writes)
            let took = took || eff.Allocates
            for next, written in successorsOf ins neverReturns written do
              work.Push(next, written, turned, took)
        | Error _ ->
          found <- true
      else
        ()
    found

  /// Tells whether the instruction turns the window to one of its own, which
  /// is how a function that calls others sets up its frame.
  let private turnsWindow (ins: IInstruction) =
    (ins :?> Instruction).Opcode = Opcode.SAVE

  /// Tells whether the instruction jumps right past the given address, within
  /// the code that the reading of where a function starts goes through, as
  /// code that skips one way of an if-else to the code after it does.
  let private jumpsJustPast (addr: Addr) (ins: IInstruction) =
    match ins.DirectBranchTarget() with
    | true, target ->
      let leadEnd = addr + 4UL * uint64 MaxLeadLength
      not ins.IsCall && addr < target && target < leadEnd
    | false, _ ->
      false

  /// Tells whether the code right above the address ends the flow, as the
  /// given test tells: the transfer whose delay slot lies right above, or else
  /// the instruction right above. An address right past a transfer is its
  /// delay slot, which runs with the transfer rather than starts anything,
  /// and code that jumps right past the address runs on into the code there,
  /// which the address only starts another way to.
  let private hasFlowEndAbove (lu: LiftingUnit) (addr: Addr) endsFlow =
    let tryParseAbove offset =
      if offset <= addr then
        lu.TryParseInstruction(addr - offset) |> Result.toOption
      else
        None
    let endsFlowBefore ins = endsFlow ins && not (jumpsJustPast addr ins)
    match tryParseAbove 4UL with
    | Some above when (above :?> Instruction).HasDelaySlot ->
      false
    | above ->
      match tryParseAbove 8UL with
      | Some transfer when transfer.Extent = 8u -> endsFlowBefore transfer
      | _ -> above |> Option.exists endsFlowBefore

  /// Tells whether the code at the address reads no register that code above
  /// may have left, nor changes one of the window of the caller before turning
  /// the window, and turns the window first or lies where no code runs into
  /// it: it lies apart, as it starts its section, or the code above ends the
  /// flow, as the given test tells. Code that starts with a nop pads functions
  /// apart rather than starts one, and code that traps starts nothing.
  let private startsCleanly lu neverReturns liesApart endsFlow (addr: Addr) =
    match (lu: LiftingUnit).TryParseInstruction(addr) with
    | Ok ins when not (ins.IsNop || ins.IsExit) ->
      not (readsLeftover lu neverReturns addr)
      && (turnsWindow ins || liesApart || hasFlowEndAbove lu addr endsFlow)
    | _ ->
      false

  /// Tells whether code that ends with the instruction runs into nothing past
  /// it: it returns or jumps, traps, or pads with a nop.
  let leaves (ins: IInstruction) =
    ins.IsNop
    || ins.IsExit
    || (ins.IsBranch && not ins.IsCondBranch && not ins.IsCall)

  /// Tells whether the code at the address shows a function starting there,
  /// given whether it starts its section, where code above that leaves or
  /// calls ends the flow, as a call may never return. Code past a call to a
  /// function that never returns, as the given test tells of the callee, runs
  /// only from a branch to it.
  let showsEntry lu neverReturns isSectionStart addr =
    let endsFlow ins = leaves ins || (ins: IInstruction).IsCall
    startsCleanly lu neverReturns isSectionStart endsFlow addr

  /// Tells whether the code at the address shows a function starting there,
  /// as showsEntry does, where code resumes past what the recovery has built
  /// for a function. A call right above runs into it then, as the recovery
  /// builds code only so far as it takes the callees to return, which it may
  /// yet find that one does that it took for one that never returns.
  let showsEntryPastCode lu neverReturns addr =
    startsCleanly lu neverReturns false leaves addr

  /// Tells whether the code at the address shows a function starting there,
  /// as showsEntry does, where code resumes past what the recovery has built
  /// for a function, which ends the flow where it ends, as nothing past that
  /// code then runs into the address, whatever lies between.
  let showsEntryPastFlowEnd lu neverReturns addr =
    startsCleanly lu neverReturns true leaves addr

  /// Tells whether the instruction fills space between functions rather than
  /// runs: a nop that pads them apart, or ILLTRAP, which a word of a jump
  /// table that GCC lays in .text before its function reads as, as does the
  /// word that follows a call to a function that never returns.
  let private isFiller (ins: IInstruction) =
    ins.IsNop || (ins :?> Instruction).Opcode = Opcode.ILLTRAP

  /// Tells whether the words from the address up to the given end are nops.
  let rec private isNopsUpTo (lu: LiftingUnit) (addr: Addr) endAddr =
    addr >= endAddr
    || (match lu.TryParseInstruction addr with
        | Ok ins when ins.IsNop -> isNopsUpTo lu (addr + 4UL) endAddr
        | _ -> false)

  /// Tells whether the instruction branches ahead whatever happens, without
  /// running the word past it, as BA,a does.
  let private skipsAhead (ins: IInstruction) target =
    ins.IsBranch
    && not (ins.IsCondBranch || ins.IsCall)
    && ins.Extent = 4u
    && target > ins.Address

  /// Returns where the instruction skips the nops past it to, if it does: GNU
  /// as pads a long way to an alignment with BA,a over the nops that fill it.
  let private tryFindPaddingEnd lu (ins: IInstruction) =
    match ins.DirectBranchTarget() with
    | true, target when skipsAhead ins target ->
      if isNopsUpTo lu (ins.Address + 4UL) target then Some target else None
    | _ ->
      None

  /// Returns where code resumes from the address, before the given end, past
  /// what fills space between functions.
  let skipFiller (lu: LiftingUnit) (addr: Addr) endAddr =
    let rec skip (addr: Addr) =
      if addr >= endAddr then
        addr
      else
        match lu.TryParseInstruction addr with
        | Ok ins when isFiller ins ->
          skip (addr + 4UL)
        | Ok ins ->
          match tryFindPaddingEnd lu ins with
          | Some next -> skip next
          | None -> addr
        | Error _ ->
          addr
    skip addr

  /// Tells whether the instruction jumps to the given address, rather than
  /// calls code there.
  let private jumpsTo target (ins: IInstruction) =
    match ins.DirectBranchTarget() with
    | true, t -> t = target && not ins.IsCall
    | false, _ -> false

  /// Tells whether code from the address up to the given target, read one
  /// instruction after another, jumps to the target, as a function does to a
  /// block of its own that it lays past the rest of its code, such as one that
  /// calls a function that never returns. The reading stops where the given
  /// test tells that the code of another function starts, as such a function
  /// may jump to the target as its tail. Code that does not decode tells
  /// nothing, and the reading resumes at the next word.
  let jumpsAhead (lu: LiftingUnit) (addr: Addr) target startsAnother =
    let rec scan (addr: Addr) =
      if addr >= target || startsAnother addr then
        false
      else
        match lu.TryParseInstruction addr with
        | Ok ins -> jumpsTo target ins || scan (addr + 4UL)
        | Error _ -> scan (addr + 4UL)
    scan addr

  /// Returns where the first transfer from the address goes, if it is a jump
  /// rather than a call and goes to a fixed address.
  let tryFindFirstJumpTarget (lu: LiftingUnit) (addr: Addr) =
    let rec scan count (addr: Addr) =
      if count = 0 then
        None
      else
        match lu.TryParseInstruction addr with
        | Ok ins when ins.IsBranch && not ins.IsCall ->
          match ins.DirectBranchTarget() with
          | true, target -> Some target
          | false, _ -> None
        | Ok ins when ins.IsTerminator null ->
          None
        | Ok _ ->
          scan (count - 1) (addr + 4UL)
        | Error _ ->
          None
    scan MaxLeadLength addr
