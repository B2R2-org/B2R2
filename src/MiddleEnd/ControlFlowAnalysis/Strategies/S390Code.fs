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
open B2R2.FrontEnd.S390

/// Provides what S390 code tells on its own of where a function starts. The
/// ABI of Linux hands a function its arguments in R2 to R6 and in F0, F2, F4
/// and F6, the address to return to in R14 and the stack pointer in R15, and
/// has it save R6 to R13 and F8 to F15 before it changes any of them, for its
/// caller. Code that reads another register before it writes it, or changes
/// one that it has to save without having saved it, runs on what code above
/// left there and starts no function, which code that a switch jumps to does
/// on the way to the end of the switch. A function first sets up its frame,
/// saving registers or taking room on the stack, or lies where no code runs
/// into it: the code above returns, jumps, traps, pads with a nop, or calls a
/// function that never returns.
module internal S390Code =
  /// Returns the IDs of the registers from the first up to the last, which
  /// S390 numbers one after another.
  let private idsFrom (first: Register) (last: Register) =
    [ int first .. int last ] |> List.map RegisterID.create

  /// The most instructions that the reading of where a function may start goes
  /// through.
  let [<Literal>] private MaxLeadLength = 24

  /// Tells whether the instruction runs another one that the code picks as it
  /// runs, which the IR reads every register for.
  let private executes (ins: IInstruction) =
    let op = (ins :?> Instruction).Opcode
    op = Opcode.EX || op = Opcode.EXRL

  /// The stack pointer.
  let private sp = Register.toRegID Register.R15

  /// Tells whether the number keeps one word of a doubleword as it is when
  /// ANDed with it, as an instruction does that writes only the other word of
  /// a register.
  let private isWordMask (n: BitVector) =
    let v = n.ToUInt64()
    v = 0xFFFFFFFF00000000UL || v = 0x00000000FFFFFFFFUL

  /// Adds the registers that the expression reads to the set, leaving out the
  /// given register where the expression keeps one word of it as it is, as
  /// the instruction that writes the other word reads nothing of it.
  let rec private addReads (reads: HashSet<RegisterID>) kept e =
    match e with
    | Var(RegisterID = rid) ->
      reads.Add rid |> ignore
    | BinOp(Op = BinOpType.AND; Left = Var(RegisterID = rid); Right = Num n)
      when Some rid = kept && isWordMask n ->
      ()
    | BinOp(Left = e1; Right = e2) | RelOp(Left = e1; Right = e2) ->
      addReads reads kept e1
      addReads reads kept e2
    | UnOp(Operand = e) | Cast(Operand = e) | Extract(Operand = e)
    | Load(Addr = e) ->
      addReads reads kept e
    | Ite(Cond = c; TrueExpr = e1; FalseExpr = e2) ->
      addReads reads kept c
      addReads reads kept e1
      addReads reads kept e2
    | RoundCtrl(Mode = mode; Body = body) ->
      addReads reads kept mode
      addReads reads kept body
    | ExprList(Elements = es) ->
      for e in es do addReads reads kept e
    | _ ->
      ()

  /// Substitutes the definitions of the temporaries of an instruction for
  /// them, given what each holds.
  let rec private resolve (temps: Dictionary<int, Expr>) e =
    match e with
    | TempVar(Index = n) when temps.ContainsKey n -> resolve temps temps[n]
    | _ -> e

  /// Tells whether the value moves the stack pointer down by a constant,
  /// taking room on the stack.
  let private allocates temps e =
    match resolve temps e with
    | BinOp(Op = BinOpType.ADD; Left = Var(RegisterID = rid); Right = Num n) ->
      rid = sp && n.ToUInt64() >>> 63 = 1UL
    | _ ->
      false

  /// Tells whether the address is one that the stack pointer gives.
  let rec private isOnStack temps e =
    match resolve temps e with
    | Var(RegisterID = rid) ->
      rid = sp
    | BinOp(Op = BinOpType.ADD; Left = e1; Right = e2) ->
      isOnStack temps e1 || isOnStack temps e2
    | _ ->
      false

  /// Represents what an instruction does with registers: the ones that it
  /// reads before it writes them, the ones that it writes, the ones that it
  /// saves on the stack, and whether it takes room on the stack.
  type private Effect =
    { Reads: HashSet<RegisterID>
      Writes: HashSet<RegisterID>
      Saves: HashSet<RegisterID>
      mutable Allocates: bool }

  /// Notes what the statement does with registers in the effect, given what
  /// the temporaries of the instruction hold so far.
  let private note (eff: Effect) (temps: Dictionary<int, Expr>) stmt =
    let addNew e kept =
      let reads = HashSet<RegisterID>()
      addReads reads kept e
      reads.ExceptWith eff.Writes
      eff.Reads.UnionWith reads
    match stmt with
    | Put(Dst = TempVar(Index = n); Src = src) ->
      addNew src None
      temps[n] <- src
    | Put(Dst = Var(RegisterID = rid); Src = src) ->
      addNew src (Some rid)
      if rid = sp && allocates temps src then eff.Allocates <- true else ()
      eff.Writes.Add rid |> ignore
    | Store(Addr = addr; Value = Var(RegisterID = rid))
      when isOnStack temps addr ->
      addNew addr None
      eff.Saves.Add rid |> ignore
    | Store(Addr = addr; Value = v) ->
      addNew addr None
      addNew v None
    | InterJmp(Target = e) | CJmp(Cond = e) ->
      addNew e None
    | InterCJmp(Cond = c; TrueTarget = t; FalseTarget = f) ->
      addNew c None
      addNew t None
      addNew f None
    | _ ->
      ()

  /// Returns what the instruction does with registers, as its IR tells.
  let private effectOf (lu: LiftingUnit) (ins: IInstruction) =
    let eff =
      { Reads = HashSet()
        Writes = HashSet()
        Saves = HashSet()
        Allocates = false }
    let temps = Dictionary<int, Expr>()
    for stmt in lu.LiftInstruction ins do note eff temps stmt done
    eff

  /// The registers that hold what a function receives from its caller: its
  /// arguments, the address to return to, the stack pointer, and the thread
  /// pointer, which the access registers hold.
  let private received =
    [ idsFrom Register.R2 Register.R6
      idsFrom Register.R14 Register.R15
      idsFrom Register.FPR0 Register.FPR0
      idsFrom Register.FPR2 Register.FPR2
      idsFrom Register.FPR4 Register.FPR4
      idsFrom Register.FPR6 Register.FPR6
      idsFrom Register.VR24 Register.VR31
      idsFrom Register.AR0 Register.AR1 ]
    |> List.concat
    |> HashSet

  /// The registers that a function saves before it changes them.
  let private preserved =
    [ idsFrom Register.R6 Register.R13
      idsFrom Register.FPR8 Register.FPR15 ]
    |> List.concat
    |> HashSet

  /// Tells whether the instruction reads a register that it has not received
  /// and that the code on the way to it has not written, or changes one that
  /// it has to save without having saved it.
  let private isLeftoverUse eff (written: Set<_>) (saved: Set<_>) =
    eff.Reads
    |> Seq.exists (fun r -> not (received.Contains r || written.Contains r))
    || eff.Writes
       |> Seq.exists (fun r -> preserved.Contains r && not (saved.Contains r))

  /// The registers that a call may change: the volatile ones, which hold
  /// what the callee returns, and the condition code.
  let private clobberedByCall =
    [ idsFrom Register.R0 Register.R5
      idsFrom Register.R14 Register.R14
      idsFrom Register.FPR0 Register.FPR7
      idsFrom Register.CC Register.CC ]
    |> List.concat
    |> Set.ofList

  /// Returns where the code goes past the instruction, given the registers
  /// written so far: past a call, which changes the volatile registers, to
  /// the next instruction; past a branch, to its direct target, and to the
  /// next instruction as well if it branches on a condition; nowhere past an
  /// indirect jump, an exit, or an interrupt; and to the next one otherwise.
  let private successorsOf (ins: IInstruction) written =
    let next = ins.Address + uint64 ins.Length
    if ins.IsCall then
      [ next, Set.union written clobberedByCall ]
    elif ins.IsBranch then
      let target =
        match ins.DirectBranchTarget() with
        | true, t -> [ t, written ]
        | false, _ -> []
      if ins.IsCondBranch then (next, written) :: target else target
    elif ins.IsExit || ins.IsInterrupt then
      []
    else
      [ next, written ]

  /// Tells whether the code from the address, along any way that it goes
  /// within MaxLeadLength instructions, reads a register that code above left,
  /// or changes one that it has to save without having saved it. Code that does
  /// not decode may do anything, while code past an instruction that runs
  /// another one tells nothing more.
  let private readsLeftover (lu: LiftingUnit) (addr: Addr) =
    let work = Stack<Addr * Set<RegisterID> * Set<RegisterID>>()
    let visited = HashSet<Addr>()
    let mutable found = false
    work.Push(addr, Set.empty, Set.empty)
    while not found && work.Count > 0 && visited.Count < MaxLeadLength do
      let addr, written, saved = work.Pop()
      if visited.Add addr then
        match lu.TryParseInstruction addr with
        | Ok ins when executes ins ->
          ()
        | Ok ins ->
          let eff = effectOf lu ins
          let saved = Set.union saved (Set.ofSeq eff.Saves)
          if isLeftoverUse eff written saved then
            found <- true
          else
            let written = Set.union written (Set.ofSeq eff.Writes)
            for next, written in successorsOf ins written do
              work.Push(next, written, saved)
        | Error _ ->
          found <- true
      else
        ()
    found

  /// Tells whether the instruction sets up the frame of a function: it saves
  /// the return address or a register that it has to save on the stack, or
  /// takes room there.
  let private setsUpFrame lu ins =
    let eff = effectOf lu ins
    eff.Allocates
    || eff.Saves
       |> Seq.exists (fun r -> r = Register.toRegID Register.R14
                               || preserved.Contains r)

  /// Tells whether an instruction that ends right at the address ends the
  /// flow, as the given test tells, at any length that one decodes at, as
  /// nothing tells where the instruction above an address starts.
  let private hasFlowEndAbove (lu: LiftingUnit) (addr: Addr) endsFlow =
    [ 2UL; 4UL; 6UL ]
    |> List.exists (fun len ->
      len <= addr
      && match lu.TryParseInstruction(addr - len) with
         | Ok ins -> uint64 ins.Length = len && endsFlow ins
         | Error _ -> false)

  /// Tells whether the code at the address reads no register that code above
  /// may have left, nor changes one that it has to save before saving it, and
  /// sets up a frame first or lies where no code runs into it: it starts its
  /// section, or the instruction above ends the flow, as the given test tells.
  /// Code that starts with a nop pads functions apart rather than starts one.
  let private startsCleanly lu isSectionStart endsFlow (addr: Addr) =
    match (lu: LiftingUnit).TryParseInstruction(addr) with
    | Ok ins when not ins.IsNop ->
      not (readsLeftover lu addr)
      && (setsUpFrame lu ins
          || isSectionStart
          || hasFlowEndAbove lu addr endsFlow)
    | _ ->
      false

  /// Tells whether code that ends with the instruction runs into nothing past
  /// it: it returns or jumps, traps, or pads with a nop.
  let private leaves (ins: IInstruction) =
    ins.IsNop
    || ins.IsExit
    || (ins.IsBranch && not ins.IsCondBranch && not ins.IsCall)

  /// Tells whether the code at the address shows a function starting there,
  /// given whether it starts its section, where code above that leaves or
  /// calls ends the flow, as a call may never return.
  let showsEntry lu isSectionStart addr =
    startsCleanly lu isSectionStart (fun ins -> leaves ins || ins.IsCall) addr

  /// Tells whether the code at the address shows a function starting there,
  /// as showsEntry does, where code resumes past what the recovery has built
  /// for a function. A call right above runs into it then, as the recovery
  /// builds code only so far as it takes the callees to return, which it may
  /// yet find that one does that it took for one that never returns.
  let showsEntryPastCode lu isSectionStart addr =
    startsCleanly lu isSectionStart leaves addr

  /// Returns the address that the instruction names, counting halfwords from
  /// itself, if its opcode is the given one.
  let private tryRelativeAddress opcode (ins: Instruction) =
    match ins.Operands with
    | TwoOperands(_, OpRImm(ImmS32 halfwords)) when ins.Opcode = opcode ->
      Some(ins.Address + uint64 (2L * int64 halfwords))
    | _ ->
      None

  /// Returns the address that the instruction takes as a constant, if it does:
  /// the one that LARL loads, counting halfwords from the instruction, as code
  /// does that passes a callback or stores a function pointer.
  let tryTakenAddress ins = tryRelativeAddress Opcode.LARL ins

  /// Returns the address of the instruction that the given one runs, if it is
  /// EXRL, which picks the length that the instruction there works on.
  let tryExecutedAddress ins = tryRelativeAddress Opcode.EXRL ins

  /// Tells whether the instruction is shaped as a template that EXRL runs: it
  /// works on two operands in storage, a byte long by its own length, as EXRL
  /// ORs the length that a register holds into it. clang lays such templates
  /// past the functions of a source file, where they read as code that starts
  /// a function.
  let private isTemplate (ins: Instruction) =
    match ins.Operands with
    | TwoOperands(OpStoreLen(1us, _, _), _) -> ins.Fmt = InstructionFormat.SS
    | _ -> false

  /// Returns where code resumes from the address, before the given end, past
  /// the nops that pad functions apart and the templates that EXRL runs.
  let skipPadding (lu: LiftingUnit) (addr: Addr) endAddr =
    let rec skip (addr: Addr) =
      if addr >= endAddr then
        addr
      else
        match lu.TryParseInstruction addr with
        | Ok ins when ins.IsNop || isTemplate (ins :?> Instruction) ->
          skip (addr + uint64 ins.Length)
        | _ ->
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
  /// nothing, and the reading resumes at the next halfword.
  let jumpsAhead (lu: LiftingUnit) (addr: Addr) target startsAnother =
    let rec scan (addr: Addr) =
      if addr >= target || startsAnother addr then
        false
      else
        match lu.TryParseInstruction addr with
        | Ok ins -> jumpsTo target ins || scan (addr + uint64 ins.Length)
        | Error _ -> scan (addr + 2UL)
    scan addr
