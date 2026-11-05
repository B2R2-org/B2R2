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
open B2R2.ABI
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.Collections
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.ControlFlowAnalysis.ExternalFunctionLoader

/// Represents the constants that every path to a point holds: in registers,
/// and in the temporaries of the instruction it is in.
type private Knowns =
  { Registers: Map<RegisterID, uint64>
    Temps: Map<int, uint64> }

/// Represents a call that a recovered function makes, with the constants that
/// registers hold as the call starts.
type private CallSite =
  { Instruction: IInstruction
    Values: Map<RegisterID, uint64> }

/// Represents the function identification for 32-bit ARM. It takes what the
/// binary tells, as FunctionIdentification does, and then finds more in what
/// the recovery builds. A code address that recovered code calls starts a
/// function: as an argument that an external function is known to call, as
/// __libc_start_main calls main, or as the constant target of an indirect
/// call. A jump that leaves its function for code outside of it, up to the
/// next function, calls a function as its tail, as code of 32-bit ARM keeps
/// each function in one piece. A code address that the data of the binary
/// holds may name a label instead, whose address GNU C lets a program take,
/// so it starts a function only once the code there shows one starting, as
/// ARM32EntryEvidence tells, which the target of such a jump also has to.
type ARM32FunctionIdentification(hdl: BinHandle, exnInfo: ExceptionInfo) =
  let metadata = FunctionIdentification(hdl, exnInfo) :> IFunctionIdentifiable

  let file = hdl.File

  let cc = hdl.Conventions.Calling

  let wordMask = 0xFFFFFFFFUL

  /// Tells whether only the loader writes to the given address: memory that
  /// stays read-only once loaded, or the GOT, which code only reads.
  let isStable addr =
    match file with
    | :? ELFBinFile as elf ->
      elf.IsReadOnlyAfterLoading addr
      || BinFileOps.tryFindSectionNameByAddr file addr = Ok ".got"
    | _ ->
      file.IsExecutableAddr addr

  /// Reads the word at the given address as the loader leaves it: what a
  /// relocation writes there, or what the file holds where only the loader
  /// writes.
  let tryReadWord addr =
    match BinFileOps.tryComputeRelocationValue file addr with
    | Ok v -> Some(v &&& wordMask)
    | Error _ when isStable addr -> Result.toOption (hdl.TryReadUInt(addr, 4))
    | Error _ -> None

  let fold op (x: uint64) (y: uint64) =
    match op with
    | BinOpType.ADD -> Some(x + y)
    | BinOpType.SUB -> Some(x - y)
    | BinOpType.MUL -> Some(x * y)
    | BinOpType.SHL when y < 32UL -> Some(x <<< int y)
    | BinOpType.SHR when y < 32UL -> Some(x >>> int y)
    | BinOpType.AND -> Some(x &&& y)
    | BinOpType.OR -> Some(x ||| y)
    | BinOpType.XOR -> Some(x ^^^ y)
    | _ -> None

  let extract (v: uint64) rt pos =
    let width = RegType.toBitWidth rt
    let v = v >>> pos
    if width >= 64 then v else v &&& ((1UL <<< width) - 1UL)

  /// Evaluates the expression to the constant that it is on every path, if any,
  /// reading memory only where the loader leaves it as the binary says.
  let rec eval (knowns: Knowns) pc e =
    match e with
    | Num(Value = bv) ->
      Some(bv.ToUInt64())
    | PCVar _ ->
      Some pc
    | Var(RegisterID = r) ->
      Map.tryFind r knowns.Registers
    | TempVar(Index = i) ->
      Map.tryFind i knowns.Temps
    | BinOp(Op = op; Type = rt; Left = l; Right = r) when rt = 32<rt> ->
      match eval knowns pc l, eval knowns pc r with
      | Some x, Some y -> fold op x y |> Option.map (fun v -> v &&& wordMask)
      | _ -> None
    | Load(Type = rt; Addr = a) when rt = 32<rt> ->
      eval knowns pc a |> Option.bind tryReadWord
    | Extract(Operand = x; Type = rt; StartPos = pos) ->
      eval knowns pc x |> Option.map (fun v -> extract v rt pos)
    | Cast(Kind = CastKind.ZeroExt; Operand = x) ->
      eval knowns pc x
    | _ ->
      None

  let update key value map =
    match value with
    | Some v -> Map.add key v map
    | None -> Map.remove key map

  /// Applies the statement to what the path knows. A temporary lives within
  /// one instruction, so a new instruction forgets them.
  let step knowns pc stmt =
    match stmt with
    | ISMark _ ->
      { knowns with Temps = Map.empty }
    | Put(Dst = Var(RegisterID = r); Src = src) ->
      let regs = update r (eval knowns pc src) knowns.Registers
      { knowns with Registers = regs }
    | Put(Dst = TempVar(Index = i); Src = src) ->
      { knowns with Temps = update i (eval knowns pc src) knowns.Temps }
    | _ ->
      knowns

  /// Notes the call that starts with the given instruction, as the registers
  /// hold before the call writes the link register.
  let noteCall (calls: Dictionary<Addr, CallSite>) knowns lifted =
    let ins = (lifted: LiftedInstruction).Original
    match lifted.Stmts with
    | [||] ->
      ()
    | stmts ->
      match stmts[0] with
      | ISMark _ when ins.IsCall ->
        calls[ins.Address] <- { Instruction = ins; Values = knowns.Registers }
      | _ ->
        ()

  /// Applies the block to what a path knows. A callee may write any register
  /// that its caller saves, so a call forgets those.
  let transfer calls knowns (blk: ILowUIRBasicBlock) =
    if blk.IsAbstract then
      let isKept r _ = not (cc.IsCallerSaved r)
      { Registers = Map.filter isKept knowns.Registers; Temps = Map.empty }
    else
      blk.LiftedInstructions
      |> Array.fold (fun knowns lifted ->
        noteCall calls knowns lifted
        let pc = lifted.Original.Address
        lifted.Stmts |> Array.fold (fun k s -> step k pc s) knowns) knowns

  let join a b =
    { Registers =
        Map.filter (fun r v -> Map.tryFind r b.Registers = Some v) a.Registers
      Temps = Map.filter (fun i v -> Map.tryFind i b.Temps = Some v) a.Temps }

  let propagate (knownsAt: Dictionary<_, Knowns>) (work: Queue<_>) succ out =
    match knownsAt.TryGetValue succ with
    | true, old ->
      let joined = join old out
      if joined <> old then
        knownsAt[succ] <- joined
        work.Enqueue succ
      else
        ()
    | false, _ ->
      knownsAt[succ] <- out
      work.Enqueue succ

  /// Finds the calls that the function makes, each with the constants that
  /// registers hold on every path to it.
  let findCalls (fn: Function) =
    let cfg = fn.CFG
    let calls = Dictionary<Addr, CallSite>()
    let knownsAt = Dictionary<IVertex<LowUIRBasicBlock>, Knowns>()
    let work = Queue<IVertex<LowUIRBasicBlock>>()
    for root in cfg.Roots do
      knownsAt[root] <- { Registers = Map.empty; Temps = Map.empty }
      work.Enqueue root
    while work.Count > 0 do
      let v = work.Dequeue()
      let out = transfer calls knownsAt[v] v.VData.Internals
      for succ in cfg.GetSuccs v do propagate knownsAt work succ out
    calls.Values

  /// The calls that each recovered function makes, by its CFG, which stays the
  /// same until the function is built again, along with how many edges the CFG
  /// had then. A round of identification thus runs the data flow only over the
  /// functions built since the last round.
  let callsByCFG =
    System.Runtime.CompilerServices.ConditionalWeakTable<LowUIRCFG, _>()

  let findCallsOnce (fn: Function) =
    match callsByCFG.TryGetValue fn.CFG with
    | true, (edgeCount, calls) when edgeCount = fn.CFG.EdgeCount ->
      calls
    | _ ->
      let calls = Seq.toArray (findCalls fn)
      callsByCFG.AddOrUpdate(fn.CFG, (fn.CFG.EdgeCount, calls))
      calls

  /// Returns the address of the function that a call to the given target
  /// enters, as the recovery takes it: the trampoline of the PLT entry that
  /// covers the target, which a call that switches Thumb code to ARM enters
  /// past the Thumb stub starting it, or else the target itself.
  let toCalleeAddr target =
    match file with
    | :? ELFBinFile as elf ->
      elf.TryFindTrampoline target |> Option.defaultValue target
    | _ ->
      target

  /// Returns the constant that the argument of the given index holds as the
  /// call starts, if the argument is passed in a register.
  let tryArgOf (site: CallSite) idx =
    match cc.GetIntArgLocation idx with
    | ArgLocation.Reg r -> Map.tryFind r site.Values
    | _ -> None

  /// Returns the constant that an indirect call jumps to through a register.
  let tryTargetOf (site: CallSite) =
    match site.Instruction with
    | :? ARM32.Instruction as ins ->
      match ins.Operands with
      | ARM32.OneOperand(ARM32.OprReg reg) ->
        Map.tryFind (ARM32.Register.toRegID reg) site.Values
      | _ ->
        None
    | _ ->
      None

  /// Finds the code addresses that the call proves to start functions.
  let prove (externals: Dictionary<Addr, string>) (site: CallSite) =
    match site.Instruction.DirectBranchTarget() with
    | true, target ->
      match externals.TryGetValue(toCalleeAddr target) with
      | true, name ->
        ELF.getCallbackArgsOfKnownFunc name |> List.choose (tryArgOf site)
      | false, _ ->
        []
    | false, _ ->
      Option.toList (tryTargetOf site)

  /// Lists the address ranges of the sections that link the binary to others,
  /// such as a PLT.
  let linkageRanges =
    BinFileOps.getSections file
    |> Seq.filter (fun s -> s.Kind = DynamicLinkageSection && s.Size > 0UL)
    |> Seq.map (fun s -> AddrRange.create s.Address (s.Address + s.Size - 1UL))
    |> Seq.toArray

  /// Tells whether the address lies in code that links the binary to others,
  /// which serves imports rather than starting functions: an entry of the
  /// import table, or the code that binds such entries as the PLT starts.
  let isInLinkage addr =
    BinFileOps.isInImportTable file addr
    || linkageRanges |> Array.exists (fun r -> r.IsIncluding addr)

  /// Tells whether a call to the given address enters code of this binary in
  /// an instruction set that a function can start in: Thumb as the lowest bit
  /// says, or ARM at a word.
  let isCodePointer (v: uint64) =
    let addr = v &&& ~~~1UL
    file.IsExecutableAddr addr
    && not (isInLinkage addr)
    && (v &&& 1UL = 1UL || v &&& 3UL = 0UL)

  /// Returns the names of the external functions by the addresses that calls
  /// reach them at, without the tag of a reference to a function of this
  /// binary.
  let namesOfExternals (functions: Function[]) =
    let names = Dictionary<Addr, string>()
    for fn in functions do
      if fn.IsExternal then names[fn.EntryPoint] <- fn.Name.Split('@')[0]
      else ()
    names

  /// Names the sections that hold nothing but pointers.
  let pointerSectionNames =
    set [ ".fini_array"
          ".got"
          ".init_array"
          ".preinit_array" ]

  /// Names the sections that hold pointers among other data.
  let dataSectionNames =
    set [ ".data"
          ".data.rel.ro"
          ".rodata" ]

  /// Returns the values that the loader writes where it relocates the binary.
  let relocatedValues () =
    match file.Relocations with
    | Some relocs ->
      relocs.Relocations
      |> Seq.choose (fun reloc ->
        relocs.TryComputeRelocationValue reloc.Address |> Result.toOption)
    | None ->
      Seq.empty

  /// Returns the words that the section holds.
  let readWords (section: BinSection) =
    if section.Size < 4UL then
      [||]
    else
      [| section.Address .. 4UL .. section.Address + section.Size - 4UL |]
      |> Array.map (fun addr -> hdl.TryReadUInt(addr, 4))
      |> Array.map (Result.defaultValue 0UL)

  /// Tells whether a word next to the one at the given index is an address of
  /// the binary. Pointers sit together, in tables and in structures, while a
  /// number that happens to look like a code address sits among numbers.
  let hasAddressNext (words: uint64[]) idx =
    [ idx - 1; idx + 1 ]
    |> List.exists (fun i ->
      i >= 0 && i < words.Length && file.IsValidAddr words[i])

  /// Returns the words of the section that may be pointers.
  let pointersIn (section: BinSection) =
    if pointerSectionNames.Contains section.Name then
      readWords section
    elif dataSectionNames.Contains section.Name then
      let words = readWords section
      words
      |> Array.indexed
      |> Array.filter (fun (idx, _) -> hasAddressNext words idx)
      |> Array.map snd
    else
      [||]

  /// Returns the words that the data sections of the binary may point with.
  let storedValues () =
    BinFileOps.getSections file |> Seq.collect pointersIn

  /// Lists the code addresses that the data of the binary holds, in the form
  /// that Identify gives. A binary that the loader relocates has one wherever a
  /// relocation writes one, and nowhere else, while one that stays where it is
  /// linked has its pointers in its data sections as they are.
  let dataPointers =
    let values =
      if file.IsBaseRelative then relocatedValues () else storedValues ()
    values
    |> Seq.map (fun v -> v &&& wordMask)
    |> Seq.filter isCodePointer
    |> Seq.distinct
    |> Seq.toArray

  /// Pairs each of the recovered functions that the binary defines, in the
  /// order of their entries, with the entry of the next one.
  let withNextEntries (recovered: Function[]) =
    let internals =
      recovered
      |> Array.filter (fun fn -> not fn.IsExternal)
      |> Array.sortBy (fun fn -> fn.EntryPoint)
    internals
    |> Array.mapi (fun i fn ->
      if i + 1 < internals.Length then fn, internals[i + 1].EntryPoint
      else fn, System.UInt64.MaxValue)

  /// Checks if the recovery followed the jump that ends the given vertex
  /// within its function, rather than took it for a tail call.
  let isFollowedWithin (cfg: LowUIRCFG) v =
    cfg.GetSuccEdges v |> Array.exists (fun e -> e.Label = InterJmpEdge)

  /// Returns where the direct jump that ends the given vertex goes, if the
  /// recovery followed it within its function.
  let tryFollowedTarget cfg (v: IVertex<LowUIRBasicBlock>) =
    match v.VData.Internals.Terminator with
    | InterJmp(Target = Num(Value = n); Kind = InterJmpKind.Base)
      when isFollowedWithin cfg v ->
      Some(n.ToUInt64())
    | _ ->
      None

  /// Returns where the given instruction jumps to in the form that Identify
  /// gives, with the lowest bit set for Thumb, as a direct jump stays in its
  /// instruction set.
  let toPointer (ins: IInstruction) target =
    if (ins :?> ARM32.Instruction).IsThumb then target ||| 1UL else target

  /// Finds the jumps that leave the given function, each as the vertex that it
  /// ends, its address, and where it goes in the form that Identify gives: the
  /// direct jumps that the recovery followed from within the function, from
  /// its entry up to the given next entry, to code outside of it.
  let findLeavingJumps next (fn: Function) =
    let isWithin addr = fn.EntryPoint <= addr && addr < next
    fn.CFG.Vertices
    |> Array.filter (fun v -> not v.VData.Internals.IsAbstract)
    |> Array.choose (fun v ->
      let ins = v.VData.Internals.LastInstruction
      match tryFollowedTarget fn.CFG v with
      | Some target when isWithin ins.Address && not (isWithin target) ->
        Some(v, ins.Address, toPointer ins target)
      | _ ->
        None)

  /// Collects the ranges of the blocks that the given function reaches from
  /// its roots without leaving it through the given vertices.
  let collectHomeRanges (fn: Function) (exits: HashSet<_>) =
    let cfg = fn.CFG
    let visited = HashSet<IVertex<LowUIRBasicBlock>>()
    let work = Queue<IVertex<LowUIRBasicBlock>>(cfg.Roots)
    let ranges = List<AddrRange>()
    while work.Count > 0 do
      let v = work.Dequeue()
      let blk = v.VData.Internals
      if visited.Add v then
        if blk.IsAbstract then () else ranges.Add blk.Range
        if exits.Contains v then ()
        else for succ in cfg.GetSuccs v do work.Enqueue succ
      else
        ()
    ranges.ToArray()

  /// The jumps that leave each recovered function and the code that it covers
  /// but for what it reaches only through them, by its CFG, with the count of
  /// its edges and the next entry that they hold for, as finding them takes
  /// walking the whole CFG, while most functions stay the same from round to
  /// round.
  let leavingByCFG =
    System.Runtime.CompilerServices.ConditionalWeakTable<LowUIRCFG, _>()

  /// Finds the jumps that leave the given function, up to the given next
  /// entry, and the code that it covers but for what it reaches only through
  /// them.
  let findLeavingOnce (fn: Function, next) =
    let cfg = fn.CFG
    match leavingByCFG.TryGetValue cfg with
    | true, (edgeCount, nextOfCache, leaving)
      when edgeCount = cfg.EdgeCount && nextOfCache = next ->
      leaving
    | _ ->
      let jumps = findLeavingJumps next fn
      let exits = HashSet(Array.map (fun (v, _, _) -> v) jumps)
      let leaving = jumps, collectHomeRanges fn exits
      leavingByCFG.AddOrUpdate(cfg, (cfg.EdgeCount, next, leaving))
      leaving

  /// Checks if the given jump that leaves its function decodes from data or
  /// lands on data: it or where it goes lies in a literal that recovered code
  /// loads, as when the recovery reads a literal pool as code.
  let isAmidData (evidence: ARM32EntryEvidence) (_, jmpAddr, pointer) =
    evidence.IsInLoadedLiteral jmpAddr
    || evidence.IsInLoadedLiteral(pointer &&& ~~~1UL)

  /// Finds the code addresses that jumps leaving their functions prove to start
  /// functions, in the form that Identify gives. Code of 32-bit ARM keeps each
  /// function in one piece, so such a jump enters another function, at its
  /// entry unless hand-written code shares its middle or a linker redirects
  /// the jump through a veneer: the code there has to show a function
  /// starting without only branching on, and no function may cover it but
  /// through such a jump. A jump amid data proves nothing.
  let proveByTailCalls (evidence: ARM32EntryEvidence) recovered =
    let leaving = withNextEntries recovered |> Array.map findLeavingOnce
    let home = leaving |> Array.collect snd |> AddrRangeUnion.ofArray
    leaving
    |> Array.collect fst
    |> Array.filter (not << isAmidData evidence)
    |> Array.map (fun (_, _, pointer) -> pointer)
    |> Array.distinct
    |> Array.filter (fun pointer ->
      not (IntervalSet.containsAddr (pointer &&& ~~~1UL) home)
      && evidence.ShowsEntry pointer
      && not (evidence.OnlyBranchesOn pointer))

  /// Where the function past each recovered one may start, by the entry of the
  /// recovered one and the end of what the recovery has built of it, as
  /// telling it takes reading that code anew, round after round.
  let startsPast = Dictionary<Addr * Addr, Addr option>()

  /// Returns the end of what the recovery has built of the function.
  let codeEndOf (fn: Function) =
    fn.CFG.Vertices
    |> Array.filter (fun v -> not v.VData.Internals.IsAbstract)
    |> Array.fold (fun e v -> max e (v.VData.Internals.Range.Max + 1UL)) 0UL

  let tryFindStartPast (evidence: ARM32EntryEvidence) (fn: Function) =
    let key = fn.EntryPoint, codeEndOf fn
    match startsPast.TryGetValue key with
    | true, start ->
      start
    | false, _ ->
      let start = evidence.TryFindStartPast fn
      startsPast[key] <- start
      start

  /// Checks if the pointer leads before the next entry, to code that no
  /// recovered function covers.
  let isFreeBefore (evidence: ARM32EntryEvidence) next pointer =
    let addr = pointer &&& ~~~1UL
    addr < next && not (evidence.Covers addr)

  /// Finds where the functions that follow the recovered ones start, in the
  /// form that Identify gives, which covers functions that nothing calls or
  /// points to, such as dead code that a linker keeps.
  let findNextStarts evidence recovered =
    withNextEntries recovered
    |> Array.choose (fun (fn, next) ->
      tryFindStartPast evidence fn
      |> Option.filter (isFreeBefore evidence next))

  interface IIncrementalFunctionIdentifiable with
    member _.Identify() = metadata.Identify()

    member _.IdentifyMore recovered =
      let externals = namesOfExternals recovered
      let evidence = ARM32EntryEvidence(hdl, recovered, toCalleeAddr)
      recovered
      |> Seq.filter (fun fn -> not fn.IsExternal)
      |> Seq.collect findCallsOnce
      |> Seq.collect (prove externals)
      |> Seq.append (proveByTailCalls evidence recovered)
      |> Seq.append (findNextStarts evidence recovered)
      |> Seq.filter isCodePointer
      |> Seq.append (Array.filter evidence.IsLikelyEntry dataPointers)
      |> Seq.distinct
      |> Seq.toArray
