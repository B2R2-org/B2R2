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
open System.Runtime.CompilerServices
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.ControlFlowAnalysis.ExternalFunctionLoader
open B2R2.MiddleEnd.ControlFlowAnalysis.Strategies.FunctionIdentificationCommon

/// Represents a value that the code of a recovered function computes, with
/// whether it moves with the binary as the loader places it, as a value that
/// the code computes from the PC does.
[<Struct>]
type private ComputedValue = { Value: uint64; IsPlaced: bool }

/// Represents the function identification for SPARC. It takes what the binary
/// tells, as FunctionIdentification does, and then finds the functions that
/// the data of the binary points to, as neither GCC nor clang emits call frame
/// information for SPARC code that would tell every function up front, and
/// nothing calls a function that only a pointer leads to, such as one in a
/// table of callbacks. A word of data may name code that starts no function,
/// so it starts one only where the code shows a function starting, as
/// SPARCCode tells, which the code alone tells, so that the recovery knows
/// every such function before it starts. The same goes for an address that
/// recovered code computes and hands on: passes to a function, calls or
/// jumps to through a register, or stores, as _start passes main to
/// __libc_start_main and code passes callbacks. A binary that the loader may
/// place anywhere computes such an address from the PC, as PIC code finds its
/// GOT, so a number that the code computes otherwise names no address there.
/// Where code resumes past a recovered function, past the nops and the jump
/// tables that GCC lays before the function that uses them, a function starts
/// where the code shows one starting, as nothing else leads to a function that
/// nothing calls or points to.
type SPARCFunctionIdentification(hdl: BinHandle, exnInfo: ExceptionInfo) =
  let metadata = FunctionIdentification(hdl, exnInfo) :> IFunctionIdentifiable

  let file = hdl.File

  /// The address ranges of the code that a function may start in.
  let codeRanges = findCodeRanges file

  /// Tells whether the value names code of this binary that a function may
  /// start at: a word-aligned address in a section of such code, where no
  /// entry of the import table lies. The loader maps more than the sections,
  /// such as the headers of the file and read-only data, along with code, so
  /// a number that names an address there names no code.
  let isCodePointer (v: uint64) =
    v % 4UL = 0UL
    && codeRanges |> Array.exists (fun r -> r.IsIncluding v)
    && not (BinFileOps.isInImportTable file v)

  /// Names the sections that hold nothing but pointers and variables, whose
  /// every word that names code is a pointer.
  let pointerSectionNames =
    set [ ".data"
          ".data.rel.ro"
          ".fini_array"
          ".got"
          ".init_array"
          ".preinit_array" ]

  /// The size of a pointer, to which SPARC aligns one.
  let pointerSize = WordSize.toByteWidth hdl.ISA.WordSize |> uint64

  /// Returns the words of the section that name code, each with where it
  /// lies, reading one at every aligned slot.
  let readCodeWords (section: BinSection) =
    let first = (section.Address + pointerSize - 1UL) / pointerSize
    let last = (section.Address + section.Size) / pointerSize
    [| first * pointerSize .. pointerSize .. last * pointerSize - pointerSize |]
    |> Array.choose (fun slot ->
      match hdl.TryReadUInt(slot, int pointerSize) with
      | Ok v when isCodePointer v -> Some(slot, v)
      | _ -> None)

  /// Where the executable sections start, which no code runs into from above.
  let sectionStarts = findSectionStarts file

  let lu = hdl.NewLiftingUnit()

  /// The stubs of the imports that never return, as their names tell for
  /// sure, such as _exit.
  let noReturnStubs =
    let cc = hdl.Conventions.Calling
    let isNoRet (entry: BinImport) =
      ELF.getNoReturnStatusFromKnownFunc cc entry.Name = NoRet
    match file.ImportTable with
    | Some tbl ->
      tbl.Imports
      |> Seq.filter isNoRet
      |> Seq.choose (fun entry -> entry.TrampolineAddress)
      |> HashSet
    | None ->
      HashSet()

  /// Tells whether the function at the given address never returns, as the
  /// stub of an import that its name tells never to return.
  let neverReturns callee = noReturnStubs.Contains callee

  /// What the code at each address shows of a function starting there, as
  /// telling it takes lifting.
  let entryEvidence = Dictionary<Addr, bool>()

  /// Tells whether the code at the address shows a function starting there.
  let showsEntry addr =
    match entryEvidence.TryGetValue addr with
    | true, shows ->
      shows
    | false, _ ->
      let isSectionStart = sectionStarts.Contains addr
      let shows = SPARCCode.showsEntry lu neverReturns isSectionStart addr
      entryEvidence[addr] <- shows
      shows

  /// Splits the given words, which are in order, into runs of words that lie
  /// next to each other.
  let splitIntoRuns (words: (Addr * Addr)[]) =
    let runs = List<List<Addr>>()
    let mutable lastSlot = None
    for slot, v in words do
      match lastSlot with
      | Some last when slot = last + pointerSize -> runs[runs.Count - 1].Add v
      | _ -> runs.Add(List [ v ])
      lastSlot <- Some slot
    runs

  /// Returns the code addresses that the runs of words naming code in the
  /// read-only data hold, keeping only the runs whose every word names code
  /// that shows a function starting, as a table of callbacks holds nothing
  /// else.
  let readTablesOfCallbacks (section: BinSection) =
    readCodeWords section
    |> splitIntoRuns
    |> Seq.filter (Seq.forall showsEntry)
    |> Seq.concat
    |> Seq.toArray

  /// Returns the code addresses that the data sections of the binary hold as
  /// they are, at which the code shows a function starting.
  let storedEntries () =
    BinFileOps.getSections file
    |> Seq.collect (fun s ->
      if pointerSectionNames.Contains s.Name then
        readCodeWords s |> Array.map snd |> Array.filter showsEntry
      elif s.Name = ".rodata" then
        readTablesOfCallbacks s
      else
        [||])
    |> Seq.toArray

  /// Returns the code addresses in data at which the code shows a function
  /// starting. A binary that the loader relocates has one wherever a
  /// relocation writes one, and nowhere else, while one that stays where it is
  /// linked has its pointers in its data sections as they are.
  let findLikelyEntries () =
    if file.IsBaseRelative then
      relocatedValues file
      |> Seq.filter isCodePointer
      |> Seq.distinct
      |> Seq.filter showsEntry
      |> Seq.toArray
    else
      storedEntries () |> Array.distinct

  /// The registers in which a function receives its arguments.
  let argRegisters =
    [ SPARC.Register.O0
      SPARC.Register.O1
      SPARC.Register.O2
      SPARC.Register.O3
      SPARC.Register.O4
      SPARC.Register.O5 ]
    |> List.map SPARC.Register.toRegID

  /// Masks the value to the given width.
  let mask rt (v: uint64) =
    let width = RegType.toBitWidth rt
    if width >= 64 then v else v &&& ((1UL <<< width) - 1UL)

  let fold op (x: uint64) (y: uint64) =
    match op with
    | BinOpType.ADD -> Some(x + y)
    | BinOpType.SUB -> Some(x - y)
    | BinOpType.SHL when y < 64UL -> Some(x <<< int y)
    | BinOpType.SHR when y < 64UL -> Some(x >>> int y)
    | BinOpType.AND -> Some(x &&& y)
    | BinOpType.OR -> Some(x ||| y)
    | BinOpType.XOR -> Some(x ^^^ y)
    | _ -> None

  /// Tells whether what the operation yields moves with the binary, given
  /// whether its operands do: an address plus an offset does, while the
  /// distance between two addresses does not.
  let isPlacedBy op isLeftPlaced isRightPlaced =
    match op with
    | BinOpType.SUB -> isLeftPlaced && not isRightPlaced
    | _ -> isLeftPlaced || isRightPlaced

  /// Evaluates the expression to the constant that it is on every path, if
  /// any, given what the registers and the temporaries hold.
  let rec eval (regs: Map<RegisterID, ComputedValue>) temps pc e =
    match e with
    | Num(Value = bv) when bv.Length <= 64<rt> ->
      Some { Value = bv.ToUInt64(); IsPlaced = false }
    | PCVar _ ->
      Some { Value = pc; IsPlaced = true }
    | Var(RegisterID = r) ->
      Map.tryFind r regs
    | TempVar(Index = i) ->
      Map.tryFind i temps
    | BinOp(Op = op; Type = rt; Left = l; Right = r) ->
      match eval regs temps pc l, eval regs temps pc r with
      | Some x, Some y ->
        fold op x.Value y.Value
        |> Option.map (fun v ->
          { Value = mask rt v
            IsPlaced = isPlacedBy op x.IsPlaced y.IsPlaced })
      | _ ->
        None
    | Cast(Kind = CastKind.ZeroExt; Operand = x) ->
      eval regs temps pc x
    | Extract(Operand = x; Type = rt; StartPos = pos) ->
      eval regs temps pc x
      |> Option.map (fun k -> { k with Value = mask rt (k.Value >>> pos) })
    | _ ->
      None

  let update key value map =
    match value with
    | Some v -> Map.add key v map
    | None -> Map.remove key map

  /// Tells whether the instruction leaves for code of another function, with
  /// what the arguments hold: it calls, returns, jumps through a register, or
  /// calls as its tail by handing on the return address of its caller.
  let leavesFunction (ins: IInstruction) =
    ins.IsCall
    || ins.IsRET
    || ins.IsIndirectBranch
    || (ins :?> SPARC.Instruction).PassesReturnAddress

  /// Notes the values that the statement of the given instruction hands on:
  /// those of the arguments as the code leaves for another function, the
  /// address that it jumps to through a register, and the value that it
  /// stores.
  let noteHandedOn (found: HashSet<_>) (ins: IInstruction) regs temps stmt =
    let add k = found.Add k |> ignore
    let pc = ins.Address
    match stmt with
    | InterJmp(Target = target) when leavesFunction ins ->
      for r in argRegisters do Map.tryFind r regs |> Option.iter add
      if ins.IsIndirectBranch then eval regs temps pc target |> Option.iter add
      else ()
    | Store(Value = v) ->
      eval regs temps pc v |> Option.iter add
    | _ ->
      ()

  /// Applies the statements to what the registers hold, noting the values
  /// that they hand on if they are those of the given instruction. A
  /// temporary lives within one instruction, so a new instruction forgets
  /// them.
  let applyStmts found (ins: IInstruction option) regs (stmts: Stmt[]) =
    let pc = ins |> Option.map _.Address |> Option.defaultValue 0UL
    let mutable regs = regs
    let mutable temps = Map.empty
    for stmt in stmts do
      match stmt with
      | ISMark _ ->
        temps <- Map.empty
      | Put(Dst = Var(RegisterID = r); Src = src) ->
        regs <- update r (eval regs temps pc src) regs
      | Put(Dst = TempVar(Index = i); Src = src) ->
        temps <- update i (eval regs temps pc src) temps
      | stmt ->
        ins |> Option.iter (fun ins -> noteHandedOn found ins regs temps stmt)
    regs

  /// Applies the block to what the registers hold: each instruction, or what
  /// the callee does, as its summary tells.
  let transfer found regs (blk: ILowUIRBasicBlock) =
    if blk.IsAbstract then
      applyStmts found None regs blk.AbstractContent.Rundown
    else
      blk.LiftedInstructions
      |> Array.fold (fun regs lifted ->
        applyStmts found (Some lifted.Original) regs lifted.Stmts) regs

  /// Meets what two ways into a block know: what both know alike.
  let meet (a: Map<RegisterID, ComputedValue>) b =
    a |> Map.filter (fun r k -> Map.tryFind r b = Some k)

  /// Returns the values that the code of the function hands on, as the
  /// registers hold them on every way there.
  let readHandedOn (fn: Function) =
    let cfg = fn.CFG
    let found = HashSet<ComputedValue>()
    let incoming = Dictionary<IVertex<LowUIRBasicBlock>, Map<_, _>>()
    let work = Queue<IVertex<LowUIRBasicBlock>>()
    for root in cfg.Roots do
      incoming[root] <- Map.empty
      work.Enqueue root
    while work.Count > 0 do
      let v = work.Dequeue()
      let out = transfer found incoming[v] v.VData.Internals
      for succ in cfg.GetSuccs v do
        match incoming.TryGetValue succ with
        | true, prev ->
          let next = meet prev out
          if next.Count <> prev.Count then
            incoming[succ] <- next
            work.Enqueue succ
          else
            ()
        | false, _ ->
          incoming[succ] <- out
          work.Enqueue succ
    found
    |> Seq.filter (fun k -> k.IsPlaced || not file.IsBaseRelative)
    |> Seq.toArray

  /// The values that the code of each recovered function hands on, by its
  /// CFG, with the counts of its vertices and edges, as reading them takes
  /// walking the whole function, while most functions stay the same from
  /// round to round of identification.
  let handedOnByCFG = ConditionalWeakTable<LowUIRCFG, _>()

  /// Returns the values that the code of the function hands on, reading them
  /// anew only once the function has changed.
  let valuesHandedOnBy fn = readOnce handedOnByCFG readHandedOn fn

  /// Tells whether the value that recovered code hands on surely starts a
  /// function: it names code that shows a function starting, and the code
  /// computes the value from the PC, or the code there turns the window
  /// first. Code of a binary that stays where it is linked builds a number in
  /// the same way as an address, so a number may name code by chance, such
  /// as a block that a function jumps to.
  let surelyStartsFunction (k: ComputedValue) =
    isCodePointer k.Value
    && showsEntry k.Value
    && (k.IsPlaced || SPARCCode.turnsWindowAt lu k.Value)

  /// Returns what the blocks that the recovery has built for the function
  /// cover, along with the delay slots of their last instructions, which run
  /// with them.
  let readBuiltCode (fn: Function) =
    fn.CFG.Vertices
    |> Array.filter (fun v -> not v.VData.Internals.IsAbstract)
    |> Array.map (fun v ->
      let blk = v.VData.Internals
      let last = blk.LastInstruction
      AddrRange.create blk.Range.Min (last.Address + uint64 last.Extent - 1UL))
    |> AddrRangeUnion.ofArray

  /// What the blocks of each recovered function cover, by its CFG, with the
  /// counts of its vertices and edges, as telling it takes every block of the
  /// function.
  let builtCodeByCFG = ConditionalWeakTable<LowUIRCFG, _>()

  /// Returns what the blocks that the recovery has built for the function
  /// cover, reading them anew only once the function has changed.
  let findBuiltCode fn = readOnce builtCodeByCFG readBuiltCode fn

  /// Returns where the given code that the recovery has built ends, past its
  /// last block, if it has built any.
  let tryFindCodeEnd (built: AddrRangeUnion) =
    Array.tryLast built.Ranges |> Option.map (fun range -> range.Max + 1UL)

  /// Tells whether the code at the address, where code resumes past a
  /// recovered function, shows a function starting there.
  let showsEntryPastCode addr =
    SPARCCode.showsEntryPastCode lu neverReturns addr

  /// Tells whether the code of the function at the given entry, of which the
  /// recovery has built the given code, jumps to the given address where code
  /// resumes past it. The code that the recovery has yet to build is the
  /// function's own up to where it shows another function starting.
  let jumpsAhead entry built start =
    let startsAnother addr =
      not (AddrRangeUnion.containsAddr addr built) && showsEntryPastCode addr
    SPARCCode.jumpsAhead lu entry start startsAnother

  /// Tells whether the given vertex of the CFG calls an external function that
  /// never returns, which its name tells for sure, such as abort, unlike what
  /// the recovery finds of a function of the binary, which it may yet find to
  /// return.
  let callsNoReturnExternal (cfg: LowUIRCFG) v =
    cfg.GetSuccs v
    |> Array.exists (fun w ->
      let bbl = w.VData.Internals
      bbl.IsAbstract
      && bbl.AbstractContent.IsExternal
      && bbl.AbstractContent.ReturningStatus = NoRet)

  /// Tells whether the code that the recovery has built for the function ends
  /// the flow where it ends, at the given address, as the last instruction of
  /// its last block, with its delay slot, returns or jumps, or calls an
  /// external function that never returns.
  let endsFlowAt (fn: Function) codeEnd =
    fn.CFG.Vertices
    |> Array.exists (fun v ->
      let bbl = v.VData.Internals
      not bbl.IsAbstract
      && (let last = bbl.LastInstruction
          last.Address + uint64 last.Extent = codeEnd
          && (SPARCCode.leaves last || callsNoReturnExternal fn.CFG v)))

  /// Tells whether the code where code resumes past the given function, at the
  /// given start past the end of its code, shows a function starting there,
  /// either by the code right above the start, or, past code of the function
  /// that ends the flow, by the code at the start alone.
  let showsEntryPast fn codeEnd start =
    showsEntryPastCode start
    || (endsFlowAt fn codeEnd
        && SPARCCode.showsEntryPastFlowEnd lu neverReturns start)

  /// Returns where code resumes past each of the given functions: past the end
  /// of its code and what fills space past it, before the next entry, where no
  /// code of a function at or before it reaches, along with the function, what
  /// the recovery has built of it, and where that ends.
  let findResumes internals =
    withNextEntries internals
    |> Array.fold (fun (reach, starts) (fn: Function, next) ->
      let built = findBuiltCode fn
      match tryFindCodeEnd built with
      | Some codeEnd ->
        let reach = max reach codeEnd
        let start = SPARCCode.skipFiller lu codeEnd next
        if start < next && start >= reach then
          reach, (fn, built, codeEnd, start) :: starts
        else
          reach, starts
      | None ->
        reach, starts) (0UL, [])
    |> snd

  /// Tells whether the code at the given start, past the given function,
  /// jumps first into what the recovery has built of the function between its
  /// entry and the start, as code of the function does that the compiler
  /// leaves past the rest of it, which nothing reaches.
  let jumpsBackInto (fn: Function) built start =
    match SPARCCode.tryFindFirstJumpTarget lu start with
    | Some target ->
      fn.EntryPoint < target
      && target < start
      && AddrRangeUnion.containsAddr target built
    | None ->
      false

  /// Returns where code resumes past each of the given functions, as
  /// findResumes finds, where the code shows a function starting and the code
  /// of the function does not jump, as it does to a block of its own that the
  /// recovery has yet to build, nor the code there into the function. Nothing
  /// else leads to a function that nothing calls or points to.
  let findNextStarts internals =
    findResumes internals
    |> List.filter (fun (fn, built, codeEnd, start) ->
      isCodePointer start
      && showsEntryPast fn codeEnd start
      && not (jumpsAhead fn.EntryPoint built start)
      && not (jumpsBackInto fn built start))
    |> List.map (fun (_, _, _, start) -> start)
    |> List.toArray

  /// Returns where the direct jumps of the function go, rather than its calls.
  let readJumpTargets (fn: Function) =
    fn.CFG.Vertices
    |> Array.choose (fun v ->
      let blk = v.VData.Internals
      if blk.IsAbstract || blk.LastInstruction.IsCall then
        None
      else
        match blk.LastInstruction.DirectBranchTarget() with
        | true, target -> Some target
        | false, _ -> None)

  /// Where the direct jumps of each recovered function go, by its CFG, with
  /// the counts of its vertices and edges.
  let jumpTargetsByCFG = ConditionalWeakTable<LowUIRCFG, _>()

  /// Returns the addresses that the code that the recovery has built for the
  /// given functions jumps to.
  let findJumpTargets internals =
    internals
    |> Array.collect (readOnce jumpTargetsByCFG readJumpTargets)
    |> HashSet

  /// Tells whether the value that recovered code hands on starts a function
  /// once the recovery has built every function that anything else leads to:
  /// it names code that shows a function starting, which no code that the
  /// recovery has built jumps to, as the given set tells.
  let startsFunctionAtLast (jumpTargets: HashSet<Addr>) (k: ComputedValue) =
    isCodePointer k.Value
    && showsEntry k.Value
    && not (jumpTargets.Contains k.Value)

  /// Returns where more functions start in the given recovered functions:
  /// where the values that they hand on surely start one, and where code
  /// resumes past them. Once these find no more, where the values that they
  /// hand on start one at last, as the recovery has then built every function
  /// that anything else leads to, which tells the blocks that they jump to.
  let findMore (internals: Function[]) =
    let known = internals |> Array.map _.EntryPoint |> HashSet
    let isNew addr = not (known.Contains addr)
    let handedOn =
      internals |> Array.collect valuesHandedOnBy |> Array.distinct
    let found =
      handedOn
      |> Array.filter surelyStartsFunction
      |> Array.map _.Value
      |> Array.append (findNextStarts internals)
      |> Array.distinct
      |> Array.filter isNew
    if Array.isEmpty found then
      let jumpTargets = findJumpTargets internals
      handedOn
      |> Array.filter (startsFunctionAtLast jumpTargets)
      |> Array.map _.Value
      |> Array.filter isNew
    else
      found

  interface IIncrementalFunctionIdentifiable with
    member _.Identify() =
      Array.append (metadata.Identify()) (findLikelyEntries ())
      |> Array.distinct

    member _.IdentifyMore recovered =
      recovered
      |> Array.filter (fun fn -> not fn.IsExternal)
      |> findMore
