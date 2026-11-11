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
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.ControlFlowAnalysis.ExternalFunctionLoader

/// Represents what a register or a temporary holds on every path to a point:
/// a constant, telling whether it moves with the binary as the loader places
/// it, as an address does that the code computes from the PC or reads where
/// the loader writes one, or the argument of the given index as the function
/// received it.
type private Known =
  | Const of value: uint64 * isPlaced: bool
  | Arg of int

/// Represents what every path to a point holds: in registers, and in the
/// temporaries of the instruction it is in.
type private Knowns =
  { Registers: Map<RegisterID, Known>
    Temps: Map<int, Known> }

/// Represents a call that a recovered function makes, also as its tail, with
/// what registers hold as the call starts.
type private CallSite =
  { Instruction: IInstruction
    Values: Map<RegisterID, Known> }

/// Represents the calls that a recovered function makes, with the indices of
/// the arguments that it calls through a register as it received them, the
/// jumps through a register with which it calls such an argument as its tail,
/// and the constants that it stores to memory, among which are the function
/// pointers that it sets for calls to go through.
type private Calls =
  { Sites: CallSite[]
    CalledArgs: int list
    ArgJumps: Addr[]
    StoredConstants: uint64[] }

/// Represents the function identification for 32-bit ARM. It takes what the
/// binary tells, as FunctionIdentification does, and then finds more in what
/// the recovery builds. A code address that recovered code calls starts a
/// function: as an argument that an external function is known to call, as
/// __libc_start_main calls main, or a recovered function calls through a
/// register as it received it, or as the constant target of an indirect
/// call. A jump that leaves its function for code outside of it, up to the
/// next function, calls a function as its tail, as code of 32-bit ARM keeps
/// each function in one piece. A code address that the data of the binary
/// holds, or that recovered code stores to memory, may name a label instead,
/// whose address GNU C lets a program take, so it starts a function only once
/// the code there shows one starting, as ARM32EntryEvidence tells, which the
/// target of such a jump also has to.
type ARM32FunctionIdentification(hdl: BinHandle, exnInfo: ExceptionInfo) =
  let metadata = FunctionIdentification(hdl, exnInfo) :> IFunctionIdentifiable

  let file = hdl.File

  let cc = hdl.Conventions.Calling

  /// What registers hold as a function starts: the arguments that its caller
  /// passes in them.
  let argsAtEntry =
    cc.IntArgs
    |> Array.indexed
    |> Array.choose (fun (idx, loc) ->
      match loc with
      | ArgLocation.Reg r -> Some(r, Arg idx)
      | _ -> None)
    |> Map.ofArray

  /// Checks if the function calls through a register, which is how it may call
  /// an argument that it receives.
  let callsThroughRegister (fn: Function) =
    fn.CFG.Vertices
    |> Array.exists (fun v ->
      let blk = v.VData.Internals
      not blk.IsAbstract
      && blk.LastInstruction.IsCall
      && blk.LastInstruction.IsIndirectBranch)

  /// Checks if the instruction jumps through a register other than the link
  /// register, which is how a function may call an argument as its tail.
  let isJumpThroughRegister (ins: ARM32.Instruction) =
    match ins.Opcode, ins.Operands with
    | ARM32.Opcode.BX, ARM32.OneOperand(ARM32.OprReg reg) ->
      reg <> ARM32.Register.LR
    | _ ->
      false

  /// Checks if the vertex ends with a jump through a register other than the
  /// link register.
  let endsInJumpThroughRegister (v: IVertex<LowUIRBasicBlock>) =
    let blk = v.VData.Internals
    not blk.IsAbstract
    && isJumpThroughRegister (blk.LastInstruction :?> ARM32.Instruction)

  /// Checks if the function jumps through a register other than the link
  /// register, which is how it may call an argument as its tail.
  let jumpsThroughRegister (fn: Function) =
    Array.exists endsInJumpThroughRegister fn.CFG.Vertices

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

  /// Reads the word at the given address as the loader leaves it, telling
  /// whether it moves with the binary: what a relocation writes there, which
  /// does, or what the file holds where only the loader writes.
  let tryReadWord addr =
    match BinFileOps.tryComputeRelocationValue file addr with
    | Ok v ->
      Some(v &&& wordMask, true)
    | Error _ when isStable addr ->
      hdl.TryReadUInt(addr, 4)
      |> Result.toOption
      |> Option.map (fun v -> v, false)
    | Error _ ->
      None

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

  /// Tells whether what the operation yields moves with the binary, given
  /// whether its operands do: an address plus an offset does, while the
  /// distance between two addresses does not.
  let isPlacedBy op isLeftPlaced isRightPlaced =
    match op with
    | BinOpType.SUB -> isLeftPlaced && not isRightPlaced
    | _ -> isLeftPlaced || isRightPlaced

  let extract (v: uint64) rt pos =
    let width = RegType.toBitWidth rt
    let v = v >>> pos
    if width >= 64 then v else v &&& ((1UL <<< width) - 1UL)

  /// Returns the constant that the given map holds for the key, if any, telling
  /// whether it moves with the binary.
  let tryConstIn map key =
    match Map.tryFind key map with
    | Some(Const(v, isPlaced)) -> Some(v, isPlaced)
    | _ -> None

  /// Evaluates the expression to the constant that it is on every path, if any,
  /// reading memory only where the loader leaves it as the binary says, and
  /// telling whether the constant moves with the binary as the loader places
  /// it.
  let rec eval (knowns: Knowns) pc e =
    match e with
    | Num(Value = bv) ->
      Some(bv.ToUInt64(), false)
    | PCVar _ ->
      Some(pc, true)
    | Var(RegisterID = r) ->
      tryConstIn knowns.Registers r
    | TempVar(Index = i) ->
      tryConstIn knowns.Temps i
    | BinOp(Op = op; Type = rt; Left = l; Right = r) when rt = 32<rt> ->
      match eval knowns pc l, eval knowns pc r with
      | Some(x, px), Some(y, py) ->
        fold op x y |> Option.map (fun v -> v &&& wordMask, isPlacedBy op px py)
      | _ ->
        None
    | Load(Type = rt; Addr = a) when rt = 32<rt> ->
      eval knowns pc a |> Option.bind (fst >> tryReadWord)
    | Extract(Operand = x; Type = rt; StartPos = pos) ->
      eval knowns pc x |> Option.map (fun (v, p) -> extract v rt pos, p)
    | Cast(Kind = CastKind.ZeroExt; Operand = x) ->
      eval knowns pc x
    | _ ->
      None

  /// Evaluates the expression to what it holds on every path, if known: what
  /// the register or the temporary that it reads holds, as a copy passes an
  /// argument on untouched, or else the constant that it is.
  let evalKnown knowns pc e =
    match e with
    | Var(RegisterID = r) ->
      Map.tryFind r knowns.Registers
    | TempVar(Index = i) ->
      Map.tryFind i knowns.Temps
    | _ ->
      eval knowns pc e |> Option.map Const

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
      let regs = update r (evalKnown knowns pc src) knowns.Registers
      { knowns with Registers = regs }
    | Put(Dst = TempVar(Index = i); Src = src) ->
      { knowns with Temps = update i (evalKnown knowns pc src) knowns.Temps }
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

  /// Notes the word that the statement stores to memory, if it is a constant on
  /// every path that may name code. A narrower store, as of a character or
  /// two, holds no pointer, nor does a number that stays put where the loader
  /// may place the binary anywhere, as code there computes an address from the
  /// PC or reads one where the loader writes it.
  let noteStore (stores: HashSet<uint64>) knowns pc stmt =
    match stmt with
    | Store(Value = v) when Expr.typeOf v = 32<rt> ->
      match eval knowns pc v with
      | Some(value, isPlaced) when isPlaced || not file.IsBaseRelative ->
        stores.Add value |> ignore
      | _ ->
        ()
    | _ ->
      ()

  /// Applies the instruction to what a path knows, noting the call that it
  /// starts and the constants that it stores.
  let applyInstruction calls stores knowns (lifted: LiftedInstruction) =
    noteCall calls knowns lifted
    let pc = lifted.Original.Address
    let apply k s =
      noteStore stores k pc s
      step k pc s
    Array.fold apply knowns lifted.Stmts

  /// Applies the block to what a path knows. A callee may write any register
  /// that its caller saves, so a call forgets those.
  let transfer calls stores knowns (blk: ILowUIRBasicBlock) =
    if blk.IsAbstract then
      let isKept r _ = not (cc.IsCallerSaved r)
      { Registers = Map.filter isKept knowns.Registers; Temps = Map.empty }
    else
      Array.fold (applyInstruction calls stores) knowns blk.LiftedInstructions

  /// Checks if the recovery took the jump that ends the given vertex for a
  /// tail call.
  let callsTail (cfg: LowUIRCFG) v =
    cfg.GetSuccEdges v |> Array.exists (fun e -> e.Label = TailCallEdge)

  /// Notes the call that the jump ending the given vertex makes as its tail,
  /// passing the arguments as any call does, if it jumps directly.
  let noteTailCall (calls: Dictionary<Addr, CallSite>) v knowns =
    let ins = (v: IVertex<LowUIRBasicBlock>).VData.Internals.LastInstruction
    if ins.IsDirectBranch then
      calls[ins.Address] <- { Instruction = ins; Values = knowns.Registers }
    else
      ()

  /// Notes the jump through a register that ends the given vertex, with what
  /// registers hold as it jumps.
  let noteJump (jumps: Dictionary<Addr, CallSite>) v knowns =
    let ins = (v: IVertex<LowUIRBasicBlock>).VData.Internals.LastInstruction
    jumps[ins.Address] <- { Instruction = ins; Values = knowns.Registers }

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

  /// Returns what the register that an indirect call jumps through holds.
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

  /// Returns the index of the argument that the call jumps to, if it calls an
  /// argument of its function as the function received it.
  let tryCalledArgOf site =
    match tryTargetOf site with
    | Some(Arg idx) -> Some idx
    | _ -> None

  /// Finds the calls that the function makes, each with what registers hold on
  /// every path to it from the entry, where the function receives its
  /// arguments, the arguments that it calls, the jumps with which it calls
  /// one as its tail, and the constants that it stores. Only a call or a jump
  /// through a register reads the arguments, so a function that makes none
  /// leaves them out.
  let findCalls (fn: Function) =
    let cfg = fn.CFG
    let calls = Dictionary<Addr, CallSite>()
    let jumps = Dictionary<Addr, CallSite>()
    let stores = HashSet<uint64>()
    let knownsAt = Dictionary<IVertex<LowUIRBasicBlock>, Knowns>()
    let work = Queue<IVertex<LowUIRBasicBlock>>()
    let readsArgs = callsThroughRegister fn || jumpsThroughRegister fn
    let args = if readsArgs then argsAtEntry else Map.empty
    for root in cfg.Roots do
      let regs =
        if root.VData.Internals.PPoint.Address = fn.EntryPoint then args
        else Map.empty
      knownsAt[root] <- { Registers = regs; Temps = Map.empty }
      work.Enqueue root
    while work.Count > 0 do
      let v = work.Dequeue()
      let out = transfer calls stores knownsAt[v] v.VData.Internals
      if callsTail cfg v then noteTailCall calls v out else ()
      if endsInJumpThroughRegister v then noteJump jumps v out else ()
      for succ in cfg.GetSuccs v do propagate knownsAt work succ out
    let sites = Seq.toArray calls.Values
    { Sites = sites
      CalledArgs =
        sites |> Array.choose tryCalledArgOf |> Array.distinct |> Array.toList
      ArgJumps =
        jumps.Values
        |> Seq.filter (fun site -> Option.isSome (tryCalledArgOf site))
        |> Seq.map (fun site -> site.Instruction.Address)
        |> Seq.toArray
      StoredConstants = Seq.toArray stores }

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
      let calls = findCalls fn
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
    | ArgLocation.Reg r -> tryConstIn site.Values r |> Option.map fst
    | _ -> None

  /// Returns the indices of the arguments that the function calls: those that
  /// an external function, named without the tag of a reference to it, is
  /// known to call back, or those that a function of the binary calls through
  /// a register as it received them.
  let argsCalledBy (fn: Function) =
    if fn.IsExternal then
      ELF.getCallbackArgsOfKnownFunc (fn.Name.Split('@')[0])
    else
      (findCallsOnce fn).CalledArgs

  /// Returns the indices of the arguments that each of the recovered functions
  /// calls, by the address that calls reach it at.
  let findCalledArgs (functions: Function[]) =
    let calledArgs = Dictionary<Addr, int list>()
    for fn in functions do
      match argsCalledBy fn with
      | [] -> ()
      | idxs -> calledArgs[fn.EntryPoint] <- idxs
    calledArgs

  /// Returns the jumps with which the function calls an argument as it received
  /// it, as its tail.
  let argJumpsOf (fn: Function) = (findCallsOnce fn).ArgJumps

  /// Finds the code addresses that the call proves to start functions: the
  /// constants that it passes in the arguments that its callee calls, or the
  /// constant that it jumps to through a register.
  let prove (calledArgs: Dictionary<Addr, int list>) (site: CallSite) =
    match site.Instruction.DirectBranchTarget() with
    | true, target ->
      match calledArgs.TryGetValue(toCalleeAddr target) with
      | true, idxs ->
        List.choose (tryArgOf site) idxs
      | false, _ ->
        []
    | false, _ ->
      match tryTargetOf site with
      | Some(Const(target, _)) ->
        [ target ]
      | _ ->
        []

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

  /// Tells whether the value is an address that lies in a section of the
  /// binary, as what a pointer points to does. The loader also maps the
  /// headers of the file, which no section holds and no pointer points to, so
  /// a number that happens to name one is no address.
  let isInSection v =
    file.IsValidAddr v && Result.isOk (BinFileOps.tryFindSectionByAddr file v)

  /// Tells whether a word next to the one at the given index is an address of
  /// the binary. Pointers sit together, in tables and in structures, while a
  /// number that happens to look like a code address sits among numbers.
  let hasAddressNext (words: uint64[]) idx =
    [ idx - 1; idx + 1 ]
    |> List.exists (fun i ->
      i >= 0 && i < words.Length && isInSection words[i])

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

  /// Lists the code addresses that the given functions store to memory, in the
  /// form that Identify gives, as code does that sets a function pointer at
  /// run time, such as one in .bss, which no data section holds.
  let pointersStoredBy (recovered: Function[]) =
    recovered
    |> Array.filter (fun fn -> not fn.IsExternal)
    |> Array.collect (fun fn -> (findCallsOnce fn).StoredConstants)
    |> Array.filter isCodePointer
    |> Array.distinct

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
      not (AddrRangeUnion.containsAddr (pointer &&& ~~~1UL) home)
      && evidence.ShowsEntry pointer
      && not (evidence.OnlyBranchesOn pointer))

  /// Where code resumes past each recovered function, by its CFG, with the
  /// count of its edges, as telling it takes reading the function anew, round
  /// after round.
  let gapsByCFG =
    System.Runtime.CompilerServices.ConditionalWeakTable<LowUIRCFG, _>()

  let tryFindGapPast (evidence: ARM32EntryEvidence) (fn: Function) =
    let cfg = fn.CFG
    match gapsByCFG.TryGetValue cfg with
    | true, (edgeCount, gap) when edgeCount = cfg.EdgeCount ->
      gap
    | _ ->
      let gap = evidence.TryFindGapPast fn
      gapsByCFG.AddOrUpdate(cfg, (cfg.EdgeCount, gap))
      gap

  /// Checks if the address lies before the next entry, in code that no
  /// recovered function covers.
  let isFreeBefore (evidence: ARM32EntryEvidence) next addr =
    addr < next && not (evidence.Covers addr)

  /// Finds where the function past the given one starts, in the form that
  /// Identify gives, if one does where code resumes before the next entry and
  /// no recovered function lies. What the code there leads to tells, which
  /// may change as the recovery finds more functions, such as one that the
  /// code calls as its tail.
  let tryFindStartPast evidence next fn =
    tryFindGapPast evidence fn
    |> Option.filter (fun gap -> isFreeBefore evidence next gap.Start)
    |> Option.bind (fun gap -> evidence.TryFindStartIn(fn, gap))

  /// Finds where the functions that follow the recovered ones start, in the
  /// form that Identify gives, which covers functions that nothing calls or
  /// points to, such as dead code that a linker keeps.
  let findNextStarts evidence recovered =
    withNextEntries recovered
    |> Array.choose (fun (fn, next) -> tryFindStartPast evidence next fn)

  interface IIncrementalFunctionIdentifiable with
    member _.Identify() = metadata.Identify()

    member _.IdentifyMore recovered =
      let calledArgs = findCalledArgs recovered
      let evidence =
        ARM32EntryEvidence(hdl, recovered, toCalleeAddr, argJumpsOf)
      let pointers = Array.append dataPointers (pointersStoredBy recovered)
      recovered
      |> Seq.filter (fun fn -> not fn.IsExternal)
      |> Seq.collect (fun fn -> (findCallsOnce fn).Sites)
      |> Seq.collect (prove calledArgs)
      |> Seq.append (proveByTailCalls evidence recovered)
      |> Seq.append (findNextStarts evidence recovered)
      |> Seq.filter isCodePointer
      |> Seq.append (Array.filter evidence.IsLikelyEntry pointers)
      |> Seq.distinct
      |> Seq.toArray
