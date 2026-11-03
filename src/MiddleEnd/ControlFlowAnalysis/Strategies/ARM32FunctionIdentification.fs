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
/// binary tells, as FunctionIdentification does, and then a code address only
/// once recovered code calls it: as an argument that an external function is
/// known to call, as __libc_start_main calls main, or as the constant target
/// of an indirect call. A code address that is merely stored somewhere may name
/// a label, whose address GNU C lets a program take, but no call targets one.
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

  /// Tells whether a call to the given address enters code of this binary in
  /// an instruction set that a function can start in: Thumb as the lowest bit
  /// says, or ARM at a word.
  let isCodePointer (v: uint64) =
    let addr = v &&& ~~~1UL
    file.IsExecutableAddr addr
    && not (BinFileOps.isInImportTable file addr)
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

  interface IIncrementalFunctionIdentifiable with
    member _.Identify() = metadata.Identify()

    member _.IdentifyMore recovered =
      let externals = namesOfExternals recovered
      recovered
      |> Seq.filter (fun fn -> not fn.IsExternal)
      |> Seq.collect findCalls
      |> Seq.collect (prove externals)
      |> Seq.filter isCodePointer
      |> Seq.distinct
      |> Seq.toArray
