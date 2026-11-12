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

namespace B2R2.MiddleEnd.DataFlow.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.Intel
open B2R2.BinIR
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.DataFlow.LowUIRSensitiveDataFlow
open B2R2.MiddleEnd.SSA
open B2R2.MiddleEnd.ControlFlowGraph

[<TestClass>]
type DataFlowTests() =
  let isRegular (v: VarPoint) =
    match v.VarKind with
    | Regular _ -> true
    | _ -> false

  let reg addr idx reg =
    { ProgramPoint = ProgramPoint(addr, idx)
      VarKind = Regular(Register.toRegID reg) }

  let mkConst (v: uint32) rt = BitVector(v, rt) |> ConstantDomain.Const

  let rec findVarDefFromStmts (stmts: _[]) vaddr idx addr kind =
    if idx < stmts.Length then
      match stmts[idx] with
      | (pp: ProgramPoint), SSA.Def(v, _) when v.Kind = kind ->
        if pp.Address = addr then Some v
        else findVarDefFromStmts stmts vaddr (idx + 1) addr kind
      | _, SSA.Phi(v, _) when v.Kind = kind ->
        if vaddr = addr then Some v
        else findVarDefFromStmts stmts vaddr (idx + 1) addr kind
      | _ ->
        findVarDefFromStmts stmts vaddr (idx + 1) addr kind
    else
      None

  let rec findSSAVarDef (ssaCFG: SSACFG) vidx addr kind =
    if vidx < ssaCFG.Vertices.Length then
      let v = ssaCFG.Vertices[vidx]
      let stmts = v.VData.Internals.Statements
      findVarDefFromStmts stmts v.VData.Internals.PPoint.Address 0 addr kind
      |> function
        | Some v -> v
        | None -> findSSAVarDef ssaCFG (vidx + 1) addr kind
    else
      failwith $"variable {kind} @ {addr:x} not found"

  let ssaReg ssaCFG r addr rt =
    let rid = Register.toRegID r
    let rstr = Register.toString r
    let k = SSA.RegVar(rt, rid, rstr)
    let v = findSSAVarDef ssaCFG 0 addr k
    SSASparseDataFlow.SSAVarPoint.RegularSSAVar
    <| { Kind = k; Identifier = v.Identifier }

  let ssaRegInitial r rt =
    let rid = Register.toRegID r
    let rstr = Register.toString r
    let k = SSA.RegVar(rt, rid, rstr)
    SSASparseDataFlow.SSAVarPoint.RegularSSAVar
    <| { Kind = k; Identifier = 0 }

  let ssaStk ssaCFG offset addr rt =
    let kind = SSA.StackVar(rt, offset)
    let v = findSSAVarDef ssaCFG 0 addr kind
    SSASparseDataFlow.SSAVarPoint.RegularSSAVar
    <| { Kind = v.Kind; Identifier = v.Identifier }

  let irReg addr idx r =
    let rid = Register.toRegID r
    let pp = ProgramPoint(addr, idx)
    let varKind = Regular rid
    { ProgramPoint = pp; VarKind = varKind }

  let irStk addr idx offset =
    let pp = ProgramPoint(addr, idx)
    let varKind = StackLocal offset
    { ProgramPoint = pp; VarKind = varKind }

  let spp addr idx: SensitiveProgramPoint<int> =
    { ProgramPoint = ProgramPoint(addr, idx); ExecutionContext = 0 }

  let svp addr idx varKind: SensitiveVarPoint<int> =
    { SensitiveProgramPoint = spp addr idx; VarKind = varKind }

  let mkUntouchedReg r =
    Regular(Register.toRegID r)
    |> UntouchedValueDomain.RegisterTag
    |> UntouchedValueDomain.Untouched

  let cmp vp c = vp, c

  /// Computes constant propagation on sample 7 without the block at 0x1d, then
  /// adds the block back and computes again, as CFG recovery would.
  let computeWithLateBlock () =
    let brew = Binaries.loadOne Binaries.sample7
    let cfg = brew.Functions[0UL].CFG
    let late =
      cfg.FindVertexBy(fun b -> b.VData.Internals.PPoint.Address = 0x1DUL)
    let preds, succs = cfg.GetPredEdges late, cfg.GetSuccEdges late
    cfg.RemoveVertex late
    let cp = ConstantPropagation(brew.BinHandle, cfg.Vertices)
    let dfa = cp :> IDataFlowComputable<_, _, _>
    dfa.Compute cfg |> ignore
    let v = cfg.AddVertex late.VData
    for e in preds do cfg.AddEdge(e.First, v, e.Label)
    for e in succs do cfg.AddEdge(v, e.Second, e.Label)
    cp.State.MarkVertexAsPending v
    for e in succs do cp.State.MarkVertexAsPending e.Second
    dfa.Compute cfg |> ignore
    cp.State

#if !EMULATION
  [<TestMethod>]
  member _.``Reaching Definitions Test 1``() =
    let brew = Binaries.loadOne Binaries.sample1
    let cfg = brew.Functions[0UL].CFG
    let dfa = ReachingDefinitionAnalysis() :> IDataFlowComputable<_, _, _>
    let state = dfa.Compute cfg
    let v = cfg.FindVertexBy(fun b -> b.VData.Internals.PPoint.Address = 0xEUL)
    (* v is the second vertex of the CFG. *)
    let rd = state.GetAbsValue v
    let ins = rd.Ins |> Set.filter isRegular
    let solution =
      [ reg 0x0UL 1 Register.EDX
        reg 0x4UL 1 Register.ESP
        reg 0x5UL 1 Register.ESI
        reg 0x5UL 2 Register.OF
        reg 0x5UL 3 Register.CF
        reg 0x5UL 4 Register.SF
        reg 0x5UL 5 Register.ZF
        reg 0x5UL 6 Register.PF
        reg 0x5UL 7 Register.AF
        reg 0x7UL 1 Register.ECX
        reg 0xAUL 4 Register.CF
        reg 0xAUL 5 Register.OF
        reg 0xAUL 6 Register.AF
        reg 0xAUL 7 Register.SF
        reg 0xAUL 8 Register.ZF
        reg 0xAUL 11 Register.PF ]
    Assert.AreEqual(Set.ofList solution, ins)
#endif

  [<TestMethod>]
  member _.``Reaching Definitions Test 2``() =
    let brew = Binaries.loadOne Binaries.sample4
    let cfg = brew.Functions[0UL].CFG
    let dfa = ReachingDefinitionAnalysis() :> IDataFlowComputable<_, _, _>
    let state = dfa.Compute cfg
    let v = cfg.FindVertexBy(fun b -> b.VData.Internals.PPoint.Address = 0x21UL)
    (* The sole definition of ECX lives in the innermost block, so it reaches
       the exit block only after two rounds of propagation. *)
    let rd = state.GetAbsValue v
    let ecx = Regular(Register.toRegID Register.ECX)
    let ins = rd.Ins |> Set.filter (fun vp -> vp.VarKind = ecx)
    Assert.AreEqual(Set.singleton (reg 0x15UL 1 Register.ECX), ins)

  [<TestMethod>]
  member _.``Reaching Definitions Test 3``() =
    let brew = Binaries.loadOne Binaries.sample4
    let cfg = brew.Functions[0UL].CFG
    let at addr =
      cfg.FindVertexBy(fun b -> b.VData.Internals.PPoint.Address = addr)
    let dfa = ReachingDefinitionAnalysis() :> IDataFlowComputable<_, _, _>
    dfa.Compute cfg |> ignore
    cfg.RemoveEdge(at 0x15UL, at 0xEUL)
    (* Cutting the back edge strands the sole definition of ECX, so reusing the
       instance must not carry the answer of the older graph over. *)
    let state = dfa.Compute cfg
    let rd = state.GetAbsValue(at 0x21UL)
    let ecx = Regular(Register.toRegID Register.ECX)
    let ins = rd.Ins |> Set.filter (fun vp -> vp.VarKind = ecx)
    Assert.AreEqual<Set<VarPoint>>(Set.empty, ins)

  [<TestMethod>]
  member _.``Use-Def Test 1``() =
    let brew = Binaries.loadOne Binaries.sample1
    let cfg = brew.Functions[0UL].CFG
    let chain = DataFlowChain.compute cfg IRLevel
    let vp = reg 0xEUL 1 Register.EDX
    let res = chain.UseDefChain |> Map.find vp |> Set.toArray
    let solution = [| reg 0x0UL 1 Register.EDX |]
    CollectionAssert.AreEqual(solution, res)

  [<TestMethod>]
  member _.``Use-Def Test 2``() =
    let brew = Binaries.loadOne Binaries.sample1
    let cfg = brew.Functions[0UL].CFG
    let chain = DataFlowChain.compute cfg DisasmLevel
    let vp = reg 0xEUL 0 Register.EDX
    let res = chain.UseDefChain |> Map.find vp |> Set.toArray
    let solution = [| reg 0x0UL 0 Register.EDX |]
    CollectionAssert.AreEqual(solution, res)

#if !EMULATION
  [<TestMethod>]
  member _.``Use-Def Test 3``() =
    let brew = Binaries.loadOne Binaries.sample1
    let cfg = brew.Functions[0UL].CFG
    let chain = DataFlowChain.compute cfg IRLevel
    let vp = reg 0x1AUL 1 Register.EDX
    let res = chain.UseDefChain |> Map.find vp |> Set.toArray
    let solution = [| reg 0x12UL 3 Register.EDX; reg 0x1AUL 3 Register.EDX |]
    CollectionAssert.AreEqual(solution, res)
#endif

  [<TestMethod>]
  member _.``SSA Constant Propagation Test 1``() =
    let brew = Binaries.loadOne Binaries.sample2
    let cfg = brew.Functions[0UL].CFG
    let lifter = SSALifterFactory.Create brew.BinHandle
    let promoter = SSAPromoterFactory.Create brew.BinHandle
    let g = (lifter.Lift cfg |> promoter.Promote).Graph
    let cp = SSAConstantPropagation brew.BinHandle
    let dfa = cp :> IDataFlowComputable<_, _, _>
    let state = dfa.Compute g
    [ ssaRegInitial Register.RSP 64<rt> |> cmp <| mkConst 0x80000000u 64<rt>
      ssaRegInitial Register.RBP 64<rt> |> cmp <| ConstantDomain.NotAConst
      ssaReg g Register.RSP 0x4UL 64<rt> |> cmp <| mkConst 0x7ffffff8u 64<rt>
      ssaReg g Register.RBP 0x5UL 64<rt> |> cmp <| mkConst 0x7ffffff8u 64<rt>
      ssaStk g (8 + 0xc) 0x11UL 32<rt> |> cmp <| mkConst 0x2u 32<rt>
      ssaStk g (8 + 0x8) 0x18UL 32<rt> |> cmp <| mkConst 0x3u 32<rt>
      ssaStk g (8 + 0xc) 0x21UL 32<rt> |> cmp <| mkConst 0x3u 32<rt>
      ssaStk g (8 + 0x8) 0x28UL 32<rt> |> cmp <| mkConst 0x2u 32<rt>
      ssaStk g (8 + 0xc) 0x2fUL 32<rt> |> cmp <| ConstantDomain.NotAConst
      ssaStk g (8 + 0x8) 0x2fUL 32<rt> |> cmp <| ConstantDomain.NotAConst
      ssaReg g Register.RAX 0x32UL 64<rt> |> cmp <| ConstantDomain.NotAConst
      ssaReg g Register.RDX 0x2fUL 64<rt> |> cmp <| ConstantDomain.NotAConst
      ssaReg g Register.RAX 0x35UL 64<rt> |> cmp <| ConstantDomain.NotAConst
      ssaReg g Register.RBP 0x3bUL 64<rt> |> cmp <| ConstantDomain.NotAConst
      ssaReg g Register.RSP 0x3bUL 64<rt> |> cmp <| mkConst 0x80000000u 64<rt>
      ssaReg g Register.RSP 0x3CUL 64<rt> |> cmp <| mkConst 0x80000008u 64<rt> ]
    |> List.iter (fun (var, ans) ->
      let out = state.GetAbsValue var
      Assert.AreEqual<ConstantDomain.Lattice>(ans, out))

  [<TestMethod>]
  member _.``SSA Def Lookup Test``() =
    let brew = Binaries.loadOne Binaries.sample2
    let cfg = brew.Functions[0UL].CFG
    let lifter = SSALifterFactory.Create brew.BinHandle
    let promoter = SSAPromoterFactory.Create brew.BinHandle
    let g = (lifter.Lift cfg |> promoter.Promote).Graph
    let cp = SSAConstantPropagation brew.BinHandle
    let rid = Register.toRegID Register.RSP
    let kind = SSA.RegVar(64<rt>, rid, Register.toString Register.RSP)
    (* Asking before Compute must answer None rather than trip over the SSA
       edges that the analysis has yet to build. *)
    let early = cp.State.TryGetSSADef { Kind = kind; Identifier = 1 }
    Assert.AreEqual<bool>(true, Option.isNone early)
    (cp :> IDataFlowComputable<_, _, _>).Compute g |> ignore
    let var = findSSAVarDef g 0 0x4UL kind
    Assert.AreEqual<bool>(true, cp.State.TryGetSSADef var |> Option.isSome)

  [<TestMethod>]
  member _.``SSA Constant Propagation Test 2``() =
    let brew = Binaries.loadOne Binaries.sample5
    let cfg = brew.Functions[0UL].CFG
    let lifter = SSALifterFactory.Create brew.BinHandle
    let promoter = SSAPromoterFactory.Create brew.BinHandle
    let g = (lifter.Lift cfg |> promoter.Promote).Graph
    let cp = SSAConstantPropagation brew.BinHandle
    let dfa = cp :> IDataFlowComputable<_, _, _>
    let state = dfa.Compute g
    (* A value read from memory is unknown, so joining it with a constant
       must not come out as that constant. *)
    [ ssaReg g Register.RAX 0x18UL 64<rt> |> cmp <| ConstantDomain.NotAConst
      ssaReg g Register.RBX 0x30UL 64<rt> |> cmp <| ConstantDomain.NotAConst ]
    |> List.iter (fun (var, ans) ->
      let out = state.GetAbsValue var
      Assert.AreEqual<ConstantDomain.Lattice>(ans, out))

  [<TestMethod>]
  member _.``SSA Constant Propagation Test 3``() =
    let brew = Binaries.loadOne Binaries.sample6
    let cfg = brew.Functions[0UL].CFG
    let lifter = SSALifterFactory.Create brew.BinHandle
    let promoter = SSAPromoterFactory.Create brew.BinHandle
    let g = (lifter.Lift cfg |> promoter.Promote).Graph
    let cp = SSAConstantPropagation brew.BinHandle
    let state = (cp :> IDataFlowComputable<_, _, _>).Compute g
    (* EAX comes in from the caller on one path, so joining it with 3 must
       not come out as 3. *)
    let vp = ssaReg g Register.EAX 0x9UL 32<rt>
    let out = state.GetAbsValue vp
    Assert.AreEqual<ConstantDomain.Lattice>(ConstantDomain.NotAConst, out)

#if !EMULATION
  [<TestMethod>]
  member _.``Constant Propagation Test 1``() =
    let brew = Binaries.loadOne Binaries.sample2
    let hdl = brew.BinHandle
    let cfg = brew.Functions[0UL].CFG
    let varDfa = ConstantPropagation(hdl, cfg.Vertices)
    let dfa = varDfa :> IDataFlowComputable<_, _, _>
    let state = dfa.Compute cfg
    let rbp = -8 (* stack offset of old rbp *)
    [ irStk 0xbUL 1 rbp |> cmp <| ConstantDomain.Undef
      irStk 0x11UL 1 (rbp - 0xc) |> cmp <| mkConst 0x2u 32<rt>
      irStk 0x18UL 1 (rbp - 0x8) |> cmp <| mkConst 0x3u 32<rt>
      irStk 0x21UL 1 (rbp - 0xc) |> cmp <| mkConst 0x3u 32<rt>
      irStk 0x28UL 1 (rbp - 0x8) |> cmp <| mkConst 0x2u 32<rt>
      irReg 0x2fUL 1 Register.RDX |> cmp <| ConstantDomain.NotAConst ]
    |> List.iter (fun (vp, ans) ->
      let out = state.GetAbsValue vp
      Assert.AreEqual<ConstantDomain.Lattice>(ans, out))

  [<TestMethod>]
  member _.``Constant Propagation Test 2``() =
    let brew = Binaries.loadOne Binaries.sample6
    let cfg = brew.Functions[0UL].CFG
    let cp = ConstantPropagation(brew.BinHandle, cfg.Vertices)
    let state = (cp :> IDataFlowComputable<_, _, _>).Compute cfg
    (* Same as above, on the LowUIR framework: the phi at 0x9 joins the
       caller's EAX with 3. *)
    let vp = irReg 0x9UL 0 Register.EAX
    let out = state.GetAbsValue vp
    Assert.AreEqual<ConstantDomain.Lattice>(ConstantDomain.NotAConst, out)
#endif

  [<TestMethod>]
  member _.``Constant Propagation Test 3``() =
    let brew = Binaries.loadOne Binaries.sample9
    let cfg = brew.Functions[0UL].CFG
    (* Gap analysis makes 0x8 a root as well, after which no root dominates
       0xa alone. Both of its predecessors still clear ECX before it. *)
    let v8 = cfg.FindVertexBy(fun v -> v.VData.Internals.PPoint.Address = 0x8UL)
    cfg.AddRoot v8
    let cp = ConstantPropagation(brew.BinHandle, cfg.Vertices)
    let state = (cp :> IDataFlowComputable<_, _, _>).Compute cfg
    let out = state.GetAbsValue(irReg 0xaUL 1 Register.EAX)
    Assert.AreEqual<ConstantDomain.Lattice>(mkConst 0u 32<rt>, out)

  [<TestMethod>]
  member _.``Constant Propagation Test 4``() =
    let brew = Binaries.loadOne Binaries.sample11
    let cfg = brew.Functions[0UL].CFG
    let cp = ConstantPropagation(brew.BinHandle, cfg.Vertices)
    let state = (cp :> IDataFlowComputable<_, _, _>).Compute cfg
    (* Only the loader writes the image, so both loads of ECX read the word
       that it holds at 0x16, and the phi at 0x6 joins one constant. *)
    let out = state.GetAbsValue(irReg 0x13UL 1 Register.EAX)
    Assert.AreEqual<ConstantDomain.Lattice>(mkConst 0x12345678u 32<rt>, out)

  [<TestMethod>]
  member _.``Constant Propagation Test 5``() =
    let brew = Binaries.loadAt 0x80000000UL Binaries.sample12
    let cfg = brew.Functions[0x80000000UL].CFG
    let cp = ConstantPropagation(brew.BinHandle, cfg.Vertices)
    let state = (cp :> IDataFlowComputable<_, _, _>).Compute cfg
    (* The argument comes from the caller, not from the image, although the
       data flow names its slot by an address that the image covers. *)
    let out = state.GetAbsValue(irReg 0x80000000UL 1 Register.EAX)
    Assert.AreEqual<ConstantDomain.Lattice>(ConstantDomain.NotAConst, out)

  [<TestMethod>]
  member _.``Constant Propagation Test 6``() =
    let brew = Binaries.loadAt 0x7fffffe0UL Binaries.sample13
    let cfg = brew.Functions[0x7fffffe0UL].CFG
    let cp = ConstantPropagation(brew.BinHandle, cfg.Vertices)
    let state = (cp :> IDataFlowComputable<_, _, _>).Compute cfg
    (* The store writes the stack, which lies wherever the stack pointer
       points, so the load still reads the word that the image holds. *)
    let out = state.GetAbsValue(irReg 0x7fffffe8UL 1 Register.EAX)
    Assert.AreEqual<ConstantDomain.Lattice>(mkConst 0x12345678u 32<rt>, out)

  /// MIPS reads zero from its zero register, whose initial value no
  /// instruction replaces.
  [<TestMethod>]
  member _.``Constant Propagation reads the MIPS zero register as zero``() =
    (* addiu v0, zero, 6 ; jr ra ; nop *)
    let brew = Binaries.loadMIPSAt 0x400000UL "2402000603e0000800000000"
    let cfg = brew.Functions[0x400000UL].CFG
    let cp = ConstantPropagation(brew.BinHandle, cfg.Vertices)
    let state = (cp :> IDataFlowComputable<_, _, _>).Compute cfg
    let v0 = Regular(FrontEnd.MIPS.Register.toRegID FrontEnd.MIPS.Register.R2)
    let vp = { ProgramPoint = ProgramPoint(0x400000UL, 1); VarKind = v0 }
    let six = mkConst 6u 32<rt>
    Assert.AreEqual<ConstantDomain.Lattice>(six, state.GetAbsValue vp)

  /// A MIPS PIC function finds gp from t9, which holds its own address on
  /// entry when the data flow is told which function it runs in.
  [<TestMethod>]
  member _.``Constant Propagation gives t9 the MIPS function address``() =
    (* lui gp, 0x1 ; addu gp, gp, t9 ; jr ra ; nop *)
    let hex = "3c1c00010399e02103e0000800000000"
    let brew = Binaries.loadMIPSAt 0x400000UL hex
    let hdl = brew.BinHandle
    let cfg = brew.Functions[0x400000UL].CFG
    let gp = Regular(FrontEnd.MIPS.Register.toRegID FrontEnd.MIPS.Register.R28)
    let vp = { ProgramPoint = ProgramPoint(0x400004UL, 1); VarKind = gp }
    let provider = RegisterInitialValueProvider.createForFunction hdl 0x400000UL
    let cp = ConstantPropagation(hdl, cfg.Vertices, provider)
    let state = (cp :> IDataFlowComputable<_, _, _>).Compute cfg
    let gpValue = mkConst 0x410000u 32<rt>
    Assert.AreEqual<ConstantDomain.Lattice>(gpValue, state.GetAbsValue vp)

  /// A register that holds an address outside the GOT may walk memory in a
  /// loop, and a CFG that still lacks the way back shows only its first pass,
  /// so a load through it reads nothing, though the register holds a
  /// constant and only the loader writes where it points.
  [<TestMethod>]
  member _.``Constant Propagation loads nothing outside the GOT``() =
    (* lui v1, 0x40 ; lw v0, 0x10(v1) ; jr ra ; nop ; .word 0x12345678 *)
    let hex = "3c0300408c62001003e000080000000012345678"
    let brew = Binaries.loadMIPSAt 0x400000UL hex
    let cfg = brew.Functions[0x400000UL].CFG
    let cp = ConstantPropagation(brew.BinHandle, cfg.Vertices)
    let state = (cp :> IDataFlowComputable<_, _, _>).Compute cfg
    let v0 = Regular(FrontEnd.MIPS.Register.toRegID FrontEnd.MIPS.Register.R2)
    let vp = { ProgramPoint = ProgramPoint(0x400004UL, 1); VarKind = v0 }
    let top = ConstantDomain.NotAConst
    Assert.AreEqual<ConstantDomain.Lattice>(top, state.GetAbsValue vp)

  /// A load through a byte that the code loads through an argument reads
  /// what no one knows, rather than nothing yet, which a phi would drop for a
  /// constant that another path brings.
  [<TestMethod>]
  member _.``Constant Propagation loads nothing through a loaded byte``() =
    (* lbu v1, 0(a0) ; lw v0, 0(v1) ; jr ra ; nop *)
    let hex = "908300008c62000003e0000800000000"
    let brew = Binaries.loadMIPSAt 0x400000UL hex
    let cfg = brew.Functions[0x400000UL].CFG
    let cp = ConstantPropagation(brew.BinHandle, cfg.Vertices)
    let state = (cp :> IDataFlowComputable<_, _, _>).Compute cfg
    let v0 = Regular(FrontEnd.MIPS.Register.toRegID FrontEnd.MIPS.Register.R2)
    let vp = { ProgramPoint = ProgramPoint(0x400004UL, 1); VarKind = v0 }
    let top = ConstantDomain.NotAConst
    Assert.AreEqual<ConstantDomain.Lattice>(top, state.GetAbsValue vp)

  /// CFG recovery hands new blocks over in no particular order, so a load
  /// through gp may come before the block that sets gp. It then reads nothing
  /// yet, rather than what no one knows, and reads the GOT once gp is known.
  [<TestMethod>]
  member _.``Constant Propagation loads through gp that it learns late``() =
    (* lui gp, 0x43 ; b 0x400530 ; addiu gp, gp, -0x7ff0 ; nop
       lw v0, -0x7fe8(gp) ; jr ra ; nop *)
    let hex = "3c1c004310000002279c8010000000008f82801803e0000800000000"
    let hdl = Binaries.loadPatchedMIPS "elf_mips32" 0x520 hex
    let cfg = MiddleEnd.BinaryBrew(hdl).Functions[0x400520UL].CFG
    let lateFirst =
      cfg.Vertices
      |> Array.sortByDescending _.VData.Internals.BlockAddress
    let cp = ConstantPropagation(hdl, lateFirst)
    let state = (cp :> IDataFlowComputable<_, _, _>).Compute cfg
    let v0 = Regular(FrontEnd.MIPS.Register.toRegID FrontEnd.MIPS.Register.R2)
    let vp = { ProgramPoint = ProgramPoint(0x400530UL, 1); VarKind = v0 }
    let gotEntry = mkConst 0x400520u 32<rt>
    Assert.AreEqual<ConstantDomain.Lattice>(gotEntry, state.GetAbsValue vp)

  [<TestMethod>]
  member _.``SSA Var Abstract Value Lookup Test``() =
    let brew = Binaries.loadOne Binaries.sample2
    let cfg = brew.Functions[0UL].CFG
    let cp = ConstantPropagation(brew.BinHandle, cfg.Vertices)
    (cp :> IDataFlowComputable<_, _, _>).Compute cfg |> ignore
    let state = cp.State
    for v in cfg.Vertices do
      if v.VData.Internals.IsAbstract then ()
      else state.GetTerminatorInSSA v |> ignore
    let known = state.SSAVarToVp.Keys |> Seq.head
    (* A variable coming in from outside the function never gets registered,
       but it holds what the analysis assumes on entry, which is zero for the
       base of DS. One that the analysis never defined at all has no value, so
       the lookup must answer None instead of throwing. *)
    let dsBase =
      { known with
          Kind = SSA.RegVar(64<rt>, Register.toRegID Register.DSBase, "DSBase")
          Identifier = 0 }
    let stray = { known with Identifier = System.Int32.MaxValue }
    let hit = state.TryGetAbsValueOfSSAVar known
    let entry = state.TryGetAbsValueOfSSAVar dsBase
    let miss = state.TryGetAbsValueOfSSAVar stray
    let zero = mkConst 0u 64<rt>
    Assert.AreEqual<bool>(true, Option.isSome hit)
    Assert.AreEqual<ConstantDomain.Lattice option>(Some zero, entry)
    Assert.AreEqual<bool>(true, Option.isNone miss)

  [<TestMethod>]
  member _.``SSA Phi Operand Lookup Test``() =
    let brew = Binaries.loadOne Binaries.sample10
    let cfg = brew.Functions[0UL].CFG
    let at addr =
      cfg.FindVertexBy(fun v -> v.VData.Internals.PPoint.Address = addr)
    let cp = ConstantPropagation(brew.BinHandle, cfg.Vertices)
    (cp :> IDataFlowComputable<_, _, _>).Compute cfg |> ignore
    let state = cp.State
    let join = at 0xaUL
    match state.GetTerminatorInSSA join with
    | SSA.Jmp(SSA.InterJmp(SSA.Var phi)) ->
      (* Each operand of the phi of ECX is the definition from its own edge. *)
      let defAddrFrom pred =
        state.TryGetSSAPhiOperand(phi, at pred, join)
        |> Option.map (fun v -> state.SSAVarToVp[v].ProgramPoint.Address)
      let actual = [ defAddrFrom 0x4UL; defAddrFrom 0x8UL ]
      let expected = [ Some 0x4UL; Some 0x8UL ]
      Assert.AreEqual<Addr option list>(expected, actual)
    | terminator ->
      Assert.Fail $"Unexpected terminator: {terminator}"

  [<TestMethod>]
  member _.``Untouched Value Analysis 1``() =
    let brew = Binaries.loadOne Binaries.sample3
    let cfg = brew.Functions[0UL].CFG
    let roots = cfg.Roots
    let uva = UntouchedValueAnalysis(brew.BinHandle, roots)
    let dfa = uva :> IDataFlowComputable<_, _, _>
    cfg |> DiGraph.iterVertex uva.State.MarkVertexAsPending
    let state = dfa.Compute cfg
    let rbp = -8 (* stack offset of old rbp *)
    [ irStk 0xcUL 1 (rbp - 0x14) |> cmp <| mkUntouchedReg Register.RDI
      irStk 0xfUL 1 (rbp - 0x18) |> cmp <| mkUntouchedReg Register.RSI
      irStk 0x15UL 1 (rbp - 0x10) |> cmp <| mkUntouchedReg Register.RDI
      irStk 0x1eUL 1 (rbp - 0xc) |> cmp <| UntouchedValueDomain.Touched
      irReg 0x32UL 1 Register.RCX |> cmp <| UntouchedValueDomain.Touched
      irReg 0x35UL 1 Register.RDX |> cmp <| UntouchedValueDomain.Touched
      irReg 0x38UL 1 Register.RSI |> cmp <| UntouchedValueDomain.Touched
      irReg 0x3bUL 1 Register.RAX |> cmp <| mkUntouchedReg Register.RDI ]
    |> List.iter (fun (vp, ans) ->
      let out = state.GetAbsValue vp
      Assert.AreEqual<UntouchedValueDomain.Lattice>(ans, out))

  [<TestMethod>]
  member _.``Untouched Value Analysis 2``() =
    let brew = Binaries.loadOne Binaries.sample8
    let cfg = brew.Functions[0UL].CFG
    let uva = UntouchedValueAnalysis(brew.BinHandle, cfg.Roots)
    let dfa = uva :> IDataFlowComputable<_, _, _>
    cfg |> DiGraph.iterVertex uva.State.MarkVertexAsPending
    let state = dfa.Compute cfg
    (* EAX takes the first argument, four bytes above the stack pointer at
       entry, which the function never writes. *)
    let arg =
      StackLocal 4
      |> UntouchedValueDomain.RegisterTag
      |> UntouchedValueDomain.Untouched
    let out = state.GetAbsValue(irReg 0x0UL 1 Register.EAX)
    Assert.AreEqual<UntouchedValueDomain.Lattice>(arg, out)

  /// MIPS copies a register by oring it with the zero register, which leaves
  /// the value untouched.
  [<TestMethod>]
  member _.``Untouched Value Analysis passes a value through the zero``() =
    (* move s0, a0 ; jr ra ; nop *)
    let brew = Binaries.loadMIPSAt 0x400000UL "0080802503e0000800000000"
    let cfg = brew.Functions[0x400000UL].CFG
    let uva = UntouchedValueAnalysis(brew.BinHandle, cfg.Roots)
    let dfa = uva :> IDataFlowComputable<_, _, _>
    cfg |> DiGraph.iterVertex uva.State.MarkVertexAsPending
    let state = dfa.Compute cfg
    let regOf r = Regular(FrontEnd.MIPS.Register.toRegID r)
    let s0 = regOf FrontEnd.MIPS.Register.R16
    let vp = { ProgramPoint = ProgramPoint(0x400000UL, 1); VarKind = s0 }
    let a0 =
      regOf FrontEnd.MIPS.Register.R4
      |> UntouchedValueDomain.RegisterTag
      |> UntouchedValueDomain.Untouched
    Assert.AreEqual<UntouchedValueDomain.Lattice>(a0, state.GetAbsValue vp)

  [<TestMethod>]
  member _.``Sensitive Constant Propagation EvalExpr 1``() =
    let brew = Binaries.loadOne Binaries.sample1
    let scheme =
      { new LowUIRSensitiveDataFlow.IScheme<int> with
          member _.DefaultExecutionContext = 0
          member _.TryComputeExecutionContext(_, exeCtx, _, _) = Some exeCtx
          member _.OnVertexNewlyAnalyzed _ = ()
          member _.OnRemoveVertex _ = () }
    let cp = LowUIRSensitiveConstantPropagation(brew.BinHandle, scheme)
    let spp: LowUIRSensitiveDataFlow.SensitiveProgramPoint<int> =
      { ProgramPoint = ProgramPoint(0x1234UL, 0); ExecutionContext = 0 }
    let n42 = LowUIR.AST.num (BitVector(42u, 32<rt>))
    let n8 = LowUIR.AST.num (BitVector(8u, 32<rt>))
    [ n42, mkConst 42u 32<rt>
      LowUIR.AST.add n42 n8, mkConst 50u 32<rt>
      LowUIR.AST.pcvar 32<rt> "EIP", mkConst 0x1234u 32<rt> ]
    |> List.iter (fun (e, ans) ->
      let out = cp.EvalExpr(spp, e)
      Assert.AreEqual<ConstantDomain.Lattice>(ans, out))

  [<TestMethod>]
  member _.``Sensitive Data Flow Chains 1``() =
    let brew = Binaries.loadOne Binaries.sample3
    let cfg = brew.Functions[0UL].CFG
    let scheme =
      { new LowUIRSensitiveDataFlow.IScheme<int> with
          member _.DefaultExecutionContext = 0
          member _.TryComputeExecutionContext(_, exeCtx, _, _) = Some exeCtx
          member _.OnVertexNewlyAnalyzed _ = ()
          member _.OnRemoveVertex _ = () }
    let cp = LowUIRSensitiveConstantPropagation(brew.BinHandle, scheme)
    let state = cp.State
    for root in cfg.Roots do state.MarkEdgeAsPending(null, root)
    for e in cfg.Edges do state.MarkEdgeAsPending(e.First, e.Second)
    (cp :> IDataFlowComputable<_, _, _>).Compute cfg |> ignore
    (* Reading a stack slot registers a use of that slot. *)
    Assert.AreEqual(state.UseDefMap.ContainsKey(svp 0x32UL 1 (StackLocal -12)),
                    true)
    (* The destination of a Put is a definition, never a use of itself. *)
    let rbp = Regular(Register.toRegID Register.RBP)
    Assert.AreEqual(state.UseDefMap.ContainsKey(svp 0x5UL 1 rbp), false)

#if !EMULATION
  [<TestMethod>]
  member _.``Sensitive Constant Propagation Test 1``() =
    let brew = Binaries.loadOne Binaries.sample6
    let cfg = brew.Functions[0UL].CFG
    let scheme =
      { new LowUIRSensitiveDataFlow.IScheme<int> with
          member _.DefaultExecutionContext = 0
          member _.TryComputeExecutionContext(_, exeCtx, _, _) = Some exeCtx
          member _.OnVertexNewlyAnalyzed _ = ()
          member _.OnRemoveVertex _ = () }
    let cp = LowUIRSensitiveConstantPropagation(brew.BinHandle, scheme)
    let state = cp.State
    for root in cfg.Roots do state.MarkEdgeAsPending(null, root)
    for e in cfg.Edges do state.MarkEdgeAsPending(e.First, e.Second)
    (cp :> IDataFlowComputable<_, _, _>).Compute cfg |> ignore
    (* The path that skips 0x4 brings in the caller's EAX, so the read at 0x9
       must not see 3. *)
    let eax = brew.BinHandle.RegisterFactory.GetRegVar "EAX"
    let out = cp.EvalExpr(spp 0x9UL 2, eax)
    Assert.AreEqual<ConstantDomain.Lattice>(ConstantDomain.NotAConst, out)
#endif

  [<TestMethod>]
  member _.``Sparse Data Flow Phi Test 1``() =
    let brew = Binaries.loadOne Binaries.sample1
    let cfg = brew.Functions[0UL].CFG
    let cp = ConstantPropagation(brew.BinHandle, cfg.Vertices)
    (cp :> IDataFlowComputable<_, _, _>).Compute cfg |> ignore
    (* A temporary never outlives its instruction, so a block that starts an
       instruction has no temporary coming in to join. *)
    let tempPhis =
      [ for KeyValue(v, phiInfo) in cp.State.PhiInfos do
          if v.VData.Internals.PPoint.Position = 0 then
            yield! Seq.filter VarKind.isTemporary phiInfo.Keys
          else
            () ]
    Assert.AreEqual<VarKind list>([], tempPhis)

#if !EMULATION
  [<TestMethod>]
  member _.``Sparse Data Flow Phi Test 2``() =
    let brew = Binaries.loadOne Binaries.sample6
    let cfg = brew.Functions[0UL].CFG
    let at addr =
      cfg.FindVertexBy(fun b -> b.VData.Internals.PPoint.Address = addr)
    let taken = cfg.FindEdge(at 0x0UL, at 0x9UL)
    cfg.RemoveEdge taken
    let cp = ConstantPropagation(brew.BinHandle, cfg.Vertices)
    let dfa = cp :> IDataFlowComputable<_, _, _>
    dfa.Compute cfg |> ignore
    cfg.AddEdge(taken.First, taken.Second, taken.Label)
    cp.State.MarkVertexAsPending taken.Second
    (* Bringing the taken branch back places a phi at 0x9, a vertex that has
       already run. The phi must still join both of its operands, including
       the caller's EAX. *)
    let state = dfa.Compute cfg
    let out = state.GetAbsValue(irReg 0x9UL 0 Register.EAX)
    Assert.AreEqual<ConstantDomain.Lattice>(ConstantDomain.NotAConst, out)

  [<TestMethod>]
  member _.``Sparse Data Flow Phi Test 3``() =
    let state = computeWithLateBlock ()
    (* The late block passes on the 5 from 0x3 only until its own store of 7
       shows up, so the phi at 0x4b must never join that 5. *)
    let out = state.GetAbsValue(irStk 0x4BUL 0 -12)
    Assert.AreEqual<ConstantDomain.Lattice>(mkConst 7u 32<rt>, out)

  [<TestMethod>]
  member _.``Sparse Data Flow Phi Test 4``() =
    let state = computeWithLateBlock ()
    (* The late block stops passing on the 5 from 0xb once its own store shows
       up, but the block at 0x43 still does, so the phi at 0x4b remains a use
       of that store. *)
    let uses = state.DefUseMap[irStk 0xBUL 1 -8]
    Assert.AreEqual<bool>(true, uses.Contains(irStk 0x4BUL 0 -8))

  [<TestMethod>]
  member _.``Sparse Data Flow Removal Test 1``() =
    let brew = Binaries.loadOne Binaries.sample7
    let cfg = brew.Functions[0UL].CFG
    let cp = ConstantPropagation(brew.BinHandle, cfg.Vertices)
    let dfa = cp :> IDataFlowComputable<_, _, _>
    dfa.Compute cfg |> ignore
    let join =
      cfg.FindVertexBy(fun b -> b.VData.Internals.PPoint.Address = 0x4BUL)
    cp.State.MarkVertexAsRemoval join
    cfg.RemoveVertex join
    dfa.Compute cfg |> ignore
    (* The phi at 0x4b leaves the graph with its vertex, so the store at 0x31
       is no longer used there. *)
    let uses = cp.State.DefUseMap[irStk 0x31UL 1 -12]
    Assert.AreEqual<bool>(false, uses.Contains(irStk 0x4BUL 0 -12))
#endif

  [<TestMethod>]
  member _.``Sparse Data Flow Reset Test 1``() =
    let brew = Binaries.loadOne Binaries.sample1
    let cfg = brew.Functions[0UL].CFG
    let cp = ConstantPropagation(brew.BinHandle, cfg.Vertices)
    let state = cp.State
    for v in cfg.Vertices do state.MarkVertexAsRemoval v
    state.Reset()
    (* A reset state must not invalidate the discarded graph's vertices. *)
    Assert.AreEqual<bool>(false, fst <| state.DequeueVertexForRemoval())

  [<TestMethod>]
  member _.``Sensitive Data Flow Reset Test 1``() =
    let brew = Binaries.loadOne Binaries.sample3
    let cfg = brew.Functions[0UL].CFG
    let scheme =
      { new LowUIRSensitiveDataFlow.IScheme<int> with
          member _.DefaultExecutionContext = 0
          member _.TryComputeExecutionContext(_, exeCtx, _, _) = Some exeCtx
          member _.OnVertexNewlyAnalyzed _ = ()
          member _.OnRemoveVertex _ = () }
    let cp = LowUIRSensitiveConstantPropagation(brew.BinHandle, scheme)
    let state = cp.State
    for v in cfg.Vertices do state.TryMarkVertexAsRemoval v |> ignore
    state.Reset()
    (* A reset state must not invalidate the discarded graph's vertices. *)
    Assert.AreEqual<bool>(true, Seq.isEmpty state.VerticesForRemoval)
