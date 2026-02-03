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
open B2R2.MiddleEnd.DataFlow
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
      | _ -> findVarDefFromStmts stmts vaddr (idx + 1) addr kind
    else None

  let rec findSSAVarDef (ssaCFG: SSACFG) vidx addr kind =
    if vidx < ssaCFG.Vertices.Length then
      let v = ssaCFG.Vertices[vidx]
      let stmts = v.VData.Internals.Statements
      findVarDefFromStmts stmts v.VData.Internals.PPoint.Address 0 addr kind
      |> function
        | Some v -> v
        | None -> findSSAVarDef ssaCFG (vidx + 1) addr kind
    else failwith $"variable {kind} @ {addr:x} not found"

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

  let mkUntouchedReg r =
    Regular(Register.toRegID r)
    |> UntouchedValueDomain.RegisterTag
    |> UntouchedValueDomain.Untouched

  let cmp vp c = vp, c

#if !EMULATION
  [<TestMethod>]
  member _.``Reaching Definitions Test 1``() =
    let brew = Binaries.loadOne Binaries.sample1
    let cfg = brew.Functions[0UL].CFG
    let dfa = ReachingDefinitionAnalysis() :> IDataFlowComputable<_, _, _, _>
    let state = dfa.Compute cfg
    let v = cfg.FindVertex(fun b -> b.VData.Internals.PPoint.Address = 0xEUL)
    let rd = (state :> IAbsValProvider<_, _>).GetAbsValue v.ID (* 2nd vertex *)
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
  member _.``Use-Def Test 1``() =
    let brew = Binaries.loadOne Binaries.sample1
    let cfg = brew.Functions[0UL].CFG
    let chain = DataFlowChain.init cfg false
    let vp = reg 0xEUL 1 Register.EDX
    let res = chain.UseDefChain |> Map.find vp |> Set.toArray
    let solution = [| reg 0x0UL 1 Register.EDX |]
    CollectionAssert.AreEqual(solution, res)

  [<TestMethod>]
  member _.``Use-Def Test 2``() =
    let brew = Binaries.loadOne Binaries.sample1
    let cfg = brew.Functions[0UL].CFG
    let chain = DataFlowChain.init cfg true
    let vp = reg 0xEUL 0 Register.EDX
    let res = chain.UseDefChain |> Map.find vp |> Set.toArray
    let solution = [| reg 0x0UL 0 Register.EDX |]
    CollectionAssert.AreEqual(solution, res)

#if !EMULATION
  [<TestMethod>]
  member _.``Use-Def Test 3``() =
    let brew = Binaries.loadOne Binaries.sample1
    let cfg = brew.Functions[0UL].CFG
    let chain = DataFlowChain.init cfg false
    let vp = reg 0x1AUL 1 Register.EDX
    let res = chain.UseDefChain |> Map.find vp |> Set.toArray
    let solution = [| reg 0x12UL 3 Register.EDX; reg 0x1AUL 3 Register.EDX |]
    CollectionAssert.AreEqual(solution, res)
#endif

  [<TestMethod>]
  member _.``SSA Constant Propagation Test 1``() =
    let brew = Binaries.loadOne Binaries.sample2
    let cfg = brew.Functions[0UL].CFG
    let lifter = SSALifterFactory.Create(brew.BinHandle)
    let g = lifter.Lift cfg
    let cp = SSAConstantPropagation brew.BinHandle
    let dfa = cp :> IDataFlowComputable<_, _, _, _>
    let state = dfa.Compute g
    [ ssaRegInitial Register.RSP 64<rt> |> cmp <| mkConst 0x80000000u 64<rt>
      ssaRegInitial Register.RBP 64<rt> |> cmp <| ConstantDomain.Undef
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
      ssaReg g Register.RBP 0x3bUL 64<rt> |> cmp <| ConstantDomain.Undef
      ssaReg g Register.RSP 0x3bUL 64<rt> |> cmp <| mkConst 0x80000000u 64<rt>
      ssaReg g Register.RSP 0x3CUL 64<rt> |> cmp <| mkConst 0x80000008u 64<rt> ]
    |> List.iter (fun (var, ans) ->
      let out = (state :> IAbsValProvider<_, _>).GetAbsValue var
      Assert.AreEqual<ConstantDomain.Lattice>(ans, out))

#if !EMULATION
  [<TestMethod>]
  member _.``Constant Propagation Test 1``() =
    let brew = Binaries.loadOne Binaries.sample2
    let hdl = brew.BinHandle
    let cfg = brew.Functions[0UL].CFG
    let varDfa = ConstantPropagation(hdl, cfg.Vertices)
    let dfa = varDfa :> IDataFlowComputable<_, _, _, _>
    let state = dfa.Compute cfg
    let rbp = -8 (* stack offset of old rbp *)
    [ irStk 0xbUL 1 rbp |> cmp <| ConstantDomain.Undef
      irStk 0x11UL 1 (rbp - 0xc) |> cmp <| mkConst 0x2u 32<rt>
      irStk 0x18UL 1 (rbp - 0x8) |> cmp <| mkConst 0x3u 32<rt>
      irStk 0x21UL 1 (rbp - 0xc) |> cmp <| mkConst 0x3u 32<rt>
      irStk 0x28UL 1 (rbp - 0x8) |> cmp <| mkConst 0x2u 32<rt>
      irReg 0x2fUL 1 Register.RDX |> cmp <| ConstantDomain.NotAConst ]
    |> List.iter (fun (vp, ans) ->
      let out = (state :> IAbsValProvider<_, _>).GetAbsValue vp
      Assert.AreEqual<ConstantDomain.Lattice>(ans, out))
#endif

  [<TestMethod>]
  member _.``Untouched Value Analysis 1``() =
    let brew = Binaries.loadOne Binaries.sample3
    let cfg = brew.Functions[0UL].CFG
    let roots = cfg.Roots
    let uva = UntouchedValueAnalysis(brew.BinHandle, roots)
    let dfa = uva :> IDataFlowComputable<_, _, _, _>
    cfg.IterVertex uva.MarkVertexAsPending
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
      let out = (state :> IAbsValProvider<_, _>).GetAbsValue vp
      Assert.AreEqual<UntouchedValueDomain.Lattice>(ans, out))
