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
open System.Diagnostics

open B2R2
open B2R2.BinIR
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.ControlFlowAnalysis.Strategies
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.ControlFlowGraph

[<TestClass>]
type PersistentDataFlowTests () =

  let getBrewFromBinary arch (binary: byte[]) =
    let isa = ISA.Init arch Endian.Little
    let hdl = BinHandle (binary, isa, ArchOperationMode.NoMode, None, false)
    let exnInfo = ExceptionInfo hdl
    let funcId = FunctionIdentification (hdl, exnInfo)
    let strategies =
      [| funcId :> ICFGBuildingStrategy<_, _, _, _>; CFGRecovery () |]
    BinaryBrew (hdl, exnInfo, strategies)

  (*
    Example 1: Fibonacci function

    unsigned int fib(unsigned int m)
    {
        unsigned int f0 = 0, f1 = 1, f2, i;
        if (m <= 1) return m;
        else {
            for (i = 2; i <= m; i++) {
                f2 = f0 + f1;
                f0 = f1;
                f1 = f2;
            }
            return f2;
        }
    }

    00000000: 8B 54 24 04        mov         edx,dword ptr [esp+4]
    00000004: 56                 push        esi
    00000005: 33 F6              xor         esi,esi
    00000007: 8D 4E 01           lea         ecx,[esi+1]
    0000000A: 3B D1              cmp         edx,ecx
    0000000C: 77 04              ja          00000012
    0000000E: 8B C2              mov         eax,edx
    00000010: 5E                 pop         esi
    00000011: C3                 ret
    00000012: 4A                 dec         edx
    00000013: 8D 04 31           lea         eax,[ecx+esi]
    00000016: 8D 31              lea         esi,[ecx]
    00000018: 8B C8              mov         ecx,eax
    0000001A: 83 EA 01           sub         edx,1
    0000001D: 75 F4              jne         00000013
    0000001F: 5E                 pop         esi
    00000020: C3                 ret

    8B5424045633F68D4E013BD177048BC25EC34A8D04318D318BC883EA0175F45EC3
  *)

  let binary1 =
    [| 0x8Buy; 0x54uy; 0x24uy; 0x04uy; 0x56uy; 0x33uy; 0xF6uy; 0x8Duy; 0x4Euy;
       0x01uy; 0x3Buy; 0xD1uy; 0x77uy; 0x04uy; 0x8Buy; 0xC2uy; 0x5Euy; 0xC3uy;
       0x4Auy; 0x8Duy; 0x04uy; 0x31uy; 0x8Duy; 0x31uy; 0x8Buy; 0xC8uy; 0x83uy;
       0xEAuy; 0x01uy; 0x75uy; 0xF4uy; 0x5Euy; 0xC3uy |]
  let brew1 = getBrewFromBinary Architecture.IntelX86 binary1

  (*
    Example 2: An example from Dragon Book, p636

    void example(int cond)
    {
        int x, y, z;
        if (cond) {
            x = 2;
            y = 3;
        }
        else {
            x = 3;
            y = 2;
        }
        z = x + y;
    }

    0000000000000000 <example>:
     0:   f3 0f 1e fa             endbr64
     4:   55                      push   rbp
     5:   48 89 e5                mov    rbp,rsp
     8:   89 7d ec                mov    DWORD PTR [rbp-0x14],edi
     b:   83 7d ec 00             cmp    DWORD PTR [rbp-0x14],0x0
     f:   74 10                   je     21 <example+0x21>
    11:   c7 45 f4 02 00 00 00    mov    DWORD PTR [rbp-0xc],0x2
    18:   c7 45 f8 03 00 00 00    mov    DWORD PTR [rbp-0x8],0x3
    1f:   eb 0e                   jmp    2f <example+0x2f>
    21:   c7 45 f4 03 00 00 00    mov    DWORD PTR [rbp-0xc],0x3
    28:   c7 45 f8 02 00 00 00    mov    DWORD PTR [rbp-0x8],0x2
    2f:   8b 55 f4                mov    edx,DWORD PTR [rbp-0xc]
    32:   8b 45 f8                mov    eax,DWORD PTR [rbp-0x8]
    35:   01 d0                   add    eax,edx
    37:   89 45 fc                mov    DWORD PTR [rbp-0x4],eax
    3a:   90                      nop
    3b:   5d                      pop    rbp
    3c:   c3                      ret

    00000000: f30f 1efa 5548 89e5 897d ec83 7dec 0074  ....UH...}..}..t
    00000010: 10c7 45f4 0200 0000 c745 f803 0000 00eb  ..E......E......
    00000020: 0ec7 45f4 0300 0000 c745 f802 0000 008b  ..E......E......
    00000030: 55f4 8b45 f801 d089 45fc 905d c3         U..E....E..].
  *)

  let binary2 =
    [| 0xF3uy; 0x0Fuy; 0x1Euy; 0xFAuy; 0x55uy; 0x48uy; 0x89uy; 0xE5uy; 0x89uy;
       0x7Duy; 0xECuy; 0x83uy; 0x7Duy; 0xECuy; 0x00uy; 0x74uy; 0x10uy; 0xC7uy;
       0x45uy; 0xF4uy; 0x02uy; 0x00uy; 0x00uy; 0x00uy; 0xC7uy; 0x45uy; 0xF8uy;
       0x03uy; 0x00uy; 0x00uy; 0x00uy; 0xEBuy; 0x0Euy; 0xC7uy; 0x45uy; 0xF4uy;
       0x03uy; 0x00uy; 0x00uy; 0x00uy; 0xC7uy; 0x45uy; 0xF8uy; 0x02uy; 0x00uy;
       0x00uy; 0x00uy; 0x8Buy; 0x55uy; 0xF4uy; 0x8Buy; 0x45uy; 0xF8uy; 0x01uy;
       0xD0uy; 0x89uy; 0x45uy; 0xFCuy; 0x90uy; 0x5Duy; 0xC3uy |]
  let brew2 = getBrewFromBinary Architecture.IntelX64 binary2

#if !EMULATION
  [<TestMethod>]
  member __.``Reaching Definitions Test 1``() =
    let cfg = brew1.Functions[0UL].CFG
    let dfa = ReachingDefinitionAnalysis () :> IDataFlowAnalysis<_, _, _, _>
    dfa.Compute cfg
    let v = cfg.FindVertexBy (fun b -> b.VData.PPoint.Address = 0xEUL) (* 2nd *)
    let rd = dfa.GetAbsValue v.ID
    let ins =
      rd.Ins |> Set.filter (fun v ->
      match v.VarKind with
      | Regular _ -> true
      | _ -> false)
    let solution = [
      { ProgramPoint = ProgramPoint (0UL, 1)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.EDX) }
      { ProgramPoint = ProgramPoint (4UL, 1)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.ESP) }
      { ProgramPoint = ProgramPoint (5UL, 1)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.ESI) }
      { ProgramPoint = ProgramPoint (5UL, 2)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.OF) }
      { ProgramPoint = ProgramPoint (5UL, 3)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.CF) }
      { ProgramPoint = ProgramPoint (5UL, 4)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.SF) }
      { ProgramPoint = ProgramPoint (5UL, 5)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.ZF) }
      { ProgramPoint = ProgramPoint (5UL, 6)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.PF) }
      { ProgramPoint = ProgramPoint (5UL, 7)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.AF) }
      { ProgramPoint = ProgramPoint (7UL, 1)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.ECX) }
      { ProgramPoint = ProgramPoint (0xAUL, 4)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.CF) }
      { ProgramPoint = ProgramPoint (0xAUL, 5)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.OF) }
      { ProgramPoint = ProgramPoint (0xAUL, 6)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.AF) }
      { ProgramPoint = ProgramPoint (0xAUL, 7)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.SF) }
      { ProgramPoint = ProgramPoint (0xAUL, 8)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.ZF) }
      { ProgramPoint = ProgramPoint (0xAUL, 11)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.PF) } ]
    Assert.AreEqual (Set.ofList solution, ins)
#endif

  [<TestMethod>]
  member __.``Use-Def Test 1``() =
    let cfg = brew1.Functions[0UL].CFG
    let chain = DataFlowChain.init cfg false
    let vp =
      { ProgramPoint = ProgramPoint (0xEUL, 1)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.EDX) }
    let res = chain.UseDefChain |> Map.find vp |> Set.toArray
    let solution = [|
      { ProgramPoint = ProgramPoint (0x0UL, 1)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.EDX) } |]
    CollectionAssert.AreEqual (solution, res)

  [<TestMethod>]
  member __.``Use-Def Test 2``() =
    let cfg = brew1.Functions[0UL].CFG
    let chain = DataFlowChain.init cfg true
    let vp =
      { ProgramPoint = ProgramPoint (0xEUL, 0)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.EDX) }
    let res = chain.UseDefChain |> Map.find vp |> Set.toArray
    let solution = [|
      { ProgramPoint = ProgramPoint (0x0UL, 0)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.EDX) } |]
    CollectionAssert.AreEqual (solution, res)

#if !EMULATION
  [<TestMethod>]
  member __.``Use-Def Test 3``() =
    let cfg = brew1.Functions[0UL].CFG
    let chain = DataFlowChain.init cfg false
    let vp =
      { ProgramPoint = ProgramPoint (0x1AUL, 1)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.EDX) }
    let res = chain.UseDefChain |> Map.find vp |> Set.toArray
    let solution = [|
      { ProgramPoint = ProgramPoint (0x12UL, 3)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.EDX) }
      { ProgramPoint = ProgramPoint (0x1AUL, 3)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.EDX) } |]
    CollectionAssert.AreEqual (solution, res)
#endif

  [<TestMethod>]
  member __.``SSA Constant Propagation Test 1`` () =
    let fn = brew2.Functions[0UL]
    let lifter = SSA.SSALifter ()
    let cfg = (lifter: SSA.ISSALiftable<CFGEdgeKind>).Lift fn.CFG
    let hdl = brew2.BinHandle
    let cp = SSA.SSAConstantPropagation hdl
    let dfa = cp :> IDataFlowAnalysis<_, _, _, _>
    dfa.Compute cfg
    cfg.IterVertex (fun v ->
      Debug.Print $"[Vertex {v.VData.PPoint.Address:x}]"
      let inss = v.VData.LiftedSSAStmts
      let stmts = inss |> Array.map (fun (_, stmt) -> stmt)
      Debug.Print <| $"{SSA.Pp.stmtsToString stmts}")
    let rt = 64<rt>
    let genRegularVar r id =
      let rid = Intel.Register.toRegID r
      let rstr = Intel.Register.toString r
      let v = SSA.RegVar (rt, rid, rstr)
      SSA.SSAVarPoint.RegularSSAVar { Kind = v; Identifier = id }
    let genMemVar memId addr = SSA.SSAVarPoint.MemorySSAVar (memId, addr)
    let regularVarEq r id c =
      let vp = genRegularVar r id
      (vp, c)
    let memVarEq memId addr c =
      let vp = genMemVar memId addr
      (vp, c)
    let regularVarNotConst r id =
      regularVarEq r id ConstantDomain.NotAConst
    let regularVarConst r id value =
      regularVarEq r id (ConstantDomain.Const (BitVector.OfUInt64 value rt))
    let regularVarUndef r id =
      regularVarEq r id ConstantDomain.Undef
    let memVarNotConst memId addr =
      memVarEq memId addr ConstantDomain.NotAConst
    let memVarConst memId addr value =
      memVarEq memId addr (ConstantDomain.Const (BitVector.OfUInt64 value rt))
    let memVarUndef memId addr =
      memVarEq memId addr ConstantDomain.Undef
    let varAnsMap =
      [ regularVarConst Intel.Register.RSP 0 0x80000000UL
        regularVarConst Intel.Register.RSP 1 0x7ffffff8UL
        regularVarUndef Intel.Register.RBP 0
        regularVarConst Intel.Register.RBP 1 0x7ffffff8UL
        memVarUndef 1 0x7ffffff8UL
        memVarConst 5 (0x7ffffff8UL - 0xcUL) 0x2UL
        memVarConst 6 (0x7ffffff8UL - 0x8UL) 0x3UL
        memVarConst 7 (0x7ffffff8UL - 0xcUL) 0x3UL
        memVarConst 8 (0x7ffffff8UL - 0x8UL) 0x2UL
        memVarNotConst 3 (0x7ffffff8UL - 0xcUL)
        memVarNotConst 3 (0x7ffffff8UL - 0x8UL)
        regularVarNotConst Intel.Register.RAX 1
        regularVarNotConst Intel.Register.RDX 1
        regularVarNotConst Intel.Register.RAX 2
        regularVarNotConst Intel.Register.RBP 2
        regularVarConst Intel.Register.RSP 2 (0x7ffffff8UL + 0x8UL)
        regularVarConst Intel.Register.RSP 3 (0x7ffffff8UL + 0x10UL) ]
    varAnsMap |> List.iter (fun (var, ans) ->
      let out = dfa.GetAbsValue var
      Debug.Print <| sprintf "%A: %A <-> %A" var ans out
      Assert.AreEqual (ans, out))

  [<TestMethod>]
  member __.``Incremental Data Flow Test 1``() =
    let cfg = brew2.Functions[0UL].CFG
    let rt = 64<rt>
    let roots = cfg.GetRoots ()
    let regValues =
      (Intel.Register.RSP, Constants.InitialStackPointer)
      |> fun (r, v) -> Intel.Register.toRegID r, BitVector.OfUInt64 v rt
      |> Seq.singleton
      |> Map.ofSeq
    let genRegularVar addr i r =
      let rid = Intel.Register.toRegID r
      let pp = ProgramPoint (addr, i)
      let varKind = VarKind.Regular rid
      { ProgramPoint = pp; VarKind = varKind }
    let genMemVar addr i memAddr =
      let pp = ProgramPoint (addr, i)
      let varKind = VarKind.Memory (Some memAddr)
      { ProgramPoint = pp; VarKind = varKind }
    let regularVarEq addr i r c =
      let vp = genRegularVar addr i r
      vp, c
    let memVarEq addr i memAddr c =
      let vp = genMemVar addr i memAddr
      vp, c
    let regularVarConst addr i r value =
      regularVarEq addr i r (ConstantDomain.Const (BitVector.OfUInt64 value rt))
    let regularVarUndef addr i r =
      regularVarEq addr i r ConstantDomain.Undef
    let memVarNotConst addr i memAddr =
      memVarEq addr i memAddr ConstantDomain.NotAConst
    let memVarDWordConst addr i memAddr v =
      memVarEq addr i memAddr (ConstantDomain.Const (BitVector.OfUInt32 v 32<rt>))
    let memVarUndef addr i memAddr =
      memVarEq addr i memAddr ConstantDomain.Undef
    let varAnsMap =
      [ regularVarConst 0x0UL 0 Intel.Register.RSP 0x80000000UL
        regularVarConst 0x4UL 1 Intel.Register.RSP 0x7ffffff8UL
        regularVarUndef 0x5UL 0 Intel.Register.RBP
        regularVarConst 0x5UL 1 Intel.Register.RBP 0x7ffffff8UL
        memVarUndef 0xbUL 1 0x7ffffff8UL
        memVarDWordConst 0x11UL 1 (0x7ffffff8UL - 0xcUL) 0x2ul
        memVarDWordConst 0x18UL 1 (0x7ffffff8UL - 0x8UL) 0x3ul
        memVarDWordConst 0x21UL 1 (0x7ffffff8UL - 0xcUL) 0x3ul
        memVarDWordConst 0x28UL 1 (0x7ffffff8UL - 0x8UL) 0x2ul
        memVarNotConst 0x2fUL 0 (0x7ffffff8UL - 0xcUL)
        memVarNotConst 0x2fUL 0 (0x7ffffff8UL - 0x8UL)
        regularVarConst 0x3bUL 2 Intel.Register.RSP (0x7ffffff8UL + 0x8UL)
        regularVarConst 0x3cUL 2 Intel.Register.RSP (0x7ffffff8UL + 0x10UL) ]
    let idfa =
      { new IncrementalDataFlowAnalysis<int, CFGEdgeKind> () with
        member __.Bottom = 0
        member __.Transfer (_, _, _, _) = None
        member __.IsSubsumable (_, _) = true
        member __.Join (_, _) = 0 }
    let dfa = idfa :> IDataFlowAnalysis<_, _, _, _>
    Seq.iter idfa.PushWork roots
    idfa.SetInitialRegisterConstants regValues
    dfa.Compute cfg
    varAnsMap |> List.iter (fun (vp, ans) ->
      let out = idfa.GetConstant vp
      Assert.AreEqual (ans, out))
