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

namespace B2R2.DataFlow.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting

open B2R2
open B2R2.FrontEnd
open B2R2.BinGraph
open B2R2.DataFlow
open B2R2.MiddleEnd

[<TestClass>]
type ImperativeDataFlowTests () =

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

  let binary =
    [| 0x8Buy; 0x54uy; 0x24uy; 0x04uy; 0x56uy; 0x33uy; 0xF6uy; 0x8Duy; 0x4Euy;
       0x01uy; 0x3Buy; 0xD1uy; 0x77uy; 0x04uy; 0x8Buy; 0xC2uy; 0x5Euy; 0xC3uy;
       0x4Auy; 0x8Duy; 0x04uy; 0x31uy; 0x8Duy; 0x31uy; 0x8Buy; 0xC8uy; 0x83uy;
       0xEAuy; 0x01uy; 0x75uy; 0xF4uy; 0x5Euy; 0xC3uy |]

  let isa = ISA.Init Architecture.IntelX86 Endian.Little
  let hdl = BinHandler.Init (isa, binary)
  let ess = BinEssence.Init hdl [ NoReturnAnalysis () ]

  [<TestMethod>]
  member __.``Reaching Definitions Test 1``() =
    let cfg, root = ess.SCFG.GetFunctionCFG (0UL, IRCFG.initImperative)
    let rd = ReachingDefinitions (cfg)
    let ins, _outs = rd.Compute cfg root
    let v = cfg.FindVertexBy (fun b -> b.VData.PPoint.Address = 0xEUL) (* 2nd *)
    let result = ins.[v.GetID ()] |> Set.filter (fun v ->
      match v.VarExpr with
      | Regular _ -> true
      | _ -> false)
    let solution = [
      { ProgramPoint = ProgramPoint (0UL, 1)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.EDX) }
      { ProgramPoint = ProgramPoint (4UL, 2)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.ESP) }
      { ProgramPoint = ProgramPoint (5UL, 2)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.ESI) }
      { ProgramPoint = ProgramPoint (5UL, 3)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.OF) }
      { ProgramPoint = ProgramPoint (5UL, 4)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.CF) }
      { ProgramPoint = ProgramPoint (5UL, 5)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.SF) }
      { ProgramPoint = ProgramPoint (5UL, 6)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.ZF) }
      { ProgramPoint = ProgramPoint (5UL, 9)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.PF) }
      { ProgramPoint = ProgramPoint (5UL, 10)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.AF) }
      { ProgramPoint = ProgramPoint (7UL, 1)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.ECX) }
      { ProgramPoint = ProgramPoint (0xAUL, 4)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.CF) }
      { ProgramPoint = ProgramPoint (0xAUL, 5)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.OF) }
      { ProgramPoint = ProgramPoint (0xAUL, 6)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.AF) }
      { ProgramPoint = ProgramPoint (0xAUL, 7)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.SF) }
      { ProgramPoint = ProgramPoint (0xAUL, 8)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.ZF) }
      { ProgramPoint = ProgramPoint (0xAUL, 11)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.PF) } ]
    Assert.AreEqual (result, Set.ofList solution)

  [<TestMethod>]
  member __.``Use-Def Test 1``() =
    let cfg, root = ess.SCFG.GetFunctionCFG (0UL, IRCFG.initImperative)
    let chain = DataFlowChain.init cfg root false
    let vp =
      { ProgramPoint = ProgramPoint (0xEUL, 1)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.EDX) }
    let res = chain.UseDefChain |> Map.find vp |> Set.toArray
    let solution = [|
      { ProgramPoint = ProgramPoint (0x0UL, 1)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.EDX) } |]
    CollectionAssert.AreEqual (solution, res)

  [<TestMethod>]
  member __.``Use-Def Test 2``() =
    let cfg, root = ess.SCFG.GetFunctionCFG (0UL, IRCFG.initImperative)
    let chain = DataFlowChain.init cfg root true
    let vp =
      { ProgramPoint = ProgramPoint (0xEUL, 0)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.EDX) }
    let res = chain.UseDefChain |> Map.find vp |> Set.toArray
    let solution = [|
      { ProgramPoint = ProgramPoint (0x0UL, 0)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.EDX) } |]
    CollectionAssert.AreEqual (solution, res)

  [<TestMethod>]
  member __.``Use-Def Test 3``() =
    let cfg, root = ess.SCFG.GetFunctionCFG (0UL, IRCFG.initImperative)
    let chain = DataFlowChain.init cfg root false
    let vp =
      { ProgramPoint = ProgramPoint (0x1AUL, 1)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.EDX) }
    let res = chain.UseDefChain |> Map.find vp |> Set.toArray
    let solution = [|
      { ProgramPoint = ProgramPoint (0x12UL, 4)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.EDX) }
      { ProgramPoint = ProgramPoint (0x1AUL, 4)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.EDX) } |]
    CollectionAssert.AreEqual (solution, res)

[<TestClass>]
type PersistentDataFlowTests () =

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

  let binary =
    [| 0x8Buy; 0x54uy; 0x24uy; 0x04uy; 0x56uy; 0x33uy; 0xF6uy; 0x8Duy; 0x4Euy;
       0x01uy; 0x3Buy; 0xD1uy; 0x77uy; 0x04uy; 0x8Buy; 0xC2uy; 0x5Euy; 0xC3uy;
       0x4Auy; 0x8Duy; 0x04uy; 0x31uy; 0x8Duy; 0x31uy; 0x8Buy; 0xC8uy; 0x83uy;
       0xEAuy; 0x01uy; 0x75uy; 0xF4uy; 0x5Euy; 0xC3uy |]

  let isa = ISA.Init Architecture.IntelX86 Endian.Little
  let hdl = BinHandler.Init (isa, binary)
  let ess = BinEssence.Init hdl [ NoReturnAnalysis () ]

  [<TestMethod>]
  member __.``Reaching Definitions Test 1``() =
    let cfg, root = ess.SCFG.GetFunctionCFG (0UL, IRCFG.initPersistent)
    let rd = ReachingDefinitions (cfg)
    let ins, _outs = rd.Compute cfg root
    let v = cfg.FindVertexBy (fun b -> b.VData.PPoint.Address = 0xEUL) (* 2nd *)
    let result = ins.[v.GetID ()] |> Set.filter (fun v ->
      match v.VarExpr with
      | Regular _ -> true
      | _ -> false)
    let solution = [
      { ProgramPoint = ProgramPoint (0UL, 1)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.EDX) }
      { ProgramPoint = ProgramPoint (4UL, 2)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.ESP) }
      { ProgramPoint = ProgramPoint (5UL, 2)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.ESI) }
      { ProgramPoint = ProgramPoint (5UL, 3)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.OF) }
      { ProgramPoint = ProgramPoint (5UL, 4)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.CF) }
      { ProgramPoint = ProgramPoint (5UL, 5)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.SF) }
      { ProgramPoint = ProgramPoint (5UL, 6)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.ZF) }
      { ProgramPoint = ProgramPoint (5UL, 9)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.PF) }
      { ProgramPoint = ProgramPoint (5UL, 10)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.AF) }
      { ProgramPoint = ProgramPoint (7UL, 1)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.ECX) }
      { ProgramPoint = ProgramPoint (0xAUL, 4)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.CF) }
      { ProgramPoint = ProgramPoint (0xAUL, 5)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.OF) }
      { ProgramPoint = ProgramPoint (0xAUL, 6)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.AF) }
      { ProgramPoint = ProgramPoint (0xAUL, 7)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.SF) }
      { ProgramPoint = ProgramPoint (0xAUL, 8)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.ZF) }
      { ProgramPoint = ProgramPoint (0xAUL, 11)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.PF) } ]
    Assert.AreEqual (result, Set.ofList solution)

  [<TestMethod>]
  member __.``Use-Def Test 1``() =
    let cfg, root = ess.SCFG.GetFunctionCFG (0UL, IRCFG.initPersistent)
    let chain = DataFlowChain.init cfg root false
    let vp =
      { ProgramPoint = ProgramPoint (0xEUL, 1)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.EDX) }
    let res = chain.UseDefChain |> Map.find vp |> Set.toArray
    let solution = [|
      { ProgramPoint = ProgramPoint (0x0UL, 1)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.EDX) } |]
    CollectionAssert.AreEqual (solution, res)

  [<TestMethod>]
  member __.``Use-Def Test 2``() =
    let cfg, root = ess.SCFG.GetFunctionCFG (0UL, IRCFG.initPersistent)
    let chain = DataFlowChain.init cfg root true
    let vp =
      { ProgramPoint = ProgramPoint (0xEUL, 0)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.EDX) }
    let res = chain.UseDefChain |> Map.find vp |> Set.toArray
    let solution = [|
      { ProgramPoint = ProgramPoint (0x0UL, 0)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.EDX) } |]
    CollectionAssert.AreEqual (solution, res)

  [<TestMethod>]
  member __.``Use-Def Test 3``() =
    let cfg, root = ess.SCFG.GetFunctionCFG (0UL, IRCFG.initPersistent)
    let chain = DataFlowChain.init cfg root false
    let vp =
      { ProgramPoint = ProgramPoint (0x1AUL, 1)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.EDX) }
    let res = chain.UseDefChain |> Map.find vp |> Set.toArray
    let solution = [|
      { ProgramPoint = ProgramPoint (0x12UL, 4)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.EDX) }
      { ProgramPoint = ProgramPoint (0x1AUL, 4)
        VarExpr = Regular (Intel.Register.toRegID Intel.Register.EDX) } |]
    CollectionAssert.AreEqual (solution, res)
