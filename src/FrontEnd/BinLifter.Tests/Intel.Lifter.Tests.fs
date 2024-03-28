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

module B2R2.FrontEnd.Tests.IntelLifter

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.Intel
open type Register

[<AutoOpen>]
module TestHelper =
  let num v rt = BitVector.OfUInt32 v rt |> AST.num

  let t1 id = AST.tmpvar 1<rt> id

  let t32 id = AST.tmpvar 32<rt> id

  let t64 id = AST.tmpvar 64<rt> id

  let unwrapStmts stmts = Array.sub stmts 1 (Array.length stmts - 2)

  let inline ( ++ ) byteStr givenStmts =
    ByteArray.ofHexString byteStr, Array.ofList givenStmts

  let inline ( ** ) stmts eflagsStmts = List.append stmts eflagsStmts

  let test ctxt wordSize (givenStmts: Stmt[]) (bytes: byte[]) =
    let parser = IntelParser (wordSize) :> IInstructionParsable
    let ins = parser.Parse (bytes, 0UL) :?> IntelInternalInstruction
    CollectionAssert.AreEqual (givenStmts, unwrapStmts <| ins.Translate ctxt)

  let testX86 ctxt (bytes: byte[], givenStmts) =
    test ctxt WordSize.Bit32 givenStmts bytes

  let testX64 ctxt (bytes: byte[], givenStmts) =
    test ctxt WordSize.Bit64 givenStmts bytes

  let eflagsOnAdd srcE dstE addVal operator =
    let ( !. ) = operator
    let tmpvarId =
      match dstE with
      | { E = TempVar (_, id) } -> id
      | _ -> failwithf "Expr should be tmpvar"
    [ t1 (tmpvarId + 1) := AST.xthi 1<rt> <| srcE
      t1 (tmpvarId + 2) := AST.xthi 1<rt> <| dstE
      !.CF := dstE .< srcE
      !.OF := (t1 (tmpvarId + 1) == AST.num0 1<rt>)
        .& (t1 (tmpvarId + 1) <+> t1 (tmpvarId + 2))
      !.AF := (((dstE <+> srcE) <+> num addVal 32<rt>) .& num 0x10u 32<rt>)
        == num 0x10u 32<rt>
      !.SF := t1 (tmpvarId + 2)
      !.ZF := dstE == AST.num0 32<rt>
      t32 (tmpvarId + 3) := dstE <+> (dstE >> num 0x4u 32<rt>)
      t32 (tmpvarId + 4) := t32 (tmpvarId + 3)
        <+> (t32 (tmpvarId + 3) >> num 0x2u 32<rt>)
      !.PF := AST.not <| AST.xtlo 1<rt> (t32 (tmpvarId + 4)
        <+> (t32 (tmpvarId + 4) >> AST.num1 32<rt>)) ]

#if !EMULATION
[<TestClass>]
type IntelX86UnitTest () =
  let isa = ISA.Init Architecture.IntelX86 Endian.Little

  let ctxt = IntelTranslationContext isa

  let ( !. ) name = Register.toRegID name |> ctxt.GetRegVar

  [<TestMethod>]
  member __.``[X86] ADD instruction lift Test (1)`` () =
    "0500000100"
    ++ [ t32 1 := !.EAX
         t32 2 := t32 1 .+ num 0x10000u 32<rt>
         !.EAX := t32 2 ]
    ** eflagsOnAdd (t32 1) (t32 2) (0x10000u) (!.)
    |> testX86 ctxt

  [<TestMethod>]
  member __.``[X86] ADD instruction lift Test (2)`` () =
    "8340100a"
    ++ [ t32 1 := !.EAX .+ num 0x10u 32<rt>
         t32 2 := AST.loadLE 32<rt> <| t32 1
         t32 3 := t32 2 .+ num 0xau 32<rt>
         AST.loadLE 32<rt> <| t32 1 := t32 3 ]
    ** eflagsOnAdd (t32 2) (t32 3) (0xau) (!.)
    |> testX86 ctxt

[<TestClass>]
type IntelX64UnitTest () =
  let isa = ISA.Init Architecture.IntelX64 Endian.Little

  let ctxt = IntelTranslationContext isa

  let ( !. ) name = Register.toRegID name |> ctxt.GetRegVar

  [<TestMethod>]
  member __.``[X64] ADD instruction lift Test (1)`` () =
    "0500000100"
    ++ [ t32 1 := AST.xtlo 32<rt> !.RAX
         t32 2 := t32 1 .+ num 0x10000u 32<rt>
         !.RAX := AST.zext 64<rt> <| t32 2 ]
    ** eflagsOnAdd (t32 1) (t32 2) (0x10000u) (!.)
    |> testX64 ctxt

  [<TestMethod>]
  member __.``[X64] ADD instruction lift Test (2)`` () =
    "8340100a"
    ++ [ t64 1 := !.RAX .+ num 0x10ul 64<rt>
         t32 2 := AST.loadLE 32<rt> <| t64 1
         t32 3 := t32 2 .+ num 0xau 32<rt>
         AST.loadLE 32<rt> <| t64 1 := t32 3 ]
    ** eflagsOnAdd (t32 2) (t32 3) (0xau) (!.)
    |> testX64 ctxt
#endif
