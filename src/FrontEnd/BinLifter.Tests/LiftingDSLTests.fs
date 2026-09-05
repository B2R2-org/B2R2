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

namespace B2R2.FrontEnd.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils

/// Provides a bare LowUIR builder that only knows how to hold a stream, which
/// is all the lifting DSL ever asks of a builder.
[<AutoOpen>]
module private LiftingDSLTestHelper =
  let newBuilder () =
    let stream = LowUIRStream()
    { new ILowUIRBuilder with
        member _.WordSize with get() = WordSize.Bit64
        member _.RegType with get() = 64<rt>
        member _.Endianness with get() = Endian.Little
        member _.Stream with get() = stream
        member _.ISA with get() = ISA Architecture.Intel
#if EMULATION
        member _.ConditionCodeOp
          with get() = Terminator.impossible ()
            and set _ = Terminator.impossible ()
#endif
        member _.GetRegVar(rid: RegisterID): Expr = AST.var 64<rt> rid "R"
        member _.GetRegVar(_: string): Expr = Terminator.impossible ()
        member _.GetPseudoRegVar(_, _) = Terminator.impossible ()
        member _.GetAllRegVars() = Terminator.impossible ()
        member _.GetGeneralRegVars() = Terminator.impossible ()
        member _.GetRegisterID(_: Expr): RegisterID = Terminator.impossible ()
        member _.GetRegisterID(_: string): RegisterID =
          Terminator.impossible ()
        member _.GetRegisterIDAliases _ = Terminator.impossible ()
        member _.GetRegisterName _ = Terminator.impossible ()
        member _.GetAllRegisterNames() = Terminator.impossible ()
        member _.GetRegType _ = Terminator.impossible ()
        member _.ProgramCounter = Terminator.impossible ()
        member _.StackPointer with get() = Terminator.impossible ()
        member _.FramePointer with get() = Terminator.impossible ()
        member _.IsProgramCounter _ = Terminator.impossible ()
        member _.IsStackPointer _ = Terminator.impossible ()
        member _.IsFramePointer _ = Terminator.impossible () }

  /// Starts a lift computation expression at the given address, standing in
  /// for `lift` where the test has no instruction to hand it.
  let liftAt bld addr insLen = LiftBuilder(bld, addr, insLen, true)

[<TestClass>]
type LiftingDSLTests() =
  let num v = BitVector(u32 = v, bitLen = 32<rt>) |> AST.num

  let varA = AST.var 32<rt> (RegisterID.create 0) "A"

  let varB = AST.var 32<rt> (RegisterID.create 1) "B"

  let varC = AST.var 32<rt> (RegisterID.create 2) "C"

  /// Renames every label id to the order in which the label is first seen, so
  /// that two streams that differ only in label creation order compare equal.
  let canonicalize (stmts: Stmt[]) =
    let ids = System.Collections.Generic.Dictionary<int, int>()
    let renumber (lbl: Label) =
      match ids.TryGetValue lbl.Id with
      | true, newId ->
        AST.label lbl.Name newId lbl.Address
      | _ ->
        let newId = ids.Count
        ids[lbl.Id] <- newId
        AST.label lbl.Name newId lbl.Address
    let renameDest e =
      match e with
      | JmpDest(lbl, _) ->
        AST.jmpDest (renumber lbl)
      | _ ->
        e
    stmts
    |> Array.map (fun stmt ->
      match stmt with
      | LMark(lbl, _) ->
        AST.lmark (renumber lbl)
      | Jmp(dst, _) ->
        AST.jmp (renameDest dst)
      | CJmp(cond, t, f, _) ->
        AST.cjmp cond (renameDest t) (renameDest f)
      | _ ->
        stmt)

  /// Asserts that the DSL emits the very same stream as the hand-written form,
  /// modulo label ids.
  let assertSameIR handWritten dsl =
    let bld = newBuilder ()
    handWritten bld
    let expected = bld.Stream.ToStmts()
    dsl bld
    let actual = bld.Stream.ToStmts()
    CollectionAssert.AreEqual(canonicalize expected, canonicalize actual)

  [<TestMethod>]
  member _.``[LiftingDSL] Straight-line statements``() =
    assertSameIR
      (fun bld ->
        markStart bld 0UL 4u
        bld.Stream.Append(varA := num 1u)
        bld.Stream.Append(varB := num 2u)
        bld.Stream.Append(varC := varA .+ varB)
        markEnd bld 4u)
      (fun bld ->
        liftAt bld 0UL 4u {
          varA := num 1u
          varB := num 2u
          varC := varA .+ varB
        } |> ignore)

  [<TestMethod>]
  member _.``[LiftingDSL] Statements mixed with emitting helpers``() =
    let helper (bld: ILowUIRBuilder) =
      bld.Stream.Append(varB := num 2u)
      bld.Stream.Append(varC := num 3u)
    assertSameIR
      (fun bld ->
        markStart bld 0UL 4u
        bld.Stream.Append(varA := num 1u)
        helper bld
        bld.Stream.Append(varA := num 4u)
        markEnd bld 4u)
      (fun bld ->
        liftAt bld 0UL 4u {
          varA := num 1u
          helper bld
          varA := num 4u
        } |> ignore)

  [<TestMethod>]
  member _.``[LiftingDSL] _when falls through without a jump``() =
    assertSameIR
      (fun bld ->
        markStart bld 0UL 4u
        let lblThen = label bld "Then"
        let lblEnd = label bld "ThenEnd"
        let cond = varA == num 0u
        bld.Stream.Append(AST.cjmp cond
                                   (AST.jmpDest lblThen)
                                   (AST.jmpDest lblEnd))
        bld.Stream.Append(AST.lmark lblThen)
        bld.Stream.Append(varB := num 1u)
        bld.Stream.Append(AST.lmark lblEnd)
        markEnd bld 4u)
      (fun bld ->
        liftAt bld 0UL 4u {
          _when bld "Then" (varA == num 0u)
            (block {
              varB := num 1u })
        } |> ignore)

  [<TestMethod>]
  member _.``[LiftingDSL] _unless swaps the jump targets``() =
    assertSameIR
      (fun bld ->
        markStart bld 0UL 4u
        let lblThen = label bld "Err"
        let lblEnd = label bld "ErrEnd"
        let cond = varA == num 0u
        bld.Stream.Append(AST.cjmp cond
                                   (AST.jmpDest lblEnd)
                                   (AST.jmpDest lblThen))
        bld.Stream.Append(AST.lmark lblThen)
        bld.Stream.Append(varB := num 1u)
        bld.Stream.Append(AST.lmark lblEnd)
        markEnd bld 4u)
      (fun bld ->
        liftAt bld 0UL 4u {
          _unless bld "Err" (varA == num 0u)
            (block {
              varB := num 1u })
        } |> ignore)

  [<TestMethod>]
  member _.``[LiftingDSL] _if emits a diamond``() =
    assertSameIR
      (fun bld ->
        markStart bld 0UL 4u
        let lblThen = label bld "Eq"
        let lblElse = label bld "NotEq"
        let lblEnd = label bld "EqEnd"
        let cond = varA == num 0u
        bld.Stream.Append(AST.cjmp cond
                                   (AST.jmpDest lblThen)
                                   (AST.jmpDest lblElse))
        bld.Stream.Append(AST.lmark lblThen)
        bld.Stream.Append(varB := num 1u)
        bld.Stream.Append(AST.jmp (AST.jmpDest lblEnd))
        bld.Stream.Append(AST.lmark lblElse)
        bld.Stream.Append(varB := num 2u)
        bld.Stream.Append(AST.lmark lblEnd)
        markEnd bld 4u)
      (fun bld ->
        liftAt bld 0UL 4u {
          _if bld "Eq" (varA == num 0u)
            (block {
              varB := num 1u })
            (block {
              varB := num 2u })
        } |> ignore)

  [<TestMethod>]
  member _.``[LiftingDSL] _while emits a pre-test loop``() =
    assertSameIR
      (fun bld ->
        markStart bld 0UL 4u
        let lblCond = label bld "LoopCond"
        let lblBody = label bld "Loop"
        let lblEnd = label bld "LoopEnd"
        let cond = varA == num 0u
        bld.Stream.Append(AST.lmark lblCond)
        bld.Stream.Append(AST.cjmp cond
                                   (AST.jmpDest lblBody)
                                   (AST.jmpDest lblEnd))
        bld.Stream.Append(AST.lmark lblBody)
        bld.Stream.Append(varA := varA .+ num 1u)
        bld.Stream.Append(AST.jmp (AST.jmpDest lblCond))
        bld.Stream.Append(AST.lmark lblEnd)
        markEnd bld 4u)
      (fun bld ->
        liftAt bld 0UL 4u {
          _while bld "Loop" (varA == num 0u)
            (block {
              varA := varA .+ num 1u })
        } |> ignore)

  [<TestMethod>]
  member _.``[LiftingDSL] _repeat inverts the loop like rcl``() =
    assertSameIR
      (fun bld ->
        markStart bld 0UL 4u
        let lblBody = label bld "Rotate"
        let lblElse = label bld "NoRotate"
        let lblEnd = label bld "RotateEnd"
        let cond = varA != num 0u
        bld.Stream.Append(AST.cjmp cond
                                   (AST.jmpDest lblBody)
                                   (AST.jmpDest lblElse))
        bld.Stream.Append(AST.lmark lblBody)
        bld.Stream.Append(varA := varA .- num 1u)
        bld.Stream.Append(AST.cjmp cond
                                   (AST.jmpDest lblBody)
                                   (AST.jmpDest lblEnd))
        bld.Stream.Append(AST.lmark lblElse)
        bld.Stream.Append(varB := varB)
        bld.Stream.Append(AST.lmark lblEnd)
        markEnd bld 4u)
      (fun bld ->
        liftAt bld 0UL 4u {
          _repeat bld "Rotate" (varA != num 0u)
            (block {
              varA := varA .- num 1u })
            (block {
              varB := varB })
        } |> ignore)

  [<TestMethod>]
  member _.``[LiftingDSL] An emitting helper stays inside its branch``() =
    let helper (bld: ILowUIRBuilder) =
      bld.Stream.Append(varC := num 99u)
      bld.Stream.Append(varC := varC .+ num 1u)
    assertSameIR
      (fun bld ->
        markStart bld 0UL 4u
        let lblThen = label bld "Eq"
        let lblElse = label bld "NotEq"
        let lblEnd = label bld "EqEnd"
        let cond = varA == num 0u
        bld.Stream.Append(AST.cjmp cond
                                   (AST.jmpDest lblThen)
                                   (AST.jmpDest lblElse))
        bld.Stream.Append(AST.lmark lblThen)
        helper bld
        bld.Stream.Append(varB := num 1u)
        bld.Stream.Append(AST.jmp (AST.jmpDest lblEnd))
        bld.Stream.Append(AST.lmark lblElse)
        bld.Stream.Append(varB := num 2u)
        helper bld
        bld.Stream.Append(AST.lmark lblEnd)
        markEnd bld 4u)
      (fun bld ->
        liftAt bld 0UL 4u {
          _if bld "Eq" (varA == num 0u)
            (block {
              helper bld
              varB := num 1u })
            (block {
              varB := num 2u
              helper bld })
        } |> ignore)

  [<TestMethod>]
  member _.``[LiftingDSL] Nested _if keeps its shape``() =
    assertSameIR
      (fun bld ->
        markStart bld 0UL 4u
        let lblThen = label bld "Out"
        let lblElse = label bld "NotOut"
        let lblEnd = label bld "OutEnd"
        let cond = varA == num 0u
        bld.Stream.Append(AST.cjmp cond
                                   (AST.jmpDest lblThen)
                                   (AST.jmpDest lblElse))
        bld.Stream.Append(AST.lmark lblThen)
        let lblThen2 = label bld "In"
        let lblElse2 = label bld "NotIn"
        let lblEnd2 = label bld "InEnd"
        let cond2 = varB == num 0u
        bld.Stream.Append(AST.cjmp cond2
                                   (AST.jmpDest lblThen2)
                                   (AST.jmpDest lblElse2))
        bld.Stream.Append(AST.lmark lblThen2)
        bld.Stream.Append(varC := num 1u)
        bld.Stream.Append(AST.jmp (AST.jmpDest lblEnd2))
        bld.Stream.Append(AST.lmark lblElse2)
        bld.Stream.Append(varC := num 2u)
        bld.Stream.Append(AST.lmark lblEnd2)
        bld.Stream.Append(AST.jmp (AST.jmpDest lblEnd))
        bld.Stream.Append(AST.lmark lblElse)
        bld.Stream.Append(varC := num 3u)
        bld.Stream.Append(AST.lmark lblEnd)
        markEnd bld 4u)
      (fun bld ->
        liftAt bld 0UL 4u {
          _if bld "Out" (varA == num 0u)
            (block {
              _if bld "In" (varB == num 0u)
                (block {
                  varC := num 1u })
                (block {
                  varC := num 2u }) })
            (block {
              varC := num 3u })
        } |> ignore)

  [<TestMethod>]
  member _.``[LiftingDSL] A for loop appends every iteration``() =
    assertSameIR
      (fun bld ->
        markStart bld 0UL 4u
        for i in 0u .. 3u do bld.Stream.Append(varA := num i)
        markEnd bld 4u)
      (fun bld ->
        liftAt bld 0UL 4u {
          for i in 0u .. 3u do varA := num i
        } |> ignore)

  [<TestMethod>]
  member _.``[LiftingDSL] A conditional statement picks one branch``() =
    assertSameIR
      (fun bld ->
        markStart bld 0UL 4u
        bld.Stream.Append(varA := num 1u)
        bld.Stream.Append(varB := num 3u)
        markEnd bld 4u)
      (fun bld ->
        liftAt bld 0UL 4u {
          varA := num 1u
          if varA = varB then varB := num 2u else varB := num 3u
        } |> ignore)

  [<TestMethod>]
  member _.``[LiftingDSL] append adds no instruction marks``() =
    let bld = newBuilder ()
    bld.Stream.Append(varA := num 1u)
    bld.Stream.Append(varB := num 2u)
    let expected = bld.Stream.ToStmts()
    append bld {
      varA := num 1u
      varB := num 2u
    }
    CollectionAssert.AreEqual(expected, bld.Stream.ToStmts())

  [<TestMethod>]
  member _.``[LiftingDSL] An append helper stays inside its branch``() =
    let helper bld =
      append bld {
        varC := num 99u
        varC := varC .+ num 1u
      }
    assertSameIR
      (fun bld ->
        markStart bld 0UL 4u
        let lblThen = label bld "Eq"
        let lblEnd = label bld "EqEnd"
        bld.Stream.Append(AST.cjmp (varA == num 0u)
                                   (AST.jmpDest lblThen)
                                   (AST.jmpDest lblEnd))
        bld.Stream.Append(AST.lmark lblThen)
        helper bld
        bld.Stream.Append(varB := num 1u)
        bld.Stream.Append(AST.lmark lblEnd)
        markEnd bld 4u)
      (fun bld ->
        liftAt bld 0UL 4u {
          _when bld "Eq" (varA == num 0u)
            (block {
              helper bld
              varB := num 1u })
        } |> ignore)

  [<TestMethod>]
  member _.``[LiftingDSL] liftOpen leaves the instruction unclosed``() =
    let bld = newBuilder ()
    markStart bld 0UL 4u
    bld.Stream.Append(varA := num 1u)
    let expected = bld.Stream.ToStmts()
    LiftBuilder(bld, 0UL, 4u, false) {
      varA := num 1u
    } |> ignore
    CollectionAssert.AreEqual(expected, bld.Stream.ToStmts())
