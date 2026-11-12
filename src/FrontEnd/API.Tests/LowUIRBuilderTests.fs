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
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter

[<TestClass>]
type LowUIRBuilderTests() =
  let newBuilder arch =
    let hdl = BinHandle.LoadEmpty(ISA(arch: Architecture))
    ArchSupport.createBuilder hdl.ISA hdl.RegisterFactory

  (* Leave the next instruction looking like a delay slot or an instruction
     whose nullification guard can be omitted, as a previous region might. *)
  let leavePendingState (builder: ILowUIRBuilder) =
    match builder with
    | :? MIPS.LowUIRBuilder as bld ->
      bld.InDelaySlot <- true
    | :? SPARC.LowUIRBuilder as bld ->
      bld.Arm InterJmpKind.Base
      bld.Armed <- false
      bld.DelaySlotAddr <- ValueSome 0UL
      bld.AnnulCond <- ValueSome AST.b1
    | :? SH4.LowUIRBuilder as bld ->
      bld.Arm InterJmpKind.Base
      bld.Armed <- false
      bld.DelaySlotAddr <- ValueSome 0UL
    | :? PARISC.LowUIRBuilder as bld ->
      bld.ArmGateway PARISC.Gateway.SystemCall
      bld.Promote()
      bld.ArmGateway PARISC.Gateway.SetThreadPointer
      bld.DelaySlotAddr <- ValueSome 0UL
      bld.PrevEnd <- ValueSome 0UL
      bld.PrevMayNullify <- false
    | _ ->
      ()

  [<TestMethod>]
  [<DataRow(Architecture.Intel)>]
  [<DataRow(Architecture.ARMv7)>]
  [<DataRow(Architecture.MIPS)>]
  [<DataRow(Architecture.SPARC)>]
  [<DataRow(Architecture.SH4)>]
  [<DataRow(Architecture.PARISC)>]
  member _.``New Region Retains Buffer And Identifier Counters``(arch) =
    let builder = newBuilder arch
    let stream = builder.Stream
    let temp = stream.NewTempVar 32<rt>
    let label = stream.NewLabel "Test"
    stream.Append(AST.ismark 4u)
    let capacity = stream.Capacity
    builder.BeginRegion()
    Assert.AreSame(stream, builder.Stream)
    Assert.AreEqual<int>(0, stream.Count)
    Assert.AreEqual<int>(capacity, stream.Capacity)
    Assert.AreNotEqual<Expr>(temp, stream.NewTempVar 32<rt>)
    Assert.AreEqual<int>(label.Id + 1, (stream.NewLabel "Test").Id)

  [<TestMethod>]
  [<DataRow(Architecture.MIPS, "00000000")>]
  [<DataRow(Architecture.SPARC, "01000000")>]
  [<DataRow(Architecture.SH4, "0900")>]
  [<DataRow(Architecture.PARISC, "08000240")>]
  member _.``New Region Lifts Without Previous Branch State``(arch, hex) =
    let isa = ISA(arch: Architecture)
    let hdl = BinHandle.LoadRawImage(ByteArray.ofHexString hex, isa)
    let ins = hdl.NewLiftingUnit().ParseInstruction(addr = 0UL)
    let builder = newBuilder arch
    leavePendingState builder
    builder.Stream.Append(AST.ismark 4u)
    builder.BeginRegion()
    let actual = ins.Translate builder
    let expected = ins.Translate(newBuilder arch)
    CollectionAssert.AreEqual(expected, actual)
