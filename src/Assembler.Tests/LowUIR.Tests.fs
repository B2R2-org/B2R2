namespace B2R2.Assembler.Tests


open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd

[<TestClass>]
type LowUIRTests () =
  let regfactory = Intel.RegFactory WordSize.Bit64 :> RegisterFactory
  let p = LowUIRParser (ISA.DefaultISA, regfactory)
  let size1Num = BitVector.T
  let size64Num = BitVector.cast size1Num 64<rt>

  [<TestMethod>]
  member __.``[IntelAssemblerLowUIR] Test Register Assignment ``() =
    let result = p.Run "RAX := 0x1:I64" |> Option.get
    let regID = Intel.Register.toRegID (Intel.Register.RAX)
    let answer =
      Put (Var(64<rt>, regID, "RAX", EmptyRegisterSet ()),Num size64Num)
    Assert.AreEqual (answer, result)

  [<TestMethod>]
  member __.``[IntelAssemblerLowUIR] Test IEMark ``() =
    let result = p.Run "=== IEMark (pc := 1)" |> Option.get
    let answer = IEMark 1UL
    Assert.AreEqual (answer, result)

  [<TestMethod>]
  member __.``[IntelAssemblerLowUIR] Test Temporary Registers``() =
    let result = p.Run "T_2:I1 := 1" |> Option.get
    let answer = Put (TempVar(1<rt>,2), Num size1Num)
    Assert.AreEqual (answer, result)

  [<TestMethod>]
  member __.``[IntelAssemblerLowUIR] Test Operation in Expression``() =
    let result = p.Run "RAX := (0x1:I64 - 0x1:I64)" |> Option.get
    let regID = Intel.Register.toRegID (Intel.Register.RAX)
    let answer =
      Put (Var (64<rt>, regID, "RAX", RegisterSet.empty),
           Num (BitVector.cast BitVector.F 64<rt>))
    Assert.AreEqual (answer, result)

