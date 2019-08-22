namespace BinIR.Tests

open System
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2.BinIR.LowUIR

[<TestClass>]
type TestClass () =

    [<TestMethod>]
    member __.``Start Or End of IR test``() =
      let P = LowUIRParser ()
      let pvalue = P.Run "=== ISMark (41181D)"
      Assert.AreEqual (ISMark(4266013UL,0u), pvalue)
      Assert.IsTrue(true)

    [<TestMethod>]
    member __.``Parse unsigned int64``() =
      let P = LowUIRParser ()
      let pvalue = P.Run "6832748"
      Assert.AreEqual (6832748, pvalue)
      Assert.IsTrue(true)