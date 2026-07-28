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

open System.Threading
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open Microsoft.VisualStudio.TestTools.UnitTesting

[<TestClass>]
type InstructionCollectionTests() =
  static let isa = ISA(Architecture.Intel, WordSize.Bit64)

  /// An image of 0x2000 one-byte "nop"s, large enough that the sweep does not
  /// necessarily finish before the constructor returns.
  static let hdl = BinHandle(Array.create 0x2000 0x90uy, isa)

  static let newCollection () =
    InstructionCollection(LinearSweepInstructionCollector hdl)

  /// A collector whose sweep fails, to check that the failure is observable.
  static let failing =
    { new IInstructionCollectable with
        member _.Collect(_, _) = failwith "sweep blew up"
        member _.ParseInstructionCandidate _ =
          Error ErrorCase.ParsingFailure }

  [<TestMethod>]
  member _.``[InstructionCollection] count is final after completion test``() =
    let instrs = newCollection ()
    instrs.Completion.Wait()
    Assert.AreEqual<bool>(true, instrs.Completion.IsCompleted)
    Assert.AreEqual<int>(0x2000, instrs.Count)

  (* A lookup must not depend on how far the sweep has progressed: a miss is
     parsed on demand. This is checked without waiting for Completion. *)
  [<TestMethod>]
  member _.``[InstructionCollection] lookup before completion test``() =
    let instrs = newCollection ()
    Assert.AreEqual<bool>(true, Result.isOk (instrs.TryFind 0x1fffUL))
    Assert.AreEqual<string>("nop", (instrs.Find 0x1ffeUL).Disasm())

  (* Find used to read the cache directly, so it threw KeyNotFoundException for
     an address the sweep had not reached yet. It must now fall back like
     TryFind, differing only in how it reports failure. *)
  [<TestMethod>]
  member _.``[InstructionCollection] find falls back to parsing test``() =
    let instrs = newCollection ()
    instrs.Cancel()
    instrs.Completion.Wait()
    Assert.AreEqual<string>("nop", (instrs.Find 0x1fffUL).Disasm())

  [<TestMethod>]
  member _.``[InstructionCollection] find at a bad address raises test``() =
    let instrs = newCollection ()
    instrs.Completion.Wait()
    Assert.ThrowsExactly<ParsingFailureException>(fun () ->
      instrs.Find 0x9999UL |> ignore) |> ignore
    Assert.AreEqual(Error ErrorCase.ParsingFailure, instrs.TryFind 0x9999UL)

  (* Cancelling stops the sweep instead of faulting it, so Completion still
     finishes successfully and the collection stays usable. *)
  [<TestMethod>]
  member _.``[InstructionCollection] cancel stops the sweep test``() =
    let instrs = newCollection ()
    instrs.Cancel()
    instrs.Completion.Wait()
    Assert.AreEqual<bool>(false, instrs.Completion.IsFaulted)
    Assert.AreEqual<bool>(true, instrs.Count <= 0x2000)
    Assert.AreEqual<bool>(true, Result.isOk (instrs.TryFind 0x10UL))

  (* The failure used to vanish into an ignored task, leaving an empty
     collection indistinguishable from a binary with no code. *)
  [<TestMethod>]
  member _.``[InstructionCollection] sweep failure is observable test``() =
    let instrs = InstructionCollection failing
    let exn =
      Assert.ThrowsExactly<System.AggregateException>(fun () ->
        instrs.Completion.Wait())
    Assert.AreEqual<string>("sweep blew up", exn.InnerException.Message)
