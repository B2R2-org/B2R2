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

namespace B2R2.MiddleEnd.Executor.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.Executor

[<TestClass>]
type LiftCacheTests() =
  (* nop; nop; nop *)
  let nops = [| 0x90uy; 0x90uy; 0x90uy |]

  let newCache (bytes: byte[]) =
    let isa = ISA(Architecture.Intel, WordSize.Bit64)
    BinHandle.LoadRawImage(bytes, isa, OS.Linux) |> LiftCache

  [<TestMethod>]
  member _.``A lifted instruction carries the statements of its address``() =
    let cache = newCache nops
    match cache.TryLift 0x1UL with
    | Ok lifted ->
      Assert.AreEqual<uint32>(1u, lifted.Instruction.Length)
      Assert.AreEqual<bool>(true, Array.length lifted.Stmts > 0)
    | Error e ->
      Assert.Fail $"Lifting the instruction failed: {e}."

  [<TestMethod>]
  member _.``An address outside the binary fails to parse``() =
    let cache = newCache nops
    match cache.TryParse 0x1000UL with
    | Ok ins -> Assert.Fail $"An invalid address parsed as {ins}."
    | Error e -> Assert.AreEqual<ErrorCase>(ErrorCase.ParsingFailure, e)

  [<TestMethod>]
  member _.``An address is parsed and lifted only once``() =
    let cache = newCache nops
    match cache.TryLift 0x0UL, cache.TryLift 0x0UL with
    | Ok first, Ok second ->
      Assert.AreEqual<bool>(true,
                            obj.ReferenceEquals(first.Instruction,
                                                second.Instruction))
      Assert.AreEqual<bool>(true,
                            obj.ReferenceEquals(first.Stmts, second.Stmts))
    | _ ->
      Assert.Fail "Lifting the instruction failed."

  [<TestMethod>]
  member _.``A failure to parse is remembered as well``() =
    let cache = newCache nops
    let first = cache.TryParse 0x1000UL
    Assert.AreEqual<Result<IInstruction, ErrorCase>>(first,
                                                     cache.TryParse 0x1000UL)

  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``Warming up a range of unparsable addresses terminates``() =
    let cache = newCache nops
    cache.WarmUp [ 0x0UL, 0x100UL ]
    match cache.TryLift 0x2UL with
    | Ok lifted -> Assert.AreEqual<uint32>(1u, lifted.Instruction.Length)
    | Error e -> Assert.Fail $"Lifting the instruction failed: {e}."

  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``Warming up an empty range terminates``() =
    let cache = newCache nops
    cache.WarmUp [ 0x2UL, 0x2UL ]
    match cache.TryLift 0x2UL with
    | Ok lifted -> Assert.AreEqual<uint32>(1u, lifted.Instruction.Length)
    | Error e -> Assert.Fail $"Lifting the instruction failed: {e}."

