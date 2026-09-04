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
open B2R2.MiddleEnd.Executor

[<TestClass>]
type CallPolicyTests() =
  [<TestMethod>]
  member _.``A policy that carries no registry yields an empty one``() =
    let registry = CallPolicy.registry CallPolicy.FollowDirectInternalCalls
    Assert.AreEqual<string option>(None, registry.TryFind 0x1000UL)

  [<TestMethod>]
  member _.``Registering a hook switches the policy to hook dispatch``() =
    match CallPolicy.register 0x1000UL "hook" CallPolicy.StopAtCalls with
    | CallPolicy.UseCallHooks hooks ->
      Assert.AreEqual<string option>(Some "hook", hooks.TryFind 0x1000UL)
    | policy ->
      Assert.Fail $"Unexpected policy: {policy}"

  [<TestMethod>]
  member _.``Registering a hook keeps the ones already registered``() =
    let policy =
      CallPolicy.StopAtCalls
      |> CallPolicy.register 0x1000UL "first"
      |> CallPolicy.register 0x2000UL "second"
    match policy with
    | CallPolicy.UseCallHooks hooks ->
      Assert.AreEqual<string option>(Some "first", hooks.TryFind 0x1000UL)
      Assert.AreEqual<string option>(Some "second", hooks.TryFind 0x2000UL)
    | policy ->
      Assert.Fail $"Unexpected policy: {policy}"

  [<TestMethod>]
  member _.``Registering hooks in bulk switches the policy as well``() =
    let policy =
      CallPolicy.FollowDirectInternalCalls
      |> CallPolicy.registerMany [ 0x1000UL, "first"; 0x2000UL, "second" ]
    match policy with
    | CallPolicy.UseCallHooks hooks ->
      Assert.AreEqual<string option>(Some "first", hooks.TryFind 0x1000UL)
      Assert.AreEqual<string option>(Some "second", hooks.TryFind 0x2000UL)
    | policy ->
      Assert.Fail $"Unexpected policy: {policy}"
