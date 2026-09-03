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

open System
open System.Collections.Generic
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd.Executor

[<TestClass>]
type StateAccessTests() =
  /// Stands in for a value domain whose values are always concrete words, so
  /// that a test reads the shared machinery and nothing else.
  let fakeDomain () =
    let regs = Dictionary<RegisterID, uint64>()
    let mem = Dictionary<Addr, uint64>()
    { new IStateDomain<Dictionary<RegisterID, uint64>, uint64, string> with

        member _.State = regs

        member _.WordValue value = value

        member _.Zero _ = 0UL

        member _.TryGetRegisterValue rid =
          match regs.TryGetValue rid with
          | true, value -> Ok value
          | false, _ -> Error $"register {int rid} holds no value"

        member _.SetRegisterValue(rid, value) = regs[rid] <- value

        member _.TryReadValue(addr, _) =
          match mem.TryGetValue addr with
          | true, value -> Ok value
          | false, _ -> Error $"no value at {addr:x}"

        member _.WriteValue(addr, value) = mem[addr] <- value

        member _.TryGetAddr value = Ok value

        member _.RegisterUnavailable role = $"{role} is unavailable"

        member _.FormatError error = error }

  let newAccess arch (ws: WordSize) =
    let hdl = BinHandle.LoadRawImage([| 0x90uy |], ISA(arch, ws), OS.Linux)
    StateAccess.create hdl (fakeDomain ())

  let newIntel64 () = newAccess Architecture.Intel WordSize.Bit64

  [<TestMethod>]
  member _.``The default stack top depends on the word size``() =
    Assert.AreEqual<Addr>(0x7fffffffe000UL, (newIntel64 ()).DefaultStackTop)
    let access = newAccess Architecture.Intel WordSize.Bit32
    Assert.AreEqual<Addr>(0xbfffe000UL, access.DefaultStackTop)
    Assert.AreEqual<int>(4, access.WordBytes)

  [<TestMethod>]
  member _.``Initializing the stack puts the pointer at the stack top``() =
    let access = newIntel64 ()
    access.InitializeDefaultStack()
    Assert.AreEqual<Addr>(access.DefaultStackTop, access.StackPointer)

  [<TestMethod>]
  member _.``A push moves the stack pointer down by one word``() =
    let access = newIntel64 ()
    access.InitializeStack 0x2000UL
    let addr = access.PushToStack 0x1234UL
    Assert.AreEqual<Addr>(0x2000UL - uint64 access.WordBytes, addr)
    Assert.AreEqual<Addr>(addr, access.StackPointer)

  [<TestMethod>]
  member _.``A pop hands back what a push left and unwinds the stack``() =
    let access = newIntel64 ()
    access.InitializeStack 0x2000UL
    access.PushToStack 0x1234UL |> ignore
    Assert.AreEqual<uint64>(0x1234UL, access.PopFromStack())
    Assert.AreEqual<Addr>(0x2000UL, access.StackPointer)

  [<TestMethod>]
  member _.``Allocating a stack buffer moves the pointer down by its size``() =
    let access = newIntel64 ()
    access.InitializeStack 0x2000UL
    Assert.AreEqual<Addr>(0x1fc0UL, access.AllocateStackBuffer 0x40)
    Assert.AreEqual<Addr>(0x1fc0UL, access.StackPointer)

  [<TestMethod>]
  member _.``The frame pointer initializes to the stack pointer``() =
    let access = newIntel64 ()
    access.InitializeStack 0x2000UL
    access.InitializeFramePointer()
    Assert.AreEqual<uint64>(0x2000UL, access.GetRegister "RBP")

  [<TestMethod>]
  member _.``A register reads back by name and by ID alike``() =
    let access = newIntel64 ()
    access.SetRegister("RAX", 0x11UL)
    Assert.AreEqual<uint64>(0x11UL, access.GetRegister "rax")
    access.ZeroRegisters [| "RAX" |]
    Assert.AreEqual<uint64>(0UL, access.GetRegister "RAX")

  [<TestMethod>]
  member _.``An argument goes to the register the ABI names``() =
    let access = newIntel64 ()
    access.SetArgument(0, 0x22UL)
    Assert.AreEqual<uint64>(0x22UL, access.GetRegister "RDI")

  [<TestMethod>]
  member _.``An argument the ABI passes on the stack is refused``() =
    let access = newAccess Architecture.Intel WordSize.Bit32
    Assert.ThrowsExactly<InvalidOperationException>(fun () ->
      access.SetArgument(0, 0x22UL))
    |> ignore

  [<TestMethod>]
  member _.``A failure of the value domain raises with its own message``() =
    let access = newIntel64 ()
    access.InitializeStack 0x2000UL
    let error =
      Assert.ThrowsExactly<InvalidOperationException>(fun () ->
        access.PopFromStack() |> ignore)
    Assert.AreEqual<bool>(true, error.Message.StartsWith "Cannot pop")

  [<TestMethod>]
  member _.``A push and a pop round-trip through the interface``() =
    let access = newIntel64 ()
    access.InitializeDefaultStack()
    match access.TryPushToStack(access.WordValue 0x1234UL) with
    | Ok _ ->
      let expected = Ok 0x1234UL
      Assert.AreEqual<Result<uint64, string>>(expected,
                                              access.TryPopFromStack())
    | Error e ->
      Assert.Fail $"Failed to push to the stack: {e}"
