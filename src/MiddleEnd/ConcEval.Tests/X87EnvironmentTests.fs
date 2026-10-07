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

namespace B2R2.MiddleEnd.ConcEval.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd.Executor
open B2R2.MiddleEnd.ConcEval

/// The x87 tag word that FNSTENV and FNSAVE store. The FPU keeps no more than
/// whether each register is empty, and works out the rest from the values as
/// it stores the word: 00 for a finite nonzero value, 01 for a zero, 10 for a
/// special one, and 11 for an empty register, two bits per physical register
/// (Intel SDM Vol. 1, 8.1.7). These run the code rather than read its IR, as
/// what matters is how the values are judged, in the analysis build's eighty
/// bits and the emulation build's doubles alike.
[<TestClass>]
type X87EnvironmentTests() =
  (* Where the environment goes: memory no section backs, which the executor
     takes writes to all the same. *)
  let [<Literal>] Env = 0x8000UL

  (* Runs `count` instructions that end in a store of the environment at RSP,
     from the state FNINIT leaves, and reads back the tag word, eight bytes
     into the 28-byte image. *)
  let storedTags count (hex: string) =
    let isa = ISA(Architecture.Intel, WordSize.Bit64)
    let hdl = BinHandle.LoadRawImage(ByteArray.ofHexString hex, isa, OS.Linux)
    let rf = hdl.RegisterFactory
    let reg (name: string) (v: uint64) =
      let rid = rf.GetRegisterID name
      rid, BitVector(v, rf.GetRegType rid)
    let exec = ConcExecutor hdl
    let regs = [| reg "RSP" Env; reg "FCW" 0x37FUL; reg "FTW" 0xFFFFUL |]
    let st =
      exec.CreateState { Memory = BinSectionBackedMemory; Registers = regs }
    exec.Run(0UL, st, ConcRunOptions.Default().WithMaxInstructions count)
    |> ignore
    match Memory.read (Env + 8UL) Endian.Little 16<rt> st.Memory with
    | Ok v -> v.ToUInt64()
    | Error _ -> failwith "no environment was stored"

  [<TestMethod>]
  member _.``FNSTENV tags every register of an empty stack empty``() =
    Assert.AreEqual<uint64>(0xFFFFUL, storedTags 1 "d93424" (* fnstenv [rsp] *))

  [<TestMethod>]
  member _.``FNSTENV tags a zero 01``() =
    (* fldz ; fnstenv [rsp] -- the zero sits in physical register 7 *)
    Assert.AreEqual<uint64>(0x7FFFUL, storedTags 2 "d9eed93424")

  [<TestMethod>]
  member _.``FNSTENV tags a finite nonzero value 00``() =
    (* fld1 ; fnstenv [rsp] *)
    Assert.AreEqual<uint64>(0x3FFFUL, storedTags 2 "d9e8d93424")

  [<TestMethod>]
  member _.``FNSTENV tags each register where it physically sits``() =
    (* fldz ; fld1 ; fnstenv [rsp] -- the zero in register 7, the one in 6 *)
    Assert.AreEqual<uint64>(0x4FFFUL, storedTags 3 "d9eed9e8d93424")

  [<TestMethod>]
  member _.``FNSTENV tags an infinity 10``() =
    (* fld1 ; fldz ; fdivp st(1), st(0) ; fnstenv [rsp] -- one over zero is an
       infinity, left in register 7 once the zero is popped *)
    Assert.AreEqual<uint64>(0xBFFFUL, storedTags 4 "d9e8d9eedef9d93424")

  [<TestMethod>]
  member _.``FNSAVE stores the tags FNSTENV would``() =
    (* fldz ; fnsave [rsp] -- the tags go out before FNSAVE empties the stack *)
    Assert.AreEqual<uint64>(0x7FFFUL, storedTags 2 "d9eedd3424")
