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

/// The x87 environment that FNSTENV and FNSAVE store and FLDENV and FRSTOR
/// read back: the control, status, and tag words, and the pointers to the last
/// instruction and its operand. These run the code rather than read its IR, as
/// what matters is what lands in the image, in the analysis build's eighty-bit
/// values and the emulation build's doubles alike.
[<TestClass>]
type X87EnvironmentTests() =
  (* Where the environment goes: memory no section backs, which the executor
     takes writes to all the same. *)
  let [<Literal>] Env = 0x8000UL

  (* Pointers as a 64-bit process has them: the instruction high in the address
     space, the selectors Linux gives its code and data, and the opcode of
     FLD1. *)
  let pointers =
    [ "FIP", 0x5555_5555_4002UL
      "FCS", 0x33UL
      "FOP", 0x1e8UL
      "FDP", 0x7fff_1234_5678UL
      "FDS", 0x2bUL ]

  (* Runs `count` instructions of code loaded at `base`, from the state FNINIT
     leaves, RSP pointing at Env, with `regs` set on top and each (offset,
     value, type) of `image` written at Env first. *)
  let runAt (``base``: Addr) count (hex: string) regs image =
    let isa = ISA(Architecture.Intel, WordSize.Bit64)
    let bytes = ByteArray.ofHexString hex
    let hdl = BinHandle.LoadRawImage(bytes, isa, ``base``, OS.Linux)
    let rf = hdl.RegisterFactory
    let reg (name: string, v: uint64) =
      let rid = rf.GetRegisterID name
      rid, BitVector(v, rf.GetRegType rid)
    let exec = ConcExecutor hdl
    let regs =
      [ "RSP", Env; "FCW", 0x37FUL; "FTW", 0xFFFFUL ] @ regs
      |> List.map reg
      |> Array.ofList
    let st =
      exec.CreateState { Memory = BinSectionBackedMemory; Registers = regs }
    for off, (v: uint64), typ in image do
      Memory.write (Env + off) (BitVector(v, typ)) Endian.Little st.Memory
    exec.Run(``base``, st, ConcRunOptions.Default().WithMaxInstructions count)
    |> ignore
    hdl, st

  let run count hex regs image = runAt 0UL count hex regs image

  (* The field of type `typ` at `off` bytes into what was stored at Env. *)
  let field (st: ConcState) off typ =
    match Memory.read (Env + off) Endian.Little typ st.Memory with
    | Ok v -> v.ToUInt64()
    | Error _ -> failwith "no environment was stored"

  let regOf (hdl: BinHandle) (st: ConcState) (name: string) =
    match st.TryGetReg(hdl.RegisterFactory.GetRegisterID name) with
    | Def v -> v.ToUInt64()
    | Undef -> failwith $"{name} is undefined"

  (* The tag word, eight bytes into the 28-byte image that the last of `count`
     instructions stores at RSP. *)
  let storedTags count hex =
    let _, st = run count hex [] []
    field st 8UL 16<rt>

  (* Code where a 64-bit process has it, high in the address space. *)
  let [<Literal>] Code = 0x5555_5555_4000UL

  (* The pointers in the 28-byte image after `count` instructions at Code: the
     instruction offset, then the word holding the code selector. *)
  let lastInstr count hex =
    let _, st = runAt Code count hex [] []
    field st 12UL 32<rt>, field st 16UL 32<rt>

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

  (* The 28-byte image gives each pointer 32 bits and each selector a word,
     with the opcode in the 11 bits above the code selector (Intel SDM Vol. 1,
     Figure 8-9), so a 64-bit pointer has no room to spill into what follows. *)
  [<TestMethod>]
  member _.``FNSTENV keeps each pointer within its own field``() =
    let _, st = run 1 "d93424" (* fnstenv [rsp] *) pointers []
    let actual =
      [| field st 12UL 32<rt>
         field st 16UL 16<rt>
         field st 18UL 16<rt>
         field st 20UL 32<rt>
         field st 24UL 16<rt> |]
    let expected = [| 0x55554002UL; 0x33UL; 0x1e8UL; 0x12345678UL; 0x2bUL |]
    CollectionAssert.AreEqual(expected, actual)

  (* The FPU fills the upper halves the image leaves reserved with ones. *)
  [<TestMethod>]
  member _.``FNSTENV fills the reserved halves with ones``() =
    let _, st = run 1 "d93424" (* fnstenv [rsp] *) [] []
    let reserved = [ 2UL; 6UL; 10UL; 26UL ]
    let actual = [| for off in reserved -> field st off 16<rt> |]
    CollectionAssert.AreEqual(Array.create 4 0xFFFFUL, actual)

  (* FLDENV reads each field back, and a pointer gets the 32 bits the image
     has room for, whatever its upper half held before. *)
  [<TestMethod>]
  member _.``FLDENV reads each pointer from its own field``() =
    let image =
      [ 0UL, 0x37FUL, 16<rt>
        2UL, 0xFFFFUL, 16<rt>
        4UL, 0UL, 16<rt>
        6UL, 0xFFFFUL, 16<rt>
        8UL, 0xFFFFUL, 16<rt>
        10UL, 0xFFFFUL, 16<rt>
        12UL, 0x55554002UL, 32<rt>
        16UL, 0x33UL, 16<rt>
        18UL, 0x1e8UL, 16<rt>
        20UL, 0x12345678UL, 32<rt>
        24UL, 0x2bUL, 16<rt>
        26UL, 0xFFFFUL, 16<rt> ]
    let stale = [ "FIP", 0xdead_0000_0000_0000UL ]
    let hdl, st = run 1 "d92424" (* fldenv [rsp] *) stale image
    let regs = [ "FIP"; "FCS"; "FOP"; "FDP"; "FDS" ]
    let actual = [| for r in regs -> regOf hdl st r |]
    let expected = [| 0x55554002UL; 0x33UL; 0x1e8UL; 0x12345678UL; 0x2bUL |]
    CollectionAssert.AreEqual(expected, actual)

  (* FNSTENV stores the control word as it was and then masks every
     exception. *)
  [<TestMethod>]
  member _.``FNSTENV masks every exception once it has stored``() =
    let unmasked = [ "FCW", 0x37BUL ]
    let hdl, st = run 1 "d93424" (* fnstenv [rsp] *) unmasked []
    let actual = [| field st 0UL 16<rt>; regOf hdl st "FCW" |]
    CollectionAssert.AreEqual([| 0x37BUL; 0x37FUL |], actual)

  (* A ninth push finds the register it takes over still holding a value, and
     the FPU, the exception masked, pushes the real indefinite instead. *)
  [<TestMethod>]
  member _.``A push onto a full stack leaves the indefinite``() =
    (* fld1 nine times ; fstp qword [rsp+64] *)
    let hex = String.replicate 9 "d9e8" + "dd5c2440"
    let _, st = run 10 hex [] []
    Assert.AreEqual<uint64>(0xfff8000000000000UL, field st 64UL 64<rt>)

  (* FNINIT gives the FPU its initial state, which has no last instruction or
     operand: both pointers, their selectors, and the opcode go to zero (Intel
     SDM Vol. 2A, FINIT/FNINIT). *)
  [<TestMethod>]
  member _.``FNINIT clears the pointers``() =
    let hdl, st = run 1 "dbe3" (* fninit *) pointers []
    let actual = [| for r, _ in pointers -> regOf hdl st r |]
    CollectionAssert.AreEqual(Array.create 5 0UL, actual)

  (* Once the state is out, FNSAVE initializes the FPU as FNINIT does. *)
  [<TestMethod>]
  member _.``FNSAVE clears the pointers it has saved``() =
    let hdl, st = run 1 "dd3424" (* fnsave [rsp] *) pointers []
    let actual = [| for r, _ in pointers -> regOf hdl st r |]
    CollectionAssert.AreEqual(Array.create 5 0UL, actual)

  (* FNSTENV reports where the last x87 instruction was, in the 32 bits the
     image has for it, and leaves the selector and opcode after it as they
     were: the current processors update neither but on an exception. *)
  [<TestMethod>]
  member _.``FNSTENV reports the last x87 instruction``() =
    (* fld1 ; fnstenv [rsp] *)
    let actual = lastInstr 2 "d9e8d93424"
    Assert.AreEqual<uint64 * uint64>((0x55554000UL, 0UL), actual)

  (* Control instructions do not count, FNSTENV among them; FNOP does. *)
  [<TestMethod>]
  member _.``FNSTENV skips the control instructions``() =
    (* fld1 ; fwait ; fnstcw [rsp+16] ; fnstenv [rsp] *)
    let actual = lastInstr 4 "d9e89bd97c2410d93424"
    Assert.AreEqual<uint64 * uint64>((0x55554000UL, 0UL), actual)

  [<TestMethod>]
  member _.``FNSTENV counts FNOP as an x87 instruction``() =
    (* fld1 ; fnop ; fnstenv [rsp] *)
    let actual = lastInstr 3 "d9e8d9d0d93424"
    Assert.AreEqual<uint64 * uint64>((0x55554002UL, 0UL), actual)
