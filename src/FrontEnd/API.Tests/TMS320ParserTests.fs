(*
  B2R2 - the Next-Generation Reversing Platform

  Copyright (c) SoftSec Lab. @ KAIST, since 2016

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*)

namespace B2R2.FrontEnd.API.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.TMS320C6000
open type Opcode
open type Register

/// Shortcut for creating operands.
[<AutoOpen>]
module private TMS320Shortcut =
  type O =
    static member Reg (r) =
      OpReg r

    static member Imm (v) =
      Immediate v

    static member RegPair (r1, r2) =
      RegisterPair (r1, r2)

    static member Mem (r, modType, offset) =
      OprMem (r, modType, offset)

type TMS320ParserTests () =
  let test (funit: FunctionalUnit) (bytes: byte[]) (opcode, oprs: Operands) =
    let reader = BinReader.Init Endian.Little
    let span = System.ReadOnlySpan bytes
    let mutable inpar = false
    let ins = ParsingMain.parse span reader &inpar 0UL
    Assert.AreEqual<Opcode> (opcode, ins.Info.Opcode)
    Assert.AreEqual<FunctionalUnit> (funit, ins.Info.FunctionalUnit)
    Assert.AreEqual<Operands> (oprs, ins.Info.Operands)

  let operandsFromArray oprList =
    let oprs = Array.ofList oprList
    match oprs.Length with
    | 0 -> NoOperand
    | 1 -> OneOperand oprs[0]
    | 2 -> TwoOperands (oprs[0], oprs[1])
    | 3 -> ThreeOperands (oprs[0], oprs[1], oprs[2])
    | 4 -> FourOperands (oprs[0], oprs[1], oprs[2], oprs[3])
    | _ -> Terminator.impossible ()

  let ( ** ) opcode oprList = (opcode, operandsFromArray oprList)

  let ( ++ ) byteString pair = (ByteArray.ofHexString byteString, pair)

  [<TestMethod>]
  member __.``[TMS320] .D Unit Insturctions Parse Test (1)`` () =
    "B03a3003"
    ++ ADD ** [ O.Reg A1; O.Reg B12; O.Reg A6 ]
    ||> test D1XUnit

  [<TestMethod>]
  member __.``[TMS320] .D Unit Insturctions Parse Test (2)`` () =
    "24809403"
    ++ LDB ** [ O.Mem (A5, NegativeOffset, UCst5 4UL); O.Reg A7 ]
    ||> test D1Unit

  [<TestMethod>]
  member __.``[TMS320] .L Unit Insturctions Parse Test (1)`` () =
    "58830001"
    ++ ABS2 ** [ O.Reg A0; O.Reg A2 ]
    ||> test L1Unit

  [<TestMethod>]
  member __.``[TMS320] .L Unit Insturctions Parse Test (2)`` () =
    "38130802"
    ++ SUBDP ** [ O.RegPair (A1, A0); O.RegPair (B3, B2); O.RegPair (A5, A4) ]
    ||> test L1XUnit

  [<TestMethod>]
  member __.``[TMS320] .M Unit Insturctions Parse Test (1)`` () =
    "F0040401"
    ++ AVG2 ** [ O.Reg A0; O.Reg A1; O.Reg A2 ]
    ||> test M1Unit

  [<TestMethod>]
  member __.``[TMS320] .M Unit Insturctions Parse Test (2)`` () =
    "F0531414"
    ++ MPY2IR ** [ O.Reg A2; O.Reg B5; O.RegPair (A9, A8) ]
    ||> test M1XUnit

  [<TestMethod>]
  member __.``[TMS320] .S Unit Insturctions Parse Test (1)`` () =
    "200B0401"
    ++ ABSDP ** [ O.RegPair (A1, A0); O.RegPair (A3, A2) ]
    ||> test S1Unit

  [<TestMethod>]
  member __.``[TMS320] .S Unit Insturctions Parse Test (2)`` () =
    "20091000"
    ++ SHRU ** [ O.RegPair (A5, A4); O.Imm 0x0UL; O.RegPair (A1, A0) ]
    ||> test S1Unit

  [<TestMethod>]
  member __.``[TMS320] No Unit Insturctions Parse Test (1)`` () =
    "00E00100"
    ++ IDLE ** [ ]
    ||> test NoUnit

  [<TestMethod>]
  member __.``[TMS320] No Unit Insturctions Parse Test (2)`` () =
    "00800000"
    ++ NOP ** [ O.Imm 5UL ]
    ||> test NoUnit
