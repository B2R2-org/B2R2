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
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.AVR
open type Opcode
open type Register

/// Shortcut for creating operands.
[<AutoOpen>]
module private AVRShortcut =
  type O =
    static member Reg (r) =
      OprReg r

    static member Imm (v) =
      OprImm v

    static member Addr (v) =
      OprAddr v

    static member MemDisp (r, v) =
      OprMemory (DispMode (r, v))

    static member MemPostIdx (r) =
      OprMemory (PostIdxMode r)

type AVRParserTests () =
  let test (bytes: byte[]) (opcode, oprs: Operands) =
    let reader = BinReader.Init Endian.Little
    let span = System.ReadOnlySpan bytes
    let ins = ParsingMain.parse span reader 0UL
    Assert.AreEqual<Opcode> (opcode, ins.Info.Opcode)
    Assert.AreEqual<Operands> (oprs, ins.Info.Operands)

  let operandsFromArray oprList =
    let oprs = Array.ofList oprList
    match oprs.Length with
    | 0 -> NoOperand
    | 1 -> OneOperand oprs[0]
    | 2 -> TwoOperands (oprs[0], oprs[1])
    | _ -> Terminator.impossible ()

  let ( ** ) opcode oprList = (opcode, operandsFromArray oprList)

  let ( ++ ) byteString pair = (ByteArray.ofHexString byteString, pair)

  [<TestMethod>]
  member __.``[AVR] No Operand Insturctions Parse Test (1)`` () =
    "0895"
    ++ RET ** [ ] ||> test

  [<TestMethod>]
  member __.``[AVR] One Operand Insturctions Parse Test (1)`` () =
    "81f1"
    ++ BREQ ** [ O.Addr 96 ] ||> test

  [<TestMethod>]
  member __.``[AVR] One Operand Insturctions Parse Test (2)`` () =
    "b4f4"
    ++ BRGE ** [ O.Addr 44 ] ||> test

  [<TestMethod>]
  member __.``[AVR] Two Register Operands Insturctions Parse Test (1)`` () =
    "c90e"
    ++ ADD ** [ O.Reg R12; O.Reg R25 ] ||> test

  [<TestMethod>]
  member __.``[AVR] Two Register Operands Insturctions Parse Test (2)`` () =
    "e12c"
    ++ MOV ** [ O.Reg R14; O.Reg R1 ] ||> test

  [<TestMethod>]
  member __.``[AVR] Memory Operands Insturctions Parse Test (1)`` () =
    "1d92"
    ++ ST ** [ O.MemPostIdx X; OprReg R1 ] ||> test

  [<TestMethod>]
  member __.``[AVR] Memory Operands Insturctions Parse Test (2)`` () =
    "6980"
    ++ LDD ** [ O.Reg R6; O.MemDisp (Y, 1) ] ||> test

  [<TestMethod>]
  member __.``[AVR] Immediate Operand Insturction Parse Test (1)`` () =
    "8fef"
    ++ LDI ** [ O.Reg R24; O.Imm 0xff ] ||> test
