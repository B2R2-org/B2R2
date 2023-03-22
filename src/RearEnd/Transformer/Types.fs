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

namespace B2R2.RearEnd.Transformer

open B2R2

/// Byte array tagged with additional information.
type ByteArray = {
  Address: Addr
  ISA: ISA option
  Bytes: byte[]
}
with
  override __.ToString () =
    let s = Utils.makeByteArraySummary __.Bytes
    match __.ISA with
    | Some isa -> $"0x{__.Address:x}: {ISA.ArchToString isa.Arch}: {s}"
    | None -> $"0x{__.Address:x}: {s}"

/// Instruction tagged with its corresponding bytes.
type Instruction =
  | ValidInstruction of FrontEnd.BinLifter.Instruction * byte[]
  | BadInstruction of Addr * byte[]
with
  override __.ToString () =
    match __ with
    | ValidInstruction (ins, bs) ->
      let bs = Utils.makeByteArraySummary bs
      $"0x{ins.Address:x}: {bs}: {ins.Disasm ()}"
    | BadInstruction (addr, bs) ->
      let bs = Utils.makeByteArraySummary bs
      $"0x{addr:x}: {bs}: (bad)"
