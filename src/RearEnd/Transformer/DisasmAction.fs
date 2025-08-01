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
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile

/// The `disasm` action.
type DisasmAction() =
  let rec disasm acc (lifter: LiftingUnit) (ptr: BinFilePointer) =
    if ptr.IsValid then
      match lifter.TryParseInstruction ptr with
      | Ok instr ->
        let insLen = int instr.Length
        let insBytes =
          IBinFile.Slice(lifter.File, ptr.Offset, insLen).ToArray()
        let ptr = ptr.Advance insLen
        let acc = ValidInstruction(instr, insBytes) :: acc
        disasm acc lifter ptr
      | Error _ ->
        let badbyte = [| lifter.File.RawBytes[ptr.Offset] |]
        let acc = BadInstruction(ptr.Addr, badbyte) :: acc
        let ptr = ptr.Advance 1
        disasm acc lifter ptr
    else
      List.rev acc |> List.toArray

  let disasmByteArray _args (o: obj) =
    let bin = unbox<Binary> o
    let hdl = Binary.Handle bin
    let lifter = hdl.NewLiftingUnit()
    let baddr = hdl.File.BaseAddress
    let len = hdl.File.Length
    let ptr = BinFilePointer(baddr, baddr + uint64 len - 1UL, 0, len - 1)
    disasm [] lifter ptr
    |> box

  interface IAction with
    member _.ActionID with get() = "disasm"
    member _.Signature with get() = "Binary -> Instruction array"
    member _.Description with get() = """
    Take in a binary and linearly disassemble the binary to return a list of
    instructions along with its corresponding bytes.
"""
    member _.Transform(args, collection) =
      { Values = collection.Values |> Array.map (disasmByteArray args) }
