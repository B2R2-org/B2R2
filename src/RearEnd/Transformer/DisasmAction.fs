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
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinInterface

/// The `disasm` action.
type DisasmAction () =
  let rec disasm acc hdl bp =
    if BinaryPointer.IsValid bp then
      match BinHandle.TryParseInstr (hdl, bp) with
      | Ok instr ->
        let insLen = int instr.Length
        let insBytes = hdl.BinFile.Span.Slice(bp.Offset, insLen).ToArray()
        let bp = BinaryPointer.Advance bp insLen
        let acc = ValidInstruction (instr, insBytes) :: acc
        disasm acc hdl bp
      | Error _ ->
        let acc =
          BadInstruction (bp.Addr, [| hdl.BinFile.Span[bp.Offset] |]) :: acc
        let bp = BinaryPointer.Advance bp 1
        disasm acc hdl bp
    else
      List.rev acc |> List.toArray

  interface IAction with
    member __.ActionID with get() = "disasm"
    member __.InputType with get() = typeof<ByteArray>
    member __.OutputType with get() = typeof<Instruction[]>
    member __.Description with get() = """
    Takes in a binary array and linearly disassemble the binary to return a list
    of instructions along with its corresponding bytes.

      - <isa> <mode>: disassemble the binary for the given ISA and mode.
      - <isa>: disassemble the binary for the given ISA.
"""
    member __.Transform args input =
      let barr = unbox<ByteArray> input
      let baseAddr = Some barr.Address
      let hdl =
        match args with
        | isa :: mode :: [] ->
          let isa = ISA.OfString isa
          let mode = ArchOperationMode.ofString mode
          BinHandle.Init (isa, mode, false, baseAddr, bytes=barr.Bytes)
        | isa :: [] ->
          let isa = ISA.OfString isa
          let mode = ArchOperationMode.NoMode
          BinHandle.Init (isa, mode, false, baseAddr, bytes=barr.Bytes)
        | [] ->
          let isa = Utils.unwrapISA barr.ISA
          let mode = ArchOperationMode.NoMode
          BinHandle.Init (isa, mode, false, baseAddr, bytes=barr.Bytes)
        | _ -> invalidArg (nameof DisasmAction) "Invalid arguments given."
      let bp = BinaryPointer (barr.Address, 0, barr.Bytes.Length - 1)
      disasm [] hdl bp