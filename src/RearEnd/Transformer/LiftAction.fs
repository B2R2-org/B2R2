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

open System.Threading
open System.Text
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile

/// The `lift` action.
type LiftAction() =
  let appendInstruction (sb: StringBuilder) (instr: IInstruction) stmts =
    sb.Append("0x").Append(instr.Address.ToString("x"))
      .Append(": ").AppendLine(instr.Disasm()) |> ignore
    for stmt in stmts do
      match stmt with
      | ISMark _
      | IEMark _ ->
        ()
      | _ ->
        sb.Append("  ").AppendLine(PrettyPrinter.ToString stmt)
        |> ignore

  let rec lift
    (ct: CancellationToken)
    (sb: StringBuilder)
    (lifter: LiftingUnit)
    (ptr: BinFilePointer) =
    ct.ThrowIfCancellationRequested()
    if ptr.CanReadFileBytes then
      match lifter.TryParseInstruction ptr with
      | Ok instr when instr.Length > 0u
                      && int instr.Length <= ptr.ReadableAmount ->
        let stmts = lifter.LiftInstruction instr
        appendInstruction sb instr stmts
        let ptr = ptr.Advance(instr.Length)
        lift ct sb lifter ptr
      | _ ->
        sb.Append("0x").Append(ptr.Addr.ToString("x"))
          .AppendLine(": <undecodable>") |> ignore
        sb.ToString()
    else
      sb.ToString()

  let binaryOfInput (input: obj) =
    match input with
    | :? Binary as binary ->
      binary
    | :? BinarySlice as slice ->
      slice.ToBinary()
    | _ ->
      invalidArg "input" "Invalid input type."

  let liftByteArray ct (o: obj) =
    let bin = binaryOfInput o
    let hdl = Binary.Handle bin
    let lifter = hdl.NewLiftingUnit()
    let baddr = hdl.File.BaseAddress
    let len = hdl.File.Length
    let ptr =
      BinFilePointer.CreateFileBacked(
        baddr,
        baddr + uint64 len - 1UL,
        0,
        len - 1
      )
    let sb = StringBuilder()
    lift ct sb lifter ptr
    |> box

  let transform ct collection =
    { Values =
        collection.Values |> Array.map (liftByteArray ct) }

  interface IAction with
    member _.ActionID with get() = "lift"
    member _.Signature with get() = "Binary | BinarySlice -> string"
    member _.Description with get() =
      """
    Take in a binary and linearly disassemble the binary and lift it to a
    sequence of LowUIR statements, and dump the result to a string.
"""
    member _.Transform(args, collection) =
      match args with
      | [] ->
        transform CancellationToken.None collection
      | _ ->
        invalidArg (nameof args) "Invalid argument."

  interface ICancellableAction with
    member _.Transform(args, collection, ct) =
      match args with
      | [] ->
        transform ct collection
      | _ ->
        invalidArg (nameof args) "Invalid argument."
