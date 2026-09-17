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
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile

/// The `lift` action.
type LiftAction() =
  let rec lift cancellationToken (sb: StringBuilder) (lifter: LiftingUnit)
               (ptr: BinFilePointer) =
    let cancellationToken: CancellationToken = cancellationToken
    cancellationToken.ThrowIfCancellationRequested()
    if ptr.CanReadFileBytes then
      match lifter.TryParseInstruction ptr with
      | Ok instr ->
        let s = lifter.LiftInstruction instr |> PrettyPrinter.ToString
        let ptr = ptr.Advance(instr.Length)
        lift cancellationToken (sb.Append s) lifter ptr
      | Error _ -> "Bad instruction found"
    else
      sb.ToString()

  let binaryOfInput (input: obj) =
    match input with
    | :? Binary as binary -> binary
    | :? BinarySlice as slice -> slice.ToBinary()
    | _ -> invalidArg "input" "Invalid input type."

  let liftByteArray cancellationToken (o: obj) =
    let bin = binaryOfInput o
    let hdl = Binary.Handle bin
    let lifter = hdl.NewLiftingUnit()
    let baddr = hdl.File.BaseAddress
    let len = hdl.File.Length
    let ptr =
      BinFilePointer.CreateFileBacked(
        baddr, baddr + uint64 len - 1UL, 0, len - 1)
    let sb = StringBuilder()
    lift cancellationToken sb lifter ptr
    |> box

  let transform cancellationToken collection =
    { Values =
        collection.Values |> Array.map (liftByteArray cancellationToken) }

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
      | [] -> transform CancellationToken.None collection
      | _ -> invalidArg (nameof args) "Invalid argument."

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      match args with
      | [] -> transform cancellationToken collection
      | _ -> invalidArg (nameof args) "Invalid argument."
