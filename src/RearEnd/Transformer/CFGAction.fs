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

open System
open System.Globalization
open System.Threading
open B2R2.MiddleEnd
open B2R2.MiddleEnd.ControlFlowAnalysis

/// The `cfg` action.
type CFGAction() =
  let parseAddress (args: string list) =
    match args with
    | [ (address: string) ] ->
      let style, address =
        if address.StartsWith("0x", StringComparison.OrdinalIgnoreCase) then
          NumberStyles.HexNumber, address[2..]
        else
          NumberStyles.Integer, address
      UInt64.Parse(address, style, CultureInfo.InvariantCulture)
    | _ ->
      invalidArg (nameof args) "Expected: cfg entry=<address>."

  let tryGetFunctionCFG cancellationToken source (fn: Function) =
    let cancellationToken: CancellationToken = cancellationToken
    cancellationToken.ThrowIfCancellationRequested()
    try
      CFG.Init(fn.EntryPoint, fn.CFG, source)
    with e ->
      NoCFG e.Message

  let findFunction address (brew: BinaryBrew) =
    brew.Functions.Sequence
    |> Seq.tryFind (fun fn -> fn.EntryPoint = address)

  let getAllCFGs cancellationToken source (brew: BinaryBrew) =
    brew.Functions.Sequence
    |> Seq.map (tryGetFunctionCFG cancellationToken source)
    |> Seq.map box
    |> Seq.toArray

  let getOneCFG cancellationToken args (bin: Binary) =
    let cancellationToken: CancellationToken = cancellationToken
    let hdl = Binary.Handle bin
    let brew = BinaryBrew hdl
    cancellationToken.ThrowIfCancellationRequested()
    let address = parseAddress args
    match findFunction address brew with
    | Some fn ->
      [| tryGetFunctionCFG cancellationToken bin fn |> box |]
    | None ->
      [| NoCFG $"Function not found: {address:x}" |> box |]

  let getFunctionCFG cancellationToken (fn: FunctionInfo) =
    let hdl = Binary.Handle fn.Source
    let brew = BinaryBrew hdl
    match findFunction fn.Entry brew with
    | Some func ->
      [| tryGetFunctionCFG cancellationToken fn.Source func |> box |]
    | None ->
      [| NoCFG $"Function not found: {fn.Entry:x}" |> box |]

  let getCFGs cancellationToken args (input: obj) =
    let cancellationToken: CancellationToken = cancellationToken
    cancellationToken.ThrowIfCancellationRequested()
    match input with
    | :? Binary as bin ->
      try
        let hdl = Binary.Handle bin
        let brew = BinaryBrew hdl
        cancellationToken.ThrowIfCancellationRequested()
        match args with
        | [] ->
          getAllCFGs cancellationToken bin brew
        | _ ->
          getOneCFG cancellationToken args bin
      with e ->
        [| e.ToString() |> NoCFG |> box |]
    | :? FunctionInfo as fn ->
      if List.isEmpty args then
        getFunctionCFG cancellationToken fn
      else
        invalidArg (nameof args) "FunctionInfo input accepts no arguments."
    | _ ->
      invalidArg (nameof input) "Invalid argument."

  let transform cancellationToken args collection =
    { Values =
        collection.Values
        |> Array.collect (getCFGs cancellationToken args) }

  interface IAction with
    member _.ActionID with get() = "cfg"
    member _.Signature with get() =
      "Binary -> cfg -> CFG collection | cfg entry=<address> -> CFG"
    member _.Description with get() =
      """
    Take in a Binary as input and returns an IR-level Control Flow Graph (CFG)
    as output. This action assumes that the given binary is well-formed, meaning
    that it has no bad instructions, and the control does not flow in the middle
    of an instruction. Any indirect branches will be simply ignored, i.e., it
    does not perform any of the heavy analyses in our middle-end.
"""
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection
