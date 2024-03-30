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

namespace B2R2.FrontEnd

open System.Collections.Concurrent
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile

[<AutoOpen>]
module private InstructionCollection =
  let rec update (hdl: BinHandle) (dict: ConcurrentDictionary<_, _>) shift ptr =
    if BinFilePointer.IsValid ptr then
      match hdl.TryParseInstr (ptr=ptr) with
      | Ok ins ->
        dict.TryAdd (ptr.Addr, ins) |> ignore
        update hdl dict shift (BinFilePointer.Advance ptr (int ins.Length))
      | Error _ ->
        update hdl dict shift (BinFilePointer.Advance ptr shift)
    else ()

  let updateDictionary (hdl: BinHandle) dict =
    let entryPoint = hdl.File.EntryPoint |> Option.defaultValue 0UL
    let ptr = hdl.File.ToBinFilePointer entryPoint
    let shiftAmount = 1 (* FIXME *)
    task { update hdl dict shiftAmount ptr } |> ignore

/// Collection of lifted instructions. When this class is instantiated, it will
/// automatically lift all possible instructions from the given binary, and
/// store them in the internal collection. This is shared across all functions.
type InstructionCollection (hdl: BinHandle) =
  let dict = ConcurrentDictionary<Addr, Instruction> ()
  do updateDictionary hdl dict

  /// Find cached one or parse (and cache) the instruction at the given address.
  member __.Find (addr: Addr) =
    match dict.TryGetValue addr with
    | true, ins -> Ok ins
    | false, _ ->
      match hdl.TryParseInstr (addr=addr) with
      | Ok ins -> dict.AddOrUpdate (addr, ins, (fun _ _ -> ins)) |> Ok
      | Error e -> Error e
