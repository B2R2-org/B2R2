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

module B2R2.RearEnd.BinDump.FunctionSymbols

open System.Collections.Generic
open B2R2
open B2R2.FrontEnd

let ofLinkageTable (hdl: BinHandle) =
  let funcs = Dictionary()
  for entry in hdl.File.GetLinkageTableEntries() do
    if entry.TrampolineAddress = 0UL then ()
    else funcs.TryAdd(entry.TrampolineAddress, entry.FuncName) |> ignore
  funcs

let ofText (hdl: BinHandle) =
  let funcs = Dictionary()
  for addr in hdl.File.GetFunctionAddresses() do
    match hdl.File.TryFindName addr with
    | Ok name -> funcs.TryAdd(addr, name) |> ignore
    | Error _ -> funcs.TryAdd(addr, Addr.toFuncName addr) |> ignore
  for entry in hdl.File.GetLinkageTableEntries() do
    if entry.TrampolineAddress = 0UL then ()
    else funcs.TryAdd(entry.TrampolineAddress, entry.FuncName) |> ignore
  funcs
