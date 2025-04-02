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

module B2R2.Peripheral.Assembly.ARM32.SecondPass

open B2R2
open B2R2.FrontEnd.ARM32
open B2R2.Peripheral.Assembly.ARM32.ParserHelper

let updateOperands _insAddress operandList labelToAddress =
  let rec doChecking operands (mapping: Map<string, Addr>) result =
    match operands with
    | [] -> extractOperands (List.rev result)
    | hd :: tail ->
      match hd with
      | GoToLabel (a1) ->
        if mapping.ContainsKey a1 then
          let lblAddr = mapping[a1]
          let value = LiteralMode (int64 lblAddr) |> OprMemory
          doChecking tail mapping (value :: result)
        else
          printfn "the label %s is not defined" a1
          failwith "Incorrect Label"
      | _ -> doChecking tail mapping (hd :: result)
  doChecking operandList labelToAddress []

/// This is the second pass. UpdateInsInfos replaces every occurance of Labels
/// coming as operands by their relative address values.
let updateInsInfos (insInfoList: AsmInsInfo list) labelToAddress =
  let rec doUpdate insInfos mapping result =
    match insInfos with
    | [] -> List.rev result
    | hd :: tail ->
      let operands = hd.Operands
      let operands = getOperandsAsList operands
      let operands = updateOperands hd.Address operands mapping
      let newInsInfo = {hd with Operands = operands}
      doUpdate tail mapping (newInsInfo :: result)
  doUpdate insInfoList labelToAddress []
