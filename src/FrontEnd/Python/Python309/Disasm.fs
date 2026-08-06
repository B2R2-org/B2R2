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

module internal B2R2.FrontEnd.Python.Python309.Disasm

open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.Python

(* dis names the comparison rather than showing its index, and this
   table is CPython 3.9's own cmp_op. *)
let private cmpOp =
  [| "<"; "<="; "=="; "!="; ">"; ">=" |]

(* The low two bits pick the conversion, bit 2 says a format spec
   follows, and dis joins the two with a comma only when the
   conversion is not the empty default. *)
let private formatValueConv = [| ""; "str"; "repr"; "ascii" |]

let private formatValueFlags arg =
  let conv = formatValueConv[arg &&& 0x3]
  if arg &&& 0x4 = 0 then conv
  elif conv = "" then "with format"
  else conv + ", with format"

(* One name per set bit, in bit order. *)
let private makeFunctionFlags arg =
  [| "defaults"; "kwdefaults"; "annotations"; "closure" |]
  |> Array.indexed
  |> Array.filter (fun (i, _) -> arg &&& (1 <<< i) <> 0)
  |> Array.map snd
  |> String.concat ", "

/// Spells the operand the way dis does, or None to leave the raw
/// argument to speak for itself.
let private buildOperand (ins: Instruction) (opcode: Opcode) =
  match ins.Operands with
  | NoOperand | TwoOperands _ ->
    None
  | OneOperand(arg, resolved) ->
    match opcode with
    | Opcode.LOAD_CONST ->
      resolved |> Option.map Disasm.reprPyObj
    | Opcode.COMPARE_OP ->
      if arg < cmpOp.Length then Some cmpOp[arg] else None
    | Opcode.FORMAT_VALUE ->
      Some(formatValueFlags arg)
    | Opcode.MAKE_FUNCTION ->
      Some(makeFunctionFlags arg)
    | _ ->
      (* A name, local or free variable reads as it stands. *)
      resolved |> Option.map Disasm.toStringPyObj

let disasm (ins: Instruction) (builder: IDisasmBuilder) =
  let opcode: Opcode = LanguagePrimitives.EnumOfValue ins.Opcode
  let operand = buildOperand ins opcode
  Disasm.disasmWithOperand ins (Disasm.opcodeToString opcode) operand
                           builder
