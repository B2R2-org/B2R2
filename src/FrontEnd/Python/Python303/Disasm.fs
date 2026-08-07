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

module internal B2R2.FrontEnd.Python.Python303.Disasm

open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.Python

(* dis names the comparison rather than showing its index, and this
   table is CPython 3.3's own cmp_op. *)
let private cmpOp =
  [| "<"
     "<="
     "=="
     "!="
     ">"
     ">="
     "in"
     "not in"
     "is"
     "is not"
     "exception match"
     "BAD" |]

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
    (* 3.3 spells a call's argument as the two counts packed
       into it: the low byte is positional, the high byte keyword
       pairs. 3.6 split these into separate opcodes. *)
    | Opcode.CALL_FUNCTION
    | Opcode.CALL_FUNCTION_VAR
    | Opcode.CALL_FUNCTION_KW
    | Opcode.CALL_FUNCTION_VAR_KW ->
      Some(sprintf "%d positional, %d keyword pair"
                   (arg % 256) (arg / 256))
    | _ ->
      (* A name, local or free variable reads as it stands. *)
      resolved |> Option.map Disasm.toStringPyObj

let disasm (ins: Instruction) (builder: IDisasmBuilder) =
  let opcode: Opcode = LanguagePrimitives.EnumOfValue ins.Opcode
  let operand = buildOperand ins opcode
  Disasm.disasmWithOperand ins (Disasm.opcodeToString opcode) operand
                           builder
