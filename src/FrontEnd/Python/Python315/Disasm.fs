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
module internal B2R2.FrontEnd.Python.Python315.Disasm

open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.Python

/// BINARY_OP operators, in CPython's _nb_ops order.
let private binaryOps =
  [|
    "+"
    "&"
    "//"
    "<<"
    "@"
    "*"
    "%"
    "|"
    "**"
    ">>"
    "-"
    "/"
    "^"
    "+="
    "&="
    "//="
    "<<="
    "@="
    "*="
    "%="
    "|="
    "**="
    ">>="
    "-="
    "/="
    "^="
    "[]"
  |]
/// COMPARE_OP comparisons, in dis.cmp_op order.
let private cmpOps =
  [|
    "<"
    "<="
    "=="
    "!="
    ">"
    ">="
  |]
/// CALL_INTRINSIC_1 functions.
let private intrinsic1 =
  [|
    "INTRINSIC_1_INVALID"
    "INTRINSIC_PRINT"
    "INTRINSIC_IMPORT_STAR"
    "INTRINSIC_STOPITERATION_ERROR"
    "INTRINSIC_ASYNC_GEN_WRAP"
    "INTRINSIC_UNARY_POSITIVE"
    "INTRINSIC_LIST_TO_TUPLE"
    "INTRINSIC_TYPEVAR"
    "INTRINSIC_PARAMSPEC"
    "INTRINSIC_TYPEVARTUPLE"
    "INTRINSIC_SUBSCRIPT_GENERIC"
    "INTRINSIC_TYPEALIAS"
  |]
/// CALL_INTRINSIC_2 functions.
let private intrinsic2 =
  [|
    "INTRINSIC_2_INVALID"
    "INTRINSIC_PREP_RERAISE_STAR"
    "INTRINSIC_TYPEVAR_WITH_BOUND"
    "INTRINSIC_TYPEVAR_WITH_CONSTRAINTS"
    "INTRINSIC_SET_FUNCTION_TYPE_PARAMS"
    "INTRINSIC_SET_TYPEPARAM_DEFAULT"
  |]
/// LOAD_SPECIAL methods.
let private specialMethods =
  [|
    "__enter__"
    "__exit__"
    "__aenter__"
    "__aexit__"
  |]
/// LOAD_COMMON_CONSTANT values, rendered the way dis renders them: a
/// type by its bare name, anything else by its repr.
let private commonConstants =
  [|
    "AssertionError"
    "NotImplementedError"
    "tuple"
    "<built-in function all>"
    "<built-in function any>"
    "list"
    "set"
    "None"
    "''"
    "True"
    "False"
    "-1"
  |]

let private at (tbl: string[]) i =
  if i >= 0 && i < tbl.Length then tbl[i] else ""

/// The operand rendering CPython prints next to the oparg.
/// Empty means the oparg speaks for itself.
let private operandNote (opcode: Opcode) (arg: int) =
  match opcode with
  | Opcode.BINARY_OP ->
    at binaryOps arg
  | Opcode.COMPARE_OP ->
    (* 3.13 moved the comparison into the high bits and
       added a bit forcing the result to bool. *)
    let name = at cmpOps ((arg >>> 5) &&& 0xF)
    if name = "" then ""
    elif (arg &&& 0x10) <> 0 then "bool(" + name + ")"
    else name
  | Opcode.IS_OP ->
    if arg = 0 then "is" else "is not"
  | Opcode.CONTAINS_OP ->
    if arg = 0 then "in" else "not in"
  | Opcode.CALL_INTRINSIC_1 ->
    at intrinsic1 arg
  | Opcode.CALL_INTRINSIC_2 ->
    at intrinsic2 arg
  | Opcode.LOAD_SPECIAL ->
    at specialMethods arg
  | Opcode.LOAD_COMMON_CONSTANT ->
    at commonConstants arg
  | Opcode.CONVERT_VALUE ->
    match arg with
    | 1 -> "str"
    | 2 -> "repr"
    | 3 -> "ascii"
    | _ -> ""
  | Opcode.SET_FUNCTION_ATTRIBUTE ->
    (* A bit field: CPython names every bit that is set, in
       ascending order, comma separated. *)
    (* Bit 2 (annotations) was retired in 3.14; bit 4 is `annotate`. *)
    [| "defaults"; "kwdefaults"; ""; "closure"; "annotate" |]
    |> Array.mapi (fun i n -> if (arg >>> i) &&& 1 = 1 then n else "")
    |> Array.filter (fun n -> n <> "")
    |> String.concat ", "
  | _ ->
    ""

/// `dis` prints a constant with repr and a name bare, so the two
/// have to be told apart here, where the enum is known.
let private isConstOperand (opcode: Opcode) =
  match opcode with
  | Opcode.LOAD_CONST -> true
  | _ -> false

/// The word CPython prints for the flag bit an opcode packs beside its
/// index: a bare pushed NULL for a global, the NULL|self pair a method
/// lookup leaves on the stack. Empty when the opcode carries no flag.
let private flagWord (ins: Instruction) (opcode: Opcode) =
  if not ins.Flag then
    ""
  elif opcode = Opcode.LOAD_GLOBAL then
    "NULL"
  (* IMPORT_NAME spends its two low bits on how eagerly the module is bound,
     and the lazy bit wins when both are set. *)
  elif opcode = Opcode.IMPORT_NAME then
    match ins.Operands with
    | OneOperand(arg, _) when (arg &&& 1) = 1 -> "lazy"
    | _ -> "eager"
  else
    "NULL|self"

/// Spells the operand the way dis does, or None to leave the raw
/// argument to speak for itself.
let private buildOperand (ins: Instruction) (opcode: Opcode) =
  match ins.Operands with
  | NoOperand | TwoOperands _ ->
    None
  | OneOperand(arg, resolved) ->
    match resolved with
    | Some var ->
      let name =
        if isConstOperand opcode then Disasm.reprPyObj var
        else Disasm.toStringPyObj var
      Some(Disasm.withFlag false (flagWord ins opcode) name)
    | None ->
      (* An argument that indexes no table the code object carries -- a
         comparison, a bit field -- reads from the version's own table. *)
      match operandNote opcode arg with
      | "" -> None
      | note -> Some note

let disasm (ins: Instruction) (builder: IDisasmBuilder) =
  let opcode: Opcode = LanguagePrimitives.EnumOfValue ins.Opcode
  Disasm.disasmWithOperand ins (Disasm.opcodeToString opcode)
                           (buildOperand ins opcode) builder
