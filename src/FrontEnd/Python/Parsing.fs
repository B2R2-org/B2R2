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

/// Reads a byte, folds the EXTENDED_ARG prefixes ahead of it, looks up what
/// its argument names and measures how far to advance. Only the numbering it
/// reads through belongs to a version; the loop itself never has.
module internal B2R2.FrontEnd.Python.Parsing

open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.Python
open B2R2.FrontEnd.BinLifter

/// Which of the code object's tables an opcode's argument indexes, keyed by
/// address so that each code object reads against its own. An opcode whose
/// argument is a number rather than an index has no table.
let private tableOf (binFile: PythonBinFile) minor opcode =
  match opcode with
  | Opcode.LOAD_CONST
  | Opcode.RETURN_CONST
  | Opcode.KW_NAMES
  | Opcode.INSTRUMENTED_RETURN_CONST ->
    binFile.Consts
  | Opcode.LOAD_NAME
  | Opcode.STORE_NAME
  | Opcode.DELETE_NAME
  | Opcode.STORE_ATTR
  | Opcode.DELETE_ATTR
  | Opcode.STORE_GLOBAL
  | Opcode.DELETE_GLOBAL
  | Opcode.LOAD_ATTR
  | Opcode.LOAD_METHOD
  | Opcode.IMPORT_NAME
  | Opcode.IMPORT_FROM
  | Opcode.LOAD_GLOBAL
  | Opcode.LOAD_SUPER_ATTR
  | Opcode.LOAD_FROM_DICT_OR_GLOBALS
  | Opcode.STORE_ANNOTATION
  | Opcode.INSTRUMENTED_LOAD_SUPER_ATTR ->
    binFile.Names
  | Opcode.LOAD_FAST
  | Opcode.STORE_FAST
  | Opcode.DELETE_FAST
  | Opcode.LOAD_FAST_CHECK
  | Opcode.LOAD_FAST_AND_CLEAR
  | Opcode.LOAD_FAST_BORROW
  | Opcode.LOAD_FAST_BORROW_LOAD_FAST_BORROW
  | Opcode.LOAD_FAST_LOAD_FAST
  | Opcode.STORE_FAST_LOAD_FAST
  | Opcode.STORE_FAST_STORE_FAST
  | Opcode.MAKE_CELL
  | Opcode.LOAD_FROM_DICT_OR_DEREF ->
    binFile.Varnames
  (* 3.11 folded the cell and free variables into the locals array, so from
     there on these index co_varnames rather than a space of their own. *)
  | Opcode.LOAD_CLOSURE
  | Opcode.LOAD_DEREF
  | Opcode.STORE_DEREF
  | Opcode.DELETE_DEREF
  | Opcode.LOAD_CLASSDEREF ->
    if minor >= 11 then binFile.Varnames else binFile.FreeVars
  | _ ->
    [||]

/// The opcodes 3.13 introduced that pack TWO co_varnames indices into one
/// argument, the high nibble first, so the operand carries both names.
let private isPairedLocal opcode =
  match opcode with
  | Opcode.LOAD_FAST_LOAD_FAST
  | Opcode.LOAD_FAST_BORROW_LOAD_FAST_BORROW
  | Opcode.STORE_FAST_LOAD_FAST
  | Opcode.STORE_FAST_STORE_FAST -> true
  | _ -> false

/// How far below the co_names index an opcode's flag bits sit, which is what
/// the raw argument has to be shifted by to reach the entry it names. The
/// flags arrive one version at a time: LOAD_GLOBAL gains its single bit in
/// 3.11, the attribute lookups theirs in 3.12, and IMPORT_NAME two of its own
/// in 3.15 -- before which every one of these arguments is a bare index.
let private flagBits minor opcode =
  match opcode with
  | Opcode.LOAD_GLOBAL -> if minor >= 11 then 1 else 0
  | Opcode.LOAD_ATTR -> if minor >= 12 then 1 else 0
  (* Two bits here, is-method-call and is-two-arg-super, rather than one. *)
  | Opcode.LOAD_SUPER_ATTR
  | Opcode.INSTRUMENTED_LOAD_SUPER_ATTR -> 2
  | Opcode.IMPORT_NAME -> if minor >= 15 then 2 else 0
  | _ -> 0

/// What an argument names, once the table it indexes is in hand. It is not
/// always the argument itself: several opcodes pack flag bits below the
/// index, and a few name two entries at once. The raw value is kept as the
/// operand either way, so that it still matches the oparg CPython reports.
let private resolveOperand minor opcode (entries: PyObject[]) idx =
  (* Bounds-checked on every path, not just the plain one: the shifted and
     nibble-split forms can land out of range too, and naming the opcode makes
     a table or encoding mismatch diagnosable from the message. *)
  let get i =
    if i < 0 || i >= entries.Length then
      failwithf "%A: oparg %d resolves to table index %d, but the table \
                 holds %d entries" opcode idx i entries.Length
    else
      entries[i]
  if isPairedLocal opcode then
    OneOperand(idx, Some(PyTuple [| get (idx >>> 4); get (idx &&& 0xF) |]))
  else
    OneOperand(idx, Some(get (idx >>> flagBits minor opcode)))

/// Looks up what the argument at this address names.
let private resolveArg (bf: PythonBinFile) opcode addr idx =
  let minor = PythonVersion.minor bf.Version
  tableOf bf minor opcode
  |> Array.tryFind (fun (r, _) -> r.Min <= addr && r.Max >= addr)
  |> function
    | Some(_, entries) -> resolveOperand minor opcode entries idx
    (* No table covers this address, which happens when a linear sweep walks
       off a code object, and for every opcode whose argument is a number
       rather than an index -- the raw argument is then the whole answer. *)
    | None -> OneOperand(idx, None)

/// The byte IS the opcode, once read through the version's own table, so
/// decoding is a lookup rather than the 200-line match it used to be, and the
/// encoded length comes from CPython's inline-cache table rather than a
/// hand-maintained size per case. An argument is one byte wide under wordcode
/// and two before it -- the same width the EXTENDED_ARG prefix carries, and
/// reading the wrong one takes the high half of the argument from whatever
/// follows the instruction.
let rec private doParse semantics (span: ByteSpan) reader bf s c e =
  let version = (bf: PythonBinFile).Version
  let b = (reader: IBinReader).ReadUInt8(span, 0) |> int
  if b = Tables.extendedArg version then
    (* A prefix is as wide as the instruction it precedes. *)
    if Tables.isWordcode version then
      let a = reader.ReadUInt8(span, 1) |> int
      doParse semantics (span.Slice 2) reader bf s (c + 2UL) ((e ||| a) <<< 8)
    else
      let a = reader.ReadUInt16(span, 1) |> int
      doParse semantics (span.Slice 3) reader bf s (c + 3UL) ((e ||| a) <<< 16)
  else
    let opcode = Tables.decode version b
    if opcode = Opcode.InvalidOp then raise ParsingFailureException else ()
    let opr =
      if Tables.hasOperand version b then
        let raw =
          if Tables.isWordcode version then reader.ReadUInt8(span, 1) |> int
          else reader.ReadUInt16(span, 1) |> int
        resolveArg bf opcode c (raw ||| e)
      else
        NoOperand
    let total = uint32 (c - s) + Tables.length version b
    Instruction(s, total, opcode, opr, LifterHelpers.rt, version, bf, semantics)

/// Everything about an instruction that the rest of B2R2 asks of it. Nothing
/// here holds state, so one instance serves every file ever opened.
let semantics =
  { new IInstructionSemantics with
      member _.Lift(ins, bld) = Lifter.translate ins.BinFile ins bld
      member _.Disasm(ins, bld) = Disasm.disasm ins bld
      member _.IsBranch ins = Semantics.isBranch ins
      member _.IsCondBranch ins = Semantics.isCondBranch ins
      member _.IsCJmpOnTrue ins = Semantics.isCJmpOnTrue ins
      member _.IsCall ins = Semantics.isCall ins
      member _.IsRET ins = Semantics.isRET ins
      member _.IsExit ins = Semantics.isExit ins
      member _.IsNop ins = Semantics.isNop ins
      member _.HasFlag ins = Semantics.hasFlag ins
      member _.SuperHasExplicitArgs ins = Semantics.superHasExplicitArgs ins
      member _.BranchTarget(ins, ft, n) = Semantics.branchTarget ins ft n }

/// Decodes the instruction at the given address.
let parse (span: ByteSpan) reader binFile addr =
  doParse semantics span reader binFile addr addr 0
