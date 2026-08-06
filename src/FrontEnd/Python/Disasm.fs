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

module internal B2R2.FrontEnd.Python.Disasm

open System.Collections.Concurrent
open System.Globalization
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile.Python

(* Every mnemonic is its Opcode case name in lower case, and has been for
   every opcode of every version. Generic over the version's own Opcode
   enum so each version reuses this rather than carrying a name table of
   its own. Cached because Enum.GetName allocates and Disasm runs per
   instruction. *)
let private mnemonics = ConcurrentDictionary<struct (System.Type * int),
                                             string>()

let inline opcodeToString (opcode: 'Op when 'Op: enum<int>) =
  let key = struct (typeof<'Op>, LanguagePrimitives.EnumToValue opcode)
  match mnemonics.TryGetValue key with
  | true, s ->
    s
  | _ ->
    match System.Enum.GetName opcode with
    | null -> raise InvalidOpcodeException
    | name -> mnemonics.GetOrAdd(key, name.ToLowerInvariant())

let rec toStringPyObj = function
  | PyNone ->
    "None"
  | PyInt i ->
    i.ToString()
  | PyLong s ->
    s
  | PyREF(_, obj) ->
    toStringPyObj obj
  | PyAscii str | PyShortAscii str | PyShortAsciiInterned str ->
    str
  | PyCode c ->
    $"<code object {c.Name}, file \"{c.FileName}\", line {c.FirstLineNo}>"
  | PyFloat f ->
    f.ToString()
  | PyBinaryFloat f ->
    let s = f.ToString("R", CultureInfo.InvariantCulture)
    let s = if s.Contains "E" || s.Contains "." then s else s + ".0"
    s
  | PyComplex(real, imag) ->
    if real = "0.0" then $"{imag}j"
    elif imag.StartsWith "-" then $"{real}{imag}j"
    else $"{real}+{imag}j"
  | PyBinaryComplex(real, imag) ->
    let fmt (f: double) =
      let s = f.ToString("R", CultureInfo.InvariantCulture)
      if s.Contains "E" || s.Contains "." then s else s + ".0"
    if real = 0.0 then $"{fmt imag}j"
    elif imag < 0.0 then $"{fmt real}{fmt imag}j"
    else $"{fmt real}+{fmt imag}j"
  | PyEllipsis ->
    "..."
  | PyTuple t ->
    let t = Array.map toStringPyObj t
    String.concat ", " t
  | PyTrue ->
    "True"
  | PyFalse ->
    "False"
  | PyString s ->
    System.Text.Encoding.ASCII.GetString s
  (* A constant frozenset, which the compiler builds for membership tests
     against a set literal. Rendered the way CPython's own dis renders it,
     since that is what this string is compared against. *)
  | PyFrozenSet objects ->
    let items = objects |> Array.map toStringPyObj |> String.concat ", "
    $"frozenset({{{items}}})"

let buildOprs (ins: Instruction) (builder: IDisasmBuilder) =
  match ins.Operands with
  | NoOperand ->
    ()
  | OneOperand(idx, None) ->
    builder.Accumulate(AsmWordKind.String, "\t\t")
    builder.Accumulate(AsmWordKind.Value, string idx)
  | OneOperand(idx, Some var) ->
    builder.Accumulate(AsmWordKind.String, "\t\t")
    builder.Accumulate(AsmWordKind.Value, string idx)
    builder.Accumulate(AsmWordKind.String, " (")
    builder.Accumulate(AsmWordKind.Value, toStringPyObj var)
    builder.Accumulate(AsmWordKind.String, ")")
  | TwoOperands _ ->
    ()

/// Renders one instruction. `mnemonic` comes from the caller because only
/// the version's own module knows which Opcode enum the raw value belongs to.
let disasm (ins: Instruction) mnemonic (builder: IDisasmBuilder) =
  builder.AccumulateAddrMarker ins.Address
  builder.Accumulate(AsmWordKind.Mnemonic, mnemonic)
  buildOprs ins builder
