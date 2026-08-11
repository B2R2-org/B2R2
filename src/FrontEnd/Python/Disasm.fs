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

open System
open System.Collections.Concurrent
open System.Globalization
open System.Text
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile.Python

/// Every mnemonic is its Opcode case name in lower case, and has been for
/// every opcode of every version, so nothing here needs a name table of its
/// own. Cached because Enum.GetName allocates and disassembly runs once per
/// instruction.
let private mnemonics = ConcurrentDictionary<Opcode, string>()

let opcodeToString (opcode: Opcode) =
  match mnemonics.TryGetValue opcode with
  | true, s ->
    s
  | _ ->
    match Enum.GetName opcode with
    | null -> raise InvalidOpcodeException
    | name -> mnemonics.GetOrAdd(opcode, name.ToLowerInvariant())

/// The comparisons COMPARE_OP names, in dis.cmp_op order. Every version since
/// 3.9 has had these six and no others; which bits of the argument index them
/// is the version's own business.
let cmpOps = [| "<"; "<="; "=="; "!="; ">"; ">=" |]

/// The entry at `i`, or the empty string when the table does not reach that
/// far -- which is how an argument no table explains reads back as its own
/// raw number.
let at (tbl: string[]) i = if i >= 0 && i < tbl.Length then tbl[i] else ""

/// A double spelled so that it reads back as itself, with the trailing `.0`
/// that tells a whole number from an int.
let private roundTripFloat (f: double) =
  let s = f.ToString("R", CultureInfo.InvariantCulture)
  if s.Contains "E" || s.Contains "." then s else s + ".0"

/// Renders a value as a *name*, which is what `dis` prints for anything the
/// operand indexes out of co_names or co_varnames: no quotes on a string, no
/// parentheses on a tuple. See reprPyObjWith below for the other rendering.
let rec toStringPyObj = function
  | PyNone ->
    "None"
  | PyInt i ->
    i.ToString()
  | PyLong s ->
    s
  | PyREF(_, obj) ->
    toStringPyObj obj
  | PyAscii str | PySurrogateText(str, _)
  | PyShortAscii str | PyShortAsciiInterned str ->
    str
  | PyCode c ->
    $"<code object {c.Name}, file \"{c.FileName}\", line {c.FirstLineNo}>"
  | PyFloat f ->
    f.ToString()
  | PyBinaryFloat f ->
    roundTripFloat f
  | PyComplex(real, imag) ->
    if real = "0.0" then $"{imag}j"
    elif imag.StartsWith "-" then $"{real}{imag}j"
    else $"{real}+{imag}j"
  | PyBinaryComplex(real, imag) ->
    let re, im = roundTripFloat real, roundTripFloat imag
    if real = 0.0 then $"{im}j"
    elif imag < 0.0 then $"{re}{im}j"
    else $"{re}+{im}j"
  | PyEllipsis ->
    "..."
  | PyTuple t ->
    Array.map toStringPyObj t |> String.concat ", "
  (* A slice and a frozenset are spelled the way CPython's own repr does, so
     that `load_const` of one reads the same on both sides. *)
  | PySlice(start, stop, step) ->
    let f = toStringPyObj
    $"slice({f start}, {f stop}, {f step})"
  | PyFrozenSet items ->
    if Array.isEmpty items then
      "frozenset()"
    else
      let items = Array.map toStringPyObj items
      "frozenset({" + String.concat ", " items + "})"
  | PyTrue ->
    "True"
  | PyFalse ->
    "False"
  | PyString s ->
    Encoding.ASCII.GetString s

/// Whether repr leaves a character alone, which is str.isprintable(): every
/// category CPython calls unprintable, plus space being the one separator it
/// keeps. A lone surrogate lands in Surrogate and so gets spelled -- which is
/// the point, since that is how CPython shows one.
let private isPrintable (cat: UnicodeCategory) (cp: int) =
  match cat with
  | UnicodeCategory.Control
  | UnicodeCategory.Format
  | UnicodeCategory.Surrogate
  | UnicodeCategory.PrivateUse
  | UnicodeCategory.OtherNotAssigned
  | UnicodeCategory.LineSeparator
  | UnicodeCategory.ParagraphSeparator -> false
  | UnicodeCategory.SpaceSeparator -> cp = 0x20
  | _ -> true

/// The escape repr picks for an unprintable code point, narrowest first.
let private escapeCodePoint cp =
  if cp < 0x100 then sprintf "\\x%02x" cp
  elif cp < 0x10000 then sprintf "\\u%04x" cp
  else sprintf "\\U%08x" cp

/// Escapes a string the way repr does: control characters are spelled rather
/// than emitted, and the quote is single unless that would need escaping
/// while a double quote would not, which is the rule CPython applies.
/// `lone` holds the positions the marshal reader saw a surrogate arrive on
/// its own, which is the one thing the decoded string can no longer be asked.
let private pyStrRepr (lone: Set<int>) (s: string) =
  let quote = if s.Contains "'" && not (s.Contains "\"") then '"' else '\''
  let sb = StringBuilder()
  sb.Append quote |> ignore
  let mutable i = 0
  while i < s.Length do
    (* A surrogate PAIR is one code point, so it must be measured as a pair
       rather than as the two unprintable halves it is made of. Which of the
       two it is cannot be seen here: a Python str is a sequence of code
       POINTS, where `'🐍'` is two lone surrogates, while a .NET
       string is UTF-16 code UNITS, where those same two values are one
       astral character -- four UTF-8 bytes and three-plus-three arrive
       identical. So the reader passes on where it saw the halves arrive
       separately, and everything else pairs. *)
    let paired =
      not (lone.Contains i) && Char.IsHighSurrogate s[i]
      && i + 1 < s.Length && Char.IsLowSurrogate s[i + 1]
    let cp =
      if paired then Char.ConvertToUtf32(s[i], s[i + 1]) else int s[i]
    (* Asked with an index, .NET reads the pair and answers for the character
       it spells -- which is the wrong answer for a surrogate standing on its
       own, and would let it through unescaped. *)
    let cat =
      if paired then CharUnicodeInfo.GetUnicodeCategory(s, i)
      else CharUnicodeInfo.GetUnicodeCategory s[i]
    match s[i] with
    | '\\' -> sb.Append "\\\\" |> ignore
    | '\n' -> sb.Append "\\n" |> ignore
    | '\r' -> sb.Append "\\r" |> ignore
    | '\t' -> sb.Append "\\t" |> ignore
    | c when c = quote -> sb.Append('\\').Append c |> ignore
    | _ when not (isPrintable cat cp) -> sb.Append(escapeCodePoint cp) |> ignore
    | _ -> sb.Append(s.Substring(i, if paired then 2 else 1)) |> ignore
    i <- i + (if paired then 2 else 1)
  sb.Append quote |> ignore
  sb.ToString()

/// The same for a bytes constant, which repr prefixes with `b` and where a
/// byte outside printable ASCII is spelled rather than decoded -- decoding it
/// as text loses the byte, since anything non-ASCII becomes a replacement
/// character and no longer says what was in the file.
let private pyBytesRepr (bs: byte[]) =
  let hasSingle = Array.contains (byte '\'') bs
  let hasDouble = Array.contains (byte '"') bs
  let quote = if hasSingle && not hasDouble then '"' else '\''
  let sb = StringBuilder()
  sb.Append('b').Append quote |> ignore
  for b in bs do
    match char b with
    | '\\' -> sb.Append "\\\\" |> ignore
    | '\n' -> sb.Append "\\n" |> ignore
    | '\r' -> sb.Append "\\r" |> ignore
    | '\t' -> sb.Append "\\t" |> ignore
    | c when c = quote -> sb.Append('\\').Append c |> ignore
    | c when b >= 0x20uy && b < 0x7Fuy -> sb.Append c |> ignore
    | _ -> sb.Append(sprintf "\\x%02x" (int b)) |> ignore
  sb.Append quote |> ignore
  sb.ToString()

/// The seventeen significant digits that tell a double from every other one,
/// with where the decimal point falls among them -- the value is 0.digits
/// times ten to the decpt, which is the decomposition CPython chooses its
/// notation on.
let private exactDigits (f: double) =
  let s = abs(f).ToString("E16", CultureInfo.InvariantCulture)
  let i = s.IndexOf 'E'
  s.Substring(0, i).Replace(".", ""), int (s.Substring(i + 1)) + 1

/// Rounds a digit string to `n` places, half away from zero. Also reports
/// whether the carry ran off the front, which moves the point one place.
let private roundTo (digits: string) n =
  if digits[n] < '5' then
    digits.Substring(0, n), 0
  else
    let arr = digits.Substring(0, n).ToCharArray()
    let mutable i = n - 1
    let mutable carry = true
    while carry && i >= 0 do
      if arr[i] = '9' then
        arr[i] <- '0'
      else
        arr[i] <- char (int arr[i] + 1)
        carry <- false
      i <- i - 1
    if carry then "1" + String(arr[0..n - 2]), 1
    else String arr, 0

/// The fewest digits that still read back as the same double, which is what
/// Python's repr prints. Shortens the exact decimal a digit at a time rather
/// than trusting one of .NET's fixed precisions: "R" keeps digits a subnormal
/// has no need of, and on an exact tie rounds the last one the way repr does
/// not -- 2**-25 reads `5.960464477539063e-08` in Python and one digit longer
/// from .NET.
let private shortestDigits (f: double) =
  let inv = CultureInfo.InvariantCulture
  let all, decpt = exactDigits f
  let rec search n =
    if n >= all.Length then
      all.TrimEnd '0', decpt
    else
      let digits, shift = roundTo all n
      let s = "0." + digits + "E" + string (decpt + shift)
      if Double.Parse(s, NumberStyles.Float, inv) = abs f then
        digits.TrimEnd '0', decpt + shift
      else
        search (n + 1)
  search 1

/// The float spelling repr uses inside a complex, which unlike a bare float
/// does not gain a trailing `.0` -- `complex(3, 0)` reads `(3+0j)`. Turns to
/// the exponent by where the point falls rather than by magnitude, which is
/// the rule CPython applies and not the one .NET does.
///
/// `legacy` picks 3.0's spelling. `sys.float_repr_style` reads `legacy` there
/// and `short` from 3.1 on: before the shortest-representation work landed,
/// repr was plain `%.17g`, so 3.0 writes `3.1415926535897931` where every
/// later version writes `3.141592653589793`, and turns to the exponent one
/// place later because `%g` does so at its own precision.
let private complexPartWith legacy (f: double) =
  if Double.IsNaN f then
    "nan"
  elif Double.IsPositiveInfinity f then
    "inf"
  elif Double.IsNegativeInfinity f then
    "-inf"
  elif f = 0.0 then
    if Double.IsNegative f then "-0" else "0"
  else
    let sign = if Double.IsNegative f then "-" else ""
    let digits, decpt =
      if legacy then
        let all, decpt = exactDigits f
        all.TrimEnd '0', decpt
      else
        shortestDigits f
    if decpt <= -4 || decpt > (if legacy then 17 else 16) then
      let tail = digits.Substring 1
      let body =
        if tail = "" then digits else digits.Substring(0, 1) + "." + tail
      sign + body + (decpt - 1).ToString("'e'+00;'e'-00")
    elif decpt <= 0 then
      sign + "0." + String('0', -decpt) + digits
    elif decpt >= digits.Length then
      sign + digits + String('0', decpt - digits.Length)
    else
      sign + digits.Substring(0, decpt) + "." + digits.Substring decpt

/// And for a float on its own, where a whole number keeps the trailing `.0`
/// that tells it from an int.
let private pyFloatReprWith legacy (f: double) =
  let s = complexPartWith legacy f
  if s |> Seq.exists (fun c -> c = '.' || c = 'e' || c = 'n') then s
  else s + ".0"

/// repr for a complex. A real part of positive zero is dropped along with the
/// parentheses, which is how CPython spells a pure imaginary (`2j`), and the
/// sign between the parts comes from the imaginary part's own sign bit, so
/// negative zero still reads as `-0j`.
let private pyComplexReprWith legacy (real: double) (imag: double) =
  let part = complexPartWith legacy
  if real = 0.0 && not (Double.IsNegative real) then
    part imag + "j"
  else
    let sign = if Double.IsNegative imag then "-" else "+"
    "(" + part real + sign + part (abs imag) + "j)"

/// Renders a value as a *constant*, which is what `dis` prints for anything
/// the operand indexes out of co_consts: a string carries its quotes and a
/// tuple its parentheses, down to the trailing comma that tells a one-element
/// tuple from a parenthesised value. Only the operand's own opcode says which
/// of the two renderings applies, so the version's module chooses; see
/// buildOperand in each Python3XX/Disasm.fs. `legacy` travels the whole walk
/// rather than stopping at a leaf, because a float can sit inside the tuple a
/// single LOAD_CONST names.
let rec reprPyObjWith legacy obj =
  match obj with
  | PyAscii s | PyShortAscii s | PyShortAsciiInterned s ->
    pyStrRepr Set.empty s
  | PySurrogateText(s, lone) ->
    pyStrRepr (Set.ofArray lone) s
  | PyString bs ->
    pyBytesRepr bs
  | PyBinaryFloat f ->
    pyFloatReprWith legacy f
  | PyBinaryComplex(real, imag) ->
    pyComplexReprWith legacy real imag
  (* `...` is how the ellipsis is written in source; repr names the object. *)
  | PyEllipsis ->
    "Ellipsis"
  | PyREF(_, o) ->
    reprPyObjWith legacy o
  | PyTuple [||] ->
    "()"
  | PyTuple [| single |] ->
    "(" + reprPyObjWith legacy single + ",)"
  | PyTuple t ->
    "(" + (t |> Array.map (reprPyObjWith legacy) |> String.concat ", ") + ")"
  | PyFrozenSet [||] ->
    "frozenset()"
  | PyFrozenSet items ->
    let items = items |> Array.map (reprPyObjWith legacy) |> String.concat ", "
    "frozenset({" + items + "})"
  | o ->
    toStringPyObj o

/// What every version from 3.1 on prints.
let reprPyObj obj = reprPyObjWith false obj

/// What 3.0 prints, whose repr predates the shortest-float work.
let reprPyObjLegacyFloat obj = reprPyObjWith true obj

/// BINARY_OP operators, in CPython's _nb_ops order. 3.14 gave subscription
/// its own entry at the end. Which words a table like this holds is a
/// version's own business; how the operand reads around it is not.
let private binaryOps13 =
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
  |]

let private binaryOps14 = Array.append binaryOps13 [| "[]" |]

/// cmp_op up to 3.8, which still spelled the comparisons 3.9 split out into
/// IS_OP, CONTAINS_OP and JUMP_IF_NOT_EXC_MATCH.
let private cmpOpsLegacy =
  [|
    "<"
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
    "BAD"
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

/// CALL_INTRINSIC_2 functions. 3.13 added the last of them.
let private intrinsic2 =
  [|
    "INTRINSIC_2_INVALID"
    "INTRINSIC_PREP_RERAISE_STAR"
    "INTRINSIC_TYPEVAR_WITH_BOUND"
    "INTRINSIC_TYPEVAR_WITH_CONSTRAINTS"
    "INTRINSIC_SET_FUNCTION_TYPE_PARAMS"
  |]

let private intrinsic2From13 =
  Array.append intrinsic2 [| "INTRINSIC_SET_TYPEPARAM_DEFAULT" |]

/// LOAD_SPECIAL methods.
let private specialMethods =
  [|
    "__enter__"
    "__exit__"
    "__aenter__"
    "__aexit__"
  |]

/// LOAD_COMMON_CONSTANT values, rendered the way dis renders them: a type by
/// its bare name, anything else by its repr. 3.15 added the last four.
let private commonConstants14 =
  [|
    "AssertionError"
    "NotImplementedError"
    "tuple"
    "<built-in function all>"
    "<built-in function any>"
    "list"
    "set"
    "None"
  |]

let private commonConstants15 =
  Array.append commonConstants14 [| "''"; "True"; "False"; "-1" |]

/// The bits SET_FUNCTION_ATTRIBUTE and MAKE_FUNCTION name, lowest first. 3.14
/// retired the annotations bit and put `annotate` above closure.
let private functionAttrs13 =
  [|
    "defaults"
    "kwdefaults"
    "annotations"
    "closure"
  |]

let private functionAttrs14 =
  [|
    "defaults"
    "kwdefaults"
    ""
    "closure"
    "annotate"
  |]

/// Every name whose bit the argument sets, in ascending order.
let private bitNames (names: string[]) arg =
  names
  |> Array.mapi (fun i n -> if (arg >>> i) &&& 1 = 1 then n else "")
  |> Array.filter (fun n -> n <> "")
  |> String.concat ", "

/// The conversion FORMAT_VALUE and CONVERT_VALUE name by number.
let private conversions =
  [|
    ""
    "str"
    "repr"
    "ascii"
  |]

/// FORMAT_VALUE's low two bits pick the conversion and bit two says a format
/// spec travels with it, which dis joins to the conversion with a comma.
let private formatValueFlags arg =
  let conv = conversions[arg &&& 0x3]
  if arg &&& 0x4 = 0 then conv
  elif conv = "" then "with format"
  else conv + ", with format"

/// COMPARE_OP's argument is the bare index up to 3.11, and up to 3.8 it
/// indexes a cmp_op that still holds the identity and membership tests. 3.12
/// moved the index four bits up to make room for cache flags, 3.13 five, and
/// 3.13 added one below it saying the result is forced to bool.
let private compareNote minor arg =
  if minor <= 8 then at cmpOpsLegacy arg
  elif minor <= 11 then at cmpOps arg
  elif minor = 12 then at cmpOps (arg >>> 4)
  else
    match at cmpOps ((arg >>> 5) &&& 0xF) with
    | "" -> ""
    | name when (arg &&& 0x10) <> 0 -> "bool(" + name + ")"
    | name -> name

/// What dis prints next to an argument that indexes no table the code object
/// carries -- a comparison, a bit field, an interpreter-internal table.
/// Empty means the argument speaks for itself.
let private operandNote minor opcode arg =
  match opcode with
  | Opcode.COMPARE_OP -> compareNote minor arg
  | Opcode.IS_OP -> if arg = 0 then "is" else "is not"
  | Opcode.CONTAINS_OP -> if arg = 0 then "in" else "not in"
  | Opcode.FORMAT_VALUE -> formatValueFlags arg
  | Opcode.BINARY_OP ->
    at (if minor >= 14 then binaryOps14 else binaryOps13) arg
  | Opcode.CALL_INTRINSIC_1 -> at intrinsic1 arg
  | Opcode.CALL_INTRINSIC_2 ->
    at (if minor >= 13 then intrinsic2From13 else intrinsic2) arg
  | Opcode.LOAD_SPECIAL -> at specialMethods arg
  | Opcode.LOAD_COMMON_CONSTANT ->
    at (if minor >= 15 then commonConstants15 else commonConstants14) arg
  | Opcode.CONVERT_VALUE -> at conversions arg
  | Opcode.MAKE_FUNCTION -> bitNames functionAttrs13 arg
  | Opcode.SET_FUNCTION_ATTRIBUTE ->
    bitNames (if minor >= 14 then functionAttrs14 else functionAttrs13) arg
  (* 3.0 to 3.5 pack two counts into a call's argument: the low byte counts
     positional arguments and the high byte keyword pairs. 3.6 split them. *)
  | Opcode.CALL_FUNCTION
  | Opcode.CALL_FUNCTION_VAR
  | Opcode.CALL_FUNCTION_KW
  | Opcode.CALL_FUNCTION_VAR_KW when minor <= 5 ->
    sprintf "%d positional, %d keyword pair" (arg % 256) (arg / 256)
  | _ -> ""

/// dis prints a constant with repr and a name bare, so the two have to be
/// told apart, and only the opcode says which of them it is. An opcode a
/// version does not have cannot reach this, so nothing here needs a version.
let private isConstOperand opcode =
  match opcode with
  | Opcode.LOAD_CONST
  | Opcode.KW_NAMES
  | Opcode.RETURN_CONST
  | Opcode.INSTRUMENTED_RETURN_CONST -> true
  | _ -> false

/// The word CPython prints for the flag bit an opcode packs beside its index:
/// a bare pushed NULL for a global, the NULL|self pair a method lookup leaves
/// on the stack, and from 3.15 how eagerly an import binds. Empty when the
/// opcode carries no flag, which is every opcode before 3.11.
let private flagWord (ins: Instruction) opcode =
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

/// Joins an operand to the flag its opcode packs alongside the index. CPython
/// printed the flag ahead of the name up to 3.12 and after it from 3.13.
let private withFlag (ins: Instruction) opcode (name: string) =
  match flagWord ins opcode with
  | "" -> name
  | flag when ins.Minor <= 12 -> flag + " + " + name
  | flag -> name + " + " + flag

/// Spells the operand the way dis does, or None to leave the raw argument to
/// speak for itself.
let private buildOperand (ins: Instruction) opcode =
  match ins.Operands with
  | NoOperand ->
    None
  | OneOperand(arg, resolved) ->
    match resolved with
    | Some var ->
      (* 3.0's repr predates the shortest-float work, so it spells a float
         differently from every version after it. *)
      let name =
        if not (isConstOperand opcode) then toStringPyObj var
        elif ins.Minor = 0 then reprPyObjLegacyFloat var
        else reprPyObj var
      Some(withFlag ins opcode name)
    | None ->
      match operandNote ins.Minor opcode arg with
      | "" -> None
      | note -> Some note

/// Renders one instruction the way CPython's own dis does.
let disasm (ins: Instruction) (builder: IDisasmBuilder) =
  builder.AccumulateAddrMarker ins.Address
  builder.Accumulate(AsmWordKind.Mnemonic, opcodeToString ins.Opcode)
  match ins.Operands with
  | NoOperand ->
    ()
  | OneOperand(idx, _) ->
    builder.Accumulate(AsmWordKind.String, "\t\t")
    builder.Accumulate(AsmWordKind.Value, string idx)
    match buildOperand ins ins.Opcode with
    | Some text ->
      builder.Accumulate(AsmWordKind.String, " (")
      builder.Accumulate(AsmWordKind.Value, text)
      builder.Accumulate(AsmWordKind.String, ")")
    | None ->
      ()
  builder
