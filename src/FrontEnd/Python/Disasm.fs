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
  | PyAscii str | PySurrogateText(str, _)
  | PyShortAscii str | PyShortAsciiInterned str ->
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
  (* Rendered the way CPython's own repr does, so `load_const` of a frozenset
     reads the same on both sides. Without this the renderer threw part-way
     through the operand, taking the rest of the code object with it. *)
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
    System.Text.Encoding.ASCII.GetString s

/// Renders a value the way CPython's `repr` does, which is what `dis` shows
/// for a *constant*. This is not the same as toStringPyObj above, which
/// renders a *name*: a string constant carries quotes and a tuple carries its
/// parentheses -- including the trailing comma that tells a one-element tuple
/// apart from a parenthesised value -- whereas a name carries neither. Only
/// the operand's own opcode says which of the two it is, so the version's
/// module chooses; see buildOperand in each Python3XX/Disasm.fs.
/// Escapes a string the way Python's own repr does: control characters are
/// spelled rather than emitted, and the quote is single unless that would
/// need escaping while a double quote would not -- which is the rule CPython
/// applies, so following it keeps the two renderings comparable without
/// having to know which quote it picked.
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

/// `lone` holds the positions the marshal reader saw a surrogate arrive on
/// its own, which is the one thing the decoded string can no longer be asked.
let private pyStrRepr (lone: Set<int>) (s: string) =
  let quote = if s.Contains "'" && not (s.Contains "\"") then '"' else '\''
  let sb = System.Text.StringBuilder()
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
      not (lone.Contains i) && System.Char.IsHighSurrogate s[i]
      && i + 1 < s.Length && System.Char.IsLowSurrogate s[i + 1]
    let cp = if paired then System.Char.ConvertToUtf32(s[i], s[i + 1])
             else int s[i]
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
    | _ when not (isPrintable cat cp) ->
      sb.Append(escapeCodePoint cp) |> ignore
    | _ ->
      sb.Append(s.Substring(i, if paired then 2 else 1)) |> ignore
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
  let sb = System.Text.StringBuilder()
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
  if digits[n] < '5' then digits.Substring(0, n), 0
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
    if carry then "1" + System.String(arr[0..n - 2]), 1
    else System.String arr, 0

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
    if n >= all.Length then all.TrimEnd '0', decpt
    else
      let digits, shift = roundTo all n
      let s = "0." + digits + "E" + string (decpt + shift)
      if System.Double.Parse(s, NumberStyles.Float, inv) = abs f then
        digits.TrimEnd '0', decpt + shift
      else search (n + 1)
  search 1

/// The float spelling repr uses inside a complex, which unlike a bare float
/// does not gain a trailing `.0` -- `complex(3, 0)` reads `(3+0j)`. Turns to
/// the exponent by where the point falls rather than by magnitude, which is
/// the rule CPython applies and not the one .NET does.
let private complexPart (f: double) =
  if System.Double.IsNaN f then "nan"
  elif System.Double.IsPositiveInfinity f then "inf"
  elif System.Double.IsNegativeInfinity f then "-inf"
  elif f = 0.0 then if System.Double.IsNegative f then "-0" else "0"
  else
    let sign = if System.Double.IsNegative f then "-" else ""
    let digits, decpt = shortestDigits f
    if decpt <= -4 || decpt > 16 then
      let tail = digits.Substring 1
      let body =
        if tail = "" then digits else digits.Substring(0, 1) + "." + tail
      sign + body + (decpt - 1).ToString("'e'+00;'e'-00")
    elif decpt <= 0 then
      sign + "0." + System.String('0', -decpt) + digits
    elif decpt >= digits.Length then
      sign + digits + System.String('0', decpt - digits.Length)
    else
      sign + digits.Substring(0, decpt) + "." + digits.Substring decpt

/// And for a float on its own, where a whole number keeps the trailing `.0`
/// that tells it from an int.
let private pyFloatRepr (f: double) =
  let s = complexPart f
  if s |> Seq.exists (fun c -> c = '.' || c = 'e' || c = 'n') then s
  else s + ".0"

/// repr for a complex. A real part of positive zero is dropped along with the
/// parentheses, which is how CPython spells a pure imaginary (`2j`), and the
/// sign between the parts comes from the imaginary part's own sign bit, so
/// negative zero still reads as `-0j`.
let private pyComplexRepr (real: double) (imag: double) =
  if real = 0.0 && not (System.Double.IsNegative real) then
    complexPart imag + "j"
  else
    let sign = if System.Double.IsNegative imag then "-" else "+"
    "(" + complexPart real + sign + complexPart (abs imag) + "j)"

let rec reprPyObj obj =
  match obj with
  | PyAscii s | PyShortAscii s | PyShortAsciiInterned s ->
    pyStrRepr Set.empty s
  | PySurrogateText(s, lone) ->
    pyStrRepr (Set.ofArray lone) s
  | PyString bs ->
    pyBytesRepr bs
  | PyBinaryFloat f ->
    pyFloatRepr f
  | PyBinaryComplex(real, imag) ->
    pyComplexRepr real imag
  (* `...` is how the ellipsis is written in source; repr names the object. *)
  | PyEllipsis ->
    "Ellipsis"
  | PyREF(_, o) ->
    reprPyObj o
  | PyTuple [||] ->
    "()"
  | PyTuple [| single |] ->
    "(" + reprPyObj single + ",)"
  | PyTuple t ->
    "(" + (t |> Array.map reprPyObj |> String.concat ", ") + ")"
  | PyFrozenSet [||] ->
    "frozenset()"
  | PyFrozenSet items ->
    let items = items |> Array.map reprPyObj |> String.concat ", "
    "frozenset({" + items + "})"
  | o ->
    toStringPyObj o

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

/// Joins an operand to the flag bits its opcode packs alongside the index.
/// Both the word and the side it goes on belong to the version -- the same
/// bit means different things across them, and CPython printed the flag
/// ahead of the name up to 3.12 and after it from 3.13 -- so the version
/// passes them in and only the joining is shared.
let withFlag precedes (flag: string) (name: string) =
  if flag = "" then name
  elif precedes then flag + " + " + name
  else name + " + " + flag

/// Renders one instruction with the version supplying the operand text.
/// Needed because some arguments index no table the code object carries --
/// a comparison operator, a flag set -- so only the version knows how to
/// spell them, and because whether a resolved value is a constant or a name
/// likewise follows from the opcode. `None` means "nothing to add beyond the
/// raw argument".
let disasmWithOperand (ins: Instruction) mnemonic operand builder =
  let builder = (builder: IDisasmBuilder)
  builder.AccumulateAddrMarker ins.Address
  builder.Accumulate(AsmWordKind.Mnemonic, mnemonic)
  match ins.Operands with
  | NoOperand
  | TwoOperands _ ->
    ()
  | OneOperand(idx, _) ->
    builder.Accumulate(AsmWordKind.String, "\t\t")
    builder.Accumulate(AsmWordKind.Value, string idx)
    match operand with
    | Some text ->
      builder.Accumulate(AsmWordKind.String, " (")
      builder.Accumulate(AsmWordKind.Value, text)
      builder.Accumulate(AsmWordKind.String, ")")
    | None ->
      ()
