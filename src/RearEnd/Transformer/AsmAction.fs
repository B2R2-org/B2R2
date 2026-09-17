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

namespace B2R2.RearEnd.Transformer

open System
open System.Globalization
open System.Text.RegularExpressions
open System.Threading
open B2R2
open B2R2.Assembly

/// The `asm` action.
type AsmAction() =
  let parseUInt64 (value: string) =
    let style, value =
      if value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) then
        NumberStyles.HexNumber, value[2..]
      else
        NumberStyles.Integer, value
    UInt64.Parse(value, style, CultureInfo.InvariantCulture)

  let tryParseISA (name: string) =
    try Some(ISA name) with _ -> None

  let defaultISA = ISA(Architecture.Intel, WordSize.Bit64)

  let parseArgs (args: string list) =
    match args with
    | [ code ] -> code, defaultISA, 0UL
    | [ code; second ] ->
      match tryParseISA second with
      | Some isa -> code, isa, 0UL
      | None -> code, defaultISA, parseUInt64 second
    | [ code; isaName; baseAddress ] ->
      match tryParseISA isaName with
      | Some isa -> code, isa, parseUInt64 baseAddress
      | None -> invalidArg (nameof isaName) "Invalid ISA."
    | _ -> invalidArg (nameof args) "Invalid argument."

  let normalizeMemory (code: string) =
    Regex.Replace(
      code,
      @"\[\s*([^\]]*?)\s*\]",
      MatchEvaluator(fun m ->
        let inner = Regex.Replace(m.Groups[1].Value, @"\s*([+-])\s*", "$1")
        "[" + inner + "]"))

  let assemblyCandidates (code: string) =
    [ code; normalizeMemory code ]
    |> List.distinct

  let assemble (code: string) isa baseAddress =
    let asm = Assembler(isa, baseAddress)
    let rec tryAssemble errors candidates =
      match candidates with
      | [] ->
        let message = String.concat Environment.NewLine errors
        invalidArg (nameof code) message
      | candidate :: rest ->
        match asm.Lower candidate with
        | Ok lowered ->
          lowered
          |> List.collect (fun (_, bytes) -> bytes |> Array.toList)
          |> List.toArray
        | Error error -> tryAssemble (error :: errors) rest
    assemblyCandidates code
    |> tryAssemble []

  let transformOne cancellationToken args =
    let cancellationToken: CancellationToken = cancellationToken
    cancellationToken.ThrowIfCancellationRequested()
    let code, isa, baseAddress = parseArgs args
    let bytes = assemble code isa baseAddress
    { Bytes = bytes
      BaseAddress = baseAddress
      ISA = isa
      OS = OS.UnknownOS
      Annotation = code }
    |> box

  let transform cancellationToken args collection =
    if collection.Values |> Array.forall isNull then ()
    else invalidArg (nameof collection) "Invalid argument type."
    { Values = [| transformOne cancellationToken args |] }

  interface IAction with
    member _.ActionID with get() = "asm"
    member _.Signature with get() =
      "Unit -> asm code=<text> [isa=<isa>] [base=<addr>] -> ByteArray"
    member _.Description with get() =
      """
    Assemble one or more machine instructions into bytes.
"""
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection
