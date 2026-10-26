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
open System.Numerics
open System.Security.Cryptography
open System.Threading

module internal IntegerParsing =
  let tryParse (text: string) =
    let text = text.Trim()
    let negative = text.StartsWith("-", StringComparison.Ordinal)
    let digits = if negative then text[1..] else text
    if digits.StartsWith("0x", StringComparison.OrdinalIgnoreCase) then
      let hex = digits[2..]
      if String.IsNullOrEmpty hex then
        None
      else
        match BigInteger.TryParse(
                "0" + hex,
                NumberStyles.AllowHexSpecifier,
                CultureInfo.InvariantCulture
              ) with
        | true, number ->
          Some(if negative then -number else number)
        | _ ->
          None
    else
      match BigInteger.TryParse(
              text,
              NumberStyles.Integer,
              CultureInfo.InvariantCulture
            ) with
      | true, number ->
        Some number
      | _ ->
        None

  let parse text =
    tryParse text
    |> Option.defaultWith (fun () ->
      invalidArg (nameof text) $"Invalid integer: {text}")

  let sample minimum maximum =
    if minimum >= maximum then
      invalidArg (nameof maximum) "max must be greater than min."
    else
      let span = maximum - minimum
      let bytes =
        (span - BigInteger.One).ToByteArray(
          isUnsigned = true, isBigEndian = true
        )
      let highest = int bytes[0]
      let mutable mask = 0
      let mutable bit = 1
      while bit <= highest do
        mask <- mask ||| bit
        bit <- bit <<< 1
      let rec draw () =
        RandomNumberGenerator.Fill bytes
        bytes[0] <- bytes[0] &&& byte mask
        let value = BigInteger(ReadOnlySpan<byte>(bytes), true, true)
        if value < span then minimum + value else draw ()
      draw ()

/// Produce an integer in the half-open range [min, max).
type RandomAction() =
  let transform (ct: CancellationToken) args =
    match args with
    | [ minimum; maximum ] ->
      let minimum = IntegerParsing.parse minimum
      let maximum = IntegerParsing.parse maximum
      ct.ThrowIfCancellationRequested()
      { Values = [| IntegerParsing.sample minimum maximum |> box |] }
    | _ ->
      invalidArg (nameof args) "Expected: random min=<int> max=<int>."

  interface IAction with
    member _.ActionID with get() = "random"
    member _.Signature with get() =
      "Unit -> random min=<int> max=<int> -> Int"
    member _.Description with get() =
      "Return an integer in the half-open range [min, max)."
    member _.Transform(args, _collection) =
      transform CancellationToken.None args

  interface ICancellableAction with
    member _.Transform(args, _collection, ct) =
      transform ct args
