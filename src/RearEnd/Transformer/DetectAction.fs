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
open System.Collections.Generic
open System.IO
open System.Threading
open B2R2

/// The `detect` action.
type DetectAction() =
  let resultToString (path: string, matchRate: float) =
    ColoredString(NoColor, $"{path}: {matchRate:F}")
    |> OutputColored
    |> box

  let detectFile (ct: CancellationToken) fp path =
    ct.ThrowIfCancellationRequested()
    let bs = File.ReadAllBytes path
    let span = ReadOnlySpan bs
    let ngramCount = span.Length - fp.NGramSize + 1
    let ngrams = HashSet<int>(ngramCount)
    for index = 0 to ngramCount - 1 do
      ct.ThrowIfCancellationRequested()
      ngrams.Add(Utils.hashNgram span index fp.NGramSize) |> ignore
    let matchCnt =
      fp.Patterns
      |> List.fold (fun cnt pattern ->
        let hash, _ = pattern
        if ngrams.Contains hash then cnt + 1 else cnt) 0
    path, float matchCnt / float fp.Patterns.Length

  let detectDir ct fp path =
    Directory.GetFiles path
    |> Array.map (detectFile ct fp)
    |> Array.sortByDescending snd
    |> Array.map resultToString
    |> box

  let detect ct path input =
    let fp = unbox<Fingerprint> input
    if File.Exists path then
      detectFile ct fp path |> resultToString
    elif Directory.Exists path then
      detectDir ct fp path
    else
      invalidArg (nameof path) "File not found."

  let transform ct args collection =
    match args with
    | [ path ] ->
      { Values =
          collection.Values
          |> Array.map (detect ct path) }
    | [] ->
      invalidArg (nameof args) "A path should be given."
    | _ ->
      invalidArg (nameof args) "Too many paths are given."

  interface IAction with
    member _.ActionID with get() = "detect"
    member _.Signature with get() =
      "Fingerprint -> detect path=<path> -> OutString"
    member _.Description with get() =
      """
    Take in a fingerprint and a path as input, and analyze file(s) in the given
    path to detect the fingerprint. This action will eventually return a match
    score as output. If path is a directory, it analyzes every file in the
    directory. If path is a file, it only analyzes the file.
"""
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, ct) =
      transform ct args collection
