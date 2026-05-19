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

[<RequireQualifiedAccess>]
module B2R2.RearEnd.BinExplore.GUI.StringUtils

open System

/// Splits the input string `s` into segments based on occurrences of the
/// `query` string.
let splitByMatch (query: string) (s: string) =
  let rec loop start acc =
    let idx = s.IndexOf(query, start, StringComparison.OrdinalIgnoreCase)
    if idx < 0 then
      if start < s.Length then List.rev ((false, s.Substring start) :: acc)
      else List.rev acc
    else
      let acc =
        if idx > start then (false, s.Substring(start, idx - start)) :: acc
        else acc
      loop (idx + query.Length) ((true, s.Substring(idx, query.Length)) :: acc)
  if String.IsNullOrEmpty query then [ false, s ]
  else loop 0 []
