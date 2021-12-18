#!/usr/bin/env fsharpi
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

open System.Text.RegularExpressions

let split line =
  let r = new Regex("(\/\/\/ .+)?([a-zA-Z0-9]+)?\s*(\(\*.+\*\))?")
  let m = r.Match (line)
  m.Groups[1].ToString(), m.Groups[2].ToString(), m.Groups[3].ToString()

let print idx (desc, op, comment) =
  if String.length desc > 0 then printfn "  %s" desc; idx + 1
  else if String.length comment > 0 then
    printfn "  | %s = %d %s" op idx comment; idx
  else printfn "  | %s = %d" op idx; idx

let conv file =
  System.IO.File.ReadLines (file)
  |> Seq.map split
  |> Seq.fold print -1
  |> ignore

let main args =
  if Array.length args < 2 then
    printfn "Usage: %s <input opcode file>" args[0]
  else conv args[1]

fsi.CommandLineArgs |> main
