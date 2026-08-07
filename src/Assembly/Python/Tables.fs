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

/// The encoding facts of every Python version B2R2 reads, each read off the
/// very enum that version's parser decodes with so that the assembler and the
/// decoder cannot come to disagree about which byte an instruction is: there
/// is only the one table, and this points at it.
module B2R2.Assembly.Python.Tables

open System
open B2R2
open B2R2.Assembly.Python
open B2R2.FrontEnd.Python

/// The opcode number a mnemonic names in the given version's enum, or None
/// when that version has no such instruction.
let private lookup (t: Type) (name: string) =
  let name = name.ToUpperInvariant()
  (* Enum.TryParse takes a number for a number, so a name that is all digits
     would resolve to whatever opcode holds that value rather than failing. *)
  if name |> Seq.forall Char.IsDigit then None
  else
    match Enum.TryParse(t, name) with
    | true, v when Enum.IsDefined(t, v) -> Some(Convert.ToInt32 v)
    | _ -> None

/// How the given version encodes. Every version has an opcode enum of its own,
/// so all of them have to be named somewhere; naming them here keeps that to
/// one match rather than one file each, since nothing else about a version
/// differs.
let specOf = function
  | PythonVersion.Python300 ->
    { Lookup = lookup typeof<Python300.Opcode>
      HasOperand =
        fun n -> Python300.Opcode.hasOperand (enum<Python300.Opcode> n)
      CacheCount =
        fun _ -> 0
      IsWordcode = false
      ExtendedArg = int Python300.Opcode.EXTENDED_ARG }
  | PythonVersion.Python301 ->
    { Lookup = lookup typeof<Python301.Opcode>
      HasOperand =
        fun n -> Python301.Opcode.hasOperand (enum<Python301.Opcode> n)
      CacheCount =
        fun _ -> 0
      IsWordcode = false
      ExtendedArg = int Python301.Opcode.EXTENDED_ARG }
  | PythonVersion.Python302 ->
    { Lookup = lookup typeof<Python302.Opcode>
      HasOperand =
        fun n -> Python302.Opcode.hasOperand (enum<Python302.Opcode> n)
      CacheCount =
        fun _ -> 0
      IsWordcode = false
      ExtendedArg = int Python302.Opcode.EXTENDED_ARG }
  | PythonVersion.Python303 ->
    { Lookup = lookup typeof<Python303.Opcode>
      HasOperand =
        fun n -> Python303.Opcode.hasOperand (enum<Python303.Opcode> n)
      CacheCount =
        fun _ -> 0
      IsWordcode = false
      ExtendedArg = int Python303.Opcode.EXTENDED_ARG }
  | PythonVersion.Python304 ->
    { Lookup = lookup typeof<Python304.Opcode>
      HasOperand =
        fun n -> Python304.Opcode.hasOperand (enum<Python304.Opcode> n)
      CacheCount =
        fun _ -> 0
      IsWordcode = false
      ExtendedArg = int Python304.Opcode.EXTENDED_ARG }
  | PythonVersion.Python305 ->
    { Lookup = lookup typeof<Python305.Opcode>
      HasOperand =
        fun n -> Python305.Opcode.hasOperand (enum<Python305.Opcode> n)
      CacheCount =
        fun _ -> 0
      IsWordcode = false
      ExtendedArg = int Python305.Opcode.EXTENDED_ARG }
  | PythonVersion.Python306 ->
    { Lookup = lookup typeof<Python306.Opcode>
      HasOperand =
        fun n -> Python306.Opcode.hasOperand (enum<Python306.Opcode> n)
      CacheCount =
        fun n -> Python306.Opcode.inlineCacheCount (enum<Python306.Opcode> n)
      IsWordcode = true
      ExtendedArg = int Python306.Opcode.EXTENDED_ARG }
  | PythonVersion.Python307 ->
    { Lookup = lookup typeof<Python307.Opcode>
      HasOperand =
        fun n -> Python307.Opcode.hasOperand (enum<Python307.Opcode> n)
      CacheCount =
        fun n -> Python307.Opcode.inlineCacheCount (enum<Python307.Opcode> n)
      IsWordcode = true
      ExtendedArg = int Python307.Opcode.EXTENDED_ARG }
  | PythonVersion.Python308 ->
    { Lookup = lookup typeof<Python308.Opcode>
      HasOperand =
        fun n -> Python308.Opcode.hasOperand (enum<Python308.Opcode> n)
      CacheCount =
        fun n -> Python308.Opcode.inlineCacheCount (enum<Python308.Opcode> n)
      IsWordcode = true
      ExtendedArg = int Python308.Opcode.EXTENDED_ARG }
  | PythonVersion.Python309 ->
    { Lookup = lookup typeof<Python309.Opcode>
      HasOperand =
        fun n -> Python309.Opcode.hasOperand (enum<Python309.Opcode> n)
      CacheCount =
        fun n -> Python309.Opcode.inlineCacheCount (enum<Python309.Opcode> n)
      IsWordcode = true
      ExtendedArg = int Python309.Opcode.EXTENDED_ARG }
  | PythonVersion.Python310 ->
    { Lookup = lookup typeof<Python310.Opcode>
      HasOperand =
        fun n -> Python310.Opcode.hasOperand (enum<Python310.Opcode> n)
      CacheCount =
        fun n -> Python310.Opcode.inlineCacheCount (enum<Python310.Opcode> n)
      IsWordcode = true
      ExtendedArg = int Python310.Opcode.EXTENDED_ARG }
  | PythonVersion.Python311 ->
    { Lookup = lookup typeof<Python311.Opcode>
      HasOperand =
        fun n -> Python311.Opcode.hasOperand (enum<Python311.Opcode> n)
      CacheCount =
        fun n -> Python311.Opcode.inlineCacheCount (enum<Python311.Opcode> n)
      IsWordcode = true
      ExtendedArg = int Python311.Opcode.EXTENDED_ARG }
  | PythonVersion.Python312 ->
    { Lookup = lookup typeof<Python312.Opcode>
      HasOperand =
        fun n -> Python312.Opcode.hasOperand (enum<Python312.Opcode> n)
      CacheCount =
        fun n -> Python312.Opcode.inlineCacheCount (enum<Python312.Opcode> n)
      IsWordcode = true
      ExtendedArg = int Python312.Opcode.EXTENDED_ARG }
  | PythonVersion.Python313 ->
    { Lookup = lookup typeof<Python313.Opcode>
      HasOperand =
        fun n -> Python313.Opcode.hasOperand (enum<Python313.Opcode> n)
      CacheCount =
        fun n -> Python313.Opcode.inlineCacheCount (enum<Python313.Opcode> n)
      IsWordcode = true
      ExtendedArg = int Python313.Opcode.EXTENDED_ARG }
  | PythonVersion.Python314 ->
    { Lookup = lookup typeof<Python314.Opcode>
      HasOperand =
        fun n -> Python314.Opcode.hasOperand (enum<Python314.Opcode> n)
      CacheCount =
        fun n -> Python314.Opcode.inlineCacheCount (enum<Python314.Opcode> n)
      IsWordcode = true
      ExtendedArg = int Python314.Opcode.EXTENDED_ARG }
  | PythonVersion.Python315 ->
    { Lookup = lookup typeof<Python315.Opcode>
      HasOperand =
        fun n -> Python315.Opcode.hasOperand (enum<Python315.Opcode> n)
      CacheCount =
        fun n -> Python315.Opcode.inlineCacheCount (enum<Python315.Opcode> n)
      IsWordcode = true
      ExtendedArg = int Python315.Opcode.EXTENDED_ARG }
  | version -> failwithf "Unsupported Python version: %A" version

// vim: set tw=80 sts=2 sw=2:
