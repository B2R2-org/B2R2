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

/// Turns one line of Python disassembly back into the bytes it was written
/// from. The syntax read here is the one B2R2's own Python disassembler
/// writes, so a line of its output can be handed straight back.
module B2R2.Assembly.Python.Encoder

open System

/// One statement, as the syntax has it: a name, and the number beside it when
/// the instruction takes one.
type Statement =
  { Mnemonic: string
    Oparg: int option }

/// Reads one line. Three things beside the instruction may be there, and all
/// three are dropped: the address the disassembler marks a line with, the
/// parenthesised note it prints beside an argument, and a comment. The note is
/// dropped because it is not input -- it names an entry in a code object that
/// no single line carries, so the argument itself is the whole of what a line
/// says.
let parseLine (line: string) =
  let line =
    match line.IndexOf ';' with
    | -1 -> line
    | i -> line.Substring(0, i)
  let line =
    match line.IndexOf '(' with
    | -1 -> line
    | i -> line.Substring(0, i)
  let line =
    match line.IndexOf ':' with
    | -1 -> line
    | i -> line.Substring(i + 1)
  match line.Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries) with
  | [||] -> Ok None
  | [| name |] -> Ok(Some { Mnemonic = name; Oparg = None })
  | [| name; arg |] ->
    match Int32.TryParse arg with
    | true, n when n >= 0 -> Ok(Some { Mnemonic = name; Oparg = Some n })
    | _ -> Error $"'{arg}' is not an argument"
  | parts ->
    let text = String.concat " " parts
    Error $"too many words on '{text}'"

/// The bytes above the one the instruction itself carries, most significant
/// first, each of which needs an EXTENDED_ARG of its own to reach the
/// instruction. An argument that fits needs none.
let private prefixBytes width arg =
  let rec go acc n =
    if n = 0 then acc
    else go (byte (n &&& 0xFF) :: acc) (n >>> 8)
  go [] (arg >>> width) |> List.toArray

/// Encodes one statement, or says why it cannot be.
let encode (spec: VersionSpec) stmt =
  match spec.Lookup stmt.Mnemonic with
  | None -> Error $"unknown instruction '{stmt.Mnemonic}'"
  | Some op ->
    let takesArg = spec.HasOperand op
    match stmt.Oparg with
    | Some _ when not takesArg ->
      Error $"'{stmt.Mnemonic}' takes no argument"
    | None when takesArg ->
      Error $"'{stmt.Mnemonic}' needs an argument"
    | oparg ->
      let arg = defaultArg oparg 0
      (* Before wordcode an instruction with an argument spent two bytes on
         it, so EXTENDED_ARG carried two as well; from 3.6 every instruction
         is two bytes wide and each prefix carries one. *)
      let width = if spec.IsWordcode then 8 else 16
      let ext = byte spec.ExtendedArg
      let prefix =
        prefixBytes width arg
        |> Array.collect (fun b ->
          if spec.IsWordcode then [| ext; b |] else [| ext; b; 0uy |])
      let body =
        if spec.IsWordcode then [| byte op; byte (arg &&& 0xFF) |]
        elif takesArg then
          [| byte op; byte (arg &&& 0xFF); byte ((arg >>> 8) &&& 0xFF) |]
        else [| byte op |]
      (* The decoder counts an instruction's inline caches into its length, so
         bytes that stop short of them are not the instruction it read. *)
      let caches = Array.zeroCreate (2 * spec.CacheCount op)
      Ok(Array.concat [ prefix; body; caches ])

/// Encodes a whole source, one byte array per instruction.
let encodeAll spec (source: string) =
  let rec go acc = function
    | [] -> Ok(List.rev acc)
    | (line: string) :: rest ->
      match parseLine line with
      | Error e -> Error e
      | Ok None -> go acc rest
      | Ok(Some stmt) ->
        match encode spec stmt with
        | Error e -> Error e
        | Ok bytes -> go (bytes :: acc) rest
  source.Split '\n'
  |> Array.toList
  |> List.map (fun l -> l.TrimEnd '\r')
  |> go []
