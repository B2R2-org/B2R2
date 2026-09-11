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

/// <summary>
/// The encoding facts of every CIL instruction, taken from the decoder itself
/// rather than written out beside it: every candidate opcode is handed to
/// B2R2's own CIL parser with a run of zero bytes behind it, and what comes
/// back says what the instruction is called, what it takes and how wide that
/// is. So the assembler and the decoder cannot come to disagree about which
/// bytes an instruction is -- there is only the one table, and this reads it.
/// </summary>
module B2R2.Assembly.CIL.Tables

open System.Collections.Generic
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.CIL

/// The bytes a probe is padded out with. They are zero so that a switch reads
/// a count of nothing and stays inside its padding; there are more of them
/// than the widest operand there is.
let private filler = Array.zeroCreate 16

/// Every opcode a probe is made for: the one-byte space less the prefix byte,
/// which names whatever follows it rather than an instruction of its own, and
/// the space behind that byte.
let private candidates =
  [ for b in List.except [ 0xfe ] [ 0 .. 0xff ] do
      yield [| byte b |]
    for sub in 0 .. 0xff do
      yield [| 0xfeuy; byte sub |] ]

/// Decodes one candidate, padded out, or says nothing when it names no
/// instruction.
let private probe (parser: IInstructionParsable) (code: byte[]) =
  try
    match parser.Parse(Array.append code filler, 0UL) with
    | :? Instruction as ins -> Some ins
    | _ -> None
  with _ ->
    None

/// How the operand of one decoded instruction is laid out. Its width is
/// whatever of the instruction the opcode bytes do not account for.
let private shapeOf (code: byte[]) (ins: Instruction) =
  let width = int ins.Length - code.Length
  match ins.Operands with
  | NoOperand -> Bare
  | OneOperand(OprVar _) -> Fixed(VarKind, width)
  | OneOperand(OprI4 _) -> Fixed(I4Kind, width)
  | OneOperand(OprI8 _) -> Fixed(I8Kind, width)
  | OneOperand(OprR4 _) -> Fixed(R4Kind, width)
  | OneOperand(OprR8 _) -> Fixed(R8Kind, width)
  | OneOperand(OprTarget _) -> Fixed(TargetKind, width)
  | OneOperand(OprToken _) -> Fixed(TokenKind, width)
  | OneOperand(OprByte _) -> Fixed(ByteKind, width)
  | OneOperand(OprTargets _) -> Table

/// The name the disassembler writes an instruction with, which is the first
/// word of what it writes.
let private mnemonicOf (ins: Instruction) =
  let text = (ins :> IInstruction).Disasm()
  match text.IndexOf ' ' with
  | -1 -> text
  | i -> text.Substring(0, i)

/// Walks the whole candidate space and writes down what the decoder made of
/// each one. No two instructions share a name, so a name finds one encoding.
let private build () =
  let parser = CILParser(BinReader.Init Endian.Little) :> IInstructionParsable
  let dict = Dictionary<string, Encoding>()
  for code in candidates do
    match probe parser code with
    | None ->
      ()
    | Some ins ->
      dict[mnemonicOf ins] <- { Code = code; Shape = shapeOf code ins }
  dict

/// The table, built once for the process rather than once per assembler.
let private table = lazy (build ())

/// The instruction the given mnemonic names, or nothing when there is none.
let lookup (name: string) =
  match table.Force().TryGetValue name with
  | true, encoding -> Some encoding
  | _ -> None

// vim: set tw=80 sts=2 sw=2:
