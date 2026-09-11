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
/// The encoding facts of every WASM instruction, taken from the decoder
/// itself rather than written out beside it: every candidate opcode is handed
/// to B2R2's own WASM parser with a run of zero bytes behind it, and what
/// comes back says both what the instruction is called and what it takes. So
/// the assembler and the decoder cannot come to disagree about which bytes an
/// instruction is -- there is only the one table, and this reads it.
///
/// What a probe cannot say is the handful of choices that belong to writing
/// rather than to reading: that a block written without a type yields
/// nothing, that a bare select is the one-byte form, and that a number is
/// written in as few bytes as it needs. Those live in Encoder.
/// </summary>
module B2R2.Assembly.WASM.Tables

open System.Collections.Generic
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.WASM

/// <summary>
/// The bytes a probe is padded out with.
///
/// They are zero so that every count a probe runs into is zero as well: a
/// br_table reading its count out of them reads no labels at all, and a
/// memarg reading its alignment out of them finds the flag bit clear. Both
/// keep the probe inside its padding, which a count read out of anything else
/// would not. There are as many of them as the widest operand there is.
/// </summary>
let private filler = Array.zeroCreate 32

/// <summary>
/// The last SIMD opcode a probe is made for.
///
/// That space is encoded as a LEB128 u32 rather than as a byte, so it has no
/// end of its own to stop at. The decoder currently reaches 0x113, and this
/// leaves room for a good many more before one would fall outside the table.
/// </summary>
let [<Literal>] private SimdLimit = 0x3ff

/// <summary>
/// Every opcode a probe is made for: the one-byte space, the two prefixed
/// spaces whose opcode is a byte, and the SIMD space, whose opcode is a
/// LEB128 u32 and so is written out rather than taken as one.
///
/// The three prefix bytes are left out of the one-byte space, since what they
/// name is whatever follows them rather than an instruction of their own.
/// </summary>
let private prefixes = [ 0xfc; 0xfd; 0xfe ]

let private candidates =
  [ for b in List.except prefixes [ 0 .. 0xff ] do
      yield [| byte b |]
    for sub in 0 .. 0xff do
      yield [| 0xfcuy; byte sub |]
      yield [| 0xfeuy; byte sub |]
    for sub in 0 .. SimdLimit do
      yield Array.append [| 0xfduy |] (LEB128.encodeUInt32 (uint32 sub)) ]

/// Decodes one candidate, padded out, or says nothing when it names no
/// instruction.
let private probe (parser: IInstructionParsable) (code: byte[]) =
  try
    match parser.Parse(Array.append code filler, 0UL) with
    | :? Instruction as ins -> Some ins
    | _ -> None
  with _ ->
    None

/// The kind of one decoded operand.
let private kindOf = function
  | Index _ -> IndexKind
  | I32 _ -> I32Kind
  | I64 _ -> I64Kind
  | F32 _ -> F32Kind
  | F64 _ -> F64Kind
  | V128 _ -> V128Kind
  | Type _ -> TypeKind
  | RefType _ -> RefTypeKind
  | Alignment _ -> AlignmentKind
  | Address _ -> AddressKind
  | LaneIndex _ -> LaneKind
  | ConsistencyModel _ -> ConsistencyKind

/// The operands of one decoded instruction, however many of them there are.
let private operandsOf = function
  | NoOperand -> []
  | OneOperand opr -> [ opr ]
  | TwoOperands(opr1, opr2) -> [ opr1; opr2 ]
  | ThreeOperands(opr1, opr2, opr3) -> [ opr1; opr2; opr3 ]
  | Operands oprs -> oprs

/// <summary>
/// How the operands of one decoded instruction are laid out.
///
/// A memarg is told by the alignment in it, which nothing else carries. The
/// two whose length is a count in the stream are told by name instead: what a
/// probe hands back says how many that probe happened to hold rather than how
/// many the instruction takes, so there is nothing in it to read them off.
/// </summary>
let private shapeOf (ins: Instruction) =
  let kinds = operandsOf ins.Operands |> List.map kindOf
  match ins.Opcode with
  | BrTable ->
    LabelTable
  | SelectT ->
    TypeVector
  | _ ->
    if List.contains AlignmentKind kinds then
      if List.last kinds = LaneKind then MemArgLane else MemArg
    else
      Fixed kinds

/// The name the disassembler writes an instruction with, which is the first
/// word of what it writes.
let private mnemonicOf (ins: Instruction) =
  let text = (ins :> IInstruction).Disasm()
  match text.IndexOf ' ' with
  | -1 -> text
  | i -> text.Substring(0, i)

/// Adds one encoding under the name it is written with, keeping the order the
/// candidates were tried in, so that where two of them share a name the
/// narrower comes first.
let private add (dict: Dictionary<_, _>) name encoding =
  match dict.TryGetValue name with
  | true, encodings -> dict[name] <- encodings @ [ encoding ]
  | _ -> dict[name] <- [ encoding ]

/// Walks the whole candidate space and writes down what the decoder made of
/// each one.
let private build () =
  let parser = WASMParser(BinReader.Init Endian.Little) :> IInstructionParsable
  let dict = Dictionary<string, Encoding list>()
  for code in candidates do
    match probe parser code with
    | None -> ()
    | Some ins -> add dict (mnemonicOf ins) { Code = code; Shape = shapeOf ins }
  dict

/// The table, built once for the process rather than once per assembler.
let private table = lazy (build ())

/// The instructions the given mnemonic names, narrowest first.
let lookup (name: string) =
  match table.Force().TryGetValue name with
  | true, encodings -> encodings
  | _ -> []

// vim: set tw=80 sts=2 sw=2:
