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

namespace B2R2.FrontEnd.Python

open System
open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.Python
open B2R2.FrontEnd.BinLifter

/// <summary>
/// What decoding asks of a version, and nothing else. The loop that reads a
/// byte, folds the EXTENDED_ARG prefixes ahead of it and measures how far to
/// advance is the same on every version there is; only these answers differ,
/// so only these live in a version's own directory.
/// </summary>
type ParseSpec =
  { /// Which of the code object's tables the opcode indexes, keyed by the
    /// address so that each code object reads against its own. An opcode
    /// whose argument is a number rather than an index has no table.
    Table: PythonBinFile -> int -> (AddrRange * PyObject[])[]
    /// The entry an argument names, given the table it names it in. Not
    /// always the argument itself: several opcodes pack flag bits below the
    /// index, and a few name two entries at once.
    Resolve: int -> PyObject[] -> int -> Operands
    /// Whether the opcode takes an argument at all.
    HasOperand: int -> bool
    /// How far to advance past it, inline caches included.
    Length: int -> uint32
    /// Whether the byte names an instruction of this version.
    IsDefined: int -> bool
    /// EXTENDED_ARG's own number, which prefixes a wide argument.
    ExtendedArg: int
    /// Whether an instruction is two bytes wide. 3.6 replaced the older
    /// encoding, where an instruction with an argument was three bytes and a
    /// prefix carried two of them, with wordcode.
    IsWordcode: bool }

/// The decode loop, which is the same for every version B2R2 reads.
module internal ParsingHelpers =

  /// Reads the argument an instruction carries and looks up what it names.
  /// The argument is one byte under wordcode and two before it -- the same
  /// width the EXTENDED_ARG prefix carries, and reading the wrong one takes
  /// the high half of the argument from whatever follows the instruction.
  let private parseOperand spec opcode (span: ByteSpan) (reader: IBinReader)
                           binFile addr extArg =
    let raw =
      if spec.IsWordcode then reader.ReadUInt8(span, 1) |> int
      else reader.ReadUInt16(span, 1) |> int
    let idx = raw ||| extArg
    let table = spec.Table binFile opcode
    match table |> Array.tryFind (fun (r, _) -> r.Min <= addr && r.Max >= addr)
      with
    | Some(_, entries) -> spec.Resolve opcode entries idx
    (* No table covers this address, which happens when a linear sweep walks
       off a code object, and for every opcode whose argument is a number
       rather than an index -- the raw argument is then the whole answer. *)
    | None -> OneOperand(idx, None)

  (* The byte IS the opcode: each version's Opcode enum carries CPython's own
     numbering, so decoding is a cast, and the encoded length comes from
     CPython's inline-cache table rather than a hand-maintained size per case.
     That is what the 200-line byte->opcode match here used to do by hand. *)
  let rec private doParse spec semantics (span: ByteSpan) (reader: IBinReader)
                          (bf: PythonBinFile) s c e =
    let b = reader.ReadUInt8(span, 0) |> int
    if b = spec.ExtendedArg then
      (* A prefix carries one byte of the argument under wordcode and two
         before it, and is as wide as the instruction it precedes. *)
      if spec.IsWordcode then
        let a = reader.ReadUInt8(span, 1) |> int
        doParse spec semantics (span.Slice 2) reader bf s (c + 2UL)
                ((e ||| a) <<< 8)
      else
        let a = reader.ReadUInt16(span, 1) |> int
        doParse spec semantics (span.Slice 3) reader bf s (c + 3UL)
                ((e ||| a) <<< 16)
    else
      if not (spec.IsDefined b) then raise ParsingFailureException else ()
      let opr =
        if spec.HasOperand b then
          parseOperand spec b span reader bf c e
        else NoOperand
      let total = uint32 (c - s) + spec.Length b
      Instruction(s, total, b, opr, OperationSize.RegType, bf.Version, bf,
                  semantics)

  /// Decodes the instruction at the given address.
  let parse spec semantics (span: ByteSpan) reader binFile addr =
    doParse spec semantics span reader binFile addr addr 0
