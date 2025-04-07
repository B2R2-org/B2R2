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

module internal B2R2.FrontEnd.S390.ParsingMain

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.S390.ParsingFormats
open B2R2.FrontEnd.S390.Helper

/// One-Halfword (2 bytes) Sized Instructions
let parseFmt1 (span: ByteSpan) (reader: IBinReader) wordSize state =
  let bin = reader.ReadUInt16 (span, 0)
  let functions = [| parseE; parseI; parseRR; |]
  let oper =
    functions
    |> Array.Parallel.map (fun f -> f bin state)
    |> Array.tryFind (fun struct (opcode, operand, fmt) -> opcode <> Op.InvalOp)
  match oper with
  | Some value -> value
  | None -> raise ParsingFailureException

/// Two-Halfword (4 bytes) Sized Instructions: RX format
let parseFmt2 (span: ByteSpan) (reader: IBinReader) wordSize state =
  let bin = reader.ReadUInt32 (span, 0)
  let oper = parseRX bin state
  let struct (opcode, _, _) = oper
  if opcode = Op.InvalOp then raise ParsingFailureException
  else oper

/// Two-Halfword (4 bytes) Sized Instructions
let parseFmt3 (span: ByteSpan) (reader: IBinReader) wordSize state =
  let bin = reader.ReadUInt32 (span, 0)
  let functions = [|
    parseRI; parseRRD; parseRRE; parseRRF;
    parseRS; parseRSI; parseRX; parseS;
    parseSI; parseIE |]
  let oper =
    functions
    |> Array.Parallel.map (fun f -> f bin state)
    |> Array.tryFind (fun struct (opcode, operand, fmt) -> opcode <> Op.InvalOp)
  match oper with
  | Some value -> value
  | None -> raise ParsingFailureException

/// Three-Halfword (6 bytes) Sized Instructions
let parseFmt4 (span: ByteSpan) reader wordSize state =
  let bytes = span.Slice(0, 6).ToArray ()
  let bin = BitVector.OfArr (Array.rev bytes) |> BitVector.ToUInt64
  let functions = [|
    parseMII; parseRIE; parseRIL; parseRIS;
    parseRRS; parseRSL; parseRSY; parseRXE;
    parseRXY; parseRXF; parseSIL; parseSIY;
    parseSMI; parseSS; parseSSE; parseSSF;
    parseVRI; parseVRR; parseVRS; parseVRV;
    parseVRX; parseVSI |]
  let oper =
    functions
    |> Array.Parallel.map (fun f -> f bin state)
    |> Array.tryFind (fun struct (opcode, operand, fmt) -> opcode <> Op.InvalOp)
  match oper with
  | Some value -> value
  | None -> raise ParsingFailureException

let parseByFmt span reader bin wordSize state =
  match extract16 bin 0 1 with
  | 0b00us -> (parseFmt1 span reader wordSize state, 2u)
  | 0b01us -> (parseFmt2 span reader wordSize state, 4u)
  | 0b10us -> (parseFmt3 span reader wordSize state, 4u)
  | 0b11us -> (parseFmt4 span reader wordSize state, 6u)
  | _ -> Terminator.impossible ()

let parse (span: ByteSpan) (reader: IBinReader) arch wordSize addr state =
  let bin = reader.ReadUInt16 (span, 0)

  let struct (opcode, operand, fmt), numBytes =
    parseByFmt span reader bin wordSize state
  let insInfo: InsInfo = {
    Address = addr
    NumBytes = numBytes
    Fmt = fmt
    Opcode = opcode
    Operands = operand
    Arch = arch
  }

  S390Instruction (addr, numBytes, insInfo, wordSize)

// vim: set tw=80 sts=2 sw=2: