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

module B2R2.FrontEnd.BinLifter.ARM32.Parser

open System
open B2R2

let getThumbBytes (span: ByteSpan) (reader: IBinReader) =
  let b = reader.ReadUInt16 (span, 0)
  match b >>> 11 with
  | 0x1dus | 0x1eus | 0x1fus ->
    let b2 = reader.ReadUInt16 (span, 2)
    struct (((uint32 b2) <<< 16) + (uint32 b), 4u)
  | _ -> struct (uint32 b, 2u)

let isARMv7 = function
  | Arch.ARMv7 -> true
  | _ -> false

let isARMv8 = function
  | Arch.AARCH32 -> true
  | _ -> false

let parseThumb (itstate: byref<byte list>) bin = function
  | 2u -> Parserv7.parseV7Thumb16 &itstate bin
  | 4u -> Parserv7.parseV7Thumb32 &itstate bin
  | _ -> failwith "Invalid instruction length"

let newInsInfo addr len mode op cond itState wback q simdt oprs cflag =
  let insInfo =
    { Address = addr
      NumBytes = len
      Condition  = cond
      Opcode = op
      Operands = oprs
      ITState = itState
      WriteBack = wback
      Qualifier = q
      SIMDTyp = simdt
      Mode = mode
      Cflag = cflag }
  ARM32Instruction (addr, len, insInfo)

let parse span reader mode (it: byref<byte list>) arch addr =
  let struct (bin, len) =
    match mode with
    | ArchOperationMode.ThumbMode -> getThumbBytes span reader
    | ArchOperationMode.ARMMode -> struct (reader.ReadUInt32 (span, 0), 4u)
    | _-> raise InvalidTargetArchModeException
  match mode with
  | ArchOperationMode.ARMMode ->
    Parserv8.parseV8A32ARM mode addr bin len
  | ArchOperationMode.ThumbMode ->
    if isARMv7 arch then
      let op, cond, itState, wback, q, simdt, oprs, cflag =
        parseThumb &it bin len
      let wback = match wback with | Some true -> true | _ -> false (* xxx *)
      let q = match q with | Some W -> W | _ -> N (* xxx *)
      newInsInfo addr len mode op cond itState wback q simdt oprs cflag
    else raise UnallocatedException
  | _ -> raise InvalidTargetArchModeException

// vim: set tw=80 sts=2 sw=2:
