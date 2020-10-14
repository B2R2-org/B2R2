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

open B2R2
open B2R2.FrontEnd.BinLifter

let getThumbBytes (reader: BinReader) pos =
  let struct (b, nextPos) = reader.ReadUInt16 pos
  match b >>> 11 with
  | 0x1dus | 0x1eus | 0x1fus ->
    let struct (b2, nextPos) = reader.ReadUInt16 nextPos
    struct (((uint32 b2) <<< 16) + (uint32 b), nextPos)
  | _ -> struct (uint32 b, nextPos)

let isARMv7 = function
  | Arch.ARMv7 -> true
  | _ -> false

let isARMv8 = function
  | Arch.AARCH32 -> true
  | _ -> false

let parseThumb ctxt bin = function
  | 2u -> Parserv7.parseV7Thumb16 ctxt bin
  | 4u -> Parserv7.parseV7Thumb32 ctxt bin
  | _ -> failwith "Invalid instruction length"

let computeContext opcode ctxt =
  match opcode with
  | Op.BLX -> struct (ParsingContext.ARMSwitchOperationMode ctxt, Some ctxt)
  | _ -> struct (ctxt, None)

let parse reader (ctxt: ParsingContext) arch addr pos =
  let mode = ctxt.ArchOperationMode
  let struct (bin, nextPos) =
    match mode with
    | ArchOperationMode.ThumbMode -> getThumbBytes reader pos
    | ArchOperationMode.ARMMode -> reader.ReadUInt32 pos
    | _-> raise InvalidTargetArchModeException
  let len = nextPos - pos |> uint32
  let opcode, cond, itState, wback, qualifier, simdt, oprs, cflag, ctxt =
    match ctxt.ArchOperationMode with
    | ArchOperationMode.ARMMode ->
      if isARMv7 arch then Parserv7.parseV7ARM ctxt bin
      else Parserv8.parseV8A32ARM ctxt bin // XXX
    | ArchOperationMode.ThumbMode ->
      if isARMv7 arch then parseThumb ctxt bin len
      else raise UnallocatedException
    | _ -> raise InvalidTargetArchModeException
  let insInfo =
    { Address = addr
      NumBytes = len
      Condition  = cond
      Opcode = opcode
      Operands = oprs
      ITState = itState
      WriteBack = wback
      Qualifier = qualifier
      SIMDTyp = simdt
      Mode = mode
      Cflag = cflag }
  let struct (ctxt, aux) = computeContext opcode ctxt
  ARM32Instruction (addr, len, insInfo, ctxt, aux)

// vim: set tw=80 sts=2 sw=2:
