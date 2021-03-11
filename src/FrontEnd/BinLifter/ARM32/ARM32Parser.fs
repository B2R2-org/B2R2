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

let parseThumb (itstate: byref<byte list>) bin = function
  | 2u -> Parserv7.parseV7Thumb16 &itstate bin
  | 4u -> Parserv7.parseV7Thumb32 &itstate bin
  | _ -> failwith "Invalid instruction length"

let parse reader mode (it: byref<byte list>) arch addr pos =
  let struct (bin, nextPos) =
    match mode with
    | ArchOperationMode.ThumbMode -> getThumbBytes reader pos
    | ArchOperationMode.ARMMode -> reader.ReadUInt32 pos
    | _-> raise InvalidTargetArchModeException
  let len = nextPos - pos |> uint32
  let opcode, cond, itState, wback, qualifier, simdt, oprs, cflag =
    match mode with
    | ArchOperationMode.ARMMode ->
      if isARMv7 arch then Parserv7.parseV7ARM bin
      else Parserv8.parseV8A32ARM bin // XXX
    | ArchOperationMode.ThumbMode ->
      if isARMv7 arch then parseThumb &it bin len
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
  ARM32Instruction (addr, len, insInfo)

// vim: set tw=80 sts=2 sw=2:
