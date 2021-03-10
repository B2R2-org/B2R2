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

module B2R2.FrontEnd.BinLifter.EVM.Parser

open B2R2
open B2R2.FrontEnd.BinLifter

let private parsePush (reader: BinReader) opcode size pos =
  let struct (bytes, nextPos) = reader.ReadBytes (size, pos)
  struct (opcode <| BitVector.ofArr (Array.rev bytes), 3, nextPos)

let private parseOpcode (reader: BinReader) pos =
  let struct (bin, nextPos) = reader.ReadByte pos
  match bin with
  | 0x00uy -> struct (STOP, 0, nextPos)
  | 0x01uy -> struct (ADD, 3, nextPos)
  | 0x02uy -> struct (MUL, 5, nextPos)
  | 0x03uy -> struct (SUB, 3, nextPos)
  | 0x04uy -> struct (DIV, 5, nextPos)
  | 0x05uy -> struct (SDIV,50, nextPos)
  | 0x06uy -> struct (MOD, 5, nextPos)
  | 0x07uy -> struct (SMOD, 5, nextPos)
  | 0x08uy -> struct (ADDMOD, 8, nextPos)
  | 0x09uy -> struct (MULMOD, 8, nextPos)
  | 0x0auy -> struct (EXP, 10, nextPos)
  | 0x0buy -> struct (SIGNEXTEND, 5, nextPos)
  | 0x10uy -> struct (LT, 3, nextPos)
  | 0x11uy -> struct (GT, 3, nextPos)
  | 0x12uy -> struct (SLT, 3, nextPos)
  | 0x13uy -> struct (SGT, 3, nextPos)
  | 0x14uy -> struct (EQ, 3, nextPos)
  | 0x15uy -> struct (ISZERO, 3, nextPos)
  | 0x16uy -> struct (AND, 3, nextPos)
  | 0x17uy -> struct (OR, 3, nextPos)
  | 0x18uy -> struct (XOR, 3, nextPos)
  | 0x19uy -> struct (NOT, 3, nextPos)
  | 0x1auy -> struct (BYTE, 3, nextPos)
  | 0x1buy -> struct (SHL, 3, nextPos)
  | 0x1cuy -> struct (SHR, 3, nextPos)
  | 0x1duy -> struct (SAR, 3, nextPos)
  | 0x20uy -> struct (SHA3, 30, nextPos)
  | 0x30uy -> struct (ADDRESS, 2, nextPos)
  | 0x31uy -> struct (BALANCE, 400, nextPos)
  | 0x32uy -> struct (ORIGIN, 2, nextPos)
  | 0x33uy -> struct (CALLER, 2, nextPos)
  | 0x34uy -> struct (CALLVALUE, 2, nextPos)
  | 0x35uy -> struct (CALLDATALOAD, 3, nextPos)
  | 0x36uy -> struct (CALLDATASIZE, 2, nextPos)
  | 0x37uy -> struct (CALLDATACOPY, 3, nextPos)
  | 0x38uy -> struct (CODESIZE, 2, nextPos)
  | 0x39uy -> struct (CODECOPY, 3, nextPos)
  | 0x3auy -> struct (GASPRICE, 2, nextPos)
  | 0x3buy -> struct (EXTCODESIZE, 700, nextPos)
  | 0x3cuy -> struct (EXTCODECOPY, 700, nextPos)
  | 0x3duy -> struct (RETURNDATASIZE, 2, nextPos)
  | 0x3euy -> struct (RETURNDATACOPY, 3, nextPos)
  | 0x40uy -> struct (BLOCKHASH, 20, nextPos)
  | 0x41uy -> struct (COINBASE, 2, nextPos)
  | 0x42uy -> struct (TIMESTAMP, 2, nextPos)
  | 0x43uy -> struct (NUMBER, 2, nextPos)
  | 0x44uy -> struct (DIFFICULTY, 2, nextPos)
  | 0x45uy -> struct (GASLIMIT, 2, nextPos)
  | 0x50uy -> struct (POP, 2, nextPos)
  | 0x51uy -> struct (MLOAD, 3, nextPos)
  | 0x52uy -> struct (MSTORE, 3, nextPos)
  | 0x53uy -> struct (MSTORE8, 3, nextPos)
  | 0x54uy -> struct (SLOAD, 200, nextPos)
  | 0x55uy -> struct (SSTORE, 20000, nextPos)
  | 0x56uy -> struct (JUMP, 8, nextPos)
  | 0x57uy -> struct (JUMPI, 10, nextPos)
  | 0x58uy -> struct (GETPC, 2, nextPos)
  | 0x59uy -> struct (MSIZE, 2, nextPos)
  | 0x5auy -> struct (GAS, 2, nextPos)
  | 0x5buy -> struct (JUMPDEST, 1, nextPos)
  | 0x60uy -> parsePush reader PUSH1 1 nextPos
  | 0x61uy -> parsePush reader PUSH2 2 nextPos
  | 0x62uy -> parsePush reader PUSH3 3 nextPos
  | 0x63uy -> parsePush reader PUSH4 4 nextPos
  | 0x64uy -> parsePush reader PUSH5 5 nextPos
  | 0x65uy -> parsePush reader PUSH6 6 nextPos
  | 0x66uy -> parsePush reader PUSH7 7 nextPos
  | 0x67uy -> parsePush reader PUSH8 8 nextPos
  | 0x68uy -> parsePush reader PUSH9 9 nextPos
  | 0x69uy -> parsePush reader PUSH10 10 nextPos
  | 0x6auy -> parsePush reader PUSH11 11 nextPos
  | 0x6buy -> parsePush reader PUSH12 12 nextPos
  | 0x6cuy -> parsePush reader PUSH13 13 nextPos
  | 0x6duy -> parsePush reader PUSH14 14 nextPos
  | 0x6euy -> parsePush reader PUSH15 15 nextPos
  | 0x6fuy -> parsePush reader PUSH16 16 nextPos
  | 0x70uy -> parsePush reader PUSH17 17 nextPos
  | 0x71uy -> parsePush reader PUSH18 18 nextPos
  | 0x72uy -> parsePush reader PUSH19 19 nextPos
  | 0x73uy -> parsePush reader PUSH20 20 nextPos
  | 0x74uy -> parsePush reader PUSH21 21 nextPos
  | 0x75uy -> parsePush reader PUSH22 22 nextPos
  | 0x76uy -> parsePush reader PUSH23 23 nextPos
  | 0x77uy -> parsePush reader PUSH24 24 nextPos
  | 0x78uy -> parsePush reader PUSH25 25 nextPos
  | 0x79uy -> parsePush reader PUSH26 26 nextPos
  | 0x7auy -> parsePush reader PUSH27 27 nextPos
  | 0x7buy -> parsePush reader PUSH28 28 nextPos
  | 0x7cuy -> parsePush reader PUSH29 29 nextPos
  | 0x7duy -> parsePush reader PUSH30 30 nextPos
  | 0x7euy -> parsePush reader PUSH31 31 nextPos
  | 0x7fuy -> parsePush reader PUSH32 32 nextPos
  | 0x80uy -> struct (DUP1, 3, nextPos)
  | 0x81uy -> struct (DUP2, 3, nextPos)
  | 0x82uy -> struct (DUP3, 3, nextPos)
  | 0x83uy -> struct (DUP4, 3, nextPos)
  | 0x84uy -> struct (DUP5, 3, nextPos)
  | 0x85uy -> struct (DUP6, 3, nextPos)
  | 0x86uy -> struct (DUP7, 3, nextPos)
  | 0x87uy -> struct (DUP8, 3, nextPos)
  | 0x88uy -> struct (DUP9, 3, nextPos)
  | 0x89uy -> struct (DUP10, 3, nextPos)
  | 0x8auy -> struct (DUP11, 3, nextPos)
  | 0x8buy -> struct (DUP12, 3, nextPos)
  | 0x8cuy -> struct (DUP13, 3, nextPos)
  | 0x8duy -> struct (DUP14, 3, nextPos)
  | 0x8euy -> struct (DUP15, 3, nextPos)
  | 0x8fuy -> struct (DUP16, 3, nextPos)
  | 0x90uy -> struct (SWAP1, 3, nextPos)
  | 0x91uy -> struct (SWAP2, 3, nextPos)
  | 0x92uy -> struct (SWAP3, 3, nextPos)
  | 0x93uy -> struct (SWAP4, 3, nextPos)
  | 0x94uy -> struct (SWAP5, 3, nextPos)
  | 0x95uy -> struct (SWAP6, 3, nextPos)
  | 0x96uy -> struct (SWAP7, 3, nextPos)
  | 0x97uy -> struct (SWAP8, 3, nextPos)
  | 0x98uy -> struct (SWAP9, 3, nextPos)
  | 0x99uy -> struct (SWAP10, 3, nextPos)
  | 0x9auy -> struct (SWAP11, 3, nextPos)
  | 0x9buy -> struct (SWAP12, 3, nextPos)
  | 0x9cuy -> struct (SWAP13, 3, nextPos)
  | 0x9duy -> struct (SWAP14, 3, nextPos)
  | 0x9euy -> struct (SWAP15, 3, nextPos)
  | 0x9fuy -> struct (SWAP16, 3, nextPos)
  | 0xa0uy -> struct (LOG0, 375, nextPos)
  | 0xa1uy -> struct (LOG1, 750, nextPos)
  | 0xa2uy -> struct (LOG2, 1125, nextPos)
  | 0xa3uy -> struct (LOG3, 1500, nextPos)
  | 0xa4uy -> struct (LOG4, 1875, nextPos)
  | 0xb0uy -> struct (JUMPTO, 0, nextPos)
  | 0xb1uy -> struct (JUMPIF, 0, nextPos)
  | 0xb2uy -> struct (JUMPSUB, 0, nextPos)
  | 0xb4uy -> struct (JUMPSUBV, 0, nextPos)
  | 0xb5uy -> struct (BEGINSUB, 0, nextPos)
  | 0xb6uy -> struct (BEGINDATA, 0, nextPos)
  | 0xb8uy -> struct (RETURNSUB, 0, nextPos)
  | 0xb9uy -> struct (PUTLOCAL, 0, nextPos)
  | 0xbauy -> struct (GETLOCAL, 0, nextPos)
  | 0xe1uy -> struct (SLOADBYTES, 0, nextPos)
  | 0xe2uy -> struct (SSTOREBYTES, 0, nextPos)
  | 0xe3uy -> struct (SSIZE, 0, nextPos)
  | 0xf0uy -> struct (CREATE, 32000, nextPos)
  | 0xf1uy -> struct (CALL, -1, nextPos)
  | 0xf2uy -> struct (CALLCODE, -1, nextPos)
  | 0xf3uy -> struct (RETURN, 0, nextPos)
  | 0xf4uy -> struct (DELEGATECALL, -1, nextPos)
  | 0xf5uy -> struct (CREATE2, 0, nextPos)
  | 0xfauy -> struct (STATICCALL, 4, nextPos)
  | 0xfcuy -> struct (TXEXECGAS, 0, nextPos)
  | 0xfduy -> struct (REVERT, 0, nextPos)
  | 0xfeuy -> struct (INVALID, 0, nextPos)
  | 0xffuy -> struct (SELFDESTRUCT, 5000, nextPos)
  | _ -> raise ParsingFailureException

let parse (reader: BinReader) offset wordSize addr pos =
  let struct (opcode, gas, nextPos) = parseOpcode reader pos
  let instrLen = nextPos - pos |> uint32
  let insInfo =
    { Address = addr
      NumBytes = instrLen
      Offset = offset
      Opcode = opcode
      GAS = gas }
  EVMInstruction (addr, instrLen, insInfo, wordSize)

// vim: set tw=80 sts=2 sw=2:
