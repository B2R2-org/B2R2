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

module internal B2R2.FrontEnd.EVM.ParsingMain

open System
open B2R2
open B2R2.FrontEnd.BinLifter

let private parsePush (span: ReadOnlySpan<byte>) opcode size =
  let bytes = span.Slice(1, int size).ToArray ()
  struct (opcode <| BitVector.OfArr (Array.rev bytes), 3, 1u + size)

let private parseOpcode (span: ReadOnlySpan<byte>) =
  match span[0] with
  | 0x00uy -> struct (STOP, 0, 1u)
  | 0x01uy -> struct (ADD, 3, 1u)
  | 0x02uy -> struct (MUL, 5, 1u)
  | 0x03uy -> struct (SUB, 3, 1u)
  | 0x04uy -> struct (DIV, 5, 1u)
  | 0x05uy -> struct (SDIV,50, 1u)
  | 0x06uy -> struct (MOD, 5, 1u)
  | 0x07uy -> struct (SMOD, 5, 1u)
  | 0x08uy -> struct (ADDMOD, 8, 1u)
  | 0x09uy -> struct (MULMOD, 8, 1u)
  | 0x0auy -> struct (EXP, 10, 1u)
  | 0x0buy -> struct (SIGNEXTEND, 5, 1u)
  | 0x10uy -> struct (LT, 3, 1u)
  | 0x11uy -> struct (GT, 3, 1u)
  | 0x12uy -> struct (SLT, 3, 1u)
  | 0x13uy -> struct (SGT, 3, 1u)
  | 0x14uy -> struct (EQ, 3, 1u)
  | 0x15uy -> struct (ISZERO, 3, 1u)
  | 0x16uy -> struct (AND, 3, 1u)
  | 0x17uy -> struct (OR, 3, 1u)
  | 0x18uy -> struct (XOR, 3, 1u)
  | 0x19uy -> struct (NOT, 3, 1u)
  | 0x1auy -> struct (BYTE, 3, 1u)
  | 0x1buy -> struct (SHL, 3, 1u)
  | 0x1cuy -> struct (SHR, 3, 1u)
  | 0x1duy -> struct (SAR, 3, 1u)
  | 0x20uy -> struct (SHA3, 30, 1u)
  | 0x30uy -> struct (ADDRESS, 2, 1u)
  | 0x31uy -> struct (BALANCE, 400, 1u)
  | 0x32uy -> struct (ORIGIN, 2, 1u)
  | 0x33uy -> struct (CALLER, 2, 1u)
  | 0x34uy -> struct (CALLVALUE, 2, 1u)
  | 0x35uy -> struct (CALLDATALOAD, 3, 1u)
  | 0x36uy -> struct (CALLDATASIZE, 2, 1u)
  | 0x37uy -> struct (CALLDATACOPY, 3, 1u)
  | 0x38uy -> struct (CODESIZE, 2, 1u)
  | 0x39uy -> struct (CODECOPY, 3, 1u)
  | 0x3auy -> struct (GASPRICE, 2, 1u)
  | 0x3buy -> struct (EXTCODESIZE, 700, 1u)
  | 0x3cuy -> struct (EXTCODECOPY, 700, 1u)
  | 0x3duy -> struct (RETURNDATASIZE, 2, 1u)
  | 0x3euy -> struct (RETURNDATACOPY, 3, 1u)
  | 0x3fuy -> struct (EXTCODEHASH, 400, 1u)
  | 0x40uy -> struct (BLOCKHASH, 20, 1u)
  | 0x41uy -> struct (COINBASE, 2, 1u)
  | 0x42uy -> struct (TIMESTAMP, 2, 1u)
  | 0x43uy -> struct (NUMBER, 2, 1u)
  | 0x44uy -> struct (DIFFICULTY, 2, 1u)
  | 0x45uy -> struct (GASLIMIT, 2, 1u)
  | 0x46uy -> struct (CHAINID, 2, 1u)
  | 0x47uy -> struct (SELFBALANCE, 5, 1u)
  | 0x48uy -> struct (BASEFEE, 2, 1u)
  | 0x50uy -> struct (POP, 2, 1u)
  | 0x51uy -> struct (MLOAD, 3, 1u)
  | 0x52uy -> struct (MSTORE, 3, 1u)
  | 0x53uy -> struct (MSTORE8, 3, 1u)
  | 0x54uy -> struct (SLOAD, 200, 1u)
  | 0x55uy -> struct (SSTORE, 20000, 1u)
  | 0x56uy -> struct (JUMP, 8, 1u)
  | 0x57uy -> struct (JUMPI, 10, 1u)
  | 0x58uy -> struct (GETPC, 2, 1u)
  | 0x59uy -> struct (MSIZE, 2, 1u)
  | 0x5auy -> struct (GAS, 2, 1u)
  | 0x5buy -> struct (JUMPDEST, 1, 1u)
  | 0x60uy -> parsePush span PUSH1 1u
  | 0x61uy -> parsePush span PUSH2 2u
  | 0x62uy -> parsePush span PUSH3 3u
  | 0x63uy -> parsePush span PUSH4 4u
  | 0x64uy -> parsePush span PUSH5 5u
  | 0x65uy -> parsePush span PUSH6 6u
  | 0x66uy -> parsePush span PUSH7 7u
  | 0x67uy -> parsePush span PUSH8 8u
  | 0x68uy -> parsePush span PUSH9 9u
  | 0x69uy -> parsePush span PUSH10 10u
  | 0x6auy -> parsePush span PUSH11 11u
  | 0x6buy -> parsePush span PUSH12 12u
  | 0x6cuy -> parsePush span PUSH13 13u
  | 0x6duy -> parsePush span PUSH14 14u
  | 0x6euy -> parsePush span PUSH15 15u
  | 0x6fuy -> parsePush span PUSH16 16u
  | 0x70uy -> parsePush span PUSH17 17u
  | 0x71uy -> parsePush span PUSH18 18u
  | 0x72uy -> parsePush span PUSH19 19u
  | 0x73uy -> parsePush span PUSH20 20u
  | 0x74uy -> parsePush span PUSH21 21u
  | 0x75uy -> parsePush span PUSH22 22u
  | 0x76uy -> parsePush span PUSH23 23u
  | 0x77uy -> parsePush span PUSH24 24u
  | 0x78uy -> parsePush span PUSH25 25u
  | 0x79uy -> parsePush span PUSH26 26u
  | 0x7auy -> parsePush span PUSH27 27u
  | 0x7buy -> parsePush span PUSH28 28u
  | 0x7cuy -> parsePush span PUSH29 29u
  | 0x7duy -> parsePush span PUSH30 30u
  | 0x7euy -> parsePush span PUSH31 31u
  | 0x7fuy -> parsePush span PUSH32 32u
  | 0x80uy -> struct (DUP1, 3, 1u)
  | 0x81uy -> struct (DUP2, 3, 1u)
  | 0x82uy -> struct (DUP3, 3, 1u)
  | 0x83uy -> struct (DUP4, 3, 1u)
  | 0x84uy -> struct (DUP5, 3, 1u)
  | 0x85uy -> struct (DUP6, 3, 1u)
  | 0x86uy -> struct (DUP7, 3, 1u)
  | 0x87uy -> struct (DUP8, 3, 1u)
  | 0x88uy -> struct (DUP9, 3, 1u)
  | 0x89uy -> struct (DUP10, 3, 1u)
  | 0x8auy -> struct (DUP11, 3, 1u)
  | 0x8buy -> struct (DUP12, 3, 1u)
  | 0x8cuy -> struct (DUP13, 3, 1u)
  | 0x8duy -> struct (DUP14, 3, 1u)
  | 0x8euy -> struct (DUP15, 3, 1u)
  | 0x8fuy -> struct (DUP16, 3, 1u)
  | 0x90uy -> struct (SWAP1, 3, 1u)
  | 0x91uy -> struct (SWAP2, 3, 1u)
  | 0x92uy -> struct (SWAP3, 3, 1u)
  | 0x93uy -> struct (SWAP4, 3, 1u)
  | 0x94uy -> struct (SWAP5, 3, 1u)
  | 0x95uy -> struct (SWAP6, 3, 1u)
  | 0x96uy -> struct (SWAP7, 3, 1u)
  | 0x97uy -> struct (SWAP8, 3, 1u)
  | 0x98uy -> struct (SWAP9, 3, 1u)
  | 0x99uy -> struct (SWAP10, 3, 1u)
  | 0x9auy -> struct (SWAP11, 3, 1u)
  | 0x9buy -> struct (SWAP12, 3, 1u)
  | 0x9cuy -> struct (SWAP13, 3, 1u)
  | 0x9duy -> struct (SWAP14, 3, 1u)
  | 0x9euy -> struct (SWAP15, 3, 1u)
  | 0x9fuy -> struct (SWAP16, 3, 1u)
  | 0xa0uy -> struct (LOG0, 375, 1u)
  | 0xa1uy -> struct (LOG1, 750, 1u)
  | 0xa2uy -> struct (LOG2, 1125, 1u)
  | 0xa3uy -> struct (LOG3, 1500, 1u)
  | 0xa4uy -> struct (LOG4, 1875, 1u)
  | 0xf0uy -> struct (CREATE, 32000, 1u)
  | 0xf1uy -> struct (CALL, -1, 1u)
  | 0xf2uy -> struct (CALLCODE, -1, 1u)
  | 0xf3uy -> struct (RETURN, 0, 1u)
  | 0xf4uy -> struct (DELEGATECALL, -1, 1u)
  | 0xf5uy -> struct (CREATE2, 0, 1u)
  | 0xfauy -> struct (STATICCALL, 4, 1u)
  | 0xfduy -> struct (REVERT, 0, 1u)
  | 0xfeuy -> struct (INVALID, 0, 1u)
  | 0xffuy -> struct (SELFDESTRUCT, 5000, 1u)
  | _ -> raise ParsingFailureException

let parse span offset wordSize addr =
  let struct (opcode, gas, instrLen) = parseOpcode span
  let insInfo =
    { Address = addr
      NumBytes = instrLen
      Offset = offset
      Opcode = opcode
      GAS = gas }
  EVMInstruction (addr, instrLen, insInfo, wordSize)

// vim: set tw=80 sts=2 sw=2:
