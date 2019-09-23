(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>
          Seung Il Jung <sijung@kaist.ac.kr>

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

module B2R2.FrontEnd.EVM.Parser

open B2R2
open B2R2.FrontEnd

let private parsePush (reader: BinReader) opcode size pos =
  let struct (bytes, nextPos) = reader.ReadBytes (size, pos)
  opcode <| BitVector.ofArr (Array.rev bytes), 3, nextPos

let private parseOpcode (reader: BinReader) pos =
  let struct (bin, nextPos) = reader.ReadByte pos
  match bin with
  | 0x00uy -> STOP, 0, nextPos
  | 0x01uy -> ADD, 3, nextPos
  | 0x02uy -> MUL, 5, nextPos
  | 0x03uy -> SUB, 3, nextPos
  | 0x04uy -> DIV, 5, nextPos
  | 0x05uy -> SDIV,50, nextPos
  | 0x06uy -> MOD, 5, nextPos
  | 0x07uy -> SMOD, 5, nextPos
  | 0x08uy -> ADDMOD, 8, nextPos
  | 0x09uy -> MULMOD, 8, nextPos
  | 0x0auy -> EXP, 10, nextPos
  | 0x0buy -> SIGNEXTEND, 5, nextPos
  | 0x10uy -> LT, 3, nextPos
  | 0x11uy -> GT, 3, nextPos
  | 0x12uy -> SLT, 3, nextPos
  | 0x13uy -> SGT, 3, nextPos
  | 0x14uy -> EQ, 3, nextPos
  | 0x15uy -> ISZERO, 3, nextPos
  | 0x16uy -> AND, 3, nextPos
  | 0x17uy -> OR, 3, nextPos
  | 0x18uy -> XOR, 3, nextPos
  | 0x19uy -> NOT, 3, nextPos
  | 0x1auy -> BYTE, 3, nextPos
  | 0x1buy -> SHL, 3, nextPos
  | 0x1cuy -> SHR, 3, nextPos
  | 0x1duy -> SAR, 3, nextPos
  | 0x20uy -> SHA3, 30, nextPos
  | 0x30uy -> ADDRESS, 2, nextPos
  | 0x31uy -> BALANCE, 400, nextPos
  | 0x32uy -> ORIGIN, 2, nextPos
  | 0x33uy -> CALLER, 2, nextPos
  | 0x34uy -> CALLVALUE, 2, nextPos
  | 0x35uy -> CALLDATALOAD, 3, nextPos
  | 0x36uy -> CALLDATASIZE, 2, nextPos
  | 0x37uy -> CALLDATACOPY, 3, nextPos
  | 0x38uy -> CODESIZE, 2, nextPos
  | 0x39uy -> CODECOPY, 3, nextPos
  | 0x3auy -> GASPRICE, 2, nextPos
  | 0x3buy -> EXTCODESIZE, 700, nextPos
  | 0x3cuy -> EXTCODECOPY, 700, nextPos
  | 0x3duy -> RETURNDATASIZE, 2, nextPos
  | 0x3euy -> RETURNDATACOPY, 3, nextPos
  | 0x40uy -> BLOCKHASH, 20, nextPos
  | 0x41uy -> COINBASE, 2, nextPos
  | 0x42uy -> TIMESTAMP, 2, nextPos
  | 0x43uy -> NUMBER, 2, nextPos
  | 0x44uy -> DIFFICULTY, 2, nextPos
  | 0x45uy -> GASLIMIT, 2, nextPos
  | 0x50uy -> POP, 2, nextPos
  | 0x51uy -> MLOAD, 3, nextPos
  | 0x52uy -> MSTORE, 3, nextPos
  | 0x53uy -> MSTORE8, 3, nextPos
  | 0x54uy -> SLOAD, 200, nextPos
  | 0x55uy -> SSTORE, 20000, nextPos
  | 0x56uy -> JUMP, 8, nextPos
  | 0x57uy -> JUMPI, 10, nextPos
  | 0x58uy -> GETPC, 2, nextPos
  | 0x59uy -> MSIZE, 2, nextPos
  | 0x5auy -> GAS, 2, nextPos
  | 0x5buy -> JUMPDEST, 1, nextPos
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
  | 0x80uy -> DUP1, 3, nextPos
  | 0x81uy -> DUP2, 3, nextPos
  | 0x82uy -> DUP3, 3, nextPos
  | 0x83uy -> DUP4, 3, nextPos
  | 0x84uy -> DUP5, 3, nextPos
  | 0x85uy -> DUP6, 3, nextPos
  | 0x86uy -> DUP7, 3, nextPos
  | 0x87uy -> DUP8, 3, nextPos
  | 0x88uy -> DUP9, 3, nextPos
  | 0x89uy -> DUP10, 3, nextPos
  | 0x8auy -> DUP11, 3, nextPos
  | 0x8buy -> DUP12, 3, nextPos
  | 0x8cuy -> DUP13, 3, nextPos
  | 0x8duy -> DUP14, 3, nextPos
  | 0x8euy -> DUP15, 3, nextPos
  | 0x8fuy -> DUP16, 3, nextPos
  | 0x90uy -> SWAP1, 3, nextPos
  | 0x91uy -> SWAP2, 3, nextPos
  | 0x92uy -> SWAP3, 3, nextPos
  | 0x93uy -> SWAP4, 3, nextPos
  | 0x94uy -> SWAP5, 3, nextPos
  | 0x95uy -> SWAP6, 3, nextPos
  | 0x96uy -> SWAP7, 3, nextPos
  | 0x97uy -> SWAP8, 3, nextPos
  | 0x98uy -> SWAP9, 3, nextPos
  | 0x99uy -> SWAP10, 3, nextPos
  | 0x9auy -> SWAP11, 3, nextPos
  | 0x9buy -> SWAP12, 3, nextPos
  | 0x9cuy -> SWAP13, 3, nextPos
  | 0x9duy -> SWAP14, 3, nextPos
  | 0x9euy -> SWAP15, 3, nextPos
  | 0x9fuy -> SWAP16, 3, nextPos
  | 0xa0uy -> LOG0, 375, nextPos
  | 0xa1uy -> LOG1, 750, nextPos
  | 0xa2uy -> LOG2, 1125, nextPos
  | 0xa3uy -> LOG3, 1500, nextPos
  | 0xa4uy -> LOG4, 1875, nextPos
  | 0xb0uy -> JUMPTO, 0, nextPos
  | 0xb1uy -> JUMPIF, 0, nextPos
  | 0xb2uy -> JUMPSUB, 0, nextPos
  | 0xb4uy -> JUMPSUBV, 0, nextPos
  | 0xb5uy -> BEGINSUB, 0, nextPos
  | 0xb6uy -> BEGINDATA, 0, nextPos
  | 0xb8uy -> RETURNSUB, 0, nextPos
  | 0xb9uy -> PUTLOCAL, 0, nextPos
  | 0xbauy -> GETLOCAL, 0, nextPos
  | 0xe1uy -> SLOADBYTES, 0, nextPos
  | 0xe2uy -> SSTOREBYTES, 0, nextPos
  | 0xe3uy -> SSIZE, 0, nextPos
  | 0xf0uy -> CREATE, 32000, nextPos
  | 0xf1uy -> CALL, -1, nextPos
  | 0xf2uy -> CALLCODE, -1, nextPos
  | 0xf3uy -> RETURN, 0, nextPos
  | 0xf4uy -> DELEGATECALL, -1, nextPos
  | 0xf5uy -> CREATE2, 0, nextPos
  | 0xfauy -> STATICCALL, 4, nextPos
  | 0xfcuy -> TXEXECGAS, 0, nextPos
  | 0xfduy -> REVERT, 0, nextPos
  | 0xfeuy -> INVALID, 0, nextPos
  | 0xffuy -> SELFDESTRUCT, 5000, nextPos
  | _ -> raise ParsingFailureException

let parse (reader: BinReader) wordSize addr pos =
  let opcode, gas, nextPos = parseOpcode reader pos
  let instrLen = nextPos - pos |> uint32
  let insInfo =
    {
      Address = addr
      NumBytes = instrLen
      Opcode = opcode
      GAS = gas
    }
  EVMInstruction (addr, instrLen, insInfo, wordSize)

// vim: set tw=80 sts=2 sw=2:
