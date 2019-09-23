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

module internal B2R2.FrontEnd.EVM.Disasm

open B2R2
open System.Text

let regToStr = function
  | R.SP  -> "sp"
  | R.GAS  -> "gas"
  | _ -> failwith "Unknown Reg"

let opCodeToString = function
  | Op.STOP -> "stop"
  | Op.ADD -> "add"
  | Op.MUL -> "mul"
  | Op.SUB -> "sub"
  | Op.DIV -> "div"
  | Op.SDIV -> "sdiv"
  | Op.MOD -> "mod"
  | Op.SMOD -> "smod"
  | Op.ADDMOD -> "addmod"
  | Op.MULMOD -> "mulmod"
  | Op.EXP -> "exp"
  | Op.SIGNEXTEND -> "signextend"
  | Op.LT -> "lt"
  | Op.GT -> "gt"
  | Op.SLT -> "slt"
  | Op.SGT -> "sgt"
  | Op.EQ -> "eq"
  | Op.ISZERO -> "iszero"
  | Op.AND -> "and"
  | Op.OR -> "or"
  | Op.XOR -> "xor"
  | Op.NOT -> "not"
  | Op.BYTE -> "byte"
  | Op.SHL -> "shl"
  | Op.SHR -> "shr"
  | Op.SAR -> "sar"
  | Op.SHA3 -> "sha3"
  | Op.ADDRESS -> "address"
  | Op.BALANCE -> "balance"
  | Op.ORIGIN -> "origin"
  | Op.CALLER -> "caller"
  | Op.CALLVALUE -> "callvalue"
  | Op.CALLDATALOAD -> "calldataload"
  | Op.CALLDATASIZE -> "calldatasize"
  | Op.CALLDATACOPY -> "calldatacopy"
  | Op.CODESIZE -> "codesize"
  | Op.CODECOPY -> "codecopy"
  | Op.GASPRICE -> "gasprice"
  | Op.EXTCODESIZE -> "extcodesize"
  | Op.EXTCODECOPY -> "extcodecopy"
  | Op.RETURNDATASIZE -> "returndatasize"
  | Op.RETURNDATACOPY -> "returndatacopy"
  | Op.BLOCKHASH -> "blockhash"
  | Op.COINBASE -> "coinbase"
  | Op.TIMESTAMP -> "timestamp"
  | Op.NUMBER -> "number"
  | Op.DIFFICULTY -> "difficulty"
  | Op.GASLIMIT -> "gaslimit"
  | Op.POP -> "pop"
  | Op.MLOAD -> "mload"
  | Op.MSTORE -> "mstore"
  | Op.MSTORE8 -> "mstore8"
  | Op.SLOAD -> "sload"
  | Op.SSTORE -> "sstore"
  | Op.JUMP -> "jump"
  | Op.JUMPI -> "jumpi"
  | Op.GETPC -> "getpc"
  | Op.MSIZE -> "msize"
  | Op.GAS -> "gas"
  | Op.JUMPDEST -> "jumpdest"
  | Op.PUSH1 imm -> "push1 " + BitVector.toString imm
  | Op.PUSH2 imm -> "push2 " + BitVector.toString imm
  | Op.PUSH3 imm -> "push3 " + BitVector.toString imm
  | Op.PUSH4 imm -> "push4 " + BitVector.toString imm
  | Op.PUSH5 imm -> "push5 " + BitVector.toString imm
  | Op.PUSH6 imm -> "push6 " + BitVector.toString imm
  | Op.PUSH7 imm -> "push7 " + BitVector.toString imm
  | Op.PUSH8 imm -> "push8 " + BitVector.toString imm
  | Op.PUSH9 imm -> "push9 " + BitVector.toString imm
  | Op.PUSH10 imm -> "push10 " + BitVector.toString imm
  | Op.PUSH11 imm -> "push11 " + BitVector.toString imm
  | Op.PUSH12 imm -> "push12 " + BitVector.toString imm
  | Op.PUSH13 imm -> "push13 " + BitVector.toString imm
  | Op.PUSH14 imm -> "push14 " + BitVector.toString imm
  | Op.PUSH15 imm -> "push15 " + BitVector.toString imm
  | Op.PUSH16 imm -> "push16 " + BitVector.toString imm
  | Op.PUSH17 imm -> "push17 " + BitVector.toString imm
  | Op.PUSH18 imm -> "push18 " + BitVector.toString imm
  | Op.PUSH19 imm -> "push19 " + BitVector.toString imm
  | Op.PUSH20 imm -> "push20 " + BitVector.toString imm
  | Op.PUSH21 imm -> "push21 " + BitVector.toString imm
  | Op.PUSH22 imm -> "push22 " + BitVector.toString imm
  | Op.PUSH23 imm -> "push23 " + BitVector.toString imm
  | Op.PUSH24 imm -> "push24 " + BitVector.toString imm
  | Op.PUSH25 imm -> "push25 " + BitVector.toString imm
  | Op.PUSH26 imm -> "push26 " + BitVector.toString imm
  | Op.PUSH27 imm -> "push27 " + BitVector.toString imm
  | Op.PUSH28 imm -> "push28 " + BitVector.toString imm
  | Op.PUSH29 imm -> "push29 " + BitVector.toString imm
  | Op.PUSH30 imm -> "push30 " + BitVector.toString imm
  | Op.PUSH31 imm -> "push31 " + BitVector.toString imm
  | Op.PUSH32 imm -> "push32 " + BitVector.toString imm
  | Op.DUP1 -> "dup1"
  | Op.DUP2 -> "dup2"
  | Op.DUP3 -> "dup3"
  | Op.DUP4 -> "dup4"
  | Op.DUP5 -> "dup5"
  | Op.DUP6 -> "dup6"
  | Op.DUP7 -> "dup7"
  | Op.DUP8 -> "dup8"
  | Op.DUP9 -> "dup9"
  | Op.DUP10 -> "dup10"
  | Op.DUP11 -> "dup11"
  | Op.DUP12 -> "dup12"
  | Op.DUP13 -> "dup13"
  | Op.DUP14 -> "dup14"
  | Op.DUP15 -> "dup15"
  | Op.DUP16 -> "dup16"
  | Op.SWAP1 -> "swap1"
  | Op.SWAP2 -> "swap2"
  | Op.SWAP3 -> "swap3"
  | Op.SWAP4 -> "swap4"
  | Op.SWAP5 -> "swap5"
  | Op.SWAP6 -> "swap6"
  | Op.SWAP7 -> "swap7"
  | Op.SWAP8 -> "swap8"
  | Op.SWAP9 -> "swap9"
  | Op.SWAP10 -> "swap10"
  | Op.SWAP11 -> "swap11"
  | Op.SWAP12 -> "swap12"
  | Op.SWAP13 -> "swap13"
  | Op.SWAP14 -> "swap14"
  | Op.SWAP15 -> "swap15"
  | Op.SWAP16 -> "swap16"
  | Op.LOG0 -> "log0"
  | Op.LOG1 -> "log1"
  | Op.LOG2 -> "log2"
  | Op.LOG3 -> "log3"
  | Op.LOG4 -> "log4"
  | Op.JUMPTO -> "jumpto"
  | Op.JUMPIF -> "jumpif"
  | Op.JUMPSUB -> "jumpsub"
  | Op.JUMPSUBV -> "jumpsubv"
  | Op.BEGINSUB -> "beginsub"
  | Op.BEGINDATA -> "begindata"
  | Op.RETURNSUB -> "returnsub"
  | Op.PUTLOCAL -> "putlocal"
  | Op.GETLOCAL -> "getlocal"
  | Op.SLOADBYTES -> "sloadbytes"
  | Op.SSTOREBYTES -> "sstorebytes"
  | Op.SSIZE -> "ssize"
  | Op.CREATE -> "create"
  | Op.CALL -> "call"
  | Op.CALLCODE -> "callcode"
  | Op.RETURN -> "return"
  | Op.DELEGATECALL -> "delegatecall"
  | Op.CREATE2 -> "create2"
  | Op.STATICCALL -> "staticcall"
  | Op.TXEXECGAS -> "txexecgas"
  | Op.REVERT -> "revert"
  | Op.INVALID -> "invalid"
  | Op.SELFDESTRUCT -> "selfdestruct"

let inline printAddr (addr: Addr) wordSize verbose (sb: StringBuilder) =
  if not verbose then sb else sb.Append(addr.ToString("X8")).Append(": ")

let inline printOpcode insInfo (sb: StringBuilder) =
  sb.Append(opCodeToString insInfo.Opcode)

let disasm showAddr wordSize insInfo =
  let pc = insInfo.Address
  let sb = StringBuilder ()
  let sb = printAddr pc wordSize showAddr sb
  let sb = printOpcode insInfo sb
  sb.ToString ()

// vim: set tw=80 sts=2 sw=2:
