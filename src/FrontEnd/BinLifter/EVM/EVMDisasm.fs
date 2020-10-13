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

module internal B2R2.FrontEnd.BinLifter.EVM.Disasm

open B2R2
open B2R2.FrontEnd.BinLifter

let opcodeToStrings = function
  | Op.STOP -> struct ("stop", None)
  | Op.ADD -> struct("add", None)
  | Op.MUL -> struct("mul", None)
  | Op.SUB -> struct("sub", None)
  | Op.DIV -> struct("div", None)
  | Op.SDIV -> struct("sdiv", None)
  | Op.MOD -> struct("mod", None)
  | Op.SMOD -> struct("smod", None)
  | Op.ADDMOD -> struct("addmod", None)
  | Op.MULMOD -> struct("mulmod", None)
  | Op.EXP -> struct("exp", None)
  | Op.SIGNEXTEND -> struct("signextend", None)
  | Op.LT -> struct("lt", None)
  | Op.GT -> struct("gt", None)
  | Op.SLT -> struct("slt", None)
  | Op.SGT -> struct("sgt", None)
  | Op.EQ -> struct("eq", None)
  | Op.ISZERO -> struct("iszero", None)
  | Op.AND -> struct("and", None)
  | Op.OR -> struct("or", None)
  | Op.XOR -> struct("xor", None)
  | Op.NOT -> struct("not", None)
  | Op.BYTE -> struct("byte", None)
  | Op.SHL -> struct("shl", None)
  | Op.SHR -> struct("shr", None)
  | Op.SAR -> struct("sar", None)
  | Op.SHA3 -> struct("sha3", None)
  | Op.ADDRESS -> struct("address", None)
  | Op.BALANCE -> struct("balance", None)
  | Op.ORIGIN -> struct("origin", None)
  | Op.CALLER -> struct("caller", None)
  | Op.CALLVALUE -> struct("callvalue", None)
  | Op.CALLDATALOAD -> struct("calldataload", None)
  | Op.CALLDATASIZE -> struct("calldatasize", None)
  | Op.CALLDATACOPY -> struct("calldatacopy", None)
  | Op.CODESIZE -> struct("codesize", None)
  | Op.CODECOPY -> struct("codecopy", None)
  | Op.GASPRICE -> struct("gasprice", None)
  | Op.EXTCODESIZE -> struct("extcodesize", None)
  | Op.EXTCODECOPY -> struct("extcodecopy", None)
  | Op.RETURNDATASIZE -> struct("returndatasize", None)
  | Op.RETURNDATACOPY -> struct("returndatacopy", None)
  | Op.BLOCKHASH -> struct("blockhash", None)
  | Op.COINBASE -> struct("coinbase", None)
  | Op.TIMESTAMP -> struct("timestamp", None)
  | Op.NUMBER -> struct("number", None)
  | Op.DIFFICULTY -> struct("difficulty", None)
  | Op.GASLIMIT -> struct("gaslimit", None)
  | Op.POP -> struct("pop", None)
  | Op.MLOAD -> struct("mload", None)
  | Op.MSTORE -> struct("mstore", None)
  | Op.MSTORE8 -> struct("mstore8", None)
  | Op.SLOAD -> struct("sload", None)
  | Op.SSTORE -> struct("sstore", None)
  | Op.JUMP -> struct("jump", None)
  | Op.JUMPI -> struct("jumpi", None)
  | Op.GETPC -> struct("getpc", None)
  | Op.MSIZE -> struct("msize", None)
  | Op.GAS -> struct("gas", None)
  | Op.JUMPDEST -> struct("jumpdest", None)
  | Op.PUSH1 imm -> struct("push1", BitVector.valToString imm |> Some)
  | Op.PUSH2 imm -> struct("push2", BitVector.valToString imm |> Some)
  | Op.PUSH3 imm -> struct("push3", BitVector.valToString imm |> Some)
  | Op.PUSH4 imm -> struct("push4", BitVector.valToString imm |> Some)
  | Op.PUSH5 imm -> struct("push5", BitVector.valToString imm |> Some)
  | Op.PUSH6 imm -> struct("push6", BitVector.valToString imm |> Some)
  | Op.PUSH7 imm -> struct("push7", BitVector.valToString imm |> Some)
  | Op.PUSH8 imm -> struct("push8", BitVector.valToString imm |> Some)
  | Op.PUSH9 imm -> struct("push9", BitVector.valToString imm |> Some)
  | Op.PUSH10 imm -> struct("push10", BitVector.valToString imm |> Some)
  | Op.PUSH11 imm -> struct("push11", BitVector.valToString imm |> Some)
  | Op.PUSH12 imm -> struct("push12", BitVector.valToString imm |> Some)
  | Op.PUSH13 imm -> struct("push13", BitVector.valToString imm |> Some)
  | Op.PUSH14 imm -> struct("push14", BitVector.valToString imm |> Some)
  | Op.PUSH15 imm -> struct("push15", BitVector.valToString imm |> Some)
  | Op.PUSH16 imm -> struct("push16", BitVector.valToString imm |> Some)
  | Op.PUSH17 imm -> struct("push17", BitVector.valToString imm |> Some)
  | Op.PUSH18 imm -> struct("push18", BitVector.valToString imm |> Some)
  | Op.PUSH19 imm -> struct("push19", BitVector.valToString imm |> Some)
  | Op.PUSH20 imm -> struct("push20", BitVector.valToString imm |> Some)
  | Op.PUSH21 imm -> struct("push21", BitVector.valToString imm |> Some)
  | Op.PUSH22 imm -> struct("push22", BitVector.valToString imm |> Some)
  | Op.PUSH23 imm -> struct("push23", BitVector.valToString imm |> Some)
  | Op.PUSH24 imm -> struct("push24", BitVector.valToString imm |> Some)
  | Op.PUSH25 imm -> struct("push25", BitVector.valToString imm |> Some)
  | Op.PUSH26 imm -> struct("push26", BitVector.valToString imm |> Some)
  | Op.PUSH27 imm -> struct("push27", BitVector.valToString imm |> Some)
  | Op.PUSH28 imm -> struct("push28", BitVector.valToString imm |> Some)
  | Op.PUSH29 imm -> struct("push29", BitVector.valToString imm |> Some)
  | Op.PUSH30 imm -> struct("push30", BitVector.valToString imm |> Some)
  | Op.PUSH31 imm -> struct("push31", BitVector.valToString imm |> Some)
  | Op.PUSH32 imm -> struct("push32", BitVector.valToString imm |> Some)
  | Op.DUP1 -> struct("dup1", None)
  | Op.DUP2 -> struct("dup2", None)
  | Op.DUP3 -> struct("dup3", None)
  | Op.DUP4 -> struct("dup4", None)
  | Op.DUP5 -> struct("dup5", None)
  | Op.DUP6 -> struct("dup6", None)
  | Op.DUP7 -> struct("dup7", None)
  | Op.DUP8 -> struct("dup8", None)
  | Op.DUP9 -> struct("dup9", None)
  | Op.DUP10 -> struct("dup10", None)
  | Op.DUP11 -> struct("dup11", None)
  | Op.DUP12 -> struct("dup12", None)
  | Op.DUP13 -> struct("dup13", None)
  | Op.DUP14 -> struct("dup14", None)
  | Op.DUP15 -> struct("dup15", None)
  | Op.DUP16 -> struct("dup16", None)
  | Op.SWAP1 -> struct("swap1", None)
  | Op.SWAP2 -> struct("swap2", None)
  | Op.SWAP3 -> struct("swap3", None)
  | Op.SWAP4 -> struct("swap4", None)
  | Op.SWAP5 -> struct("swap5", None)
  | Op.SWAP6 -> struct("swap6", None)
  | Op.SWAP7 -> struct("swap7", None)
  | Op.SWAP8 -> struct("swap8", None)
  | Op.SWAP9 -> struct("swap9", None)
  | Op.SWAP10 -> struct("swap10", None)
  | Op.SWAP11 -> struct("swap11", None)
  | Op.SWAP12 -> struct("swap12", None)
  | Op.SWAP13 -> struct("swap13", None)
  | Op.SWAP14 -> struct("swap14", None)
  | Op.SWAP15 -> struct("swap15", None)
  | Op.SWAP16 -> struct("swap16", None)
  | Op.LOG0 -> struct("log0", None)
  | Op.LOG1 -> struct("log1", None)
  | Op.LOG2 -> struct("log2", None)
  | Op.LOG3 -> struct("log3", None)
  | Op.LOG4 -> struct("log4", None)
  | Op.JUMPTO -> struct("jumpto", None)
  | Op.JUMPIF -> struct("jumpif", None)
  | Op.JUMPSUB -> struct("jumpsub", None)
  | Op.JUMPSUBV -> struct("jumpsubv", None)
  | Op.BEGINSUB -> struct("beginsub", None)
  | Op.BEGINDATA -> struct("begindata", None)
  | Op.RETURNSUB -> struct("returnsub", None)
  | Op.PUTLOCAL -> struct("putlocal", None)
  | Op.GETLOCAL -> struct("getlocal", None)
  | Op.SLOADBYTES -> struct("sloadbytes", None)
  | Op.SSTOREBYTES -> struct("sstorebytes", None)
  | Op.SSIZE -> struct("ssize", None)
  | Op.CREATE -> struct("create", None)
  | Op.CALL -> struct("call", None)
  | Op.CALLCODE -> struct("callcode", None)
  | Op.RETURN -> struct("return", None)
  | Op.DELEGATECALL -> struct("delegatecall", None)
  | Op.CREATE2 -> struct("create2", None)
  | Op.STATICCALL -> struct("staticcall", None)
  | Op.TXEXECGAS -> struct("txexecgas", None)
  | Op.REVERT -> struct("revert", None)
  | Op.INVALID -> struct("invalid", None)
  | Op.SELFDESTRUCT -> struct("selfdestruct", None)

let inline buildOpcode insInfo builder acc =
  let struct (opcode, extra) = opcodeToStrings insInfo.Opcode
  match extra with
  | None -> builder AsmWordKind.Mnemonic opcode acc
  | Some extra ->
    builder AsmWordKind.Mnemonic opcode acc
    |> builder AsmWordKind.String " "
    |> builder AsmWordKind.Value extra

let disasm showAddr insInfo builder acc =
  let pc = insInfo.Address
  DisasmBuilder.addr pc WordSize.Bit32 showAddr builder acc
  |> buildOpcode insInfo builder

// vim: set tw=80 sts=2 sw=2:
