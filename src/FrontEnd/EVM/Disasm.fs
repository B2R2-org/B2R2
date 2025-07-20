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

module internal B2R2.FrontEnd.EVM.Disasm

open B2R2
open B2R2.FrontEnd.BinLifter

let opcodeToStrings = function
  | STOP -> struct ("stop", None)
  | ADD -> struct("add", None)
  | MUL -> struct("mul", None)
  | SUB -> struct("sub", None)
  | DIV -> struct("div", None)
  | SDIV -> struct("sdiv", None)
  | MOD -> struct("mod", None)
  | SMOD -> struct("smod", None)
  | ADDMOD -> struct("addmod", None)
  | MULMOD -> struct("mulmod", None)
  | EXP -> struct("exp", None)
  | SIGNEXTEND -> struct("signextend", None)
  | LT -> struct("lt", None)
  | GT -> struct("gt", None)
  | SLT -> struct("slt", None)
  | SGT -> struct("sgt", None)
  | EQ -> struct("eq", None)
  | ISZERO -> struct("iszero", None)
  | AND -> struct("and", None)
  | OR -> struct("or", None)
  | XOR -> struct("xor", None)
  | NOT -> struct("not", None)
  | BYTE -> struct("byte", None)
  | SHL -> struct("shl", None)
  | SHR -> struct("shr", None)
  | SAR -> struct("sar", None)
  | SHA3 -> struct("sha3", None)
  | ADDRESS -> struct("address", None)
  | BALANCE -> struct("balance", None)
  | ORIGIN -> struct("origin", None)
  | CALLER -> struct("caller", None)
  | CALLVALUE -> struct("callvalue", None)
  | CALLDATALOAD -> struct("calldataload", None)
  | CALLDATASIZE -> struct("calldatasize", None)
  | CALLDATACOPY -> struct("calldatacopy", None)
  | CODESIZE -> struct("codesize", None)
  | CODECOPY -> struct("codecopy", None)
  | GASPRICE -> struct("gasprice", None)
  | EXTCODESIZE -> struct("extcodesize", None)
  | EXTCODECOPY -> struct("extcodecopy", None)
  | RETURNDATASIZE -> struct("returndatasize", None)
  | RETURNDATACOPY -> struct("returndatacopy", None)
  | EXTCODEHASH -> struct("extcodehash", None)
  | BLOCKHASH -> struct("blockhash", None)
  | COINBASE -> struct("coinbase", None)
  | TIMESTAMP -> struct("timestamp", None)
  | NUMBER -> struct("number", None)
  | DIFFICULTY -> struct("difficulty", None)
  | GASLIMIT -> struct("gaslimit", None)
  | CHAINID -> struct("chain_id", None)
  | SELFBALANCE -> struct("this.balance", None)
  | BASEFEE -> struct("block.basefee", None)
  | POP -> struct("pop", None)
  | MLOAD -> struct("mload", None)
  | MSTORE -> struct("mstore", None)
  | MSTORE8 -> struct("mstore8", None)
  | SLOAD -> struct("sload", None)
  | SSTORE -> struct("sstore", None)
  | JUMP -> struct("jump", None)
  | JUMPI -> struct("jumpi", None)
  | GETPC -> struct("getpc", None)
  | MSIZE -> struct("msize", None)
  | GAS -> struct("gas", None)
  | JUMPDEST -> struct("jumpdest", None)
  | TLOAD -> struct("tload", None)
  | TSTORE -> struct("tstore", None)
  | MCOPY -> struct("mcopy", None)
  | PUSH0 -> struct("push0", None)
  | PUSH1 imm -> struct("push1", BitVector.ValToString imm |> Some)
  | PUSH2 imm -> struct("push2", BitVector.ValToString imm |> Some)
  | PUSH3 imm -> struct("push3", BitVector.ValToString imm |> Some)
  | PUSH4 imm -> struct("push4", BitVector.ValToString imm |> Some)
  | PUSH5 imm -> struct("push5", BitVector.ValToString imm |> Some)
  | PUSH6 imm -> struct("push6", BitVector.ValToString imm |> Some)
  | PUSH7 imm -> struct("push7", BitVector.ValToString imm |> Some)
  | PUSH8 imm -> struct("push8", BitVector.ValToString imm |> Some)
  | PUSH9 imm -> struct("push9", BitVector.ValToString imm |> Some)
  | PUSH10 imm -> struct("push10", BitVector.ValToString imm |> Some)
  | PUSH11 imm -> struct("push11", BitVector.ValToString imm |> Some)
  | PUSH12 imm -> struct("push12", BitVector.ValToString imm |> Some)
  | PUSH13 imm -> struct("push13", BitVector.ValToString imm |> Some)
  | PUSH14 imm -> struct("push14", BitVector.ValToString imm |> Some)
  | PUSH15 imm -> struct("push15", BitVector.ValToString imm |> Some)
  | PUSH16 imm -> struct("push16", BitVector.ValToString imm |> Some)
  | PUSH17 imm -> struct("push17", BitVector.ValToString imm |> Some)
  | PUSH18 imm -> struct("push18", BitVector.ValToString imm |> Some)
  | PUSH19 imm -> struct("push19", BitVector.ValToString imm |> Some)
  | PUSH20 imm -> struct("push20", BitVector.ValToString imm |> Some)
  | PUSH21 imm -> struct("push21", BitVector.ValToString imm |> Some)
  | PUSH22 imm -> struct("push22", BitVector.ValToString imm |> Some)
  | PUSH23 imm -> struct("push23", BitVector.ValToString imm |> Some)
  | PUSH24 imm -> struct("push24", BitVector.ValToString imm |> Some)
  | PUSH25 imm -> struct("push25", BitVector.ValToString imm |> Some)
  | PUSH26 imm -> struct("push26", BitVector.ValToString imm |> Some)
  | PUSH27 imm -> struct("push27", BitVector.ValToString imm |> Some)
  | PUSH28 imm -> struct("push28", BitVector.ValToString imm |> Some)
  | PUSH29 imm -> struct("push29", BitVector.ValToString imm |> Some)
  | PUSH30 imm -> struct("push30", BitVector.ValToString imm |> Some)
  | PUSH31 imm -> struct("push31", BitVector.ValToString imm |> Some)
  | PUSH32 imm -> struct("push32", BitVector.ValToString imm |> Some)
  | DUP1 -> struct("dup1", None)
  | DUP2 -> struct("dup2", None)
  | DUP3 -> struct("dup3", None)
  | DUP4 -> struct("dup4", None)
  | DUP5 -> struct("dup5", None)
  | DUP6 -> struct("dup6", None)
  | DUP7 -> struct("dup7", None)
  | DUP8 -> struct("dup8", None)
  | DUP9 -> struct("dup9", None)
  | DUP10 -> struct("dup10", None)
  | DUP11 -> struct("dup11", None)
  | DUP12 -> struct("dup12", None)
  | DUP13 -> struct("dup13", None)
  | DUP14 -> struct("dup14", None)
  | DUP15 -> struct("dup15", None)
  | DUP16 -> struct("dup16", None)
  | SWAP1 -> struct("swap1", None)
  | SWAP2 -> struct("swap2", None)
  | SWAP3 -> struct("swap3", None)
  | SWAP4 -> struct("swap4", None)
  | SWAP5 -> struct("swap5", None)
  | SWAP6 -> struct("swap6", None)
  | SWAP7 -> struct("swap7", None)
  | SWAP8 -> struct("swap8", None)
  | SWAP9 -> struct("swap9", None)
  | SWAP10 -> struct("swap10", None)
  | SWAP11 -> struct("swap11", None)
  | SWAP12 -> struct("swap12", None)
  | SWAP13 -> struct("swap13", None)
  | SWAP14 -> struct("swap14", None)
  | SWAP15 -> struct("swap15", None)
  | SWAP16 -> struct("swap16", None)
  | LOG0 -> struct("log0", None)
  | LOG1 -> struct("log1", None)
  | LOG2 -> struct("log2", None)
  | LOG3 -> struct("log3", None)
  | LOG4 -> struct("log4", None)
  | CREATE -> struct("create", None)
  | CALL -> struct("call", None)
  | CALLCODE -> struct("callcode", None)
  | RETURN -> struct("return", None)
  | DELEGATECALL -> struct("delegatecall", None)
  | CREATE2 -> struct("create2", None)
  | STATICCALL -> struct("staticcall", None)
  | REVERT -> struct("revert", None)
  | INVALID -> struct("invalid", None)
  | SELFDESTRUCT -> struct("selfdestruct", None)

let inline buildOpcode (ins: Instruction) (builder: IDisasmBuilder) =
  let struct (opcode, extra) = opcodeToStrings ins.Opcode
  match extra with
  | None -> builder.Accumulate AsmWordKind.Mnemonic opcode
  | Some extra ->
    builder.Accumulate AsmWordKind.Mnemonic opcode
    builder.Accumulate AsmWordKind.String " "
    builder.Accumulate AsmWordKind.Value extra

let disasm (ins: Instruction) (builder: IDisasmBuilder) =
  builder.AccumulateAddrMarker ins.Address
  buildOpcode ins builder

// vim: set tw=80 sts=2 sw=2:
