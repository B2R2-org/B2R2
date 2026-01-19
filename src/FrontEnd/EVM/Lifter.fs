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

module internal B2R2.FrontEnd.EVM.Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.EVM

let inline private updateGas bld gas =
  let gasReg = regVar bld R.GAS
  bld <+ (gasReg := gasReg .+ numI32 gas 64<rt>)

let sideEffects name bld = bld <+ AST.sideEffect name

let private getSPSize size = numI32 (32 * size) 256<rt>

/// Pushes an element to stack.
let private pushToStack bld expr =
  let spReg = regVar bld R.SP
  let expr = if OperationSize.regType = Expr.TypeOf expr then expr
             else AST.zext OperationSize.regType expr
  bld <+ (spReg := (spReg .- (getSPSize 1))) (* SP := SP - 32 *)
  bld <+ (AST.store Endian.Big spReg expr) (* [SP] := expr *)

/// Pops an element from stack and returns the element.
let private popFromStack bld =
  let spReg = regVar bld R.SP
  let tmp = bld.Stream.NewTempVar OperationSize.regType
  bld <+ (tmp := AST.loadBE (OperationSize.regType) spReg) (* tmp := [SP] *)
  bld <+ (spReg := (spReg .+ (getSPSize 1))) (* SP := SP + 32 *)
  tmp

/// Peek the 'pos'-th item.
let private peekStack bld pos =
  let spReg = regVar bld R.SP
  let regType = OperationSize.regType
  let tmp = bld.Stream.NewTempVar regType
  bld <+ (tmp := AST.loadBE regType (spReg .+ (getSPSize (pos - 1))))
  tmp

/// Swap the topmost item with ('pos' + 1)-th item.
let private swapStack bld pos =
  let spReg = regVar bld R.SP
  let regType = OperationSize.regType
  let tmp1 = bld.Stream.NewTempVar regType
  let tmp2 = bld.Stream.NewTempVar regType
  bld <+ (tmp1 := AST.loadBE regType spReg)
  bld <+ (tmp2 := AST.loadBE regType (spReg .+ (getSPSize pos)))
  bld <+ (AST.store Endian.Big (spReg .+ (getSPSize pos)) tmp1)
  bld <+ (AST.store Endian.Big spReg tmp2)

let endBasicOperation bld opFn src1 src2 (ins: Instruction) =
  pushToStack bld (opFn src1 src2)
  updateGas bld ins.GAS

/// Binary operations and relative operations.
let basicOperation ins bld opFn =
  let src1, src2 = popFromStack bld, popFromStack bld
  endBasicOperation bld opFn src1 src2 ins

/// Shift operations. They use the flipped order of operands.
let shiftOperation ins bld opFn =
  let src1, src2 = popFromStack bld, popFromStack bld
  endBasicOperation bld opFn src2 src1 ins

let add ins bld = basicOperation ins bld (.+)

let mul ins bld = basicOperation ins bld (.*)

let sub ins bld = basicOperation ins bld (.-)

let div ins bld = basicOperation ins bld (./)

let sdiv ins bld = basicOperation ins bld (?/)

let modu ins bld = basicOperation ins bld (.%)

let smod ins bld = basicOperation ins bld (?%)

let lt ins bld = basicOperation ins bld AST.lt

let gt ins bld = basicOperation ins bld AST.gt

let slt ins bld = basicOperation ins bld AST.slt

let sgt ins bld = basicOperation ins bld AST.sgt

let eq ins bld = basicOperation ins bld (==)

let logAnd ins bld = basicOperation ins bld (.&)

let logOr ins bld = basicOperation ins bld (.|)

let xor ins bld = basicOperation ins bld (<+>)

let shl ins bld = shiftOperation ins bld (<<)

let shr ins bld = shiftOperation ins bld (>>)

let sar ins bld = shiftOperation ins bld (?>>)

let addmod (ins: Instruction) bld =
  let src1 = popFromStack bld
  let src2 = popFromStack bld
  let src3 = popFromStack bld
  let expr = (src1 .+ src2) .% src3
  pushToStack bld expr
  updateGas bld ins.GAS

let mulmod (ins: Instruction) bld =
  let src1 = popFromStack bld
  let src2 = popFromStack bld
  let src3 = popFromStack bld
  let expr = (src1 .* src2) .% src3
  pushToStack bld expr
  updateGas bld ins.GAS

let private makeNum i = numI32 i OperationSize.regType

let signextend (ins: Instruction) bld =
  let b = popFromStack bld
  let x = popFromStack bld
  let expr = x .& (makeNum 1 << ((b .+ makeNum 1) .* makeNum 8) .- makeNum 1)
  let sext = AST.sext 256<rt> expr
  pushToStack bld sext
  updateGas bld ins.GAS

let iszero (ins: Instruction) bld =
  let cond = popFromStack bld
  let rt = OperationSize.regType
  let expr = AST.zext rt (cond == AST.num0 rt)
  pushToStack bld expr
  updateGas bld ins.GAS

let not (ins: Instruction) bld =
  let e = popFromStack bld
  let expr = AST.zext OperationSize.regType (AST.not e)
  pushToStack bld expr
  updateGas bld ins.GAS

let byte (ins: Instruction) bld =
  let n = popFromStack bld
  let x = popFromStack bld
  let expr = (x >> (makeNum 248 .- n .* makeNum 8)) .& makeNum 0xff
  pushToStack bld expr
  updateGas bld ins.GAS

let pop (ins: Instruction) bld =
  popFromStack bld |> ignore
  updateGas bld ins.GAS

let jump (ins: Instruction) bld =
  try
    let dst = popFromStack bld
    let dstAddr = dst .+ (numU64 ins.Offset 256<rt>)
    updateGas bld ins.GAS
    bld <+ AST.interjmp dstAddr InterJmpKind.Base
  with
    :? System.InvalidOperationException -> (* Special case: terminate func. *)
      sideEffects Terminate bld

let jumpi (ins: Instruction) bld =
  let dst = popFromStack bld
  let dstAddr = dst .+ (numU64 ins.Offset 256<rt>)
  let cond = popFromStack bld
  let fall = numU64 (ins.Address + 1UL) 64<rt>
  updateGas bld ins.GAS
  bld <+ AST.intercjmp (AST.xtlo 1<rt> cond) dstAddr fall

let getpc (ins: Instruction) bld =
  let expr = regVar bld R.PC |> AST.zext OperationSize.regType
  pushToStack bld expr
  updateGas bld ins.GAS

let gas (ins: Instruction) bld =
  let expr = AST.zext OperationSize.regType (regVar bld R.GAS)
  pushToStack bld expr
  updateGas bld ins.GAS

let push (ins: Instruction) bld imm =
  let expr = BitVector.Cast(imm, 256<rt>) |> AST.num
  pushToStack bld expr
  updateGas bld ins.GAS

let dup (ins: Instruction) bld pos =
  let src = peekStack bld pos
  pushToStack bld src
  updateGas bld ins.GAS

let swap (ins: Instruction) bld pos =
  swapStack bld pos
  updateGas bld ins.GAS

let callExternFunc (ins: Instruction) bld name argCount doesRet =
  let args = List.init argCount (fun _ -> popFromStack bld)
  let expr = AST.app name args OperationSize.regType
  if doesRet then pushToStack bld expr
  else bld <+ (AST.extCall expr)
  updateGas bld ins.GAS

let call (ins: Instruction) bld fname =
  let gas = popFromStack bld
  let addr = popFromStack bld
  let value = popFromStack bld
  let argsOffset = popFromStack bld
  let argsLength = popFromStack bld
  let retOffset = popFromStack bld
  let retLength = popFromStack bld
  let args = [ gas; addr; value; argsOffset; argsLength; retOffset; retLength ]
  let expr = AST.app fname args OperationSize.regType
  pushToStack bld expr
  updateGas bld ins.GAS

let callAndTerminate ins name argCount bld =
  callExternFunc ins bld name argCount false
  sideEffects Terminate bld

let private translateOpcode ins bld = function
  | STOP -> sideEffects Terminate bld
  | ADD -> add ins bld
  | MUL -> mul ins bld
  | SUB -> sub ins bld
  | DIV -> div ins bld
  | SDIV -> sdiv ins bld
  | MOD -> modu ins bld
  | SMOD -> smod ins bld
  | ADDMOD -> addmod ins bld
  | MULMOD -> mulmod ins bld
  | EXP -> callExternFunc ins bld "exp" 2 true
  | SIGNEXTEND -> signextend ins bld
  | LT -> lt ins bld
  | GT -> gt ins bld
  | SLT -> slt ins bld
  | SGT -> sgt ins bld
  | EQ -> eq ins bld
  | ISZERO -> iszero ins bld
  | AND -> logAnd ins bld
  | OR -> logOr ins bld
  | XOR -> xor ins bld
  | NOT -> not ins bld
  | BYTE -> byte ins bld
  | SHL -> shl ins bld
  | SHR -> shr ins bld
  | SAR -> sar ins bld
  | SHA3 -> callExternFunc ins bld "keccak256" 2 true
  | ADDRESS -> callExternFunc ins bld "address" 0 true
  | BALANCE -> callExternFunc ins bld "balance" 1 true
  | ORIGIN -> callExternFunc ins bld "tx.origin" 0 true
  | CALLER -> callExternFunc ins bld "msg.sender" 0 true
  | CALLVALUE -> callExternFunc ins bld "msg.value" 0 true
  | CALLDATALOAD -> callExternFunc ins bld "msg.data" 1 true
  | CALLDATASIZE -> callExternFunc ins bld "msg.data.size" 0 true
  | CALLDATACOPY -> callExternFunc ins bld "calldatacopy" 3 false
  | CODESIZE -> callExternFunc ins bld "codesize" 0 true
  | CODECOPY -> callExternFunc ins bld "codecopy" 3 false
  | GASPRICE -> callExternFunc ins bld "tx.gasprice" 0 true
  | EXTCODESIZE -> callExternFunc ins bld "extcodesize" 1 true
  | EXTCODECOPY -> callExternFunc ins bld "extcodecopy" 4 false
  | RETURNDATASIZE -> callExternFunc ins bld "returndatasize" 0 true
  | RETURNDATACOPY -> callExternFunc ins bld "returndatacopy" 3 false
  | EXTCODEHASH -> callExternFunc ins bld "extcodehash" 1 true
  | BLOCKHASH -> callExternFunc ins bld "blockhash" 1 true
  | COINBASE -> callExternFunc ins bld "block.coinbase" 0 true
  | TIMESTAMP -> callExternFunc ins bld "block.timestamp" 0 true
  | NUMBER -> callExternFunc ins bld "block.number" 0 true
  | DIFFICULTY -> callExternFunc ins bld "block.difficulty" 0 true
  | GASLIMIT -> callExternFunc ins bld "block.gaslimit" 0 true
  | CHAINID -> callExternFunc ins bld "chainid" 0 true
  | SELFBALANCE -> callExternFunc ins bld "selfbalance" 0 true
  | BASEFEE -> callExternFunc ins bld "basefee" 0 true
  | POP -> pop ins bld
  | MLOAD -> callExternFunc ins bld "mload" 1 true
  | MSTORE -> callExternFunc ins bld "mstore" 2 false
  | MSTORE8 -> callExternFunc ins bld "mstore8" 2 false
  | SLOAD -> callExternFunc ins bld "sload" 1 true
  | SSTORE -> callExternFunc ins bld "sstore" 2 false
  | JUMP -> jump ins bld
  | JUMPI -> jumpi ins bld
  | GETPC -> getpc ins bld
  | MSIZE -> callExternFunc ins bld "msize" 0 true
  | GAS -> gas ins bld
  | JUMPDEST -> ()
  | TLOAD -> callExternFunc ins bld "tload" 1 true
  | TSTORE -> callExternFunc ins bld "tstore" 2 false
  | MCOPY -> callExternFunc ins bld "mcopy" 3 false
  | PUSH0 -> push ins bld (BitVector.Zero 256<rt>)
  | PUSH1 imm -> push ins bld imm
  | PUSH2 imm -> push ins bld imm
  | PUSH3 imm -> push ins bld imm
  | PUSH4 imm -> push ins bld imm
  | PUSH5 imm -> push ins bld imm
  | PUSH6 imm -> push ins bld imm
  | PUSH7 imm -> push ins bld imm
  | PUSH8 imm -> push ins bld imm
  | PUSH9 imm -> push ins bld imm
  | PUSH10 imm -> push ins bld imm
  | PUSH11 imm -> push ins bld imm
  | PUSH12 imm -> push ins bld imm
  | PUSH13 imm -> push ins bld imm
  | PUSH14 imm -> push ins bld imm
  | PUSH15 imm -> push ins bld imm
  | PUSH16 imm -> push ins bld imm
  | PUSH17 imm -> push ins bld imm
  | PUSH18 imm -> push ins bld imm
  | PUSH19 imm -> push ins bld imm
  | PUSH20 imm -> push ins bld imm
  | PUSH21 imm -> push ins bld imm
  | PUSH22 imm -> push ins bld imm
  | PUSH23 imm -> push ins bld imm
  | PUSH24 imm -> push ins bld imm
  | PUSH25 imm -> push ins bld imm
  | PUSH26 imm -> push ins bld imm
  | PUSH27 imm -> push ins bld imm
  | PUSH28 imm -> push ins bld imm
  | PUSH29 imm -> push ins bld imm
  | PUSH30 imm -> push ins bld imm
  | PUSH31 imm -> push ins bld imm
  | PUSH32 imm -> push ins bld imm
  | DUP1 -> dup ins bld 1
  | DUP2 -> dup ins bld 2
  | DUP3 -> dup ins bld 3
  | DUP4 -> dup ins bld 4
  | DUP5 -> dup ins bld 5
  | DUP6 -> dup ins bld 6
  | DUP7 -> dup ins bld 7
  | DUP8 -> dup ins bld 8
  | DUP9 -> dup ins bld 9
  | DUP10 -> dup ins bld 10
  | DUP11 -> dup ins bld 11
  | DUP12 -> dup ins bld 12
  | DUP13 -> dup ins bld 13
  | DUP14 -> dup ins bld 14
  | DUP15 -> dup ins bld 15
  | DUP16 -> dup ins bld 16
  | SWAP1 -> swap ins bld 1
  | SWAP2 -> swap ins bld 2
  | SWAP3 -> swap ins bld 3
  | SWAP4 -> swap ins bld 4
  | SWAP5 -> swap ins bld 5
  | SWAP6 -> swap ins bld 6
  | SWAP7 -> swap ins bld 7
  | SWAP8 -> swap ins bld 8
  | SWAP9 -> swap ins bld 9
  | SWAP10 -> swap ins bld 10
  | SWAP11 -> swap ins bld 11
  | SWAP12 -> swap ins bld 12
  | SWAP13 -> swap ins bld 13
  | SWAP14 -> swap ins bld 14
  | SWAP15 -> swap ins bld 15
  | SWAP16 -> swap ins bld 16
  | RETURN -> callAndTerminate ins "return" 2 bld
  | REVERT -> callAndTerminate ins "revert" 2 bld
  | CALL -> callExternFunc ins bld "call" 7 true
  | CALLCODE -> callExternFunc ins bld "callcode" 7 true
  | LOG0 -> callExternFunc ins bld "log0" 2 false
  | LOG1 -> callExternFunc ins bld "log1" 3 false
  | LOG2 -> callExternFunc ins bld "log2" 4 false
  | LOG3 -> callExternFunc ins bld "log3" 5 false
  | LOG4 -> callExternFunc ins bld "log4" 6 false
  | CREATE -> callExternFunc ins bld "create" 3 true
  | DELEGATECALL -> callExternFunc ins bld "delegatecall" 6 true
  | CREATE2 -> callExternFunc ins bld "create2" 4 true
  | STATICCALL -> callExternFunc ins bld "staticcall" 6 true
  | INVALID -> sideEffects Terminate bld
  | SELFDESTRUCT -> callAndTerminate ins "selfdestruct" 1 bld

let translate (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.NumBytes)
  translateOpcode ins bld ins.Opcode
  bld --!> ins.NumBytes
