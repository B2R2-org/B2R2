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

let sideEffects insInfo name bld =
  bld <!-- (insInfo.Address, insInfo.NumBytes)
  bld <+ AST.sideEffect name
  bld --!> insInfo.NumBytes

let nop insInfo bld =
  bld <!-- (insInfo.Address, insInfo.NumBytes)
  bld --!> insInfo.NumBytes

let private getSPSize size = numI32 (32 * size) 256<rt>

/// Pushes an element to stack.
let private pushToStack bld expr =
  let spReg = regVar bld R.SP
  let expr = if OperationSize.regType = TypeCheck.typeOf expr then expr
             else AST.zext OperationSize.regType expr
  bld <+ (spReg := (spReg .+ (getSPSize 1))) (* SP := SP + 32 *)
  bld <+ (AST.store Endian.Big spReg expr) (* [SP] := expr *)

/// Pops an element from stack and returns the element.
let private popFromStack bld =
  let spReg = regVar bld R.SP
  let tmp = bld.Stream.NewTempVar OperationSize.regType
  bld <+ (tmp := AST.loadBE (OperationSize.regType) spReg) (* tmp := [SP] *)
  bld <+ (spReg := (spReg .- (getSPSize 1))) (* SP := SP - 32 *)
  tmp

// Peek the 'pos'-th item.
let private peekStack bld pos =
  let spReg = regVar bld R.SP
  let regType = OperationSize.regType
  let tmp = bld.Stream.NewTempVar regType
  bld <+ (tmp := AST.loadBE regType (spReg .- (getSPSize (pos - 1))))
  tmp

// Swap the topmost item with ('pos' + 1)-th item.
let private swapStack bld pos =
  let spReg = regVar bld R.SP
  let regType = OperationSize.regType
  let tmp1 = bld.Stream.NewTempVar regType
  let tmp2 = bld.Stream.NewTempVar regType
  bld <+ (tmp1 := AST.loadBE regType spReg)
  bld <+ (tmp2 := AST.loadBE regType (spReg .- (getSPSize pos)))
  bld <+ (AST.store Endian.Big (spReg .- (getSPSize pos)) tmp1)
  bld <+ (AST.store Endian.Big spReg tmp2)

let startBasicOperation insInfo bld =
  bld <!-- (insInfo.Address, insInfo.NumBytes)

let endBasicOperation bld opFn src1 src2 insInfo =
  pushToStack bld (opFn src1 src2)
  updateGas bld insInfo.GAS
  bld --!> insInfo.NumBytes

/// Binary operations and relative operations.
let basicOperation insInfo bld opFn =
  startBasicOperation insInfo bld
  let src1, src2 = popFromStack bld, popFromStack bld
  endBasicOperation bld opFn src1 src2 insInfo

/// Shift operations. They use the flipped order of operands.
let shiftOperation insInfo bld opFn =
  startBasicOperation insInfo bld
  let src1, src2 = popFromStack bld, popFromStack bld
  endBasicOperation bld opFn src2 src1 insInfo

let add insInfo bld = basicOperation insInfo bld (.+)
let mul insInfo bld = basicOperation insInfo bld (.*)
let sub insInfo bld = basicOperation insInfo bld (.-)
let div insInfo bld = basicOperation insInfo bld (./)
let sdiv insInfo bld = basicOperation insInfo bld (?/)
let modu insInfo bld = basicOperation insInfo bld (.%)
let smod insInfo bld = basicOperation insInfo bld (?%)
let lt insInfo bld = basicOperation insInfo bld AST.lt
let gt insInfo bld = basicOperation insInfo bld AST.gt
let slt insInfo bld = basicOperation insInfo bld AST.slt
let sgt insInfo bld = basicOperation insInfo bld AST.sgt
let eq insInfo bld = basicOperation insInfo bld (==)
let logAnd insInfo bld = basicOperation insInfo bld (.&)
let logOr insInfo bld = basicOperation insInfo bld (.|)
let xor insInfo bld = basicOperation insInfo bld (<+>)
let shl insInfo bld = shiftOperation insInfo bld (<<)
let shr insInfo bld = shiftOperation insInfo bld (>>)
let sar insInfo bld = shiftOperation insInfo bld (?>>)

let addmod insInfo bld =
  bld <!-- (insInfo.Address, insInfo.NumBytes)
  let src1 = popFromStack bld
  let src2 = popFromStack bld
  let src3 = popFromStack bld
  let expr = (src1 .+ src2) .% src3
  pushToStack bld expr
  updateGas bld insInfo.GAS
  bld --!> insInfo.NumBytes

let mulmod insInfo bld =
  bld <!-- (insInfo.Address, insInfo.NumBytes)
  let src1 = popFromStack bld
  let src2 = popFromStack bld
  let src3 = popFromStack bld
  let expr = (src1 .* src2) .% src3
  pushToStack bld expr
  updateGas bld insInfo.GAS
  bld --!> insInfo.NumBytes

let private makeNum i = numI32 i OperationSize.regType

let signextend insInfo bld =
  bld <!-- (insInfo.Address, insInfo.NumBytes)
  let b = popFromStack bld
  let x = popFromStack bld
  let expr = x .& (makeNum 1 << ((b .+ makeNum 1) .* makeNum 8) .- makeNum 1)
  let sext = AST.sext 256<rt> expr
  pushToStack bld sext
  updateGas bld insInfo.GAS
  bld --!> insInfo.NumBytes

let iszero insInfo bld =
  bld <!-- (insInfo.Address, insInfo.NumBytes)
  let cond = popFromStack bld
  let rt = OperationSize.regType
  let expr = AST.zext rt (cond == AST.num0 rt)
  pushToStack bld expr
  updateGas bld insInfo.GAS
  bld --!> insInfo.NumBytes

let not insInfo bld =
  bld <!-- (insInfo.Address, insInfo.NumBytes)
  let e = popFromStack bld
  let expr = AST.zext OperationSize.regType (AST.not e)
  pushToStack bld expr
  updateGas bld insInfo.GAS
  bld --!> insInfo.NumBytes

let byte insInfo bld =
  bld <!-- (insInfo.Address, insInfo.NumBytes)
  let n = popFromStack bld
  let x = popFromStack bld
  let expr = (x >> (makeNum 248 .- n .* makeNum 8)) .& makeNum 0xff
  pushToStack bld expr
  updateGas bld insInfo.GAS
  bld --!> insInfo.NumBytes

let pop insInfo bld =
  bld <!-- (insInfo.Address, insInfo.NumBytes)
  popFromStack bld |> ignore
  updateGas bld insInfo.GAS
  bld --!> insInfo.NumBytes

let mload insInfo bld =
  bld <!-- (insInfo.Address, insInfo.NumBytes)
  let addr = popFromStack bld
  let expr = AST.loadBE OperationSize.regType addr
  pushToStack bld expr
  updateGas bld insInfo.GAS
  bld --!> insInfo.NumBytes

let mstore insInfo bld =
  bld <!-- (insInfo.Address, insInfo.NumBytes)
  let addr = popFromStack bld
  let value = popFromStack bld
  bld <+ AST.store Endian.Big addr value
  updateGas bld insInfo.GAS
  bld --!> insInfo.NumBytes

let mstore8 insInfo bld =
  bld <!-- (insInfo.Address, insInfo.NumBytes)
  let addr = popFromStack bld
  let value = popFromStack bld
  let lsb = AST.extract value 8<rt> 0
  bld <+ AST.store Endian.Big addr lsb
  updateGas bld insInfo.GAS
  bld --!> insInfo.NumBytes

let jump insInfo bld =
  try
    bld <!-- (insInfo.Address, insInfo.NumBytes)
    let dst = popFromStack bld
    let dstAddr = dst .+ (numU64 insInfo.Offset 256<rt>)
    updateGas bld insInfo.GAS
    bld <+ AST.interjmp dstAddr InterJmpKind.Base
    bld --!> insInfo.NumBytes
  with
    | :? System.InvalidOperationException -> (* Special case: terminate func. *)
      sideEffects insInfo Terminate bld

let jumpi insInfo bld =
  bld <!-- (insInfo.Address, insInfo.NumBytes)
  let dst = popFromStack bld
  let dstAddr = dst .+ (numU64 insInfo.Offset 256<rt>)
  let cond = popFromStack bld
  let fall = numU64 (insInfo.Address + 1UL) 64<rt>
  updateGas bld insInfo.GAS
  bld <+ AST.intercjmp (AST.xtlo 1<rt> cond) dstAddr fall
  bld --!> insInfo.NumBytes

let getpc insInfo bld =
  bld <!-- (insInfo.Address, insInfo.NumBytes)
  let expr = regVar bld R.PC |> AST.zext OperationSize.regType
  pushToStack bld expr
  updateGas bld insInfo.GAS
  bld --!> insInfo.NumBytes

let gas insInfo bld =
  bld <!-- (insInfo.Address, insInfo.NumBytes)
  let expr = AST.zext OperationSize.regType (regVar bld R.GAS)
  pushToStack bld expr
  updateGas bld insInfo.GAS
  bld --!> insInfo.NumBytes

let push insInfo bld imm =
  bld <!-- (insInfo.Address, insInfo.NumBytes)
  let expr = BitVector.Cast (imm, 256<rt>) |> AST.num
  pushToStack bld expr
  updateGas bld insInfo.GAS
  bld --!> insInfo.NumBytes

let dup insInfo bld pos =
  bld <!-- (insInfo.Address, insInfo.NumBytes)
  let src = peekStack bld pos
  pushToStack bld src
  updateGas bld insInfo.GAS
  bld --!> insInfo.NumBytes

let swap insInfo bld pos =
  bld <!-- (insInfo.Address, insInfo.NumBytes)
  swapStack bld pos
  updateGas bld insInfo.GAS
  bld --!> insInfo.NumBytes

let callExternFunc insInfo bld name argCount doesRet =
  bld <!-- (insInfo.Address, insInfo.NumBytes)
  let args = List.init argCount (fun _ -> popFromStack bld)
  let expr = AST.app name args OperationSize.regType
  if doesRet then pushToStack bld expr
  else bld <+ (AST.extCall expr)
  updateGas bld insInfo.GAS
  bld --!> insInfo.NumBytes

let call insInfo bld fname =
  bld <!-- (insInfo.Address, insInfo.NumBytes)
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
  updateGas bld insInfo.GAS
  bld --!> insInfo.NumBytes

let ret insInfo bld =
  popFromStack bld |> ignore
  popFromStack bld |> ignore
  sideEffects insInfo Terminate bld

let selfdestruct insInfo bld =
  popFromStack bld |> ignore
  sideEffects insInfo Terminate bld

let translate insInfo bld =
  match insInfo.Opcode with
  | STOP -> sideEffects insInfo Terminate bld
  | ADD -> add insInfo bld
  | MUL -> mul insInfo bld
  | SUB -> sub insInfo bld
  | DIV -> div insInfo bld
  | SDIV -> sdiv insInfo bld
  | MOD -> modu insInfo bld
  | SMOD -> smod insInfo bld
  | ADDMOD -> addmod insInfo bld
  | MULMOD -> mulmod insInfo bld
  | EXP -> callExternFunc insInfo bld "exp" 2 true
  | SIGNEXTEND -> signextend insInfo bld
  | LT -> lt insInfo bld
  | GT -> gt insInfo bld
  | SLT -> slt insInfo bld
  | SGT -> sgt insInfo bld
  | EQ -> eq insInfo bld
  | ISZERO -> iszero insInfo bld
  | AND -> logAnd insInfo bld
  | OR -> logOr insInfo bld
  | XOR -> xor insInfo bld
  | NOT -> not insInfo bld
  | BYTE -> byte insInfo bld
  | SHL -> shl insInfo bld
  | SHR -> shr insInfo bld
  | SAR -> sar insInfo bld
  | SHA3 -> callExternFunc insInfo bld "keccak256" 2 true
  | ADDRESS -> callExternFunc insInfo bld "address" 0 true
  | BALANCE -> callExternFunc insInfo bld "balance" 1 true
  | ORIGIN -> callExternFunc insInfo bld "tx.origin" 0 true
  | CALLER -> callExternFunc insInfo bld "msg.sender" 0 true
  | CALLVALUE -> callExternFunc insInfo bld "msg.value" 0 true
  | CALLDATALOAD -> callExternFunc insInfo bld "msg.data" 1 true
  | CALLDATASIZE -> callExternFunc insInfo bld "msg.data.size" 0 true
  | CALLDATACOPY -> callExternFunc insInfo bld "calldatacopy" 3 false
  | CODESIZE -> callExternFunc insInfo bld "codesize" 0 true
  | CODECOPY -> callExternFunc insInfo bld "codecopy" 3 false
  | GASPRICE -> callExternFunc insInfo bld "tx.gasprice" 0 true
  | EXTCODESIZE -> callExternFunc insInfo bld "extcodesize" 1 true
  | EXTCODECOPY -> callExternFunc insInfo bld "extcodecopy" 4 false
  | RETURNDATASIZE -> callExternFunc insInfo bld "returndatasize" 0 true
  | RETURNDATACOPY -> callExternFunc insInfo bld "returndatacopy" 3 false
  | EXTCODEHASH -> callExternFunc insInfo bld "extcodehash" 1 true
  | BLOCKHASH -> callExternFunc insInfo bld "blockhash" 1 true
  | COINBASE -> callExternFunc insInfo bld "block.coinbase" 0 true
  | TIMESTAMP -> callExternFunc insInfo bld "block.timestamp" 0 true
  | NUMBER -> callExternFunc insInfo bld "block.number" 0 true
  | DIFFICULTY -> callExternFunc insInfo bld "block.difficulty" 0 true
  | GASLIMIT -> callExternFunc insInfo bld "block.gaslimit" 0 true
  | CHAINID -> callExternFunc insInfo bld "chainid" 0 true
  | SELFBALANCE -> callExternFunc insInfo bld "selfbalance" 0 true
  | BASEFEE -> callExternFunc insInfo bld "basefee" 0 true
  | POP -> pop insInfo bld
  | MLOAD -> mload insInfo bld
  | MSTORE -> mstore insInfo bld
  | MSTORE8 -> mstore8 insInfo bld
  | SLOAD -> callExternFunc insInfo bld "sload" 1 true
  | SSTORE -> callExternFunc insInfo bld "sstore" 2 false
  | JUMP -> jump insInfo bld
  | JUMPI -> jumpi insInfo bld
  | GETPC -> getpc insInfo bld
  | MSIZE -> callExternFunc insInfo bld "msize" 0 true
  | GAS -> gas insInfo bld
  | JUMPDEST -> nop insInfo bld
  | PUSH1 imm -> push insInfo bld imm
  | PUSH2 imm -> push insInfo bld imm
  | PUSH3 imm -> push insInfo bld imm
  | PUSH4 imm -> push insInfo bld imm
  | PUSH5 imm -> push insInfo bld imm
  | PUSH6 imm -> push insInfo bld imm
  | PUSH7 imm -> push insInfo bld imm
  | PUSH8 imm -> push insInfo bld imm
  | PUSH9 imm -> push insInfo bld imm
  | PUSH10 imm -> push insInfo bld imm
  | PUSH11 imm -> push insInfo bld imm
  | PUSH12 imm -> push insInfo bld imm
  | PUSH13 imm -> push insInfo bld imm
  | PUSH14 imm -> push insInfo bld imm
  | PUSH15 imm -> push insInfo bld imm
  | PUSH16 imm -> push insInfo bld imm
  | PUSH17 imm -> push insInfo bld imm
  | PUSH18 imm -> push insInfo bld imm
  | PUSH19 imm -> push insInfo bld imm
  | PUSH20 imm -> push insInfo bld imm
  | PUSH21 imm -> push insInfo bld imm
  | PUSH22 imm -> push insInfo bld imm
  | PUSH23 imm -> push insInfo bld imm
  | PUSH24 imm -> push insInfo bld imm
  | PUSH25 imm -> push insInfo bld imm
  | PUSH26 imm -> push insInfo bld imm
  | PUSH27 imm -> push insInfo bld imm
  | PUSH28 imm -> push insInfo bld imm
  | PUSH29 imm -> push insInfo bld imm
  | PUSH30 imm -> push insInfo bld imm
  | PUSH31 imm -> push insInfo bld imm
  | PUSH32 imm -> push insInfo bld imm
  | DUP1 -> dup insInfo bld 1
  | DUP2 -> dup insInfo bld 2
  | DUP3 -> dup insInfo bld 3
  | DUP4 -> dup insInfo bld 4
  | DUP5 -> dup insInfo bld 5
  | DUP6 -> dup insInfo bld 6
  | DUP7 -> dup insInfo bld 7
  | DUP8 -> dup insInfo bld 8
  | DUP9 -> dup insInfo bld 9
  | DUP10 -> dup insInfo bld 10
  | DUP11 -> dup insInfo bld 11
  | DUP12 -> dup insInfo bld 12
  | DUP13 -> dup insInfo bld 13
  | DUP14 -> dup insInfo bld 14
  | DUP15 -> dup insInfo bld 15
  | DUP16 -> dup insInfo bld 16
  | SWAP1 -> swap insInfo bld 1
  | SWAP2 -> swap insInfo bld 2
  | SWAP3 -> swap insInfo bld 3
  | SWAP4 -> swap insInfo bld 4
  | SWAP5 -> swap insInfo bld 5
  | SWAP6 -> swap insInfo bld 6
  | SWAP7 -> swap insInfo bld 7
  | SWAP8 -> swap insInfo bld 8
  | SWAP9 -> swap insInfo bld 9
  | SWAP10 -> swap insInfo bld 10
  | SWAP11 -> swap insInfo bld 11
  | SWAP12 -> swap insInfo bld 12
  | SWAP13 -> swap insInfo bld 13
  | SWAP14 -> swap insInfo bld 14
  | SWAP15 -> swap insInfo bld 15
  | SWAP16 -> swap insInfo bld 16
  | RETURN | REVERT -> ret insInfo bld
  | CALL -> callExternFunc insInfo bld "call" 7 true
  | CALLCODE -> callExternFunc insInfo bld "callcode" 7 true
  | LOG0 -> callExternFunc insInfo bld "log0" 2 false
  | LOG1 -> callExternFunc insInfo bld "log1" 3 false
  | LOG2 -> callExternFunc insInfo bld "log2" 4 false
  | LOG3 -> callExternFunc insInfo bld "log3" 5 false
  | LOG4 -> callExternFunc insInfo bld "log4" 6 false
  | CREATE -> callExternFunc insInfo bld "create" 3 true
  | DELEGATECALL -> callExternFunc insInfo bld "delegatecall" 6 true
  | CREATE2 -> callExternFunc insInfo bld "create2" 4 true
  | STATICCALL -> callExternFunc insInfo bld "staticcall" 6 true
  | INVALID -> sideEffects insInfo Terminate bld
  | SELFDESTRUCT -> selfdestruct insInfo bld
