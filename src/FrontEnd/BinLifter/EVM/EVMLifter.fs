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

module internal B2R2.FrontEnd.BinLifter.EVM.Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.EVM

let inline private getRegVar (ctxt: TranslationContext) name =
  Register.toRegID name |> ctxt.GetRegVar

let inline private (<!) (builder: IRBuilder) (s) = builder.Append (s)

let inline private startMark insInfo (builder: IRBuilder) =
  builder <! (AST.ismark (insInfo.NumBytes))

let inline private endMark insInfo (builder: IRBuilder) =
  builder <! (AST.iemark (insInfo.NumBytes)); builder

let inline private numI32 n t = BitVector.ofInt32 n t |> AST.num
let inline private numU64 n t = BitVector.ofUInt64 n t |> AST.num

let inline private updateGas ctxt gas builder =
  let gasReg = getRegVar ctxt R.GAS
  builder <! (gasReg := gasReg .+ numI32 gas 64<rt>)

let sideEffects insInfo name =
  let builder = new IRBuilder (4)
  startMark insInfo builder
  builder <! AST.sideEffect name
  endMark insInfo builder

let nop insInfo =
  let builder = new IRBuilder (4)
  startMark insInfo builder
  endMark insInfo builder

let private getSPSize size = numI32 (32 * size) 256<rt>

/// Pushes an element to stack.
let private pushToStack (ctxt: TranslationContext) expr builder =
  let spReg = getRegVar ctxt R.SP
  let tmp = AST.tmpvar OperationSize.regType
  let expr = if OperationSize.regType = TypeCheck.typeOf expr then expr
             else AST.zext OperationSize.regType expr
  builder <! (spReg := (spReg .+ (getSPSize 1))) (* SP := SP + 32 *)
  builder <! (tmp := expr)                       (* tmp := expr *)
  builder <! (AST.store Endian.Little spReg tmp) (* [SP] := tmp *)

/// Pops an element from stack and returns the element.
let private popFromStack (ctxt: TranslationContext) builder =
  let spReg = getRegVar ctxt R.SP
  let tmp = AST.tmpvar OperationSize.regType
  builder <! (tmp := AST.loadLE (OperationSize.regType) spReg) (* tmp := [SP] *)
  builder <! (spReg := (spReg .- (getSPSize 1)))           (* SP := SP - 32 *)
  tmp

let private peekStack (ctxt: TranslationContext) pos builder =
  let spReg = getRegVar ctxt R.SP
  let regType = OperationSize.regType
  let tmp = AST.tmpvar regType
  builder <! (tmp := AST.loadLE regType (spReg .- (getSPSize (pos - 1))))
  tmp

let private swapStack (ctxt: TranslationContext) pos builder=
  let spReg = getRegVar ctxt R.SP
  let regType = OperationSize.regType
  let tmp1 = AST.tmpvar regType
  let tmp2 = AST.tmpvar regType
  builder <! (tmp1 := AST.loadLE regType spReg)
  builder <! (tmp2 := AST.loadLE regType (spReg .- (getSPSize (pos - 1))))
  builder <! (AST.store Endian.Little (spReg .- (getSPSize (pos - 1))) tmp1)
  builder <! (AST.store Endian.Little spReg tmp2)

/// Binary operations and relative operations.
let basicOperation insInfo ctxt opFn =
  let builder = new IRBuilder (12)
  startMark insInfo builder
  let src1 = popFromStack ctxt builder
  let src2 = popFromStack ctxt builder
  pushToStack ctxt (opFn src1 src2) builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let add insInfo ctxt = basicOperation insInfo ctxt (.+)
let mul insInfo ctxt = basicOperation insInfo ctxt (.*)
let sub insInfo ctxt = basicOperation insInfo ctxt (.-)
let div insInfo ctxt = basicOperation insInfo ctxt (./)
let sdiv insInfo ctxt = basicOperation insInfo ctxt (?/)
let modu insInfo ctxt = basicOperation insInfo ctxt (.%)
let smod insInfo ctxt = basicOperation insInfo ctxt (?%)
let lt insInfo ctxt = basicOperation insInfo ctxt AST.lt
let gt insInfo ctxt = basicOperation insInfo ctxt AST.gt
let slt insInfo ctxt = basicOperation insInfo ctxt AST.slt
let sgt insInfo ctxt = basicOperation insInfo ctxt AST.sgt
let eq insInfo ctxt = basicOperation insInfo ctxt (==)
let logAnd insInfo ctxt = basicOperation insInfo ctxt (.&)
let logOr insInfo ctxt = basicOperation insInfo ctxt (.|)
let xor insInfo ctxt = basicOperation insInfo ctxt (<+>)
let shl insInfo ctxt = basicOperation insInfo ctxt (<<)
let shr insInfo ctxt = basicOperation insInfo ctxt (>>)
let sar insInfo ctxt = basicOperation insInfo ctxt (?>>)

let addmod insInfo ctxt =
  let builder = new IRBuilder (12)
  startMark insInfo builder
  let src1 = popFromStack ctxt builder
  let src2 = popFromStack ctxt builder
  let src3 = popFromStack ctxt builder
  let expr = (src1 .+ src2) .% src3
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let mulmod insInfo ctxt =
  let builder = new IRBuilder (12)
  startMark insInfo builder
  let src1 = popFromStack ctxt builder
  let src2 = popFromStack ctxt builder
  let src3 = popFromStack ctxt builder
  let expr = (src1 .* src2) .% src3
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let private makeNum i =
  AST.num <| BitVector.ofInt32 i OperationSize.regType

let signextend insInfo ctxt =
  let builder = new IRBuilder (12)
  startMark insInfo builder
  let b = popFromStack ctxt builder
  let x = popFromStack ctxt builder
  let expr = x .& (makeNum 1 << ((b .+ makeNum 1) .* makeNum 8) .- makeNum 1)
  let sext = AST.sext 256<rt> expr
  pushToStack ctxt sext builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let iszero insInfo ctxt =
  let builder = new IRBuilder (8)
  startMark insInfo builder
  let cond = popFromStack ctxt builder
  let rt = OperationSize.regType
  let expr = AST.zext rt (cond == AST.num0 rt)
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let not insInfo ctxt =
  let builder = new IRBuilder (8)
  startMark insInfo builder
  let e = popFromStack ctxt builder
  let expr = AST.zext OperationSize.regType (AST.not e)
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let byte insInfo ctxt =
  let builder = new IRBuilder (12)
  startMark insInfo builder
  let n = popFromStack ctxt builder
  let x = popFromStack ctxt builder
  let expr = (x >> (makeNum 248 .- n .* makeNum 8)) .& makeNum 0xff
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let pop insInfo ctxt =
  let builder = new IRBuilder (8)
  startMark insInfo builder
  popFromStack ctxt builder |> ignore
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let mload insInfo ctxt =
  let builder = new IRBuilder (8)
  startMark insInfo builder
  let addr = popFromStack ctxt builder
  let expr = AST.loadLE OperationSize.regType addr
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let mstore insInfo ctxt =
  let builder = new IRBuilder (12)
  startMark insInfo builder
  let addr = popFromStack ctxt builder
  let value = popFromStack ctxt builder
  updateGas ctxt insInfo.GAS builder
  builder <! (AST.loadLE OperationSize.regType addr := value)
  endMark insInfo builder

let mstore8 insInfo ctxt =
  let builder = new IRBuilder (12)
  startMark insInfo builder
  let addr = popFromStack ctxt builder
  let value = popFromStack ctxt builder
  updateGas ctxt insInfo.GAS builder
  builder <! (AST.loadLE 8<rt> addr := value .& makeNum 0xff)
  endMark insInfo builder

let jump insInfo ctxt =
  let builder = new IRBuilder (8)
  try
    startMark insInfo builder
    let dst = popFromStack ctxt builder
    let dstAddr = dst .+ (BitVector.ofUInt64 insInfo.Offset 256<rt> |> AST.num)
    updateGas ctxt insInfo.GAS builder
    builder <! AST.interjmp dstAddr InterJmpKind.Base
    endMark insInfo builder
  with
    | :? System.InvalidOperationException -> (* Special case: terminate func. *)
      sideEffects insInfo Terminate

let jumpi insInfo ctxt =
  let builder = new IRBuilder (12)
  startMark insInfo builder
  let dst = popFromStack ctxt builder
  let dstAddr = dst .+ (BitVector.ofUInt64 insInfo.Offset 256<rt> |> AST.num)
  let cond = popFromStack ctxt builder
  let fall = numU64 (insInfo.Address + 1UL) 64<rt>
  updateGas ctxt insInfo.GAS builder
  builder <! AST.intercjmp (AST.xtlo 1<rt> cond) dstAddr fall
  endMark insInfo builder

let getpc insInfo ctxt =
  let builder = new IRBuilder (8)
  startMark insInfo builder
  let expr = getRegVar ctxt R.PC |> AST.zext OperationSize.regType
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let gas insInfo ctxt =
  let builder = new IRBuilder (8)
  startMark insInfo builder
  let expr = AST.zext OperationSize.regType (getRegVar ctxt R.GAS)
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let push insInfo ctxt imm =
  let builder = new IRBuilder (8)
  startMark insInfo builder
  let expr = BitVector.cast imm 256<rt> |> AST.num
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let dup insInfo ctxt pos =
  let builder = new IRBuilder (8)
  startMark insInfo builder
  let src = peekStack ctxt pos builder
  pushToStack ctxt src builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let swap insInfo ctxt pos =
  let builder = new IRBuilder (12)
  startMark insInfo builder
  swapStack ctxt pos builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let obtainInfo insInfo ctxt name =
  let builder = new IRBuilder (8)
  startMark insInfo builder
  let expr = AST.app name [] OperationSize.regType
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let address insInfo ctxt =
  let builder = new IRBuilder (8)
  startMark insInfo builder
  let pc = BitVector.ofUInt64 insInfo.Address OperationSize.regType |> AST.num
  pushToStack ctxt pc builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let balance insInfo ctxt =
  let builder = new IRBuilder (8)
  startMark insInfo builder
  let addr = popFromStack ctxt builder
  let expr = AST.app "balance" [ addr ] OperationSize.regType
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let calldataload insInfo ctxt =
  let builder = new IRBuilder (12)
  startMark insInfo builder
  let i = popFromStack ctxt builder
  let length = AST.num1 OperationSize.regType
  let expr = AST.app "msg.data" [ i; length ] OperationSize.regType
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let calldatacopy insInfo ctxt =
  let builder = new IRBuilder (12)
  startMark insInfo builder
  let dstOffset = popFromStack ctxt builder
  let offset = popFromStack ctxt builder
  let length = popFromStack ctxt builder
  let src = AST.app "msg.data" [ offset; length ] OperationSize.regType
  builder <! (AST.loadLE OperationSize.regType dstOffset := src)
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let codecopy insInfo ctxt =
  let builder = new IRBuilder (12)
  startMark insInfo builder
  let dstOffset = popFromStack ctxt builder |> AST.xtlo 64<rt>
  let offset = popFromStack ctxt builder
  let length = popFromStack ctxt builder
  let src = AST.app "code" [ offset; length ] OperationSize.regType
  builder <! (AST.loadLE OperationSize.regType dstOffset := src)
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let extcodecopy insInfo ctxt =
  let builder = new IRBuilder (12)
  startMark insInfo builder
  let addr = popFromStack ctxt builder
  let dstOffset = popFromStack ctxt builder
  let offset = popFromStack ctxt builder
  let length = popFromStack ctxt builder
  let src = AST.app "code" [ addr; offset; length ] OperationSize.regType
  builder <! (AST.loadLE OperationSize.regType dstOffset := src)
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let returndatacopy insInfo ctxt =
  let builder = new IRBuilder (12)
  startMark insInfo builder
  let dstOffset = popFromStack ctxt builder
  let offset = popFromStack ctxt builder
  let length = popFromStack ctxt builder
  let src = AST.app "returndata" [ offset; length ] OperationSize.regType
  builder <! (AST.loadLE OperationSize.regType dstOffset := src)
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let codesize insInfo ctxt =
  let builder = new IRBuilder (8)
  startMark insInfo builder
  let expr = AST.app "code.size" [] OperationSize.regType
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let extcodesize insInfo ctxt =
  let builder = new IRBuilder (8)
  startMark insInfo builder
  let addr = popFromStack ctxt builder
  let expr = AST.app "code.size" [ addr ] OperationSize.regType
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let blockhash insInfo ctxt =
  let builder = new IRBuilder (8)
  startMark insInfo builder
  let blockNum = popFromStack ctxt builder
  let expr = AST.app "block.blockHash" [ blockNum ] OperationSize.regType
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let sha3 insInfo ctxt =
  let builder = new IRBuilder (12)
  startMark insInfo builder
  let offset = popFromStack ctxt builder
  let length = popFromStack ctxt builder
  let expr = AST.app "keccak256" [ offset; length ] OperationSize.regType
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let call insInfo ctxt fname =
  let builder = new IRBuilder (20)
  startMark insInfo builder
  let gas = popFromStack ctxt builder
  let addr = popFromStack ctxt builder
  let value = popFromStack ctxt builder
  let argsOffset = popFromStack ctxt builder
  let argsLength = popFromStack ctxt builder
  let retOffset = popFromStack ctxt builder
  let retLength = popFromStack ctxt builder
  let args = [ gas; addr; value; argsOffset; argsLength; retOffset; retLength ]
  let expr = AST.app fname args OperationSize.regType
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let sload insInfo ctxt =
  let builder = new IRBuilder (8)
  startMark insInfo builder
  let key = popFromStack ctxt builder
  let value = AST.app "sload" [key] OperationSize.regType
  pushToStack ctxt value builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let sstore insInfo ctxt =
  let builder = new IRBuilder (8)
  startMark insInfo builder
  let key = popFromStack ctxt builder
  let value = popFromStack ctxt builder
  let t = AST.tmpvar OperationSize.regType
  updateGas ctxt insInfo.GAS builder
  builder <! (t := AST.app "sstore" [ key; value ] OperationSize.regType)
  endMark insInfo builder

let exp insInfo ctxt =
  let builder = new IRBuilder (12)
  startMark insInfo builder
  let a = popFromStack ctxt builder
  let b = popFromStack ctxt builder
  let expr = AST.app "exp" [ a; b ] OperationSize.regType
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let ret insInfo ctxt =
  let builder = new IRBuilder (8)
  popFromStack ctxt builder |> ignore
  popFromStack ctxt builder |> ignore
  sideEffects insInfo Terminate

let selfdestruct insInfo ctxt =
  let builder = new IRBuilder (8)
  popFromStack ctxt builder |> ignore
  sideEffects insInfo Terminate

let translate insInfo (ctxt: TranslationContext) =
  match insInfo.Opcode with
  | STOP -> sideEffects insInfo Terminate
  | ADD -> add insInfo ctxt
  | MUL -> mul insInfo ctxt
  | SUB -> sub insInfo ctxt
  | DIV -> div insInfo ctxt
  | SDIV -> sdiv insInfo ctxt
  | MOD -> modu insInfo ctxt
  | SMOD -> smod insInfo ctxt
  | ADDMOD -> addmod insInfo ctxt
  | MULMOD -> mulmod insInfo ctxt
  | EXP -> exp insInfo ctxt
  | SIGNEXTEND -> signextend insInfo ctxt
  | LT -> lt insInfo ctxt
  | GT -> gt insInfo ctxt
  | SLT -> slt insInfo ctxt
  | SGT -> sgt insInfo ctxt
  | EQ -> eq insInfo ctxt
  | ISZERO -> iszero insInfo ctxt
  | AND -> logAnd insInfo ctxt
  | OR -> logOr insInfo ctxt
  | XOR -> xor insInfo ctxt
  | NOT -> not insInfo ctxt
  | BYTE -> byte insInfo ctxt
  | SHL -> shl insInfo ctxt
  | SHR -> shr insInfo ctxt
  | SAR -> sar insInfo ctxt
  | SHA3 -> sha3 insInfo ctxt
  | CALLER -> obtainInfo insInfo ctxt "msg.caller"
  | CALLVALUE -> obtainInfo insInfo ctxt "msg.value"
  | ADDRESS -> address insInfo ctxt
  | BALANCE -> balance insInfo ctxt
  | ORIGIN -> obtainInfo insInfo ctxt "tx.origin"
  | CALLDATALOAD -> calldataload insInfo ctxt
  | CALLDATASIZE -> obtainInfo insInfo ctxt "msg.data.size"
  | COINBASE -> obtainInfo insInfo ctxt "block.coinbase"
  | TIMESTAMP -> obtainInfo insInfo ctxt "block.timestamp"
  | NUMBER -> obtainInfo insInfo ctxt "block.number"
  | DIFFICULTY -> obtainInfo insInfo ctxt "block.difficulty"
  | CALLDATACOPY -> calldatacopy insInfo ctxt
  | CODECOPY -> codecopy insInfo ctxt
  | GASPRICE -> obtainInfo insInfo ctxt "tx.gasprice"
  | CODESIZE -> codesize insInfo ctxt
  | EXTCODESIZE -> extcodesize insInfo ctxt
  | EXTCODECOPY -> extcodecopy insInfo ctxt
  | RETURNDATASIZE -> obtainInfo insInfo ctxt "returndatasize"
  | RETURNDATACOPY -> returndatacopy insInfo ctxt
  | BLOCKHASH -> blockhash insInfo ctxt
  | GASLIMIT -> obtainInfo insInfo ctxt "block.gaslimit"
  | POP -> pop insInfo ctxt
  | MLOAD -> mload insInfo ctxt
  | MSTORE -> mstore insInfo ctxt
  | MSTORE8 -> mstore8 insInfo ctxt
  | SLOAD -> sload insInfo ctxt
  | SSTORE -> sstore insInfo ctxt
  | JUMP -> jump insInfo ctxt
  | JUMPI -> jumpi insInfo ctxt
  | GETPC -> getpc insInfo ctxt
  | MSIZE -> obtainInfo insInfo ctxt "msize"
  | GAS -> gas insInfo ctxt
  | JUMPDEST -> nop insInfo
  | PUSH1 imm -> push insInfo ctxt imm
  | PUSH2 imm -> push insInfo ctxt imm
  | PUSH3 imm -> push insInfo ctxt imm
  | PUSH4 imm -> push insInfo ctxt imm
  | PUSH5 imm -> push insInfo ctxt imm
  | PUSH6 imm -> push insInfo ctxt imm
  | PUSH7 imm -> push insInfo ctxt imm
  | PUSH8 imm -> push insInfo ctxt imm
  | PUSH9 imm -> push insInfo ctxt imm
  | PUSH10 imm -> push insInfo ctxt imm
  | PUSH11 imm -> push insInfo ctxt imm
  | PUSH12 imm -> push insInfo ctxt imm
  | PUSH13 imm -> push insInfo ctxt imm
  | PUSH14 imm -> push insInfo ctxt imm
  | PUSH15 imm -> push insInfo ctxt imm
  | PUSH16 imm -> push insInfo ctxt imm
  | PUSH17 imm -> push insInfo ctxt imm
  | PUSH18 imm -> push insInfo ctxt imm
  | PUSH19 imm -> push insInfo ctxt imm
  | PUSH20 imm -> push insInfo ctxt imm
  | PUSH21 imm -> push insInfo ctxt imm
  | PUSH22 imm -> push insInfo ctxt imm
  | PUSH23 imm -> push insInfo ctxt imm
  | PUSH24 imm -> push insInfo ctxt imm
  | PUSH25 imm -> push insInfo ctxt imm
  | PUSH26 imm -> push insInfo ctxt imm
  | PUSH27 imm -> push insInfo ctxt imm
  | PUSH28 imm -> push insInfo ctxt imm
  | PUSH29 imm -> push insInfo ctxt imm
  | PUSH30 imm -> push insInfo ctxt imm
  | PUSH31 imm -> push insInfo ctxt imm
  | PUSH32 imm -> push insInfo ctxt imm
  | DUP1 -> dup insInfo ctxt 1
  | DUP2 -> dup insInfo ctxt 2
  | DUP3 -> dup insInfo ctxt 3
  | DUP4 -> dup insInfo ctxt 4
  | DUP5 -> dup insInfo ctxt 5
  | DUP6 -> dup insInfo ctxt 6
  | DUP7 -> dup insInfo ctxt 7
  | DUP8 -> dup insInfo ctxt 8
  | DUP9 -> dup insInfo ctxt 9
  | DUP10 -> dup insInfo ctxt 10
  | DUP11 -> dup insInfo ctxt 11
  | DUP12 -> dup insInfo ctxt 12
  | DUP13 -> dup insInfo ctxt 13
  | DUP14 -> dup insInfo ctxt 14
  | DUP15 -> dup insInfo ctxt 15
  | DUP16 -> dup insInfo ctxt 16
  | SWAP1 -> swap insInfo ctxt 1
  | SWAP2 -> swap insInfo ctxt 2
  | SWAP3 -> swap insInfo ctxt 3
  | SWAP4 -> swap insInfo ctxt 4
  | SWAP5 -> swap insInfo ctxt 5
  | SWAP6 -> swap insInfo ctxt 6
  | SWAP7 -> swap insInfo ctxt 7
  | SWAP8 -> swap insInfo ctxt 8
  | SWAP9 -> swap insInfo ctxt 9
  | SWAP10 -> swap insInfo ctxt 10
  | SWAP11 -> swap insInfo ctxt 11
  | SWAP12 -> swap insInfo ctxt 12
  | SWAP13 -> swap insInfo ctxt 13
  | SWAP14 -> swap insInfo ctxt 14
  | SWAP15 -> swap insInfo ctxt 15
  | SWAP16 -> swap insInfo ctxt 16
  | RETURN
  | REVERT -> ret insInfo ctxt
  | CALL -> call insInfo ctxt "call.gas"
  | CALLCODE -> call insInfo ctxt "callcode.gas"
  | LOG0
  | LOG1
  | LOG2
  | LOG3
  | LOG4
  | JUMPTO
  | JUMPIF
  | JUMPSUB
  | JUMPSUBV
  | BEGINSUB
  | BEGINDATA
  | RETURNSUB
  | PUTLOCAL
  | GETLOCAL
  | SLOADBYTES
  | SSTOREBYTES
  | SSIZE
  | CREATE
  | DELEGATECALL
  | CREATE2
  | STATICCALL
  | TXEXECGAS
  | INVALID
  | SELFDESTRUCT -> selfdestruct insInfo ctxt
  |> fun builder -> builder.ToStmts ()
