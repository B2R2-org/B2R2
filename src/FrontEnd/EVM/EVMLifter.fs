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
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.EVM

let inline private getRegVar (ctxt: TranslationContext) name =
  Register.toRegID name |> ctxt.GetRegVar

let inline private (<!) (builder: IRBuilder) (s) = builder.Append (s)

let inline private startMark insInfo (builder: IRBuilder) =
  builder <! (AST.ismark (insInfo.NumBytes))

let inline private endMark insInfo (builder: IRBuilder) =
  builder <! (AST.iemark (insInfo.NumBytes)); builder

let inline private updateGas ctxt gas builder =
  let gasReg = getRegVar ctxt R.GAS
  builder <! (gasReg := gasReg .+ numI32 gas 64<rt>)

let sideEffects insInfo name =
  let builder = IRBuilder (4)
  startMark insInfo builder
  builder <! AST.sideEffect name
  endMark insInfo builder

let nop insInfo =
  let builder = IRBuilder (4)
  startMark insInfo builder
  endMark insInfo builder

let private getSPSize size = numI32 (32 * size) 256<rt>

/// Pushes an element to stack.
let private pushToStack (ctxt: TranslationContext) expr (builder: IRBuilder) =
  let spReg = getRegVar ctxt R.SP
  let expr = if OperationSize.regType = TypeCheck.typeOf expr then expr
             else AST.zext OperationSize.regType expr
  builder <! (spReg := (spReg .+ (getSPSize 1))) (* SP := SP + 32 *)
  builder <! (AST.store Endian.Big spReg expr) (* [SP] := expr *)

/// Pops an element from stack and returns the element.
let private popFromStack (ctxt: TranslationContext) (builder: IRBuilder) =
  let spReg = getRegVar ctxt R.SP
  let tmp = builder.NewTempVar OperationSize.regType
  builder <! (tmp := AST.loadBE (OperationSize.regType) spReg) (* tmp := [SP] *)
  builder <! (spReg := (spReg .- (getSPSize 1)))           (* SP := SP - 32 *)
  tmp

// Peek the 'pos'-th item.
let private peekStack (ctxt: TranslationContext) pos (builder: IRBuilder) =
  let spReg = getRegVar ctxt R.SP
  let regType = OperationSize.regType
  let tmp = builder.NewTempVar regType
  builder <! (tmp := AST.loadBE regType (spReg .- (getSPSize (pos - 1))))
  tmp

// Swap the topmost item with ('pos' + 1)-th item.
let private swapStack (ctxt: TranslationContext) pos (builder: IRBuilder) =
  let spReg = getRegVar ctxt R.SP
  let regType = OperationSize.regType
  let tmp1 = builder.NewTempVar regType
  let tmp2 = builder.NewTempVar regType
  builder <! (tmp1 := AST.loadBE regType spReg)
  builder <! (tmp2 := AST.loadBE regType (spReg .- (getSPSize pos)))
  builder <! (AST.store Endian.Big (spReg .- (getSPSize pos)) tmp1)
  builder <! (AST.store Endian.Big spReg tmp2)

let startBasicOperation insInfo =
  let builder = IRBuilder (12)
  startMark insInfo builder
  builder

let endBasicOperation ctxt opFn src1 src2 insInfo builder =
  pushToStack ctxt (opFn src1 src2) builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

/// Binary operations and relative operations.
let basicOperation insInfo ctxt opFn =
  let builder = startBasicOperation insInfo
  let src1, src2 = popFromStack ctxt builder, popFromStack ctxt builder
  endBasicOperation ctxt opFn src1 src2 insInfo builder

/// Shift operations. They use the flipped order of operands.
let shiftOperation insInfo ctxt opFn =
  let builder = startBasicOperation insInfo
  let src1, src2 = popFromStack ctxt builder, popFromStack ctxt builder
  endBasicOperation ctxt opFn src2 src1 insInfo builder

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
let shl insInfo ctxt = shiftOperation insInfo ctxt (<<)
let shr insInfo ctxt = shiftOperation insInfo ctxt (>>)
let sar insInfo ctxt = shiftOperation insInfo ctxt (?>>)

let addmod insInfo ctxt =
  let builder = IRBuilder (12)
  startMark insInfo builder
  let src1 = popFromStack ctxt builder
  let src2 = popFromStack ctxt builder
  let src3 = popFromStack ctxt builder
  let expr = (src1 .+ src2) .% src3
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let mulmod insInfo ctxt =
  let builder = IRBuilder (12)
  startMark insInfo builder
  let src1 = popFromStack ctxt builder
  let src2 = popFromStack ctxt builder
  let src3 = popFromStack ctxt builder
  let expr = (src1 .* src2) .% src3
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let private makeNum i = numI32 i OperationSize.regType

let signextend insInfo ctxt =
  let builder = IRBuilder (12)
  startMark insInfo builder
  let b = popFromStack ctxt builder
  let x = popFromStack ctxt builder
  let expr = x .& (makeNum 1 << ((b .+ makeNum 1) .* makeNum 8) .- makeNum 1)
  let sext = AST.sext 256<rt> expr
  pushToStack ctxt sext builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let iszero insInfo ctxt =
  let builder = IRBuilder (8)
  startMark insInfo builder
  let cond = popFromStack ctxt builder
  let rt = OperationSize.regType
  let expr = AST.zext rt (cond == AST.num0 rt)
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let not insInfo ctxt =
  let builder = IRBuilder (8)
  startMark insInfo builder
  let e = popFromStack ctxt builder
  let expr = AST.zext OperationSize.regType (AST.not e)
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let byte insInfo ctxt =
  let builder = IRBuilder (12)
  startMark insInfo builder
  let n = popFromStack ctxt builder
  let x = popFromStack ctxt builder
  let expr = (x >> (makeNum 248 .- n .* makeNum 8)) .& makeNum 0xff
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let pop insInfo ctxt =
  let builder = IRBuilder (8)
  startMark insInfo builder
  popFromStack ctxt builder |> ignore
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let mload insInfo ctxt =
  let builder = IRBuilder (8)
  startMark insInfo builder
  let addr = popFromStack ctxt builder
  let expr = AST.loadBE OperationSize.regType addr
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let mstore insInfo ctxt =
  let builder = IRBuilder (8)
  startMark insInfo builder
  let addr = popFromStack ctxt builder
  let value = popFromStack ctxt builder
  builder <! AST.store Endian.Big addr value
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let mstore8 insInfo ctxt =
  let builder = IRBuilder (8)
  startMark insInfo builder
  let addr = popFromStack ctxt builder
  let value = popFromStack ctxt builder
  let lsb = AST.extract value 8<rt> 0
  builder <! AST.store Endian.Big addr lsb
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let jump insInfo ctxt =
  let builder = IRBuilder (8)
  try
    startMark insInfo builder
    let dst = popFromStack ctxt builder
    let dstAddr = dst .+ (numU64 insInfo.Offset 256<rt>)
    updateGas ctxt insInfo.GAS builder
    builder <! AST.interjmp dstAddr InterJmpKind.Base
    endMark insInfo builder
  with
    | :? System.InvalidOperationException -> (* Special case: terminate func. *)
      sideEffects insInfo Terminate

let jumpi insInfo ctxt =
  let builder = IRBuilder (12)
  startMark insInfo builder
  let dst = popFromStack ctxt builder
  let dstAddr = dst .+ (numU64 insInfo.Offset 256<rt>)
  let cond = popFromStack ctxt builder
  let fall = numU64 (insInfo.Address + 1UL) 64<rt>
  updateGas ctxt insInfo.GAS builder
  builder <! AST.intercjmp (AST.xtlo 1<rt> cond) dstAddr fall
  endMark insInfo builder

let getpc insInfo ctxt =
  let builder = IRBuilder (8)
  startMark insInfo builder
  let expr = getRegVar ctxt R.PC |> AST.zext OperationSize.regType
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let gas insInfo ctxt =
  let builder = IRBuilder (8)
  startMark insInfo builder
  let expr = AST.zext OperationSize.regType (getRegVar ctxt R.GAS)
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let push insInfo ctxt imm =
  let builder = IRBuilder (8)
  startMark insInfo builder
  let expr = BitVector.Cast (imm, 256<rt>) |> AST.num
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let dup insInfo ctxt pos =
  let builder = IRBuilder (8)
  startMark insInfo builder
  let src = peekStack ctxt pos builder
  pushToStack ctxt src builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let swap insInfo ctxt pos =
  let builder = IRBuilder (12)
  startMark insInfo builder
  swapStack ctxt pos builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let callExternFunc insInfo ctxt name argCount doesRet =
  let builder = IRBuilder (15)
  startMark insInfo builder
  let args = List.init argCount (fun _ -> popFromStack ctxt builder)
  let expr = AST.app name args OperationSize.regType
  if doesRet then pushToStack ctxt expr builder
  else builder <! (AST.extCall expr)
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let call insInfo ctxt fname =
  let builder = IRBuilder (20)
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

let ret insInfo ctxt =
  let builder = IRBuilder (8)
  popFromStack ctxt builder |> ignore
  popFromStack ctxt builder |> ignore
  sideEffects insInfo Terminate

let selfdestruct insInfo ctxt =
  let builder = IRBuilder (8)
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
  | EXP -> callExternFunc insInfo ctxt "exp" 2 true
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
  | SHA3 -> callExternFunc insInfo ctxt "keccak256" 2 true
  | ADDRESS -> callExternFunc insInfo ctxt "address" 0 true
  | BALANCE -> callExternFunc insInfo ctxt "balance" 1 true
  | ORIGIN -> callExternFunc insInfo ctxt "tx.origin" 0 true
  | CALLER -> callExternFunc insInfo ctxt "msg.sender" 0 true
  | CALLVALUE -> callExternFunc insInfo ctxt "msg.value" 0 true
  | CALLDATALOAD -> callExternFunc insInfo ctxt "msg.data" 1 true
  | CALLDATASIZE -> callExternFunc insInfo ctxt "msg.data.size" 0 true
  | CALLDATACOPY -> callExternFunc insInfo ctxt "calldatacopy" 3 false
  | CODESIZE -> callExternFunc insInfo ctxt "codesize" 0 true
  | CODECOPY -> callExternFunc insInfo ctxt "codecopy" 3 false
  | GASPRICE -> callExternFunc insInfo ctxt "tx.gasprice" 0 true
  | EXTCODESIZE -> callExternFunc insInfo ctxt "extcodesize" 1 true
  | EXTCODECOPY -> callExternFunc insInfo ctxt "extcodecopy" 4 false
  | RETURNDATASIZE -> callExternFunc insInfo ctxt "returndatasize" 0 true
  | RETURNDATACOPY -> callExternFunc insInfo ctxt "returndatacopy" 3 false
  | EXTCODEHASH -> callExternFunc insInfo ctxt "extcodehash" 1 true
  | BLOCKHASH -> callExternFunc insInfo ctxt "blockhash" 1 true
  | COINBASE -> callExternFunc insInfo ctxt "block.coinbase" 0 true
  | TIMESTAMP -> callExternFunc insInfo ctxt "block.timestamp" 0 true
  | NUMBER -> callExternFunc insInfo ctxt "block.number" 0 true
  | DIFFICULTY -> callExternFunc insInfo ctxt "block.difficulty" 0 true
  | GASLIMIT -> callExternFunc insInfo ctxt "block.gaslimit" 0 true
  | CHAINID -> callExternFunc insInfo ctxt "chainid" 0 true
  | SELFBALANCE -> callExternFunc insInfo ctxt "selfbalance" 0 true
  | BASEFEE -> callExternFunc insInfo ctxt "basefee" 0 true
  | POP -> pop insInfo ctxt
  | MLOAD -> mload insInfo ctxt
  | MSTORE -> mstore insInfo ctxt
  | MSTORE8 -> mstore8 insInfo ctxt
  | SLOAD -> callExternFunc insInfo ctxt "sload" 1 true
  | SSTORE -> callExternFunc insInfo ctxt "sstore" 2 false
  | JUMP -> jump insInfo ctxt
  | JUMPI -> jumpi insInfo ctxt
  | GETPC -> getpc insInfo ctxt
  | MSIZE -> callExternFunc insInfo ctxt "msize" 0 true
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
  | RETURN | REVERT -> ret insInfo ctxt
  | CALL -> callExternFunc insInfo ctxt "call" 7 true
  | CALLCODE -> callExternFunc insInfo ctxt "callcode" 7 true
  | LOG0 -> callExternFunc insInfo ctxt "log0" 2 false
  | LOG1 -> callExternFunc insInfo ctxt "log1" 3 false
  | LOG2 -> callExternFunc insInfo ctxt "log2" 4 false
  | LOG3 -> callExternFunc insInfo ctxt "log3" 5 false
  | LOG4 -> callExternFunc insInfo ctxt "log4" 6 false
  | CREATE -> callExternFunc insInfo ctxt "create" 3 true
  | DELEGATECALL -> callExternFunc insInfo ctxt "delegatecall" 6 true
  | CREATE2 -> callExternFunc insInfo ctxt "create2" 4 true
  | STATICCALL -> callExternFunc insInfo ctxt "staticcall" 6 true
  | INVALID -> sideEffects insInfo Terminate
  | SELFDESTRUCT -> selfdestruct insInfo ctxt
