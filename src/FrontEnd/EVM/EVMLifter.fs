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
open B2R2.BinIR.LowUIR.AST
open B2R2.FrontEnd
open B2R2.FrontEnd.EVM

let inline private getRegVar (ctxt: TranslationContext) name =
  Register.toRegID name |> ctxt.GetRegVar

let inline private (<!) (builder: StmtBuilder) (s) = builder.Append (s)

let inline private startMark insInfo (builder: StmtBuilder) =
  builder <! (ISMark (insInfo.Address, insInfo.NumBytes))

let inline private endMark insInfo (builder: StmtBuilder) =
  builder <! (IEMark (uint64 insInfo.NumBytes + insInfo.Address)); builder

let inline private numI32 n t = BitVector.ofInt32 n t |> num
let inline private numU64 n t = BitVector.ofUInt64 n t |> num

let inline private updateGas ctxt gas builder =
  let gasReg = getRegVar ctxt R.GAS
  builder <! (gasReg := gasReg .+ numI32 gas 64<rt>)

let sideEffects insInfo name =
  let builder = new StmtBuilder (4)
  startMark insInfo builder
  builder <! (SideEffect name)
  endMark insInfo builder

let nop insInfo =
  let builder = new StmtBuilder (4)
  startMark insInfo builder
  endMark insInfo builder

let private getSPSize size = numI32 (32 * size) 256<rt>

/// Pushes an element to stack.
let private pushToStack (ctxt: TranslationContext) expr builder =
  let spReg = getRegVar ctxt R.SP
  let tmp = tmpVar (typeOf expr)
  builder <! (spReg := (spReg .+ (getSPSize 1))) // SP := SP + 32
  builder <! (tmp := expr)                       // tmp := expr
  builder <! (Store (Endian.Little, spReg, tmp)) // [SP] := tmp

/// Pops an element from stack and returns the element.
let private popFromStack (ctxt: TranslationContext) builder =
  let spReg = getRegVar ctxt R.SP
  let tmp = tmpVar OperationSize.regType
  builder <! (tmp := loadLE (OperationSize.regType) spReg) // tmp := [SP]
  builder <! (spReg := (spReg .- (getSPSize 1)))           // SP := SP - 32
  tmp

let private peekStack (ctxt: TranslationContext) pos builder =
  let spReg = getRegVar ctxt R.SP
  let regType = OperationSize.regType
  let tmp = tmpVar regType
  builder <! (tmp := loadLE regType (spReg .- (getSPSize (pos - 1))))
  tmp

let private swapStack (ctxt: TranslationContext) pos builder=
  let spReg = getRegVar ctxt R.SP
  let regType = OperationSize.regType
  let tmp1 = tmpVar regType
  let tmp2 = tmpVar regType
  builder <! (tmp1 := loadLE regType spReg)
  builder <! (tmp2 := loadLE regType (spReg .- (getSPSize (pos - 1))))
  builder <! (Store (Endian.Little, (spReg .- (getSPSize (pos - 1))), tmp1))
  builder <! (Store (Endian.Little, spReg, tmp2))

/// Binary operations and relative operations.
let basicOperation insInfo ctxt opFn =
  let builder = new StmtBuilder (12)
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
let lt insInfo ctxt = basicOperation insInfo ctxt lt
let gt insInfo ctxt = basicOperation insInfo ctxt gt
let slt insInfo ctxt = basicOperation insInfo ctxt slt
let sgt insInfo ctxt = basicOperation insInfo ctxt sgt
let eq insInfo ctxt = basicOperation insInfo ctxt (==)
let logAnd insInfo ctxt = basicOperation insInfo ctxt (.&)
let logOr insInfo ctxt = basicOperation insInfo ctxt (.|)
let xor insInfo ctxt = basicOperation insInfo ctxt (<+>)
let shl insInfo ctxt = basicOperation insInfo ctxt (<<)
let shr insInfo ctxt = basicOperation insInfo ctxt (>>)
let sar insInfo ctxt = basicOperation insInfo ctxt (?>>)

let addmod insInfo ctxt =
  let builder = new StmtBuilder (12)
  startMark insInfo builder
  let src1 = popFromStack ctxt builder
  let src2 = popFromStack ctxt builder
  let src3 = popFromStack ctxt builder
  let expr = (src1 .+ src2) .% src3
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let mulmod insInfo ctxt =
  let builder = new StmtBuilder (12)
  startMark insInfo builder
  let src1 = popFromStack ctxt builder
  let src2 = popFromStack ctxt builder
  let src3 = popFromStack ctxt builder
  let expr = (src1 .* src2) .% src3
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let private makeNum i =
  num <| BitVector.ofInt32 i OperationSize.regType

let signextend insInfo ctxt =
  let builder = new StmtBuilder (12)
  startMark insInfo builder
  let b = popFromStack ctxt builder
  let x = popFromStack ctxt builder
  let expr = x .& (makeNum 1 << ((b .+ makeNum 1) .* makeNum 8) .- makeNum 1)
  let sext = sExt 256<rt> expr
  pushToStack ctxt sext builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let iszero insInfo ctxt =
  let builder = new StmtBuilder (8)
  startMark insInfo builder
  let cond = popFromStack ctxt builder
  let expr = zExt OperationSize.regType (cond == num0 OperationSize.regType)
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let not insInfo ctxt =
  let builder = new StmtBuilder (8)
  startMark insInfo builder
  let e = popFromStack ctxt builder
  let expr = zExt OperationSize.regType (not e)
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let byte insInfo ctxt =
  let builder = new StmtBuilder (12)
  startMark insInfo builder
  let n = popFromStack ctxt builder
  let x = popFromStack ctxt builder
  let expr = (x >> (makeNum 248 .- n .* makeNum 8)) .& makeNum 0xff
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let pop insInfo ctxt =
  let builder = new StmtBuilder (8)
  startMark insInfo builder
  popFromStack ctxt builder |> ignore
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let mload insInfo ctxt =
  let builder = new StmtBuilder (8)
  startMark insInfo builder
  let addr = popFromStack ctxt builder
  let expr = loadLE OperationSize.regType addr
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let mstore insInfo ctxt =
  let builder = new StmtBuilder (12)
  startMark insInfo builder
  let addr = popFromStack ctxt builder
  let value = popFromStack ctxt builder
  updateGas ctxt insInfo.GAS builder
  builder <! (loadLE OperationSize.regType addr := value)
  endMark insInfo builder

let mstore8 insInfo ctxt =
  let builder = new StmtBuilder (12)
  startMark insInfo builder
  let addr = popFromStack ctxt builder
  let value = popFromStack ctxt builder
  updateGas ctxt insInfo.GAS builder
  builder <! (loadLE 8<rt> addr := value .& makeNum 0xff)
  endMark insInfo builder

let jump insInfo ctxt =
  let builder = new StmtBuilder (8)
  let pc = getRegVar ctxt R.PC
  try
    startMark insInfo builder
    let dst = popFromStack ctxt builder
    let dstAddr = dst .+ (BitVector.ofUInt64 insInfo.Offset 256<rt> |> num)
    updateGas ctxt insInfo.GAS builder
    builder <! InterJmp (pc, dstAddr, InterJmpInfo.Base)
    endMark insInfo builder
  with
    | :? System.InvalidOperationException -> (* Special case: terminate func. *)
      sideEffects insInfo Halt

let jumpi insInfo ctxt =
  let builder = new StmtBuilder (12)
  startMark insInfo builder
  let pc = getRegVar ctxt R.PC
  let dst = popFromStack ctxt builder
  let dstAddr = dst .+ (BitVector.ofUInt64 insInfo.Offset 256<rt> |> num)
  let cond = popFromStack ctxt builder
  let fall = numU64 (insInfo.Address + 1UL) 64<rt>
  updateGas ctxt insInfo.GAS builder
  builder <! InterCJmp (extractLow 1<rt> cond, pc, dstAddr, fall)
  endMark insInfo builder

let getpc insInfo ctxt =
  let builder = new StmtBuilder (8)
  startMark insInfo builder
  let expr = getRegVar ctxt R.PC |> zExt OperationSize.regType
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let gas insInfo ctxt =
  let builder = new StmtBuilder (8)
  startMark insInfo builder
  let expr = zExt OperationSize.regType (getRegVar ctxt R.GAS)
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let push insInfo ctxt imm =
  let builder = new StmtBuilder (8)
  startMark insInfo builder
  let expr = BitVector.ofBv imm 256<rt> |> num
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let dup insInfo ctxt pos =
  let builder = new StmtBuilder (8)
  startMark insInfo builder
  let src = peekStack ctxt pos builder
  pushToStack ctxt src builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let swap insInfo ctxt pos =
  let builder = new StmtBuilder (12)
  startMark insInfo builder
  swapStack ctxt pos builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let obtainInfo insInfo ctxt name =
  let builder = new StmtBuilder (8)
  startMark insInfo builder
  let expr = app name [] OperationSize.regType
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let address insInfo ctxt =
  let builder = new StmtBuilder (8)
  startMark insInfo builder
  let pc = BitVector.ofUInt64 insInfo.Address OperationSize.regType |> num
  pushToStack ctxt pc builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let balance insInfo ctxt =
  let builder = new StmtBuilder (8)
  startMark insInfo builder
  let addr = popFromStack ctxt builder
  let expr = app "balance" [ addr ] OperationSize.regType
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let calldataload insInfo ctxt =
  let builder = new StmtBuilder (12)
  startMark insInfo builder
  let i = popFromStack ctxt builder
  let length = num1 OperationSize.regType
  let expr = app "msg.data" [ i; length ] OperationSize.regType
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let calldatacopy insInfo ctxt =
  let builder = new StmtBuilder (12)
  startMark insInfo builder
  let dstOffset = popFromStack ctxt builder
  let offset = popFromStack ctxt builder
  let length = popFromStack ctxt builder
  let src = app "msg.data" [ offset; length ] OperationSize.regType
  builder <! (loadLE OperationSize.regType dstOffset := src)
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let codecopy insInfo ctxt =
  let builder = new StmtBuilder (12)
  startMark insInfo builder
  let dstOffset = popFromStack ctxt builder |> extractLow 64<rt>
  let offset = popFromStack ctxt builder
  let length = popFromStack ctxt builder
  let src = app "code" [ offset; length ] OperationSize.regType
  builder <! (loadLE OperationSize.regType dstOffset := src)
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let extcodecopy insInfo ctxt =
  let builder = new StmtBuilder (12)
  startMark insInfo builder
  let addr = popFromStack ctxt builder
  let dstOffset = popFromStack ctxt builder
  let offset = popFromStack ctxt builder
  let length = popFromStack ctxt builder
  let src = app "code" [ addr; offset; length ] OperationSize.regType
  builder <! (loadLE OperationSize.regType dstOffset := src)
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let returndatacopy insInfo ctxt =
  let builder = new StmtBuilder (12)
  startMark insInfo builder
  let dstOffset = popFromStack ctxt builder
  let offset = popFromStack ctxt builder
  let length = popFromStack ctxt builder
  let src = app "returndata" [ offset; length ] OperationSize.regType
  builder <! (loadLE OperationSize.regType dstOffset := src)
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let codesize insInfo ctxt =
  let builder = new StmtBuilder (8)
  startMark insInfo builder
  let expr = app "code.size" [] OperationSize.regType
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let extcodesize insInfo ctxt =
  let builder = new StmtBuilder (8)
  startMark insInfo builder
  let addr = popFromStack ctxt builder
  let expr = app "code.size" [ addr ] OperationSize.regType
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let blockhash insInfo ctxt =
  let builder = new StmtBuilder (8)
  startMark insInfo builder
  let blockNum = popFromStack ctxt builder
  let expr = app "block.blockHash" [ blockNum ] OperationSize.regType
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let sha3 insInfo ctxt =
  let builder = new StmtBuilder (12)
  startMark insInfo builder
  let offset = popFromStack ctxt builder
  let length = popFromStack ctxt builder
  let expr = app "keccak256" [ offset; length ] OperationSize.regType
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let call insInfo ctxt fname =
  let builder = new StmtBuilder (20)
  startMark insInfo builder
  let gas = popFromStack ctxt builder
  let addr = popFromStack ctxt builder
  let value = popFromStack ctxt builder
  let argsOffset = popFromStack ctxt builder
  let argsLength = popFromStack ctxt builder
  let retOffset = popFromStack ctxt builder
  let retLength = popFromStack ctxt builder
  let args = [ gas; addr; value; argsOffset; argsLength; retOffset; retLength ]
  let expr = app fname args OperationSize.regType
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let sload insInfo ctxt =
  let builder = new StmtBuilder (8)
  startMark insInfo builder
  let key = popFromStack ctxt builder
  let value = app "sload" [key] OperationSize.regType
  pushToStack ctxt value builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let sstore insInfo ctxt =
  let builder = new StmtBuilder (8)
  startMark insInfo builder
  let key = popFromStack ctxt builder
  let value = popFromStack ctxt builder
  let t = tmpVar OperationSize.regType
  updateGas ctxt insInfo.GAS builder
  builder <! (t := app "sstore" [ key; value ] OperationSize.regType)
  endMark insInfo builder

let exp insInfo ctxt =
  let builder = new StmtBuilder (12)
  startMark insInfo builder
  let a = popFromStack ctxt builder
  let b = popFromStack ctxt builder
  let expr = app "exp" [ a; b ] OperationSize.regType
  pushToStack ctxt expr builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let ret insInfo ctxt =
  let builder = new StmtBuilder (8)
  popFromStack ctxt builder |> ignore
  popFromStack ctxt builder |> ignore
  sideEffects insInfo Halt

let selfdestruct insInfo ctxt =
  let builder = new StmtBuilder (8)
  popFromStack ctxt builder |> ignore
  sideEffects insInfo Halt

let translate insInfo (ctxt: TranslationContext) =
  match insInfo.Opcode with
  | Op.STOP -> sideEffects insInfo Halt
  | Op.ADD -> add insInfo ctxt
  | Op.MUL -> mul insInfo ctxt
  | Op.SUB -> sub insInfo ctxt
  | Op.DIV -> div insInfo ctxt
  | Op.SDIV -> sdiv insInfo ctxt
  | Op.MOD -> modu insInfo ctxt
  | Op.SMOD -> smod insInfo ctxt
  | Op.ADDMOD -> addmod insInfo ctxt
  | Op.MULMOD -> mulmod insInfo ctxt
  | Op.EXP -> exp insInfo ctxt
  | Op.SIGNEXTEND -> signextend insInfo ctxt
  | Op.LT -> lt insInfo ctxt
  | Op.GT -> gt insInfo ctxt
  | Op.SLT -> slt insInfo ctxt
  | Op.SGT -> sgt insInfo ctxt
  | Op.EQ -> eq insInfo ctxt
  | Op.ISZERO -> iszero insInfo ctxt
  | Op.AND -> logAnd insInfo ctxt
  | Op.OR -> logOr insInfo ctxt
  | Op.XOR -> xor insInfo ctxt
  | Op.NOT -> not insInfo ctxt
  | Op.BYTE -> byte insInfo ctxt
  | Op.SHL -> shl insInfo ctxt
  | Op.SHR -> shr insInfo ctxt
  | Op.SAR -> sar insInfo ctxt
  | Op.SHA3 -> sha3 insInfo ctxt
  | Op.CALLER -> obtainInfo insInfo ctxt "msg.caller"
  | Op.CALLVALUE -> obtainInfo insInfo ctxt "msg.value"
  | Op.ADDRESS -> address insInfo ctxt
  | Op.BALANCE -> balance insInfo ctxt
  | Op.ORIGIN -> obtainInfo insInfo ctxt "tx.origin"
  | Op.CALLDATALOAD -> calldataload insInfo ctxt
  | Op.CALLDATASIZE -> obtainInfo insInfo ctxt "msg.data.size"
  | Op.COINBASE -> obtainInfo insInfo ctxt "block.coinbase"
  | Op.TIMESTAMP -> obtainInfo insInfo ctxt "block.timestamp"
  | Op.NUMBER -> obtainInfo insInfo ctxt "block.number"
  | Op.DIFFICULTY -> obtainInfo insInfo ctxt "block.difficulty"
  | Op.CALLDATACOPY -> calldatacopy insInfo ctxt
  | Op.CODECOPY -> codecopy insInfo ctxt
  | Op.GASPRICE -> obtainInfo insInfo ctxt "tx.gasprice"
  | Op.CODESIZE -> codesize insInfo ctxt
  | Op.EXTCODESIZE -> extcodesize insInfo ctxt
  | Op.EXTCODECOPY -> extcodecopy insInfo ctxt
  | Op.RETURNDATASIZE -> obtainInfo insInfo ctxt "returndatasize"
  | Op.RETURNDATACOPY -> returndatacopy insInfo ctxt
  | Op.BLOCKHASH -> blockhash insInfo ctxt
  | Op.GASLIMIT -> obtainInfo insInfo ctxt "block.gaslimit"
  | Op.POP -> pop insInfo ctxt
  | Op.MLOAD -> mload insInfo ctxt
  | Op.MSTORE -> mstore insInfo ctxt
  | Op.MSTORE8 -> mstore8 insInfo ctxt
  | Op.SLOAD -> sload insInfo ctxt
  | Op.SSTORE -> sstore insInfo ctxt
  | Op.JUMP -> jump insInfo ctxt
  | Op.JUMPI -> jumpi insInfo ctxt
  | Op.GETPC -> getpc insInfo ctxt
  | Op.MSIZE -> obtainInfo insInfo ctxt "msize"
  | Op.GAS -> gas insInfo ctxt
  | Op.JUMPDEST -> nop insInfo
  | Op.PUSH1 imm -> push insInfo ctxt imm
  | Op.PUSH2 imm -> push insInfo ctxt imm
  | Op.PUSH3 imm -> push insInfo ctxt imm
  | Op.PUSH4 imm -> push insInfo ctxt imm
  | Op.PUSH5 imm -> push insInfo ctxt imm
  | Op.PUSH6 imm -> push insInfo ctxt imm
  | Op.PUSH7 imm -> push insInfo ctxt imm
  | Op.PUSH8 imm -> push insInfo ctxt imm
  | Op.PUSH9 imm -> push insInfo ctxt imm
  | Op.PUSH10 imm -> push insInfo ctxt imm
  | Op.PUSH11 imm -> push insInfo ctxt imm
  | Op.PUSH12 imm -> push insInfo ctxt imm
  | Op.PUSH13 imm -> push insInfo ctxt imm
  | Op.PUSH14 imm -> push insInfo ctxt imm
  | Op.PUSH15 imm -> push insInfo ctxt imm
  | Op.PUSH16 imm -> push insInfo ctxt imm
  | Op.PUSH17 imm -> push insInfo ctxt imm
  | Op.PUSH18 imm -> push insInfo ctxt imm
  | Op.PUSH19 imm -> push insInfo ctxt imm
  | Op.PUSH20 imm -> push insInfo ctxt imm
  | Op.PUSH21 imm -> push insInfo ctxt imm
  | Op.PUSH22 imm -> push insInfo ctxt imm
  | Op.PUSH23 imm -> push insInfo ctxt imm
  | Op.PUSH24 imm -> push insInfo ctxt imm
  | Op.PUSH25 imm -> push insInfo ctxt imm
  | Op.PUSH26 imm -> push insInfo ctxt imm
  | Op.PUSH27 imm -> push insInfo ctxt imm
  | Op.PUSH28 imm -> push insInfo ctxt imm
  | Op.PUSH29 imm -> push insInfo ctxt imm
  | Op.PUSH30 imm -> push insInfo ctxt imm
  | Op.PUSH31 imm -> push insInfo ctxt imm
  | Op.PUSH32 imm -> push insInfo ctxt imm
  | Op.DUP1 -> dup insInfo ctxt 1
  | Op.DUP2 -> dup insInfo ctxt 2
  | Op.DUP3 -> dup insInfo ctxt 3
  | Op.DUP4 -> dup insInfo ctxt 4
  | Op.DUP5 -> dup insInfo ctxt 5
  | Op.DUP6 -> dup insInfo ctxt 6
  | Op.DUP7 -> dup insInfo ctxt 7
  | Op.DUP8 -> dup insInfo ctxt 8
  | Op.DUP9 -> dup insInfo ctxt 9
  | Op.DUP10 -> dup insInfo ctxt 10
  | Op.DUP11 -> dup insInfo ctxt 11
  | Op.DUP12 -> dup insInfo ctxt 12
  | Op.DUP13 -> dup insInfo ctxt 13
  | Op.DUP14 -> dup insInfo ctxt 14
  | Op.DUP15 -> dup insInfo ctxt 15
  | Op.DUP16 -> dup insInfo ctxt 16
  | Op.SWAP1 -> swap insInfo ctxt 1
  | Op.SWAP2 -> swap insInfo ctxt 2
  | Op.SWAP3 -> swap insInfo ctxt 3
  | Op.SWAP4 -> swap insInfo ctxt 4
  | Op.SWAP5 -> swap insInfo ctxt 5
  | Op.SWAP6 -> swap insInfo ctxt 6
  | Op.SWAP7 -> swap insInfo ctxt 7
  | Op.SWAP8 -> swap insInfo ctxt 8
  | Op.SWAP9 -> swap insInfo ctxt 9
  | Op.SWAP10 -> swap insInfo ctxt 10
  | Op.SWAP11 -> swap insInfo ctxt 11
  | Op.SWAP12 -> swap insInfo ctxt 12
  | Op.SWAP13 -> swap insInfo ctxt 13
  | Op.SWAP14 -> swap insInfo ctxt 14
  | Op.SWAP15 -> swap insInfo ctxt 15
  | Op.SWAP16 -> swap insInfo ctxt 16
  | Op.RETURN
  | Op.REVERT -> ret insInfo ctxt
  | Op.CALL -> call insInfo ctxt "call.gas"
  | Op.CALLCODE -> call insInfo ctxt "callcode.gas"
  | Op.LOG0
  | Op.LOG1
  | Op.LOG2
  | Op.LOG3
  | Op.LOG4
  | Op.JUMPTO
  | Op.JUMPIF
  | Op.JUMPSUB
  | Op.JUMPSUBV
  | Op.BEGINSUB
  | Op.BEGINDATA
  | Op.RETURNSUB
  | Op.PUTLOCAL
  | Op.GETLOCAL
  | Op.SLOADBYTES
  | Op.SSTOREBYTES
  | Op.SSIZE
  | Op.CREATE
  | Op.DELEGATECALL
  | Op.CREATE2
  | Op.STATICCALL
  | Op.TXEXECGAS
  | Op.INVALID
  | Op.SELFDESTRUCT -> selfdestruct insInfo ctxt
  |> fun builder -> builder.ToStmts ()
