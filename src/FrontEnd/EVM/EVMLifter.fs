(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Seung Il Jung <sijung@kaist.ac.kr>
          Sang Kil Cha <sangkilc@kaist.ac.kr>

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

let inline getRegVar (ctxt: TranslationContext) name =
  Register.toRegID name |> ctxt.GetRegVar

let inline private (<!) (builder: StmtBuilder) (s) = builder.Append (s)

let startMark insInfo (builder: StmtBuilder) =
  builder <! (ISMark (insInfo.Address, insInfo.NumBytes))

let endMark insInfo (builder: StmtBuilder) =
  builder <! (IEMark (uint64 insInfo.NumBytes + insInfo.Address)); builder

let inline numU32 n t = BitVector.ofUInt32 n t |> num
let inline numI32 n t = BitVector.ofInt32 n t |> num
let inline numU64 n t = BitVector.ofUInt64 n t |> num
let inline numI64 n t = BitVector.ofInt64 n t |> num

let updateGas ctxt gas builder =
  let gasReg = getRegVar ctxt R.GAS
  builder <! (gasReg := gasReg .+ numI32 gas 64<rt>)

let bvOfBaseAddr (ctxt: TranslationContext) addr = numU64 addr ctxt.WordBitSize

let bvOfInstrLen (ctxt: TranslationContext) insInfo =
  numU32 insInfo.NumBytes ctxt.WordBitSize

let sideEffects insInfo name =
  let builder = new StmtBuilder (4)
  startMark insInfo builder
  builder <! (SideEffect name)
  endMark insInfo builder

let nop insInfo =
  let builder = new StmtBuilder (4)
  startMark insInfo builder
  endMark insInfo builder

let opPush ctxt expr builder =
  let sp = getRegVar ctxt R.SP
  builder <! (sp := sp .- (num <| BitVector.ofInt32 32 OperationSize.regType))
  builder <! (loadLE OperationSize.regType sp := expr)

let opPop ctxt builder =
  let t = tmpVar OperationSize.regType
  let sp = getRegVar ctxt R.SP
  builder <! (t := loadLE OperationSize.regType sp)
  builder <! (sp := sp .+ (num <| BitVector.ofInt32 32 OperationSize.regType))
  t

let getOneInputFromStack ctxt builder = opPop ctxt builder
let getTwoInputsFromStack ctxt builder = opPop ctxt builder, opPop ctxt builder
let getThreeInputsFromStack ctxt builder =
  opPop ctxt builder, opPop ctxt builder, opPop ctxt builder

 /// Binary operations and relative operations.
let basicOperation insInfo ctxt opFn =
  let builder = new StmtBuilder (8)
  let dst = tmpVar OperationSize.regType
  startMark insInfo builder
  let src1, src2 = getTwoInputsFromStack ctxt builder
  builder <! (dst := zExt OperationSize.regType (opFn src1 src2))
  opPush ctxt dst builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let add insInfo ctxt = basicOperation insInfo ctxt (.+)
let mul insInfo ctxt = basicOperation insInfo ctxt (.*)
let sub insInfo ctxt = basicOperation insInfo ctxt (.-)
let div insInfo ctxt = basicOperation insInfo ctxt (./)
let sdiv insInfo ctxt = basicOperation insInfo ctxt (?/)
let modu insInfo ctxt = basicOperation insInfo ctxt (.%)
let smod insInfo ctxt = basicOperation insInfo ctxt (?%)

let addmod insInfo ctxt =
  let builder = new StmtBuilder (8)
  let dst = tmpVar OperationSize.regType
  startMark insInfo builder
  let src1, src2, src3 = getThreeInputsFromStack ctxt builder
  builder <! (dst := (src1 .+ src2) .% src3)
  opPush ctxt dst builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let mulmod insInfo ctxt =
  let builder = new StmtBuilder (8)
  let dst = tmpVar OperationSize.regType
  startMark insInfo builder
  let src1, src2, src3 = getThreeInputsFromStack ctxt builder
  builder <! (dst := (src1 .* src2) .% src3)
  opPush ctxt dst builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let signextend insInfo ctxt =
  let builder = new StmtBuilder (8)
  let dst = tmpVar OperationSize.regType
  startMark insInfo builder
  let b, x = getTwoInputsFromStack ctxt builder
  builder <! (dst := sExt OperationSize.regType x) // FIXME
  opPush ctxt dst builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let lt insInfo ctxt = basicOperation insInfo ctxt lt
let gt insInfo ctxt = basicOperation insInfo ctxt gt
let slt insInfo ctxt = basicOperation insInfo ctxt slt
let sgt insInfo ctxt = basicOperation insInfo ctxt sgt
let eq insInfo ctxt = basicOperation insInfo ctxt (==)

let iszero insInfo ctxt =
  let builder = new StmtBuilder (8)
  let opSize = OperationSize.regType
  let dst = tmpVar opSize
  startMark insInfo builder
  let src = getOneInputFromStack ctxt builder
  builder <! (dst := zExt opSize (src == num0 opSize))
  opPush ctxt dst builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let logAnd insInfo ctxt = basicOperation insInfo ctxt (.&)
let logOr insInfo ctxt = basicOperation insInfo ctxt (.|)
let xor insInfo ctxt = basicOperation insInfo ctxt (<+>)

let not insInfo ctxt =
  let builder = new StmtBuilder (8)
  let opSize = OperationSize.regType
  let dst = tmpVar opSize
  startMark insInfo builder
  let src = getOneInputFromStack ctxt builder
  builder <! (dst := zExt opSize (not src))
  opPush ctxt dst builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let byte insInfo ctxt =
  let builder = new StmtBuilder (8)
  let dst = tmpVar OperationSize.regType
  startMark insInfo builder
  let src1, src2 = getTwoInputsFromStack ctxt builder
  let num i = num <| BitVector.ofInt32 i OperationSize.regType
  builder <! (dst := (src2 >> (num 248 .- src1 .* num 8)) .& num 0xff)
  opPush ctxt dst builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let shl insInfo ctxt = basicOperation insInfo ctxt (<<)
let shr insInfo ctxt = basicOperation insInfo ctxt (>>)
let sar insInfo ctxt = basicOperation insInfo ctxt (?>>)

let pop insInfo ctxt =
  let builder = new StmtBuilder (4)
  startMark insInfo builder
  opPop ctxt builder |> ignore
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let mload insInfo ctxt =
  let builder = new StmtBuilder (8)
  let opSize = OperationSize.regType
  let value = tmpVar opSize
  startMark insInfo builder
  let offset = getOneInputFromStack ctxt builder
  builder <! (value := loadLE opSize (offset .+ numI32 32 opSize))
  opPush ctxt value builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let mstore insInfo ctxt =
  let builder = new StmtBuilder (8)
  let opSize = OperationSize.regType
  startMark insInfo builder
  let offset, value = getTwoInputsFromStack ctxt builder
  builder <! (loadLE opSize (offset .+ numI32 32 opSize) := value)
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let mstore8 insInfo ctxt =
  let builder = new StmtBuilder (8)
  let opSize = OperationSize.regType
  startMark insInfo builder
  let offset, value = getTwoInputsFromStack ctxt builder
  let num i = numI32 i opSize
  builder <! (loadLE opSize (offset .+ num 32) := value .& num 0xff)
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let jump insInfo ctxt =
  let builder = new StmtBuilder (8)
  startMark insInfo builder
  let src = getOneInputFromStack ctxt builder
  builder <! (getRegVar ctxt R.PC := extractLow 64<rt> src)
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let jumpi insInfo ctxt =
  let builder = new StmtBuilder (8)
  startMark insInfo builder
  let src, cond = getTwoInputsFromStack ctxt builder
  let src = extractLow 64<rt> src
  let pc = getRegVar ctxt R.PC
  builder <! (pc := ite (extractLow 1<rt> cond) src (pc .+ num1 64<rt>))// FIXME
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let getpc insInfo ctxt =
  let builder = new StmtBuilder (8)
  startMark insInfo builder
  let pc = getRegVar ctxt R.PC |> zExt OperationSize.regType
  opPush ctxt pc builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let gas insInfo ctxt =
  let builder = new StmtBuilder (8)
  startMark insInfo builder
  let gasRemaining = tmpVar OperationSize.regType
  builder <! (gasRemaining := zExt OperationSize.regType (getRegVar ctxt R.GAS))
  opPush ctxt gasRemaining builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let push insInfo ctxt imm =
  let builder = new StmtBuilder (8)
  let dst = tmpVar OperationSize.regType
  startMark insInfo builder
  builder <! (dst := zExt OperationSize.regType (num imm))
  opPush ctxt dst builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let dup insInfo ctxt pos =
  let builder = new StmtBuilder (8)
  let value = tmpVar OperationSize.regType
  startMark insInfo builder
  let sp = getRegVar ctxt R.SP
  let pos = numI32 (pos * 32) OperationSize.regType
  builder <! (value := loadLE OperationSize.regType (sp .+ pos))
  opPush ctxt value builder
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

let swap insInfo ctxt pos =
  let builder = new StmtBuilder (8)
  startMark insInfo builder
  let sp = getRegVar ctxt R.SP
  let pos = numI32 (pos * 32) OperationSize.regType
  let tmp = tmpVar OperationSize.regType
  let src1 = loadLE OperationSize.regType sp
  let src2 = loadLE OperationSize.regType (sp .+ pos)
  builder <! (tmp := src1)
  builder <! (loadLE OperationSize.regType sp := src2)
  builder <! (loadLE OperationSize.regType (sp .+ pos) := tmp)
  updateGas ctxt insInfo.GAS builder
  endMark insInfo builder

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
  | Op.EXP -> sideEffects insInfo UndefinedInstr
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
  | Op.SHA3 -> sideEffects insInfo UndefinedInstr
  | Op.ADDRESS
  | Op.BALANCE
  | Op.ORIGIN
  | Op.CALLER
  | Op.CALLVALUE
  | Op.CALLDATALOAD
  | Op.CALLDATASIZE
  | Op.CALLDATACOPY
  | Op.CODESIZE
  | Op.CODECOPY
  | Op.GASPRICE
  | Op.EXTCODESIZE
  | Op.EXTCODECOPY
  | Op.RETURNDATASIZE
  | Op.RETURNDATACOPY
  | Op.BLOCKHASH
  | Op.COINBASE
  | Op.TIMESTAMP
  | Op.NUMBER
  | Op.DIFFICULTY
  | Op.GASLIMIT -> sideEffects insInfo UndefinedInstr
  | Op.POP -> pop insInfo ctxt
  | Op.MLOAD -> mload insInfo ctxt
  | Op.MSTORE -> mstore insInfo ctxt
  | Op.MSTORE8 -> mstore8 insInfo ctxt
  | Op.SLOAD -> sideEffects insInfo UndefinedInstr
  | Op.SSTORE -> sideEffects insInfo UndefinedInstr
  | Op.JUMP -> jump insInfo ctxt
  | Op.JUMPI -> jumpi insInfo ctxt
  | Op.GETPC -> getpc insInfo ctxt
  | Op.MSIZE -> sideEffects insInfo UndefinedInstr
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
  | Op.DUP1 -> dup insInfo ctxt 0
  | Op.DUP2 -> dup insInfo ctxt 1
  | Op.DUP3 -> dup insInfo ctxt 2
  | Op.DUP4 -> dup insInfo ctxt 3
  | Op.DUP5 -> dup insInfo ctxt 4
  | Op.DUP6 -> dup insInfo ctxt 5
  | Op.DUP7 -> dup insInfo ctxt 6
  | Op.DUP8 -> dup insInfo ctxt 7
  | Op.DUP9 -> dup insInfo ctxt 8
  | Op.DUP10 -> dup insInfo ctxt 9
  | Op.DUP11 -> dup insInfo ctxt 10
  | Op.DUP12 -> dup insInfo ctxt 11
  | Op.DUP13 -> dup insInfo ctxt 12
  | Op.DUP14 -> dup insInfo ctxt 13
  | Op.DUP15 -> dup insInfo ctxt 14
  | Op.DUP16 -> dup insInfo ctxt 15
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
  | Op.CALL
  | Op.CALLCODE
  | Op.RETURN
  | Op.DELEGATECALL
  | Op.CREATE2
  | Op.STATICCALL
  | Op.TXEXECGAS
  | Op.REVERT
  | Op.INVALID
  | Op.SELFDESTRUCT -> sideEffects insInfo UndefinedInstr
  |> fun builder -> builder.ToStmts ()
