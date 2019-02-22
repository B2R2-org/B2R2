(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>
          DongYeop Oh <oh51dy@kaist.ac.kr>

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

module B2R2.BinGraph.DisasHeuristic

open B2R2
open B2R2.BinIR.LowUIR.Eval
open B2R2.FrontEnd

/// An arbitrary stack value for applying heuristics.
let stackAddr t = Def (BitVector.ofInt32 0x1000000 t)

let getStackPtrRegID = function
  | Arch.IntelX86 -> Intel.Register.ESP |> Intel.Register.toRegID
  | Arch.IntelX64 -> Intel.Register.RSP |> Intel.Register.toRegID
  | _ -> failwith "Not supported arch."

let initStateForLibcStart handle startAddr =
  let isa = handle.ISA
  // FIXME
  let sp = getStackPtrRegID isa.Arch
  let vars = match isa.Arch with
             | Arch.IntelX86 -> Map.add sp (stackAddr 32<rt>) Map.empty
             | Arch.IntelX64 -> Map.add sp (stackAddr 64<rt>) Map.empty
             | _ -> failwith "Not supported arch."
  {
    PC = startAddr
    BlockEnd = false
    Vars = vars
    TmpVars = Map.empty
    Mems = Map.empty
    NextStmtIdx = 0
    LblMap = Map.empty
  }

let intel32LibcParams acc st =
  let f addr acc =
    try (loadMem st.Mems Endian.Little addr 32<rt> |> BitVector.toUInt64) :: acc
    with InvalidMemException -> acc
  /// 1st, 4th, and 5th parameter of _libc_start_main
  match Map.tryFind (Intel.Register.ESP |> Intel.Register.toRegID) st.Vars with
  | Some (Def esp) -> let esp = BitVector.toUInt64 esp
                      f esp acc |> f (esp + 12UL) |> f (esp + 16UL)
  | _ -> acc

let intel64LibcParams acc st =
  let f var acc =
    match Map.tryFind (Intel.Register.toRegID var) st.Vars with
    | Some (Def addr) -> (BitVector.toUInt64 addr) :: acc
    | _ -> acc
  /// 1st, 4th, and 5th parameter of _libc_start_main
  f Intel.Register.RDI acc |> f Intel.Register.RCX |> f Intel.Register.R8

let findNewLeadersByLibcHeuristic acc handle st =
  match handle.ISA.Arch with
  | Arch.IntelX86 -> intel32LibcParams acc st
  | Arch.IntelX64 -> intel64LibcParams acc st
  | _ -> failwith "Not supported arch."

let rec buildBlock acc startAddr endAddr instrMap =
  let ins: 'T when 'T :> Instruction = Map.find startAddr instrMap
  let nextAddr = startAddr + uint64 ins.Length
  if nextAddr = endAddr then List.rev (ins :: acc)
  else buildBlock (ins :: acc) nextAddr endAddr instrMap

/// Evaluate concretely, but ignore any expressions that involve unknown values.
let analyzeLibcStartBlock st stmts =
  Array.fold (fun st stmt ->
    try evalStmt st emptyCallBack stmt with
    | UnknownVarException (* Simply ignore exceptions *)
    | InvalidMemException -> st
  ) st stmts

let getLibcFuncPtrArgs acc handle leaders instrMap (callerAddr: Addr) =
  let s, _ = Set.partition (fun leaderAddr -> leaderAddr < callerAddr) leaders
  let blockLeader = Set.maxElement s
  let blk = buildBlock [] blockLeader callerAddr instrMap
  let ir = List.map (fun ins -> BinHandler.LiftInstr handle ins) blk
  let st = initStateForLibcStart handle blockLeader
  let st = List.fold analyzeLibcStartBlock st ir
  let acc = findNewLeadersByLibcHeuristic acc handle st
  acc, instrMap

let isLibcStartMain (handle: BinHandler) = function
  | true, "__libc_start_main" -> FileFormat.isELF handle.FileInfo.FileFormat
  | _, _ -> false

let isCallTargetLibcStart handle (ins: 'T when 'T :> Instruction) =
  match ins.DirectBranchTarget () with
  | false, _ -> false
  | true, addr ->
    handle.FileInfo.TryFindFunctionSymbolName addr
    |> isLibcStartMain handle

let isCallingLibcStart handle (ins: 'T when 'T :> Instruction) =
  ins.IsCall () && isCallTargetLibcStart handle ins

/// Examine __libc_start_main's arguments with copy propagation
let recoverLibcPtrs acc handle leaders exits instrMap =
  let callers = List.filter (fun ins -> isCallingLibcStart handle ins) exits
  match callers with
  | [i] -> getLibcFuncPtrArgs acc handle leaders instrMap i.Address
  | _ -> acc, instrMap

let recover handle leaders exits instrMap =
  recoverLibcPtrs [] handle leaders exits instrMap

// vim: set tw=80 sts=2 sw=2:
