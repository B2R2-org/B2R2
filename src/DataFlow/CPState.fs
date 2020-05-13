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

namespace B2R2.DataFlow

open B2R2
open B2R2.FrontEnd
open B2R2.BinIR.SSA

type CPState = {
  RegState : Map<Variable, CPValue>
  MemState : Map<int, Map<Addr, CPValue>>
  DefaultWordSize : RegType
}

module CPState =

  let private initRegister hdl r regSt =
    let id = hdl.RegisterBay.RegIDFromRegExpr r
    let rt = hdl.RegisterBay.RegTypeFromRegExpr r
    let str = hdl.RegisterBay.RegIDToString id
    let var = { Kind = RegVar (rt, id, str); Identifier = 0 }
    match hdl.RegisterBay.StackPointer with
    | Some sp when sp = id ->
      let c = Const (BitVector.ofUInt64 0x80000000UL rt)
      Map.add var c regSt
    | _ -> Map.add var NotAConst regSt (* Undef? *)

  let top hdl =
    let regSt =
      hdl.RegisterBay.GetAllRegExprs ()
      |> List.fold (fun regSt r -> initRegister hdl r regSt) Map.empty
    let memSt = Map.add 0 Map.empty Map.empty
    { RegState = regSt
      MemState = memSt
      DefaultWordSize = hdl.ISA.WordSize |> WordSize.toRegType }

  let storeReg v c st =
    { st with RegState = Map.add v c st.RegState }

  let tryFindReg v st =
    Map.tryFind v st.RegState

  let loadReg v st =
    Map.find v st.RegState

  let inline initializeMemory mid st =
    if Map.containsKey mid st.MemState then st
    else { st with MemState = Map.add mid Map.empty st.MemState }

  let addMem mid addr c st =
    let st = initializeMemory mid st
    let mem = Map.find mid st.MemState
    let mem = Map.add addr c mem
    c, { st with MemState = Map.add mid mem st.MemState }

  let storeMem mDst mSrc rt addr c st =
    if rt = st.DefaultWordSize then
      if addr % uint64 rt = 0UL then
        addMem mDst.Identifier addr c st
      else NotAConst, st (* Ignore misaligned access *)
    else NotAConst, st (* Ignore small size access *)

  let tryFindMem mid addr st =
    let st = initializeMemory mid st
    let mem = Map.find mid st.MemState
    Map.tryFind addr mem

  let loadMem m rt addr st =
    if rt = st.DefaultWordSize then
      if addr % uint64 rt = 0UL then
        let mid = m.Identifier
        match tryFindMem mid addr st with
        | Some c -> c, st
        | None -> addMem mid addr NotAConst st
      else NotAConst, st (* Invalid misaligned access *)
    else NotAConst, st (* Ignore small size access *)

  let copyMem mDst mSrc st =
    let mem = Map.find mSrc.Identifier st.MemState
    { st with MemState = Map.add mDst.Identifier mem st.MemState }

  let private mergeState st1 st2 =
    st1
    |> Map.fold (fun acc v c ->
      match Map.tryFind v acc with
      | Some c' ->
        let c = CPValue.meet c c'
        Map.add v c acc
      | None -> Map.add v c acc) st2

  let mergeMem mDstid mSrcids st =
    let mem =
      mSrcids
      |> Array.choose (fun mid -> Map.tryFind mid st.MemState)
      |> Array.reduce mergeState
    { st with MemState = Map.add mDstid mem st.MemState }

  let meet (st1: CPState) (st2: CPState) =
    let regSt = mergeState st1.RegState st2.RegState
    let memSt =
      st1.MemState
      |> Map.fold (fun acc mid map ->
        match Map.tryFind mid acc with
        | Some map' ->
          let map = mergeState map map'
          Map.add mid map acc
        | None -> Map.add mid map acc) st2.MemState
    { st1 with RegState = regSt ; MemState = memSt }
