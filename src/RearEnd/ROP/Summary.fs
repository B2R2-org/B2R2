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

namespace B2R2.RearEnd.ROP

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinHandleNS
open B2R2.FrontEnd.BinLifter.Intel

type Summary = {
  InRegs  : Set<Reg>
  InMems  : Set<Value>
  OutRegs : Map<Reg, Value>
  OutMems : Map<Value, Value>
  SysCall : Summary list
  SideEff : bool
}

module Summary =
  let inline mergeInput (r1, m1) (r2, m2) = (r1 + r2, m1 + m2)

  let private emptyInput = (Set.empty, Set.empty)

  // FIXME
  let private ESP =
    Var (32<rt>, Register.toRegID Register.ESP, "ESP", RegisterSet.empty)

  let private REGS =
    [| "EIP"; "ESP"; "EBP"; "EAX"; "EBX"; "ECX"; "EDX"; "ESI"; "EDI" |]

  let private syscallOutRegs =
    Map.ofList [("EAX", Undefined (32<rt>, "EAX0") |> Value)]

  let rec getInput = function
    | Var (_, _, n, _) -> (Set.empty.Add (n), Set.empty)
    | TempVar (_, n) -> failwithf "getInput fail: T_%d" n
    | UnOp (_, expr, _, _) -> getInput expr
    | BinOp (_, _, lExpr, rExpr, _, _) | RelOp (_, lExpr, rExpr, _, _) ->
      mergeInput (getInput lExpr) (getInput rExpr)
    | Load (_, _, expr, _, _) ->
      mergeInput (getInput expr) (Set.empty, Set.empty.Add (Value expr))
    | Ite (cExpr, tExpr, fExpr, _, _) ->
      mergeInput (getInput cExpr) (getInput tExpr)
      |> mergeInput (getInput fExpr)
    | Cast (_, _, expr, _, _) -> getInput expr
    | expr -> emptyInput // Num, Name, PCVar

  let private getInputAll state =
    Set.empty
    |> Map.foldBack (fun _ v acc -> Set.add v acc) state.Regs
    |> Map.foldBack (fun k v acc -> Set.add k acc |> Set.add v) state.Mems
    |> Set.fold (fun acc v -> v.GetExpr () |> getInput |> mergeInput acc)
                emptyInput

  let rec private getSummary (state: State) =
    let inRegs, inMems = getInputAll state
    { InRegs  = inRegs
      InMems  = inMems
      OutRegs = state.Regs
      OutMems = state.Mems
      SysCall = state.SysCall |> List.map getSummary
      SideEff = state.SideEff }

  let private calcOffset n =
    if n % 4 = 0 && n >=0 then Some (n / 4)
    else None

  let private getEspOff = function
    | var when var = ESP -> Some 0
    | BinOp (BinOpType.ADD, 32<rt>, var, Num (n), _, _)
    | BinOp (BinOpType.ADD, 32<rt>, Num (n), var, _, _) when var = ESP ->
      calcOffset (BitVector.toInt32 n)
    | BinOp (BinOpType.SUB, 32<rt>, var, Num (n), _, _) when var = ESP ->
      calcOffset (-(BitVector.toInt32 n))
    | _ -> None

  let private getStackOff (v: Value) =
    match v.GetExpr () with
    | Load (_, 32<rt>, expr, _, _) -> getEspOff expr
    | _ -> None

  let private getRegStackOff reg regs =
    match Map.tryFind reg regs with
    | Some v -> getStackOff v
    | None -> None

  let private getRegsStackOff (sum: Summary) =
    let folder acc reg =
      match getRegStackOff reg sum.OutRegs with
      | Some v -> Map.add reg v acc
      | None -> acc
    Array.fold folder Map.empty REGS

  let private isStackMem (addr: Value) =
    match getEspOff (addr.GetExpr ()) with
    | Some _ -> true
    | None -> false

  let private isStackMems = Set.forall isStackMem

  let private isLinearExpr = function
    | Var (32<rt>, _, reg, _) -> Some (reg, 0u)
    | BinOp (BinOpType.ADD, _, Var (32<rt>, _, reg, _), Num n, _, _)
    | BinOp (BinOpType.ADD, _, Num n, Var (32<rt>, _, reg, _), _, _) ->
      Some (reg, BitVector.toUInt32 n)
    | BinOp (BinOpType.SUB, _, Var (32<rt>, _, reg, _), Num n, _, _)
    | BinOp (BinOpType.SUB, _, Num n, Var (32<rt>, _, reg, _), _, _) ->
      Some (reg, BitVector.neg n |> BitVector.toUInt32)
    | _ -> None

  let private isLinear (value: Value) = value.GetExpr () |> isLinearExpr

  let private getMemWriter regs (sum: Summary) =
    let outMems = sum.OutMems
    if outMems.Count = 1 then
      let addr, value = Map.toList outMems |> List.head
      match isLinear addr, isLinear value with
      | Some (reg1, off1), Some (reg2, off2) ->
        if reg1 <> reg2 && Set.contains reg1 regs && Set.contains reg2 regs then
          Some ((reg1, off1), (reg2, off2))
        else None
      | _, _ -> None
    else None

  let isSysCall (sum: Summary) =
    sum.SideEff && sum.InRegs = Set.empty && sum.InMems = Set.empty
                && sum.OutRegs = syscallOutRegs && sum.OutMems = Map.empty

  let isEspAdder min (sum: Summary) =
    if not sum.SideEff && sum.OutMems = Map.empty && isStackMems sum.InMems then
      match Map.tryFind "EIP" (getRegsStackOff sum) with
      | Some eip ->
        if eip < min then (true, None)
        elif min <= eip then (false, Some eip)
        else (false, None)
      | None -> (false, None)
    else (false, None)

  let inline containKeys keys map =
    Set.forall (fun k -> Map.containsKey k map) keys

  let private isReg reg = Array.exists (fun x -> x = reg) REGS

  let private getRegs regMap =
    let folder acc reg _ =
      if isReg reg then Set.add reg acc
      else acc
    Map.fold folder Set.empty regMap

  let private getLinear reg (sum: Summary) =
    match Map.tryFind reg sum.OutRegs with
    | Some value -> isLinear value
    | None -> None

  let private getLinearLoad reg (sum: Summary) =
    match Map.tryFind reg sum.OutRegs with
    | Some value ->
      match value.GetExpr () with
      | Load (_, _, addr, _, _) -> isLinearExpr addr
      | _ -> None
    | _ -> None

  let isSetter (sum: Summary) =
    if not sum.SideEff && sum.OutMems = Map.empty && isStackMems sum.InMems then
      let regMap = getRegsStackOff sum
      let regSet = getRegs sum.OutRegs |> Set.remove "ESP"
      if regSet.Count > 1 then
        match containKeys regSet regMap, Map.tryFind "EIP" regMap with
        | true, Some eip ->
          if Map.forall (fun reg off -> reg = "EIP" || off < eip) regMap then
            (true, Some (eip, regMap))
          else (false, None)
        | _, _ -> (false, None)
      else (true, None)
    else (false, None)

  let isMemWriter regs (sum: Summary) =
    if not sum.SideEff && isStackMems sum.InMems then
      match Map.tryFind "EIP" (getRegsStackOff sum), getMemWriter regs sum with
      | Some eip, Some writer -> (true, Some (eip, writer))
      | Some eip, None -> (true, None)
      | None, _ -> (false, None)
    else (false, None)

  let isStackPivotor regs (sum: Summary) =
    if not sum.SideEff then
      match getLinear "ESP" sum, getLinearLoad "EIP" sum with
      | Some (r, o), Some eip when r <> "ESP" && eip = (r, o - 4u) ->
        (false, Some eip)
      | _, _ -> (true, None)
    else (false, None)

  let private checkRegs (sum: Summary) regs =
    let checker (reg, v) =
      match Map.tryFind reg sum.OutRegs with
      | Some x when x = (BitVector.ofUInt32 v 32<rt> |> Num |> Value) -> true
      | _ -> false
    Array.forall checker regs

  let private addNum32 (ptr: Value) num =
    Num (BitVector.ofInt32 num 32<rt>)
    |> Simplify.simplifyBinOp BinOpType.ADD 32<rt> (ptr.GetExpr ())
    |> Value

  let private toBytes (value: Value) =
    match value.GetExpr () with
    | Num n -> (BitVector.getValue n).ToByteArray () |> Some
    | _ -> None

  let private readMemStr (sum: Summary) ptr =
    let mems = sum.OutMems
    let read ptr =
      match Map.tryFind ptr mems with
      | Some value -> toBytes value
      | None -> None
    let rec readStr ptr acc =
      match read ptr with
      | Some bytes when Array.contains 0uy bytes ->
        let str = Array.findIndex (fun x -> x = 0uy) bytes
                  |> Array.sub bytes 0 |> String.fromBytes
        acc + str
      | Some bytes ->
        let str = String.fromBytes bytes
        readStr (addNum32 ptr (String.length str)) (acc + str)
      | _ -> ""
    readStr ptr ""

  let private checkShellCode (sum: Summary) =
    match Map.tryFind "EBX" sum.OutRegs with
    | Some ebx ->
      checkRegs sum [|("EAX", 0xbu); ("ECX", 0u); ("EDX", 0u)|]
      && readMemStr sum ebx |> System.IO.Path.GetFullPath = "/bin/sh"
    | None -> false

  let isShellCode (sum: Summary) =
    match sum.SysCall with
    | [sum] when checkShellCode sum -> true
    | _ -> false

  let pp s =
    printfn "-------------[InRegs]-------------"
    Set.iter (fun v -> printfn "  %s" v) s.InRegs
    printfn "-------------[InMems]-------------"
    Set.iter (fun v -> v.ToString() |> printfn "  [%s]") s.InMems
    printfn "-------------[OutRegs]-------------"
    Map.iter (fun k v -> printfn "  %s = %s" k (v.ToString())) s.OutRegs
    printfn "-------------[OutMems]-------------"
    Map.iter (fun k v -> printfn "  [%s] = %s" (k.ToString()) (v.ToString()))
             s.OutMems
    printfn "-----------------------------------"

  let summary hdl gadget =
    gadget.Instrs
    |> List.map (BinHandle.LiftInstr hdl)
    |> Array.concat
    |> Array.fold (State.evalStmt) State.initState
    |> getSummary
