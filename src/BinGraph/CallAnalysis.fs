(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>

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

namespace B2R2.BinGraph

open B2R2
open B2R2.BinFile
open B2R2.FrontEnd
open System.Collections.Generic

/// Callee can be either external or internal.
type CalleeKind =
  | ExternalCallee
  | InternalCallee

/// Callee is a function invoked within the binary under analysis. Callee can be
/// an external function, i.e., it does not need to be defined within the
/// binary. We let a target address be a callee's address if one of the
/// following two conditions hold: (1) the address is a target of a call
/// instruction, and (2) the address is maked as a function in the symbol table,
/// and the function is referenced by a branch instruction (either call or jmp).
type Callee = {
  CalleeName: string
  Addr: Addr option
  CalleeKind: CalleeKind
  Callers: Addr list
}

/// A mapping from a caller address to its callees.
type CallerMap = Dictionary<Addr, Set<Callee>>

/// A mapping from callee's name to its information.
type CalleeMap (map) =
  let strCalleeMap: Map<string, Callee> = map
  let addrCalleeMap = Dictionary<Addr, Callee> ()
  do map
    |> Map.iter (fun _ callee ->
      match callee.Addr with
      | None -> ()
      | Some addr -> addrCalleeMap.[addr] <- callee)

  member __.Callees with get () = strCalleeMap |> Map.toSeq |> Seq.map snd
  member __.Contains (addr) = addrCalleeMap.ContainsKey addr
  member __.Contains (name) = strCalleeMap.ContainsKey name
  member __.Find (addr) = addrCalleeMap.TryGetValue addr |> Utils.tupleToOpt
  member __.Find (name) = Map.tryFind name strCalleeMap

module CallerMap =
  let private accumulateCallee caller callee (m: CallerMap) =
    match m.TryGetValue caller with
    | false, _ -> m.Add (caller, (Set.singleton callee))
    | true, callees -> m.Add (caller, (Set.add callee callees))

  let build (calleeMap: CalleeMap) =
    let m = CallerMap ()
    calleeMap.Callees
    |> Seq.iter (fun callee ->
      callee.Callers
      |> List.iter (fun caller ->
        accumulateCallee caller callee m))
    m

module CalleeMap =
  open Monads.OrElse

  let private buildLinkMap (entries: seq<LinkageTableEntry>) =
    entries
    |> Seq.fold (fun map entry ->
      Map.add entry.TableAddress entry.FuncName map
      |> Map.add entry.TrampolineAddress entry.FuncName
      ) Map.empty

  let private accumulateCallRelationship caller calleeName calleeAddr kind map =
    match Map.tryFind calleeName map with
    | None ->
      let info =
        { CalleeName = calleeName
          Addr = calleeAddr
          CalleeKind = kind
          Callers = [caller] }
      Map.add calleeName info map
    | Some info ->
      Map.add calleeName { info with Callers = caller :: info.Callers } map

  let private obtainFuncName (hdl: BinHandler) addr =
    match hdl.FileInfo.TryFindFunctionSymbolName addr |> Utils.tupleToOpt with
    | None -> "func_" + addr.ToString("X")
    | Some name -> name

  let checkDirectBranch hdl (ins: Instruction) (funcs: Set<Addr>) linkMap =
    match ins.DirectBranchTarget () |> Utils.tupleToOpt with
    | Some target ->
      orElse {
        yield!
          if Set.contains target funcs |> not then None
          else Some (obtainFuncName hdl target, InternalCallee)
        yield!
          Map.tryFind target linkMap
          |> Option.map (fun n -> n, ExternalCallee)
      } |> Option.map (fun (n, kind) -> n, Some target, kind)
    | _ -> None

  let checkIndirectBranch (ins: Instruction) (hdl: BinHandler) =
    match ins.IndirectTrampolineAddr () |> Utils.tupleToOpt with
    | Some addr ->
      hdl.FileInfo.TryFindFunctionSymbolName addr
      |> Utils.tupleToOpt
      |> Option.map (fun n -> n, None, ExternalCallee)
    | _ -> None

  let computeBranchRelationship hdl addr ins funcs linkMap acc =
    orElse {
      yield! checkDirectBranch hdl ins funcs linkMap
      yield! checkIndirectBranch ins hdl
    } |> function
      | None -> acc
      | Some (cn, ca, ck) -> accumulateCallRelationship addr cn ca ck acc

  let addMissingCallees hdl (funcs: Set<Addr>) (cm: Map<string, Callee>) =
    let calleeAddrs =
      cm
      |> Map.toSeq
      |> Seq.choose (fun (_, callee) -> callee.Addr |> Option.map id)
      |> Set.ofSeq
    Set.difference funcs calleeAddrs
    |> Set.fold (fun acc addr ->
        let name = obtainFuncName hdl addr
        Map.add name
          { CalleeName = name
            Addr = Some addr
            CalleeKind = InternalCallee
            Callers = [] } acc) cm

  let build (hdl: BinHandler) funcs (instrMap: InstrMap) =
    let linkMap = hdl.FileInfo.GetLinkageTableEntries () |> buildLinkMap
    instrMap
    |> Seq.fold (fun acc (KeyValue (addr, (ins, _))) ->
      computeBranchRelationship hdl addr ins funcs linkMap acc) Map.empty
    |> addMissingCallees hdl funcs
    |> CalleeMap
