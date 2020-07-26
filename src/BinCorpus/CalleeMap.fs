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

namespace B2R2.BinCorpus

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
  CalleeID: string
  CalleeName: string
  Addr: Addr option
  CalleeKind: CalleeKind
  Callers: Set<Addr>
  /// Is this callee a no-return function such as "exit"?
  mutable IsNoReturn: bool
}
with
  static member private obtainFuncIDAndName (hdl: BinHandler) (addr: Addr) =
    let id = "func_" + addr.ToString ("X")
    match hdl.FileInfo.TryFindFunctionSymbolName addr |> Utils.tupleToOpt with
    | None -> id, id
    | Some name -> id, name

  static member Init hdl addr calleeKind =
    let id, name = Callee.obtainFuncIDAndName hdl addr
    { CalleeID = id
      CalleeName = name
      Addr = Some addr
      CalleeKind = calleeKind
      Callers = Set.empty
      IsNoReturn = false }

  static member AddCaller callerAddr callee =
    { callee with Callers = Set.add callerAddr callee.Callers }

  static member RemoveCaller callerAddr callee =
    { callee with Callers = Set.remove callerAddr callee.Callers }

/// A mapping from callee's name to its information.
type CalleeMap (hdl, ?linkMap, ?strCalleeMap, ?addrCalleeMap, ?callerMap) =
  let buildLinkMap hdl =
    hdl.FileInfo.GetLinkageTableEntries ()
    |> Seq.fold (fun map entry ->
      Map.add entry.TableAddress entry.FuncName map
      |> Map.add entry.TrampolineAddress entry.FuncName) Map.empty
  let linkMap = defaultArg linkMap <| buildLinkMap hdl
  let strCalleeMap = defaultArg strCalleeMap Map.empty
  let addrCalleeMap = defaultArg addrCalleeMap Map.empty
  let callerMap = defaultArg callerMap Map.empty

  member __.Callees with get () = addrCalleeMap |> Map.toSeq |> Seq.map snd
  member __.Entries with get () =
    addrCalleeMap |> Map.toSeq |> Seq.map fst |> Set.ofSeq
  member __.CallerMap with get () = callerMap
  member __.Contains (addr) = Map.containsKey addr addrCalleeMap
  member __.Contains (name) = Map.containsKey name strCalleeMap
  member __.Find (addr) = Map.tryFind addr addrCalleeMap
  member __.Find (name) =
    Map.tryFind name strCalleeMap
    |> Option.bind (fun addr -> Map.tryFind addr addrCalleeMap)

  member __.InternalCallees with get () =
    addrCalleeMap |> Map.toSeq |> Seq.map snd
    |> Seq.filter (fun c -> c.Addr.IsSome)

  member private __.AddCallee hdl entry =
    if Map.containsKey entry addrCalleeMap then strCalleeMap, addrCalleeMap
    else
      let callee =
        if Map.containsKey entry linkMap then ExternalCallee else InternalCallee
        |> Callee.Init hdl entry
      let strCalleeMap = Map.add callee.CalleeID entry strCalleeMap
      let addrCalleeMap = Map.add entry callee addrCalleeMap
      strCalleeMap, addrCalleeMap

  member __.AddEntry hdl entry =
    let strCalleeMap, addrCalleeMap = __.AddCallee hdl entry
    CalleeMap (hdl, linkMap, strCalleeMap, addrCalleeMap, callerMap)

  member __.AddCaller hdl callerAddr calleeAddr =
    let strCalleeMap, addrCalleeMap = __.AddCallee hdl calleeAddr
    (* Update calleeMap *)
    let callee =
      Map.find calleeAddr addrCalleeMap |> Callee.AddCaller callerAddr
    let addrCalleeMap = Map.add calleeAddr callee addrCalleeMap
    (* Update callerMap *)
    let callerMap =
      match Map.tryFind callerAddr callerMap with
      | Some callees ->
        Map.add callerAddr (Set.add calleeAddr callees) callerMap
      | None -> Map.add callerAddr (Set.singleton calleeAddr) callerMap
    CalleeMap (hdl, linkMap, strCalleeMap, addrCalleeMap, callerMap)

  member __.ReplaceCaller hdl oldCaller newCaller calleeAddr =
    (* Update calleeMap *)
    let callee =
      Map.find calleeAddr addrCalleeMap
      |> Callee.RemoveCaller oldCaller
      |> Callee.AddCaller newCaller
    let addrCalleeMap = Map.add calleeAddr callee addrCalleeMap
    (* Update callerMap *)
    let callees = Map.find oldCaller callerMap
    let callerMap =
      if Set.count callees = 1 then Map.remove oldCaller callerMap
      else Map.add oldCaller (Set.remove calleeAddr callees) callerMap
    let callerMap =
      match Map.tryFind newCaller callerMap with
      | Some callees -> Map.add newCaller (Set.add calleeAddr callees) callerMap
      | None -> Map.add newCaller (Set.singleton calleeAddr) callerMap
    CalleeMap (hdl, linkMap, strCalleeMap, addrCalleeMap, callerMap)

  member __.RemoveCaller callerAddr calleeAddr =
    (* Update calleeMap *)
    let callee =
      Map.find calleeAddr addrCalleeMap |> Callee.RemoveCaller callerAddr
    let addrCalleeMap = Map.add calleeAddr callee addrCalleeMap
    (* Update callerMap *)
    let callees = Map.find callerAddr callerMap |> Set.remove calleeAddr
    let callerMap =
      if Set.isEmpty callees then Map.remove callerAddr callerMap
      else Map.add callerAddr callees callerMap
    CalleeMap (hdl, linkMap, strCalleeMap, addrCalleeMap, callerMap)
