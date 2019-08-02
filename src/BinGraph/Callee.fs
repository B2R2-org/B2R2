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

/// Callee can be either external or internal.
type CalleeKind =
  | ExternalCallee
  | InternalCallee

/// Callee is a function invoked within the binary under analysis. Callee can be
/// an external function, i.e., it does not need to be defined within the
/// binary.
type Callee = {
  CalleeName: string
  Addr: Addr option
  CalleeKind: CalleeKind
  Callers: Addr list
}

/// A mapping from callee's name to its information.
type CalleeMap = Map<string, Callee>

module CalleeMap =
  open Monads.OrElse

  let buildLinkMap (entries: seq<LinkageTableEntry>) =
    entries
    |> Seq.fold (fun map entry ->
      Map.add entry.TableAddress entry.FuncName map
      |> Map.add entry.TrampolineAddress entry.FuncName
      ) Map.empty

  let accumulateBranchRelationship caller calleeName calleeAddr kind map =
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

  let checkDirectBranch (ins: Instruction) (funcs: Map<Addr, string>) linkMap =
    match ins.DirectBranchTarget () |> Utils.tupleToOpt with
    | Some target ->
      orElse {
        yield!
          Map.tryFind target funcs
          |> Option.map (fun n -> n, InternalCallee)
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
      yield! checkDirectBranch ins funcs linkMap
      yield! checkIndirectBranch ins hdl
    } |> function
      | None -> acc
      | Some (cn, ca, ck) -> accumulateBranchRelationship addr cn ca ck acc

  let build (hdl: BinHandler) (funcs: Map<Addr, string>) (instrMap: InstrMap) =
    let linkMap = hdl.FileInfo.GetLinkageTableEntries () |> buildLinkMap
    instrMap
    |> Seq.fold (fun acc (KeyValue (addr, (ins, _))) ->
      computeBranchRelationship hdl addr ins funcs linkMap acc) Map.empty
