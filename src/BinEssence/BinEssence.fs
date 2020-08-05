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

namespace B2R2.BinEssence

open B2R2
open B2R2.FrontEnd

/// <summary>
///   Binary apparatus (Apparatus) contains the key components and information
///   about our CFG analysis, such as all the parsed instructions from the
///   target binary as well as the positions of all the leaders found. This will
///   be updated through our CFG analyses.
/// </summary>
/// <remarks>
///   <para>B2R2's CFG analyses roughly work as follows.</para>
///   <para>
///     In the very first stage, we recursively parse (and lift) binary
///     instructions starting from the given entry point. In this stage, we
///     simply follow concrete edges. Therefore we may miss indirect branches in
///     this stage, but we will handle them later. After parsing the entire
///     binary, we obtain a mapping (InstrMap) from an address to an InsInfo.
///   </para>
///   <para>
///     Next, we recursively traverse every instruction found again as we did in
///     the first stage, but in this stage, we will analyze lifted LowUIR
///     statements to figure out any internal branches (intra-instruction
///     branches). This step is important to gather all possible program points
///     (ProgramPoint), which are a jump target, i.e., a leader. The leader
///     information is stored in the LeaderInfos field.
///   </para>
///   <para>
///     While we compute the leader positions, we mark every call target
///     encountered to build both CallerMap and CalleeMap. Normally, being a
///     call target (i.e., callee) implies being a function entry. However, this
///     is not always the case. We should not always consider a callee as a
///     function. Nevertheless, our lens-based framework can provide a valid CFG
///     at any callee, which can greatly help further analyses.
///   </para>
///   <para>
///     Once Apparatus is constructed, our SCFG module will then build a graph
///     based on the information found in the Apparatus. The details should be
///     found in the SCFG module.
///   </para>
///   <para>
///     Now that we have obtained basic information (Apparatus and SCFG) to work
///     with, we perform some post analyses to improve the information. For
///     example, we remove unnecessary edges from the SCFG by disconnecting
///     return edges from a function that termiates the process (e.g., exit
///     function), and we recover indirect branch targets to discover more
///     instructions. After the post analyses, we may or may not have an updated
///     Apparatus, in which case we rerun the above steps to update our SCFG
///     (with newly found instructions, etc.). We terminate our analysis when
///     our post analayses do not bring a different Apparatus.
///   </para>
/// </remarks>
type BinEssence = {
  BinHandler : BinHandler
  InstrMap : InstrMap
  SCFG : SCFG
}

module BinEssence =

  let private initEssence hdl graphImpl =
    let acc =
      { InstrMap = InstrMap ()
        BasicBlockMap = SCFGUtils.init ()
        CalleeMap = CalleeMap (hdl)
        Graph = IRCFG.init graphImpl
        NoReturnInfo = NoReturnInfo.Init Set.empty Set.empty
        IndirectBranchMap = Map.empty }
    let scfg = SCFG (hdl, acc, graphImpl=graphImpl)
    { BinHandler = hdl
      InstrMap = acc.InstrMap
      SCFG = scfg }

  let addEntry ess parseMode entry =
    match ess.SCFG.AddEntry ess.BinHandler parseMode entry with
    | Ok (scfg) -> Ok { ess with SCFG = scfg }
    | Error () -> Error ()

  let addEntries ess parseMode entries =
    entries
    |> Set.fold (fun ess entry ->
      match ess with
      | Ok ess -> addEntry ess parseMode entry
      | _ -> ess) (Ok ess)

  let addEdge ess parseMode src dst edgeKind =
    match ess.SCFG.AddEdge ess.BinHandler parseMode src dst edgeKind with
    | Ok (scfg, hasNewIndBranch) ->
      Ok ({ ess with SCFG = scfg }, hasNewIndBranch)
    | Error () -> Error ()

  let addNoReturnInfo ess noRetFuncs noRetCallSites =
    let scfg = ess.SCFG.AddNoReturnInfo ess.BinHandler noRetFuncs noRetCallSites
    { ess with SCFG = scfg }

  let addIndirectBranchMap ess indMap =
    let scfg = ess.SCFG.AddIndirectBranchMap ess.BinHandler indMap
    { ess with SCFG = scfg }

  /// This function returns an initial sequence of entry points obtained from
  /// the binary itself (e.g., from its symbol information). Therefore, if the
  /// binary is stripped, the returned sequence will be incomplete, and we need
  /// to expand it during the other analyses.
  let private getInitialEntryPoints hdl =
    let fi = hdl.FileInfo
    fi.GetFunctionAddresses ()
    |> Set.ofSeq
    |> fun set ->
      match fi.EntryPoint with
      | None -> set
      | Some entry -> Set.add entry set

  let init hdl graphImpl =
    let ess = initEssence hdl graphImpl
    match getInitialEntryPoints hdl |> addEntries ess None with
    | Ok ess -> ess
    | Error _ -> Utils.impossible ()

  let initByEntries hdl graphImpl entries =
    let ess = initEssence hdl graphImpl
    addEntries ess None entries
