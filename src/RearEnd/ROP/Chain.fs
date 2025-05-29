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

open System
open System.Collections.Concurrent
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile

type ROPHandle = {
  BinBase: Addr
  BinHdl: BinHandle
  LiftingUnit: LiftingUnit
  Gadgets: GadgetArr
  Summaries: ConcurrentDictionary<uint64, Summary>
}

module ROPHandle =
  let inline getFileInfo rop = rop.LiftingUnit.File

  let inline tryFindPlt rop name =
    rop.LiftingUnit.File.GetLinkageTableEntries ()
    |> Seq.tryFind (fun entry -> entry.FuncName = name)

  let inline getKeys map = Map.fold (fun acc k _ -> Set.add k acc) Set.empty map

  let inline mergeMap m1 m2 = Map.fold (fun acc k v -> Map.add k v acc) m1 m2

  let inline addOffset regMap off = Map.map (fun _ v -> v + off) regMap

  let init (binHdl: BinHandle) binBase =
    { BinBase = binBase
      BinHdl = binHdl
      LiftingUnit = binHdl.NewLiftingUnit ()
      Gadgets = Galileo.findGadgets binHdl |> Map.toArray |> GadgetArr.sort
      Summaries = ConcurrentDictionary<uint64, Summary> () }

  let private getSummary (rop: ROPHandle) (gadget: Gadget) =
    try
      rop.Summaries.GetOrAdd (gadget.Offset,
                              (fun _ -> Summary.summary rop.LiftingUnit gadget))
      |> Ok
    with
    | B2R2.BinIR.InvalidExprException as e -> Error <| sprintf "%A" e
    | _ -> reraise ()

  let private getSetterMap rop =
    let folder acc info =
      let regs = info |> snd |> snd |> getKeys
      match Map.tryFind regs acc with
      | Some infos -> Map.add regs (info :: infos) acc
      | None -> Map.add regs [info] acc
    GadgetArr.pickAll (getSummary rop >> Summary.isSetter) rop.Gadgets
    |> List.fold folder Map.empty

  let private findSetter setterMap todoSet doneSet =
    let folder acc regs setters =
      if Set.isSubset todoSet regs
           && (Set.intersect doneSet regs = Set.empty) then
        List.append acc setters
      else acc
    match Map.fold folder [] setterMap with
    | [] -> None
    | cands -> List.minBy (snd >> fst) cands |> Some

  let private getSubsets n set =
    let rec getSubset i = function
      | hd :: remain ->
        if i = n then List.append [Set.ofList [hd]] (getSubset i remain)
        elif i < n then
          List.append
            (getSubset (i + 1) remain |> List.map (fun x -> Set.add hd x))
            (getSubset i remain)
        else failwith "getSubsets fail"
      | [] -> []
    getSubset 1 (Set.toList set)

  let private getRegsSetters setterMap regs =
    let cache = ConcurrentDictionary<Set<string>, Option<_>> ()
    let getSetter todoSet doneSet =
      cache.GetOrAdd (todoSet, (fun k -> findSetter setterMap todoSet doneSet))
    let rec finder todoSet doneSet =
      if todoSet = Set.empty then Some (ROPPayload.empty, Map.empty)
      else
        List.rev [1 .. todoSet.Count]
        |> List.tryPick (fun n -> helper n todoSet doneSet)
    and helper n todoSet doneSet =
      List.tryPick (fun set ->
        match getSetter set doneSet, finder (todoSet - set) (doneSet + set) with
        | Some (gadget, (eip1, regMap1)), Some (p2, regMap2) ->
          let payload =
            (  ROPPayload.empty
              |> ROPPayload.addGadget gadget
              |> ROPPayload.addDummy32 eip1, p2 ) ||> ROPPayload.merge
          let regMap = mergeMap (addOffset regMap1 1)
                                (addOffset regMap2 (eip1 + 1))
          Some (payload, regMap)
        | _, _ -> None) (getSubsets n todoSet)
    finder regs Set.empty

  let private setupRegs rop regVals =
    match getRegsSetters (getSetterMap rop) (getKeys regVals) with
    | Some (payload, regMap) ->
      Map.fold (fun p r v -> ROPPayload.setExpr v (Map.find r regMap) p)
               payload regVals
      |> Some
    | None -> None

  let private setVals regMap regVals payload =
    Map.fold (fun p r v -> ROPPayload.setExpr v (Map.find r regMap) p)
             payload regVals

  let private setAndWrite rop =
    let setterMap = getSetterMap rop
    let setableRegs = Map.fold (fun acc k _ -> acc + k) Set.empty setterMap
    let rec chainSetter = function
      | (writer, (eip, ((aReg, aOff), (vReg, vOff)))) :: remain ->
        match getRegsSetters setterMap (Set.ofList [aReg; vReg]) with
        | Some (setter, regMap) ->
          ( fun addr value ->
            setter
            |> setVals regMap
                ( Map.ofList [ (aReg, ROPExpr.subNum32 addr aOff);
                               (vReg, ROPExpr.subNum32 value vOff) ] )
            |> ROPPayload.addGadget writer
            |> ROPPayload.addDummy32 eip ) |> Some
        | None -> chainSetter remain
      | [] -> None
    GadgetArr.pickAll (getSummary rop >> Summary.isMemWriter setableRegs)
                      rop.Gadgets
    |> List.sortBy (snd >> fst) |> chainSetter

  let write32s rop addr values =
    match setAndWrite rop with
    | Some writer ->
      Array.fold
        (fun (p, a) v ->
          (writer a v |> ROPPayload.merge p, ROPExpr.addNum32 a 4u))
        (ROPPayload.empty, addr) values
      |> fst |> Some
    | None -> None

  let private getEspAdder rop min =
    let chooser = getSummary rop >> Summary.isEspAdder min
    match GadgetArr.pickAll chooser rop.Gadgets with
    | [] -> None
    | cands ->
      List.minBy (fun (g, o) -> (List.length g.Instrs) + o) cands |> Some

  let funCall rop (func: ROPExpr) (args: ROPExpr array) =
    match getEspAdder rop args.Length with
    | Some (adder, incOff) ->
      ROPPayload.initWithExpr func
      |> ROPPayload.addGadget adder
      |> ROPPayload.addExprs args
      |> ROPPayload.addDummy32 (incOff - args.Length)
      |> Some
    | None -> None

  let private findBytes rop bytes =
    let chooser (vmRange: AddrRange) =
      let min = vmRange.Min
      let size = vmRange.Max - vmRange.Min + 1UL
      rop.BinHdl.ReadBytes (min, int size)
      |> ByteArray.tryFindIdx min bytes
    (getFileInfo rop).GetVMMappedRegions Permission.Readable
    |> Seq.tryPick chooser


  let private getWritableAddr rop =
    let vmRange =
      (getFileInfo rop).GetVMMappedRegions Permission.Writable
      |> Array.maxBy (fun range -> range.Max - range.Min + 1UL)
    vmRange.Min + rop.BinBase

  let private toUInt32Arr (src: byte[]) =
    let srcLen = Array.length src
    let dstLen =
      if srcLen % 4 = 0 then srcLen/4
      else (srcLen / 4) + 1
    let dst = Array.init dstLen (fun _ -> 0u)
    Buffer.BlockCopy (src, 0, dst, 0, srcLen)
    dst

  let private getOrWriteStr rop str =
    let bytes = String.toBytes str
    match findBytes rop bytes with
    | None ->
      let addr = getWritableAddr rop
      let payload =
        toUInt32Arr bytes
        |> Array.map ROPExpr.ofUInt32
        |> write32s rop (ROPExpr.ofUInt32 addr)
      if Option.isSome payload then Some (payload, addr)
      else None
    | Some addr -> Some (None, addr)

  let private getSysCall rop =
    GadgetArr.tryFind (getSummary rop >> Summary.isSysCall) rop.Gadgets

  let private syscallRegs = [| "EAX"; "EBX"; "ECX"; "EDX"; "ESI"; "EDI" |]

  let private getSysCallRegs num args =
    Array.append [|ROPExpr.ofUInt32 num|] args
    |> Array.mapi (fun idx expr -> (Array.get syscallRegs idx, expr))
    |> Map.ofArray

  let private trySysCall rop num args =
    match getSysCall rop with
    | Some syscall ->
      getSysCallRegs num args
      |> setupRegs rop |> ROPPayload.addGadgetToSome syscall
    | None -> None

  let private doSysCall rop name num args =
    match tryFindPlt rop name with
    | Some entry -> funCall rop (ROPExpr.ofUInt32 entry.TableAddress) args
    | None -> trySysCall rop num args

  let sysOpen rop fname opt = doSysCall rop "open" 0x05u [|fname; opt|]

  let sysRead rop fd buf size = doSysCall rop "read" 0x03u [|fd; buf; size|]

  let sysWrite rop fd buf size = doSysCall rop "write" 0x04u [|fd; buf; size|]

  let sysExecve rop fname args env =
    doSysCall rop "execve" 0x0bu [|fname; args; env|]

  let private shellWithExecve rop =
    match getOrWriteStr rop "/bin/sh" with
    | Some (p1, shAddr) ->
      sysExecve rop (ROPExpr.ofUInt32 shAddr) ROPExpr.zero32 ROPExpr.zero32
      |> ROPPayload.mergeAny p1
    | None -> None

  let private shellWithSystem rop =
    match tryFindPlt rop "system", getOrWriteStr rop "sh" with
    | Some e, Some (p1, shAddr) ->
      funCall rop (ROPExpr.ofUInt32 e.TableAddress) [|ROPExpr.ofUInt32 shAddr|]
      |> ROPPayload.mergeAny p1
    | _, _ -> None

  let findShellCode rop =
    match Array.tryFind (getSummary rop >> Summary.isShellCode) rop.Gadgets with
    | Some g -> Some [| ROPValue.Gadget g |]
    | None -> None

  let execShell rop =
    shellWithSystem rop
    |> Option.orElseWith (fun () -> shellWithExecve rop)
    |> Option.orElseWith (fun () -> findShellCode rop)

  let private getRegSetter rop setterMap reg value =
    match findSetter setterMap (Set.ofList [reg]) Set.empty with
    | Some (gadget, (eip, regMap)) ->
      ROPPayload.empty
      |> ROPPayload.addGadget gadget
      |> ROPPayload.addDummy32 eip
      |> ROPPayload.setExpr value ((Map.find reg regMap) + 1) |> Some
    | None -> None

  let indirectStackPivot rop setterMap esp =
    let setableRegs =
      getSetterMap rop |> Map.fold (fun acc k _ -> acc + k) Set.empty
    let rec chain = function
      | (pivotor, (reg, off)) :: remain ->
        match getRegSetter rop setterMap reg (ROPExpr.subNum32 esp off) with
        | Some setter ->
          ROPPayload.empty
          |> ROPPayload.addGadget pivotor
          |> ROPPayload.merge setter |> Some
        | None -> None
      | [] -> None
    GadgetArr.pickAll (getSummary rop >> Summary.isStackPivotor setableRegs)
                      rop.Gadgets
    |> List.sortBy (fun (g, _) -> List.length g.Instrs) |> chain

  let stackPivot rop esp =
    let setterMap = getSetterMap rop
    match getRegSetter rop setterMap "ESP" esp with
    | None -> indirectStackPivot rop setterMap esp
    | payload -> payload
