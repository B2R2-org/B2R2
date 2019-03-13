(*
    B2R2 - the Next-Generation Reversing Platform

    Author: HyungSeok Han <hyungseok.han@kaist.ac.kr>

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

namespace B2R2.ROP

open System.Collections
open B2R2
open B2R2.BinFile
open B2R2.FrontEnd

type ROPHandle = {
    BinBase   : Addr
    BinHdl    : BinHandler
    Gadgets   : GadgetArr
    Summaries : Concurrent.ConcurrentDictionary<uint64, Summary>
}

module ROPHandle =
    let inline getFileInfo hdl = hdl.BinHdl.FileInfo

    let inline tryFindPlt hdl name =
        hdl.BinHdl.FileInfo.GetLinkageTableEntries ()
        |> Seq.tryFind (fun entry -> entry.FuncName = name)

    let inline getKeys map = Map.fold (fun acc k _ -> Set.add k acc) Set.empty map

    let inline mergeMap m1 m2 = Map.fold (fun acc k v -> Map.add k v acc) m1 m2

    let inline addOffset regMap off = Map.map (fun _ v -> v + off) regMap

    let init binHdl binBase = {
        BinBase   = binBase
        BinHdl    = binHdl
        Gadgets   = Galileo.findGadgets binHdl |> Map.toArray |> GadgetArr.sort
        Summaries = new Concurrent.ConcurrentDictionary<uint64, Summary> ()
    }

    let private getSummary (hdl: ROPHandle) (gadget: Gadget) =
        hdl.Summaries.GetOrAdd (gadget.Offset, (fun _ -> Summary.summary gadget))

    let private getSetterMap hdl =
        let folder acc info =
            let regs = info |> snd |> snd |> getKeys
            match Map.tryFind regs acc with
            | Some infos -> Map.add regs (info :: infos) acc
            | None -> Map.add regs [info] acc
        GadgetArr.pickAll (getSummary hdl >> Summary.isSetter) hdl.Gadgets
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

    let private getRegsSetters hdl setterMap regs =
        let cache = new Concurrent.ConcurrentDictionary<Set<string>, Option<_>> ()
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

    let private setupRegs hdl regVals =
        match getRegsSetters hdl (getSetterMap hdl) (getKeys regVals) with
        | Some (payload, regMap) ->
            Map.fold (fun p r v -> ROPPayload.setExpr v (Map.find r regMap) p)
                              payload regVals
            |> Some
        | None -> None

    let private setVals regMap regVals payload =
        Map.fold (fun p r v -> ROPPayload.setExpr v (Map.find r regMap) p)
                          payload regVals

    let private setAndWrite hdl =
        let setterMap = getSetterMap hdl
        let setableRegs = Map.fold (fun acc k _ -> acc + k) Set.empty setterMap
        let rec chainSetter = function
            | (writer, (eip, ((aReg, aOff), (vReg, vOff)))) :: remain ->
                match getRegsSetters hdl setterMap (Set.ofList [aReg; vReg]) with
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
        GadgetArr.pickAll (getSummary hdl >> Summary.isMemWriter setableRegs)
                                            hdl.Gadgets
        |> List.sortBy (snd >> fst) |> chainSetter

    let write32s hdl addr values =
        match setAndWrite hdl with
        | Some writer ->
            Array.fold
                (fun (p, a) v ->
                    (writer a v |> ROPPayload.merge p, ROPExpr.addNum32 a 4u))
                (ROPPayload.empty, addr) values
            |> fst |> Some
        | None -> None

    let private getEspAdder hdl min =
        let chooser = getSummary hdl >> Summary.isEspAdder min
        match GadgetArr.pickAll chooser hdl.Gadgets with
        | [] -> None
        | cands ->
            List.minBy (fun (g, o) -> (List.length g.Instrs) + o) cands |> Some

    let funCall hdl (func: ROPExpr) (args: ROPExpr array) =
        match getEspAdder hdl args.Length with
        | Some (adder, incOff) ->
            ROPPayload.initWithExpr func
            |> ROPPayload.addGadget adder
            |> ROPPayload.addExprs args
            |> ROPPayload.addDummy32 (incOff - args.Length)
            |> Some
        | None -> None

    let private findBytes hdl bytes =
        let chooser (seg: Segment) =
            let min = seg.Address
            BinHandler.ReadBytes (hdl.BinHdl, min, int seg.Size)
            |> ByteArray.tryFindIdx min bytes
        (getFileInfo hdl).GetSegments Permission.Readable
        |> Seq.tryPick chooser


    let private getWritableAddr hdl =
        let seg =
            (getFileInfo hdl).GetSegments Permission.Writable
            |> Seq.maxBy (fun seg -> seg.Size)
        seg.Address + hdl.BinBase

    let private getOrWriteStr hdl str =
        let bytes = String.toBytes str
        match findBytes hdl bytes with
        | None ->
            let addr = getWritableAddr hdl
            let payload =
                ByteArray.toUInt32Arr bytes
                |> Array.map ROPExpr.ofUInt32
                |> write32s hdl (ROPExpr.ofUInt32 addr)
            if Option.isSome payload then Some (payload, addr)
            else None
        | Some addr -> Some (None, addr)

    let private getSysCall hdl =
        GadgetArr.tryFind (getSummary hdl >> Summary.isSysCall) hdl.Gadgets

    let private syscallRegs = [| "EAX"; "EBX"; "ECX"; "EDX"; "ESI"; "EDI" |]

    let private getSysCallRegs num args =
        Array.append [|ROPExpr.ofUInt32 num|] args
        |> Array.mapi (fun idx expr -> (Array.get syscallRegs idx, expr))
        |> Map.ofArray

    let private trySysCall hdl num args =
        match getSysCall hdl with
        | Some syscall ->
            getSysCallRegs num args
            |> setupRegs hdl |> ROPPayload.addGadgetToSome syscall
        | None -> None

    let private doSysCall hdl name num args =
        match tryFindPlt hdl name with
        | Some entry -> funCall hdl (ROPExpr.ofUInt32 entry.TableAddress) args
        | None -> trySysCall hdl num args

    let sysOpen hdl fname opt = doSysCall hdl "open" 0x05u [|fname; opt|]

    let sysRead hdl fd buf size = doSysCall hdl "read" 0x03u [|fd; buf; size|]

    let sysWrite hdl fd buf size = doSysCall hdl "write" 0x04u [|fd; buf; size|]

    let sysExecve hdl fname args env =
        doSysCall hdl "execve" 0x0bu [|fname; args; env|]

    let private shellWithExecve hdl =
        match getOrWriteStr hdl "/bin/sh" with
        | Some (p1, shAddr) ->
            sysExecve hdl (ROPExpr.ofUInt32 shAddr) ROPExpr.zero32 ROPExpr.zero32
            |> ROPPayload.mergeAny p1
        | None -> None

    let private shellWithSystem hdl =
        match tryFindPlt hdl "system", getOrWriteStr hdl "sh" with
        | Some e, Some (p1, shAddr) ->
            funCall hdl (ROPExpr.ofUInt32 e.TableAddress) [|ROPExpr.ofUInt32 shAddr|]
            |> ROPPayload.mergeAny p1
        | _, _ -> None

    let findShellCode hdl =
        match Array.tryFind (getSummary hdl >> Summary.isShellCode) hdl.Gadgets with
        | Some g -> Some [|ROPValue.Gadget g|]
        | None -> None

    let execShell hdl =
        Monads.OrElse.orElse {
            yield! shellWithSystem hdl
            yield! shellWithExecve hdl
            yield! findShellCode hdl
        }

    let private getRegSetter hdl setterMap reg value =
        match findSetter setterMap (Set.ofList [reg]) Set.empty with
        | Some (gadget, (eip, regMap)) ->
            ROPPayload.empty
            |> ROPPayload.addGadget gadget
            |> ROPPayload.addDummy32 eip
            |> ROPPayload.setExpr value ((Map.find reg regMap) + 1) |> Some
        | None -> None

    let indirectStackPivot hdl setterMap esp =
        let setableRegs =
            getSetterMap hdl |> Map.fold (fun acc k _ -> acc + k) Set.empty
        let rec chain = function
            | (pivotor, (reg, off)) :: remain ->
                match getRegSetter hdl setterMap reg (ROPExpr.subNum32 esp off) with
                | Some setter ->
                    ROPPayload.empty
                    |> ROPPayload.addGadget pivotor
                    |> ROPPayload.merge setter |> Some
                | None -> None
            | [] -> None
        GadgetArr.pickAll (getSummary hdl >> Summary.isStackPivotor setableRegs)
                                            hdl.Gadgets
        |> List.sortBy (fun (g, _) -> List.length g.Instrs) |> chain

    let stackPivot hdl esp =
        let setterMap = getSetterMap hdl
        match getRegSetter hdl setterMap "ESP" esp with
        | None -> indirectStackPivot hdl setterMap esp
        | payload -> payload
