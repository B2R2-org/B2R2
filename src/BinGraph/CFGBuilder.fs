(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Soomin Kim <soomink@kaist.ac.kr>
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

namespace B2R2.BinGraph

open B2R2
open B2R2.BinFile
open B2R2.FrontEnd
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open System.Collections.Generic

type Function (entry, name, regType) =
  let irCFG = IRCFG ()
  let ssaCFG = lazy (SSAGraph.transform regType irCFG (SSACFG ()))

  member val Entry : Addr = entry

  member val Name : string = name

  member val DisasmCFG = DisasmCFG ()

  member __.IRCFG with get () = irCFG

  member __.SSACFG with get () = ssaCFG.Force ()

type Funcs = Dictionary<Addr, Function>

type CFGBuilder () =
  let unanalyzedFuncs = HashSet<Addr> ()
  let instrMap = Dictionary<Addr, Instruction> ()
  let stmtMap = Dictionary<PPoint, Stmt> ()
  let labelMap = Dictionary<Addr * Symbol, int> ()
  let disasmBoundaries = Dictionary<Addr * Addr, Addr option> ()
  let irBoundaries = Dictionary<PPoint * PPoint, Addr option> ()

  let isExecutable hdl addr =
    match hdl.FileInfo.GetSections addr |> Seq.tryHead with
    | Some s -> s.Kind = SectionKind.ExecutableSection
    | _ -> false

  member __.InstrMap with get () = instrMap

  member __.StmtMap with get () = stmtMap

  member __.LabelMap with get () = labelMap

  member __.UnanalyzedFuncs with get () = unanalyzedFuncs

  member __.AddInstr (instr: Instruction) =
    instrMap.[instr.Address] <- instr

  member __.GetInstr addr =
    instrMap.[addr]

  member __.TryGetInstr addr =
    if instrMap.ContainsKey addr then Some instrMap.[addr] else None

  member __.AddStmt ppoint stmt =
    stmtMap.[ppoint] <- stmt

  member __.GetStmt ppoint =
    stmtMap.[ppoint]

  member __.AddLabel (addr, idx) symb =
    labelMap.[(addr, symb)] <- idx

  member __.FindPPointByLabel addr symb =
    let idx = labelMap.[(addr, symb)]
    (addr, idx)

  member __.AddDisasmBoundary startAddr endAddr =
    disasmBoundaries.[(startAddr, endAddr)] <- None

  member __.ExistDisasmBoundary addr =
    disasmBoundaries.Keys |> Seq.map fst |> Seq.contains addr

  member __.RemoveDisasmBoundary boundary =
    disasmBoundaries.Remove boundary |> ignore

  member __.GetDisasmBoundaries () =
    disasmBoundaries.Keys |> Seq.toList |> List.sort

  member __.UpdateEntryOfDisasmBoundary leader entry =
    let boundary =
      Seq.find (fun (sAddr, _) -> sAddr = leader) disasmBoundaries.Keys
    disasmBoundaries.[boundary] <- Some entry

  member __.TryGetEntryByDisasmLeader leader =
    let boundary =
      Seq.find (fun (sAddr, _) -> sAddr = leader) disasmBoundaries.Keys
    if disasmBoundaries.ContainsKey boundary then
      Some disasmBoundaries.[boundary]
    else None

  member __.AddIRBoundary startPpoint endPpoint =
    irBoundaries.[(startPpoint, endPpoint)] <- None

  member __.GetIRBoundaries () =
    irBoundaries.Keys |> Seq.toList |> List.sort

  member __.RemoveIRBoundary boundary =
    irBoundaries.Remove boundary |> ignore

  member __.UpdateEntryOfIRBoundary leader entry =
    let boundary =
      Seq.find (fun (sPpoint, _) -> sPpoint = leader) irBoundaries.Keys
    irBoundaries.[boundary] <- Some entry

  member __.TryGetEntryByIRLeader leader =
    let boundary =
      Seq.find (fun (sAddr, _) -> sAddr = leader) irBoundaries.Keys
    if irBoundaries.ContainsKey boundary then
      Some irBoundaries.[boundary]
    else None

  member __.IsInteresting hdl addr =
    hdl.FileInfo.IsValidAddr addr && isExecutable hdl addr
