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
  inherit VertexData (VertexData.genID ())

  let irCFG = IRCFG ()
  let ssaCFG = lazy (SSAGraph.transform regType irCFG (SSACFG ()))

  member val Entry : Addr = entry

  member val Name : string = name

  member val DisasmCFG = DisasmCFG ()

  member __.IRCFG with get () = irCFG

  member __.SSACFG with get () = ssaCFG.Force ()

type CallGraphEdge =
  | CGCallEdge
  | CGRetEdge

type Funcs = Dictionary<Addr, Function>

type CallGraph = SimpleDiGraph<Function, CallGraphEdge>

type CFGBuilder () =
  let unanalyzedFuncs = HashSet<Addr> ()
  let instrMap = Dictionary<Addr, Instruction> ()
  let stmtMap = Dictionary<PPoint, Stmt> ()
  let labelMap = Dictionary<Addr * Symbol, int> ()
  let disasmLeaders = HashSet<Addr> ()
  let disasmBoundaries = Dictionary<Addr, (Addr * Addr) * Addr option> ()
  let irLeaders = HashSet<PPoint> ()
  let irBoundaries = Dictionary<PPoint, (PPoint * PPoint) * Addr option> ()

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
    disasmLeaders.Add startAddr |> ignore
    disasmBoundaries.[startAddr] <- ((startAddr, endAddr), None)

  member __.ExistDisasmBoundary addr =
    disasmLeaders.Contains addr

  member __.RemoveDisasmBoundary leader =
    disasmBoundaries.Remove leader |> ignore

  member __.GetDisasmBoundaries () =
    disasmBoundaries.Values |> Seq.map fst |> Seq.toList |> List.sort

  member __.UpdateEntryOfDisasmBoundary leader entry =
    disasmBoundaries.[leader] <- (fst disasmBoundaries.[leader], Some entry)

  member __.GetEntryByDisasmLeader leader =
    snd disasmBoundaries.[leader]

  member __.TryGetEntryByDisasmLeader leader =
    if disasmBoundaries.ContainsKey leader then
      Some <| snd disasmBoundaries.[leader]
    else None

  member __.AddIRLeader ppoint =
    irLeaders.Add ppoint |> ignore

  member __.GetIRLeaders () =
    irLeaders |> Seq.toList |> List.sort

  member __.AddIRBoundary startPpoint endPpoint =
    irBoundaries.[startPpoint] <- ((startPpoint, endPpoint), None)

  member __.GetIRBoundaries () =
    irBoundaries.Values |> Seq.map fst |> Seq.toList |> List.sort

  member __.RemoveIRBoundary leader =
    irBoundaries.Remove leader |> ignore

  member __.UpdateEntryOfIRBoundary leader entry =
    irBoundaries.[leader] <- (fst irBoundaries.[leader], Some entry)

  member __.GetEntryByIRLeader leader =
    snd irBoundaries.[leader]

  member __.TryGetEntryByIRLeader leader =
    if irBoundaries.ContainsKey leader then
      Some <| snd irBoundaries.[leader]
    else None

  member __.IsInteresting hdl addr =
    hdl.FileInfo.IsValidAddr addr && isExecutable hdl addr
