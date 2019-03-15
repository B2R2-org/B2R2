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

type PPoint = Addr * int

type DisassemblyBBL (range: AddrRange, instrs, last) =
  inherit RangedVertexData (range)

  /// List of all the instructions in this block.
  member __.Instrs: Instruction list = instrs

  /// The last instruction of this block (to access it efficiently).
  member __.LastInstr: Instruction = last

  /// Do we need to resolve the successor(s) of this basic block?
  member val ToResolve = false with get, set

type IRBBL (ppoint, lastPpoint, stmts, last) =
  inherit VertexData (VertexData.genID ())

  /// This block's starting program point
  member __.Ppoint: PPoint = ppoint

  /// List of all the statements in this block.
  member __.Stmts: Stmt list = stmts

  /// The last statement of this block (to access it efficiently).
  member __.LastStmt: Stmt = last

  /// Program point of the last statement.
  member __.LastPpoint: PPoint = lastPpoint

  /// Do we need to resolve the successor(s) of this basic block?
  member val ToResolve = false with get, set

type CFGEdge =
  | JmpEdge
  | CJmpTrueEdge
  | CJmpFalseEdge

type CFG<'a when 'a :> VertexData> = DiGraph<'a, CFGEdge>

type DisasmVertex = Vertex<DisassemblyBBL>

type DisasmCFG = RangedDiGraph<DisassemblyBBL, CFGEdge>

type IRVertex = Vertex<IRBBL>

type IRCFG = SimpleDiGraph<IRBBL, CFGEdge>

type Function (entry, name) =
  let disasmCFG = DisasmCFG ()
  let irCFG = IRCFG ()
  let mutable ssaCFG = IRCFG ()

  member val Entry : Addr = entry

  member val Name : string = name

  member __.DisasmCFG with get () = disasmCFG

  member __.IRCFG with get () = irCFG

  member __.SSACFG with get () = ssaCFG and set (v) = ssaCFG <- v

type Funcs = Dictionary<Addr, Function>

type CFGBuilder () =
  let instrMap = Dictionary<Addr, Instruction> ()
  let stmtMap = Dictionary<PPoint, Stmt> ()
  let labelMap = Dictionary<Addr * Symbol, int> ()
  let disasmLeaders = Dictionary<Addr, Addr option * bool> ()
  let irLeaders = Dictionary<PPoint, Addr option * bool> ()

  let isExecutable hdl addr =
    match hdl.FileInfo.GetSections addr |> Seq.tryHead with
    | Some s -> s.Kind = SectionKind.ExecutableSection
    | _ -> false

  member __.InstrMap with get () = instrMap

  member __.StmtMap with get () = stmtMap

  member __.LabelMap with get () = labelMap

  member __.DisasmLeaders with get () = disasmLeaders

  member __.IRLeaders with get () = irLeaders

  member val DisasmEnd : Addr = 0UL with get, set

  member __.AddInstr (instr: Instruction) =
    instrMap.[instr.Address] <- instr

  member __.GetInstr addr =
    instrMap.[addr]

  member __.AddStmt ppoint stmt =
    stmtMap.[ppoint] <- stmt

  member __.GetStmt ppoint =
    stmtMap.[ppoint]

  member __.AddLabel (addr, idx) symb =
    labelMap.[(addr, symb)] <- idx

  member __.FindPPointByLabel addr symb =
    let idx = labelMap.[(addr, symb)]
    (addr, idx)

  member __.TryGetEntryByDisasmLeader leader =
    if disasmLeaders.ContainsKey (leader) then
      disasmLeaders.[leader] |> fst |> Some
    else None

  member __.GetParsableByDisasmLeader leader =
    disasmLeaders.[leader] |> snd

  member __.GetLiftableByIRLeader leader =
    irLeaders.[leader] |> snd

  member __.TryGetEntryByIRLeader leader =
    if irLeaders.ContainsKey (leader) then irLeaders.[leader] |> fst |> Some
    else None

  member __.AddDisasmLeader addr =
    disasmLeaders.[addr] <- (None, false)

  member __.ExistDisasmLeader addr =
    disasmLeaders.ContainsKey (addr)

  member __.UpdateEntryOfDisasmLeader addr entry =
    let _, b = disasmLeaders.[addr]
    disasmLeaders.[addr] <- (Some entry, b)

  member __.UpdateParsableOfDisasmLeader addr =
    let entry, _ = disasmLeaders.[addr]
    disasmLeaders.[addr] <- (entry, true)

  member __.GetDisasmLeaders () =
    disasmLeaders.Keys |> Seq.toList |> List.sort

  member __.AddIRLeader ppoint =
    irLeaders.[ppoint] <- (None, false)

  member __.UpdateEntryOfIRLeader ppoint entry =
    let _, b = irLeaders.[ppoint]
    irLeaders.[ppoint] <- (Some entry, b)

  member __.UpdateLiftableOfIRLeader ppoint =
    let entry, _ = irLeaders.[ppoint]
    irLeaders.[ppoint] <- (entry, true)

  member __.GetIRLeaders () =
    irLeaders.Keys |> Seq.toList |> List.sort

  member __.IsInteresting hdl addr =
    hdl.FileInfo.IsValidAddr addr && isExecutable hdl addr
