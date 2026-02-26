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

[<RequireQualifiedAccess>]
module B2R2.RearEnd.BinExplore.API

open System.Text.Json
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.DataFlow
open B2R2.RearEnd.Visualization

type CFGKind =
  | Disasm = 0
  | IR = 1
  | SSA = 2
  | Call = 3

/// Returns the binary file path of the given arbiter.
let getBinInfo (arbiter: Arbiter<_, _>) =
  let brew = arbiter.GetBinaryBrew()
  let txt = brew.BinHandle.File.Path
  let txt = "\"" + txt.Replace(@"\", @"\\") + "\""
  Some(encoding.GetBytes(txt))

let private cfgToJSON cfgType (brew: BinaryBrew<_, _>) (g: LowUIRCFG) =
  match cfgType with
  | CFGKind.IR ->
    let roots = g.Roots |> Seq.toList
    Visualizer.getJSONFromGraph g roots
  | CFGKind.Disasm ->
    let file = brew.BinHandle.File
    let disasmBuilder = AsmWordDisasmBuilder(true, file, file.ISA.WordSize)
    let g = DisasmCFG(disasmBuilder, g)
    let roots = g.Roots |> Seq.toList
    Visualizer.getJSONFromGraph g roots
  | CFGKind.SSA ->
    let factory = SSA.SSALifterFactory.Create brew.BinHandle
    let ssaCFG = factory.Lift g
    let roots = ssaCFG.Roots |> List.ofArray
    Visualizer.getJSONFromGraph ssaCFG roots
  | _ ->
    failwith "Invalid CFG type"

let getRegularCFG funcID (brew: BinaryBrew<_, _>) cfgType =
  let func = brew.Functions.FindByID funcID
  try
    let s = cfgToJSON cfgType brew func.CFG
    Some(encoding.GetBytes s)
  with e ->
#if DEBUG
    eprintfn "%A" e
    failwith "[FATAL]: Failed to generate CFG"
#else
    None
#endif

/// Returns the CFG of the given function ID and CFG type.
let getCFG (arbiter: Arbiter<_, _>) cfgType funcID =
  let brew = arbiter.GetBinaryBrew()
  match cfgType with
  | CFGKind.Call ->
    try
      let g, roots = CallGraph.create BinGraph.Imperative brew
      let s = Visualizer.getJSONFromGraph g roots
      Some(encoding.GetBytes s)
    with e ->
#if DEBUG
      eprintfn "%A" e
      failwith "[FATAL]: Failed to generate CG"
#else
      None
#endif
  | typ ->
    getRegularCFG funcID brew typ

let inline private toJson<'T> (obj: 'T) =
  JsonSerializer.Serialize obj

/// Returns the list of functions in the binary, sorted by their entry point.
let getFunctions (arbiter: Arbiter<_, _>) =
  let brew = arbiter.GetBinaryBrew()
  let names =
    brew.Functions.Sequence
    |> Seq.sortBy (fun fn -> fn.EntryPoint)
    |> Seq.map (fun fn -> { FuncID = fn.ID; FuncName = fn.Name })
    |> Seq.toArray
  Some(toJson names |> encoding.GetBytes)

/// Returns the hex view of the binary, including the address, bytes, and ASCII
/// representation.
let getHexview (arbiter: Arbiter<_, _>) =
  let brew = arbiter.GetBinaryBrew()
  brew.BinHandle.File.GetVMMappedRegions()
  |> Array.map (fun region ->
    let size = region.Max - region.Min + 1UL
    let bs = brew.BinHandle.ReadBytes(region.Min, int size)
    let coloredHex =
      bs |> Array.map (fun b -> Color.FromByte b, b.ToString("X2"))
    let coloredAscii =
      bs |> Array.map (fun b -> Color.FromByte b, Byte.getRepresentation b)
    let coloredBytes = (* DataColoredHexAscii *)
      Array.map2 (fun (c: Color, h) (_, a) ->
        { Color = c.ToString()
          Hex = h
          Ascii = a }) coloredHex coloredAscii
    { SegAddr = region.Min; SegBytes = bs; SegColoredHexAscii = coloredBytes })
  |> toJson
  |> encoding.GetBytes
  |> Some

let private myprinter acc (output: OutString) =
  acc + output.ToString() + System.Environment.NewLine

/// Executes the given command with the provided arguments and returns the
/// result as a JSON string.
let runCommand arbiter cmdStore (line: string) =
  CLI.runCommandLine cmdStore arbiter line
  |> Array.fold myprinter ""
  |> fun s -> s + System.Environment.NewLine
  |> toJson
  |> encoding.GetBytes
  |> Some

let private computeConnectedVars chain v =
  match Map.tryFind v chain.UseDefChain with
  | None ->
    match Map.tryFind v chain.DefUseChain with
    | None -> Set.singleton v
    | Some us -> us
  | Some ds ->
    ds
    |> Set.fold (fun s d ->
      match Map.tryFind d chain.DefUseChain with
      | None -> s
      | Some us -> Set.union us s) ds

let private getVarNames (hdl: BinHandle) = function
  | Regular v ->
    hdl.RegisterFactory.GetRegisterIDAliases v
    |> Array.map (hdl.RegisterFactory.GetRegisterName)
  | _ -> [||]

/// Returns the dataflow information of the given variable at the specified
/// program point.
let getDataflow (arbiter: Arbiter<_, _>) (args: string) =
  let brew = arbiter.GetBinaryBrew()
  let args = args.Split([| ',' |])
  let entry, addr, tag = args[0] |> uint64, args[1] |> uint64, args[2]
  match tag with
  | "variable" ->
    try
      let var = args[3] |> brew.BinHandle.RegisterFactory.GetRegisterID
      let cfg = brew.Functions[entry].CFG
      let chain = DataFlowChain.init cfg true
      let v = { ProgramPoint = ProgramPoint(addr, 0); VarKind = Regular var }
      computeConnectedVars chain v
      |> Set.toArray
      |> Array.map (fun vp ->
        { VarAddr = vp.ProgramPoint.Address
          VarNames = getVarNames brew.BinHandle vp.VarKind })
      |> toJson
      |> encoding.GetBytes
      |> Some
    with e ->
#if DEBUG
      eprintfn "%A" e
      failwith "[FATAL]: Failed to obtain dataflow info"
#else
      None
#endif
  | _ ->
    None
