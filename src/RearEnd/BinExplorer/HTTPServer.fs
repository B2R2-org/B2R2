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

module internal B2R2.RearEnd.BinExplorer.HTTPServer

open System
open System.Net
open System.Runtime.Serialization
open System.Runtime.Serialization.Json
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.DataFlow
open B2R2.RearEnd.Visualization

type CFGType =
  | DisasmCFG = 0
  | IRCFG = 1
  | SSACFG = 2
  | CallCFG = 3

[<DataContract>]
type JsonFuncInfo =
  { [<field: DataMember(Name = "id")>]
    FuncID: string
    [<field: DataMember(Name = "name")>]
    FuncName: string }

[<DataContract>]
type DataColoredHexAscii =
  { [<field: DataMember(Name = "color")>]
    Color: string
    [<field: DataMember(Name = "hex")>]
    Hex: string
    [<field: DataMember(Name = "ascii")>]
    Ascii: string }

[<DataContract>]
type JsonSegInfo =
  { [<field: DataMember(Name = "addr")>]
    SegAddr: Addr
    [<field: DataMember(Name = "bytes")>]
    SegBytes: byte[]
    [<field: DataMember(Name = "coloredHexAscii")>]
    SegColoredHexAscii: DataColoredHexAscii[] }

[<DataContract>]
type JsonVarPoint =
  { [<field: DataMember(Name = "addr")>]
    VarAddr: Addr
    [<field: DataMember(Name = "name")>]
    VarNames: string[] }

let rootDir =
  let asm = Reflection.Assembly.GetExecutingAssembly()
  let outDir = IO.Path.GetDirectoryName asm.Location
  IO.Path.Combine(outDir, "WebUI")

let listener host handler =
  let hl = new HttpListener()
  hl.Prefixes.Add host
  hl.Start()
  let task = Async.FromBeginEnd(hl.BeginGetContext, hl.EndGetContext)
  let rec loop () =
    async {
      let! context = task
      handler context.Request context.Response
      return! loop ()
    }
  loop ()

let defaultEnc = Text.Encoding.UTF8

let json<'T> (obj: 'T) =
  use ms = new IO.MemoryStream()
  (DataContractJsonSerializer(typeof<'T>)).WriteObject(ms, obj)
  Text.Encoding.Default.GetString(ms.ToArray())

let jsonParser<'T> (jsonString: string): 'T =
  use ms = new IO.MemoryStream(Text.Encoding.Default.GetBytes(jsonString))
  let obj = (DataContractJsonSerializer(typeof<'T>)).ReadObject(ms)
  obj :?> 'T

let readIfExists path =
  if IO.File.Exists path then Some(IO.File.ReadAllBytes(path))
  else None

let getContentType (path: string) =
  match IO.Path.GetExtension path with
  | ".css" -> "text/css"
  | ".js" -> "text/javascript"
  | ".png" -> "image/png"
  | ".jpg" -> "image/jpeg"
  | ".ico" -> "image/x-icon"
  | ".woff2" -> "font/woff2"
  | _ -> "text/html"

let answer (req: HttpListenerRequest) (resp: HttpListenerResponse) = function
  | Some bytes ->
    resp.ContentType <- getContentType req.Url.LocalPath
    resp.ContentEncoding <- defaultEnc
    resp.OutputStream.Write(bytes, 0, bytes.Length)
    resp.OutputStream.Close()
  | None ->
    resp.StatusCode <- 404
    resp.Close()

let handleBinInfo req resp (arbiter: Arbiter<_, _>) =
  let brew = arbiter.GetBinaryBrew()
  let txt = brew.BinHandle.File.Path
  let txt = "\"" + txt.Replace(@"\", @"\\") + "\""
  Some(defaultEnc.GetBytes(txt)) |> answer req resp

let cfgToJSON cfgType (brew: BinaryBrew<_, _>) (g: LowUIRCFG) =
  match cfgType with
  | CFGType.IRCFG ->
    let roots = g.Roots |> Seq.toList
    Visualizer.getJSONFromGraph g roots
  | CFGType.DisasmCFG ->
    let file = brew.BinHandle.File
    let disasmBuilder = AsmWordDisasmBuilder(true, file, file.ISA.WordSize)
    let g = DisasmCFG(disasmBuilder, g)
    let roots = g.Roots |> Seq.toList
    Visualizer.getJSONFromGraph g roots
  | CFGType.SSACFG ->
    let factory = SSA.SSALifterFactory.Create brew.BinHandle
    let ssaCFG = factory.Lift g
    let roots = ssaCFG.Roots |> List.ofArray
    Visualizer.getJSONFromGraph ssaCFG roots
  | _ -> failwith "Invalid CFG type"

let handleRegularCFG req resp funcID (brew: BinaryBrew<_, _>) cfgType =
  let func = brew.Functions.FindByID funcID
  try
    let s = cfgToJSON cfgType brew func.CFG
    Some(defaultEnc.GetBytes s) |> answer req resp
  with e ->
#if DEBUG
    printfn "%A" e; failwith "[FATAL]: Failed to generate CFG"
#else
    answer req resp None
#endif

let handleCFG req resp (arbiter: Arbiter<_, _>) cfgType funcID =
  let brew = arbiter.GetBinaryBrew()
  match cfgType with
  | CFGType.CallCFG ->
    try
      let g, roots = CallGraph.create BinGraph.Imperative brew
      let s = Visualizer.getJSONFromGraph g roots
      Some(defaultEnc.GetBytes s) |> answer req resp
    with e ->
#if DEBUG
      printfn "%A" e; failwith "[FATAL]: Failed to generate CG"
#else
      answer req resp None
#endif
  | typ -> handleRegularCFG req resp funcID brew typ

let handleFunctions req resp (arbiter: Arbiter<_, _>) =
  let brew = arbiter.GetBinaryBrew()
  let names =
    brew.Functions.Sequence
    |> Seq.sortBy (fun fn -> fn.EntryPoint)
    |> Seq.map (fun fn -> { FuncID = fn.ID; FuncName = fn.Name })
    |> Seq.toArray
  Some(json<(JsonFuncInfo) []> names |> defaultEnc.GetBytes)
  |> answer req resp

let handleHexview req resp (arbiter: Arbiter<_, _>) =
  let brew = arbiter.GetBinaryBrew()
  brew.BinHandle.File.GetVMMappedRegions()
  |> Seq.map (fun reg ->
    let size = reg.Max - reg.Min + 1UL
    let bs = brew.BinHandle.ReadBytes(reg.Min, int size)
    let coloredHex =
      bs |> Array.map (fun b -> Color.FromByte b, b.ToString("X2"))
    let coloredAscii =
      bs |> Array.map (fun b -> Color.FromByte b, Byte.getRepresentation b)
    let cha = (* DataColoredHexAscii *)
      Array.map2 (fun (c: Color, h) (_, a) ->
        { Color = c.ToString()
          Hex = h
          Ascii = a }) coloredHex coloredAscii
    { SegAddr = reg.Min; SegBytes = bs; SegColoredHexAscii = cha })
  |> json<seq<JsonSegInfo>>
  |> defaultEnc.GetBytes
  |> Some
  |> answer req resp

let private myprinter _ acc (output: OutString) =
  acc + output.ToString() + Environment.NewLine

let handleCommand req resp arbiter cmdMap (args: string) =
  let result = CLI.handle cmdMap arbiter args "" myprinter
  Some(json<string> result |> defaultEnc.GetBytes) |> answer req resp

let computeConnectedVars chain v =
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

let getVarNames (hdl: BinHandle) = function
  | Regular v ->
    hdl.RegisterFactory.GetRegisterIDAliases v
    |> Array.map (hdl.RegisterFactory.GetRegisterName)
  | _ -> [||]

let handleDataflow req resp (arbiter: Arbiter<_, _>) (args: string) =
  let brew = arbiter.GetBinaryBrew()
  let args = args.Split([| ',' |])
  let entry = args[0] |> uint64
  let addr = args[1] |> uint64
  let tag = args[2] (* either variable or value. *)
  match tag with
  | "variable" ->
    let var = args[3] |> brew.BinHandle.RegisterFactory.GetRegisterID
    try
      let cfg = brew.Functions[entry].CFG
      let chain = DataFlowChain.init cfg true
      let v = { ProgramPoint = ProgramPoint(addr, 0); VarKind = Regular var }
      computeConnectedVars chain v
      |> Set.toArray
      |> Array.map (fun vp ->
        { VarAddr = vp.ProgramPoint.Address
          VarNames = getVarNames brew.BinHandle vp.VarKind })
      |> json<JsonVarPoint []>
      |> defaultEnc.GetBytes
      |> Some
      |> answer req resp
    with e ->
#if DEBUG
      printfn "%A" e; failwith "[FATAL]: Failed to obtain dataflow info"
#else
      answer req resp None
#endif
  | _ -> answer req resp None

let handleAJAX req resp arbiter cmdMap query args =
  match query with
  | "BinInfo" -> handleBinInfo req resp arbiter
  | "Disasm" -> handleCFG req resp arbiter CFGType.DisasmCFG args
  | "LowUIR" -> handleCFG req resp arbiter CFGType.IRCFG args
  | "SSA" -> handleCFG req resp arbiter CFGType.SSACFG args
  | "CG" -> handleCFG req resp arbiter CFGType.CallCFG args
  | "Functions" -> handleFunctions req resp arbiter
  | "Hexview" -> handleHexview req resp arbiter
  | "Command" -> handleCommand req resp arbiter cmdMap args
  | "DataFlow" -> handleDataflow req resp arbiter args
  | _ -> answer req resp None

let handle (req: HttpListenerRequest) (resp: HttpListenerResponse) arbiter m =
  match req.Url.LocalPath.Remove(0, 1) with (* Remove the first '/' *)
  | "ajax/" ->
    handleAJAX req resp arbiter m req.QueryString["q"] req.QueryString["args"]
  | "" ->
    IO.Path.Combine(rootDir, "index.html") |> readIfExists |> answer req resp
  | path ->
    IO.Path.Combine(rootDir, path) |> readIfExists |> answer req resp

let startServer arbiter ip port verbose =
  let host = "http://" + ip + ":" + port.ToString() + "/"
  let cmdMap = CLI.spec |> CmdStore
  let hdl (req: HttpListenerRequest) (resp: HttpListenerResponse) =
    try handle req resp arbiter cmdMap
    with e -> if verbose then eprintfn "%A" e else ()
  listener host hdl
