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

module internal B2R2.Utilities.BinExplorer.HTTPServer

open System
open System.Net
open System.Runtime.Serialization
open System.Runtime.Serialization.Json
open B2R2
open B2R2.FrontEnd
open B2R2.BinGraph
open B2R2.Visualization

type CFGType =
  | DisasmCFG
  | IRCFG
  | SSACFG
  | CallCFG

[<DataContract>]
type JsonFuncInfo = {
  [<field: DataMember(Name = "id")>]
  FuncID: string
  [<field: DataMember(Name = "name")>]
  FuncName: string
}

[<DataContract>]
type JsonSegInfo = {
  [<field: DataMember(Name = "addr")>]
  SegAddr: Addr
  [<field: DataMember(Name = "bytes")>]
  SegBytes: byte []
}

let rootDir =
  let asm = Reflection.Assembly.GetExecutingAssembly ()
  let outDir = IO.Path.GetDirectoryName asm.Location
  IO.Path.Combine (outDir, "WebUI")

let listener host handler =
  let hl = new HttpListener ()
  hl.Prefixes.Add host
  hl.Start()
  let task = Async.FromBeginEnd (hl.BeginGetContext, hl.EndGetContext)
  let rec loop () = async {
    let! context = task
    handler context.Request context.Response
    return! loop ()
  }
  loop ()

let defaultEnc = Text.Encoding.UTF8

let json<'t> (obj: 't) =
  use ms = new IO.MemoryStream ()
  (new DataContractJsonSerializer(typeof<'t>)).WriteObject(ms, obj)
  Text.Encoding.Default.GetString (ms.ToArray ())

let jsonParser<'t> (jsonString:string)  : 't =
  use ms = new IO.MemoryStream (Text.Encoding.Default.GetBytes(jsonString))
  let obj = (new DataContractJsonSerializer(typeof<'t>)).ReadObject(ms)
  obj :?> 't

let readIfExists path =
  if IO.File.Exists path then Some (IO.File.ReadAllBytes (path))
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
    resp.OutputStream.Write (bytes, 0, bytes.Length)
    resp.OutputStream.Close ()
  | None ->
    resp.StatusCode <- 404
    resp.Close ()

let handleBinInfo req resp arbiter =
  let ess = Protocol.getBinEssence arbiter
  let txt = ess.BinHandler.FileInfo.FilePath
  let txt = "\"" + txt.Replace(@"\", @"\\") + "\""
  Some (defaultEnc.GetBytes (txt)) |> answer req resp

let cfgToJSON cfgType ess g roots =
  match cfgType with
  | IRCFG ->
    Visualizer.getJSONFromGraph g roots
  | DisasmCFG ->
    let lens = DisasmLens.Init ess.BinaryApparatus
    let g, roots = lens.Filter g roots ess.BinaryApparatus
    Visualizer.getJSONFromGraph g roots
  | SSACFG ->
    let lens = SSALens.Init ess.BinHandler ess.SCFG
    let g, roots = lens.Filter g roots ess.BinaryApparatus
    Visualizer.getJSONFromGraph g roots
  | _ -> failwith "Invalid CFG type"

let handleRegularCFG req resp name (ess: BinEssence) cfgType =
  match ess.SCFG.FindFunctionEntryByName name with
  | None -> answer req resp None
  | Some addr ->
    try
      let cfg, root = ess.SCFG.GetFunctionCFG (addr)
      let s = cfgToJSON cfgType ess cfg [root]
      Some (defaultEnc.GetBytes s) |> answer req resp
    with e ->
#if DEBUG
      printfn "%A" e; failwith "[FATAL]: Failed to generate CFG"
#else
      answer req resp None
#endif

let handleCFG req resp arbiter cfgType name =
  let ess = Protocol.getBinEssence arbiter
  match cfgType with
  | CallCFG ->
    try
      let lens = CallGraphLens.Init ess.SCFG
      let cfg = ess.SCFG.Graph
      let g, roots = lens.Filter cfg [] ess.BinaryApparatus
      let s = Visualizer.getJSONFromGraph g roots
      Some (defaultEnc.GetBytes s) |> answer req resp
    with e ->
#if DEBUG
      printfn "%A" e; failwith "[FATAL]: Failed to generate CG"
#else
      answer req resp None
#endif
  | typ -> handleRegularCFG req resp name ess typ

let handleFunctions req resp arbiter =
  let ess = Protocol.getBinEssence arbiter
  let names =
    BinaryApparatus.getInternalFunctions ess.BinaryApparatus
    |> Seq.map (fun c -> { FuncID = c.CalleeID; FuncName = c.CalleeName })
    |> Seq.toArray
  Some (json<(JsonFuncInfo) []> names |> defaultEnc.GetBytes)
  |> answer req resp

let handleHexview req resp arbiter =
  let ess = Protocol.getBinEssence arbiter
  ess.BinHandler.FileInfo.GetSegments ()
  |> Seq.map (fun seg ->
    let bs = BinHandler.ReadBytes (ess.BinHandler, seg.Address, int (seg.Size))
    { SegAddr = seg.Address; SegBytes = bs })
  |> json<seq<JsonSegInfo>>
  |> defaultEnc.GetBytes
  |> Some
  |> answer req resp

let jsonPrinter _ acc line = acc + line + "\n"

let handleCommand req resp arbiter cmdMap (args: string) =
  let result = CLI.handle cmdMap arbiter args "" jsonPrinter
  Some (json<string> result  |> defaultEnc.GetBytes) |> answer req resp

let handleAJAX req resp arbiter cmdMap query args =
  match query with
  | "BinInfo" -> handleBinInfo req resp arbiter
  | "Disasm" -> handleCFG req resp arbiter DisasmCFG args
  | "LowUIR" -> handleCFG req resp arbiter IRCFG args
  | "SSA" -> handleCFG req resp arbiter SSACFG args
  | "CG" -> handleCFG req resp arbiter CallCFG args
  | "Functions" -> handleFunctions req resp arbiter
  | "Hexview" -> handleHexview req resp arbiter
  | "Command" -> handleCommand req resp arbiter cmdMap args
  | _ -> answer req resp None

let handle (req: HttpListenerRequest) (resp: HttpListenerResponse) arbiter m =
  match req.Url.LocalPath.Remove (0, 1) with (* Remove the first '/' *)
  | "ajax/" ->
    handleAJAX req resp arbiter m req.QueryString.["q"] req.QueryString.["args"]
  | "" ->
    IO.Path.Combine (rootDir, "index.html") |> readIfExists |> answer req resp
  | path ->
    IO.Path.Combine (rootDir, path) |> readIfExists |> answer req resp

let startServer arbiter ip port verbose =
  let host = "http://" + ip + ":" + port.ToString () + "/"
  let cmdMap = CmdSpec.speclist |> CmdMap.build
  let handler (req: HttpListenerRequest) (resp: HttpListenerResponse) =
    try handle req resp arbiter cmdMap
    with e -> if verbose then eprintfn "%A" e else ()
  listener host handler

// vim: set tw=80 sts=2 sw=2:
