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
open B2R2.BinGraph
open B2R2.Visualization

type CFGType =
  | DisasmCFG
  | IRCFG

[<DataContract>]
  type JsonDefs = {
    [<field: DataMember(Name = "name")>]
    Name: string
    [<field: DataMember(Name = "addr")>]
    Addr: string
    [<field: DataMember(Name = "idx")>]
    Idx: string
    [<field: DataMember(Name = "comment")>]
    Comment: string
    [<field: DataMember(Name = "command")>]
    Command: string
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

let getContentType path =
  match IO.Path.GetExtension path with
  | ".css" -> "text/css"
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

let cfgToJSON cfgType hdl g root =
  match cfgType with
  | IRCFG ->
    Visualizer.getJSONFromGraph g root None
  | DisasmCFG ->
    let lens = DisasmLens.Init ()
    let g, root = lens.Filter g root
    Visualizer.getJSONFromGraph g root (Some hdl)

let handleCFG req resp arbiter cfgType name =
  let ess = Protocol.getBinEssence arbiter
  match ess.SCFG.FindFunctionEntryByName name with
  | None -> answer req resp None
  | Some addr ->
    let s = ess.SCFG.GetFunctionCFG (addr) ||> cfgToJSON cfgType ess.BinHandler
    Some (defaultEnc.GetBytes s) |> answer req resp

let handleFunctions req resp arbiter =
  let ess = Protocol.getBinEssence arbiter
  let names =
    Map.toArray ess.BinaryApparatus.FunctionAddrs |> Array.map fst
  Some (json<string []> names |> defaultEnc.GetBytes)
  |> answer req resp

// let getComment hdl addr idx comment (func: Function) = function
//   | DisasmCFG -> Visualizer.setCommentDisasmCFG hdl addr idx comment func.DisasmCFG
//   | IRCFG -> Visualizer.setCommentIRCFG hdl addr idx comment func.IRCFG

// let handleComment req resp arbiter cfgType (args: string) =
//   let commentReq = (jsonParser<JsonDefs> args)
//   let name = commentReq.name
//   let ess = Protocol.getBinEssence arbiter
//   match BinEssence.TryFindFuncByName name ess with
//   | None -> None |> answer req resp
//   | Some func ->
//     let hdl = ess.BinHandler
//     let addr = commentReq.addr
//     let comment = commentReq.comment
//     let idx = commentReq.idx |> int
//     let status = getComment hdl addr idx comment func cfgType
//     Some (json<string> status  |> defaultEnc.GetBytes) |> answer req resp

// let handleAddress req resp arbiter (args: string) =
//   let jsonData = (jsonParser<JsonDefs> args)
//   let entry: Addr =  Convert.ToUInt64(jsonData.addr, 16) |> uint64
//   let ess = Protocol.getBinEssence arbiter
//   let addrs =
//     Array.ofSeq ess.Functions.Values
//     |> Array.map (fun (func: Function) -> func.Entry|> uint64)
//     |> Array.sort
//   let searchedAddr = Array.fold (fun acc x -> if entry >= x then x else acc) 0UL addrs
//   match BinEssence.TryFindFuncByEntry searchedAddr ess with
//   | None -> Some (json<string> "" |> defaultEnc.GetBytes) |> answer req resp
//   | Some func ->
//     let hdl = ess.BinHandler
//     let cfg = Visualizer.visualizeDisasmCFG hdl func.DisasmCFG
//     let namedcfg = cfg.[..cfg.Length-2] + ",\"Name\": \""+ func.Name + "\"}"
//     Some (defaultEnc.GetBytes namedcfg) |> answer req resp

let handleStr cmds arbiter (line: string) =
  match line.Split (' ') |> Array.toList with
  | cmd :: args ->
    let ess = Protocol.getBinEssence arbiter
    Cmd.handle cmds ess cmd args
      |> Array.fold (fun acc x -> acc + x.ToString()+"\n") ""
  | [] -> ""

let jsonPrinter _ acc line = acc + line + "\n"

let handleCommand req resp arbiter (args: string) =
  let jsonData = (jsonParser<JsonDefs> args)
  let cmd = jsonData.Command
  let cmds = CmdSpec.speclist |> CmdMap.build
  let result = CLI.handle cmds arbiter cmd "" jsonPrinter
  Some (json<string> result  |> defaultEnc.GetBytes) |> answer req resp

let handleAJAX req resp arbiter query args =
    match query with
    | "bininfo" -> handleBinInfo req resp arbiter
    | "cfg-disasm" -> handleCFG req resp arbiter DisasmCFG args
    | "cfg-ir" -> handleCFG req resp arbiter IRCFG args
    | "functions" -> handleFunctions req resp arbiter
    | "disasm-comment" -> () // handleComment req resp arbiter DisasmCFG args
    | "ir-comment" -> () // handleComment req resp arbiter IRCFG args
    | "address" -> () // handleAddress req resp arbiter args
    | "command" -> handleCommand req resp arbiter args
    | _ -> ()

let handle (req: HttpListenerRequest) (resp: HttpListenerResponse) arbiter =
  match req.Url.LocalPath.Remove (0, 1) with (* Remove the first '/' *)
  | "ajax/" ->
    handleAJAX req resp arbiter req.QueryString.["q"] req.QueryString.["args"]
  | "" ->
    IO.Path.Combine (rootDir, "index.html") |> readIfExists |> answer req resp
  | path ->
    IO.Path.Combine (rootDir, path) |> readIfExists |> answer req resp

let startServer arbiter port =
  let host = "http://localhost:" + port.ToString () + "/"
  let handler (req: HttpListenerRequest) (resp: HttpListenerResponse) =
    try handle req resp arbiter
    with _ -> () (* Gracefully terminate if a fatal error occurs. *)
  listener host handler

// vim: set tw=80 sts=2 sw=2:
