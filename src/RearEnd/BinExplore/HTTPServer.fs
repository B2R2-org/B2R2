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
module internal B2R2.RearEnd.BinExplore.HTTPServer

open System
open System.IO
open System.Net
open B2R2

let listen host reqHandler =
  let hl = new HttpListener()
  hl.Prefixes.Add host
  hl.Start()
  let rec loop () =
    async {
      let! context = Async.FromBeginEnd(hl.BeginGetContext, hl.EndGetContext)
      try reqHandler context.Request context.Response
      with _ -> ()
      return! loop ()
    }
  loop ()
  |> Async.Start

let pathToContentType (path: string) =
  match Path.GetExtension path with
  | ".css" -> "text/css"
  | ".js" -> "text/javascript"
  | ".png" -> "image/png"
  | ".jpg" -> "image/jpeg"
  | ".ico" -> "image/x-icon"
  | ".woff2" -> "font/woff2"
  | _ -> "text/html"

let answer (req: HttpListenerRequest) (resp: HttpListenerResponse) = function
  | Some bytes ->
    resp.ContentType <- pathToContentType req.Url.LocalPath
    resp.ContentEncoding <- encoding
    resp.OutputStream.Write(bytes, 0, bytes.Length)
    resp.OutputStream.Close()
  | None ->
    resp.StatusCode <- 404
    resp.Close()

let invokeAPI (req: HttpListenerRequest) arbiter cmdStore =
  let query, args = req.QueryString["q"], req.QueryString["args"]
  match query with
  | "BinInfo" -> API.getBinInfo arbiter
  | "Disasm" -> API.getCFG arbiter API.CFGKind.Disasm args
  | "LowUIR" -> API.getCFG arbiter API.CFGKind.IR args
  | "SSA" -> API.getCFG arbiter API.CFGKind.SSA args
  | "CG" -> API.getCFG arbiter API.CFGKind.Call args
  | "Functions" -> API.getFunctions arbiter true
  | "Hexview" -> API.getHexview arbiter
  | "Command" -> API.runCommand arbiter cmdStore args
  | "DataFlow" -> API.getDataflow arbiter args
  | _ -> None

let [<Literal>] WebBaseDir = "WebUI"

let rootDir =
  let asm = Reflection.Assembly.GetExecutingAssembly()
  let outDir = Path.GetDirectoryName asm.Location
  Path.Combine(outDir, WebBaseDir)

let readIfExists path =
  if File.Exists path then Some(File.ReadAllBytes(path))
  else None

let handleWebRequest (req: HttpListenerRequest) resp arbiter cmdStore =
  match req.Url.LocalPath.Remove(0, 1) with (* Remove the first '/' *)
  | "ajax/" ->
    invokeAPI req arbiter cmdStore
    |> answer req resp
  | "" ->
    Path.Combine(rootDir, "index.html")
    |> readIfExists
    |> answer req resp
  | path ->
    Path.Combine(rootDir, path)
    |> readIfExists
    |> answer req resp

let start arbiter ip (port: int) isVerbose cmdStore =
  let host = $"http://{ip}:{port.ToString()}/"
  let reqHandler (req: HttpListenerRequest) (resp: HttpListenerResponse) =
    try handleWebRequest req resp arbiter cmdStore
    with e -> if isVerbose then eprintfn "%A" e else ()
  listen host reqHandler
