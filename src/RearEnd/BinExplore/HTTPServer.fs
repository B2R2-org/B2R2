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

let [<Literal>] private ContentType = "application/json"

let answer (resp: HttpListenerResponse) = function
  | Some(json: string) ->
    let bytes = encoding.GetBytes(json)
    resp.ContentType <- ContentType
    resp.ContentEncoding <- encoding
    resp.OutputStream.Write(bytes, 0, bytes.Length)
    resp.OutputStream.Close()
  | None ->
    resp.StatusCode <- 404
    resp.Close()

let invokeAPI (req: HttpListenerRequest) arbiter =
  let query = req.QueryString["q"]
  match query with
  | "getFilePath" ->
    JsonAPI.getFilePath arbiter
    |> Some
  | "getDisasmCFG" ->
    let addr = req.QueryString["addr"]
    let cw = req.QueryString["cw"]
    let ch = req.QueryString["ch"]
    JsonAPI.getDisasmCFG arbiter addr cw ch
    |> Some
  | "getLowUIRCFG" ->
    let addr = req.QueryString["addr"]
    let cw = req.QueryString["cw"]
    let ch = req.QueryString["ch"]
    JsonAPI.getLowUIRCFG arbiter addr cw ch
    |> Some
  | "getSSACFG" ->
    let addr = req.QueryString["addr"]
    let cw = req.QueryString["cw"]
    let ch = req.QueryString["ch"]
    JsonAPI.getSSACFG arbiter addr cw ch
    |> Some
  | "getCallCFG" ->
    JsonAPI.getCallCFG arbiter
    |> Some
  | "getFunctions" ->
    JsonAPI.getFunctions arbiter true
    |> Some
  | "getBytes" ->
    JsonAPI.getBytes arbiter req.QueryString["addr"] req.QueryString["size"]
    |> Some
  | "getImmediateDataflowChain" ->
    let fnAddr = req.QueryString["fnAddr"]
    let insAddr = req.QueryString["insAddr"]
    let register = req.QueryString["register"]
    JsonAPI.getImmediateDataflowChain arbiter fnAddr insAddr register
    |> Some
  | _ ->
    eprintsn $"Unknown API query: {query}"
    None

let readIfExists path =
  if File.Exists path then Some(File.ReadAllBytes(path))
  else None

let handleWebRequest (req: HttpListenerRequest) resp arbiter =
  match req.Url.LocalPath.Remove(0, 1) with (* Remove the first '/' *)
  | "api/" ->
    invokeAPI req arbiter
    |> answer resp
  | _ ->
    None
    |> answer resp

let start arbiter ip (port: int) isVerbose =
  let host = $"http://{ip}:{port.ToString()}/"
  let reqHandler (req: HttpListenerRequest) (resp: HttpListenerResponse) =
    try handleWebRequest req resp arbiter
    with e -> if isVerbose then eprintfn "%A" e else ()
  listen host reqHandler
