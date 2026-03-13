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
module B2R2.RearEnd.BinExplore.JsonAPI

open System
open System.Text.Json
open System.Text.Json.Serialization
open B2R2.FrontEnd
open B2R2.MiddleEnd.DataFlow
open B2R2.RearEnd.Visualization

type Status =
  | Success = 0
  | Failure = 1

[<CLIMutable>]
type JsonResult<'T> =
  { [<JsonPropertyName("status")>]
    Status: Status
    [<JsonPropertyName("result")>]
    Result: 'T }

let inline private toJson<'T> (result: Result<'T, string>) =
  match result with
  | Ok res ->
    { Status = Status.Success; Result = res }
    |> JsonSerializer.Serialize
  | Error e ->
    { Status = Status.Failure; Result = e }
    |> JsonSerializer.Serialize

let getFilePath arbiter =
  API.getFilePath arbiter
  |> Result.map (fun path -> "\"" + path.Replace(@"\", @"\\") + "\"")
  |> toJson

let inline private toDouble (s: string) defaultValue =
  try Convert.ToDouble(s) with _ -> defaultValue

let getDisasmCFG arbiter (functionString: string) cwString chString =
  let fnAddr = try Convert.ToUInt64(functionString, 16) with _ -> 0UL
  let cw = toDouble cwString Visualizer.CharWidth
  let ch = toDouble chString Visualizer.CharHeight
  API.getDisasmCFG arbiter fnAddr cw ch
  |> Result.map (fun g ->
    let roots = g.GetRoots() |> List.ofArray
    JSONExport.toStr roots g)
  |> toJson

let getLowUIRCFG arbiter (functionString: string) cwString chString =
  let fnAddr = try Convert.ToUInt64(functionString, 16) with _ -> 0UL
  let cw = toDouble cwString Visualizer.CharWidth
  let ch = toDouble chString Visualizer.CharHeight
  API.getLowUIRCFG arbiter fnAddr cw ch
  |> Result.map (fun g ->
    let roots = g.GetRoots() |> List.ofArray
    JSONExport.toStr roots g)
  |> toJson

let getSSACFG arbiter (functionString: string) cwString chString =
  let fnAddr = try Convert.ToUInt64(functionString, 16) with _ -> 0UL
  let cw = toDouble cwString Visualizer.CharWidth
  let ch = toDouble chString Visualizer.CharHeight
  API.getSSACFG arbiter fnAddr cw ch
  |> Result.map (fun g ->
    let roots = g.GetRoots() |> List.ofArray
    JSONExport.toStr roots g)
  |> toJson

let getCallCFG arbiter =
  API.getCallCFG arbiter
  |> Result.map (fun g ->
    let roots = g.GetRoots() |> List.ofArray
    JSONExport.toStr roots g)
  |> toJson

let getFunctions arbiter isInternal =
  API.getFunctions arbiter isInternal
  |> Result.map (fun funcs ->
    funcs
    |> Array.map (fun fn -> { FuncID = fn.ID; FuncName = fn.Name }))
  |> toJson

let getBytes arbiter addrString (sizeString: string) =
  let addr = try Convert.ToUInt64(addrString, 16) with _ -> 0UL
  let size = try Convert.ToInt32(sizeString) with _ -> 0
  API.getBytes arbiter addr size
  |> toJson

let private getVarNames (hdl: BinHandle) = function
  | Regular v ->
    hdl.RegisterFactory.GetRegisterIDAliases v
    |> Array.map (hdl.RegisterFactory.GetRegisterName)
  | _ -> [||]

let getImmediateDataflowChain arbiter fnAddrString insAddrString register =
  let fnAddr = try Convert.ToUInt64(fnAddrString, 16) with _ -> 0UL
  let insAddr = try Convert.ToUInt64(insAddrString, 16) with _ -> 0UL
  API.getImmediateDataflowChain arbiter fnAddr insAddr register
  |> Result.map (fun vps ->
    arbiter.GetBinaryBrew()
    |> Result.map (fun brew ->
      vps
      |> Array.map (fun vp ->
        { VarAddr = vp.ProgramPoint.Address
          VarNames = getVarNames brew.BinHandle vp.VarKind })
    )
  )
  |> toJson
