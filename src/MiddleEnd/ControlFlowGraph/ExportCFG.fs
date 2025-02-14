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

namespace B2R2.MiddleEnd.ControlFlowGraph

open B2R2.MiddleEnd.BinGraph
open System.IO
open System.Text
open System.Collections.Generic
open System.Runtime.Serialization
open System.Runtime.Serialization.Json

[<RequireQualifiedAccess>]
module ExportCFG =
  [<DataContract>]
  type private EdgeData = {
    [<field: DataMember(Name = "from")>]
    From: string
    [<field: DataMember(Name = "to")>]
    To: string
    [<field: DataMember(Name = "type")>]
    Type: string
  }

  [<DataContract>]
  type private CFGData = {
    [<field: DataMember(Name = "nodes")>]
    Nodes: string[]
    [<field: DataMember(Name = "edges")>]
    Edges: EdgeData[]
  }

  let private translateNodes (cfg: IReadOnlyGraph<_, _>) =
    let lst = List ()
    cfg.IterVertex (fun (v: IVertex<#IVisualizable>) ->
      lst.Add $"{v.VData.BlockAddress:x}")
    lst.ToArray ()

  let private translateEdges (cfg: IReadOnlyGraph<_, _>) =
    let lst = List ()
    cfg.IterEdge (fun (e: Edge<#IVisualizable, _>) ->
      let src, dst = e.First, e.Second
      lst.Add { From = $"{src.VData.BlockAddress:x}"
                To = $"{dst.VData.BlockAddress:x}"
                Type = e.ToString () })
    lst.ToArray ()

  /// Export the control flow graph to a JSON format.
  [<CompiledName "ToJson">]
  let toJson (cfg: IReadOnlyGraph<_, _>) jsonPath =
    let enc = Encoding.UTF8
    use fs = File.Create (jsonPath)
    use writer = JsonReaderWriterFactory.CreateJsonWriter (fs, enc, true, true)
    let nodes = translateNodes cfg
    let edges = translateEdges cfg
    let data = { Nodes = nodes; Edges = edges }
    let ser = DataContractJsonSerializer (typedefof<CFGData>)
    ser.WriteObject (writer, data)
    writer.Flush ()
