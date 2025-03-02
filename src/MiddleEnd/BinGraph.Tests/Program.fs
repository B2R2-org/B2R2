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

module B2R2.MiddleEnd.BinGraph.Tests.Program

open BenchmarkDotNet.Attributes
open BenchmarkDotNet.Running
open BenchmarkDotNet.Jobs
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.BinGraph.Dominance

[<SimpleJob(RuntimeMoniker.Net90)>]
type Benchmarks () =
  let mutable g = null
  let mutable fileName: string = null

  [<Params(
    "99_objdump_clang_m32_O1_80b18d0.json",
    "499_gcc_base.amd64-m32-ccr-Ofast_clang_m32_Of_81428e0.json",
    "4152_find_clang_O0_433cd0.json"
  )>]
  member _.FileName with get() = fileName and set(n) = fileName <- n

  [<GlobalSetup>]
  member __.GlobalSetup () =
    let constructor () = ImperativeDiGraph () :> IDiGraph<_, _>
    let json = System.IO.File.ReadAllText ("TestData/" + __.FileName)
    let hexStrToInt (s: string) = System.Convert.ToInt32 (s, 16)
    g <- Serializer.FromJson (json, constructor, hexStrToInt, int)

  [<Benchmark>]
  member _.IterativeAlgorithm () =
    let dom = IterativeDominance.create g (CytronDominanceFrontier ())
    let v = g.Vertices[0]
    dom.Dominators v |> ignore

  [<Benchmark>]
  member _.LengauerTarjanAlgorithm () =
    let dom = LengauerTarjanDominance.create g (CytronDominanceFrontier ())
    let v = g.Vertices[0]
    dom.Dominators v |> ignore

  [<Benchmark>]
  member _.CooperAlgorithm () =
    let dom = CooperDominance.create g (CytronDominanceFrontier ())
    let v = g.Vertices[0]
    dom.Dominators v |> ignore

[<EntryPoint>]
let main _args =
  BenchmarkRunner.Run<Benchmarks> () |> ignore
  0
