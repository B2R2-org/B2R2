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
open BenchmarkDotNet.Columns
open BenchmarkDotNet.Configs
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.BinGraph.Dominance

[<BenchmarkCategory("Dominance")>]
type Doms () =
  let mutable g = null
  let mutable fileName: string = null

  [<Params(
    "99_183_dwp_clang_m32_O3_8204810_17.json",
    "499_703_git_clang_m32_Os_80ada73_1.json",
    "866_1462_libtiff.so.5.4.0_clang_O2_10170_1.json",
    "1180_1852_calculix_base.amd64-m32-ccr-Ofast_clang_m32_Of_81a1400_1.json",
    "2125_3648_as_clang_m32_O2_8073110_1.json",
    "3450_5467_touch_clang_O0_403510_4.json",
    "4152_6667_find_clang_O0_433cd0_1.json"
  )>]
  member _.FileName with get() = fileName and set(n) = fileName <- n

  [<GlobalSetup>]
  member this.GlobalSetup () =
    let constructor () = ImperativeDiGraph () :> IDiGraph<_, _>
    let json =
      System.IO.File.ReadAllText ("TestData/Benchmark/Vertex/" + this.FileName)
    g <- Serializer.FromJson (json, constructor, id, id)

  [<Benchmark(Baseline = true)>]
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

[<BenchmarkCategory("Dominance Frontier")>]
type DominanceFrontier () =
  let mutable g = null
  let mutable fileName: string = null

  [<Params(
    "99_183_dwp_clang_m32_O3_8204810_17.json",
    "499_703_git_clang_m32_Os_80ada73_1.json",
    "866_1462_libtiff.so.5.4.0_clang_O2_10170_1.json",
    "1180_1852_calculix_base.amd64-m32-ccr-Ofast_clang_m32_Of_81a1400_1.json",
    "2125_3648_as_clang_m32_O2_8073110_1.json",
    "3450_5467_touch_clang_O0_403510_4.json",
    "4152_6667_find_clang_O0_433cd0_1.json"
  )>]
  member _.FileName with get() = fileName and set(n) = fileName <- n

  [<GlobalSetup>]
  member this.GlobalSetup () =
    let constructor () = ImperativeDiGraph () :> IDiGraph<_, _>
    let json =
      System.IO.File.ReadAllText ("TestData/Benchmark/Vertex/" + this.FileName)
    g <- Serializer.FromJson (json, constructor, id, id)

  [<Benchmark(Baseline = true)>]
  member _.CytronDF () =
    let dom = CooperDominance.create g (CytronDominanceFrontier ())
    let v = g.Vertices[0]
    dom.DominanceFrontier v |> ignore

  [<Benchmark>]
  member _.CooperDF () =
    let dom = CooperDominance.create g (CooperDominanceFrontier ())
    let v = g.Vertices[0]
    dom.DominanceFrontier v |> ignore

[<EntryPoint>]
let main _args =
  let cfg = ManualConfig.Create DefaultConfig.Instance
  let cfg = cfg.WithOption (ConfigOptions.JoinSummary, true)
  let cfg = cfg.WithOption (ConfigOptions.DisableLogFile, true)
  let cfg = cfg.AddColumn (CategoriesColumn.Default)
  let cfg = cfg.HideColumns ([| "Type"; "Error" |])
  let cfg = cfg.AddLogicalGroupRules (BenchmarkLogicalGroupRule.ByCategory)
  BenchmarkRunner.Run (
    [| typeof<Doms>
       typeof<DominanceFrontier> |],
    cfg
  ) |> ignore
  0
