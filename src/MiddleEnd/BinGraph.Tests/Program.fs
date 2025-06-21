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

[<BenchmarkCategory("Static Dominance")>]
type StaticDoms () =
  let mutable g = null
  let mutable fileName: string = null

  [<Params(
    "99_150_gcc_base_clang_O0_6a37b0_28.json",
    "232_314_filezilla_gcc_O1_6a0c37_1.json",
    "385_597_touch_clang_Os_4247b0_4.json",
    "581_862_git_gcc_O3_477510_2.json",
    "852_1367_calculix_base_gcc_m32_Of_810bc40_1.json",
    "1075_2225_libxml2_clang_m32_Of_103f10_1.json",
    "1551_2446_pr_clang_O0_408630_2.json",
    "2125_3648_as_clang_m32_O2_8073110_1.json",
    "3301_6355_gcc_base_gcc_O1_54faa0_1.json",
    "4152_6667_find_clang_O0_433cd0_1.json",
    "5486_9806_mysqld_gcc_O0_16c9f72_1.json",
    "7431_10884_date_clang_m32_O0_8070750_2.json",
    "9603_13419_wrf_base_gcc_O0_403364_2.json"
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
  member _.SimpleLengauerTarjanAlgorithm () =
    let dom = SimpleLengauerTarjanDominance.create g
                                                   (CytronDominanceFrontier ())
    let v = g.Vertices[0]
    dom.Dominators v |> ignore

  [<Benchmark>]
  member _.SemiNCAAlgorithm () =
    let dom = SemiNCADominance.create g (CytronDominanceFrontier ())
    let v = g.Vertices[0]
    dom.Dominators v |> ignore

  [<Benchmark>]
  member _.CooperAlgorithm () =
    let dom = CooperDominance.create g (CytronDominanceFrontier ())
    let v = g.Vertices[0]
    dom.Dominators v |> ignore

[<BenchmarkCategory("Dynamic Dominance")>]
type DynamicDoms () =
  let mutable g = null
  let mutable testList = null
  let mutable initialDom = null
  let mutable fileName: string = null
  let mutable rng = null
  let dfp = CytronDominanceFrontier ()

  [<Params(
    "99_150_gcc_base_clang_O0_6a37b0_28.json",
    "232_314_filezilla_gcc_O1_6a0c37_1.json",
    "385_597_touch_clang_Os_4247b0_4.json",
    "581_862_git_gcc_O3_477510_2.json",
    "852_1367_calculix_base_gcc_m32_Of_810bc40_1.json",
    "1075_2225_libxml2_clang_m32_Of_103f10_1.json",
    "1551_2446_pr_clang_O0_408630_2.json",
    "2125_3648_as_clang_m32_O2_8073110_1.json",
    "3301_6355_gcc_base_gcc_O1_54faa0_1.json",
    "4152_6667_find_clang_O0_433cd0_1.json",
    "5486_9806_mysqld_gcc_O0_16c9f72_1.json",
    "7431_10884_date_clang_m32_O0_8070750_2.json",
    "9603_13419_wrf_base_gcc_O0_403364_2.json"
  )>]
  member _.FileName with get() = fileName and set(n) = fileName <- n

  [<GlobalSetup>]
  member __.GlobalSetup () =
    rng <- System.Random 42
    let rec buildTestList acc (g: IDiGraph<_, _>) = function
      | 0 -> acc
      | i ->
        let edges =
          g.Edges
          |> Array.filter (fun e ->
            let succCount = g.GetPredEdges e.Second |> Array.length
            succCount > 1)
        let edge = edges[rng.Next(0, edges.Length)]
        let h = g.RemoveEdge edge
        buildTestList ((h, edge) :: acc) h (i - 1)
    let constructor () = ImperativeDiGraph () :> IDiGraph<_, _>
    let json =
      System.IO.File.ReadAllText ("TestData/Benchmark/Vertex/" + __.FileName)
    g <- Serializer.FromJson (json, constructor, id, id)
    testList <-  buildTestList [] g 10
    let h = testList |> List.head |> fst
    initialDom <- SemiNCADominance.create h dfp

  [<Benchmark(Baseline = true)>]
  member _.DepthBasedSearchAlgorithm () =
    testList
    |> List.fold (fun dom (h, edge) ->
      let dom =
        DepthBasedSearchDominance.insertEdge h dom dfp
                                             DepthBasedSearchDominance.SemiNCA
                                             edge
      let v = h.Vertices[0]
      dom.Dominators v |> ignore
      dom
    ) initialDom |> ignore

  [<Benchmark>]
  member _.SemiNCAAlgorithm () =
    testList
    |> List.iter (fun (h, edge) ->
      let dom = SemiNCADominance.create h dfp
      let v = h.Vertices[0]
      dom.Dominators v |> ignore
    )

[<BenchmarkCategory("Dominance Frontier")>]
type DominanceFrontier () =
  let mutable g = null
  let mutable fileName: string = null

  [<Params(
    "99_150_gcc_base_clang_O0_6a37b0_28.json",
    "232_314_filezilla_gcc_O1_6a0c37_1.json",
    "385_597_touch_clang_Os_4247b0_4.json",
    "581_862_git_gcc_O3_477510_2.json",
    "852_1367_calculix_base_gcc_m32_Of_810bc40_1.json",
    "1075_2225_libxml2_clang_m32_Of_103f10_1.json",
    "1551_2446_pr_clang_O0_408630_2.json",
    "2125_3648_as_clang_m32_O2_8073110_1.json",
    "3301_6355_gcc_base_gcc_O1_54faa0_1.json",
    "4152_6667_find_clang_O0_433cd0_1.json",
    "5486_9806_mysqld_gcc_O0_16c9f72_1.json",
    "7431_10884_date_clang_m32_O0_8070750_2.json",
    "9603_13419_wrf_base_gcc_O0_403364_2.json"
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
    [| typeof<StaticDoms>
       typeof<DynamicDoms>
       typeof<DominanceFrontier> |],
    cfg
  ) |> ignore
  0
