(*
  Scores B2R2's jump table recovery against the JumpTableBench ground truth.
  x86 and x64 for now.

    dotnet fsi .github/jumptable-test.fsx <binaryDir> <groundTruthDir>

  Every <groundTruthDir>/<case>.json is compared against <binaryDir>/<case>.
  Exits non-zero when any table or target is missed or invented, so it can
  gate a build as it stands.
*)

(* Release, because scoring a hundred binaries is CPU bound; run
   `dotnet build -c Release` first. One build output only: listing several
   puts two copies of the same assembly on the probing path, and a script
   that loads half of each dies with a linkage error that reads like a
   source bug. *)
#I "../src/MiddleEnd/API/bin/Release/net10.0"
#r "B2R2.Core.dll"
#r "B2R2.FrontEnd.BinLifter.dll"
#r "B2R2.FrontEnd.BinFile.dll"
#r "B2R2.FrontEnd.API.dll"
#r "B2R2.MiddleEnd.BinGraph.dll"
#r "B2R2.MiddleEnd.ControlFlowGraph.dll"
#r "B2R2.MiddleEnd.ControlFlowAnalysis.dll"
#r "B2R2.MiddleEnd.API.dll"

open System
open System.IO
open System.Text.Json
open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

/// Represents one jump table, either as the ground truth records it or as
/// B2R2 recovered it. Targets are a set because a table may send several
/// entries to the same block.
type Table =
  { InsAddr: Addr
    Kind: string
    Targets: Set<Addr> }

/// Represents how one binary scored. Detection counts tables matched by
/// their indirect branch address; target counts compare the target sets of
/// the tables that matched.
type Score =
  { Case: string
    TableTP: int
    TableFP: int
    TableFN: int
    TargetTP: int
    TargetFP: int
    TargetFN: int
    Skipped: int }

let private zero case =
  { Case = case
    TableTP = 0
    TableFP = 0
    TableFN = 0
    TargetTP = 0
    TargetFP = 0
    TargetFN = 0
    Skipped = 0 }

let private parseAddr (s: string) =
  if s.StartsWith "0x" then Convert.ToUInt64(s.Substring 2, 16)
  else failwithf "address must be written as 0x...: %s" s

let private readTable (e: JsonElement) =
  { InsAddr = parseAddr (e.GetProperty("insAddr").GetString())
    Kind = e.GetProperty("kind").GetString()
    Targets =
      e.GetProperty("targets").EnumerateArray()
      |> Seq.map (fun t -> parseAddr (t.GetString()))
      |> Set.ofSeq }

/// Reads the architecture and the tables out of one ground truth file.
let private readTruth path =
  use doc = JsonDocument.Parse(File.ReadAllText path: string)
  let root = doc.RootElement
  let arch = root.GetProperty("arch").GetString()
  let tables =
    root.GetProperty("jumpTables").EnumerateArray()
    |> Seq.map readTable
    |> Seq.toList
  arch, tables

/// Collects the targets B2R2 attached to the indirect branch at insAddr, which
/// are the successors it reached through the jump table.
let private targetsOf (cfg: LowUIRCFG) insAddr =
  cfg.Vertices
  |> Array.filter (fun v ->
    not v.VData.Internals.IsAbstract
    && v.VData.Internals.LastInstruction.Address = insAddr)
  |> Array.collect cfg.GetSuccEdges
  |> Array.filter (fun e -> e.Label = IndirectJmpEdge)
  |> Array.map (fun e -> e.Second.VData.Internals.BlockAddress)
  |> Set.ofArray

let private kindOf (jmptbl: ControlFlowAnalysis.JmpTableInfo) =
  if jmptbl.IsFunctionPointerTable then "functionPointerTable"
  elif jmptbl.IsSingleEntry then "singleEntry"
  else "switch"

/// Maps a ground truth architecture name onto the ISA the binary has to
/// report. Only the two Intel widths are scored so far.
let private isaOf arch =
  match arch with
  | "x86" -> Some(Architecture.Intel, WordSize.Bit32)
  | "x64" -> Some(Architecture.Intel, WordSize.Bit64)
  | _ -> None

/// Loads the binary a case names, unless the ground truth names an
/// architecture this script does not score, or one the binary disagrees with.
let private load case binPath arch =
  match isaOf arch with
  | None ->
    eprintfn "skipping %s: %s is not scored yet" case arch
    None
  | Some(expected, wordSize) ->
    let hdl = BinHandle.LoadFile(binPath: string)
    if hdl.ISA.Arch = expected && hdl.ISA.WordSize = wordSize then
      Some hdl
    else
      eprintfn "skipping %s: ground truth says %s, binary is %A" case arch
        hdl.ISA
      None

/// Recovers CFGs and reports every jump table B2R2 found. CFG recovery writes
/// progress to the console, which would bury the report, so it is muted for
/// the duration.
let private recover (hdl: BinHandle) =
  let saved = Console.Out
  Console.SetOut TextWriter.Null
  try
    let brew = BinaryBrew hdl
    (* An external function reports no table, which is what keeps the body
       below off its absent CFG. *)
    [ for fn in brew.Functions.Sequence do
        for jmptbl in fn.JumpTables do
          { InsAddr = jmptbl.InsAddr
            Kind = kindOf jmptbl
            Targets = targetsOf fn.CFG jmptbl.InsAddr } ]
  finally
    Console.SetOut saved

/// Compares the targets of two tables that matched on their branch address.
/// Function pointer tables become tail calls rather than intraprocedural
/// edges, so their targets are counted as skipped instead of scored.
let private scoreTargets (score: Score) (expected: Table) (actual: Table) =
  if expected.Kind = "functionPointerTable" then
    { score with Skipped = score.Skipped + 1 }
  else
    let tp = Set.intersect expected.Targets actual.Targets |> Set.count
    { score with
        TargetTP = score.TargetTP + tp
        TargetFP = score.TargetFP + (Set.count actual.Targets - tp)
        TargetFN = score.TargetFN + (Set.count expected.Targets - tp) }

let private scoreCase case expected actual =
  let byAddr = List.map (fun t -> t.InsAddr, t) >> Map.ofList
  let expected, actual = byAddr expected, byAddr actual
  let matched = Map.keys expected |> Seq.filter actual.ContainsKey |> List.ofSeq
  let score =
    { zero case with
        TableTP = List.length matched
        TableFP = actual.Count - List.length matched
        TableFN = expected.Count - List.length matched }
  matched
  |> List.fold (fun s addr -> scoreTargets s expected[addr] actual[addr]) score

let private f1 tp fp fn =
  if tp = 0 then 0.0 else 2.0 * float tp / float (2 * tp + fp + fn)

let private report (score: Score) =
  let verdict =
    if score.TableFP + score.TableFN + score.TargetFP + score.TargetFN = 0 then
      "ok"
    else "FAIL"
  printfn "%-4s %-34s tables %d/%d/%d  targets %d/%d/%d  skipped %d"
    verdict score.Case score.TableTP score.TableFP score.TableFN
    score.TargetTP score.TargetFP score.TargetFN score.Skipped

let private runCase binDir jsonPath =
  let case = Path.GetFileNameWithoutExtension(jsonPath: string)
  let binPath = Path.Combine(binDir, case)
  if not (File.Exists binPath) then
    eprintfn "no binary for %s at %s" case binPath
    None
  else
    let arch, expected = readTruth jsonPath
    match load case binPath arch with
    | None ->
      None
    | Some hdl ->
      let score = scoreCase case expected (recover hdl)
      report score
      Some score

let private summarize scores =
  let sum f = scores |> List.sumBy f
  let tTP, tFP, tFN = sum (_.TableTP), sum (_.TableFP), sum (_.TableFN)
  let gTP, gFP, gFN = sum (_.TargetTP), sum (_.TargetFP), sum (_.TargetFN)
  printfn ""
  printfn "%d cases scored" (List.length scores)
  printfn "tables   tp %d  fp %d  fn %d  f1 %.4f" tTP tFP tFN (f1 tTP tFP tFN)
  printfn "targets  tp %d  fp %d  fn %d  f1 %.4f" gTP gFP gFN (f1 gTP gFP gFN)
  tFP + tFN + gFP + gFN

let private main (argv: string[]) =
  if argv.Length <> 2 then
    eprintfn "usage: jumptable-test.fsx <binaryDir> <groundTruthDir>"
    2
  else
    let binDir, jsonDir = argv[0], argv[1]
    let missing = [ binDir; jsonDir ] |> List.filter (Directory.Exists >> not)
    if not (List.isEmpty missing) then
      eprintfn "no such directory: %s" (String.concat ", " missing)
      2
    else
    let files = Directory.GetFiles(jsonDir, "*.json") |> Array.sort
    if Array.isEmpty files then
      eprintfn "no ground truth in %s" jsonDir
      2
    else
      let scores = files |> Array.toList |> List.choose (runCase binDir)
      if List.isEmpty scores then 2
      elif summarize scores = 0 then 0
      else 1

exit (main (Array.skip 1 fsi.CommandLineArgs))
