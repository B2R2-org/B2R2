(*
  Scores B2R2's jump table recovery against the JumpTableBench ground truth.
  x86 and x64 for now.

    dotnet fsi .github/jumptable-test.fsx <binaryDir> <groundTruthDir>
    dotnet fsi .github/jumptable-test.fsx <binary> <groundTruth.json>

  Given two directories, every <groundTruthDir>/<case>.json is compared
  against <binaryDir>/<case>; given two files, the one binary is compared
  against the one ground truth. Exits non-zero when any table or target is
  missed or invented, so it can gate a build as it stands.
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

/// Recovers CFGs and reports every jump table B2R2 found, once for each
/// indirect branch that jumps through it: the one that recovered the table and
/// the ones waiting on it, since the ground truth lists them all. CFG recovery
/// writes progress to the console, which would bury the report, so it is muted
/// for the duration.
let private recover (hdl: BinHandle) =
  let saved = Console.Out
  Console.SetOut TextWriter.Null
  try
    let brew = BinaryBrew hdl
    (* An external function reports no table, which is what keeps the body
       below off its absent CFG. *)
    [ for fn in brew.Functions.Sequence do
        for jmptbl in fn.JumpTables do
          for insAddr in jmptbl.InsAddr :: jmptbl.WaitingInstructions do
            { InsAddr = insAddr
              Kind = kindOf jmptbl
              Targets = targetsOf fn.CFG insAddr } ]
  finally
    Console.SetOut saved

/// Tells whether the targets of a table are scored. Function pointer tables
/// become tail calls rather than intraprocedural edges, so theirs are not.
let private isScored (table: Table) = table.Kind <> "functionPointerTable"

/// Compares the targets of two tables that matched on their branch address,
/// counting a table whose targets are not scored as skipped.
let private scoreTargets (score: Score) (expected: Table) (actual: Table) =
  if not (isScored expected) then
    { score with Skipped = score.Skipped + 1 }
  else
    let tp = Set.intersect expected.Targets actual.Targets |> Set.count
    { score with
        TargetTP = score.TargetTP + tp
        TargetFP = score.TargetFP + (Set.count actual.Targets - tp)
        TargetFN = score.TargetFN + (Set.count expected.Targets - tp) }

let private byAddr tables =
  tables |> List.map (fun t -> t.InsAddr, t) |> Map.ofList

let private scoreCase case expected actual =
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

/// Counts the tables and targets a score missed or invented.
let private errorsOf (score: Score) =
  score.TableFP + score.TableFN + score.TargetFP + score.TargetFN

let private report (score: Score) =
  let verdict = if errorsOf score = 0 then "ok" else "FAIL"
  printfn "%-4s %-34s tables %d/%d/%d  targets %d/%d/%d  skipped %d"
    verdict score.Case score.TableTP score.TableFP score.TableFN
    score.TargetTP score.TargetFP score.TargetFN score.Skipped

let private hexes (addrs: Set<Addr>) =
  addrs |> Seq.map (sprintf "0x%x") |> String.concat " "

let private listAddrs label addrs =
  if Set.isEmpty addrs then [] else [ label + " " + hexes addrs ]

/// Says which targets of a matched table B2R2 missed and which it invented.
let private diffTargets (expected: Table) (actual: Table) =
  listAddrs "missing" (expected.Targets - actual.Targets)
  @ listAddrs "extra" (actual.Targets - expected.Targets)
  |> String.concat "; "

/// Says what B2R2 got wrong at one branch address, if anything.
let private diagnose expected actual addr =
  match Map.tryFind addr expected, Map.tryFind addr actual with
  | Some(e: Table), None ->
    Some $"missed table ({e.Kind}, {e.Targets.Count} targets)"
  | None, Some(a: Table) ->
    Some $"invented table ({a.Kind}, {a.Targets.Count} targets)"
  | Some e, Some a when isScored e && e.Targets <> a.Targets ->
    Some(diffTargets e a)
  | _ ->
    None

/// Prints a line for every branch B2R2 got wrong, with its instruction, so a
/// failing case can be chased down from its addresses. A case that passed
/// prints nothing here.
let private explain (hdl: BinHandle) expected actual =
  let expected, actual = byAddr expected, byAddr actual
  let keys m = Map.keys m |> Set.ofSeq
  let lu = hdl.NewLiftingUnit()
  for addr in Set.union (keys expected) (keys actual) do
    diagnose expected actual addr
    |> Option.iter (fun problem ->
      let ins = lu.ParseInstruction(addr: Addr).Disasm()
      printfn "  0x%x %s: %s" addr ins problem)

/// Scores one binary against one ground truth file and reports the result.
let private scoreFile case binPath jsonPath =
  let arch, expected = readTruth jsonPath
  match load case binPath arch with
  | None ->
    None
  | Some hdl ->
    let actual = recover hdl
    let score = scoreCase case expected actual
    report score
    explain hdl expected actual
    Some score

let private runCase binDir jsonPath =
  let case = Path.GetFileNameWithoutExtension(jsonPath: string)
  let binPath = Path.Combine(binDir, case)
  if not (File.Exists binPath) then
    eprintfn "no binary for %s at %s" case binPath
    None
  else
    scoreFile case binPath jsonPath

let private summarize scores =
  let sum f = scores |> List.sumBy f
  let tTP, tFP, tFN = sum (_.TableTP), sum (_.TableFP), sum (_.TableFN)
  let gTP, gFP, gFN = sum (_.TargetTP), sum (_.TargetFP), sum (_.TargetFN)
  printfn ""
  printfn "%d cases scored" (List.length scores)
  printfn "tables   tp %d  fp %d  fn %d  f1 %.4f" tTP tFP tFN (f1 tTP tFP tFN)
  printfn "targets  tp %d  fp %d  fn %d  f1 %.4f" gTP gFP gFN (f1 gTP gFP gFN)
  tFP + tFN + gFP + gFN

/// Scores every case the ground truth directory holds and prints the totals.
let private runDirs binDir jsonDir =
  let files = Directory.GetFiles(jsonDir, "*.json") |> Array.sort
  if Array.isEmpty files then
    eprintfn "no ground truth in %s" jsonDir
    2
  else
    let scores = files |> Array.toList |> List.choose (runCase binDir)
    if List.isEmpty scores then 2
    elif summarize scores = 0 then 0
    else 1

/// Scores a single binary, naming the case after it. The one line report
/// already says everything a summary would.
let private runFiles binPath jsonPath =
  match scoreFile (Path.GetFileName(binPath: string)) binPath jsonPath with
  | None -> 2
  | Some score -> if errorsOf score = 0 then 0 else 1

/// Explains why two paths are neither two directories nor two files.
let private complain paths =
  let exists p = File.Exists p || Directory.Exists p
  match List.filter (exists >> not) paths with
  | [] ->
    eprintfn "expected two directories or two files, not one of each"
  | missing ->
    eprintfn "no such file or directory: %s" (String.concat ", " missing)

let private main (argv: string[]) =
  match argv with
  | [| bin; json |] when Directory.Exists bin && Directory.Exists json ->
    runDirs bin json
  | [| bin; json |] when File.Exists bin && File.Exists json ->
    runFiles bin json
  | [| bin; json |] ->
    complain [ bin; json ]
    2
  | _ ->
    (* Straight to stderr: B2R2's eprintfn would label usage an error. *)
    stderr.WriteLine("usage: jumptable-test.fsx <binaryDir> <groundTruthDir>")
    stderr.WriteLine("       jumptable-test.fsx <binary> <groundTruth.json>")
    2

exit (main (Array.skip 1 fsi.CommandLineArgs))
