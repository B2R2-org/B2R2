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

namespace B2R2.RearEnd.Transformer

open System
open System.Diagnostics
open System.Globalization
open System.IO
open System.Numerics
open System.Text
open System.Threading
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

module internal ReplRendering =
  type private SymbAnswer = B2R2.MiddleEnd.SymbEval.SymbAnswer

  type private RenderMode =
    | Preview
    | Full

  type PrintedValue =
    { Values: ReplValue list }

  let formatKind kind = ReplValueKind.toString kind

  let normalizePath (path: string) =
    path.Replace('\\', '/')

  let [<Literal>] HexViewBytesPerRow = 8

  let private splitTextForDisplay (text: string) =
    seq {
      let normalized = text.Replace("\r\n", "\n")
      use reader = new StringReader(normalized)
      let mutable reading = true
      while reading do
        match reader.ReadLine() with
        | null ->
          reading <- false
        | line ->
          yield line
    }

  let private displayField name value =
    $"  {name}: {value}"

  let private indentDisplay count lines =
    let indent = String.replicate count " "
    lines |> List.map (fun line -> indent + line)

  let private displaySection name lines =
    match lines with
    | [] ->
      [ displayField name "none" ]
    | lines ->
      $"  {name}:" :: indentDisplay 4 lines

  let private normalizeDisplayLine (line: string) =
    if line.IndexOf '\r' < 0 && line.IndexOf '\n' < 0 then
      Seq.singleton line
    else
      splitTextForDisplay line

  let typeDescription value =
    formatKind (value: ReplValue).Kind

  let private tryVertexRange (vertex: IVertex<LowUIRBasicBlock>) =
    try
      let internals = vertex.VData.Internals
      if internals.IsAbstract then
        None
      else
        let range = internals.Range
        Some(range.Min, range.Max + 1UL)
    with _ ->
      None

  let private foldRange ranges =
    ranges
    |> Array.fold (fun acc (start, finish) ->
      match acc with
      | None ->
        Some(start, finish)
      | Some(minimum, maximum) ->
        Some(min minimum start, max maximum finish)) None

  let private cfgRange entry (cfg: LowUIRCFG) =
    let ranges = cfg.Vertices |> Array.choose tryVertexRange
    let entryRanges =
      ranges |> Array.filter (fun (start, _) -> start >= entry)
    if Array.isEmpty entryRanges then
      foldRange ranges
    else
      foldRange entryRanges

  let private renderCFG mode index = function
    | CFG(entry, cfg, _) ->
      let label =
        match index with
        | Some index ->
          $"CFG #{index}"
        | None ->
          "CFG"
      match mode with
      | Preview ->
        [ $"{label} 0x{entry:x}: {cfg.Vertices.Length} nodes, "
          + $"{cfg.Edges.Length} edges" ]
      | Full ->
        let range =
          cfgRange entry cfg
          |> Option.map (fun (start, finish) ->
            $"0x{start:x}-0x{finish:x} (end exclusive)")
          |> Option.defaultValue "unknown"
        [ label
          $"  entry: 0x{entry:x}"
          $"  range: {range}"
          $"  vertices: {cfg.Vertices.Length}"
          $"  edges: {cfg.Edges.Length}"
          $"  roots: {cfg.Roots.Length}"
          $"  exits: {cfg.Exits.Length}" ]
    | NoCFG error ->
      let label =
        match index with
        | Some index ->
          $"CFG #{index}"
        | None ->
          "CFG"
      [ $"{label}"
        $"  error: {error}" ]

  let private binaryPath binary =
    let hdl = Binary.Handle binary
    if String.IsNullOrWhiteSpace hdl.File.Path then
      "<memory>"
    else
      normalizePath hdl.File.Path

  let private binaryDisplayFields binary =
    let hdl = Binary.Handle binary
    let bytes = hdl.File.RawBytes
    let annotation = Binary.Annotation binary
    [ displayField "path" (binaryPath binary)
      displayField "format" (FileFormat.toString hdl.File.Format)
      displayField "isa" (string hdl.ISA)
      displayField "os" (string hdl.OS)
      displayField "base" $"0x{hdl.File.BaseAddress:x}"
      displayField "size" $"{bytes.Length} bytes" ]
    @ if String.IsNullOrWhiteSpace annotation then
        []
      else
        [ displayField "annotation" annotation ]

  let private renderBinary mode binary =
    match mode with
    | Preview -> [ $"Binary: {binaryPath binary}" ]
    | Full -> "Binary" :: binaryDisplayFields binary

  let private renderInstructionArray mode (values: Instruction[]) =
    seq {
      yield $"{values.Length} instructions"
      for value in values do
        match mode with
        | Preview ->
          match value with
          | ValidInstruction(ins, _) ->
            yield $"  0x{ins.Address:x}: {ins.Disasm()}"
          | BadInstruction(addr, _) ->
            yield $"  0x{addr:x}: <undecodable>"
        | Full ->
          yield "  " + value.ToString()
    }

  let private renderByteRows (values: byte[]) =
    seq {
      if values.Length = 0 then
        yield "  <empty>"
      else
        for offset in 0 .. HexViewBytesPerRow .. values.Length - 1 do
          let count = min HexViewBytesPerRow (values.Length - offset)
          let hex =
            [ for index in offset .. offset + count - 1 ->
                values[index].ToString("x2") ]
            |> String.concat " "
          yield "  " + hex
    }

  let private renderHexRow baseAddress (values: byte[]) addressFormat offset =
    let count = min HexViewBytesPerRow (values.Length - offset)
    let address = baseAddress + uint64 offset
    let addressFormat: string = addressFormat
    let builder = StringBuilder($"  {address.ToString(addressFormat)}: ")
    for index in 0 .. HexViewBytesPerRow - 1 do
      let hex =
        if index < count then
          values[offset + index].ToString("x2")
        else
          "  "
      builder.Append(hex) |> ignore
      if index < HexViewBytesPerRow - 1 then
        builder.Append(' ') |> ignore
      else
        ()
    builder.Append("  |") |> ignore
    for index in 0 .. count - 1 do
      let value = values[offset + index]
      let character =
        if value >= 0x20uy && value <= 0x7euy then char value else '.'
      builder.Append(character) |> ignore
    builder.Append('|') |> ignore
    builder.ToString()

  let private renderHexRows baseAddress (values: byte[]) =
    seq {
      if values.Length = 0 then
        yield "  <empty>"
      else
        let lastOffset =
          (values.Length - 1) / HexViewBytesPerRow * HexViewBytesPerRow
        let lastAddress = baseAddress + uint64 lastOffset
        let width =
          max 8 ((max baseAddress lastAddress).ToString("x").Length)
        let addressFormat = "x" + string width
        for offset in 0 .. HexViewBytesPerRow .. values.Length - 1 do
          yield renderHexRow baseAddress values addressFormat offset
    }

  let private renderBinaryBytes mode bytes =
    let bytes: BinaryBytes = bytes
    let size = bytes.Bytes.Length
    let unit = if size = 1 then "byte" else "bytes"
    let header = $"ByteArray ({size} {unit})"
    seq {
      yield header
      match mode with
      | Preview ->
        yield! renderByteRows bytes.Bytes
      | Full ->
        yield displayField "base" $"0x{bytes.BaseAddress:x}"
        yield displayField "isa" (string bytes.ISA)
        yield displayField "os" (string bytes.OS)
        if not (String.IsNullOrWhiteSpace bytes.Annotation) then
          yield displayField "annotation" bytes.Annotation
        else
          ()
        yield ""
        yield! renderHexRows bytes.BaseAddress bytes.Bytes
    }

  let private renderFingerprint mode fingerprint =
    let fingerprint: Fingerprint = fingerprint
    seq {
      yield "Fingerprint"
      yield displayField "count" $"{List.length fingerprint.Patterns} patterns"
      if mode = Full then
        yield displayField "n-gram" (string fingerprint.NGramSize)
        yield displayField "window" (string fingerprint.WindowSize)
        if not (String.IsNullOrWhiteSpace fingerprint.Annotation) then
          yield displayField "annotation" fingerprint.Annotation
        else
          ()
      else
        ()
      if List.isEmpty fingerprint.Patterns then
        yield displayField "patterns" "none"
      else
        yield "  patterns:"
        for hash, position in fingerprint.Patterns do
          yield $"    {hash:x2}@{position}"
    }

  let private renderClusterResult result =
    let result: ClusterResult = result
    seq {
      yield "ClusterResult"
      yield displayField "count" $"{result.Clusters.Length} clusters"
      if result.Clusters.Length = 0 then
        yield displayField "clusters" "none"
      else
        yield "  clusters:"
        for index in 0 .. result.Clusters.Length - 1 do
          let cluster = result.Clusters[index]
          yield $"    #{index} ({cluster.Length} values):"
          for item in cluster do
            yield "      " + item
    }

  let private formatRange startAddress endAddress =
    $"0x{startAddress:x}-0x{endAddress:x} (end exclusive)"

  let private trySectionByAddress (slice: BinarySlice) =
    let hdl = Binary.Handle slice.Source
    match BinFileOps.tryFindSectionByAddr hdl.File slice.StartAddress with
    | Ok section ->
      Some section
    | _ ->
      None

  let private tryFileRange (slice: BinarySlice) =
    trySectionByAddress slice
    |> Option.bind (fun section ->
      section.Offset
      |> Option.map (fun offset ->
        let fileStart = offset + slice.StartAddress - section.Address
        fileStart, fileStart + slice.Size, section.Name))

  let private renderSlice mode slice =
    let slice: BinarySlice = slice
    match mode with
    | Preview ->
      [ $"BinarySlice: 0x{slice.StartAddress:x}-0x{slice.EndAddress:x} "
        + $"({slice.Size} bytes)" ]
    | Full ->
      let label = slice.Label |> Option.defaultValue "<none>"
      let fileRange =
        match tryFileRange slice with
        | Some(fileStart, fileEnd, section) ->
          [ $"  file: {formatRange fileStart fileEnd}"
            $"  section: {section}" ]
        | None ->
          []
      [ "BinarySlice"
        displayField "label" label
        displayField "source" (binaryPath slice.Source)
        displayField "virtual"
          (formatRange slice.StartAddress slice.EndAddress) ]
      @ fileRange
      @ [ $"  size: {slice.Size} bytes" ]

  let private renderSection mode section =
    let section: SectionInfo = section
    match mode with
    | Preview ->
      [ $"{section.Name}: 0x{section.Address:x} "
        + $"({section.Size} bytes)" ]
    | Full ->
      [ "SectionInfo"
        displayField "name" section.Name
        displayField "source" (binaryPath section.Source)
        displayField "address" $"0x{section.Address:x}"
        displayField "size" $"{section.Size} bytes"
        displayField "file-size" $"{section.FileSize} bytes"
        displayField "kind" section.Kind ]

  let private renderFunction mode fn =
    let fn: FunctionInfo = fn
    let symbol = fn.Symbol |> Option.defaultValue "<none>"
    match mode with
    | Preview ->
      match fn.Symbol with
      | Some symbol -> [ $"0x{fn.Entry:x}: {symbol}" ]
      | None -> [ $"0x{fn.Entry:x}" ]
    | Full ->
      [ "FunctionInfo"
        displayField "source" (binaryPath fn.Source)
        displayField "entry" $"0x{fn.Entry:x}"
        displayField "symbol" symbol ]

  let private renderStringMatch mode stringMatch =
    let stringMatch: StringMatch = stringMatch
    match mode with
    | Preview ->
      [ $"0x{stringMatch.Address:x}: {stringMatch.Text}" ]
    | Full ->
      [ "StringMatch"
        displayField "source" (binaryPath stringMatch.Source)
        displayField "address" $"0x{stringMatch.Address:x}"
        displayField "text" stringMatch.Text ]

  let private renderRegisterView mode view =
    let view: RegisterView = view
    let lines =
      view.Registers
      |> Array.map (fun reg -> $"{reg.Name}: {reg.Value}")
      |> Array.toList
    match mode with
    | Preview ->
      $"PC=0x{view.PC:x}" :: lines
    | Full ->
      [ "RegisterView"; displayField "pc" $"0x{view.PC:x}" ]
      @ displaySection "registers" lines

  let private renderMemoryView mode view =
    let view: MemoryView = view
    seq {
      if mode = Full then
        yield "MemoryView"
        yield displayField "address" $"0x{view.Address:x}"
        yield displayField "size" $"{view.Bytes.Length} bytes"
      else
        yield $"0x{view.Address:x}:"
      match mode with
      | Preview ->
        yield! renderByteRows view.Bytes
      | Full ->
        yield ""
        yield! renderHexRows view.Address view.Bytes
    }

  let private renderMemoryBytes mode label addr bytes =
    seq {
      yield $"  {label}:"
      match bytes with
      | Some bytes ->
        let lines =
          match mode with
          | Preview -> renderByteRows bytes
          | Full -> renderHexRows addr bytes
        for line in lines do
          yield "  " + line
      | None ->
        yield "    <unreadable>"
    }

  let private renderMemoryDiff mode diff =
    let diff: MemoryDiff = diff
    seq {
      match diff.Before, diff.After with
      | Some before, Some after when before = after ->
        yield! renderMemoryBytes mode "unchanged" diff.Address (Some after)
      | before, after ->
        yield! renderMemoryBytes mode "before" diff.Address before
        yield! renderMemoryBytes mode "after" diff.Address after
    }

  let private renderMemoryAccess mode access =
    let access: MemoryAccess = access
    let head =
      match access.Kind with
      | MemoryAccessKind.Read ->
        $"read  at 0x{access.Instruction:x}"
      | MemoryAccessKind.Write ->
        $"write at 0x{access.Instruction:x}"
    let head =
      head + $" addr=0x{access.Address:x} size={access.Size}"
    let violation =
      match access.Violation with
      | Some message ->
        [ $"  violation: {message}" ]
      | None ->
        []
    seq {
      yield head
      match access.Kind with
      | MemoryAccessKind.Read ->
        yield! renderMemoryBytes mode "value" access.Address access.After
      | MemoryAccessKind.Write ->
        yield! renderMemoryBytes mode "before" access.Address access.Before
        yield! renderMemoryBytes mode "after" access.Address access.After
      yield! violation
    }

  let private renderTrace mode trace =
    let trace: ExecutionTrace = trace
    seq {
      yield $"ExecutionTrace: {trace.InstructionCount} instructions, "
            + $"PC=0x{trace.FinalPC:x}"
      if mode = Full then
        yield displayField "attempted" (string trace.Instructions.Length)
        yield displayField "start" $"0x{trace.Start:x}"
      else
        ()
      if trace.Instructions.Length = 0 then
        if mode = Full then
          yield displayField "instructions" "none"
        else
          ()
      else
        if mode = Full then yield "  instructions:" else ()
        for ins in trace.Instructions do
          let indent = if mode = Full then "    " else "  "
          yield $"{indent}0x{ins.Address:x}: {ins.Disassembly}"
      if mode = Full || trace.RegisterDiffs.Length > 0 then
        yield! displaySection "registers" (Array.toList trace.RegisterDiffs)
      else
        ()
      if trace.MemoryAccesses.Length = 0 then
        if mode = Full then
          yield displayField "memory-accesses" "none"
        else
          ()
      else
        yield "  memory-accesses:"
        for access in trace.MemoryAccesses do
          for line in renderMemoryAccess mode access do
            yield "    " + line
      if trace.MemoryDiffs.Length = 0 then
        if mode = Full then
          yield displayField "memory-watch" "none"
        else
          ()
      else
        yield "  memory-watch:"
        for diff in trace.MemoryDiffs do
          for line in renderMemoryDiff mode diff do
            yield "    " + line
      if mode = Full || trace.StopReasons.Length > 0 then
        yield! displaySection "stop-reasons" (Array.toList trace.StopReasons)
      else
        ()
    }

  let renderRequirements needs =
    let needs: ContextRequirements = needs
    let target =
      match needs.EndAddress, needs.Count with
      | Some finish, _ ->
        $"0x{needs.Start:x}-0x{finish:x}"
      | None, Some count ->
        $"0x{needs.Start:x} count={count}"
      | None, None ->
        $"0x{needs.Start:x}"
    let header =
      [ "ContextRequirements"
        displayField "target" target
        displayField "register-count" (string needs.Registers.Length)
        displayField "memory-count" (string needs.Memory.Length) ]
    let registers =
      needs.Registers
      |> Array.toList
      |> List.map (fun item ->
        $"{item.Name} read at 0x{item.Address:x}  {item.Disassembly}"
        + $"  => @make-concrete-executor regs=[{item.Name}=<value>]")
    let memory =
      needs.Memory
      |> Array.toList
      |> List.map (fun item ->
        match item.Address with
        | Some addr ->
          $"0x{addr:x} size={item.Size} at 0x{item.At:x}"
          + $"  => @write-memory addr=0x{addr:x} bytes=<hex>"
        | None ->
          $"<unknown> size={item.Size} at 0x{item.At:x}"
          + $"  ({item.Reason})")
    header
    @ displaySection "required-registers" registers
    @ displaySection "required-memory" memory

  let private renderAddressValue (value: AddressValue) =
    [ $"0x{value.Address:x}" ]

  let private symbRegionPermission permission =
    let permission: SymbRegionPermission = permission
    [ if permission.Read then Some "r" else None
      if permission.Write then Some "w" else None
      if permission.Execute then Some "x" else None ]
    |> List.choose id
    |> function
      | [] ->
        "-"
      | permissions ->
        String.concat "" permissions

  let private renderSymbExecutor mode executor =
    let executor: SymbExecutorValue = executor
    let solver =
      executor.Solver
      |> Option.map (fun solver -> "@" + solver.ID)
      |> Option.defaultValue "none"
    let inputs =
      executor.Inputs
      |> List.rev
      |> List.map (fun input ->
        $"{input.Name}: {input.Location}, {input.Size} bytes")
    match mode with
    | Preview ->
      [ $"SymbExecutor: {binaryPath executor.Binary}, "
        + $"PC=0x{executor.State.PC:x}, solver={solver}" ]
      @ if List.isEmpty inputs then
          []
        else
          displaySection "symbolic-inputs" inputs
    | Full ->
      let avoids =
        executor.Avoids
        |> Seq.map (fun address -> $"0x{address:x}")
        |> Seq.toList
      let regions =
        executor.Regions
        |> List.rev
        |> List.map (fun region ->
          let permission = symbRegionPermission region.Permission
          $"{region.Name}: 0x{region.Start:x}-0x{region.Finish:x}, "
          + permission)
      let hooks = executor.HookDescriptions |> List.rev
      [ "SymbExecutor" ]
      @ binaryDisplayFields executor.Binary
      @ [ displayField "pc" $"0x{executor.State.PC:x}"
          displayField "solver" solver ]
      @ displaySection "symbolic-inputs" inputs
      @ displaySection "avoid" avoids
      @ displaySection "regions" regions
      @ displaySection "hooks" hooks

  let private renderSymbSolver mode solver =
    let solver: SymbSolverValue = solver
    match mode with
    | Preview ->
      [ "@" + solver.ID ]
    | Full ->
      [ "SymbSolver"
        displayField "id" ("@" + solver.ID)
        displayField "description" solver.Description ]

  let private renderConcExecutor mode executor =
    let executor: ConcExecutorValue = executor
    match mode with
    | Preview ->
      let trace = executor.LastTrace
      let status =
        match trace with
        | Some trace ->
          $"PC=0x{trace.FinalPC:x}, {trace.InstructionCount} instructions"
        | None ->
          $"PC=0x{executor.State.PC:x}"
      [ $"ConcExecutor: {binaryPath executor.Binary}, {status}" ]
      @ match trace with
        | Some trace -> Array.toList trace.StopReasons
        | None -> []
    | Full ->
      executor.SummaryLines

  let private renderInputModel
        (source: SymbExecutorValue)
        (values: B2R2.MiddleEnd.SymbEval.SolverValue list)
        (groups: (string * byte[]) list) =
    let groupedCount =
      groups |> List.sumBy (fun (_, bytes: byte[]) -> bytes.Length)
    let fields =
      if groupedCount = List.length values && groupedCount > 0 then
        groups
        |> List.map (fun (name, bytes) ->
          let isRegister =
            source.Inputs
            |> List.exists (fun input ->
              input.Name = name
              && input.Location.StartsWith("reg:", StringComparison.Ordinal))
          let endian = (Binary.Handle source.Binary).ISA.Endian
          let bytes =
            if isRegister && endian = Endian.Little then
              Array.rev bytes
            else
              bytes
          let hex = Convert.ToHexString(bytes)
          let hex = if isRegister then hex.TrimStart('0') else hex
          let hex = if hex = "" then "0" else hex.ToLowerInvariant()
          $"{name}=0x{hex}")
      else
        values
        |> List.map (fun value -> $"{value.Name}={value.Value}")
    if List.isEmpty fields then "<none>" else String.concat ", " fields

  let private renderSymbRun mode result =
    let result: SymbRunValue = result
    match mode with
    | Full ->
      splitTextForDisplay (result.ToString())
    | Preview ->
      let run = result.Result
      let answer = run.Answer
      let status =
        match run.Timeout, answer with
        | Some timeout, _ ->
          $"timed out after {timeout} ms"
        | None, SymbAnswer.Satisfiable _ ->
          "satisfiable"
        | None, SymbAnswer.Unsatisfiable ->
          "unsatisfiable"
        | None, SymbAnswer.Reachable _ ->
          "reachable"
        | None, SymbAnswer.Unreachable ->
          "unreachable"
        | None, SymbAnswer.Unknown _ ->
          "unknown"
      seq {
        yield $"SymbRunResult: {status}"
        match answer with
        | SymbAnswer.Satisfiable _ ->
          for index, (target, values, groups) in
              List.indexed result.InputModels do
            let fields = renderInputModel result.Source values groups
            yield $"  model #{index} at 0x{target:x}: {fields}"
        | SymbAnswer.Reachable answers ->
          for answer in answers do
            yield $"  reached 0x{answer.Target:x}"
        | SymbAnswer.Unknown failures ->
          for failure in failures do
            yield $"  {failure}"
        | SymbAnswer.Unreachable
        | SymbAnswer.Unsatisfiable ->
          ()
      }

  let private ansiOfColor = function
    | NoColor ->
      ""
    | Red ->
      "\x1b[31m"
    | Green ->
      "\x1b[32m"
    | Yellow ->
      "\x1b[33m"
    | Blue ->
      "\x1b[34m"
    | DarkCyan ->
      "\x1b[36m"
    | DarkYellow ->
      "\x1b[33m"
    | RedHighlight ->
      "\x1b[37;41m"
    | GreenHighlight ->
      "\x1b[30;42m"

  let private renderOutString (output: OutString) =
    let reset = "\x1b[0m"
    let builder = StringBuilder()
    output.Render(fun color text ->
      match ansiOfColor color with
      | "" ->
        builder.Append text |> ignore
      | ansi ->
        builder.Append ansi |> ignore
        builder.Append text |> ignore
        builder.Append reset |> ignore)
    splitTextForDisplay (builder.ToString())

  let rec private renderObject mode index (value: obj) =
    seq {
      match value with
      | null ->
        yield "()"
      | :? CFG as cfg ->
        yield! renderCFG mode index cfg
      | :? Binary as binary ->
        yield! renderBinary mode binary
      | :? BinaryBytes as bytes ->
        yield! renderBinaryBytes mode bytes
      | :? (Instruction[]) as instructions ->
        yield! renderInstructionArray mode instructions
      | :? TextArtifact as artifact ->
        yield! splitTextForDisplay artifact.Content
      | :? string as text ->
        yield! splitTextForDisplay text
      | :? OutString as output ->
        yield! renderOutString output
      | :? Fingerprint as fingerprint ->
        yield! renderFingerprint mode fingerprint
      | :? ClusterResult as result ->
        yield! renderClusterResult result
      | :? BinarySlice as slice ->
        yield! renderSlice mode slice
      | :? SectionInfo as section ->
        yield! renderSection mode section
      | :? FunctionInfo as fn ->
        yield! renderFunction mode fn
      | :? StringMatch as stringMatch ->
        yield! renderStringMatch mode stringMatch
      | :? RegisterView as view ->
        yield! renderRegisterView mode view
      | :? MemoryView as view ->
        yield! renderMemoryView mode view
      | :? ExecutionTrace as trace ->
        yield! renderTrace mode trace
      | :? ContextRequirements as needs ->
        yield! renderRequirements needs
      | :? AddressValue as address ->
        yield! renderAddressValue address
      | :? ConcExecutorValue as executor ->
        yield! renderConcExecutor mode executor
      | :? SymbExecutorValue as executor ->
        yield! renderSymbExecutor mode executor
      | :? SymbSolverValue as solver ->
        yield! renderSymbSolver mode solver
      | :? SymbRunValue as result ->
        yield! renderSymbRun mode result
      | :? Array as values ->
        let name = value.GetType().GetElementType().Name
        yield $"{name} array ({values.Length} values)"
        for index in 0 .. values.Length - 1 do
          yield! renderObject mode (Some index) (values.GetValue index)
      | value ->
        yield! splitTextForDisplay (value.ToString())
    }

  let private renderValue mode value =
    let value: ReplValue = value
    let values = value.Collection.Values
    seq {
      if value.IsCollection then
        yield $"{typeDescription value} ({values.Length} values)"
      else
        ()
      for index in 0 .. values.Length - 1 do
        let lines =
          renderObject mode None values[index]
          |> Seq.collect normalizeDisplayLine
        if value.IsCollection then
          use items = lines.GetEnumerator()
          if items.MoveNext() then
            let first = items.Current
            if mode = Preview && not (items.MoveNext()) then
              yield $"  #{index}: {first}"
            else
              yield $"  value #{index}:"
              yield "    " + first
              if mode = Preview then
                yield "    " + items.Current
              else
                ()
              while items.MoveNext() do
                yield "    " + items.Current
          else
            yield $"  #{index}: <empty>"
        else
          yield! lines
    }

  let private renderPrintResult mode result =
    let result: PrintedValue = result
    result.Values |> Seq.collect (renderValue mode)

  let outputValue value =
    ReplOutput.ofLazy (renderValue Preview value)
      (lazy (renderValue Full value |> Seq.toList))

  let outputPrintResult result =
    ReplOutput.ofLazy (renderPrintResult Preview result)
      (lazy (renderPrintResult Full result |> Seq.toList))

