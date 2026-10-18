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

namespace B2R2.RearEnd.Transformer.Tests

open System
open System.Threading
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.MiddleEnd.SymbEval
open B2R2.RearEnd.Transformer

[<TestClass>]
type ReplParserTests() =
  let registry = lazy(ActionRegistry.create None)

  let collectionValue kind =
    { Kind = ReplValueKind.List kind
      IsCollection = true
      Collection = { Values = [||] } }

  let stateForCollection kind =
    let value = collectionValue kind
    { TransformerReplState.empty with
        Bindings = Map.ofList [ "targets", value ]
        Current = Some value }

  let parseEvaluate input =
    match TransformerReplParser.parse input with
    | Ok(Evaluate(segments, binding, expected)) ->
      segments, binding, expected
    | Ok command ->
      Assert.Fail $"Expected an evaluation, but parsed {command}."
      [], None, None
    | Error message ->
      Assert.Fail $"Parsing failed: {message}"
      [], None, None

  let candidateTexts kind input =
    Suggestions.get registry.Value (stateForCollection kind) input input.Length
    |> fun result -> result.Items |> List.map _.Text

  let completionHint kind input =
    let value =
      { Kind = kind
        IsCollection = false
        Collection = { Values = [||] } }
    let state =
      { TransformerReplState.empty with
          Bindings = Map.ofList [ "target", value ]
          Current = Some value }
    Suggestions.get registry.Value state input input.Length
    |> _.Hint
    |> Option.defaultValue ""

  let assertArguments expected actual =
    Assert.AreEqual<string list>(expected, actual)

  let assertDoesNotContain (expected: string) (actual: string) =
    let contains = actual.Contains(expected, StringComparison.Ordinal)
    Assert.AreEqual(false, contains, actual)

  let parsePartial input =
    match ReplLanguage.tryParsePartialPipeline input with
    | Some pipeline ->
      pipeline
    | None ->
      Assert.Fail "Expected incomplete input to produce a partial pipeline."
      Unchecked.defaultof<ReplPartialPipeline>

  let evaluate registry state input =
    match TransformerReplEvaluator.evaluateCommand
            registry state input CancellationToken.None with
    | Continue(registry, state, _) ->
      registry, state
    | Exit _ ->
      Assert.Fail "Expected command evaluation to continue."
      registry, state

  let evaluateOutput registry state input =
    match TransformerReplEvaluator.evaluateCommand
            registry state input CancellationToken.None with
    | Continue(registry, state, output) ->
      registry, state, output
    | Exit _ ->
      Assert.Fail "Expected command evaluation to continue."
      registry, state, ReplOutput.ofLines []

  let evaluateControlOutput registry state input =
    match TransformerReplEvaluator.evaluateControlCommand
            registry state input CancellationToken.None with
    | Continue(registry, state, output) ->
      registry, state, output
    | Exit _ ->
      Assert.Fail "Expected command evaluation to continue."
      registry, state, ReplOutput.ofLines []

  [<TestMethod>]
  member _.``Pipeline parser preserves stage and argument boundaries``() =
    let input =
      "let hits = target |> @slice section=.text |> @grep "
      + "pattern=837d..63 before=0 after=50"
    let segments, binding, expected = parseEvaluate input
    Assert.AreEqual(Some "hits", binding)
    Assert.AreEqual(None, expected)
    Assert.AreEqual(3, List.length segments)
    Assert.AreEqual("target", segments[0].Head)
    Assert.IsEmpty segments[0].Arguments
    Assert.AreEqual("@slice", segments[1].Head)
    assertArguments [ "section=.text" ] segments[1].Arguments
    Assert.AreEqual("@grep", segments[2].Head)
    assertArguments
      [ "pattern=837d..63"; "before=0"; "after=50" ] segments[2].Arguments

  [<TestMethod>]
  member _.``Pipeline parser keeps quoted action values intact``() =
    let input =
      "let code = @asm code=\"cmp dword ptr [rbp-0x0], 0x63\" "
      + "isa=x86-64"
    let segments, _, _ = parseEvaluate input
    Assert.AreEqual(1, List.length segments)
    Assert.AreEqual("@asm", segments[0].Head)
    assertArguments
      [ "code=\"cmp dword ptr [rbp-0x0], 0x63\""; "isa=x86-64" ]
      segments[0].Arguments

  [<TestMethod>]
  member _.``Pipeline parser retains iter lambda tokens``() =
    let input = "targets |> iter @strings (fun item -> min=4)"
    let segments, binding, expected = parseEvaluate input
    Assert.AreEqual(None, binding)
    Assert.AreEqual(None, expected)
    Assert.AreEqual(2, List.length segments)
    Assert.AreEqual("iter", segments[1].Head)
    assertArguments
      [ "@strings"; "("; "fun"; "item"; "->"; "min=4"; ")" ]
      segments[1].Arguments

  [<TestMethod>]
  member _.``Pipeline parser retains literal punctuation``() =
    let segments, _, _ = parseEvaluate "let pair = (left, right)"
    Assert.AreEqual(1, List.length segments)
    Assert.AreEqual("(", segments[0].Head)
    assertArguments [ "left"; ","; "right"; ")" ] segments[0].Arguments
    let segments, _, _ = parseEvaluate "let values = [left; right]"
    Assert.AreEqual("[", segments[0].Head)
    assertArguments [ "left"; ";"; "right"; "]" ] segments[0].Arguments

  [<TestMethod>]
  member _.``Pipeline parser rejects incomplete delimiters``() =
    match TransformerReplParser.parse "targets |> iter @strings (fun item" with
    | Error _ ->
      ()
    | Ok command ->
      Assert.Fail $"Expected a parse error, but parsed {command}."

  [<TestMethod>]
  member _.``Partial iter analysis records a missing lambda arrow``() =
    let analysis =
      ReplLanguage.analyzeIter "iter" [ "@strings"; "("; "fun"; "item" ]
    Assert.AreEqual(Some "strings", analysis.ActionID)
    Assert.AreEqual(Some [ "item" ], analysis.LambdaParameters)
    Assert.AreEqual(1, analysis.ExpectedParameterCount)
    Assert.AreEqual(true, analysis.HasOpeningDelimiter)
    Assert.AreEqual(false, analysis.HasArrow)
    Assert.AreEqual(false, analysis.HasClosingDelimiter)

  [<TestMethod>]
  member _.``Partial parser retains an incomplete lambda``() =
    let pipeline =
      parsePartial "targets |> iter @strings (fun item "
    Assert.AreEqual(Some 8, pipeline.LastPipelineStart)
    Assert.AreEqual(false, pipeline.HasTrailingPipeline)
    Assert.AreEqual<string list list>(
      [ [ "targets" ]; [ "iter"; "@strings"; "("; "fun"; "item" ] ],
      pipeline.Segments |> List.map _.Tokens
    )

  [<TestMethod>]
  member _.``Partial parser identifies the active incomplete scope``() =
    let input = "targets |> iter @grep (fun item -> pattern=1234 "
    let scope =
      parsePartial input
      |> ReplLanguage.tryPartialScope
      |> Option.defaultWith (fun () ->
        Assert.Fail "Expected an incomplete lambda scope."
        Unchecked.defaultof<ReplPartialScope>)
    Assert.AreEqual(input.IndexOf("fun", StringComparison.Ordinal), scope.Start)
    assertArguments
      [ "fun"; "item"; "->"; "pattern=1234" ] scope.Tokens
    let context = InputAnalysis.analyze input input.Length
    Assert.AreEqual(input[scope.Start..], context.Expression)
    assertArguments scope.Tokens context.SegmentWords

  [<TestMethod>]
  member _.``Partial parser records a trailing pipeline``() =
    let pipeline = parsePartial "targets |> "
    Assert.AreEqual(Some 8, pipeline.LastPipelineStart)
    Assert.AreEqual(true, pipeline.HasTrailingPipeline)
    Assert.AreEqual<string list list>(
      [ [ "targets" ] ],
      pipeline.Segments |> List.map _.Tokens
    )

  [<TestMethod>]
  member _.``Partial parser retains an unfinished quoted value``() =
    let pipeline = parsePartial "target |> @asm code=\"cmp dword"
    Assert.AreEqual(false, pipeline.HasTrailingPipeline)
    Assert.AreEqual<string list list>(
      [ [ "target" ]; [ "@asm"; "code=\"cmp dword" ] ],
      pipeline.Segments |> List.map _.Tokens
    )

  [<TestMethod>]
  member _.``Completion suggests iterator keywords while editing one``() =
    let candidates =
      candidateTexts ReplValueKind.Binary "targets |> iter"
    Assert.AreEqual(true, List.contains "iter" candidates)
    Assert.AreEqual(true, List.contains "iteri" candidates)

  [<TestMethod>]
  member _.``Completion suggests a lambda arrow after its parameter``() =
    let candidates =
      candidateTexts ReplValueKind.Binary
        "targets |> iter @strings (fun item "
    let detail = String.concat ", " candidates
    Assert.AreEqual(true, List.contains "-> " candidates, detail)

  [<TestMethod>]
  member _.``Completion suggests optional grep parameters in a lambda``() =
    let input =
      "targets |> iter @grep (fun item -> pattern=1234 "
    let candidates = candidateTexts ReplValueKind.BinarySlice input
    let detail = String.concat ", " candidates
    Assert.AreEqual(true, List.contains "context=" candidates, detail)
    Assert.AreEqual(true, List.contains "before=" candidates, detail)
    Assert.AreEqual(true, List.contains "after=" candidates, detail)

  [<TestMethod>]
  member _.``Completion suggests compatible argument bindings``() =
    let executor = collectionValue ReplValueKind.ConcExecutor
    let address =
      { Address = 0x401e08UL }
      |> box
      |> fun value -> { Values = [| value |] }
      |> ReplValue.ofCollection ReplValueKind.Address
    let limit =
      100
      |> box
      |> fun value -> { Values = [| value |] }
      |> ReplValue.ofCollection ReplValueKind.Int
    let state =
      { TransformerReplState.empty with
          Bindings =
            Map.ofList
              [ "executor", executor
                "functionEntry", address
                "failureLimit", limit ] }
    let entryInput = "executor |> @run-concrete entry=f"
    let entryCandidates =
      Suggestions.get registry.Value state entryInput entryInput.Length
      |> _.Items
      |> List.map _.Text
    Assert.Contains("functionEntry", entryCandidates)
    Assert.DoesNotContain("failureLimit", entryCandidates)
    let limitInput = "executor |> @run-concrete limit=f"
    let limitCandidates =
      Suggestions.get registry.Value state limitInput limitInput.Length
      |> _.Items
      |> List.map _.Text
    Assert.Contains("failureLimit", limitCandidates)
    Assert.DoesNotContain("functionEntry", limitCandidates)

  [<TestMethod>]
  member _.``Completion hint filters edit operation overloads``() =
    let hint =
      completionHint
        ReplValueKind.Binary
        "target |> @edit replace start="
    StringAssert.Contains(hint, "@edit replace")
    assertDoesNotContain "@edit insert" hint
    assertDoesNotContain "@edit delete" hint
    assertDoesNotContain "@edit force-replace" hint

  [<TestMethod>]
  member _.``Completion hint filters list operation overloads``() =
    let hint =
      completionHint ReplValueKind.Binary "target |> @list functions"
    StringAssert.Contains(hint, "@list functions")
    assertDoesNotContain "@list sections" hint
    assertDoesNotContain "@list known-functions" hint

  [<TestMethod>]
  member _.``Completion hint filters memory operation overloads``() =
    let hint =
      completionHint
        ReplValueKind.ConcExecutor
        "target |> @mem read addr="
    StringAssert.Contains(hint, "@mem read")
    assertDoesNotContain "@mem write" hint

  [<TestMethod>]
  member _.``Colon-prefixed shell input is not a control command``() =
    let _, _, output =
      evaluateOutput registry.Value TransformerReplState.empty ":help"
    Assert.AreEqual<string list>(
      [ "Error: Unknown value or action: :help" ],
      output.Lines
    )

  [<TestMethod>]
  member _.``Colon-prefixed shell input has no completion``() =
    let suggestions =
      Suggestions.get registry.Value TransformerReplState.empty ":help" 5
    Assert.IsEmpty suggestions.Items

  [<TestMethod>]
  member _.``Control prompt does not recognize show``() =
    let _, _, output =
      evaluateControlOutput registry.Value TransformerReplState.empty ":show"
    Assert.AreEqual<string list>(
      [ "Error: Unknown REPL command: :show" ],
      output.Lines
    )

  [<TestMethod>]
  member _.``Completion suggests observed addresses with latest sources``() =
    let registry, state =
      evaluate
        registry.Value
        TransformerReplState.empty
        "let target = @load hex=90c3 isa=x86-64"
    let registry, state =
      evaluate registry state "let targets = [target; target]"
    let registry, state =
      evaluate registry state "targets |> iter @disasm |> @print"
    let source = Unchecked.defaultof<Binary>
    let functionValue =
      { Source = source; Entry = 0UL; Symbol = None }
      |> box
      |> fun value -> { Values = [| value |] }
      |> ReplValue.ofCollection ReplValueKind.FunctionInfo
    let state =
      TransformerReplState.observeValue
        state.NextLogID
        "@list functions"
        functionValue
        state
    let input = "let addr = 0x"
    let items = Suggestions.get registry state input input.Length |> _.Items
    let zero = items |> List.filter (fun item -> item.Text = "0x0")
    Assert.HasCount(1, zero)
    Assert.AreEqual("command #4 · @list functions", zero.Head.Detail)
    let one = items |> List.find (fun item -> item.Text = "0x1")
    Assert.AreEqual("command #3 · @disasm", one.Detail)

  [<TestMethod>]
  member _.``Completion preserves symbolic input widths``() =
    let solverValue name value: SolverValue =
      { Name = name; Value = BitVector(uint64 value, 8<rt>) }
    let values =
      [ solverValue "idx_0" 0xf0
        solverValue "idx_1" 0xff
        solverValue "idx_2" 0xff
        solverValue "idx_3" 0xf0 ]
      @ ([ 0 .. 7 ]
         |> List.map (fun index -> solverValue $"ind_{index}" 0))
    let answer: SymbSatisfiabilityAnswer =
      { Target = 0x401e5cUL
        State = SymbState()
        Values = values }
    let result: SymbRunResult =
      { Answer = SymbAnswer.Satisfiable [ answer ]
        StopReasons = []
        PruneReasons = []
        StateCount = 1
        Timeout = None }
    let source = Unchecked.defaultof<SymbExecutorValue>
    let run = SymbRunValue(source, "satisfy", Some answer.Target, result)
    let value =
      ReplValue.ofCollection
        ReplValueKind.SymbRunResult
        { Values = [| box run |] }
    let state =
      TransformerReplState.observeValue
        7
        "@run-symbolic"
        value
        TransformerReplState.empty
    let idxInput = "let idxValue = 0x"
    let idxItems =
      Suggestions.get registry.Value state idxInput idxInput.Length |> _.Items
    let idx =
      idxItems |> List.find (fun item -> item.Text = "0xf0fffff0")
    Assert.AreEqual("command #7 · @run-symbolic · idx:4", idx.Detail)
    let indInput = "let indValue = 0x0"
    let indItems =
      Suggestions.get registry.Value state indInput indInput.Length |> _.Items
    let ind =
      indItems
      |> List.find (fun item -> item.Text = "0x0000000000000000")
    Assert.AreEqual("command #7 · @run-symbolic · ind:8", ind.Detail)
