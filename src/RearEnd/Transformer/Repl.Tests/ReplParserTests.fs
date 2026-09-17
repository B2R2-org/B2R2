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
open Microsoft.VisualStudio.TestTools.UnitTesting
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
    | Ok(Evaluate(segments, binding, expected)) -> segments, binding, expected
    | Ok command ->
      Assert.Fail $"Expected an evaluation, but parsed {command}."
      [], None, None
    | Error message ->
      Assert.Fail $"Parsing failed: {message}"
      [], None, None

  let candidateTexts kind input =
    Suggestions.get registry.Value (stateForCollection kind) input input.Length
    |> fun result -> result.Items |> List.map _.Text

  let assertArguments expected actual =
    Assert.AreEqual<string list>(expected, actual)

  let parsePartial input =
    match ReplLanguage.tryParsePartialPipeline input with
    | Some pipeline -> pipeline
    | None ->
      Assert.Fail "Expected incomplete input to produce a partial pipeline."
      Unchecked.defaultof<ReplPartialPipeline>

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
    | Error _ -> ()
    | Ok command -> Assert.Fail $"Expected a parse error, but parsed {command}."

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
      pipeline.Segments |> List.map _.Tokens)

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
      [ [ "targets" ] ], pipeline.Segments |> List.map _.Tokens)

  [<TestMethod>]
  member _.``Partial parser retains an unfinished quoted value``() =
    let pipeline = parsePartial "target |> @asm code=\"cmp dword"
    Assert.AreEqual(false, pipeline.HasTrailingPipeline)
    Assert.AreEqual<string list list>(
      [ [ "target" ]; [ "@asm"; "code=\"cmp dword" ] ],
      pipeline.Segments |> List.map _.Tokens)

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
