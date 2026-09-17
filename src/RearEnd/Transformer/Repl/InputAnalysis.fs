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

/// Whether completion is editing a token or starting the next syntax slot.
[<RequireQualifiedAccess>]
type InputCompletionPhase =
  | EditingToken
  | StartingToken

/// Cursor-local syntax facts used by interactive suggestion providers.
type InputContext =
  { InputBeforeCursor: string
    InputAfterCursor: string
    Prefix: string
    CompletionPhase: InputCompletionPhase
    TokenStart: int
    TokenLength: int
    Words: string list
    FullExpression: string
    Expression: string
    Segment: string
    SegmentWords: string list
    PartialPipeline: ReplPartialPipeline option
    HasBinding: bool
    HasPipeline: bool }

module InputAnalysis =
  let tokenizeWith mode text = ReplLanguage.tokenizeWith mode text

  let tokenize text = ReplLanguage.tokenize text

  let tokenizeStrict text = ReplLanguage.tokenizeStrict text

  let splitWords text = ReplLanguage.splitWords text

  let updateDepth depth token = ReplLanguage.updateDepth depth token

  let splitPipelineTokens text = ReplLanguage.splitPipelineText text

  let splitPipeline text = ReplLanguage.splitPipeline text

  let splitTopLevelCommands text = ReplLanguage.splitTopLevelCommands text

  let isIncomplete text = ReplLanguage.isIncomplete text

  let combineCommandLines lines = ReplLanguage.combineCommandLines lines

  let allButLast values =
    match List.rev values with
    | _ :: rest -> List.rev rest
    | [] -> []

  let expressionPortion input = ReplLanguage.expressionPortion input

  let tokenStart (input: string) cursor =
    let rec loop index quote start =
      if index >= cursor then
        start
      else
        let chr = input[index]
        match quote with
        | Some delimiter when chr = delimiter ->
          loop (index + 1) None start
        | Some _ ->
          loop (index + 1) quote start
        | None when chr = '\'' || chr = '"' ->
          loop (index + 1) (Some chr) index
        | None when chr = '|' && index + 1 < cursor
          && input[index + 1] = '>' ->
          loop (index + 2) None (index + 2)
        | None when chr = '-' && index + 1 < cursor
          && input[index + 1] = '>' ->
          loop (index + 2) None (index + 2)
        | None when chr = '|' && index + 1 < cursor
          && input[index + 1] = ']' ->
          loop (index + 2) None (index + 2)
        | None when chr = '[' && index + 1 < cursor
          && input[index + 1] = '|' ->
          loop (index + 2) None (index + 2)
        | None when ReplLanguage.isTokenPunctuation chr ->
          loop (index + 1) None (index + 1)
        | None when chr = ' ' || chr = '\t' || chr = '=' ->
          loop (index + 1) None (index + 1)
        | None ->
          loop (index + 1) None start
    loop 0 None 0

  let topLevelLastPipeline input = ReplLanguage.topLevelLastPipeline input

  let activeExpression input = ReplLanguage.activeExpression input

  let private partialPipeline previous fullExpression =
    previous
    |> Option.bind (fun (context: InputContext) ->
      context.PartialPipeline
      |> Option.bind (fun pipeline ->
        ReplLanguage.tryUpdatePartialPipeline context.FullExpression pipeline
          fullExpression))
    |> Option.orElseWith (fun () ->
      ReplLanguage.tryParsePartialPipeline fullExpression)

  let analyzeExpressionWithCache previous (input: string) cursor
                                 (fullExpression: string) =
    let cursor = max 0 (min cursor input.Length)
    let start = tokenStart input cursor
    let prefix =
      if cursor <= start then "" else input[start..cursor - 1]
    let inputBeforeCursor =
      if cursor = 0 then "" else input[..cursor - 1]
    let inputAfterCursor =
      if cursor = input.Length then "" else input[cursor..]
    let words = splitWords inputBeforeCursor
    let partialPipeline = partialPipeline previous fullExpression
    let expression, segment, segmentWords, lastPipeline =
      match partialPipeline with
      | Some pipeline ->
        let lastPipeline = pipeline.LastPipelineStart
        match ReplLanguage.tryPartialScope pipeline with
        | Some scope ->
          let segment =
            if scope.Start >= fullExpression.Length then ""
            else fullExpression[scope.Start..]
          segment, segment, scope.Tokens, lastPipeline
        | None ->
          let segmentStart =
            lastPipeline |> Option.map ((+) 2) |> Option.defaultValue 0
          let segment =
            if segmentStart >= fullExpression.Length then ""
            else fullExpression[segmentStart..]
          let words =
            if pipeline.HasTrailingPipeline then []
            else
              pipeline.Segments
              |> List.tryLast
              |> Option.map _.Tokens
              |> Option.defaultValue []
          fullExpression, segment, words, lastPipeline
      | None ->
        let expression = activeExpression fullExpression
        let lastPipeline = topLevelLastPipeline expression
        let segmentStart =
          lastPipeline |> Option.map ((+) 2) |> Option.defaultValue 0
        let segment =
          if segmentStart >= expression.Length then ""
          else expression[segmentStart..]
        expression, segment, splitWords segment, lastPipeline
    let trimmed = inputBeforeCursor.TrimStart()
    { InputBeforeCursor = inputBeforeCursor
      InputAfterCursor = inputAfterCursor
      Prefix = prefix
      CompletionPhase =
        if cursor = start then InputCompletionPhase.StartingToken
        else InputCompletionPhase.EditingToken
      TokenStart = start
      TokenLength = cursor - start
      Words = words
      FullExpression = fullExpression
      Expression = expression
      Segment = segment
      SegmentWords = segmentWords
      PartialPipeline = partialPipeline
      HasBinding =
        ReplLanguage.bindingHeader trimmed |> Option.isSome
      HasPipeline = Option.isSome lastPipeline }

  let analyzeExpression (input: string) cursor fullExpression =
    analyzeExpressionWithCache None input cursor fullExpression

  let analyzeWithCache previous (input: string) cursor =
    let cursor = max 0 (min cursor input.Length)
    let inputBeforeCursor =
      if cursor = 0 then "" else input[..cursor - 1]
    let fullExpression = expressionPortion inputBeforeCursor
    analyzeExpressionWithCache previous input cursor fullExpression

  let analyze (input: string) cursor = analyzeWithCache None input cursor
