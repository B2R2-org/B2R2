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

/// Routes parsed REPL commands to control or pipeline evaluation.
module internal ReplDispatch =
  open ReplEvaluation
  open ReplControl

  let dispatch
    includeSuggestions
    registry
    state
    input
    cancellationToken
    loadScript =
    function
    | Error message ->
      fail registry state message
    | Ok NoInput ->
      continueWith registry state []
    | Ok Quit ->
      Exit(registry, state)
    | Ok(Help None) ->
      continueWith registry state ReplHelp.guideLines
    | Ok(Help(Some action)) ->
      showActionHelp registry state action
    | Ok Actions ->
      showActions registry state
    | Ok History ->
      showHistory registry state
    | Ok Values ->
      showValues registry state
    | Ok Undo ->
      undo registry state
    | Ok Log ->
      showLog registry state
    | Ok(ExportValue(name, path)) ->
      exportValue registry state name path
    | Ok(Inspect name) ->
      inspect registry state name
    | Ok(Needs(name, args)) ->
      needs registry state name args
    | Ok(Restore(id, name)) ->
      restore registry state id name input
    | Ok(SaveScript path) ->
      saveScript registry state path
    | Ok(LoadScript path) ->
      loadScript path
    | Ok(ScriptRecord enabled) ->
      setScriptRecord registry state enabled
    | Ok(ScriptComment text) ->
      addScriptComment registry state text
    | Ok(PluginLoad path) ->
      loadPlugin registry state path input
    | Ok(Layout _) ->
      continueWith registry state [ ":layout is only available in the TUI." ]
    | Ok Reset ->
      continueWith
        registry
        (TransformerReplState.reset state)
        [ "Analysis state reset." ]
    | Ok(TypeOf name) ->
      showType registry state name
    | Ok(TypeOfExpression segments) ->
      showExpressionType registry state segments
    | Ok(Evaluate(segments, binding, expected)) ->
      ReplPipeline.evaluate
        includeSuggestions
        registry
        state
        segments
        binding
        expected
        input
        cancellationToken
