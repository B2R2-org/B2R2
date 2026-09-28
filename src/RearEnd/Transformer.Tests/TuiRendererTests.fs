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

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2.RearEnd.Transformer

[<TestClass>]
type TuiRendererTests() =
  let registry = lazy(ActionRegistry.create None)

  let itemsCompletion =
    { Items =
        [ { Text = "load"
            Label = "load"
            Detail = "Load a binary"
            Kind = SuggestionKind.Action
            AppendSpace = true
            Form = SuggestionForm.Token
            CursorOffset = None } ]
      Start = 0
      Length = 0
      Hint = None
      HintHighlights = []
      Diagnostics = [] }

  let emptyCompletion =
    { itemsCompletion with Items = []; Hint = None }

  [<TestMethod>]
  member _.``suggestion list is labeled when items are shown``() =
    let frame =
      TransformerTuiRenderer.render
        80 30 registry.Value TransformerTuiModel.initial itemsCompletion
    let hasCaption =
      frame.Lines
      |> Array.exists (fun line -> line.Contains "Suggestions")
    Assert.AreEqual(true, hasCaption)

  [<TestMethod>]
  member _.``empty completion keeps its own placeholder text``() =
    let frame =
      TransformerTuiRenderer.render
        80 30 registry.Value TransformerTuiModel.initial emptyCompletion
    let hasPlaceholder =
      frame.Lines
      |> Array.exists (fun line ->
        line.Contains "Suggestions appear here as you type.")
    Assert.AreEqual(true, hasPlaceholder)

  [<TestMethod>]
  member _.``view find renders an input row with its cursor``() =
    let pane =
      { BlockIndex = 1
        Lines = [| { Kind = TuiLineKind.Output; Text = "needle" } |]
        Cursor = { Line = 0; Column = 0 }
        Anchor = None
        FindText = "needle"
        IsFinding = true }
    let model =
      { TransformerTuiModel.initial with
          Overlay = TuiOverlay.View
          ViewPane = Some pane }
    let frame =
      TransformerTuiRenderer.render 80 30 registry.Value model emptyCompletion
    let hasFindInput =
      frame.Lines |> Array.exists (fun line -> line.Contains " find: needle")
    Assert.AreEqual(true, hasFindInput)
    Assert.AreEqual(30, frame.CursorRow)
    Assert.AreEqual(14, frame.CursorColumn)
