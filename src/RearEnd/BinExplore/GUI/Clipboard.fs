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

namespace B2R2.RearEnd.BinExplore.GUI

open Avalonia.Controls
open Avalonia.Controls.Primitives

[<RequireQualifiedAccess>]
module Clipboard =

  let tryGetHostTopLevel (source: obj) =
    match source with
    | :? Control as control ->
      match TopLevel.GetTopLevel control with
      | :? PopupRoot as popup when not (isNull popup.ParentTopLevel) ->
        popup.ParentTopLevel
      | topLevel ->
        topLevel
    | _ ->
      null

  let setText reportError source text =
    let topLevel = tryGetHostTopLevel source
    if isNull topLevel then
      reportError "Clipboard is unavailable."
    else
      Async.StartImmediate(async {
        try
          do! topLevel.Clipboard.SetTextAsync text |> Async.AwaitTask
        with ex ->
          reportError $"Failed to copy text: {ex.Message}"
      })

