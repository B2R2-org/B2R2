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

open Avalonia.FuncUI
open Avalonia.FuncUI.Hosts
open Avalonia.Controls

type MainWindow(arbiter) as this =
  inherit HostWindow()

  let init arbiter =
    { LoadedBinary = None
      Functions = []
      SelectedFunction = None
      StatusMessage = "Welcome to BinExplore!" }

  let update (msg: Message) (model: Model) =
    match msg with
    | LoadBinary path ->
      { model with
          LoadedBinary = Some "sample_binary.exe"
          Functions = [
            "main"
            "foo"
            "bar"
            "baz"
          ]
          StatusMessage = "Loaded binary: sample_binary.exe" }
    | CloseWorkspace ->
      { model with
          LoadedBinary = None
          Functions = []
          SelectedFunction = None
          StatusMessage = "Workspace closed. Open a file to start exploring." }
    | SelectFunction func ->
      { model with
          SelectedFunction = Some func
          StatusMessage = $"Selected function: {func}" }
    | UpdateStatus msg ->
      { model with StatusMessage = msg }
    | NoOp ->
      model

  do
    base.Title <- "BinExplore"
    base.MinWidth <- 800.0
    base.MinHeight <- 600.0
    let screen = this.Screens.Primary
    if screen <> null then
      base.Width <- float screen.WorkingArea.Width * 0.8
      base.Height <- float screen.WorkingArea.Height * 0.8
      base.WindowStartupLocation <- WindowStartupLocation.CenterScreen
    else
      ()
    Elmish.Program.mkSimple (fun () -> init arbiter) update MainView.view
    |> Elmish.Program.withHost this
    |> Elmish.Program.run
