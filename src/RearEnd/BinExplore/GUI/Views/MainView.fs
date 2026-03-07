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

module B2R2.RearEnd.BinExplore.GUI.MainView

open Avalonia.Controls
open Avalonia.FuncUI.DSL

let private workspaceView model dispatch =
  Grid.create [
    Grid.columnDefinitions "250,5,*"
    Grid.children [
      FunctionList.view model dispatch
      GridSplitter.create [
        GridSplitter.column 1
        GridSplitter.background model.Theme.Panel.Border
        GridSplitter.resizeDirection GridResizeDirection.Columns
      ]
      DockPanel.create [
        Grid.column 2
        DockPanel.children [
          TabBar.view model dispatch
          CFGPanel.view model dispatch
        ]
      ]
    ]
  ]

let private mainArea (model: Model) dispatch =
  match model.LoadedBinary with
  | None -> Welcome.view model dispatch
  | Some _ -> workspaceView model dispatch

let view (model: Model) (dispatch: Message -> unit) =
  DockPanel.create [
    DockPanel.children [
      MenuBar.view model dispatch
      StatusBar.view model
      mainArea model dispatch
    ]
  ]
