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

module B2R2.RearEnd.BinExplore.GUI.MenuBar

open Avalonia.FuncUI.DSL
open Avalonia.Controls
open Avalonia.Controls.Primitives
open Avalonia.Platform.Storage

let private tryGetHostTopLevel (source: obj) =
  match source with
  | :? Control as control ->
    match TopLevel.GetTopLevel control with
    | :? PopupRoot as popup when not (isNull popup.ParentTopLevel) ->
      popup.ParentTopLevel
    | topLevel ->
      topLevel
  | _ ->
    null

let private openBinaryDialog dispatch (source: obj) =
  let topLevel = tryGetHostTopLevel source
  if isNull topLevel then
    ()
  else
    async {
      try
        let! files =
          FilePickerOpenOptions(Title = "Open Binary", AllowMultiple = false)
          |> topLevel.StorageProvider.OpenFilePickerAsync
          |> Async.AwaitTask
        files
        |> Seq.tryHead
        |> Option.iter (fun file ->
          dispatch (OpenBinary file.Path.LocalPath))
      with ex ->
        dispatch (UpdateStatusMsg $"Failed to open file dialog: {ex.Message}")
    } |> Async.StartImmediate

let private menuFile model dispatch =
  MenuItem.create [
    MenuItem.header "File"
    MenuItem.background model.Theme.Menu.ItemBackground
    MenuItem.foreground model.Theme.Menu.ItemForeground
    MenuItem.viewItems [
      MenuItem.create [
        MenuItem.header "Open Binary..."
        MenuItem.background model.Theme.Menu.ItemBackground
        MenuItem.foreground model.Theme.Menu.ItemForeground
        MenuItem.onClick (fun e -> openBinaryDialog dispatch e.Source)
      ]
      MenuItem.create [
        MenuItem.header "Close Session"
        MenuItem.background model.Theme.Menu.ItemBackground
        MenuItem.foreground model.Theme.Menu.ItemForeground
        MenuItem.isEnabled model.LoadedBinary.IsSome
        MenuItem.onClick (fun _ -> dispatch CloseWorkspace)
      ]
      MenuItem.create [
        MenuItem.header "-"
        MenuItem.background model.Theme.Menu.ItemBackground
        MenuItem.foreground model.Theme.Menu.ItemForeground
      ]
      MenuItem.create [
        MenuItem.header "Exit"
        MenuItem.background model.Theme.Menu.ItemBackground
        MenuItem.foreground model.Theme.Menu.ItemForeground
        MenuItem.onClick (fun _ -> dispatch ExitApplication)
      ]
    ]
  ]

let private isDarkSelected model =
  match model.ThemeMode with
  | Builtin Dark -> true
  | _ -> false

let private isLightSelected model =
  match model.ThemeMode with
  | Builtin Light -> true
  | _ -> false

let private isCustomSelected model =
  match model.ThemeMode with
  | Custom _ -> true
  | _ -> false

let private menuView model dispatch =
  MenuItem.create [
    MenuItem.header "View"
    MenuItem.background model.Theme.Menu.ItemBackground
    MenuItem.foreground model.Theme.Menu.ItemForeground
    MenuItem.viewItems [
      MenuItem.create [
        MenuItem.header "Themes"
        MenuItem.background model.Theme.Menu.ItemBackground
        MenuItem.foreground model.Theme.Menu.ItemForeground
        MenuItem.viewItems [
          MenuItem.create [
            MenuItem.header "Dark"
            MenuItem.background model.Theme.Menu.ItemBackground
            MenuItem.foreground model.Theme.Menu.ItemForeground
            MenuItem.toggleType MenuItemToggleType.Radio
            MenuItem.isChecked (isDarkSelected model)
            MenuItem.onClick (fun _ -> dispatch (SetThemeMode(Builtin Dark)))
          ]
          MenuItem.create [
            MenuItem.header "Light"
            MenuItem.background model.Theme.Menu.ItemBackground
            MenuItem.foreground model.Theme.Menu.ItemForeground
            MenuItem.toggleType MenuItemToggleType.Radio
            MenuItem.isChecked (isLightSelected model)
            MenuItem.onClick (fun _ -> dispatch (SetThemeMode(Builtin Light)))
          ]
          MenuItem.create [
            MenuItem.header "Custom..."
            MenuItem.background model.Theme.Menu.ItemBackground
            MenuItem.foreground model.Theme.Menu.ItemForeground
            MenuItem.toggleType MenuItemToggleType.Radio
            MenuItem.isChecked (isCustomSelected model)
            MenuItem.onClick (fun _ ->
              dispatch (UpdateStatusMsg "Not implemented yet."))
          ]
        ]
      ]
    ]
  ]

let view model dispatch =
  Menu.create [
    Menu.dock Dock.Top
    Menu.background model.Theme.Menu.Background
    Menu.foreground model.Theme.Menu.Foreground
    Menu.viewItems [
      menuFile model dispatch
      menuView model dispatch
    ]
  ]
