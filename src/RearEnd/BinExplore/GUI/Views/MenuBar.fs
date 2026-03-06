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

let view model dispatch =
  let isDarkSelected =
    match model.ThemeMode with
    | Builtin Dark -> true
    | _ -> false
  let isLightSelected =
    match model.ThemeMode with
    | Builtin Light -> true
    | _ -> false
  let isCustomSelected =
    match model.ThemeMode with
    | Custom _ -> true
    | _ -> false
  let menuBg = model.Theme.Panel.AltBackground
  let menuFg = model.Theme.Text.Primary
  Menu.create [
    Menu.dock Dock.Top
    Menu.background menuBg
    Menu.foreground menuFg
    Menu.viewItems [
      MenuItem.create [
        MenuItem.header "File"
        MenuItem.background menuBg
        MenuItem.foreground menuFg
        MenuItem.viewItems [
          MenuItem.create [
            MenuItem.header "Open Binary..."
            MenuItem.background menuBg
            MenuItem.foreground menuFg
            MenuItem.onClick (fun _ -> dispatch (OpenBinary ""))
          ]
          MenuItem.create [
            MenuItem.header "Close Binary"
            MenuItem.background menuBg
            MenuItem.foreground menuFg
            MenuItem.isEnabled model.LoadedBinary.IsSome
            MenuItem.onClick (fun _ -> dispatch CloseBinary)
          ]
          MenuItem.create [
            MenuItem.header "-"
            MenuItem.background menuBg
            MenuItem.foreground menuFg
          ]
          MenuItem.create [
            MenuItem.header "Exit"
            MenuItem.background menuBg
            MenuItem.foreground menuFg
            MenuItem.onClick (fun _ -> dispatch ExitApplication)
          ]
        ]
      ]
      MenuItem.create [
        MenuItem.header "View"
        MenuItem.background menuBg
        MenuItem.foreground menuFg
        MenuItem.viewItems [
          MenuItem.create [
            MenuItem.header "Themes"
            MenuItem.background menuBg
            MenuItem.foreground menuFg
            MenuItem.viewItems [
              MenuItem.create [
                MenuItem.header "Dark"
                MenuItem.background menuBg
                MenuItem.foreground menuFg
                MenuItem.toggleType MenuItemToggleType.Radio
                MenuItem.isChecked isDarkSelected
                MenuItem.onClick (fun _ ->
                  dispatch (SetThemeMode(Builtin Dark)))
              ]
              MenuItem.create [
                MenuItem.header "Light"
                MenuItem.background menuBg
                MenuItem.foreground menuFg
                MenuItem.toggleType MenuItemToggleType.Radio
                MenuItem.isChecked isLightSelected
                MenuItem.onClick (fun _ ->
                  dispatch (SetThemeMode(Builtin Light)))
              ]
              MenuItem.create [
                MenuItem.header "Custom..."
                MenuItem.background menuBg
                MenuItem.foreground menuFg
                MenuItem.toggleType MenuItemToggleType.Radio
                MenuItem.isChecked isCustomSelected
                MenuItem.onClick (fun _ ->
                  dispatch (UpdateStatus "Not implemented yet."))
              ]
            ]
          ]
        ]
      ]
    ]
  ]
