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

module B2R2.RearEnd.BinExplore.GUI.Dialogs

open Avalonia
open Avalonia.Controls
open Avalonia.Layout
open Avalonia.Media
open Avalonia.Threading

let confirm (owner: Window) text yesStr noStr fnOnYes =
  Dispatcher.UIThread.Post(fun () ->
    let mutable result = false
    let dialog = Window()
    dialog.Title <- owner.Title
    dialog.Width <- 420.0
    dialog.Height <- 170.0
    dialog.CanResize <- false
    dialog.WindowStartupLocation <- WindowStartupLocation.CenterOwner
    let message =
      TextBlock(
        Text = text,
        TextWrapping = TextWrapping.Wrap,
        Margin = Thickness 16.0
      )
    let yesButton =
      Button(
        Content = yesStr,
        Width = 90.0,
        Margin = Thickness 4.0,
        HorizontalContentAlignment = HorizontalAlignment.Center,
        VerticalContentAlignment = VerticalAlignment.Center
      )
    let noButton =
      Button(Content = noStr,
             Width = 90.0,
             Margin = Thickness 4.0,
             HorizontalContentAlignment = HorizontalAlignment.Center,
             VerticalContentAlignment = VerticalAlignment.Center)
    yesButton.Click.Add(fun _ ->
      result <- true
      dialog.Close())
    noButton.Click.Add(fun _ -> dialog.Close())
    let buttons =
      StackPanel(
        Orientation = Orientation.Horizontal,
        HorizontalAlignment = HorizontalAlignment.Right,
        Margin = Thickness(12.0, 0.0, 12.0, 12.0)
      )
    buttons.Children.Add yesButton
    buttons.Children.Add noButton
    let panel = DockPanel()
    DockPanel.SetDock(buttons, Dock.Bottom)
    panel.Children.Add buttons
    panel.Children.Add message
    dialog.Content <- panel
    dialog.Closed.Add(fun _ -> if not result then () else fnOnYes ())
    dialog.ShowDialog owner |> ignore)