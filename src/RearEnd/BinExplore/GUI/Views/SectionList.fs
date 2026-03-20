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

[<RequireQualifiedAccess>]
module B2R2.RearEnd.BinExplore.GUI.SectionList

open Avalonia.Controls
open Avalonia.Layout
open Avalonia.Media
open Avalonia.FuncUI
open Avalonia.FuncUI.DSL
open Avalonia.FuncUI.Types
open B2R2.FrontEnd.BinFile

let private panelHeaderView model =
  Border.create [
    Border.dock Dock.Top
    Border.background model.Theme.Panel.AltBackground
    Border.padding 8.0
    Border.child (
      Grid.create [
        Grid.columnDefinitions "*,Auto"
        Grid.children [
          TextBlock.create [
            TextBlock.text "Sections"
            TextBlock.fontSize 13.0
            TextBlock.foreground model.Theme.Text.Secondary
          ]
          TextBlock.create [
            Grid.column 1
            TextBlock.text $"({List.length model.Sections})"
            TextBlock.fontSize 12.0
            TextBlock.foreground model.Theme.Text.Muted
            TextBlock.verticalAlignment VerticalAlignment.Center
          ]
        ]
      ]
    )
  ]

let private emptyStateView model =
  TextBlock.create [
    TextBlock.text "No sections loaded."
    TextBlock.margin 10.0
    TextBlock.foreground model.Theme.Text.Muted
    TextBlock.fontSize 13.0
  ]

let private sectionAddressText (section: SectionItem) =
  $"0x{section.Address:X}"

let private sectionItemHeaderText model (section: SectionItem) =
  Grid.create [
    Grid.columnDefinitions "*,Auto"
    Grid.margin (4.0, 0.0)
    Grid.children [
      TextBlock.create [
        TextBlock.text section.Name
        TextBlock.foreground model.Theme.Text.Primary
        TextBlock.fontFamily model.Theme.Font.Monospace.FontFamily
        TextBlock.fontSize 13.0
        TextBlock.fontWeight FontWeight.SemiBold
      ]
      TextBlock.create [
        Grid.column 1
        TextBlock.margin (4.0, 0.0, 0.0, 0.0)
        TextBlock.text (sectionAddressText section)
        TextBlock.foreground model.Theme.Text.Muted
        TextBlock.fontFamily model.Theme.Font.Monospace.FontFamily
        TextBlock.fontSize 12.0
        TextBlock.verticalAlignment VerticalAlignment.Center
      ]
    ]
  ]

let private sectionItemHeaderView model section (isExpanded: IWritable<bool>) =
  Button.create [
    Button.background model.Theme.Common.Transparent
    Button.foreground model.Theme.Text.Primary
    Button.borderThickness 0.0
    Button.padding (8.0, 6.0)
    Button.horizontalContentAlignment HorizontalAlignment.Stretch
    Button.content (
      Grid.create [
        Grid.columnDefinitions "Auto,*,Auto"
        Grid.children [
          TextBlock.create [
            TextBlock.text (if isExpanded.Current then "▼" else "▶")
            TextBlock.margin (0.0, 0.0, 8.0, 0.0)
            TextBlock.foreground model.Theme.Text.Muted
            TextBlock.fontSize 11.0
            TextBlock.verticalAlignment VerticalAlignment.Center
          ]
          Grid.create [
            Grid.column 1
            Grid.children [ sectionItemHeaderText model section ]
          ]
        ]
      ]
    )
    Button.onClick (fun _ -> isExpanded.Set(not isExpanded.Current))
  ]

let private detailRow model label value =
  DockPanel.create
    [
      DockPanel.lastChildFill true
      DockPanel.children
        [
          TextBlock.create [
            TextBlock.dock Dock.Left
            TextBlock.width 72.0
            TextBlock.text label
            TextBlock.foreground model.Theme.Text.Secondary
            TextBlock.fontSize 12.0
          ]
          TextBlock.create [
            TextBlock.text value
            TextBlock.foreground model.Theme.Text.Primary
            TextBlock.fontFamily model.Theme.Font.Monospace.FontFamily
            TextBlock.fontSize 12.0
          ]
        ]
    ]

let private detailContent model (content: SectionContent) =
  match content with
  | ELF sh ->
    let flags = ELF.SectionFlags.toList sh.SecFlags |> String.concat ", "
    let offset = $"0x{sh.SecOffset:x}"
    let size = $"0x{sh.SecSize:x}"
    let entSize = $"0x{sh.SecEntrySize:x}"
    let link = $"{sh.SecLink}"
    let info = $"{sh.SecInfo}"
    let align = $"0x{sh.SecAlignment:x}"
    [ detailRow model "Offset" offset :> IView
      detailRow model "Size" size
      detailRow model "Entry Size" entSize
      detailRow model "ELF Flags" flags
      detailRow model "Link" link
      detailRow model "Info" info
      detailRow model "Alignment" align ]
  | Empty -> []

let private sectionItemDetailView (model: Model) (section: SectionItem) =
  Border.create [
    Border.margin (18.0, 6.0, 4.0, 10.0)
    Border.padding 10.0
    Border.background model.Theme.Panel.AltBackground
    Border.borderThickness 1.0
    Border.borderBrush model.Theme.Panel.Border
    Border.cornerRadius 4.0
    Border.child (
      StackPanel.create [
        StackPanel.spacing 4.0
        StackPanel.children [
          detailRow model "Name" section.Name
          detailRow model "Address" (sectionAddressText section)
          yield! detailContent model section.Content
        ]
      ]
    )
  ]

let private sectionItemView (model: Model) (section: SectionItem) =
  Component.create ($"section-item-{section.Address:X}", fun ctx ->
    let isExpanded = ctx.useState false
    Border.create [
      Border.borderThickness (0.0, 0.0, 0.0, 1.0)
      Border.borderBrush model.Theme.Panel.Border
      Border.padding (4.0, 0.0)
      Border.child (
        StackPanel.create [
          StackPanel.children [
            sectionItemHeaderView model section isExpanded
            if isExpanded.Current then sectionItemDetailView model section
            else ()
          ]
        ]
      )
    ]
  )

let private listBodyView model =
  ScrollViewer.create [
    ScrollViewer.content (
      if List.isEmpty model.Sections then
        emptyStateView model :> IView
      else
        StackPanel.create [
          StackPanel.children (
            model.Sections
            |> List.map (fun section ->
              sectionItemView model section)
          )
        ]
    )
  ]

let view model _dispatch =
  Border.create [
    Border.background model.Theme.Panel.Background
    Border.borderThickness 1.0
    Border.borderBrush model.Theme.Panel.Border
    Border.child (
      DockPanel.create [
        DockPanel.children [
          panelHeaderView model
          listBodyView model
        ]
      ]
    )
  ]
