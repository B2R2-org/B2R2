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

/// Represents the theme settings for the application, including colors for
/// various UI elements.
type Theme =
  { Name: string
    Window: WindowTheme
    Panel: PanelTheme
    Text: TextTheme
    Font: FontTheme
    Tab: TabTheme
    Graph: GraphTheme
    Common: CommonTheme
    Search: SearchTheme }

/// Represents the theme settings for the main window.
and WindowTheme =
  { Background: string }

/// Represents the theme settings for panels within the application.
and PanelTheme =
  { Background: string
    AltBackground: string
    Border: string }

/// Represents the theme settings for text elements within the application.
and TextTheme =
  { Primary: string
    Secondary: string
    Muted: string
    Highlight: string
    Address: string
    Mnemonic: string
    Variable: string
    Value: string }

/// Represents the font settings used in the application.
and FontTheme =
  { Monospace: FontStyle }

/// Represents a font style.
and FontStyle =
  { FontFamily: string
    FontSize: float }

/// Represents the theme settings for tabs within the application.
and TabTheme =
  { ActiveBackground: string
    InactiveBackground: string
    CloseForeground: string }

/// Represents the theme settings for graph elements within the application.
and GraphTheme =
  { MinimapNode: string
    MinimapEdge: string
    ViewportRect: string
    InterJmpEdge: string
    InterCJmpTrueEdge: string
    InterCJmpFalseEdge: string
    IntraJmpEdge: string
    IntraCJmpTrueEdge: string
    IntraCJmpFalseEdge: string
    FallthroughEdge: string
    CallEdge: string
    ReturnEdge: string
    HoveredEdge: string }

/// Represents common theme settings that can be used across different UI
/// elements.
and CommonTheme =
  { Transparent: string }

/// Represents the theme settings for the search dropdown in the toolbar.
and SearchTheme =
  { /// Background color of the dropdown panel.
    Background: string
    /// Background color of the currently selected/highlighted result item.
    SelectedBackground: string
    /// Foreground color of the result text.
    Foreground: string
    /// Foreground color of the clear-search button.
    ClearForeground: string }

[<RequireQualifiedAccess>]
module Theme =
  let [<Literal>] private DefaultTTFamily =
    "avares://B2R2.RearEnd.BinExplore/Assets/Fonts#Inconsolata"

  let private defaultTTFont =
    { FontFamily = DefaultTTFamily
      FontSize = 12.0 }

  let darkTheme =
    { Name = "Dark"
      Window = { Background = "#1E1E1E" }
      Panel =
        { Background = "#252526"
          AltBackground = "#2D2D30"
          Border = "#3E3E42" }
      Text =
        { Primary = "#FFFFFF"
          Secondary = "#AAAAAA"
          Muted = "#A0A0A0"
          Highlight = "#55CCFF"
          Address = "#99A0A0"
          Mnemonic = "#2CB174"
          Variable = "#9CDCFE"
          Value = "#CE9178" }
      Font =
        { Monospace = defaultTTFont }
      Tab =
        { ActiveBackground = "#1E1E1E"
          InactiveBackground = "#2D2D30"
          CloseForeground = "#AAAAAA" }
      Graph =
        { MinimapNode = "#888888"
          MinimapEdge = "#AAAAAA"
          ViewportRect = "#FFFFFF"
          InterJmpEdge = "#FFB86C"
          InterCJmpTrueEdge = "#3E9955"
          InterCJmpFalseEdge = "#AA2222"
          IntraJmpEdge = "#FFB86C"
          IntraCJmpTrueEdge = "#3E9955"
          IntraCJmpFalseEdge = "#AA2222"
          FallthroughEdge = "#BD93F9"
          CallEdge = "#8BE9FD"
          ReturnEdge = "#FF79C6"
          HoveredEdge = "#55CCFF" }
      Common = { Transparent = "Transparent" }
      Search =
        { Background = "#080C12"
          SelectedBackground = "#0E639C"
          Foreground = "#FFFFFF"
          ClearForeground = "#E05A5A" } }

  let lightTheme =
    { Name = "Light"
      Window = { Background = "#F3F3F3" }
      Panel =
        { Background = "#FFFFFF"
          AltBackground = "#ECECEC"
          Border = "#CFCFCF" }
      Text =
        { Primary = "#111111"
          Secondary = "#555555"
          Muted = "#707070"
          Highlight = "#EE0055"
          Address = "#607070"
          Mnemonic = "#0A7A4A"
          Variable = "#0000CC"
          Value = "#1A5090" }
      Font =
        { Monospace = defaultTTFont }
      Tab =
        { ActiveBackground = "#FFFFFF"
          InactiveBackground = "#E6E6E6"
          CloseForeground = "#666666" }
      Graph =
        { MinimapNode = "#AAAAAA"
          MinimapEdge = "#777777"
          ViewportRect = "#8A6A00"
          InterJmpEdge = "#C87020"
          InterCJmpTrueEdge = "#1A7A3A"
          InterCJmpFalseEdge = "#CC2222"
          IntraJmpEdge = "#C87020"
          IntraCJmpTrueEdge = "#1A7A3A"
          IntraCJmpFalseEdge = "#CC2222"
          FallthroughEdge = "#7336B5"
          CallEdge = "#0A6080"
          ReturnEdge = "#8B2880"
          HoveredEdge = "#0078FF" }
      Common = { Transparent = "Transparent" }
      Search =
        { Background = "#FFFFFF"
          SelectedBackground = "#BEE3FF"
          Foreground = "#111111"
          ClearForeground = "#C42B1C" } }

  let ofBuiltin = function
    | Dark -> darkTheme
    | Light -> lightTheme

  let defaultMode = Builtin Dark

  let defaultTheme = ofBuiltin Dark

  let resolve mode customThemes =
    match mode with
    | Builtin builtin ->
      ofBuiltin builtin
    | Custom themeId ->
      customThemes |> Map.tryFind themeId |> Option.defaultValue defaultTheme

  let modeName = function
    | Builtin Dark -> "Dark"
    | Builtin Light -> "Light"
    | Custom(ThemeId id) -> id
