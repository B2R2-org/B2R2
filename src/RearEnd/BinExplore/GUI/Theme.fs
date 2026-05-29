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
    Panel: PanelTheme
    Text: TextTheme
    Font: FontTheme
    Tab: TabTheme
    Graph: GraphTheme
    Linear: LinearTheme
    Hex: HexTheme
    Common: CommonTheme
    Menu: MenuTheme
    Toolbar: ToolbarTheme
    Search: SearchTheme
    StatusBar: StatusBarTheme }

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
  { StripBackground: string
    ActiveBackground: string
    InactiveBackground: string
    ActiveForeground: string
    InactiveForeground: string
    Border: string
    CloseForeground: string }

/// Represents the theme settings for graph elements within the application.
and GraphTheme =
  { Background: string
    MinimapNode: string
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

/// Represents the theme settings for the linear view.
and LinearTheme =
  { Background: string
    SectionHeaderBackground: string
    FunctionHeaderBackground: string
    LinkageTableHeaderBackground: string
    HeaderBorder: string }

/// Represents the theme settings for the hexdump view.
and HexTheme =
  { CodeArea: string
    LinkageArea: string
    ReadOnlyDataArea: string
    WritableDataArea: string
    ExceptionArea: string
    MetadataArea: string }

/// Represents common theme settings that can be used across different UI
/// elements.
and CommonTheme =
  { Transparent: string }

/// Represents the theme settings for the menu bar.
and MenuTheme =
  { Background: string
    Foreground: string
    ItemBackground: string
    ItemForeground: string }

/// Represents the theme settings for the toolbar.
and ToolbarTheme =
  { Background: string
    Border: string
    ControlBackground: string
    ControlForeground: string
    ControlBorder: string
    ActiveControlBackground: string
    Separator: string }

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

/// Represents the theme settings for the status bar.
and StatusBarTheme =
  { Background: string
    Foreground: string
    PrimaryForeground: string
    MutedForeground: string
    HighlightForeground: string
    Separator: string }

[<RequireQualifiedAccess>]
module Theme =
  let [<Literal>] private DefaultTTFamily =
    "avares://B2R2.RearEnd.BinExplore/Assets/Fonts#Inconsolata"

  let private defaultTTFont =
    { FontFamily = DefaultTTFamily
      FontSize = 12.0 }

  let darkTheme =
    { Name = "Dark"
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
        { StripBackground = "#2D2D30"
          ActiveBackground = "#1E1E1E"
          InactiveBackground = "#2D2D30"
          ActiveForeground = "#FFFFFF"
          InactiveForeground = "#AAAAAA"
          Border = "#3E3E42"
          CloseForeground = "#AAAAAA" }
      Graph =
        { Background = "#1E1E1E"
          MinimapNode = "#888888"
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
      Linear =
        { Background = "#1E1E1E"
          SectionHeaderBackground = "#2D2D30"
          FunctionHeaderBackground = "#252526"
          LinkageTableHeaderBackground = "#1E1E1E"
          HeaderBorder = "#3E3E42" }
      Hex =
        { CodeArea = "#001155"
          LinkageArea = "#770055"
          ReadOnlyDataArea = "#338822"
          WritableDataArea = "#117777"
          ExceptionArea = "#997711"
          MetadataArea = "#555555" }
      Common =
        { Transparent = "Transparent" }
      Menu =
        { Background = "#2D2D30"
          Foreground = "#FFFFFF"
          ItemBackground = "#2D2D30"
          ItemForeground = "#FFFFFF" }
      Toolbar =
        { Background = "#2D2D30"
          Border = "#3E3E42"
          ControlBackground = "#252526"
          ControlForeground = "#FFFFFF"
          ControlBorder = "#3E3E42"
          ActiveControlBackground = "#1E1E1E"
          Separator = "#3E3E42" }
      Search =
        { Background = "#080C12"
          SelectedBackground = "#3366AA"
          Foreground = "#FFFFFF"
          ClearForeground = "#E05A5A" }
      StatusBar =
        { Background = "#2D2D30"
          Foreground = "#AAAAAA"
          PrimaryForeground = "#FFFFFF"
          MutedForeground = "#A0A0A0"
          HighlightForeground = "#55CCFF"
          Separator = "#AAAAAA" } }

  let lightTheme =
    { Name = "Light"
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
        { StripBackground = "#ECECEC"
          ActiveBackground = "#FFFFFF"
          InactiveBackground = "#E6E6E6"
          ActiveForeground = "#111111"
          InactiveForeground = "#555555"
          Border = "#CFCFCF"
          CloseForeground = "#666666" }
      Graph =
        { Background = "#F3F3F3"
          MinimapNode = "#AAAAAA"
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
      Linear =
        { Background = "#F3F3F3"
          SectionHeaderBackground = "#ECECEC"
          FunctionHeaderBackground = "#FFFFFF"
          LinkageTableHeaderBackground = "#F3F3F3"
          HeaderBorder = "#CFCFCF" }
      Hex =
        { CodeArea = "#A9CCFF"
          LinkageArea = "#E2C8FF"
          ReadOnlyDataArea = "#C9F5A8"
          WritableDataArea = "#9EEAF9"
          ExceptionArea = "#FFB347"
          MetadataArea = "#DDDDDD" }
      Common =
        { Transparent = "Transparent" }
      Menu =
        { Background = "#ECECEC"
          Foreground = "#111111"
          ItemBackground = "#ECECEC"
          ItemForeground = "#111111" }
      Toolbar =
        { Background = "#ECECEC"
          Border = "#CFCFCF"
          ControlBackground = "#FFFFFF"
          ControlForeground = "#111111"
          ControlBorder = "#CFCFCF"
          ActiveControlBackground = "#FFFFFF"
          Separator = "#CFCFCF" }
      Search =
        { Background = "#FFFFFF"
          SelectedBackground = "#BEE3FF"
          Foreground = "#111111"
          ClearForeground = "#C42B1C" }
      StatusBar =
        { Background = "#ECECEC"
          Foreground = "#555555"
          PrimaryForeground = "#111111"
          MutedForeground = "#707070"
          HighlightForeground = "#EE0055"
          Separator = "#555555" } }

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
