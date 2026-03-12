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
    Common: CommonTheme }

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
  { Function: FontStyle
    Disassembly: FontStyle }

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
  { InterJmpEdge: string
    InterCJmpTrue: string
    InterCJmpFalse: string
    IntraJmpEdge: string
    IntraCJmpTrue: string
    IntraCJmpFalse: string
    Fallthrough: string
    Call: string
    Return: string }

/// Represents common theme settings that can be used across different UI
/// elements.
and CommonTheme =
  { Transparent: string }

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
        { Function = defaultTTFont
          Disassembly = defaultTTFont }
      Tab =
        { ActiveBackground = "#1E1E1E"
          InactiveBackground = "#2D2D30"
          CloseForeground = "#AAAAAA" }
      Graph =
        { InterJmpEdge = "#FFB86C"
          InterCJmpTrue = "#3E9955"
          InterCJmpFalse = "#AA2222"
          IntraJmpEdge = "#FFB86C"
          IntraCJmpTrue = "#3E9955"
          IntraCJmpFalse = "#AA2222"
          Fallthrough = "#BD93F9"
          Call = "#8BE9FD"
          Return = "#FF79C6" }
      Common = { Transparent = "Transparent" } }

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
        { Function = defaultTTFont
          Disassembly = defaultTTFont }
      Tab =
        { ActiveBackground = "#FFFFFF"
          InactiveBackground = "#E6E6E6"
          CloseForeground = "#666666" }
      Graph =
        { InterJmpEdge = "#C87020"
          InterCJmpTrue = "#1A7A3A"
          InterCJmpFalse = "#CC2222"
          IntraJmpEdge = "#C87020"
          IntraCJmpTrue = "#1A7A3A"
          IntraCJmpFalse = "#CC2222"
          Fallthrough = "#7336B5"
          Call = "#0A6080"
          Return = "#8B2880" }
      Common = { Transparent = "Transparent" } }

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
