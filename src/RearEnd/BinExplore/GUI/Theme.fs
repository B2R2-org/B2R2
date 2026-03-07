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
    Highlight: string }

/// Represents the font settings used in the application.
and FontTheme =
  { FunctionText: string }

/// Represents the theme settings for tabs within the application.
and TabTheme =
  { ActiveBackground: string
    InactiveBackground: string
    CloseForeground: string }

/// Represents common theme settings that can be used across different UI
/// elements.
and CommonTheme =
  { Transparent: string }

[<RequireQualifiedAccess>]
module Theme =
  let private defaultFunctionTextFont =
    "avares://B2R2.RearEnd.BinExplore/Assets/Fonts#Inconsolata"

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
          Highlight = "#55CCFF" }
      Font =
        { FunctionText = defaultFunctionTextFont }
      Tab =
        { ActiveBackground = "#1E1E1E"
          InactiveBackground = "#2D2D30"
          CloseForeground = "#AAAAAA" }
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
          Highlight = "#EE0055" }
      Font =
        { FunctionText = defaultFunctionTextFont }
      Tab =
        { ActiveBackground = "#FFFFFF"
          InactiveBackground = "#E6E6E6"
          CloseForeground = "#666666" }
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
