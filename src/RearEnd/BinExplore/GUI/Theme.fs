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
    Muted: string }

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
  let defaultTheme =
    { Name = "Dark"
      Window = { Background = "#1E1E1E" }
      Panel =
        { Background = "#252526"
          AltBackground = "#2D2D30"
          Border = "#3E3E42" }
      Text =
        { Primary = "#FFFFFF"
          Secondary = "#AAAAAA"
          Muted = "#A0A0A0" }
      Tab =
        { ActiveBackground = "#1E1E1E"
          InactiveBackground = "#2D2D30"
          CloseForeground = "#AAAAAA" }
      Common = { Transparent = "Transparent" } }
