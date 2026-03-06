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

/// Represents messages that can be sent to the main view.
type Message =
  /// Message to open a binary file, carrying the file path.
  | OpenBinary of string
  /// Message to close the currently loaded binary file.
  | CloseBinary
  /// Message to open a new tab for a specific function.
  | OpenTab of string
  /// Message to pin a tab, making it persist.
  | PinTab of string
  /// Message to close a specific tab.
  | CloseTab of string
  /// Message to switch to a specific tab, making it active.
  | SwitchTab of string
  /// Message to update function filter text.
  | UpdateFunctionFilter of string
  /// Message to update the status message in the status bar.
  | UpdateStatus of string
  /// Message to exit the application.
  | ExitApplication
