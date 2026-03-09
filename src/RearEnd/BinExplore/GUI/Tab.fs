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

open B2R2
open B2R2.RearEnd.Visualization

/// Represents a tab in the UI.
type Tab =
  { /// The unique identifier of the tab.
    ID: string
    /// The title of the tab displayed in the UI.
    Title: string
    /// The content of the tab.
    Content: TabContent }

/// Represents the content of a tab.
and TabContent =
  /// A tab displaying the control flow graph of a function.
  | CFGTab of FunctionItem * TabContentState<VisGraph * CFGViewState>
  /// A tab displaying the hexadecimal view of a specific address.
  | HexTab of baseAddr: Addr
  /// A tab displaying sections of the binary.
  | SectionTab

/// Represents the loading state of a tab's content, which can be not loaded,
/// currently loading, or fully loaded with the content of type 'T.
and TabContentState<'T> =
  | NotLoaded
  | Loading
  | Loaded of 'T

[<RequireQualifiedAccess>]
module Tab =

  /// Creates a new Tab instance for a given FunctionItem, with the content set
  /// to a CFGTab.
  let ofFunctionItem func =
    { ID = $"fn-{func.FuncID}"
      Title = func.Name
      Content = CFGTab(func, NotLoaded) }
