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

namespace B2R2.RearEnd

open System

/// Define a column of a table with a specified width in bytes (# of chars).
type TableColumn =
  | RightAligned of width: int
  | LeftAligned of width: int
with
  static member ofPaddedString isLast (s: string) = function
    | RightAligned w -> let s = s.PadLeft (w) in if isLast then s else s + " "
    | LeftAligned w -> if isLast then s else s.PadRight (w) + " "

/// Define a output configuration of a table.
type TableConfig = TableColumn list

/// Our rear-end applications should *not* use System.Console or `printfn` to
/// directly output strings. Instead, they should resort to Printer to
/// "indirectly" print out strings to console.
type Printer =
  [<CompiledName "Print">]
  static member print s =
    OutString.toConsole s

  [<CompiledName "Print">]
  static member print s =
    ColoredString.toConsole s

  [<CompiledName "Print">]
  static member print (s: string, [<ParamArray>] args) =
    Console.Write (s, args)

  [<CompiledName "PrintLine">]
  static member println s =
    OutString.toConsoleLine s

  [<CompiledName "PrintLine">]
  static member println s =
    ColoredString.toConsoleLine s

  [<CompiledName "PrintLine">]
  static member println (s: string, [<ParamArray>] args) =
    Console.WriteLine (s, args)

  [<CompiledName "PrintLine">]
  static member println () =
    Console.WriteLine ()

  [<CompiledName "PrintRow">]
  static member printrow indent (cfg: TableConfig) (strs: string list) =
    let lastIdx = List.length cfg - 1
    List.zip cfg strs
    |> List.iteri (fun i (c, s) ->
      if indent then
        Console.Write ("  ")
      Console.Write (TableColumn.ofPaddedString (i = lastIdx) s c))
    Console.WriteLine ()

module CS = ColoredSegment

module Printer =
  let [<Literal>] private colWidth = 24

  let printSectionTitle title =
    [ CS.red "# "; CS.nocolor title ]
    |> Printer.println
    Printer.println ()

  let printSubsectionTitle (str: string) =
    Printer.println ("    - " + str)

  let printSubsubsectionTitle (str: string) =
    Printer.println ("         * " + str)

  let printTwoCols (col1: string) (col2: string) =
    Printer.print (col1.PadLeft colWidth + " ")
    Printer.println col2

  /// Print a two-column row while highlighting the second col.
  let printTwoColsHi (col1: string) (col2: string) =
    Printer.print (col1.PadLeft colWidth + " ")
    Printer.println [ CS.green col2 ]

  /// Print a two-column row where the second column is represented as a
  /// ColoredString.
  let printTwoColsWithCS (col1: string) (col2: ColoredString) =
    Printer.print (col1.PadLeft colWidth + " ")
    Printer.println col2

  let printError str =
    [ CS.nocolor "[*] Error: "; CS.red str ] |> Printer.println
    Printer.println ()
