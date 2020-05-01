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

module B2R2.Utilities.Repl.Display

open System

let private cprintf c fmt =
  Printf.kprintf (fun s ->
    let old = Console.ForegroundColor
    try
      Console.ForegroundColor <- c;
      Console.Write s
    finally
      Console.ForegroundColor <- old) fmt

let printRed str = cprintf ConsoleColor.Red str
let printBlue str = cprintf ConsoleColor.Blue str
let printCyan str = cprintf ConsoleColor.Cyan str
let printGray str = cprintf ConsoleColor.Gray str

/// Prints all the registers and their statuses to the console.
let private printRegStatusString (state: ReplState) delta =
  state.GetAllRegValString delta
  |> List.iteri (fun idx (s, changed) ->
    let p = if changed then printRed else printGray
    if idx % 3 = 2 then p "%-34s\n" s else p "%-34s" s)

/// Prints all the temporary registers and their statuses to the console.
let private printTRegStatusString (state: ReplState) delta =
  state.GetAllTempValString delta
  |> List.iteri (fun idx (s, changed) ->
    let p = if changed then printRed else printGray
    if idx % 3 = 2 then p "%-34s\n" s else p "%-34s" s)

/// Used to print all available registers to the console.
let printRegisters showTemporary state regdelta =
  printCyan "Registers:\n" ;
  printRegStatusString state regdelta
  if showTemporary then
    printCyan "\nTemporary Registers:\n"
    printTRegStatusString state []
  else ()
  Console.WriteLine ()
