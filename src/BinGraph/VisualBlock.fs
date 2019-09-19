(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>

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

namespace B2R2.BinGraph

open B2R2

/// The basic term used to describe a line of a basic block (when visualized).
type Term =
  /// Address of a disassembled line.
  | Address of string
  /// Mneomonic, i.e., opcode.
  | Mnemonic of string
  /// Operand.
  | Operand of string
  /// Just a string.
  | String of string
  /// Comment.
  | Comment of string
with
  static member Width = function
    | Address (s)
    | Mnemonic (s)
    | Operand (s)
    | String (s)
    | Comment (s) -> s.Length

  static member ToString = function
    | Address (s)
    | Mnemonic (s)
    | Operand (s)
    | String (s)
    | Comment (s) -> s

  static member ToStringTuple = function
    | Address (s) -> s, "address"
    | Mnemonic (s) -> s, "menmonic"
    | Operand (s) -> s, "operand"
    | String (s) -> s, "string"
    | Comment (s) -> s, "comment"

/// A visual line of a basic block.
type VisualLine = Term list

module VisualLine =
  [<CompiledName("LineWidth")>]
  let lineWidth terms =
    (* Assume that each term is separated by a space char (+1). *)
    terms |> List.fold (fun width term -> width + Term.Width term + 1) 0

  [<CompiledName("ToString")>]
  let toString terms =
    terms |> List.map Term.ToString |> String.concat " "

/// A visual representation of a basic block.
type VisualBlock = VisualLine list

module VisualBlock =
  let empty (addr: Addr): VisualBlock =
    [ [String ("# fake block @ " + (addr.ToString ("X")))] ]
