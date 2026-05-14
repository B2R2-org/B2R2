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

namespace B2R2.MiddleEnd.SymEval

open System
open System.Text
open B2R2

/// Provides typed accessors over solver-returned symbolic values.
type SymModel(values: SolverValue list) =
  /// Raw solver values.
  member _.Values = values

  /// Finds a solver value by symbolic variable name.
  member _.TryGetValue name =
    values
    |> List.tryFind (fun value -> value.Name = name)
    |> Option.map (fun value -> value.Value)

  /// Gets a solver value by symbolic variable name.
  member this.GetValue name =
    match this.TryGetValue name with
    | Some value -> value
    | None ->
      raise (InvalidOperationException $"Solver value {name} is missing.")

  /// Gets an 8-bit solver value by symbolic variable name.
  member this.GetByte name =
    this.GetValue name |> BitVector.ToUInt64 |> byte

  /// Gets an 8-bit solver value for a symbolic byte expression.
  member this.GetByte expr =
    match expr with
    | SymExpr.Var(name, _) -> this.GetByte name
    | expr ->
      raise (InvalidOperationException $"Unexpected query value: {expr}.")

  /// Reads bytes from symbolic byte expressions.
  member this.ReadBytes(values: seq<SymExpr>) =
    values
    |> Seq.map this.GetByte
    |> Seq.toArray

  /// Reads bytes from a symbolic byte buffer.
  member this.ReadBytes(buffer: SymByteBuffer) =
    buffer.Values
    |> this.ReadBytes

  /// Reads a null-terminated ASCII string from symbolic byte expressions.
  member this.ReadCString(values: seq<SymExpr>) =
    this.ReadBytes values
    |> Array.takeWhile ((<>) 0uy)
    |> Encoding.ASCII.GetString

  /// Reads a null-terminated ASCII string from a symbolic byte buffer.
  member this.ReadCString(buffer: SymByteBuffer) =
    buffer.Values
    |> this.ReadCString
