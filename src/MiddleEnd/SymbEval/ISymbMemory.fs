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

namespace B2R2.MiddleEnd.SymbEval

open B2R2
open B2R2.BinIR

/// Represents a symbolic memory used in the evaluation.
type ISymbMemory =
  /// Reads a symbolic byte from a concrete address.
  abstract ByteRead: Addr -> Result<SymbExpr, SymbEvalError>

  /// Store a symbolic byte at a concrete address.
  abstract ByteWrite: Addr * SymbExpr -> unit

  /// Loads a symbolic value from concrete addresses.
  abstract Load: Addr * Endian * RegType -> Result<SymbExpr, SymbEvalError>

  /// Store a symbolic value at concrete addresses.
  abstract Store: Addr * SymbExpr * Endian -> unit

  /// Return an independent copy of this memory object.
  abstract Clone: unit -> ISymbMemory

  /// Clears up the memory contents; make the whole memory empty.
  abstract Clear: unit -> unit

[<RequireQualifiedAccess>]
module internal SymbMemoryOperation =
  let private byteType = 8<rt>

  let private concat (lhs: SymbExpr) (rhs: SymbExpr) =
    match lhs, rhs with
    | Const lhs, Const rhs ->
      Const(BitVector.Concat(lhs, rhs))
    | _ ->
      let typ = lhs.Type + rhs.Type
      SymbExpr.binop BinOpType.CONCAT typ lhs rhs

  let private extractByte pos = function
    | Const bv -> Const(BitVector.Extract(bv, byteType, pos))
    | expr -> SymbExpr.extract expr byteType pos

  let private combineBytes = function
    | [] -> Error(UnsupportedOperation "Cannot load zero bytes from memory.")
    | byte :: bytes -> List.fold concat byte bytes |> Ok

  let load addr endian typ (mem: ISymbMemory) =
    let len = RegType.toByteWidth typ
    let bytes =
      [ 0 .. len - 1 ]
      |> List.fold (fun acc offset ->
        match acc with
        | Ok bytes ->
          mem.ByteRead(addr + uint64 offset)
          |> Result.map (fun byte -> byte :: bytes)
        | Error e -> Error e) (Ok [])
    match bytes with
    | Ok bytes ->
      let bytes =
        match endian with
        | Endian.Big -> List.rev bytes
        | _ -> bytes
      combineBytes bytes
    | Error e -> Error e

  let store addr (value: SymbExpr) endian (mem: ISymbMemory) =
    let len = RegType.toByteWidth value.Type
    for offset = 0 to len - 1 do
      let pos =
        match endian with
        | Endian.Big -> (len - offset - 1) * 8
        | _ -> offset * 8
      mem.ByteWrite(addr + uint64 offset, extractByte pos value)
