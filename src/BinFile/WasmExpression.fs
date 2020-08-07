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

module internal B2R2.BinFile.Wasm.Expression

open B2R2
open B2R2.BinFile
open System

let peekConstExpr (reader: BinReader) offset =
  let evt =
    reader.PeekUInt8 offset
    |> LanguagePrimitives.EnumOfValue
  let offset' = offset + 1
  match evt with
  | ConstExprValueType.i32 ->
    let v, len = reader.PeekUInt32LEB128 offset'
    I32 (v), offset' + len + 1
  | ConstExprValueType.i64 ->
    let v, len = reader.PeekUInt64LEB128 offset'
    I64 (v), offset' + len + 1
  | ConstExprValueType.f32 ->
    let b = reader.PeekBytes (4, offset')
    let v = BitConverter.ToSingle (b, 0)
    F32 (v), offset' + 4 + 1
  | ConstExprValueType.f64 ->
    let b = reader.PeekBytes (8, offset')
    let v = BitConverter.ToDouble (b, 0)
    F64 (v), offset' + 8 + 1
  | _ -> raise InvalidFileTypeException