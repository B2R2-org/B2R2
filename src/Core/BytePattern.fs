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

namespace B2R2

open System

/// Represents a byte pattern.
type BytePattern = ByteValue[]

and ByteValue =
  /// This matches any byte, i.e., it is like a kleene star.
  | AnyByte
  /// This matches only one single byte value.
  | OneByte of byte

[<RequireQualifiedAccess>]
module BytePattern =
  let private isEqual bv v =
    match bv with
    | AnyByte -> true
    | OneByte b -> b = v

  /// Check if the given byte array (bs) matches the pattern. The comparison
  /// starts at the very first byte of the arrays.
  [<CompiledName "Match">]
  let ``match`` (pattern: BytePattern) (bs: byte []) =
    let patternLen = Array.length pattern
    if patternLen > bs.Length then false
    else
      let bs = Array.sub bs 0 patternLen
      Array.forall2 isEqual pattern bs

  /// Check if the given span matches the pattern. The comparison starts at the
  /// offset zero.
  [<CompiledName "MatchSpan">]
  let matchSpan pattern (span: ReadOnlySpan<byte>) =
    let mutable matched = true
    let patternLen = Array.length pattern
    if patternLen > span.Length then false
    else
      for i in [ 0 .. patternLen - 1 ] do
        match pattern[i] with
        | AnyByte -> ()
        | OneByte b -> if span[i] = b then () else matched <- false
      done
      matched
