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

/// A set of convenient misc. functions.
module B2R2.Utils

/// Not implemented features encountered, so raise an exception and die.
val futureFeature: unit -> 'a

/// Fatal error. This should never happen.
val impossible: unit -> 'a

/// Exit the whole program with a fatal error message.
val fatalExit: string -> 'a

/// Physical equality.
val inline (===) : 'a -> 'a -> bool when 'a : not struct

/// Convert a tuple result to an option type. The tuple result is obtained from
/// TryGetValue methods, e.g., from IDictionary.
val inline tupleResultToOpt: bool * 'a -> 'a option

/// Return the first item of a triple.
val inline fstOfTriple: ('a * 'b * 'c) -> 'a

/// Return the second item of a triple.
val inline sndOfTriple: ('a * 'b * 'c) -> 'b

/// Return the third item of a triple.
val inline thdOfTriple: ('a * 'b * 'c) -> 'c
