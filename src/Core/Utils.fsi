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

/// A set of convenient misc. functions.
module B2R2.Utils

/// Assert two values are equal. If not, raise an exception (exn).
val assertEqual<'a when 'a : equality> : 'a -> 'a -> exn -> unit

/// Assert check condition. If not, raise an exception (exn).
val assertByCond: condition: bool -> exn -> unit

/// Not implemented features encountered, so raise an exception and die.
val futureFeature: unit -> 'a

/// Apply a procedure in the middle of function pipes.
val inline tap : ('a -> unit) -> 'a -> 'a

/// Curry a pair of arguments.
val inline curry : ('a * 'b -> 'c) -> 'a -> 'b -> 'c

/// Uncurry a pair of arguments.
val inline uncurry : ('a -> 'b -> 'c) -> 'a * 'b -> 'c

/// Physical equality.
val inline (===) : 'a -> 'a -> bool when 'a : not struct

/// Convert a tuple result to an option type. The tuple result is obtained from
/// the TryGetValue pattern, e.g., IDictionary.
val inline tupleToOpt: bool * 'a -> 'a option

/// Write B2R2 logo to console. We can selectively append a new line at the end.
val writeB2R2: newLine: bool -> unit
