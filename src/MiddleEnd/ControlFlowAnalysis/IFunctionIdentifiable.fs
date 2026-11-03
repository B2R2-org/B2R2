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

namespace B2R2.MiddleEnd.ControlFlowAnalysis

open B2R2

/// Represents a function identification strategy. This is used to find
/// candidate functions to analyze.
type IFunctionIdentifiable =
  /// Finds a list of candidate functions to analyze. It returns a list of
  /// addresses of the candidate functions.
  abstract Identify: unit -> Addr[]

/// Represents a function identification strategy that also finds functions in
/// what the recovery has built, such as those that only a pointer leads to.
/// The recovery holds back its gap analysis until this finds no more, since a
/// gap may hold a function yet to be found.
and IIncrementalFunctionIdentifiable =
  inherit IFunctionIdentifiable

  /// Finds more candidate functions in the given functions, which the recovery
  /// has built from every candidate found so far, along with the external
  /// functions it knows of. It returns their addresses, in the form that
  /// Identify does, and an empty array once it finds no more. The functions
  /// are valid only during the call.
  abstract IdentifyMore: recovered: Function[] -> Addr[]