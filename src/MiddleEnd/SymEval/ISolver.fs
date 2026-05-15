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

open B2R2

/// Represents the result of a solver satisfiability query.
type SolverStatus =
  | Sat
  | Unsat
  | Unknown

/// Represents a single value returned by a solver's value query.
type SolverValue =
  { Name: string
    Value: BitVector }

/// Represents a parsed solver response.
type SolverOutput =
  { Status: SolverStatus
    Values: SolverValue list }

/// Represents an SMT solver for symbolic path conditions.
type ISolver =
  /// Check whether the given SMT-LIB2 assertion script is satisfiable.
  abstract CheckSat: smt2: string -> Result<string, SymEvalError>

  /// Get a raw model for the given SMT-LIB2 assertion script.
  abstract GetModels: smt2: string -> Result<string, SymEvalError>
