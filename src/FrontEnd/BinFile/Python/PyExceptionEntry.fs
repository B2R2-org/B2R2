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

namespace B2R2.FrontEnd.BinFile.Python

open B2R2

/// Represents one entry of a Python exception table (`co_exceptiontable`),
/// i.e., one guarded range of bytecode, the handler it dispatches to, and the
/// value-stack state that handler is entered with. Python 3.11 replaced the
/// run-time block stack with this table (zero-cost exceptions), so a code
/// object older than that has no entries at all.
type PyExceptionEntry =
  { /// Start address of the guarded range (inclusive).
    Start: Addr
    /// End address of the guarded range (inclusive). CPython stores a length
    /// instead, i.e., an exclusive end; this is that end minus one, so the
    /// range reads the way every other range in B2R2 does. Note that CPython's
    /// own `dis` prints the exclusive end here, which is therefore one more
    /// than this.
    End: Addr
    /// Address of the handler this range transfers control to. Unlike a
    /// BinExceptionHandler's own target this is never absent: the entry exists
    /// precisely because there is somewhere to go.
    Target: Addr
    /// Value-stack depth the handler is entered at: the interpreter pops the
    /// stack down to this many entries first. Nothing else says what the
    /// handler block's own entry state is, which is why this type exists
    /// beside the format-agnostic BinExceptionHandler rather than instead of
    /// it.
    Depth: int
    /// Whether the offset of the instruction that raised is pushed (underneath
    /// the exception itself) before the handler is entered, which a re-raising
    /// handler needs in order to say where the exception came from. One more
    /// stack slot on entry when it is set.
    PushLasti: bool }
