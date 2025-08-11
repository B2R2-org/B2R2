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

namespace B2R2.FrontEnd.S390

/// Represents an instruction format used in S390 architecture.
type InstructionFormat =
  | E = 0
  | I = 1
  | IE = 2
  | MII = 3
  | RI = 4
  | RIE = 5
  | RIL = 6
  | RIS = 7
  | RR = 8
  | RRD = 9
  | RRE = 10
  | RRF = 11
  | RRS = 12
  | RS = 13
  | RSI = 14
  | RSL = 15
  | RSY = 16
  | RX = 17
  | RXE = 18
  | RXF = 19
  | RXY = 20
  | S = 21
  | SI = 22
  | SIL = 23
  | SIY = 24
  | SMI = 25
  | SS = 26
  | SSE = 27
  | SSF = 28
  | VRI = 29
  | VRR = 30
  | VRS = 31
  | VRV = 32
  | VRX = 33
  | VSI = 34
  | Invalid = 35

type internal Fmt = InstructionFormat
