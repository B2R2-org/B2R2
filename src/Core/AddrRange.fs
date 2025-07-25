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

/// Raised when two address ranges overlap in an ARMap, which does not allow
/// overlapping intervals.
exception RangeOverlapException

/// Raised when creating/handling AddrRange that has wrong interval, i.e., Min
/// value is larger than Max value.
exception InvalidAddrRangeException

type AddrRange =
  val Min: Addr
  val Max: Addr

  new (min, max) =
    if min > max then raise InvalidAddrRangeException else ()
    { Min = min; Max = max }

  new (addr) =
    { Min = addr; Max = addr }

  override this.ToString () =
    $"{this.Min:x} -- {this.Max:x}"

  override this.Equals (rhs: obj) =
    match rhs with
    | :? AddrRange as r -> this.Min = r.Min && this.Max = r.Max
    | _ -> raise InvalidAddrRangeException

  override this.GetHashCode () =
    hash (this.Min, this.Max)

  member this.Count with get() = this.Max - this.Min + 1UL

  member this.ToTuple () =
    this.Min, this.Max

  member this.Slice (target: AddrRange) =
    let l = max this.Min target.Min
    let h = min this.Max target.Max
    AddrRange (l, h)

  /// Check if the address range is including the given address.
  member inline this.IsIncluding (addr: Addr) =
    this.Min <= addr && addr <= this.Max

  static member inline GetMin (range: AddrRange) = range.Min

  static member inline GetMax (range: AddrRange) = range.Max

// vim: set tw=80 sts=2 sw=2:
