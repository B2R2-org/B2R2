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

namespace B2R2.BinCorpus

open B2R2

type IndirectBranchInfo = {
  /// The host function (owner) of the indirect jump.
  HostFunctionAddr: Addr
  /// Possible target addresses.
  TargetAddresses: Set<Addr>
  /// Information about the corresponding jump table (if exists).
  JumpTableInfo: JumpTableInfo option
}

/// Jump table (for switch-case) information.
and JumpTableInfo = {
  /// Base address of the jump table.
  JTBaseAddr: Addr
  /// The start and the end address of the jump table (AddrRange).
  JTRange: AddrRange
  /// Size of each entry of the table.
  JTEntrySize: RegType
}
with
  static member Init jtBase jtRange jtEntrySize =
    { JTBaseAddr = jtBase ; JTRange = jtRange ; JTEntrySize = jtEntrySize }

/// No-return function info.
type NoReturnInfo = {
  /// No-return function addresses.
  NoReturnFuncs: Set<Addr>
  /// Program points of no-return call sites.
  NoReturnCallSites: Set<ProgramPoint>
}
with
  static member Init noRetFuncs noRetCallSites =
    { NoReturnFuncs = noRetFuncs ; NoReturnCallSites = noRetCallSites }
