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

namespace B2R2.ABI

/// Represents a specific Windows build. Windows system-call numbers change
/// from build to build, so a build must be selected to resolve a
/// WindowsSyscall to its number. The enum value is an arbitrary index (build
/// numbers are not unique across service packs, so they cannot be used).
type WindowsBuild =
  /// Windows NT 3.x (3.1).
  | WinNT31 = 0
  /// Windows NT 3.x (3.5).
  | WinNT35 = 1
  /// Windows NT 3.x (3.51).
  | WinNT351 = 2
  /// Windows NT 4.0 (SP0).
  | WinNT4_SP0 = 3
  /// Windows NT 4.0 (SP1).
  | WinNT4_SP1 = 4
  /// Windows NT 4.0 (SP2).
  | WinNT4_SP2 = 5
  /// Windows NT 4.0 (SP3).
  | WinNT4_SP3 = 6
  /// Windows NT 4.0 (SP3 TSE).
  | WinNT4_SP3TSE = 7
  /// Windows NT 4.0 (SP4).
  | WinNT4_SP4 = 8
  /// Windows NT 4.0 (SP5).
  | WinNT4_SP5 = 9
  /// Windows NT 4.0 (SP6).
  | WinNT4_SP6 = 10
  /// Windows 2000 (SP0).
  | Win2000_SP0 = 11
  /// Windows 2000 (SP1).
  | Win2000_SP1 = 12
  /// Windows 2000 (SP2).
  | Win2000_SP2 = 13
  /// Windows 2000 (SP3).
  | Win2000_SP3 = 14
  /// Windows 2000 (SP4).
  | Win2000_SP4 = 15
  /// Windows XP (SP0).
  | WinXP_SP0 = 16
  /// Windows XP (SP1).
  | WinXP_SP1 = 17
  /// Windows XP (SP2).
  | WinXP_SP2 = 18
  /// Windows XP (SP3).
  | WinXP_SP3 = 19
  /// Windows Server 2003 (SP0).
  | WinSrv2003_SP0 = 20
  /// Windows Server 2003 (SP1).
  | WinSrv2003_SP1 = 21
  /// Windows Server 2003 (SP2).
  | WinSrv2003_SP2 = 22
  /// Windows Server 2003 (R2).
  | WinSrv2003_R2 = 23
  /// Windows Server 2003 (R2 SP2).
  | WinSrv2003_R2SP2 = 24
  /// Windows Vista (SP0).
  | WinVista_SP0 = 25
  /// Windows Vista (SP1).
  | WinVista_SP1 = 26
  /// Windows Vista (SP2).
  | WinVista_SP2 = 27
  /// Windows 7 (SP0).
  | Win7_SP0 = 28
  /// Windows 7 (SP1).
  | Win7_SP1 = 29
  /// Windows 8 (8.0).
  | Win8 = 30
  /// Windows 8 (8.1).
  | Win8_1 = 31
  /// Windows 10 (1507).
  | Win10_1507 = 32
  /// Windows 10 (1511).
  | Win10_1511 = 33
  /// Windows 10 (1607).
  | Win10_1607 = 34
  /// Windows 10 (1703).
  | Win10_1703 = 35
  /// Windows 10 (1709).
  | Win10_1709 = 36
  /// Windows 10 (1803).
  | Win10_1803 = 37
  /// Windows 10 (1809).
  | Win10_1809 = 38
  /// Windows 10 (1903).
  | Win10_1903 = 39
  /// Windows 10 (1909).
  | Win10_1909 = 40
  /// Windows 10 (2004).
  | Win10_2004 = 41
  /// Windows 10 (20H2).
  | Win10_20H2 = 42
  /// Windows 10 (21H1).
  | Win10_21H1 = 43
  /// Windows 10 (21H2).
  | Win10_21H2 = 44
  /// Windows 10 (22H2).
  | Win10_22H2 = 45
  /// Windows 11 and Server (Server 2022).
  | WinSrv2022 = 46
  /// Windows 11 and Server (11 21H2).
  | Win11_21H2 = 47
  /// Windows 11 and Server (11 22H2).
  | Win11_22H2 = 48
  /// Windows 11 and Server (11 23H2).
  | Win11_23H2 = 49
  /// Windows 11 and Server (Server 23H2).
  | WinSrv23H2 = 50
  /// Windows 11 and Server (11 24H2).
  | Win11_24H2 = 51
  /// Windows 11 and Server (Server 2025).
  | WinSrv2025 = 52
  /// Windows 11 and Server (11 25H2).
  | Win11_25H2 = 53
