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

namespace B2R2.FrontEnd.BinFile.Mach

/// Represents the type of a Mach-O section.
type SectionType =
  /// Regular section.
  | S_REGULAR = 0x0
  /// Zero fill on demand section.
  | S_ZEROFILL = 0x1
  /// Section with only literal C strings.
  | S_CSTRING_LITERALS = 0x2
  /// Section with only 4 byte literals.
  | S_4BYTE_LITERALS = 0x3
  /// Section with only 8 byte literals.
  | S_8BYTE_LITERALS = 0x4
  /// section with only pointers to literals.
  | S_LITERAL_POINTERS = 0x5
  /// Section with only non-lazy symbol pointers .
  | S_NON_LAZY_SYMBOL_POINTERS = 0x6
  /// Section with only lazy symbol pointers.
  | S_LAZY_SYMBOL_POINTERS = 0x7
  /// Section with only symbol stubs, byte size of stub in the reserved2 field.
  | S_SYMBOL_STUBS = 0x8
  /// Section with only function pointers for initialization.
  | S_MOD_INIT_FUNC_POINTERS = 0x9
  /// Section with only function pointers for termination.
  | S_MOD_TERM_FUNC_POINTERS = 0xa
  /// Section contains symbols that are to be coalesced.
  | S_COALESCED = 0xb
  /// Zero fill on demand section (this can be larger than 4 gigabytes).
  | S_GB_ZEROFILL = 0xc
  /// Section with only pairs of function pointers for interposing.
  | S_INTERPOSING = 0xd
  /// Section with only 16 byte literals.
  | S_16BYTE_LITERALS = 0xe
  /// Section contains DTrace Object Format.
  | S_DTRACE_DOF = 0xf
  /// Section with only lazy symbol pointers to lazy loaded dylibs.
  | S_LAZY_DYLIB_SYMBOL_POINTERS = 0x10
  /// Template of initial values for TLVs.
  | S_THREAD_LOCAL_REGULAR = 0x11
  /// Template of initial values for TLVs.
  | S_THREAD_LOCAL_ZEROFILL = 0x12
  /// TLV descriptors.
  | S_THREAD_LOCAL_VARIABLES = 0x13
  /// Pointers to TLV descriptors.
  | S_THREAD_LOCAL_VARIABLE_POINTERS = 0x14
  /// Functions to call to initialize TLV values .
  | S_THREAD_LOCAL_INIT_FUNCTION_POINTERS = 0x15
