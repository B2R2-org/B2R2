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

/// Represents the type of load commands in Mach-O files.
type CmdType =
  /// Defines a segment of this file to be mapped into the address space of the
  /// process that loads this file. It also includes all the sections contained
  /// by the segment.
  | LC_SEGMENT = 0x01
  /// The symbol table for this file.
  | LC_SYMTAB = 0x02
  /// The gdb symbol table info (obsolete).
  | LC_SYMSEG = 0x03
  /// This command defines the initial thread state of the main thread of the
  /// process. LC_THREAD is similar to LC_UNIXTHREAD but does not cause the
  /// kernel to allocate a stack.
  | LC_THREAD = 0x04
  /// This command defines the initial thread state of the main thread of the
  /// process.
  | LC_UNIXTHREAD = 0x05
  /// Load a specified fixed VM shared library.
  | LC_LOADFVMLIB = 0x06
  /// Fixed VM shared library identification.
  | LC_IDFVMLIB = 0x07
  /// Object identification info (obsolete).
  | LC_IDENT = 0x08
  /// Fixed VM file inclusion (internal use).
  | LC_FVMFILE = 0x09
  /// Prepage command (internal use).
  | LC_PREPAGE = 0x0A
  /// Dynamic link-edit symbol table info.
  | LC_DYSYMTAB = 0x0B
  /// Load a dynamically linked shared library.
  | LC_LOAD_DYLIB = 0x0C
  /// This command Specifies the install name of a dynamic shared library.
  | LC_ID_DYLIB = 0x0D
  /// Load a dynamic linker.
  | LC_LOAD_DYLINKER = 0x0E
  /// Dynamic linker identification.
  | LC_ID_DYLINKER = 0x0F
  /// Modules prebound for a dynamically linked shared library.
  | LC_PREBOUND_DYLIB = 0x10
  /// Image routines.
  | LC_ROUTINES = 0x11
  /// Sub framework.
  | LC_SUB_FRAMEWORK = 0x12
  /// Sub umbrella.
  | LC_SUB_UMBRELLA = 0x13
  /// Sub client.
  | LC_SUB_CLIENT = 0x14
  /// Sub library.
  | LC_SUB_LIBRARY = 0x15
  /// Two-level namespace lookup hints
  | LC_TWOLEVEL_HINTS = 0x16
  /// Prebind checksum.
  | LC_PREBIND_CKSUM = 0x17
  /// Load a dynamically linked shared library that is allowed to be missing.
  | LC_LOAD_WEAK_DYLIB = 0x80000018
  /// 64-bit segment of this file to be mapped.
  | LC_SEGMENT64 = 0x19
  /// 64-bit image routines.
  | LC_ROUTINES64 = 0x1A
  /// The uuid.
  | LC_UUID = 0x1B
  /// Runpath additions.
  | LC_RPATH = 0x8000001C
  /// Local of code signature.
  | LC_CODE_SIGNATURE = 0x1D
  /// Local of info to split segments
  | LC_SEGMENT_SPLIT_INFO = 0x1E
  /// Load and re-export dylib.
  | LC_REEXPORT_DYLIB = 0x8000001F
  /// Delay load of dylib until first use.
  | LC_LAZY_LOAD_DYLIB = 0x20
  /// Encrypted segment information.
  | LC_ENCRYPTION_INFO = 0x21
  /// Compressed dyld information.
  | LC_DYLD_INFO = 0x22
  /// Compressed dyld information only.
  | LC_DYLD_INFO_ONLY = 0x80000022
  /// Load upward dylib.
  | LC_LOAD_UPWARD_DYLIB = 0x80000023
  /// Build for MacOSX min OS version.
  | LC_VERSION_MIN_MACOSX = 0x24
  /// Build for iPhoneOS min OS version.
  | LC_VERSION_MIN_IPHONEOS = 0x25
  /// Compressed table of function start addresses.
  | LC_FUNCTION_STARTS = 0x26
  /// String for dyld to treat like environment variable.
  | LC_DYLD_ENVIRONMENT = 0x27
  /// Replacement for LC_UNIXTHREAD.
  | LC_MAIN = 0x80000028
  /// Table of non-instructions in __text.
  | LC_DATA_IN_CODE = 0x29
  /// Source version used to build binary.
  | LC_SOURCE_VERSION = 0x2A
  /// Code signing DRs copied from linked dylibs.
  | LC_DYLIB_CODE_SIGN_DRS = 0x2B
  /// 64-bit encrypted segment information.
  | LC_ENCRYPTION_INFO_64 = 0x2C
  /// Linker options in MH_OBJECT files.
  | LC_LINKER_OPTION = 0x2D
  /// Optimization hints in MH_OBJECT files.
  | LC_LINKER_OPTIMIZATION_HINT = 0x2E
  /// Build for AppleTV min OS version.
  | LC_VERSION_MIN_TVOS = 0x2F
  /// Build for Watch min OS version
  | LC_VERSION_MIN_WATCHOS = 0x30
