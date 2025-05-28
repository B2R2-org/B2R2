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

open B2R2

/// Represents a symbol in a Mach-O file.
type Symbol = {
  /// Symbol name.
  SymName: string
  /// Symbol type (N_TYPE field of n_type).
  SymType: SymbolType
  /// Is this an external symbol?
  IsExternal: bool
  /// The number of the section that this symbol can be found.
  SecNum: int
  /// Providing additional information about the nature of this symbol for
  /// non-stab symbols.
  SymDesc: int16
  /// External library version info.
  VerInfo: DyLibCmd option
  /// Address of the symbol.
  SymAddr: Addr
}
with
  /// Checks if this symbol is a function symbol.
  static member inline IsFunc secText s =
    (s.SymType = SymbolType.N_FUN && s.SymName.Length > 0) ||
    (s.SymType.HasFlag SymbolType.N_SECT
      && s.SecNum = (secText + 1)
      && s.SymDesc = 0s)

  /// Checks if this symbol is a static symbol.
  static member inline IsStatic s =
    let isDebuggingInfo s = int s.SymType &&& 0xe0 <> 0
    (* REFERENCED_DYNAMICALLY field of n_desc is set. This means this symbol
       will not be stripped (thus, this symbol is dynamic). *)
    let isReferrencedDynamically s = s.SymDesc &&& 0x10s <> 0s
    isDebuggingInfo s
    || (s.SecNum > 0 && s.SymAddr > 0UL && s.VerInfo = None
       && (isReferrencedDynamically s |> not))

/// Represents the symbol type (N_TYPE).
and SymbolType =
  /// The symbol is undefined.
  | N_UNDF = 0x0
  /// The symbol is absolute. The linker does not update the value of an
  /// absolute symbol.
  | N_ABS = 0x2
  /// The symbol is defined in the section number given in n_sect.
  | N_SECT = 0xe
  /// The symbol is undefined and the image is using a prebound value for the
  /// symbol.
  | N_PBUD = 0xc
  /// The symbol is defined to be the same as another symbol.
  | N_INDR = 0xa
  /// Global symbol.
  | N_GSYM = 0x20
  /// Procedure name (f77 kludge).
  | N_FNAME = 0x22
  /// Procedure.
  | N_FUN = 0x24
  /// Static symbol.
  | N_STSYM = 0x26
  /// .lcomm symbol.
  | N_LCSYM = 0x28
  /// Begin nsect sym.
  | N_BNSYM = 0x2e
  /// AST file path.
  | N_AST = 0x32
  /// Emitted with gcc2_compiled and in gcc source.
  | N_OPT = 0x3c
  /// Register sym.
  | N_RSYM = 0x40
  /// Source line.
  | N_SLINE = 0x44
  /// End nsect sym.
  | N_ENSYM = 0x4e
  /// Structure element.
  | N_SSYM = 0x60
  /// Source file name.
  | N_SO = 0x64
  /// Object file name.
  | N_OSO = 0x66
  /// Local symbol.
  | N_LSYM = 0x80
  /// Include file beginning.
  | N_BINCL = 0x82
  /// "#included" file name: name,,n_sect,0,address.
  | N_SOL = 0x84
  /// Compiler parameters.
  | N_PARAMS = 0x86
  /// Compiler version.
  | N_VERSION= 0x88
  /// Compiler optimization level.
  | N_OLEVEL = 0x8a
  /// Parameter.
  | N_PSYM = 0xa0
  /// Include file end.
  | N_EINCL = 0xa2
  /// Alternate entry.
  | N_ENTRY = 0xa4
  /// Left bracket.
  | N_LBRAC = 0xc0
  /// Deleted include file.
  | N_EXCL = 0xc2
  /// Right bracket.
  | N_RBRAC = 0xe0
  /// Begin common.
  | N_BCOMM = 0xe2
  /// End common.
  | N_ECOMM = 0xe4
  /// End common (local name).
  | N_ECOML = 0xe8
  /// Second stab entry with length information.
  | N_LENG = 0xfe
  /// Global pascal symbol.
  | N_PC = 0x30
