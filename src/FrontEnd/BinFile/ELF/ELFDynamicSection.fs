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

namespace B2R2.FrontEnd.BinFile.ELF

open System
open B2R2
open B2R2.FrontEnd.BinFile.FileHelper

/// ELF dynamic tags.
type DynamicTag =
  | DT_NULL = 0UL
  | DT_NEEDED = 1UL
  | DT_PLTRELSZ = 2UL
  | DT_PLTGOT = 3UL
  | DT_HASH = 4UL
  | DT_STRTAB = 5UL
  | DT_SYMTAB = 6UL
  | DT_RELA = 7UL
  | DT_RELASZ = 8UL
  | DT_RELAENT = 9UL
  | DT_STRSZ = 10UL
  | DT_SYMENT = 11UL
  | DT_INIT = 12UL
  | DT_FINI = 13UL
  | DT_SONAME = 14UL
  | DT_RPATH = 15UL
  | DT_SYMBOLIC = 16UL
  | DT_REL = 17UL
  | DT_RELSZ = 18UL
  | DT_RELENT = 19UL
  | DT_PLTREL = 20UL
  | DT_DEBUG = 21UL
  | DT_TEXTREL = 22UL
  | DT_JMPREL = 23UL
  | DT_BIND_NOW = 24UL
  | DT_INIT_ARRAY = 25UL
  | DT_FINI_ARRAY = 26UL
  | DT_INIT_ARRAYSZ = 27UL
  | DT_FINI_ARRAYSZ = 28UL
  | DT_RUNPATH = 29UL
  | DT_FLAGS = 30UL
  | DT_PREINIT_ARRAY = 32UL
  | DT_PRE_INIT_ARRAYSZ = 33UL
  | DT_MAXPOSTAGS = 34UL
  | DT_FLAGS_1 = 0x6ffffffbUL
  | DT_RELACOUNT = 0x6ffffff9UL
  | DT_LOOS = 0x6000000dUL
  | DT_HIOS = 0x6ffff000UL
  | DT_VERSYM = 0x6ffffff0UL
  | DT_VERNEED = 0x6ffffffeUL
  | DT_VERNEEDNUM = 0x6fffffffUL
  | DT_VALRNGLO = 0x6ffffd00UL
  | DT_GNU_PRELINKED = 0x6ffffdf5UL
  | DT_GNU_CONFLICTSZ = 0x6ffffdf6UL
  | DT_GNU_LIBLISTSZ = 0x6ffffdf7UL
  | DT_CHECKSUM = 0x6ffffdf8UL
  | DT_PLTPADSZ = 0x6ffffdf9UL
  | DT_MOVEENT = 0x6ffffdfaUL
  | DT_MOVESZ = 0x6ffffdfbUL
  | DT_FEATURE = 0x6ffffdfcUL
  | DT_POSFLAG_1 = 0x6ffffdfdUL
  | DT_SYMINSZ = 0x6ffffdfeUL
  | DT_SYMINENT = 0x6ffffdffUL
  | DT_VALRNGHI = 0x6ffffdffUL
  | DT_ADDRRNGLO = 0x6ffffe00UL
  | DT_GNU_HASH = 0x6ffffef5UL
  | DT_TLSDESC_PLT = 0x6ffffef6UL
  | DT_TLSDESC_GOT = 0x6ffffef7UL
  | DT_GNU_CONFLICT = 0x6ffffef8UL
  | DT_GNU_LIBLIST = 0x6ffffef9UL
  | DT_CONFIG = 0x6ffffefaUL
  | DT_DEPAUDIT = 0x6ffffefbUL
  | DT_AUDIT = 0x6ffffefcUL
  | DT_PLTPAD = 0x6ffffefdUL
  | DT_MOVETAB = 0x6ffffefeUL
  | DT_SYMINFO = 0x6ffffeffUL
  | DT_ADDRRNGHI = 0x6ffffeffUL
  | DT_PPC_GOT = 0x70000000UL
  | DT_PPC_OPT = 0x70000001UL
  | DT_PPC64_GLINK = 0x70000000UL
  | DT_PPC64_OPD = 0x70000001UL
  | DT_PPC64_OPDSZ = 0x70000002UL
  | DT_SPARC_REGISTER = 0x70000001UL
  | DT_MIPS_RLD_VERSION = 0x70000001UL
  | DT_MIPS_TIME_STAMP = 0x70000002UL
  | DT_MIPS_ICHECKSUM = 0x70000003UL
  | DT_MIPS_IVERSION = 0x70000004UL
  | DT_MIPS_FLAGS = 0x70000005UL
  | DT_MIPS_BASE_ADDRESS = 0x70000006UL
  | DT_MIPS_MSYM = 0x70000007UL
  | DT_MIPS_CONFLICT = 0x70000008UL
  | DT_MIPS_LIBLIST = 0x70000009UL
  | DT_MIPS_LOCAL_GOTNO = 0x7000000aUL
  | DT_MIPS_CONFLICTNO = 0x7000000bUL
  | DT_MIPS_LIBLISTNO = 0x70000010UL
  | DT_MIPS_SYMTABNO = 0x70000011UL
  | DT_MIPS_UNREFEXTNO = 0x70000012UL
  | DT_MIPS_GOTSYM = 0x70000013UL
  | DT_MIPS_HIPAGENO = 0x70000014UL
  | DT_MIPS_RLD_MAP = 0x70000016UL
  | DT_MIPS_DELTA_CLASS = 0x70000017UL
  | DT_MIPS_DELTA_CLASS_NO = 0x70000018UL
  | DT_MIPS_DELTA_INSTANCE = 0x70000019UL
  | DT_MIPS_DELTA_INSTANCE_NO = 0x7000001aUL
  | DT_MIPS_DELTA_RELOC = 0x7000001bUL
  | DT_MIPS_DELTA_RELOC_NO = 0x7000001cUL
  | DT_MIPS_DELTA_SYM = 0x7000001dUL
  | DT_MIPS_DELTA_SYM_NO = 0x7000001eUL
  | DT_MIPS_DELTA_CLASSSYM = 0x70000020UL
  | DT_MIPS_DELTA_CLASSSYM_NO = 0x70000021UL
  | DT_MIPS_CXX_FLAGS = 0x70000022UL
  | DT_MIPS_PIXIE_INIT = 0x70000023UL
  | DT_MIPS_SYMBOL_LIB = 0x70000024UL
  | DT_MIPS_LOCALPAGE_GOTIDX = 0x70000025UL
  | DT_MIPS_LOCAL_GOTIDX = 0x70000026UL
  | DT_MIPS_HIDDEN_GOTIDX = 0x70000027UL
  | DT_MIPS_PROTECTED_GOTIDX = 0x70000028UL
  | DT_MIPS_OPTIONS = 0x70000029UL
  | DT_MIPS_INTERFACE = 0x7000002aUL
  | DT_MIPS_DYNSTR_ALIGN = 0x7000002bUL
  | DT_MIPS_INTERFACE_SIZE = 0x7000002cUL
  | DT_MIPS_RLD_TEXT_RESOLVE_ADDR = 0x7000002dUL
  | DT_MIPS_PERF_SUFFIX = 0x7000002eUL
  | DT_MIPS_COMPACT_SIZE = 0x7000002fUL
  | DT_MIPS_GP_VALUE = 0x70000030UL
  | DT_MIPS_AUX_DYNAMIC = 0x70000031UL
  | DT_MIPS_PLTGOT = 0x70000032UL
  | DT_MIPS_RWPLT = 0x70000034UL
  | DT_MIPS_RLD_MAP_REL = 0x70000035UL

/// Dynamic section entry.
type DynamicSectionEntry = {
  DTag: DynamicTag
  DVal: uint64
}

module internal DynamicSection =
  let private readDynamicEntry reader cls span =
    let dtag = readUIntByWordSize span reader cls 0
    let dval = readUIntByWordSize span reader cls (selectByWordSize cls 4 8)
    { DTag = LanguagePrimitives.EnumOfValue dtag; DVal = dval }

  let private parseDynamicSection ({ Bytes = bytes } as toolBox) sec =
    let reader = toolBox.Reader
    let cls = toolBox.Header.Class
    let numEntries = int sec.SecSize / int sec.SecEntrySize
    let entries = Array.zeroCreate numEntries
    let rec parseLoop n offset =
      if n = numEntries then entries
      else
        let span = ReadOnlySpan (bytes, offset, int sec.SecEntrySize)
        let ent = readDynamicEntry reader cls span
        entries[n] <- ent
        if ent.DTag = DynamicTag.DT_NULL && ent.DVal = 0UL then entries[0..n]
        else parseLoop (n + 1) (offset + int sec.SecEntrySize)
    parseLoop 0 (int sec.SecOffset)

  let readEntries toolBox secHeaders =
    let dynamicSection =
      secHeaders |> Array.tryFind (fun s -> s.SecType = SectionType.SHT_DYNAMIC)
    match dynamicSection with
    | Some sec -> parseDynamicSection toolBox sec
    | None -> [||]
