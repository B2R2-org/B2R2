#!/usr/bin/env python3
"""Writes out the Mach-O fixtures that no toolchain can build.

Some of what the parser has to handle cannot be produced by a current SDK: an
assembler always emits __text even when nothing goes in it, ld64 keeps the
empty section, no SDK targets i386 or armv7 any more, and ld64 stopped emitting
LC_UNIXTHREAD long ago. Those fixtures are written here instead. Run this from
the directory it lives in; it rewrites each file and its archive in place.

The fixtures clang and lipo can build are listed in README.md instead.
"""
import struct
import sys
import zipfile

MH_MAGIC, MH_MAGIC_64 = 0xFEEDFACE, 0xFEEDFACF
MH_OBJECT, MH_EXECUTE, MH_DYLIB = 1, 2, 6
CPU_I386, CPU_ARM, CPU_ARM64, CPU_X64 = 7, 12, 0x0100000C, 0x01000007
LC_SEGMENT, LC_SEGMENT_64, LC_SYMTAB = 0x1, 0x19, 0x2
LC_UNIXTHREAD, LC_ID_DYLIB, LC_DATA_IN_CODE = 0x5, 0xD, 0x29
LC_DYLD_INFO_ONLY, LC_DYSYMTAB = 0x80000022, 0xB
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_LINKER_OPTION = 0x2D
LC_FILESET_ENTRY = 0x80000035
MH_KEXT_BUNDLE, MH_FILESET = 0xB, 0xC
PTR_START_MULTI, PTR_START_LAST, PTR_START_NONE = 0x8000, 0x8000, 0xFFFF
N_SECT_EXT, N_ABS_EXT, N_UNDF_EXT = 0x0F, 0x03, 0x01
N_ARM_THUMB_DEF, MH_PIE, SUBSECTIONS_VIA_SYMBOLS = 0x8, 0x200000, 0x2000


def name16(s):
    return s.encode() + b'\0' * (16 - len(s))


def header32(cputype, cpusub, filetype, ncmds, sizeofcmds, flags):
    return struct.pack('<I2i4I', MH_MAGIC, cputype, cpusub, filetype,
                       ncmds, sizeofcmds, flags)


def header64(cputype, cpusub, filetype, ncmds, sizeofcmds, flags):
    return struct.pack('<I2i5I', MH_MAGIC_64, cputype, cpusub, filetype,
                       ncmds, sizeofcmds, flags, 0)


def seg32(name, vmaddr, vmsize, fileoff, filesize, prot, sects,
          secseg=None):
    cmd = struct.pack('<2I', LC_SEGMENT, 56 + 68 * len(sects)) + name16(name) \
        + struct.pack('<4I2i2I', vmaddr, vmsize, fileoff, filesize,
                      prot, prot, len(sects), 0)
    for sn, addr, size, off, align, reloff, nreloc, flags in sects:
        cmd += name16(sn) + name16(secseg or name) \
            + struct.pack('<9I', addr, size, off, align, reloff, nreloc,
                          flags, 0, 0)
    return cmd


def seg64(name, vmaddr, vmsize, fileoff, filesize, prot, sects,
          secseg=None):
    cmd = struct.pack('<2I', LC_SEGMENT_64, 72 + 80 * len(sects)) \
        + name16(name) \
        + struct.pack('<4Q2i2I', vmaddr, vmsize, fileoff, filesize,
                      prot, prot, len(sects), 0)
    for sn, addr, size, off, align, flags in sects:
        cmd += name16(sn) + name16(secseg or name) \
            + struct.pack('<2Q8I', addr, size, off, align, 0, 0, flags,
                          0, 0, 0)
    return cmd


def symtab(symoff, nsyms, stroff, strsize):
    return struct.pack('<6I', LC_SYMTAB, 24, symoff, nsyms, stroff, strsize)


def nlist32(strx, ntype, nsect, ndesc, value):
    return struct.pack('<IBBhI', strx, ntype, nsect, ndesc, value)


def nlist64(strx, ntype, nsect, ndesc, value):
    return struct.pack('<IBBhQ', strx, ntype, nsect, ndesc, value)


def notext():
    """A data-only object, which an assembler cannot emit: it always lays down
    __text first, and ld64 keeps the empty section in whatever it links."""
    data = struct.pack('<4I', 1, 2, 3, 4)
    strtab = b'\0_g_table\0'
    sizeofcmds = 72 + 80 + 24
    dataoff = 32 + sizeofcmds
    symoff = dataoff + len(data)
    stroff = symoff + 16
    return (header64(CPU_X64, 3, MH_OBJECT, 2, sizeofcmds,
                     SUBSECTIONS_VIA_SYMBOLS)
            + seg64('', 0, len(data), dataoff, len(data), 7,
                    [('__data', 0, len(data), dataoff, 3, 0)], '__DATA')
            + symtab(symoff, 1, stroff, len(strtab))
            + data + nlist64(1, N_SECT_EXT, 1, 0, 0) + strtab)


# (cputype, cpusubtype, thread flavor, uint32 count, pc slot)
THREADS = {'x64': (CPU_X64, 3, 4, 42, 16), 'arm64': (CPU_ARM64, 0, 6, 68, 32)}


def unixthread(kind):
    """An executable naming its entry point through LC_UNIXTHREAD, the way
    binaries older than LC_MAIN and kernel images do. ld64 no longer emits
    the command at all."""
    cputype, cpusub, flavor, count, pcslot = THREADS[kind]
    thrsz = 16 + count * 4
    sizeofcmds = 72 + 80 + thrsz
    textoff = 32 + sizeofcmds
    text = b'\xc3' * 16
    vmaddr = 0x100000000
    filesize = textoff + len(text)
    state = bytearray(count * 4)
    struct.pack_into('<Q', state, pcslot * 8, vmaddr + textoff)
    return (header64(cputype, cpusub, MH_EXECUTE, 2, sizeofcmds, 0)
            + seg64('__TEXT', vmaddr, 0x1000, 0, filesize, 5,
                    [('__text', vmaddr + textoff, len(text), textoff, 4,
                      0x80000400)])
            + struct.pack('<4I', LC_UNIXTHREAD, thrsz, flavor, count)
            + bytes(state) + text)


def i386_dyldinfo():
    """A 32-bit dylib carrying LC_DYLD_INFO_ONLY, the counterpart of
    mach_x64_dyldinfo. The word behind the rebase slot is deliberately
    non-zero, so reading the slot eight bytes wide instead of four yields a
    visibly wrong target."""
    page = 0x1000
    data = struct.pack('<3I', 0, 0x1008, 0xAABBCCDD)
    rebase = bytes([0x11,           # SET_TYPE_IMM, pointer
                    0x21, 0x04,     # SET_SEGMENT_AND_OFFSET_ULEB seg 1, off 4
                    0x51,           # DO_REBASE_IMM_TIMES x1
                    0x00])          # DONE
    bind = bytes([0x40]) + b'_ext_symbol\0' \
        + bytes([0x51,              # SET_TYPE_IMM, pointer
                 0x3e,              # SET_DYLIB_SPECIAL_IMM, flat lookup
                 0x71, 0x00,        # SET_SEGMENT_AND_OFFSET_ULEB seg 1, off 0
                 0x90,              # DO_BIND
                 0x00])             # DONE
    install = b'/usr/lib/libi386.dylib\0'
    pad = b'\0' * (-len(install) % 4)
    idcmd = struct.pack('<6I', LC_ID_DYLIB, 24 + len(install) + len(pad),
                        24, 0, 0x10000, 0x10000) + install + pad
    link = page * 2
    dyldcmd = struct.pack('<2I', LC_DYLD_INFO_ONLY, 48) \
        + struct.pack('<10I', link, len(rebase), link + len(rebase),
                      len(bind), 0, 0, 0, 0, 0, 0)
    cmds = seg32('__TEXT', 0, page, 0, page, 5,
                 [('__text', 0x200, 0, 0x200, 2, 0, 0, 0x80000400)]) \
        + seg32('__DATA', page, page, page, page, 3,
                [('__data', page, len(data), page, 2, 0, 0, 0)]) \
        + seg32('__LINKEDIT', link, page, link, len(rebase) + len(bind), 1,
                []) \
        + idcmd + dyldcmd
    out = bytearray(link + len(rebase) + len(bind))
    out[0:28] = header32(CPU_I386, 3, MH_DYLIB, 5, len(cmds), 0x100085)
    out[28:28 + len(cmds)] = cmds
    out[page:page + len(data)] = data
    out[link:link + len(rebase)] = rebase
    out[link + len(rebase):] = bind
    return bytes(out)


def dysymtab(extreloff, nextrel, locreloff, nlocrel):
    fields = [0] * 18
    fields[14], fields[15] = extreloff, nextrel
    fields[16], fields[17] = locreloff, nlocrel
    return struct.pack('<2I18I', LC_DYSYMTAB, 80, *fields)


def plain_reloc(addr, symnum, pcrel, length, ext, rtype):
    word = (symnum & 0xFFFFFF) | (pcrel << 24) | (length << 25) \
        | (ext << 27) | (rtype << 28)
    return struct.pack('<II', addr, word)


def scattered_reloc(addr, value, pcrel, length, rtype):
    word = (1 << 31) | (pcrel << 30) | (length << 28) | (rtype << 24) \
        | (addr & 0xFFFFFF)
    return struct.pack('<II', word, value)


def i386_reloc():
    """A 32-bit object carrying the relocation shapes x86-64 never produces: a
    scattered entry, a PC-relative one, and a plain external one. The scattered
    field holds 0x2010 while the entry measures it from 0x2000, which is the
    whole reason a scattered entry exists."""
    text = struct.pack('<3i', 0x2010, -4, 0x30)
    relocs = (scattered_reloc(0x0, 0x2000, 0, 2, 2)
              + plain_reloc(0x4, 0, 1, 2, 1, 0)
              + plain_reloc(0x8, 1, 0, 2, 1, 0))
    strtab = b'\0_pcrel_target\0_plain_target\0'
    nlists = nlist32(1, N_UNDF_EXT, 0, 0, 0) + nlist32(15, N_UNDF_EXT, 0, 0, 0)
    sizeofcmds = 56 + 68 + 24
    textoff = 28 + sizeofcmds
    reloff = textoff + len(text)
    symoff = reloff + len(relocs)
    stroff = symoff + len(nlists)
    return (header32(CPU_I386, 3, MH_OBJECT, 2, sizeofcmds,
                     SUBSECTIONS_VIA_SYMBOLS)
            + seg32('', 0, len(text), textoff, len(text), 7,
                    [('__text', 0, len(text), textoff, 2, reloff, 3,
                      0x80000400)], '__TEXT')
            + symtab(symoff, 2, stroff, len(strtab))
            + text + relocs + nlists + strtab)


def arm32_thumb():
    """An ARMv7 executable mixing A32 and T32 code, with a data range embedded
    in __text. N_ARM_THUMB_DEF marks the Thumb function and LC_DATA_IN_CODE
    marks the data. It is MH_PIE and carries an absolute symbol too, so a load
    address can be seen to move the section-defined symbols and to leave the
    absolute one where it is."""
    vmaddr, absval = 0x1000, 0x1234
    text = b'\x00' * 0x40
    strtab = b'\0_arm_fn\0_thumb_fn\0_abs_sym\0'
    sizeofcmds = 56 + 68 + 24 + 16
    textoff = 28 + sizeofcmds
    textaddr = vmaddr + textoff
    armfn, thumbfn = textaddr, textaddr + 0x20
    datastart, datalen = textaddr + 0x10, 8
    nlists = (nlist32(1, N_SECT_EXT, 1, 0, armfn)
              + nlist32(9, N_SECT_EXT, 1, N_ARM_THUMB_DEF, thumbfn)
              + nlist32(19, N_ABS_EXT, 0, 0, absval))
    # A data_in_code_entry counts its start from the Mach-O header.
    dice = struct.pack('<IHH', datastart - vmaddr, datalen, 1)
    symoff = textoff + len(text)
    stroff = symoff + len(nlists)
    diceoff = stroff + len(strtab)
    return (header32(CPU_ARM, 9, MH_EXECUTE, 3, sizeofcmds, MH_PIE)
            + seg32('__TEXT', vmaddr, 0x1000, 0, diceoff + len(dice), 5,
                    [('__text', textaddr, len(text), textoff, 2, 0, 0,
                      0x80000400)])
            + symtab(symoff, 3, stroff, len(strtab))
            + struct.pack('<4I', LC_DATA_IN_CODE, 16, diceoff, len(dice))
            + text + nlists + strtab + dice)


def x64_extreloc():
    """A non-PIE dylib whose relocations live in the external and local tables
    of LC_DYSYMTAB rather than hanging off its sections. Only an image built
    without PIE, chained fixups and dyld info carries them, which no current
    linker will produce. Their r_address counts from the image base, here the
    __TEXT vmaddr, not from any section."""
    page, textvm = 0x1000, 0x1000
    datavm, linkvm = 0x2000, 0x3000
    # 0x2000 takes the external entry, whose addend is 0x10; 0x2008 takes the
    # local one, holding the unslid address 0x2000.
    data = struct.pack('<2Q', 0x10, datavm)
    strtab = b'\0_data_base\0_ext_sym\0'
    nlists = (nlist64(1, N_SECT_EXT, 2, 0, datavm)
              + nlist64(12, N_UNDF_EXT, 0, 0, 0))
    extrel = plain_reloc(datavm - textvm, 0, 0, 3, 1, 0)
    locrel = plain_reloc(datavm + 8 - textvm, 2, 0, 3, 0, 0)
    install = b'/usr/lib/libextreloc.dylib\0'
    pad = b'\0' * (-len(install) % 8)
    idcmd = struct.pack('<6I', LC_ID_DYLIB, 24 + len(install) + len(pad),
                        24, 0, 0x10000, 0x10000) + install + pad
    symoff = linkvm
    stroff = symoff + len(nlists)
    reloff = stroff + len(strtab)
    linksize = len(nlists) + len(strtab) + len(extrel) + len(locrel)
    cmds = (seg64('__TEXT', textvm, page, 0, page, 5,
                  [('__text', textvm + 0x200, 0, 0x200, 4, 0x80000400)])
            + seg64('__DATA', datavm, page, page, page, 3,
                    [('__data', datavm, len(data), page, 3, 0)])
            + seg64('__LINKEDIT', linkvm, page, linkvm, linksize, 1, [])
            + idcmd
            + symtab(symoff, 2, stroff, len(strtab))
            + dysymtab(reloff, 1, reloff + len(extrel), 1))
    out = bytearray(linkvm + linksize)
    out[0:32] = header64(CPU_X64, 3, MH_DYLIB, 6, len(cmds), 0x100085)
    out[32:32 + len(cmds)] = cmds
    out[page:page + len(data)] = data
    out[symoff:symoff + len(nlists)] = nlists
    out[stroff:stroff + len(strtab)] = strtab
    out[reloff:reloff + len(extrel)] = extrel
    out[reloff + len(extrel):] = locrel
    return bytes(out)


def x64_multichain():
    """A dylib whose one fixup page holds two chains, so its page_start is an
    index into the overflow list rather than an offset into the page. Only the
    32-bit pointer formats make dyld emit that, and this parser does not read
    those, so the payload pairs it with DYLD_CHAINED_PTR_64: the overflow walk
    it exercises is the same one either way."""
    page = 0x1000
    datavm, linkvm = 0x1000, 0x2000
    # Two one-entry chains on the same page, at 0x1000 and 0x1010, each with a
    # next of zero. Their targets, 0x1008 and 0x1018, follow them.
    data = struct.pack('<4Q', 0x1008, 0, 0x1018, 0)
    starts_in_image = struct.pack('<4I', 3, 0, 16, 0)
    page_start = struct.pack('<3H', PTR_START_MULTI | 1, 0x0000,
                             PTR_START_LAST | 0x10)
    in_segment = struct.pack('<IHHQIH', 22 + len(page_start), page, 2,
                             datavm, 0, 1) + page_start
    starts = starts_in_image + in_segment
    header = struct.pack('<7I', 0, 32, 32 + len(starts), 32 + len(starts),
                         0, 1, 0)
    payload = header + b'\0' * (32 - len(header)) + starts + b'\0'
    cmds = (seg64('__TEXT', 0, page, 0, page, 5,
                  [('__text', 0x200, 0, 0x200, 4, 0x80000400)])
            + seg64('__DATA', datavm, page, page, page, 3,
                    [('__data', datavm, len(data), page, 3, 0)])
            + seg64('__LINKEDIT', linkvm, page, linkvm, len(payload), 1, [])
            + struct.pack('<4I', LC_DYLD_CHAINED_FIXUPS, 16, linkvm,
                          len(payload)))
    out = bytearray(linkvm + len(payload))
    out[0:32] = header64(CPU_X64, 3, MH_DYLIB, 4, len(cmds), 0x100085)
    out[32:32 + len(cmds)] = cmds
    out[page:page + len(data)] = data
    out[linkvm:] = payload
    return bytes(out)


def fileset_entry(vmaddr, fileoff, name):
    """One LC_FILESET_ENTRY. Its lc_str offset is at 24, not at 8 the way
    every other string-carrying command puts it."""
    payload = name.encode() + b'\0'
    size = (32 + len(payload) + 7) & ~7
    return struct.pack('<2I2Q2I', LC_FILESET_ENTRY, size, vmaddr, fileoff,
                       32, 0) + payload.ljust(size - 32, b'\0')


VM = 0x100000000
LINK = 0x3000


def kext(fileoff, strx, name):
    """One image held inside the fileset. Every offset it names is into the
    container: its __TEXT sits at its own page, but its __LINKEDIT and its
    symbol table are the container's, far outside the page. An image read
    against a copy cut out of the container would read those at the wrong
    place, which is what tells a fileset apart from a universal binary."""
    text = fileoff + 0x800
    cmds = (seg64('__TEXT', VM + fileoff, 0x1000, fileoff, 0x1000, 5,
                  [('__text', VM + text, 1, text, 4, 0x80000400)])
            + seg64('__LINKEDIT', VM + LINK, 0x1000, LINK, 0x30, 1, [])
            + symtab(LINK + strx * 16, 1, LINK + 32, 17))
    return header64(CPU_X64, 3, MH_KEXT_BUNDLE, 3, len(cmds), 0) + cmds


def fileset():
    """A fileset container, as a kernel collection is: two images named by
    LC_FILESET_ENTRY, sharing one __LINKEDIT. __PRELINK_TEXT occupies no
    virtual memory, which a kernel image carries several of, so a segment map
    that does not drop it builds an inverted address range."""
    entries = [('com.example.kext.a', 0x1000, 0),
               ('com.example.kext.b', 0x2000, 1)]
    cmds = (seg64('__TEXT_EXEC', VM + 0x1000, 0x2000, 0x1000, 0x2000, 5, [])
            + seg64('__PRELINK_TEXT', VM + LINK, 0, LINK, 0, 1, [])
            + seg64('__LINKEDIT', VM + LINK, 0x1000, LINK, 0x30, 1, [])
            + symtab(LINK, 2, LINK + 32, 17))
    for name, fileoff, _ in entries:
        cmds += fileset_entry(VM + fileoff, fileoff, name)
    out = bytearray(LINK + 0x30)
    out[0:32] = header64(CPU_X64, 3, MH_FILESET, 4 + len(entries), len(cmds), 0)
    out[32:32 + len(cmds)] = cmds
    for _, fileoff, strx in entries:
        sub = kext(fileoff, strx, None)
        out[fileoff:fileoff + len(sub)] = sub
        out[fileoff + 0x800] = 0xC3  # ret
    out[LINK:LINK + 16] = nlist64(1, N_SECT_EXT, 1, 0, VM + 0x1800)
    out[LINK + 16:LINK + 32] = nlist64(9, N_SECT_EXT, 1, 0, VM + 0x2800)
    out[LINK + 32:] = b'\0_a_func\0_b_func\0'
    return bytes(out)


def linker_option(*opts):
    """One LC_LINKER_OPTION. Its strings follow the count one after another,
    each NUL-terminated, and the last is padded out to the alignment a 64-bit
    load command keeps."""
    payload = b''.join(o.encode() + b'\0' for o in opts)
    size = (12 + len(payload) + 7) & ~7
    return struct.pack('<3I', LC_LINKER_OPTION, size, len(opts)) \
        + payload.ljust(size - 12, b'\0')


def linkeropt():
    """An object file that names what it needs linked with LC_LINKER_OPTION,
    the way clang's autolinking writes it, rather than with LC_LOAD_DYLIB,
    which no object file carries. Every form that names a library is here:
    the four that join the name to the flag and the three that put it in the
    string after. -lfoo is named twice, as autolinking repeats a directive
    for every translation unit carrying it, and -random_flag names no library
    at all."""
    text = b'\xc3' + b'\0' * 7
    strtab = b'\0_f\0'
    opts = (linker_option('-lfoo')
            + linker_option('-framework', 'Bar')
            + linker_option('-weak-lbaz')
            + linker_option('-weak_framework', 'Qux')
            + linker_option('-needed-lquux')
            + linker_option('-hidden-lcorge')
            + linker_option('-needed_framework', 'Grault')
            + linker_option('-lfoo')
            + linker_option('-random_flag'))
    sizeofcmds = 72 + 80 + 24 + len(opts)
    textoff = 32 + sizeofcmds
    symoff = textoff + len(text)
    stroff = symoff + 16
    return (header64(CPU_X64, 3, MH_OBJECT, 11, sizeofcmds,
                     SUBSECTIONS_VIA_SYMBOLS)
            + seg64('', 0, len(text), textoff, len(text), 7,
                    [('__text', 0, len(text), textoff, 4, 0x80000400)],
                    '__TEXT')
            + symtab(symoff, 1, stroff, len(strtab))
            + opts + text + nlist64(1, N_SECT_EXT, 1, 0, 0) + strtab)


FIXTURES = {'mach_x64_notext': notext,
            'mach_x64_unixthread': lambda: unixthread('x64'),
            'mach_arm64_unixthread': lambda: unixthread('arm64'),
            'mach_i386_dyldinfo': i386_dyldinfo,
            'mach_i386_reloc': i386_reloc,
            'mach_arm32_thumb': arm32_thumb,
            'mach_x64_extreloc': x64_extreloc,
            'mach_x64_multichain': x64_multichain,
            'mach_x64_fileset': fileset,
            'mach_x64_linkeropt': linkeropt}


def main(check):
    failed = False
    for name, build in sorted(FIXTURES.items()):
        data = build()
        archive = name + '.zip'
        if check:
            with zipfile.ZipFile(archive) as z:
                same = z.read(name) == data
            print('%-24s %s' % (name, 'matches' if same else 'DIFFERS'))
            failed = failed or not same
        else:
            with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
                z.writestr(name, data)
            print('%-24s %d bytes' % (name, len(data)))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main('--check' in sys.argv))
