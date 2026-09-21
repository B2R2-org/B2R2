# PE test fixtures

Each fixture is a minimal binary built with MSVC and zipped. They are kept small
and each isolates a specific parser capability, mirroring the ELF/Mach fixtures.

Because a PE *image* carries no symbols of its own (names come from a PDB),
symbol coverage avoids large PDBs by using a COFF object and a DLL export table;
only `pe_x64_pdb` bundles a (tiny, CRT-free) PDB to exercise the PDB path.

| Fixture | In-zip | Purpose |
| --- | --- | --- |
| `pe_x64` | `.exe` | Canonical x64 console exe: metadata, sections, relocations, `.pdata` exceptions, address space. |
| `pe_x86` | `.exe` | x86 (PE32) header + 32-bit ISA decoding; no exception directory. |
| `pe_x64_pdb` | `.exe` + `.pdb` | PDB-based symbol path (`/NODEFAULTLIB` build keeps the PDB tiny). |
| `pe_x64_obj` | `.obj` | COFF object (`IsCoffOnly`): no entry point, object kind, COFF symbol table. |
| `pe_x64_dll` | `.dll` | DLL exports + shared-library kind + export-table name resolution. |
| `pe_x64_exc` | `.exe` | C++ try/catch (FH4) plus `__try/__except` (SEH): personality routine, scope-table handler, multi-catch. Built `/MD`. |
| `pe_x64_exc_fh3` | `.exe` | Same source built with `/d2FH4-` so the C++ catch uses the classic FH3 format. |
| `pe_x64_guardcf` | `.exe` | Control Flow Guard function table in the load configuration: the call targets the loader vouches for. |
| `pe_x64_tls` | `.exe` | Thread-local storage directory with two callbacks, which nothing else in the image names. |

Build notes: most fixtures are built with `cl /O2`; `pe_x64_pdb` uses
`cl /Zi /Od /GS- /c` + `link /DEBUG /NODEFAULTLIB /ENTRY:main`; the exception
fixtures use `cl /EHsc /O1 /MD` (the `/MD` dynamic CRT keeps them tiny);
`pe_x64_guardcf` uses `cl /O1 /MD /guard:cf` with `/link /guard:cf`, and
`pe_x64_tls` uses `cl /O1 /MD` over a source putting its callbacks in
`.CRT$XLB`. Neither of those two can drop the CRT: the guard table rides on
`_load_config_used` and the callback array on `_tls_used`, and the CRT is
what supplies both.
