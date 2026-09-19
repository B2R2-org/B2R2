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

namespace B2R2.FrontEnd.MIPS

open B2R2

/// <summary>
/// Represents a CP0 (System Control Coprocessor) register.
///
/// <para>A CP0 register is named by a (rd, sel) PAIR rather than by a single
/// number, so the pair cannot BE the RegisterID: deriving one arithmetically
/// from the two fields leaves gaps, and a RegisterID has to be a dense index
/// from zero. <c>RegisterSet</c> uses it directly as a bit position and is
/// sized for the widest architecture there is, so a sparse id lands outside
/// the set and every pass that collects register uses throws on it. The ids
/// below therefore run on from the highest the MIPS register set already uses
/// (ULR at 0x109), and the pair each one answers to is a table rather than a
/// shift.</para>
///
/// <para>The register numbers were verified against binutils: assembling
/// <c>mfc0 $8, $12</c> for mips64r2 yields 0x40086000, which objdump renders
/// as <c>mfc0 a4, c0_status</c> -- rd = 12 is Status. The same check fixed
/// Index=0, BadVAddr=8, Count=9, EntryHi=10, Compare=11, Cause=13, EPC=14,
/// PRId=15 and Config=16 (sel 1 of which is Config1).</para>
/// </summary>
type CP0Register =
  /// TLB index for TLBR / TLBWI. Bit 31 (P) is set by TLBP and read-only.
  | Index = 0x10A
  /// Virtual-processor control, which DVP and EVP read and change.
  | VPControl = 0x10B
  /// Which entry TLBWR writes. Read-only, and the one register here whose
  /// VALUE no model can be right about -- see the write mask below.
  | Random = 0x122
  /// Faulting virtual address. Written by hardware only; read-only to MTC0.
  | BadVAddr = 0x10C
  /// Free-running counter half of the CP0 timer.
  | Count = 0x10D
  /// VPN2 and ASID of the TLB entry a TLB instruction reads or writes.
  | EntryHi = 0x10E
  /// Compare half of the CP0 timer: a match raises the timer interrupt, and
  /// writing it clears that interrupt.
  | Compare = 0x10F
  /// Processor status and control: interrupt masks and the operating mode.
  | Status = 0x110
  /// Cause of the last exception. Mostly written by hardware.
  | Cause = 0x111
  /// Exception program counter: where ERET returns to.
  | EPC = 0x112
  /// Processor identification. Entirely read-only.
  | PRId = 0x113
  /// Configuration register 0. Only the K0 cache-coherency field is writable.
  | Config = 0x114
  /// Configuration register 1, which says how big the TLB and the caches
  /// are. Entirely read-only.
  | Config1 = 0x11D
  /// Configuration register 2, whose top bit says Config3 follows it.
  /// Entirely read-only.
  | Config2 = 0x11E
  /// Configuration register 3, which announces the optional features a core
  /// has -- segmentation control and the extended virtual addressing among
  /// them. Entirely read-only.
  | Config3 = 0x11F
  /// Configuration register 4. Entirely read-only.
  | Config4 = 0x120
  /// Configuration register 5, which is where the extended virtual
  /// addressing is switched on where a core has it.
  | Config5 = 0x121
  /// How large a page the TLB can hold, and -- the part that matters here --
  /// whether the extended PHYSICAL addressing is switched on.
  | PageGrain = 0x123
  /// Where DERET resumes.
  | DEPC = 0x115
  /// Where ERET resumes when Status.ERL says the last exception was an error
  /// rather than an ordinary one.
  | ErrorEPC = 0x116
  /// The even page of the pair a TLB entry holds: its physical page number
  /// and the attributes that go with it.
  | EntryLo0 = 0x117
  /// The odd page of that pair.
  | EntryLo1 = 0x118
  /// A pointer into the page table, which a refill handler reads to find the
  /// entry the faulting address needs.
  | Context = 0x119
  /// How big the pair of pages a TLB entry maps is.
  | PageMask = 0x11A
  /// How many entries at the bottom of the TLB a random replacement must not
  /// touch.
  | Wired = 0x11B
  /// Context's counterpart for a 64-bit address space.
  | XContext = 0x11C

/// Provides the (rd, sel) mapping and the write/reset behaviour of the CP0
/// registers this front end models.
[<RequireQualifiedAccess>]
module CP0 =
  /// <summary>
  /// Every CP0 register modelled here, with the (rd, sel) pair that names it.
  ///
  /// Anything outside this table is unimplemented, which Release 6 defines
  /// rather than leaving UNDEFINED: "Reading a reserved register or a
  /// register that is not implemented for the current core configuration
  /// returns 0" (MFC0, MD00087 rev 6.06) and "Writes to a register that is
  /// reserved or not defined for the current core configuration are ignored"
  /// (MTC0). The lifter follows that rule for every unmodelled pair, on every
  /// release: a defined answer is more use to a caller than a faithful
  /// UNDEFINED one.
  /// </summary>
  let private table =
    [| 0, 0, CP0Register.Index
       (* VPControl is select FOUR, not one. One is MVPControl, which the
          multithreading ASE defines and which binutils names as such; a
          reference reading select one while DVP had set VPControl's DIS bit
          answered zero, which is what showed the pair apart. *)
       0, 4, CP0Register.VPControl
       1, 0, CP0Register.Random
       2, 0, CP0Register.EntryLo0
       3, 0, CP0Register.EntryLo1
       4, 0, CP0Register.Context
       5, 0, CP0Register.PageMask
       5, 1, CP0Register.PageGrain
       6, 0, CP0Register.Wired
       8, 0, CP0Register.BadVAddr
       9, 0, CP0Register.Count
       10, 0, CP0Register.EntryHi
       11, 0, CP0Register.Compare
       12, 0, CP0Register.Status
       13, 0, CP0Register.Cause
       14, 0, CP0Register.EPC
       15, 0, CP0Register.PRId
       16, 0, CP0Register.Config
       16, 1, CP0Register.Config1
       16, 2, CP0Register.Config2
       16, 3, CP0Register.Config3
       16, 4, CP0Register.Config4
       16, 5, CP0Register.Config5
       20, 0, CP0Register.XContext
       24, 0, CP0Register.DEPC
       30, 0, CP0Register.ErrorEPC |]

  /// <summary>
  /// How many entries the TLB has.
  ///
  /// It is a property of the processor, not of the architecture: Config1
  /// bits 30..25 hold this number minus one, and a model that answered a
  /// different count there would be a different processor. Thirty-two is what
  /// the 5KEf reports and sixty-four is what the Release 5 processor below
  /// does, which is also what its Wired register's six-bit field says.
  /// </summary>
  let entryCount (wordSize: WordSize) =
    if wordSize = WordSize.Bit32 then 64 else 32

  /// The most any of them has, which is how much storage is laid out. A
  /// machine that has fewer simply never names the rest.
  let [<Literal>] MaxEntryCount = 64

  /// <summary>
  /// Where the TLB's own storage begins, as a RegisterID.
  ///
  /// A TLB entry is not a coprocessor 0 register: no (rd, sel) pair names
  /// one, and no MFC0 reads one. What it is is state, and the only state
  /// this front end has is registers -- so the array is four registers per
  /// entry, laid out end to end from here, and the instructions that read and
  /// write it do so by index. The base is above every named register so that
  /// adding one never collides.
  /// </summary>
  let [<Literal>] private TLBBase = 0x200

  /// The four values one TLB entry holds, in the order they are laid out.
  type TLBField =
    /// The virtual page number and address space id the entry matches on.
    | Hi = 0
    /// The even page of the pair: its physical page number and attributes.
    | Lo0 = 1
    /// The odd page of the pair.
    | Lo1 = 2
    /// How big the pair of pages is.
    | Mask = 3

  /// The register holding one field of one entry.
  let tlbReg (index: int) (field: TLBField): CP0Register =
    LanguagePrimitives.EnumOfValue(TLBBase + index * 4 + int field)

  /// Every register the TLB's storage takes, which is four per entry.
  let tlbRegs =
    [| for i in 0 .. MaxEntryCount - 1 do
         for f in 0 .. 3 do
           yield tlbReg i (LanguagePrimitives.EnumOfValue f) |]

  /// Whether a register is one of those, and which entry and field it is.
  let (|TLBStorage|_|) (reg: CP0Register) =
    let v = int reg - TLBBase
    if v >= 0 && v < MaxEntryCount * 4 then Some(v / 4, v % 4) else None

  /// Every CP0 register modelled here, the TLB's own storage included: the
  /// entries are not addressable by MFC0, but they are state a lifter reads
  /// and writes and so are variables like the rest.
  let modelled =
    Array.append (table |> Array.map (fun (_, _, reg) -> reg)) tlbRegs

  /// Returns the modelled CP0 register a (rd, sel) pair names, or ValueNone
  /// when the pair is not implemented here.
  let tryOfRdSel rd sel =
    match table |> Array.tryFind (fun (r, s, _) -> r = rd && s = sel) with
    | Some(_, _, reg) -> ValueSome reg
    | None -> ValueNone

  /// Which bits a write actually changes. Hardware keeps the rest at their
  /// old value, so a write-then-read test only round-trips through this mask.
  ///
  /// These masks come from the MIPS64 Privileged Resource Architecture
  /// (MD00091), NOT from the instruction-set manual (MD00087, which documents
  /// the MFC0/MTC0 ENCODING but not the register layouts). They are the
  /// conservative subset every MIPS64 core agrees on; a real core's mask
  /// depends on its configuration -- TLB size sets how much of Index is
  /// writable, and Config3/Config5 gate several Status bits -- so a mask that
  /// has to be exact is a property of one named processor.
  let private release2WriteMask reg =
    match reg with
    (* The index field only. P (bit 31) is set by TLBP and read-only, and the
       field is as wide as the number of entries needs -- five bits for the
       thirty-two this front end keeps, which is what Config1 reports. *)
    | CP0Register.Index -> uint64 (entryCount WordSize.Bit64 - 1)
    (* Written by the exception path alone. *)
    | CP0Register.BadVAddr -> 0UL
    | CP0Register.Count -> 0xFFFFFFFFUL
    (* Compare is fully writable; the side effect (clearing Cause.TI) is NOT
       modelled here -- there is no interrupt path to clear. *)
    | CP0Register.Compare -> 0xFFFFFFFFUL
    (* R (63:62), VPN2 and ASID (7:0), with bits 12:8 reserved. How much of
       VPN2 is writable is how wide the processor's physical address space
       is: a 5KEf keeps 61:40 clear, which is what makes this 0xC00003FF
       above the ASID rather than all ones. Measured by writing all ones and
       reading back, the way the rest of these were. *)
    | CP0Register.EntryHi -> 0xC00003FFFFFFE0FFUL
    (* PFN, and the C, D, V and G attributes below it. The width of PFN is
       again the processor's physical address space. *)
    | CP0Register.EntryLo0 -> 0x3FFFFFFFUL
    | CP0Register.EntryLo1 -> 0x3FFFFFFFUL
    (* PTEBase alone: the rest is the faulting address, which the exception
       path writes and a program cannot. *)
    | CP0Register.Context -> 0xFFFFFFFFFF800000UL
    (* The mask field, 28:13, which is why only whole page sizes can be
       named. *)
    | CP0Register.PageMask -> 0x1FFFE000UL
    (* As many bits as there are entries to keep, which is six on a processor
       with forty-eight of them and five on this one. *)
    | CP0Register.Wired -> 0x1FUL
    (* PTEBase again, above the region and the bad virtual page number. *)
    | CP0Register.XContext -> 0xFFFFFFF800000000UL
    (* Measured rather than read off the field list, which is what the
       constant here used to be and which named six fields the value did not
       actually carry. On the 5KEf the rest of this file describes: CU1, CU0,
       FR, RE, PX, BEV, TS, SR, NMI, IM7..IM0 and the three implementation
       bits at 7..5, plus KSU, ERL, EXL and IE at the bottom. CU3 and CU2 are
       NOT writable -- the processor has no coprocessor 3 or 2 -- and neither
       are RP and MX. *)
    | CP0Register.Status -> 0x36F8FFFFUL
    (* DC (27), IV (23), WP (22) and the two software interrupt bits IP1..IP0
       (9:8). Everything else records what the last exception was.
       DC is a per-processor knob, and both sides of it were measured. Writing
       0x8badf00d to Cause reads back
         0x00800000  on a 20Kc  (PRId 0x000182a0), and
         0x08800000  on a 5KEf  (PRId 0x00018900),
       so bit 27 is writable on the Release 2 core and not on the Release 1
       one. The mask below is the 5KEf's. Another processor moves this line --
       which is the whole reason it is one function and not a constant folded
       into the lifter. *)
    | CP0Register.Cause -> 0x08C00300UL
    | CP0Register.EPC -> 0xFFFFFFFFFFFFFFFFUL
    | CP0Register.DEPC -> 0xFFFFFFFFFFFFFFFFUL
    | CP0Register.ErrorEPC -> 0xFFFFFFFFFFFFFFFFUL
    (* DIS, bit 0. The rest records which processors there are, which is the
       hardware's to say. *)
    | CP0Register.VPControl -> 0x1UL
    (* Entirely read-only. *)
    | CP0Register.PRId -> 0UL
    (* Read-only as well, and the reason is worth keeping. Random is the entry
       TLBWR writes, and the architecture says it decrements AS THE PROCESSOR
       RUNS, between Wired and the last entry. The rate is the one thing a
       lifter has no way to have: it has no clock. What it can have is the
       range and the direction, so the register is stepped by TLBWR itself --
       which is a conforming sequence, because software is forbidden from
       depending on any particular one. *)
    | CP0Register.Random -> 0UL
    (* K0, the cache-coherency attribute of kseg0, is the only writable field.*)
    | CP0Register.Config -> 0x7UL
    (* What the processor has, which a program reads and cannot change. The
       later ones are read-only on this processor as well: Config5 carries
       writable bits only on a core that has the features they switch on, and
       this one has none of them. *)
    | CP0Register.Config1 -> 0UL
    | CP0Register.Config2 -> 0UL
    | CP0Register.Config3 -> 0UL
    | CP0Register.Config4 -> 0UL
    (* EVA, bit 28, and nothing else. It is the one bit of the Config
       registers this front end does NOT take from the processor the rest of
       them were measured on, and the reason is that the front end is already
       a processor that has the extended virtual addressing: it decodes and
       lifts LBE, LWE, SBE and the rest unconditionally. A Config5 that
       answered zero would announce a processor without them while executing
       them, and a guest that asks before it issues one -- which is what the
       architecture tells it to do -- would be told the wrong thing. The rest
       of the register stays read-only: those bits switch on features this
       front end does not have. *)
    | CP0Register.Config5 -> 0x10000000UL
    | _ -> 0UL

  /// <summary>
  /// Whether the register is thirty-two bits wide, which decides what DMFC0
  /// answers.
  ///
  /// A MIPS64 processor holds the registers that carry an address or a page
  /// number at the full width and the rest at thirty-two. A thirty-two bit
  /// value moved into a sixty-four bit register is SIGN extended, the way
  /// every thirty-two bit value on this architecture travels, so the
  /// difference shows on the first read of a register whose top bit is set:
  /// Config reads 0x80004482 on the processor this file describes, and a
  /// zero extension answers 0x0000000080004482 where the processor answers
  /// 0xFFFFFFFF80004482.
  /// </summary>
  let isWord reg =
    match reg with
    | CP0Register.EntryLo0
    | CP0Register.EntryLo1
    | CP0Register.Context
    | CP0Register.BadVAddr
    | CP0Register.EntryHi
    | CP0Register.EPC
    | CP0Register.XContext
    | CP0Register.DEPC
    | CP0Register.ErrorEPC -> false
    | _ -> true

  /// The value a register holds out of reset, so that reading one whose write
  /// mask is zero still shows something.
  ///
  /// No lifter applies these: an instruction cannot set the state a machine
  /// starts in, and nothing in this front end runs before the first one does.
  /// They are here because they were measured on a real processor rather than
  /// chosen, and because whoever models a reset needs them then rather than
  /// having to measure them again.
  ///
  /// They are what a 5KEf on a Malta board holds at the point a freestanding
  /// image gets control. They describe THAT core and that board rather than an
  /// invented processor, and another one gives other values -- the same read
  /// on a 20Kc gives PRId 0x000182a0 and Config 0x8000408a instead.
  let private release2ResetValue reg =
    match reg with
    (* Company 0, processor ID 0x89 (5KE), revision 0x00. *)
    | CP0Register.PRId -> 0x00000000_00018900UL
    | CP0Register.Config -> 0x00000000_80004482UL
    (* Measured on the same 5KEf: Config2 follows (bit 31), the TLB has
       thirty-two entries (bits 30..25 hold that number minus one), and the
       rest describes caches this front end does not model. *)
    | CP0Register.Config1 -> 0x00000000_BE61309BUL
    (* Its top bit alone, which says Config3 follows it. Config3's own top
       bit is clear, and Config3, Config4 and Config5 all read zero: this
       processor announces none of the optional features they describe. *)
    | CP0Register.Config2 -> 0x00000000_80000000UL
    (* BEV alone. ERL is already clear by the time a freestanding image runs,
       the boot path that would have cleared it having run first. *)
    | CP0Register.Status -> 0x00000000_00400000UL
    (* The last entry, which is where a processor's own replacement pointer
       starts. *)
    | CP0Register.Random -> uint64 (entryCount WordSize.Bit64 - 1)
    | _ -> 0UL

  /// <summary>
  /// The same two tables for a MIPS32 Release 5 processor, which is a
  /// different machine and not the one above narrowed.
  ///
  /// Measured the same way the ones above were, on the processor a 32-bit
  /// guest is lifted against. Almost every value differs, and two of the
  /// differences are more than a width: the TLB has SIXTY-FOUR entries, which
  /// its Wired register's six-bit field is what says; and EntryLo is wider
  /// than the machine, because the extended physical addressing puts four
  /// more bits of page frame number above the thirty-two a move reaches.
  ///
  /// Those four are not there until PageGrain switches them on, so EntryLo's
  /// mask is not a constant on this processor and is not answered here -- see
  /// the lifter, which asks the register.
  /// </summary>
  let private release5WriteMask reg =
    match reg with
    | CP0Register.Index -> uint64 (entryCount WordSize.Bit32 - 1)
    | CP0Register.BadVAddr -> 0UL
    | CP0Register.Count -> 0xFFFFFFFFUL
    (* Without the extended physical addressing. With it the whole of the low
       half is writable and four bits of the high half with it, which the
       lifter works out from PageGrain. *)
    | CP0Register.EntryLo0 | CP0Register.EntryLo1 -> 0x03FFFFFFUL
    | CP0Register.Context -> 0xFF800000UL
    | CP0Register.PageMask -> 0x1FFFE000UL
    (* The read and execute inhibit bits, the extended physical addressing,
       the small-page support and the inhibit-exception control. *)
    | CP0Register.PageGrain -> 0xE8000000UL
    | CP0Register.Wired -> 0x3FUL
    | CP0Register.EntryHi -> 0xFFFFE4FFUL
    | CP0Register.Compare -> 0xFFFFFFFFUL
    | CP0Register.Status -> 0x3C68FF1FUL
    | CP0Register.Cause -> 0x08C00300UL
    | CP0Register.EPC -> 0xFFFFFFFFUL
    | CP0Register.DEPC -> 0xFFFFFFFFUL
    | CP0Register.ErrorEPC -> 0xFFFFFFFFUL
    | CP0Register.VPControl -> 0x1UL
    | CP0Register.PRId -> 0UL
    | CP0Register.Config -> 0x7UL
    | CP0Register.Config1 -> 0UL
    | CP0Register.Config2 -> 0UL
    | CP0Register.Config3 -> 0UL
    | CP0Register.Config4 -> 0UL
    (* This processor HAS the features the others gate, so most of the
       register is writable rather than one bit of it. *)
    | CP0Register.Config5 -> 0x7800033CUL
    | _ -> 0UL

  /// What a Release 5 processor holds out of reset. The Config registers are
  /// where it says what it has, and it says a great deal more than the one
  /// above: the extended virtual addressing, the extended physical
  /// addressing, and the pair of moves that reach the top of a register.
  let private release5ResetValue reg =
    match reg with
    | CP0Register.PRId -> 0x00000000_0001A800UL
    | CP0Register.Config -> 0x00000000_80040482UL
    | CP0Register.Config1 -> 0x00000000_FEA3519BUL
    | CP0Register.Config2 -> 0x00000000_80000000UL
    | CP0Register.Config3 -> 0x00000000_BF0030A0UL
    | CP0Register.Config4 -> 0x00000000_C01C0000UL
    | CP0Register.Config5 -> 0x00000000_10000038UL
    | CP0Register.Status -> 0x00000000_00400000UL
    | CP0Register.Random -> uint64 (entryCount WordSize.Bit32 - 1)
    | _ -> 0UL

  /// Which bits a write changes, on the processor the word size names.
  let writeMask (wordSize: WordSize) reg =
    if wordSize = WordSize.Bit32 then release5WriteMask reg
    else release2WriteMask reg

  /// What the register holds out of reset, on that same processor.
  let resetValue (wordSize: WordSize) reg =
    if wordSize = WordSize.Bit32 then release5ResetValue reg
    else release2ResetValue reg

  /// <summary>
  /// The bit of PageGrain that switches the extended physical addressing on,
  /// which is what gives EntryLo more bits than a move reaches.
  /// </summary>
  let [<Literal>] ExtendedPhysical = 0x20000000UL

  /// What EntryLo keeps once that bit is set: the whole of the low half --
  /// the read and execute inhibit bits at the top of it come with the
  /// feature -- and four more of page frame number above it.
  let [<Literal>] ExtendedEntryLo = 0xFFFFFFFFFUL

  /// The name objdump prints for a register, used by the disassembler.
  /// What each of an entry's four fields is called. Nothing outside this
  /// front end names them, so the spelling only has to be readable.
  let private tlbNames = [| "hi"; "lo0"; "lo1"; "mask" |]

  /// The name one field of one TLB entry is printed under.
  let private tlbName index field = $"tlb{index}_{tlbNames[field]}"

  let toString reg =
    match reg with
    | CP0Register.Index -> "c0_index"
    | CP0Register.BadVAddr -> "c0_badvaddr"
    | CP0Register.Count -> "c0_count"
    | CP0Register.EntryHi -> "c0_entryhi"
    | CP0Register.Compare -> "c0_compare"
    | CP0Register.Status -> "c0_status"
    | CP0Register.Cause -> "c0_cause"
    | CP0Register.EPC -> "c0_epc"
    | CP0Register.DEPC -> "c0_depc"
    | CP0Register.ErrorEPC -> "c0_errorepc"
    | CP0Register.VPControl -> "c0_vpcontrol"
    | CP0Register.PRId -> "c0_prid"
    | CP0Register.Random -> "c0_random"
    | CP0Register.Config -> "c0_config"
    | CP0Register.Config1 -> "c0_config1"
    | CP0Register.Config2 -> "c0_config2"
    | CP0Register.Config3 -> "c0_config3"
    | CP0Register.Config4 -> "c0_config4"
    | CP0Register.Config5 -> "c0_config5"
    | CP0Register.PageGrain -> "c0_pagegrain"
    | CP0Register.EntryLo0 -> "c0_entrylo0"
    | CP0Register.EntryLo1 -> "c0_entrylo1"
    | CP0Register.Context -> "c0_context"
    | CP0Register.PageMask -> "c0_pagemask"
    | CP0Register.Wired -> "c0_wired"
    | CP0Register.XContext -> "c0_xcontext"
    | TLBStorage(index, field) -> tlbName index field
    | _ -> "c0_unknown"
