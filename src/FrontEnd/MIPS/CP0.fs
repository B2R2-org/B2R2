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
  /// Where DERET resumes.
  | DEPC = 0x115
  /// Where ERET resumes when Status.ERL says the last exception was an error
  /// rather than an ordinary one.
  | ErrorEPC = 0x116

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
       0, 1, CP0Register.VPControl
       8, 0, CP0Register.BadVAddr
       9, 0, CP0Register.Count
       10, 0, CP0Register.EntryHi
       11, 0, CP0Register.Compare
       12, 0, CP0Register.Status
       13, 0, CP0Register.Cause
       14, 0, CP0Register.EPC
       15, 0, CP0Register.PRId
       16, 0, CP0Register.Config
       24, 0, CP0Register.DEPC
       30, 0, CP0Register.ErrorEPC |]

  /// Every CP0 register modelled here.
  let modelled = table |> Array.map (fun (_, _, reg) -> reg)

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
  let writeMask reg =
    match reg with
    (* The index field only. P (bit 31) is set by TLBP and read-only. Six bits
       covers the 64-entry TLB of the usual MIPS64 cores. *)
    | CP0Register.Index -> 0x3FUL
    (* Written by the exception path alone. *)
    | CP0Register.BadVAddr -> 0UL
    | CP0Register.Count -> 0xFFFFFFFFUL
    (* Compare is fully writable; the side effect (clearing Cause.TI) is NOT
       modelled here -- there is no interrupt path to clear. *)
    | CP0Register.Compare -> 0xFFFFFFFFUL
    (* R (63:62), VPN2 (61:13) and ASID (7:0). Bits 12:8 are reserved. *)
    | CP0Register.EntryHi -> 0xFFFFFFFFFFFFE0FFUL
    (* CU3..CU0, RP, FR, RE, MX, BEV, TS, SR, NMI, IM7..IM0, KSU, ERL, EXL,
       IE. The impl-dependent and Config-gated bits are left read-only. *)
    | CP0Register.Status -> 0xF4C0FF1FUL
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
    (* K0, the cache-coherency attribute of kseg0, is the only writable field.*)
    | CP0Register.Config -> 0x7UL
    | _ -> 0UL

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
  let resetValue reg =
    match reg with
    (* Company 0, processor ID 0x89 (5KE), revision 0x00. *)
    | CP0Register.PRId -> 0x00000000_00018900UL
    | CP0Register.Config -> 0x00000000_80004482UL
    (* BEV alone. ERL is already clear by the time a freestanding image runs,
       the boot path that would have cleared it having run first. *)
    | CP0Register.Status -> 0x00000000_00400000UL
    | _ -> 0UL

  /// The name objdump prints for a register, used by the disassembler.
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
    | CP0Register.Config -> "c0_config"
    | _ -> "c0_unknown"
