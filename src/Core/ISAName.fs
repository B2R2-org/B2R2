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

/// Reads and writes the canonical names of an ISA, which are the names B2R2
/// takes on its command line and prints back.
module internal B2R2.ISAName

/// <summary>
/// Reads and writes the ARM names that say which version they mean: a base
/// name, the version after a dash and each extension after a plus, as in
/// "aarch64-v8.2+fp16" or "thumb-v7ve+simd". GCC's -march names are read as
/// well, as the little-endian base of their architecture: "armv8.2-a+fp16" is
/// "aarch64-v8.2+fp16" and "armv7ve" is "armv7-v7ve".
/// </summary>
module private ARMVersion =
  let private arm = ARM32Mode.ARM
  let private thumb = ARM32Mode.Thumb

  let private bases =
    [ "aarch64", (Architecture.ARMv8, Endian.Little, WordSize.Bit64, arm)
      "aarch64be", (Architecture.ARMv8, Endian.Big, WordSize.Bit64, arm)
      "armv7", (Architecture.ARMv7, Endian.Little, WordSize.Bit32, arm)
      "armv7be", (Architecture.ARMv7, Endian.Big, WordSize.Bit32, arm)
      "thumb", (Architecture.ARMv7, Endian.Little, WordSize.Bit32, thumb)
      "thumbbe", (Architecture.ARMv7, Endian.Big, WordSize.Bit32, thumb) ]

  let private aarch64Versions =
    [ "v8", ARMArchVersion.V8
      "v8.1", ARMArchVersion.V8_1
      "v8.2", ARMArchVersion.V8_2
      "v8.3", ARMArchVersion.V8_3
      "v8.4", ARMArchVersion.V8_4
      "v8.5", ARMArchVersion.V8_5
      "v8.6", ARMArchVersion.V8_6 ]

  let private armv7Versions =
    [ "v7", ARMArchVersion.V7
      "v7ve", ARMArchVersion.V7VE ]

  let private aarch64Extensions =
    [ "crc", int AArch64Extension.CRC
      "aes", int AArch64Extension.AES
      "sha2", int AArch64Extension.SHA2
      "sha3", int AArch64Extension.SHA3
      "sm4", int AArch64Extension.SM4
      "fp16", int AArch64Extension.FP16
      "fp16fml", int AArch64Extension.FP16FML
      "dotprod", int AArch64Extension.DotProd
      "lse", int AArch64Extension.LSE
      "rdma", int AArch64Extension.RDMA
      "rcpc", int AArch64Extension.RCPC
      "i8mm", int AArch64Extension.I8MM
      "bf16", int AArch64Extension.BF16
      "memtag", int AArch64Extension.MemTag
      "sb", int AArch64Extension.SB
      "flagm", int AArch64Extension.FlagM
      "pauth", int AArch64Extension.PAuth
      "ssbs", int AArch64Extension.SSBS
      "ras", int AArch64Extension.RAS
      "profile", int AArch64Extension.SPE
      "trf", int AArch64Extension.TRF ]

  let private armv7Extensions =
    [ "fp", int ARMv7Extension.FP
      "simd", int ARMv7Extension.SIMD
      "vfpv4", int ARMv7Extension.VFPv4
      "fp16", int ARMv7Extension.FP16
      "idiv", int ARMv7Extension.IDIV
      "mp", int ARMv7Extension.MP
      "sec", int ARMv7Extension.Sec
      "virt", int ARMv7Extension.Virt ]

  (* GCC's name for the Armv8.0 Cryptographic Extension, which is two of the
     features above; it is read but never printed. *)
  let private crypto =
    "crypto", int (AArch64Extension.AES ||| AArch64Extension.SHA2)

  let lookup key pairs =
    List.tryFind (fun (k, _) -> k = key) pairs |> Option.map snd

  let fromGCC (head: string) =
    match head with
    | "armv7-a" ->
      Some("armv7", "v7")
    | "armv7ve" ->
      Some("armv7", "v7ve")
    | "armv8-a" ->
      Some("aarch64", "v8")
    | _ when head.StartsWith "armv8." && head.EndsWith "-a" ->
      Some("aarch64", "v" + head.Substring(4, head.Length - 6))
    | _ ->
      None

  let splitBase (head: string) =
    match fromGCC head, head.LastIndexOf '-' with
    | Some pair, _ -> Some pair
    | None, i when i > 0 -> Some(head.Substring(0, i), head.Substring(i + 1))
    | None, _ -> None

  let versionsOf arch =
    if arch = Architecture.ARMv8 then aarch64Versions else armv7Versions

  let extensionsOf arch =
    if arch = Architecture.ARMv8 then crypto :: aarch64Extensions
    else armv7Extensions

  let extensionBits arch (names: string[]) =
    let bits = names |> Array.map (fun n -> lookup n (extensionsOf arch))
    if Array.forall Option.isSome bits then
      Some(Array.fold (fun acc b -> acc ||| Option.get b) 0 bits)
    else
      None

  let flagsOf arch mode verName extNames =
    match lookup verName (versionsOf arch), extensionBits arch extNames with
    | Some version, Some exts -> Some(ISAFlags.ofARM mode version exts)
    | _ -> None

  /// <summary>
  /// Reads what a name that says its version means: the architecture,
  /// endianness and word size of its base, and flags holding the instruction
  /// set, the version and the extensions. Nothing for any other name.
  /// </summary>
  let tryParse (name: string) =
    let parts = name.Split '+'
    match splitBase parts[0] with
    | Some(baseName, verName) ->
      match lookup baseName bases with
      | Some(arch, endian, wordSize, mode) ->
        flagsOf arch mode verName parts[1..]
        |> Option.map (fun flags -> arch, endian, wordSize, flags)
      | None ->
        None
    | None ->
      None

  [<return: Struct>]
  let (|Versioned|_|) name =
    match tryParse name with
    | Some isa -> ValueSome isa
    | None -> ValueNone

  /// Returns the name an ARM ISA with a version prints as: its base name, the
  /// version after a dash, and each extension after a plus, in the order
  /// above.
  let print baseName arch (version: ARMArchVersion) exts =
    let verName = versionsOf arch |> List.find (fun (_, v) -> v = version)
    let named =
      extensionsOf arch
      |> List.filter (fun (n, bit) -> n <> fst crypto && (exts &&& bit) = bit)
    baseName + "-" + fst verName
    + String.concat "" [ for n, _ in named -> "+" + n ]

/// Reads what a canonical ISA name means, or UnknownISA when it is not a
/// name this knows.
let parse (isaName: string) =
  (* The three MIPS encodings sit in the same flags word as the release, so
     a name that says both hands over both. Named here because the arms
     below are one line each. *)
  let umips = int MIPSISAMode.MicroMIPS
  let umips6 = int MIPSRelease.R6 ||| int MIPSISAMode.MicroMIPS
  let m16 = int MIPSISAMode.MIPS16
  match isaName.ToLowerInvariant() with
  | ARMVersion.Versioned(arch, endian, wordSize, flags) ->
    arch, endian, wordSize, flags
  | "x86" | "i386" ->
    ISADefaults.ofArchWordSize Architecture.Intel WordSize.Bit32
  | "x64" | "x86-64" | "amd64" ->
    ISADefaults.ofArchWordSize Architecture.Intel WordSize.Bit64
  | "armv7" | "armv7le" | "armel" | "armhf" | "arm32" | "arm" ->
    ISADefaults.ofArch Architecture.ARMv7
  | "armv7be" ->
    ISADefaults.ofArchEndian Architecture.ARMv7 Endian.Big
  | "thumb" | "t32" ->
    ISADefaults.ofARM32Mode Endian.Little false ARM32Mode.Thumb
  | "thumbbe" | "t32be" ->
    ISADefaults.ofARM32Mode Endian.Big false ARM32Mode.Thumb
  | "armv8a32" | "aarch32" ->
    ISADefaults.ofArchWordSize Architecture.ARMv8 WordSize.Bit32
  | "armv8a32be" | "aarch32be" ->
    Architecture.ARMv8, Endian.Big, WordSize.Bit32, 0
  | "aarch32t" ->
    ISADefaults.ofARM32Mode Endian.Little true ARM32Mode.Thumb
  | "aarch32tbe" ->
    ISADefaults.ofARM32Mode Endian.Big true ARM32Mode.Thumb
  | "armv8a64" | "aarch64" | "arm64" ->
    ISADefaults.ofArch Architecture.ARMv8
  | "armv8a64be" | "aarch64be" ->
    ISADefaults.ofArchEndian Architecture.ARMv8 Endian.Big
  | "mipsel" | "mips32le" ->
    Architecture.MIPS, Endian.Little, WordSize.Bit32, 0
  | "mips32" | "mips32be" ->
    Architecture.MIPS, Endian.Big, WordSize.Bit32, 0
  | "mips64el" | "mips64" | "mips64le" ->
    Architecture.MIPS, Endian.Little, WordSize.Bit64, 0
  | "mips64be" ->
    Architecture.MIPS, Endian.Big, WordSize.Bit64, 0
  | "mipsr6el" | "mips32r6el" | "mips32r6le" ->
    Architecture.MIPS, Endian.Little, WordSize.Bit32, int MIPSRelease.R6
  | "mips32r6" | "mips32r6be" ->
    Architecture.MIPS, Endian.Big, WordSize.Bit32, int MIPSRelease.R6
  | "mips64r6el" | "mips64r6" | "mips64r6le" ->
    Architecture.MIPS, Endian.Little, WordSize.Bit64, int MIPSRelease.R6
  | "mips64r6be" ->
    Architecture.MIPS, Endian.Big, WordSize.Bit64, int MIPSRelease.R6
  | "micromipsel" | "micromips32le" ->
    Architecture.MIPS, Endian.Little, WordSize.Bit32, umips
  | "micromips" | "micromips32" | "micromips32be" ->
    Architecture.MIPS, Endian.Big, WordSize.Bit32, umips
  | "micromips64el" | "micromips64le" ->
    Architecture.MIPS, Endian.Little, WordSize.Bit64, umips
  | "micromips64" | "micromips64be" ->
    Architecture.MIPS, Endian.Big, WordSize.Bit64, umips
  | "micromipsr6el" | "micromips32r6le" ->
    Architecture.MIPS, Endian.Little, WordSize.Bit32, umips6
  | "micromips32r6" | "micromips32r6be" ->
    Architecture.MIPS, Endian.Big, WordSize.Bit32, umips6
  | "micromips64r6el" | "micromips64r6le" ->
    Architecture.MIPS, Endian.Little, WordSize.Bit64, umips6
  | "micromips64r6" | "micromips64r6be" ->
    Architecture.MIPS, Endian.Big, WordSize.Bit64, umips6
  | "mips16el" | "mips16le" ->
    Architecture.MIPS, Endian.Little, WordSize.Bit32, m16
  | "mips16" | "mips16be" ->
    Architecture.MIPS, Endian.Big, WordSize.Bit32, m16
  | "mips16-64el" | "mips16-64le" ->
    Architecture.MIPS, Endian.Little, WordSize.Bit64, m16
  | "mips16-64" | "mips16-64be" ->
    Architecture.MIPS, Endian.Big, WordSize.Bit64, m16
  | "ppc32le" ->
    Architecture.PPC, Endian.Little, WordSize.Bit32, 0
  | "ppc32" | "ppc32be" ->
    Architecture.PPC, Endian.Big, WordSize.Bit32, 0
  | "ppc64le" ->
    Architecture.PPC, Endian.Little, WordSize.Bit64, 0
  | "ppc64" | "ppc64be" ->
    Architecture.PPC, Endian.Big, WordSize.Bit64, 0
  | "riscv32" ->
    Architecture.RISCV, Endian.Little, WordSize.Bit32, 0
  | "riscv64" | "riscv" ->
    Architecture.RISCV, Endian.Little, WordSize.Bit64, 0
  | "sparc32" | "sparcv8" ->
    Architecture.SPARC, Endian.Big, WordSize.Bit32, 0
  | "sparc" | "sparc64" ->
    ISADefaults.ofArchEndian Architecture.SPARC Endian.Big
  | "s390" ->
    ISADefaults.ofArchWordSize Architecture.S390 WordSize.Bit32
  | "s390x" ->
    ISADefaults.ofArchWordSize Architecture.S390 WordSize.Bit64
  | "sh4" ->
    ISADefaults.ofArchEndian Architecture.SH4 Endian.Little
  | "sh4be" ->
    ISADefaults.ofArchEndian Architecture.SH4 Endian.Big
  | "parisc" | "hppa" | "hppa32" ->
    ISADefaults.ofArchWordSize Architecture.PARISC WordSize.Bit32
  | "parisc64" | "hppa64" ->
    ISADefaults.ofArchWordSize Architecture.PARISC WordSize.Bit64
  | "m68k" | "68k" ->
    ISADefaults.ofM68KModel M68KModel.M68020
  | "m68000" | "68000" ->
    ISADefaults.ofM68KModel M68KModel.M68000
  | "m68010" | "68010" ->
    ISADefaults.ofM68KModel M68KModel.M68010
  | "m68020" | "68020" ->
    ISADefaults.ofM68KModel M68KModel.M68020
  | "m68030" | "68030" ->
    ISADefaults.ofM68KModel M68KModel.M68030
  | "m68040" | "68040" ->
    ISADefaults.ofM68KModel M68KModel.M68040
  | "m68060" | "68060" ->
    ISADefaults.ofM68KModel M68KModel.M68060
  | "alpha" | "alphaev6" ->
    ISADefaults.ofArch Architecture.Alpha
  | "avr" | "avr8" ->
    ISADefaults.ofArch Architecture.AVR
  | "avr6" ->
    ISADefaults.ofAVRCore AVRCore.Avr6 0UL
  | "tms320c6000" ->
    ISADefaults.ofArch Architecture.TMS320C6000
  | "evm" ->
    ISADefaults.ofArch Architecture.EVM
  | "cil" ->
    ISADefaults.ofArch Architecture.CIL
  (* The bare name takes the default version, the way "m68k" takes a default
     model, so that an input whose version is not the point does not have to
     name one. *)
  | "python" ->
    ISADefaults.ofArch Architecture.Python
  | "python3.0" ->
    ISADefaults.ofPythonVersion PythonVersion.Python300
  | "python3.1" ->
    ISADefaults.ofPythonVersion PythonVersion.Python301
  | "python3.2" ->
    ISADefaults.ofPythonVersion PythonVersion.Python302
  | "python3.3" ->
    ISADefaults.ofPythonVersion PythonVersion.Python303
  | "python3.4" ->
    ISADefaults.ofPythonVersion PythonVersion.Python304
  | "python3.5" ->
    ISADefaults.ofPythonVersion PythonVersion.Python305
  | "python3.6" ->
    ISADefaults.ofPythonVersion PythonVersion.Python306
  | "python3.7" ->
    ISADefaults.ofPythonVersion PythonVersion.Python307
  | "python3.8" ->
    ISADefaults.ofPythonVersion PythonVersion.Python308
  | "python3.9" ->
    ISADefaults.ofPythonVersion PythonVersion.Python309
  | "python3.10" ->
    ISADefaults.ofPythonVersion PythonVersion.Python310
  | "python3.11" ->
    ISADefaults.ofPythonVersion PythonVersion.Python311
  | "python3.12" ->
    ISADefaults.ofPythonVersion PythonVersion.Python312
  | "python3.13" ->
    ISADefaults.ofPythonVersion PythonVersion.Python313
  | "python3.14" ->
    ISADefaults.ofPythonVersion PythonVersion.Python314
  | "python3.15" ->
    ISADefaults.ofPythonVersion PythonVersion.Python315
  | "wasm" ->
    ISADefaults.ofArch Architecture.WASM
  | "bpf" | "ebpf" | "bpfel" ->
    ISADefaults.ofArch Architecture.BPF
  | "bpfeb" ->
    ISADefaults.ofArchEndian Architecture.BPF Endian.Big
  | _ ->
    ISADefaults.ofArch Architecture.UnknownISA

(* A version is part of what an ARM ISA reads, so a name that left it out
   would read back as every encoding rather than the version's. *)
let private armName baseName arch flags =
  match ISAFlags.armArchVersion flags with
  | ARMArchVersion.Any -> baseName
  | v -> ARMVersion.print baseName arch v (ISAFlags.armExtensions flags)

(* Which encoding a MIPS ISA is read in belongs in its name for the same
   reason the release does: the three have separate opcode maps, so a name
   that left it out would print an ISA that reads a different instruction
   set from the one it names.
   MIPS16e has no Release 6 spelling because Release 6 removed the ASE. *)
let private mipsName endian wordSize flags =
  let le = endian = Endian.Little
  let w64 = wordSize = WordSize.Bit64
  let width = if w64 then "64" else "32"
  let rel = if ISAFlags.mipsRelease flags = MIPSRelease.R6 then "r6" else ""
  match ISAFlags.mipsISAMode flags with
  | MIPSISAMode.MicroMIPS ->
    "micromips" + width + rel + (if le then "le" else "")
  | MIPSISAMode.MIPS16 ->
    (if w64 then "mips16-64" else "mips16") + (if le then "le" else "")
  | _ ->
    (* The big-endian 64-bit name carries its "be" where the 32-bit one
       does not, because "mips64" already names the LITTLE-endian one in
       the table above: printing a big-endian MIPS64 as "mips64" made it
       read back as a different ISA. The Release 6 arm never had that. *)
    "mips" + width + rel + (if le then "le" elif w64 then "be" else "")

/// Returns the name an ISA prints as, which is one that reads back as the
/// same ISA.
let print arch endian wordSize flags =
  let thumb = ISAFlags.arm32Mode flags = ARM32Mode.Thumb
  match arch, endian, wordSize with
  | Architecture.Intel, _, WordSize.Bit32 ->
    "x86"
  | Architecture.Intel, _, WordSize.Bit64 ->
    "x86-64"
  | Architecture.ARMv7, Endian.Little, _ ->
    armName (if thumb then "thumb" else "armv7") arch flags
  | Architecture.ARMv7, Endian.Big, _ ->
    armName (if thumb then "thumbbe" else "armv7be") arch flags
  | Architecture.ARMv8, Endian.Little, WordSize.Bit32 ->
    if thumb then "aarch32t" else "aarch32"
  | Architecture.ARMv8, Endian.Big, WordSize.Bit32 ->
    if thumb then "aarch32tbe" else "aarch32be"
  | Architecture.ARMv8, Endian.Little, WordSize.Bit64 ->
    armName "aarch64" arch flags
  | Architecture.ARMv8, Endian.Big, WordSize.Bit64 ->
    armName "aarch64be" arch flags
  | Architecture.MIPS, _, WordSize.Bit32
  | Architecture.MIPS, _, WordSize.Bit64 ->
    mipsName endian wordSize flags
  | Architecture.PPC, Endian.Little, WordSize.Bit32 ->
    "ppc32le"
  | Architecture.PPC, Endian.Big, WordSize.Bit32 ->
    "ppc32"
  | Architecture.PPC, Endian.Little, WordSize.Bit64 ->
    "ppc64le"
  | Architecture.PPC, Endian.Big, WordSize.Bit64 ->
    "ppc64"
  | Architecture.RISCV, Endian.Little, WordSize.Bit32 ->
    "riscv32"
  | Architecture.RISCV, Endian.Little, WordSize.Bit64 ->
    "riscv64"
  | Architecture.SPARC, Endian.Big, WordSize.Bit32 ->
    "sparc32"
  | Architecture.SPARC, Endian.Big, WordSize.Bit64 ->
    "sparc64"
  | Architecture.S390, Endian.Big, WordSize.Bit32 ->
    "s390"
  | Architecture.S390, Endian.Big, WordSize.Bit64 ->
    "s390x"
  | Architecture.SH4, Endian.Little, WordSize.Bit32 ->
    "sh4"
  | Architecture.SH4, Endian.Big, WordSize.Bit32 ->
    "sh4be"
  | Architecture.PARISC, Endian.Big, WordSize.Bit32 ->
    "parisc"
  | Architecture.PARISC, Endian.Big, WordSize.Bit64 ->
    "parisc64"
  | Architecture.M68K, _, _ ->
    match ISAFlags.m68kModel flags with
    | M68KModel.M68000 -> "m68000"
    | M68KModel.M68010 -> "m68010"
    | M68KModel.M68020 -> "m68020"
    | M68KModel.M68030 -> "m68030"
    | M68KModel.M68040 -> "m68040"
    | M68KModel.M68060 -> "m68060"
    | _ -> raise InvalidISAException
  | Architecture.Alpha, Endian.Little, WordSize.Bit64 ->
    "alpha"
  | Architecture.AVR, _, _ ->
    "avr"
  | Architecture.TMS320C6000, _, _ ->
    "tms320c6000"
  | Architecture.EVM, _, _ ->
    "evm"
  | Architecture.Python, _, _ ->
    match ISAFlags.pythonVersion flags with
    | PythonVersion.Python300 -> "python3.0"
    | PythonVersion.Python301 -> "python3.1"
    | PythonVersion.Python302 -> "python3.2"
    | PythonVersion.Python303 -> "python3.3"
    | PythonVersion.Python304 -> "python3.4"
    | PythonVersion.Python305 -> "python3.5"
    | PythonVersion.Python306 -> "python3.6"
    | PythonVersion.Python307 -> "python3.7"
    | PythonVersion.Python308 -> "python3.8"
    | PythonVersion.Python309 -> "python3.9"
    | PythonVersion.Python310 -> "python3.10"
    | PythonVersion.Python311 -> "python3.11"
    | PythonVersion.Python312 -> "python3.12"
    | PythonVersion.Python313 -> "python3.13"
    | PythonVersion.Python314 -> "python3.14"
    | PythonVersion.Python315 -> "python3.15"
    | _ -> raise InvalidISAException
  | Architecture.WASM, _, _ ->
    "wasm"
  | Architecture.BPF, Endian.Little, _ ->
    "bpfel"
  | Architecture.BPF, Endian.Big, _ ->
    "bpfeb"
  | Architecture.CIL, _, _ ->
    "cil"
  | _ ->
    raise InvalidISAException
