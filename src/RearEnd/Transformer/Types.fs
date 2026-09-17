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

namespace B2R2.RearEnd.Transformer

open System
open System.Text
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.MiddleEnd.ControlFlowGraph
open type FileFormat

/// Binary is the main data object representing a byte sequence tagged with
/// some useful information.
type Binary = Binary of Lazy<BinHandle> * annotation: string
with
  static member Init(annot, hdl) = Binary(hdl, annot)

  static member PlainInit hdl = Binary(hdl, "")

  static member Handle bin =
    match bin with
    | Binary(hdl, _) ->
      hdl.Value

  static member Annotation bin =
    match bin with
    | Binary(_, annot) ->
      annot

  static member MakeAnnotation(prefix, bin) =
    match bin with
    | Binary(hdl, annot) ->
      let path = hdl.Value.File.Path
      if String.IsNullOrEmpty path then
        annot
      else
        $"{prefix}{path}"

  /// <summary>
  /// Derives a Binary holding the whole content of the given one, edited. The
  /// file format is detected anew rather than carried over, since an edit can
  /// change what the bytes are: a byte inserted ahead of an ELF header leaves
  /// something that is no longer an ELF.
  /// </summary>
  static member OfEditedContent(prefix, bin, bs) =
    let isa = (Binary.Handle bin).ISA
    let edited = lazy BinHandle.LoadFileBytes(bs, isa)
    Binary.Init(Binary.MakeAnnotation(prefix, bin), edited)

  /// <summary>
  /// Derives a Binary holding a fragment of the given one, taken as a raw image
  /// based at the given address. No file format is carried over, since a
  /// fragment of a structured file is not one itself; only the ISA and the OS
  /// are, as those hold for any part of the same binary.
  /// </summary>
  static member OfFragment(prefix, bin, bs, baseAddr) =
    let hdl = Binary.Handle bin
    let fragment = lazy BinHandle.LoadRawImage(bs, hdl.ISA, baseAddr, hdl.OS)
    Binary.Init(Binary.MakeAnnotation(prefix, bin), fragment)

  override this.ToString() =
    match this with
    | Binary(hdl, annot) when hdl.Value.File.Format = RawBinary ->
      let hdl = hdl.Value
      let s = Utils.makeMemorySummary hdl.File.RawBytes
      if String.IsNullOrEmpty annot then
        $"Binary(Raw) | 0x{hdl.File.BaseAddress:x8} | {s}"
      else
        $"Binary(Raw) | 0x{hdl.File.BaseAddress:x8} | {s} | {annot}"
    | Binary(hdl, annot) ->
      let hdl = hdl.Value
      let file = hdl.File
      let s = Utils.makeMemorySummary file.RawBytes
      let fmt = FileFormat.toString hdl.File.Format
      let path = file.Path
      let finfo = if String.IsNullOrEmpty path then "" else $", {path}"
      if String.IsNullOrEmpty annot then
        $"Binary({fmt}{finfo}) | 0x{file.BaseAddress:x8} | {s}"
      else
        $"Binary({fmt}{finfo}) | 0x{file.BaseAddress:x8} | {s} | {annot}"

/// Raw binary bytes retained with the information needed to reconstruct an
/// analyzable Binary value.
type BinaryBytes =
  { Bytes: byte[]
    BaseAddress: Addr
    ISA: ISA
    OS: OS
    Annotation: string }
with
  override this.ToString() =
    let summary = Utils.makeByteArraySummary this.Bytes
    $"ByteArray | 0x{this.BaseAddress:x8} | {summary}"

/// A source-aware byte slice inside a binary.
type BinarySlice =
  { Source: Binary
    StartAddress: Addr
    EndAddress: Addr
    Label: string option }
with
  member this.Size = this.EndAddress - this.StartAddress

  member this.Bytes =
    if this.Size > uint64 Int32.MaxValue then
      invalidArg (nameof this) "The slice is too large."
    else
      let hdl = Binary.Handle this.Source
      hdl.File.Slice(this.StartAddress, int this.Size).ToArray()

  member this.ToBinary() =
    Binary.OfFragment(
      "Sliced from ",
      this.Source,
      this.Bytes,
      this.StartAddress
    )

  override this.ToString() =
    let label = this.Label |> Option.defaultValue "slice"
    $"{label} 0x{this.StartAddress:x}-0x{this.EndAddress:x} (end exclusive)"

/// One printable string found in a binary.
type StringMatch =
  { Source: Binary
    Address: Addr
    Text: string }
with
  override this.ToString() = $"0x{this.Address:x8}  {this.Text}"

/// A section discovered in a binary.
type SectionInfo =
  { Source: Binary
    Name: string
    Address: Addr
    Size: uint64
    FileSize: uint64
    Kind: string }
with
  member this.Range =
    { Source = this.Source
      StartAddress = this.Address
      EndAddress = this.Address + this.FileSize
      Label = Some this.Name }

  override this.ToString() =
    let finish =
      if this.Size = 0UL then this.Address else this.Address + this.Size
    $"section {this.Name} 0x{this.Address:x}-0x{finish:x} {this.FileSize} bytes"

/// A function entry discovered in a binary.
type FunctionInfo =
  { Source: Binary
    Entry: Addr
    Symbol: string option }
with
  override this.ToString() =
    match this.Symbol with
    | Some symbol ->
      $"function 0x{this.Entry:x} {symbol}"
    | None ->
      $"function 0x{this.Entry:x}"

/// A concrete register value shown from a concrete execution context.
type RegisterValue =
  { Name: string
    Value: string }

/// A snapshot of concrete register values.
type RegisterView =
  { PC: Addr
    Registers: RegisterValue[] }

/// A byte range read from concrete memory.
type MemoryView =
  { Address: Addr
    Bytes: byte[] }

/// One watched memory range before and after concrete execution.
type MemoryDiff =
  { Address: Addr
    Before: byte[] option
    After: byte[] option }

/// A concrete memory access observed while executing one instruction.
[<RequireQualifiedAccess>]
type MemoryAccessKind =
  | Read
  | Write

/// A concrete memory read or write observed during execution.
type MemoryAccess =
  { Instruction: Addr
    Kind: MemoryAccessKind
    Address: Addr
    Size: int
    Before: byte[] option
    After: byte[] option
    Violation: string option }

/// One concrete instruction executed by a trace or state-changing run.
type TraceInstruction =
  { Address: Addr
    Disassembly: string }

/// A structured concrete execution trace.
type ExecutionTrace =
  { Start: Addr
    FinalPC: Addr
    InstructionCount: int
    Instructions: TraceInstruction[]
    RegisterDiffs: string[]
    MemoryAccesses: MemoryAccess[]
    MemoryDiffs: MemoryDiff[]
    StopReasons: string[] }

/// A register that must be defined before strict concrete execution.
type RequiredRegister =
  { Name: string
    Address: Addr
    Disassembly: string }

/// A memory range that must be readable before strict concrete execution.
type RequiredMemory =
  { Address: Addr option
    Size: int
    At: Addr
    Reason: string }

/// Context required to concretely execute a code range.
type ContextRequirements =
  { Executor: obj
    Start: Addr
    EndAddress: Addr option
    Count: int option
    Registers: RequiredRegister[]
    Memory: RequiredMemory[] }

/// A concrete address value produced by helper actions.
type AddressValue =
  { Address: Addr }
with
  override this.ToString() = $"0x{this.Address:x}"

/// Text with a stable artifact name and file extension.
type TextArtifact =
  { Name: string
    Extension: string
    Content: string }
with
  override this.ToString() = this.Content

/// Shared writer used by the REPL and saving actions.
module ReplArtifactWriter =
  let rec write fname (o: obj) =
    match o with
    | :? Binary as bin ->
      writeBinary fname bin
    | :? BinarySlice as slice ->
      writeBinary fname (slice.ToBinary())
    | :? BinaryBytes as bytes ->
      System.IO.File.WriteAllBytes(fname, bytes.Bytes)
    | :? TextArtifact as artifact ->
      System.IO.File.WriteAllText(fname, artifact.Content)
    | :? OutString as os ->
      writeOutString fname os
    | _ ->
      System.IO.File.WriteAllText(fname, o.ToString())

  and writeBinary fname bin =
    let hdl = Binary.Handle bin
    System.IO.File.WriteAllBytes(fname, hdl.File.RawBytes.ToArray())

  and writeOutString fname (os: OutString) =
    System.IO.File.WriteAllText(fname, os.ToString())

  and writeText fname (o: obj) =
    match o with
    | :? TextArtifact as artifact ->
      System.IO.File.WriteAllText(fname, artifact.Content)
    | :? OutString as os ->
      writeOutString fname os
    | :? string as text ->
      System.IO.File.WriteAllText(fname, text)
    | _ ->
      invalidArg (nameof o)
        "write supports text and displayable values; use save for Binary."

/// Instruction tagged with its corresponding bytes.
type Instruction =
  | ValidInstruction of BinLifter.IInstruction * byte[]
  | BadInstruction of Addr * byte[]
with
  override this.ToString() =
    match this with
    | ValidInstruction(ins, bs) ->
      let bs = Utils.makeByteArraySummary bs
      $"{ins.Address:x16} | {bs.PadRight 48} | {ins.Disasm ()}"
    | BadInstruction(addr, bs) ->
      let bs = Utils.makeByteArraySummary bs
      $"{addr:x16} | {bs.PadRight 32} | (bad)"

/// Fingerprint of a binary, which is a list of (hash * byte position) tuple.
type Fingerprint =
  { Patterns: (int * int) list
    NGramSize: int
    WindowSize: int
    Annotation: string }
with
  override this.ToString() =
    let sb = StringBuilder()
    sb.Append $"({this.Annotation}){Environment.NewLine}" |> ignore
    this.Patterns
    |> List.iter (fun (b, p) ->
      sb.Append $"{b:x2}@{p}{Environment.NewLine}" |> ignore)
    sb.ToString()

/// CFG of a function.
type CFG =
  | CFG of addr: Addr * ir: LowUIRCFG * source: Binary option
  | NoCFG of err: string (* Error message describing the reason for failure. *)
with
  static member Init(addr, ir) = CFG(addr, ir, None)

  static member Init(addr, ir, source) = CFG(addr, ir, Some source)

/// Collection of objects.
type ObjCollection = { Values: obj array }

/// Clustering result.
type ClusterResult = { Clusters: string array array }
