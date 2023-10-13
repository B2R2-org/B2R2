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

namespace B2R2.FrontEnd.BinFile

open System
open System.Runtime.InteropServices
open B2R2

/// BinFile describes a binary file in a format-agnostic way.
[<AbstractClass>]
type BinFile (path, fmt, isa, typ, content) =
  /// The file path where this file is located.
  member __.FilePath with get(): string = path

  /// The format of this file: ELF, PE, Mach-O, or etc.
  member __.FileFormat with get(): FileFormat = fmt

  /// The ISA that this file expects to run on.
  member __.ISA with get(): ISA = isa

  /// What kind of binary is this?
  member __.FileType with get(): FileType = typ

  /// Addressable content of this file.
  member __.Content with get(): IContentAddressable = content

  /// The base address of the associated binary at which it is prefered to be
  /// loaded in memory.
  abstract member BaseAddress: Addr

  /// The entry point of this binary (the start address that this binary runs
  /// at). Note that some binaries (e.g., PE DLL files) do not have a specific
  /// entry point, and EntryPoint will return None in such a case.
  abstract EntryPoint: Addr option

  /// The beginning of the text section of this binary.
  abstract TextStartAddr: Addr

  /// Is this binary stripped?
  abstract IsStripped: bool

  /// Is NX enabled for this binary? (DEP enabled or not)
  abstract IsNXEnabled: bool

  /// Is this binary relocatable (i.e., position-independent)?
  abstract IsRelocatable: bool

  /// <summary>
  ///   Return a relocated address of the given virtual address if there is a
  ///   corresponding relocation entry.
  /// </summary>
  /// <param name="addr">Virtual address be relocated.</param>
  /// <returns>
  ///   Returns a relocated address for a given virtual address.
  /// </returns>
  abstract member GetRelocatedAddr: relocAddr: Addr -> Result<Addr, ErrorCase>

  /// <summary>
  ///   Add a symbol for the address. This function is useful when we can
  ///   obtain extra symbol information from outside of B2R2.
  /// </summary>
  /// <returns>
  ///   Does not return a value.
  /// </returns>
  abstract member AddSymbol: Addr -> Symbol -> unit

  /// <summary>
  ///   Return a list of all the symbols from the binary.
  /// </summary>
  /// <returns>
  ///   A sequence of symbols.
  /// </returns>
  abstract member GetSymbols: unit -> seq<Symbol>

  /// <summary>
  ///   Return a list of all the static symbols from the binary. Static symbols
  ///   can be removed when we strip the binary. Unlike dynamic symbols, static
  ///   symbols are not required to run the binary, thus they can be safely
  ///   removed before releasing it.
  /// </summary>
  /// <returns>
  ///   A sequence of static symbols.
  /// </returns>
  abstract member GetStaticSymbols: unit -> seq<Symbol>

  /// <summary>
  ///   Return a list of all the dynamic symbols from the binary. Dynamic
  ///   symbols are the ones that are required to run the binary. The
  ///   "excludeImported" argument indicates whether to exclude external symbols
  ///   that are imported from other files. However, even if "excludeImported"
  ///   is true, returned symbols may include a forwarding entry that redirects
  ///   to another function in an external file (cf. SymbolKind.ForwardType).
  ///   When "excludeImported" argument is not given, this function will simply
  ///   return all possible dynamic symbols.
  /// </summary>
  /// <returns>
  ///   A sequence of dynamic symbols.
  /// </returns>
  abstract member GetDynamicSymbols: ?excludeImported: bool -> seq<Symbol>

  /// <summary>
  ///   Return a list of all relocation symbols from the binary.
  /// </summary>
  /// <returns>
  ///   A sequence of relocation symbols.
  /// </returns>
  abstract member GetRelocationSymbols: unit -> seq<Symbol>

  /// <summary>
  ///   Return a list of all the sections from the binary.
  /// </summary>
  /// <returns>
  ///   A sequence of sections.
  /// </returns>
  abstract member GetSections: unit -> seq<Section>

  /// <summary>
  ///   Return a section that contains the given address.
  /// </summary>
  /// <param name="addr">The address that belongs to a section.</param>
  /// <returns>
  ///   A sequence of sections. This function returns a singleton if there
  ///   exists a corresponding section. Otherwise, it returns an empty sequence.
  /// </returns>
  abstract member GetSections: addr: Addr -> seq<Section>

  /// <summary>
  ///   Return a section that has the specified name.
  /// </summary>
  /// <param name="name">The name of the section.</param>
  /// <returns>
  ///   A sequence of sections that have the specified name. This function
  ///   returns an empty sequence if there is no section of the given name.
  /// </returns>
  abstract member GetSections: name: string -> seq<Section>

  /// <summary>
  ///   Return a sequence text sections.
  /// </summary>
  /// <returns>
  ///   A sequence of text sections.
  /// </returns>
  abstract member GetTextSections: unit -> seq<Section>

  /// <summary>
  ///   Return a list of segments from the binary. If the isLoadable parameter
  ///   is true, it will only return a list of "loadable" segments. Otherwise,
  ///   it will return all possible segments. By default, this function returns
  ///   only loadable segments, e.g., PT_LOAD segment of ELF.
  /// </summary>
  /// <returns>
  ///   A sequence of segments.
  /// </returns>
  abstract member GetSegments:
    [<Optional; DefaultParameterValue(true)>] isLoadable:bool
    -> seq<Segment>

  /// <summary>
  ///   Return a list of the segments from the binary, which contain the given
  ///   address.
  /// </summary>
  /// <param name="addr">The address that belongs to segments.</param>
  /// <returns>
  ///   A sequence of segments.
  /// </returns>
  member __.GetSegments (addr: Addr) =
    __.GetSegments ()
    |> Seq.filter (fun s -> (addr >= s.Address) && (addr < s.Address + s.Size))

  /// <summary>
  ///   For a given permission, return a list of segments that satisfy the
  ///   permission. For a given "READ-only" permission, this function may return
  ///   a segment whose permission is "READABLE and WRITABLE", as an instance.
  /// </summary>
  /// <returns>
  ///   A sequence of segments.
  /// </returns>
  member __.GetSegments (perm: Permission) =
    __.GetSegments ()
    |> Seq.filter (fun s -> (s.Permission &&& perm = perm) && s.Size > 0UL)

  /// <summary>
  ///   Return a list of all the linkage table entries from the binary.
  /// </summary>
  /// <returns>
  ///   A sequence of linkage table entries, e.g., PLT entries for ELF files.
  /// </returns>
  abstract member GetLinkageTableEntries: unit -> seq<LinkageTableEntry>

  /// <summary>
  ///   Return if a given address is an address of a linkage table entry.
  /// </summary>
  /// <returns>
  ///   True if the address is a linkage table address, false otherwise.
  /// </returns>
  abstract member IsLinkageTable: Addr -> bool

  /// <summary>
  ///   Find the symbol name for a given address.
  /// </summary>
  /// <returns>
  ///   Returns a symbol as an Ok value if a symbol exists, otherwise returns
  ///   an Error value.
  /// </returns>
  abstract member TryFindFunctionSymbolName: Addr -> Result<string, ErrorCase>

  /// <summary>
  ///   Convert the section at the address (Addr) into a binary pointer, which
  ///   can exclusively point to binary contents of the section.
  /// </summary>
  abstract member ToBinFilePointer: Addr -> BinFilePointer

  /// <summary>
  ///   Convert the section of the name (string) into a binary pointer, which
  ///   can exclusively point to binary contents of the section.
  /// </summary>
  abstract member ToBinFilePointer: string -> BinFilePointer

  /// <summary>
  ///   Returns a sequence of local function symbols (excluding external
  ///   functions) from a given BinFile.
  /// </summary>
  /// <returns>
  ///   A sequence of function symbols.
  /// </returns>
  member __.GetFunctionSymbols () =
    let dict = Collections.Generic.Dictionary<Addr, Symbol> ()
    __.GetStaticSymbols ()
    |> Seq.iter (fun s ->
      if s.Kind = SymFunctionType then dict[s.Address] <- s
      elif s.Kind = SymNoType (* This is to handle ppc's PLT symbols. *)
        && s.Address > 0UL && s.Name.Contains "pic32."
      then dict[s.Address] <- s
      else ())
    __.GetDynamicSymbols (true) |> Seq.iter (fun s ->
      if dict.ContainsKey s.Address then ()
      elif s.Kind = SymFunctionType then dict[s.Address] <- s
      else ())
    dict.Values

  /// <summary>
  ///   Returns a sequence of local function addresses (excluding external
  ///   functions) from a given BinFile. This function only considers addresses
  ///   that are certain.
  /// </summary>
  /// <returns>
  ///   A sequence of function addresses.
  /// </returns>
  abstract member GetFunctionAddresses: unit -> seq<Addr>

  default __.GetFunctionAddresses () =
    __.GetFunctionSymbols ()
    |> Seq.map (fun s -> s.Address)

  /// <summary>
  ///   Returns a sequence of local function addresses (excluding external
  ///   functions) from a given BinFile. If the argument is true, then this
  ///   funciton utilizes exception information of the binary to infer function
  ///   entries. Note that the inference process is not necessarily precise, so
  ///   this is really just an experimental feature, and will be removed in the
  ///   future.
  /// </summary>
  /// <returns>
  ///   A sequence of function addresses.
  /// </returns>
  abstract member GetFunctionAddresses: bool -> seq<Addr>

  default __.GetFunctionAddresses (_) =
    __.GetFunctionSymbols ()
    |> Seq.map (fun s -> s.Address)

  /// <summary>
  ///   Return a new BinFile by replacing the content with the given byte array,
  ///   assuming the file format, ISA, and its file path do not change. The new
  ///   byte array is placed at the same base address as the original one. This
  ///   function does not directly affect the corresponding file in the file
  ///   system, though.
  /// </summary>
  /// <return>
  ///   A newly generated BinFile.
  /// </return>
  abstract member NewBinFile: byte[] -> BinFile

  /// <summary>
  ///   Return a new BinFile by replacing the content with the given byte array,
  ///   assuming the file format, ISA, and its file path do not change. The new
  ///   byte array is placed at the given base address (baseAddr). This function
  ///   does not directly affect the corresponding file in the file system,
  ///   though.
  /// </summary>
  /// <return>
  ///   A newly generated BinFile.
  /// </return>
  abstract member NewBinFile: byte[] * baseAddr: Addr -> BinFile

  /// <summary>
  ///   Get a sequence of executable sections including linkage table code
  ///   sections such as PLT.
  /// </summary>
  /// <returns>
  ///   A sequence of executable sections.
  /// </returns>
  member __.GetExecutableSections () =
    __.GetSections ()
    |> Seq.filter (fun s -> (s.Kind = SectionKind.ExecutableSection)
                         || (s.Kind = SectionKind.LinkageTableSection))

  /// <summary>
  ///   Convert <see cref="T:B2R2.FrontEnd.BinFile.FileType">FileType</see> to
  ///   string.
  /// </summary>
  /// <param name="ty">A FileType to convert.</param>
  /// <returns>
  ///   A converted string.
  /// </returns>
  static member FileTypeToString (ty) =
    match ty with
    | FileType.ExecutableFile -> "Executable"
    | FileType.CoreFile -> "Core dump"
    | FileType.LibFile -> "Library"
    | FileType.ObjFile -> "Object"
    | _ -> "Unknown"

  /// <summary>
  ///   Convert from permission to string.
  /// </summary>
  /// <param name="p">A permission to convert.</param>
  /// <returns>
  ///   A converted string.
  /// </returns>
  static member PermissionToString (p: Permission) =
    let r =
      if p &&& Permission.Readable = LanguagePrimitives.EnumOfValue 0 then ""
      else "R"
    let w =
      if p &&& Permission.Writable = LanguagePrimitives.EnumOfValue 0 then ""
      else "W"
    let x =
      if p &&& Permission.Executable = LanguagePrimitives.EnumOfValue 0 then ""
      else "X"
    r + w + x

  /// <summary>
  ///   Convert from entrypoint information to string.
  /// </summary>
  /// <param name="entryPoint">Entry point of a given binary.</param>
  /// <returns>
  ///   A converted string.
  /// </returns>
  static member EntryPointToString (entryPoint: Addr option) =
    match entryPoint with
    | None -> "none"
    | Some entry -> sprintf "0x%x" entry
