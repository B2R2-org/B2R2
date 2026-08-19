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

namespace B2R2.FrontEnd.BinFile.Python

open B2R2.FrontEnd.BinFile

/// Decodes the exception table of Python code objects (3.11 and later) and
/// projects it onto the format-agnostic exception frame type.
[<RequireQualifiedAccess>]
module PyExceptionTable =
  (* CPython writes every field as a big-endian run of 6-bit chunks: bit 0x40
     says one more chunk follows, and bit 0x80 marks the first byte of an
     entry, so it belongs to no chunk. Mirrors parse_varint in CPython's
     ceval.c. Stops at the end of the buffer rather than reading past it, so a
     truncated table costs its own last entry and nothing else. *)
  let private readVarint (bs: byte[]) offset =
    let mutable value = int bs[offset] &&& 0x3F
    let mutable offset = offset
    while offset + 1 < bs.Length && int bs[offset] &&& 0x40 <> 0 do
      offset <- offset + 1
      value <- (value <<< 6) ||| (int bs[offset] &&& 0x3F)
    value, offset + 1

  /// Decodes raw exception-table bytes into entries addressed in the file's
  /// own address space, where codeAddr is where the code object's bytecode
  /// begins. CPython counts in code units -- one instruction word of two
  /// bytes, inline caches included -- so every offset it holds is doubled
  /// here.
  let decode codeAddr (bs: byte[]) =
    let entries = ResizeArray()
    let mutable offset = 0
    (* The 0x80 bit is on an entry's first byte and nowhere else, so a byte
       without it is not the start of an entry: stop there rather than read
       the rest of the buffer as if it were entries. *)
    while offset < bs.Length && int bs[offset] &&& 0x80 <> 0 do
      let start, next = readVarint bs offset
      let length, next = readVarint bs next
      let target, next = readVarint bs next
      let depthAndLasti, next = readVarint bs next
      (* CPython emits no empty range, and one would end up with its end
         before its start once the exclusive end becomes an inclusive one. *)
      if length > 0 then
        entries.Add({ Start = codeAddr + uint64 (start * 2)
                      End = codeAddr + uint64 ((start + length) * 2) - 1UL
                      Target = codeAddr + uint64 (target * 2)
                      Depth = depthAndLasti >>> 1
                      PushLasti = depthAndLasti &&& 1 <> 0 })
      else
        ()
      offset <- next
    entries.ToArray()

  let rec private unwrapRef = function
    | PyREF(_, o) -> unwrapRef o
    | o -> o

  /// The entries of one code object, in the order CPython wrote them, which is
  /// by start address. Empty for a legacy (pre-3.11) code object, which has no
  /// exception table to read: it manages a run-time block stack instead.
  let ofCodeObject (co: PyCodeObject) =
    match unwrapRef co.ExceptionTable with
    | PyString bs -> decode (fst co.Code) bs
    | _ -> [||]

  let rec private collectCodeObjects acc obj =
    match unwrapRef obj with
    | PyCode co ->
      let acc = co :: acc
      match unwrapRef co.Consts with
      | PyTuple objs -> Array.fold collectCodeObjects acc objs
      | _ -> acc
    | _ ->
      acc

  /// Every code object of the file, the outermost one first, paired with its
  /// own entries. A nested function is a code object of its own, held in the
  /// enclosing one's constants and carrying a table of its own.
  let collect pyObj =
    collectCodeObjects [] pyObj
    |> List.rev
    |> List.map (fun co -> co, ofCodeObject co)
    |> List.toArray

  let private codeLength (co: PyCodeObject) =
    match unwrapRef (snd co.Code) with
    | PyString bs -> uint64 bs.Length
    | _ -> 0UL

  let private toHandler (e: PyExceptionEntry) =
    { BlockStart = e.Start; BlockEnd = e.End; Handler = Some e.Target }

  (* Depth and PushLasti fall away here: the format-agnostic frame has nowhere
     to keep them, and none of its consumers would know what to do with a value
     stack anyway. They are why the decoded entries stay reachable in their own
     right, through PythonBinFile.ExceptionEntries, rather than these frames
     being the only view of the table. *)
  let private toFrame (co: PyCodeObject, entries) =
    let addr = fst co.Code
    { FunctionStart = addr
      (* A code object with no bytecode would otherwise wrap around to the
         largest address there is. *)
      FunctionEnd = addr + (max (codeLength co) 1UL) - 1UL
      PersonalityRoutine = None (* Python dispatches without one. *)
      Handlers = Array.map toHandler entries }

  /// The exception frames of the whole file, one per code object. A code
  /// object with no entries still gets a frame, since a frame says where a
  /// function begins and ends as well as what guards it.
  let toFrames pyObj = collect pyObj |> Array.map toFrame

  /// Returns the entry covering the given address, or None when none does.
  /// CPython's entries never overlap -- the compiler flattens nested try
  /// blocks into disjoint ranges and expresses the nesting by an inner range's
  /// handler itself falling inside an outer range -- so at most one entry
  /// matches, and feeding an entry's Target back into this walks the handler
  /// chain outwards.
  let tryFindEntry addr (entries: PyExceptionEntry[]) =
    entries |> Array.tryFind (fun e -> e.Start <= addr && addr <= e.End)
