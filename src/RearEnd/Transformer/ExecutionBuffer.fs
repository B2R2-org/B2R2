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
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.MiddleEnd.Executor

type ExecutionBuffer =
  { Register: string
    Name: string
    Size: Addr
    Permission: ContextRegionPermission
    Address: Addr }

and ExecutionLayout =
  { StackTop: Addr
    StackStart: Addr
    InitialStackPointer: Addr
    Buffers: ExecutionBuffer list }

type private ExecutionMemoryPolicy =
  { PageBytes: Addr
    StackBytes: Addr
    FirstBufferAddress: Addr
    StackPermission: ContextRegionPermission }

[<RequireQualifiedAccess>]
module ExecutionSetup =
  (* These addresses describe a synthetic execution space, not an OS memory
     allocation. A 4-KiB placement granularity separates buffers without
     claiming the target's actual page size. The 64-KiB stack is for short,
     bounded executions. Buffer search starts at 0x70000000, above typical
     fixed image addresses and below either default stack. If the image or
     stack occupies that range, the search continues at the next free
     page-aligned address. *)
  let private memoryPolicy =
    { PageBytes = 0x1000UL
      StackBytes = 0x10000UL
      FirstBufferAddress = 0x70000000UL
      StackPermission =
        { Read = true; Write = true; Execute = false } }

  let private alignUp value =
    let pageBytes = memoryPolicy.PageBytes
    let remainder = value % pageBytes
    if remainder = 0UL then
      value
    elif value > UInt64.MaxValue - pageBytes + remainder then
      invalidOp "No address space remains for an execution buffer."
    else
      value + pageBytes - remainder

  let private overlaps start finish (region: ContextRegion) =
    start < region.Finish && finish > region.Start

  let private permission (entry: string) text =
    let permission = ContextParsing.parseRegionPermission entry text
    if permission.Execute then
      invalidArg (nameof entry) "Buffers cannot be executable."
    else
      permission

  let private parseBuffer (entry: string) =
    let register, spec = ContextParsing.splitAssignment entry
    let parts = spec.Split(':')
    if parts.Length <> 3 || String.IsNullOrWhiteSpace parts[0] then
      invalidArg (nameof entry)
        $"Expected buffer REG=name:size:permission: {entry}"
    else
      ()
    let size = ContextParsing.parseAddress parts[1]
    if size = 0UL then
      invalidArg (nameof entry) "Buffer size must be positive."
    else
      register, parts[0].Trim(), size, permission entry parts[2]

  let parseBuffers text =
    let buffers = ContextParsing.entries text |> Array.map parseBuffer
    let names = buffers |> Array.map (fun (_, name, _, _) -> name)
    let registers = buffers |> Array.map (fun (reg, _, _, _) -> reg)
    let distinct count values =
      values
      |> Array.distinctBy (fun (value: string) -> value.ToUpperInvariant())
      |> Array.length
      |> (=) count
    if not (distinct names.Length names) then
      invalidArg (nameof text) "Buffer names must be unique."
    elif not (distinct registers.Length registers) then
      invalidArg (nameof text) "Buffer registers must be unique."
    else
      buffers |> Array.toList

  let private findFree start size limit (occupied: ContextRegion list) =
    let rec search candidate =
      if candidate >= limit || size > limit - candidate then
        invalidOp "No address space remains for an execution buffer."
      else
        let finish = candidate + size
        match occupied |> List.tryFind (overlaps candidate finish) with
        | None -> candidate
        | Some region -> search (alignUp region.Finish)
    search (alignUp start)

  let validateRegisterNames (hdl: BinHandle) names =
    let aliases name =
      let factory = hdl.RegisterFactory
      let rid = factory.GetRegisterID(name = name)
      factory.GetRegisterIDAliases rid |> Set.ofArray
    let isReserved rid =
      let factory = hdl.RegisterFactory
      factory.IsProgramCounter rid
      || factory.IsStackPointer rid
      || factory.IsFramePointer rid
    names
    |> List.fold (fun seen name ->
      let current = aliases name
      if current |> Set.exists isReserved then
        invalidArg (nameof names)
          $"Direct execution reserves the PC and stack registers: {name}"
      elif seen |> List.exists (fun prior ->
        Set.intersect prior current |> Set.isEmpty |> not) then
        invalidArg (nameof names) $"Overlapping register assignment: {name}"
      else
        current :: seen) []
    |> ignore

  let private region name start finish permission =
    { Name = name
      Start = start
      Finish = finish
      Permission = permission }

  let private imageRegions (hdl: BinHandle) addressLimit =
    BinFileOps.getSegments hdl.File
    |> Seq.iter (fun segment ->
      let fits =
        segment.Address < addressLimit
        && segment.Size <= addressLimit - segment.Address
      if segment.Size > 0UL && not fits then
        invalidOp "The binary image exceeds the execution address space."
      else
        ())
    ContextParsing.imageRegions hdl.File

  let layoutAt (hdl: BinHandle) stackPointer bufferText =
    let wordBytes = uint64 (StateAccess.wordBytes hdl)
    if wordBytes <> 4UL && wordBytes <> 8UL then
      invalidOp "Direct execution requires a 32- or 64-bit target."
    else
      ()
    let addressLimit =
      if wordBytes = 4UL then 0x100000000UL else UInt64.MaxValue
    if stackPointer < memoryPolicy.StackBytes
       || stackPointer > addressLimit - wordBytes then
      invalidArg (nameof stackPointer) "The stack pointer is out of range."
    else
      ()
    let stackTop = stackPointer + wordBytes
    let stackStart = stackTop - memoryPolicy.StackBytes
    let image = imageRegions hdl addressLimit
    if image |> List.exists (overlaps stackStart stackTop) then
      invalidOp "The execution stack overlaps the binary image."
    else
      ()
    let stack =
      region "stack" stackStart stackTop memoryPolicy.StackPermission
    let specs = parseBuffers bufferText
    specs
    |> List.map (fun (register, _, _, _) -> register)
    |> validateRegisterNames hdl
    let buffers, _ =
      specs
      |> List.fold (fun (buffers, occupied) (register, name, size, perm) ->
        let address =
          findFree memoryPolicy.FirstBufferAddress size addressLimit occupied
        let buffer =
          { Register = register
            Name = name
            Size = size
            Permission = perm
            Address = address }
        let next = region name address (address + size) perm
        buffer :: buffers, next :: occupied) ([], stack :: image)
    { StackTop = stackTop
      StackStart = stackStart
      InitialStackPointer = stackPointer
      Buffers = List.rev buffers }

  let layout hdl bufferText =
    (* The accessor's default top is exclusive. Reserve one word below it
       for a return address while leaving that word undefined. *)
    let stackPointer =
      StateAccess.defaultStackTop hdl
      - uint64 (StateAccess.wordBytes hdl)
    layoutAt hdl stackPointer bufferText

  let requestedBufferSpec options hasArguments =
    Map.tryFind "buffers" options
    |> Option.orElseWith (fun () ->
      if hasArguments then Some "[]" else None)

  let layoutForStack hdl stackPointer buffers =
    match stackPointer with
    | Some stackPointer -> layoutAt hdl stackPointer buffers
    | None -> layout hdl buffers

  let regions layout =
    let stackPermission = memoryPolicy.StackPermission
    let stack =
      region "stack" layout.StackStart layout.StackTop stackPermission
    stack ::
      (layout.Buffers
       |> List.map (fun buffer ->
         let finish = buffer.Address + buffer.Size
         region buffer.Name buffer.Address finish buffer.Permission))
