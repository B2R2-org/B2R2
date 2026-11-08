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
open System.Runtime.InteropServices
open System.Text

module internal TransformerTuiWindowsConsole =
  [<Literal>]
  let StandardInputHandle = -10

  [<Literal>]
  let KeyEvent = 0x0001us

  [<Literal>]
  let MouseEvent = 0x0002us

  [<Literal>]
  let EnableMouseInput = 0x0010u

  [<Literal>]
  let EnableQuickEditMode = 0x0040u

  [<Literal>]
  let EnableExtendedFlags = 0x0080u

  [<Literal>]
  let RightAltPressed = 0x0001u

  [<Literal>]
  let LeftAltPressed = 0x0002u

  [<Literal>]
  let RightCtrlPressed = 0x0004u

  [<Literal>]
  let LeftCtrlPressed = 0x0008u

  [<Literal>]
  let ShiftPressed = 0x0010u

  [<Literal>]
  let FirstMouseButton = 0x0001u

  [<Literal>]
  let RightMouseButton = 0x0002u

  [<Literal>]
  let MouseMoved = 0x0001u

  [<Literal>]
  let MouseWheeled = 0x0004u

  [<Literal>]
  let InputRecordSize = 20

  [<Literal>]
  let InputEventOffset = 4

  [<Literal>]
  let ClipboardUnicodeText = 13u

  [<Literal>]
  let GlobalMoveable = 0x0002u

  [<DllImport(
    "kernel32.dll",
    EntryPoint = "GetStdHandle",
    SetLastError = true)>]
  extern nativeint getStdHandle(int standardHandle)

  [<DllImport("kernel32.dll", EntryPoint = "GetConsoleMode",
    SetLastError = true)>]
  extern bool getConsoleMode(nativeint handle, uint32& mode)

  [<DllImport("kernel32.dll", EntryPoint = "SetConsoleMode",
    SetLastError = true)>]
  extern bool setConsoleMode(nativeint handle, uint32 mode)

  [<DllImport("kernel32.dll", EntryPoint = "GetNumberOfConsoleInputEvents",
    SetLastError = true)>]
  extern bool getNumberOfConsoleInputEvents(
    nativeint handle,
    uint32& count)

  [<DllImport("kernel32.dll", EntryPoint = "ReadConsoleInputW",
    SetLastError = true)>]
  extern bool readConsoleInput(
    nativeint handle,
    nativeint buffer,
    uint32 length,
    uint32& count)

  [<DllImport("user32.dll", EntryPoint = "OpenClipboard",
    SetLastError = true)>]
  extern bool openClipboard(nativeint owner)

  [<DllImport("user32.dll", EntryPoint = "CloseClipboard",
    SetLastError = true)>]
  extern bool closeClipboard()

  [<DllImport("user32.dll", EntryPoint = "EmptyClipboard",
    SetLastError = true)>]
  extern bool emptyClipboard()

  [<DllImport("user32.dll", EntryPoint = "SetClipboardData",
    SetLastError = true)>]
  extern nativeint setClipboardData(uint32 format, nativeint memory)

  [<DllImport("kernel32.dll", EntryPoint = "GlobalAlloc",
    SetLastError = true)>]
  extern nativeint globalAlloc(uint32 flags, nativeint bytes)

  [<DllImport("kernel32.dll", EntryPoint = "GlobalLock",
    SetLastError = true)>]
  extern nativeint globalLock(nativeint memory)

  [<DllImport("kernel32.dll", EntryPoint = "GlobalUnlock",
    SetLastError = true)>]
  extern bool globalUnlock(nativeint memory)

  [<DllImport("kernel32.dll", EntryPoint = "GlobalFree",
    SetLastError = true)>]
  extern nativeint globalFree(nativeint memory)

  let mutable private inputHandle: nativeint option = None
  let mutable private inputMode: uint32 option = None
  let mutable private recordBuffer: nativeint option = None
  let private pending = Collections.Generic.Queue<TuiInputEvent>()

  let hasFlag value flag = value &&& flag <> 0u

  let isValidHandle handle =
    handle <> nativeint 0 && handle <> nativeint -1

  let tryCopyText (text: string) =
    if not (OperatingSystem.IsWindows()) || String.IsNullOrEmpty text then
      false
    else
      let bytes = Encoding.Unicode.GetBytes(text + "\000")
      let byteCount = nativeint bytes.Length
      let mutable memory = globalAlloc (GlobalMoveable, byteCount)
      if memory = nativeint 0 then
        false
      else
        let pointer = globalLock memory
        if pointer = nativeint 0 then
          globalFree memory |> ignore
          false
        else
          Marshal.Copy(bytes, 0, pointer, bytes.Length)
          globalUnlock memory |> ignore
          if not (openClipboard(nativeint 0)) then
            globalFree memory |> ignore
            false
          else
            try
              let isStored =
                if emptyClipboard () then
                  setClipboardData (ClipboardUnicodeText, memory)
                  <> nativeint 0
                else
                  false
              if isStored then
                memory <- nativeint 0
                true
              else
                false
            finally
              closeClipboard () |> ignore
              if memory <> nativeint 0 then globalFree memory |> ignore
              else ()

  let keyModifiers state =
    let shift = hasFlag state ShiftPressed
    let alt = hasFlag state LeftAltPressed || hasFlag state RightAltPressed
    let control =
      hasFlag state LeftCtrlPressed || hasFlag state RightCtrlPressed
    shift, alt, control

  let toKeyEvent bytes =
    let offset = InputEventOffset
    if BitConverter.ToInt32(bytes, offset) = 0 then
      None
    else
      let state = BitConverter.ToUInt32(bytes, offset + 12)
      let shift, alt, control = keyModifiers state
      let keyCode = BitConverter.ToUInt16(bytes, offset + 6)
      let key = enum<ConsoleKey> (int keyCode)
      let character = char (BitConverter.ToUInt16(bytes, offset + 10))
      let key = ConsoleKeyInfo(character, key, shift, alt, control)
      let repeats = max 1 (int (BitConverter.ToUInt16(bytes, offset + 4)))
      for _ = 2 to repeats do
        pending.Enqueue(TuiInputEvent.Key key)
      Some(TuiInputEvent.Key key)

  let toMouseEvent bytes =
    let offset = InputEventOffset
    let column = int (BitConverter.ToInt16(bytes, offset)) + 1
    let row = int (BitConverter.ToInt16(bytes, offset + 2)) + 1
    let buttonState = BitConverter.ToUInt32(bytes, offset + 4)
    let eventFlags = BitConverter.ToUInt32(bytes, offset + 12)
    let button =
      if hasFlag buttonState FirstMouseButton then 0
      elif hasFlag buttonState RightMouseButton then 2
      else 3
    if hasFlag eventFlags MouseWheeled then
      let delta = int16 (buttonState >>> 16)
      let button = if delta > 0s then 64 else 65
      { Button = button
        Column = column
        Row = row
        IsRelease = false
        IsDrag = false }
      |> TuiInputEvent.Mouse
      |> Some
    elif hasFlag eventFlags MouseMoved then
      if buttonState = 0u then
        None
      else
        { Button = button
          Column = column
          Row = row
          IsRelease = false
          IsDrag = true }
        |> TuiInputEvent.Mouse
        |> Some
    else
      { Button = button
        Column = column
        Row = row
        IsRelease = buttonState = 0u
        IsDrag = false }
      |> TuiInputEvent.Mouse
      |> Some

  let toInputEvent bytes =
    match BitConverter.ToUInt16(bytes, 0) with
    | eventType when eventType = KeyEvent ->
      toKeyEvent bytes
    | eventType when eventType = MouseEvent ->
      toMouseEvent bytes
    | _ ->
      None

  let readRecord handle =
    match recordBuffer with
    | None ->
      None
    | Some buffer ->
      let mutable count = 0u
      if readConsoleInput(handle, buffer, 1u, &count) && count = 1u then
        let bytes = Array.zeroCreate<byte> InputRecordSize
        Marshal.Copy(buffer, bytes, 0, InputRecordSize)
        Some bytes
      else
        None

  let rec readInputEvent handle attempts =
    if pending.Count > 0 then
      Some(pending.Dequeue())
    elif attempts = 0 then
      None
    else
      let mutable count = 0u
      if not (getNumberOfConsoleInputEvents (handle, &count))
         || count = 0u then
        None
      else
        match readRecord handle |> Option.bind toInputEvent with
        | Some input ->
          Some input
        | None ->
          readInputEvent handle (attempts - 1)

  let enable () =
    if not (OperatingSystem.IsWindows()) then
      false
    else
      let handle = getStdHandle StandardInputHandle
      let mutable mode = 0u
      let canRead =
        isValidHandle handle && getConsoleMode (handle, &mode)
      if not canRead then
        false
      else
        let mouseMode =
          (mode ||| EnableMouseInput ||| EnableExtendedFlags)
          &&& (~~~EnableQuickEditMode)
        if setConsoleMode (handle, mouseMode) then
          try
            recordBuffer <- Some(Marshal.AllocHGlobal InputRecordSize)
            inputHandle <- Some handle
            inputMode <- Some mode
            true
          with _ ->
            setConsoleMode(handle, mode) |> ignore
            false
        else
          false

  let restore () =
    match inputHandle, inputMode with
    | Some handle, Some mode ->
      setConsoleMode(handle, mode) |> ignore
    | _ ->
      ()
    recordBuffer |> Option.iter Marshal.FreeHGlobal
    inputHandle <- None
    inputMode <- None
    recordBuffer <- None
    pending.Clear()

  let isEnabled () = inputHandle.IsSome

  let tryReadInputEvent () =
    inputHandle |> Option.bind (fun handle -> readInputEvent handle 16)
