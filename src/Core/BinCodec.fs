namespace B2R2

/// Little Endian Base 128 Codec
module LEB128 =
  [<Literal>]
  let max32LEB128Length = 5
  [<Literal>]
  let max64LEB128Length = 10

  let inline private decodeLEB128 (bytes: byte []) (castValue: byte -> 'T) maxLength extendSign (signExtension: 'T) =
    let rec decodeLoop offset value currentByte length =
      let newValue = value ||| (castValue (currentByte &&& 0x7fuy) <<< (offset * 7))
      if currentByte &&& 0x80uy <> 0uy && offset = length - 1 then
        invalidArg "bytes" "LEB128 Overflow"
      else
        if currentByte &&& 0x80uy = 0uy then
          let finalValue = extendSign currentByte offset newValue signExtension maxLength
          (finalValue, uint8 (offset + 1))
        else
          decodeLoop (offset + 1) newValue bytes.[offset + 1] length
    if bytes.Length = 0 then
      invalidArg "bytes" "Invalid buffer length"
    else
      let len = if bytes.Length > maxLength then maxLength else bytes.Length
      decodeLoop 0 (castValue 0uy) bytes.[0] len

  let inline private extendSign currentByte offset (currentValue: 'T) (signExtension: 'T) maxLength =
    if currentByte &&& 0x40uy <> 0uy then
      let shiftOffset = if offset < (maxLength - 1) then offset + 1 else offset
      signExtension <<< (7 * (shiftOffset)) ||| currentValue
    else
      currentValue

  [<CompiledName("DecodeUInt64")>]
  let decodeUInt64 (bytes: byte []) =
    decodeLEB128 bytes uint64 max64LEB128Length (fun b o v s l -> v) 0UL

  [<CompiledName("DecodeUInt32")>]
  let decodeUInt32 (bytes: byte []) =
    decodeLEB128 bytes uint32 max32LEB128Length (fun b o v s l -> v) 0u

  [<CompiledName("DecodeSInt64")>]
  let decodeSInt64 (bytes: byte []) =
    decodeLEB128 bytes int64 max64LEB128Length extendSign 0xFFFFFFFFFFFFFFFFL

  [<CompiledName("DecodeSInt32")>]
  let decodeSInt32 (bytes: byte []) =
    decodeLEB128 bytes int32 max32LEB128Length extendSign 0xFFFFFFFF