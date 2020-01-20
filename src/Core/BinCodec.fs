namespace B2R2

/// Little Endian Base 128 Codec
module LEB128 =
  [<Literal>]
  let max32LEB128Length = 5
  [<Literal>]
  let max64LEB128Length = 10

  let inline private decodeUnsignedInt (bytes: byte []) (castValue: byte -> 'T) maxLength =
    let rec decodeLoop offset value currentByte length =
      let newValue = value ||| (castValue (currentByte &&& 0x7fuy) <<< (offset * 7))
      if currentByte &&& 0x80uy <> 0uy && offset = length - 1 then
        Error "LEB128 Overflow"
      else
        if currentByte &&& 0x80uy = 0uy then
          Ok (newValue, uint8 (offset + 1))
        else
          decodeLoop (offset + 1) newValue bytes.[offset + 1] length
    if bytes.Length = 0 then
      Error "Invalid buffer length"
    else
      let len = if bytes.Length > maxLength then maxLength else bytes.Length
      decodeLoop 0 (castValue 0uy) bytes.[0] len

  let inline private decodeSignedInt (bytes: byte []) (castValue: byte -> 'T) maxLength signExtension =
    let rec decodeLoop offset value bits currentByte length =
      let newValue = value ||| (castValue (currentByte &&& 0x7fuy) <<< bits)
      if currentByte &&& 0x80uy <> 0uy && offset = length - 1 then
        Error "LEB128 Overflow"
      else
        if currentByte &&& 0x80uy = 0uy then
          let finalValue =
            if currentByte &&& 0x40uy <> 0uy then
              let shiftOffset = if offset < (maxLength - 1) then offset + 1 else offset
              signExtension <<< (7 * (shiftOffset)) ||| newValue
            else
              newValue
          Ok (finalValue, uint8 (offset + 1))
        else
          decodeLoop (offset + 1) newValue (bits + 7) bytes.[offset + 1] length
    if bytes.Length = 0 then
      Error "Invalid buffer length"
    else
      let len = if bytes.Length > maxLength then maxLength else bytes.Length
      decodeLoop 0 (castValue 0uy) 0 bytes.[0] len

  [<CompiledName("DecodeUInt64")>]
  let decodeUInt64 (bytes: byte []) =
    decodeUnsignedInt bytes uint64 max64LEB128Length

  [<CompiledName("DecodeUInt32")>]
  let decodeUInt32 (bytes: byte []) =
    decodeUnsignedInt bytes uint32 max32LEB128Length

  [<CompiledName("DecodeSInt64")>]
  let decodeSInt64 (bytes: byte []) =
    decodeSignedInt bytes int64 max64LEB128Length 0xFFFFFFFFFFFFFFFFL

  [<CompiledName("DecodeSInt32")>]
  let decodeSInt32 (bytes: byte []) =
    decodeSignedInt bytes int32 max32LEB128Length 0xFFFFFFFF