namespace B2R2

/// Little Endian Base 128 Codec
module LEB128 =
  [<Literal>]
  let Max32LEB128Length = 5
  [<Literal>]
  let Max64LEB128Length = 10

  let DecodeUInt32 (bytes: byte []) =
    let rec decodeLoop (offset, value, currentByte, length) =
      let newValue = value ||| ((uint32 currentByte &&& 0x7fu) <<< (offset * 7))
      if currentByte &&& 0x80uy = 0uy || offset = length - 1 then
        Ok newValue
      else
        decodeLoop (offset + 1, newValue, bytes.[offset + 1], length)
    if bytes.Length = 0 then
      Error "Invalid buffer length"
    else
      let len = if bytes.Length > Max32LEB128Length then Max32LEB128Length else bytes.Length
      decodeLoop (0, 0u, bytes.[0], len)

  let DecodeUInt64 (bytes: byte []) =
    let rec decodeLoop (offset, value, currentByte, length) =
      let newValue = value ||| ((uint64 currentByte &&& 0x7fUL) <<< (offset * 7))
      if currentByte &&& 0x80uy = 0uy || offset = length - 1 then
        Ok newValue
      else
        decodeLoop (offset + 1, newValue, bytes.[offset + 1], length)
    if bytes.Length = 0 then
      Error "Invalid buffer length"
    else
      let len = if bytes.Length > Max64LEB128Length then Max64LEB128Length else bytes.Length
      decodeLoop (0, 0UL, bytes.[0], len)

  let DecodeSInt32 (bytes: byte []) =
    let rec decodeLoop (offset, value, bits, currentByte, length) =
      let newValue = value ||| (int32 (currentByte &&& 0x7fuy) <<< bits)
      if currentByte &&& 0x80uy = 0uy || offset = length - 1 then
        let finalValue =
          if currentByte &&& 0x40uy <> 0uy then
            let shiftOffset = if offset < 4 then offset + 1 else offset
            0xFFFFFFFF <<< (7 * (shiftOffset)) ||| newValue
          else
            newValue
        Ok finalValue
      else
        decodeLoop (offset + 1, newValue, bits + 7, bytes.[offset + 1], length)
    if bytes.Length = 0 then
      Error "Invalid buffer length"
    else
      let len = if bytes.Length > Max32LEB128Length then Max32LEB128Length else bytes.Length
      decodeLoop (0, 0, 0, bytes.[0], len)

  let DecodeSigned64 (bytes: byte []) =
    let rec decodeLoop (offset, value, bits, currentByte, length) =
      let newValue = value ||| (int64 (currentByte &&& 0x7fuy) <<< bits)
      if currentByte &&& 0x80uy = 0uy || offset = length - 1 then
        let finalValue =
          if currentByte &&& 0x40uy <> 0uy then
            let shiftOffset = if offset < 9 then offset + 1 else offset
            0xFFFFFFFFFFFFFFFFL <<< (7 * (shiftOffset)) ||| newValue
          else
            newValue
        Ok finalValue
      else
        decodeLoop (offset + 1, newValue, bits + 7, bytes.[offset + 1], length)
    if bytes.Length = 0 then
      Error "Invalid buffer length"
    else
      let len = if bytes.Length > Max64LEB128Length then Max64LEB128Length else bytes.Length
      decodeLoop (0, 0L, 0, bytes.[0], len)