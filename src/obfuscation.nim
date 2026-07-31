import std/macros

const XOR_KEY* = 0xA7'u8
#################################################################
proc xorEncode(input: string): seq[byte] {.compileTime.} =
  result = newSeq[byte](input.len)
  for i in 0 ..< input.len:
    result[i] = byte(ord(input[i])) xor XOR_KEY

#################################################################
proc xorDecode*(data: openArray[byte]): string {.inline.} =
  result = newString(data.len)
  for i in 0 ..< data.len:
    result[i] = chr(data[i] xor XOR_KEY)

#################################################################
macro s*(lit: static[string]): string =
  ## Obfuscate a string literal at compile time.
  ## The plaintext is XOR-encoded into a byte array; decoding happens at runtime.
  let encoded = xorEncode(lit)
  # Build a NimNode array literal: [0xXX'u8, 0xYY'u8, ...]
  var arrNode = newNimNode(nnkBracket)
  for b in encoded:
    arrNode.add(newLit(b))
  # Return: xorDecode([...])
  result = newCall(bindSym("xorDecode"), arrNode)
