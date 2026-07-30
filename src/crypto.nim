import nimcrypto/[sha2, bcmode, rijndael, sysrand, utils]
import types

#################################################################

proc deriveFileKey*(): array[32, byte] =
  var ctx: sha256
  ctx.init()
  let passphrase = FILE_KEY_PASSPHRASE()   # call proc to get decoded string
  ctx.update(passphrase.toOpenArrayByte(0, passphrase.high))
  let digest = ctx.finish()
  copyMem(addr result[0], unsafeAddr digest.data[0], 32)


let FILE_KEY* = deriveFileKey()

type CryptoError* = object of CatchableError

#################################################################

proc encryptFile*(data: openArray[byte]): seq[byte] =
  var nonce: array[12, byte]
  # Use nimcrypto's sysrand.randomBytes which calls CryptGenRandom on Windows
  if sysrand.randomBytes(nonce) != 12:
    raise newException(CryptoError, "randomBytes failed")

  # AES-256-GCM encryption
  var ctx: GCM[aes256]
  ctx.init(FILE_KEY, nonce, [])   # key, nonce, AAD (empty)

  let cipherLen = data.len
  var cipher = newSeq[byte](cipherLen)
  var tag: array[16, byte]

  if cipherLen > 0:
    ctx.encrypt(data.toOpenArray(0, cipherLen - 1), cipher.toOpenArray(0, cipherLen - 1))
  ctx.getTag(tag)

  # Assemble: nonce || ciphertext || tag
  result = newSeq[byte](12 + cipherLen + 16)
  copyMem(addr result[0],        unsafeAddr nonce[0],  12)
  if cipherLen > 0:
    copyMem(addr result[12],     unsafeAddr cipher[0], cipherLen)
  copyMem(addr result[12 + cipherLen], unsafeAddr tag[0], 16)

#################################################################

proc decryptFile*(data: openArray[byte]): seq[byte] =
  if data.len < 12 + 16:
    raise newException(CryptoError,
      "Encrypted blob too short (" & $data.len & " bytes)")

  # Split: nonce | ciphertext+tag
  var nonce: array[12, byte]
  copyMem(addr nonce[0], unsafeAddr data[0], 12)

  let cipherPlusTagLen = data.len - 12
  let cipherLen        = cipherPlusTagLen - 16

  var tag: array[16, byte]
  copyMem(addr tag[0], unsafeAddr data[data.len - 16], 16)

  # AES-256-GCM decryption
  var ctx: GCM[aes256]
  ctx.init(FILE_KEY, nonce, [])

  result = newSeq[byte](cipherLen)
  if cipherLen > 0:
    ctx.decrypt(data.toOpenArray(12, 12 + cipherLen - 1),
                result.toOpenArray(0, cipherLen - 1))


  var computedTag: array[16, byte]
  ctx.getTag(computedTag)
  if computedTag != tag:
    raise newException(CryptoError, "GCM tag mismatch — wrong key or tampered data")
