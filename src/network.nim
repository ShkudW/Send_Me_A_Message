import std/[strutils, json, times, os, algorithm]
import winhttp
import types
import obfuscation
import login   # for refreshAllTokens

#################################################################
proc skypeHeaders*(tokens: TokenDict): seq[(string, string)] =
  @[
    (s("Authorization"),             s("skype_token ") & tokens.skypeToken),
    (s("X-Skypetoken"),              tokens.skypeToken),
    (s("User-Agent"),                USER_AGENT()),
    (s("Accept"),                    s("application/json")),
    (s("Content-Type"),              s("application/json")),
    (s("X-Ms-Client-Type"),          s("web")),
    (s("X-Ms-Client-Version"),       s("1415/26070217343")),
    (s("Ms-Ic3-Product"),            s("tfl")),
    (s("Ms-Ic3-Additional-Product"), s("Sfl")),
    (s("Origin"),                    s("https://teams.live.com")),
    (s("Referer"),                   s("https://teams.live.com/v2/")),
  ]

#################################################################

proc csaHeaders*(tokens: TokenDict): seq[(string, string)] =
  @[
    (s("X-Skypetoken"),              tokens.skypeToken),
    (s("X-Ms-User-Type"),            s("real-user")),
    (s("X-Ms-Client-Type"),          s("web")),
    (s("X-Ms-Client-Version"),       s("1415/26070217343")),
    (s("Ms-Ic3-Product"),            s("tfl")),
    (s("Ms-Ic3-Additional-Product"), s("Sfl")),
    (s("Accept"),                    s("*/*")),
    (s("Origin"),                    s("https://teams.live.com")),
    (s("Referer"),                   s("https://teams.live.com/v2/")),
    (s("Cache-Control"),             s("no-store, no-cache")),
  ]


#################################################################

proc graphHeaders*(tokens: TokenDict): seq[(string, string)] =
  ## Standard Microsoft Graph API headers.
  @[
    (s("Authorization"),  s("Bearer ") & tokens.graphToken),
    (s("User-Agent"),     USER_AGENT()),
    (s("Accept"),         s("application/json")),
    (s("Content-Type"),   s("application/json")),
    (s("Origin"),         s("https://teams.live.com")),
    (s("Referer"),        s("https://teams.live.com/")),
  ]

#################################################################
#################################################################

proc extractBetween*(text, startMark, endMark: string): string =
  let si = text.find(startMark)
  if si < 0: return ""
  let inner = text[si + startMark.len .. ^1]
  let ei = inner.find(endMark)
  if ei < 0: return ""
  return inner[0 ..< ei]

proc urlEncode*(str: string): string =
  result = ""
  for c in str:
    case c
    of 'A'..'Z', 'a'..'z', '0'..'9', '-', '_', '.', '~':
      result.add(c)
    else:
      result.add('%')
      result.add(toHex(ord(c), 2))

#################################################################
proc apiCall*(
  verb:    string;
  url:     string;
  tokens:  var TokenDict;
  headers: seq[(string, string)] = @[];
  body:    string = "";
  debug:   bool   = false;
  maxRetries: int = MAX_RETRIES;
): HttpResponse {.gcsafe.} =
  var attempt = 0
  while attempt < maxRetries:
    inc attempt
    let resp = httpRequest(verb, url, headers, body)
    case resp.code
    of 200, 201, 202, 204:
      return resp
    of 401:
      if attempt >= maxRetries:
        raise newException(IOError, s("401 after retries"))
      try:
        refreshAllTokens(tokens, debug)
      except ValueError as e:
        raise newException(IOError, s("token refresh: ") & e.msg)
      continue
    of 429:
      let retryAfterStr = resp[s("Retry-After")]
      let waitSecs = try: parseInt(retryAfterStr) except: DEFAULT_RETRY_AFTER
      sleep(waitSecs * 1000)
      continue
    else:
      raise newException(IOError,
        s("HTTP ") & $resp.code & " " & verb & " " & url)
  raise newException(IOError, s("max retries exceeded"))

#################################################################
proc fetchMessages*(threadId: string; tokens: var TokenDict;
                    pageSize: int = 200; debug: bool = false): seq[JsonNode] {.gcsafe.} =
  let tidEnc = urlEncode(threadId)
  let url = (
    s("https://teams.live.com/api/chatsvc/consumer/v1/users/ME/conversations/") &
    tidEnc & s("/messages") &
    s("?view=msnp24Equivalent|supportsMessageProperties|supportsExtendedHistory") &
    s("&pageSize=") & $pageSize & s("&startTime=0")
  )
  let resp = apiCall(s("GET"), url, tokens, skypeHeaders(tokens), debug = debug)
  let data = parseJson(resp.body)
  let msgs = data.getOrDefault(s("messages"))
  if msgs.kind == JArray:
    result = msgs.elems
    result.sort(proc(a, b: JsonNode): int =
      let ai = try: a.getOrDefault(s("id")).getStr("0").parseBiggestInt() except: 0i64
      let bi = try: b.getOrDefault(s("id")).getStr("0").parseBiggestInt() except: 0i64
      cmp(ai, bi))
  else:
    result = @[]

#################################################################
proc buildSendPayload(threadId, convLink, nowIso, msgId, chunk,
                       skypeId, displayName: string): string =
  $(%*{
    s("type"):                s("Message"),
    s("conversationid"):      threadId,
    s("conversationLink"):    convLink,
    s("from"):                skypeId,
    s("fromUserId"):          skypeId,
    s("composetime"):         nowIso,
    s("originalarrivaltime"): nowIso,
    s("content"):             chunk,
    s("messagetype"):         s("RichText/Html"),
    s("contenttype"):         s("Text"),
    s("imdisplayname"):       displayName,
    s("clientmessageid"):     msgId,
    s("callId"):              s(""),
    s("state"):               0,
    s("version"):             s("0"),
    s("amsreferences"):       newJArray(),
    s("properties"): %*{
      s("importance"):      s(""),
      s("subject"):         s(""),
      s("title"):           s(""),
      s("cards"):           s("[]"),
      s("links"):           s("[]"),
      s("mentions"):        s("[]"),
      s("onbehalfof"):      newJNull(),
      s("files"):           s("[]"),
      s("policyViolation"): newJNull(),
      s("formatVariant"):   s("TEAMS"),
    },
    s("crossPostChannels"): newJArray(),
  })

proc sendRaw*(threadId, content: string; tokens: var TokenDict;
              debug: bool = false) {.gcsafe.} =
  ## Send content as a Teams message to threadId.
  ## Uses primary endpoint with fallback; splits large messages into chunks.
  let tidEnc   = urlEncode(threadId)
  let url1     = s("https://teams.live.com/api/chatsvc/consumer/v1/users/ME/conversations/") & tidEnc & s("/messages")
  let url2     = s("https://msgapi.teams.live.com/v1/users/ME/conversations/") & tidEnc & s("/messages")
  let nowIso   = format(now().utc, "yyyy-MM-dd'T'HH:mm:ss'.000Z'")
  let msgId    = $int(epochTime() * 1000)
  let convLink = s("https://teams.live.com/api/chatsvc/consumer/v1/users/ME/conversations/") & threadId

  const MAX_MSG = 27_000
  if content.len <= MAX_MSG:
    let body = buildSendPayload(threadId, convLink, nowIso, msgId, content,
                                tokens.skypeId, tokens.displayName)
    var sent = false
    try:
      let r = apiCall(s("POST"), url1, tokens, skypeHeaders(tokens), body, debug)
      sent = r.code in {200, 201}
    except: discard
    if not sent:
      try:
        let r = apiCall(s("POST"), url2, tokens, skypeHeaders(tokens), body, debug)
        sent = r.code in {200, 201}
      except: discard
    if not sent:
      raise newException(IOError, s("send_raw failed"))
  else:
    var offset = 0
    var part   = 1
    while offset < content.len:
      let chunk = content[offset .. min(offset + MAX_MSG - 1, content.high)]
      let body  = buildSendPayload(threadId, convLink, nowIso, msgId, chunk,
                                   tokens.skypeId, tokens.displayName)
      var sent = false
      try:
        let r = apiCall(s("POST"), url1, tokens, skypeHeaders(tokens), body, debug)
        sent = r.code in {200, 201}
      except: discard
      if not sent:
        try:
          discard apiCall(s("POST"), url2, tokens, skypeHeaders(tokens), body, debug)
        except: discard
      offset += MAX_MSG
      inc part

#################################################################
proc resolveThread*(serverContact: string; tokens: var TokenDict;
                    debug: bool = false): string {.gcsafe.} =

  if serverContact.startsWith(s("19:")) or serverContact.startsWith(s("48:")) or
     (serverContact.startsWith(s("8:")) and "@" notin serverContact):
    return serverContact

  let emailLocal = if "@" in serverContact: serverContact.split("@")[0].toLowerAscii()
                   else: serverContact.toLowerAscii()
  var targetMri  = ""

  try:
    let r = apiCall(s("GET"),
      s("https://teams.live.com/api/csa/api/v3/teams/users/me") &
      s("?isPrefetch=false&enableMembershipSummary=true") &
      s("&supportsAdditionalSystemGeneratedFolders=true&enableEngageCommunities=false"),
      tokens, csaHeaders(tokens), debug = debug)
    if r.code == 200:
      let data = parseJson(r.body)
      for chat in data.getOrDefault(s("chats")).getElems():
        for m in chat.getOrDefault(s("members")).getElems():
          let mri = m.getOrDefault(s("mri")).getStr()
          if mri.toLowerAscii() == tokens.skypeId.toLowerAscii(): continue
          if emailLocal in mri.toLowerAscii() or emailLocal in serverContact.toLowerAscii():
            if s(".cid.") in mri or emailLocal in mri.toLowerAscii():
              targetMri = mri
              let chatId = chat.getOrDefault(s("id")).getStr()
              return chatId
  except Exception:
    discard


  try:
    let r = apiCall(s("GET"),
      s("https://teams.live.com/api/chatsvc/consumer/v1/users/ME/conversations") &
      s("?startTime=0&view=msnp24Equivalent&pageSize=200"),
      tokens, skypeHeaders(tokens), debug = debug)
    if r.code == 200:
      let data = parseJson(r.body)
      for conv in data.getOrDefault(s("conversations")).getElems():
        for m in conv.getOrDefault(s("members")).getElems():
          let mri     = m.getOrDefault(s("id")).getStr()
          let display = (m.getOrDefault(s("displayName")).getStr() &
                         m.getOrDefault(s("friendlyName")).getStr()).toLowerAscii()
          if mri.toLowerAscii() != tokens.skypeId.toLowerAscii() and (
            emailLocal in mri.toLowerAscii() or
            emailLocal in display or
            ("@" in serverContact and serverContact.toLowerAscii() in display)
          ):
            targetMri = mri
            let convId = conv.getOrDefault(s("id")).getStr()
            return convId
  except Exception:
    discard


  try:
    let r = apiCall(s("GET"),
      s("https://teams.live.com/api/mt/part/consumer-s/beta/users?q=") &
      urlEncode(serverContact) & s("&top=10"),
      tokens, skypeHeaders(tokens), debug = debug)
    if r.code == 200:
      var results = parseJson(r.body)
      if results.kind == JObject:
        let v = results.getOrDefault(s("value"))
        let u = results.getOrDefault(s("users"))
        if v.kind == JArray: results = v
        elif u.kind == JArray: results = u
      if results.kind == JArray:
        for u in results.getElems():
          let mri   = u.getOrDefault(s("mri")).getStr() & u.getOrDefault(s("id")).getStr()
          let email = (u.getOrDefault(s("email")).getStr() &
                       u.getOrDefault(s("userPrincipalName")).getStr()).toLowerAscii()
          let uname = (u.getOrDefault(s("displayName")).getStr() &
                       u.getOrDefault(s("username")).getStr()).toLowerAscii()
          if mri.len > 0 and (
            email == serverContact.toLowerAscii() or
            emailLocal in email or
            emailLocal in uname or
            emailLocal in mri.toLowerAscii()
          ):
            targetMri = mri
            break
  except Exception:
    discard

  # Fallback MRI construction
  if targetMri.len == 0:
    targetMri = s("8:live:") & emailLocal


  try:
    let body = $(%*{
      s("members"): @[
        %*{s("id"): tokens.skypeId, s("role"): s("Admin")},
        %*{s("id"): targetMri,      s("role"): s("User")},
      ],
      s("properties"): %*{
        s("threadType"):       s("chat"),
        s("chatFilesIndexId"): s(""),
      },
    })
    let r = apiCall(s("POST"),
      s("https://teams.live.com/api/chatsvc/consumer/v1/threads"),
      tokens, skypeHeaders(tokens), body, debug)
    let loc = r[s("Location")]
    let threadIdx = loc.find(s("19:"))
    if r.code in {200, 201} and threadIdx >= 0:
      var tid = loc[threadIdx .. ^1]
      let slash = tid.find('/')
      if slash > 0: tid = tid[0 ..< slash]
      return tid
    if r.code in {200, 201}:
      let tid = parseJson(r.body).getOrDefault(s("id")).getStr()
      if tid.len > 0: return tid
    if r.code == 409:
      if threadIdx >= 0:
        var tid = loc[threadIdx .. ^1]
        let slash = tid.find('/')
        if slash > 0: tid = tid[0 ..< slash]
        return tid
  except Exception:
    discard

  return targetMri
