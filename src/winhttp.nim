import std/[strutils, uri]
import winim/lean          # DWORD, LPCWSTR, HMODULE, FARPROC, etc.
import obfuscation         # s() macro for XOR-obfuscated string literals



type
  HINTERNET = pointer
  INTERNET_PORT = uint16

# WinHTTP constants
const
  WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY = DWORD(4)
  WINHTTP_NO_PROXY_NAME               = nil
  WINHTTP_NO_PROXY_BYPASS             = nil
  WINHTTP_OPTION_REDIRECT_POLICY      = DWORD(88)
  WINHTTP_OPTION_REDIRECT_POLICY_NEVER = DWORD(0)
  WINHTTP_FLAG_SECURE                 = DWORD(0x00800000)
  WINHTTP_QUERY_STATUS_CODE           = DWORD(19)
  WINHTTP_QUERY_RAW_HEADERS_CRLF      = DWORD(22)
  WINHTTP_QUERY_FLAG_NUMBER           = DWORD(0x20000000)
  INTERNET_DEFAULT_HTTP_PORT          = INTERNET_PORT(80)
  INTERNET_DEFAULT_HTTPS_PORT         = INTERNET_PORT(443)


type
  HttpResponse* = object
    code*:    int
    body*:    string
    headers*: seq[(string, string)]
    url*:     string

proc `[]`*(resp: HttpResponse; header: string): string =
  let lower = header.toLowerAscii()
  for (k, v) in resp.headers:
    if k.toLowerAscii() == lower:
      return v
  return ""



type
  FnWinHttpOpen = proc(
    pszAgentW:          LPCWSTR,
    dwAccessType:       DWORD,
    pszProxyW:          LPCWSTR,
    pszProxyBypassW:    LPCWSTR,
    dwFlags:            DWORD,
  ): HINTERNET {.stdcall, gcsafe.}

  FnWinHttpConnect = proc(
    hSession:           HINTERNET,
    pswzServerName:     LPCWSTR,
    nServerPort:        INTERNET_PORT,
    dwReserved:         DWORD,
  ): HINTERNET {.stdcall, gcsafe.}

  FnWinHttpOpenRequest = proc(
    hConnect:           HINTERNET,
    pwszVerb:           LPCWSTR,
    pwszObjectName:     LPCWSTR,
    pwszVersion:        LPCWSTR,
    pwszReferrer:       LPCWSTR,
    ppwszAcceptTypes:   pointer,
    dwFlags:            DWORD,
  ): HINTERNET {.stdcall, gcsafe.}

  FnWinHttpSetOption = proc(
    hInternet:          HINTERNET,
    dwOption:           DWORD,
    lpBuffer:           pointer,
    dwBufferLength:     DWORD,
  ): WINBOOL {.stdcall, gcsafe.}

  FnWinHttpAddRequestHeaders = proc(
    hRequest:           HINTERNET,
    lpszHeaders:        LPCWSTR,
    dwHeadersLength:    DWORD,
    dwModifiers:        DWORD,
  ): WINBOOL {.stdcall, gcsafe.}

  FnWinHttpSendRequest = proc(
    hRequest:           HINTERNET,
    lpszHeaders:        LPCWSTR,
    dwHeadersLength:    DWORD,
    lpOptional:         pointer,
    dwOptionalLength:   DWORD,
    dwTotalLength:      DWORD,
    dwContext:          DWORD_PTR,
  ): WINBOOL {.stdcall, gcsafe.}

  FnWinHttpReceiveResponse = proc(
    hRequest:           HINTERNET,
    lpReserved:         pointer,
  ): WINBOOL {.stdcall, gcsafe.}

  FnWinHttpQueryHeaders = proc(
    hRequest:           HINTERNET,
    dwInfoLevel:        DWORD,
    pwszName:           LPCWSTR,
    lpBuffer:           pointer,
    lpdwBufferLength:   ptr DWORD,
    lpdwIndex:          ptr DWORD,
  ): WINBOOL {.stdcall, gcsafe.}

  FnWinHttpReadData = proc(
    hRequest:           HINTERNET,
    lpBuffer:           LPVOID,
    dwNumberOfBytesToRead: DWORD,
    lpdwNumberOfBytesRead: ptr DWORD,
  ): WINBOOL {.stdcall, gcsafe.}

  FnWinHttpCloseHandle = proc(
    hInternet:          HINTERNET,
  ): WINBOOL {.stdcall, gcsafe.}



type WinHttpVtable = object
  Open:           FnWinHttpOpen
  Connect:        FnWinHttpConnect
  OpenRequest:    FnWinHttpOpenRequest
  SetOption:      FnWinHttpSetOption
  AddHeaders:     FnWinHttpAddRequestHeaders
  SendRequest:    FnWinHttpSendRequest
  ReceiveResp:    FnWinHttpReceiveResponse
  QueryHeaders:   FnWinHttpQueryHeaders
  ReadData:       FnWinHttpReadData
  CloseHandle:    FnWinHttpCloseHandle

var gWH: WinHttpVtable
var gWHLoaded = false

proc loadWinHttp() =
  ## Load winhttp.dll and resolve all function pointers dynamically.
  ## The DLL name and all function names are XOR-decoded at runtime.
  if gWHLoaded: return


  let dllName = s("winhttp.dll")
  let hDll = LoadLibraryA(dllName.cstring)
  if hDll == 0:
    raise newException(IOError, "loadWinHttp: LoadLibraryA failed")

  proc resolve(name: string): FARPROC =
    result = GetProcAddress(hDll, name.cstring)
    if result == nil:
      raise newException(IOError, "loadWinHttp: GetProcAddress failed for " & name)

  gWH.Open        = cast[FnWinHttpOpen](resolve(s("WinHttpOpen")))
  gWH.Connect     = cast[FnWinHttpConnect](resolve(s("WinHttpConnect")))
  gWH.OpenRequest = cast[FnWinHttpOpenRequest](resolve(s("WinHttpOpenRequest")))
  gWH.SetOption   = cast[FnWinHttpSetOption](resolve(s("WinHttpSetOption")))
  gWH.AddHeaders  = cast[FnWinHttpAddRequestHeaders](resolve(s("WinHttpAddRequestHeaders")))
  gWH.SendRequest = cast[FnWinHttpSendRequest](resolve(s("WinHttpSendRequest")))
  gWH.ReceiveResp = cast[FnWinHttpReceiveResponse](resolve(s("WinHttpReceiveResponse")))
  gWH.QueryHeaders= cast[FnWinHttpQueryHeaders](resolve(s("WinHttpQueryHeaders")))
  gWH.ReadData    = cast[FnWinHttpReadData](resolve(s("WinHttpReadData")))
  gWH.CloseHandle = cast[FnWinHttpCloseHandle](resolve(s("WinHttpCloseHandle")))
  gWHLoaded = true



proc toWStr(str: string): seq[Utf16Char] =
  result = newSeq[Utf16Char](str.len + 1)
  for i, c in str:
    result[i] = Utf16Char(ord(c))
  result[str.len] = Utf16Char(0)

proc fromWStr(buf: openArray[Utf16Char]): string =
  result = ""
  for c in buf:
    if ord(c) == 0: break
    result.add(chr(ord(c) and 0xFF))

proc queryHeaderStr(hReq: HINTERNET; infoLevel: DWORD): string =
  var bufLen: DWORD = 0
  discard gWH.QueryHeaders(hReq, infoLevel, nil, nil, bufLen.addr, nil)
  if bufLen == 0: return ""
  var buf = newSeq[Utf16Char](bufLen div 2 + 1)
  if gWH.QueryHeaders(hReq, infoLevel, nil, buf[0].addr, bufLen.addr, nil) == 0:
    return ""
  fromWStr(buf)

proc queryStatusCode(hReq: HINTERNET): int =
  var code: DWORD = 0
  var sz:   DWORD = sizeof(DWORD).DWORD
  if gWH.QueryHeaders(hReq,
       DWORD(WINHTTP_QUERY_STATUS_CODE or WINHTTP_QUERY_FLAG_NUMBER),
       nil, cast[LPVOID](code.addr), sz.addr, nil) != 0:
    return code.int
  return 0

proc parseHeaders(raw: string): seq[(string, string)] =
  result = @[]
  for line in raw.splitLines():
    let trimmed = line.strip()
    if trimmed.len == 0: continue
    let colon = trimmed.find(':')
    if colon < 0: continue
    let name  = trimmed[0 ..< colon].strip()
    let value = trimmed[colon + 1 .. ^1].strip()
    result.add((name, value))



proc httpRequest*(verb, url: string;
                  headers: seq[(string, string)] = @[];
                  body: string = "";
                  followRedirects: bool = true;
                  maxRedirects: int = 10): HttpResponse {.gcsafe.} =

  loadWinHttp()

  var currentUrl = url
  var redirectsLeft = maxRedirects

  let CHROME_UA = (
    s("Mozilla/5.0 (Windows NT 10.0; Win64; x64) ") &
    s("AppleWebKit/537.36 (KHTML, like Gecko) ") &
    s("Chrome/150.0.0.0 Safari/537.36")
  )

  var wAgent = toWStr(CHROME_UA)
  let hSession = gWH.Open(
    cast[LPCWSTR](wAgent[0].addr),
    DWORD(WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY),
    cast[LPCWSTR](WINHTTP_NO_PROXY_NAME),
    cast[LPCWSTR](WINHTTP_NO_PROXY_BYPASS),
    DWORD(0),
  )
  if hSession == nil:
    raise newException(IOError, "WinHttpOpen failed")

  # Disable automatic redirect following (handle manually to capture Location)
  var redirectPolicy: DWORD = WINHTTP_OPTION_REDIRECT_POLICY_NEVER
  discard gWH.SetOption(hSession, WINHTTP_OPTION_REDIRECT_POLICY,
    redirectPolicy.addr, sizeof(DWORD).DWORD)

  # Set 30-second timeouts (resolve, connect, send, receive)
  const WINHTTP_OPTION_RESOLVE_TIMEOUT  = DWORD(6)
  const WINHTTP_OPTION_CONNECT_TIMEOUT  = DWORD(7)
  const WINHTTP_OPTION_SEND_TIMEOUT     = DWORD(8)
  const WINHTTP_OPTION_RECEIVE_TIMEOUT  = DWORD(9)
  var timeout30: DWORD = 30_000
  discard gWH.SetOption(hSession, WINHTTP_OPTION_RESOLVE_TIMEOUT,  timeout30.addr, sizeof(DWORD).DWORD)
  discard gWH.SetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT,  timeout30.addr, sizeof(DWORD).DWORD)
  discard gWH.SetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT,     timeout30.addr, sizeof(DWORD).DWORD)
  discard gWH.SetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT,  timeout30.addr, sizeof(DWORD).DWORD)

  defer: discard gWH.CloseHandle(hSession)

  while true:
    let parsed   = parseUri(currentUrl)
    let isHttps  = parsed.scheme.toLowerAscii() == "https"
    let hostname = parsed.hostname
    let port     = if parsed.port.len > 0: parsed.port.parseInt().uint16
                   elif isHttps: INTERNET_DEFAULT_HTTPS_PORT
                   else: INTERNET_DEFAULT_HTTP_PORT
    var path     = parsed.path
    if parsed.query.len > 0: path &= "?" & parsed.query

    var wHostname = toWStr(hostname)
    let hConnect = gWH.Connect(hSession,
      cast[LPCWSTR](wHostname[0].addr),
      INTERNET_PORT(port), 0)
    if hConnect == nil:
      raise newException(IOError, "WinHttpConnect failed")
    defer: discard gWH.CloseHandle(hConnect)

    let flags: DWORD = if isHttps: WINHTTP_FLAG_SECURE else: 0
    var wVerb = toWStr(verb)
    var wPath = toWStr(if path.len > 0: path else: "/")
    let hReq = gWH.OpenRequest(hConnect,
      cast[LPCWSTR](wVerb[0].addr),
      cast[LPCWSTR](wPath[0].addr),
      nil, nil, nil, flags)
    if hReq == nil:
      raise newException(IOError, "WinHttpOpenRequest failed")
    defer: discard gWH.CloseHandle(hReq)

    var hasUA = false
    var hasAL = false
    for (k, _) in headers:
      let kl = k.toLowerAscii()
      if kl == s("user-agent"):      hasUA = true
      if kl == s("accept-language"): hasAL = true

    var headerBlock = ""
    if not hasUA:
      headerBlock &= s("User-Agent: ") & CHROME_UA & "\r\n"
    if not hasAL:
      headerBlock &= s("Accept-Language: en-US,en;q=0.9") & "\r\n"
    for (k, v) in headers:
      headerBlock &= k & ": " & v & "\r\n"

    if headerBlock.len > 0:
      let wHeaders = toWStr(headerBlock)
      discard gWH.AddHeaders(hReq,
        cast[LPCWSTR](wHeaders[0].addr),
        DWORD(headerBlock.len), 0)

    let bodyPtr = if body.len > 0: cast[pointer](body[0].unsafeAddr) else: nil
    let bodySz  = DWORD(body.len)
    if gWH.SendRequest(hReq, nil, 0, bodyPtr, bodySz, bodySz, 0) == 0:
      raise newException(IOError, "WinHttpSendRequest failed")

    if gWH.ReceiveResp(hReq, nil) == 0:
      raise newException(IOError, "WinHttpReceiveResponse failed")

    let statusCode    = queryStatusCode(hReq)
    let rawHeaders    = queryHeaderStr(hReq, WINHTTP_QUERY_RAW_HEADERS_CRLF)
    let parsedHeaders = parseHeaders(rawHeaders)

    # Handle redirects manually
    if followRedirects and statusCode in [301, 302, 303, 307, 308] and redirectsLeft > 0:
      var location = ""
      for (k, v) in parsedHeaders:
        if k.toLowerAscii() == "location":
          location = v
          break
      if location.len > 0:
        if location.startsWith(s("http://")) or location.startsWith(s("https://")):
          currentUrl = location
        else:
          let base = parseUri(currentUrl)
          currentUrl = $base.combine(parseUri(location))
        dec redirectsLeft
        let newVerb = if statusCode == 303: "GET" else: verb
        if newVerb != verb:
          return httpRequest(newVerb, currentUrl, headers, "", followRedirects, redirectsLeft)
        continue

    # Read response body
    var responseBody = ""
    var chunk = newString(65536)
    while true:
      var bytesRead: DWORD = 0
      if gWH.ReadData(hReq, cast[LPVOID](chunk[0].addr),
           DWORD(chunk.len), bytesRead.addr) == 0:
        break
      if bytesRead == 0: break
      responseBody &= chunk[0 ..< bytesRead.int]

    result = HttpResponse(
      code:    statusCode,
      body:    responseBody,
      headers: parsedHeaders,
      url:     currentUrl,
    )
    return
