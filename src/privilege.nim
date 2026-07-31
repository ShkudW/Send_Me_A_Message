import std/[strutils, strformat]
import winim/lean
import obfuscation


proc cmdIsAdmin*(): string =
  var ntAuthority: SID_IDENTIFIER_AUTHORITY
  ntAuthority.Value[5] = BYTE(5)  # SECURITY_NT_AUTHORITY

  var adminGroup: PSID = nil

  let ok = AllocateAndInitializeSid(
    addr ntAuthority,
    BYTE(2),
    DWORD(SECURITY_BUILTIN_DOMAIN_RID),
    DWORD(DOMAIN_ALIAS_RID_ADMINS),
    0, 0, 0, 0, 0, 0,
    addr adminGroup,
  )

  if ok == 0:
    return s("AllocateAndInitializeSid failed: error ") & $GetLastError()

  var bIsAdmin: WINBOOL = 0
  if CheckTokenMembership(0, adminGroup, addr bIsAdmin) == 0:
    bIsAdmin = 0

  FreeSid(adminGroup)

  if bIsAdmin != 0:
    return s("Yes, running as Administrator.")
  else:
    return s("No, running as standard user.")


proc cmdPrivs*(): string =
  var hToken: HANDLE = 0
  if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, addr hToken) == 0:
    return s("OpenProcessToken failed: error ") & $GetLastError()

  var dwSize: DWORD = 0
  discard GetTokenInformation(hToken, tokenPrivileges, nil, 0, addr dwSize)

  if dwSize == 0:
    CloseHandle(hToken)
    return s("GetTokenInformation (size query) failed: error ") & $GetLastError()


  var buffer = newSeq[byte](dwSize)
  if GetTokenInformation(hToken, tokenPrivileges,
                         addr buffer[0], dwSize, addr dwSize) == 0:
    CloseHandle(hToken)
    return s("GetTokenInformation failed: error ") & $GetLastError()

  CloseHandle(hToken)

  let privCount = cast[ptr DWORD](addr buffer[0])[]

  let entrySize = sizeof(LUID_AND_ATTRIBUTES)
  let basePtr   = cast[int](addr buffer[4])

  var lines: seq[string]
  lines.add(s("Privilege Name                            State"))
  lines.add(s("-".repeat(62)))

  for i in 0 ..< privCount.int:
    let entry = cast[ptr LUID_AND_ATTRIBUTES](basePtr + i * entrySize)
    let luid   = entry.Luid
    let attrs  = entry.Attributes

    var nameSize: DWORD = 0
    discard LookupPrivilegeNameW(nil, unsafeAddr luid, nil, addr nameSize)
    if nameSize == 0:
      continue

    var nameBuf = newSeq[WCHAR](nameSize + 1)
    if LookupPrivilegeNameW(nil, unsafeAddr luid,
                            addr nameBuf[0], addr nameSize) == 0:
      continue

    let privName = $cast[WideCString](addr nameBuf[0])

    var state: string
    if (attrs and SE_PRIVILEGE_ENABLED) != 0:
      state = s("Enabled")
    elif (attrs and SE_PRIVILEGE_ENABLED_BY_DEFAULT) != 0:
      state = s("Enabled (Default)")
    else:
      state = s("Disabled")

    lines.add(&"{privName:<42} {state}")

  return lines.join("\n")
