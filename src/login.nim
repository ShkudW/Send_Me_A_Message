import std/[strutils, base64, uri, json, oids]
import winhttp
import regex
import nimcrypto/[sha2, sysrand]
import types
import obfuscation

#################################################################

proc reFind(pattern: Regex2; text: string; group: int = 1;
            default: string = ""): string =

  var m: RegexMatch2
  if text.find(pattern, m):
    let b = m.group(group - 1)
    if b.a >= 0 and b.b >= 0:
      return text[b.a .. b.b]
  return default

proc generatePkce*(): tuple[verifier: string; challenge: string] =
  ## Generate a PKCE code_verifier + code_challenge (S256).
  var raw: array[32, byte]
  discard sysrand.randomBytes(raw)
  let verifier  = encode(raw, safe = true).strip(chars = {'='})
  var ctx: sha256
  ctx.init()
  ctx.update(verifier.toOpenArrayByte(0, verifier.high))
  let digest    = ctx.finish()
  let challenge = encode(digest.data, safe = true).strip(chars = {'='})
  result = (verifier: verifier, challenge: challenge)

proc urlEncode*(params: seq[(string, string)]): string =
  ## Build a URL-encoded query string from a sequence of (key, value) pairs.
  var parts: seq[string]
  for (k, v) in params:
    parts.add(encodeUrl(k) & "=" & encodeUrl(v))
  result = parts.join("&")

proc commonHeaders*(): seq[(string, string)] =
  @[
    (s("User-Agent"),       USER_AGENT()),
    (s("Accept-Language"),  s("en-US,en;q=0.9")),
  ]

#####################################################################################################

proc refreshAllTokens*(tokens: var TokenDict; debug: bool = false) {.gcsafe.} =

  let body8 = urlEncode(@[
    (s("client_id"),     TEAMS_CLIENT_ID()),
    (s("scope"),         s("https://auth.fl.teams.microsoft.com/teams.auth.readwrite openid profile offline_access")),
    (s("grant_type"),    s("refresh_token")),
    (s("client_info"),   s("1")),
    (s("x-client-SKU"),  s("msal.js.browser")),
    (s("x-client-VER"),  s("5.6.3")),
    (s("refresh_token"), tokens.refreshToken),
  ])
  let url8 = s("https://login.microsoftonline.com/") & TEAMS_TENANT() & s("/oauth2/v2.0/token")
  let r8   = httpRequest(s("POST"), url8,
    headers = @[
      (s("Content-Type"), s("application/x-www-form-urlencoded")),
      (s("Origin"),       s("https://teams.live.com")),
    ],
    body = body8,
  )
  if r8.code != 200:
    let errMsg = r8.body
    if s("invalid_grant") in errMsg:
      raise newException(ValueError, s("invalid_grant"))
    raise newException(ValueError, s("token_refresh_8"))
  let d8 = parseJson(r8.body)
  if d8.hasKey(s("error")):
    let e = d8[s("error")].getStr()
    if s("invalid_grant") in e:
      raise newException(ValueError, s("invalid_grant"))
    raise newException(ValueError, s("token_error_8"))
  if d8.hasKey(s("refresh_token")):
    tokens.refreshToken = d8[s("refresh_token")].getStr()
  tokens.accessToken = d8[s("access_token")].getStr()

  let body8b = urlEncode(@[
    (s("client_id"),     TEAMS_CLIENT_ID()),
    (s("scope"),         URL_GRAPH_SCOPE()),
    (s("grant_type"),    s("refresh_token")),
    (s("client_info"),   s("1")),
    (s("x-client-SKU"),  s("msal.js.browser")),
    (s("x-client-VER"),  s("5.6.3")),
    (s("refresh_token"), tokens.refreshToken),
  ])
  let r8b = httpRequest(s("POST"),
    URL_CONSUMERS_TOKEN(),
    headers = @[
      (s("Content-Type"), s("application/x-www-form-urlencoded")),
      (s("Origin"),       s("https://teams.live.com")),
    ],
    body = body8b,
  )
  if r8b.code == 200:
    let d8b = parseJson(r8b.body)
    if d8b.hasKey(s("access_token")):
      tokens.graphToken = d8b[s("access_token")].getStr()

  let r9 = httpRequest(s("POST"),
    URL_TEAMS_AUTHZ(),
    headers = @[
      (s("Authorization"),        s("Bearer ") & tokens.accessToken),
      (s("Content-Type"),         s("application/json")),
      (s("Accept"),               s("application/json")),
      (s("Origin"),               s("https://teams.live.com")),
      (s("X-Ms-Client-Type"),     s("web")),
      (s("X-Ms-Client-Version"),  s("1415/26070217343")),
      (s("Ms-Teams-Authz-Type"),  s("ExplicitLogin")),
    ],
    body = s("{}"),
  )
  if r9.code != 200:
    raise newException(ValueError, s("token_refresh_9"))
  let d9   = parseJson(r9.body)
  let sobj = d9.getOrDefault(s("skypeToken"))
  if sobj.kind == JObject:
    tokens.skypeToken = sobj.getOrDefault(s("skypetoken")).getStr()



# Pre-compiled regex patterns (compile once at module load)
let reSft      = re2("""\"sFT\"\s*:\s*\"([^\"]+)\"""")
let reCanary   = re2("""\"apiCanary\"\s*:\s*\"([^\"]+)\"""")
let reSctx     = re2("""\"sCtx\"\s*:\s*\"([^\"]+)\"""")
let reSftag    = re2("""\"sFTTag\"\s*:\s*\"([^\"]+)\"""")
let rePpftVal  = re2("""value=\"([^\"]+)\"[^>]*name=\"PPFT\"""")
let rePpftInp  = re2("""<input[^>]+name=\"PPFT\"[^>]+value=\"([^\"]+)\"""")
let reUrlPost  = re2("""\"urlPost\"\s*:\s*\"([^\"]+)\"""")
let reErrCode  = re2("""\"sErrorCode\"\s*:\s*\"([^\"]+)\"""")
let reCode     = re2("""[?&]code=([^&\s#]+)""")
let reCodeBody = re2("""name=\"code\"[^>]+value=\"([^\"]+)\"""")

proc login*(username, password: string; debug: bool = false): TokenDict =

  result = newTokenDict()
  let pkce = generatePkce()
  let cid  = $genOid()

  let params1 = urlEncode(@[
    (s("client_id"),           M365_CLIENT_ID()),
    (s("redirect_uri"),        s("https://m365.cloud.microsoft/landingv2")),
    (s("response_type"),       s("code id_token")),
    (s("scope"),               s("openid profile https://www.office.com/v2/OfficeHome.All")),
    (s("response_mode"),       s("form_post")),
    (s("nonce"),               NONCE()),
    (s("ui_locales"),          s("en-US")),
    (s("mkt"),                 s("en-US")),
    (s("client-request-id"),   cid),
    (s("state"),               s("cli_state")),
    (s("x-client-SKU"),        s("ID_NET8_0")),
    (s("x-client-ver"),        s("8.16.0.0")),
    (s("sso_reload"),          s("true")),
  ])
  let r1 = httpRequest(s("GET"),
    s("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?") & params1,
    headers = commonHeaders(),
  )
  if r1.code != 200:
    raise newException(ValueError, s("login_step1"))
  let sft    = reFind(reSft,    r1.body)
  let canary = reFind(reCanary, r1.body)
  let sctx   = reFind(reSctx,   r1.body)
  if sft.len == 0:
    raise newException(ValueError, s("login_step1_sft"))
  var flowToken = sft

  let body2 = $(%*{
    s("username"): username, s("isOtherIdpSupported"): true, s("checkPhones"): false,
    s("isRemoteNGCSupported"): true, s("isCookieBannerShown"): false, s("isFidoSupported"): true,
    s("originalRequest"): sctx, s("country"): s("IL"), s("forceotclogin"): false,
    s("isExternalFederationDisallowed"): false, s("isRemoteConnectSupported"): false,
    s("federationFlags"): 0, s("isSignup"): false, s("flowToken"): flowToken,
    s("isAccessPassSupported"): true, s("isQrCodePinSupported"): true,
  })
  let r2 = httpRequest(s("POST"),
    URL_LOGIN_COMMON(),
    headers = @[
      (s("Content-Type"),      s("application/json; charset=UTF-8")),
      (s("Accept"),            s("application/json")),
      (s("Hpgid"),             s("1104")),
      (s("Hpgact"),            s("1800")),
      (s("Canary"),            canary),
      (s("Client-Request-Id"), cid),
      (s("Origin"),            s("https://login.microsoftonline.com")),
      (s("Referer"),           s("https://login.microsoftonline.com/")),
    ],
    body = body2,
  )
  if r2.code != 200:
    raise newException(ValueError, s("login_step2"))
  let gct = parseJson(r2.body)
  flowToken = gct.getOrDefault(s("FlowToken")).getStr(flowToken)
  let ifExists = gct.getOrDefault(s("IfExistsResult")).getInt(-1)
  if ifExists notin [0, 1, 5, 6]:
    raise newException(ValueError, s("login_step2_user"))


  let params3 = urlEncode(@[
    (s("client_id"),         M365_CLIENT_ID()),
    (s("scope"),             s("openid profile https://www.office.com/v2/OfficeHome.All")),
    (s("redirect_uri"),      s("https://m365.cloud.microsoft/landingv2")),
    (s("response_type"),     s("code id_token")),
    (s("response_mode"),     s("form_post")),
    (s("nonce"),             NONCE()),
    (s("ui_locales"),        s("en-US")),
    (s("mkt"),               s("en-US")),
    (s("client-request-id"), cid),
    (s("state"),             s("cli_state")),
    (s("login_hint"),        username),
    (s("uaid"),              cid.replace("-", "")),
    (s("msproxy"),           s("1")),
    (s("issuer"),            s("mso")),
    (s("tenant"),            s("common")),
    (s("jshs"),              s("0")),
  ])
  let r3 = httpRequest(s("GET"),
    s("https://login.live.com/oauth20_authorize.srf?") & params3,
    headers = @[(s("Referer"), s("https://login.microsoftonline.com/"))],
  )
  if r3.code != 200:
    raise newException(ValueError, s("login_step3"))
  let html3 = r3.body
  let r3url  = r3.url

  var ppft = ""
  let sftag = reFind(reSftag, html3)
  if sftag.len > 0:
    try:
      let sftagHtml = parseJson(sftag).getStr()
      ppft = reFind(rePpftVal, sftagHtml)
    except: discard
  if ppft.len == 0:
    ppft = reFind(rePpftInp, html3)
  if ppft.len == 0:
    raise newException(ValueError, s("login_step3_ppft"))
  let urlPostRaw = reFind(reUrlPost, html3)
  let ppsx_url   = if urlPostRaw.len > 0: urlPostRaw.replace("\\/", "/")
                   else: s("https://login.live.com/ppsecure/post.srf")


  let body4 = $(%*{s("username"): username, s("password"): password, s("checkpasswordflowtoken"): s("")})
  let r4 = httpRequest(s("POST"),
    s("https://login.live.com/checkpassword.srf"),
    headers = @[
      (s("Content-Type"),      s("application/json; charset=utf-8")),
      (s("Accept"),            s("application/json")),
      (s("Hpgid"),             s("33")),
      (s("Hpgact"),            s("0")),
      (s("Correlationid"),     cid),
      (s("Client-Request-Id"), cid),
      (s("Origin"),            s("https://login.live.com")),
      (s("Referer"),           r3url),
    ],
    body = body4,
  )
  if r4.code != 200:
    raise newException(ValueError, s("login_step4"))
  let d4  = parseJson(r4.body)
  let vft = d4.getOrDefault(s("vanguardflowtoken")).getStr()
  if d4.getOrDefault(s("validationresult")).getStr() != s("succeed"):
    raise newException(ValueError, s("login_step4_pass"))


  let body5 = urlEncode(@[
    (s("login"),        username),
    (s("loginfmt"),     username),
    (s("type"),         s("11")),
    (s("LoginOptions"), s("3")),
    (s("passwd"),       password),
    (s("ps"),           s("2")),
    (s("PPFT"),         ppft),
    (s("PPSX"),         s("Passpor")),
    (s("flowToken"),    vft),
  ])
  let r5 = httpRequest(s("POST"), ppsx_url,
    headers = @[
      (s("Content-Type"), s("application/x-www-form-urlencoded")),
      (s("Origin"),       s("https://login.live.com")),
      (s("Referer"),      r3url),
    ],
    body = body5,
  )
  let errCode5 = reFind(reErrCode, r5.body)
  if errCode5.len > 0:
    raise newException(ValueError, s("login_step5"))


  let params6 = urlEncode(@[
    (s("client_id"),            TEAMS_CLIENT_ID()),
    (s("scope"),                s("https://auth.fl.teams.microsoft.com/teams.auth.readwrite openid profile offline_access")),
    (s("redirect_uri"),         s("https://teams.live.com/v2/")),
    (s("response_type"),        s("code")),
    (s("response_mode"),        s("query")),
    (s("code_challenge"),       pkce.challenge),
    (s("code_challenge_method"),s("S256")),
    (s("client_info"),          s("1")),
    (s("x-client-SKU"),         s("msal.js.browser")),
    (s("x-client-VER"),         s("5.6.3")),
    (s("nonce"),                NONCE()),
    (s("state"),                s("teams_state")),
    (s("prompt"),               s("none")),
    (s("login_hint"),           username),
  ])
  let r6 = httpRequest(s("GET"),
    s("https://login.microsoftonline.com/") & TEAMS_TENANT() & s("/oauth2/v2.0/authorize?") & params6,
    headers = commonHeaders(),
    followRedirects = false,
  )
  var authCode = ""
  let loc6 = r6[s("Location")]
  if loc6.len > 0:
    authCode = reFind(reCode, loc6)
  if authCode.len == 0:
    authCode = reFind(reCodeBody, r5.body)
  if authCode.len == 0:
    authCode = reFind(reCodeBody, r6.body)
  if authCode.len == 0:
    raise newException(ValueError, s("login_step6"))


  let body7 = urlEncode(@[
    (s("client_id"),     TEAMS_CLIENT_ID()),
    (s("scope"),         s("https://auth.fl.teams.microsoft.com/teams.auth.readwrite openid profile offline_access")),
    (s("code"),          authCode),
    (s("redirect_uri"),  s("https://teams.live.com/v2/")),
    (s("grant_type"),    s("authorization_code")),
    (s("code_verifier"), pkce.verifier),
    (s("client_info"),   s("1")),
    (s("x-client-SKU"),  s("msal.js.browser")),
    (s("x-client-VER"),  s("5.6.3")),
  ])
  let r7 = httpRequest(s("POST"),
    s("https://login.microsoftonline.com/") & TEAMS_TENANT() & s("/oauth2/v2.0/token"),
    headers = @[
      (s("Content-Type"), s("application/x-www-form-urlencoded")),
      (s("Origin"),       s("https://teams.live.com")),
    ],
    body = body7,
  )
  if r7.code != 200:
    raise newException(ValueError, s("login_step7"))
  let d7 = parseJson(r7.body)
  if d7.hasKey(s("error")):
    raise newException(ValueError, s("login_step7_err"))
  result.refreshToken = d7[s("refresh_token")].getStr()
  result.accessToken  = d7[s("access_token")].getStr()

  let body8b_login = urlEncode(@[
    (s("client_id"),     TEAMS_CLIENT_ID()),
    (s("scope"),         URL_GRAPH_SCOPE()),
    (s("grant_type"),    s("refresh_token")),
    (s("client_info"),   s("1")),
    (s("x-client-SKU"),  s("msal.js.browser")),
    (s("x-client-VER"),  s("5.6.3")),
    (s("refresh_token"), result.refreshToken),
  ])
  let r8b_login = httpRequest(s("POST"),
    URL_CONSUMERS_TOKEN(),
    headers = @[
      (s("Content-Type"), s("application/x-www-form-urlencoded")),
      (s("Origin"),       s("https://teams.live.com")),
    ],
    body = body8b_login,
  )
  if r8b_login.code == 200:
    let d8b_login = parseJson(r8b_login.body)
    if d8b_login.hasKey(s("access_token")):
      result.graphToken = d8b_login[s("access_token")].getStr()


  let r9_login = httpRequest(s("POST"),
    URL_TEAMS_AUTHZ(),
    headers = @[
      (s("Authorization"),        s("Bearer ") & result.accessToken),
      (s("Content-Type"),         s("application/json")),
      (s("Accept"),               s("application/json")),
      (s("Origin"),               s("https://teams.live.com")),
      (s("X-Ms-Client-Type"),     s("web")),
      (s("X-Ms-Client-Version"),  s("1415/26070217343")),
      (s("Ms-Teams-Authz-Type"),  s("ExplicitLogin")),
    ],
    body = s("{}"),
  )
  if r9_login.code != 200:
    raise newException(ValueError, s("login_step9"))
  let d9_login = parseJson(r9_login.body)
  let sobj     = d9_login.getOrDefault(s("skypeToken"))
  if sobj.kind == JObject:
    result.skypeToken   = sobj.getOrDefault(s("skypetoken")).getStr()
    result.displayName  = sobj.getOrDefault(s("skypeId")).getStr()
    result.skypeId      = sobj.getOrDefault(s("skypeId")).getStr()
