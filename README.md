# Send_Me_A_Message
C2 Framework based on Microsoft Teams traffic

## Set up:
* Create Two accounts on outlook.com (Personal Accounts)
* !!! when you create the accounts don't set up MFA! !!!

### Client functionality:
* Client written in NIM
* Server written in Python using textual for terminal UI

* All commands executed with WinAPI:
```text
whoami         = GetUserNameW
hostname       = GetComputerNameW
pwd            = GetCurrentDirectoryW
ls [path]      = FindFirstFileW / FindNextFileW
cat <path>     = CreateFileW + ReadFile
ps             = CreateToolhelp32Snapshot + Process32FirstW/NextW
kill <pid>     = OpenProcess + TerminateProcess
sysinfo        = GetSystemInfo + GlobalMemoryStatusEx + RtlGetVersion
ipconfig       = GetAdaptersInfo (iphlpapi.dll)
netstat        = GetExtendedTcpTable (iphlpapi.dll)
ping <host>    = IcmpSendEcho (iphlpapi.dll)
dns <host>     = DnsQuery_W (dnsapi.dll)
drives         = GetLogicalDriveStringsW + GetDiskFreeSpaceExW
uptime         = GetTickCount64
env            = GetEnvironmentStringsW
getenv <var>   = GetEnvironmentVariableW
mkdir <path>   = CreateDirectoryW
rm <path>      = DeleteFileW / RemoveDirectoryW
mv <src> <dst> = MoveFileW
cp <src> <dst> = CopyFileW
screenshot     = BitBlt + GetDC (saves PNG, returns base64)
clipboard      = OpenClipboard + GetClipboardData
exec           = CreateProcessW
exec_spoof     = CreateToolhelp32Snapshot + Process32FirstW + OpenProcess + UpdateProcThreadAttribute 
getpid         = GetCurrentProcessId
```

* Compile the client with NIM:
```text
nim.exe c --app:gui --cpu:amd64 --nimcache:nimcache_new -p:src -o:taskhostw.exe src\teams_client.nim
```


### Artifacts:
* The client create a file called "session.dat" on %APPDATA%\Roaming\Microsoft\Teams\cache (and the Teams and cache folders as well) - storing the encrypted Refresh Token
* API Request:
   - https://teams.live.com/api/chatsvc/consumer/v1/users/ME/conversations
   - https://teams.live.com/api/csa/api/v3/teams/users/me
   - https://m365.cloud.microsoft/landingv2
   - https://login.microsoftonline.com/common/oauth2/v2.0/authorize
   - https://login.live.com/oauth20_authorize.srf
   - https://login.live.com/checkpassword.srf
   - https://login.microsoftonline.com/
   - https://my.microsoftpersonalcontent.com/personal/
 

### Run the Server:
 - Linux:
```
python3 -m venv CTT
source CTT/bin/active
pip install requests
pip install textual
pip install cryptography
python3 CTT.py
```

- Windows:
```
python -m pip install requests
python -mpip install textual
python -m pip install cryptography
python CTT.py
```
